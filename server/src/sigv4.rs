//! AWS Signature Version 4 for the brokered proxy leg (injection kind
//! `aws-sigv4`).
//!
//! Unlike the other injection kinds, a SigV4 credential is not a header value
//! that can be pasted onto the request: the `Authorization` header is an HMAC
//! over the request itself (method, path, selected headers, payload
//! hash and timestamp), keyed by a key derived from the secret access key. So
//! the signature is computed here, per forwarded request, after the proxy has
//! settled the exact method, URL and body it is about to send.
//!
//! The template carries the non-secret half — access key id, region and
//! service — and the stored secret is the secret access key. Everything that
//! goes into the signature is derived from what is actually sent upstream, so
//! a signature can never authorize a different request than the one the grant
//! constraints just validated.

use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

type HmacSha256 = Hmac<Sha256>;

/// Headers the signer synthesizes. A caller-supplied copy of any of these is
/// dropped before signing (`x-amz-security-token` too: a session token is not
/// part of this template, and a caller's would pair with our signature).
pub const SYNTHESIZED: &[&str] = &["x-amz-date", "x-amz-content-sha256", "x-amz-security-token"];

/// S3 headers that name a SECOND resource (CopyObject / UploadPartCopy read
/// from `x-amz-copy-source`). Grant constraints cover only the request's own
/// method and path, so a copy source could read objects outside the approved
/// prefix. Stripped from caller headers on the `aws-sigv4` kind.
pub const STRIPPED_CALLER_HEADERS: &[&str] = &[
    "x-amz-copy-source",
    "x-amz-copy-source-range",
    "x-amz-copy-source-if-match",
    "x-amz-copy-source-if-none-match",
    "x-amz-copy-source-if-modified-since",
    "x-amz-copy-source-if-unmodified-since",
];

/// Longest region / service string a template may carry.
const MAX_SCOPE_PART_BYTES: usize = 64;

/// The non-secret half of a SigV4 credential, as stored in the template.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Scope<'a> {
    pub access_key_id: &'a str,
    pub region: &'a str,
    pub service: &'a str,
}

/// Validate an access key id: printable ASCII with no separators, since it is
/// written verbatim into `Credential=<id>/<date>/...`.
pub fn validate_access_key_id(id: &str) -> Result<(), &'static str> {
    if id.is_empty() || id.len() > 128 {
        return Err("SigV4 access key id must be 1-128 characters");
    }
    if !id
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
    {
        return Err("SigV4 access key id may contain only letters, digits, '-' and '_'");
    }
    Ok(())
}

/// Parse the stored `region/service` scope string.
pub fn parse_scope(scope: &str) -> Result<(&str, &str), &'static str> {
    let (region, service) = scope
        .split_once('/')
        .ok_or("SigV4 scope must be 'region/service', e.g. 'us-east-1/s3'")?;
    for part in [region, service] {
        if part.is_empty()
            || part.len() > MAX_SCOPE_PART_BYTES
            || !part
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
        {
            return Err("SigV4 region and service must be lowercase letters, digits and '-'");
        }
    }
    // Grant constraints are method + path, so only a service whose operation
    // those select is signable: S3, with the query string refused by the
    // proxy (it carries S3 subresources such as `?acl` and `?versionId`).
    // JSON- and query-protocol services pick the operation from
    // `X-Amz-Target` or an `Action` parameter on a shared `POST /`.
    if service != "s3" {
        return Err("SigV4 service must be 's3'; other AWS services are not supported");
    }
    Ok((region, service))
}

/// Characters SigV4 leaves unescaped (RFC 3986 unreserved).
fn is_unreserved(b: u8) -> bool {
    b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.' | b'_' | b'~')
}

/// SigV4 `UriEncode`: every byte outside the unreserved set as `%XX`
/// (uppercase hex); `/` too unless `keep_slash`.
pub fn uri_encode(input: &str, keep_slash: bool) -> String {
    let mut out = String::with_capacity(input.len());
    for &b in input.as_bytes() {
        if is_unreserved(b) || (keep_slash && b == b'/') {
            out.push(b as char);
        } else {
            out.push_str(&format!("%{b:02X}"));
        }
    }
    out
}

/// The wire path for a SigV4 request: the decoded canonical path,
/// single-encoded with [`uri_encode`]. Sending exactly this form means the
/// path the upstream sees and the path that was signed cannot diverge through
/// a URL library's own encoding choices.
pub fn wire_path(decoded_path: &str) -> String {
    if decoded_path.is_empty() {
        return "/".into();
    }
    uri_encode(decoded_path, true)
}

fn hmac(key: &[u8], data: &[u8]) -> Zeroizing<Vec<u8>> {
    let mut mac = HmacSha256::new_from_slice(key).expect("HMAC accepts any key length");
    mac.update(data);
    Zeroizing::new(mac.finalize().into_bytes().to_vec())
}

/// What the signer needs to know about the outbound request.
pub struct Request<'a> {
    /// Uppercase method, as sent.
    pub method: &'a str,
    /// `host` or `host:port` exactly as the `Host` header will carry it.
    pub host: &'a str,
    /// The path as sent on the wire ([`wire_path`]).
    pub wire_path: &'a str,
    /// Other headers to sign (lowercase names); `host` and the synthesized
    /// headers are added by the signer.
    pub extra_signed_headers: Vec<(String, String)>,
    pub payload: &'a [u8],
}

/// The headers to set on the outbound request.
pub struct Signed {
    pub authorization: String,
    pub amz_date: String,
    pub content_sha256: String,
}

/// Collapse runs of spaces and trim, per SigV4 canonical header values.
fn canonical_header_value(v: &str) -> String {
    v.split_whitespace().collect::<Vec<_>>().join(" ")
}

pub fn sign(
    scope: &Scope<'_>,
    secret_access_key: &[u8],
    req: &Request<'_>,
    now: chrono::DateTime<chrono::Utc>,
) -> Signed {
    let amz_date = now.format("%Y%m%dT%H%M%SZ").to_string();
    let date = now.format("%Y%m%d").to_string();
    let content_sha256 = hex::encode(Sha256::digest(req.payload));

    let mut headers: Vec<(String, String)> = req
        .extra_signed_headers
        .iter()
        .map(|(k, v)| (k.to_ascii_lowercase(), canonical_header_value(v)))
        .collect();
    headers.push(("host".into(), req.host.to_owned()));
    headers.push(("x-amz-content-sha256".into(), content_sha256.clone()));
    headers.push(("x-amz-date".into(), amz_date.clone()));
    headers.sort_by(|a, b| a.0.cmp(&b.0));
    // Repeated header names fold into one comma-joined line.
    let mut folded: Vec<(String, String)> = Vec::new();
    for (k, v) in headers {
        match folded.last_mut() {
            Some((lk, lv)) if *lk == k => {
                lv.push(',');
                lv.push_str(&v);
            }
            _ => folded.push((k, v)),
        }
    }
    let canonical_headers: String = folded.iter().map(|(k, v)| format!("{k}:{v}\n")).collect();
    let signed_headers = folded
        .iter()
        .map(|(k, _)| k.as_str())
        .collect::<Vec<_>>()
        .join(";");

    let canonical_request = format!(
        "{}\n{}\n{}\n{}\n{}\n{}",
        req.method, req.wire_path, "", canonical_headers, signed_headers, content_sha256
    );
    let credential_scope = format!("{date}/{}/{}/aws4_request", scope.region, scope.service);
    let string_to_sign = format!(
        "AWS4-HMAC-SHA256\n{amz_date}\n{credential_scope}\n{}",
        hex::encode(Sha256::digest(canonical_request.as_bytes()))
    );

    let mut k_secret = Zeroizing::new(Vec::with_capacity(4 + secret_access_key.len()));
    k_secret.extend_from_slice(b"AWS4");
    k_secret.extend_from_slice(secret_access_key);
    let k_date = hmac(&k_secret, date.as_bytes());
    let k_region = hmac(&k_date, scope.region.as_bytes());
    let k_service = hmac(&k_region, scope.service.as_bytes());
    let k_signing = hmac(&k_service, b"aws4_request");
    let signature = hex::encode(&*hmac(&k_signing, string_to_sign.as_bytes()));

    Signed {
        authorization: format!(
            "AWS4-HMAC-SHA256 Credential={}/{credential_scope}, SignedHeaders={signed_headers}, Signature={signature}",
            scope.access_key_id
        ),
        amz_date,
        content_sha256,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;

    #[test]
    fn scope_and_key_id_validation() {
        assert_eq!(parse_scope("us-east-1/s3"), Ok(("us-east-1", "s3")));
        assert!(parse_scope("us-east-1").is_err());
        assert!(parse_scope("US-EAST-1/s3").is_err());
        assert!(parse_scope("us-east-1/s3/x").is_err());
        assert!(parse_scope("/s3").is_err());
        assert!(parse_scope("us-east-1/dynamodb").is_err());
        assert!(validate_access_key_id("AKIAIOSFODNN7EXAMPLE").is_ok());
        assert!(validate_access_key_id("a/b").is_err());
        assert!(validate_access_key_id("").is_err());
    }

    #[test]
    fn encoding_rules() {
        assert_eq!(uri_encode("a b/c~d", true), "a%20b/c~d");
        assert_eq!(uri_encode("a b/c", false), "a%20b%2Fc");
        assert_eq!(wire_path("/bucket/my key!.jpg"), "/bucket/my%20key%21.jpg");
    }

    fn at(s: &str) -> chrono::DateTime<chrono::Utc> {
        chrono::Utc
            .from_utc_datetime(&chrono::NaiveDateTime::parse_from_str(s, "%Y%m%dT%H%M%SZ").unwrap())
    }

    /// Expected values computed with botocore 1.43 (`S3SigV4Auth` /
    /// `SigV4Auth`, clock pinned) for the same inputs.
    #[test]
    fn matches_botocore_s3_get() {
        let scope = Scope {
            access_key_id: "AKIDEXAMPLE",
            region: "us-east-1",
            service: "s3",
        };
        let signed = sign(
            &scope,
            b"wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY",
            &Request {
                method: "GET",
                host: "minio.example.dev",
                wire_path: &wire_path("/lake-media/sha256/ab/abcdef"),
                extra_signed_headers: vec![],
                payload: b"",
            },
            at("20261002T010203Z"),
        );
        assert_eq!(signed.amz_date, "20261002T010203Z");
        assert_eq!(
            signed.content_sha256,
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
        assert_eq!(signed.authorization, BOTOCORE_S3_GET);
    }

    #[test]
    fn matches_botocore_s3_put_with_amz_header() {
        let scope = Scope {
            access_key_id: "AKIDEXAMPLE",
            region: "us-east-1",
            service: "s3",
        };
        let signed = sign(
            &scope,
            b"wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY",
            &Request {
                method: "PUT",
                host: "minio.example.dev:9000",
                wire_path: &wire_path("/bucket/a b.txt"),
                extra_signed_headers: vec![("x-amz-meta-note".into(), "  hello   world ".into())],
                payload: b"hello",
            },
            at("20261002T010203Z"),
        );
        assert_eq!(signed.authorization, BOTOCORE_S3_PUT);
    }

    #[test]
    fn repeated_header_values_keep_their_order() {
        let scope = Scope {
            access_key_id: "AKIDEXAMPLE",
            region: "us-east-1",
            service: "s3",
        };
        let sign_with = |values: [&str; 2]| {
            sign(
                &scope,
                b"secret",
                &Request {
                    method: "GET",
                    host: "minio.example.dev",
                    wire_path: "/b/k",
                    extra_signed_headers: values
                        .iter()
                        .map(|v| ("x-amz-meta-a".to_owned(), (*v).to_owned()))
                        .collect(),
                    payload: b"",
                },
                at("20261002T010203Z"),
            )
            .authorization
        };
        assert_ne!(sign_with(["z", "a"]), sign_with(["a", "z"]));
    }

    const BOTOCORE_S3_GET: &str = "AWS4-HMAC-SHA256 \
        Credential=AKIDEXAMPLE/20261002/us-east-1/s3/aws4_request, \
        SignedHeaders=host;x-amz-content-sha256;x-amz-date, \
        Signature=7c22efceba70c54548fed8a13e80256296a191d11988d419cb310835af5abf37";
    const BOTOCORE_S3_PUT: &str = "AWS4-HMAC-SHA256 \
        Credential=AKIDEXAMPLE/20261002/us-east-1/s3/aws4_request, \
        SignedHeaders=host;x-amz-content-sha256;x-amz-date;x-amz-meta-note, \
        Signature=df90e737a5a91cbe07e4433757d3a0558b423385bbd939d4e39bc223bfd2f6e7";
}
