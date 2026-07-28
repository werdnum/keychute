//! Shared API types for Keychute: the contract between server, CLI, and tests.
//!
//! This crate is IO-free. Semantics are specified in `docs/DESIGN.md` and
//! pinned in `docs/IMPLEMENTATION.md`.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Delivery tier: how much of the secret the client-side world gets to see.
/// Ordering is meaningful: lower = less exposure.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum Tier {
    #[serde(rename = "brokered")]
    Brokered = 0,
    #[serde(rename = "trusted-client")]
    TrustedClient = 1,
    #[serde(rename = "cooperating-client")]
    CooperatingClient = 2,
    #[serde(rename = "direct")]
    Direct = 3,
}

impl Tier {
    pub fn as_int(self) -> i32 {
        self as i32
    }

    pub fn from_int(v: i32) -> Option<Tier> {
        match v {
            0 => Some(Tier::Brokered),
            1 => Some(Tier::TrustedClient),
            2 => Some(Tier::CooperatingClient),
            3 => Some(Tier::Direct),
            _ => None,
        }
    }

    /// Plain-language description used in pushes and the approval UI.
    pub fn human_label(self) -> &'static str {
        match self {
            Tier::Brokered => "brokered (tier 0): the client never sees the secret",
            Tier::TrustedClient => {
                "trusted-client (tier 1): deterministic client code handles the secret"
            }
            Tier::CooperatingClient => {
                "cooperating-client (tier 2): code in the agent's own container handles the secret — the agent CAN read it"
            }
            Tier::Direct => "direct (tier 3): the agent itself receives the secret",
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Tier::Brokered => "brokered",
            Tier::TrustedClient => "trusted-client",
            Tier::CooperatingClient => "cooperating-client",
            Tier::Direct => "direct",
        }
    }
}

/// Concrete delivery mechanism. Each maps to exactly one tier.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Mechanism {
    #[serde(rename = "brokered")]
    Brokered,
    #[serde(rename = "autofill")]
    Autofill,
    #[serde(rename = "cli-read")]
    CliRead,
    #[serde(rename = "direct-read")]
    DirectRead,
}

impl Mechanism {
    pub fn tier(self) -> Tier {
        match self {
            Mechanism::Brokered => Tier::Brokered,
            Mechanism::Autofill => Tier::TrustedClient,
            Mechanism::CliRead => Tier::CooperatingClient,
            Mechanism::DirectRead => Tier::Direct,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Mechanism::Brokered => "brokered",
            Mechanism::Autofill => "autofill",
            Mechanism::CliRead => "cli-read",
            Mechanism::DirectRead => "direct-read",
        }
    }

    pub fn from_str_opt(s: &str) -> Option<Mechanism> {
        match s {
            "brokered" => Some(Mechanism::Brokered),
            "autofill" => Some(Mechanism::Autofill),
            "cli-read" => Some(Mechanism::CliRead),
            "direct-read" => Some(Mechanism::DirectRead),
            _ => None,
        }
    }

    /// Mechanisms whose grants are exercised via `/read` (plaintext release).
    pub fn is_releasing(self) -> bool {
        !matches!(self, Mechanism::Brokered)
    }
}

/// An HTTPS origin constraint. Scheme is fixed to https by construction.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Origin {
    pub host: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub port: Option<u16>,
}

impl Origin {
    /// Parse from `host` or `host:port`. Host is lowercased. Rejects empty,
    /// schemes, paths, userinfo, and wildcard hosts.
    pub fn parse(s: &str) -> Result<Origin, String> {
        let s = s.trim();
        if s.is_empty() {
            return Err("empty origin".into());
        }
        if s.contains('/') || s.contains('@') || s.contains('?') || s.contains('#') {
            return Err(format!("origin must be host[:port], got {s:?}"));
        }
        let (host, port) = match s.rsplit_once(':') {
            Some((h, p)) if !h.contains(':') => {
                let port: u16 = p.parse().map_err(|_| format!("bad port in origin {s:?}"))?;
                if port == 0 {
                    return Err("port 0 is not a valid origin port".into());
                }
                (h, Some(port))
            }
            _ => (s, None),
        };
        let host = host.trim_end_matches('.').to_ascii_lowercase();
        if host.is_empty()
            || host.contains('*')
            || !host
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '.')
        {
            return Err(format!("invalid origin host {host:?}"));
        }
        Ok(Origin { host, port })
    }

    /// Effective port (443 when unspecified).
    pub fn effective_port(&self) -> u16 {
        self.port.unwrap_or(443)
    }

    pub fn to_display(&self) -> String {
        match self.port {
            Some(p) => format!("https://{}:{}", self.host, p),
            None => format!("https://{}", self.host),
        }
    }

    /// Two origins are the same target iff host and *effective* port match.
    pub fn same_target(&self, other: &Origin) -> bool {
        self.host == other.host && self.effective_port() == other.effective_port()
    }
}

/// Constraints on a requested or granted capability.
///
/// Empty vectors mean "unconstrained" in policy rows; a brokered access
/// *request* must supply exactly one origin and at least one method
/// (validated server-side).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct Constraints {
    #[serde(default)]
    pub origins: Vec<Origin>,
    #[serde(default)]
    pub methods: Vec<String>,
    #[serde(default)]
    pub path_prefixes: Vec<String>,
    pub ttl_seconds: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_uses: Option<u32>,
}

/// Client-supplied context: rendered verbatim (escaped) on the approval page,
/// encrypted at rest, never in pushes or audit rows.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct RequestContext {
    #[serde(default)]
    pub reason: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub structured: Option<serde_json::Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateAccessRequest {
    pub idempotency_key: String,
    pub secret_name: String,
    pub mechanism: Mechanism,
    pub constraints: Constraints,
    #[serde(default)]
    pub context: RequestContext,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum RequestState {
    #[serde(rename = "pending")]
    Pending,
    #[serde(rename = "approved")]
    Approved,
    #[serde(rename = "denied")]
    Denied,
    #[serde(rename = "expired")]
    Expired,
}

impl RequestState {
    pub fn as_str(self) -> &'static str {
        match self {
            RequestState::Pending => "pending",
            RequestState::Approved => "approved",
            RequestState::Denied => "denied",
            RequestState::Expired => "expired",
        }
    }

    pub fn from_str_opt(s: &str) -> Option<RequestState> {
        match s {
            "pending" => Some(RequestState::Pending),
            "approved" => Some(RequestState::Approved),
            "denied" => Some(RequestState::Denied),
            "expired" => Some(RequestState::Expired),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccessRequestStatus {
    pub request_id: Uuid,
    pub state: RequestState,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub grant_id: Option<Uuid>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub deny_reason: Option<String>,
    pub expires_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReadGrantRequest {
    pub idempotency_key: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReadGrantResponse {
    /// Secret payload: utf8 string, or base64 when not valid UTF-8.
    pub secret: String,
    pub encoding: SecretEncoding,
    /// Immutable id of the payload actually released: a secret_version id, or
    /// the grant id itself for passthrough payloads.
    pub secret_version_id: Uuid,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SecretEncoding {
    #[serde(rename = "utf8")]
    Utf8,
    #[serde(rename = "base64")]
    Base64,
}

/// Standard error envelope.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApiError {
    pub error: ApiErrorBody,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApiErrorBody {
    pub code: String,
    pub message: String,
}

impl ApiError {
    pub fn new(code: impl Into<String>, message: impl Into<String>) -> Self {
        ApiError {
            error: ApiErrorBody {
                code: code.into(),
                message: message.into(),
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tier_ordering() {
        assert!(Tier::Brokered < Tier::Direct);
        assert_eq!(Tier::from_int(2), Some(Tier::CooperatingClient));
        assert_eq!(Tier::from_int(4), None);
    }

    #[test]
    fn mechanism_tiers() {
        assert_eq!(Mechanism::Brokered.tier(), Tier::Brokered);
        assert_eq!(Mechanism::CliRead.tier(), Tier::CooperatingClient);
        assert!(!Mechanism::Brokered.is_releasing());
        assert!(Mechanism::Autofill.is_releasing());
    }

    #[test]
    fn origin_parsing() {
        let o = Origin::parse("API.Example.com").unwrap();
        assert_eq!(o.host, "api.example.com");
        assert_eq!(o.effective_port(), 443);
        let o = Origin::parse("api.example.com:8443").unwrap();
        assert_eq!(o.port, Some(8443));
        assert!(Origin::parse("http://x.com").is_err());
        assert!(Origin::parse("*.example.com").is_err());
        assert!(Origin::parse("a b").is_err());
        assert!(Origin::parse("x.com:0").is_err());
        assert!(Origin::parse("user@x.com").is_err());
    }

    #[test]
    fn origin_same_target_default_port() {
        let a = Origin::parse("x.com").unwrap();
        let b = Origin::parse("x.com:443").unwrap();
        assert!(a.same_target(&b));
    }

    #[test]
    fn serde_shapes() {
        let req: CreateAccessRequest = serde_json::from_value(serde_json::json!({
            "idempotency_key": "k1",
            "secret_name": "example-api-token",
            "mechanism": "brokered",
            "constraints": {
                "origins": [{"host": "api.example.com"}],
                "methods": ["GET", "POST"],
                "path_prefixes": ["/v1"],
                "ttl_seconds": 3600
            },
            "context": {"reason": "test"}
        }))
        .unwrap();
        assert_eq!(req.mechanism, Mechanism::Brokered);
        assert_eq!(req.constraints.origins[0].host, "api.example.com");
    }
}
