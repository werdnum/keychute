//! Canonical JSON serialization for the idempotency MAC (addendum #18).
//!
//! The MAC input is the request body serialized with object keys sorted
//! (recursively) and no whitespace, MINUS `idempotency_key` and MINUS
//! `context.structured`.
//!
//! The `context.structured` exclusion is deliberate and is the one deviation
//! from "the whole body minus the key". That field carries MACHINE-CAPTURED
//! environment (the CLI's `ps` snapshot of the invoking pipeline), which is
//! inherently nondeterministic across reruns: a background job exiting
//! between two invocations changes it. Folding it in would break the only
//! recovery path a client has after a failed grant read — rerun with the same
//! idempotency key to reach the same request and the same derived read key —
//! turning it into a permanent 409 that strands an approved grant and burns a
//! fresh operator approval.
//!
//! Everything a human or a caller deliberately states stays IN, including
//! `context.reason`: a client that changes its stated reason under a reused
//! key is claiming something different about the same request and gets a 409,
//! not a silent replay of the old text.

use keychute_types::CreateAccessRequest;

/// Serialize a JSON value canonically: object keys sorted byte-wise,
/// no whitespace, standard JSON escaping.
pub fn canonical_json(v: &serde_json::Value, out: &mut String) {
    match v {
        serde_json::Value::Null => out.push_str("null"),
        serde_json::Value::Bool(b) => out.push_str(if *b { "true" } else { "false" }),
        serde_json::Value::Number(n) => out.push_str(&n.to_string()),
        serde_json::Value::String(s) => {
            // serde_json's string serialization is deterministic.
            out.push_str(&serde_json::to_string(s).expect("string serialization is infallible"));
        }
        serde_json::Value::Array(items) => {
            out.push('[');
            for (i, item) in items.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                canonical_json(item, out);
            }
            out.push(']');
        }
        serde_json::Value::Object(map) => {
            let mut keys: Vec<&String> = map.keys().collect();
            keys.sort();
            out.push('{');
            for (i, k) in keys.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                out.push_str(
                    &serde_json::to_string(k).expect("string serialization is infallible"),
                );
                out.push(':');
                canonical_json(&map[k.as_str()], out);
            }
            out.push('}');
        }
    }
}

/// Canonical MAC payload for a create-access-request body: the typed request
/// serialized to a Value, `idempotency_key` and `context.structured` removed
/// (see module docs), canonicalized.
pub fn canonical_request_payload(req: &CreateAccessRequest) -> Vec<u8> {
    let mut v = serde_json::to_value(req).expect("CreateAccessRequest serializes");
    if let serde_json::Value::Object(map) = &mut v {
        map.remove("idempotency_key");
        if let Some(serde_json::Value::Object(ctx)) = map.get_mut("context") {
            ctx.remove("structured");
        }
    }
    let mut out = String::new();
    canonical_json(&v, &mut out);
    out.into_bytes()
}

#[cfg(test)]
mod tests {
    use super::*;
    use keychute_types::{Constraints, Mechanism, Origin, RequestContext};

    fn canon(v: serde_json::Value) -> String {
        let mut s = String::new();
        canonical_json(&v, &mut s);
        s
    }

    #[test]
    fn sorts_keys_recursively_no_whitespace() {
        let v = serde_json::json!({
            "zeta": {"b": 2, "a": 1},
            "alpha": [ {"y": true, "x": null} ],
            "mid": "str \" escape",
            "num": 3.5,
        });
        assert_eq!(
            canon(v),
            r#"{"alpha":[{"x":null,"y":true}],"mid":"str \" escape","num":3.5,"zeta":{"a":1,"b":2}}"#
        );
    }

    #[test]
    fn stable_across_key_insertion_order() {
        let a: serde_json::Value = serde_json::from_str(r#"{"a":1,"b":{"c":2,"d":3}}"#).unwrap();
        let b: serde_json::Value = serde_json::from_str(r#"{"b":{"d":3,"c":2},"a":1}"#).unwrap();
        assert_eq!(canon(a), canon(b));
    }

    #[test]
    fn request_payload_excludes_idempotency_key() {
        let mk = |key: &str| CreateAccessRequest {
            idempotency_key: key.to_owned(),
            secret_name: "s".into(),
            mechanism: Mechanism::Brokered,
            constraints: Constraints {
                origins: vec![Origin::parse("api.example.com").unwrap()],
                methods: vec!["GET".into()],
                path_prefixes: vec!["/v1".into()],
                ttl_seconds: 60,
                max_uses: None,
            },
            context: RequestContext::default(),
        };
        let a = canonical_request_payload(&mk("key-1"));
        let b = canonical_request_payload(&mk("key-2"));
        assert_eq!(a, b);
        assert!(!String::from_utf8(a.clone())
            .unwrap()
            .contains("idempotency_key"));
        assert!(String::from_utf8(a)
            .unwrap()
            .contains("\"secret_name\":\"s\""));

        // A retry whose machine-captured pipeline snapshot drifted must
        // replay, not 409: `structured` is out of the MAC.
        let mut drifted = mk("key-1");
        drifted.context = RequestContext {
            reason: String::new(),
            structured: Some(serde_json::json!({"pipeline_siblings": ["kubeseal"]})),
        };
        assert_eq!(canonical_request_payload(&drifted), b);

        // ...but a deliberately changed reason IS a different claim about the
        // request and must be detected.
        let mut reworded = mk("key-1");
        reworded.context = RequestContext {
            reason: "a different stated reason".into(),
            structured: None,
        };
        assert_ne!(canonical_request_payload(&reworded), b);
        // Same reason, differing snapshots: still identical.
        let mut same_reason_a = mk("key-1");
        same_reason_a.context = RequestContext {
            reason: "deploy".into(),
            structured: Some(serde_json::json!({"pipeline_siblings": ["a"]})),
        };
        let mut same_reason_b = mk("key-1");
        same_reason_b.context = RequestContext {
            reason: "deploy".into(),
            structured: Some(serde_json::json!({"pipeline_siblings": ["b", "c"]})),
        };
        assert_eq!(
            canonical_request_payload(&same_reason_a),
            canonical_request_payload(&same_reason_b)
        );
    }
}
