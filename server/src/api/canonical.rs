//! Canonical JSON serialization for the idempotency MAC (addendum #18).
//!
//! The MAC input is the request body serialized with object keys sorted
//! (recursively) and no whitespace, MINUS the `idempotency_key` field.

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
/// serialized to a Value, `idempotency_key` removed, canonicalized.
pub fn canonical_request_payload(req: &CreateAccessRequest) -> Vec<u8> {
    let mut v = serde_json::to_value(req).expect("CreateAccessRequest serializes");
    if let serde_json::Value::Object(map) = &mut v {
        map.remove("idempotency_key");
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
    }
}
