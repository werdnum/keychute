//! Policy engine: pure decision logic. Contract in docs/IMPLEMENTATION.md
//! ("Policy engine contract") and docs/DESIGN.md §5–§6.
//!
//! No IO here: the API layer maps DB rows into [`ClientRow`] / [`SecretRow`] /
//! [`PolicyRow`] and calls [`evaluate`].

pub mod paths;

use chrono::{DateTime, Utc};
use keychute_types::{Constraints, Mechanism, Origin, Tier};
use uuid::Uuid;

/// Longest method token we accept. RFC 9110 sets no limit; this is a sanity
/// bound so a policy row or request cannot carry an unbounded "method".
pub const MAX_HTTP_METHOD_LEN: usize = 64;

/// True when `s` is a syntactically valid HTTP method: a non-empty RFC 9110
/// `token` of reasonable length.
///
/// `token = 1*tchar`, `tchar = "!" / "#" / "$" / "%" / "&" / "'" / "*" / "+" /
/// "-" / "." / "^" / "_" / "`" / "|" / "~" / DIGIT / ALPHA`. This admits real
/// non-alphabetic methods such as `M-SEARCH` (SSDP) and vendor `X-FOO` verbs,
/// which an alphabetic-only check wrongly rejected, while still excluding
/// whitespace, separators and control characters.
pub fn is_valid_http_method(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= MAX_HTTP_METHOD_LEN
        && s.bytes().all(|b| {
            b.is_ascii_alphanumeric()
                || matches!(
                    b,
                    b'!' | b'#'
                        ..=b'\'' | b'*' | b'+' | b'-' | b'.' | b'^' | b'_' | b'`' | b'|' | b'~'
                )
        })
}

/// Policy outcome stored on a row.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Outcome {
    AutoApprove,
    NotifyOnly,
    RequireApproval,
    Deny,
}

impl Outcome {
    pub fn from_str_opt(s: &str) -> Option<Outcome> {
        match s {
            "auto-approve" => Some(Outcome::AutoApprove),
            "notify-only" => Some(Outcome::NotifyOnly),
            "require-approval" => Some(Outcome::RequireApproval),
            "deny" => Some(Outcome::Deny),
            _ => None,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Outcome::AutoApprove => "auto-approve",
            Outcome::NotifyOnly => "notify-only",
            Outcome::RequireApproval => "require-approval",
            Outcome::Deny => "deny",
        }
    }

    /// Restrictiveness rank for tie-breaking: higher = more restrictive.
    fn restrictiveness(self) -> u8 {
        match self {
            Outcome::AutoApprove => 0,
            Outcome::NotifyOnly => 1,
            Outcome::RequireApproval => 2,
            Outcome::Deny => 3,
        }
    }
}

/// A row of the `clients` table, as the policy engine needs it.
#[derive(Debug, Clone)]
pub struct ClientRow {
    pub name: String,
    pub enabled: bool,
    pub max_tier: Tier,
    pub allowed_mechanisms: Vec<Mechanism>,
}

/// A row of the `secrets` table, as the policy engine needs it.
#[derive(Debug, Clone)]
pub struct SecretRow {
    pub name: String,
    pub enabled: bool,
    pub max_tier: Tier,
    /// Has an operator ever seen this value (migration 0007)? A client
    /// deposit starts false.
    pub operator_vetted: bool,
}

/// A row of the `policies` table.
#[derive(Debug, Clone)]
pub struct PolicyRow {
    pub id: Uuid,
    /// None = any client.
    pub client_name: Option<String>,
    /// Exactly one of `secret_name` / `secret_tag` is set, or both None = any secret.
    pub secret_name: Option<String>,
    pub secret_tag: Option<String>,
    pub mechanism: Mechanism,
    pub outcome: Outcome,
    pub priority: i32,
    /// Empty = unconstrained.
    pub origins: Vec<Origin>,
    /// Empty = unconstrained; compared case-insensitively.
    pub methods: Vec<String>,
    /// Canonical prefixes; empty = unconstrained.
    pub path_prefixes: Vec<String>,
    /// None = unlimited TTL.
    pub max_ttl_seconds: Option<u64>,
    /// None = unlimited uses.
    pub max_uses: Option<u32>,
    /// Row expiry; None = never expires.
    pub not_after: Option<DateTime<Utc>>,
}

/// The grant a client is asking for.
#[derive(Debug, Clone)]
pub struct RequestedGrant {
    pub secret_name: String,
    pub mechanism: Mechanism,
    pub constraints: Constraints,
}

/// Final decision for a requested grant.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Decision {
    Deny { reason: String },
    RequireApproval,
    NotifyOnly,
    AutoApprove,
}

/// Result of policy evaluation: the decision plus the winning row's identity
/// and expiry, so grants minted from it can be capped at policy expiry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Evaluation {
    pub decision: Decision,
    /// Expiry of the policy row that produced the decision (grant cap).
    pub policy_not_after: Option<DateTime<Utc>>,
    /// Id of the policy row that produced the decision, when one did.
    pub policy_id: Option<Uuid>,
}

impl Evaluation {
    fn deny(reason: impl Into<String>) -> Evaluation {
        Evaluation {
            decision: Decision::Deny {
                reason: reason.into(),
            },
            policy_not_after: None,
            policy_id: None,
        }
    }
}

/// Evaluate a requested grant against the policy table. Pure.
///
/// `secret` is None for an unknown secret name (allowed: approval-time entry);
/// in that case — and when the secret exists but no operator has vetted it —
/// the result is clamped to at most RequireApproval.
pub fn evaluate(
    client: &ClientRow,
    secret: Option<&SecretRow>,
    secret_tags: &[String],
    req: &RequestedGrant,
    policies: &[PolicyRow],
    now: DateTime<Utc>,
) -> Evaluation {
    // Hard caps first: these deny regardless of policy rows.
    if !client.enabled {
        return Evaluation::deny("client is disabled");
    }
    if !client.allowed_mechanisms.contains(&req.mechanism) {
        return Evaluation::deny(format!(
            "mechanism {} not allowed for client {}",
            req.mechanism.as_str(),
            client.name
        ));
    }
    let tier = req.mechanism.tier();
    if tier > client.max_tier {
        return Evaluation::deny(format!(
            "tier {} exceeds client max tier {}",
            tier.as_str(),
            client.max_tier.as_str()
        ));
    }
    if let Some(s) = secret {
        if !s.enabled {
            return Evaluation::deny("secret is disabled");
        }
        if tier > s.max_tier {
            return Evaluation::deny(format!(
                "tier {} exceeds secret max tier {}",
                tier.as_str(),
                s.max_tier.as_str()
            ));
        }
    }

    let applicable: Vec<&PolicyRow> = policies
        .iter()
        .filter(|p| is_applicable(p, client, req, secret_tags, now))
        .collect();

    // Deny rows match on OVERLAP: any intersection of usable scope rejects.
    for p in applicable.iter().filter(|p| p.outcome == Outcome::Deny) {
        if scopes_overlap(p, &req.constraints) {
            return Evaluation {
                decision: Decision::Deny {
                    reason: format!("denied by policy {}", p.id),
                },
                policy_not_after: p.not_after,
                policy_id: Some(p.id),
            };
        }
    }

    // Non-deny rows match only when the request is a SUBSET in every dimension.
    let winner = applicable
        .iter()
        .filter(|p| p.outcome != Outcome::Deny && request_is_subset(p, &req.constraints))
        .max_by_key(|p| precedence_key(p));

    match winner {
        Some(p) => {
            let mut decision = match p.outcome {
                Outcome::AutoApprove => Decision::AutoApprove,
                Outcome::NotifyOnly => Decision::NotifyOnly,
                Outcome::RequireApproval => Decision::RequireApproval,
                Outcome::Deny => unreachable!("deny rows filtered above"),
            };
            // Never auto-approve (or silently notify) a release of a secret no
            // human has seen: one that doesn't exist yet, or one a CLIENT
            // deposited and no operator has reviewed. The second case is what
            // stops a deposit from being an end-run around this clamp — the
            // depositing client picks the name, so without it a client could
            // satisfy a name-scoped or wildcard standing policy with bytes
            // nobody reviewed and have them released with no human in the loop.
            let unvetted = match secret {
                None => true,
                Some(s) => !s.operator_vetted,
            };
            if unvetted && matches!(decision, Decision::AutoApprove | Decision::NotifyOnly) {
                decision = Decision::RequireApproval;
            }
            // A brokered row with NO origin constraint is unconstrained in the
            // one dimension that decides where the credential is sent: an
            // empty `origins` matches whatever origin the client named, so
            // auto-approving on it would inject the real credential into a
            // request to a client-chosen host — with no push, since only
            // notify-only pushes. Requests must name exactly one origin
            // (`validate_request`); a standing row that grants without naming
            // any is refused the same widening. Row creation rejects this too
            // — this clamp also covers rows already in the table.
            if req.mechanism == Mechanism::Brokered
                && p.origins.is_empty()
                && matches!(decision, Decision::AutoApprove | Decision::NotifyOnly)
            {
                decision = Decision::RequireApproval;
            }
            Evaluation {
                decision,
                policy_not_after: p.not_after,
                policy_id: Some(p.id),
            }
        }
        None => Evaluation {
            decision: Decision::RequireApproval,
            policy_not_after: None,
            policy_id: None,
        },
    }
}

/// Row applicability: matches the request's client, secret, and mechanism
/// dimensions and has not expired. Scope (constraints) is checked separately.
fn is_applicable(
    p: &PolicyRow,
    client: &ClientRow,
    req: &RequestedGrant,
    secret_tags: &[String],
    now: DateTime<Utc>,
) -> bool {
    if p.mechanism != req.mechanism {
        return false;
    }
    if let Some(nafter) = p.not_after {
        if nafter <= now {
            return false;
        }
    }
    if let Some(c) = &p.client_name {
        if *c != client.name {
            return false;
        }
    }
    match (&p.secret_name, &p.secret_tag) {
        (Some(name), _) => *name == req.secret_name,
        (None, Some(tag)) => secret_tags.iter().any(|t| t == tag),
        (None, None) => true,
    }
}

/// Overlap rule for deny rows: scopes intersect when every dimension
/// intersects; an empty side is unconstrained and always intersects.
fn scopes_overlap(p: &PolicyRow, req: &Constraints) -> bool {
    let origins_overlap = p.origins.is_empty()
        || req.origins.is_empty()
        || p.origins
            .iter()
            .any(|po| req.origins.iter().any(|ro| po.same_target(ro)));

    let methods_overlap = p.methods.is_empty()
        || req.methods.is_empty()
        || p.methods
            .iter()
            .any(|pm| req.methods.iter().any(|rm| pm.eq_ignore_ascii_case(rm)));

    // Deny rows fail closed: prefixes are compared ASCII-case-insensitively
    // (like methods just above) so a deny on `/admin` cannot be dodged by
    // requesting `/Admin` and letting a broader allow row win. Widening the
    // deny is the safe direction; the subset rule for non-deny rows keeps the
    // exact, case-sensitive segment-boundary match of `prefix_matches`.
    let prefixes_overlap = p.path_prefixes.is_empty()
        || req.path_prefixes.is_empty()
        || p.path_prefixes.iter().any(|pp| {
            let pp = pp.to_ascii_lowercase();
            req.path_prefixes.iter().any(|rp| {
                let rp = rp.to_ascii_lowercase();
                paths::prefix_matches(&pp, &rp) || paths::prefix_matches(&rp, &pp)
            })
        });

    origins_overlap && methods_overlap && prefixes_overlap
}

/// Subset rule for non-deny rows: the requested constraints must fit within
/// the row's in every dimension.
///
/// An empty vector means "unconstrained" (the whole universe) on both sides,
/// so an unconstrained *request* dimension only fits a row that is itself
/// unconstrained in that dimension — a broad request can never match a narrow
/// row (DESIGN §5: "ambiguity can never widen access").
fn request_is_subset(p: &PolicyRow, req: &Constraints) -> bool {
    // Origins.
    let origins_ok = if req.origins.is_empty() {
        p.origins.is_empty()
    } else {
        p.origins.is_empty()
            || req
                .origins
                .iter()
                .all(|ro| p.origins.iter().any(|po| po.same_target(ro)))
    };
    if !origins_ok {
        return false;
    }

    // Methods (case-insensitive).
    let methods_ok = if req.methods.is_empty() {
        p.methods.is_empty()
    } else {
        p.methods.is_empty()
            || req
                .methods
                .iter()
                .all(|rm| p.methods.iter().any(|pm| pm.eq_ignore_ascii_case(rm)))
    };
    if !methods_ok {
        return false;
    }

    // Path prefixes: every requested prefix covered by some row prefix.
    let prefixes_ok = if req.path_prefixes.is_empty() {
        p.path_prefixes.is_empty()
    } else {
        p.path_prefixes.is_empty()
            || req.path_prefixes.iter().all(|rp| {
                p.path_prefixes
                    .iter()
                    .any(|pp| paths::prefix_matches(pp, rp))
            })
    };
    if !prefixes_ok {
        return false;
    }

    // TTL: row None = unlimited.
    if let Some(max_ttl) = p.max_ttl_seconds {
        if req.ttl_seconds > max_ttl {
            return false;
        }
    }

    // Uses: requested None = unlimited, which only fits a row with None.
    match (req.max_uses, p.max_uses) {
        (_, None) => {}
        (None, Some(_)) => return false,
        (Some(r), Some(m)) => {
            if r > m {
                return false;
            }
        }
    }

    true
}

/// Precedence: client-specific beats wildcard; exact secret beats tag beats
/// wildcard; then higher priority int; then most restrictive outcome; then
/// earlier `not_after` (a full tie must not mint a longer-lived grant just
/// because of row order — `policy_not_after` caps the grant); finally the row
/// id, so the order is total and evaluation is independent of input order
/// (the DB only orders rows by the non-unique `created_at`).
/// Higher key wins under `max_by_key`.
fn precedence_key(p: &PolicyRow) -> (u8, u8, i32, u8, std::cmp::Reverse<DateTime<Utc>>, Uuid) {
    let client_spec = u8::from(p.client_name.is_some());
    let secret_spec: u8 = if p.secret_name.is_some() {
        2
    } else if p.secret_tag.is_some() {
        1
    } else {
        0
    };
    (
        client_spec,
        secret_spec,
        p.priority,
        p.outcome.restrictiveness(),
        // No expiry sorts as latest: it is the least restrictive cap.
        std::cmp::Reverse(p.not_after.unwrap_or(DateTime::<Utc>::MAX_UTC)),
        p.id,
    )
}

#[cfg(test)]
mod tests {
    use super::paths::{canonicalize, prefix_matches};
    use super::*;
    use chrono::Duration;

    // ---------- method tokens ----------

    #[test]
    fn http_method_token_syntax() {
        for good in [
            "GET",
            "get",
            "PATCH",
            "M-SEARCH",
            "X-FOO",
            "NOTIFY",
            "a1!#$%&'*+-.^_`|~",
        ] {
            assert!(is_valid_http_method(good), "expected accept: {good:?}");
        }
        for bad in [
            "",
            "bad method",
            "GET GET",
            "GE\tT",
            "GET\n",
            "GET/1",
            "(GET)",
            "GET,POST",
            "\u{e9}",
        ] {
            assert!(!is_valid_http_method(bad), "expected reject: {bad:?}");
        }
        assert!(is_valid_http_method(&"A".repeat(MAX_HTTP_METHOD_LEN)));
        assert!(!is_valid_http_method(&"A".repeat(MAX_HTTP_METHOD_LEN + 1)));
    }

    // ---------- canonicalize ----------

    #[test]
    fn canonicalize_table() {
        let ok: &[(&str, &str)] = &[
            ("/", "/"),
            ("/v1/account", "/v1/account"),
            ("/%41bc", "/Abc"),
            ("/a%20b", "/a b"),
            ("/a%25b", "/a%b"), // decoded once: literal '%' survives
            ("/a/b/", "/a/b/"),
            ("/caf%C3%A9", "/café"),
            ("/...x", "/...x"),         // not a dot segment
            ("/v1;p=1/x", "/v1;p=1/x"), // path params on a non-dot segment
            ("/x;..", "/x;.."),         // '..' only after ';' — base is "x"
        ];
        for (raw, want) in ok {
            assert_eq!(canonicalize(raw).as_deref(), Ok(*want), "raw={raw:?}");
        }

        let bad: &[&str] = &[
            "no-slash",
            "",
            "/a%2Fb",                   // encoded '/'
            "/a%2fb",                   // encoded '/', lowercase
            "/a%5Cb",                   // encoded '\'
            "/a%5cb",                   // encoded '\', lowercase
            "/a\\b",                    // raw backslash
            "/a/./b",                   // dot segment
            "/a/../b",                  // dot-dot segment
            "/..",                      // trailing dot-dot
            "/.",                       // trailing dot
            "/a/..",                    // dot-dot at end
            "/%GG",                     // bad hex
            "/%2",                      // truncated escape
            "/%",                       // bare percent
            "/a%0Ab",                   // encoded control char (LF)
            "/a\u{7}b",                 // raw control char
            "/%00",                     // NUL
            "/%FF%FE",                  // non-UTF8 after decode
            "/..;/x",                   // dot-dot hidden behind a path parameter
            "/..;jsessionid=1/x",       // servlet-style '..;params'
            "/..%3b/x",                 // encoded ';' decodes to '..;'
            "/..%3B/x",                 // uppercase hex spelling
            "/.;/x",                    // single-dot behind a path parameter
            "/.;x",                     // single-dot with params, no trailing slash
            "/v1/account/..;/v1/admin", // full escape shape from the report
            "//",                       // all-slash: would strip to an unconstrained prefix
            "///",                      // all-slash
            "/a//b",                    // duplicate slash (empty segment)
            "/a/b//",                   // trailing duplicate slash
        ];
        for raw in bad {
            assert!(canonicalize(raw).is_err(), "expected reject: {raw:?}");
        }
    }

    // ---------- prefix_matches ----------

    #[test]
    fn prefix_matches_table() {
        let cases: &[(&str, &str, bool)] = &[
            ("/", "/anything/at/all", true),
            ("/", "/", true),
            ("/v1/account", "/v1/account", true),
            ("/v1/account", "/v1/account/settings", true),
            ("/v1/account", "/v1/account-delete", false),
            ("/v1/account", "/v1/accoun", false),
            ("/v1/account/", "/v1/account", true), // trailing slash stripped
            ("/v1/account/", "/v1/account/x", true),
            ("/v1", "/v2/x", false),
            // Non-canonical all-slash prefixes fail closed (never match),
            // and canonicalize() rejects them before they can be stored.
            ("//", "/anything", false),
            ("///", "/anything", false),
        ];
        for (prefix, path, want) in cases {
            assert_eq!(
                prefix_matches(prefix, path),
                *want,
                "prefix={prefix:?} path={path:?}"
            );
        }
    }

    // ---------- evaluate: fixtures ----------

    fn now() -> DateTime<Utc> {
        DateTime::parse_from_rfc3339("2026-07-28T12:00:00Z")
            .unwrap()
            .with_timezone(&Utc)
    }

    fn client() -> ClientRow {
        ClientRow {
            name: "family-assistant".into(),
            enabled: true,
            max_tier: Tier::Direct,
            allowed_mechanisms: vec![
                Mechanism::Brokered,
                Mechanism::Autofill,
                Mechanism::CliRead,
                Mechanism::DirectRead,
            ],
        }
    }

    fn secret() -> SecretRow {
        SecretRow {
            name: "example-api-token".into(),
            enabled: true,
            max_tier: Tier::Direct,
            operator_vetted: true,
        }
    }

    /// A client-deposited secret no operator has reviewed yet.
    fn unvetted_secret() -> SecretRow {
        SecretRow {
            operator_vetted: false,
            ..secret()
        }
    }

    fn origin(s: &str) -> Origin {
        Origin::parse(s).unwrap()
    }

    fn req_brokered() -> RequestedGrant {
        RequestedGrant {
            secret_name: "example-api-token".into(),
            mechanism: Mechanism::Brokered,
            constraints: Constraints {
                origins: vec![origin("api.example.com")],
                methods: vec!["GET".into()],
                path_prefixes: vec!["/v1/account".into()],
                ttl_seconds: 3600,
                max_uses: Some(5),
            },
        }
    }

    /// A row that is wildcard in every dimension EXCEPT origin, which names
    /// the origin `req_brokered()` asks for: a brokered row that grants
    /// without naming an origin is clamped to require-approval (it would
    /// otherwise release the credential to any host the client picks), so the
    /// precedence tests below would all measure that clamp instead of what
    /// they mean to. Tests about origin matching set `origins` themselves.
    fn row(outcome: Outcome) -> PolicyRow {
        PolicyRow {
            id: Uuid::new_v4(),
            client_name: None,
            secret_name: None,
            secret_tag: None,
            mechanism: Mechanism::Brokered,
            outcome,
            priority: 0,
            origins: vec![origin("api.example.com")],
            methods: vec![],
            path_prefixes: vec![],
            max_ttl_seconds: None,
            max_uses: None,
            not_after: None,
        }
    }

    fn eval(
        client: &ClientRow,
        secret: Option<&SecretRow>,
        tags: &[String],
        req: &RequestedGrant,
        policies: &[PolicyRow],
    ) -> Evaluation {
        evaluate(client, secret, tags, req, policies, now())
    }

    fn assert_deny(e: &Evaluation) {
        assert!(
            matches!(e.decision, Decision::Deny { .. }),
            "expected Deny, got {:?}",
            e.decision
        );
    }

    // ---------- evaluate: hard caps ----------

    #[test]
    fn disabled_client_denied() {
        let mut c = client();
        c.enabled = false;
        assert_deny(&eval(&c, Some(&secret()), &[], &req_brokered(), &[]));
    }

    #[test]
    fn mechanism_not_in_client_list_denied() {
        let mut c = client();
        c.allowed_mechanisms = vec![Mechanism::Brokered];
        let mut r = req_brokered();
        r.mechanism = Mechanism::CliRead;
        assert_deny(&eval(&c, Some(&secret()), &[], &r, &[]));
    }

    #[test]
    fn tier_over_client_cap_denied() {
        let mut c = client();
        c.max_tier = Tier::TrustedClient;
        let mut r = req_brokered();
        r.mechanism = Mechanism::DirectRead;
        assert_deny(&eval(&c, Some(&secret()), &[], &r, &[]));
    }

    #[test]
    fn tier_over_secret_cap_denied() {
        let mut s = secret();
        s.max_tier = Tier::Brokered;
        let mut r = req_brokered();
        r.mechanism = Mechanism::CliRead;
        assert_deny(&eval(&client(), Some(&s), &[], &r, &[]));
    }

    #[test]
    fn disabled_secret_denied() {
        let mut s = secret();
        s.enabled = false;
        assert_deny(&eval(&client(), Some(&s), &[], &req_brokered(), &[]));
    }

    #[test]
    fn secret_cap_not_applied_when_unknown() {
        // Unknown secret: no secret-tier cap; falls through to RequireApproval.
        let e = eval(&client(), None, &[], &req_brokered(), &[]);
        assert_eq!(e.decision, Decision::RequireApproval);
        assert_eq!(e.policy_id, None);
    }

    // ---------- evaluate: deny overlap ----------

    #[test]
    fn deny_all_dimensions_empty_fires() {
        let p = row(Outcome::Deny); // all dims empty = deny-all for this mechanism
        let id = p.id;
        let e = eval(&client(), Some(&secret()), &[], &req_brokered(), &[p]);
        assert_deny(&e);
        assert_eq!(e.policy_id, Some(id));
    }

    #[test]
    fn deny_non_overlapping_origin_does_not_fire() {
        let mut p = row(Outcome::Deny);
        p.origins = vec![origin("other.example.com")];
        let e = eval(&client(), Some(&secret()), &[], &req_brokered(), &[p]);
        assert_eq!(e.decision, Decision::RequireApproval);
    }

    #[test]
    fn deny_overlapping_prefix_either_direction_fires() {
        // Row prefix is NARROWER than the request: still overlaps.
        let mut p = row(Outcome::Deny);
        p.path_prefixes = vec!["/v1/account/danger".into()];
        assert_deny(&eval(
            &client(),
            Some(&secret()),
            &[],
            &req_brokered(),
            &[p],
        ));

        // Row prefix is BROADER than the request: overlaps too.
        let mut p = row(Outcome::Deny);
        p.path_prefixes = vec!["/v1".into()];
        assert_deny(&eval(
            &client(),
            Some(&secret()),
            &[],
            &req_brokered(),
            &[p],
        ));
    }

    #[test]
    fn deny_disjoint_prefix_does_not_fire() {
        let mut p = row(Outcome::Deny);
        p.path_prefixes = vec!["/v2".into()];
        let e = eval(&client(), Some(&secret()), &[], &req_brokered(), &[p]);
        assert_eq!(e.decision, Decision::RequireApproval);
    }

    #[test]
    fn deny_method_case_insensitive_overlap() {
        let mut p = row(Outcome::Deny);
        p.methods = vec!["get".into()];
        assert_deny(&eval(
            &client(),
            Some(&secret()),
            &[],
            &req_brokered(),
            &[p],
        ));
    }

    #[test]
    fn deny_beats_matching_auto_approve() {
        let allow = row(Outcome::AutoApprove);
        let deny = row(Outcome::Deny);
        assert_deny(&eval(
            &client(),
            Some(&secret()),
            &[],
            &req_brokered(),
            &[allow, deny],
        ));
    }

    #[test]
    fn deny_prefix_overlap_is_case_insensitive() {
        // A deny on "/admin" cannot be dodged by requesting "/Admin", even
        // when a broader auto-approve row would otherwise win.
        let mut deny = row(Outcome::Deny);
        deny.path_prefixes = vec!["/admin".into()];
        let allow = row(Outcome::AutoApprove); // unconstrained: covers all
        let mut r = req_brokered();
        r.constraints.path_prefixes = vec!["/Admin".into()];
        assert_deny(&eval(&client(), Some(&secret()), &[], &r, &[allow, deny]));

        // The other direction too: uppercase deny row, lowercase request.
        let mut deny = row(Outcome::Deny);
        deny.path_prefixes = vec!["/Admin/Danger".into()];
        let mut r = req_brokered();
        r.constraints.path_prefixes = vec!["/admin".into()];
        assert_deny(&eval(&client(), Some(&secret()), &[], &r, &[deny]));

        // Disjoint paths still do not fire regardless of case.
        let mut deny = row(Outcome::Deny);
        deny.path_prefixes = vec!["/Admin".into()];
        let mut r = req_brokered();
        r.constraints.path_prefixes = vec!["/administrator".into()];
        let e = eval(&client(), Some(&secret()), &[], &r, &[deny]);
        assert_eq!(e.decision, Decision::RequireApproval);
    }

    #[test]
    fn deny_prefix_boundary_no_false_overlap() {
        // "/v1/account" deny row vs "/v1/account-delete" request: no overlap.
        let mut p = row(Outcome::Deny);
        p.path_prefixes = vec!["/v1/account".into()];
        let mut r = req_brokered();
        r.constraints.path_prefixes = vec!["/v1/account-delete".into()];
        let e = eval(&client(), Some(&secret()), &[], &r, &[p]);
        assert_eq!(e.decision, Decision::RequireApproval);
    }

    // ---------- evaluate: subset rule ----------

    #[test]
    fn subset_all_dimensions_auto_approves() {
        let mut p = row(Outcome::AutoApprove);
        p.origins = vec![origin("api.example.com"), origin("api2.example.com")];
        p.methods = vec!["GET".into(), "POST".into()];
        p.path_prefixes = vec!["/v1".into()];
        p.max_ttl_seconds = Some(7200);
        p.max_uses = Some(10);
        let e = eval(
            &client(),
            Some(&secret()),
            &[],
            &req_brokered(),
            &[p.clone()],
        );
        assert_eq!(e.decision, Decision::AutoApprove);
        assert_eq!(e.policy_id, Some(p.id));
    }

    #[test]
    fn origin_superset_request_falls_through() {
        // Request asks for an origin the row does not include.
        let mut p = row(Outcome::AutoApprove);
        p.origins = vec![origin("other.example.com")];
        let e = eval(&client(), Some(&secret()), &[], &req_brokered(), &[p]);
        assert_eq!(e.decision, Decision::RequireApproval);
        assert_eq!(e.policy_id, None);
    }

    #[test]
    fn unconstrained_request_dim_only_fits_unconstrained_row() {
        // Request with no origin constraint (= any origin) must not match a
        // row constrained to one origin.
        let mut p = row(Outcome::AutoApprove);
        p.origins = vec![origin("api.example.com")];
        let mut r = req_brokered();
        r.constraints.origins = vec![];
        let e = eval(&client(), Some(&secret()), &[], &r, &[p]);
        assert_eq!(e.decision, Decision::RequireApproval);
    }

    #[test]
    fn method_subset_case_insensitive() {
        let mut p = row(Outcome::AutoApprove);
        p.methods = vec!["get".into(), "post".into()];
        let e = eval(&client(), Some(&secret()), &[], &req_brokered(), &[p]);
        assert_eq!(e.decision, Decision::AutoApprove);
    }

    #[test]
    fn prefix_not_covered_falls_through() {
        let mut p = row(Outcome::AutoApprove);
        p.path_prefixes = vec!["/v1/account-delete".into()];
        let e = eval(&client(), Some(&secret()), &[], &req_brokered(), &[p]);
        assert_eq!(e.decision, Decision::RequireApproval);
    }

    #[test]
    fn ttl_over_cap_falls_through() {
        let mut p = row(Outcome::AutoApprove);
        p.max_ttl_seconds = Some(600);
        let e = eval(&client(), Some(&secret()), &[], &req_brokered(), &[p]);
        assert_eq!(e.decision, Decision::RequireApproval);
    }

    #[test]
    fn uses_over_cap_falls_through() {
        let mut p = row(Outcome::AutoApprove);
        p.max_uses = Some(2); // request asks for 5
        let e = eval(&client(), Some(&secret()), &[], &req_brokered(), &[p]);
        assert_eq!(e.decision, Decision::RequireApproval);
    }

    #[test]
    fn unlimited_uses_request_only_fits_unlimited_row() {
        let mut p = row(Outcome::AutoApprove);
        p.max_uses = Some(100);
        let mut r = req_brokered();
        r.constraints.max_uses = None;
        let e = eval(&client(), Some(&secret()), &[], &r, &[p.clone()]);
        assert_eq!(e.decision, Decision::RequireApproval);

        p.max_uses = None;
        let e = eval(&client(), Some(&secret()), &[], &r, &[p]);
        assert_eq!(e.decision, Decision::AutoApprove);
    }

    // ---------- evaluate: applicability filter ----------

    #[test]
    fn wrong_mechanism_row_ignored() {
        let mut p = row(Outcome::AutoApprove);
        p.mechanism = Mechanism::CliRead;
        let e = eval(&client(), Some(&secret()), &[], &req_brokered(), &[p]);
        assert_eq!(e.decision, Decision::RequireApproval);
    }

    #[test]
    fn other_client_row_ignored() {
        let mut p = row(Outcome::AutoApprove);
        p.client_name = Some("k8s-agent".into());
        let e = eval(&client(), Some(&secret()), &[], &req_brokered(), &[p]);
        assert_eq!(e.decision, Decision::RequireApproval);
    }

    #[test]
    fn other_secret_row_ignored_and_tag_row_matches() {
        let mut p = row(Outcome::AutoApprove);
        p.secret_name = Some("some-other-secret".into());
        let e = eval(&client(), Some(&secret()), &[], &req_brokered(), &[p]);
        assert_eq!(e.decision, Decision::RequireApproval);

        let mut p = row(Outcome::AutoApprove);
        p.secret_tag = Some("api-tokens".into());
        let tags = vec!["api-tokens".to_string()];
        let e = eval(&client(), Some(&secret()), &tags, &req_brokered(), &[p]);
        assert_eq!(e.decision, Decision::AutoApprove);

        let mut p = row(Outcome::AutoApprove);
        p.secret_tag = Some("api-tokens".into());
        let e = eval(&client(), Some(&secret()), &[], &req_brokered(), &[p]);
        assert_eq!(e.decision, Decision::RequireApproval);
    }

    #[test]
    fn expired_row_ignored() {
        let mut p = row(Outcome::AutoApprove);
        p.not_after = Some(now() - Duration::hours(1));
        let e = eval(&client(), Some(&secret()), &[], &req_brokered(), &[p]);
        assert_eq!(e.decision, Decision::RequireApproval);

        // Expired deny rows do not fire either.
        let mut p = row(Outcome::Deny);
        p.not_after = Some(now() - Duration::hours(1));
        let e = eval(&client(), Some(&secret()), &[], &req_brokered(), &[p]);
        assert_eq!(e.decision, Decision::RequireApproval);
    }

    #[test]
    fn row_expiring_exactly_now_ignored() {
        let mut p = row(Outcome::AutoApprove);
        p.not_after = Some(now());
        let e = eval(&client(), Some(&secret()), &[], &req_brokered(), &[p]);
        assert_eq!(e.decision, Decision::RequireApproval);
    }

    // ---------- evaluate: precedence ----------

    #[test]
    fn client_specific_beats_wildcard() {
        let mut specific = row(Outcome::NotifyOnly);
        specific.client_name = Some("family-assistant".into());
        let wildcard = row(Outcome::AutoApprove);
        let e = eval(
            &client(),
            Some(&secret()),
            &[],
            &req_brokered(),
            &[wildcard, specific.clone()],
        );
        assert_eq!(e.decision, Decision::NotifyOnly);
        assert_eq!(e.policy_id, Some(specific.id));
    }

    #[test]
    fn exact_secret_beats_tag_beats_wildcard() {
        let mut exact = row(Outcome::NotifyOnly);
        exact.secret_name = Some("example-api-token".into());
        let mut tag = row(Outcome::AutoApprove);
        tag.secret_tag = Some("api-tokens".into());
        let wildcard = row(Outcome::AutoApprove);
        let tags = vec!["api-tokens".to_string()];

        let e = eval(
            &client(),
            Some(&secret()),
            &tags,
            &req_brokered(),
            &[wildcard.clone(), tag.clone(), exact.clone()],
        );
        assert_eq!(e.policy_id, Some(exact.id));

        // Without the exact row, tag beats wildcard.
        let mut tag2 = row(Outcome::NotifyOnly);
        tag2.secret_tag = Some("api-tokens".into());
        let e = eval(
            &client(),
            Some(&secret()),
            &tags,
            &req_brokered(),
            &[wildcard, tag2.clone()],
        );
        assert_eq!(e.policy_id, Some(tag2.id));
    }

    #[test]
    fn higher_priority_wins() {
        let mut low = row(Outcome::NotifyOnly);
        low.priority = 1;
        let mut high = row(Outcome::AutoApprove);
        high.priority = 5;
        let e = eval(
            &client(),
            Some(&secret()),
            &[],
            &req_brokered(),
            &[low, high.clone()],
        );
        assert_eq!(e.decision, Decision::AutoApprove);
        assert_eq!(e.policy_id, Some(high.id));
    }

    #[test]
    fn residual_tie_most_restrictive_wins() {
        let auto = row(Outcome::AutoApprove);
        let notify = row(Outcome::NotifyOnly);
        let require = row(Outcome::RequireApproval);
        let e = eval(
            &client(),
            Some(&secret()),
            &[],
            &req_brokered(),
            &[auto.clone(), notify.clone(), require.clone()],
        );
        assert_eq!(e.decision, Decision::RequireApproval);
        assert_eq!(e.policy_id, Some(require.id));

        let e = eval(
            &client(),
            Some(&secret()),
            &[],
            &req_brokered(),
            &[auto, notify.clone()],
        );
        assert_eq!(e.decision, Decision::NotifyOnly);
        assert_eq!(e.policy_id, Some(notify.id));
    }

    #[test]
    fn brokered_row_without_origins_never_grants_unattended() {
        // An empty `origins` is "any origin", and a brokered grant sends the
        // real credential TO that origin: auto-approving here would let a
        // client name attacker.example and have the secret injected into a
        // request to it, with no push (only notify-only pushes) and no
        // operator in the loop. Both granting outcomes clamp to
        // require-approval; the row still matches, it just cannot release.
        for outcome in [Outcome::AutoApprove, Outcome::NotifyOnly] {
            let mut p = row(outcome);
            p.origins = vec![];
            let mut r = req_brokered();
            r.constraints.origins = vec![origin("attacker.example")];
            let e = eval(&client(), Some(&secret()), &[], &r, &[p.clone()]);
            assert_eq!(
                e.decision,
                Decision::RequireApproval,
                "{outcome:?} row with no origins must not grant unattended"
            );
            assert_eq!(e.policy_id, Some(p.id));
        }
        // Naming the origin the client asked for is what makes it grantable.
        let mut p = row(Outcome::AutoApprove);
        p.origins = vec![origin("api.example.com")];
        let e = eval(&client(), Some(&secret()), &[], &req_brokered(), &[p]);
        assert_eq!(e.decision, Decision::AutoApprove);
        // Non-brokered mechanisms are unaffected: they release to the caller,
        // not to a client-named host, so an unconstrained row is not a
        // redirection vector.
        let mut p = row(Outcome::AutoApprove);
        p.origins = vec![];
        p.mechanism = Mechanism::CliRead;
        let mut r = req_brokered();
        r.mechanism = Mechanism::CliRead;
        r.constraints.origins = vec![];
        r.constraints.methods = vec![];
        r.constraints.path_prefixes = vec![];
        let e = eval(&client(), Some(&secret()), &[], &r, &[p]);
        assert_eq!(e.decision, Decision::AutoApprove);
    }

    #[test]
    fn full_tie_prefers_restrictive_expiry_regardless_of_order() {
        // Same specificity, priority and outcome, different not_after: the
        // earlier expiry must cap the grant, whichever order the rows arrive
        // in (the DB only orders by the non-unique created_at).
        let mut short = row(Outcome::AutoApprove);
        short.not_after = Some(now() + Duration::hours(1));
        let mut long = row(Outcome::AutoApprove);
        long.not_after = Some(now() + Duration::days(30));
        let mut unlimited = row(Outcome::AutoApprove);
        unlimited.not_after = None;
        for rows in [
            vec![short.clone(), long.clone(), unlimited.clone()],
            vec![unlimited.clone(), long.clone(), short.clone()],
            vec![long.clone(), unlimited.clone(), short.clone()],
        ] {
            let e = eval(&client(), Some(&secret()), &[], &req_brokered(), &rows);
            assert_eq!(e.policy_id, Some(short.id));
            assert_eq!(e.policy_not_after, short.not_after);
        }
        // Identical rows apart from id: the winner is order-independent.
        let a = row(Outcome::AutoApprove);
        let b = row(Outcome::AutoApprove);
        let e1 = eval(
            &client(),
            Some(&secret()),
            &[],
            &req_brokered(),
            &[a.clone(), b.clone()],
        );
        let e2 = eval(&client(), Some(&secret()), &[], &req_brokered(), &[b, a]);
        assert_eq!(e1.policy_id, e2.policy_id);
    }

    #[test]
    fn specificity_beats_priority() {
        // A wildcard row with huge priority loses to a client-specific row.
        let mut wildcard = row(Outcome::AutoApprove);
        wildcard.priority = 1000;
        let mut specific = row(Outcome::NotifyOnly);
        specific.client_name = Some("family-assistant".into());
        specific.priority = 0;
        let e = eval(
            &client(),
            Some(&secret()),
            &[],
            &req_brokered(),
            &[wildcard, specific.clone()],
        );
        assert_eq!(e.decision, Decision::NotifyOnly);
        assert_eq!(e.policy_id, Some(specific.id));
    }

    // ---------- evaluate: unknown secret & not_after propagation ----------

    #[test]
    fn no_matching_row_requires_approval() {
        let e = eval(&client(), Some(&secret()), &[], &req_brokered(), &[]);
        assert_eq!(e.decision, Decision::RequireApproval);
        assert_eq!(e.policy_id, None);
        assert_eq!(e.policy_not_after, None);
    }

    #[test]
    fn unknown_secret_clamps_auto_approve_and_notify() {
        let p = row(Outcome::AutoApprove);
        let e = eval(&client(), None, &[], &req_brokered(), &[p]);
        assert_eq!(e.decision, Decision::RequireApproval);

        let p = row(Outcome::NotifyOnly);
        let e = eval(&client(), None, &[], &req_brokered(), &[p]);
        assert_eq!(e.decision, Decision::RequireApproval);

        // Deny still denies for unknown secrets.
        let p = row(Outcome::Deny);
        assert_deny(&eval(&client(), None, &[], &req_brokered(), &[p]));
    }

    /// A client deposit must not be able to satisfy a standing auto-approve or
    /// notify-only row. The depositing client picks the name, so without this
    /// clamp it could create a row matching a name-scoped OR wildcard policy
    /// and have bytes no human ever saw released with nobody in the loop.
    #[test]
    fn unvetted_secret_clamps_auto_approve_and_notify() {
        let p = row(Outcome::AutoApprove);
        let e = eval(
            &client(),
            Some(&unvetted_secret()),
            &[],
            &req_brokered(),
            &[p],
        );
        assert_eq!(e.decision, Decision::RequireApproval);

        let p = row(Outcome::NotifyOnly);
        let e = eval(
            &client(),
            Some(&unvetted_secret()),
            &[],
            &req_brokered(),
            &[p],
        );
        assert_eq!(e.decision, Decision::RequireApproval);

        // A wildcard row (no secret_name) is the same story — the clamp is on
        // the secret, not on how the row selected it.
        let mut p = row(Outcome::AutoApprove);
        p.secret_name = None;
        let e = eval(
            &client(),
            Some(&unvetted_secret()),
            &[],
            &req_brokered(),
            &[p],
        );
        assert_eq!(e.decision, Decision::RequireApproval);

        // Deny still denies, and an operator-vetted secret still auto-approves.
        let p = row(Outcome::Deny);
        assert_deny(&eval(
            &client(),
            Some(&unvetted_secret()),
            &[],
            &req_brokered(),
            &[p],
        ));
        let p = row(Outcome::AutoApprove);
        let e = eval(&client(), Some(&secret()), &[], &req_brokered(), &[p]);
        assert_eq!(e.decision, Decision::AutoApprove);
    }

    #[test]
    fn policy_not_after_propagates_to_evaluation() {
        let mut p = row(Outcome::AutoApprove);
        let exp = now() + Duration::hours(6);
        p.not_after = Some(exp);
        let e = eval(
            &client(),
            Some(&secret()),
            &[],
            &req_brokered(),
            &[p.clone()],
        );
        assert_eq!(e.decision, Decision::AutoApprove);
        assert_eq!(e.policy_not_after, Some(exp));
        assert_eq!(e.policy_id, Some(p.id));
    }
}
