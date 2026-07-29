//! Config file (YAML) loading. Shape pinned in docs/IMPLEMENTATION.md.

use anyhow::{bail, Context};
use keychute_types::{Mechanism, Tier};
use serde::Deserialize;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Deserialize)]
pub struct Config {
    pub listen_addr: String,
    /// External base URL used in push approval links, e.g. https://keychute.example.dev
    pub external_url: String,
    #[serde(default)]
    pub tls: Option<TlsConfig>,
    /// Plaintext HTTP requires explicit opt-in (addendum #7). Loopback only
    /// unless `allow_insecure_http_non_loopback` is also set.
    #[serde(default)]
    pub allow_insecure_http: bool,
    #[serde(default)]
    pub allow_insecure_http_non_loopback: bool,
    #[serde(default)]
    pub database_url: Option<String>,
    pub kek_file: PathBuf,
    pub human_auth: HumanAuthConfig,
    #[serde(default)]
    pub clients: Vec<ClientConfig>,
    #[serde(default)]
    pub tokenreview_url: Option<String>,
    #[serde(default)]
    pub tokenreview_token_path: Option<PathBuf>,
    #[serde(default)]
    pub tokenreview_ca_path: Option<PathBuf>,
    /// Optional PEM bundle of additional root CAs trusted by the outbound
    /// (brokered-proxy) HTTP client — for upstream origins behind an internal
    /// CA. System roots remain trusted.
    #[serde(default)]
    pub upstream_ca_path: Option<PathBuf>,
    #[serde(default)]
    pub pushover: Option<PushoverConfig>,
    #[serde(default)]
    pub limits: Limits,
}

#[derive(Debug, Clone, Deserialize)]
pub struct TlsConfig {
    pub cert_path: PathBuf,
    pub key_path: PathBuf,
}

#[derive(Debug, Clone, Deserialize)]
pub struct HumanAuthConfig {
    pub mode: HumanAuthMode,
    #[serde(default)]
    pub r#static: Option<StaticHumanAuth>,
    #[serde(default)]
    pub oidc: Option<OidcHumanAuth>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum HumanAuthMode {
    Static,
    Oidc,
}

#[derive(Debug, Clone, Deserialize)]
pub struct StaticHumanAuth {
    /// hex SHA-256 of the bearer token
    pub token_sha256: String,
    pub subject: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct OidcHumanAuth {
    pub issuer: String,
    pub audience: String,
    pub jwks_url: String,
    #[serde(default)]
    pub allowed_subjects: Vec<String>,
    #[serde(default)]
    pub allowed_group: Option<String>,
    #[serde(default = "default_group_claim")]
    pub group_claim: String,
    /// Allowed clock skew for exp/nbf, seconds.
    #[serde(default = "default_skew")]
    pub clock_skew_seconds: u64,
}

fn default_group_claim() -> String {
    "groups".into()
}
fn default_skew() -> u64 {
    60
}

#[derive(Debug, Clone, Deserialize)]
pub struct ClientConfig {
    pub name: String,
    pub max_tier: Tier,
    pub mechanisms: Vec<Mechanism>,
    pub auth: ClientAuthConfig,
    /// May this client deposit NEW secrets via `POST /v1/secrets`? Default
    /// false: depositing is a write the operator opts into per client, and it
    /// never permits replacing an existing secret (rotation stays operator-only).
    #[serde(default)]
    pub may_store_secrets: bool,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ClientAuthConfig {
    #[serde(default)]
    pub api_token_sha256: Option<String>,
    #[serde(default)]
    pub service_account: Option<ServiceAccountAuth>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ServiceAccountAuth {
    pub audience: String,
    pub subject: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct PushoverConfig {
    #[serde(default = "default_pushover_base")]
    pub base_url: String,
    #[serde(default)]
    pub token: Option<String>,
    #[serde(default)]
    pub token_path: Option<PathBuf>,
    #[serde(default)]
    pub user_key: Option<String>,
    #[serde(default)]
    pub user_key_path: Option<PathBuf>,
}

fn default_pushover_base() -> String {
    "https://api.pushover.net".into()
}

#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct Limits {
    pub max_pending_per_client: i64,
    pub max_waits_per_client: usize,
    pub wait_max_seconds: u64,
    pub request_expiry_seconds: i64,
    pub proxy_max_body_bytes: usize,
    pub proxy_stream_deadline_seconds: u64,
    pub replay_window_seconds: i64,
    pub max_proxy_streams_per_client: usize,
    /// Client-initiated secret deposits (`POST /v1/secrets`) allowed per
    /// client per rolling hour. Each deposit pushes the operator and adds a
    /// row they may have to review, so an opted-in client that goes haywire
    /// (or is prompt-injected) must not be able to bury them. Counted from
    /// the audit log.
    pub max_deposits_per_hour_per_client: i64,
    /// How long the server keeps draining in-flight responses after a
    /// shutdown signal before closing what is left. 0 disables draining.
    ///
    /// Must fit INSIDE the pod's `terminationGracePeriodSeconds` (Kubernetes
    /// default 30 s), or the kubelet SIGKILLs us mid-drain and the drain was
    /// pointless — the default 25 s leaves ~5 s of headroom. Draining matters
    /// more than usual here: the chart pins `replicas: 1` + `Recreate`
    /// because an approval-time passthrough payload is wrapped under the
    /// PROCESS-LOCAL ephemeral KEK (DESIGN §5), so an in-flight passthrough
    /// read that is cut off is permanently unrecoverable — and a finite-use
    /// grant that already committed its use-accounting would lose that use
    /// without ever returning a response.
    pub drain_seconds: u64,
}

impl Default for Limits {
    fn default() -> Self {
        Limits {
            max_pending_per_client: 10,
            max_waits_per_client: 5,
            wait_max_seconds: 300,
            request_expiry_seconds: 3600,
            proxy_max_body_bytes: 10 * 1024 * 1024,
            proxy_stream_deadline_seconds: 300,
            replay_window_seconds: 60,
            max_proxy_streams_per_client: 8,
            max_deposits_per_hour_per_client: 20,
            drain_seconds: 25,
        }
    }
}

/// Refuse a plaintext `http://` URL to a non-loopback host for an outbound
/// endpoint that carries credentials (or, for JWKS, trust anchors). Loopback
/// hosts stay allowed for local development and tests; `insecure_ok` is the
/// explicit `allow_insecure_http_non_loopback` override. Non-http(s) schemes
/// are always rejected.
fn validate_outbound_https(what: &str, url: &str, insecure_ok: bool) -> anyhow::Result<()> {
    if let Some(rest) = url.strip_prefix("http://") {
        let hostport = rest.split(['/', '?', '#']).next().unwrap_or("");
        // Bracketed IPv6 first; else strip any :port.
        let host = match hostport.strip_prefix('[') {
            Some(v6) => v6.split(']').next().unwrap_or(""),
            None => hostport.split(':').next().unwrap_or(""),
        };
        let loopback = host.eq_ignore_ascii_case("localhost")
            || host
                .parse::<std::net::IpAddr>()
                .map(|ip| ip.is_loopback())
                .unwrap_or(false);
        if !loopback && !insecure_ok {
            bail!(
                "{what} {url} is plaintext HTTP to a non-loopback host: \
                 use https://, or set allow_insecure_http_non_loopback: true"
            );
        }
    } else if !url.starts_with("https://") {
        bail!("{what} {url} must be an http(s):// URL");
    }
    Ok(())
}

impl Config {
    pub fn load(path: &Path) -> anyhow::Result<Config> {
        let raw =
            std::fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
        let mut config: Config = serde_yaml::from_str(&raw).context("parsing config YAML")?;
        if let Ok(url) = std::env::var("KEYCHUTE_DATABASE_URL") {
            config.database_url = Some(url);
        }
        config.normalize();
        config.validate()?;
        Ok(config)
    }

    /// Normalize post-parse: token hashes compare against lowercase-hex
    /// SHA-256 digests, so uppercase config values would never authenticate.
    pub fn normalize(&mut self) {
        for c in &mut self.clients {
            if let Some(h) = &mut c.auth.api_token_sha256 {
                *h = h.trim().to_ascii_lowercase();
            }
        }
        if let Some(s) = &mut self.human_auth.r#static {
            s.token_sha256 = s.token_sha256.trim().to_ascii_lowercase();
        }
    }

    pub fn validate(&self) -> anyhow::Result<()> {
        if self.database_url.is_none() {
            bail!("database_url missing (config or KEYCHUTE_DATABASE_URL)");
        }
        if self.tls.is_none() {
            if !self.allow_insecure_http {
                bail!(
                    "no TLS configured: refusing plaintext HTTP without allow_insecure_http: true"
                );
            }
            let loopback = self
                .listen_addr
                .parse::<std::net::SocketAddr>()
                .map(|a| a.ip().is_loopback())
                .unwrap_or(false);
            if !loopback && !self.allow_insecure_http_non_loopback {
                bail!(
                    "refusing plaintext HTTP on non-loopback {} without allow_insecure_http_non_loopback: true",
                    self.listen_addr
                );
            }
        }
        match self.human_auth.mode {
            HumanAuthMode::Static => {
                let Some(s) = &self.human_auth.r#static else {
                    bail!("human_auth.mode=static requires human_auth.static");
                };
                // Same trap as a malformed client digest below: no bearer
                // token could ever match, silently locking the operator out.
                if s.token_sha256.len() != 64
                    || !s.token_sha256.bytes().all(|b| b.is_ascii_hexdigit())
                {
                    bail!(
                        "human_auth.static.token_sha256 must be a 64-character hex \
                         SHA-256 digest (got {} characters)",
                        s.token_sha256.len()
                    );
                }
            }
            HumanAuthMode::Oidc => {
                let oidc = self.human_auth.oidc.as_ref().ok_or_else(|| {
                    anyhow::anyhow!("human_auth.mode=oidc requires human_auth.oidc")
                })?;
                if oidc.allowed_subjects.is_empty() && oidc.allowed_group.is_none() {
                    bail!("oidc human auth requires allowed_subjects or allowed_group (authorization allowlist)");
                }
            }
        }
        for c in &self.clients {
            let has_token = c.auth.api_token_sha256.is_some();
            let has_sa = c.auth.service_account.is_some();
            // Exactly one binding: reconciliation stores both columns and
            // authn accepts either path, so two bindings silently widen what
            // can act as this client.
            if !has_token && !has_sa {
                bail!("client {} has no auth binding", c.name);
            }
            if has_token && has_sa {
                bail!(
                    "client {} has two auth bindings (api_token_sha256 and service_account): \
                     configure exactly one",
                    c.name
                );
            }
            // Authn looks tokens up by their lowercase 64-hex SHA-256 digest
            // (normalize() already lowercased this value): a malformed digest
            // would reconcile as an enabled client no token can ever match —
            // a healthy-looking deployment with a permanently locked-out
            // client. Fail startup instead.
            if let Some(h) = &c.auth.api_token_sha256 {
                if h.len() != 64 || !h.bytes().all(|b| b.is_ascii_hexdigit()) {
                    bail!(
                        "client {}: api_token_sha256 must be a 64-character hex \
                         SHA-256 digest (got {} characters)",
                        c.name,
                        h.len()
                    );
                }
            }
            if c.mechanisms.is_empty() {
                bail!("client {} has no allowed mechanisms", c.name);
            }
            // Service-account auth is resolved by Kubernetes TokenReview;
            // without an endpoint `authenticate_client` has nothing to call
            // and falls through to unauthenticated. Same trap as a malformed
            // token digest: the deployment looks healthy while the client can
            // never authenticate.
            if c.auth.service_account.is_some() && self.tokenreview_url.is_none() {
                bail!(
                    "client {} uses service_account auth but tokenreview_url is not set: \
                     no presented service-account token could ever be verified",
                    c.name
                );
            }
            for m in &c.mechanisms {
                if m.tier() > c.max_tier {
                    bail!(
                        "client {}: mechanism {} exceeds max_tier {}",
                        c.name,
                        m.as_str(),
                        c.max_tier.as_str()
                    );
                }
            }
        }
        // Security-critical limits must be sane: a nonpositive expiry stores
        // every request already-expired, a nonpositive replay window disables
        // idempotent replay, and zero pending/concurrency limits reject every
        // request, wait, or proxy stream. (Unsigned fields only need a zero
        // check; the i64 ones feed chrono/SQL arithmetic and can go negative.)
        let l = &self.limits;
        if l.request_expiry_seconds <= 0 {
            bail!(
                "limits.request_expiry_seconds must be positive (got {})",
                l.request_expiry_seconds
            );
        }
        if l.replay_window_seconds <= 0 {
            bail!(
                "limits.replay_window_seconds must be positive (got {})",
                l.replay_window_seconds
            );
        }
        if l.max_pending_per_client <= 0 {
            bail!(
                "limits.max_pending_per_client must be positive (got {})",
                l.max_pending_per_client
            );
        }
        if l.max_waits_per_client == 0 {
            bail!("limits.max_waits_per_client must be positive");
        }
        if l.max_proxy_streams_per_client == 0 {
            bail!("limits.max_proxy_streams_per_client must be positive");
        }
        // Zero or negative here would not "disable deposits" — the endpoint
        // stays routed and every deposit answers 429, a quiet outage for every
        // opted-in client. Withdrawing the capability is `may_store_secrets:
        // false` on the client, which says so.
        if l.max_deposits_per_hour_per_client <= 0 {
            bail!(
                "limits.max_deposits_per_hour_per_client must be positive (got {});                  to withhold deposits, unset may_store_secrets on the client",
                l.max_deposits_per_hour_per_client
            );
        }
        // Outbound endpoints that carry credentials must not be plaintext to
        // a non-loopback host (same rule as the listen side, same explicit
        // override): TokenReview posts the caller's SA token and the reviewer
        // credential; Pushover posts the app token and user key; a JWKS URL
        // is worse still — plaintext key fetch lets an on-path attacker
        // substitute a signing key and mint operator tokens.
        let insecure_ok = self.allow_insecure_http_non_loopback;
        if let Some(url) = &self.tokenreview_url {
            validate_outbound_https("tokenreview_url", url, insecure_ok)?;
        }
        if let Some(p) = &self.pushover {
            validate_outbound_https("pushover.base_url", &p.base_url, insecure_ok)?;
        }
        if let Some(oidc) = &self.human_auth.oidc {
            validate_outbound_https("human_auth.oidc.jwks_url", &oidc.jwks_url, insecure_ok)?;
        }
        // Zero here is never a usable configuration, only a quiet outage:
        // waits that return immediately, a body cap every nonempty payload
        // trips, and a proxy deadline that has elapsed before the upstream
        // send.
        if l.wait_max_seconds == 0 {
            bail!("limits.wait_max_seconds must be positive");
        }
        if l.proxy_max_body_bytes == 0 {
            bail!("limits.proxy_max_body_bytes must be positive");
        }
        if l.proxy_stream_deadline_seconds == 0 {
            bail!("limits.proxy_stream_deadline_seconds must be positive");
        }
        let names: std::collections::HashSet<_> = self.clients.iter().map(|c| &c.name).collect();
        if names.len() != self.clients.len() {
            bail!("duplicate client names in config");
        }
        // Addendum #2: authn bindings must be unambiguous across clients.
        let mut token_hashes = std::collections::HashSet::new();
        let mut sa_bindings = std::collections::HashSet::new();
        for c in &self.clients {
            if let Some(h) = &c.auth.api_token_sha256 {
                if !token_hashes.insert(h.to_ascii_lowercase()) {
                    bail!("duplicate api_token_sha256 across clients (ambiguous binding)");
                }
            }
            if let Some(sa) = &c.auth.service_account {
                if !sa_bindings.insert((sa.audience.clone(), sa.subject.clone())) {
                    bail!(
                        "duplicate service-account binding {}/{} across clients",
                        sa.audience,
                        sa.subject
                    );
                }
            }
        }
        Ok(())
    }

    pub fn database_url(&self) -> &str {
        self.database_url.as_deref().expect("validated")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const BASE_YAML: &str = r#"
listen_addr: "127.0.0.1:8443"
external_url: "https://keychute.example.dev"
allow_insecure_http: true
database_url: "postgres://x/y"
kek_file: "/etc/keychute/keyset.json"
human_auth:
  mode: static
  static:
    token_sha256: "ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789"
    subject: "andrew"
clients:
  - name: "agent"
    max_tier: "cooperating-client"
    mechanisms: ["cli-read"]
    auth:
      api_token_sha256: "  FFEE00112233445566778899AABBCCDDEEFF00112233445566778899AABBCCDD  "
"#;

    #[test]
    fn client_auth_binding_is_exactly_one() {
        // Both bindings: rejected (either would authenticate as this client).
        let yaml = format!(
            "{BASE_YAML}      service_account:\n        \
             audience: \"keychute.example.dev\"\n        \
             subject: \"system:serviceaccount:ns:agent\"\n"
        );
        let mut cfg: Config = serde_yaml::from_str(&yaml).unwrap();
        cfg.normalize();
        let err = cfg.validate().unwrap_err().to_string();
        assert!(err.contains("two auth bindings"), "{err}");

        // Neither binding: still rejected.
        let mut cfg: Config = serde_yaml::from_str(BASE_YAML).unwrap();
        cfg.clients[0].auth.api_token_sha256 = None;
        cfg.normalize();
        let err = cfg.validate().unwrap_err().to_string();
        assert!(err.contains("no auth binding"), "{err}");

        // Service account alone: accepted, but only with a TokenReview
        // endpoint to verify presented tokens against.
        let mut cfg: Config = serde_yaml::from_str(BASE_YAML).unwrap();
        cfg.clients[0].auth.api_token_sha256 = None;
        cfg.clients[0].auth.service_account = Some(ServiceAccountAuth {
            audience: "keychute.example.dev".into(),
            subject: "system:serviceaccount:ns:agent".into(),
        });
        cfg.normalize();
        let err = cfg.validate().unwrap_err().to_string();
        assert!(err.contains("tokenreview_url is not set"), "{err}");
        cfg.tokenreview_url = Some(
            "https://kubernetes.default.svc/apis/authentication.k8s.io/v1/tokenreviews".into(),
        );
        cfg.validate().unwrap();
    }

    #[test]
    fn limits_reject_nonpositive_security_critical_values() {
        let check = |mutate: fn(&mut Limits), needle: &str| {
            let mut cfg: Config = serde_yaml::from_str(BASE_YAML).unwrap();
            cfg.normalize();
            mutate(&mut cfg.limits);
            let err = cfg.validate().unwrap_err().to_string();
            assert!(err.contains(needle), "{err}");
        };
        // Negative expiry would store every request already-expired.
        check(|l| l.request_expiry_seconds = -1, "request_expiry_seconds");
        check(|l| l.request_expiry_seconds = 0, "request_expiry_seconds");
        // Zero replay window disables idempotent replay entirely.
        check(|l| l.replay_window_seconds = 0, "replay_window_seconds");
        check(|l| l.replay_window_seconds = -60, "replay_window_seconds");
        // Zero/negative caps would reject every request, wait, or stream.
        check(|l| l.max_pending_per_client = 0, "max_pending_per_client");
        check(|l| l.max_pending_per_client = -1, "max_pending_per_client");
        check(|l| l.max_waits_per_client = 0, "max_waits_per_client");
        check(
            |l| l.max_proxy_streams_per_client = 0,
            "max_proxy_streams_per_client",
        );
        // Zero-valued wait/proxy limits are a quiet outage, not a config.
        check(|l| l.wait_max_seconds = 0, "wait_max_seconds");
        check(|l| l.proxy_max_body_bytes = 0, "proxy_max_body_bytes");
        check(
            |l| l.proxy_stream_deadline_seconds = 0,
            "proxy_stream_deadline_seconds",
        );
        // The defaults themselves must pass.
        let mut cfg: Config = serde_yaml::from_str(BASE_YAML).unwrap();
        cfg.normalize();
        cfg.validate().unwrap();
    }

    #[test]
    fn tokenreview_url_plaintext_rules() {
        let check = |url: &str, insecure_ok: bool, want_ok: bool| {
            let mut cfg: Config = serde_yaml::from_str(BASE_YAML).unwrap();
            cfg.tokenreview_url = Some(url.into());
            cfg.allow_insecure_http_non_loopback = insecure_ok;
            cfg.normalize();
            assert_eq!(
                cfg.validate().is_ok(),
                want_ok,
                "{url} insecure={insecure_ok}"
            );
        };
        check(
            "https://kubernetes.default.svc/apis/authentication.k8s.io/v1/tokenreviews",
            false,
            true,
        );
        check("http://127.0.0.1:8001/tokenreviews", false, true);
        check("http://localhost:8001/tokenreviews", false, true);
        check("http://[::1]:8001/tokenreviews", false, true);
        // The SA token and reviewer credential would cross the wire plaintext.
        check("http://kubernetes.default.svc/tokenreviews", false, false);
        check("http://10.0.0.5:8001/tokenreviews", false, false);
        check("http://10.0.0.5:8001/tokenreviews", true, true);
        check("ftp://kubernetes.default.svc/tokenreviews", false, false);

        // Same rule for the other credential-carrying outbound endpoints.
        let mut cfg: Config = serde_yaml::from_str(BASE_YAML).unwrap();
        cfg.pushover = Some(PushoverConfig {
            base_url: "http://pushover.internal".into(),
            token: Some("t".into()),
            token_path: None,
            user_key: Some("u".into()),
            user_key_path: None,
        });
        cfg.normalize();
        assert!(cfg
            .validate()
            .unwrap_err()
            .to_string()
            .contains("pushover.base_url"));

        let mut cfg: Config = serde_yaml::from_str(BASE_YAML).unwrap();
        cfg.human_auth.oidc = Some(OidcHumanAuth {
            issuer: "https://idp.example.dev".into(),
            audience: "keychute".into(),
            jwks_url: "http://idp.example.dev/jwks".into(),
            allowed_subjects: vec!["andrew".into()],
            allowed_group: None,
            group_claim: "groups".into(),
            clock_skew_seconds: 60,
        });
        cfg.normalize();
        // Plaintext JWKS is a signing-key substitution vector regardless of
        // human_auth.mode: reject it whenever the section is present.
        assert!(cfg.validate().unwrap_err().to_string().contains("jwks_url"));
    }

    #[test]
    fn malformed_token_digests_fail_validation() {
        // A typo'd digest would otherwise reconcile as an enabled client (or a
        // configured operator) that no presented token can ever match.
        let check_client = |digest: &str| {
            let mut cfg: Config = serde_yaml::from_str(BASE_YAML).unwrap();
            cfg.clients[0].auth.api_token_sha256 = Some(digest.into());
            cfg.normalize();
            let err = cfg.validate().unwrap_err().to_string();
            assert!(err.contains("api_token_sha256"), "{digest:?}: {err}");
        };
        check_client("");
        check_client(&"a".repeat(63));
        check_client(&"a".repeat(65));
        check_client(&"g".repeat(64)); // non-hex
        let mut cfg: Config = serde_yaml::from_str(BASE_YAML).unwrap();
        cfg.human_auth.r#static.as_mut().unwrap().token_sha256 = "deadbeef".into();
        cfg.normalize();
        let err = cfg.validate().unwrap_err().to_string();
        assert!(err.contains("human_auth.static.token_sha256"), "{err}");
    }

    #[test]
    fn normalize_lowercases_token_hashes() {
        let mut cfg: Config = serde_yaml::from_str(BASE_YAML).unwrap();
        cfg.normalize();
        cfg.validate().unwrap();
        assert_eq!(
            cfg.clients[0].auth.api_token_sha256.as_deref(),
            Some("ffee00112233445566778899aabbccddeeff00112233445566778899aabbccdd")
        );
        assert_eq!(
            cfg.human_auth.r#static.as_ref().unwrap().token_sha256,
            "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789"
        );
    }
}
