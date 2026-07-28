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
        }
    }
}

impl Config {
    pub fn load(path: &Path) -> anyhow::Result<Config> {
        let raw =
            std::fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
        let mut config: Config = serde_yaml::from_str(&raw).context("parsing config YAML")?;
        if let Ok(url) = std::env::var("KEYCHUTE_DATABASE_URL") {
            config.database_url = Some(url);
        }
        config.validate()?;
        Ok(config)
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
                if self.human_auth.r#static.is_none() {
                    bail!("human_auth.mode=static requires human_auth.static");
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
            if !has_token && !has_sa {
                bail!("client {} has no auth binding", c.name);
            }
            if c.mechanisms.is_empty() {
                bail!("client {} has no allowed mechanisms", c.name);
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
