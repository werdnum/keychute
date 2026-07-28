//! Envelope encryption. Contract in docs/IMPLEMENTATION.md §crypto.
//! STUB — implemented by the crypto task.

use secrecy::SecretBox;
use std::path::Path;
use uuid::Uuid;

/// Alias for plaintext secret material. Never Debug/Display.
pub type SecretBytes = SecretBox<[u8]>;

#[derive(Debug, thiserror::Error)]
pub enum CryptoError {
    #[error("keyset error: {0}")]
    Keyset(String),
    #[error("decryption failed")]
    DecryptFailed,
    #[error("unknown kek id {0}")]
    UnknownKek(String),
}

#[derive(Clone, Copy)]
pub enum AadContext {
    SecretVersion { secret_id: Uuid, version: i32 },
    GrantPassthrough { grant_id: Uuid },
    RequestContext { request_id: Uuid },
}

pub struct Sealed {
    pub ciphertext: Vec<u8>,
    pub nonce: Vec<u8>,
    pub wrapped_dek: Vec<u8>,
    pub kek_id: String,
}

pub struct Keyset {
    _private: (),
}

impl Keyset {
    pub fn load(_path: &Path) -> anyhow::Result<Keyset> {
        unimplemented!("crypto task")
    }
    pub fn seal(&self, _plaintext: &SecretBytes, _aad: AadContext) -> Result<Sealed, CryptoError> {
        unimplemented!("crypto task")
    }
    pub fn open(
        &self,
        _ciphertext: &[u8],
        _nonce: &[u8],
        _wrapped_dek: &[u8],
        _kek_id: &str,
        _aad: AadContext,
    ) -> Result<SecretBytes, CryptoError> {
        unimplemented!("crypto task")
    }
    /// Rewrap a wrapped DEK from `old_kek_id` to the active KEK.
    pub fn rewrap(
        &self,
        _wrapped_dek: &[u8],
        _old_kek_id: &str,
    ) -> Result<(Vec<u8>, String), CryptoError> {
        unimplemented!("crypto task")
    }
    /// Domain-separated HMAC-SHA256 for idempotency payload binding.
    pub fn idem_mac(&self, _client: &str, _payload_canonical: &[u8]) -> [u8; 32] {
        unimplemented!("crypto task")
    }
    /// MAC for UI CSRF tokens (separate domain label).
    pub fn csrf_mac(&self, _payload: &[u8]) -> [u8; 32] {
        unimplemented!("crypto task")
    }
    pub fn active_kek_id(&self) -> &str {
        unimplemented!("crypto task")
    }
}

/// Process-local ephemeral KEK for grant passthrough payloads.
pub struct EphemeralKek {
    _private: (),
}

impl EphemeralKek {
    pub fn generate() -> EphemeralKek {
        EphemeralKek { _private: () }
    }
    pub fn seal(&self, _plaintext: &SecretBytes, _aad: AadContext) -> Result<Sealed, CryptoError> {
        unimplemented!("crypto task")
    }
    pub fn open(
        &self,
        _ciphertext: &[u8],
        _nonce: &[u8],
        _wrapped_dek: &[u8],
        _aad: AadContext,
    ) -> Result<SecretBytes, CryptoError> {
        unimplemented!("crypto task")
    }
}
