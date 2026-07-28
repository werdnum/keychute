//! Envelope encryption. Contract in docs/IMPLEMENTATION.md §crypto.
//!
//! - Payload: XChaCha20-Poly1305 under a fresh per-seal DEK, 24-byte random
//!   nonce, context-derived AAD (never stored).
//! - DEK wrap: XChaCha20-Poly1305 under a KEK, own fresh 24-byte nonce, AAD
//!   `keychute/v1/dek-wrap`; wrapped blob = wrap_nonce || wrap_ct.
//! - `Keyset` holds the file-backed KEKs plus the idempotency/CSRF MAC key;
//!   `EphemeralKek` is the process-local key for grant passthrough payloads.
//!
//! Invariants: no `Debug`/`Display` on key or plaintext material, errors carry
//! no secret data, all randomness from the OS RNG, intermediate DEK/plaintext
//! buffers zeroize on drop.

use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{Key, XChaCha20Poly1305, XNonce};
use hmac::{Hmac, Mac};
use rand::rngs::OsRng;
use rand::RngCore;
use secrecy::{ExposeSecret, SecretBox};
use sha2::Sha256;
use std::collections::HashMap;
use std::path::Path;
use subtle::ConstantTimeEq;
use uuid::Uuid;
use zeroize::Zeroizing;

/// Alias for plaintext secret material. Never Debug/Display.
pub type SecretBytes = SecretBox<[u8]>;

/// AAD used when wrapping a DEK under a KEK (any KEK, file-backed or ephemeral).
const DEK_WRAP_AAD: &[u8] = b"keychute/v1/dek-wrap";
/// The `kek_id` recorded for rows sealed under the process-local ephemeral KEK.
pub const EPHEMERAL_KEK_ID: &str = "ephemeral";

const KEY_LEN: usize = 32;
const NONCE_LEN: usize = 24;

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

impl AadContext {
    /// Canonical AAD bytes. Never stored; rebuilt from row identity at decrypt
    /// time so relocated ciphertext fails AEAD verification. `Uuid`'s `Display`
    /// is the hyphenated lowercase form.
    fn derive(&self) -> Vec<u8> {
        match self {
            AadContext::SecretVersion { secret_id, version } => {
                format!("keychute/v1/secret-version/{secret_id}/{version}").into_bytes()
            }
            AadContext::GrantPassthrough { grant_id } => {
                format!("keychute/v1/grant-passthrough/{grant_id}").into_bytes()
            }
            AadContext::RequestContext { request_id } => {
                format!("keychute/v1/request-context/{request_id}").into_bytes()
            }
        }
    }
}

pub struct Sealed {
    pub ciphertext: Vec<u8>,
    pub nonce: Vec<u8>,
    pub wrapped_dek: Vec<u8>,
    pub kek_id: String,
}

/// A single 32-byte key held in a zeroizing container. No Debug/Display.
struct KeyMaterial(Zeroizing<[u8; KEY_LEN]>);

impl KeyMaterial {
    fn random() -> KeyMaterial {
        let mut k = Zeroizing::new([0u8; KEY_LEN]);
        OsRng.fill_bytes(&mut *k);
        KeyMaterial(k)
    }

    fn from_slice(bytes: &[u8]) -> Option<KeyMaterial> {
        if bytes.len() != KEY_LEN {
            return None;
        }
        let mut k = Zeroizing::new([0u8; KEY_LEN]);
        k.copy_from_slice(bytes);
        Some(KeyMaterial(k))
    }

    fn cipher(&self) -> XChaCha20Poly1305 {
        XChaCha20Poly1305::new(Key::from_slice(&*self.0))
    }
}

fn random_nonce() -> [u8; NONCE_LEN] {
    let mut n = [0u8; NONCE_LEN];
    OsRng.fill_bytes(&mut n);
    n
}

/// Wrap a fresh DEK under `kek` and encrypt `plaintext` under the DEK.
fn seal_with_kek(
    kek: &KeyMaterial,
    kek_id: &str,
    plaintext: &SecretBytes,
    aad: AadContext,
) -> Result<Sealed, CryptoError> {
    let dek = KeyMaterial::random();

    // Payload encryption under the DEK with the context AAD.
    let payload_nonce = random_nonce();
    let ciphertext = dek
        .cipher()
        .encrypt(
            XNonce::from_slice(&payload_nonce),
            Payload {
                msg: plaintext.expose_secret(),
                aad: &aad.derive(),
            },
        )
        .map_err(|_| CryptoError::DecryptFailed)?;

    // Wrap the DEK under the KEK.
    let wrap_nonce = random_nonce();
    let wrap_ct = kek
        .cipher()
        .encrypt(
            XNonce::from_slice(&wrap_nonce),
            Payload {
                msg: &*dek.0,
                aad: DEK_WRAP_AAD,
            },
        )
        .map_err(|_| CryptoError::DecryptFailed)?;

    let mut wrapped_dek = Vec::with_capacity(NONCE_LEN + wrap_ct.len());
    wrapped_dek.extend_from_slice(&wrap_nonce);
    wrapped_dek.extend_from_slice(&wrap_ct);

    Ok(Sealed {
        ciphertext,
        nonce: payload_nonce.to_vec(),
        wrapped_dek,
        kek_id: kek_id.to_string(),
    })
}

/// Unwrap a DEK blob (`wrap_nonce || wrap_ct`) under `kek`.
fn unwrap_dek(kek: &KeyMaterial, wrapped_dek: &[u8]) -> Result<KeyMaterial, CryptoError> {
    if wrapped_dek.len() <= NONCE_LEN {
        return Err(CryptoError::DecryptFailed);
    }
    let (wrap_nonce, wrap_ct) = wrapped_dek.split_at(NONCE_LEN);
    let dek_bytes = Zeroizing::new(
        kek.cipher()
            .decrypt(
                XNonce::from_slice(wrap_nonce),
                Payload {
                    msg: wrap_ct,
                    aad: DEK_WRAP_AAD,
                },
            )
            .map_err(|_| CryptoError::DecryptFailed)?,
    );
    KeyMaterial::from_slice(&dek_bytes).ok_or(CryptoError::DecryptFailed)
}

/// Unwrap the DEK under `kek` and decrypt the payload with the context AAD.
fn open_with_kek(
    kek: &KeyMaterial,
    ciphertext: &[u8],
    nonce: &[u8],
    wrapped_dek: &[u8],
    aad: AadContext,
) -> Result<SecretBytes, CryptoError> {
    if nonce.len() != NONCE_LEN {
        return Err(CryptoError::DecryptFailed);
    }
    let dek = unwrap_dek(kek, wrapped_dek)?;
    let plaintext = Zeroizing::new(
        dek.cipher()
            .decrypt(
                XNonce::from_slice(nonce),
                Payload {
                    msg: ciphertext,
                    aad: &aad.derive(),
                },
            )
            .map_err(|_| CryptoError::DecryptFailed)?,
    );
    let boxed: Box<[u8]> = plaintext.as_slice().into();
    Ok(SecretBox::new(boxed))
}

/// On-disk shape of `keyset.json`. Holds base64 strings only; decoded material
/// goes straight into zeroizing containers.
#[derive(serde::Deserialize)]
struct KeysetFile {
    active: String,
    keys: HashMap<String, String>,
    mac_key: String,
}

pub struct Keyset {
    active: String,
    keys: HashMap<String, KeyMaterial>,
    mac_key: KeyMaterial,
}

impl Keyset {
    pub fn load(path: &Path) -> anyhow::Result<Keyset> {
        let raw = std::fs::read_to_string(path)
            .map_err(|e| anyhow::anyhow!("reading keyset file {}: {e}", path.display()))?;
        let file: KeysetFile = serde_json::from_str(&raw)
            .map_err(|e| anyhow::anyhow!("parsing keyset file {}: {e}", path.display()))?;
        Keyset::from_file(file)
    }

    fn from_file(file: KeysetFile) -> anyhow::Result<Keyset> {
        if file.keys.is_empty() {
            anyhow::bail!("keyset has no keys");
        }
        if !file.keys.contains_key(&file.active) {
            anyhow::bail!("active kek id {:?} not present in keys", file.active);
        }
        let mut keys = HashMap::with_capacity(file.keys.len());
        for (id, b64) in &file.keys {
            keys.insert(id.clone(), decode_key(b64, &format!("key {id:?}"))?);
        }
        let mac_key = decode_key(&file.mac_key, "mac_key")?;
        Ok(Keyset {
            active: file.active,
            keys,
            mac_key,
        })
    }

    pub fn active_kek_id(&self) -> &str {
        &self.active
    }

    fn kek(&self, kek_id: &str) -> Result<&KeyMaterial, CryptoError> {
        self.keys
            .get(kek_id)
            .ok_or_else(|| CryptoError::UnknownKek(kek_id.to_string()))
    }

    pub fn seal(&self, plaintext: &SecretBytes, aad: AadContext) -> Result<Sealed, CryptoError> {
        let kek = self.kek(&self.active)?;
        seal_with_kek(kek, &self.active, plaintext, aad)
    }

    pub fn open(
        &self,
        ciphertext: &[u8],
        nonce: &[u8],
        wrapped_dek: &[u8],
        kek_id: &str,
        aad: AadContext,
    ) -> Result<SecretBytes, CryptoError> {
        let kek = self.kek(kek_id)?;
        open_with_kek(kek, ciphertext, nonce, wrapped_dek, aad)
    }

    /// Rewrap a wrapped DEK from `old_kek_id` to the active KEK. Never touches
    /// payload ciphertext.
    pub fn rewrap(
        &self,
        wrapped_dek: &[u8],
        old_kek_id: &str,
    ) -> Result<(Vec<u8>, String), CryptoError> {
        let old = self.kek(old_kek_id)?;
        let active = self.kek(&self.active)?;
        let dek = unwrap_dek(old, wrapped_dek)?;

        let wrap_nonce = random_nonce();
        let wrap_ct = active
            .cipher()
            .encrypt(
                XNonce::from_slice(&wrap_nonce),
                Payload {
                    msg: &*dek.0,
                    aad: DEK_WRAP_AAD,
                },
            )
            .map_err(|_| CryptoError::DecryptFailed)?;

        let mut blob = Vec::with_capacity(NONCE_LEN + wrap_ct.len());
        blob.extend_from_slice(&wrap_nonce);
        blob.extend_from_slice(&wrap_ct);
        Ok((blob, self.active.clone()))
    }

    /// Domain-separated HMAC-SHA256 for idempotency payload binding.
    pub fn idem_mac(&self, client: &str, payload_canonical: &[u8]) -> [u8; 32] {
        let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(&*self.mac_key.0)
            .expect("HMAC accepts any key length");
        mac.update(b"keychute/v1/idem-mac\0");
        mac.update(client.as_bytes());
        mac.update(b"\0");
        mac.update(payload_canonical);
        mac.finalize().into_bytes().into()
    }

    /// MAC for UI CSRF tokens (separate domain label).
    pub fn csrf_mac(&self, payload: &[u8]) -> [u8; 32] {
        let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(&*self.mac_key.0)
            .expect("HMAC accepts any key length");
        mac.update(b"keychute/v1/csrf\0");
        mac.update(payload);
        mac.finalize().into_bytes().into()
    }
}

fn decode_key(b64: &str, what: &str) -> anyhow::Result<KeyMaterial> {
    use base64::Engine;
    let decoded = Zeroizing::new(
        base64::engine::general_purpose::STANDARD
            .decode(b64)
            .map_err(|_| anyhow::anyhow!("{what}: invalid base64"))?,
    );
    KeyMaterial::from_slice(&decoded)
        .ok_or_else(|| anyhow::anyhow!("{what}: expected {KEY_LEN} bytes, got {}", decoded.len()))
}

/// Constant-time byte-slice comparison for MAC verification. Slices of
/// different lengths compare unequal.
pub fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    a.ct_eq(b).into()
}

/// Process-local ephemeral KEK for grant passthrough payloads. Generated at
/// startup, held only in memory: after a restart, payloads sealed by the
/// previous process cannot be opened (fresh random key).
pub struct EphemeralKek {
    key: KeyMaterial,
}

impl EphemeralKek {
    #[allow(clippy::new_without_default)]
    pub fn generate() -> EphemeralKek {
        EphemeralKek {
            key: KeyMaterial::random(),
        }
    }

    /// Seal under the process-local key. `Sealed.kek_id` is the literal
    /// [`EPHEMERAL_KEK_ID`]; callers store `passthrough_ephemeral = true`.
    pub fn seal(&self, plaintext: &SecretBytes, aad: AadContext) -> Result<Sealed, CryptoError> {
        seal_with_kek(&self.key, EPHEMERAL_KEK_ID, plaintext, aad)
    }

    pub fn open(
        &self,
        ciphertext: &[u8],
        nonce: &[u8],
        wrapped_dek: &[u8],
        aad: AadContext,
    ) -> Result<SecretBytes, CryptoError> {
        open_with_kek(&self.key, ciphertext, nonce, wrapped_dek, aad)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::Engine;

    fn b64(bytes: &[u8]) -> String {
        base64::engine::general_purpose::STANDARD.encode(bytes)
    }

    fn keyset_json(active: &str, keys: &[(&str, &[u8])], mac_key: &[u8]) -> String {
        let keys: serde_json::Map<String, serde_json::Value> = keys
            .iter()
            .map(|(id, k)| (id.to_string(), serde_json::Value::String(b64(k))))
            .collect();
        serde_json::json!({ "active": active, "keys": keys, "mac_key": b64(mac_key) }).to_string()
    }

    fn load_from_str(json: &str) -> anyhow::Result<Keyset> {
        Keyset::from_file(serde_json::from_str(json)?)
    }

    fn test_keyset() -> Keyset {
        load_from_str(&keyset_json("k0", &[("k0", &[1u8; 32])], &[9u8; 32])).unwrap()
    }

    fn secret(bytes: &[u8]) -> SecretBytes {
        SecretBox::new(bytes.into())
    }

    fn uuid(n: u128) -> Uuid {
        Uuid::from_u128(n)
    }

    #[test]
    fn roundtrip_all_aad_variants() {
        let ks = test_keyset();
        let contexts = [
            AadContext::SecretVersion {
                secret_id: uuid(1),
                version: 1,
            },
            AadContext::GrantPassthrough { grant_id: uuid(2) },
            AadContext::RequestContext {
                request_id: uuid(3),
            },
        ];
        for aad in contexts {
            let pt = secret(b"hello keychute");
            let sealed = ks.seal(&pt, aad).unwrap();
            assert_eq!(sealed.kek_id, "k0");
            assert_eq!(sealed.nonce.len(), 24);
            let opened = ks
                .open(
                    &sealed.ciphertext,
                    &sealed.nonce,
                    &sealed.wrapped_dek,
                    &sealed.kek_id,
                    aad,
                )
                .unwrap();
            assert_eq!(opened.expose_secret(), b"hello keychute");
        }
    }

    #[test]
    fn aad_swap_fails() {
        let ks = test_keyset();
        let a = uuid(0xa);
        let sealed = ks
            .seal(
                &secret(b"payload"),
                AadContext::SecretVersion {
                    secret_id: a,
                    version: 1,
                },
            )
            .unwrap();
        let wrong = [
            AadContext::SecretVersion {
                secret_id: a,
                version: 2,
            },
            AadContext::SecretVersion {
                secret_id: uuid(0xb),
                version: 1,
            },
            AadContext::GrantPassthrough { grant_id: a },
            AadContext::RequestContext { request_id: a },
        ];
        for aad in wrong {
            let err = ks
                .open(
                    &sealed.ciphertext,
                    &sealed.nonce,
                    &sealed.wrapped_dek,
                    &sealed.kek_id,
                    aad,
                )
                .unwrap_err();
            assert!(matches!(err, CryptoError::DecryptFailed));
        }
    }

    #[test]
    fn tamper_fails() {
        let ks = test_keyset();
        let aad = AadContext::SecretVersion {
            secret_id: uuid(1),
            version: 1,
        };
        let sealed = ks.seal(&secret(b"payload"), aad).unwrap();

        let mut ct = sealed.ciphertext.clone();
        ct[0] ^= 1;
        assert!(matches!(
            ks.open(&ct, &sealed.nonce, &sealed.wrapped_dek, &sealed.kek_id, aad),
            Err(CryptoError::DecryptFailed)
        ));

        let mut nonce = sealed.nonce.clone();
        nonce[0] ^= 1;
        assert!(matches!(
            ks.open(
                &sealed.ciphertext,
                &nonce,
                &sealed.wrapped_dek,
                &sealed.kek_id,
                aad
            ),
            Err(CryptoError::DecryptFailed)
        ));

        let mut wd = sealed.wrapped_dek.clone();
        let last = wd.len() - 1;
        wd[last] ^= 1;
        assert!(matches!(
            ks.open(&sealed.ciphertext, &sealed.nonce, &wd, &sealed.kek_id, aad),
            Err(CryptoError::DecryptFailed)
        ));
    }

    #[test]
    fn rewrap_to_new_active_kek() {
        let k0 = [1u8; 32];
        let k1 = [2u8; 32];
        let mac = [9u8; 32];
        let aad = AadContext::SecretVersion {
            secret_id: uuid(7),
            version: 3,
        };

        let old = load_from_str(&keyset_json("k0", &[("k0", &k0)], &mac)).unwrap();
        let sealed = old.seal(&secret(b"durable"), aad).unwrap();
        assert_eq!(sealed.kek_id, "k0");

        // Rotated keyset: both keys present, k1 active.
        let rotated = load_from_str(&keyset_json("k1", &[("k0", &k0), ("k1", &k1)], &mac)).unwrap();
        assert_eq!(rotated.active_kek_id(), "k1");
        let (new_wd, new_id) = rotated.rewrap(&sealed.wrapped_dek, &sealed.kek_id).unwrap();
        assert_eq!(new_id, "k1");
        let opened = rotated
            .open(&sealed.ciphertext, &sealed.nonce, &new_wd, &new_id, aad)
            .unwrap();
        assert_eq!(opened.expose_secret(), b"durable");

        // Retired keyset: k0 gone. Un-rewrapped blob fails with UnknownKek;
        // the rewrapped one still opens.
        let retired = load_from_str(&keyset_json("k1", &[("k1", &k1)], &mac)).unwrap();
        let err = retired
            .open(
                &sealed.ciphertext,
                &sealed.nonce,
                &sealed.wrapped_dek,
                &sealed.kek_id,
                aad,
            )
            .unwrap_err();
        assert!(matches!(err, CryptoError::UnknownKek(id) if id == "k0"));
        let opened = retired
            .open(&sealed.ciphertext, &sealed.nonce, &new_wd, &new_id, aad)
            .unwrap();
        assert_eq!(opened.expose_secret(), b"durable");
    }

    #[test]
    fn ephemeral_roundtrip_and_restart_isolation() {
        let aad = AadContext::GrantPassthrough {
            grant_id: uuid(0x42),
        };
        let kek = EphemeralKek::generate();
        let sealed = kek.seal(&secret(b"one-shot"), aad).unwrap();
        assert_eq!(sealed.kek_id, EPHEMERAL_KEK_ID);
        let opened = kek
            .open(&sealed.ciphertext, &sealed.nonce, &sealed.wrapped_dek, aad)
            .unwrap();
        assert_eq!(opened.expose_secret(), b"one-shot");

        // A fresh process key (simulated restart) cannot open old payloads.
        let restarted = EphemeralKek::generate();
        assert!(matches!(
            restarted.open(&sealed.ciphertext, &sealed.nonce, &sealed.wrapped_dek, aad),
            Err(CryptoError::DecryptFailed)
        ));
    }

    #[test]
    fn macs_are_domain_and_input_separated() {
        let ks = test_keyset();
        let a = ks.idem_mac("client-a", b"payload");
        assert_eq!(a, ks.idem_mac("client-a", b"payload"));
        assert_ne!(a, ks.idem_mac("client-b", b"payload"));
        assert_ne!(a, ks.idem_mac("client-a", b"payload2"));
        // Different domain label ⇒ different MAC on the same payload.
        assert_ne!(a.as_slice(), ks.csrf_mac(b"payload").as_slice());
        // Boundary shift must not collide: ("ab","c") vs ("a","bc").
        assert_ne!(ks.idem_mac("ab", b"c"), ks.idem_mac("a", b"bc"));

        assert!(ct_eq(&a, &ks.idem_mac("client-a", b"payload")));
        assert!(!ct_eq(&a, &ks.csrf_mac(b"payload")));
        assert!(!ct_eq(&a, &a[..16]));
    }

    #[test]
    fn keyset_load_rejects_bad_input() {
        // Bad base64 in a key.
        let bad_b64 = serde_json::json!({
            "active": "k0",
            "keys": { "k0": "not!!base64" },
            "mac_key": b64(&[9u8; 32]),
        })
        .to_string();
        assert!(load_from_str(&bad_b64).is_err());

        // Wrong key length.
        assert!(load_from_str(&keyset_json("k0", &[("k0", &[1u8; 16])], &[9u8; 32])).is_err());

        // Wrong mac_key length.
        assert!(load_from_str(&keyset_json("k0", &[("k0", &[1u8; 32])], &[9u8; 31])).is_err());

        // Active key missing from the map.
        assert!(load_from_str(&keyset_json("k1", &[("k0", &[1u8; 32])], &[9u8; 32])).is_err());

        // Valid input loads.
        let ks = load_from_str(&keyset_json("k0", &[("k0", &[1u8; 32])], &[9u8; 32])).unwrap();
        assert_eq!(ks.active_kek_id(), "k0");
    }

    #[test]
    fn keyset_load_reads_file() {
        let dir = std::env::temp_dir().join(format!("keychute-crypto-test-{}", Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("keyset.json");
        std::fs::write(&path, keyset_json("k0", &[("k0", &[3u8; 32])], &[9u8; 32])).unwrap();
        let ks = Keyset::load(&path).unwrap();
        assert_eq!(ks.active_kek_id(), "k0");
        assert!(Keyset::load(&dir.join("missing.json")).is_err());
        std::fs::remove_dir_all(&dir).ok();
    }
}
