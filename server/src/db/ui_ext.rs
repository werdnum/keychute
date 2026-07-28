//! Store-layer additions owned by the approval-UI/notify task. Keep UI-specific
//! queries here rather than editing the Phase-A modules.

use crate::audit::{insert_audit, kinds, AuditEvent};
use crate::crypto::Sealed;
use crate::db::grants::GrantRow;
use crate::db::requests::{AccessRequestRow, GrantParams};
use crate::db::secrets::SecretVersionRow;
use chrono::{DateTime, Utc};
use sqlx::PgPool;
use uuid::Uuid;

use crate::db::take_kek_shared_lock;

/// Secret created at approval time ("store this secret in Keychute",
/// addendum #16). `secret_id` is app-generated so the payload can be sealed
/// with its `SecretVersion { secret_id, version: 1 }` AAD before the
/// transaction opens.
pub struct StoreSecretParams {
    pub secret_id: Uuid,
    pub name: String,
    pub description: String,
    pub max_tier: i32,
    /// 'bearer' | 'header' | 'basic'.
    pub injection_kind: String,
    /// Header name for 'header'; NULL for 'bearer' and 'basic'.
    pub injection_header: Option<String>,
    /// Username for 'basic' (migration 0003); NULL otherwise. The proxy also
    /// falls back to `injection_header` for pre-0003 'basic' rows.
    pub injection_username: Option<String>,
    /// Sealed under the durable keyset with AAD SecretVersion{secret_id, 1}.
    pub sealed: Sealed,
}

/// Approve a pending request with an app-supplied grant id (required for
/// passthrough payloads, whose AAD binds the grant id before insert).
///
/// One transaction: flip `pending -> approved` (rowcount-checked, incl.
/// `now() < expires_at` per addendum #8), optionally create the secret +
/// version 1 (addendum #16), insert the grant, audit. Returns `None` — with
/// nothing written — when the request was not approvable.
pub async fn approve_request(
    db: &PgPool,
    request_id: Uuid,
    resolved_by: &str,
    grant_id: Uuid,
    grant: &GrantParams,
    store: Option<&StoreSecretParams>,
) -> anyhow::Result<Option<Uuid>> {
    let mut tx = db.begin().await?;
    if store.is_some() || grant.passthrough.is_some() {
        take_kek_shared_lock(&mut tx).await?;
    }
    let updated = sqlx::query(
        "UPDATE access_requests \
         SET state = 'approved', resolved_by = $2, resolved_at = now() \
         WHERE id = $1 AND state = 'pending' AND now() < expires_at",
    )
    .bind(request_id)
    .bind(resolved_by)
    .execute(&mut *tx)
    .await?;
    if updated.rows_affected() != 1 {
        return Ok(None);
    }

    if let Some(s) = store {
        sqlx::query(
            "INSERT INTO secrets \
             (id, name, description, max_tier, injection_kind, injection_header, \
              injection_username, current_version) \
             VALUES ($1, $2, $3, $4, $5, $6, $7, 1)",
        )
        .bind(s.secret_id)
        .bind(&s.name)
        .bind(&s.description)
        .bind(s.max_tier)
        .bind(&s.injection_kind)
        .bind(&s.injection_header)
        .bind(&s.injection_username)
        .execute(&mut *tx)
        .await?;
        sqlx::query(
            "INSERT INTO secret_versions \
             (secret_id, version, ciphertext, nonce, wrapped_dek, kek_id, created_by_request) \
             VALUES ($1, 1, $2, $3, $4, $5, $6)",
        )
        .bind(s.secret_id)
        .bind(&s.sealed.ciphertext)
        .bind(&s.sealed.nonce)
        .bind(&s.sealed.wrapped_dek)
        .bind(&s.sealed.kek_id)
        .bind(request_id)
        .execute(&mut *tx)
        .await?;
        insert_audit(
            &mut *tx,
            &AuditEvent {
                kind: kinds::SECRET_CREATED,
                request_id: Some(request_id),
                secret_name: Some(s.name.clone()),
                actor: Some(resolved_by.to_owned()),
                ..Default::default()
            },
        )
        .await?;
    }

    let (pt_ct, pt_nonce, pt_dek, pt_eph) = match &grant.passthrough {
        Some(p) => (
            Some(&p.ciphertext),
            Some(&p.nonce),
            Some(&p.wrapped_dek),
            p.ephemeral,
        ),
        None => (None, None, None, false),
    };
    sqlx::query(
        "INSERT INTO grants \
         (id, request_id, client_name, secret_name, mechanism, constraints, not_after, max_uses, \
          passthrough_ciphertext, passthrough_nonce, passthrough_wrapped_dek, passthrough_ephemeral) \
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)",
    )
    .bind(grant_id)
    .bind(request_id)
    .bind(&grant.client_name)
    .bind(&grant.secret_name)
    .bind(&grant.mechanism)
    .bind(&grant.constraints)
    .bind(grant.not_after)
    .bind(grant.max_uses)
    .bind(pt_ct)
    .bind(pt_nonce)
    .bind(pt_dek)
    .bind(pt_eph)
    .execute(&mut *tx)
    .await?;
    insert_audit(
        &mut *tx,
        &AuditEvent {
            kind: kinds::REQUEST_APPROVED,
            request_id: Some(request_id),
            grant_id: Some(grant_id),
            client_name: Some(grant.client_name.clone()),
            secret_name: Some(grant.secret_name.clone()),
            actor: Some(resolved_by.to_owned()),
            ..Default::default()
        },
    )
    .await?;
    tx.commit().await?;
    Ok(Some(grant_id))
}

/// Create a secret with its version 1 from the admin UI (`POST /ui/secrets`),
/// with the `secret-created` audit row in the same transaction.
pub async fn create_secret_with_version(
    db: &PgPool,
    store: &StoreSecretParams,
    actor: &str,
) -> anyhow::Result<()> {
    let mut tx = db.begin().await?;
    take_kek_shared_lock(&mut tx).await?;
    sqlx::query(
        "INSERT INTO secrets \
         (id, name, description, max_tier, injection_kind, injection_header, \
          injection_username, current_version) \
         VALUES ($1, $2, $3, $4, $5, $6, $7, 1)",
    )
    .bind(store.secret_id)
    .bind(&store.name)
    .bind(&store.description)
    .bind(store.max_tier)
    .bind(&store.injection_kind)
    .bind(&store.injection_header)
    .bind(&store.injection_username)
    .execute(&mut *tx)
    .await?;
    sqlx::query(
        "INSERT INTO secret_versions \
         (secret_id, version, ciphertext, nonce, wrapped_dek, kek_id) \
         VALUES ($1, 1, $2, $3, $4, $5)",
    )
    .bind(store.secret_id)
    .bind(&store.sealed.ciphertext)
    .bind(&store.sealed.nonce)
    .bind(&store.sealed.wrapped_dek)
    .bind(&store.sealed.kek_id)
    .execute(&mut *tx)
    .await?;
    insert_audit(
        &mut *tx,
        &AuditEvent {
            kind: kinds::SECRET_CREATED,
            secret_name: Some(store.name.clone()),
            actor: Some(actor.to_owned()),
            ..Default::default()
        },
    )
    .await?;
    tx.commit().await?;
    Ok(())
}

/// Rotate a stored secret: bump `current_version`, seal the new payload with
/// the version-bound AAD (the closure receives the new version number), insert
/// the version row, and audit `secret-rotated` — one transaction.
pub async fn rotate_secret_version(
    db: &PgPool,
    secret_id: Uuid,
    secret_name: &str,
    actor: &str,
    seal: impl FnOnce(i32) -> Result<Sealed, crate::crypto::CryptoError>,
) -> anyhow::Result<SecretVersionRow> {
    let mut tx = db.begin().await?;
    take_kek_shared_lock(&mut tx).await?;
    let version: i32 = sqlx::query_scalar(
        "UPDATE secrets SET current_version = current_version + 1, updated_at = now() \
         WHERE id = $1 RETURNING current_version",
    )
    .bind(secret_id)
    .fetch_optional(&mut *tx)
    .await?
    .ok_or_else(|| anyhow::anyhow!("secret not found"))?;
    let sealed = seal(version).map_err(|e| anyhow::anyhow!("sealing rotated secret: {e}"))?;
    let row = sqlx::query_as::<_, SecretVersionRow>(
        "INSERT INTO secret_versions \
         (secret_id, version, ciphertext, nonce, wrapped_dek, kek_id) \
         VALUES ($1, $2, $3, $4, $5, $6) RETURNING *",
    )
    .bind(secret_id)
    .bind(version)
    .bind(&sealed.ciphertext)
    .bind(&sealed.nonce)
    .bind(&sealed.wrapped_dek)
    .bind(&sealed.kek_id)
    .fetch_one(&mut *tx)
    .await?;
    insert_audit(
        &mut *tx,
        &AuditEvent {
            kind: kinds::SECRET_ROTATED,
            secret_name: Some(secret_name.to_owned()),
            secret_version_id: Some(row.id),
            actor: Some(actor.to_owned()),
            ..Default::default()
        },
    )
    .await?;
    tx.commit().await?;
    Ok(row)
}

/// Grants that are still exercisable: not revoked, not past `not_after`.
pub async fn list_active_grants(db: &PgPool) -> anyhow::Result<Vec<GrantRow>> {
    Ok(sqlx::query_as::<_, GrantRow>(
        "SELECT * FROM grants WHERE NOT revoked AND now() < not_after ORDER BY created_at DESC",
    )
    .fetch_all(db)
    .await?)
}

/// Push dedup (addendum #10): true when another pending request with the same
/// dedup key (client + secret + mechanism + normalized-constraints jsonb) had
/// a push delivered after `since`.
pub async fn recent_duplicate_push(
    db: &PgPool,
    row: &AccessRequestRow,
    since: DateTime<Utc>,
) -> anyhow::Result<bool> {
    Ok(sqlx::query_scalar(
        "SELECT EXISTS (SELECT 1 FROM access_requests \
         WHERE id <> $1 AND client_name = $2 AND secret_name = $3 AND mechanism = $4 \
           AND constraints = $5 AND state = 'pending' AND push_delivered_at > $6)",
    )
    .bind(row.id)
    .bind(&row.client_name)
    .bind(&row.secret_name)
    .bind(&row.mechanism)
    .bind(&row.constraints)
    .bind(since)
    .fetch_one(db)
    .await?)
}

/// Purge lifecycle (addendum #11d): delete replay rows whose window has
/// closed. Their pin on secret_versions ends with them.
pub async fn delete_stale_grant_reads(db: &PgPool, cutoff: DateTime<Utc>) -> anyhow::Result<u64> {
    let res = sqlx::query("DELETE FROM grant_reads WHERE first_read_at < $1")
        .bind(cutoff)
        .execute(db)
        .await?;
    Ok(res.rows_affected())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::{AadContext, EphemeralKek, Keyset};
    use crate::db::requests::PassthroughPayload;
    use chrono::Duration;
    use secrecy::SecretBox;

    struct TestDb {
        pool: PgPool,
        admin_url: String,
        name: String,
    }

    /// Fresh randomly-named database + migrations, gated on KEYCHUTE_TEST_DB
    /// (same pattern as `db::tests`).
    async fn setup() -> anyhow::Result<Option<TestDb>> {
        let Ok(admin_url) = std::env::var("KEYCHUTE_TEST_DB") else {
            println!("skipped: KEYCHUTE_TEST_DB unset");
            return Ok(None);
        };
        let admin = PgPool::connect(&admin_url).await?;
        let name = format!("keychute_uiext_{:08x}", rand::random::<u32>());
        sqlx::query(&format!("CREATE DATABASE {name}"))
            .execute(&admin)
            .await?;
        admin.close().await;
        let base = admin_url
            .rsplit_once('/')
            .map(|(b, _)| b.to_owned())
            .ok_or_else(|| anyhow::anyhow!("KEYCHUTE_TEST_DB must include a database path"))?;
        let pool = PgPool::connect(&format!("{base}/{name}")).await?;
        sqlx::migrate!("../migrations").run(&pool).await?;
        Ok(Some(TestDb {
            pool,
            admin_url,
            name,
        }))
    }

    impl TestDb {
        async fn teardown(self) {
            self.pool.close().await;
            if let Ok(admin) = PgPool::connect(&self.admin_url).await {
                let _ = sqlx::query(&format!("DROP DATABASE {} WITH (FORCE)", self.name))
                    .execute(&admin)
                    .await;
                admin.close().await;
            }
        }
    }

    fn test_keyset() -> Keyset {
        use base64::Engine;
        let dir = std::env::temp_dir().join(format!("keychute-uiext-{}", Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("keyset.json");
        let b64 = |b: &[u8]| base64::engine::general_purpose::STANDARD.encode(b);
        std::fs::write(
            &path,
            serde_json::json!({
                "active": "k0",
                "keys": {"k0": b64(&[1u8; 32])},
                "mac_key": b64(&[9u8; 32]),
            })
            .to_string(),
        )
        .unwrap();
        let ks = Keyset::load(&path).unwrap();
        std::fs::remove_dir_all(&dir).ok();
        ks
    }

    async fn insert_pending(
        db: &PgPool,
        secret_name: &str,
        idem: &str,
        expires_at: DateTime<Utc>,
    ) -> anyhow::Result<AccessRequestRow> {
        let req = crate::db::requests::NewAccessRequest {
            client_name: "test-client".into(),
            secret_name: secret_name.into(),
            mechanism: "cli-read".into(),
            constraints: serde_json::json!({"ttl_seconds": 600}),
            context_ciphertext: None,
            context_nonce: None,
            context_wrapped_dek: None,
            context_kek_id: None,
            expires_at,
            policy_not_after: None,
            idem_client: "test-client".into(),
            idem_key: idem.into(),
            idem_mac: vec![0u8; 32],
        };
        Ok(crate::db::requests::insert_access_request(db, &req)
            .await?
            .row)
    }

    fn grant_params(passthrough: Option<PassthroughPayload>) -> GrantParams {
        GrantParams {
            client_name: "test-client".into(),
            secret_name: "s1".into(),
            mechanism: "cli-read".into(),
            constraints: serde_json::json!({"ttl_seconds": 600}),
            not_after: Utc::now() + Duration::seconds(600),
            max_uses: Some(1),
            passthrough,
        }
    }

    #[tokio::test]
    async fn approve_with_store_and_with_passthrough() -> anyhow::Result<()> {
        let Some(t) = setup().await? else {
            return Ok(());
        };
        let db = &t.pool;
        let keyset = test_keyset();
        let ephemeral = EphemeralKek::generate();

        // Store path: approval creates the secret + version 1 + grant.
        let row = insert_pending(db, "s1", "k1", Utc::now() + Duration::seconds(600)).await?;
        let secret_id = Uuid::new_v4();
        let sealed = keyset
            .seal(
                &SecretBox::new(b"hunter2".as_slice().into()),
                AadContext::SecretVersion {
                    secret_id,
                    version: 1,
                },
            )
            .unwrap();
        let store = StoreSecretParams {
            secret_id,
            name: "s1".into(),
            description: "test".into(),
            max_tier: 2,
            injection_kind: "bearer".into(),
            injection_header: None,
            injection_username: None,
            sealed,
        };
        let grant_id = Uuid::new_v4();
        let got = approve_request(
            db,
            row.id,
            "andrew",
            grant_id,
            &grant_params(None),
            Some(&store),
        )
        .await?;
        assert_eq!(got, Some(grant_id));
        let secret = crate::db::get_secret_by_name(db, "s1").await?.unwrap();
        assert_eq!(secret.current_version, 1);
        let version = crate::db::get_secret_version(db, secret.id, 1)
            .await?
            .unwrap();
        assert_eq!(version.created_by_request, Some(row.id));
        let grant = crate::db::get_grant(db, grant_id).await?.unwrap();
        assert!(!grant.passthrough_ephemeral);
        assert!(grant.passthrough_ciphertext.is_none());
        // Re-approving the same request writes nothing.
        assert_eq!(
            approve_request(
                db,
                row.id,
                "andrew",
                Uuid::new_v4(),
                &grant_params(None),
                None
            )
            .await?,
            None
        );

        // Passthrough path.
        let row2 = insert_pending(db, "s2", "k2", Utc::now() + Duration::seconds(600)).await?;
        let g2 = Uuid::new_v4();
        let sealed = ephemeral
            .seal(
                &SecretBox::new(b"once".as_slice().into()),
                AadContext::GrantPassthrough { grant_id: g2 },
            )
            .unwrap();
        let pt = PassthroughPayload {
            ciphertext: sealed.ciphertext,
            nonce: sealed.nonce,
            wrapped_dek: sealed.wrapped_dek,
            ephemeral: true,
        };
        let got = approve_request(db, row2.id, "andrew", g2, &grant_params(Some(pt)), None).await?;
        assert_eq!(got, Some(g2));
        let grant = crate::db::get_grant(db, g2).await?.unwrap();
        assert!(grant.passthrough_ephemeral);
        let opened = ephemeral
            .open(
                grant.passthrough_ciphertext.as_deref().unwrap(),
                grant.passthrough_nonce.as_deref().unwrap(),
                grant.passthrough_wrapped_dek.as_deref().unwrap(),
                AadContext::GrantPassthrough { grant_id: g2 },
            )
            .unwrap();
        use secrecy::ExposeSecret;
        assert_eq!(opened.expose_secret(), b"once");

        // Expired-but-still-pending request cannot be approved (addendum #8).
        let row3 = insert_pending(db, "s3", "k3", Utc::now() - Duration::seconds(5)).await?;
        assert_eq!(
            approve_request(
                db,
                row3.id,
                "andrew",
                Uuid::new_v4(),
                &grant_params(None),
                None
            )
            .await?,
            None
        );

        t.teardown().await;
        Ok(())
    }

    #[tokio::test]
    async fn dedup_active_grants_and_grant_read_purge() -> anyhow::Result<()> {
        let Some(t) = setup().await? else {
            return Ok(());
        };
        let db = &t.pool;
        let now = Utc::now();

        let a = insert_pending(db, "dup", "d1", now + Duration::seconds(600)).await?;
        let b = insert_pending(db, "dup", "d2", now + Duration::seconds(600)).await?;
        // No delivery recorded anywhere: no dedup.
        assert!(!recent_duplicate_push(db, &b, now - Duration::seconds(60)).await?);
        crate::db::mark_push_delivered(db, a.id).await?;
        // Twin (same client/secret/mechanism/constraints) delivered just now.
        assert!(recent_duplicate_push(db, &b, now - Duration::seconds(60)).await?);
        // Outside the window: no dedup.
        assert!(!recent_duplicate_push(db, &b, now + Duration::seconds(60)).await?);
        // A row never dedups against itself.
        assert!(!recent_duplicate_push(db, &a, now - Duration::seconds(60)).await?);

        // Active-grant listing excludes revoked/expired.
        let g_live = Uuid::new_v4();
        approve_request(db, a.id, "andrew", g_live, &grant_params(None), None).await?;
        let g_dead = Uuid::new_v4();
        approve_request(db, b.id, "andrew", g_dead, &grant_params(None), None).await?;
        crate::db::revoke_grant(db, g_dead, "andrew").await?;
        let active: Vec<Uuid> = list_active_grants(db).await?.iter().map(|g| g.id).collect();
        assert!(active.contains(&g_live));
        assert!(!active.contains(&g_dead));

        // grant_reads purge honors the cutoff.
        sqlx::query(
            "INSERT INTO grant_reads (grant_id, idem_key, first_read_at) VALUES ($1, 'old', $2)",
        )
        .bind(g_live)
        .bind(now - Duration::seconds(300))
        .execute(db)
        .await?;
        sqlx::query(
            "INSERT INTO grant_reads (grant_id, idem_key, first_read_at) VALUES ($1, 'new', $2)",
        )
        .bind(g_live)
        .bind(now)
        .execute(db)
        .await?;
        let purged = delete_stale_grant_reads(db, now - Duration::seconds(60)).await?;
        assert_eq!(purged, 1);

        t.teardown().await;
        Ok(())
    }

    #[tokio::test]
    async fn create_and_rotate_secret() -> anyhow::Result<()> {
        let Some(t) = setup().await? else {
            return Ok(());
        };
        let db = &t.pool;
        let keyset = test_keyset();

        let secret_id = Uuid::new_v4();
        let sealed = keyset
            .seal(
                &SecretBox::new(b"v1".as_slice().into()),
                AadContext::SecretVersion {
                    secret_id,
                    version: 1,
                },
            )
            .unwrap();
        create_secret_with_version(
            db,
            &StoreSecretParams {
                secret_id,
                name: "rot".into(),
                description: String::new(),
                max_tier: 0,
                injection_kind: "header".into(),
                injection_header: Some("X-Api-Key".into()),
                injection_username: None,
                sealed,
            },
            "andrew",
        )
        .await?;

        let row = rotate_secret_version(db, secret_id, "rot", "andrew", |version| {
            assert_eq!(version, 2);
            keyset.seal(
                &SecretBox::new(b"v2".as_slice().into()),
                AadContext::SecretVersion { secret_id, version },
            )
        })
        .await?;
        assert_eq!(row.version, 2);
        let secret = crate::db::get_secret_by_name(db, "rot").await?.unwrap();
        assert_eq!(secret.current_version, 2);
        // Rotated payload opens with the version-bound AAD.
        use secrecy::ExposeSecret;
        let opened = keyset
            .open(
                &row.ciphertext,
                &row.nonce,
                &row.wrapped_dek,
                &row.kek_id,
                AadContext::SecretVersion {
                    secret_id,
                    version: 2,
                },
            )
            .unwrap();
        assert_eq!(opened.expose_secret(), b"v2");
        // Audit rows exist for create + rotate.
        let kinds: Vec<String> =
            sqlx::query_scalar("SELECT kind FROM audit_log WHERE secret_name = 'rot' ORDER BY id")
                .fetch_all(db)
                .await?;
        assert_eq!(kinds, vec!["secret-created", "secret-rotated"]);

        t.teardown().await;
        Ok(())
    }
}
