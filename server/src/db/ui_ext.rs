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

use crate::db::{take_kek_shared_lock, SealFn};

/// Secret created at approval time ("store this secret in Keychute",
/// addendum #16). `secret_id` is app-generated so the payload's
/// `SecretVersion { secret_id, version: 1 }` AAD is known before the
/// transaction opens — the sealing itself happens inside it.
pub struct StoreSecretParams<'a> {
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
    /// Seals the value under the durable keyset with AAD
    /// SecretVersion{secret_id, 1}. Called inside the writing transaction,
    /// under the KEK shared lock ([`crate::db::SealFn`]).
    pub seal: SealFn<'a>,
}

/// Outcome of [`approve_request`]. Every non-`Approved` variant means nothing
/// was written at all.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ApproveOutcome {
    Approved(Uuid),
    /// The request was resolved or expired concurrently.
    NotApprovable,
    /// "Also store this secret" lost a race for the name — a client deposit
    /// (`POST /v1/secrets`) or another operator got there first.
    SecretNameTaken,
}

/// Approve a pending request with an app-supplied grant id (required for
/// passthrough payloads, whose AAD binds the grant id before insert).
///
/// One transaction: flip `pending -> approved` (rowcount-checked, incl.
/// `now() < expires_at` per addendum #8), optionally create the secret +
/// version 1 (addendum #16, sealed here under the KEK shared lock), insert the
/// grant, audit. Nothing is written unless the whole thing succeeds.
pub async fn approve_request(
    db: &PgPool,
    request_id: Uuid,
    resolved_by: &str,
    grant_id: Uuid,
    grant: &GrantParams,
    store: Option<StoreSecretParams<'_>>,
) -> anyhow::Result<ApproveOutcome> {
    let mut tx = db.begin().await?;
    // Only the stored-secret path inserts a KEYSET-wrapped DEK. A passthrough
    // payload is wrapped under the process-local ephemeral KEK, which is not in
    // the keyset and is never retired ([`crate::db::PassthroughPayload`]), so
    // addendum #19 does not apply to it.
    if store.is_some() {
        take_kek_shared_lock(&mut tx).await?;
    }
    // `$3` is the proposed grant deadline (requested TTL already capped at
    // `policy_not_after` by the handler), rechecked on the DB clock inside
    // this transaction: the handler computed it before waiting on the KEK
    // advisory lock and sealing, and approving past it would hand the client
    // an approved status whose grant can only ever return `grant-expired`.
    // `RETURNING secret_name` is the request's OWN name, read inside the
    // transaction that resolves it: the operator may have approved against a
    // different stored secret (UI substitution), and the audit row below has to
    // record which name was asked for versus which one was actually released.
    let requested_name: Option<String> = sqlx::query_scalar(
        "UPDATE access_requests \
         SET state = 'approved', resolved_by = $2, resolved_at = now() \
         WHERE id = $1 AND state = 'pending' AND now() < expires_at AND now() < $3 \
         RETURNING secret_name",
    )
    .bind(request_id)
    .bind(resolved_by)
    .bind(grant.not_after)
    .fetch_optional(&mut *tx)
    .await?;
    let Some(requested_name) = requested_name else {
        return Ok(ApproveOutcome::NotApprovable);
    };

    if let Some(s) = store {
        // Sealed here, not by the caller: the KEK shared lock is already held,
        // so the key this picks cannot be retired before the version row
        // commits (addendum #19).
        let sealed = (s.seal)().map_err(|e| anyhow::anyhow!("sealing secret: {e}"))?;
        // The approval page rendered against "no such secret" and the handler
        // rechecked it, but a client deposit (`POST /v1/secrets`) can claim the
        // name in the gap. Losing that race must roll the approval back with a
        // 409 the operator can act on — not a unique violation surfacing as a
        // 500 — and must never touch the bytes the winner stored.
        let inserted = sqlx::query(
            "INSERT INTO secrets \
             (id, name, description, max_tier, injection_kind, injection_header, \
              injection_username, current_version) \
             VALUES ($1, $2, $3, $4, $5, $6, $7, 1) \
             ON CONFLICT (name) DO NOTHING",
        )
        .bind(s.secret_id)
        .bind(&s.name)
        .bind(&s.description)
        .bind(s.max_tier)
        .bind(&s.injection_kind)
        .bind(&s.injection_header)
        .bind(&s.injection_username)
        .execute(&mut *tx)
        .await?
        .rows_affected();
        if inserted == 0 {
            tx.rollback().await?;
            return Ok(ApproveOutcome::SecretNameTaken);
        }
        sqlx::query(
            "INSERT INTO secret_versions \
             (secret_id, version, ciphertext, nonce, wrapped_dek, kek_id, created_by_request) \
             VALUES ($1, 1, $2, $3, $4, $5, $6)",
        )
        .bind(s.secret_id)
        .bind(&sealed.ciphertext)
        .bind(&sealed.nonce)
        .bind(&sealed.wrapped_dek)
        .bind(&sealed.kek_id)
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

    // See `requests::resolve_approve`: payloads are ephemeral-KEK-sealed by
    // construction, and the flag outlives the ciphertext the sweeper nulls.
    let (pt_ct, pt_nonce, pt_dek, pt_eph) = match &grant.passthrough {
        Some(p) => {
            let (ct, nonce, dek) = p.parts();
            (Some(ct), Some(nonce), Some(dek), true)
        }
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
            // Server vocabulary only: the name the client asked for, recorded
            // when the operator released a DIFFERENT stored secret instead.
            // `secret_name` above is always what was actually released.
            detail: (requested_name != grant.secret_name)
                .then(|| serde_json::json!({ "substituted_for_requested_name": requested_name })),
            ..Default::default()
        },
    )
    .await?;
    tx.commit().await?;
    Ok(ApproveOutcome::Approved(grant_id))
}

/// Create a secret with its version 1 from the admin UI (`POST /ui/secrets`),
/// with the `secret-created` audit row in the same transaction. The payload is
/// sealed inside that transaction, under the KEK shared lock (addendum #19).
///
/// Returns `Ok(false)` when the name was taken between the handler's
/// "does this exist?" lookup and this insert — a real race now that clients can
/// deposit secrets too (`POST /v1/secrets`). The caller re-renders instead of
/// surfacing a unique-violation as a 500; nothing is overwritten either way.
pub async fn create_secret_with_version(
    db: &PgPool,
    store: StoreSecretParams<'_>,
    actor: &str,
) -> anyhow::Result<bool> {
    let mut tx = db.begin().await?;
    take_kek_shared_lock(&mut tx).await?;
    let sealed = (store.seal)().map_err(|e| anyhow::anyhow!("sealing secret: {e}"))?;
    let inserted = sqlx::query(
        "INSERT INTO secrets \
         (id, name, description, max_tier, injection_kind, injection_header, \
          injection_username, current_version) \
         VALUES ($1, $2, $3, $4, $5, $6, $7, 1) \
         ON CONFLICT (name) DO NOTHING",
    )
    .bind(store.secret_id)
    .bind(&store.name)
    .bind(&store.description)
    .bind(store.max_tier)
    .bind(&store.injection_kind)
    .bind(&store.injection_header)
    .bind(&store.injection_username)
    .execute(&mut *tx)
    .await?
    .rows_affected();
    if inserted == 0 {
        tx.rollback().await?;
        return Ok(false);
    }
    sqlx::query(
        "INSERT INTO secret_versions \
         (secret_id, version, ciphertext, nonce, wrapped_dek, kek_id) \
         VALUES ($1, 1, $2, $3, $4, $5)",
    )
    .bind(store.secret_id)
    .bind(&sealed.ciphertext)
    .bind(&sealed.nonce)
    .bind(&sealed.wrapped_dek)
    .bind(&sealed.kek_id)
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
    Ok(true)
}

/// Rotate a stored secret: bump `current_version`, seal the new payload with
/// the version-bound AAD (the closure receives the new version number), insert
/// the version row, and audit `secret-rotated` — one transaction.
///
/// Rotation is operator-only, and the value being rotated in is the operator's
/// own: it clears any unvetted flag left by a client deposit (migration 0007)
/// in the same statement that bumps the version. Leaving it set would keep
/// forcing manual approval for a credential the operator just typed, and would
/// label their own value "not yet reviewed".
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
        "UPDATE secrets \
         SET current_version = current_version + 1, operator_vetted = true, updated_at = now() \
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

/// Grants that can still release a credential: not revoked, not past
/// `not_after`, and either with uses remaining (the fresh-use predicate
/// `begin_grant_use` increments under) OR still inside a replay window.
///
/// The replay clause matters for revocation: an exhausted grant keeps
/// re-releasing the same plaintext to a same-key retry until its window
/// closes, and revoking is the ONLY thing that stops that (it makes replay
/// return `ExpiredOrRevoked` and nulls the passthrough ciphertext). Hiding
/// such a grant from the operator would remove the revoke button during
/// precisely the window where it still does something.
/// What "active" means, shared by the list and the overview's count so the
/// two can never disagree. `$1` is the replay window in seconds.
const ACTIVE_GRANTS_PREDICATE: &str = "NOT g.revoked AND now() < g.not_after \
     AND ((g.max_uses IS NULL OR g.use_count < g.max_uses) \
          OR EXISTS (SELECT 1 FROM grant_reads r \
                     WHERE r.grant_id = g.id \
                       AND r.first_read_at > now() - make_interval(secs => $1::double precision)))";

pub async fn list_active_grants(
    db: &PgPool,
    replay_window_seconds: i64,
) -> anyhow::Result<Vec<GrantRow>> {
    let sql = format!(
        "SELECT * FROM grants g WHERE {ACTIVE_GRANTS_PREDICATE} ORDER BY g.created_at DESC"
    );
    Ok(sqlx::query_as::<_, GrantRow>(&sql)
        .bind(replay_window_seconds as f64)
        .fetch_all(db)
        .await?)
}

/// Active grants — the count only, for the overview page. Same reasoning as
/// [`crate::db::count_pending`]: `GrantRow` can carry a passthrough payload,
/// which a count has no business loading.
pub async fn count_active_grants(db: &PgPool, replay_window_seconds: i64) -> anyhow::Result<i64> {
    let sql = format!("SELECT count(*) FROM grants g WHERE {ACTIVE_GRANTS_PREDICATE}");
    Ok(sqlx::query_scalar(&sql)
        .bind(replay_window_seconds as f64)
        .fetch_one(db)
        .await?)
}

/// Push dedup (addendum #10): true when another pending request with the same
/// dedup key (client + secret + mechanism + normalized-constraints jsonb) had
/// a push ACTUALLY SENT after `since`.
///
/// `push_attempts > 0` is the "actually sent" part and it is load-bearing: a
/// deduped row is itself marked delivered (so the sweeper stops reselecting
/// it) WITHOUT a push being sent, and without this predicate that row would
/// become the next arrival's dedup target. A client re-submitting an
/// identical request just inside the window would then chain dedups
/// indefinitely and the operator would be notified exactly once, ever, while
/// requests piled up unattended. Only rows that really pushed can suppress.
pub async fn recent_duplicate_push(
    db: &PgPool,
    row: &AccessRequestRow,
    since: DateTime<Utc>,
) -> anyhow::Result<bool> {
    Ok(sqlx::query_scalar(
        "SELECT EXISTS (SELECT 1 FROM access_requests \
         WHERE id <> $1 AND client_name = $2 AND secret_name = $3 AND mechanism = $4 \
           AND constraints = $5 AND state = 'pending' AND push_delivered_at > $6 \
           AND push_attempts > 0)",
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

/// Purge lifecycle (addendum #11d): drop the secret_versions pin of replay
/// rows whose window has closed. The row itself is KEPT as a tombstone:
/// deleting it would let the same idempotency key — which
/// [`crate::db::grants::begin_grant_use`] already reported as `Exhausted` —
/// silently burn a fresh use on a multi-use grant after the next sweep, and
/// release a newer secret version under a key the caller believes is spent.
/// Tombstones die with their grant (`ON DELETE CASCADE`).
///
/// The window is evaluated on the DATABASE clock, matching the replay
/// predicate in [`crate::db::grants::begin_grant_use`]: a cutoff from the
/// process clock could drop a pin that an in-window replay still needs.
pub async fn unpin_stale_grant_reads(
    db: &PgPool,
    replay_window_seconds: i64,
) -> anyhow::Result<u64> {
    let res = sqlx::query(
        "UPDATE grant_reads SET secret_version_id = NULL \
         WHERE first_read_at < now() - make_interval(secs => $1::double precision) \
           AND secret_version_id IS NOT NULL",
    )
    .bind(replay_window_seconds as f64)
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
            expires_at,
            policy_not_after: None,
            idem_client: "test-client".into(),
            idem_key: idem.into(),
            idem_mac: vec![0u8; 32],
        };
        Ok(crate::db::requests::insert_access_request(db, &req, None)
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
    async fn approve_refuses_an_already_elapsed_grant_deadline() -> anyhow::Result<()> {
        let Some(t) = setup().await? else {
            return Ok(());
        };
        let db = &t.pool;
        // The handler computed the deadline before the transaction; if it has
        // already passed (short TTL, expired policy cap), approving would mint
        // a grant that can only ever return grant-expired.
        let row =
            insert_pending(db, "s-late", "late-1", Utc::now() + Duration::seconds(600)).await?;
        let mut params = grant_params(None);
        params.not_after = Utc::now() - Duration::seconds(1);
        let got = approve_request(db, row.id, "andrew", Uuid::new_v4(), &params, None).await?;
        assert_eq!(got, ApproveOutcome::NotApprovable);
        // Nothing was written: the request is still pending and approvable.
        let r = crate::db::get_request(db, row.id).await?.unwrap();
        assert_eq!(r.state, "pending");
        Ok(())
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
        let store = StoreSecretParams {
            secret_id,
            name: "s1".into(),
            description: "test".into(),
            max_tier: 2,
            injection_kind: "bearer".into(),
            injection_header: None,
            injection_username: None,
            seal: Box::new(|| {
                keyset.seal(
                    &SecretBox::new(b"hunter2".as_slice().into()),
                    AadContext::SecretVersion {
                        secret_id,
                        version: 1,
                    },
                )
            }),
        };
        let grant_id = Uuid::new_v4();
        let got = approve_request(
            db,
            row.id,
            "andrew",
            grant_id,
            &grant_params(None),
            Some(store),
        )
        .await?;
        assert_eq!(got, ApproveOutcome::Approved(grant_id));
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
            ApproveOutcome::NotApprovable
        );

        // Passthrough path.
        let row2 = insert_pending(db, "s2", "k2", Utc::now() + Duration::seconds(600)).await?;
        let g2 = Uuid::new_v4();
        let pt =
            PassthroughPayload::seal(&ephemeral, g2, &SecretBox::new(b"once".as_slice().into()))
                .unwrap();
        let got = approve_request(db, row2.id, "andrew", g2, &grant_params(Some(pt)), None).await?;
        assert_eq!(got, ApproveOutcome::Approved(g2));
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
            ApproveOutcome::NotApprovable
        );

        t.teardown().await;
        Ok(())
    }

    /// A client deposit can claim the name between the approval page rendering
    /// and the approve transaction. That must roll the whole approval back —
    /// no grant, request still pending — rather than fail on a unique
    /// violation (a 500 for the operator) or touch the winner's bytes.
    #[tokio::test]
    async fn approve_with_store_loses_a_name_race_cleanly() -> anyhow::Result<()> {
        let Some(t) = setup().await? else {
            return Ok(());
        };
        let db = &t.pool;
        let keyset = test_keyset();

        // The client's deposit lands first.
        let deposited_id = Uuid::new_v4();
        crate::db::create_secret_from_client(
            db,
            StoreSecretParams {
                secret_id: deposited_id,
                name: "contested".into(),
                description: "from the client".into(),
                max_tier: 0,
                injection_kind: "bearer".into(),
                injection_header: None,
                injection_username: None,
                seal: Box::new(|| {
                    keyset.seal(
                        &SecretBox::new(b"client-value".as_slice().into()),
                        AadContext::SecretVersion {
                            secret_id: deposited_id,
                            version: 1,
                        },
                    )
                }),
            },
            "k8s-agent",
            crate::db::DepositRate {
                max_per_window: 10,
                window_hours: 1,
            },
        )
        .await?;

        // The operator approves with "also store this", against a page that
        // rendered before the deposit existed.
        let row = insert_pending(
            db,
            "contested",
            "k-race",
            Utc::now() + Duration::seconds(600),
        )
        .await?;
        let secret_id = Uuid::new_v4();
        let got = approve_request(
            db,
            row.id,
            "andrew",
            Uuid::new_v4(),
            &grant_params(None),
            Some(StoreSecretParams {
                secret_id,
                name: "contested".into(),
                description: "from the operator".into(),
                max_tier: 2,
                injection_kind: "bearer".into(),
                injection_header: None,
                injection_username: None,
                seal: Box::new(|| {
                    keyset.seal(
                        &SecretBox::new(b"operator-value".as_slice().into()),
                        AadContext::SecretVersion {
                            secret_id,
                            version: 1,
                        },
                    )
                }),
            }),
        )
        .await?;
        assert_eq!(got, ApproveOutcome::SecretNameTaken);

        // Nothing was written: the request is still pending and approvable,
        // and the deposited row is untouched.
        let r = crate::db::get_request(db, row.id).await?.unwrap();
        assert_eq!(r.state, "pending");
        let secret = crate::db::get_secret_by_name(db, "contested")
            .await?
            .unwrap();
        assert_eq!(secret.id, deposited_id);
        assert_eq!(secret.description, "from the client");
        assert_eq!(secret.current_version, 1);

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
        // A real send claims the row (bumping push_attempts) and then marks
        // it delivered — that is what makes it a valid dedup target.
        assert!(crate::notify::claim_for_push(db, a.id).await?);
        crate::db::mark_push_delivered(db, a.id).await?;
        // Twin (same client/secret/mechanism/constraints) delivered just now.
        assert!(recent_duplicate_push(db, &b, now - Duration::seconds(60)).await?);
        // Outside the window: no dedup.
        assert!(!recent_duplicate_push(db, &b, now + Duration::seconds(60)).await?);
        // A row never dedups against itself.
        assert!(!recent_duplicate_push(db, &a, now - Duration::seconds(60)).await?);

        // Dedup must NOT chain: `b` is now marked delivered without ever
        // having pushed (that is what the dedup branch does), so a third
        // identical arrival must not dedup against `b` once `a` ages out —
        // otherwise a client re-submitting inside the window suppresses the
        // operator's notifications forever.
        crate::db::mark_push_delivered(db, b.id).await?;
        let c = insert_pending(db, "dup", "d3", now + Duration::seconds(600)).await?;
        // Window that excludes `a`'s real push but would include `b`'s
        // dedup-marked "delivery".
        let after_a: Vec<(chrono::DateTime<Utc>,)> =
            sqlx::query_as("SELECT push_delivered_at FROM access_requests WHERE id = $1")
                .bind(a.id)
                .fetch_all(db)
                .await?;
        let since = after_a[0].0 + Duration::milliseconds(1);
        assert!(!recent_duplicate_push(db, &c, since).await?);

        // Active-grant listing excludes revoked/expired.
        let g_live = Uuid::new_v4();
        approve_request(db, a.id, "andrew", g_live, &grant_params(None), None).await?;
        let g_dead = Uuid::new_v4();
        approve_request(db, b.id, "andrew", g_dead, &grant_params(None), None).await?;
        crate::db::revoke_grant(db, g_dead, "andrew").await?;
        let active: Vec<Uuid> = list_active_grants(db, 60)
            .await?
            .iter()
            .map(|g| g.id)
            .collect();
        assert!(active.contains(&g_live));
        assert!(!active.contains(&g_dead));

        // grant_reads unpin honors the cutoff, and keeps the burned rows.
        sqlx::query(
            "INSERT INTO grant_reads (grant_id, idem_key, secret_version_id, first_read_at) \
             VALUES ($1, 'old', $2, $3)",
        )
        .bind(g_live)
        .bind(Uuid::new_v4())
        .bind(now - Duration::seconds(300))
        .execute(db)
        .await?;
        sqlx::query(
            "INSERT INTO grant_reads (grant_id, idem_key, secret_version_id, first_read_at) \
             VALUES ($1, 'new', $2, $3)",
        )
        .bind(g_live)
        .bind(Uuid::new_v4())
        .bind(now)
        .execute(db)
        .await?;
        let unpinned = unpin_stale_grant_reads(db, 60).await?;
        assert_eq!(unpinned, 1);
        // A second sweep touches nothing (tombstones are not rewritten).
        assert_eq!(unpin_stale_grant_reads(db, 60).await?, 0);
        // The stale row survives as a tombstone (key stays burned) with its
        // version pin dropped; the in-window row keeps its pin.
        let rows: Vec<(String, Option<Uuid>)> = sqlx::query_as(
            "SELECT idem_key, secret_version_id FROM grant_reads WHERE grant_id = $1 \
             ORDER BY idem_key",
        )
        .bind(g_live)
        .fetch_all(db)
        .await?;
        assert_eq!(rows.len(), 2);
        assert_eq!(rows[1].0, "old");
        assert!(rows[1].1.is_none());
        assert_eq!(rows[0].0, "new");
        assert!(rows[0].1.is_some());

        // The property the tombstone exists for: the unpinned key is still
        // burned as far as `begin_grant_use` is concerned — never a fresh use.
        let burned = crate::db::begin_grant_use(
            db,
            g_live,
            Some("old"),
            None,
            kinds::RELEASE_ATTEMPT,
            60,
            None,
        )
        .await?;
        assert!(
            matches!(burned, crate::db::GrantUse::Exhausted),
            "unpinned tombstone must stay exhausted, got {burned:?}"
        );
        // ...and that verdict came from the key, not from a spent grant: an
        // unseen key on the same grant is still a first use.
        let fresh = crate::db::begin_grant_use(
            db,
            g_live,
            Some("fresh"),
            None,
            kinds::RELEASE_ATTEMPT,
            60,
            None,
        )
        .await?;
        assert!(
            matches!(fresh, crate::db::GrantUse::FirstUse { .. }),
            "grant should still have its use left, got {fresh:?}"
        );

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
        create_secret_with_version(
            db,
            StoreSecretParams {
                secret_id,
                name: "rot".into(),
                description: String::new(),
                max_tier: 0,
                injection_kind: "header".into(),
                injection_header: Some("X-Api-Key".into()),
                injection_username: None,
                seal: Box::new(|| {
                    keyset.seal(
                        &SecretBox::new(b"v1".as_slice().into()),
                        AadContext::SecretVersion {
                            secret_id,
                            version: 1,
                        },
                    )
                }),
            },
            "andrew",
        )
        .await?;

        // Pretend this row arrived as a client deposit: rotating in the
        // operator's own value must clear the unvetted flag, or the clamp
        // would keep forcing approval for a credential they just typed.
        sqlx::query("UPDATE secrets SET operator_vetted = false WHERE id = $1")
            .bind(secret_id)
            .execute(db)
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
        assert!(
            secret.operator_vetted,
            "an operator rotation vets the secret"
        );
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

    /// Addendum #19 ordering: a writer must not read the active KEK (seal)
    /// until it holds the shared advisory lock. With the exclusive side held —
    /// what `db::verify_no_references` does while it proves a KEK is
    /// unreferenced — the writer must still be parked, having sealed nothing.
    #[tokio::test]
    async fn sealing_waits_for_the_kek_advisory_lock() -> anyhow::Result<()> {
        use std::sync::atomic::{AtomicBool, Ordering};
        use std::sync::Arc;

        let Some(t) = setup().await? else {
            return Ok(());
        };
        let db = &t.pool;

        // Stand-in for the retirement path: hold the exclusive lock.
        let mut retiring = db.begin().await?;
        sqlx::query("SELECT pg_advisory_xact_lock(hashtext('keychute-kek'))")
            .execute(&mut *retiring)
            .await?;

        let sealed = Arc::new(AtomicBool::new(false));
        let flag = sealed.clone();
        let pool = db.clone();
        let keyset = test_keyset();
        let secret_id = Uuid::new_v4();
        let writer = tokio::spawn(async move {
            create_secret_with_version(
                &pool,
                StoreSecretParams {
                    secret_id,
                    name: "locked".into(),
                    description: String::new(),
                    max_tier: 0,
                    injection_kind: "bearer".into(),
                    injection_header: None,
                    injection_username: None,
                    seal: Box::new(move || {
                        flag.store(true, Ordering::SeqCst);
                        keyset.seal(
                            &SecretBox::new(b"v1".as_slice().into()),
                            AadContext::SecretVersion {
                                secret_id,
                                version: 1,
                            },
                        )
                    }),
                },
                "andrew",
            )
            .await
        });

        tokio::time::sleep(std::time::Duration::from_millis(300)).await;
        assert!(
            !sealed.load(Ordering::SeqCst),
            "sealed before taking the KEK shared lock"
        );
        // Retirement finishes; the writer proceeds and seals under the lock.
        retiring.rollback().await?;
        writer.await??;
        assert!(sealed.load(Ordering::SeqCst));
        assert!(crate::db::get_secret_by_name(db, "locked").await?.is_some());

        t.teardown().await;
        Ok(())
    }
}
