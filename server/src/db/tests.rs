//! DB smoke tests. These need a live Postgres: set KEYCHUTE_TEST_DB to an
//! admin URL (e.g. postgres://postgres@127.0.0.1:55432/postgres). When unset,
//! each test prints "skipped" and returns Ok.

use super::*;
use crate::audit;
use crate::config::{ClientAuthConfig, ClientConfig, ServiceAccountAuth};
use chrono::{Duration, Utc};
use keychute_types::{Mechanism, Tier};
use sqlx::PgPool;
use uuid::Uuid;

struct TestDb {
    pool: PgPool,
    admin_url: String,
    name: String,
}

/// Create a fresh randomly-named database off the admin URL and run
/// migrations on it. Returns None (after printing) when KEYCHUTE_TEST_DB is
/// unset.
async fn setup() -> anyhow::Result<Option<TestDb>> {
    let Ok(admin_url) = std::env::var("KEYCHUTE_TEST_DB") else {
        println!("skipped: KEYCHUTE_TEST_DB unset");
        return Ok(None);
    };
    let admin = PgPool::connect(&admin_url).await?;
    let name = format!("keychute_test_{:08x}", rand::random::<u32>());
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

fn token_client(name: &str) -> ClientConfig {
    ClientConfig {
        name: name.to_owned(),
        max_tier: Tier::CooperatingClient,
        mechanisms: vec![Mechanism::CliRead],
        auth: ClientAuthConfig {
            api_token_sha256: Some("ab".repeat(32)),
            service_account: None,
        },
    }
}

fn sa_client(name: &str) -> ClientConfig {
    ClientConfig {
        name: name.to_owned(),
        max_tier: Tier::Brokered,
        mechanisms: vec![Mechanism::Brokered],
        auth: ClientAuthConfig {
            api_token_sha256: None,
            service_account: Some(ServiceAccountAuth {
                audience: "keychute.example.dev".into(),
                subject: format!("system:serviceaccount:{name}:{name}"),
            }),
        },
    }
}

fn new_request(client: &str, idem_key: &str, mac: &[u8]) -> NewAccessRequest {
    NewAccessRequest {
        client_name: client.to_owned(),
        secret_name: "example-api-token".into(),
        mechanism: "cli-read".into(),
        constraints: serde_json::json!({ "ttl_seconds": 600, "max_uses": 1 }),
        context_ciphertext: None,
        context_nonce: None,
        context_wrapped_dek: None,
        context_kek_id: None,
        expires_at: Utc::now() + Duration::hours(1),
        idem_client: client.to_owned(),
        idem_key: idem_key.to_owned(),
        idem_mac: mac.to_vec(),
    }
}

#[tokio::test]
async fn migration_runs_on_fresh_database() -> anyhow::Result<()> {
    let Some(t) = setup().await? else {
        return Ok(());
    };
    let tables = vec![
        "secrets",
        "secret_versions",
        "secret_tags",
        "clients",
        "policies",
        "access_requests",
        "grants",
        "grant_reads",
        "audit_log",
    ];
    let n: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM information_schema.tables \
         WHERE table_schema = 'public' AND table_name = ANY($1)",
    )
    .bind(&tables)
    .fetch_one(&t.pool)
    .await?;
    assert_eq!(n, tables.len() as i64);
    t.teardown().await;
    Ok(())
}

#[tokio::test]
async fn reconcile_clients_is_idempotent_and_disables_removed() -> anyhow::Result<()> {
    let Some(t) = setup().await? else {
        return Ok(());
    };
    let a = token_client("family-assistant");
    let b = sa_client("k8s-agent");

    reconcile_clients(&t.pool, &[a.clone(), b.clone()]).await?;
    reconcile_clients(&t.pool, &[a.clone(), b.clone()]).await?;
    let rows = list_clients(&t.pool).await?;
    assert_eq!(rows.len(), 2);
    assert!(rows.iter().all(|r| r.enabled));
    let fa = get_client_by_name(&t.pool, "family-assistant")
        .await?
        .unwrap();
    assert_eq!(fa.auth_kind, "api-token");
    assert_eq!(fa.max_tier, Tier::CooperatingClient.as_int());
    assert_eq!(fa.mechanisms, vec!["cli-read".to_owned()]);
    let k8s = get_client_by_name(&t.pool, "k8s-agent").await?.unwrap();
    assert_eq!(k8s.auth_kind, "service-account");
    assert_eq!(k8s.sa_audience.as_deref(), Some("keychute.example.dev"));

    // Drop b from config: it must be disabled but retained.
    reconcile_clients(&t.pool, std::slice::from_ref(&a)).await?;
    let k8s = get_client_by_name(&t.pool, "k8s-agent").await?.unwrap();
    assert!(!k8s.enabled);
    assert!(
        get_client_by_name(&t.pool, "family-assistant")
            .await?
            .unwrap()
            .enabled
    );

    // Re-adding re-enables the same row (same id).
    reconcile_clients(&t.pool, &[a, b]).await?;
    let k8s2 = get_client_by_name(&t.pool, "k8s-agent").await?.unwrap();
    assert!(k8s2.enabled);
    assert_eq!(k8s2.id, k8s.id);
    t.teardown().await;
    Ok(())
}

#[tokio::test]
async fn insert_access_request_idempotency() -> anyhow::Result<()> {
    let Some(t) = setup().await? else {
        return Ok(());
    };
    let first = insert_access_request(&t.pool, &new_request("fa", "key-1", b"mac-one")).await?;
    assert!(first.created);

    // Same key + same payload MAC: same row, not created.
    let retry = insert_access_request(&t.pool, &new_request("fa", "key-1", b"mac-one")).await?;
    assert!(!retry.created);
    assert_eq!(retry.row.id, first.row.id);
    assert_eq!(retry.row.idem_mac, first.row.idem_mac);

    // Same key + DIFFERENT payload: original row returned; caller sees the
    // MAC mismatch and answers 409.
    let conflict = insert_access_request(&t.pool, &new_request("fa", "key-1", b"mac-two")).await?;
    assert!(!conflict.created);
    assert_eq!(conflict.row.id, first.row.id);
    assert_eq!(conflict.row.idem_mac, b"mac-one".to_vec());

    // Same key, different client: independent request.
    let other = insert_access_request(&t.pool, &new_request("other", "key-1", b"mac-one")).await?;
    assert!(other.created);
    assert_ne!(other.row.id, first.row.id);
    t.teardown().await;
    Ok(())
}

#[tokio::test]
async fn begin_grant_use_single_use_semantics() -> anyhow::Result<()> {
    let Some(t) = setup().await? else {
        return Ok(());
    };
    let req = insert_access_request(&t.pool, &new_request("fa", "grant-key", b"mac")).await?;
    let grant_id = resolve_approve(
        &t.pool,
        req.row.id,
        "andrew",
        &GrantParams {
            client_name: "fa".into(),
            secret_name: "example-api-token".into(),
            mechanism: "cli-read".into(),
            constraints: serde_json::json!({ "ttl_seconds": 600, "max_uses": 1 }),
            not_after: Utc::now() + Duration::hours(1),
            max_uses: Some(1),
            passthrough: None,
        },
    )
    .await?
    .expect("request was pending");

    // A second approval of the same request writes nothing.
    assert!(resolve_approve(
        &t.pool,
        req.row.id,
        "andrew",
        &GrantParams {
            client_name: "fa".into(),
            secret_name: "example-api-token".into(),
            mechanism: "cli-read".into(),
            constraints: serde_json::json!({}),
            not_after: Utc::now() + Duration::hours(1),
            max_uses: Some(1),
            passthrough: None,
        },
    )
    .await?
    .is_none());

    let version_id = Uuid::new_v4();
    let mut handles = Vec::new();
    for i in 0..10 {
        let pool = t.pool.clone();
        handles.push(tokio::spawn(async move {
            let key = format!("reader-{i}");
            let out = begin_grant_use(
                &pool,
                grant_id,
                Some(&key),
                Some(version_id),
                audit::kinds::RELEASE_ATTEMPT,
                60,
            )
            .await
            .expect("db error");
            (key, out)
        }));
    }
    let mut first_use_keys = Vec::new();
    let mut exhausted = 0;
    for h in handles {
        let (key, out) = h.await?;
        match out {
            GrantUse::FirstUse { grant } => {
                assert_eq!(grant.use_count, 1);
                first_use_keys.push(key);
            }
            GrantUse::Exhausted => exhausted += 1,
            other => panic!("unexpected outcome: {other:?}"),
        }
    }
    assert_eq!(first_use_keys.len(), 1, "exactly one first use");
    assert_eq!(exhausted, 9);

    // Replay with the winning key returns the pinned version, no increment.
    match begin_grant_use(
        &t.pool,
        grant_id,
        Some(&first_use_keys[0]),
        Some(Uuid::new_v4()), // deliberately different: pinned id must win
        audit::kinds::RELEASE_ATTEMPT,
        60,
    )
    .await?
    {
        GrantUse::Replay {
            grant,
            secret_version_id,
            passthrough,
        } => {
            assert_eq!(secret_version_id, Some(version_id));
            assert!(!passthrough);
            assert_eq!(grant.use_count, 1);
        }
        other => panic!("expected Replay, got {other:?}"),
    }

    // A different key on the consumed grant is Exhausted.
    match begin_grant_use(
        &t.pool,
        grant_id,
        Some("fresh-key"),
        Some(version_id),
        audit::kinds::RELEASE_ATTEMPT,
        60,
    )
    .await?
    {
        GrantUse::Exhausted => {}
        other => panic!("expected Exhausted, got {other:?}"),
    }

    let g = get_grant(&t.pool, grant_id).await?.unwrap();
    assert_eq!(g.use_count, 1);

    // Write-ahead audit: one release-attempt for the first use, one for the
    // replay (the exhausted attempts write nothing).
    let attempts: i64 =
        sqlx::query_scalar("SELECT count(*) FROM audit_log WHERE kind = $1 AND grant_id = $2")
            .bind(audit::kinds::RELEASE_ATTEMPT)
            .bind(grant_id)
            .fetch_one(&t.pool)
            .await?;
    assert_eq!(attempts, 2);

    // Unknown grant id.
    match begin_grant_use(
        &t.pool,
        Uuid::new_v4(),
        Some("x"),
        None,
        audit::kinds::RELEASE_ATTEMPT,
        60,
    )
    .await?
    {
        GrantUse::NotFound => {}
        other => panic!("expected NotFound, got {other:?}"),
    }

    // Revocation beats replay.
    assert!(revoke_grant(&t.pool, grant_id, "andrew").await?);
    match begin_grant_use(
        &t.pool,
        grant_id,
        Some(&first_use_keys[0]),
        None,
        audit::kinds::RELEASE_ATTEMPT,
        60,
    )
    .await?
    {
        GrantUse::ExpiredOrRevoked => {}
        other => panic!("expected ExpiredOrRevoked, got {other:?}"),
    }

    t.teardown().await;
    Ok(())
}
