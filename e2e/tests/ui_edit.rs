//! Editing standing policies and stored secrets through the real UI: the edit
//! pages pre-fill from the row, saving rewrites it in place (audited), and the
//! change is what the policy engine and grant revalidation act on next.

use keychute_e2e::*;

async fn policy_id(env: &TestEnv) -> uuid::Uuid {
    sqlx::query_scalar("SELECT id FROM policies")
        .fetch_one(&env.db)
        .await
        .unwrap()
}

async fn secret_id(env: &TestEnv, name: &str) -> uuid::Uuid {
    sqlx::query_scalar("SELECT id FROM secrets WHERE name = $1")
        .bind(name)
        .fetch_one(&env.db)
        .await
        .unwrap()
}

async fn audit_count(env: &TestEnv, kind: &str) -> i64 {
    sqlx::query_scalar("SELECT count(*) FROM audit_log WHERE kind = $1")
        .bind(kind)
        .fetch_one(&env.db)
        .await
        .unwrap()
}

/// POST the policy edit form for `id`, with a token from its edit page.
async fn submit_policy_edit(
    env: &TestEnv,
    id: uuid::Uuid,
    fields: &[(&str, &str)],
) -> (reqwest::StatusCode, String) {
    let page = env
        .ui_get(&format!("/ui/policies/{id}/edit"))
        .await
        .unwrap();
    let action = format!("/ui/policies/{id}");
    let token = extract_csrf(&page, &action).expect("edit form csrf token");
    let mut form: Vec<(&str, &str)> = vec![("csrf_token", &token)];
    form.extend_from_slice(fields);
    env.ui_post(&action, &form).await.unwrap()
}

async fn setup_autofill(env: &TestEnv, tier: &str, outcome: &str) {
    env.seed_secret("hellofresh-login", "hunter2", tier, "bearer", "")
        .await
        .unwrap();
    env.create_policy(&[
        ("client_name", "family-assistant"),
        ("secret_name", "hellofresh-login"),
        ("mechanism", "autofill"),
        ("outcome", outcome),
        ("origins", "hellofresh.com"),
        ("max_ttl_seconds", "86400"),
    ])
    .await
    .unwrap();
}

async fn autofill(env: &TestEnv, idem: &str) -> serde_json::Value {
    let (_, body) = env
        .fa()
        .create_request(autofill_request(
            idem,
            "hellofresh-login",
            &["hellofresh.com"],
            3600,
        ))
        .await
        .unwrap();
    body
}

#[tokio::test(flavor = "multi_thread")]
async fn policy_edit_changes_outcome_in_place() {
    let env = TestEnv::spawn(SpawnOpts::default()).await.unwrap();
    setup_autofill(&env, "trusted-client", "require-approval").await;
    assert_eq!(autofill(&env, "before").await["state"], "pending");

    let id = policy_id(&env).await;
    let list = env.ui_get("/ui/policies").await.unwrap();
    assert!(
        list.contains(&format!("href=\"/ui/policies/{id}/edit\"")),
        "{list}"
    );
    let page = env
        .ui_get(&format!("/ui/policies/{id}/edit"))
        .await
        .unwrap();
    assert!(
        page.contains(r#"<option value="require-approval" selected>"#),
        "{page}"
    );
    assert!(
        page.contains(r#"<option value="family-assistant" selected>"#),
        "{page}"
    );
    assert!(page.contains("hellofresh.com</textarea>"), "{page}");
    assert!(page.contains(r#"value="86400""#), "{page}");

    let edit = [
        ("client_name", "family-assistant"),
        ("secret_name", "hellofresh-login"),
        ("mechanism", "autofill"),
        ("outcome", "auto-approve"),
        ("origins", "hellofresh.com"),
        ("max_ttl_seconds", "86400"),
    ];
    let (status, body) = submit_policy_edit(&env, id, &edit).await;
    assert!(status.is_redirection(), "{status}: {body}");

    // Same row, new outcome — and the engine acts on it.
    assert_eq!(policy_id(&env).await, id);
    let after = autofill(&env, "after").await;
    assert_eq!(after["state"], "approved", "{after}");
    assert_eq!(after["auto_approved"], true, "{after}");

    let detail: serde_json::Value = sqlx::query_scalar(
        "SELECT detail FROM audit_log WHERE kind = 'policy-updated' ORDER BY id DESC LIMIT 1",
    )
    .fetch_one(&env.db)
    .await
    .unwrap();
    assert_eq!(detail["previous_outcome"], "require-approval", "{detail}");
    assert_eq!(detail["outcome"], "auto-approve", "{detail}");

    // And back the other way.
    let mut back = edit;
    back[3] = ("outcome", "require-approval");
    let (status, body) = submit_policy_edit(&env, id, &back).await;
    assert!(status.is_redirection(), "{status}: {body}");
    assert_eq!(autofill(&env, "again").await["state"], "pending");
}

#[tokio::test(flavor = "multi_thread")]
async fn policy_edit_applies_creation_rules() {
    let env = TestEnv::spawn(SpawnOpts::default()).await.unwrap();
    env.seed_secret("api", "tok", "brokered", "bearer", "")
        .await
        .unwrap();
    env.create_policy(&[
        ("secret_name", "api"),
        ("mechanism", "brokered"),
        ("outcome", "require-approval"),
    ])
    .await
    .unwrap();
    let id = policy_id(&env).await;
    // Flipping an origin-less brokered row to auto-approve is refused, as it
    // would be at creation.
    let (status, body) = submit_policy_edit(
        &env,
        id,
        &[
            ("secret_name", "api"),
            ("mechanism", "brokered"),
            ("outcome", "auto-approve"),
        ],
    )
    .await;
    assert_eq!(status, 400, "{body}");
    let outcome: String = sqlx::query_scalar("SELECT outcome FROM policies")
        .fetch_one(&env.db)
        .await
        .unwrap();
    assert_eq!(outcome, "require-approval");
    assert_eq!(audit_count(&env, "policy-updated").await, 0);
}

#[tokio::test(flavor = "multi_thread")]
async fn config_managed_rows_are_not_editable() {
    let env = TestEnv::spawn(SpawnOpts::default()).await.unwrap();
    setup_autofill(&env, "trusted-client", "require-approval").await;
    let pid = policy_id(&env).await;
    let sid = secret_id(&env, "hellofresh-login").await;
    // Grab live forms first, then hand both rows to config.
    let policy_page = env
        .ui_get(&format!("/ui/policies/{pid}/edit"))
        .await
        .unwrap();
    let policy_token = extract_csrf(&policy_page, &format!("/ui/policies/{pid}")).unwrap();
    let secret_page = env
        .ui_get(&format!("/ui/secrets/{sid}/edit"))
        .await
        .unwrap();
    let secret_token = extract_csrf(&secret_page, &format!("/ui/secrets/{sid}")).unwrap();
    sqlx::query("UPDATE policies SET managed_by_config = true")
        .execute(&env.db)
        .await
        .unwrap();
    sqlx::query("UPDATE secrets SET managed_by_config = true")
        .execute(&env.db)
        .await
        .unwrap();

    let resp = env
        .operator()
        .get(&format!("/ui/policies/{pid}/edit"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 409);
    let resp = env
        .operator()
        .get(&format!("/ui/secrets/{sid}/edit"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 409);

    let (status, _) = env
        .ui_post(
            &format!("/ui/policies/{pid}"),
            &[
                ("csrf_token", &policy_token),
                ("mechanism", "autofill"),
                ("outcome", "deny"),
            ],
        )
        .await
        .unwrap();
    assert_eq!(status, 409);
    let (status, _) = env
        .ui_post(
            &format!("/ui/secrets/{sid}"),
            &[
                ("csrf_token", &secret_token),
                ("max_tier", "direct"),
                ("injection_kind", "bearer"),
                ("enabled", "on"),
            ],
        )
        .await
        .unwrap();
    assert_eq!(status, 409);
    assert_eq!(audit_count(&env, "policy-updated").await, 0);
    assert_eq!(audit_count(&env, "secret-updated").await, 0);
}

/// POST the secret settings form for `name`, with a token from its edit page.
async fn submit_secret_edit(
    env: &TestEnv,
    name: &str,
    fields: &[(&str, &str)],
) -> (reqwest::StatusCode, String) {
    let id = secret_id(env, name).await;
    let page = env.ui_get(&format!("/ui/secrets/{id}/edit")).await.unwrap();
    let action = format!("/ui/secrets/{id}");
    let token = extract_csrf(&page, &action).expect("settings form csrf token");
    let mut form: Vec<(&str, &str)> = vec![("csrf_token", &token)];
    form.extend_from_slice(fields);
    env.ui_post(&action, &form).await.unwrap()
}

#[tokio::test(flavor = "multi_thread")]
async fn secret_edit_changes_tier_tags_and_enabled() {
    let env = TestEnv::spawn(SpawnOpts::default()).await.unwrap();
    // Capped at brokered: an autofill (tier 1) release is out of reach, even
    // under an auto-approve rule.
    setup_autofill(&env, "brokered", "auto-approve").await;
    assert_ne!(autofill(&env, "capped").await["state"], "approved");

    let id = secret_id(&env, "hellofresh-login").await;
    let list = env.ui_get("/ui/secrets").await.unwrap();
    assert!(
        list.contains(&format!("href=\"/ui/secrets/{id}/edit\"")),
        "{list}"
    );
    let page = env.ui_get(&format!("/ui/secrets/{id}/edit")).await.unwrap();
    assert!(
        page.contains(r#"<option value="brokered" selected>"#),
        "{page}"
    );
    assert!(
        page.contains(r#"<option value="bearer" selected>"#),
        "{page}"
    );
    assert!(page.contains(r#"value="seeded by e2e""#), "{page}");

    let (status, body) = submit_secret_edit(
        &env,
        "hellofresh-login",
        &[
            ("description", "meal kits"),
            ("max_tier", "trusted-client"),
            ("injection_kind", "bearer"),
            ("tags", "web, prod web"),
            ("enabled", "on"),
        ],
    )
    .await;
    assert!(status.is_redirection(), "{status}: {body}");
    let (description, max_tier, enabled): (String, i32, bool) =
        sqlx::query_as("SELECT description, max_tier, enabled FROM secrets WHERE id = $1")
            .bind(id)
            .fetch_one(&env.db)
            .await
            .unwrap();
    assert_eq!(
        (description.as_str(), max_tier, enabled),
        ("meal kits", 1, true)
    );
    let tags: Vec<String> =
        sqlx::query_scalar("SELECT tag FROM secret_tags WHERE secret_id = $1 ORDER BY tag")
            .bind(id)
            .fetch_all(&env.db)
            .await
            .unwrap();
    assert_eq!(tags, ["prod", "web"]);
    let list = env.ui_get("/ui/secrets").await.unwrap();
    assert!(list.contains("tag:prod"), "{list}");

    // The raised cap is what the engine now sees.
    let approved = autofill(&env, "raised").await;
    assert_eq!(approved["state"], "approved", "{approved}");

    // Unchecking "Enabled" disables it: nothing new is released.
    let (status, body) = submit_secret_edit(
        &env,
        "hellofresh-login",
        &[
            ("description", "meal kits"),
            ("max_tier", "trusted-client"),
            ("injection_kind", "bearer"),
            ("tags", "prod web"),
        ],
    )
    .await;
    assert!(status.is_redirection(), "{status}: {body}");
    assert_ne!(autofill(&env, "disabled").await["state"], "approved");
    assert_eq!(audit_count(&env, "secret-updated").await, 2);
}

#[tokio::test(flavor = "multi_thread")]
async fn secret_edit_round_trips_and_validates_injection() {
    let env = TestEnv::spawn(SpawnOpts::default()).await.unwrap();
    env.seed_secret("api", "tok", "brokered", "header", "X-Api-Key")
        .await
        .unwrap();
    let id = secret_id(&env, "api").await;
    let page = env.ui_get(&format!("/ui/secrets/{id}/edit")).await.unwrap();
    assert!(
        page.contains(r#"<option value="header" selected>"#),
        "{page}"
    );
    assert!(page.contains(r#"value="X-Api-Key""#), "{page}");

    // Switching to header injection with a reserved header is refused.
    let (status, body) = submit_secret_edit(
        &env,
        "api",
        &[
            ("max_tier", "brokered"),
            ("injection_kind", "header"),
            ("injection_header", "Host"),
            ("enabled", "on"),
        ],
    )
    .await;
    assert_eq!(status, 400, "{body}");

    // Basic auth: the username lands in its own column.
    let (status, body) = submit_secret_edit(
        &env,
        "api",
        &[
            ("max_tier", "brokered"),
            ("injection_kind", "basic"),
            ("injection_header", "svc"),
            ("enabled", "on"),
        ],
    )
    .await;
    assert!(status.is_redirection(), "{status}: {body}");
    let (kind, header, user): (String, Option<String>, Option<String>) = sqlx::query_as(
        "SELECT injection_kind, injection_header, injection_username FROM secrets WHERE id = $1",
    )
    .bind(id)
    .fetch_one(&env.db)
    .await
    .unwrap();
    assert_eq!(
        (kind.as_str(), header, user.as_deref()),
        ("basic", None, Some("svc"))
    );
    let page = env.ui_get(&format!("/ui/secrets/{id}/edit")).await.unwrap();
    assert!(
        page.contains(r#"<option value="basic" selected>"#),
        "{page}"
    );
    assert!(page.contains(r#"value="svc""#), "{page}");
}

#[tokio::test(flavor = "multi_thread")]
async fn secret_rotate_from_edit_page() {
    let env = TestEnv::spawn(SpawnOpts::default()).await.unwrap();
    env.seed_secret("api", "tok", "brokered", "bearer", "")
        .await
        .unwrap();
    let id = secret_id(&env, "api").await;
    let page = env.ui_get(&format!("/ui/secrets/{id}/edit")).await.unwrap();
    let action = format!("/ui/secrets/{id}/rotate");
    let token = extract_csrf(&page, &action).expect("rotate form csrf token");
    let (status, body) = env
        .ui_post(
            &action,
            &[("csrf_token", &token), ("secret_value", "tok-2")],
        )
        .await
        .unwrap();
    assert!(status.is_redirection(), "{status}: {body}");
    let version: i32 = sqlx::query_scalar("SELECT current_version FROM secrets WHERE id = $1")
        .bind(id)
        .fetch_one(&env.db)
        .await
        .unwrap();
    assert_eq!(version, 2);
    assert_eq!(audit_count(&env, "secret-rotated").await, 1);

    // Deleted meanwhile: the same form is refused, never a re-create.
    env.delete_secret("api").await.unwrap();
    let (status, _) = env
        .ui_post(
            &action,
            &[("csrf_token", &token), ("secret_value", "tok-3")],
        )
        .await
        .unwrap();
    assert_eq!(status, 404);
    let count: i64 = sqlx::query_scalar("SELECT count(*) FROM secrets")
        .fetch_one(&env.db)
        .await
        .unwrap();
    assert_eq!(count, 0);
}
