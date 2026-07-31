//! Deleting a stored secret from the approval UI: the two-step confirmation,
//! what the confirmation page tells the operator, and what deletion does to
//! the grants that were still holding the credential.

use keychute_e2e::*;

/// Approve a `cli-read` request for `secret` and return its grant id.
async fn grant_for(env: &TestEnv, secret: &str, idem: &str) -> String {
    let (status, body) = env
        .k8s()
        .create_request(cli_read_request(idem, secret, 3600, "e2e delete"))
        .await
        .unwrap();
    assert_eq!(status, 201, "{body}");
    let request_id = body["request_id"].as_str().expect("request_id").to_owned();
    env.approve(&request_id, &[]).await.unwrap();
    let page = env.ui_get("/ui/grants").await.unwrap();
    // Deliberately NOT read here: a cli-read grant is single-use, so reading it
    // would leave a spent grant whose "live" window is the replay window, and
    // the point of the assertions below is a grant that could still release.
    extract_grant_ids(&page)
        .into_iter()
        .next()
        .expect("a live grant")
}

/// Grant ids linked from the grants page (the revoke form actions).
fn extract_grant_ids(html: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut rest = html;
    while let Some(at) = rest.find("/ui/grants/") {
        let tail = &rest[at + "/ui/grants/".len()..];
        let id: String = tail
            .chars()
            .take_while(|c| c.is_ascii_hexdigit() || *c == '-')
            .collect();
        if id.len() == 36 && !out.contains(&id) {
            out.push(id);
        }
        rest = tail;
    }
    out
}

/// The whole journey: an operator deletes a credential, is told what goes with
/// it, and the grant that was still holding it stops working immediately.
#[tokio::test(flavor = "multi_thread")]
async fn deleting_a_secret_removes_it_and_revokes_its_live_grants() {
    let env = TestEnv::spawn(SpawnOpts::default()).await.unwrap();
    env.seed_secret("retired-key", "hunter2", "cooperating-client", "bearer", "")
        .await
        .unwrap();
    // A standing policy naming the secret: kept, but called out, because it
    // would apply again to anything later created under the same name.
    env.create_policy(&[
        ("client_name", "k8s-agent"),
        ("secret_name", "retired-key"),
        ("mechanism", "cli-read"),
        ("outcome", "require-approval"),
        ("priority", "0"),
        ("max_ttl_seconds", "3600"),
    ])
    .await
    .unwrap();
    let grant_id = grant_for(&env, "retired-key", "del-1").await;

    let confirm = env.delete_secret("retired-key").await.unwrap();
    // The confirmation page is where the consequences are stated.
    assert!(
        confirm.contains("k8s-agent"),
        "confirmation page does not list the live grant: {confirm}"
    );
    assert!(
        confirm.contains("revoked"),
        "confirmation page does not say the grant will be revoked: {confirm}"
    );
    assert!(
        confirm.contains("the policies page"),
        "confirmation page does not point at the surviving policy: {confirm}"
    );
    // It must not leak the credential itself — deleting is not a reveal.
    assert!(
        !confirm.contains("hunter2"),
        "confirmation page rendered the secret value: {confirm}"
    );

    // Gone from the list...
    let page = env.ui_get("/ui/secrets").await.unwrap();
    assert!(!page.contains("retired-key"), "{page}");
    let count: i64 = sqlx::query_scalar("SELECT count(*) FROM secrets WHERE name = 'retired-key'")
        .fetch_one(&env.db)
        .await
        .unwrap();
    assert_eq!(count, 0);
    // ...along with every stored version of it.
    let versions: i64 = sqlx::query_scalar("SELECT count(*) FROM secret_versions")
        .fetch_one(&env.db)
        .await
        .unwrap();
    assert_eq!(versions, 0, "secret_versions outlived the secret");

    // The grant that was still holding the credential is revoked, and the
    // client is told so rather than getting a stale replay.
    let (status, body) = env
        .k8s()
        .read_grant(&grant_id, "after-delete")
        .await
        .unwrap();
    assert_eq!(status, 410, "{body}");
    assert_eq!(body["error"]["code"], "grant-expired", "{body}");

    // The audit log outlives the credential.
    let kinds: Vec<String> = sqlx::query_scalar(
        "SELECT kind FROM audit_log WHERE secret_name = 'retired-key' ORDER BY id",
    )
    .fetch_all(&env.db)
    .await
    .unwrap();
    assert!(kinds.contains(&"secret-deleted".to_owned()), "{kinds:?}");
    assert!(kinds.contains(&"grant-revoked".to_owned()), "{kinds:?}");
}

/// Deletion is a mutation behind the same POST guard as every other one: no
/// GET does it, a stale token does not, and a rotation between the two steps
/// invalidates the confirmation instead of destroying bytes nobody looked at.
#[tokio::test(flavor = "multi_thread")]
async fn delete_is_guarded_and_bound_to_the_displayed_version() {
    let env = TestEnv::spawn(SpawnOpts::default()).await.unwrap();
    env.seed_secret("guarded", "v1", "brokered", "bearer", "")
        .await
        .unwrap();
    let id: uuid::Uuid = sqlx::query_scalar("SELECT id FROM secrets WHERE name = 'guarded'")
        .fetch_one(&env.db)
        .await
        .unwrap();

    // No GET route deletes (or even confirms) anything.
    let resp = env
        .operator()
        .get(&format!("/ui/secrets/{id}/deleted"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 405, "GET must not reach the delete handler");

    // A POST without the form token is refused.
    let (status, _) = env
        .ui_post(
            &format!("/ui/secrets/{id}/delete"),
            &[("csrf_token", "nope")],
        )
        .await
        .unwrap();
    assert_eq!(status, 403);

    // Walk to the confirmation page, then rotate the secret before confirming:
    // the confirmation describes version 1 and must not delete version 2.
    let page = env.ui_get("/ui/secrets").await.unwrap();
    let action = format!("/ui/secrets/{id}/delete");
    let token = extract_csrf(&page, &action).expect("delete csrf token");
    let (status, confirm) = env
        .ui_post(&action, &[("csrf_token", &token)])
        .await
        .unwrap();
    assert_eq!(status, 200, "{confirm}");
    let confirm_action = format!("/ui/secrets/{id}/deleted");
    let confirm_token = extract_csrf(&confirm, &confirm_action).expect("confirm csrf token");
    let version =
        extract_form_field(&confirm, &confirm_action, "current_version").expect("version field");
    assert_eq!(version, "1");

    env.seed_secret("guarded", "v2", "brokered", "bearer", "")
        .await
        .unwrap();
    let (status, body) = env
        .ui_post(
            &confirm_action,
            &[
                ("csrf_token", &confirm_token),
                ("current_version", &version),
            ],
        )
        .await
        .unwrap();
    assert_eq!(status, 409, "{body}");
    assert!(
        sqlx::query_scalar::<_, i64>("SELECT count(*) FROM secrets WHERE name = 'guarded'")
            .fetch_one(&env.db)
            .await
            .unwrap()
            == 1,
        "a stale confirmation deleted the rotated secret"
    );

    // Only the operator may delete: a client token cannot even open the
    // confirmation page.
    let resp = env
        .client(FA_TOKEN)
        .post(&format!("/ui/secrets/{id}/delete"))
        .header(reqwest::header::ORIGIN, &env.external_url)
        .form(&[("csrf_token", "whatever")])
        .send()
        .await
        .unwrap();
    assert!(
        resp.status() == 401 || resp.status() == 403,
        "client token reached the delete flow: {}",
        resp.status()
    );
}
