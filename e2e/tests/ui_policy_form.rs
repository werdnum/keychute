//! The policy form: client/secret/tag are pickers over known values, and the
//! request page links to the form pre-filled from that request.

use keychute_e2e::*;

/// The pre-filled policy link on a request page, with maud's `&amp;` undone.
fn policy_link(page: &str) -> String {
    let start = page
        .find("href=\"/ui/policies?")
        .expect("request page links a pre-filled policy")
        + "href=\"".len();
    let end = start + page[start..].find('"').unwrap();
    page[start..end].replace("&amp;", "&")
}

#[tokio::test(flavor = "multi_thread")]
async fn policy_form_offers_known_clients_and_secrets() {
    let env = TestEnv::spawn(SpawnOpts::default()).await.unwrap();
    env.seed_secret("example-api-token", "tok-abc", "brokered", "bearer", "")
        .await
        .unwrap();

    let page = env.ui_get("/ui/policies").await.unwrap();
    assert!(page.contains(r#"<select name="client_name">"#), "{page}");
    assert!(
        page.contains(r#"<option value="family-assistant">"#),
        "{page}"
    );
    assert!(page.contains(r#"<option value="k8s-agent">"#), "{page}");
    assert!(page.contains(r#"<select name="secret_name">"#), "{page}");
    assert!(
        page.contains(r#"<option value="example-api-token">"#),
        "{page}"
    );
    assert!(page.contains(r#"<select name="secret_tag">"#), "{page}");
    assert!(
        !page.contains(r#"input type="text" name="client_name""#),
        "{page}"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn request_page_links_a_prefilled_policy() {
    let env = TestEnv::spawn(SpawnOpts::default()).await.unwrap();
    env.seed_secret("example-api-token", "tok-abc", "brokered", "bearer", "")
        .await
        .unwrap();
    let (status, body) = env
        .fa()
        .create_request(brokered_request(
            "prefill-idem",
            "example-api-token",
            "localhost",
            env.upstream_port,
            &["GET", "POST"],
            &["/v1", "/v2"],
            600,
        ))
        .await
        .unwrap();
    assert_eq!(status, 201, "{body}");
    let id = body["request_id"].as_str().unwrap().to_owned();

    let link = policy_link(&env.ui_get(&format!("/ui/requests/{id}")).await.unwrap());
    let page = env.ui_get(&link).await.unwrap();
    assert!(page.contains("Pre-filled from a request"), "{page}");
    assert!(
        page.contains(r#"<option value="family-assistant" selected>"#),
        "{page}"
    );
    assert!(
        page.contains(r#"<option value="example-api-token" selected>"#),
        "{page}"
    );
    assert!(
        page.contains(r#"<option value="brokered" selected>"#),
        "{page}"
    );
    let port = env.upstream_port;
    assert!(
        page.contains(&format!("localhost:{port}</textarea>")),
        "{page}"
    );
    assert!(page.contains(r#"value="GET, POST""#), "{page}");
    assert!(page.contains("/v1\n/v2</textarea>"), "{page}");
    assert!(
        page.contains(r#"name="max_ttl_seconds" min="1" inputmode="numeric" value="600""#),
        "{page}"
    );

    // The request is untouched by following the link.
    let detail = env.ui_get(&format!("/ui/requests/{id}")).await.unwrap();
    assert!(detail.contains("Your decision"), "{detail}");

    // The resolved page keeps the link.
    env.deny(&id).await.unwrap();
    let resolved = env.ui_get(&format!("/ui/requests/{id}")).await.unwrap();
    assert_eq!(policy_link(&resolved), link);
}

/// A pre-fill naming something the pickers do not list (a secret not stored
/// yet) stays selected rather than collapsing to "any".
#[tokio::test(flavor = "multi_thread")]
async fn prefill_keeps_an_unstored_secret_name() {
    let env = TestEnv::spawn(SpawnOpts::default()).await.unwrap();
    let page = env
        .ui_get("/ui/policies?client=family-assistant&secret=not-yet&mechanism=cli-read")
        .await
        .unwrap();
    assert!(
        page.contains(r#"<option value="not-yet" selected>not-yet (not stored yet)"#),
        "{page}"
    );
    assert!(
        page.contains(r#"<option value="cli-read" selected>"#),
        "{page}"
    );
}
