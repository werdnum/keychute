//! The landing page: what a browser gets at the bare hostname, without
//! knowing that the UI hangs off `/ui/...`.

use keychute_e2e::*;

#[tokio::test(flavor = "multi_thread")]
async fn landing_page_summarizes_and_links_the_ui() {
    let env = TestEnv::spawn(SpawnOpts::default()).await.unwrap();

    // Empty install: reachable, and explicit that nothing needs a decision.
    let page = env.ui_get("/").await.unwrap();
    assert!(
        page.contains("Nothing is waiting for your decision."),
        "{page}"
    );
    for href in ["/ui/requests", "/ui/grants", "/ui/policies", "/ui/secrets"] {
        assert!(
            page.contains(&format!("href=\"{href}\"")),
            "landing page does not link {href}: {page}"
        );
    }

    // A pending request is the one time-critical thing, so it must show up
    // both as the banner and in the section counts.
    env.seed_secret("example-api-token", "tok-abc", "brokered", "bearer", "")
        .await
        .unwrap();
    let (status, body) = env
        .fa()
        .create_request(brokered_request(
            "landing-idem",
            "example-api-token",
            "localhost",
            env.upstream_port,
            &["GET"],
            &["/v1"],
            600,
        ))
        .await
        .unwrap();
    assert_eq!(status, 201, "{body}");

    let page = env.ui_get("/").await.unwrap();
    assert!(page.contains("1 request is waiting"), "{page}");
    assert!(page.contains("1 pending"), "{page}");
    assert!(page.contains("1 stored"), "{page}");
}

#[tokio::test(flavor = "multi_thread")]
async fn ui_root_redirects_to_the_landing_page() {
    let env = TestEnv::spawn(SpawnOpts::default()).await.unwrap();

    for path in ["/ui", "/ui/"] {
        let resp = env.operator().get(path).send().await.unwrap();
        assert!(
            resp.status().is_redirection(),
            "GET {path} -> {}",
            resp.status()
        );
        assert_eq!(
            resp.headers()
                .get(reqwest::header::LOCATION)
                .and_then(|v| v.to_str().ok()),
            Some("/"),
            "GET {path} redirected elsewhere"
        );
    }
}

/// The counts name which secrets exist and who currently holds a grant, so
/// the landing page is behind operator authn like every other UI page.
#[tokio::test(flavor = "multi_thread")]
async fn landing_page_requires_operator_authn() {
    let env = TestEnv::spawn(SpawnOpts::default()).await.unwrap();

    let resp = env.client("not-the-operator-token").get("/").send().await;
    assert_eq!(resp.unwrap().status(), 401);
}
