//! The passkey connector page the browser extension opens: `GET /kem/v1/webauthn` and its
//! script, served by the API's own router with a policy that allows no inline script.

mod common;

use axum::http::StatusCode;
use common::App;

const EXTENSION_ID: &str = "abcdefghijklmnopabcdefghijklmnop";

#[tokio::test]
async fn the_page_is_html_with_its_script_as_a_file_of_its_own() {
    let app = App::new(false);
    let reply = app.client().get("/kem/v1/webauthn").await;
    assert_eq!(reply.status, StatusCode::OK);
    assert_eq!(reply.content_type(), "text/html; charset=utf-8");
    let page = String::from_utf8(reply.body.clone()).expect("UTF-8");
    assert!(page.starts_with("<!doctype html>"));
    assert_eq!(page.matches("<script").count(), 1, "one script, and it has a src");
    assert!(page.contains("<script src=\"/kem/v1/webauthn/connector.js\"></script>"));
    assert!(!page.contains("<style"), "no inline style");
    assert!(!page.contains("{{"), "the placeholder is filled in");
}

#[tokio::test]
async fn the_page_needs_no_login_and_sets_the_hardening_headers() {
    let app = App::new(false);
    let reply = app.client().get("/kem/v1/webauthn").await;
    assert_eq!(reply.status, StatusCode::OK);
    let csp = reply.header("content-security-policy").expect("a policy");
    assert!(csp.contains("default-src 'none'"), "{csp}");
    assert!(csp.contains("script-src 'self'"), "{csp}");
    assert!(csp.contains("frame-ancestors 'none'"), "{csp}");
    assert!(csp.contains("connect-src 'none'"), "{csp}");
    assert!(csp.contains("require-trusted-types-for 'script'"), "{csp}");
    for forbidden in ["unsafe-inline", "unsafe-eval", "http:", "https:", "data:", "*"] {
        assert!(!csp.contains(forbidden), "{forbidden} in {csp}");
    }
    assert_eq!(reply.header("x-content-type-options"), Some("nosniff"));
    assert_eq!(reply.header("referrer-policy"), Some("no-referrer"));
    assert_eq!(reply.header("x-frame-options"), Some("DENY"));
    assert_eq!(reply.header("cache-control"), Some("no-store"));
}

#[tokio::test]
async fn the_page_carries_the_extensions_the_admin_named_and_only_those() {
    let none = App::new(false).client().get("/kem/v1/webauthn").await;
    let page = String::from_utf8(none.body).expect("UTF-8");
    assert!(
        page.contains("<meta name=\"kemlock-extension-ids\" content=\"\">"),
        "no extension is allowed until one is named"
    );

    let app = App::with_extension_ids(&[EXTENSION_ID, "0123456789abcdef0123456789abcdef01234567"]);
    let named = app.client().get("/kem/v1/webauthn").await;
    let page = String::from_utf8(named.body).expect("UTF-8");
    assert!(page.contains(&format!(
        "content=\"{EXTENSION_ID},0123456789abcdef0123456789abcdef01234567\""
    )));
}

#[tokio::test]
async fn the_script_is_javascript_under_the_same_policy() {
    let app = App::new(false);
    let reply = app.client().get("/kem/v1/webauthn/connector.js").await;
    assert_eq!(reply.status, StatusCode::OK);
    assert_eq!(reply.content_type(), "text/javascript; charset=utf-8");
    assert_eq!(reply.header("x-content-type-options"), Some("nosniff"));
    assert!(
        reply
            .header("content-security-policy")
            .is_some_and(|csp| csp.contains("script-src 'self'"))
    );
    let script = String::from_utf8(reply.body).expect("UTF-8");
    // It asks for the PRF extension with the salt the web vault uses, and answers only an
    // allowlisted extension.
    assert!(script.contains("navigator.credentials.get"));
    assert!(script.contains("kemlock/v1/prf-salt"));
    assert!(script.contains("kemlock-extension-ids"));
    assert!(script.contains(".chromiumapp.org"));
    assert!(script.contains(".extensions.allizom.org"));
    assert!(!script.contains("eval("));
    assert!(!script.contains("innerHTML"));
}

#[tokio::test]
async fn the_connector_has_no_other_methods_and_unknown_paths_stay_not_found() {
    let app = App::new(false);
    let reply = app
        .client()
        .post("/kem/v1/webauthn", serde_json::json!({}))
        .await;
    assert!(
        matches!(reply.status, StatusCode::METHOD_NOT_ALLOWED | StatusCode::NOT_FOUND),
        "{}",
        reply.status
    );
    let other = app.client().get("/kem/v1/webauthn/other.js").await;
    assert_eq!(other.status, StatusCode::NOT_FOUND);
}
