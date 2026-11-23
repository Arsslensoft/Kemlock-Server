//! The SSO gate against a real Keycloak: the same flow as `sso_gate.rs` (an SSO user opens the
//! vault with no password), with Keycloak's own login page as the provider.
//!
//! It runs only when `KEMLOCK_SSO_GATE_ISSUER` names a Keycloak realm that was imported from
//! `tools/sso-gate/realm-kemlock.json`; otherwise it says so and passes. `tools/sso-gate/run.sh`
//! starts that Keycloak with Docker Compose, runs this test against it and stops it again.
//!
//! The browser is played here: the authorization URL is opened, Keycloak's login form is filled
//! in and posted, and the redirect to the server's callback is followed in-process.

mod sso_common;

use axum::http::StatusCode;
use kemlock_app::ports::UserRepo;
use kemlock_app::sso::SsoIdentityRepo;
use kemlock_identity::reqwest::{Client, ClientBuilder, redirect::Policy};
use kemlock_server::build;
use sso_common::*;

const CLIENT_ID: &str = "kemlock";
const CLIENT_SECRET: &str = "kemlock-gate-secret";
const SECRET: &str = r#"{"title":"Example","password":"hunter2"}"#;

/// Keycloak's login page, driven the way a browser would.
struct Keycloak {
    http: Client,
    username: &'static str,
    password: &'static str,
}

impl Keycloak {
    fn new(username: &'static str, password: &'static str) -> Keycloak {
        Keycloak {
            http: ClientBuilder::new()
                .redirect(Policy::none())
                .build()
                .expect("an HTTP client"),
            username,
            password,
        }
    }
}

/// The `name=value` of each cookie a response sets, joined for a `Cookie` header.
fn cookies_of(headers: &kemlock_identity::reqwest::header::HeaderMap) -> String {
    headers
        .get_all("set-cookie")
        .iter()
        .filter_map(|v| v.to_str().ok())
        .filter_map(|v| v.split(';').next())
        .collect::<Vec<_>>()
        .join("; ")
}

/// The login form's action in Keycloak's page, with its `&amp;` undone.
fn form_action(html: &str) -> String {
    let form = html
        .find("kc-form-login")
        .expect("Keycloak's login form is in the page");
    let rest = &html[form..];
    let start = rest.find("action=\"").expect("the form has an action") + "action=\"".len();
    let end = rest[start..].find('"').expect("the action ends") + start;
    rest[start..end].replace("&amp;", "&")
}

impl Browser for Keycloak {
    async fn login(&self, authorization_url: &str) -> String {
        let page = self
            .http
            .get(authorization_url)
            .send()
            .await
            .expect("Keycloak answers");
        assert_eq!(page.status().as_u16(), 200, "the login page");
        let cookies = cookies_of(page.headers());
        let action = form_action(&page.text().await.expect("a page"));

        let submitted = self
            .http
            .post(&action)
            .header("cookie", cookies)
            .form(&[
                ("username", self.username),
                ("password", self.password),
                ("credentialId", ""),
            ])
            .send()
            .await
            .expect("Keycloak takes the login");
        assert_eq!(
            submitted.status().as_u16(),
            302,
            "Keycloak redirects after a good login"
        );
        submitted
            .headers()
            .get("location")
            .and_then(|v| v.to_str().ok())
            .expect("a Location header")
            .to_owned()
    }
}

fn issuer() -> Option<String> {
    match std::env::var("KEMLOCK_SSO_GATE_ISSUER") {
        Ok(issuer) if !issuer.trim().is_empty() => Some(issuer.trim().to_owned()),
        _ => {
            eprintln!(
                "KEMLOCK_SSO_GATE_ISSUER is not set; skipping (tools/sso-gate/run.sh sets it)"
            );
            None
        }
    }
}

#[tokio::test]
async fn an_sso_user_opens_the_vault_with_no_password_through_keycloak() {
    let Some(issuer) = issuer() else { return };
    let dir = TempDir::new("keycloak");
    let built = build(&config(&dir.0)).await.expect("the server builds");
    enable_sso(
        &built,
        &dir.0,
        &issuer,
        CLIENT_ID,
        CLIENT_SECRET,
        &["email", "profile"],
    )
    .await;
    let phone = Phone::new(built.router.clone());
    let browser = Keycloak::new("ada", "ada-password-1");

    // First sign-in: Keycloak's login page, the callback, finish. A new account with no keys.
    let first = SignIn::new().through(&phone, &built.router, &browser).await;
    assert_eq!(first.status, StatusCode::OK, "{:?}", first.json());
    assert_eq!(first.json()["newAccount"], true);
    let (access, user_id) = tokens_of(&first);

    let email = kemlock_domain::Email::parse("ada@example.org").expect("an email");
    let account = built
        .store
        .by_email(&email)
        .await
        .expect("the store answers")
        .expect("the account was made");
    assert_eq!(account.id.to_string(), user_id);
    assert!(account.opaque_record.is_none());
    assert!(account.wrapped_root_key.is_empty());
    let identities = built
        .store
        .identities_of(account.id)
        .await
        .expect("the store answers");
    assert_eq!(identities.len(), 1);
    assert_eq!(identities[0].issuer, issuer);

    // The device makes its keys and wraps its root key under one of its own.
    let (device_key, wrapped_root, item, _) = make_vault(&phone, &access, &user_id, SECRET).await;

    // The session ends (the app is closed, the tokens are dropped); the phone signs in again with
    // SSO, on a new Keycloak browser session, and opens the vault: no password.
    let second = SignIn::new().through(&phone, &built.router, &browser).await;
    assert_eq!(second.status, StatusCode::OK, "{:?}", second.json());
    assert_eq!(second.json()["newAccount"], false);
    let (access, again_id) = tokens_of(&second);
    assert_eq!(again_id, user_id);
    let opened = open_vault(&phone, &access, &user_id, &device_key, &wrapped_root, &item).await;
    assert_eq!(opened, SECRET);

    built.store.close().await.expect("closes");
}

#[tokio::test]
async fn keycloak_users_with_an_unverified_email_are_refused() {
    let Some(issuer) = issuer() else { return };
    let dir = TempDir::new("keycloak-unverified");
    let built = build(&config(&dir.0)).await.expect("the server builds");
    enable_sso(
        &built,
        &dir.0,
        &issuer,
        CLIENT_ID,
        CLIENT_SECRET,
        &["email", "profile"],
    )
    .await;
    let phone = Phone::new(built.router.clone());
    let browser = Keycloak::new("mallory", "mallory-password-1");

    let refused = SignIn::new().through(&phone, &built.router, &browser).await;
    assert_eq!(
        refused.status,
        StatusCode::FORBIDDEN,
        "{:?}",
        refused.json()
    );
    assert_eq!(
        refused.json()["type"],
        "urn:kemlock:problem:sso-email-not-verified"
    );
    let email = kemlock_domain::Email::parse("mallory@example.org").expect("an email");
    assert!(
        built
            .store
            .by_email(&email)
            .await
            .expect("the store answers")
            .is_none()
    );

    built.store.close().await.expect("closes");
}
