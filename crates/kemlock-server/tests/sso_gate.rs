//! The gate of the SSO workstream: an SSO user opens the vault with no password.
//!
//! The real server is built (SQLite, its keys, the SSO routes, the OpenID Connect client) and a
//! fake provider runs on a local port. The phone signs in through the provider (start, the
//! provider's login, the callback, finish), keeps its root key wrapped under a key of its own (a
//! stand-in for a trusted-device key), loses its session when the provider says the person's
//! session ended (back-channel logout), signs in with SSO again, and opens an item it stored
//! before. At no point is a password, OPAQUE or a key handed to the server.
//!
//! `tools/sso-gate/` runs the same flow against a real Keycloak.

mod sso_common;

use axum::http::StatusCode;
use kemlock_app::b64url;
use kemlock_app::ports::UserRepo;
use kemlock_app::sso::SsoIdentityRepo;
use kemlock_crypto::{hash, rand};
use kemlock_identity::testing::{FakeProvider, FakeUser};
use kemlock_server::build;
use serde_json::json;
use sso_common::*;

/// The fake provider's "login": it signs in the person it was told to at once.
impl Browser for FakeProvider {
    async fn login(&self, authorization_url: &str) -> String {
        self.approve(authorization_url)
            .expect("the provider approves")
    }
}

const SECRET: &str = r#"{"title":"Example","password":"hunter2"}"#;

async fn server_for(name: &str, provider: &FakeProvider) -> (TempDir, kemlock_server::Built) {
    let dir = TempDir::new(name);
    let built = build(&config(&dir.0)).await.expect("the server builds");
    enable_sso(
        &built,
        &dir.0,
        provider.issuer(),
        provider.client_id(),
        provider.client_secret().expect("a confidential client"),
        &["email", "profile"],
    )
    .await;
    (dir, built)
}

async fn provider() -> FakeProvider {
    FakeProvider::start("kemlock", Some("s3cret"))
        .await
        .expect("the fake provider starts")
}

fn ada() -> kemlock_domain::Email {
    kemlock_domain::Email::parse("ada@example.org").expect("an email")
}

#[tokio::test]
async fn an_sso_user_opens_the_vault_with_no_password() {
    let provider = provider().await;
    let (_dir, built) = server_for("gate", &provider).await;
    let phone = Phone::new(built.router.clone());

    // --- First sign-in, through the provider. The account is made; it has no keys and no password.
    let first = SignIn::new()
        .through(&phone, &built.router, &provider)
        .await;
    assert_eq!(first.status, StatusCode::OK, "{:?}", first.json());
    assert_eq!(first.json()["newAccount"], true);
    let (access, user_id) = tokens_of(&first);

    let account = built
        .store
        .by_email(&ada())
        .await
        .expect("the store answers")
        .expect("the account was made");
    assert_eq!(account.id.to_string(), user_id);
    assert!(account.opaque_record.is_none(), "no password is set");
    assert!(account.wrapped_root_key.is_empty(), "no key is held");
    assert!(account.public_bundle.is_empty());
    assert!(account.sealed_private_keys.is_empty());
    let linked = built
        .store
        .find_identity(provider.issuer(), "sub-ada")
        .await
        .expect("the store answers")
        .expect("the subject is linked");
    assert_eq!(linked.user, account.id);

    // --- The phone makes its keys, stores an item sealed under them, and wraps its root key under
    // a key of its own. The server sees the sealed item and nothing else.
    let (device_key, wrapped_root, item, _item_id) =
        make_vault(&phone, &access, &user_id, SECRET).await;

    // --- The provider ends the person's session; its back-channel logout reaches the server.
    let logout_token = provider.logout_token(Some("sub-ada"), Some("provider-session-1"));
    let logged_out = plain(
        &built.router,
        "POST",
        "/kem/v1/auth/sso/backchannel-logout",
        Some(&format!("logout_token={logout_token}")),
    )
    .await;
    assert_eq!(logged_out.status, StatusCode::OK, "{:?}", logged_out.body);
    let stale = phone
        .send("GET", "/kem/v1/sync", Some(&access), &[], None)
        .await;
    assert_eq!(
        stale.status,
        StatusCode::UNAUTHORIZED,
        "the session ended at once"
    );
    assert_eq!(stale.json()["type"], "urn:kemlock:problem:session-ended");

    // --- The phone signs in with SSO again: no password anywhere.
    let second = SignIn::new()
        .through(&phone, &built.router, &provider)
        .await;
    assert_eq!(second.status, StatusCode::OK, "{:?}", second.json());
    assert_eq!(second.json()["newAccount"], false, "the same account");
    let (access, again_id) = tokens_of(&second);
    assert_eq!(again_id, user_id);

    // --- The vault opens on the device, and the item reads back.
    let opened = open_vault(&phone, &access, &user_id, &device_key, &wrapped_root, &item).await;
    assert_eq!(opened, SECRET);

    // --- Nothing the server holds can open it: it never had a key, and still has none.
    let account = built
        .store
        .by_email(&ada())
        .await
        .expect("the store answers")
        .expect("the account");
    assert!(account.opaque_record.is_none());
    assert!(account.wrapped_root_key.is_empty());
    assert!(account.sealed_private_keys.is_empty());

    built.store.close().await.expect("closes");
}

#[tokio::test]
async fn a_second_person_gets_their_own_account_and_a_stolen_code_is_useless() {
    let provider = provider().await;
    let (_dir, built) = server_for("gate-two", &provider).await;

    let ada_phone = Phone::new(built.router.clone());
    let (_, ada_id) = tokens_of(
        &SignIn::new()
            .through(&ada_phone, &built.router, &provider)
            .await,
    );

    provider.set_user(FakeUser::new("sub-bob", "bob@example.org"));
    let bob_phone = Phone::new(built.router.clone());
    let (_, bob_id) = tokens_of(
        &SignIn::new()
            .through(&bob_phone, &built.router, &provider)
            .await,
    );
    assert_ne!(ada_id, bob_id);

    // A code taken by another app is useless without the phone's verifier and device key.
    provider.set_user(FakeUser::new("sub-ada", "ada@example.org"));
    let victim = Phone::new(built.router.clone());
    let verifier = b64url::encode(&rand::bytes::<32>());
    let started = victim
        .send(
            "POST",
            "/kem/v1/auth/sso/start",
            None,
            &[],
            Some(json!({
                "challenge": b64url::encode(&hash::sha256(verifier.as_bytes())),
                "state": APP_STATE,
            })),
        )
        .await;
    let url = started.json()["authorizationUrl"]
        .as_str()
        .expect("a URL")
        .to_owned();
    let redirect = provider.login(&url).await;
    let called = plain(
        &built.router,
        "GET",
        redirect
            .strip_prefix(DOMAIN)
            .expect("the server's callback"),
        None,
    )
    .await;
    let code = one_time_code(&called);

    let thief = Phone::new(built.router.clone());
    let stolen = thief
        .send(
            "POST",
            "/kem/v1/auth/sso/finish",
            None,
            &[],
            Some(json!({"code": code, "verifier": verifier, "device": {"name": "Thief"}})),
        )
        .await;
    assert_eq!(
        stolen.status,
        StatusCode::UNAUTHORIZED,
        "{:?}",
        stolen.json()
    );
    assert_eq!(
        provider.token_requests(),
        2,
        "the provider's code stayed unspent"
    );

    built.store.close().await.expect("closes");
}

#[tokio::test]
async fn a_provider_that_does_not_verify_the_email_gets_no_account() {
    let provider = provider().await;
    let (_dir, built) = server_for("gate-unverified", &provider).await;

    let mut eve = FakeUser::new("sub-eve", "eve@example.org");
    eve.email_verified = Some(false);
    provider.set_user(eve);
    let phone = Phone::new(built.router.clone());
    let refused = SignIn::new()
        .through(&phone, &built.router, &provider)
        .await;
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
    let none = built
        .store
        .by_email(&kemlock_domain::Email::parse("eve@example.org").expect("an email"))
        .await
        .expect("the store answers");
    assert!(none.is_none(), "no account was made");

    built.store.close().await.expect("closes");
}
