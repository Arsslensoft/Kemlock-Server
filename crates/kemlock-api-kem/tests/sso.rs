//! The SSO routes through the router, in-process, over fakes: start, callback, finish and
//! back-channel logout, with a real DPoP client and a scripted provider.

mod common;
#[path = "../../kemlock-app/tests/sso_fakes/mod.rs"]
mod sso_fakes;

use axum::Router;
use axum::http::StatusCode;
use common::{App, Client, Reply, Req, Session, b64};
use kemlock_api_kem::testing::DpopSigner;
use kemlock_api_kem::{SsoApiDoc, SsoRuntime, sso_router};
use kemlock_app::ports::{Clock, SecretSeal, TwoFactor, TwoFactorMethod, TwoFactorRepo};
use kemlock_app::sso::{LogoutClaims, NoSpaces, SsoSettings};
use serde_json::{Value, json};
use sso_fakes::*;
use utoipa::OpenApi;

const APP_STATE: &str = "app-state-0123456789";

struct Sso {
    app: App,
    router: Router,
    repos: FakeSsoRepos,
    provider: ScriptedProvider,
    /// The phone's PKCE verifier.
    verifier: String,
}

fn sso() -> Sso {
    sso_on(App::new(false))
}

fn sso_on(app: App) -> Sso {
    let repos = FakeSsoRepos::default();
    let mut settings = SsoSettings::new(ISSUER, "kemlock", app.crypto.now());
    settings.set_client_secret(&app.crypto, "s3cret");
    repos.set_settings(settings);
    let provider = ScriptedProvider::new();
    let runtime = SsoRuntime::new(repos.clone(), provider.clone(), NoSpaces);
    let router = app
        .router
        .clone()
        .merge(sso_router(app.api.clone(), runtime));
    Sso {
        app,
        router,
        repos,
        provider,
        verifier: b64(&[7u8; 32]),
    }
}

impl Sso {
    /// A device with its own DPoP key, talking to the merged router.
    fn device(&self) -> Client {
        Client::new(
            self.router.clone(),
            self.app.clock.clone(),
            DpopSigner::es256(),
        )
    }

    fn challenge(&self) -> String {
        b64(&kemlock_crypto::hash::sha256(self.verifier.as_bytes()))
    }

    fn start_body(&self) -> Value {
        json!({"challenge": self.challenge(), "state": APP_STATE})
    }

    async fn start(&self, client: &Client) -> Reply {
        client
            .post("/kem/v1/auth/sso/start", self.start_body())
            .await
    }

    /// The browser's part: the provider's login, then the server's callback. Returns the reply
    /// to the callback.
    async fn browser(&self, client: &Client, provider_code: &str) -> Reply {
        let state = self
            .provider
            .last_request()
            .expect("start reached the provider")
            .state;
        callback(client, &format!("code={provider_code}&state={state}")).await
    }

    /// `start`, the browser, and `finish`: the reply to the last.
    async fn sign_in(&self, client: &Client, provider_code: &str) -> Reply {
        let started = self.start(client).await;
        assert_eq!(started.status, StatusCode::OK, "{:?}", started.json());
        let redirected = self.browser(client, provider_code).await;
        assert_eq!(
            redirected.status,
            StatusCode::SEE_OTHER,
            "{:?}",
            redirected.body
        );
        let code = code_of(redirected.header("location").expect("a Location header"));
        self.finish(client, &code).await
    }

    async fn finish(&self, client: &Client, code: &str) -> Reply {
        client
            .post(
                "/kem/v1/auth/sso/finish",
                json!({
                    "code": code,
                    "verifier": self.verifier,
                    "device": {"name": "Pixel", "kind": "kemlock-android"},
                }),
            )
            .await
    }
}

/// The browser's request to the callback: no DPoP, it is the provider's redirect.
async fn callback(client: &Client, query: &str) -> Reply {
    client
        .send(
            "GET",
            &format!("/kem/v1/auth/sso/callback?{query}"),
            Req {
                no_proof: true,
                ..Req::default()
            },
        )
        .await
}

fn code_of(location: &str) -> String {
    location
        .split("code=")
        .nth(1)
        .and_then(|rest| rest.split('&').next())
        .expect("the redirect carries a code")
        .to_owned()
}

fn session_of(reply: &Reply) -> Session {
    let json = reply.json();
    assert_eq!(json["status"], "signed_in", "{json}");
    Session::from_tokens(&json["tokens"])
}

const EXTENSION_ID: &str = "abcdefghijklmnopabcdefghijklmnop";
const EXTENSION_REDIRECT: &str = "https://abcdefghijklmnopabcdefghijklmnop.chromiumapp.org/";

// ---------------------------------------------------------------------------------------------
// start

#[tokio::test]
async fn start_gives_the_providers_address() {
    let sso = sso();
    let client = sso.device();
    let reply = sso.start(&client).await;
    assert_eq!(reply.status, StatusCode::OK, "{:?}", reply.json());
    let json = reply.json();
    assert_eq!(json["providerName"], "Single sign-on");
    let url = json["authorizationUrl"].as_str().expect("a URL");
    assert!(url.starts_with("https://idp.test/authorize?"), "{url}");
    assert!(
        reply.header("dpop-nonce").is_some(),
        "the nonce header is on SSO routes too"
    );
    assert_eq!(
        sso.provider.last_request().expect("asked").redirect_uri,
        "https://kemlock.test/kem/v1/auth/sso/callback"
    );
}

#[tokio::test]
async fn start_needs_a_dpop_proof() {
    let sso = sso();
    let client = sso.device();
    let reply = client
        .send(
            "POST",
            "/kem/v1/auth/sso/start",
            Req {
                body: Some(sso.start_body()),
                no_proof: true,
                ..Req::default()
            },
        )
        .await;
    assert_eq!(reply.status, StatusCode::UNAUTHORIZED);
    assert_eq!(reply.problem(), "invalid-dpop-proof");
    assert!(sso.provider.last_request().is_none());
}

#[tokio::test]
async fn start_refuses_bad_input_and_an_unconfigured_server() {
    let sso = sso();
    let client = sso.device();
    for body in [
        json!({"challenge": "short", "state": APP_STATE}),
        json!({"challenge": sso.challenge(), "state": "tiny"}),
        json!({"challenge": sso.challenge(), "state": APP_STATE, "redirect": "https://evil.example/"}),
        json!({"challenge": sso.challenge(), "state": APP_STATE, "surprise": 1}),
    ] {
        let reply = client.post("/kem/v1/auth/sso/start", body.clone()).await;
        assert_eq!(reply.status, StatusCode::BAD_REQUEST, "{body}");
        assert_eq!(reply.problem(), "invalid-request");
        assert_eq!(reply.content_type(), "application/problem+json");
    }

    let off = SsoSettings {
        enabled: false,
        ..sso.repos.settings().expect("settings")
    };
    sso.repos.set_settings(off);
    let reply = sso.start(&client).await;
    assert_eq!(reply.status, StatusCode::NOT_FOUND);
    assert_eq!(reply.problem(), "sso-not-configured");
}

// ---------------------------------------------------------------------------------------------
// callback

#[tokio::test]
async fn the_callback_redirects_to_the_app_with_a_code_and_keeps_it_out_of_caches() {
    let sso = sso();
    let client = sso.device();
    sso.start(&client).await;
    let reply = sso.browser(&client, "provider-code-1").await;
    assert_eq!(reply.status, StatusCode::SEE_OTHER);
    let location = reply.header("location").expect("a Location header");
    assert!(location.starts_with("kemlock://sso?code="), "{location}");
    assert!(
        location.ends_with(&format!("&state={APP_STATE}")),
        "{location}"
    );
    assert_eq!(reply.header("cache-control"), Some("no-store"));
    assert_eq!(reply.header("referrer-policy"), Some("no-referrer"));
}

#[tokio::test]
async fn the_callback_passes_a_provider_error_to_the_app() {
    let sso = sso();
    let client = sso.device();
    sso.start(&client).await;
    let state = sso.provider.last_request().expect("asked").state;
    let reply = callback(&client, &format!("error=access_denied&state={state}")).await;
    assert_eq!(reply.status, StatusCode::SEE_OTHER);
    assert_eq!(
        reply.header("location"),
        Some(format!("kemlock://sso?error=access_denied&state={APP_STATE}").as_str())
    );
}

#[tokio::test]
async fn the_callback_refuses_a_missing_foreign_or_expired_state() {
    let sso = sso();
    let client = sso.device();
    for query in ["", "code=abc", "code=abc&state=forged", "state="] {
        let reply = callback(&client, query).await;
        assert_eq!(reply.status, StatusCode::BAD_REQUEST, "{query}");
        assert_eq!(reply.problem(), "sso-state-invalid", "{query}");
        assert!(reply.header("location").is_none());
    }

    sso.start(&client).await;
    let state = sso.provider.last_request().expect("asked").state;
    sso.app.clock.advance(time::Duration::minutes(11));
    let reply = callback(&client, &format!("code=abc&state={state}")).await;
    assert_eq!(reply.problem(), "sso-state-invalid");
}

// ---------------------------------------------------------------------------------------------
// finish

#[tokio::test]
async fn a_full_sign_in_makes_an_account_and_issues_tokens_the_api_accepts() {
    let sso = sso();
    let client = sso.device();
    let reply = sso.sign_in(&client, "provider-code-1").await;
    assert_eq!(reply.status, StatusCode::OK, "{:?}", reply.json());
    let json = reply.json();
    assert_eq!(json["newAccount"], true);
    assert_eq!(json["mfaViaSso"], false);
    assert_eq!(json["tokens"]["tokenType"], "DPoP");
    let session = session_of(&reply);

    // The account exists with no keys, and is linked to the provider's subject.
    let user = sso
        .app
        .store
        .user_by_email("ada@example.org")
        .expect("the account was made");
    assert_eq!(user.id.to_string(), session.user_id);
    assert!(user.opaque_record.is_none());
    assert!(user.wrapped_root_key.is_empty());
    assert_eq!(sso.repos.identities().len(), 1);

    // The same tokens as a password sign-in: the rest of the API takes them with the same key.
    let synced = client
        .get_authed("/kem/v1/sync", &session.access_token)
        .await;
    assert_eq!(synced.status, StatusCode::OK, "{:?}", synced.json());
    // And only with the key they are bound to.
    let thief = sso.device();
    let stolen = thief
        .get_authed("/kem/v1/sync", &session.access_token)
        .await;
    assert_eq!(stolen.status, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn finish_needs_the_dpop_key_and_verifier_of_start() {
    let sso = sso();
    let client = sso.device();
    sso.start(&client).await;
    let redirected = sso.browser(&client, "provider-code-1").await;
    let code = code_of(redirected.header("location").expect("Location"));

    // Another device (another key) with the code and the verifier.
    let other = sso.device();
    let reply = sso.finish(&other, &code).await;
    assert_eq!(reply.status, StatusCode::UNAUTHORIZED);
    assert_eq!(reply.problem(), "unauthorized");

    // The right device with another verifier.
    let reply = client
        .post(
            "/kem/v1/auth/sso/finish",
            json!({
                "code": code,
                "verifier": b64(&[9u8; 32]),
                "device": {"name": "Pixel"},
            }),
        )
        .await;
    assert_eq!(reply.status, StatusCode::UNAUTHORIZED);
    assert_eq!(
        sso.provider.exchanges(),
        0,
        "the provider's code stayed unspent"
    );
    assert!(sso.app.store.user_by_email("ada@example.org").is_none());

    // And without a proof at all.
    let reply = client
        .send(
            "POST",
            "/kem/v1/auth/sso/finish",
            Req {
                body: Some(
                    json!({"code": code, "verifier": sso.verifier, "device": {"name": "x"}}),
                ),
                no_proof: true,
                ..Req::default()
            },
        )
        .await;
    assert_eq!(reply.problem(), "invalid-dpop-proof");

    // The right device with the right verifier still works.
    let reply = sso.finish(&client, &code).await;
    assert_eq!(reply.status, StatusCode::OK, "{:?}", reply.json());
}

#[tokio::test]
async fn finish_refuses_garbage_and_an_unverified_email() {
    let sso = sso();
    let client = sso.device();
    let reply = sso.finish(&client, "garbage").await;
    assert_eq!(reply.status, StatusCode::BAD_REQUEST);
    assert_eq!(reply.problem(), "sso-state-invalid");

    let mut unverified = claims("sub-1", "ada@example.org");
    unverified.email_verified = Some(false);
    sso.provider.say(unverified);
    let reply = sso.sign_in(&client, "provider-code-1").await;
    assert_eq!(reply.status, StatusCode::FORBIDDEN);
    assert_eq!(reply.problem(), "sso-email-not-verified");
    assert!(sso.app.store.user_by_email("ada@example.org").is_none());
}

#[tokio::test]
async fn a_provider_failure_is_a_502_without_its_details() {
    let sso = sso();
    let client = sso.device();
    sso.start(&client).await;
    let redirected = sso.browser(&client, "provider-code-1").await;
    let code = code_of(redirected.header("location").expect("Location"));
    // The provider's code is spent before the server asks.
    sso.finish(&client, &code).await;
    let reply = sso.finish(&client, &code).await;
    assert_eq!(reply.status, StatusCode::BAD_GATEWAY);
    assert_eq!(reply.problem(), "sso-provider-failed");
    assert!(!String::from_utf8_lossy(&reply.body).contains("invalid_grant"));
}

#[tokio::test]
async fn an_account_with_two_step_gets_the_challenge_unless_the_provider_did_mfa() {
    let sso = sso();
    let client = sso.device();
    let first = sso.sign_in(&client, "provider-code-1").await;
    let user = session_of(&first).user_id.parse().expect("a user id");
    TwoFactorRepo::put(
        &sso.app.store,
        &TwoFactor {
            user,
            method: TwoFactorMethod::Totp,
            sealed_secret: sso.app.crypto.seal("totp", &[9u8; 20]),
            enabled: true,
            created_at: sso.app.crypto.now(),
        },
    )
    .await
    .expect("stored");

    // No amr: the second step is owed, and the existing route completes it.
    let second = sso.sign_in(&client, "provider-code-2").await;
    assert_eq!(second.status, StatusCode::OK);
    let json = second.json();
    assert_eq!(json["status"], "two_factor_required");
    assert_eq!(json["methods"], json!(["totp"]));
    assert!(json["tokens"].is_null());
    let code = kemlock_crypto::totp::code_at(
        &[9u8; 20],
        u64::try_from(sso.app.now()).expect("a positive time"),
    );
    let done = client
        .post(
            "/kem/v1/auth/two-factor",
            json!({"challenge": json["challenge"], "method": "totp", "code": code}),
        )
        .await;
    assert_eq!(done.status, StatusCode::OK, "{:?}", done.json());

    // amr shows MFA: tokens at once, and the response says why.
    let mut mfa = claims("sub-1", "ada@example.org");
    mfa.amr = vec!["pwd".to_owned(), "otp".to_owned()];
    sso.provider.say(mfa);
    let third = sso.sign_in(&client, "provider-code-3").await;
    let json = third.json();
    assert_eq!(json["status"], "signed_in", "{json}");
    assert_eq!(json["mfaViaSso"], true);
}

// ---------------------------------------------------------------------------------------------
// back-channel logout

async fn logout(sso: &Sso, body: &str) -> Reply {
    sso.device()
        .send(
            "POST",
            "/kem/v1/auth/sso/backchannel-logout",
            Req {
                headers: vec![(
                    "content-type",
                    "application/x-www-form-urlencoded".to_owned(),
                )],
                raw_body: Some(body.as_bytes().to_vec()),
                no_proof: true,
                ..Req::default()
            },
        )
        .await
}

#[tokio::test]
async fn a_logout_token_ends_the_subjects_sessions() {
    let sso = sso();
    let client = sso.device();
    let session = session_of(&sso.sign_in(&client, "provider-code-1").await);
    assert_eq!(
        client
            .get_authed("/kem/v1/sync", &session.access_token)
            .await
            .status,
        StatusCode::OK
    );

    let reply = logout(&sso, "logout_token=a.signed.token").await;
    assert_eq!(
        reply.status,
        StatusCode::OK,
        "{:?}",
        String::from_utf8_lossy(&reply.body)
    );
    assert_eq!(reply.header("cache-control"), Some("no-store"));

    // The access token stops working at once, and the refresh token is gone.
    let synced = client
        .get_authed("/kem/v1/sync", &session.access_token)
        .await;
    assert_eq!(synced.status, StatusCode::UNAUTHORIZED);
    assert_eq!(synced.problem(), "session-ended");
    let refreshed = client
        .post(
            "/kem/v1/auth/token",
            json!({"grantType": "refresh_token", "refreshToken": session.refresh_token}),
        )
        .await;
    assert_eq!(refreshed.status, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn an_invalid_logout_token_is_a_400_in_the_oidc_shape() {
    let sso = sso();
    let client = sso.device();
    let session = session_of(&sso.sign_in(&client, "provider-code-1").await);
    sso.provider
        .say_logout(Err(kemlock_app::sso::SsoError::Token("forged".to_owned())));

    let reply = logout(&sso, "logout_token=forged").await;
    assert_eq!(reply.status, StatusCode::BAD_REQUEST);
    let json = reply.json();
    assert_eq!(json["error"], "invalid_request");
    assert!(json["error_description"].is_string());
    // Nothing ended.
    assert_eq!(
        client
            .get_authed("/kem/v1/sync", &session.access_token)
            .await
            .status,
        StatusCode::OK
    );

    // No token at all, or the token under another name.
    for body in ["", "other=1", "logout_token"] {
        let reply = logout(&sso, body).await;
        // "logout_token" with no value is an empty token, which the provider refuses too.
        assert_eq!(reply.status, StatusCode::BAD_REQUEST, "{body:?}");
    }
}

#[tokio::test]
async fn a_logout_for_an_unknown_subject_is_still_a_200() {
    let sso = sso();
    sso.provider.say_logout(Ok(LogoutClaims {
        issuer: ISSUER.to_owned(),
        subject: Some("nobody".to_owned()),
        session_id: None,
    }));
    let reply = logout(&sso, "logout_token=t").await;
    assert_eq!(reply.status, StatusCode::OK);
}

#[tokio::test]
async fn logout_without_sso_set_up_is_a_404() {
    let sso = sso();
    sso.repos.set_settings(SsoSettings {
        enabled: false,
        ..sso.repos.settings().expect("settings")
    });
    let reply = logout(&sso, "logout_token=t").await;
    assert_eq!(reply.status, StatusCode::NOT_FOUND);
}

// ---------------------------------------------------------------------------------------------
// the rest of the API is untouched, and the document

#[tokio::test]
async fn the_merged_router_still_serves_the_rest_of_the_api() {
    let sso = sso();
    let client = sso.device();
    let config = client.get("/kem/v1/config").await;
    assert_eq!(config.status, StatusCode::OK);
    let unknown = client.get("/kem/v1/auth/sso/nowhere").await;
    assert_eq!(unknown.status, StatusCode::NOT_FOUND);
    assert_eq!(unknown.problem(), "not-found");
}

#[test]
fn the_sso_openapi_document_names_the_four_routes() {
    let doc = serde_json::to_value(SsoApiDoc::openapi()).expect("serialises");
    let paths = doc["paths"].as_object().expect("paths");
    for (path, method) in [
        ("/kem/v1/auth/sso/start", "post"),
        ("/kem/v1/auth/sso/callback", "get"),
        ("/kem/v1/auth/sso/finish", "post"),
        ("/kem/v1/auth/sso/backchannel-logout", "post"),
    ] {
        assert!(paths[path][method].is_object(), "{method} {path}");
    }
    assert_eq!(paths.len(), 4);
}

// ---------------------------------------------------------------------------------------------
// the browser extension

fn browser_start_body(sso: &Sso, kind: &str) -> Value {
    json!({
        "challenge": sso.challenge(),
        "state": APP_STATE,
        "redirect": EXTENSION_REDIRECT,
        "kind": kind,
    })
}

#[tokio::test]
async fn a_browser_extension_on_the_list_signs_in_through_its_own_address() {
    let sso = sso_on(App::with_extension_ids(&[EXTENSION_ID]));
    let client = sso.device();
    let started = client
        .post(
            "/kem/v1/auth/sso/start",
            browser_start_body(&sso, "kemlock-browser"),
        )
        .await;
    assert_eq!(started.status, StatusCode::OK, "{:?}", started.json());

    let redirected = sso.browser(&client, "provider-code-1").await;
    assert_eq!(redirected.status, StatusCode::SEE_OTHER);
    let location = redirected.header("location").expect("a Location header");
    assert!(
        location.starts_with(&format!("{EXTENSION_REDIRECT}?code=")),
        "{location}"
    );
    assert_eq!(redirected.header("cache-control"), Some("no-store"));
    assert_eq!(redirected.header("referrer-policy"), Some("no-referrer"));

    let finished = client
        .post(
            "/kem/v1/auth/sso/finish",
            json!({
                "code": code_of(location),
                "verifier": sso.verifier,
                "device": {"name": "Kemlock", "kind": "kemlock-browser", "deviceType": 2},
            }),
        )
        .await;
    assert_eq!(finished.status, StatusCode::OK, "{:?}", finished.json());
    assert_eq!(finished.json()["status"], "signed_in");
}

#[tokio::test]
async fn an_extension_the_admin_did_not_name_gets_no_sso_code() {
    for app in [
        App::new(false),
        App::with_extension_ids(&["ponmlkjihgfedcbaponmlkjihgfedcba"]),
    ] {
        let sso = sso_on(app);
        let client = sso.device();
        let reply = client
            .post(
                "/kem/v1/auth/sso/start",
                browser_start_body(&sso, "kemlock-browser"),
            )
            .await;
        assert_eq!(reply.status, StatusCode::BAD_REQUEST, "{:?}", reply.json());
        assert_eq!(reply.problem(), "invalid-request");
        assert!(sso.provider.last_request().is_none());
    }
}

#[tokio::test]
async fn only_a_browser_device_may_start_at_an_extensions_address() {
    let sso = sso_on(App::with_extension_ids(&[EXTENSION_ID]));
    let client = sso.device();
    for body in [
        json!({"challenge": sso.challenge(), "state": APP_STATE, "redirect": EXTENSION_REDIRECT}),
        browser_start_body(&sso, "kemlock-web"),
        browser_start_body(&sso, "kemlock-android"),
        browser_start_body(&sso, "other"),
    ] {
        let reply = client.post("/kem/v1/auth/sso/start", body.clone()).await;
        assert_eq!(reply.status, StatusCode::BAD_REQUEST, "{body}");
    }
    assert!(sso.provider.last_request().is_none());
}

#[tokio::test]
async fn a_browser_sign_in_is_not_finished_by_another_kind_of_device() {
    let sso = sso_on(App::with_extension_ids(&[EXTENSION_ID]));
    let client = sso.device();
    let started = client
        .post(
            "/kem/v1/auth/sso/start",
            browser_start_body(&sso, "kemlock-browser"),
        )
        .await;
    assert_eq!(started.status, StatusCode::OK);
    let redirected = sso.browser(&client, "provider-code-1").await;
    let code = code_of(redirected.header("location").expect("a Location header"));
    for device in [
        json!({"name": "Web", "kind": "kemlock-web"}),
        json!({"name": "Pixel", "kind": "kemlock-android"}),
        json!({"name": "Something"}),
    ] {
        let reply = client
            .post(
                "/kem/v1/auth/sso/finish",
                json!({"code": code, "verifier": sso.verifier, "device": device}),
            )
            .await;
        assert_eq!(reply.status, StatusCode::UNAUTHORIZED, "{device}");
    }
}
