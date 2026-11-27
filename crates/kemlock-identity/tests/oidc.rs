//! The relying party against an in-process provider over HTTP: discovery, the authorization URL,
//! the code exchange with PKCE, the nonce and the client secret, ID token validation, key
//! rotation, and back-channel logout tokens.

use kemlock_app::b64url;
use kemlock_app::sso::model::{AuthorizationRequest, CodeExchange};
use kemlock_app::sso::{ClientConfig, OidcProvider, SsoError};
use kemlock_crypto::hash;
use kemlock_identity::OidcClient;
use kemlock_identity::testing::{Es256Signer, FakeProvider, FakeUser};
use serde_json::json;
use std::collections::HashMap;
use std::time::Duration;

const CLIENT_ID: &str = "kemlock";
const SECRET: &str = "s3cret";
const CALLBACK: &str = "https://kemlock.test/kem/v1/auth/sso/callback";

struct Rp {
    provider: FakeProvider,
    oidc: OidcClient,
    config: ClientConfig,
}

async fn rp_with(secret: Option<&str>) -> Rp {
    let provider = FakeProvider::start(CLIENT_ID, secret)
        .await
        .expect("the fake provider starts");
    let config = ClientConfig {
        issuer: provider.issuer().to_owned(),
        client_id: CLIENT_ID.to_owned(),
        client_secret: secret.map(str::to_owned),
        scopes: vec!["email".to_owned(), "profile".to_owned()],
    };
    Rp {
        provider,
        oidc: OidcClient::new().expect("the client builds"),
        config,
    }
}

async fn rp() -> Rp {
    rp_with(Some(SECRET)).await
}

fn request() -> AuthorizationRequest {
    AuthorizationRequest {
        state: "sealed-state-abc".to_owned(),
        nonce: "nonce-123".to_owned(),
        code_verifier: b64url::encode(&[7u8; 32]),
        redirect_uri: CALLBACK.to_owned(),
    }
}

fn exchange_of(code: String, request: &AuthorizationRequest) -> CodeExchange {
    CodeExchange {
        code,
        code_verifier: request.code_verifier.clone(),
        redirect_uri: request.redirect_uri.clone(),
        nonce: request.nonce.clone(),
    }
}

/// The authorization URL, the provider's login, and the code from the redirect.
async fn login(rp: &Rp, request: &AuthorizationRequest) -> String {
    let url = rp
        .oidc
        .authorization_url(&rp.config, request)
        .await
        .expect("the authorization URL is built");
    let location = rp.provider.approve(&url).expect("the provider approves");
    let parsed = url::Url::parse(&location).expect("the redirect is a URL");
    let query: HashMap<String, String> = parsed
        .query_pairs()
        .map(|(k, v)| (k.into_owned(), v.into_owned()))
        .collect();
    assert!(location.starts_with(CALLBACK), "{location}");
    assert_eq!(
        query.get("state").map(String::as_str),
        Some(request.state.as_str())
    );
    query
        .get("code")
        .expect("the redirect carries a code")
        .clone()
}

#[tokio::test]
async fn the_authorization_url_carries_pkce_nonce_state_scopes_and_the_callback() {
    let rp = rp().await;
    let request = request();
    let url = rp
        .oidc
        .authorization_url(&rp.config, &request)
        .await
        .expect("built");
    let parsed = url::Url::parse(&url).expect("a URL");
    assert_eq!(
        format!("{}://{}", parsed.scheme(), parsed.authority()),
        rp.provider.issuer()
    );
    assert_eq!(parsed.path(), "/authorize");
    let query: HashMap<String, String> = parsed
        .query_pairs()
        .map(|(k, v)| (k.into_owned(), v.into_owned()))
        .collect();
    assert_eq!(query["response_type"], "code");
    assert_eq!(query["client_id"], CLIENT_ID);
    assert_eq!(query["redirect_uri"], CALLBACK);
    assert_eq!(query["state"], request.state);
    assert_eq!(query["nonce"], request.nonce);
    assert_eq!(query["code_challenge_method"], "S256");
    assert_eq!(
        query["code_challenge"],
        b64url::encode(&hash::sha256(request.code_verifier.as_bytes()))
    );
    let scopes: Vec<&str> = query["scope"].split(' ').collect();
    assert!(scopes.contains(&"openid"));
    assert!(scopes.contains(&"email"));
    assert!(scopes.contains(&"profile"));
    assert!(
        !query.contains_key("code_verifier"),
        "the verifier stays with the server"
    );
}

#[tokio::test]
async fn an_openid_scope_in_the_settings_is_not_asked_for_twice() {
    let mut rp = rp().await;
    rp.config.scopes = vec!["openid".to_owned(), "email".to_owned()];
    let url = rp
        .oidc
        .authorization_url(&rp.config, &request())
        .await
        .expect("built");
    let parsed = url::Url::parse(&url).expect("a URL");
    let scope = parsed
        .query_pairs()
        .find(|(k, _)| k == "scope")
        .map(|(_, v)| v.into_owned())
        .expect("a scope");
    assert_eq!(scope.split(' ').filter(|s| *s == "openid").count(), 1);
}

#[tokio::test]
async fn the_provider_redirects_a_browser_to_the_callback_with_a_code() {
    let rp = rp().await;
    let url = rp
        .oidc
        .authorization_url(&rp.config, &request())
        .await
        .expect("built");
    // Over HTTP, not in process: the same endpoint a browser would open.
    let browser = openidconnect::reqwest::ClientBuilder::new()
        .redirect(openidconnect::reqwest::redirect::Policy::none())
        .build()
        .expect("a client");
    let response = browser
        .get(&url)
        .send()
        .await
        .expect("the provider answers");
    assert_eq!(response.status().as_u16(), 303);
    let location = response
        .headers()
        .get("location")
        .and_then(|v| v.to_str().ok())
        .expect("a Location header");
    assert!(
        location.starts_with(&format!("{CALLBACK}?code=")),
        "{location}"
    );
    assert!(location.ends_with("&state=sealed-state-abc"), "{location}");
}

#[tokio::test]
async fn a_full_exchange_returns_the_verified_claims() {
    let rp = rp().await;
    let mut ada = FakeUser::new("sub-ada", "ada@example.org");
    ada.amr = vec!["pwd".to_owned(), "otp".to_owned()];
    ada.groups = vec!["/eng".to_owned(), "/ops".to_owned()];
    ada.session_id = Some("sid-7".to_owned());
    rp.provider.set_user(ada);

    let request = request();
    let code = login(&rp, &request).await;
    let claims = rp
        .oidc
        .exchange(&rp.config, &exchange_of(code, &request))
        .await
        .expect("the exchange works");
    assert_eq!(claims.issuer, rp.provider.issuer());
    assert_eq!(claims.subject, "sub-ada");
    assert_eq!(claims.email.as_deref(), Some("ada@example.org"));
    assert_eq!(claims.email_verified, Some(true));
    assert_eq!(claims.name.as_deref(), Some("Ada Lovelace"));
    assert_eq!(claims.amr, vec!["pwd", "otp"]);
    assert_eq!(claims.groups, vec!["/eng", "/ops"]);
    assert_eq!(claims.session_id.as_deref(), Some("sid-7"));
}

#[tokio::test]
async fn missing_optional_claims_stay_missing() {
    let rp = rp().await;
    let mut user = FakeUser::new("sub-x", "x@example.org");
    user.email_verified = None;
    user.name = None;
    user.session_id = None;
    rp.provider.set_user(user);
    let request = request();
    let code = login(&rp, &request).await;
    let claims = rp
        .oidc
        .exchange(&rp.config, &exchange_of(code, &request))
        .await
        .expect("the exchange works");
    assert_eq!(claims.email_verified, None);
    assert_eq!(claims.name, None);
    assert_eq!(claims.session_id, None);
    assert!(claims.amr.is_empty());
    assert!(claims.groups.is_empty());
}

#[tokio::test]
async fn a_string_email_verified_is_accepted() {
    let rp = rp().await;
    rp.provider.set_string_booleans(true);
    let request = request();
    let code = login(&rp, &request).await;
    let claims = rp
        .oidc
        .exchange(&rp.config, &exchange_of(code, &request))
        .await
        .expect("the exchange works");
    assert_eq!(claims.email_verified, Some(true));
}

#[tokio::test]
async fn a_public_client_needs_no_secret() {
    let rp = rp_with(None).await;
    let request = request();
    let code = login(&rp, &request).await;
    let claims = rp
        .oidc
        .exchange(&rp.config, &exchange_of(code, &request))
        .await
        .expect("the exchange works");
    assert_eq!(claims.subject, "sub-ada");
}

#[tokio::test]
async fn a_code_works_once() {
    let rp = rp().await;
    let request = request();
    let code = login(&rp, &request).await;
    rp.oidc
        .exchange(&rp.config, &exchange_of(code.clone(), &request))
        .await
        .expect("the first exchange works");
    assert!(matches!(
        rp.oidc
            .exchange(&rp.config, &exchange_of(code, &request))
            .await,
        Err(SsoError::Provider(_))
    ));
}

#[tokio::test]
async fn the_wrong_pkce_verifier_is_refused_by_the_provider() {
    let rp = rp().await;
    let request = request();
    let code = login(&rp, &request).await;
    let mut exchange = exchange_of(code, &request);
    exchange.code_verifier = b64url::encode(&[8u8; 32]);
    assert!(matches!(
        rp.oidc.exchange(&rp.config, &exchange).await,
        Err(SsoError::Provider(_))
    ));
}

#[tokio::test]
async fn the_wrong_client_secret_is_refused_by_the_provider() {
    let mut rp = rp().await;
    let request = request();
    let code = login(&rp, &request).await;
    rp.config.client_secret = Some("not-the-secret".to_owned());
    assert!(matches!(
        rp.oidc
            .exchange(&rp.config, &exchange_of(code, &request))
            .await,
        Err(SsoError::Provider(_))
    ));
}

#[tokio::test]
async fn an_id_token_with_another_nonce_is_refused() {
    let rp = rp().await;
    let request = request();
    let code = login(&rp, &request).await;
    let mut exchange = exchange_of(code, &request);
    exchange.nonce = "a-different-nonce".to_owned();
    assert!(matches!(
        rp.oidc.exchange(&rp.config, &exchange).await,
        Err(SsoError::Token(_))
    ));
}

#[tokio::test]
async fn an_expired_id_token_is_refused() {
    let rp = rp().await;
    rp.provider.set_id_token_lifetime(-30);
    let request = request();
    let code = login(&rp, &request).await;
    assert!(matches!(
        rp.oidc
            .exchange(&rp.config, &exchange_of(code, &request))
            .await,
        Err(SsoError::Token(_))
    ));
}

#[tokio::test]
async fn an_id_token_for_another_audience_is_refused() {
    let rp = rp().await;
    rp.provider.set_audience(Some("another-client"));
    let request = request();
    let code = login(&rp, &request).await;
    assert!(matches!(
        rp.oidc
            .exchange(&rp.config, &exchange_of(code, &request))
            .await,
        Err(SsoError::Token(_))
    ));
}

#[tokio::test]
async fn an_id_token_signed_with_an_unpublished_key_is_refused() {
    let rp = rp().await;
    rp.provider.sign_ids_with_a_rogue_key(true);
    let request = request();
    let code = login(&rp, &request).await;
    assert!(matches!(
        rp.oidc
            .exchange(&rp.config, &exchange_of(code, &request))
            .await,
        Err(SsoError::Token(_))
    ));
}

#[tokio::test]
async fn a_rotated_signing_key_is_picked_up_without_a_restart() {
    let rp = rp().await;
    let request = request();

    // The first sign-in discovers the provider and caches its keys.
    let code = login(&rp, &request).await;
    rp.oidc
        .exchange(&rp.config, &exchange_of(code, &request))
        .await
        .expect("the first exchange works");

    // The provider rotates its key; the cache is stale, and the next token is signed by the new one.
    rp.provider.rotate_key();
    let code = login(&rp, &request).await;
    rp.oidc
        .exchange(&rp.config, &exchange_of(code, &request))
        .await
        .expect("the keys are fetched again and the token verifies");
}

#[tokio::test]
async fn a_stale_cache_refetches_after_its_ttl_too() {
    let rp = rp().await;
    let oidc = OidcClient::new()
        .expect("builds")
        .with_cache_ttl(Duration::ZERO);
    let request = request();
    for _ in 0..2 {
        let url = oidc
            .authorization_url(&rp.config, &request)
            .await
            .expect("discovers each time");
        let location = rp.provider.approve(&url).expect("approves");
        let code = url::Url::parse(&location)
            .expect("a URL")
            .query_pairs()
            .find(|(k, _)| k == "code")
            .map(|(_, v)| v.into_owned())
            .expect("a code");
        oidc.exchange(&rp.config, &exchange_of(code, &request))
            .await
            .expect("the exchange works");
    }
}

#[tokio::test]
async fn a_provider_that_cant_be_reached_is_a_provider_error() {
    let rp = rp().await;
    let mut config = rp.config.clone();
    config.issuer = "http://127.0.0.1:1".to_owned();
    assert!(matches!(
        rp.oidc.authorization_url(&config, &request()).await,
        Err(SsoError::Provider(_))
    ));
    config.issuer = "not a url".to_owned();
    assert!(matches!(
        rp.oidc.authorization_url(&config, &request()).await,
        Err(SsoError::Provider(_))
    ));
}

// ---------------------------------------------------------------------------------------------
// Back-channel logout

#[tokio::test]
async fn a_logout_token_from_the_provider_is_valid() {
    let rp = rp().await;
    let token = rp.provider.logout_token(Some("sub-ada"), Some("sid-1"));
    let claims = rp
        .oidc
        .validate_logout_token(&rp.config, &token)
        .await
        .expect("valid");
    assert_eq!(claims.issuer, rp.provider.issuer());
    assert_eq!(claims.subject.as_deref(), Some("sub-ada"));
    assert_eq!(claims.session_id.as_deref(), Some("sid-1"));

    let sid_only = rp.provider.logout_token(None, Some("sid-2"));
    let claims = rp
        .oidc
        .validate_logout_token(&rp.config, &sid_only)
        .await
        .expect("valid");
    assert_eq!(claims.subject, None);
}

#[tokio::test]
async fn a_logout_token_signed_by_someone_else_is_refused() {
    let rp = rp().await;
    let claims = rp.provider.logout_claims(Some("sub-ada"), None);
    // Same key id as the provider's, a different key.
    let forged = Es256Signer::new("key-1").sign(&claims);
    assert!(matches!(
        rp.oidc.validate_logout_token(&rp.config, &forged).await,
        Err(SsoError::Token(_))
    ));
}

#[tokio::test]
async fn forged_logout_tokens_force_one_fetch_of_the_keys_not_one_each() {
    let rp = rp().await;
    // The keys are cached by one valid token: one discovery.
    rp.oidc
        .validate_logout_token(&rp.config, &rp.provider.logout_token(Some("a"), None))
        .await
        .expect("valid");
    assert_eq!(rp.provider.discovery_requests(), 1);

    // Many tokens that don't verify, from anyone who can reach the route: the first may check
    // whether the provider rotated its key, the rest are refused from what is cached.
    let claims = rp.provider.logout_claims(Some("sub-ada"), None);
    for _ in 0..20 {
        let forged = Es256Signer::new("key-1").sign(&claims);
        assert!(matches!(
            rp.oidc.validate_logout_token(&rp.config, &forged).await,
            Err(SsoError::Token(_))
        ));
    }
    assert_eq!(
        rp.provider.discovery_requests(),
        2,
        "one forced fetch, not twenty"
    );
}

#[tokio::test]
async fn a_rotation_is_still_found_once_the_floor_has_passed() {
    let rp = rp().await;
    let oidc = OidcClient::new()
        .expect("builds")
        .with_refresh_floor(Duration::from_millis(50));
    oidc.validate_logout_token(&rp.config, &rp.provider.logout_token(Some("a"), None))
        .await
        .expect("valid");
    // A forged token uses up the forced fetch; the provider then rotates.
    let forged = Es256Signer::new("key-1").sign(&rp.provider.logout_claims(Some("a"), None));
    assert!(
        oidc.validate_logout_token(&rp.config, &forged)
            .await
            .is_err()
    );
    rp.provider.rotate_key();
    let token = rp.provider.logout_token(Some("a"), None);
    assert!(
        oidc.validate_logout_token(&rp.config, &token)
            .await
            .is_err(),
        "inside the floor the cached keys are used"
    );
    tokio::time::sleep(Duration::from_millis(80)).await;
    oidc.validate_logout_token(&rp.config, &token)
        .await
        .expect("after the floor the keys are fetched again");
}

#[tokio::test]
async fn a_logout_token_that_breaks_a_rule_is_refused() {
    let rp = rp().await;
    for (what, change) in [
        ("another audience", json!({"aud": "another-client"})),
        ("another issuer", json!({"iss": "https://evil.example"})),
        ("a nonce", json!({"nonce": "n"})),
        ("no event", json!({"events": {}})),
    ] {
        let mut claims = rp.provider.logout_claims(Some("sub-ada"), None);
        for (key, value) in change.as_object().expect("an object") {
            claims[key] = value.clone();
        }
        let token = rp.provider.sign(&claims);
        assert!(
            matches!(
                rp.oidc.validate_logout_token(&rp.config, &token).await,
                Err(SsoError::Token(_))
            ),
            "{what}"
        );
    }
}

#[tokio::test]
async fn a_logout_token_after_a_key_rotation_refetches_the_keys() {
    let rp = rp().await;
    // Cache the provider's keys with one valid token.
    rp.oidc
        .validate_logout_token(&rp.config, &rp.provider.logout_token(Some("a"), None))
        .await
        .expect("valid");
    rp.provider.rotate_key();
    let token = rp.provider.logout_token(Some("a"), None);
    rp.oidc
        .validate_logout_token(&rp.config, &token)
        .await
        .expect("valid after the keys are fetched again");
}
