//! A security key as the second step (provider 7): the challenge in the 400 answer.
//!
//! The Kemlock app signs in with a key through `VwKeyStep` and the server's own challenge
//! (`kemlock/mobile/test/vaultwarden_server/api_test.dart:152-232`); the fixtures in
//! `fixtures/webauthn/` are what a real Vaultwarden 1.37.5 sent and took (their README lists the
//! rules). The design's 2FA row: "WebAuthn options under `"7"` for the server's own domain".
//!
//! Nothing here can sign: the key is registered with a credential of the right shape and the
//! challenge is asked for, never answered (see `kemlock_contract_tests::webauthn`).

use kemlock_contract_tests::account::{device_id, set_field};
use kemlock_contract_tests::shape::{Mode, assert_shape, assert_single_spelling};
use kemlock_contract_tests::util::key_of;
use kemlock_contract_tests::webauthn::register_key;
use kemlock_contract_tests::{fixtures, fresh_session};
use serde_json::{Value, json};

#[tokio::test]
async fn the_challenge_under_7_has_vaultwardens_shape_and_names_the_servers_own_domain() {
    // `TwoFactorProviders2["7"]` is the options for `navigator.credentials.get`: `allowCredentials`
    // (the key's id), `challenge`, `extensions.appid` (the server's `/app-id.json`), `rpId` (the
    // host of the server's domain), `timeout` and `userVerification` (webauthn/README.md; the app
    // reads `rpId` and refuses a challenge for another origin, api_test.dart:176-179).
    let s = fresh_session().await;
    let key = register_key(&s).await;

    let reply = s.http.token(&s.account.login_form(&device_id())).await;
    assert_eq!(
        reply.status,
        400,
        "an account with a security key asks for it as a second step; got {}",
        reply.text()
    );
    let body = reply.json();
    assert_single_spelling("two-step answer", &body);
    let providers = key_of(&body, "TwoFactorProviders")
        .and_then(Value::as_array)
        .unwrap_or_else(|| panic!("TwoFactorProviders must be a list: {body}"));
    assert!(
        providers.iter().any(|p| p == &json!(7) || p == &json!("7")),
        "the security key is provider 7; got {providers:?}"
    );
    let challenge = key_of(&body, "TwoFactorProviders2")
        .and_then(|details| key_of(details, "7"))
        .unwrap_or_else(|| panic!("TwoFactorProviders2 has the key \"7\": {body}"));

    let recorded = fixtures::json("webauthn/providers2-7.json");
    assert_shape(
        "TwoFactorProviders2[\"7\"]",
        &recorded,
        challenge,
        Mode::Exact,
    );
    assert_single_spelling("TwoFactorProviders2[\"7\"]", challenge);

    assert_eq!(
        challenge["rpId"],
        json!(key.rp_id),
        "rpId is the host of the server's domain (webauthn/README.md: \"for the name localhost\")"
    );
    assert_eq!(
        challenge["extensions"]["appid"],
        json!(format!("{}/app-id.json", s.http.base())),
        "the appid is the server's own /app-id.json"
    );
    let text = challenge["challenge"].as_str().unwrap_or_default();
    assert_eq!(
        text.len(),
        43,
        "the challenge is 32 random bytes in base64url: {text}"
    );
    let allowed = &challenge["allowCredentials"][0];
    assert_eq!(
        allowed["id"],
        json!(key.credential_id),
        "the registered key is the one asked for"
    );
    assert_eq!(allowed["type"], "public-key");
    assert!(
        challenge["timeout"].is_u64() || challenge["timeout"].is_i64(),
        "{challenge}"
    );
}

#[tokio::test]
async fn an_answer_for_another_challenge_is_refused_with_a_400_and_no_token() {
    // webauthn/README.md, "What the server did": a refused answer is "HTTP 400 ... and no
    // `TwoFactorProviders`", and "an answer to an older challenge, after a newer one was asked for,
    // is refused". The recorded `token.json` answers a challenge of another server and day.
    let s = fresh_session().await;
    register_key(&s).await;
    let first = s.http.token(&s.account.login_form(&device_id())).await;
    assert_eq!(first.status, 400, "{}", first.text());

    let answer = fixtures::text("webauthn/token.json");
    let mut form = s.account.login_form(&device_id());
    set_field(&mut form, "twoFactorProvider", "7");
    set_field(&mut form, "twoFactorToken", answer.trim());
    set_field(&mut form, "twoFactorRemember", "0");
    let refused = s.http.token(&form).await;
    assert_eq!(
        refused.status,
        400,
        "an answer that isn't to the challenge the server made is a 400; got {}",
        refused.text()
    );
    assert!(
        refused.json().get("access_token").is_none(),
        "no token: {}",
        refused.text()
    );
}
