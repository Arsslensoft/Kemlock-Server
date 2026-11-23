//! Security keys as Bitwarden's second step (provider 7): the web vault's registration routes,
//! the challenge in the token endpoint's 400 and the key's answer, with the real WebAuthn relying
//! party and a software authenticator. The rules are the ones `tests/fixtures/webauthn/README.md`
//! of the contract tests lists for Vaultwarden 1.37.5.

mod common;

use axum::body::Body;
use axum::http::StatusCode;
use common::{DOMAIN, HASH, Harness};
use kemlock_app::ports::{TwoFactor, TwoFactorMethod, TwoFactorRepo};
use kemlock_crypto::seal::ServerSeal;
use kemlock_identity::authenticator::{
    SoftwareAuthenticator, bitwarden_assertion, bitwarden_registration,
};
use serde_json::{Value, json};

const EMAIL: &str = "ada@example.com";

fn authenticator() -> SoftwareAuthenticator {
    SoftwareAuthenticator::new("vault.test", DOMAIN)
}

fn keys_of(value: &Value) -> Vec<&str> {
    let mut keys: Vec<&str> = value
        .as_object()
        .expect("an object")
        .keys()
        .map(String::as_str)
        .collect();
    keys.sort_unstable();
    keys
}

/// `get-webauthn`: the account's keys and a verification token.
async fn get_webauthn(h: &Harness, token: &str) -> (StatusCode, Value) {
    h.json(
        "POST",
        "/api/two-factor/get-webauthn",
        Some(token),
        Some(json!({"masterPasswordHash": HASH})),
    )
    .await
}

/// The whole registration as the web vault runs it: the keys, the challenge, the key's answer.
async fn register_key(
    h: &Harness,
    token: &str,
    slot: Value,
    name: &str,
) -> (SoftwareAuthenticator, Value) {
    let (status, first) = get_webauthn(h, token).await;
    assert_eq!(status, StatusCode::OK, "{first}");
    let verification = first["userVerificationToken"].clone();
    let (status, created) = h
        .json(
            "POST",
            "/api/two-factor/get-webauthn-challenge",
            Some(token),
            Some(json!({"masterPasswordHash": HASH, "userVerificationToken": verification})),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{created}");
    let mut authenticator = authenticator();
    let answer = authenticator.create(&created["options"]);
    let (status, done) = h
        .json(
            "PUT",
            "/api/two-factor/webauthn",
            Some(token),
            Some(json!({
                "id": slot,
                "name": name,
                "masterPasswordHash": HASH,
                "userVerificationToken": verification,
                "deviceResponse": bitwarden_registration(&answer),
            })),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{done}");
    (authenticator, done)
}

/// `get-webauthn-challenge` with a body.
async fn post_challenge(h: &Harness, bearer: &str, body: Value) -> (StatusCode, Value) {
    h.json(
        "POST",
        "/api/two-factor/get-webauthn-challenge",
        Some(bearer),
        Some(body),
    )
    .await
}

/// `PUT /api/two-factor/webauthn` with a body.
async fn put_webauthn(h: &Harness, bearer: &str, body: Value) -> (StatusCode, Value) {
    h.json("PUT", "/api/two-factor/webauthn", Some(bearer), Some(body))
        .await
}

/// `DELETE /api/two-factor/webauthn` with a body.
async fn delete_webauthn(h: &Harness, bearer: &str, body: Value) -> (StatusCode, Value) {
    h.json(
        "DELETE",
        "/api/two-factor/webauthn",
        Some(bearer),
        Some(body),
    )
    .await
}

/// A fresh registration challenge's creation options.
async fn new_options(h: &Harness, bearer: &str, verification: &Value) -> Value {
    let (_, created) =
        post_challenge(h, bearer, json!({"userVerificationToken": verification})).await;
    created["options"].clone()
}

/// A password sign-in with the fields given after the standard ones.
async fn sign_in(h: &Harness, extra: &[(&str, &str)]) -> (StatusCode, Value) {
    let mut fields = Harness::password_fields(EMAIL, HASH);
    fields.extend_from_slice(extra);
    h.token(&fields).await
}

/// The password sign-in's 400 with the challenge for the account's key.
async fn ask(h: &Harness) -> Value {
    let (status, body) = sign_in(h, &[]).await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
    body
}

/// The answer of `authenticator` to `options`, as the client sends it for provider 7.
fn answer(authenticator: &mut SoftwareAuthenticator, options: &Value) -> String {
    bitwarden_assertion(&authenticator.get(options))
}

async fn answer_with(h: &Harness, token: &str, remember: bool) -> (StatusCode, Value) {
    sign_in(
        h,
        &[
            ("twoFactorProvider", "7"),
            ("twoFactorToken", token),
            ("twoFactorRemember", if remember { "1" } else { "0" }),
        ],
    )
    .await
}

fn is_message(body: &Value, message: &str) -> bool {
    body["message"] == message && body.get("TwoFactorProviders").is_none()
}

// ---------------------------------------------------------------------------------------------
// The account routes

#[tokio::test]
async fn a_key_is_registered_with_the_web_vaults_three_calls() {
    let h = Harness::with_webauthn().await;
    let (token, _) = h.signed_in(EMAIL).await;

    let (status, before) = get_webauthn(&h, &token).await;
    assert_eq!(status, StatusCode::OK);
    assert!(before["userVerificationToken"].is_string(), "{before}");
    assert_eq!(before["webAuthn"]["enabled"], false);
    assert_eq!(before["webAuthn"]["keys"], json!([]));

    let (authenticator, done) = register_key(&h, &token, json!(1), "Yubi").await;
    drop(authenticator);
    assert_eq!(done["enabled"], true);
    assert_eq!(done["object"], "twoFactorU2f");
    assert_eq!(
        done["keys"],
        json!([{"id": 1, "name": "Yubi", "migrated": false}])
    );
    let (_, after) = get_webauthn(&h, &token).await;
    assert_eq!(after["webAuthn"]["enabled"], true);
    assert_eq!(after["webAuthn"]["keys"][0]["name"], "Yubi");
}

#[tokio::test]
async fn the_creation_options_name_the_servers_relying_party() {
    let h = Harness::with_webauthn().await;
    let (token, _) = h.signed_in(EMAIL).await;
    let (_, first) = get_webauthn(&h, &token).await;
    let (status, created) = h
        .json(
            "POST",
            "/api/two-factor/get-webauthn-challenge",
            Some(&token),
            Some(json!({
                "masterPasswordHash": HASH,
                "userVerificationToken": first["userVerificationToken"],
            })),
        )
        .await;
    assert_eq!(status, StatusCode::OK);
    let options = &created["options"];
    assert_eq!(options["rp"]["id"], "vault.test");
    assert_eq!(options["challenge"].as_str().map(str::len), Some(43));
    assert_eq!(options["status"], "ok");
    assert_eq!(options["errorMessage"], "");
    assert_eq!(
        options["authenticatorSelection"]["userVerification"],
        "discouraged"
    );
}

#[tokio::test]
async fn the_challenge_needs_the_verification_token_and_the_token_stands_in_for_the_password() {
    let h = Harness::with_webauthn().await;
    let (token, _) = h.signed_in(EMAIL).await;
    let (other, _) = h.signed_in("grace@example.com").await;
    // Without the token the body isn't what the route reads: 422.
    let (status, _) = post_challenge(&h, &token, json!({"masterPasswordHash": HASH})).await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);

    let (_, first) = get_webauthn(&h, &token).await;
    let verification = first["userVerificationToken"].clone();
    let (status, body) =
        post_challenge(&h, &token, json!({"userVerificationToken": verification})).await;
    assert_eq!(status, StatusCode::OK, "the token alone is enough: {body}");

    // A made-up token, another account's token and a wrong password are refused.
    let (status, body) = post_challenge(&h, &token, json!({"userVerificationToken": "junk"})).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["message"], "Invalid user verification token");
    let (status, body) =
        post_challenge(&h, &other, json!({"userVerificationToken": verification})).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["message"], "Invalid user verification token");
    let (status, body) = post_challenge(
        &h,
        &token,
        json!({"masterPasswordHash": "wrong", "userVerificationToken": verification}),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["message"], "Invalid password");

    // An expired token is refused.
    h.env.advance(time::Duration::minutes(11));
    let (status, _) =
        post_challenge(&h, &token, json!({"userVerificationToken": verification})).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn the_routes_need_a_bearer_token_and_the_password() {
    let h = Harness::with_webauthn().await;
    let (token, _) = h.signed_in(EMAIL).await;
    let (status, _) = h
        .json(
            "POST",
            "/api/two-factor/get-webauthn",
            None,
            Some(json!({"masterPasswordHash": HASH})),
        )
        .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    let (status, body) = h
        .json(
            "POST",
            "/api/two-factor/get-webauthn",
            Some(&token),
            Some(json!({"masterPasswordHash": "wrong"})),
        )
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["message"], "Invalid password");
    let (status, body) = h
        .json(
            "POST",
            "/api/two-factor/get-webauthn",
            Some(&token),
            Some(json!({})),
        )
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["message"], "No validation provided");
}

#[tokio::test]
async fn slots_are_one_to_five_and_a_slot_can_be_written_as_text() {
    let h = Harness::with_webauthn().await;
    let (token, _) = h.signed_in(EMAIL).await;
    let (_, first) = get_webauthn(&h, &token).await;
    let verification = first["userVerificationToken"].clone();
    let (_, created) = h
        .json(
            "POST",
            "/api/two-factor/get-webauthn-challenge",
            Some(&token),
            Some(json!({"userVerificationToken": verification})),
        )
        .await;
    let mut authenticator = authenticator();
    let device_response = bitwarden_registration(&authenticator.create(&created["options"]));
    let put = |slot: Value| {
        json!({
            "id": slot,
            "name": "Key",
            "userVerificationToken": verification,
            "deviceResponse": device_response,
        })
    };
    for bad in [json!(0), json!(6), json!("x")] {
        let (status, body) = put_webauthn(&h, &token, put(bad)).await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(body["message"], "Invalid key slot");
    }
    // The challenge wasn't used up by the refused slots.
    let (status, body) = put_webauthn(&h, &token, put(json!("4"))).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["keys"][0]["id"], 4);
}

#[tokio::test]
async fn a_registration_answer_is_refused_without_a_challenge_or_from_another_site() {
    let h = Harness::with_webauthn().await;
    let (token, _) = h.signed_in(EMAIL).await;
    let (_, first) = get_webauthn(&h, &token).await;
    let verification = first["userVerificationToken"].clone();
    let register = |device_response: Value| {
        json!({
            "id": 1,
            "name": "Key",
            "userVerificationToken": verification,
            "deviceResponse": device_response,
        })
    };

    // No challenge was asked for.
    let mut honest = authenticator();
    let options = new_options(&h, &token, &verification).await;
    let answer = bitwarden_registration(&honest.create(&options));
    let (status, _) = put_webauthn(&h, &token, register(answer.clone())).await;
    assert_eq!(status, StatusCode::OK);
    let (status, body) = put_webauthn(&h, &token, register(answer)).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["message"], "Can't recover challenge");

    // A key of another site.
    let options = new_options(&h, &token, &verification).await;
    let mut phisher = SoftwareAuthenticator::new("evil.test", DOMAIN);
    let (status, body) = put_webauthn(
        &h,
        &token,
        register(bitwarden_registration(&phisher.create(&options))),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["message"], "Webauthn");
}

#[tokio::test]
async fn keys_are_deleted_by_slot_with_the_password() {
    let h = Harness::with_webauthn().await;
    let (token, _) = h.signed_in(EMAIL).await;
    register_key(&h, &token, json!(1), "One").await;
    register_key(&h, &token, json!(3), "Three").await;
    let delete = |slot: Value, hash: &str| json!({"id": slot, "masterPasswordHash": hash});

    let (status, body) = delete_webauthn(&h, &token, delete(json!(1), "wrong")).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["message"], "Invalid password");
    let (status, body) = delete_webauthn(&h, &token, delete(json!(2), HASH)).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["message"], "Webauthn entry not found");

    let (status, body) = delete_webauthn(&h, &token, delete(json!(1), HASH)).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["enabled"], true);
    assert_eq!(
        body["keys"],
        json!([{"id": 3, "name": "Three", "migrated": false}])
    );
    let (status, body) = delete_webauthn(&h, &token, delete(json!(3), HASH)).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["enabled"], false);
    assert_eq!(body["keys"], json!([]));

    // With the last key gone the account signs in with the password alone.
    let (status, body) = sign_in(&h, &[]).await;
    assert_eq!(status, StatusCode::OK, "{body}");
}

// ---------------------------------------------------------------------------------------------
// The token endpoint

#[tokio::test]
async fn the_second_step_offers_the_key_with_the_servers_own_challenge() {
    let h = Harness::with_webauthn().await;
    let (token, _) = h.signed_in(EMAIL).await;
    register_key(&h, &token, json!(1), "Yubi").await;

    let body = ask(&h).await;
    assert_eq!(body["error"], "invalid_grant");
    assert_eq!(body["error_description"], "Two factor required.");
    assert_eq!(body["TwoFactorProviders"], json!(["7"]));
    let options = &body["TwoFactorProviders2"]["7"];
    // fixtures/webauthn/providers2-7.json, key for key.
    assert_eq!(
        keys_of(options),
        [
            "allowCredentials",
            "challenge",
            "extensions",
            "rpId",
            "timeout",
            "userVerification"
        ]
    );
    assert_eq!(options["rpId"], "vault.test");
    assert_eq!(
        options["extensions"],
        json!({"appid": "https://vault.test/app-id.json"})
    );
    assert_eq!(options["userVerification"], "discouraged");
    assert_eq!(options["timeout"], 60_000);
    assert_eq!(options["challenge"].as_str().map(str::len), Some(43));
    assert_eq!(options["allowCredentials"][0]["type"], "public-key");
}

#[tokio::test]
async fn a_right_answer_signs_in_and_remember_skips_the_step_next_time() {
    let h = Harness::with_webauthn().await;
    let (token, _) = h.signed_in(EMAIL).await;
    let (mut key, _) = register_key(&h, &token, json!(1), "Yubi").await;

    let options = ask(&h).await["TwoFactorProviders2"]["7"].clone();
    let (status, body) = answer_with(&h, &answer(&mut key, &options), true).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert!(body["access_token"].is_string());
    let remember = body["TwoFactorToken"]
        .as_str()
        .expect("a remember token")
        .to_owned();

    let (status, body) = sign_in(
        &h,
        &[
            ("twoFactorProvider", "5"),
            ("twoFactorToken", remember.as_str()),
        ],
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert!(body["access_token"].is_string());
}

#[tokio::test]
async fn a_refused_answer_uses_the_challenge_up() {
    let h = Harness::with_webauthn().await;
    let (token, _) = h.signed_in(EMAIL).await;
    let (mut key, _) = register_key(&h, &token, json!(1), "Yubi").await;

    let options = ask(&h).await["TwoFactorProviders2"]["7"].clone();
    let mut stranger = authenticator();
    let (status, body) = answer_with(&h, &answer(&mut stranger, &options), false).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert!(is_message(&body, "Webauthn"), "{body}");
    assert!(body.get("access_token").is_none());

    // The same challenge, answered correctly, now finds none.
    let (status, body) = answer_with(&h, &answer(&mut key, &options), false).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert!(is_message(&body, "Can't recover login challenge"), "{body}");
}

#[tokio::test]
async fn an_accepted_answer_sent_again_finds_no_challenge() {
    let h = Harness::with_webauthn().await;
    let (token, _) = h.signed_in(EMAIL).await;
    let (mut key, _) = register_key(&h, &token, json!(1), "Yubi").await;

    let options = ask(&h).await["TwoFactorProviders2"]["7"].clone();
    let sent = answer(&mut key, &options);
    let (status, body) = answer_with(&h, &sent, false).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let (status, body) = answer_with(&h, &sent, false).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert!(is_message(&body, "Can't recover login challenge"), "{body}");
}

#[tokio::test]
async fn an_answer_to_an_older_challenge_is_refused_once_a_newer_one_was_asked_for() {
    let h = Harness::with_webauthn().await;
    let (token, _) = h.signed_in(EMAIL).await;
    let (mut key, _) = register_key(&h, &token, json!(1), "Yubi").await;

    let older = ask(&h).await["TwoFactorProviders2"]["7"].clone();
    let newer = ask(&h).await["TwoFactorProviders2"]["7"].clone();
    assert_ne!(older["challenge"], newer["challenge"]);
    let (status, body) = answer_with(&h, &answer(&mut key, &older), false).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert!(is_message(&body, "Webauthn"), "{body}");
}

#[tokio::test]
async fn a_counter_that_did_not_grow_is_refused() {
    let h = Harness::with_webauthn().await;
    let (token, _) = h.signed_in(EMAIL).await;
    let (mut key, _) = register_key(&h, &token, json!(1), "Yubi").await;

    let options = ask(&h).await["TwoFactorProviders2"]["7"].clone();
    let (status, body) = answer_with(&h, &answer(&mut key, &options), false).await;
    assert_eq!(status, StatusCode::OK, "{body}");

    // A clone of the key that starts again from the beginning.
    key.set_counter(0);
    let options = ask(&h).await["TwoFactorProviders2"]["7"].clone();
    let (status, body) = answer_with(&h, &answer(&mut key, &options), false).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert!(is_message(&body, "Webauthn"), "{body}");
}

#[tokio::test]
async fn origins_are_compared_as_urls_not_as_text() {
    let h = Harness::with_webauthn().await;
    let (token, _) = h.signed_in(EMAIL).await;
    let (mut key, _) = register_key(&h, &token, json!(1), "Yubi").await;

    for (origin, accepted) in [
        ("https://vault.test:9999", false),
        ("http://vault.test", false),
        ("https://vault.test.evil.example", false),
        ("https://VAULT.TEST", true),
    ] {
        key.set_origin(origin);
        let options = ask(&h).await["TwoFactorProviders2"]["7"].clone();
        let (status, body) = answer_with(&h, &answer(&mut key, &options), false).await;
        if accepted {
            assert_eq!(status, StatusCode::OK, "{origin}: {body}");
        } else {
            assert_eq!(status, StatusCode::BAD_REQUEST, "{origin}: {body}");
            assert!(is_message(&body, "Webauthn"), "{origin}: {body}");
        }
    }
}

#[tokio::test]
async fn the_answer_may_spell_client_data_json_either_way() {
    let h = Harness::with_webauthn().await;
    let (token, _) = h.signed_in(EMAIL).await;
    let (mut key, _) = register_key(&h, &token, json!(1), "Yubi").await;

    // The standard spelling, as a browser's toJSON writes it.
    let options = ask(&h).await["TwoFactorProviders2"]["7"].clone();
    let standard = key.get(&options).to_string();
    assert!(standard.contains("clientDataJSON"));
    let (status, body) = answer_with(&h, &standard, false).await;
    assert_eq!(status, StatusCode::OK, "{body}");
}

#[tokio::test]
async fn a_key_and_an_authenticator_app_are_offered_together() {
    let h = Harness::with_webauthn().await;
    let (token, user) = h.signed_in(EMAIL).await;
    register_key(&h, &token, json!(1), "Yubi").await;
    let sealed = ServerSeal::new(&common::SERVER_KEY).seal("totp", &[5u8; 20]);
    TwoFactorRepo::put(
        &h.store,
        &TwoFactor {
            user,
            method: TwoFactorMethod::Totp,
            sealed_secret: sealed,
            enabled: true,
            created_at: h.env.time(),
        },
    )
    .await
    .expect("an enrolment");

    let body = ask(&h).await;
    assert_eq!(body["TwoFactorProviders"], json!(["0", "7"]));
    assert!(body["TwoFactorProviders2"]["0"].is_null());
    assert!(body["TwoFactorProviders2"]["7"]["challenge"].is_string());
}

// ---------------------------------------------------------------------------------------------
// Without a relying party, and the facets list

#[tokio::test]
async fn without_a_relying_party_security_keys_are_off() {
    let h = Harness::new().await;
    let (token, user) = h.signed_in(EMAIL).await;
    let (status, body) = get_webauthn(&h, &token).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(
        body["message"],
        "`DOMAIN` environment variable is not set. Webauthn disabled"
    );

    // A key stored by a server that had one is not offered, and nothing else is usable.
    TwoFactorRepo::put(
        &h.store,
        &TwoFactor {
            user,
            method: TwoFactorMethod::WebAuthn,
            sealed_secret: vec![1, 2, 3],
            enabled: true,
            created_at: h.env.time(),
        },
    )
    .await
    .expect("a row");
    let (status, body) = sign_in(&h, &[]).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(
        body["message"],
        "No enabled and usable two factor providers are available for this account"
    );
}

#[tokio::test]
async fn app_id_json_names_the_servers_origin() {
    let h = Harness::with_webauthn().await;
    let (status, headers, bytes) = h.send("GET", "/app-id.json", &[], Body::empty()).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        headers.get("content-type").and_then(|v| v.to_str().ok()),
        Some("application/fido.trusted-apps+json")
    );
    let body: Value = serde_json::from_slice(&bytes).expect("JSON");
    assert_eq!(
        body["trustedFacets"][0]["version"],
        json!({"major": 1, "minor": 0})
    );
    assert_eq!(body["trustedFacets"][0]["ids"], json!([DOMAIN]));
}
