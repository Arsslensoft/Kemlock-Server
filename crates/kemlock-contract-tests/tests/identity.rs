//! `/identity`: prelogin on both paths, the token grants, the second step, any client, and the
//! bounds of the KDF.
//!
//! The citations are to the Kemlock app (`kemlock/mobile/...`), to Amethystora Vault
//! (`amethyst/apps/vault-net/tests/vaultwarden.rs`) and to its spec
//! (`amethystora-plans/vault-sync/spec-protocol.md`).

use kemlock_contract_tests::account::{device_id as new_device, remove_field, set_field};
use kemlock_contract_tests::shape::{Mode, assert_shape, assert_single_spelling};
use kemlock_contract_tests::util::{is_jwt, is_uuid, jwt_parts, key_of, message_of};
use kemlock_contract_tests::{Account, Http, Kdf, Reply, client, fixtures, fresh_session, totp};
use serde_json::{Value, json};

async fn prelogin(http: &Http, path: &str, email: &str) -> Reply {
    http.send(http.call("POST", path).json(&json!({"email": email})))
        .await
}

fn now_seconds() -> i64 {
    i64::try_from(totp::now()).unwrap_or(0)
}

// ─── Prelogin ───────────────────────────────────────────────────────────────

#[tokio::test]
async fn prelogin_has_vaultwardens_shape_on_the_old_path_and_the_new_one() {
    // Kemlock calls `/accounts/prelogin` (vw_api.dart:246-254); Amethystora calls
    // `/accounts/prelogin/password` first and `/accounts/prelogin` after a 404
    // (spec-protocol.md:70-90). Both read `kdf`, `kdfIterations`, `kdfMemory`, `kdfParallelism` and
    // `kdfSettings`, and `salt` is null on Vaultwarden.
    let http = client();
    let cases = [
        ("PBKDF2", "account-pbkdf2.json", Kdf::pbkdf2(600_000)),
        ("Argon2id", "account-argon2id.json", Kdf::argon2id(3, 64, 4)),
    ];
    for (name, fixture, kdf) in cases {
        let account = http.register_ok(kdf.clone()).await;
        let recorded = fixtures::account(fixture)["prelogin"].clone();
        let mut bodies = Vec::new();
        for path in [
            "/identity/accounts/prelogin",
            "/identity/accounts/prelogin/password",
        ] {
            let reply = prelogin(&http, path, &account.email).await;
            let body = reply.ok_json(path);
            assert_shape(&format!("{path} for {name}"), &recorded, &body, Mode::Exact);
            assert_single_spelling(path, &body);
            assert_eq!(body["kdf"], json!(kdf.kind), "{path}: kdf for {name}");
            assert_eq!(
                body["kdfIterations"],
                json!(kdf.iterations),
                "{path}: kdfIterations for {name}"
            );
            assert_eq!(
                body["kdfMemory"],
                json!(kdf.memory),
                "{path}: kdfMemory is null for PBKDF2 and MiB for Argon2id"
            );
            assert_eq!(
                body["kdfParallelism"],
                json!(kdf.parallelism),
                "{path}: kdfParallelism"
            );
            assert_eq!(
                body["kdfSettings"],
                json!({
                    "kdfType": kdf.kind,
                    "iterations": kdf.iterations,
                    "memory": kdf.memory,
                    "parallelism": kdf.parallelism,
                }),
                "{path}: kdfSettings says the same as the older names, as Vaultwarden's does \
                 (Amethystora refuses an answer whose two forms differ, spec-protocol.md:86)"
            );
            assert!(
                body["salt"].is_null(),
                "{path}: Vaultwarden answers salt: null, and Amethystora refuses a salt that is \
                 not the email (spec-protocol.md:84 and 111); got {}",
                body["salt"]
            );
            bodies.push(body);
        }
        assert_eq!(
            bodies[0], bodies[1],
            "the new path answers with the same body as the old one for {name} \
             (design: \"The same body as prelogin\")"
        );
    }
}

#[tokio::test]
async fn prelogin_of_an_unknown_email_is_a_made_up_answer_that_stays_the_same() {
    // Vaultwarden answers for any email, made-up ones too, so as not to say which accounts exist
    // (vw_api.dart:244-245); Amethystora asserts the settings are within bounds and the same each
    // time (vaultwarden.rs:299-303).
    let http = client();
    let recorded = fixtures::account("account-pbkdf2.json")["prelogin"].clone();
    for email in ["nobody-at-all@example.test", "another-nobody@example.test"] {
        for path in [
            "/identity/accounts/prelogin",
            "/identity/accounts/prelogin/password",
        ] {
            let first = prelogin(&http, path, email).await;
            let second = prelogin(&http, path, email).await;
            let a = first.ok_json(&format!("{path} for an unknown email"));
            let b = second.ok_json(&format!("{path} for an unknown email, again"));
            assert_eq!(
                a, b,
                "{path}: Vaultwarden gives an unknown email the same made-up settings each time"
            );
            assert_shape(&format!("{path} for {email}"), &recorded, &a, Mode::Subset);
            assert_single_spelling(path, &a);
            let kind = a["kdfSettings"]["kdfType"].as_u64();
            let iterations = a["kdfSettings"]["iterations"].as_u64().unwrap_or(0);
            match kind {
                Some(0) => assert!(
                    (5_000..=2_000_000).contains(&iterations),
                    "{path}: made-up PBKDF2 rounds must be within Bitwarden's bounds \
                     (BwKdf.fromJson, bitwarden.dart:67-68), got {iterations}"
                ),
                Some(1) => {
                    let memory = a["kdfSettings"]["memory"].as_u64().unwrap_or(0);
                    let lanes = a["kdfSettings"]["parallelism"].as_u64().unwrap_or(0);
                    assert!(
                        (2..=10).contains(&iterations),
                        "{path}: passes {iterations}"
                    );
                    assert!((16..=1024).contains(&memory), "{path}: memory {memory}");
                    assert!((1..=16).contains(&lanes), "{path}: lanes {lanes}");
                }
                other => panic!("{path}: made-up kdfType must be 0 or 1, got {other:?}"),
            }
        }
    }
}

#[tokio::test]
async fn prelogin_reads_the_email_without_regard_to_case() {
    // Vaultwarden finds an account by its lower-cased email, and the apps send it trimmed
    // (vw_api.dart:247, `email.trim()`) but as typed. Both apps derive the master key from the
    // lower-cased email (spec-protocol.md:111), so the account must be found either way.
    let http = client();
    let account = http.register_ok(Kdf::argon2id(3, 64, 4)).await;
    let upper = account.email.to_uppercase();
    let reply = prelogin(&http, "/identity/accounts/prelogin", &upper).await;
    let body = reply.ok_json("prelogin with an upper-case email");
    assert_eq!(
        body["kdf"],
        json!(1),
        "the account's own KDF, not a made-up one"
    );
    assert_eq!(body["kdfIterations"], json!(3));
    assert_eq!(body["kdfMemory"], json!(64));
    assert_eq!(body["kdfParallelism"], json!(4));
}

// ─── Grants ─────────────────────────────────────────────────────────────────

#[tokio::test]
async fn the_password_grant_answers_as_vaultwardens_token_does() {
    // Kemlock: vw_api.dart:259-282 and 539-577 (`Key`, `Kdf*`, `access_token`, `refresh_token`,
    // `expires_in`, `TwoFactorToken`); api_test.dart:54-63 opens `Key` with the master key.
    // Amethystora: spec-protocol.md:196-215 (section 3.4) and vaultwarden.rs:274-278. The token's
    // claims: design ("keep Vaultwarden's RS256 tokens: 2-hour access").
    let http = client();
    let account = http.register_ok(Kdf::cheap_pbkdf2()).await;
    let device = new_device();
    let reply = http.token(&account.login_form(&device)).await;
    let body = reply.ok_json("password grant");
    assert_single_spelling("token answer", &body);
    let recorded = fixtures::account("account-pbkdf2.json")["token"].clone();
    assert_shape("token answer", &recorded, &body, Mode::Subset);

    let access = body["access_token"].as_str().unwrap_or_default();
    assert!(is_jwt(access), "access_token is a three-part JWT: {access}");
    assert!(
        body["refresh_token"]
            .as_str()
            .is_some_and(|t| !t.is_empty()),
        "a password login has a refresh token (vaultwarden.rs:277); got {}",
        body["refresh_token"]
    );
    assert_eq!(body["token_type"], json!("Bearer"));
    assert_eq!(
        body["expires_in"],
        json!(7200),
        "Vaultwarden's access token lasts two hours (spec-protocol.md:194, 3.3); the app turns \
         expires_in into its own expiry (vw_api.dart:586-587)"
    );
    let scope = body["scope"].as_str().unwrap_or_default();
    assert!(
        scope.contains("api") && scope.contains("offline_access"),
        "scope says what was granted; got {scope:?}"
    );
    assert_eq!(
        body["Key"],
        json!(account.user_key),
        "Key is the user key as registered"
    );
    assert_eq!(body["PrivateKey"], json!(account.private_key));
    assert_eq!(body["Kdf"], json!(0));
    assert_eq!(body["KdfIterations"], json!(100_000));
    assert!(body["KdfMemory"].is_null() && body["KdfParallelism"].is_null());
    assert_ne!(
        body["ForcePasswordReset"],
        json!(true),
        "ForcePasswordReset true makes Amethystora stop (spec-protocol.md:209)"
    );
    let unlock = &body["UserDecryptionOptions"];
    assert_eq!(unlock["HasMasterPassword"], json!(true));
    assert_eq!(
        unlock["MasterPasswordUnlock"]["Salt"],
        json!(account.email),
        "the salt is the email, as in the recorded answer"
    );
    assert_eq!(
        unlock["MasterPasswordUnlock"]["MasterKeyEncryptedUserKey"],
        json!(account.user_key)
    );
    assert_eq!(
        unlock["MasterPasswordUnlock"]["MasterKeyWrappedUserKey"],
        json!(account.user_key)
    );

    let (header, claims) = jwt_parts(access).expect("a decodable access token");
    assert_eq!(
        header["alg"],
        json!("RS256"),
        "Vaultwarden signs with RS256"
    );
    let subject = claims["sub"].as_str().unwrap_or_default();
    assert!(
        is_uuid(subject),
        "sub is the account's id (vw_api.dart:732-741): {subject}"
    );
    assert_eq!(claims["email"], json!(account.email));
    assert_eq!(
        claims["client_id"],
        json!("mobile"),
        "the server copies client_id into the token (browser/README.md, task 1.4)"
    );
    let left = claims["exp"].as_i64().unwrap_or(0) - now_seconds();
    assert!(
        (7000..=7300).contains(&left),
        "exp is two hours away; it is {left} seconds away"
    );
}

#[tokio::test]
async fn the_refresh_grant_gives_a_new_refresh_token_each_time() {
    // vw_api.dart:306-316 (a refused token is "signed out": 400 or 401), api_test.dart:234-242,
    // vaultwarden.rs:279-285 and spec-protocol.md:273: Vaultwarden makes a new refresh token
    // each time, and the client must keep what comes back.
    let session = fresh_session().await;
    let old = session.refresh.clone().expect("a refresh token");
    let form = [
        ("grant_type".to_owned(), "refresh_token".to_owned()),
        ("client_id".to_owned(), "mobile".to_owned()),
        ("refresh_token".to_owned(), old.clone()),
    ];
    let reply = session.http.token(&form).await;
    let body = reply.ok_json("refresh grant");
    assert_single_spelling("refresh answer", &body);
    assert!(
        is_jwt(body["access_token"].as_str().unwrap_or_default()),
        "{body}"
    );
    let new = body["refresh_token"].as_str().unwrap_or_default();
    assert!(
        !new.is_empty() && new != old,
        "Vaultwarden hands out a new refresh token with every refresh; got {new:?}"
    );
    assert!(
        body["expires_in"].is_number(),
        "expires_in tells when the new token ends"
    );

    let renewed = kemlock_contract_tests::Session {
        access: body["access_token"].as_str().unwrap_or_default().to_owned(),
        ..session.clone()
    };
    assert!(
        renewed.revision_date().await > 0,
        "the renewed access token opens the API (api_test.dart:237)"
    );

    let bad = [
        ("grant_type".to_owned(), "refresh_token".to_owned()),
        ("client_id".to_owned(), "mobile".to_owned()),
        ("refresh_token".to_owned(), "not a refresh token".to_owned()),
    ];
    let refused = session.http.token(&bad).await;
    assert!(
        refused.status == 400 || refused.status == 401,
        "a refresh token the server doesn't know is a 400 (or a 401), which the app reads as \
         'signed out' (vw_api.dart:313); got {} {}",
        refused.status,
        refused.text()
    );
    assert!(refused.json().get("access_token").is_none());
}

#[tokio::test]
async fn the_client_credentials_grant_gives_a_session_without_a_refresh_token() {
    // The personal API key: vw_api.dart:286-301 and 543-585 (no refresh token comes back, the key
    // signs in again), api_test.dart:74-105, vaultwarden.rs:286-292 (`refresh.is_none()`),
    // spec-protocol.md:192-194. The same user key comes back, so the master password still opens it.
    let session = fresh_session().await;
    let reply = session
        .post(
            "/api/accounts/api-key",
            &json!({"masterPasswordHash": session.account.hash}),
        )
        .await;
    let key = reply.ok_json("POST /api/accounts/api-key");
    let secret = key_of(&key, "apiKey")
        .and_then(Value::as_str)
        .unwrap_or_else(|| panic!("api-key: the answer has apiKey, got {key}"))
        .to_owned();

    let form: Vec<(String, String)> = [
        ("grant_type", "client_credentials".to_owned()),
        ("client_id", format!("user.{}", session.user_id)),
        ("client_secret", secret.clone()),
        ("scope", "api".to_owned()),
        ("deviceType", "0".to_owned()),
        ("deviceIdentifier", new_device()),
        ("deviceName", "Kemlock contract tests".to_owned()),
    ]
    .into_iter()
    .map(|(name, value)| (name.to_owned(), value))
    .collect();
    let reply = session.http.token(&form).await;
    let body = reply.ok_json("client_credentials grant");
    assert_single_spelling("client_credentials answer", &body);
    assert!(
        is_jwt(body["access_token"].as_str().unwrap_or_default()),
        "{body}"
    );
    assert!(
        body.get("refresh_token")
            .and_then(Value::as_str)
            .is_none_or(str::is_empty),
        "Vaultwarden gives the API key's session no refresh token (design: \"Serve the personal-key \
         grant without a refresh token\"); got {}",
        body["refresh_token"]
    );
    assert_eq!(
        body["Key"],
        json!(session.account.user_key),
        "the API key's session carries the same user key (api_test.dart:92)"
    );
    assert_eq!(
        body["Kdf"],
        json!(0),
        "and the KDF, which the master password needs"
    );

    let signed = kemlock_contract_tests::Session {
        access: body["access_token"].as_str().unwrap_or_default().to_owned(),
        ..session.clone()
    };
    assert!(signed.revision_date().await > 0, "its token opens the API");

    let mut wrong = form;
    set_field(&mut wrong, "client_secret", "not the secret");
    let refused = session.http.token(&wrong).await;
    assert_eq!(
        refused.status,
        400,
        "a wrong API key is a 400 (vw_api.dart:565-574 reads 400 or 401 as a refusal); got {}",
        refused.text()
    );
}

// ─── The second step ────────────────────────────────────────────────────────

/// Turns the authenticator on for the account, as the web vault does
/// (api_test.dart:107-116; vaultwarden.rs:472-484): the server makes a key, and a code from it
/// proves it was kept. Returns the key.
async fn turn_on_authenticator(session: &kemlock_contract_tests::Session) -> String {
    let hash = &session.account.hash;
    let generated = session
        .post(
            "/api/two-factor/get-authenticator",
            &json!({"masterPasswordHash": hash}),
        )
        .await
        .ok_json("get-authenticator");
    let secret = key_of(&generated, "authenticator")
        .and_then(|inner| key_of(inner, "key"))
        .or_else(|| key_of(&generated, "key"))
        .and_then(Value::as_str)
        .unwrap_or_else(|| panic!("get-authenticator: no authenticator.key in {generated}"))
        .to_owned();
    let verification = key_of(&generated, "userVerificationToken")
        .cloned()
        .unwrap_or(Value::Null);
    let code = totp::code_at(&secret, totp::now());
    session
        .put(
            "/api/two-factor/authenticator",
            &json!({
                "key": secret,
                "token": code,
                "masterPasswordHash": hash,
                "userVerificationToken": verification,
            }),
        )
        .await
        .ok_json("PUT authenticator");
    secret
}

fn second_step(
    account: &Account,
    device: &str,
    provider: &str,
    token: &str,
    remember: bool,
) -> Vec<(String, String)> {
    let mut form = account.login_form(device);
    set_field(&mut form, "twoFactorProvider", provider);
    set_field(&mut form, "twoFactorToken", token);
    set_field(
        &mut form,
        "twoFactorRemember",
        if remember { "1" } else { "0" },
    );
    form
}

#[tokio::test]
async fn a_second_step_is_a_400_with_the_providers_and_then_a_remember_token_skips_it() {
    // vw_api.dart:565-575 (a 400 with `TwoFactorProviders` is the second step, `_message` finds
    // the rest), api_test.dart:119-149, vaultwarden.rs:472-503 (`TwoFactor(vec![0])`, a wrong code
    // is the server's own message, the next period's code is taken once), spec-protocol.md:217-240.
    let session = fresh_session().await;
    let secret = turn_on_authenticator(&session).await;
    let account = session.account.clone();
    let http = session.http.clone();
    let device = new_device();

    let reply = http.token(&account.login_form(&device)).await;
    assert_eq!(
        reply.status,
        400,
        "a password login on an account with a second step is a 400, not a 200 or a 401; got {}",
        reply.text()
    );
    let body = reply.json();
    assert_single_spelling("two-step answer", &body);
    assert!(
        body.get("access_token").is_none(),
        "no token before the second step: {body}"
    );
    let providers = key_of(&body, "TwoFactorProviders")
        .and_then(Value::as_array)
        .unwrap_or_else(|| panic!("TwoFactorProviders must be a list of provider numbers: {body}"));
    assert!(
        providers.iter().any(|p| p == &json!(0) || p == &json!("0")),
        "the authenticator is provider 0; got {providers:?}"
    );
    let details = key_of(&body, "TwoFactorProviders2")
        .and_then(Value::as_object)
        .unwrap_or_else(|| {
            panic!("TwoFactorProviders2 must be an object keyed by provider: {body}")
        });
    assert!(
        details.contains_key("0"),
        "TwoFactorProviders2 has the key \"0\": {body}"
    );

    let wrong = http
        .token(&second_step(&account, &device, "0", "000000", false))
        .await;
    assert_eq!(
        wrong.status,
        400,
        "a wrong code is a 400; got {}",
        wrong.text()
    );
    assert!(wrong.json().get("access_token").is_none());
    assert!(
        message_of(&wrong.json()).is_some() || wrong.json().get("TwoFactorProviders").is_some(),
        "a wrong code says something the app can show: {}",
        wrong.text()
    );

    // The code that turned it on can't be used again: the next period's is taken, within the
    // allowed drift (api_test.dart:131)
    let code = totp::code_at(&secret, totp::now() + 30);
    let reply = http
        .token(&second_step(&account, &device, "0", &code, true))
        .await;
    let body = reply.ok_json("the second step, with the code");
    let remember = body["TwoFactorToken"]
        .as_str()
        .unwrap_or_default()
        .to_owned();
    assert!(
        !remember.is_empty(),
        "with twoFactorRemember=1 the answer carries a TwoFactorToken (vw_api.dart:545, \
         api_test.dart:139); got {body}"
    );
    assert_eq!(body["Key"], json!(account.user_key));

    // Provider 5, the remember token, skips the step (vw_api.dart:277-281)
    let again = http
        .token(&second_step(&account, &device, "5", &remember, false))
        .await;
    let body = again.ok_json("the remember token as provider 5");
    assert!(
        is_jwt(body["access_token"].as_str().unwrap_or_default()),
        "{body}"
    );
}

#[tokio::test]
async fn the_api_key_skips_the_second_step() {
    // api_test.dart:89-105 and vaultwarden.rs:499-502: "the API key asks for no second factor".
    let session = fresh_session().await;
    turn_on_authenticator(&session).await;
    let key = session
        .post(
            "/api/accounts/api-key",
            &json!({"masterPasswordHash": session.account.hash}),
        )
        .await
        .ok_json("api-key");
    let secret = key_of(&key, "apiKey")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_owned();
    let form: Vec<(String, String)> = [
        ("grant_type", "client_credentials".to_owned()),
        ("client_id", format!("user.{}", session.user_id)),
        ("client_secret", secret),
        ("scope", "api".to_owned()),
        ("deviceType", "0".to_owned()),
        ("deviceIdentifier", new_device()),
        ("deviceName", "Kemlock contract tests".to_owned()),
    ]
    .into_iter()
    .map(|(name, value)| (name.to_owned(), value))
    .collect();
    let reply = session.http.token(&form).await;
    reply.ok_json("client_credentials on an account with a second step");
}

#[tokio::test]
async fn the_email_code_route_takes_no_token() {
    // `POST /api/two-factor/send-email-login` takes `email`, `masterPasswordHash` and
    // `deviceIdentifier` and no bearer token (design, routes table; vw_api.dart:319-326,
    // spec-protocol.md:226). An account without email codes can't be sent one, but the route is there
    // and doesn't ask who is calling.
    let http = client();
    let account = http.register_ok(Kdf::cheap_pbkdf2()).await;
    let reply = http
        .send(
            http.call("POST", "/api/two-factor/send-email-login")
                .json(&json!({
                    "email": account.email,
                    "masterPasswordHash": account.hash,
                    "deviceIdentifier": new_device(),
                })),
        )
        .await;
    assert!(
        ![401, 404, 405].contains(&reply.status),
        "the route exists and asks for no bearer token; got {} {}",
        reply.status,
        reply.text()
    );
}

#[tokio::test]
async fn a_new_device_is_never_challenged() {
    // `POST /api/accounts/resend-new-device-otp` is "called only after a new-device challenge,
    // which this server never sends" (design, routes table; spec-protocol.md:238-252: Bitwarden's
    // own server answers `device_error`). Vaultwarden lets any device in with the password.
    let http = client();
    let account = http.register_ok(Kdf::cheap_pbkdf2()).await;
    for _ in 0..3 {
        let reply = http.token(&account.login_form(&new_device())).await;
        let text = reply.text();
        assert_eq!(
            reply.status, 200,
            "a device never seen before signs in: {text}"
        );
        assert!(
            !text.contains("device_error") && !text.contains("new device verification"),
            "no new-device challenge: {text}"
        );
    }
}

// ─── Failures ───────────────────────────────────────────────────────────────

#[tokio::test]
async fn a_wrong_password_and_an_unknown_email_are_both_a_400_the_app_reads_as_auth() {
    // api_test.dart:65-72 (`VwProblem.auth`), vw_api.dart:574 and spec-protocol.md:253-272:
    // Vaultwarden answers 400 with its message in `message` and `errorModel`, never a 401.
    let http = client();
    let account = http.register_ok(Kdf::cheap_pbkdf2()).await;
    let mut form = account.login_form(&new_device());
    set_field(
        &mut form,
        "password",
        "d3JvbmcgcGFzc3dvcmQgaGFzaCAuLi4uLi4uLi4=",
    );
    let wrong = http.token(&form).await;
    assert_eq!(wrong.status, 400, "a wrong password: {}", wrong.text());
    assert!(wrong.json().get("access_token").is_none());
    assert!(
        message_of(&wrong.json()).is_some(),
        "the refusal has a message the app can show: {}",
        wrong.text()
    );

    let mut form = account.login_form(&new_device());
    set_field(&mut form, "username", "nobody-here@example.test");
    let unknown = http.token(&form).await;
    assert_eq!(
        unknown.status,
        wrong.status,
        "an unknown email is refused as a wrong password is, so as not to say which accounts exist; \
         got {}",
        unknown.text()
    );
}

#[tokio::test]
async fn any_scope_but_api_offline_access_is_refused() {
    // spec-protocol.md:165: "`scope` exactly `api offline_access`; anything else is refused on
    // Vaultwarden". The Kemlock app sends exactly that (vw_api.dart:270).
    let http = client();
    let account = http.register_ok(Kdf::cheap_pbkdf2()).await;
    let mut form = account.login_form(&new_device());
    set_field(&mut form, "scope", "something else");
    let reply = http.token(&form).await;
    assert_eq!(reply.status, 400, "an unsupported scope: {}", reply.text());
    assert!(reply.json().get("access_token").is_none());
}

// ─── Any client ─────────────────────────────────────────────────────────────

#[tokio::test]
async fn any_client_id_and_any_device_type_signs_in() {
    // Design, headers table: `client_id` "Any non-empty value", `deviceType` "Any Bitwarden device
    // type", `deviceName` "Any". Kemlock sends `mobile` with 0 or 1 (vw_api.dart:271-272), Amethystora
    // `cli` with 8, also as a `Device-Type` header (vaultwarden.rs:83); a browser extension sends
    // `browser` with 2, 3 or 5 (browser/README.md, task 1.4: `mobile`, `web` and `kemlock` got 200
    // too: "the server doesn't hold an extension to `browser`").
    let http = client();
    let account = http.register_ok(Kdf::cheap_pbkdf2()).await;
    let cases = [
        ("mobile", "0"),
        ("mobile", "1"),
        ("cli", "8"),
        ("browser", "2"),
        ("browser", "3"),
        ("browser", "5"),
        ("web", "9"),
        ("desktop", "7"),
        ("connector", "21"),
        ("kemlock", "0"),
        ("a-client-nobody-has-heard-of", "99"),
    ];
    for (client_id, device_type) in cases {
        let mut form = account.login_form(&new_device());
        set_field(&mut form, "client_id", client_id);
        set_field(&mut form, "deviceType", device_type);
        set_field(
            &mut form,
            "deviceName",
            &format!("Any name for {client_id}"),
        );
        let reply = http
            .token_with_headers(
                &form,
                &[
                    ("Accept", "application/json"),
                    ("Device-Type", device_type),
                    ("User-Agent", "AmethystoraVault/1.0"),
                ],
            )
            .await;
        let body = reply.ok_json(&format!("client_id {client_id}, device type {device_type}"));
        let access = body["access_token"].as_str().unwrap_or_default();
        let (_, claims) = jwt_parts(access).expect("an access token");
        assert_eq!(
            claims["client_id"],
            json!(client_id),
            "Vaultwarden copies client_id into the token's claim and checks nothing else"
        );
    }
}

#[tokio::test]
async fn a_missing_client_id_or_device_identifier_is_refused_and_a_blank_one_is_not() {
    // browser/README.md: "`client_id` is only checked not to be blank for the password grant";
    // spec-protocol.md:281-286: "Vaultwarden needs the device fields too".
    // Vaultwarden 1.37.5 api/identity.rs, `login` (the "password" grant): `check_is_some(
    // data.client_id.as_ref(), "client_id cannot be blank")` only tests for `None`, so a field
    // that is sent empty is `Some("")` and passes. `device_identifier` and the other fields get
    // the same check, so only a missing one is refused.
    let http = client();
    let account = http.register_ok(Kdf::cheap_pbkdf2()).await;
    let mut form = account.login_form(&new_device());
    remove_field(&mut form, "client_id");
    let absent = http.token(&form).await;
    assert_eq!(absent.status, 400, "no client_id: {}", absent.text());
    assert_eq!(
        message_of(&absent.json()).as_deref(),
        Some("client_id cannot be blank")
    );

    let mut form = account.login_form(&new_device());
    set_field(&mut form, "client_id", "");
    let blank = http.token(&form).await;
    let body = blank.ok_json("a client_id sent empty is present, and Vaultwarden takes it");
    let (_, claims) =
        jwt_parts(body["access_token"].as_str().unwrap_or_default()).expect("an access token");
    assert_eq!(
        claims["client_id"],
        json!(""),
        "copied into the claim as sent"
    );

    let mut form = account.login_form(&new_device());
    remove_field(&mut form, "deviceIdentifier");
    let missing = http.token(&form).await;
    assert_eq!(
        missing.status,
        400,
        "no deviceIdentifier: {}",
        missing.text()
    );
}

#[tokio::test]
async fn no_header_makes_the_server_answer_version_header_missing() {
    // Design, headers table: "The server never answers `version_header_missing` or
    // `invalid_client_version`, as Bitwarden's does: Kemlock's own version number would fail that
    // check." Kemlock sends its own version, 1.1.0 (vw_api.dart:218); Amethystora sends 2025.12.0
    // and a `Bitwarden-Client-Name` of `cli`; any of them may send none (spec-protocol.md:146-157).
    let http = client();
    let account = http.register_ok(Kdf::cheap_pbkdf2()).await;
    let sets: [&[(&str, &str)]; 9] = [
        &[],
        &[("Bitwarden-Client-Name", "kemlock")],
        &[("Bitwarden-Client-Version", "1.1.0")],
        &[
            ("Bitwarden-Client-Name", "kemlock"),
            ("Bitwarden-Client-Version", "1.1.0"),
        ],
        &[
            ("Bitwarden-Client-Name", "cli"),
            ("Bitwarden-Client-Version", "2025.12.0"),
        ],
        &[("Bitwarden-Client-Version", "0.0.1")],
        &[("Bitwarden-Client-Version", "2024.11.0")],
        &[("Bitwarden-Client-Version", "banana")],
        &[
            ("Bitwarden-Client-Name", "some-other-app"),
            ("User-Agent", "Dart/3.9 (dart:io)"),
        ],
    ];
    for headers in sets {
        let reply = http
            .token_with_headers(&account.login_form(&new_device()), headers)
            .await;
        let text = reply.text();
        assert_eq!(
            reply.status, 200,
            "a sign-in with headers {headers:?} gets in, as it does on Vaultwarden: {text}"
        );
        assert!(
            !text.contains("version_header_missing") && !text.contains("invalid_client_version"),
            "headers {headers:?}: Bitwarden's own server would refuse these, Vaultwarden does not: \
             {text}"
        );
    }

    // And the API takes calls with or without them: Amethystora sends the version, Kemlock its own
    let session = http.login(&account).await;
    for version in [None, Some("1.1.0"), Some("2024.11.0"), Some("banana")] {
        let reply = session.sync_as(version).await;
        assert_eq!(
            reply.status,
            200,
            "/api/sync as version {version:?}: {}",
            reply.text()
        );
    }
}

// ─── The bounds of the KDF ──────────────────────────────────────────────────

#[tokio::test]
async fn the_kdf_bounds_both_apps_hold_a_server_to_are_taken() {
    // Both apps refuse a server's answer outside Bitwarden's bounds (BwKdf.fromJson,
    // bitwarden.dart:43-58; spec-protocol.md:92-110), and Amethystora registers accounts
    // within them (vaultwarden.rs:449-451). The server takes every setting from its lowest to its
    // highest.
    let http = client();
    let inside = [
        Kdf::pbkdf2(100_000),
        Kdf::pbkdf2(600_000),
        Kdf::pbkdf2(2_000_000),
        Kdf::argon2id(2, 16, 1),
        Kdf::argon2id(3, 64, 4),
        Kdf::argon2id(10, 1024, 16),
    ];
    for kdf in inside {
        let (account, finish) = http.register(kdf.clone()).await;
        assert!(
            finish.is_success(),
            "register/finish takes {kdf:?} as Vaultwarden does; got {} {}",
            finish.status,
            finish.text()
        );
        let reply = prelogin(&http, "/identity/accounts/prelogin", &account.email).await;
        let body = reply.ok_json("prelogin after registering");
        assert_eq!(body["kdfIterations"], json!(kdf.iterations), "{kdf:?}");
        assert_eq!(body["kdfMemory"], json!(kdf.memory), "{kdf:?}");
        assert_eq!(body["kdfParallelism"], json!(kdf.parallelism), "{kdf:?}");
    }
}

#[tokio::test]
async fn kdf_settings_outside_every_bound_are_refused() {
    // The settings Vaultwarden refuses, and this server with it: PBKDF2 under 100,000 rounds,
    // Argon2 memory outside 15 to 1024 MiB (16 to 1024 for the apps), lanes outside 1 to 16.
    // Design: "PBKDF2 100,000 to 2,000,000; Argon2 2 to 10 passes, 16 to 1,024 MiB, 1 to 16 lanes".
    let http = client();
    let outside = [
        Kdf::pbkdf2(99_999),
        Kdf::pbkdf2(1),
        Kdf::argon2id(2, 14, 1),
        Kdf::argon2id(2, 1025, 1),
        Kdf::argon2id(2, 16, 0),
        Kdf::argon2id(2, 16, 17),
        Kdf::argon2id(0, 16, 1),
    ];
    for kdf in outside {
        let (_, finish) = http.register(kdf.clone()).await;
        assert!(
            finish.status == 400 || finish.status == 422,
            "register/finish refuses {kdf:?}: Vaultwarden holds KDF settings to its bounds and the \
             apps refuse anything outside them; got {} {}",
            finish.status,
            finish.text()
        );
    }
}

#[tokio::test]
async fn the_bitwarden_api_takes_the_kdf_settings_vaultwarden_takes_past_amethystoras_bounds() {
    // Design, "Capabilities": Amethystora takes "0 and 1 within bounds: PBKDF2 100,000 to
    // 2,000,000; Argon2 2 to 10 passes, 16 to 1,024 MiB, 1 to 16 lanes", and a changed KDF
    // "offers only settings inside Amethystora's bounds": the bounds narrow what the web vault
    // offers, not what the Bitwarden API takes, which "answers exactly as Vaultwarden does".
    // Vaultwarden 1.37.5 api/core/accounts.rs, `set_kdf_data` (called by `register/finish`)
    // refuses PBKDF2 under 100,000 rounds, Argon2 under 1 pass, memory outside 15 to 1024 MiB and
    // lanes outside 1 to 16, and nothing above: a pass of 1, 15 MiB, 11 passes or 2,000,001
    // rounds are all taken. (`kdf_settings_outside_every_bound_are_refused` has the refusals.)
    let http = client();
    for kdf in [
        Kdf::argon2id(1, 16, 1),
        Kdf::argon2id(11, 16, 1),
        Kdf::argon2id(2, 15, 1),
        Kdf::pbkdf2(2_000_001),
    ] {
        let (_, finish) = http.register(kdf.clone()).await;
        assert!(
            finish.is_success(),
            "register/finish takes {kdf:?} as Vaultwarden does; got {} {}",
            finish.status,
            finish.text()
        );
    }
}
