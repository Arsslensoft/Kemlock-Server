//! `/identity` and the account routes: prelogin, registration, the three grants, the second step.

mod common;

use axum::body::Body;
use axum::http::StatusCode;
use common::{DOMAIN, HASH, Harness, USER_KEY, claims};
use kemlock_app::admin::AdminUserRepo;
use kemlock_app::ports::{
    DeviceRepo, RefreshToken, TokenApi, TokenRepo, TwoFactor, TwoFactorMethod, TwoFactorRepo,
    UserRepo,
};
use kemlock_app::privacy::{AccountEraser, ClientAddr, PrivacyLog};
use kemlock_crypto::seal::ServerSeal;
use serde_json::{Value, json};
use time::Duration;

const BAD_LOGIN: &str = "Username or password is incorrect. Try again";
const DISABLED: &str = "This user has been disabled";
const BEING_DELETED: &str = "This user is being deleted";

fn keys_of(v: &Value) -> Vec<&str> {
    let mut keys: Vec<&str> = v
        .as_object()
        .expect("an object")
        .keys()
        .map(String::as_str)
        .collect();
    keys.sort_unstable();
    keys
}

#[tokio::test]
async fn config_names_a_bitwarden_version_and_the_kemlock_api() {
    let h = Harness::new().await;
    let (status, body) = h.json("GET", "/api/config", None, None).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["object"], "config");
    assert_eq!(body["version"], "2026.6.0");
    assert_eq!(body["environment"]["api"], format!("{DOMAIN}/api"));
    assert_eq!(
        body["environment"]["identity"],
        format!("{DOMAIN}/identity")
    );
    assert_eq!(body["environment"]["vault"], DOMAIN);
    assert_eq!(body["settings"]["disableUserRegistration"], false);
    assert_eq!(body["featureStates"]["pm-19148-innovation-archive"], true);
    assert_eq!(body["kemlock"]["api"], format!("{DOMAIN}/kem/v1"));
    assert_eq!(body["kemlock"]["versions"], json!(["v1"]));
}

#[tokio::test]
async fn prelogin_answers_both_kdfs_on_both_routes() {
    let h = Harness::new().await;
    h.account_with("ada@example.com", HASH, USER_KEY, 1, 3, Some(64), Some(4))
        .await;
    h.account_with("pbk@example.com", HASH, USER_KEY, 0, 600_000, None, None)
        .await;

    for route in [
        "/identity/accounts/prelogin",
        "/identity/accounts/prelogin/password",
    ] {
        let (status, argon) = h
            .json(
                "POST",
                route,
                None,
                Some(json!({"email": " Ada@Example.com "})),
            )
            .await;
        assert_eq!(status, StatusCode::OK, "{route}");
        assert_eq!(
            argon,
            json!({
                "kdf": 1, "kdfIterations": 3, "kdfMemory": 64, "kdfParallelism": 4,
                "kdfSettings": {"iterations": 3, "kdfType": 1, "memory": 64, "parallelism": 4},
                "salt": null
            })
        );
        let (_, pbkdf2) = h
            .json(
                "POST",
                route,
                None,
                Some(json!({"email": "pbk@example.com"})),
            )
            .await;
        assert_eq!(pbkdf2["kdf"], 0);
        assert_eq!(pbkdf2["kdfIterations"], 600_000);
        assert_eq!(pbkdf2["kdfMemory"], Value::Null);
        assert_eq!(pbkdf2["kdfSettings"]["kdfType"], 0);
    }
}

#[tokio::test]
async fn an_unknown_email_gets_the_same_plausible_settings_every_time() {
    let h = Harness::new().await;
    let ask = |email: &'static str| {
        let h = &h;
        async move {
            h.json(
                "POST",
                "/identity/accounts/prelogin",
                None,
                Some(json!({"email": email})),
            )
            .await
        }
    };
    let (status, first) = ask("nobody@example.com").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(ask("nobody@example.com").await.1, first);
    assert_eq!(
        ask("NOBODY@example.com").await.1,
        first,
        "case doesn't matter"
    );

    // It looks like a real account's: the same keys, and one of Vaultwarden's six settings.
    let (_, known) = {
        h.account("real@example.com", HASH).await;
        ask("real@example.com").await
    };
    assert_eq!(keys_of(&first), keys_of(&known));
    let settings = (first["kdf"].as_i64(), first["kdfIterations"].as_i64());
    assert!(
        [(0, 600_000), (0, 100_000), (0, 5_000), (1, 3), (1, 6)]
            .iter()
            .any(|(k, i)| settings == (Some(*k), Some(*i))),
        "{settings:?}"
    );
    // Each email gets its own pick, and over many emails more than one setting turns up.
    let mut seen = std::collections::HashSet::new();
    for n in 0..30 {
        let email = format!("person{n}@example.com");
        let body = h
            .json(
                "POST",
                "/identity/accounts/prelogin",
                None,
                Some(json!({"email": email})),
            )
            .await
            .1;
        seen.insert((body["kdf"].as_i64(), body["kdfIterations"].as_i64()));
    }
    assert!(seen.len() > 1, "{seen:?}");
}

#[tokio::test]
async fn registering_and_signing_in() {
    let h = Harness::new().await;

    // With no mail to send, the token comes straight back: as plain text, or as JSON when asked.
    let (status, headers, bytes) = h
        .send(
            "POST",
            "/identity/accounts/register/send-verification-email",
            &[("content-type", "application/json")],
            Body::from(json!({"email": "new@example.com", "name": "New"}).to_string()),
        )
        .await;
    assert_eq!(status, StatusCode::OK);
    assert!(
        headers["content-type"]
            .to_str()
            .expect("text")
            .starts_with("text/plain")
    );
    let token = String::from_utf8(bytes).expect("a token");
    assert_eq!(token.split('.').count(), 3);
    let (_, _, bytes) = h
        .send(
            "POST",
            "/identity/accounts/register/send-verification-email",
            &[
                ("content-type", "application/json"),
                ("accept", "application/json"),
            ],
            Body::from(json!({"email": "new@example.com"}).to_string()),
        )
        .await;
    let as_json: Value = serde_json::from_slice(&bytes).expect("JSON");
    assert!(as_json.is_string());

    let register = |token: &str| {
        json!({
            "email": "new@example.com",
            "masterPasswordHash": HASH,
            "masterPasswordHint": "  ",
            "kdf": 0, "kdfIterations": 600_000,
            "userSymmetricKey": USER_KEY,
            "keys": {"encryptedPrivateKey": "2.priv|key|mac", "publicKey": "MIIBIjAN"},
            "emailVerificationToken": token
        })
    };
    let (status, body) = h
        .json(
            "POST",
            "/identity/accounts/register/finish",
            None,
            Some(register(&token)),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body, json!({"object": "registerFinish"}));
    // The same address twice is refused.
    let (status, body) = h
        .json(
            "POST",
            "/identity/accounts/register/finish",
            None,
            Some(register(&token)),
        )
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(
        body["message"],
        "Registration not allowed or user already exists"
    );

    let answer = h.login("new@example.com", HASH).await;
    assert_eq!(answer["token_type"], "Bearer");
    assert_eq!(answer["expires_in"], 7200);
    assert_eq!(answer["scope"], "api offline_access");
    assert_eq!(answer["Key"], USER_KEY);
    assert_eq!(answer["PrivateKey"], "2.priv|key|mac");
    assert_eq!(
        (answer["Kdf"].as_i64(), answer["KdfIterations"].as_i64()),
        (Some(0), Some(600_000))
    );
    assert_eq!(answer["KdfMemory"], Value::Null);
    assert_eq!(answer["ForcePasswordReset"], false);
    assert_eq!(
        answer["MasterPasswordPolicy"],
        json!({"Object": "masterPasswordPolicy"})
    );
    assert_eq!(answer["UserDecryptionOptions"]["HasMasterPassword"], true);
    assert_eq!(
        answer["UserDecryptionOptions"]["Object"],
        "userDecryptionOptions"
    );
    assert_eq!(
        answer["UserDecryptionOptions"]["MasterPasswordUnlock"]["Salt"],
        "new@example.com"
    );
    assert_eq!(
        answer["UserDecryptionOptions"]["MasterPasswordUnlock"]["MasterKeyWrappedUserKey"],
        USER_KEY
    );
    assert_eq!(
        answer["AccountKeys"]["publicKeyEncryptionKeyPair"]["publicKey"],
        "MIIBIjAN"
    );
    assert_eq!(answer["AccountKeys"]["Object"], "privateKeys");
    assert!(answer["refresh_token"].is_string());
    assert!(answer.get("TwoFactorToken").is_none());
}

#[tokio::test]
async fn registration_is_refused_when_signups_are_off_and_bad_kdfs_are_named() {
    let h = Harness::with(|s| s.signups_allowed = false).await;
    let (status, body) = h
        .json(
            "POST",
            "/identity/accounts/register/send-verification-email",
            None,
            Some(json!({"email": "x@example.com"})),
        )
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(
        body["message"],
        "Registration not allowed or user already exists"
    );

    let h = Harness::new().await;
    let (_, _, bytes) = h
        .send(
            "POST",
            "/identity/accounts/register/send-verification-email",
            &[("content-type", "application/json")],
            Body::from(json!({"email": "x@example.com"}).to_string()),
        )
        .await;
    let token = String::from_utf8(bytes).expect("a token");
    let (status, body) = h
        .json(
            "POST",
            "/identity/accounts/register/finish",
            None,
            Some(json!({
                "email": "x@example.com", "masterPasswordHash": HASH,
                "kdf": 0, "kdfIterations": 5_000, "userSymmetricKey": USER_KEY,
                "emailVerificationToken": token
            })),
        )
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(
        body["message"],
        "PBKDF2 KDF iterations must be at least 100000."
    );

    // A token for another address is no use, and neither is a body of the wrong shape.
    let (status, body) = h
        .json(
            "POST",
            "/identity/accounts/register/finish",
            None,
            Some(json!({
                "email": "y@example.com", "masterPasswordHash": HASH,
                "kdf": 0, "kdfIterations": 600_000, "userSymmetricKey": USER_KEY,
                "emailVerificationToken": token
            })),
        )
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(
        body["message"],
        "Email verification token does not match email"
    );
    let (status, _) = h
        .json(
            "POST",
            "/identity/accounts/register/finish",
            None,
            Some(json!({"email": "z"})),
        )
        .await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
}

#[tokio::test]
async fn sign_in_failures_say_what_vaultwarden_says() {
    let h = Harness::new().await;
    h.account("ada@example.com", HASH).await;

    let ask = |mut fields: Vec<(&'static str, &'static str)>, drop: &'static str| {
        fields.retain(|(k, _)| *k != drop);
        let h = &h;
        async move { h.token(&fields).await }
    };
    let base = Harness::password_fields("ada@example.com", HASH);
    let base: Vec<(&'static str, &'static str)> = base
        .into_iter()
        .map(|(k, v)| {
            // The fields borrow from this test's constants, which live for the whole run.
            let v: &'static str = Box::leak(v.to_owned().into_boxed_str());
            let k: &'static str = Box::leak(k.to_owned().into_boxed_str());
            (k, v)
        })
        .collect();

    for (dropped, message) in [
        ("client_id", "client_id cannot be blank"),
        ("password", "password cannot be blank"),
        ("scope", "scope cannot be blank"),
        ("username", "username cannot be blank"),
        ("deviceIdentifier", "device_identifier cannot be blank"),
        ("deviceName", "device_name cannot be blank"),
        ("deviceType", "device_type cannot be blank"),
    ] {
        let (status, body) = ask(base.clone(), dropped).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{dropped}");
        assert_eq!(body["message"], message, "{dropped}");
    }

    let (status, body) = h
        .token(&Harness::password_fields("ada@example.com", "not-the-hash"))
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["message"], BAD_LOGIN);
    assert_eq!(body["errorModel"]["message"], BAD_LOGIN);
    let (_, body) = h
        .token(&Harness::password_fields("nobody@example.com", HASH))
        .await;
    assert_eq!(
        body["message"], BAD_LOGIN,
        "an unknown account is no different"
    );

    let mut wrong_scope = Harness::password_fields("ada@example.com", HASH);
    wrong_scope.retain(|(k, _)| *k != "scope");
    wrong_scope.push(("scope", "api"));
    let (_, body) = h.token(&wrong_scope).await;
    assert_eq!(body["message"], "Scope (api) not supported");

    let (status, body) = h.token(&[("grant_type", "magic")]).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["message"], "Invalid type");
    let (status, _) = h.token(&[("client_id", "mobile")]).await;
    assert_eq!(
        status,
        StatusCode::UNPROCESSABLE_ENTITY,
        "no grant_type at all"
    );
}

#[tokio::test]
async fn the_device_type_may_come_from_a_header_and_any_client_id_is_fine() {
    let h = Harness::new().await;
    h.account("ada@example.com", HASH).await;
    let mut fields = Harness::password_fields("ada@example.com", HASH);
    fields.retain(|(k, _)| !matches!(*k, "deviceType" | "client_id"));
    fields.push(("client_id", "amethystora-anything"));
    let mut form = url::form_urlencoded::Serializer::new(String::new());
    for (k, v) in &fields {
        form.append_pair(k, v);
    }
    let (status, _, bytes) = h
        .send(
            "POST",
            "/identity/connect/token",
            &[
                ("content-type", "application/x-www-form-urlencoded"),
                ("device-type", "8"),
            ],
            Body::from(form.finish()),
        )
        .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "{}",
        String::from_utf8_lossy(&bytes)
    );
    let body: Value = serde_json::from_slice(&bytes).expect("JSON");
    let c = claims(
        body["access_token"].as_str().expect("a token"),
        h.env.time().unix_timestamp(),
    );
    assert_eq!(c.devicetype, "Linux");
    assert_eq!(c.client_id, "amethystora-anything");
}

#[tokio::test]
async fn the_access_token_carries_vaultwardens_claims() {
    let h = Harness::new().await;
    let user = h.account("ada@example.com", HASH).await;
    let body = h.login("ada@example.com", HASH).await;
    let now = h.env.time().unix_timestamp();
    let c = claims(body["access_token"].as_str().expect("a token"), now);
    assert_eq!(c.iss, format!("{DOMAIN}|login"));
    assert_eq!(c.sub, user.to_string());
    assert!(c.premium && c.email_verified);
    assert_eq!(c.name, "Kemlock test");
    assert_eq!(c.email, "ada@example.com");
    assert_eq!(c.devicetype, "Android");
    assert_eq!(c.client_id, "mobile");
    assert_eq!(c.scope, ["api", "offline_access"]);
    assert_eq!(c.amr, ["Application"]);
    assert_eq!((c.nbf, c.exp), (now, now + 7200), "two hours");
    assert!(uuid::Uuid::parse_str(&c.device).is_ok());
    assert!(uuid::Uuid::parse_str(&c.sstamp).is_ok());

    // The token works until it expires, 401 after.
    let token = body["access_token"].as_str().expect("a token");
    let (status, _) = h
        .json("GET", "/api/accounts/revision-date", Some(token), None)
        .await;
    assert_eq!(status, StatusCode::OK);
    h.env.advance(Duration::hours(2) + Duration::seconds(31));
    let (status, _) = h
        .json("GET", "/api/accounts/revision-date", Some(token), None)
        .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn refresh_tokens_rotate_and_a_late_reuse_ends_the_sign_in() {
    let h = Harness::new().await;
    h.account("ada@example.com", HASH).await;
    let first = h.login("ada@example.com", HASH).await;
    let r0 = first["refresh_token"].as_str().expect("a token").to_owned();

    let refresh = |token: String| {
        let h = &h;
        async move {
            h.token(&[
                ("grant_type", "refresh_token"),
                ("client_id", "mobile"),
                ("refresh_token", token.as_str()),
            ])
            .await
        }
    };
    let (status, second) = refresh(r0.clone()).await;
    assert_eq!(status, StatusCode::OK, "{second}");
    assert_eq!(
        keys_of(&second),
        [
            "access_token",
            "expires_in",
            "refresh_token",
            "scope",
            "token_type"
        ]
    );
    assert_eq!(second["scope"], "api offline_access");
    let r1 = second["refresh_token"]
        .as_str()
        .expect("a token")
        .to_owned();
    assert_ne!(r1, r0, "a new refresh token each time");
    let (_, status_check) = h
        .json(
            "GET",
            "/api/accounts/revision-date",
            second["access_token"].as_str(),
            None,
        )
        .await;
    assert!(status_check.is_number());

    let (status, third) = refresh(r1.clone()).await;
    assert_eq!(status, StatusCode::OK);
    let r2 = third["refresh_token"].as_str().expect("a token").to_owned();

    // The first token again, within a minute of its use: a lost answer, retried. It gets the
    // successor it made (not a second chain), and a new access token.
    let (status, again) = refresh(r0.clone()).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(again["refresh_token"], json!(r1), "the same successor");

    // Later it is a replay: it fails, and the whole sign-in's tokens go with it.
    h.env.advance(Duration::seconds(61));
    let (status, body) = refresh(r0).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body, json!({"error": "invalid_grant"}));
    let (status, body) = refresh(r2).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body, json!({"error": "invalid_grant"}));

    let (status, body) = refresh("not-a-token".to_owned()).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body, json!({"error": "invalid_grant"}));
    let (_, body) = h.token(&[("grant_type", "refresh_token")]).await;
    assert_eq!(body["message"], "refresh_token cannot be blank");
}

/// Puts a refresh token for `device` of `user` in the store, as the API `api` would have made it,
/// and returns its text.
async fn stored_refresh_token(
    h: &Harness,
    user: kemlock_domain::UserId,
    device: kemlock_domain::DeviceId,
    n: u8,
    api: TokenApi,
) -> String {
    let raw = [n; 32];
    let now = h.env.time();
    TokenRepo::insert(
        &h.store,
        &RefreshToken {
            hash: kemlock_crypto::hash::sha256(&raw),
            family: uuid::Uuid::new_v4(),
            user,
            device,
            security_stamp: UserRepo::by_id(&h.store, user)
                .await
                .expect("a read")
                .expect("the user")
                .security_stamp,
            created_at: now,
            expires_at: now + Duration::days(30),
            used_at: None,
            api,
        },
    )
    .await
    .expect("a token");
    kemlock_app::b64url::encode(&raw)
}

#[tokio::test]
async fn a_kemlock_refresh_token_is_refused_at_the_bitwarden_endpoint() {
    let h = Harness::new().await;
    let user = h.account("ada@example.com", HASH).await;
    h.login("ada@example.com", HASH).await;
    let mut device = DeviceRepo::list(&h.store, user)
        .await
        .expect("the devices")
        .remove(0);
    let refresh = |token: String| {
        let h = &h;
        async move {
            h.token(&[
                ("grant_type", "refresh_token"),
                ("client_id", "mobile"),
                ("refresh_token", token.as_str()),
            ])
            .await
        }
    };

    // A token the Kemlock API made is bound to a DPoP key; here it would be a bearer token.
    let kemlock = stored_refresh_token(&h, user, device.id, 1, TokenApi::Kemlock).await;
    let (status, body) = refresh(kemlock.clone()).await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
    assert_eq!(body, json!({"error": "invalid_grant"}));
    // And it ended that sign-in for good, as a stolen token does.
    let (status, _) = refresh(kemlock).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);

    // A Bitwarden token works on a device that also holds a DPoP key (a phone on both APIs).
    device.dpop_jkt = Some("jkt".to_owned());
    DeviceRepo::upsert(&h.store, &device).await.expect("a key");
    let bitwarden = stored_refresh_token(&h, user, device.id, 2, TokenApi::Bitwarden).await;
    let (status, body) = refresh(bitwarden).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    // The refresh did not take the key off the device.
    let after = DeviceRepo::get(&h.store, device.id)
        .await
        .expect("a read")
        .expect("the device");
    assert_eq!(after.dpop_jkt.as_deref(), Some("jkt"));

    // A token from before the tag is taken only for a device with no DPoP key.
    let legacy = stored_refresh_token(&h, user, device.id, 3, TokenApi::Unknown).await;
    let (status, _) = refresh(legacy).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    device.dpop_jkt = None;
    DeviceRepo::upsert(&h.store, &device).await.expect("no key");
    let legacy = stored_refresh_token(&h, user, device.id, 4, TokenApi::Unknown).await;
    let (status, body) = refresh(legacy).await;
    assert_eq!(status, StatusCode::OK, "{body}");
}

#[tokio::test]
async fn a_refresh_token_expires_after_thirty_days_or_ninety_on_a_phone() {
    let h = Harness::new().await;
    h.account("ada@example.com", HASH).await;
    // `Harness::login` is a phone (device type 0): 90 days.
    let phone = h.login("ada@example.com", HASH).await;
    let mut desktop_fields = Harness::password_fields("ada@example.com", HASH);
    desktop_fields.retain(|(k, _)| !matches!(*k, "deviceType" | "deviceIdentifier"));
    desktop_fields.push(("deviceType", "6"));
    desktop_fields.push(("deviceIdentifier", "desktop-1"));
    let (_, desktop) = h.token(&desktop_fields).await;

    h.env.advance(Duration::days(31));
    let refresh = |token: &Value| {
        let token = token["refresh_token"].as_str().expect("a token").to_owned();
        let h = &h;
        async move {
            h.token(&[
                ("grant_type", "refresh_token"),
                ("refresh_token", token.as_str()),
            ])
            .await
            .0
        }
    };
    assert_eq!(refresh(&phone).await, StatusCode::OK);
    assert_eq!(refresh(&desktop).await, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn the_personal_api_key_signs_in_without_a_refresh_token() {
    let h = Harness::new().await;
    let (token, user) = h.signed_in("ada@example.com").await;

    let (status, body) = h
        .json(
            "POST",
            "/api/accounts/api-key",
            Some(&token),
            Some(json!({"masterPasswordHash": "wrong"})),
        )
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["message"], "Invalid password");
    let (status, body) = h
        .json(
            "POST",
            "/api/accounts/api-key",
            Some(&token),
            Some(json!({"masterPasswordHash": HASH})),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["object"], "apiKey");
    let key = body["apiKey"].as_str().expect("a key").to_owned();
    assert_eq!(key.len(), 30);
    assert!(key.bytes().all(|b| b.is_ascii_alphanumeric()));
    // Asking again gives the same key; rotating gives another.
    let (_, again) = h
        .json(
            "POST",
            "/api/accounts/api-key",
            Some(&token),
            Some(json!({"masterPasswordHash": HASH})),
        )
        .await;
    assert_eq!(again["apiKey"], key.as_str());
    let (_, rotated) = h
        .json(
            "POST",
            "/api/accounts/rotate-api-key",
            Some(&token),
            Some(json!({"masterPasswordHash": HASH})),
        )
        .await;
    assert_ne!(rotated["apiKey"], key.as_str());
    let key = rotated["apiKey"].as_str().expect("a key").to_owned();

    let client_id = format!("user.{user}");
    let fields = |secret: &'static str| {
        vec![
            ("grant_type", "client_credentials"),
            ("client_id", "placeholder"),
            ("client_secret", secret),
            ("scope", "api"),
            ("deviceType", "8"),
            ("deviceIdentifier", "cli-1"),
            ("deviceName", "Amethystora Vault"),
        ]
    };
    let call = |secret: String| {
        let client_id = client_id.clone();
        let h = &h;
        async move {
            let mut f = fields("placeholder");
            f.retain(|(k, _)| !matches!(*k, "client_id" | "client_secret"));
            f.push(("client_id", client_id.as_str()));
            f.push(("client_secret", secret.as_str()));
            h.token(&f).await
        }
    };
    let (status, body) = call(key.clone()).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert!(body.get("refresh_token").is_none(), "no refresh token");
    assert_eq!(body["scope"], "api");
    assert_eq!(body["Key"], USER_KEY);
    assert_eq!(body["expires_in"], 7200);
    assert_eq!(body["token_type"], "Bearer");
    let c = claims(
        body["access_token"].as_str().expect("a token"),
        h.env.time().unix_timestamp(),
    );
    assert_eq!(c.scope, ["api"]);
    assert_eq!(c.devicetype, "Linux");

    let (status, body) = call("not-the-key".to_owned()).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["message"], "Incorrect client_secret");
    let (_, body) = h
        .token(&[
            ("grant_type", "client_credentials"),
            ("client_id", "user.not-a-uuid"),
            ("client_secret", "x"),
            ("scope", "api"),
            ("deviceType", "8"),
            ("deviceIdentifier", "d"),
            ("deviceName", "n"),
        ])
        .await;
    assert_eq!(body["message"], "Invalid client_id");
    let (_, body) = h
        .token(&[
            ("grant_type", "client_credentials"),
            ("client_id", "mobile"),
            ("client_secret", "x"),
            ("scope", "api"),
            ("deviceType", "8"),
            ("deviceIdentifier", "d"),
            ("deviceName", "n"),
        ])
        .await;
    assert_eq!(body["message"], "Malformed client_id");
    let (_, body) = h
        .token(&[
            ("grant_type", "client_credentials"),
            ("client_id", client_id.as_str()),
            ("client_secret", key.as_str()),
            ("scope", "api"),
        ])
        .await;
    assert_eq!(body["message"], "device_identifier cannot be blank");
    let (_, body) = h
        .token(&[
            ("grant_type", "client_credentials"),
            ("client_id", client_id.as_str()),
            ("client_secret", key.as_str()),
            ("scope", "nonsense"),
        ])
        .await;
    assert_eq!(body["message"], "Scope not supported");
}

async fn enrol_totp(h: &Harness, user: kemlock_domain::UserId, secret: &[u8]) {
    let sealed = ServerSeal::new(&common::SERVER_KEY).seal("totp", secret);
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
}

#[tokio::test]
async fn an_authenticator_account_gets_the_second_step_and_can_be_remembered() {
    let h = Harness::new().await;
    let user = h.account("ada@example.com", HASH).await;
    let secret = [5u8; 20];
    enrol_totp(&h, user, &secret).await;

    // No code: the 400 Vaultwarden sends, listing the providers both ways.
    let (status, body) = h
        .token(&Harness::password_fields("ada@example.com", HASH))
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["error"], "invalid_grant");
    assert_eq!(body["error_description"], "Two factor required.");
    assert_eq!(body["TwoFactorProviders"], json!(["0"]));
    assert_eq!(body["TwoFactorProviders2"], json!({"0": null}));
    assert_eq!(
        body["MasterPasswordPolicy"],
        json!({"Object": "masterPasswordPolicy"})
    );

    let code = kemlock_crypto::totp::code_at(
        &secret,
        u64::try_from(h.env.time().unix_timestamp()).expect("a time"),
    );
    let with = |provider: &'static str, token: String, remember: &'static str| {
        let h = &h;
        async move {
            let mut f = Harness::password_fields("ada@example.com", HASH);
            f.push(("twoFactorProvider", provider));
            f.push(("twoFactorToken", token.as_str()));
            f.push(("twoFactorRemember", remember));
            h.token(&f).await
        }
    };
    let (status, body) = with("0", "000000".to_owned(), "0").await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert!(
        body["message"]
            .as_str()
            .expect("a message")
            .starts_with("Invalid TOTP code! Server time: 2026-11-21 12:00:00 UTC IP: "),
        "{body}"
    );
    let (_, body) = with("0", "12ab56".to_owned(), "0").await;
    assert_eq!(body["message"], "TOTP code is not a number");

    let (status, body) = with("0", code, "1").await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let remember = body["TwoFactorToken"]
        .as_str()
        .expect("a remember token")
        .to_owned();

    // The remember token stands in for the code on this device, and only on this device.
    let (status, body) = with("5", remember.clone(), "0").await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert!(body.get("TwoFactorToken").is_none());
    let mut other_device = Harness::password_fields("ada@example.com", HASH);
    other_device.retain(|(k, _)| *k != "deviceIdentifier");
    other_device.push(("deviceIdentifier", "another-device"));
    other_device.push(("twoFactorProvider", "5"));
    other_device.push(("twoFactorToken", remember.as_str()));
    let (status, body) = h.token(&other_device).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["TwoFactorProviders"], json!(["0"]));

    // A recovery code is taken though never offered; this account (enrolled straight in the store)
    // has none, so any is refused, as Vaultwarden words it.
    let (_, body) = with("8", "abcd".to_owned(), "0").await;
    assert_eq!(body["message"], "Two-step token is invalid. Try again.");
    // A provider that isn't enabled gets the challenge again.
    let (_, body) = with("1", "123456".to_owned(), "0").await;
    assert_eq!(body["error"], "invalid_grant");
}

#[tokio::test]
async fn an_authenticator_code_whose_time_step_was_used_is_refused() {
    // Vaultwarden's `validate_totp_code` keeps `last_used` and refuses a step at or before it,
    // with the message of a wrong code.
    let h = Harness::new().await;
    let user = h.account("ada@example.com", HASH).await;
    let secret = [5u8; 20];
    enrol_totp(&h, user, &secret).await;
    let code_now = || {
        kemlock_crypto::totp::code_at(
            &secret,
            u64::try_from(h.env.time().unix_timestamp()).expect("a time"),
        )
    };
    let sign_in = |code: String| {
        let h = &h;
        async move {
            let mut f = Harness::password_fields("ada@example.com", HASH);
            f.push(("twoFactorProvider", "0"));
            f.push(("twoFactorToken", code.as_str()));
            f.push(("twoFactorRemember", "0"));
            h.token(&f).await
        }
    };

    let first = code_now();
    let (status, body) = sign_in(first.clone()).await;
    assert_eq!(status, StatusCode::OK, "{body}");

    // The same code again, and a code of the step before it, are both used up.
    let (status, body) = sign_in(first.clone()).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert!(
        body["message"]
            .as_str()
            .expect("a message")
            .starts_with("Invalid TOTP code! Server time: 2026-11-21 12:00:00 UTC IP: "),
        "{body}"
    );
    let earlier = kemlock_crypto::totp::code_at(
        &secret,
        u64::try_from(h.env.time().unix_timestamp()).expect("a time") - 30,
    );
    let (status, _) = sign_in(earlier).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);

    // A later step is good again.
    h.env.advance(Duration::seconds(30));
    let (status, body) = sign_in(code_now()).await;
    assert_eq!(status, StatusCode::OK, "{body}");
}

#[tokio::test]
async fn the_api_key_skips_the_second_step() {
    let h = Harness::new().await;
    let (token, user) = h.signed_in("ada@example.com").await;
    enrol_totp(&h, user, &[5u8; 20]).await;
    let (_, body) = h
        .json(
            "POST",
            "/api/accounts/api-key",
            Some(&token),
            Some(json!({"masterPasswordHash": HASH})),
        )
        .await;
    let key = body["apiKey"].as_str().expect("a key").to_owned();
    let client_id = format!("user.{user}");
    let (status, body) = h
        .token(&[
            ("grant_type", "client_credentials"),
            ("client_id", client_id.as_str()),
            ("client_secret", key.as_str()),
            ("scope", "api"),
            ("deviceType", "8"),
            ("deviceIdentifier", "cli"),
            ("deviceName", "cli"),
        ])
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let (_, profile) = h
        .json("GET", "/api/accounts/profile", Some(&token), None)
        .await;
    assert_eq!(profile["twoFactorEnabled"], true);
}

#[tokio::test]
async fn send_email_login_says_so_while_email_codes_are_off() {
    // The default server has no mailer: as in Vaultwarden without SMTP, the answer is an error.
    let h = Harness::new().await;
    h.account("ada@example.com", HASH).await;
    let (status, body) = h
        .json(
            "POST",
            "/api/two-factor/send-email-login",
            None,
            Some(json!({"email": "ada@example.com", "masterPasswordHash": HASH, "deviceIdentifier": "d"})),
        )
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["message"], "Email 2FA is disabled");
}

#[tokio::test]
async fn a_new_hash_is_upgraded_to_the_current_rounds_at_sign_in() {
    // Accounts are made with 1,000 rounds; the server's current number is higher.
    let h = Harness::with(|s| s.password_iterations = 2_000).await;
    h.account("ada@example.com", HASH).await;
    let before = {
        let user = h.login("ada@example.com", HASH).await;
        user["access_token"].as_str().expect("a token").to_owned()
    };
    // The upgrade moved the revision date, and the password still works afterwards.
    let (_, date) = h
        .json("GET", "/api/accounts/revision-date", Some(&before), None)
        .await;
    assert!(date.as_i64().expect("a number") > 1_000);
    h.login("ada@example.com", HASH).await;
}

#[tokio::test]
async fn the_known_device_check_tells_a_signed_in_device_from_a_new_one() {
    let h = Harness::new().await;
    h.account("ada@example.com", HASH).await;
    let email_b64 = kemlock_app::b64url::encode(b"ada@example.com");
    let ask = |identifier: &str| {
        let identifier = identifier.to_owned();
        let email_b64 = email_b64.clone();
        let h = &h;
        async move {
            let (_, _, bytes) = h
                .send(
                    "GET",
                    "/api/devices/knowndevice",
                    &[
                        ("x-request-email", email_b64.as_str()),
                        ("x-device-identifier", identifier.as_str()),
                    ],
                    Body::empty(),
                )
                .await;
            serde_json::from_slice::<Value>(&bytes).expect("JSON")
        }
    };
    assert_eq!(
        ask("6a3c5f2e-9d1b-4c7e-8a40-0f9e7d6c5b4a").await,
        json!(false)
    );
    h.login("ada@example.com", HASH).await;
    assert_eq!(
        ask("6a3c5f2e-9d1b-4c7e-8a40-0f9e7d6c5b4a").await,
        json!(true)
    );
    assert_eq!(ask("another").await, json!(false));
}

#[tokio::test]
async fn a_user_an_admin_disabled_gets_neither_a_password_sign_in_nor_a_refresh() {
    let h = Harness::new().await;
    let user = h.account("ada@example.com", HASH).await;
    let first = h.login("ada@example.com", HASH).await;
    let refresh_token = first["refresh_token"].as_str().expect("a token").to_owned();

    AdminUserRepo::set_disabled(&h.store, user, Some((h.env.time(), user)))
        .await
        .expect("disables");

    let (status, body) = h
        .token(&Harness::password_fields("ada@example.com", HASH))
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["message"], DISABLED);
    assert!(body.get("access_token").is_none());
    let refresh = |token: String| {
        let h = &h;
        async move {
            h.token(&[
                ("grant_type", "refresh_token"),
                ("client_id", "mobile"),
                ("refresh_token", token.as_str()),
            ])
            .await
        }
    };
    let (status, body) = refresh(refresh_token.clone()).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["message"], DISABLED);
    assert!(body.get("access_token").is_none());

    // Enabling the account lets the password in again; the refresh token went with the session.
    AdminUserRepo::set_disabled(&h.store, user, None)
        .await
        .expect("enables");
    h.login("ada@example.com", HASH).await;
    let (status, body) = refresh(refresh_token).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body, json!({"error": "invalid_grant"}));
}

#[tokio::test]
async fn a_disabled_user_is_told_so_only_after_the_password_is_proved() {
    // Vaultwarden's `_password_login` checks the password first and `enabled` after it.
    let h = Harness::new().await;
    let user = h.account("ada@example.com", HASH).await;
    AdminUserRepo::set_disabled(&h.store, user, Some((h.env.time(), user)))
        .await
        .expect("disables");

    let (status, body) = h
        .token(&Harness::password_fields("ada@example.com", "wrong"))
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(
        body["message"], "Username or password is incorrect. Try again",
        "a wrong password is no different for a disabled account"
    );
    let (_, unknown) = h
        .token(&Harness::password_fields("nobody@example.com", "wrong"))
        .await;
    assert_eq!(body, unknown);

    let (status, body) = h
        .token(&Harness::password_fields("ada@example.com", HASH))
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["message"], DISABLED);
}

#[tokio::test]
async fn a_disabled_users_api_key_login_says_so_before_the_secret_is_looked_at() {
    // Vaultwarden's `user_api_key_login` checks `enabled` before the secret, so a wrong secret
    // hears it too.
    let h = Harness::new().await;
    let (token, user) = h.signed_in("ada@example.com").await;
    let (_, key) = h
        .json(
            "POST",
            "/api/accounts/api-key",
            Some(&token),
            Some(json!({"masterPasswordHash": HASH})),
        )
        .await;
    let key = key["apiKey"].as_str().expect("a key").to_owned();
    let client_id = format!("user.{user}");
    let call = |secret: String| {
        let client_id = client_id.clone();
        let h = &h;
        async move {
            h.token(&[
                ("grant_type", "client_credentials"),
                ("client_id", client_id.as_str()),
                ("client_secret", secret.as_str()),
                ("scope", "api"),
                ("deviceType", "8"),
                ("deviceIdentifier", "cli-1"),
                ("deviceName", "Amethystora Vault"),
            ])
            .await
        }
    };
    AdminUserRepo::set_disabled(&h.store, user, Some((h.env.time(), user)))
        .await
        .expect("disables");

    let (status, body) = call("wrong".to_owned()).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(
        body["message"],
        "This user has been disabled (API key login)"
    );
    let (status, body) = call(key.clone()).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(
        body["message"],
        "This user has been disabled (API key login)"
    );
    assert!(body.get("access_token").is_none());

    AdminUserRepo::set_disabled(&h.store, user, None)
        .await
        .expect("enables");
    let (status, body) = call(key).await;
    assert_eq!(status, StatusCode::OK, "{body}");
}

// ---------------------------------------------------------------------------------------------
// The sign-in log and the deleted-account grace period.

/// The fields of a password sign-in with an authenticator code.
fn with_code(token: &str) -> Vec<(&str, &str)> {
    let mut f = Harness::password_fields("ada@example.com", HASH);
    f.push(("twoFactorProvider", "0"));
    f.push(("twoFactorToken", token));
    f
}

/// Every row of the sign-in log as `method:outcome`, sorted.
async fn logged(h: &Harness) -> Vec<String> {
    let from = time::macros::datetime!(2000-01-01 0:00 UTC);
    let to = time::macros::datetime!(2100-01-01 0:00 UTC);
    let mut rows: Vec<String> = PrivacyLog::sign_ins_between(&h.store, from, to)
        .await
        .expect("the log reads")
        .iter()
        .map(|r| format!("{}:{}", r.method, r.outcome.as_str()))
        .collect();
    rows.sort();
    rows
}

#[tokio::test]
async fn the_token_endpoint_logs_each_sign_in_attempt_and_its_second_step() {
    let h = Harness::new().await;
    let user = h.account("ada@example.com", HASH).await;
    let secret = [5u8; 20];
    enrol_totp(&h, user, &secret).await;

    // A wrong password names no account in the log.
    let (status, _) = h
        .token(&Harness::password_fields("ada@example.com", "wrong"))
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(logged(&h).await, ["password:failure"]);
    assert!(
        PrivacyLog::sign_ins_of(&h.store, user)
            .await
            .expect("the log reads")
            .is_empty()
    );

    // The right password with no code: the second step is asked for, and the password was right.
    let (status, body) = h
        .token(&Harness::password_fields("ada@example.com", HASH))
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["error_description"], "Two factor required.");
    // A wrong code, then the right one.
    let code = kemlock_crypto::totp::code_at(
        &secret,
        u64::try_from(h.env.time().unix_timestamp()).expect("a time"),
    );
    assert_eq!(
        h.token(&with_code("000000")).await.0,
        StatusCode::BAD_REQUEST
    );
    let (status, signed) = h.token(&with_code(&code)).await;
    assert_eq!(status, StatusCode::OK, "{signed}");

    assert_eq!(
        logged(&h).await,
        [
            "password:failure",
            "password:success",
            "two-factor:failure",
            "two-factor:success"
        ]
    );
    let hers = PrivacyLog::sign_ins_of(&h.store, user)
        .await
        .expect("the log reads");
    assert_eq!(hers.len(), 3, "the password prompt and both codes name her");
    assert!(hers.iter().all(|r| r.device.is_some()));

    // A refresh is logged too, and so is a refused one.
    let refresh = signed["refresh_token"]
        .as_str()
        .expect("a token")
        .to_owned();
    let refreshed = h
        .token(&[
            ("grant_type", "refresh_token"),
            ("client_id", "mobile"),
            ("refresh_token", refresh.as_str()),
        ])
        .await;
    assert_eq!(refreshed.0, StatusCode::OK);
    let refused = h
        .token(&[
            ("grant_type", "refresh_token"),
            ("client_id", "mobile"),
            ("refresh_token", "not-a-token-at-all"),
        ])
        .await;
    assert_eq!(refused.0, StatusCode::BAD_REQUEST);
    let rows = logged(&h).await;
    assert_eq!(
        rows.iter().filter(|r| r.starts_with("refresh:")).count(),
        2,
        "{rows:?}"
    );
}

#[tokio::test]
async fn a_request_that_never_reaches_a_credential_check_is_not_an_attempt() {
    let h = Harness::new().await;
    let (status, _) = h
        .token(&[("grant_type", "password"), ("client_id", "mobile")])
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    let mut fields = Harness::password_fields("ada@example.com", HASH);
    fields.retain(|(k, _)| *k != "scope");
    fields.push(("scope", "something-else"));
    assert_eq!(h.token(&fields).await.0, StatusCode::BAD_REQUEST);
    assert!(logged(&h).await.is_empty());
}

#[tokio::test]
async fn the_address_the_server_settled_is_logged_cut_to_its_24() {
    use axum::http::Request;
    use tower::ServiceExt;

    let h = Harness::new().await;
    h.account("ada@example.com", HASH).await;
    let body = {
        let mut form = url::form_urlencoded::Serializer::new(String::new());
        for (k, v) in Harness::password_fields("ada@example.com", HASH) {
            form.append_pair(k, v);
        }
        form.finish()
    };
    let mut request = Request::builder()
        .method("POST")
        .uri("/identity/connect/token")
        .header("content-type", "application/x-www-form-urlencoded")
        .body(Body::from(body))
        .expect("a request");
    request
        .extensions_mut()
        .insert(ClientAddr("198.51.100.77".parse().expect("an address")));
    let response = h
        .router
        .clone()
        .oneshot(request)
        .await
        .expect("the router answers");
    assert_eq!(response.status(), StatusCode::OK);

    let rows = PrivacyLog::sign_ins_between(
        &h.store,
        time::macros::datetime!(2000-01-01 0:00 UTC),
        time::macros::datetime!(2100-01-01 0:00 UTC),
    )
    .await
    .expect("the log reads");
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].ip.as_deref(), Some("198.51.100.0/24"));
}

#[tokio::test]
async fn an_account_whose_deletion_is_pending_gets_no_token_by_any_grant() {
    let h = Harness::new().await;
    let (token, user) = h.signed_in("ada@example.com").await;
    let first = h.login("ada@example.com", HASH).await;
    let refresh_token = first["refresh_token"].as_str().expect("a token").to_owned();
    let (_, key) = h
        .json(
            "POST",
            "/api/accounts/api-key",
            Some(&token),
            Some(json!({"masterPasswordHash": HASH})),
        )
        .await;
    let key = key["apiKey"].as_str().expect("a key").to_owned();
    let now = h.env.time();
    AccountEraser::schedule_erasure(&h.store, user, now, now + Duration::days(7))
        .await
        .expect("scheduled");

    // A wrong password is told nothing about it.
    let (_, body) = h
        .token(&Harness::password_fields("ada@example.com", "wrong"))
        .await;
    assert_eq!(body["message"], BAD_LOGIN);
    let (status, body) = h
        .token(&Harness::password_fields("ada@example.com", HASH))
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["message"], BEING_DELETED);
    assert!(body.get("access_token").is_none());
    let (status, body) = h
        .token(&[
            ("grant_type", "refresh_token"),
            ("client_id", "mobile"),
            ("refresh_token", refresh_token.as_str()),
        ])
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["message"], BEING_DELETED);
    let client_id = format!("user.{user}");
    let (status, body) = h
        .token(&[
            ("grant_type", "client_credentials"),
            ("client_id", client_id.as_str()),
            ("client_secret", key.as_str()),
            ("scope", "api"),
            ("deviceType", "8"),
            ("deviceIdentifier", "cli-1"),
            ("deviceName", "Amethystora Vault"),
        ])
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["message"], BEING_DELETED);

    // Cancelling the schedule (an admin's act) lets the password in again.
    AccountEraser::cancel_erasure(&h.store, user)
        .await
        .expect("cancelled");
    h.login("ada@example.com", HASH).await;
}

#[tokio::test]
async fn a_refresh_after_the_security_stamp_moved_ends_the_sign_in() {
    // A password change, a key replacement or an admin reset gives the account a new stamp; the
    // Bitwarden app's next refresh must fail, and so must every later token of that sign-in.
    let h = Harness::new().await;
    let user = h.account("ada@example.com", HASH).await;
    let first = h.login("ada@example.com", HASH).await;
    let r0 = first["refresh_token"].as_str().expect("a token").to_owned();
    let refresh = |token: String| {
        let h = &h;
        async move {
            h.token(&[
                ("grant_type", "refresh_token"),
                ("client_id", "mobile"),
                ("refresh_token", token.as_str()),
            ])
            .await
        }
    };
    // Before the change a refresh works, and hands on a token of the same sign-in.
    let (status, second) = refresh(r0).await;
    assert_eq!(status, StatusCode::OK, "{second}");
    let r1 = second["refresh_token"]
        .as_str()
        .expect("a token")
        .to_owned();

    let mut account = UserRepo::by_id(&h.store, user)
        .await
        .expect("reads")
        .expect("the account");
    account.security_stamp = uuid::Uuid::new_v4();
    UserRepo::update(&h.store, &account).await.expect("updates");

    let (status, body) = refresh(r1.clone()).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body, json!({"error": "invalid_grant"}));
    assert!(body.get("access_token").is_none());
    // The sign-in's family is gone: the token does not come back to life.
    let (status, body) = refresh(r1).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body, json!({"error": "invalid_grant"}));

    // A fresh sign-in after the change gets tokens bound to the new stamp.
    let again = h.login("ada@example.com", HASH).await;
    let (status, body) =
        refresh(again["refresh_token"].as_str().expect("a token").to_owned()).await;
    assert_eq!(status, StatusCode::OK, "{body}");
}

#[tokio::test]
async fn a_remember_token_ends_when_a_method_is_turned_off_or_on_again() {
    // Vaultwarden clears the remembered devices when a method goes; the token is bound to the
    // account's two-step version instead of being a stateless pass.
    let h = Harness::new().await;
    let user = h.account("ada@example.com", HASH).await;
    let secret = [5u8; 20];
    enrol_totp(&h, user, &secret).await;
    let sign_in = |provider: &'static str, token: String, remember: &'static str| {
        let h = &h;
        async move {
            let mut f = Harness::password_fields("ada@example.com", HASH);
            f.push(("twoFactorProvider", provider));
            f.push(("twoFactorToken", token.as_str()));
            f.push(("twoFactorRemember", remember));
            h.token(&f).await
        }
    };
    let code_now = || {
        kemlock_crypto::totp::code_at(
            &secret,
            u64::try_from(h.env.time().unix_timestamp()).expect("a time"),
        )
    };
    let (status, body) = sign_in("0", code_now(), "1").await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let remember = body["TwoFactorToken"]
        .as_str()
        .expect("a remember token")
        .to_owned();
    let (status, _) = sign_in("5", remember.clone(), "0").await;
    assert_eq!(status, StatusCode::OK, "the token works before any change");

    // A method's stored state changing (the account is enrolled the same again) is not a change
    // to its methods, so the token stays good.
    enrol_totp(&h, user, &secret).await;
    let (status, _) = sign_in("5", remember.clone(), "0").await;
    assert_eq!(status, StatusCode::OK);

    // Turning the method off, even to turn it on again at once, ends every remembered device.
    TwoFactorRepo::remove(&h.store, user, TwoFactorMethod::Totp)
        .await
        .expect("removed");
    enrol_totp(&h, user, &secret).await;
    let (status, body) = sign_in("5", remember.clone(), "0").await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["TwoFactorProviders"], json!(["0"]));
    assert!(body.get("access_token").is_none());

    // A new one, asked for after the change, is good until the next.
    h.env.advance(Duration::seconds(60));
    let (status, body) = sign_in("0", code_now(), "1").await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let fresh = body["TwoFactorToken"]
        .as_str()
        .expect("a remember token")
        .to_owned();
    let (status, _) = sign_in("5", fresh, "0").await;
    assert_eq!(status, StatusCode::OK);
}

#[tokio::test]
async fn password_and_api_key_sign_ins_are_rate_limited_per_address_as_vaultwarden_does() {
    // LOGIN_RATELIMIT_MAX_BURST tries at once, then one more every LOGIN_RATELIMIT_SECONDS.
    let h = Harness::with(|s| {
        s.login_ratelimit_max_burst = 3;
        s.login_ratelimit_seconds = 60;
    })
    .await;
    h.account("ada@example.com", HASH).await;

    // Right or wrong, every password try that reaches the credential check is one of the three;
    // a request that is refused earlier (a blank field, a wrong scope) is not.
    let (status, body) = h
        .token(&Harness::password_fields("ada@example.com", "not-the-hash"))
        .await;
    assert_eq!(
        (status, &body["message"]),
        (StatusCode::BAD_REQUEST, &json!(BAD_LOGIN))
    );
    let mut wrong_scope = Harness::password_fields("ada@example.com", HASH);
    wrong_scope.retain(|(k, _)| *k != "scope");
    wrong_scope.push(("scope", "api"));
    let (_, body) = h.token(&wrong_scope).await;
    assert_eq!(body["message"], "Scope (api) not supported");
    let (status, _) = h
        .token(&Harness::password_fields("nobody@example.com", HASH))
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    let (status, _) = h
        .token(&Harness::password_fields("ada@example.com", HASH))
        .await;
    assert_eq!(status, StatusCode::OK, "the third try still goes through");

    // The fourth is refused with Vaultwarden's 429 and its error shape, even with the right
    // password, and so is an API key sign-in from the same address.
    let (status, body) = h
        .token(&Harness::password_fields("ada@example.com", HASH))
        .await;
    assert_eq!(status, StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(body["message"], "Too many login requests");
    assert_eq!(body["errorModel"]["message"], "Too many login requests");
    assert_eq!(body["validationErrors"][""][0], "Too many login requests");
    let (status, body) = h
        .token(&[
            ("grant_type", "client_credentials"),
            ("client_id", "user.00000000-0000-0000-0000-000000000000"),
            ("client_secret", "secret"),
            ("scope", "api"),
            ("deviceType", "8"),
            ("deviceIdentifier", "cli"),
            ("deviceName", "cli"),
        ])
        .await;
    assert_eq!(status, StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(body["message"], "Too many login requests");

    // A request that is not a sign-in try yet still says what is missing.
    let mut blank = Harness::password_fields("ada@example.com", HASH);
    blank.retain(|(k, _)| *k != "client_id");
    let (status, body) = h.token(&blank).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["message"], "client_id cannot be blank");

    // A minute gives one try back.
    h.env.advance(Duration::seconds(60));
    let (status, _) = h
        .token(&Harness::password_fields("ada@example.com", HASH))
        .await;
    assert_eq!(status, StatusCode::OK);
    let (status, _) = h
        .token(&Harness::password_fields("ada@example.com", HASH))
        .await;
    assert_eq!(status, StatusCode::TOO_MANY_REQUESTS);
}

#[tokio::test]
async fn a_request_with_no_sign_in_may_not_send_more_than_a_few_kib() {
    let h = Harness::new().await;
    let (token, _) = h.signed_in("ada@example.com").await;
    let big = "a".repeat(40 * 1024);
    let body = format!("{{\"email\":\"{big}\"}}");
    for uri in [
        "/identity/connect/token",
        "/identity/accounts/prelogin",
        "/identity/accounts/prelogin/password",
        "/identity/accounts/register/send-verification-email",
        "/identity/accounts/register/verification-email-clicked",
        "/identity/accounts/register/finish",
        "/api/two-factor/send-email-login",
    ] {
        let (status, _, _) = h
            .send(
                "POST",
                uri,
                &[("content-type", "application/json")],
                Body::from(body.clone()),
            )
            .await;
        assert_eq!(status, StatusCode::PAYLOAD_TOO_LARGE, "{uri}");
    }
    // A signed-in route reads it, whatever it then makes of it.
    let bearer = format!("Bearer {token}");
    let (status, _, _) = h
        .send(
            "POST",
            "/api/folders",
            &[
                ("content-type", "application/json"),
                ("authorization", bearer.as_str()),
            ],
            Body::from(format!("{{\"name\":\"{big}\"}}")),
        )
        .await;
    assert_ne!(status, StatusCode::PAYLOAD_TOO_LARGE);
}

#[tokio::test]
async fn prelogin_is_limited_per_address() {
    let h = Harness::with(|s| s.unauthenticated_ratelimit_max_burst = 3).await;
    h.account("ada@example.com", HASH).await;
    let ask = |path: &'static str| {
        let h = &h;
        async move {
            h.json("POST", path, None, Some(json!({"email": "ada@example.com"})))
                .await
        }
    };
    for _ in 0..3 {
        let (status, _) = ask("/identity/accounts/prelogin").await;
        assert_eq!(status, StatusCode::OK);
    }
    // Both routes share the address's budget.
    let (status, body) = ask("/identity/accounts/prelogin/password").await;
    assert_eq!(status, StatusCode::TOO_MANY_REQUESTS, "{body}");
    // Ten seconds give one back.
    h.env.advance(Duration::seconds(10));
    let (status, _) = ask("/identity/accounts/prelogin").await;
    assert_eq!(status, StatusCode::OK);
}

#[tokio::test]
async fn wrong_passwords_are_counted_per_account_from_any_address() {
    // The console's limit is 2 here, so an account slows after two wrong passwords in a window
    // and refuses everything after twenty; the slowdown is switched off so the test doesn't wait.
    let live = kemlock_app::admin::Live::new(true);
    live.set_password_limit(2);
    let shared = live.clone();
    let h = Harness::with(move |s| {
        s.live = Some(shared);
        s.password_slowdown_secs = 0;
    })
    .await;
    h.account("ada@example.com", HASH).await;
    let wrong = || async {
        h.token(&Harness::password_fields("ada@example.com", "not-the-hash"))
            .await
    };
    // Tries from different addresses all count against the account.
    for _ in 0..20 {
        let (status, body) = wrong().await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
        assert_eq!(body["message"], BAD_LOGIN);
    }
    // The account is locked: even the right password is refused until the window ends.
    let (status, body) = h
        .token(&Harness::password_fields("ada@example.com", HASH))
        .await;
    assert_eq!(status, StatusCode::TOO_MANY_REQUESTS, "{body}");
    assert_eq!(body["message"], "Too many login requests");
    h.env.advance(Duration::minutes(16));
    let (status, body) = h
        .token(&Harness::password_fields("ada@example.com", HASH))
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");

    // Past the limit, a right password still gets in and clears the count.
    for _ in 0..5 {
        wrong().await;
    }
    let (status, body) = h
        .token(&Harness::password_fields("ada@example.com", HASH))
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    for _ in 0..20 {
        let (status, _) = wrong().await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "the count started again");
    }
}

#[tokio::test]
async fn a_rotated_api_key_rejects_the_old_secret_and_takes_the_new_one() {
    let h = Harness::new().await;
    let (token, user) = h.signed_in("ada@example.com").await;
    let ask = |route: &'static str| {
        let h = &h;
        let token = token.clone();
        async move {
            let (status, body) = h
                .json(
                    "POST",
                    route,
                    Some(&token),
                    Some(json!({"masterPasswordHash": HASH})),
                )
                .await;
            assert_eq!(status, StatusCode::OK, "{body}");
            body["apiKey"].as_str().expect("a key").to_owned()
        }
    };
    let old = ask("/api/accounts/api-key").await;
    let new = ask("/api/accounts/rotate-api-key").await;
    assert_ne!(old, new);

    let client_id = format!("user.{user}");
    let sign_in = |secret: String| {
        let h = &h;
        let client_id = client_id.clone();
        async move {
            h.token(&[
                ("grant_type", "client_credentials"),
                ("client_id", client_id.as_str()),
                ("client_secret", secret.as_str()),
                ("scope", "api"),
                ("deviceType", "8"),
                ("deviceIdentifier", "cli-rotated"),
                ("deviceName", "CLI"),
            ])
            .await
        }
    };
    let (status, body) = sign_in(old).await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
    assert_eq!(body["message"], "Incorrect client_secret");
    let (status, body) = sign_in(new).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["scope"], "api");
}

#[tokio::test]
async fn an_account_stops_taking_second_step_codes_after_five_tries_then_waits_longer_each_time() {
    let h = Harness::new().await;
    let user = h.account("ada@example.com", HASH).await;
    let secret = [5u8; 20];
    enrol_totp(&h, user, &secret).await;
    let code = |h: &Harness| {
        kemlock_crypto::totp::code_at(
            &secret,
            u64::try_from(h.env.time().unix_timestamp()).expect("a time"),
        )
    };
    let try_code = |token: String| {
        let h = &h;
        async move {
            let mut f = Harness::password_fields("ada@example.com", HASH);
            f.push(("twoFactorProvider", "0"));
            f.push(("twoFactorToken", token.as_str()));
            h.token(&f).await
        }
    };

    // The count is the Kemlock API's: five tries a window from any address.
    for _ in 0..5 {
        let (status, body) = try_code("000000".to_owned()).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
    }
    // The sixth is refused, and so is the right code: the account waits one second.
    let (status, body) = try_code(code(&h)).await;
    assert_eq!(status, StatusCode::TOO_MANY_REQUESTS, "{body}");
    assert_eq!(body["message"], "Too many login requests");

    // A try after the wait goes on, and a wrong one doubles the next wait.
    h.env.advance(Duration::seconds(1));
    let (status, body) = try_code("000000".to_owned()).await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
    h.env.advance(Duration::seconds(1));
    let (status, _) = try_code(code(&h)).await;
    assert_eq!(status, StatusCode::TOO_MANY_REQUESTS, "two seconds are owed now");
    h.env.advance(Duration::seconds(2));

    // The right code, once the wait is over, works and clears the count.
    let (status, body) = try_code(code(&h)).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    for _ in 0..5 {
        let (status, _) = try_code("000000".to_owned()).await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
    }
}

/// The count is one per account across both APIs: the Kemlock API's second step reserves from the
/// same row, so wrong codes sent to the Bitwarden token endpoint use up what the Kemlock API allows.
#[tokio::test]
async fn the_bitwarden_second_step_uses_the_count_of_the_kemlock_second_step() {
    use kemlock_app::second_step_guard::{Reservation, SecondStepGuard};
    let h = Harness::new().await;
    let user = h.account("ada@example.com", HASH).await;
    let secret = [5u8; 20];
    enrol_totp(&h, user, &secret).await;
    let now = h.env.time().unix_timestamp();
    // Four tries the Kemlock API made already.
    for _ in 0..4 {
        assert_eq!(
            SecondStepGuard::reserve_second_step(&h.store, user, now, 5, 900)
                .await
                .expect("a reservation"),
            Reservation::Granted
        );
    }
    let mut f = Harness::password_fields("ada@example.com", HASH);
    f.push(("twoFactorProvider", "0"));
    f.push(("twoFactorToken", "000000"));
    // One more try reaches the limit, and the next is told to wait, on this API too.
    let (status, body) = h.token(&f).await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
    let (status, body) = h.token(&f).await;
    assert_eq!(status, StatusCode::TOO_MANY_REQUESTS, "{body}");
}

#[tokio::test]
async fn a_request_for_an_emailed_code_is_limited_by_address_like_a_sign_in() {
    let h = Harness::with(|s| s.login_ratelimit_max_burst = 2).await;
    h.account("ada@example.com", HASH).await;
    let ask = || async {
        h.json(
            "POST",
            "/api/two-factor/send-email-login",
            None,
            Some(json!({"email": "ada@example.com", "masterPasswordHash": HASH})),
        )
        .await
    };
    for _ in 0..2 {
        let (status, body) = ask().await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(body["message"], "Email 2FA is disabled");
    }
    let (status, body) = ask().await;
    assert_eq!(status, StatusCode::TOO_MANY_REQUESTS, "{body}");
    assert_eq!(body["message"], "Too many login requests");
}

/// `POST /api/accounts/api-key`: the key the account is shown.
async fn shown_api_key(h: &Harness, token: &str) -> String {
    let (status, body) = h
        .json(
            "POST",
            "/api/accounts/api-key",
            Some(token),
            Some(json!({"masterPasswordHash": HASH})),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    body["apiKey"].as_str().expect("a key").to_owned()
}

#[tokio::test]
async fn the_personal_api_key_is_sealed_at_rest_and_still_signs_in_and_shows() {
    let h = Harness::new().await;
    let (token, user) = h.signed_in("ada@example.com").await;
    let key = shown_api_key(&h, &token).await;
    assert_eq!(key.len(), 30);

    // What the database holds is not the key.
    let dir = tempfile::tempdir().expect("a folder");
    h.store.snapshot_to(dir.path()).await.expect("a snapshot");
    let rows = std::fs::read_to_string(dir.path().join("bw_accounts.jsonl")).expect("the table");
    assert!(!rows.contains(&key), "{rows}");
    assert!(rows.contains("sealed:"));

    // The owner is shown the same key again, and it signs in.
    assert_eq!(shown_api_key(&h, &token).await, key);
    let client_id = format!("user.{user}");
    let (status, body) = h
        .token(&[
            ("grant_type", "client_credentials"),
            ("client_id", client_id.as_str()),
            ("client_secret", key.as_str()),
            ("scope", "api"),
            ("deviceType", "8"),
            ("deviceIdentifier", "cli-1"),
            ("deviceName", "Amethystora Vault"),
        ])
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    // A key that is not the account's is refused.
    let (_, body) = h
        .token(&[
            ("grant_type", "client_credentials"),
            ("client_id", client_id.as_str()),
            ("client_secret", "not-the-key"),
            ("scope", "api"),
            ("deviceType", "8"),
            ("deviceIdentifier", "cli-1"),
            ("deviceName", "Amethystora Vault"),
        ])
        .await;
    assert_eq!(body["message"], "Incorrect client_secret");
}
