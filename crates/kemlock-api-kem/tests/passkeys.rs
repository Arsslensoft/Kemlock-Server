//! The passkey and security key routes through the router, in-process: the real WebAuthn relying
//! party (`kemlock-identity`) against a software authenticator, over the fakes of the other ports,
//! with a real DPoP client.

mod common;
#[path = "../../kemlock-app/tests/passkey_fakes/mod.rs"]
mod passkey_fakes;
#[path = "../../kemlock-app/tests/sso_fakes/mod.rs"]
mod sso_fakes;

use axum::Router;
use axum::http::StatusCode;
use common::{
    App, Client, Reply, Req, Session, b64, register_and_sign_in, sign_in_reply, test_device,
    totp_now,
};
use kemlock_api_kem::testing::DpopSigner;
use kemlock_api_kem::{PasskeyRuntime, PasskeysApiDoc, passkeys_router};
use kemlock_app::register::FIRST_KEY_VERSION;
use kemlock_app::sso::{SpaceMembership, SpaceRole};
use kemlock_domain::{SpaceId, UserId};
use kemlock_identity::WebAuthnRp;
use kemlock_identity::authenticator::SoftwareAuthenticator;
use passkey_fakes::FakePasskeys;
use serde_json::{Value, json};
use sso_fakes::FakeMembership;
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use time::Duration;
use utoipa::OpenApi;

const WRAP: [u8; 92] = [0x5a; 92];

struct Pk {
    app: App,
    router: Router,
    membership: FakeMembership,
    calls: AtomicUsize,
}

fn pk() -> Pk {
    let app = App::new(true);
    let membership = FakeMembership::default();
    let webauthn = WebAuthnRp::new(common::DOMAIN).expect("a relying party");
    let runtime = PasskeyRuntime::new(
        FakePasskeys::default(),
        Arc::new(webauthn),
        membership.clone(),
    );
    let router = app
        .router
        .clone()
        .merge(passkeys_router(app.api.clone(), runtime));
    Pk {
        app,
        router,
        membership,
        calls: AtomicUsize::new(0),
    }
}

fn authenticator() -> SoftwareAuthenticator {
    SoftwareAuthenticator::new("kemlock.test", common::DOMAIN)
}

fn device_body() -> Value {
    json!({"name": "Pixel", "kind": "kemlock-android"})
}

impl Pk {
    /// A device with its own DPoP key, talking to the merged router.
    fn device(&self) -> Client {
        Client::new(
            self.router.clone(),
            self.app.clock.clone(),
            DpopSigner::es256(),
        )
    }

    /// A signed-in device: the account registered, then signed in with the password.
    async fn signed_in(&self, email: &str) -> (Client, Session) {
        let client = self.device();
        let session = register_and_sign_in(&client, email).await;
        (client, session)
    }

    /// One request from an address of its own, so the per-address limits of one test don't add up.
    async fn call(
        &self,
        client: &Client,
        method: &str,
        uri: &str,
        token: Option<&str>,
        body: Option<Value>,
    ) -> Reply {
        let n = self.calls.fetch_add(1, Ordering::Relaxed);
        let peer = SocketAddr::from((
            [
                10,
                1,
                u8::try_from(n / 250).unwrap_or(0),
                u8::try_from(n % 250).unwrap_or(0) + 1,
            ],
            40_000,
        ));
        client
            .send(
                method,
                uri,
                Req {
                    access_token: token,
                    body,
                    peer: Some(peer),
                    ..Req::default()
                },
            )
            .await
    }

    /// `auth/two-factor/webauthn/options` for a sign-in's second step.
    async fn key_options(&self, client: &Client, body: Value) -> Reply {
        self.call(
            client,
            "POST",
            "/kem/v1/auth/two-factor/webauthn/options",
            None,
            Some(body),
        )
        .await
    }

    async fn passkeys(&self, client: &Client, session: &Session) -> Value {
        let reply = self
            .call(
                client,
                "GET",
                "/kem/v1/account/passkeys",
                Some(&session.access_token),
                None,
            )
            .await;
        assert_eq!(reply.status, StatusCode::OK, "{:?}", reply.json());
        reply.json()["passkeys"].clone()
    }

    /// Registers a passkey, optionally with its PRF copy of the root key. Returns its id and the
    /// authenticator that made it.
    async fn new_passkey(
        &self,
        client: &Client,
        session: &Session,
        name: &str,
        prf: Option<Value>,
    ) -> (String, SoftwareAuthenticator) {
        let started = self
            .call(
                client,
                "POST",
                "/kem/v1/account/passkeys/options",
                Some(&session.access_token),
                None,
            )
            .await;
        assert_eq!(started.status, StatusCode::OK, "{:?}", started.json());
        let options = started.json()["options"].clone();
        let mut authenticator = authenticator();
        let credential = authenticator.create(&options);
        let mut body = json!({"name": name, "credential": credential});
        if let Some(prf) = prf {
            body["prf"] = prf;
        }
        let reply = self
            .call(
                client,
                "POST",
                "/kem/v1/account/passkeys",
                Some(&session.access_token),
                Some(body),
            )
            .await;
        assert_eq!(reply.status, StatusCode::CREATED, "{:?}", reply.json());
        let id = reply.json()["id"].as_str().expect("an id").to_owned();
        (id, authenticator)
    }

    /// The body of `passkey/verify` for a fresh challenge: options asked for, and answered.
    async fn passkey_answer(
        &self,
        client: &Client,
        authenticator: &mut SoftwareAuthenticator,
    ) -> Value {
        let asked = self
            .call(client, "POST", "/kem/v1/auth/passkey/options", None, None)
            .await;
        assert_eq!(asked.status, StatusCode::OK, "{:?}", asked.json());
        let asked = asked.json();
        let credential = authenticator.get(&asked["options"]);
        json!({
            "challenge": asked["challenge"],
            "credential": credential,
            "device": device_body(),
        })
    }

    async fn verify(&self, client: &Client, body: Value) -> Reply {
        self.call(
            client,
            "POST",
            "/kem/v1/auth/passkey/verify",
            None,
            Some(body),
        )
        .await
    }

    /// Asks and answers: the reply to `passkey/verify`.
    async fn passkey_sign_in(
        &self,
        client: &Client,
        authenticator: &mut SoftwareAuthenticator,
    ) -> Reply {
        let body = self.passkey_answer(client, authenticator).await;
        self.verify(client, body).await
    }
}

// ---------------------------------------------------------------------------------------------
// Signing in with a passkey

#[tokio::test]
async fn a_passkey_with_prf_signs_in_a_new_device_and_hands_back_its_copy() {
    let pk = pk();
    let (d1, s1) = pk.signed_in("sam@example.org").await;
    let prf = json!({"wrappedKey": b64(&WRAP), "keyVersion": FIRST_KEY_VERSION});
    let (id, mut authenticator) = pk.new_passkey(&d1, &s1, "Laptop", Some(prf)).await;

    let listed = pk.passkeys(&d1, &s1).await;
    assert_eq!(listed[0]["id"], id.as_str());
    assert_eq!(listed[0]["name"], "Laptop");
    assert_eq!(listed[0]["prf"], true);
    assert_eq!(listed[0]["prfKeyVersion"], FIRST_KEY_VERSION);
    assert!(listed[0]["lastUsedAt"].is_null());

    // A device that has no session asks for options, which name nothing about an account.
    let d2 = pk.device();
    let asked = pk
        .call(&d2, "POST", "/kem/v1/auth/passkey/options", None, None)
        .await;
    assert_eq!(asked.status, StatusCode::OK, "{:?}", asked.json());
    assert_eq!(asked.json()["options"]["allowCredentials"], json!([]));
    assert_eq!(asked.json()["options"]["userVerification"], "required");
    assert_eq!(asked.json()["options"]["rpId"], "kemlock.test");

    let signed = pk.passkey_sign_in(&d2, &mut authenticator).await;
    assert_eq!(signed.status, StatusCode::OK, "{:?}", signed.json());
    let json = signed.json();
    assert_eq!(json["tokens"]["tokenType"], "DPoP");
    assert_eq!(json["passkeyId"], id.as_str());
    assert_eq!(json["prf"]["wrappedKey"], b64(&WRAP));
    assert_eq!(json["prf"]["keyVersion"], FIRST_KEY_VERSION);
    assert_eq!(json["keyVersion"], FIRST_KEY_VERSION);

    // The tokens are good, and the passkey records its use.
    let s2 = Session::from_tokens(&json["tokens"]);
    assert_eq!(s2.user_id, s1.user_id);
    assert_ne!(s2.device_id, s1.device_id);
    let listed = pk.passkeys(&d2, &s2).await;
    assert!(listed[0]["lastUsedAt"].is_string(), "{listed}");
}

#[tokio::test]
async fn a_passkey_without_prf_signs_in_but_opens_nothing_until_it_is_given_a_copy() {
    let pk = pk();
    let (d1, s1) = pk.signed_in("sam@example.org").await;
    let (id, mut authenticator) = pk.new_passkey(&d1, &s1, "Laptop", None).await;

    let d2 = pk.device();
    let signed = pk.passkey_sign_in(&d2, &mut authenticator).await;
    assert_eq!(signed.status, StatusCode::OK, "{:?}", signed.json());
    assert!(signed.json()["prf"].is_null());
    assert_eq!(pk.passkeys(&d1, &s1).await[0]["prf"], false);

    let put = |body: Value| {
        let uri = format!("/kem/v1/account/passkeys/{id}/prf");
        let (pk, d1, s1) = (&pk, &d1, &s1);
        async move {
            pk.call(d1, "PUT", &uri, Some(&s1.access_token), Some(body))
                .await
        }
    };
    // The wrong length, and a key version the account isn't at.
    let short = put(json!({"wrappedKey": b64(&WRAP[..91]), "keyVersion": FIRST_KEY_VERSION})).await;
    assert_eq!(short.status, StatusCode::BAD_REQUEST, "{:?}", short.json());
    let stale = put(json!({"wrappedKey": b64(&WRAP), "keyVersion": FIRST_KEY_VERSION + 1})).await;
    assert_eq!(stale.status, StatusCode::BAD_REQUEST, "{:?}", stale.json());
    let stored = put(json!({"wrappedKey": b64(&WRAP), "keyVersion": FIRST_KEY_VERSION})).await;
    assert_eq!(stored.status, StatusCode::NO_CONTENT, "{:?}", stored.json());

    let again = pk.passkey_sign_in(&d2, &mut authenticator).await;
    assert_eq!(again.status, StatusCode::OK, "{:?}", again.json());
    assert_eq!(again.json()["prf"]["wrappedKey"], b64(&WRAP));
}

#[tokio::test]
async fn a_challenge_is_good_once_and_only_for_the_key_that_asked() {
    let pk = pk();
    let (d1, s1) = pk.signed_in("sam@example.org").await;
    let (_, mut authenticator) = pk.new_passkey(&d1, &s1, "Laptop", None).await;

    // Answered by a device with another DPoP key.
    let asker = pk.device();
    let body = pk.passkey_answer(&asker, &mut authenticator).await;
    let thief = pk.device();
    let stolen = pk.verify(&thief, body).await;
    assert_eq!(
        stolen.status,
        StatusCode::UNAUTHORIZED,
        "{:?}",
        stolen.json()
    );

    // A right answer is accepted once, and the same body sent again is a replay.
    let body = pk.passkey_answer(&asker, &mut authenticator).await;
    let first = pk.verify(&asker, body.clone()).await;
    assert_eq!(first.status, StatusCode::OK, "{:?}", first.json());
    let replay = pk.verify(&asker, body).await;
    assert_eq!(replay.status, StatusCode::BAD_REQUEST);
    assert_eq!(replay.problem(), "invalid-request");
}

#[tokio::test]
async fn an_answer_from_an_authenticator_the_server_never_saw_is_refused() {
    let pk = pk();
    let (d1, s1) = pk.signed_in("sam@example.org").await;
    pk.new_passkey(&d1, &s1, "Laptop", None).await;

    let mut stranger = authenticator();
    let refused = pk.passkey_sign_in(&pk.device(), &mut stranger).await;
    assert_eq!(
        refused.status,
        StatusCode::UNAUTHORIZED,
        "{:?}",
        refused.json()
    );
    assert_eq!(refused.problem(), "unauthorized");
}

#[tokio::test]
async fn a_challenge_that_is_not_ours_or_is_old_is_refused() {
    let pk = pk();
    let (d1, s1) = pk.signed_in("sam@example.org").await;
    let (_, mut authenticator) = pk.new_passkey(&d1, &s1, "Laptop", None).await;
    let client = pk.device();

    let mut body = pk.passkey_answer(&client, &mut authenticator).await;
    body["challenge"] = json!(b64(&[1, 2, 3]));
    let forged = pk.verify(&client, body).await;
    assert_eq!(forged.status, StatusCode::BAD_REQUEST);

    let body = pk.passkey_answer(&client, &mut authenticator).await;
    pk.app.clock.advance(Duration::minutes(6));
    let late = pk.verify(&client, body).await;
    assert_eq!(late.status, StatusCode::BAD_REQUEST, "{:?}", late.json());

    // Not an object, and a member that isn't ours.
    let mut body = pk.passkey_answer(&client, &mut authenticator).await;
    body["credential"] = json!("text");
    assert_eq!(
        pk.verify(&client, body).await.status,
        StatusCode::BAD_REQUEST
    );
    let mut body = pk.passkey_answer(&client, &mut authenticator).await;
    body["extra"] = json!(1);
    assert_eq!(
        pk.verify(&client, body).await.status,
        StatusCode::BAD_REQUEST
    );
}

#[tokio::test]
async fn require_sso_blocks_a_member_and_spares_the_admins_of_the_space() {
    let pk = pk();
    let (d1, s1) = pk.signed_in("sam@example.org").await;
    let (_, mut authenticator) = pk.new_passkey(&d1, &s1, "Laptop", None).await;
    let user: UserId = s1.user_id.parse().expect("a UUID");
    let space = SpaceId::random();
    let membership = |role| {
        vec![SpaceMembership {
            space,
            role,
            require_sso: true,
        }]
    };

    pk.membership.put(user, membership(SpaceRole::Member));
    let blocked = pk.passkey_sign_in(&pk.device(), &mut authenticator).await;
    assert_eq!(
        blocked.status,
        StatusCode::FORBIDDEN,
        "{:?}",
        blocked.json()
    );
    assert_eq!(blocked.problem(), "sso-required");
    assert_eq!(blocked.json()["spaceId"], space.to_string());
    assert!(blocked.json().get("tokens").is_none());

    pk.membership.put(user, membership(SpaceRole::Admin));
    let admin = pk.passkey_sign_in(&pk.device(), &mut authenticator).await;
    assert_eq!(admin.status, StatusCode::OK, "{:?}", admin.json());
}

// ---------------------------------------------------------------------------------------------
// An account's passkeys

#[tokio::test]
async fn passkeys_are_renamed_and_deleted_by_their_owner() {
    let pk = pk();
    let (d1, s1) = pk.signed_in("sam@example.org").await;
    let (d2, s2) = pk.signed_in("ada@example.org").await;
    let (id, mut authenticator) = pk.new_passkey(&d1, &s1, "Laptop", None).await;
    let token = Some(s1.access_token.as_str());
    let uri = format!("/kem/v1/account/passkeys/{id}");

    let renamed = pk
        .call(
            &d1,
            "PATCH",
            &uri,
            token,
            Some(json!({"name": "  Home desktop "})),
        )
        .await;
    assert_eq!(
        renamed.status,
        StatusCode::NO_CONTENT,
        "{:?}",
        renamed.json()
    );
    assert_eq!(pk.passkeys(&d1, &s1).await[0]["name"], "Home desktop");
    let nameless = pk
        .call(&d1, "PATCH", &uri, token, Some(json!({"name": " "})))
        .await;
    assert_eq!(nameless.status, StatusCode::BAD_REQUEST);

    // Another account's passkey is not found, not forbidden.
    let other = Some(s2.access_token.as_str());
    let foreign = pk
        .call(&d2, "PATCH", &uri, other, Some(json!({"name": "Mine"})))
        .await;
    assert_eq!(foreign.status, StatusCode::NOT_FOUND);
    assert_eq!(
        pk.call(&d2, "DELETE", &uri, other, None).await.status,
        StatusCode::NOT_FOUND
    );
    let bad_id = pk
        .call(
            &d1,
            "DELETE",
            "/kem/v1/account/passkeys/not-a-uuid",
            token,
            None,
        )
        .await;
    assert_eq!(bad_id.status, StatusCode::BAD_REQUEST);

    // Deleted, it signs nobody in.
    let deleted = pk.call(&d1, "DELETE", &uri, token, None).await;
    assert_eq!(deleted.status, StatusCode::NO_CONTENT);
    assert_eq!(
        pk.call(&d1, "DELETE", &uri, token, None).await.status,
        StatusCode::NOT_FOUND
    );
    assert_eq!(pk.passkeys(&d1, &s1).await, json!([]));
    let refused = pk.passkey_sign_in(&pk.device(), &mut authenticator).await;
    assert_eq!(refused.status, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn an_account_has_at_most_five_passkeys() {
    let pk = pk();
    let (d1, s1) = pk.signed_in("sam@example.org").await;
    for i in 0..5 {
        pk.new_passkey(&d1, &s1, &format!("key {i}"), None).await;
    }
    let sixth = pk
        .call(
            &d1,
            "POST",
            "/kem/v1/account/passkeys/options",
            Some(&s1.access_token),
            None,
        )
        .await;
    assert_eq!(sixth.status, StatusCode::BAD_REQUEST, "{:?}", sixth.json());
    assert_eq!(
        pk.passkeys(&d1, &s1).await.as_array().map(Vec::len),
        Some(5)
    );
}

#[tokio::test]
async fn registering_a_passkey_needs_a_session_a_name_and_a_right_answer() {
    let pk = pk();
    let (d1, s1) = pk.signed_in("sam@example.org").await;
    let token = Some(s1.access_token.as_str());

    let anonymous = pk
        .call(&d1, "GET", "/kem/v1/account/passkeys", None, None)
        .await;
    assert_eq!(anonymous.status, StatusCode::UNAUTHORIZED);

    let started = pk
        .call(&d1, "POST", "/kem/v1/account/passkeys/options", token, None)
        .await;
    let options = started.json()["options"].clone();
    assert_eq!(options["authenticatorSelection"]["residentKey"], "required");
    let mut elsewhere = SoftwareAuthenticator::new("kemlock.test", "https://evil.test");
    let wrong = pk
        .call(
            &d1,
            "POST",
            "/kem/v1/account/passkeys",
            token,
            Some(json!({"name": "Phish", "credential": elsewhere.create(&options)})),
        )
        .await;
    assert_eq!(wrong.status, StatusCode::BAD_REQUEST, "{:?}", wrong.json());
    // The wrong answer used the challenge up.
    let mut honest = authenticator();
    let late = pk
        .call(
            &d1,
            "POST",
            "/kem/v1/account/passkeys",
            token,
            Some(json!({"name": "Laptop", "credential": honest.create(&options)})),
        )
        .await;
    assert_eq!(late.status, StatusCode::BAD_REQUEST, "{:?}", late.json());
    assert_eq!(pk.passkeys(&d1, &s1).await, json!([]));
}

// ---------------------------------------------------------------------------------------------
// Security keys

/// Registers a security key for the account through the enrolment routes.
async fn enrol_key(
    pk: &Pk,
    client: &Client,
    session: &Session,
    name: &str,
) -> SoftwareAuthenticator {
    let token = Some(session.access_token.as_str());
    let started = pk
        .call(
            client,
            "POST",
            "/kem/v1/account/two-factor/webauthn",
            token,
            None,
        )
        .await;
    assert_eq!(started.status, StatusCode::OK, "{:?}", started.json());
    let options = started.json()["options"].clone();
    assert_eq!(
        options["authenticatorSelection"]["userVerification"],
        "discouraged"
    );
    let mut authenticator = authenticator();
    let confirmed = pk
        .call(
            client,
            "POST",
            "/kem/v1/account/two-factor/webauthn/confirm",
            token,
            Some(json!({"name": name, "credential": authenticator.create(&options)})),
        )
        .await;
    assert_eq!(confirmed.status, StatusCode::OK, "{:?}", confirmed.json());
    assert_eq!(confirmed.json()["enabled"], true);
    authenticator
}

#[tokio::test]
async fn a_security_key_answers_the_second_step_of_a_password_sign_in() {
    let pk = pk();
    let (d1, s1) = pk.signed_in("sam@example.org").await;
    let mut key = enrol_key(&pk, &d1, &s1, "Yubi").await;

    // A new device signs in with the password and is asked for the second step.
    let d2 = pk.device();
    let first = sign_in_reply(&d2, "sam@example.org", test_device()).await;
    assert_eq!(first.status, StatusCode::OK, "{:?}", first.json());
    let first = first.json();
    assert_eq!(first["status"], "two_factor_required");
    assert_eq!(first["methods"], json!(["webauthn"]));
    let challenge = first["challenge"].clone();

    let asked = pk
        .call(
            &d2,
            "POST",
            "/kem/v1/auth/two-factor/webauthn/options",
            None,
            Some(json!({"challenge": challenge})),
        )
        .await;
    assert_eq!(asked.status, StatusCode::OK, "{:?}", asked.json());
    let options = asked.json()["options"].clone();
    assert_eq!(options["allowCredentials"][0]["type"], "public-key");
    assert_eq!(
        options["extensions"]["appid"],
        "https://kemlock.test/app-id.json"
    );
    assert_eq!(options["userVerification"], "discouraged");

    let answer = json!({"challenge": challenge, "credential": key.get(&options)});
    let signed = pk
        .call(
            &d2,
            "POST",
            "/kem/v1/auth/two-factor/webauthn",
            None,
            Some(answer.clone()),
        )
        .await;
    assert_eq!(signed.status, StatusCode::OK, "{:?}", signed.json());
    let s2 = Session::from_tokens(&signed.json());
    assert_eq!(s2.user_id, s1.user_id);
    assert_ne!(s2.device_id, s1.device_id);

    // The same answer again finds no challenge to answer.
    let replay = pk
        .call(
            &d2,
            "POST",
            "/kem/v1/auth/two-factor/webauthn",
            None,
            Some(answer),
        )
        .await;
    assert_eq!(
        replay.status,
        StatusCode::UNAUTHORIZED,
        "{:?}",
        replay.json()
    );
}

#[tokio::test]
async fn the_second_step_refuses_another_device_key_a_wrong_key_and_a_made_up_challenge() {
    let pk = pk();
    let (d1, s1) = pk.signed_in("sam@example.org").await;
    let mut key = enrol_key(&pk, &d1, &s1, "Yubi").await;
    let d2 = pk.device();
    let first = sign_in_reply(&d2, "sam@example.org", test_device())
        .await
        .json();
    let challenge = first["challenge"].clone();
    assert_eq!(
        pk.key_options(&pk.device(), json!({"challenge": challenge}))
            .await
            .status,
        StatusCode::UNAUTHORIZED,
        "a device with another DPoP key"
    );
    assert_eq!(
        pk.key_options(&d2, json!({"challenge": b64(&[1, 2, 3])}))
            .await
            .status,
        StatusCode::BAD_REQUEST
    );

    // An answer from a key the account doesn't have is refused and uses the challenge up.
    let asked = pk.key_options(&d2, json!({"challenge": challenge})).await;
    let options = asked.json()["options"].clone();
    let mut stranger = authenticator();
    let wrong = pk
        .call(
            &d2,
            "POST",
            "/kem/v1/auth/two-factor/webauthn",
            None,
            Some(json!({"challenge": challenge, "credential": stranger.get(&options)})),
        )
        .await;
    assert_eq!(wrong.status, StatusCode::UNAUTHORIZED);
    let late = pk
        .call(
            &d2,
            "POST",
            "/kem/v1/auth/two-factor/webauthn",
            None,
            Some(json!({"challenge": challenge, "credential": key.get(&options)})),
        )
        .await;
    assert_eq!(late.status, StatusCode::UNAUTHORIZED, "{:?}", late.json());
}

#[tokio::test]
async fn a_session_alone_cannot_add_a_security_key_beside_an_authenticator_app() {
    let pk = pk();
    let (d1, s1) = pk.signed_in("sam@example.org").await;
    let token = Some(s1.access_token.as_str());
    let enrol = pk
        .call(&d1, "POST", "/kem/v1/account/two-factor/totp", token, None)
        .await;
    let secret = enrol.json()["secret"]
        .as_str()
        .expect("a secret")
        .to_owned();
    let confirmed = pk
        .call(
            &d1,
            "POST",
            "/kem/v1/account/two-factor/totp/confirm",
            token,
            Some(json!({"code": totp_now(&pk.app, &secret)})),
        )
        .await;
    assert_eq!(
        confirmed.status,
        StatusCode::NO_CONTENT,
        "{:?}",
        confirmed.json()
    );

    let refused = pk
        .call(
            &d1,
            "POST",
            "/kem/v1/account/two-factor/webauthn",
            token,
            None,
        )
        .await;
    assert_eq!(refused.status, StatusCode::CONFLICT, "{:?}", refused.json());
}

#[tokio::test]
async fn a_security_key_that_isnt_ours_is_not_registered() {
    let pk = pk();
    let (d1, s1) = pk.signed_in("sam@example.org").await;
    let token = Some(s1.access_token.as_str());
    let started = pk
        .call(
            &d1,
            "POST",
            "/kem/v1/account/two-factor/webauthn",
            token,
            None,
        )
        .await;
    let options = started.json()["options"].clone();
    let mut elsewhere = SoftwareAuthenticator::new("evil.test", common::DOMAIN);
    let refused = pk
        .call(
            &d1,
            "POST",
            "/kem/v1/account/two-factor/webauthn/confirm",
            token,
            Some(json!({"name": "Phish", "credential": elsewhere.create(&options)})),
        )
        .await;
    assert_eq!(
        refused.status,
        StatusCode::BAD_REQUEST,
        "{:?}",
        refused.json()
    );
    // Still no second step: a password sign-in gives tokens.
    let signed = sign_in_reply(&pk.device(), "sam@example.org", test_device())
        .await
        .json();
    assert_eq!(signed["status"], "signed_in");
}

#[test]
fn the_openapi_document_names_the_routes() {
    let doc = serde_json::to_value(PasskeysApiDoc::openapi()).expect("serialises");
    let paths = doc["paths"].as_object().expect("paths");
    for (path, method) in [
        ("/kem/v1/auth/passkey/options", "post"),
        ("/kem/v1/auth/passkey/verify", "post"),
        ("/kem/v1/account/passkeys", "get"),
        ("/kem/v1/account/passkeys", "post"),
        ("/kem/v1/account/passkeys/options", "post"),
        ("/kem/v1/account/passkeys/{id}", "patch"),
        ("/kem/v1/account/passkeys/{id}", "delete"),
        ("/kem/v1/account/passkeys/{id}/prf", "put"),
        ("/kem/v1/account/two-factor/webauthn", "post"),
        ("/kem/v1/account/two-factor/webauthn", "get"),
        ("/kem/v1/account/two-factor/webauthn/{slot}", "delete"),
        ("/kem/v1/account/two-factor/webauthn/confirm", "post"),
        ("/kem/v1/auth/two-factor/webauthn/options", "post"),
        ("/kem/v1/auth/two-factor/webauthn", "post"),
    ] {
        assert!(paths[path][method].is_object(), "{method} {path}");
    }
    // Eleven paths: the {slot} one is the security keys' removal.
    assert_eq!(paths.len(), 11);
}
