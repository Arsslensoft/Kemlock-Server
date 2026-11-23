//! A server moved from Vaultwarden keeps every two-step setup: the sample data folder's account
//! gets each kind of setup in turn (as Vaultwarden 1.37.5 wrote it into `twofactor`), is imported
//! by `SqlImportSink`, and signs in to the Bitwarden API with its old second step.
//!
//! The WebAuthn and U2F registrations are made with a software authenticator and the server's own
//! relying party, then written in Vaultwarden's forms (a `Passkey` and a U2F registration), so the
//! sign-in shows the imported credentials really verify.

mod common;
#[allow(clippy::unwrap_used)]
#[path = "../../kemlock-vaultwarden/tests/common/mod.rs"]
mod vwfix;

use common::{DOMAIN, HASH, Harness, IntoBlobs, SERVER_KEY};
use kemlock_api_bw::TwoStepParts;
use kemlock_api_bw::password::hash_password;
use kemlock_app::b64url;
use kemlock_app::notices::{BoxFuture, Notice, Notices, Outbox};
use kemlock_app::passkeys::{CredentialKind, RegistrationStart, WebAuthn};
use kemlock_app::ports::TwoFactorRepo;
use kemlock_app::two_step::{
    Duo, DuoError, DuoKeys, DuoPrompt, TwoStepSettings, Yubico, YubicoError,
};
use kemlock_crypto::seal::ServerSeal;
use kemlock_domain::UserId;
use kemlock_identity::WebAuthnRp;
use kemlock_identity::authenticator::{SoftwareAuthenticator, bitwarden_assertion};
use kemlock_store_sql::{ImportOptions, SqlImportSink, SqlStore};
use kemlock_vaultwarden::{apply, map_snapshot};
use serde_json::{Value, json};
use std::sync::{Arc, Mutex};
use uuid::Uuid;
use vwfix::ALICE;

const OTP: &str = "cccccccccccckhvfhkbjtkjlkhdfhjcehcbvlnbtjhgv";
/// The `totp_recover` the moved account had in Vaultwarden.
const RECOVERY: &str = "MOVEDCODEMOVEDCODEMOVEDCODE22222";

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

#[derive(Clone, Default)]
struct Mailbox(Arc<Mutex<Vec<(String, String)>>>);

impl Outbox for Mailbox {
    fn deliver(&self, notice: Notice) -> BoxFuture<'_, ()> {
        Box::pin(async move {
            if let Notice::TwoStepCode(code) = notice {
                self.0
                    .lock()
                    .expect("the lock")
                    .push((code.to.as_str().to_owned(), code.code.clone()));
            }
        })
    }
}

struct FakeYubico;

impl Yubico for FakeYubico {
    fn verify<'a>(&'a self, otp: &'a str) -> BoxFuture<'a, Result<(), YubicoError>> {
        Box::pin(async move {
            if otp == OTP {
                Ok(())
            } else {
                Err(YubicoError::Rejected)
            }
        })
    }
}

/// `(device, state, host)` of the prompts started.
type Started = (String, String, String);

#[derive(Clone, Default)]
struct FakeDuo(Arc<Mutex<Vec<Started>>>);

impl Duo for FakeDuo {
    fn check_keys<'a>(&'a self, _keys: &'a DuoKeys) -> BoxFuture<'a, Result<(), DuoError>> {
        Box::pin(async { Ok(()) })
    }

    fn auth_url<'a>(
        &'a self,
        prompt: &'a DuoPrompt<'a>,
    ) -> BoxFuture<'a, Result<String, DuoError>> {
        Box::pin(async move {
            self.0.lock().expect("the lock").push((
                prompt.device.to_owned(),
                prompt.state.to_owned(),
                prompt.keys.host.clone(),
            ));
            Ok(format!("https://{}/prompt", prompt.keys.host))
        })
    }

    fn verify<'a>(
        &'a self,
        prompt: &'a DuoPrompt<'a>,
        code: &'a str,
    ) -> BoxFuture<'a, Result<(), DuoError>> {
        Box::pin(async move {
            let known = self
                .0
                .lock()
                .expect("the lock")
                .iter()
                .any(|p| p.0 == prompt.device && p.1 == prompt.state);
            if known && prompt.username == "alice@example.org" && code == "duo-says-yes" {
                Ok(())
            } else {
                Err(DuoError::Rejected)
            }
        })
    }
}

/// A server that was moved: alice's `twofactor` rows are what the test gave her.
struct Moved {
    h: Harness,
    store: SqlStore,
    mailbox: Mailbox,
    duo: FakeDuo,
    // The folders the move used, kept until the test ends.
    _folders: (tempfile::TempDir, tempfile::TempDir, tempfile::TempDir),
}

fn sql_text(text: &str) -> String {
    text.replace('\'', "''")
}

/// Imports the sample folder with alice's two-step setups replaced by `rows` (`atype`, `data`), as a
/// Vaultwarden server whose settings are `settings` would have them.
async fn moved(rows: &[(i64, String)], settings: TwoStepSettings) -> Moved {
    let vw = tempfile::tempdir().expect("a temp folder");
    vwfix::create_sample_folder(vw.path()).await;
    let mut conn = vwfix::writer(vw.path()).await;
    let hash = hash_password(HASH.as_bytes(), &[1, 2, 3, 4, 5, 6, 7, 8], 1_000);
    let mut sql = format!(
        "UPDATE users SET password_hash = X'{}', password_iterations = 1000,
                totp_recover = '{RECOVERY}' WHERE uuid = '{ALICE}';
         DELETE FROM twofactor WHERE user_uuid = '{ALICE}';",
        hex(&hash)
    );
    for (index, (kind, data)) in rows.iter().enumerate() {
        sql.push_str(&format!(
            "INSERT INTO twofactor (uuid, user_uuid, atype, enabled, data, last_used)
             VALUES ('20000000-0000-4000-8000-00000000010{index}', '{ALICE}', {kind}, 1, '{}', 0);",
            sql_text(data)
        ));
    }
    vwfix::exec(&mut conn, &sql).await;
    sqlx::Connection::close(conn).await.expect("closes");

    let store_dir = tempfile::tempdir().expect("a temp folder");
    let store = SqlStore::connect(&format!(
        "sqlite://{}?mode=rwc",
        store_dir
            .path()
            .join("kemlock.db")
            .to_string_lossy()
            .replace('\\', "/")
    ))
    .await
    .expect("a store");
    let mailbox = Mailbox::default();
    let duo = FakeDuo::default();
    let h = Harness::on_two_step(
        store.clone(),
        TwoStepParts {
            settings,
            notices: Notices::with_outbox(Arc::new(mailbox.clone())),
            yubico: Arc::new(FakeYubico),
            duo: Arc::new(duo.clone()),
        },
        true,
    )
    .await;

    let dest = tempfile::tempdir().expect("a temp folder");
    let mapped = map_snapshot(&vwfix::read_folder(vw.path()).await).expect("maps");
    let mut sink = SqlImportSink::begin(
        &store,
        ServerSeal::new(&SERVER_KEY),
        ImportOptions::new(
            dest.path(),
            Arc::new(IntoBlobs(h.blobs.clone())),
            h.env.time(),
        ),
    )
    .await
    .expect("a pass opens");
    apply(&mapped, &[], &mut sink)
        .await
        .expect("the pass applies");
    Moved {
        h,
        store,
        mailbox,
        duo,
        _folders: (vw, store_dir, dest),
    }
}

fn everything_on() -> TwoStepSettings {
    TwoStepSettings {
        email_enabled: true,
        yubico_enabled: true,
        duo_global: Some(DuoKeys {
            host: "api-global.duosecurity.com".to_owned(),
            ik: "DIGLOBALGLOBALGLOBAL".to_owned(),
            sk: "global-secret-key".to_owned(),
        }),
        ..TwoStepSettings::default()
    }
}

impl Moved {
    /// The password sign-in a client makes before it has a code.
    async fn first_step(&self) -> (u16, Value) {
        let (status, body) = self
            .h
            .token(&Harness::password_fields("alice@example.org", HASH))
            .await;
        (status.as_u16(), body)
    }

    async fn second_step(&self, provider: &str, token: &str) -> (u16, Value) {
        let mut fields = Harness::password_fields("alice@example.org", HASH);
        fields.push(("twoFactorProvider", provider));
        fields.push(("twoFactorToken", token));
        let (status, body) = self.h.token(&fields).await;
        (status.as_u16(), body)
    }

    async fn methods(&self) -> Vec<String> {
        let mut methods: Vec<String> =
            TwoFactorRepo::list(&self.store, UserId(Uuid::parse_str(ALICE).expect("a UUID")))
                .await
                .expect("reads")
                .into_iter()
                .map(|t| t.method.as_str().to_owned())
                .collect();
        methods.sort();
        methods
    }
}

// ---------------------------------------------------------------------------------------------
// One kind at a time.

#[tokio::test]
async fn an_email_setup_moves_with_its_address_and_signs_in() {
    let m = moved(
        &[(
            1,
            r#"{"email":"old.address@example.org","last_token":null,"token_sent":1700000000,"attempts":0}"#
                .to_owned(),
        )],
        everything_on(),
    )
    .await;
    assert_eq!(m.methods().await, vec!["email"]);

    let (status, body) = m.first_step().await;
    assert_eq!(status, 400, "{body}");
    assert_eq!(body["TwoFactorProviders"], json!(["1"]));
    assert_eq!(
        body["TwoFactorProviders2"],
        json!({"1": {"Email": "ol*********@example.org"}})
    );
    let (status, _) =
        m.h.json(
            "POST",
            "/api/two-factor/send-email-login",
            None,
            Some(json!({"email": "alice@example.org", "masterPasswordHash": HASH})),
        )
        .await;
    assert_eq!(status, 200);
    let (to, code) = m
        .mailbox
        .0
        .lock()
        .expect("the lock")
        .last()
        .cloned()
        .expect("a code was mailed");
    assert_eq!(to, "old.address@example.org");
    let (status, body) = m.second_step("1", &code).await;
    assert_eq!(status, 200, "{body}");
    assert!(body["access_token"].is_string());
}

#[tokio::test]
async fn a_yubikey_setup_moves_with_its_keys_and_signs_in() {
    let m = moved(
        &[(3, r#"{"keys":["cccccccccccc"],"nfc":true}"#.to_owned())],
        everything_on(),
    )
    .await;
    assert_eq!(m.methods().await, vec!["yubikey"]);
    let (status, body) = m.first_step().await;
    assert_eq!(status, 400, "{body}");
    assert_eq!(body["TwoFactorProviders"], json!(["3"]));
    assert_eq!(body["TwoFactorProviders2"], json!({"3": {"Nfc": true}}));
    // A key that wasn't registered is no key, whatever Yubico says.
    let other = OTP.replacen("cccccccccccc", "dddddddddddd", 1);
    assert_eq!(m.second_step("3", &other).await.0, 400);
    let (status, body) = m.second_step("3", OTP).await;
    assert_eq!(status, 200, "{body}");
}

#[tokio::test]
async fn a_duo_setup_without_keys_of_its_own_uses_the_servers_and_signs_in() {
    // Vaultwarden keeps an empty string for an account on the global integration.
    let m = moved(&[(2, String::new())], everything_on()).await;
    assert_eq!(m.methods().await, vec!["duo"]);
    let (status, body) = m.first_step().await;
    assert_eq!(status, 400, "{body}");
    assert_eq!(body["TwoFactorProviders"], json!(["2"]));
    let (_, state, host) = m
        .duo
        .0
        .lock()
        .expect("the lock")
        .last()
        .cloned()
        .expect("a prompt");
    assert_eq!(host, "api-global.duosecurity.com");
    let (status, body) = m.second_step("2", &format!("duo-says-yes|{state}")).await;
    assert_eq!(status, 200, "{body}");
}

#[tokio::test]
async fn a_duo_setup_with_keys_of_its_own_keeps_them() {
    let own =
        r#"{"host":"api-own.duosecurity.com","ik":"DIOWNOWNOWNOWNOWNOWN","sk":"own-secret-key"}"#;
    // The server has no Duo keys: the account's own are all there is.
    let m = moved(
        &[(2, own.to_owned())],
        TwoStepSettings {
            email_enabled: true,
            ..TwoStepSettings::default()
        },
    )
    .await;
    let (status, body) = m.first_step().await;
    assert_eq!(status, 400, "{body}");
    let (_, state, host) = m
        .duo
        .0
        .lock()
        .expect("the lock")
        .last()
        .cloned()
        .expect("a prompt");
    assert_eq!(host, "api-own.duosecurity.com");
    let (status, body) = m.second_step("2", &format!("duo-says-yes|{state}")).await;
    assert_eq!(status, 200, "{body}");

    // The same data through get-duo shows the keys hidden but four characters.
    let token = body["access_token"].as_str().expect("a token").to_owned();
    let (status, body) =
        m.h.json(
            "POST",
            "/api/two-factor/get-duo",
            Some(&token),
            Some(json!({"masterPasswordHash": HASH})),
        )
        .await;
    assert_eq!(status, 200, "{body}");
    assert_eq!(
        body["duo"],
        json!({"enabled": true, "host": "api-************", "clientSecret": "own-************", "clientId": "DIOW************"})
    );
}

// ---------------------------------------------------------------------------------------------
// Security keys: WebAuthn and U2F registrations.

/// A security key registered with the server's relying party: the authenticator, and the credential
/// the relying party made of it (webauthn-rs-core's JSON).
fn registered() -> (SoftwareAuthenticator, Value) {
    let rp = WebAuthnRp::new(DOMAIN).expect("a relying party");
    let started = rp
        .start_registration(&RegistrationStart {
            kind: CredentialKind::SecurityKey,
            user_handle: &[7; 16],
            user_name: "alice@example.org",
            display_name: "Alice",
            exclude: &[],
        })
        .expect("creation options");
    let mut authenticator = SoftwareAuthenticator::new("vault.test", DOMAIN);
    let answer = authenticator.create(&started.options);
    let made = rp
        .finish_registration(
            CredentialKind::SecurityKey,
            &started.state,
            answer.to_string().as_bytes(),
        )
        .expect("the registration is accepted");
    let credential = serde_json::from_slice(&made.credential).expect("a credential");
    (authenticator, credential)
}

/// The same key as Vaultwarden writes a WebAuthn registration.
fn webauthn_row(credential: &Value) -> String {
    json!([{"id": 1, "name": "Blue key", "migrated": false, "credential": {"cred": credential}}])
        .to_string()
}

/// The same key as Vaultwarden wrote a U2F registration, before it moved them to WebAuthn.
fn u2f_row(credential: &Value) -> String {
    let id = b64url::decode(credential["cred_id"].as_str().expect("an id")).expect("base64url");
    let key = &credential["cred"]["key"]["EC_EC2"];
    let mut public = vec![4u8];
    public.extend(b64url::decode(key["x"].as_str().expect("x")).expect("base64url"));
    public.extend(b64url::decode(key["y"].as_str().expect("y")).expect("base64url"));
    json!([{
        "id": 1, "name": "Old key",
        "reg": {"keyHandle": id, "pubKey": public, "attestationCert": null, "deviceName": null},
        "counter": 0, "compromised": false, "migrated": null
    }])
    .to_string()
}

#[tokio::test]
async fn a_webauthn_registration_moves_and_signs_in() {
    let (mut authenticator, credential) = registered();
    let m = moved(&[(7, webauthn_row(&credential))], everything_on()).await;
    assert_eq!(m.methods().await, vec!["webauthn"]);

    let (status, body) = m.first_step().await;
    assert_eq!(status, 400, "{body}");
    assert_eq!(body["TwoFactorProviders"], json!(["7"]));
    let options = body["TwoFactorProviders2"]["7"].clone();
    assert_eq!(
        options["allowCredentials"][0]["id"], credential["cred_id"],
        "the imported credential is the one asked for"
    );
    let answer = bitwarden_assertion(&authenticator.get(&options));
    let (status, body) = m.second_step("7", &answer).await;
    assert_eq!(status, 200, "{body}");
}

#[tokio::test]
async fn a_u2f_registration_moves_and_signs_in_through_the_app_id() {
    let (mut authenticator, credential) = registered();
    let m = moved(&[(4, u2f_row(&credential))], everything_on()).await;
    assert_eq!(m.methods().await, vec!["webauthn"]);

    let (status, body) = m.first_step().await;
    assert_eq!(status, 400, "{body}");
    assert_eq!(body["TwoFactorProviders"], json!(["7"]));
    let options = body["TwoFactorProviders2"]["7"].clone();
    // A U2F key signs for the app id, which the options name.
    let app_id = format!("{DOMAIN}/app-id.json");
    assert_eq!(options["extensions"]["appid"], app_id);
    authenticator.set_rp_id(&app_id);
    // A U2F key never verifies the user.
    authenticator.set_user_verified(false);
    let mut answer: Value =
        serde_json::from_str(&bitwarden_assertion(&authenticator.get(&options))).expect("JSON");
    answer["extensions"] = json!({"appid": true});
    let (status, body) = m.second_step("7", &answer.to_string()).await;
    assert_eq!(status, 200, "{body}");
}

#[tokio::test]
async fn a_key_vaultwarden_migrated_from_u2f_is_one_key() {
    let (mut authenticator, credential) = registered();
    let mut migrated = u2f_row(&credential);
    migrated = migrated.replace(r#""migrated":null"#, r#""migrated":true"#);
    let m = moved(
        &[(4, migrated), (7, webauthn_row(&credential))],
        everything_on(),
    )
    .await;
    let (_, body) = m.first_step().await;
    assert_eq!(
        body["TwoFactorProviders2"]["7"]["allowCredentials"]
            .as_array()
            .map(Vec::len),
        Some(1)
    );
    let options = body["TwoFactorProviders2"]["7"].clone();
    let answer = bitwarden_assertion(&authenticator.get(&options));
    assert_eq!(m.second_step("7", &answer).await.0, 200);
}

// ---------------------------------------------------------------------------------------------
// Everything at once.

#[tokio::test]
async fn an_account_with_every_kind_of_setup_keeps_them_all() {
    let (_, credential) = registered();
    let m = moved(
        &[
            (
                1,
                r#"{"email":"old.address@example.org","last_token":null,"token_sent":0,"attempts":0}"#
                    .to_owned(),
            ),
            (2, String::new()),
            (3, r#"{"keys":["cccccccccccc"],"nfc":false}"#.to_owned()),
            (4, u2f_row(&credential)),
        ],
        everything_on(),
    )
    .await;
    assert_eq!(
        m.methods().await,
        vec!["duo", "email", "webauthn", "yubikey"]
    );
    let (status, body) = m.first_step().await;
    assert_eq!(status, 400, "{body}");
    assert_eq!(body["TwoFactorProviders"], json!(["1", "2", "3", "7"]));
}

#[tokio::test]
async fn an_account_without_a_usable_second_step_is_never_let_in_without_one() {
    // The server has no mailer, Yubico or Duo yet: the moved account can't sign in until it has,
    // and the password alone is not enough.
    let m = moved(
        &[
            (
                1,
                r#"{"email":"old.address@example.org","last_token":null,"token_sent":0,"attempts":0}"#
                    .to_owned(),
            ),
            (3, r#"{"keys":["cccccccccccc"],"nfc":false}"#.to_owned()),
        ],
        TwoStepSettings::default(),
    )
    .await;
    let (status, body) = m.first_step().await;
    assert_eq!(status, 400, "{body}");
    assert_eq!(
        body["message"],
        "No enabled and usable two factor providers are available for this account"
    );
    assert!(body["access_token"].is_null());
}

#[tokio::test]
async fn setups_that_cannot_be_read_still_close_the_account() {
    let m = moved(
        &[(1, "damaged".to_owned()), (3, "{}".to_owned())],
        everything_on(),
    )
    .await;
    assert_eq!(m.methods().await, vec!["email", "yubikey"]);
    // Whatever the answer says, the password alone doesn't open it.
    let (status, body) = m.first_step().await;
    assert_ne!(status, 200, "{body}");
    assert!(body["access_token"].is_null());
}

// ---------------------------------------------------------------------------------------------
// The recovery code the account had in Vaultwarden.

#[tokio::test]
async fn the_recovery_code_of_a_moved_account_is_shown_with_the_password() {
    let m = moved(&[], everything_on()).await;
    let body = m.h.login("alice@example.org", HASH).await;
    let token = body["access_token"].as_str().expect("a token").to_owned();
    let (status, shown) =
        m.h.json(
            "POST",
            "/api/two-factor/get-recover",
            Some(&token),
            Some(json!({"masterPasswordHash": HASH})),
        )
        .await;
    assert_eq!(status, 200, "{shown}");
    assert_eq!(
        shown,
        json!({"code": RECOVERY, "object": "twoFactorRecover"})
    );
}

#[tokio::test]
async fn the_recovery_code_of_a_moved_account_signs_in_and_switches_its_methods_off() {
    let m = moved(
        &[(
            1,
            r#"{"email":"old.address@example.org","last_token":null,"token_sent":1700000000,"attempts":0}"#
                .to_owned(),
        )],
        everything_on(),
    )
    .await;
    assert_eq!(m.first_step().await.0, 400, "the second step is asked for");

    // A wrong code is Vaultwarden's refusal and changes nothing.
    let (status, body) = m.second_step("8", "not the code").await;
    assert_eq!(status, 400);
    assert_eq!(body["message"], "Two-step token is invalid. Try again.");
    assert_eq!(m.methods().await, vec!["email"]);

    // Spaces and case don't matter.
    let typed = format!(
        "{} {}",
        RECOVERY[..16].to_lowercase(),
        RECOVERY[16..].to_lowercase()
    );
    let (status, body) = m.second_step("8", &typed).await;
    assert_eq!(status, 200, "{body}");
    assert!(body["access_token"].is_string());
    assert!(m.methods().await.is_empty());

    // The code is spent: the account has none to show, and signs in with the password alone.
    let token = body["access_token"].as_str().expect("a token").to_owned();
    let (_, shown) =
        m.h.json(
            "POST",
            "/api/two-factor/get-recover",
            Some(&token),
            Some(json!({"masterPasswordHash": HASH})),
        )
        .await;
    assert_eq!(shown["code"], Value::Null);
    assert_eq!(m.first_step().await.0, 200);
}
