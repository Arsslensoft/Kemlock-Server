//! The admin passkey step-up as the server wires it: the real WebAuthn relying party and a
//! software authenticator, over a real store. A fresh, user-verified assertion from one of the
//! admin's own passkeys makes the token every write takes.

use kemlock_app::Actor;
use kemlock_app::admin::{AdminError, PasskeyStepper, StepUp};
use kemlock_app::passkeys::{CredentialKind, PasskeyRepo, RegistrationStart, WebAuthn};
use kemlock_app::ports::UserRepo;
use kemlock_crypto::opaque::OpaqueServer;
use kemlock_crypto::seal::ServerSeal;
use kemlock_domain::{
    AccountMode, DeviceId, Email, KdfParams, Passkey, PasskeyId, Role, User, UserId,
};
use kemlock_identity::authenticator::SoftwareAuthenticator;
use kemlock_server::adapters::ServerCrypto;
use kemlock_server::passkeys::{relying_party, step_up};
use kemlock_store_sql::SqlStore;
use std::sync::Arc;
use time::macros::datetime;
use uuid::Uuid;

const DOMAIN: &str = "https://kemlock.test";

fn crypto() -> ServerCrypto {
    ServerCrypto::new(ServerSeal::new(&[7u8; 32]), OpaqueServer::generate())
}

fn account(email: &str) -> User {
    User {
        id: UserId::random(),
        email: Email::parse(email).expect("a valid email"),
        name: Some("Ada".to_owned()),
        mode: AccountMode::KemlockOnly,
        role: Role::Admin,
        kdf: KdfParams::new_account([3; 16]),
        opaque_record: Some(vec![1; 192]),
        wrapped_root_key: vec![2; 100],
        public_bundle: vec![3; 500],
        bundle_signature: vec![4; 340],
        sealed_private_keys: vec![5; 800],
        key_version: 1,
        security_stamp: Uuid::new_v4(),
        created_at: datetime!(2026-01-02 03:04:05 UTC),
        updated_at: datetime!(2026-01-02 03:04:05 UTC),
    }
}

struct Fx {
    store: SqlStore,
    crypto: ServerCrypto,
    stepper: Arc<dyn PasskeyStepper>,
    actor: Actor,
    authenticator: SoftwareAuthenticator,
}

/// An admin with one passkey, made through the real registration ceremony.
async fn fx() -> Fx {
    let store = SqlStore::connect("sqlite::memory:").await.expect("a store");
    let crypto = crypto();
    let rp = relying_party(DOMAIN).expect("a relying party");
    let user = account("ada@example.org");
    UserRepo::insert(&store, &user).await.expect("an account");

    let started = rp
        .start_registration(&RegistrationStart {
            kind: CredentialKind::Passkey,
            user_handle: user.id.as_bytes(),
            user_name: "ada@example.org",
            display_name: "Ada",
            exclude: &[],
        })
        .expect("a registration");
    let mut authenticator = SoftwareAuthenticator::new("kemlock.test", DOMAIN);
    let answer = authenticator.create(&started.options);
    let made = rp
        .finish_registration(
            CredentialKind::Passkey,
            &started.state,
            answer.to_string().as_bytes(),
        )
        .expect("a credential");
    store
        .insert_passkey(&Passkey {
            id: PasskeyId::random(),
            user: user.id,
            credential_id: made.credential_id,
            name: "Work key".to_owned(),
            credential: made.credential,
            prf_wrap: None,
            created_at: datetime!(2026-01-02 03:04:05 UTC),
            last_used_at: None,
        })
        .await
        .expect("the passkey is stored");

    Fx {
        stepper: step_up(store.clone(), rp, crypto.clone()),
        store,
        crypto,
        actor: Actor {
            user: user.id,
            device: DeviceId::random(),
            admin: true,
        },
        authenticator,
    }
}

impl Fx {
    /// The check a write runs on its `Step-Up-Token` header.
    fn accepts(&self, actor: &Actor, token: &str) -> bool {
        StepUp {
            users: self.store.clone(),
            two_factor: self.store.clone(),
            auth: self.crypto.clone(),
            seal: self.crypto.clone(),
            totp: self.crypto.clone(),
            env: self.crypto.clone(),
        }
        .check(actor, token)
        .is_ok()
    }
}

#[tokio::test]
async fn a_user_verified_assertion_makes_a_token_the_writes_take() {
    let mut fx = fx().await;
    let challenge = fx.stepper.options(&fx.actor).await.expect("options");

    let answer = fx.authenticator.get(&challenge.options);
    let issued = fx
        .stepper
        .finish(
            &fx.actor,
            &challenge.challenge,
            answer.to_string().as_bytes(),
        )
        .await
        .expect("a token");
    assert!(fx.accepts(&fx.actor, &issued.token));
    let elsewhere = Actor {
        device: DeviceId::random(),
        ..fx.actor
    };
    assert!(
        !fx.accepts(&elsewhere, &issued.token),
        "bound to the device"
    );

    // The passkey's use is kept, so the counter has moved on in the store.
    let stored = fx.store.passkeys_of(fx.actor.user).await.expect("passkeys");
    assert!(stored[0].last_used_at.is_some());
}

#[tokio::test]
async fn an_assertion_without_user_verification_makes_no_token() {
    let mut fx = fx().await;
    fx.authenticator.set_user_verified(false);
    let challenge = fx.stepper.options(&fx.actor).await.expect("options");
    let answer = fx.authenticator.get(&challenge.options);
    let refused = fx
        .stepper
        .finish(
            &fx.actor,
            &challenge.challenge,
            answer.to_string().as_bytes(),
        )
        .await;
    assert_eq!(refused, Err(AdminError::StepUpFailed));
    let stored = fx.store.passkeys_of(fx.actor.user).await.expect("passkeys");
    assert!(stored[0].last_used_at.is_none(), "nothing was recorded");
}

#[tokio::test]
async fn an_authenticator_for_another_origin_makes_no_token() {
    let mut fx = fx().await;
    fx.authenticator.set_origin("https://evil.example");
    let challenge = fx.stepper.options(&fx.actor).await.expect("options");
    let answer = fx.authenticator.get(&challenge.options);
    let refused = fx
        .stepper
        .finish(
            &fx.actor,
            &challenge.challenge,
            answer.to_string().as_bytes(),
        )
        .await;
    assert_eq!(refused, Err(AdminError::StepUpFailed));
}
