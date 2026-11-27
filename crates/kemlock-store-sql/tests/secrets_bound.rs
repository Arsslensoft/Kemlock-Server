//! The start-up pass that seals the stored per-account secrets to their accounts
//! (`SqlStore::bind_secrets`).
//!
//! It runs on in-memory SQLite and in a file, and on PostgreSQL and MySQL when
//! `KEMLOCK_TEST_POSTGRES_URL` / `KEMLOCK_TEST_MYSQL_URL` are set.

mod common;

use common::{external, file, memory, unique_email, user};
use kemlock_app::admin::SettingsRepo;
use kemlock_app::ports::{
    CryptoError, SecretSeal, TwoFactor, TwoFactorMethod, TwoFactorRepo, UserRepo, Zeroizing,
};
use kemlock_app::sealed::{SECRETS_BOUND_KEY, bound_purpose};
use kemlock_crypto::seal::ServerSeal;
use kemlock_store_sql::SqlStore;
use time::macros::datetime;

struct Seal(ServerSeal);

impl SecretSeal for Seal {
    fn seal(&self, purpose: &str, value: &[u8]) -> Vec<u8> {
        self.0.seal(purpose, value)
    }

    fn open(&self, purpose: &str, sealed: &[u8]) -> Result<Zeroizing<Vec<u8>>, CryptoError> {
        self.0
            .open(purpose, sealed)
            .map_err(|_| CryptoError::Invalid)
    }
}

fn seal() -> Seal {
    Seal(ServerSeal::new(&[5u8; 32]))
}

async fn pass(store: &SqlStore) {
    // A database kept between runs holds the flag of the last one.
    SettingsRepo::delete_setting(store, SECRETS_BOUND_KEY)
        .await
        .expect("the flag is cleared");
    let seal = seal();
    let sam = user(&unique_email("bind-sam"));
    let kim = user(&unique_email("bind-kim"));
    for account in [&sam, &kim] {
        UserRepo::insert(store, account).await.expect("insert user");
    }
    let row = |user, method, sealed: Vec<u8>| TwoFactor {
        user,
        method,
        sealed_secret: sealed,
        enabled: true,
        created_at: datetime!(2026-11-25 10:00:00 UTC),
    };
    // Sam's seed was sealed the old way; Kim's is sealed to Kim; Sam's email row opens neither
    // way (another key sealed it).
    let old = seal.seal("totp", b"seed");
    let bound = seal.seal(&bound_purpose("totp", kim.id), b"kim-seed");
    let foreign = ServerSeal::new(&[6u8; 32]).seal("two-step-email", b"{}");
    TwoFactorRepo::put(store, &row(sam.id, TwoFactorMethod::Totp, old.clone()))
        .await
        .expect("put");
    TwoFactorRepo::put(store, &row(kim.id, TwoFactorMethod::Totp, bound.clone()))
        .await
        .expect("put");
    TwoFactorRepo::put(store, &row(sam.id, TwoFactorMethod::Email, foreign.clone()))
        .await
        .expect("put");

    let report = store.bind_secrets(&seal).await.expect("the pass runs");
    assert!(
        report.sealed_again >= 1 && report.unreadable >= 1,
        "{report:?}"
    );

    let rows = TwoFactorRepo::list(store, sam.id).await.expect("list");
    let totp = rows
        .iter()
        .find(|r| r.method == TwoFactorMethod::Totp)
        .expect("a seed");
    assert_ne!(totp.sealed_secret, old, "sealed again");
    assert_eq!(
        seal.open(&bound_purpose("totp", sam.id), &totp.sealed_secret)
            .expect("opens bound")
            .as_slice(),
        b"seed"
    );
    assert!(
        seal.open("totp", &totp.sealed_secret).is_err(),
        "no longer the bare form"
    );
    // Not another account's.
    assert!(
        seal.open(&bound_purpose("totp", kim.id), &totp.sealed_secret)
            .is_err()
    );
    let email = rows
        .iter()
        .find(|r| r.method == TwoFactorMethod::Email)
        .expect("an email row");
    assert_eq!(
        email.sealed_secret, foreign,
        "what opens neither way is left alone"
    );
    let kims = TwoFactorRepo::list(store, kim.id).await.expect("list");
    assert_eq!(kims[0].sealed_secret, bound, "already bound: untouched");

    // Run again: nothing is left to do, and the flag says it was done.
    let again = store.bind_secrets(&seal).await.expect("the pass runs");
    assert_eq!(again.sealed_again, 0);

    // A blob sealed the old way that turns up after the pass is not the migration's: it is left
    // as it is, and never sealed to the account it was put in.
    let planted = seal.seal("totp", b"a seed the database writer chose");
    TwoFactorRepo::put(
        store,
        &TwoFactor {
            user: kim.id,
            method: TwoFactorMethod::YubiKey,
            sealed_secret: planted.clone(),
            enabled: true,
            created_at: datetime!(2026-11-25 10:00:00 UTC),
        },
    )
    .await
    .expect("put");
    let later = store.bind_secrets(&seal).await.expect("the pass runs");
    assert_eq!(later, kemlock_store_sql::BindReport::default());
    let kims = TwoFactorRepo::list(store, kim.id).await.expect("list");
    let yubikey = kims
        .iter()
        .find(|r| r.method == TwoFactorMethod::YubiKey)
        .expect("the planted row");
    assert_eq!(yubikey.sealed_secret, planted, "not sealed to the account");
    let flag = SettingsRepo::settings_with_prefix(store, SECRETS_BOUND_KEY)
        .await
        .expect("settings");
    assert!(flag.iter().any(|(k, v)| k == SECRETS_BOUND_KEY && v == "1"));
}

#[tokio::test]
async fn sqlite_in_memory() {
    pass(&memory().await).await;
}

#[tokio::test]
async fn sqlite_in_a_file() {
    let (store, _dir) = file().await;
    pass(&store).await;
}

#[tokio::test]
async fn postgres_when_configured() {
    if let Some(store) = external("KEMLOCK_TEST_POSTGRES_URL").await {
        pass(&store).await;
    }
}

#[tokio::test]
async fn mysql_when_configured() {
    if let Some(store) = external("KEMLOCK_TEST_MYSQL_URL").await {
        pass(&store).await;
    }
}
