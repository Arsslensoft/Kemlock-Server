//! The passkey ports: `PasskeyRepo` and `ChallengeRepo`.
//!
//! Each scenario runs on every backend that is available, as `unlock.rs` does: in-memory SQLite,
//! SQLite in a file, and PostgreSQL and MySQL when `KEMLOCK_TEST_POSTGRES_URL` /
//! `KEMLOCK_TEST_MYSQL_URL` are set.

mod common;

use common::{external, file, memory, unique_email, user};
use kemlock_app::passkeys::{ChallengeKind, ChallengeRepo, PasskeyRepo};
use kemlock_app::ports::{StoreError, UserRepo};
use kemlock_domain::{Passkey, PasskeyId, PrfWrap, UserId};
use kemlock_store_sql::SqlStore;
use time::macros::datetime;
use time::{Duration, OffsetDateTime};
use uuid::Uuid;

const T0: OffsetDateTime = datetime!(2026-11-23 10:00:00 UTC);

async fn account(store: &SqlStore, prefix: &str) -> UserId {
    let account = user(&unique_email(prefix));
    UserRepo::insert(store, &account)
        .await
        .expect("insert user");
    account.id
}

/// A credential id no other run shares: the id is unique across the whole table.
fn credential_id(len: usize) -> Vec<u8> {
    let mut id = Uuid::new_v4().as_bytes().to_vec();
    id.resize(len, 0xab);
    id
}

fn passkey(user: UserId, name: &str, created_at: OffsetDateTime) -> Passkey {
    Passkey {
        id: PasskeyId::random(),
        user,
        credential_id: credential_id(32),
        name: name.to_owned(),
        credential: br#"{"cred_id":"x","counter":0}"#.to_vec(),
        prf_wrap: None,
        created_at,
        last_used_at: None,
    }
}

async fn passkeys(store: &SqlStore) {
    let sam = account(store, "passkeys-sam").await;
    let ada = account(store, "passkeys-ada").await;
    let first = passkey(sam, "Laptop", T0);
    let second = Passkey {
        prf_wrap: Some(PrfWrap {
            wrapped_key: vec![7; 92],
            key_version: 3,
        }),
        ..passkey(sam, "Phone", T0 + Duration::minutes(1))
    };
    let foreign = passkey(ada, "Ada's", T0);
    for p in [&second, &first, &foreign] {
        PasskeyRepo::insert_passkey(store, p).await.expect("insert");
    }

    // An account's passkeys come back oldest first, as written, and only its own.
    assert_eq!(
        PasskeyRepo::passkeys_of(store, sam).await.expect("list"),
        vec![first.clone(), second.clone()]
    );
    assert_eq!(
        PasskeyRepo::passkeys_of(store, ada).await.expect("list"),
        vec![foreign.clone()]
    );
    assert_eq!(
        PasskeyRepo::passkey_by_credential(store, &second.credential_id)
            .await
            .expect("read"),
        Some(second.clone())
    );
    assert_eq!(
        PasskeyRepo::passkey_by_credential(store, &credential_id(32))
            .await
            .expect("read"),
        None
    );

    // A credential id is taken once across the whole server, and an account must exist.
    let clash = Passkey {
        credential_id: first.credential_id.clone(),
        ..passkey(ada, "Same device", T0)
    };
    assert_eq!(
        PasskeyRepo::insert_passkey(store, &clash).await,
        Err(StoreError::Duplicate)
    );
    assert_eq!(
        PasskeyRepo::insert_passkey(store, &passkey(UserId::random(), "Nobody's", T0)).await,
        Err(StoreError::NotFound)
    );

    // The longest credential id WebAuthn allows is 1,023 bytes.
    let long = Passkey {
        credential_id: credential_id(1023),
        ..passkey(sam, "Long id", T0 + Duration::minutes(2))
    };
    PasskeyRepo::insert_passkey(store, &long)
        .await
        .expect("a 1,023-byte id");
    assert_eq!(
        PasskeyRepo::passkey_by_credential(store, &long.credential_id)
            .await
            .expect("read"),
        Some(long.clone())
    );
    PasskeyRepo::delete_passkey(store, sam, long.id)
        .await
        .expect("delete");

    // Renaming is the owner's alone.
    PasskeyRepo::rename_passkey(store, sam, first.id, "Work laptop")
        .await
        .expect("rename");
    assert_eq!(
        PasskeyRepo::rename_passkey(store, ada, first.id, "Mine").await,
        Err(StoreError::NotFound)
    );
    assert_eq!(
        PasskeyRepo::rename_passkey(store, sam, PasskeyId::random(), "Ghost").await,
        Err(StoreError::NotFound)
    );
    // Renaming to the name it already has changes nothing and is not an error.
    PasskeyRepo::rename_passkey(store, sam, first.id, "Work laptop")
        .await
        .expect("the same name");

    // A sign-in keeps the credential with its new counter, and when it was used.
    let used_at = T0 + Duration::hours(1);
    PasskeyRepo::record_passkey_use(store, first.id, br#"{"cred_id":"x","counter":4}"#, used_at)
        .await
        .expect("use");
    assert_eq!(
        PasskeyRepo::record_passkey_use(store, PasskeyId::random(), b"{}", used_at).await,
        Err(StoreError::NotFound)
    );
    PasskeyRepo::record_passkey_use(store, first.id, br#"{"cred_id":"x","counter":4}"#, used_at)
        .await
        .expect("the same use again");

    // The PRF copy is set, replaced and removed.
    let wrap = PrfWrap {
        wrapped_key: vec![8; 92],
        key_version: 2,
    };
    PasskeyRepo::set_passkey_wrap(store, sam, first.id, Some(&wrap))
        .await
        .expect("set");
    assert_eq!(
        PasskeyRepo::set_passkey_wrap(store, ada, first.id, Some(&wrap)).await,
        Err(StoreError::NotFound)
    );
    PasskeyRepo::set_passkey_wrap(store, sam, first.id, Some(&wrap))
        .await
        .expect("the same wrap again");
    PasskeyRepo::set_passkey_wrap(store, sam, second.id, None)
        .await
        .expect("removed");

    let listed = PasskeyRepo::passkeys_of(store, sam).await.expect("list");
    assert_eq!(listed.len(), 2);
    assert_eq!(listed[0].name, "Work laptop");
    assert_eq!(listed[0].credential, br#"{"cred_id":"x","counter":4}"#);
    assert_eq!(listed[0].last_used_at, Some(used_at));
    assert_eq!(listed[0].prf_wrap, Some(wrap));
    assert_eq!(listed[1].prf_wrap, None);

    // Deleting is the owner's alone, and once.
    assert_eq!(
        PasskeyRepo::delete_passkey(store, ada, first.id).await,
        Err(StoreError::NotFound)
    );
    PasskeyRepo::delete_passkey(store, sam, first.id)
        .await
        .expect("delete");
    assert_eq!(
        PasskeyRepo::delete_passkey(store, sam, first.id).await,
        Err(StoreError::NotFound)
    );
    assert_eq!(
        PasskeyRepo::passkey_by_credential(store, &first.credential_id)
            .await
            .expect("read"),
        None
    );
    // And the credential id can be registered again.
    PasskeyRepo::insert_passkey(
        store,
        &Passkey {
            credential_id: first.credential_id.clone(),
            ..passkey(ada, "Reused id", T0)
        },
    )
    .await
    .expect("a free id");
}

async fn challenges(store: &SqlStore) {
    let sam = account(store, "challenges-sam").await;
    let ada = account(store, "challenges-ada").await;
    let kind = ChallengeKind::SecurityKeyLogin;
    let expires = T0 + Duration::minutes(5);

    // A state is taken once.
    ChallengeRepo::put_challenge(store, sam, kind, b"state one", expires)
        .await
        .expect("put");
    assert_eq!(
        ChallengeRepo::take_challenge(store, sam, kind, T0)
            .await
            .expect("take"),
        Some(b"state one".to_vec())
    );
    assert_eq!(
        ChallengeRepo::take_challenge(store, sam, kind, T0)
            .await
            .expect("take"),
        None,
        "a state that was taken is gone"
    );

    // A newer state replaces the older one.
    ChallengeRepo::put_challenge(store, sam, kind, b"older", expires)
        .await
        .expect("put");
    ChallengeRepo::put_challenge(store, sam, kind, b"newer", expires)
        .await
        .expect("replace");
    assert_eq!(
        ChallengeRepo::take_challenge(store, sam, kind, T0)
            .await
            .expect("take"),
        Some(b"newer".to_vec())
    );
    assert_eq!(
        ChallengeRepo::take_challenge(store, sam, kind, T0)
            .await
            .expect("take"),
        None
    );

    // Each account and each kind has a state of its own.
    ChallengeRepo::put_challenge(
        store,
        sam,
        ChallengeKind::PasskeyRegistration,
        b"sam",
        expires,
    )
    .await
    .expect("put");
    ChallengeRepo::put_challenge(
        store,
        ada,
        ChallengeKind::PasskeyRegistration,
        b"ada",
        expires,
    )
    .await
    .expect("put");
    ChallengeRepo::put_challenge(store, sam, kind, b"login", expires)
        .await
        .expect("put");
    assert_eq!(
        ChallengeRepo::take_challenge(store, ada, ChallengeKind::PasskeyRegistration, T0)
            .await
            .expect("take"),
        Some(b"ada".to_vec())
    );
    assert_eq!(
        ChallengeRepo::take_challenge(store, sam, ChallengeKind::SecurityKeyRegistration, T0)
            .await
            .expect("take"),
        None,
        "another kind"
    );
    assert_eq!(
        ChallengeRepo::take_challenge(store, sam, ChallengeKind::PasskeyRegistration, T0)
            .await
            .expect("take"),
        Some(b"sam".to_vec())
    );
    assert_eq!(
        ChallengeRepo::take_challenge(store, sam, kind, T0)
            .await
            .expect("take"),
        Some(b"login".to_vec())
    );

    // An expired state is not handed out, and taking it removes it.
    ChallengeRepo::put_challenge(store, sam, kind, b"stale", expires)
        .await
        .expect("put");
    assert_eq!(
        ChallengeRepo::take_challenge(store, sam, kind, expires)
            .await
            .expect("take"),
        None,
        "at the expiry instant it is over"
    );
    assert_eq!(
        ChallengeRepo::take_challenge(store, sam, kind, T0)
            .await
            .expect("take"),
        None
    );

    // An account that doesn't exist has no states.
    assert_eq!(
        ChallengeRepo::put_challenge(store, UserId::random(), kind, b"x", expires).await,
        Err(StoreError::NotFound)
    );

    // The purge removes what expired before the cut, and no more.
    ChallengeRepo::put_challenge(store, sam, kind, b"old", T0)
        .await
        .expect("put");
    ChallengeRepo::put_challenge(store, ada, kind, b"fresh", T0 + Duration::hours(1))
        .await
        .expect("put");
    let purged = ChallengeRepo::purge_challenges(store, T0 + Duration::minutes(30))
        .await
        .expect("purge");
    assert!(purged >= 1, "at least the old state went: {purged}");
    assert_eq!(
        ChallengeRepo::take_challenge(store, sam, kind, T0 - Duration::minutes(1))
            .await
            .expect("take"),
        None
    );
    assert_eq!(
        ChallengeRepo::take_challenge(store, ada, kind, T0)
            .await
            .expect("take"),
        Some(b"fresh".to_vec())
    );
}

async fn run_all(store: &SqlStore) {
    passkeys(store).await;
    challenges(store).await;
}

#[tokio::test]
async fn sqlite_in_memory() {
    run_all(&memory().await).await;
}

#[tokio::test]
async fn sqlite_in_a_file() {
    let (store, _dir) = file().await;
    run_all(&store).await;
}

#[tokio::test]
async fn postgres_when_configured() {
    if let Some(store) = external("KEMLOCK_TEST_POSTGRES_URL").await {
        run_all(&store).await;
    }
}

#[tokio::test]
async fn mysql_when_configured() {
    if let Some(store) = external("KEMLOCK_TEST_MYSQL_URL").await {
        run_all(&store).await;
    }
}
