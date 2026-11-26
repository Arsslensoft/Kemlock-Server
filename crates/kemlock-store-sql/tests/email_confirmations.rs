//! The hold on an account until the link mailed to its address is opened: `UserRepo`'s
//! `hold_unconfirmed`, `email_unconfirmed`, `confirmation_of` and `spend_confirmation`.
//!
//! Each scenario runs on every backend that is available, as `email_changes.rs` does: in-memory
//! SQLite, SQLite in a file, and PostgreSQL and MySQL when `KEMLOCK_TEST_POSTGRES_URL` /
//! `KEMLOCK_TEST_MYSQL_URL` are set.

mod common;

use common::{external, file, memory, unique_email, user};
use kemlock_app::ports::{EmailConfirmation, StoreError, UserRepo};
use kemlock_domain::UserId;
use kemlock_store_sql::SqlStore;
use time::macros::datetime;
use time::{Duration, OffsetDateTime};
use uuid::Uuid;

const T0: OffsetDateTime = datetime!(2026-11-25 10:00:00 UTC);

async fn account(store: &SqlStore, prefix: &str) -> UserId {
    let account = user(&unique_email(prefix));
    UserRepo::insert(store, &account)
        .await
        .expect("insert user");
    account.id
}

/// A token hash no other run shares: a database kept between runs holds no clash.
fn hash() -> [u8; 32] {
    let mut out = [0u8; 32];
    out[..16].copy_from_slice(Uuid::new_v4().as_bytes());
    out[16..].copy_from_slice(Uuid::new_v4().as_bytes());
    out
}

async fn holds(store: &SqlStore) {
    let sam = account(store, "hold-sam").await;
    let ada = account(store, "hold-ada").await;
    let (first, second, ada_hash) = (hash(), hash(), hash());
    let lifetime = Duration::hours(24);

    // An account nobody held back is confirmed.
    assert_eq!(store.email_unconfirmed(sam).await, Ok(false));
    assert_eq!(store.confirmation_of(sam).await, Ok(None));

    store
        .hold_unconfirmed(sam, first, T0, T0 + lifetime)
        .await
        .expect("holds");
    assert_eq!(store.email_unconfirmed(sam).await, Ok(true));
    assert_eq!(store.email_unconfirmed(ada).await, Ok(false), "another's");
    assert_eq!(
        store.confirmation_of(sam).await,
        Ok(Some(EmailConfirmation {
            user: sam,
            requested_at: T0,
            expires_at: T0 + lifetime,
        }))
    );

    // A new link replaces the one before: the old token opens nothing.
    store
        .hold_unconfirmed(sam, second, T0 + Duration::hours(1), T0 + lifetime)
        .await
        .expect("replaces");
    assert_eq!(store.spend_confirmation(first, T0).await, Ok(None));
    assert_eq!(store.email_unconfirmed(sam).await, Ok(true));

    // A link out of time opens nothing and leaves the hold.
    store
        .hold_unconfirmed(ada, ada_hash, T0, T0 + lifetime)
        .await
        .expect("holds");
    assert_eq!(
        store.spend_confirmation(ada_hash, T0 + lifetime).await,
        Ok(None)
    );
    assert_eq!(store.email_unconfirmed(ada).await, Ok(true));

    // An unknown token opens nothing.
    assert_eq!(store.spend_confirmation(hash(), T0).await, Ok(None));

    // A good link releases the account, once.
    assert_eq!(
        store
            .spend_confirmation(second, T0 + Duration::hours(2))
            .await,
        Ok(Some(sam))
    );
    assert_eq!(store.email_unconfirmed(sam).await, Ok(false));
    assert_eq!(store.spend_confirmation(second, T0).await, Ok(None));
    assert_eq!(store.email_unconfirmed(ada).await, Ok(true));

    // A hold for an account that doesn't exist is refused by the foreign key.
    assert_eq!(
        store
            .hold_unconfirmed(UserId::random(), hash(), T0, T0 + lifetime)
            .await,
        Err(StoreError::NotFound)
    );
}

#[tokio::test]
async fn sqlite_in_memory() {
    let store = memory().await;
    holds(&store).await;
}

#[tokio::test]
async fn sqlite_in_a_file() {
    let (store, _dir) = file().await;
    holds(&store).await;
}

#[tokio::test]
async fn postgres_when_configured() {
    if let Some(store) = external("KEMLOCK_TEST_POSTGRES_URL").await {
        holds(&store).await;
    }
}

#[tokio::test]
async fn mysql_when_configured() {
    if let Some(store) = external("KEMLOCK_TEST_MYSQL_URL").await {
        holds(&store).await;
    }
}
