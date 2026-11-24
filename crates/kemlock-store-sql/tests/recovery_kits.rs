//! The Recovery Kit port: `RecoveryKitRepo`.
//!
//! Each scenario runs on every backend that is available, as `passkeys.rs` does: in-memory SQLite,
//! SQLite in a file, and PostgreSQL and MySQL when `KEMLOCK_TEST_POSTGRES_URL` /
//! `KEMLOCK_TEST_MYSQL_URL` are set.

mod common;

use common::{external, file, memory, unique_email, user};
use kemlock_app::ports::UserRepo;
use kemlock_app::recovery_kit::RecoveryKitRepo;
use kemlock_domain::{RecoveryKit, UserId};
use kemlock_store_sql::SqlStore;
use time::OffsetDateTime;
use time::macros::datetime;

const T0: OffsetDateTime = datetime!(2026-11-28 10:00:00 UTC);

async fn account(store: &SqlStore, prefix: &str) -> UserId {
    let account = user(&unique_email(prefix));
    UserRepo::insert(store, &account)
        .await
        .expect("insert user");
    account.id
}

fn kit(id: &str, byte: u8, version: u32) -> RecoveryKit {
    RecoveryKit {
        kit_id: id.to_owned(),
        wrapped_key: vec![byte; 92],
        key_version: version,
        created_at: T0,
    }
}

async fn kits(store: &SqlStore) {
    let sam = account(store, "kit-sam").await;
    let ada = account(store, "kit-ada").await;

    assert_eq!(store.recovery_kit(sam).await, Ok(None));
    assert_eq!(store.remove_recovery_kit(sam).await, Ok(false));
    assert_eq!(
        store
            .replace_recovery_kit(sam, &kit("AAAAAAAA", 1, 1))
            .await,
        Ok(false),
        "nothing to replace"
    );

    assert_eq!(
        store.insert_recovery_kit(sam, &kit("AAAAAAAA", 1, 1)).await,
        Ok(true)
    );
    assert_eq!(
        store.insert_recovery_kit(sam, &kit("BBBBBBBB", 2, 1)).await,
        Ok(false),
        "an account that has a kit keeps it"
    );
    assert_eq!(
        store.recovery_kit(sam).await,
        Ok(Some(kit("AAAAAAAA", 1, 1)))
    );

    assert_eq!(
        store
            .replace_recovery_kit(sam, &kit("CCCCCCCC", 3, 2))
            .await,
        Ok(true)
    );
    assert_eq!(
        store.recovery_kit(sam).await,
        Ok(Some(kit("CCCCCCCC", 3, 2)))
    );
    assert_eq!(store.recovery_kit(ada).await, Ok(None), "another account's");

    assert_eq!(store.remove_recovery_kit(sam).await, Ok(true));
    assert_eq!(store.remove_recovery_kit(sam).await, Ok(false));
    assert_eq!(store.recovery_kit(sam).await, Ok(None));
}

#[tokio::test]
async fn sqlite_in_memory() {
    kits(&memory().await).await;
}

#[tokio::test]
async fn sqlite_in_a_file() {
    let (store, _dir) = file().await;
    kits(&store).await;
}

#[tokio::test]
async fn postgres_when_configured() {
    if let Some(store) = external("KEMLOCK_TEST_POSTGRES_URL").await {
        kits(&store).await;
    }
}

#[tokio::test]
async fn mysql_when_configured() {
    if let Some(store) = external("KEMLOCK_TEST_MYSQL_URL").await {
        kits(&store).await;
    }
}
