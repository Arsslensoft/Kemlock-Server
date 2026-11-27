//! Shared by the integration tests: stores on each backend, and builders for domain values.
//!
//! Each test binary uses a different part of this, so unused items are fine.
#![allow(dead_code)]

use kemlock_app::ports::{ItemStore, StoreError};
use kemlock_domain::{
    AccountMode, Device, DeviceId, DeviceKind, Email, Item, ItemDraft, ItemFormat, ItemId,
    ItemKind, KdfParams, Owner, Revision, Role, User, UserId,
};
use kemlock_store_sql::SqlStore;
use std::path::Path;
use time::OffsetDateTime;
use time::macros::datetime;
use uuid::Uuid;

/// A fresh in-memory SQLite store.
pub(crate) async fn memory() -> SqlStore {
    SqlStore::connect("sqlite::memory:")
        .await
        .expect("an in-memory store connects")
}

pub(crate) fn file_url(path: &Path) -> String {
    format!(
        "sqlite://{}?mode=rwc",
        path.to_string_lossy().replace('\\', "/")
    )
}

/// A SQLite store in a file of its own; keep the directory alive as long as the store.
pub(crate) async fn file() -> (SqlStore, tempfile::TempDir) {
    let dir = tempfile::tempdir().expect("a temp dir");
    let url = file_url(&dir.path().join("kemlock.db"));
    let store = SqlStore::connect(&url)
        .await
        .expect("a file store connects");
    (store, dir)
}

/// A store on the server named by the environment variable, or `None` (with a note) when it is
/// not set, so PostgreSQL and MySQL tests run only where someone set a database up. The database
/// may hold earlier runs' rows, so tests use ids of their own.
pub(crate) async fn external(var: &str) -> Option<SqlStore> {
    match std::env::var(var) {
        Ok(url) if !url.is_empty() => Some(
            SqlStore::connect(&url)
                .await
                .expect("the external database connects"),
        ),
        _ => {
            eprintln!("{var} is not set; skipping");
            None
        }
    }
}

pub(crate) fn kind(name: &str) -> ItemKind {
    ItemKind::try_from(name.to_owned()).expect("a valid item kind")
}

pub(crate) fn user_owner() -> Owner {
    Owner::User(UserId::random())
}

/// The time every draft is made at unless a test says otherwise.
pub(crate) const MADE_AT: OffsetDateTime = datetime!(2026-06-01 12:00:00 UTC);

/// A live item draft; `expected` is the stored revision the write must find.
pub(crate) fn draft(id: ItemId, owner: Owner, expected: Option<u64>, revision: u64) -> ItemDraft {
    ItemDraft {
        id,
        owner,
        kind: kind("login"),
        format: ItemFormat::Kem1,
        expected: expected.map(Revision),
        revision: Revision(revision),
        key_version: 1,
        ciphertext: Some(vec![(revision % 251) as u8; 40]),
        item_key: Some(vec![9; 60]),
        deleted_at: None,
        updated_at: MADE_AT,
        signature: None,
    }
}

/// A deletion: a tombstone with no ciphertext.
pub(crate) fn tombstone(
    id: ItemId,
    owner: Owner,
    expected: Option<u64>,
    revision: u64,
    at: OffsetDateTime,
) -> ItemDraft {
    ItemDraft {
        ciphertext: None,
        item_key: None,
        deleted_at: Some(at),
        updated_at: at,
        ..draft(id, owner, expected, revision)
    }
}

pub(crate) async fn put(store: &SqlStore, draft: ItemDraft) -> Item {
    ItemStore::put(store, draft)
        .await
        .expect("the write is accepted")
}

pub(crate) async fn put_err(store: &SqlStore, draft: ItemDraft) -> StoreError {
    ItemStore::put(store, draft)
        .await
        .expect_err("the write is refused")
}

pub(crate) fn user(email: &str) -> User {
    User {
        id: UserId::random(),
        email: Email::parse(email).expect("a valid email"),
        name: Some("Test User".to_owned()),
        mode: AccountMode::KemlockOnly,
        role: Role::User,
        kdf: KdfParams::new_account([3; 16]),
        opaque_record: Some(vec![1; 192]),
        wrapped_root_key: vec![2; 100],
        public_bundle: vec![3; 5000],
        bundle_signature: vec![4; 3400],
        sealed_private_keys: vec![5; 8000],
        key_version: 1,
        security_stamp: Uuid::new_v4(),
        created_at: datetime!(2026-01-02 03:04:05 UTC),
        updated_at: datetime!(2026-01-02 03:04:05 UTC),
    }
}

/// An address no other test run shares, so a database kept between runs holds no clash.
pub(crate) fn unique_email(prefix: &str) -> String {
    format!("{prefix}-{}@example.org", Uuid::new_v4().simple())
}

pub(crate) fn device(user: UserId, name: &str, created_at: OffsetDateTime) -> Device {
    Device {
        id: DeviceId::random(),
        user,
        name: name.to_owned(),
        kind: DeviceKind::KemlockAndroid,
        dpop_jkt: Some("thumbprint".to_owned()),
        created_at,
        last_seen_at: created_at,
    }
}
