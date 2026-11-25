//! The profile port: `ProfileRepo`, the pending change of sign-in address and the single sign-on
//! link that makes an account's name and address its identity provider's.
//!
//! Each scenario runs on every backend that is available, as `recovery_kits.rs` does: in-memory
//! SQLite, SQLite in a file, and PostgreSQL and MySQL when `KEMLOCK_TEST_POSTGRES_URL` /
//! `KEMLOCK_TEST_MYSQL_URL` are set.

mod common;

use common::{external, file, memory, unique_email, user};
use kemlock_app::ports::{StoreError, UserRepo};
use kemlock_app::profile::ProfileRepo;
use kemlock_app::sso::{SsoIdentity, SsoIdentityRepo};
use kemlock_domain::{Email, EmailChange, KdfParams, UserId};
use kemlock_store_sql::SqlStore;
use time::OffsetDateTime;
use time::macros::datetime;
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

/// A pending change for `user` to `new_email`, whose link holds the token with this hash.
fn change(user: UserId, new_email: &str, token_hash: [u8; 32]) -> EmailChange {
    EmailChange {
        user,
        email: Email::parse(new_email).expect("an address"),
        token_hash,
        opaque_record: vec![token_hash[0]; 192],
        kdf: KdfParams::new_account([token_hash[1]; 16]),
        wrapped_root_key: vec![token_hash[2]; 92],
        requested_at: T0,
        expires_at: T0 + EmailChange::LIFETIME,
    }
}

async fn changes(store: &SqlStore) {
    let sam = account(store, "change-sam").await;
    let ada = account(store, "change-ada").await;
    let sam_new = unique_email("change-sam-new");
    let ada_new = unique_email("change-ada-new");
    let (first_hash, second_hash, ada_hash) = (hash(), hash(), hash());

    assert_eq!(store.email_change_of(sam).await, Ok(None));
    assert_eq!(store.take_email_change(first_hash).await, Ok(None));
    store
        .remove_email_change(sam)
        .await
        .expect("nothing to remove is fine");

    // The first ask is kept whole.
    let first = change(sam, &sam_new, first_hash);
    store.put_email_change(&first).await.expect("keeps");
    assert_eq!(store.email_change_of(sam).await, Ok(Some(first.clone())));
    assert_eq!(
        store.email_change_of(ada).await,
        Ok(None),
        "another account's"
    );

    // A new ask replaces the one before: the old token no longer finds anything.
    let second = change(sam, &sam_new, second_hash);
    store.put_email_change(&second).await.expect("replaces");
    assert_eq!(store.email_change_of(sam).await, Ok(Some(second.clone())));
    assert_eq!(store.take_email_change(first_hash).await, Ok(None));

    // Another account has its own.
    let other = change(ada, &ada_new, ada_hash);
    store.put_email_change(&other).await.expect("keeps");

    // A link is taken once, by its token's hash, and takes nothing of the other account's.
    assert_eq!(
        store.take_email_change(second_hash).await,
        Ok(Some(second.clone()))
    );
    assert_eq!(store.take_email_change(second_hash).await, Ok(None));
    assert_eq!(store.email_change_of(sam).await, Ok(None));
    assert_eq!(store.email_change_of(ada).await, Ok(Some(other.clone())));

    // Taking an ask back removes it, and its link finds nothing.
    store.remove_email_change(ada).await.expect("removes");
    assert_eq!(store.email_change_of(ada).await, Ok(None));
    assert_eq!(store.take_email_change(ada_hash).await, Ok(None));

    // A change for an account that doesn't exist is refused by the foreign key.
    let nobody = change(UserId::random(), &unique_email("nobody"), hash());
    assert_eq!(
        store.put_email_change(&nobody).await,
        Err(StoreError::NotFound)
    );
}

async fn cascade(store: &SqlStore) {
    let sam = account(store, "cascade-sam").await;
    let token_hash = hash();
    store
        .put_email_change(&change(sam, &unique_email("cascade-new"), token_hash))
        .await
        .expect("keeps");
    assert!(
        store
            .email_change_of(sam)
            .await
            .expect("reads")
            .is_some()
    );
    // Erasing the account leaves no pending change behind: the foreign key cascades.
    kemlock_app::privacy::AccountEraser::erase_user(
        store,
        &UserRepo::by_id(store, sam)
            .await
            .expect("reads")
            .expect("the account"),
    )
    .await
    .expect("erases");
    assert_eq!(store.email_change_of(sam).await, Ok(None));
    assert_eq!(store.take_email_change(token_hash).await, Ok(None));
}

async fn sso(store: &SqlStore) {
    let ada = account(store, "sso-ada").await;
    let bob = account(store, "sso-bob").await;
    assert_eq!(store.has_sso_identity(ada).await, Ok(false));

    SsoIdentityRepo::insert_identity(
        store,
        &SsoIdentity {
            issuer: format!("https://idp.example.org/{}", Uuid::new_v4().simple()),
            subject: "sub-ada".to_owned(),
            user: ada,
            email: "ada@example.org".to_owned(),
            linked_at: T0,
            last_login_at: T0,
        },
    )
    .await
    .expect("links");

    assert_eq!(store.has_sso_identity(ada).await, Ok(true));
    assert_eq!(store.has_sso_identity(bob).await, Ok(false), "only hers");
}

#[tokio::test]
async fn sqlite_in_memory() {
    let store = memory().await;
    changes(&store).await;
    cascade(&store).await;
    sso(&store).await;
}

#[tokio::test]
async fn sqlite_in_a_file() {
    let (store, _dir) = file().await;
    changes(&store).await;
    cascade(&store).await;
    sso(&store).await;
}

#[tokio::test]
async fn postgres_when_configured() {
    if let Some(store) = external("KEMLOCK_TEST_POSTGRES_URL").await {
        changes(&store).await;
        cascade(&store).await;
        sso(&store).await;
    }
}

#[tokio::test]
async fn mysql_when_configured() {
    if let Some(store) = external("KEMLOCK_TEST_MYSQL_URL").await {
        changes(&store).await;
        cascade(&store).await;
        sso(&store).await;
    }
}
