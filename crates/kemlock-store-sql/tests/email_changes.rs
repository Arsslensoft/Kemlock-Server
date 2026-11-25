//! The profile port: `ProfileRepo`, the pending change of sign-in address, the single sign-on
//! link that makes an account's name and address its identity provider's, and the two conditional
//! writes that replace an account's sign-in records (with the emergency-access grants that follow
//! a new address).
//!
//! Each scenario runs on every backend that is available, as `recovery_kits.rs` does: in-memory
//! SQLite, SQLite in a file, and PostgreSQL and MySQL when `KEMLOCK_TEST_POSTGRES_URL` /
//! `KEMLOCK_TEST_MYSQL_URL` are set.

mod common;

use common::{external, file, memory, unique_email, user};
use kemlock_app::emergency::EmergencyRepo;
use kemlock_app::ports::{StoreError, UserRepo};
use kemlock_app::profile::ProfileRepo;
use kemlock_app::sso::{SsoIdentity, SsoIdentityRepo};
use kemlock_domain::unlock::{EmergencyGrant, EmergencyKind, GrantId};
use kemlock_domain::{Email, EmailChange, KdfParams, User, UserId};
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
    assert_eq!(store.email_change_by_token(first_hash).await, Ok(None));
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
    assert_eq!(store.email_change_by_token(first_hash).await, Ok(None));

    // Another account has its own.
    let other = change(ada, &ada_new, ada_hash);
    store.put_email_change(&other).await.expect("keeps");

    // A link finds its change by its token's hash, and leaves it where it is: it is spent by the
    // write that makes the change, not by looking at it.
    assert_eq!(
        store.email_change_by_token(second_hash).await,
        Ok(Some(second.clone()))
    );
    assert_eq!(
        store.email_change_by_token(second_hash).await,
        Ok(Some(second.clone()))
    );
    assert_eq!(store.email_change_of(ada).await, Ok(Some(other.clone())));

    // Taking an ask back removes it, and its link finds nothing.
    store.remove_email_change(ada).await.expect("removes");
    assert_eq!(store.email_change_of(ada).await, Ok(None));
    assert_eq!(store.email_change_by_token(ada_hash).await, Ok(None));
    store.remove_email_change(sam).await.expect("removes");
    assert_eq!(store.email_change_by_token(second_hash).await, Ok(None));

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
    assert!(store.email_change_of(sam).await.expect("reads").is_some());
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
    assert_eq!(store.email_change_by_token(token_hash).await, Ok(None));
}

async fn read(store: &SqlStore, id: UserId) -> User {
    UserRepo::by_id(store, id)
        .await
        .expect("reads")
        .expect("the account")
}

/// `before` with new sign-in records, a new stamp when asked, and a later write time.
fn with_new_records(before: &User, byte: u8, new_stamp: bool) -> User {
    User {
        opaque_record: Some(vec![byte; 192]),
        kdf: KdfParams::new_account([byte; 16]),
        wrapped_root_key: vec![byte; 92],
        security_stamp: if new_stamp {
            Uuid::new_v4()
        } else {
            before.security_stamp
        },
        updated_at: before.updated_at + Duration::hours(1),
        ..before.clone()
    }
}

async fn replacing_credentials(store: &SqlStore) {
    let sam = account(store, "replace-sam").await;
    let before = read(store, sam).await;
    store
        .put_email_change(&change(sam, &unique_email("replace-new"), hash()))
        .await
        .expect("keeps");

    // The records, the settings, the wrap, the stamp and the time are replaced, and the rest of
    // the row, the keys and the address among it, is not.
    let after = with_new_records(&before, 9, true);
    assert_eq!(store.replace_credentials(&before, &after).await, Ok(true));
    let now = read(store, sam).await;
    assert_eq!(now.opaque_record, after.opaque_record);
    assert_eq!(now.kdf, after.kdf);
    assert_eq!(now.wrapped_root_key, after.wrapped_root_key);
    assert_eq!(now.security_stamp, after.security_stamp);
    assert_eq!(now.updated_at, after.updated_at);
    assert_eq!(now.email, before.email);
    assert_eq!(now.public_bundle, before.public_bundle);
    assert_eq!(now.sealed_private_keys, before.sealed_private_keys);
    assert_eq!(now.key_version, before.key_version);
    // The change of address made from the old password went with it.
    assert_eq!(store.email_change_of(sam).await, Ok(None));

    // A write from a copy of the row that is out of date happens not at all.
    let stale = with_new_records(&before, 5, true);
    assert_eq!(store.replace_credentials(&before, &stale).await, Ok(false));
    assert_eq!(read(store, sam).await, now);

    // Another request writes the account between the read and the write: the write finds the row
    // changed and leaves what the other wrote, whatever the copy it holds says.
    let held = read(store, sam).await;
    let mut renamed = held.clone();
    renamed.name = Some("Someone Else".to_owned());
    renamed.updated_at = held.updated_at + Duration::minutes(1);
    UserRepo::update(store, &renamed).await.expect("renames");
    let attempt = with_new_records(&held, 4, false);
    assert_eq!(store.replace_credentials(&held, &attempt).await, Ok(false));
    assert_eq!(read(store, sam).await, renamed);

    // An account's stamp changing is as good a sign of another write as its time.
    let held = read(store, sam).await;
    let mut disabled_elsewhere = held.clone();
    disabled_elsewhere.security_stamp = Uuid::new_v4();
    UserRepo::update(store, &disabled_elsewhere)
        .await
        .expect("changes the stamp");
    let mut same_time = with_new_records(&held, 3, false);
    same_time.updated_at = held.updated_at;
    assert_eq!(
        store.replace_credentials(&held, &same_time).await,
        Ok(false)
    );

    // Without a new stamp the write still goes through, with the stamp left as it was.
    let held = read(store, sam).await;
    let kept = with_new_records(&held, 2, false);
    assert_eq!(store.replace_credentials(&held, &kept).await, Ok(true));
    assert_eq!(read(store, sam).await.security_stamp, held.security_stamp);

    // No such account is no match either.
    let ghost = user(&unique_email("replace-ghost"));
    assert_eq!(
        store
            .replace_credentials(&ghost, &with_new_records(&ghost, 1, true))
            .await,
        Ok(false)
    );
}

/// An invitation from `grantor` to `contact`, accepted by `grantee` when one is given.
async fn grant(
    store: &SqlStore,
    grantor: UserId,
    contact: &str,
    grantee: Option<UserId>,
) -> EmergencyGrant {
    let mut grant = EmergencyGrant::invite(
        GrantId::random(),
        grantor,
        Email::parse(contact).expect("an address"),
        EmergencyKind::Takeover,
        7,
        T0,
    )
    .expect("a grant");
    grant.grantee = grantee;
    EmergencyRepo::insert_grant(store, &grant)
        .await
        .expect("inserts");
    grant
}

async fn grant_email(store: &SqlStore, id: GrantId) -> String {
    EmergencyRepo::grant(store, id)
        .await
        .expect("reads")
        .expect("the grant")
        .grantee_email
        .as_str()
        .to_owned()
}

async fn applying_an_address(store: &SqlStore) {
    let old = unique_email("apply-old");
    let new = unique_email("apply-new");
    let sam = user(&old);
    UserRepo::insert(store, &sam).await.expect("inserts");
    let ada = account(store, "apply-ada").await;
    let bob = account(store, "apply-bob").await;
    let kim = account(store, "apply-kim").await;
    let lee = account(store, "apply-lee").await;
    // Ada's contact is Sam, who accepted. Bob's invitation to the old address waits. Kim has
    // invited both addresses. Lee invited someone else.
    let accepted = grant(store, ada, &old, Some(sam.id)).await;
    let waiting = grant(store, bob, &old, None).await;
    let kim_old = grant(store, kim, &old, None).await;
    let kim_new = grant(store, kim, &new, None).await;
    let someone_else = unique_email("apply-else");
    let unrelated = grant(store, lee, &someone_else, None).await;

    let token_hash = hash();
    let pending = change(sam.id, &new, token_hash);
    store.put_email_change(&pending).await.expect("keeps");
    let before = read(store, sam.id).await;
    let after = User {
        email: pending.email.clone(),
        ..with_new_records(&before, 6, true)
    };

    // A copy of the row that is out of date applies nothing, and the link is still good.
    let mut moved_on = before.clone();
    moved_on.updated_at = before.updated_at + Duration::minutes(1);
    UserRepo::update(store, &moved_on).await.expect("writes");
    assert_eq!(
        store.apply_email_change(&pending, &before, &after).await,
        Ok(false)
    );
    assert_eq!(read(store, sam.id).await, moved_on);
    assert_eq!(
        store.email_change_by_token(token_hash).await,
        Ok(Some(pending.clone()))
    );
    assert_eq!(grant_email(store, accepted.id).await, old);

    // A change that is not the account's pending one (spent, replaced) applies nothing either, and
    // the update that came first is rolled back with it.
    let before = read(store, sam.id).await;
    let after = User {
        email: pending.email.clone(),
        ..with_new_records(&before, 6, true)
    };
    let not_pending = change(sam.id, &new, hash());
    assert_eq!(
        store
            .apply_email_change(&not_pending, &before, &after)
            .await,
        Ok(false)
    );
    assert_eq!(read(store, sam.id).await, before);
    assert_eq!(grant_email(store, accepted.id).await, old);

    // Applied: the address, the records and the stamp are the new ones, the change is spent, and
    // the grants follow the address.
    assert_eq!(
        store.apply_email_change(&pending, &before, &after).await,
        Ok(true)
    );
    let now = read(store, sam.id).await;
    assert_eq!(now.email.as_str(), new);
    assert_eq!(now.opaque_record, after.opaque_record);
    assert_eq!(now.kdf, after.kdf);
    assert_eq!(now.wrapped_root_key, after.wrapped_root_key);
    assert_eq!(now.security_stamp, after.security_stamp);
    assert_eq!(now.public_bundle, before.public_bundle);
    assert_eq!(now.name, before.name);
    assert_eq!(store.email_change_of(sam.id).await, Ok(None));
    assert_eq!(store.email_change_by_token(token_hash).await, Ok(None));
    // A link is good once: the same change can't be applied again.
    assert_eq!(
        store
            .apply_email_change(&pending, &now, &with_new_records(&now, 7, true))
            .await,
        Ok(false)
    );
    assert_eq!(
        grant_email(store, accepted.id).await,
        new,
        "a contact who accepted"
    );
    assert_eq!(
        grant_email(store, waiting.id).await,
        new,
        "an invitation at the old address"
    );
    assert_eq!(
        grant_email(store, kim_old.id).await,
        old,
        "the grantor has a grant to the new address already: both stay as they were"
    );
    assert_eq!(grant_email(store, kim_new.id).await, new);
    assert_eq!(grant_email(store, unrelated.id).await, someone_else);
    // The grants the account is the contact of are found at the new address.
    let at_new = EmergencyRepo::grants_for_email(store, &now.email)
        .await
        .expect("reads");
    let found: Vec<GrantId> = at_new.iter().map(|g| g.id).collect();
    assert!(found.contains(&accepted.id) && found.contains(&waiting.id));
}

async fn applying_a_taken_address(store: &SqlStore) {
    let sam = account(store, "taken-sam").await;
    let taker = user(&unique_email("taken-by"));
    UserRepo::insert(store, &taker).await.expect("inserts");
    let token_hash = hash();
    let pending = change(sam, taker.email.as_str(), token_hash);
    store.put_email_change(&pending).await.expect("keeps");
    let before = read(store, sam).await;
    let after = User {
        email: pending.email.clone(),
        ..with_new_records(&before, 8, true)
    };

    // The unique address refuses it, and nothing is written: the account, the change and the
    // link stay as they were.
    assert_eq!(
        store.apply_email_change(&pending, &before, &after).await,
        Err(StoreError::Duplicate)
    );
    assert_eq!(read(store, sam).await, before);
    assert_eq!(
        store.email_change_by_token(token_hash).await,
        Ok(Some(pending))
    );
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
    replacing_credentials(&store).await;
    applying_an_address(&store).await;
    applying_a_taken_address(&store).await;
    sso(&store).await;
}

#[tokio::test]
async fn sqlite_in_a_file() {
    let (store, _dir) = file().await;
    changes(&store).await;
    cascade(&store).await;
    replacing_credentials(&store).await;
    applying_an_address(&store).await;
    applying_a_taken_address(&store).await;
    sso(&store).await;
}

#[tokio::test]
async fn postgres_when_configured() {
    if let Some(store) = external("KEMLOCK_TEST_POSTGRES_URL").await {
        changes(&store).await;
        cascade(&store).await;
        replacing_credentials(&store).await;
        applying_an_address(&store).await;
        applying_a_taken_address(&store).await;
        sso(&store).await;
    }
}

#[tokio::test]
async fn mysql_when_configured() {
    if let Some(store) = external("KEMLOCK_TEST_MYSQL_URL").await {
        changes(&store).await;
        cascade(&store).await;
        replacing_credentials(&store).await;
        applying_an_address(&store).await;
        applying_a_taken_address(&store).await;
        sso(&store).await;
    }
}
