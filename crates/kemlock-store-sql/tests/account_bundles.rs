//! An account's bundle history (docs/crypto.md, "Signed item writes", "Key versions"): every bundle
//! it has had stays readable by key version, whichever path replaced it.

mod common;

use common::{memory, unique_email, user};
use kemlock_app::ports::{StoredBundle, UserRepo};
use kemlock_domain::User;
use time::Duration;

fn rotated(user: &User, key_version: u32, fill: u8) -> User {
    User {
        public_bundle: vec![fill; 5000],
        bundle_signature: vec![fill + 1; 3400],
        key_version,
        updated_at: user.updated_at + Duration::days(1),
        ..user.clone()
    }
}

fn stored(user: &User) -> StoredBundle {
    StoredBundle {
        key_version: user.key_version,
        public_bundle: user.public_bundle.clone(),
        bundle_signature: user.bundle_signature.clone(),
    }
}

#[tokio::test]
async fn a_new_account_keeps_its_first_bundle() {
    let store = memory().await;
    let ada = user(&unique_email("ada"));
    UserRepo::insert(&store, &ada).await.expect("insert");
    assert_eq!(
        UserRepo::bundle_at(&store, ada.id, 1).await.expect("read"),
        Some(stored(&ada))
    );
    assert_eq!(
        UserRepo::bundle_at(&store, ada.id, 2).await.expect("read"),
        None
    );
}

#[tokio::test]
async fn a_key_replacement_keeps_the_bundle_before_it() {
    let store = memory().await;
    let ada = user(&unique_email("ada"));
    UserRepo::insert(&store, &ada).await.expect("insert");
    let second = rotated(&ada, 2, 20);
    UserRepo::update(&store, &second).await.expect("rotate");
    let third = rotated(&second, 3, 30);
    UserRepo::update(&store, &third)
        .await
        .expect("rotate again");

    for version in [&ada, &second, &third] {
        assert_eq!(
            UserRepo::bundle_at(&store, ada.id, version.key_version)
                .await
                .expect("read"),
            Some(stored(version)),
            "version {}",
            version.key_version
        );
    }
    assert_eq!(
        UserRepo::bundles_of(&store, ada.id).await.expect("read"),
        vec![stored(&ada), stored(&second), stored(&third)]
    );
    // The account itself is at the newest.
    assert_eq!(
        UserRepo::by_id(&store, ada.id)
            .await
            .expect("read")
            .map(|u| u.key_version),
        Some(3)
    );
}

#[tokio::test]
async fn the_current_version_is_the_accounts_row_and_a_version_kept_is_never_rewritten() {
    let store = memory().await;
    let ada = user(&unique_email("ada"));
    UserRepo::insert(&store, &ada).await.expect("insert");
    // Writing the account again with another bundle under the same version leaves the history as
    // it was, but a write is checked against the account's row, so the current version answers
    // with that.
    let other = rotated(&ada, 1, 90);
    UserRepo::update(&store, &other).await.expect("update");
    assert_eq!(
        UserRepo::bundle_at(&store, ada.id, 1).await.expect("read"),
        Some(stored(&other))
    );
    // Once the account moves on, the version before it is what the history kept first.
    let next = rotated(&other, 2, 50);
    UserRepo::update(&store, &next).await.expect("rotate");
    assert_eq!(
        UserRepo::bundle_at(&store, ada.id, 1).await.expect("read"),
        Some(stored(&ada))
    );
    assert_eq!(
        UserRepo::bundle_at(&store, ada.id, 2).await.expect("read"),
        Some(stored(&next))
    );
}

#[tokio::test]
async fn the_first_keys_of_an_account_are_kept_too() {
    let store = memory().await;
    let mut bare = user(&unique_email("sso"));
    bare.public_bundle = Vec::new();
    bare.bundle_signature = Vec::new();
    bare.sealed_private_keys = Vec::new();
    bare.key_version = 0;
    UserRepo::insert(&store, &bare).await.expect("insert");
    assert!(
        UserRepo::bundles_of(&store, bare.id)
            .await
            .expect("read")
            .is_empty()
    );

    let keyed = rotated(&bare, 1, 40);
    UserRepo::set_first_keys(&store, &keyed)
        .await
        .expect("first keys");
    assert_eq!(
        UserRepo::bundle_at(&store, bare.id, 1).await.expect("read"),
        Some(stored(&keyed))
    );
}

#[tokio::test]
async fn an_unknown_account_has_no_history() {
    let store = memory().await;
    let nobody = user(&unique_email("nobody"));
    assert_eq!(
        UserRepo::bundle_at(&store, nobody.id, 1)
            .await
            .expect("read"),
        None
    );
    assert!(
        UserRepo::bundles_of(&store, nobody.id)
            .await
            .expect("read")
            .is_empty()
    );
}

#[tokio::test]
async fn a_copy_of_a_rotated_account_carries_its_past_bundles_to_a_replica() {
    use kemlock_federation::extra::MemberStore;
    let home = memory().await;
    let replica = memory().await;
    let ada = user(&unique_email("ada"));
    UserRepo::insert(&home, &ada).await.expect("insert");
    let second = rotated(&ada, 2, 20);
    UserRepo::update(&home, &second).await.expect("rotate");

    // The home's copy of the account names the bundle before its current one.
    let copy = MemberStore::member_account(&home, ada.id)
        .await
        .expect("read")
        .expect("an account of the home");
    assert_eq!(copy.key_version, 2);
    assert_eq!(copy.past_bundles.len(), 1);
    assert_eq!(copy.past_bundles[0].key_version, 1);
    assert_eq!(copy.past_bundles[0].public_bundle, ada.public_bundle);

    // A replica that applies it can answer for either version.
    let vault = kemlock_domain::Owner::User(ada.id);
    let home_id = kemlock_domain::ServerId::random();
    MemberStore::apply_member_account(&replica, vault, home_id, &copy)
        .await
        .expect("applied");
    assert_eq!(
        MemberStore::writer_bundle(&replica, ada.id, 2)
            .await
            .expect("read"),
        Some(second.public_bundle.clone())
    );
    assert_eq!(
        MemberStore::writer_bundle(&replica, ada.id, 1)
            .await
            .expect("read"),
        Some(ada.public_bundle.clone())
    );
    assert_eq!(
        MemberStore::writer_bundle(&replica, ada.id, 3)
            .await
            .expect("read"),
        None
    );
}

#[tokio::test]
async fn a_bundle_says_when_the_account_replaced_it() {
    let store = memory().await;
    let ada = user(&unique_email("ada"));
    UserRepo::insert(&store, &ada).await.expect("insert");
    // Nothing has replaced the first yet.
    assert_eq!(
        UserRepo::bundle_retired_at(&store, ada.id, 1)
            .await
            .expect("read"),
        None
    );
    UserRepo::update(&store, &rotated(&ada, 2, 20))
        .await
        .expect("rotate");
    let first = UserRepo::bundle_retired_at(&store, ada.id, 1)
        .await
        .expect("read")
        .expect("replaced");
    assert!(first > 0);
    // The current one, and a version the account never had, have no end.
    for version in [2, 7] {
        assert_eq!(
            UserRepo::bundle_retired_at(&store, ada.id, version)
                .await
                .expect("read"),
            None
        );
    }
}
