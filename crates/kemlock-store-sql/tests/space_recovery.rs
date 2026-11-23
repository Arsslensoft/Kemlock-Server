//! Recovery boxes on SQLite: one per space and member, replaced by a new one, and gone with a
//! member who is revoked or removed.

mod common;

use common::memory;
use kemlock_app::spaces::{RecoveryBox, SpaceChanges, SpaceRecoveryRepo, SpaceRepo};
use kemlock_domain::spaces::{CustomPermissions, Member, MemberState, Space, SpaceRole};
use kemlock_domain::{SpaceId, UserId};
use kemlock_store_sql::SqlStore;
use time::OffsetDateTime;
use time::macros::datetime;
use uuid::Uuid;

const NOW: OffsetDateTime = datetime!(2026-06-01 12:00:00 UTC);

fn confirmed(space: SpaceId, user: UserId, role: SpaceRole) -> Member {
    let mut m = Member::invited(space, user, role, CustomPermissions::NONE, user, NOW);
    m.state = MemberState::Confirmed;
    m
}

fn boxed(space: SpaceId, user: UserId, key_seq: u64, fill: u8) -> RecoveryBox {
    RecoveryBox {
        space,
        user,
        key_seq,
        sealed: vec![fill; 1693],
        enrolled_at: NOW,
    }
}

/// A space with an owner and a member.
async fn space_of_two(store: &SqlStore) -> (SpaceId, UserId, UserId) {
    let space = SpaceId(Uuid::new_v4());
    let sam = UserId(Uuid::new_v4());
    let ana = UserId(Uuid::new_v4());
    let mut changes = SpaceChanges::new(space);
    changes.space = Some(Space {
        id: space,
        name: vec![7; 40],
        key_version: 1,
        keys_pending_since: None,
        created_at: NOW,
        updated_at: NOW,
    });
    changes.members = vec![
        confirmed(space, sam, SpaceRole::Owner),
        confirmed(space, ana, SpaceRole::Member),
    ];
    store.create(changes).await.expect("the space is made");
    (space, sam, ana)
}

#[tokio::test]
async fn a_box_is_kept_replaced_and_withdrawn() {
    let store = memory().await;
    let (space, sam, ana) = space_of_two(&store).await;
    assert_eq!(store.recovery_box(space, ana).await.expect("reads"), None);

    store
        .put_recovery_box(boxed(space, ana, 5, 1))
        .await
        .expect("stored");
    store
        .put_recovery_box(boxed(space, sam, 5, 2))
        .await
        .expect("stored");
    assert_eq!(
        store.recovery_box(space, ana).await.expect("reads"),
        Some(boxed(space, ana, 5, 1))
    );

    // A new box replaces the member's, and only theirs.
    store
        .put_recovery_box(boxed(space, ana, 8, 3))
        .await
        .expect("replaced");
    assert_eq!(
        store.recovery_box(space, ana).await.expect("reads"),
        Some(boxed(space, ana, 8, 3))
    );
    assert_eq!(
        store.recovery_box(space, sam).await.expect("reads"),
        Some(boxed(space, sam, 5, 2))
    );

    assert!(
        store
            .delete_recovery_box(space, ana)
            .await
            .expect("withdrawn")
    );
    assert!(
        !store
            .delete_recovery_box(space, ana)
            .await
            .expect("nothing to withdraw")
    );
    assert_eq!(store.recovery_box(space, ana).await.expect("reads"), None);
}

#[tokio::test]
async fn a_revoked_or_removed_member_takes_their_box_with_them() {
    let store = memory().await;
    let (space, sam, ana) = space_of_two(&store).await;
    for user in [sam, ana] {
        store
            .put_recovery_box(boxed(space, user, 5, 1))
            .await
            .expect("stored");
    }

    let mut revoke = SpaceChanges::new(space);
    let mut revoked = confirmed(space, ana, SpaceRole::Member);
    revoked.state = MemberState::Revoked;
    revoke.members = vec![revoked];
    store.apply(revoke).await.expect("ana is revoked");
    assert_eq!(store.recovery_box(space, ana).await.expect("reads"), None);
    assert!(
        store
            .recovery_box(space, sam)
            .await
            .expect("reads")
            .is_some()
    );

    store
        .put_recovery_box(boxed(space, ana, 5, 1))
        .await
        .expect("stored again");
    let mut remove = SpaceChanges::new(space);
    remove.members_removed = vec![ana];
    store.apply(remove).await.expect("ana is removed");
    assert_eq!(store.recovery_box(space, ana).await.expect("reads"), None);
    assert!(
        store
            .recovery_box(space, sam)
            .await
            .expect("reads")
            .is_some()
    );
}
