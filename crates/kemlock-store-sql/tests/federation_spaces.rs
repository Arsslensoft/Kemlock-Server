//! A space's roles, keys and policies as home records, on SQL: the snapshot a home reads, and what
//! a replica's store holds after it applies the records.

mod common;

use common::memory;
use kemlock_app::policies::PolicyRepo;
use kemlock_app::spaces::{SpaceChanges, SpaceRepo};
use kemlock_domain::policies::SpacePolicies;
use kemlock_domain::spaces::{
    Collection, CollectionGrant, CollectionId, CollectionPermission, CustomPermissions, Grantee,
    Group, GroupId, KeyCopy, Member, MemberState, Space, SpaceRole,
};
use kemlock_domain::{ItemId, SpaceId, UserId};
use kemlock_federation::spaces::{SpaceMirror, SpaceRecord, SpaceSnapshot};
use time::OffsetDateTime;
use time::macros::datetime;

const AT: OffsetDateTime = datetime!(2026-06-01 12:00:00 UTC);

fn member(space: SpaceId, user: UserId, role: SpaceRole, state: MemberState) -> Member {
    let confirmed = state == MemberState::Confirmed;
    Member {
        space,
        user,
        role,
        custom: CustomPermissions::NONE,
        state,
        invited_by: user,
        invited_at: AT,
        accepted_at: Some(AT),
        sealed_space_key: confirmed.then(|| vec![5; 64]),
        key_version: confirmed.then_some(1),
        confirmation: None,
        revoked_at: None,
    }
}

/// The records the home would publish for a snapshot, each carried through its payload.
fn records(space: SpaceId, snap: &SpaceSnapshot) -> Vec<SpaceRecord> {
    let mut out = vec![SpaceRecord::Space(snap.state.space.clone())];
    out.extend(snap.state.members.iter().cloned().map(SpaceRecord::Member));
    out.extend(snap.state.groups.iter().cloned().map(SpaceRecord::Group));
    for c in &snap.state.collections {
        out.push(SpaceRecord::Collection {
            collection: c.clone(),
            grants: snap
                .state
                .grants
                .iter()
                .filter(|g| g.collection == c.id)
                .copied()
                .collect(),
        });
    }
    for (user, copies) in &snap.key_copies {
        out.push(SpaceRecord::Keys {
            user: *user,
            copies: copies.clone(),
        });
    }
    if let Some(p) = &snap.policies {
        out.push(SpaceRecord::Policies(p.clone()));
    }
    out.into_iter()
        .map(|r| {
            SpaceRecord::from_record(space, r.kind(), &r.payload(space))
                .expect("a payload")
                .expect("a space kind")
        })
        .collect()
}

#[tokio::test]
async fn a_space_travels_between_two_stores_as_records() {
    let home = memory().await;
    let replica = memory().await;
    let space = SpaceId::random();
    let owner = UserId::random();
    let invited = UserId::random();
    let collection = Collection {
        id: CollectionId::random(),
        space,
        parent: None,
        name: vec![2; 40],
        key_version: 1,
        stale_since: None,
        created_at: AT,
    };
    let group = Group {
        id: GroupId::random(),
        space,
        name: vec![3; 40],
        members: [owner, invited].into_iter().collect(),
        created_at: AT,
    };
    SpaceRepo::create(
        &home,
        SpaceChanges {
            space: Some(Space {
                id: space,
                name: vec![1; 40],
                key_version: 1,
                keys_pending_since: None,
                created_at: AT,
                updated_at: AT,
            }),
            members: vec![
                member(space, owner, SpaceRole::Owner, MemberState::Confirmed),
                member(space, invited, SpaceRole::Member, MemberState::Invited),
            ],
            groups: vec![group],
            collections: vec![collection.clone()],
            grants: vec![
                CollectionGrant {
                    collection: collection.id,
                    grantee: Grantee::Member(owner),
                    permission: CollectionPermission::Manage,
                },
                CollectionGrant {
                    collection: collection.id,
                    grantee: Grantee::Member(invited),
                    permission: CollectionPermission::View,
                },
            ],
            key_copies: vec![KeyCopy {
                collection: collection.id,
                user: owner,
                key_version: 1,
                sealed: vec![9; 80],
            }],
            ..SpaceChanges::new(space)
        },
    )
    .await
    .expect("a space");
    PolicyRepo::put_space_policies(
        &home,
        space,
        &SpacePolicies {
            require_sso: true,
            ..SpacePolicies::default()
        },
        owner,
        AT,
    )
    .await
    .expect("policies");

    // The snapshot holds the confirmed member only, with what was sealed to them.
    let snap = SpaceMirror::space_snapshot(&home, space)
        .await
        .expect("a snapshot")
        .expect("the space");
    assert_eq!(snap.state.members.len(), 1);
    assert_eq!(snap.state.members[0].user, owner);
    assert_eq!(
        snap.state.groups[0].members.len(),
        1,
        "the invited one is not published"
    );
    assert_eq!(snap.state.grants.len(), 1);
    assert_eq!(snap.key_copies.len(), 1);
    assert_eq!(snap.key_copies[0].1.len(), 1);
    assert!(
        snap.policies
            .as_ref()
            .is_some_and(|p| p.policies.require_sso)
    );
    assert_eq!(
        SpaceMirror::space_snapshot(&home, SpaceId::random())
            .await
            .expect("no error"),
        None
    );

    // The replica applies the records in order, and then holds the same space.
    for record in records(space, &snap) {
        SpaceMirror::apply_space_record(&replica, space, &record)
            .await
            .expect("applied");
    }
    let held = SpaceMirror::space_snapshot(&replica, space)
        .await
        .expect("a snapshot")
        .expect("the space");
    assert_eq!(held.state.space, snap.state.space);
    assert_eq!(held.state.members, snap.state.members);
    assert_eq!(held.state.groups, snap.state.groups);
    assert_eq!(held.state.collections, snap.state.collections);
    assert_eq!(held.state.grants, snap.state.grants);
    assert_eq!(held.key_copies, snap.key_copies);
    assert_eq!(
        held.policies.as_ref().map(|p| p.policies.clone()),
        snap.policies.as_ref().map(|p| p.policies.clone())
    );

    // A grant that went away at the home goes at the replica; a role change replaces the row.
    let mut promoted = snap.state.members[0].clone();
    promoted.role = SpaceRole::Admin;
    let c = snap.state.collections[0].clone();
    for record in [
        SpaceRecord::Member(promoted),
        SpaceRecord::Collection {
            collection: c,
            grants: Vec::new(),
        },
    ] {
        SpaceMirror::apply_space_record(&replica, space, &record)
            .await
            .expect("applied");
    }
    let held = SpaceMirror::space_snapshot(&replica, space)
        .await
        .expect("a snapshot")
        .expect("the space");
    assert_eq!(held.state.members[0].role, SpaceRole::Admin);
    assert!(held.state.grants.is_empty());

    // A member who is gone takes their seat, grants and keys with them.
    SpaceMirror::apply_space_record(&replica, space, &SpaceRecord::MemberGone(owner))
        .await
        .expect("applied");
    SpaceMirror::apply_space_record(&replica, space, &SpaceRecord::KeysGone(owner))
        .await
        .expect("applied");
    let held = SpaceMirror::space_snapshot(&replica, space)
        .await
        .expect("a snapshot")
        .expect("the space");
    assert!(held.state.members.is_empty());
    assert!(held.key_copies.is_empty());
}

#[tokio::test]
async fn a_record_that_comes_before_its_space_is_ignored() {
    let replica = memory().await;
    let space = SpaceId::random();
    let user = UserId::random();
    SpaceMirror::apply_space_record(
        &replica,
        space,
        &SpaceRecord::Member(member(
            space,
            user,
            SpaceRole::Owner,
            MemberState::Confirmed,
        )),
    )
    .await
    .expect("ignored, not an error");
    assert_eq!(
        SpaceMirror::space_snapshot(&replica, space)
            .await
            .expect("no error"),
        None
    );
}

#[tokio::test]
async fn the_held_items_of_a_space_travel_as_a_set_the_replica_replaces() {
    let home = memory().await;
    let replica = memory().await;
    let space = SpaceId::random();
    let owner = UserId::random();
    SpaceRepo::create(
        &home,
        SpaceChanges {
            space: Some(Space {
                id: space,
                name: vec![1; 40],
                key_version: 1,
                keys_pending_since: None,
                created_at: AT,
                updated_at: AT,
            }),
            members: vec![member(
                space,
                owner,
                SpaceRole::Owner,
                MemberState::Confirmed,
            )],
            ..SpaceChanges::new(space)
        },
    )
    .await
    .expect("a space");
    let mut items = [ItemId::random(), ItemId::random(), ItemId::random()];
    items.sort();

    // The home's snapshot says which items its key replacement left held.
    let none = SpaceMirror::space_snapshot(&home, space)
        .await
        .expect("a snapshot")
        .expect("the space");
    assert!(none.held.is_empty());
    home.hold_items(space, &[items[1], items[0]])
        .await
        .expect("held");
    let snap = SpaceMirror::space_snapshot(&home, space)
        .await
        .expect("a snapshot")
        .expect("the space");
    assert_eq!(snap.held, vec![items[0], items[1]]);

    // The replica keeps the same held state once it applies the record the home would publish,
    // so it doesn't serve those items as live.
    let record = SpaceRecord::from_record(
        space,
        SpaceRecord::Held(snap.held.clone()).kind(),
        &SpaceRecord::Held(snap.held.clone()).payload(space),
    )
    .expect("a payload")
    .expect("a space kind");
    SpaceMirror::apply_space_record(&replica, space, &record)
        .await
        .expect("applied");
    assert_eq!(
        replica.held_items(space).await.expect("held"),
        vec![items[0], items[1]]
    );

    // A later record is the set as it is then: one item released, another held, and finally none.
    SpaceMirror::apply_space_record(
        &replica,
        space,
        &SpaceRecord::Held(vec![items[1], items[2]]),
    )
    .await
    .expect("applied");
    assert_eq!(
        replica.held_items(space).await.expect("held"),
        vec![items[1], items[2]]
    );
    SpaceMirror::apply_space_record(&replica, space, &SpaceRecord::Held(Vec::new()))
        .await
        .expect("applied");
    assert!(replica.held_items(space).await.expect("held").is_empty());
}
