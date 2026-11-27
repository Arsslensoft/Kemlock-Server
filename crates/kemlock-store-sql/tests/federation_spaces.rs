//! A space's roles, keys and policies as home records, on SQL: the snapshot a home reads, and what
//! a replica's store holds after it applies the records.

mod common;

use common::{draft, memory, put};
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
        sealed_by: None,
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
                sealed_by: None,
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
    // The replica holds the space's items (they are pulled before the home records).
    for item in items {
        put(
            &replica,
            draft(item, kemlock_domain::Owner::Space(space), None, 1),
        )
        .await;
    }

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

#[tokio::test]
async fn a_collection_or_group_of_another_space_is_reported_before_a_record_names_it() {
    let store = memory().await;
    let mine = SpaceId::random();
    let theirs = SpaceId::random();
    let owner = UserId::random();
    let space = |id: SpaceId| Space {
        id,
        name: vec![1; 40],
        key_version: 1,
        keys_pending_since: None,
        created_at: AT,
        updated_at: AT,
    };
    let collection = Collection {
        id: CollectionId::random(),
        space: theirs,
        parent: None,
        name: vec![2; 40],
        key_version: 1,
        stale_since: None,
        created_at: AT,
    };
    let group = Group {
        id: GroupId::random(),
        space: theirs,
        name: vec![3; 40],
        members: [owner].into_iter().collect(),
        created_at: AT,
    };
    for (id, collections, groups) in [
        (mine, Vec::new(), Vec::new()),
        (theirs, vec![collection.clone()], vec![group.clone()]),
    ] {
        SpaceRepo::create(
            &store,
            SpaceChanges {
                space: Some(space(id)),
                members: vec![member(id, owner, SpaceRole::Owner, MemberState::Confirmed)],
                groups,
                collections,
                ..SpaceChanges::new(id)
            },
        )
        .await
        .expect("a space");
    }

    // The other space's ids are taken, whichever kind a record names them as.
    assert_eq!(
        store.ids_held_elsewhere(mine, &[collection.id], &[]).await,
        Ok(true)
    );
    assert_eq!(
        store.ids_held_elsewhere(mine, &[], &[group.id]).await,
        Ok(true)
    );
    // Its own ids and ids nobody has are fine.
    assert_eq!(
        store
            .ids_held_elsewhere(theirs, &[collection.id], &[group.id])
            .await,
        Ok(false)
    );
    assert_eq!(
        store
            .ids_held_elsewhere(mine, &[CollectionId::random()], &[GroupId::random()])
            .await,
        Ok(false)
    );
}

#[tokio::test]
async fn a_held_record_only_touches_the_items_of_its_own_space() {
    let replica = memory().await;
    let (mine, theirs) = (SpaceId::random(), SpaceId::random());
    let (own_item, their_item) = (ItemId::random(), ItemId::random());
    put(
        &replica,
        draft(own_item, kemlock_domain::Owner::Space(mine), None, 1),
    )
    .await;
    put(
        &replica,
        draft(their_item, kemlock_domain::Owner::Space(theirs), None, 1),
    )
    .await;
    // The other space's home holds its item.
    SpaceMirror::apply_space_record(&replica, theirs, &SpaceRecord::Held(vec![their_item]))
        .await
        .expect("held");

    // This space's home names both, and an id nobody has: only its own item is held, and the
    // other space's hold stays.
    SpaceMirror::apply_space_record(
        &replica,
        mine,
        &SpaceRecord::Held(vec![own_item, their_item, ItemId::random()]),
    )
    .await
    .expect("applied");
    assert_eq!(
        replica.held_items(mine).await.expect("held"),
        vec![own_item]
    );
    assert_eq!(
        replica.held_items(theirs).await.expect("held"),
        vec![their_item]
    );
    // And an empty set from this space doesn't release the other's item.
    SpaceMirror::apply_space_record(&replica, mine, &SpaceRecord::Held(Vec::new()))
        .await
        .expect("applied");
    assert_eq!(
        replica.held_items(theirs).await.expect("held"),
        vec![their_item]
    );
}

#[tokio::test]
async fn a_member_taken_out_signs_only_where_they_could_edit_and_only_before_they_left() {
    use kemlock_domain::Owner;
    use kemlock_federation::extra::{MemberStore, WRITE_SKEW_SECS};
    let store = memory().await;
    let space = SpaceId::random();
    let owner = UserId::random();
    let gone = UserId::random();
    let collection = |id: CollectionId| Collection {
        id,
        space,
        parent: None,
        name: vec![2; 40],
        key_version: 1,
        stale_since: None,
        created_at: AT,
    };
    let (editable, read_only, unshared) = (
        CollectionId::random(),
        CollectionId::random(),
        CollectionId::random(),
    );
    let mut revoked = member(space, gone, SpaceRole::Member, MemberState::Revoked);
    revoked.revoked_at = Some(AT);
    let grant = |collection, user, permission| CollectionGrant {
        collection,
        grantee: Grantee::Member(user),
        permission,
    };
    SpaceRepo::create(
        &store,
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
                revoked,
            ],
            collections: vec![
                collection(editable),
                collection(read_only),
                collection(unshared),
            ],
            grants: vec![
                grant(editable, owner, CollectionPermission::Manage),
                grant(editable, gone, CollectionPermission::Edit),
                grant(read_only, owner, CollectionPermission::Manage),
                grant(read_only, gone, CollectionPermission::View),
                grant(unshared, owner, CollectionPermission::Manage),
            ],
            ..SpaceChanges::new(space)
        },
    )
    .await
    .expect("a space");
    let vault = Owner::Space(space);
    let left = u64::try_from(AT.unix_timestamp()).expect("a time");
    let may = |user, collection, made| {
        let store = &store;
        async move {
            store
                .writer_may_edit(vault, user, collection, made)
                .await
                .expect("a read")
        }
    };

    // Before they left, where they held edit.
    assert_eq!(may(gone, editable, left - 1_000).await, Some(true));
    assert_eq!(may(gone, editable, left + WRITE_SKEW_SECS).await, Some(true));
    // After they left, not.
    assert_eq!(may(gone, editable, left + WRITE_SKEW_SECS + 1).await, Some(false));
    // Never where they could only read, or had no grant.
    assert_eq!(may(gone, read_only, left - 1_000).await, Some(false));
    assert_eq!(may(gone, unshared, left - 1_000).await, Some(false));
    // A confirmed member is judged by their grants alone.
    assert_eq!(may(owner, unshared, left + 1_000_000).await, Some(true));
    // A collection the server doesn't hold is a reason to wait.
    assert_eq!(may(gone, CollectionId::random(), left).await, None);
}

#[tokio::test]
async fn a_collection_is_this_spaces_another_spaces_or_not_known_yet() {
    use kemlock_domain::Owner;
    use kemlock_federation::extra::MemberStore;
    let store = memory().await;
    let owner = UserId::random();
    let make = |space: SpaceId, collection: CollectionId| SpaceChanges {
        space: Some(Space {
            id: space,
            name: vec![1; 40],
            key_version: 1,
            keys_pending_since: None,
            created_at: AT,
            updated_at: AT,
        }),
        members: vec![member(space, owner, SpaceRole::Owner, MemberState::Confirmed)],
        collections: vec![Collection {
            id: collection,
            space,
            parent: None,
            name: vec![2; 40],
            key_version: 1,
            stale_since: None,
            created_at: AT,
        }],
        ..SpaceChanges::new(space)
    };
    let (mine, theirs) = (SpaceId::random(), SpaceId::random());
    let (my_collection, their_collection) = (CollectionId::random(), CollectionId::random());
    SpaceRepo::create(&store, make(mine, my_collection))
        .await
        .expect("a space");
    SpaceRepo::create(&store, make(theirs, their_collection))
        .await
        .expect("another space");

    let ask = |collection| store.space_has_collection(Owner::Space(mine), collection);
    assert_eq!(ask(my_collection).await, Ok(Some(true)));
    assert_eq!(ask(their_collection).await, Ok(Some(false)));
    assert_eq!(ask(CollectionId::random()).await, Ok(None));
    // A space this server doesn't hold knows nothing yet; a personal vault has no collections.
    assert_eq!(
        store
            .space_has_collection(Owner::Space(SpaceId::random()), my_collection)
            .await,
        Ok(None)
    );
    assert_eq!(
        store
            .space_has_collection(Owner::User(owner), my_collection)
            .await,
        Ok(Some(false))
    );
}
