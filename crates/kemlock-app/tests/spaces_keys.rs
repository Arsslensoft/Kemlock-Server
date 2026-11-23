//! Spaces: collections, groups, grants, item writes, the key replacement after offboarding, and
//! the owners a device syncs.

mod fakes;
mod space_fakes;

use fakes::actor;
use kemlock_app::dedup::TagStore;
use kemlock_app::ports::ItemStore;
use kemlock_app::spaces::{
    CollectionRekey, CreateCollectionInput, CreateGroupInput, EditCollectionInput, EditGroupInput,
    ReplacementInput, SpacesError,
};
use kemlock_domain::spaces::{
    Collection, CollectionId, CollectionPermission, Grantee, GroupId, MemberState, SpaceError,
    SpaceRole,
};
use kemlock_domain::{
    DedupTag, Item, ItemError, ItemId, Owner, Revision, SpaceId, TagSet, UserId, VersionVector,
};
use space_fakes::{SpaceWorld, key_for, name, sealed_key};

/// Sam owns a space; Ana and Lee are members with Edit on its first collection.
struct Ctx {
    w: SpaceWorld,
    sam: UserId,
    ana: UserId,
    lee: UserId,
    space: SpaceId,
    everyone: CollectionId,
}

impl Ctx {
    async fn new() -> Ctx {
        let w = SpaceWorld::new();
        let sam = w.user("sam@example.org").await;
        let ana = w.user("ana@example.org").await;
        let lee = w.user("lee@example.org").await;
        let (space, everyone) = w.make_space(sam).await;
        for member in [ana, lee] {
            w.join(
                space,
                sam,
                sam,
                member,
                SpaceRole::Member,
                vec![(everyone, CollectionPermission::Edit)],
            )
            .await;
        }
        Ctx {
            w,
            sam,
            ana,
            lee,
            space,
            everyone,
        }
    }

    /// A collection only Sam holds.
    async fn private_collection(&self) -> CollectionId {
        let id = CollectionId::random();
        self.w
            .create_collection()
            .execute(
                &actor(self.sam),
                self.space,
                CreateCollectionInput {
                    id,
                    parent: None,
                    name: name(8),
                    grants: Vec::new(),
                    keys: vec![key_for(id, self.sam, 6)],
                },
            )
            .await
            .expect("Sam makes a private collection");
        id
    }

    async fn put(
        &self,
        by: UserId,
        collection: CollectionId,
        id: ItemId,
        expected: Option<u64>,
        revision: u64,
        key_version: u32,
    ) -> Result<Item, SpacesError> {
        self.w
            .put_space_item()
            .execute(
                &actor(by),
                collection,
                self.w
                    .item_write(self.space, id, expected, revision, key_version),
            )
            .await
    }

    async fn new_item(&self, by: UserId, collection: CollectionId) -> ItemId {
        let id = ItemId::random();
        self.put(by, collection, id, None, 1, 1)
            .await
            .expect("a new item is written");
        id
    }

    fn state(&self) -> kemlock_domain::spaces::SpaceState {
        self.w.spaces.state(self.space)
    }

    fn collection(&self, id: CollectionId) -> Collection {
        self.state()
            .collection(id)
            .cloned()
            .expect("the collection")
    }
}

fn invalid<T: std::fmt::Debug>(result: Result<T, SpacesError>) -> bool {
    matches!(result, Err(SpacesError::Rule(SpaceError::Invalid(_))))
}

// ---- collections ----

#[tokio::test]
async fn a_collection_is_made_with_keys_for_exactly_its_grantees() {
    let c = Ctx::new().await;
    let finance = CollectionId::random();
    let input = |keys| CreateCollectionInput {
        id: finance,
        parent: None,
        name: name(11),
        grants: vec![(Grantee::Member(c.ana), CollectionPermission::View)],
        keys,
    };
    // Sam is granted Manage on what he makes, so he and Ana need a copy each: not fewer, not more.
    let missing =
        c.w.create_collection()
            .execute(
                &actor(c.sam),
                c.space,
                input(vec![key_for(finance, c.sam, 1)]),
            )
            .await;
    let extra =
        c.w.create_collection()
            .execute(
                &actor(c.sam),
                c.space,
                input(vec![
                    key_for(finance, c.sam, 1),
                    key_for(finance, c.ana, 1),
                    key_for(finance, c.lee, 1),
                ]),
            )
            .await;
    assert!(invalid(missing) && invalid(extra));
    assert!(c.state().collection(finance).is_none());

    let made =
        c.w.create_collection()
            .execute(
                &actor(c.sam),
                c.space,
                input(vec![key_for(finance, c.sam, 1), key_for(finance, c.ana, 2)]),
            )
            .await
            .expect("the keys are exactly right");
    assert_eq!(made.key_version, 1);
    let holders = c.w.spaces.holders_of(finance);
    assert_eq!(holders.len(), 2);
    assert!(holders.contains(&c.sam) && holders.contains(&c.ana));
    assert_eq!(
        c.w.spaces
            .copy(finance, c.ana)
            .expect("Ana's copy")
            .key_version,
        1
    );
    let state = c.state();
    assert_eq!(
        state.access(c.ana, finance).map(|a| (a.edit, a.manage)),
        Some((false, false))
    );
    assert_eq!(state.access(c.sam, finance).map(|a| a.manage), Some(true));
    // The id is taken once.
    let again =
        c.w.create_collection()
            .execute(
                &actor(c.sam),
                c.space,
                input(vec![key_for(finance, c.sam, 1), key_for(finance, c.ana, 2)]),
            )
            .await;
    assert_eq!(again.err(), Some(SpacesError::Duplicate));
}

#[tokio::test]
async fn only_roles_that_create_collections_create_them() {
    let c = Ctx::new().await;
    let id = CollectionId::random();
    let refused =
        c.w.create_collection()
            .execute(
                &actor(c.ana),
                c.space,
                CreateCollectionInput {
                    id,
                    parent: None,
                    name: name(11),
                    grants: Vec::new(),
                    keys: vec![key_for(id, c.ana, 1)],
                },
            )
            .await;
    assert!(matches!(
        refused.err(),
        Some(SpacesError::Rule(SpaceError::Forbidden(_)))
    ));
}

#[tokio::test]
async fn collections_nest_rename_and_move_without_cycles() {
    let c = Ctx::new().await;
    let child = CollectionId::random();
    c.w.create_collection()
        .execute(
            &actor(c.sam),
            c.space,
            CreateCollectionInput {
                id: child,
                parent: Some(c.everyone),
                name: name(12),
                grants: Vec::new(),
                keys: vec![key_for(child, c.sam, 1)],
            },
        )
        .await
        .expect("a nested collection");
    assert_eq!(c.collection(child).parent, Some(c.everyone));

    // Under itself, under its own child, or under a collection that isn't there: refused.
    for parent in [Some(child), Some(CollectionId::random())] {
        let moved =
            c.w.edit_collection()
                .execute(
                    &actor(c.sam),
                    c.space,
                    c.everyone,
                    EditCollectionInput {
                        name: None,
                        parent: Some(parent),
                    },
                )
                .await;
        assert!(invalid(moved));
    }
    let renamed =
        c.w.edit_collection()
            .execute(
                &actor(c.sam),
                c.space,
                child,
                EditCollectionInput {
                    name: Some(name(13)),
                    parent: Some(None),
                },
            )
            .await
            .expect("Sam renames and moves it to the top");
    assert_eq!(renamed.name, name(13));
    assert_eq!(c.collection(child).parent, None);

    // Edit isn't Manage: Ana can write items but can't change the collection.
    let by_editor =
        c.w.edit_collection()
            .execute(
                &actor(c.ana),
                c.space,
                c.everyone,
                EditCollectionInput {
                    name: Some(name(14)),
                    parent: None,
                },
            )
            .await;
    assert!(matches!(
        by_editor.err(),
        Some(SpacesError::Rule(SpaceError::Forbidden(_)))
    ));
}

#[tokio::test]
async fn a_collection_is_deleted_only_when_empty_and_unnested() {
    let c = Ctx::new().await;
    let child = CollectionId::random();
    c.w.create_collection()
        .execute(
            &actor(c.sam),
            c.space,
            CreateCollectionInput {
                id: child,
                parent: Some(c.everyone),
                name: name(12),
                grants: Vec::new(),
                keys: vec![key_for(child, c.sam, 1)],
            },
        )
        .await
        .expect("a nested collection");
    // The parent has a child.
    assert!(invalid(
        c.w.delete_collection()
            .execute(&actor(c.sam), c.space, c.everyone)
            .await
    ));
    // The child holds an item, then a tombstone only.
    let item = c.new_item(c.sam, child).await;
    assert!(invalid(
        c.w.delete_collection()
            .execute(&actor(c.sam), c.space, child)
            .await
    ));
    let mut gone = c.w.item_write(c.space, item, Some(1), 2, 1);
    gone.sealed = None;
    c.w.put_space_item()
        .execute(&actor(c.sam), child, gone)
        .await
        .expect("Sam deletes the item");
    c.w.delete_collection()
        .execute(&actor(c.sam), c.space, child)
        .await
        .expect("an empty collection is deleted");
    assert!(c.state().collection(child).is_none());
    assert!(c.w.spaces.holders_of(child).is_empty());
    assert_eq!(c.w.spaces.item_collection(item), None);
}

// ---- grants ----

#[tokio::test]
async fn a_grant_seals_the_key_to_each_member_it_newly_reaches() {
    let w = SpaceWorld::new();
    let sam = w.user("sam@example.org").await;
    let ana = w.user("ana@example.org").await;
    let (space, everyone) = w.make_space(sam).await;
    w.join(space, sam, sam, ana, SpaceRole::Member, Vec::new())
        .await;
    assert!(!w.spaces.holders_of(everyone).contains(&ana));

    macro_rules! grant {
        ($permission:expr, $keys:expr) => {
            w.grant().execute(
                &actor(sam),
                space,
                everyone,
                Grantee::Member(ana),
                $permission,
                $keys,
            )
        };
    }
    // Without her key, with a key for someone who already holds it, or a malformed one: refused.
    assert!(invalid(
        grant!(CollectionPermission::View, Vec::new()).await
    ));
    assert!(invalid(
        grant!(
            CollectionPermission::View,
            vec![key_for(everyone, ana, 1), key_for(everyone, sam, 1)]
        )
        .await
    ));
    let mut short = key_for(everyone, ana, 1);
    short.sealed.truncate(10);
    assert!(invalid(
        grant!(CollectionPermission::View, vec![short]).await
    ));
    assert!(!w.spaces.holders_of(everyone).contains(&ana));

    let made = grant!(CollectionPermission::View, vec![key_for(everyone, ana, 7)])
        .await
        .expect("a grant with her key");
    assert_eq!(made.permission, CollectionPermission::View);
    assert_eq!(
        w.spaces.copy(everyone, ana).expect("her copy").sealed,
        sealed_key(7)
    );
    // Changing the permission of someone who holds the key takes no key.
    grant!(CollectionPermission::Edit, Vec::new())
        .await
        .expect("a change of permission");
    assert!(invalid(
        grant!(
            CollectionPermission::Manage,
            vec![key_for(everyone, ana, 8)]
        )
        .await
    ));
    let state = w.spaces.state(space);
    assert_eq!(state.access(ana, everyone).map(|a| a.edit), Some(true));
    assert_eq!(
        state
            .grants
            .iter()
            .filter(|g| g.grantee == Grantee::Member(ana))
            .count(),
        1
    );
}

#[tokio::test]
async fn only_a_holder_of_manage_grants_a_collection_and_only_to_members_in_good_standing() {
    let c = Ctx::new().await;
    // Ana has Edit: she can't grant. Make her a manager of Everyone, and she can.
    let by_editor =
        c.w.grant()
            .execute(
                &actor(c.ana),
                c.space,
                c.everyone,
                Grantee::Member(c.lee),
                CollectionPermission::View,
                Vec::new(),
            )
            .await;
    assert!(matches!(
        by_editor.err(),
        Some(SpacesError::Rule(SpaceError::Forbidden(_)))
    ));
    c.w.grant()
        .execute(
            &actor(c.sam),
            c.space,
            c.everyone,
            Grantee::Member(c.ana),
            CollectionPermission::Manage,
            Vec::new(),
        )
        .await
        .expect("Sam promotes her grant");
    // Manage on Everyone is no power over the private collection.
    let private = c.private_collection().await;
    let elsewhere =
        c.w.grant()
            .execute(
                &actor(c.ana),
                c.space,
                private,
                Grantee::Member(c.lee),
                CollectionPermission::View,
                vec![key_for(private, c.lee, 1)],
            )
            .await;
    assert!(matches!(
        elsewhere.err(),
        Some(SpacesError::Rule(SpaceError::Forbidden(_)))
    ));

    // An unknown group and a stranger can't be granted a collection, and neither can a member
    // who has been revoked (the space then waits for its keys to be replaced).
    for grantee in [
        Grantee::Group(GroupId::random()),
        Grantee::Member(UserId::random()),
    ] {
        let refused =
            c.w.grant()
                .execute(
                    &actor(c.sam),
                    c.space,
                    private,
                    grantee,
                    CollectionPermission::View,
                    Vec::new(),
                )
                .await;
        assert!(invalid(refused));
    }
    c.w.offboard()
        .revoke(&actor(c.sam), c.space, c.lee)
        .await
        .expect("Lee is revoked");
    let to_revoked =
        c.w.grant()
            .execute(
                &actor(c.sam),
                c.space,
                private,
                Grantee::Member(c.lee),
                CollectionPermission::View,
                Vec::new(),
            )
            .await;
    assert_eq!(
        to_revoked.err(),
        Some(SpacesError::Rule(SpaceError::KeysPending))
    );
}

#[tokio::test]
async fn revoking_a_grant_takes_the_copy_and_stales_only_that_collection() {
    let c = Ctx::new().await;
    let private = c.private_collection().await;
    c.w.grant()
        .execute(
            &actor(c.sam),
            c.space,
            private,
            Grantee::Member(c.ana),
            CollectionPermission::Edit,
            vec![key_for(private, c.ana, 3)],
        )
        .await
        .expect("Ana is granted the private collection too");

    c.w.revoke_grant()
        .execute(&actor(c.sam), c.space, c.everyone, Grantee::Member(c.ana))
        .await
        .expect("Ana's grant on Everyone is revoked");

    assert!(!c.w.spaces.holders_of(c.everyone).contains(&c.ana));
    assert!(c.w.spaces.holders_of(private).contains(&c.ana));
    assert!(c.collection(c.everyone).stale_since.is_some());
    assert!(c.collection(private).stale_since.is_none());
    assert!(c.state().space.keys_pending_since.is_none());
    // Only the stale collection pauses.
    assert_eq!(
        c.put(c.lee, c.everyone, ItemId::random(), None, 1, 1)
            .await
            .err(),
        Some(SpacesError::Rule(SpaceError::KeysPending))
    );
    c.put(c.ana, private, ItemId::random(), None, 1, 1)
        .await
        .expect("the other collection still takes writes");
    // A grant that isn't there can't be revoked.
    assert_eq!(
        c.w.revoke_grant()
            .execute(&actor(c.sam), c.space, c.everyone, Grantee::Member(c.ana))
            .await
            .err(),
        Some(SpacesError::NotFound)
    );
}

// ---- groups ----

#[tokio::test]
async fn a_group_carries_a_grant_and_membership_changes_move_keys() {
    let c = Ctx::new().await;
    let private = c.private_collection().await;
    let ops = GroupId::random();
    let group =
        c.w.create_group()
            .execute(
                &actor(c.sam),
                c.space,
                CreateGroupInput {
                    id: ops,
                    name: name(21),
                    members: vec![c.ana],
                },
            )
            .await
            .expect("a group");
    assert!(group.members.contains(&c.ana));
    // Granting the group a collection seals its key to each of its confirmed members.
    c.w.grant()
        .execute(
            &actor(c.sam),
            c.space,
            private,
            Grantee::Group(ops),
            CollectionPermission::Edit,
            vec![key_for(private, c.ana, 4)],
        )
        .await
        .expect("the group is granted");
    assert!(c.w.spaces.holders_of(private).contains(&c.ana));

    // Adding Lee gives him access, so he needs a key; without it the change is refused.
    macro_rules! add {
        ($keys:expr) => {
            c.w.edit_group().execute(
                &actor(c.sam),
                c.space,
                ops,
                EditGroupInput {
                    name: None,
                    members: Some(vec![c.ana, c.lee]),
                    keys: $keys,
                },
            )
        };
    }
    assert!(invalid(add!(Vec::new()).await));
    add!(vec![key_for(private, c.lee, 5)])
        .await
        .expect("Lee is added with his key");
    assert!(c.w.spaces.holders_of(private).contains(&c.lee));

    // Taking Ana out removes her copy and marks the collection for replacement.
    let removed =
        c.w.edit_group()
            .execute(
                &actor(c.sam),
                c.space,
                ops,
                EditGroupInput {
                    name: None,
                    members: Some(vec![c.lee]),
                    keys: Vec::new(),
                },
            )
            .await
            .expect("Ana leaves the group");
    assert!(!removed.members.contains(&c.ana));
    assert!(!c.w.spaces.holders_of(private).contains(&c.ana));
    assert!(c.collection(private).stale_since.is_some());

    // A rename takes no keys; keys with no member change are refused.
    c.w.edit_group()
        .execute(
            &actor(c.sam),
            c.space,
            ops,
            EditGroupInput {
                name: Some(name(22)),
                members: None,
                keys: Vec::new(),
            },
        )
        .await
        .expect("a rename");
    assert!(invalid(
        c.w.edit_group()
            .execute(
                &actor(c.sam),
                c.space,
                ops,
                EditGroupInput {
                    name: None,
                    members: None,
                    keys: vec![key_for(private, c.lee, 5)],
                },
            )
            .await
    ));
}

#[tokio::test]
async fn deleting_a_group_drops_its_grants_and_stales_what_only_it_opened() {
    let c = Ctx::new().await;
    let private = c.private_collection().await;
    let ops = GroupId::random();
    c.w.create_group()
        .execute(
            &actor(c.sam),
            c.space,
            CreateGroupInput {
                id: ops,
                name: name(21),
                members: vec![c.ana],
            },
        )
        .await
        .expect("a group");
    c.w.grant()
        .execute(
            &actor(c.sam),
            c.space,
            private,
            Grantee::Group(ops),
            CollectionPermission::View,
            vec![key_for(private, c.ana, 4)],
        )
        .await
        .expect("granted");

    c.w.delete_group()
        .execute(&actor(c.sam), c.space, ops)
        .await
        .expect("the group is deleted");
    let state = c.state();
    assert!(state.group(ops).is_none());
    assert!(
        state
            .grants
            .iter()
            .all(|g| g.grantee != Grantee::Group(ops))
    );
    assert!(!c.w.spaces.holders_of(private).contains(&c.ana));
    assert!(c.collection(private).stale_since.is_some());
    // Ana still holds Everyone by her own grant.
    assert!(c.w.spaces.holders_of(c.everyone).contains(&c.ana));
    assert_eq!(
        c.w.delete_group()
            .execute(&actor(c.sam), c.space, ops)
            .await
            .err(),
        Some(SpacesError::NotFound)
    );
}

#[tokio::test]
async fn only_members_in_the_space_are_put_in_a_group() {
    let c = Ctx::new().await;
    let refused =
        c.w.create_group()
            .execute(
                &actor(c.sam),
                c.space,
                CreateGroupInput {
                    id: GroupId::random(),
                    name: name(21),
                    members: vec![c.ana, UserId::random()],
                },
            )
            .await;
    assert!(invalid(refused));
    let by_member =
        c.w.create_group()
            .execute(
                &actor(c.ana),
                c.space,
                CreateGroupInput {
                    id: GroupId::random(),
                    name: name(21),
                    members: Vec::new(),
                },
            )
            .await;
    assert!(matches!(
        by_member.err(),
        Some(SpacesError::Rule(SpaceError::Forbidden(_)))
    ));
}

// ---- items ----

#[tokio::test]
async fn a_member_with_edit_writes_an_item_and_the_collection_is_recorded() {
    let c = Ctx::new().await;
    let id = ItemId::random();
    let first = c
        .put(c.ana, c.everyone, id, None, 1, 1)
        .await
        .expect("Ana writes");
    assert_eq!(first.owner, Owner::Space(c.space));
    assert_eq!(first.revision, Revision(1));
    assert_eq!(c.w.spaces.item_collection(id), Some(c.everyone));
    assert_eq!(
        c.w.world.notifier.calls().last().map(|(owner, _)| *owner),
        Some(Owner::Space(c.space))
    );
    assert!(
        c.w.world
            .store
            .events()
            .iter()
            .any(|e| e.action == "item.put" && e.actor == Some(c.ana))
    );

    // Lee replaces it; a stale writer is told the current revision.
    let second = c
        .put(c.lee, c.everyone, id, Some(1), 2, 1)
        .await
        .expect("Lee replaces it");
    assert_eq!(second.revision, Revision(2));
    assert_eq!(
        c.put(c.ana, c.everyone, id, Some(1), 2, 1).await.err(),
        Some(SpacesError::StaleItem {
            item: id,
            current: Some(Revision(2))
        })
    );
    // A delete leaves a tombstone, and needs no key version.
    let mut gone = c.w.item_write(c.space, id, Some(2), 3, 1);
    gone.sealed = None;
    let tombstone =
        c.w.put_space_item()
            .execute(&actor(c.ana), c.everyone, gone)
            .await
            .expect("Ana deletes");
    assert!(tombstone.is_tombstone());
}

#[tokio::test]
async fn an_item_write_needs_edit_membership_and_the_current_key() {
    let c = Ctx::new().await;
    let private = c.private_collection().await;
    // Ana holds no grant on the private collection; Lee has only a view of Everyone.
    c.w.grant()
        .execute(
            &actor(c.sam),
            c.space,
            c.everyone,
            Grantee::Member(c.lee),
            CollectionPermission::ViewHidePasswords,
            Vec::new(),
        )
        .await
        .expect("Lee's grant is lowered");
    let outsider = c.w.user("zed@example.org").await;
    assert!(matches!(
        c.put(c.ana, private, ItemId::random(), None, 1, 1)
            .await
            .err(),
        Some(SpacesError::Rule(SpaceError::Forbidden(_)))
    ));
    assert!(matches!(
        c.put(c.lee, c.everyone, ItemId::random(), None, 1, 1)
            .await
            .err(),
        Some(SpacesError::Rule(SpaceError::Forbidden(_)))
    ));
    assert_eq!(
        c.put(outsider, c.everyone, ItemId::random(), None, 1, 1)
            .await
            .err(),
        Some(SpacesError::Rule(SpaceError::NotAMember))
    );
    // The collection is at key version 1; version 2 isn't its key yet.
    assert_eq!(
        c.put(c.ana, c.everyone, ItemId::random(), None, 1, 2)
            .await
            .err(),
        Some(SpacesError::Rule(SpaceError::StaleKeyVersion {
            current: 1
        }))
    );
    // This use case is for space items: a vault write is refused here.
    let vault = fakes::write(c.ana, ItemId::random(), None, 1);
    assert_eq!(
        c.w.put_space_item()
            .execute(&actor(c.ana), c.everyone, vault)
            .await
            .err(),
        Some(SpacesError::Item(ItemError::Forbidden))
    );
}

#[tokio::test]
async fn moving_an_item_needs_edit_on_both_collections() {
    let c = Ctx::new().await;
    let private = c.private_collection().await;
    let id = c.new_item(c.sam, private).await;
    // Ana can write Everyone but not the private collection the item is in.
    assert!(matches!(
        c.put(c.ana, c.everyone, id, Some(1), 2, 1).await.err(),
        Some(SpacesError::Rule(SpaceError::Forbidden(_)))
    ));
    // Sam holds Manage on both, so he can move it, and it is then Everyone's.
    let moved = c
        .put(c.sam, c.everyone, id, Some(1), 2, 1)
        .await
        .expect("Sam moves it");
    assert_eq!(moved.revision, Revision(2));
    assert_eq!(c.w.spaces.item_collection(id), Some(c.everyone));
    c.put(c.ana, c.everyone, id, Some(2), 3, 1)
        .await
        .expect("Ana now edits it");
}

#[tokio::test]
async fn space_items_sync_to_confirmed_members_only() {
    let c = Ctx::new().await;
    let id = c.new_item(c.ana, c.everyone).await;
    let outsider = c.w.user("zed@example.org").await;
    // A pending invitation doesn't open the space's items either.
    c.w.invite()
        .execute(
            &actor(c.sam),
            c.space,
            kemlock_app::spaces::InviteInput {
                email: "zed@example.org".to_owned(),
                role: SpaceRole::Member,
                custom: kemlock_domain::spaces::CustomPermissions::NONE,
                grants: Vec::new(),
            },
        )
        .await
        .expect("Zed is invited");

    for (user, sees) in [(c.sam, true), (c.lee, true), (outsider, false)] {
        let owners = c.w.sync_owners().execute(user).await.expect("owners");
        assert_eq!(owners[0], Owner::User(user));
        let page =
            c.w.world
                .store
                .changes_since(&owners, &VersionVector::new(), 100)
                .await
                .expect("a page");
        assert_eq!(page.items.iter().any(|i| i.id == id), sees, "{user}");
    }
    // The owners are the account's own vault first, then each confirmed space.
    assert_eq!(
        c.w.sync_owners().execute(c.sam).await.expect("owners"),
        vec![Owner::User(c.sam), Owner::Space(c.space)]
    );
}

// ---- key replacement ----

/// Sam, Ana and Lee in a space with Everyone (Ana and Lee edit) and a collection only Sam holds.
/// Two items in Everyone and one in the private collection. Then Lee is revoked, so the space key
/// and Everyone's key await replacement.
struct AfterRevoke {
    c: Ctx,
    private: CollectionId,
    items: [ItemId; 2],
    private_item: ItemId,
}

impl AfterRevoke {
    async fn new() -> AfterRevoke {
        let c = Ctx::new().await;
        let private = c.private_collection().await;
        let a = c.new_item(c.ana, c.everyone).await;
        let b = c.new_item(c.lee, c.everyone).await;
        let private_item = c.new_item(c.sam, private).await;
        c.w.offboard()
            .revoke(&actor(c.sam), c.space, c.lee)
            .await
            .expect("Lee is revoked");
        AfterRevoke {
            c,
            private,
            items: [a, b],
            private_item,
        }
    }

    /// The replacement a client would send: the space key to Sam and Ana, Everyone's key to the
    /// same two, every name again, and both items of Everyone re-wrapped as revision 2.
    fn input(&self) -> ReplacementInput {
        let c = &self.c;
        ReplacementInput {
            space_key_version: 2,
            space_name: Some(name(40)),
            sealed_space_keys: vec![(c.sam, sealed_key(20)), (c.ana, sealed_key(21))],
            collection_names: vec![(c.everyone, name(41)), (self.private, name(42))],
            group_names: Vec::new(),
            collections: vec![CollectionRekey {
                collection: c.everyone,
                key_version: 2,
                keys: vec![
                    key_for(c.everyone, c.sam, 30),
                    key_for(c.everyone, c.ana, 31),
                ],
            }],
            writes: self
                .items
                .iter()
                .map(|id| (c.everyone, c.w.item_write(c.space, *id, Some(1), 2, 2)))
                .collect(),
        }
    }

    async fn replace(&self, by: UserId, input: ReplacementInput) -> Result<Vec<Item>, SpacesError> {
        self.c
            .w
            .replace_keys()
            .execute(&actor(by), self.c.space, input)
            .await
    }

    /// Nothing changed: the keys still await replacement and the items are at revision 1.
    fn untouched(&self) -> bool {
        let state = self.c.state();
        state.space.keys_pending_since.is_some()
            && state.space.key_version == 1
            && self.items.iter().all(|id| {
                self.c
                    .w
                    .world
                    .store
                    .item(*id)
                    .is_some_and(|i| i.revision == Revision(1))
            })
    }
}

#[tokio::test]
async fn a_replacement_lands_new_keys_names_and_items_as_one_transaction() {
    let o = AfterRevoke::new().await;
    let c = &o.c;
    assert!(c.state().space.keys_pending_since.is_some());
    assert!(c.collection(c.everyone).stale_since.is_some());
    assert!(c.collection(o.private).stale_since.is_none());

    let stored = o
        .replace(c.sam, o.input())
        .await
        .expect("a complete replacement lands");
    assert_eq!(stored.len(), 2);

    let state = c.state();
    assert_eq!(state.space.key_version, 2);
    assert_eq!(state.space.keys_pending_since, None);
    assert_eq!(state.space.name, name(40));
    assert_eq!(c.collection(c.everyone).key_version, 2);
    assert_eq!(c.collection(c.everyone).stale_since, None);
    assert_eq!(c.collection(c.everyone).name, name(41));
    // A collection whose key wasn't replaced keeps its version but gets its name under the new
    // space key.
    assert_eq!(c.collection(o.private).key_version, 1);
    assert_eq!(c.collection(o.private).name, name(42));

    // The members who stay hold the new space key and collection key; Lee holds nothing.
    let ana = c.w.spaces.member(c.space, c.ana).expect("Ana");
    assert_eq!(ana.sealed_space_key, Some(sealed_key(21)));
    assert_eq!(ana.key_version, Some(2));
    let copy = c.w.spaces.copy(c.everyone, c.ana).expect("Ana's new copy");
    assert_eq!((copy.key_version, copy.sealed), (2, sealed_key(31)));
    let lee = c.w.spaces.member(c.space, c.lee).expect("Lee's row");
    assert_eq!(
        (lee.state, lee.sealed_space_key),
        (MemberState::Revoked, None)
    );
    assert!(!c.w.spaces.holders_of(c.everyone).contains(&c.lee));

    // The items are re-wrapped under the new key version, as the next revision.
    for id in o.items {
        let item = c.w.world.store.item(id).expect("the item");
        assert_eq!((item.revision, item.key_version), (Revision(2), 2));
        assert_eq!(item.owner, Owner::Space(c.space));
    }
    let untouched =
        c.w.world
            .store
            .item(o.private_item)
            .expect("the other item");
    assert_eq!(untouched.revision, Revision(1));
    assert_eq!(
        c.w.world.notifier.calls().last().map(|(owner, _)| *owner),
        Some(Owner::Space(c.space))
    );
    assert!(
        c.w.world
            .store
            .events()
            .iter()
            .any(|e| e.action == "space.keys.replace")
    );

    // Writes resume, under the new key only.
    c.put(c.ana, c.everyone, ItemId::random(), None, 1, 2)
        .await
        .expect("Ana writes under the new key");
    assert_eq!(
        c.put(c.ana, c.everyone, ItemId::random(), None, 1, 1)
            .await
            .err(),
        Some(SpacesError::Rule(SpaceError::StaleKeyVersion {
            current: 2
        }))
    );
    assert_eq!(
        c.put(c.lee, c.everyone, ItemId::random(), None, 1, 2)
            .await
            .err(),
        Some(SpacesError::Rule(SpaceError::NotAMember))
    );
}

#[tokio::test]
async fn an_incomplete_replacement_changes_nothing() {
    let o = AfterRevoke::new().await;
    let c = &o.c;
    let mut cases: Vec<(&str, ReplacementInput)> = Vec::new();
    let mut case = |why: &'static str, edit: &dyn Fn(&mut ReplacementInput)| {
        let mut input = o.input();
        edit(&mut input);
        cases.push((why, input));
    };
    case("a skipped key version", &|i| i.space_key_version = 3);
    case("no key for a member who stays", &|i| {
        i.sealed_space_keys.retain(|(u, _)| *u != c.ana)
    });
    case("a key for the revoked member", &|i| {
        i.sealed_space_keys.push((c.lee, sealed_key(22)))
    });
    case("a name left under the old key", &|i| {
        i.collection_names.pop();
    });
    case("no space name", &|i| i.space_name = None);
    case("an item left under the old key", &|i| {
        i.writes.pop();
    });
    case("an item under the old key version", &|i| {
        i.writes[0].1.key_version = 1
    });
    case("a collection key not sealed to a holder", &|i| {
        i.collections[0].keys.retain(|k| k.user != c.ana)
    });
    case("a collection key sealed to the revoked member", &|i| {
        i.collections[0].keys.push(key_for(c.everyone, c.lee, 32))
    });
    case("a collection that isn't waiting", &|i| {
        i.collections.push(CollectionRekey {
            collection: o.private,
            key_version: 2,
            keys: vec![key_for(o.private, c.sam, 33)],
        })
    });
    case("no collection key at all", &|i| i.collections.clear());
    case("an item that isn't in the space", &|i| {
        i.writes[0].1.id = ItemId::random()
    });
    case("an item moved to another collection", &|i| {
        i.writes[0].0 = o.private
    });
    for (why, input) in cases {
        let result = o.replace(c.sam, input).await;
        assert!(invalid(result), "{why}");
        assert!(o.untouched(), "{why} left a change behind");
    }

    // A stale item write names the item; an ordinary member can't replace keys at all.
    let mut stale = o.input();
    stale.writes[0].1 = c.w.item_write(c.space, o.items[0], Some(5), 6, 2);
    assert_eq!(
        o.replace(c.sam, stale).await.err(),
        Some(SpacesError::StaleItem {
            item: o.items[0],
            current: Some(Revision(1))
        })
    );
    assert!(matches!(
        o.replace(c.ana, o.input()).await.err(),
        Some(SpacesError::Rule(SpaceError::Forbidden(_)))
    ));
    assert!(o.untouched());
}

#[tokio::test]
async fn a_replacement_is_refused_when_no_key_awaits_one() {
    let c = Ctx::new().await;
    let refused =
        c.w.replace_keys()
            .execute(
                &actor(c.sam),
                c.space,
                ReplacementInput {
                    space_key_version: 1,
                    space_name: None,
                    sealed_space_keys: Vec::new(),
                    collection_names: Vec::new(),
                    group_names: Vec::new(),
                    collections: Vec::new(),
                    writes: Vec::new(),
                },
            )
            .await;
    assert!(matches!(
        refused.err(),
        Some(SpacesError::Rule(SpaceError::State(_)))
    ));
}

#[tokio::test]
async fn a_lost_grant_needs_only_its_collection_key_replaced() {
    let c = Ctx::new().await;
    let item = c.new_item(c.lee, c.everyone).await;
    c.w.revoke_grant()
        .execute(&actor(c.sam), c.space, c.everyone, Grantee::Member(c.ana))
        .await
        .expect("Ana's grant is revoked");

    macro_rules! replace {
        ($input:expr) => {
            c.w.replace_keys().execute(&actor(c.sam), c.space, $input)
        };
    }
    let rekey = |keys| ReplacementInput {
        space_key_version: 1,
        space_name: None,
        sealed_space_keys: Vec::new(),
        collection_names: Vec::new(),
        group_names: Vec::new(),
        collections: vec![CollectionRekey {
            collection: c.everyone,
            key_version: 2,
            keys,
        }],
        writes: vec![(c.everyone, c.w.item_write(c.space, item, Some(1), 2, 2))],
    };
    // Sam and Lee may hold Everyone now; sending Ana a key is refused, and the space key stays.
    assert!(invalid(
        replace!(rekey(vec![
            key_for(c.everyone, c.sam, 1),
            key_for(c.everyone, c.lee, 1),
            key_for(c.everyone, c.ana, 1)
        ]))
        .await
    ));
    let mut with_names = rekey(vec![
        key_for(c.everyone, c.sam, 1),
        key_for(c.everyone, c.lee, 1),
    ]);
    with_names.space_name = Some(name(40));
    assert!(invalid(replace!(with_names).await));

    let stored = replace!(rekey(vec![
        key_for(c.everyone, c.sam, 50),
        key_for(c.everyone, c.lee, 51),
    ]))
    .await
    .expect("the collection key is replaced");
    assert_eq!(stored.len(), 1);
    assert_eq!(c.state().space.key_version, 1);
    assert_eq!(c.collection(c.everyone).key_version, 2);
    assert_eq!(c.collection(c.everyone).stale_since, None);
    assert_eq!(
        c.w.spaces
            .copy(c.everyone, c.lee)
            .expect("Lee's copy")
            .sealed,
        sealed_key(51)
    );
    assert!(!c.w.spaces.holders_of(c.everyone).contains(&c.ana));
    c.put(c.lee, c.everyone, ItemId::random(), None, 1, 2)
        .await
        .expect("writes resume under the new key");
}

/// Tags for an item at revision 1, under dedup key version `version`.
async fn tag_item(c: &Ctx, item: ItemId, version: u32) {
    let tags = TagSet::new(version, [DedupTag([7; 32])]).expect("a small set");
    let stored =
        c.w.world
            .store
            .put_tags(Owner::Space(c.space), item, Revision(1), &tags)
            .await
            .expect("tags are stored");
    assert!(stored);
}

#[tokio::test]
async fn replacing_the_space_key_moves_the_dedup_key_version_and_drops_old_tags() {
    let o = AfterRevoke::new().await;
    let c = &o.c;
    let owner = Owner::Space(c.space);
    // An item the replacement doesn't rewrite, so only the rotation can clear its tags.
    tag_item(c, o.private_item, 1).await;
    assert_eq!(c.w.world.store.tags_of(o.private_item).len(), 1);
    let before = c.w.world.store.settings(owner).await.expect("settings");

    o.replace(c.sam, o.input())
        .await
        .expect("a complete replacement lands");

    let after = c.w.world.store.settings(owner).await.expect("settings");
    assert_eq!(after.version, before.version + 1);
    assert!(c.w.world.store.tags_of(o.private_item).is_empty());
}

#[tokio::test]
async fn a_refused_replacement_leaves_the_dedup_key_alone() {
    let o = AfterRevoke::new().await;
    let c = &o.c;
    let owner = Owner::Space(c.space);
    tag_item(c, o.private_item, 1).await;
    let before = c.w.world.store.settings(owner).await.expect("settings");

    let mut incomplete = o.input();
    incomplete.writes.pop();
    assert!(invalid(o.replace(c.sam, incomplete).await));

    let after = c.w.world.store.settings(owner).await.expect("settings");
    assert_eq!(after.version, before.version);
    assert_eq!(c.w.world.store.tags_of(o.private_item).len(), 1);
}

#[tokio::test]
async fn replacing_only_a_collection_key_keeps_the_dedup_key_version() {
    let c = Ctx::new().await;
    let owner = Owner::Space(c.space);
    let item = c.new_item(c.lee, c.everyone).await;
    let private = c.private_collection().await;
    let kept = c.new_item(c.sam, private).await;
    tag_item(&c, kept, 1).await;
    c.w.revoke_grant()
        .execute(&actor(c.sam), c.space, c.everyone, Grantee::Member(c.ana))
        .await
        .expect("Ana's grant is revoked");
    let before = c.w.world.store.settings(owner).await.expect("settings");

    c.w.replace_keys()
        .execute(
            &actor(c.sam),
            c.space,
            ReplacementInput {
                space_key_version: 1,
                space_name: None,
                sealed_space_keys: Vec::new(),
                collection_names: Vec::new(),
                group_names: Vec::new(),
                collections: vec![CollectionRekey {
                    collection: c.everyone,
                    key_version: 2,
                    keys: vec![
                        key_for(c.everyone, c.sam, 50),
                        key_for(c.everyone, c.lee, 51),
                    ],
                }],
                writes: vec![(c.everyone, c.w.item_write(c.space, item, Some(1), 2, 2))],
            },
        )
        .await
        .expect("the collection key is replaced");

    // The dedup key comes from the space key, which stays.
    let after = c.w.world.store.settings(owner).await.expect("settings");
    assert_eq!(after.version, before.version);
    assert_eq!(c.w.world.store.tags_of(kept).len(), 1);
}
