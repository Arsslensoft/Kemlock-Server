//! `SpaceRepo` on SQLite: the use cases of `kemlock-app` run over a real `SqlStore`, and the
//! transactional parts (changes, cascades, a key replacement that fails half way) are checked
//! against it directly.

mod common;

use common::{draft, memory, user};
use kemlock_app::ports::{Clock, ItemStore, Notifier, StoreError, UserRepo};
use kemlock_app::spaces::{
    AcceptInvitation, BundleFingerprints, CollectionRekey, ConfirmInput, ConfirmMember,
    ConfirmationFacts, CreateSpace, CreateSpaceInput, GetSpace, InviteInput, InviteMember,
    KeyReplacement, NewCollection, OWNER_REQUIRED, Offboard, PutSpaceItem, ReplaceKeys,
    ReplacementInput, SealedCollectionKey, SpaceChanges, SpaceRepo, SyncOwners,
};
use kemlock_app::{Actor, AuthConfig};
use kemlock_domain::spaces::{
    CollectionGrant, CollectionId, CollectionPermission, CustomPermissions, Grantee, Group,
    GroupId, MemberState, SEALED_KEY_LEN, SpaceRole,
};
use kemlock_domain::{
    ChangeId, DeviceId, ItemFormat, ItemId, ItemKind, ItemWrite, Owner, Revision, Sealed, SpaceId,
    UserId, VersionVector,
};
use kemlock_store_sql::SqlStore;
use std::collections::BTreeSet;
use time::OffsetDateTime;
use time::macros::datetime;

#[derive(Clone, Copy)]
struct FixedClock;

impl Clock for FixedClock {
    fn now(&self) -> OffsetDateTime {
        datetime!(2026-06-01 12:00:00 UTC)
    }
}

#[derive(Clone, Copy)]
struct Silent;

impl Notifier for Silent {
    async fn sync_now(&self, _owner: Owner, _change: ChangeId) {}
}

/// A fingerprint of the first 64 bytes of a bundle, which is enough to tell two test users apart.
#[derive(Clone, Copy)]
struct FirstBytes;

impl BundleFingerprints for FirstBytes {
    fn fingerprint(&self, bundle: &[u8]) -> Option<[u8; 64]> {
        bundle.get(..64).and_then(|b| <[u8; 64]>::try_from(b).ok())
    }

    /// Any signature of the right length: these tests are of the store, not of `sig1`.
    fn verify_confirmation(
        &self,
        _confirmer_bundle: &[u8],
        _facts: &ConfirmationFacts<'_>,
        _statement: &[u8],
        signature: &[u8],
    ) -> bool {
        signature.len() == 3373
    }
}

fn sealed_key(fill: u8) -> Vec<u8> {
    let mut key = vec![fill; SEALED_KEY_LEN];
    key[0] = 1;
    key
}

fn name(fill: u8) -> Vec<u8> {
    vec![fill; 40]
}

fn actor(user: UserId) -> Actor {
    Actor {
        user,
        device: DeviceId::random(),
        admin: false,
    }
}

struct Person {
    id: UserId,
    email: String,
    fingerprint: Vec<u8>,
}

async fn person(store: &SqlStore, seed: u8, email: &str) -> Person {
    let mut account = user(email);
    account.public_bundle = vec![seed; 200];
    UserRepo::insert(store, &account)
        .await
        .expect("the account is stored");
    Person {
        id: account.id,
        email: email.to_owned(),
        fingerprint: account.public_bundle[..64].to_vec(),
    }
}

async fn make_space(store: &SqlStore, owner: UserId) -> (SpaceId, CollectionId) {
    let space = SpaceId::random();
    let collection = CollectionId::random();
    CreateSpace {
        spaces: store.clone(),
        events: store.clone(),
        clock: FixedClock,
    }
    .execute(
        &actor(owner),
        CreateSpaceInput {
            id: space,
            name: name(1),
            sealed_space_key: sealed_key(2),
            collection: NewCollection {
                id: collection,
                name: name(3),
                sealed_key: sealed_key(4),
            },
        },
    )
    .await
    .expect("the space is made");
    (space, collection)
}

/// `owner` invites `member` with Edit on `collection`, and confirms them.
async fn join(
    store: &SqlStore,
    space: SpaceId,
    collection: CollectionId,
    owner: &Person,
    member: &Person,
) {
    InviteMember {
        spaces: store.clone(),
        users: store.clone(),
        events: store.clone(),
        clock: FixedClock,
    }
    .execute(
        &actor(owner.id),
        space,
        InviteInput {
            email: member.email.clone(),
            role: SpaceRole::Member,
            custom: CustomPermissions::NONE,
            grants: vec![(collection, CollectionPermission::Edit)],
        },
    )
    .await
    .expect("invited");
    AcceptInvitation {
        spaces: store.clone(),
        events: store.clone(),
        clock: FixedClock,
    }
    .execute(&actor(member.id), space)
    .await
    .expect("accepted");
    ConfirmMember {
        spaces: store.clone(),
        users: store.clone(),
        fingerprints: FirstBytes,
        events: store.clone(),
        clock: FixedClock,
    }
    .execute(
        &actor(owner.id),
        space,
        member.id,
        ConfirmInput {
            fingerprint: member.fingerprint.clone(),
            statement: b"compared".to_vec(),
            signature: vec![0x55; 3373],
            sealed_space_key: sealed_key(5),
            collection_keys: vec![SealedCollectionKey {
                collection,
                user: member.id,
                sealed: sealed_key(6),
            }],
        },
    )
    .await
    .expect("confirmed");
}

fn write(
    space: SpaceId,
    id: ItemId,
    expected: Option<u64>,
    revision: u64,
    key_version: u32,
) -> ItemWrite {
    ItemWrite {
        id,
        owner: Owner::Space(space),
        kind: ItemKind::try_from("login".to_owned()).expect("a valid kind"),
        format: ItemFormat::Kem1,
        expected: expected.map(Revision),
        revision: Revision(revision),
        key_version,
        sealed: Some(Sealed {
            ciphertext: vec![0xaa; 64],
            item_key: vec![0xbb; kemlock_domain::item::ITEM_KEY_LEN],
        }),
    }
}

fn put_space_item(
    store: &SqlStore,
) -> PutSpaceItem<SqlStore, SqlStore, SqlStore, Silent, FixedClock> {
    PutSpaceItem {
        spaces: store.clone(),
        items: store.clone(),
        events: store.clone(),
        push: Silent,
        clock: FixedClock,
        config: AuthConfig::default(),
    }
}

#[tokio::test]
async fn a_new_space_reads_back_as_it_was_made() {
    let store = memory().await;
    let sam = person(&store, 1, "sam@example.org").await;
    let (space, everyone) = make_space(&store, sam.id).await;

    let loaded = SpaceRepo::load(&store, space)
        .await
        .expect("loads")
        .expect("the space exists");
    assert_eq!(loaded.space.id, space);
    assert_eq!(loaded.space.name, name(1));
    assert_eq!(loaded.space.key_version, 1);
    assert_eq!(loaded.space.keys_pending_since, None);
    assert_eq!(loaded.members.len(), 1);
    assert_eq!(loaded.members[0].user, sam.id);
    assert_eq!(loaded.members[0].role, SpaceRole::Owner);
    assert_eq!(loaded.members[0].state, MemberState::Confirmed);
    assert_eq!(loaded.members[0].sealed_space_key, Some(sealed_key(2)));
    assert_eq!(loaded.members[0].key_version, Some(1));
    assert_eq!(loaded.members[0].confirmation, None);
    assert_eq!(loaded.collections.len(), 1);
    assert_eq!(loaded.collections[0].id, everyone);
    assert_eq!(loaded.collections[0].parent, None);
    assert_eq!(
        loaded.grants,
        vec![CollectionGrant {
            collection: everyone,
            grantee: Grantee::Member(sam.id),
            permission: CollectionPermission::Manage,
        }]
    );
    assert_eq!(
        SpaceRepo::holders(&store, space).await.expect("holders"),
        vec![(everyone, sam.id)]
    );
    assert_eq!(SpaceRepo::load(&store, SpaceId::random()).await, Ok(None));
}

#[tokio::test]
async fn a_space_id_is_taken_once() {
    let store = memory().await;
    let sam = person(&store, 1, "sam@example.org").await;
    let (space, _) = make_space(&store, sam.id).await;
    let existing = SpaceRepo::load(&store, space)
        .await
        .expect("loads")
        .expect("exists");
    let again = SpaceRepo::create(
        &store,
        SpaceChanges {
            space: Some(existing.space.clone()),
            ..SpaceChanges::new(space)
        },
    )
    .await;
    assert_eq!(again, Err(StoreError::Duplicate));
    // Creating needs the row.
    let rowless = SpaceRepo::create(&store, SpaceChanges::new(SpaceId::random())).await;
    assert!(matches!(rowless, Err(StoreError::Backend(_))));
}

#[tokio::test]
async fn confirming_stores_the_signed_statement_and_the_sealed_keys() {
    let store = memory().await;
    let sam = person(&store, 1, "sam@example.org").await;
    let ana = person(&store, 2, "ana@example.org").await;
    let (space, everyone) = make_space(&store, sam.id).await;
    join(&store, space, everyone, &sam, &ana).await;

    let loaded = SpaceRepo::load(&store, space)
        .await
        .expect("loads")
        .expect("exists");
    let member = loaded.member(ana.id).expect("Ana is a member");
    assert_eq!(member.state, MemberState::Confirmed);
    assert_eq!(member.sealed_space_key, Some(sealed_key(5)));
    let confirmation = member.confirmation.as_ref().expect("a confirmation");
    assert_eq!(confirmation.by, sam.id);
    assert_eq!(confirmation.fingerprint, ana.fingerprint);
    assert_eq!(confirmation.statement, b"compared".to_vec());
    assert_eq!(confirmation.signature, vec![0x55; 3373]);
    assert_eq!(confirmation.member_key_version, 1);
    assert_eq!(loaded.access(ana.id, everyone).map(|a| a.edit), Some(true));

    let copies = SpaceRepo::key_copies(&store, space, ana.id)
        .await
        .expect("copies");
    assert_eq!(copies.len(), 1);
    assert_eq!(copies[0].sealed, sealed_key(6));
    assert_eq!(
        SpaceRepo::memberships(&store, ana.id)
            .await
            .expect("memberships")
            .len(),
        1
    );
    let owners = SyncOwners {
        spaces: store.clone(),
    }
    .execute(ana.id)
    .await
    .expect("owners");
    assert_eq!(owners, vec![Owner::User(ana.id), Owner::Space(space)]);
    let summaries = SpaceRepo::spaces(&store, &[space, SpaceId::random()])
        .await
        .expect("spaces");
    assert_eq!(summaries.len(), 1);
    let view = GetSpace {
        spaces: store.clone(),
    }
    .execute(&actor(ana.id), space)
    .await
    .expect("a view");
    assert_eq!(view.collection_keys.len(), 1);
}

#[tokio::test]
async fn a_space_item_is_stored_with_its_collection_and_syncs_to_members() {
    let store = memory().await;
    let sam = person(&store, 1, "sam@example.org").await;
    let ana = person(&store, 2, "ana@example.org").await;
    let (space, everyone) = make_space(&store, sam.id).await;
    join(&store, space, everyone, &sam, &ana).await;

    let id = ItemId::random();
    let item = put_space_item(&store)
        .execute(&actor(ana.id), everyone, write(space, id, None, 1, 1))
        .await
        .expect("Ana writes");
    assert_eq!(item.owner, Owner::Space(space));
    assert_eq!(
        SpaceRepo::item_collections(&store, &[id, ItemId::random()])
            .await
            .expect("links"),
        vec![(id, everyone)]
    );
    let infos = SpaceRepo::space_items(&store, space).await.expect("items");
    assert_eq!(infos.len(), 1);
    assert_eq!(infos[0].collection, Some(everyone));
    assert!(!infos[0].deleted);
    assert_eq!(infos[0].revision, Revision(1));

    // A replace keeps the item's single link; a delete leaves a tombstone.
    put_space_item(&store)
        .execute(&actor(sam.id), everyone, write(space, id, Some(1), 2, 1))
        .await
        .expect("Sam replaces");
    let mut gone = write(space, id, Some(2), 3, 1);
    gone.sealed = None;
    put_space_item(&store)
        .execute(&actor(ana.id), everyone, gone)
        .await
        .expect("Ana deletes");
    let infos = SpaceRepo::space_items(&store, space).await.expect("items");
    assert_eq!((infos.len(), infos[0].deleted), (1, true));

    // Members of the space receive the space's items; others don't.
    let owners = SyncOwners {
        spaces: store.clone(),
    }
    .execute(ana.id)
    .await
    .expect("owners");
    let page = ItemStore::changes_since(&store, &owners, &VersionVector::new(), 100)
        .await
        .expect("a page");
    assert_eq!(page.items.len(), 1);
    let stranger = person(&store, 3, "zed@example.org").await;
    let none = SyncOwners {
        spaces: store.clone(),
    }
    .execute(stranger.id)
    .await
    .expect("owners");
    let nothing = ItemStore::changes_since(&store, &none, &VersionVector::new(), 100)
        .await
        .expect("a page");
    assert!(nothing.items.is_empty());
}

#[tokio::test]
async fn offboarding_and_replacing_keys_go_through_the_store() {
    let store = memory().await;
    let sam = person(&store, 1, "sam@example.org").await;
    let ana = person(&store, 2, "ana@example.org").await;
    let (space, everyone) = make_space(&store, sam.id).await;
    join(&store, space, everyone, &sam, &ana).await;
    let id = ItemId::random();
    put_space_item(&store)
        .execute(&actor(ana.id), everyone, write(space, id, None, 1, 1))
        .await
        .expect("Ana writes");

    let outcome = Offboard {
        spaces: store.clone(),
        events: store.clone(),
        clock: FixedClock,
    }
    .revoke(&actor(sam.id), space, ana.id)
    .await
    .expect("Ana is revoked");
    assert!(outcome.keys_pending);
    assert_eq!(outcome.exposed.len(), 1);
    assert_eq!(outcome.exposed[0].live_items, 1);
    let paused = SpaceRepo::load(&store, space)
        .await
        .expect("loads")
        .expect("exists");
    assert!(paused.space.keys_pending_since.is_some());
    assert!(paused.collections[0].stale_since.is_some());
    assert_eq!(
        SpaceRepo::holders(&store, space).await.expect("holders"),
        vec![(everyone, sam.id)]
    );
    let revoked = paused.member(ana.id).expect("the row stays");
    assert_eq!(revoked.state, MemberState::Revoked);
    assert_eq!(revoked.sealed_space_key, None);

    // A write that fails in the store changes nothing else: the space key stays at version 1.
    let mut bad = paused.space.clone();
    bad.key_version = 9;
    bad.keys_pending_since = None;
    let half = SpaceRepo::replace_keys(
        &store,
        KeyReplacement {
            changes: SpaceChanges {
                space: Some(bad),
                ..SpaceChanges::new(space)
            },
            writes: vec![(draft(id, Owner::Space(space), Some(7), 8), everyone)],
        },
    )
    .await;
    assert_eq!(
        half,
        Err(StoreError::Conflict {
            item: id,
            current: Some(Revision(1))
        })
    );
    let still = SpaceRepo::load(&store, space)
        .await
        .expect("loads")
        .expect("exists");
    assert_eq!(still.space.key_version, 1);
    assert!(still.space.keys_pending_since.is_some());

    // The real replacement lands everything.
    let stored = ReplaceKeys {
        spaces: store.clone(),
        items: store.clone(),
        tags: store.clone(),
        events: store.clone(),
        push: Silent,
        clock: FixedClock,
        config: AuthConfig::default(),
    }
    .execute(
        &actor(sam.id),
        space,
        ReplacementInput {
            space_key_version: 2,
            space_name: Some(name(40)),
            sealed_space_keys: vec![(sam.id, sealed_key(20))],
            collection_names: vec![(everyone, name(41))],
            group_names: Vec::new(),
            collections: vec![CollectionRekey {
                collection: everyone,
                key_version: 2,
                keys: vec![SealedCollectionKey {
                    collection: everyone,
                    user: sam.id,
                    sealed: sealed_key(21),
                }],
            }],
            writes: vec![(everyone, write(space, id, Some(1), 2, 2))],
        },
    )
    .await
    .expect("the replacement lands");
    assert_eq!(stored.len(), 1);
    let after = SpaceRepo::load(&store, space)
        .await
        .expect("loads")
        .expect("exists");
    assert_eq!(after.space.key_version, 2);
    assert_eq!(after.space.name, name(40));
    assert_eq!(after.space.keys_pending_since, None);
    assert_eq!(after.collections[0].key_version, 2);
    assert_eq!(after.collections[0].name, name(41));
    assert_eq!(after.collections[0].stale_since, None);
    assert_eq!(
        after.member(sam.id).expect("Sam").sealed_space_key,
        Some(sealed_key(20))
    );
    let copies = SpaceRepo::key_copies(&store, space, sam.id)
        .await
        .expect("copies");
    assert_eq!(
        (copies[0].key_version, copies[0].sealed.clone()),
        (2, sealed_key(21))
    );
    let rewritten = ItemStore::get(&store, id)
        .await
        .expect("get")
        .expect("the item");
    assert_eq!(
        (rewritten.revision, rewritten.key_version),
        (Revision(2), 2)
    );
    assert_eq!(rewritten.owner, Owner::Space(space));
}

#[tokio::test]
async fn removing_a_member_clears_their_grants_keys_and_group_memberships() {
    let store = memory().await;
    let sam = person(&store, 1, "sam@example.org").await;
    let ana = person(&store, 2, "ana@example.org").await;
    let (space, everyone) = make_space(&store, sam.id).await;
    join(&store, space, everyone, &sam, &ana).await;
    let ops = GroupId::random();
    SpaceRepo::apply(
        &store,
        SpaceChanges {
            groups: vec![Group {
                id: ops,
                space,
                name: name(30),
                members: BTreeSet::from([ana.id, sam.id]),
                created_at: datetime!(2026-06-01 12:00:00 UTC),
            }],
            grants: vec![CollectionGrant {
                collection: everyone,
                grantee: Grantee::Group(ops),
                permission: CollectionPermission::View,
            }],
            ..SpaceChanges::new(space)
        },
    )
    .await
    .expect("a group and its grant");
    let loaded = SpaceRepo::load(&store, space)
        .await
        .expect("loads")
        .expect("exists");
    assert_eq!(loaded.groups.len(), 1);
    assert_eq!(loaded.groups[0].members, BTreeSet::from([ana.id, sam.id]));
    assert_eq!(loaded.grants.len(), 3);

    SpaceRepo::apply(
        &store,
        SpaceChanges {
            members_removed: vec![ana.id],
            ..SpaceChanges::new(space)
        },
    )
    .await
    .expect("Ana is removed");
    let loaded = SpaceRepo::load(&store, space)
        .await
        .expect("loads")
        .expect("exists");
    assert!(loaded.member(ana.id).is_none());
    assert_eq!(loaded.groups[0].members, BTreeSet::from([sam.id]));
    assert!(
        loaded
            .grants
            .iter()
            .all(|g| g.grantee != Grantee::Member(ana.id))
    );
    assert_eq!(
        SpaceRepo::holders(&store, space).await.expect("holders"),
        vec![(everyone, sam.id)]
    );
    assert!(
        SpaceRepo::memberships(&store, ana.id)
            .await
            .expect("memberships")
            .is_empty()
    );

    // Deleting the group takes its grants with it.
    SpaceRepo::apply(
        &store,
        SpaceChanges {
            groups_removed: vec![ops],
            ..SpaceChanges::new(space)
        },
    )
    .await
    .expect("the group is deleted");
    let loaded = SpaceRepo::load(&store, space)
        .await
        .expect("loads")
        .expect("exists");
    assert!(loaded.groups.is_empty());
    assert_eq!(loaded.grants.len(), 1);
}

#[tokio::test]
async fn deleting_a_collection_clears_its_grants_keys_and_item_links() {
    let store = memory().await;
    let sam = person(&store, 1, "sam@example.org").await;
    let (space, everyone) = make_space(&store, sam.id).await;
    let id = ItemId::random();
    put_space_item(&store)
        .execute(&actor(sam.id), everyone, write(space, id, None, 1, 1))
        .await
        .expect("Sam writes");
    let collection = SpaceRepo::load(&store, space)
        .await
        .expect("loads")
        .expect("exists")
        .collections[0]
        .clone();

    SpaceRepo::apply(
        &store,
        SpaceChanges {
            collections_removed: vec![everyone],
            ..SpaceChanges::new(space)
        },
    )
    .await
    .expect("the collection is deleted");
    let loaded = SpaceRepo::load(&store, space)
        .await
        .expect("loads")
        .expect("exists");
    assert!(loaded.collections.is_empty() && loaded.grants.is_empty());
    assert!(
        SpaceRepo::item_collections(&store, &[id])
            .await
            .expect("links")
            .is_empty()
    );

    // Bring a collection with the same id back: nothing of the old one is left under it.
    SpaceRepo::apply(
        &store,
        SpaceChanges {
            collections: vec![collection],
            ..SpaceChanges::new(space)
        },
    )
    .await
    .expect("a collection with the old id");
    let loaded = SpaceRepo::load(&store, space)
        .await
        .expect("loads")
        .expect("exists");
    assert_eq!(loaded.collections.len(), 1);
    assert!(loaded.grants.is_empty());
    assert!(
        SpaceRepo::holders(&store, space)
            .await
            .expect("holders")
            .is_empty()
    );
}

fn put_space_batch(
    store: &SqlStore,
) -> kemlock_app::spaces::PutSpaceBatch<SqlStore, SqlStore, SqlStore, Silent, FixedClock> {
    kemlock_app::spaces::PutSpaceBatch {
        spaces: store.clone(),
        items: store.clone(),
        events: store.clone(),
        push: Silent,
        clock: FixedClock,
        config: AuthConfig::default(),
    }
}

fn vault_write(owner: UserId, id: ItemId) -> ItemWrite {
    ItemWrite {
        owner: Owner::User(owner),
        ..write(SpaceId::random(), id, None, 1, 1)
    }
}

#[tokio::test]
async fn a_batch_of_vault_and_space_items_is_stored_whole_or_not_at_all() {
    let store = memory().await;
    let sam = person(&store, 1, "sam@example.org").await;
    let (space, everyone) = make_space(&store, sam.id).await;
    let (own, shared) = (ItemId::random(), ItemId::random());

    let stored = put_space_batch(&store)
        .execute(
            &actor(sam.id),
            vec![
                (vault_write(sam.id, own), None),
                (write(space, shared, None, 1, 1), Some(everyone)),
            ],
        )
        .await
        .expect("the batch is stored");
    assert_eq!(stored.len(), 2);
    assert_eq!(
        SpaceRepo::item_collections(&store, &[own, shared])
            .await
            .expect("links"),
        vec![(shared, everyone)],
        "only the space item has a collection"
    );

    // The second write is stale: the first is rolled back with it.
    let fresh = ItemId::random();
    let refused = put_space_batch(&store)
        .execute(
            &actor(sam.id),
            vec![
                (vault_write(sam.id, fresh), None),
                (write(space, shared, None, 1, 1), Some(everyone)),
            ],
        )
        .await
        .err();
    assert!(matches!(
        refused,
        Some(kemlock_app::spaces::SpacesError::StaleItem { .. })
    ));
    assert!(
        ItemStore::get(&store, fresh)
            .await
            .expect("reads")
            .is_none(),
        "the vault item of the failed batch was not kept"
    );
}

#[tokio::test]
async fn the_require_sso_policy_is_kept_per_space_and_binds_confirmed_members() {
    use kemlock_app::sso::{MembershipFacts, SpaceMembership};
    let store = memory().await;
    let sam = person(&store, 1, "sam@example.org").await;
    let ana = person(&store, 2, "ana@example.org").await;
    let (space, everyone) = make_space(&store, sam.id).await;
    let (other, _) = make_space(&store, sam.id).await;
    join(&store, space, everyone, &sam, &ana).await;

    // No policy stored: nobody is bound.
    assert_eq!(
        SpaceRepo::require_sso_of(&store, &[space, other])
            .await
            .expect("policies"),
        Vec::<SpaceId>::new()
    );
    SpaceRepo::set_require_sso(&store, space, true)
        .await
        .expect("set");
    assert_eq!(
        SpaceRepo::require_sso_of(&store, &[space, other])
            .await
            .expect("policies"),
        vec![space]
    );
    let facts = |user| MembershipFacts::spaces_of(&store, user);
    assert_eq!(
        facts(ana.id).await.expect("facts"),
        vec![SpaceMembership {
            space,
            role: kemlock_app::sso::SpaceRole::Member,
            require_sso: true,
        }]
    );
    let mut sams = facts(sam.id).await.expect("facts");
    sams.sort_by_key(|m| m.space);
    assert_eq!(sams.len(), 2);
    assert!(
        sams.iter()
            .all(|m| m.role == kemlock_app::sso::SpaceRole::Owner)
    );
    assert_eq!(sams.iter().filter(|m| m.require_sso).count(), 1);

    // Turning it off keeps the row and clears the flag.
    SpaceRepo::set_require_sso(&store, space, false)
        .await
        .expect("cleared");
    assert!(
        SpaceRepo::require_sso_of(&store, &[space])
            .await
            .expect("policies")
            .is_empty()
    );
}

#[tokio::test]
async fn another_space_cannot_take_over_or_wipe_a_collection_or_group() {
    let store = memory().await;
    let sam = person(&store, 1, "sam@example.org").await;
    let eve = person(&store, 2, "eve@example.org").await;
    let (victim, everyone) = make_space(&store, sam.id).await;
    let (attacker, _) = make_space(&store, eve.id).await;
    let group = Group {
        id: GroupId::random(),
        space: victim,
        name: name(5),
        members: BTreeSet::from([sam.id]),
        created_at: datetime!(2026-06-01 12:00:00 UTC),
    };
    SpaceRepo::apply(
        &store,
        SpaceChanges {
            groups: vec![group.clone()],
            ..SpaceChanges::new(victim)
        },
    )
    .await
    .expect("the victim's own group");
    let before = SpaceRepo::load(&store, victim)
        .await
        .expect("loads")
        .expect("exists");
    let holders = SpaceRepo::holders(&store, victim).await.expect("holders");
    assert_eq!(
        SpaceRepo::collection_space(&store, everyone).await,
        Ok(Some(victim))
    );
    assert_eq!(
        SpaceRepo::group_space(&store, group.id).await,
        Ok(Some(victim))
    );
    assert_eq!(
        SpaceRepo::collection_space(&store, CollectionId::random()).await,
        Ok(None)
    );

    // Taking the id over: the collection and the group, each under the attacker's own space.
    let mut moved = before.collections[0].clone();
    moved.space = attacker;
    let mut hijacked = group.clone();
    hijacked.space = attacker;
    hijacked.members = BTreeSet::new();
    let attempts = [
        SpaceChanges {
            collections: vec![moved],
            ..SpaceChanges::new(attacker)
        },
        SpaceChanges {
            groups: vec![hijacked],
            ..SpaceChanges::new(attacker)
        },
        // Wiping it: removals by id, and the grants and key copies under it.
        SpaceChanges {
            collections_removed: vec![everyone],
            ..SpaceChanges::new(attacker)
        },
        SpaceChanges {
            groups_removed: vec![group.id],
            ..SpaceChanges::new(attacker)
        },
        SpaceChanges {
            grants_removed: vec![(everyone, Grantee::Member(sam.id))],
            ..SpaceChanges::new(attacker)
        },
        SpaceChanges {
            key_copies_removed: vec![(everyone, sam.id)],
            ..SpaceChanges::new(attacker)
        },
        // A grant on the victim's collection, to the victim's group, is just as foreign.
        SpaceChanges {
            grants: vec![CollectionGrant {
                collection: everyone,
                grantee: Grantee::Group(group.id),
                permission: CollectionPermission::Manage,
            }],
            ..SpaceChanges::new(attacker)
        },
        // A change to one space that carries a row of another.
        SpaceChanges {
            groups: vec![group.clone()],
            ..SpaceChanges::new(attacker)
        },
    ];
    for changes in attempts {
        assert_eq!(
            SpaceRepo::apply(&store, changes).await,
            Err(StoreError::Duplicate)
        );
    }

    // Nothing of the victim's moved or went.
    let after = SpaceRepo::load(&store, victim)
        .await
        .expect("loads")
        .expect("exists");
    assert_eq!(after.collections, before.collections);
    assert_eq!(after.grants, before.grants);
    assert_eq!(after.groups, before.groups);
    assert_eq!(
        SpaceRepo::holders(&store, victim).await.expect("holders"),
        holders
    );
    let theirs = SpaceRepo::load(&store, attacker)
        .await
        .expect("loads")
        .expect("exists");
    assert!(theirs.groups.is_empty());
    assert!(theirs.collections.iter().all(|c| c.id != everyone));

    // The victim's own space can still change and delete them.
    SpaceRepo::apply(
        &store,
        SpaceChanges {
            groups_removed: vec![group.id],
            collections_removed: vec![everyone],
            ..SpaceChanges::new(victim)
        },
    )
    .await
    .expect("the owner space deletes its own");
    assert_eq!(
        SpaceRepo::collection_space(&store, everyone).await,
        Ok(None)
    );
}

#[tokio::test]
async fn a_change_that_leaves_a_space_with_no_confirmed_owner_is_refused() {
    let store = memory().await;
    let sam = person(&store, 1, "sam@example.org").await;
    let lee = person(&store, 2, "lee@example.org").await;
    let (space, _) = make_space(&store, sam.id).await;
    let sam_row = SpaceRepo::load(&store, space)
        .await
        .expect("loads")
        .expect("exists")
        .members[0]
        .clone();
    let mut lee_row = sam_row.clone();
    lee_row.user = lee.id;
    SpaceRepo::apply(
        &store,
        SpaceChanges {
            members: vec![lee_row.clone()],
            ..SpaceChanges::new(space)
        },
    )
    .await
    .expect("a second owner");

    // Two owners each take the other out, each valid against what they read. The first lands; the
    // second would leave members but no owner and is refused, whichever way it is done. (Sam
    // comes back as an admin first, so that members remain.)
    SpaceRepo::apply(
        &store,
        SpaceChanges {
            members_removed: vec![sam.id],
            ..SpaceChanges::new(space)
        },
    )
    .await
    .expect("Lee removes Sam");
    let mut sam_back = sam_row.clone();
    sam_back.role = SpaceRole::Admin;
    SpaceRepo::apply(
        &store,
        SpaceChanges {
            members: vec![sam_back],
            ..SpaceChanges::new(space)
        },
    )
    .await
    .expect("an admin joins");
    let removed = SpaceRepo::apply(
        &store,
        SpaceChanges {
            members_removed: vec![lee.id],
            ..SpaceChanges::new(space)
        },
    )
    .await;
    assert_eq!(removed, Err(StoreError::Backend(OWNER_REQUIRED.to_owned())));
    let mut demoted = lee_row.clone();
    demoted.role = SpaceRole::Admin;
    let mut revoked = lee_row.clone();
    revoked.state = MemberState::Revoked;
    for member in [demoted, revoked] {
        let refused = SpaceRepo::apply(
            &store,
            SpaceChanges {
                members: vec![member],
                ..SpaceChanges::new(space)
            },
        )
        .await;
        assert_eq!(refused, Err(StoreError::Backend(OWNER_REQUIRED.to_owned())));
    }
    // Lee is still the confirmed owner, and the refusals rolled back whole.
    let after = SpaceRepo::load(&store, space)
        .await
        .expect("loads")
        .expect("exists");
    let lee_now = after
        .members
        .iter()
        .find(|m| m.user == lee.id)
        .expect("Lee");
    assert_eq!(
        (lee_now.role, lee_now.state),
        (SpaceRole::Owner, MemberState::Confirmed)
    );
    assert_eq!(after.members.len(), 2);

    // A change that leaves an owner still works, and so does one that removes everyone (an
    // organization's deletion leaves no space to manage).
    SpaceRepo::apply(
        &store,
        SpaceChanges {
            members_removed: vec![sam.id],
            ..SpaceChanges::new(space)
        },
    )
    .await
    .expect("the admin leaves");
    SpaceRepo::apply(
        &store,
        SpaceChanges {
            members_removed: vec![lee.id],
            ..SpaceChanges::new(space)
        },
    )
    .await
    .expect("the last member leaves with the space");
    let emptied = SpaceRepo::load(&store, space)
        .await
        .expect("loads")
        .expect("exists");
    assert!(emptied.members.is_empty());
}

#[tokio::test]
async fn two_owners_removing_each_other_together_leave_one_of_them() {
    let store = memory().await;
    let sam = person(&store, 1, "sam@example.org").await;
    let lee = person(&store, 2, "lee@example.org").await;
    let ana = person(&store, 3, "ana@example.org").await;
    let (space, _) = make_space(&store, sam.id).await;
    let sam_row = SpaceRepo::load(&store, space)
        .await
        .expect("loads")
        .expect("exists")
        .members[0]
        .clone();
    let mut lee_row = sam_row.clone();
    lee_row.user = lee.id;
    let mut ana_row = sam_row.clone();
    ana_row.user = ana.id;
    ana_row.role = SpaceRole::Admin;
    SpaceRepo::apply(
        &store,
        SpaceChanges {
            members: vec![lee_row, ana_row],
            ..SpaceChanges::new(space)
        },
    )
    .await
    .expect("a second owner and an admin");

    // Each owner's request was valid against the two owners it read; they land together. The store
    // takes them one at a time, so the second meets the first's result and is refused.
    let remove = |user: UserId| {
        let store = store.clone();
        async move {
            SpaceRepo::apply(
                &store,
                SpaceChanges {
                    members_removed: vec![user],
                    ..SpaceChanges::new(space)
                },
            )
            .await
        }
    };
    let (first, second) = tokio::join!(remove(sam.id), remove(lee.id));
    assert_eq!(
        [first.is_ok(), second.is_ok()]
            .iter()
            .filter(|ok| **ok)
            .count(),
        1,
        "{first:?} {second:?}"
    );
    let after = SpaceRepo::load(&store, space)
        .await
        .expect("loads")
        .expect("exists");
    let owners = after
        .members
        .iter()
        .filter(|m| m.role == SpaceRole::Owner && m.state == MemberState::Confirmed)
        .count();
    assert_eq!(owners, 1);
}

#[tokio::test]
async fn a_rotation_counts_only_accepted_and_confirmed_memberships() {
    use kemlock_app::rotation::RotationStore;
    let store = memory().await;
    let owner = person(&store, 1, "owner-rot@example.org").await;
    let guest = person(&store, 2, "guest-rot@example.org").await;
    let (space, collection) = make_space(&store, owner.id).await;
    let spaces_of = |user: UserId| {
        let store = store.clone();
        async move {
            RotationStore::holdings(&store, user)
                .await
                .expect("holdings")
                .spaces
        }
    };
    assert_eq!(spaces_of(owner.id).await, 1);

    // Invited and not accepted: no membership, so a rotation need not move any space's keys.
    InviteMember {
        spaces: store.clone(),
        users: store.clone(),
        events: store.clone(),
        clock: FixedClock,
    }
    .execute(
        &actor(owner.id),
        space,
        InviteInput {
            email: guest.email.clone(),
            role: SpaceRole::Member,
            custom: CustomPermissions::NONE,
            grants: vec![(collection, CollectionPermission::Edit)],
        },
    )
    .await
    .expect("invited");
    assert_eq!(spaces_of(guest.id).await, 0);

    // Accepted: a member now.
    AcceptInvitation {
        spaces: store.clone(),
        events: store.clone(),
        clock: FixedClock,
    }
    .execute(&actor(guest.id), space)
    .await
    .expect("accepted");
    assert_eq!(spaces_of(guest.id).await, 1);
}

#[tokio::test]
async fn a_rotation_keeps_the_old_keys_for_an_account_in_a_space_and_waits_for_them_to_be_used() {
    use kemlock_app::rotation::{
        Install, InstallRequest, RotationError, RotationStore as Rotations,
    };
    let store = memory().await;
    let owner = person(&store, 1, "owner-keys@example.org").await;
    make_space(&store, owner.id).await;
    let account = UserRepo::by_id(&store, owner.id)
        .await
        .expect("read")
        .expect("account");
    let request = |from: u32| InstallRequest {
        rotation: [7; 16],
        from_version: from,
        to_version: from + 1,
        public_bundle: vec![8; 3621],
        bundle_signature: vec![9; 3373],
        sealed_private_keys: vec![10; 189],
        sealed_previous_private_keys: vec![11; 189],
        wrapped_root_key: Some(vec![12; 92]),
        kit: None,
        drop_kit: false,
        device_copy: None,
        passkeys: Vec::new(),
        drop_passkeys: Vec::new(),
        emergency: Vec::new(),
        drop_emergency: Vec::new(),
        recovery: Vec::new(),
        drop_recovery: Vec::new(),
        sends: Vec::new(),
        spaces_handled: true,
    };
    let install = |before: &kemlock_domain::User, request: InstallRequest| {
        let mut after = before.clone();
        after.key_version = request.to_version;
        after.security_stamp = uuid::Uuid::new_v4();
        after.updated_at = datetime!(2026-12-02 10:00:00 UTC);
        Install {
            request,
            before: before.clone(),
            after,
            device: DeviceId::random(),
            now: datetime!(2026-12-02 10:00:00 UTC),
            staged_since: datetime!(2026-12-02 08:00:00 UTC),
        }
    };

    Rotations::install(&store, install(&account, request(1)))
        .await
        .expect("the first rotation");
    let kept = Rotations::previous_keys(&store, owner.id)
        .await
        .expect("read")
        .expect("the old keys are kept for the space's rekey");
    assert_eq!((kept.key_version, kept.sealed), (1, vec![11; 189]));

    // A second rotation would replace them before the space has moved: refused, nothing written.
    let after = UserRepo::by_id(&store, owner.id)
        .await
        .expect("read")
        .expect("account");
    let second = Rotations::install(&store, install(&after, request(2))).await;
    assert_eq!(second, Err(RotationError::SpacesPending));
    assert_eq!(
        UserRepo::by_id(&store, owner.id)
            .await
            .expect("read")
            .expect("account")
            .key_version,
        2
    );

    // Once the space has moved, the keys are dropped and the next rotation goes through.
    assert_eq!(
        Rotations::clear_previous_keys(&store, owner.id).await,
        Ok(true)
    );
    let after = UserRepo::by_id(&store, owner.id)
        .await
        .expect("read")
        .expect("account");
    Rotations::install(&store, install(&after, request(2)))
        .await
        .expect("the second rotation");
}
