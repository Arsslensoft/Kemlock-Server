//! The space chain on SQLite: an append is one transaction that checks the head, stores the
//! records, boxes and names and derives the space tables; a racing append is `Stale`; and outside
//! changes to a chained space are queued (the default), refused or applied as the setting says.

mod common;
// Real signed records, as the API tests make them: sync takes a chained space's members from the
// verified chain, so a fixture that syncs can't store filler bytes as records.
#[path = "../../kemlock-app/tests/chain_kit/mod.rs"]
mod chain_kit;

use chain_kit::{Chain, Person, Step};
use common::{draft, memory, put, tombstone};
use kemlock_app::SyncDelta;
use kemlock_app::SyncOutcome;
use kemlock_app::ports::ItemStore;
use kemlock_app::spaces::chain_project::{Batch, project};
use kemlock_app::spaces::{
    AppendOutcome, ChainAppend, ChainHead, ExternalChangeMode, ExternalSource, PendingChange,
    SpaceChainRepo, SpaceChanges, SpaceRepo, StoredName, StoredRecord, StoredSeal,
};
use kemlock_crypto::space_chain::{self as sc, KeyRef, NameTarget};
use kemlock_domain::spaces::{
    CollectionId, CollectionPermission, CustomPermissions, Grantee, Member, MemberState, Space,
    SpaceRole,
};
use kemlock_domain::{ItemDraft, ItemId, Owner, SpaceId, SyncCursor, UserId, VersionVector};
use kemlock_store_sql::SqlStore;
use std::sync::Arc;
use time::OffsetDateTime;
use time::macros::datetime;
use uuid::Uuid;

const NOW: OffsetDateTime = datetime!(2026-06-01 12:00:00 UTC);

fn record(seq: u64, fill: u8, by: UserId) -> StoredRecord {
    StoredRecord {
        seq,
        link: [fill; 32],
        epoch: 1,
        by,
        at: 1_780_000_000,
        entry: vec![fill; 300],
        signature: vec![fill; 3373],
        cosignature: (seq == 2).then(|| vec![fill; 3373]),
    }
}

fn head(r: &StoredRecord) -> ChainHead {
    ChainHead {
        seq: r.seq,
        link: r.link,
        epoch: r.epoch,
    }
}

fn owner(space: SpaceId, user: UserId) -> Member {
    let mut m = Member::invited(
        space,
        user,
        SpaceRole::Owner,
        CustomPermissions::NONE,
        user,
        NOW,
    );
    m.state = MemberState::Confirmed;
    m
}

/// A chained space made by one append: its row, its owner and the first record.
async fn chained(store: &SqlStore) -> (SpaceId, UserId, ChainHead) {
    let space = SpaceId(Uuid::new_v4());
    let sam = UserId(Uuid::new_v4());
    let first = record(0, 1, sam);
    let mut changes = SpaceChanges::new(space);
    changes.space = Some(Space {
        id: space,
        name: vec![7; 40],
        key_version: 1,
        keys_pending_since: None,
        created_at: NOW,
        updated_at: NOW,
    });
    changes.members = vec![owner(space, sam)];
    let outcome = store
        .chain_append(
            space,
            ChainAppend {
                expected: None,
                records: vec![first.clone()],
                seals: vec![StoredSeal {
                    seq: 0,
                    key: KeyRef::Space,
                    version: 1,
                    member: sam,
                    bundle_version: 1,
                    sealed: vec![9; 1661],
                }],
                names: vec![StoredName {
                    seq: 0,
                    target: NameTarget::Space,
                    version: 1,
                    hash: [3; 32],
                    sealed: vec![7; 40],
                }],
                changes,
                creating: true,
                held: Vec::new(),
                writes: Vec::new(),
                answers: None,
                state: None,
            },
        )
        .await
        .expect("the append");
    assert_eq!(outcome, AppendOutcome::Appended(head(&first)));
    (space, sam, head(&first))
}

fn append(expected: Option<ChainHead>, records: Vec<StoredRecord>) -> ChainAppend {
    ChainAppend {
        expected,
        records,
        seals: Vec::new(),
        names: Vec::new(),
        changes: SpaceChanges::new(SpaceId(Uuid::nil())),
        creating: false,
        held: Vec::new(),
        writes: Vec::new(),
        answers: None,
        state: None,
    }
}

#[tokio::test]
async fn an_append_stores_the_chain_and_derives_the_space_in_one_transaction() {
    let store = memory().await;
    let (space, sam, first) = chained(&store).await;

    // The server's tables follow the record.
    let state = SpaceRepo::load(&store, space)
        .await
        .expect("load")
        .expect("a space");
    assert_eq!(state.members.len(), 1);
    assert_eq!(state.member(sam).map(|m| m.role), Some(SpaceRole::Owner));
    assert!(store.is_chained(space).await.expect("chained"));
    assert_eq!(store.chain_head(space).await.expect("head"), Some(first));

    // The records come back as stored, from any seq.
    let all = store.chain_records(space, 0).await.expect("records");
    assert_eq!(all, vec![record(0, 1, sam)]);
    assert!(
        store
            .chain_records(space, 1)
            .await
            .expect("records")
            .is_empty()
    );
    let seals = store.chain_seals(space, 0).await.expect("seals");
    assert_eq!(seals.len(), 1);
    assert_eq!(seals[0].key, KeyRef::Space);
    assert_eq!(seals[0].sealed.len(), 1661);

    // A second record, a rekey-shaped one with its cosignature, follows.
    let second = record(1, 2, sam);
    let third = record(2, 3, sam);
    let outcome = store
        .chain_append(
            space,
            append(Some(first), vec![second.clone(), third.clone()]),
        )
        .await
        .expect("the append");
    assert_eq!(outcome, AppendOutcome::Appended(head(&third)));
    let all = store.chain_records(space, 1).await.expect("records");
    assert_eq!(all, vec![second, third]);
}

#[tokio::test]
async fn an_append_that_doesnt_follow_the_head_is_stale_and_stores_nothing() {
    let store = memory().await;
    let (space, sam, first) = chained(&store).await;
    // Another append got in first.
    let winner = record(1, 2, sam);
    assert_eq!(
        store
            .chain_append(space, append(Some(first), vec![winner.clone()]))
            .await
            .expect("won"),
        AppendOutcome::Appended(head(&winner))
    );
    // The loser follows the old head.
    let loser = record(1, 9, sam);
    let outcome = store
        .chain_append(space, append(Some(first), vec![loser]))
        .await
        .expect("answered");
    assert_eq!(outcome, AppendOutcome::Stale(Some(head(&winner))));
    // Nor can a new chain start over a space that has one.
    let again = store
        .chain_append(space, append(None, vec![record(0, 5, sam)]))
        .await
        .expect("answered");
    assert_eq!(again, AppendOutcome::Stale(Some(head(&winner))));
    assert_eq!(
        store.chain_records(space, 0).await.expect("records").len(),
        2
    );
}

fn invite_changes(space: SpaceId, user: UserId) -> SpaceChanges {
    let mut changes = SpaceChanges::new(space);
    changes.members = vec![Member::invited(
        space,
        user,
        SpaceRole::Member,
        CustomPermissions::NONE,
        UserId(Uuid::new_v4()),
        NOW,
    )];
    changes
}

#[tokio::test]
async fn an_outside_change_to_a_chained_space_is_queued_by_default_and_answers_ok() {
    let store = memory().await;
    let (space, _, _) = chained(&store).await;
    let ana = UserId(Uuid::new_v4());
    let mut changes = invite_changes(space, ana);
    let collection = CollectionId(Uuid::new_v4());
    changes.grants = vec![kemlock_domain::spaces::CollectionGrant {
        collection,
        grantee: Grantee::Member(ana),
        permission: CollectionPermission::Edit,
    }];
    // Vaultwarden-style success, nothing applied.
    SpaceRepo::apply(&store, changes)
        .await
        .expect("answers as if it worked");
    let state = SpaceRepo::load(&store, space)
        .await
        .expect("load")
        .expect("a space");
    assert!(state.member(ana).is_none());
    let queued = store.pending_external(space).await.expect("pending");
    assert_eq!(queued.len(), 1);
    assert_eq!(queued[0].source, ExternalSource::Bitwarden);
    assert_eq!(queued[0].account, ana);
    assert_eq!(queued[0].via, "Bitwarden-compatible API");
    assert_eq!(
        queued[0].change,
        PendingChange::AddMember {
            role: SpaceRole::Member,
            custom: CustomPermissions::NONE,
            grants: vec![(collection, CollectionPermission::Edit)],
        }
    );
    assert_eq!(
        store.external_change_mode().await.expect("mode"),
        ExternalChangeMode::Queue
    );

    // A removal and a role change queue too; a member's own accept step does not.
    let mut removal = SpaceChanges::new(space);
    removal.members_removed = vec![ana];
    SpaceRepo::apply(&store, removal).await.expect("ok");
    let one = store
        .pending_external_one(space, queued[0].id)
        .await
        .expect("one");
    assert_eq!(one.as_ref().map(|p| p.id), Some(queued[0].id));
    // Dropping it is once only.
    assert!(
        store
            .dismiss_external(space, queued[0].id)
            .await
            .expect("dropped")
    );
    assert!(
        !store
            .dismiss_external(space, queued[0].id)
            .await
            .expect("gone")
    );
    assert!(
        store
            .pending_external_one(space, queued[0].id)
            .await
            .expect("one")
            .is_none()
    );
}

#[tokio::test]
async fn the_setting_can_refuse_and_an_unchained_space_is_changed_as_before() {
    let store = memory().await;
    let (space, _, _) = chained(&store).await;
    store
        .put_setting("setting.space_chain_external_changes", "refuse")
        .await
        .expect("saved");
    assert_eq!(
        store.external_change_mode().await.expect("mode"),
        ExternalChangeMode::Refuse
    );
    let ana = UserId(Uuid::new_v4());
    let refused = SpaceRepo::apply(&store, invite_changes(space, ana)).await;
    assert!(refused.is_err(), "refused");
    assert!(
        store
            .pending_external(space)
            .await
            .expect("pending")
            .is_empty()
    );

    // A space with no chain takes the change.
    let plain = SpaceId(Uuid::new_v4());
    let sam = UserId(Uuid::new_v4());
    let mut made = SpaceChanges::new(plain);
    made.space = Some(Space {
        id: plain,
        name: vec![7; 40],
        key_version: 1,
        keys_pending_since: None,
        created_at: NOW,
        updated_at: NOW,
    });
    made.members = vec![owner(plain, sam)];
    SpaceRepo::create(&store, made).await.expect("created");
    assert!(!store.is_chained(plain).await.expect("chained"));
    SpaceRepo::apply(&store, invite_changes(plain, ana))
        .await
        .expect("applied");
    let state = SpaceRepo::load(&store, plain)
        .await
        .expect("load")
        .expect("a space");
    assert!(state.member(ana).is_some());
}

#[tokio::test]
async fn answering_marks_the_queued_change_done_in_the_appending_transaction() {
    let store = memory().await;
    let (space, sam, first) = chained(&store).await;
    let ana = UserId(Uuid::new_v4());
    SpaceRepo::apply(&store, invite_changes(space, ana))
        .await
        .expect("queued");
    let queued = store.pending_external(space).await.expect("pending");
    assert_eq!(queued.len(), 1);

    let mut answer = append(Some(first), vec![record(1, 2, sam)]);
    answer.answers = Some(queued[0].id);
    answer.changes = invite_changes(space, ana);
    store.chain_append(space, answer).await.expect("appended");
    assert!(
        store
            .pending_external(space)
            .await
            .expect("pending")
            .is_empty()
    );
    // Done, not dropped: it can't be answered or dropped again.
    assert!(
        store
            .pending_external_one(space, queued[0].id)
            .await
            .expect("one")
            .is_none()
    );
    assert!(
        !store
            .dismiss_external(space, queued[0].id)
            .await
            .expect("dismissed")
    );
    let state = SpaceRepo::load(&store, space)
        .await
        .expect("load")
        .expect("a space");
    assert!(state.member(ana).is_some());

    // A stale answer changes nothing, the entry included.
    let other = UserId(Uuid::new_v4());
    SpaceRepo::apply(&store, invite_changes(space, other))
        .await
        .expect("queued");
    let queued = store.pending_external(space).await.expect("pending");
    let mut late = append(Some(first), vec![record(1, 8, sam)]);
    late.answers = Some(queued[0].id);
    assert!(matches!(
        store.chain_append(space, late).await.expect("answered"),
        AppendOutcome::Stale(_)
    ));
    assert_eq!(
        store.pending_external(space).await.expect("pending").len(),
        1
    );
}

#[tokio::test]
async fn held_items_are_kept_per_space() {
    let store = memory().await;
    let space = SpaceId(Uuid::new_v4());
    let items = [
        kemlock_domain::ItemId(Uuid::new_v4()),
        kemlock_domain::ItemId(Uuid::new_v4()),
    ];
    store.hold_items(space, &items).await.expect("held");
    store
        .hold_items(space, &items[..1])
        .await
        .expect("held again");
    let mut held = store.held_items(space).await.expect("held");
    held.sort();
    let mut want = items.to_vec();
    want.sort();
    assert_eq!(held, want);
    assert!(
        store
            .held_items(SpaceId(Uuid::new_v4()))
            .await
            .expect("none")
            .is_empty()
    );
}

// ---- held items ----

fn ids(items: &[kemlock_domain::Item]) -> Vec<ItemId> {
    items.iter().map(|i| i.id).collect()
}

#[tokio::test]
async fn a_held_item_is_left_out_of_every_sync_read_until_it_is_released() {
    let store = memory().await;
    let (space, _sam, _) = chained(&store).await;
    let owner = Owner::Space(space);
    let first = put(&store, draft(ItemId::random(), owner, None, 1)).await;
    let held = put(&store, draft(ItemId::random(), owner, None, 1)).await;
    let last = put(&store, draft(ItemId::random(), owner, None, 1)).await;
    store.hold_items(space, &[held.id]).await.expect("held");
    assert_eq!(store.held_items(space).await.expect("list"), vec![held.id]);

    let page = ItemStore::changes_since_each(&store, &[(owner, VersionVector::new())], 10)
        .await
        .expect("changes");
    assert_eq!(ids(&page.items), vec![first.id, last.id]);
    let page = ItemStore::changes_since(&store, &[owner], &VersionVector::new(), 10)
        .await
        .expect("changes");
    assert_eq!(ids(&page.items), vec![first.id, last.id]);

    // A held item that is the newest change doesn't count as the newest change: a cursor made of
    // what was sent covers `latest`, so the 304 shortcut still works.
    let newest = put(&store, draft(ItemId::random(), owner, None, 1)).await;
    store.hold_items(space, &[newest.id]).await.expect("held");
    let latest = ItemStore::latest_each(&store, &[owner])
        .await
        .expect("latest");
    assert_eq!(
        latest[0].1,
        [(last.change.origin, last.change.seq)]
            .into_iter()
            .collect()
    );
    let latest = ItemStore::latest(&store, &[owner]).await.expect("latest");
    assert_eq!(
        latest,
        [(last.change.origin, last.change.seq)]
            .into_iter()
            .collect()
    );
    // A vault item is never held.
    let own = Owner::User(UserId::random());
    let mine = put(&store, draft(ItemId::random(), own, None, 1)).await;
    let page = ItemStore::changes_since_each(&store, &[(own, VersionVector::new())], 10)
        .await
        .expect("changes");
    assert_eq!(ids(&page.items), vec![mine.id]);
}

/// Stores a write of a space item into `collection`, as the use case does once it has accepted it.
async fn write(
    store: &SqlStore,
    collection: CollectionId,
    draft: ItemDraft,
) -> kemlock_domain::Item {
    SpaceRepo::put_item(store, draft, collection)
        .await
        .expect("the write is stored")
}

fn under(mut draft: ItemDraft, key_version: u32) -> ItemDraft {
    draft.key_version = key_version;
    draft
}

/// A chain of real signed records, stored as the chain route stores them: each record is applied
/// to the verified state, and the space's tables are projected from that state with the boxes and
/// names the records committed.
struct Real {
    space: SpaceId,
    chain: Chain,
    state: sc::State,
    head: Option<ChainHead>,
}

impl Real {
    fn new(space: SpaceId) -> Real {
        Real {
            space,
            chain: Chain::new(*space.0.as_bytes(), 1_780_000_000),
            state: sc::State::empty(),
            head: None,
        }
    }

    /// A `grant` record of `by`, which the kit has no step for.
    fn grant(
        &mut self,
        by: &Person,
        collection: CollectionId,
        to: UserId,
        permission: sc::CollectionPerm,
    ) -> Step {
        let record = self.chain.peek(
            by,
            sc::Body::Grant {
                collection: *collection.as_bytes(),
                grantee: sc::Grantee::User(*to.0.as_bytes()),
                permission,
            },
        );
        let seq = self.chain.head.map_or(0, |(seq, _)| seq + 1);
        self.chain.head = Some((seq, sc::link(&record.entry)));
        Step {
            record,
            seals: Vec::new(),
            names: Vec::new(),
        }
    }

    /// Appends the steps in one transaction, with the changes they derive.
    async fn store(&mut self, store: &SqlStore, steps: &[Step]) {
        let space_bytes = *self.space.0.as_bytes();
        let existing = SpaceRepo::load(store, self.space).await.expect("the space");
        let holders = SpaceRepo::holders(store, self.space)
            .await
            .expect("holders");
        let mut records = Vec::new();
        let mut seals = Vec::new();
        let mut names = Vec::new();
        for step in steps {
            let applied = self
                .state
                .apply(&space_bytes, &step.record)
                .expect("a record that verifies");
            let parsed = sc::Record::parse(&step.record.entry).expect("a record");
            let seq = parsed.seq;
            records.push(StoredRecord {
                seq,
                link: applied.link,
                epoch: parsed.epoch,
                by: UserId(Uuid::from_bytes(parsed.by)),
                at: parsed.at,
                entry: step.record.entry.clone(),
                signature: step.record.signature.clone(),
                cosignature: step.record.cosignature.clone(),
            });
            for commit in &applied.seals {
                for (member, bundle_version) in &commit.recipients {
                    let sent = step
                        .seals
                        .iter()
                        .find(|s| {
                            s.seq == seq
                                && s.key == commit.key
                                && s.version == commit.version
                                && s.member == *member
                        })
                        .expect("a box for each recipient");
                    seals.push(StoredSeal {
                        seq,
                        key: commit.key,
                        version: commit.version,
                        member: UserId(Uuid::from_bytes(*member)),
                        bundle_version: *bundle_version,
                        sealed: sent.sealed.clone(),
                    });
                }
            }
            for name in &applied.names {
                let sent = step
                    .names
                    .iter()
                    .find(|n| n.seq == seq && n.target == name.target)
                    .expect("a sealed name for each name hash");
                names.push(StoredName {
                    seq,
                    target: name.target,
                    version: name.version,
                    hash: name.hash,
                    sealed: sent.sealed.clone(),
                });
            }
            self.state = applied.state;
        }
        let changes = project(
            self.space,
            existing.as_ref(),
            &holders,
            &self.state,
            Batch {
                seals: &seals,
                names: &names,
            },
            NOW,
        );
        let last = records.last().expect("a step");
        let new_head = ChainHead {
            seq: last.seq,
            link: last.link,
            epoch: last.epoch,
        };
        let outcome = store
            .chain_append(
                self.space,
                ChainAppend {
                    expected: self.head,
                    records,
                    seals,
                    names,
                    changes,
                    creating: self.head.is_none(),
                    held: Vec::new(),
                    writes: Vec::new(),
                    answers: None,
                    state: Some(Arc::new(self.state.clone())),
                },
            )
            .await
            .expect("the append");
        assert_eq!(outcome, AppendOutcome::Appended(new_head));
        self.head = Some(new_head);
    }
}

/// A space whose collection has moved to key version 2, with a live item under version 1 that a
/// key replacement held, and one item written after it. Its chain is sam's (an Owner, with the
/// manage grant `create` gives him): `create`, then a `keys` record.
async fn held_after_a_replacement(
    store: &SqlStore,
) -> (
    SpaceId,
    UserId,
    CollectionId,
    kemlock_domain::Item,
    kemlock_domain::Item,
) {
    let space = SpaceId(Uuid::new_v4());
    let sam = UserId(Uuid::new_v4());
    let id = CollectionId(Uuid::new_v4());
    let sam_keys = Person::new(*sam.0.as_bytes(), 1);
    let mut real = Real::new(space);
    let create = real.chain.create(&sam_keys, *id.as_bytes());
    real.store(store, &[create]).await;
    let owner = Owner::Space(space);
    let held = write(store, id, under(draft(ItemId::random(), owner, None, 1), 1)).await;
    let after = write(store, id, under(draft(ItemId::random(), owner, None, 1), 1)).await;
    // The keys record: the collection's key moves to version 2 and the item is named held.
    let rotate = real
        .chain
        .rotate_collection(&sam_keys, *id.as_bytes(), 2, &[&sam_keys]);
    real.store(store, &[rotate]).await;
    store.hold_items(space, &[held.id]).await.expect("held");
    (space, sam, id, held, after)
}

#[tokio::test]
async fn a_write_under_the_current_key_version_releases_a_held_item() {
    let store = memory().await;
    let (space, _sam, collection, held, after) = held_after_a_replacement(&store).await;
    let owner = Owner::Space(space);
    // A device that was sent `after` holds a cursor past the held item.
    let cursor: VersionVector = [(after.change.origin, after.change.seq)]
        .into_iter()
        .collect();

    let live = write(
        &store,
        collection,
        under(draft(held.id, owner, Some(1), 2), 2),
    )
    .await;
    assert!(store.held_items(space).await.expect("list").is_empty());
    assert_eq!(live.key_version, 2);
    assert!(live.change.seq > after.change.seq);
    // It is served as live, a change after the cursor, with the new revision.
    let page = ItemStore::changes_since_each(&store, &[(owner, cursor)], 10)
        .await
        .expect("changes");
    assert_eq!(ids(&page.items), vec![held.id]);
    assert_eq!(page.items[0].revision, live.revision);
    assert_eq!(page.items[0].key_version, 2);
}

#[tokio::test]
async fn a_write_under_an_old_key_version_leaves_the_item_held() {
    let store = memory().await;
    let (space, _sam, collection, held, _after) = held_after_a_replacement(&store).await;
    let owner = Owner::Space(space);

    // The use cases refuse this write (I2); a store that is handed it anyway doesn't lift the hold.
    write(
        &store,
        collection,
        under(draft(held.id, owner, Some(1), 2), 1),
    )
    .await;
    assert_eq!(store.held_items(space).await.expect("list"), vec![held.id]);
    let page = ItemStore::changes_since_each(&store, &[(owner, VersionVector::new())], 10)
        .await
        .expect("changes");
    assert!(!ids(&page.items).contains(&held.id));

    // Nor does one under a version the collection has not reached.
    write(
        &store,
        collection,
        under(draft(held.id, owner, Some(2), 3), 3),
    )
    .await;
    assert_eq!(store.held_items(space).await.expect("list"), vec![held.id]);
}

#[tokio::test]
async fn a_tombstone_over_a_held_item_releases_it() {
    let store = memory().await;
    let (space, _sam, collection, held, after) = held_after_a_replacement(&store).await;
    let owner = Owner::Space(space);
    let cursor: VersionVector = [(after.change.origin, after.change.seq)]
        .into_iter()
        .collect();

    // A delete seals nothing, so it has no key version to compare.
    let gone = write(
        &store,
        collection,
        tombstone(held.id, owner, Some(1), 2, NOW),
    )
    .await;
    assert!(store.held_items(space).await.expect("list").is_empty());
    let page = ItemStore::changes_since_each(&store, &[(owner, cursor)], 10)
        .await
        .expect("changes");
    assert_eq!(ids(&page.items), vec![held.id]);
    assert!(page.items[0].is_tombstone());
    assert_eq!(page.items[0].change, gone.change);
}

#[tokio::test]
async fn the_sync_a_device_runs_sends_held_items_marked_held_until_a_write_releases_them() {
    let store = memory().await;
    let (space, sam, collection, held, after) = held_after_a_replacement(&store).await;
    let owner = Owner::Space(space);
    let sync = SyncDelta {
        items: store.clone(),
        spaces: store.clone(),
    };

    let SyncOutcome::Page(first) = sync
        .execute(sam, &SyncCursor::default(), None)
        .await
        .expect("a sync")
    else {
        panic!("a page is expected");
    };
    // The held item comes in change order, marked.
    assert_eq!(ids(&first.items), vec![held.id, after.id]);
    assert_eq!(
        first.held.iter().copied().collect::<Vec<_>>(),
        vec![held.id]
    );
    assert!(!first.more);
    // Nothing changed for a device that has what it was sent, the held item included.
    assert_eq!(
        sync.execute(sam, &first.next, None).await.expect("a sync"),
        SyncOutcome::Unchanged
    );

    write(
        &store,
        collection,
        under(draft(held.id, owner, Some(1), 2), 2),
    )
    .await;
    let SyncOutcome::Page(second) = sync.execute(sam, &first.next, None).await.expect("a sync")
    else {
        panic!("the released item is a change");
    };
    assert_eq!(ids(&second.items), vec![held.id]);
    assert_eq!(
        sync.execute(sam, &second.next, None).await.expect("a sync"),
        SyncOutcome::Unchanged
    );
}

// ---- held items in sync (I4) ----

/// A space with Finance at key version 2 and `sam` (an Owner, with the manage grant `create`
/// gives him), `vic` (confirmed, a view grant) and `ana` (confirmed, no grant) in it, and a held
/// item and a live one, both written under version 1. The chain is real, and `real` and `sam_keys`
/// carry on with it.
struct Held {
    space: SpaceId,
    collection: CollectionId,
    sam: UserId,
    vic: UserId,
    ana: UserId,
    real: Real,
    sam_keys: Person,
    live: kemlock_domain::Item,
    held: kemlock_domain::Item,
}

async fn editors_and_viewers(store: &SqlStore) -> Held {
    let space = SpaceId(Uuid::new_v4());
    let (sam, vic, ana) = (
        UserId(Uuid::new_v4()),
        UserId(Uuid::new_v4()),
        UserId(Uuid::new_v4()),
    );
    let id = CollectionId(Uuid::new_v4());
    let sam_keys = Person::new(*sam.0.as_bytes(), 1);
    let vic_keys = Person::new(*vic.0.as_bytes(), 2);
    let ana_keys = Person::new(*ana.0.as_bytes(), 3);
    let mut real = Real::new(space);
    let steps = vec![
        real.chain.create(&sam_keys, *id.as_bytes()),
        real.chain.invite(&sam_keys, vic_keys.id, sc::Role::Member),
        real.chain.confirm(&sam_keys, &vic_keys),
        real.chain.invite(&sam_keys, ana_keys.id, sc::Role::Member),
        real.chain.confirm(&sam_keys, &ana_keys),
        real.grant(&sam_keys, id, vic, sc::CollectionPerm::View),
    ];
    real.store(store, &steps).await;
    let owner = Owner::Space(space);
    let live = write(store, id, under(draft(ItemId::random(), owner, None, 1), 1)).await;
    let held = write(store, id, under(draft(ItemId::random(), owner, None, 1), 1)).await;
    // The collection's key moves to version 2, sealed to those with access: sam and vic.
    let rotate =
        real.chain
            .rotate_collection(&sam_keys, *id.as_bytes(), 2, &[&sam_keys, &vic_keys]);
    real.store(store, &[rotate]).await;
    store.hold_items(space, &[held.id]).await.expect("held");
    Held {
        space,
        collection: id,
        sam,
        vic,
        ana,
        real,
        sam_keys,
        live,
        held,
    }
}

fn sync_of(store: &SqlStore) -> SyncDelta<SqlStore, SqlStore> {
    SyncDelta {
        items: store.clone(),
        spaces: store.clone(),
    }
}

async fn page_of(
    sync: &SyncDelta<SqlStore, SqlStore>,
    user: UserId,
    since: &SyncCursor,
) -> kemlock_app::SyncPage {
    match sync.execute(user, since, None).await.expect("a sync") {
        SyncOutcome::Page(page) => page,
        SyncOutcome::Unchanged => panic!("a page is expected"),
    }
}

#[tokio::test]
async fn every_member_is_sent_a_held_item_marked_held_whatever_their_access() {
    let store = memory().await;
    let w = editors_and_viewers(&store).await;
    let sync = sync_of(&store);

    let sam = page_of(&sync, w.sam, &SyncCursor::default()).await;
    assert_eq!(ids(&sam.items), vec![w.live.id, w.held.id]);
    assert_eq!(
        sam.held.iter().copied().collect::<Vec<_>>(),
        vec![w.held.id]
    );
    // With the key version it had, and the revision and bytes as they were.
    let sent = sam.items.iter().find(|i| i.id == w.held.id).expect("sent");
    assert_eq!((sent.key_version, sent.revision), (1, w.held.revision));
    assert_eq!(sent.ciphertext, w.held.ciphertext);

    let vic = page_of(&sync, w.vic, &SyncCursor::default()).await;
    let ana = page_of(&sync, w.ana, &SyncCursor::default()).await;
    // A viewer, and a member with no grant, are sent it as the editor is: an item the space
    // manifest lists must not go missing from their copy.
    for page in [&vic, &ana] {
        assert_eq!(ids(&page.items), vec![w.live.id, w.held.id]);
        assert_eq!(
            page.held.iter().copied().collect::<Vec<_>>(),
            vec![w.held.id]
        );
        let sent = page.items.iter().find(|i| i.id == w.held.id).expect("sent");
        assert_eq!((sent.key_version, sent.revision), (1, w.held.revision));
    }

    // All are up to date; each cursor holds what it was sent of the held items.
    for (user, next) in [(w.sam, &sam.next), (w.vic, &vic.next), (w.ana, &ana.next)] {
        assert_eq!(
            sync.execute(user, next, None).await.expect("a sync"),
            SyncOutcome::Unchanged
        );
    }
    // A cursor read back from its bytes is the same one.
    let again = SyncCursor::from_cursor_bytes(&sam.next.to_cursor_bytes()).expect("reads");
    assert_eq!(again, sam.next);
    assert_eq!(
        sync.execute(w.sam, &again, None).await.expect("a sync"),
        SyncOutcome::Unchanged
    );
}

#[tokio::test]
async fn after_a_release_the_editor_and_the_viewer_both_see_the_new_live_revision() {
    let store = memory().await;
    let w = editors_and_viewers(&store).await;
    let sync = sync_of(&store);
    let sam = page_of(&sync, w.sam, &SyncCursor::default()).await;
    let vic = page_of(&sync, w.vic, &SyncCursor::default()).await;

    let owner = Owner::Space(w.space);
    let live = write(
        &store,
        w.collection,
        under(draft(w.held.id, owner, Some(1), 2), 2),
    )
    .await;
    for (user, cursor) in [(w.sam, &sam.next), (w.vic, &vic.next)] {
        let page = page_of(&sync, user, cursor).await;
        assert_eq!(ids(&page.items), vec![w.held.id]);
        assert!(page.held.is_empty(), "the new revision is live");
        assert_eq!(page.items[0].revision, live.revision);
        assert_eq!(page.items[0].key_version, 2);
        assert_eq!(
            sync.execute(user, &page.next, None).await.expect("a sync"),
            SyncOutcome::Unchanged
        );
    }
}

#[tokio::test]
async fn a_member_who_gains_edit_later_is_sent_nothing_more_of_the_held_items() {
    let store = memory().await;
    let mut w = editors_and_viewers(&store).await;
    let sync = sync_of(&store);
    // Ana has no grant, and is sent the live item and the held one all the same.
    let before = page_of(&sync, w.ana, &SyncCursor::default()).await;
    assert_eq!(ids(&before.items), vec![w.live.id, w.held.id]);
    assert!(before.held.contains(&w.held.id));

    let step = w
        .real
        .grant(&w.sam_keys, w.collection, w.ana, sc::CollectionPerm::Edit);
    w.real.store(&store, &[step]).await;

    // The grant moves no item: the held one isn't sent again.
    assert_eq!(
        sync.execute(w.ana, &before.next, None)
            .await
            .expect("a sync"),
        SyncOutcome::Unchanged
    );
}

#[tokio::test]
async fn a_tombstone_over_a_held_item_reaches_the_editor_and_the_viewer() {
    let store = memory().await;
    let w = editors_and_viewers(&store).await;
    let sync = sync_of(&store);
    let sam = page_of(&sync, w.sam, &SyncCursor::default()).await;
    let vic = page_of(&sync, w.vic, &SyncCursor::default()).await;

    let owner = Owner::Space(w.space);
    write(
        &store,
        w.collection,
        tombstone(w.held.id, owner, Some(1), 2, NOW),
    )
    .await;
    for (user, cursor) in [(w.sam, &sam.next), (w.vic, &vic.next)] {
        let page = page_of(&sync, user, cursor).await;
        assert_eq!(ids(&page.items), vec![w.held.id]);
        assert!(page.items[0].is_tombstone());
        assert!(page.held.is_empty());
    }
}

#[tokio::test]
async fn held_items_follow_the_page_limit_and_the_cursor_with_the_live_ones() {
    let store = memory().await;
    let w = editors_and_viewers(&store).await;
    let sync = sync_of(&store);
    // The live item comes first, the held one second; pages of one.
    let first = match sync
        .execute(w.sam, &SyncCursor::default(), Some(1))
        .await
        .expect("a sync")
    {
        SyncOutcome::Page(page) => page,
        SyncOutcome::Unchanged => panic!("a page is expected"),
    };
    assert_eq!(ids(&first.items), vec![w.live.id]);
    assert!(first.more);
    let second = page_of(&sync, w.sam, &first.next).await;
    assert_eq!(ids(&second.items), vec![w.held.id]);
    assert!(second.held.contains(&w.held.id));
    assert!(!second.more);
}

// ---- how much of the chain one account signed lately, on every backend ----

async fn chain_usage_counts_what_one_account_signed_lately(store: &SqlStore) {
    let (space, sam, first) = chained(store).await;
    let lee = UserId(Uuid::new_v4());
    let mut records = Vec::new();
    for (seq, by, at) in [
        (1u64, lee, 1_780_000_100u64),
        (2, lee, 1_780_003_000),
        (3, sam, 1_780_003_100),
        (4, lee, 1_780_090_000),
    ] {
        let mut r = record(seq, u8::try_from(seq).expect("small") + 1, by);
        r.at = at;
        r.cosignature = None;
        records.push(r);
    }
    let last = head(records.last().expect("records"));
    assert_eq!(
        store
            .chain_append(space, append(Some(first), records))
            .await
            .expect("the append"),
        AppendOutcome::Appended(last)
    );

    // Lee signed three (at 100, 3000 and 90000 after the start), two of them from 3000 on.
    let usage = store
        .chain_usage(space, lee, 1_780_003_000, 1_780_000_050)
        .await
        .expect("usage");
    assert_eq!((usage.by_member_hour, usage.by_member_day), (2, 3));
    // Sam signed the first record and the third.
    let usage = store
        .chain_usage(space, sam, 1_780_003_050, 1_779_999_999)
        .await
        .expect("usage");
    assert_eq!((usage.by_member_hour, usage.by_member_day), (1, 2));
    // Nothing for an account that signed none, or in a space that is not there.
    let stranger = UserId(Uuid::new_v4());
    let usage = store
        .chain_usage(space, stranger, 0, 0)
        .await
        .expect("usage");
    assert_eq!((usage.by_member_hour, usage.by_member_day), (0, 0));
    let usage = store
        .chain_usage(SpaceId(Uuid::new_v4()), lee, 0, 0)
        .await
        .expect("usage");
    assert_eq!((usage.by_member_hour, usage.by_member_day), (0, 0));
}

async fn all(store: &SqlStore) {
    chain_usage_counts_what_one_account_signed_lately(store).await;
}

#[tokio::test]
async fn usage_sqlite_in_memory() {
    all(&memory().await).await;
}

#[tokio::test]
async fn usage_sqlite_in_a_file() {
    let (store, _dir) = common::file().await;
    all(&store).await;
}

#[tokio::test]
async fn usage_postgres_when_configured() {
    if let Some(store) = common::external("KEMLOCK_TEST_POSTGRES_URL").await {
        all(&store).await;
    }
}

#[tokio::test]
async fn usage_mysql_when_configured() {
    if let Some(store) = common::external("KEMLOCK_TEST_MYSQL_URL").await {
        all(&store).await;
    }
}
