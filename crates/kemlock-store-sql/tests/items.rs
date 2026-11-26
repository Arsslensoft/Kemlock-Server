//! `ItemStore`: writes, conflicts, batches, sequence numbers, delta sync, tombstones.
//!
//! Each scenario runs on every backend that is available (see `accounts.rs`). A scenario uses
//! owners and item ids of its own and asserts on sequence numbers only relative to its own
//! writes, so a database kept between runs does not disturb it.

mod common;

use common::{MADE_AT, draft, external, file, memory, put, put_err, tombstone, user_owner};
use kemlock_app::ports::{ItemStore, ServerInfo, StoreError};
use kemlock_domain::{Hlc, ItemId, Revision, VersionVector};
use kemlock_store_sql::SqlStore;
use std::collections::HashMap;
use time::Duration;
use time::macros::datetime;

fn millis(time: time::OffsetDateTime) -> u64 {
    u64::try_from(time.unix_timestamp_nanos() / 1_000_000).expect("after 1970")
}

async fn get(store: &SqlStore, id: ItemId) -> Option<kemlock_domain::Item> {
    ItemStore::get(store, id).await.expect("get")
}

async fn put_and_get(store: &SqlStore) {
    let owner = user_owner();
    let id = ItemId::random();

    assert_eq!(get(store, id).await, None);

    let first = put(store, draft(id, owner, None, 1)).await;
    assert_eq!(first.change.origin, ServerInfo::server_id(store));
    assert!(first.change.seq >= 1, "sequence numbers start at 1");
    assert_eq!(first.revision, Revision(1));
    assert_eq!(first.owner, owner);
    assert_eq!(first.updated_at, MADE_AT);
    assert!(!first.is_tombstone());
    assert_eq!(get(store, id).await, Some(first.clone()));

    let second = put(store, draft(id, owner, Some(1), 2)).await;
    assert_eq!(second.change.seq, first.change.seq + 1);
    assert!(second.change.hlc > first.change.hlc);
    assert_eq!(second.revision, Revision(2));
    assert_eq!(get(store, id).await, Some(second));
}

async fn conflicts(store: &SqlStore) {
    let owner = user_owner();
    let id = ItemId::random();
    put(store, draft(id, owner, None, 1)).await;
    let current = put(store, draft(id, owner, Some(1), 2)).await;

    // A stale write names the revision that is stored.
    assert_eq!(
        put_err(store, draft(id, owner, Some(1), 2)).await,
        StoreError::Conflict {
            item: id,
            current: Some(Revision(2))
        }
    );
    // Creating what exists.
    assert_eq!(
        put_err(store, draft(id, owner, None, 1)).await,
        StoreError::Conflict {
            item: id,
            current: Some(Revision(2))
        }
    );
    // Updating what is not there.
    let missing = ItemId::random();
    assert_eq!(
        put_err(store, draft(missing, owner, Some(1), 2)).await,
        StoreError::Conflict {
            item: missing,
            current: None
        }
    );
    assert_eq!(get(store, missing).await, None);

    // An id that is another owner's item is taken, and its revision is not revealed.
    assert_eq!(
        put_err(store, draft(id, user_owner(), None, 1)).await,
        StoreError::Duplicate
    );
    assert_eq!(
        put_err(store, draft(id, user_owner(), Some(2), 3)).await,
        StoreError::Duplicate
    );

    // None of that changed anything, and none of it used a sequence number.
    assert_eq!(get(store, id).await, Some(current.clone()));
    let next = put(store, draft(id, owner, Some(2), 3)).await;
    assert_eq!(next.change.seq, current.change.seq + 1);
}

async fn batches(store: &SqlStore) {
    let owner = user_owner();

    // An empty batch is nothing.
    assert!(
        ItemStore::put_batch(store, Vec::new())
            .await
            .expect("empty batch")
            .is_empty()
    );

    // A batch stores every draft, in order, with consecutive sequence numbers.
    let ids: Vec<ItemId> = (0..3).map(|_| ItemId::random()).collect();
    let stored = ItemStore::put_batch(
        store,
        ids.iter().map(|id| draft(*id, owner, None, 1)).collect(),
    )
    .await
    .expect("batch");
    assert_eq!(stored.iter().map(|i| i.id).collect::<Vec<_>>(), ids);
    for pair in stored.windows(2) {
        assert_eq!(pair[1].change.seq, pair[0].change.seq + 1);
        assert!(pair[1].change.hlc > pair[0].change.hlc);
    }
    for item in &stored {
        assert_eq!(get(store, item.id).await, Some(item.clone()));
    }
    let last_seq = stored[2].change.seq;

    // All or none: the second draft is stale, so the first and third are not stored either,
    // and the conflict names the item that failed.
    let fresh_a = ItemId::random();
    let fresh_c = ItemId::random();
    let outcome = ItemStore::put_batch(
        store,
        vec![
            draft(fresh_a, owner, None, 1),
            draft(ids[1], owner, None, 1),
            draft(fresh_c, owner, None, 1),
        ],
    )
    .await;
    assert_eq!(
        outcome,
        Err(StoreError::Conflict {
            item: ids[1],
            current: Some(Revision(1))
        })
    );
    assert_eq!(get(store, fresh_a).await, None);
    assert_eq!(get(store, fresh_c).await, None);

    // With two bad drafts, the first one is named.
    let outcome = ItemStore::put_batch(
        store,
        vec![draft(ids[2], owner, None, 1), draft(ids[0], owner, None, 1)],
    )
    .await;
    assert_eq!(
        outcome,
        Err(StoreError::Conflict {
            item: ids[2],
            current: Some(Revision(1))
        })
    );

    // The failed batches left no gap in the sequence.
    let after = put(store, draft(ItemId::random(), owner, None, 1)).await;
    assert_eq!(after.change.seq, last_seq + 1);

    // Two drafts of one item in a batch: the second sees the first.
    let twice = ItemId::random();
    let both = ItemStore::put_batch(
        store,
        vec![
            draft(twice, owner, None, 1),
            draft(twice, owner, Some(1), 2),
        ],
    )
    .await
    .expect("batch");
    assert_eq!(both[1].revision, Revision(2));
    assert_eq!(get(store, twice).await, Some(both[1].clone()));

    // A batch may hold 500 drafts, not 501, and the refused one stores nothing.
    let many: Vec<_> = (0..501)
        .map(|_| draft(ItemId::random(), owner, None, 1))
        .collect();
    let first_of_many = many[0].id;
    let refused = ItemStore::put_batch(store, many.clone()).await;
    assert!(
        matches!(refused, Err(StoreError::Backend(_))),
        "{refused:?}"
    );
    assert_eq!(get(store, first_of_many).await, None);
    let accepted = ItemStore::put_batch(store, many[..500].to_vec())
        .await
        .expect("500 drafts");
    assert_eq!(accepted.len(), 500);
    assert_eq!(get(store, many[499].id).await, Some(accepted[499].clone()));
}

/// Sequence numbers rise by exactly one per accepted write, however it was made.
async fn sequence_has_no_gaps(store: &SqlStore) {
    let owner = user_owner();
    let mut seqs = Vec::new();

    let id = ItemId::random();
    seqs.push(put(store, draft(id, owner, None, 1)).await.change.seq);
    put_err(store, draft(id, owner, None, 1)).await;
    seqs.push(put(store, draft(id, owner, Some(1), 2)).await.change.seq);

    let batch = ItemStore::put_batch(
        store,
        (0..4)
            .map(|_| draft(ItemId::random(), owner, None, 1))
            .collect(),
    )
    .await
    .expect("batch");
    seqs.extend(batch.iter().map(|i| i.change.seq));

    let bad = ItemStore::put_batch(
        store,
        vec![
            draft(ItemId::random(), owner, None, 1),
            draft(id, owner, None, 1),
        ],
    )
    .await;
    assert!(bad.is_err());

    seqs.push(put(store, draft(id, owner, Some(2), 3)).await.change.seq);

    // Twenty writes at once still take twenty consecutive numbers.
    let mut tasks = Vec::new();
    for _ in 0..20 {
        let store = store.clone();
        tasks.push(tokio::spawn(async move {
            ItemStore::put(&store, draft(ItemId::random(), owner, None, 1))
                .await
                .expect("a concurrent write")
                .change
                .seq
        }));
    }
    let mut concurrent = Vec::new();
    for task in tasks {
        concurrent.push(task.await.expect("the task finishes"));
    }
    concurrent.sort_unstable();
    seqs.extend(concurrent);

    for pair in seqs.windows(2) {
        assert_eq!(pair[1], pair[0] + 1, "sequence numbers in {seqs:?}");
    }
}

async fn paging(store: &SqlStore) {
    let owner = user_owner();
    let stranger = user_owner();

    // 25 items, of which the first ten are rewritten; and some of someone else's.
    let ids: Vec<ItemId> = (0..25).map(|_| ItemId::random()).collect();
    for id in &ids {
        put(store, draft(*id, owner, None, 1)).await;
    }
    for id in &ids[..10] {
        put(store, draft(*id, owner, Some(1), 2)).await;
    }
    for _ in 0..3 {
        put(store, draft(ItemId::random(), stranger, None, 1)).await;
    }

    // Walk every page: each item once, at its latest revision, in (origin, seq) order.
    let mut cursor = VersionVector::new();
    let mut seen = HashMap::new();
    let mut pages = 0;
    let mut last_seq = 0;
    let mut first_cursor = None;
    loop {
        let page = ItemStore::changes_since(store, &[owner], &cursor, 7)
            .await
            .expect("changes_since");
        assert!(page.items.len() <= 7);
        for item in page.items {
            assert!(item.change.seq > last_seq, "ordered by sequence");
            last_seq = item.change.seq;
            assert!(seen.insert(item.id, item).is_none(), "each item once");
        }
        cursor = page.next;
        pages += 1;
        if pages == 1 {
            first_cursor = Some(cursor.clone());
        }
        if !page.more {
            break;
        }
        assert!(pages < 10, "paging does not end");
    }
    assert_eq!(pages, 4, "25 items at 7 a page");
    assert_eq!(seen.len(), 25);
    for (n, id) in ids.iter().enumerate() {
        let want = if n < 10 { Revision(2) } else { Revision(1) };
        assert_eq!(seen[id].revision, want, "latest revision of item {n}");
        assert_eq!(seen[id].owner, owner);
    }

    // The cursor from the last page finds nothing, and stays where it is.
    let again = ItemStore::changes_since(store, &[owner], &cursor, 7)
        .await
        .expect("changes_since");
    assert!(again.items.is_empty());
    assert!(!again.more);
    assert_eq!(again.next, cursor);

    // A cursor from the first page finds the rest; a limit that fits exactly leaves no more.
    let first_cursor = first_cursor.expect("there was a first page");
    let rest = ItemStore::changes_since(store, &[owner], &first_cursor, 18)
        .await
        .expect("changes_since");
    assert_eq!(rest.items.len(), 18);
    assert!(!rest.more);
    assert_eq!(rest.next, cursor);

    // Several owners at once.
    let both = ItemStore::changes_since(store, &[owner, stranger], &VersionVector::new(), 100)
        .await
        .expect("changes_since");
    assert_eq!(both.items.len(), 28);
    assert!(!both.more);
    let none = ItemStore::changes_since(store, &[], &VersionVector::new(), 100)
        .await
        .expect("changes_since");
    assert!(none.items.is_empty());
    assert!(!none.more);

    // A write after the cursor shows up alone, then the cursor is quiet again.
    let late = put(store, draft(ids[20], owner, Some(1), 2)).await;
    let delta = ItemStore::changes_since(store, &[owner], &cursor, 7)
        .await
        .expect("changes_since");
    assert_eq!(delta.items, vec![late.clone()]);
    assert!(!delta.more);
    let quiet = ItemStore::changes_since(store, &[owner], &delta.next, 7)
        .await
        .expect("changes_since");
    assert!(quiet.items.is_empty());

    // An item written twice since the cursor is returned once, at its latest revision.
    let id = ids[21];
    put(store, draft(id, owner, Some(1), 2)).await;
    let latest = put(store, draft(id, owner, Some(2), 3)).await;
    let delta = ItemStore::changes_since(store, &[owner], &quiet.next, 7)
        .await
        .expect("changes_since");
    assert_eq!(delta.items, vec![latest]);
}

async fn latest_per_origin(store: &SqlStore) {
    let origin = ServerInfo::server_id(store);
    let a = user_owner();
    let b = user_owner();

    assert_eq!(
        ItemStore::latest(store, &[]).await.expect("latest"),
        VersionVector::new()
    );
    assert_eq!(
        ItemStore::latest(store, &[a]).await.expect("latest"),
        VersionVector::new(),
        "an owner with no items has no changes"
    );

    let a1 = ItemId::random();
    put(store, draft(a1, a, None, 1)).await;
    let a2 = put(store, draft(ItemId::random(), a, None, 1)).await;
    let b1 = put(store, draft(ItemId::random(), b, None, 1)).await;
    assert_eq!(
        ItemStore::latest(store, &[a])
            .await
            .expect("latest")
            .get(origin),
        a2.change.seq
    );
    assert_eq!(
        ItemStore::latest(store, &[b])
            .await
            .expect("latest")
            .get(origin),
        b1.change.seq
    );

    // Rewriting an item moves its owner's newest change.
    let a1_again = put(store, draft(a1, a, Some(1), 2)).await;
    assert_eq!(
        ItemStore::latest(store, &[a])
            .await
            .expect("latest")
            .get(origin),
        a1_again.change.seq
    );
    assert_eq!(
        ItemStore::latest(store, &[b])
            .await
            .expect("latest")
            .get(origin),
        b1.change.seq,
        "another owner's write does not move it"
    );
    assert_eq!(
        ItemStore::latest(store, &[a, b])
            .await
            .expect("latest")
            .get(origin),
        a1_again.change.seq
    );
}

async fn tombstones(store: &SqlStore) {
    let owner = user_owner();
    let origin = ServerInfo::server_id(store);
    let deleted_at = datetime!(2026-03-01 00:00:00 UTC);

    let live = ItemId::random();
    put(store, draft(live, owner, None, 1)).await;
    let doomed = ItemId::random();
    put(store, draft(doomed, owner, None, 1)).await;

    // Deleting leaves a tombstone: no ciphertext, no key, a deletion time.
    let gone = put(store, tombstone(doomed, owner, Some(1), 2, deleted_at)).await;
    assert!(gone.is_tombstone());
    assert_eq!(gone.ciphertext, None);
    assert_eq!(gone.item_key, None);
    assert_eq!(gone.deleted_at, Some(deleted_at));
    assert_eq!(get(store, doomed).await, Some(gone.clone()));

    // It travels in deltas, like any change.
    let page = ItemStore::changes_since(store, &[owner], &VersionVector::new(), 10)
        .await
        .expect("changes_since");
    assert_eq!(page.items.len(), 2);
    assert!(page.items.contains(&gone));

    // Purging before the deletion changes nothing and leaves the horizon where it was.
    let horizon_before = ItemStore::purged_through(store, &[owner])
        .await
        .expect("horizon");
    ItemStore::purge_tombstones(store, deleted_at - Duration::days(1))
        .await
        .expect("purge");
    assert_eq!(get(store, doomed).await, Some(gone.clone()));
    assert_eq!(
        ItemStore::purged_through(store, &[owner])
            .await
            .expect("horizon"),
        horizon_before
    );

    // Purging after it removes the tombstone, and the horizon covers its change.
    let purged = ItemStore::purge_tombstones(store, deleted_at + Duration::hours(1))
        .await
        .expect("purge");
    assert!(purged >= 1);
    assert_eq!(get(store, doomed).await, None);
    assert!(get(store, live).await.is_some(), "live items stay");
    let horizon = ItemStore::purged_through(store, &[owner])
        .await
        .expect("horizon");
    assert!(horizon.get(origin) >= gone.change.seq);
    assert!(horizon.get(origin) > horizon_before.get(origin));
    assert!(
        !VersionVector::new().dominates(&horizon),
        "a cursor from before the purge must start a full sync"
    );

    // The horizon is the owner's own: another account's cursors are not affected by this purge.
    let someone_else = user_owner();
    assert!(
        VersionVector::new().dominates(
            &ItemStore::purged_through(store, &[someone_else])
                .await
                .expect("horizon")
        ),
        "another owner has no horizon"
    );
    let both = ItemStore::purged_through(store, &[owner, someone_else])
        .await
        .expect("horizon");
    assert_eq!(both, horizon);

    // The purged tombstone no longer travels.
    let page = ItemStore::changes_since(store, &[owner], &VersionVector::new(), 10)
        .await
        .expect("changes_since");
    assert_eq!(page.items.len(), 1);
    assert_eq!(page.items[0].id, live);

    // A later deletion is purged by a later purge, and the horizon moves again.
    let later = ItemId::random();
    put(store, draft(later, owner, None, 1)).await;
    let later_gone = put(
        store,
        tombstone(later, owner, Some(1), 2, deleted_at + Duration::hours(2)),
    )
    .await;
    ItemStore::purge_tombstones(store, deleted_at + Duration::hours(1))
        .await
        .expect("purge");
    assert_eq!(
        get(store, later).await,
        Some(later_gone.clone()),
        "a newer tombstone is kept"
    );
    let purged = ItemStore::purge_tombstones(store, deleted_at + Duration::hours(3))
        .await
        .expect("purge");
    assert!(purged >= 1);
    assert_eq!(get(store, later).await, None);
    let moved = ItemStore::purged_through(store, &[owner])
        .await
        .expect("horizon");
    assert!(moved.get(origin) >= later_gone.change.seq);
    assert!(moved.get(origin) > horizon.get(origin));
}

async fn clock(store: &SqlStore) {
    let owner = user_owner();
    let first = put(store, draft(ItemId::random(), owner, None, 1)).await;
    assert!(
        first.change.hlc >= Hlc::from_parts(millis(MADE_AT), 0),
        "not before the draft's time"
    );

    // A draft made before the last write still gets a later HLC time.
    let mut old = draft(ItemId::random(), owner, None, 1);
    old.updated_at = datetime!(2020-01-01 00:00:00 UTC);
    let second = put(store, old).await;
    assert!(second.change.hlc > first.change.hlc);

    // A draft made later pulls the clock forward to its own time.
    let mut ahead = draft(ItemId::random(), owner, None, 1);
    ahead.updated_at = MADE_AT + Duration::hours(1);
    let third = put(store, ahead).await;
    assert!(third.change.hlc > second.change.hlc);
    assert!(third.change.hlc.millis() >= millis(MADE_AT + Duration::hours(1)));

    // Within a batch, every item takes a later time than the one before.
    let batch = ItemStore::put_batch(
        store,
        (0..3)
            .map(|_| draft(ItemId::random(), owner, None, 1))
            .collect(),
    )
    .await
    .expect("batch");
    assert!(batch[0].change.hlc > third.change.hlc);
    assert!(batch[1].change.hlc > batch[0].change.hlc);
    assert!(batch[2].change.hlc > batch[1].change.hlc);
}

/// A draft made far in the future (a wrong or hostile client clock) doesn't pull the HLC with it.
async fn clock_ignores_a_far_future_draft(store: &SqlStore) {
    let owner = user_owner();
    let mut ahead = draft(ItemId::random(), owner, None, 1);
    ahead.updated_at = datetime!(2100-01-01 00:00:00 UTC);
    let written = put(store, ahead).await;
    let now_ms =
        u64::try_from(time::OffsetDateTime::now_utc().unix_timestamp() * 1000).expect("a time");
    assert!(
        written.change.hlc.millis() <= now_ms + 61_000,
        "the clock stayed near the server's, at {}",
        written.change.hlc.millis()
    );
    // And a later write still orders after it.
    let next = put(store, draft(ItemId::random(), owner, None, 1)).await;
    assert!(next.change.hlc > written.change.hlc);
}

/// A cursor per owner: an owner the device has just joined is read from empty, whatever sequence
/// numbers of this server the device has seen of other owners.
async fn owner_cursors(store: &SqlStore) {
    let origin = ServerInfo::server_id(store);
    let a = user_owner();
    let b = user_owner();
    let nobody = user_owner();
    put(store, draft(ItemId::random(), a, None, 1)).await;
    let b1 = put(store, draft(ItemId::random(), b, None, 1)).await;
    let a2 = put(store, draft(ItemId::random(), a, None, 1)).await;
    let b2 = put(store, draft(ItemId::random(), b, None, 1)).await;

    // The device has seen all of `a` and none of `b`. One vector at a2's sequence would skip b1.
    let seen_a: VersionVector = [(origin, a2.change.seq)].into_iter().collect();
    let cursors = [(a, seen_a.clone()), (b, VersionVector::new())];
    let page = ItemStore::changes_since_each(store, &cursors, 10)
        .await
        .expect("changes_since_each");
    let ids: Vec<ItemId> = page.items.iter().map(|i| i.id).collect();
    assert_eq!(ids, vec![b1.id, b2.id]);
    assert!(!page.more);

    // A page cut short says more follows, and is a prefix.
    let short = ItemStore::changes_since_each(store, &cursors, 1)
        .await
        .expect("changes_since_each");
    assert_eq!(short.items.len(), 1);
    assert_eq!(short.items[0].id, b1.id);
    assert!(short.more);
    assert!(
        ItemStore::changes_since_each(store, &[], 10)
            .await
            .expect("changes_since_each")
            .items
            .is_empty()
    );

    // The newest change and the horizon of each owner on its own.
    let latest = ItemStore::latest_each(store, &[a, b, nobody])
        .await
        .expect("latest_each");
    let at = |seq: u64| -> VersionVector { [(origin, seq)].into_iter().collect() };
    assert_eq!(
        latest,
        vec![
            (a, at(a2.change.seq)),
            (b, at(b2.change.seq)),
            (nobody, VersionVector::new())
        ]
    );
    let horizon = ItemStore::purged_each(store, &[a, nobody])
        .await
        .expect("purged_each");
    assert_eq!(
        horizon,
        vec![(a, VersionVector::new()), (nobody, VersionVector::new())]
    );

    // More distinct cursors than one query ORs together are read in chunks, then merged.
    let mut many = Vec::new();
    let mut want = Vec::new();
    for _ in 0..110 {
        let owner = user_owner();
        let item = put(store, draft(ItemId::random(), owner, None, 1)).await;
        let before = item.change.seq - 1;
        let since = if before == 0 {
            VersionVector::new()
        } else {
            at(before)
        };
        many.push((owner, since));
        want.push(item.id);
    }
    let all = ItemStore::changes_since_each(store, &many, 500)
        .await
        .expect("changes_since_each");
    let ids: Vec<ItemId> = all.items.iter().map(|i| i.id).collect();
    assert_eq!(ids, want);
    assert!(!all.more);
    let cut = ItemStore::changes_since_each(store, &many, 105)
        .await
        .expect("changes_since_each");
    assert_eq!(cut.items.len(), 105);
    assert!(cut.more);
    let ids: Vec<ItemId> = cut.items.iter().map(|i| i.id).collect();
    assert_eq!(ids, want[..105]);
}

async fn run_all(store: &SqlStore) {
    put_and_get(store).await;
    conflicts(store).await;
    batches(store).await;
    sequence_has_no_gaps(store).await;
    paging(store).await;
    latest_per_origin(store).await;
    owner_cursors(store).await;
    tombstones(store).await;
    clock(store).await;
    clock_ignores_a_far_future_draft(store).await;
}

#[tokio::test]
async fn sqlite_in_memory() {
    run_all(&memory().await).await;
}

#[tokio::test]
async fn sqlite_in_a_file() {
    let (store, _dir) = file().await;
    run_all(&store).await;
}

#[tokio::test]
async fn postgres_when_configured() {
    if let Some(store) = external("KEMLOCK_TEST_POSTGRES_URL").await {
        run_all(&store).await;
    }
}

#[tokio::test]
async fn mysql_when_configured() {
    if let Some(store) = external("KEMLOCK_TEST_MYSQL_URL").await {
        run_all(&store).await;
    }
}

#[tokio::test]
async fn a_signed_write_is_kept_with_the_item_and_does_not_set_the_flag() {
    let store = memory().await;
    let writer = kemlock_domain::UserId::random();
    let owner = kemlock_domain::Owner::User(writer);
    let other = user_owner();
    let id = ItemId::random();
    let signature = kemlock_domain::WriteSignature {
        writer,
        key_version: 2,
        signature: vec![5; kemlock_domain::WriteSignature::SIGNATURE_LEN],
    };

    // Unsigned writes leave no flag.
    put(&store, draft(ItemId::random(), owner, None, 1)).await;
    assert!(
        !ItemStore::signed_writes_required(&store, owner)
            .await
            .expect("flag")
    );

    let mut signed = draft(id, owner, None, 1);
    signed.signature = Some(signature.clone());
    let stored = put(&store, signed).await;
    assert_eq!(stored.signature, Some(signature.clone()));
    assert_eq!(
        get(&store, id).await.expect("the item").signature,
        Some(signature.clone())
    );
    // Only the owner's own request sets the flag, not a signed write.
    assert!(
        !ItemStore::signed_writes_required(&store, owner)
            .await
            .expect("flag")
    );
    ItemStore::require_signed_writes(&store, owner, MADE_AT)
        .await
        .expect("asked");
    assert!(
        ItemStore::signed_writes_required(&store, owner)
            .await
            .expect("flag")
    );
    // It is the owner's, and no other's.
    assert!(
        !ItemStore::signed_writes_required(&store, other)
            .await
            .expect("flag")
    );

    // The signature comes back on a sync, and a newer unsigned write replaces it.
    let page = ItemStore::changes_since(&store, &[owner], &VersionVector::new(), 10)
        .await
        .expect("a page");
    assert!(
        page.items
            .iter()
            .any(|i| i.id == id && i.signature == Some(signature.clone()))
    );
    let replaced = put(&store, draft(id, owner, Some(1), 2)).await;
    assert_eq!(replaced.signature, None);
}

#[tokio::test]
async fn an_owner_may_ask_for_signed_writes_and_clear_it_again() {
    let store = memory().await;
    let owner = user_owner();
    assert!(
        !ItemStore::signed_writes_required(&store, owner)
            .await
            .expect("flag")
    );
    ItemStore::require_signed_writes(&store, owner, MADE_AT)
        .await
        .expect("asked");
    ItemStore::require_signed_writes(&store, owner, MADE_AT)
        .await
        .expect("asked twice");
    assert!(
        ItemStore::signed_writes_required(&store, owner)
            .await
            .expect("flag")
    );
    ItemStore::clear_signed_writes(&store, owner)
        .await
        .expect("cleared");
    ItemStore::clear_signed_writes(&store, owner)
        .await
        .expect("cleared twice");
    assert!(
        !ItemStore::signed_writes_required(&store, owner)
            .await
            .expect("flag")
    );
}
