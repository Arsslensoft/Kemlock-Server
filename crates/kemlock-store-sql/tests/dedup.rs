//! `TagStore` and `DismissalStore`: tags, groups, the key version, the on/off switch and the rule
//! that any item write clears the item's tags.
//!
//! Each scenario runs on every backend that is available, as `accounts.rs` does, with owners and
//! item ids of its own.

mod common;

use common::{MADE_AT, draft, external, file, memory, put, tombstone, user_owner};
use kemlock_app::dedup::{DismissalStore, TagStore};
use kemlock_app::ports::ItemStore;
use kemlock_domain::{
    DedupTag, Dismissal, DismissalId, ItemFormat, ItemId, Owner, Revision, TagSet, UserId,
};
use kemlock_store_sql::SqlStore;

fn tag(n: u8) -> DedupTag {
    DedupTag([n; 32])
}

fn set(version: u32, tags: &[u8]) -> TagSet {
    TagSet::new(version, tags.iter().copied().map(tag)).expect("a small set")
}

async fn new_item(store: &SqlStore, owner: Owner) -> ItemId {
    let id = ItemId::random();
    put(store, draft(id, owner, None, 1)).await;
    id
}

async fn tagged(store: &SqlStore, owner: Owner, version: u32, tags: &[u8]) -> ItemId {
    let id = new_item(store, owner).await;
    assert!(
        store
            .put_tags(owner, id, Revision(1), &set(version, tags))
            .await
            .expect("tags are stored"),
        "the item is at revision 1"
    );
    id
}

fn sorted(mut ids: Vec<ItemId>) -> Vec<ItemId> {
    ids.sort();
    ids
}

async fn settings_start_off_and_are_kept(store: &SqlStore) {
    let owner = user_owner();
    let by = UserId::random();
    let initial = store.settings(owner).await.expect("settings");
    assert!(!initial.enabled);
    assert_eq!(initial.version, 1);
    assert_eq!(initial.changed_by, None);

    let on = store
        .set_matching(owner, true, by, MADE_AT)
        .await
        .expect("on");
    assert!(on.enabled);
    assert_eq!(on.changed_by, Some(by));
    assert_eq!(on.changed_at, Some(MADE_AT));
    assert_eq!(store.settings(owner).await.expect("read"), on);
    // Another owner is not touched.
    assert!(!store.settings(user_owner()).await.expect("other").enabled);

    let again = store
        .set_matching(owner, true, by, MADE_AT)
        .await
        .expect("on again");
    assert_eq!(again, on);
}

async fn equal_tags_make_groups(store: &SqlStore) {
    let owner = user_owner();
    let a = tagged(store, owner, 1, &[1, 2]).await;
    let b = tagged(store, owner, 1, &[2, 3]).await;
    let c = tagged(store, owner, 1, &[9]).await;
    let waits = new_item(store, owner).await;
    // Another owner with the same tag value is another group, and another key version is ignored.
    let elsewhere = user_owner();
    tagged(store, elsewhere, 1, &[2]).await;
    tagged(store, owner, 2, &[2]).await;

    assert_eq!(store.matches(owner, 1, a).await.expect("matches"), vec![b]);
    assert_eq!(store.matches(owner, 1, b).await.expect("matches"), vec![a]);
    assert!(
        store
            .matches(owner, 1, c)
            .await
            .expect("matches")
            .is_empty()
    );
    assert!(
        store
            .matches(owner, 1, waits)
            .await
            .expect("matches")
            .is_empty()
    );

    let groups = store.groups(owner, 1).await.expect("groups");
    assert_eq!(groups.len(), 1);
    assert_eq!(groups[0].tag, tag(2));
    assert_eq!(groups[0].items, sorted(vec![a, b]));

    // Three items carry tags under version 1 (the version-2 one is waiting under version 1), and
    // one has none at all.
    assert_eq!(store.waiting(owner, 1).await.expect("waiting"), 2);
    assert_eq!(store.waiting(owner, 2).await.expect("waiting"), 4);
}

async fn put_tags_replaces_and_checks_the_item(store: &SqlStore) {
    let owner = user_owner();
    let id = new_item(store, owner).await;

    assert!(
        store
            .put_tags(owner, id, Revision(1), &set(1, &[1, 2]))
            .await
            .expect("stored")
    );
    assert!(
        store
            .put_tags(owner, id, Revision(1), &set(1, &[3]))
            .await
            .expect("replaced")
    );
    let other = tagged(store, owner, 1, &[3]).await;
    assert_eq!(
        store.matches(owner, 1, id).await.expect("matches"),
        vec![other]
    );
    // The old tags went with the replacement.
    let third = tagged(store, owner, 1, &[1]).await;
    assert!(
        store
            .matches(owner, 1, third)
            .await
            .expect("matches")
            .is_empty()
    );

    // Not stored: another revision, another owner, an unknown item.
    assert!(
        !store
            .put_tags(owner, id, Revision(2), &set(1, &[7]))
            .await
            .expect("refused")
    );
    assert!(
        !store
            .put_tags(user_owner(), id, Revision(1), &set(1, &[7]))
            .await
            .expect("refused")
    );
    assert!(
        !store
            .put_tags(owner, ItemId::random(), Revision(1), &set(1, &[7]))
            .await
            .expect("refused")
    );

    // An empty set clears.
    assert!(
        store
            .put_tags(owner, id, Revision(1), &set(1, &[]))
            .await
            .expect("cleared")
    );
    assert!(store.matches(owner, 1, other).await.expect("m").is_empty());
}

async fn any_write_clears_the_tags(store: &SqlStore) {
    let owner = user_owner();
    let a = tagged(store, owner, 1, &[1]).await;
    let b = tagged(store, owner, 1, &[1]).await;
    assert_eq!(store.groups(owner, 1).await.expect("groups").len(), 1);

    // A new revision with no tags, as the Kemlock API writes one.
    put(store, draft(a, owner, Some(1), 2)).await;
    assert!(store.groups(owner, 1).await.expect("groups").is_empty());
    assert_eq!(store.waiting(owner, 1).await.expect("waiting"), 1);
    // Tags of the old revision can't be stored for the new one by mistake.
    assert!(
        !store
            .put_tags(owner, a, Revision(1), &set(1, &[1]))
            .await
            .expect("refused")
    );
    assert!(
        store
            .put_tags(owner, a, Revision(2), &set(1, &[1]))
            .await
            .expect("stored")
    );
    assert_eq!(store.groups(owner, 1).await.expect("groups").len(), 1);

    // A Bitwarden-format item loses its tags the same way: the Bitwarden API writes through the
    // same store.
    let bw_item = ItemId::random();
    let mut first = draft(bw_item, owner, None, 1);
    first.format = ItemFormat::Bw;
    put(store, first).await;
    assert!(
        store
            .put_tags(owner, bw_item, Revision(1), &set(1, &[8]))
            .await
            .expect("stored")
    );
    let partner = tagged(store, owner, 1, &[8]).await;
    assert_eq!(
        store.matches(owner, 1, partner).await.expect("m"),
        vec![bw_item]
    );
    let mut second = draft(bw_item, owner, Some(1), 2);
    second.format = ItemFormat::Bw;
    put(store, second).await;
    assert!(
        store
            .matches(owner, 1, partner)
            .await
            .expect("m")
            .is_empty()
    );

    // A batch clears every item it writes, and only those.
    let c = tagged(store, owner, 1, &[1]).await;
    ItemStore::put_batch(
        store,
        vec![draft(a, owner, Some(2), 3), draft(b, owner, Some(1), 2)],
    )
    .await
    .expect("the batch is stored");
    assert!(store.matches(owner, 1, c).await.expect("m").is_empty());
    assert!(store.groups(owner, 1).await.expect("groups").is_empty());
}

async fn a_deleted_item_leaves_its_group(store: &SqlStore) {
    let owner = user_owner();
    let a = tagged(store, owner, 1, &[1]).await;
    let b = tagged(store, owner, 1, &[1]).await;
    put(store, tombstone(b, owner, Some(1), 2, MADE_AT)).await;
    assert!(store.groups(owner, 1).await.expect("groups").is_empty());
    assert!(store.matches(owner, 1, a).await.expect("m").is_empty());
    assert!(
        !store
            .put_tags(owner, b, Revision(2), &set(1, &[1]))
            .await
            .expect("a tombstone takes no tags")
    );
    // Only the live item still waits for nothing.
    assert_eq!(store.waiting(owner, 1).await.expect("waiting"), 0);
}

async fn off_and_rotation_delete_the_tags(store: &SqlStore) {
    let owner = user_owner();
    let by = UserId::random();
    store
        .set_matching(owner, true, by, MADE_AT)
        .await
        .expect("on");
    let a = tagged(store, owner, 1, &[1]).await;
    tagged(store, owner, 1, &[1]).await;
    let other_owner = user_owner();
    let theirs = tagged(store, other_owner, 1, &[1]).await;

    let off = store
        .set_matching(owner, false, by, MADE_AT)
        .await
        .expect("off");
    assert!(!off.enabled);
    assert!(store.groups(owner, 1).await.expect("groups").is_empty());
    assert!(store.matches(owner, 1, a).await.expect("m").is_empty());
    // Someone else's tags stay.
    tagged(store, other_owner, 1, &[1]).await;
    assert!(
        !store
            .matches(other_owner, 1, theirs)
            .await
            .expect("m")
            .is_empty()
    );

    // A rotation moves the version, keeps the switch and deletes the tags.
    store
        .set_matching(owner, true, by, MADE_AT)
        .await
        .expect("on");
    let b = tagged(store, owner, 1, &[5]).await;
    tagged(store, owner, 1, &[5]).await;
    assert_eq!(store.bump_version(owner, MADE_AT).await.expect("bump"), 2);
    let settings = store.settings(owner).await.expect("settings");
    assert_eq!((settings.version, settings.enabled), (2, true));
    assert!(store.groups(owner, 1).await.expect("groups").is_empty());
    assert!(store.matches(owner, 2, b).await.expect("m").is_empty());
    assert!(
        store
            .put_tags(owner, b, Revision(1), &set(2, &[5]))
            .await
            .expect("tags under the new version")
    );
    assert_eq!(store.bump_version(owner, MADE_AT).await.expect("bump"), 3);
}

async fn dismissals_are_kept_per_owner(store: &SqlStore) {
    let owner = user_owner();
    let by = UserId::random();
    let items = [ItemId::random(), ItemId::random(), ItemId::random()];
    let first = Dismissal::new(owner, items, by, MADE_AT).expect("three items");
    let second = Dismissal::new(
        owner,
        [items[0], items[1]],
        by,
        MADE_AT + time::Duration::minutes(1),
    )
    .expect("two items");
    store.add(&first).await.expect("add");
    store.add(&second).await.expect("add");
    store.add(&first).await.expect_err("an id is used once");

    assert_eq!(
        DismissalStore::get(store, first.id).await.expect("get"),
        Some(first.clone())
    );
    assert_eq!(
        DismissalStore::get(store, DismissalId::random())
            .await
            .expect("get"),
        None
    );
    assert_eq!(
        store.list(owner).await.expect("list"),
        vec![first.clone(), second.clone()]
    );
    assert!(store.list(user_owner()).await.expect("list").is_empty());

    assert!(store.remove(first.id).await.expect("remove"));
    assert!(!store.remove(first.id).await.expect("remove again"));
    assert_eq!(store.list(owner).await.expect("list"), vec![second]);
}

async fn run_all(store: &SqlStore) {
    settings_start_off_and_are_kept(store).await;
    equal_tags_make_groups(store).await;
    put_tags_replaces_and_checks_the_item(store).await;
    any_write_clears_the_tags(store).await;
    a_deleted_item_leaves_its_group(store).await;
    off_and_rotation_delete_the_tags(store).await;
    dismissals_are_kept_per_owner(store).await;
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
