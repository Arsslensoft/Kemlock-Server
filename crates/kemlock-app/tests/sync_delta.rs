mod fakes;

use fakes::*;
use kemlock_app::ports::ChangePage;
use kemlock_app::{AppError, SyncOutcome, SyncPage};
use kemlock_domain::{ItemId, Owner, SyncCursor, UserId, VersionVector};
use time::Duration;

async fn page(world: &World, user: UserId, since: &SyncCursor, limit: Option<u32>) -> SyncPage {
    match world
        .sync_delta()
        .execute(user, since, limit)
        .await
        .expect("the sync works")
    {
        SyncOutcome::Page(page) => page,
        SyncOutcome::Unchanged => panic!("a page is expected"),
    }
}

async fn put_new(world: &World, user: UserId) -> ItemId {
    let id = ItemId::random();
    world
        .put_item()
        .execute(&actor(user), write(user, id, None, 1))
        .await
        .expect("put");
    id
}

#[tokio::test]
async fn a_first_sync_returns_everything_and_a_cursor() {
    let world = World::new().with_signups();
    let user = make_user(&world, "sam@example.org").await;
    let a = put_new(&world, user).await;
    let b = put_new(&world, user).await;

    let first = page(&world, user, &SyncCursor::default(), None).await;
    let ids: Vec<ItemId> = first.items.iter().map(|i| i.id).collect();
    assert_eq!(ids, vec![a, b], "oldest change first");
    assert!(!first.more);
    assert_eq!(first.next.merged().get(world.store.server()), 2);
}

#[tokio::test]
async fn an_empty_vault_syncs_to_an_empty_page() {
    let world = World::new().with_signups();
    let user = make_user(&world, "sam@example.org").await;
    let first = page(&world, user, &SyncCursor::default(), None).await;
    assert!(first.items.is_empty());
    assert!(!first.more);
}

#[tokio::test]
async fn a_cursor_that_covers_the_latest_change_is_unchanged() {
    let world = World::new().with_signups();
    let user = make_user(&world, "sam@example.org").await;
    put_new(&world, user).await;
    let first = page(&world, user, &SyncCursor::default(), None).await;

    let again = world
        .sync_delta()
        .execute(user, &first.next, None)
        .await
        .expect("the sync works");
    assert_eq!(again, SyncOutcome::Unchanged);
}

#[tokio::test]
async fn a_cursor_returns_only_what_changed_after_it() {
    let world = World::new().with_signups();
    let user = make_user(&world, "sam@example.org").await;
    let a = put_new(&world, user).await;
    put_new(&world, user).await;
    let first = page(&world, user, &SyncCursor::default(), None).await;

    // Item a changes again, and a new item appears.
    world
        .put_item()
        .execute(&actor(user), write(user, a, Some(1), 2))
        .await
        .expect("replace");
    let c = put_new(&world, user).await;

    let delta = page(&world, user, &first.next, None).await;
    let ids: Vec<ItemId> = delta.items.iter().map(|i| i.id).collect();
    assert_eq!(ids, vec![a, c]);
    assert_eq!(
        delta.items[0].revision.0, 2,
        "each item once, at its latest revision"
    );
    assert_eq!(delta.next.merged().get(world.store.server()), 4);
}

#[tokio::test]
async fn pages_of_a_given_size_cover_everything_exactly_once() {
    let world = World::new().with_signups();
    let user = make_user(&world, "sam@example.org").await;
    let mut expected = Vec::new();
    for _ in 0..5 {
        expected.push(put_new(&world, user).await);
    }

    let mut seen = Vec::new();
    let mut cursor = SyncCursor::default();
    let mut pages = 0;
    loop {
        let p = page(&world, user, &cursor, Some(2)).await;
        pages += 1;
        seen.extend(p.items.iter().map(|i| i.id));
        cursor = p.next;
        if !p.more {
            break;
        }
        assert!(pages < 10, "paging must end");
    }
    assert_eq!(pages, 3);
    assert_eq!(seen, expected);

    // The final cursor is up to date.
    assert_eq!(
        world
            .sync_delta()
            .execute(user, &cursor, Some(2))
            .await
            .expect("the sync works"),
        SyncOutcome::Unchanged
    );
}

#[tokio::test]
async fn the_page_size_is_clamped() {
    let world = World::new().with_signups();
    let user = make_user(&world, "sam@example.org").await;
    for _ in 0..3 {
        put_new(&world, user).await;
    }
    let one = page(&world, user, &SyncCursor::default(), Some(0)).await;
    assert_eq!(one.items.len(), 1);
    assert!(one.more);
    let all = page(&world, user, &SyncCursor::default(), Some(100_000)).await;
    assert_eq!(all.items.len(), 3);
}

#[tokio::test]
async fn tombstones_are_synced_like_items() {
    let world = World::new().with_signups();
    let user = make_user(&world, "sam@example.org").await;
    let id = put_new(&world, user).await;
    let first = page(&world, user, &SyncCursor::default(), None).await;
    world
        .put_item()
        .execute(&actor(user), delete(user, id, 1, 2))
        .await
        .expect("delete");

    let delta = page(&world, user, &first.next, None).await;
    assert_eq!(delta.items.len(), 1);
    assert!(delta.items[0].is_tombstone());
}

#[tokio::test]
async fn an_account_only_sees_its_own_items() {
    let world = World::new().with_signups();
    let sam = make_user(&world, "sam@example.org").await;
    let alex = make_user(&world, "alex@example.org").await;
    put_new(&world, sam).await;
    let theirs = put_new(&world, alex).await;

    let alex_page = page(&world, alex, &SyncCursor::default(), None).await;
    let ids: Vec<ItemId> = alex_page.items.iter().map(|i| i.id).collect();
    assert_eq!(ids, vec![theirs]);
}

#[tokio::test]
async fn a_cursor_behind_the_tombstone_horizon_needs_a_full_sync() {
    let world = World::new().with_signups();
    let user = make_user(&world, "sam@example.org").await;
    let id = put_new(&world, user).await;
    let early = page(&world, user, &SyncCursor::default(), None).await;
    put_new(&world, user).await;
    world
        .put_item()
        .execute(&actor(user), delete(user, id, 1, 2))
        .await
        .expect("delete");
    // Purge the tombstone, which moves the horizon to change 3.
    world.env.clock.advance(Duration::days(40));
    let purged = kemlock_app::ports::ItemStore::purge_tombstones(
        &world.store,
        kemlock_app::ports::Clock::now(&world.env),
    )
    .await
    .expect("purges");
    assert_eq!(purged, 1);

    // The device that last synced at change 1 can't know the deletion: start again.
    assert_eq!(
        world
            .sync_delta()
            .execute(user, &early.next, None)
            .await
            .map(|_| ()),
        Err(AppError::FullSyncRequired)
    );
    // Starting again without a cursor is always allowed.
    let fresh = page(&world, user, &SyncCursor::default(), None).await;
    assert_eq!(fresh.items.len(), 1);
    // The finished sync's cursor is moved up to the horizon, so the next sync is a delta again.
    assert_eq!(fresh.next.merged().get(world.store.server()), 3);
    assert_eq!(
        world
            .sync_delta()
            .execute(user, &fresh.next, None)
            .await
            .expect("the sync works"),
        SyncOutcome::Unchanged
    );
}

/// A store that runs a purge the moment the page is asked for, as one on another replica could
/// between the reads of a single sync.
#[derive(Clone)]
struct PurgesMidSync {
    inner: FakeStore,
    purge_before: time::OffsetDateTime,
    armed: std::sync::Arc<std::sync::atomic::AtomicBool>,
}

impl kemlock_app::ports::ItemStore for PurgesMidSync {
    async fn get(
        &self,
        id: ItemId,
    ) -> Result<Option<kemlock_domain::Item>, kemlock_app::ports::StoreError> {
        kemlock_app::ports::ItemStore::get(&self.inner, id).await
    }

    async fn put(
        &self,
        draft: kemlock_domain::ItemDraft,
    ) -> Result<kemlock_domain::Item, kemlock_app::ports::StoreError> {
        kemlock_app::ports::ItemStore::put(&self.inner, draft).await
    }

    async fn put_batch(
        &self,
        drafts: Vec<kemlock_domain::ItemDraft>,
    ) -> Result<Vec<kemlock_domain::Item>, kemlock_app::ports::StoreError> {
        kemlock_app::ports::ItemStore::put_batch(&self.inner, drafts).await
    }

    async fn changes_since(
        &self,
        owners: &[kemlock_domain::Owner],
        since: &VersionVector,
        limit: u32,
    ) -> Result<ChangePage, kemlock_app::ports::StoreError> {
        if self.armed.swap(false, std::sync::atomic::Ordering::SeqCst) {
            kemlock_app::ports::ItemStore::purge_tombstones(&self.inner, self.purge_before).await?;
        }
        kemlock_app::ports::ItemStore::changes_since(&self.inner, owners, since, limit).await
    }

    async fn latest(
        &self,
        owners: &[kemlock_domain::Owner],
    ) -> Result<VersionVector, kemlock_app::ports::StoreError> {
        kemlock_app::ports::ItemStore::latest(&self.inner, owners).await
    }

    async fn purged_through(
        &self,
        owners: &[kemlock_domain::Owner],
    ) -> Result<VersionVector, kemlock_app::ports::StoreError> {
        kemlock_app::ports::ItemStore::purged_through(&self.inner, owners).await
    }

    async fn purge_tombstones(
        &self,
        before: time::OffsetDateTime,
    ) -> Result<u64, kemlock_app::ports::StoreError> {
        kemlock_app::ports::ItemStore::purge_tombstones(&self.inner, before).await
    }
}

#[tokio::test]
async fn a_purge_after_the_page_is_read_still_demands_a_full_sync() {
    let world = World::new().with_signups();
    let user = make_user(&world, "sam@example.org").await;
    let id = put_new(&world, user).await;
    let early = page(&world, user, &SyncCursor::default(), None).await;
    world
        .put_item()
        .execute(&actor(user), delete(user, id, 1, 2))
        .await
        .expect("delete");
    world.env.clock.advance(Duration::days(40));

    // The purge runs just before the page is read, so the page lacks the tombstone. The horizon
    // must be read after the page, or this sync would pair that page with a stale horizon and
    // the client would never learn the item was deleted.
    let racing = kemlock_app::SyncDelta {
        items: PurgesMidSync {
            inner: world.store.clone(),
            purge_before: kemlock_app::ports::Clock::now(&world.env),
            armed: std::sync::Arc::new(std::sync::atomic::AtomicBool::new(true)),
        },
        spaces: NoSpaceStore,
    };
    assert_eq!(
        racing.execute(user, &early.next, None).await.map(|_| ()),
        Err(AppError::FullSyncRequired)
    );
}

#[tokio::test]
async fn another_accounts_purged_tombstone_does_not_force_a_full_sync() {
    let world = World::new().with_signups();
    let sam = make_user(&world, "sam@example.org").await;
    let alex = make_user(&world, "alex@example.org").await;
    put_new(&world, sam).await;
    let sams_cursor = page(&world, sam, &SyncCursor::default(), None).await.next;

    // Alex deletes an item and the purge removes the tombstone, which moves a horizon.
    let theirs = put_new(&world, alex).await;
    world
        .put_item()
        .execute(&actor(alex), delete(alex, theirs, 1, 2))
        .await
        .expect("delete");
    world.env.clock.advance(Duration::days(40));
    kemlock_app::ports::ItemStore::purge_tombstones(
        &world.store,
        kemlock_app::ports::Clock::now(&world.env),
    )
    .await
    .expect("purges");

    // Sam's items never changed and none of sam's tombstones went: no full sync, and the cursor
    // is still good, where a global horizon would have answered 410 for every account.
    assert_eq!(
        world
            .sync_delta()
            .execute(sam, &sams_cursor, None)
            .await
            .expect("sam's sync is a delta, not a full sync"),
        SyncOutcome::Unchanged
    );
    // Alex's own stale cursor, from before the deletion, still needs a full sync.
    let alexs_early = SyncCursor::from_owners([(
        Owner::User(alex),
        VersionVector::from_iter([(world.store.server(), 2)]),
    )]);
    assert_eq!(
        world
            .sync_delta()
            .execute(alex, &alexs_early, None)
            .await
            .map(|_| ()),
        Err(AppError::FullSyncRequired)
    );
}
