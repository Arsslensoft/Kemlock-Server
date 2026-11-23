//! Delta sync across spaces: a device receives its user's vault and every space its user is a
//! confirmed member of, and nothing else.

mod chain_kit;
mod fakes;
mod space_fakes;

use chain_kit::invited_chain;
use fakes::{actor, write};
use kemlock_app::spaces::{CreateCollectionInput, InviteInput, SpaceChainRepo};
use kemlock_app::{SyncOutcome, SyncPage};
use kemlock_domain::spaces::{
    CollectionId, CollectionPermission, CustomPermissions, Grantee, SpaceRole,
};
use kemlock_domain::{ItemId, Owner, SpaceId, SyncCursor, UserId};
use space_fakes::{SpaceWorld, key_for, name};

async fn synced(w: &SpaceWorld, user: UserId) -> Vec<ItemId> {
    match w
        .sync_delta()
        .execute(user, &SyncCursor::default(), None)
        .await
        .expect("the sync works")
    {
        SyncOutcome::Page(page) => page.items.iter().map(|i| i.id).collect(),
        SyncOutcome::Unchanged => panic!("a page is expected"),
    }
}

#[tokio::test]
async fn a_confirmed_member_syncs_the_spaces_items_with_their_own() {
    let w = SpaceWorld::new();
    let sam = w.user("sam@example.org").await;
    let ana = w.user("ana@example.org").await;
    let (space, everyone) = w.make_space(sam).await;
    w.join(
        space,
        sam,
        sam,
        ana,
        SpaceRole::Member,
        vec![(everyone, CollectionPermission::Edit)],
    )
    .await;

    let shared = ItemId::random();
    w.put_space_item()
        .execute(
            &actor(sam),
            everyone,
            w.item_write(space, shared, None, 1, 1),
        )
        .await
        .expect("Sam writes into the space");
    let own = ItemId::random();
    w.world
        .put_item()
        .execute(&actor(ana), write(ana, own, None, 1))
        .await
        .expect("Ana writes to her vault");

    let ids = synced(&w, ana).await;
    assert!(ids.contains(&shared), "the space's item arrives");
    assert!(ids.contains(&own), "so does her own");
    assert_eq!(ids.len(), 2);
    // Sam sees the space item and not Ana's vault.
    assert_eq!(synced(&w, sam).await, vec![shared]);
}

#[tokio::test]
async fn an_invited_or_outside_account_does_not_sync_the_space() {
    let w = SpaceWorld::new();
    let sam = w.user("sam@example.org").await;
    let ana = w.user("ana@example.org").await;
    let eve = w.user("eve@example.org").await;
    let (space, everyone) = w.make_space(sam).await;
    w.invite()
        .execute(
            &actor(sam),
            space,
            InviteInput {
                email: "ana@example.org".to_owned(),
                role: SpaceRole::Member,
                custom: CustomPermissions::NONE,
                grants: vec![(everyone, CollectionPermission::View)],
            },
        )
        .await
        .expect("the invitation is made");
    w.put_space_item()
        .execute(
            &actor(sam),
            everyone,
            w.item_write(space, ItemId::random(), None, 1, 1),
        )
        .await
        .expect("Sam writes into the space");

    assert!(synced(&w, ana).await.is_empty(), "invited, not confirmed");
    assert!(synced(&w, eve).await.is_empty(), "not in the space");
}

#[tokio::test]
async fn a_member_who_was_removed_stops_syncing_the_space() {
    let w = SpaceWorld::new();
    let sam = w.user("sam@example.org").await;
    let ana = w.user("ana@example.org").await;
    let (space, everyone) = w.make_space(sam).await;
    w.join(
        space,
        sam,
        sam,
        ana,
        SpaceRole::Member,
        vec![(everyone, CollectionPermission::View)],
    )
    .await;
    w.put_space_item()
        .execute(
            &actor(sam),
            everyone,
            w.item_write(space, ItemId::random(), None, 1, 1),
        )
        .await
        .expect("Sam writes into the space");
    assert_eq!(synced(&w, ana).await.len(), 1);

    w.offboard()
        .remove(&actor(sam), space, ana)
        .await
        .expect("Ana is removed");
    assert!(synced(&w, ana).await.is_empty());
}

// ---- a cursor per owner: what a device joining a space, or holding an old cursor, receives ----

async fn page_since(
    w: &SpaceWorld,
    user: UserId,
    since: &SyncCursor,
    limit: Option<u32>,
) -> SyncPage {
    match w
        .sync_delta()
        .execute(user, since, limit)
        .await
        .expect("the sync works")
    {
        SyncOutcome::Page(page) => page,
        SyncOutcome::Unchanged => panic!("a page is expected"),
    }
}

async fn outcome_since(w: &SpaceWorld, user: UserId, since: &SyncCursor) -> SyncOutcome {
    w.sync_delta()
        .execute(user, since, None)
        .await
        .expect("the sync works")
}

fn ids_of(page: &SyncPage) -> Vec<ItemId> {
    page.items.iter().map(|i| i.id).collect()
}

async fn put_in_space(
    w: &SpaceWorld,
    by: UserId,
    space: SpaceId,
    collection: CollectionId,
) -> ItemId {
    let id = ItemId::random();
    w.put_space_item()
        .execute(&actor(by), collection, w.item_write(space, id, None, 1, 1))
        .await
        .expect("the item is written into the space");
    id
}

async fn put_own(w: &SpaceWorld, user: UserId) -> ItemId {
    let id = ItemId::random();
    w.world
        .put_item()
        .execute(&actor(user), write(user, id, None, 1))
        .await
        .expect("the item is written to the vault");
    id
}

#[tokio::test]
async fn a_device_that_joins_a_space_gets_the_items_written_before_it_joined() {
    let w = SpaceWorld::new();
    let sam = w.user("sam@example.org").await;
    let ana = w.user("ana@example.org").await;
    let (space, everyone) = w.make_space(sam).await;
    let early = vec![
        put_in_space(&w, sam, space, everyone).await,
        put_in_space(&w, sam, space, everyone).await,
    ];
    // Ana's vault is written after the space's items, so her cursor holds a higher sequence of
    // this server than any of them: the case a single vector got wrong.
    let own = put_own(&w, ana).await;
    let first = page_since(&w, ana, &SyncCursor::default(), None).await;
    assert_eq!(ids_of(&first), vec![own]);

    w.join(
        space,
        sam,
        sam,
        ana,
        SpaceRole::Member,
        vec![(everyone, CollectionPermission::Edit)],
    )
    .await;

    let joined = page_since(&w, ana, &first.next, None).await;
    assert_eq!(ids_of(&joined), early, "the space's whole history, once");
    assert!(!joined.more);
    assert_eq!(
        outcome_since(&w, ana, &joined.next).await,
        SyncOutcome::Unchanged
    );
    // From then on the space is a delta like any owner.
    let late = put_in_space(&w, sam, space, everyone).await;
    let delta = page_since(&w, ana, &joined.next, None).await;
    assert_eq!(ids_of(&delta), vec![late]);
}

#[tokio::test]
async fn a_grant_made_later_loses_and_repeats_no_item() {
    let w = SpaceWorld::new();
    let sam = w.user("sam@example.org").await;
    let ana = w.user("ana@example.org").await;
    let (space, everyone) = w.make_space(sam).await;
    let private = CollectionId::random();
    w.create_collection()
        .execute(
            &actor(sam),
            space,
            CreateCollectionInput {
                id: private,
                parent: None,
                name: name(8),
                grants: Vec::new(),
                keys: vec![key_for(private, sam, 6)],
            },
        )
        .await
        .expect("Sam makes a collection only he holds");
    let shared = put_in_space(&w, sam, space, everyone).await;
    let secret = put_in_space(&w, sam, space, private).await;
    put_own(&w, ana).await;

    // Ana joins with the first collection only. Members sync every envelope of their spaces, the
    // collections they are not granted included, so the private one's item arrives too.
    w.join(
        space,
        sam,
        sam,
        ana,
        SpaceRole::Member,
        vec![(everyone, CollectionPermission::View)],
    )
    .await;
    let first = page_since(&w, ana, &SyncCursor::default(), None).await;
    let mut got = ids_of(&first);
    got.retain(|id| *id == shared || *id == secret);
    assert_eq!(got, vec![shared, secret]);

    // The grant adds a key to an envelope Ana holds: the next sync has nothing for it.
    w.grant()
        .execute(
            &actor(sam),
            space,
            private,
            Grantee::Member(ana),
            CollectionPermission::View,
            vec![key_for(private, ana, 7)],
        )
        .await
        .expect("Sam grants the collection");
    assert_eq!(
        outcome_since(&w, ana, &first.next).await,
        SyncOutcome::Unchanged
    );
    // What is written to it after that arrives once, and a device with no cursor has all of it.
    let later = put_in_space(&w, sam, space, private).await;
    assert_eq!(
        ids_of(&page_since(&w, ana, &first.next, None).await),
        vec![later]
    );
    let fresh = ids_of(&page_since(&w, ana, &SyncCursor::default(), None).await);
    for id in [shared, secret, later] {
        assert_eq!(fresh.iter().filter(|seen| **seen == id).count(), 1);
    }
}

#[tokio::test]
async fn a_revoked_member_stops_receiving_the_spaces_changes() {
    let w = SpaceWorld::new();
    let sam = w.user("sam@example.org").await;
    let ana = w.user("ana@example.org").await;
    let (space, everyone) = w.make_space(sam).await;
    w.join(
        space,
        sam,
        sam,
        ana,
        SpaceRole::Member,
        vec![(everyone, CollectionPermission::View)],
    )
    .await;
    let before = put_in_space(&w, sam, space, everyone).await;
    let first = page_since(&w, ana, &SyncCursor::default(), None).await;
    assert_eq!(ids_of(&first), vec![before]);

    // The space changes after Ana's sync, and then she is revoked.
    put_in_space(&w, sam, space, everyone).await;
    w.offboard()
        .revoke(&actor(sam), space, ana)
        .await
        .expect("Sam revokes Ana");

    assert_eq!(
        outcome_since(&w, ana, &first.next).await,
        SyncOutcome::Unchanged,
        "the space's change is not hers"
    );
    // Her next page carries her own change only, and her cursor no longer lists the space.
    let own = put_own(&w, ana).await;
    let delta = page_since(&w, ana, &first.next, None).await;
    assert_eq!(ids_of(&delta), vec![own]);
    assert!(delta.next.since(Owner::Space(space)).is_empty());
}

#[tokio::test]
async fn a_version_1_cursor_still_works_as_every_owner_at_that_vector() {
    let w = SpaceWorld::new();
    let sam = w.user("sam@example.org").await;
    let ana = w.user("ana@example.org").await;
    let (space, everyone) = w.make_space(sam).await;
    w.join(
        space,
        sam,
        sam,
        ana,
        SpaceRole::Member,
        vec![(everyone, CollectionPermission::Edit)],
    )
    .await;
    put_in_space(&w, sam, space, everyone).await;
    put_own(&w, ana).await;
    let first = page_since(&w, ana, &SyncCursor::default(), None).await;
    assert_eq!(
        first.next.to_cursor_bytes()[0],
        2,
        "the server writes version 2"
    );

    // What a device synced before the cursor changed holds: one vector.
    let legacy = SyncCursor::from_cursor_bytes(&first.next.merged().to_cursor_bytes())
        .expect("a version 1 cursor is read");
    assert_eq!(
        outcome_since(&w, ana, &legacy).await,
        SyncOutcome::Unchanged
    );
    let in_space = put_in_space(&w, sam, space, everyone).await;
    let own = put_own(&w, ana).await;
    let delta = page_since(&w, ana, &legacy, None).await;
    assert_eq!(ids_of(&delta), vec![in_space, own]);
    // And the cursor it hands back is version 2.
    assert_eq!(delta.next.to_cursor_bytes()[0], 2);
    assert_eq!(
        outcome_since(&w, ana, &delta.next).await,
        SyncOutcome::Unchanged
    );
}

#[tokio::test]
async fn paging_across_owners_with_different_cursors_returns_every_item_once() {
    let w = SpaceWorld::new();
    let sam = w.user("sam@example.org").await;
    let ana = w.user("ana@example.org").await;
    let (space, everyone) = w.make_space(sam).await;
    put_own(&w, ana).await;
    let first = page_since(&w, ana, &SyncCursor::default(), None).await;

    // Two items of the space before Ana joins, then more of the space and of her vault, mixed.
    let mut expected = vec![
        put_in_space(&w, sam, space, everyone).await,
        put_in_space(&w, sam, space, everyone).await,
    ];
    w.join(
        space,
        sam,
        sam,
        ana,
        SpaceRole::Member,
        vec![(everyone, CollectionPermission::Edit)],
    )
    .await;
    expected.push(put_own(&w, ana).await);
    expected.push(put_in_space(&w, sam, space, everyone).await);
    expected.push(put_own(&w, ana).await);

    let mut seen = Vec::new();
    let mut cursor = first.next;
    let mut pages = 0;
    loop {
        let page = page_since(&w, ana, &cursor, Some(2)).await;
        pages += 1;
        seen.extend(ids_of(&page));
        cursor = page.next;
        if !page.more {
            break;
        }
        assert!(pages < 10, "paging must end");
    }
    assert_eq!(pages, 3);
    seen.sort();
    expected.sort();
    assert_eq!(seen, expected, "every item once");
    assert_eq!(
        outcome_since(&w, ana, &cursor).await,
        SyncOutcome::Unchanged
    );
}

/// Gives `space` a chain in which `sam` made it and invited `ana`, and in which a `confirm` record
/// confirmed her only when `confirmed` says so. The members table is left as it is.
async fn chain_of(w: &SpaceWorld, space: SpaceId, sam: UserId, ana: UserId, confirmed: bool) {
    w.spaces
        .chain_append(space, invited_chain(space, sam, ana, confirmed))
        .await
        .expect("the chain is stored");
}

#[tokio::test]
async fn a_row_confirmed_without_a_confirm_record_does_not_sync_a_chained_space() {
    let w = SpaceWorld::new();
    let sam = w.user("sam@example.org").await;
    let ana = w.user("ana@example.org").await;
    let (space, everyone) = w.make_space(sam).await;
    // The members table says Ana is confirmed, as an outside change can leave it.
    w.join(
        space,
        sam,
        sam,
        ana,
        SpaceRole::Member,
        vec![(everyone, CollectionPermission::Edit)],
    )
    .await;
    let item = put_in_space(&w, sam, space, everyone).await;
    assert_eq!(
        synced(&w, ana).await,
        vec![item],
        "no chain: the table rules"
    );

    // The chain invited her and never confirmed her: the space is not hers to sync.
    chain_of(&w, space, sam, ana, false).await;
    assert!(synced(&w, ana).await.is_empty());
    assert_eq!(
        w.sync_owners().execute(ana).await.expect("owners"),
        vec![Owner::User(ana)]
    );
}

#[tokio::test]
async fn a_member_the_chain_confirms_syncs_a_chained_space() {
    let w = SpaceWorld::new();
    let sam = w.user("sam@example.org").await;
    let ana = w.user("ana@example.org").await;
    let (space, everyone) = w.make_space(sam).await;
    w.join(
        space,
        sam,
        sam,
        ana,
        SpaceRole::Member,
        vec![(everyone, CollectionPermission::Edit)],
    )
    .await;
    let item = put_in_space(&w, sam, space, everyone).await;
    chain_of(&w, space, sam, ana, true).await;
    assert_eq!(synced(&w, ana).await, vec![item]);
    assert_eq!(
        w.sync_owners().execute(ana).await.expect("owners"),
        vec![Owner::User(ana), Owner::Space(space)]
    );
}
