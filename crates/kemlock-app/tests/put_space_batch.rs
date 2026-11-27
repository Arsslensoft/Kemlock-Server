//! A batch that mixes vault and space items: checked write by write, stored all together or
//! not at all.

mod fakes;
mod space_fakes;

use fakes::{actor, write};
use kemlock_app::spaces::SpacesError;
use kemlock_domain::spaces::{CollectionPermission, SpaceError, SpaceRole};
use kemlock_domain::{ItemId, Owner};
use space_fakes::SpaceWorld;

#[tokio::test]
async fn vault_and_space_items_are_stored_together_with_their_collections() {
    let w = SpaceWorld::new();
    let sam = w.user("sam@example.org").await;
    let (space, everyone) = w.make_space(sam).await;
    let (own, shared) = (ItemId::random(), ItemId::random());

    let stored = w
        .put_space_batch()
        .execute(
            &actor(sam),
            vec![
                (write(sam, own, None, 1), None),
                (w.item_write(space, shared, None, 1, 1), Some(everyone)),
            ],
        )
        .await
        .expect("the batch is stored");

    assert_eq!(stored.len(), 2);
    assert_eq!(stored[0].owner, Owner::User(sam));
    assert_eq!(stored[1].owner, Owner::Space(space));
    assert_eq!(w.spaces.item_collection(shared), Some(everyone));
    assert_eq!(w.spaces.item_collection(own), None);
    // One nudge per owner.
    assert_eq!(w.world.notifier.calls().len(), 2);
}

#[tokio::test]
async fn one_refused_write_stores_nothing() {
    let w = SpaceWorld::new();
    let sam = w.user("sam@example.org").await;
    let lee = w.user("lee@example.org").await;
    let (space, everyone) = w.make_space(sam).await;
    w.join(
        space,
        sam,
        sam,
        lee,
        SpaceRole::Member,
        vec![(everyone, CollectionPermission::View)],
    )
    .await;
    let (own, shared) = (ItemId::random(), ItemId::random());

    // Lee may view Everyone but not write to it.
    let refused = w
        .put_space_batch()
        .execute(
            &actor(lee),
            vec![
                (write(lee, own, None, 1), None),
                (w.item_write(space, shared, None, 1, 1), Some(everyone)),
            ],
        )
        .await
        .err();
    assert!(matches!(
        refused,
        Some(SpacesError::Rule(SpaceError::Forbidden(_)))
    ));
    assert!(
        w.world.store.item(own).is_none(),
        "the vault item isn't stored"
    );
    assert!(w.world.store.item(shared).is_none());
}

#[tokio::test]
async fn a_stranger_cannot_write_into_a_space_and_learns_nothing_of_it() {
    let w = SpaceWorld::new();
    let sam = w.user("sam@example.org").await;
    let eve = w.user("eve@example.org").await;
    let (space, everyone) = w.make_space(sam).await;

    let refused = w
        .put_space_batch()
        .execute(
            &actor(eve),
            vec![(
                w.item_write(space, ItemId::random(), None, 1, 1),
                Some(everyone),
            )],
        )
        .await
        .err();
    assert_eq!(refused, Some(SpacesError::Rule(SpaceError::NotAMember)));
}

#[tokio::test]
async fn a_space_item_needs_a_collection_and_a_vault_item_has_none() {
    let w = SpaceWorld::new();
    let sam = w.user("sam@example.org").await;
    let (space, everyone) = w.make_space(sam).await;

    let no_collection = w
        .put_space_batch()
        .execute(
            &actor(sam),
            vec![(w.item_write(space, ItemId::random(), None, 1, 1), None)],
        )
        .await
        .err();
    assert!(matches!(
        no_collection,
        Some(SpacesError::Rule(SpaceError::Invalid(_)))
    ));

    let stray = w
        .put_space_batch()
        .execute(
            &actor(sam),
            vec![(write(sam, ItemId::random(), None, 1), Some(everyone))],
        )
        .await
        .err();
    assert!(matches!(
        stray,
        Some(SpacesError::Rule(SpaceError::Invalid(_)))
    ));
}

#[tokio::test]
async fn a_stale_space_write_is_a_conflict_that_names_the_item() {
    let w = SpaceWorld::new();
    let sam = w.user("sam@example.org").await;
    let (space, everyone) = w.make_space(sam).await;
    let id = ItemId::random();
    w.put_space_item()
        .execute(&actor(sam), everyone, w.item_write(space, id, None, 1, 1))
        .await
        .expect("the item is created");

    // The writer thinks the item is still new.
    let stale = w
        .put_space_batch()
        .execute(
            &actor(sam),
            vec![(w.item_write(space, id, None, 1, 1), Some(everyone))],
        )
        .await
        .err();
    assert!(matches!(
        stale,
        Some(SpacesError::StaleItem { item, .. }) if item == id
    ));
}

#[tokio::test]
async fn an_item_appearing_twice_or_an_oversized_batch_is_refused() {
    let w = SpaceWorld::new();
    let sam = w.user("sam@example.org").await;
    let id = ItemId::random();
    let twice = w
        .put_space_batch()
        .execute(
            &actor(sam),
            vec![
                (write(sam, id, None, 1), None),
                (write(sam, id, Some(1), 2), None),
            ],
        )
        .await
        .err();
    assert!(matches!(
        twice,
        Some(SpacesError::Rule(SpaceError::Invalid(_)))
    ));

    let many = (0..501)
        .map(|_| (write(sam, ItemId::random(), None, 1), None))
        .collect();
    let oversized = w.put_space_batch().execute(&actor(sam), many).await.err();
    assert!(matches!(
        oversized,
        Some(SpacesError::Rule(SpaceError::Invalid(_)))
    ));
}

#[tokio::test]
async fn a_vault_item_of_a_mixed_batch_must_name_the_accounts_current_key_version() {
    use kemlock_app::ports::UserRepo;

    let w = SpaceWorld::new();
    let sam = w.user("sam@example.org").await;
    let (space, everyone) = w.make_space(sam).await;
    // A rotation of the root key moved the account to key version 2.
    let mut account = w.world.store.user(sam).expect("the account");
    account.key_version = 2;
    UserRepo::update(&w.world.store, &account)
        .await
        .expect("the account is updated");
    let (own, shared) = (ItemId::random(), ItemId::random());

    // The vault item is sealed under version 1, as a device that missed the rotation does it.
    let refused = w
        .put_space_batch()
        .execute(
            &actor(sam),
            vec![
                (write(sam, own, None, 1), None),
                (w.item_write(space, shared, None, 1, 1), Some(everyone)),
            ],
        )
        .await
        .err();
    assert!(matches!(
        refused,
        Some(SpacesError::Rule(SpaceError::Invalid(_)))
    ));
    assert!(w.world.store.item(own).is_none());
    assert!(w.world.store.item(shared).is_none(), "nothing is stored");
}
