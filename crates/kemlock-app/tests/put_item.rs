mod fakes;

use fakes::*;
use kemlock_app::AppError;
use kemlock_domain::{ItemError, ItemId, ItemWrite, Owner, Revision, Sealed};

#[tokio::test]
async fn a_new_item_is_stored_at_revision_one_with_a_change_id() {
    let world = World::new().with_signups();
    let user = make_user(&world, "sam@example.org").await;
    let id = ItemId::random();

    let item = world
        .put_item()
        .execute(&actor(user), write(user, id, None, 1))
        .await
        .expect("the put works");
    assert_eq!(item.id, id);
    assert_eq!(item.revision, Revision(1));
    assert_eq!(item.owner, Owner::User(user));
    assert_eq!(item.change.origin, world.store.server());
    assert_eq!(item.change.seq, 1);
    assert_eq!(world.store.item(id), Some(item));
}

#[tokio::test]
async fn a_put_records_an_event_and_nudges_the_owner() {
    let world = World::new().with_signups();
    let user = make_user(&world, "sam@example.org").await;
    let who = actor(user);
    let id = ItemId::random();

    let item = world
        .put_item()
        .execute(&who, write(user, id, None, 1))
        .await
        .expect("the put works");

    let events = world.store.events();
    let event = events
        .iter()
        .find(|e| e.action == "item.put")
        .expect("an event was recorded");
    assert_eq!(event.actor, Some(user));
    assert_eq!(event.device, Some(who.device));
    assert_eq!(event.target, Some(id.to_string()));

    assert_eq!(
        world.notifier.calls(),
        vec![(Owner::User(user), item.change)]
    );
}

#[tokio::test]
async fn a_replace_needs_the_stored_revision_and_the_next_one() {
    let world = World::new().with_signups();
    let user = make_user(&world, "sam@example.org").await;
    let who = actor(user);
    let id = ItemId::random();
    world
        .put_item()
        .execute(&who, write(user, id, None, 1))
        .await
        .expect("create");

    let second = world
        .put_item()
        .execute(&who, write(user, id, Some(1), 2))
        .await
        .expect("replace");
    assert_eq!(second.revision, Revision(2));
    assert_eq!(second.change.seq, 2);

    // A stale writer still holds revision 1: conflict, naming revision 2.
    let stale = world
        .put_item()
        .execute(&who, write(user, id, Some(1), 2))
        .await;
    assert_eq!(
        stale,
        Err(AppError::Conflict {
            item: id,
            current: Some(Revision(2))
        })
    );

    // A skipped revision is refused.
    let skipped = world
        .put_item()
        .execute(&who, write(user, id, Some(2), 4))
        .await;
    assert_eq!(
        skipped,
        Err(AppError::Item(ItemError::BadRevision { got: Revision(4) }))
    );
}

#[tokio::test]
async fn creating_over_an_existing_item_is_a_conflict() {
    let world = World::new().with_signups();
    let user = make_user(&world, "sam@example.org").await;
    let who = actor(user);
    let id = ItemId::random();
    world
        .put_item()
        .execute(&who, write(user, id, None, 1))
        .await
        .expect("create");
    let again = world
        .put_item()
        .execute(&who, write(user, id, None, 1))
        .await;
    assert_eq!(
        again,
        Err(AppError::Conflict {
            item: id,
            current: Some(Revision(1))
        })
    );
}

#[tokio::test]
async fn a_delete_leaves_a_tombstone() {
    let world = World::new().with_signups();
    let user = make_user(&world, "sam@example.org").await;
    let who = actor(user);
    let id = ItemId::random();
    world
        .put_item()
        .execute(&who, write(user, id, None, 1))
        .await
        .expect("create");

    let tombstone = world
        .put_item()
        .execute(&who, delete(user, id, 1, 2))
        .await
        .expect("delete");
    assert!(tombstone.is_tombstone());
    assert_eq!(tombstone.revision, Revision(2));
    assert_eq!(tombstone.ciphertext, None);
    assert_eq!(tombstone.item_key, None);
    assert!(
        world
            .store
            .events()
            .iter()
            .any(|e| e.action == "item.delete")
    );
}

#[tokio::test]
async fn nobody_writes_another_accounts_vault() {
    let world = World::new().with_signups();
    let sam = make_user(&world, "sam@example.org").await;
    let alex = make_user(&world, "alex@example.org").await;
    let result = world
        .put_item()
        .execute(&actor(alex), write(sam, ItemId::random(), None, 1))
        .await;
    assert_eq!(result, Err(AppError::Item(ItemError::Forbidden)));
    assert!(world.notifier.calls().is_empty());
}

#[tokio::test]
async fn malformed_and_oversized_values_are_refused() {
    let world = World::new().with_signups();
    let user = make_user(&world, "sam@example.org").await;
    let who = actor(user);

    let short = ItemWrite {
        sealed: Some(Sealed {
            ciphertext: vec![1; 5],
            item_key: vec![2; kemlock_domain::item::ITEM_KEY_LEN],
        }),
        ..write(user, ItemId::random(), None, 1)
    };
    assert_eq!(
        world.put_item().execute(&who, short).await,
        Err(AppError::Item(ItemError::Malformed))
    );

    let huge = ItemWrite {
        sealed: Some(Sealed {
            ciphertext: vec![1; 1024 * 1024 + 1],
            item_key: vec![2; kemlock_domain::item::ITEM_KEY_LEN],
        }),
        ..write(user, ItemId::random(), None, 1)
    };
    assert_eq!(
        world.put_item().execute(&who, huge).await,
        Err(AppError::Item(ItemError::TooLarge))
    );
}

#[tokio::test]
async fn an_id_taken_by_another_account_answers_the_same_whatever_revision_is_guessed() {
    let world = World::new().with_signups();
    let sam = make_user(&world, "sam@example.org").await;
    let alex = make_user(&world, "alex@example.org").await;
    let id = ItemId::random();
    for revision in 1..=3 {
        let expected = (revision > 1).then_some(revision - 1);
        world
            .put_item()
            .execute(&actor(sam), write(sam, id, expected, revision))
            .await
            .expect("sam's writes");
    }

    // Alex's own owner, sam's item id. A stale-revision answer would name sam's revision (3);
    // every guess must get the answer an id taken by someone else gets, with no revision.
    for expected in [None, Some(1), Some(2), Some(3), Some(40)] {
        let result = world
            .put_item()
            .execute(&actor(alex), write(alex, id, expected, 4))
            .await;
        assert_eq!(result, Err(AppError::Duplicate), "expected {expected:?}");
    }
    assert_eq!(world.store.item(id).map(|i| i.revision), Some(Revision(3)));
}

/// Moves the account to key version 2, as a rotation of its root key does.
async fn rotate(world: &World, user: kemlock_domain::UserId) {
    use kemlock_app::ports::UserRepo;
    let mut account = world.store.user(user).expect("the account");
    account.key_version = 2;
    UserRepo::update(&world.store, &account)
        .await
        .expect("the account is updated");
}

#[tokio::test]
async fn a_sealed_write_must_name_the_accounts_current_key_version() {
    let world = World::new().with_signups();
    let user = make_user(&world, "sam@example.org").await;
    let who = actor(user);
    let id = ItemId::random();
    world
        .put_item()
        .execute(&who, write(user, id, None, 1))
        .await
        .expect("at key version 1 the account's version is 1");

    rotate(&world, user).await;
    // A device that did not learn of the rotation still seals at version 1: refused, and the
    // stored item stays as it was.
    let stale = world
        .put_item()
        .execute(&who, write(user, id, Some(1), 2))
        .await;
    assert!(matches!(stale, Err(AppError::Invalid(_))), "{stale:?}");
    assert_eq!(world.store.item(id).map(|item| item.revision), Some(Revision(1)));

    let current = kemlock_domain::ItemWrite {
        key_version: 2,
        ..write(user, id, Some(1), 2)
    };
    world
        .put_item()
        .execute(&who, current)
        .await
        .expect("at the current version");
}

#[tokio::test]
async fn a_deletion_names_no_key_version_and_is_not_refused_for_it() {
    let world = World::new().with_signups();
    let user = make_user(&world, "sam@example.org").await;
    let who = actor(user);
    let id = ItemId::random();
    world
        .put_item()
        .execute(&who, write(user, id, None, 1))
        .await
        .expect("create");
    rotate(&world, user).await;
    world
        .put_item()
        .execute(&who, delete(user, id, 1, 2))
        .await
        .expect("a tombstone from a device that missed the rotation");
}
