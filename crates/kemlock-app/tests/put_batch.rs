mod fakes;

use fakes::*;
use kemlock_app::AppError;
use kemlock_domain::{ItemError, ItemId, Owner, Revision};

#[tokio::test]
async fn a_batch_stores_every_write_with_consecutive_changes() {
    let world = World::new().with_signups();
    let user = make_user(&world, "sam@example.org").await;
    let ids: Vec<ItemId> = (0..3).map(|_| ItemId::random()).collect();
    let writes = ids.iter().map(|id| write(user, *id, None, 1)).collect();

    let stored = world
        .put_batch()
        .execute(&actor(user), writes)
        .await
        .expect("the batch works");
    assert_eq!(stored.len(), 3);
    let seqs: Vec<u64> = stored.iter().map(|i| i.change.seq).collect();
    assert_eq!(seqs, vec![1, 2, 3]);
    for id in &ids {
        assert!(world.store.item(*id).is_some());
    }
}

#[tokio::test]
async fn a_batch_nudges_the_owner_once_with_the_newest_change() {
    let world = World::new().with_signups();
    let user = make_user(&world, "sam@example.org").await;
    let writes = (0..4)
        .map(|_| write(user, ItemId::random(), None, 1))
        .collect();
    let stored = world
        .put_batch()
        .execute(&actor(user), writes)
        .await
        .expect("the batch works");

    let calls = world.notifier.calls();
    assert_eq!(calls.len(), 1);
    assert_eq!(calls[0].0, Owner::User(user));
    assert_eq!(calls[0].1, stored[3].change);
    assert!(
        world
            .store
            .events()
            .iter()
            .any(|e| e.action == "item.batch")
    );
}

#[tokio::test]
async fn one_stale_write_stores_nothing_and_names_its_item() {
    let world = World::new().with_signups();
    let user = make_user(&world, "sam@example.org").await;
    let who = actor(user);
    let existing = ItemId::random();
    world
        .put_item()
        .execute(&who, write(user, existing, None, 1))
        .await
        .expect("create");
    let calls_before = world.notifier.calls().len();

    let fresh = ItemId::random();
    let result = world
        .put_batch()
        .execute(
            &who,
            vec![
                write(user, fresh, None, 1),
                // The writer thinks the item is new, but it exists at revision 1.
                write(user, existing, None, 1),
            ],
        )
        .await;
    assert_eq!(
        result,
        Err(AppError::Conflict {
            item: existing,
            current: Some(Revision(1))
        })
    );
    assert!(world.store.item(fresh).is_none(), "all or none");
    assert_eq!(world.notifier.calls().len(), calls_before);
}

#[tokio::test]
async fn a_domain_refusal_stores_nothing() {
    let world = World::new().with_signups();
    let sam = make_user(&world, "sam@example.org").await;
    let alex = make_user(&world, "alex@example.org").await;
    let mine = ItemId::random();
    let result = world
        .put_batch()
        .execute(
            &actor(sam),
            vec![
                write(sam, mine, None, 1),
                write(alex, ItemId::random(), None, 1),
            ],
        )
        .await;
    assert_eq!(result, Err(AppError::Item(ItemError::Forbidden)));
    assert!(world.store.item(mine).is_none());
}

#[tokio::test]
async fn an_item_may_appear_once() {
    let world = World::new().with_signups();
    let user = make_user(&world, "sam@example.org").await;
    let id = ItemId::random();
    let result = world
        .put_batch()
        .execute(
            &actor(user),
            vec![write(user, id, None, 1), write(user, id, Some(1), 2)],
        )
        .await;
    assert!(matches!(result, Err(AppError::Invalid(_))));
}

#[tokio::test]
async fn a_batch_holds_up_to_five_hundred_writes() {
    let world = World::new().with_signups();
    let user = make_user(&world, "sam@example.org").await;
    let who = actor(user);

    let too_many = (0..501)
        .map(|_| write(user, ItemId::random(), None, 1))
        .collect();
    assert!(matches!(
        world.put_batch().execute(&who, too_many).await,
        Err(AppError::Invalid(_))
    ));

    let exactly = (0..500)
        .map(|_| write(user, ItemId::random(), None, 1))
        .collect();
    let stored = world
        .put_batch()
        .execute(&who, exactly)
        .await
        .expect("500 is allowed");
    assert_eq!(stored.len(), 500);
}

#[tokio::test]
async fn an_empty_batch_does_nothing() {
    let world = World::new().with_signups();
    let user = make_user(&world, "sam@example.org").await;
    let stored = world
        .put_batch()
        .execute(&actor(user), Vec::new())
        .await
        .expect("empty is fine");
    assert!(stored.is_empty());
    assert!(world.notifier.calls().is_empty());
}

#[tokio::test]
async fn a_batch_can_mix_puts_and_deletes() {
    let world = World::new().with_signups();
    let user = make_user(&world, "sam@example.org").await;
    let who = actor(user);
    let old = ItemId::random();
    world
        .put_item()
        .execute(&who, write(user, old, None, 1))
        .await
        .expect("create");
    let new = ItemId::random();
    let stored = world
        .put_batch()
        .execute(
            &who,
            vec![delete(user, old, 1, 2), write(user, new, None, 1)],
        )
        .await
        .expect("the batch works");
    assert!(stored[0].is_tombstone());
    assert!(!stored[1].is_tombstone());
}

#[tokio::test]
async fn a_batch_over_another_accounts_id_is_taken_and_stores_nothing() {
    let world = World::new().with_signups();
    let sam = make_user(&world, "sam@example.org").await;
    let alex = make_user(&world, "alex@example.org").await;
    let theirs = ItemId::random();
    world
        .put_item()
        .execute(&actor(sam), write(sam, theirs, None, 1))
        .await
        .expect("sam's item");
    let mine = ItemId::random();
    let result = world
        .put_batch()
        .execute(
            &actor(alex),
            vec![write(alex, mine, None, 1), write(alex, theirs, Some(1), 2)],
        )
        .await;
    assert_eq!(result, Err(AppError::Duplicate));
    assert!(world.store.item(mine).is_none());
}

#[tokio::test]
async fn a_batch_with_one_write_at_a_stale_key_version_stores_nothing() {
    use kemlock_app::ports::UserRepo;
    let world = World::new().with_signups();
    let user = make_user(&world, "sam@example.org").await;
    let mut account = world.store.user(user).expect("the account");
    account.key_version = 2;
    UserRepo::update(&world.store, &account)
        .await
        .expect("the account is updated");

    let (current, stale) = (ItemId::random(), ItemId::random());
    let writes = vec![
        kemlock_domain::ItemWrite {
            key_version: 2,
            ..write(user, current, None, 1)
        },
        write(user, stale, None, 1),
    ];
    let refused = world.put_batch().execute(&actor(user), writes).await;
    assert!(matches!(refused, Err(AppError::Invalid(_))), "{refused:?}");
    assert!(world.store.item(current).is_none());
    assert!(world.store.item(stale).is_none());
}
