//! The signed-only flag of an owner (docs/crypto.md, "The signed-only flag"): the owner asks for it,
//! and after it an unsigned `kem1` write is refused. A signed write does not set it.

mod fakes;
mod space_fakes;

use fakes::*;
use kemlock_app::AppError;
use kemlock_app::signed_writes::SetSignedWrites;
use kemlock_domain::spaces::{CollectionPermission, SpaceRole};
use kemlock_domain::{ItemError, ItemFormat, ItemId, ItemWrite, Owner, UserId, WriteSignature};
use space_fakes::SpaceWorld;

fn signed(user: UserId, mut w: ItemWrite) -> ItemWrite {
    w.signature = Some(WriteSignature {
        writer: user,
        key_version: 1,
        signature: vec![5; WriteSignature::SIGNATURE_LEN],
    });
    w
}

fn setting(world: &World) -> SetSignedWrites<FakeStore, space_fakes::Spaces, FakeStore, FakeEnv> {
    SetSignedWrites {
        items: world.store.clone(),
        spaces: space_fakes::FakeSpaces::new(world.store.clone()),
        events: world.store.clone(),
        clock: world.env.clone(),
    }
}

#[tokio::test]
async fn a_signed_write_does_not_make_an_owner_signed_only() {
    let world = World::new().with_signups();
    let user = make_user(&world, "sam@example.org").await;
    let who = actor(user);
    let id = ItemId::random();

    world
        .put_item()
        .execute(&who, write(user, id, None, 1))
        .await
        .expect("an unsigned write is accepted");
    let signed_write = world
        .put_item()
        .execute(&who, signed(user, write(user, id, Some(1), 2)))
        .await
        .expect("a signed one is too");
    assert!(signed_write.signature.is_some());
    // The Kemlock app does not sign yet: one device that does must not lock the others out.
    world
        .put_item()
        .execute(&who, write(user, id, Some(2), 3))
        .await
        .expect("an unsigned write is still accepted");
}

#[tokio::test]
async fn once_the_owner_asks_unsigned_writes_are_refused_and_it_can_be_undone() {
    let world = World::new().with_signups();
    let user = make_user(&world, "sam@example.org").await;
    let who = actor(user);
    let id = ItemId::random();
    world
        .put_item()
        .execute(&who, write(user, id, None, 1))
        .await
        .expect("a write");

    setting(&world)
        .execute(&who, Owner::User(user), true)
        .await
        .expect("the owner asks");
    assert_eq!(
        world
            .put_item()
            .execute(&who, write(user, id, Some(1), 2))
            .await,
        Err(AppError::Item(ItemError::SignatureRequired))
    );
    assert_eq!(
        world.put_item().execute(&who, delete(user, id, 1, 2)).await,
        Err(AppError::Item(ItemError::SignatureRequired))
    );
    world
        .put_item()
        .execute(&who, signed(user, delete(user, id, 1, 2)))
        .await
        .expect("a signed delete is accepted");

    // Turning it off is logged, like turning it on.
    setting(&world)
        .execute(&who, Owner::User(user), false)
        .await
        .expect("the owner clears it");
    world
        .put_item()
        .execute(&who, write(user, ItemId::random(), None, 1))
        .await
        .expect("unsigned writes are accepted again");
    let actions: Vec<_> = world.store.events().iter().map(|e| e.action).collect();
    assert!(actions.contains(&"signed_writes.require"));
    assert!(actions.contains(&"signed_writes.clear"));
}

#[tokio::test]
async fn a_batch_with_an_unsigned_write_is_refused_whole() {
    let world = World::new().with_signups();
    let user = make_user(&world, "sam@example.org").await;
    let who = actor(user);
    setting(&world)
        .execute(&who, Owner::User(user), true)
        .await
        .expect("the owner asks");

    let (a, b) = (ItemId::random(), ItemId::random());
    let result = world
        .put_batch()
        .execute(
            &who,
            vec![
                signed(user, write(user, a, None, 1)),
                write(user, b, None, 1),
            ],
        )
        .await;
    assert_eq!(result, Err(AppError::Item(ItemError::SignatureRequired)));
    assert!(world.store.item(a).is_none(), "nothing was stored");
}

#[tokio::test]
async fn a_bitwarden_format_write_is_never_held_to_the_flag() {
    let world = World::new().with_signups();
    let user = make_user(&world, "sam@example.org").await;
    let who = actor(user);
    setting(&world)
        .execute(&who, Owner::User(user), true)
        .await
        .expect("the owner asks");
    let mut bw = write(user, ItemId::random(), None, 1);
    bw.format = ItemFormat::Bw;
    world
        .put_item()
        .execute(&who, bw)
        .await
        .expect("a bw write needs no signature");
}

#[tokio::test]
async fn nobody_sets_the_flag_of_another_persons_vault() {
    let world = World::new().with_signups();
    let sam = make_user(&world, "sam@example.org").await;
    let alex = make_user(&world, "alex@example.org").await;
    for required in [true, false] {
        assert_eq!(
            setting(&world)
                .execute(&actor(alex), Owner::User(sam), required)
                .await,
            Err(AppError::Forbidden)
        );
    }
}

#[tokio::test]
async fn a_caller_who_may_not_write_the_owner_learns_nothing_of_the_flag() {
    let world = World::new().with_signups();
    let sam = make_user(&world, "sam@example.org").await;
    let alex = make_user(&world, "alex@example.org").await;
    setting(&world)
        .execute(&actor(sam), Owner::User(sam), true)
        .await
        .expect("sam asks");

    // Alex writing Sam's vault is refused as a stranger is, not for the missing signature.
    let result = world
        .put_item()
        .execute(&actor(alex), write(sam, ItemId::random(), None, 1))
        .await;
    assert_eq!(result, Err(AppError::Item(ItemError::Forbidden)));
}

#[tokio::test]
async fn a_stale_write_to_a_signed_only_owner_is_a_conflict_before_it_is_a_missing_signature() {
    let world = World::new().with_signups();
    let user = make_user(&world, "sam@example.org").await;
    let who = actor(user);
    let id = ItemId::random();
    world
        .put_item()
        .execute(&who, write(user, id, None, 1))
        .await
        .expect("a write");
    setting(&world)
        .execute(&who, Owner::User(user), true)
        .await
        .expect("the owner asks");
    let result = world
        .put_item()
        .execute(&who, write(user, id, Some(7), 8))
        .await;
    assert!(
        matches!(result, Err(AppError::Conflict { .. })),
        "{result:?}"
    );
}

#[tokio::test]
async fn a_space_is_set_by_an_owner_or_admin_and_only_by_them() {
    let w = SpaceWorld::new();
    let sam = w.user("sam@example.org").await;
    let alex = w.user("alex@example.org").await;
    let kim = w.user("kim@example.org").await;
    let (space, everyone) = w.make_space(sam).await;
    w.join(
        space,
        sam,
        sam,
        alex,
        SpaceRole::Member,
        vec![(everyone, CollectionPermission::Edit)],
    )
    .await;
    let set = SetSignedWrites {
        items: w.world.store.clone(),
        spaces: w.spaces.clone(),
        events: w.world.store.clone(),
        clock: w.world.env.clone(),
    };
    let owner = Owner::Space(space);

    // An ordinary member may not, and a stranger can't tell the space exists.
    assert_eq!(
        set.execute(&actor(alex), owner, true).await,
        Err(AppError::Forbidden)
    );
    assert_eq!(
        set.execute(&actor(kim), owner, true).await,
        Err(AppError::NotFound)
    );
    set.execute(&actor(sam), owner, true)
        .await
        .expect("the owner asks");
    assert!(
        kemlock_app::ports::ItemStore::signed_writes_required(&w.world.store, owner)
            .await
            .expect("a read")
    );
    set.execute(&actor(sam), owner, false)
        .await
        .expect("and clears it");
}
