//! The signed-only flag of an owner (docs/crypto.md, "Signed item writes"): the first signed
//! `kem1` write sets it, and after it an unsigned `kem1` write is refused.

mod fakes;

use fakes::*;
use kemlock_app::AppError;
use kemlock_app::signed_writes::RequireSignedWrites;
use kemlock_domain::{ItemError, ItemFormat, ItemId, ItemWrite, Owner, UserId, WriteSignature};

fn signed(user: UserId, mut w: ItemWrite) -> ItemWrite {
    w.signature = Some(WriteSignature {
        writer: user,
        key_version: 1,
        signature: vec![5; WriteSignature::SIGNATURE_LEN],
    });
    w
}

#[tokio::test]
async fn unsigned_writes_are_accepted_until_a_signed_one_is() {
    let world = World::new().with_signups();
    let user = make_user(&world, "sam@example.org").await;
    let who = actor(user);
    let id = ItemId::random();

    world
        .put_item()
        .execute(&who, write(user, id, None, 1))
        .await
        .expect("an unsigned write is accepted while no signed one was");
    assert_eq!(
        world
            .put_item()
            .execute(&who, signed(user, write(user, id, Some(1), 2)))
            .await
            .map(|i| i.signature.is_some()),
        Ok(true)
    );
    // The owner is signed-only now: the same write without a signature is refused, and so is a
    // delete without one.
    assert_eq!(
        world
            .put_item()
            .execute(&who, write(user, id, Some(2), 3))
            .await,
        Err(AppError::Item(ItemError::SignatureRequired))
    );
    assert_eq!(
        world.put_item().execute(&who, delete(user, id, 2, 3)).await,
        Err(AppError::Item(ItemError::SignatureRequired))
    );
    // A signed delete goes through.
    world
        .put_item()
        .execute(&who, signed(user, delete(user, id, 2, 3)))
        .await
        .expect("a signed delete is accepted");
}

#[tokio::test]
async fn a_batch_with_an_unsigned_write_is_refused_whole() {
    let world = World::new().with_signups();
    let user = make_user(&world, "sam@example.org").await;
    let who = actor(user);
    world
        .put_item()
        .execute(&who, signed(user, write(user, ItemId::random(), None, 1)))
        .await
        .expect("a signed write");

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
    world
        .put_item()
        .execute(&who, signed(user, write(user, ItemId::random(), None, 1)))
        .await
        .expect("a signed write");
    let mut bw = write(user, ItemId::random(), None, 1);
    bw.format = ItemFormat::Bw;
    world
        .put_item()
        .execute(&who, bw)
        .await
        .expect("a bw write needs no signature");
}

#[tokio::test]
async fn an_owner_may_ask_for_signed_writes_before_the_first() {
    let world = World::new().with_signups();
    let user = make_user(&world, "sam@example.org").await;
    let who = actor(user);
    let require = RequireSignedWrites {
        items: world.store.clone(),
        clock: world.env.clone(),
    };
    require
        .execute(&who, Owner::User(user))
        .await
        .expect("the owner asks");
    assert_eq!(
        world
            .put_item()
            .execute(&who, write(user, ItemId::random(), None, 1))
            .await,
        Err(AppError::Item(ItemError::SignatureRequired))
    );
    // Nobody asks for another account's vault, or for a space.
    assert_eq!(
        require.execute(&who, Owner::User(UserId::random())).await,
        Err(AppError::Forbidden)
    );
}
