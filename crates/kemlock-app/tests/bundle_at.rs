//! Who may read an account's bundle at a key version (docs/crypto.md, "Signed item writes"): the
//! account, and a confirmed member of a space it is a confirmed member of.

mod fakes;
mod space_fakes;

use fakes::actor;
use kemlock_app::AppError;
use kemlock_app::signed_writes::GetBundleAt;
use kemlock_domain::spaces::SpaceRole;
use space_fakes::SpaceWorld;

#[tokio::test]
async fn an_account_and_its_space_mates_may_read_a_bundle_and_nobody_else() {
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
        vec![(everyone, kemlock_domain::spaces::CollectionPermission::Edit)],
    )
    .await;
    let read = GetBundleAt {
        users: w.world.store.clone(),
        spaces: w.spaces.clone(),
    };

    // The account reads its own bundle.
    let own = read
        .execute(&actor(sam), sam, 1)
        .await
        .expect("its own bundle");
    assert_eq!(own.key_version, 1);
    assert!(!own.public_bundle.is_empty());
    // A member of a space it is confirmed in reads it, and the other way round.
    let seen = read
        .execute(&actor(alex), sam, 1)
        .await
        .expect("a space mate");
    assert_eq!(seen, own);
    assert!(read.execute(&actor(sam), alex, 1).await.is_ok());
    // A version the account never had is not found, and neither is an account that shares no
    // space, nor one that doesn't exist.
    assert_eq!(
        read.execute(&actor(sam), sam, 2).await,
        Err(AppError::NotFound)
    );
    assert_eq!(
        read.execute(&actor(kim), sam, 1).await,
        Err(AppError::NotFound)
    );
    assert_eq!(
        read.execute(&actor(sam), kemlock_domain::UserId::random(), 1)
            .await,
        Err(AppError::NotFound)
    );
}
