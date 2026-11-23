//! The membership facts the sign-in checks read from the spaces, with the "Require SSO" policy
//! each space has.

mod fakes;
mod space_fakes;

use fakes::actor;
use kemlock_app::spaces::SpaceRepo;
use kemlock_app::sso::{
    MembershipFacts, RequireSso, SignInMethod, SpaceRole as PolicyRole, SsoError,
};
use kemlock_domain::UserId;
use kemlock_domain::spaces::{CollectionPermission, SpaceRole};
use space_fakes::SpaceWorld;

async fn facts(w: &SpaceWorld, user: UserId) -> Vec<(bool, PolicyRole)> {
    w.facts()
        .spaces_of(user)
        .await
        .expect("facts")
        .into_iter()
        .map(|m| (m.require_sso, m.role))
        .collect()
}

#[tokio::test]
async fn the_facts_are_the_confirmed_memberships_with_their_policy_and_role() {
    let w = SpaceWorld::new();
    let sam = w.user("sam@example.org").await;
    let ana = w.user("ana@example.org").await;
    let lee = w.user("lee@example.org").await;
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
    w.join(
        space,
        sam,
        sam,
        lee,
        SpaceRole::Admin,
        vec![(everyone, CollectionPermission::View)],
    )
    .await;

    assert_eq!(facts(&w, ana).await, vec![(false, PolicyRole::Member)]);
    SpaceRepo::set_require_sso(&w.spaces, space, true)
        .await
        .expect("set");
    assert_eq!(facts(&w, ana).await, vec![(true, PolicyRole::Member)]);
    assert_eq!(facts(&w, lee).await, vec![(true, PolicyRole::Admin)]);
    assert_eq!(facts(&w, sam).await, vec![(true, PolicyRole::Owner)]);

    // The check over these facts: the ordinary member is blocked, the admin and owner are not.
    let check = RequireSso {
        membership: w.facts(),
    };
    let user = |id| w.world.store.user(id).expect("the account exists");
    assert_eq!(
        check.check(&user(ana), SignInMethod::Password).await,
        Err(SsoError::SsoRequired { space })
    );
    assert_eq!(
        check.check(&user(lee), SignInMethod::Password).await,
        Ok(())
    );
    assert_eq!(
        check.check(&user(sam), SignInMethod::PhoneApproval).await,
        Ok(())
    );
    assert_eq!(check.check(&user(ana), SignInMethod::Sso).await, Ok(()));
}

#[tokio::test]
async fn an_invited_or_removed_account_is_not_bound_by_the_space() {
    let w = SpaceWorld::new();
    let sam = w.user("sam@example.org").await;
    let ana = w.user("ana@example.org").await;
    let (space, everyone) = w.make_space(sam).await;
    SpaceRepo::set_require_sso(&w.spaces, space, true)
        .await
        .expect("set");
    w.invite()
        .execute(
            &actor(sam),
            space,
            kemlock_app::spaces::InviteInput {
                email: "ana@example.org".to_owned(),
                role: SpaceRole::Member,
                custom: kemlock_domain::spaces::CustomPermissions::NONE,
                grants: vec![(everyone, CollectionPermission::View)],
            },
        )
        .await
        .expect("invited");
    assert!(facts(&w, ana).await.is_empty(), "invited, not confirmed");

    // Confirmed, then removed: the space no longer has her.
    w.accept()
        .execute(&actor(ana), space)
        .await
        .expect("accepted");
    w.confirm()
        .execute(
            &actor(sam),
            space,
            ana,
            w.confirm_input(ana, vec![space_fakes::key_for(everyone, ana, 5)]),
        )
        .await
        .expect("confirmed");
    assert_eq!(facts(&w, ana).await.len(), 1);
    w.offboard()
        .remove(&actor(sam), space, ana)
        .await
        .expect("removed");
    assert!(facts(&w, ana).await.is_empty());
}
