//! The SSO group rules applied at sign-in: an account is invited to the spaces the rules name, in
//! the mapped role, and nothing here confirms anyone.

mod fakes;
mod space_fakes;

use fakes::actor;
use kemlock_app::spaces::{InviteInput, SpacesError};
use kemlock_app::sso::{GroupAssignment, SpaceRole as RuleRole};
use kemlock_domain::spaces::{
    CollectionId, CollectionPermission, CustomPermissions, Grantee, MemberState, SpaceError,
    SpaceRole,
};
use kemlock_domain::{SpaceId, UserId};
use space_fakes::{SpaceWorld, key_for};
use uuid::Uuid;

fn assign(space: SpaceId, role: RuleRole, collections: &[CollectionId]) -> GroupAssignment {
    GroupAssignment {
        space,
        role,
        collections: collections.iter().map(|c| c.0).collect(),
    }
}

/// Sam owns a space with the collection Everyone; Ana has an account and no place in it.
async fn scene() -> (SpaceWorld, UserId, UserId, SpaceId, CollectionId) {
    let w = SpaceWorld::new();
    let sam = w.user("sam@example.org").await;
    let ana = w.user("ana@example.org").await;
    let (space, everyone) = w.make_space(sam).await;
    (w, sam, ana, space, everyone)
}

#[tokio::test]
async fn a_rule_invites_the_account_in_the_mapped_role_with_view_grants() {
    let (w, _sam, ana, space, everyone) = scene().await;
    let missing = CollectionId(Uuid::from_u128(99));
    let invited = w
        .apply_group_rules()
        .execute(ana, &[assign(space, RuleRole::Admin, &[everyone, missing])])
        .await
        .expect("the rules apply");
    assert_eq!(invited, vec![space]);

    let member = w.spaces.member(space, ana).expect("Ana has a row");
    assert_eq!(member.state, MemberState::Invited);
    assert_eq!(member.role, SpaceRole::Admin);
    assert_eq!(member.invited_by, ana);
    assert_eq!(member.sealed_space_key, None);
    assert_eq!(member.confirmation, None);

    // Only the collection the space has is granted, read-only; no key is sealed to Ana.
    let state = w.spaces.state(space);
    let grants: Vec<_> = state
        .grants
        .iter()
        .filter(|g| g.grantee == Grantee::Member(ana))
        .collect();
    assert_eq!(grants.len(), 1);
    assert_eq!(grants[0].collection, everyone);
    assert_eq!(grants[0].permission, CollectionPermission::View);
    assert_eq!(w.spaces.copy(everyone, ana), None);
    assert!(
        w.world
            .store
            .events()
            .iter()
            .any(|e| e.action == "space.member.sso-invite" && e.actor == Some(ana))
    );
}

#[tokio::test]
async fn a_rule_for_owner_invites_an_admin() {
    let (w, _sam, ana, space, _) = scene().await;
    w.apply_group_rules()
        .execute(ana, &[assign(space, RuleRole::Owner, &[])])
        .await
        .expect("the rules apply");
    let member = w.spaces.member(space, ana).expect("Ana has a row");
    assert_eq!(member.role, SpaceRole::Admin);
}

#[tokio::test]
async fn the_invited_account_still_needs_a_confirmation_with_the_right_fingerprint() {
    let (w, sam, ana, space, everyone) = scene().await;
    w.apply_group_rules()
        .execute(ana, &[assign(space, RuleRole::Member, &[everyone])])
        .await
        .expect("the rules apply");
    let keys = vec![key_for(everyone, ana, 5)];

    // Not yet accepted: nobody can confirm her.
    let early = w
        .confirm()
        .execute(&actor(sam), space, ana, w.confirm_input(ana, keys.clone()))
        .await;
    assert!(early.is_err());

    w.accept()
        .execute(&actor(ana), space)
        .await
        .expect("she accepts");
    // Accepting grants nothing either.
    assert_eq!(w.spaces.copy(everyone, ana), None);
    assert!(!w.spaces.member(space, ana).expect("row").is_confirmed());

    let mut wrong = w.confirm_input(ana, keys.clone());
    wrong.fingerprint = vec![0; wrong.fingerprint.len()];
    let refused = w
        .confirm()
        .execute(&actor(sam), space, ana, wrong)
        .await
        .err();
    assert!(matches!(
        refused,
        Some(SpacesError::Rule(SpaceError::FingerprintMismatch))
    ));

    w.confirm()
        .execute(&actor(sam), space, ana, w.confirm_input(ana, keys))
        .await
        .expect("Sam compares the fingerprint and confirms");
    assert!(w.spaces.member(space, ana).expect("row").is_confirmed());
    assert!(w.spaces.copy(everyone, ana).is_some());
}

#[tokio::test]
async fn applying_the_rules_again_invites_once() {
    let (w, _sam, ana, space, everyone) = scene().await;
    let rules = [assign(space, RuleRole::Member, &[everyone])];
    let first = w.apply_group_rules().execute(ana, &rules).await;
    assert_eq!(first, Ok(vec![space]));
    let second = w.apply_group_rules().execute(ana, &rules).await;
    assert_eq!(second, Ok(Vec::new()));
}

#[tokio::test]
async fn an_existing_row_is_left_as_it_is() {
    let (w, sam, ana, space, everyone) = scene().await;
    let lee = w.user("lee@example.org").await;
    let zed = w.user("zed@example.org").await;
    // Ana is confirmed as a member with Edit; Lee was revoked; Zed's invitation is pending.
    w.join(
        space,
        sam,
        sam,
        ana,
        SpaceRole::Member,
        vec![(everyone, CollectionPermission::Edit)],
    )
    .await;
    w.join(space, sam, sam, lee, SpaceRole::Member, Vec::new())
        .await;
    w.offboard()
        .revoke(&actor(sam), space, lee)
        .await
        .expect("Lee is revoked");
    w.invite()
        .execute(
            &actor(sam),
            space,
            InviteInput {
                email: "zed@example.org".to_owned(),
                role: SpaceRole::Member,
                custom: CustomPermissions::NONE,
                grants: Vec::new(),
            },
        )
        .await
        .expect("Zed is invited");

    let rules = [assign(space, RuleRole::Admin, &[everyone])];
    for user in [ana, lee, zed] {
        let before = w.spaces.member(space, user).expect("a row");
        let invited = w
            .apply_group_rules()
            .execute(user, &rules)
            .await
            .expect("the rules apply");
        assert!(invited.is_empty());
        assert_eq!(w.spaces.member(space, user), Some(before));
    }
    let state = w.spaces.state(space);
    assert_eq!(
        state.access(ana, everyone).map(|a| a.edit),
        Some(true),
        "Ana keeps her Edit grant"
    );
    assert!(state.access(lee, everyone).is_none());
    assert!(state.access(zed, everyone).is_none());
}

#[tokio::test]
async fn a_space_that_is_gone_is_skipped_and_the_others_still_apply() {
    let (w, _sam, ana, space, _) = scene().await;
    let gone = SpaceId::random();
    let invited = w
        .apply_group_rules()
        .execute(
            ana,
            &[
                assign(gone, RuleRole::Member, &[]),
                assign(space, RuleRole::Member, &[]),
            ],
        )
        .await
        .expect("the rules apply");
    assert_eq!(invited, vec![space]);
    assert!(w.spaces.member(gone, ana).is_none());
}

#[tokio::test]
async fn no_assignments_change_nothing() {
    let (w, _sam, ana, space, _) = scene().await;
    let invited = w
        .apply_group_rules()
        .execute(ana, &[])
        .await
        .expect("the rules apply");
    assert!(invited.is_empty());
    assert!(w.spaces.member(space, ana).is_none());
}

#[tokio::test]
async fn a_space_awaiting_a_key_replacement_gets_the_invitation_without_grants() {
    let (w, sam, ana, space, everyone) = scene().await;
    let lee = w.user("lee@example.org").await;
    w.join(
        space,
        sam,
        sam,
        lee,
        SpaceRole::Member,
        vec![(everyone, CollectionPermission::Edit)],
    )
    .await;
    w.offboard()
        .revoke(&actor(sam), space, lee)
        .await
        .expect("Lee is revoked");
    assert!(w.spaces.state(space).space.keys_pending_since.is_some());

    let invited = w
        .apply_group_rules()
        .execute(ana, &[assign(space, RuleRole::Member, &[everyone])])
        .await
        .expect("the rules apply");
    assert_eq!(invited, vec![space]);
    assert!(w.spaces.state(space).access(ana, everyone).is_none());
}
