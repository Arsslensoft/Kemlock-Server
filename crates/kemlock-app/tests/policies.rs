//! Space policies over in-memory fakes: who may read and set them, what binds a person across their
//! spaces, the join check (two-step login, one space per member) and the Send rules.

mod chain_kit;
mod fakes;
mod send_fakes;
mod space_fakes;

use chain_kit::invited_chain;
use fakes::{FakeEnv, FakeStore, actor};
use kemlock_app::policies::{
    GetPolicies, JoinGuard, MemberSendRules, MyPolicies, PoliciesError, SetPolicies,
};
use kemlock_app::ports::{TwoFactor, TwoFactorMethod, TwoFactorRepo};
use kemlock_app::sends::{SendPolicies, SendRules};
use kemlock_app::spaces::SpaceChainRepo;
use kemlock_domain::policies::{MasterPasswordPolicy, SpacePolicies, TimeoutAction};
use kemlock_domain::spaces::SpaceRole;
use kemlock_domain::{SpaceId, UserId};
use send_fakes::FakePolicies;
use space_fakes::{SpaceWorld, Spaces};
use time::macros::datetime;

struct Policies {
    w: SpaceWorld,
    policies: FakePolicies,
}

impl Policies {
    fn new() -> Self {
        Policies {
            w: SpaceWorld::new(),
            policies: FakePolicies::new(),
        }
    }

    fn guard(&self) -> JoinGuard<Spaces, FakePolicies, FakeStore> {
        JoinGuard {
            spaces: self.w.spaces.clone(),
            policies: self.policies.clone(),
            two_factor: self.w.world.store.clone(),
        }
    }

    fn get(&self) -> GetPolicies<Spaces, FakePolicies> {
        GetPolicies {
            spaces: self.w.spaces.clone(),
            policies: self.policies.clone(),
        }
    }

    fn set(&self) -> SetPolicies<Spaces, FakePolicies, FakeStore, FakeEnv> {
        SetPolicies {
            spaces: self.w.spaces.clone(),
            policies: self.policies.clone(),
            events: self.w.world.store.clone(),
            clock: self.w.world.env.clone(),
        }
    }

    fn mine(&self) -> MyPolicies<Spaces, FakePolicies> {
        MyPolicies {
            spaces: self.w.spaces.clone(),
            policies: self.policies.clone(),
        }
    }

    fn send_rules(&self) -> MemberSendRules<Spaces, FakePolicies> {
        MemberSendRules {
            spaces: self.w.spaces.clone(),
            policies: self.policies.clone(),
        }
    }

    /// A space made by a fresh owner.
    async fn space(&self, owner_email: &str) -> (SpaceId, UserId) {
        let owner = self.w.user(owner_email).await;
        let (space, _) = self.w.make_space(owner).await;
        (space, owner)
    }

    /// `member` joins `space` through the real invite, accept and confirm steps.
    async fn join(&self, space: SpaceId, owner: UserId, member: UserId, role: SpaceRole) {
        self.w
            .join(space, owner, owner, member, role, Vec::new())
            .await;
    }

    /// Gives `user` a confirmed two-step method.
    async fn enrol_two_step(&self, user: UserId, enabled: bool) {
        TwoFactorRepo::put(
            &self.w.world.store,
            &TwoFactor {
                user,
                method: TwoFactorMethod::Totp,
                sealed_secret: vec![1; 40],
                enabled,
                created_at: datetime!(2026-03-01 12:00 UTC),
            },
        )
        .await
        .expect("the enrolment is stored");
    }
}

fn strict() -> SpacePolicies {
    SpacePolicies {
        two_step: true,
        single_space: true,
        ..SpacePolicies::default()
    }
}

// ---- reading and setting ----

#[tokio::test]
async fn an_owner_sets_a_spaces_policies_and_it_is_logged() {
    let p = Policies::new();
    let (space, owner) = p.space("sam@example.org").await;
    let new = SpacePolicies {
        master_password: Some(MasterPasswordPolicy::fourteen_characters()),
        always_show_email: true,
        ..SpacePolicies::default()
    };

    let stored = p
        .set()
        .execute(&actor(owner), space, new.clone())
        .await
        .expect("an owner sets them");
    assert_eq!(stored.policies, new);
    assert_eq!(stored.updated_by, Some(owner));
    assert!(stored.updated_at.is_some());
    assert_eq!(p.policies.stored(space), Some(stored.clone()));
    assert_eq!(
        p.get().execute(&actor(owner), space).await.expect("read"),
        stored
    );
    assert!(
        p.w.world
            .store
            .events()
            .iter()
            .any(|e| e.action == "space.policies.update" && e.actor == Some(owner))
    );
}

#[tokio::test]
async fn an_admin_may_set_them_and_a_member_may_only_read_them() {
    let p = Policies::new();
    let (space, owner) = p.space("sam@example.org").await;
    let admin = p.w.user("bob@example.org").await;
    let member = p.w.user("ana@example.org").await;
    p.join(space, owner, admin, SpaceRole::Admin).await;
    p.join(space, owner, member, SpaceRole::Member).await;

    p.set()
        .execute(&actor(admin), space, strict())
        .await
        .expect("an admin sets them");

    let refused = p
        .set()
        .execute(&actor(member), space, SpacePolicies::default())
        .await;
    assert!(matches!(refused, Err(PoliciesError::Forbidden(_))));
    assert_eq!(
        p.policies.stored(space).expect("still set").policies,
        strict()
    );

    let read = p
        .get()
        .execute(&actor(member), space)
        .await
        .expect("a member reads them");
    assert_eq!(read.policies, strict());
}

#[tokio::test]
async fn someone_outside_the_space_or_not_yet_confirmed_learns_nothing() {
    let p = Policies::new();
    let (space, owner) = p.space("sam@example.org").await;
    let stranger = p.w.user("eve@example.org").await;
    let invited = p.w.user("ana@example.org").await;
    p.w.invite()
        .execute(
            &actor(owner),
            space,
            kemlock_app::spaces::InviteInput {
                email: "ana@example.org".to_owned(),
                role: SpaceRole::Member,
                custom: Default::default(),
                grants: Vec::new(),
            },
        )
        .await
        .expect("invited");

    for user in [stranger, invited] {
        assert_eq!(
            p.get().execute(&actor(user), space).await.err(),
            Some(PoliciesError::NotFound)
        );
        assert_eq!(
            p.set().execute(&actor(user), space, strict()).await.err(),
            Some(PoliciesError::NotFound)
        );
    }
    assert_eq!(
        p.get()
            .execute(&actor(owner), SpaceId::random())
            .await
            .err(),
        Some(PoliciesError::NotFound)
    );
    assert_eq!(p.policies.stored(space), None);
}

#[tokio::test]
async fn nonsense_settings_are_refused_before_they_are_stored() {
    let p = Policies::new();
    let (space, owner) = p.space("sam@example.org").await;
    let nonsense = SpacePolicies {
        master_password: Some(MasterPasswordPolicy {
            min_length: Some(500),
            ..MasterPasswordPolicy::default()
        }),
        ..SpacePolicies::default()
    };
    let refused = p.set().execute(&actor(owner), space, nonsense).await;
    assert!(matches!(refused, Err(PoliciesError::Invalid(_))));
    assert_eq!(p.policies.stored(space), None);
}

// ---- what binds a person ----

#[tokio::test]
async fn my_policies_fold_every_space_and_spare_owners_and_admins() {
    let p = Policies::new();
    let (first, sam) = p.space("sam@example.org").await;
    let (second, zed) = p.space("zed@example.org").await;
    let ana = p.w.user("ana@example.org").await;
    p.join(first, sam, ana, SpaceRole::Member).await;
    p.join(second, zed, ana, SpaceRole::Admin).await;

    p.policies.set(
        first,
        SpacePolicies {
            require_sso: true,
            master_password: Some(MasterPasswordPolicy {
                min_length: Some(14),
                ..MasterPasswordPolicy::default()
            }),
            session_timeout_minutes: Some(60),
            session_timeout_action: Some(TimeoutAction::Lock),
            disable_export: true,
            ..SpacePolicies::default()
        },
    );
    p.policies.set(
        second,
        SpacePolicies {
            require_sso: true,
            two_step: true,
            master_password: Some(MasterPasswordPolicy {
                min_complexity: Some(3),
                ..MasterPasswordPolicy::default()
            }),
            session_timeout_minutes: Some(30),
            ..SpacePolicies::default()
        },
    );

    let effective = p.mine().execute(&actor(ana)).await.expect("what binds ana");
    // Require SSO binds her through the first space only; she is an admin of the second, so its
    // two-step requirement doesn't bind her.
    assert!(effective.require_sso);
    assert!(!effective.two_step);
    assert!(effective.disable_export);
    let mp = effective.master_password.expect("master password rules");
    assert_eq!(mp.min_length, Some(14));
    assert_eq!(mp.min_complexity, Some(3));
    assert_eq!(effective.session_timeout_minutes, Some(30));

    // The owner of the first space is exempt from its Require SSO.
    let sams = p.mine().execute(&actor(sam)).await.expect("what binds sam");
    assert!(!sams.require_sso);
    assert!(sams.disable_export);
}

#[tokio::test]
async fn someone_in_no_space_is_bound_by_nothing() {
    let p = Policies::new();
    let loner = p.w.user("ana@example.org").await;
    let effective = p
        .mine()
        .execute(&actor(loner))
        .await
        .expect("nothing binds");
    assert_eq!(effective, Default::default());
}

#[tokio::test]
async fn the_send_rules_follow_the_members_spaces() {
    let p = Policies::new();
    let (space, owner) = p.space("sam@example.org").await;
    let member = p.w.user("ana@example.org").await;
    p.join(space, owner, member, SpaceRole::Member).await;
    p.policies.set(
        space,
        SpacePolicies {
            always_show_email: true,
            disable_send: true,
            ..SpacePolicies::default()
        },
    );

    assert_eq!(
        p.send_rules().send_rules(member).await,
        Ok(SendRules {
            disabled: true,
            force_email: true,
        })
    );
    // The owner is exempt; a person in no space is bound by nothing.
    assert_eq!(
        p.send_rules().send_rules(owner).await,
        Ok(SendRules::default())
    );
    let loner = p.w.user("zed@example.org").await;
    assert_eq!(
        p.send_rules().send_rules(loner).await,
        Ok(SendRules::default())
    );
}

// ---- the join check ----

#[tokio::test]
async fn a_space_that_requires_two_step_refuses_a_member_without_it() {
    let p = Policies::new();
    let (space, _owner) = p.space("sam@example.org").await;
    let ana = p.w.user("ana@example.org").await;
    p.policies.set(
        space,
        SpacePolicies {
            two_step: true,
            ..SpacePolicies::default()
        },
    );

    assert_eq!(
        p.guard().check(ana, space, SpaceRole::Member).await,
        Err(PoliciesError::TwoStepRequired)
    );
    // A method that is not confirmed yet doesn't count.
    p.enrol_two_step(ana, false).await;
    assert_eq!(
        p.guard().check(ana, space, SpaceRole::Custom).await,
        Err(PoliciesError::TwoStepRequired)
    );
    p.enrol_two_step(ana, true).await;
    assert_eq!(p.guard().check(ana, space, SpaceRole::Member).await, Ok(()));
}

#[tokio::test]
async fn owners_and_admins_join_whatever_the_policies_say() {
    let p = Policies::new();
    let (space, _owner) = p.space("sam@example.org").await;
    let ana = p.w.user("ana@example.org").await;
    p.policies.set(space, strict());
    for role in [SpaceRole::Owner, SpaceRole::Admin] {
        assert_eq!(p.guard().check(ana, space, role).await, Ok(()), "{role:?}");
    }
    assert_eq!(
        p.guard().check(ana, space, SpaceRole::Member).await,
        Err(PoliciesError::TwoStepRequired)
    );
}

#[tokio::test]
async fn one_space_per_member_refuses_a_second_space() {
    let p = Policies::new();
    let (first, sam) = p.space("sam@example.org").await;
    let (second, _zed) = p.space("zed@example.org").await;
    let ana = p.w.user("ana@example.org").await;
    p.policies.set(
        second,
        SpacePolicies {
            single_space: true,
            ..SpacePolicies::default()
        },
    );

    // Not in another space yet: fine.
    assert_eq!(
        p.guard().check(ana, second, SpaceRole::Member).await,
        Ok(())
    );
    p.join(first, sam, ana, SpaceRole::Member).await;
    assert_eq!(
        p.guard().check(ana, second, SpaceRole::Member).await,
        Err(PoliciesError::SingleSpace)
    );
    // An admin of the single-space one is exempt.
    assert_eq!(p.guard().check(ana, second, SpaceRole::Admin).await, Ok(()));
}

#[tokio::test]
async fn a_space_that_allows_one_space_per_member_bars_its_members_from_others() {
    let p = Policies::new();
    let (first, sam) = p.space("sam@example.org").await;
    let (second, _zed) = p.space("zed@example.org").await;
    let ana = p.w.user("ana@example.org").await;
    let bob = p.w.user("bob@example.org").await;
    p.policies.set(
        first,
        SpacePolicies {
            single_space: true,
            ..SpacePolicies::default()
        },
    );
    p.join(first, sam, ana, SpaceRole::Member).await;
    p.join(first, sam, bob, SpaceRole::Admin).await;

    // Ana is bound by the first space and may not join the second, which has no policy at all.
    assert_eq!(
        p.guard().check(ana, second, SpaceRole::Member).await,
        Err(PoliciesError::OtherSpaceSingle)
    );
    // Bob is an admin of the first, so it doesn't bind him.
    assert_eq!(
        p.guard().check(bob, second, SpaceRole::Member).await,
        Ok(())
    );
}

#[tokio::test]
async fn an_invitation_or_a_revoked_membership_is_not_being_in_a_space() {
    let p = Policies::new();
    let (first, sam) = p.space("sam@example.org").await;
    let (second, _zed) = p.space("zed@example.org").await;
    let ana = p.w.user("ana@example.org").await;
    p.policies.set(
        first,
        SpacePolicies {
            single_space: true,
            ..SpacePolicies::default()
        },
    );
    p.policies.set(
        second,
        SpacePolicies {
            single_space: true,
            ..SpacePolicies::default()
        },
    );

    p.w.invite()
        .execute(
            &actor(sam),
            first,
            kemlock_app::spaces::InviteInput {
                email: "ana@example.org".to_owned(),
                role: SpaceRole::Member,
                custom: Default::default(),
                grants: Vec::new(),
            },
        )
        .await
        .expect("invited");
    // Invited to the first, she may still join the second.
    assert_eq!(
        p.guard().check(ana, second, SpaceRole::Member).await,
        Ok(())
    );

    // Having accepted, she is in it.
    p.w.accept()
        .execute(&actor(ana), first)
        .await
        .expect("accepted");
    assert_eq!(
        p.guard().check(ana, second, SpaceRole::Member).await,
        Err(PoliciesError::SingleSpace)
    );
}

#[tokio::test]
async fn a_space_without_policies_lets_anyone_join() {
    let p = Policies::new();
    let (first, sam) = p.space("sam@example.org").await;
    let (second, _zed) = p.space("zed@example.org").await;
    let ana = p.w.user("ana@example.org").await;
    p.join(first, sam, ana, SpaceRole::Member).await;
    assert_eq!(
        p.guard().check(ana, second, SpaceRole::Member).await,
        Ok(())
    );
}

// ---- spaces with a chain ----

/// Gives `space` a chain in which `sam` made it and invited `ana`, and in which a `confirm` record
/// confirmed her only when `confirmed` says so. The members table is left as it is.
async fn chain_of(p: &Policies, space: SpaceId, sam: UserId, ana: UserId, confirmed: bool) {
    p.w.spaces
        .chain_append(space, invited_chain(space, sam, ana, confirmed))
        .await
        .expect("the chain is stored");
}

#[tokio::test]
async fn a_member_the_chain_confirms_is_in_a_chained_space() {
    let p = Policies::new();
    let (first, sam) = p.space("sam@example.org").await;
    let (second, _zed) = p.space("zed@example.org").await;
    let ana = p.w.user("ana@example.org").await;
    p.policies.set(
        second,
        SpacePolicies {
            single_space: true,
            ..SpacePolicies::default()
        },
    );
    p.join(first, sam, ana, SpaceRole::Member).await;
    chain_of(&p, first, sam, ana, true).await;
    assert_eq!(
        p.guard().check(ana, second, SpaceRole::Member).await,
        Err(PoliciesError::SingleSpace)
    );
}

#[tokio::test]
async fn a_row_confirmed_without_a_confirm_record_is_not_in_a_chained_space() {
    let p = Policies::new();
    let (first, sam) = p.space("sam@example.org").await;
    let (second, _zed) = p.space("zed@example.org").await;
    let ana = p.w.user("ana@example.org").await;
    p.policies.set(
        second,
        SpacePolicies {
            single_space: true,
            ..SpacePolicies::default()
        },
    );
    // The table says Ana is confirmed in the first space, as an outside change can leave it, but
    // its chain invited her and never confirmed her.
    p.join(first, sam, ana, SpaceRole::Member).await;
    assert_eq!(
        p.guard().check(ana, second, SpaceRole::Member).await,
        Err(PoliciesError::SingleSpace)
    );
    chain_of(&p, first, sam, ana, false).await;
    assert_eq!(
        p.guard().check(ana, second, SpaceRole::Member).await,
        Ok(())
    );
}

#[tokio::test]
async fn a_space_without_a_chain_counts_its_confirmed_rows_as_before() {
    let p = Policies::new();
    let (first, sam) = p.space("sam@example.org").await;
    let (second, _zed) = p.space("zed@example.org").await;
    let ana = p.w.user("ana@example.org").await;
    p.policies.set(
        first,
        SpacePolicies {
            single_space: true,
            ..SpacePolicies::default()
        },
    );
    p.join(first, sam, ana, SpaceRole::Member).await;
    assert_eq!(
        p.guard().check(ana, second, SpaceRole::Member).await,
        Err(PoliciesError::OtherSpaceSingle)
    );
}

#[tokio::test]
async fn a_chained_space_takes_its_policies_from_its_chain_only() {
    let p = Policies::new();
    let (space, sam) = p.space("sam@example.org").await;
    let ana = p.w.user("ana@example.org").await;
    chain_of(&p, space, sam, ana, false).await;
    let refused = p
        .set()
        .execute(&actor(sam), space, strict())
        .await
        .expect_err("a route that sets policies with no record is refused");
    assert!(matches!(refused, PoliciesError::Invalid(_)), "{refused:?}");
    assert_eq!(p.policies.stored(space), None);

    // A space with no chain is set as before.
    let (plain, zed) = p.space("zed@example.org").await;
    p.set()
        .execute(&actor(zed), plain, strict())
        .await
        .expect("an unchained space takes the route");
}
