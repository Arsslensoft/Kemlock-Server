//! Account recovery enrolment of a space over in-memory fakes: who may enrol, what the chain must
//! say first, and who may recover whom.

mod chain_kit;
mod fakes;
mod space_fakes;

use chain_kit::{Chain, Person, append_of};
use fakes::{FakeEnv, FakeStore, actor};
use kemlock_app::spaces::{
    RECOVERY_BOX_LEN, RecoveryError, SpaceChainRepo, SpaceRecovery, SpaceRecoveryRepo,
};
use kemlock_crypto::space_chain::{Body, Policies, Role};
use kemlock_domain::spaces::SpaceRole;
use kemlock_domain::{SpaceId, UserId};
use space_fakes::{SpaceWorld, Spaces};

/// The `seq` of the `recovery-key` record in the chain below.
const KEY_SEQ: u64 = 5;

struct Rig {
    w: SpaceWorld,
    space: SpaceId,
    owner: UserId,
    admin: UserId,
    member: UserId,
    /// Holds the recovery key the chain records.
    recovery: Person,
}

impl Rig {
    fn recovery(&self) -> SpaceRecovery<Spaces, FakeStore, FakeEnv> {
        SpaceRecovery {
            spaces: self.w.spaces.clone(),
            events: self.w.world.store.clone(),
            clock: self.w.world.env.clone(),
        }
    }

    /// A box of the right shape: what the real one is sealed to is not the server's to check.
    fn boxed() -> Vec<u8> {
        let mut sealed = vec![7u8; RECOVERY_BOX_LEN];
        sealed[0] = 1;
        sealed
    }

    /// A space with an Owner, an Admin and a Member, all confirmed by the chain and the table.
    /// With `on`, the chain sets a recovery key (record 5) and turns `accountRecovery` on (6).
    async fn new(on: bool) -> Rig {
        let w = SpaceWorld::new();
        let owner = w.user("sam@example.org").await;
        let admin = w.user("bob@example.org").await;
        let member = w.user("ana@example.org").await;
        let (space, _) = w.make_space(owner).await;
        w.join(space, owner, owner, admin, SpaceRole::Admin, Vec::new())
            .await;
        w.join(space, owner, owner, member, SpaceRole::Member, Vec::new())
            .await;

        let sam = Person::new(*owner.0.as_bytes(), 1);
        let bob = Person::new(*admin.0.as_bytes(), 2);
        let ana = Person::new(*member.0.as_bytes(), 3);
        let recovery = Person::new([0x77; 16], 4);
        let mut chain = Chain::new(*space.0.as_bytes(), 0);
        let mut steps = vec![
            chain.create(&sam, [9; 16]),
            chain.invite(&sam, bob.id, Role::Admin),
            chain.confirm(&sam, &bob),
            chain.invite(&sam, ana.id, Role::Member),
            chain.confirm(&sam, &ana),
        ];
        if on {
            steps.push(chain.record(
                &sam,
                Body::RecoveryKey {
                    key: recovery.bundle.kx1_public.as_bytes().to_vec(),
                },
            ));
            steps.push(chain.record(
                &sam,
                Body::Policies {
                    policies: Policies {
                        account_recovery: true,
                        ..Policies::default()
                    },
                },
            ));
        }
        let refs: Vec<&chain_kit::Step> = steps.iter().collect();
        w.spaces
            .chain_append(space, append_of(space, &sam, &refs))
            .await
            .expect("the chain is stored");
        Rig {
            w,
            space,
            owner,
            admin,
            member,
            recovery,
        }
    }

    /// The Owner changes the recovery key: record 7, which makes earlier boxes stale.
    async fn rotate_recovery_key(&self) {
        let sam = Person::new(*self.owner.0.as_bytes(), 1);
        let (_, state) = self
            .w
            .spaces
            .chain_state(self.space)
            .await
            .expect("the chain reads")
            .expect("there is a chain");
        // The state names the head; a new key is another person's key.
        assert_eq!(state.recovery_key_seq, Some(KEY_SEQ));
        let records = self
            .w
            .spaces
            .chain_records(self.space, 0)
            .await
            .expect("the records read");
        let mut chain = Chain::new(*self.space.0.as_bytes(), 0);
        chain.head = records.last().map(|r| (r.seq, r.link));
        let other = Person::new([0x78; 16], 5);
        let step = chain.record(
            &sam,
            Body::RecoveryKey {
                key: other.bundle.kx1_public.as_bytes().to_vec(),
            },
        );
        let mut append = append_of(self.space, &sam, &[&step]);
        append.expected = self
            .w
            .spaces
            .chain_head(self.space)
            .await
            .expect("the head reads");
        append.records[0].seq = u64::try_from(records.len()).expect("a few records");
        self.w
            .spaces
            .chain_append(self.space, append)
            .await
            .expect("the new key is stored");
    }
}

#[tokio::test]
async fn the_chains_state_names_the_record_that_set_the_recovery_key() {
    let r = Rig::new(true).await;
    let (_, state) =
        r.w.spaces
            .chain_state(r.space)
            .await
            .expect("the chain reads")
            .expect("there is a chain");
    assert_eq!(state.recovery_key_seq, Some(KEY_SEQ));
    assert!(state.policies.account_recovery);
    assert_eq!(
        state.recovery_key.as_deref(),
        Some(r.recovery.bundle.kx1_public.as_bytes().as_slice())
    );
}

#[tokio::test]
async fn every_confirmed_member_enrols_an_owner_included_and_a_new_box_replaces_the_old() {
    let r = Rig::new(true).await;
    for user in [r.owner, r.admin, r.member] {
        r.recovery()
            .enrol(&actor(user), r.space, KEY_SEQ, Rig::boxed())
            .await
            .expect("a confirmed member enrols");
        let stored =
            r.w.spaces
                .recovery_box(r.space, user)
                .await
                .expect("it reads")
                .expect("the box is kept");
        assert_eq!(stored.key_seq, KEY_SEQ);
        assert_eq!(stored.sealed, Rig::boxed());
    }
    let mut newer = Rig::boxed();
    newer[1] = 9;
    r.recovery()
        .enrol(&actor(r.member), r.space, KEY_SEQ, newer.clone())
        .await
        .expect("enrolling again replaces");
    assert_eq!(
        r.w.spaces
            .recovery_box(r.space, r.member)
            .await
            .expect("it reads")
            .expect("the box is kept")
            .sealed,
        newer
    );
    assert!(
        r.w.world
            .store
            .events()
            .iter()
            .any(|e| e.action == "space.recovery.enrol" && e.actor == Some(r.owner))
    );
}

#[tokio::test]
async fn enrolling_is_refused_while_the_policy_is_off() {
    let r = Rig::new(false).await;
    assert_eq!(
        r.recovery()
            .enrol(&actor(r.member), r.space, KEY_SEQ, Rig::boxed())
            .await,
        Err(RecoveryError::NotEnabled)
    );
}

#[tokio::test]
async fn enrolling_under_another_recovery_key_record_is_stale() {
    let r = Rig::new(true).await;
    assert_eq!(
        r.recovery()
            .enrol(&actor(r.member), r.space, KEY_SEQ - 1, Rig::boxed())
            .await,
        Err(RecoveryError::Stale {
            current: Some(KEY_SEQ)
        })
    );
    assert_eq!(
        r.w.spaces
            .recovery_box(r.space, r.member)
            .await
            .expect("it reads"),
        None
    );
}

#[tokio::test]
async fn a_box_of_another_shape_is_refused() {
    let r = Rig::new(true).await;
    let mut short = Rig::boxed();
    short.pop();
    let mut versionless = Rig::boxed();
    versionless[0] = 2;
    for bad in [short, versionless, Vec::new()] {
        assert!(matches!(
            r.recovery()
                .enrol(&actor(r.member), r.space, KEY_SEQ, bad)
                .await,
            Err(RecoveryError::Invalid(_))
        ));
    }
}

#[tokio::test]
async fn a_stranger_is_told_there_is_no_such_space() {
    let r = Rig::new(true).await;
    let zed = r.w.user("zed@example.org").await;
    assert_eq!(
        r.recovery()
            .enrol(&actor(zed), r.space, KEY_SEQ, Rig::boxed())
            .await,
        Err(RecoveryError::NotFound)
    );
    assert_eq!(
        r.recovery().withdraw(&actor(zed), r.space).await,
        Err(RecoveryError::NotFound)
    );
    assert_eq!(
        r.recovery().fetch(&actor(zed), r.space, r.member).await,
        Err(RecoveryError::NotFound)
    );
}

#[tokio::test]
async fn an_owner_recovers_anyone() {
    let r = Rig::new(true).await;
    for user in [r.admin, r.member] {
        r.recovery()
            .enrol(&actor(user), r.space, KEY_SEQ, Rig::boxed())
            .await
            .expect("they enrol");
        let found = r
            .recovery()
            .fetch(&actor(r.owner), r.space, user)
            .await
            .expect("an owner recovers anyone");
        assert_eq!(found.sealed, Rig::boxed());
        assert_eq!(found.key_seq, KEY_SEQ);
        assert!(!found.stale);
    }
    assert!(
        r.w.world
            .store
            .events()
            .iter()
            .any(|e| e.action == "space.recovery.read" && e.actor == Some(r.owner))
    );
}

#[tokio::test]
async fn an_admin_recovers_a_member_but_not_an_owner() {
    let r = Rig::new(true).await;
    for user in [r.owner, r.member] {
        r.recovery()
            .enrol(&actor(user), r.space, KEY_SEQ, Rig::boxed())
            .await
            .expect("they enrol");
    }
    assert!(
        r.recovery()
            .fetch(&actor(r.admin), r.space, r.member)
            .await
            .is_ok()
    );
    assert_eq!(
        r.recovery().fetch(&actor(r.admin), r.space, r.owner).await,
        Err(RecoveryError::Forbidden)
    );
}

#[tokio::test]
async fn a_member_recovers_no_one() {
    let r = Rig::new(true).await;
    r.recovery()
        .enrol(&actor(r.admin), r.space, KEY_SEQ, Rig::boxed())
        .await
        .expect("they enrol");
    assert_eq!(
        r.recovery().fetch(&actor(r.member), r.space, r.admin).await,
        Err(RecoveryError::Forbidden)
    );
}

#[tokio::test]
async fn nothing_enrolled_is_not_found() {
    let r = Rig::new(true).await;
    assert_eq!(
        r.recovery().fetch(&actor(r.owner), r.space, r.member).await,
        Err(RecoveryError::NotFound)
    );
}

#[tokio::test]
async fn withdrawing_removes_the_box_and_is_not_an_error_without_one() {
    let r = Rig::new(true).await;
    r.recovery()
        .enrol(&actor(r.member), r.space, KEY_SEQ, Rig::boxed())
        .await
        .expect("they enrol");
    r.recovery()
        .withdraw(&actor(r.member), r.space)
        .await
        .expect("they withdraw");
    assert_eq!(
        r.recovery().fetch(&actor(r.owner), r.space, r.member).await,
        Err(RecoveryError::NotFound)
    );
    r.recovery()
        .withdraw(&actor(r.member), r.space)
        .await
        .expect("withdrawing nothing is fine");
}

#[tokio::test]
async fn boxes_stay_after_the_recovery_key_changes_and_are_served_stale() {
    let r = Rig::new(true).await;
    r.recovery()
        .enrol(&actor(r.member), r.space, KEY_SEQ, Rig::boxed())
        .await
        .expect("they enrol");
    r.rotate_recovery_key().await;
    let found = r
        .recovery()
        .fetch(&actor(r.owner), r.space, r.member)
        .await
        .expect("the earlier box is still served");
    assert!(found.stale);
    assert_eq!(found.key_seq, KEY_SEQ);
    // And enrolling under the key that was replaced is refused.
    assert_eq!(
        r.recovery()
            .enrol(&actor(r.member), r.space, KEY_SEQ, Rig::boxed())
            .await,
        Err(RecoveryError::Stale {
            current: Some(KEY_SEQ + 2)
        })
    );
}
