//! Emergency access: invite, accept, confirm, request, wait, release.

mod fakes;

use fakes::unlock::*;
use fakes::*;
use kemlock_app::emergency::EmergencyEvent;
use kemlock_app::{Actor, AppError};
use kemlock_domain::UserId;
use kemlock_domain::unlock::{
    EmergencyGrant, EmergencyKind, EmergencyState, MAX_GRANTS_PER_GRANTOR, SEALED_BOX_OVERHEAD,
};
use time::Duration;

const GRANTOR: &str = "sam@example.org";
const CONTACT: &str = "kim@example.org";

struct Scene {
    world: World,
    notices: FakeNotices,
    sam: Actor,
    kim: Actor,
    sam_id: UserId,
    kim_id: UserId,
}

async fn scene() -> Scene {
    let world = World::new().with_signups();
    let sam_id = make_user(&world, GRANTOR).await;
    let kim_id = make_user(&world, CONTACT).await;
    Scene {
        sam: actor(sam_id),
        kim: actor(kim_id),
        sam_id,
        kim_id,
        notices: FakeNotices::default(),
        world,
    }
}

fn sealed() -> Vec<u8> {
    vec![0x77; SEALED_BOX_OVERHEAD + 64]
}

impl Scene {
    async fn invite(&self, kind: EmergencyKind, days: u32) -> EmergencyGrant {
        emergency_access(&self.world, &self.notices)
            .invite(&self.sam, CONTACT, kind, days)
            .await
            .expect("invites")
    }

    /// A grant that is confirmed, ready for the contact to ask.
    async fn confirmed(&self, kind: EmergencyKind, days: u32) -> EmergencyGrant {
        let grant = self.invite(kind, days).await;
        let access = emergency_access(&self.world, &self.notices);
        access.accept(&self.kim, grant.id).await.expect("accepts");
        access
            .confirm(&self.sam, grant.id, sealed())
            .await
            .expect("confirms")
    }
}

#[tokio::test]
async fn the_whole_path_ends_with_the_contact_holding_the_sealed_key() {
    let s = scene().await;
    let access = emergency_access(&s.world, &s.notices);

    let invited = s.invite(EmergencyKind::Takeover, 7).await;
    assert_eq!(invited.state, EmergencyState::Invited);
    assert_eq!(invited.grantor, s.sam_id);
    assert_eq!(invited.wait_days, 7);

    let accepted = access.accept(&s.kim, invited.id).await.expect("accepts");
    assert_eq!(accepted.state, EmergencyState::Accepted);
    assert_eq!(accepted.grantee, Some(s.kim_id));

    // The grantor now sees the contact's keys to check and seal to.
    let overview = access.list(&s.sam).await.expect("lists");
    let view = &overview.trusted_contacts[0];
    let keys = view.contact_keys.as_ref().expect("the contact's keys");
    assert_eq!(keys.public_bundle, bundle(s.kim_id));

    let confirmed = access
        .confirm(&s.sam, invited.id, sealed())
        .await
        .expect("confirms");
    assert_eq!(confirmed.state, EmergencyState::Confirmed);

    let started = access.initiate(&s.kim, invited.id).await.expect("asks");
    assert_eq!(started.state, EmergencyState::RecoveryInitiated);
    // Nothing is released while the wait runs.
    assert_eq!(
        access.release_key(&s.kim, invited.id).await.map(|_| ()),
        Err(AppError::Forbidden)
    );

    s.world.env.clock.advance(Duration::days(7));
    let approved = approve_due(&s.world, &s.notices)
        .execute()
        .await
        .expect("the timer runs");
    assert_eq!(approved, 1);
    assert_eq!(
        s.world.store.grant_of(invited.id).expect("stored").state,
        EmergencyState::Approved
    );

    let release = access
        .release_key(&s.kim, invited.id)
        .await
        .expect("released");
    assert_eq!(release.sealed_key, sealed());
    assert_eq!(release.kind, EmergencyKind::Takeover);
    assert_eq!(release.grantor, s.sam_id);
}

#[tokio::test]
async fn each_step_tells_the_other_party() {
    let s = scene().await;
    let access = emergency_access(&s.world, &s.notices);
    let grant = s.confirmed(EmergencyKind::View, 3).await;
    access.initiate(&s.kim, grant.id).await.expect("asks");
    s.world.env.clock.advance(Duration::days(3));
    approve_due(&s.world, &s.notices)
        .execute()
        .await
        .expect("the timer runs");

    let sent: Vec<(String, EmergencyEvent)> = s
        .notices
        .emergency()
        .into_iter()
        .map(|n| (n.to.as_str().to_owned(), n.event))
        .collect();
    assert_eq!(
        sent,
        vec![
            (CONTACT.to_owned(), EmergencyEvent::Invited),
            (GRANTOR.to_owned(), EmergencyEvent::Accepted),
            (CONTACT.to_owned(), EmergencyEvent::Confirmed),
            (GRANTOR.to_owned(), EmergencyEvent::RecoveryInitiated),
            (CONTACT.to_owned(), EmergencyEvent::Approved),
            (GRANTOR.to_owned(), EmergencyEvent::Approved),
        ]
    );
}

#[tokio::test]
async fn the_timer_waits_for_the_wait_time() {
    let s = scene().await;
    let access = emergency_access(&s.world, &s.notices);
    let grant = s.confirmed(EmergencyKind::View, 7).await;
    access.initiate(&s.kim, grant.id).await.expect("asks");

    s.world
        .env
        .clock
        .advance(Duration::days(7) - Duration::seconds(1));
    assert_eq!(approve_due(&s.world, &s.notices).execute().await, Ok(0));
    assert_eq!(
        s.world.store.grant_of(grant.id).expect("stored").state,
        EmergencyState::RecoveryInitiated
    );

    s.world.env.clock.advance(Duration::seconds(1));
    assert_eq!(approve_due(&s.world, &s.notices).execute().await, Ok(1));
    // A second run has nothing left to approve.
    assert_eq!(approve_due(&s.world, &s.notices).execute().await, Ok(0));
}

#[tokio::test]
async fn the_grantors_refusal_stops_the_timer() {
    let s = scene().await;
    let access = emergency_access(&s.world, &s.notices);
    let grant = s.confirmed(EmergencyKind::Takeover, 7).await;
    access.initiate(&s.kim, grant.id).await.expect("asks");
    s.world.env.clock.advance(Duration::days(3));

    let rejected = access.reject(&s.sam, grant.id).await.expect("refuses");
    assert_eq!(rejected.state, EmergencyState::Rejected);

    s.world.env.clock.advance(Duration::days(30));
    assert_eq!(approve_due(&s.world, &s.notices).execute().await, Ok(0));
    assert_eq!(
        access.release_key(&s.kim, grant.id).await.map(|_| ()),
        Err(AppError::Forbidden)
    );
    assert!(
        s.notices
            .emergency()
            .iter()
            .any(|n| n.event == EmergencyEvent::Rejected && n.to.as_str() == CONTACT)
    );

    // The contact may ask again, and the wait starts over.
    access.initiate(&s.kim, grant.id).await.expect("asks again");
    s.world.env.clock.advance(Duration::days(6));
    assert_eq!(approve_due(&s.world, &s.notices).execute().await, Ok(0));
}

#[tokio::test]
async fn the_grantor_can_approve_early() {
    let s = scene().await;
    let access = emergency_access(&s.world, &s.notices);
    let grant = s.confirmed(EmergencyKind::View, 30).await;
    access.initiate(&s.kim, grant.id).await.expect("asks");

    access.approve(&s.sam, grant.id).await.expect("approves");

    let release = access
        .release_key(&s.kim, grant.id)
        .await
        .expect("released");
    assert_eq!(release.sealed_key, sealed());
}

#[tokio::test]
async fn an_approval_can_be_taken_back_before_the_key_is_fetched() {
    let s = scene().await;
    let access = emergency_access(&s.world, &s.notices);
    let grant = s.confirmed(EmergencyKind::View, 1).await;
    access.initiate(&s.kim, grant.id).await.expect("asks");
    access.approve(&s.sam, grant.id).await.expect("approves");

    access
        .reject(&s.sam, grant.id)
        .await
        .expect("takes it back");

    assert_eq!(
        access.release_key(&s.kim, grant.id).await.map(|_| ()),
        Err(AppError::Forbidden)
    );
}

#[tokio::test]
async fn invitations_are_checked() {
    let s = scene().await;
    let access = emergency_access(&s.world, &s.notices);

    for days in [0, 91] {
        let result = access
            .invite(&s.sam, CONTACT, EmergencyKind::View, days)
            .await;
        assert!(matches!(result, Err(AppError::Invalid(_))), "{days} days");
    }
    let yourself = access
        .invite(&s.sam, "  SAM@example.org ", EmergencyKind::View, 7)
        .await;
    assert!(matches!(yourself, Err(AppError::Invalid(_))));
    let nonsense = access.invite(&s.sam, "nope", EmergencyKind::View, 7).await;
    assert!(matches!(nonsense, Err(AppError::Invalid(_))));
    assert!(s.notices.emergency().is_empty());

    s.invite(EmergencyKind::View, 7).await;
    let twice = access
        .invite(&s.sam, CONTACT, EmergencyKind::Takeover, 14)
        .await;
    assert_eq!(twice, Err(AppError::Duplicate));
}

#[tokio::test]
async fn an_account_names_a_limited_number_of_contacts() {
    let s = scene().await;
    let access = emergency_access(&s.world, &s.notices);
    for i in 0..MAX_GRANTS_PER_GRANTOR {
        access
            .invite(
                &s.sam,
                &format!("friend{i}@example.org"),
                EmergencyKind::View,
                7,
            )
            .await
            .expect("inside the limit");
    }
    let over = access
        .invite(&s.sam, "one-more@example.org", EmergencyKind::View, 7)
        .await;
    assert!(matches!(over, Err(AppError::Invalid(_))));
}

#[tokio::test]
async fn only_the_named_account_can_accept() {
    let s = scene().await;
    let grant = s.invite(EmergencyKind::View, 7).await;
    let access = emergency_access(&s.world, &s.notices);
    let other = make_user(&s.world, "lee@example.org").await;

    assert_eq!(
        access.accept(&actor(other), grant.id).await.map(|_| ()),
        Err(AppError::NotFound)
    );
    // The grantor can't accept their own invitation either.
    assert_eq!(
        access.accept(&s.sam, grant.id).await.map(|_| ()),
        Err(AppError::NotFound)
    );
    access.accept(&s.kim, grant.id).await.expect("accepts");
    let twice = access.accept(&s.kim, grant.id).await;
    assert!(matches!(twice, Err(AppError::Invalid(_))));
}

#[tokio::test]
async fn only_the_grantor_confirms_and_the_box_must_fit() {
    let s = scene().await;
    let grant = s.invite(EmergencyKind::View, 7).await;
    let access = emergency_access(&s.world, &s.notices);
    access.accept(&s.kim, grant.id).await.expect("accepts");

    assert_eq!(
        access.confirm(&s.kim, grant.id, sealed()).await.map(|_| ()),
        Err(AppError::NotFound)
    );
    let short = access.confirm(&s.sam, grant.id, vec![1; 12]).await;
    assert!(matches!(short, Err(AppError::Invalid(_))));
    assert_eq!(
        s.world.store.grant_of(grant.id).expect("stored").state,
        EmergencyState::Accepted
    );
}

#[tokio::test]
async fn steps_out_of_order_are_refused() {
    let s = scene().await;
    let grant = s.invite(EmergencyKind::View, 7).await;
    let access = emergency_access(&s.world, &s.notices);

    // The contact hasn't accepted, so the grant isn't theirs yet.
    assert_eq!(
        access.initiate(&s.kim, grant.id).await.map(|_| ()),
        Err(AppError::NotFound)
    );
    let early = access.confirm(&s.sam, grant.id, sealed()).await;
    assert!(matches!(early, Err(AppError::Invalid(_))));
    let approve = access.approve(&s.sam, grant.id).await;
    assert!(matches!(approve, Err(AppError::Invalid(_))));
    access.accept(&s.kim, grant.id).await.expect("accepts");
    let unconfirmed = access.initiate(&s.kim, grant.id).await;
    assert!(matches!(unconfirmed, Err(AppError::Invalid(_))));
}

#[tokio::test]
async fn either_party_can_end_a_grant_and_a_stranger_can_not() {
    let s = scene().await;
    let access = emergency_access(&s.world, &s.notices);
    let stranger = make_user(&s.world, "lee@example.org").await;

    let one = s.confirmed(EmergencyKind::View, 7).await;
    assert_eq!(
        access.revoke(&actor(stranger), one.id).await,
        Err(AppError::NotFound)
    );
    access
        .revoke(&s.kim, one.id)
        .await
        .expect("the contact leaves");
    assert!(s.world.store.grant_of(one.id).is_none());

    let two = s.confirmed(EmergencyKind::Takeover, 7).await;
    access
        .revoke(&s.sam, two.id)
        .await
        .expect("the grantor revokes");
    assert!(s.world.store.grant_of(two.id).is_none());
    assert_eq!(access.revoke(&s.sam, two.id).await, Err(AppError::NotFound));
}

#[tokio::test]
async fn lists_show_each_party_their_side_and_never_the_sealed_key() {
    let s = scene().await;
    let access = emergency_access(&s.world, &s.notices);
    let grant = s.confirmed(EmergencyKind::View, 14).await;

    let sam = access.list(&s.sam).await.expect("lists");
    assert_eq!(sam.trusted_contacts.len(), 1);
    assert!(sam.grantors.is_empty());
    assert_eq!(sam.trusted_contacts[0].grant.sealed_key, None);
    assert_eq!(
        sam.trusted_contacts[0].grant.state,
        EmergencyState::Confirmed
    );
    assert!(
        sam.trusted_contacts[0].contact_keys.is_none(),
        "keys are shown only while the grantor has yet to confirm"
    );

    let kim = access.list(&s.kim).await.expect("lists");
    assert!(kim.trusted_contacts.is_empty());
    assert_eq!(kim.grantors.len(), 1);
    assert_eq!(kim.grantors[0].grant.id, grant.id);
    assert_eq!(kim.grantors[0].grant.sealed_key, None);
    assert_eq!(
        kim.grantors[0].grantor_email.as_ref().map(|e| e.as_str()),
        Some(GRANTOR)
    );
}

#[tokio::test]
async fn an_invitation_is_listed_for_the_contact_before_they_accept() {
    let s = scene().await;
    let grant = s.invite(EmergencyKind::View, 7).await;
    let kim = emergency_access(&s.world, &s.notices)
        .list(&s.kim)
        .await
        .expect("lists");
    assert_eq!(kim.grantors.len(), 1);
    assert_eq!(kim.grantors[0].grant.id, grant.id);
    assert_eq!(kim.grantors[0].grant.state, EmergencyState::Invited);
}

#[tokio::test]
async fn nobody_but_the_accepted_contact_fetches_the_key() {
    let s = scene().await;
    let access = emergency_access(&s.world, &s.notices);
    let grant = s.confirmed(EmergencyKind::View, 1).await;
    access.initiate(&s.kim, grant.id).await.expect("asks");
    access.approve(&s.sam, grant.id).await.expect("approves");

    // The grantor holds no right to the box meant for the contact, and a stranger none at all.
    assert_eq!(
        access.release_key(&s.sam, grant.id).await.map(|_| ()),
        Err(AppError::NotFound)
    );
    let stranger = make_user(&s.world, "lee@example.org").await;
    assert_eq!(
        access
            .release_key(&actor(stranger), grant.id)
            .await
            .map(|_| ()),
        Err(AppError::NotFound)
    );
}
