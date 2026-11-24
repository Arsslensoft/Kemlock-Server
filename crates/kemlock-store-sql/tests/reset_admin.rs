//! `ResetAdmin` over the real store: every admin becomes a plain user, the first-admin marker is
//! gone, so the server's next start opens setup again, and the reset is in the event log.

mod common;

use common::{memory, unique_email, user};
use kemlock_app::FirstAdminRepo;
use kemlock_app::admin::{AdminEventRepo, EventFilter};
use kemlock_app::ports::{Clock, UserRepo};
use kemlock_app::reset_admin::{ACTION, ResetAdmin};
use kemlock_domain::Role;
use time::OffsetDateTime;
use time::macros::datetime;

const NOW: OffsetDateTime = datetime!(2026-06-01 12:00:00 UTC);

struct FixedClock;

impl Clock for FixedClock {
    fn now(&self) -> OffsetDateTime {
        NOW
    }
}

#[tokio::test]
async fn reset_admin_demotes_every_admin_clears_the_marker_and_logs_it() {
    let store = memory().await;
    let mut first = user(&unique_email("first"));
    first.role = Role::Admin;
    FirstAdminRepo::insert_first_admin(&store, &first)
        .await
        .expect("first admin");
    let mut second = user(&unique_email("second"));
    second.role = Role::Admin;
    UserRepo::insert(&store, &second).await.expect("insert");
    let plain = user(&unique_email("plain"));
    UserRepo::insert(&store, &plain).await.expect("insert");
    assert_eq!(UserRepo::count_admins(&store).await.expect("count"), 2);

    let reset = ResetAdmin {
        users: store.clone(),
        admins: store.clone(),
        events: store.clone(),
        settings: store.clone(),
        two_factor: store.clone(),
        clock: FixedClock,
    };
    let mut demoted = reset.execute(None).await.expect("reset");
    demoted.sort();
    let mut expected = vec![
        first.email.as_str().to_owned(),
        second.email.as_str().to_owned(),
    ];
    expected.sort();
    assert_eq!(demoted, expected);

    assert_eq!(UserRepo::count_admins(&store).await.expect("count"), 0);
    let kept = UserRepo::by_id(&store, first.id)
        .await
        .expect("by id")
        .expect("the account stays");
    assert_eq!(kept.role, Role::User);
    assert_eq!(kept.email, first.email);
    assert_eq!(
        FirstAdminRepo::first_admin(&store).await.expect("marker"),
        None
    );

    let events = store
        .query_events(
            &EventFilter {
                action: Some(ACTION.to_owned()),
                ..EventFilter::default()
            },
            None,
            10,
        )
        .await
        .expect("events");
    assert_eq!(events.events.len(), 1);
    assert_eq!(events.events[0].actor, None);

    // With no admin and no marker, the next start opens setup with a new code, as on a new server
    // (FirstRun::start checks exactly these two).

    // A second run has nothing left to demote and still succeeds.
    assert!(reset.execute(None).await.expect("again").is_empty());
}

#[tokio::test]
async fn promote_hands_the_role_to_an_account_with_two_step_and_changes_nothing_otherwise() {
    use kemlock_app::ports::{TwoFactor, TwoFactorMethod, TwoFactorRepo};
    let store = memory().await;
    let mut old = user(&unique_email("old"));
    old.role = Role::Admin;
    UserRepo::insert(&store, &old).await.expect("insert");
    let heir = user(&unique_email("heir"));
    UserRepo::insert(&store, &heir).await.expect("insert");
    let reset = ResetAdmin {
        users: store.clone(),
        admins: store.clone(),
        events: store.clone(),
        settings: store.clone(),
        two_factor: store.clone(),
        clock: FixedClock,
    };

    // No two-step method yet: refused, and the old admin is still the admin.
    assert!(reset.execute(Some(&heir.email)).await.is_err());
    assert_eq!(UserRepo::count_admins(&store).await.expect("count"), 1);
    // An unknown account is refused too.
    let ghost = kemlock_domain::Email::parse("ghost@example.org").expect("email");
    assert!(reset.execute(Some(&ghost)).await.is_err());
    assert_eq!(UserRepo::count_admins(&store).await.expect("count"), 1);

    TwoFactorRepo::put(
        &store,
        &TwoFactor {
            user: heir.id,
            method: TwoFactorMethod::Totp,
            sealed_secret: vec![1; 40],
            enabled: true,
            created_at: NOW,
        },
    )
    .await
    .expect("two-step");
    let demoted = reset.execute(Some(&heir.email)).await.expect("promote");
    assert_eq!(demoted, vec![old.email.as_str().to_owned()]);
    let after = |id| {
        let store = store.clone();
        async move {
            UserRepo::by_id(&store, id)
                .await
                .expect("by id")
                .expect("kept")
                .role
        }
    };
    assert_eq!(after(heir.id).await, Role::Admin);
    assert_eq!(after(old.id).await, Role::User);
}
