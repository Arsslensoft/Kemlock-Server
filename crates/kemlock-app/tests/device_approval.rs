//! Device approval: request, list, answer and poll.

mod fakes;

use fakes::unlock::*;
use fakes::*;
use kemlock_app::devices::{
    Answer, ApprovalRepo, ApprovalRequestInput, NOTICES_PER_HOUR, Poll, phrase_for,
};
use kemlock_app::ports::Clock;
use kemlock_app::{Actor, AppError, DeviceInfo, SignedIn};
use kemlock_domain::unlock::{
    ApprovalState, HOURLY_REQUEST_LIMIT, KX1_PUBLIC_KEY_LEN, REQUEST_TTL, SEALED_BOX_OVERHEAD,
    SOURCE_HOURLY_REQUEST_LIMIT,
};
use kemlock_domain::{DeviceId, DeviceKind, UserId};
use std::net::{IpAddr, Ipv4Addr};
use time::Duration;

const EMAIL: &str = "sam@example.org";
const NEW_JKT: &str = "new-device-jkt";

/// A world with one account that has a device signed in.
async fn account() -> (World, UserId, Actor) {
    let world = World::new().with_signups();
    let user = make_user(&world, EMAIL).await;
    let SignedIn::Tokens(tokens) = sign_in_with(&world, EMAIL, &PASSWORD, device("Pixel"), "jkt-1")
        .await
        .expect("signs in")
    else {
        panic!("tokens expected");
    };
    let open = Actor {
        user,
        device: tokens.device,
        admin: false,
    };
    (world, user, open)
}

fn public_key(byte: u8) -> Vec<u8> {
    vec![byte; KX1_PUBLIC_KEY_LEN]
}

fn sealed_box() -> Vec<u8> {
    vec![0x5b; SEALED_BOX_OVERHEAD + 64]
}

fn input(email: &str, key: Vec<u8>) -> ApprovalRequestInput {
    ApprovalRequestInput {
        email: email.to_owned(),
        device: DeviceInfo {
            id: None,
            name: "Firefox on Linux".to_owned(),
            bitwarden_identifier: None,
            kind: DeviceKind::KemlockWeb,
        },
        public_key: key,
        jkt: NEW_JKT.to_owned(),
        ip: IpAddr::V4(Ipv4Addr::new(203, 0, 113, 77)),
    }
}

#[tokio::test]
async fn a_request_gets_an_id_a_phrase_and_a_15_minute_life() {
    let (world, user, _) = account().await;
    let notices = FakeNotices::default();
    let key = public_key(9);

    let requested = request_approval(&world, &notices)
        .execute(input(EMAIL, key.clone()))
        .await
        .expect("the request is accepted");

    assert_eq!(requested.phrase, phrase_for(&world.env, &key));
    assert_eq!(requested.phrase.split(' ').count(), 5);
    assert_eq!(requested.expires_at, world.env.now() + REQUEST_TTL);
    let stored = world
        .store
        .auth_request(requested.id)
        .expect("the request is stored");
    assert_eq!(stored.user, user);
    assert_eq!(stored.state, ApprovalState::Pending);
    assert_eq!(stored.public_key, key);
    assert_eq!(stored.jkt, NEW_JKT);
    assert_eq!(stored.ip, "203.0.113.0/24", "the address is cut to its /24");
    assert_eq!(stored.device_name, "Firefox on Linux");
}

#[tokio::test]
async fn the_account_is_told_about_the_new_device() {
    let (world, _, _) = account().await;
    let notices = FakeNotices::default();
    request_approval(&world, &notices)
        .execute(input(EMAIL, public_key(9)))
        .await
        .expect("accepted");

    let sent = notices.new_devices();
    assert_eq!(sent.len(), 1);
    assert_eq!(sent[0].to.as_str(), EMAIL);
    assert_eq!(sent[0].device_name, "Firefox on Linux");
    assert_eq!(sent[0].ip, "203.0.113.0/24");
}

#[tokio::test]
async fn an_unknown_email_looks_the_same_and_stores_nothing() {
    let (world, _, _) = account().await;
    let notices = FakeNotices::default();
    let key = public_key(9);

    let ghost = request_approval(&world, &notices)
        .execute(input("nobody@example.org", key.clone()))
        .await
        .expect("answers as for a real account");

    assert_eq!(ghost.phrase, phrase_for(&world.env, &key));
    assert_eq!(world.store.auth_request_count(), 0);
    assert!(notices.new_devices().is_empty());
    // Polling the ghost reads as pending, like a real request nobody has answered.
    assert_eq!(
        poll_approval(&world)
            .execute(ghost.id, NEW_JKT)
            .await
            .expect("polls"),
        Poll::Pending { expires_at: None }
    );
}

#[tokio::test]
async fn malformed_requests_are_refused() {
    let (world, _, _) = account().await;
    let notices = FakeNotices::default();
    let use_case = request_approval(&world, &notices);

    for key in [
        vec![],
        vec![1; KX1_PUBLIC_KEY_LEN - 1],
        vec![1; KX1_PUBLIC_KEY_LEN + 1],
    ] {
        assert!(matches!(
            use_case.execute(input(EMAIL, key)).await,
            Err(AppError::Invalid(_))
        ));
    }
    assert!(matches!(
        use_case.execute(input("not an email", public_key(1))).await,
        Err(AppError::Invalid(_))
    ));
    let mut no_key = input(EMAIL, public_key(1));
    no_key.jkt = String::new();
    assert!(matches!(
        use_case.execute(no_key).await,
        Err(AppError::Invalid(_))
    ));
    assert_eq!(world.store.auth_request_count(), 0);
}

/// A request from the address `203.0.<n>.7`: one source per `n`.
fn input_from(email: &str, key: Vec<u8>, n: u8) -> ApprovalRequestInput {
    ApprovalRequestInput {
        ip: IpAddr::V4(Ipv4Addr::new(203, 0, n, 7)),
        ..input(email, key)
    }
}

#[tokio::test]
async fn an_address_takes_three_requests_an_hour_and_the_rest_are_answered_like_any_other() {
    let (world, _, _) = account().await;
    let notices = FakeNotices::default();
    let use_case = request_approval(&world, &notices);

    for i in 0..SOURCE_HOURLY_REQUEST_LIMIT {
        world.env.clock.advance(Duration::seconds(1));
        use_case
            .execute(input(EMAIL, public_key(i as u8)))
            .await
            .expect("inside the limit");
    }
    assert_eq!(world.store.auth_request_count(), SOURCE_HOURLY_REQUEST_LIMIT);
    assert_eq!(notices.new_devices().len(), NOTICES_PER_HOUR);

    // The next from the same address is answered like a request for an email with no account: no
    // refusal tells a stranger the account exists or that its hour is spent, and nothing is
    // stored or mailed.
    world.env.clock.advance(Duration::seconds(1));
    let key = public_key(99);
    let fourth = use_case
        .execute(input(EMAIL, key.clone()))
        .await
        .expect("answered like any other");
    let stranger = use_case
        .execute(input("nobody@example.org", key.clone()))
        .await
        .expect("answered");
    assert_eq!(fourth.phrase, phrase_for(&world.env, &key));
    assert_eq!(fourth.phrase, stranger.phrase);
    assert_eq!(fourth.expires_at, stranger.expires_at);
    assert_eq!(world.store.auth_request_count(), SOURCE_HOURLY_REQUEST_LIMIT);
    assert!(world.store.auth_request(fourth.id).is_none());
    assert_eq!(notices.new_devices().len(), NOTICES_PER_HOUR);

    // Another address is not held back by it: it has an hour of its own with the account.
    let other = use_case
        .execute(input_from(EMAIL, public_key(100), 1))
        .await
        .expect("answered");
    assert!(world.store.auth_request(other.id).is_some());

    // The first of the three was made 3 seconds ago, so its slot opens in 3597 seconds.
    world.env.clock.advance(Duration::seconds(3597));
    let later = use_case
        .execute(input(EMAIL, public_key(101)))
        .await
        .expect("the first slot has opened");
    assert!(world.store.auth_request(later.id).is_some());
}

#[tokio::test]
async fn all_addresses_take_thirty_an_hour_and_the_owner_is_told_once_when_one_is_held_back() {
    let (world, _, open) = account().await;
    let notices = FakeNotices::default();
    let use_case = request_approval(&world, &notices);

    for i in 0..HOURLY_REQUEST_LIMIT {
        use_case
            .execute(input_from(EMAIL, public_key(i as u8), i as u8))
            .await
            .expect("inside the limit");
    }
    assert_eq!(world.store.auth_request_count(), HOURLY_REQUEST_LIMIT);
    // The owner is mailed about the first few only.
    assert_eq!(notices.new_devices().len(), NOTICES_PER_HOUR);

    // The next, from an address nobody has heard from, is answered like any other but held back:
    // no open device is shown it, and the owner is told approvals are being throttled.
    let key = public_key(99);
    let held = use_case
        .execute(input_from(EMAIL, key.clone(), 200))
        .await
        .expect("answered like any other");
    assert_eq!(held.phrase, phrase_for(&world.env, &key));
    assert_eq!(notices.new_devices().len(), NOTICES_PER_HOUR + 1);
    assert!(
        notices.new_devices()[NOTICES_PER_HOUR]
            .device_name
            .contains("held back")
    );
    // Only once: the ones after it cost the owner no more mail.
    use_case
        .execute(input_from(EMAIL, public_key(98), 201))
        .await
        .expect("answered like any other");
    assert_eq!(notices.new_devices().len(), NOTICES_PER_HOUR + 1);
    let listed = list_approvals(&world).execute(&open).await.expect("lists");
    assert_eq!(listed.len(), HOURLY_REQUEST_LIMIT, "held back ones are not shown");
    assert!(world.store.auth_request(held.id).is_none());
}

#[tokio::test]
async fn an_address_the_owner_was_answered_from_is_not_held_back_with_the_rest() {
    let (world, _, open) = account().await;
    let notices = FakeNotices::default();
    let use_case = request_approval(&world, &notices);

    // The owner's own device asked from this address and was approved.
    let mine = use_case
        .execute(input_from(EMAIL, public_key(1), 150))
        .await
        .expect("accepted");
    let mut stored = world.store.auth_request(mine.id).expect("stored");
    stored
        .approve(sealed_box(), world.env.now())
        .expect("pending");
    assert!(
        ApprovalRepo::save_request(&world.store, &stored, ApprovalState::Pending)
            .await
            .expect("saved")
    );
    // Strangers use up the rest of the account's hour.
    for i in 1..HOURLY_REQUEST_LIMIT {
        use_case
            .execute(input_from(EMAIL, public_key(i as u8), i as u8))
            .await
            .expect("inside the limit");
    }
    // The owner asks again from the same address: a real request, shown on the open devices.
    let again = use_case
        .execute(input_from(EMAIL, public_key(77), 150))
        .await
        .expect("answered");
    let stored = world.store.auth_request(again.id).expect("stored for real");
    assert_eq!(stored.state, ApprovalState::Pending);
    let listed = list_approvals(&world).execute(&open).await.expect("lists");
    assert!(listed.iter().any(|p| p.id == again.id));
    // A stranger's is held back.
    let stranger = use_case
        .execute(input_from(EMAIL, public_key(78), 220))
        .await
        .expect("answered");
    assert!(world.store.auth_request(stranger.id).is_none());
}

#[tokio::test]
async fn the_owner_is_mailed_about_three_requests_an_hour_however_many_come() {
    let (world, _, _) = account().await;
    let notices = FakeNotices::default();
    let use_case = request_approval(&world, &notices);
    for i in 0..NOTICES_PER_HOUR + 2 {
        world.env.clock.advance(Duration::seconds(1));
        use_case
            .execute(input_from(EMAIL, public_key(i as u8), i as u8))
            .await
            .expect("accepted");
    }
    // Every request is stored and shows on the open devices; only the first three are mailed.
    assert_eq!(world.store.auth_request_count(), NOTICES_PER_HOUR + 2);
    assert_eq!(notices.new_devices().len(), NOTICES_PER_HOUR);

    // An hour on, the next request is mailed again.
    world.env.clock.advance(Duration::hours(1));
    use_case
        .execute(input(EMAIL, public_key(50)))
        .await
        .expect("accepted");
    assert_eq!(notices.new_devices().len(), NOTICES_PER_HOUR + 1);
}

#[tokio::test]
async fn open_devices_list_pending_requests_with_phrase_ip_and_age() {
    let (world, user, open) = account().await;
    let notices = FakeNotices::default();
    let key = public_key(7);
    let requested = request_approval(&world, &notices)
        .execute(input(EMAIL, key.clone()))
        .await
        .expect("accepted");
    world.env.clock.advance(Duration::minutes(3));

    let listed = list_approvals(&world).execute(&open).await.expect("lists");
    assert_eq!(listed.len(), 1);
    assert_eq!(listed[0].id, requested.id);
    assert_eq!(listed[0].phrase, requested.phrase);
    assert_eq!(
        listed[0].public_key, key,
        "the open device gets the key to seal to"
    );
    assert_eq!(listed[0].ip, "203.0.113.0/24");
    assert_eq!(listed[0].device_name, "Firefox on Linux");
    assert_eq!(world.env.now() - listed[0].created_at, Duration::minutes(3));

    // Another account sees nothing of it.
    let stranger = make_user(&world, "kim@example.org").await;
    assert_ne!(stranger, user);
    assert!(
        list_approvals(&world)
            .execute(&actor(stranger))
            .await
            .expect("lists")
            .is_empty()
    );
}

#[tokio::test]
async fn expired_and_answered_requests_are_not_listed() {
    let (world, _, open) = account().await;
    let notices = FakeNotices::default();
    let old = request_approval(&world, &notices)
        .execute(input(EMAIL, public_key(1)))
        .await
        .expect("accepted");
    world.env.clock.advance(Duration::minutes(16));
    let fresh = request_approval(&world, &notices)
        .execute(input(EMAIL, public_key(2)))
        .await
        .expect("accepted");
    let answered = request_approval(&world, &notices)
        .execute(input(EMAIL, public_key(3)))
        .await
        .expect("accepted");
    answer_approval(&world)
        .execute(&open, answered.id, Answer::Deny)
        .await
        .expect("denies");

    let listed = list_approvals(&world).execute(&open).await.expect("lists");
    let ids: Vec<_> = listed.iter().map(|p| p.id).collect();
    assert_eq!(ids, vec![fresh.id]);
    assert!(!ids.contains(&old.id));
}

#[tokio::test]
async fn approving_relays_the_sealed_key_to_the_new_device() {
    let (world, user, open) = account().await;
    let notices = FakeNotices::default();
    let requested = request_approval(&world, &notices)
        .execute(input(EMAIL, public_key(7)))
        .await
        .expect("accepted");
    assert_eq!(
        poll_approval(&world)
            .execute(requested.id, NEW_JKT)
            .await
            .expect("polls"),
        Poll::Pending {
            expires_at: Some(requested.expires_at)
        }
    );

    answer_approval(&world)
        .execute(
            &open,
            requested.id,
            Answer::Approve {
                sealed_key: sealed_box(),
            },
        )
        .await
        .expect("approves");

    assert_eq!(
        poll_approval(&world)
            .execute(requested.id, NEW_JKT)
            .await
            .expect("polls"),
        Poll::Approved {
            sealed_key: sealed_box(),
            account: user,
        }
    );
    let kinds: Vec<_> = world.store.events().iter().map(|e| e.action).collect();
    assert!(kinds.contains(&"device.approval_approved"));
}

#[tokio::test]
async fn a_denial_sends_no_key() {
    let (world, _, open) = account().await;
    let notices = FakeNotices::default();
    let requested = request_approval(&world, &notices)
        .execute(input(EMAIL, public_key(7)))
        .await
        .expect("accepted");

    answer_approval(&world)
        .execute(&open, requested.id, Answer::Deny)
        .await
        .expect("denies");

    assert_eq!(
        poll_approval(&world)
            .execute(requested.id, NEW_JKT)
            .await
            .expect("polls"),
        Poll::Denied
    );
    let stored = world.store.auth_request(requested.id).expect("stored");
    assert_eq!(stored.sealed_key, None);
}

#[tokio::test]
async fn a_request_takes_one_answer() {
    let (world, _, open) = account().await;
    let notices = FakeNotices::default();
    let requested = request_approval(&world, &notices)
        .execute(input(EMAIL, public_key(7)))
        .await
        .expect("accepted");
    let answer = answer_approval(&world);

    answer
        .execute(&open, requested.id, Answer::Deny)
        .await
        .expect("denies");
    let again = answer
        .execute(
            &open,
            requested.id,
            Answer::Approve {
                sealed_key: sealed_box(),
            },
        )
        .await;
    assert!(matches!(again, Err(AppError::Invalid(_))));
    assert_eq!(
        world
            .store
            .auth_request(requested.id)
            .expect("stored")
            .state,
        ApprovalState::Denied
    );
}

#[tokio::test]
async fn only_the_accounts_own_devices_can_answer() {
    let (world, _, _) = account().await;
    let notices = FakeNotices::default();
    let requested = request_approval(&world, &notices)
        .execute(input(EMAIL, public_key(7)))
        .await
        .expect("accepted");
    let stranger = make_user(&world, "kim@example.org").await;

    let result = answer_approval(&world)
        .execute(&actor(stranger), requested.id, Answer::Deny)
        .await;
    assert_eq!(result, Err(AppError::NotFound));
    assert_eq!(
        world
            .store
            .auth_request(requested.id)
            .expect("stored")
            .state,
        ApprovalState::Pending
    );
}

#[tokio::test]
async fn a_box_of_the_wrong_size_or_an_expired_request_is_refused() {
    let (world, _, open) = account().await;
    let notices = FakeNotices::default();
    let requested = request_approval(&world, &notices)
        .execute(input(EMAIL, public_key(7)))
        .await
        .expect("accepted");
    let answer = answer_approval(&world);

    let too_short = answer
        .execute(
            &open,
            requested.id,
            Answer::Approve {
                sealed_key: vec![1; 40],
            },
        )
        .await;
    assert!(matches!(too_short, Err(AppError::Invalid(_))));

    world.env.clock.advance(REQUEST_TTL);
    let late = answer
        .execute(
            &open,
            requested.id,
            Answer::Approve {
                sealed_key: sealed_box(),
            },
        )
        .await;
    assert_eq!(late, Err(AppError::Invalid("the request has expired")));
    assert_eq!(
        poll_approval(&world)
            .execute(requested.id, NEW_JKT)
            .await
            .expect("polls"),
        Poll::Expired
    );
}

#[tokio::test]
async fn only_the_requesting_key_can_read_the_answer() {
    let (world, _, open) = account().await;
    let notices = FakeNotices::default();
    let requested = request_approval(&world, &notices)
        .execute(input(EMAIL, public_key(7)))
        .await
        .expect("accepted");
    answer_approval(&world)
        .execute(
            &open,
            requested.id,
            Answer::Approve {
                sealed_key: sealed_box(),
            },
        )
        .await
        .expect("approves");

    // Another key polls: it learns nothing, not even that the request exists.
    assert_eq!(
        poll_approval(&world)
            .execute(requested.id, "someone-elses-jkt")
            .await
            .expect("polls"),
        Poll::Pending { expires_at: None }
    );
}

#[tokio::test]
async fn an_approval_not_used_in_time_expires() {
    let (world, _, open) = account().await;
    let notices = FakeNotices::default();
    let requested = request_approval(&world, &notices)
        .execute(input(EMAIL, public_key(7)))
        .await
        .expect("accepted");
    answer_approval(&world)
        .execute(
            &open,
            requested.id,
            Answer::Approve {
                sealed_key: sealed_box(),
            },
        )
        .await
        .expect("approves");

    world.env.clock.advance(Duration::minutes(15));
    assert_eq!(
        poll_approval(&world)
            .execute(requested.id, NEW_JKT)
            .await
            .expect("polls"),
        Poll::Expired
    );
}

#[tokio::test]
async fn purging_deletes_requests_a_day_after_they_expired() {
    let (world, _, _) = account().await;
    let notices = FakeNotices::default();
    request_approval(&world, &notices)
        .execute(input(EMAIL, public_key(7)))
        .await
        .expect("accepted");

    world.env.clock.advance(Duration::hours(23));
    assert_eq!(purge_approvals(&world).execute().await, Ok(0));
    world.env.clock.advance(Duration::hours(2));
    assert_eq!(purge_approvals(&world).execute().await, Ok(1));
    assert_eq!(world.store.auth_request_count(), 0);
}

#[tokio::test]
async fn the_device_id_the_client_names_is_kept() {
    let (world, _, _) = account().await;
    let notices = FakeNotices::default();
    let chosen = DeviceId::random();
    let mut request = input(EMAIL, public_key(7));
    request.device.id = Some(chosen);

    let requested = request_approval(&world, &notices)
        .execute(request)
        .await
        .expect("accepted");

    assert_eq!(
        world
            .store
            .auth_request(requested.id)
            .expect("stored")
            .device,
        chosen
    );
}
