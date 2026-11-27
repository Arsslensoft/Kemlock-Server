//! The account-side ports: ServerInfo, UserRepo, DeviceRepo, TokenRepo, TwoFactorRepo, EventLog.
//!
//! Each scenario runs on every backend that is available: in-memory SQLite, SQLite in a file, and
//! PostgreSQL and MySQL when `KEMLOCK_TEST_POSTGRES_URL` / `KEMLOCK_TEST_MYSQL_URL` are set.
//! Backends run their scenarios one after another in a single test, so a shared database sees
//! no interleaving.

mod common;

use common::{device, external, file, file_url, memory, unique_email, user};
use kemlock_app::FirstAdminRepo;
use kemlock_app::ports::{
    DeviceRepo, Event, EventLog, RefreshToken, ServerInfo, StoreError, TokenRepo, TwoFactor,
    TwoFactorMethod, TwoFactorRepo, UserRepo,
};
use kemlock_app::second_step_guard::{Reservation, SecondStepGuard};
use kemlock_domain::{DeviceId, DeviceKind, Role, UserId};
use kemlock_store_sql::SqlStore;
use time::macros::datetime;
use uuid::Uuid;

async fn server_info(store: &SqlStore) {
    let id = ServerInfo::server_id(store);
    assert_ne!(id.0, Uuid::nil());
    assert_eq!(id.0.get_version_num(), 4, "the server id is a UUID v4");
    assert_eq!(ServerInfo::server_id(&store.clone()), id, "clones share it");
}

async fn users(store: &SqlStore) {
    let ada = user(&unique_email("ada"));
    UserRepo::insert(store, &ada).await.expect("insert");

    assert_eq!(
        UserRepo::by_id(store, ada.id).await.expect("by_id"),
        Some(ada.clone())
    );
    assert_eq!(
        UserRepo::by_email(store, &ada.email)
            .await
            .expect("by_email"),
        Some(ada.clone())
    );
    assert_eq!(
        UserRepo::by_id(store, UserId::random())
            .await
            .expect("by_id"),
        None
    );

    // The same email under another id is a duplicate; so is the same id.
    let mut clash = user(ada.email.as_str());
    assert_eq!(
        UserRepo::insert(store, &clash).await,
        Err(StoreError::Duplicate)
    );
    clash.email = kemlock_domain::Email::parse(&unique_email("other")).expect("valid");
    clash.id = ada.id;
    assert_eq!(
        UserRepo::insert(store, &clash).await,
        Err(StoreError::Duplicate)
    );

    // Update changes the row, and the email index follows.
    let mut renamed = ada.clone();
    renamed.name = Some("Ada Lovelace".to_owned());
    renamed.key_version = 2;
    renamed.opaque_record = None;
    renamed.updated_at = datetime!(2026-03-04 05:06:07 UTC);
    UserRepo::update(store, &renamed).await.expect("update");
    assert_eq!(
        UserRepo::by_id(store, ada.id).await.expect("by_id"),
        Some(renamed.clone())
    );

    let mut moved = renamed.clone();
    moved.email = kemlock_domain::Email::parse(&unique_email("moved")).expect("valid");
    UserRepo::update(store, &moved).await.expect("update");
    assert_eq!(
        UserRepo::by_email(store, &ada.email)
            .await
            .expect("by_email"),
        None
    );
    assert_eq!(
        UserRepo::by_email(store, &moved.email)
            .await
            .expect("by_email"),
        Some(moved.clone())
    );

    // Updating an unknown account is NotFound; taking another account's email is a duplicate.
    let ghost = user(&unique_email("ghost"));
    assert_eq!(
        UserRepo::update(store, &ghost).await,
        Err(StoreError::NotFound)
    );
    let bob = user(&unique_email("bob"));
    UserRepo::insert(store, &bob).await.expect("insert");
    let mut grabbing = bob.clone();
    grabbing.email = moved.email.clone();
    assert_eq!(
        UserRepo::update(store, &grabbing).await,
        Err(StoreError::Duplicate)
    );

    // Admins are counted by role.
    let before = UserRepo::count_admins(store).await.expect("count_admins");
    let mut admin = user(&unique_email("admin"));
    admin.role = Role::Admin;
    UserRepo::insert(store, &admin).await.expect("insert");
    assert_eq!(
        UserRepo::count_admins(store).await.expect("count_admins"),
        before + 1
    );
    let mut demoted = admin.clone();
    demoted.role = Role::User;
    UserRepo::update(store, &demoted).await.expect("update");
    assert_eq!(
        UserRepo::count_admins(store).await.expect("count_admins"),
        before
    );
}

async fn devices(store: &SqlStore) {
    let owner = user(&unique_email("devices"));
    UserRepo::insert(store, &owner).await.expect("insert user");

    let older = device(owner.id, "Pixel", datetime!(2026-01-01 00:00:00 UTC));
    let newer = device(owner.id, "Laptop", datetime!(2026-02-01 00:00:00 UTC));
    DeviceRepo::upsert(store, &newer).await.expect("upsert");
    DeviceRepo::upsert(store, &older).await.expect("upsert");

    // Another account can't take a device id over, whatever its use case read first: nothing of
    // the device changes.
    let thief = user(&unique_email("device-thief"));
    UserRepo::insert(store, &thief).await.expect("insert thief");
    let mut taken = older.clone();
    taken.user = thief.id;
    taken.name = "Taken".to_owned();
    assert_eq!(
        DeviceRepo::upsert(store, &taken).await,
        Err(StoreError::Duplicate)
    );
    assert_eq!(
        DeviceRepo::get(store, older.id).await.expect("get"),
        Some(older.clone())
    );

    assert_eq!(
        DeviceRepo::get(store, older.id).await.expect("get"),
        Some(older.clone())
    );
    assert_eq!(
        DeviceRepo::get(store, DeviceId::random())
            .await
            .expect("get"),
        None
    );
    // Oldest first.
    assert_eq!(
        DeviceRepo::list(store, owner.id).await.expect("list"),
        vec![older.clone(), newer.clone()]
    );
    assert!(
        DeviceRepo::list(store, UserId::random())
            .await
            .expect("list")
            .is_empty()
    );

    // Upsert replaces the device with the same id.
    let mut seen = older.clone();
    seen.name = "Pixel 9".to_owned();
    seen.kind = DeviceKind::Other;
    seen.dpop_jkt = None;
    seen.last_seen_at = datetime!(2026-05-05 05:05:05 UTC);
    DeviceRepo::upsert(store, &seen).await.expect("upsert");
    assert_eq!(
        DeviceRepo::get(store, older.id).await.expect("get"),
        Some(seen.clone())
    );
    assert_eq!(
        DeviceRepo::list(store, owner.id).await.expect("list").len(),
        2
    );

    // Seen is written only while the device still has the key the caller read it with: a cleared
    // key is not put back.
    assert_eq!(
        DeviceRepo::touch_seen(store, older.id, "jkt-x", datetime!(2026-06-06 06:06:06 UTC)).await,
        Ok(false),
        "the device has no key now"
    );
    let mut keyed = seen.clone();
    keyed.dpop_jkt = Some("jkt-x".to_owned());
    DeviceRepo::upsert(store, &keyed).await.expect("upsert");
    assert_eq!(
        DeviceRepo::touch_seen(
            store,
            older.id,
            "jkt-other",
            datetime!(2026-06-06 06:06:06 UTC)
        )
        .await,
        Ok(false),
        "another key"
    );
    assert_eq!(
        DeviceRepo::touch_seen(store, older.id, "jkt-x", datetime!(2026-06-06 06:06:06 UTC)).await,
        Ok(true)
    );
    let touched = DeviceRepo::get(store, older.id)
        .await
        .expect("get")
        .expect("there");
    assert_eq!(touched.last_seen_at, datetime!(2026-06-06 06:06:06 UTC));
    assert_eq!(touched.dpop_jkt.as_deref(), Some("jkt-x"));
    assert_eq!(touched.name, "Pixel 9");
    assert_eq!(
        DeviceRepo::touch_seen(
            store,
            DeviceId::random(),
            "jkt-x",
            datetime!(2026-06-06 06:06:06 UTC)
        )
        .await,
        Ok(false),
        "no such device"
    );
    // Put back as the rest of the scenario expects.
    DeviceRepo::upsert(store, &seen).await.expect("upsert");

    // A device needs an account.
    let orphan = device(
        UserId::random(),
        "Orphan",
        datetime!(2026-01-01 00:00:00 UTC),
    );
    assert_eq!(
        DeviceRepo::upsert(store, &orphan).await,
        Err(StoreError::NotFound)
    );

    // Removing a device takes its tokens with it, and leaves the others alone.
    let token = refresh_token(&owner.id, &newer.id, 1);
    let keep = refresh_token(&owner.id, &seen.id, 2);
    TokenRepo::insert(store, &token).await.expect("insert");
    TokenRepo::insert(store, &keep).await.expect("insert");
    DeviceRepo::remove(store, newer.id).await.expect("remove");
    assert_eq!(DeviceRepo::get(store, newer.id).await.expect("get"), None);
    assert_eq!(
        TokenRepo::take(store, token.hash, datetime!(2026-06-01 00:00:00 UTC))
            .await
            .expect("take"),
        None
    );
    assert!(
        TokenRepo::take(store, keep.hash, datetime!(2026-06-01 00:00:00 UTC))
            .await
            .expect("take")
            .is_some()
    );
    // Removing it again is harmless.
    DeviceRepo::remove(store, newer.id).await.expect("remove");
}

/// A token with a hash of its own; `n` tells tokens of one scenario apart.
fn refresh_token(user: &UserId, device: &DeviceId, n: u8) -> RefreshToken {
    let mut hash = [n; 32];
    hash[..16].copy_from_slice(Uuid::new_v4().as_bytes());
    RefreshToken {
        hash,
        family: Uuid::new_v4(),
        user: *user,
        device: *device,
        security_stamp: Uuid::from_u128(0x57a3),
        created_at: datetime!(2026-01-02 03:04:05 UTC),
        expires_at: datetime!(2026-02-02 03:04:05 UTC),
        used_at: None,
    }
}

async fn tokens(store: &SqlStore) {
    let owner = user(&unique_email("tokens"));
    UserRepo::insert(store, &owner).await.expect("insert user");
    let phone = device(owner.id, "Phone", datetime!(2026-01-01 00:00:00 UTC));
    let tablet = device(owner.id, "Tablet", datetime!(2026-01-01 00:00:00 UTC));
    DeviceRepo::upsert(store, &phone).await.expect("upsert");
    DeviceRepo::upsert(store, &tablet).await.expect("upsert");

    // take returns the token as it was, and marks it used.
    let first = refresh_token(&owner.id, &phone.id, 1);
    TokenRepo::insert(store, &first).await.expect("insert");
    assert_eq!(
        TokenRepo::insert(store, &first).await,
        Err(StoreError::Duplicate)
    );
    let used_at = datetime!(2026-01-10 10:00:00 UTC);
    let taken = TokenRepo::take(store, first.hash, used_at)
        .await
        .expect("take")
        .expect("the token exists");
    assert_eq!(taken, first);
    assert_eq!(taken.used_at, None);

    // Taking it again shows it used, at the time of the first take.
    let again = TokenRepo::take(store, first.hash, datetime!(2026-01-11 10:00:00 UTC))
        .await
        .expect("take")
        .expect("the token exists");
    assert_eq!(again.used_at, Some(used_at));
    assert_eq!(again.family, first.family);

    // An unknown hash is None.
    assert_eq!(
        TokenRepo::take(store, [0xEE; 32], used_at)
            .await
            .expect("take"),
        None
    );

    // A token needs its device.
    let stray = refresh_token(&owner.id, &DeviceId::random(), 3);
    assert_eq!(
        TokenRepo::insert(store, &stray).await,
        Err(StoreError::NotFound)
    );

    // Revoking a family removes every token of it and no other.
    let family = Uuid::new_v4();
    let mut a = refresh_token(&owner.id, &phone.id, 4);
    let mut b = refresh_token(&owner.id, &tablet.id, 5);
    let other = refresh_token(&owner.id, &phone.id, 6);
    a.family = family;
    b.family = family;
    for token in [&a, &b, &other] {
        TokenRepo::insert(store, token).await.expect("insert");
    }
    TokenRepo::revoke_family(store, family)
        .await
        .expect("revoke_family");
    for gone in [&a, &b] {
        assert_eq!(
            TokenRepo::take(store, gone.hash, used_at)
                .await
                .expect("take"),
            None
        );
    }
    assert!(
        TokenRepo::take(store, other.hash, used_at)
            .await
            .expect("take")
            .is_some()
    );

    // Revoking a device removes its tokens only.
    let on_tablet = refresh_token(&owner.id, &tablet.id, 7);
    let on_phone = refresh_token(&owner.id, &phone.id, 8);
    TokenRepo::insert(store, &on_tablet).await.expect("insert");
    TokenRepo::insert(store, &on_phone).await.expect("insert");
    TokenRepo::revoke_device(store, tablet.id)
        .await
        .expect("revoke_device");
    assert_eq!(
        TokenRepo::take(store, on_tablet.hash, used_at)
            .await
            .expect("take"),
        None
    );
    assert!(
        TokenRepo::take(store, on_phone.hash, used_at)
            .await
            .expect("take")
            .is_some()
    );

    // Restamping a device rebinds its tokens to the new stamp and leaves the others alone.
    let stamp = Uuid::new_v4();
    TokenRepo::restamp_device(store, phone.id, stamp)
        .await
        .expect("restamp_device");
    let bound = TokenRepo::take(store, on_phone.hash, used_at)
        .await
        .expect("take")
        .expect("the phone's token is there");
    assert_eq!(bound.security_stamp, stamp);
}

async fn two_factor(store: &SqlStore) {
    let owner = user(&unique_email("2fa"));
    UserRepo::insert(store, &owner).await.expect("insert user");
    assert!(
        TwoFactorRepo::list(store, owner.id)
            .await
            .expect("list")
            .is_empty()
    );

    let totp = TwoFactor {
        user: owner.id,
        method: TwoFactorMethod::Totp,
        sealed_secret: vec![1; 48],
        enabled: false,
        created_at: datetime!(2026-01-02 03:04:05 UTC),
    };
    let webauthn = TwoFactor {
        user: owner.id,
        method: TwoFactorMethod::WebAuthn,
        sealed_secret: vec![2; 200],
        enabled: true,
        created_at: datetime!(2026-01-03 03:04:05 UTC),
    };
    TwoFactorRepo::put(store, &webauthn).await.expect("put");
    TwoFactorRepo::put(store, &totp).await.expect("put");
    assert_eq!(
        TwoFactorRepo::list(store, owner.id).await.expect("list"),
        vec![totp.clone(), webauthn.clone()],
        "ordered by method"
    );

    // Putting a method again replaces its enrolment.
    let enabled = TwoFactor {
        sealed_secret: vec![7; 48],
        enabled: true,
        ..totp.clone()
    };
    TwoFactorRepo::put(store, &enabled).await.expect("put");
    assert_eq!(
        TwoFactorRepo::list(store, owner.id).await.expect("list"),
        vec![enabled.clone(), webauthn.clone()]
    );

    // A TOTP step is accepted once, and only if it is newer than the last one accepted.
    let accept = |step: u64| TwoFactorRepo::accept_totp_step(store, owner.id, step);
    assert_eq!(accept(100).await, Ok(true), "the first step");
    assert_eq!(
        accept(100).await,
        Ok(false),
        "the same step again is a replay"
    );
    assert_eq!(accept(99).await, Ok(false), "an older step is a replay too");
    assert_eq!(accept(101).await, Ok(true), "a newer step is fine");
    // Replacing the enrolment (confirming it, say) keeps the step that was accepted.
    TwoFactorRepo::put(store, &enabled).await.expect("put");
    assert_eq!(accept(101).await, Ok(false), "the step survived the upsert");
    // Only TOTP has steps, and only a user who has one.
    assert_eq!(
        TwoFactorRepo::accept_totp_step(store, UserId::random(), 1).await,
        Ok(false)
    );

    TwoFactorRepo::remove(store, owner.id, TwoFactorMethod::Totp)
        .await
        .expect("remove");
    assert_eq!(accept(200).await, Ok(false), "no enrolment, no step");
    assert_eq!(
        TwoFactorRepo::list(store, owner.id).await.expect("list"),
        vec![webauthn.clone()]
    );
    // Removing what is not there is harmless.
    TwoFactorRepo::remove(store, owner.id, TwoFactorMethod::Totp)
        .await
        .expect("remove");

    // An enrolment needs its account.
    let orphan = TwoFactor {
        user: UserId::random(),
        ..webauthn
    };
    assert_eq!(
        TwoFactorRepo::put(store, &orphan).await,
        Err(StoreError::NotFound)
    );
}

async fn two_step_version_moves_when_a_method_is_turned_on_or_off(store: &SqlStore) {
    let owner = user(&unique_email("2fa-version"));
    UserRepo::insert(store, &owner).await.expect("insert user");
    let version = || TwoFactorRepo::two_step_version(store, owner.id);
    assert_eq!(version().await, Ok(0), "no row is version 0");

    let totp = TwoFactor {
        user: owner.id,
        method: TwoFactorMethod::Totp,
        sealed_secret: vec![1; 48],
        enabled: false,
        created_at: datetime!(2026-01-02 03:04:05 UTC),
    };
    // A new method moves it, and turning it on moves it again.
    TwoFactorRepo::put(store, &totp).await.expect("put");
    assert_eq!(version().await, Ok(1));
    let on = TwoFactor {
        enabled: true,
        ..totp.clone()
    };
    TwoFactorRepo::put(store, &on).await.expect("put");
    assert_eq!(version().await, Ok(2));

    // Changing what a method stores (an emailed code, a new secret) doesn't.
    let state = TwoFactor {
        sealed_secret: vec![9; 48],
        ..on.clone()
    };
    TwoFactorRepo::put(store, &state).await.expect("put");
    assert!(
        TwoFactorRepo::accept_totp_step(store, owner.id, 5)
            .await
            .expect("step")
    );
    assert_eq!(version().await, Ok(2));

    // Taking one off does; taking off what isn't there doesn't.
    TwoFactorRepo::remove(store, owner.id, TwoFactorMethod::Totp)
        .await
        .expect("remove");
    assert_eq!(version().await, Ok(3));
    TwoFactorRepo::remove(store, owner.id, TwoFactorMethod::Totp)
        .await
        .expect("remove");
    assert_eq!(version().await, Ok(3));

    // It is the account's own.
    assert_eq!(
        TwoFactorRepo::two_step_version(store, UserId::random()).await,
        Ok(0)
    );
}

async fn second_step_attempts_are_reserved_atomically_and_kept(store: &SqlStore) {
    let owner = user(&unique_email("2fa-attempts"));
    UserRepo::insert(store, &owner).await.expect("insert user");
    let reserve = |now: i64| SecondStepGuard::reserve_second_step(store, owner.id, now, 3, 900);

    // Parallel attempts: exactly three of ten pass, whichever order they land in.
    let tasks: Vec<_> = (0..10)
        .map(|_| {
            let (store, user) = (store.clone(), owner.id);
            tokio::spawn(async move {
                SecondStepGuard::reserve_second_step(&store, user, 1000, 3, 900).await
            })
        })
        .collect();
    let mut answers = Vec::new();
    for task in tasks {
        answers.push(task.await.expect("the task ran"));
    }
    let granted = answers
        .iter()
        .filter(|a| matches!(a, Ok(Reservation::Granted)))
        .count();
    assert_eq!(granted, 3, "{answers:?}");
    assert!(
        answers
            .iter()
            .all(|a| matches!(a, Ok(Reservation::Granted | Reservation::Wait(_)))),
        "{answers:?}"
    );

    // A wait counts nothing, and doubles for the attempt after it.
    assert!(matches!(reserve(1000).await, Ok(Reservation::Wait(_))));
    assert_eq!(reserve(1001).await, Ok(Reservation::Granted));
    assert_eq!(reserve(1001).await, Ok(Reservation::Wait(2)));

    // A right code clears it.
    SecondStepGuard::clear_second_step(store, owner.id)
        .await
        .expect("clear");
    assert_eq!(reserve(1001).await, Ok(Reservation::Granted));

    // It is the account's own.
    let other = user(&unique_email("2fa-attempts-other"));
    UserRepo::insert(store, &other).await.expect("insert user");
    for _ in 0..3 {
        SecondStepGuard::reserve_second_step(store, other.id, 1001, 3, 900)
            .await
            .expect("reserve");
    }
    assert_eq!(reserve(1001).await, Ok(Reservation::Granted));
}

async fn events(store: &SqlStore) {
    let owner = user(&unique_email("events"));
    UserRepo::insert(store, &owner).await.expect("insert user");
    for (actor, device, target) in [
        (
            Some(owner.id),
            Some(DeviceId::random()),
            Some("item:1".to_owned()),
        ),
        (None, None, None),
        (Some(UserId::random()), None, Some("x".repeat(2000))),
    ] {
        EventLog::record(
            store,
            Event {
                actor,
                device,
                action: "test.action",
                target,
                at: datetime!(2026-04-05 06:07:08 UTC),
            },
        )
        .await
        .expect("record");
    }
}

/// The first-admin marker: one account, atomically, and no second.
async fn first_admin(store: &SqlStore) {
    let ada = user(&unique_email("first-admin"));
    let bob = user(&unique_email("first-admin"));
    let before = FirstAdminRepo::first_admin(store)
        .await
        .expect("first_admin");
    if before.is_some() {
        // A database kept between runs has its first admin already: nobody else may be one.
        assert_eq!(
            FirstAdminRepo::insert_first_admin(store, &ada).await,
            Err(StoreError::Duplicate)
        );
        assert_eq!(UserRepo::by_id(store, ada.id).await.expect("by_id"), None);
        return;
    }
    FirstAdminRepo::insert_first_admin(store, &ada)
        .await
        .expect("the first admin");
    assert_eq!(
        FirstAdminRepo::first_admin(store)
            .await
            .expect("first_admin"),
        Some(ada.id)
    );
    assert_eq!(
        UserRepo::by_id(store, ada.id).await.expect("by_id"),
        Some(ada.clone())
    );

    // A second first admin is refused whole: no account, and the marker still names the first.
    assert_eq!(
        FirstAdminRepo::insert_first_admin(store, &bob).await,
        Err(StoreError::Duplicate)
    );
    assert_eq!(UserRepo::by_id(store, bob.id).await.expect("by_id"), None);
    assert_eq!(
        FirstAdminRepo::first_admin(store)
            .await
            .expect("first_admin"),
        Some(ada.id)
    );
}

/// The first keys of an account that single sign-on made with none go in once: of two enrolments
/// at the same moment the database lets one through and the other is a duplicate.
async fn first_keys(store: &SqlStore) {
    let mut bare = user(&unique_email("first-keys"));
    bare.opaque_record = None;
    bare.wrapped_root_key = Vec::new();
    bare.public_bundle = Vec::new();
    bare.bundle_signature = Vec::new();
    bare.sealed_private_keys = Vec::new();
    bare.key_version = 0;
    UserRepo::insert(store, &bare).await.expect("insert");

    let with = |marker: u8| {
        let mut keys = bare.clone();
        keys.public_bundle = vec![marker; 3637];
        keys.bundle_signature = vec![marker; 3373];
        keys.sealed_private_keys = vec![marker; 64];
        keys.key_version = 1;
        keys.updated_at = datetime!(2026-05-06 07:08:09 UTC);
        // What the enrolment must not touch.
        keys.name = Some("Changed".to_owned());
        keys
    };
    let (first, second) = (with(0xa1), with(0xb2));
    let (one, two) = tokio::join!(
        UserRepo::set_first_keys(store, &first),
        UserRepo::set_first_keys(store, &second)
    );
    let results = [one, two];
    assert_eq!(
        results.iter().filter(|r| r.is_ok()).count(),
        1,
        "one enrolment wins: {results:?}"
    );
    assert_eq!(
        results
            .iter()
            .filter(|r| **r == Err(StoreError::Duplicate))
            .count(),
        1,
        "the other is a duplicate: {results:?}"
    );

    // The winner's keys are what is stored, whole, and nothing else of the account changed.
    let winner = if results[0].is_ok() { &first } else { &second };
    let stored = UserRepo::by_id(store, bare.id)
        .await
        .expect("by_id")
        .expect("the account");
    assert_eq!(stored.public_bundle, winner.public_bundle);
    assert_eq!(stored.bundle_signature, winner.bundle_signature);
    assert_eq!(stored.sealed_private_keys, winner.sealed_private_keys);
    assert_eq!(stored.key_version, 1);
    assert_eq!(stored.updated_at, winner.updated_at);
    assert_eq!(stored.name, bare.name, "only the key columns are written");
    assert!(stored.wrapped_root_key.is_empty() && stored.opaque_record.is_none());

    // Keys are made once, and an account that never existed is not found.
    assert_eq!(
        UserRepo::set_first_keys(store, &with(0xc3)).await,
        Err(StoreError::Duplicate)
    );
    let mut ghost = with(0xd4);
    ghost.id = UserId::random();
    assert_eq!(
        UserRepo::set_first_keys(store, &ghost).await,
        Err(StoreError::NotFound)
    );
}

async fn run_all(store: &SqlStore) {
    server_info(store).await;
    users(store).await;
    first_admin(store).await;
    first_keys(store).await;
    devices(store).await;
    tokens(store).await;
    two_factor(store).await;
    two_step_version_moves_when_a_method_is_turned_on_or_off(store).await;
    second_step_attempts_are_reserved_atomically_and_kept(store).await;
    events(store).await;
}

#[tokio::test]
async fn sqlite_in_memory() {
    run_all(&memory().await).await;
}

#[tokio::test]
async fn sqlite_in_a_file() {
    let (store, _dir) = file().await;
    run_all(&store).await;
}

#[tokio::test]
async fn postgres_when_configured() {
    if let Some(store) = external("KEMLOCK_TEST_POSTGRES_URL").await {
        run_all(&store).await;
    }
}

#[tokio::test]
async fn mysql_when_configured() {
    if let Some(store) = external("KEMLOCK_TEST_MYSQL_URL").await {
        run_all(&store).await;
    }
}

#[tokio::test]
async fn second_step_attempts_are_seen_by_another_server_on_the_same_database() {
    // Two servers (a restart, or two replicas) on one database file: what one reserved the other
    // sees, so the limit holds across them.
    let (first, dir) = file().await;
    let owner = user(&unique_email("2fa-attempts-shared"));
    UserRepo::insert(&first, &owner).await.expect("insert user");
    for _ in 0..3 {
        assert_eq!(
            SecondStepGuard::reserve_second_step(&first, owner.id, 1000, 3, 900).await,
            Ok(Reservation::Granted)
        );
    }
    let second = SqlStore::connect(&file_url(&dir.path().join("kemlock.db")))
        .await
        .expect("a second store opens the same file");
    assert_eq!(
        SecondStepGuard::reserve_second_step(&second, owner.id, 1000, 3, 900).await,
        Ok(Reservation::Wait(1)),
        "the other server's attempts count here"
    );
    // A right code on the second server clears it for the first.
    SecondStepGuard::clear_second_step(&second, owner.id)
        .await
        .expect("clear");
    assert_eq!(
        SecondStepGuard::reserve_second_step(&first, owner.id, 1000, 3, 900).await,
        Ok(Reservation::Granted)
    );
}
