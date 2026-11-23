//! The unlock-side ports: ApprovalRepo, KeyCopyRepo and EmergencyRepo.
//!
//! Each scenario runs on every backend that is available, as `accounts.rs` does: in-memory SQLite,
//! SQLite in a file, and PostgreSQL and MySQL when `KEMLOCK_TEST_POSTGRES_URL` /
//! `KEMLOCK_TEST_MYSQL_URL` are set.

mod common;

use common::{device, external, file, memory, unique_email, user};
use kemlock_app::devices::{ApprovalRepo, KeyCopyRepo};
use kemlock_app::emergency::EmergencyRepo;
use kemlock_app::ports::{DeviceRepo, StoreError, UserRepo};
use kemlock_domain::unlock::{
    ApprovalId, ApprovalState, AuthRequest, DeviceKeyCopy, EmergencyGrant, EmergencyKind,
    EmergencyState, GrantId, KeyProtection,
};
use kemlock_domain::{DeviceId, DeviceKind, Email, UserId};
use kemlock_store_sql::SqlStore;
use time::macros::datetime;
use time::{Duration, OffsetDateTime};

const T0: OffsetDateTime = datetime!(2026-11-22 10:00:00 UTC);

async fn account(store: &SqlStore, prefix: &str) -> UserId {
    let account = user(&unique_email(prefix));
    UserRepo::insert(store, &account)
        .await
        .expect("insert user");
    account.id
}

fn request(user: UserId, created_at: OffsetDateTime) -> AuthRequest {
    AuthRequest {
        id: ApprovalId::random(),
        user,
        device: DeviceId::random(),
        device_name: "Firefox on Linux".to_owned(),
        device_kind: DeviceKind::KemlockWeb,
        public_key: vec![7; 1600],
        jkt: "new-device-jkt".to_owned(),
        ip: "203.0.113.0/24".to_owned(),
        state: ApprovalState::Pending,
        sealed_key: None,
        answered_at: None,
        created_at,
        expires_at: created_at + Duration::minutes(15),
    }
}

async fn approvals(store: &SqlStore) {
    let owner = account(store, "approvals").await;
    let other = account(store, "approvals-other").await;
    let first = request(owner, T0);
    let second = request(owner, T0 + Duration::minutes(2));
    let foreign = request(other, T0);
    for r in [&first, &second, &foreign] {
        ApprovalRepo::insert_request(store, r)
            .await
            .expect("insert");
    }

    // A request reads back as it was written, and an unknown id reads as none.
    assert_eq!(
        ApprovalRepo::request(store, first.id).await.expect("read"),
        Some(first.clone())
    );
    assert_eq!(
        ApprovalRepo::request(store, ApprovalId::random())
            .await
            .expect("read"),
        None
    );
    // The same id twice is refused.
    assert_eq!(
        ApprovalRepo::insert_request(store, &first).await,
        Err(StoreError::Duplicate)
    );
    // A request for an account that doesn't exist is refused too.
    assert_eq!(
        ApprovalRepo::insert_request(store, &request(UserId::random(), T0)).await,
        Err(StoreError::NotFound)
    );

    // Pending lists are per account, newest first, and drop what has expired.
    let now = T0 + Duration::minutes(5);
    assert_eq!(
        ApprovalRepo::pending_requests(store, owner, now)
            .await
            .expect("list"),
        vec![second.clone(), first.clone()]
    );
    let later = T0 + Duration::minutes(16);
    assert_eq!(
        ApprovalRepo::pending_requests(store, owner, later)
            .await
            .expect("list"),
        vec![second.clone()]
    );

    // Answering is a compare-and-set: the first answer wins.
    let mut approved = first.clone();
    approved
        .approve(vec![1, 2, 3], T0 + Duration::minutes(1))
        .expect("pending");
    assert!(
        ApprovalRepo::save_request(store, &approved, ApprovalState::Pending)
            .await
            .expect("save")
    );
    let mut denied = first.clone();
    denied.deny(T0 + Duration::minutes(1)).expect("pending");
    assert!(
        !ApprovalRepo::save_request(store, &denied, ApprovalState::Pending)
            .await
            .expect("save"),
        "the second answer finds the request already answered"
    );
    assert_eq!(
        ApprovalRepo::request(store, first.id).await.expect("read"),
        Some(approved.clone())
    );
    assert_eq!(
        ApprovalRepo::pending_requests(store, owner, now)
            .await
            .expect("list"),
        vec![second.clone()],
        "an answered request isn't pending"
    );

    // Using the approval up drops the box, once.
    let mut used = approved.clone();
    used.consume(T0 + Duration::minutes(2)).expect("approved");
    assert!(
        ApprovalRepo::save_request(store, &used, ApprovalState::Approved)
            .await
            .expect("save")
    );
    assert!(
        !ApprovalRepo::save_request(store, &used, ApprovalState::Approved)
            .await
            .expect("save")
    );
    let stored = ApprovalRepo::request(store, first.id)
        .await
        .expect("read")
        .expect("there");
    assert_eq!(stored.state, ApprovalState::Consumed);
    assert_eq!(stored.sealed_key, None);

    // The hourly count: strictly after `since`, oldest first, per account.
    assert_eq!(
        ApprovalRepo::requests_since(store, owner, T0 - Duration::hours(1))
            .await
            .expect("count"),
        vec![T0, T0 + Duration::minutes(2)]
    );
    assert_eq!(
        ApprovalRepo::requests_since(store, owner, T0)
            .await
            .expect("count"),
        vec![T0 + Duration::minutes(2)]
    );

    // Purging deletes what expired before the cut and nothing else.
    let before = T0 + Duration::minutes(16);
    let purged = ApprovalRepo::purge_requests(store, before)
        .await
        .expect("purge");
    assert!(purged >= 2, "the owner's first and the other account's");
    assert_eq!(
        ApprovalRepo::request(store, first.id).await.expect("read"),
        None
    );
    assert_eq!(
        ApprovalRepo::request(store, second.id).await.expect("read"),
        Some(second)
    );
}

async fn key_copies(store: &SqlStore) {
    let owner = account(store, "copies").await;
    let phone = device(owner, "Pixel", T0);
    let tablet = device(owner, "iPad", T0);
    DeviceRepo::upsert(store, &phone).await.expect("device");
    DeviceRepo::upsert(store, &tablet).await.expect("device");

    assert_eq!(
        KeyCopyRepo::key_copy(store, phone.id).await.expect("read"),
        None
    );
    let copy = DeviceKeyCopy {
        device: phone.id,
        wrapped_key: vec![0xc3; 92],
        protection: KeyProtection::SecureEnclave,
        created_at: T0,
        updated_at: T0,
    };
    KeyCopyRepo::put_key_copy(store, &copy).await.expect("put");
    assert_eq!(
        KeyCopyRepo::key_copy(store, phone.id).await.expect("read"),
        Some(copy.clone())
    );

    // Replacing the copy keeps the first creation time.
    let replaced = DeviceKeyCopy {
        wrapped_key: vec![0x11; 100],
        protection: KeyProtection::Keystore,
        created_at: T0 + Duration::days(2),
        updated_at: T0 + Duration::days(2),
        ..copy.clone()
    };
    KeyCopyRepo::put_key_copy(store, &replaced)
        .await
        .expect("replace");
    let stored = KeyCopyRepo::key_copy(store, phone.id)
        .await
        .expect("read")
        .expect("there");
    assert_eq!(stored.wrapped_key, vec![0x11; 100]);
    assert_eq!(stored.protection, KeyProtection::Keystore);
    assert_eq!(stored.created_at, T0);
    assert_eq!(stored.updated_at, T0 + Duration::days(2));

    // A device that doesn't exist can't hold one.
    let orphan = DeviceKeyCopy {
        device: DeviceId::random(),
        ..copy.clone()
    };
    assert_eq!(
        KeyCopyRepo::put_key_copy(store, &orphan).await,
        Err(StoreError::NotFound)
    );

    // Removing a copy leaves the device; removing the device takes its copy along.
    let tablet_copy = DeviceKeyCopy {
        device: tablet.id,
        ..copy
    };
    KeyCopyRepo::put_key_copy(store, &tablet_copy)
        .await
        .expect("put");
    KeyCopyRepo::remove_key_copy(store, phone.id)
        .await
        .expect("remove");
    assert_eq!(
        KeyCopyRepo::key_copy(store, phone.id).await.expect("read"),
        None
    );
    assert!(
        DeviceRepo::get(store, phone.id)
            .await
            .expect("read")
            .is_some()
    );
    DeviceRepo::remove(store, tablet.id)
        .await
        .expect("sign out");
    assert_eq!(
        KeyCopyRepo::key_copy(store, tablet.id).await.expect("read"),
        None,
        "the copy goes with its device"
    );
    // Removing what isn't there is fine.
    KeyCopyRepo::remove_key_copy(store, phone.id)
        .await
        .expect("remove again");
}

fn grant(grantor: UserId, contact: &str) -> EmergencyGrant {
    EmergencyGrant::invite(
        GrantId::random(),
        grantor,
        Email::parse(contact).expect("a valid email"),
        EmergencyKind::Takeover,
        7,
        T0,
    )
    .expect("a valid grant")
}

async fn emergency(store: &SqlStore) {
    let grantor = account(store, "grantor").await;
    let contact_email = unique_email("contact");
    let contact = Email::parse(&contact_email).expect("valid");
    let invited = grant(grantor, &contact_email);
    EmergencyRepo::insert_grant(store, &invited)
        .await
        .expect("insert");

    assert_eq!(
        EmergencyRepo::grant(store, invited.id).await.expect("read"),
        Some(invited.clone())
    );
    assert_eq!(
        EmergencyRepo::grant(store, GrantId::random())
            .await
            .expect("read"),
        None
    );
    // The grantor names a contact once.
    let again = grant(grantor, &contact_email);
    assert_eq!(
        EmergencyRepo::insert_grant(store, &again).await,
        Err(StoreError::Duplicate)
    );
    assert_eq!(
        EmergencyRepo::grants_of_grantor(store, grantor)
            .await
            .expect("list"),
        vec![invited.clone()]
    );
    assert_eq!(
        EmergencyRepo::grants_for_email(store, &contact)
            .await
            .expect("list"),
        vec![invited.clone()]
    );

    // Walk the grant through its states with compare-and-set saves.
    let contact_account = account(store, "contact-account").await;
    let mut grant = invited.clone();
    grant.accept(contact_account, T0).expect("invited");
    assert!(
        EmergencyRepo::save_grant(store, &grant, EmergencyState::Invited)
            .await
            .expect("save")
    );
    grant.confirm(vec![0x77; 1693], T0).expect("accepted");
    assert!(
        EmergencyRepo::save_grant(store, &grant, EmergencyState::Accepted)
            .await
            .expect("save")
    );
    let started = T0 + Duration::days(1);
    grant.initiate(started).expect("confirmed");
    assert!(
        EmergencyRepo::save_grant(store, &grant, EmergencyState::Confirmed)
            .await
            .expect("save")
    );
    assert_eq!(
        EmergencyRepo::grant(store, grant.id).await.expect("read"),
        Some(grant.clone())
    );
    assert_eq!(
        EmergencyRepo::recovering_grants(store)
            .await
            .expect("list")
            .iter()
            .filter(|g| g.id == grant.id)
            .count(),
        1
    );

    // The timer and the grantor race: whichever saves first from `RecoveryInitiated` wins.
    let mut approved = grant.clone();
    approved
        .approve_due(started + Duration::days(7))
        .expect("due");
    let mut rejected = grant.clone();
    rejected
        .reject(started + Duration::days(3))
        .expect("running");
    assert!(
        EmergencyRepo::save_grant(store, &rejected, EmergencyState::RecoveryInitiated)
            .await
            .expect("save")
    );
    assert!(
        !EmergencyRepo::save_grant(store, &approved, EmergencyState::RecoveryInitiated)
            .await
            .expect("save"),
        "the approval finds the grant already refused"
    );
    let stored = EmergencyRepo::grant(store, grant.id)
        .await
        .expect("read")
        .expect("there");
    assert_eq!(stored.state, EmergencyState::Rejected);
    assert_eq!(stored.recovery_initiated_at, None);
    assert!(
        EmergencyRepo::recovering_grants(store)
            .await
            .expect("list")
            .iter()
            .all(|g| g.id != grant.id)
    );

    EmergencyRepo::remove_grant(store, grant.id)
        .await
        .expect("remove");
    assert_eq!(
        EmergencyRepo::grant(store, grant.id).await.expect("read"),
        None
    );
    EmergencyRepo::remove_grant(store, grant.id)
        .await
        .expect("removing again is fine");
}

async fn run_all(store: &SqlStore) {
    approvals(store).await;
    key_copies(store).await;
    emergency(store).await;
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
