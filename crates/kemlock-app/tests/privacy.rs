//! The privacy use cases over in-memory fakes: export, erasure and re-authentication, the
//! retention job, the processing summary and the incident export.

mod fakes;
mod privacy_fakes;

use fakes::*;
use kemlock_app::b64url;
use kemlock_app::error::AppError;
use kemlock_app::ports::{Clock, DeviceRepo, Event, UserRepo};
use kemlock_app::privacy::{
    AccountEraser, EraseAccount, ErasedRows, Erasure, ExportAccount, ExportIncident,
    ExportProcessingSummary, IncidentRequest, NewSignIn, NoSends, PrivacyLog, PrivacySettings,
    ProcessingInputs, PurgedTrash, Reauthenticate, Requester, RunRetention, SendEraser,
    TwoFactorInfo,
};
use kemlock_domain::privacy::{Retention, SignInEntry, SignInOutcome, StoredEvent};
use kemlock_domain::spaces::{CustomPermissions, Member, SpaceRole};
use kemlock_domain::{
    AccountMode, BlobId, Device, DeviceId, DeviceKind, Email, ItemId, KdfParams, Role, SpaceId,
    User, UserId,
};
use privacy_fakes::{FakePrivacy, FakeSends};
use std::net::IpAddr;
use time::macros::datetime;
use time::{Duration, OffsetDateTime};
use uuid::Uuid;

// ---------------------------------------------------------------------------------------------
// Builders.

fn account(email: &str) -> User {
    User {
        id: UserId::random(),
        email: Email::parse(email).expect("a valid email"),
        name: Some("Ada Lovelace".to_owned()),
        mode: AccountMode::KemlockOnly,
        role: Role::User,
        kdf: KdfParams::new_account([3; 16]),
        opaque_record: Some(vec![1; 192]),
        wrapped_root_key: vec![2; 100],
        public_bundle: vec![3; 50],
        bundle_signature: vec![4; 34],
        sealed_private_keys: vec![5; 80],
        key_version: 1,
        security_stamp: Uuid::new_v4(),
        created_at: datetime!(2026-01-02 03:04:05 UTC),
        updated_at: datetime!(2026-01-02 03:04:05 UTC),
    }
}

fn device_of(user: UserId, name: &str) -> Device {
    Device {
        id: DeviceId::random(),
        user,
        name: name.to_owned(),
        kind: DeviceKind::KemlockAndroid,
        dpop_jkt: Some("jkt".to_owned()),
        created_at: datetime!(2026-01-03 00:00 UTC),
        last_seen_at: datetime!(2026-02-03 00:00 UTC),
    }
}

type Export = ExportAccount<FakeStore, FakePrivacy, FakePrivacy, FakeEnv>;

fn export(world: &World, privacy: &FakePrivacy) -> Export {
    ExportAccount {
        users: world.store.clone(),
        data: privacy.clone(),
        log: privacy.clone(),
        clock: world.env.clone(),
    }
}

type Erase =
    EraseAccount<FakeStore, FakePrivacy, FakeSends, FakePrivacy, FakePrivacy, FakePrivacy, FakeEnv>;

fn erase(world: &World, privacy: &FakePrivacy, sends: &FakeSends) -> Erase {
    EraseAccount {
        users: world.store.clone(),
        eraser: privacy.clone(),
        sends: sends.clone(),
        files: privacy.clone(),
        settings: privacy.clone(),
        log: privacy.clone(),
        env: world.env.clone(),
    }
}

// ---------------------------------------------------------------------------------------------
// Export.

#[tokio::test]
async fn an_export_holds_the_record_and_the_vault_as_stored() {
    let world = World::new().with_signups();
    let user = make_user(&world, "ada@example.org").await;
    let privacy = FakePrivacy::new(&world.store);
    world
        .store
        .upsert(&device_of(user, "Pixel"))
        .await
        .expect("a device");
    let id = ItemId::random();
    world
        .put_item()
        .execute(&actor(user), write(user, id, None, 1))
        .await
        .expect("an item");
    // A second item, so the vault takes more than one page of the store.
    let second = ItemId::random();
    world
        .put_item()
        .execute(&actor(user), write(user, second, None, 1))
        .await
        .expect("an item");
    let ip: IpAddr = "203.0.113.77".parse().expect("ip");
    privacy
        .record_event(
            Event {
                actor: Some(user),
                device: None,
                action: "auth.sign_in",
                target: None,
                at: world.env.now(),
            },
            Some(ip),
        )
        .await
        .expect("an event");
    privacy
        .record_sign_in(NewSignIn {
            user: Some(user),
            device: None,
            method: "password",
            outcome: SignInOutcome::Success,
            at: world.env.now(),
            ip: Some(ip),
        })
        .await
        .expect("a sign-in");
    privacy.lock().two_factor.push(TwoFactorInfo {
        method: "totp".to_owned(),
        enabled: true,
        created_at: world.env.now(),
    });
    privacy.lock().memberships.push(Member::invited(
        SpaceId::random(),
        user,
        SpaceRole::Member,
        CustomPermissions::NONE,
        UserId::random(),
        world.env.now(),
    ));

    let exported = export(&world, &privacy)
        .execute(user, Requester::Account)
        .await
        .expect("the export works");
    let doc = &exported.document;

    assert_eq!(doc["format"], "kemlock-account-export/1");
    assert_eq!(doc["account"]["email"], "ada@example.org");
    assert_eq!(doc["account"]["name"], "Test Person");
    assert_eq!(doc["devices"][0]["name"], "Pixel");
    assert_eq!(doc["twoFactor"][0]["method"], "totp");
    assert_eq!(doc["spaces"][0]["role"], "member");
    // The addresses in the logs are the truncated ones.
    assert_eq!(doc["signIns"][0]["ip"], "203.0.113.0/24");
    assert_eq!(doc["events"][0]["ip"], "203.0.113.0/24");
    let items = doc["vault"]["items"].as_array().expect("an item list");
    assert_eq!(items.len(), 2);
    let stored = items
        .iter()
        .find(|i| i["id"] == id.to_string())
        .expect("the first item");
    assert_eq!(stored["ciphertext"], b64url::encode(&filler(64, 0xaa)));
    assert_eq!(stored["revision"], 1);
    // Verifiers and sealed secrets the server uses are not data the person gave it.
    let text = exported.to_json_string();
    assert!(!text.contains("opaque"), "{text}");
    assert!(exported.file_name.starts_with("kemlock-account-"));
    assert!(exported.file_name.ends_with(".json"));
}

#[tokio::test]
async fn an_export_is_logged_under_who_asked_for_it() {
    let world = World::new().with_signups();
    let user = make_user(&world, "ada@example.org").await;
    let admin = UserId::random();
    let privacy = FakePrivacy::new(&world.store);
    let exporter = export(&world, &privacy);

    exporter
        .execute(user, Requester::Account)
        .await
        .expect("self export");
    exporter
        .execute(user, Requester::Admin(admin))
        .await
        .expect("admin export");

    let events: Vec<StoredEvent> = privacy
        .events()
        .into_iter()
        .filter(|e| e.action == "account.export")
        .collect();
    assert_eq!(events.len(), 2);
    assert_eq!(events[0].actor, Some(user));
    assert_eq!(events[0].target, None);
    assert_eq!(events[1].actor, Some(admin));
    assert_eq!(events[1].target, Some(user.to_string()));
}

#[tokio::test]
async fn exporting_an_unknown_account_is_not_found() {
    let world = World::new();
    let privacy = FakePrivacy::new(&world.store);
    assert_eq!(
        export(&world, &privacy)
            .execute(UserId::random(), Requester::Account)
            .await,
        Err(AppError::NotFound)
    );
}

// ---------------------------------------------------------------------------------------------
// Erasure.

fn canned_rows(privacy: &FakePrivacy) -> (BlobId, String) {
    let blob = BlobId::random();
    let key = "cipher-1/attachment-1".to_owned();
    privacy.lock().canned = ErasedRows {
        items: 4,
        devices: 2,
        blobs: vec![blob],
        cipher_files: vec![key.clone()],
        ..ErasedRows::default()
    };
    (blob, key)
}

#[tokio::test]
async fn erasing_an_account_removes_its_rows_sends_and_files() {
    let world = World::new();
    let user = account("ada@example.org");
    world.store.put_user(user.clone());
    let privacy = FakePrivacy::new(&world.store);
    let sends = FakeSends::default();
    let (blob, key) = canned_rows(&privacy);

    let outcome = erase(&world, &privacy, &sends)
        .execute(user.id, Requester::Account)
        .await
        .expect("the erasure works");

    let Erasure::Erased(report) = outcome else {
        panic!("expected an erasure, got {outcome:?}");
    };
    assert_eq!(report.rows.items, 4);
    assert_eq!(report.sends, 2);
    assert_eq!(report.files_deleted, 2);
    assert_eq!(report.files_failed, 0);
    assert_eq!(privacy.lock().erased, vec![user.id]);
    assert_eq!(sends.0.lock().expect("lock").clone(), vec![user.id]);
    assert_eq!(privacy.lock().deleted_blobs, vec![blob]);
    assert_eq!(privacy.lock().deleted_cipher_files, vec![key]);

    // The event that says it happened names no one: not the account, not its email or name.
    let events = privacy.events();
    let event = events
        .iter()
        .find(|e| e.action == "account.erased")
        .expect("an event");
    assert_eq!(event.actor, None);
    assert_eq!(event.target, None);
}

#[tokio::test]
async fn an_admins_erasure_names_the_admin_and_ignores_the_grace_period() {
    let world = World::new();
    let user = account("ada@example.org");
    world.store.put_user(user.clone());
    let privacy = FakePrivacy::new(&world.store);
    privacy.lock().retention.deleted_account_grace_days = 14;
    let admin = UserId::random();

    let outcome = erase(&world, &privacy, &FakeSends::default())
        .execute(user.id, Requester::Admin(admin))
        .await
        .expect("the erasure works");

    assert!(matches!(outcome, Erasure::Erased(_)));
    let events = privacy.events();
    let event = events
        .iter()
        .find(|e| e.action == "account.erased")
        .expect("an event");
    assert_eq!(event.actor, Some(admin));
}

#[tokio::test]
async fn files_that_wont_delete_are_counted_not_fatal() {
    let world = World::new();
    let user = account("ada@example.org");
    world.store.put_user(user.clone());
    let privacy = FakePrivacy::new(&world.store);
    canned_rows(&privacy);
    privacy.lock().fail_files = true;

    let outcome = erase(&world, &privacy, &FakeSends::default())
        .execute(user.id, Requester::Account)
        .await
        .expect("the erasure still works");

    let Erasure::Erased(report) = outcome else {
        panic!("expected an erasure");
    };
    assert_eq!(report.files_deleted, 0);
    assert_eq!(report.files_failed, 2);
    assert_eq!(privacy.lock().erased, vec![user.id], "the rows went");
}

#[tokio::test]
async fn the_only_owner_of_a_space_with_others_must_hand_it_over_first() {
    let world = World::new();
    let user = account("ada@example.org");
    world.store.put_user(user.clone());
    let privacy = FakePrivacy::new(&world.store);
    privacy.lock().blocking = vec![SpaceId::random()];

    let refused = erase(&world, &privacy, &FakeSends::default())
        .execute(user.id, Requester::Account)
        .await;

    assert!(matches!(refused, Err(AppError::Invalid(_))), "{refused:?}");
    assert!(privacy.lock().erased.is_empty());
    assert!(world.store.user(user.id).is_some());
}

#[tokio::test]
async fn erasing_an_unknown_account_is_not_found() {
    let world = World::new();
    let privacy = FakePrivacy::new(&world.store);
    let missing = erase(&world, &privacy, &FakeSends::default())
        .execute(UserId::random(), Requester::Account)
        .await;
    assert_eq!(missing, Err(AppError::NotFound));
}

#[tokio::test]
async fn a_grace_period_schedules_the_erasure_and_ends_the_sessions() {
    let world = World::new();
    let user = account("ada@example.org");
    let stamp = user.security_stamp;
    world.store.put_user(user.clone());
    let privacy = FakePrivacy::new(&world.store);
    privacy.lock().retention.deleted_account_grace_days = 14;
    let eraser = erase(&world, &privacy, &FakeSends::default());

    let outcome = eraser
        .execute(user.id, Requester::Account)
        .await
        .expect("the request works");
    let due = world.env.now() + Duration::days(14);
    assert_eq!(outcome, Erasure::Scheduled { due });
    assert!(privacy.lock().erased.is_empty(), "nothing is erased yet");
    assert_ne!(
        world
            .store
            .user(user.id)
            .expect("still there")
            .security_stamp,
        stamp,
        "the sessions ended"
    );

    // Asking again doesn't move the date.
    world.env.clock.advance(Duration::days(3));
    assert_eq!(
        eraser.execute(user.id, Requester::Account).await,
        Ok(Erasure::Scheduled { due })
    );

    // Until it is due, the job finds nothing; then it erases.
    assert!(
        privacy
            .due_erasures(world.env.now())
            .await
            .expect("due")
            .is_empty()
    );
    world.env.clock.advance(Duration::days(12));
    let due_now = privacy.due_erasures(world.env.now()).await.expect("due");
    assert_eq!(due_now, vec![user.id]);
    let erased = eraser.erase_due(user.id).await.expect("erased");
    assert!(matches!(erased, Erasure::Erased(_)));
    assert_eq!(privacy.lock().erased, vec![user.id]);
}

#[tokio::test]
async fn a_due_erasure_is_held_while_a_space_would_be_left_with_no_owner() {
    let world = World::new();
    let user = account("ada@example.org");
    world.store.put_user(user.clone());
    let privacy = FakePrivacy::new(&world.store);
    privacy.lock().retention.deleted_account_grace_days = 14;
    let eraser = erase(&world, &privacy, &FakeSends::default());
    eraser
        .execute(user.id, Requester::Account)
        .await
        .expect("scheduled");

    // The other owner steps down during the grace period.
    world.env.clock.advance(Duration::days(15));
    privacy.lock().blocking = vec![SpaceId::random()];
    assert!(matches!(
        eraser.erase_due(user.id).await,
        Err(AppError::Invalid(_))
    ));
    assert!(privacy.lock().erased.is_empty(), "nothing was erased");

    // Once the space has an owner again, the next run erases.
    privacy.lock().blocking = Vec::new();
    assert!(matches!(
        eraser.erase_due(user.id).await,
        Ok(Erasure::Erased(_))
    ));
}

// ---------------------------------------------------------------------------------------------
// Re-authentication.

fn reauth(world: &World) -> Reauthenticate<FakeStore, FakePassword, FakeSeal, FakeEnv> {
    Reauthenticate {
        users: world.store.clone(),
        auth: world.password.clone(),
        seal: world.seal.clone(),
        clock: world.env.clone(),
    }
}

#[tokio::test]
async fn the_right_password_re_authenticates_once_bound_to_the_account_and_key() {
    let world = World::new().with_signups();
    let user = make_user(&world, "ada@example.org").await;
    let other = make_user(&world, "bob@example.org").await;
    let (state, finalization) = login_messages(&world, "ada@example.org", &PASSWORD, "jkt-1")
        .await
        .expect("both messages");

    // Another account's session can't use Ada's proof, nor another key.
    assert_eq!(
        reauth(&world)
            .execute(other, &state, &finalization, "jkt-1")
            .await,
        Err(AppError::Unauthorized)
    );
    assert_eq!(
        reauth(&world)
            .execute(user, &state, &finalization, "jkt-2")
            .await,
        Err(AppError::Unauthorized)
    );
    assert_eq!(
        reauth(&world)
            .execute(user, &state, &finalization, "jkt-1")
            .await,
        Ok(())
    );
}

#[tokio::test]
async fn a_bad_finalization_a_forged_state_or_an_old_one_is_refused() {
    let world = World::new().with_signups();
    let user = make_user(&world, "ada@example.org").await;
    let (state, finalization) = login_messages(&world, "ada@example.org", &PASSWORD, "jkt-1")
        .await
        .expect("both messages");

    let garbage = vec![9u8; finalization.len()];
    assert_eq!(
        reauth(&world)
            .execute(user, &state, &garbage, "jkt-1")
            .await,
        Err(AppError::Unauthorized)
    );
    assert!(matches!(
        reauth(&world)
            .execute(user, b"not a sealed state", &finalization, "jkt-1")
            .await,
        Err(AppError::Invalid(_))
    ));
    world.env.clock.advance(Duration::minutes(6));
    assert!(matches!(
        reauth(&world)
            .execute(user, &state, &finalization, "jkt-1")
            .await,
        Err(AppError::Invalid(_))
    ));
}

// ---------------------------------------------------------------------------------------------
// Retention.

type Retain = RunRetention<FakePrivacy, FakePrivacy, FakeStore, FakeStore, FakePrivacy, FakeEnv>;

fn retain(world: &World, privacy: &FakePrivacy) -> Retain {
    RunRetention {
        settings: privacy.clone(),
        store: privacy.clone(),
        items: world.store.clone(),
        approvals: world.store.clone(),
        files: privacy.clone(),
        clock: world.env.clone(),
    }
}

#[tokio::test]
async fn the_retention_job_cuts_each_kind_at_its_default() {
    let world = World::new().with_signups();
    let privacy = FakePrivacy::new(&world.store);
    let now = world.env.now();

    let report = retain(&world, &privacy)
        .execute()
        .await
        .expect("the job runs");

    assert_eq!(report.events, 3);
    assert_eq!(report.sign_ins, 2);
    assert_eq!(report.full_ips_dropped, 1);
    assert_eq!(report.email_log, 5);
    let calls = privacy.calls();
    let cutoff = |name: &str| {
        calls
            .iter()
            .find(|(n, _)| *n == name)
            .expect("the call was made")
            .1
    };
    assert_eq!(cutoff("events"), now - Duration::days(365));
    assert_eq!(cutoff("sign_ins"), now - Duration::days(90));
    assert_eq!(cutoff("trash"), now - Duration::days(30));
    assert_eq!(cutoff("email_log"), now - Duration::days(30));
    // Full addresses are off: any left from before go now.
    assert_eq!(cutoff("full_ips"), now);
}

#[tokio::test]
async fn a_longer_setting_moves_the_cutoffs_and_full_addresses_age_out() {
    let world = World::new();
    let privacy = FakePrivacy::new(&world.store);
    let retention = Retention {
        event_log_days: 730,
        full_ip_days: 7,
        trash_days: 90,
        ..Retention::default()
    };
    privacy.save_retention(&retention).await.expect("saved");
    let now = world.env.now();

    retain(&world, &privacy).execute().await.expect("runs");

    let calls = privacy.calls();
    let cutoff = |name: &str| calls.iter().find(|(n, _)| *n == name).expect("call").1;
    assert_eq!(cutoff("events"), now - Duration::days(730));
    assert_eq!(cutoff("full_ips"), now - Duration::days(7));
    assert_eq!(cutoff("trash"), now - Duration::days(90));
}

#[tokio::test]
async fn old_tombstones_go_and_the_files_of_purged_trash_are_deleted() {
    let world = World::new().with_signups();
    let user = make_user(&world, "ada@example.org").await;
    let privacy = FakePrivacy::new(&world.store);
    let doomed = ItemId::random();
    let kept = ItemId::random();
    for id in [doomed, kept] {
        world
            .put_item()
            .execute(&actor(user), write(user, id, None, 1))
            .await
            .expect("an item");
    }
    world
        .put_item()
        .execute(&actor(user), delete(user, doomed, 1, 2))
        .await
        .expect("a deletion");
    world.env.clock.advance(Duration::days(200));
    world
        .put_item()
        .execute(&actor(user), delete(user, kept, 1, 2))
        .await
        .expect("a later deletion");
    let blob = BlobId::random();
    privacy.lock().trash = vec![PurgedTrash {
        item: ItemId::random(),
        blobs: vec![blob],
        cipher_files: vec!["c/a".to_owned()],
    }];

    let report = retain(&world, &privacy).execute().await.expect("runs");

    assert_eq!(report.tombstones, 1, "only the 200-day-old one");
    assert!(world.store.item(doomed).is_none());
    assert!(world.store.item(kept).is_some());
    assert_eq!(report.approvals, 0);
    assert_eq!(report.trashed_items, 1);
    assert_eq!(report.files_deleted, 2);
    assert_eq!(privacy.lock().deleted_blobs, vec![blob]);
    assert_eq!(privacy.lock().deleted_cipher_files, vec!["c/a".to_owned()]);
}

// ---------------------------------------------------------------------------------------------
// The processing summary.

#[tokio::test]
async fn the_processing_summary_follows_the_settings() {
    let world = World::new();
    let privacy = FakePrivacy::new(&world.store);
    privacy.lock().inputs = ProcessingInputs {
        operator_name: Some("Example GmbH".to_owned()),
        smtp_provider: Some("smtp.example.org".to_owned()),
        s3_storage: Some("s3.example.org".to_owned()),
        push_relay: true,
        update_check: true,
        ..ProcessingInputs::default()
    };
    privacy.lock().retention.trash_days = 45;
    let summary = ExportProcessingSummary {
        source: privacy.clone(),
        settings: privacy.clone(),
        clock: world.env.clone(),
    }
    .execute()
    .await
    .expect("the summary is written");

    assert_eq!(summary.json["controller"]["name"], "Example GmbH");
    assert_eq!(
        summary.json["controller"]["dpoContact"],
        "[DPO or privacy contact: add before use]"
    );
    let names: Vec<String> = summary.json["recipients"]
        .as_array()
        .expect("recipients")
        .iter()
        .map(|r| r["name"].as_str().expect("a name").to_owned())
        .collect();
    assert_eq!(names.len(), 3);
    assert!(names.iter().any(|n| n.contains("smtp.example.org")));
    assert!(names.iter().any(|n| n.contains("push relay")));
    assert!(names.iter().any(|n| n.contains("s3.example.org")));
    let trash = summary.json["retention"]
        .as_array()
        .expect("retention")
        .iter()
        .find(|r| r["data"] == "Trash")
        .expect("the trash row");
    assert_eq!(trash["period"], "45 days");
    assert_eq!(summary.json["generatedAt"], "2026-03-01T12:00:00Z");

    let md = &summary.markdown;
    assert!(md.contains("Example GmbH"));
    assert!(md.contains("| Trash | 45 days |"));
    assert!(md.contains("Update check"), "optional processing is listed");
    assert!(!md.contains("Website icons"));
    assert!(md.contains("Art. 30"));
}

#[tokio::test]
async fn a_bare_installation_has_no_recipients_and_placeholders_for_the_operator() {
    let world = World::new();
    let privacy = FakePrivacy::new(&world.store);
    let summary = ExportProcessingSummary {
        source: privacy.clone(),
        settings: privacy.clone(),
        clock: world.env.clock.clone(),
    }
    .execute()
    .await
    .expect("the summary is written");

    assert!(
        summary.json["recipients"]
            .as_array()
            .expect("list")
            .is_empty()
    );
    assert!(
        summary.json["controller"]["name"]
            .as_str()
            .expect("name")
            .contains("add before use")
    );
    assert!(summary.markdown.contains("None outside this server."));
}

// ---------------------------------------------------------------------------------------------
// The incident export.

fn ev(actor: Option<UserId>, action: &str, at: OffsetDateTime) -> StoredEvent {
    StoredEvent {
        id: Uuid::new_v4(),
        actor,
        device: None,
        action: action.to_owned(),
        target: None,
        at,
        ip: None,
    }
}

#[tokio::test]
async fn the_incident_export_lists_accounts_window_categories_and_the_deadline() {
    let world = World::new();
    let ada = account("ada@example.org");
    world.store.put_user(ada.clone());
    let erased = UserId::random();
    let privacy = FakePrivacy::new(&world.store);
    let start = datetime!(2026-02-20 00:00 UTC);
    privacy.lock().events = vec![
        ev(
            Some(ada.id),
            "auth.sign_in",
            datetime!(2026-02-21 10:00 UTC),
        ),
        ev(
            Some(ada.id),
            "account.export",
            datetime!(2026-02-22 10:00 UTC),
        ),
        ev(Some(erased), "item.put", datetime!(2026-02-21 11:00 UTC)),
        // Outside the window.
        ev(Some(ada.id), "item.put", datetime!(2026-01-01 10:00 UTC)),
        ev(None, "setup.finish", datetime!(2026-02-21 12:00 UTC)),
    ];
    privacy.lock().sign_ins = vec![
        SignInEntry {
            id: Uuid::new_v4(),
            user: Some(ada.id),
            device: None,
            method: "password".to_owned(),
            outcome: SignInOutcome::Failure,
            at: datetime!(2026-02-21 09:00 UTC),
            ip: Some("203.0.113.0/24".to_owned()),
        },
        SignInEntry {
            id: Uuid::new_v4(),
            user: Some(ada.id),
            device: None,
            method: "password".to_owned(),
            outcome: SignInOutcome::Success,
            at: datetime!(2026-02-21 09:05 UTC),
            ip: Some("203.0.113.0/24".to_owned()),
        },
    ];
    let admin = UserId::random();
    let aware = datetime!(2026-03-01 08:00 UTC);

    let export = ExportIncident {
        users: world.store.clone(),
        log: privacy.clone(),
        clock: world.env.clone(),
    }
    .execute(
        &IncidentRequest {
            from: start,
            to: datetime!(2026-03-01 00:00 UTC),
            accounts: None,
            aware_at: Some(aware),
            extra_categories: vec!["Server logs".to_owned()],
        },
        admin,
    )
    .await
    .expect("the export works");

    assert_eq!(export.affected_accounts, 2);
    let accounts = export.json["affectedAccounts"]
        .as_array()
        .expect("accounts");
    let by_email = |email: Option<&str>| {
        accounts
            .iter()
            .find(|a| a["email"].as_str() == email)
            .expect("the account is listed")
    };
    let listed = by_email(Some("ada@example.org"));
    assert_eq!(listed["events"], 2);
    assert_eq!(listed["signIns"], 2);
    assert_eq!(listed["firstSeen"], "2026-02-21T09:00:00Z");
    assert_eq!(listed["lastSeen"], "2026-02-22T10:00:00Z");
    assert_eq!(
        by_email(None)["events"],
        1,
        "an erased account has no email"
    );
    assert_eq!(export.json["signInCounts"]["failure"], 1);
    assert_eq!(export.json["eventCounts"]["item.put"], 1);
    assert_eq!(export.json["notifyAuthorityBy"], "2026-03-04T08:00:00Z");
    let categories: Vec<&str> = export.json["dataCategories"]
        .as_array()
        .expect("categories")
        .iter()
        .filter_map(|c| c.as_str())
        .collect();
    assert!(categories.iter().any(|c| c.starts_with("Sign-in activity")));
    assert!(categories.iter().any(|c| c.starts_with("Vault metadata")));
    assert!(categories.contains(&"Server logs"));
    assert!(
        export
            .markdown
            .contains("Notify the supervisory authority by")
    );
    assert!(export.markdown.contains("(erased)"));

    // The export is itself in the log, under the admin.
    let logged = privacy
        .events()
        .into_iter()
        .find(|e| e.action == "incident.export")
        .expect("an event");
    assert_eq!(logged.actor, Some(admin));
}

#[tokio::test]
async fn an_incident_can_be_limited_to_some_accounts_and_needs_a_real_window() {
    let world = World::new();
    let ada = account("ada@example.org");
    let bob = account("bob@example.org");
    world.store.put_user(ada.clone());
    world.store.put_user(bob.clone());
    let privacy = FakePrivacy::new(&world.store);
    let at = datetime!(2026-02-21 10:00 UTC);
    privacy.lock().events = vec![
        ev(Some(ada.id), "auth.sign_in", at),
        ev(Some(bob.id), "auth.sign_in", at),
    ];
    let incident = ExportIncident {
        users: world.store.clone(),
        log: privacy.clone(),
        clock: world.env.clone(),
    };
    let window = |accounts| IncidentRequest {
        from: datetime!(2026-02-20 00:00 UTC),
        to: datetime!(2026-02-22 00:00 UTC),
        accounts,
        aware_at: None,
        extra_categories: Vec::new(),
    };

    let only_ada = incident
        .execute(&window(Some(vec![ada.id])), UserId::random())
        .await
        .expect("export");
    assert_eq!(only_ada.affected_accounts, 1);
    assert!(only_ada.json["notifyAuthorityBy"].is_null());

    let backwards = IncidentRequest {
        from: datetime!(2026-02-22 00:00 UTC),
        to: datetime!(2026-02-20 00:00 UTC),
        ..window(None)
    };
    assert!(matches!(
        incident.execute(&backwards, UserId::random()).await,
        Err(AppError::Invalid(_))
    ));
}

#[tokio::test]
async fn no_sends_store_erases_nothing() {
    assert_eq!(NoSends.erase_sends(UserId::random()).await, Ok(0));
}

#[tokio::test]
async fn the_fake_user_repo_still_holds_an_account_after_a_scheduled_request() {
    // The scheduled erasure only changes the security stamp, nothing else of the account.
    let world = World::new();
    let user = account("ada@example.org");
    world.store.put_user(user.clone());
    let privacy = FakePrivacy::new(&world.store);
    privacy.lock().retention.deleted_account_grace_days = 1;
    erase(&world, &privacy, &FakeSends::default())
        .execute(user.id, Requester::Account)
        .await
        .expect("scheduled");
    let kept = UserRepo::by_id(&world.store, user.id)
        .await
        .expect("a read")
        .expect("the account");
    assert_eq!(kept.email, user.email);
    assert_eq!(kept.name, user.name);
}

// ---------------------------------------------------------------------------------------------
// The sign-in log, as the APIs write it.

#[test]
fn a_refusal_of_the_credentials_or_the_account_is_a_failed_attempt_and_other_errors_are_not() {
    use kemlock_app::privacy::attempt_outcome;

    let ok: Result<(), AppError> = Ok(());
    assert_eq!(attempt_outcome(&ok), Some(SignInOutcome::Success));
    for refused in [
        AppError::Unauthorized,
        AppError::AccountDisabled,
        AppError::SsoRequired {
            space: SpaceId::random(),
        },
        AppError::SessionEnded("expired"),
        AppError::Forbidden,
    ] {
        let result: Result<(), AppError> = Err(refused.clone());
        assert_eq!(
            attempt_outcome(&result),
            Some(SignInOutcome::Failure),
            "{refused:?}"
        );
    }
    for not_an_attempt in [
        AppError::Invalid("bad body"),
        AppError::Store("down".to_owned()),
        AppError::NotFound,
    ] {
        let result: Result<(), AppError> = Err(not_an_attempt.clone());
        assert_eq!(attempt_outcome(&result), None, "{not_an_attempt:?}");
    }
}

#[tokio::test]
async fn a_sign_in_row_has_the_account_the_method_and_the_address_cut_on_write() {
    use kemlock_app::privacy::{record_sign_in, sign_in_entry};

    let world = World::new();
    let privacy = FakePrivacy::new(&world.store);
    let (user, device) = (UserId::random(), DeviceId::random());
    let at = world.env.now();

    let signed_in: Result<(UserId, DeviceId), AppError> = Ok((user, device));
    let entry = sign_in_entry(
        "password",
        None,
        &signed_in,
        at,
        Some("203.0.113.77".parse().expect("an address")),
        |(u, d)| (Some(*u), Some(*d)),
    );
    record_sign_in(&privacy, entry).await;

    let refused: Result<(UserId, DeviceId), AppError> = Err(AppError::Unauthorized);
    let entry = sign_in_entry(
        "two-factor",
        Some(user),
        &refused,
        at,
        Some("2001:db8:1:2::7".parse().expect("an address")),
        |(u, d)| (Some(*u), Some(*d)),
    );
    record_sign_in(&privacy, entry).await;

    let malformed: Result<(UserId, DeviceId), AppError> = Err(AppError::Invalid("bad body"));
    let entry = sign_in_entry("password", None, &malformed, at, None, |_| (None, None));
    assert_eq!(entry, None, "a malformed request leaves no row");
    record_sign_in(&privacy, entry).await;

    let rows = privacy.lock().sign_ins.clone();
    assert_eq!(rows.len(), 2);
    assert_eq!(rows[0].method, "password");
    assert_eq!(rows[0].outcome, SignInOutcome::Success);
    assert_eq!((rows[0].user, rows[0].device), (Some(user), Some(device)));
    assert_eq!(rows[0].ip.as_deref(), Some("203.0.113.0/24"));
    assert_eq!(rows[1].method, "two-factor");
    assert_eq!(rows[1].outcome, SignInOutcome::Failure);
    assert_eq!(
        (rows[1].user, rows[1].device),
        (Some(user), None),
        "a failure names the account the request named, and no device"
    );
    assert_eq!(rows[1].ip.as_deref(), Some("2001:db8:1::/48"));
}
