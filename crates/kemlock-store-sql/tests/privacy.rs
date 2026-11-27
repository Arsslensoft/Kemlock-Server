//! The privacy ports on a real `SqlStore`: retention settings, the logs and their addresses,
//! erasing an account, the retention deletes, and the copy made before migrations.

mod common;

use common::{MADE_AT, device, draft, file, file_url, memory, put, tombstone, unique_email, user};
use kemlock_app::Actor;
use kemlock_app::files::AttachmentRepo;
use kemlock_app::ports::{
    Clock, DeviceRepo, Event, EventLog, ItemStore, RefreshToken, StoreError, TokenRepo, UserRepo,
};
use kemlock_app::privacy::{
    AccountData, AccountEraser, NewSignIn, PrivacyLog, PrivacySettings, RetentionStore,
};
use kemlock_app::spaces::{
    AcceptInvitation, BundleFingerprints, ConfirmInput, ConfirmMember, CreateSpace,
    CreateSpaceInput, InviteInput, InviteMember, NewCollection, SealedCollectionKey, SpaceRepo,
};
use kemlock_domain::privacy::{Retention, SignInOutcome};
use kemlock_domain::spaces::{
    CollectionId, CollectionPermission, CustomPermissions, SEALED_KEY_LEN, SpaceRole,
};
use kemlock_domain::{
    Attachment, AttachmentId, AttachmentStatus, BlobId, DeviceId, ItemDraft, ItemFormat, ItemId,
    Owner, SpaceId, UserId,
};
use kemlock_store_sql::SqlStore;
use std::net::IpAddr;
use time::macros::datetime;
use time::{Duration, OffsetDateTime};
use uuid::Uuid;

fn ip(text: &str) -> IpAddr {
    text.parse().expect("an address")
}

fn event(actor: Option<UserId>, target: Option<&str>, at: OffsetDateTime) -> Event {
    Event {
        actor,
        device: None,
        action: "test.action",
        target: target.map(str::to_owned),
        at,
    }
}

fn sign_in(user: Option<UserId>, at: OffsetDateTime, from: Option<IpAddr>) -> NewSignIn {
    NewSignIn {
        user,
        device: None,
        method: "password",
        outcome: SignInOutcome::Success,
        at,
        ip: from,
    }
}

// ---------------------------------------------------------------------------------------------
// Settings.

#[tokio::test]
async fn retention_defaults_saves_and_refuses_values_outside_the_ranges() {
    let store = memory().await;
    assert_eq!(
        PrivacySettings::retention(&store).await,
        Ok(Retention::default())
    );

    let custom = Retention {
        trash_days: 60,
        full_ip_days: 7,
        ..Retention::default()
    };
    PrivacySettings::save_retention(&store, &custom)
        .await
        .expect("saved");
    assert_eq!(PrivacySettings::retention(&store).await, Ok(custom));

    let bad = Retention {
        trash_days: 0,
        ..Retention::default()
    };
    assert!(PrivacySettings::save_retention(&store, &bad).await.is_err());
    assert_eq!(
        PrivacySettings::retention(&store).await,
        Ok(custom),
        "a refused value changes nothing"
    );
}

#[tokio::test]
async fn an_overlay_is_applied_over_the_saved_retention_on_every_read() {
    let store = memory().await;
    let saved = Retention {
        trash_days: 60,
        ..Retention::default()
    };
    PrivacySettings::save_retention(&store, &saved)
        .await
        .expect("saved");

    // The overlay reads a value that changes, so a read always sees the latest.
    let days = std::sync::Arc::new(std::sync::atomic::AtomicU32::new(120));
    let seen = days.clone();
    store.set_retention_overlay(move |r| {
        r.event_log_days = seen.load(std::sync::atomic::Ordering::SeqCst);
    });
    let read = PrivacySettings::retention(&store).await.expect("read");
    assert_eq!(read.event_log_days, 120, "the overlay's value");
    assert_eq!(
        read.trash_days, 60,
        "what the overlay leaves is the saved value"
    );

    days.store(400, std::sync::atomic::Ordering::SeqCst);
    let read = PrivacySettings::retention(&store).await.expect("read");
    assert_eq!(read.event_log_days, 400);

    // A clone shares it, and saving stores the value as given, not the overlay's.
    let clone = store.clone();
    assert_eq!(
        PrivacySettings::retention(&clone)
            .await
            .expect("read")
            .event_log_days,
        400
    );
    PrivacySettings::save_retention(&store, &saved)
        .await
        .expect("saved again");
    let raw = store.setting("privacy.retention").await.expect("read");
    assert!(
        raw.expect("stored").contains("\"eventLogDays\":365"),
        "the stored value is untouched"
    );
}

#[tokio::test]
async fn named_settings_replace_their_value() {
    let store = memory().await;
    assert_eq!(store.setting("k").await, Ok(None));
    store.put_setting("k", "one").await.expect("saved");
    store.put_setting("k", "two").await.expect("replaced");
    assert_eq!(store.setting("k").await, Ok(Some("two".to_owned())));
}

// ---------------------------------------------------------------------------------------------
// The logs.

#[tokio::test]
async fn logs_keep_the_address_truncated_and_the_whole_one_only_while_asked() {
    let store = memory().await;
    let account = user(&unique_email("logs"));
    UserRepo::insert(&store, &account).await.expect("account");

    PrivacyLog::record_event(
        &store,
        event(Some(account.id), None, MADE_AT),
        Some(ip("203.0.113.77")),
    )
    .await
    .expect("event");
    PrivacyLog::record_event(
        &store,
        event(Some(account.id), None, MADE_AT + Duration::seconds(1)),
        Some(ip("2001:db8:1:2:3:4:5:6")),
    )
    .await
    .expect("event");
    PrivacyLog::record_sign_in(
        &store,
        sign_in(Some(account.id), MADE_AT, Some(ip("198.51.100.9"))),
    )
    .await
    .expect("sign-in");

    let events = PrivacyLog::events_of(&store, account.id)
        .await
        .expect("events");
    assert_eq!(events.len(), 2);
    assert_eq!(events[0].ip.as_deref(), Some("203.0.113.0/24"));
    assert_eq!(events[1].ip.as_deref(), Some("2001:db8:1::/48"));
    let sign_ins = PrivacyLog::sign_ins_of(&store, account.id)
        .await
        .expect("sign-ins");
    assert_eq!(sign_ins.len(), 1);
    assert_eq!(sign_ins[0].ip.as_deref(), Some("198.51.100.0/24"));
    assert_eq!(sign_ins[0].outcome, SignInOutcome::Success);

    // Full addresses are off by default: there is none to drop.
    let later = MADE_AT + Duration::days(1);
    assert_eq!(RetentionStore::drop_full_ips(&store, later).await, Ok(0));

    // Turned on, an address is kept whole beside the cut one, until it is dropped.
    PrivacySettings::save_retention(
        &store,
        &Retention {
            full_ip_days: 7,
            ..Retention::default()
        },
    )
    .await
    .expect("saved");
    PrivacyLog::record_event(
        &store,
        event(Some(account.id), None, MADE_AT),
        Some(ip("203.0.113.5")),
    )
    .await
    .expect("event");
    PrivacyLog::record_sign_in(
        &store,
        sign_in(Some(account.id), MADE_AT, Some(ip("203.0.113.5"))),
    )
    .await
    .expect("sign-in");
    assert_eq!(
        RetentionStore::drop_full_ips(&store, MADE_AT - Duration::days(1)).await,
        Ok(0),
        "too new to drop"
    );
    assert_eq!(RetentionStore::drop_full_ips(&store, later).await, Ok(2));
    assert_eq!(RetentionStore::drop_full_ips(&store, later).await, Ok(0));
    // What stays is the cut address.
    let events = PrivacyLog::events_of(&store, account.id)
        .await
        .expect("events");
    assert!(events.iter().all(|e| {
        e.ip.as_deref()
            .is_some_and(|i| i.ends_with("/24") || i.ends_with("/48"))
    }));
}

#[tokio::test]
async fn events_and_sign_ins_are_read_by_window() {
    let store = memory().await;
    let account = user(&unique_email("window"));
    UserRepo::insert(&store, &account).await.expect("account");
    let day = |n: i64| MADE_AT + Duration::days(n);
    for n in [0, 1, 2, 3] {
        PrivacyLog::record_event(&store, event(Some(account.id), None, day(n)), None)
            .await
            .expect("event");
        PrivacyLog::record_sign_in(&store, sign_in(Some(account.id), day(n), None))
            .await
            .expect("sign-in");
    }
    let inside = PrivacyLog::events_between(&store, day(1), day(3))
        .await
        .expect("events");
    assert_eq!(inside.len(), 2, "from included, to excluded");
    let signed = PrivacyLog::sign_ins_between(&store, day(1), day(3))
        .await
        .expect("sign-ins");
    assert_eq!(signed.len(), 2);
}

#[tokio::test]
async fn the_retention_deletes_remove_only_what_is_older_than_the_cutoff() {
    let store = memory().await;
    let account = user(&unique_email("purge"));
    UserRepo::insert(&store, &account).await.expect("account");
    let old = datetime!(2025-01-01 00:00 UTC);
    PrivacyLog::record_event(&store, event(Some(account.id), None, old), None)
        .await
        .expect("old event");
    PrivacyLog::record_event(&store, event(Some(account.id), None, MADE_AT), None)
        .await
        .expect("new event");
    PrivacyLog::record_sign_in(&store, sign_in(Some(account.id), old, None))
        .await
        .expect("old sign-in");
    PrivacyLog::record_sign_in(&store, sign_in(Some(account.id), MADE_AT, None))
        .await
        .expect("new sign-in");

    let cutoff = datetime!(2026-01-01 00:00 UTC);
    assert_eq!(RetentionStore::purge_events(&store, cutoff).await, Ok(1));
    assert_eq!(RetentionStore::purge_sign_ins(&store, cutoff).await, Ok(1));
    assert_eq!(
        PrivacyLog::events_of(&store, account.id)
            .await
            .expect("events")
            .len(),
        1
    );
    assert_eq!(
        PrivacyLog::sign_ins_of(&store, account.id)
            .await
            .expect("sign-ins")
            .len(),
        1
    );
    assert_eq!(
        RetentionStore::purge_email_log(&store, cutoff).await,
        Ok(0),
        "no email log here"
    );
}

// ---------------------------------------------------------------------------------------------
// The trash.

fn bw_item(id: ItemId, owner: Owner, cipher: &str) -> ItemDraft {
    ItemDraft {
        format: ItemFormat::Bw,
        key_version: 0,
        ciphertext: Some(cipher.as_bytes().to_vec()),
        item_key: None,
        ..draft(id, owner, None, 1)
    }
}

fn attachment(item: ItemId, owner: Owner, blob: BlobId) -> Attachment {
    Attachment {
        id: AttachmentId(Uuid::new_v4()),
        item,
        owner,
        blob,
        size: 100,
        status: AttachmentStatus::Ready,
        created_at: MADE_AT,
    }
}

#[tokio::test]
async fn trash_older_than_the_cutoff_becomes_a_tombstone_with_its_files() {
    let store = memory().await;
    let owner = Owner::User(UserId::random());
    let trashed = ItemId::random();
    let recent = ItemId::random();
    let live = ItemId::random();
    let kemlock = ItemId::random();
    put(
        &store,
        bw_item(
            trashed,
            owner,
            r#"{"id":"cipher-1","deletedDate":"2026-01-01T00:00:00.000000Z","attachments":[{"id":"att-1"}]}"#,
        ),
    )
    .await;
    put(
        &store,
        bw_item(
            recent,
            owner,
            r#"{"id":"cipher-2","deletedDate":"2026-05-30T00:00:00.000000Z"}"#,
        ),
    )
    .await;
    put(
        &store,
        bw_item(live, owner, r#"{"id":"cipher-3","deletedDate":null}"#),
    )
    .await;
    // A Kemlock item's trash is sealed: the server can't tell, and leaves it.
    put(&store, draft(kemlock, owner, None, 1)).await;
    let blob = BlobId::random();
    AttachmentRepo::add(&store, &attachment(trashed, owner, blob))
        .await
        .expect("an attachment");

    let purged = RetentionStore::purge_trash(&store, datetime!(2026-03-01 00:00 UTC), MADE_AT)
        .await
        .expect("the purge runs");

    assert_eq!(purged.len(), 1);
    assert_eq!(purged[0].item, trashed);
    assert_eq!(purged[0].cipher_files, vec!["cipher-1/att-1".to_owned()]);
    assert_eq!(purged[0].blobs, vec![blob]);
    let stored = ItemStore::get(&store, trashed)
        .await
        .expect("a read")
        .expect("the tombstone");
    assert!(stored.is_tombstone());
    assert_eq!(stored.ciphertext, None);
    assert_eq!(stored.revision.0, 2);
    for kept in [recent, live, kemlock] {
        let item = ItemStore::get(&store, kept)
            .await
            .expect("a read")
            .expect("still there");
        assert!(!item.is_tombstone(), "{kept}");
    }

    // It doesn't run twice over the same item.
    assert!(
        RetentionStore::purge_trash(&store, datetime!(2026-03-01 00:00 UTC), MADE_AT)
            .await
            .expect("the purge runs")
            .is_empty()
    );
}

// ---------------------------------------------------------------------------------------------
// Erasure.

#[derive(Clone, Copy)]
struct FixedClock;

impl Clock for FixedClock {
    fn now(&self) -> OffsetDateTime {
        MADE_AT
    }
}

#[derive(Clone, Copy)]
struct FirstBytes;

impl BundleFingerprints for FirstBytes {
    fn fingerprint(&self, bundle: &[u8]) -> Option<[u8; 64]> {
        bundle.get(..64).and_then(|b| <[u8; 64]>::try_from(b).ok())
    }

    /// Any signature of the right length, which is what `confirm` below makes: these tests are of
    /// the store, not of `sig1`.
    fn verify_confirmation(
        &self,
        _confirmer_bundle: &[u8],
        _facts: &kemlock_app::spaces::ConfirmationFacts<'_>,
        _statement: &[u8],
        signature: &[u8],
    ) -> bool {
        signature.len() == 3373
    }
}

/// Any key box signature of the right length: these tests are of the store, not of `sig1`.
#[derive(Clone, Copy)]
struct AnySignature;

impl kemlock_app::spaces::KeyBoxVerifier for AnySignature {
    async fn verify(
        &self,
        _facts: &kemlock_app::spaces::KeyBoxFacts<'_>,
        _signature: &[u8],
    ) -> Result<u32, kemlock_app::spaces::SpacesError> {
        Ok(1)
    }
}

fn sealed_key(fill: u8) -> Vec<u8> {
    let mut key = vec![fill; SEALED_KEY_LEN];
    key[0] = 1;
    key
}

fn actor_of(user: UserId) -> Actor {
    Actor {
        user,
        device: DeviceId::random(),
        admin: false,
    }
}

struct Person {
    user: kemlock_domain::User,
    fingerprint: Vec<u8>,
}

async fn person(store: &SqlStore, seed: u8, email: &str, name: &str) -> Person {
    let mut account = user(email);
    account.name = Some(name.to_owned());
    account.public_bundle = vec![seed; 200];
    UserRepo::insert(store, &account).await.expect("account");
    Person {
        fingerprint: account.public_bundle[..64].to_vec(),
        user: account,
    }
}

async fn make_space(store: &SqlStore, owner: UserId) -> (SpaceId, CollectionId) {
    let space = SpaceId::random();
    let collection = CollectionId::random();
    CreateSpace {
        spaces: store.clone(),
        events: store.clone(),
        clock: FixedClock,
        boxes: AnySignature,
    }
    .execute(
        &actor_of(owner),
        CreateSpaceInput {
            id: space,
            name: vec![1; 40],
            sealed_space_key: sealed_key(2),
            space_key_signature: vec![0x55; 3373],
            collection: NewCollection {
                id: collection,
                name: vec![3; 40],
                sealed_key: sealed_key(4),
                key_signature: vec![0x55; 3373],
            },
        },
    )
    .await
    .expect("the space is made");
    (space, collection)
}

/// `owner` invites `member`, who accepts, and `owner` confirms them.
async fn join(
    store: &SqlStore,
    space: SpaceId,
    collection: CollectionId,
    owner: &Person,
    member: &Person,
) {
    InviteMember {
        spaces: store.clone(),
        users: store.clone(),
        events: store.clone(),
        clock: FixedClock,
    }
    .execute(
        &actor_of(owner.user.id),
        space,
        InviteInput {
            email: member.user.email.as_str().to_owned(),
            role: SpaceRole::Member,
            custom: CustomPermissions::NONE,
            grants: vec![(collection, CollectionPermission::Edit)],
        },
    )
    .await
    .expect("invited");
    AcceptInvitation {
        spaces: store.clone(),
        events: store.clone(),
        clock: FixedClock,
    }
    .execute(&actor_of(member.user.id), space)
    .await
    .expect("accepted");
    ConfirmMember {
        spaces: store.clone(),
        users: store.clone(),
        fingerprints: FirstBytes,
        events: store.clone(),
        clock: FixedClock,
        boxes: AnySignature,
    }
    .execute(
        &actor_of(owner.user.id),
        space,
        member.user.id,
        ConfirmInput {
            fingerprint: member.fingerprint.clone(),
            statement: b"compared".to_vec(),
            signature: vec![0x55; 3373],
            sealed_space_key: sealed_key(5),
            space_key_signature: vec![0x55; 3373],
            collection_keys: vec![SealedCollectionKey {
                collection,
                user: member.user.id,
                sealed: sealed_key(6),
                signature: vec![0x55; 3373],
            }],
        },
    )
    .await
    .expect("confirmed");
}

#[tokio::test]
async fn erasing_an_account_removes_what_is_its_and_leaves_everyone_else() {
    let store = memory().await;
    let ada = person(&store, 1, &unique_email("ada"), "Ada Lovelace").await;
    let bob = person(&store, 2, &unique_email("bob"), "Bob Barker").await;
    let ada_id = ada.user.id;
    let ada_email = ada.user.email.as_str().to_owned();

    // Ada's data: a device with a token, items (one a Bitwarden cipher with a file), a file row
    // of the Kemlock API, logs, a scheduled erasure.
    let phone = device(ada_id, "Pixel", MADE_AT);
    DeviceRepo::upsert(&store, &phone).await.expect("device");
    TokenRepo::insert(
        &store,
        &RefreshToken {
            hash: [7; 32],
            family: Uuid::new_v4(),
            user: ada_id,
            device: phone.id,
            security_stamp: ada.user.security_stamp,
            created_at: MADE_AT,
            expires_at: MADE_AT + Duration::days(30),
            used_at: None,
        },
    )
    .await
    .expect("token");
    let ada_owner = Owner::User(ada_id);
    let item_one = ItemId::random();
    let item_two = ItemId::random();
    let cipher = ItemId::random();
    put(&store, draft(item_one, ada_owner, None, 1)).await;
    put(&store, draft(item_two, ada_owner, None, 1)).await;
    put(
        &store,
        bw_item(
            cipher,
            ada_owner,
            r#"{"id":"c-ada","attachments":[{"id":"a-1"}]}"#,
        ),
    )
    .await;
    let ada_blob = BlobId::random();
    AttachmentRepo::add(&store, &attachment(item_one, ada_owner, ada_blob))
        .await
        .expect("attachment");
    // Bob's item must survive.
    let bobs_item = ItemId::random();
    put(&store, draft(bobs_item, Owner::User(bob.user.id), None, 1)).await;

    PrivacyLog::record_event(
        &store,
        event(
            Some(ada_id),
            Some(&format!(
                "invited {} (Ada Lovelace)",
                ada_email.to_uppercase()
            )),
            MADE_AT,
        ),
        Some(ip("203.0.113.9")),
    )
    .await
    .expect("event");
    PrivacyLog::record_event(
        &store,
        event(
            Some(bob.user.id),
            Some(&format!("invited {ada_email}")),
            MADE_AT,
        ),
        Some(ip("198.51.100.1")),
    )
    .await
    .expect("event");
    PrivacyLog::record_event(
        &store,
        event(Some(bob.user.id), Some("unrelated"), MADE_AT),
        None,
    )
    .await
    .expect("event");
    PrivacyLog::record_sign_in(
        &store,
        sign_in(Some(ada_id), MADE_AT, Some(ip("203.0.113.9"))),
    )
    .await
    .expect("sign-in");
    PrivacyLog::record_sign_in(
        &store,
        sign_in(Some(bob.user.id), MADE_AT, Some(ip("198.51.100.1"))),
    )
    .await
    .expect("sign-in");
    AccountEraser::schedule_erasure(&store, ada_id, MADE_AT, MADE_AT + Duration::days(7))
        .await
        .expect("scheduled");

    // Spaces: Ada is alone in one, and a plain member of Bob's.
    let (alone, _) = make_space(&store, ada_id).await;
    let (shared, shared_collection) = make_space(&store, bob.user.id).await;
    join(&store, shared, shared_collection, &bob, &ada).await;
    assert!(
        AccountEraser::blocking_spaces(&store, ada_id)
            .await
            .expect("blocking")
            .is_empty(),
        "a member, or alone, is never blocked"
    );

    let rows = AccountEraser::erase_user(&store, &ada.user)
        .await
        .expect("the erasure works");

    assert_eq!(rows.items, 3);
    assert_eq!(rows.devices, 1);
    assert_eq!(rows.refresh_tokens, 1);
    assert_eq!(rows.sign_ins, 1);
    assert_eq!(rows.spaces_removed, 1);
    assert_eq!(rows.space_memberships, 1);
    assert_eq!(rows.blobs, vec![ada_blob]);
    assert_eq!(rows.cipher_files, vec!["c-ada/a-1".to_owned()]);
    assert!(rows.events_scrubbed >= 3, "{rows:?}");

    // Ada is gone, with her vault, devices, logs, schedule and spaces.
    assert_eq!(UserRepo::by_id(&store, ada_id).await, Ok(None));
    for id in [item_one, item_two, cipher] {
        assert_eq!(
            ItemStore::get(&store, id).await.map(|i| i.is_some()),
            Ok(false)
        );
    }
    assert_eq!(DeviceRepo::list(&store, ada_id).await, Ok(Vec::new()));
    assert_eq!(
        AttachmentRepo::by_id(&store, attachment(item_one, ada_owner, ada_blob).id).await,
        Ok(None)
    );
    assert!(
        PrivacyLog::sign_ins_of(&store, ada_id)
            .await
            .expect("sign-ins")
            .is_empty()
    );
    assert_eq!(
        AccountEraser::scheduled_erasure(&store, ada_id).await,
        Ok(None)
    );
    assert!(
        SpaceRepo::load(&store, alone)
            .await
            .expect("a read")
            .is_none()
    );
    assert!(
        SpaceRepo::memberships(&store, ada_id)
            .await
            .expect("memberships")
            .is_empty()
    );

    // Her events keep no name, email or address; Bob's mention of her is cut too.
    // (The space use cases wrote events of her own as well; they hold only ids.)
    let hers: Vec<_> = PrivacyLog::events_of(&store, ada_id)
        .await
        .expect("events")
        .into_iter()
        .filter(|e| e.action == "test.action")
        .collect();
    assert_eq!(hers.len(), 1);
    assert_eq!(
        hers[0].target.as_deref(),
        Some("invited [erased] ([erased])")
    );
    assert_eq!(hers[0].ip, None);
    let bobs: Vec<_> = PrivacyLog::events_of(&store, bob.user.id)
        .await
        .expect("events")
        .into_iter()
        .filter(|e| e.action == "test.action")
        .collect();
    let mention = bobs
        .iter()
        .find(|e| {
            e.target
                .as_deref()
                .is_some_and(|t| t.starts_with("invited"))
        })
        .expect("Bob's event");
    assert_eq!(mention.target.as_deref(), Some("invited [erased]"));
    assert_eq!(
        mention.ip.as_deref(),
        Some("198.51.100.0/24"),
        "Bob's own address stays"
    );
    assert!(
        bobs.iter()
            .any(|e| e.target.as_deref() == Some("unrelated"))
    );

    // Bob, his item, his sign-in and his space are untouched, minus Ada's place in it.
    assert!(
        UserRepo::by_id(&store, bob.user.id)
            .await
            .expect("a read")
            .is_some()
    );
    assert!(
        ItemStore::get(&store, bobs_item)
            .await
            .expect("a read")
            .is_some()
    );
    assert_eq!(
        PrivacyLog::sign_ins_of(&store, bob.user.id)
            .await
            .expect("sign-ins")
            .len(),
        1
    );
    let state = SpaceRepo::load(&store, shared)
        .await
        .expect("a read")
        .expect("Bob's space is still there");
    assert!(state.members.iter().all(|m| m.user != ada_id));
    assert!(state.members.iter().any(|m| m.user == bob.user.id));

    // Erasing twice finds nothing.
    assert_eq!(
        AccountEraser::erase_user(&store, &ada.user).await,
        Err(StoreError::NotFound)
    );
}

#[tokio::test]
async fn the_only_owner_of_a_space_with_others_is_blocked() {
    let store = memory().await;
    let ada = person(&store, 1, &unique_email("ada"), "Ada Lovelace").await;
    let bob = person(&store, 2, &unique_email("bob"), "Bob Barker").await;
    let (space, collection) = make_space(&store, ada.user.id).await;
    assert!(
        AccountEraser::blocking_spaces(&store, ada.user.id)
            .await
            .expect("blocking")
            .is_empty(),
        "alone in it, there is no one to leave stranded"
    );
    join(&store, space, collection, &ada, &bob).await;

    assert_eq!(
        AccountEraser::blocking_spaces(&store, ada.user.id).await,
        Ok(vec![space])
    );
    assert_eq!(
        AccountEraser::blocking_spaces(&store, bob.user.id).await,
        Ok(Vec::new()),
        "a plain member is never blocked"
    );
}

#[tokio::test]
async fn a_scheduled_erasure_is_due_when_its_time_comes_and_can_be_cancelled() {
    let store = memory().await;
    let id = UserId::random();
    let due = MADE_AT + Duration::days(7);
    AccountEraser::schedule_erasure(&store, id, MADE_AT, due)
        .await
        .expect("scheduled");
    assert_eq!(
        AccountEraser::scheduled_erasure(&store, id).await,
        Ok(Some(due))
    );
    assert_eq!(
        AccountEraser::due_erasures(&store, due - Duration::seconds(1)).await,
        Ok(Vec::new())
    );
    assert_eq!(AccountEraser::due_erasures(&store, due).await, Ok(vec![id]));

    // Asking again moves the date.
    let later = due + Duration::days(1);
    AccountEraser::schedule_erasure(&store, id, MADE_AT, later)
        .await
        .expect("rescheduled");
    assert_eq!(
        AccountEraser::scheduled_erasure(&store, id).await,
        Ok(Some(later))
    );

    AccountEraser::cancel_erasure(&store, id)
        .await
        .expect("cancelled");
    assert_eq!(AccountEraser::scheduled_erasure(&store, id).await, Ok(None));
}

// ---------------------------------------------------------------------------------------------
// What an export reads.

#[tokio::test]
async fn the_export_reads_devices_the_whole_vault_and_two_step_methods() {
    let store = memory().await;
    let account = user(&unique_email("export"));
    UserRepo::insert(&store, &account).await.expect("account");
    DeviceRepo::upsert(&store, &device(account.id, "Pixel", MADE_AT))
        .await
        .expect("device");
    let owner = Owner::User(account.id);
    // More items than a page of the export reads.
    for _ in 0..3 {
        put(&store, draft(ItemId::random(), owner, None, 1)).await;
    }
    let devices = AccountData::devices(&store, account.id)
        .await
        .expect("devices");
    assert_eq!(devices.len(), 1);
    let vault = AccountData::vault(&store, account.id).await.expect("vault");
    assert_eq!(vault.len(), 3);
    assert!(
        vault.iter().all(|i| i.ciphertext.is_some()),
        "as stored, ciphertext included"
    );
    assert!(
        AccountData::two_factor(&store, account.id)
            .await
            .expect("2fa")
            .is_empty()
    );
    assert!(
        AccountData::memberships(&store, account.id)
            .await
            .expect("spaces")
            .is_empty()
    );
}

// ---------------------------------------------------------------------------------------------
// The copy made before migrations.

async fn forget_last_migration(url: &str) {
    let db = sea_orm::Database::connect(url)
        .await
        .expect("a raw connection");
    sea_orm::ConnectionTrait::execute_unprepared(
        &db,
        "DELETE FROM seaql_migrations WHERE version = 'm20261123_080001_privacy'",
    )
    .await
    .expect("the migration is forgotten");
    db.close().await.expect("closed");
}

#[tokio::test]
async fn a_new_database_is_not_copied_but_an_older_one_is_before_it_migrates() {
    let dir = tempfile::tempdir().expect("a temp dir");
    let url = file_url(&dir.path().join("db.sqlite3"));
    let backups = dir.path().join("backups");

    // A new database has nothing to lose.
    let store = SqlStore::connect(&url).await.expect("a new database");
    let account = user(&unique_email("kept"));
    UserRepo::insert(&store, &account).await.expect("account");
    store.close().await.expect("closed");
    assert!(
        !backups.exists(),
        "no copy of a database that was just made"
    );

    // The same database with a migration still to run is copied first.
    forget_last_migration(&url).await;
    let store = SqlStore::connect(&url).await.expect("an upgrade");
    store.close().await.expect("closed");
    let copy = kemlock_store_sql::pre_migration_path(&dir.path().join("db.sqlite3"));
    assert!(copy.exists(), "{} should exist", copy.display());
    assert!(copy.starts_with(&backups));

    // The copy is a database of its own, with the account in it.
    let copied = SqlStore::connect(&file_url(&copy))
        .await
        .expect("the copy opens");
    assert!(
        UserRepo::by_id(&copied, account.id)
            .await
            .expect("a read")
            .is_some()
    );
    copied.close().await.expect("closed");
}

#[tokio::test]
async fn a_database_in_a_file_that_is_up_to_date_makes_no_copy() {
    let (store, dir) = file().await;
    store.close().await.expect("closed");
    let url = file_url(&dir.path().join("kemlock.db"));
    let again = SqlStore::connect(&url).await.expect("reopened");
    again.close().await.expect("closed");
    assert!(!dir.path().join("backups").exists());
}

#[tokio::test]
async fn an_erased_accounts_tombstones_go_with_it_and_not_after_their_180_days() {
    let store = memory().await;
    let ada = person(&store, 1, &unique_email("ada"), "Ada Lovelace").await;
    let bob = person(&store, 2, &unique_email("bob"), "Bob Barker").await;
    let ada_owner = Owner::User(ada.user.id);
    let gone = ItemId::random();
    let bobs = ItemId::random();
    put(&store, draft(gone, ada_owner, None, 1)).await;
    // Deleted a day ago: far inside the 180 days a tombstone is otherwise kept.
    put(
        &store,
        tombstone(gone, ada_owner, Some(1), 2, MADE_AT - Duration::days(1)),
    )
    .await;
    put(&store, draft(bobs, Owner::User(bob.user.id), None, 1)).await;
    put(
        &store,
        tombstone(
            bobs,
            Owner::User(bob.user.id),
            Some(1),
            2,
            MADE_AT - Duration::days(1),
        ),
    )
    .await;
    assert!(
        ItemStore::get(&store, gone)
            .await
            .expect("a read")
            .expect("the tombstone")
            .is_tombstone()
    );

    let rows = AccountEraser::erase_user(&store, &ada.user)
        .await
        .expect("the erasure works");

    assert_eq!(rows.items, 1, "the tombstone is a row of the account");
    assert_eq!(
        ItemStore::get(&store, gone).await.map(|i| i.is_some()),
        Ok(false)
    );
    assert!(
        ItemStore::purged_through(&store, &[ada_owner])
            .await
            .expect("a horizon")
            .is_empty()
    );
    assert!(
        ItemStore::get(&store, bobs)
            .await
            .expect("a read")
            .is_some_and(|i| i.is_tombstone()),
        "another account's tombstone waits out its own period"
    );
}

#[tokio::test]
async fn an_event_written_while_a_request_is_served_carries_its_truncated_address() {
    let store = memory().await;
    let actor = UserId::random();
    kemlock_store_sql::with_request_ip(Some(ip("203.0.113.9")), async {
        EventLog::record(&store, event(Some(actor), None, MADE_AT)).await
    })
    .await
    .expect("an event in a request");
    EventLog::record(
        &store,
        event(Some(actor), None, MADE_AT + Duration::seconds(1)),
    )
    .await
    .expect("an event outside any request");

    let events = PrivacyLog::events_of(&store, actor).await.expect("events");
    assert_eq!(events.len(), 2);
    assert_eq!(events[0].ip.as_deref(), Some("203.0.113.0/24"));
    assert_eq!(events[1].ip, None, "no request, no address");
}

#[tokio::test]
async fn an_events_whole_address_is_kept_only_while_the_admin_keeps_full_addresses() {
    let store = memory().await;
    let actor = UserId::random();
    let in_request = |at: OffsetDateTime| {
        kemlock_store_sql::with_request_ip(Some(ip("203.0.113.9")), {
            let store = store.clone();
            async move { EventLog::record(&store, event(Some(actor), None, at)).await }
        })
    };
    in_request(MADE_AT).await.expect("an event");
    PrivacySettings::save_retention(
        &store,
        &Retention {
            full_ip_days: 7,
            ..Retention::default()
        },
    )
    .await
    .expect("saved");
    in_request(MADE_AT + Duration::seconds(1))
        .await
        .expect("an event");

    // Both rows keep the truncated address; the whole one exists only on the second, and the
    // retention job's drop removes it once it is old enough.
    let dropped = RetentionStore::drop_full_ips(&store, MADE_AT + Duration::days(30))
        .await
        .expect("drop");
    assert_eq!(
        dropped, 1,
        "only the row written under the 7-day setting had one"
    );
    let events = PrivacyLog::events_of(&store, actor).await.expect("events");
    assert!(
        events
            .iter()
            .all(|e| e.ip.as_deref() == Some("203.0.113.0/24"))
    );
}

#[tokio::test]
async fn a_pending_erasure_is_what_sign_in_asks_and_an_admin_can_cancel_it() {
    use kemlock_app::admin::AdminUserRepo;

    let store = memory().await;
    let ada = person(&store, 1, &unique_email("ada"), "Ada Lovelace").await;
    let bob = person(&store, 2, &unique_email("bob"), "Bob Barker").await;
    let due = MADE_AT + Duration::days(7);
    assert_eq!(
        UserRepo::erasure_pending(&store, ada.user.id).await,
        Ok(None)
    );

    AccountEraser::schedule_erasure(&store, ada.user.id, MADE_AT, due)
        .await
        .expect("scheduled");
    assert_eq!(
        UserRepo::erasure_pending(&store, ada.user.id).await,
        Ok(Some(due))
    );
    assert_eq!(
        UserRepo::erasure_pending(&store, bob.user.id).await,
        Ok(None),
        "only the account that asked"
    );

    assert_eq!(
        AdminUserRepo::cancel_pending_erasure(&store, ada.user.id).await,
        Ok(true)
    );
    assert_eq!(
        UserRepo::erasure_pending(&store, ada.user.id).await,
        Ok(None)
    );
    assert_eq!(
        AdminUserRepo::cancel_pending_erasure(&store, ada.user.id).await,
        Ok(false),
        "nothing left to cancel"
    );

    // An admin deleting an account takes its schedule with it, so the retention job never finds a
    // due erasure for an account that is gone.
    AccountEraser::schedule_erasure(&store, bob.user.id, MADE_AT, due)
        .await
        .expect("scheduled");
    AdminUserRepo::erase_user(&store, bob.user.id)
        .await
        .expect("erased");
    assert_eq!(
        AccountEraser::scheduled_erasure(&store, bob.user.id).await,
        Ok(None)
    );
}

#[tokio::test]
async fn the_last_admin_is_never_erased_and_one_of_two_admins_can_be() {
    let store = memory().await;
    let mut first = user(&unique_email("admin-one"));
    first.role = kemlock_domain::Role::Admin;
    let mut second = user(&unique_email("admin-two"));
    second.role = kemlock_domain::Role::Admin;
    let plain = user(&unique_email("plain"));
    for account in [&first, &second, &plain] {
        UserRepo::insert(&store, account).await.expect("insert");
    }

    // A person who is no admin goes whatever the admins are doing.
    AccountEraser::erase_user(&store, &plain)
        .await
        .expect("an ordinary account can be erased");
    // One of two admins goes...
    AccountEraser::erase_user(&store, &first)
        .await
        .expect("one of two admins can be erased");
    // ...and the one that is left is refused, inside the erasing transaction: nothing is erased.
    let refused = AccountEraser::erase_user(&store, &second).await;
    assert_eq!(
        refused,
        Err(StoreError::Backend(
            kemlock_app::privacy::LAST_ADMIN.to_owned()
        ))
    );
    assert!(
        UserRepo::by_id(&store, second.id)
            .await
            .expect("lookup")
            .is_some(),
        "the last admin is still there"
    );
}
