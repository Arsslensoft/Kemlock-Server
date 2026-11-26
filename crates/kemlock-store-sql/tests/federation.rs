//! The federation ports on SQL: peers, vault settings, cursors and home records round-trip, and
//! replicating versions between two stores gives the same heads, siblings and outcomes as the
//! in-memory store: duplicates ignored, a conflict kept as siblings, a merge that replaces both.

mod common;

use common::{draft, memory, put, user_owner};
use kemlock_app::ports::StoreError;
use kemlock_domain::{ChangeId, Hlc, ItemId, Owner, Revision, ServerId, VersionVector};
use kemlock_federation::change::ChangeRecord;
use kemlock_federation::home::{HomeRecord, VaultFederation};
use kemlock_federation::ports::{
    ApplyOutcome, HomeStatus, LogSwitches, Peer, PeerRepo, PeerState, ReplicaStore,
    StoredHomeRecord, VaultRepo,
};
use kemlock_federation::wire::ChangeKey;
use kemlock_store_sql::SqlStore;
use time::Duration;

fn peer(n: u8) -> Peer {
    Peer {
        id: ServerId(uuid::Uuid::from_bytes([n; 16])),
        operator: format!("Operator {n}"),
        identity_key: vec![n; 1984],
        addresses: vec![format!("https://s{n}.example.org")],
        suites: vec!["kfed1-mlkem1024x25519-aes256gcm".to_owned()],
        state: PeerState::Paired,
        paired_at: 1_800_000_000,
        last_seen: None,
    }
}

#[tokio::test]
async fn peers_round_trip_and_their_state_and_switches_change() {
    let store = memory().await;
    let p = peer(1);
    store.insert_peer(&p).await.expect("insert");
    assert!(matches!(
        store.insert_peer(&p).await,
        Err(StoreError::Duplicate)
    ));
    assert_eq!(store.get_peer(p.id).await.expect("get"), Some(p.clone()));
    assert_eq!(store.get_peer(ServerId::random()).await.expect("get"), None);

    store.insert_peer(&peer(2)).await.expect("insert");
    assert_eq!(store.list_peers().await.expect("list").len(), 2);

    store
        .set_peer_state(p.id, PeerState::Revoked)
        .await
        .expect("state");
    store.touch_peer(p.id, 1_800_000_500).await.expect("touch");
    let got = store.get_peer(p.id).await.expect("get").expect("there");
    assert_eq!(got.state, PeerState::Revoked);
    assert_eq!(got.last_seen, Some(1_800_000_500));
    assert!(matches!(
        store
            .set_peer_state(ServerId::random(), PeerState::Paired)
            .await,
        Err(StoreError::NotFound)
    ));

    assert_eq!(
        store.log_switches(p.id).await.expect("switches"),
        LogSwitches::default()
    );
    let on = LogSwitches {
        send: true,
        pull: false,
    };
    store.set_log_switches(p.id, on).await.expect("set");
    assert_eq!(store.log_switches(p.id).await.expect("switches"), on);
    let both = LogSwitches {
        send: true,
        pull: true,
    };
    store.set_log_switches(p.id, both).await.expect("set again");
    assert_eq!(store.log_switches(p.id).await.expect("switches"), both);

    assert!(store.remove_peer(p.id).await.expect("remove"));
    assert!(!store.remove_peer(p.id).await.expect("remove again"));
    assert_eq!(store.get_peer(p.id).await.expect("get"), None);
}

#[tokio::test]
async fn vault_settings_cursors_and_home_records_round_trip() {
    let store = memory().await;
    let vault = user_owner();
    assert_eq!(store.get_vault(vault).await.expect("get"), None);
    let mut settings = VaultFederation::federated(
        vault,
        ServerId::random(),
        vec![ServerId::random(), ServerId::random()],
    );
    store.put_vault(&settings).await.expect("put");
    assert_eq!(
        store.get_vault(vault).await.expect("get"),
        Some(settings.clone())
    );
    // A promotion replaces the row.
    settings.epoch = 2;
    settings.promotion = Some(vec![9, 9]);
    settings.home_history = vec![(1, ServerId::random())];
    settings.replicas.reverse();
    store.put_vault(&settings).await.expect("put again");
    assert_eq!(
        store.get_vault(vault).await.expect("get"),
        Some(settings.clone())
    );
    assert_eq!(
        store.list_vaults().await.expect("list"),
        vec![settings.clone()]
    );

    let peer_id = ServerId::random();
    assert!(
        store
            .peer_cursor(peer_id, vault)
            .await
            .expect("cursor")
            .is_empty()
    );
    let mut cursor = VersionVector::new();
    cursor.observe(&ChangeId {
        origin: ServerId::random(),
        seq: 12,
        hlc: Hlc(1),
    });
    store
        .set_peer_cursor(peer_id, vault, &cursor)
        .await
        .expect("set");
    assert_eq!(
        store.peer_cursor(peer_id, vault).await.expect("cursor"),
        cursor
    );
    cursor.observe(&ChangeId {
        origin: ServerId::random(),
        seq: 3,
        hlc: Hlc(1),
    });
    store
        .set_peer_cursor(peer_id, vault, &cursor)
        .await
        .expect("set again");
    assert_eq!(
        store.peer_cursor(peer_id, vault).await.expect("cursor"),
        cursor
    );

    let record = |index: u64, epoch: u64, status: HomeStatus| StoredHomeRecord {
        signed: vec![index as u8; 20],
        record: HomeRecord {
            vault,
            index,
            epoch,
            kind: "member-added".to_owned(),
            payload: vec![1, 2, 3],
            signer: settings.home,
        },
        status,
    };
    assert!(
        store
            .put_home_record(&record(1, 1, HomeStatus::Applied))
            .await
            .expect("put")
    );
    assert!(
        !store
            .put_home_record(&record(1, 1, HomeStatus::Applied))
            .await
            .expect("again")
    );
    assert!(
        store
            .put_home_record(&record(2, 1, HomeStatus::Quarantined))
            .await
            .expect("put")
    );
    assert!(
        store
            .put_home_record(&record(3, 2, HomeStatus::Applied))
            .await
            .expect("put")
    );
    let after_one = store.home_records(vault, 1, 10).await.expect("records");
    assert_eq!(
        after_one.iter().map(|r| r.record.index).collect::<Vec<_>>(),
        vec![2, 3]
    );
    assert_eq!(
        store
            .home_records(vault, 0, 2)
            .await
            .expect("records")
            .len(),
        2
    );
    let held = store.quarantined(vault).await.expect("quarantined");
    assert_eq!(held.len(), 1);
    assert_eq!(held[0].record.index, 2);
}

/// What replication would send for the head and siblings of `owner`'s items on `from`.
async fn records_of(from: &SqlStore, owner: Owner) -> Vec<(ChangeRecord, Vec<u8>)> {
    let page = ReplicaStore::export_since(from, owner, &VersionVector::new(), 100)
        .await
        .expect("export");
    page.entries
        .into_iter()
        .map(|e| {
            (
                ChangeRecord::from_item(&e.item, e.lineage),
                e.signature.unwrap_or_else(|| b"signature".to_vec()),
            )
        })
        .collect()
}

async fn apply_all(to: &SqlStore, records: &[(ChangeRecord, Vec<u8>)]) -> Vec<ApplyOutcome> {
    let mut outcomes = Vec::new();
    for (record, signature) in records {
        outcomes.push(
            ReplicaStore::apply(to, record, signature)
                .await
                .expect("apply"),
        );
    }
    outcomes
}

#[tokio::test]
async fn replicated_versions_apply_once_conflict_into_siblings_and_resolve() {
    let a = memory().await;
    let b = memory().await;
    let owner = user_owner();
    let id = ItemId::random();

    // A writes revision 1; B applies it, and a second application is a duplicate.
    put(&a, draft(id, owner, None, 1)).await;
    let first = records_of(&a, owner).await;
    assert_eq!(apply_all(&b, &first).await, vec![ApplyOutcome::Applied]);
    assert_eq!(apply_all(&b, &first).await, vec![ApplyOutcome::Duplicate]);
    let at_b = kemlock_app::ports::ItemStore::get(&b, id)
        .await
        .expect("get")
        .expect("item");
    assert_eq!(at_b.change, first[0].0.change);

    // Both servers accept an edit while apart; B's is later.
    let mut edit_a = draft(id, owner, Some(1), 2);
    edit_a.ciphertext = Some(vec![0xA; 40]);
    put(&a, edit_a).await;
    let mut edit_b = draft(id, owner, Some(1), 2);
    edit_b.ciphertext = Some(vec![0xB; 40]);
    edit_b.updated_at += Duration::seconds(5);
    put(&b, edit_b).await;

    let from_a = records_of(&a, owner).await;
    let from_b = records_of(&b, owner).await;
    // At B the later version is already the head, so A's edit becomes its sibling; at A the
    // later version arrives and takes over as head, and A's own edit is demoted.
    assert_eq!(apply_all(&b, &from_a).await, vec![ApplyOutcome::Sibling]);
    assert_eq!(apply_all(&a, &from_b).await, vec![ApplyOutcome::Applied]);

    // Both agree on the head and on the one sibling.
    let head_a = kemlock_app::ports::ItemStore::get(&a, id)
        .await
        .expect("get")
        .expect("head");
    let head_b = kemlock_app::ports::ItemStore::get(&b, id)
        .await
        .expect("get")
        .expect("head");
    assert_eq!(head_a.change, head_b.change);
    assert_eq!(head_a.ciphertext, Some(vec![0xB; 40]));
    let sibs_a = ReplicaStore::siblings(&a, owner, id)
        .await
        .expect("siblings");
    let sibs_b = ReplicaStore::siblings(&b, owner, id)
        .await
        .expect("siblings");
    assert_eq!((sibs_a.len(), sibs_b.len()), (1, 1));
    assert_eq!(sibs_a[0].change, sibs_b[0].change);
    assert_eq!(sibs_a[0].ciphertext, Some(vec![0xA; 40]));

    // Both stores report every version they hold, and the summaries agree.
    assert_eq!(
        ReplicaStore::leaves(&a, owner).await.expect("leaves"),
        ReplicaStore::leaves(&b, owner).await.expect("leaves")
    );
    assert_eq!(
        ReplicaStore::latest(&a, owner).await.expect("latest"),
        ReplicaStore::latest(&b, owner).await.expect("latest")
    );
    // The page a device would sync (heads only) is unchanged by siblings; replication's page
    // also lists the sibling.
    let page = ReplicaStore::export_since(&a, owner, &VersionVector::new(), 100)
        .await
        .expect("export");
    assert_eq!(page.entries.len(), 2);
    let small = ReplicaStore::export_since(&a, owner, &VersionVector::new(), 1)
        .await
        .expect("export");
    assert!(small.more);
    assert_eq!(small.entries.len(), 1);

    // A merge written on B replaces both; B marks the siblings replaced and A applies it.
    let mut merged = draft(id, owner, Some(2), 3);
    merged.ciphertext = Some(vec![0xC; 40]);
    merged.updated_at += Duration::seconds(10);
    put(&b, merged).await;
    assert_eq!(
        ReplicaStore::resolve_siblings(&b, owner, id)
            .await
            .expect("resolve"),
        1
    );
    assert!(
        ReplicaStore::siblings(&b, owner, id)
            .await
            .expect("siblings")
            .is_empty()
    );
    let from_b = records_of(&b, owner).await;
    let merged_record = from_b
        .iter()
        .find(|(r, _)| r.revision == Revision(3))
        .expect("the merged version is exported");
    assert!(
        merged_record.0.lineage.len() >= 3,
        "{:?}",
        merged_record.0.lineage
    );
    assert_eq!(
        apply_all(&a, std::slice::from_ref(merged_record)).await,
        vec![ApplyOutcome::Applied]
    );
    assert!(
        ReplicaStore::siblings(&a, owner, id)
            .await
            .expect("siblings")
            .is_empty()
    );
    let head = kemlock_app::ports::ItemStore::get(&a, id)
        .await
        .expect("get")
        .expect("head");
    assert_eq!(head.revision, Revision(3));

    // A version that was replaced never comes back, even from a server that still sends it.
    assert_eq!(apply_all(&a, &from_a).await, vec![ApplyOutcome::Duplicate]);
    assert!(
        ReplicaStore::siblings(&a, owner, id)
            .await
            .expect("siblings")
            .is_empty()
    );
}

#[tokio::test]
async fn a_signature_is_kept_once_and_an_item_id_of_another_owner_is_refused() {
    let a = memory().await;
    let b = memory().await;
    let owner = user_owner();
    let id = ItemId::random();
    let item = put(&a, draft(id, owner, None, 1)).await;
    let key = ChangeKey::of(&item.change);
    ReplicaStore::store_signature(&a, key, &[], b"first")
        .await
        .expect("store");
    ReplicaStore::store_signature(&a, key, &[], b"second")
        .await
        .expect("store");
    let page = ReplicaStore::export_since(&a, owner, &VersionVector::new(), 10)
        .await
        .expect("export");
    assert_eq!(page.entries[0].signature.as_deref(), Some(&b"first"[..]));

    // B already holds that id under another owner: the record is refused as taken.
    put(&b, draft(id, user_owner(), None, 1)).await;
    let records = records_of(&a, owner).await;
    let outcome = ReplicaStore::apply(&b, &records[0].0, &records[0].1).await;
    assert!(matches!(outcome, Err(StoreError::Duplicate)));
}

/// A peer's record with an HLC time at the top of the range used to raise `last_hlc` to it, and
/// the next local write then took a time the column can't hold: every write failed, across
/// restarts. The clock stops at the limit now, and the start-up repair sets it back.
#[tokio::test]
async fn a_record_with_a_huge_hlc_time_neither_stops_local_writes_nor_survives_a_restart() {
    let (store, dir) = common::file().await;
    let source = memory().await;
    let owner = user_owner();
    put(&source, draft(ItemId::random(), owner, None, 1)).await;
    let (mut record, signature) = records_of(&source, owner).await.remove(0);
    record.change.hlc = Hlc(u64::MAX >> 1);
    assert_eq!(
        ReplicaStore::apply(&store, &record, &signature)
            .await
            .expect("apply"),
        ApplyOutcome::Applied
    );

    // The clock is at the limit: a local write still goes through, at the limit.
    let written = put(&store, draft(ItemId::random(), user_owner(), None, 1)).await;
    assert_eq!(written.change.hlc, Hlc::MAX);

    // After a restart the clock is back at the wall clock.
    let url = common::file_url(&dir.path().join("kemlock.db"));
    drop(store);
    let store = SqlStore::connect(&url).await.expect("reconnect");
    let written = put(&store, draft(ItemId::random(), user_owner(), None, 1)).await;
    let now_ms = u64::try_from(time::OffsetDateTime::now_utc().unix_timestamp() * 1000)
        .expect("a time after 1970");
    assert!(
        written.change.hlc.millis() <= now_ms + 60_000,
        "the repaired clock is near the wall clock, not at {}",
        written.change.hlc.millis()
    );
    assert!(written.change.hlc.millis() >= now_ms - 60_000);
}

#[tokio::test]
async fn a_promotion_is_held_unless_the_saved_setting_says_auto() {
    use kemlock_federation::extra::{FedAdminRepo, PromotionMode};
    let store = memory().await;
    assert_eq!(store.promotion_mode().await, Ok(PromotionMode::Hold));
    store
        .put_setting("setting.federation_promotion", "auto")
        .await
        .expect("saved");
    assert_eq!(store.promotion_mode().await, Ok(PromotionMode::Auto));
    // Anything else, a misspelling included, holds.
    store
        .put_setting("setting.federation_promotion", "atuo")
        .await
        .expect("saved");
    assert_eq!(store.promotion_mode().await, Ok(PromotionMode::Hold));
}

#[tokio::test]
async fn past_keys_and_pending_addresses_are_kept_per_peer_and_go_with_the_peer() {
    use kemlock_federation::keyrecs::{KeyStore, PendingAddresses};
    let store = memory().await;
    let p = peer(1);
    store.insert_peer(&p).await.expect("insert");
    assert!(store.past_keys(p.id).await.expect("keys").is_empty());

    store
        .push_past_key(p.id, &[1; 1984], 100)
        .await
        .expect("push");
    store
        .push_past_key(p.id, &[2; 1984], 200)
        .await
        .expect("push");
    let kept = store.past_keys(p.id).await.expect("keys");
    assert_eq!(
        kept.iter()
            .map(|k| (k.key[0], k.replaced_at))
            .collect::<Vec<_>>(),
        vec![(1, 100), (2, 200)],
        "oldest first"
    );

    let pending = PendingAddresses {
        peer: p.id,
        operator: "Operator 1".to_owned(),
        addresses: vec!["https://moved.example.org".to_owned()],
        suites: vec!["kfed1-mlkem1024x25519-aes256gcm".to_owned()],
        received_at: 300,
    };
    store.put_pending_addresses(&pending).await.expect("put");
    assert_eq!(
        store.pending_addresses(p.id).await,
        Ok(Some(pending.clone()))
    );
    assert_eq!(
        store.list_pending_addresses().await,
        Ok(vec![pending.clone()])
    );
    // A second change replaces the first.
    let newer = PendingAddresses {
        received_at: 400,
        ..pending
    };
    store.put_pending_addresses(&newer).await.expect("replace");
    assert_eq!(store.list_pending_addresses().await, Ok(vec![newer]));
    store.clear_pending_addresses(p.id).await.expect("clear");
    assert_eq!(store.pending_addresses(p.id).await, Ok(None));

    // Unpairing forgets the history, so a later pairing starts clean.
    store
        .put_pending_addresses(&PendingAddresses {
            peer: p.id,
            operator: String::new(),
            addresses: Vec::new(),
            suites: Vec::new(),
            received_at: 500,
        })
        .await
        .expect("put");
    assert!(store.remove_peer(p.id).await.expect("remove"));
    assert!(store.past_keys(p.id).await.expect("keys").is_empty());
    assert_eq!(store.list_pending_addresses().await, Ok(Vec::new()));
}

#[tokio::test]
async fn the_addresses_the_admin_chose_are_kept_per_peer_and_go_with_the_peer() {
    use kemlock_federation::extra::FedAdminRepo;
    let store = memory().await;
    let p = peer(1);
    store.insert_peer(&p).await.expect("insert");
    assert!(
        store
            .trusted_addresses(p.id)
            .await
            .expect("read")
            .is_empty()
    );
    let lan = "http://192.168.1.5:8080".to_owned();
    let public = "https://s1.example.org".to_owned();
    store
        .trust_addresses(p.id, &[lan.clone(), public.clone()])
        .await
        .expect("trust");
    // Again, and with a blank: no duplicates, nothing empty.
    store
        .trust_addresses(p.id, &[lan.clone(), String::new()])
        .await
        .expect("trust again");
    assert_eq!(
        store.trusted_addresses(p.id).await,
        Ok(vec![lan.clone(), public.clone()]),
        "sorted, once each"
    );
    assert!(
        store
            .trusted_addresses(ServerId::random())
            .await
            .expect("read")
            .is_empty()
    );
    assert!(store.remove_peer(p.id).await.expect("remove"));
    assert!(
        store
            .trusted_addresses(p.id)
            .await
            .expect("read")
            .is_empty()
    );
}

fn signature_of(writer: kemlock_domain::UserId, fill: u8) -> kemlock_domain::WriteSignature {
    kemlock_domain::WriteSignature {
        writer,
        key_version: 1,
        signature: vec![fill; kemlock_domain::WriteSignature::SIGNATURE_LEN],
    }
}

#[tokio::test]
async fn a_writer_signature_travels_with_a_version_and_the_flag_is_set_only_by_the_owner() {
    use kemlock_app::ports::ItemStore;
    let a = memory().await;
    let b = memory().await;
    let writer = kemlock_domain::UserId::random();
    let owner = Owner::User(writer);
    let id = ItemId::random();
    let mut signed = draft(id, owner, None, 1);
    signed.signature = Some(signature_of(writer, 7));
    put(&a, signed).await;
    // A signature does not set the flag, here or at the peer.
    assert!(
        !ItemStore::signed_writes_required(&a, owner)
            .await
            .expect("flag")
    );
    assert!(
        !ReplicaStore::owner_signed_only(&b, owner)
            .await
            .expect("flag")
    );

    // The signature is in the record, and applying it keeps it and sets the flag at B.
    let records = records_of(&a, owner).await;
    assert_eq!(records[0].0.write, Some(signature_of(writer, 7)));
    assert_eq!(apply_all(&b, &records).await, vec![ApplyOutcome::Applied]);
    let held = ItemStore::get(&b, id).await.expect("get").expect("item");
    assert_eq!(held.signature, Some(signature_of(writer, 7)));
    assert!(
        !ReplicaStore::owner_signed_only(&b, owner)
            .await
            .expect("flag")
    );
    // The flag is the owner's to set, and a peer takes it from the home.
    ReplicaStore::set_owner_signed_only(&b, owner, true)
        .await
        .expect("set");
    assert!(
        ReplicaStore::owner_signed_only(&b, owner)
            .await
            .expect("flag")
    );
    ReplicaStore::set_owner_signed_only(&b, owner, false)
        .await
        .expect("cleared");
    assert!(
        !ReplicaStore::owner_signed_only(&b, owner)
            .await
            .expect("flag")
    );

    // A sibling keeps its signature too.
    let mut edit_a = draft(id, owner, Some(1), 2);
    edit_a.signature = Some(signature_of(writer, 8));
    put(&a, edit_a).await;
    let mut edit_b = draft(id, owner, Some(1), 2);
    edit_b.signature = Some(signature_of(writer, 9));
    edit_b.updated_at += Duration::seconds(5);
    put(&b, edit_b).await;
    let from_a = records_of(&a, owner).await;
    assert!(
        apply_all(&b, &from_a)
            .await
            .contains(&ApplyOutcome::Sibling)
    );
    let siblings = ReplicaStore::siblings(&b, owner, id)
        .await
        .expect("siblings");
    assert_eq!(siblings.len(), 1);
    assert_eq!(siblings[0].signature, Some(signature_of(writer, 8)));
}

#[tokio::test]
async fn a_record_that_names_the_head_at_a_lower_revision_is_refused_and_leaves_no_trace() {
    use kemlock_app::ports::ItemStore;
    let a = memory().await;
    let owner = user_owner();
    let id = ItemId::random();
    put(&a, draft(id, owner, None, 1)).await;
    put(&a, draft(id, owner, Some(1), 2)).await;
    let head = put(&a, draft(id, owner, Some(2), 3)).await;

    let mut replay = ChangeRecord::from_item(&head, vec![ChangeKey::of(&head.change)]);
    replay.change = ChangeId {
        origin: ServerId::random(),
        seq: 1,
        hlc: Hlc(head.change.hlc.0 + 1_000_000),
    };
    replay.revision = Revision(2);
    assert_eq!(
        ReplicaStore::apply(&a, &replay, b"signature")
            .await
            .expect("apply"),
        ApplyOutcome::Refused
    );
    let held = ItemStore::get(&a, id).await.expect("get").expect("item");
    assert_eq!(held.change, head.change);
    assert_eq!(held.revision, Revision(3));
}

#[tokio::test]
async fn a_record_that_changes_an_items_format_or_kind_is_refused() {
    use kemlock_app::ports::ItemStore;
    let a = memory().await;
    let owner = user_owner();
    let id = ItemId::random();
    put(&a, draft(id, owner, None, 1)).await;
    let head = put(&a, draft(id, owner, Some(1), 2)).await;

    // A later change that names the head and labels the item `bw` (so no writer check would look
    // at it), or gives it another kind, is refused and leaves the item as it was.
    let mut relabelled = ChangeRecord::from_item(&head, vec![ChangeKey::of(&head.change)]);
    relabelled.change = ChangeId {
        origin: ServerId::random(),
        seq: 1,
        hlc: Hlc(head.change.hlc.0 + 1_000_000),
    };
    relabelled.revision = Revision(3);
    relabelled.format = kemlock_domain::ItemFormat::Bw;
    assert_eq!(
        ReplicaStore::apply(&a, &relabelled, b"signature").await.expect("apply"),
        ApplyOutcome::Refused
    );
    let mut other_kind = relabelled.clone();
    other_kind.format = head.format;
    other_kind.kind = kemlock_domain::ItemKind::try_from("note".to_owned()).expect("a kind");
    other_kind.change.seq = 2;
    assert_eq!(
        ReplicaStore::apply(&a, &other_kind, b"signature").await.expect("apply"),
        ApplyOutcome::Refused
    );
    let held = ItemStore::get(&a, id).await.expect("get").expect("item");
    assert_eq!(held.change, head.change);
    assert_eq!(held.format, kemlock_domain::ItemFormat::Kem1);
}
