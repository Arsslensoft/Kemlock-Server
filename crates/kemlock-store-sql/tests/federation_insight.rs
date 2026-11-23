//! What the admin console shows beyond the federation rows, on SQL: the vaults homed here with
//! their owner and size, when a server last wrote to one, and the descriptor and mismatch records
//! of a peer, which go with the peer.

mod common;

use common::{MADE_AT, draft, memory, put, tombstone, user};
use kemlock_app::ports::{ServerInfo, UserRepo};
use kemlock_domain::{ItemId, Owner, ServerId};
use kemlock_federation::extra::FedAdminRepo;
use kemlock_federation::insight::{MismatchRecord, PeerSecurityRecord};
use kemlock_federation::ports::{Peer, PeerRepo, PeerState};

#[tokio::test]
async fn the_vaults_homed_here_are_listed_with_owner_and_size() {
    let store = memory().await;
    let ada = user("ada@example.org");
    let bob = user("bob@example.org");
    UserRepo::insert(&store, &ada).await.expect("ada");
    UserRepo::insert(&store, &bob).await.expect("bob");
    let vault = Owner::User(ada.id);
    put(&store, draft(ItemId::random(), vault, None, 1)).await;
    put(&store, draft(ItemId::random(), vault, None, 1)).await;
    let gone = ItemId::random();
    put(&store, draft(gone, vault, None, 1)).await;
    put(&store, tombstone(gone, vault, Some(1), 2, MADE_AT)).await;

    let listed = store.local_vaults().await.expect("the vaults");
    let ada_row = listed
        .iter()
        .find(|v| v.vault == vault)
        .expect("ada's vault");
    assert_eq!(ada_row.owner_email.as_deref(), Some("ada@example.org"));
    assert_eq!(ada_row.members, 1);
    assert_eq!(
        ada_row.size_bytes, 80,
        "two live items of 40 bytes; the tombstone has none"
    );
    let bob_row = listed
        .iter()
        .find(|v| v.vault == Owner::User(bob.id))
        .expect("bob's vault");
    assert_eq!(bob_row.size_bytes, 0);

    let one = store.vault_info(vault).await.expect("one").expect("known");
    assert_eq!(one, *ada_row);
    let stranger = Owner::User(kemlock_domain::UserId::random());
    assert_eq!(store.vault_info(stranger).await.expect("none"), None);
}

#[tokio::test]
async fn the_newest_change_of_an_origin_is_found() {
    let store = memory().await;
    let ada = user("ada@example.org");
    UserRepo::insert(&store, &ada).await.expect("ada");
    let vault = Owner::User(ada.id);
    put(&store, draft(ItemId::random(), vault, None, 1)).await;
    let here = ServerInfo::server_id(&store);

    let at = store
        .newest_change_from(vault, here)
        .await
        .expect("a lookup")
        .expect("a change");
    assert_eq!(at, u64::try_from(MADE_AT.unix_timestamp()).expect("a time"));
    assert_eq!(
        store
            .newest_change_from(vault, ServerId::random())
            .await
            .expect("a lookup"),
        None
    );
}

fn peer(id: ServerId) -> Peer {
    Peer {
        id,
        operator: "Other".to_owned(),
        identity_key: vec![1; 32],
        addresses: vec!["https://other.example.org".to_owned()],
        suites: vec![],
        state: PeerState::Paired,
        paired_at: 1_800_000_000,
        last_seen: None,
    }
}

#[tokio::test]
async fn descriptor_and_mismatch_records_are_kept_replaced_and_forgotten_with_the_peer() {
    let store = memory().await;
    let id = ServerId::random();
    PeerRepo::insert_peer(&store, &peer(id))
        .await
        .expect("a peer");

    assert_eq!(store.peer_security(id).await.expect("none"), None);
    let mut security = PeerSecurityRecord {
        peer: id,
        descriptor: vec![7; 20],
        fetched_at: 1_800_000_100,
        kem_key_id: vec![3; 32],
        kem_first_seen: 1_800_000_100,
        suite: None,
    };
    store.put_peer_security(&security).await.expect("kept");
    security.fetched_at += 60;
    security.suite = Some("kfed1-mlkem1024x25519-aes256gcm".to_owned());
    store.put_peer_security(&security).await.expect("replaced");
    assert_eq!(
        store.peer_security(id).await.expect("read"),
        Some(security.clone())
    );

    let mut mismatch = MismatchRecord {
        peer: id,
        offered_key: vec![9; 32],
        first_at: 1_800_000_200,
        last_at: 1_800_000_200,
        attempts: 1,
        source: "https://other.example.org".to_owned(),
        kept_blocking_at: None,
        kept_blocking_by: None,
    };
    store.put_mismatch(&mismatch).await.expect("kept");
    mismatch.attempts = 4;
    mismatch.last_at = 1_800_000_500;
    mismatch.kept_blocking_at = Some(1_800_000_600);
    mismatch.kept_blocking_by = Some("an admin".to_owned());
    store.put_mismatch(&mismatch).await.expect("replaced");
    assert_eq!(store.mismatch(id).await.expect("read"), Some(mismatch));

    assert!(PeerRepo::remove_peer(&store, id).await.expect("removed"));
    assert_eq!(store.peer_security(id).await.expect("gone"), None);
    assert_eq!(store.mismatch(id).await.expect("gone"), None);
}
