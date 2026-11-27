//! The event logs behind the per-peer switches, on SQL: the events of a vault's members are read in
//! id order and in pages, what a peer sent is kept once, and it goes with the peer.

mod common;

use common::{memory, user};
use kemlock_app::ports::{Event, EventLog, UserRepo};
use kemlock_domain::{Owner, ServerId};
use kemlock_federation::eventsync::{EventSync, LogEntry};
use time::macros::datetime;

fn entry(n: u8) -> LogEntry {
    let mut id = [0u8; 16];
    id[15] = n;
    LogEntry {
        id,
        at_ms: 1_800_000_000_000 + u64::from(n),
        actor: Some([9; 16]),
        device: None,
        action: "login".to_owned(),
        target: Some(format!("target {n}")),
    }
}

#[tokio::test]
async fn the_events_of_a_vaults_members_are_read_in_pages() {
    let store = memory().await;
    let member = user("member@example.org");
    let stranger = user("stranger@example.org");
    UserRepo::insert(&store, &member).await.expect("a member");
    UserRepo::insert(&store, &stranger)
        .await
        .expect("a stranger");
    for (actor, action) in [
        (member.id, "login"),
        (stranger.id, "login"),
        (member.id, "item.create"),
        (member.id, "logout"),
    ] {
        EventLog::record(
            &store,
            Event {
                actor: Some(actor),
                device: None,
                action,
                target: None,
                at: datetime!(2026-06-01 12:00:00 UTC),
            },
        )
        .await
        .expect("an event");
        // Event ids are UUID v7: they sort by the millisecond they are made in.
        tokio::time::sleep(std::time::Duration::from_millis(3)).await;
    }
    let vault = Owner::User(member.id);

    let all = EventSync::vault_events(&store, vault, [0; 16], 100)
        .await
        .expect("events");
    let actions: Vec<&str> = all.iter().map(|e| e.action.as_str()).collect();
    assert_eq!(
        actions,
        ["login", "item.create", "logout"],
        "the stranger's is not the vault's"
    );
    assert!(all.windows(2).all(|w| w[0].id < w[1].id));
    assert!(all.iter().all(|e| e.actor == Some(*member.id.0.as_bytes())));

    // A page after an id starts after it.
    let first = EventSync::vault_events(&store, vault, [0; 16], 1)
        .await
        .expect("a page");
    assert_eq!(first.len(), 1);
    let rest = EventSync::vault_events(&store, vault, first[0].id, 100)
        .await
        .expect("the rest");
    assert_eq!(rest.len(), 2);
    assert_eq!(rest[0].action, "item.create");

    // A space, or a vault nobody holds, has no member events here.
    let nobody = Owner::User(user("nobody@example.org").id);
    assert!(
        EventSync::vault_events(&store, nobody, [0; 16], 100)
            .await
            .expect("events")
            .is_empty()
    );
}

#[tokio::test]
async fn what_a_peer_sent_is_kept_once_and_goes_with_the_peer() {
    let store = memory().await;
    let peer = ServerId::random();
    let other = ServerId::random();
    let vault = Owner::User(user("v@example.org").id);

    assert_eq!(
        EventSync::peer_events_cursor(&store, peer, vault)
            .await
            .expect("cursor"),
        [0; 16]
    );
    let page = vec![entry(1), entry(2), entry(3)];
    assert_eq!(
        EventSync::store_peer_events(&store, peer, vault, &page)
            .await
            .expect("stored"),
        3
    );
    assert_eq!(
        EventSync::store_peer_events(&store, peer, vault, &page)
            .await
            .expect("stored"),
        0,
        "the same events are kept once"
    );
    EventSync::store_peer_events(&store, other, vault, &[entry(1)])
        .await
        .expect("stored");
    assert_eq!(
        EventSync::peer_events_cursor(&store, peer, vault)
            .await
            .expect("cursor"),
        entry(3).id
    );
    assert_eq!(
        EventSync::peer_events_cursor(&store, other, vault)
            .await
            .expect("cursor"),
        entry(1).id,
        "the cursor is per peer"
    );

    let held = EventSync::peer_events(&store, vault, 100)
        .await
        .expect("events");
    assert_eq!(held.len(), 4);
    assert_eq!(held[0].entry.id, entry(3).id, "newest first");
    assert_eq!(held[0].entry.target.as_deref(), Some("target 3"));
    assert_eq!(
        EventSync::peer_events(&store, vault, 2)
            .await
            .expect("events")
            .len(),
        2
    );

    assert_eq!(
        EventSync::forget_peer_events(&store, peer)
            .await
            .expect("forgotten"),
        3
    );
    let left = EventSync::peer_events(&store, vault, 100)
        .await
        .expect("events");
    assert_eq!(left.len(), 1);
    assert_eq!(left[0].from, other);
}

#[tokio::test]
async fn a_peer_that_sends_events_without_end_keeps_only_the_newest_ones() {
    let store = memory().await;
    let peer = ServerId::random();
    let vault = Owner::User(kemlock_domain::UserId::random());
    let numbered = |n: u32| {
        let mut id = [0u8; 16];
        id[12..].copy_from_slice(&n.to_be_bytes());
        LogEntry {
            id,
            at_ms: 1_800_000_000_000 + u64::from(n),
            actor: None,
            device: None,
            action: "login".to_owned(),
            target: None,
        }
    };
    // 10,050 events in pages of 500, a little over the 10,000 the store keeps for one peer.
    let total = 10_050u32;
    let mut next = 1u32;
    while next <= total {
        let last = (next + 499).min(total);
        let page: Vec<LogEntry> = (next..=last).map(numbered).collect();
        EventSync::store_peer_events(&store, peer, vault, &page)
            .await
            .expect("stored");
        next = last + 1;
    }
    let kept = EventSync::peer_events(&store, vault, 20_000)
        .await
        .expect("events");
    assert_eq!(kept.len(), 10_000);
    // The oldest went; the newest stays, and is the cursor a pull resumes from.
    assert!(kept.iter().all(|e| e.entry.id > numbered(50).id));
    assert_eq!(
        EventSync::peer_events_cursor(&store, peer, vault)
            .await
            .expect("cursor"),
        numbered(total).id
    );
}

#[tokio::test]
async fn the_list_is_ordered_by_when_events_were_received_not_by_the_time_a_peer_puts_on_them() {
    let store = memory().await;
    let peer = ServerId::random();
    let vault = Owner::User(kemlock_domain::UserId::random());
    // The first event claims to be from the far future; the second, sent later, from the past.
    let mut early = entry(1);
    early.at_ms = i64::MAX as u64;
    let mut late = entry(2);
    late.at_ms = 1;
    EventSync::store_peer_events(&store, peer, vault, &[early.clone()])
        .await
        .expect("stored");
    tokio::time::sleep(std::time::Duration::from_millis(5)).await;
    EventSync::store_peer_events(&store, peer, vault, &[late.clone()])
        .await
        .expect("stored");
    let listed = EventSync::peer_events(&store, vault, 10)
        .await
        .expect("events");
    let ids: Vec<[u8; 16]> = listed.iter().map(|e| e.entry.id).collect();
    assert_eq!(
        ids,
        vec![late.id, early.id],
        "the later arrival is on top, whatever its time says"
    );
    // The time is still shown as the peer gave it.
    assert_eq!(listed[1].entry.at_ms, i64::MAX as u64);
}
