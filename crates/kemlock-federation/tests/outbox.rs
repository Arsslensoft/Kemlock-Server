//! Changes waiting for a peer, and cancelling them: what is counted, that a cancel keeps exactly
//! the versions held from that peer and nothing else, and that nothing is deleted.

use kemlock_domain::{ItemId, Owner, ServerId, UserId};
use kemlock_federation::memory::MemoryStore;
use kemlock_federation::message::{Request, Response};
use kemlock_federation::outbox::{Cancelled, Withholding};
use kemlock_federation::ports::ReplicaStore;
use kemlock_federation::replicate::Channel;
use kemlock_federation::testing::{draft, identity};
use kemlock_federation::{FedError, Replica, Suite};
use std::sync::Arc;

const NOW: u64 = 1_800_000_000;

/// B's session to A: every request goes straight to A as B.
struct ToA<'a> {
    a: &'a Replica<MemoryStore>,
    b: ServerId,
}

impl Channel for ToA<'_> {
    async fn call(&mut self, request: &Request) -> Result<Response, FedError> {
        Ok(self.a.serve(self.b, request, NOW).await.response)
    }
}

struct Pair {
    a: Replica<MemoryStore>,
    b: Replica<MemoryStore>,
    a_id: ServerId,
    b_id: ServerId,
    vault: Owner,
}

/// A is the home of a personal vault, B its replica.
async fn pair() -> Pair {
    let ia = identity(1, NOW, &Suite::IMPLEMENTED);
    let ib = identity(2, NOW, &Suite::IMPLEMENTED);
    let a = Replica::new(MemoryStore::new(ia.server), Arc::new(ia.clone()));
    let b = Replica::new(MemoryStore::new(ib.server), Arc::new(ib.clone()));
    a.pin_peer(&ib.descriptor, NOW).await.expect("pin");
    b.pin_peer(&ia.descriptor, NOW).await.expect("pin");
    let vault = Owner::User(UserId::random());
    a.federate(vault, vec![ib.server]).await.expect("federate");
    b.accept_vault(vault, ia.server, vec![ib.server])
        .await
        .expect("accept");
    Pair {
        a,
        b,
        a_id: ia.server,
        b_id: ib.server,
        vault,
    }
}

impl Pair {
    fn write(&self, at: u64) -> ItemId {
        let id = ItemId::random();
        self.a
            .store()
            .put(draft(id, self.vault, None, 1, at))
            .expect("write");
        id
    }

    /// B pulls A's changes, as its job would; returns how many it applied.
    async fn b_pulls(&self) -> usize {
        let mut channel = ToA {
            a: &self.a,
            b: self.b_id,
        };
        self.b
            .pull(&mut channel, self.a_id, self.vault)
            .await
            .expect("pull")
            .counts
            .applied
    }
}

#[tokio::test]
async fn what_the_peer_has_not_been_given_is_counted_per_vault() {
    let t = pair().await;
    let empty = t.a.waiting_for(t.b_id, t.vault).await.expect("count");
    assert_eq!(
        (empty.changes, empty.at_least, empty.oldest_at),
        (0, false, None)
    );

    for at in [1_000_000, 2_000_000, 3_000_000] {
        t.write(at);
    }
    let waiting = t.a.waiting_for(t.b_id, t.vault).await.expect("count");
    assert_eq!((waiting.changes, waiting.at_least), (3, false));
    assert!(waiting.oldest_at.is_some());

    // Another vault's changes are another vault's.
    let other = Owner::User(UserId::random());
    assert_eq!(
        t.a.waiting_for(t.b_id, other).await.expect("count").changes,
        0
    );
}

#[tokio::test]
async fn a_long_queue_is_counted_to_a_limit_and_says_so() {
    let t = pair().await;
    for n in 0..130u64 {
        t.write(1_000_000 + n);
    }
    let waiting = t.a.waiting_for(t.b_id, t.vault).await.expect("count");
    assert_eq!(waiting.changes, 100);
    assert!(waiting.at_least);
}

#[tokio::test]
async fn a_cancel_keeps_what_is_held_from_that_peer_and_only_that() {
    let t = pair().await;
    let kept = t.write(1_000_000);
    t.write(2_000_000);
    let before = t.a.store().latest(t.vault).await.expect("latest");

    let cancelled =
        t.a.cancel_waiting(t.b_id, t.vault, NOW)
            .await
            .expect("cancel");
    assert_eq!(
        cancelled,
        Some(Cancelled {
            dropped: 2,
            at_least: false
        })
    );
    let after = t.a.waiting_for(t.b_id, t.vault).await.expect("count");
    assert_eq!(after.changes, 0, "no longer counted as waiting");

    // The peer pulls and gets none of them; asking for the item by id gets nothing either.
    assert_eq!(t.b_pulls().await, 0);
    let fetched =
        t.a.serve(
            t.b_id,
            &Request::Fetch {
                vault: t.vault,
                items: vec![kept],
            },
            NOW,
        )
        .await
        .response;
    assert!(matches!(&fetched, Response::Changes { records, .. } if records.is_empty()));

    // Nothing here was deleted: this server holds both, and a third server could still get them.
    assert_eq!(t.a.store().latest(t.vault).await.expect("latest"), before);
    assert!(
        t.a.store()
            .export_items(t.vault, &[kept])
            .await
            .is_ok_and(|e| e.len() == 1)
    );
    let held = t.a.store().withheld(t.b_id, t.vault).await.expect("read");
    assert_eq!(held.map(|w| (w.upto, w.at)), Some((before, NOW)));
    let third = ServerId::random();
    assert_eq!(t.a.store().withheld(third, t.vault).await, Ok(None));

    // What is written afterwards flows as usual, and is counted again.
    t.write(3_000_000);
    let waiting = t.a.waiting_for(t.b_id, t.vault).await.expect("count");
    assert_eq!(waiting.changes, 1);
    assert_eq!(t.b_pulls().await, 1);
}

#[tokio::test]
async fn cancelling_with_nothing_waiting_or_for_a_stranger_does_nothing() {
    let t = pair().await;
    assert_eq!(
        t.a.cancel_waiting(t.b_id, t.vault, NOW)
            .await
            .expect("cancel"),
        None,
        "nothing waits"
    );
    t.write(1_000_000);
    // A server that doesn't hold the vault, a vault this server doesn't federate, and itself.
    let stranger = ServerId::random();
    assert_eq!(t.a.cancel_waiting(stranger, t.vault, NOW).await, Ok(None));
    let other = Owner::User(UserId::random());
    assert_eq!(t.a.cancel_waiting(t.b_id, other, NOW).await, Ok(None));
    assert_eq!(t.a.cancel_waiting(t.a_id, t.vault, NOW).await, Ok(None));
    assert_eq!(t.a.store().withheld(t.b_id, t.vault).await, Ok(None));
    // And the change is still waiting.
    assert_eq!(
        t.a.waiting_for(t.b_id, t.vault)
            .await
            .expect("count")
            .changes,
        1
    );
}

#[tokio::test]
async fn a_second_cancel_adds_to_the_first_and_an_unpair_forgets_it() {
    let t = pair().await;
    t.write(1_000_000);
    t.a.cancel_waiting(t.b_id, t.vault, NOW)
        .await
        .expect("cancel");
    t.write(2_000_000);
    let again =
        t.a.cancel_waiting(t.b_id, t.vault, NOW + 5)
            .await
            .expect("cancel");
    assert_eq!(
        again,
        Some(Cancelled {
            dropped: 1,
            at_least: false
        })
    );
    assert_eq!(t.b_pulls().await, 0);
    assert_eq!(
        t.a.store()
            .withheld(t.b_id, t.vault)
            .await
            .expect("read")
            .map(|w| w.at),
        Some(NOW + 5)
    );

    t.a.store().forget_withheld(t.b_id).await.expect("forget");
    assert_eq!(t.a.store().withheld(t.b_id, t.vault).await, Ok(None));
}

#[tokio::test]
async fn a_resume_offers_the_withheld_changes_again_through_the_next_comparison() {
    let t = pair().await;
    let first = t.write(1_000_000);
    t.write(2_000_000);
    t.a.cancel_waiting(t.b_id, t.vault, NOW)
        .await
        .expect("cancel");
    // The peer's cursor moved past them: a pull alone will not bring them, even after a resume.
    assert_eq!(t.b_pulls().await, 0);

    assert!(t.a.resume_waiting(t.b_id, t.vault).await.expect("resume"));
    assert_eq!(t.a.store().withheld(t.b_id, t.vault).await, Ok(None));
    assert!(
        !t.a.resume_waiting(t.b_id, t.vault).await.expect("again"),
        "nothing is left to lift"
    );
    assert_eq!(t.b_pulls().await, 0);

    // The comparison of the two copies finds the items the peer lacks and fetches them by id.
    let mut channel = ToA { a: &t.a, b: t.b_id };
    let report =
        t.b.reconcile(&mut channel, t.a_id, t.vault)
            .await
            .expect("reconcile");
    assert!(!report.in_step);
    assert_eq!(report.fetched.applied, 2);
    assert!(
        t.b.store()
            .export_items(t.vault, &[first])
            .await
            .is_ok_and(|e| e.len() == 1)
    );
    assert!(
        t.b.reconcile(&mut channel, t.a_id, t.vault)
            .await
            .expect("reconcile")
            .in_step
    );
}
