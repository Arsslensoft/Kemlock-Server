//! How the replication job runs its visits: each due peer is its own task, so one slow peer doesn't
//! delay another, and a visit that runs out of time is a partial success, not a failure.

use kemlock_domain::{Owner, ServerId, UserId};
use kemlock_federation::health::HealthConfig;
use kemlock_federation::job::RunOutcome;
use kemlock_federation::memory::MemoryStore;
use kemlock_federation::message::{Request, Response};
use kemlock_federation::ports::Peer;
use kemlock_federation::replicate::Channel;
use kemlock_federation::testing::identity;
use kemlock_federation::{Connector, FedError, PeerRunner, Replica, Suite};
use std::sync::Arc;
use std::time::Duration;

const NOW: u64 = 1_800_000_000;

/// A session whose every call takes a minute.
struct Slow;

impl Channel for Slow {
    async fn call(&mut self, _request: &Request) -> Result<Response, FedError> {
        tokio::time::sleep(Duration::from_secs(60)).await;
        Err(FedError::Remote("too late".to_owned()))
    }
}

/// Opens a session that hangs to `slow_peer`, and fails at once to every other peer.
#[derive(Clone)]
struct Mixed {
    slow_peer: ServerId,
    /// Whether the slow peer's connection itself hangs (otherwise the session opens and hangs).
    hang_on_connect: bool,
}

impl Connector for Mixed {
    type Chan = Slow;

    async fn connect(&self, peer: &Peer) -> Result<Slow, FedError> {
        if peer.id == self.slow_peer {
            if self.hang_on_connect {
                tokio::time::sleep(Duration::from_secs(60)).await;
            }
            Ok(Slow)
        } else {
            Err(FedError::Remote("refused at once".to_owned()))
        }
    }

    async fn close(&self, _channel: Slow) -> Result<(), FedError> {
        Ok(())
    }
}

struct World {
    runner: Arc<PeerRunner<MemoryStore, Mixed>>,
    slow: ServerId,
    fast: ServerId,
    replica: Arc<Replica<MemoryStore>>,
}

async fn world(hang_on_connect: bool, deadline: Duration) -> World {
    let (me, slow, fast) = (
        identity(1, NOW, &Suite::IMPLEMENTED),
        identity(2, NOW, &Suite::IMPLEMENTED),
        identity(3, NOW, &Suite::IMPLEMENTED),
    );
    let replica = Arc::new(Replica::new(MemoryStore::new(me.server), Arc::new(me)));
    replica.pin_peer(&slow.descriptor, NOW).await.expect("pin");
    replica.pin_peer(&fast.descriptor, NOW).await.expect("pin");
    let runner = Arc::new(
        PeerRunner::new(
            replica.clone(),
            Mixed {
                slow_peer: slow.server,
                hang_on_connect,
            },
            "test".to_owned(),
        )
        .with_health(HealthConfig::every(0))
        .with_visit_deadline(deadline),
    );
    World {
        runner,
        slow: slow.server,
        fast: fast.server,
        replica,
    }
}

#[tokio::test]
async fn a_slow_peer_does_not_delay_the_visit_to_another_and_is_not_started_twice() {
    let w = world(true, Duration::from_secs(120)).await;
    let started = w.runner.tick(NOW).await;
    // Both were started, and tick did not wait for the slow one.
    assert_eq!(started.len(), 2);
    assert!(started.contains(&w.slow) && started.contains(&w.fast));

    // The fast peer's run ended (and failed) while the slow one's is still going.
    tokio::time::sleep(Duration::from_millis(200)).await;
    let fast = w
        .runner
        .status_of(w.fast)
        .expect("the fast peer was visited");
    assert_eq!(fast.consecutive_failures, 1);
    let slow = w
        .runner
        .status_of(w.slow)
        .expect("the slow peer was started");
    assert_eq!(slow.consecutive_failures, 0);
    assert!(slow.last_success.is_none());

    // The next tick starts neither: one is running, the other is backing off.
    assert!(w.runner.tick(NOW).await.is_empty());
    // And a direct run for the slow peer finds it already running.
    assert_eq!(
        w.runner.run_peer(w.slow, NOW).await.expect("a run"),
        RunOutcome::Leased
    );
}

#[tokio::test]
async fn a_visit_that_runs_out_of_time_is_a_partial_success_with_a_note() {
    let w = world(false, Duration::from_millis(150)).await;
    // A vault the slow peer is a replica of, so the visit has a call to make that never answers.
    let vault = Owner::User(UserId::random());
    w.replica
        .federate(vault, vec![w.slow])
        .await
        .expect("federate");

    let outcome = w.runner.run_peer(w.slow, NOW).await.expect("not a failure");
    let RunOutcome::Done(statuses) = outcome else {
        panic!("a partial run is a Done");
    };
    assert_eq!(statuses.len(), 1);
    assert!(
        statuses[0].note.is_some(),
        "the vault says it wasn't reached"
    );

    let status = w.runner.status_of(w.slow).expect("a status");
    assert_eq!(status.consecutive_failures, 0);
    assert!(status.down_since.is_none() && status.last_error.is_none());
    assert_eq!(status.last_success, Some(NOW));
}
