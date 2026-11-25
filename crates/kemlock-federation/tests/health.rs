//! Peer health probes through the replication job: the status a peer has before and after its
//! probes, how a failing peer is backed off, the timeout, and a peer that is not paired.

use kemlock_federation::health::{HealthConfig, HealthStatus};
use kemlock_federation::memory::MemoryStore;
use kemlock_federation::message::{Request, Response};
use kemlock_federation::ports::Peer;
use kemlock_federation::replicate::Channel;
use kemlock_federation::testing::identity;
use kemlock_federation::{Connector, FedError, PeerRunner, Replica, Suite};
use kemlock_domain::ServerId;
use std::collections::VecDeque;
use std::sync::{Arc, Mutex};
use std::time::Duration;

const NOW: u64 = 1_800_000_000;

/// A channel nobody opens: these tests never start a session.
struct Never;

impl Channel for Never {
    async fn call(&mut self, _request: &Request) -> Result<Response, FedError> {
        Err(FedError::Remote("no session".to_owned()))
    }
}

/// A connector whose probes answer from a script, and count how often they were asked.
#[derive(Default)]
struct Scripted {
    answers: Mutex<VecDeque<Result<(), &'static str>>>,
    asked: Mutex<u32>,
    /// A probe that never ends, for the timeout.
    hang: bool,
}

impl Scripted {
    fn answering(answers: &[Result<(), &'static str>]) -> Scripted {
        Scripted {
            answers: Mutex::new(answers.iter().copied().collect()),
            ..Scripted::default()
        }
    }
}

impl Connector for Arc<Scripted> {
    type Chan = Never;

    async fn connect(&self, _peer: &Peer) -> Result<Never, FedError> {
        Err(FedError::Remote("this connector opens no sessions".to_owned()))
    }

    async fn close(&self, _channel: Never) -> Result<(), FedError> {
        Ok(())
    }

    async fn probe(&self, _peer: &Peer) -> Result<(), FedError> {
        *self.asked.lock().expect("lock") += 1;
        if self.hang {
            tokio::time::sleep(Duration::from_secs(60)).await;
        }
        match self.answers.lock().expect("lock").pop_front() {
            Some(Ok(())) | None => Ok(()),
            Some(Err(why)) => Err(FedError::Remote(why.to_owned())),
        }
    }
}

struct Setup {
    runner: PeerRunner<MemoryStore, Arc<Scripted>>,
    connector: Arc<Scripted>,
    peer: ServerId,
}

async fn setup(connector: Scripted, config: HealthConfig) -> Setup {
    let (a, b) = (
        identity(1, NOW, &Suite::IMPLEMENTED),
        identity(2, NOW, &Suite::IMPLEMENTED),
    );
    let replica = Arc::new(Replica::new(MemoryStore::new(a.server), Arc::new(a)));
    replica.pin_peer(&b.descriptor, NOW).await.expect("pin");
    let connector = Arc::new(connector);
    let runner = PeerRunner::new(replica, connector.clone(), "test".to_owned()).with_health(config);
    Setup {
        runner,
        connector,
        peer: b.server,
    }
}

fn steady() -> HealthConfig {
    // No jitter, so the schedule can be read off exactly.
    HealthConfig {
        jitter_percent: 0,
        ..HealthConfig::every(60)
    }
}

#[tokio::test]
async fn a_peer_is_unknown_until_its_first_probe_and_online_after() {
    let t = setup(Scripted::default(), steady()).await;
    assert_eq!(t.runner.health_status(t.peer, NOW), HealthStatus::Unknown);

    assert_eq!(t.runner.probe_tick(NOW).await, vec![(t.peer, true)]);
    assert_eq!(t.runner.health_status(t.peer, NOW), HealthStatus::Online);
    let health = t.runner.health_of(t.peer).expect("recorded");
    assert_eq!(health.last_seen, Some(NOW));
    assert!(health.latency_ms.is_some() && health.last_error.is_none());
    assert_eq!(health.next_probe_at, NOW + 60);

    // Not asked again before it is due, asked again when it is.
    assert!(t.runner.probe_tick(NOW + 59).await.is_empty());
    assert_eq!(t.runner.probe_tick(NOW + 60).await.len(), 1);
    assert_eq!(*t.connector.asked.lock().expect("lock"), 2);
}

#[tokio::test]
async fn failing_probes_degrade_then_take_a_peer_offline_and_back_off() {
    let t = setup(
        Scripted::answering(&[Err("refused"), Err("refused"), Err("timed out"), Ok(())]),
        steady(),
    )
    .await;
    assert_eq!(t.runner.probe_tick(NOW).await, vec![(t.peer, false)]);
    assert_eq!(t.runner.health_status(t.peer, NOW), HealthStatus::Degraded);
    // The first failure is retried at the usual interval, the next after twice that.
    assert_eq!(t.runner.health_of(t.peer).expect("health").next_probe_at, NOW + 60);

    assert!(t.runner.probe_tick(NOW + 59).await.is_empty());
    t.runner.probe_tick(NOW + 60).await;
    assert_eq!(t.runner.health_status(t.peer, NOW + 60), HealthStatus::Degraded);
    assert_eq!(
        t.runner.health_of(t.peer).expect("health").next_probe_at,
        NOW + 60 + 120
    );

    assert!(t.runner.probe_tick(NOW + 60 + 119).await.is_empty());
    t.runner.probe_tick(NOW + 180).await;
    assert_eq!(t.runner.health_status(t.peer, NOW + 180), HealthStatus::Offline);
    let down = t.runner.health_of(t.peer).expect("health");
    assert_eq!(down.down_since, Some(NOW));
    assert!(
        down.last_error
            .as_deref()
            .is_some_and(|e| e.contains("timed out"))
    );

    // It answers again: online at once, and probed at the usual pace.
    t.runner.probe_tick(NOW + 180 + 240).await;
    assert_eq!(
        t.runner.health_status(t.peer, NOW + 180 + 240),
        HealthStatus::Online
    );
    let back = t.runner.health_of(t.peer).expect("health");
    assert_eq!((back.down_since, back.last_error), (None, None));
    assert_eq!(back.next_probe_at, NOW + 180 + 240 + 60);
}

#[tokio::test]
async fn a_probe_that_hangs_fails_at_the_timeout() {
    let config = HealthConfig {
        timeout_secs: 1,
        ..steady()
    };
    let t = setup(
        Scripted {
            hang: true,
            ..Scripted::default()
        },
        config,
    )
    .await;
    assert_eq!(t.runner.probe_tick(NOW).await, vec![(t.peer, false)]);
    let health = t.runner.health_of(t.peer).expect("health");
    assert_eq!(health.consecutive_failures, 1);
    assert!(
        health
            .last_error
            .as_deref()
            .is_some_and(|e| e.contains("in time"))
    );
}

#[tokio::test]
async fn probes_can_be_turned_off_and_a_stranger_is_not_probed() {
    let off = setup(Scripted::default(), HealthConfig::every(0)).await;
    assert!(off.runner.probe_tick(NOW).await.is_empty());
    assert_eq!(*off.connector.asked.lock().expect("lock"), 0);
    assert_eq!(off.runner.health_status(off.peer, NOW), HealthStatus::Unknown);

    let on = setup(Scripted::default(), steady()).await;
    assert_eq!(on.runner.probe_peer(ServerId::random(), NOW).await, None);
    assert_eq!(*on.connector.asked.lock().expect("lock"), 0);

    // Forgetting a peer forgets its health.
    on.runner.probe_tick(NOW).await;
    on.runner.forget(on.peer);
    assert_eq!(on.runner.health_status(on.peer, NOW), HealthStatus::Unknown);
}

#[tokio::test]
async fn a_visit_that_cannot_open_a_session_counts_as_a_failed_answer() {
    let t = setup(Scripted::default(), HealthConfig::every(0)).await;
    // Probes are off, so only visits tell: this connector opens no sessions.
    let result = t.runner.run_peer(t.peer, NOW).await;
    assert!(result.is_err());
    assert_eq!(t.runner.health_status(t.peer, NOW), HealthStatus::Degraded);
    assert_eq!(
        t.runner.health_of(t.peer).and_then(|h| h.last_error),
        Some("the peer answered with an error: this connector opens no sessions".to_owned())
    );
}
