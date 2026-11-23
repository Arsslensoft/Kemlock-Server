//! The PostgreSQL transport: `NOTIFY` out, `LISTEN` in.
//!
//! The channel is a trait so the logic (the echo as local delivery, the fall-back when a notify
//! fails, the nudge-everyone after a lost connection) is tested without a server; `PgChannel`
//! is the real one.

use super::Sink;
use kemlock_app::notices::BoxFuture;
use kemlock_app::ports::StoreError;
use kemlock_domain::Owner;
use kemlock_store_sql::{NudgeListener, SqlStore};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::mpsc;
use tokio::task::JoinHandle;

/// A `LISTEN` that yields payloads.
pub(crate) trait Listening: Send {
    /// The next payload; `None` when the connection dropped and came back (notifications in
    /// between are lost).
    fn recv(&mut self) -> BoxFuture<'_, Result<Option<String>, StoreError>>;
}

/// `NOTIFY` and `LISTEN` on the nudge channel.
pub(crate) trait Channel: Send + Sync + 'static {
    fn notify(&self, payload: String) -> BoxFuture<'_, Result<(), StoreError>>;
    fn listen(&self) -> BoxFuture<'_, Result<Box<dyn Listening>, StoreError>>;
}

/// The real channel, on the store's PostgreSQL pool.
pub(crate) struct PgChannel(pub(crate) SqlStore);

struct PgListening(NudgeListener);

impl Listening for PgListening {
    fn recv(&mut self) -> BoxFuture<'_, Result<Option<String>, StoreError>> {
        Box::pin(self.0.recv())
    }
}

impl Channel for PgChannel {
    fn notify(&self, payload: String) -> BoxFuture<'_, Result<(), StoreError>> {
        Box::pin(async move { self.0.pg_notify(&payload).await })
    }

    fn listen(&self) -> BoxFuture<'_, Result<Box<dyn Listening>, StoreError>> {
        Box::pin(async move {
            let listener = self.0.pg_listen().await?;
            Ok(Box::new(PgListening(listener)) as Box<dyn Listening>)
        })
    }
}

/// Starts listening (failing now if it can't) and the two tasks: one sends queued nudges, the
/// other delivers what it hears. Returns the queue's sender and the tasks.
pub(crate) async fn start(
    channel: Arc<dyn Channel>,
    sink: Sink,
    retry_after: Duration,
) -> Result<(mpsc::UnboundedSender<Owner>, Vec<JoinHandle<()>>), StoreError> {
    let listening = channel.listen().await?;
    let (tx, rx) = mpsc::unbounded_channel();
    let publisher = tokio::spawn(publish_loop(channel.clone(), sink.clone(), rx));
    let listener = tokio::spawn(listen_loop(channel, sink, listening, retry_after));
    Ok((tx, vec![publisher, listener]))
}

async fn publish_loop(
    channel: Arc<dyn Channel>,
    sink: Sink,
    mut queue: mpsc::UnboundedReceiver<Owner>,
) {
    while let Some(owner) = queue.recv().await {
        if let Err(error) = channel.notify(owner.to_string()).await {
            // Our own sockets still hear of it; other replicas catch up at their next sync.
            tracing::warn!(%error, "couldn't NOTIFY a nudge; delivering it locally only");
            sink.owner(owner);
        }
    }
}

async fn listen_loop(
    channel: Arc<dyn Channel>,
    sink: Sink,
    mut listening: Box<dyn Listening>,
    retry_after: Duration,
) {
    loop {
        match listening.recv().await {
            Ok(Some(payload)) => match payload.parse::<Owner>() {
                Ok(owner) => sink.owner(owner),
                Err(_) => tracing::warn!("ignored a nudge with a payload that names no owner"),
            },
            Ok(None) => {
                tracing::warn!("the LISTEN connection was lost and re-made; nudging every socket");
                sink.everyone();
            }
            Err(error) => {
                tracing::warn!(%error, "the LISTEN connection failed; listening again");
                loop {
                    tokio::time::sleep(retry_after).await;
                    match channel.listen().await {
                        Ok(next) => {
                            listening = next;
                            sink.everyone();
                            break;
                        }
                        Err(error) => tracing::warn!(%error, "couldn't LISTEN yet"),
                    }
                }
            }
        }
    }
}

#[cfg(test)]
pub(crate) mod fake {
    use super::*;
    use std::sync::Mutex;
    use std::sync::atomic::{AtomicBool, Ordering};

    pub(crate) type Event = Result<Option<String>, StoreError>;

    /// A channel in memory: every notification goes to every listener, and a test can inject
    /// events (a lost connection) or make notifying and listening fail.
    #[derive(Default)]
    pub(crate) struct Bus {
        listeners: Mutex<Vec<mpsc::UnboundedSender<Event>>>,
        pub(crate) fail_notify: AtomicBool,
        pub(crate) fail_listen: AtomicBool,
        pub(crate) listens: std::sync::atomic::AtomicUsize,
    }

    impl Bus {
        pub(crate) fn inject(&self, event: Event) {
            for listener in self.listeners.lock().expect("lock").iter() {
                let _ = listener.send(event.clone());
            }
        }
    }

    struct FakeListening(mpsc::UnboundedReceiver<Event>);

    impl Listening for FakeListening {
        fn recv(&mut self) -> BoxFuture<'_, Result<Option<String>, StoreError>> {
            Box::pin(async move {
                self.0
                    .recv()
                    .await
                    .unwrap_or_else(|| Err(StoreError::Backend("closed".to_owned())))
            })
        }
    }

    impl Channel for Bus {
        fn notify(&self, payload: String) -> BoxFuture<'_, Result<(), StoreError>> {
            Box::pin(async move {
                if self.fail_notify.load(Ordering::SeqCst) {
                    return Err(StoreError::Backend("notify refused".to_owned()));
                }
                self.inject(Ok(Some(payload)));
                Ok(())
            })
        }

        fn listen(&self) -> BoxFuture<'_, Result<Box<dyn Listening>, StoreError>> {
            Box::pin(async move {
                if self.fail_listen.load(Ordering::SeqCst) {
                    return Err(StoreError::Backend("listen refused".to_owned()));
                }
                self.listens.fetch_add(1, Ordering::SeqCst);
                let (tx, rx) = mpsc::unbounded_channel();
                self.listeners.lock().expect("lock").push(tx);
                Ok(Box::new(FakeListening(rx)) as Box<dyn Listening>)
            })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::super::testing::{Heard, eventually};
    use super::super::{Fanout, FanoutOptions, Transport};
    use super::fake::Bus;
    use super::*;
    use kemlock_domain::UserId;
    use std::sync::atomic::Ordering;

    fn options() -> FanoutOptions {
        FanoutOptions {
            retry_after: Duration::from_millis(10),
            ..FanoutOptions::default()
        }
    }

    fn owner() -> Owner {
        Owner::User(UserId::random())
    }

    #[tokio::test]
    async fn a_nudge_reaches_every_replica_once_through_the_channel() {
        let bus = Arc::new(Bus::default());
        let (a, b) = (Heard::default(), Heard::default());
        let fanout_a = Fanout::over_channel(bus.clone(), a.sink(), options())
            .await
            .expect("a");
        let _fanout_b = Fanout::over_channel(bus.clone(), b.sink(), options())
            .await
            .expect("b");
        assert_eq!(fanout_a.transport(), Transport::Postgres);

        let o = owner();
        fanout_a.nudge(o);
        eventually(|| a.owners().len() == 1 && b.owners().len() == 1).await;
        // The publisher hears its own notification: that is its local delivery, so exactly once.
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert_eq!(a.owners(), vec![o]);
        assert_eq!(b.owners(), vec![o]);
    }

    #[tokio::test]
    async fn the_payload_is_the_owner_and_nothing_else() {
        let bus = Arc::new(Bus::default());
        let heard = Heard::default();
        let fanout = Fanout::over_channel(bus.clone(), heard.sink(), options())
            .await
            .expect("fanout");
        // A raw listener sees what goes on the wire.
        let mut wire = bus.listen().await.expect("listens");
        let o = Owner::Space(kemlock_domain::SpaceId::random());
        fanout.nudge(o);
        let payload = wire.recv().await.expect("event").expect("payload");
        assert_eq!(payload, o.to_string());
        assert!(payload.starts_with("space:"));
    }

    #[tokio::test]
    async fn a_failed_notify_still_nudges_this_replicas_sockets() {
        let bus = Arc::new(Bus::default());
        bus.fail_notify.store(true, Ordering::SeqCst);
        let heard = Heard::default();
        let fanout = Fanout::over_channel(bus, heard.sink(), options())
            .await
            .expect("fanout");
        let o = owner();
        fanout.nudge(o);
        eventually(|| heard.owners() == vec![o]).await;
    }

    #[tokio::test]
    async fn a_reconnected_listener_nudges_everyone() {
        let bus = Arc::new(Bus::default());
        let heard = Heard::default();
        let _fanout = Fanout::over_channel(bus.clone(), heard.sink(), options())
            .await
            .expect("fanout");
        bus.inject(Ok(None));
        eventually(|| heard.everyone_count() == 1).await;
    }

    #[tokio::test]
    async fn a_failed_listener_listens_again_and_nudges_everyone() {
        let bus = Arc::new(Bus::default());
        let heard = Heard::default();
        let fanout = Fanout::over_channel(bus.clone(), heard.sink(), options())
            .await
            .expect("fanout");
        assert_eq!(bus.listens.load(Ordering::SeqCst), 1);
        // The server refuses at first, then lets it listen.
        bus.fail_listen.store(true, Ordering::SeqCst);
        bus.inject(Err(StoreError::Backend("connection reset".to_owned())));
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert_eq!(heard.everyone_count(), 0, "not before it can listen again");
        bus.fail_listen.store(false, Ordering::SeqCst);
        eventually(|| heard.everyone_count() == 1).await;
        assert_eq!(bus.listens.load(Ordering::SeqCst), 2);

        // And it hears nudges on the new connection.
        let o = owner();
        fanout.nudge(o);
        eventually(|| heard.owners() == vec![o]).await;
    }

    #[tokio::test]
    async fn a_payload_that_names_no_owner_is_ignored() {
        let bus = Arc::new(Bus::default());
        let heard = Heard::default();
        let fanout = Fanout::over_channel(bus.clone(), heard.sink(), options())
            .await
            .expect("fanout");
        bus.inject(Ok(Some("garbage".to_owned())));
        let o = owner();
        fanout.nudge(o);
        eventually(|| heard.owners() == vec![o]).await;
        assert_eq!(heard.everyone_count(), 0);
    }

    #[tokio::test]
    async fn not_being_able_to_listen_at_start_is_an_error() {
        let bus = Arc::new(Bus::default());
        bus.fail_listen.store(true, Ordering::SeqCst);
        let result = Fanout::over_channel(bus, Heard::default().sink(), options()).await;
        assert!(result.is_err());
    }
}
