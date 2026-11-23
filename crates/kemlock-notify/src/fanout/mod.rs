//! Telling every replica's open sockets that an owner's vault changed.
//!
//! A commit on one replica must nudge the sockets that other replicas hold. A nudge carries only
//! the owner, never what changed:
//!
//! - **SQLite** is one process: the nudge goes straight to the local [`Sink`].
//! - **PostgreSQL** sends `NOTIFY kemlock_nudge, '<owner>'`; each replica `LISTEN`s and delivers
//!   to its own sockets. The commit's own replica hears its notification too, which is how it
//!   delivers locally (one path, so no socket is nudged twice).
//! - **MySQL** has no channel, so each replica appends the owner to the `live_nudges` table and
//!   polls it every second, skipping the entries it appended itself (it delivers those at once).
//!
//! A replica that loses its `LISTEN` connection nudges every socket once after reconnecting,
//! since it can't know what it missed.

mod polling;
mod postgres;

use kemlock_domain::Owner;
use kemlock_store_sql::{Dialect, SqlStore};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::mpsc;
use tokio::task::JoinHandle;

pub use kemlock_app::notices::BoxFuture;
use kemlock_app::ports::StoreError;

/// Where a delivered nudge goes: the replica's own sockets.
#[derive(Clone)]
pub struct Sink {
    owner: Arc<dyn Fn(Owner) + Send + Sync>,
    everyone: Arc<dyn Fn() + Send + Sync>,
}

impl std::fmt::Debug for Sink {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Sink").finish_non_exhaustive()
    }
}

impl Sink {
    /// `owner` nudges that owner's sockets; `everyone` nudges every socket (after a lost
    /// connection).
    pub fn new(
        owner: impl Fn(Owner) + Send + Sync + 'static,
        everyone: impl Fn() + Send + Sync + 'static,
    ) -> Self {
        Sink {
            owner: Arc::new(owner),
            everyone: Arc::new(everyone),
        }
    }

    pub(crate) fn owner(&self, owner: Owner) {
        (self.owner)(owner);
    }

    pub(crate) fn everyone(&self) {
        (self.everyone)();
    }
}

/// Timings of the fan-out. The defaults are what the server runs.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FanoutOptions {
    /// How often a MySQL replica polls the nudge log.
    pub poll_every: Duration,
    /// How long a nudge stays in the log before any replica may delete it.
    pub keep: Duration,
    /// How long to wait before listening again on PostgreSQL after the connection fails.
    pub retry_after: Duration,
}

impl Default for FanoutOptions {
    fn default() -> Self {
        FanoutOptions {
            poll_every: Duration::from_secs(1),
            keep: Duration::from_secs(60),
            retry_after: Duration::from_secs(1),
        }
    }
}

/// How nudges travel between replicas.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Transport {
    /// One process: straight to the local sink.
    InProcess,
    /// PostgreSQL `NOTIFY` and `LISTEN`.
    Postgres,
    /// MySQL: the polled `live_nudges` table.
    Polling,
}

/// Stops the background tasks when the last [`Fanout`] clone is dropped.
#[derive(Debug)]
struct Tasks(Vec<JoinHandle<()>>);

impl Drop for Tasks {
    fn drop(&mut self) {
        for task in &self.0 {
            task.abort();
        }
    }
}

#[derive(Clone)]
enum Route {
    Local(Sink),
    Queue(mpsc::UnboundedSender<Owner>),
}

/// Publishes nudges to every replica, this one included. Cheap to clone.
#[derive(Clone)]
pub struct Fanout {
    route: Route,
    transport: Transport,
    _tasks: Arc<Tasks>,
}

impl std::fmt::Debug for Fanout {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Fanout")
            .field("transport", &self.transport)
            .finish_non_exhaustive()
    }
}

impl Fanout {
    /// A fan-out for one process: nudges go straight to `sink`.
    pub fn in_process(sink: Sink) -> Fanout {
        Fanout {
            route: Route::Local(sink),
            transport: Transport::InProcess,
            _tasks: Arc::new(Tasks(Vec::new())),
        }
    }

    /// Picks the transport the database allows and starts it. Fails when PostgreSQL can't be
    /// listened to or MySQL's log can't be read: better to know at start than to run deaf.
    pub async fn connect(
        store: &SqlStore,
        sink: Sink,
        options: FanoutOptions,
    ) -> Result<Fanout, StoreError> {
        match store.dialect() {
            Dialect::Sqlite => Ok(Fanout::in_process(sink)),
            Dialect::Postgres => {
                let channel = Arc::new(postgres::PgChannel(store.clone()));
                Fanout::over_channel(channel, sink, options).await
            }
            Dialect::MySql => Fanout::over_log(Arc::new(store.clone()), sink, options).await,
        }
    }

    pub(crate) async fn over_channel(
        channel: Arc<dyn postgres::Channel>,
        sink: Sink,
        options: FanoutOptions,
    ) -> Result<Fanout, StoreError> {
        let (tx, tasks) = postgres::start(channel, sink, options.retry_after).await?;
        Ok(Fanout {
            route: Route::Queue(tx),
            transport: Transport::Postgres,
            _tasks: Arc::new(Tasks(tasks)),
        })
    }

    pub(crate) async fn over_log<L: kemlock_app::push::NudgeLog + 'static>(
        log: Arc<L>,
        sink: Sink,
        options: FanoutOptions,
    ) -> Result<Fanout, StoreError> {
        let (tx, tasks) = polling::start(log, sink, options.poll_every, options.keep).await?;
        Ok(Fanout {
            route: Route::Queue(tx),
            transport: Transport::Polling,
            _tasks: Arc::new(Tasks(tasks)),
        })
    }

    /// Which transport is in use.
    pub fn transport(&self) -> Transport {
        self.transport
    }

    /// Nudges the owner's sockets on every replica. Never waits: the work is queued.
    pub fn nudge(&self, owner: Owner) {
        match &self.route {
            Route::Local(sink) => sink.owner(owner),
            Route::Queue(tx) => {
                // The worker is gone only at shutdown.
                let _ = tx.send(owner);
            }
        }
    }
}

#[cfg(test)]
pub(crate) mod testing {
    use super::*;
    use std::sync::Mutex;
    use std::sync::atomic::{AtomicUsize, Ordering};

    /// A sink that remembers what it was told.
    #[derive(Clone, Default)]
    pub(crate) struct Heard {
        pub(crate) owners: Arc<Mutex<Vec<Owner>>>,
        pub(crate) everyone: Arc<AtomicUsize>,
    }

    impl Heard {
        pub(crate) fn sink(&self) -> Sink {
            let owners = self.owners.clone();
            let everyone = self.everyone.clone();
            Sink::new(
                move |owner| owners.lock().expect("lock").push(owner),
                move || {
                    everyone.fetch_add(1, Ordering::SeqCst);
                },
            )
        }

        pub(crate) fn owners(&self) -> Vec<Owner> {
            self.owners.lock().expect("lock").clone()
        }

        pub(crate) fn everyone_count(&self) -> usize {
            self.everyone.load(Ordering::SeqCst)
        }
    }

    /// Waits until `check` holds, up to five seconds.
    pub(crate) async fn eventually(mut check: impl FnMut() -> bool) {
        for _ in 0..500 {
            if check() {
                return;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        panic!("the condition never held");
    }
}

#[cfg(test)]
mod tests {
    use super::testing::Heard;
    use super::*;
    use kemlock_domain::UserId;

    #[tokio::test]
    async fn in_process_a_nudge_is_delivered_at_once_and_once() {
        let heard = Heard::default();
        let fanout = Fanout::in_process(heard.sink());
        assert_eq!(fanout.transport(), Transport::InProcess);
        let owner = Owner::User(UserId::random());
        fanout.nudge(owner);
        assert_eq!(heard.owners(), vec![owner]);
        assert_eq!(heard.everyone_count(), 0);
    }

    #[tokio::test]
    async fn sqlite_picks_the_in_process_transport() {
        let store = SqlStore::connect("sqlite::memory:").await.expect("store");
        let heard = Heard::default();
        let fanout = Fanout::connect(&store, heard.sink(), FanoutOptions::default())
            .await
            .expect("connects");
        assert_eq!(fanout.transport(), Transport::InProcess);
        let owner = Owner::User(UserId::random());
        fanout.clone().nudge(owner);
        assert_eq!(heard.owners(), vec![owner]);
    }
}
