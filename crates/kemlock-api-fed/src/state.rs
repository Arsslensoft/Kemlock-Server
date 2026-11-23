//! What the federation routes share: the replication engine, the handshake nonce cache and an
//! optional channel of events for the console and the replication job.

use kemlock_domain::{Owner, ServerId};
use kemlock_federation::{FedStore, NonceCache, Replica};
use std::sync::Arc;
use tokio::sync::Mutex;
use tokio::sync::mpsc::UnboundedSender;

/// Something the federation routes saw that another part of the server acts on.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum FedEvent {
    /// A known server offered an identity key other than the pinned one: "Possible man in the
    /// middle". The session was refused. `offered` is the key it sent.
    KeyMismatch { offered: Vec<u8> },
    /// A session was refused; `reason` is for the log.
    Refused { reason: String },
    /// A peer showed it has more of a vault: the replication job should pull it.
    Nudge { peer: ServerId, vault: Owner },
}

/// The state of the `/fed/v1` routes. Cloning shares everything.
#[derive(Debug)]
pub struct FedState<S> {
    pub(crate) replica: Arc<Replica<S>>,
    pub(crate) nonces: Arc<Mutex<NonceCache>>,
    pub(crate) events: Option<UnboundedSender<FedEvent>>,
}

impl<S> Clone for FedState<S> {
    fn clone(&self) -> Self {
        FedState {
            replica: self.replica.clone(),
            nonces: self.nonces.clone(),
            events: self.events.clone(),
        }
    }
}

impl<S: FedStore> FedState<S> {
    pub fn new(replica: Arc<Replica<S>>) -> FedState<S> {
        FedState {
            replica,
            nonces: Arc::new(Mutex::new(NonceCache::new())),
            events: None,
        }
    }

    /// Sends [`FedEvent`]s to `events`.
    pub fn with_events(mut self, events: UnboundedSender<FedEvent>) -> FedState<S> {
        self.events = Some(events);
        self
    }

    pub fn replica(&self) -> &Arc<Replica<S>> {
        &self.replica
    }

    pub(crate) fn emit(&self, event: FedEvent) {
        if let Some(events) = &self.events {
            // A receiver that is gone is not an error here.
            let _ = events.send(event);
        }
    }
}
