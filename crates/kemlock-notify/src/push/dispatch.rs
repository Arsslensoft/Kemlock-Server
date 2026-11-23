//! [`PushDispatcher`]: turns a commit's nudge into a "sync now" to the owner's phones.
//!
//! Nudges queue and are gathered for a short window, so a burst of writes (an import, a batch)
//! sends one push per device rather than one per item. Only the replica that took the write
//! pushes: the dispatcher is fed by the local commit, never by the fan-out between replicas.

use super::{Installation, PushTarget, RelayError, open_installation};
use crate::audience::Audience;
use kemlock_app::ports::SecretSeal;
use kemlock_app::push::{PushRegistration, PushRepo};
use kemlock_domain::{Owner, UserId};
use std::collections::HashSet;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::mpsc;
use tokio::task::JoinHandle;
use tokio::time::Instant;

/// How long nudges are gathered before one send.
pub const DEFAULT_WINDOW: Duration = Duration::from_secs(1);

#[derive(Debug)]
struct Task(JoinHandle<()>);

impl Drop for Task {
    fn drop(&mut self) {
        self.0.abort();
    }
}

/// Queues owners to push to. Cheap to clone; the worker stops with the last clone.
#[derive(Clone, Debug)]
pub struct PushDispatcher {
    queue: mpsc::UnboundedSender<Owner>,
    _task: Arc<Task>,
}

impl PushDispatcher {
    /// Starts the worker. It does nothing until the server has registered with the relay (an
    /// installation is stored), so it is safe to run always.
    pub fn start<R, A, S>(
        repo: R,
        audience: A,
        seal: S,
        client: super::RelayClient,
        window: Duration,
    ) -> PushDispatcher
    where
        R: PushRepo + 'static,
        A: Audience,
        S: SecretSeal + 'static,
    {
        let (queue, rx) = mpsc::unbounded_channel();
        let worker = Worker {
            repo,
            audience,
            seal,
            client,
        };
        let task = tokio::spawn(worker.run(rx, window));
        PushDispatcher {
            queue,
            _task: Arc::new(Task(task)),
        }
    }

    /// Queues a push for the owner's devices. Never waits.
    pub fn nudge(&self, owner: Owner) {
        // The worker is gone only at shutdown.
        let _ = self.queue.send(owner);
    }
}

struct Worker<R, A, S> {
    repo: R,
    audience: A,
    seal: S,
    client: super::RelayClient,
}

impl<R: PushRepo, A: Audience, S: SecretSeal> Worker<R, A, S> {
    async fn run(self, mut queue: mpsc::UnboundedReceiver<Owner>, window: Duration) {
        while let Some(first) = queue.recv().await {
            let mut owners = HashSet::from([first]);
            let deadline = Instant::now() + window;
            let mut open = true;
            while open {
                match tokio::time::timeout_at(deadline, queue.recv()).await {
                    Ok(Some(owner)) => {
                        owners.insert(owner);
                    }
                    Ok(None) => open = false,
                    Err(_) => break,
                }
            }
            self.flush(owners).await;
            if !open {
                return;
            }
        }
    }

    async fn flush(&self, owners: HashSet<Owner>) {
        let installation = match open_installation(&self.repo, &self.seal).await {
            Ok(Some(installation)) => installation,
            // Not opted in: nothing to do.
            Ok(None) => return,
            Err(error) => {
                tracing::warn!(%error, "couldn't read the push installation");
                return;
            }
        };
        let mut users: HashSet<UserId> = HashSet::new();
        for owner in owners {
            users.extend(self.audience.users(owner).await);
        }
        if users.is_empty() {
            return;
        }
        let users: Vec<UserId> = users.into_iter().collect();
        let registrations = match self.repo.registrations_for(&users).await {
            Ok(found) => found,
            Err(error) => {
                tracing::warn!(%error, "couldn't read push tokens");
                return;
            }
        };
        if registrations.is_empty() {
            return;
        }
        self.send(&installation, &registrations).await;
    }

    async fn send(&self, installation: &Installation, registrations: &[PushRegistration]) {
        let targets: Vec<PushTarget> = registrations
            .iter()
            .map(|r| PushTarget {
                kind: r.kind,
                token: r.token.clone(),
            })
            .collect();
        match self.client.send_sync(installation, &targets).await {
            Ok(outcome) => {
                for dead in &outcome.rejected {
                    for registration in registrations.iter().filter(|r| &r.token == dead) {
                        if let Err(error) = self.repo.remove_registration(registration.device).await
                        {
                            tracing::warn!(%error, "couldn't forget a dead push token");
                        }
                    }
                }
            }
            Err(RelayError::Unauthorized) => {
                tracing::warn!(
                    "the push relay refused this installation; turn the relay off and on again"
                );
            }
            Err(error) => tracing::warn!(%error, "couldn't send a push"),
        }
    }
}
