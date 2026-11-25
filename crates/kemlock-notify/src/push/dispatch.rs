//! [`PushDispatcher`]: turns a commit's nudge into a "sync now" to the owner's phones.
//!
//! Nudges queue and are gathered for a short window, so a burst of writes (an import, a batch)
//! sends one push per device rather than one per item. Only the replica that took the write
//! pushes: the dispatcher is fed by the local commit, never by the fan-out between replicas.
//!
//! Each device is pushed to by its kind:
//!
//! - `apns`: straight to Apple when the server holds an Apple key; else through the optional relay
//!   when the operator turned it on; else nothing;
//! - `unifiedpush`: straight to the endpoint, always, from a task of its own so a slow endpoint
//!   holds up nothing else;
//! - `fcm` (an old row): nothing, Kemlock doesn't use Firebase.

use super::{
    ApnsSender, PushTarget, RelayClient, RelayError, SendOutcome, UnifiedPushSender,
    open_installation,
};
use crate::audience::Audience;
use kemlock_app::ports::SecretSeal;
use kemlock_app::push::{PushKind, PushRegistration, PushRepo};
use kemlock_domain::{Owner, UserId};
use std::collections::HashSet;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::mpsc;
use tokio::task::JoinHandle;
use tokio::time::Instant;

/// How long nudges are gathered before one send.
pub const DEFAULT_WINDOW: Duration = Duration::from_secs(1);

/// How long one flush's UnifiedPush sends may take in all, queueing included.
const UNIFIEDPUSH_DEADLINE: Duration = Duration::from_secs(20);

/// The senders that need no relay: Apple's push, when the operator gave the server a key, and
/// UnifiedPush.
#[derive(Clone, Debug, Default)]
pub struct DirectSenders {
    pub apns: Option<ApnsSender>,
    pub unified_push: UnifiedPushSender,
}

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
    /// Starts the worker. It pushes to iPhones through Apple when `direct` has an Apple sender,
    /// and otherwise through `relay` once the server has registered with it (an installation is
    /// stored), so it is safe to run always.
    pub fn start<R, A, S>(
        repo: R,
        audience: A,
        seal: S,
        relay: RelayClient,
        direct: DirectSenders,
        window: Duration,
    ) -> PushDispatcher
    where
        R: PushRepo + 'static,
        A: Audience,
        S: SecretSeal + 'static,
    {
        let (queue, rx) = mpsc::unbounded_channel();
        let worker = Worker {
            repo: Arc::new(repo),
            audience,
            seal,
            relay,
            direct,
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
    repo: Arc<R>,
    audience: A,
    seal: S,
    relay: RelayClient,
    direct: DirectSenders,
}

impl<R: PushRepo + 'static, A: Audience, S: SecretSeal> Worker<R, A, S> {
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
        let of_kind = |kind: PushKind| -> Vec<&PushRegistration> {
            registrations.iter().filter(|r| r.kind == kind).collect()
        };

        let iphones = of_kind(PushKind::Apns);
        if !iphones.is_empty() {
            self.push_iphones(&iphones).await;
        }
        let androids: Vec<PushRegistration> = of_kind(PushKind::UnifiedPush)
            .into_iter()
            .cloned()
            .collect();
        if !androids.is_empty() {
            self.push_androids(androids);
        }
        // Firebase rows (`fcm`, from an older server) are left alone: nothing sends to them.
    }

    /// UnifiedPush, in a task of its own. The endpoints are the phones' distributors, anyone's
    /// servers, and a slow one must not hold up the iPhones, the relay or the next flush. The
    /// sends have a deadline, and the sender bounds how many run at once.
    fn push_androids(&self, androids: Vec<PushRegistration>) {
        let (repo, sender) = (self.repo.clone(), self.direct.unified_push.clone());
        tokio::spawn(async move {
            let endpoints: Vec<String> = androids.iter().map(|r| r.token.clone()).collect();
            match tokio::time::timeout(UNIFIEDPUSH_DEADLINE, sender.send_sync(&endpoints)).await {
                Ok(outcome) => {
                    let sent: Vec<&PushRegistration> = androids.iter().collect();
                    forget(&*repo, &sent, &outcome).await;
                }
                Err(_) => tracing::warn!("UnifiedPush endpoints took too long; the push was cut"),
            }
        });
    }

    /// Apple's push when the server has a key, else the relay if the operator turned it on.
    async fn push_iphones(&self, iphones: &[&PushRegistration]) {
        if let Some(apns) = &self.direct.apns {
            let tokens: Vec<String> = iphones.iter().map(|r| r.token.clone()).collect();
            let outcome = apns.send_sync(&tokens).await;
            self.forget(iphones, &outcome).await;
            return;
        }
        let installation = match open_installation(&*self.repo, &self.seal).await {
            Ok(Some(installation)) => installation,
            // No Apple key and not opted in to the relay: nothing to send through.
            Ok(None) => return,
            Err(error) => {
                tracing::warn!(%error, "couldn't read the push installation");
                return;
            }
        };
        let targets: Vec<PushTarget> = iphones
            .iter()
            .map(|r| PushTarget {
                kind: r.kind,
                token: r.token.clone(),
            })
            .collect();
        match self.relay.send_sync(&installation, &targets).await {
            Ok(outcome) => self.forget(iphones, &outcome).await,
            Err(RelayError::Unauthorized) => {
                tracing::warn!(
                    "the push relay refused this installation; turn the relay off and on again"
                );
            }
            Err(error) => tracing::warn!(%error, "couldn't send a push"),
        }
    }

    /// Forgets the devices whose tokens the push service no longer knows.
    async fn forget(&self, sent: &[&PushRegistration], outcome: &SendOutcome) {
        forget(&*self.repo, sent, outcome).await;
    }
}

async fn forget<R: PushRepo>(repo: &R, sent: &[&PushRegistration], outcome: &SendOutcome) {
    for dead in &outcome.rejected {
        for registration in sent.iter().filter(|r| &r.token == dead) {
            if let Err(error) = repo.remove_registration(registration.device).await {
                tracing::warn!(%error, "couldn't forget a dead push token");
            }
        }
    }
}
