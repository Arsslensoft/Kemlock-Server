//! `GET /kem/v1/live`: a WebSocket that sends `{"type":"sync"}` when one of the account's items
//! changed, so open web vaults and desktop apps sync at once instead of at the next schedule.
//!
//! A nudge carries only its type, never what changed. By default the hub keeps nudges in memory,
//! which serves one server process. `kemlock-notify` replaces that: [`LiveHub::with_outbound`]
//! hands every commit's nudge to the cross-replica fan-out and push relay, which in turn calls
//! [`LiveHub::nudge`] on each replica to reach that replica's sockets. The hub also carries the
//! [`Notices`] the API's use cases email through.

use axum::extract::ws::{Message, WebSocket};
use kemlock_app::notices::Notices;
use kemlock_app::ports::Notifier;
use kemlock_domain::{ChangeId, Owner, UserId};
use std::future::Future;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::broadcast::{self, error::RecvError};
use tokio::time::Instant;
use uuid::Uuid;

/// The text frame sent for a nudge.
pub const SYNC_FRAME: &str = r#"{"type":"sync"}"#;

/// The owner a nudge names when every socket should sync (a replica lost its link to the others
/// and can't know what it missed). It is the nil account, which no one has.
const EVERYONE: Owner = Owner::User(UserId(Uuid::nil()));

/// Where a commit's nudge goes when it isn't delivered locally.
type Outbound = Arc<dyn Fn(Owner) + Send + Sync>;

/// Fans "sync now" out to every open socket of the owner. Cheap to clone.
#[derive(Clone)]
pub struct LiveHub {
    tx: broadcast::Sender<Owner>,
    notices: Notices,
    outbound: Option<Outbound>,
}

impl std::fmt::Debug for LiveHub {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LiveHub")
            .field("outbound", &self.outbound.is_some())
            .field("notices", &self.notices)
            .finish_non_exhaustive()
    }
}

impl Default for LiveHub {
    fn default() -> Self {
        LiveHub::new()
    }
}

impl LiveHub {
    pub fn new() -> Self {
        let (tx, _rx) = broadcast::channel(256);
        LiveHub {
            tx,
            notices: Notices::logging(),
            outbound: None,
        }
    }

    /// Sends a commit's nudge to `outbound` instead of straight to this hub's sockets. The
    /// receiver is expected to deliver it back here with [`LiveHub::nudge`], on this replica and
    /// the others, so each socket hears it once.
    #[must_use]
    pub fn with_outbound(mut self, outbound: impl Fn(Owner) + Send + Sync + 'static) -> Self {
        self.outbound = Some(Arc::new(outbound));
        self
    }

    /// Sets the sender of the emails the use cases raise (approval requests, emergency access).
    #[must_use]
    pub fn with_notices(mut self, notices: Notices) -> Self {
        self.notices = notices;
        self
    }

    /// The sender of the emails the use cases raise.
    pub fn notices(&self) -> Notices {
        self.notices.clone()
    }

    /// Nudges every socket of `owner` on this replica. Sockets that aren't open miss it, which is
    /// fine: they sync when they connect.
    pub fn nudge(&self, owner: Owner) {
        // No receiver is not an error.
        let _ = self.tx.send(owner);
    }

    /// Nudges every open socket on this replica.
    pub fn nudge_all(&self) {
        let _ = self.tx.send(EVERYONE);
    }

    pub fn subscribe(&self) -> broadcast::Receiver<Owner> {
        self.tx.subscribe()
    }
}

impl Notifier for LiveHub {
    async fn sync_now(&self, owner: Owner, _change: ChangeId) {
        match &self.outbound {
            Some(outbound) => outbound(owner),
            None => self.nudge(owner),
        }
    }
}

/// How often an open socket checks that its session is still good.
pub const RECHECK_EVERY: Duration = Duration::from_secs(60);

/// How long a socket opened with a token that expires at `expires_at` (Unix seconds) may stay
/// open at `now`; zero when the token is already past it.
pub fn until_expiry(expires_at: i64, now: i64) -> Duration {
    Duration::from_secs(u64::try_from(expires_at.saturating_sub(now)).unwrap_or(0))
}

/// Serves one socket until either side closes, the session ends or the token that opened it
/// expires: forwards the nudges of any of `owners`, ignores what the client sends except for
/// closing.
///
/// A socket outlives the request that opened it, so the request's authentication has to be
/// enforced for as long as it is open. It closes at `lifetime` (the access token's remaining
/// time: a client reconnects with a fresh token), and every [`RECHECK_EVERY`] it asks
/// `still_valid`, which says whether the session still stands (the security stamp, the device
/// and its key), so a password change, a sign-out or a detected refresh-token reuse ends the
/// stream within a minute instead of at the token's end.
pub async fn serve_socket<F, Fut>(
    mut socket: WebSocket,
    hub: LiveHub,
    owners: Vec<Owner>,
    lifetime: Duration,
    mut still_valid: F,
) where
    F: FnMut() -> Fut + Send,
    Fut: Future<Output = bool> + Send,
{
    let mut nudges = hub.subscribe();
    let expiry = tokio::time::sleep(lifetime);
    tokio::pin!(expiry);
    let mut recheck = tokio::time::interval_at(Instant::now() + RECHECK_EVERY, RECHECK_EVERY);
    loop {
        tokio::select! {
            () = &mut expiry => break,
            _ = recheck.tick() => {
                if !still_valid().await {
                    break;
                }
            }
            nudge = nudges.recv() => {
                let send = match nudge {
                    Ok(o) if o == EVERYONE || owners.contains(&o) => true,
                    Ok(_) => false,
                    // Missed some nudges: one more is the right answer to all of them.
                    Err(RecvError::Lagged(_)) => true,
                    Err(RecvError::Closed) => break,
                };
                if send && socket.send(Message::Text(SYNC_FRAME.into())).await.is_err() {
                    break;
                }
            }
            incoming = socket.recv() => {
                match incoming {
                    None | Some(Err(_) | Ok(Message::Close(_))) => break,
                    Some(Ok(_)) => {}
                }
            }
        }
    }
    // Tell the client why the stream stopped; a failure just means it is gone already.
    let _ = socket.send(Message::Close(None)).await;
}

#[cfg(test)]
mod tests {
    use super::*;
    use kemlock_domain::{Hlc, ServerId, UserId};

    fn change() -> ChangeId {
        ChangeId {
            origin: ServerId::random(),
            seq: 1,
            hlc: Hlc(1),
        }
    }

    #[tokio::test]
    async fn a_nudge_reaches_subscribers() {
        let hub = LiveHub::new();
        let mut rx = hub.subscribe();
        let owner = Owner::User(UserId::random());
        hub.sync_now(owner, change()).await;
        assert_eq!(rx.recv().await.expect("a nudge"), owner);
    }

    #[test]
    fn a_socket_lives_until_its_token_expires() {
        assert_eq!(until_expiry(1_000, 400), Duration::from_secs(600));
        assert_eq!(until_expiry(1_000, 1_000), Duration::ZERO);
        // A token already past its end gets no time at all, never a wrapped huge one.
        assert_eq!(until_expiry(1_000, 5_000), Duration::ZERO);
        assert_eq!(until_expiry(i64::MIN, i64::MAX), Duration::ZERO);
    }

    #[tokio::test]
    async fn a_nudge_with_nobody_listening_is_fine() {
        let hub = LiveHub::new();
        hub.sync_now(Owner::User(UserId::random()), change()).await;
    }

    #[tokio::test]
    async fn with_an_outbound_a_commit_goes_there_and_not_to_the_sockets() {
        let seen = Arc::new(std::sync::Mutex::new(Vec::new()));
        let hub = LiveHub::new().with_outbound({
            let seen = seen.clone();
            move |owner| seen.lock().expect("lock").push(owner)
        });
        let mut rx = hub.subscribe();
        let owner = Owner::User(UserId::random());
        hub.sync_now(owner, change()).await;
        assert_eq!(*seen.lock().expect("lock"), vec![owner]);
        assert!(rx.try_recv().is_err(), "the sockets wait for the fan-out");
        // The fan-out delivers it back with `nudge`.
        hub.nudge(owner);
        assert_eq!(rx.recv().await.expect("a nudge"), owner);
    }

    #[tokio::test]
    async fn a_nudge_for_everyone_reaches_every_subscriber() {
        let hub = LiveHub::new();
        let mut rx = hub.subscribe();
        hub.nudge_all();
        assert_eq!(rx.recv().await.expect("a nudge"), EVERYONE);
    }

    #[test]
    fn the_hub_logs_notices_until_a_sender_is_set() {
        assert!(format!("{:?}", LiveHub::new()).contains("mail: false"));
    }
}
