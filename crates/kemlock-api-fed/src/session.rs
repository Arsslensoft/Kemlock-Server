//! The peer session over any duplex stream of binary messages: the hello and its reply, then one
//! sealed frame in and one out. The WebSocket route adapts a socket to [`Duplex`]; the tests use
//! channels.

use crate::state::{FedEvent, FedState};
use kemlock_federation::{FedError, FedStore, SessionServer, unix_now};
use std::future::Future;
use std::time::Duration;

/// Frames a peer may send per minute before the session is dropped.
pub const MAX_FRAMES_PER_MINUTE: u32 = 1_000;

/// How long a connection may take to send its hello. The route is open to the internet, so a
/// connection that opens a socket and says nothing would otherwise hold a task and a descriptor
/// for as long as it likes.
pub const HELLO_TIMEOUT: Duration = Duration::from_secs(10);

/// A stream of binary messages in both directions.
pub trait Duplex: Send {
    /// The next message, or `None` when the peer closed or the stream failed.
    fn recv(&mut self) -> impl Future<Output = Option<Vec<u8>>> + Send;
    /// Sends a message; false when the stream is gone.
    fn send(&mut self, message: Vec<u8>) -> impl Future<Output = bool> + Send;
}

/// How a session ended.
#[derive(Debug, PartialEq, Eq)]
pub enum SessionEnd {
    /// The peer ended it with the last frame, and the answer to that was sent.
    Closed,
    /// The stream ended without the last frame: the peer vanished or the stream was cut short.
    Cut,
    /// The session was refused or dropped; nothing more was sent.
    Refused(FedError),
}

/// Counts frames in the current minute.
#[derive(Debug)]
struct RateWindow {
    started: u64,
    count: u32,
}

impl RateWindow {
    fn new(now: u64) -> RateWindow {
        RateWindow {
            started: now,
            count: 0,
        }
    }

    fn allow(&mut self, now: u64) -> bool {
        if now >= self.started.saturating_add(60) {
            self.started = now;
            self.count = 0;
        }
        self.count += 1;
        self.count <= MAX_FRAMES_PER_MINUTE
    }
}

fn refuse<S: FedStore>(state: &FedState<S>, error: FedError) -> SessionEnd {
    match &error {
        FedError::KeyMismatch { offered } => {
            tracing::warn!(
                offered = %hex::encode(offered),
                "a federation peer offered an identity key that is not the pinned one"
            );
            state.emit(FedEvent::KeyMismatch {
                offered: offered.clone(),
            });
        }
        other => {
            tracing::info!(error = %other, "a federation session was refused");
            state.emit(FedEvent::Refused {
                reason: other.to_string(),
            });
        }
    }
    SessionEnd::Refused(error)
}

/// Runs one session to its end. `clock` gives Unix seconds.
pub async fn serve_session<S: FedStore, D: Duplex>(
    state: &FedState<S>,
    io: &mut D,
    clock: fn() -> u64,
) -> SessionEnd {
    serve_session_within(state, io, clock, HELLO_TIMEOUT).await
}

/// [`serve_session`], waiting `hello_timeout` for the hello.
pub async fn serve_session_within<S: FedStore, D: Duplex>(
    state: &FedState<S>,
    io: &mut D,
    clock: fn() -> u64,
    hello_timeout: Duration,
) -> SessionEnd {
    let Ok(Some(hello)) = tokio::time::timeout(hello_timeout, io.recv()).await else {
        // Nothing came in time, or the stream ended.
        return SessionEnd::Cut;
    };
    let accepted = state
        .replica
        .accept_shared(&state.nonces, &hello, clock())
        .await;
    let (reply, session) = match accepted {
        Ok(accepted) => accepted,
        Err(error) => return refuse(state, error),
    };
    if !io.send(reply).await {
        return SessionEnd::Cut;
    }

    let mut server = SessionServer::new(state.replica.clone(), session);
    let mut window = RateWindow::new(clock());
    loop {
        let Some(frame) = io.recv().await else {
            return SessionEnd::Cut;
        };
        let now = clock();
        if !window.allow(now) {
            return refuse(state, FedError::Refused("too many frames from this peer"));
        }
        match server.on_frame(&frame, now).await {
            Ok(handled) => {
                if let Some(vault) = handled.pull {
                    state.emit(FedEvent::Nudge {
                        peer: server.peer(),
                        vault,
                    });
                }
                if !io.send(handled.reply).await {
                    return SessionEnd::Cut;
                }
                if handled.closed {
                    return SessionEnd::Closed;
                }
            }
            Err(error) => return refuse(state, error),
        }
    }
}

/// [`serve_session`] with the system clock.
pub async fn serve<S: FedStore, D: Duplex>(state: &FedState<S>, io: &mut D) -> SessionEnd {
    serve_session(state, io, unix_now).await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_window_allows_a_burst_up_to_the_limit_and_resets() {
        let mut w = RateWindow::new(100);
        for _ in 0..MAX_FRAMES_PER_MINUTE {
            assert!(w.allow(100));
        }
        assert!(!w.allow(101));
        assert!(w.allow(160));
    }
}
