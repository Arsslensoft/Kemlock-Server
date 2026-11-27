//! Sessions over a transport: the requester's end ([`SecureChannel`]) and the responder's end
//! ([`SessionServer`]).
//!
//! A [`Transport`] moves one message and brings back one: first the hello and the reply, then a
//! sealed frame and the frame answering it. The HTTP layer's WebSocket is one transport; the
//! tests use a function call.

use crate::descriptor::SignedDescriptor;
use crate::error::{FedError, Result};
use crate::handshake::{self, Initiator, NonceCache, Session};
use crate::message::{Request, Response};
#[cfg(test)]
use crate::ports::PeerRepo;
use crate::ports::PeerState;
use crate::replicate::{Channel, FedStore, Replica};
use kemlock_domain::{Owner, ServerId};
use std::future::Future;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

/// The wall clock in Unix seconds, for callers that have no better source.
pub fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

/// Sends one message to the peer and waits for its one answer.
pub trait Transport: Send {
    fn exchange(&mut self, message: Vec<u8>) -> impl Future<Output = Result<Vec<u8>>> + Send;
}

/// The requester's end of an established session: requests go out as sealed frames, responses
/// come back as sealed frames.
#[derive(Debug)]
pub struct SecureChannel<T> {
    session: Session,
    transport: T,
    clock: fn() -> u64,
}

impl<T: Transport> SecureChannel<T> {
    pub fn new(session: Session, transport: T) -> SecureChannel<T> {
        SecureChannel {
            session,
            transport,
            clock: unix_now,
        }
    }

    /// Uses `clock` (Unix seconds) for the hourly rekey instead of the system's.
    pub fn with_clock(mut self, clock: fn() -> u64) -> SecureChannel<T> {
        self.clock = clock;
        self
    }

    pub fn session(&self) -> &Session {
        &self.session
    }

    /// The transport under the session, for tests that play frames into it directly.
    #[doc(hidden)]
    pub fn transport_mut(&mut self) -> &mut T {
        &mut self.transport
    }

    async fn round_trip(&mut self, request: &Request, last: bool) -> Result<Response> {
        let now = (self.clock)();
        let frame = self.session.writer.seal(&request.encode(), last, now)?;
        let reply = self.transport.exchange(frame).await?;
        let opened = self.session.reader.open(&reply)?;
        if opened.last != last {
            return Err(FedError::Frame(
                "the answer did not end the stream as asked",
            ));
        }
        Response::decode(&opened.payload)
    }

    /// Ends the session: sends the last frame and checks the answer ended the stream too, so a
    /// stream cut short is noticed.
    pub async fn close(mut self) -> Result<()> {
        match self.round_trip(&Request::Bye, true).await? {
            Response::Ack => self.session.reader.finish(),
            _ => Err(FedError::Malformed("an unexpected answer to the goodbye")),
        }
    }
}

impl<T: Transport> Channel for SecureChannel<T> {
    async fn call(&mut self, request: &Request) -> Result<Response> {
        self.round_trip(request, false).await
    }
}

/// What the responder did with one frame.
#[derive(Debug)]
pub struct Handled {
    /// The sealed frame to send back.
    pub reply: Vec<u8>,
    /// A vault the peer showed it has more of: schedule a pull.
    pub pull: Option<Owner>,
    /// The peer ended the session.
    pub closed: bool,
}

/// The responder's end of an established session.
#[derive(Debug)]
pub struct SessionServer<S> {
    replica: Arc<Replica<S>>,
    session: Session,
}

impl<S: FedStore> SessionServer<S> {
    pub fn new(replica: Arc<Replica<S>>, session: Session) -> SessionServer<S> {
        SessionServer { replica, session }
    }

    /// The paired peer on the other end.
    pub fn peer(&self) -> ServerId {
        self.session.peer
    }

    /// Opens one request frame, answers it and seals the answer. Any frame that isn't the next
    /// one, unchanged, is an error and the session should be dropped.
    pub async fn on_frame(&mut self, frame: &[u8], now: u64) -> Result<Handled> {
        let opened = self.session.reader.open(frame)?;
        let request = Request::decode(&opened.payload)?;
        let served = self.replica.serve(self.session.peer, &request, now).await;
        let reply = self
            .session
            .writer
            .seal(&served.response.encode(), opened.last, now)?;
        Ok(Handled {
            reply,
            pull: served.pull,
            closed: opened.last,
        })
    }
}

impl<S: FedStore> Replica<S> {
    /// Opens a session to a paired peer: checks its descriptor against the pinned key, sends the
    /// hello through `transport` and finishes the handshake with the reply.
    pub async fn connect<T: Transport>(
        &self,
        peer: ServerId,
        descriptor: &SignedDescriptor,
        mut transport: T,
        now: u64,
    ) -> Result<SecureChannel<T>> {
        let stored = self
            .store
            .get_peer(peer)
            .await?
            .filter(|p| p.state == PeerState::Paired)
            .ok_or(FedError::UnknownPeer)?;
        let pinned = stored.key()?;
        let (initiator, hello) = Initiator::start(&self.identity(), descriptor, &pinned, now)?;
        let reply = transport.exchange(hello).await?;
        let session = initiator.finish(&reply, now, self.padding)?;
        Ok(SecureChannel::new(session, transport))
    }

    /// [`accept`](Self::accept) with the nonce cache behind a lock that is held only while the
    /// handshake itself runs, which needs no storage: the keys of the paired peers are read before
    /// it is taken and the peer's last-seen time is written after it is let go, so a slow database
    /// can't make every other hello wait on the lock.
    pub async fn accept_shared(
        &self,
        cache: &tokio::sync::Mutex<NonceCache>,
        hello: &[u8],
        now: u64,
    ) -> Result<(Vec<u8>, Session)> {
        let keys = self.peer_keys().await?;
        let accepted = {
            let mut cache = cache.lock().await;
            handshake::respond(&self.identity(), &keys, &mut cache, hello, now, self.padding)?
        };
        self.store.touch_peer(accepted.session.peer, now).await?;
        Ok((accepted.reply, accepted.session))
    }

    /// Answers a hello from a peer. Only a paired peer gets past it. Returns the reply to send
    /// and the responder's end of the session.
    pub async fn accept(
        &self,
        cache: &mut NonceCache,
        hello: &[u8],
        now: u64,
    ) -> Result<(Vec<u8>, Session)> {
        let keys = self.peer_keys().await?;
        let accepted =
            handshake::respond(&self.identity(), &keys, cache, hello, now, self.padding)?;
        self.store.touch_peer(accepted.session.peer, now).await?;
        Ok((accepted.reply, accepted.session))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::memory::MemoryStore;
    use crate::suite::Suite;
    use crate::testing::{draft, identity};
    use kemlock_domain::{ItemId, UserId};
    use std::sync::Mutex;

    /// A transport that hands every message to the other replica in this process. The first
    /// message is the hello; the rest are frames.
    struct InProcess {
        remote: Arc<Replica<MemoryStore>>,
        cache: NonceCache,
        server: Option<SessionServer<MemoryStore>>,
        now: u64,
        /// Frames seen on the wire, for the replay and tamper tests.
        wire: Arc<Mutex<Vec<Vec<u8>>>>,
        /// Alters the next frame sent, if set.
        tamper: Arc<Mutex<bool>>,
    }

    impl Transport for InProcess {
        async fn exchange(&mut self, message: Vec<u8>) -> Result<Vec<u8>> {
            let mut message = message;
            if self.server.is_none() {
                let (reply, session) = self
                    .remote
                    .accept(&mut self.cache, &message, self.now)
                    .await?;
                self.server = Some(SessionServer::new(self.remote.clone(), session));
                return Ok(reply);
            }
            if std::mem::take(&mut *self.tamper.lock().expect("tamper")) {
                let n = message.len();
                message[n - 1] ^= 1;
            }
            self.wire.lock().expect("wire").push(message.clone());
            let handled = match self.server.as_mut() {
                Some(server) => server.on_frame(&message, self.now).await?,
                None => return Err(FedError::Frame("no session")),
            };
            Ok(handled.reply)
        }
    }

    const NOW: u64 = 1_800_000_000;

    fn now() -> u64 {
        NOW
    }

    struct World {
        a: Arc<Replica<MemoryStore>>,
        b: Arc<Replica<MemoryStore>>,
        vault: Owner,
    }

    async fn world() -> World {
        let ia = identity(1, NOW, &Suite::IMPLEMENTED);
        let ib = identity(2, NOW, &Suite::IMPLEMENTED);
        let a = Arc::new(Replica::new(
            MemoryStore::new(ia.server),
            Arc::new(ia.clone()),
        ));
        let b = Arc::new(Replica::new(
            MemoryStore::new(ib.server),
            Arc::new(ib.clone()),
        ));
        a.pin_peer(&ib.descriptor, NOW).await.expect("pin");
        b.pin_peer(&ia.descriptor, NOW).await.expect("pin");
        let vault = Owner::User(UserId::random());
        a.federate(vault, vec![ib.server]).await.expect("federate");
        b.accept_vault(vault, ia.server, vec![ib.server])
            .await
            .expect("accept");
        World { a, b, vault }
    }

    fn transport(remote: &Arc<Replica<MemoryStore>>) -> InProcess {
        InProcess {
            remote: remote.clone(),
            cache: NonceCache::new(),
            server: None,
            now: NOW,
            wire: Arc::new(Mutex::new(Vec::new())),
            tamper: Arc::new(Mutex::new(false)),
        }
    }

    #[tokio::test]
    async fn a_session_carries_a_pull_and_closes_cleanly() {
        let w = world().await;
        w.a.store
            .put(draft(ItemId::random(), w.vault, None, 1, 1_000))
            .expect("put");
        let mut channel =
            w.b.connect(
                w.a.server_id(),
                &w.a.identity().descriptor,
                transport(&w.a),
                NOW,
            )
            .await
            .expect("connect")
            .with_clock(now);
        let report =
            w.b.pull(&mut channel, w.a.server_id(), w.vault)
                .await
                .expect("pull");
        assert_eq!(report.counts.applied, 1);
        w.b.nudge(&mut channel, w.vault).await.expect("nudge");
        channel.close().await.expect("close");
        // The responder saw the peer: last_seen is set.
        let peer =
            w.a.store
                .get_peer(w.b.server_id())
                .await
                .expect("get")
                .expect("peer");
        assert_eq!(peer.last_seen, Some(NOW));
    }

    #[tokio::test]
    async fn a_replayed_frame_is_refused_by_the_session() {
        let w = world().await;
        let t = transport(&w.a);
        let wire = t.wire.clone();
        let mut channel =
            w.b.connect(w.a.server_id(), &w.a.identity().descriptor, t, NOW)
                .await
                .expect("connect")
                .with_clock(now);
        w.b.nudge(&mut channel, w.vault).await.expect("nudge");
        let recorded = wire.lock().expect("wire")[0].clone();
        // An attacker plays the recorded frame again into the same session.
        let again = channel.transport.exchange(recorded).await;
        assert!(again.is_err());
    }

    #[tokio::test]
    async fn a_tampered_frame_is_refused_and_does_not_change_the_store() {
        let w = world().await;
        w.a.store
            .put(draft(ItemId::random(), w.vault, None, 1, 1_000))
            .expect("put");
        let t = transport(&w.a);
        let tamper = t.tamper.clone();
        let mut channel =
            w.b.connect(w.a.server_id(), &w.a.identity().descriptor, t, NOW)
                .await
                .expect("connect")
                .with_clock(now);
        *tamper.lock().expect("tamper") = true;
        assert!(
            w.b.pull(&mut channel, w.a.server_id(), w.vault)
                .await
                .is_err()
        );
        assert_eq!(w.b.store.len(), 0);
    }

    #[tokio::test]
    async fn a_stranger_cannot_open_a_session() {
        let w = world().await;
        let stranger = identity(7, NOW, &Suite::IMPLEMENTED);
        let outsider = Arc::new(Replica::new(
            MemoryStore::new(stranger.server),
            Arc::new(stranger.clone()),
        ));
        // The stranger pins A (it can read A's public descriptor) but A never paired with it.
        outsider
            .pin_peer(&w.a.identity().descriptor, NOW)
            .await
            .expect("pin");
        let result = outsider
            .connect(
                w.a.server_id(),
                &w.a.identity().descriptor,
                transport(&w.a),
                NOW,
            )
            .await;
        assert!(matches!(result, Err(FedError::UnknownPeer)));
    }

    #[tokio::test]
    async fn a_revoked_peer_cannot_connect() {
        let w = world().await;
        w.a.store
            .set_peer_state(w.b.server_id(), PeerState::Revoked)
            .await
            .expect("revoke");
        let result =
            w.b.connect(
                w.a.server_id(),
                &w.a.identity().descriptor,
                transport(&w.a),
                NOW,
            )
            .await;
        assert!(result.is_err());
    }

    #[test]
    fn the_clock_reads_a_plausible_time() {
        assert!(unix_now() > 1_700_000_000);
    }
}
