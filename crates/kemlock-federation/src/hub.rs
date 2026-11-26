//! Pairing as two admin consoles drive it.
//!
//! One admin shows a one-time code ([`Pairings::new_code`]); the other types it
//! ([`Pairings::start`]). The CPace messages of `docs/federation.md` travel over plain HTTP between
//! the two servers (`POST /fed/v1/pair/start` and `/pair/finish`, [`PairingLink`] on the typing
//! side, [`Pairings::respond`] and [`Pairings::finish`] on the showing side): the code is the
//! authentication, so nothing else is needed, and a wrong code leaves the other side learning
//! nothing. When the exchange succeeds each side holds the other's verified descriptor and a
//! six-word fingerprint, **not yet pinned**: the admin compares the words with the other admin's
//! and confirms ([`Pairings::confirm`]), which pins the identity key and records what they
//! acknowledged. Until then the peer is not a peer.
//!
//! The state is in memory: a restart forgets a code and a pairing in progress, and the admins
//! start again, which costs a minute and can't leave a half-paired peer.

use crate::addr::Trust;
use crate::descriptor::SignedDescriptor;
use crate::error::{FedError, Result};
use crate::extra::Acknowledgement;
use crate::net::Http;
use crate::pairing::{
    CODE_LIFETIME_SECS, Fingerprint, PairingCode, PairingInitiator, PendingPairing, respond,
};
use crate::ports::Peer;
use crate::replicate::{FedStore, Replica};
use kemlock_app::federation_view::BoxFut;
use kemlock_domain::ServerId;
use std::collections::HashMap;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};

/// The most pairings in progress at once, per side.
const MAX_PENDING: usize = 8;

/// How the typing side reaches the showing side. The network implementation is [`HttpLink`]; the
/// gate test hands the messages straight to the other server.
pub trait PairingLink: Send + Sync {
    /// Sends message 1 to the server at `address`; returns message 2.
    fn start(&self, address: &str, message: Vec<u8>) -> BoxFut<'_, Result<Vec<u8>>>;
    /// Sends message 3 for the pairing `initiator` started.
    fn finish(
        &self,
        address: &str,
        initiator: ServerId,
        message: Vec<u8>,
    ) -> BoxFut<'_, Result<()>>;
}

/// [`PairingLink`] over HTTP.
#[derive(Clone, Debug)]
pub struct HttpLink(pub Http);

impl PairingLink for HttpLink {
    fn start(&self, address: &str, message: Vec<u8>) -> BoxFut<'_, Result<Vec<u8>>> {
        // The admin typed this address: it may be `http` and on a private network.
        let address = address.to_owned();
        Box::pin(async move {
            self.0
                .post(&address, "/fed/v1/pair/start", message, Trust::Admin)
                .await
        })
    }

    fn finish(
        &self,
        address: &str,
        initiator: ServerId,
        message: Vec<u8>,
    ) -> BoxFut<'_, Result<()>> {
        let address = address.to_owned();
        let path = format!("/fed/v1/pair/finish?initiator={initiator}");
        Box::pin(async move {
            self.0
                .post(&address, &path, message, Trust::Admin)
                .await
                .map(|_| ())
        })
    }
}

/// Which side of the pairing this server was.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Side {
    /// The admin here typed the code.
    Typed,
    /// The admin here showed the code.
    Showed,
}

/// A pairing whose exchange succeeded and that waits for the admin to compare the fingerprint.
#[derive(Clone, Debug)]
pub struct AwaitingPeer {
    pub descriptor: SignedDescriptor,
    pub fingerprint: Fingerprint,
    pub side: Side,
    /// The address the admin typed, if this side typed the code.
    pub address: Option<String>,
    /// Unix seconds.
    pub since: u64,
}

impl AwaitingPeer {
    pub fn server(&self) -> ServerId {
        self.descriptor.descriptor.server
    }

    pub fn words(&self) -> Vec<String> {
        self.fingerprint.words()
    }
}

/// What the admin confirms.
#[derive(Clone, Debug)]
pub struct Confirmation {
    /// The admin compared the six words with the other admin's and they match.
    pub fingerprint_matches: bool,
    /// Needed when the peer's operator isn't this server's: the three acknowledgements.
    pub acknowledgement: Option<Acknowledgement>,
}

#[derive(Default)]
struct HubState {
    code: Option<(PairingCode, u64)>,
    responding: HashMap<ServerId, (PendingPairing, u64)>,
    awaiting: HashMap<ServerId, AwaitingPeer>,
}

/// The pairing state of one server.
pub struct Pairings<S> {
    replica: Arc<Replica<S>>,
    link: Arc<dyn PairingLink>,
    state: Mutex<HubState>,
}

impl<S> std::fmt::Debug for Pairings<S> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Pairings").finish_non_exhaustive()
    }
}

impl<S: FedStore> Pairings<S> {
    pub fn new(replica: Arc<Replica<S>>, link: Arc<dyn PairingLink>) -> Pairings<S> {
        Pairings {
            replica,
            link,
            state: Mutex::new(HubState::default()),
        }
    }

    fn state(&self) -> MutexGuard<'_, HubState> {
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Makes a one-time code, replacing any earlier one. Returns it as shown (`XXXX-XXXX-XXXX`)
    /// and when it expires.
    pub fn new_code(&self, now: u64) -> (String, u64) {
        let code = PairingCode::generate();
        let shown = code.display();
        let expires = now + CODE_LIFETIME_SECS;
        self.state().code = Some((code, expires));
        (shown, expires)
    }

    /// Whether a code is waiting to be typed on the other side.
    pub fn code_waiting(&self, now: u64) -> bool {
        self.state()
            .code
            .as_ref()
            .is_some_and(|(_, expires)| *expires > now)
    }

    /// Message 1 from the typing side: uses up the code (right or wrong, it is good for one
    /// attempt) and answers with message 2.
    pub fn respond(&self, message: &[u8], now: u64) -> Result<Vec<u8>> {
        let initiator = initiator_of(message)?;
        let code = {
            let mut state = self.state();
            match state.code.take() {
                Some((code, expires)) if expires > now => code,
                _ => return Err(FedError::Pairing),
            }
        };
        let identity = self.replica.identity();
        let (pending, reply) = respond(code, &identity, message)?;
        let mut state = self.state();
        state.responding.retain(|_, (_, expires)| *expires > now);
        if state.responding.len() >= MAX_PENDING {
            return Err(FedError::Pairing);
        }
        state
            .responding
            .insert(initiator, (pending, now + CODE_LIFETIME_SECS));
        Ok(reply)
    }

    /// Message 3 from the typing side: if it opens, the exchange succeeded and the peer waits for
    /// the admin's confirmation.
    pub fn finish(&self, initiator: ServerId, message: &[u8], now: u64) -> Result<()> {
        let pending = {
            let mut state = self.state();
            match state.responding.remove(&initiator) {
                Some((pending, expires)) if expires > now => pending,
                _ => return Err(FedError::Pairing),
            }
        };
        let paired = pending.finish(message, now)?;
        self.hold(AwaitingPeer {
            descriptor: paired.descriptor,
            fingerprint: paired.fingerprint,
            side: Side::Showed,
            address: None,
            since: now,
        })
    }

    fn hold(&self, awaiting: AwaitingPeer) -> Result<()> {
        let mut state = self.state();
        if state.awaiting.len() >= MAX_PENDING {
            return Err(FedError::Pairing);
        }
        state.awaiting.insert(awaiting.server(), awaiting);
        Ok(())
    }

    /// The admin here typed `typed` (the code as the other admin showed it) for the server at
    /// `address`. Runs the exchange. Returns the pairing that now waits for the confirmation.
    pub async fn start(&self, address: &str, typed: &str, now: u64) -> Result<AwaitingPeer> {
        let code = PairingCode::parse(typed)?;
        let identity = self.replica.identity();
        let (initiator, first) = PairingInitiator::start(&code, &identity)?;
        let second = self.link.start(address, first).await?;
        let (paired, third) = initiator.finish(&second, now)?;
        if paired.descriptor.descriptor.server == identity.server {
            return Err(FedError::Refused("a server can't pair with itself"));
        }
        self.link.finish(address, identity.server, third).await?;
        let awaiting = AwaitingPeer {
            descriptor: paired.descriptor,
            fingerprint: paired.fingerprint,
            side: Side::Typed,
            address: Some(address.trim_end_matches('/').to_owned()),
            since: now,
        };
        self.hold(awaiting.clone())?;
        Ok(awaiting)
    }

    /// The pairings that wait for the admin.
    pub fn awaiting(&self, now: u64) -> Vec<AwaitingPeer> {
        let mut state = self.state();
        state
            .awaiting
            .retain(|_, a| a.since.saturating_add(CODE_LIFETIME_SECS) > now);
        let mut out: Vec<AwaitingPeer> = state.awaiting.values().cloned().collect();
        out.sort_by_key(|a| a.since);
        out
    }

    /// The admin walked away from a pairing.
    pub fn cancel(&self, peer: ServerId) -> bool {
        self.state().awaiting.remove(&peer).is_some()
    }

    /// The admin compared the words and confirms: pins the peer's identity key and records the
    /// acknowledgements. A peer run by another operator needs all three.
    pub async fn confirm(
        &self,
        peer: ServerId,
        confirmation: Confirmation,
        now: u64,
    ) -> Result<Peer> {
        let awaiting = self
            .state()
            .awaiting
            .get(&peer)
            .cloned()
            .ok_or(FedError::Pairing)?;
        if !confirmation.fingerprint_matches {
            self.cancel(peer);
            return Err(FedError::Refused(
                "the fingerprints differ: someone is between the two servers",
            ));
        }
        let ours = self
            .replica
            .identity()
            .descriptor
            .descriptor
            .operator
            .clone();
        let foreign = awaiting.descriptor.descriptor.operator != ours;
        if foreign
            && !confirmation
                .acknowledgement
                .as_ref()
                .is_some_and(Acknowledgement::complete)
        {
            return Err(FedError::Refused(
                "a server run by another operator needs the three acknowledgements",
            ));
        }
        let mut pinned = self.replica.pin_peer(&awaiting.descriptor, now).await?;
        if let Some(address) = &awaiting.address
            && !pinned.addresses.contains(address)
        {
            // The admin typed an address the descriptor doesn't list (a name on the private
            // network): keep it first, so the runner tries it.
            pinned.addresses.insert(0, address.clone());
            self.replica
                .store()
                .update_peer_descriptor(
                    pinned.id,
                    &pinned.operator,
                    &pinned.addresses,
                    &pinned.suites,
                )
                .await?;
        }
        // What the admin typed, and what the descriptor listed when the admin confirmed the pairing
        // (the exchange was authenticated by the code), may be dialled as the admin chose: over
        // `http`, on a private network. Addresses a later descriptor adds may not.
        self.replica
            .store()
            .trust_addresses(pinned.id, &pinned.addresses)
            .await?;
        if let Some(ack) = &confirmation.acknowledgement {
            self.replica.store().put_acknowledgement(peer, ack).await?;
        }
        self.state().awaiting.remove(&peer);
        Ok(pinned)
    }
}

/// The initiator's server id in message 1.
fn initiator_of(message: &[u8]) -> Result<ServerId> {
    let value = crate::cbor::Value::decode(message).map_err(|_| FedError::Pairing)?;
    let fields = value.as_fields().map_err(|_| FedError::Pairing)?;
    let id = fields.fixed::<16>(3).map_err(|_| FedError::Pairing)?;
    Ok(crate::wire::server_id(id))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::extra::FedAdminRepo as _;
    use crate::memory::MemoryStore;
    use crate::suite::Suite;
    use crate::testing::identity;

    const NOW: u64 = 1_800_000_000;

    /// A link that hands the messages straight to the other server's hub.
    struct Loop(Arc<Pairings<MemoryStore>>);

    impl PairingLink for Loop {
        fn start(&self, _address: &str, message: Vec<u8>) -> BoxFut<'_, Result<Vec<u8>>> {
            Box::pin(async move { self.0.respond(&message, NOW) })
        }

        fn finish(
            &self,
            _address: &str,
            initiator: ServerId,
            message: Vec<u8>,
        ) -> BoxFut<'_, Result<()>> {
            Box::pin(async move { self.0.finish(initiator, &message, NOW) })
        }
    }

    /// A link with nobody at the other end, for the side that only shows the code.
    struct Nobody;

    impl PairingLink for Nobody {
        fn start(&self, _address: &str, _message: Vec<u8>) -> BoxFut<'_, Result<Vec<u8>>> {
            Box::pin(async { Err(FedError::Pairing) })
        }

        fn finish(
            &self,
            _address: &str,
            _initiator: ServerId,
            _message: Vec<u8>,
        ) -> BoxFut<'_, Result<()>> {
            Box::pin(async { Err(FedError::Pairing) })
        }
    }

    fn confirmation() -> Confirmation {
        Confirmation {
            fingerprint_matches: true,
            acknowledgement: Some(Acknowledgement {
                metadata: true,
                deletion: true,
                cross_border: true,
                by: "an admin".to_owned(),
                at: NOW,
            }),
        }
    }

    #[tokio::test]
    async fn the_addresses_the_admin_typed_and_confirmed_are_the_ones_that_may_be_private() {
        let ia = identity(1, NOW, &Suite::IMPLEMENTED);
        let ib = identity(2, NOW, &Suite::IMPLEMENTED);
        let (a_id, b_id) = (ia.server, ib.server);
        let a = Arc::new(Replica::new(MemoryStore::new(a_id), Arc::new(ia)));
        let b = Arc::new(Replica::new(MemoryStore::new(b_id), Arc::new(ib)));
        let shower = Arc::new(Pairings::new(b.clone(), Arc::new(Nobody)));
        let typer = Pairings::new(a.clone(), Arc::new(Loop(shower.clone())));

        let (code, _) = shower.new_code(NOW);
        // The admin of A types a private address that B's descriptor doesn't list.
        let typed = "http://192.168.1.5:8080";
        let awaiting = typer.start(typed, &code, NOW).await.expect("paired");
        assert_eq!(awaiting.server(), b_id);
        typer
            .confirm(b_id, confirmation(), NOW)
            .await
            .expect("confirmed");
        let trusted = a.store().trusted_addresses(b_id).await.expect("trusted");
        assert!(trusted.iter().any(|t| t == typed), "{trusted:?}");
        assert!(
            trusted.iter().any(|t| t == "https://s2.example.org"),
            "what the descriptor listed when the admin confirmed: {trusted:?}"
        );

        // B only showed the code: what A's descriptor lists is what its admin confirmed.
        shower
            .confirm(a_id, confirmation(), NOW)
            .await
            .expect("confirmed");
        let trusted = b.store().trusted_addresses(a_id).await.expect("trusted");
        assert_eq!(trusted, vec!["https://s1.example.org".to_owned()]);
        // A server nobody paired has nothing trusted.
        assert!(
            a.store()
                .trusted_addresses(ServerId::random())
                .await
                .expect("trusted")
                .is_empty()
        );
    }
}
