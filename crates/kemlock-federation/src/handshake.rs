//! The session handshake: mutual authentication and session keys between two paired servers.
//!
//! Server A (the initiator) has read server B's descriptor and checked it against B's pinned
//! identity key. A sends a **hello**: a fresh ephemeral `kx1` key, an encapsulation to B's KEM
//! key, both suite lists, the chosen suite, a nonce, a timestamp and A's own descriptor, all
//! signed with A's identity key. B checks it against A's pinned key and answers with a **reply**:
//! encapsulations to A's ephemeral key and to A's KEM key, a session id, a nonce and a timestamp,
//! signed over the transcript. Both derive the session keys from the three shared secrets and the
//! transcript hash. The formats and labels are in `docs/federation.md`.
//!
//! This module is sans-IO: it takes bytes and the time and returns bytes and a [`Session`].

use crate::cbor::Value;
use crate::crypto;
use crate::descriptor::{SKEW_SECS, SignedDescriptor, kem_key_id};
use crate::error::{FedError, Result};
use crate::frame::{Direction, FrameReader, FrameWriter, Padding};
use crate::identity::{KemPair, KeyDirectory, LocalIdentity};
use crate::signed::Signed;
use crate::suite::{self, Suite};
use crate::wire::server_id;
use kemlock_crypto::{kx1, sig1};
use kemlock_domain::ServerId;
use std::collections::HashMap;
use zeroize::Zeroizing;

/// The handshake format version.
pub const VERSION: u64 = 1;
/// The `sig1` context of a hello's signature.
pub const HELLO_CONTEXT: &str = "federation-hello";
/// The `sig1` context of a reply's signature, which covers the transcript hash.
pub const REPLY_CONTEXT: &str = "federation-reply";
/// The label hashed into the transcript.
pub const TRANSCRIPT_LABEL: &[u8] = b"kemlock/v1/fed/transcript";
/// The largest hello or reply either side reads.
pub const MAX_MESSAGE: usize = 64 * 1024;

/// Which side of the handshake a session came from.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Role {
    Initiator,
    Responder,
}

/// An established session: the frame streams of both directions.
#[derive(Debug)]
pub struct Session {
    pub id: [u8; 16],
    pub peer: ServerId,
    pub suite: Suite,
    pub role: Role,
    pub writer: FrameWriter,
    pub reader: FrameReader,
}

impl Session {
    fn new(
        role: Role,
        id: [u8; 16],
        peer: ServerId,
        suite: Suite,
        prk: &[u8; 32],
        now: u64,
        padding: Padding,
    ) -> Result<Session> {
        let aead = suite.aead()?;
        let (out, inn) = match role {
            Role::Initiator => (
                Direction::InitiatorToResponder,
                Direction::ResponderToInitiator,
            ),
            Role::Responder => (
                Direction::ResponderToInitiator,
                Direction::InitiatorToResponder,
            ),
        };
        Ok(Session {
            id,
            peer,
            suite,
            role,
            writer: FrameWriter::new(id, aead, prk, out, now, padding),
            reader: FrameReader::new(id, aead, prk, inn),
        })
    }
}

/// The initiator's first message, before its signature.
#[derive(Clone, Debug)]
pub struct Hello {
    pub initiator: ServerId,
    pub responder: ServerId,
    pub responder_kem_id: [u8; 32],
    pub ephemeral: kx1::PublicKey,
    pub ct_responder: Vec<u8>,
    pub initiator_suites: Vec<String>,
    pub responder_suites: Vec<String>,
    pub suite: String,
    pub nonce: [u8; 32],
    pub timestamp: u64,
    pub descriptor: Vec<u8>,
}

impl Hello {
    pub fn to_body(&self) -> Vec<u8> {
        Value::map(vec![
            (0, Value::Uint(VERSION)),
            (1, Value::bytes(self.initiator.as_bytes())),
            (2, Value::bytes(self.responder.as_bytes())),
            (3, Value::bytes(&self.responder_kem_id)),
            (4, Value::bytes(self.ephemeral.as_bytes())),
            (5, Value::bytes(&self.ct_responder)),
            (
                6,
                Value::Array(
                    self.initiator_suites
                        .iter()
                        .map(|s| Value::text(s))
                        .collect(),
                ),
            ),
            (
                7,
                Value::Array(
                    self.responder_suites
                        .iter()
                        .map(|s| Value::text(s))
                        .collect(),
                ),
            ),
            (8, Value::text(&self.suite)),
            (9, Value::bytes(&self.nonce)),
            (10, Value::Uint(self.timestamp)),
            (11, Value::bytes(&self.descriptor)),
        ])
        .encode()
    }

    pub fn from_body(body: &[u8]) -> Result<Hello> {
        let value = Value::decode(body)?;
        let f = value.as_fields()?;
        f.only(&[0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11])?;
        if f.uint(0)? != VERSION {
            return Err(FedError::Malformed("unknown handshake version"));
        }
        let ct_responder = f.bytes(5)?;
        if ct_responder.len() != kx1::CIPHERTEXT_LEN {
            return Err(FedError::Malformed(
                "the encapsulation has the wrong length",
            ));
        }
        Ok(Hello {
            initiator: server_id(f.fixed::<16>(1)?),
            responder: server_id(f.fixed::<16>(2)?),
            responder_kem_id: f.fixed::<32>(3)?,
            ephemeral: kx1::PublicKey::from_bytes(f.bytes(4)?)
                .map_err(|_| FedError::Malformed("the ephemeral key has the wrong length"))?,
            ct_responder: ct_responder.to_vec(),
            initiator_suites: f.texts(6, 16, 64)?,
            responder_suites: f.texts(7, 16, 64)?,
            suite: f.text(8)?.to_owned(),
            nonce: f.fixed::<32>(9)?,
            timestamp: f.uint(10)?,
            descriptor: f.bytes(11)?.to_vec(),
        })
    }
}

/// The responder's answer, before its signature.
#[derive(Clone, Debug)]
pub struct Reply {
    pub responder: ServerId,
    pub initiator: ServerId,
    pub session: [u8; 16],
    pub ct_ephemeral: Vec<u8>,
    pub ct_initiator_kem: Vec<u8>,
    pub suite: String,
    pub nonce: [u8; 32],
    pub timestamp: u64,
    pub hello_hash: [u8; 32],
}

impl Reply {
    pub fn to_body(&self) -> Vec<u8> {
        Value::map(vec![
            (0, Value::Uint(VERSION)),
            (1, Value::bytes(self.responder.as_bytes())),
            (2, Value::bytes(self.initiator.as_bytes())),
            (3, Value::bytes(&self.session)),
            (4, Value::bytes(&self.ct_ephemeral)),
            (5, Value::bytes(&self.ct_initiator_kem)),
            (6, Value::text(&self.suite)),
            (7, Value::bytes(&self.nonce)),
            (8, Value::Uint(self.timestamp)),
            (9, Value::bytes(&self.hello_hash)),
        ])
        .encode()
    }

    pub fn from_body(body: &[u8]) -> Result<Reply> {
        let value = Value::decode(body)?;
        let f = value.as_fields()?;
        f.only(&[0, 1, 2, 3, 4, 5, 6, 7, 8, 9])?;
        if f.uint(0)? != VERSION {
            return Err(FedError::Malformed("unknown handshake version"));
        }
        let ct_ephemeral = f.bytes(4)?;
        let ct_initiator_kem = f.bytes(5)?;
        if ct_ephemeral.len() != kx1::CIPHERTEXT_LEN
            || ct_initiator_kem.len() != kx1::CIPHERTEXT_LEN
        {
            return Err(FedError::Malformed("an encapsulation has the wrong length"));
        }
        Ok(Reply {
            responder: server_id(f.fixed::<16>(1)?),
            initiator: server_id(f.fixed::<16>(2)?),
            session: f.fixed::<16>(3)?,
            ct_ephemeral: ct_ephemeral.to_vec(),
            ct_initiator_kem: ct_initiator_kem.to_vec(),
            suite: f.text(6)?.to_owned(),
            nonce: f.fixed::<32>(7)?,
            timestamp: f.uint(8)?,
            hello_hash: f.fixed::<32>(9)?,
        })
    }
}

/// `SHA-256("kemlock/v1/fed/transcript" ‖ lp(hello envelope) ‖ lp(reply body))`.
pub fn transcript_hash(hello_envelope: &[u8], reply_body: &[u8]) -> [u8; 32] {
    let mut input = TRANSCRIPT_LABEL.to_vec();
    crypto::lp(&mut input, hello_envelope);
    crypto::lp(&mut input, reply_body);
    crypto::sha256(&input)
}

/// The session's master secret: `HKDF-Extract(salt = transcript hash, ikm = ss_B ‖ ss_E ‖ ss_A)`,
/// where `ss_B` is the secret encapsulated to the responder's KEM key, `ss_E` the one to the
/// initiator's ephemeral key and `ss_A` the one to the initiator's KEM key.
pub fn master_secret(
    transcript: &[u8; 32],
    ss_responder: &[u8; 32],
    ss_ephemeral: &[u8; 32],
    ss_initiator: &[u8; 32],
) -> Zeroizing<[u8; 32]> {
    let mut ikm = Zeroizing::new(Vec::with_capacity(96));
    ikm.extend_from_slice(ss_responder);
    ikm.extend_from_slice(ss_ephemeral);
    ikm.extend_from_slice(ss_initiator);
    crypto::hkdf_extract(transcript, &ikm)
}

fn check_skew(timestamp: u64, now: u64, what: &'static str) -> Result<()> {
    if timestamp.abs_diff(now) > SKEW_SECS {
        Err(FedError::Expired(what))
    } else {
        Ok(())
    }
}

/// The initiator's state between its hello and the reply.
pub struct Initiator {
    local_server: ServerId,
    responder: ServerId,
    responder_key: sig1::PublicKey,
    suite: Suite,
    ephemeral: kx1::PrivateKey,
    ss_responder: Zeroizing<[u8; 32]>,
    kem: KemPair,
    hello_envelope: Vec<u8>,
}

impl std::fmt::Debug for Initiator {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Initiator")
            .field("responder", &self.responder)
            .field("suite", &self.suite)
            .finish_non_exhaustive()
    }
}

impl Initiator {
    /// Starts a session with the server whose descriptor is `peer`, checked at `now` against the
    /// identity key `pinned` at pairing. Returns the state and the hello to send.
    pub fn start(
        local: &LocalIdentity,
        peer: &SignedDescriptor,
        pinned: &sig1::PublicKey,
        now: u64,
    ) -> Result<(Initiator, Vec<u8>)> {
        let ephemeral = crypto::kem_generate()?;
        Initiator::start_with_ephemeral(local, peer, pinned, now, ephemeral)
    }

    /// [`start`](Self::start) with the ephemeral key pair chosen by the caller, so the test
    /// vectors can pin it. Never use a key pair twice.
    #[doc(hidden)]
    pub fn start_with_ephemeral(
        local: &LocalIdentity,
        peer: &SignedDescriptor,
        pinned: &sig1::PublicKey,
        now: u64,
        ephemeral_pair: (kx1::PrivateKey, kx1::PublicKey),
    ) -> Result<(Initiator, Vec<u8>)> {
        peer.verify(now, Some(pinned))?;
        let d = &peer.descriptor;
        let suite = d.negotiate(&local.suites())?;
        // Fail before any KEM work if this build can't run the suite.
        suite.aead()?;
        let kem = local
            .kems
            .first()
            .ok_or(FedError::Invalid("an identity needs a KEM key"))?
            .clone();

        let (ephemeral, ephemeral_public) = ephemeral_pair;
        let (ct_responder, ss_responder) = crypto::kem_encapsulate(&d.kem_key)?;
        let hello = Hello {
            initiator: local.server,
            responder: d.server,
            responder_kem_id: kem_key_id(&d.kem_key),
            ephemeral: ephemeral_public,
            ct_responder,
            initiator_suites: local.descriptor.descriptor.suites.clone(),
            responder_suites: d.suites.clone(),
            suite: suite.name().to_owned(),
            nonce: crypto::random(),
            timestamp: now,
            descriptor: local.descriptor.to_bytes(),
        };
        let envelope = Signed::sign(&local.signing, HELLO_CONTEXT, hello.to_body())?.encode();
        Ok((
            Initiator {
                local_server: local.server,
                responder: d.server,
                responder_key: d.identity_key.clone(),
                suite,
                ephemeral,
                ss_responder,
                kem,
                hello_envelope: envelope.clone(),
            },
            envelope,
        ))
    }

    /// Checks the reply and derives the session.
    pub fn finish(self, reply: &[u8], now: u64, padding: Padding) -> Result<Session> {
        if reply.len() > MAX_MESSAGE {
            return Err(FedError::Malformed("the reply is too large"));
        }
        let envelope = Signed::decode(reply)?;
        let body = Reply::from_body(&envelope.body)?;
        if body.responder != self.responder || body.initiator != self.local_server {
            return Err(FedError::Invalid("the reply names other servers"));
        }
        if body.suite != self.suite.name() {
            return Err(FedError::Invalid("the reply changed the suite"));
        }
        if body.hello_hash != crypto::sha256(&self.hello_envelope) {
            return Err(FedError::Invalid("the reply answers another hello"));
        }
        check_skew(
            body.timestamp,
            now,
            "the reply's timestamp is too far from our clock",
        )?;
        let transcript = transcript_hash(&self.hello_envelope, &envelope.body);
        crypto::verify(
            &self.responder_key,
            REPLY_CONTEXT,
            &transcript,
            &envelope.signature,
        )?;

        let ss_ephemeral = crypto::kem_decapsulate(&self.ephemeral, &body.ct_ephemeral)?;
        let ss_initiator = crypto::kem_decapsulate(&self.kem.private, &body.ct_initiator_kem)?;
        let prk = master_secret(
            &transcript,
            &self.ss_responder,
            &ss_ephemeral,
            &ss_initiator,
        );
        Session::new(
            Role::Initiator,
            body.session,
            self.responder,
            self.suite,
            &prk,
            now,
            padding,
        )
    }
}

/// Handshake nonces seen recently, so a recorded hello can't be played again inside the
/// timestamp window.
#[derive(Debug, Default)]
pub struct NonceCache {
    seen: HashMap<[u8; 32], u64>,
}

impl NonceCache {
    /// The most nonces held; only authenticated peers add to it.
    pub const CAPACITY: usize = 16_384;

    pub fn new() -> NonceCache {
        NonceCache::default()
    }

    /// Records a nonce sent at `timestamp`, or fails if it was seen.
    pub fn insert(&mut self, nonce: [u8; 32], timestamp: u64, now: u64) -> Result<()> {
        // A hello older than the window is refused on its timestamp, so its nonce can go.
        self.seen
            .retain(|_, sent| sent.saturating_add(SKEW_SECS) >= now);
        if self.seen.contains_key(&nonce) {
            return Err(FedError::Replay);
        }
        if self.seen.len() >= Self::CAPACITY {
            return Err(FedError::Refused("too many handshakes in the last minutes"));
        }
        self.seen.insert(nonce, timestamp);
        Ok(())
    }
}

/// What the responder sends back, and the session it now holds.
#[derive(Debug)]
pub struct Accepted {
    pub reply: Vec<u8>,
    pub session: Session,
}

/// Answers a hello. `keys` holds the identity keys pinned at pairing, so only a paired peer gets
/// past the descriptor check, and `cache` refuses a replayed hello.
pub fn respond(
    local: &LocalIdentity,
    keys: &dyn KeyDirectory,
    cache: &mut NonceCache,
    hello: &[u8],
    now: u64,
    padding: Padding,
) -> Result<Accepted> {
    if hello.len() > MAX_MESSAGE {
        return Err(FedError::Malformed("the hello is too large"));
    }
    let envelope = Signed::decode(hello)?;
    let h = Hello::from_body(&envelope.body)?;
    if h.responder != local.server {
        return Err(FedError::Invalid(
            "the hello is addressed to another server",
        ));
    }

    // Authenticate the initiator before doing any KEM work for it.
    let descriptor = SignedDescriptor::parse(&h.descriptor)?;
    if descriptor.descriptor.server != h.initiator {
        return Err(FedError::Invalid("the descriptor is another server's"));
    }
    let pinned = keys
        .identity_key(h.initiator)
        .ok_or(FedError::UnknownPeer)?;
    descriptor.verify(now, Some(&pinned))?;
    envelope.verify(&pinned, HELLO_CONTEXT)?;
    check_skew(
        h.timestamp,
        now,
        "the hello's timestamp is too far from our clock",
    )?;

    // Both lists are signed into the hello, so each must be exactly what its owner publishes,
    // and the suite must be the one the connecting server's rule picks.
    if h.responder_suites != local.descriptor.descriptor.suites {
        return Err(FedError::Invalid("the hello carries a stale suite list"));
    }
    if h.initiator_suites != descriptor.descriptor.suites {
        return Err(FedError::Invalid(
            "the hello's suite list is not the descriptor's",
        ));
    }
    let initiator_known = descriptor.descriptor.known_suites();
    let expected = suite::negotiate(&h.responder_suites, &initiator_known)?;
    if h.suite != expected.name() {
        return Err(FedError::Invalid("the hello chose another suite"));
    }
    expected.aead()?;

    let kem = local.kem(&h.responder_kem_id).ok_or(FedError::Invalid(
        "the hello names a KEM key we do not hold",
    ))?;
    let ss_responder = crypto::kem_decapsulate(&kem.private, &h.ct_responder)?;
    cache.insert(h.nonce, h.timestamp, now)?;

    let (ct_ephemeral, ss_ephemeral) = crypto::kem_encapsulate(&h.ephemeral)?;
    let (ct_initiator_kem, ss_initiator) = crypto::kem_encapsulate(&descriptor.descriptor.kem_key)?;
    let session_id: [u8; 16] = crypto::random();
    let reply = Reply {
        responder: local.server,
        initiator: h.initiator,
        session: session_id,
        ct_ephemeral,
        ct_initiator_kem,
        suite: expected.name().to_owned(),
        nonce: crypto::random(),
        timestamp: now,
        hello_hash: crypto::sha256(hello),
    };
    let body = reply.to_body();
    let transcript = transcript_hash(hello, &body);
    let signature = crypto::sign(&local.signing, REPLY_CONTEXT, &transcript)?;
    let prk = master_secret(&transcript, &ss_responder, &ss_ephemeral, &ss_initiator);
    let session = Session::new(
        Role::Responder,
        session_id,
        h.initiator,
        expected,
        &prk,
        now,
        padding,
    )?;
    Ok(Accepted {
        reply: Signed { body, signature }.encode(),
        session,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::{directory, identity};

    const NOW: u64 = 1_800_000_000;

    struct Pair {
        a: LocalIdentity,
        b: LocalIdentity,
        keys_a: HashMap<ServerId, sig1::PublicKey>,
        keys_b: HashMap<ServerId, sig1::PublicKey>,
    }

    fn pair() -> Pair {
        let a = identity(1, NOW, &Suite::IMPLEMENTED);
        let b = identity(2, NOW, &Suite::IMPLEMENTED);
        Pair {
            keys_a: directory(&[&b]),
            keys_b: directory(&[&a]),
            a,
            b,
        }
    }

    fn connect(p: &Pair) -> (Session, Session) {
        let (init, hello) =
            Initiator::start(&p.a, &p.b.descriptor, &p.b.public, NOW).expect("start");
        let mut cache = NonceCache::new();
        let accepted = respond(
            &p.b,
            &p.keys_b,
            &mut cache,
            &hello,
            NOW + 1,
            Padding::Step4096,
        )
        .expect("respond");
        let a = init
            .finish(&accepted.reply, NOW + 2, Padding::Step4096)
            .expect("finish");
        (a, accepted.session)
    }

    #[test]
    fn a_handshake_gives_both_sides_the_same_working_session() {
        let p = pair();
        let (mut a, mut b) = connect(&p);
        assert_eq!(a.id, b.id);
        assert_eq!(a.suite, b.suite);
        assert_eq!(a.peer, p.b.server);
        assert_eq!(b.peer, p.a.server);
        assert_eq!(a.role, Role::Initiator);
        assert_eq!(b.role, Role::Responder);
        let f = a.writer.seal(b"hello b", false, NOW).expect("seal");
        assert_eq!(b.reader.open(&f).expect("open").payload, b"hello b");
        let f = b.writer.seal(b"hello a", true, NOW).expect("seal");
        let opened = a.reader.open(&f).expect("open");
        assert_eq!(opened.payload, b"hello a");
        assert!(opened.last);
        let _ = &p.keys_a;
    }

    #[test]
    fn the_suite_is_the_first_of_the_responders_list_the_initiator_supports() {
        let a = identity(1, NOW, &[Suite::ChaCha20Poly1305]);
        let b = identity(2, NOW, &[Suite::Aes256Gcm, Suite::ChaCha20Poly1305]);
        let keys_b = directory(&[&a]);
        let (init, hello) = Initiator::start(&a, &b.descriptor, &b.public, NOW).expect("start");
        let accepted = respond(
            &b,
            &keys_b,
            &mut NonceCache::new(),
            &hello,
            NOW,
            Padding::Off,
        )
        .expect("respond");
        assert_eq!(accepted.session.suite, Suite::ChaCha20Poly1305);
        let session = init
            .finish(&accepted.reply, NOW, Padding::Off)
            .expect("finish");
        assert_eq!(session.suite, Suite::ChaCha20Poly1305);
    }

    #[test]
    fn no_common_suite_fails_before_any_message() {
        let a = identity(1, NOW, &[Suite::Aes256Gcm]);
        let b = identity(2, NOW, &[Suite::ChaCha20Poly1305]);
        assert_eq!(
            Initiator::start(&a, &b.descriptor, &b.public, NOW).map(|_| ()),
            Err(FedError::NoCommonSuite)
        );
    }

    #[test]
    fn a_replayed_hello_is_refused() {
        let p = pair();
        let (_, hello) = Initiator::start(&p.a, &p.b.descriptor, &p.b.public, NOW).expect("start");
        let mut cache = NonceCache::new();
        respond(&p.b, &p.keys_b, &mut cache, &hello, NOW, Padding::Off).expect("first");
        assert_eq!(
            respond(&p.b, &p.keys_b, &mut cache, &hello, NOW + 5, Padding::Off).map(|_| ()),
            Err(FedError::Replay)
        );
    }

    #[test]
    fn an_old_or_future_hello_is_refused() {
        let p = pair();
        let (_, hello) = Initiator::start(&p.a, &p.b.descriptor, &p.b.public, NOW).expect("start");
        for now in [NOW + SKEW_SECS + 1, NOW - SKEW_SECS - 1] {
            assert!(matches!(
                respond(
                    &p.b,
                    &p.keys_b,
                    &mut NonceCache::new(),
                    &hello,
                    now,
                    Padding::Off
                ),
                Err(FedError::Expired(_))
            ));
        }
        respond(
            &p.b,
            &p.keys_b,
            &mut NonceCache::new(),
            &hello,
            NOW + SKEW_SECS,
            Padding::Off,
        )
        .expect("inside the window");
    }

    #[test]
    fn a_stranger_is_refused_at_the_first_message() {
        let p = pair();
        let stranger = identity(7, NOW, &Suite::IMPLEMENTED);
        let (_, hello) =
            Initiator::start(&stranger, &p.b.descriptor, &p.b.public, NOW).expect("start");
        assert_eq!(
            respond(
                &p.b,
                &p.keys_b,
                &mut NonceCache::new(),
                &hello,
                NOW,
                Padding::Off
            )
            .map(|_| ()),
            Err(FedError::UnknownPeer)
        );
    }

    #[test]
    fn a_known_server_with_another_key_is_a_key_mismatch() {
        let p = pair();
        // A impostor that claims A's id but holds another identity key.
        let mut impostor = identity(9, NOW, &Suite::IMPLEMENTED);
        impostor.server = p.a.server;
        let impostor = LocalIdentity::new(
            p.a.server,
            impostor.signing.clone(),
            impostor.kems.clone(),
            crate::identity::DescriptorParams {
                suites: Suite::IMPLEMENTED.to_vec(),
                addresses: vec![],
                operator: "x".to_owned(),
                not_before: NOW,
                not_after: NOW + 1000,
            },
        )
        .expect("identity");
        let (_, hello) =
            Initiator::start(&impostor, &p.b.descriptor, &p.b.public, NOW).expect("start");
        match respond(
            &p.b,
            &p.keys_b,
            &mut NonceCache::new(),
            &hello,
            NOW,
            Padding::Off,
        ) {
            Err(FedError::KeyMismatch { offered }) => {
                assert_eq!(offered, impostor.public.as_bytes().to_vec());
            }
            other => panic!("expected a key mismatch, got {other:?}"),
        }
    }

    #[test]
    fn the_initiator_refuses_a_descriptor_that_is_not_the_pinned_one() {
        let p = pair();
        let other = identity(5, NOW, &Suite::IMPLEMENTED);
        assert!(matches!(
            Initiator::start(&p.a, &other.descriptor, &p.b.public, NOW),
            Err(FedError::KeyMismatch { .. })
        ));
    }

    #[test]
    fn a_changed_hello_fails() {
        let p = pair();
        let (_, hello) = Initiator::start(&p.a, &p.b.descriptor, &p.b.public, NOW).expect("start");
        // Sample bytes across the whole message, including the signature and the embedded
        // descriptor.
        for i in (0..hello.len()).step_by(97) {
            let mut bad = hello.clone();
            bad[i] ^= 1;
            assert!(
                respond(
                    &p.b,
                    &p.keys_b,
                    &mut NonceCache::new(),
                    &bad,
                    NOW,
                    Padding::Off
                )
                .is_err(),
                "byte {i}"
            );
        }
    }

    #[test]
    fn a_changed_reply_fails() {
        let p = pair();
        // The reply's length doesn't depend on the randomness, so sample positions across it.
        let (init, hello) =
            Initiator::start(&p.a, &p.b.descriptor, &p.b.public, NOW).expect("start");
        let accepted = respond(
            &p.b,
            &p.keys_b,
            &mut NonceCache::new(),
            &hello,
            NOW,
            Padding::Off,
        )
        .expect("respond");
        let len = accepted.reply.len();
        init.finish(&accepted.reply, NOW, Padding::Off)
            .expect("the untouched reply is accepted");
        for i in (0..len).step_by(131) {
            let (init, hello) =
                Initiator::start(&p.a, &p.b.descriptor, &p.b.public, NOW).expect("start");
            let accepted = respond(
                &p.b,
                &p.keys_b,
                &mut NonceCache::new(),
                &hello,
                NOW,
                Padding::Off,
            )
            .expect("respond");
            let mut bad = accepted.reply.clone();
            bad[i] ^= 1;
            assert!(init.finish(&bad, NOW, Padding::Off).is_err(), "byte {i}");
        }
    }

    #[test]
    fn a_reply_to_another_hello_fails() {
        let p = pair();
        let (first, _) = Initiator::start(&p.a, &p.b.descriptor, &p.b.public, NOW).expect("start");
        let (_, hello2) = Initiator::start(&p.a, &p.b.descriptor, &p.b.public, NOW).expect("start");
        let accepted = respond(
            &p.b,
            &p.keys_b,
            &mut NonceCache::new(),
            &hello2,
            NOW,
            Padding::Off,
        )
        .expect("respond");
        assert!(first.finish(&accepted.reply, NOW, Padding::Off).is_err());
    }

    #[test]
    fn a_stale_reply_fails_on_its_timestamp() {
        let p = pair();
        let (init, hello) =
            Initiator::start(&p.a, &p.b.descriptor, &p.b.public, NOW).expect("start");
        let accepted = respond(
            &p.b,
            &p.keys_b,
            &mut NonceCache::new(),
            &hello,
            NOW,
            Padding::Off,
        )
        .expect("respond");
        assert!(matches!(
            init.finish(&accepted.reply, NOW + SKEW_SECS + 1, Padding::Off),
            Err(FedError::Expired(_))
        ));
    }

    #[test]
    fn a_downgrade_in_the_hello_is_caught() {
        // A hello that picks the second suite although the first is common, re-signed by a
        // properly paired initiator, is still refused: the choice is checked against both lists.
        let p = pair();
        let (_, hello) = Initiator::start(&p.a, &p.b.descriptor, &p.b.public, NOW).expect("start");
        let env = Signed::decode(&hello).expect("decode");
        let mut h = Hello::from_body(&env.body).expect("body");
        h.suite = Suite::ChaCha20Poly1305.name().to_owned();
        let forged = Signed::sign(&p.a.signing, HELLO_CONTEXT, h.to_body())
            .expect("sign")
            .encode();
        assert_eq!(
            respond(
                &p.b,
                &p.keys_b,
                &mut NonceCache::new(),
                &forged,
                NOW,
                Padding::Off
            )
            .map(|_| ()),
            Err(FedError::Invalid("the hello chose another suite"))
        );
    }

    #[test]
    fn a_hello_for_another_responder_or_a_stale_list_is_refused() {
        let p = pair();
        let (_, hello) = Initiator::start(&p.a, &p.b.descriptor, &p.b.public, NOW).expect("start");
        let env = Signed::decode(&hello).expect("decode");
        let mut h = Hello::from_body(&env.body).expect("body");
        h.responder_suites.reverse();
        let forged = Signed::sign(&p.a.signing, HELLO_CONTEXT, h.to_body())
            .expect("sign")
            .encode();
        assert!(
            respond(
                &p.b,
                &p.keys_b,
                &mut NonceCache::new(),
                &forged,
                NOW,
                Padding::Off
            )
            .is_err()
        );
        let c = identity(3, NOW, &Suite::IMPLEMENTED);
        assert!(
            respond(
                &c,
                &directory(&[&p.a]),
                &mut NonceCache::new(),
                &hello,
                NOW,
                Padding::Off
            )
            .is_err()
        );
    }

    #[test]
    fn the_previous_kem_key_still_opens_a_hello_during_rotation() {
        let p = pair();
        // B rotates: a new key is current, the old one stays for the overlap.
        let old = p.b.kems[0].clone();
        let new = KemPair::generate().expect("kem");
        let rotated = LocalIdentity::new(
            p.b.server,
            p.b.signing.clone(),
            vec![new, old],
            crate::identity::DescriptorParams {
                suites: Suite::IMPLEMENTED.to_vec(),
                addresses: vec![],
                operator: "x".to_owned(),
                not_before: NOW,
                not_after: NOW + 1000,
            },
        )
        .expect("identity");
        // A still holds the old descriptor, so its hello names the old key.
        let (init, hello) =
            Initiator::start(&p.a, &p.b.descriptor, &p.b.public, NOW).expect("start");
        // The suites lists are the same, so only the KEM key id differs.
        let accepted = respond(
            &rotated,
            &p.keys_b,
            &mut NonceCache::new(),
            &hello,
            NOW,
            Padding::Off,
        )
        .expect("respond");
        init.finish(&accepted.reply, NOW, Padding::Off)
            .expect("finish");
    }

    #[test]
    fn nonce_cache_forgets_old_entries_and_has_a_cap() {
        let mut cache = NonceCache::new();
        cache.insert([1; 32], 100, 100).expect("first");
        assert_eq!(cache.insert([1; 32], 100, 101), Err(FedError::Replay));
        // Once the window has passed the nonce is forgotten (its hello would fail on time).
        cache
            .insert([1; 32], 100 + 2 * SKEW_SECS, 100 + 2 * SKEW_SECS)
            .expect("forgotten");
    }
}
