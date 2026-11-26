//! Pairing: how two servers learn each other's identity keys, once.
//!
//! The admin of one server shows a one-time code; the admin of the other types it in. The code is
//! the password of a CPace exchange (draft-irtf-cfrg-cpace, ristretto255 with SHA-512, through the
//! `pakery-cpace` crate), so a man in the middle who doesn't have it can make one guess per run
//! and no more. The exchange's session key seals each server's signed descriptor, which carries
//! its identity key, so a descriptor only opens for someone who typed the right code. Each server
//! then pins the other's identity key. Both admins also compare a six-word fingerprint of the two
//! identity keys. See `docs/federation.md`.

use crate::cbor::Value;
use crate::crypto::{self, Aead};
use crate::descriptor::SignedDescriptor;
use crate::error::{FedError, Result};
use crate::identity::LocalIdentity;
use crate::wire::server_id;
use kemlock_crypto::sig1;
use kemlock_domain::ServerId;
use pakery_cpace::{CpaceInitiator, CpaceMode, CpaceResponder, InitiatorState};
use pakery_crypto::CpaceRistretto255;
use std::fmt;
use zeroize::Zeroizing;

pub type Pake = CpaceRistretto255;

/// The pairing message format version.
pub const VERSION: u64 = 1;
/// CPace's channel identifier.
pub const CHANNEL_ID: &[u8] = b"kemlock/v1/fed/pair";
/// The code's length in characters.
pub const CODE_CHARS: usize = 12;
/// How long a code is good for, in seconds. An admin console enforces it; one attempt burns it.
pub const CODE_LIFETIME_SECS: u64 = 600;

const ALPHABET: &[u8; 32] = b"0123456789ABCDEFGHJKMNPQRSTVWXYZ";
const MAX_MESSAGE: usize = 32 * 1024;

/// The random source CPace draws its scalars from: kemlock-crypto's, so a seeded test run is
/// reproducible.
#[derive(Debug, Default)]
pub struct SystemRng;

impl rand_core::TryRng for SystemRng {
    type Error = core::convert::Infallible;

    fn try_next_u32(&mut self) -> core::result::Result<u32, Self::Error> {
        Ok(u32::from_le_bytes(crypto::random::<4>()))
    }

    fn try_next_u64(&mut self) -> core::result::Result<u64, Self::Error> {
        Ok(u64::from_le_bytes(crypto::random::<8>()))
    }

    fn try_fill_bytes(&mut self, dst: &mut [u8]) -> core::result::Result<(), Self::Error> {
        kemlock_crypto::rand::fill(dst);
        Ok(())
    }
}

impl rand_core::TryCryptoRng for SystemRng {}

/// The one-time pairing code: 12 characters of Crockford's base32 (60 bits), shown as
/// `XXXX-XXXX-XXXX`. It is not `Clone`, and the responder takes it by value, so a code can be
/// used for one run.
pub struct PairingCode(Zeroizing<String>);

impl fmt::Debug for PairingCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("PairingCode(..)")
    }
}

impl PairingCode {
    pub fn generate() -> PairingCode {
        let raw: [u8; CODE_CHARS] = crypto::random();
        let text: String = raw
            .iter()
            .map(|b| char::from(ALPHABET[usize::from(b & 31)]))
            .collect();
        PairingCode(Zeroizing::new(text))
    }

    /// Reads a code as a person types it: dashes and spaces are ignored, case doesn't matter and
    /// `O`, `I`, `L` mean `0`, `1`, `1` as in Crockford's base32.
    pub fn parse(input: &str) -> Result<PairingCode> {
        let mut text = String::with_capacity(CODE_CHARS);
        for c in input.chars() {
            if c == '-' || c.is_whitespace() {
                continue;
            }
            if !c.is_ascii() {
                return Err(FedError::Pairing);
            }
            let c = match c.to_ascii_uppercase() {
                'O' => '0',
                'I' | 'L' => '1',
                other => other,
            };
            if !ALPHABET.contains(&(c as u8)) {
                return Err(FedError::Pairing);
            }
            text.push(c);
        }
        if text.len() != CODE_CHARS {
            return Err(FedError::Pairing);
        }
        Ok(PairingCode(Zeroizing::new(text)))
    }

    /// `XXXX-XXXX-XXXX`.
    pub fn display(&self) -> String {
        format!("{}-{}-{}", &self.0[..4], &self.0[4..8], &self.0[8..])
    }

    /// The password CPace uses: the 12 characters, upper case, without dashes.
    fn password(&self) -> &[u8] {
        self.0.as_bytes()
    }
}

/// Six proquints (Daniel Wilkerson's pronounceable encoding: `consonant vowel consonant vowel
/// consonant` for 16 bits) from the first 12 bytes of a hash of both identity keys: 96 bits the
/// admins read to each other. A word list would need a licence and a table; this needs neither.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Fingerprint([u16; 6]);

const CONSONANTS: &[u8; 16] = b"bdfghjklmnprstvz";
const VOWELS: &[u8; 4] = b"aiou";

/// One proquint.
pub fn proquint(n: u16) -> String {
    let n = usize::from(n);
    let bytes = [
        CONSONANTS[(n >> 12) & 0xf],
        VOWELS[(n >> 10) & 0x3],
        CONSONANTS[(n >> 6) & 0xf],
        VOWELS[(n >> 4) & 0x3],
        CONSONANTS[n & 0xf],
    ];
    bytes.iter().map(|b| char::from(*b)).collect()
}

impl Fingerprint {
    /// The fingerprint of two servers' identities. The order of the arguments doesn't matter:
    /// the lower server id goes first.
    pub fn of(a: (ServerId, &sig1::PublicKey), b: (ServerId, &sig1::PublicKey)) -> Fingerprint {
        let (first, second) = if a.0.as_bytes() <= b.0.as_bytes() {
            (a, b)
        } else {
            (b, a)
        };
        let mut input = b"kemlock/v1/fed/fingerprint".to_vec();
        for (id, key) in [first, second] {
            crypto::lp(&mut input, id.as_bytes());
            crypto::lp(&mut input, key.as_bytes());
        }
        let digest = crypto::sha512(&input);
        let mut words = [0u16; 6];
        for (i, word) in words.iter_mut().enumerate() {
            *word = u16::from_be_bytes([digest[2 * i], digest[2 * i + 1]]);
        }
        Fingerprint(words)
    }

    pub fn words(&self) -> Vec<String> {
        self.0.iter().map(|w| proquint(*w)).collect()
    }
}

impl fmt::Display for Fingerprint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.words().join("-"))
    }
}

/// The outcome of a pairing: the peer's verified descriptor (whose identity key is to be pinned)
/// and the fingerprint both admins compare.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Paired {
    pub descriptor: SignedDescriptor,
    pub fingerprint: Fingerprint,
}

/// What both sides bind into the sealed descriptors: the session id, both CPace shares and both
/// server ids.
pub fn binding(
    sid: &[u8; 16],
    ya: &[u8],
    yb: &[u8],
    initiator: ServerId,
    responder: ServerId,
) -> Vec<u8> {
    let mut out = b"kemlock/v1/fed/pair".to_vec();
    crypto::lp(&mut out, sid);
    crypto::lp(&mut out, ya);
    crypto::lp(&mut out, yb);
    crypto::lp(&mut out, initiator.as_bytes());
    crypto::lp(&mut out, responder.as_bytes());
    out
}

/// `(responder's key, initiator's key)`, each from the CPace session key and the session id.
pub fn directional_keys(isk: &[u8], sid: &[u8; 16]) -> (Zeroizing<[u8; 32]>, Zeroizing<[u8; 32]>) {
    let prk = crypto::hkdf_extract(sid, isk);
    (
        crypto::hkdf_expand::<32>(&prk, b"kemlock/v1/fed/pair/responder"),
        crypto::hkdf_expand::<32>(&prk, b"kemlock/v1/fed/pair/initiator"),
    )
}

/// `nonce (12) ‖ AES-256-GCM(key, nonce, plaintext, aad)` with a random nonce.
fn seal(key: &[u8; 32], aad: &[u8], plaintext: &[u8]) -> Result<Vec<u8>> {
    seal_with_nonce(key, &crypto::random(), aad, plaintext)
}

/// [`seal`] with the nonce given, for the test vectors.
pub fn seal_with_nonce(
    key: &[u8; 32],
    nonce: &[u8; 12],
    aad: &[u8],
    plaintext: &[u8],
) -> Result<Vec<u8>> {
    let mut out = nonce.to_vec();
    out.extend_from_slice(&Aead::Aes256Gcm.seal(key, nonce, aad, plaintext)?);
    Ok(out)
}

/// What a CPace run gives both sides, for the test vectors and the tests.
#[derive(Debug)]
pub struct CpaceTrace {
    pub ya: Vec<u8>,
    pub yb: Vec<u8>,
    pub isk_initiator: Vec<u8>,
    pub isk_responder: Vec<u8>,
    pub session_id_initiator: Vec<u8>,
    pub session_id_responder: Vec<u8>,
}

/// Runs both sides of CPace (ristretto255, SHA-512, initiator-responder mode) with the random
/// sources given.
pub fn cpace_exchange(
    prs: &[u8],
    sid: &[u8; 16],
    ad_initiator: &[u8],
    ad_responder: &[u8],
    rng_initiator: &mut impl rand_core::CryptoRng,
    rng_responder: &mut impl rand_core::CryptoRng,
) -> Result<CpaceTrace> {
    let (ya, state) =
        CpaceInitiator::<Pake>::start(prs, CHANNEL_ID, sid, ad_initiator, rng_initiator)
            .map_err(|_| FedError::Pairing)?;
    let (yb, out_responder) = CpaceResponder::<Pake>::respond(
        &ya,
        prs,
        CHANNEL_ID,
        sid,
        ad_initiator,
        ad_responder,
        CpaceMode::InitiatorResponder,
        rng_responder,
    )
    .map_err(|_| FedError::Pairing)?;
    let out_initiator = state
        .finish(&yb, ad_responder, CpaceMode::InitiatorResponder)
        .map_err(|_| FedError::Pairing)?;
    Ok(CpaceTrace {
        ya,
        yb,
        isk_initiator: out_initiator.isk.as_bytes().to_vec(),
        isk_responder: out_responder.isk.as_bytes().to_vec(),
        session_id_initiator: out_initiator.session_id,
        session_id_responder: out_responder.session_id,
    })
}

/// Opens a [`seal`]. Any failure is a failed pairing: a wrong code, or a changed message.
fn open(key: &[u8; 32], aad: &[u8], sealed: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
    if sealed.len() < 12 + crypto::TAG_LEN {
        return Err(FedError::Pairing);
    }
    let (nonce, rest) = sealed.split_at(12);
    let mut n = [0u8; 12];
    n.copy_from_slice(nonce);
    Aead::Aes256Gcm
        .open(key, &n, aad, rest)
        .map_err(|_| FedError::Pairing)
}

/// Parses and verifies a peer's descriptor from its pairing message. There is no pinned key yet:
/// the PAKE is what authenticates it.
fn read_descriptor(bytes: &[u8], expected: ServerId, now: u64) -> Result<SignedDescriptor> {
    let descriptor = SignedDescriptor::parse(bytes).map_err(|_| FedError::Pairing)?;
    if descriptor.descriptor.server != expected {
        return Err(FedError::Pairing);
    }
    descriptor
        .verify(now, None)
        .map_err(|_| FedError::Pairing)?;
    Ok(descriptor)
}

/// The initiator (the admin who typed the code) between its first message and the answer.
pub struct PairingInitiator {
    state: InitiatorState<Pake>,
    sid: [u8; 16],
    ya: Vec<u8>,
    local_server: ServerId,
    local_descriptor: Vec<u8>,
    local_key: sig1::PublicKey,
}

impl fmt::Debug for PairingInitiator {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PairingInitiator").finish_non_exhaustive()
    }
}

impl PairingInitiator {
    /// Starts a pairing with the code the other admin showed. Returns the state and message 1.
    pub fn start(code: &PairingCode, local: &LocalIdentity) -> Result<(PairingInitiator, Vec<u8>)> {
        let sid: [u8; 16] = crypto::random();
        let (ya, state) = CpaceInitiator::<Pake>::start(
            code.password(),
            CHANNEL_ID,
            &sid,
            local.server.as_bytes(),
            &mut SystemRng,
        )
        .map_err(|_| FedError::Pairing)?;
        let message = Value::map(vec![
            (0, Value::Uint(VERSION)),
            (1, Value::bytes(&sid)),
            (2, Value::bytes(&ya)),
            (3, Value::bytes(local.server.as_bytes())),
        ])
        .encode();
        Ok((
            PairingInitiator {
                state,
                sid,
                ya,
                local_server: local.server,
                local_descriptor: local.descriptor.to_bytes(),
                local_key: local.public.clone(),
            },
            message,
        ))
    }

    /// Reads message 2. With the wrong code the descriptor inside doesn't open and this fails:
    /// the answer is then not sent, so the other server learns nothing about the guess.
    /// Returns the peer's verified descriptor and message 3.
    pub fn finish(self, message: &[u8], now: u64) -> Result<(Paired, Vec<u8>)> {
        if message.len() > MAX_MESSAGE {
            return Err(FedError::Pairing);
        }
        let value = Value::decode(message).map_err(|_| FedError::Pairing)?;
        let f = value.as_fields().map_err(|_| FedError::Pairing)?;
        f.only(&[0, 1, 2]).map_err(|_| FedError::Pairing)?;
        let yb = f.bytes(0).map_err(|_| FedError::Pairing)?;
        let sealed = f.bytes(1).map_err(|_| FedError::Pairing)?;
        let responder = server_id(f.fixed::<16>(2).map_err(|_| FedError::Pairing)?);

        let out = self
            .state
            .finish(yb, responder.as_bytes(), CpaceMode::InitiatorResponder)
            .map_err(|_| FedError::Pairing)?;
        let (responder_key, initiator_key) = directional_keys(out.isk.as_bytes(), &self.sid);
        let aad = binding(&self.sid, &self.ya, yb, self.local_server, responder);
        let bytes = open(&responder_key, &aad, sealed)?;
        let descriptor = read_descriptor(&bytes, responder, now)?;
        let fingerprint = Fingerprint::of(
            (self.local_server, &self.local_key),
            (responder, &descriptor.descriptor.identity_key),
        );
        let third = Value::map(vec![(
            0,
            Value::Bytes(seal(&initiator_key, &aad, &self.local_descriptor)?),
        )])
        .encode();
        Ok((
            Paired {
                descriptor,
                fingerprint,
            },
            third,
        ))
    }
}

/// The responder (the admin who showed the code) between its answer and message 3.
pub struct PendingPairing {
    initiator_key: Zeroizing<[u8; 32]>,
    aad: Vec<u8>,
    initiator: ServerId,
    local_server: ServerId,
    local_key: sig1::PublicKey,
}

impl fmt::Debug for PendingPairing {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PendingPairing").finish_non_exhaustive()
    }
}

/// Whether `message` is a well-formed message 1 from another server: what [`respond`] reads before
/// it uses the code. The hub checks it first, so a message that could not be an attempt at the code
/// (not CBOR, a missing field, our own id) doesn't use the code up.
pub fn check_first_message(message: &[u8], local: ServerId) -> Result<()> {
    if message.len() > MAX_MESSAGE {
        return Err(FedError::Pairing);
    }
    let value = Value::decode(message).map_err(|_| FedError::Pairing)?;
    let f = value.as_fields().map_err(|_| FedError::Pairing)?;
    f.only(&[0, 1, 2, 3]).map_err(|_| FedError::Pairing)?;
    if f.uint(0).map_err(|_| FedError::Pairing)? != VERSION {
        return Err(FedError::Pairing);
    }
    f.fixed::<16>(1).map_err(|_| FedError::Pairing)?;
    f.bytes(2).map_err(|_| FedError::Pairing)?;
    let initiator = server_id(f.fixed::<16>(3).map_err(|_| FedError::Pairing)?);
    if initiator == local {
        return Err(FedError::Pairing);
    }
    Ok(())
}

/// Answers message 1 with the code that was shown. The code is used up. Returns the state to
/// finish with message 3, and message 2.
pub fn respond(
    code: PairingCode,
    local: &LocalIdentity,
    message: &[u8],
) -> Result<(PendingPairing, Vec<u8>)> {
    if message.len() > MAX_MESSAGE {
        return Err(FedError::Pairing);
    }
    let value = Value::decode(message).map_err(|_| FedError::Pairing)?;
    let f = value.as_fields().map_err(|_| FedError::Pairing)?;
    f.only(&[0, 1, 2, 3]).map_err(|_| FedError::Pairing)?;
    if f.uint(0).map_err(|_| FedError::Pairing)? != VERSION {
        return Err(FedError::Pairing);
    }
    let sid = f.fixed::<16>(1).map_err(|_| FedError::Pairing)?;
    let ya = f.bytes(2).map_err(|_| FedError::Pairing)?;
    let initiator = server_id(f.fixed::<16>(3).map_err(|_| FedError::Pairing)?);
    if initiator == local.server {
        return Err(FedError::Pairing);
    }

    let (yb, out) = CpaceResponder::<Pake>::respond(
        ya,
        code.password(),
        CHANNEL_ID,
        &sid,
        initiator.as_bytes(),
        local.server.as_bytes(),
        CpaceMode::InitiatorResponder,
        &mut SystemRng,
    )
    .map_err(|_| FedError::Pairing)?;
    let (responder_key, initiator_key) = directional_keys(out.isk.as_bytes(), &sid);
    let aad = binding(&sid, ya, &yb, initiator, local.server);
    let sealed = seal(&responder_key, &aad, &local.descriptor.to_bytes())?;
    let reply = Value::map(vec![
        (0, Value::Bytes(yb)),
        (1, Value::Bytes(sealed)),
        (2, Value::bytes(local.server.as_bytes())),
    ])
    .encode();
    Ok((
        PendingPairing {
            initiator_key,
            aad,
            initiator,
            local_server: local.server,
            local_key: local.public.clone(),
        },
        reply,
    ))
}

impl PendingPairing {
    /// Reads message 3. It opens only if the initiator held the right code.
    pub fn finish(self, message: &[u8], now: u64) -> Result<Paired> {
        if message.len() > MAX_MESSAGE {
            return Err(FedError::Pairing);
        }
        let value = Value::decode(message).map_err(|_| FedError::Pairing)?;
        let f = value.as_fields().map_err(|_| FedError::Pairing)?;
        f.only(&[0]).map_err(|_| FedError::Pairing)?;
        let sealed = f.bytes(0).map_err(|_| FedError::Pairing)?;
        let bytes = open(&self.initiator_key, &self.aad, sealed)?;
        let descriptor = read_descriptor(&bytes, self.initiator, now)?;
        let fingerprint = Fingerprint::of(
            (self.local_server, &self.local_key),
            (self.initiator, &descriptor.descriptor.identity_key),
        );
        Ok(Paired {
            descriptor,
            fingerprint,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::suite::Suite;
    use crate::testing::identity;

    const NOW: u64 = 1_800_000_000;

    #[test]
    fn codes_parse_the_way_people_type_them() {
        let code = PairingCode::generate();
        let shown = code.display();
        assert_eq!(shown.len(), 14);
        let typed = PairingCode::parse(&shown.to_lowercase()).expect("lower case");
        assert_eq!(typed.display(), shown);
        let spaced = PairingCode::parse(&shown.replace('-', " ")).expect("spaces");
        assert_eq!(spaced.display(), shown);
        assert_eq!(
            PairingCode::parse("oil0-0000-0000")
                .expect("confusables")
                .display(),
            "0110-0000-0000"
        );
        for bad in [
            "",
            "ABCD-EFGH-JKM",
            "ABCD-EFGH-JKMNN",
            "ABCU-EFGH-JKMN",
            "ABCD-EFGH-JKM\u{e9}",
        ] {
            assert!(PairingCode::parse(bad).is_err(), "{bad}");
        }
        assert!(format!("{code:?}").find(&shown[..4]).is_none());
    }

    #[test]
    fn generated_codes_use_the_alphabet_and_differ() {
        let a = PairingCode::generate();
        let b = PairingCode::generate();
        assert_ne!(a.display(), b.display());
        for c in a.display().chars().filter(|c| *c != '-') {
            assert!(ALPHABET.contains(&(c as u8)));
        }
    }

    #[test]
    fn proquints_match_the_published_examples() {
        // 127.0.0.1 is lusab-babad and 63.84.220.193 is gutih-tugad in Wilkerson's description.
        assert_eq!(proquint(0x7f00), "lusab");
        assert_eq!(proquint(0x0001), "babad");
        assert_eq!(proquint(0x3f54), "gutih");
        assert_eq!(proquint(0xdcc1), "tugad");
        assert_eq!(proquint(0x0000), "babab");
        assert_eq!(proquint(0xffff), "zuzuz");
    }

    #[test]
    fn cpace_gives_both_sides_the_same_session_key() {
        let sid = [3u8; 16];
        let run = cpace_exchange(b"CODE", &sid, b"a", b"b", &mut SystemRng, &mut SystemRng)
            .expect("exchange");
        assert_eq!(run.isk_initiator, run.isk_responder);
        assert_eq!(run.session_id_initiator, run.session_id_responder);
        assert_eq!(run.isk_initiator.len(), 64);
        let other = cpace_exchange(b"CODE", &sid, b"a", b"b", &mut SystemRng, &mut SystemRng)
            .expect("exchange");
        assert_ne!(
            run.isk_initiator, other.isk_initiator,
            "fresh scalars each run"
        );
    }

    #[test]
    fn the_fingerprint_is_symmetric_and_depends_on_both_keys() {
        let a = identity(1, NOW, &Suite::IMPLEMENTED);
        let b = identity(2, NOW, &Suite::IMPLEMENTED);
        let c = identity(3, NOW, &Suite::IMPLEMENTED);
        let ab = Fingerprint::of((a.server, &a.public), (b.server, &b.public));
        let ba = Fingerprint::of((b.server, &b.public), (a.server, &a.public));
        let ac = Fingerprint::of((a.server, &a.public), (c.server, &c.public));
        assert_eq!(ab, ba);
        assert_ne!(ab, ac);
        let shown = ab.to_string();
        assert_eq!(shown.split('-').count(), 6);
        assert!(shown.split('-').all(|w| w.len() == 5));
    }

    fn run(
        code_shown: &PairingCode,
        code_typed: &PairingCode,
        a: &LocalIdentity,
        b: &LocalIdentity,
    ) -> Result<(Paired, Paired)> {
        let (init, m1) = PairingInitiator::start(code_typed, a)?;
        let shown = PairingCode::parse(&code_shown.display())?;
        let (pending, m2) = respond(shown, b, &m1)?;
        let (paired_a, m3) = init.finish(&m2, NOW)?;
        let paired_b = pending.finish(&m3, NOW)?;
        Ok((paired_a, paired_b))
    }

    #[test]
    fn pairing_with_the_right_code_exchanges_identity_keys_and_agrees_on_the_fingerprint() {
        let a = identity(1, NOW, &Suite::IMPLEMENTED);
        let b = identity(2, NOW, &Suite::IMPLEMENTED);
        let code = PairingCode::generate();
        let (paired_a, paired_b) = run(&code, &code, &a, &b).expect("paired");
        assert_eq!(paired_a.descriptor.descriptor.server, b.server);
        assert_eq!(paired_a.descriptor.descriptor.identity_key, b.public);
        assert_eq!(paired_b.descriptor.descriptor.server, a.server);
        assert_eq!(paired_b.descriptor.descriptor.identity_key, a.public);
        assert_eq!(paired_a.fingerprint, paired_b.fingerprint);
    }

    #[test]
    fn the_wrong_code_fails_on_the_initiators_side_and_sends_nothing_more() {
        let a = identity(1, NOW, &Suite::IMPLEMENTED);
        let b = identity(2, NOW, &Suite::IMPLEMENTED);
        let shown = PairingCode::generate();
        let typed = PairingCode::generate();
        let (init, m1) = PairingInitiator::start(&typed, &a).expect("start");
        let (_pending, m2) =
            respond(PairingCode::parse(&shown.display()).expect("code"), &b, &m1).expect("respond");
        assert_eq!(init.finish(&m2, NOW).map(|_| ()), Err(FedError::Pairing));
    }

    #[test]
    fn a_man_in_the_middle_without_the_code_cannot_make_either_side_accept_its_key() {
        let a = identity(1, NOW, &Suite::IMPLEMENTED);
        let b = identity(2, NOW, &Suite::IMPLEMENTED);
        let mallory = identity(3, NOW, &Suite::IMPLEMENTED);
        let code = PairingCode::generate();
        // Mallory answers A as if she were B, guessing a code.
        let (init, m1) = PairingInitiator::start(&code, &a).expect("start");
        let guess = PairingCode::generate();
        let (_p, m2) = respond(guess, &mallory, &m1).expect("respond");
        assert!(init.finish(&m2, NOW).is_err());
        // Mallory plays A to B with a guessed code.
        let (_i, m1) = PairingInitiator::start(&PairingCode::generate(), &mallory).expect("start");
        let (pending, _m2) =
            respond(PairingCode::parse(&code.display()).expect("code"), &b, &m1).expect("respond");
        // She can't produce a message 3 that opens: a replayed or random one fails.
        assert!(pending.finish(&[0xa0], NOW).is_err());
    }

    #[test]
    fn a_changed_message_fails_the_pairing() {
        let a = identity(1, NOW, &Suite::IMPLEMENTED);
        let b = identity(2, NOW, &Suite::IMPLEMENTED);
        let code = PairingCode::generate();
        let (init, m1) = PairingInitiator::start(&code, &a).expect("start");
        let (pending, m2) =
            respond(PairingCode::parse(&code.display()).expect("code"), &b, &m1).expect("respond");
        // Changed message 2.
        let mut bad = m2.clone();
        let last = bad.len() - 1;
        bad[last] ^= 1;
        let (init2, m1b) = PairingInitiator::start(&code, &a).expect("start");
        let (_p2, m2b) =
            respond(PairingCode::parse(&code.display()).expect("code"), &b, &m1b).expect("respond");
        let mut bad2 = m2b;
        let mid = bad2.len() / 2;
        bad2[mid] ^= 1;
        assert!(init2.finish(&bad2, NOW).is_err());
        let _ = bad;
        // Changed message 3.
        let (_paired, mut m3) = init.finish(&m2, NOW).expect("finish");
        let mid = m3.len() / 2;
        m3[mid] ^= 1;
        assert_eq!(pending.finish(&m3, NOW).map(|_| ()), Err(FedError::Pairing));
    }

    #[test]
    fn pairing_with_oneself_or_with_junk_is_refused() {
        let a = identity(1, NOW, &Suite::IMPLEMENTED);
        let code = PairingCode::generate();
        let (_, m1) = PairingInitiator::start(&code, &a).expect("start");
        assert!(respond(PairingCode::parse(&code.display()).expect("code"), &a, &m1).is_err());
        let junk_messages: [&[u8]; 3] = [&[], &[0xff], &[0xa0]];
        for junk in junk_messages {
            assert!(respond(PairingCode::generate(), &a, junk).is_err());
        }
    }
}
