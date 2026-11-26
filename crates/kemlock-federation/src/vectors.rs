//! The federation test vectors of `test-vectors/federation-*.json`: one JSON file per format,
//! generated from fixed keys and a seeded random source, and checked by code that rebuilds every
//! value from the inputs the file lists.
//!
//! Every file is `{"format", "version", "description", "cases", ...}` with bytes as lower-case
//! hex, in the style of `kemlock-crypto`'s vectors. The generator (`kemlock-fed-vectors`, feature
//! `vectors`) seeds kemlock-crypto's random source per file, so the output is the same on every
//! run; without the feature the generated files are valid but not reproducible, which is enough
//! for the self-check in this module's tests.

use crate::cbor::Value;
use crate::change::{self, ChangeRecord};
use crate::crypto;
use crate::descriptor::{Descriptor, SignedDescriptor, VALIDITY_SECS, kem_key_id};
use crate::error::{FedError, Result};
use crate::frame::{self, Direction, FrameReader, FrameWriter, Padding};
use crate::handshake::{self, Hello, Initiator, NonceCache, Reply};
use crate::hashtree::{self, Leaf, Tree};
use crate::home::{HomeRecord, PromotionRecord, VaultFederation, Verdict};
use crate::identity::{DescriptorParams, KemPair, LocalIdentity};
use crate::pairing::{self, Fingerprint, PairingCode};
use crate::signed::Signed;
use crate::suite::Suite;
use crate::testing::directory;
use crate::wire::{ChangeKey, item_id, owner, server_id};
use kemlock_crypto::{kx1, sig1};
use kemlock_domain::{
    ChangeId, Hlc, ItemFormat, ItemKind, Owner, Revision, ServerId, WriteSignature,
};
use serde_json::{Value as Json, json};
use std::collections::HashMap;

/// The version every file carries; a format change means a new label, not a new number here.
pub const VERSION: u64 = 1;

/// The files, without their `.json`.
pub const FILES: &[&str] = &[
    "federation-descriptor",
    "federation-handshake",
    "federation-frames",
    "federation-pairing",
    "federation-change",
    "federation-hashtree",
];

/// The time every vector is made at (Unix seconds).
pub const NOW: u64 = 1_800_000_000;

fn hx(bytes: &[u8]) -> Json {
    Json::String(hex::encode(bytes))
}

fn unhex(value: &Json) -> Result<Vec<u8>> {
    value
        .as_str()
        .and_then(|s| hex::decode(s).ok())
        .ok_or(FedError::Malformed("a vector value is not hex"))
}

fn field<'a>(value: &'a Json, key: &str) -> Result<&'a Json> {
    value
        .get(key)
        .ok_or(FedError::Malformed("a vector field is missing"))
}

fn bytes_of(value: &Json, key: &str) -> Result<Vec<u8>> {
    unhex(field(value, key)?)
}

fn array_of<const N: usize>(value: &Json, key: &str) -> Result<[u8; N]> {
    bytes_of(value, key)?
        .try_into()
        .map_err(|_| FedError::Malformed("a vector field has the wrong length"))
}

fn uint_of(value: &Json, key: &str) -> Result<u64> {
    field(value, key)?
        .as_u64()
        .ok_or(FedError::Malformed("a vector field is not an integer"))
}

fn text_of<'a>(value: &'a Json, key: &str) -> Result<&'a str> {
    field(value, key)?
        .as_str()
        .ok_or(FedError::Malformed("a vector field is not text"))
}

fn flag_of(value: &Json, key: &str) -> Result<bool> {
    field(value, key)?
        .as_bool()
        .ok_or(FedError::Malformed("a vector field is not a boolean"))
}

fn texts_of(value: &Json, key: &str) -> Result<Vec<String>> {
    field(value, key)?
        .as_array()
        .ok_or(FedError::Malformed("a vector field is not a list"))?
        .iter()
        .map(|v| {
            v.as_str()
                .map(str::to_owned)
                .ok_or(FedError::Malformed("a vector list entry is not text"))
        })
        .collect()
}

fn list_of<'a>(value: &'a Json, key: &str) -> Result<&'a Vec<Json>> {
    field(value, key)?
        .as_array()
        .ok_or(FedError::Malformed("a vector field is not a list"))
}

fn ensure(condition: bool, what: &'static str) -> Result<()> {
    if condition {
        Ok(())
    } else {
        Err(FedError::Invalid(what))
    }
}

/// Like [`ensure`], for a value that holds a signature made again from the file's inputs.
///
/// ML-DSA signing may be hedged or deterministic (docs/crypto.md), and the public functions run
/// on aws-lc, whose signing draws its own randomness, so a rebuilt signature equals the file's
/// only when the signing is the seeded RustCrypto one (feature `vectors`, the generator's). Without
/// it the file's signature is checked the way every verifier does: each check opens or verifies
/// the stored envelope, which accepts either kind.
fn ensure_resigned(same: bool, what: &'static str) -> Result<()> {
    if cfg!(feature = "vectors") {
        ensure(same, what)
    } else {
        Ok(())
    }
}

/// `offset, offset + 1, …` wrapping at 256: bytes a person can recognise.
fn counting<const N: usize>(offset: u8) -> [u8; N] {
    core::array::from_fn(|i| offset.wrapping_add(i as u8))
}

/// Runs `f` with this file's own seeded random stream.
#[cfg(feature = "vectors")]
fn seeded<T>(file: &str, f: impl FnOnce() -> Result<T>) -> Result<T> {
    let seed = crypto::sha256(format!("kemlock-fed-vectors/{file}").as_bytes());
    kemlock_crypto::with_seeded_random(seed, f)
}

/// Without the `vectors` feature there is no seeded stream: the output is valid, not reproducible.
#[cfg(not(feature = "vectors"))]
fn seeded<T>(_file: &str, f: impl FnOnce() -> Result<T>) -> Result<T> {
    f()
}

fn document(format: &str, description: &str, cases: Vec<Json>, extra: Vec<(&str, Json)>) -> Json {
    let mut doc = json!({
        "format": format,
        "version": VERSION,
        "description": description,
        "cases": cases,
    });
    if let Some(map) = doc.as_object_mut() {
        for (key, value) in extra {
            map.insert(key.to_owned(), value);
        }
    }
    doc
}

/// A random source that hands out a fixed byte string, for CPace's scalars.
struct Scripted {
    bytes: Vec<u8>,
    pos: usize,
}

impl Scripted {
    fn new(bytes: &[u8]) -> Scripted {
        Scripted {
            bytes: bytes.to_vec(),
            pos: 0,
        }
    }

    fn take(&mut self, dst: &mut [u8]) {
        for b in dst.iter_mut() {
            *b = self.bytes.get(self.pos).copied().unwrap_or(0);
            self.pos += 1;
        }
    }
}

impl rand_core::TryRng for Scripted {
    type Error = core::convert::Infallible;

    fn try_next_u32(&mut self) -> core::result::Result<u32, Self::Error> {
        let mut b = [0u8; 4];
        self.take(&mut b);
        Ok(u32::from_le_bytes(b))
    }

    fn try_next_u64(&mut self) -> core::result::Result<u64, Self::Error> {
        let mut b = [0u8; 8];
        self.take(&mut b);
        Ok(u64::from_le_bytes(b))
    }

    fn try_fill_bytes(&mut self, dst: &mut [u8]) -> core::result::Result<(), Self::Error> {
        self.take(dst);
        Ok(())
    }
}

impl rand_core::TryCryptoRng for Scripted {}

/// A server whose keys come from fixed seeds.
struct Party {
    identity: LocalIdentity,
    signing_seed: [u8; 64],
    kem_seed: [u8; 96],
}

fn party(n: u8, suites: &[Suite]) -> Result<Party> {
    let signing_seed: [u8; 64] = counting(n.wrapping_mul(16));
    let kem_seed: [u8; 96] = counting(n.wrapping_mul(16).wrapping_add(100));
    let kem = KemPair::from_private(kx1::PrivateKey::from_bytes(&kem_seed))?;
    let identity = LocalIdentity::new(
        server_id([n; 16]),
        sig1::SigningKey::from_bytes(&signing_seed),
        vec![kem],
        DescriptorParams {
            suites: suites.to_vec(),
            addresses: vec![format!("https://server-{n}.example.org")],
            operator: format!("Operator {n}"),
            not_before: NOW,
            not_after: NOW + VALIDITY_SECS,
        },
    )?;
    Ok(Party {
        identity,
        signing_seed,
        kem_seed,
    })
}

// ---- descriptor ----

fn descriptor_case(name: &str, seeds: (&[u8; 64], &[u8; 96]), d: &SignedDescriptor) -> Json {
    let inner = &d.descriptor;
    json!({
        "name": name,
        "server_id": hx(inner.server.as_bytes()),
        "signing_seed": hx(seeds.0),
        "kem_seed": hx(seeds.1),
        "identity_key": hx(inner.identity_key.as_bytes()),
        "kem_key": hx(inner.kem_key.as_bytes()),
        "kem_key_id": hx(&kem_key_id(&inner.kem_key)),
        "suites": inner.suites,
        "addresses": inner.addresses,
        "operator": inner.operator,
        "not_before": inner.not_before,
        "not_after": inner.not_after,
        "body": hx(&d.envelope.body),
        "signature": hx(&d.envelope.signature),
        "envelope": hx(&d.to_bytes()),
    })
}

fn descriptor_doc() -> Result<Json> {
    seeded("federation-descriptor", || {
        let two = party(1, &Suite::IMPLEMENTED)?;
        let chacha = party(2, &[Suite::ChaCha20Poly1305])?;
        let third = party(3, &Suite::IMPLEMENTED)?;
        let mut with_unknown = third.identity.descriptor.descriptor.clone();
        with_unknown
            .suites
            .insert(0, "kfed9-from-the-future".to_owned());
        with_unknown.suites.push(Suite::Fips.name().to_owned());
        let unknown = SignedDescriptor::sign(with_unknown, &third.identity.signing)?;

        let cases = vec![
            descriptor_case(
                "both-implemented-suites",
                (&two.signing_seed, &two.kem_seed),
                &two.identity.descriptor,
            ),
            descriptor_case(
                "chacha-only",
                (&chacha.signing_seed, &chacha.kem_seed),
                &chacha.identity.descriptor,
            ),
            descriptor_case(
                "unknown-and-fips-suites-are-kept",
                (&third.signing_seed, &third.kem_seed),
                &unknown,
            ),
        ];

        let good = &two.identity.descriptor;
        let mut flipped = good.envelope.clone();
        flipped.signature[100] ^= 1;
        let mut long = good.descriptor.clone();
        long.not_after = long.not_before + VALIDITY_SECS + 1;
        let long = SignedDescriptor::sign(long, &two.identity.signing)?;
        let mut body = Value::decode(&good.envelope.body)?;
        if let Value::Map(entries) = &mut body {
            entries.push((9, Value::Uint(1)));
        }
        let extra = Signed::sign(
            &two.identity.signing,
            crate::descriptor::CONTEXT,
            body.encode(),
        )?;
        let negative = vec![
            json!({"name": "flipped-signature-byte", "now": NOW, "envelope": hx(&flipped.encode())}),
            json!({"name": "window-longer-than-37-days", "now": NOW, "envelope": hx(&long.to_bytes())}),
            json!({"name": "unknown-field", "now": NOW, "envelope": hx(&extra.encode())}),
            json!({"name": "before-not-before", "now": NOW - 301, "envelope": hx(&good.to_bytes())}),
            json!({"name": "after-not-after", "now": NOW + VALIDITY_SECS + 1, "envelope": hx(&good.to_bytes())}),
        ];
        Ok(document(
            "federation-descriptor",
            "The signed descriptor: deterministic CBOR body, sig1 signature under the context \
             federation-descriptor, kx1 key id. Negative cases must fail to parse or verify at `now`.",
            cases,
            vec![("negative", Json::Array(negative))],
        ))
    })
}

fn check_descriptor(doc: &Json) -> Result<()> {
    for case in list_of(doc, "cases")? {
        let signing = sig1::SigningKey::from_bytes(&array_of::<64>(case, "signing_seed")?);
        let public = crypto::sign_public(&signing)?;
        let kem = KemPair::from_private(kx1::PrivateKey::from_bytes(&array_of::<96>(
            case, "kem_seed",
        )?))?;
        ensure(
            public.as_bytes()[..] == bytes_of(case, "identity_key")?[..],
            "identity key",
        )?;
        ensure(
            kem.public.as_bytes()[..] == bytes_of(case, "kem_key")?[..],
            "kem key",
        )?;
        ensure(
            kem_key_id(&kem.public) == array_of::<32>(case, "kem_key_id")?,
            "kem key id",
        )?;
        let d = Descriptor {
            server: server_id(array_of::<16>(case, "server_id")?),
            identity_key: public,
            kem_key: kem.public,
            suites: texts_of(case, "suites")?,
            addresses: texts_of(case, "addresses")?,
            operator: text_of(case, "operator")?.to_owned(),
            not_before: uint_of(case, "not_before")?,
            not_after: uint_of(case, "not_after")?,
        };
        ensure(d.to_body() == bytes_of(case, "body")?, "descriptor body")?;
        let signed = SignedDescriptor::sign(d, &signing)?;
        ensure_resigned(
            signed.envelope.signature == bytes_of(case, "signature")?,
            "signature",
        )?;
        ensure_resigned(signed.to_bytes() == bytes_of(case, "envelope")?, "envelope")?;
        SignedDescriptor::parse(&bytes_of(case, "envelope")?)?.verify(NOW, None)?;
    }
    for case in list_of(doc, "negative")? {
        let now = uint_of(case, "now")?;
        let outcome =
            SignedDescriptor::parse(&bytes_of(case, "envelope")?).and_then(|d| d.verify(now, None));
        ensure(outcome.is_err(), "a negative descriptor was accepted")?;
    }
    Ok(())
}

// ---- frames ----

fn direction_name(direction: Direction) -> &'static str {
    match direction {
        Direction::InitiatorToResponder => "initiator_to_responder",
        Direction::ResponderToInitiator => "responder_to_initiator",
    }
}

fn direction_of(name: &str) -> Result<Direction> {
    match name {
        "initiator_to_responder" => Ok(Direction::InitiatorToResponder),
        "responder_to_initiator" => Ok(Direction::ResponderToInitiator),
        _ => Err(FedError::Malformed("an unknown direction")),
    }
}

fn padding_name(padding: Padding) -> &'static str {
    match padding {
        Padding::Off => "off",
        Padding::Step4096 => "4096",
    }
}

fn padding_of(name: &str) -> Result<Padding> {
    match name {
        "off" => Ok(Padding::Off),
        "4096" => Ok(Padding::Step4096),
        _ => Err(FedError::Malformed("an unknown padding")),
    }
}

fn suite_of(name: &str) -> Result<Suite> {
    Suite::from_name(name).ok_or(FedError::Malformed("an unknown suite"))
}

/// One writer's frames: each is `(now, last, payload)`.
#[allow(clippy::too_many_arguments)]
fn frame_run(
    name: &str,
    suite: Suite,
    session: [u8; 16],
    prk: &[u8; 32],
    direction: Direction,
    padding: Padding,
    steps: &[(u64, bool, Vec<u8>)],
    start: u64,
) -> Result<Json> {
    let mut writer = FrameWriter::new(session, suite.aead()?, prk, direction, start, padding);
    let mut frames = Vec::new();
    for (now, last, payload) in steps {
        let counter = writer.counter();
        let frame = writer.seal(payload, *last, *now)?;
        frames.push(json!({
            "now": now,
            "last": last,
            "payload": hx(payload),
            "counter": counter,
            "epoch": writer.epoch(),
            "frame": hx(&frame),
        }));
    }
    Ok(json!({
        "name": name,
        "suite": suite.name(),
        "session_id": hx(&session),
        "master_secret": hx(prk),
        "direction": direction_name(direction),
        "padding": padding_name(padding),
        "start": start,
        "frames": frames,
    }))
}

fn frames_doc() -> Result<Json> {
    seeded("federation-frames", || {
        let prk: [u8; 32] = counting(1);
        let session: [u8; 16] = counting(0x40);
        let big: Vec<u8> = counting::<255>(7)
            .iter()
            .cycle()
            .take(5000)
            .copied()
            .collect();
        let mut cases = Vec::new();
        for suite in Suite::IMPLEMENTED {
            let tag = if suite == Suite::Aes256Gcm {
                "aes"
            } else {
                "chacha"
            };
            cases.push(frame_run(
                &format!("{tag}-unpadded"),
                suite,
                session,
                &prk,
                Direction::InitiatorToResponder,
                Padding::Off,
                &[
                    (0, false, Vec::new()),
                    (1, false, b"hello".to_vec()),
                    (2, true, counting::<300>(9).to_vec()),
                ],
                0,
            )?);
            cases.push(frame_run(
                &format!("{tag}-padded-to-4096"),
                suite,
                session,
                &prk,
                Direction::ResponderToInitiator,
                Padding::Step4096,
                &[(0, false, b"hello".to_vec()), (1, true, big.clone())],
                0,
            )?);
            cases.push(frame_run(
                &format!("{tag}-rekey-after-an-hour"),
                suite,
                session,
                &prk,
                Direction::InitiatorToResponder,
                Padding::Off,
                &[
                    (10, false, b"epoch zero".to_vec()),
                    (frame::REKEY_SECS, false, b"epoch one".to_vec()),
                    (frame::REKEY_SECS + 1, true, b"still epoch one".to_vec()),
                ],
                0,
            )?);
        }

        // The key schedule of one direction over two epochs.
        let chain0 = frame::chain_key(&prk, Direction::InitiatorToResponder);
        let (key0, iv0) = frame::epoch_material(&chain0);
        let chain1 = frame::next_chain(&chain0);
        let (key1, iv1) = frame::epoch_material(&chain1);
        let schedule = json!({
            "master_secret": hx(&prk),
            "direction": direction_name(Direction::InitiatorToResponder),
            "chain_key_0": hx(&*chain0),
            "frame_key_0": hx(&*key0),
            "frame_iv_0": hx(&iv0),
            "chain_key_1": hx(&*chain1),
            "frame_key_1": hx(&*key1),
            "frame_iv_1": hx(&iv1),
            "nonce_counter_0": hx(&frame::frame_nonce(&iv0, 0)),
            "nonce_counter_7": hx(&frame::frame_nonce(&iv0, 7)),
        });

        // Streams that must fail: frames before `fail_at` open, the one at `fail_at` does not.
        let first = cases
            .first()
            .and_then(|c| c.get("frames"))
            .and_then(Json::as_array)
            .ok_or(FedError::Malformed("no frames"))?;
        let frame_hex = |i: usize| -> Result<String> {
            first
                .get(i)
                .and_then(|f| f.get("frame"))
                .and_then(Json::as_str)
                .map(str::to_owned)
                .ok_or(FedError::Malformed("no frame"))
        };
        let (f0, f1, f2) = (frame_hex(0)?, frame_hex(1)?, frame_hex(2)?);
        let mut flipped = hex::decode(&f2).map_err(|_| FedError::Malformed("hex"))?;
        flipped[frame::HEADER_LEN - 1] ^= 1;
        let mut truncated = hex::decode(&f2).map_err(|_| FedError::Malformed("hex"))?;
        truncated.pop();
        let negative = vec![
            json!({"name": "replayed-frame", "frames": [f0, f0], "fail_at": 1}),
            json!({"name": "dropped-first-frame", "frames": [f1], "fail_at": 0}),
            json!({"name": "reordered-frames", "frames": [f1, f0], "fail_at": 0}),
            json!({"name": "last-flag-flipped", "frames": [f0, f1, hex::encode(&flipped)], "fail_at": 2}),
            json!({"name": "truncated-last-frame", "frames": [f0, f1, hex::encode(&truncated)], "fail_at": 2}),
            json!({"name": "after-the-last-frame", "frames": [f0, f1, f2, f2], "fail_at": 3}),
        ];
        Ok(document(
            "federation-frames",
            "Sealed frames: header, nonce, padding, rekey. `cases` are writer runs a reader must \
             open in order and a writer must reproduce byte for byte; `negative` streams use the \
             session of the first case (suite, session id, master secret, direction).",
            cases,
            vec![
                ("key_schedule", schedule),
                ("negative", Json::Array(negative)),
                (
                    "negative_session",
                    json!({
                        "suite": Suite::Aes256Gcm.name(),
                        "session_id": hx(&session),
                        "master_secret": hx(&prk),
                        "direction": direction_name(Direction::InitiatorToResponder),
                    }),
                ),
            ],
        ))
    })
}

/// Rebuilds one writer run and opens its frames with a reader.
fn check_frame_run(case: &Json) -> Result<()> {
    let suite = suite_of(text_of(case, "suite")?)?;
    let session = array_of::<16>(case, "session_id")?;
    let prk = array_of::<32>(case, "master_secret")?;
    let direction = direction_of(text_of(case, "direction")?)?;
    let padding = padding_of(text_of(case, "padding")?)?;
    let mut writer = FrameWriter::new(
        session,
        suite.aead()?,
        &prk,
        direction,
        uint_of(case, "start")?,
        padding,
    );
    let mut reader = FrameReader::new(session, suite.aead()?, &prk, direction);
    for entry in list_of(case, "frames")? {
        let payload = bytes_of(entry, "payload")?;
        let last = flag_of(entry, "last")?;
        let frame = writer.seal(&payload, last, uint_of(entry, "now")?)?;
        ensure(
            frame == bytes_of(entry, "frame")?,
            "a frame is not reproduced",
        )?;
        let opened = reader.open(&frame)?;
        ensure(
            opened.payload == payload && opened.last == last,
            "a frame opens wrongly",
        )?;
    }
    Ok(())
}

fn check_frames(doc: &Json) -> Result<()> {
    for case in list_of(doc, "cases")? {
        check_frame_run(case)?;
    }
    let schedule = field(doc, "key_schedule")?;
    let prk = array_of::<32>(schedule, "master_secret")?;
    let direction = direction_of(text_of(schedule, "direction")?)?;
    let chain0 = frame::chain_key(&prk, direction);
    ensure(
        chain0[..] == bytes_of(schedule, "chain_key_0")?[..],
        "chain key 0",
    )?;
    let (key0, iv0) = frame::epoch_material(&chain0);
    ensure(
        key0[..] == bytes_of(schedule, "frame_key_0")?[..],
        "frame key 0",
    )?;
    ensure(
        iv0[..] == bytes_of(schedule, "frame_iv_0")?[..],
        "frame iv 0",
    )?;
    let chain1 = frame::next_chain(&chain0);
    ensure(
        chain1[..] == bytes_of(schedule, "chain_key_1")?[..],
        "chain key 1",
    )?;
    let (key1, iv1) = frame::epoch_material(&chain1);
    ensure(
        key1[..] == bytes_of(schedule, "frame_key_1")?[..],
        "frame key 1",
    )?;
    ensure(
        iv1[..] == bytes_of(schedule, "frame_iv_1")?[..],
        "frame iv 1",
    )?;
    ensure(
        frame::frame_nonce(&iv0, 0)[..] == bytes_of(schedule, "nonce_counter_0")?[..],
        "nonce 0",
    )?;
    ensure(
        frame::frame_nonce(&iv0, 7)[..] == bytes_of(schedule, "nonce_counter_7")?[..],
        "nonce 7",
    )?;

    let session = field(doc, "negative_session")?;
    let suite = suite_of(text_of(session, "suite")?)?;
    for case in list_of(doc, "negative")? {
        let mut reader = FrameReader::new(
            array_of::<16>(session, "session_id")?,
            suite.aead()?,
            &array_of::<32>(session, "master_secret")?,
            direction_of(text_of(session, "direction")?)?,
        );
        let fail_at = usize::try_from(uint_of(case, "fail_at")?)
            .map_err(|_| FedError::Malformed("fail_at"))?;
        let frames = list_of(case, "frames")?;
        for (i, f) in frames.iter().enumerate() {
            let outcome = reader.open(&unhex(f)?);
            if i < fail_at {
                ensure(outcome.is_ok(), "a frame before the failure did not open")?;
            } else if i == fail_at {
                ensure(outcome.is_err(), "a bad frame opened")?;
                break;
            }
        }
    }
    Ok(())
}

// ---- handshake ----

fn handshake_case(suite: Suite) -> Result<Json> {
    let a = party(1, &[suite])?;
    let b = party(2, &[suite])?;
    let ephemeral_private = kx1::PrivateKey::from_bytes(&counting::<96>(200));
    let ephemeral_public = crypto::kem_public(&ephemeral_private)?;
    let (initiator, hello) = Initiator::start_with_ephemeral(
        &a.identity,
        &b.identity.descriptor,
        &b.identity.public,
        NOW,
        (ephemeral_private.clone(), ephemeral_public),
    )?;
    let keys_b = directory(&[&a.identity]);
    let accepted = handshake::respond(
        &b.identity,
        &keys_b,
        &mut NonceCache::new(),
        &hello,
        NOW + 1,
        Padding::Off,
    )?;
    let mut session_a = initiator.finish(&accepted.reply, NOW + 2, Padding::Off)?;
    let mut session_b = accepted.session;

    let hello_env = Signed::decode(&hello)?;
    let reply_env = Signed::decode(&accepted.reply)?;
    let h = Hello::from_body(&hello_env.body)?;
    let r = Reply::from_body(&reply_env.body)?;
    let transcript = handshake::transcript_hash(&hello, &reply_env.body);
    let ss_responder = crypto::kem_decapsulate(&b.identity.kems[0].private, &h.ct_responder)?;
    let ss_ephemeral = crypto::kem_decapsulate(&ephemeral_private, &r.ct_ephemeral)?;
    let ss_initiator = crypto::kem_decapsulate(&a.identity.kems[0].private, &r.ct_initiator_kem)?;
    let prk = handshake::master_secret(&transcript, &ss_responder, &ss_ephemeral, &ss_initiator);

    let request = session_a.writer.seal(b"request", false, NOW + 3)?;
    let response = session_b.writer.seal(b"response", true, NOW + 3)?;
    ensure(
        session_b.reader.open(&request)?.payload == b"request",
        "request",
    )?;
    ensure(
        session_a.reader.open(&response)?.payload == b"response",
        "response",
    )?;

    let direction_keys = |direction: Direction| {
        let chain = frame::chain_key(&prk, direction);
        let (key, iv) = frame::epoch_material(&chain);
        json!({
            "direction": direction_name(direction),
            "chain_key": hx(&*chain),
            "frame_key": hx(&*key),
            "frame_iv": hx(&iv),
        })
    };
    Ok(json!({
        "name": suite.name(),
        "suite": suite.name(),
        "initiator_time": NOW,
        "responder_time": NOW + 1,
        "initiator": {
            "server_id": hx(a.identity.server.as_bytes()),
            "signing_seed": hx(&a.signing_seed),
            "kem_seed": hx(&a.kem_seed),
            "descriptor": hx(&a.identity.descriptor.to_bytes()),
        },
        "responder": {
            "server_id": hx(b.identity.server.as_bytes()),
            "signing_seed": hx(&b.signing_seed),
            "kem_seed": hx(&b.kem_seed),
            "descriptor": hx(&b.identity.descriptor.to_bytes()),
        },
        "ephemeral_private_key": hx(ephemeral_private.as_bytes()),
        "hello": hx(&hello),
        "reply": hx(&accepted.reply),
        "session_id": hx(&session_a.id),
        "transcript_hash": hx(&transcript),
        "shared_secrets": {
            "responder_kem": hx(&*ss_responder),
            "ephemeral": hx(&*ss_ephemeral),
            "initiator_kem": hx(&*ss_initiator),
        },
        "master_secret": hx(&*prk),
        "directions": [
            direction_keys(Direction::InitiatorToResponder),
            direction_keys(Direction::ResponderToInitiator),
        ],
        "frames": [
            {"direction": direction_name(Direction::InitiatorToResponder), "counter": 0, "last": false, "payload": hx(b"request"), "frame": hx(&request)},
            {"direction": direction_name(Direction::ResponderToInitiator), "counter": 0, "last": true, "payload": hx(b"response"), "frame": hx(&response)},
        ],
    }))
}

fn handshake_doc() -> Result<Json> {
    seeded("federation-handshake", || {
        let mut cases = Vec::new();
        for suite in Suite::IMPLEMENTED {
            cases.push(handshake_case(suite)?);
        }
        // Handshakes that must be refused: a hello with a changed byte, and one outside the
        // timestamp window.
        let a = party(1, &Suite::IMPLEMENTED)?;
        let b = party(2, &Suite::IMPLEMENTED)?;
        let (_, hello) = Initiator::start_with_ephemeral(
            &a.identity,
            &b.identity.descriptor,
            &b.identity.public,
            NOW,
            (
                kx1::PrivateKey::from_bytes(&counting::<96>(210)),
                crypto::kem_public(&kx1::PrivateKey::from_bytes(&counting::<96>(210)))?,
            ),
        )?;
        let mut flipped = hello.clone();
        let middle = flipped.len() / 2;
        flipped[middle] ^= 1;
        let negative = vec![
            json!({"name": "hello-with-a-changed-byte", "now": NOW, "hello": hx(&flipped)}),
            json!({"name": "hello-too-old", "now": NOW + 301, "hello": hx(&hello)}),
            json!({"name": "hello-from-the-future", "now": NOW - 301, "hello": hx(&hello)}),
        ];
        Ok(document(
            "federation-handshake",
            "The session handshake: signed hello and reply, transcript hash, the three shared \
             secrets, the master secret, per-direction keys and the first frames. A verifier \
             parses the messages, checks both signatures, decapsulates with the listed private \
             keys and recomputes everything. Negative hellos are checked by the responder \
             `negative_responder` (the second party of the first case) at `now`.",
            cases,
            vec![
                ("negative", Json::Array(negative)),
                (
                    "negative_responder",
                    json!({
                        "initiator_server_id": hx(a.identity.server.as_bytes()),
                        "initiator_identity_key": hx(a.identity.public.as_bytes()),
                        "responder_signing_seed": hx(&b.signing_seed),
                        "responder_kem_seed": hx(&b.kem_seed),
                        "responder_suites": crate::suite::names(&Suite::IMPLEMENTED),
                    }),
                ),
            ],
        ))
    })
}

fn check_handshake(doc: &Json) -> Result<()> {
    for case in list_of(doc, "cases")? {
        let suite = suite_of(text_of(case, "suite")?)?;
        let initiator = field(case, "initiator")?;
        let responder = field(case, "responder")?;
        let a_public = crypto::sign_public(&sig1::SigningKey::from_bytes(&array_of::<64>(
            initiator,
            "signing_seed",
        )?))?;
        let b_public = crypto::sign_public(&sig1::SigningKey::from_bytes(&array_of::<64>(
            responder,
            "signing_seed",
        )?))?;
        let a_kem = KemPair::from_private(kx1::PrivateKey::from_bytes(&array_of::<96>(
            initiator, "kem_seed",
        )?))?;
        let b_kem = KemPair::from_private(kx1::PrivateKey::from_bytes(&array_of::<96>(
            responder, "kem_seed",
        )?))?;
        SignedDescriptor::parse(&bytes_of(initiator, "descriptor")?)?
            .verify(NOW, Some(&a_public))?;
        SignedDescriptor::parse(&bytes_of(responder, "descriptor")?)?
            .verify(NOW, Some(&b_public))?;

        let hello = bytes_of(case, "hello")?;
        let reply = bytes_of(case, "reply")?;
        let hello_env = Signed::decode(&hello)?;
        hello_env.verify(&a_public, handshake::HELLO_CONTEXT)?;
        let reply_env = Signed::decode(&reply)?;
        let h = Hello::from_body(&hello_env.body)?;
        let r = Reply::from_body(&reply_env.body)?;
        ensure(h.suite == suite.name(), "the hello's suite")?;
        ensure(r.suite == suite.name(), "the reply's suite")?;
        let transcript = handshake::transcript_hash(&hello, &reply_env.body);
        ensure(
            transcript[..] == bytes_of(case, "transcript_hash")?[..],
            "transcript hash",
        )?;
        crypto::verify(
            &b_public,
            handshake::REPLY_CONTEXT,
            &transcript,
            &reply_env.signature,
        )?;

        let ephemeral =
            kx1::PrivateKey::from_bytes(&array_of::<96>(case, "ephemeral_private_key")?);
        let secrets = field(case, "shared_secrets")?;
        let ss_responder = crypto::kem_decapsulate(&b_kem.private, &h.ct_responder)?;
        let ss_ephemeral = crypto::kem_decapsulate(&ephemeral, &r.ct_ephemeral)?;
        let ss_initiator = crypto::kem_decapsulate(&a_kem.private, &r.ct_initiator_kem)?;
        ensure(
            ss_responder[..] == bytes_of(secrets, "responder_kem")?[..],
            "responder secret",
        )?;
        ensure(
            ss_ephemeral[..] == bytes_of(secrets, "ephemeral")?[..],
            "ephemeral secret",
        )?;
        ensure(
            ss_initiator[..] == bytes_of(secrets, "initiator_kem")?[..],
            "initiator secret",
        )?;
        let prk =
            handshake::master_secret(&transcript, &ss_responder, &ss_ephemeral, &ss_initiator);
        ensure(
            prk[..] == bytes_of(case, "master_secret")?[..],
            "master secret",
        )?;

        let session = array_of::<16>(case, "session_id")?;
        ensure(r.session == session, "session id")?;
        for entry in list_of(case, "directions")? {
            let direction = direction_of(text_of(entry, "direction")?)?;
            let chain = frame::chain_key(&prk, direction);
            ensure(chain[..] == bytes_of(entry, "chain_key")?[..], "chain key")?;
            let (key, iv) = frame::epoch_material(&chain);
            ensure(key[..] == bytes_of(entry, "frame_key")?[..], "frame key")?;
            ensure(iv[..] == bytes_of(entry, "frame_iv")?[..], "frame iv")?;
        }
        for entry in list_of(case, "frames")? {
            let direction = direction_of(text_of(entry, "direction")?)?;
            let mut reader = FrameReader::new(session, suite.aead()?, &prk, direction);
            let opened = reader.open(&bytes_of(entry, "frame")?)?;
            ensure(
                opened.payload == bytes_of(entry, "payload")?,
                "frame payload",
            )?;
            ensure(opened.last == flag_of(entry, "last")?, "frame last flag")?;
        }
    }

    let responder = field(doc, "negative_responder")?;
    let b_signing =
        sig1::SigningKey::from_bytes(&array_of::<64>(responder, "responder_signing_seed")?);
    let b_kem = KemPair::from_private(kx1::PrivateKey::from_bytes(&array_of::<96>(
        responder,
        "responder_kem_seed",
    )?))?;
    let b = LocalIdentity::new(
        server_id([2; 16]),
        b_signing,
        vec![b_kem],
        DescriptorParams {
            suites: Suite::IMPLEMENTED.to_vec(),
            addresses: vec!["https://server-2.example.org".to_owned()],
            operator: "Operator 2".to_owned(),
            not_before: NOW,
            not_after: NOW + VALIDITY_SECS,
        },
    )?;
    let mut keys: HashMap<ServerId, sig1::PublicKey> = HashMap::new();
    keys.insert(
        server_id(array_of::<16>(responder, "initiator_server_id")?),
        sig1::PublicKey::from_bytes(&bytes_of(responder, "initiator_identity_key")?)
            .map_err(|_| FedError::Malformed("an identity key"))?,
    );
    for case in list_of(doc, "negative")? {
        let outcome = handshake::respond(
            &b,
            &keys,
            &mut NonceCache::new(),
            &bytes_of(case, "hello")?,
            uint_of(case, "now")?,
            Padding::Off,
        );
        ensure(outcome.is_err(), "a negative hello was accepted")?;
    }
    Ok(())
}

// ---- pairing ----

fn pairing_doc() -> Result<Json> {
    seeded("federation-pairing", || {
        let code = "ABCDEFGHJKMN";
        let sid: [u8; 16] = counting(0x10);
        let ad_a = [1u8; 16];
        let ad_b = [2u8; 16];
        let draw_a: [u8; 64] = counting(0x20);
        let draw_b: [u8; 64] = counting(0x60);
        let trace = pairing::cpace_exchange(
            code.as_bytes(),
            &sid,
            &ad_a,
            &ad_b,
            &mut Scripted::new(&draw_a),
            &mut Scripted::new(&draw_b),
        )?;
        let responder = party(2, &Suite::IMPLEMENTED)?;
        let initiator = party(1, &Suite::IMPLEMENTED)?;
        let (responder_key, initiator_key) = pairing::directional_keys(&trace.isk_initiator, &sid);
        let aad = pairing::binding(
            &sid,
            &trace.ya,
            &trace.yb,
            initiator.identity.server,
            responder.identity.server,
        );
        let nonce_r: [u8; 12] = counting(0x90);
        let nonce_i: [u8; 12] = counting(0xa0);
        let sealed_r = pairing::seal_with_nonce(
            &responder_key,
            &nonce_r,
            &aad,
            &responder.identity.descriptor.to_bytes(),
        )?;
        let sealed_i = pairing::seal_with_nonce(
            &initiator_key,
            &nonce_i,
            &aad,
            &initiator.identity.descriptor.to_bytes(),
        )?;
        let cpace = json!({
            "name": "cpace-ristretto255-sha512",
            "password": code,
            "channel_id": hx(pairing::CHANNEL_ID),
            "sid": hx(&sid),
            "ad_initiator": hx(&ad_a),
            "ad_responder": hx(&ad_b),
            "draw_initiator": hx(&draw_a),
            "draw_responder": hx(&draw_b),
            "ya": hx(&trace.ya),
            "yb": hx(&trace.yb),
            "isk": hx(&trace.isk_initiator),
            "session_id_output": hx(&trace.session_id_initiator),
            "responder_key": hx(&*responder_key),
            "initiator_key": hx(&*initiator_key),
            "binding": hx(&aad),
            "initiator": {
                "server_id": hx(initiator.identity.server.as_bytes()),
                "descriptor": hx(&initiator.identity.descriptor.to_bytes()),
                "nonce": hx(&nonce_i),
                "sealed_descriptor": hx(&sealed_i),
            },
            "responder": {
                "server_id": hx(responder.identity.server.as_bytes()),
                "descriptor": hx(&responder.identity.descriptor.to_bytes()),
                "nonce": hx(&nonce_r),
                "sealed_descriptor": hx(&sealed_r),
            },
        });
        let fingerprint = Fingerprint::of(
            (initiator.identity.server, &initiator.identity.public),
            (responder.identity.server, &responder.identity.public),
        );
        let swapped = Fingerprint::of(
            (responder.identity.server, &responder.identity.public),
            (initiator.identity.server, &initiator.identity.public),
        );
        let proquints: Vec<Json> = [
            (0x7f00u16, "lusab"),
            (0x0001, "babad"),
            (0x3f54, "gutih"),
            (0xdcc1, "tugad"),
            (0x0000, "babab"),
            (0xffff, "zuzuz"),
        ]
        .iter()
        .map(|(n, word)| json!({"value": n, "word": word}))
        .collect();
        let codes: Vec<Json> = [
            ("abcd-efgh-jkmn", Some("ABCD-EFGH-JKMN")),
            ("ABCD EFGH JKMN", Some("ABCD-EFGH-JKMN")),
            ("oil0-0000-0000", Some("0110-0000-0000")),
            ("ABCD-EFGH-JKM", None),
            ("ABCU-EFGH-JKMN", None),
            ("ABCD-EFGH-JKMNN", None),
        ]
        .iter()
        .map(|(input, normalized)| json!({"input": input, "normalized": normalized}))
        .collect();
        Ok(document(
            "federation-pairing",
            "Pairing: CPace (draft-irtf-cfrg-cpace, ristretto255 + SHA-512, initiator-responder \
             mode) with the one-time code as the password, the keys and binding that seal each \
             server's descriptor, the six-proquint fingerprint, and the code's normal form. \
             `draw_*` are the 64 bytes each side's scalar is reduced from.",
            vec![cpace],
            vec![
                (
                    "fingerprint",
                    json!({
                        "initiator_server_id": hx(initiator.identity.server.as_bytes()),
                        "initiator_identity_key": hx(initiator.identity.public.as_bytes()),
                        "responder_server_id": hx(responder.identity.server.as_bytes()),
                        "responder_identity_key": hx(responder.identity.public.as_bytes()),
                        "words": fingerprint.to_string(),
                        "words_swapped": swapped.to_string(),
                    }),
                ),
                ("proquints", Json::Array(proquints)),
                ("codes", Json::Array(codes)),
            ],
        ))
    })
}

fn check_pairing(doc: &Json) -> Result<()> {
    for case in list_of(doc, "cases")? {
        let sid = array_of::<16>(case, "sid")?;
        let prs = text_of(case, "password")?.as_bytes().to_vec();
        ensure(
            bytes_of(case, "channel_id")? == pairing::CHANNEL_ID,
            "channel id",
        )?;
        let trace = pairing::cpace_exchange(
            &prs,
            &sid,
            &bytes_of(case, "ad_initiator")?,
            &bytes_of(case, "ad_responder")?,
            &mut Scripted::new(&bytes_of(case, "draw_initiator")?),
            &mut Scripted::new(&bytes_of(case, "draw_responder")?),
        )?;
        ensure(trace.ya == bytes_of(case, "ya")?, "ya")?;
        ensure(trace.yb == bytes_of(case, "yb")?, "yb")?;
        ensure(
            trace.isk_initiator == bytes_of(case, "isk")?,
            "initiator isk",
        )?;
        ensure(
            trace.isk_responder == bytes_of(case, "isk")?,
            "responder isk",
        )?;
        ensure(
            trace.session_id_initiator == bytes_of(case, "session_id_output")?,
            "session id",
        )?;

        let initiator = field(case, "initiator")?;
        let responder = field(case, "responder")?;
        let initiator_id = server_id(array_of::<16>(initiator, "server_id")?);
        let responder_id = server_id(array_of::<16>(responder, "server_id")?);
        let (responder_key, initiator_key) = pairing::directional_keys(&trace.isk_initiator, &sid);
        ensure(
            responder_key[..] == bytes_of(case, "responder_key")?[..],
            "responder key",
        )?;
        ensure(
            initiator_key[..] == bytes_of(case, "initiator_key")?[..],
            "initiator key",
        )?;
        let aad = pairing::binding(&sid, &trace.ya, &trace.yb, initiator_id, responder_id);
        ensure(aad == bytes_of(case, "binding")?, "binding")?;
        for (side, key) in [(initiator, &initiator_key), (responder, &responder_key)] {
            let sealed = pairing::seal_with_nonce(
                key,
                &array_of::<12>(side, "nonce")?,
                &aad,
                &bytes_of(side, "descriptor")?,
            )?;
            ensure(
                sealed == bytes_of(side, "sealed_descriptor")?,
                "a sealed descriptor",
            )?;
        }
    }

    let fp = field(doc, "fingerprint")?;
    let a = (
        server_id(array_of::<16>(fp, "initiator_server_id")?),
        sig1::PublicKey::from_bytes(&bytes_of(fp, "initiator_identity_key")?)
            .map_err(|_| FedError::Malformed("an identity key"))?,
    );
    let b = (
        server_id(array_of::<16>(fp, "responder_server_id")?),
        sig1::PublicKey::from_bytes(&bytes_of(fp, "responder_identity_key")?)
            .map_err(|_| FedError::Malformed("an identity key"))?,
    );
    ensure(
        Fingerprint::of((a.0, &a.1), (b.0, &b.1)).to_string() == text_of(fp, "words")?,
        "fingerprint",
    )?;
    ensure(
        Fingerprint::of((b.0, &b.1), (a.0, &a.1)).to_string() == text_of(fp, "words_swapped")?,
        "swapped fingerprint",
    )?;
    ensure(
        text_of(fp, "words")? == text_of(fp, "words_swapped")?,
        "fingerprint symmetry",
    )?;

    for entry in list_of(doc, "proquints")? {
        let value = u16::try_from(uint_of(entry, "value")?)
            .map_err(|_| FedError::Malformed("a proquint value"))?;
        ensure(
            pairing::proquint(value) == text_of(entry, "word")?,
            "a proquint",
        )?;
    }
    for entry in list_of(doc, "codes")? {
        let parsed = PairingCode::parse(text_of(entry, "input")?);
        match field(entry, "normalized")?.as_str() {
            Some(expected) => ensure(
                parsed.ok().map(|c| c.display()).as_deref() == Some(expected),
                "a code's normal form",
            )?,
            None => ensure(parsed.is_err(), "a bad code was accepted")?,
        }
    }
    Ok(())
}

// ---- change records, promotion, home records ----

fn record_json(r: &ChangeRecord) -> Json {
    json!({
        "origin": hx(r.change.origin.as_bytes()),
        "seq": r.change.seq,
        "hlc": r.change.hlc.0,
        "item_id": hx(r.item.as_bytes()),
        "owner": hx(&r.owner.to_bytes()),
        "kind": r.kind.as_str(),
        "format": r.format.as_str(),
        "revision": r.revision.0,
        "key_version": r.key_version,
        "ciphertext": r.ciphertext.as_deref().map(hx),
        "item_key": r.item_key.as_deref().map(hx),
        "deleted": r.deleted,
        "updated_at_ms": r.updated_at_ms,
        "lineage": r.lineage.iter().map(|k| hx(&k.to_bytes())).collect::<Vec<Json>>(),
        "writer_signature": r.write.as_ref().map(|w| hx(&w.to_stored())),
    })
}

fn record_from_json(v: &Json) -> Result<ChangeRecord> {
    let optional = |key: &str| -> Result<Option<Vec<u8>>> {
        match field(v, key)? {
            Json::Null => Ok(None),
            other => unhex(other).map(Some),
        }
    };
    let lineage = list_of(v, "lineage")?
        .iter()
        .map(|k| unhex(k).and_then(|b| ChangeKey::from_bytes(&b)))
        .collect::<Result<Vec<ChangeKey>>>()?;
    let format = match text_of(v, "format")? {
        "kem1" => ItemFormat::Kem1,
        "bw" => ItemFormat::Bw,
        _ => return Err(FedError::Malformed("an item format")),
    };
    let write = match v.get("writer_signature") {
        None | Some(Json::Null) => None,
        Some(other) => Some(
            WriteSignature::from_stored(&unhex(other)?)
                .ok_or(FedError::Malformed("a writer signature"))?,
        ),
    };
    Ok(ChangeRecord {
        change: ChangeId {
            origin: server_id(array_of::<16>(v, "origin")?),
            seq: uint_of(v, "seq")?,
            hlc: Hlc(uint_of(v, "hlc")?),
        },
        item: crate::wire::item_id(array_of::<16>(v, "item_id")?),
        owner: owner(array_of::<17>(v, "owner")?)?,
        kind: ItemKind::try_from(text_of(v, "kind")?.to_owned())
            .map_err(|_| FedError::Malformed("an item kind"))?,
        format,
        revision: Revision(uint_of(v, "revision")?),
        key_version: u32::try_from(uint_of(v, "key_version")?)
            .map_err(|_| FedError::Malformed("a key version"))?,
        ciphertext: optional("ciphertext")?,
        item_key: optional("item_key")?,
        deleted: flag_of(v, "deleted")?,
        updated_at_ms: uint_of(v, "updated_at_ms")?,
        lineage,
        write,
    })
}

fn change_doc() -> Result<Json> {
    seeded("federation-change", || {
        let origin = server_id([0x11; 16]);
        let other = server_id([0x12; 16]);
        let signing_seed: [u8; 64] = counting(0x50);
        let signing = sig1::SigningKey::from_bytes(&signing_seed);
        let live = ChangeRecord {
            change: ChangeId {
                origin,
                seq: 7,
                hlc: Hlc::from_parts(1_800_000_000_123, 5),
            },
            item: item_id([0x21; 16]),
            owner: Owner::User(kemlock_domain::UserId(uuid::Uuid::from_bytes([0x31; 16]))),
            kind: ItemKind::try_from("login".to_owned()).map_err(|_| FedError::Crypto)?,
            format: ItemFormat::Kem1,
            revision: Revision(3),
            key_version: 1,
            ciphertext: Some(counting::<40>(0x60).to_vec()),
            item_key: Some(counting::<60>(0x70).to_vec()),
            deleted: false,
            updated_at_ms: 1_800_000_000_123,
            lineage: vec![
                ChangeKey { origin, seq: 6 },
                ChangeKey {
                    origin: other,
                    seq: 3,
                },
            ],
            write: None,
        };
        let tombstone = ChangeRecord {
            change: ChangeId {
                origin,
                seq: 9,
                hlc: Hlc::from_parts(1_800_000_000_456, 0),
            },
            revision: Revision(4),
            ciphertext: None,
            item_key: None,
            deleted: true,
            updated_at_ms: 1_800_000_000_456,
            lineage: vec![ChangeKey { origin, seq: 7 }],
            ..live.clone()
        };
        let bitwarden = ChangeRecord {
            change: ChangeId {
                origin,
                seq: 10,
                hlc: Hlc::from_parts(1_800_000_000_789, 1),
            },
            format: ItemFormat::Bw,
            owner: Owner::Space(kemlock_domain::SpaceId(uuid::Uuid::from_bytes([0x32; 16]))),
            lineage: Vec::new(),
            ..live.clone()
        };
        // A write that carries its writing account's signature too: the origin's signature covers
        // the field, and the writer's covers the statement of docs/crypto.md, "Signed item writes".
        let writer_seed: [u8; 64] = counting(0xe0);
        let writer_key = sig1::SigningKey::from_bytes(&writer_seed);
        let writer = kemlock_domain::UserId(uuid::Uuid::from_bytes([0x31; 16]));
        let mut written = ChangeRecord {
            change: ChangeId {
                origin,
                seq: 11,
                hlc: Hlc::from_parts(1_800_000_000_900, 0),
            },
            write: Some(WriteSignature {
                writer,
                key_version: 2,
                signature: vec![0; WriteSignature::SIGNATURE_LEN],
            }),
            ..live.clone()
        };
        let writer_statement = crate::writes::statement_of(&written)
            .ok_or(FedError::Crypto)?
            .to_bytes()
            .map_err(|_| FedError::Crypto)?;
        let writer_signature = writer_key
            .sign("item-write", &writer_statement)
            .map_err(|_| FedError::Crypto)?;
        written.write = Some(WriteSignature {
            writer,
            key_version: 2,
            signature: writer_signature,
        });
        let writer_public = crypto::sign_public(&writer_key)?;
        let mut cases = Vec::new();
        for (name, record) in [
            ("live-item-with-lineage", &live),
            ("tombstone", &tombstone),
            ("bitwarden-item-in-a-space-without-lineage", &bitwarden),
            ("live-item-signed-by-its-writer", &written),
        ] {
            let signed = record.sign(&signing)?;
            let mut case = record_json(record);
            if let Some(map) = case.as_object_mut() {
                map.insert("name".to_owned(), json!(name));
                map.insert("signing_seed".to_owned(), hx(&signing_seed));
                map.insert("body".to_owned(), hx(&signed.body));
                map.insert("signature".to_owned(), hx(&signed.signature));
                map.insert("envelope".to_owned(), hx(&signed.encode()));
                if record.write.is_some() {
                    map.insert("writer_signing_seed".to_owned(), hx(&writer_seed));
                    map.insert(
                        "writer_public_key".to_owned(),
                        hx(writer_public.as_bytes()),
                    );
                    map.insert("writer_statement".to_owned(), hx(&writer_statement));
                }
            }
            cases.push(case);
        }

        // A relay that changes a record, keeping the origin's signature, or invents one.
        let good = live.sign(&signing)?;
        let mut altered = live.clone();
        altered.ciphertext = Some(vec![0; 40]);
        let altered = Signed {
            body: altered.to_body(),
            signature: good.signature.clone(),
        };
        let relay = sig1::SigningKey::from_bytes(&counting::<64>(0x90));
        let invented = live.sign(&relay)?;
        let negative = vec![
            json!({"name": "ciphertext-changed-by-a-relay", "envelope": hx(&altered.encode())}),
            json!({"name": "signed-by-another-key", "envelope": hx(&invented.encode())}),
        ];

        // A vault with three servers; the third is promoted.
        let seeds: Vec<[u8; 64]> = (0..3u8).map(|i| counting(0xc0 + 16 * i)).collect();
        let ids: Vec<ServerId> = (0..3u8).map(|i| server_id([0xa1 + i; 16])).collect();
        let vault_owner = Owner::Space(kemlock_domain::SpaceId(uuid::Uuid::from_bytes([0x41; 16])));
        let vault = VaultFederation::federated(vault_owner, ids[0], vec![ids[1], ids[2]]);
        let promotion = PromotionRecord::build(&vault, ids[2], NOW)?;
        let promoted = promotion.sign(&sig1::SigningKey::from_bytes(&seeds[2]))?;
        let after = crate::home::apply_promotion(&vault, &promotion)?;
        let home_record = HomeRecord {
            vault: vault_owner,
            index: 1,
            epoch: 1,
            kind: "member-added".to_owned(),
            payload: counting::<24>(0x10).to_vec(),
            signer: ids[0],
        };
        let home_signed = home_record.sign(&sig1::SigningKey::from_bytes(&seeds[0]))?;
        let verdicts: Vec<Json> = [(1u64, 1u64, 0usize), (2, 1, 0), (1, 2, 1), (2, 2, 1)]
            .iter()
            .map(|(vault_epoch, record_epoch, signer)| {
                let mut current = vault.clone();
                current.epoch = *vault_epoch;
                let record = HomeRecord {
                    epoch: *record_epoch,
                    signer: ids[*signer],
                    ..home_record.clone()
                };
                let verdict = match crate::home::judge(&current, &record) {
                    Ok(Verdict::Apply) => "apply",
                    Ok(Verdict::Quarantine) => "quarantine",
                    Ok(Verdict::Behind) => "behind",
                    Err(_) => "refuse",
                };
                json!({
                    "vault_epoch": vault_epoch,
                    "record_epoch": record_epoch,
                    "signer": hx(ids[*signer].as_bytes()),
                    "verdict": verdict,
                })
            })
            .collect();
        let mut servers_json: Vec<Json> = Vec::new();
        for (id, seed) in ids.iter().zip(&seeds) {
            servers_json.push(json!({"server_id": hx(id.as_bytes()), "signing_seed": hx(seed)}));
        }
        let replicas_json: Vec<Json> = promotion
            .replicas
            .iter()
            .map(|r| hx(r.as_bytes()))
            .collect();
        let order_json: Vec<Json> = after.order().iter().map(|r| hx(r.as_bytes())).collect();
        let home = json!({
            "servers": servers_json,
            "vault": hx(&vault_owner.to_bytes()),
            "promotion": {
                "epoch": promotion.epoch,
                "new_home": hx(promotion.new_home.as_bytes()),
                "previous_home": hx(promotion.previous_home.as_bytes()),
                "issued_at": promotion.issued_at,
                "replicas": replicas_json,
                "body": hx(&promoted.body),
                "signature": hx(&promoted.signature),
                "envelope": hx(&promoted.encode()),
                "order_after": order_json,
            },
            "home_record": {
                "index": home_record.index,
                "epoch": home_record.epoch,
                "kind": home_record.kind,
                "payload": hx(&home_record.payload),
                "signer": hx(home_record.signer.as_bytes()),
                "body": hx(&home_signed.body),
                "signature": hx(&home_signed.signature),
                "envelope": hx(&home_signed.encode()),
            },
            "verdicts": verdicts,
        });
        Ok(document(
            "federation-change",
            "Origin-signed change records (sig1, context federation-change), a promotion record \
             (context federation-promotion) and a home record (context federation-home-record). \
             Negative envelopes must fail to open under the key of the record's origin.",
            cases,
            vec![("negative", Json::Array(negative)), ("home", home)],
        ))
    })
}

fn check_change(doc: &Json) -> Result<()> {
    for case in list_of(doc, "cases")? {
        let record = record_from_json(case)?;
        let signing = sig1::SigningKey::from_bytes(&array_of::<64>(case, "signing_seed")?);
        ensure(record.to_body() == bytes_of(case, "body")?, "record body")?;
        let signed = record.sign(&signing)?;
        ensure_resigned(
            signed.signature == bytes_of(case, "signature")?,
            "record signature",
        )?;
        ensure_resigned(
            signed.encode() == bytes_of(case, "envelope")?,
            "record envelope",
        )?;
        let keys: HashMap<ServerId, sig1::PublicKey> =
            [(record.change.origin, crypto::sign_public(&signing)?)]
                .into_iter()
                .collect();
        ensure(
            change::open(&bytes_of(case, "envelope")?, &keys)? == record,
            "record opens",
        )?;
        // A writer's signature verifies over the statement rebuilt from the record, and over no
        // other.
        if record.write.is_some() {
            let statement = crate::writes::statement_of(&record)
                .ok_or(FedError::Malformed("a writer statement"))?;
            ensure(
                statement.to_bytes().map_err(|_| FedError::Crypto)?
                    == bytes_of(case, "writer_statement")?,
                "writer statement",
            )?;
            let writer_public = sig1::PublicKey::from_bytes(&bytes_of(case, "writer_public_key")?)
                .map_err(|_| FedError::Crypto)?;
            let signature = record
                .write
                .as_ref()
                .map(|w| w.signature.clone())
                .unwrap_or_default();
            ensure(
                statement.verify(&writer_public, &signature).is_ok(),
                "writer signature",
            )?;
            let mut changed = record.clone();
            changed.revision = Revision(record.revision.0 + 1);
            let other = crate::writes::statement_of(&changed)
                .ok_or(FedError::Malformed("a writer statement"))?;
            ensure(
                other.verify(&writer_public, &signature).is_err(),
                "a writer signature over another revision",
            )?;
        }
        // The tombstone's item survives the round trip through a stored item.
        let item = record.to_item()?;
        ensure(
            ChangeRecord::from_item(&item, record.lineage.clone()) == record,
            "item round trip",
        )?;
    }
    let first = list_of(doc, "cases")?
        .first()
        .ok_or(FedError::Malformed("no cases"))?;
    let record = record_from_json(first)?;
    let signing = sig1::SigningKey::from_bytes(&array_of::<64>(first, "signing_seed")?);
    let keys: HashMap<ServerId, sig1::PublicKey> =
        [(record.change.origin, crypto::sign_public(&signing)?)]
            .into_iter()
            .collect();
    for case in list_of(doc, "negative")? {
        ensure(
            change::open(&bytes_of(case, "envelope")?, &keys).is_err(),
            "a negative record was accepted",
        )?;
    }

    let home = field(doc, "home")?;
    let servers = list_of(home, "servers")?;
    let mut ids = Vec::new();
    let mut signing = Vec::new();
    let mut directory: HashMap<ServerId, sig1::PublicKey> = HashMap::new();
    for s in servers {
        let id = server_id(array_of::<16>(s, "server_id")?);
        let key = sig1::SigningKey::from_bytes(&array_of::<64>(s, "signing_seed")?);
        directory.insert(id, crypto::sign_public(&key)?);
        ids.push(id);
        signing.push(key);
    }
    let vault_owner = owner(array_of::<17>(home, "vault")?)?;
    let vault = VaultFederation::federated(vault_owner, ids[0], vec![ids[1], ids[2]]);
    let promo = field(home, "promotion")?;
    let envelope = bytes_of(promo, "envelope")?;
    let opened = crate::home::open_promotion(&envelope, &directory)?;
    ensure(opened.epoch == uint_of(promo, "epoch")?, "promotion epoch")?;
    ensure(
        opened.new_home == ids[2] && opened.previous_home == ids[0],
        "promotion servers",
    )?;
    let rebuilt = PromotionRecord::build(&vault, ids[2], uint_of(promo, "issued_at")?)?;
    ensure(rebuilt == opened, "promotion rebuilt")?;
    ensure(
        rebuilt.to_body() == bytes_of(promo, "body")?,
        "promotion body",
    )?;
    ensure_resigned(
        rebuilt.sign(&signing[2])?.signature == bytes_of(promo, "signature")?,
        "promotion signature",
    )?;
    let after = crate::home::apply_promotion(&vault, &opened)?;
    let order: Vec<Vec<u8>> = after
        .order()
        .iter()
        .map(|i| i.as_bytes().to_vec())
        .collect();
    let expected: Vec<Vec<u8>> = list_of(promo, "order_after")?
        .iter()
        .map(unhex)
        .collect::<Result<Vec<_>>>()?;
    ensure(order == expected, "order after promotion")?;

    let record = field(home, "home_record")?;
    let envelope = bytes_of(record, "envelope")?;
    let opened = crate::home::open_home_record(&envelope, &directory)?;
    ensure(
        opened.index == uint_of(record, "index")?,
        "home record index",
    )?;
    ensure(
        opened.to_body() == bytes_of(record, "body")?,
        "home record body",
    )?;
    ensure_resigned(
        opened.sign(&signing[0])?.signature == bytes_of(record, "signature")?,
        "home record signature",
    )?;
    for entry in list_of(home, "verdicts")? {
        let mut current = vault.clone();
        current.epoch = uint_of(entry, "vault_epoch")?;
        let signer = server_id(array_of::<16>(entry, "signer")?);
        let candidate = HomeRecord {
            epoch: uint_of(entry, "record_epoch")?,
            signer,
            ..opened.clone()
        };
        let verdict = match crate::home::judge(&current, &candidate) {
            Ok(Verdict::Apply) => "apply",
            Ok(Verdict::Quarantine) => "quarantine",
            Ok(Verdict::Behind) => "behind",
            Err(_) => "refuse",
        };
        ensure(verdict == text_of(entry, "verdict")?, "a home verdict")?;
    }
    Ok(())
}

// ---- hash tree ----

fn hashtree_doc() -> Result<Json> {
    seeded("federation-hashtree", || {
        let origin_a = server_id([1; 16]);
        let origin_b = server_id([2; 16]);
        let items: Vec<(ItemIdBytes, Vec<(ChangeKey, u64)>)> = vec![
            (
                id_bytes(0x00, 1),
                vec![(
                    ChangeKey {
                        origin: origin_a,
                        seq: 1,
                    },
                    1,
                )],
            ),
            (
                id_bytes(0x00, 2),
                vec![
                    (
                        ChangeKey {
                            origin: origin_a,
                            seq: 5,
                        },
                        2,
                    ),
                    (
                        ChangeKey {
                            origin: origin_b,
                            seq: 3,
                        },
                        2,
                    ),
                ],
            ),
            (
                id_bytes(0x7f, 3),
                vec![(
                    ChangeKey {
                        origin: origin_b,
                        seq: 9,
                    },
                    4,
                )],
            ),
            (
                id_bytes(0xff, 4),
                vec![(
                    ChangeKey {
                        origin: origin_a,
                        seq: 12,
                    },
                    1,
                )],
            ),
        ];
        let mut leaves = Vec::new();
        let mut leaf_json = Vec::new();
        for (id, versions) in &items {
            let item = item_id(*id);
            let typed: Vec<(ChangeKey, Revision)> =
                versions.iter().map(|(k, r)| (*k, Revision(*r))).collect();
            let digest = hashtree::leaf_digest(item, &typed);
            leaves.push(Leaf { item, digest });
            let versions_json: Vec<Json> = versions
                .iter()
                .map(|(k, r)| json!({"change": hx(&k.to_bytes()), "revision": r}))
                .collect();
            leaf_json.push(json!({
                "item_id": hx(id),
                "versions": versions_json,
                "digest": hx(&digest),
            }));
        }
        let tree = Tree::build(&leaves);
        let mut buckets = serde_json::Map::new();
        for leaf in &leaves {
            let index = usize::from(hashtree::bucket_of(leaf.item));
            buckets.insert(index.to_string(), hx(&tree.buckets[index]));
        }
        let empty = Tree::build(&[]);
        let case = json!({
            "name": "four-items-in-three-buckets",
            "leaves": leaf_json,
            "bucket_digests": buckets,
            "root": hx(&tree.root),
            "empty_root": hx(&empty.root),
        });
        Ok(document(
            "federation-hashtree",
            "Hash-tree summaries: a leaf per item over the versions held, 256 buckets keyed by \
             the item id's first byte, and a root. Only the buckets that hold leaves are listed; \
             an empty bucket's digest is SHA-256(label || u8(index)), and the root hashes all 256.",
            vec![case],
            Vec::new(),
        ))
    })
}

type ItemIdBytes = [u8; 16];

fn id_bytes(first: u8, rest: u8) -> ItemIdBytes {
    let mut b = [rest; 16];
    b[0] = first;
    b
}

fn check_hashtree(doc: &Json) -> Result<()> {
    for case in list_of(doc, "cases")? {
        let mut leaves = Vec::new();
        for leaf in list_of(case, "leaves")? {
            let item = item_id(array_of::<16>(leaf, "item_id")?);
            let versions = list_of(leaf, "versions")?
                .iter()
                .map(|v| -> Result<(ChangeKey, Revision)> {
                    Ok((
                        ChangeKey::from_bytes(&bytes_of(v, "change")?)?,
                        Revision(uint_of(v, "revision")?),
                    ))
                })
                .collect::<Result<Vec<_>>>()?;
            let digest = hashtree::leaf_digest(item, &versions);
            ensure(digest == array_of::<32>(leaf, "digest")?, "a leaf digest")?;
            leaves.push(Leaf { item, digest });
        }
        let tree = Tree::build(&leaves);
        ensure(tree.root == array_of::<32>(case, "root")?, "the root")?;
        ensure(
            Tree::build(&[]).root == array_of::<32>(case, "empty_root")?,
            "the empty root",
        )?;
        let listed = field(case, "bucket_digests")?
            .as_object()
            .ok_or(FedError::Malformed("bucket digests"))?;
        for (index, digest) in listed {
            let index: usize = index
                .parse()
                .map_err(|_| FedError::Malformed("a bucket index"))?;
            ensure(
                tree.buckets.get(index).map(|d| d[..].to_vec()) == Some(unhex(digest)?),
                "a bucket digest",
            )?;
        }
    }
    Ok(())
}

// ---- all ----

/// Every file, in the order of [`FILES`].
pub fn all() -> Result<Vec<(&'static str, Json)>> {
    Ok(vec![
        ("federation-descriptor", descriptor_doc()?),
        ("federation-handshake", handshake_doc()?),
        ("federation-frames", frames_doc()?),
        ("federation-pairing", pairing_doc()?),
        ("federation-change", change_doc()?),
        ("federation-hashtree", hashtree_doc()?),
    ])
}

/// Rebuilds every value of a file from the inputs it lists and compares.
pub fn check(name: &str, doc: &Json) -> Result<()> {
    match name {
        "federation-descriptor" => check_descriptor(doc),
        "federation-handshake" => check_handshake(doc),
        "federation-frames" => check_frames(doc),
        "federation-pairing" => check_pairing(doc),
        "federation-change" => check_change(doc),
        "federation-hashtree" => check_hashtree(doc),
        _ => Err(FedError::Malformed("an unknown vector file")),
    }
}

/// A file's text: pretty-printed JSON with a final newline.
pub fn render(doc: &Json) -> Result<String> {
    let mut text = serde_json::to_string_pretty(doc)
        .map_err(|_| FedError::Malformed("a vector document does not render"))?;
    text.push('\n');
    Ok(text)
}

/// Writes every file and `federation-SHA256SUMS` into `out`, creating it if needed.
pub fn write_all(out: &std::path::Path) -> std::result::Result<(), String> {
    use std::fmt::Write as _;
    let docs = all().map_err(|e| format!("generating the vectors failed: {e}"))?;
    std::fs::create_dir_all(out).map_err(|e| format!("{}: {e}", out.display()))?;
    let mut sums = String::new();
    for (name, doc) in &docs {
        let text = render(doc).map_err(|e| format!("{name}: {e}"))?;
        let file = format!("{name}.json");
        std::fs::write(out.join(&file), &text).map_err(|e| format!("{file}: {e}"))?;
        let digest = crypto::sha256(text.as_bytes());
        writeln!(sums, "{}  {file}", hex::encode(digest)).map_err(|e| e.to_string())?;
    }
    std::fs::write(out.join("federation-SHA256SUMS"), sums)
        .map_err(|e| format!("federation-SHA256SUMS: {e}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_generated_file_checks_out() {
        let docs = all().expect("generate");
        assert_eq!(docs.len(), FILES.len());
        for (name, doc) in &docs {
            assert_eq!(doc["format"], *name);
            assert_eq!(doc["version"], VERSION);
            check(name, doc).unwrap_or_else(|e| panic!("{name}: {e}"));
        }
    }

    #[test]
    fn files_are_listed_in_order() {
        let names: Vec<&str> = all().expect("generate").iter().map(|(n, _)| *n).collect();
        assert_eq!(names, FILES);
    }

    #[test]
    fn a_changed_vector_fails_its_check() {
        let docs = all().expect("generate");
        let (name, mut doc) = docs
            .into_iter()
            .find(|(n, _)| *n == "federation-descriptor")
            .expect("the descriptor file");
        let body = doc["cases"][0]["body"].as_str().expect("hex").to_owned();
        let mut changed = body.into_bytes();
        changed[10] = if changed[10] == b'0' { b'1' } else { b'0' };
        doc["cases"][0]["body"] = Json::String(String::from_utf8(changed).expect("ascii"));
        assert!(check(name, &doc).is_err());
    }

    /// With the `vectors` feature the output is reproducible, so a committed file must be what
    /// the generator writes now. Without the files (a checkout that never generated them) the
    /// test says so and passes.
    #[cfg(feature = "vectors")]
    #[test]
    fn committed_files_are_current() {
        let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../test-vectors");
        for (name, doc) in all().expect("generate") {
            let path = dir.join(format!("{name}.json"));
            match std::fs::read_to_string(&path) {
                Ok(committed) => assert_eq!(committed, render(&doc).expect("render"), "{name}"),
                Err(_) => eprintln!("{} is not committed yet; skipping", path.display()),
            }
        }
    }
}
