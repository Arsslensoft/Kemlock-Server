//! Sealed frames: the records of an established peer session.
//!
//! ```text
//! frame  = header (29) ‖ AEAD(key, nonce, padded payload, aad = "kemlock/v1/fed/frame" ‖ header)
//! header = session id (16) ‖ u32be(epoch) ‖ u64be(counter) ‖ u8(flags)
//! nonce  = iv XOR (0 (4) ‖ u64be(counter))
//! ```
//!
//! Each direction has its own key, IV and counter. The counter starts at 0 and counts every
//! frame of that direction, across rekeys; a reader accepts only the next one, so a repeated,
//! dropped or reordered frame fails. Bit 0 of the flags marks the last frame, and a stream that
//! ends without it was cut short. The payload is padded to a multiple of 4096 bytes by default
//! (`payload ‖ 0x80 ‖ zeros`). A direction rekeys every hour or GiB by ratcheting its chain key
//! one way, so a later key does not open earlier frames.

use crate::crypto::{self, Aead, TAG_LEN};
use crate::error::{FedError, Result};
use zeroize::Zeroizing;

/// Session id, epoch, counter and flags.
pub const HEADER_LEN: usize = 16 + 4 + 8 + 1;
/// The padding step.
pub const PAD_STEP: usize = 4096;
/// The most a frame may carry.
pub const MAX_PAYLOAD: usize = 4 * 1024 * 1024;
/// A direction rekeys after this many seconds.
pub const REKEY_SECS: u64 = 3600;
/// A direction rekeys after this many bytes.
pub const REKEY_BYTES: u64 = 1 << 30;

const FLAG_LAST: u8 = 0x01;
const AAD_LABEL: &[u8] = b"kemlock/v1/fed/frame";

/// Whether frames are padded.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Padding {
    /// No padding beyond the one marker byte.
    Off,
    /// Padded to a multiple of 4096 bytes: the default.
    Step4096,
}

impl Padding {
    fn step(self) -> usize {
        match self {
            Padding::Off => 1,
            Padding::Step4096 => PAD_STEP,
        }
    }
}

/// Which way a stream runs.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Direction {
    InitiatorToResponder = 1,
    ResponderToInitiator = 2,
}

impl Direction {
    pub fn reverse(self) -> Direction {
        match self {
            Direction::InitiatorToResponder => Direction::ResponderToInitiator,
            Direction::ResponderToInitiator => Direction::InitiatorToResponder,
        }
    }
}

/// The chain key a direction starts from: `HKDF-Expand(prk, "kemlock/v1/fed/chain" ‖ u8(dir))`.
pub fn chain_key(prk: &[u8; 32], direction: Direction) -> Zeroizing<[u8; 32]> {
    let mut info = b"kemlock/v1/fed/chain".to_vec();
    info.push(direction as u8);
    crypto::hkdf_expand::<32>(prk, &info)
}

/// The frame key and IV of an epoch: `HKDF-Expand(chain, "kemlock/v1/fed/frame-key")` (32 bytes)
/// and `HKDF-Expand(chain, "kemlock/v1/fed/frame-iv")` (12 bytes).
pub fn epoch_material(chain: &[u8; 32]) -> (Zeroizing<[u8; 32]>, [u8; 12]) {
    let key = crypto::hkdf_expand::<32>(chain, b"kemlock/v1/fed/frame-key");
    let iv = *crypto::hkdf_expand::<12>(chain, b"kemlock/v1/fed/frame-iv");
    (key, iv)
}

/// The next epoch's chain key: `HKDF-Expand(chain, "kemlock/v1/fed/ratchet")`.
pub fn next_chain(chain: &[u8; 32]) -> Zeroizing<[u8; 32]> {
    crypto::hkdf_expand::<32>(chain, b"kemlock/v1/fed/ratchet")
}

/// The nonce of frame `counter`: the IV with the counter, big-endian, XORed into its last 8 bytes.
pub fn frame_nonce(iv: &[u8; 12], counter: u64) -> [u8; 12] {
    let mut nonce = *iv;
    for (i, byte) in counter.to_be_bytes().iter().enumerate() {
        nonce[4 + i] ^= byte;
    }
    nonce
}

/// The keys of one epoch of one direction.
struct Keys {
    aead: Aead,
    chain: Zeroizing<[u8; 32]>,
    key: Zeroizing<[u8; 32]>,
    iv: [u8; 12],
    epoch: u32,
}

impl Keys {
    fn new(aead: Aead, chain: Zeroizing<[u8; 32]>, epoch: u32) -> Keys {
        let (key, iv) = epoch_material(&chain);
        Keys {
            aead,
            chain,
            key,
            iv,
            epoch,
        }
    }

    fn next(&self) -> Keys {
        Keys::new(
            self.aead,
            next_chain(&self.chain),
            self.epoch.wrapping_add(1),
        )
    }

    fn nonce(&self, counter: u64) -> [u8; 12] {
        frame_nonce(&self.iv, counter)
    }
}

fn aad(header: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(AAD_LABEL.len() + header.len());
    out.extend_from_slice(AAD_LABEL);
    out.extend_from_slice(header);
    out
}

fn pad(payload: &[u8], step: usize) -> Zeroizing<Vec<u8>> {
    let total = (payload.len() + 1).div_ceil(step) * step;
    let mut out = Zeroizing::new(Vec::with_capacity(total));
    out.extend_from_slice(payload);
    out.push(0x80);
    out.resize(total, 0);
    out
}

fn unpad(padded: &[u8]) -> Result<&[u8]> {
    match padded.iter().rposition(|b| *b != 0) {
        Some(i) if padded[i] == 0x80 => Ok(&padded[..i]),
        _ => Err(FedError::Frame("the padding is not valid")),
    }
}

/// The sending half of one direction.
pub struct FrameWriter {
    session: [u8; 16],
    keys: Keys,
    counter: u64,
    epoch_bytes: u64,
    epoch_started: u64,
    padding: Padding,
    finished: bool,
}

impl std::fmt::Debug for FrameWriter {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FrameWriter")
            .field("counter", &self.counter)
            .field("epoch", &self.keys.epoch)
            .finish_non_exhaustive()
    }
}

impl FrameWriter {
    /// A writer for `direction` of a session whose master secret is `prk`, started at `now`.
    pub fn new(
        session: [u8; 16],
        aead: Aead,
        prk: &[u8; 32],
        direction: Direction,
        now: u64,
        padding: Padding,
    ) -> FrameWriter {
        FrameWriter {
            session,
            keys: Keys::new(aead, chain_key(prk, direction), 0),
            counter: 0,
            epoch_bytes: 0,
            epoch_started: now,
            padding,
            finished: false,
        }
    }

    /// Seals one frame at `now` (unix seconds, for the hourly rekey). `last` ends the stream.
    pub fn seal(&mut self, payload: &[u8], last: bool, now: u64) -> Result<Vec<u8>> {
        if self.finished {
            return Err(FedError::Frame("the stream has already ended"));
        }
        if payload.len() > MAX_PAYLOAD {
            return Err(FedError::Frame("the payload is too large"));
        }
        if self.counter == u64::MAX {
            return Err(FedError::Frame("the counter is exhausted"));
        }
        if now >= self.epoch_started.saturating_add(REKEY_SECS) || self.epoch_bytes >= REKEY_BYTES {
            self.keys = self.keys.next();
            self.epoch_bytes = 0;
            self.epoch_started = now;
        }
        let mut header = Vec::with_capacity(HEADER_LEN);
        header.extend_from_slice(&self.session);
        header.extend_from_slice(&self.keys.epoch.to_be_bytes());
        header.extend_from_slice(&self.counter.to_be_bytes());
        header.push(if last { FLAG_LAST } else { 0 });

        let padded = pad(payload, self.padding.step());
        let nonce = self.keys.nonce(self.counter);
        let sealed = self
            .keys
            .aead
            .seal(&self.keys.key, &nonce, &aad(&header), &padded)?;

        let mut frame = header;
        frame.extend_from_slice(&sealed);
        self.counter += 1;
        self.epoch_bytes += frame.len() as u64;
        self.finished = last;
        Ok(frame)
    }

    /// The epoch the next frame is sealed under.
    pub fn epoch(&self) -> u32 {
        self.keys.epoch
    }

    /// How many frames were sealed.
    pub fn counter(&self) -> u64 {
        self.counter
    }

    /// Pretends `bytes` more bytes went out in this epoch. For tests of the rekey limit.
    #[doc(hidden)]
    pub fn add_epoch_bytes(&mut self, bytes: u64) {
        self.epoch_bytes = self.epoch_bytes.saturating_add(bytes);
    }
}

/// What a reader got from one frame.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Opened {
    pub payload: Vec<u8>,
    /// The frame ended the stream.
    pub last: bool,
}

/// The receiving half of one direction.
pub struct FrameReader {
    session: [u8; 16],
    keys: Keys,
    expected: u64,
    finished: bool,
}

impl std::fmt::Debug for FrameReader {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FrameReader")
            .field("expected", &self.expected)
            .field("epoch", &self.keys.epoch)
            .finish_non_exhaustive()
    }
}

impl FrameReader {
    /// A reader for `direction` of a session whose master secret is `prk`.
    pub fn new(session: [u8; 16], aead: Aead, prk: &[u8; 32], direction: Direction) -> FrameReader {
        FrameReader {
            session,
            keys: Keys::new(aead, chain_key(prk, direction), 0),
            expected: 0,
            finished: false,
        }
    }

    /// Opens the next frame. Anything but the next frame of this session, unchanged, is an error:
    /// another session, a repeated, skipped or reordered counter, a changed byte, an epoch that
    /// isn't the current one or the next, or a frame after the last one.
    pub fn open(&mut self, frame: &[u8]) -> Result<Opened> {
        if self.finished {
            return Err(FedError::Frame("the stream has already ended"));
        }
        if frame.len() < HEADER_LEN + TAG_LEN {
            return Err(FedError::Frame("too short"));
        }
        if frame.len() > HEADER_LEN + MAX_PAYLOAD + PAD_STEP + TAG_LEN + 1 {
            return Err(FedError::Frame("too long"));
        }
        let (header, sealed) = frame.split_at(HEADER_LEN);
        if header[..16] != self.session {
            return Err(FedError::Frame("another session's frame"));
        }
        let mut epoch = [0u8; 4];
        epoch.copy_from_slice(&header[16..20]);
        let epoch = u32::from_be_bytes(epoch);
        let mut counter = [0u8; 8];
        counter.copy_from_slice(&header[20..28]);
        let counter = u64::from_be_bytes(counter);
        let flags = header[28];
        if flags & !FLAG_LAST != 0 {
            return Err(FedError::Frame("unknown flags"));
        }
        if counter != self.expected {
            return Err(FedError::Frame("repeated, dropped or reordered"));
        }
        let advance = if epoch == self.keys.epoch {
            None
        } else if self.keys.epoch.checked_add(1) == Some(epoch) {
            Some(self.keys.next())
        } else {
            return Err(FedError::Frame("unexpected epoch"));
        };
        let keys = advance.as_ref().unwrap_or(&self.keys);
        let padded = keys
            .aead
            .open(&keys.key, &keys.nonce(counter), &aad(header), sealed)?;
        let payload = unpad(&padded)?.to_vec();
        if payload.len() > MAX_PAYLOAD {
            return Err(FedError::Frame("the payload is too large"));
        }
        if let Some(next) = advance {
            self.keys = next;
        }
        self.expected += 1;
        let last = flags & FLAG_LAST != 0;
        self.finished = last;
        Ok(Opened { payload, last })
    }

    /// Ok only when the last frame was seen: a stream that ends without it was cut short.
    pub fn finish(&self) -> Result<()> {
        if self.finished {
            Ok(())
        } else {
            Err(FedError::Frame("the stream was cut short"))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SESSION: [u8; 16] = [9; 16];

    fn pair(aead: Aead, padding: Padding) -> (FrameWriter, FrameReader) {
        let prk = [5u8; 32];
        (
            FrameWriter::new(
                SESSION,
                aead,
                &prk,
                Direction::InitiatorToResponder,
                0,
                padding,
            ),
            FrameReader::new(SESSION, aead, &prk, Direction::InitiatorToResponder),
        )
    }

    #[test]
    fn frames_round_trip_in_order_with_both_aeads() {
        for aead in [Aead::Aes256Gcm, Aead::ChaCha20Poly1305] {
            let (mut w, mut r) = pair(aead, Padding::Step4096);
            let payloads: [&[u8]; 3] = [b"one", b"", b"three three"];
            for (i, payload) in payloads.iter().enumerate() {
                let frame = w.seal(payload, false, 0).expect("seal");
                let opened = r.open(&frame).expect("open");
                assert_eq!(opened.payload, *payload, "frame {i}");
                assert!(!opened.last);
            }
            let frame = w.seal(b"bye", true, 0).expect("seal");
            let opened = r.open(&frame).expect("open");
            assert!(opened.last);
            r.finish().expect("finished");
            assert!(w.seal(b"more", false, 0).is_err());
        }
    }

    #[test]
    fn frames_are_padded_to_4096_steps() {
        let (mut w, _) = pair(Aead::Aes256Gcm, Padding::Step4096);
        for len in [0usize, 1, 100, 4094, 4095, 4096, 5000] {
            let frame = w.seal(&vec![1; len], false, 0).expect("seal");
            let padded = (len + 1).div_ceil(PAD_STEP) * PAD_STEP;
            assert_eq!(frame.len(), HEADER_LEN + padded + TAG_LEN, "len {len}");
        }
        let (mut w, _) = pair(Aead::Aes256Gcm, Padding::Off);
        let frame = w.seal(&[1; 10], false, 0).expect("seal");
        assert_eq!(frame.len(), HEADER_LEN + 11 + TAG_LEN);
    }

    #[test]
    fn a_repeated_frame_fails() {
        let (mut w, mut r) = pair(Aead::Aes256Gcm, Padding::Off);
        let frame = w.seal(b"a", false, 0).expect("seal");
        r.open(&frame).expect("first");
        assert!(r.open(&frame).is_err());
    }

    #[test]
    fn a_dropped_frame_fails_the_next_one() {
        let (mut w, mut r) = pair(Aead::Aes256Gcm, Padding::Off);
        let _lost = w.seal(b"a", false, 0).expect("seal");
        let second = w.seal(b"b", false, 0).expect("seal");
        assert!(r.open(&second).is_err());
    }

    #[test]
    fn reordered_frames_fail() {
        let (mut w, mut r) = pair(Aead::Aes256Gcm, Padding::Off);
        let a = w.seal(b"a", false, 0).expect("seal");
        let b = w.seal(b"b", false, 0).expect("seal");
        assert!(r.open(&b).is_err());
        // The failed attempt didn't move the reader: the right order still works.
        r.open(&a).expect("a");
        r.open(&b).expect("b");
    }

    #[test]
    fn a_cut_short_stream_is_detected() {
        let (mut w, mut r) = pair(Aead::Aes256Gcm, Padding::Off);
        let a = w.seal(b"a", false, 0).expect("seal");
        r.open(&a).expect("a");
        assert!(r.finish().is_err());
        let last = w.seal(b"z", true, 0).expect("seal");
        // A truncated final frame doesn't open.
        assert!(r.open(&last[..last.len() - 1]).is_err());
        r.open(&last).expect("last");
        r.finish().expect("finished");
        // Nothing opens after the last frame.
        let (mut w2, _) = pair(Aead::Aes256Gcm, Padding::Off);
        let _ = w2.seal(b"x", false, 0).expect("seal");
        let after = w2.seal(b"y", false, 0).expect("seal");
        assert!(r.open(&after).is_err());
    }

    #[test]
    fn every_changed_byte_fails() {
        let (mut w, _) = pair(Aead::Aes256Gcm, Padding::Off);
        let frame = w.seal(b"payload", false, 0).expect("seal");
        for i in 0..frame.len() {
            let (_, mut r) = pair(Aead::Aes256Gcm, Padding::Off);
            let mut bad = frame.clone();
            bad[i] ^= 1;
            assert!(r.open(&bad).is_err(), "byte {i}");
        }
    }

    #[test]
    fn the_header_is_authenticated_not_just_checked() {
        // Flipping the last flag on a frame that was sealed without it fails the tag, so a
        // network attacker can't end a stream early.
        let (mut w, mut r) = pair(Aead::Aes256Gcm, Padding::Off);
        let mut frame = w.seal(b"x", false, 0).expect("seal");
        frame[HEADER_LEN - 1] = FLAG_LAST;
        assert!(r.open(&frame).is_err());
    }

    #[test]
    fn another_sessions_or_directions_frames_fail() {
        let prk = [5u8; 32];
        let mut w = FrameWriter::new(
            [1; 16],
            Aead::Aes256Gcm,
            &prk,
            Direction::InitiatorToResponder,
            0,
            Padding::Off,
        );
        let frame = w.seal(b"x", false, 0).expect("seal");
        let mut other_session = FrameReader::new(
            [2; 16],
            Aead::Aes256Gcm,
            &prk,
            Direction::InitiatorToResponder,
        );
        assert!(other_session.open(&frame).is_err());
        let mut other_direction = FrameReader::new(
            [1; 16],
            Aead::Aes256Gcm,
            &prk,
            Direction::ResponderToInitiator,
        );
        assert!(other_direction.open(&frame).is_err());
        let mut other_key = FrameReader::new(
            [1; 16],
            Aead::Aes256Gcm,
            &[6; 32],
            Direction::InitiatorToResponder,
        );
        assert!(other_key.open(&frame).is_err());
    }

    #[test]
    fn it_rekeys_every_hour_and_the_reader_follows() {
        let (mut w, mut r) = pair(Aead::ChaCha20Poly1305, Padding::Off);
        let a = w.seal(b"a", false, 10).expect("seal");
        assert_eq!(w.epoch(), 0);
        r.open(&a).expect("a");
        let b = w.seal(b"b", false, REKEY_SECS).expect("seal");
        assert_eq!(w.epoch(), 1);
        assert_eq!(r.open(&b).expect("b").payload, b"b");
        let c = w.seal(b"c", false, REKEY_SECS + 1).expect("seal");
        assert_eq!(w.epoch(), 1);
        r.open(&c).expect("c");
    }

    #[test]
    fn it_rekeys_after_a_gibibyte() {
        let (mut w, mut r) = pair(Aead::Aes256Gcm, Padding::Off);
        let a = w.seal(b"a", false, 0).expect("seal");
        r.open(&a).expect("a");
        w.add_epoch_bytes(REKEY_BYTES);
        let b = w.seal(b"b", false, 1).expect("seal");
        assert_eq!(w.epoch(), 1);
        r.open(&b).expect("b");
    }

    #[test]
    fn an_old_epoch_after_a_rekey_fails() {
        let (mut w, mut r) = pair(Aead::Aes256Gcm, Padding::Off);
        let a = w.seal(b"a", false, 0).expect("seal");
        let b = w.seal(b"b", false, REKEY_SECS).expect("seal");
        r.open(&a).expect("a");
        r.open(&b).expect("b");
        // The reader moved on; a frame of the old epoch with the next counter can't be forged
        // from the new keys, and the old frame itself is a repeat.
        assert!(r.open(&a).is_err());
    }

    #[test]
    fn a_reader_that_missed_frames_cannot_jump_epochs() {
        let (mut w, mut r) = pair(Aead::Aes256Gcm, Padding::Off);
        let _ = w.seal(b"a", false, 0).expect("seal");
        let _ = w.seal(b"b", false, REKEY_SECS).expect("seal");
        let c = w.seal(b"c", false, 2 * REKEY_SECS + 5).expect("seal");
        assert_eq!(w.epoch(), 2);
        assert!(r.open(&c).is_err());
    }

    #[test]
    fn oversized_and_undersized_input_is_refused() {
        let (mut w, mut r) = pair(Aead::Aes256Gcm, Padding::Off);
        assert!(w.seal(&vec![0; MAX_PAYLOAD + 1], false, 0).is_err());
        assert!(r.open(&[0; HEADER_LEN + TAG_LEN - 1]).is_err());
        assert!(
            r.open(&vec![0; HEADER_LEN + MAX_PAYLOAD + PAD_STEP + TAG_LEN + 2])
                .is_err()
        );
    }

    #[test]
    fn padding_without_the_marker_is_refused() {
        assert_eq!(unpad(&[1, 2, 0x80, 0, 0]), Ok(&[1u8, 2][..]));
        assert!(unpad(&[1, 2, 3]).is_err());
        assert!(unpad(&[0, 0]).is_err());
        assert!(unpad(&[]).is_err());
    }

    #[test]
    fn nonces_differ_by_counter() {
        let keys = Keys::new(Aead::Aes256Gcm, Zeroizing::new([1; 32]), 0);
        assert_ne!(keys.nonce(0), keys.nonce(1));
        assert_eq!(&keys.nonce(0)[..4], &keys.nonce(1)[..4]);
    }
}
