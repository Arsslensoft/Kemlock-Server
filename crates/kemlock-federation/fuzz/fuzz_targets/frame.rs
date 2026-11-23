//! Sealed frames: arbitrary bytes into a reader, and a valid frame with one byte changed.

#![no_main]

use kemlock_federation::crypto::Aead;
use kemlock_federation::frame::{Direction, FrameReader, FrameWriter, Padding};
use libfuzzer_sys::fuzz_target;

const PRK: [u8; 32] = [3; 32];
const SESSION: [u8; 16] = [1; 16];

fuzz_target!(|data: &[u8]| {
    for aead in [Aead::Aes256Gcm, Aead::ChaCha20Poly1305] {
        let mut reader = FrameReader::new(SESSION, aead, &PRK, Direction::InitiatorToResponder);
        let _ = reader.open(data);

        // One byte of a real frame changed: it must fail, and never panic.
        if let [at, flip, ..] = data {
            let mut writer = FrameWriter::new(
                SESSION,
                aead,
                &PRK,
                Direction::InitiatorToResponder,
                0,
                Padding::Off,
            );
            if let Ok(mut frame) = writer.seal(b"payload", false, 0) {
                let i = usize::from(*at) % frame.len();
                if *flip != 0 {
                    frame[i] ^= *flip;
                    let mut reader =
                        FrameReader::new(SESSION, aead, &PRK, Direction::InitiatorToResponder);
                    assert!(reader.open(&frame).is_err(), "a changed frame must not open");
                }
            }
        }
    }
});
