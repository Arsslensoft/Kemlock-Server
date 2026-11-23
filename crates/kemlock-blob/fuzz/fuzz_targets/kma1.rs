//! `KMA1` headers and lengths: never a panic, and a stream of any piece sizes gives the answer the
//! whole file gives.

#![no_main]

use kemlock_blob::kma1::{self, Header, HEADER_LEN, Kma1Error, MAGIC, StreamCheck};
use libfuzzer_sys::fuzz_target;

fn stream<'a>(pieces: impl Iterator<Item = &'a [u8]>) -> Result<(Header, u64), Kma1Error> {
    let mut check = StreamCheck::new();
    for piece in pieces {
        check.push(piece)?;
    }
    check.finish()
}

fuzz_target!(|data: &[u8]| {
    if let Ok(header) = Header::parse(data) {
        assert_eq!(data[..MAGIC.len()], MAGIC);
        assert_eq!(header.nonce_prefix[..], data[MAGIC.len()..HEADER_LEN]);
    }

    // The upload arrives in pieces of whatever size the network gives: the first byte picks one.
    let size = 1 + usize::from(data.first().copied().unwrap_or(0)) % 31;
    assert_eq!(
        stream(data.chunks(size)),
        stream(std::iter::once(data)),
        "the check must not depend on how the bytes arrive"
    );

    // Any length a sealed file of some plaintext size can have is a length chunks can make.
    let mut eight = [0u8; 8];
    for (to, from) in eight.iter_mut().zip(data) {
        *to = *from;
    }
    let plain = u64::from_le_bytes(eight) % (1 << 40);
    assert!(kma1::check_length(kma1::sealed_length(plain)).is_ok());
    let _ = kma1::check_length(u64::from_le_bytes(eight));
});
