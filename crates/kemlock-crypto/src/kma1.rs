//! `KMA1`, the chunked file format of attachments and file Sends, sealed and opened whole.
//!
//! ```text
//! "KMA1" ‖ nonce prefix (8 random bytes) ‖ chunk 0 ‖ chunk 1 ‖ … ‖ last chunk
//! chunk = AES-256-GCM(key, nonce = prefix ‖ u32be(counter), aad = 0x00, or 0x01 for the last chunk,
//!                     up to 65536 bytes of plaintext) ‖ tag(16)
//! ```
//!
//! This is the layout the Kemlock app's `attachment_format.dart` writes and `docs/crypto.md` states
//! under Sends. Every chunk but the last holds exactly 64 KiB of plaintext, and the last holds the
//! rest, possibly nothing, so a file always ends in exactly one last chunk. The key is the file's
//! own; for a file Send it is the Send's payload key.
//!
//! These functions take and return the whole file, which is what a browser holds for a file small
//! enough to read into memory. A client that streams makes the same bytes chunk by chunk.

use zeroize::Zeroizing;

use crate::{
    Error, aead,
    backend::{Active, Backend},
    keys::SecretKey,
    rand,
};

/// The four bytes every `KMA1` file starts with.
pub const MAGIC: [u8; 4] = *b"KMA1";
/// The random nonce prefix after the magic.
pub const PREFIX_LEN: usize = 8;
/// Magic and nonce prefix.
pub const HEADER_LEN: usize = MAGIC.len() + PREFIX_LEN;
/// The plaintext in every chunk but the last.
pub const CHUNK_LEN: usize = 64 * 1024;
/// A full chunk as stored: its plaintext and tag.
pub const SEALED_CHUNK_LEN: usize = CHUNK_LEN + aead::TAG_LEN;
/// The smallest file: a header and the empty last chunk's tag.
pub const MIN_LEN: usize = HEADER_LEN + aead::TAG_LEN;

const MIDDLE: [u8; 1] = [0];
const LAST: [u8; 1] = [1];

/// The length of the `KMA1` file a `plain`-byte file becomes.
pub fn sealed_len(plain: usize) -> usize {
    let chunks = plain.div_ceil(CHUNK_LEN).max(1);
    HEADER_LEN + plain + chunks * aead::TAG_LEN
}

/// `prefix ‖ u32be(counter)`.
fn nonce(prefix: &[u8; PREFIX_LEN], counter: u32) -> [u8; 12] {
    let mut out = [0u8; 12];
    out[..PREFIX_LEN].copy_from_slice(prefix);
    out[PREFIX_LEN..].copy_from_slice(&counter.to_be_bytes());
    out
}

/// Seals `plain` as a `KMA1` file under `key`, with a fresh random nonce prefix.
pub fn seal(key: &SecretKey, plain: &[u8]) -> Result<Vec<u8>, Error> {
    seal_in::<Active>(key, plain)
}

pub(crate) fn seal_in<B: Backend>(key: &SecretKey, plain: &[u8]) -> Result<Vec<u8>, Error> {
    let prefix = rand::try_bytes::<B, PREFIX_LEN>()?;
    seal_with_prefix_in::<B>(key, &prefix, plain)
}

/// Seals with a chosen prefix, so a test can pin the bytes. A prefix must never be used for two
/// files under one key.
pub(crate) fn seal_with_prefix_in<B: Backend>(
    key: &SecretKey,
    prefix: &[u8; PREFIX_LEN],
    plain: &[u8],
) -> Result<Vec<u8>, Error> {
    let mut out = Vec::with_capacity(sealed_len(plain.len()));
    out.extend_from_slice(&MAGIC);
    out.extend_from_slice(prefix);
    let mut counter: u32 = 0;
    let mut offset = 0;
    loop {
        let end = (offset + CHUNK_LEN).min(plain.len());
        let last = end == plain.len();
        let aad = if last { &LAST } else { &MIDDLE };
        let sealed = B::aes256gcm_seal(
            key.as_bytes(),
            &nonce(prefix, counter),
            aad,
            &plain[offset..end],
        )?;
        out.extend_from_slice(&sealed);
        if last {
            return Ok(out);
        }
        offset = end;
        counter = counter.checked_add(1).ok_or_else(Error::invalid)?;
    }
}

/// Opens a `KMA1` file. Fails for the wrong key, a changed, reordered, cut or extended file, a
/// wrong magic and a length no sequence of chunks makes; nothing is returned in part.
pub fn open(key: &SecretKey, file: &[u8]) -> Result<Zeroizing<Vec<u8>>, Error> {
    open_in::<Active>(key, file)
}

pub(crate) fn open_in<B: Backend>(
    key: &SecretKey,
    file: &[u8],
) -> Result<Zeroizing<Vec<u8>>, Error> {
    check_shape(file)?;
    let prefix: [u8; PREFIX_LEN] = file[MAGIC.len()..HEADER_LEN]
        .try_into()
        .map_err(|_| Error::invalid())?;
    let mut out = Zeroizing::new(Vec::with_capacity(file.len() - HEADER_LEN));
    let mut counter: u32 = 0;
    let mut offset = HEADER_LEN;
    loop {
        let end = (offset + SEALED_CHUNK_LEN).min(file.len());
        let last = end == file.len();
        let aad = if last { &LAST } else { &MIDDLE };
        let plain = B::aes256gcm_open(
            key.as_bytes(),
            &nonce(&prefix, counter),
            aad,
            &file[offset..end],
        )?;
        out.extend_from_slice(&plain);
        if last {
            return Ok(out);
        }
        offset = end;
        counter = counter.checked_add(1).ok_or_else(Error::invalid)?;
    }
}

/// Whether `file` can be a header followed by whole chunks: the magic, and a body of full chunks
/// then a last one of 16 to 65,552 bytes. Nothing is decrypted.
pub fn check_shape(file: &[u8]) -> Result<(), Error> {
    if file.get(..MAGIC.len()) != Some(&MAGIC[..]) {
        return Err(Error::invalid());
    }
    check_len(file.len() as u64)
}

/// Whether a file of `total` bytes has the length a header and whole chunks make: at least a
/// header and one tag, and after the header full chunks then a last one of 16 to 65,552 bytes. It
/// is the rule a server applies to the size a file Send announces, before any byte arrives.
pub fn check_len(total: u64) -> Result<(), Error> {
    if total < MIN_LEN as u64 {
        return Err(Error::invalid());
    }
    let rest = (total - HEADER_LEN as u64) % SEALED_CHUNK_LEN as u64;
    if rest == 0 || rest >= aead::TAG_LEN as u64 {
        Ok(())
    } else {
        Err(Error::invalid())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The key of the app's fixtures: bytes 0xa0 to 0xbf.
    fn fixture_key() -> SecretKey {
        SecretKey::from_bytes(&core::array::from_fn(|i| {
            0xa0 + u8::try_from(i).unwrap_or(0)
        }))
    }

    fn pattern(len: usize) -> Vec<u8> {
        (0..len).map(|i| ((i * 31 + 7) & 0xff) as u8).collect()
    }

    fn unhex(text: &str) -> Vec<u8> {
        (0..text.len() / 2)
            .map(|i| u8::from_str_radix(&text[2 * i..2 * i + 2], 16).expect("hex"))
            .collect()
    }

    // The two small files of the app's `test/fixtures/attachments`, which pin the format.
    const EMPTY: &str = "4b4d413101020304050607082a16a0a91c727e7beadcea74048b68eb";
    const SHORT: &str = "4b4d4131090a0b0c0d0e0f10701842a7640ce54cb5521fb8f7e2c096224d21cebf19926dd1f655d1472bdd44224e97b3ecb2d59239ec02";
    const TWO_CHUNKS: &[u8] = include_bytes!("../../kemlock-blob/tests/fixtures/two-chunks.kma1");

    #[test]
    fn writes_the_apps_fixture_files_byte_for_byte() {
        for_backends!(B => {
            let key = fixture_key();
            let empty = seal_with_prefix_in::<B>(&key, &[1, 2, 3, 4, 5, 6, 7, 8], b"").expect("seal");
            assert_eq!(empty, unhex(EMPTY), "{}", B::NAME);
            let short = seal_with_prefix_in::<B>(
                &key,
                &[9, 10, 11, 12, 13, 14, 15, 16],
                b"Kemlock attachment fixture\n",
            )
            .expect("seal");
            assert_eq!(short, unhex(SHORT), "{}", B::NAME);
            let prefix: [u8; PREFIX_LEN] = TWO_CHUNKS[4..HEADER_LEN].try_into().expect("prefix");
            let two = seal_with_prefix_in::<B>(&key, &prefix, &pattern(65636)).expect("seal");
            assert_eq!(two, TWO_CHUNKS, "{}", B::NAME);
        });
    }

    #[test]
    fn opens_the_apps_fixture_files() {
        for_backends!(B => {
            let key = fixture_key();
            assert!(open_in::<B>(&key, &unhex(EMPTY)).expect("open").is_empty(), "{}", B::NAME);
            assert_eq!(
                open_in::<B>(&key, &unhex(SHORT)).expect("open").as_slice(),
                b"Kemlock attachment fixture\n",
                "{}",
                B::NAME
            );
            assert_eq!(
                open_in::<B>(&key, TWO_CHUNKS).expect("open").as_slice(),
                pattern(65636).as_slice(),
                "{}",
                B::NAME
            );
        });
    }

    #[test]
    fn round_trips_around_the_chunk_size() {
        for_backends!(B => {
            let key = SecretKey::from_bytes(&[7; 32]);
            for len in [0, 1, 65535, 65536, 65537, 131072, 131073, 200_000] {
                let plain = pattern(len);
                let file = seal_in::<B>(&key, &plain).expect("seal");
                assert_eq!(file.len(), sealed_len(len), "{} {len}", B::NAME);
                assert!(check_shape(&file).is_ok(), "{} {len}", B::NAME);
                assert_eq!(
                    open_in::<B>(&key, &file).expect("open").as_slice(),
                    plain.as_slice(),
                    "{} {len}",
                    B::NAME
                );
            }
        });
    }

    #[test]
    fn the_length_is_header_plain_and_a_tag_per_chunk() {
        assert_eq!(sealed_len(0), 28);
        assert_eq!(sealed_len(1), 12 + 1 + 16);
        assert_eq!(sealed_len(65536), 12 + 65536 + 16);
        assert_eq!(sealed_len(65537), 12 + 65537 + 32);
        assert_eq!(sealed_len(65636), TWO_CHUNKS.len());
    }

    #[test]
    fn nonces_are_fresh_per_file() {
        let key = SecretKey::from_bytes(&[7; 32]);
        let a = seal(&key, b"same").expect("seal");
        let b = seal(&key, b"same").expect("seal");
        assert_ne!(a[MAGIC.len()..HEADER_LEN], b[MAGIC.len()..HEADER_LEN]);
    }

    #[test]
    fn another_key_or_any_changed_byte_fails() {
        for_backends!(B => {
            let key = SecretKey::from_bytes(&[7; 32]);
            let file = seal_in::<B>(&key, &pattern(70_000)).expect("seal");
            assert!(open_in::<B>(&SecretKey::from_bytes(&[8; 32]), &file).is_err(), "{}", B::NAME);
            for index in [0, 3, 4, 11, 12, 100, 65_000, 65_563, 65_564, file.len() - 1] {
                let mut bad = file.clone();
                bad[index] ^= 1;
                assert!(open_in::<B>(&key, &bad).is_err(), "{} byte {index}", B::NAME);
            }
        });
    }

    #[test]
    fn reordered_cut_and_extended_files_fail() {
        for_backends!(B => {
            let key = SecretKey::from_bytes(&[7; 32]);
            let file = seal_in::<B>(&key, &pattern(3 * CHUNK_LEN + 5)).expect("seal");
            // Cut at a chunk boundary: the shape is fine, but no chunk is marked last.
            let cut = &file[..HEADER_LEN + 3 * SEALED_CHUNK_LEN];
            assert!(check_shape(cut).is_ok());
            assert!(open_in::<B>(&key, cut).is_err(), "{}", B::NAME);
            // The first two chunks swapped.
            let first = HEADER_LEN..HEADER_LEN + SEALED_CHUNK_LEN;
            let second = first.end..first.end + SEALED_CHUNK_LEN;
            let mut swapped = file[..HEADER_LEN].to_vec();
            swapped.extend_from_slice(&file[second.clone()]);
            swapped.extend_from_slice(&file[first.clone()]);
            swapped.extend_from_slice(&file[second.end..]);
            assert!(open_in::<B>(&key, &swapped).is_err(), "{}", B::NAME);
            // Extended: another full chunk of the same file after the last.
            let mut longer = file.clone();
            longer.extend_from_slice(&file[first]);
            assert!(open_in::<B>(&key, &longer).is_err(), "{}", B::NAME);
        });
    }

    #[test]
    fn announced_lengths_follow_the_chunk_rule() {
        let full = SEALED_CHUNK_LEN as u64;
        let header = HEADER_LEN as u64;
        for ok in [
            28,
            29,
            12 + 16 + 65_536,
            header + full,
            header + full + 16,
            header + 3 * full,
        ] {
            assert!(check_len(ok).is_ok(), "{ok}");
        }
        for bad in [
            0,
            11,
            12,
            27,
            header + full + 1,
            header + full + 15,
            header + 2 * full + 7,
        ] {
            assert!(check_len(bad).is_err(), "{bad}");
        }
        for plain in [0, 1, 65_535, 65_536, 65_537, 1_000_000] {
            assert!(check_len(sealed_len(plain) as u64).is_ok(), "{plain}");
        }
    }

    #[test]
    fn shapes_that_no_chunks_make_are_refused_before_decrypting() {
        assert!(check_shape(b"").is_err());
        assert!(
            check_shape(&unhex(EMPTY)[..27]).is_err(),
            "shorter than a tag"
        );
        let mut wrong_magic = unhex(EMPTY);
        wrong_magic[0] = b'X';
        assert!(check_shape(&wrong_magic).is_err());
        // A last chunk of 1 to 15 bytes can't hold a tag.
        for extra in 1..16 {
            let mut file = TWO_CHUNKS[..HEADER_LEN + SEALED_CHUNK_LEN].to_vec();
            file.extend(core::iter::repeat_n(0, extra));
            assert!(check_shape(&file).is_err(), "{extra}");
        }
        assert!(check_shape(TWO_CHUNKS).is_ok());
    }
}
