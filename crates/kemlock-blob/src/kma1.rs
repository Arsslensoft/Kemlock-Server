//! The `KMA1` header and size shape, checked without decrypting anything.
//!
//! `KMA1` is the format the Kemlock app writes a file attached to a note in (the comment in the
//! app's `attachment_format.dart` pins it, and `tests/fixtures/` holds its files):
//!
//! ```text
//! "KMA1" | nonce prefix (8 random bytes) | chunk 0 | chunk 1 | … | last chunk
//! chunk = AES-256-GCM(key, nonce = prefix ‖ counter (4 bytes, big-endian),
//!                     aad = 0x00, or 0x01 for the last chunk,
//!                     up to 64 KiB of plaintext) ‖ tag (16 bytes)
//! ```
//!
//! Every chunk but the last holds exactly 64 KiB of plaintext (65 552 bytes sealed); the last
//! holds the rest, possibly nothing, so a file always ends in exactly one last chunk. The key is
//! the file's own and never reaches the server, so the server can't open a chunk. It can still
//! refuse bytes that can't be a `KMA1` file: wrong magic, shorter than a header and one tag, or a
//! length that no sequence of chunks makes. That is all this module does; every function takes
//! plain bytes and never panics, so it can be fuzzed as it is.

/// The four bytes every `KMA1` file starts with.
pub const MAGIC: [u8; 4] = *b"KMA1";
/// The random nonce prefix after the magic.
pub const PREFIX_LEN: usize = 8;
/// Magic and nonce prefix.
pub const HEADER_LEN: usize = 4 + PREFIX_LEN;
/// An AES-256-GCM tag.
pub const TAG_LEN: usize = 16;
/// The plaintext in every chunk but the last.
pub const CHUNK_LEN: usize = 64 * 1024;
/// A full chunk as stored: its plaintext and tag.
pub const SEALED_CHUNK_LEN: usize = CHUNK_LEN + TAG_LEN;
/// The smallest `KMA1` file: a header and the one (empty) last chunk's tag.
pub const MIN_LEN: usize = HEADER_LEN + TAG_LEN;

/// Why bytes can't be a `KMA1` file.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum Kma1Error {
    #[error("shorter than a KMA1 header and one tag")]
    TooShort,
    #[error("doesn't start with KMA1")]
    BadMagic,
    #[error("the length is not that of any sequence of KMA1 chunks")]
    BadLength,
}

/// A parsed `KMA1` header.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Header {
    /// The first eight bytes of every chunk's nonce.
    pub nonce_prefix: [u8; PREFIX_LEN],
}

impl Header {
    /// Reads the header at the start of `bytes`, which may hold more than the header.
    pub fn parse(bytes: &[u8]) -> Result<Header, Kma1Error> {
        let Some(header) = bytes.get(..HEADER_LEN) else {
            // A prefix that already disagrees with the magic is `BadMagic` even when short.
            let seen = bytes.len().min(MAGIC.len());
            return if bytes[..seen] == MAGIC[..seen] {
                Err(Kma1Error::TooShort)
            } else {
                Err(Kma1Error::BadMagic)
            };
        };
        if header[..MAGIC.len()] != MAGIC {
            return Err(Kma1Error::BadMagic);
        }
        let mut nonce_prefix = [0u8; PREFIX_LEN];
        nonce_prefix.copy_from_slice(&header[MAGIC.len()..]);
        Ok(Header { nonce_prefix })
    }
}

/// Whether a file of `total` bytes can be a header followed by whole chunks: every chunk but the
/// last is 65 552 bytes, and the last is 16 to 65 552 (a tag, then up to 64 KiB of plaintext).
pub fn check_length(total: u64) -> Result<(), Kma1Error> {
    let min = MIN_LEN as u64;
    if total < min {
        return Err(Kma1Error::BadLength);
    }
    let body = total - HEADER_LEN as u64;
    let rest = body % SEALED_CHUNK_LEN as u64;
    // `rest == 0` is a last chunk that is full; otherwise it must at least hold its tag.
    if rest == 0 || rest >= TAG_LEN as u64 {
        Ok(())
    } else {
        Err(Kma1Error::BadLength)
    }
}

/// The size of the `KMA1` file a `plain`-byte file becomes (the app's `kma1Length`).
pub fn sealed_length(plain: u64) -> u64 {
    let chunk = CHUNK_LEN as u64;
    let chunks = if plain == 0 { 1 } else { plain.div_ceil(chunk) };
    HEADER_LEN as u64 + plain + chunks * TAG_LEN as u64
}

/// Checks a `KMA1` file as it streams past: the header when its twelfth byte arrives, the length
/// at the end. Keeps at most a header of bytes.
#[derive(Debug, Default, Clone)]
pub struct StreamCheck {
    head: Vec<u8>,
    header: Option<Header>,
    seen: u64,
}

impl StreamCheck {
    pub fn new() -> Self {
        Self::default()
    }

    /// Feeds the next bytes. Fails as soon as the bytes seen can't be a `KMA1` file's start.
    pub fn push(&mut self, bytes: &[u8]) -> Result<(), Kma1Error> {
        self.seen = self.seen.saturating_add(bytes.len() as u64);
        if self.header.is_some() {
            return Ok(());
        }
        let room = HEADER_LEN - self.head.len();
        self.head.extend_from_slice(&bytes[..bytes.len().min(room)]);
        // Wrong magic is known from the first bytes, before the header is complete.
        let known = self.head.len().min(MAGIC.len());
        if self.head[..known] != MAGIC[..known] {
            return Err(Kma1Error::BadMagic);
        }
        if self.head.len() == HEADER_LEN {
            self.header = Some(Header::parse(&self.head)?);
        }
        Ok(())
    }

    /// The bytes fed so far.
    pub fn seen(&self) -> u64 {
        self.seen
    }

    /// Ends the stream: it must have had a whole header and a length chunks can make. Returns
    /// the header and the total.
    pub fn finish(self) -> Result<(Header, u64), Kma1Error> {
        let Some(header) = self.header else {
            return Err(Kma1Error::TooShort);
        };
        check_length(self.seen)?;
        Ok((header, self.seen))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn file(len: usize) -> Vec<u8> {
        let mut bytes = b"KMA1".to_vec();
        bytes.extend((0..len.saturating_sub(4)).map(|i| (i % 251) as u8));
        bytes.truncate(len.max(4));
        bytes
    }

    #[test]
    fn a_header_is_read_and_the_rest_ignored() {
        let mut bytes = b"KMA1".to_vec();
        bytes.extend([1, 2, 3, 4, 5, 6, 7, 8, 99, 99]);
        assert_eq!(
            Header::parse(&bytes),
            Ok(Header {
                nonce_prefix: [1, 2, 3, 4, 5, 6, 7, 8]
            })
        );
    }

    #[test]
    fn bad_headers_are_refused() {
        assert_eq!(Header::parse(b""), Err(Kma1Error::TooShort));
        assert_eq!(Header::parse(b"KMA"), Err(Kma1Error::TooShort));
        assert_eq!(Header::parse(b"KMA1\x01\x02"), Err(Kma1Error::TooShort));
        assert_eq!(Header::parse(b"XMA1"), Err(Kma1Error::BadMagic));
        assert_eq!(Header::parse(b"XM"), Err(Kma1Error::BadMagic));
        assert_eq!(Header::parse(b"KMA2000000000000"), Err(Kma1Error::BadMagic));
        assert_eq!(Header::parse(b"kma1000000000000"), Err(Kma1Error::BadMagic));
    }

    #[test]
    fn lengths_follow_the_chunk_layout() {
        // 12 + the empty file's tag.
        assert_eq!(check_length(28), Ok(()));
        for bad in [0, 11, 12, 27] {
            assert_eq!(check_length(bad), Err(Kma1Error::BadLength), "{bad}");
        }
        // One chunk of 1 byte, of 64 KiB (full last chunk), and a full chunk then a tag.
        for ok in [
            29,
            12 + 65_552,
            12 + 65_552 + 16,
            12 + 65_552 * 3,
            12 + 65_552 + 17,
        ] {
            assert_eq!(check_length(ok), Ok(()), "{ok}");
        }
        // A last chunk too short to hold its tag.
        for bad in [12 + 65_552 + 1, 12 + 65_552 + 15, 12 + 65_552 * 2 + 15] {
            assert_eq!(check_length(bad), Err(Kma1Error::BadLength), "{bad}");
        }
        // The largest length doesn't overflow.
        let _ = check_length(u64::MAX);
    }

    #[test]
    fn the_sealed_length_is_always_a_valid_length() {
        assert_eq!(sealed_length(0), 28);
        assert_eq!(sealed_length(36), 64);
        assert_eq!(sealed_length(65_636), 65_680);
        for plain in [0, 1, 65_535, 65_536, 65_537, 131_072, 1 << 30] {
            assert_eq!(check_length(sealed_length(plain)), Ok(()), "{plain}");
        }
    }

    #[test]
    fn a_stream_is_checked_however_it_is_cut() {
        let bytes = file(65_680);
        for step in [1, 3, 12, 13, 4096, 70_000] {
            let mut check = StreamCheck::new();
            for piece in bytes.chunks(step) {
                check.push(piece).expect("a valid start");
            }
            assert_eq!(check.seen(), 65_680);
            let (header, total) = check.finish().expect("a valid file");
            assert_eq!(total, 65_680);
            assert_eq!(header.nonce_prefix[0], 0);
        }
    }

    #[test]
    fn a_stream_with_the_wrong_magic_fails_at_the_first_wrong_byte() {
        let mut check = StreamCheck::new();
        assert_eq!(check.push(b"KM"), Ok(()));
        assert_eq!(check.push(b"X"), Err(Kma1Error::BadMagic));
        let mut check = StreamCheck::new();
        assert_eq!(check.push(b"PK\x03\x04"), Err(Kma1Error::BadMagic));
    }

    #[test]
    fn a_short_or_oddly_long_stream_fails_at_the_end() {
        let mut check = StreamCheck::new();
        check.push(&file(11)).expect("so far fine");
        assert_eq!(check.finish().map(|_| ()), Err(Kma1Error::TooShort));
        let mut check = StreamCheck::new();
        check.push(&file(12)).expect("so far fine");
        assert_eq!(check.finish().map(|_| ()), Err(Kma1Error::BadLength));
        let mut check = StreamCheck::new();
        check.push(&file(12 + 65_552 + 3)).expect("so far fine");
        assert_eq!(check.finish().map(|_| ()), Err(Kma1Error::BadLength));
    }

    #[test]
    fn parsing_never_panics_on_any_prefix() {
        let bytes = file(40);
        for end in 0..=bytes.len() {
            let _ = Header::parse(&bytes[..end]);
            let mut check = StreamCheck::new();
            let _ = check.push(&bytes[..end]);
            let _ = check.finish();
        }
    }
}
