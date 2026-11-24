//! The Recovery Kit: a random 32-byte kit key split into pieces with Shamir's secret sharing over
//! GF(2^8), and the root key wrapped under that key.
//!
//! The pieces are the Kemlock app's, byte for byte (`docs/crypto.md`, "The Recovery Kit"):
//!
//! ```text
//! BMCKIT1-<kit id>-<needed><made><piece>-<key share>-<check>
//! ```
//!
//! The kit id is 8 base32 characters (5 random bytes) that tie the pieces of one kit together, the
//! three digits say how many pieces rebuild the key, how many were made and which this is, the key
//! share is 52 base32 characters, and the check is the first 4 base32 characters of the SHA-256 of
//! everything before it. Base32 is RFC 4648's alphabet without padding.
//!
//! The server keeps the root key wrapped under the kit key, as it does for a passkey's PRF output:
//!
//! ```text
//! wrap key = HKDF(ikm = kit key (32), salt = absent, info = "kemlock/v1/kit-wrap" ‖ lp(kit id), L = 32)
//! aad      = "kemlock/v1/root-wrap/kit" ‖ account id (16) ‖ u32be(key version) ‖ lp(kit id)
//! wrapped  = AES-256-GCM(wrap key, nonce, root key, aad)
//! ```
//!
//! A wrong kit key fails the tag, so the wrap is also the verifier: the server needs no other.

use zeroize::Zeroizing;

use crate::{
    Error, aead,
    backend::{Active, Backend},
    keys::{ROOT_KEY_LEN, RootKey, SecretKey},
    rand,
    wire::lp,
};

const PREFIX: &str = "BMCKIT1";
const ALPHABET: &[u8; 32] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
/// The kit key's length.
pub const KIT_KEY_LEN: usize = 32;
/// The most pieces a kit has: single digits keep the format fixed.
pub const MAX_PIECES: u8 = 9;
/// The length of a wrapped root key: nonce, 64 key bytes, tag.
pub const WRAPPED_LEN: usize = ROOT_KEY_LEN + aead::OVERHEAD;

const WRAP_INFO: &[u8] = b"kemlock/v1/kit-wrap";
const AAD_LABEL: &[u8] = b"kemlock/v1/root-wrap/kit";

/// What is wrong with a piece, or with the pieces collected so far.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PieceProblem {
    /// Not a Recovery Kit piece at all.
    Format,
    /// A piece with a typo: its check does not match.
    Checksum,
    /// A piece of another kit than the ones collected.
    OtherKit,
    /// A piece already collected.
    Duplicate,
    /// Fewer pieces than the kit needs.
    NotEnough,
}

impl PieceProblem {
    /// A short stable name, for an error code.
    pub fn code(self) -> &'static str {
        match self {
            PieceProblem::Format => "format",
            PieceProblem::Checksum => "checksum",
            PieceProblem::OtherKit => "other-kit",
            PieceProblem::Duplicate => "duplicate",
            PieceProblem::NotEnough => "not-enough",
        }
    }
}

impl core::fmt::Display for PieceProblem {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(match self {
            PieceProblem::Format => "not a Recovery Kit piece",
            PieceProblem::Checksum => "the piece has a typo: its check does not match",
            PieceProblem::OtherKit => "the piece is from another kit",
            PieceProblem::Duplicate => "the piece was already entered",
            PieceProblem::NotEnough => "not enough pieces",
        })
    }
}

impl std::error::Error for PieceProblem {}

/// One piece of a Recovery Kit, read from its text.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct KitPiece {
    /// Ties the pieces of one kit together: 8 base32 characters.
    pub kit_id: String,
    /// Pieces needed to rebuild the key.
    pub threshold: u8,
    /// Pieces made.
    pub shares: u8,
    /// This piece's number, 1-based.
    pub index: u8,
    /// This piece's share of the kit key, wiped when the piece is dropped.
    pub y: Zeroizing<[u8; KIT_KEY_LEN]>,
}

// ---- GF(2^8), the AES field (x^8 + x^4 + x^3 + x + 1), generator 3 ----

struct Tables {
    exp: [u8; 510],
    log: [u8; 256],
}

const fn tables() -> Tables {
    let mut exp = [0u8; 510];
    let mut log = [0u8; 256];
    let mut x: u16 = 1;
    let mut i = 0;
    while i < 255 {
        exp[i] = x as u8;
        log[x as usize] = i as u8;
        let mut doubled = x << 1;
        if doubled & 0x100 != 0 {
            doubled ^= 0x11b;
        }
        x = doubled ^ x;
        i += 1;
    }
    while i < 510 {
        exp[i] = exp[i - 255];
        i += 1;
    }
    Tables { exp, log }
}

static T: Tables = tables();

fn mul(a: u8, b: u8) -> u8 {
    if a == 0 || b == 0 {
        0
    } else {
        T.exp[usize::from(T.log[usize::from(a)]) + usize::from(T.log[usize::from(b)])]
    }
}

/// `a / b`, with `b` not zero.
fn div(a: u8, b: u8) -> u8 {
    if a == 0 {
        0
    } else {
        T.exp[usize::from(T.log[usize::from(a)]) + 255 - usize::from(T.log[usize::from(b)])]
    }
}

/// Splits `secret` into `count` shares (x = 1..=count), any `threshold` of which rebuild it.
/// `coefficients` holds the `threshold - 1` random polynomial coefficient rows.
fn split_with(
    secret: &[u8; KIT_KEY_LEN],
    threshold: u8,
    count: u8,
    coefficients: &[Zeroizing<[u8; KIT_KEY_LEN]>],
) -> Vec<Zeroizing<[u8; KIT_KEY_LEN]>> {
    (1..=count)
        .map(|x| {
            let mut y = Zeroizing::new([0u8; KIT_KEY_LEN]);
            for (i, out) in y.iter_mut().enumerate() {
                let mut value = 0u8;
                for j in (0..usize::from(threshold) - 1).rev() {
                    value = mul(value ^ coefficients[j][i], x);
                }
                *out = value ^ secret[i];
            }
            y
        })
        .collect()
}

/// Rebuilds the secret from distinct shares by interpolating at 0.
fn combine(shares: &[(u8, &[u8; KIT_KEY_LEN])]) -> Zeroizing<[u8; KIT_KEY_LEN]> {
    let mut out = Zeroizing::new([0u8; KIT_KEY_LEN]);
    for (i, (xi, y)) in shares.iter().enumerate() {
        let mut basis = 1u8;
        for (j, (xj, _)) in shares.iter().enumerate() {
            if i != j {
                basis = mul(basis, div(*xj, *xj ^ *xi));
            }
        }
        for b in 0..KIT_KEY_LEN {
            out[b] ^= mul(y[b], basis);
        }
    }
    out
}

// ---- text ----

fn base32(bytes: &[u8]) -> String {
    let mut out = String::new();
    let (mut bits, mut value) = (0u32, 0u32);
    for byte in bytes {
        value = (value << 8) | u32::from(*byte);
        bits += 8;
        while bits >= 5 {
            out.push(char::from(ALPHABET[((value >> (bits - 5)) & 31) as usize]));
            bits -= 5;
        }
        value &= (1 << bits) - 1;
    }
    if bits > 0 {
        out.push(char::from(ALPHABET[((value << (5 - bits)) & 31) as usize]));
    }
    out
}

/// Bits past the last whole byte are dropped, whatever they are.
fn unbase32(text: &str) -> Result<Zeroizing<Vec<u8>>, PieceProblem> {
    let mut out = Zeroizing::new(Vec::new());
    let (mut bits, mut value) = (0u32, 0u32);
    for c in text.bytes() {
        let v = ALPHABET
            .iter()
            .position(|a| *a == c)
            .ok_or(PieceProblem::Format)?;
        value = (value << 5) | v as u32;
        bits += 5;
        if bits >= 8 {
            out.push(((value >> (bits - 8)) & 0xff) as u8);
            bits -= 8;
        }
        value &= (1 << bits) - 1;
    }
    Ok(out)
}

fn check_of(body: &str) -> String {
    base32(&Active::sha256(body.as_bytes()))[..4].to_owned()
}

/// The piece's text, with its check.
pub fn piece_text(piece: &KitPiece) -> String {
    let body = format!(
        "{PREFIX}-{}-{}{}{}-{}",
        piece.kit_id,
        piece.threshold,
        piece.shares,
        piece.index,
        base32(&piece.y[..])
    );
    format!("{body}-{}", check_of(&body))
}

/// The piece with its long share in groups of four, for print and reading aloud.
pub fn display_piece(text: &str) -> String {
    let mut parts: Vec<String> = text.split('-').map(str::to_owned).collect();
    if parts.len() == 5 {
        parts[3] = parts[3]
            .as_bytes()
            .chunks(4)
            .map(|c| String::from_utf8_lossy(c).into_owned())
            .collect::<Vec<_>>()
            .join(" ");
    }
    parts.join("-")
}

/// Reads a piece however it was typed: any case, with or without spaces. `Format` for text that is
/// not a piece, `Checksum` for a piece whose check does not match.
pub fn parse_piece(input: &str) -> Result<KitPiece, PieceProblem> {
    let text: String = input
        .chars()
        .filter(|c| !c.is_whitespace())
        .collect::<String>()
        .to_uppercase();
    let parts: Vec<&str> = text.split('-').collect();
    if parts.len() != 5 || parts[0] != PREFIX {
        return Err(PieceProblem::Format);
    }
    let (kit_id, digits, share, check) = (parts[1], parts[2], parts[3], parts[4]);
    let base32_of = |s: &str, n: usize| s.len() == n && s.bytes().all(|b| ALPHABET.contains(&b));
    if !base32_of(kit_id, 8)
        || digits.len() != 3
        || !digits.bytes().all(|b| b.is_ascii_digit())
        || !base32_of(share, 52)
    {
        return Err(PieceProblem::Format);
    }
    if check_of(&parts[..4].join("-")) != check {
        return Err(PieceProblem::Checksum);
    }
    let d: Vec<u8> = digits.bytes().map(|b| b - b'0').collect();
    let (threshold, shares, index) = (d[0], d[1], d[2]);
    if threshold < 1 || threshold > shares || index < 1 || index > shares {
        return Err(PieceProblem::Format);
    }
    let bytes = unbase32(share)?;
    let y: [u8; KIT_KEY_LEN] = bytes
        .get(..KIT_KEY_LEN)
        .and_then(|b| b.try_into().ok())
        .ok_or(PieceProblem::Format)?;
    let y = Zeroizing::new(y);
    Ok(KitPiece {
        kit_id: kit_id.to_owned(),
        threshold,
        shares,
        index,
        y,
    })
}

/// A new kit: its id, its random key and the text of `shares` pieces, any `threshold` of which
/// rebuild the key.
pub type NewKit = (String, Zeroizing<[u8; KIT_KEY_LEN]>, Vec<String>);

/// Makes a kit. `Err` for a threshold under 1 or over the count, or more than [`MAX_PIECES`]
/// pieces.
pub fn make_kit(threshold: u8, shares: u8) -> Result<NewKit, Error> {
    if threshold < 1 || threshold > shares || shares > MAX_PIECES {
        return Err(Error::invalid());
    }
    let key = Zeroizing::new(rand::bytes::<KIT_KEY_LEN>());
    let kit_id = base32(&rand::bytes::<5>());
    let coefficients: Vec<Zeroizing<[u8; KIT_KEY_LEN]>> = (1..threshold)
        .map(|_| Zeroizing::new(rand::bytes::<KIT_KEY_LEN>()))
        .collect();
    let pieces = split_with(&key, threshold, shares, &coefficients)
        .into_iter()
        .zip(1..)
        .map(|(y, index)| {
            piece_text(&KitPiece {
                kit_id: kit_id.clone(),
                threshold,
                shares,
                index,
                y,
            })
        })
        .collect();
    Ok((kit_id, key, pieces))
}

/// The kit key from pieces of one kit: `Duplicate`, `OtherKit` or `NotEnough` when they do not
/// make a set. More pieces than needed are fine.
pub fn rebuild_key(pieces: &[KitPiece]) -> Result<Zeroizing<[u8; KIT_KEY_LEN]>, PieceProblem> {
    let first = pieces.first().ok_or(PieceProblem::NotEnough)?;
    for (i, piece) in pieces.iter().enumerate() {
        if piece.kit_id != first.kit_id {
            return Err(PieceProblem::OtherKit);
        }
        if pieces[..i].iter().any(|p| p.index == piece.index) {
            return Err(PieceProblem::Duplicate);
        }
    }
    if pieces.len() < usize::from(first.threshold) {
        return Err(PieceProblem::NotEnough);
    }
    let shares: Vec<(u8, &[u8; KIT_KEY_LEN])> = pieces.iter().map(|p| (p.index, &*p.y)).collect();
    Ok(combine(&shares))
}

// ---- the root key's wrap ----

fn wrap_key(kit_key: &[u8; KIT_KEY_LEN], kit_id: &str) -> Result<SecretKey, Error> {
    let mut info = Vec::with_capacity(WRAP_INFO.len() + 4 + kit_id.len());
    info.extend_from_slice(WRAP_INFO);
    lp(&mut info, kit_id.as_bytes())?;
    let mut out = Zeroizing::new([0u8; 32]);
    Active::hkdf_sha256(kit_key, None, &info, &mut *out)?;
    Ok(SecretKey::from_bytes(&out))
}

fn aad(account_id: &[u8; 16], key_version: u32, kit_id: &str) -> Result<Vec<u8>, Error> {
    let mut out = Vec::with_capacity(AAD_LABEL.len() + 20 + kit_id.len());
    out.extend_from_slice(AAD_LABEL);
    out.extend_from_slice(account_id);
    out.extend_from_slice(&key_version.to_be_bytes());
    lp(&mut out, kit_id.as_bytes())?;
    Ok(out)
}

/// Wraps the root key under the kit key: `nonce(12) ‖ ciphertext(64) ‖ tag(16)`.
pub fn seal(
    kit_key: &[u8; KIT_KEY_LEN],
    kit_id: &str,
    root: &RootKey,
    account_id: &[u8; 16],
    key_version: u32,
) -> Result<Vec<u8>, Error> {
    let key = wrap_key(kit_key, kit_id)?;
    aead::seal::<Active>(
        key.as_bytes(),
        &aad(account_id, key_version, kit_id)?,
        root.as_bytes(),
    )
}

/// Opens a wrapped root key. Fails for another kit key, kit, account or key version, and for any
/// altered byte.
pub fn open(
    kit_key: &[u8; KIT_KEY_LEN],
    kit_id: &str,
    wrapped: &[u8],
    account_id: &[u8; 16],
    key_version: u32,
) -> Result<RootKey, Error> {
    if wrapped.len() != WRAPPED_LEN {
        return Err(Error::invalid());
    }
    let key = wrap_key(kit_key, kit_id)?;
    let plain = aead::open::<Active>(
        key.as_bytes(),
        &aad(account_id, key_version, kit_id)?,
        wrapped,
    )?;
    let bytes: &[u8; ROOT_KEY_LEN] = plain.as_slice().try_into().map_err(|_| Error::invalid())?;
    Ok(RootKey::from_bytes(bytes))
}

/// Whether `text` is a kit id: 8 base32 characters.
pub fn is_kit_id(text: &str) -> bool {
    text.len() == 8 && text.bytes().all(|b| ALPHABET.contains(&b))
}
