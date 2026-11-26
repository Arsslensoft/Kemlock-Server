//! The one Ed25519 verification rule, shared by both backends (docs/crypto.md, "Ed25519
//! verification rule").
//!
//! `verify(A, M, R ‖ S)` passes only when all of these hold:
//!
//! 1. `A` is a canonical encoding (its 255-bit `y` is below `p = 2^255 - 19`) of a point that does
//!    not have small order, and it decodes to a point on the curve;
//! 2. `R`, the first 32 bytes of the signature, meets the same three conditions;
//! 3. `S`, the last 32 bytes, is below the group order `L`;
//! 4. `[S]B = R + [k]A` holds exactly (not multiplied by the cofactor), with
//!    `k = SHA-512(R ‖ A ‖ M) mod L` over the bytes as sent.
//!
//! That is what RustCrypto's `verify_strict` checks. aws-lc's verification is not known to do all
//! of it (nothing promises that it refuses small-order keys, non-canonical encodings or an `S`
//! between `L` and `2^253`), so the native backend runs the checks here before calling aws-lc, and
//! aws-lc's own exact equation does the rest. The two backends therefore accept the same
//! signatures.
//!
//! The checks that need curve arithmetic (is the point on the curve) are left to the backends:
//! both refuse a point that does not decode, and a signature can't verify under one anyway. The
//! checks here are plain byte comparisons, which is what lets them run without a curve library.
//! There are exactly eight points of small order, and so exactly the `y` values below.

use crate::{Error, wire::array_ref};

/// `p = 2^255 - 19`, little endian.
const P: [u8; 32] = [
    0xed, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f,
];

/// The group order `L = 2^252 + 27742317777372353535851937790883648493`, little endian.
const L: [u8; 32] = [
    0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58, 0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9, 0xde, 0x14,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10,
];

/// The `y` coordinates (little endian) of the eight points of small order, whichever way their `x`
/// goes: `0` (order 4, `x` = ±sqrt(-1)), `1` (the identity), `p - 1` (order 2), and two of order 8.
const SMALL_ORDER_Y: [[u8; 32]; 5] = [
    [0; 32],
    [
        0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00,
    ],
    [
        0xec, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0x7f,
    ],
    [
        0x26, 0xe8, 0x95, 0x8f, 0xc2, 0xb2, 0x27, 0xb0, 0x45, 0xc3, 0xf4, 0x89, 0xf2, 0xef, 0x98,
        0xf0, 0xd5, 0xdf, 0xac, 0x05, 0xd3, 0xc6, 0x33, 0x39, 0xb1, 0x38, 0x02, 0x88, 0x6d, 0x53,
        0xfc, 0x05,
    ],
    [
        0xc7, 0x17, 0x6a, 0x70, 0x3d, 0x4d, 0xd8, 0x4f, 0xba, 0x3c, 0x0b, 0x76, 0x0d, 0x10, 0x67,
        0x0f, 0x2a, 0x20, 0x53, 0xfa, 0x2c, 0x39, 0xcc, 0xc6, 0x4e, 0xc7, 0xfd, 0x77, 0x92, 0xac,
        0x03, 0x7a,
    ],
];

/// `a < b` for 32-byte little-endian integers.
fn less_than(a: &[u8; 32], b: &[u8; 32]) -> bool {
    a.iter()
        .rev()
        .zip(b.iter().rev())
        .find(|(x, y)| x != y)
        .is_some_and(|(x, y)| x < y)
}

/// Refuses the encoding of a point (a public key, or the `R` of a signature) that is not
/// canonical or that has small order. It does not check that the point is on the curve.
///
/// The encoding is the 255-bit `y` (little endian) with the sign of `x` in the top bit. It is
/// canonical when `y < p` and, for `x = 0`, the sign bit is clear; the only points with `x = 0`
/// have `y` = 1 or `p - 1`, which have small order and are refused below whatever the sign.
pub(crate) fn check_point(encoded: &[u8; 32]) -> Result<(), Error> {
    let mut y = *encoded;
    y[31] &= 0x7f;
    if !less_than(&y, &P) || SMALL_ORDER_Y.contains(&y) {
        return Err(Error::invalid());
    }
    Ok(())
}

/// Refuses an `S` that is not below the group order.
pub(crate) fn check_scalar(s: &[u8; 32]) -> Result<(), Error> {
    if less_than(s, &L) {
        Ok(())
    } else {
        Err(Error::invalid())
    }
}

/// Everything in the rule that is a comparison of bytes, for a key and a signature as sent.
pub(crate) fn check_inputs(public: &[u8; 32], signature: &[u8]) -> Result<(), Error> {
    let signature: &[u8; 64] = array_ref(signature)?;
    let r: &[u8; 32] = array_ref(&signature[..32])?;
    let s: &[u8; 32] = array_ref(&signature[32..])?;
    check_point(public)?;
    check_point(r)?;
    check_scalar(s)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn y(n: u8) -> [u8; 32] {
        let mut out = [0u8; 32];
        out[0] = n;
        out
    }

    #[test]
    fn the_eight_small_order_points_are_refused_with_either_sign() {
        for base in SMALL_ORDER_Y {
            assert!(check_point(&base).is_err());
            let mut negative = base;
            negative[31] |= 0x80;
            assert!(check_point(&negative).is_err());
        }
    }

    #[test]
    fn y_at_or_above_p_is_refused() {
        // y = p, p + 1 (the identity), and the top of the range.
        assert!(check_point(&P).is_err());
        let mut p_plus_one = P;
        p_plus_one[0] = 0xee;
        assert!(check_point(&p_plus_one).is_err());
        let mut top = [0xff; 32];
        top[31] = 0x7f;
        assert!(check_point(&top).is_err());
        // Another point's y + p: y = 2 written as 2 + p.
        let mut two_plus_p = P;
        two_plus_p[0] = 0xef;
        assert!(check_point(&two_plus_p).is_err());
        // The same y below p is not refused here (whether it is a point is the backend's check).
        assert!(check_point(&y(2)).is_ok());
    }

    #[test]
    fn the_base_point_and_ordinary_keys_pass() {
        // The base point's encoding, 0x58 followed by 0x66 31 times, and RFC 8032 test 1's key.
        let mut base = [0x66u8; 32];
        base[0] = 0x58;
        assert!(check_point(&base).is_ok());
        let key = [
            0xd7, 0x5a, 0x98, 0x01, 0x82, 0xb1, 0x0a, 0xb7, 0xd5, 0x4b, 0xfe, 0xd3, 0xc9, 0x64,
            0x07, 0x3a, 0x0e, 0xe1, 0x72, 0xf3, 0xda, 0xa6, 0x23, 0x25, 0xaf, 0x02, 0x1a, 0x68,
            0xf7, 0x07, 0x51, 0x1a,
        ];
        assert!(check_point(&key).is_ok());
    }

    #[test]
    fn s_must_be_below_l() {
        let mut below = L;
        below[0] -= 1;
        assert!(check_scalar(&below).is_ok());
        assert!(check_scalar(&L).is_err());
        let mut above = L;
        above[0] += 1;
        assert!(check_scalar(&above).is_err());
        assert!(check_scalar(&[0; 32]).is_ok());
        assert!(check_scalar(&[0xff; 32]).is_err());
        // Just under 2^253: a check on the top three bits alone lets it through; this one doesn't.
        let mut under_2_253 = [0xff; 32];
        under_2_253[31] = 0x1f;
        assert!(check_scalar(&under_2_253).is_err());
    }

    #[test]
    fn inputs_need_a_64_byte_signature_and_checked_parts() {
        let key = y(2);
        let mut sig = [0u8; 64];
        sig[0] = 2;
        assert!(check_inputs(&key, &sig).is_ok());
        assert!(check_inputs(&key, &sig[..63]).is_err());
        assert!(check_inputs(&key, &[sig.as_slice(), &[0]].concat()).is_err());
        // A small-order R, a small-order key and an S of L each fail alone.
        let mut small_r = sig;
        small_r[..32].copy_from_slice(&SMALL_ORDER_Y[1]);
        assert!(check_inputs(&key, &small_r).is_err());
        assert!(check_inputs(&SMALL_ORDER_Y[1], &sig).is_err());
        let mut big_s = sig;
        big_s[32..].copy_from_slice(&L);
        assert!(check_inputs(&key, &big_s).is_err());
    }
}
