//! TOTP (RFC 6238) as the server's second factor: HMAC-SHA-1, 6 digits, 30-second steps.

use subtle::ConstantTimeEq as _;

use crate::backend::{Active, Backend};

const STEP_SECONDS: u64 = 30;
const DIGITS: usize = 6;

/// The code for the time step that contains `unix_seconds`.
pub fn code_at(secret: &[u8], unix_seconds: u64) -> String {
    code_for_counter(secret, unix_seconds / STEP_SECONDS)
}

fn code_for_counter(secret: &[u8], counter: u64) -> String {
    let mac = Active::hmac_sha1(secret, &counter.to_be_bytes());
    // RFC 4226 dynamic truncation.
    let offset = usize::from(mac[19] & 0x0f);
    let binary = u32::from_be_bytes([
        mac[offset] & 0x7f,
        mac[offset + 1],
        mac[offset + 2],
        mac[offset + 3],
    ]);
    format!("{:0width$}", binary % 1_000_000, width = DIGITS)
}

/// Checks `code` against the steps before, at and after `unix_seconds`, so one step of clock drift
/// either way is tolerated and no more. Every candidate is compared in constant time and
/// none is skipped once one matches.
pub fn verify(secret: &[u8], code: &str, unix_seconds: u64) -> bool {
    verify_step(secret, code, unix_seconds).is_some()
}

/// [`verify`], returning the time step (the RFC 6238 counter) the code is for, so a caller can
/// refuse a code whose step was already used. When the code fits two neighbouring steps (about
/// one chance in 500,000) the earlier one is returned, so a replay of the same code always maps
/// to the same step.
pub fn verify_step(secret: &[u8], code: &str, unix_seconds: u64) -> Option<u64> {
    if code.len() != DIGITS || !code.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    let counter = unix_seconds / STEP_SECONDS;
    let candidates = [
        counter.checked_sub(1),
        Some(counter),
        counter.checked_add(1),
    ];
    let mut found = None;
    for candidate in candidates.into_iter().flatten() {
        let expected = code_for_counter(secret, candidate);
        if bool::from(expected.as_bytes().ct_eq(code.as_bytes())) {
            found = found.or(Some(candidate));
        }
    }
    found
}

#[cfg(test)]
mod tests {
    use super::*;

    // RFC 6238 appendix B, the SHA-1 secret, shown here as its 6 low digits.
    const SECRET: &[u8] = b"12345678901234567890";

    #[test]
    fn rfc6238_vectors() {
        for (time, code) in [
            (59u64, "287082"),
            (1_111_111_109, "081804"),
            (1_111_111_111, "050471"),
            (1_234_567_890, "005924"),
            (2_000_000_000, "279037"),
            (20_000_000_000, "353130"),
        ] {
            assert_eq!(code_at(SECRET, time), code, "t = {time}");
        }
    }

    #[test]
    fn a_whole_step_gives_one_code() {
        assert_eq!(code_at(SECRET, 30), code_at(SECRET, 59));
        assert_ne!(code_at(SECRET, 59), code_at(SECRET, 60));
    }

    #[test]
    fn codes_are_six_digits_with_leading_zeros() {
        assert_eq!(code_at(SECRET, 1_234_567_890).len(), 6);
        assert_eq!(code_at(SECRET, 1_111_111_109), "081804");
    }

    #[test]
    fn accepts_the_previous_current_and_next_step_only() {
        let now = 1_700_000_000u64;
        for step in [-1i64, 0, 1] {
            let t = now.checked_add_signed(step * 30).expect("in range");
            assert!(verify(SECRET, &code_at(SECRET, t), now), "step {step}");
        }
        for step in [-2i64, 2, 10] {
            let t = now.checked_add_signed(step * 30).expect("in range");
            assert!(!verify(SECRET, &code_at(SECRET, t), now), "step {step}");
        }
    }

    #[test]
    fn the_matching_step_is_returned() {
        let now = 1_700_000_000u64;
        let counter = now / 30;
        for (offset, step) in [(-30i64, counter - 1), (0, counter), (30, counter + 1)] {
            let t = now.checked_add_signed(offset).expect("in range");
            assert_eq!(
                verify_step(SECRET, &code_at(SECRET, t), now),
                Some(step),
                "offset {offset}"
            );
        }
        assert_eq!(verify_step(SECRET, &code_at(SECRET, now + 90), now), None);
        assert_eq!(verify_step(SECRET, "12345", now), None);
        // Time zero has no step before it.
        assert_eq!(verify_step(SECRET, &code_at(SECRET, 0), 0), Some(0));
    }

    #[test]
    fn rejects_wrong_malformed_and_wrongly_keyed_codes() {
        let now = 59u64;
        assert!(verify(SECRET, "287082", now));
        assert!(!verify(SECRET, "287083", now));
        assert!(!verify(b"another secret", "287082", now));
        for bad in [
            "", "28708", "2870822", "28708a", " 87082", "+87082", "28 082",
        ] {
            assert!(!verify(SECRET, bad, now), "{bad:?}");
        }
    }

    #[test]
    fn works_at_the_very_start_and_end_of_time() {
        // No step before zero, and no overflow after the last one.
        assert!(verify(SECRET, &code_at(SECRET, 0), 0));
        assert!(verify(SECRET, &code_at(SECRET, 30), 0));
        assert!(verify(SECRET, &code_at(SECRET, u64::MAX), u64::MAX));
    }
}
