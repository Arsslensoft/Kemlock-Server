//! The five-word phrase both devices show for one approval request.
//!
//! The new device and the approving device must show the same words, so the person can tell a
//! request from the device in front of them from one an attacker made. The phrase comes from the
//! request's one-time public key: the first 65 bits of
//! `SHA-256("kemlock approval v1" ‖ public key)`, cut into five 13-bit groups, each taken modulo
//! 7776 as an index into EFF's large word list (the same list the Kemlock app's password
//! generator bundles). A 13-bit group has 8192 values, so the first 416 words come up a little
//! more often than the rest; with five words that costs about a tenth of a bit.
//!
//! The word list is EFF's, from <https://www.eff.org/dice>, under CC BY 3.0 US, one word per
//! line in the list's order.

use std::sync::OnceLock;

/// What the hash starts with.
pub const PHRASE_LABEL: &[u8] = b"kemlock approval v1";
/// Words in a phrase.
pub const PHRASE_WORDS: usize = 5;
/// Words in EFF's large list.
pub const WORD_COUNT: usize = 7776;

const BITS_PER_WORD: usize = 13;

fn words() -> &'static [&'static str] {
    static WORDS: OnceLock<Vec<&'static str>> = OnceLock::new();
    WORDS.get_or_init(|| {
        include_str!("eff_large_wordlist.txt")
            .lines()
            .map(str::trim)
            .filter(|w| !w.is_empty())
            .collect()
    })
}

/// The bytes to hash for a request's one-time public key.
pub fn phrase_input(public_key: &[u8]) -> Vec<u8> {
    let mut input = Vec::with_capacity(PHRASE_LABEL.len() + public_key.len());
    input.extend_from_slice(PHRASE_LABEL);
    input.extend_from_slice(public_key);
    input
}

/// The phrase for a digest of [`phrase_input`]: five words, lower case, joined by single spaces.
pub fn phrase_from_digest(digest: &[u8; 32]) -> String {
    // The first 72 bits; the top 65 of them are the phrase's.
    let head = digest[..9]
        .iter()
        .fold(0u128, |acc, byte| (acc << 8) | u128::from(*byte));
    let bits = head >> (72 - PHRASE_WORDS * BITS_PER_WORD);
    let list = words();
    let mut out = Vec::with_capacity(PHRASE_WORDS);
    for i in 0..PHRASE_WORDS {
        let shift = BITS_PER_WORD * (PHRASE_WORDS - 1 - i);
        let group = (bits >> shift) & ((1 << BITS_PER_WORD) - 1);
        // `group` is below 8192, so it fits a usize on every target.
        let index = usize::try_from(group).unwrap_or(0) % WORD_COUNT;
        out.push(list.get(index).copied().unwrap_or("abacus"));
    }
    out.join(" ")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_list_is_effs_7776_words() {
        let list = words();
        assert_eq!(list.len(), WORD_COUNT);
        assert_eq!(list[0], "abacus");
        assert_eq!(list[WORD_COUNT - 1], "zoom");
    }

    #[test]
    fn an_all_zero_digest_is_the_first_word_five_times() {
        assert_eq!(
            phrase_from_digest(&[0; 32]),
            "abacus abacus abacus abacus abacus"
        );
    }

    #[test]
    fn an_all_one_digest_wraps_each_group_into_the_list() {
        // 8191 mod 7776 = 415, the 416th word.
        assert_eq!(words()[415], "backed");
        assert_eq!(
            phrase_from_digest(&[0xff; 32]),
            "backed backed backed backed backed"
        );
    }

    #[test]
    fn only_the_first_65_bits_count() {
        let mut a = [0x5a; 32];
        let mut b = a;
        // Bits 65 to 71 of the first nine bytes, and everything after them.
        b[8] ^= 0x7f;
        b[20] ^= 0xff;
        assert_eq!(phrase_from_digest(&a), phrase_from_digest(&b));
        // The 65th bit is the top bit of byte 8: flipping it changes the last group.
        a[8] ^= 0x80;
        assert_ne!(phrase_from_digest(&a), phrase_from_digest(&b));
    }

    #[test]
    fn groups_are_read_most_significant_first() {
        // Group 0 is the top 13 bits: 0x0001 << 3 puts a 1 at the bottom of group 0.
        let mut digest = [0u8; 32];
        digest[1] = 0x08;
        let phrase = phrase_from_digest(&digest);
        assert_eq!(phrase, "abdomen abacus abacus abacus abacus");
    }

    #[test]
    fn the_input_is_the_label_then_the_key() {
        assert_eq!(
            phrase_input(&[1, 2]),
            b"kemlock approval v1\x01\x02".to_vec()
        );
    }
}
