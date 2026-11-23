//! The normalisation of `docs/crypto.md`, "Duplicate tags": how raw item values become the
//! canonical values a tag hashes. Every client must produce the same strings, or one item gets two
//! tags, so each rule here is the document's, and `test-vectors/dedup-normalise.json` pins them.
//!
//! - **Lower case** is each code point's *simple* lowercase mapping (UnicodeData field 13): no
//!   SpecialCasing and no final-sigma rule. `İ` (U+0130) becomes `i`, `Σ` always becomes `σ`, `ẞ`
//!   becomes `ß`, and `ß` stays `ß`. Rust's [`char::to_lowercase`] is the full mapping, which
//!   differs from the simple one in exactly one place, U+0130 (SpecialCasing's only unconditional
//!   lowercase entry, `i` followed by U+0307), and a test below walks every code point to keep it
//!   so. [`str::to_lowercase`] is never used: it applies the final-sigma rule.
//! - **NFC** is Unicode normalisation form C, from `unicode-normalization`.
//! - **Trimming** removes characters with the Unicode `White_Space` property ([`str::trim`]).
//!   U+FEFF is not one of them.

use unicode_normalization::UnicodeNormalization as _;

/// The simple lowercase mapping of one code point.
fn simple_lower(c: char) -> char {
    if c == '\u{130}' {
        return 'i';
    }
    let mut mapped = c.to_lowercase();
    match (mapped.next(), mapped.next()) {
        (Some(lower), None) => lower,
        // Unreachable but for U+0130, handled above; a code point with no single mapping stays.
        _ => c,
    }
}

/// `s` with every code point lower-cased by its simple mapping.
pub fn lower(s: &str) -> String {
    s.chars().map(simple_lower).collect()
}

/// `s` in Unicode normalisation form C.
pub fn nfc(s: &str) -> String {
    s.nfc().collect()
}

/// A login's **username**: trimmed, NFC, lower case.
pub fn username(raw: &str) -> String {
    lower(&nfc(raw.trim()))
}

/// A login's **password**: exactly as typed.
pub fn password(raw: &str) -> String {
    raw.to_owned()
}

/// A passkey's **relying party**: lower case.
pub fn relying_party(raw: &str) -> String {
    lower(raw)
}

const B64URL: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

fn b64_value(c: u8) -> Option<u8> {
    match c {
        b'A'..=b'Z' => Some(c - b'A'),
        b'a'..=b'z' => Some(c - b'a' + 26),
        b'0'..=b'9' => Some(c - b'0' + 52),
        b'-' | b'+' => Some(62),
        b'_' | b'/' => Some(63),
        _ => None,
    }
}

/// A passkey's **credential id**: base64url without padding. The raw value may be padded and may
/// use the standard alphabet; it is decoded and written again. A value that isn't base64 can't be
/// made canonical and is returned as it is, trimmed.
pub fn credential_id(raw: &str) -> String {
    let text = raw.trim().trim_end_matches('=');
    // One leftover character can't hold a byte: not base64.
    if text.len() % 4 == 1 {
        return raw.trim().to_owned();
    }
    let mut bytes = Vec::with_capacity(text.len() * 3 / 4);
    let mut acc: u32 = 0;
    let mut bits = 0u32;
    for c in text.bytes() {
        let Some(v) = b64_value(c) else {
            return raw.trim().to_owned();
        };
        acc = (acc << 6) | u32::from(v);
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            bytes.push(u8::try_from((acc >> bits) & 0xff).unwrap_or(0));
            acc &= (1 << bits) - 1;
        }
    }
    let mut out = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for chunk in bytes.chunks(3) {
        let b = [
            chunk[0],
            *chunk.get(1).unwrap_or(&0),
            *chunk.get(2).unwrap_or(&0),
        ];
        let n = (u32::from(b[0]) << 16) | (u32::from(b[1]) << 8) | u32::from(b[2]);
        for i in 0..=chunk.len() {
            let index = usize::try_from((n >> (18 - 6 * i)) & 0x3f).unwrap_or(0);
            out.push(char::from(B64URL[index]));
        }
    }
    out
}

const B32: &[u8; 32] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

/// A code's **secret**: the decoded secret bytes, written again as RFC 4648 base32, upper case,
/// no padding. The raw value may have any case, spaces (or any white space) and `=` padding.
/// `None` when it isn't base32 or decodes to nothing.
pub fn secret(raw: &str) -> Option<String> {
    let mut bytes = Vec::with_capacity(raw.len() * 5 / 8);
    let mut acc: u32 = 0;
    let mut bits = 0u32;
    for c in raw.chars() {
        if c.is_whitespace() || c == '=' {
            continue;
        }
        let value = match c.to_ascii_uppercase() {
            u @ 'A'..='Z' => u32::from(u) - u32::from('A'),
            d @ '2'..='7' => u32::from(d) - u32::from('2') + 26,
            _ => return None,
        };
        acc = (acc << 5) | value;
        bits += 5;
        if bits >= 8 {
            bits -= 8;
            bytes.push(u8::try_from((acc >> bits) & 0xff).unwrap_or(0));
            acc &= (1 << bits) - 1;
        }
    }
    if bytes.is_empty() {
        return None;
    }
    let mut out = String::with_capacity(bytes.len().div_ceil(5) * 8);
    for chunk in bytes.chunks(5) {
        let mut buf = [0u8; 5];
        buf[..chunk.len()].copy_from_slice(chunk);
        let n = buf
            .iter()
            .fold(0u64, |acc, byte| (acc << 8) | u64::from(*byte));
        let chars = (chunk.len() * 8).div_ceil(5);
        for i in 0..chars {
            let index = usize::try_from((n >> (35 - 5 * i)) & 0x1f).unwrap_or(0);
            out.push(char::from(B32[index]));
        }
    }
    Some(out)
}

/// A card's **number**: its ASCII digits only.
pub fn card_number(raw: &str) -> String {
    raw.chars().filter(char::is_ascii_digit).collect()
}

fn digits(s: &str) -> Option<u32> {
    let s = s.trim();
    if s.is_empty() || !s.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    s.parse().ok()
}

/// A card's **expiry** from its month and year: `YYYY-MM`, or `""` when either is unknown. A
/// month is 1 to 12; a year is two digits (the 2000s) or four.
pub fn expiry(month: &str, year: &str) -> String {
    let month = digits(month).filter(|m| (1..=12).contains(m));
    let year = match (digits(year), year.trim().len()) {
        (Some(y), 2) => Some(2000 + y),
        (Some(y), 4) => Some(y),
        _ => None,
    };
    match (year, month) {
        (Some(y), Some(m)) => format!("{y:04}-{m:02}"),
        _ => String::new(),
    }
}

/// [`expiry`] from one text: `YYYY-MM`, `YYYY/MM`, `MM/YY`, `MM/YYYY` or `MM-YY`.
pub fn expiry_text(raw: &str) -> String {
    let Some((a, b)) = raw.trim().split_once(['/', '-']) else {
        return String::new();
    };
    if a.trim().len() == 4 {
        expiry(b, a)
    } else {
        expiry(a, b)
    }
}

/// A note's **text**: NFC; CRLF and lone CR become LF; spaces and tabs at the end of each line
/// removed; blank lines at the end removed.
pub fn note(raw: &str) -> String {
    let text = nfc(raw).replace("\r\n", "\n").replace('\r', "\n");
    let mut lines: Vec<&str> = text
        .split('\n')
        .map(|line| line.trim_end_matches([' ', '\t']))
        .collect();
    while lines.last().is_some_and(|line| line.is_empty()) {
        lines.pop();
    }
    lines.join("\n")
}

/// A key's **fingerprint**: an SSH key's OpenSSH `SHA256:…` fingerprint as it is, or a PGP key's
/// v4 (40 digits) or v6 (64 digits) fingerprint as upper-case hex. `None` for anything else.
pub fn fingerprint(raw: &str) -> Option<String> {
    let text = raw.trim();
    if let Some(rest) = text.strip_prefix("SHA256:") {
        return (!rest.is_empty()).then(|| text.to_owned());
    }
    let squeezed: String = text
        .chars()
        .filter(|c| !c.is_whitespace() && *c != ':')
        .collect::<String>()
        .to_ascii_uppercase();
    let hex = squeezed.strip_prefix("0X").unwrap_or(&squeezed);
    let right_length = hex.len() == 40 || hex.len() == 64;
    (right_length && hex.bytes().all(|b| b.is_ascii_hexdigit())).then(|| hex.to_owned())
}

/// A set of **backup codes**: each trimmed, empty ones and duplicates dropped, sorted by code
/// point (which is the order of their UTF-8 bytes).
pub fn codes<S: AsRef<str>>(raw: &[S]) -> Vec<String> {
    let mut out: Vec<String> = raw
        .iter()
        .map(|code| code.as_ref().trim().to_owned())
        .filter(|code| !code.is_empty())
        .collect();
    out.sort();
    out.dedup();
    out
}

/// An identity's **full name** or **email**: trimmed, NFC, lower case.
pub fn identity_text(raw: &str) -> String {
    username(raw)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lower_is_the_simple_mapping() {
        assert_eq!(lower("\u{130}stanbul"), "istanbul");
        assert_eq!(lower("\u{3a3}\u{391}\u{3a3}"), "\u{3c3}\u{3b1}\u{3c3}");
        assert_eq!(lower("\u{1e9e}"), "\u{df}");
        assert_eq!(lower("Stra\u{df}e"), "stra\u{df}e");
        assert_eq!(lower("STRASSE"), "strasse");
        assert_ne!(lower("Stra\u{df}e"), lower("STRASSE"));
    }

    #[test]
    fn only_u0130_has_a_multi_character_lowercase() {
        // The reason `simple_lower` can lean on `char::to_lowercase`.
        for c in (0..=0x10ffff).filter_map(char::from_u32) {
            let count = c.to_lowercase().count();
            if c == '\u{130}' {
                assert_eq!(count, 2);
            } else {
                assert_eq!(count, 1, "U+{:04X}", u32::from(c));
            }
        }
    }

    #[test]
    fn usernames_are_trimmed_composed_and_lower() {
        assert_eq!(username("  Alice\t"), "alice");
        assert_eq!(username("Cafe\u{301}"), "caf\u{e9}");
        assert_eq!(username("Caf\u{c9}"), "caf\u{e9}");
        assert_eq!(username("\u{a0}\u{3000}Bob\u{2003}"), "bob");
        // U+FEFF is not White_Space.
        assert_eq!(username("\u{feff}Bob"), "\u{feff}bob");
    }

    #[test]
    fn passwords_are_untouched() {
        assert_eq!(password("  Hunter2 \u{301}"), "  Hunter2 \u{301}");
    }

    #[test]
    fn secrets_are_base32_whatever_the_input_looks_like() {
        let canonical = Some("JBSWY3DPEHPK3PXP".to_owned());
        assert_eq!(secret("JBSWY3DPEHPK3PXP"), canonical);
        assert_eq!(secret("jbsw y3dp ehpk 3pxp"), canonical);
        assert_eq!(secret("jbswy3dpehpk3pxp======"), canonical);
        assert_eq!(secret("MFRGG==="), Some("MFRGG".to_owned()));
        assert_eq!(secret("mfrgg"), Some("MFRGG".to_owned()));
        assert_eq!(secret("MFRGGZDF"), Some("MFRGGZDF".to_owned()));
        assert_eq!(secret(""), None);
        assert_eq!(secret("not base32!"), None);
        assert_eq!(secret("1189"), None);
    }

    #[test]
    fn credential_ids_are_base64url_without_padding() {
        assert_eq!(credential_id("-__-"), "-__-");
        assert_eq!(credential_id("+//+"), "-__-");
        assert_eq!(
            credential_id("dGVzdC1jcmVkZW50aWFs"),
            "dGVzdC1jcmVkZW50aWFs"
        );
        assert_eq!(credential_id("dGVzdA=="), "dGVzdA");
        assert_eq!(credential_id(" dGVzdA "), "dGVzdA");
        assert_eq!(credential_id("dGVzdA"), "dGVzdA");
        // Not base64: left alone.
        assert_eq!(credential_id("not base64!"), "not base64!");
        assert_eq!(credential_id("a"), "a");
    }

    #[test]
    fn card_numbers_keep_ascii_digits() {
        assert_eq!(card_number("4111 1111-1111 1111"), "4111111111111111");
        assert_eq!(card_number("\u{664}111"), "111");
    }

    #[test]
    fn expiry_is_year_dash_month_or_empty() {
        assert_eq!(expiry("9", "2030"), "2030-09");
        assert_eq!(expiry("12", "30"), "2030-12");
        assert_eq!(expiry(" 01 ", " 2031 "), "2031-01");
        assert_eq!(expiry("13", "2030"), "");
        assert_eq!(expiry("0", "2030"), "");
        assert_eq!(expiry("5", "203"), "");
        assert_eq!(expiry("", ""), "");
        assert_eq!(expiry("5", "20x0"), "");
        assert_eq!(expiry_text("2030-09"), "2030-09");
        assert_eq!(expiry_text("09/30"), "2030-09");
        assert_eq!(expiry_text("9/2030"), "2030-09");
        assert_eq!(expiry_text("2030/9"), "2030-09");
        assert_eq!(expiry_text("soon"), "");
    }

    #[test]
    fn notes_lose_carriage_returns_and_trailing_blanks() {
        assert_eq!(
            note("line one  \r\nline two\t\r\n\r\n  \r\n"),
            "line one\nline two"
        );
        assert_eq!(note("a\rb\r\rc"), "a\nb\n\nc");
        assert_eq!(note("\n\n a \n"), "\n\n a");
        assert_eq!(note("  \n\t\n"), "");
        assert_eq!(note("cafe\u{301}"), "caf\u{e9}");
        // Leading white space and inner blank lines stay.
        assert_eq!(note("  x\n\n y  "), "  x\n\n y");
    }

    #[test]
    fn fingerprints_are_ssh_as_is_or_pgp_hex() {
        assert_eq!(
            fingerprint(" SHA256:AbC+/123 "),
            Some("SHA256:AbC+/123".to_owned())
        );
        let v4 = "9f3a 77c1 0b2e 45d6 8a19  c0de 12f4 5b6a 7788 9900";
        assert_eq!(
            fingerprint(v4),
            Some("9F3A77C10B2E45D68A19C0DE12F45B6A77889900".to_owned())
        );
        assert_eq!(
            fingerprint("0x9F3A77C10B2E45D68A19C0DE12F45B6A77889900"),
            Some("9F3A77C10B2E45D68A19C0DE12F45B6A77889900".to_owned())
        );
        assert_eq!(fingerprint(&"ab".repeat(32)), Some("AB".repeat(32)));
        assert_eq!(fingerprint("SHA256:"), None);
        assert_eq!(fingerprint("MD5:aa:bb"), None);
        assert_eq!(fingerprint("zz"), None);
    }

    #[test]
    fn backup_codes_are_trimmed_unique_and_sorted() {
        assert_eq!(
            codes(&[" 2222", "1111", "2222 ", "", "3333", "11111"]),
            ["1111", "11111", "2222", "3333"]
        );
        assert!(codes::<&str>(&[]).is_empty());
        // By code point, not by locale.
        assert_eq!(codes(&["b", "B", "\u{e9}", "a"]), ["B", "a", "b", "\u{e9}"]);
    }

    #[test]
    fn identity_text_is_a_username() {
        assert_eq!(identity_text(" Alice M\u{dc}ller "), "alice m\u{fc}ller");
    }
}
