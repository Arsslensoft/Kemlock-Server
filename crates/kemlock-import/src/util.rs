// Partly ported from Bitwarden's clients (https://github.com/bitwarden/clients):
//   libs/importer/src/importers/base-importer.ts
//   libs/importer/src/importers/keeper/keeper-importer.ts,
//   at commit f9c68e008ba91dc19edf519305a82d3a994a7baa.
// Copyright (C) Bitwarden Inc. Licensed GPL-3.0-only; combined here into kemlock-import, which is
// AGPL-3.0-only, as the GPL-3.0 permits. See the crate's NOTICE.

//! Helpers the parsers share: Bitwarden's `BaseImporter` (blank checks, URI fixing, key-value
//! fields that spill into the note, names, card expiry), reading JSON loosely, and dates.

use std::borrow::Cow;

use serde_json::Value;

use crate::model::{Card, CustomField, FieldKind, Login, UriRule};

// ---------------------------------------------------------------------------------------------
// Text
// ---------------------------------------------------------------------------------------------

/// The text of a file: UTF-8 (lossy), or UTF-16 with a byte-order mark; a UTF-8 mark is dropped.
pub fn decode_text(bytes: &[u8]) -> Cow<'_, str> {
    if let Some(rest) = bytes.strip_prefix(&[0xEF, 0xBB, 0xBF]) {
        return String::from_utf8_lossy(rest);
    }
    let little = bytes.starts_with(&[0xFF, 0xFE]);
    let big = bytes.starts_with(&[0xFE, 0xFF]);
    if little || big {
        let units = bytes
            .get(2..)
            .unwrap_or(&[])
            .as_chunks::<2>()
            .0
            .iter()
            .map(|pair| {
                let (a, b) = (pair[0], pair[1]);
                if little {
                    u16::from_le_bytes([a, b])
                } else {
                    u16::from_be_bytes([a, b])
                }
            });
        let text: String = char::decode_utf16(units)
            .map(|c| c.unwrap_or(char::REPLACEMENT_CHARACTER))
            .collect();
        return Cow::Owned(text);
    }
    String::from_utf8_lossy(bytes)
}

/// `Utils.isNullOrWhitespace`.
pub fn is_blank(s: &str) -> bool {
    s.trim().is_empty()
}

/// The text unless it is missing or only whitespace: `getValueOrDefault(str)`.
pub fn nonblank(s: Option<&str>) -> Option<String> {
    s.filter(|s| !is_blank(s)).map(|s| s.to_string())
}

/// `getValueOrDefault(str, default)`.
pub fn or_default(s: Option<&str>, default: &str) -> String {
    nonblank(s).unwrap_or_else(|| default.to_string())
}

/// `cleanupCipher`'s name rule: a blank name is `--`.
pub fn clean_name(name: Option<&str>) -> String {
    or_default(name, "--")
}

/// A note that is only whitespace is no note.
pub fn clean_notes(notes: Option<String>) -> Option<String> {
    notes.filter(|n| !is_blank(n))
}

/// Splits on `\r\n`, `\r` and `\n`.
pub fn split_newlines(s: &str) -> Vec<&str> {
    let mut out = Vec::new();
    let mut rest = s;
    while let Some(at) = rest.find(['\r', '\n']) {
        out.push(&rest[..at]);
        let after = &rest[at..];
        let skip = if after.starts_with("\r\n") { 2 } else { 1 };
        rest = &after[skip..];
    }
    out.push(rest);
    out
}

/// Line breaks as `\n`.
pub fn normalise_newlines(s: &str) -> String {
    split_newlines(s).join("\n")
}

/// Whether the text has a line break.
pub fn has_newline(s: &str) -> bool {
    s.contains(['\r', '\n'])
}

/// Adds `name: value` to a note, as Bitwarden's `processKvp` does for a value too long or too
/// tall for a field.
pub fn append_note(notes: &mut Option<String>, name: &str, value: &str) {
    let note = notes.get_or_insert_with(String::new);
    note.push_str(name);
    note.push_str(": ");
    note.push_str(&normalise_newlines(value));
    note.push('\n');
}

/// `processKvp`: a custom field, or, when the value is over 200 characters or has a line break, a
/// line of the note. A blank value adds nothing.
pub fn kvp(
    fields: &mut Vec<CustomField>,
    notes: &mut Option<String>,
    key: &str,
    value: &str,
    kind: FieldKind,
) {
    if is_blank(value) {
        return;
    }
    let key = if is_blank(key) { "" } else { key };
    if value.chars().count() > 200 || has_newline(value.trim()) {
        append_note(notes, key, value);
    } else {
        fields.push(CustomField {
            name: key.to_string(),
            value: value.to_string(),
            kind,
        });
    }
}

/// A custom field added as it is (Keeper's `addField`): nothing when the value is empty.
pub fn add_field(fields: &mut Vec<CustomField>, name: &str, value: &str, kind: FieldKind) {
    if value.is_empty() {
        return;
    }
    fields.push(CustomField {
        name: name.to_string(),
        value: value.to_string(),
        kind,
    });
}

/// `Name Middle Last` as Bitwarden's `getFullName` splits it, on single spaces: one part is the
/// first name, two are first and last, three or more give a middle name and a last one with the
/// rest.
pub fn full_name(full: &str) -> (Option<String>, Option<String>, Option<String>) {
    if is_blank(full) {
        return (None, None, None);
    }
    let parts: Vec<&str> = full.split(' ').collect();
    let first = nonblank(parts.first().copied());
    match parts.len() {
        1 => (first, None, None),
        2 => (first, None, nonblank(parts.get(1).copied())),
        _ => (
            first,
            nonblank(parts.get(1).copied()),
            Some(parts[2..].join(" ")),
        ),
    }
}

/// `Name Middle Last` as Proton Pass's `processNames` splits it, on runs of whitespace: the first
/// and last words, and what lies between as the middle name.
pub fn split_name_words(full: &str) -> (Option<String>, Option<String>, Option<String>) {
    let parts: Vec<&str> = full.split_whitespace().collect();
    match parts.len() {
        0 => (None, None, None),
        1 => (Some(parts[0].to_string()), None, None),
        2 => (Some(parts[0].to_string()), None, Some(parts[1].to_string())),
        n => (
            Some(parts[0].to_string()),
            Some(parts[1..n - 1].join(" ")),
            Some(parts[n - 1].to_string()),
        ),
    }
}

// ---------------------------------------------------------------------------------------------
// Websites
// ---------------------------------------------------------------------------------------------

/// `fixUri`: trimmed, `http://` put in front of an address with a dot and no scheme, cut to 1,000
/// characters. `None` when nothing is left.
pub fn fix_uri(uri: &str) -> Option<String> {
    let mut uri = uri.trim().to_string();
    if !uri.contains("://") && uri.contains('.') {
        uri = format!("http://{uri}");
    }
    if uri.chars().count() > 1000 {
        uri = uri.chars().take(1000).collect();
    }
    if is_blank(&uri) { None } else { Some(uri) }
}

/// `makeUriArray`: the fixed addresses that are left, with the default match rule.
pub fn make_uris<'a>(uris: impl IntoIterator<Item = &'a str>) -> Vec<UriRule> {
    uris.into_iter()
        .filter_map(fix_uri)
        .map(|uri| UriRule {
            uri,
            match_rule: None,
        })
        .collect()
}

/// The host of an address, lower case, without a port or credentials. `None` when there is none.
pub fn hostname(url: &str) -> Option<String> {
    let url = url.trim();
    let rest = match url.find("://") {
        Some(at) => &url[at + 3..],
        None => url,
    };
    let end = rest.find(['/', '?', '#']).unwrap_or(rest.len());
    let authority = &rest[..end];
    let host = match authority.rfind('@') {
        Some(at) => &authority[at + 1..],
        None => authority,
    };
    let host = if host.starts_with('[') {
        host
    } else {
        host.split(':').next().unwrap_or(host)
    };
    let host = host.trim().to_lowercase();
    if host.is_empty() { None } else { Some(host) }
}

/// `nameFromUrl`: the host without a leading `www.`.
pub fn name_from_url(url: &str) -> Option<String> {
    let host = hostname(url)?;
    Some(match host.strip_prefix("www.") {
        Some(rest) if !rest.is_empty() => rest.to_string(),
        _ => host,
    })
}

// ---------------------------------------------------------------------------------------------
// Logins
// ---------------------------------------------------------------------------------------------

/// `convertToNoteIfNeeded`: a login with no username, no password and no address is a note.
pub fn is_noteworthy_login(login: &Login) -> bool {
    login.username.as_deref().is_none_or(is_blank)
        && login.password.as_deref().is_none_or(is_blank)
        && login.uris.is_empty()
}

// ---------------------------------------------------------------------------------------------
// Cards
// ---------------------------------------------------------------------------------------------

/// A card number without spaces and dashes; `None` when blank.
pub fn card_number(raw: &str) -> Option<String> {
    let number: String = raw
        .trim()
        .chars()
        .filter(|c| *c != ' ' && *c != '-')
        .collect();
    if number.is_empty() {
        None
    } else {
        Some(number)
    }
}

/// The brand from the leading digits: Visa, Mastercard, Amex, Discover, Diners, JCB, UnionPay or
/// Maestro; `None` when the number matches none.
pub fn card_brand(number: &str) -> Option<String> {
    let digits: String = number.chars().filter(char::is_ascii_digit).collect();
    let n2: u32 = digits.get(..2).and_then(|d| d.parse().ok()).unwrap_or(0);
    let n3: u32 = digits.get(..3).and_then(|d| d.parse().ok()).unwrap_or(0);
    let n4: u32 = digits.get(..4).and_then(|d| d.parse().ok()).unwrap_or(0);
    let brand = if digits.starts_with('4') {
        "Visa"
    } else if (51..=55).contains(&n2) || (2221..=2720).contains(&n4) {
        "Mastercard"
    } else if n2 == 34 || n2 == 37 {
        "Amex"
    } else if n4 == 6011 || n2 == 65 || (644..=649).contains(&n3) {
        "Discover"
    } else if (300..=305).contains(&n3) || n2 == 36 || n2 == 38 {
        "Diners"
    } else if (3528..=3589).contains(&n4) {
        "JCB"
    } else if n2 == 62 {
        "UnionPay"
    } else if [5018, 5020, 5038, 6304, 6759].contains(&n4) || (6761..=6763).contains(&n4) {
        "Maestro"
    } else {
        return None;
    };
    Some(brand.to_string())
}

/// A month number from `5` or `05`; 1 to 12.
pub fn parse_month(s: &str) -> Option<u8> {
    let n: u8 = s.trim().parse().ok()?;
    (1..=12).contains(&n).then_some(n)
}

/// A year from two digits (`29` is 2029) or four.
pub fn parse_year(s: &str) -> Option<u16> {
    let s = s.trim();
    let n: u16 = s.parse().ok()?;
    match s.len() {
        2 => Some(2000 + n),
        4 if (1900..=2999).contains(&n) => Some(n),
        _ => None,
    }
}

/// `setCardExpiration`: `M/YY`, `MM/YY`, `M/YYYY` or `MM/YYYY`, spaces ignored. False, with the
/// card untouched, for anything else.
pub fn set_card_expiration(card: &mut Card, expiration: &str) -> bool {
    let compact: String = expiration.chars().filter(|c| !c.is_whitespace()).collect();
    let Some((month, year)) = compact.split_once('/') else {
        return false;
    };
    let month_ok = matches!(month.len(), 1 | 2) && month.chars().all(|c| c.is_ascii_digit());
    let year_ok = match year.len() {
        2 => year.chars().all(|c| c.is_ascii_digit()),
        4 => {
            year.chars().all(|c| c.is_ascii_digit())
                && matches!(year.as_bytes().first(), Some(b'1' | b'2'))
        }
        _ => false,
    };
    if !month_ok || !year_ok {
        return false;
    }
    // `0?(1[0-2]|[1-9])`: "00" and "13" don't match.
    let (Some(m), Some(y)) = (parse_month(month), parse_year(year)) else {
        return false;
    };
    card.exp_month = Some(m);
    card.exp_year = Some(y);
    true
}

// ---------------------------------------------------------------------------------------------
// JSON, read loosely
// ---------------------------------------------------------------------------------------------

/// The string under `key`, when it is one.
pub fn jstr<'a>(v: &'a Value, key: &str) -> Option<&'a str> {
    v.get(key)?.as_str()
}

/// The array under `key`, or an empty one.
pub fn jarr<'a>(v: &'a Value, key: &str) -> &'a [Value] {
    v.get(key)
        .and_then(Value::as_array)
        .map(Vec::as_slice)
        .unwrap_or(&[])
}

/// The integer under `key`; a whole float counts, as a JavaScript number does.
pub fn jint(v: &Value, key: &str) -> Option<i64> {
    as_int(v.get(key)?)
}

/// The integer a JSON number or numeric string holds.
pub fn as_int(v: &Value) -> Option<i64> {
    match v {
        Value::Number(n) => n.as_i64().or_else(|| {
            n.as_f64()
                .filter(|f| f.is_finite() && f.fract() == 0.0 && f.abs() < 9.0e15)
                .map(|f| f as i64)
        }),
        Value::String(s) => s.trim().parse().ok(),
        _ => None,
    }
}

/// The boolean under `key`.
pub fn jbool(v: &Value, key: &str) -> Option<bool> {
    v.get(key)?.as_bool()
}

/// A scalar as text, as JavaScript's `String(v)` would show it: strings as they are, numbers and
/// booleans written out, `None` for null, arrays and objects.
pub fn scalar_text(v: &Value) -> Option<String> {
    match v {
        Value::String(s) => Some(s.clone()),
        Value::Number(n) => Some(n.to_string()),
        Value::Bool(b) => Some(b.to_string()),
        _ => None,
    }
}

// ---------------------------------------------------------------------------------------------
// Dates
// ---------------------------------------------------------------------------------------------

/// Days since 1970-01-01 of a calendar date (proleptic Gregorian).
pub fn days_from_civil(year: i64, month: i64, day: i64) -> i64 {
    let y = if month <= 2 { year - 1 } else { year };
    let era = (if y >= 0 { y } else { y - 399 }) / 400;
    let yoe = y - era * 400;
    let mp = if month > 2 { month - 3 } else { month + 9 };
    let doy = (153 * mp + 2) / 5 + day - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

/// The calendar date of a day count since 1970-01-01.
pub fn civil_from_days(days: i64) -> (i64, i64, i64) {
    let z = days + 719_468;
    let era = (if z >= 0 { z } else { z - 146_096 }) / 146_097;
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    (if m <= 2 { y + 1 } else { y }, m, d)
}

/// `yyyy-mm-dd` for epoch milliseconds, in UTC; `None` outside years 0 to 9999.
pub fn ymd_from_ms(ms: i64) -> Option<String> {
    let (y, m, d) = civil_from_days(ms.div_euclid(86_400_000));
    if !(0..=9999).contains(&y) {
        return None;
    }
    Some(format!("{y:04}-{m:02}-{d:02}"))
}

/// Epoch milliseconds of an ISO 8601 / RFC 3339 time such as `2024-01-02T03:04:05.678Z`, or of a
/// date alone. `None` when the text isn't one.
pub fn parse_iso_ms(text: &str) -> Option<i64> {
    let s = text.trim();
    let year: i64 = s.get(0..4)?.parse().ok()?;
    let month: i64 = s.get(5..7)?.parse().ok()?;
    let day: i64 = s.get(8..10)?.parse().ok()?;
    if s.get(4..5)? != "-" || s.get(7..8)? != "-" {
        return None;
    }
    if !(1..=12).contains(&month) || !(1..=31).contains(&day) {
        return None;
    }
    let mut seconds = days_from_civil(year, month, day) * 86_400;
    let mut millis = 0i64;
    let mut rest = s.get(10..)?;
    if let Some(time) = rest.strip_prefix(['T', ' ']) {
        let hour: i64 = time.get(0..2)?.parse().ok()?;
        let minute: i64 = time.get(3..5)?.parse().ok()?;
        if hour > 23 || minute > 59 {
            return None;
        }
        seconds += hour * 3600 + minute * 60;
        rest = time.get(5..)?;
        if let Some(after) = rest.strip_prefix(':') {
            let second: i64 = after.get(0..2)?.parse().ok()?;
            if second > 60 {
                return None;
            }
            seconds += second;
            rest = after.get(2..)?;
            if let Some(frac) = rest.strip_prefix('.') {
                let digits: String = frac.chars().take_while(char::is_ascii_digit).collect();
                let kept: String = digits.chars().take(3).collect();
                if kept.is_empty() {
                    return None;
                }
                millis = kept.parse::<i64>().ok()? * 10i64.pow(3 - kept.len() as u32);
                rest = frac.get(digits.len()..)?;
            }
        }
    }
    let offset_minutes = match rest {
        "" | "Z" | "z" => 0,
        tz => {
            let sign = match tz.get(0..1)? {
                "+" => 1,
                "-" => -1,
                _ => return None,
            };
            let hours: i64 = tz.get(1..3)?.parse().ok()?;
            let rest = tz.get(3..)?;
            let rest = rest.strip_prefix(':').unwrap_or(rest);
            let minutes: i64 = if rest.is_empty() {
                0
            } else {
                rest.get(0..2)?.parse().ok()?
            };
            sign * (hours * 60 + minutes)
        }
    };
    Some((seconds - offset_minutes * 60) * 1000 + millis)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decodes_utf8_with_and_without_a_mark_and_utf16() {
        assert_eq!(decode_text(b"\xEF\xBB\xBFabc"), "abc");
        assert_eq!(decode_text("héllo".as_bytes()), "héllo");
        let le: Vec<u8> = [0xFF, 0xFE]
            .into_iter()
            .chain("hi é".encode_utf16().flat_map(u16::to_le_bytes))
            .collect();
        assert_eq!(decode_text(&le), "hi é");
        let be: Vec<u8> = [0xFE, 0xFF]
            .into_iter()
            .chain("hi".encode_utf16().flat_map(u16::to_be_bytes))
            .collect();
        assert_eq!(decode_text(&be), "hi");
        // Invalid bytes don't fail the read.
        assert!(decode_text(&[b'a', 0xFF, b'b']).contains('a'));
    }

    #[test]
    fn blank_checks() {
        assert!(is_blank("  \t\n"));
        assert_eq!(nonblank(Some(" x ")).as_deref(), Some(" x "));
        assert_eq!(nonblank(Some("  ")), None);
        assert_eq!(nonblank(None), None);
        assert_eq!(or_default(Some(""), "--"), "--");
        assert_eq!(clean_name(None), "--");
        assert_eq!(clean_notes(Some("  ".into())), None);
    }

    #[test]
    fn newlines_split_and_join() {
        assert_eq!(split_newlines("a\r\nb\rc\nd"), ["a", "b", "c", "d"]);
        assert_eq!(normalise_newlines("a\r\nb\rc"), "a\nb\nc");
        assert_eq!(split_newlines(""), [""]);
    }

    #[test]
    fn kvp_makes_fields_and_spills_long_or_tall_values_into_the_note() {
        let mut fields = Vec::new();
        let mut notes = None;
        kvp(&mut fields, &mut notes, "PIN", "1234", FieldKind::Hidden);
        kvp(&mut fields, &mut notes, "Blank", "  ", FieldKind::Text);
        kvp(&mut fields, &mut notes, "Tall", "a\r\nb", FieldKind::Text);
        kvp(
            &mut fields,
            &mut notes,
            "Long",
            &"x".repeat(201),
            FieldKind::Text,
        );
        kvp(&mut fields, &mut notes, " ", "v", FieldKind::Text);
        assert_eq!(fields.len(), 2);
        assert_eq!(fields[0].name, "PIN");
        assert_eq!(fields[0].kind, FieldKind::Hidden);
        assert_eq!(fields[1].name, "");
        let notes = notes.expect("a note");
        assert!(notes.starts_with("Tall: a\nb\nLong: xxx"));
        assert!(notes.ends_with('\n'));
    }

    #[test]
    fn names_split_as_bitwarden_does() {
        assert_eq!(full_name("Ada"), (Some("Ada".into()), None, None));
        assert_eq!(
            full_name("Ada Lovelace"),
            (Some("Ada".into()), None, Some("Lovelace".into()))
        );
        assert_eq!(
            full_name("Ada King Lovelace Byron"),
            (
                Some("Ada".into()),
                Some("King".into()),
                Some("Lovelace Byron".into())
            )
        );
        assert_eq!(full_name(" "), (None, None, None));
        assert_eq!(
            split_name_words("Ada  Augusta King Lovelace"),
            (
                Some("Ada".into()),
                Some("Augusta King".into()),
                Some("Lovelace".into())
            )
        );
        assert_eq!(split_name_words(""), (None, None, None));
    }

    #[test]
    fn uris_are_fixed() {
        assert_eq!(
            fix_uri(" example.com ").as_deref(),
            Some("http://example.com")
        );
        assert_eq!(fix_uri("https://a.b/c").as_deref(), Some("https://a.b/c"));
        assert_eq!(fix_uri("localhost").as_deref(), Some("localhost"));
        assert_eq!(fix_uri("   "), None);
        assert_eq!(
            fix_uri(&"a".repeat(2000)).map(|u| u.chars().count()),
            Some(1000)
        );
        let uris = make_uris(["a.com", " ", "https://b.example"]);
        assert_eq!(uris.len(), 2);
        assert_eq!(uris[0].uri, "http://a.com");
    }

    #[test]
    fn hostnames() {
        assert_eq!(
            hostname("https://User:pw@WWW.Example.com:8443/a?b#c").as_deref(),
            Some("www.example.com")
        );
        assert_eq!(
            hostname("androidapp://com.example.app").as_deref(),
            Some("com.example.app")
        );
        assert_eq!(hostname("example.org/x").as_deref(), Some("example.org"));
        assert_eq!(hostname(""), None);
        assert_eq!(
            name_from_url("https://www.example.com/x").as_deref(),
            Some("example.com")
        );
        assert_eq!(
            name_from_url("http://sub.example.com").as_deref(),
            Some("sub.example.com")
        );
        assert_eq!(name_from_url("https://www."), Some("www.".to_string()));
    }

    #[test]
    fn a_login_with_nothing_to_sign_in_with_is_a_note() {
        let mut login = Login::default();
        assert!(is_noteworthy_login(&login));
        login.username = Some(" ".into());
        assert!(is_noteworthy_login(&login));
        login.uris = make_uris(["a.com"]);
        assert!(!is_noteworthy_login(&login));
    }

    #[test]
    fn card_numbers_and_brands() {
        assert_eq!(
            card_number(" 4111 1111-1111 1111 ").as_deref(),
            Some("4111111111111111")
        );
        assert_eq!(card_number(" "), None);
        assert_eq!(card_brand("4111111111111111").as_deref(), Some("Visa"));
        assert_eq!(
            card_brand("5555555555554444").as_deref(),
            Some("Mastercard")
        );
        assert_eq!(
            card_brand("2223003122003222").as_deref(),
            Some("Mastercard")
        );
        assert_eq!(card_brand("378282246310005").as_deref(), Some("Amex"));
        assert_eq!(card_brand("6011111111111117").as_deref(), Some("Discover"));
        assert_eq!(card_brand("30569309025904").as_deref(), Some("Diners"));
        assert_eq!(card_brand("3530111333300000").as_deref(), Some("JCB"));
        assert_eq!(card_brand("6200000000000005").as_deref(), Some("UnionPay"));
        assert_eq!(card_brand("5018000000000009").as_deref(), Some("Maestro"));
        assert_eq!(card_brand("1234"), None);
        assert_eq!(card_brand(""), None);
    }

    #[test]
    fn card_expiry() {
        let mut card = Card::default();
        assert!(set_card_expiration(&mut card, "05/29"));
        assert_eq!((card.exp_month, card.exp_year), (Some(5), Some(2029)));
        assert!(set_card_expiration(&mut card, " 12 / 2031 "));
        assert_eq!((card.exp_month, card.exp_year), (Some(12), Some(2031)));
        let mut card = Card::default();
        for bad in [
            "", "13/29", "00/29", "5/3", "05/329", "05-29", "05/3029", "ab/cd", "123/45",
        ] {
            assert!(!set_card_expiration(&mut card, bad), "{bad}");
        }
        assert_eq!(card.exp_month, None);
        assert_eq!(parse_month("07"), Some(7));
        assert_eq!(parse_month("0"), None);
        assert_eq!(parse_year("29"), Some(2029));
        assert_eq!(parse_year("2029"), Some(2029));
        assert_eq!(parse_year("202"), None);
    }

    #[test]
    fn json_is_read_loosely() {
        let v: Value =
            serde_json::json!({"a": "x", "n": 5, "f": 6.0, "s": "7", "b": true, "l": [1]});
        assert_eq!(jstr(&v, "a"), Some("x"));
        assert_eq!(jstr(&v, "n"), None);
        assert_eq!(jint(&v, "n"), Some(5));
        assert_eq!(jint(&v, "f"), Some(6));
        assert_eq!(jint(&v, "s"), Some(7));
        assert_eq!(jint(&v, "a"), None);
        assert_eq!(jbool(&v, "b"), Some(true));
        assert_eq!(jarr(&v, "l").len(), 1);
        assert_eq!(jarr(&v, "missing").len(), 0);
        assert_eq!(scalar_text(&v["n"]).as_deref(), Some("5"));
        assert_eq!(scalar_text(&v["l"]), None);
    }

    #[test]
    fn dates() {
        assert_eq!(days_from_civil(1970, 1, 1), 0);
        assert_eq!(civil_from_days(0), (1970, 1, 1));
        assert_eq!(civil_from_days(days_from_civil(2024, 2, 29)), (2024, 2, 29));
        assert_eq!(
            civil_from_days(days_from_civil(1969, 12, 31)),
            (1969, 12, 31)
        );
        assert_eq!(parse_iso_ms("1970-01-01T00:00:00Z"), Some(0));
        assert_eq!(
            parse_iso_ms("2024-01-02T03:04:05.678Z"),
            Some(1_704_164_645_678)
        );
        assert_eq!(
            parse_iso_ms("2024-01-02T03:04:05.6Z"),
            Some(1_704_164_645_600)
        );
        assert_eq!(
            parse_iso_ms("2024-01-02T05:04:05+02:00"),
            Some(1_704_164_645_000)
        );
        assert_eq!(parse_iso_ms("2024-01-02"), Some(1_704_153_600_000));
        assert_eq!(parse_iso_ms("not a date"), None);
        assert_eq!(parse_iso_ms("2024-13-02"), None);
        assert_eq!(
            ymd_from_ms(1_704_164_645_678).as_deref(),
            Some("2024-01-02")
        );
        assert_eq!(ymd_from_ms(i64::MAX), None);
    }
}
