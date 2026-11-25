//! Duplicate tags: keyed hashes of normalised values, so a device (or, if allowed, the server) can
//! group equal items without anyone learning the values.
//!
//! ```text
//! dedup key = HKDF(ikm = user key or space key, salt = absent,
//!                  info = "kemlock dedup v1" ‖ owner (17) ‖ u32be(key version), L = 32)
//! tag       = HMAC-SHA256(dedup key, canonical input)
//! ```
//!
//! The canonical input is a JSON array whose first element is the tag's name, followed by the
//! normalised values as strings, serialised as RFC 8785 (JCS) without whitespace. Tags are the
//! full 32 bytes.
//!
//! [`canonical_input`], [`tag`] and [`tag_for`] take values as they are. The functions that make
//! a tag from an item's raw values ([`login_tags`], [`secret_tag`], and so on) first normalise
//! them as `docs/crypto.md`'s "Normalisation" says, with the rules in [`normalise`] and [`site`];
//! `test-vectors/dedup-normalise.json` pins both.

pub mod normalise;
mod punycode;
pub mod site;

use zeroize::Zeroizing;

use crate::{
    Error,
    backend::{Active, Backend},
    keys::SecretKey,
    owner::Owner,
};

const KEY_INFO_LABEL: &[u8] = b"kemlock dedup v1";

/// The tag names of the design.
pub mod name {
    pub const CRED: &str = "cred";
    pub const ACCOUNT: &str = "account";
    pub const SECRET: &str = "secret";
    pub const PASSKEY: &str = "passkey";
    pub const CARD: &str = "card";
    pub const NOTE: &str = "note";
    pub const KEY: &str = "key";
    pub const IDENTITY: &str = "identity";
    pub const CODES: &str = "codes";
    /// A contact's email and phone (added with the contact person fields).
    pub const CONTACT: &str = "contact";
    /// An identity document's number (added with the identity documents).
    pub const DOCUMENT: &str = "document";
    /// A file's content hash (added with the `file` kind).
    pub const FILE: &str = "file";
}

/// The dedup key of one owner and key version, derived from its user key or space key.
pub fn dedup_key(
    owner_key: &SecretKey,
    owner: &Owner,
    key_version: u32,
) -> Result<SecretKey, Error> {
    dedup_key_in::<Active>(owner_key, owner, key_version)
}

pub(crate) fn dedup_key_in<B: Backend>(
    owner_key: &SecretKey,
    owner: &Owner,
    key_version: u32,
) -> Result<SecretKey, Error> {
    let mut info = Vec::with_capacity(KEY_INFO_LABEL.len() + 17 + 4);
    info.extend_from_slice(KEY_INFO_LABEL);
    info.extend_from_slice(&owner.to_bytes());
    info.extend_from_slice(&key_version.to_be_bytes());
    let mut out = Zeroizing::new([0u8; 32]);
    B::hkdf_sha256(owner_key.as_bytes(), None, &info, &mut *out)?;
    Ok(SecretKey::from_bytes(&out))
}

/// The canonical input: `[name, value, …]` as RFC 8785 JSON without whitespace.
pub fn canonical_input(name: &str, values: &[&str]) -> Vec<u8> {
    let mut out =
        Vec::with_capacity(2 + name.len() + values.iter().map(|v| v.len() + 3).sum::<usize>());
    out.push(b'[');
    push_json_string(&mut out, name);
    for value in values {
        out.push(b',');
        push_json_string(&mut out, value);
    }
    out.push(b']');
    out
}

/// A string as RFC 8785 serialises it: the two-character escapes for `"`, `\`, backspace, tab,
/// line feed, form feed and carriage return, `\u00xx` in lower case for the other control
/// characters, and every other character as itself in UTF-8.
fn push_json_string(out: &mut Vec<u8>, s: &str) {
    out.push(b'"');
    let mut buf = [0u8; 4];
    for c in s.chars() {
        match c {
            '"' => out.extend_from_slice(b"\\\""),
            '\\' => out.extend_from_slice(b"\\\\"),
            '\u{8}' => out.extend_from_slice(b"\\b"),
            '\t' => out.extend_from_slice(b"\\t"),
            '\n' => out.extend_from_slice(b"\\n"),
            '\u{c}' => out.extend_from_slice(b"\\f"),
            '\r' => out.extend_from_slice(b"\\r"),
            c if u32::from(c) < 0x20 => {
                out.extend_from_slice(format!("\\u{:04x}", u32::from(c)).as_bytes());
            }
            c => out.extend_from_slice(c.encode_utf8(&mut buf).as_bytes()),
        }
    }
    out.push(b'"');
}

/// `HMAC-SHA256(dedup key, canonical input)`.
pub fn tag(dedup_key: &SecretKey, canonical_input: &[u8]) -> [u8; 32] {
    Active::hmac_sha256(dedup_key.as_bytes(), canonical_input)
}

/// The tag of `name` over `values`, from the canonical input of both.
pub fn tag_for(dedup_key: &SecretKey, name: &str, values: &[&str]) -> [u8; 32] {
    tag(dedup_key, &canonical_input(name, values))
}

// ---- from raw values ----------------------------------------------------------------------

/// How a website of a login is matched, as the app stores it. Only `Regex` and `Never` matter
/// here: a website with either makes no tag, since it doesn't name one site.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MatchRule {
    Domain,
    Host,
    StartsWith,
    Exact,
    Regex,
    Never,
}

impl MatchRule {
    /// The rule named `name` (`domain`, `host`, `startsWith`, `exact`, `regex`, `never`, in any
    /// case); any other name is the default, `Domain`.
    pub fn parse(name: &str) -> MatchRule {
        match name.trim().to_ascii_lowercase().as_str() {
            "host" => MatchRule::Host,
            "startswith" | "starts-with" | "starts_with" => MatchRule::StartsWith,
            "exact" => MatchRule::Exact,
            "regex" => MatchRule::Regex,
            "never" => MatchRule::Never,
            _ => MatchRule::Domain,
        }
    }

    /// Whether a website with this rule makes a tag.
    pub fn makes_tag(self) -> bool {
        !matches!(self, MatchRule::Regex | MatchRule::Never)
    }
}

/// One website of a login: its address as written and its rule.
#[derive(Clone, Copy, Debug)]
pub struct Website<'a> {
    pub uri: &'a str,
    pub rule: MatchRule,
}

/// The sites of a login's websites: one per website that makes a tag and has a site, each once,
/// in code point order.
pub fn sites<S: AsRef<str>>(websites: &[Website<'_>], shared_hosts: &[S]) -> Vec<String> {
    let mut out: Vec<String> = websites
        .iter()
        .filter(|w| w.rule.makes_tag())
        .filter_map(|w| site::site(w.uri, shared_hosts))
        .collect();
    out.sort();
    out.dedup();
    out
}

/// The canonical inputs of a login's `cred` tags (site, username, password), one per site.
pub fn cred_inputs<S: AsRef<str>>(
    websites: &[Website<'_>],
    shared_hosts: &[S],
    username: &str,
    password: &str,
) -> Vec<Vec<u8>> {
    let username = normalise::username(username);
    let password = normalise::password(password);
    sites(websites, shared_hosts)
        .iter()
        .map(|s| canonical_input(name::CRED, &[s, &username, &password]))
        .collect()
}

/// The canonical inputs of a login's `account` tags (site, username), one per site. The device
/// matches on them and never uploads them.
pub fn account_inputs<S: AsRef<str>>(
    websites: &[Website<'_>],
    shared_hosts: &[S],
    username: &str,
) -> Vec<Vec<u8>> {
    let username = normalise::username(username);
    sites(websites, shared_hosts)
        .iter()
        .map(|s| canonical_input(name::ACCOUNT, &[s, &username]))
        .collect()
}

/// The canonical input of a code's `secret` tag; `None` when the secret isn't base32.
pub fn secret_input(secret: &str) -> Option<Vec<u8>> {
    normalise::secret(secret).map(|s| canonical_input(name::SECRET, &[&s]))
}

/// The canonical input of a passkey's tag (relying party, credential id).
pub fn passkey_input(relying_party: &str, credential_id: &str) -> Vec<u8> {
    canonical_input(
        name::PASSKEY,
        &[
            &normalise::relying_party(relying_party),
            &normalise::credential_id(credential_id),
        ],
    )
}

/// The canonical input of a card's tag (number, expiry from its month and year); `None` for a
/// card without digits.
pub fn card_input(number: &str, month: &str, year: &str) -> Option<Vec<u8>> {
    let number = normalise::card_number(number);
    (!number.is_empty())
        .then(|| canonical_input(name::CARD, &[&number, &normalise::expiry(month, year)]))
}

/// The canonical input of a note's tag; `None` for a note with no text.
pub fn note_input(text: &str) -> Option<Vec<u8>> {
    let text = normalise::note(text);
    (!text.is_empty()).then(|| canonical_input(name::NOTE, &[&text]))
}

/// The canonical input of a key's tag; `None` when the fingerprint is neither an OpenSSH
/// `SHA256:` one nor a PGP v4 or v6 one.
pub fn key_input(fingerprint: &str) -> Option<Vec<u8>> {
    normalise::fingerprint(fingerprint).map(|f| canonical_input(name::KEY, &[&f]))
}

/// The canonical input of a backup-code set's tag; `None` for no codes.
pub fn codes_input<S: AsRef<str>>(codes: &[S]) -> Option<Vec<u8>> {
    let codes = normalise::codes(codes);
    let values: Vec<&str> = codes.iter().map(String::as_str).collect();
    (!values.is_empty()).then(|| canonical_input(name::CODES, &values))
}

/// The canonical input of an identity's tag (full name, email); `None` when both are empty.
pub fn identity_input(full_name: &str, email: &str) -> Option<Vec<u8>> {
    let full_name = normalise::identity_text(full_name);
    let email = normalise::identity_text(email);
    (!(full_name.is_empty() && email.is_empty()))
        .then(|| canonical_input(name::IDENTITY, &[&full_name, &email]))
}

/// The canonical input of a contact's tag (email, phone); `None` when both are empty once
/// normalised. A contact with only an email or only a phone still has one.
pub fn contact_input(email: &str, phone: &str) -> Option<Vec<u8>> {
    let email = normalise::email(email);
    let phone = normalise::phone(phone);
    (!(email.is_empty() && phone.is_empty()))
        .then(|| canonical_input(name::CONTACT, &[&email, &phone]))
}

/// The canonical input of an identity document's tag (its number); `None` for a number of fewer
/// than four letters and digits.
pub fn document_input(number: &str) -> Option<Vec<u8>> {
    normalise::document_number(number).map(|n| canonical_input(name::DOCUMENT, &[&n]))
}

/// The canonical input of a file's tag (the SHA-256 of its plaintext as hex); `None` when it
/// isn't 64 hex digits.
pub fn file_input(content_hash: &str) -> Option<Vec<u8>> {
    normalise::content_hash(content_hash).map(|h| canonical_input(name::FILE, &[&h]))
}

/// A login's tags: one `cred` and one `account` tag per site. Only the `cred` tags are uploaded
/// when server matching is on.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct LoginTags {
    pub cred: Vec<[u8; 32]>,
    pub account: Vec<[u8; 32]>,
}

/// The tags of a login from its raw values.
pub fn login_tags<S: AsRef<str>>(
    key: &SecretKey,
    websites: &[Website<'_>],
    shared_hosts: &[S],
    username: &str,
    password: &str,
) -> LoginTags {
    LoginTags {
        cred: cred_inputs(websites, shared_hosts, username, password)
            .iter()
            .map(|input| tag(key, input))
            .collect(),
        account: account_inputs(websites, shared_hosts, username)
            .iter()
            .map(|input| tag(key, input))
            .collect(),
    }
}

/// The `secret` tag of a code from its raw secret.
pub fn secret_tag(key: &SecretKey, secret: &str) -> Option<[u8; 32]> {
    secret_input(secret).map(|input| tag(key, &input))
}

/// The tag of a passkey from its raw relying party and credential id.
pub fn passkey_tag(key: &SecretKey, relying_party: &str, credential_id: &str) -> [u8; 32] {
    tag(key, &passkey_input(relying_party, credential_id))
}

/// The tag of a card from its raw number, expiry month and expiry year.
pub fn card_tag(key: &SecretKey, number: &str, month: &str, year: &str) -> Option<[u8; 32]> {
    card_input(number, month, year).map(|input| tag(key, &input))
}

/// The tag of a note from its raw text.
pub fn note_tag(key: &SecretKey, text: &str) -> Option<[u8; 32]> {
    note_input(text).map(|input| tag(key, &input))
}

/// The tag of an SSH or PGP key from its raw fingerprint.
pub fn key_tag(key: &SecretKey, fingerprint: &str) -> Option<[u8; 32]> {
    key_input(fingerprint).map(|input| tag(key, &input))
}

/// The tag of a set of backup codes from the raw codes.
pub fn codes_tag<S: AsRef<str>>(key: &SecretKey, codes: &[S]) -> Option<[u8; 32]> {
    codes_input(codes).map(|input| tag(key, &input))
}

/// The tag of an identity from its raw full name and email.
pub fn identity_tag(key: &SecretKey, full_name: &str, email: &str) -> Option<[u8; 32]> {
    identity_input(full_name, email).map(|input| tag(key, &input))
}

/// The tag of a contact from its raw email and phone.
pub fn contact_tag(key: &SecretKey, email: &str, phone: &str) -> Option<[u8; 32]> {
    contact_input(email, phone).map(|input| tag(key, &input))
}

/// The tag of an identity document from its raw number.
pub fn document_tag(key: &SecretKey, number: &str) -> Option<[u8; 32]> {
    document_input(number).map(|input| tag(key, &input))
}

/// The tag of a file from the raw SHA-256 of its plaintext.
pub fn file_tag(key: &SecretKey, content_hash: &str) -> Option<[u8; 32]> {
    file_input(content_hash).map(|input| tag(key, &input))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn canonical_input_is_compact_json() {
        assert_eq!(
            canonical_input("cred", &["example.com", "alice", "hunter2"]),
            br#"["cred","example.com","alice","hunter2"]"#
        );
        assert_eq!(canonical_input("note", &[]), br#"["note"]"#);
        assert_eq!(canonical_input("note", &[""]), br#"["note",""]"#);
    }

    #[test]
    fn strings_are_escaped_as_rfc_8785_says() {
        // RFC 8785 section 3.2.2.2: the string 20ac $ 0f 0a A ' B " 5c 5c " / serialises as
        // "€$\u000f\nA'B\"\\\\\"/".
        let value = "\u{20ac}$\u{0f}\nA'B\"\\\\\"/";
        let expected = "[\"x\",\"\u{20ac}$\\u000f\\nA'B\\\"\\\\\\\\\\\"/\"]";
        assert_eq!(canonical_input("x", &[value]), expected.as_bytes());
    }

    #[test]
    fn control_characters_and_the_short_escapes() {
        let all: String = [
            '\u{0}', '\u{1}', '\u{8}', '\t', '\n', '\u{b}', '\u{c}', '\r', '\u{1f}', '\u{7f}',
        ]
        .iter()
        .collect();
        assert_eq!(
            canonical_input("n", &[all.as_str()]),
            "[\"n\",\"\\u0000\\u0001\\b\\t\\n\\u000b\\f\\r\\u001f\u{7f}\"]".as_bytes()
        );
    }

    #[test]
    fn non_ascii_stays_utf8_and_slash_is_not_escaped() {
        assert_eq!(
            canonical_input("n", &["caf\u{e9} \u{1f600} a/b \u{2028}"]),
            "[\"n\",\"caf\u{e9} \u{1f600} a/b \u{2028}\"]".as_bytes()
        );
    }

    #[test]
    fn values_cannot_run_into_each_other() {
        assert_ne!(
            canonical_input("cred", &["ab", "c"]),
            canonical_input("cred", &["a", "bc"])
        );
        assert_ne!(
            canonical_input("cred", &["a", "b"]),
            canonical_input("account", &["a", "b"])
        );
        assert_ne!(
            canonical_input("cred", &["a,b"]),
            canonical_input("cred", &["a", "b"])
        );
    }

    #[test]
    fn key_is_hkdf_with_the_documented_info() {
        for_backends!(B => {
            let user_key = SecretKey::from_bytes(&[4; 32]);
            let owner = Owner::user([6; 16]);
            let key = dedup_key_in::<B>(&user_key, &owner, 2).expect("dedup key");
            let mut info = b"kemlock dedup v1".to_vec();
            info.push(1);
            info.extend_from_slice(&[6; 16]);
            info.extend_from_slice(&[0, 0, 0, 2]);
            let mut expected = [0u8; 32];
            B::hkdf_sha256(&[4; 32], None, &info, &mut expected).expect("hkdf");
            assert_eq!(key.as_bytes(), &expected, "{}", B::NAME);
        });
    }

    #[test]
    fn owner_key_and_key_version_each_change_the_key() {
        let user_key = SecretKey::from_bytes(&[4; 32]);
        let owner = Owner::user([6; 16]);
        let base = dedup_key(&user_key, &owner, 1).expect("dedup key");
        assert_ne!(
            base.as_bytes(),
            dedup_key(&user_key, &owner, 2).expect("key").as_bytes()
        );
        assert_ne!(
            base.as_bytes(),
            dedup_key(&user_key, &Owner::user([7; 16]), 1)
                .expect("key")
                .as_bytes()
        );
        assert_ne!(
            base.as_bytes(),
            dedup_key(&user_key, &Owner::space([6; 16]), 1)
                .expect("key")
                .as_bytes()
        );
        assert_ne!(
            base.as_bytes(),
            dedup_key(&SecretKey::from_bytes(&[5; 32]), &owner, 1)
                .expect("key")
                .as_bytes()
        );
    }

    #[test]
    fn tags_are_hmac_sha256_of_the_canonical_input() {
        for_backends!(B => {
            let key = SecretKey::from_bytes(&[8; 32]);
            let input = canonical_input("cred", &["example.com", "alice", "pw"]);
            assert_eq!(tag(&key, &input), B::hmac_sha256(&[8; 32], &input), "{}", B::NAME);
        });
    }

    #[test]
    fn equal_values_give_equal_tags_and_any_change_breaks_it() {
        let key = SecretKey::from_bytes(&[8; 32]);
        let a = tag_for(&key, name::CRED, &["example.com", "alice", "pw"]);
        assert_eq!(
            a,
            tag_for(&key, name::CRED, &["example.com", "alice", "pw"])
        );
        assert_ne!(
            a,
            tag_for(&key, name::CRED, &["example.com", "alice", "pw2"])
        );
        assert_ne!(
            a,
            tag_for(&key, name::ACCOUNT, &["example.com", "alice", "pw"])
        );
        assert_ne!(
            a,
            tag_for(
                &SecretKey::from_bytes(&[9; 32]),
                name::CRED,
                &["example.com", "alice", "pw"]
            )
        );
        assert_eq!(a.len(), 32);
    }

    fn key() -> SecretKey {
        SecretKey::from_bytes(&[8; 32])
    }

    fn web(uri: &str) -> Website<'_> {
        Website {
            uri,
            rule: MatchRule::Domain,
        }
    }

    #[test]
    fn rules_are_read_by_name() {
        assert_eq!(MatchRule::parse("regex"), MatchRule::Regex);
        assert_eq!(MatchRule::parse(" Never "), MatchRule::Never);
        assert_eq!(MatchRule::parse("startsWith"), MatchRule::StartsWith);
        assert_eq!(MatchRule::parse("host"), MatchRule::Host);
        assert_eq!(MatchRule::parse("exact"), MatchRule::Exact);
        assert_eq!(MatchRule::parse("domain"), MatchRule::Domain);
        assert_eq!(MatchRule::parse("something else"), MatchRule::Domain);
        assert!(MatchRule::Exact.makes_tag() && !MatchRule::Regex.makes_tag());
    }

    #[test]
    fn a_login_has_a_tag_per_site_whatever_its_spelling() {
        let none: [&str; 0] = [];
        let a = login_tags(
            &key(),
            &[web("https://www.Example.com/login")],
            &none,
            "  Alice ",
            "Hunter2",
        );
        let b = login_tags(
            &key(),
            &[
                web("http://example.com:8080/"),
                web("https://m.example.com"),
            ],
            &none,
            "alice",
            "Hunter2",
        );
        assert_eq!(a.cred.len(), 1);
        assert_eq!(a, b);
        assert_ne!(a.cred[0], a.account[0]);
        let other_password = login_tags(&key(), &[web("example.com")], &none, "alice", "hunter2");
        assert_ne!(a.cred, other_password.cred);
        assert_eq!(a.account, other_password.account);
    }

    #[test]
    fn regex_and_never_websites_make_no_tag() {
        let none: [&str; 0] = [];
        let sites = [
            Website {
                uri: "https://a.example",
                rule: MatchRule::Regex,
            },
            Website {
                uri: "https://b.example",
                rule: MatchRule::Never,
            },
            web("not a host"),
        ];
        assert_eq!(
            login_tags(&key(), &sites, &none, "alice", "pw"),
            LoginTags::default()
        );
    }

    #[test]
    fn the_inputs_are_the_documented_arrays() {
        let none: [&str; 0] = [];
        assert_eq!(
            cred_inputs(&[web("https://www.example.com")], &none, " Alice", " pw "),
            vec![br#"["cred","example.com","alice"," pw "]"#.to_vec()]
        );
        assert_eq!(
            account_inputs(&[web("https://www.example.com")], &none, "Alice"),
            vec![br#"["account","example.com","alice"]"#.to_vec()]
        );
        assert_eq!(
            secret_input("jbsw y3dp"),
            Some(br#"["secret","JBSWY3DP"]"#.to_vec())
        );
        assert_eq!(
            passkey_input("Example.COM", "dGVzdA=="),
            br#"["passkey","example.com","dGVzdA"]"#.to_vec()
        );
        assert_eq!(
            card_input("4111 1111", "9", "30"),
            Some(br#"["card","41111111","2030-09"]"#.to_vec())
        );
        assert_eq!(
            card_input("4111", "", ""),
            Some(br#"["card","4111",""]"#.to_vec())
        );
        assert_eq!(card_input("none", "9", "30"), None);
        assert_eq!(
            note_input("a  \r\nb\r\n\r\n"),
            Some(br#"["note","a\nb"]"#.to_vec())
        );
        assert_eq!(note_input(" \r\n"), None);
        assert_eq!(
            key_input("sha256:x"),
            None,
            "the SSH prefix is case sensitive"
        );
        assert_eq!(
            key_input("SHA256:abc"),
            Some(br#"["key","SHA256:abc"]"#.to_vec())
        );
        assert_eq!(
            codes_input(&["b ", "a", "b", ""]),
            Some(br#"["codes","a","b"]"#.to_vec())
        );
        assert_eq!(codes_input::<&str>(&[]), None);
        assert_eq!(
            identity_input(" Alice ", "A@B.C"),
            Some(br#"["identity","alice","a@b.c"]"#.to_vec())
        );
        assert_eq!(identity_input("", " "), None);
    }

    #[test]
    fn tags_from_raw_values_are_the_tags_of_their_inputs() {
        let k = key();
        assert_eq!(
            secret_tag(&k, "jbswy3dp"),
            secret_input("JBSWY3DP").map(|i| tag(&k, &i))
        );
        assert_eq!(
            passkey_tag(&k, "A.example", "dGVzdA"),
            tag(&k, &passkey_input("a.example", "dGVzdA=="))
        );
        assert_eq!(note_tag(&k, "x\r\n"), Some(tag_for(&k, name::NOTE, &["x"])));
        assert_eq!(
            codes_tag(&k, &["2", "1"]),
            Some(tag_for(&k, name::CODES, &["1", "2"]))
        );
        assert_eq!(
            identity_tag(&k, "Al", "al@x"),
            Some(tag_for(&k, name::IDENTITY, &["al", "al@x"]))
        );
        assert_eq!(
            card_tag(&k, "12", "1", "2031"),
            Some(tag_for(&k, name::CARD, &["12", "2031-01"]))
        );
        assert_eq!(
            key_tag(&k, "9f3a77c10b2e45d68a19c0de12f45b6a77889900"),
            Some(tag_for(
                &k,
                name::KEY,
                &["9F3A77C10B2E45D68A19C0DE12F45B6A77889900"]
            ))
        );
    }

    #[test]
    fn contacts_documents_and_files_have_their_documented_inputs() {
        assert_eq!(
            contact_input(" Alex@Example.ORG ", "+1 (555) 0142"),
            Some(br#"["contact","alex@example.org","15550142"]"#.to_vec())
        );
        // One of the two is enough; the other stays an empty string, so it can't run into it.
        assert_eq!(
            contact_input("a@b.c", ""),
            Some(br#"["contact","a@b.c",""]"#.to_vec())
        );
        assert_eq!(
            contact_input("", "555 0142"),
            Some(br#"["contact","","5550142"]"#.to_vec())
        );
        assert_eq!(contact_input("  ", "call me"), None);
        assert_ne!(contact_input("a@b.c", ""), contact_input("", "a@b.c"));

        assert_eq!(
            document_input("X 1234-567"),
            Some(br#"["document","x1234567"]"#.to_vec())
        );
        assert_eq!(document_input("12"), None);

        let hash = "0123456789ABCDEF".repeat(4);
        assert_eq!(
            file_input(&hash),
            Some(format!(r#"["file","{}"]"#, hash.to_ascii_lowercase()).into_bytes())
        );
        assert_eq!(file_input("not a hash"), None);
    }

    #[test]
    fn the_new_tag_names_keep_a_value_from_matching_another_kind() {
        let k = key();
        let hash = "ab".repeat(32);
        assert_ne!(
            file_tag(&k, &hash),
            key_tag(&k, &hash),
            "a file's hash and a key's fingerprint are different tags"
        );
        assert_ne!(
            document_tag(&k, "abcd1234"),
            note_tag(&k, "abcd1234"),
            "a document number and a note are different tags"
        );
        assert_ne!(
            contact_tag(&k, "a@b.c", ""),
            identity_tag(&k, "a@b.c", ""),
            "a contact and an identity are different tags"
        );
    }

    #[test]
    fn tags_of_the_new_kinds_are_the_tags_of_their_inputs() {
        let k = key();
        assert_eq!(
            contact_tag(&k, "A@B.C", "+1 5"),
            Some(tag_for(&k, name::CONTACT, &["a@b.c", "15"]))
        );
        assert_eq!(contact_tag(&k, "", ""), None);
        assert_eq!(
            document_tag(&k, "AB-12 34"),
            Some(tag_for(&k, name::DOCUMENT, &["ab1234"]))
        );
        assert_eq!(document_tag(&k, "1"), None);
        let hash = "ef".repeat(32);
        assert_eq!(
            file_tag(&k, &hash.to_ascii_uppercase()),
            Some(tag_for(&k, name::FILE, &[hash.as_str()]))
        );
        assert_eq!(file_tag(&k, "short"), None);
        // A certificate's thumbprint is a `key` tag, whichever way it is written.
        let colons = ["EF"; 32].join(":");
        assert_eq!(key_tag(&k, &colons), key_tag(&k, &hash));
        assert_eq!(
            key_tag(&k, &colons),
            Some(tag_for(&k, name::KEY, &[hash.to_ascii_uppercase().as_str()]))
        );
    }

    #[test]
    fn straße_and_strasse_are_two_usernames() {
        let none: [&str; 0] = [];
        let site = [web("example.com")];
        assert_ne!(
            login_tags(&key(), &site, &none, "Stra\u{df}e", "pw").cred,
            login_tags(&key(), &site, &none, "STRASSE", "pw").cred
        );
        assert_eq!(
            login_tags(&key(), &site, &none, "Cafe\u{301}", "pw").cred,
            login_tags(&key(), &site, &none, "CAF\u{c9}", "pw").cred
        );
    }
}
