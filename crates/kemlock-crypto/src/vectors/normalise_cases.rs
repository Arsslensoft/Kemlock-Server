//! The raw items of `dedup-normalise.json`, and how a case's raw values turn into canonical
//! inputs. The generator writes the cases and the check replays them, both through [`inputs`]; the
//! check also holds the headline cases to canonical inputs written out by hand, so a change that
//! moves both sides together is still caught.

// The generator reads the cases; a test build without the RustCrypto backend has no generator.
#![allow(dead_code)]

use serde_json::{Value, json};

use crate::dedup::{self, MatchRule, Website};

/// The dedup key every case's tags are made under: `0, 1, 2, …`.
pub(crate) fn key_bytes() -> [u8; 32] {
    core::array::from_fn(|i| u8::try_from(i).unwrap_or(0))
}

/// One raw case: its name, the tag it makes, the raw values and the app's shared hosts.
pub(crate) struct Raw {
    pub(crate) name: &'static str,
    pub(crate) tag: &'static str,
    pub(crate) raw: Value,
    pub(crate) shared_hosts: Vec<&'static str>,
}

fn login(
    name: &'static str,
    tag: &'static str,
    websites: &[(&str, &str)],
    username: &str,
    password: &str,
) -> Raw {
    let sites: Vec<Value> = websites
        .iter()
        .map(|(uri, rule)| json!({ "uri": uri, "rule": rule }))
        .collect();
    Raw {
        name,
        tag,
        raw: json!({ "websites": sites, "username": username, "password": password }),
        shared_hosts: Vec::new(),
    }
}

fn plain(name: &'static str, tag: &'static str, raw: Value) -> Raw {
    Raw {
        name,
        tag,
        raw,
        shared_hosts: Vec::new(),
    }
}

/// Every raw case, in the order of the file.
pub(crate) fn raw_cases() -> Vec<Raw> {
    let example = [("https://www.Example.com/login?next=1", "domain")];
    let mut cases = vec![
        login(
            "cred-url-with-www-and-path",
            "cred",
            &example,
            " Alice ",
            "Hunter2 ",
        ),
        login(
            "cred-istanbul",
            "cred",
            &[("https://\u{130}STANBUL.example/", "domain")],
            "\u{130}stanbul",
            "pw",
        ),
        login(
            "cred-final-sigma-is-always-sigma",
            "cred",
            &[("example.com", "domain")],
            "\u{3a3}\u{391}\u{3a3}",
            "pw",
        ),
        login(
            "cred-sharp-s-stays",
            "cred",
            &[("example.com", "domain")],
            "Stra\u{df}e",
            "pw",
        ),
        login(
            "cred-strasse-is-another-name",
            "cred",
            &[("example.com", "domain")],
            "STRASSE",
            "pw",
        ),
        login(
            "cred-capital-sharp-s",
            "cred",
            &[("example.com", "domain")],
            "\u{1e9e}",
            "pw",
        ),
        login(
            "cred-decomposed-e",
            "cred",
            &[("example.com", "domain")],
            "Cafe\u{301}",
            "pw",
        ),
        login(
            "cred-several-websites",
            "cred",
            &[
                ("https://a.example.co.uk", "domain"),
                ("https://login.example.co.uk/x", "host"),
                ("https://alice.github.io/blog", "domain"),
                ("https://shop.\u{516c}\u{53f8}.cn", "domain"),
                ("https://x.example", "regex"),
                ("https://y.example", "never"),
                ("not a host", "domain"),
            ],
            "bob",
            "pw",
        ),
        login(
            "cred-no-site",
            "cred",
            &[("https://x.example", "regex")],
            "bob",
            "pw",
        ),
        login(
            "cred-internationalised-host",
            "cred",
            &[("https://M\u{dc}NCHEN.de/", "domain")],
            "bob",
            "pw",
        ),
        login(
            "account-the-same-login",
            "account",
            &example,
            " Alice ",
            "Hunter2 ",
        ),
        login(
            "account-two-websites-one-site",
            "account",
            &[
                ("https://one.example.org", "domain"),
                ("http://two.example.org:8080/", "exact"),
            ],
            "Alice",
            "",
        ),
    ];

    let mut addresses = login(
        "cred-addresses-and-shared-hosts",
        "cred",
        &[
            ("http://192.168.0.1:8080/admin", "domain"),
            ("https://[2001:DB8::1]/", "domain"),
            ("https://Mysite.sites.example.net/", "domain"),
            ("https://other.example.net", "domain"),
        ],
        "bob",
        "pw",
    );
    addresses.shared_hosts = vec!["sites.example.net"];
    cases.push(addresses);

    cases.extend([
        plain(
            "secret-spaces-and-lower-case",
            "secret",
            json!({ "secret": "jbsw y3dp ehpk 3pxp" }),
        ),
        plain(
            "secret-padding",
            "secret",
            json!({ "secret": "jbswy3dpehpk3pxp======" }),
        ),
        plain("secret-short", "secret", json!({ "secret": "MFRGG===" })),
        plain(
            "secret-not-base32",
            "secret",
            json!({ "secret": "not base32!" }),
        ),
        plain(
            "passkey-case-and-padding",
            "passkey",
            json!({ "relying_party": "Example.COM", "credential_id": "dGVzdA==" }),
        ),
        plain(
            "passkey-standard-alphabet",
            "passkey",
            json!({ "relying_party": "example.com", "credential_id": "+//+" }),
        ),
        plain(
            "card-digits-and-expiry",
            "card",
            json!({
                "number": "4111 1111-1111 1111",
                "expiry_month": "9",
                "expiry_year": "30"
            }),
        ),
        plain(
            "card-unknown-expiry",
            "card",
            json!({ "number": "4111111111111111", "expiry_month": "", "expiry_year": "" }),
        ),
        plain(
            "card-without-digits",
            "card",
            json!({ "number": "none", "expiry_month": "1", "expiry_year": "2030" }),
        ),
        plain(
            "note-crlf-and-trailing-blanks",
            "note",
            json!({ "text": "line one  \r\nline two\t\r\n\r\n  \r\n" }),
        ),
        plain(
            "note-lone-cr-and-decomposed-e",
            "note",
            json!({ "text": "cafe\u{301}\rx" }),
        ),
        plain("note-blank", "note", json!({ "text": "  \n" })),
        plain(
            "key-ssh",
            "key",
            json!({ "fingerprint": "SHA256:uNiVztksCsDhcc0u9e8BujQXVUpKZIDTMczCvj3tD2s" }),
        ),
        plain(
            "key-pgp-v4",
            "key",
            json!({ "fingerprint": " 9f3a 77c1 0b2e 45d6 8a19 c0de 12f4 5b6a 7788 9900" }),
        ),
        plain("key-unknown", "key", json!({ "fingerprint": "MD5:ab:cd" })),
        plain(
            "codes-duplicates",
            "codes",
            json!({ "codes": [" 22222222", "11111111", "22222222 ", "", "33333333"] }),
        ),
        plain("codes-none", "codes", json!({ "codes": [] })),
        plain(
            "identity-trimmed-composed-lower",
            "identity",
            json!({ "full_name": " Zoe\u{308} M\u{dc}ller ", "email": " Zoe@Example.COM " }),
        ),
    ]);
    cases
}

fn text<'a>(raw: &'a Value, key: &str) -> &'a str {
    raw[key]
        .as_str()
        .unwrap_or_else(|| panic!("`{key}` is missing or not a string in {raw}"))
}

/// The canonical inputs a raw case makes, in order; none when the item makes no tag.
pub(crate) fn inputs(tag: &str, raw: &Value, shared_hosts: &[String]) -> Vec<Vec<u8>> {
    match tag {
        dedup::name::CRED | dedup::name::ACCOUNT => {
            let websites: Vec<(String, MatchRule)> = raw["websites"]
                .as_array()
                .unwrap_or_else(|| panic!("`websites` is missing in {raw}"))
                .iter()
                .map(|w| (text(w, "uri").to_owned(), MatchRule::parse(text(w, "rule"))))
                .collect();
            let websites: Vec<Website<'_>> = websites
                .iter()
                .map(|(uri, rule)| Website { uri, rule: *rule })
                .collect();
            let username = text(raw, "username");
            if tag == dedup::name::CRED {
                dedup::cred_inputs(&websites, shared_hosts, username, text(raw, "password"))
            } else {
                dedup::account_inputs(&websites, shared_hosts, username)
            }
        }
        dedup::name::SECRET => dedup::secret_input(text(raw, "secret"))
            .into_iter()
            .collect(),
        dedup::name::PASSKEY => vec![dedup::passkey_input(
            text(raw, "relying_party"),
            text(raw, "credential_id"),
        )],
        dedup::name::CARD => dedup::card_input(
            text(raw, "number"),
            text(raw, "expiry_month"),
            text(raw, "expiry_year"),
        )
        .into_iter()
        .collect(),
        dedup::name::NOTE => dedup::note_input(text(raw, "text")).into_iter().collect(),
        dedup::name::KEY => dedup::key_input(text(raw, "fingerprint"))
            .into_iter()
            .collect(),
        dedup::name::CODES => {
            let codes: Vec<&str> = raw["codes"]
                .as_array()
                .unwrap_or_else(|| panic!("`codes` is missing in {raw}"))
                .iter()
                .map(|c| c.as_str().expect("a code is a string"))
                .collect();
            dedup::codes_input(&codes).into_iter().collect()
        }
        dedup::name::IDENTITY => dedup::identity_input(text(raw, "full_name"), text(raw, "email"))
            .into_iter()
            .collect(),
        other => panic!("unknown tag {other}"),
    }
}
