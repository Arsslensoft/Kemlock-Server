//! A website's **site**: the registrable domain by the Public Suffix List, lower case and in
//! Punycode, or the whole host for an IP address or a host under the app's shared hosts.
//!
//! The list is the snapshot at `test-vectors/public_suffix_list.dat`, compiled in, so every client
//! and the server use one list; its SHA-256 is in `docs/crypto.md`. Both the ICANN and the private
//! sections count. The parser is the PSL algorithm (publicsuffix.org/list): plain rules, `*.`
//! wildcard rules and `!` exceptions, matched on the host's labels from the right, the longest
//! matching rule prevailing, an exception beating them all, and `*` (one label) when no rule
//! matches. Rules and hosts are compared as Punycode labels.
//!
//! What a host is made of, before the list is asked:
//!
//! 1. The website text is a URL, with or without a scheme, or a bare host. Userinfo, port, path,
//!    query and fragment go. A trailing dot goes.
//! 2. A host is NFC, then lower case (the simple mapping), then each non-ASCII label is Punycode.
//!    A host that still has anything but `a-z`, `0-9`, `-`, `_` and `.` in it isn't a site.
//! 3. An IPv4 address, or an IPv6 address in RFC 5952 form without brackets, is its own site.
//! 4. `androidapp://` and `iosapp://` names are package names, not domains: the whole name is the
//!    site.
//! 5. A host equal to, or under, a shared host is its own site.
//! 6. A host that is itself a public suffix (`com`, `github.io`, `localhost`) has no registrable
//!    domain, and is its own site.

use std::collections::HashSet;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::str::FromStr as _;
use std::sync::OnceLock;

use super::normalise::{lower, nfc};
use super::punycode::label_to_ascii;

/// The pinned snapshot of the Public Suffix List.
pub const PUBLIC_SUFFIX_LIST: &str =
    include_str!("../../../../test-vectors/public_suffix_list.dat");

/// The rules of the list, with labels in Punycode.
#[derive(Debug, Default)]
struct Rules {
    /// `com`, `co.uk`.
    plain: HashSet<String>,
    /// The part after `*.` of a wildcard rule (`ck` for `*.ck`).
    wildcard: HashSet<String>,
    /// The rule after `!` (`www.ck`).
    exception: HashSet<String>,
}

/// A rule's labels as Punycode, joined by dots; `None` for a rule that can't be one.
fn rule_text(rule: &str) -> Option<String> {
    let labels: Option<Vec<String>> = lower(&nfc(rule)).split('.').map(label_to_ascii).collect();
    labels.map(|l| l.join("."))
}

impl Rules {
    fn parse(list: &str) -> Rules {
        let mut rules = Rules::default();
        for line in list.lines() {
            // A rule is the line up to its first white space; comments start with `//`.
            let Some(token) = line.split_whitespace().next() else {
                continue;
            };
            if token.starts_with("//") {
                continue;
            }
            if let Some(rest) = token.strip_prefix('!') {
                if let Some(text) = rule_text(rest) {
                    rules.exception.insert(text);
                }
            } else if let Some(rest) = token.strip_prefix("*.") {
                if let Some(text) = rule_text(rest) {
                    rules.wildcard.insert(text);
                }
            } else if let Some(text) = rule_text(token) {
                rules.plain.insert(text);
            }
        }
        rules
    }

    /// How many of the host's rightmost labels are its public suffix.
    fn suffix_len(&self, labels: &[&str]) -> usize {
        let n = labels.len();
        let mut best = 1;
        for i in 0..n {
            let suffix = labels[i..].join(".");
            if self.exception.contains(&suffix) {
                // An exception prevails over every other rule; its suffix is the rule less its
                // leftmost label.
                return n - i - 1;
            }
            let len = n - i;
            if self.plain.contains(&suffix)
                || (i + 1 < n && self.wildcard.contains(&labels[i + 1..].join(".")))
            {
                best = best.max(len);
            }
        }
        best
    }
}

fn rules() -> &'static Rules {
    static RULES: OnceLock<Rules> = OnceLock::new();
    RULES.get_or_init(|| Rules::parse(PUBLIC_SUFFIX_LIST))
}

/// The host of a website text, as written: no scheme, userinfo, port, path, query or fragment,
/// IPv6 without brackets. `None` when nothing is left.
fn host_of(uri: &str) -> Option<&str> {
    let text = uri.trim();
    let rest = match text.find("://") {
        Some(i)
            if text[..i]
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || "+-.".contains(c)) =>
        {
            &text[i + 3..]
        }
        _ => text.strip_prefix("//").unwrap_or(text),
    };
    let end = rest.find(['/', '?', '#']).unwrap_or(rest.len());
    let authority = &rest[..end];
    let authority = authority
        .rsplit_once('@')
        .map_or(authority, |(_, host)| host);
    let host = if let Some(bracketed) = authority.strip_prefix('[') {
        bracketed.split_once(']').map(|(inner, _)| inner)?
    } else {
        match authority.rsplit_once(':') {
            Some((host, port)) if port.bytes().all(|b| b.is_ascii_digit()) => host,
            _ => authority,
        }
    };
    let host = host.trim_end_matches('.');
    (!host.is_empty()).then_some(host)
}

/// A host in its canonical text: NFC, lower case, Punycode; `None` when it isn't a host name.
fn canonical_host(host: &str) -> Option<String> {
    let host = lower(&nfc(host.trim().trim_end_matches('.')));
    let mut labels = Vec::new();
    for label in host.split('.') {
        let ascii = label_to_ascii(label)?;
        let valid = !ascii.is_empty()
            && ascii
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-' || b == b'_');
        if !valid {
            return None;
        }
        labels.push(ascii);
    }
    Some(labels.join("."))
}

/// The scheme of a website text, lower case, when it has one.
fn scheme_of(uri: &str) -> Option<String> {
    let text = uri.trim();
    let (scheme, _) = text.split_once("://")?;
    scheme
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || "+-.".contains(c))
        .then(|| scheme.to_ascii_lowercase())
}

/// The **site** of a website text, or `None` when it has none (not a host, or empty).
///
/// `shared_hosts` are the app's shared hosts: a host equal to one, or under one, is its own site.
pub fn site<S: AsRef<str>>(uri: &str, shared_hosts: &[S]) -> Option<String> {
    let host = host_of(uri)?;
    if let Ok(v4) = Ipv4Addr::from_str(host) {
        return Some(v4.to_string());
    }
    if let Ok(v6) = Ipv6Addr::from_str(host) {
        return Some(v6.to_string());
    }
    let host = canonical_host(host)?;
    if matches!(scheme_of(uri).as_deref(), Some("androidapp" | "iosapp")) {
        return Some(host);
    }
    let shared = shared_hosts
        .iter()
        .filter_map(|shared| canonical_host(shared.as_ref()))
        .any(|shared| host == shared || host.ends_with(&format!(".{shared}")));
    if shared {
        return Some(host);
    }
    let labels: Vec<&str> = host.split('.').collect();
    let suffix = rules().suffix_len(&labels);
    if suffix >= labels.len() {
        return Some(host);
    }
    Some(labels[labels.len() - suffix - 1..].join("."))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn site_of(uri: &str) -> Option<String> {
        site::<&str>(uri, &[])
    }

    #[test]
    fn the_snapshot_is_the_pinned_one() {
        let digest = crate::hash::sha256(PUBLIC_SUFFIX_LIST.as_bytes());
        assert_eq!(
            hex::encode(digest),
            "017501d3fa7911c60ac7e0f68df4122b07216c585c15dc30e0f0c74b8d13a2b9"
        );
    }

    #[test]
    fn the_registrable_domain_is_one_label_above_the_suffix() {
        for (uri, expected) in [
            ("https://www.Example.com/login?x=1#y", "example.com"),
            ("example.com", "example.com"),
            ("http://a.b.example.co.uk:8080/", "example.co.uk"),
            ("//login.example.org/path", "example.org"),
            ("https://user:pw@mail.example.com/", "example.com"),
            ("https://EXAMPLE.COM.", "example.com"),
            ("login.example.com/a@b", "example.com"),
        ] {
            assert_eq!(site_of(uri).as_deref(), Some(expected), "{uri}");
        }
    }

    #[test]
    fn private_suffixes_count() {
        assert_eq!(
            site_of("https://alice.github.io/blog").as_deref(),
            Some("alice.github.io")
        );
        assert_eq!(
            site_of("https://x.y.alice.github.io").as_deref(),
            Some("alice.github.io")
        );
        assert_eq!(site_of("https://github.io").as_deref(), Some("github.io"));
    }

    #[test]
    fn wildcards_and_exceptions_follow_the_list() {
        // `*.ck` makes `foo.ck` a suffix, `!www.ck` makes `www.ck` registrable.
        assert_eq!(site_of("https://a.foo.ck").as_deref(), Some("a.foo.ck"));
        assert_eq!(site_of("https://x.www.ck").as_deref(), Some("www.ck"));
        assert_eq!(site_of("https://www.ck").as_deref(), Some("www.ck"));
        assert_eq!(site_of("https://foo.ck").as_deref(), Some("foo.ck"));
    }

    #[test]
    fn an_unlisted_top_level_name_is_one_label() {
        assert_eq!(
            site_of("https://a.b.localdomain").as_deref(),
            Some("b.localdomain")
        );
        assert_eq!(
            site_of("http://localhost:3000").as_deref(),
            Some("localhost")
        );
        assert_eq!(site_of("com").as_deref(), Some("com"));
    }

    #[test]
    fn internationalised_hosts_are_punycode() {
        assert_eq!(
            site_of("https://www.B\u{fc}cher.example.de").as_deref(),
            Some("example.de")
        );
        assert_eq!(
            site_of("https://M\u{dc}NCHEN.de/").as_deref(),
            Some("xn--mnchen-3ya.de")
        );
        assert_eq!(
            site_of("https://shop.xn--mnchen-3ya.de").as_deref(),
            Some("xn--mnchen-3ya.de")
        );
        // The list's own Unicode rules are compared as Punycode: `公司.cn` is a suffix.
        assert_eq!(
            site_of("https://shop.\u{516c}\u{53f8}.cn").as_deref(),
            Some("shop.xn--55qx5d.cn")
        );
        // A decomposed host makes the same site as the composed one.
        assert_eq!(
            site_of("https://muenchen.de").as_deref(),
            Some("muenchen.de")
        );
        assert_eq!(
            site_of("https://mu\u{308}nchen.de").as_deref(),
            site_of("https://m\u{fc}nchen.de").as_deref()
        );
    }

    #[test]
    fn istanbul_is_lowered_by_the_simple_mapping() {
        assert_eq!(
            site_of("https://\u{130}STANBUL.example").as_deref(),
            Some("istanbul.example")
        );
    }

    #[test]
    fn addresses_are_their_own_site() {
        assert_eq!(
            site_of("http://192.168.0.1:8080/admin").as_deref(),
            Some("192.168.0.1")
        );
        assert_eq!(
            site_of("https://[2001:DB8:0:0:0:0:0:1]:443/").as_deref(),
            Some("2001:db8::1")
        );
        // Not four numbers, so a name (its last label is a suffix of one label).
        assert_eq!(site_of("http://1.2.3").as_deref(), Some("2.3"));
    }

    #[test]
    fn shared_hosts_are_whole() {
        let shared = ["sites.example.net"];
        assert_eq!(
            site("https://Mysite.sites.example.net/x", &shared).as_deref(),
            Some("mysite.sites.example.net")
        );
        assert_eq!(
            site("https://sites.example.net/", &shared).as_deref(),
            Some("sites.example.net")
        );
        assert_eq!(
            site("https://other.example.net/", &shared).as_deref(),
            Some("example.net")
        );
        // A host that only ends in the same letters is not under it.
        assert_eq!(
            site("https://notsites.example.net/", &shared).as_deref(),
            Some("example.net")
        );
    }

    #[test]
    fn app_package_names_are_whole() {
        assert_eq!(
            site_of("androidapp://com.Example.app").as_deref(),
            Some("com.example.app")
        );
        assert_eq!(
            site_of("iosapp://com.example.mail").as_deref(),
            Some("com.example.mail")
        );
    }

    #[test]
    fn text_that_is_not_a_host_has_no_site() {
        for uri in [
            "",
            "   ",
            "https://",
            "my bank",
            "https://exa mple.com",
            "a..b",
        ] {
            assert_eq!(site_of(uri), None, "{uri:?}");
        }
    }
}
