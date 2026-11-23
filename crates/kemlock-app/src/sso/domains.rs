//! Email domains are proven with a DNS TXT record before SSO or sign-up rules apply to them
//! (design, "Accounts"). The admin claims a domain; the server makes a random token for it; the
//! admin publishes `kemlock-verification=<token>` as a TXT record at the domain; checking looks it
//! up and marks the domain verified.

use crate::error::AppError;
use crate::platform::Platform;
use crate::sso::error::SsoError;
use crate::sso::model::VerifiedDomain;
use crate::sso::ports::{TxtLookup, VerifiedDomainRepo};
use subtle::ConstantTimeEq;

/// What a TXT record's text starts with; the token follows.
pub const TXT_PREFIX: &str = "kemlock-verification=";

/// The longest a domain name can be (RFC 1035).
const MAX_DOMAIN_LEN: usize = 253;

/// A domain in the form the store keys it by: lower-case, no trailing dot, letters, digits and
/// hyphens in labels of 1 to 63 characters, at least two labels. Internationalised names come in
/// as punycode (`xn--...`).
pub fn normalise_domain(raw: &str) -> Result<String, SsoError> {
    let domain = raw.trim().trim_end_matches('.').to_ascii_lowercase();
    let bad = SsoError::Invalid("not a valid domain name");
    if domain.len() < 3 || domain.len() > MAX_DOMAIN_LEN {
        return Err(bad);
    }
    let labels: Vec<&str> = domain.split('.').collect();
    if labels.len() < 2 {
        return Err(bad);
    }
    for label in labels {
        let ok = (1..=63).contains(&label.len())
            && label
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
            && !label.starts_with('-')
            && !label.ends_with('-');
        if !ok {
            return Err(bad);
        }
    }
    Ok(domain)
}

/// Whether one of the TXT `records` is `kemlock-verification=<token>`. Spaces around the record
/// and one pair of surrounding quotes (some DNS panels keep them) are ignored.
pub fn records_prove(records: &[String], token: &str) -> bool {
    !token.is_empty()
        && records.iter().any(|record| {
            let record = record.trim();
            let record = record
                .strip_prefix('"')
                .and_then(|r| r.strip_suffix('"'))
                .unwrap_or(record);
            record
                .strip_prefix(TXT_PREFIX)
                .is_some_and(|found| bool::from(found.trim().as_bytes().ct_eq(token.as_bytes())))
        })
}

fn hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        out.push(char::from(DIGITS[usize::from(b >> 4)]));
        out.push(char::from(DIGITS[usize::from(b & 15)]));
    }
    out
}

#[derive(Debug)]
pub struct DomainProofs<R, T, E> {
    pub repos: R,
    pub dns: T,
    pub env: E,
}

impl<R: VerifiedDomainRepo, T: TxtLookup, E: Platform> DomainProofs<R, T, E> {
    /// Claims `domain`: makes its token, or returns the claim that is already there, so asking
    /// twice shows the admin the same record to publish.
    pub async fn begin(&self, domain: &str) -> Result<VerifiedDomain, SsoError> {
        let domain = normalise_domain(domain)?;
        if let Some(existing) = self.repos.domain_claim(&domain).await? {
            return Ok(existing);
        }
        let claim = VerifiedDomain {
            domain,
            token: hex(&self.env.bytes::<16>()),
            created_at: self.env.now(),
            verified_at: None,
        };
        self.repos.put_domain_claim(&claim).await?;
        Ok(claim)
    }

    /// Looks for the record and marks the claim verified when it is there.
    /// `SsoError::DomainProofMissing` when it isn't (yet).
    pub async fn check(&self, domain: &str) -> Result<VerifiedDomain, SsoError> {
        let domain = normalise_domain(domain)?;
        let mut claim = self
            .repos
            .domain_claim(&domain)
            .await?
            .ok_or(SsoError::App(AppError::NotFound))?;
        if claim.is_verified() {
            return Ok(claim);
        }
        let records = self.dns.txt_records(&domain).await?;
        if !records_prove(&records, &claim.token) {
            return Err(SsoError::DomainProofMissing);
        }
        claim.verified_at = Some(self.env.now());
        self.repos.put_domain_claim(&claim).await?;
        Ok(claim)
    }

    /// Whether `domain` has a verified claim.
    pub async fn is_verified(&self, domain: &str) -> Result<bool, SsoError> {
        let domain = normalise_domain(domain)?;
        Ok(self
            .repos
            .domain_claim(&domain)
            .await?
            .is_some_and(|c| c.is_verified()))
    }

    /// Drops a claim, proven or not.
    pub async fn remove(&self, domain: &str) -> Result<(), SsoError> {
        let domain = normalise_domain(domain)?;
        Ok(self.repos.remove_domain_claim(&domain).await?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn records(values: &[&str]) -> Vec<String> {
        values.iter().map(|v| (*v).to_owned()).collect()
    }

    #[test]
    fn domains_are_normalised() {
        assert_eq!(normalise_domain(" Example.ORG. "), Ok("example.org".into()));
        assert_eq!(
            normalise_domain("xn--bcher-kva.example"),
            Ok("xn--bcher-kva.example".into())
        );
        assert_eq!(normalise_domain("a-b.c1.io"), Ok("a-b.c1.io".into()));
    }

    #[test]
    fn bad_domains_are_refused() {
        let long_label = format!("{}.org", "a".repeat(64));
        let long_name = format!(
            "{}.org",
            std::iter::repeat_n("a".repeat(60), 5)
                .collect::<Vec<_>>()
                .join(".")
        );
        for bad in [
            "",
            "localhost",
            "a..b",
            ".example.org",
            "-a.example.org",
            "a-.example.org",
            "exa mple.org",
            "exa_mple.org",
            "example.org/path",
            "user@example.org",
            long_label.as_str(),
            long_name.as_str(),
        ] {
            assert!(normalise_domain(bad).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn the_record_proves_the_domain_when_the_token_matches() {
        assert!(records_prove(
            &records(&["kemlock-verification=abc123"]),
            "abc123"
        ));
        assert!(records_prove(
            &records(&["v=spf1 -all", "kemlock-verification=abc123"]),
            "abc123"
        ));
        assert!(records_prove(
            &records(&["\"kemlock-verification=abc123\""]),
            "abc123"
        ));
        assert!(records_prove(
            &records(&["  kemlock-verification=abc123 "]),
            "abc123"
        ));
    }

    #[test]
    fn a_wrong_or_partial_token_proves_nothing() {
        assert!(!records_prove(
            &records(&["kemlock-verification=abc124"]),
            "abc123"
        ));
        assert!(!records_prove(
            &records(&["kemlock-verification=abc1234"]),
            "abc123"
        ));
        assert!(!records_prove(
            &records(&["kemlock-verification=abc12"]),
            "abc123"
        ));
        assert!(!records_prove(
            &records(&["kemlock-verification=abc123x"]),
            "abc123"
        ));
        assert!(!records_prove(&records(&["other=abc123"]), "abc123"));
        assert!(!records_prove(&records(&["abc123"]), "abc123"));
        assert!(!records_prove(&[], "abc123"));
        assert!(!records_prove(&records(&["kemlock-verification="]), ""));
    }

    #[test]
    fn hex_is_lowercase_and_twice_as_long() {
        assert_eq!(hex(&[0x00, 0xab, 0xff]), "00abff");
    }
}
