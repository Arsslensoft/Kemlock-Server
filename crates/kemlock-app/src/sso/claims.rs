//! Rules about what a provider's claims mean: whether `amr` shows multi-factor authentication,
//! whether an email may be trusted, and an email's domain.

use crate::sso::model::{IdentityClaims, SsoSettings};

/// The factor an RFC 8176 `amr` value stands for, when it names one.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Factor {
    Knowledge,
    Possession,
    Inherence,
}

fn factor(method: &str) -> Option<Factor> {
    Some(match method {
        "pwd" | "pin" | "kba" => Factor::Knowledge,
        "otp" | "hwk" | "swk" | "sc" | "sms" | "tel" | "geo" => Factor::Possession,
        "fpt" | "face" | "iris" | "retina" | "vbm" => Factor::Inherence,
        _ => return None,
    })
}

/// Whether the ID token's `amr` shows the provider did multi-factor authentication: it says
/// `mfa` itself, or names methods of at least two kinds (something known, something held,
/// something the person is). One kind alone, such as a password, or a password and a second
/// password, is not enough. Values are compared case-insensitively. An absent `amr` shows nothing.
///
/// Kemlock's own two-step check is skipped only when this is true (design, "Policies").
pub fn amr_shows_mfa(amr: &[String]) -> bool {
    let mut seen: Vec<Factor> = Vec::new();
    for value in amr {
        let value = value.trim().to_ascii_lowercase();
        if value == "mfa" {
            return true;
        }
        if let Some(kind) = factor(&value)
            && !seen.contains(&kind)
        {
            seen.push(kind);
        }
    }
    seen.len() >= 2
}

/// The part of `email` after the last `@`, lower-cased.
pub fn email_domain(email: &str) -> Option<String> {
    let (local, domain) = email.trim().rsplit_once('@')?;
    if local.is_empty() || domain.is_empty() {
        return None;
    }
    Some(domain.to_ascii_lowercase())
}

/// How far the provider vouches for the email in a token.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EmailTrust {
    /// The provider said `email_verified: true`.
    Verified,
    /// The provider sent no `email_verified` claim, and the admin allows that for emails under a
    /// DNS-verified domain: the caller must check the domain.
    NeedsDomainProof,
    /// `email_verified` is false, or absent without the exception, or there is no email.
    Refused,
}

/// Applies the email rule: refuse tokens without `email_verified: true`, unless
/// `SSO_ALLOW_UNKNOWN_EMAIL_VERIFICATION` is set and the claim is absent (an explicit `false`
/// is never accepted). The exception still needs the email's domain proven by DNS.
pub fn email_trust(settings: &SsoSettings, claims: &IdentityClaims) -> EmailTrust {
    if claims.email.is_none() {
        return EmailTrust::Refused;
    }
    match claims.email_verified {
        Some(true) => EmailTrust::Verified,
        None if settings.allow_unknown_email_verification => EmailTrust::NeedsDomainProof,
        _ => EmailTrust::Refused,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use time::macros::datetime;

    fn amr(values: &[&str]) -> Vec<String> {
        values.iter().map(|v| (*v).to_owned()).collect()
    }

    #[test]
    fn mfa_is_shown_by_the_mfa_value() {
        assert!(amr_shows_mfa(&amr(&["mfa"])));
        assert!(amr_shows_mfa(&amr(&["pwd", "MFA"])));
    }

    #[test]
    fn two_kinds_of_factor_show_mfa() {
        assert!(amr_shows_mfa(&amr(&["pwd", "otp"])));
        assert!(amr_shows_mfa(&amr(&["pwd", "hwk"])));
        assert!(amr_shows_mfa(&amr(&["hwk", "pin"])));
        assert!(amr_shows_mfa(&amr(&["swk", "fpt"])));
    }

    #[test]
    fn one_kind_of_factor_does_not() {
        assert!(!amr_shows_mfa(&[]));
        assert!(!amr_shows_mfa(&amr(&["pwd"])));
        assert!(!amr_shows_mfa(&amr(&["pwd", "pin"])));
        assert!(!amr_shows_mfa(&amr(&["otp", "hwk"])));
        assert!(!amr_shows_mfa(&amr(&["pwd", "pwd"])));
    }

    #[test]
    fn unknown_values_show_nothing() {
        assert!(!amr_shows_mfa(&amr(&["urn:custom:thing", "pwd"])));
        assert!(!amr_shows_mfa(&amr(&["", " "])));
    }

    #[test]
    fn domains_come_from_after_the_last_at() {
        assert_eq!(email_domain("Ada@Example.ORG"), Some("example.org".into()));
        assert_eq!(email_domain("a@b@c.io"), Some("c.io".into()));
        assert_eq!(email_domain("nodomain"), None);
        assert_eq!(email_domain("@x.io"), None);
        assert_eq!(email_domain("x@"), None);
    }

    fn claims(email_verified: Option<bool>) -> IdentityClaims {
        IdentityClaims {
            issuer: "https://idp.test".into(),
            subject: "s".into(),
            email: Some("a@b.co".into()),
            email_verified,
            name: None,
            amr: vec![],
            groups: vec![],
            session_id: None,
        }
    }

    fn settings(allow_unknown: bool) -> SsoSettings {
        let mut s = SsoSettings::new("https://idp.test", "c", datetime!(2026-01-01 0:00 UTC));
        s.allow_unknown_email_verification = allow_unknown;
        s
    }

    #[test]
    fn a_verified_email_is_trusted() {
        assert_eq!(
            email_trust(&settings(false), &claims(Some(true))),
            EmailTrust::Verified
        );
    }

    #[test]
    fn an_unverified_email_is_refused_even_with_the_exception() {
        assert_eq!(
            email_trust(&settings(true), &claims(Some(false))),
            EmailTrust::Refused
        );
        assert_eq!(
            email_trust(&settings(false), &claims(Some(false))),
            EmailTrust::Refused
        );
    }

    #[test]
    fn a_missing_claim_needs_the_exception_and_a_domain_proof() {
        assert_eq!(
            email_trust(&settings(false), &claims(None)),
            EmailTrust::Refused
        );
        assert_eq!(
            email_trust(&settings(true), &claims(None)),
            EmailTrust::NeedsDomainProof
        );
    }

    #[test]
    fn no_email_is_refused() {
        let mut c = claims(Some(true));
        c.email = None;
        assert_eq!(email_trust(&settings(true), &c), EmailTrust::Refused);
    }
}
