//! The data SSO keeps and passes around: the provider settings, linked identities, proven domains,
//! group rules and the claims a provider asserts.

use crate::error::AppError;
use crate::ports::SecretSeal;
use crate::sso::error::SsoError;
use kemlock_domain::{SpaceId, UserId};
use serde::{Deserialize, Serialize};
use std::fmt;
use time::OffsetDateTime;
use uuid::Uuid;

/// `SecretSeal` purpose of the provider's client secret in `sso_settings`.
pub const PURPOSE_CLIENT_SECRET: &str = "sso-client-secret";

/// The scopes asked for besides `openid`, when the admin names none (Vaultwarden's default).
pub const DEFAULT_SCOPES: [&str; 2] = ["email", "profile"];

/// A role inside a space. Spaces are another area's work; this is only what a group rule can
/// grant and what the Require SSO policy looks at. Ordered so a higher role wins a merge.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum SpaceRole {
    Member,
    Admin,
    Owner,
}

/// One rule of the admin's mapping: members of `group` get `role` in `space`, with access to
/// `collections`. Stored as data in `sso_settings`, applied at each sign-in.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GroupRule {
    /// The value in the ID token's `groups` claim, compared exactly.
    pub group: String,
    pub space: SpaceId,
    pub role: SpaceRole,
    #[serde(default)]
    pub collections: Vec<Uuid>,
}

/// What the rules give a user in one space after merging every rule their groups match.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GroupAssignment {
    pub space: SpaceId,
    pub role: SpaceRole,
    pub collections: Vec<Uuid>,
}

/// The single provider this server signs people in through (design, "More identity providers":
/// one OpenID Connect connection; SAML goes through a broker).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SsoSettings {
    pub enabled: bool,
    /// What the sign-in button says.
    pub display_name: String,
    /// The provider's issuer URL (`SSO_AUTHORITY`); discovery reads `<issuer>/.well-known/...`.
    pub issuer: String,
    pub client_id: String,
    /// The client secret sealed under `server.key` (`PURPOSE_CLIENT_SECRET`); `None` for a public
    /// client, which PKCE protects.
    pub sealed_client_secret: Option<Vec<u8>>,
    /// Scopes beyond `openid`.
    pub scopes: Vec<String>,
    /// `SSO_ALLOW_UNKNOWN_EMAIL_VERIFICATION`: accept an ID token with no `email_verified` claim,
    /// but only for an email whose domain is DNS-verified.
    pub allow_unknown_email_verification: bool,
    /// `SSO_SIGNUPS_MATCH_EMAIL`: link a first sign-in to the existing account with the same
    /// (verified) email.
    pub link_by_email: bool,
    /// Make an account for a subject nobody has linked and no email matches. The provider is the
    /// admin's own, so this is on by default.
    pub create_accounts: bool,
    /// Link and create only for emails under a DNS-verified domain.
    pub require_verified_domain: bool,
    pub group_rules: Vec<GroupRule>,
    pub updated_at: OffsetDateTime,
}

impl SsoSettings {
    /// An enabled provider with the defaults.
    pub fn new(
        issuer: impl Into<String>,
        client_id: impl Into<String>,
        now: OffsetDateTime,
    ) -> Self {
        SsoSettings {
            enabled: true,
            display_name: "Single sign-on".to_owned(),
            issuer: issuer.into(),
            client_id: client_id.into(),
            sealed_client_secret: None,
            scopes: DEFAULT_SCOPES.iter().map(|s| (*s).to_owned()).collect(),
            allow_unknown_email_verification: false,
            link_by_email: true,
            create_accounts: true,
            require_verified_domain: false,
            group_rules: Vec::new(),
            updated_at: now,
        }
    }

    /// What the sign-in button says: the display name, or the issuer's host when it is blank.
    pub fn provider_name(&self) -> String {
        let name = self.display_name.trim();
        if name.is_empty() {
            issuer_host(&self.issuer).to_owned()
        } else {
            name.to_owned()
        }
    }

    /// Seals `secret` under the server key and keeps it.
    pub fn set_client_secret<S: SecretSeal>(&mut self, seal: &S, secret: &str) {
        self.sealed_client_secret = Some(seal.seal(PURPOSE_CLIENT_SECRET, secret.as_bytes()));
    }

    /// What a provider adapter needs to talk to the provider, with the secret opened.
    pub fn client_config<S: SecretSeal>(&self, seal: &S) -> Result<ClientConfig, SsoError> {
        let client_secret = match &self.sealed_client_secret {
            None => None,
            Some(sealed) => {
                let plain = seal.open(PURPOSE_CLIENT_SECRET, sealed).map_err(|_| {
                    SsoError::App(AppError::Store(
                        "the stored SSO client secret doesn't open".to_owned(),
                    ))
                })?;
                Some(String::from_utf8(plain.to_vec()).map_err(|_| {
                    SsoError::App(AppError::Store(
                        "the stored SSO client secret isn't text".to_owned(),
                    ))
                })?)
            }
        };
        Ok(ClientConfig {
            issuer: self.issuer.clone(),
            client_id: self.client_id.clone(),
            client_secret,
            scopes: self.scopes.clone(),
        })
    }
}

/// The host of an issuer URL, without scheme, credentials, port or path; the whole text when it
/// has no scheme.
fn issuer_host(issuer: &str) -> &str {
    let rest = issuer.split_once("://").map_or(issuer, |(_, rest)| rest);
    let authority = rest.split(['/', '?', '#']).next().unwrap_or_default();
    let authority = authority
        .rsplit_once('@')
        .map_or(authority, |(_, host)| host);
    if authority.starts_with('[') {
        return authority.split_inclusive(']').next().unwrap_or(authority);
    }
    authority.split(':').next().unwrap_or(authority)
}

/// The provider connection, ready for an adapter. The secret never reaches a log.
#[derive(Clone, PartialEq, Eq)]
pub struct ClientConfig {
    pub issuer: String,
    pub client_id: String,
    pub client_secret: Option<String>,
    /// Scopes beyond `openid`.
    pub scopes: Vec<String>,
}

impl fmt::Debug for ClientConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ClientConfig")
            .field("issuer", &self.issuer)
            .field("client_id", &self.client_id)
            .finish_non_exhaustive()
    }
}

/// A link between an account and a subject at a provider. One user may link several providers.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SsoIdentity {
    pub issuer: String,
    pub subject: String,
    pub user: UserId,
    /// The email the provider gave at the last sign-in, for the admin's eyes.
    pub email: String,
    pub linked_at: OffsetDateTime,
    pub last_login_at: OffsetDateTime,
}

/// An email domain an admin claims, and whether DNS proves it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifiedDomain {
    /// Lower-case, without a trailing dot.
    pub domain: String,
    /// The random token to publish as `kemlock-verification=<token>` in a TXT record.
    pub token: String,
    pub created_at: OffsetDateTime,
    /// Set when DNS showed the token; `None` while the claim is pending.
    pub verified_at: Option<OffsetDateTime>,
}

impl VerifiedDomain {
    pub fn is_verified(&self) -> bool {
        self.verified_at.is_some()
    }

    /// The TXT record value the admin publishes.
    pub fn txt_value(&self) -> String {
        format!("{}{}", crate::sso::domains::TXT_PREFIX, self.token)
    }
}

/// What a validated ID token asserts. Built by the provider adapter after it checked the
/// signature, issuer, audience, expiry and nonce.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IdentityClaims {
    pub issuer: String,
    pub subject: String,
    pub email: Option<String>,
    /// `None` when the provider sent no `email_verified` claim.
    pub email_verified: Option<bool>,
    pub name: Option<String>,
    /// Authentication Method References (RFC 8176), such as `pwd`, `otp`, `mfa`.
    pub amr: Vec<String>,
    pub groups: Vec<String>,
    pub session_id: Option<String>,
}

/// What a validated back-channel logout token names.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LogoutClaims {
    pub issuer: String,
    pub subject: Option<String>,
    pub session_id: Option<String>,
}

/// The authorization request the server makes of the provider.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AuthorizationRequest {
    /// Comes back unchanged on the callback; the server's sealed state.
    pub state: String,
    pub nonce: String,
    /// The server's PKCE verifier; the adapter sends its S256 challenge.
    pub code_verifier: String,
    /// The server's callback address.
    pub redirect_uri: String,
}

/// The code exchange the server makes after the callback.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CodeExchange {
    pub code: String,
    pub code_verifier: String,
    pub redirect_uri: String,
    /// The nonce the ID token must carry.
    pub nonce: String,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ports::CryptoError;
    use time::macros::datetime;

    struct XorSeal;

    impl SecretSeal for XorSeal {
        fn seal(&self, purpose: &str, value: &[u8]) -> Vec<u8> {
            let mut out = purpose.as_bytes().to_vec();
            out.push(0);
            out.extend(value.iter().map(|b| b ^ 0x55));
            out
        }

        fn open(
            &self,
            purpose: &str,
            sealed: &[u8],
        ) -> Result<crate::ports::Zeroizing<Vec<u8>>, CryptoError> {
            let mut prefix = purpose.as_bytes().to_vec();
            prefix.push(0);
            sealed
                .strip_prefix(prefix.as_slice())
                .map(|rest| crate::ports::Zeroizing::new(rest.iter().map(|b| b ^ 0x55).collect()))
                .ok_or(CryptoError::Invalid)
        }
    }

    fn settings() -> SsoSettings {
        SsoSettings::new(
            "https://idp.test",
            "kemlock",
            datetime!(2026-01-01 0:00 UTC),
        )
    }

    #[test]
    fn the_client_secret_round_trips_and_stays_out_of_debug() {
        let mut settings = settings();
        settings.set_client_secret(&XorSeal, "s3cret");
        let client = settings.client_config(&XorSeal).expect("opens");
        assert_eq!(client.client_secret.as_deref(), Some("s3cret"));
        assert!(!format!("{client:?}").contains("s3cret"));
    }

    #[test]
    fn a_public_client_has_no_secret() {
        let client = settings().client_config(&XorSeal).expect("config");
        assert_eq!(client.client_secret, None);
    }

    #[test]
    fn a_secret_sealed_for_another_purpose_is_refused() {
        let mut settings = settings();
        settings.sealed_client_secret = Some(XorSeal.seal("totp", b"x"));
        assert!(settings.client_config(&XorSeal).is_err());
    }

    #[test]
    fn a_blank_display_name_falls_back_to_the_issuers_host() {
        let mut settings = settings();
        settings.display_name = "Example Co".to_owned();
        assert_eq!(settings.provider_name(), "Example Co");
        settings.display_name = "  ".to_owned();
        assert_eq!(settings.provider_name(), "idp.test");
        settings.issuer = "https://login.example.org:8443/realms/kemlock".to_owned();
        assert_eq!(settings.provider_name(), "login.example.org");
        settings.issuer = "http://[::1]:8080/".to_owned();
        assert_eq!(settings.provider_name(), "[::1]");
    }

    #[test]
    fn roles_order_so_the_higher_one_wins() {
        assert!(SpaceRole::Owner > SpaceRole::Admin);
        assert!(SpaceRole::Admin > SpaceRole::Member);
    }

    #[test]
    fn a_pending_domain_isnt_verified_and_names_its_record() {
        let mut domain = VerifiedDomain {
            domain: "example.org".into(),
            token: "abc".into(),
            created_at: datetime!(2026-01-01 0:00 UTC),
            verified_at: None,
        };
        assert!(!domain.is_verified());
        assert_eq!(domain.txt_value(), "kemlock-verification=abc");
        domain.verified_at = Some(domain.created_at);
        assert!(domain.is_verified());
    }
}
