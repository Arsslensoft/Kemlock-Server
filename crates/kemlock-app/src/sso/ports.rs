//! The ports the SSO use cases call. Adapters implement them: `kemlock-store-sql` the repositories,
//! `kemlock-identity` the OpenID Connect provider and the DNS lookup, and the spaces area the two
//! space ports. Methods have distinct names (`find_identity`, `sso_settings`, ...) so a store that
//! implements every port needs no disambiguation.

use crate::ports::StoreError;
use crate::sso::error::SsoError;
use crate::sso::model::{
    AuthorizationRequest, ClientConfig, CodeExchange, GroupAssignment, IdentityClaims,
    LogoutClaims, SpaceRole, SsoIdentity, SsoSettings, VerifiedDomain,
};
use kemlock_domain::{SpaceId, UserId};
use std::future::Future;
use time::OffsetDateTime;

/// The provider connection: one row, edited by the admin console or seeded from `SSO_*`.
pub trait SsoSettingsRepo: Send + Sync {
    fn sso_settings(&self) -> impl Future<Output = Result<Option<SsoSettings>, StoreError>> + Send;
    /// Inserts the settings, or replaces the row that is there.
    fn put_sso_settings(
        &self,
        settings: &SsoSettings,
    ) -> impl Future<Output = Result<(), StoreError>> + Send;
}

/// The links between accounts and provider subjects (`sso_identities`).
pub trait SsoIdentityRepo: Send + Sync {
    fn find_identity(
        &self,
        issuer: &str,
        subject: &str,
    ) -> impl Future<Output = Result<Option<SsoIdentity>, StoreError>> + Send;
    /// Links a subject to an account; `Duplicate` when the subject is already linked, `NotFound`
    /// when the account is gone.
    fn insert_identity(
        &self,
        identity: &SsoIdentity,
    ) -> impl Future<Output = Result<(), StoreError>> + Send;
    fn identities_of(
        &self,
        user: UserId,
    ) -> impl Future<Output = Result<Vec<SsoIdentity>, StoreError>> + Send;
    /// Records a sign-in: the time, and the email the provider gave this time.
    fn touch_identity(
        &self,
        issuer: &str,
        subject: &str,
        email: &str,
        at: OffsetDateTime,
    ) -> impl Future<Output = Result<(), StoreError>> + Send;
}

/// The domains an admin claims, proven or pending (`verified_domains`).
pub trait VerifiedDomainRepo: Send + Sync {
    fn domain_claim(
        &self,
        domain: &str,
    ) -> impl Future<Output = Result<Option<VerifiedDomain>, StoreError>> + Send;
    fn domain_claims(&self)
    -> impl Future<Output = Result<Vec<VerifiedDomain>, StoreError>> + Send;
    /// Inserts the claim, or replaces the one for the same domain.
    fn put_domain_claim(
        &self,
        claim: &VerifiedDomain,
    ) -> impl Future<Output = Result<(), StoreError>> + Send;
    fn remove_domain_claim(
        &self,
        domain: &str,
    ) -> impl Future<Output = Result<(), StoreError>> + Send;
}

/// Every SSO repository in one bound. `SqlStore` implements all three.
pub trait SsoRepos:
    SsoSettingsRepo + SsoIdentityRepo + VerifiedDomainRepo + Clone + 'static
{
}

impl<T> SsoRepos for T where
    T: SsoSettingsRepo + SsoIdentityRepo + VerifiedDomainRepo + Clone + 'static
{
}

/// DNS TXT lookups, for the domain proof.
pub trait TxtLookup: Send + Sync {
    /// The TXT records at `name`, each with its character-strings joined. An empty list when the
    /// name has none (or doesn't exist); an error only when DNS itself failed.
    fn txt_records(&self, name: &str)
    -> impl Future<Output = Result<Vec<String>, SsoError>> + Send;
}

/// The OpenID Connect relying party. Implemented by `kemlock-identity` over the `openidconnect`
/// crate; tests use scripted fakes. The adapter does discovery and caches it, and validates every
/// token it hands back, so a use case only sees claims it can trust.
pub trait OidcProvider: Send + Sync {
    /// The provider's authorization URL for this request: authorization code flow, PKCE S256,
    /// the nonce, the server's callback.
    fn authorization_url(
        &self,
        client: &ClientConfig,
        request: &AuthorizationRequest,
    ) -> impl Future<Output = Result<String, SsoError>> + Send;

    /// Exchanges the code for tokens and validates the ID token: signature against the provider's
    /// keys, issuer, audience, expiry and nonce. Returns the claims, `amr` and `groups` included.
    fn exchange(
        &self,
        client: &ClientConfig,
        request: &CodeExchange,
    ) -> impl Future<Output = Result<IdentityClaims, SsoError>> + Send;

    /// Validates a back-channel logout token (OpenID Connect Back-Channel Logout 1.0, section
    /// 2.6) and names what it ends.
    fn validate_logout_token(
        &self,
        client: &ClientConfig,
        token: &str,
    ) -> impl Future<Output = Result<LogoutClaims, SsoError>> + Send;
}

/// One space an account belongs to, with what the Require SSO policy needs to know.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SpaceMembership {
    pub space: SpaceId,
    pub role: SpaceRole,
    /// Whether the space's "Require SSO" policy is on.
    pub require_sso: bool,
}

/// The membership facts the Require SSO policy reads. Spaces are another area's work: its store
/// implements this over its own tables.
pub trait MembershipFacts: Send + Sync {
    /// Every space the user is a member of.
    fn spaces_of(
        &self,
        user: UserId,
    ) -> impl Future<Output = Result<Vec<SpaceMembership>, StoreError>> + Send;
}

/// Applies the group rules' result to an account at each SSO sign-in. Implemented by the spaces
/// area.
///
/// `assignments` is the complete result of the admin's rules for this user right now, possibly
/// empty. The implementer adds a membership that is missing (a new member still waits for
/// someone to confirm their key fingerprint, so this grants no key), and updates the role and
/// collections of one that is there. Whether to remove a membership the rules no longer give is
/// the spaces area's call. A failure is logged and never stops the sign-in.
pub trait GroupSync: Send + Sync {
    fn apply_groups(
        &self,
        user: UserId,
        assignments: &[GroupAssignment],
    ) -> impl Future<Output = Result<(), StoreError>> + Send;
}

/// The spaces ports for a server that has no spaces: nobody is in one, and nothing is applied.
#[derive(Clone, Copy, Debug, Default)]
pub struct NoSpaces;

impl MembershipFacts for NoSpaces {
    async fn spaces_of(&self, _user: UserId) -> Result<Vec<SpaceMembership>, StoreError> {
        Ok(Vec::new())
    }
}

impl GroupSync for NoSpaces {
    async fn apply_groups(
        &self,
        _user: UserId,
        _assignments: &[GroupAssignment],
    ) -> Result<(), StoreError> {
        Ok(())
    }
}

// A provider or a lookup shared behind an `Arc` is still one: the server keeps one `OidcClient`
// (it caches the provider's keys) and hands every request a clone of the handle.

impl<T: OidcProvider> OidcProvider for std::sync::Arc<T> {
    fn authorization_url(
        &self,
        client: &ClientConfig,
        request: &AuthorizationRequest,
    ) -> impl Future<Output = Result<String, SsoError>> + Send {
        (**self).authorization_url(client, request)
    }

    fn exchange(
        &self,
        client: &ClientConfig,
        request: &CodeExchange,
    ) -> impl Future<Output = Result<IdentityClaims, SsoError>> + Send {
        (**self).exchange(client, request)
    }

    fn validate_logout_token(
        &self,
        client: &ClientConfig,
        token: &str,
    ) -> impl Future<Output = Result<LogoutClaims, SsoError>> + Send {
        (**self).validate_logout_token(client, token)
    }
}

impl<T: TxtLookup> TxtLookup for std::sync::Arc<T> {
    fn txt_records(
        &self,
        name: &str,
    ) -> impl Future<Output = Result<Vec<String>, SsoError>> + Send {
        (**self).txt_records(name)
    }
}

impl<T: MembershipFacts> MembershipFacts for std::sync::Arc<T> {
    fn spaces_of(
        &self,
        user: UserId,
    ) -> impl Future<Output = Result<Vec<SpaceMembership>, StoreError>> + Send {
        (**self).spaces_of(user)
    }
}

impl<T: GroupSync> GroupSync for std::sync::Arc<T> {
    fn apply_groups(
        &self,
        user: UserId,
        assignments: &[GroupAssignment],
    ) -> impl Future<Output = Result<(), StoreError>> + Send {
        (**self).apply_groups(user, assignments)
    }
}
