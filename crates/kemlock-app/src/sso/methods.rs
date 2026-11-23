//! Which ways in the server offers for an email, beyond the password every account has.
//!
//! Single sign-on is offered when a provider is set up and enabled, and, when the admin limits
//! sign-in to verified domains (`require_verified_domain`), only for an email under a domain
//! whose DNS proof is in. The answer depends on the email's domain and the settings, never on
//! whether an account exists, so it can't be used to find accounts.

use crate::error::AppError;
use crate::sso::domains::normalise_domain;
use crate::sso::ports::{SsoSettingsRepo, VerifiedDomainRepo};

#[derive(Debug)]
pub struct SignInMethods<R> {
    pub repos: R,
}

impl<R: SsoSettingsRepo + VerifiedDomainRepo> SignInMethods<R> {
    /// Whether single sign-on is a way in for `email`. An email that isn't one has only the
    /// password.
    pub async fn offers_sso(&self, email: &str) -> Result<bool, AppError> {
        Ok(self.sso_provider(email).await?.is_some())
    }

    /// The name the sign-in button shows when single sign-on is a way in for `email`, `None`
    /// when it isn't. While a provider is enabled every email gets the same answer, unless the
    /// admin limits sign-in to verified domains.
    pub async fn sso_provider(&self, email: &str) -> Result<Option<String>, AppError> {
        let Some(settings) = self.repos.sso_settings().await? else {
            return Ok(None);
        };
        if !settings.enabled {
            return Ok(None);
        }
        if settings.require_verified_domain {
            let Some((_, domain)) = email.trim().rsplit_once('@') else {
                return Ok(None);
            };
            let Ok(domain) = normalise_domain(domain) else {
                return Ok(None);
            };
            let proven = self
                .repos
                .domain_claim(&domain)
                .await?
                .is_some_and(|claim| claim.is_verified());
            if !proven {
                return Ok(None);
            }
        }
        Ok(Some(settings.provider_name()))
    }
}
