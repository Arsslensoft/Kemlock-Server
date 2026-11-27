//! The SSO screen: the provider connection (over the SSO area's `sso_settings` row) and the email
//! domains an admin proves by DNS.
//!
//! The client secret is sealed under `server.key` as the SSO area does it, and is never read back
//! out: the console learns only whether one is set.

use super::audit::Audit;
use super::error::AdminError;
use super::ports::{AdminEventRepo, AdminUserRepo, Mailer};
use crate::authenticate::Actor;
use crate::platform::Platform;
use crate::ports::SecretSeal;
use crate::sso::config::CALLBACK_PATH;
use crate::sso::{
    DomainProofs, GroupRule, SsoSettings, SsoSettingsRepo, TxtLookup, VerifiedDomain,
    VerifiedDomainRepo,
};
use std::net::IpAddr;

const MAX_GROUP_RULES: usize = 500;
const MAX_SCOPES: usize = 20;

/// What the console does with the stored client secret.
#[derive(Clone, PartialEq, Eq)]
pub enum SecretChange {
    /// Leave it as it is.
    Keep,
    /// Remove it (a public client, protected by PKCE alone).
    Clear,
    /// Seal and store this one.
    Set(String),
}

impl std::fmt::Debug for SecretChange {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SecretChange::Keep => f.write_str("Keep"),
            SecretChange::Clear => f.write_str("Clear"),
            SecretChange::Set(_) => f.write_str("Set(..)"),
        }
    }
}

/// The provider connection as the console sends it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SsoInput {
    pub enabled: bool,
    pub display_name: String,
    pub issuer: String,
    pub client_id: String,
    pub client_secret: SecretChange,
    pub scopes: Vec<String>,
    pub allow_unknown_email_verification: bool,
    pub link_by_email: bool,
    pub create_accounts: bool,
    pub require_verified_domain: bool,
    pub group_rules: Vec<GroupRule>,
}

/// The provider connection as the console shows it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SsoView {
    /// `None` until a provider is set up.
    pub settings: Option<SsoSettings>,
    /// Whether a client secret is stored.
    pub client_secret_set: bool,
    /// The redirect address to register at the provider.
    pub callback_url: String,
}

#[derive(Debug)]
pub struct SsoAdmin<So, T, R, M, P> {
    pub sso: So,
    pub dns: T,
    pub repos: R,
    pub mail: M,
    pub env: P,
    /// `DOMAIN`.
    pub domain: String,
}

fn invalid(why: &str) -> AdminError {
    AdminError::Invalid(why.to_owned())
}

fn plain_text(value: &str, max: usize) -> bool {
    !value.is_empty() && value.chars().count() <= max && !value.chars().any(char::is_control)
}

/// An issuer URL: `https://`, or `http://` for a provider on this machine; a host; no spaces.
fn issuer_ok(issuer: &str) -> bool {
    if issuer.len() > 512 || issuer.chars().any(|c| c.is_whitespace() || c.is_control()) {
        return false;
    }
    let (secure, rest) = if let Some(rest) = issuer.strip_prefix("https://") {
        (true, rest)
    } else if let Some(rest) = issuer.strip_prefix("http://") {
        (false, rest)
    } else {
        return false;
    };
    if rest.contains(['#', '?', '\\']) {
        return false;
    }
    let authority = rest.split('/').next().unwrap_or_default();
    if authority.is_empty() || authority.contains('@') {
        return false;
    }
    if secure {
        return true;
    }
    let host = authority
        .strip_prefix('[')
        .and_then(|h| h.split(']').next())
        .unwrap_or_else(|| authority.split(':').next().unwrap_or_default());
    matches!(host, "localhost" | "127.0.0.1" | "::1")
}

/// What the audit entry of a save says: the issuer, and each setting that decides who may sign in
/// as whom, with what it was, so an entry shows a provider swapped or linking turned on. Never a
/// secret.
fn change_summary(previous: Option<&SsoSettings>, issuer: &str, input: &SsoInput) -> String {
    let onoff = |on: bool| if on { "on" } else { "off" };
    let mut text = String::from("changed the single sign-on settings");
    if !input.enabled {
        text.push_str(" (sign-in is off)");
    }
    text.push_str(&format!(": issuer {issuer}"));
    match previous {
        Some(old) if old.issuer != issuer => {
            text.push_str(&format!(" (was {})", old.issuer));
        }
        None => text.push_str(" (new connection)"),
        _ => {}
    }
    let link = |label: &str, now: bool, was: Option<bool>| match was {
        Some(was) if was != now => format!("; {label} {} (was {})", onoff(now), onoff(was)),
        _ => format!("; {label} {}", onoff(now)),
    };
    text.push_str(&link(
        "link by email",
        input.link_by_email,
        previous.map(|p| p.link_by_email),
    ));
    text.push_str(&link(
        "verified domain required",
        input.require_verified_domain,
        previous.map(|p| p.require_verified_domain),
    ));
    text.push_str(&link(
        "create accounts",
        input.create_accounts,
        previous.map(|p| p.create_accounts),
    ));
    match &input.client_secret {
        SecretChange::Keep => {}
        SecretChange::Clear => text.push_str("; client secret cleared"),
        SecretChange::Set(_) => text.push_str("; client secret replaced"),
    }
    text
}

fn scope_ok(scope: &str) -> bool {
    (1..=64).contains(&scope.len())
        && scope
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, ':' | '.' | '_' | '/' | '-'))
}

impl<So, T, R, M, P> SsoAdmin<So, T, R, M, P>
where
    So: SsoSettingsRepo + VerifiedDomainRepo + Clone,
    T: TxtLookup + Clone,
    R: AdminEventRepo + AdminUserRepo + Clone,
    M: Mailer + Clone,
    P: Platform + SecretSeal + Clone,
{
    fn audit(&self) -> Audit<R, R, M, P> {
        Audit {
            events: self.repos.clone(),
            users: self.repos.clone(),
            mail: self.mail.clone(),
            clock: self.env.clone(),
        }
    }

    fn view(&self, settings: Option<SsoSettings>) -> SsoView {
        SsoView {
            client_secret_set: settings
                .as_ref()
                .is_some_and(|s| s.sealed_client_secret.is_some()),
            settings,
            callback_url: format!("{}{CALLBACK_PATH}", self.domain.trim_end_matches('/')),
        }
    }

    pub async fn get(&self) -> Result<SsoView, AdminError> {
        Ok(self.view(self.sso.sso_settings().await?))
    }

    /// Saves the provider connection, replacing what was there.
    pub async fn put(
        &self,
        actor: &Actor,
        ip: Option<IpAddr>,
        input: SsoInput,
    ) -> Result<SsoView, AdminError> {
        let display_name = input.display_name.trim().to_owned();
        if !plain_text(&display_name, 64) {
            return Err(invalid("displayName must be 1 to 64 characters"));
        }
        let issuer = input.issuer.trim().to_owned();
        if !issuer_ok(&issuer) {
            return Err(invalid(
                "issuer must be an https:// address (http:// only for localhost)",
            ));
        }
        let client_id = input.client_id.trim().to_owned();
        if !plain_text(&client_id, 256) || client_id.contains(char::is_whitespace) {
            return Err(invalid(
                "clientId must be 1 to 256 characters, with no spaces",
            ));
        }
        let mut scopes: Vec<String> = Vec::new();
        for scope in &input.scopes {
            let scope = scope.trim();
            if scope == "openid" || scopes.iter().any(|s| s == scope) {
                continue;
            }
            if !scope_ok(scope) {
                return Err(invalid("a scope has characters a scope can't have"));
            }
            scopes.push(scope.to_owned());
        }
        if scopes.len() > MAX_SCOPES {
            return Err(invalid("at most 20 scopes"));
        }
        if input.group_rules.len() > MAX_GROUP_RULES {
            return Err(invalid("at most 500 group rules"));
        }
        for rule in &input.group_rules {
            if !plain_text(&rule.group, 256) || rule.collections.len() > 200 {
                return Err(invalid(
                    "a group rule needs a group name of 1 to 256 characters and at most 200 collections",
                ));
            }
        }
        if let SecretChange::Set(secret) = &input.client_secret
            && !(1..=1024).contains(&secret.len())
        {
            return Err(invalid("clientSecret must be 1 to 1024 characters"));
        }

        let now = self.env.now();
        let previous = self.sso.sso_settings().await?;
        // The stored secret belongs to the provider it was made for: kept across a new issuer, it
        // would be sent to whoever answers there, and an admin could point the connection at a
        // server of their own to read it. A new issuer takes a new secret, or none.
        if let Some(old) = &previous
            && input.client_secret == SecretChange::Keep
            && old.sealed_client_secret.is_some()
            && old.issuer.trim_end_matches('/') != issuer.trim_end_matches('/')
        {
            return Err(invalid(
                "the issuer changed: enter the client secret again, or clear it",
            ));
        }
        let summary = change_summary(previous.as_ref(), &issuer, &input);
        let mut settings = match previous {
            Some(existing) => existing,
            None => SsoSettings::new(issuer.clone(), client_id.clone(), now),
        };
        settings.enabled = input.enabled;
        settings.display_name = display_name;
        settings.issuer = issuer;
        settings.client_id = client_id;
        settings.scopes = scopes;
        settings.allow_unknown_email_verification = input.allow_unknown_email_verification;
        settings.link_by_email = input.link_by_email;
        settings.create_accounts = input.create_accounts;
        settings.require_verified_domain = input.require_verified_domain;
        settings.group_rules = input.group_rules;
        settings.updated_at = now;
        match &input.client_secret {
            SecretChange::Keep => {}
            SecretChange::Clear => settings.sealed_client_secret = None,
            SecretChange::Set(secret) => settings.set_client_secret(&self.env, secret),
        }
        self.sso.put_sso_settings(&settings).await?;
        self.audit()
            .record(
                actor,
                ip,
                "admin.sso.update",
                None,
                &summary,
            )
            .await;
        Ok(self.view(Some(settings)))
    }

    // ---- domains ----

    fn proofs(&self) -> DomainProofs<So, T, P> {
        DomainProofs {
            repos: self.sso.clone(),
            dns: self.dns.clone(),
            env: self.env.clone(),
        }
    }

    pub async fn domains(&self) -> Result<Vec<VerifiedDomain>, AdminError> {
        Ok(self.sso.domain_claims().await?)
    }

    /// Claims a domain, or returns the claim that is there.
    pub async fn add_domain(
        &self,
        actor: &Actor,
        ip: Option<IpAddr>,
        domain: &str,
    ) -> Result<VerifiedDomain, AdminError> {
        let claim = self.proofs().begin(domain).await?;
        self.audit()
            .record(
                actor,
                ip,
                "admin.sso.domain_add",
                Some(claim.domain.clone()),
                "claimed an email domain",
            )
            .await;
        Ok(claim)
    }

    /// Looks for the DNS record. `AdminError::State` while it isn't there yet.
    pub async fn check_domain(
        &self,
        actor: &Actor,
        ip: Option<IpAddr>,
        domain: &str,
    ) -> Result<VerifiedDomain, AdminError> {
        let claim = self.proofs().check(domain).await?;
        self.audit()
            .record(
                actor,
                ip,
                "admin.sso.domain_verify",
                Some(claim.domain.clone()),
                "verified an email domain",
            )
            .await;
        Ok(claim)
    }

    pub async fn remove_domain(
        &self,
        actor: &Actor,
        ip: Option<IpAddr>,
        domain: &str,
    ) -> Result<(), AdminError> {
        let normal = crate::sso::domains::normalise_domain(domain)?;
        self.sso
            .domain_claim(&normal)
            .await?
            .ok_or(AdminError::NotFound)?;
        self.proofs().remove(&normal).await?;
        self.audit()
            .record(
                actor,
                ip,
                "admin.sso.domain_remove",
                Some(normal),
                "removed an email domain",
            )
            .await;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn issuers_must_be_https_or_local() {
        assert!(issuer_ok("https://idp.example.org"));
        assert!(issuer_ok("https://idp.example.org/realms/kemlock"));
        assert!(issuer_ok("http://localhost:8081/realms/dev"));
        assert!(issuer_ok("http://127.0.0.1/"));
        for bad in [
            "",
            "idp.example.org",
            "http://idp.example.org",
            "ftp://idp.example.org",
            "https://",
            "https://user@idp.example.org",
            "https://idp.example.org/#frag",
            "https://idp.example.org?x=1",
            "https://idp example.org",
        ] {
            assert!(!issuer_ok(bad), "{bad:?}");
        }
    }

    #[test]
    fn scopes_are_plain_words() {
        assert!(scope_ok("email"));
        assert!(scope_ok("urn:custom/scope-1.0"));
        assert!(!scope_ok(""));
        assert!(!scope_ok("two words"));
        assert!(!scope_ok(&"x".repeat(65)));
    }
}
