//! Single sign-on, wired: the OpenID Connect client, the SSO repositories on the store, and the
//! provider settings the `SSO_*` variables seed.
//!
//! The settings live in the `sso_settings` table, where the admin console edits them. The
//! variables (Vaultwarden's names) only seed an empty table at start, so a console edit is never
//! undone by a restart. The client secret is sealed under `server.key` before it is stored.
//!
//! Read: `SSO_ENABLED`, `SSO_AUTHORITY`, `SSO_CLIENT_ID`, `SSO_CLIENT_SECRET`, `SSO_SCOPES`
//! (space separated, default `email profile`), `SSO_ALLOW_UNKNOWN_EMAIL_VERIFICATION` and
//! `SSO_SIGNUPS_MATCH_EMAIL` (default true) from Vaultwarden, and `KEMLOCK_SSO_NAME` (the sign-in
//! button's label) of Kemlock's own. PKCE is always on, so `SSO_PKCE` has nothing to switch.

use crate::adapters::ServerCrypto;
use crate::sends::SystemClock;
use kemlock_api_kem::SsoRuntime;
use kemlock_app::ports::{Clock, StoreError};
use kemlock_app::spaces::ApplyGroupRules;
use kemlock_app::sso::{
    GroupAssignment, GroupSync, MembershipFacts, SpaceMembership, SsoError, SsoSettings,
    SsoSettingsRepo,
};
use kemlock_domain::UserId;
use kemlock_identity::OidcClient;
use kemlock_store_sql::SqlStore;
use std::sync::Arc;
use time::OffsetDateTime;

/// The spaces ports SSO calls, over the server's store. The membership facts are the store's own,
/// the ones every other way in (password, passkey, device approval, the Bitwarden grants) reads, so
/// they say the same of an account everywhere: which spaces it belongs to, in what role, and which
/// of them require SSO. The group mapping invites the account to the spaces the admin's rules
/// name (`ApplyGroupRules`): it never confirms, so a person already in the space still compares
/// the key fingerprint first.
#[derive(Clone, Debug)]
pub struct ServerSpaces {
    store: SqlStore,
}

impl ServerSpaces {
    pub fn new(store: SqlStore) -> Self {
        ServerSpaces { store }
    }
}

impl MembershipFacts for ServerSpaces {
    async fn spaces_of(&self, user: UserId) -> Result<Vec<SpaceMembership>, StoreError> {
        MembershipFacts::spaces_of(&self.store, user).await
    }
}

impl GroupSync for ServerSpaces {
    async fn apply_groups(
        &self,
        user: UserId,
        assignments: &[GroupAssignment],
    ) -> Result<(), StoreError> {
        ApplyGroupRules {
            spaces: self.store.clone(),
            events: self.store.clone(),
            clock: SystemClock,
        }
        .execute(user, assignments)
        .await
        .map(|_| ())
        .map_err(|e| StoreError::Backend(e.to_string()))
    }
}

/// The SSO ports for this server: the store's repositories, one shared OpenID Connect client, and
/// the spaces ports above.
pub type Runtime = SsoRuntime<SqlStore, Arc<OidcClient>, ServerSpaces>;

/// Builds the runtime the SSO routes use. The client discovers the provider on first use, so a
/// provider that is down at start doesn't stop the server.
pub fn runtime(store: SqlStore) -> Result<Runtime, SsoError> {
    Ok(SsoRuntime::new(
        store.clone(),
        Arc::new(OidcClient::new()?),
        ServerSpaces::new(store),
    ))
}

/// What the variables say: the settings, and the client secret still in the clear.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EnvSso {
    pub settings: SsoSettings,
    pub client_secret: Option<String>,
}

fn flag(env: &dyn Fn(&str) -> Option<String>, name: &str, default: bool) -> Result<bool, String> {
    match env(name).map(|v| v.trim().to_ascii_lowercase()) {
        None => Ok(default),
        Some(v) if v.is_empty() => Ok(default),
        Some(v) if matches!(v.as_str(), "true" | "1" | "yes" | "on") => Ok(true),
        Some(v) if matches!(v.as_str(), "false" | "0" | "no" | "off") => Ok(false),
        Some(v) => Err(format!("{name} must be true or false, not {v:?}")),
    }
}

fn text(env: &dyn Fn(&str) -> Option<String>, name: &str) -> Option<String> {
    env(name)
        .map(|v| v.trim().to_owned())
        .filter(|v| !v.is_empty())
}

/// The settings the `SSO_*` variables describe, or `None` when `SSO_ENABLED` isn't true.
pub fn settings_from_env(
    env: &dyn Fn(&str) -> Option<String>,
    now: OffsetDateTime,
) -> Result<Option<EnvSso>, String> {
    if !flag(env, "SSO_ENABLED", false)? {
        return Ok(None);
    }
    let authority =
        text(env, "SSO_AUTHORITY").ok_or("SSO_AUTHORITY is required when SSO_ENABLED is true")?;
    let client_id =
        text(env, "SSO_CLIENT_ID").ok_or("SSO_CLIENT_ID is required when SSO_ENABLED is true")?;
    let mut settings = SsoSettings::new(authority, client_id, now);
    if let Some(scopes) = text(env, "SSO_SCOPES") {
        settings.scopes = scopes
            .split_whitespace()
            .filter(|s| *s != "openid")
            .map(str::to_owned)
            .collect();
    }
    if let Some(name) = text(env, "KEMLOCK_SSO_NAME") {
        settings.display_name = name;
    }
    settings.allow_unknown_email_verification =
        flag(env, "SSO_ALLOW_UNKNOWN_EMAIL_VERIFICATION", false)?;
    settings.link_by_email = flag(env, "SSO_SIGNUPS_MATCH_EMAIL", true)?;
    Ok(Some(EnvSso {
        settings,
        client_secret: text(env, "SSO_CLIENT_SECRET"),
    }))
}

/// Puts the settings the variables describe into an empty `sso_settings` table. Returns whether
/// it did. A table that already has settings is left alone.
pub async fn seed_from_env(
    store: &SqlStore,
    crypto: &ServerCrypto,
    env: &dyn Fn(&str) -> Option<String>,
) -> Result<bool, String> {
    let Some(mut from_env) = settings_from_env(env, crypto.now())? else {
        return Ok(false);
    };
    let present = store
        .sso_settings()
        .await
        .map_err(|e| format!("can't read the SSO settings: {e}"))?;
    if present.is_some() {
        return Ok(false);
    }
    if let Some(secret) = &from_env.client_secret {
        from_env.settings.set_client_secret(crypto, secret);
    }
    store
        .put_sso_settings(&from_env.settings)
        .await
        .map_err(|e| format!("can't store the SSO settings: {e}"))?;
    Ok(true)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use time::macros::datetime;

    fn read(vars: &[(&str, &str)]) -> Result<Option<EnvSso>, String> {
        let map: HashMap<String, String> = vars
            .iter()
            .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
            .collect();
        settings_from_env(
            &|name| map.get(name).cloned(),
            datetime!(2026-01-01 0:00 UTC),
        )
    }

    #[test]
    fn sso_is_off_unless_enabled() {
        assert_eq!(read(&[]), Ok(None));
        assert_eq!(
            read(&[
                ("SSO_ENABLED", "false"),
                ("SSO_AUTHORITY", "https://idp.test")
            ]),
            Ok(None)
        );
    }

    #[test]
    fn the_variables_describe_the_provider() {
        let env = read(&[
            ("SSO_ENABLED", "true"),
            ("SSO_AUTHORITY", "https://idp.example.org/realms/kemlock"),
            ("SSO_CLIENT_ID", "kemlock"),
            ("SSO_CLIENT_SECRET", "s3cret"),
            ("SSO_SCOPES", "openid email profile groups"),
            ("SSO_ALLOW_UNKNOWN_EMAIL_VERIFICATION", "true"),
            ("SSO_SIGNUPS_MATCH_EMAIL", "false"),
            ("KEMLOCK_SSO_NAME", "Example Co"),
        ])
        .expect("valid")
        .expect("enabled");
        assert_eq!(env.client_secret.as_deref(), Some("s3cret"));
        let s = env.settings;
        assert!(s.enabled);
        assert_eq!(s.issuer, "https://idp.example.org/realms/kemlock");
        assert_eq!(s.client_id, "kemlock");
        assert_eq!(
            s.scopes,
            vec!["email", "profile", "groups"],
            "openid is always asked"
        );
        assert!(s.allow_unknown_email_verification);
        assert!(!s.link_by_email);
        assert_eq!(s.display_name, "Example Co");
        assert!(
            s.sealed_client_secret.is_none(),
            "sealing happens when it is stored"
        );
    }

    #[test]
    fn the_defaults_match_vaultwardens() {
        let s = read(&[
            ("SSO_ENABLED", "1"),
            ("SSO_AUTHORITY", "https://idp.test"),
            ("SSO_CLIENT_ID", "c"),
        ])
        .expect("valid")
        .expect("enabled")
        .settings;
        assert_eq!(s.scopes, vec!["email", "profile"]);
        assert!(!s.allow_unknown_email_verification);
        assert!(s.link_by_email);
        assert!(s.create_accounts);
    }

    #[test]
    fn missing_or_bad_values_are_errors_naming_the_variable() {
        let err =
            read(&[("SSO_ENABLED", "true"), ("SSO_CLIENT_ID", "c")]).expect_err("no authority");
        assert!(err.contains("SSO_AUTHORITY"), "{err}");
        let err = read(&[
            ("SSO_ENABLED", "true"),
            ("SSO_AUTHORITY", "https://idp.test"),
        ])
        .expect_err("no client id");
        assert!(err.contains("SSO_CLIENT_ID"), "{err}");
        let err = read(&[("SSO_ENABLED", "maybe")]).expect_err("not a bool");
        assert!(err.contains("SSO_ENABLED"), "{err}");
        let err = read(&[
            ("SSO_ENABLED", "true"),
            ("SSO_AUTHORITY", "https://idp.test"),
            ("SSO_CLIENT_ID", "c"),
            ("SSO_SIGNUPS_MATCH_EMAIL", "sometimes"),
        ])
        .expect_err("not a bool");
        assert!(err.contains("SSO_SIGNUPS_MATCH_EMAIL"), "{err}");
    }

    #[test]
    fn blank_values_count_as_unset() {
        assert_eq!(read(&[("SSO_ENABLED", "  ")]), Ok(None));
    }

    #[tokio::test]
    async fn the_spaces_ports_answer_with_the_stores_membership_facts() {
        let store = SqlStore::connect("sqlite::memory:").await.expect("a store");
        let user = UserId::random();
        assert_eq!(
            MembershipFacts::spaces_of(&ServerSpaces::new(store.clone()), user)
                .await
                .expect("facts"),
            MembershipFacts::spaces_of(&store, user)
                .await
                .expect("facts"),
        );
    }
}
