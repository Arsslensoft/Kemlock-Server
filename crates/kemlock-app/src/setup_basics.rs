//! The "Server basics" of first-run setup: who may join, and the outgoing mail.
//!
//! The setup screens collect them and send them with `POST /kem/v1/setup/finish`. They are
//! saved as the same settings the admin console's Settings screen edits (`signups_allowed`,
//! `signups_domains_whitelist`, `invitations_allowed`, `smtp_*`), so the console shows them as
//! what was chosen at setup and changes them from there. What the screens also ask (the public
//! address, push, where files go, backups) is not a saved setting: the address is the server's
//! `DOMAIN`, and the rest is set by the operator's environment.

use crate::admin::AdminError;
use crate::admin::ports::SettingsRepo;
use crate::admin::settings::{self, Change, EnvSettings, Settings};
use crate::error::AppError;
use crate::ports::SecretSeal;
use std::collections::BTreeMap;

/// Who may make an account.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum JoinPolicy {
    /// Only people an admin or a space invites.
    Invite,
    /// Anyone whose email is at one of the listed domains.
    Domains,
    /// Anyone.
    Anyone,
}

impl JoinPolicy {
    pub fn parse(word: &str) -> Option<JoinPolicy> {
        match word {
            "invite" => Some(JoinPolicy::Invite),
            "domains" => Some(JoinPolicy::Domains),
            "anyone" => Some(JoinPolicy::Anyone),
            _ => None,
        }
    }
}

/// What the setup screen sent. Empty mail fields mean "no mail yet".
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ServerBasics {
    pub join: JoinPolicy,
    /// Comma-separated, for [`JoinPolicy::Domains`].
    pub join_domains: String,
    pub mail_host: String,
    pub mail_port: String,
    /// `starttls` or `tls`.
    pub mail_security: String,
    pub mail_from: String,
    pub mail_user: String,
}

fn invalid(key: &str) -> AppError {
    AppError::Invalid(match key {
        "signups_domains_whitelist" => "server basics: the join domains aren't domain names",
        "smtp_host" => "server basics: the mail server name is too long or has odd characters",
        "smtp_port" => "server basics: the mail port must be a number from 1 to 65535",
        "smtp_security" => "server basics: the mail security must be starttls or tls",
        "smtp_from" => "server basics: the mail sender isn't an email address",
        "smtp_username" => "server basics: the mail user is too long or has odd characters",
        _ => "server basics: a value isn't valid",
    })
}

fn checked(key: &'static str, value: &str) -> Result<String, AppError> {
    let definition = settings::definition(key).ok_or_else(|| invalid(key))?;
    settings::validate(definition, value).map_err(|_| invalid(key))
}

fn set(
    changes: &mut BTreeMap<String, Change>,
    key: &'static str,
    value: &str,
) -> Result<(), AppError> {
    changes.insert(key.to_owned(), Change::Set(checked(key, value)?));
    Ok(())
}

impl ServerBasics {
    /// The settings these choices make, checked against each setting's type and bounds.
    pub fn changes(&self) -> Result<BTreeMap<String, Change>, AppError> {
        let mut changes = BTreeMap::new();
        match self.join {
            JoinPolicy::Invite => {
                set(&mut changes, "signups_allowed", "false")?;
                set(&mut changes, "invitations_allowed", "true")?;
                changes.insert("signups_domains_whitelist".to_owned(), Change::Reset);
            }
            JoinPolicy::Domains => {
                let domains = checked("signups_domains_whitelist", &self.join_domains)?;
                if domains.is_empty() {
                    return Err(AppError::Invalid(
                        "server basics: list at least one domain, or pick another way to join",
                    ));
                }
                set(&mut changes, "signups_allowed", "true")?;
                set(&mut changes, "invitations_allowed", "true")?;
                set(&mut changes, "signups_domains_whitelist", &domains)?;
            }
            JoinPolicy::Anyone => {
                set(&mut changes, "signups_allowed", "true")?;
                set(&mut changes, "invitations_allowed", "true")?;
                changes.insert("signups_domains_whitelist".to_owned(), Change::Reset);
            }
        }
        if !self.mail_host.trim().is_empty() {
            set(&mut changes, "smtp_host", &self.mail_host)?;
            set(&mut changes, "smtp_port", &self.mail_port)?;
            let security = match self.mail_security.as_str() {
                "tls" => "force_tls",
                other => other,
            };
            set(&mut changes, "smtp_security", security)?;
            set(&mut changes, "smtp_from", &self.mail_from)?;
            set(&mut changes, "smtp_username", &self.mail_user)?;
        }
        Ok(changes)
    }
}

/// Drops the changes whose setting the environment sets: the operator's value wins and the
/// console shows it read-only, so setup neither saves nor trips over it.
pub fn without_env_set<E: EnvSettings>(
    mut changes: BTreeMap<String, Change>,
    env: &E,
) -> BTreeMap<String, Change> {
    changes.retain(|key, _| {
        settings::definition(key).is_none_or(|d| env.get(d.env).is_none_or(|v| v.trim().is_empty()))
    });
    changes
}

/// Saves the basics through the settings store the admin console uses. `changes` come from
/// [`ServerBasics::changes`]; all are stored or none.
pub async fn save_basics<R: SettingsRepo, S: SecretSeal, E: EnvSettings>(
    settings: &Settings<R, S, E>,
    changes: &BTreeMap<String, Change>,
) -> Result<(), AppError> {
    settings.apply(changes).await.map_err(|e| match e {
        AdminError::App(app) => app,
        _ => AppError::Invalid("server basics: a value is set by the environment or isn't valid"),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn basics(join: JoinPolicy) -> ServerBasics {
        ServerBasics {
            join,
            join_domains: String::new(),
            mail_host: String::new(),
            mail_port: "587".into(),
            mail_security: "starttls".into(),
            mail_from: String::new(),
            mail_user: String::new(),
        }
    }

    fn value(changes: &BTreeMap<String, Change>, key: &str) -> Option<String> {
        match changes.get(key) {
            Some(Change::Set(v)) => Some(v.clone()),
            _ => None,
        }
    }

    #[test]
    fn invite_only_closes_sign_ups_and_clears_the_domain_list() {
        let changes = basics(JoinPolicy::Invite).changes().expect("valid");
        assert_eq!(value(&changes, "signups_allowed").as_deref(), Some("false"));
        assert_eq!(
            changes.get("signups_domains_whitelist"),
            Some(&Change::Reset)
        );
        assert!(!changes.contains_key("smtp_host"));
    }

    #[test]
    fn domains_need_a_list_and_it_is_cleaned() {
        assert!(basics(JoinPolicy::Domains).changes().is_err());
        let mut b = basics(JoinPolicy::Domains);
        b.join_domains = "Example.org, corp.example.com".into();
        let changes = b.changes().expect("valid");
        assert_eq!(value(&changes, "signups_allowed").as_deref(), Some("true"));
        assert_eq!(
            value(&changes, "signups_domains_whitelist").as_deref(),
            Some("example.org,corp.example.com")
        );
        b.join_domains = "not a domain".into();
        assert!(b.changes().is_err());
    }

    #[test]
    fn mail_is_saved_only_with_a_host_and_tls_is_spelled_force_tls() {
        let mut b = basics(JoinPolicy::Anyone);
        b.mail_host = "smtp.example.org".into();
        b.mail_security = "tls".into();
        b.mail_port = "465".into();
        b.mail_from = "Ops@Example.org".into();
        let changes = b.changes().expect("valid");
        assert_eq!(
            value(&changes, "smtp_security").as_deref(),
            Some("force_tls")
        );
        assert_eq!(value(&changes, "smtp_port").as_deref(), Some("465"));
        assert_eq!(
            value(&changes, "smtp_from").as_deref(),
            Some("ops@example.org")
        );
        b.mail_port = "99999".into();
        assert!(b.changes().is_err());
    }

    #[test]
    fn settings_the_environment_sets_are_left_out() {
        let changes = basics(JoinPolicy::Anyone).changes().expect("valid");
        let env = settings::FnEnv(|name: &str| (name == "SIGNUPS_ALLOWED").then(|| "false".into()));
        let kept = without_env_set(changes, &env);
        assert!(!kept.contains_key("signups_allowed"));
        assert!(kept.contains_key("invitations_allowed"));
    }
    #[test]
    fn join_words_parse() {
        assert_eq!(JoinPolicy::parse("anyone"), Some(JoinPolicy::Anyone));
        assert_eq!(JoinPolicy::parse("everyone"), None);
    }
}
