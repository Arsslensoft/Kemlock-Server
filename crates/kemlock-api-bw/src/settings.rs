//! Settings of the Bitwarden API.

use kemlock_app::admin::{InviteGate, Live};
use kemlock_domain::Email;
use std::sync::Arc;

/// The rounds of the server-side PBKDF2 over the client's hash: Vaultwarden's default.
pub const PASSWORD_ITERATIONS: u32 = 600_000;

/// The environment variable that switches the Bitwarden API on or off.
pub const COMPAT_VAR: &str = "KEMLOCK_BITWARDEN_COMPAT";

/// Every variable the Bitwarden API reads: the switch and Vaultwarden's rate limits.
pub const ENV_VARS: &[&str] = &[
    COMPAT_VAR,
    "LOGIN_RATELIMIT_SECONDS",
    "LOGIN_RATELIMIT_MAX_BURST",
    "UNAUTHENTICATED_RATELIMIT_SECONDS",
    "UNAUTHENTICATED_RATELIMIT_MAX_BURST",
];

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BwSettings {
    /// `DOMAIN` without a trailing slash: where attachment URLs and the config point.
    pub domain: String,
    /// The origin of `domain` (scheme, host and port), which Vaultwarden puts in every token's
    /// issuer.
    pub origin: String,
    /// `SIGNUPS_ALLOWED`.
    pub signups_allowed: bool,
    /// `SIGNUPS_VERIFY`: an address is proven by a mailed link before its account is made. Only
    /// when the server mails; the start value, which `live` replaces while the server runs.
    pub signups_verify: bool,
    /// `KEMLOCK_BW_INVITES_AUTO_ACCEPT`: an invitation to an existing account with a password counts
    /// as accepted at once, when the server doesn't mail, as Vaultwarden does. The start value, which
    /// `live` replaces while the server runs.
    pub bw_invites_auto_accept: bool,
    /// `KEMLOCK_BITWARDEN_COMPAT`: with it off, every Bitwarden route answers 404.
    pub compat: bool,
    /// Rounds for new password hashes; an account hashed with fewer is upgraded at its next sign-in.
    pub password_iterations: u32,
    /// `ORG_EVENTS_ENABLED`: with it on, organization and user events are logged as they happen and
    /// the organization says it uses events. Off by default, as in Vaultwarden.
    pub org_events_enabled: bool,
    /// `LOGIN_RATELIMIT_SECONDS`: seconds for one request to be given back to an address on the
    /// routes the login limiter guards (Vaultwarden's 60).
    pub login_ratelimit_seconds: u64,
    /// `LOGIN_RATELIMIT_MAX_BURST`: requests an address may make at once on those routes (10).
    pub login_ratelimit_max_burst: u32,
    /// `UNAUTHENTICATED_RATELIMIT_SECONDS`: the same for the routes with no sign-in that are not
    /// logins (Vaultwarden's 60).
    pub unauthenticated_ratelimit_seconds: u64,
    /// `UNAUTHENTICATED_RATELIMIT_MAX_BURST`: requests an address may make at once on those routes
    /// (50; they share it, so it is more lenient than the login one).
    pub unauthenticated_ratelimit_max_burst: u32,
    /// The least time between two password hash checks of one account (a second): a right password
    /// still passes, only a little later. The tests set it to nothing.
    pub hash_interval: std::time::Duration,
    /// How long a password hash check waits for its turn and a free place before it is answered 429.
    pub hash_wait: std::time::Duration,
    /// The longest, in seconds, a password check is held back once its account has more wrong
    /// passwords in a window than the console allows (3).
    pub password_slowdown_secs: u64,
    /// `ORG_GROUPS_ENABLED`: Vaultwarden has it off by default; spaces have groups, so this server
    /// has it on.
    pub org_groups_enabled: bool,
    /// The settings the console changes while the server runs, when the server shares them:
    /// sign-ups and the invitation gate then follow it, and `signups_allowed` above is only the
    /// start value.
    pub live: Option<Live>,
}

impl BwSettings {
    pub fn new(domain: &str, signups_allowed: bool) -> Self {
        let domain = domain.trim_end_matches('/').to_owned();
        let origin = url::Url::parse(&domain)
            .map(|u| u.origin().ascii_serialization())
            .unwrap_or_else(|_| domain.clone());
        BwSettings {
            domain,
            origin,
            signups_allowed,
            signups_verify: false,
            bw_invites_auto_accept: false,
            compat: true,
            password_iterations: PASSWORD_ITERATIONS,
            login_ratelimit_seconds: 60,
            login_ratelimit_max_burst: 10,
            unauthenticated_ratelimit_seconds: 60,
            unauthenticated_ratelimit_max_burst: 50,
            password_slowdown_secs: 3,
            hash_interval: crate::hash_gate::DEFAULT_INTERVAL,
            hash_wait: crate::hash_gate::DEFAULT_WAIT,
            org_events_enabled: false,
            org_groups_enabled: true,
            live: None,
        }
    }

    /// The same settings with the switch read from `KEMLOCK_BITWARDEN_COMPAT`.
    #[must_use]
    pub fn compat_from_env(self) -> Self {
        self.env_from(&|name| std::env::var(name).ok())
    }

    /// [`Self::compat_from_env`] over `env`, for a server whose variables are not the process's.
    #[must_use]
    pub fn env_from(mut self, env: &dyn Fn(&str) -> Option<String>) -> Self {
        self.compat = compat_enabled(env(COMPAT_VAR).as_deref());
        // Vaultwarden's own variables; a value that isn't a number leaves the default.
        if let Some(seconds) = env("LOGIN_RATELIMIT_SECONDS").and_then(|v| v.trim().parse().ok()) {
            self.login_ratelimit_seconds = seconds;
        }
        if let Some(burst) = env("LOGIN_RATELIMIT_MAX_BURST").and_then(|v| v.trim().parse().ok()) {
            self.login_ratelimit_max_burst = burst;
        }
        if let Some(seconds) =
            env("UNAUTHENTICATED_RATELIMIT_SECONDS").and_then(|v| v.trim().parse().ok())
        {
            self.unauthenticated_ratelimit_seconds = seconds;
        }
        if let Some(burst) =
            env("UNAUTHENTICATED_RATELIMIT_MAX_BURST").and_then(|v| v.trim().parse().ok())
        {
            self.unauthenticated_ratelimit_max_burst = burst;
        }
        self
    }

    /// The same settings following `live` for sign-ups and invitations.
    #[must_use]
    pub fn with_live(mut self, live: Live) -> Self {
        self.live = Some(live);
        self
    }

    /// Whether sign-ups are on.
    pub fn signups_allowed(&self) -> bool {
        self.live
            .as_ref()
            .map_or(self.signups_allowed, Live::signups_allowed)
    }

    /// Whether a Bitwarden invitation to an existing account is taken as accepted at once.
    pub fn bw_invites_auto_accept(&self) -> bool {
        self.live
            .as_ref()
            .map_or(self.bw_invites_auto_accept, Live::bw_invites_auto_accept)
    }

    /// Whether registration has to prove the address with a mailed link first.
    pub fn signups_verify(&self) -> bool {
        self.live
            .as_ref()
            .map_or(self.signups_verify, Live::signups_verify)
    }

    /// Whether `email` may register without an invitation: sign-ups are on, or (with a domain
    /// whitelist) its domain is on it.
    pub(crate) fn signups_open_for(&self, email: &str) -> bool {
        match (&self.live, Email::parse(email)) {
            (Some(live), Ok(email)) => live.signups_open_for(&email),
            (Some(live), Err(_)) => live.signups_allowed(),
            (None, _) => self.signups_allowed,
        }
    }

    /// How many second-step codes an account may try in a window: the console's setting, else 5.
    pub(crate) fn second_step_limit(&self) -> u32 {
        self.live.as_ref().map_or(5, Live::second_step_limit)
    }

    /// How many wrong passwords an account may have in a window before it slows down: the
    /// console's setting, else 10.
    pub(crate) fn password_limit(&self) -> u32 {
        self.live.as_ref().map_or(10, Live::password_limit)
    }

    /// The gate that checks server invitation tokens, while invitations are on.
    pub(crate) fn invites(&self) -> Option<Arc<dyn InviteGate>> {
        self.live.as_ref().and_then(Live::invites)
    }

    /// The issuer of one kind of token: `<origin>|login`, `<origin>|file_download` and so on.
    pub(crate) fn issuer(&self, kind: &str) -> String {
        format!("{}|{kind}", self.origin)
    }
}

/// On unless the value says no: `false`, `0`, `no` or `off`, in any case. A server copied from
/// Vaultwarden starts with it on.
pub fn compat_enabled(value: Option<&str>) -> bool {
    match value.map(|v| v.trim().to_ascii_lowercase()) {
        Some(v) => !matches!(v.as_str(), "false" | "0" | "no" | "off"),
        None => true,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_origin_drops_the_path() {
        let s = BwSettings::new("https://vault.example.org/bw/", true);
        assert_eq!(s.domain, "https://vault.example.org/bw");
        assert_eq!(s.origin, "https://vault.example.org");
        assert_eq!(s.issuer("login"), "https://vault.example.org|login");
        assert_eq!(
            BwSettings::new("http://localhost:8080", false).origin,
            "http://localhost:8080"
        );
    }

    #[test]
    fn the_switch_is_on_unless_told_otherwise() {
        assert!(compat_enabled(None));
        assert!(compat_enabled(Some("true")));
        assert!(compat_enabled(Some("")));
        for off in ["false", "FALSE", "0", "no", "Off", " off "] {
            assert!(!compat_enabled(Some(off)), "{off}");
        }
    }
}
