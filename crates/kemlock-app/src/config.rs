//! Settings the use cases read. The server fills them from its configuration.

use kemlock_domain::ItemLimits;
use time::Duration;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AuthConfig {
    /// `SIGNUPS_ALLOWED`: whether anyone may register. The first admin registers with a setup
    /// grant whatever this says.
    pub signups_allowed: bool,
    /// Access tokens live 10 minutes (design, "API and sync").
    pub access_ttl: Duration,
    /// Refresh tokens live 30 days and rotate at every use.
    pub refresh_ttl: Duration,
    /// How long a sealed OPAQUE login state or two-step challenge stays valid.
    pub challenge_ttl: Duration,
    /// How long a setup grant stays valid after the setup code is accepted.
    pub grant_ttl: Duration,
    pub item_limits: ItemLimits,
}

impl Default for AuthConfig {
    fn default() -> Self {
        AuthConfig {
            signups_allowed: false,
            access_ttl: Duration::minutes(10),
            refresh_ttl: Duration::days(30),
            challenge_ttl: Duration::minutes(5),
            grant_ttl: Duration::minutes(15),
            item_limits: ItemLimits::default(),
        }
    }
}
