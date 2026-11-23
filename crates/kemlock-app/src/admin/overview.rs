//! The Overview screen: what the server holds, at a glance.

use super::error::AdminError;
use super::ports::{
    AdminEventRepo, AdminSpaceRepo, AdminUserRepo, ComplianceRepo, InviteRepo, Mailer,
};
use crate::ports::Clock;
use time::Duration;

/// What the Overview shows.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct OverviewCounts {
    pub users: u64,
    pub admins: u64,
    pub disabled_users: u64,
    pub devices: u64,
    pub spaces: u64,
    /// Items that aren't tombstones.
    pub live_items: u64,
    /// Events in the last 24 hours.
    pub events_24h: u64,
    pub pending_invites: u64,
    pub open_requests: u64,
    pub overdue_requests: u64,
    /// Whether the server can send mail.
    pub mail_configured: bool,
}

#[derive(Debug)]
pub struct Overview<R, M, C> {
    pub repos: R,
    pub mail: M,
    pub clock: C,
}

impl<R, M, C> Overview<R, M, C>
where
    R: AdminUserRepo + AdminSpaceRepo + AdminEventRepo + InviteRepo + ComplianceRepo,
    M: Mailer,
    C: Clock,
{
    pub async fn execute(&self) -> Result<OverviewCounts, AdminError> {
        let now = self.clock.now();
        let users = self.repos.user_counts().await?;
        let spaces = self.repos.list_spaces(1, 0).await?;
        let requests = self.repos.compliance_counts(now).await?;
        Ok(OverviewCounts {
            users: users.users,
            admins: users.admins,
            disabled_users: users.disabled,
            devices: users.devices,
            spaces: spaces.total,
            live_items: self.repos.live_items().await?,
            events_24h: self
                .repos
                .count_events_since(now - Duration::hours(24))
                .await?,
            pending_invites: self.repos.pending_invites(now).await?,
            open_requests: requests.open,
            overdue_requests: requests.overdue,
            mail_configured: self.mail.configured(),
        })
    }
}
