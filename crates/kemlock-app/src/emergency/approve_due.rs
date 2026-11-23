//! The emergency-access timer: approves requests whose wait has ended.
//!
//! A job for a tokio interval. Several replicas may run it at once: each approval is a
//! compare-and-set from `RecoveryInitiated`, so a grant is approved once, and the grantor's
//! refusal racing the timer has exactly one winner.

use super::ports::{EmergencyEvent, EmergencyNotice, EmergencyNotices, EmergencyRepo};
use crate::error::AppError;
use crate::platform::Platform;
use crate::ports::{Event, EventLog, UserRepo};
use kemlock_domain::unlock::{EmergencyGrant, EmergencyState};

#[derive(Debug)]
pub struct ApproveDue<U, R, N, E, V> {
    pub users: U,
    pub grants: R,
    pub notices: N,
    pub env: E,
    pub events: V,
}

impl<U: UserRepo, R: EmergencyRepo, N: EmergencyNotices, E: Platform, V: EventLog>
    ApproveDue<U, R, N, E, V>
{
    /// Approves every running request whose wait has ended and tells both parties. Returns how
    /// many this call approved.
    pub async fn execute(&self) -> Result<u64, AppError> {
        let now = self.env.now();
        let mut approved = 0;
        for mut grant in self.grants.recovering_grants().await? {
            if !grant.is_due(now) {
                continue;
            }
            if grant.approve_due(now).is_err() {
                continue;
            }
            if !self
                .grants
                .save_grant(&grant, EmergencyState::RecoveryInitiated)
                .await?
            {
                // The grantor refused, or another replica approved, in the meantime.
                continue;
            }
            approved += 1;
            let event = Event {
                actor: None,
                device: None,
                action: "emergency.approve_due",
                target: Some(grant.id.to_string()),
                at: now,
            };
            if let Err(e) = self.events.record(event).await {
                tracing::warn!(error = %e, "couldn't record an event");
            }
            self.tell_both(&grant).await;
        }
        Ok(approved)
    }

    async fn tell_both(&self, grant: &EmergencyGrant) {
        let notice = |to| EmergencyNotice {
            to,
            grant: grant.id,
            event: EmergencyEvent::Approved,
            kind: grant.kind,
            wait_days: grant.wait_days,
        };
        self.notices
            .notify(notice(grant.grantee_email.clone()))
            .await;
        match self.users.by_id(grant.grantor).await {
            Ok(Some(grantor)) => self.notices.notify(notice(grantor.email)).await,
            Ok(None) => {}
            Err(e) => tracing::warn!(error = %e, "couldn't look up a grantor to tell"),
        }
    }
}
