//! Ports of emergency access.

use crate::ports::StoreError;
use kemlock_domain::unlock::{EmergencyGrant, EmergencyKind, EmergencyState, GrantId};
use kemlock_domain::{Email, UserId};
use std::future::Future;

/// Emergency-access grants (`emergency_access`).
pub trait EmergencyRepo: Send + Sync {
    /// Stores a new grant. `Duplicate` when the grantor already has a grant for that email.
    fn insert_grant(
        &self,
        grant: &EmergencyGrant,
    ) -> impl Future<Output = Result<(), StoreError>> + Send;

    fn grant(
        &self,
        id: GrantId,
    ) -> impl Future<Output = Result<Option<EmergencyGrant>, StoreError>> + Send;

    /// The grants a grantor made, oldest first.
    fn grants_of_grantor(
        &self,
        grantor: UserId,
    ) -> impl Future<Output = Result<Vec<EmergencyGrant>, StoreError>> + Send;

    /// The grants that name an email as their contact, oldest first.
    fn grants_for_email(
        &self,
        email: &Email,
    ) -> impl Future<Output = Result<Vec<EmergencyGrant>, StoreError>> + Send;

    /// A compare-and-set: writes the grant's mutable fields (contact, state, sealed key, request
    /// time, update time) only when the stored state is `from`, and says whether it did. Of a
    /// grantor's refusal and the timer's approval racing, one wins.
    fn save_grant(
        &self,
        grant: &EmergencyGrant,
        from: EmergencyState,
    ) -> impl Future<Output = Result<bool, StoreError>> + Send;

    /// Every grant whose request is running. The timer picks the ones whose wait has ended.
    fn recovering_grants(
        &self,
    ) -> impl Future<Output = Result<Vec<EmergencyGrant>, StoreError>> + Send;

    fn remove_grant(&self, id: GrantId) -> impl Future<Output = Result<(), StoreError>> + Send;
}

/// What happened to a grant, for the email to the other party.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EmergencyEvent {
    /// To the contact: someone named you.
    Invited,
    /// To the grantor: the contact accepted and waits for you to confirm them.
    Accepted,
    /// To the contact: the grantor confirmed you.
    Confirmed,
    /// To the grantor: the contact asked for access; refuse before the wait ends if it isn't right.
    RecoveryInitiated,
    /// To both: the contact may now fetch the key.
    Approved,
    /// To the contact: the grantor refused.
    Rejected,
}

/// An email about a grant. Best effort, like every notice.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EmergencyNotice {
    pub to: Email,
    pub grant: GrantId,
    pub event: EmergencyEvent,
    pub kind: EmergencyKind,
    pub wait_days: u32,
}

pub trait EmergencyNotices: Send + Sync {
    fn notify(&self, notice: EmergencyNotice) -> impl Future<Output = ()> + Send;
}

impl EmergencyNotices for crate::devices::LogNotices {
    async fn notify(&self, notice: EmergencyNotice) {
        tracing::info!(
            grant = %notice.grant,
            event = ?notice.event,
            "an emergency-access notice (no mail sender is configured)"
        );
    }
}
