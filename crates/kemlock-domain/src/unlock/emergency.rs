//! Emergency access: a grantor names a contact who may ask for their vault and get it after a
//! wait, unless the grantor refuses first (design, "Unlocking without the master password").

use super::approval::sealed_key_len_ok;
use crate::ids::UserId;
use crate::user::Email;
use serde::{Deserialize, Serialize};
use time::{Duration, OffsetDateTime};

uuid_id!(
    /// An emergency-access grant.
    GrantId
);

/// The shortest wait a grantor can set.
pub const MIN_WAIT_DAYS: u32 = 1;
/// The longest wait a grantor can set.
pub const MAX_WAIT_DAYS: u32 = 90;
/// How many contacts one account can name.
pub const MAX_GRANTS_PER_GRANTOR: usize = 10;

/// What the contact may do once the key is released. The sealed key is the same either way; the
/// kind tells the contact's app whether to open the vault read-only or to take the account over
/// (set a new password through the ordinary registration flow).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum EmergencyKind {
    View,
    Takeover,
}

/// Where a grant stands.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum EmergencyState {
    /// The grantor named the contact; the contact hasn't answered.
    Invited,
    /// The contact accepted; the grantor hasn't confirmed their key yet.
    Accepted,
    /// The grantor sealed the root key to the contact's `kx1` key.
    Confirmed,
    /// The contact asked for access; the wait is running.
    RecoveryInitiated,
    /// The wait ended, or the grantor said yes: the contact may fetch the sealed key.
    Approved,
    /// The grantor refused a request. The contact may ask again later.
    Rejected,
}

impl EmergencyState {
    pub fn as_str(self) -> &'static str {
        match self {
            EmergencyState::Invited => "invited",
            EmergencyState::Accepted => "accepted",
            EmergencyState::Confirmed => "confirmed",
            EmergencyState::RecoveryInitiated => "recovery-initiated",
            EmergencyState::Approved => "approved",
            EmergencyState::Rejected => "rejected",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        Some(match s {
            "invited" => EmergencyState::Invited,
            "accepted" => EmergencyState::Accepted,
            "confirmed" => EmergencyState::Confirmed,
            "recovery-initiated" => EmergencyState::RecoveryInitiated,
            "approved" => EmergencyState::Approved,
            "rejected" => EmergencyState::Rejected,
            _ => return None,
        })
    }
}

impl EmergencyKind {
    pub fn as_str(self) -> &'static str {
        match self {
            EmergencyKind::View => "view",
            EmergencyKind::Takeover => "takeover",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        Some(match s {
            "view" => EmergencyKind::View,
            "takeover" => EmergencyKind::Takeover,
            _ => return None,
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum EmergencyError {
    /// The step doesn't follow the grant's state.
    #[error("the grant is {} and can't take this step", .0.as_str())]
    WrongState(EmergencyState),
    #[error("the wait must be 1 to 90 days")]
    BadWait,
    #[error("the sealed key has the wrong shape")]
    BadSealedKey,
    #[error("the wait hasn't ended")]
    NotDue,
}

/// One grantor and one contact (`emergency_access`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EmergencyGrant {
    pub id: GrantId,
    pub grantor: UserId,
    /// The contact, by email: the invitation can go to someone before they have an account.
    pub grantee_email: Email,
    /// Set when the contact accepts.
    pub grantee: Option<UserId>,
    pub kind: EmergencyKind,
    pub wait_days: u32,
    pub state: EmergencyState,
    /// The root key sealed to the contact's `kx1` key (context `"emergency-access"`), once the
    /// grantor confirms. Opaque to the server, and handed out only when the state is `Approved`.
    pub sealed_key: Option<Vec<u8>>,
    pub recovery_initiated_at: Option<OffsetDateTime>,
    pub created_at: OffsetDateTime,
    pub updated_at: OffsetDateTime,
}

impl EmergencyGrant {
    /// A new invitation.
    pub fn invite(
        id: GrantId,
        grantor: UserId,
        grantee_email: Email,
        kind: EmergencyKind,
        wait_days: u32,
        now: OffsetDateTime,
    ) -> Result<Self, EmergencyError> {
        if !(MIN_WAIT_DAYS..=MAX_WAIT_DAYS).contains(&wait_days) {
            return Err(EmergencyError::BadWait);
        }
        Ok(EmergencyGrant {
            id,
            grantor,
            grantee_email,
            grantee: None,
            kind,
            wait_days,
            state: EmergencyState::Invited,
            sealed_key: None,
            recovery_initiated_at: None,
            created_at: now,
            updated_at: now,
        })
    }

    fn step(&mut self, to: EmergencyState, now: OffsetDateTime) {
        self.state = to;
        self.updated_at = now;
    }

    /// The contact accepts.
    pub fn accept(&mut self, grantee: UserId, now: OffsetDateTime) -> Result<(), EmergencyError> {
        if self.state != EmergencyState::Invited {
            return Err(EmergencyError::WrongState(self.state));
        }
        self.grantee = Some(grantee);
        self.step(EmergencyState::Accepted, now);
        Ok(())
    }

    /// The grantor confirms the contact and stores the root key sealed to them. A grant that was
    /// already confirmed can't be confirmed again: the grantor revokes and invites again to change
    /// the key.
    pub fn confirm(
        &mut self,
        sealed_key: Vec<u8>,
        now: OffsetDateTime,
    ) -> Result<(), EmergencyError> {
        if self.state != EmergencyState::Accepted {
            return Err(EmergencyError::WrongState(self.state));
        }
        if !sealed_key_len_ok(sealed_key.len()) {
            return Err(EmergencyError::BadSealedKey);
        }
        self.sealed_key = Some(sealed_key);
        self.step(EmergencyState::Confirmed, now);
        Ok(())
    }

    /// The contact asks for access; the wait starts now. Asking again after a refusal starts a new
    /// wait.
    pub fn initiate(&mut self, now: OffsetDateTime) -> Result<(), EmergencyError> {
        if !matches!(
            self.state,
            EmergencyState::Confirmed | EmergencyState::Rejected
        ) {
            return Err(EmergencyError::WrongState(self.state));
        }
        self.recovery_initiated_at = Some(now);
        self.step(EmergencyState::RecoveryInitiated, now);
        Ok(())
    }

    /// When the wait of a running request ends.
    pub fn due_at(&self) -> Option<OffsetDateTime> {
        if self.state != EmergencyState::RecoveryInitiated {
            return None;
        }
        self.recovery_initiated_at
            .map(|at| at + Duration::days(i64::from(self.wait_days)))
    }

    /// Whether a running request's wait has ended at `now`.
    pub fn is_due(&self, now: OffsetDateTime) -> bool {
        self.due_at().is_some_and(|due| now >= due)
    }

    /// The grantor says yes before the wait ends.
    pub fn approve_early(&mut self, now: OffsetDateTime) -> Result<(), EmergencyError> {
        if self.state != EmergencyState::RecoveryInitiated {
            return Err(EmergencyError::WrongState(self.state));
        }
        self.step(EmergencyState::Approved, now);
        Ok(())
    }

    /// The wait ended and the grantor didn't refuse: the background job approves.
    pub fn approve_due(&mut self, now: OffsetDateTime) -> Result<(), EmergencyError> {
        if self.state != EmergencyState::RecoveryInitiated {
            return Err(EmergencyError::WrongState(self.state));
        }
        if !self.is_due(now) {
            return Err(EmergencyError::NotDue);
        }
        self.step(EmergencyState::Approved, now);
        Ok(())
    }

    /// The grantor refuses a running request, or takes back an approval before the contact has
    /// fetched the key.
    pub fn reject(&mut self, now: OffsetDateTime) -> Result<(), EmergencyError> {
        if !matches!(
            self.state,
            EmergencyState::RecoveryInitiated | EmergencyState::Approved
        ) {
            return Err(EmergencyError::WrongState(self.state));
        }
        self.recovery_initiated_at = None;
        self.step(EmergencyState::Rejected, now);
        Ok(())
    }

    /// Whether the contact may fetch the sealed key now.
    pub fn key_released(&self) -> bool {
        self.state == EmergencyState::Approved && self.sealed_key.is_some()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::unlock::SEALED_BOX_OVERHEAD;
    use time::macros::datetime;

    const NOW: OffsetDateTime = datetime!(2026-11-22 10:00:00 UTC);

    fn grant() -> EmergencyGrant {
        EmergencyGrant::invite(
            GrantId::random(),
            UserId::random(),
            Email::parse("friend@example.org").expect("valid"),
            EmergencyKind::Takeover,
            7,
            NOW,
        )
        .expect("a valid grant")
    }

    fn sealed() -> Vec<u8> {
        vec![3; SEALED_BOX_OVERHEAD + 64]
    }

    fn confirmed() -> EmergencyGrant {
        let mut g = grant();
        g.accept(UserId::random(), NOW).expect("invited");
        g.confirm(sealed(), NOW).expect("accepted");
        g
    }

    #[test]
    fn waits_outside_one_to_ninety_days_are_refused() {
        for days in [0, 91, u32::MAX] {
            let result = EmergencyGrant::invite(
                GrantId::random(),
                UserId::random(),
                Email::parse("a@b.co").expect("valid"),
                EmergencyKind::View,
                days,
                NOW,
            );
            assert_eq!(result, Err(EmergencyError::BadWait), "{days}");
        }
    }

    #[test]
    fn the_happy_path_walks_every_state() {
        let mut g = grant();
        assert_eq!(g.state, EmergencyState::Invited);
        let contact = UserId::random();
        g.accept(contact, NOW).expect("invited");
        assert_eq!(g.grantee, Some(contact));
        g.confirm(sealed(), NOW).expect("accepted");
        assert_eq!(g.state, EmergencyState::Confirmed);
        g.initiate(NOW + Duration::days(1)).expect("confirmed");
        assert_eq!(g.state, EmergencyState::RecoveryInitiated);
        assert_eq!(g.due_at(), Some(NOW + Duration::days(8)));
        assert!(!g.key_released());
        g.approve_due(NOW + Duration::days(8)).expect("due");
        assert_eq!(g.state, EmergencyState::Approved);
        assert!(g.key_released());
    }

    #[test]
    fn steps_out_of_order_are_refused() {
        let mut g = grant();
        assert_eq!(
            g.confirm(sealed(), NOW),
            Err(EmergencyError::WrongState(EmergencyState::Invited))
        );
        assert_eq!(
            g.initiate(NOW),
            Err(EmergencyError::WrongState(EmergencyState::Invited))
        );
        g.accept(UserId::random(), NOW).expect("invited");
        assert_eq!(
            g.accept(UserId::random(), NOW),
            Err(EmergencyError::WrongState(EmergencyState::Accepted))
        );
        assert_eq!(
            g.initiate(NOW),
            Err(EmergencyError::WrongState(EmergencyState::Accepted))
        );
    }

    #[test]
    fn a_sealed_key_of_the_wrong_size_is_refused() {
        let mut g = grant();
        g.accept(UserId::random(), NOW).expect("invited");
        assert_eq!(
            g.confirm(vec![1; 10], NOW),
            Err(EmergencyError::BadSealedKey)
        );
        assert_eq!(g.state, EmergencyState::Accepted);
    }

    #[test]
    fn the_wait_must_have_ended() {
        let mut g = confirmed();
        g.initiate(NOW).expect("confirmed");
        assert_eq!(
            g.approve_due(NOW + Duration::days(7) - Duration::seconds(1)),
            Err(EmergencyError::NotDue)
        );
        assert!(!g.is_due(NOW + Duration::days(6)));
        assert!(g.is_due(NOW + Duration::days(7)));
        g.approve_due(NOW + Duration::days(7)).expect("due");
    }

    #[test]
    fn the_grantor_can_approve_early() {
        let mut g = confirmed();
        g.initiate(NOW).expect("confirmed");
        g.approve_early(NOW + Duration::hours(1)).expect("running");
        assert!(g.key_released());
    }

    #[test]
    fn a_rejected_request_never_comes_due_and_can_be_asked_again() {
        let mut g = confirmed();
        g.initiate(NOW).expect("confirmed");
        g.reject(NOW + Duration::days(1)).expect("running");
        assert_eq!(g.state, EmergencyState::Rejected);
        assert_eq!(g.due_at(), None);
        assert_eq!(
            g.approve_due(NOW + Duration::days(30)),
            Err(EmergencyError::WrongState(EmergencyState::Rejected))
        );
        g.initiate(NOW + Duration::days(2)).expect("rejected");
        assert_eq!(g.due_at(), Some(NOW + Duration::days(9)));
    }

    #[test]
    fn an_approval_can_be_taken_back() {
        let mut g = confirmed();
        g.initiate(NOW).expect("confirmed");
        g.approve_early(NOW).expect("running");
        g.reject(NOW + Duration::hours(2)).expect("approved");
        assert!(!g.key_released());
    }

    #[test]
    fn state_and_kind_names_round_trip() {
        for s in [
            EmergencyState::Invited,
            EmergencyState::Accepted,
            EmergencyState::Confirmed,
            EmergencyState::RecoveryInitiated,
            EmergencyState::Approved,
            EmergencyState::Rejected,
        ] {
            assert_eq!(EmergencyState::parse(s.as_str()), Some(s));
        }
        for k in [EmergencyKind::View, EmergencyKind::Takeover] {
            assert_eq!(EmergencyKind::parse(k.as_str()), Some(k));
        }
        assert_eq!(EmergencyState::parse("done"), None);
    }
}
