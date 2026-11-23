//! The requests queue (design, "Privacy and compliance"): the operator logs each privacy request
//! it gets (access, erasure, correction, opt-out) and the console shows them with their due
//! dates. Answering one is the operator's work, done with the tools beside it (export an
//! account, delete it, edit it); the queue only keeps the dates honest.
//!
//! The dates are the CCPA's: 45 calendar days, extendable once by 45 more, and 15 business days
//! for an opt-out, which can't be extended. GDPR's one month is shorter than 45 days for most
//! months, so the operator who is bound by it sets the due date by hand when logging.

use super::audit::Audit;
use super::error::AdminError;
use super::ports::{
    AdminEventRepo, AdminUserRepo, ComplianceRepo, ComplianceRequest, Mailer, RequestKind,
    RequestStatus,
};
use crate::authenticate::Actor;
use crate::platform::{Platform, random_uuid};
use kemlock_domain::UserId;
use std::net::IpAddr;
use time::{Duration, OffsetDateTime, Weekday};
use uuid::Uuid;

/// The first answer is due this many calendar days after the request arrived.
pub const RESPONSE_DAYS: i64 = 45;
/// An opt-out is due this many business days after it arrived.
pub const OPT_OUT_BUSINESS_DAYS: u32 = 15;
const MAX_NOTE_LEN: usize = 2000;
const MAX_REQUESTER_LEN: usize = 254;

/// `from` plus `days` business days: weekdays only, a Saturday or Sunday doesn't count.
pub fn add_business_days(from: OffsetDateTime, days: u32) -> OffsetDateTime {
    let mut at = from;
    let mut left = days;
    while left > 0 {
        at += Duration::days(1);
        if !matches!(at.weekday(), Weekday::Saturday | Weekday::Sunday) {
            left -= 1;
        }
    }
    at
}

/// When a request of `kind` received at `received` is due.
pub fn due_date(kind: RequestKind, received: OffsetDateTime) -> OffsetDateTime {
    match kind {
        RequestKind::OptOut => add_business_days(received, OPT_OUT_BUSINESS_DAYS),
        _ => received + Duration::days(RESPONSE_DAYS),
    }
}

/// A request to log.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NewRequest {
    pub kind: RequestKind,
    pub requester: String,
    pub user: Option<UserId>,
    /// When it arrived, if before now; `None` means now.
    pub received_at: Option<OffsetDateTime>,
    /// A due date that overrides the CCPA's.
    pub due_at: Option<OffsetDateTime>,
    pub note: Option<String>,
}

/// What to change on a request.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct RequestUpdate {
    pub status: Option<RequestStatus>,
    pub note: Option<String>,
    /// Push the due date out by another 45 days, once.
    pub extend: bool,
}

#[derive(Debug)]
pub struct Compliance<R, M, E> {
    pub repos: R,
    pub mail: M,
    pub env: E,
}

fn clean_note(note: Option<String>) -> Result<Option<String>, AdminError> {
    let Some(note) = note else {
        return Ok(None);
    };
    let note = note.trim().to_owned();
    if note.chars().count() > MAX_NOTE_LEN {
        return Err(AdminError::Invalid(format!(
            "the note is longer than {MAX_NOTE_LEN} characters"
        )));
    }
    Ok((!note.is_empty()).then_some(note))
}

impl<R, M, E> Compliance<R, M, E>
where
    R: ComplianceRepo + AdminEventRepo + AdminUserRepo + Clone,
    M: Mailer + Clone,
    E: Platform + Clone,
{
    fn audit(&self) -> Audit<R, R, M, E> {
        Audit {
            events: self.repos.clone(),
            users: self.repos.clone(),
            mail: self.mail.clone(),
            clock: self.env.clone(),
        }
    }

    /// The queue, soonest due first.
    pub async fn list(&self, open_only: bool) -> Result<Vec<ComplianceRequest>, AdminError> {
        Ok(self.repos.compliance_requests(open_only).await?)
    }

    pub async fn log(
        &self,
        actor: &Actor,
        ip: Option<IpAddr>,
        input: NewRequest,
    ) -> Result<ComplianceRequest, AdminError> {
        let requester = input.requester.trim().to_owned();
        if requester.is_empty()
            || requester.len() > MAX_REQUESTER_LEN
            || requester.chars().any(char::is_control)
        {
            return Err(AdminError::Invalid(
                "requester must be 1 to 254 characters, with no control characters".to_owned(),
            ));
        }
        let now = self.env.now();
        let received_at = input.received_at.unwrap_or(now);
        if received_at > now {
            return Err(AdminError::Invalid(
                "a request can't have arrived in the future".to_owned(),
            ));
        }
        let due_at = input
            .due_at
            .unwrap_or_else(|| due_date(input.kind, received_at));
        if due_at < received_at {
            return Err(AdminError::Invalid(
                "the due date is before the request arrived".to_owned(),
            ));
        }
        let request = ComplianceRequest {
            id: random_uuid(&self.env),
            kind: input.kind,
            requester,
            user: input.user,
            received_at,
            due_at,
            extended: false,
            status: RequestStatus::Open,
            note: clean_note(input.note)?,
            closed_at: None,
            handled_by: None,
        };
        self.repos.insert_compliance_request(&request).await?;
        self.audit()
            .record(
                actor,
                ip,
                "admin.compliance.log",
                Some(request.id.to_string()),
                "logged a privacy request",
            )
            .await;
        Ok(request)
    }

    pub async fn update(
        &self,
        actor: &Actor,
        ip: Option<IpAddr>,
        id: Uuid,
        change: RequestUpdate,
    ) -> Result<ComplianceRequest, AdminError> {
        let mut request = self
            .repos
            .compliance_request(id)
            .await?
            .ok_or(AdminError::NotFound)?;
        if change.extend {
            if request.extended {
                return Err(AdminError::State("the deadline was already extended once"));
            }
            if request.kind == RequestKind::OptOut {
                return Err(AdminError::State("an opt-out's deadline can't be extended"));
            }
            if !request.status.is_open() {
                return Err(AdminError::State("the request is closed"));
            }
            request.due_at += Duration::days(RESPONSE_DAYS);
            request.extended = true;
        }
        if let Some(note) = change.note {
            request.note = clean_note(Some(note))?;
        }
        if let Some(status) = change.status {
            let was_open = request.status.is_open();
            request.status = status;
            if status.is_open() {
                request.closed_at = None;
                request.handled_by = None;
            } else if was_open {
                request.closed_at = Some(self.env.now());
                request.handled_by = Some(actor.user);
            }
        }
        self.repos.update_compliance_request(&request).await?;
        self.audit()
            .record(
                actor,
                ip,
                "admin.compliance.update",
                Some(id.to_string()),
                "updated a privacy request",
            )
            .await;
        Ok(request)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use time::macros::datetime;

    #[test]
    fn a_response_is_due_45_days_after_the_request() {
        let received = datetime!(2026-01-10 9:00 UTC);
        assert_eq!(
            due_date(RequestKind::Access, received),
            datetime!(2026-02-24 9:00 UTC)
        );
        assert_eq!(
            due_date(RequestKind::Erasure, received),
            datetime!(2026-02-24 9:00 UTC)
        );
    }

    #[test]
    fn an_opt_out_is_due_in_15_business_days() {
        // Monday 2026-01-05: three weeks of weekdays later is Monday 2026-01-26.
        let received = datetime!(2026-01-05 9:00 UTC);
        assert_eq!(
            due_date(RequestKind::OptOut, received),
            datetime!(2026-01-26 9:00 UTC)
        );
        // Received on a Saturday, the count starts on the Monday: 15 weekdays end on a Friday.
        assert_eq!(
            add_business_days(datetime!(2026-01-10 9:00 UTC), 15),
            datetime!(2026-01-30 9:00 UTC)
        );
    }
}
