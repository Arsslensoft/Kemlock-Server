//! The ports the admin use cases call, and the plain data they pass. `kemlock-store-sql`
//! implements the repositories; tests use an in-memory fake. Like `crate::ports`, async methods
//! return `impl Future + Send` and every method is cancel-safe.

use crate::ports::StoreError;
use kemlock_domain::{
    AccountMode, CustomField, CustomFieldId, DeviceId, Email, Role, SpaceId, UserId,
};
use std::future::Future;
use time::OffsetDateTime;
use uuid::Uuid;

// ---------------------------------------------------------------------------------------------
// Users

/// One account as the console's Users screen shows it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AdminUserRow {
    pub id: UserId,
    pub email: String,
    pub name: Option<String>,
    pub role: Role,
    pub mode: AccountMode,
    pub created_at: OffsetDateTime,
    /// Set while the account is disabled.
    pub disabled_at: Option<OffsetDateTime>,
    pub devices: u32,
    /// Whether the account has a confirmed two-step method.
    pub two_step: bool,
    /// The newest sign-in of any of its devices.
    pub last_seen_at: Option<OffsetDateTime>,
    /// The owner deleted the account and its grace period is running; only an admin can cancel it.
    pub erasure_pending: bool,
}

/// Which accounts to list.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UserQuery {
    /// Part of the email or name, case-insensitive.
    pub search: Option<String>,
    pub limit: u32,
    pub offset: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UserPage {
    pub users: Vec<AdminUserRow>,
    /// Every account that matches, not only this page.
    pub total: u64,
}

/// An admin account, for the alert mail.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AdminContact {
    pub id: UserId,
    pub email: Email,
}

/// Counts of accounts and devices.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct UserCounts {
    pub users: u64,
    pub admins: u64,
    pub disabled: u64,
    pub devices: u64,
}

pub trait AdminUserRepo: Send + Sync {
    fn list_users(
        &self,
        query: &UserQuery,
    ) -> impl Future<Output = Result<UserPage, StoreError>> + Send;

    fn user_row(
        &self,
        id: UserId,
    ) -> impl Future<Output = Result<Option<AdminUserRow>, StoreError>> + Send;

    /// Disables the account (`Some((when, by whom))`) or enables it again (`None`). `NotFound`
    /// for an account that isn't there.
    fn set_disabled(
        &self,
        user: UserId,
        disabled: Option<(OffsetDateTime, UserId)>,
    ) -> impl Future<Output = Result<(), StoreError>> + Send;

    /// Whether the account is disabled. Sign-in paths call this: a disabled account signs nobody
    /// in.
    fn is_disabled(&self, user: UserId) -> impl Future<Output = Result<bool, StoreError>> + Send;

    /// Every account with the admin role, oldest first.
    fn admins(&self) -> impl Future<Output = Result<Vec<AdminContact>, StoreError>> + Send;

    /// The spaces in which `user` is the only confirmed owner.
    fn sole_owned_spaces(
        &self,
        user: UserId,
    ) -> impl Future<Output = Result<Vec<SpaceId>, StoreError>> + Send;

    /// Erases the account and what hangs off it: its items, devices, tokens, two-step methods,
    /// memberships, key copies, linked identities and invitations. Events keep their rows.
    /// This is the store's narrow erase: it leaves Sends, files, the sign-in log and federated
    /// copies. The console's "Delete user" doesn't call it; it goes through [`super::AccountErasure`]
    /// (privacy's `EraseAccount`).
    fn erase_user(&self, user: UserId) -> impl Future<Output = Result<(), StoreError>> + Send;

    /// Takes the account off the erasure schedule: its owner deleted it and the grace period is
    /// still running. `false` when no erasure was pending. A store with no schedule keeps this
    /// default.
    fn cancel_pending_erasure(
        &self,
        user: UserId,
    ) -> impl Future<Output = Result<bool, StoreError>> + Send {
        let _ = user;
        async { Ok(false) }
    }

    fn user_counts(&self) -> impl Future<Output = Result<UserCounts, StoreError>> + Send;
}

// ---------------------------------------------------------------------------------------------
// Invitations to the server

/// An invitation to make an account on this server. Only the hash of its token is kept, so a
/// database copy can't be used to accept it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Invite {
    pub id: Uuid,
    pub email: Email,
    pub invited_by: UserId,
    pub token_hash: [u8; 32],
    pub created_at: OffsetDateTime,
    pub expires_at: OffsetDateTime,
    pub last_sent_at: OffsetDateTime,
    pub sent: u32,
    pub accepted_at: Option<OffsetDateTime>,
}

impl Invite {
    pub fn is_pending(&self, now: OffsetDateTime) -> bool {
        self.accepted_at.is_none() && now < self.expires_at
    }
}

pub trait InviteRepo: Send + Sync {
    /// Stores the invitation; `Duplicate` when one for that email is stored.
    fn insert_invite(&self, invite: &Invite)
    -> impl Future<Output = Result<(), StoreError>> + Send;
    fn invites(&self) -> impl Future<Output = Result<Vec<Invite>, StoreError>> + Send;
    fn invite(&self, id: Uuid) -> impl Future<Output = Result<Option<Invite>, StoreError>> + Send;
    /// Replaces the stored invitation with the same id.
    fn update_invite(&self, invite: &Invite)
    -> impl Future<Output = Result<(), StoreError>> + Send;
    fn remove_invite(&self, id: Uuid) -> impl Future<Output = Result<(), StoreError>> + Send;
    /// The invitation a token's hash belongs to. Registration calls this to let an invited
    /// address sign up while sign-ups are closed.
    fn invite_by_token(
        &self,
        token_hash: [u8; 32],
    ) -> impl Future<Output = Result<Option<Invite>, StoreError>> + Send;
    /// How many invitations are neither accepted nor expired at `now`.
    fn pending_invites(
        &self,
        now: OffsetDateTime,
    ) -> impl Future<Output = Result<u64, StoreError>> + Send;
}

// ---------------------------------------------------------------------------------------------
// Spaces

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SpaceOwner {
    pub user: UserId,
    pub email: String,
}

/// One space as the console's Spaces list shows it. Names are encrypted under the space key,
/// which the server never holds, so a space is shown by id, owners and size.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AdminSpaceRow {
    pub id: SpaceId,
    pub created_at: OffsetDateTime,
    pub members: u32,
    pub confirmed: u32,
    /// Confirmed owners.
    pub owners: Vec<SpaceOwner>,
    pub live_items: u64,
    pub keys_pending_since: Option<OffsetDateTime>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SpacePage {
    pub spaces: Vec<AdminSpaceRow>,
    pub total: u64,
}

pub trait AdminSpaceRepo: Send + Sync {
    fn list_spaces(
        &self,
        limit: u32,
        offset: u64,
    ) -> impl Future<Output = Result<SpacePage, StoreError>> + Send;
    fn space_row(
        &self,
        id: SpaceId,
    ) -> impl Future<Output = Result<Option<AdminSpaceRow>, StoreError>> + Send;
    /// How many items (not tombstones) the server holds.
    fn live_items(&self) -> impl Future<Output = Result<u64, StoreError>> + Send;
}

// ---------------------------------------------------------------------------------------------
// Events

/// An event as the admin console writes it: with the client's address, cut when it is made.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AdminEvent {
    pub actor: Option<UserId>,
    pub device: Option<DeviceId>,
    pub action: String,
    pub target: Option<String>,
    /// The client's address cut to its /24 or /48.
    pub ip: Option<String>,
    pub at: OffsetDateTime,
}

/// An event read back, with the actor's email when the account still exists.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EventRecord {
    pub id: Uuid,
    pub at: OffsetDateTime,
    pub actor: Option<UserId>,
    pub actor_email: Option<String>,
    pub device: Option<DeviceId>,
    pub action: String,
    pub target: Option<String>,
    pub ip: Option<String>,
}

/// What to look for in the event log. Every field narrows the result.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct EventFilter {
    pub actor: Option<UserId>,
    /// An action name, or a prefix ending in `*` (`space.*`). Letters, digits, `.`, `_`, `-`
    /// and `*` only.
    pub action: Option<String>,
    /// Text the target contains. Letters, digits and `. _ - : / @` only.
    pub target: Option<String>,
    pub from: Option<OffsetDateTime>,
    pub to: Option<OffsetDateTime>,
}

/// Where the next page starts: events are newest first, ordered by time then id.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EventCursor {
    pub at: OffsetDateTime,
    pub id: Uuid,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EventPage {
    pub events: Vec<EventRecord>,
    /// Present when more events follow.
    pub next: Option<EventCursor>,
}

pub trait AdminEventRepo: Send + Sync {
    fn record_admin_event(
        &self,
        event: AdminEvent,
    ) -> impl Future<Output = Result<(), StoreError>> + Send;

    /// Events matching `filter`, newest first, after `after`, at most `limit`.
    fn query_events(
        &self,
        filter: &EventFilter,
        after: Option<&EventCursor>,
        limit: u32,
    ) -> impl Future<Output = Result<EventPage, StoreError>> + Send;

    fn count_events_since(
        &self,
        since: OffsetDateTime,
    ) -> impl Future<Output = Result<u64, StoreError>> + Send;

    /// Deletes events older than `before`. Returns how many went.
    fn purge_events_before(
        &self,
        before: OffsetDateTime,
    ) -> impl Future<Output = Result<u64, StoreError>> + Send;
}

// ---------------------------------------------------------------------------------------------
// Settings

/// Small named values the server keeps for itself, as text (the `settings` table).
pub trait SettingsRepo: Send + Sync {
    /// Every `(key, value)` whose key starts with `prefix`.
    fn settings_with_prefix(
        &self,
        prefix: &str,
    ) -> impl Future<Output = Result<Vec<(String, String)>, StoreError>> + Send;
    /// Inserts the value or replaces the one that is there.
    fn put_setting(
        &self,
        key: &str,
        value: &str,
    ) -> impl Future<Output = Result<(), StoreError>> + Send;
    fn delete_setting(&self, key: &str) -> impl Future<Output = Result<(), StoreError>> + Send;
}

// ---------------------------------------------------------------------------------------------
// Custom fields

/// The custom fields an admin defined (`custom_fields`). Names and types are not secret and are
/// kept in the clear; the values live in the items, which the server can't read.
pub trait CustomFieldRepo: Send + Sync {
    /// Every definition, oldest first.
    fn custom_fields(&self) -> impl Future<Output = Result<Vec<CustomField>, StoreError>> + Send;

    fn custom_field(
        &self,
        id: CustomFieldId,
    ) -> impl Future<Output = Result<Option<CustomField>, StoreError>> + Send;

    /// Stores the definition; `Duplicate` when another has the same name, whatever the case.
    fn insert_custom_field(
        &self,
        field: &CustomField,
    ) -> impl Future<Output = Result<(), StoreError>> + Send;

    /// Replaces the name, type, kinds and update time of the definition with the same id.
    /// `NotFound` when it is gone; `Duplicate` when another has the new name.
    fn update_custom_field(
        &self,
        field: &CustomField,
    ) -> impl Future<Output = Result<(), StoreError>> + Send;

    /// Deletes the definition; `false` when there was none.
    fn remove_custom_field(
        &self,
        id: CustomFieldId,
    ) -> impl Future<Output = Result<bool, StoreError>> + Send;
}

// ---------------------------------------------------------------------------------------------
// Compliance requests

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RequestKind {
    /// GDPR Art. 15, CCPA right to know.
    Access,
    /// GDPR Art. 17, CCPA delete.
    Erasure,
    /// CCPA correct.
    Correction,
    /// CCPA opt-out of sale or sharing, due in 15 business days.
    OptOut,
    Other,
}

impl RequestKind {
    pub fn as_str(self) -> &'static str {
        match self {
            RequestKind::Access => "access",
            RequestKind::Erasure => "erasure",
            RequestKind::Correction => "correction",
            RequestKind::OptOut => "opt-out",
            RequestKind::Other => "other",
        }
    }

    pub fn parse(s: &str) -> Option<RequestKind> {
        match s {
            "access" => Some(RequestKind::Access),
            "erasure" => Some(RequestKind::Erasure),
            "correction" => Some(RequestKind::Correction),
            "opt-out" => Some(RequestKind::OptOut),
            "other" => Some(RequestKind::Other),
            _ => None,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RequestStatus {
    Open,
    InProgress,
    Done,
    Rejected,
}

impl RequestStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            RequestStatus::Open => "open",
            RequestStatus::InProgress => "in-progress",
            RequestStatus::Done => "done",
            RequestStatus::Rejected => "rejected",
        }
    }

    pub fn parse(s: &str) -> Option<RequestStatus> {
        match s {
            "open" => Some(RequestStatus::Open),
            "in-progress" => Some(RequestStatus::InProgress),
            "done" => Some(RequestStatus::Done),
            "rejected" => Some(RequestStatus::Rejected),
            _ => None,
        }
    }

    /// Whether the request still needs an answer.
    pub fn is_open(self) -> bool {
        matches!(self, RequestStatus::Open | RequestStatus::InProgress)
    }
}

/// A privacy request the operator must answer, with its due date.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ComplianceRequest {
    pub id: Uuid,
    pub kind: RequestKind,
    /// Who asked, as they gave it.
    pub requester: String,
    /// The account the request is about, when it is one of this server's.
    pub user: Option<UserId>,
    pub received_at: OffsetDateTime,
    pub due_at: OffsetDateTime,
    /// Whether the deadline was extended once (CCPA allows 45 more days).
    pub extended: bool,
    pub status: RequestStatus,
    pub note: Option<String>,
    pub closed_at: Option<OffsetDateTime>,
    pub handled_by: Option<UserId>,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ComplianceCounts {
    pub open: u64,
    /// Open and past their due date.
    pub overdue: u64,
}

pub trait ComplianceRepo: Send + Sync {
    fn insert_compliance_request(
        &self,
        request: &ComplianceRequest,
    ) -> impl Future<Output = Result<(), StoreError>> + Send;
    fn compliance_request(
        &self,
        id: Uuid,
    ) -> impl Future<Output = Result<Option<ComplianceRequest>, StoreError>> + Send;
    /// Replaces the stored request with the same id.
    fn update_compliance_request(
        &self,
        request: &ComplianceRequest,
    ) -> impl Future<Output = Result<(), StoreError>> + Send;
    /// The queue, soonest due first: open requests only, or every request.
    fn compliance_requests(
        &self,
        open_only: bool,
    ) -> impl Future<Output = Result<Vec<ComplianceRequest>, StoreError>> + Send;
    fn compliance_counts(
        &self,
        now: OffsetDateTime,
    ) -> impl Future<Output = Result<ComplianceCounts, StoreError>> + Send;
}

// ---------------------------------------------------------------------------------------------
// Mail

/// A plain-text mail.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Notice {
    pub to: Email,
    pub subject: String,
    pub body: String,
}

#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum MailError {
    #[error("no SMTP server is set up")]
    NotConfigured,
    /// The text is for logs, never for clients.
    #[error("the mail wasn't sent: {0}")]
    Failed(String),
}

/// Sends mail through the SMTP server the admin set up.
pub trait Mailer: Send + Sync {
    /// Whether mail can be sent at all.
    fn configured(&self) -> bool;
    fn send(&self, notice: Notice) -> impl Future<Output = Result<(), MailError>> + Send;
}

/// The mailer of a server with no SMTP: nothing is sent.
#[derive(Clone, Copy, Debug, Default)]
pub struct NoMail;

impl Mailer for NoMail {
    fn configured(&self) -> bool {
        false
    }

    async fn send(&self, _notice: Notice) -> Result<(), MailError> {
        Err(MailError::NotConfigured)
    }
}
