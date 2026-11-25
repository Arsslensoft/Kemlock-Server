//! The server admin's use cases, behind the console's six screens (Overview, Users, Events, SSO,
//! Settings, Migration) and its requests queue.
//!
//! An admin is an ordinary account with the admin role and a confirmed two-step method
//! ([`crate::authenticate::is_effective_admin`]). Reads need that; a write also needs a
//! [step-up token](step_up): a password or two-step check made minutes ago. Every write goes to
//! the event log with the admin's name and a truncated address, and the other admins are mailed
//! ([`audit::Audit`]).
//!
//! - [`users::AdminUsers`]: list, invite, resend, revoke, sign out, disable, reset two-step, delete.
//! - [`spaces::AdminSpaces`]: list, change a space's owner to a confirmed member.
//! - [`events::EventLogView`]: filter, page, CSV; [`events::EventRetention`] trims old events.
//! - [`settings::Settings`]: the typed settings store, with secrets sealed and environment-set
//!   values read-only.
//! - [`step_up::StepUp`] and [`passkey_step_up::PasskeyStepUp`]: the password, authenticator code
//!   and passkey checks that make a step-up token.
//! - [`sso_admin::SsoAdmin`]: the provider connection and email domains.
//! - [`migration::MigrationRecord`] and [`migration::MigrationRunner`]: where the move from
//!   Vaultwarden stands, and what starts it in the background.
//! - [`compliance::Compliance`]: privacy requests with their due dates.
//! - [`overview::Overview`][]: counts.
//! - [`live::Live`]: the settings the running server reads on every request (sign-ups, the
//!   largest file), changed without a restart; [`invites::InviteGate`]: registration by
//!   invitation token.
//! - [`push_relay::PushRelayControl`]: Kemlock's push relay, on or off.

pub mod audit;
pub mod compliance;
pub mod error;
pub mod events;
pub mod invites;
pub mod live;
pub mod migration;
pub mod overview;
pub mod passkey_step_up;
pub mod ports;
pub mod push_relay;
pub mod settings;
pub mod spaces;
pub mod sso_admin;
pub mod step_up;
pub mod users;

pub use audit::Audit;
pub use compliance::{Compliance, NewRequest, RequestUpdate};
pub use error::AdminError;
pub use events::{EventLogView, EventRetention};
pub use invites::{AcceptInvite, InviteGate, InviteTicket};
pub use live::Live;
pub use migration::{
    MigrationRecord, MigrationRequest, MigrationRunner, MigrationState, MigrationStatus,
};
pub use overview::{Overview, OverviewCounts};
pub use passkey_step_up::{PasskeyStepUp, PasskeyStepUpChallenge, PasskeyStepper, StepUpKeys};
pub use ports::{
    AdminContact, AdminEvent, AdminEventRepo, AdminSpaceRepo, AdminSpaceRow, AdminUserRepo,
    AdminUserRow, ComplianceCounts, ComplianceRepo, ComplianceRequest, EventCursor, EventFilter,
    EventPage, EventRecord, Invite, InviteRepo, MailError, Mailer, NoMail, Notice, RequestKind,
    RequestStatus, SettingsRepo, SpaceOwner, SpacePage, UserCounts, UserPage, UserQuery,
};
pub use push_relay::{PushRelayControl, RelayStatus};
pub use settings::{Change, EnvSettings, FnEnv, NoEnv, SettingView, Settings, Source};
pub use spaces::AdminSpaces;
pub use sso_admin::{SecretChange, SsoAdmin, SsoInput, SsoView};
pub use step_up::{Issued, PasswordStarted, StepUp};
pub use users::{AccountErasure, AdminUsers, InviteIssued};

/// Every admin repository in one bound. `SqlStore` implements all of them.
pub trait AdminRepos:
    AdminUserRepo
    + InviteRepo
    + AdminSpaceRepo
    + AdminEventRepo
    + SettingsRepo
    + ComplianceRepo
    + Clone
    + 'static
{
}

impl<T> AdminRepos for T where
    T: AdminUserRepo
        + InviteRepo
        + AdminSpaceRepo
        + AdminEventRepo
        + SettingsRepo
        + ComplianceRepo
        + Clone
        + 'static
{
}
