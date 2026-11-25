//! Privacy and compliance (design, "Privacy and compliance"): export and erasure of an account,
//! the retention job, the processing summary and the incident export. Each is a use case over the
//! ports in [`ports`], so the web vault, the admin console and the background jobs share one rule.

mod erase;
mod export;
mod grace;
mod incident;
pub mod ports;
mod processing;
mod retention;
mod signin;

use kemlock_domain::UserId;

pub use erase::{EraseAccount, Erasure, ErasureReport, OwnErasure, Reauthenticate};
pub use export::{AccountExport, EXPORT_FORMAT, ExportAccount};
pub use grace::ensure_not_pending;
pub use incident::{
    ExportIncident, INCIDENT_FORMAT, IncidentExport, IncidentRequest, NOTIFY_WITHIN,
};
pub use ports::{
    AccountData, AccountEraser, ErasedRows, ErasureFiles, NewSignIn, NoSends, PrivacyLog,
    PrivacySettings, ProcessingInputs, ProcessingSource, PurgedTrash, RetentionStore, SendEraser,
    TwoFactorInfo,
};
pub use processing::{
    ExportProcessingSummary, ProcessingSummary, SUMMARY_FORMAT, render_processing_summary,
};
pub use retention::{RetentionReport, RunRetention};
pub use signin::{ClientAddr, attempt_outcome, record_sign_in, sign_in_entry};

/// Who asked for an export or an erasure. The event log names the actor either way.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Requester {
    /// The account itself, from the web vault or an app.
    Account,
    /// An admin acting on the person's request, from the admin console.
    Admin(UserId),
    /// The retention job, for an account whose grace period ended.
    Retention,
}
