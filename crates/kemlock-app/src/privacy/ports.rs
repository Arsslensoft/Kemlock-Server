//! The ports the privacy use cases call. `kemlock-store-sql` implements them on `SqlStore`; tests
//! use in-memory fakes. Like `crate::ports`, async methods return `impl Future + Send` and every
//! method is cancel-safe.

use crate::ports::{Event, StoreError};
use kemlock_domain::privacy::{Retention, SignInEntry, SignInOutcome, StoredEvent};
use kemlock_domain::spaces::Member;
use kemlock_domain::{BlobId, Device, DeviceId, Item, SpaceId, User, UserId};
use std::future::Future;
use std::net::IpAddr;
use time::OffsetDateTime;

/// What the server holds of one two-step method, without its secret.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TwoFactorInfo {
    /// `totp` or `webauthn`.
    pub method: String,
    pub enabled: bool,
    pub created_at: OffsetDateTime,
}

/// Everything the server keeps about one account besides the account row and the logs: what an
/// export lists.
pub trait AccountData: Send + Sync {
    fn devices(&self, user: UserId)
    -> impl Future<Output = Result<Vec<Device>, StoreError>> + Send;

    /// The account's own vault as stored: every item and tombstone it owns, ciphertext included.
    /// Items of spaces it belongs to are the space's, not the account's.
    fn vault(&self, user: UserId) -> impl Future<Output = Result<Vec<Item>, StoreError>> + Send;

    /// The account's place in every space, in any state.
    fn memberships(
        &self,
        user: UserId,
    ) -> impl Future<Output = Result<Vec<Member>, StoreError>> + Send;

    fn two_factor(
        &self,
        user: UserId,
    ) -> impl Future<Output = Result<Vec<TwoFactorInfo>, StoreError>> + Send;
}

/// A sign-in attempt to record. The log keeps the address truncated whatever is passed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NewSignIn {
    pub user: Option<UserId>,
    pub device: Option<DeviceId>,
    /// `password`, `two-factor`, `passkey`, `device-approval`, `device-key`, `sso`, `refresh` or
    /// `api-key`.
    pub method: &'static str,
    pub outcome: SignInOutcome,
    pub at: OffsetDateTime,
    pub ip: Option<IpAddr>,
}

/// The event log and the sign-in log, with their addresses.
pub trait PrivacyLog: Send + Sync {
    /// Writes an event with the client's address. The address is cut to its /24 or /48 on the way
    /// in; the whole one is kept beside it only while the retention settings keep full addresses.
    fn record_event(
        &self,
        event: Event,
        ip: Option<IpAddr>,
    ) -> impl Future<Output = Result<(), StoreError>> + Send;

    /// Writes a sign-in attempt, truncating its address as `record_event` does.
    fn record_sign_in(
        &self,
        entry: NewSignIn,
    ) -> impl Future<Output = Result<(), StoreError>> + Send;

    /// Events whose actor is the account, oldest first.
    fn events_of(
        &self,
        user: UserId,
    ) -> impl Future<Output = Result<Vec<StoredEvent>, StoreError>> + Send;

    /// The account's sign-in attempts, oldest first.
    fn sign_ins_of(
        &self,
        user: UserId,
    ) -> impl Future<Output = Result<Vec<SignInEntry>, StoreError>> + Send;

    /// Events from `from` up to but not including `to`, oldest first.
    fn events_between(
        &self,
        from: OffsetDateTime,
        to: OffsetDateTime,
    ) -> impl Future<Output = Result<Vec<StoredEvent>, StoreError>> + Send;

    /// Sign-in attempts in the same window.
    fn sign_ins_between(
        &self,
        from: OffsetDateTime,
        to: OffsetDateTime,
    ) -> impl Future<Output = Result<Vec<SignInEntry>, StoreError>> + Send;
}

/// The admin's retention settings, kept in the database.
pub trait PrivacySettings: Send + Sync {
    /// The saved settings, or the defaults when none were saved.
    fn retention(&self) -> impl Future<Output = Result<Retention, StoreError>> + Send;

    fn save_retention(
        &self,
        retention: &Retention,
    ) -> impl Future<Output = Result<(), StoreError>> + Send;
}

/// What an erasure removed from the database, and the files that now have no row.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ErasedRows {
    pub items: u64,
    pub devices: u64,
    pub refresh_tokens: u64,
    pub sign_ins: u64,
    /// Events whose name or email was removed, or whose address was dropped.
    pub events_scrubbed: u64,
    pub space_memberships: u64,
    /// Spaces the account was alone in, removed with their items.
    pub spaces_removed: u64,
    /// Attachment files of the Kemlock API to delete.
    pub blobs: Vec<BlobId>,
    /// Files of Bitwarden-API ciphers (`<cipher id>/<attachment id>`) to delete.
    pub cipher_files: Vec<String>,
}

pub trait AccountEraser: Send + Sync {
    /// Spaces the account owns alone while others are still in them. Erasing it would leave them
    /// without an owner, so the account must hand them over or delete them first.
    fn blocking_spaces(
        &self,
        user: UserId,
    ) -> impl Future<Output = Result<Vec<SpaceId>, StoreError>> + Send;

    /// In one transaction: removes the account's items, attachment rows, devices, refresh tokens,
    /// two-step methods, key copies, approvals, space memberships and sign-in log, the emergency
    /// grants it gave or received, and the account row; and strips its name and email from the
    /// event log (and drops the addresses of its events). Spaces it was alone in go too.
    /// `NotFound` when the account doesn't exist.
    fn erase_user(
        &self,
        user: &User,
    ) -> impl Future<Output = Result<ErasedRows, StoreError>> + Send;

    /// Marks the account for erasure at `due`, for the grace period of a deleted account.
    fn schedule_erasure(
        &self,
        user: UserId,
        requested_at: OffsetDateTime,
        due: OffsetDateTime,
    ) -> impl Future<Output = Result<(), StoreError>> + Send;

    /// When the account's erasure is due, if one is scheduled.
    fn scheduled_erasure(
        &self,
        user: UserId,
    ) -> impl Future<Output = Result<Option<OffsetDateTime>, StoreError>> + Send;

    /// Takes the account off the schedule.
    fn cancel_erasure(&self, user: UserId) -> impl Future<Output = Result<(), StoreError>> + Send;

    /// Accounts whose erasure is due at `now`.
    fn due_erasures(
        &self,
        now: OffsetDateTime,
    ) -> impl Future<Output = Result<Vec<UserId>, StoreError>> + Send;
}

/// Removes an account's Sends. Sends are a feature of their own; whoever stores them implements
/// this, and [`NoSends`] stands in until there are any.
pub trait SendEraser: Send + Sync {
    /// Deletes every Send the account made. Returns how many.
    fn erase_sends(&self, user: UserId) -> impl Future<Output = Result<u64, StoreError>> + Send;
}

/// For a server with no Sends.
#[derive(Clone, Copy, Debug, Default)]
pub struct NoSends;

impl SendEraser for NoSends {
    async fn erase_sends(&self, _user: UserId) -> Result<u64, StoreError> {
        Ok(0)
    }
}

/// Deletes the files rows no longer name. A file already gone is not an error.
pub trait ErasureFiles: Send + Sync {
    /// An attachment of the Kemlock API.
    fn delete_blob(&self, blob: BlobId) -> impl Future<Output = Result<(), StoreError>> + Send;

    /// A file of the Bitwarden API, by its `<cipher id>/<attachment id>` key.
    fn delete_cipher_file(&self, key: &str) -> impl Future<Output = Result<(), StoreError>> + Send;
}

/// One item the trash purge removed, and the files that went with it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PurgedTrash {
    pub item: kemlock_domain::ItemId,
    pub blobs: Vec<BlobId>,
    pub cipher_files: Vec<String>,
}

/// What the retention job deletes by age, apart from the tombstones and device approvals that
/// `ItemStore` and `ApprovalRepo` already purge.
pub trait RetentionStore: Send + Sync {
    /// Deletes events older than `before`. Returns how many.
    fn purge_events(
        &self,
        before: OffsetDateTime,
    ) -> impl Future<Output = Result<u64, StoreError>> + Send;

    fn purge_sign_ins(
        &self,
        before: OffsetDateTime,
    ) -> impl Future<Output = Result<u64, StoreError>> + Send;

    /// Drops the whole addresses kept beside the truncated ones, on rows older than `before`.
    /// Returns how many rows lost one.
    fn drop_full_ips(
        &self,
        before: OffsetDateTime,
    ) -> impl Future<Output = Result<u64, StoreError>> + Send;

    /// Deletes the Bitwarden-API items that were put in the trash before `before`, leaving
    /// tombstones, and their attachment rows. Only `ItemFormat::Bw` items: the server can read the
    /// trash date only in those. A Kemlock item keeps it inside its ciphertext, so the server
    /// can't see it is trashed and never purges it; the Kemlock apps empty their own trash.
    fn purge_trash(
        &self,
        before: OffsetDateTime,
        now: OffsetDateTime,
    ) -> impl Future<Output = Result<Vec<PurgedTrash>, StoreError>> + Send;

    /// Deletes email-log rows older than `before`. The email log belongs to the mail sender; a
    /// store that has none leaves this as it is.
    fn purge_email_log(
        &self,
        before: OffsetDateTime,
    ) -> impl Future<Output = Result<u64, StoreError>> + Send {
        let _ = before;
        async { Ok(0) }
    }
}

/// What the processing summary says about this installation: the settings the server was started
/// with and the integrations the admin turned on.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ProcessingInputs {
    /// The operator's name, for the controller line; `None` leaves a placeholder.
    pub operator_name: Option<String>,
    pub dpo_contact: Option<String>,
    /// The mail provider, when mail is set up (a host name).
    pub smtp_provider: Option<String>,
    /// The single sign-on identity provider's issuer, when SSO is on.
    pub identity_provider: Option<String>,
    /// The push relay is on.
    pub push_relay: bool,
    /// The S3-compatible storage endpoint (or `AWS S3`), when files live in a bucket.
    pub s3_storage: Option<String>,
    pub update_check: bool,
    pub website_icons: bool,
    /// Where backups go (`local` or `S3`), when they are on.
    pub backup_destination: Option<String>,
    /// Peer servers the vault is federated with.
    pub federation_peers: u32,
}

/// Where the processing summary reads the installation's settings from.
pub trait ProcessingSource: Send + Sync {
    fn inputs(&self) -> impl Future<Output = Result<ProcessingInputs, StoreError>> + Send;
}
