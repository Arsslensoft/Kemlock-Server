//! Ports of device approval and trusted devices.
//!
//! Method names are distinct from the other repositories' (`get`, `put`, `remove`), so one store
//! type can implement all of them and callers needn't spell out which trait they mean.

use crate::ports::StoreError;
use kemlock_domain::unlock::{ApprovalId, ApprovalState, AuthRequest, DeviceKeyCopy};
use kemlock_domain::{DeviceId, DeviceKind, Email, UserId};
use std::future::Future;
use time::OffsetDateTime;

/// What the hourly limits need to know of an earlier request.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RecentRequest {
    pub created_at: OffsetDateTime,
    /// The request's address, cut to its /24 or /48 (what the request stored).
    pub ip: String,
    pub state: ApprovalState,
}

/// Pending device approvals (`auth_requests`).
pub trait ApprovalRepo: Send + Sync {
    /// Stores a new request.
    fn insert_request(
        &self,
        request: &AuthRequest,
    ) -> impl Future<Output = Result<(), StoreError>> + Send;

    fn request(
        &self,
        id: ApprovalId,
    ) -> impl Future<Output = Result<Option<AuthRequest>, StoreError>> + Send;

    /// The account's pending requests that haven't expired at `now`, newest first.
    fn pending_requests(
        &self,
        user: UserId,
        now: OffsetDateTime,
    ) -> impl Future<Output = Result<Vec<AuthRequest>, StoreError>> + Send;

    /// A compare-and-set: writes the request's state, sealed key and answer time only when the
    /// stored state is `from`, and says whether it did. Of two racing answers, one wins.
    fn save_request(
        &self,
        request: &AuthRequest,
        from: ApprovalState,
    ) -> impl Future<Output = Result<bool, StoreError>> + Send;

    /// The account's requests made after `since`, oldest first, with where each came from and how
    /// it stands. Backs the hourly limits.
    fn requests_since(
        &self,
        user: UserId,
        since: OffsetDateTime,
    ) -> impl Future<Output = Result<Vec<RecentRequest>, StoreError>> + Send;

    /// Deletes requests that expired before `before`. Returns how many went.
    fn purge_requests(
        &self,
        before: OffsetDateTime,
    ) -> impl Future<Output = Result<u64, StoreError>> + Send;
}

/// The trusted-device copies of the root key (`device_key_copies`), one per device.
pub trait KeyCopyRepo: Send + Sync {
    fn key_copy(
        &self,
        device: DeviceId,
    ) -> impl Future<Output = Result<Option<DeviceKeyCopy>, StoreError>> + Send;

    /// Inserts or replaces the device's copy. `NotFound` when the device doesn't exist.
    fn put_key_copy(
        &self,
        copy: &DeviceKeyCopy,
    ) -> impl Future<Output = Result<(), StoreError>> + Send;

    /// [`put_key_copy`](KeyCopyRepo::put_key_copy) for a copy the client made for `key_version`: a
    /// store that can read the account refuses (`StaleKeyVersion`) a copy for a version that is no
    /// longer the account's. `None` checks nothing. Every store implements the check.
    fn put_key_copy_at(
        &self,
        copy: &DeviceKeyCopy,
        key_version: Option<u32>,
    ) -> impl Future<Output = Result<(), StoreError>> + Send;

    /// Deletes the device's copy, if it has one.
    fn remove_key_copy(
        &self,
        device: DeviceId,
    ) -> impl Future<Output = Result<(), StoreError>> + Send;
}

/// Both repositories: what the API's store type must be on top of the others.
pub trait DevicesStore: ApprovalRepo + KeyCopyRepo {}

impl<T: ApprovalRepo + KeyCopyRepo> DevicesStore for T {}

/// What an email about a new device says: enough for the account's owner to tell their own
/// sign-in from someone else's, and nothing that could open the vault.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NewDeviceNotice {
    pub to: Email,
    pub device_name: String,
    pub device_kind: DeviceKind,
    /// The request's address, cut to its /24 or /48.
    pub ip: String,
    pub at: OffsetDateTime,
}

/// Tells an account's owner a new device asked to sign in. Best effort: a failure to send is the
/// sender's to log, never a reason to refuse the request.
pub trait DeviceNotices: Send + Sync {
    fn new_device(&self, notice: NewDeviceNotice) -> impl Future<Output = ()> + Send;
}

/// A notice sender that only writes a log line, for a server with no mail configured.
#[derive(Clone, Copy, Debug, Default)]
pub struct LogNotices;

impl DeviceNotices for LogNotices {
    async fn new_device(&self, notice: NewDeviceNotice) {
        tracing::info!(
            device = %notice.device_name,
            ip = %notice.ip,
            "a new device asked for approval (no mail sender is configured)"
        );
    }
}
