//! The ports the Send use cases call. `kemlock-store-sql` implements [`SendRepo`] and
//! `kemlock-blob` implements [`SendBlobs`]; tests use in-memory fakes. Methods have names no other
//! port has, so one store implements them all without disambiguation.
//!
//! These are also the port the Bitwarden layer builds its Send routes on: it maps Bitwarden's
//! `name`, `notes`, `key` and `data` onto the sealed parts of a `SendRecord` and calls the same use
//! cases, so a Send made through either API follows one set of rules.

use crate::files::{BlobError, BlobStore};
use crate::ports::StoreError;
use crate::quota::{QuotaRefusal, check};
use kemlock_domain::sends::{SendId, SendRecord};
use kemlock_domain::{BlobId, UserId};
use std::future::Future;
use time::OffsetDateTime;

/// What these Sends' files announced, in bytes: what the file Send quota counts.
pub fn file_send_bytes(sends: &[SendRecord]) -> u64 {
    sends
        .iter()
        .filter_map(|s| s.file)
        .fold(0u64, |total, file| total.saturating_add(file.size))
}

/// The `sends` table.
pub trait SendRepo: Send + Sync {
    /// Stores a new Send; `Duplicate` when the id is taken, `NotFound` when the owner is gone.
    fn add_send(&self, send: &SendRecord) -> impl Future<Output = Result<(), StoreError>> + Send;

    /// Stores a new Send, as [`add_send`](SendRepo::add_send), when the bytes the owner's file Sends
    /// announced, plus this Send's file, fit `quota` (see [`check`]); otherwise stores nothing and
    /// says why. A store makes the sum and the insert one step, so two Sends made together can't
    /// each see room that only one of them may take. The provided method does them one after the
    /// other, which only a store with no concurrent callers may use.
    fn add_send_within_quota(
        &self,
        send: &SendRecord,
        quota: Option<u64>,
    ) -> impl Future<Output = Result<Result<(), QuotaRefusal>, StoreError>> + Send {
        async move {
            if let (Some(_), Some(file)) = (quota, send.file) {
                let used = file_send_bytes(&self.sends_of(send.owner).await?);
                if let Err(refusal) = check(quota, used, file.size) {
                    return Ok(Err(refusal));
                }
            }
            self.add_send(send).await?;
            Ok(Ok(()))
        }
    }

    /// [`add_send_within_quota`](SendRepo::add_send_within_quota) for a Send whose sealed key is
    /// for `key_version`: a store that can read the owner's account refuses (`StaleKeyVersion`)
    /// when that is no longer the account's, so a Send can't be made after a rotation with a key
    /// of the old root key. `None` checks nothing. Every store implements the check.
    fn add_send_within_quota_at(
        &self,
        send: &SendRecord,
        quota: Option<u64>,
        key_version: Option<u32>,
    ) -> impl Future<Output = Result<Result<(), QuotaRefusal>, StoreError>> + Send;

    fn send_by_id(
        &self,
        id: SendId,
    ) -> impl Future<Output = Result<Option<SendRecord>, StoreError>> + Send;

    /// An account's Sends, newest first.
    fn sends_of(
        &self,
        owner: UserId,
    ) -> impl Future<Output = Result<Vec<SendRecord>, StoreError>> + Send;

    /// Writes what an owner may change: the name and notes, the content of a note, the password,
    /// the view limit, the two dates and the two switches, and the revision time. Never the owner,
    /// the key, the file or the view count. `NotFound` when the Send is gone.
    fn update_send(&self, send: &SendRecord)
    -> impl Future<Output = Result<(), StoreError>> + Send;

    /// [`update_send`](SendRepo::update_send) for a change sealed for `key_version` (the account's
    /// key version the client made `meta` and the content with): a store that can read the
    /// owner's account refuses (`StaleKeyVersion`) when that is no longer the account's. `None`
    /// checks nothing. Every store implements the check.
    fn update_send_at(
        &self,
        send: &SendRecord,
        key_version: Option<u32>,
    ) -> impl Future<Output = Result<(), StoreError>> + Send;

    /// Marks a file Send's bytes as arrived. `false` when the Send is gone or was ready already,
    /// which is how two uploads of one file are told apart.
    fn mark_send_file_ready(
        &self,
        id: SendId,
    ) -> impl Future<Output = Result<bool, StoreError>> + Send;

    /// Counts one view, in one conditional statement, so two openers racing for the last view
    /// can't both win. `false` when the view limit was already used up or the Send is gone.
    fn count_send_view(
        &self,
        id: SendId,
        at: OffsetDateTime,
    ) -> impl Future<Output = Result<bool, StoreError>> + Send;

    /// Deletes the row. A row that is already gone is not an error.
    fn remove_send(&self, id: SendId) -> impl Future<Output = Result<(), StoreError>> + Send;

    /// Sends whose deletion date is at or before `now`, and file Sends whose bytes never arrived
    /// and that were made before `abandoned_before`. At most `limit`, oldest first.
    fn sends_to_delete(
        &self,
        now: OffsetDateTime,
        abandoned_before: OffsetDateTime,
        limit: u32,
    ) -> impl Future<Output = Result<Vec<SendRecord>, StoreError>> + Send;
}

/// Where a file Send's bytes live: the same blob storage attachments use, under random ids, with
/// one addition. A Bitwarden app encrypts a Send's file in its own buffer format, which is not
/// `KMA1`, so a Send may also store bytes of any format ([`SendBlobs::begin_raw`]), capped in size.
pub trait SendBlobs: BlobStore {
    /// Starts an upload of at most `max_size` bytes to `blob` that checks only the size, not a
    /// `KMA1` header. Kemlock's own clients use [`BlobStore::begin`].
    fn begin_raw(
        &self,
        blob: BlobId,
        max_size: u64,
    ) -> impl Future<Output = Result<Self::Upload, BlobError>> + Send;
}

/// What a person's space policies let them do with Sends.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct SendRules {
    /// A space they belong to forbids making or editing Sends ("Remove Send"). They may still
    /// delete one.
    pub disabled: bool,
    /// A space they belong to requires Sends to show the sender's email.
    pub force_email: bool,
}

/// Looks up the [`SendRules`] of an account. The policies area implements it over the spaces and
/// their policies.
pub trait SendPolicies: Send + Sync {
    fn send_rules(
        &self,
        user: UserId,
    ) -> impl Future<Output = Result<SendRules, StoreError>> + Send;
}

/// No policies: every account may make any Send. For a server or a test without spaces.
#[derive(Clone, Copy, Debug, Default)]
pub struct NoSendPolicies;

impl SendPolicies for NoSendPolicies {
    async fn send_rules(&self, _user: UserId) -> Result<SendRules, StoreError> {
        Ok(SendRules::default())
    }
}
