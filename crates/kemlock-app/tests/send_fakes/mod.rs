//! In-memory fakes for the Send and policy ports. Included with `mod send_fakes;` (the router tests
//! reach it with `#[path]`).
//!
//! `FakeSendBlobs` keeps to the contract of the real store, which `kemlock-blob` tests: a size cap,
//! a `KMA1` magic check as bytes arrive for `begin`, and none for `begin_raw`.
#![allow(dead_code, unused_imports)]

use bytes::Bytes;
use futures_util::StreamExt;
use kemlock_app::files::{BlobError, BlobRead, BlobStore, BlobUpload, PresignedUrl};
use kemlock_app::policies::{PolicyRepo, StoredPolicies};
use kemlock_app::quota::QuotaRefusal;
use kemlock_app::ports::StoreError;
use kemlock_app::sends::{SendBlobs, SendPolicies, SendRepo, SendRules};
use kemlock_domain::policies::{PoliciesBySpace, SpacePolicies};
use kemlock_domain::sends::{SendId, SendRecord};
use kemlock_domain::{BlobId, SpaceId, UserId};
use std::collections::{BTreeMap, HashMap};
use std::sync::{Arc, Mutex, MutexGuard};
use time::OffsetDateTime;

// ---------------------------------------------------------------------------------------------
// The sends table.

#[derive(Clone, Default)]
pub(crate) struct FakeSends {
    rows: Arc<Mutex<HashMap<SendId, SendRecord>>>,
    /// The key version of the owners' accounts, which a wrap made for another is refused under;
    /// `None` checks nothing.
    key_version: Arc<Mutex<Option<u32>>>,
}

impl FakeSends {
    pub(crate) fn new() -> Self {
        Self::default()
    }

    fn lock(&self) -> MutexGuard<'_, HashMap<SendId, SendRecord>> {
        self.rows.lock().expect("the sends lock isn't poisoned")
    }

    pub(crate) fn get(&self, id: SendId) -> Option<SendRecord> {
        self.lock().get(&id).cloned()
    }

    /// Says which key version the owners' accounts are at, as the real store reads from the
    /// account row.
    pub(crate) fn set_account_key_version(&self, version: u32) {
        *self.key_version.lock().expect("the lock isn't poisoned") = Some(version);
    }

    fn check_key_version(&self, key_version: Option<u32>) -> Result<(), StoreError> {
        let current = *self.key_version.lock().expect("the lock isn't poisoned");
        match (current, key_version) {
            (Some(current), Some(asked)) if current != 0 && current != asked => {
                Err(StoreError::StaleKeyVersion { current })
            }
            _ => Ok(()),
        }
    }

    pub(crate) fn count(&self) -> usize {
        self.lock().len()
    }

    /// Puts a row in as it is, for tests that need one in a given state.
    pub(crate) fn insert(&self, send: SendRecord) {
        self.lock().insert(send.id, send);
    }
}

impl SendRepo for FakeSends {
    async fn add_send(&self, send: &SendRecord) -> Result<(), StoreError> {
        let mut rows = self.lock();
        if rows.contains_key(&send.id) {
            return Err(StoreError::Duplicate);
        }
        rows.insert(send.id, send.clone());
        Ok(())
    }

    async fn add_send_within_quota_at(
        &self,
        send: &SendRecord,
        quota: Option<u64>,
        key_version: Option<u32>,
    ) -> Result<Result<(), QuotaRefusal>, StoreError> {
        self.check_key_version(key_version)?;
        self.add_send_within_quota(send, quota).await
    }

    async fn update_send_at(
        &self,
        send: &SendRecord,
        key_version: Option<u32>,
    ) -> Result<(), StoreError> {
        self.check_key_version(key_version)?;
        self.update_send(send).await
    }

    async fn send_by_id(&self, id: SendId) -> Result<Option<SendRecord>, StoreError> {
        Ok(self.get(id))
    }

    async fn sends_of(&self, owner: UserId) -> Result<Vec<SendRecord>, StoreError> {
        let mut found: Vec<SendRecord> = self
            .lock()
            .values()
            .filter(|s| s.owner == owner)
            .cloned()
            .collect();
        found.sort_by(|a, b| b.created_at.cmp(&a.created_at).then(a.id.cmp(&b.id)));
        Ok(found)
    }

    async fn update_send(&self, send: &SendRecord) -> Result<(), StoreError> {
        let mut rows = self.lock();
        let row = rows.get_mut(&send.id).ok_or(StoreError::NotFound)?;
        row.meta = send.meta.clone();
        row.payload = send.payload.clone();
        row.password = send.password.clone();
        row.max_access = send.max_access;
        row.hide_email = send.hide_email;
        row.disabled = send.disabled;
        row.expires_at = send.expires_at;
        row.deletion_at = send.deletion_at;
        row.revised_at = send.revised_at;
        Ok(())
    }

    async fn mark_send_file_ready(&self, id: SendId) -> Result<bool, StoreError> {
        let mut rows = self.lock();
        match rows.get_mut(&id).and_then(|s| s.file.as_mut()) {
            Some(file) if !file.ready => {
                file.ready = true;
                Ok(true)
            }
            _ => Ok(false),
        }
    }

    async fn count_send_view(&self, id: SendId, at: OffsetDateTime) -> Result<bool, StoreError> {
        let mut rows = self.lock();
        match rows.get_mut(&id) {
            Some(send) if !send.is_exhausted() => {
                send.access_count += 1;
                send.revised_at = at;
                Ok(true)
            }
            _ => Ok(false),
        }
    }

    async fn remove_send(&self, id: SendId) -> Result<(), StoreError> {
        self.lock().remove(&id);
        Ok(())
    }

    async fn sends_to_delete(
        &self,
        now: OffsetDateTime,
        abandoned_before: OffsetDateTime,
        limit: u32,
    ) -> Result<Vec<SendRecord>, StoreError> {
        let mut found: Vec<SendRecord> = self
            .lock()
            .values()
            .filter(|s| {
                s.deletion_at <= now
                    || (s.file.is_some_and(|f| !f.ready) && s.created_at < abandoned_before)
            })
            .cloned()
            .collect();
        found.sort_by_key(|s| s.created_at);
        found.truncate(limit as usize);
        Ok(found)
    }
}

// ---------------------------------------------------------------------------------------------
// Blob storage.

#[derive(Default)]
struct BlobsInner {
    blobs: HashMap<BlobId, Vec<u8>>,
    fail_deletes: bool,
}

#[derive(Clone, Default)]
pub(crate) struct FakeSendBlobs {
    inner: Arc<Mutex<BlobsInner>>,
}

impl FakeSendBlobs {
    pub(crate) fn new() -> Self {
        Self::default()
    }

    fn lock(&self) -> MutexGuard<'_, BlobsInner> {
        self.inner.lock().expect("the blob lock isn't poisoned")
    }

    pub(crate) fn get(&self, blob: BlobId) -> Option<Vec<u8>> {
        self.lock().blobs.get(&blob).cloned()
    }

    pub(crate) fn count(&self) -> usize {
        self.lock().blobs.len()
    }

    pub(crate) fn put(&self, blob: BlobId, bytes: Vec<u8>) {
        self.lock().blobs.insert(blob, bytes);
    }

    pub(crate) fn fail_deletes(&self) {
        self.lock().fail_deletes = true;
    }
}

pub(crate) struct FakeSendUpload {
    blobs: FakeSendBlobs,
    blob: BlobId,
    max: u64,
    kma1: bool,
    buffer: Vec<u8>,
}

fn check_magic(bytes: &[u8]) -> Result<(), BlobError> {
    let seen = bytes.len().min(4);
    if bytes[..seen] == b"KMA1"[..seen] {
        Ok(())
    } else {
        Err(BlobError::NotKma1("doesn't start with KMA1"))
    }
}

impl BlobUpload for FakeSendUpload {
    async fn write(&mut self, chunk: Bytes) -> Result<(), BlobError> {
        if self.buffer.len() as u64 + chunk.len() as u64 > self.max {
            return Err(BlobError::TooLarge);
        }
        self.buffer.extend_from_slice(&chunk);
        if self.kma1 {
            check_magic(&self.buffer)?;
        }
        Ok(())
    }

    async fn finish(self) -> Result<u64, BlobError> {
        let size = self.buffer.len() as u64;
        self.blobs.lock().blobs.insert(self.blob, self.buffer);
        Ok(size)
    }

    async fn abort(self) {}
}

impl BlobStore for FakeSendBlobs {
    type Upload = FakeSendUpload;

    async fn begin(&self, blob: BlobId, max_size: u64) -> Result<FakeSendUpload, BlobError> {
        Ok(FakeSendUpload {
            blobs: self.clone(),
            blob,
            max: max_size,
            kma1: true,
            buffer: Vec::new(),
        })
    }

    async fn open(&self, blob: BlobId) -> Result<BlobRead, BlobError> {
        let bytes = self.get(blob).ok_or(BlobError::NotFound)?;
        let size = bytes.len() as u64;
        let pieces: Vec<Result<Bytes, BlobError>> = bytes
            .chunks(7)
            .map(|piece| Ok(Bytes::copy_from_slice(piece)))
            .collect();
        Ok(BlobRead {
            size,
            body: futures_util::stream::iter(pieces).boxed(),
        })
    }

    async fn verify(&self, blob: BlobId, expected: u64) -> Result<(), BlobError> {
        let bytes = self.get(blob).ok_or(BlobError::NotFound)?;
        if bytes.len() as u64 != expected {
            return Err(BlobError::WrongSize);
        }
        check_magic(&bytes)
    }

    async fn delete(&self, blob: BlobId) -> Result<(), BlobError> {
        let mut inner = self.lock();
        if inner.fail_deletes {
            return Err(BlobError::Backend("the disk is full of tears".to_owned()));
        }
        inner.blobs.remove(&blob);
        Ok(())
    }

    async fn presigned_upload(&self, _blob: BlobId) -> Result<Option<PresignedUrl>, BlobError> {
        Ok(None)
    }

    async fn presigned_download(&self, _blob: BlobId) -> Result<Option<PresignedUrl>, BlobError> {
        Ok(None)
    }
}

impl SendBlobs for FakeSendBlobs {
    async fn begin_raw(&self, blob: BlobId, max_size: u64) -> Result<FakeSendUpload, BlobError> {
        Ok(FakeSendUpload {
            blobs: self.clone(),
            blob,
            max: max_size,
            kma1: false,
            buffer: Vec::new(),
        })
    }
}

// ---------------------------------------------------------------------------------------------
// Policies.

#[derive(Clone, Default)]
pub(crate) struct FakePolicies {
    rows: Arc<Mutex<BTreeMap<SpaceId, StoredPolicies>>>,
}

impl FakePolicies {
    pub(crate) fn new() -> Self {
        Self::default()
    }

    fn lock(&self) -> MutexGuard<'_, BTreeMap<SpaceId, StoredPolicies>> {
        self.rows.lock().expect("the policies lock isn't poisoned")
    }

    /// Sets a space's policies, as an admin would have.
    pub(crate) fn set(&self, space: SpaceId, policies: SpacePolicies) {
        self.lock().insert(
            space,
            StoredPolicies {
                policies,
                updated_at: None,
                updated_by: None,
            },
        );
    }

    pub(crate) fn stored(&self, space: SpaceId) -> Option<StoredPolicies> {
        self.lock().get(&space).cloned()
    }
}

impl PolicyRepo for FakePolicies {
    async fn space_policies(&self, space: SpaceId) -> Result<StoredPolicies, StoreError> {
        Ok(self.stored(space).unwrap_or_default())
    }

    async fn put_space_policies(
        &self,
        space: SpaceId,
        policies: &SpacePolicies,
        by: UserId,
        at: OffsetDateTime,
    ) -> Result<(), StoreError> {
        self.lock().insert(
            space,
            StoredPolicies {
                policies: policies.clone(),
                updated_at: Some(at),
                updated_by: Some(by),
            },
        );
        Ok(())
    }

    async fn policies_of_spaces(&self, spaces: &[SpaceId]) -> Result<PoliciesBySpace, StoreError> {
        let rows = self.lock();
        Ok(spaces
            .iter()
            .filter_map(|id| rows.get(id).map(|s| (*id, s.policies.clone())))
            .collect())
    }
}

/// Send rules that a test sets directly.
#[derive(Clone, Default)]
pub(crate) struct FixedRules(Arc<Mutex<SendRules>>);

impl FixedRules {
    pub(crate) fn new() -> Self {
        Self::default()
    }

    pub(crate) fn set(&self, rules: SendRules) {
        *self.0.lock().expect("the rules lock isn't poisoned") = rules;
    }
}

impl SendPolicies for FixedRules {
    async fn send_rules(&self, _user: UserId) -> Result<SendRules, StoreError> {
        Ok(*self.0.lock().expect("the rules lock isn't poisoned"))
    }
}
