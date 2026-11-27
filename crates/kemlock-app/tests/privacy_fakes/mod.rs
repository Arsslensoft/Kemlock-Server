//! In-memory fakes of the privacy ports, over the shared `FakeStore` for users, devices and items.
//! A test file includes this with `mod privacy_fakes;` beside `mod fakes;`.
#![allow(dead_code, unused_imports)]

use crate::fakes::FakeStore;
use kemlock_app::ports::{DeviceRepo, Event, ItemStore, StoreError};
use kemlock_app::privacy::{
    AccountData, AccountEraser, ErasedRows, ErasureFiles, NewSignIn, PrivacyLog, PrivacySettings,
    ProcessingInputs, ProcessingSource, PurgedTrash, RetentionStore, SendEraser, TwoFactorInfo,
};
use kemlock_domain::privacy::{Retention, SignInEntry, StoredEvent, truncate_ip};
use kemlock_domain::spaces::Member;
use kemlock_domain::{BlobId, Device, Item, Owner, SpaceId, User, UserId, VersionVector};
use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::{Arc, Mutex};
use time::OffsetDateTime;
use uuid::Uuid;

// ---------------------------------------------------------------------------------------------
// Fakes for the privacy ports. Users, devices and items are the shared `FakeStore`'s.

#[derive(Default)]
pub(crate) struct Inner {
    pub(crate) retention: Retention,
    pub(crate) events: Vec<StoredEvent>,
    pub(crate) sign_ins: Vec<SignInEntry>,
    pub(crate) memberships: Vec<Member>,
    pub(crate) two_factor: Vec<TwoFactorInfo>,
    pub(crate) blocking: Vec<SpaceId>,
    pub(crate) erased: Vec<UserId>,
    pub(crate) scheduled: HashMap<UserId, OffsetDateTime>,
    pub(crate) canned: ErasedRows,
    /// The store refuses the erasure because the account is the last admin.
    pub(crate) last_admin: bool,
    pub(crate) deleted_blobs: Vec<BlobId>,
    pub(crate) deleted_cipher_files: Vec<String>,
    pub(crate) fail_files: bool,
    /// Each retention call and the cutoff it was given.
    pub(crate) calls: Vec<(&'static str, OffsetDateTime)>,
    pub(crate) trash: Vec<PurgedTrash>,
    pub(crate) inputs: ProcessingInputs,
}

#[derive(Clone)]
pub(crate) struct FakePrivacy {
    pub(crate) inner: Arc<Mutex<Inner>>,
    pub(crate) store: FakeStore,
}

impl FakePrivacy {
    pub(crate) fn new(store: &FakeStore) -> Self {
        FakePrivacy {
            inner: Arc::new(Mutex::new(Inner::default())),
            store: store.clone(),
        }
    }

    pub(crate) fn lock(&self) -> std::sync::MutexGuard<'_, Inner> {
        self.inner.lock().expect("the privacy lock isn't poisoned")
    }

    pub(crate) fn events(&self) -> Vec<StoredEvent> {
        self.lock().events.clone()
    }

    pub(crate) fn calls(&self) -> Vec<(&'static str, OffsetDateTime)> {
        self.lock().calls.clone()
    }
}

impl AccountData for FakePrivacy {
    async fn devices(&self, user: UserId) -> Result<Vec<Device>, StoreError> {
        DeviceRepo::list(&self.store, user).await
    }

    async fn vault(&self, user: UserId) -> Result<Vec<Item>, StoreError> {
        let owner = [Owner::User(user)];
        let mut cursor = VersionVector::new();
        let mut items = Vec::new();
        loop {
            let page = ItemStore::changes_since(&self.store, &owner, &cursor, 1).await?;
            items.extend(page.items);
            if !page.more {
                return Ok(items);
            }
            cursor = page.next;
        }
    }

    async fn memberships(&self, user: UserId) -> Result<Vec<Member>, StoreError> {
        Ok(self
            .lock()
            .memberships
            .iter()
            .filter(|m| m.user == user)
            .cloned()
            .collect())
    }

    async fn two_factor(&self, _user: UserId) -> Result<Vec<TwoFactorInfo>, StoreError> {
        Ok(self.lock().two_factor.clone())
    }
}

impl PrivacyLog for FakePrivacy {
    async fn record_event(&self, event: Event, ip: Option<IpAddr>) -> Result<(), StoreError> {
        self.lock().events.push(StoredEvent {
            id: Uuid::new_v4(),
            actor: event.actor,
            device: event.device,
            action: event.action.to_owned(),
            target: event.target,
            at: event.at,
            ip: ip.map(truncate_ip),
        });
        Ok(())
    }

    async fn record_sign_in(&self, entry: NewSignIn) -> Result<(), StoreError> {
        self.lock().sign_ins.push(SignInEntry {
            id: Uuid::new_v4(),
            user: entry.user,
            device: entry.device,
            method: entry.method.to_owned(),
            outcome: entry.outcome,
            at: entry.at,
            ip: entry.ip.map(truncate_ip),
        });
        Ok(())
    }

    async fn events_of(&self, user: UserId) -> Result<Vec<StoredEvent>, StoreError> {
        Ok(self
            .lock()
            .events
            .iter()
            .filter(|e| e.actor == Some(user))
            .cloned()
            .collect())
    }

    async fn sign_ins_of(&self, user: UserId) -> Result<Vec<SignInEntry>, StoreError> {
        Ok(self
            .lock()
            .sign_ins
            .iter()
            .filter(|s| s.user == Some(user))
            .cloned()
            .collect())
    }

    async fn events_between(
        &self,
        from: OffsetDateTime,
        to: OffsetDateTime,
    ) -> Result<Vec<StoredEvent>, StoreError> {
        Ok(self
            .lock()
            .events
            .iter()
            .filter(|e| e.at >= from && e.at < to)
            .cloned()
            .collect())
    }

    async fn sign_ins_between(
        &self,
        from: OffsetDateTime,
        to: OffsetDateTime,
    ) -> Result<Vec<SignInEntry>, StoreError> {
        Ok(self
            .lock()
            .sign_ins
            .iter()
            .filter(|s| s.at >= from && s.at < to)
            .cloned()
            .collect())
    }
}

impl PrivacySettings for FakePrivacy {
    async fn retention(&self) -> Result<Retention, StoreError> {
        Ok(self.lock().retention)
    }

    async fn save_retention(&self, retention: &Retention) -> Result<(), StoreError> {
        self.lock().retention = *retention;
        Ok(())
    }
}

impl AccountEraser for FakePrivacy {
    async fn blocking_spaces(&self, _user: UserId) -> Result<Vec<SpaceId>, StoreError> {
        Ok(self.lock().blocking.clone())
    }

    async fn erase_user(&self, user: &User) -> Result<ErasedRows, StoreError> {
        let mut g = self.lock();
        if g.last_admin {
            return Err(StoreError::Backend(
                kemlock_app::privacy::LAST_ADMIN.to_owned(),
            ));
        }
        g.erased.push(user.id);
        Ok(g.canned.clone())
    }

    async fn schedule_erasure(
        &self,
        user: UserId,
        _requested_at: OffsetDateTime,
        due: OffsetDateTime,
    ) -> Result<(), StoreError> {
        self.lock().scheduled.insert(user, due);
        Ok(())
    }

    async fn scheduled_erasure(&self, user: UserId) -> Result<Option<OffsetDateTime>, StoreError> {
        Ok(self.lock().scheduled.get(&user).copied())
    }

    async fn cancel_erasure(&self, user: UserId) -> Result<(), StoreError> {
        self.lock().scheduled.remove(&user);
        Ok(())
    }

    async fn due_erasures(&self, now: OffsetDateTime) -> Result<Vec<UserId>, StoreError> {
        Ok(self
            .lock()
            .scheduled
            .iter()
            .filter(|(_, due)| **due <= now)
            .map(|(user, _)| *user)
            .collect())
    }
}

impl ErasureFiles for FakePrivacy {
    async fn delete_blob(&self, blob: BlobId) -> Result<(), StoreError> {
        let mut g = self.lock();
        if g.fail_files {
            return Err(StoreError::Backend("disk on fire".to_owned()));
        }
        g.deleted_blobs.push(blob);
        Ok(())
    }

    async fn delete_cipher_file(&self, key: &str) -> Result<(), StoreError> {
        let mut g = self.lock();
        if g.fail_files {
            return Err(StoreError::Backend("disk on fire".to_owned()));
        }
        g.deleted_cipher_files.push(key.to_owned());
        Ok(())
    }
}

impl RetentionStore for FakePrivacy {
    async fn purge_events(&self, before: OffsetDateTime) -> Result<u64, StoreError> {
        self.lock().calls.push(("events", before));
        Ok(3)
    }

    async fn purge_sign_ins(&self, before: OffsetDateTime) -> Result<u64, StoreError> {
        self.lock().calls.push(("sign_ins", before));
        Ok(2)
    }

    async fn drop_full_ips(&self, before: OffsetDateTime) -> Result<u64, StoreError> {
        self.lock().calls.push(("full_ips", before));
        Ok(1)
    }

    async fn purge_trash(
        &self,
        before: OffsetDateTime,
        _now: OffsetDateTime,
    ) -> Result<Vec<PurgedTrash>, StoreError> {
        let mut g = self.lock();
        g.calls.push(("trash", before));
        Ok(g.trash.clone())
    }

    async fn purge_email_log(&self, before: OffsetDateTime) -> Result<u64, StoreError> {
        self.lock().calls.push(("email_log", before));
        Ok(5)
    }

    async fn purge_held_signups(&self, before: OffsetDateTime) -> Result<u64, StoreError> {
        self.lock().calls.push(("held_signups", before));
        Ok(2)
    }
}

impl ProcessingSource for FakePrivacy {
    async fn inputs(&self) -> Result<ProcessingInputs, StoreError> {
        Ok(self.lock().inputs.clone())
    }
}

#[derive(Clone, Default)]
pub(crate) struct FakeSends(pub(crate) Arc<Mutex<Vec<UserId>>>);

impl SendEraser for FakeSends {
    async fn erase_sends(&self, user: UserId) -> Result<u64, StoreError> {
        self.0.lock().expect("the sends lock").push(user);
        Ok(2)
    }
}
