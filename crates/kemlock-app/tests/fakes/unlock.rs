//! Fakes for the approval, key-copy and emergency-access ports, kept beside `FakeStore` so one
//! store value serves every repository port.
//!
//! The state lives in `UnlockState`, a field of `FakeStore`; the repository impls are on
//! `FakeStore` itself. The notice senders record what they were asked to send.

use super::{FakeEnv, FakeSeal, FakeStore, FakeTokenSigner, World};
use kemlock_app::devices::{
    AnswerApproval, ApprovalRepo, DeviceNotices, DeviceSignIn, EndSession, KeyCopies, KeyCopyRepo,
    ListApprovals, NewDeviceNotice, PollApproval, PurgeApprovals, RecentRequest, RequestApproval,
    SignOutDevice, UntrustDevice,
};
use kemlock_app::emergency::{
    ApproveDue, EmergencyAccess, EmergencyNotice, EmergencyNotices, EmergencyRepo,
};
use kemlock_app::ports::StoreError;
use kemlock_app::sso::RequireSso;
use kemlock_domain::unlock::{
    ApprovalId, ApprovalState, AuthRequest, DeviceKeyCopy, EmergencyGrant, EmergencyState, GrantId,
};
use kemlock_domain::{DeviceId, Email, UserId};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use time::OffsetDateTime;

#[derive(Default)]
struct UnlockInner {
    requests: HashMap<ApprovalId, AuthRequest>,
    copies: HashMap<DeviceId, DeviceKeyCopy>,
    grants: HashMap<GrantId, EmergencyGrant>,
}

/// The maps behind the three repositories.
#[derive(Clone, Default)]
pub(crate) struct UnlockState(Arc<Mutex<UnlockInner>>);

impl UnlockState {
    fn lock(&self) -> std::sync::MutexGuard<'_, UnlockInner> {
        self.0.lock().expect("the unlock lock isn't poisoned")
    }
}

impl FakeStore {
    pub(crate) fn auth_request(&self, id: ApprovalId) -> Option<AuthRequest> {
        self.unlock.lock().requests.get(&id).cloned()
    }

    pub(crate) fn auth_request_count(&self) -> usize {
        self.unlock.lock().requests.len()
    }

    pub(crate) fn key_copy_of(&self, device: DeviceId) -> Option<DeviceKeyCopy> {
        self.unlock.lock().copies.get(&device).cloned()
    }

    pub(crate) fn grant_of(&self, id: GrantId) -> Option<EmergencyGrant> {
        self.unlock.lock().grants.get(&id).cloned()
    }

    /// Puts a request in as it stands, for tests that need one in a given state.
    pub(crate) fn put_auth_request(&self, request: AuthRequest) {
        self.unlock.lock().requests.insert(request.id, request);
    }
}

impl ApprovalRepo for FakeStore {
    async fn insert_request(&self, request: &AuthRequest) -> Result<(), StoreError> {
        let mut g = self.unlock.lock();
        if g.requests.contains_key(&request.id) {
            return Err(StoreError::Duplicate);
        }
        g.requests.insert(request.id, request.clone());
        Ok(())
    }

    async fn insert_request_within(
        &self,
        request: &AuthRequest,
        since: OffsetDateTime,
        max_recent: usize,
    ) -> Result<bool, StoreError> {
        let mut g = self.unlock.lock();
        let recent = g
            .requests
            .values()
            .filter(|r| r.user == request.user && r.created_at > since)
            .count();
        if recent >= max_recent {
            return Ok(false);
        }
        if g.requests.contains_key(&request.id) {
            return Err(StoreError::Duplicate);
        }
        g.requests.insert(request.id, request.clone());
        Ok(true)
    }

    async fn request(&self, id: ApprovalId) -> Result<Option<AuthRequest>, StoreError> {
        Ok(self.unlock.lock().requests.get(&id).cloned())
    }

    async fn pending_requests(
        &self,
        user: UserId,
        now: OffsetDateTime,
    ) -> Result<Vec<AuthRequest>, StoreError> {
        let mut found: Vec<AuthRequest> = self
            .unlock
            .lock()
            .requests
            .values()
            .filter(|r| r.user == user && r.is_open(now))
            .cloned()
            .collect();
        found.sort_by_key(|r| std::cmp::Reverse(r.created_at));
        Ok(found)
    }

    async fn save_request(
        &self,
        request: &AuthRequest,
        from: ApprovalState,
    ) -> Result<bool, StoreError> {
        let mut g = self.unlock.lock();
        match g.requests.get_mut(&request.id) {
            Some(stored) if stored.state == from => {
                *stored = request.clone();
                Ok(true)
            }
            _ => Ok(false),
        }
    }

    async fn requests_since(
        &self,
        user: UserId,
        since: OffsetDateTime,
    ) -> Result<Vec<RecentRequest>, StoreError> {
        let mut recent: Vec<RecentRequest> = self
            .unlock
            .lock()
            .requests
            .values()
            .filter(|r| r.user == user && r.created_at > since)
            .map(|r| RecentRequest {
                created_at: r.created_at,
                ip: r.ip.clone(),
                state: r.state,
            })
            .collect();
        recent.sort_by_key(|r| r.created_at);
        Ok(recent)
    }

    async fn purge_requests(&self, before: OffsetDateTime) -> Result<u64, StoreError> {
        let mut g = self.unlock.lock();
        let count = g.requests.len();
        g.requests.retain(|_, r| r.expires_at >= before);
        Ok((count - g.requests.len()) as u64)
    }
}

impl FakeStore {
    /// What the real stores do under the account's lock: refuse a wrap made for a key version the
    /// account no longer has (an account at version 0 accepts any).
    fn check_key_version(&self, user: UserId, key_version: Option<u32>) -> Result<(), StoreError> {
        let Some(key_version) = key_version else {
            return Ok(());
        };
        match self.lock().users.get(&user) {
            Some(account) if account.key_version != 0 && account.key_version != key_version => {
                Err(StoreError::StaleKeyVersion {
                    current: account.key_version,
                })
            }
            _ => Ok(()),
        }
    }
}

impl KeyCopyRepo for FakeStore {
    async fn key_copy(&self, device: DeviceId) -> Result<Option<DeviceKeyCopy>, StoreError> {
        Ok(self.unlock.lock().copies.get(&device).cloned())
    }

    async fn put_key_copy(&self, copy: &DeviceKeyCopy) -> Result<(), StoreError> {
        if !self.lock().devices.contains_key(&copy.device) {
            return Err(StoreError::NotFound);
        }
        self.unlock.lock().copies.insert(copy.device, copy.clone());
        Ok(())
    }

    async fn put_key_copy_at(
        &self,
        copy: &DeviceKeyCopy,
        key_version: Option<u32>,
    ) -> Result<(), StoreError> {
        let owner = self
            .lock()
            .devices
            .get(&copy.device)
            .map(|device| device.user);
        if let Some(owner) = owner {
            self.check_key_version(owner, key_version)?;
        }
        self.put_key_copy(copy).await
    }

    async fn remove_key_copy(&self, device: DeviceId) -> Result<(), StoreError> {
        self.unlock.lock().copies.remove(&device);
        Ok(())
    }
}

impl EmergencyRepo for FakeStore {
    async fn insert_grant(&self, grant: &EmergencyGrant) -> Result<(), StoreError> {
        let mut g = self.unlock.lock();
        if g.grants.contains_key(&grant.id)
            || g.grants
                .values()
                .any(|o| o.grantor == grant.grantor && o.grantee_email == grant.grantee_email)
        {
            return Err(StoreError::Duplicate);
        }
        g.grants.insert(grant.id, grant.clone());
        Ok(())
    }

    async fn grant(&self, id: GrantId) -> Result<Option<EmergencyGrant>, StoreError> {
        Ok(self.unlock.lock().grants.get(&id).cloned())
    }

    async fn grants_of_grantor(&self, grantor: UserId) -> Result<Vec<EmergencyGrant>, StoreError> {
        let mut found: Vec<EmergencyGrant> = self
            .unlock
            .lock()
            .grants
            .values()
            .filter(|g| g.grantor == grantor)
            .cloned()
            .collect();
        found.sort_by_key(|g| g.created_at);
        Ok(found)
    }

    async fn grants_for_email(&self, email: &Email) -> Result<Vec<EmergencyGrant>, StoreError> {
        let mut found: Vec<EmergencyGrant> = self
            .unlock
            .lock()
            .grants
            .values()
            .filter(|g| g.grantee_email == *email)
            .cloned()
            .collect();
        found.sort_by_key(|g| g.created_at);
        Ok(found)
    }

    async fn save_grant(
        &self,
        grant: &EmergencyGrant,
        from: EmergencyState,
    ) -> Result<bool, StoreError> {
        let mut g = self.unlock.lock();
        match g.grants.get_mut(&grant.id) {
            Some(stored) if stored.state == from => {
                *stored = grant.clone();
                Ok(true)
            }
            _ => Ok(false),
        }
    }

    async fn save_grant_at(
        &self,
        grant: &EmergencyGrant,
        from: EmergencyState,
        version: Option<OffsetDateTime>,
        key_version: Option<u32>,
    ) -> Result<bool, StoreError> {
        self.check_key_version(grant.grantor, key_version)?;
        let mut g = self.unlock.lock();
        match g.grants.get_mut(&grant.id) {
            Some(stored)
                if stored.state == from
                    && version.is_none_or(|version| stored.updated_at == version) =>
            {
                *stored = grant.clone();
                Ok(true)
            }
            _ => Ok(false),
        }
    }

    async fn recovering_grants(&self) -> Result<Vec<EmergencyGrant>, StoreError> {
        Ok(self
            .unlock
            .lock()
            .grants
            .values()
            .filter(|g| g.state == EmergencyState::RecoveryInitiated)
            .cloned()
            .collect())
    }

    async fn remove_grant(&self, id: GrantId) -> Result<(), StoreError> {
        self.unlock.lock().grants.remove(&id);
        Ok(())
    }
}

/// Records the notices it is asked to send.
#[derive(Clone, Default)]
pub(crate) struct FakeNotices {
    devices: Arc<Mutex<Vec<NewDeviceNotice>>>,
    emergency: Arc<Mutex<Vec<EmergencyNotice>>>,
}

impl FakeNotices {
    pub(crate) fn new_devices(&self) -> Vec<NewDeviceNotice> {
        self.devices
            .lock()
            .expect("the notices lock isn't poisoned")
            .clone()
    }

    pub(crate) fn emergency(&self) -> Vec<EmergencyNotice> {
        self.emergency
            .lock()
            .expect("the notices lock isn't poisoned")
            .clone()
    }
}

impl DeviceNotices for FakeNotices {
    async fn new_device(&self, notice: NewDeviceNotice) {
        self.devices
            .lock()
            .expect("the notices lock isn't poisoned")
            .push(notice);
    }
}

impl EmergencyNotices for FakeNotices {
    async fn notify(&self, notice: EmergencyNotice) {
        self.emergency
            .lock()
            .expect("the notices lock isn't poisoned")
            .push(notice);
    }
}

// ---------------------------------------------------------------------------------------------
// The wiring, as free functions over a `World`.

pub(crate) fn request_approval(
    world: &World,
    notices: &FakeNotices,
) -> RequestApproval<FakeStore, FakeStore, FakeNotices, FakeEnv> {
    RequestApproval {
        users: world.store.clone(),
        approvals: world.store.clone(),
        notices: notices.clone(),
        env: world.env.clone(),
    }
}

pub(crate) fn list_approvals(world: &World) -> ListApprovals<FakeStore, FakeEnv> {
    ListApprovals {
        approvals: world.store.clone(),
        env: world.env.clone(),
    }
}

pub(crate) fn answer_approval(world: &World) -> AnswerApproval<FakeStore, FakeEnv, FakeStore> {
    AnswerApproval {
        approvals: world.store.clone(),
        env: world.env.clone(),
        events: world.store.clone(),
    }
}

pub(crate) fn poll_approval(world: &World) -> PollApproval<FakeStore, FakeEnv> {
    PollApproval {
        approvals: world.store.clone(),
        env: world.env.clone(),
    }
}

pub(crate) fn purge_approvals(world: &World) -> PurgeApprovals<FakeStore, FakeEnv> {
    PurgeApprovals {
        approvals: world.store.clone(),
        env: world.env.clone(),
    }
}

pub(crate) type FakeDeviceSignIn = DeviceSignIn<
    FakeStore,
    FakeStore,
    FakeSeal,
    FakeStore,
    FakeStore,
    FakeTokenSigner,
    FakeEnv,
    FakeStore,
    FakeStore,
    FakeStore,
>;

pub(crate) fn device_sign_in(world: &World) -> FakeDeviceSignIn {
    DeviceSignIn {
        users: world.store.clone(),
        approvals: world.store.clone(),
        seal: world.seal.clone(),
        sessions: world.sessions(),
        sso: RequireSso {
            membership: world.store.clone(),
        },
    }
}

pub(crate) fn key_copies(world: &World) -> KeyCopies<FakeStore, FakeStore, FakeEnv> {
    KeyCopies {
        devices: world.store.clone(),
        copies: world.store.clone(),
        clock: world.env.clone(),
    }
}

pub(crate) fn sign_out_device(
    world: &World,
) -> SignOutDevice<FakeStore, FakeStore, FakeStore, FakeEnv, FakeStore> {
    SignOutDevice {
        devices: world.store.clone(),
        copies: world.store.clone(),
        tokens: world.store.clone(),
        clock: world.env.clone(),
        events: world.store.clone(),
    }
}

pub(crate) fn end_session(world: &World) -> EndSession<FakeStore, FakeStore, FakeEnv, FakeStore> {
    EndSession {
        devices: world.store.clone(),
        tokens: world.store.clone(),
        clock: world.env.clone(),
        events: world.store.clone(),
    }
}

pub(crate) fn untrust_device(
    world: &World,
) -> UntrustDevice<FakeStore, FakeStore, FakeEnv, FakeStore> {
    UntrustDevice {
        devices: world.store.clone(),
        copies: world.store.clone(),
        clock: world.env.clone(),
        events: world.store.clone(),
    }
}

pub(crate) fn emergency_access(
    world: &World,
    notices: &FakeNotices,
) -> EmergencyAccess<FakeStore, FakeStore, FakeNotices, FakeEnv, FakeStore> {
    EmergencyAccess {
        users: world.store.clone(),
        grants: world.store.clone(),
        notices: notices.clone(),
        env: world.env.clone(),
        events: world.store.clone(),
    }
}

pub(crate) fn approve_due(
    world: &World,
    notices: &FakeNotices,
) -> ApproveDue<FakeStore, FakeStore, FakeNotices, FakeEnv, FakeStore> {
    ApproveDue {
        users: world.store.clone(),
        grants: world.store.clone(),
        notices: notices.clone(),
        env: world.env.clone(),
        events: world.store.clone(),
    }
}
