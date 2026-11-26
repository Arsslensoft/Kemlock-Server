//! In-memory fakes for every port, and a `World` that wires use cases to them.
//!
//! The fakes for sealing, hashing, TOTP and OPAQUE wrap the real `kemlock-crypto` functions, so
//! the tests run real OPAQUE registrations and logins with the crate's client functions. The rest
//! are plain maps. Each integration test file includes this module with `mod fakes;`.
#![allow(dead_code, unused_imports)]

use kemlock_app::ports::{
    AccessClaims, ChangePage, Clock, CryptoError, DeviceRepo, EmailConfirmation, Event, EventLog,
    ItemStore, Notifier, PasswordAuth, Random, RefreshToken, SecretSeal, ServerInfo, StoreError,
    TokenRepo, TokenSigner, Totp, TwoFactor, TwoFactorMethod, TwoFactorRepo, UserRepo, Zeroizing,
};
use kemlock_app::privacy::{NewSignIn, PrivacyLog};
use kemlock_app::register::{
    BUNDLE_LEN, BUNDLE_PREFIX, BUNDLE_SIGNATURE_LEN, FIRST_KEY_VERSION, WRAPPED_ROOT_KEY_LEN,
};
use kemlock_app::spaces::{KeyReplacement, SpaceChanges, SpaceItemInfo, SpaceRepo};
use kemlock_app::sso::{
    MembershipFacts, RequireSso, SpaceMembership, SsoSettings, SsoSettingsRepo, VerifiedDomain,
    VerifiedDomainRepo,
};
use kemlock_app::two_step::RecoveryCodeRepo;
use kemlock_app::{
    Actor, AuthConfig, Authenticate, ConfirmTotp, DeviceInfo, EnrolTotp, FinishSetup, FirstRun,
    Hasher, OpaqueFinishInput, OpaqueStartInput, Prelogin, PutBatch, PutItem, Refresh, Register,
    RegisterInput, RegisterStartInput, Registered, Sessions, SetupState, SignIn, SignedIn,
    SyncDelta,
};
use kemlock_crypto::opaque::OpaqueServer;
use kemlock_crypto::seal::ServerSeal;
use kemlock_domain::privacy::{SignInEntry, StoredEvent, truncate_ip};
use kemlock_domain::spaces::{CollectionId, GroupId, KeyCopy, Member, Space, SpaceState};
use kemlock_domain::{
    ChangeId, Device, DeviceId, DeviceKind, Hlc, Item, ItemDraft, ItemId, KdfParams, Owner,
    ServerId, SpaceId, User, UserId, VersionVector,
};
use std::collections::{HashMap, HashSet};
use std::net::IpAddr;
use std::sync::{Arc, Mutex, MutexGuard};
use time::macros::datetime;
use time::{Duration, OffsetDateTime};
use uuid::Uuid;

pub(crate) mod contract;
pub(crate) mod dedup;
pub(crate) mod profile;
pub(crate) mod unlock;

// ---------------------------------------------------------------------------------------------
// Store: every repository port over one set of maps.

#[derive(Default)]
struct StoreInner {
    users: HashMap<UserId, User>,
    devices: HashMap<DeviceId, Device>,
    tokens: HashMap<[u8; 32], RefreshToken>,
    /// Families that were revoked: a token of one is dead whatever rows it has.
    revoked: HashSet<Uuid>,
    /// The account the first-admin marker names.
    first_admin: Option<UserId>,
    two_factor: Vec<TwoFactor>,
    /// The newest TOTP step accepted per user.
    totp_steps: HashMap<UserId, u64>,
    items: HashMap<ItemId, Item>,
    events: Vec<Event>,
    /// The address each event was written with, in step with `events`.
    event_ips: Vec<Option<IpAddr>>,
    /// The sign-in log, addresses truncated as the real store keeps them.
    sign_ins: Vec<SignInEntry>,
    seq: u64,
    hlc: Hlc,
    /// The tombstone horizon of each owner.
    purged: HashMap<Owner, VersionVector>,
    /// The spaces each account is a member of, as the Require SSO policy sees them.
    memberships: HashMap<UserId, Vec<SpaceMembership>>,
    sso_settings: Option<SsoSettings>,
    domains: HashMap<String, VerifiedDomain>,
    /// The sealed recovery code of each account, and the legacy one an import left.
    recovery: HashMap<UserId, Vec<u8>>,
    legacy_recovery: HashMap<UserId, Vec<u8>>,
    /// The accounts that may not sign in.
    disabled: HashSet<UserId>,
    /// The accounts whose deletion is pending (the grace period), with when it is due.
    erasing: HashMap<UserId, OffsetDateTime>,
    /// The second-step attempts each account has reserved.
    second_step: HashMap<UserId, kemlock_app::second_step_guard::Attempts>,
    /// The accounts held back until the link mailed to their address is opened: the SHA-256 of the
    /// link's token, when it was made and when it runs out.
    unconfirmed: HashMap<UserId, ([u8; 32], OffsetDateTime, OffsetDateTime)>,
    /// The `settings` table.
    settings: std::collections::BTreeMap<String, String>,
}

#[derive(Clone)]
pub(crate) struct FakeStore {
    inner: Arc<Mutex<StoreInner>>,
    unlock: unlock::UnlockState,
    contract: contract::ContractState,
    dedup: dedup::DedupState,
    server: ServerId,
}

impl FakeStore {
    pub(crate) fn new() -> Self {
        FakeStore {
            inner: Arc::new(Mutex::new(StoreInner::default())),
            unlock: unlock::UnlockState::default(),
            contract: contract::ContractState::default(),
            dedup: dedup::DedupState::default(),
            server: ServerId(Uuid::from_u128(0x5e47e4)),
        }
    }

    fn lock(&self) -> MutexGuard<'_, StoreInner> {
        self.inner.lock().expect("the store lock isn't poisoned")
    }

    pub(crate) fn user(&self, id: UserId) -> Option<User> {
        self.lock().users.get(&id).cloned()
    }

    /// Disables or enables the account: `account_disabled` answers for it.
    pub(crate) fn set_account_disabled(&self, id: UserId, disabled: bool) {
        let mut g = self.lock();
        if disabled {
            g.disabled.insert(id);
        } else {
            g.disabled.remove(&id);
        }
    }

    /// Puts the account's deletion on the schedule, sign-in is refused.
    pub(crate) fn set_erasure_pending(&self, id: UserId, pending: bool) {
        let mut g = self.lock();
        if pending {
            g.erasing.insert(id, datetime!(2030-01-01 0:00 UTC));
        } else {
            g.erasing.remove(&id);
        }
    }

    pub(crate) fn user_by_email(&self, email: &str) -> Option<User> {
        self.lock()
            .users
            .values()
            .find(|u| u.email.as_str() == email)
            .cloned()
    }

    pub(crate) fn put_user(&self, user: User) {
        self.lock().users.insert(user.id, user);
    }

    /// The conditional write of the profile port: the sign-in records of `after` (and its address,
    /// when `address`) go over the account's row only while the row still is as `before` read it,
    /// the same `updated_at` and security stamp. `false` when it is not, `Duplicate` when
    /// another account has the address.
    pub(crate) fn update_credentials_if(
        &self,
        before: &User,
        after: &User,
        address: bool,
    ) -> Result<bool, StoreError> {
        let mut g = self.lock();
        if address
            && g.users
                .values()
                .any(|u| u.id != before.id && u.email == after.email)
        {
            return Err(StoreError::Duplicate);
        }
        let Some(row) = g.users.get_mut(&before.id) else {
            return Ok(false);
        };
        if row.updated_at != before.updated_at || row.security_stamp != before.security_stamp {
            return Ok(false);
        }
        row.opaque_record = after.opaque_record.clone();
        row.kdf = after.kdf.clone();
        row.wrapped_root_key = after.wrapped_root_key.clone();
        row.security_stamp = after.security_stamp;
        row.updated_at = after.updated_at;
        if address {
            row.email = after.email.clone();
        }
        Ok(true)
    }

    /// The name write of the profile port: only the name changes. `false` when there is no such
    /// account.
    pub(crate) fn set_user_name(&self, id: UserId, name: Option<&str>) -> bool {
        match self.lock().users.get_mut(&id) {
            Some(row) => {
                row.name = name.map(str::to_owned);
                true
            }
            None => false,
        }
    }

    /// Another request writes the account: its `updated_at` moves on, as any write of the row does.
    pub(crate) fn touch_user(&self, id: UserId) {
        if let Some(row) = self.lock().users.get_mut(&id) {
            row.updated_at += Duration::seconds(1);
        }
    }

    pub(crate) fn devices_of(&self, user: UserId) -> Vec<Device> {
        self.lock()
            .devices
            .values()
            .filter(|d| d.user == user)
            .cloned()
            .collect()
    }

    /// Leaves a sealed legacy recovery code on the account, as an import from Vaultwarden does.
    pub(crate) fn set_legacy_recovery(&self, user: UserId, sealed: Vec<u8>) {
        self.lock().legacy_recovery.insert(user, sealed);
    }

    pub(crate) fn two_factor_of(&self, user: UserId) -> Vec<TwoFactor> {
        self.lock()
            .two_factor
            .iter()
            .filter(|t| t.user == user)
            .cloned()
            .collect()
    }

    pub(crate) fn refresh_tokens(&self) -> Vec<RefreshToken> {
        self.lock().tokens.values().cloned().collect()
    }

    pub(crate) fn events(&self) -> Vec<Event> {
        self.lock().events.clone()
    }

    /// The sign-in log, oldest first.
    pub(crate) fn sign_ins(&self) -> Vec<SignInEntry> {
        self.lock().sign_ins.clone()
    }

    /// The address each event was written with, truncated, in the order the events were written.
    pub(crate) fn event_ips(&self) -> Vec<Option<String>> {
        self.lock()
            .event_ips
            .iter()
            .map(|ip| ip.map(truncate_ip))
            .collect()
    }

    fn stored_events(&self, keep: impl Fn(&Event) -> bool) -> Vec<StoredEvent> {
        let g = self.lock();
        g.events
            .iter()
            .zip(g.event_ips.iter())
            .filter(|(e, _)| keep(e))
            .map(|(e, ip)| StoredEvent {
                id: Uuid::new_v4(),
                actor: e.actor,
                device: e.device,
                action: e.action.to_owned(),
                target: e.target.clone(),
                at: e.at,
                ip: ip.map(truncate_ip),
            })
            .collect()
    }

    pub(crate) fn item(&self, id: ItemId) -> Option<Item> {
        self.lock().items.get(&id).cloned()
    }

    pub(crate) fn admin_count(&self) -> usize {
        self.lock().users.values().filter(|u| u.is_admin()).count()
    }

    pub(crate) fn set_purged(&self, owner: Owner, purged: VersionVector) {
        self.lock().purged.insert(owner, purged);
    }

    pub(crate) fn server(&self) -> ServerId {
        self.server
    }

    /// Says which spaces `user` belongs to, for the Require SSO check.
    pub(crate) fn set_memberships(&self, user: UserId, spaces: Vec<SpaceMembership>) {
        self.lock().memberships.insert(user, spaces);
    }

    /// Sets the SSO provider up.
    pub(crate) fn set_sso(&self, settings: SsoSettings) {
        self.lock().sso_settings = Some(settings);
    }

    /// Records a domain whose DNS proof is in.
    pub(crate) fn add_verified_domain(&self, domain: &str, at: OffsetDateTime) {
        self.lock().domains.insert(
            domain.to_owned(),
            VerifiedDomain {
                domain: domain.to_owned(),
                token: "already-proven".to_owned(),
                created_at: at,
                verified_at: Some(at),
            },
        );
    }

    fn stored_change(&self, g: &mut StoreInner, now: OffsetDateTime) -> ChangeId {
        g.seq += 1;
        let millis = u64::try_from(now.unix_timestamp_nanos() / 1_000_000).unwrap_or(0);
        g.hlc = g.hlc.tick(millis);
        ChangeId {
            origin: self.server,
            seq: g.seq,
            hlc: g.hlc,
        }
    }

    fn check_draft(g: &StoreInner, draft: &ItemDraft) -> Result<(), StoreError> {
        let current = g.items.get(&draft.id).map(|i| i.revision);
        if current != draft.expected {
            return Err(StoreError::Conflict {
                item: draft.id,
                current,
            });
        }
        Ok(())
    }
}

impl ServerInfo for FakeStore {
    fn server_id(&self) -> ServerId {
        self.server
    }
}

impl UserRepo for FakeStore {
    async fn by_id(&self, id: UserId) -> Result<Option<User>, StoreError> {
        Ok(self.lock().users.get(&id).cloned())
    }

    async fn by_email(&self, email: &kemlock_domain::Email) -> Result<Option<User>, StoreError> {
        Ok(self
            .lock()
            .users
            .values()
            .find(|u| u.email == *email)
            .cloned())
    }

    async fn insert(&self, user: &User) -> Result<(), StoreError> {
        let mut g = self.lock();
        if g.users.contains_key(&user.id) || g.users.values().any(|u| u.email == user.email) {
            return Err(StoreError::Duplicate);
        }
        g.users.insert(user.id, user.clone());
        Ok(())
    }

    async fn update(&self, user: &User) -> Result<(), StoreError> {
        let mut g = self.lock();
        match g.users.get_mut(&user.id) {
            Some(slot) => {
                *slot = user.clone();
                Ok(())
            }
            None => Err(StoreError::NotFound),
        }
    }

    async fn count_admins(&self) -> Result<u64, StoreError> {
        Ok(self.lock().users.values().filter(|u| u.is_admin()).count() as u64)
    }

    async fn account_disabled(&self, id: UserId) -> Result<bool, StoreError> {
        Ok(self.lock().disabled.contains(&id))
    }

    async fn erasure_pending(&self, id: UserId) -> Result<Option<OffsetDateTime>, StoreError> {
        Ok(self.lock().erasing.get(&id).copied())
    }

    async fn email_unconfirmed(&self, id: UserId) -> Result<bool, StoreError> {
        Ok(self.lock().unconfirmed.contains_key(&id))
    }

    async fn hold_unconfirmed(
        &self,
        id: UserId,
        token_hash: [u8; 32],
        requested_at: OffsetDateTime,
        expires_at: OffsetDateTime,
    ) -> Result<(), StoreError> {
        self.lock()
            .unconfirmed
            .insert(id, (token_hash, requested_at, expires_at));
        Ok(())
    }

    async fn confirmation_of(&self, id: UserId) -> Result<Option<EmailConfirmation>, StoreError> {
        Ok(self
            .lock()
            .unconfirmed
            .get(&id)
            .map(|(_, requested_at, expires_at)| EmailConfirmation {
                user: id,
                requested_at: *requested_at,
                expires_at: *expires_at,
            }))
    }

    async fn spend_confirmation(
        &self,
        token_hash: [u8; 32],
        now: OffsetDateTime,
    ) -> Result<Option<UserId>, StoreError> {
        let mut g = self.lock();
        let found = g
            .unconfirmed
            .iter()
            .find(|(_, (hash, _, expires_at))| *hash == token_hash && *expires_at > now)
            .map(|(id, _)| *id);
        if let Some(id) = found {
            g.unconfirmed.remove(&id);
        }
        Ok(found)
    }
}

impl kemlock_app::FirstAdminRepo for FakeStore {
    async fn insert_first_admin(&self, user: &User) -> Result<(), StoreError> {
        let mut g = self.lock();
        if g.first_admin.is_some_and(|id| g.users.contains_key(&id)) {
            return Err(StoreError::Duplicate);
        }
        if g.users.contains_key(&user.id) || g.users.values().any(|u| u.email == user.email) {
            return Err(StoreError::Duplicate);
        }
        g.users.insert(user.id, user.clone());
        g.first_admin = Some(user.id);
        Ok(())
    }

    async fn first_admin(&self) -> Result<Option<UserId>, StoreError> {
        let g = self.lock();
        Ok(g.first_admin.filter(|id| g.users.contains_key(id)))
    }
}

impl DeviceRepo for FakeStore {
    async fn get(&self, id: DeviceId) -> Result<Option<Device>, StoreError> {
        Ok(self.lock().devices.get(&id).cloned())
    }

    async fn upsert(&self, device: &Device) -> Result<(), StoreError> {
        self.lock().devices.insert(device.id, device.clone());
        Ok(())
    }

    async fn list(&self, user: UserId) -> Result<Vec<Device>, StoreError> {
        Ok(self.devices_of(user))
    }

    async fn remove(&self, id: DeviceId) -> Result<(), StoreError> {
        let mut g = self.lock();
        g.devices.remove(&id);
        g.tokens.retain(|_, t| t.device != id);
        Ok(())
    }
}

impl TokenRepo for FakeStore {
    async fn insert(&self, token: &RefreshToken) -> Result<(), StoreError> {
        let mut g = self.lock();
        if g.revoked.contains(&token.family) {
            return Err(StoreError::NotFound);
        }
        g.tokens.insert(token.hash, token.clone());
        Ok(())
    }

    async fn take(
        &self,
        hash: [u8; 32],
        now: OffsetDateTime,
    ) -> Result<Option<RefreshToken>, StoreError> {
        let mut g = self.lock();
        let revoked = g.revoked.clone();
        Ok(g.tokens.get_mut(&hash).map(|t| {
            let before = t.clone();
            if t.used_at.is_none() {
                t.used_at = Some(now);
            }
            if revoked.contains(&before.family) {
                return RefreshToken {
                    used_at: before.used_at.or(Some(now)),
                    ..before
                };
            }
            before
        }))
    }

    async fn revoke_family(&self, family: Uuid) -> Result<(), StoreError> {
        let mut g = self.lock();
        g.revoked.insert(family);
        g.tokens.retain(|_, t| t.family != family);
        Ok(())
    }

    async fn revoke_device(&self, device: DeviceId) -> Result<(), StoreError> {
        self.lock().tokens.retain(|_, t| t.device != device);
        Ok(())
    }

    async fn device_tokens(&self, device: DeviceId) -> Result<Vec<RefreshToken>, StoreError> {
        Ok(self
            .lock()
            .tokens
            .values()
            .filter(|t| t.device == device)
            .cloned()
            .collect())
    }

    async fn restamp_device(&self, device: DeviceId, stamp: Uuid) -> Result<(), StoreError> {
        for token in self.lock().tokens.values_mut() {
            if token.device == device {
                token.security_stamp = stamp;
            }
        }
        Ok(())
    }
}

impl TwoFactorRepo for FakeStore {
    async fn list(&self, user: UserId) -> Result<Vec<TwoFactor>, StoreError> {
        Ok(self.two_factor_of(user))
    }

    async fn put(&self, two_factor: &TwoFactor) -> Result<(), StoreError> {
        let mut g = self.lock();
        g.two_factor
            .retain(|t| !(t.user == two_factor.user && t.method == two_factor.method));
        g.two_factor.push(two_factor.clone());
        Ok(())
    }

    async fn replace_if_sealed(&self, from: &[u8], to: &TwoFactor) -> Result<bool, StoreError> {
        let mut g = self.lock();
        match g
            .two_factor
            .iter_mut()
            .find(|t| t.user == to.user && t.method == to.method && t.sealed_secret == from)
        {
            Some(row) => {
                *row = to.clone();
                Ok(true)
            }
            None => Ok(false),
        }
    }

    async fn remove(&self, user: UserId, method: TwoFactorMethod) -> Result<(), StoreError> {
        let mut g = self.lock();
        g.two_factor
            .retain(|t| !(t.user == user && t.method == method));
        if method == TwoFactorMethod::Totp {
            g.totp_steps.remove(&user);
        }
        Ok(())
    }

    async fn accept_totp_step(&self, user: UserId, step: u64) -> Result<bool, StoreError> {
        let mut g = self.lock();
        let enrolled = g
            .two_factor
            .iter()
            .any(|t| t.user == user && t.method == TwoFactorMethod::Totp);
        if !enrolled || g.totp_steps.get(&user).is_some_and(|last| *last >= step) {
            return Ok(false);
        }
        g.totp_steps.insert(user, step);
        Ok(true)
    }
}

impl RecoveryCodeRepo for FakeStore {
    async fn recovery_code(&self, user: UserId) -> Result<Option<Vec<u8>>, StoreError> {
        Ok(self.lock().recovery.get(&user).cloned())
    }

    async fn legacy_recovery_code(&self, user: UserId) -> Result<Option<Vec<u8>>, StoreError> {
        Ok(self.lock().legacy_recovery.get(&user).cloned())
    }

    async fn put_recovery_code_if_absent(
        &self,
        user: UserId,
        sealed: &[u8],
        _at: OffsetDateTime,
    ) -> Result<bool, StoreError> {
        let mut g = self.lock();
        if g.recovery.contains_key(&user) || g.legacy_recovery.contains_key(&user) {
            return Ok(false);
        }
        g.recovery.insert(user, sealed.to_vec());
        Ok(true)
    }

    async fn remove_recovery_code(&self, user: UserId) -> Result<bool, StoreError> {
        let mut g = self.lock();
        let had_new = g.recovery.remove(&user).is_some();
        let had_legacy = g.legacy_recovery.remove(&user).is_some();
        Ok(had_new || had_legacy)
    }
}

impl ItemStore for FakeStore {
    async fn get(&self, id: ItemId) -> Result<Option<Item>, StoreError> {
        Ok(self.item(id))
    }

    async fn put(&self, draft: ItemDraft) -> Result<Item, StoreError> {
        let mut g = self.lock();
        Self::check_draft(&g, &draft)?;
        let change = self.stored_change(&mut g, draft.updated_at);
        let item = draft.into_item(change);
        g.items.insert(item.id, item.clone());
        self.dedup.clear(item.id);
        Ok(item)
    }

    async fn put_batch(&self, drafts: Vec<ItemDraft>) -> Result<Vec<Item>, StoreError> {
        let mut g = self.lock();
        for draft in &drafts {
            Self::check_draft(&g, draft)?;
        }
        let mut stored = Vec::with_capacity(drafts.len());
        for draft in drafts {
            let change = self.stored_change(&mut g, draft.updated_at);
            let item = draft.into_item(change);
            g.items.insert(item.id, item.clone());
            self.dedup.clear(item.id);
            stored.push(item);
        }
        Ok(stored)
    }

    async fn changes_since(
        &self,
        owners: &[Owner],
        since: &VersionVector,
        limit: u32,
    ) -> Result<ChangePage, StoreError> {
        let g = self.lock();
        let mut matching: Vec<&Item> = g
            .items
            .values()
            .filter(|i| owners.contains(&i.owner) && !since.covers(&i.change))
            .collect();
        matching.sort_by_key(|i| (i.change.origin, i.change.seq));
        let limit = limit as usize;
        let more = matching.len() > limit;
        matching.truncate(limit);
        let mut next = since.clone();
        for item in &matching {
            next.observe(&item.change);
        }
        Ok(ChangePage {
            items: matching.into_iter().cloned().collect(),
            next,
            more,
        })
    }

    async fn latest(&self, owners: &[Owner]) -> Result<VersionVector, StoreError> {
        let g = self.lock();
        let mut latest = VersionVector::new();
        for item in g.items.values().filter(|i| owners.contains(&i.owner)) {
            latest.observe(&item.change);
        }
        Ok(latest)
    }

    async fn purged_through(&self, owners: &[Owner]) -> Result<VersionVector, StoreError> {
        let g = self.lock();
        let mut horizon = VersionVector::new();
        for owner in owners {
            if let Some(purged) = g.purged.get(owner) {
                horizon.merge(purged);
            }
        }
        Ok(horizon)
    }

    async fn purge_tombstones(&self, before: OffsetDateTime) -> Result<u64, StoreError> {
        let mut g = self.lock();
        let doomed: Vec<ItemId> = g
            .items
            .values()
            .filter(|i| i.deleted_at.is_some_and(|d| d < before))
            .map(|i| i.id)
            .collect();
        for id in &doomed {
            if let Some(item) = g.items.remove(id) {
                g.purged
                    .entry(item.owner)
                    .or_default()
                    .observe(&item.change);
            }
        }
        Ok(doomed.len() as u64)
    }
}

impl EventLog for FakeStore {
    async fn record(&self, event: Event) -> Result<(), StoreError> {
        let mut g = self.lock();
        g.events.push(event);
        g.event_ips.push(None);
        Ok(())
    }
}

impl PrivacyLog for FakeStore {
    async fn record_event(&self, event: Event, ip: Option<IpAddr>) -> Result<(), StoreError> {
        let mut g = self.lock();
        g.events.push(event);
        g.event_ips.push(ip);
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
        Ok(self.stored_events(|e| e.actor == Some(user)))
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
        Ok(self.stored_events(|e| e.at >= from && e.at < to))
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

// ---------------------------------------------------------------------------------------------
// Time, randomness, hashing.

#[derive(Clone)]
pub(crate) struct FakeClock(Arc<Mutex<OffsetDateTime>>);

impl FakeClock {
    pub(crate) fn new() -> Self {
        FakeClock(Arc::new(Mutex::new(datetime!(2026-03-01 12:00 UTC))))
    }

    pub(crate) fn advance(&self, by: Duration) {
        let mut now = self.0.lock().expect("the clock lock isn't poisoned");
        *now += by;
    }
}

impl Clock for FakeClock {
    fn now(&self) -> OffsetDateTime {
        *self.0.lock().expect("the clock lock isn't poisoned")
    }
}

/// splitmix64: repeatable, and different at every call.
#[derive(Clone)]
pub(crate) struct FakeRandom(Arc<Mutex<u64>>);

impl FakeRandom {
    pub(crate) fn new() -> Self {
        FakeRandom(Arc::new(Mutex::new(0x1234_5678_9abc_def0)))
    }
}

impl Random for FakeRandom {
    fn fill(&self, buf: &mut [u8]) {
        let mut state = self.0.lock().expect("the random lock isn't poisoned");
        for chunk in buf.chunks_mut(8) {
            *state = state.wrapping_add(0x9e37_79b9_7f4a_7c15);
            let mut z = *state;
            z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
            z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
            z ^= z >> 31;
            chunk.copy_from_slice(&z.to_le_bytes()[..chunk.len()]);
        }
    }
}

/// Clock, randomness and hashing in one value: `kemlock_app::Platform`.
#[derive(Clone)]
pub(crate) struct FakeEnv {
    pub(crate) clock: FakeClock,
    pub(crate) random: FakeRandom,
}

impl FakeEnv {
    pub(crate) fn new() -> Self {
        FakeEnv {
            clock: FakeClock::new(),
            random: FakeRandom::new(),
        }
    }
}

impl Clock for FakeEnv {
    fn now(&self) -> OffsetDateTime {
        self.clock.now()
    }
}

impl Random for FakeEnv {
    fn fill(&self, buf: &mut [u8]) {
        self.random.fill(buf);
    }
}

impl Hasher for FakeEnv {
    fn sha256(&self, data: &[u8]) -> [u8; 32] {
        kemlock_crypto::hash::sha256(data)
    }

    fn hmac_sha256(&self, key: &[u8], data: &[u8]) -> [u8; 32] {
        kemlock_crypto::hash::hmac_sha256(key, data)
    }
}

// ---------------------------------------------------------------------------------------------
// Crypto ports.

#[derive(Clone)]
pub(crate) struct FakeSeal(Arc<ServerSeal>);

impl FakeSeal {
    pub(crate) fn new() -> Self {
        FakeSeal(Arc::new(ServerSeal::new(&[7u8; 32])))
    }
}

impl SecretSeal for FakeSeal {
    fn seal(&self, purpose: &str, value: &[u8]) -> Vec<u8> {
        self.0.seal(purpose, value)
    }

    fn open(&self, purpose: &str, sealed: &[u8]) -> Result<Zeroizing<Vec<u8>>, CryptoError> {
        self.0
            .open(purpose, sealed)
            .map_err(|_| CryptoError::Invalid)
    }
}

#[derive(Clone)]
pub(crate) struct FakePassword(Arc<OpaqueServer>);

impl FakePassword {
    pub(crate) fn new() -> Self {
        FakePassword(Arc::new(OpaqueServer::generate()))
    }
}

impl PasswordAuth for FakePassword {
    fn registration_response(
        &self,
        credential_id: &[u8],
        request: &[u8],
    ) -> Result<Vec<u8>, CryptoError> {
        self.0
            .registration_response(credential_id, request)
            .map_err(|_| CryptoError::Invalid)
    }

    fn registration_record(&self, upload: &[u8]) -> Result<Vec<u8>, CryptoError> {
        OpaqueServer::registration_record(upload).map_err(|_| CryptoError::Invalid)
    }

    fn login_start(
        &self,
        credential_id: &[u8],
        record: Option<&[u8]>,
        request: &[u8],
    ) -> Result<(Vec<u8>, Vec<u8>), CryptoError> {
        self.0
            .login_start(credential_id, record, request)
            .map_err(|_| CryptoError::Invalid)
    }

    fn login_finish(&self, state: &[u8], finalization: &[u8]) -> Result<Vec<u8>, CryptoError> {
        OpaqueServer::login_finish(state, finalization).map_err(|_| CryptoError::Invalid)
    }
}

#[derive(Clone)]
pub(crate) struct FakeTotp;

impl Totp for FakeTotp {
    fn verify_step(&self, secret: &[u8], code: &str, now: OffsetDateTime) -> Option<u64> {
        kemlock_crypto::totp::verify_step(secret, code, unix(now))
    }
}

pub(crate) fn unix(now: OffsetDateTime) -> u64 {
    u64::try_from(now.unix_timestamp()).unwrap_or(0)
}

/// Access tokens that are random names for claims kept in a map.
#[derive(Clone, Default)]
pub(crate) struct FakeTokenSigner(Arc<Mutex<HashMap<String, AccessClaims>>>);

impl TokenSigner for FakeTokenSigner {
    fn sign(&self, claims: &AccessClaims) -> String {
        let mut tokens = self.0.lock().expect("the signer lock isn't poisoned");
        let token = format!("fake-access-token-{}", tokens.len() + 1);
        tokens.insert(token.clone(), claims.clone());
        token
    }

    fn verify(&self, token: &str, now: OffsetDateTime) -> Result<AccessClaims, CryptoError> {
        let claims = self
            .0
            .lock()
            .expect("the signer lock isn't poisoned")
            .get(token)
            .cloned()
            .ok_or(CryptoError::Invalid)?;
        if claims.expires_at <= now {
            return Err(CryptoError::Invalid);
        }
        Ok(claims)
    }
}

#[derive(Clone, Default)]
pub(crate) struct FakeNotifier(Arc<Mutex<Vec<(Owner, ChangeId)>>>);

impl FakeNotifier {
    pub(crate) fn calls(&self) -> Vec<(Owner, ChangeId)> {
        self.0
            .lock()
            .expect("the notifier lock isn't poisoned")
            .clone()
    }
}

impl Notifier for FakeNotifier {
    async fn sync_now(&self, owner: Owner, change: ChangeId) {
        self.0
            .lock()
            .expect("the notifier lock isn't poisoned")
            .push((owner, change));
    }
}

// ---------------------------------------------------------------------------------------------
// The wiring.

pub(crate) type FakeSessions =
    Sessions<FakeStore, FakeStore, FakeTokenSigner, FakeEnv, FakeStore, FakeStore>;
pub(crate) type FakeSignIn = SignIn<
    FakeStore,
    FakeStore,
    FakeStore,
    FakeStore,
    FakePassword,
    FakeSeal,
    FakeTotp,
    FakeTokenSigner,
    FakeEnv,
    FakeStore,
    FakeStore,
>;
pub(crate) type FakeRefresh =
    Refresh<FakeStore, FakeStore, FakeStore, FakeTokenSigner, FakeEnv, FakeStore, FakeStore>;

/// Every fake, and a method per use case that builds it over them.
pub(crate) struct World {
    pub(crate) store: FakeStore,
    pub(crate) env: FakeEnv,
    pub(crate) password: FakePassword,
    pub(crate) seal: FakeSeal,
    pub(crate) totp: FakeTotp,
    pub(crate) signer: FakeTokenSigner,
    pub(crate) notifier: FakeNotifier,
    pub(crate) setup: Arc<SetupState>,
    pub(crate) config: AuthConfig,
    pub(crate) prelogin_secret: [u8; 32],
}

impl World {
    pub(crate) fn new() -> Self {
        World {
            store: FakeStore::new(),
            env: FakeEnv::new(),
            password: FakePassword::new(),
            seal: FakeSeal::new(),
            totp: FakeTotp,
            signer: FakeTokenSigner::default(),
            notifier: FakeNotifier::default(),
            setup: SetupState::new(),
            config: AuthConfig::default(),
            prelogin_secret: [9u8; 32],
        }
    }

    pub(crate) fn with_signups(mut self) -> Self {
        self.config.signups_allowed = true;
        self
    }

    /// With "verify the email of a new account" on: a held account is refused.
    pub(crate) fn with_email_verification(mut self) -> Self {
        self.config.signups_verify = true;
        self
    }

    pub(crate) fn first_run(&self) -> FirstRun<FakeStore, FakeEnv> {
        FirstRun {
            users: self.store.clone(),
            env: self.env.clone(),
            setup: self.setup.clone(),
            config: self.config,
        }
    }

    pub(crate) fn prelogin(&self) -> Prelogin<FakeStore, FakeEnv> {
        Prelogin {
            users: self.store.clone(),
            hasher: self.env.clone(),
            secret: self.prelogin_secret,
        }
    }

    pub(crate) fn register(&self) -> Register<FakeStore, FakePassword, FakeEnv> {
        Register {
            users: self.store.clone(),
            auth: self.password.clone(),
            env: self.env.clone(),
            setup: self.setup.clone(),
            config: self.config,
        }
    }

    pub(crate) fn enrol_totp(&self) -> EnrolTotp<FakeStore, FakeStore, FakeSeal, FakeEnv> {
        EnrolTotp {
            users: self.store.clone(),
            two_factor: self.store.clone(),
            seal: self.seal.clone(),
            env: self.env.clone(),
        }
    }

    pub(crate) fn confirm_totp(&self) -> ConfirmTotp<FakeStore, FakeSeal, FakeTotp, FakeEnv> {
        ConfirmTotp {
            two_factor: self.store.clone(),
            seal: self.seal.clone(),
            totp: self.totp.clone(),
            env: self.env.clone(),
        }
    }

    pub(crate) fn finish_setup(&self) -> FinishSetup<FakeStore, FakeStore, FakeEnv> {
        FinishSetup {
            users: self.store.clone(),
            two_factor: self.store.clone(),
            setup: self.setup.clone(),
            clock: self.env.clone(),
        }
    }

    pub(crate) fn sessions(&self) -> FakeSessions {
        Sessions {
            devices: self.store.clone(),
            tokens: self.store.clone(),
            signer: self.signer.clone(),
            env: self.env.clone(),
            events: self.store.clone(),
            two_factor: self.store.clone(),
            config: self.config,
        }
    }

    pub(crate) fn sign_in(&self) -> FakeSignIn {
        SignIn {
            users: self.store.clone(),
            two_factor: self.store.clone(),
            auth: self.password.clone(),
            seal: self.seal.clone(),
            totp: self.totp.clone(),
            sessions: self.sessions(),
            sso: RequireSso {
                membership: self.store.clone(),
            },
        }
    }

    pub(crate) fn refresh(&self) -> FakeRefresh {
        Refresh {
            users: self.store.clone(),
            sessions: self.sessions(),
        }
    }

    pub(crate) fn authenticate(
        &self,
    ) -> Authenticate<FakeStore, FakeStore, FakeStore, FakeTokenSigner, FakeEnv> {
        Authenticate {
            users: self.store.clone(),
            devices: self.store.clone(),
            two_factor: self.store.clone(),
            signer: self.signer.clone(),
            clock: self.env.clone(),
            verify_email: self.config.signups_verify,
        }
    }

    pub(crate) fn put_item(
        &self,
    ) -> PutItem<FakeStore, FakeStore, FakeNotifier, FakeEnv, FakeStore> {
        PutItem {
            items: self.store.clone(),
            events: self.store.clone(),
            push: self.notifier.clone(),
            clock: self.env.clone(),
            users: self.store.clone(),
            config: self.config,
        }
    }

    pub(crate) fn put_batch(
        &self,
    ) -> PutBatch<FakeStore, FakeStore, FakeNotifier, FakeEnv, FakeStore> {
        PutBatch {
            items: self.store.clone(),
            events: self.store.clone(),
            push: self.notifier.clone(),
            clock: self.env.clone(),
            users: self.store.clone(),
            config: self.config,
        }
    }

    pub(crate) fn sync_delta(&self) -> SyncDelta<FakeStore, NoSpaceStore> {
        SyncDelta {
            items: self.store.clone(),
            spaces: NoSpaceStore,
        }
    }
}

/// A space store with no spaces, for the tests of an account that belongs to none.
#[derive(Clone, Copy, Debug)]
pub(crate) struct NoSpaceStore;

impl SpaceRepo for NoSpaceStore {
    async fn load(&self, _: SpaceId) -> Result<Option<SpaceState>, StoreError> {
        Ok(None)
    }

    async fn memberships(&self, _: UserId) -> Result<Vec<Member>, StoreError> {
        Ok(Vec::new())
    }

    async fn spaces(&self, _: &[SpaceId]) -> Result<Vec<Space>, StoreError> {
        Ok(Vec::new())
    }

    async fn collection_space(&self, _: CollectionId) -> Result<Option<SpaceId>, StoreError> {
        Ok(None)
    }

    async fn group_space(&self, _: GroupId) -> Result<Option<SpaceId>, StoreError> {
        Ok(None)
    }

    async fn key_copies(&self, _: SpaceId, _: UserId) -> Result<Vec<KeyCopy>, StoreError> {
        Ok(Vec::new())
    }

    async fn holders(&self, _: SpaceId) -> Result<Vec<(CollectionId, UserId)>, StoreError> {
        Ok(Vec::new())
    }

    async fn space_items(&self, _: SpaceId) -> Result<Vec<SpaceItemInfo>, StoreError> {
        Ok(Vec::new())
    }

    async fn item_collections(
        &self,
        _: &[ItemId],
    ) -> Result<Vec<(ItemId, CollectionId)>, StoreError> {
        Ok(Vec::new())
    }

    async fn create(&self, _: SpaceChanges) -> Result<(), StoreError> {
        Err(StoreError::NotFound)
    }

    async fn apply(&self, _: SpaceChanges) -> Result<(), StoreError> {
        Err(StoreError::NotFound)
    }

    async fn put_item(&self, _: ItemDraft, _: CollectionId) -> Result<Item, StoreError> {
        Err(StoreError::NotFound)
    }

    async fn require_sso_of(&self, _: &[SpaceId]) -> Result<Vec<SpaceId>, StoreError> {
        Ok(Vec::new())
    }

    async fn set_require_sso(&self, _: SpaceId, _: bool) -> Result<(), StoreError> {
        Err(StoreError::NotFound)
    }

    async fn put_items(
        &self,
        _: Vec<(ItemDraft, Option<CollectionId>)>,
    ) -> Result<Vec<Item>, StoreError> {
        Err(StoreError::NotFound)
    }

    async fn replace_keys(&self, _: KeyReplacement) -> Result<Vec<Item>, StoreError> {
        Err(StoreError::NotFound)
    }
}

// ---------------------------------------------------------------------------------------------
// A client's side of registration and sign-in, with real OPAQUE.

/// The password input OPAQUE takes: a 32-byte master key (docs/crypto.md).
pub(crate) const PASSWORD: [u8; 32] = [5u8; 32];

/// The `sig1` key behind every fake account's bundle.
pub(crate) fn bundle_key() -> kemlock_crypto::sig1::SigningKey {
    kemlock_crypto::sig1::SigningKey::from_bytes(&[0x5a; 64])
}

/// A public-key bundle for `user` with docs/crypto.md's layout, `signing`'s public key and a
/// filler exchange key, and the signature `signing` makes of it (the server checks it).
pub(crate) fn signed_bundle(
    user: UserId,
    signing: &kemlock_crypto::sig1::SigningKey,
) -> (Vec<u8>, Vec<u8>) {
    let bundle = kemlock_crypto::bundle::Bundle {
        account_id: *user.as_bytes(),
        key_version: FIRST_KEY_VERSION,
        kx1_public: kemlock_crypto::kx1::PublicKey::from_bytes(&[0x42; 1600]).expect("a length"),
        sig1_public: signing.public_key().expect("a public key"),
    };
    let signature = bundle.sign(signing).expect("the bundle signs");
    (bundle.to_bytes(), signature)
}

/// A signed public-key bundle for `user`; see [`bundle_signature`] for its signature.
pub(crate) fn bundle(user: UserId) -> Vec<u8> {
    signed_bundle(user, &bundle_key()).0
}

/// [`bundle`] and its signature, for a registration.
pub(crate) fn bundle_and_signature(user: UserId) -> (Vec<u8>, Vec<u8>) {
    (bundle(user), bundle_signature(user))
}

/// The signature of [`bundle`]`(user)`. ML-DSA signing may be hedged, so the first one made for a
/// user is kept: a test that sends it and reads it back sees the same bytes.
pub(crate) fn bundle_signature(user: UserId) -> Vec<u8> {
    use std::collections::HashMap;
    use std::sync::{Mutex, OnceLock};
    static SIGNATURES: OnceLock<Mutex<HashMap<[u8; 16], Vec<u8>>>> = OnceLock::new();
    let mut known = SIGNATURES
        .get_or_init(Mutex::default)
        .lock()
        .expect("no test panics holding this");
    known
        .entry(*user.as_bytes())
        .or_insert_with(|| signed_bundle(user, &bundle_key()).1)
        .clone()
}

pub(crate) fn register_input(
    user: UserId,
    email: &str,
    upload: Vec<u8>,
    setup_grant: Option<String>,
) -> RegisterInput {
    RegisterInput {
        user,
        email: email.to_owned(),
        name: Some("Test Person".to_owned()),
        upload,
        kdf: KdfParams::new_account([4u8; 16]),
        public_bundle: bundle(user),
        bundle_signature: bundle_signature(user),
        sealed_private_keys: vec![0x22; 64],
        wrapped_root_key: vec![0x33; WRAPPED_ROOT_KEY_LEN],
        setup_grant,
    }
}

/// Registers `email` with [`PASSWORD`] through both registration messages.
pub(crate) async fn register_account(
    world: &World,
    email: &str,
    setup_grant: Option<String>,
) -> Result<Registered, kemlock_app::AppError> {
    let (state, request) =
        kemlock_crypto::opaque::client_registration_start(&PASSWORD).expect("client start");
    let response = world
        .register()
        .start(RegisterStartInput {
            email: email.to_owned(),
            request,
            setup_grant: setup_grant.clone(),
        })
        .await?;
    let (upload, _export_key) =
        kemlock_crypto::opaque::client_registration_finish(state, &PASSWORD, &response)
            .expect("client finish");
    world
        .register()
        .finish(register_input(UserId::random(), email, upload, setup_grant))
        .await
}

pub(crate) fn device(name: &str) -> DeviceInfo {
    DeviceInfo {
        id: None,
        name: name.to_owned(),
        kind: DeviceKind::KemlockAndroid,
        bitwarden_identifier: None,
    }
}

/// Both OPAQUE login messages of a client with `password`: the server's sealed login state and
/// the client's finalization, ready for `SignIn::finish`.
pub(crate) async fn login_messages(
    world: &World,
    email: &str,
    password: &[u8],
    jkt: &str,
) -> Result<(Vec<u8>, Vec<u8>), kemlock_app::AppError> {
    let (state, request) =
        kemlock_crypto::opaque::client_login_start(password).expect("client login start");
    let started = world
        .sign_in()
        .start(OpaqueStartInput {
            email: email.to_owned(),
            request,
            jkt: jkt.to_owned(),
        })
        .await?;
    let (finalization, _session_key, _export_key) =
        kemlock_crypto::opaque::client_login_finish(state, password, &started.response)
            .expect("client login finish");
    Ok((started.login_state, finalization))
}

/// Runs both OPAQUE login messages with `password` and returns the server's answer to the last.
pub(crate) async fn sign_in_with(
    world: &World,
    email: &str,
    password: &[u8],
    device: DeviceInfo,
    jkt: &str,
) -> Result<SignedIn, kemlock_app::AppError> {
    let (login_state, finalization) = login_messages(world, email, password, jkt).await?;
    world
        .sign_in()
        .finish(OpaqueFinishInput {
            email: email.to_owned(),
            login_state,
            finalization,
            device,
            jkt: jkt.to_owned(),
        })
        .await
}

/// A current TOTP code for the user's stored secret.
pub(crate) fn totp_code(world: &World, user: UserId) -> String {
    let row = world
        .store
        .two_factor_of(user)
        .into_iter()
        .find(|t| t.method == TwoFactorMethod::Totp)
        .expect("the user has a TOTP enrolment");
    // Sealed to the account, or the old way under the bare purpose, as a test may leave it.
    let secret = kemlock_app::sealed::open_bound(&world.seal, "totp", user, &row.sealed_secret)
        .expect("the secret opens")
        .value;
    kemlock_crypto::totp::code_at(&secret, unix(world.env.now()))
}

/// Registers an ordinary account (signups must be on) and returns its id.
pub(crate) async fn make_user(world: &World, email: &str) -> UserId {
    register_account(world, email, None)
        .await
        .expect("registration succeeds")
        .user
}

/// An actor for `user` on a made-up device.
pub(crate) fn actor(user: UserId) -> Actor {
    Actor {
        user,
        device: DeviceId::random(),
        admin: false,
    }
}

/// A sealed-looking value of `len` bytes.
pub(crate) fn filler(len: usize, byte: u8) -> Vec<u8> {
    vec![byte; len]
}

pub(crate) fn write(
    owner: UserId,
    id: ItemId,
    expected: Option<u64>,
    revision: u64,
) -> kemlock_domain::ItemWrite {
    kemlock_domain::ItemWrite {
        id,
        owner: Owner::User(owner),
        kind: kemlock_domain::ItemKind::try_from("login".to_owned()).expect("a valid kind"),
        format: kemlock_domain::ItemFormat::Kem1,
        expected: expected.map(kemlock_domain::Revision),
        revision: kemlock_domain::Revision(revision),
        key_version: 1,
        sealed: Some(kemlock_domain::Sealed {
            ciphertext: filler(64, 0xaa),
            item_key: filler(kemlock_domain::item::ITEM_KEY_LEN, 0xbb),
        }),
    }
}

pub(crate) fn delete(
    owner: UserId,
    id: ItemId,
    expected: u64,
    revision: u64,
) -> kemlock_domain::ItemWrite {
    kemlock_domain::ItemWrite {
        sealed: None,
        ..write(owner, id, Some(expected), revision)
    }
}

impl MembershipFacts for FakeStore {
    async fn spaces_of(&self, user: UserId) -> Result<Vec<SpaceMembership>, StoreError> {
        Ok(self
            .lock()
            .memberships
            .get(&user)
            .cloned()
            .unwrap_or_default())
    }
}

impl SsoSettingsRepo for FakeStore {
    async fn sso_settings(&self) -> Result<Option<SsoSettings>, StoreError> {
        Ok(self.lock().sso_settings.clone())
    }

    async fn put_sso_settings(&self, settings: &SsoSettings) -> Result<(), StoreError> {
        self.lock().sso_settings = Some(settings.clone());
        Ok(())
    }
}

impl VerifiedDomainRepo for FakeStore {
    async fn domain_claim(&self, domain: &str) -> Result<Option<VerifiedDomain>, StoreError> {
        Ok(self.lock().domains.get(domain).cloned())
    }

    async fn domain_claims(&self) -> Result<Vec<VerifiedDomain>, StoreError> {
        Ok(self.lock().domains.values().cloned().collect())
    }

    async fn put_domain_claim(&self, claim: &VerifiedDomain) -> Result<(), StoreError> {
        self.lock()
            .domains
            .insert(claim.domain.clone(), claim.clone());
        Ok(())
    }

    async fn remove_domain_claim(&self, domain: &str) -> Result<(), StoreError> {
        self.lock().domains.remove(domain);
        Ok(())
    }
}

impl FakeStore {
    /// The value saved under `key` in the `settings` table.
    pub(crate) fn saved_setting(&self, key: &str) -> Option<String> {
        self.lock().settings.get(key).cloned()
    }
}

impl kemlock_app::admin::SettingsRepo for FakeStore {
    async fn settings_with_prefix(
        &self,
        prefix: &str,
    ) -> Result<Vec<(String, String)>, StoreError> {
        Ok(self
            .lock()
            .settings
            .iter()
            .filter(|(key, _)| key.starts_with(prefix))
            .map(|(key, value)| (key.clone(), value.clone()))
            .collect())
    }

    async fn put_setting(&self, key: &str, value: &str) -> Result<(), StoreError> {
        self.lock()
            .settings
            .insert(key.to_owned(), value.to_owned());
        Ok(())
    }

    async fn delete_setting(&self, key: &str) -> Result<(), StoreError> {
        self.lock().settings.remove(key);
        Ok(())
    }
}

impl kemlock_app::second_step_guard::SecondStepGuard for FakeStore {
    async fn reserve_second_step(
        &self,
        user: UserId,
        now: i64,
        limit: u32,
        window_secs: i64,
    ) -> Result<kemlock_app::second_step_guard::Reservation, StoreError> {
        let mut g = self.lock();
        let before = g.second_step.get(&user).copied().unwrap_or_default();
        let (after, reservation) = before.reserve(now, limit, window_secs);
        g.second_step.insert(user, after);
        Ok(reservation)
    }

    async fn clear_second_step(&self, user: UserId) -> Result<(), StoreError> {
        self.lock().second_step.remove(&user);
        Ok(())
    }
}
