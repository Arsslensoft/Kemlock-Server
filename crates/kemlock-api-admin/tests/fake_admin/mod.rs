//! In-memory admin repositories over the API tests' fake store, and a mailer that keeps what it
//! was asked to send. Accounts and spaces are listed only once a test says they exist
//! (`track_user`, `track_space`), because the fake store can't be enumerated.
#![allow(dead_code, unused_imports)]

use crate::common::fakes::FakeStore;
use crate::space_fakes::FakeSpaces;
use kemlock_app::admin::{
    AccountErasure, AdminContact, AdminError, AdminEvent, AdminEventRepo, AdminSpaceRepo,
    AdminSpaceRow, AdminUserRepo, AdminUserRow, ComplianceCounts, ComplianceRepo,
    ComplianceRequest, CustomFieldRepo, EventCursor, EventFilter, EventPage, EventRecord, Invite,
    InviteRepo, MailError, Mailer, Notice, SettingsRepo, SpaceOwner, SpacePage, UserCounts,
    UserPage, UserQuery,
};
use kemlock_app::notices::BoxFuture;
use kemlock_app::ports::StoreError;
use kemlock_app::spaces::SpaceRepo;
use kemlock_domain::{CustomField, CustomFieldId, SpaceId, User, UserId};
use std::collections::{BTreeMap, HashMap};
use std::sync::{Arc, Mutex, MutexGuard};
use time::OffsetDateTime;
use uuid::Uuid;

#[derive(Default)]
struct Inner {
    tracked: Vec<UserId>,
    spaces: Vec<SpaceId>,
    disabled: HashMap<UserId, (OffsetDateTime, UserId)>,
    invites: Vec<Invite>,
    events: Vec<EventRecord>,
    settings: BTreeMap<String, String>,
    requests: Vec<ComplianceRequest>,
    custom_fields: Vec<CustomField>,
    erased: Vec<UserId>,
    /// Each account the delete route erased and the admin who asked, through `AccountErasure`.
    erasures: Vec<(UserId, UserId)>,
    /// Accounts whose owner deleted them and whose grace period is running.
    pending_erasures: Vec<UserId>,
    seq: u128,
    /// Set by a test: the event log refuses every write, as a full disk does.
    events_fail: bool,
}

#[derive(Clone)]
pub(crate) struct FakeAdmin {
    inner: Arc<Mutex<Inner>>,
    store: FakeStore,
    spaces: FakeSpaces<FakeStore>,
}

impl FakeAdmin {
    pub(crate) fn new(store: FakeStore, spaces: FakeSpaces<FakeStore>) -> Self {
        FakeAdmin {
            inner: Arc::new(Mutex::new(Inner::default())),
            store,
            spaces,
        }
    }

    fn lock(&self) -> MutexGuard<'_, Inner> {
        self.inner.lock().expect("the admin lock isn't poisoned")
    }

    /// From now on the event log refuses every write.
    pub(crate) fn fail_events(&self) {
        self.lock().events_fail = true;
    }

    pub(crate) fn track_user(&self, id: UserId) {
        self.lock().tracked.push(id);
    }

    pub(crate) fn track_space(&self, id: SpaceId) {
        self.lock().spaces.push(id);
    }

    pub(crate) fn events(&self) -> Vec<EventRecord> {
        self.lock().events.clone()
    }

    pub(crate) fn actions(&self) -> Vec<String> {
        self.lock()
            .events
            .iter()
            .map(|e| e.action.clone())
            .collect()
    }

    pub(crate) fn erased(&self) -> Vec<UserId> {
        self.lock().erased.clone()
    }

    /// The accounts the delete route erased through privacy's erasure, with the admin who asked.
    pub(crate) fn erasures(&self) -> Vec<(UserId, UserId)> {
        self.lock().erasures.clone()
    }

    /// Puts the account on the erasure schedule, as its owner deleting it would.
    pub(crate) fn schedule_erasure(&self, user: UserId) {
        self.lock().pending_erasures.push(user);
    }

    pub(crate) fn pending_erasures(&self) -> Vec<UserId> {
        self.lock().pending_erasures.clone()
    }

    /// The custom fields as stored, oldest first.
    pub(crate) fn custom_fields_now(&self) -> Vec<CustomField> {
        self.lock().custom_fields.clone()
    }

    pub(crate) fn saved_setting(&self, key: &str) -> Option<String> {
        self.lock().settings.get(key).cloned()
    }

    pub(crate) fn invites_now(&self) -> Vec<Invite> {
        self.lock().invites.clone()
    }

    fn row(&self, user: &User, disabled: Option<OffsetDateTime>) -> AdminUserRow {
        let devices = self.store.devices_of(user.id);
        AdminUserRow {
            id: user.id,
            email: user.email.as_str().to_owned(),
            name: user.name.clone(),
            role: user.role,
            mode: user.mode,
            created_at: user.created_at,
            disabled_at: disabled,
            devices: u32::try_from(devices.len()).unwrap_or(u32::MAX),
            two_step: self.store.two_factor_of(user.id).iter().any(|t| t.enabled),
            last_seen_at: devices.iter().map(|d| d.last_seen_at).max(),
            erasure_pending: self.lock().pending_erasures.contains(&user.id),
        }
    }
}

impl AdminUserRepo for FakeAdmin {
    async fn list_users(&self, query: &UserQuery) -> Result<UserPage, StoreError> {
        let (ids, disabled) = {
            let g = self.lock();
            (g.tracked.clone(), g.disabled.clone())
        };
        let mut rows: Vec<AdminUserRow> = ids
            .into_iter()
            .filter_map(|id| self.store.user(id))
            .map(|u| self.row(&u, disabled.get(&u.id).map(|d| d.0)))
            .collect();
        rows.sort_by(|a, b| a.email.cmp(&b.email));
        if let Some(search) = &query.search {
            let needle = search.to_lowercase();
            rows.retain(|r| {
                r.email.to_lowercase().contains(&needle)
                    || r.name
                        .as_ref()
                        .is_some_and(|n| n.to_lowercase().contains(&needle))
            });
        }
        let total = rows.len() as u64;
        let users = rows
            .into_iter()
            .skip(usize::try_from(query.offset).unwrap_or(usize::MAX))
            .take(query.limit as usize)
            .collect();
        Ok(UserPage { users, total })
    }

    async fn user_row(&self, id: UserId) -> Result<Option<AdminUserRow>, StoreError> {
        let disabled = self.lock().disabled.get(&id).map(|d| d.0);
        Ok(self.store.user(id).map(|u| self.row(&u, disabled)))
    }

    async fn set_disabled(
        &self,
        user: UserId,
        disabled: Option<(OffsetDateTime, UserId)>,
    ) -> Result<(), StoreError> {
        if self.store.user(user).is_none() {
            return Err(StoreError::NotFound);
        }
        // The Kemlock API asks the store, which is where the flag lives in the real server.
        self.store.set_account_disabled(user, disabled.is_some());
        let mut g = self.lock();
        match disabled {
            Some(d) => g.disabled.insert(user, d),
            None => g.disabled.remove(&user),
        };
        Ok(())
    }

    async fn is_disabled(&self, user: UserId) -> Result<bool, StoreError> {
        Ok(self.lock().disabled.contains_key(&user))
    }

    async fn admins(&self) -> Result<Vec<AdminContact>, StoreError> {
        let ids = self.lock().tracked.clone();
        Ok(ids
            .into_iter()
            .filter_map(|id| self.store.user(id))
            .filter(User::is_admin)
            .map(|u| AdminContact {
                id: u.id,
                email: u.email,
            })
            .collect())
    }

    async fn sole_owned_spaces(&self, user: UserId) -> Result<Vec<SpaceId>, StoreError> {
        let ids = self.lock().spaces.clone();
        let mut sole = Vec::new();
        for id in ids {
            let Some(state) = self.spaces.load(id).await? else {
                continue;
            };
            let owners: Vec<UserId> = state
                .members
                .iter()
                .filter(|m| m.is_confirmed() && m.role == kemlock_domain::spaces::SpaceRole::Owner)
                .map(|m| m.user)
                .collect();
            if owners == [user] {
                sole.push(id);
            }
        }
        Ok(sole)
    }

    async fn erase_user(&self, user: UserId) -> Result<(), StoreError> {
        let mut g = self.lock();
        g.tracked.retain(|u| *u != user);
        g.disabled.remove(&user);
        g.erased.push(user);
        Ok(())
    }

    async fn cancel_pending_erasure(&self, user: UserId) -> Result<bool, StoreError> {
        let mut g = self.lock();
        let before = g.pending_erasures.len();
        g.pending_erasures.retain(|u| *u != user);
        Ok(g.pending_erasures.len() < before)
    }

    async fn user_counts(&self) -> Result<UserCounts, StoreError> {
        let g = self.lock();
        let users: Vec<User> = g
            .tracked
            .iter()
            .filter_map(|id| self.store.user(*id))
            .collect();
        Ok(UserCounts {
            users: users.len() as u64,
            admins: users.iter().filter(|u| u.is_admin()).count() as u64,
            disabled: g.disabled.len() as u64,
            devices: users
                .iter()
                .map(|u| self.store.devices_of(u.id).len() as u64)
                .sum(),
        })
    }
}

impl InviteRepo for FakeAdmin {
    async fn insert_invite(&self, invite: &Invite) -> Result<(), StoreError> {
        let mut g = self.lock();
        if g.invites.iter().any(|i| i.email == invite.email) {
            return Err(StoreError::Duplicate);
        }
        g.invites.push(invite.clone());
        Ok(())
    }

    async fn invites(&self) -> Result<Vec<Invite>, StoreError> {
        let mut all = self.lock().invites.clone();
        all.sort_by_key(|x| std::cmp::Reverse(x.created_at));
        Ok(all)
    }

    async fn invite(&self, id: Uuid) -> Result<Option<Invite>, StoreError> {
        Ok(self.lock().invites.iter().find(|i| i.id == id).cloned())
    }

    async fn update_invite(&self, invite: &Invite) -> Result<(), StoreError> {
        let mut g = self.lock();
        match g.invites.iter_mut().find(|i| i.id == invite.id) {
            Some(slot) => {
                *slot = invite.clone();
                Ok(())
            }
            None => Err(StoreError::NotFound),
        }
    }

    async fn remove_invite(&self, id: Uuid) -> Result<(), StoreError> {
        self.lock().invites.retain(|i| i.id != id);
        Ok(())
    }

    async fn invite_by_token(&self, token_hash: [u8; 32]) -> Result<Option<Invite>, StoreError> {
        Ok(self
            .lock()
            .invites
            .iter()
            .find(|i| i.token_hash == token_hash)
            .cloned())
    }

    async fn pending_invites(&self, now: OffsetDateTime) -> Result<u64, StoreError> {
        Ok(self
            .lock()
            .invites
            .iter()
            .filter(|i| i.is_pending(now))
            .count() as u64)
    }
}

impl AdminSpaceRepo for FakeAdmin {
    async fn list_spaces(&self, limit: u32, offset: u64) -> Result<SpacePage, StoreError> {
        let ids = self.lock().spaces.clone();
        let total = ids.len() as u64;
        let mut spaces = Vec::new();
        for id in ids
            .into_iter()
            .skip(usize::try_from(offset).unwrap_or(usize::MAX))
            .take(limit as usize)
        {
            if let Some(row) = self.space_row(id).await? {
                spaces.push(row);
            }
        }
        Ok(SpacePage { spaces, total })
    }

    async fn space_row(&self, id: SpaceId) -> Result<Option<AdminSpaceRow>, StoreError> {
        let Some(state) = self.spaces.load(id).await? else {
            return Ok(None);
        };
        let owners = state
            .members
            .iter()
            .filter(|m| m.is_confirmed() && m.role == kemlock_domain::spaces::SpaceRole::Owner)
            .map(|m| SpaceOwner {
                user: m.user,
                email: self
                    .store
                    .user(m.user)
                    .map(|u| u.email.as_str().to_owned())
                    .unwrap_or_default(),
            })
            .collect();
        Ok(Some(AdminSpaceRow {
            id,
            created_at: state.space.created_at,
            members: u32::try_from(state.members.len()).unwrap_or(u32::MAX),
            confirmed: u32::try_from(state.members.iter().filter(|m| m.is_confirmed()).count())
                .unwrap_or(u32::MAX),
            owners,
            live_items: 0,
            keys_pending_since: state.space.keys_pending_since,
        }))
    }

    async fn live_items(&self) -> Result<u64, StoreError> {
        Ok(0)
    }
}

fn matches(event: &EventRecord, filter: &EventFilter) -> bool {
    filter.actor.is_none_or(|a| event.actor == Some(a))
        && filter
            .action
            .as_ref()
            .is_none_or(|a| match a.strip_suffix('*') {
                Some(prefix) => event.action.starts_with(prefix),
                None => &event.action == a,
            })
        && filter.target.as_ref().is_none_or(|t| {
            event
                .target
                .as_ref()
                .is_some_and(|target| target.contains(t.as_str()))
        })
        && filter.from.is_none_or(|from| event.at >= from)
        && filter.to.is_none_or(|to| event.at <= to)
}

impl AdminEventRepo for FakeAdmin {
    async fn record_admin_event(&self, event: AdminEvent) -> Result<(), StoreError> {
        if self.lock().events_fail {
            return Err(StoreError::Backend("the event log is full".to_owned()));
        }
        let actor_email = event
            .actor
            .and_then(|a| self.store.user(a))
            .map(|u| u.email.as_str().to_owned());
        let mut g = self.lock();
        g.seq += 1;
        let id = Uuid::from_u128(g.seq);
        g.events.push(EventRecord {
            id,
            at: event.at,
            actor: event.actor,
            actor_email,
            device: event.device,
            action: event.action,
            target: event.target,
            ip: event.ip,
        });
        Ok(())
    }

    async fn query_events(
        &self,
        filter: &EventFilter,
        after: Option<&EventCursor>,
        limit: u32,
    ) -> Result<EventPage, StoreError> {
        let mut all: Vec<EventRecord> = self
            .lock()
            .events
            .iter()
            .filter(|e| matches(e, filter))
            .cloned()
            .collect();
        all.sort_by_key(|x| std::cmp::Reverse((x.at, x.id)));
        if let Some(cursor) = after {
            all.retain(|e| (e.at, e.id) < (cursor.at, cursor.id));
        }
        let more = all.len() > limit as usize;
        all.truncate(limit as usize);
        let next = if more {
            all.last().map(|e| EventCursor { at: e.at, id: e.id })
        } else {
            None
        };
        Ok(EventPage { events: all, next })
    }

    async fn count_events_since(&self, since: OffsetDateTime) -> Result<u64, StoreError> {
        Ok(self.lock().events.iter().filter(|e| e.at >= since).count() as u64)
    }

    async fn purge_events_before(&self, before: OffsetDateTime) -> Result<u64, StoreError> {
        let mut g = self.lock();
        let was = g.events.len();
        g.events.retain(|e| e.at >= before);
        Ok((was - g.events.len()) as u64)
    }
}

impl SettingsRepo for FakeAdmin {
    async fn settings_with_prefix(
        &self,
        prefix: &str,
    ) -> Result<Vec<(String, String)>, StoreError> {
        Ok(self
            .lock()
            .settings
            .iter()
            .filter(|(k, _)| k.starts_with(prefix))
            .map(|(k, v)| (k.clone(), v.clone()))
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

impl CustomFieldRepo for FakeAdmin {
    async fn custom_fields(&self) -> Result<Vec<CustomField>, StoreError> {
        Ok(self.lock().custom_fields.clone())
    }

    async fn custom_field(&self, id: CustomFieldId) -> Result<Option<CustomField>, StoreError> {
        Ok(self
            .lock()
            .custom_fields
            .iter()
            .find(|f| f.id == id)
            .cloned())
    }

    async fn insert_custom_field(
        &self,
        field: &CustomField,
        limit: usize,
    ) -> Result<bool, StoreError> {
        let mut g = self.lock();
        if g.custom_fields
            .iter()
            .any(|f| f.name_key() == field.name_key())
        {
            return Err(StoreError::Duplicate);
        }
        if g.custom_fields.len() >= limit {
            return Ok(false);
        }
        g.custom_fields.push(field.clone());
        Ok(true)
    }

    async fn update_custom_field(&self, field: &CustomField) -> Result<(), StoreError> {
        let mut g = self.lock();
        if g.custom_fields
            .iter()
            .any(|f| f.id != field.id && f.name_key() == field.name_key())
        {
            return Err(StoreError::Duplicate);
        }
        let slot = g
            .custom_fields
            .iter_mut()
            .find(|f| f.id == field.id)
            .ok_or(StoreError::NotFound)?;
        *slot = field.clone();
        Ok(())
    }

    async fn remove_custom_field(&self, id: CustomFieldId) -> Result<bool, StoreError> {
        let mut g = self.lock();
        let before = g.custom_fields.len();
        g.custom_fields.retain(|f| f.id != id);
        Ok(g.custom_fields.len() != before)
    }
}

impl ComplianceRepo for FakeAdmin {
    async fn insert_compliance_request(
        &self,
        request: &ComplianceRequest,
    ) -> Result<(), StoreError> {
        self.lock().requests.push(request.clone());
        Ok(())
    }

    async fn compliance_request(&self, id: Uuid) -> Result<Option<ComplianceRequest>, StoreError> {
        Ok(self.lock().requests.iter().find(|r| r.id == id).cloned())
    }

    async fn update_compliance_request(
        &self,
        request: &ComplianceRequest,
    ) -> Result<(), StoreError> {
        let mut g = self.lock();
        match g.requests.iter_mut().find(|r| r.id == request.id) {
            Some(slot) => {
                *slot = request.clone();
                Ok(())
            }
            None => Err(StoreError::NotFound),
        }
    }

    async fn compliance_requests(
        &self,
        open_only: bool,
    ) -> Result<Vec<ComplianceRequest>, StoreError> {
        let mut all: Vec<ComplianceRequest> = self
            .lock()
            .requests
            .iter()
            .filter(|r| !open_only || r.status.is_open())
            .cloned()
            .collect();
        all.sort_by_key(|x| (x.due_at, x.id));
        Ok(all)
    }

    async fn compliance_counts(&self, now: OffsetDateTime) -> Result<ComplianceCounts, StoreError> {
        let g = self.lock();
        let open: Vec<&ComplianceRequest> =
            g.requests.iter().filter(|r| r.status.is_open()).collect();
        Ok(ComplianceCounts {
            open: open.len() as u64,
            overdue: open.iter().filter(|r| r.due_at < now).count() as u64,
        })
    }
}

/// A mailer that keeps what it was asked to send.
#[derive(Clone)]
pub(crate) struct FakeMailer {
    configured: bool,
    sent: Arc<Mutex<Vec<Notice>>>,
}

impl FakeMailer {
    pub(crate) fn new(configured: bool) -> Self {
        FakeMailer {
            configured,
            sent: Arc::new(Mutex::new(Vec::new())),
        }
    }

    pub(crate) fn sent(&self) -> Vec<Notice> {
        self.sent
            .lock()
            .expect("the mail lock isn't poisoned")
            .clone()
    }
}

impl Mailer for FakeMailer {
    fn configured(&self) -> bool {
        self.configured
    }

    async fn send(&self, notice: Notice) -> Result<(), MailError> {
        if !self.configured {
            return Err(MailError::NotConfigured);
        }
        self.sent
            .lock()
            .expect("the mail lock isn't poisoned")
            .push(notice);
        Ok(())
    }
}

/// What the delete route calls in the server: privacy's erasure, which here records who asked
/// and drops the account from the fake.
impl AccountErasure for FakeAdmin {
    fn erase(&self, user: UserId, admin: UserId) -> BoxFuture<'_, Result<(), AdminError>> {
        Box::pin(async move {
            let mut g = self.lock();
            g.tracked.retain(|u| *u != user);
            g.disabled.remove(&user);
            g.erasures.push((user, admin));
            Ok(())
        })
    }
}
