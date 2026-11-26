//! The admin ports (`AdminUserRepo`, `InviteRepo`, `AdminSpaceRepo`, `AdminEventRepo`,
//! `SettingsRepo`, `ComplianceRepo`) on `SqlStore`.
//!
//! Lists the console shows are read as a few small columns and put together here, so a page of
//! accounts never loads a sealed private key and the code is the same on every backend.

use crate::convert::utc;
use crate::error::{StoreResult, map_db};
use crate::store::SqlStore;
use crate::tables::admin::{event_rows, invites, requests, user_state};
use crate::tables::federation::item_siblings;
use crate::tables::space_recovery;
use crate::tables::space_tables::collection_grants::GRANTEE_MEMBER;
use crate::tables::space_tables::{
    collection_grants, collection_keys, group_members, members, spaces,
};
use crate::tables::{
    auth_requests, bw_account_extras, bw_accounts, changes, device_key_copies, devices,
    emergency_access, items, pending_erasures, refresh_tokens, settings, sso, sync_horizon,
    two_factor, users,
};
use kemlock_app::admin::{
    AdminContact, AdminEvent, AdminEventRepo, AdminSpaceRepo, AdminSpaceRow, AdminUserRepo,
    AdminUserRow, ComplianceCounts, ComplianceRepo, ComplianceRequest, EventCursor, EventFilter,
    EventPage, EventRecord, Invite, InviteRepo, SettingsRepo, SpaceOwner, SpacePage, UserCounts,
    UserPage, UserQuery,
};
use kemlock_app::ports::StoreError;
use kemlock_domain::{AccountMode, DeviceId, Email, Owner, Role, SpaceId, UserId};
use sea_orm::ActiveValue::{NotSet, Set};
use sea_orm::sea_query::{Expr, OnConflict};
use sea_orm::{
    ColumnTrait, Condition, DatabaseTransaction, EntityTrait, PaginatorTrait, QueryFilter,
    QueryOrder, QuerySelect, TransactionTrait,
};
use std::collections::{BTreeMap, BTreeSet, HashMap};
use time::OffsetDateTime;
use uuid::Uuid;

/// Commits when `outcome` is good, rolls back when it isn't, and hands `outcome` on.
async fn finish<T>(
    txn: DatabaseTransaction,
    outcome: Result<T, StoreError>,
    what: &str,
) -> Result<T, StoreError> {
    match outcome {
        Ok(value) => {
            txn.commit().await.store()?;
            Ok(value)
        }
        Err(err) => {
            if let Err(rollback) = txn.rollback().await {
                tracing::warn!(%rollback, "rollback after {what} failed");
            }
            Err(err)
        }
    }
}

fn corrupt(what: &str) -> StoreError {
    crate::convert::corrupt(what)
}

// ---------------------------------------------------------------------------------------------
// Users

/// The columns of an account the Users list needs.
type BaseRow = (Uuid, String, Option<String>, String, String, OffsetDateTime);

impl SqlStore {
    async fn base_rows(&self, ids: Option<&[Uuid]>) -> Result<Vec<BaseRow>, StoreError> {
        let mut select = users::Entity::find()
            .select_only()
            .column(users::Column::Id)
            .column(users::Column::Email)
            .column(users::Column::Name)
            .column(users::Column::Mode)
            .column(users::Column::Role)
            .column(users::Column::CreatedAt);
        if let Some(ids) = ids {
            select = select.filter(users::Column::Id.is_in(ids.to_vec()));
        }
        select
            .order_by_asc(users::Column::Email)
            .into_tuple::<BaseRow>()
            .all(self.reader())
            .await
            .store()
    }

    /// Adds devices, two-step and the disabled flag to the base rows.
    async fn enrich(&self, base: Vec<BaseRow>) -> Result<Vec<AdminUserRow>, StoreError> {
        let db = self.reader();
        let ids: Vec<Uuid> = base.iter().map(|row| row.0).collect();
        if ids.is_empty() {
            return Ok(Vec::new());
        }
        let device_rows: Vec<(Uuid, OffsetDateTime)> = devices::Entity::find()
            .select_only()
            .column(devices::Column::UserId)
            .column(devices::Column::LastSeenAt)
            .filter(devices::Column::UserId.is_in(ids.clone()))
            .into_tuple()
            .all(db)
            .await
            .store()?;
        let mut devices_of: HashMap<Uuid, (u32, Option<OffsetDateTime>)> = HashMap::new();
        for (user, seen) in device_rows {
            let entry = devices_of.entry(user).or_insert((0, None));
            entry.0 = entry.0.saturating_add(1);
            entry.1 = Some(entry.1.map_or(seen, |old| old.max(seen)));
        }
        let two_step: BTreeSet<Uuid> = two_factor::Entity::find()
            .select_only()
            .column(two_factor::Column::UserId)
            .column(two_factor::Column::Method)
            .filter(two_factor::Column::UserId.is_in(ids.clone()))
            .filter(two_factor::Column::Enabled.eq(true))
            .into_tuple::<(Uuid, String)>()
            .all(db)
            .await
            .store()?
            .into_iter()
            .map(|(user, _)| user)
            .collect();
        let erasing: BTreeSet<Uuid> = pending_erasures::Entity::find()
            .select_only()
            .column(pending_erasures::Column::UserId)
            .filter(pending_erasures::Column::UserId.is_in(ids.clone()))
            .into_tuple::<Uuid>()
            .all(db)
            .await
            .store()?
            .into_iter()
            .collect();
        let disabled: HashMap<Uuid, OffsetDateTime> = user_state::Entity::find()
            .filter(user_state::Column::UserId.is_in(ids))
            .all(db)
            .await
            .store()?
            .into_iter()
            .map(|row| (row.user_id, row.disabled_at))
            .collect();

        base.into_iter()
            .map(|(id, email, name, mode, role, created_at)| {
                let (count, seen) = devices_of.get(&id).copied().unwrap_or((0, None));
                Ok(AdminUserRow {
                    id: UserId(id),
                    email,
                    name,
                    role: if role == users::ROLE_ADMIN {
                        Role::Admin
                    } else if role == "user" {
                        Role::User
                    } else {
                        return Err(corrupt("role"));
                    },
                    mode: match mode.as_str() {
                        "kemlock-only" => AccountMode::KemlockOnly,
                        "compatible" => AccountMode::Compatible,
                        _ => return Err(corrupt("account mode")),
                    },
                    created_at,
                    disabled_at: disabled.get(&id).copied(),
                    devices: count,
                    two_step: two_step.contains(&id),
                    last_seen_at: seen,
                    erasure_pending: erasing.contains(&id),
                })
            })
            .collect()
    }
}

impl AdminUserRepo for SqlStore {
    async fn list_users(&self, query: &UserQuery) -> Result<UserPage, StoreError> {
        let mut rows = self.base_rows(None).await?;
        if let Some(search) = &query.search {
            let needle = search.to_lowercase();
            rows.retain(|(_, email, name, ..)| {
                email.to_lowercase().contains(&needle)
                    || name
                        .as_ref()
                        .is_some_and(|n| n.to_lowercase().contains(&needle))
            });
        }
        let total = rows.len() as u64;
        let page: Vec<BaseRow> = rows
            .into_iter()
            .skip(usize::try_from(query.offset).unwrap_or(usize::MAX))
            .take(query.limit as usize)
            .collect();
        Ok(UserPage {
            users: self.enrich(page).await?,
            total,
        })
    }

    async fn user_row(&self, id: UserId) -> Result<Option<AdminUserRow>, StoreError> {
        let rows = self.base_rows(Some(&[id.0])).await?;
        Ok(self.enrich(rows).await?.pop())
    }

    async fn set_disabled(
        &self,
        user: UserId,
        disabled: Option<(OffsetDateTime, UserId)>,
    ) -> Result<(), StoreError> {
        let txn = self.writer().begin().await.store()?;
        let outcome = async {
            if users::Entity::find_by_id(user.0)
                .one(&txn)
                .await
                .store()?
                .is_none()
            {
                return Err(StoreError::NotFound);
            }
            user_state::Entity::delete_by_id(user.0)
                .exec(&txn)
                .await
                .store()?;
            if let Some((at, by)) = disabled {
                user_state::Entity::insert(user_state::ActiveModel {
                    user_id: Set(user.0),
                    disabled_at: Set(utc(at)),
                    disabled_by: Set(by.0),
                })
                .exec(&txn)
                .await
                .store()?;
            } else {
                // Enabling clears the flag an account moved from Vaultwarden arrived with, too,
                // so one action enables it whichever way it was disabled.
                bw_account_extras::Entity::update_many()
                    .col_expr(bw_account_extras::Column::Enabled, Expr::value(true))
                    .filter(bw_account_extras::Column::UserId.eq(user.0))
                    .exec(&txn)
                    .await
                    .store()?;
            }
            Ok::<(), StoreError>(())
        }
        .await;
        finish(txn, outcome, "changing whether an account is disabled").await
    }

    async fn is_disabled(&self, user: UserId) -> Result<bool, StoreError> {
        Ok(user_state::Entity::find_by_id(user.0)
            .one(self.reader())
            .await
            .store()?
            .is_some())
    }

    async fn admins(&self) -> Result<Vec<AdminContact>, StoreError> {
        let rows: Vec<(Uuid, String)> = users::Entity::find()
            .select_only()
            .column(users::Column::Id)
            .column(users::Column::Email)
            .filter(users::Column::Role.eq(users::ROLE_ADMIN))
            .order_by_asc(users::Column::CreatedAt)
            .order_by_asc(users::Column::Id)
            .into_tuple()
            .all(self.reader())
            .await
            .store()?;
        rows.into_iter()
            .map(|(id, email)| {
                Ok(AdminContact {
                    id: UserId(id),
                    email: Email::parse(&email).map_err(|_| corrupt("email"))?,
                })
            })
            .collect()
    }

    async fn sole_owned_spaces(&self, user: UserId) -> Result<Vec<SpaceId>, StoreError> {
        let db = self.reader();
        let mine: Vec<Uuid> = members::Entity::find()
            .select_only()
            .column(members::Column::SpaceId)
            .filter(members::Column::UserId.eq(user.0))
            .filter(members::Column::Role.eq("owner"))
            .filter(members::Column::State.eq("confirmed"))
            .into_tuple()
            .all(db)
            .await
            .store()?;
        if mine.is_empty() {
            return Ok(Vec::new());
        }
        let owners: Vec<(Uuid, Uuid)> = members::Entity::find()
            .select_only()
            .column(members::Column::SpaceId)
            .column(members::Column::UserId)
            .filter(members::Column::SpaceId.is_in(mine.clone()))
            .filter(members::Column::Role.eq("owner"))
            .filter(members::Column::State.eq("confirmed"))
            .into_tuple()
            .all(db)
            .await
            .store()?;
        let mut count: HashMap<Uuid, usize> = HashMap::new();
        for (space, _) in owners {
            *count.entry(space).or_default() += 1;
        }
        Ok(mine
            .into_iter()
            .filter(|space| count.get(space).copied().unwrap_or(0) <= 1)
            .map(SpaceId)
            .collect())
    }

    async fn erase_user(&self, user: UserId) -> Result<(), StoreError> {
        let txn = self.writer().begin().await.store()?;
        let outcome = erase_in(&txn, user).await;
        finish(txn, outcome, "erasing an account").await
    }

    async fn cancel_pending_erasure(&self, user: UserId) -> Result<bool, StoreError> {
        let removed = pending_erasures::Entity::delete_by_id(user.0)
            .exec(self.writer())
            .await
            .store()?;
        Ok(removed.rows_affected > 0)
    }

    async fn user_counts(&self) -> Result<UserCounts, StoreError> {
        let db = self.reader();
        Ok(UserCounts {
            users: users::Entity::find().count(db).await.store()?,
            admins: users::Entity::find()
                .filter(users::Column::Role.eq(users::ROLE_ADMIN))
                .count(db)
                .await
                .store()?,
            disabled: user_state::Entity::find().count(db).await.store()?,
            devices: devices::Entity::find().count(db).await.store()?,
        })
    }
}

/// Everything of one account, in one transaction. Vault rows (items, their changes and
/// siblings, the sync horizon) go with it; the files of its attachments are left for the orphan
/// purge, which removes an attachment whose item is gone.
async fn erase_in(txn: &DatabaseTransaction, user: UserId) -> Result<(), StoreError> {
    let Some(account) = users::Entity::find_by_id(user.0).one(txn).await.store()? else {
        return Err(StoreError::NotFound);
    };
    let owner_type = i16::from(Owner::TYPE_USER);

    items::Entity::delete_many()
        .filter(items::Column::OwnerType.eq(owner_type))
        .filter(items::Column::OwnerId.eq(user.0))
        .exec(txn)
        .await
        .store()?;
    changes::Entity::delete_many()
        .filter(changes::Column::OwnerType.eq(owner_type))
        .filter(changes::Column::OwnerId.eq(user.0))
        .exec(txn)
        .await
        .store()?;
    item_siblings::Entity::delete_many()
        .filter(item_siblings::Column::OwnerType.eq(owner_type))
        .filter(item_siblings::Column::OwnerId.eq(user.0))
        .exec(txn)
        .await
        .store()?;
    sync_horizon::Entity::delete_many()
        .filter(sync_horizon::Column::OwnerType.eq(owner_type))
        .filter(sync_horizon::Column::OwnerId.eq(user.0))
        .exec(txn)
        .await
        .store()?;
    crate::tables::signed_writes::Entity::delete_many()
        .filter(crate::tables::signed_writes::Column::OwnerType.eq(owner_type))
        .filter(crate::tables::signed_writes::Column::OwnerId.eq(user.0))
        .exec(txn)
        .await
        .store()?;

    // Spaces: the account's rows and the keys sealed to it.
    space_recovery::Entity::delete_many()
        .filter(space_recovery::Column::UserId.eq(user.0))
        .exec(txn)
        .await
        .store()?;
    members::Entity::delete_many()
        .filter(members::Column::UserId.eq(user.0))
        .exec(txn)
        .await
        .store()?;
    group_members::Entity::delete_many()
        .filter(group_members::Column::UserId.eq(user.0))
        .exec(txn)
        .await
        .store()?;
    collection_keys::Entity::delete_many()
        .filter(collection_keys::Column::UserId.eq(user.0))
        .exec(txn)
        .await
        .store()?;
    collection_grants::Entity::delete_many()
        .filter(collection_grants::Column::GranteeType.eq(GRANTEE_MEMBER))
        .filter(collection_grants::Column::GranteeId.eq(user.0))
        .exec(txn)
        .await
        .store()?;

    // Emergency access: what the account granted goes; where it is the contact, the contact is
    // cleared, as the foreign key would do.
    emergency_access::Entity::delete_many()
        .filter(emergency_access::Column::GrantorId.eq(user.0))
        .exec(txn)
        .await
        .store()?;
    emergency_access::Entity::update_many()
        .set(emergency_access::ActiveModel {
            grantee_id: Set(None),
            ..Default::default()
        })
        .filter(emergency_access::Column::GranteeId.eq(user.0))
        .exec(txn)
        .await
        .store()?;

    // Sessions and sign-in methods.
    let device_ids: Vec<Uuid> = devices::Entity::find()
        .select_only()
        .column(devices::Column::Id)
        .filter(devices::Column::UserId.eq(user.0))
        .into_tuple()
        .all(txn)
        .await
        .store()?;
    if !device_ids.is_empty() {
        device_key_copies::Entity::delete_many()
            .filter(device_key_copies::Column::DeviceId.is_in(device_ids))
            .exec(txn)
            .await
            .store()?;
    }
    auth_requests::Entity::delete_many()
        .filter(auth_requests::Column::UserId.eq(user.0))
        .exec(txn)
        .await
        .store()?;
    refresh_tokens::Entity::delete_many()
        .filter(refresh_tokens::Column::UserId.eq(user.0))
        .exec(txn)
        .await
        .store()?;
    devices::Entity::delete_many()
        .filter(devices::Column::UserId.eq(user.0))
        .exec(txn)
        .await
        .store()?;
    two_factor::Entity::delete_many()
        .filter(two_factor::Column::UserId.eq(user.0))
        .exec(txn)
        .await
        .store()?;
    bw_accounts::Entity::delete_by_id(user.0)
        .exec(txn)
        .await
        .store()?;
    sso::identities::Entity::delete_many()
        .filter(sso::identities::Column::UserId.eq(user.0))
        .exec(txn)
        .await
        .store()?;
    user_state::Entity::delete_by_id(user.0)
        .exec(txn)
        .await
        .store()?;
    invites::Entity::delete_many()
        .filter(invites::Column::Email.eq(account.email.clone()))
        .exec(txn)
        .await
        .store()?;
    // An erasure the owner had scheduled is moot once the account is gone.
    pending_erasures::Entity::delete_by_id(user.0)
        .exec(txn)
        .await
        .store()?;
    users::Entity::delete_by_id(user.0)
        .exec(txn)
        .await
        .store()?;
    Ok(())
}

// ---------------------------------------------------------------------------------------------
// Invitations

impl InviteRepo for SqlStore {
    async fn insert_invite(&self, invite: &Invite) -> Result<(), StoreError> {
        invites::Entity::insert(invites::active(invite))
            .exec(self.writer())
            .await
            .store()?;
        Ok(())
    }

    async fn invites(&self) -> Result<Vec<Invite>, StoreError> {
        invites::Entity::find()
            .order_by_desc(invites::Column::CreatedAt)
            .order_by_asc(invites::Column::Id)
            .all(self.reader())
            .await
            .store()?
            .into_iter()
            .map(invites::Model::into_domain)
            .collect()
    }

    async fn invite(&self, id: Uuid) -> Result<Option<Invite>, StoreError> {
        invites::Entity::find_by_id(id)
            .one(self.reader())
            .await
            .store()?
            .map(invites::Model::into_domain)
            .transpose()
    }

    async fn update_invite(&self, invite: &Invite) -> Result<(), StoreError> {
        let row = invites::ActiveModel {
            id: NotSet,
            ..invites::active(invite)
        };
        invites::Entity::update_many()
            .set(row)
            .filter(invites::Column::Id.eq(invite.id))
            .exec(self.writer())
            .await
            .store()?;
        Ok(())
    }

    async fn remove_invite(&self, id: Uuid) -> Result<(), StoreError> {
        invites::Entity::delete_by_id(id)
            .exec(self.writer())
            .await
            .store()?;
        Ok(())
    }

    async fn invite_by_token(&self, token_hash: [u8; 32]) -> Result<Option<Invite>, StoreError> {
        invites::Entity::find()
            .filter(invites::Column::TokenHash.eq(token_hash.to_vec()))
            .one(self.reader())
            .await
            .store()?
            .map(invites::Model::into_domain)
            .transpose()
    }

    async fn pending_invites(&self, now: OffsetDateTime) -> Result<u64, StoreError> {
        invites::Entity::find()
            .filter(invites::Column::AcceptedAt.is_null())
            .filter(invites::Column::ExpiresAt.gt(utc(now)))
            .count(self.reader())
            .await
            .store()
    }
}

// ---------------------------------------------------------------------------------------------
// Spaces

impl SqlStore {
    async fn space_rows(
        &self,
        spaces: Vec<spaces::Model>,
    ) -> Result<Vec<AdminSpaceRow>, StoreError> {
        let db = self.reader();
        let ids: Vec<Uuid> = spaces.iter().map(|s| s.id).collect();
        if ids.is_empty() {
            return Ok(Vec::new());
        }
        let member_rows: Vec<(Uuid, Uuid, String, String)> = members::Entity::find()
            .select_only()
            .column(members::Column::SpaceId)
            .column(members::Column::UserId)
            .column(members::Column::Role)
            .column(members::Column::State)
            .filter(members::Column::SpaceId.is_in(ids.clone()))
            .into_tuple()
            .all(db)
            .await
            .store()?;
        let owner_ids: BTreeSet<Uuid> = member_rows
            .iter()
            .filter(|(_, _, role, state)| role == "owner" && state == "confirmed")
            .map(|(_, user, ..)| *user)
            .collect();
        let emails: HashMap<Uuid, String> = if owner_ids.is_empty() {
            HashMap::new()
        } else {
            users::Entity::find()
                .select_only()
                .column(users::Column::Id)
                .column(users::Column::Email)
                .filter(users::Column::Id.is_in(owner_ids))
                .into_tuple::<(Uuid, String)>()
                .all(db)
                .await
                .store()?
                .into_iter()
                .collect()
        };
        let item_counts: HashMap<Uuid, i64> = items::Entity::find()
            .select_only()
            .column(items::Column::OwnerId)
            .column_as(items::Column::Id.count(), "live")
            .filter(items::Column::OwnerType.eq(i16::from(Owner::TYPE_SPACE)))
            .filter(items::Column::OwnerId.is_in(ids))
            .filter(items::Column::DeletedAt.is_null())
            .group_by(items::Column::OwnerId)
            .into_tuple::<(Uuid, i64)>()
            .all(db)
            .await
            .store()?
            .into_iter()
            .collect();

        let mut by_space: BTreeMap<Uuid, (u32, u32, Vec<SpaceOwner>)> = BTreeMap::new();
        for (space, user, role, state) in member_rows {
            let entry = by_space.entry(space).or_default();
            entry.0 = entry.0.saturating_add(1);
            if state == "confirmed" {
                entry.1 = entry.1.saturating_add(1);
                if role == "owner" {
                    entry.2.push(SpaceOwner {
                        user: UserId(user),
                        email: emails.get(&user).cloned().unwrap_or_default(),
                    });
                }
            }
        }
        Ok(spaces
            .into_iter()
            .map(|space| {
                let (members, confirmed, owners) = by_space.remove(&space.id).unwrap_or_default();
                AdminSpaceRow {
                    id: SpaceId(space.id),
                    created_at: space.created_at,
                    members,
                    confirmed,
                    owners,
                    live_items: item_counts
                        .get(&space.id)
                        .map_or(0, |n| u64::try_from(*n).unwrap_or(0)),
                    keys_pending_since: space.keys_pending_since,
                }
            })
            .collect())
    }
}

impl AdminSpaceRepo for SqlStore {
    async fn list_spaces(&self, limit: u32, offset: u64) -> Result<SpacePage, StoreError> {
        let db = self.reader();
        let total = spaces::Entity::find().count(db).await.store()?;
        let page = spaces::Entity::find()
            .order_by_asc(spaces::Column::CreatedAt)
            .order_by_asc(spaces::Column::Id)
            .limit(u64::from(limit))
            .offset(offset)
            .all(db)
            .await
            .store()?;
        Ok(SpacePage {
            spaces: self.space_rows(page).await?,
            total,
        })
    }

    async fn space_row(&self, id: SpaceId) -> Result<Option<AdminSpaceRow>, StoreError> {
        let Some(space) = spaces::Entity::find_by_id(id.0)
            .one(self.reader())
            .await
            .store()?
        else {
            return Ok(None);
        };
        Ok(self.space_rows(vec![space]).await?.pop())
    }

    async fn live_items(&self) -> Result<u64, StoreError> {
        items::Entity::find()
            .filter(items::Column::DeletedAt.is_null())
            .count(self.reader())
            .await
            .store()
    }
}

// ---------------------------------------------------------------------------------------------
// Events

fn record_of(row: event_rows::Model, emails: &HashMap<Uuid, String>) -> EventRecord {
    EventRecord {
        id: row.id,
        at: row.at,
        actor: row.actor.map(UserId),
        actor_email: row.actor.and_then(|a| emails.get(&a).cloned()),
        device: row.device.map(DeviceId),
        action: row.action,
        target: row.target,
        ip: row.ip,
    }
}

fn event_condition(filter: &EventFilter, after: Option<&EventCursor>) -> Condition {
    let mut all = Condition::all();
    if let Some(actor) = filter.actor {
        all = all.add(event_rows::Column::Actor.eq(actor.0));
    }
    if let Some(action) = &filter.action {
        all = match action.strip_suffix('*') {
            Some(prefix) => all.add(event_rows::Column::Action.starts_with(prefix)),
            None => all.add(event_rows::Column::Action.eq(action.as_str())),
        };
    }
    if let Some(target) = &filter.target {
        all = all.add(event_rows::Column::Target.contains(target.as_str()));
    }
    if let Some(from) = filter.from {
        all = all.add(event_rows::Column::At.gte(utc(from)));
    }
    if let Some(to) = filter.to {
        all = all.add(event_rows::Column::At.lte(utc(to)));
    }
    if let Some(cursor) = after {
        let at = utc(cursor.at);
        all = all.add(
            Condition::any().add(event_rows::Column::At.lt(at)).add(
                Condition::all()
                    .add(event_rows::Column::At.eq(at))
                    .add(event_rows::Column::Id.lt(cursor.id)),
            ),
        );
    }
    all
}

impl AdminEventRepo for SqlStore {
    async fn record_admin_event(&self, event: AdminEvent) -> Result<(), StoreError> {
        event_rows::Entity::insert(event_rows::ActiveModel {
            id: Set(Uuid::now_v7()),
            actor: Set(event.actor.map(|u| u.0)),
            device: Set(event.device.map(|d| d.0)),
            action: Set(event.action),
            target: Set(event.target),
            at: Set(utc(event.at)),
            ip: Set(event.ip),
        })
        .exec(self.writer())
        .await
        .store()?;
        Ok(())
    }

    async fn query_events(
        &self,
        filter: &EventFilter,
        after: Option<&EventCursor>,
        limit: u32,
    ) -> Result<EventPage, StoreError> {
        let db = self.reader();
        let mut rows = event_rows::Entity::find()
            .filter(event_condition(filter, after))
            .order_by_desc(event_rows::Column::At)
            .order_by_desc(event_rows::Column::Id)
            .limit(u64::from(limit) + 1)
            .all(db)
            .await
            .store()?;
        let more = rows.len() > limit as usize;
        rows.truncate(limit as usize);
        let next = if more {
            rows.last().map(|row| EventCursor {
                at: row.at,
                id: row.id,
            })
        } else {
            None
        };
        let actors: BTreeSet<Uuid> = rows.iter().filter_map(|row| row.actor).collect();
        let emails: HashMap<Uuid, String> = if actors.is_empty() {
            HashMap::new()
        } else {
            users::Entity::find()
                .select_only()
                .column(users::Column::Id)
                .column(users::Column::Email)
                .filter(users::Column::Id.is_in(actors))
                .into_tuple::<(Uuid, String)>()
                .all(db)
                .await
                .store()?
                .into_iter()
                .collect()
        };
        Ok(EventPage {
            events: rows
                .into_iter()
                .map(|row| record_of(row, &emails))
                .collect(),
            next,
        })
    }

    async fn count_events_since(&self, since: OffsetDateTime) -> Result<u64, StoreError> {
        event_rows::Entity::find()
            .filter(event_rows::Column::At.gte(utc(since)))
            .count(self.reader())
            .await
            .store()
    }

    async fn purge_events_before(&self, before: OffsetDateTime) -> Result<u64, StoreError> {
        let result = event_rows::Entity::delete_many()
            .filter(event_rows::Column::At.lt(utc(before)))
            .exec(self.writer())
            .await
            .store()?;
        Ok(result.rows_affected)
    }
}

// ---------------------------------------------------------------------------------------------
// Settings

impl SettingsRepo for SqlStore {
    async fn settings_with_prefix(
        &self,
        prefix: &str,
    ) -> Result<Vec<(String, String)>, StoreError> {
        Ok(settings::Entity::find()
            .order_by_asc(settings::Column::Key)
            .all(self.reader())
            .await
            .store()?
            .into_iter()
            .filter(|row| row.key.starts_with(prefix))
            .map(|row| (row.key, row.value))
            .collect())
    }

    async fn put_setting(&self, key: &str, value: &str) -> Result<(), StoreError> {
        let conflict = OnConflict::column(settings::Column::Key)
            .update_column(settings::Column::Value)
            .to_owned();
        let inserted = settings::Entity::insert(settings::ActiveModel {
            key: Set(key.to_owned()),
            value: Set(value.to_owned()),
        })
        .on_conflict(conflict)
        .exec(self.writer())
        .await;
        match inserted {
            Ok(_) => Ok(()),
            // MySQL counts a replaced row with identical values as zero rows affected.
            Err(sea_orm::DbErr::RecordNotInserted) => Ok(()),
            Err(err) => Err(map_db(err)),
        }
    }

    async fn delete_setting(&self, key: &str) -> Result<(), StoreError> {
        settings::Entity::delete_by_id(key.to_owned())
            .exec(self.writer())
            .await
            .store()?;
        Ok(())
    }
}

// ---------------------------------------------------------------------------------------------
// Compliance requests

const OPEN_STATUSES: [&str; 2] = ["open", "in-progress"];

impl ComplianceRepo for SqlStore {
    async fn insert_compliance_request(
        &self,
        request: &ComplianceRequest,
    ) -> Result<(), StoreError> {
        requests::Entity::insert(requests::active(request))
            .exec(self.writer())
            .await
            .store()?;
        Ok(())
    }

    async fn compliance_request(&self, id: Uuid) -> Result<Option<ComplianceRequest>, StoreError> {
        requests::Entity::find_by_id(id)
            .one(self.reader())
            .await
            .store()?
            .map(requests::Model::into_domain)
            .transpose()
    }

    async fn update_compliance_request(
        &self,
        request: &ComplianceRequest,
    ) -> Result<(), StoreError> {
        let row = requests::ActiveModel {
            id: NotSet,
            ..requests::active(request)
        };
        requests::Entity::update_many()
            .set(row)
            .filter(requests::Column::Id.eq(request.id))
            .exec(self.writer())
            .await
            .store()?;
        Ok(())
    }

    async fn compliance_requests(
        &self,
        open_only: bool,
    ) -> Result<Vec<ComplianceRequest>, StoreError> {
        let mut select = requests::Entity::find();
        if open_only {
            select = select.filter(requests::Column::Status.is_in(OPEN_STATUSES));
        }
        select
            .order_by_asc(requests::Column::DueAt)
            .order_by_asc(requests::Column::Id)
            .all(self.reader())
            .await
            .store()?
            .into_iter()
            .map(requests::Model::into_domain)
            .collect()
    }

    async fn compliance_counts(&self, now: OffsetDateTime) -> Result<ComplianceCounts, StoreError> {
        let db = self.reader();
        let open = requests::Entity::find()
            .filter(requests::Column::Status.is_in(OPEN_STATUSES))
            .count(db)
            .await
            .store()?;
        let overdue = requests::Entity::find()
            .filter(requests::Column::Status.is_in(OPEN_STATUSES))
            .filter(requests::Column::DueAt.lt(utc(now)))
            .count(db)
            .await
            .store()?;
        Ok(ComplianceCounts { open, overdue })
    }
}
