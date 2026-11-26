//! The privacy ports on `SqlStore`: the retention settings, the event and sign-in logs with their
//! addresses, what an export lists, erasing an account, and the retention job's deletes.
//!
//! Erasing an account is one transaction: nothing is half erased. Only the transaction's own
//! handle is used inside it: on SQLite the writer pool holds one connection, so a call through
//! `self.writer()` while the transaction is open would wait for itself.

use crate::convert::{corrupt, utc};
use crate::error::{StoreResult, is_unique_violation, map_db};
use crate::store::SqlStore;
use crate::tables::attachments;
use crate::tables::changes;
use crate::tables::events;
use crate::tables::federation::{
    change_meta, home_records, item_siblings, peer_cursors, vault_federation,
};
use crate::tables::federation_logs::peer_events;
use crate::tables::federation_wiring::{federation_erasures, replicated_accounts, vault_offers};
use crate::tables::items;
use crate::tables::items::owner_parts;
use crate::tables::pending_erasures;
use crate::tables::settings;
use crate::tables::sign_in_log;
use crate::tables::space_recovery;
use crate::tables::space_tables::{
    collection_grants, collection_keys, collections, group_members, groups, item_collections,
    members, spaces,
};
use crate::tables::sso::identities;
use crate::tables::sync_horizon;
use crate::tables::{
    auth_requests, bw_accounts, bw_user_key_ids, device_key_copies, devices, emergency_access,
};
use crate::tables::{dedup_owners, item_tags};
use crate::tables::{
    refresh_tokens, second_step_attempts, two_factor, two_factor_recovery, two_step_versions, users,
};
use kemlock_app::ports::{DeviceRepo, Event, ItemStore, StoreError, TwoFactorRepo};
use kemlock_app::privacy::{
    AccountData, AccountEraser, ErasedRows, NewSignIn, PrivacyLog, PrivacySettings, PurgedTrash,
    RetentionStore, TwoFactorInfo,
};
use kemlock_app::spaces::SpaceRepo;
use kemlock_domain::privacy::{Retention, SignInEntry, StoredEvent, stored_ip};
use kemlock_domain::spaces::Member;
use kemlock_domain::{
    BlobId, Device, Item, ItemDraft, ItemId, Owner, ServerId, SpaceId, User, UserId, VersionVector,
};
use kemlock_federation::extra::VaultErased;
use kemlock_federation::home::Policy;
use sea_orm::ActiveValue::Set;
use sea_orm::sea_query::{Expr, OnConflict};
use sea_orm::{
    ColumnTrait, Condition, DatabaseTransaction, EntityTrait, QueryFilter, QueryOrder, QuerySelect,
    TransactionTrait,
};
use std::collections::HashMap;
use std::net::IpAddr;
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;
use uuid::Uuid;

/// The `settings` key of the retention settings, as JSON.
const RETENTION_KEY: &str = "privacy.retention";

/// What replaces a name or an email in an event's target.
const ERASED: &str = "[erased]";

/// How many ids go into one `IN (...)` list.
const CHUNK: usize = 500;

impl SqlStore {
    /// A small named value the server keeps for itself (`settings`), if there is one.
    pub async fn setting(&self, key: &str) -> Result<Option<String>, StoreError> {
        Ok(settings::Entity::find_by_id(key.to_owned())
            .one(self.reader())
            .await
            .store()?
            .map(|row| row.value))
    }

    /// Saves a named value, replacing what was there.
    pub async fn put_setting(&self, key: &str, value: &str) -> Result<(), StoreError> {
        let row = settings::ActiveModel {
            key: sea_orm::ActiveValue::Set(key.to_owned()),
            value: sea_orm::ActiveValue::Set(value.to_owned()),
        };
        let conflict = OnConflict::column(settings::Column::Key)
            .update_column(settings::Column::Value)
            .to_owned();
        match settings::Entity::insert(row)
            .on_conflict(conflict)
            .exec(self.writer())
            .await
        {
            Ok(_) => Ok(()),
            // MySQL counts a replaced row with identical values as zero rows affected.
            Err(sea_orm::DbErr::RecordNotInserted) => Ok(()),
            Err(err) if is_unique_violation(&err) => Err(StoreError::Duplicate),
            Err(err) => Err(map_db(err)),
        }
    }
}

impl PrivacySettings for SqlStore {
    async fn retention(&self) -> Result<Retention, StoreError> {
        let mut retention = match self.setting(RETENTION_KEY).await? {
            None => Retention::default(),
            Some(text) => serde_json::from_str(&text).map_err(|_| corrupt("retention settings"))?,
        };
        self.overlay_retention(&mut retention);
        Ok(retention)
    }

    async fn save_retention(&self, retention: &Retention) -> Result<(), StoreError> {
        retention
            .validate()
            .map_err(|e| StoreError::Backend(format!("retention settings refused: {e}")))?;
        let text = serde_json::to_string(retention)
            .map_err(|e| StoreError::Backend(format!("retention settings: {e}")))?;
        self.put_setting(RETENTION_KEY, &text).await
    }
}

impl PrivacyLog for SqlStore {
    async fn record_event(&self, event: Event, ip: Option<IpAddr>) -> Result<(), StoreError> {
        let stored = match ip {
            Some(ip) => Some(stored_ip(ip, &PrivacySettings::retention(self).await?)),
            None => None,
        };
        events::Entity::insert(events::active_with_ip(event, stored))
            .exec(self.writer())
            .await
            .store()?;
        Ok(())
    }

    async fn record_sign_in(&self, entry: NewSignIn) -> Result<(), StoreError> {
        let stored = match entry.ip {
            Some(ip) => Some(stored_ip(ip, &PrivacySettings::retention(self).await?)),
            None => None,
        };
        sign_in_log::Entity::insert(sign_in_log::active(&entry, stored))
            .exec(self.writer())
            .await
            .store()?;
        Ok(())
    }

    async fn events_of(&self, user: UserId) -> Result<Vec<StoredEvent>, StoreError> {
        let rows = events::Entity::find()
            .filter(events::Column::Actor.eq(user.0))
            .order_by_asc(events::Column::At)
            .order_by_asc(events::Column::Id)
            .all(self.reader())
            .await
            .store()?;
        Ok(rows.into_iter().map(stored_event).collect())
    }

    async fn sign_ins_of(&self, user: UserId) -> Result<Vec<SignInEntry>, StoreError> {
        sign_in_log::Entity::find()
            .filter(sign_in_log::Column::UserId.eq(user.0))
            .order_by_asc(sign_in_log::Column::At)
            .order_by_asc(sign_in_log::Column::Id)
            .all(self.reader())
            .await
            .store()?
            .into_iter()
            .map(sign_in_log::Model::into_domain)
            .collect()
    }

    async fn events_between(
        &self,
        from: OffsetDateTime,
        to: OffsetDateTime,
    ) -> Result<Vec<StoredEvent>, StoreError> {
        let rows = events::Entity::find()
            .filter(events::Column::At.gte(utc(from)))
            .filter(events::Column::At.lt(utc(to)))
            .order_by_asc(events::Column::At)
            .order_by_asc(events::Column::Id)
            .all(self.reader())
            .await
            .store()?;
        Ok(rows.into_iter().map(stored_event).collect())
    }

    async fn sign_ins_between(
        &self,
        from: OffsetDateTime,
        to: OffsetDateTime,
    ) -> Result<Vec<SignInEntry>, StoreError> {
        sign_in_log::Entity::find()
            .filter(sign_in_log::Column::At.gte(utc(from)))
            .filter(sign_in_log::Column::At.lt(utc(to)))
            .order_by_asc(sign_in_log::Column::At)
            .order_by_asc(sign_in_log::Column::Id)
            .all(self.reader())
            .await
            .store()?
            .into_iter()
            .map(sign_in_log::Model::into_domain)
            .collect()
    }
}

fn stored_event(row: events::Model) -> StoredEvent {
    StoredEvent {
        id: row.id,
        actor: row.actor.map(UserId),
        device: row.device.map(kemlock_domain::DeviceId),
        action: row.action,
        target: row.target,
        at: row.at,
        ip: row.ip,
    }
}

/// How many items one page of an export reads.
const VAULT_PAGE: u32 = 500;

impl AccountData for SqlStore {
    async fn devices(&self, user: UserId) -> Result<Vec<Device>, StoreError> {
        DeviceRepo::list(self, user).await
    }

    async fn vault(&self, user: UserId) -> Result<Vec<Item>, StoreError> {
        let owner = [Owner::User(user)];
        let mut cursor = VersionVector::new();
        let mut all = Vec::new();
        loop {
            let page = ItemStore::changes_since(self, &owner, &cursor, VAULT_PAGE).await?;
            all.extend(page.items);
            if !page.more {
                return Ok(all);
            }
            cursor = page.next;
        }
    }

    async fn memberships(&self, user: UserId) -> Result<Vec<Member>, StoreError> {
        SpaceRepo::memberships(self, user).await
    }

    async fn two_factor(&self, user: UserId) -> Result<Vec<TwoFactorInfo>, StoreError> {
        Ok(TwoFactorRepo::list(self, user)
            .await?
            .into_iter()
            .map(|t| TwoFactorInfo {
                method: t.method.as_str().to_owned(),
                enabled: t.enabled,
                created_at: t.created_at,
            })
            .collect())
    }
}

// ---------------------------------------------------------------------------------------------
// Erasing an account.

/// The text with every needle replaced by `[erased]`, matching without regard to ASCII case;
/// `None` when no needle was in it.
fn redact(text: &str, needles: &[String]) -> Option<String> {
    let mut out = text.to_owned();
    let mut changed = false;
    for needle in needles.iter().filter(|n| !n.is_empty()) {
        let needle = needle.to_ascii_lowercase();
        let mut from = 0;
        while from <= out.len() {
            let Some(found) = out.to_ascii_lowercase()[from..].find(&needle) else {
                break;
            };
            let at = from + found;
            out.replace_range(at..at + needle.len(), ERASED);
            from = at + ERASED.len();
            changed = true;
        }
    }
    changed.then_some(out)
}

/// The `<cipher id>/<attachment id>` keys of the files of a Bitwarden-API cipher, from its stored
/// JSON.
fn cipher_file_keys(bytes: &[u8]) -> Vec<String> {
    let Ok(cipher) = serde_json::from_slice::<serde_json::Value>(bytes) else {
        return Vec::new();
    };
    let Some(id) = cipher.get("id").and_then(serde_json::Value::as_str) else {
        return Vec::new();
    };
    cipher
        .get("attachments")
        .and_then(serde_json::Value::as_array)
        .map(|list| {
            list.iter()
                .filter_map(|a| a.get("id").and_then(serde_json::Value::as_str))
                .map(|attachment| format!("{id}/{attachment}"))
                .collect()
        })
        .unwrap_or_default()
}

/// When a Bitwarden-API cipher was put in the trash, from its stored JSON.
fn trashed_at(bytes: &[u8]) -> Option<OffsetDateTime> {
    let cipher = serde_json::from_slice::<serde_json::Value>(bytes).ok()?;
    let text = cipher.get("deletedDate")?.as_str()?;
    OffsetDateTime::parse(text, &Rfc3339).ok()
}

/// Deletes the rows of one owner (a person's vault or a space's items): attachments, items, the
/// change log and what hangs on it, and the federation rows. Files that need deleting are added to
/// `out`.
async fn delete_owner_data(
    txn: &DatabaseTransaction,
    owner_type: i16,
    owner_id: Uuid,
    me: ServerId,
    out: &mut ErasedRows,
) -> Result<(), StoreError> {
    let files = attachments::Entity::find()
        .filter(attachments::Column::OwnerType.eq(owner_type))
        .filter(attachments::Column::OwnerId.eq(owner_id))
        .all(txn)
        .await
        .store()?;
    out.blobs
        .extend(files.iter().map(|f| BlobId::from_uuid(f.blob_id)));

    let ciphers = items::Entity::find()
        .filter(items::Column::OwnerType.eq(owner_type))
        .filter(items::Column::OwnerId.eq(owner_id))
        .filter(items::Column::Format.eq("bw"))
        .filter(items::Column::Ciphertext.is_not_null())
        .all(txn)
        .await
        .store()?;
    for row in &ciphers {
        if let Some(bytes) = &row.ciphertext {
            out.cipher_files.extend(cipher_file_keys(bytes));
        }
    }

    attachments::Entity::delete_many()
        .filter(attachments::Column::OwnerType.eq(owner_type))
        .filter(attachments::Column::OwnerId.eq(owner_id))
        .exec(txn)
        .await
        .store()?;

    // The lineage rows of the owner's changes are keyed by (origin, seq).
    let log = changes::Entity::find()
        .filter(changes::Column::OwnerType.eq(owner_type))
        .filter(changes::Column::OwnerId.eq(owner_id))
        .all(txn)
        .await
        .store()?;
    let mut by_origin: HashMap<Uuid, Vec<i64>> = HashMap::new();
    for change in &log {
        by_origin.entry(change.origin).or_default().push(change.seq);
    }
    for (origin, seqs) in by_origin {
        for chunk in seqs.chunks(CHUNK) {
            change_meta::Entity::delete_many()
                .filter(change_meta::Column::Origin.eq(origin))
                .filter(change_meta::Column::Seq.is_in(chunk.to_vec()))
                .exec(txn)
                .await
                .store()?;
        }
    }

    let removed = items::Entity::delete_many()
        .filter(items::Column::OwnerType.eq(owner_type))
        .filter(items::Column::OwnerId.eq(owner_id))
        .exec(txn)
        .await
        .store()?;
    out.items += removed.rows_affected;
    changes::Entity::delete_many()
        .filter(changes::Column::OwnerType.eq(owner_type))
        .filter(changes::Column::OwnerId.eq(owner_id))
        .exec(txn)
        .await
        .store()?;
    sync_horizon::Entity::delete_many()
        .filter(sync_horizon::Column::OwnerType.eq(owner_type))
        .filter(sync_horizon::Column::OwnerId.eq(owner_id))
        .exec(txn)
        .await
        .store()?;
    crate::tables::signed_writes::Entity::delete_many()
        .filter(crate::tables::signed_writes::Column::OwnerType.eq(owner_type))
        .filter(crate::tables::signed_writes::Column::OwnerId.eq(owner_id))
        .exec(txn)
        .await
        .store()?;
    // A vault this server is the home of: its replicas hold copies that must go too. The erasure
    // is queued here, in this transaction, because the settings that name the replicas are
    // deleted just below; the replication job tells each peer in its next session.
    if let Some(settings) = vault_federation::Entity::find_by_id((owner_type, owner_id))
        .one(txn)
        .await
        .store()?
        && settings.home == me.0
        && settings.policy == Policy::Federated.as_str()
    {
        let queued_at = OffsetDateTime::now_utc().unix_timestamp();
        for peer in settings.replicas.as_chunks::<16>().0 {
            let peer = Uuid::from_bytes(*peer);
            let queued = federation_erasures::Entity::insert(federation_erasures::ActiveModel {
                peer: Set(peer),
                owner_type: Set(owner_type),
                owner_id: Set(owner_id),
                queued_at: Set(queued_at),
            })
            .on_conflict(
                OnConflict::columns([
                    federation_erasures::Column::Peer,
                    federation_erasures::Column::OwnerType,
                    federation_erasures::Column::OwnerId,
                ])
                .do_nothing()
                .to_owned(),
            )
            .exec(txn)
            .await;
            match queued {
                Ok(_) | Err(sea_orm::DbErr::RecordNotInserted) => {}
                Err(err) => return Err(map_db(err)),
            }
        }
    }
    item_siblings::Entity::delete_many()
        .filter(item_siblings::Column::OwnerType.eq(owner_type))
        .filter(item_siblings::Column::OwnerId.eq(owner_id))
        .exec(txn)
        .await
        .store()?;
    home_records::Entity::delete_many()
        .filter(home_records::Column::OwnerType.eq(owner_type))
        .filter(home_records::Column::OwnerId.eq(owner_id))
        .exec(txn)
        .await
        .store()?;
    peer_cursors::Entity::delete_many()
        .filter(peer_cursors::Column::OwnerType.eq(owner_type))
        .filter(peer_cursors::Column::OwnerId.eq(owner_id))
        .exec(txn)
        .await
        .store()?;
    vault_federation::Entity::delete_many()
        .filter(vault_federation::Column::OwnerType.eq(owner_type))
        .filter(vault_federation::Column::OwnerId.eq(owner_id))
        .exec(txn)
        .await
        .store()?;
    Ok(())
}

/// Deletes a space and everything in it.
pub(super) async fn delete_space(
    txn: &DatabaseTransaction,
    space: Uuid,
    me: ServerId,
    out: &mut ErasedRows,
) -> Result<(), StoreError> {
    let group_ids: Vec<Uuid> = groups::Entity::find()
        .filter(groups::Column::SpaceId.eq(space))
        .all(txn)
        .await
        .store()?
        .into_iter()
        .map(|g| g.id)
        .collect();
    for chunk in group_ids.chunks(CHUNK) {
        group_members::Entity::delete_many()
            .filter(group_members::Column::GroupId.is_in(chunk.to_vec()))
            .exec(txn)
            .await
            .store()?;
    }
    groups::Entity::delete_many()
        .filter(groups::Column::SpaceId.eq(space))
        .exec(txn)
        .await
        .store()?;

    let collection_ids: Vec<Uuid> = collections::Entity::find()
        .filter(collections::Column::SpaceId.eq(space))
        .all(txn)
        .await
        .store()?
        .into_iter()
        .map(|c| c.id)
        .collect();
    for chunk in collection_ids.chunks(CHUNK) {
        collection_grants::Entity::delete_many()
            .filter(collection_grants::Column::CollectionId.is_in(chunk.to_vec()))
            .exec(txn)
            .await
            .store()?;
        collection_keys::Entity::delete_many()
            .filter(collection_keys::Column::CollectionId.is_in(chunk.to_vec()))
            .exec(txn)
            .await
            .store()?;
    }
    collections::Entity::delete_many()
        .filter(collections::Column::SpaceId.eq(space))
        .exec(txn)
        .await
        .store()?;
    item_collections::Entity::delete_many()
        .filter(item_collections::Column::SpaceId.eq(space))
        .exec(txn)
        .await
        .store()?;
    space_recovery::Entity::delete_many()
        .filter(space_recovery::Column::SpaceId.eq(space))
        .exec(txn)
        .await
        .store()?;
    members::Entity::delete_many()
        .filter(members::Column::SpaceId.eq(space))
        .exec(txn)
        .await
        .store()?;
    delete_owner_data(txn, i16::from(Owner::TYPE_SPACE), space, me, out).await?;
    spaces::Entity::delete_by_id(space)
        .exec(txn)
        .await
        .store()?;
    out.spaces_removed += 1;
    Ok(())
}

/// Spaces `user` owns alone while others (not revoked) are still in them.
async fn blocking<C: sea_orm::ConnectionTrait>(
    db: &C,
    user: Uuid,
) -> Result<Vec<SpaceId>, StoreError> {
    let owned = members::Entity::find()
        .filter(members::Column::UserId.eq(user))
        .filter(members::Column::Role.eq("owner"))
        .filter(members::Column::State.is_in(["accepted", "confirmed"]))
        .all(db)
        .await
        .store()?;
    let mut out = Vec::new();
    for mine in owned {
        let others = members::Entity::find()
            .filter(members::Column::SpaceId.eq(mine.space_id))
            .filter(members::Column::UserId.ne(user))
            .filter(members::Column::State.ne("revoked"))
            .all(db)
            .await
            .store()?;
        let another_owner = others
            .iter()
            .any(|o| o.role == "owner" && (o.state == "accepted" || o.state == "confirmed"));
        if !others.is_empty() && !another_owner {
            out.push(SpaceId(mine.space_id));
        }
    }
    Ok(out)
}

/// Everything of one account, in the caller's transaction.
async fn erase_in(
    txn: &DatabaseTransaction,
    user: &User,
    me: ServerId,
) -> Result<ErasedRows, StoreError> {
    let uid = user.id.0;
    if users::Entity::find_by_id(uid)
        .one(txn)
        .await
        .store()?
        .is_none()
    {
        return Err(StoreError::NotFound);
    }
    let mut out = ErasedRows::default();

    // Spaces: the account's place in each, and the spaces it was alone in.
    let places = members::Entity::find()
        .filter(members::Column::UserId.eq(uid))
        .all(txn)
        .await
        .store()?;
    for place in &places {
        let others = members::Entity::find()
            .filter(members::Column::SpaceId.eq(place.space_id))
            .filter(members::Column::UserId.ne(uid))
            .filter(members::Column::State.ne("revoked"))
            .all(txn)
            .await
            .store()?;
        if others.is_empty() {
            delete_space(txn, place.space_id, me, &mut out).await?;
            continue;
        }
        let group_ids: Vec<Uuid> = groups::Entity::find()
            .filter(groups::Column::SpaceId.eq(place.space_id))
            .all(txn)
            .await
            .store()?
            .into_iter()
            .map(|g| g.id)
            .collect();
        for chunk in group_ids.chunks(CHUNK) {
            group_members::Entity::delete_many()
                .filter(group_members::Column::UserId.eq(uid))
                .filter(group_members::Column::GroupId.is_in(chunk.to_vec()))
                .exec(txn)
                .await
                .store()?;
        }
        let collection_ids: Vec<Uuid> = collections::Entity::find()
            .filter(collections::Column::SpaceId.eq(place.space_id))
            .all(txn)
            .await
            .store()?
            .into_iter()
            .map(|c| c.id)
            .collect();
        for chunk in collection_ids.chunks(CHUNK) {
            collection_keys::Entity::delete_many()
                .filter(collection_keys::Column::UserId.eq(uid))
                .filter(collection_keys::Column::CollectionId.is_in(chunk.to_vec()))
                .exec(txn)
                .await
                .store()?;
            collection_grants::Entity::delete_many()
                .filter(
                    collection_grants::Column::GranteeType.eq(collection_grants::GRANTEE_MEMBER),
                )
                .filter(collection_grants::Column::GranteeId.eq(uid))
                .filter(collection_grants::Column::CollectionId.is_in(chunk.to_vec()))
                .exec(txn)
                .await
                .store()?;
        }
        space_recovery::Entity::delete_many()
            .filter(space_recovery::Column::SpaceId.eq(place.space_id))
            .filter(space_recovery::Column::UserId.eq(uid))
            .exec(txn)
            .await
            .store()?;
        members::Entity::delete_many()
            .filter(members::Column::SpaceId.eq(place.space_id))
            .filter(members::Column::UserId.eq(uid))
            .exec(txn)
            .await
            .store()?;
        out.space_memberships += 1;
    }

    // The account's own vault.
    delete_owner_data(txn, i16::from(Owner::TYPE_USER), uid, me, &mut out).await?;

    // Sessions, devices and what hangs on them.
    let device_ids: Vec<Uuid> = devices::Entity::find()
        .filter(devices::Column::UserId.eq(uid))
        .all(txn)
        .await
        .store()?
        .into_iter()
        .map(|d| d.id)
        .collect();
    out.refresh_tokens = refresh_tokens::Entity::delete_many()
        .filter(refresh_tokens::Column::UserId.eq(uid))
        .exec(txn)
        .await
        .store()?
        .rows_affected;
    for chunk in device_ids.chunks(CHUNK) {
        device_key_copies::Entity::delete_many()
            .filter(device_key_copies::Column::DeviceId.is_in(chunk.to_vec()))
            .exec(txn)
            .await
            .store()?;
    }
    out.devices = devices::Entity::delete_many()
        .filter(devices::Column::UserId.eq(uid))
        .exec(txn)
        .await
        .store()?
        .rows_affected;
    two_factor::Entity::delete_many()
        .filter(two_factor::Column::UserId.eq(uid))
        .exec(txn)
        .await
        .store()?;
    two_factor_recovery::Entity::delete_many()
        .filter(two_factor_recovery::Column::UserId.eq(uid))
        .exec(txn)
        .await
        .store()?;
    two_step_versions::Entity::delete_many()
        .filter(two_step_versions::Column::UserId.eq(uid))
        .exec(txn)
        .await
        .store()?;
    second_step_attempts::Entity::delete_many()
        .filter(second_step_attempts::Column::UserId.eq(uid))
        .exec(txn)
        .await
        .store()?;
    bw_user_key_ids::Entity::delete_many()
        .filter(bw_user_key_ids::Column::UserId.eq(uid))
        .exec(txn)
        .await
        .store()?;
    bw_accounts::Entity::delete_many()
        .filter(bw_accounts::Column::UserId.eq(uid))
        .exec(txn)
        .await
        .store()?;
    auth_requests::Entity::delete_many()
        .filter(auth_requests::Column::UserId.eq(uid))
        .exec(txn)
        .await
        .store()?;
    identities::Entity::delete_many()
        .filter(identities::Column::UserId.eq(uid))
        .exec(txn)
        .await
        .store()?;
    // Emergency access the account gave, and what others gave it (by id or by its email).
    emergency_access::Entity::delete_many()
        .filter(
            Condition::any()
                .add(emergency_access::Column::GrantorId.eq(uid))
                .add(emergency_access::Column::GranteeId.eq(uid))
                .add(emergency_access::Column::GranteeEmail.eq(user.email.as_str())),
        )
        .exec(txn)
        .await
        .store()?;

    // Logs: the sign-in log goes; the event log stays, without name, email or address.
    out.sign_ins = sign_in_log::Entity::delete_many()
        .filter(sign_in_log::Column::UserId.eq(uid))
        .exec(txn)
        .await
        .store()?
        .rows_affected;
    pending_erasures::Entity::delete_by_id(uid)
        .exec(txn)
        .await
        .store()?;

    let mut needles = vec![user.email.as_str().to_owned()];
    if let Some(name) = user.name.as_deref().map(str::trim) {
        // A short name would match inside ordinary words.
        if name.chars().count() >= 3 {
            needles.push(name.to_owned());
        }
    }
    let mut mentioned = Condition::any().add(events::Column::Actor.eq(uid));
    for needle in &needles {
        mentioned = mentioned.add(events::Column::Target.contains(needle.as_str()));
    }
    let candidates = events::Entity::find()
        .filter(events::Column::Target.is_not_null())
        .filter(mentioned)
        .all(txn)
        .await
        .store()?;
    for row in candidates {
        let Some(new_target) = row.target.as_deref().and_then(|t| redact(t, &needles)) else {
            continue;
        };
        events::Entity::update_many()
            .col_expr(events::Column::Target, Expr::val(new_target))
            .filter(events::Column::Id.eq(row.id))
            .exec(txn)
            .await
            .store()?;
        out.events_scrubbed += 1;
    }
    let dropped = events::Entity::update_many()
        .col_expr(events::Column::Ip, Expr::cust("NULL"))
        .col_expr(events::Column::IpFull, Expr::cust("NULL"))
        .filter(events::Column::Actor.eq(uid))
        .filter(
            Condition::any()
                .add(events::Column::Ip.is_not_null())
                .add(events::Column::IpFull.is_not_null()),
        )
        .exec(txn)
        .await
        .store()?;
    out.events_scrubbed += dropped.rows_affected;

    users::Entity::delete_by_id(uid).exec(txn).await.store()?;
    Ok(out)
}

/// A replica's copy of a vault its home erased, in the caller's transaction: the vault's items and
/// everything that hangs on them, the offer, and, for a personal vault, the copied account (one
/// that lives here only for the vault; an account of this server is never touched). The attachment
/// files whose rows went are returned for the caller to delete. An event records it, with no name,
/// email or vault id.
pub(crate) async fn erase_replica_vault(
    txn: &DatabaseTransaction,
    me: ServerId,
    vault: Owner,
) -> Result<VaultErased, StoreError> {
    let (owner_type, owner_id) = owner_parts(vault);
    let copied = match vault {
        Owner::User(user) => replicated_accounts::Entity::find_by_id(user.0)
            .one(txn)
            .await
            .store()?
            .is_some(),
        Owner::Space(_) => false,
    };
    // A personal vault whose account is not a copy is this server's own: its items are the
    // account's, and a new home (an admin here accepted its promotion) must not wipe them.
    if matches!(vault, Owner::User(_)) && !copied {
        // `Duplicate` is how the store says "this account is yours": the replica answers a refusal
        // the home takes as final (`kemlock_federation::erasure::ERASE_LOCAL_ACCOUNT`).
        return Err(StoreError::Duplicate);
    }
    let mut rows = ErasedRows::default();
    let mut accounts = 0;
    let account = if copied {
        users::Entity::find_by_id(owner_id).one(txn).await.store()?
    } else {
        None
    };
    match account {
        Some(model) => {
            // The copy is an account like any other as far as its rows go: devices, tokens, the
            // vault and the row itself.
            rows = erase_in(txn, &model.into_domain()?, me).await?;
            accounts = 1;
        }
        None => delete_owner_data(txn, owner_type, owner_id, me, &mut rows).await?,
    }
    if copied {
        replicated_accounts::Entity::delete_by_id(owner_id)
            .exec(txn)
            .await
            .store()?;
    }
    // What federation keeps beside the vault's items: the event log copies the peers sent, the
    // duplicate tags and the matching switch.
    peer_events::Entity::delete_many()
        .filter(peer_events::Column::OwnerType.eq(owner_type))
        .filter(peer_events::Column::OwnerId.eq(owner_id))
        .exec(txn)
        .await
        .store()?;
    item_tags::Entity::delete_many()
        .filter(item_tags::Column::OwnerType.eq(owner_type))
        .filter(item_tags::Column::OwnerId.eq(owner_id))
        .exec(txn)
        .await
        .store()?;
    dedup_owners::Entity::delete_by_id((owner_type, owner_id))
        .exec(txn)
        .await
        .store()?;
    vault_offers::Entity::delete_by_id((owner_type, owner_id))
        .exec(txn)
        .await
        .store()?;
    events::Entity::insert(events::active_with_ip(
        Event {
            actor: None,
            device: None,
            action: "federation.vault_erased",
            target: None,
            at: OffsetDateTime::now_utc(),
        },
        None,
    ))
    .exec(txn)
    .await
    .store()?;
    Ok(VaultErased {
        items: rows.items,
        blobs: rows.blobs,
        accounts,
    })
}

impl AccountEraser for SqlStore {
    async fn blocking_spaces(&self, user: UserId) -> Result<Vec<SpaceId>, StoreError> {
        blocking(self.reader(), user.0).await
    }

    async fn erase_user(&self, user: &User) -> Result<ErasedRows, StoreError> {
        let txn = self.writer().begin().await.store()?;
        match erase_in(&txn, user, self.origin()).await {
            Ok(rows) => {
                txn.commit().await.store()?;
                Ok(rows)
            }
            Err(err) => {
                if let Err(rollback) = txn.rollback().await {
                    tracing::warn!(%rollback, "rollback after a failed erasure failed");
                }
                Err(err)
            }
        }
    }

    async fn schedule_erasure(
        &self,
        user: UserId,
        requested_at: OffsetDateTime,
        due: OffsetDateTime,
    ) -> Result<(), StoreError> {
        let row = pending_erasures::ActiveModel {
            user_id: sea_orm::ActiveValue::Set(user.0),
            requested_at: sea_orm::ActiveValue::Set(utc(requested_at)),
            due_at: sea_orm::ActiveValue::Set(utc(due)),
        };
        let conflict = OnConflict::column(pending_erasures::Column::UserId)
            .update_columns([
                pending_erasures::Column::RequestedAt,
                pending_erasures::Column::DueAt,
            ])
            .to_owned();
        match pending_erasures::Entity::insert(row)
            .on_conflict(conflict)
            .exec(self.writer())
            .await
        {
            Ok(_) | Err(sea_orm::DbErr::RecordNotInserted) => Ok(()),
            Err(err) => Err(map_db(err)),
        }
    }

    async fn scheduled_erasure(&self, user: UserId) -> Result<Option<OffsetDateTime>, StoreError> {
        Ok(pending_erasures::Entity::find_by_id(user.0)
            .one(self.reader())
            .await
            .store()?
            .map(|row| row.due_at))
    }

    async fn cancel_erasure(&self, user: UserId) -> Result<(), StoreError> {
        pending_erasures::Entity::delete_by_id(user.0)
            .exec(self.writer())
            .await
            .store()?;
        Ok(())
    }

    async fn due_erasures(&self, now: OffsetDateTime) -> Result<Vec<UserId>, StoreError> {
        Ok(pending_erasures::Entity::find()
            .filter(pending_erasures::Column::DueAt.lte(utc(now)))
            .order_by_asc(pending_erasures::Column::DueAt)
            .all(self.reader())
            .await
            .store()?
            .into_iter()
            .map(|row| UserId(row.user_id))
            .collect())
    }
}

// ---------------------------------------------------------------------------------------------
// The retention job's deletes.

/// How many Bitwarden-API items one page of the trash scan reads.
const TRASH_PAGE: u64 = 200;

impl RetentionStore for SqlStore {
    async fn purge_events(&self, before: OffsetDateTime) -> Result<u64, StoreError> {
        Ok(events::Entity::delete_many()
            .filter(events::Column::At.lt(utc(before)))
            .exec(self.writer())
            .await
            .store()?
            .rows_affected)
    }

    async fn purge_sign_ins(&self, before: OffsetDateTime) -> Result<u64, StoreError> {
        Ok(sign_in_log::Entity::delete_many()
            .filter(sign_in_log::Column::At.lt(utc(before)))
            .exec(self.writer())
            .await
            .store()?
            .rows_affected)
    }

    async fn drop_full_ips(&self, before: OffsetDateTime) -> Result<u64, StoreError> {
        let from_events = events::Entity::update_many()
            .col_expr(events::Column::IpFull, Expr::cust("NULL"))
            .filter(events::Column::IpFull.is_not_null())
            .filter(events::Column::At.lt(utc(before)))
            .exec(self.writer())
            .await
            .store()?
            .rows_affected;
        let from_sign_ins = sign_in_log::Entity::update_many()
            .col_expr(sign_in_log::Column::IpFull, Expr::cust("NULL"))
            .filter(sign_in_log::Column::IpFull.is_not_null())
            .filter(sign_in_log::Column::At.lt(utc(before)))
            .exec(self.writer())
            .await
            .store()?
            .rows_affected;
        Ok(from_events + from_sign_ins)
    }

    async fn purge_trash(
        &self,
        before: OffsetDateTime,
        now: OffsetDateTime,
    ) -> Result<Vec<PurgedTrash>, StoreError> {
        let mut purged = Vec::new();
        let mut after: Option<Uuid> = None;
        loop {
            let mut query = items::Entity::find()
                .filter(items::Column::Format.eq("bw"))
                .filter(items::Column::DeletedAt.is_null())
                .filter(items::Column::Ciphertext.is_not_null())
                .filter(items::Column::Kind.ne("bw-folder"));
            if let Some(last) = after {
                query = query.filter(items::Column::Id.gt(last));
            }
            let page = query
                .order_by_asc(items::Column::Id)
                .limit(TRASH_PAGE)
                .all(self.reader())
                .await
                .store()?;
            let Some(last) = page.last().map(|row| row.id) else {
                return Ok(purged);
            };
            after = Some(last);

            for row in page {
                let trashed = row
                    .ciphertext
                    .as_deref()
                    .and_then(trashed_at)
                    .is_some_and(|at| at < before);
                if !trashed {
                    continue;
                }
                let cipher_files = row
                    .ciphertext
                    .as_deref()
                    .map(cipher_file_keys)
                    .unwrap_or_default();
                let item = row.into_domain()?;
                let Some(next) = item.revision.next() else {
                    continue;
                };
                let tombstone = ItemDraft {
                    id: item.id,
                    owner: item.owner,
                    kind: item.kind.clone(),
                    format: item.format,
                    expected: Some(item.revision),
                    revision: next,
                    key_version: item.key_version,
                    ciphertext: None,
                    item_key: None,
                    deleted_at: Some(now),
                    updated_at: now,
                    signature: None,
                };
                match ItemStore::put(self, tombstone).await {
                    Ok(_) => {}
                    // Someone changed it since the scan: it isn't trash any more, or the next run
                    // finds it again.
                    Err(StoreError::Conflict { .. }) => continue,
                    Err(e) => return Err(e),
                }
                let blobs = self.remove_item_files(item.id).await?;
                purged.push(PurgedTrash {
                    item: item.id,
                    blobs,
                    cipher_files,
                });
            }
        }
    }
}

impl SqlStore {
    /// Deletes the attachment rows of an item and returns the files they named.
    async fn remove_item_files(&self, item: ItemId) -> Result<Vec<BlobId>, StoreError> {
        let rows = attachments::Entity::find()
            .filter(attachments::Column::ItemId.eq(item.0))
            .all(self.reader())
            .await
            .store()?;
        let mut blobs = Vec::with_capacity(rows.len());
        for row in rows {
            blobs.push(BlobId::from_uuid(row.blob_id));
            attachments::Entity::delete_by_id(row.id)
                .exec(self.writer())
                .await
                .store()?;
        }
        Ok(blobs)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use time::macros::datetime;

    fn needles(list: &[&str]) -> Vec<String> {
        list.iter().map(|s| (*s).to_owned()).collect()
    }

    #[test]
    fn names_and_emails_are_replaced_whatever_their_case() {
        let n = needles(&["ada@example.org", "Ada Lovelace"]);
        assert_eq!(
            redact("invited ADA@Example.org as ada lovelace", &n),
            Some("invited [erased] as [erased]".to_owned())
        );
        assert_eq!(redact("item 123", &n), None);
    }

    #[test]
    fn a_needle_that_appears_in_the_marker_cannot_loop() {
        // "ed" is inside "[erased]": the replacement must not be searched again.
        assert_eq!(
            redact("ed met ed", &needles(&["ed"])),
            Some("[erased] met [erased]".to_owned())
        );
    }

    #[test]
    fn cipher_files_are_named_by_cipher_and_attachment() {
        let json = br#"{"id":"c1","attachments":[{"id":"a1"},{"id":"a2"},{"x":1}]}"#;
        assert_eq!(
            cipher_file_keys(json),
            vec!["c1/a1".to_owned(), "c1/a2".to_owned()]
        );
        assert!(cipher_file_keys(b"not json").is_empty());
        assert!(cipher_file_keys(br#"{"attachments":[{"id":"a"}]}"#).is_empty());
    }

    #[test]
    fn the_trash_date_is_read_from_the_cipher() {
        let json = br#"{"id":"c1","deletedDate":"2026-11-07T10:16:50.428380Z"}"#;
        assert_eq!(
            trashed_at(json),
            Some(datetime!(2026-11-07 10:16:50.42838 UTC))
        );
        assert_eq!(trashed_at(br#"{"id":"c1","deletedDate":null}"#), None);
        assert_eq!(trashed_at(br#"{"id":"c1"}"#), None);
        assert_eq!(
            trashed_at(br#"{"deletedDate":"0001-01-01T00:00:00"}"#),
            None
        );
    }
}
