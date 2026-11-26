//! `FedAdminRepo`, `MemberStore`, `BlobSync`, `ErasureOutbox`, `VaultErasure` and `Leases` on
//! `SqlStore`: consent to a vault, the member accounts a replica keeps (copies without an OPAQUE
//! record), attachments as federation moves them, the erasures a home owes its replicas and a
//! replica's deletion of its copy, and the lease a replication job runs under.

use super::privacy::erase_replica_vault;
use crate::convert::corrupt;
use crate::error::{StoreResult, is_unique_violation, map_db};
use crate::store::SqlStore;
use crate::tables::attachments::{self, READY};
use crate::tables::events;
use crate::tables::federation::{item_siblings, peers};
use crate::tables::federation_keys::peer_trusted_addresses;
use crate::tables::federation_wiring::{
    federation_erasures, peer_acknowledgements, replicated_accounts, vault_offers,
};
use crate::tables::items::{owner_from, owner_parts};
use crate::tables::settings;
use kemlock_app::ports::{DeviceRepo, Event, StoreError, UserRepo};
use kemlock_app::spaces::SpaceRepo;
use kemlock_domain::spaces::MemberState;
use kemlock_domain::{
    Attachment, AttachmentId, BlobId, Device, DeviceId, Email, ItemId, Owner, Role, ServerId, User,
    UserId,
};
use kemlock_federation::extra::{
    Acknowledgement, BlobSync, ErasureOutbox, FedAdminRepo, Leases, MemberApply, MemberStore,
    PendingErasure, PromotionMode, StoredOffer, VaultErased, VaultErasure,
};
use kemlock_federation::home::Policy;
use kemlock_federation::insight::{MismatchRecord, PeerSecurityRecord, VaultInfo};
use kemlock_federation::members::{MemberAccount, MemberDevice};
use kemlock_federation::ports::VaultRepo;
use sea_orm::ActiveValue::{NotSet, Set};
use sea_orm::sea_query::{Expr, OnConflict};
use sea_orm::{ColumnTrait, EntityTrait, QueryFilter, QueryOrder, QuerySelect, TransactionTrait};
use std::collections::HashSet;
use time::OffsetDateTime;
use uuid::Uuid;

/// The setting `federation_promotion` as the console saves it, and the variable that overrides it.
const PROMOTION_SETTING: &str = "setting.federation_promotion";
const PROMOTION_ENV: &str = "KEMLOCK_FEDERATION_PROMOTION";

fn now_secs() -> i64 {
    OffsetDateTime::now_utc().unix_timestamp()
}

fn from_secs(secs: i64, what: &str) -> Result<OffsetDateTime, StoreError> {
    OffsetDateTime::from_unix_timestamp(secs).map_err(|_| corrupt(what))
}

impl FedAdminRepo for SqlStore {
    async fn trusted_addresses(&self, peer: ServerId) -> Result<Vec<String>, StoreError> {
        Ok(peer_trusted_addresses::Entity::find()
            .filter(peer_trusted_addresses::Column::Peer.eq(peer.0))
            .order_by_asc(peer_trusted_addresses::Column::Address)
            .all(self.reader())
            .await
            .store()?
            .into_iter()
            .map(|row| row.address)
            .collect())
    }

    async fn trust_addresses(
        &self,
        peer: ServerId,
        addresses: &[String],
    ) -> Result<(), StoreError> {
        let held = self.trusted_addresses(peer).await?;
        for address in addresses {
            let address = address.trim();
            // The column is a key, so it has a length; a longer address is never trusted.
            if address.is_empty() || address.len() > 512 || held.iter().any(|h| h == address) {
                continue;
            }
            let inserted =
                peer_trusted_addresses::Entity::insert(peer_trusted_addresses::ActiveModel {
                    peer: Set(peer.0),
                    address: Set(address.to_owned()),
                })
                .exec(self.writer())
                .await;
            match inserted {
                Ok(_) => {}
                // Another write put it there between the read and this one.
                Err(err) if is_unique_violation(&err) => {}
                Err(err) => return Err(map_db(err)),
            }
        }
        Ok(())
    }

    async fn promotion_mode(&self) -> Result<PromotionMode, StoreError> {
        // The server's layered value (environment, `kemlock.toml`, saved) when it gave one.
        if let Some(value) = self.overlaid_setting("federation_promotion") {
            return Ok(PromotionMode::parse(&value));
        }
        // The environment, then what the console saved, then `hold`: anything but `auto` holds.
        if let Ok(value) = std::env::var(PROMOTION_ENV)
            && !value.trim().is_empty()
        {
            return Ok(PromotionMode::parse(&value));
        }
        let saved = settings::Entity::find_by_id(PROMOTION_SETTING.to_owned())
            .one(self.reader())
            .await
            .store()?;
        Ok(saved.map_or(PromotionMode::Hold, |row| PromotionMode::parse(&row.value)))
    }

    async fn update_peer_descriptor(
        &self,
        peer: ServerId,
        operator: &str,
        addresses: &[String],
        suites: &[String],
    ) -> Result<(), StoreError> {
        peers::Entity::update_many()
            .col_expr(
                peers::Column::Operator,
                Expr::value(operator.chars().take(128).collect::<String>()),
            )
            .col_expr(peers::Column::Addresses, Expr::value(addresses.join("\n")))
            .col_expr(peers::Column::Suites, Expr::value(suites.join("\n")))
            .filter(peers::Column::Id.eq(peer.0))
            .exec(self.writer())
            .await
            .store()?;
        Ok(())
    }

    async fn put_acknowledgement(
        &self,
        peer: ServerId,
        ack: &Acknowledgement,
    ) -> Result<(), StoreError> {
        let conflict = OnConflict::column(peer_acknowledgements::Column::Peer)
            .update_columns([
                peer_acknowledgements::Column::Metadata,
                peer_acknowledgements::Column::Deletion,
                peer_acknowledgements::Column::CrossBorder,
                peer_acknowledgements::Column::AcknowledgedBy,
                peer_acknowledgements::Column::AcknowledgedAt,
            ])
            .to_owned();
        let inserted =
            peer_acknowledgements::Entity::insert(peer_acknowledgements::active(peer.0, ack)?)
                .on_conflict(conflict)
                .exec(self.writer())
                .await;
        match inserted {
            Ok(_) | Err(sea_orm::DbErr::RecordNotInserted) => Ok(()),
            Err(err) => Err(map_db(err)),
        }
    }

    async fn acknowledgement(&self, peer: ServerId) -> Result<Option<Acknowledgement>, StoreError> {
        peer_acknowledgements::Entity::find_by_id(peer.0)
            .one(self.reader())
            .await
            .store()?
            .map(peer_acknowledgements::Model::into_domain)
            .transpose()
    }

    async fn put_offer(&self, offer: &StoredOffer) -> Result<(), StoreError> {
        let row = vault_offers::active(offer)?;
        let (owner_type, owner_id) = owner_parts(offer.vault);
        let exists = vault_offers::Entity::find_by_id((owner_type, owner_id))
            .one(self.writer())
            .await
            .store()?
            .is_some();
        if exists {
            vault_offers::Entity::update_many()
                .set(vault_offers::ActiveModel {
                    owner_type: NotSet,
                    owner_id: NotSet,
                    ..row
                })
                .filter(vault_offers::Column::OwnerType.eq(owner_type))
                .filter(vault_offers::Column::OwnerId.eq(owner_id))
                .exec(self.writer())
                .await
                .store()?;
        } else {
            vault_offers::Entity::insert(row)
                .exec(self.writer())
                .await
                .store()?;
        }
        Ok(())
    }

    async fn offer(&self, vault: Owner) -> Result<Option<StoredOffer>, StoreError> {
        let (owner_type, owner_id) = owner_parts(vault);
        vault_offers::Entity::find_by_id((owner_type, owner_id))
            .one(self.reader())
            .await
            .store()?
            .map(vault_offers::Model::into_domain)
            .transpose()
    }

    async fn list_offers(&self) -> Result<Vec<StoredOffer>, StoreError> {
        vault_offers::Entity::find()
            .order_by_asc(vault_offers::Column::ReceivedAt)
            .order_by_asc(vault_offers::Column::OwnerId)
            .all(self.reader())
            .await
            .store()?
            .into_iter()
            .map(vault_offers::Model::into_domain)
            .collect()
    }

    async fn owns_vault(&self, vault: Owner) -> Result<bool, StoreError> {
        match vault {
            Owner::User(user) => {
                if UserRepo::by_id(self, user).await?.is_none() {
                    return Ok(false);
                }
                Ok(!MemberStore::is_replica_account(self, user).await?)
            }
            Owner::Space(space) => Ok(SpaceRepo::load(self, space).await?.is_some()),
        }
    }

    async fn items_with_siblings(&self, owner: Owner) -> Result<Vec<ItemId>, StoreError> {
        let (owner_type, owner_id) = owner_parts(owner);
        let ids: Vec<Uuid> = item_siblings::Entity::find()
            .select_only()
            .column(item_siblings::Column::ItemId)
            .filter(item_siblings::Column::OwnerType.eq(owner_type))
            .filter(item_siblings::Column::OwnerId.eq(owner_id))
            .group_by(item_siblings::Column::ItemId)
            .into_tuple::<Uuid>()
            .all(self.reader())
            .await
            .store()?;
        Ok(ids.into_iter().map(ItemId).collect())
    }

    async fn local_vaults(&self) -> Result<Vec<VaultInfo>, StoreError> {
        self.insight_local_vaults().await
    }

    async fn vault_info(&self, vault: Owner) -> Result<Option<VaultInfo>, StoreError> {
        self.insight_vault_info(vault).await
    }

    async fn newest_change_from(
        &self,
        vault: Owner,
        origin: ServerId,
    ) -> Result<Option<u64>, StoreError> {
        self.insight_newest_change(vault, origin).await
    }

    async fn put_peer_security(&self, record: &PeerSecurityRecord) -> Result<(), StoreError> {
        self.insight_put_security(record).await
    }

    async fn peer_security(
        &self,
        peer: ServerId,
    ) -> Result<Option<PeerSecurityRecord>, StoreError> {
        self.insight_security(peer).await
    }

    async fn put_mismatch(&self, record: &MismatchRecord) -> Result<(), StoreError> {
        self.insight_put_mismatch(record).await
    }

    async fn mismatch(&self, peer: ServerId) -> Result<Option<MismatchRecord>, StoreError> {
        self.insight_mismatch(peer).await
    }
}

/// The user an account copy describes, given the account it replaces (if any).
fn user_of(account: &MemberAccount, existing: Option<&User>) -> Result<User, StoreError> {
    Ok(User {
        id: account.id,
        email: Email::parse(&account.email).map_err(|_| corrupt("a copied account's email"))?,
        name: account.name.clone(),
        mode: account.mode,
        // A copy is never an admin here: roles are this server's own.
        role: Role::User,
        kdf: account.kdf.clone(),
        // No password secret is shared: the copy signs in with its device keys.
        opaque_record: None,
        wrapped_root_key: account.wrapped_root_key.clone(),
        public_bundle: account.public_bundle.clone(),
        bundle_signature: account.bundle_signature.clone(),
        sealed_private_keys: account.sealed_private_keys.clone(),
        key_version: account.key_version,
        security_stamp: existing.map_or_else(Uuid::new_v4, |u| u.security_stamp),
        created_at: from_secs(account.created_at, "a copied account's creation time")?,
        updated_at: from_secs(account.updated_at, "a copied account's update time")?,
    })
}

impl MemberStore for SqlStore {
    async fn member_ids(&self, vault: Owner) -> Result<Vec<UserId>, StoreError> {
        match vault {
            Owner::User(user) => Ok(UserRepo::by_id(self, user)
                .await?
                .map(|u| vec![u.id])
                .unwrap_or_default()),
            Owner::Space(space) => Ok(SpaceRepo::load(self, space)
                .await?
                .map(|state| {
                    state
                        .members
                        .iter()
                        .filter(|m| m.state == MemberState::Confirmed)
                        .map(|m| m.user)
                        .collect()
                })
                .unwrap_or_default()),
        }
    }

    async fn writer_bundle(
        &self,
        user: UserId,
        key_version: u32,
    ) -> Result<Option<Vec<u8>>, StoreError> {
        Ok(UserRepo::bundle_at(self, user, key_version)
            .await?
            .map(|b| b.public_bundle))
    }

    async fn member_account(&self, user: UserId) -> Result<Option<MemberAccount>, StoreError> {
        let Some(account) = UserRepo::by_id(self, user).await? else {
            return Ok(None);
        };
        if MemberStore::is_replica_account(self, user).await? {
            return Ok(None);
        }
        let devices = DeviceRepo::list(self, user)
            .await?
            .into_iter()
            .map(|d| MemberDevice {
                id: d.id,
                name: d.name,
                kind: d.kind,
                dpop_jkt: d.dpop_jkt,
                created_at: d.created_at.unix_timestamp(),
            })
            .collect();
        // The bundles before the current one go with the copy, so a replica can check a write the
        // account signed before it replaced its keys.
        let past_bundles = UserRepo::bundles_of(self, user)
            .await?
            .into_iter()
            .filter(|b| b.key_version < account.key_version)
            .map(|b| kemlock_federation::members::PastBundle {
                key_version: b.key_version,
                public_bundle: b.public_bundle,
                bundle_signature: b.bundle_signature,
            })
            .collect();
        Ok(Some(MemberAccount {
            id: account.id,
            email: account.email.as_str().to_owned(),
            name: account.name,
            mode: account.mode,
            kdf: account.kdf,
            wrapped_root_key: account.wrapped_root_key,
            public_bundle: account.public_bundle,
            bundle_signature: account.bundle_signature,
            sealed_private_keys: account.sealed_private_keys,
            key_version: account.key_version,
            created_at: account.created_at.unix_timestamp(),
            updated_at: account.updated_at.unix_timestamp(),
            devices,
            past_bundles,
        }))
    }

    async fn apply_member_account(
        &self,
        vault: Owner,
        home: ServerId,
        account: &MemberAccount,
    ) -> Result<MemberApply, StoreError> {
        let existing = UserRepo::by_id(self, account.id).await?;
        let copy = replicated_accounts::Entity::find_by_id(account.id.0)
            .one(self.writer())
            .await
            .store()?;
        let replicated = copy.is_some();
        if existing.is_some() && !replicated {
            // An account of this server: a copy never replaces it.
            return Ok(MemberApply::Refused);
        }
        match vault {
            // The home of the account's own personal vault is its authority, and replaces a copy
            // that came in some other way (through a space).
            Owner::User(_) => {}
            Owner::Space(_) => {
                // A space's home may not speak for an account whose personal vault this server
                // federates: that vault's home does. Where it doesn't, a copy follows the
                // server it came from, and no other: the home of one vault must not take over
                // the copy of an account that belongs to another.
                let personal = VaultRepo::get_vault(self, Owner::User(account.id)).await?;
                if personal.is_some_and(|v| v.policy == Policy::Federated)
                    || copy.is_some_and(|c| c.home != home.0)
                {
                    return Ok(MemberApply::Refused);
                }
            }
        }
        let user = user_of(account, existing.as_ref())?;
        if let Some(other) = UserRepo::by_email(self, &user.email).await?
            && other.id != user.id
        {
            return Ok(MemberApply::Refused);
        }
        let mut changed = false;
        match &existing {
            None => {
                UserRepo::insert(self, &user).await?;
                changed = true;
            }
            Some(current) if *current != user => {
                UserRepo::update(self, &user).await?;
                changed = true;
            }
            Some(_) => {}
        }
        // What the account signed under its earlier keys is checked against these.
        for past in &account.past_bundles {
            crate::tables::account_bundles::record(
                self.writer(),
                account.id.0,
                i64::from(past.key_version),
                &past.public_bundle,
                &past.bundle_signature,
                user.updated_at,
            )
            .await?;
        }
        if !replicated {
            replicated_accounts::Entity::insert(replicated_accounts::ActiveModel {
                user_id: Set(account.id.0),
                home: Set(home.0),
                synced_at: Set(now_secs()),
            })
            .exec(self.writer())
            .await
            .store()?;
        } else {
            replicated_accounts::Entity::update_many()
                .col_expr(replicated_accounts::Column::Home, Expr::value(home.0))
                .col_expr(
                    replicated_accounts::Column::SyncedAt,
                    Expr::value(now_secs()),
                )
                .filter(replicated_accounts::Column::UserId.eq(account.id.0))
                .exec(self.writer())
                .await
                .store()?;
        }

        // The registrations: the home's list is the list.
        let current = DeviceRepo::list(self, account.id).await?;
        let wanted: HashSet<DeviceId> = account.devices.iter().map(|d| d.id).collect();
        for device in &current {
            if !wanted.contains(&device.id) {
                DeviceRepo::remove(self, device.id).await?;
                changed = true;
            }
        }
        for registration in &account.devices {
            let created_at = from_secs(registration.created_at, "a copied device's creation time")?;
            let previous = current.iter().find(|d| d.id == registration.id);
            if previous.is_none()
                && let Some(other) = DeviceRepo::get(self, registration.id).await?
                && other.user != account.id
            {
                // A device id is global, and the upsert would move that device, with the key it
                // registered, to this account: a home can't take another account's device.
                tracing::warn!(user = %account.id, "a copied account listed a device of another account: skipped");
                continue;
            }
            let device = Device {
                id: registration.id,
                user: account.id,
                name: registration.name.clone(),
                kind: registration.kind,
                dpop_jkt: registration.dpop_jkt.clone(),
                created_at,
                last_seen_at: previous.map_or(created_at, |d| d.last_seen_at),
            };
            if previous != Some(&device) {
                DeviceRepo::upsert(self, &device).await?;
                changed = true;
            }
        }
        Ok(if changed {
            MemberApply::Applied
        } else {
            MemberApply::Unchanged
        })
    }

    async fn is_replica_account(&self, user: UserId) -> Result<bool, StoreError> {
        Ok(replicated_accounts::Entity::find_by_id(user.0)
            .one(self.reader())
            .await
            .store()?
            .is_some())
    }
}

impl BlobSync for SqlStore {
    async fn attachments_after(
        &self,
        owner: Owner,
        after: AttachmentId,
        limit: u32,
    ) -> Result<Vec<Attachment>, StoreError> {
        let (owner_type, owner_id) = owner_parts(owner);
        attachments::Entity::find()
            .filter(attachments::Column::OwnerType.eq(owner_type))
            .filter(attachments::Column::OwnerId.eq(owner_id))
            .filter(attachments::Column::Status.eq(READY))
            .filter(attachments::Column::Id.gt(after.0))
            .order_by_asc(attachments::Column::Id)
            .limit(u64::from(limit))
            .all(self.reader())
            .await
            .store()?
            .into_iter()
            .map(attachments::Model::into_domain)
            .collect()
    }

    async fn attachment_of_blob(&self, blob: BlobId) -> Result<Option<Attachment>, StoreError> {
        attachments::Entity::find()
            .filter(attachments::Column::BlobId.eq(blob.to_uuid()))
            .one(self.reader())
            .await
            .store()?
            .map(attachments::Model::into_domain)
            .transpose()
    }

    async fn attachment(&self, id: AttachmentId) -> Result<Option<Attachment>, StoreError> {
        attachments::Entity::find_by_id(id.0)
            .one(self.reader())
            .await
            .store()?
            .map(attachments::Model::into_domain)
            .transpose()
    }

    async fn add_replicated_attachment(&self, attachment: &Attachment) -> Result<bool, StoreError> {
        let inserted = attachments::Entity::insert(attachments::active(attachment)?)
            .exec(self.writer())
            .await;
        match inserted {
            Ok(_) => Ok(true),
            Err(err) if is_unique_violation(&err) => Ok(false),
            Err(err) => Err(map_db(err)),
        }
    }
}

impl Leases for SqlStore {
    async fn acquire_lease(
        &self,
        name: &str,
        holder: &str,
        ttl_secs: u64,
    ) -> Result<bool, StoreError> {
        let ttl = time::Duration::seconds(i64::try_from(ttl_secs).unwrap_or(i64::MAX / 2));
        self.try_lease(name, holder, ttl).await
    }

    async fn drop_lease(&self, name: &str, holder: &str) -> Result<(), StoreError> {
        self.release_lease(name, holder).await
    }
}

impl ErasureOutbox for SqlStore {
    async fn pending_erasures(&self, peer: ServerId) -> Result<Vec<PendingErasure>, StoreError> {
        federation_erasures::Entity::find()
            .filter(federation_erasures::Column::Peer.eq(peer.0))
            .order_by_asc(federation_erasures::Column::QueuedAt)
            .all(self.reader())
            .await
            .store()?
            .into_iter()
            .map(|row| {
                Ok(PendingErasure {
                    peer: ServerId(row.peer),
                    vault: owner_from(row.owner_type, row.owner_id)?,
                    queued_at: u64::try_from(row.queued_at).map_err(|_| corrupt("erasure time"))?,
                })
            })
            .collect()
    }

    async fn complete_erasure(&self, peer: ServerId, vault: Owner) -> Result<(), StoreError> {
        let (owner_type, owner_id) = owner_parts(vault);
        let done = federation_erasures::Entity::delete_by_id((peer.0, owner_type, owner_id))
            .exec(self.writer())
            .await
            .store()?;
        if done.rows_affected > 0 {
            // For the operator's record: which peer was told, never whose vault.
            events::Entity::insert(events::active_with_ip(
                Event {
                    actor: None,
                    device: None,
                    action: "federation.erasure_forwarded",
                    target: Some(format!("peer:{peer}")),
                    at: OffsetDateTime::now_utc(),
                },
                None,
            ))
            .exec(self.writer())
            .await
            .store()?;
        }
        Ok(())
    }
}

impl VaultErasure for SqlStore {
    async fn erase_vault(&self, vault: Owner) -> Result<VaultErased, StoreError> {
        let txn = self.writer().begin().await.store()?;
        match erase_replica_vault(&txn, self.origin(), vault).await {
            Ok(erased) => {
                txn.commit().await.store()?;
                Ok(erased)
            }
            Err(err) => {
                if let Err(rollback) = txn.rollback().await {
                    tracing::warn!(%rollback, "rollback after a failed vault erasure failed");
                }
                Err(err)
            }
        }
    }
}
