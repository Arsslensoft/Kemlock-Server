//! `RotationStore` on the tables a root-key rotation touches (docs/crypto.md, "Rotating the root
//! key").
//!
//! The install is one transaction. Its first statement is the conditional write of the account's
//! row, which takes that row's lock until commit; everything it then reads (the account's wraps,
//! its live items, the staged rows) is read there, so a wrap another request adds meanwhile either
//! was written before the lock (and is seen, and refused as not named) or waits for the commit.
//! The items go through `items::write_in`, the write every item write goes through, so they get
//! their change ids, their tags cleared and the same checks as any write.

use super::items::{lock_meta, signed_only_in, write_in};
use crate::convert::utc;
use crate::error::{StoreResult, is_unique_violation, map_db};
use crate::store::SqlStore;
use crate::tables::items::{owner_parts, stored_signature};
use crate::tables::{
    account_bundles, auth_requests, device_key_copies, devices, email_changes, emergency_access,
    items, passkeys, recovery_kits, rotation_previous_keys, rotation_staged_items, sends,
    space_recovery, space_tables::members, users,
};
use kemlock_app::ports::StoreError;
use kemlock_app::rotation::{
    Holdings, Install, Installed, PreviousKeys, ResetGrant, RotationError, RotationStore,
    StagedItem, check_install, check_staged_write, device_copy_row,
};
use kemlock_domain::sends::SendId;
use kemlock_domain::unlock::{EmergencyState, GrantId};
use kemlock_domain::{
    DeviceId, Email, ItemDraft, ItemFormat, ItemId, Owner, PasskeyId, RecoveryKit, Revision,
    SpaceId, UserId, WriteSignature,
};
use sea_orm::ActiveValue::Set;
use sea_orm::{
    ColumnTrait, ConnectionTrait, DatabaseTransaction, EntityTrait, PaginatorTrait, QueryFilter,
    QuerySelect, TransactionTrait,
};
use time::OffsetDateTime;
use uuid::Uuid;

/// The account's holdings, read from `db`: the connection, or the install's transaction.
async fn holdings_in<C: ConnectionTrait>(db: &C, user: UserId) -> Result<Holdings, StoreError> {
    let kit = recovery_kits::Entity::find_by_id(user.0)
        .one(db)
        .await
        .store()?
        .map(|row| row.kit_id);

    let passkeys = passkeys::Entity::find()
        .filter(passkeys::Column::UserId.eq(user.0))
        .filter(passkeys::Column::PrfWrappedKey.is_not_null())
        .all(db)
        .await
        .store()?
        .into_iter()
        .map(|row| (PasskeyId(row.id), row.credential_id))
        .collect();

    let device_ids: Vec<Uuid> = devices::Entity::find()
        .filter(devices::Column::UserId.eq(user.0))
        .select_only()
        .column(devices::Column::Id)
        .into_tuple()
        .all(db)
        .await
        .store()?;
    let device_copies = if device_ids.is_empty() {
        Vec::new()
    } else {
        device_key_copies::Entity::find()
            .filter(device_key_copies::Column::DeviceId.is_in(device_ids))
            .all(db)
            .await
            .store()?
            .into_iter()
            .map(|row| DeviceId(row.device_id))
            .collect()
    };

    let mut emergency = Vec::new();
    for row in emergency_access::Entity::find()
        .filter(emergency_access::Column::GrantorId.eq(user.0))
        .filter(emergency_access::Column::SealedKey.is_not_null())
        .all(db)
        .await
        .store()?
    {
        let state = EmergencyState::parse(&row.state)
            .ok_or_else(|| StoreError::Backend("an emergency grant has an unknown state".into()))?;
        emergency.push((GrantId(row.id), state, row.grantee_id.map(UserId)));
    }

    let mut as_contact = Vec::new();
    for row in emergency_access::Entity::find()
        .filter(emergency_access::Column::GranteeId.eq(user.0))
        .filter(emergency_access::Column::SealedKey.is_not_null())
        .all(db)
        .await
        .store()?
    {
        let state = EmergencyState::parse(&row.state)
            .ok_or_else(|| StoreError::Backend("an emergency grant has an unknown state".into()))?;
        as_contact.push((GrantId(row.id), state));
    }

    let mut recovery = Vec::new();
    for row in space_recovery::Entity::find()
        .filter(space_recovery::Column::UserId.eq(user.0))
        .all(db)
        .await
        .store()?
    {
        let seq = u64::try_from(row.key_seq)
            .map_err(|_| StoreError::Backend("a recovery key seq is negative".into()))?;
        recovery.push((SpaceId(row.space_id), seq));
    }

    let sends = sends::Entity::find()
        .filter(sends::Column::OwnerId.eq(user.0))
        .all(db)
        .await
        .store()?
        .into_iter()
        .map(|row| (SendId(row.id), row.kind))
        .collect();

    let (owner_type, owner_id) = owner_parts(Owner::User(user));
    let rows: Vec<(Uuid, i64, String)> = items::Entity::find()
        .filter(items::Column::OwnerType.eq(owner_type))
        .filter(items::Column::OwnerId.eq(owner_id))
        .filter(items::Column::DeletedAt.is_null())
        .select_only()
        .column(items::Column::Id)
        .column(items::Column::Revision)
        .column(items::Column::Format)
        .into_tuple()
        .all(db)
        .await
        .store()?;
    let mut live_items = Vec::with_capacity(rows.len());
    for (id, revision, format) in rows {
        let revision = u64::try_from(revision)
            .map_err(|_| StoreError::Backend("an item revision is negative".into()))?;
        let format = if format == ItemFormat::Kem1.as_str() {
            ItemFormat::Kem1
        } else {
            ItemFormat::Bw
        };
        live_items.push((ItemId(id), Revision(revision), format));
    }

    let spaces = members::Entity::find()
        .filter(members::Column::UserId.eq(user.0))
        // An invitation not yet accepted is no membership, and a removed member has none.
        .filter(members::Column::State.is_in(["accepted", "confirmed"]))
        .count(db)
        .await
        .store()?;

    let previous_keys = rotation_previous_keys::Entity::find_by_id(user.0)
        .one(db)
        .await
        .store()?
        .is_some();

    Ok(Holdings {
        kit,
        passkeys,
        device_copies,
        emergency,
        as_contact,
        recovery,
        sends,
        live_items,
        spaces,
        previous_keys,
    })
}

/// The ids and base revisions of the rows `rotation` staged for `user` since `since`, without the
/// ciphertexts: those are read a chunk at a time when they are written.
async fn staged_in<C: ConnectionTrait>(
    db: &C,
    user: UserId,
    rotation: Uuid,
    since: OffsetDateTime,
) -> Result<Vec<(Uuid, i64)>, StoreError> {
    rotation_staged_items::Entity::find()
        .filter(rotation_staged_items::Column::UserId.eq(user.0))
        .filter(rotation_staged_items::Column::RotationId.eq(rotation))
        .filter(rotation_staged_items::Column::StagedAt.gte(utc(since)))
        .select_only()
        .column(rotation_staged_items::Column::ItemId)
        .column(rotation_staged_items::Column::BaseRevision)
        .into_tuple()
        .all(db)
        .await
        .store()
}

/// How many staged items the install reads and writes at a time.
const WRITE_CHUNK: usize = 500;

async fn finish<T>(
    txn: DatabaseTransaction,
    outcome: Result<T, RotationError>,
) -> Result<T, RotationError> {
    match outcome {
        Ok(value) => {
            txn.commit()
                .await
                .map_err(|e| RotationError::from(map_db(e)))?;
            Ok(value)
        }
        Err(err) => {
            if let Err(rollback) = txn.rollback().await {
                tracing::warn!(%rollback, "rollback after a failed rotation failed");
            }
            Err(err)
        }
    }
}

fn db<T>(result: Result<T, sea_orm::DbErr>) -> Result<T, RotationError> {
    result.map_err(|e| RotationError::from(map_db(e)))
}

impl RotationStore for SqlStore {
    async fn holdings(&self, user: UserId) -> Result<Holdings, StoreError> {
        holdings_in(self.reader(), user).await
    }

    async fn snapshot(
        &self,
        user: UserId,
        rotation: [u8; 16],
        since: OffsetDateTime,
    ) -> Result<(Holdings, Vec<(ItemId, Revision)>), StoreError> {
        let holdings = holdings_in(self.reader(), user).await?;
        let mut staged = Vec::new();
        for (item, base) in
            staged_in(self.reader(), user, Uuid::from_bytes(rotation), since).await?
        {
            let base = u64::try_from(base)
                .map_err(|_| StoreError::Backend("a revision is negative".into()))?;
            staged.push((ItemId(item), Revision(base)));
        }
        Ok((holdings, staged))
    }

    async fn stage(
        &self,
        user: UserId,
        rotation: [u8; 16],
        staged: Vec<StagedItem>,
        now: OffsetDateTime,
        since: OffsetDateTime,
    ) -> Result<u64, StoreError> {
        let rotation = Uuid::from_bytes(rotation);
        let txn = self.writer().begin().await.store()?;
        let outcome = async {
            // Only the account's own items are staged for it: an id is global, and a row about
            // another owner's item would be installed over it. The use case checks too.
            let ids: Vec<ItemId> = staged.iter().map(|s| s.id).collect();
            super::spaces::ensure_items_of(&txn, Owner::User(user), &ids).await?;
            // Rows of another attempt, and rows that ran out, are no use to anyone.
            rotation_staged_items::Entity::delete_many()
                .filter(rotation_staged_items::Column::UserId.eq(user.0))
                .filter(
                    sea_orm::Condition::any()
                        .add(rotation_staged_items::Column::RotationId.ne(rotation))
                        .add(rotation_staged_items::Column::StagedAt.lt(utc(since))),
                )
                .exec(&txn)
                .await
                .store()?;
            for item in staged {
                rotation_staged_items::Entity::delete_many()
                    .filter(rotation_staged_items::Column::UserId.eq(user.0))
                    .filter(rotation_staged_items::Column::ItemId.eq(item.id.0))
                    .exec(&txn)
                    .await
                    .store()?;
                let base = i64::try_from(item.base_revision.0)
                    .map_err(|_| StoreError::Backend("a revision does not fit".into()))?;
                rotation_staged_items::Entity::insert(rotation_staged_items::ActiveModel {
                    user_id: Set(user.0),
                    item_id: Set(item.id.0),
                    rotation_id: Set(rotation),
                    base_revision: Set(base),
                    ciphertext: Set(item.ciphertext),
                    item_key: Set(item.item_key),
                    write_sig: Set(item.signature.as_ref().map(WriteSignature::to_stored)),
                    staged_at: Set(utc(now)),
                })
                .exec(&txn)
                .await
                .store()?;
            }
            rotation_staged_items::Entity::find()
                .filter(rotation_staged_items::Column::UserId.eq(user.0))
                .filter(rotation_staged_items::Column::RotationId.eq(rotation))
                .count(&txn)
                .await
                .store()
        }
        .await;
        match outcome {
            Ok(count) => {
                txn.commit().await.store()?;
                Ok(count)
            }
            Err(err) => {
                if let Err(rollback) = txn.rollback().await {
                    tracing::warn!(%rollback, "rollback after a failed staging failed");
                }
                Err(err)
            }
        }
    }

    async fn discard(&self, user: UserId) -> Result<(), StoreError> {
        rotation_staged_items::Entity::delete_many()
            .filter(rotation_staged_items::Column::UserId.eq(user.0))
            .exec(self.writer())
            .await
            .store()?;
        Ok(())
    }

    async fn install(&self, install: Install) -> Result<Installed, RotationError> {
        let txn = db(self.writer().begin().await)?;
        let outcome = self.install_in(&txn, &install).await;
        finish(txn, outcome).await
    }

    async fn previous_keys(&self, user: UserId) -> Result<Option<PreviousKeys>, StoreError> {
        rotation_previous_keys::Entity::find_by_id(user.0)
            .one(self.reader())
            .await
            .store()?
            .map(|row| {
                Ok(PreviousKeys {
                    key_version: u32::try_from(row.key_version)
                        .map_err(|_| StoreError::Backend("a key version is negative".into()))?,
                    sealed: row.sealed,
                })
            })
            .transpose()
    }

    async fn clear_previous_keys(&self, user: UserId) -> Result<bool, StoreError> {
        let deleted = rotation_previous_keys::Entity::delete_many()
            .filter(rotation_previous_keys::Column::UserId.eq(user.0))
            .exec(self.writer())
            .await
            .store()?;
        Ok(deleted.rows_affected > 0)
    }
}

impl SqlStore {
    /// The body of the install's transaction.
    async fn install_in(
        &self,
        txn: &DatabaseTransaction,
        install: &Install,
    ) -> Result<Installed, RotationError> {
        let request = &install.request;
        let user = install.before.id;
        let now = install.now;

        // Item writes queue on the `server_meta` lock, and every write of a wrap of the root key
        // takes the account's row lock (`owner_lock::begin_locked`). Take the first now, and the
        // second with the conditional write of the account's row below, before anything is read:
        // a write that began earlier has committed by then and is seen by what is read; one that
        // begins later waits for this transaction.
        lock_meta(txn).await?;

        // The account: conditional on the row as it was read, and it takes the row's lock.
        let row = users::ActiveModel {
            wrapped_root_key: Set(install.after.wrapped_root_key.clone()),
            public_bundle: Set(install.after.public_bundle.clone()),
            bundle_signature: Set(install.after.bundle_signature.clone()),
            sealed_private_keys: Set(install.after.sealed_private_keys.clone()),
            key_version: Set(i64::from(install.after.key_version)),
            security_stamp: Set(install.after.security_stamp),
            updated_at: Set(utc(install.after.updated_at)),
            ..Default::default()
        };
        let written = db(users::Entity::update_many()
            .set(row)
            .filter(users::Column::Id.eq(user.0))
            .filter(users::Column::UpdatedAt.eq(utc(install.before.updated_at)))
            .filter(users::Column::SecurityStamp.eq(install.before.security_stamp))
            .filter(users::Column::KeyVersion.eq(i64::from(install.before.key_version)))
            .exec(txn)
            .await)?;
        if written.rows_affected != 1 {
            return Err(RotationError::AccountChanged);
        }

        // The bundle history: the bundle this replaces (if the history lacks it) and the new one,
        // in this transaction. The new one's time is when the old one was retired
        // (`bundle_retired_at`), and a federated write signed by the replaced key is refused after
        // it. `record` keeps a version only once, so a row already there stays as it was.
        account_bundles::record(
            txn,
            user.0,
            i64::from(install.before.key_version),
            &install.before.public_bundle,
            &install.before.bundle_signature,
            install.before.updated_at,
        )
        .await?;
        account_bundles::record(
            txn,
            user.0,
            i64::from(install.after.key_version),
            &install.after.public_bundle,
            &install.after.bundle_signature,
            install.after.updated_at,
        )
        .await?;

        // A pending change of address holds a password wrap of the root key this install
        // replaces. Opening its link would put that wrap back next to the new key version, so it
        // goes with the rotation (the person asks again), inside the same transaction.
        db(email_changes::Entity::delete_many()
            .filter(email_changes::Column::UserId.eq(user.0))
            .exec(txn)
            .await)?;

        // What the account holds, as of now, against what the request names.
        let holdings = holdings_in(txn, user).await?;
        let rotation = Uuid::from_bytes(request.rotation);
        let staged = staged_in(txn, user, rotation, install.staged_since).await?;
        let mut pairs = Vec::with_capacity(staged.len());
        for (item, base) in &staged {
            let base = u64::try_from(*base)
                .map_err(|_| StoreError::Backend("a revision is negative".into()))?;
            pairs.push((ItemId(*item), Revision(base)));
        }
        check_install(install, &holdings, &pairs)?;

        // The items, through the one write every item write goes through, a chunk at a time: the
        // ciphertexts of a large vault are not all held at once.
        let mut change = None;
        // A vault that takes signed writes only installs no item the account didn't sign.
        let signed_only = signed_only_in(txn, Owner::User(user)).await?;
        for chunk in staged.chunks(WRITE_CHUNK) {
            let ids: Vec<Uuid> = chunk.iter().map(|(item, _)| *item).collect();
            let mut live = std::collections::HashMap::new();
            for row in items::Entity::find()
                .filter(items::Column::Id.is_in(ids.clone()))
                .all(txn)
                .await
                .store()?
            {
                let id = row.id;
                live.insert(id, row.into_domain()?);
            }
            let rows = rotation_staged_items::Entity::find()
                .filter(rotation_staged_items::Column::UserId.eq(user.0))
                .filter(rotation_staged_items::Column::RotationId.eq(rotation))
                .filter(rotation_staged_items::Column::ItemId.is_in(ids))
                .all(txn)
                .await
                .store()?;
            let mut drafts = Vec::with_capacity(rows.len());
            for row in rows {
                // A row staged for an item deleted since is of no account.
                let Some(item) = live.get(&row.item_id).filter(|item| !item.is_tombstone()) else {
                    continue;
                };
                let base = Revision(u64::try_from(row.base_revision).unwrap_or(0));
                let next = base.next().ok_or_else(|| {
                    RotationError::Incomplete("items: a revision is spent".to_owned())
                })?;
                let signature = check_staged_write(
                    request,
                    user,
                    item.id,
                    item.kind.as_str(),
                    next,
                    (&row.ciphertext, &row.item_key),
                    stored_signature(row.write_sig.as_deref())?,
                    signed_only,
                )?;
                drafts.push(ItemDraft {
                    id: item.id,
                    owner: item.owner,
                    kind: item.kind.clone(),
                    format: item.format,
                    expected: Some(base),
                    revision: next,
                    key_version: request.to_version,
                    ciphertext: Some(row.ciphertext),
                    item_key: Some(row.item_key),
                    deleted_at: None,
                    updated_at: now,
                    signature,
                });
            }
            if drafts.is_empty() {
                continue;
            }
            match write_in(txn, self.origin(), drafts).await {
                Ok(written) => change = written.last().map(|item| item.change).or(change),
                Err(StoreError::Conflict { .. }) => {
                    return Err(RotationError::Incomplete(
                        "items: one changed while the rotation was installed".to_owned(),
                    ));
                }
                Err(other) => return Err(other.into()),
            }
        }

        // The Sends.
        for (id, sealed_key, meta) in &request.sends {
            let row = sends::ActiveModel {
                sealed_key: Set(sealed_key.clone()),
                meta: Set(meta.clone()),
                revised_at: Set(utc(now)),
                ..Default::default()
            };
            db(sends::Entity::update_many()
                .set(row)
                .filter(sends::Column::Id.eq(id.0))
                .filter(sends::Column::OwnerId.eq(user.0))
                .exec(txn)
                .await)?;
        }

        // The Recovery Kit: replaced, or gone.
        db(recovery_kits::Entity::delete_many()
            .filter(recovery_kits::Column::UserId.eq(user.0))
            .exec(txn)
            .await)?;
        if let Some((kit_id, wrapped_key)) = &request.kit {
            let kit = RecoveryKit {
                kit_id: kit_id.clone(),
                wrapped_key: wrapped_key.clone(),
                key_version: request.to_version,
                created_at: now,
            };
            db(
                recovery_kits::Entity::insert(recovery_kits::active(user, &kit))
                    .exec(txn)
                    .await,
            )?;
        }

        // The passkeys' PRF wraps: replaced, or removed (the passkey stays).
        for (id, wrapped_key) in &request.passkeys {
            let row = passkeys::ActiveModel {
                prf_wrapped_key: Set(Some(wrapped_key.clone())),
                prf_key_version: Set(Some(i64::from(request.to_version))),
                ..Default::default()
            };
            db(passkeys::Entity::update_many()
                .set(row)
                .filter(passkeys::Column::Id.eq(id.0))
                .filter(passkeys::Column::UserId.eq(user.0))
                .exec(txn)
                .await)?;
        }
        if !request.drop_passkeys.is_empty() {
            let row = passkeys::ActiveModel {
                prf_wrapped_key: Set(None),
                prf_key_version: Set(None),
                ..Default::default()
            };
            db(passkeys::Entity::update_many()
                .set(row)
                .filter(passkeys::Column::Id.is_in(request.drop_passkeys.iter().map(|id| id.0)))
                .filter(passkeys::Column::UserId.eq(user.0))
                .exec(txn)
                .await)?;
        }

        // The emergency boxes: replaced, or the grant goes back to waiting for its confirmation.
        for (id, boxed) in &request.emergency {
            let row = emergency_access::ActiveModel {
                sealed_key: Set(Some(boxed.clone())),
                updated_at: Set(utc(now)),
                ..Default::default()
            };
            db(emergency_access::Entity::update_many()
                .set(row)
                .filter(emergency_access::Column::Id.eq(id.0))
                .filter(emergency_access::Column::GrantorId.eq(user.0))
                .exec(txn)
                .await)?;
        }
        if !request.drop_emergency.is_empty() {
            let row = emergency_access::ActiveModel {
                sealed_key: Set(None),
                state: Set(EmergencyState::Accepted.as_str().to_owned()),
                recovery_initiated_at: Set(None),
                updated_at: Set(utc(now)),
                ..Default::default()
            };
            db(emergency_access::Entity::update_many()
                .set(row)
                .filter(
                    emergency_access::Column::Id
                        .is_in(request.drop_emergency.iter().map(|id| id.0)),
                )
                .filter(emergency_access::Column::GrantorId.eq(user.0))
                .exec(txn)
                .await)?;
        }

        // The grants that name the account as the contact hold a box sealed to its old exchange
        // key, which this rotation replaces: they go back to waiting for the grantor's
        // confirmation, who then seals to the new bundle.
        // The rows are read again here so the grantors told are exactly the grants reset.
        let mut reset_grants: Vec<ResetGrant> = Vec::new();
        if !holdings.as_contact.is_empty() {
            let held = db(emergency_access::Entity::find()
                .filter(emergency_access::Column::GranteeId.eq(user.0))
                .filter(emergency_access::Column::SealedKey.is_not_null())
                .all(txn)
                .await)?;
            if !held.is_empty() {
                let row = emergency_access::ActiveModel {
                    sealed_key: Set(None),
                    state: Set(EmergencyState::Accepted.as_str().to_owned()),
                    recovery_initiated_at: Set(None),
                    updated_at: Set(utc(now)),
                    ..Default::default()
                };
                db(emergency_access::Entity::update_many()
                    .set(row)
                    .filter(emergency_access::Column::Id.is_in(held.iter().map(|grant| grant.id)))
                    .exec(txn)
                    .await)?;
                for grant in &held {
                    match Email::parse(&grant.grantee_email) {
                        Ok(contact) => reset_grants.push(ResetGrant {
                            grantor: UserId(grant.grantor_id),
                            contact,
                        }),
                        Err(_) => {
                            tracing::warn!("a reset grant's contact address doesn't parse, no mail")
                        }
                    }
                }
            }
        }

        // The space recovery boxes: replaced, or deleted.
        for (space, _seq, boxed) in &request.recovery {
            let row = space_recovery::ActiveModel {
                sealed: Set(boxed.clone()),
                ..Default::default()
            };
            db(space_recovery::Entity::update_many()
                .set(row)
                .filter(space_recovery::Column::SpaceId.eq(space.0))
                .filter(space_recovery::Column::UserId.eq(user.0))
                .exec(txn)
                .await)?;
        }
        if !request.drop_recovery.is_empty() {
            db(space_recovery::Entity::delete_many()
                .filter(
                    space_recovery::Column::SpaceId
                        .is_in(request.drop_recovery.iter().map(|space| space.0)),
                )
                .filter(space_recovery::Column::UserId.eq(user.0))
                .exec(txn)
                .await)?;
        }

        // Every trusted-device copy of the old root key goes; the calling device's is new.
        let device_ids: Vec<Uuid> = holdings
            .device_copies
            .iter()
            .map(|device| device.0)
            .collect();
        if !device_ids.is_empty() {
            db(device_key_copies::Entity::delete_many()
                .filter(device_key_copies::Column::DeviceId.is_in(device_ids))
                .exec(txn)
                .await)?;
        }
        if let Some(copy) = device_copy_row(install) {
            let row = device_key_copies::ActiveModel {
                device_id: Set(copy.device.0),
                wrapped_key: Set(copy.wrapped_key),
                protection: Set(copy.protection.as_str().to_owned()),
                created_at: Set(utc(copy.created_at)),
                updated_at: Set(utc(copy.updated_at)),
            };
            match device_key_copies::Entity::insert(row).exec(txn).await {
                Ok(_) => {}
                Err(err) if is_unique_violation(&err) => {}
                Err(err) => return Err(map_db(err).into()),
            }
        }

        // A device approval answered with the old root key sealed to a new device's key, and not
        // yet taken, is a wrap of it too.
        db(auth_requests::Entity::delete_many()
            .filter(auth_requests::Column::UserId.eq(user.0))
            .filter(auth_requests::Column::SealedKey.is_not_null())
            .exec(txn)
            .await)?;

        // The old private keys, sealed under the new user key, until the spaces have moved.
        // They are kept only for an account in a space, whose `rekey` needs them; one that is in
        // none has nothing to sign with them.
        db(rotation_previous_keys::Entity::delete_many()
            .filter(rotation_previous_keys::Column::UserId.eq(user.0))
            .exec(txn)
            .await)?;
        if holdings.spaces > 0 {
            db(
                rotation_previous_keys::Entity::insert(rotation_previous_keys::ActiveModel {
                    user_id: Set(user.0),
                    key_version: Set(i64::from(install.before.key_version)),
                    sealed: Set(request.sealed_previous_private_keys.clone()),
                    created_at: Set(utc(now)),
                })
                .exec(txn)
                .await,
            )?;
        }

        // The staged rows have done their work.
        db(rotation_staged_items::Entity::delete_many()
            .filter(rotation_staged_items::Column::UserId.eq(user.0))
            .exec(txn)
            .await)?;
        Ok(Installed {
            change,
            reset_grants,
        })
    }
}
