//! `SpaceChainRepo` on the chain tables, and the `SpaceRepo` parts that belong with them: whether a
//! space has a chain, the external-changes setting, the queue of changes kept for admins, and the
//! items a key replacement held.
//!
//! An append is one transaction: it checks the stored head is the one the records follow, inserts
//! the records, their boxes and names, then applies the space tables the chain derives (the same
//! `apply_in` every other space change goes through). Of two racing appends one wins; the other
//! finds the head moved, or loses the unique key of `(space, seq)`, and is `Stale`.

use super::items::{release_written, write_in};
use super::spaces::{apply_in, ensure_items_of, finish, link_item};
use crate::error::StoreResult;
use crate::store::SqlStore;
use crate::tables::settings;
use crate::tables::space_chain::{held, names, pending, records, seals};
use kemlock_app::ports::StoreError;
use kemlock_app::spaces::{
    AppendOutcome, ChainAppend, ChainHead, ChainUsage, ExternalChangeMode, ExternalSource,
    HomeGate, PendingChange, PendingExternal, SpaceChainRepo, StoredRecord, StoredSeal,
    pending_from_changes, replay_state,
};
use kemlock_crypto::space_chain::State;
use kemlock_crypto::space_chain::{self as sc, KeyRef};
use kemlock_domain::spaces::{CollectionId, CollectionPermission, CustomPermissions, SpaceRole};
use kemlock_domain::{ItemDraft, ItemId, Owner, SpaceId, UserId};
use kemlock_federation::chain::{ChainWire, WireName, WireSeal};
use kemlock_federation::home::Policy;
use kemlock_federation::ports::{ReplicaStore, VaultRepo};
use sea_orm::ActiveValue::Set;
use sea_orm::sea_query::Expr;
use sea_orm::{
    ColumnTrait, ConnectionTrait, EntityTrait, PaginatorTrait, QueryFilter, QueryOrder,
    QuerySelect, TransactionTrait,
};
use std::collections::HashMap;
use std::sync::{Arc, Mutex, PoisonError};
use time::OffsetDateTime;
use uuid::Uuid;

/// The saved setting that says what happens to a change from outside Kemlock clients.
const MODE_SETTING: &str = "setting.space_chain_external_changes";
/// The environment variable that sets it, which wins over the saved value.
const MODE_ENV: &str = "KEMLOCK_SPACE_CHAIN_EXTERNAL_CHANGES";

fn bad(what: &str) -> StoreError {
    StoreError::Backend(format!("a stored space chain row is malformed: {what}"))
}

fn to_i64(value: u64, what: &str) -> Result<i64, StoreError> {
    i64::try_from(value).map_err(|_| bad(what))
}

fn head_of(row: &records::Model) -> Result<ChainHead, StoreError> {
    Ok(ChainHead {
        seq: u64::try_from(row.seq).map_err(|_| bad("seq"))?,
        link: <[u8; 32]>::try_from(row.link.as_slice()).map_err(|_| bad("link"))?,
        epoch: u32::try_from(row.epoch).map_err(|_| bad("epoch"))?,
    })
}

fn record_of(row: records::Model) -> Result<StoredRecord, StoreError> {
    let head = head_of(&row)?;
    Ok(StoredRecord {
        seq: head.seq,
        link: head.link,
        epoch: head.epoch,
        by: UserId(row.signer),
        at: u64::try_from(row.at).map_err(|_| bad("at"))?,
        entry: row.entry,
        signature: row.signature,
        cosignature: row.cosignature,
    })
}

fn seal_of(row: seals::Model) -> Result<StoredSeal, StoreError> {
    Ok(StoredSeal {
        seq: u64::try_from(row.seq).map_err(|_| bad("seq"))?,
        key: KeyRef::parse(&row.key_ref).ok_or_else(|| bad("key ref"))?,
        version: u32::try_from(row.version).map_err(|_| bad("version"))?,
        member: UserId(row.member),
        bundle_version: u32::try_from(row.bundle_version).map_err(|_| bad("bundle version"))?,
        sealed: row.sealed,
    })
}

async fn head_in<C: ConnectionTrait>(
    db: &C,
    space: SpaceId,
) -> Result<Option<ChainHead>, StoreError> {
    records::Entity::find()
        .filter(records::Column::SpaceId.eq(space.0))
        .order_by_desc(records::Column::Seq)
        .one(db)
        .await
        .store()?
        .map(|row| head_of(&row))
        .transpose()
}

/// The most spaces whose chain state is kept: past it the cache starts over, which only means the
/// next read of a space replays its chain again.
const MAX_CACHED_CHAINS: usize = 256;

/// The verified state at the head of each chain used lately, under the head's link. A link is the
/// hash chain over every record before it, so a state kept under a link is the state of exactly
/// that chain: a head that has moved on, or a record a replica took, simply doesn't match and the
/// chain is replayed.
#[derive(Default)]
pub(crate) struct ChainStates(Mutex<HashMap<SpaceId, (ChainHead, Arc<State>)>>);

impl std::fmt::Debug for ChainStates {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ChainStates").finish_non_exhaustive()
    }
}

impl ChainStates {
    fn get(&self, space: SpaceId, head: &ChainHead) -> Option<Arc<State>> {
        let map = self.0.lock().unwrap_or_else(PoisonError::into_inner);
        map.get(&space)
            .filter(|(kept, _)| kept.link == head.link && kept.seq == head.seq)
            .map(|(_, state)| Arc::clone(state))
    }

    fn put(&self, space: SpaceId, head: ChainHead, state: Arc<State>) {
        let mut map = self.0.lock().unwrap_or_else(PoisonError::into_inner);
        if map.len() >= MAX_CACHED_CHAINS && !map.contains_key(&space) {
            map.clear();
        }
        map.insert(space, (head, state));
    }
}

impl SpaceChainRepo for SqlStore {
    async fn chain_state(
        &self,
        space: SpaceId,
    ) -> Result<Option<(ChainHead, Arc<State>)>, StoreError> {
        let Some(head) = head_in(self.reader(), space).await? else {
            return Ok(None);
        };
        if let Some(state) = self.chain_states().get(space, &head) {
            return Ok(Some((head, state)));
        }
        let Some((head, state)) = replay_state(self, space).await? else {
            return Ok(None);
        };
        self.chain_states().put(space, head, Arc::clone(&state));
        Ok(Some((head, state)))
    }

    async fn chain_head(&self, space: SpaceId) -> Result<Option<ChainHead>, StoreError> {
        head_in(self.reader(), space).await
    }

    async fn chain_records(
        &self,
        space: SpaceId,
        from: u64,
    ) -> Result<Vec<StoredRecord>, StoreError> {
        let Ok(from) = i64::try_from(from) else {
            return Ok(Vec::new());
        };
        records::Entity::find()
            .filter(records::Column::SpaceId.eq(space.0))
            .filter(records::Column::Seq.gte(from))
            .order_by_asc(records::Column::Seq)
            .all(self.reader())
            .await
            .store()?
            .into_iter()
            .map(record_of)
            .collect()
    }

    async fn chain_seals(&self, space: SpaceId, seq: u64) -> Result<Vec<StoredSeal>, StoreError> {
        let Ok(seq) = i64::try_from(seq) else {
            return Ok(Vec::new());
        };
        seals::Entity::find()
            .filter(seals::Column::SpaceId.eq(space.0))
            .filter(seals::Column::Seq.eq(seq))
            .all(self.reader())
            .await
            .store()?
            .into_iter()
            .map(seal_of)
            .collect()
    }

    async fn chain_append(
        &self,
        space: SpaceId,
        append: ChainAppend,
    ) -> Result<AppendOutcome, StoreError> {
        let kept_state = append.state.clone();
        let expected = append.expected;
        let txn = self.writer().begin().await.store()?;
        let outcome = async {
            let stored = head_in(&txn, space).await?;
            if stored != append.expected {
                return Ok(AppendOutcome::Stale(stored));
            }
            let mut last = stored;
            for record in &append.records {
                records::Entity::insert(records::ActiveModel {
                    space_id: Set(space.0),
                    seq: Set(to_i64(record.seq, "seq")?),
                    link: Set(record.link.to_vec()),
                    epoch: Set(i64::from(record.epoch)),
                    signer: Set(record.by.0),
                    at: Set(to_i64(record.at, "at")?),
                    entry: Set(record.entry.clone()),
                    signature: Set(record.signature.clone()),
                    cosignature: Set(record.cosignature.clone()),
                })
                .exec(&txn)
                .await
                .store()?;
                last = Some(ChainHead {
                    seq: record.seq,
                    link: record.link,
                    epoch: record.epoch,
                });
            }
            for seal in &append.seals {
                seals::Entity::insert(seals::ActiveModel {
                    space_id: Set(space.0),
                    seq: Set(to_i64(seal.seq, "seq")?),
                    key_ref: Set(seal.key.text()),
                    version: Set(i64::from(seal.version)),
                    member: Set(seal.member.0),
                    bundle_version: Set(i64::from(seal.bundle_version)),
                    sealed: Set(seal.sealed.clone()),
                })
                .exec(&txn)
                .await
                .store()?;
            }
            for name in &append.names {
                names::Entity::insert(names::ActiveModel {
                    space_id: Set(space.0),
                    seq: Set(to_i64(name.seq, "seq")?),
                    target: Set(name.target.text()),
                    version: Set(i64::from(name.version)),
                    name_hash: Set(name.hash.to_vec()),
                    sealed: Set(name.sealed.clone()),
                })
                .exec(&txn)
                .await
                .store()?;
            }
            ensure_items_of(&txn, Owner::Space(space), &append.held).await?;
            for item in &append.held {
                held::Entity::delete_many()
                    .filter(held::Column::ItemId.eq(item.0))
                    .exec(&txn)
                    .await
                    .store()?;
                held::Entity::insert(held::ActiveModel {
                    item_id: Set(item.0),
                    space_id: Set(space.0),
                })
                .exec(&txn)
                .await
                .store()?;
            }
            if let Some(answered) = append.answers {
                pending::Entity::update_many()
                    .col_expr(pending::Column::Status, Expr::value("done"))
                    .col_expr(
                        pending::Column::DoneAt,
                        Expr::value(OffsetDateTime::now_utc().unix_timestamp()),
                    )
                    .filter(pending::Column::Id.eq(answered))
                    .filter(pending::Column::SpaceId.eq(space.0))
                    .exec(&txn)
                    .await
                    .store()?;
            }
            apply_in(&txn, append.changes, append.creating).await?;
            // The items a key replacement re-wrote, stored with the records as a replacement's are.
            if !append.writes.is_empty() {
                let (drafts, collections): (Vec<ItemDraft>, Vec<CollectionId>) =
                    append.writes.into_iter().unzip();
                let stored = write_in(&txn, self.origin(), drafts).await?;
                for (item, collection) in stored.iter().zip(collections) {
                    link_item(&txn, item.id, space, collection).await?;
                    // An item an earlier replacement held, written under the current key
                    // version, is live again (I4), as any item write makes it.
                    release_written(&txn, item, Some(collection)).await?;
                }
            }
            let head = last.ok_or_else(|| bad("an append with no records"))?;
            Ok::<AppendOutcome, StoreError>(AppendOutcome::Appended(head))
        }
        .await;
        let outcome = finish(txn, outcome, "a failed chain append").await;
        // Only once the append has committed: the state is the one at the head it made.
        if let (Ok(AppendOutcome::Appended(head)), Some(state)) = (&outcome, kept_state) {
            self.chain_states().put(space, *head, state);
        }
        match outcome {
            // The `(space, seq)` key says another append got there first, when the head has moved.
            // A duplicate with the head where the records were checked is something else, such as
            // a collection or group id another space holds, and is the caller's to answer: it is
            // not a lost race to retry.
            Err(StoreError::Duplicate) => {
                let current = head_in(self.writer(), space).await?;
                if current == expected {
                    Err(StoreError::Duplicate)
                } else {
                    Ok(AppendOutcome::Stale(current))
                }
            }
            other => other,
        }
    }

    async fn chain_usage(
        &self,
        space: SpaceId,
        member: UserId,
        since_hour: u64,
        since_day: u64,
    ) -> Result<ChainUsage, StoreError> {
        let db = self.reader();
        Ok(ChainUsage {
            by_member_hour: signed_since(db, space, member, since_hour).await?,
            by_member_day: signed_since(db, space, member, since_day).await?,
        })
    }

    async fn chain_home_gate(&self, space: SpaceId) -> Result<Option<HomeGate>, StoreError> {
        let Some(vault) = VaultRepo::get_vault(self, Owner::Space(space)).await? else {
            return Ok(None);
        };
        if vault.policy != Policy::Federated {
            return Ok(None);
        }
        let me = ReplicaStore::server_id(self);
        Ok(Some(HomeGate {
            is_home: vault.home == me,
            epoch: u32::try_from(vault.epoch).unwrap_or(u32::MAX),
            server: *me.as_bytes(),
            promotion: vault.promotion.as_deref().map(kemlock_crypto::hash::sha256),
        }))
    }

    async fn pending_external(&self, space: SpaceId) -> Result<Vec<PendingExternal>, StoreError> {
        pending::Entity::find()
            .filter(pending::Column::SpaceId.eq(space.0))
            .filter(pending::Column::Status.eq("pending"))
            .order_by_asc(pending::Column::QueuedAt)
            .order_by_asc(pending::Column::Id)
            .all(self.reader())
            .await
            .store()?
            .into_iter()
            .map(pending_of)
            .collect()
    }

    async fn pending_external_one(
        &self,
        space: SpaceId,
        id: Uuid,
    ) -> Result<Option<PendingExternal>, StoreError> {
        pending::Entity::find_by_id(id)
            .filter(pending::Column::SpaceId.eq(space.0))
            .filter(pending::Column::Status.eq("pending"))
            .one(self.reader())
            .await
            .store()?
            .map(pending_of)
            .transpose()
    }

    async fn dismiss_external(&self, space: SpaceId, id: Uuid) -> Result<bool, StoreError> {
        let result = pending::Entity::delete_many()
            .filter(pending::Column::SpaceId.eq(space.0))
            .filter(pending::Column::Id.eq(id))
            .filter(pending::Column::Status.eq("pending"))
            .exec(self.writer())
            .await
            .store()?;
        Ok(result.rows_affected > 0)
    }
}

/// How many records `member` signed in the chain at or after `since` (Unix seconds, by `at`). A count
/// over `(space_id, signer, at)`, which an index serves.
async fn signed_since<C: ConnectionTrait>(
    db: &C,
    space: SpaceId,
    member: UserId,
    since: u64,
) -> Result<u64, StoreError> {
    records::Entity::find()
        .filter(records::Column::SpaceId.eq(space.0))
        .filter(records::Column::Signer.eq(member.0))
        .filter(records::Column::At.gte(i64::try_from(since).unwrap_or(i64::MAX)))
        .count(db)
        .await
        .store()
}

fn grants_text(grants: &[(CollectionId, CollectionPermission)]) -> String {
    grants
        .iter()
        .map(|(c, p)| format!("{}:{}", c.0, p.as_str()))
        .collect::<Vec<_>>()
        .join(",")
}

fn grants_of(text: &str) -> Result<Vec<(CollectionId, CollectionPermission)>, StoreError> {
    text.split(',')
        .filter(|part| !part.is_empty())
        .map(|part| {
            let (id, permission) = part.split_once(':').ok_or_else(|| bad("grants"))?;
            Ok((
                CollectionId(Uuid::parse_str(id).map_err(|_| bad("grants"))?),
                CollectionPermission::parse(permission).ok_or_else(|| bad("grants"))?,
            ))
        })
        .collect()
}

fn pending_model(change: &PendingExternal) -> pending::ActiveModel {
    let (role, custom, collection, permission, grants) = match &change.change {
        PendingChange::AddMember {
            role,
            custom,
            grants,
        } => (
            Some(role.as_str().to_owned()),
            i64::from(custom.bits()),
            None,
            None,
            grants_text(grants),
        ),
        PendingChange::RemoveMember => (None, 0, None, None, String::new()),
        PendingChange::Role { role, custom } => (
            Some(role.as_str().to_owned()),
            i64::from(custom.bits()),
            None,
            None,
            String::new(),
        ),
        PendingChange::GrantSet {
            collection,
            permission,
        } => (
            None,
            0,
            Some(collection.0),
            Some(permission.as_str().to_owned()),
            String::new(),
        ),
        PendingChange::GrantRemove { collection } => {
            (None, 0, Some(collection.0), None, String::new())
        }
    };
    pending::ActiveModel {
        id: Set(change.id),
        space_id: Set(change.space.0),
        source: Set(change.source.as_str().to_owned()),
        queued_at: Set(change.queued_at.unix_timestamp()),
        requested_by: Set(change.requested_by.map(|u| u.0)),
        via: Set(change.via.clone()),
        account: Set(change.account.0),
        kind: Set(change.change.kind().to_owned()),
        role: Set(role),
        custom: Set(custom),
        collection: Set(collection),
        permission: Set(permission),
        grants: Set(grants),
        status: Set("pending".to_owned()),
        done_at: Set(None),
    }
}

fn pending_of(row: pending::Model) -> Result<PendingExternal, StoreError> {
    let role = || {
        row.role
            .as_deref()
            .and_then(SpaceRole::parse)
            .ok_or_else(|| bad("pending role"))
    };
    let custom = u16::try_from(row.custom)
        .ok()
        .and_then(CustomPermissions::from_bits)
        .ok_or_else(|| bad("pending custom"))?;
    let collection = || {
        row.collection
            .map(CollectionId)
            .ok_or_else(|| bad("pending collection"))
    };
    let change = match row.kind.as_str() {
        "add-member" => PendingChange::AddMember {
            role: role()?,
            custom,
            grants: grants_of(&row.grants)?,
        },
        "remove-member" => PendingChange::RemoveMember,
        "role" => PendingChange::Role {
            role: role()?,
            custom,
        },
        "grant-set" => PendingChange::GrantSet {
            collection: collection()?,
            permission: row
                .permission
                .as_deref()
                .and_then(CollectionPermission::parse)
                .ok_or_else(|| bad("pending permission"))?,
        },
        "grant-remove" => PendingChange::GrantRemove {
            collection: collection()?,
        },
        _ => return Err(bad("pending kind")),
    };
    Ok(PendingExternal {
        id: row.id,
        space: SpaceId(row.space_id),
        source: ExternalSource::parse(&row.source).ok_or_else(|| bad("pending source"))?,
        queued_at: OffsetDateTime::from_unix_timestamp(row.queued_at)
            .map_err(|_| bad("pending time"))?,
        requested_by: row.requested_by.map(UserId),
        via: row.via,
        account: UserId(row.account),
        email: None,
        change,
    })
}

/// The setting that says the one-time pass of `project_chain_policies` was done.
const POLICIES_PROJECTED_KEY: &str = "chain_policies_projected_v1";

impl SqlStore {
    /// Writes the policy settings the chain of `space` signs into `space_policy_settings`, which
    /// is what the server enforces: the chain is the one place they are set on a chained space.
    /// `false` when the space has no chain.
    pub(crate) async fn project_policies_of(&self, space: SpaceId) -> Result<bool, StoreError> {
        let Some((_, state)) = SpaceChainRepo::chain_state(self, space).await? else {
            return Ok(false);
        };
        let creator = records::Entity::find_by_id((space.0, 0i64))
            .one(self.reader())
            .await
            .store()?
            .map(|row| UserId(row.signer))
            .ok_or_else(|| bad("a chain with no first record"))?;
        super::policies::upsert_policies(
            self.writer(),
            space,
            &kemlock_app::spaces::chain_project::policies_of(&state.policies),
            creator,
            OffsetDateTime::now_utc(),
        )
        .await?;
        Ok(true)
    }

    /// Once, at the first start of a server that enforces the policies a chain signs: projects the
    /// policies of every chained space into `space_policy_settings`. Spaces chained before then
    /// kept the settings their route (now refused on a chained space) had last set, which the
    /// chain does not say. Returns how many spaces it wrote; cheap when it was done already.
    pub async fn project_chain_policies(&self) -> Result<u64, StoreError> {
        use kemlock_app::admin::SettingsRepo;
        let done = SettingsRepo::settings_with_prefix(self, POLICIES_PROJECTED_KEY).await?;
        if done.iter().any(|(key, _)| key == POLICIES_PROJECTED_KEY) {
            return Ok(0);
        }
        let spaces: Vec<Uuid> = records::Entity::find()
            .select_only()
            .column(records::Column::SpaceId)
            .filter(records::Column::Seq.eq(0i64))
            .into_tuple()
            .all(self.reader())
            .await
            .store()?;
        let mut written = 0;
        for space in spaces {
            if self.project_policies_of(SpaceId(space)).await? {
                written += 1;
            }
        }
        SettingsRepo::put_setting(self, POLICIES_PROJECTED_KEY, "1").await?;
        Ok(written)
    }

    /// Whether the space has any record of a chain.
    pub(crate) async fn space_has_chain(&self, space: SpaceId) -> Result<bool, StoreError> {
        Ok(records::Entity::find()
            .filter(records::Column::SpaceId.eq(space.0))
            .one(self.reader())
            .await
            .store()?
            .is_some())
    }

    /// The setting `space_chain_external_changes`: the environment, then what the console saved,
    /// then `queue`.
    pub(crate) async fn read_external_mode(&self) -> Result<ExternalChangeMode, StoreError> {
        // The server's layered value (environment, `kemlock.toml`, saved) when it gave one.
        if let Some(value) = self.overlaid_setting("space_chain_external_changes") {
            return Ok(ExternalChangeMode::parse(&value));
        }
        if let Ok(value) = std::env::var(MODE_ENV)
            && !value.trim().is_empty()
        {
            return Ok(ExternalChangeMode::parse(&value));
        }
        let saved = settings::Entity::find_by_id(MODE_SETTING.to_owned())
            .one(self.reader())
            .await
            .store()?;
        Ok(saved.map_or(ExternalChangeMode::Queue, |row| {
            ExternalChangeMode::parse(&row.value)
        }))
    }

    pub(crate) async fn write_pending(&self, change: PendingExternal) -> Result<(), StoreError> {
        pending::Entity::insert(pending_model(&change))
            .exec(self.writer())
            .await
            .store()?;
        Ok(())
    }

    /// A change from outside Kemlock clients to a space, as `SpaceRepo::apply` meets it. A space
    /// with no chain applies it. A chained space applies nothing the chain didn't sign: the
    /// change is queued for an Admin's app (mode `queue`, and the caller is told it worked, as
    /// Vaultwarden would) or refused. Steps of the server's own (a member accepting) go through.
    pub(crate) async fn external_apply(
        &self,
        changes: kemlock_app::spaces::SpaceChanges,
        creating: bool,
    ) -> Result<(), StoreError> {
        let space = changes.space_id;
        if creating {
            return self.write_changes(changes, true).await;
        }
        if !self.space_has_chain(space).await? {
            return self.write_changes_keeping_owner(changes).await;
        }
        let Some(state) = kemlock_app::spaces::SpaceRepo::load(self, space).await? else {
            return Err(StoreError::NotFound);
        };
        let (queued, other) = pending_from_changes(&state, &changes);
        if queued.is_empty() && !other {
            return self.write_changes_keeping_owner(changes).await;
        }
        if self.read_external_mode().await? != ExternalChangeMode::Queue {
            return Err(StoreError::Backend(
                kemlock_app::spaces::CHAIN_REQUIRED.to_owned(),
            ));
        }
        if other {
            tracing::warn!(%space, "an outside change to groups, collections or keys of a chained space was not applied");
        }
        let now = OffsetDateTime::now_utc();
        for (account, change) in queued {
            self.write_pending(PendingExternal {
                id: Uuid::new_v4(),
                space,
                source: ExternalSource::Bitwarden,
                queued_at: now,
                requested_by: None,
                via: "Bitwarden-compatible API".to_owned(),
                account,
                email: None,
                change,
            })
            .await?;
        }
        Ok(())
    }

    pub(crate) async fn write_held(
        &self,
        space: SpaceId,
        items: &[ItemId],
    ) -> Result<(), StoreError> {
        let txn = self.writer().begin().await.store()?;
        let outcome = async {
            ensure_items_of(&txn, Owner::Space(space), items).await?;
            for item in items {
                held::Entity::delete_many()
                    .filter(held::Column::ItemId.eq(item.0))
                    .exec(&txn)
                    .await
                    .store()?;
                held::Entity::insert(held::ActiveModel {
                    item_id: Set(item.0),
                    space_id: Set(space.0),
                })
                .exec(&txn)
                .await
                .store()?;
            }
            Ok::<(), StoreError>(())
        }
        .await;
        finish(txn, outcome, "a failed hold of items").await
    }

    /// Makes `items` exactly the space's held set: a replica's copy of the home's set, which
    /// replaces whatever it held before (an item the home released is no longer in it).
    pub(crate) async fn replace_held(
        &self,
        space: SpaceId,
        items: &[ItemId],
    ) -> Result<(), StoreError> {
        let txn = self.writer().begin().await.store()?;
        let outcome = async {
            held::Entity::delete_many()
                .filter(held::Column::SpaceId.eq(space.0))
                .exec(&txn)
                .await
                .store()?;
            // Only the space's own items can be held by it: the home of one space can't lift or
            // set the hold of an item of another.
            let (owner_type, owner_id) = crate::tables::items::owner_parts(Owner::Space(space));
            let ids: Vec<Uuid> = items.iter().map(|i| i.0).collect();
            let owned: Vec<Uuid> = crate::tables::items::Entity::find()
                .filter(crate::tables::items::Column::OwnerType.eq(owner_type))
                .filter(crate::tables::items::Column::OwnerId.eq(owner_id))
                .filter(crate::tables::items::Column::Id.is_in(ids))
                .all(&txn)
                .await
                .store()?
                .into_iter()
                .map(|row| row.id)
                .collect();
            for item in items.iter().filter(|i| owned.contains(&i.0)) {
                held::Entity::delete_many()
                    .filter(held::Column::ItemId.eq(item.0))
                    .filter(held::Column::SpaceId.eq(space.0))
                    .exec(&txn)
                    .await
                    .store()?;
                held::Entity::insert(held::ActiveModel {
                    item_id: Set(item.0),
                    space_id: Set(space.0),
                })
                .exec(&txn)
                .await
                .store()?;
            }
            Ok::<(), StoreError>(())
        }
        .await;
        finish(txn, outcome, "a failed copy of the held items").await
    }

    pub(crate) async fn read_held(&self, space: SpaceId) -> Result<Vec<ItemId>, StoreError> {
        Ok(held::Entity::find()
            .filter(held::Column::SpaceId.eq(space.0))
            .order_by_asc(held::Column::ItemId)
            .all(self.reader())
            .await
            .store()?
            .into_iter()
            .map(|row| ItemId(row.item_id))
            .collect())
    }
}

impl SqlStore {
    /// The chain records after `after` with their boxes and names, for publishing to replicas.
    pub(crate) async fn chain_wire_after(
        &self,
        space: SpaceId,
        after: Option<u64>,
    ) -> Result<Vec<ChainWire>, StoreError> {
        let from = after.map_or(0, |a| a.saturating_add(1));
        let mut out = Vec::new();
        for record in self.chain_records(space, from).await? {
            let seq = to_i64(record.seq, "seq")?;
            let seals = seals::Entity::find()
                .filter(seals::Column::SpaceId.eq(space.0))
                .filter(seals::Column::Seq.eq(seq))
                .order_by_asc(seals::Column::KeyRef)
                .order_by_asc(seals::Column::Member)
                .all(self.reader())
                .await
                .store()?;
            let names = names::Entity::find()
                .filter(names::Column::SpaceId.eq(space.0))
                .filter(names::Column::Seq.eq(seq))
                .order_by_asc(names::Column::Target)
                .all(self.reader())
                .await
                .store()?;
            out.push(ChainWire {
                seq: record.seq,
                link: record.link,
                epoch: record.epoch,
                by: *record.by.0.as_bytes(),
                at: record.at,
                entry: record.entry,
                signature: record.signature,
                cosignature: record.cosignature,
                seals: seals
                    .into_iter()
                    .map(|row| {
                        Ok(WireSeal {
                            key: row.key_ref,
                            version: u32::try_from(row.version).map_err(|_| bad("version"))?,
                            member: *row.member.as_bytes(),
                            bundle_version: u32::try_from(row.bundle_version)
                                .map_err(|_| bad("bundle version"))?,
                            sealed: row.sealed,
                        })
                    })
                    .collect::<Result<_, StoreError>>()?,
                names: names
                    .into_iter()
                    .map(|row| {
                        Ok(WireName {
                            target: row.target,
                            version: u32::try_from(row.version).map_err(|_| bad("version"))?,
                            hash: <[u8; 32]>::try_from(row.name_hash.as_slice())
                                .map_err(|_| bad("name hash"))?,
                            sealed: row.sealed,
                        })
                    })
                    .collect::<Result<_, StoreError>>()?,
            });
        }
        Ok(out)
    }

    /// Keeps a chain record a replica took from the home, when it is the next in the chain. The
    /// replica's other tables come from the space home records, so nothing is derived here.
    pub(crate) async fn keep_chain_wire(
        &self,
        space: SpaceId,
        wire: &ChainWire,
    ) -> Result<(), StoreError> {
        let txn = self.writer().begin().await.store()?;
        let outcome = async {
            let next = head_in(&txn, space).await?.map_or(0, |h| h.seq + 1);
            if wire.seq != next {
                return Ok::<(), StoreError>(());
            }
            let seq = to_i64(wire.seq, "seq")?;
            records::Entity::insert(records::ActiveModel {
                space_id: Set(space.0),
                seq: Set(seq),
                link: Set(wire.link.to_vec()),
                epoch: Set(i64::from(wire.epoch)),
                signer: Set(Uuid::from_bytes(wire.by)),
                at: Set(to_i64(wire.at, "at")?),
                entry: Set(wire.entry.clone()),
                signature: Set(wire.signature.clone()),
                cosignature: Set(wire.cosignature.clone()),
            })
            .exec(&txn)
            .await
            .store()?;
            for seal in &wire.seals {
                seals::Entity::insert(seals::ActiveModel {
                    space_id: Set(space.0),
                    seq: Set(seq),
                    key_ref: Set(seal.key.clone()),
                    version: Set(i64::from(seal.version)),
                    member: Set(Uuid::from_bytes(seal.member)),
                    bundle_version: Set(i64::from(seal.bundle_version)),
                    sealed: Set(seal.sealed.clone()),
                })
                .exec(&txn)
                .await
                .store()?;
            }
            for name in &wire.names {
                names::Entity::insert(names::ActiveModel {
                    space_id: Set(space.0),
                    seq: Set(seq),
                    target: Set(name.target.clone()),
                    version: Set(i64::from(name.version)),
                    name_hash: Set(name.hash.to_vec()),
                    sealed: Set(name.sealed.clone()),
                })
                .exec(&txn)
                .await
                .store()?;
            }
            Ok(())
        }
        .await;
        let kept = finish(txn, outcome, "a failed chain record from the home").await;
        // A record that sets the space's policies sets what this replica enforces too: derived from
        // the chain, never from a policies record of the home's own that no chain record backs.
        let sets_policies = sc::Record::parse(&wire.entry)
            .is_ok_and(|r| matches!(r.kind(), sc::Kind::Create | sc::Kind::Policies));
        if kept.is_ok() && sets_policies {
            self.project_policies_of(space).await?;
        }
        kept
    }
}
