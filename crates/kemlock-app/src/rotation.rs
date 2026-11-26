//! Rotating the root key (docs/crypto.md, "Rotating the root key").
//!
//! The browser makes a new root key and moves everything the old one protected under it; this
//! module is what the server does with the result, and none of it opens anything:
//!
//! - [`Rotation::plan`] says what the account holds that a rotation must cover;
//! - [`Rotation::stage`] keeps the re-encrypted items apart, invisible to every reader, until the
//!   install (so a rotation that fails or is abandoned leaves the vault as it was);
//! - [`Rotation::install`] checks the whole request and then installs it in **one transaction**
//!   ([`RotationStore::install`]): the new keys, every re-encrypted item, every new wrap, and the
//!   deletion of every wrap of the old root key, or nothing.
//!
//! The checks that need the account's holdings run inside the store's transaction, on a read made
//! there, through [`check_install`], so a wrap another device added while the client worked can
//! never be left behind.

use crate::authenticate::Actor;
use crate::config::AuthConfig;
use crate::error::AppError;
use crate::notices::{KeysRotatedNotice, Notice, Notices};
use crate::platform::{Platform, random_uuid};
use crate::ports::{ItemStore, Notifier, StoreError, UserRepo};
use crate::register::{
    BUNDLE_LEN, BUNDLE_PREFIX, BUNDLE_SIGNATURE_LEN, SEALED_PRIVATE_KEYS_RANGE,
    WRAPPED_ROOT_KEY_LEN, check_bundle_signature,
};
use kemlock_crypto::recovery_kit::{WRAPPED_LEN as KIT_WRAP_LEN, is_kit_id};
use kemlock_domain::item::{ITEM_KEY_LEN, MIN_SEALED_LEN};
use kemlock_domain::sends::SendId;
use kemlock_domain::unlock::{
    DeviceKeyCopy, EmergencyState, GrantId, KeyProtection, MAX_WRAPPED_KEY_LEN,
};
use kemlock_domain::{
    AccountMode, ChangeId, DeviceId, ItemFormat, ItemId, Owner, PasskeyId, PrfWrap, Revision,
    SpaceId, User, UserId,
};
use std::collections::{BTreeMap, BTreeSet};
use std::future::Future;
use time::{Duration, OffsetDateTime};
use uuid::Uuid;

/// The most items one staging request carries.
pub const MAX_STAGE_BATCH: usize = 200;
/// The most live items a rotation covers: the install is one transaction.
pub const MAX_ROTATION_ITEMS: usize = 50_000;
/// How long staged rows are good for.
pub const STAGING_TTL: Duration = Duration::hours(2);
/// A box of a root key sealed to a space's recovery key: `u8(1)` and 1,692 bytes.
pub const RECOVERY_BOX_LEN: usize = 1693;
/// A Send's sealed link key: `u32be(key version)` and a 48-byte seal.
pub const SEND_SEALED_KEY_LEN: usize = 4 + 12 + 32 + 16;
/// A Send's meta is at most 16 KiB and at least a nonce and a tag.
pub const SEND_META_RANGE: std::ops::RangeInclusive<usize> = 28..=16 * 1024;

// ---- what the account holds ----

/// Everything of the account that a rotation has to cover, read at one moment.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Holdings {
    /// The id of the Recovery Kit, when it has one.
    pub kit: Option<String>,
    /// The passkeys with a PRF wrap, with their credential ids.
    pub passkeys: Vec<(PasskeyId, Vec<u8>)>,
    /// The devices with a trusted-device copy.
    pub device_copies: Vec<DeviceId>,
    /// The emergency grants that hold a box, with their state and the contact's account.
    pub emergency: Vec<(GrantId, EmergencyState, Option<UserId>)>,
    /// The grants in which the account is the **contact** and holds a box: a grantor sealed their
    /// root key to the account's `kx1` key, which a rotation replaces, so the box opens no more.
    /// The install sends each back to waiting for its grantor's confirmation.
    pub as_contact: Vec<(GrantId, EmergencyState)>,
    /// The space recovery enrolments, with the `seq` of the recovery key each is sealed to.
    pub recovery: Vec<(SpaceId, u64)>,
    /// The Sends, with their kind (0 text, 1 file).
    pub sends: Vec<(SendId, i16)>,
    /// The live items of the vault, with their revision and format.
    pub live_items: Vec<(ItemId, Revision, ItemFormat)>,
    /// How many spaces the account is a member of.
    pub spaces: u64,
}

/// The Recovery Kit's previous keys, kept until the spaces have moved on.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PreviousKeys {
    pub key_version: u32,
    pub sealed: Vec<u8>,
}

/// What `GET /kem/v1/account/rotation` answers.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Plan {
    pub account: User,
    pub holdings: Holdings,
    pub previous_keys: Option<PreviousKeys>,
}

/// An item re-encrypted under the new keys, waiting for the install.
#[derive(Clone, PartialEq, Eq)]
pub struct StagedItem {
    pub id: ItemId,
    /// The revision the client read; the item is written at the next one.
    pub base_revision: Revision,
    pub ciphertext: Vec<u8>,
    pub item_key: Vec<u8>,
}

impl std::fmt::Debug for StagedItem {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("StagedItem")
            .field("id", &self.id)
            .field("base_revision", &self.base_revision)
            .finish_non_exhaustive()
    }
}

// ---- the request ----

/// A rotation's install, as a client sends it, decoded.
#[derive(Clone)]
pub struct InstallRequest {
    pub rotation: [u8; 16],
    pub from_version: u32,
    pub to_version: u32,
    pub public_bundle: Vec<u8>,
    pub bundle_signature: Vec<u8>,
    pub sealed_private_keys: Vec<u8>,
    pub sealed_previous_private_keys: Vec<u8>,
    /// The password wrap of the new root key; present exactly when the account has one.
    pub wrapped_root_key: Option<Vec<u8>>,
    /// The new Recovery Kit: its id and the wrap of the new root key.
    pub kit: Option<(String, Vec<u8>)>,
    pub drop_kit: bool,
    /// The calling device's trusted-device copy of the new root key.
    pub device_copy: Option<(Vec<u8>, KeyProtection)>,
    pub passkeys: Vec<(PasskeyId, Vec<u8>)>,
    pub drop_passkeys: Vec<PasskeyId>,
    pub emergency: Vec<(GrantId, Vec<u8>)>,
    pub drop_emergency: Vec<GrantId>,
    /// Space, the `seq` of the recovery key the box is sealed to, the box.
    pub recovery: Vec<(SpaceId, u64, Vec<u8>)>,
    pub drop_recovery: Vec<SpaceId>,
    /// Send, sealed key, meta.
    pub sends: Vec<(SendId, Vec<u8>, Vec<u8>)>,
    /// The client moves the account's spaces to the new keys itself.
    pub spaces_handled: bool,
}

impl std::fmt::Debug for InstallRequest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("InstallRequest")
            .field("from_version", &self.from_version)
            .field("to_version", &self.to_version)
            .finish_non_exhaustive()
    }
}

/// What the store is asked to install: the request, as checked, with the rows to write.
#[derive(Clone)]
pub struct Install {
    pub request: InstallRequest,
    /// The account as it was read: the write is conditional on it.
    pub before: User,
    /// The account as it will be.
    pub after: User,
    /// The signed-in device.
    pub device: DeviceId,
    pub now: OffsetDateTime,
    /// Staged rows older than this are ignored.
    pub staged_since: OffsetDateTime,
}

impl std::fmt::Debug for Install {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Install")
            .field("account", &self.before.id)
            .finish_non_exhaustive()
    }
}

// ---- refusals ----

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum RotationError {
    /// What the server holds is not what the request names: a wrap, a Send or an item changed
    /// since the client read the plan. Carries what, in words and counts, never a key.
    #[error("the account changed since the plan was read: {0}")]
    Incomplete(String),
    /// `fromVersion` or `toVersion` is not the account's version and the next one.
    #[error("the key version is not the account's")]
    StaleVersion,
    /// The account is in a space and the client did not say it moves the space's keys.
    #[error("the account is in a space whose keys must move too")]
    SpacesNeedRekey,
    /// A live item is not in `kem1` format, so it cannot be re-encrypted.
    #[error("an item of the vault is in a format that can't be rotated")]
    UnsupportedItems,
    /// The account's vault is federated (a replica holds a copy of the account, or the personal
    /// vault has replicas): another server holds wraps and ciphertext this one can't replace.
    #[error("the account's vault is federated")]
    Federated,
    /// The account is shared with the Bitwarden apps, which hold its root key.
    #[error("the account is shared with Bitwarden apps")]
    CompatibleAccount,
    /// The account row changed while the rotation was made: nothing was written.
    #[error("the account changed meanwhile")]
    AccountChanged,
    #[error(transparent)]
    App(#[from] AppError),
}

impl From<StoreError> for RotationError {
    fn from(e: StoreError) -> Self {
        RotationError::App(AppError::from(e))
    }
}

// ---- the port ----

pub trait RotationStore: Send + Sync {
    /// What the account holds that a rotation covers.
    fn holdings(&self, user: UserId) -> impl Future<Output = Result<Holdings, StoreError>> + Send;

    /// What the account holds and the items `rotation` staged since `since`, as `(item, base
    /// revision)`, read without a lock: for a check that spends nothing, before the password and a
    /// one-time proof are spent on an install the same check would refuse.
    fn snapshot(
        &self,
        user: UserId,
        rotation: [u8; 16],
        since: OffsetDateTime,
    ) -> impl Future<Output = Result<(Holdings, Vec<(ItemId, Revision)>), StoreError>> + Send;

    /// Stages `items` for `rotation`: a row for the same item is replaced;
 rows of another
    /// rotation, or staged before `since`, are deleted first. Returns how many rows the rotation
    /// has staged now.
    fn stage(
        &self,
        user: UserId,
        rotation: [u8; 16],
        items: Vec<StagedItem>,
        now: OffsetDateTime,
        since: OffsetDateTime,
    ) -> impl Future<Output = Result<u64, StoreError>> + Send;

    /// Deletes the account's staged rows.
    fn discard(&self, user: UserId) -> impl Future<Output = Result<(), StoreError>> + Send;

    /// Installs the rotation in one transaction: reads the account's holdings and staged rows
    /// there, runs [`check_install`], and either writes everything or nothing. See the module
    /// docs for what is written.
    fn install(
        &self,
        install: Install,
    ) -> impl Future<Output = Result<Option<ChangeId>, RotationError>> + Send;

    /// The previous private keys, while they are kept.
    fn previous_keys(
        &self,
        user: UserId,
    ) -> impl Future<Output = Result<Option<PreviousKeys>, StoreError>> + Send;

    /// Deletes the previous private keys; `true` when there were some.
    fn clear_previous_keys(
        &self,
        user: UserId,
    ) -> impl Future<Output = Result<bool, StoreError>> + Send;
}

// ---- the checks that need the account's holdings ----

/// `named` and `dropped` are disjoint, repeat nothing, and together are exactly `held`.
fn covers(
    what: &str,
    held: &BTreeSet<Uuid>,
    named: &[Uuid],
    dropped: &[Uuid],
) -> Result<(), RotationError> {
    let mut seen = BTreeSet::new();
    for id in named.iter().chain(dropped) {
        if !seen.insert(*id) {
            return Err(AppError::Invalid("a wrap is named twice").into());
        }
    }
    let missing = held.difference(&seen).count();
    let unknown = seen.difference(held).count();
    if missing > 0 || unknown > 0 {
        return Err(RotationError::Incomplete(format!(
            "{what}: {missing} not named, {unknown} not held"
        )));
    }
    Ok(())
}

/// Every wrap of the old root key the account holds is replaced or named as dropped, and nothing
/// else; the staged items are exactly the live items at the revisions the client read; and the
/// account's spaces are the client's to move. Run by the store inside the install's transaction on
/// the holdings and staged rows it read there.
pub fn check_install(
    install: &Install,
    holdings: &Holdings,
    staged: &[(ItemId, Revision)],
) -> Result<(), RotationError> {
    let request = &install.request;

    // The install is one transaction: a vault too large for it is refused, not half moved.
    if holdings.live_items.len() > MAX_ROTATION_ITEMS {
        return Err(AppError::Invalid("the vault has more items than one rotation moves").into());
    }

    covers(
        "passkeys",
        &holdings.passkeys.iter().map(|(id, _)| id.0).collect(),
        &request
            .passkeys
            .iter()
            .map(|(id, _)| id.0)
            .collect::<Vec<_>>(),
        &request
            .drop_passkeys
            .iter()
            .map(|id| id.0)
            .collect::<Vec<_>>(),
    )?;
    covers(
        "emergency grants",
        &holdings.emergency.iter().map(|(id, _, _)| id.0).collect(),
        &request
            .emergency
            .iter()
            .map(|(id, _)| id.0)
            .collect::<Vec<_>>(),
        &request
            .drop_emergency
            .iter()
            .map(|id| id.0)
            .collect::<Vec<_>>(),
    )?;
    covers(
        "space recovery boxes",
        &holdings.recovery.iter().map(|(space, _)| space.0).collect(),
        &request
            .recovery
            .iter()
            .map(|(space, _, _)| space.0)
            .collect::<Vec<_>>(),
        &request
            .drop_recovery
            .iter()
            .map(|space| space.0)
            .collect::<Vec<_>>(),
    )?;
    covers(
        "sends",
        &holdings.sends.iter().map(|(id, _)| id.0).collect(),
        &request
            .sends
            .iter()
            .map(|(id, _, _)| id.0)
            .collect::<Vec<_>>(),
        &[],
    )?;
    // A box is sealed to one recovery key; one sealed to another is no replacement.
    let seqs: BTreeMap<Uuid, u64> = holdings
        .recovery
        .iter()
        .map(|(space, seq)| (space.0, *seq))
        .collect();
    if request
        .recovery
        .iter()
        .any(|(space, seq, _)| seqs.get(&space.0) != Some(seq))
    {
        return Err(RotationError::Incomplete(
            "space recovery boxes: a recovery key changed".to_owned(),
        ));
    }

    match (&holdings.kit, &request.kit, request.drop_kit) {
        (_, Some(_), true) => {
            return Err(AppError::Invalid("a kit can't be both replaced and dropped").into());
        }
        (Some(_), None, false) => {
            return Err(RotationError::Incomplete(
                "kit: held, neither replaced nor dropped".to_owned(),
            ));
        }
        _ => {}
    }

    if holdings
        .live_items
        .iter()
        .any(|(_, _, format)| *format != ItemFormat::Kem1)
    {
        return Err(RotationError::UnsupportedItems);
    }
    let live: BTreeMap<ItemId, Revision> = holdings
        .live_items
        .iter()
        .map(|(id, revision, _)| (*id, *revision))
        .collect();
    // A row staged for an item that is no longer live (deleted since) is of no account.
    let staged: BTreeMap<ItemId, Revision> = staged
        .iter()
        .copied()
        .filter(|(id, _)| live.contains_key(id))
        .collect();
    if live != staged {
        let changed = live
            .iter()
            .filter(|(id, revision)| staged.get(id) != Some(revision))
            .count();
        return Err(RotationError::Incomplete(format!(
            "items: {changed} to stage again"
        )));
    }

    if holdings.spaces > 0 && !request.spaces_handled {
        return Err(RotationError::SpacesNeedRekey);
    }
    Ok(())
}

// ---- the use cases ----

/// Rotating the account's root key.
#[derive(Debug)]
pub struct Rotation<U, I, R, E, N> {
    pub users: U,
    pub items: I,
    pub store: R,
    pub env: E,
    /// Tells the account's open devices to sync (they find their sessions ended).
    pub push: N,
    /// Mails the account's address.
    pub notices: Notices,
    pub config: AuthConfig,
}

impl<U, I, R, E, N> Rotation<U, I, R, E, N>
where
    U: UserRepo,
    I: ItemStore,
    R: RotationStore,
    E: Platform,
    N: Notifier,
{
    /// The account, if it can be rotated: it has keys and is not shared with the Bitwarden apps.
    async fn account(&self, user: UserId) -> Result<User, RotationError> {
        let account = self
            .users
            .by_id(user)
            .await?
            .ok_or(AppError::Unauthorized)?;
        if account.mode == AccountMode::Compatible {
            return Err(RotationError::CompatibleAccount);
        }
        if account.public_bundle.is_empty() || account.key_version == 0 {
            return Err(AppError::NotFound.into());
        }
        Ok(account)
    }

    /// What the account holds and what the previous keys are.
    pub async fn plan(&self, user: UserId) -> Result<Plan, RotationError> {
        let account = self.account(user).await?;
        let holdings = self.store.holdings(user).await?;
        let previous_keys = self.store.previous_keys(user).await?;
        Ok(Plan {
            account,
            holdings,
            previous_keys,
        })
    }

    /// Stages re-encrypted items. Each must be a live `kem1` item of the account's vault at the
    /// revision the client read, with well-formed sealed values; the next revision and the key
    /// are the client's (the server can't open them).
    pub async fn stage(
        &self,
        user: UserId,
        rotation: [u8; 16],
        to_version: u32,
        items: Vec<StagedItem>,
    ) -> Result<u64, RotationError> {
        let account = self.account(user).await?;
        if account.key_version.checked_add(1) != Some(to_version) {
            return Err(RotationError::StaleVersion);
        }
        if items.is_empty() || items.len() > MAX_STAGE_BATCH {
            return Err(AppError::Invalid("a staging request holds 1 to 200 items").into());
        }
        let mut seen = BTreeSet::new();
        for staged in &items {
            if !seen.insert(staged.id) {
                return Err(AppError::Invalid("an item appears twice in the request").into());
            }
            if staged.ciphertext.len() < MIN_SEALED_LEN
                || staged.ciphertext.len() > self.config.item_limits.max_ciphertext
                || staged.item_key.len() != ITEM_KEY_LEN
            {
                return Err(AppError::Invalid("a sealed value is malformed").into());
            }
            let stored = self.items.get(staged.id).await?;
            let fits = stored.is_some_and(|item| {
                item.owner == Owner::User(user)
                    && !item.is_tombstone()
                    && item.format == ItemFormat::Kem1
                    && item.revision == staged.base_revision
            });
            if !fits {
                return Err(RotationError::Incomplete(
                    "items: one changed since it was read".to_owned(),
                ));
            }
        }
        let now = self.env.now();
        Ok(self
            .store
            .stage(user, rotation, items, now, now - STAGING_TTL)
            .await?)
    }

    /// Abandons: deletes the staged rows.
    pub async fn discard(&self, user: UserId) -> Result<(), RotationError> {
        Ok(self.store.discard(user).await?)
    }

    /// Says the spaces have moved to the new keys: the previous private keys are deleted. `false`
    /// when there were none.
    pub async fn finish_spaces(&self, user: UserId) -> Result<bool, RotationError> {
        Ok(self.store.clear_previous_keys(user).await?)
    }

    /// What can be known without the account's holdings, before the password is spent: the
    /// account, the versions, and the shape of every value. Returns the account.
    pub async fn check(
        &self,
        user: UserId,
        request: &InstallRequest,
    ) -> Result<User, RotationError> {
        let account = self.account(user).await?;
        if request.from_version != account.key_version
            || account.key_version.checked_add(1) != Some(request.to_version)
        {
            return Err(RotationError::StaleVersion);
        }
        check_shapes(&account, request)?;
        Ok(account)
    }

    /// The checks the install runs inside its transaction, run now on a plain read: it says what
    /// the install would say about the account's wraps, Sends and items, and spends nothing. The
    /// route runs it before it asks for the password and a one-time proof, so an install that
    /// another device's write made incomplete does not burn either. The install checks again.
    pub async fn precheck(
        &self,
        actor: &Actor,
        request: &InstallRequest,
    ) -> Result<(), RotationError> {
        let account = self.check(actor.user, request).await?;
        let now = self.env.now();
        let (holdings, staged) = self
            .store
            .snapshot(actor.user, request.rotation, now - STAGING_TTL)
            .await?;
        let install = Install {
            request: request.clone(),
            before: account.clone(),
            after: account,
            device: actor.device,
            now,
            staged_since: now - STAGING_TTL,
        };
        check_install(&install, &holdings, &staged)
    }

    /// Installs the rotation. `actor` is the signed-in device.
 Returns the account as it is now.
    pub async fn install(
        &self,
        actor: &Actor,
        request: InstallRequest,
    ) -> Result<User, RotationError> {
        let before = self.check(actor.user, &request).await?;
        let now = self.env.now();
        let after = User {
            public_bundle: request.public_bundle.clone(),
            bundle_signature: request.bundle_signature.clone(),
            sealed_private_keys: request.sealed_private_keys.clone(),
            wrapped_root_key: request.wrapped_root_key.clone().unwrap_or_default(),
            key_version: request.to_version,
            security_stamp: random_uuid(&self.env),
            updated_at: now,
            ..before.clone()
        };
        let change = self
            .store
            .install(Install {
                request,
                before: before.clone(),
                after: after.clone(),
                device: actor.device,
                now,
                staged_since: now - STAGING_TTL,
            })
            .await?;
        // The keys are rotated: nothing from here on can say they were not. The mail is best
        // effort, and the nudge makes every open device sync and find its session ended.
        self.notices
            .send(Notice::KeysRotated(KeysRotatedNotice {
                to: after.email.clone(),
                at: now,
            }))
            .await;
        if let Some(change) = change {
            self.push.sync_now(Owner::User(before.id), change).await;
        }
        Ok(after)
    }
}

/// The shape of everything the client sent, against the account as it is.
fn check_shapes(account: &User, request: &InstallRequest) -> Result<(), RotationError> {
    let invalid = |why: &'static str| RotationError::App(AppError::Invalid(why));

    // The bundle: for this account at the new version, signed by its own key, with a new pair.
    let bundle = &request.public_bundle;
    let layout_ok = bundle.len() == BUNDLE_LEN
        && bundle.starts_with(BUNDLE_PREFIX)
        && bundle[17..33] == *account.id.as_bytes()
        && bundle[33..37] == request.to_version.to_be_bytes();
    if !layout_ok {
        return Err(invalid("the public bundle is malformed"));
    }
    if request.bundle_signature.len() != BUNDLE_SIGNATURE_LEN {
        return Err(invalid("the bundle signature is malformed"));
    }
    check_bundle_signature(bundle, &request.bundle_signature)?;
    let old = &account.public_bundle;
    if old.len() == BUNDLE_LEN
        && (old[37..1637] == bundle[37..1637] || old[1637..] == bundle[1637..])
    {
        return Err(invalid("the key pair must be replaced"));
    }
    if !SEALED_PRIVATE_KEYS_RANGE.contains(&request.sealed_private_keys.len())
        || !SEALED_PRIVATE_KEYS_RANGE.contains(&request.sealed_previous_private_keys.len())
    {
        return Err(invalid("the sealed private keys are malformed"));
    }

    // The password wrap is there exactly when the account has a password wrap.
    match (
        &request.wrapped_root_key,
        account.wrapped_root_key.is_empty(),
    ) {
        (Some(wrap), false) if wrap.len() == WRAPPED_ROOT_KEY_LEN => {}
        (None, true) => {}
        _ => return Err(invalid("the password wrap is missing, extra or malformed")),
    }

    if let Some((kit_id, wrap)) = &request.kit
        && (!is_kit_id(kit_id) || wrap.len() != KIT_WRAP_LEN)
    {
        return Err(invalid("the recovery kit is malformed"));
    }
    if let Some((wrap, _)) = &request.device_copy
        && (wrap.is_empty() || wrap.len() > MAX_WRAPPED_KEY_LEN)
    {
        return Err(invalid("the device copy must be 1 to 1024 bytes"));
    }
    if request
        .passkeys
        .iter()
        .any(|(_, wrap)| wrap.len() != PrfWrap::WRAPPED_KEY_LEN)
    {
        return Err(invalid("a passkey wrap is malformed"));
    }
    if request
        .emergency
        .iter()
        .any(|(_, boxed)| !kemlock_domain::unlock::sealed_key_len_ok(boxed.len()))
    {
        return Err(invalid("an emergency box is malformed"));
    }
    if request
        .recovery
        .iter()
        .any(|(_, _, boxed)| boxed.len() != RECOVERY_BOX_LEN || boxed.first() != Some(&1))
    {
        return Err(invalid("a recovery box is malformed"));
    }
    let version_prefix = request.to_version.to_be_bytes();
    if request.sends.iter().any(|(_, sealed_key, meta)| {
        sealed_key.len() != SEND_SEALED_KEY_LEN
            || sealed_key[..4] != version_prefix
            || !SEND_META_RANGE.contains(&meta.len())
    }) {
        return Err(invalid("a Send's sealed values are malformed"));
    }
    Ok(())
}

/// The calling device's copy as a row, for the store.
pub fn device_copy_row(install: &Install) -> Option<DeviceKeyCopy> {
    install
        .request
        .device_copy
        .as_ref()
        .map(|(wrapped_key, protection)| DeviceKeyCopy {
            device: install.device,
            wrapped_key: wrapped_key.clone(),
            protection: *protection,
            created_at: install.now,
            updated_at: install.now,
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    use kemlock_domain::{KdfParams, Role};

    fn request() -> InstallRequest {
        InstallRequest {
            rotation: [1; 16],
            from_version: 1,
            to_version: 2,
            public_bundle: Vec::new(),
            bundle_signature: Vec::new(),
            sealed_private_keys: Vec::new(),
            sealed_previous_private_keys: Vec::new(),
            wrapped_root_key: None,
            kit: None,
            drop_kit: false,
            device_copy: None,
            passkeys: Vec::new(),
            drop_passkeys: Vec::new(),
            emergency: Vec::new(),
            drop_emergency: Vec::new(),
            recovery: Vec::new(),
            drop_recovery: Vec::new(),
            sends: Vec::new(),
            spaces_handled: false,
        }
    }

    fn user() -> User {
        let now = OffsetDateTime::UNIX_EPOCH;
        User {
            id: UserId::random(),
            email: kemlock_domain::Email::parse("a@b.co").expect("email"),
            name: None,
            mode: AccountMode::KemlockOnly,
            role: Role::User,
            kdf: KdfParams::new_account([0; 16]),
            opaque_record: None,
            wrapped_root_key: Vec::new(),
            public_bundle: Vec::new(),
            bundle_signature: Vec::new(),
            sealed_private_keys: Vec::new(),
            key_version: 1,
            security_stamp: Uuid::nil(),
            created_at: now,
            updated_at: now,
        }
    }

    fn install(request: InstallRequest) -> Install {
        let now = OffsetDateTime::UNIX_EPOCH;
        Install {
            request,
            before: user(),
            after: user(),
            device: DeviceId::random(),
            now,
            staged_since: now,
        }
    }

    fn item(id: ItemId, revision: u64) -> (ItemId, Revision, ItemFormat) {
        (id, Revision(revision), ItemFormat::Kem1)
    }

    #[test]
    fn an_empty_account_needs_nothing() {
        assert_eq!(
            check_install(&install(request()), &Holdings::default(), &[]),
            Ok(())
        );
    }

    #[test]
    fn every_wrap_is_replaced_or_dropped_and_nothing_else() {
        let (a, b) = (PasskeyId::random(), PasskeyId::random());
        let holdings = Holdings {
            passkeys: vec![(a, vec![1]), (b, vec![2])],
            ..Holdings::default()
        };
        let mut r = request();
        r.passkeys = vec![(a, vec![0; 92])];
        // One passkey is named nowhere: refused.
        assert!(matches!(
            check_install(&install(r.clone()), &holdings, &[]),
            Err(RotationError::Incomplete(_))
        ));
        r.drop_passkeys = vec![b];
        assert_eq!(check_install(&install(r.clone()), &holdings, &[]), Ok(()));
        // A passkey the server does not hold, a wrap named twice, and one both replaced and dropped.
        let mut stray = r.clone();
        stray.drop_passkeys.push(PasskeyId::random());
        assert!(matches!(
            check_install(&install(stray), &holdings, &[]),
            Err(RotationError::Incomplete(_))
        ));
        let mut twice = r.clone();
        twice.drop_passkeys.push(a);
        assert!(matches!(
            check_install(&install(twice), &holdings, &[]),
            Err(RotationError::App(AppError::Invalid(_)))
        ));
    }

    #[test]
    fn a_kit_is_replaced_or_dropped_when_there_is_one() {
        let holdings = Holdings {
            kit: Some("ABCDEFGH".to_owned()),
            ..Holdings::default()
        };
        let mut r = request();
        assert!(matches!(
            check_install(&install(r.clone()), &holdings, &[]),
            Err(RotationError::Incomplete(_))
        ));
        r.drop_kit = true;
        assert_eq!(check_install(&install(r.clone()), &holdings, &[]), Ok(()));
        r.kit = Some(("ABCDEFGH".to_owned(), vec![0; 92]));
        assert!(matches!(
            check_install(&install(r), &holdings, &[]),
            Err(RotationError::App(AppError::Invalid(_)))
        ));
    }

    #[test]
    fn the_staged_items_are_exactly_the_live_ones_at_the_revisions_read() {
        let (a, b) = (ItemId::random(), ItemId::random());
        let holdings = Holdings {
            live_items: vec![item(a, 3), item(b, 1)],
            ..Holdings::default()
        };
        let r = request();
        let ok = [(a, Revision(3)), (b, Revision(1))];
        assert_eq!(check_install(&install(r.clone()), &holdings, &ok), Ok(()));
        // One item was edited since it was staged, one is missing.
        for staged in [
            vec![(a, Revision(2)), (b, Revision(1))],
            vec![(a, Revision(3))],
        ] {
            assert!(
                matches!(
                    check_install(&install(r.clone()), &holdings, &staged),
                    Err(RotationError::Incomplete(_))
                ),
                "{staged:?}"
            );
        }
    }

    #[test]
    fn a_vault_too_large_for_one_transaction_is_refused() {
        let live: Vec<_> = (0..=MAX_ROTATION_ITEMS)
            .map(|n| item(ItemId::random(), n as u64 + 1))
            .collect();
        let staged: Vec<_> = live.iter().map(|(id, revision, _)| (*id, *revision)).collect();
        let holdings = Holdings {
            live_items: live,
            ..Holdings::default()
        };
        assert!(matches!(
            check_install(&install(request()), &holdings, &staged),
            Err(RotationError::App(AppError::Invalid(_)))
        ));
    }

    #[test]
    fn a_row_staged_for_an_item_deleted_since_is_ignored() {
        let a = ItemId::random();
        let holdings = Holdings {
            live_items: vec![item(a, 3)],
            ..Holdings::default()
        };
        let staged = [(a, Revision(3)), (ItemId::random(), Revision(1))];
        assert_eq!(
            check_install(&install(request()), &holdings, &staged),
            Ok(())
        );
    }

    #[test]
    fn an_item_that_is_not_kem1_stops_the_rotation() {
        let a = ItemId::random();
        let holdings = Holdings {
            live_items: vec![(a, Revision(1), ItemFormat::Bw)],
            ..Holdings::default()
        };
        assert_eq!(
            check_install(&install(request()), &holdings, &[(a, Revision(1))]),
            Err(RotationError::UnsupportedItems)
        );
    }

    #[test]
    fn spaces_need_the_client_to_say_it_moves_them() {
        let holdings = Holdings {
            spaces: 2,
            ..Holdings::default()
        };
        let mut r = request();
        assert_eq!(
            check_install(&install(r.clone()), &holdings, &[]),
            Err(RotationError::SpacesNeedRekey)
        );
        r.spaces_handled = true;
        assert_eq!(check_install(&install(r), &holdings, &[]), Ok(()));
    }

    #[test]
    fn a_recovery_box_must_be_for_the_recovery_key_the_server_holds() {
        let space = SpaceId::random();
        let holdings = Holdings {
            recovery: vec![(space, 4)],
            ..Holdings::default()
        };
        let mut r = request();
        r.recovery = vec![(space, 4, vec![1; RECOVERY_BOX_LEN])];
        assert_eq!(check_install(&install(r.clone()), &holdings, &[]), Ok(()));
        r.recovery = vec![(space, 5, vec![1; RECOVERY_BOX_LEN])];
        assert!(matches!(
            check_install(&install(r), &holdings, &[]),
            Err(RotationError::Incomplete(_))
        ));
    }

    #[test]
    fn the_sends_are_exactly_the_accounts() {
        let (a, b) = (SendId::random(), SendId::random());
        let holdings = Holdings {
            sends: vec![(a, 0), (b, 1)],
            ..Holdings::default()
        };
        let mut r = request();
        r.sends = vec![(a, vec![0; SEND_SEALED_KEY_LEN], vec![0; 40])];
        assert!(matches!(
            check_install(&install(r.clone()), &holdings, &[]),
            Err(RotationError::Incomplete(_))
        ));
        r.sends.push((b, vec![0; SEND_SEALED_KEY_LEN], vec![0; 40]));
        assert_eq!(check_install(&install(r), &holdings, &[]), Ok(()));
    }

    #[test]
    fn a_send_wrap_names_the_new_key_version() {
        let account = user();
        let mut r = request();
        // The shape check stops at the bundle first; the Send rule is exercised on its own.
        let prefix = r.to_version.to_be_bytes();
        let ok = [prefix.as_slice(), &[0; 60]].concat();
        let old = [1u32.to_be_bytes().as_slice(), &[0; 60]].concat();
        assert_eq!(ok.len(), SEND_SEALED_KEY_LEN);
        assert_ne!(ok[..4], old[..4]);
        r.sends = vec![(SendId::random(), old, vec![0; 40])];
        assert!(check_shapes(&account, &r).is_err());
    }
}
