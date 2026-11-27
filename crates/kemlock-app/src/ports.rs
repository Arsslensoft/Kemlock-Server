//! The ports use cases call. Adapters implement them; tests use in-memory fakes.
//!
//! Async methods are written as `fn … -> impl Future<Output = …> + Send` so implementers can use
//! `async fn` and use cases stay `Send` for axum. Every method is cancel-safe: a dropped future
//! leaves the store as it was or as it would have been after the call.

use kemlock_domain::spaces::CollectionId;
use kemlock_domain::{
    ChangeId, Device, DeviceId, Email, Item, ItemDraft, ItemId, Owner, Revision, ServerId, User,
    UserId, VersionVector,
};
use std::future::Future;
use time::OffsetDateTime;
use uuid::Uuid;

/// A buffer wiped when dropped; what `SecretSeal::open` returns.
pub use zeroize::Zeroizing;

/// Why a store call failed.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum StoreError {
    /// An optimistic check failed: the item's stored revision isn't the one the write expected.
    #[error("item {item} changed: stored revision is {current:?}")]
    Conflict {
        item: ItemId,
        current: Option<Revision>,
    },
    /// A unique key is taken (an email, an item id under another owner).
    #[error("already exists")]
    Duplicate,
    #[error("not found")]
    NotFound,
    /// The database or file storage failed; the message is for logs, never for clients.
    #[error("store failure: {0}")]
    Backend(String),
}

/// The wall clock. Use cases never read the system time directly.
pub trait Clock: Send + Sync {
    fn now(&self) -> OffsetDateTime;
}

/// A cryptographically secure random source.
pub trait Random: Send + Sync {
    fn fill(&self, buf: &mut [u8]);

    fn bytes<const N: usize>(&self) -> [u8; N]
    where
        Self: Sized,
    {
        let mut out = [0u8; N];
        self.fill(&mut out);
        out
    }
}

/// This installation's identity and setup state.
pub trait ServerInfo: Send + Sync {
    /// This server's id, made at first start and never changed. Every change it accepts carries it.
    fn server_id(&self) -> ServerId;
}

/// A hold on an account until the link mailed to its address is opened.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct EmailConfirmation {
    pub user: UserId,
    /// When the link was made.
    pub requested_at: OffsetDateTime,
    /// When it stops working.
    pub expires_at: OffsetDateTime,
}

/// A public-key bundle an account has had, with its self-signature, at one key version.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StoredBundle {
    pub key_version: u32,
    pub public_bundle: Vec<u8>,
    pub bundle_signature: Vec<u8>,
}

pub trait UserRepo: Send + Sync {
    fn by_id(&self, id: UserId) -> impl Future<Output = Result<Option<User>, StoreError>> + Send;
    fn by_email(
        &self,
        email: &Email,
    ) -> impl Future<Output = Result<Option<User>, StoreError>> + Send;
    /// Inserts a new account; `Duplicate` when the email is taken.
    fn insert(&self, user: &User) -> impl Future<Output = Result<(), StoreError>> + Send;
    fn update(&self, user: &User) -> impl Future<Output = Result<(), StoreError>> + Send;
    /// Stores the account's first keys (`public_bundle`, `bundle_signature`,
    /// `sealed_private_keys`, `key_version` and `updated_at` of `user`) only while the account
    /// still has none (`key_version` 0), in one step: of two callers at once, one gets `Ok` and the
    /// other `Duplicate`. `NotFound` for no such account. The default checks and then writes in
    /// two steps, which is only as good as the store is single-threaded; a store that serves
    /// requests concurrently overrides it with a conditional write.
    fn set_first_keys(&self, user: &User) -> impl Future<Output = Result<(), StoreError>> + Send {
        async move {
            match self.by_id(user.id).await? {
                None => Err(StoreError::NotFound),
                Some(old) if old.key_version != 0 => Err(StoreError::Duplicate),
                Some(mut old) => {
                    old.public_bundle = user.public_bundle.clone();
                    old.bundle_signature = user.bundle_signature.clone();
                    old.sealed_private_keys = user.sealed_private_keys.clone();
                    old.key_version = user.key_version;
                    old.updated_at = user.updated_at;
                    self.update(&old).await
                }
            }
        }
    }
    /// The account's bundle at `key_version`: the current one, or one it had before a key
    /// replacement (docs/crypto.md, "Signed item writes"), for as long as the store keeps them.
    /// `None` for a version the account never had, or one the store no longer holds.
    ///
    /// The default knows only the current bundle, for a store that keeps no history.
    fn bundle_at(
        &self,
        id: UserId,
        key_version: u32,
    ) -> impl Future<Output = Result<Option<StoredBundle>, StoreError>> + Send {
        async move {
            Ok(self
                .by_id(id)
                .await?
                .filter(|u| u.key_version == key_version && !u.public_bundle.is_empty())
                .map(|u| StoredBundle {
                    key_version: u.key_version,
                    public_bundle: u.public_bundle,
                    bundle_signature: u.bundle_signature,
                }))
        }
    }

    /// When the account replaced its bundle at `key_version` with the next version, Unix seconds:
    /// when the keys of that version stopped signing (docs/crypto.md, "Signed item writes"). `None`
    /// for the current version, and for one the store doesn't know the end of.
    ///
    /// The default knows none.
    fn bundle_retired_at(
        &self,
        _id: UserId,
        _key_version: u32,
    ) -> impl Future<Output = Result<Option<i64>, StoreError>> + Send {
        async { Ok(None) }
    }

    /// Every bundle the account has had that the store holds, oldest key version first, the
    /// current one last. The default has only the current one.
    fn bundles_of(
        &self,
        id: UserId,
    ) -> impl Future<Output = Result<Vec<StoredBundle>, StoreError>> + Send {
        async move {
            Ok(self
                .by_id(id)
                .await?
                .filter(|u| u.key_version > 0 && !u.public_bundle.is_empty())
                .map(|u| StoredBundle {
                    key_version: u.key_version,
                    public_bundle: u.public_bundle,
                    bundle_signature: u.bundle_signature,
                })
                .into_iter()
                .collect())
        }
    }

    fn count_admins(&self) -> impl Future<Output = Result<u64, StoreError>> + Send;
    /// Whether the account may not sign in: an admin disabled it, or Vaultwarden had it disabled
    /// before the move. Sign-in and refresh on both APIs ask this and issue nothing to a disabled
    /// account.
    fn account_disabled(&self, id: UserId)
    -> impl Future<Output = Result<bool, StoreError>> + Send;

    /// When the account's erasure is due, while one is pending (the deleted-account grace
    /// period). Sign-in and refresh on both APIs ask this after the credentials check out and
    /// answer that the account is being deleted. A store with no erasure schedule keeps this
    /// default: nothing is pending.
    fn erasure_pending(
        &self,
        id: UserId,
    ) -> impl Future<Output = Result<Option<OffsetDateTime>, StoreError>> + Send {
        let _ = id;
        async { Ok(None) }
    }

    /// Whether the account is held back until the link mailed to its address is opened (the
    /// "verify the email of a new account" setting): it may not sign in or act until then. An
    /// account with no hold is confirmed, as every account is that existed before the setting.
    /// A store with no such holds keeps this default: nothing is held.
    fn email_unconfirmed(
        &self,
        id: UserId,
    ) -> impl Future<Output = Result<bool, StoreError>> + Send {
        let _ = id;
        async { Ok(false) }
    }

    /// Inserts a new account that is held until its link is opened, in one step: the account and
    /// its hold go in together or not at all, so the account is never there unheld. `Duplicate`
    /// when the email is taken. The default inserts and then holds in two steps, which leaves a
    /// moment between them; a store that serves requests concurrently overrides it with a
    /// transaction.
    fn insert_held(
        &self,
        user: &User,
        token_hash: [u8; 32],
        requested_at: OffsetDateTime,
        expires_at: OffsetDateTime,
    ) -> impl Future<Output = Result<(), StoreError>> + Send {
        async move {
            self.insert(user).await?;
            self.hold_unconfirmed(user.id, token_hash, requested_at, expires_at)
                .await
        }
    }

    /// Holds the account until its link is opened, in place of any hold it had: `token_hash` is
    /// the SHA-256 of the link's token, which stops working at `expires_at`.
    fn hold_unconfirmed(
        &self,
        id: UserId,
        token_hash: [u8; 32],
        requested_at: OffsetDateTime,
        expires_at: OffsetDateTime,
    ) -> impl Future<Output = Result<(), StoreError>> + Send {
        let _ = (id, token_hash, requested_at, expires_at);
        async {
            Err(StoreError::Backend(
                "this store can't hold an account until its email is confirmed".to_owned(),
            ))
        }
    }

    /// The account's hold, if it has one: when its link was made and when it runs out.
    fn confirmation_of(
        &self,
        id: UserId,
    ) -> impl Future<Output = Result<Option<EmailConfirmation>, StoreError>> + Send {
        let _ = id;
        async { Ok(None) }
    }

    /// Spends the link whose token has this SHA-256: the hold is removed and the account is
    /// said. `None` for a link that is unknown, spent or out of time at `now`.
    fn spend_confirmation(
        &self,
        token_hash: [u8; 32],
        now: OffsetDateTime,
    ) -> impl Future<Output = Result<Option<UserId>, StoreError>> + Send {
        let _ = (token_hash, now);
        async { Ok(None) }
    }
}

pub trait DeviceRepo: Send + Sync {
    fn get(&self, id: DeviceId) -> impl Future<Output = Result<Option<Device>, StoreError>> + Send;
    /// Inserts or replaces the device with this id.
    fn upsert(&self, device: &Device) -> impl Future<Output = Result<(), StoreError>> + Send;
    fn list(&self, user: UserId) -> impl Future<Output = Result<Vec<Device>, StoreError>> + Send;
    /// Deletes the device, its refresh tokens and any key copy it holds.
    fn remove(&self, id: DeviceId) -> impl Future<Output = Result<(), StoreError>> + Send;

    /// Records that the device was seen at `at`, only while it is still registered with the DPoP
    /// key `jkt`, and says whether it was. A device whose key was cleared meanwhile (a refresh
    /// token used twice, sessions ended everywhere) stays as it is: writing back the whole row a
    /// caller read earlier would put the cleared key back. The default reads and writes in two
    /// steps; a store that serves requests concurrently overrides it with a conditional write.
    fn touch_seen(
        &self,
        id: DeviceId,
        jkt: &str,
        at: OffsetDateTime,
    ) -> impl Future<Output = Result<bool, StoreError>> + Send {
        async move {
            match self.get(id).await? {
                Some(mut device) if device.dpop_jkt.as_deref() == Some(jkt) => {
                    device.last_seen_at = at;
                    self.upsert(&device).await?;
                    Ok(true)
                }
                _ => Ok(false),
            }
        }
    }

    /// Records that the device was seen at `at`, whatever key it holds, and nothing else of the row:
    /// a caller that read the row earlier must not write back what a sign-out cleared since. A
    /// device that is gone stays gone. The default reads and writes in two steps; a store that
    /// serves requests concurrently overrides it with one conditional write.
    fn touch_last_seen(
        &self,
        id: DeviceId,
        at: OffsetDateTime,
    ) -> impl Future<Output = Result<(), StoreError>> + Send {
        async move {
            if let Some(mut device) = self.get(id).await? {
                device.last_seen_at = at;
                self.upsert(&device).await?;
            }
            Ok(())
        }
    }
}

/// Which API issued a refresh token. The two APIs share one table and one token form, but a Kemlock
/// token is bound to a DPoP key and a Bitwarden one is a bearer token, so one API refuses the
/// other's.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum TokenApi {
    /// Issued before the tag existed: no one knows. The Bitwarden API takes it only for a device
    /// with no DPoP key.
    #[default]
    Unknown,
    Kemlock,
    Bitwarden,
}

impl TokenApi {
    /// The value stored in the `api` column.
    pub fn as_i16(self) -> i16 {
        match self {
            TokenApi::Unknown => 0,
            TokenApi::Kemlock => 1,
            TokenApi::Bitwarden => 2,
        }
    }

    /// The tag a stored value stands for; one that is none of them is `Unknown`.
    pub fn from_i16(value: i16) -> Self {
        match value {
            1 => TokenApi::Kemlock,
            2 => TokenApi::Bitwarden,
            _ => TokenApi::Unknown,
        }
    }
}

/// A refresh token as stored: only its SHA-256, so a database copy can't be replayed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RefreshToken {
    pub hash: [u8; 32],
    /// Every rotation of one sign-in shares a family; reusing a used token revokes the family.
    pub family: Uuid,
    pub user: UserId,
    pub device: DeviceId,
    /// The account's security stamp when the token was issued. A refresh is refused once the
    /// account's stamp is another one (a password change ends every session).
    pub security_stamp: Uuid,
    /// When the sign-in this token descends from happened. A rotation carries it forward, so a
    /// refresh never makes a session look newly signed in.
    pub created_at: OffsetDateTime,
    pub expires_at: OffsetDateTime,
    pub used_at: Option<OffsetDateTime>,
    /// The API that issued the token.
    pub api: TokenApi,
}

pub trait TokenRepo: Send + Sync {
    /// Stores a token. `NotFound` when its family was revoked, so a rotation that was racing the
    /// revocation can't leave a live token behind (and when its device is gone).
    fn insert(&self, token: &RefreshToken) -> impl Future<Output = Result<(), StoreError>> + Send;
    /// Marks the token used and returns it as it was before, so the caller sees whether it had
    /// been used already. `None` for an unknown hash. A token of a revoked family is returned as
    /// used.
    fn take(
        &self,
        hash: [u8; 32],
        now: OffsetDateTime,
    ) -> impl Future<Output = Result<Option<RefreshToken>, StoreError>> + Send;
    /// Ends a family for good: its tokens are deleted and the family is recorded as revoked, so
    /// tokens that reach the store later (`insert`) or that survive some other way (`take`) are
    /// dead too.
    fn revoke_family(&self, family: Uuid) -> impl Future<Output = Result<(), StoreError>> + Send;
    fn revoke_device(
        &self,
        device: DeviceId,
    ) -> impl Future<Output = Result<(), StoreError>> + Send;
    /// The device's refresh tokens, used or not, so a caller can tell its families apart.
    fn device_tokens(
        &self,
        device: DeviceId,
    ) -> impl Future<Output = Result<Vec<RefreshToken>, StoreError>> + Send;
    /// Binds every refresh token of the device to `stamp`, the account's new security stamp. The
    /// device that changed the stamp (a change of the KDF) keeps its way back in, by refreshing,
    /// while every other token is still bound to the old stamp and is dead.
    fn restamp_device(
        &self,
        device: DeviceId,
        stamp: Uuid,
    ) -> impl Future<Output = Result<(), StoreError>> + Send;
}

/// One page of a delta sync.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ChangePage {
    /// Items (and tombstones) changed after the cursor, in (origin, seq) order, each once at its
    /// latest revision.
    pub items: Vec<Item>,
    /// The cursor after this page.
    pub next: VersionVector,
    /// Whether another page follows.
    pub more: bool,
}

/// One page of a delta sync in which every owner has its own cursor, see
/// [`ItemStore::changes_since_each`]. The next cursor is the caller's to build: each owner's
/// advances by the change ids of that owner's items in `items`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EachPage {
    /// Items (and tombstones) some owner's cursor doesn't cover, in (origin, seq) order across
    /// all owners, each once at its latest revision.
    pub items: Vec<Item>,
    /// Whether another page follows.
    pub more: bool,
}

/// One page of held items, see [`ItemStore::held_since_each`]: each item comes with the collection it
/// is held in, whose vector its change id advances.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct HeldPage {
    /// Held items some collection's vector doesn't cover, in (origin, seq) order across all
    /// collections.
    pub items: Vec<(CollectionId, Item)>,
    /// Whether another page follows.
    pub more: bool,
}

impl EachPage {
    /// The first `limit` items of several partial answers, in (origin, seq) order. Each part is
    /// the first items (at most `limit`) of some owners' uncovered items in that order, and
    /// whether it left more out. The first `limit` of all of them is then the first `limit` of
    /// the whole, so the page is a prefix of what remains, which is what lets a cursor advance by
    /// the items of the page and skip nothing.
    pub fn merge(parts: impl IntoIterator<Item = (Vec<Item>, bool)>, limit: u32) -> EachPage {
        let limit = usize::try_from(limit.max(1)).unwrap_or(usize::MAX);
        let mut items = Vec::new();
        let mut more = false;
        for (part, part_more) in parts {
            more |= part_more;
            items.extend(part);
        }
        items.sort_by_key(|i| (i.change.origin, i.change.seq));
        if items.len() > limit {
            items.truncate(limit);
            more = true;
        }
        EachPage { items, more }
    }
}

pub trait ItemStore: Send + Sync {
    fn get(&self, id: ItemId) -> impl Future<Output = Result<Option<Item>, StoreError>> + Send;

    /// In one transaction: checks the stored revision is `draft.expected` (else `Conflict`),
    /// takes this server's next sequence number and an HLC time not before the last one, writes
    /// the item and appends the change to the change log. Returns the stored item.
    fn put(&self, draft: ItemDraft) -> impl Future<Output = Result<Item, StoreError>> + Send;

    /// `put` for up to 500 drafts in one transaction: all are stored or none is. A conflict names
    /// the first item that failed.
    fn put_batch(
        &self,
        drafts: Vec<ItemDraft>,
    ) -> impl Future<Output = Result<Vec<Item>, StoreError>> + Send;

    /// Items of `owners` whose latest change `since` doesn't cover, oldest change first, at most
    /// `limit` of them.
    fn changes_since(
        &self,
        owners: &[Owner],
        since: &VersionVector,
        limit: u32,
    ) -> impl Future<Output = Result<ChangePage, StoreError>> + Send;

    /// The newest change of each origin among `owners`' items: what a device that is up to date
    /// holds. Cheap; backs the 304 shortcut.
    fn latest(
        &self,
        owners: &[Owner],
    ) -> impl Future<Output = Result<VersionVector, StoreError>> + Send;

    /// The tombstone horizon of `owners`: purged tombstones of items they own are among the
    /// changes this vector covers, so a cursor of theirs that doesn't dominate it must start a full
    /// sync. Per owner, so one account's purged deletions never force another account to resync.
    fn purged_through(
        &self,
        owners: &[Owner],
    ) -> impl Future<Output = Result<VersionVector, StoreError>> + Send;

    /// [`changes_since`](Self::changes_since) with a cursor of its own for each owner: the items
    /// of each owner that its own vector doesn't cover, oldest change first across all owners, at
    /// most `limit`. A device's cursor holds one vector per owner (`SyncCursor`), so an owner it
    /// has just joined asks from the empty vector and gets its whole history, whatever sequence
    /// numbers the device has seen of other owners.
    ///
    /// The default asks each owner in turn; an adapter overrides it to ask once.
    fn changes_since_each(
        &self,
        owners: &[(Owner, VersionVector)],
        limit: u32,
    ) -> impl Future<Output = Result<EachPage, StoreError>> + Send {
        async move {
            let mut parts = Vec::with_capacity(owners.len());
            for (owner, since) in owners {
                let page = self
                    .changes_since(std::slice::from_ref(owner), since, limit)
                    .await?;
                parts.push((page.items, page.more));
            }
            Ok(EachPage::merge(parts, limit))
        }
    }

    /// [`latest`](Self::latest) for each owner on its own, in the order given.
    fn latest_each(
        &self,
        owners: &[Owner],
    ) -> impl Future<Output = Result<Vec<(Owner, VersionVector)>, StoreError>> + Send {
        async move {
            let mut each = Vec::with_capacity(owners.len());
            for owner in owners {
                each.push((*owner, self.latest(std::slice::from_ref(owner)).await?));
            }
            Ok(each)
        }
    }

    /// [`purged_through`](Self::purged_through) for each owner on its own, in the order given.
    fn purged_each(
        &self,
        owners: &[Owner],
    ) -> impl Future<Output = Result<Vec<(Owner, VersionVector)>, StoreError>> + Send {
        async move {
            let mut each = Vec::with_capacity(owners.len());
            for owner in owners {
                each.push((
                    *owner,
                    self.purged_through(std::slice::from_ref(owner)).await?,
                ));
            }
            Ok(each)
        }
    }

    /// The **held** items (docs/crypto.md, I4) of these collections that the collection's own vector
    /// doesn't cover, oldest change first across all of them, at most `limit`. Every read above
    /// leaves held items out; every confirmed member of the space is sent them from here. The caller
    /// has checked the membership: the store only reads what it is asked.
    ///
    /// The default has none, for a store without held items.
    fn held_since_each(
        &self,
        _collections: &[(CollectionId, VersionVector)],
        _limit: u32,
    ) -> impl Future<Output = Result<HeldPage, StoreError>> + Send {
        async { Ok(HeldPage::default()) }
    }

    /// The newest change of each origin among the held items of each collection, in the order
    /// given: what a device that is up to date with them holds. Backs the 304 shortcut.
    fn held_latest_each(
        &self,
        _collections: &[CollectionId],
    ) -> impl Future<Output = Result<Vec<(CollectionId, VersionVector)>, StoreError>> + Send {
        async { Ok(Vec::new()) }
    }

    /// Whether `owner` accepts signed `kem1` writes only (docs/crypto.md, "The signed-only flag"):
    /// its owner (or a space's owner or admin) asked.
    ///
    /// The default is false, for a store that keeps no such flag.
    fn signed_writes_required(
        &self,
        _owner: Owner,
    ) -> impl Future<Output = Result<bool, StoreError>> + Send {
        async { Ok(false) }
    }

    /// Makes `owner` accept signed writes only, at `at`. Idempotent. Only a request of the owner's
    /// own authority sets it (docs/crypto.md, "The signed-only flag").
    fn require_signed_writes(
        &self,
        _owner: Owner,
        _at: OffsetDateTime,
    ) -> impl Future<Output = Result<(), StoreError>> + Send {
        async { Ok(()) }
    }

    /// Makes `owner` accept unsigned writes again. Idempotent.
    fn clear_signed_writes(
        &self,
        _owner: Owner,
    ) -> impl Future<Output = Result<(), StoreError>> + Send {
        async { Ok(()) }
    }

    /// Purges tombstones deleted before `before`, moving each owner's horizon. Returns how many
    /// went.
    fn purge_tombstones(
        &self,
        before: OffsetDateTime,
    ) -> impl Future<Output = Result<u64, StoreError>> + Send;
}

/// A record in the event log (actor, action, target, device, time).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Event {
    pub actor: Option<UserId>,
    pub device: Option<DeviceId>,
    pub action: &'static str,
    pub target: Option<String>,
    pub at: OffsetDateTime,
}

pub trait EventLog: Send + Sync {
    fn record(&self, event: Event) -> impl Future<Output = Result<(), StoreError>> + Send;
}

/// Tells an owner's open devices to sync. Carries only "sync now", never what changed.
pub trait Notifier: Send + Sync {
    fn sync_now(&self, owner: Owner, change: ChangeId) -> impl Future<Output = ()> + Send;
}

/// Seals secrets the server itself must read under `server.key` (docs/crypto.md, "Server-side
/// secrets"). `purpose` is bound into the seal, so a value sealed for one purpose never opens
/// as another.
pub trait SecretSeal: Send + Sync {
    fn seal(&self, purpose: &str, value: &[u8]) -> Vec<u8>;
    /// The opened value, wiped when it is dropped: it can be a TOTP secret or a login state.
    fn open(&self, purpose: &str, sealed: &[u8]) -> Result<Zeroizing<Vec<u8>>, CryptoError>;
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum CryptoError {
    /// A message didn't parse, or a proof, tag or signature didn't verify. Deliberately vague.
    #[error("invalid")]
    Invalid,
}

/// The server side of OPAQUE (`opaque1` in docs/crypto.md). Messages are opaque-ke's serialised
/// bytes; the credential identifier is the lower-cased email.
pub trait PasswordAuth: Send + Sync {
    /// Registration, first message: the client's `RegistrationRequest` in, the server's
    /// `RegistrationResponse` out.
    fn registration_response(
        &self,
        credential_id: &[u8],
        request: &[u8],
    ) -> Result<Vec<u8>, CryptoError>;
    /// Registration, last message: the client's `RegistrationUpload` in, the record to store out.
    fn registration_record(&self, upload: &[u8]) -> Result<Vec<u8>, CryptoError>;
    /// Sign-in, first message. `record` is `None` for an unknown account, which still gets a
    /// response indistinguishable from a real one. Returns the server's login state (to keep until
    /// `login_finish`) and the `CredentialResponse` for the client.
    fn login_start(
        &self,
        credential_id: &[u8],
        record: Option<&[u8]>,
        request: &[u8],
    ) -> Result<(Vec<u8>, Vec<u8>), CryptoError>;
    /// Sign-in, last message: the client's `CredentialFinalization` in; the 64-byte session key
    /// out when the password was right.
    fn login_finish(&self, state: &[u8], finalization: &[u8]) -> Result<Vec<u8>, CryptoError>;
}

/// What a Kemlock API access token says. Lives 10 minutes and is bound to a DPoP key.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AccessClaims {
    pub user: UserId,
    pub device: DeviceId,
    /// The device's DPoP key thumbprint (`cnf.jkt`).
    pub jkt: String,
    pub security_stamp: Uuid,
    pub admin: bool,
    /// When the sign-in this session began (the RFC 9068 `auth_time`): a refresh carries it
    /// forward, so it is the age of the last real sign-in, not of this token.
    pub auth_time: OffsetDateTime,
    pub issued_at: OffsetDateTime,
    pub expires_at: OffsetDateTime,
}

/// Signs and checks access tokens (Ed25519, compact JWS).
pub trait TokenSigner: Send + Sync {
    fn sign(&self, claims: &AccessClaims) -> String;
    /// Checks the signature and expiry against `now`.
    fn verify(&self, token: &str, now: OffsetDateTime) -> Result<AccessClaims, CryptoError>;
}

/// A two-step method an account has set up.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TwoFactorMethod {
    /// An authenticator app (RFC 6238, SHA-1, 6 digits, 30 s), as Bitwarden's type 0.
    Totp,
    /// A WebAuthn security key, as Bitwarden's type 7.
    WebAuthn,
    /// A code sent to an email address, as Bitwarden's type 1.
    Email,
    /// A YubiKey OTP checked with Yubico's API, as Bitwarden's type 3.
    YubiKey,
    /// Duo's Universal Prompt, as Bitwarden's type 2.
    Duo,
}

impl TwoFactorMethod {
    /// The name the Kemlock API and the store use.
    pub fn as_str(self) -> &'static str {
        match self {
            TwoFactorMethod::Totp => "totp",
            TwoFactorMethod::WebAuthn => "webauthn",
            TwoFactorMethod::Email => "email",
            TwoFactorMethod::YubiKey => "yubikey",
            TwoFactorMethod::Duo => "duo",
        }
    }

    /// The method named `name`, as [`TwoFactorMethod::as_str`] spells it.
    pub fn parse(name: &str) -> Option<Self> {
        match name {
            "totp" => Some(TwoFactorMethod::Totp),
            "webauthn" => Some(TwoFactorMethod::WebAuthn),
            "email" => Some(TwoFactorMethod::Email),
            "yubikey" => Some(TwoFactorMethod::YubiKey),
            "duo" => Some(TwoFactorMethod::Duo),
            _ => None,
        }
    }
}

/// One enrolment. The secret is sealed under `server.key`, with the method's own purpose (`"totp"`, `"webauthn"`, or the `two_step` ones).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TwoFactor {
    pub user: UserId,
    pub method: TwoFactorMethod,
    pub sealed_secret: Vec<u8>,
    pub enabled: bool,
    pub created_at: OffsetDateTime,
}

pub trait TwoFactorRepo: Send + Sync {
    fn list(&self, user: UserId)
    -> impl Future<Output = Result<Vec<TwoFactor>, StoreError>> + Send;
    /// Inserts or replaces the user's enrolment of that method.
    fn put(&self, two_factor: &TwoFactor) -> impl Future<Output = Result<(), StoreError>> + Send;
    /// Replaces the account's enrolment of `to.method` with `to`, only while its sealed secret is
    /// still `from`, and says whether it did. A caller that read an enrolment, then writes a
    /// change of its own (sealing a seed to the account, turning the method on), must not undo
    /// what happened in between: a removal, or a new enrolment with another secret. The default
    /// reads and writes in two steps; a store that serves requests concurrently overrides it with
    /// a conditional write.
    fn replace_if_sealed(
        &self,
        from: &[u8],
        to: &TwoFactor,
    ) -> impl Future<Output = Result<bool, StoreError>> + Send {
        async move {
            let held = self
                .list(to.user)
                .await?
                .into_iter()
                .any(|t| t.method == to.method && t.sealed_secret == from);
            if held {
                self.put(to).await?;
            }
            Ok(held)
        }
    }
    /// Records `step` as the newest accepted step of the user's TOTP enrolment, atomically, only
    /// if it is newer than the one recorded. `false` means the step is at or before the last
    /// accepted one (or there is no TOTP enrolment): the code is a replay and must be refused.
    fn accept_totp_step(
        &self,
        user: UserId,
        step: u64,
    ) -> impl Future<Output = Result<bool, StoreError>> + Send;
    fn remove(
        &self,
        user: UserId,
        method: TwoFactorMethod,
    ) -> impl Future<Output = Result<(), StoreError>> + Send;
    /// The account's two-step version: a counter that moves whenever a method is turned on or off
    /// (set up, enabled, disabled, removed, or all of them by a recovery code or an admin's
    /// reset), but not when a method's stored state changes (an emailed code, a spent TOTP step).
    /// The Bitwarden API binds its "remember this device" tokens to it, so any change ends them, as
    /// Vaultwarden clears the remembered devices. 0 for an account that never changed. A store
    /// that keeps none says 0 for every account.
    fn two_step_version(
        &self,
        user: UserId,
    ) -> impl Future<Output = Result<i64, StoreError>> + Send {
        let _ = user;
        async { Ok(0) }
    }
}

/// Checks two-step codes.
pub trait Totp: Send + Sync {
    /// The time step (RFC 6238 counter) `code` is valid for with `secret` at `now`, allowing one
    /// 30-second step either side; `None` when it is valid for none. Callers refuse a step that
    /// was used already, so a code can't be replayed within its window.
    fn verify_step(&self, secret: &[u8], code: &str, now: OffsetDateTime) -> Option<u64>;

    /// Whether `code` is valid for `secret` at `now`, allowing one 30-second step either side.
    fn verify(&self, secret: &[u8], code: &str, now: OffsetDateTime) -> bool {
        self.verify_step(secret, code, now).is_some()
    }
}
