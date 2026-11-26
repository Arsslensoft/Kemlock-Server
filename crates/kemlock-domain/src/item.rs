//! Items as the server stores them: ciphertext it can't read, plus what it needs to sync them.

use crate::change::ChangeId;
use crate::ids::{ItemId, UserId};
use crate::owner::Owner;
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;

/// How an item's bytes are laid out. `kem1` is Kemlock's envelope (docs/crypto.md); `bw` keeps
/// Vaultwarden's cipher JSON byte for byte for the Bitwarden API.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ItemFormat {
    Kem1,
    Bw,
}

impl ItemFormat {
    pub fn as_str(self) -> &'static str {
        match self {
            ItemFormat::Kem1 => "kem1",
            ItemFormat::Bw => "bw",
        }
    }
}

/// An item's revision. Clients assign it, because it is sealed into the item's AAD: a new item is
/// revision 1 and each write is the previous revision plus one.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct Revision(pub u64);

impl Revision {
    pub const FIRST: Revision = Revision(1);

    pub fn next(self) -> Option<Revision> {
        self.0.checked_add(1).map(Revision)
    }
}

/// An item's kind, such as `login` or `otp`: 1 to 64 bytes of `[a-z0-9_-]`. The server doesn't
/// interpret it; the kind is in the AAD so it can't relabel an item either.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct ItemKind(String);

impl ItemKind {
    pub const MAX_LEN: usize = 64;

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl TryFrom<String> for ItemKind {
    type Error = ItemError;
    fn try_from(s: String) -> Result<Self, ItemError> {
        let ok = !s.is_empty()
            && s.len() <= Self::MAX_LEN
            && s.bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-' || b == b'_');
        if ok {
            Ok(ItemKind(s))
        } else {
            Err(ItemError::BadKind)
        }
    }
}

impl From<ItemKind> for String {
    fn from(k: ItemKind) -> String {
        k.0
    }
}

/// The writing account's signature of a `kem1` write (docs/crypto.md, "Signed item writes"). The
/// server stores it with the item's change and serves it back, so any device or peer can check it;
/// it never makes one.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WriteSignature {
    /// The account that wrote, and whose `sig1` key made the signature.
    pub writer: UserId,
    /// The key version of the bundle that signed.
    pub key_version: u32,
    /// The `sig1` signature, 3373 bytes.
    pub signature: Vec<u8>,
}

impl WriteSignature {
    /// A `sig1` signature: ML-DSA-65 (3309) and Ed25519 (64).
    pub const SIGNATURE_LEN: usize = 3309 + 64;
    /// The stored and federated form: `writer (16) ‖ u32be(key version) ‖ signature`.
    pub const STORED_LEN: usize = 16 + 4 + Self::SIGNATURE_LEN;

    pub fn to_stored(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(Self::STORED_LEN);
        out.extend_from_slice(self.writer.as_bytes());
        out.extend_from_slice(&self.key_version.to_be_bytes());
        out.extend_from_slice(&self.signature);
        out
    }

    /// Parses the stored form, refusing any other length.
    pub fn from_stored(bytes: &[u8]) -> Option<WriteSignature> {
        if bytes.len() != Self::STORED_LEN {
            return None;
        }
        let mut writer = [0u8; 16];
        writer.copy_from_slice(&bytes[..16]);
        let mut version = [0u8; 4];
        version.copy_from_slice(&bytes[16..20]);
        Some(WriteSignature {
            writer: UserId(uuid::Uuid::from_bytes(writer)),
            key_version: u32::from_be_bytes(version),
            signature: bytes[20..].to_vec(),
        })
    }
}

/// An item as stored. A tombstone has `deleted_at` set and no ciphertext or item key.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Item {
    pub id: ItemId,
    pub owner: Owner,
    pub kind: ItemKind,
    pub format: ItemFormat,
    pub revision: Revision,
    pub key_version: u32,
    pub ciphertext: Option<Vec<u8>>,
    pub item_key: Option<Vec<u8>>,
    pub deleted_at: Option<OffsetDateTime>,
    pub updated_at: OffsetDateTime,
    /// The change that wrote this revision.
    pub change: ChangeId,
    /// The writing account's signature of this revision, when it came signed.
    pub signature: Option<WriteSignature>,
}

impl Item {
    pub fn is_tombstone(&self) -> bool {
        self.deleted_at.is_some()
    }

    /// Bytes this revision takes, for quotas.
    pub fn size(&self) -> usize {
        self.ciphertext.as_ref().map_or(0, Vec::len) + self.item_key.as_ref().map_or(0, Vec::len)
    }
}

/// A write a client asks for: a new revision of one item, or its deletion.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ItemWrite {
    pub id: ItemId,
    pub owner: Owner,
    pub kind: ItemKind,
    pub format: ItemFormat,
    /// `If-Match`: the revision the client last saw, `None` when the item must not exist yet.
    pub expected: Option<Revision>,
    /// The revision the client sealed; must be `expected + 1`, or 1 for a new item.
    pub revision: Revision,
    pub key_version: u32,
    /// `None` deletes the item, leaving a tombstone.
    pub sealed: Option<Sealed>,
    /// The writer's signature (docs/crypto.md, "Signed item writes"). Checked against the
    /// writer's bundle by the layer that holds it, not here.
    pub signature: Option<WriteSignature>,
}

/// An item's ciphertext and wrapped item key, both `nonce ‖ ciphertext ‖ tag` values.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Sealed {
    pub ciphertext: Vec<u8>,
    pub item_key: Vec<u8>,
}

/// Size limits on one item, set by the admin.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ItemLimits {
    pub max_ciphertext: usize,
}

impl Default for ItemLimits {
    fn default() -> Self {
        // JSON bodies are capped at 2 MiB (design, "Limits"); base64 makes 1 MiB of ciphertext
        // about 1.4 MiB on the wire.
        ItemLimits {
            max_ciphertext: 1024 * 1024,
        }
    }
}

/// The shortest valid AES-256-GCM value: a 12-byte nonce and a 16-byte tag.
pub const MIN_SEALED_LEN: usize = 28;
/// A wrapped 32-byte item key: nonce, key, tag.
pub const ITEM_KEY_LEN: usize = 12 + 32 + 16;

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ItemError {
    #[error("the item kind must be 1 to 64 characters of a-z, 0-9, - and _")]
    BadKind,
    #[error(
        "the item was changed since revision {expected:?}; the current revision is {current:?}"
    )]
    Stale {
        expected: Option<Revision>,
        current: Option<Revision>,
    },
    #[error("revision {got:?} must be one more than the stored revision")]
    BadRevision { got: Revision },
    #[error("an item can't change its kind or format")]
    Immutable,
    /// The item id is in use under another owner. Answered exactly as the store answers an id
    /// taken by someone else (`Duplicate`), and never with that item's revision.
    #[error("that item id is taken")]
    Taken,
    #[error("only the owner's members may write this item")]
    Forbidden,
    #[error("the sealed values are malformed")]
    Malformed,
    #[error("the item is larger than this server allows")]
    TooLarge,
    /// The write carries a signature that can't be the actor's: wrong writer, wrong format or wrong
    /// length. The signature itself is checked where the writer's bundle is.
    #[error("the write signature is not valid")]
    BadSignature,
    /// The owner accepts signed writes only (docs/crypto.md, "Signed item writes").
    #[error("this owner accepts signed writes only")]
    SignatureRequired,
}

impl ItemWrite {
    /// Applies the write to the stored item, or refuses it. `actor` is the signed-in account.
    ///
    /// The rules: the actor may write the owner (for now only their own vault; spaces come with
    /// their membership rules), `If-Match` matches the stored revision, the new revision is one
    /// more, owner, kind and format never change, and the sealed values are well-formed and within
    /// the limits. Returns the item as it will be stored, without its change id, which the store
    /// assigns in the same transaction.
    pub fn apply(
        self,
        stored: Option<&Item>,
        actor: UserId,
        limits: ItemLimits,
        now: OffsetDateTime,
    ) -> Result<ItemDraft, ItemError> {
        match self.owner {
            Owner::User(u) if u == actor => {}
            _ => return Err(ItemError::Forbidden),
        }
        // Before anything says what the stored item looks like: an id that is some other owner's
        // item is simply taken. Checking `If-Match` first would let a caller learn that item's
        // revision from the stale-revision answer.
        if stored.is_some_and(|s| s.owner != self.owner) {
            return Err(ItemError::Taken);
        }
        let current = stored.map(|i| i.revision);
        if current != self.expected {
            return Err(ItemError::Stale {
                expected: self.expected,
                current,
            });
        }
        let want = match current {
            None => Revision::FIRST,
            Some(r) => r
                .next()
                .ok_or(ItemError::BadRevision { got: self.revision })?,
        };
        if self.revision != want {
            return Err(ItemError::BadRevision { got: self.revision });
        }
        if let Some(stored) = stored
            && (stored.kind != self.kind || stored.format != self.format)
        {
            return Err(ItemError::Immutable);
        }
        if let Some(signature) = &self.signature
            && (self.format != ItemFormat::Kem1
                || signature.writer != actor
                || signature.signature.len() != WriteSignature::SIGNATURE_LEN)
        {
            return Err(ItemError::BadSignature);
        }
        if let Some(sealed) = &self.sealed {
            if sealed.ciphertext.len() < MIN_SEALED_LEN || sealed.item_key.len() != ITEM_KEY_LEN {
                return Err(ItemError::Malformed);
            }
            if sealed.ciphertext.len() > limits.max_ciphertext {
                return Err(ItemError::TooLarge);
            }
        }
        let (ciphertext, item_key, deleted_at) = match self.sealed {
            Some(s) => (Some(s.ciphertext), Some(s.item_key), None),
            None => (None, None, Some(now)),
        };
        Ok(ItemDraft {
            id: self.id,
            owner: self.owner,
            kind: self.kind,
            format: self.format,
            expected: self.expected,
            revision: self.revision,
            key_version: self.key_version,
            ciphertext,
            item_key,
            deleted_at,
            updated_at: now,
            signature: self.signature,
        })
    }
}

/// An item ready to store: everything but the change id.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ItemDraft {
    pub id: ItemId,
    pub owner: Owner,
    pub kind: ItemKind,
    pub format: ItemFormat,
    /// The revision the store must still find, for its optimistic check.
    pub expected: Option<Revision>,
    pub revision: Revision,
    pub key_version: u32,
    pub ciphertext: Option<Vec<u8>>,
    pub item_key: Option<Vec<u8>>,
    pub deleted_at: Option<OffsetDateTime>,
    pub updated_at: OffsetDateTime,
    /// The writer's signature, kept with the change.
    pub signature: Option<WriteSignature>,
}

impl ItemDraft {
    pub fn into_item(self, change: ChangeId) -> Item {
        Item {
            id: self.id,
            owner: self.owner,
            kind: self.kind,
            format: self.format,
            revision: self.revision,
            key_version: self.key_version,
            ciphertext: self.ciphertext,
            item_key: self.item_key,
            deleted_at: self.deleted_at,
            updated_at: self.updated_at,
            change,
            signature: self.signature,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::change::Hlc;
    use crate::ids::ServerId;

    fn kind(s: &str) -> ItemKind {
        ItemKind::try_from(s.to_owned()).expect("valid kind")
    }

    fn write(actor: UserId, expected: Option<u64>, revision: u64) -> ItemWrite {
        ItemWrite {
            id: ItemId::random(),
            owner: Owner::User(actor),
            kind: kind("login"),
            format: ItemFormat::Kem1,
            expected: expected.map(Revision),
            revision: Revision(revision),
            key_version: 1,
            sealed: Some(Sealed {
                ciphertext: vec![7; 64],
                item_key: vec![1; ITEM_KEY_LEN],
            }),
            signature: None,
        }
    }

    fn stored(w: &ItemWrite, revision: u64) -> Item {
        Item {
            id: w.id,
            owner: w.owner,
            kind: w.kind.clone(),
            format: w.format,
            revision: Revision(revision),
            key_version: 1,
            ciphertext: Some(vec![0; 64]),
            item_key: Some(vec![0; ITEM_KEY_LEN]),
            deleted_at: None,
            updated_at: OffsetDateTime::UNIX_EPOCH,
            change: ChangeId {
                origin: ServerId::random(),
                seq: 1,
                hlc: Hlc::default(),
            },
            signature: None,
        }
    }

    #[test]
    fn every_kind_of_item_is_accepted() {
        // The server keeps no list of kinds: the `file` kind needs nothing added here.
        for kind in [
            "login",
            "note",
            "file",
            "otp",
            "backup-codes",
            "passkey",
            "card",
            "identity",
            "contact",
            "certificate",
            "ssh-key",
            "pgp-key",
        ] {
            assert_eq!(
                ItemKind::try_from(kind.to_owned()).map(String::from),
                Ok(kind.to_owned()),
                "{kind}"
            );
        }
    }

    #[test]
    fn kinds_are_checked() {
        assert!(ItemKind::try_from("backup-codes".to_owned()).is_ok());
        for bad in ["", "Login", "a b", &"x".repeat(65)] {
            assert_eq!(ItemKind::try_from(bad.to_owned()), Err(ItemError::BadKind));
        }
    }

    #[test]
    fn a_new_item_starts_at_revision_one() {
        let me = UserId::random();
        let now = OffsetDateTime::UNIX_EPOCH;
        assert!(
            write(me, None, 1)
                .apply(None, me, ItemLimits::default(), now)
                .is_ok()
        );
        assert_eq!(
            write(me, None, 2).apply(None, me, ItemLimits::default(), now),
            Err(ItemError::BadRevision { got: Revision(2) })
        );
    }

    #[test]
    fn a_stale_write_is_refused() {
        let me = UserId::random();
        let w = write(me, Some(3), 4);
        let s = stored(&w, 5);
        assert_eq!(
            w.apply(
                Some(&s),
                me,
                ItemLimits::default(),
                OffsetDateTime::UNIX_EPOCH
            ),
            Err(ItemError::Stale {
                expected: Some(Revision(3)),
                current: Some(Revision(5))
            })
        );
    }

    #[test]
    fn the_next_revision_is_accepted_and_a_delete_leaves_a_tombstone() {
        let me = UserId::random();
        let mut w = write(me, Some(5), 6);
        let s = stored(&w, 5);
        w.sealed = None;
        let draft = w
            .apply(
                Some(&s),
                me,
                ItemLimits::default(),
                OffsetDateTime::UNIX_EPOCH,
            )
            .expect("applies");
        assert_eq!(draft.revision, Revision(6));
        assert!(draft.ciphertext.is_none() && draft.deleted_at.is_some());
    }

    #[test]
    fn another_accounts_vault_is_forbidden() {
        let me = UserId::random();
        let w = write(UserId::random(), None, 1);
        assert_eq!(
            w.apply(None, me, ItemLimits::default(), OffsetDateTime::UNIX_EPOCH),
            Err(ItemError::Forbidden)
        );
    }

    #[test]
    fn an_id_under_another_owner_is_taken_whatever_revision_is_expected() {
        let me = UserId::random();
        let other = UserId::random();
        let theirs = {
            let w = write(other, Some(1), 2);
            stored(&w, 5)
        };
        // The caller's own owner, but the id is somebody else's item: `Taken`, for a guessed
        // revision, a right one and "new" alike, so no answer differs and none shows revision 5.
        for expected in [None, Some(1), Some(4), Some(5)] {
            let mut w = write(me, expected, 6);
            w.id = theirs.id;
            assert_eq!(
                w.apply(
                    Some(&theirs),
                    me,
                    ItemLimits::default(),
                    OffsetDateTime::UNIX_EPOCH
                ),
                Err(ItemError::Taken),
                "expected {expected:?}"
            );
        }
    }

    #[test]
    fn kind_and_format_never_change() {
        let me = UserId::random();
        let mut w = write(me, Some(1), 2);
        let s = stored(&w, 1);
        w.kind = kind("note");
        assert_eq!(
            w.apply(
                Some(&s),
                me,
                ItemLimits::default(),
                OffsetDateTime::UNIX_EPOCH
            ),
            Err(ItemError::Immutable)
        );
    }

    #[test]
    fn malformed_and_oversized_values_are_refused() {
        let me = UserId::random();
        let mut short = write(me, None, 1);
        short.sealed = Some(Sealed {
            ciphertext: vec![0; 27],
            item_key: vec![0; ITEM_KEY_LEN],
        });
        assert_eq!(
            short.apply(None, me, ItemLimits::default(), OffsetDateTime::UNIX_EPOCH),
            Err(ItemError::Malformed)
        );
        let big = write(me, None, 1);
        assert_eq!(
            big.apply(
                None,
                me,
                ItemLimits { max_ciphertext: 32 },
                OffsetDateTime::UNIX_EPOCH
            ),
            Err(ItemError::TooLarge)
        );
    }

    fn signature(writer: UserId) -> WriteSignature {
        WriteSignature {
            writer,
            key_version: 1,
            signature: vec![9; WriteSignature::SIGNATURE_LEN],
        }
    }

    #[test]
    fn a_signature_by_the_actor_travels_with_the_draft() {
        let me = UserId::random();
        let mut w = write(me, None, 1);
        w.signature = Some(signature(me));
        let draft = w
            .apply(None, me, ItemLimits::default(), OffsetDateTime::UNIX_EPOCH)
            .expect("applies");
        assert_eq!(draft.signature, Some(signature(me)));
        let item = draft.into_item(ChangeId {
            origin: ServerId::random(),
            seq: 1,
            hlc: Hlc::default(),
        });
        assert_eq!(item.signature, Some(signature(me)));
    }

    #[test]
    fn a_signature_that_cannot_be_the_actors_is_refused() {
        let me = UserId::random();
        let apply =
            |w: ItemWrite| w.apply(None, me, ItemLimits::default(), OffsetDateTime::UNIX_EPOCH);
        // Another writer.
        let mut w = write(me, None, 1);
        w.signature = Some(signature(UserId::random()));
        assert_eq!(apply(w), Err(ItemError::BadSignature));
        // The wrong length.
        let mut w = write(me, None, 1);
        let mut short = signature(me);
        short.signature.pop();
        w.signature = Some(short);
        assert_eq!(apply(w), Err(ItemError::BadSignature));
        // Only kem1 envelopes are signed.
        let mut w = write(me, None, 1);
        w.format = ItemFormat::Bw;
        w.signature = Some(signature(me));
        assert_eq!(apply(w), Err(ItemError::BadSignature));
    }

    #[test]
    fn the_stored_form_of_a_signature_round_trips() {
        let sig = signature(UserId::random());
        let bytes = sig.to_stored();
        assert_eq!(bytes.len(), WriteSignature::STORED_LEN);
        assert_eq!(WriteSignature::from_stored(&bytes), Some(sig));
        assert_eq!(WriteSignature::from_stored(&bytes[1..]), None);
        assert_eq!(WriteSignature::from_stored(&[]), None);
    }
}
