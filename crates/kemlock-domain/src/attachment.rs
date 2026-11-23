//! Attachments: files attached to an item, stored as `KMA1` bytes the server can't read.
//!
//! An attachment belongs to the item it is uploaded for, and an item's JSON names its attachments
//! by id, so a change to them reaches other devices as a new revision of the item, written by the
//! client. The server keeps only the row below and the file in blob storage under a random
//! [`BlobId`], never its name.

use crate::ids::{ItemId, UserId};
use crate::owner::Owner;
use serde::{Deserialize, Serialize};
use std::fmt;
use time::OffsetDateTime;
use uuid::Uuid;

/// An attachment's id, made by the server when an upload starts and written into the item's JSON
/// by the client.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct AttachmentId(pub Uuid);

impl AttachmentId {
    /// A new random id (UUID v4).
    pub fn random() -> Self {
        Self(Uuid::new_v4())
    }
}

impl fmt::Debug for AttachmentId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "AttachmentId({})", self.0)
    }
}

impl fmt::Display for AttachmentId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl std::str::FromStr for AttachmentId {
    type Err = uuid::Error;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Uuid::parse_str(s).map(Self)
    }
}

/// Where an attachment's bytes live in blob storage: 16 random bytes, written as 32 lower-case
/// hex digits. It says nothing about the file, its item or its owner.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct BlobId([u8; 16]);

/// A blob id that isn't 32 lower-case hex digits.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("a blob id is 32 lower-case hex digits")]
pub struct BadBlobId;

impl BlobId {
    /// A new random id.
    pub fn random() -> Self {
        Self(*Uuid::new_v4().as_bytes())
    }

    pub fn from_bytes(bytes: [u8; 16]) -> Self {
        Self(bytes)
    }

    pub fn as_bytes(&self) -> &[u8; 16] {
        &self.0
    }

    /// The id as a UUID, for databases with a UUID column.
    pub fn to_uuid(&self) -> Uuid {
        Uuid::from_bytes(self.0)
    }

    pub fn from_uuid(uuid: Uuid) -> Self {
        Self(*uuid.as_bytes())
    }
}

impl fmt::Display for BlobId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for byte in self.0 {
            write!(f, "{byte:02x}")?;
        }
        Ok(())
    }
}

impl fmt::Debug for BlobId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "BlobId({self})")
    }
}

impl std::str::FromStr for BlobId {
    type Err = BadBlobId;
    fn from_str(s: &str) -> Result<Self, BadBlobId> {
        let valid = s.len() == 32 && s.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'));
        if !valid {
            return Err(BadBlobId);
        }
        let mut out = [0u8; 16];
        for (i, byte) in out.iter_mut().enumerate() {
            *byte = u8::from_str_radix(&s[2 * i..2 * i + 2], 16).map_err(|_| BadBlobId)?;
        }
        Ok(BlobId(out))
    }
}

/// Whether the bytes have arrived.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum AttachmentStatus {
    /// The upload started; the bytes aren't (all) there yet.
    Pending,
    /// The bytes are stored, in the size announced, and begin like a `KMA1` file.
    Ready,
}

impl AttachmentStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            AttachmentStatus::Pending => "pending",
            AttachmentStatus::Ready => "ready",
        }
    }
}

/// An attachment as stored.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Attachment {
    pub id: AttachmentId,
    pub item: ItemId,
    pub owner: Owner,
    pub blob: BlobId,
    /// The size of the `KMA1` file in bytes: announced when the upload starts, and what the
    /// upload must then match exactly.
    pub size: u64,
    pub status: AttachmentStatus,
    pub created_at: OffsetDateTime,
}

/// The size limit on one attachment, set by the admin.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AttachmentLimits {
    /// The most bytes one `KMA1` file may have.
    pub max_size: u64,
}

impl AttachmentLimits {
    /// 100 MiB, as the design's default.
    pub const DEFAULT_MAX_SIZE: u64 = 100 * 1024 * 1024;

    /// Refuses an empty file and one over the limit.
    pub fn check(&self, size: u64) -> Result<(), AttachmentError> {
        if size == 0 {
            Err(AttachmentError::Empty)
        } else if size > self.max_size {
            Err(AttachmentError::TooLarge)
        } else {
            Ok(())
        }
    }
}

impl Default for AttachmentLimits {
    fn default() -> Self {
        AttachmentLimits {
            max_size: Self::DEFAULT_MAX_SIZE,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum AttachmentError {
    #[error("the file is larger than this server allows")]
    TooLarge,
    #[error("the file is empty")]
    Empty,
    #[error("only the owner's members may attach files to this item")]
    Forbidden,
}

/// Whether `actor` may write what `owner` owns: for now only their own vault; spaces come with
/// their membership rules (the same rule as `ItemWrite::apply`).
pub fn may_write(owner: Owner, actor: UserId) -> bool {
    matches!(owner, Owner::User(u) if u == actor)
}

impl Attachment {
    /// A new pending attachment of `item`, which `owner` owns, started by `actor`.
    pub fn start(
        item: ItemId,
        owner: Owner,
        actor: UserId,
        size: u64,
        limits: AttachmentLimits,
        now: OffsetDateTime,
    ) -> Result<Attachment, AttachmentError> {
        if !may_write(owner, actor) {
            return Err(AttachmentError::Forbidden);
        }
        limits.check(size)?;
        Ok(Attachment {
            id: AttachmentId::random(),
            item,
            owner,
            blob: BlobId::random(),
            size,
            status: AttachmentStatus::Pending,
            created_at: now,
        })
    }

    pub fn is_ready(&self) -> bool {
        self.status == AttachmentStatus::Ready
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ids::SpaceId;

    const NOW: OffsetDateTime = OffsetDateTime::UNIX_EPOCH;

    #[test]
    fn blob_ids_round_trip_as_32_hex_digits() {
        let id = BlobId::random();
        let text = id.to_string();
        assert_eq!(text.len(), 32);
        assert_eq!(text.parse::<BlobId>(), Ok(id));
        assert_eq!(BlobId::from_uuid(id.to_uuid()), id);
        assert_eq!(
            "000102030405060708090a0b0c0d0e0f".parse::<BlobId>(),
            Ok(BlobId::from_bytes([
                0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15
            ]))
        );
    }

    #[test]
    fn blob_ids_refuse_other_spellings() {
        for bad in [
            "",
            "0001",
            "000102030405060708090A0B0C0D0E0F",
            "000102030405060708090a0b0c0d0e0g",
            "00010203-0405-0607-0809-0a0b0c0d0e0f",
            "\u{e9}\u{e9}\u{e9}\u{e9}\u{e9}\u{e9}\u{e9}\u{e9}\u{e9}\u{e9}\u{e9}\u{e9}\u{e9}\u{e9}\u{e9}\u{e9}",
        ] {
            assert_eq!(bad.parse::<BlobId>(), Err(BadBlobId), "{bad:?}");
        }
    }

    #[test]
    fn blob_ids_are_random() {
        assert_ne!(BlobId::random(), BlobId::random());
    }

    #[test]
    fn the_default_limit_is_100_mib() {
        assert_eq!(AttachmentLimits::default().max_size, 104_857_600);
    }

    #[test]
    fn sizes_are_checked_against_the_limit() {
        let limits = AttachmentLimits { max_size: 100 };
        assert_eq!(limits.check(1), Ok(()));
        assert_eq!(limits.check(100), Ok(()));
        assert_eq!(limits.check(101), Err(AttachmentError::TooLarge));
        assert_eq!(limits.check(0), Err(AttachmentError::Empty));
    }

    #[test]
    fn a_new_attachment_is_pending_and_has_its_own_blob() {
        let me = UserId::random();
        let item = ItemId::random();
        let a = Attachment::start(
            item,
            Owner::User(me),
            me,
            1234,
            AttachmentLimits::default(),
            NOW,
        )
        .expect("starts");
        assert_eq!(a.item, item);
        assert_eq!(a.size, 1234);
        assert_eq!(a.status, AttachmentStatus::Pending);
        assert!(!a.is_ready());
        let b = Attachment::start(
            item,
            Owner::User(me),
            me,
            1234,
            AttachmentLimits::default(),
            NOW,
        )
        .expect("starts");
        assert_ne!(a.id, b.id);
        assert_ne!(a.blob, b.blob);
    }

    #[test]
    fn only_the_owner_may_attach() {
        let me = UserId::random();
        let limits = AttachmentLimits::default();
        let start = |owner| Attachment::start(ItemId::random(), owner, me, 10, limits, NOW);
        assert_eq!(
            start(Owner::User(UserId::random())),
            Err(AttachmentError::Forbidden)
        );
        assert_eq!(
            start(Owner::Space(SpaceId::random())),
            Err(AttachmentError::Forbidden)
        );
        assert!(!may_write(Owner::Space(SpaceId::random()), me));
        assert!(may_write(Owner::User(me), me));
    }

    #[test]
    fn a_too_large_attachment_is_refused() {
        let me = UserId::random();
        let limits = AttachmentLimits { max_size: 10 };
        assert_eq!(
            Attachment::start(ItemId::random(), Owner::User(me), me, 11, limits, NOW),
            Err(AttachmentError::TooLarge)
        );
    }
}
