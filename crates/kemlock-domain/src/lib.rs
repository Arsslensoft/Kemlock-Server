//! Kemlock Server's domain: entities and the rules they keep, with no I/O.
//!
//! Everything here is plain data and pure functions, so use cases in
//! `kemlock-app` can be tested without a database, a network or a clock.

pub mod api_use;
pub mod attachment;
pub mod change;
pub mod dedup;
pub mod device;
pub mod ids;
pub mod item;
pub mod manifest;
pub mod owner;
pub mod passkeys;
pub mod policies;
pub mod privacy;
pub mod sends;
pub mod setup;
pub mod spaces;
pub mod sync_cursor;
pub mod unlock;
pub mod user;

pub use attachment::{
    Attachment, AttachmentError, AttachmentId, AttachmentLimits, AttachmentStatus, BadBlobId,
    BlobId,
};
pub use change::{BadCursor, ChangeId, Hlc, VersionVector};
pub use dedup::{DedupTag, Dismissal, DismissalId, DuplicateGroup, MatchingSettings, TagSet};
pub use device::{BROWSER_DEVICE_TYPES, Device, DeviceKind, browser_name};
pub use ids::{DeviceId, ItemId, ServerId, SpaceId, UserId};
pub use item::{
    Item, ItemDraft, ItemError, ItemFormat, ItemKind, ItemLimits, ItemWrite, Revision, Sealed,
};
pub use owner::Owner;
pub use passkeys::{Passkey, PasskeyId, PrfWrap};
pub use setup::{SetupError, is_secure_context};
pub use sync_cursor::SyncCursor;
pub use user::{AccountMode, Email, EmailError, KdfParams, Role, User};
