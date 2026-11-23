//! The duplicate cleaner's server side (design, "Duplicate cleaner").
//!
//! The device makes every tag from normalised values under a dedup key the server never holds
//! (`kemlock_crypto::dedup`) and matches them itself by default. With server matching on for an
//! owner, devices upload the `cred` tags and the server groups equal ones; the device still checks
//! every group before anything merges. The server never makes a tag.
//!
//! - [`StoreTags`] and [`BackfillTags`] keep an item's tags, with a write or after it.
//! - [`ListDuplicates`] groups them, without the answers saved by [`Dismiss`] (undone by
//!   [`Undismiss`]).
//! - [`SetMatching`] turns server matching on or off (off deletes the tags), [`GetMatching`] reads
//!   it, and [`RotateDedupKey`] moves the key version when a user key or space key is replaced.
//!
//! The ports are in [`ports`]. A write through any API clears the item's tags in the store's own
//! transaction, which is how a Bitwarden-API write clears them.

mod access;
pub mod dismissals;
pub mod error;
pub mod groups;
pub mod matching;
pub mod ports;
pub mod store_tags;

pub use dismissals::{Dismiss, Undismiss};
pub use error::DedupError;
pub use groups::{DuplicateReport, GetMatching, ListDuplicates};
pub use matching::{RotateDedupKey, SetMatching};
pub use ports::{DismissalStore, TagStore};
pub use store_tags::{BackfillTags, StoreTags, TagOutcome};
