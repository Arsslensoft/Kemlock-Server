//! Spaces: shared vaults with members, roles, groups, collections and grants.
//!
//! The rules are in `kemlock_domain::spaces`; these use cases load a space through
//! [`ports::SpaceRepo`], ask the rules, and store the result in one transaction. The server never
//! holds a key: clients send keys already sealed to each recipient, and the use cases check only
//! who is allowed to receive them and that every recipient got one.
//!
//! - [`CreateSpace`], [`InviteMember`], [`ResendInvitation`], [`AcceptInvitation`],
//!   [`ConfirmMember`], [`ChangeRole`], [`Offboard`] (revoke, restore, remove, leave) take a person
//!   through a space.
//! - [`LookupAccount`] finds the account an admin is about to invite, by email.
//! - [`ListSpaces`], [`GetSpace`], [`ListMembers`] read it, each member seeing what their role
//!   allows.
//! - [`CreateCollection`], [`EditCollection`], [`DeleteCollection`], [`CreateGroup`],
//!   [`EditGroup`], [`DeleteGroup`], [`GrantAccess`], [`RevokeGrant`] shape who sees what.
//! - [`ReplaceKeys`] lands the key replacement that offboarding requires, as one transaction.
//! - [`ResealKeys`] seals the keys of a space with no chain again, signed, so it has no boxes from
//!   before keys were signed.
//! - [`PutSpaceItem`] writes an item into a space, and [`SpaceAccess`] is its authorization step;
//!   [`PutSpaceBatch`] stores a batch of vault and space items together.
//! - [`SyncOwners`] lists the owners a device syncs: its user and every space it is confirmed in.
//! - [`ApplyGroupRules`] invites an account to the spaces the admin's SSO group rules name, at
//!   sign-in; it never confirms anyone.
//! - [`SpaceFacts`] gives the sign-in checks (`sso::RequireSso`) an account's confirmed memberships
//!   with the space's "Require SSO" policy, which `policies::SetPolicies` sets.

pub mod access;
pub mod authority;
pub mod chain;
pub mod chain_append;
pub mod chain_project;
pub mod chain_read;
pub mod collections;
pub mod confirm;
pub mod create;
pub mod error;
pub mod facts;
pub mod grants;
pub mod groups;
pub mod invite;
pub mod key_boxes;
pub mod lookup;
pub mod members;
pub mod ports;
pub mod put_batch;
pub mod put_item;
pub mod recovery;
pub mod replace_keys;
pub mod reseal;
pub mod sso_groups;
pub mod support;
pub mod sync_owners;
pub mod view;

pub use access::SpaceAccess;
pub use chain::{
    AppendOutcome, CHAIN_REQUIRED, ChainAppend, ChainHead, ChainUsage, ExternalChangeMode,
    ExternalSource, HomeGate, PendingChange, PendingExternal, SpaceChainRepo, StoredName,
    StoredRecord, StoredSeal, chain_confirmed, chain_required, confirmed_of, ensure_unchained,
    pending_from_changes, replay_state,
};
pub use chain_append::{AppendChain, AppendError, AppendRequest, NameIn, SealIn, invitees};
pub use chain_read::{ChainReadError, GetChain, GetChainSeals, PendingChanges};
pub use collections::{
    CreateCollection, CreateCollectionInput, DeleteCollection, EditCollection, EditCollectionInput,
};
pub use confirm::{ConfirmInput, ConfirmMember};
pub use create::{CreateSpace, CreateSpaceInput, NewCollection};
pub use error::SpacesError;
pub use facts::SpaceFacts;
pub use grants::{GrantAccess, RevokeGrant};
pub use groups::{CreateGroup, CreateGroupInput, DeleteGroup, EditGroup, EditGroupInput};
pub use invite::{AcceptInvitation, InviteInput, InviteMember, ResendInvitation};
pub use key_boxes::{KeyBoxFacts, KeyBoxKey, KeyBoxVerifier};
pub use lookup::{AccountLookup, LookupAccount};
pub use members::{ChangeRole, Exposure, Offboard, Offboarded};
pub use ports::{
    BundleFingerprints, ConfirmationFacts, KeyReplacement, OWNER_REQUIRED, SpaceChanges,
    SpaceItemInfo, SpaceRepo,
};
pub use put_batch::PutSpaceBatch;
pub use put_item::PutSpaceItem;
pub use recovery::{
    RECOVERY_BOX_LEN, Recovered, RecoveryBox, RecoveryError, SpaceRecovery, SpaceRecoveryRepo,
    may_recover,
};
pub use replace_keys::{CollectionRekey, ReplaceKeys, ReplacementInput};
pub use reseal::{ResealKeys, ResealMember};
pub use sso_groups::ApplyGroupRules;
pub use support::{SealedCollectionKey, SealedSpaceKey};
pub use sync_owners::SyncOwners;
pub use view::{GetSpace, ListMembers, ListSpaces, MemberView, SpaceSummary, SpaceView};
