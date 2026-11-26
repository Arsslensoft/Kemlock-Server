//! Spaces: shared vaults, their members, groups and collections, and the rules between them.
//!
//! A space has one space key and, per collection, one collection key (docs/crypto.md, contexts
//! `"space-key"` and `"collection-key"`). The server never sees a key: it holds each key sealed
//! to the members who may have it, and the names of the space, its collections and its groups
//! encrypted under the space key. What the server can do is keep the rules below, so it can't be
//! the one who widens access.
//!
//! - **Members** go through `Invited`, `Accepted` and `Confirmed`. Only a confirmed member holds
//!   keys. An admin confirms a member only after comparing the member's fingerprint, and sends the
//!   fingerprint they compared; the server checks it against the member's bundle and stores the
//!   admin's signed statement beside the member.
//! - **Roles** are Owner, Admin, Custom and Member. Only an owner makes an owner, and the new owner
//!   must already be confirmed, because the server can't hand out a space key.
//! - **Access to items is by grant only.** A grant gives a member or a group one of five
//!   permissions on one collection. Owners and admins manage who is in the space, but read or
//!   write a collection's items only through a grant like anyone else, because a key they were
//!   never sealed can't open it anyway.
//! - **Losing a key means replacing it.** When a member is revoked or removed, or loses access to
//!   a collection they held, the keys they held are marked for replacement and writes pause until
//!   the client lands a replacement (see [`SpaceState::replacement_plan`]).

use crate::ids::{SpaceId, UserId};
use crate::item::{Item, ItemDraft, ItemError, ItemLimits, ItemWrite, MIN_SEALED_LEN};
use crate::owner::Owner;
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use std::fmt;
use time::OffsetDateTime;
use uuid::Uuid;

macro_rules! space_id {
    ($(#[$doc:meta])* $name:ident) => {
        $(#[$doc])*
        #[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
        #[serde(transparent)]
        pub struct $name(pub Uuid);

        impl $name {
            /// A new random id (UUID v4).
            pub fn random() -> Self {
                Self(Uuid::new_v4())
            }

            /// The id's 16 raw bytes, as binary formats encode it.
            pub fn as_bytes(&self) -> &[u8; 16] {
                self.0.as_bytes()
            }
        }

        impl fmt::Debug for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(f, concat!(stringify!($name), "({})"), self.0)
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                self.0.fmt(f)
            }
        }

        impl std::str::FromStr for $name {
            type Err = uuid::Error;
            fn from_str(s: &str) -> Result<Self, Self::Err> {
                Uuid::parse_str(s).map(Self)
            }
        }
    };
}

space_id!(
    /// A collection: a set of a space's items that share one key and one set of grants.
    CollectionId
);
space_id!(
    /// A group of a space's members, granted collections as one.
    GroupId
);

/// A `kx1` sealed box of a 32-byte key: `u8(1) ‖ ct (1600) ‖ nonce (12) ‖ key (32) ‖ tag (16)`.
pub const SEALED_KEY_LEN: usize = 1 + 1600 + 12 + 32 + 16;
/// A fingerprint is a SHA-512.
pub const FINGERPRINT_LEN: usize = 64;
/// A `sig1` signature: ML-DSA-65 (3309) and Ed25519 (64).
pub const CONFIRMATION_SIGNATURE_LEN: usize = 3309 + 64;
/// The longest statement a confirmer may sign and the server keep.
pub const MAX_STATEMENT_LEN: usize = 4096;
/// The longest encrypted name kept.
pub const MAX_NAME_LEN: usize = 4096;
/// Collections nest at most this deep.
pub const MAX_COLLECTION_DEPTH: usize = 16;
/// The first version of a space key or a collection key.
pub const FIRST_KEY_VERSION: u32 = 1;

/// A member's role in a space.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum SpaceRole {
    Owner,
    Admin,
    Custom,
    Member,
}

impl SpaceRole {
    pub fn as_str(self) -> &'static str {
        match self {
            SpaceRole::Owner => "owner",
            SpaceRole::Admin => "admin",
            SpaceRole::Custom => "custom",
            SpaceRole::Member => "member",
        }
    }

    pub fn parse(s: &str) -> Option<SpaceRole> {
        match s {
            "owner" => Some(SpaceRole::Owner),
            "admin" => Some(SpaceRole::Admin),
            "custom" => Some(SpaceRole::Custom),
            "member" => Some(SpaceRole::Member),
            _ => None,
        }
    }
}

/// Where a member is on the way in (or out).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum MemberState {
    /// An admin invited them; they haven't answered.
    Invited,
    /// They accepted; no admin has compared their fingerprint yet. No key is sealed to them.
    Accepted,
    /// An admin compared their fingerprint and sealed the keys.
    Confirmed,
    /// Taken out, keeping their row so they can be restored (and confirmed again).
    Revoked,
}

impl MemberState {
    pub fn as_str(self) -> &'static str {
        match self {
            MemberState::Invited => "invited",
            MemberState::Accepted => "accepted",
            MemberState::Confirmed => "confirmed",
            MemberState::Revoked => "revoked",
        }
    }

    pub fn parse(s: &str) -> Option<MemberState> {
        match s {
            "invited" => Some(MemberState::Invited),
            "accepted" => Some(MemberState::Accepted),
            "confirmed" => Some(MemberState::Confirmed),
            "revoked" => Some(MemberState::Revoked),
            _ => None,
        }
    }
}

/// The permission list behind the Custom role: a few of Bitwarden's, as a bit set. Owners and
/// admins have all of them; members none.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub struct CustomPermissions(u16);

impl CustomPermissions {
    pub const NONE: CustomPermissions = CustomPermissions(0);
    /// Invite, confirm, revoke and remove members and other Custom members.
    pub const MANAGE_USERS: CustomPermissions = CustomPermissions(1);
    /// Create, change and delete groups.
    pub const MANAGE_GROUPS: CustomPermissions = CustomPermissions(1 << 1);
    /// Create collections.
    pub const CREATE_COLLECTIONS: CustomPermissions = CustomPermissions(1 << 2);

    const ALL_BITS: u16 = 0b111;

    /// `None` when a bit is set that no permission has.
    pub fn from_bits(bits: u16) -> Option<CustomPermissions> {
        (bits & !Self::ALL_BITS == 0).then_some(CustomPermissions(bits))
    }

    pub fn bits(self) -> u16 {
        self.0
    }

    pub fn is_empty(self) -> bool {
        self.0 == 0
    }

    pub fn contains(self, other: CustomPermissions) -> bool {
        self.0 & other.0 == other.0
    }

    pub fn is_subset_of(self, other: CustomPermissions) -> bool {
        self.0 & !other.0 == 0
    }

    pub fn union(self, other: CustomPermissions) -> CustomPermissions {
        CustomPermissions(self.0 | other.0)
    }
}

/// What a grant lets a member or group do with one collection's items.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum CollectionPermission {
    View,
    ViewHidePasswords,
    Edit,
    EditHidePasswords,
    Manage,
}

/// The rights a permission (or several, combined) gives. Reading is implied: a grant gives the
/// key. `hide_passwords` is a display rule for clients, which hold the key anyway.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Access {
    pub edit: bool,
    pub hide_passwords: bool,
    pub manage: bool,
}

impl Access {
    /// Rights from two grants together: the more permissive wins on every count, so passwords stay
    /// hidden only when every grant hides them.
    pub fn combine(self, other: Access) -> Access {
        Access {
            edit: self.edit || other.edit,
            hide_passwords: self.hide_passwords && other.hide_passwords,
            manage: self.manage || other.manage,
        }
    }
}

impl CollectionPermission {
    pub fn as_str(self) -> &'static str {
        match self {
            CollectionPermission::View => "view",
            CollectionPermission::ViewHidePasswords => "view-hide-passwords",
            CollectionPermission::Edit => "edit",
            CollectionPermission::EditHidePasswords => "edit-hide-passwords",
            CollectionPermission::Manage => "manage",
        }
    }

    pub fn parse(s: &str) -> Option<CollectionPermission> {
        match s {
            "view" => Some(CollectionPermission::View),
            "view-hide-passwords" => Some(CollectionPermission::ViewHidePasswords),
            "edit" => Some(CollectionPermission::Edit),
            "edit-hide-passwords" => Some(CollectionPermission::EditHidePasswords),
            "manage" => Some(CollectionPermission::Manage),
            _ => None,
        }
    }

    pub fn access(self) -> Access {
        let (edit, hide_passwords, manage) = match self {
            CollectionPermission::View => (false, false, false),
            CollectionPermission::ViewHidePasswords => (false, true, false),
            CollectionPermission::Edit => (true, false, false),
            CollectionPermission::EditHidePasswords => (true, true, false),
            CollectionPermission::Manage => (true, false, true),
        };
        Access {
            edit,
            hide_passwords,
            manage,
        }
    }
}

/// A space. Its name is encrypted under the space key.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Space {
    pub id: SpaceId,
    pub name: Vec<u8>,
    /// The version of the current space key.
    pub key_version: u32,
    /// Set while the space key must be replaced because someone who held it left. Item writes and
    /// anything that seals a key are refused until a replacement lands.
    pub keys_pending_since: Option<OffsetDateTime>,
    pub created_at: OffsetDateTime,
    pub updated_at: OffsetDateTime,
}

/// What a confirmer left behind: that they compared this fingerprint, signed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Confirmation {
    pub by: UserId,
    pub at: OffsetDateTime,
    /// The fingerprint of the member's bundle, as the confirmer compared it.
    pub fingerprint: Vec<u8>,
    /// The member's key version the fingerprint belongs to. When the member's account moves to
    /// another key version, the confirmation no longer covers them.
    pub member_key_version: u32,
    /// The statement the confirmer signed (their `sig1` signature over it is `signature`).
    /// The server keeps both and does not interpret them; clients verify them.
    pub statement: Vec<u8>,
    pub signature: Vec<u8>,
}

/// One account's place in one space.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Member {
    pub space: SpaceId,
    pub user: UserId,
    pub role: SpaceRole,
    /// Only meaningful for `Custom`; empty otherwise.
    pub custom: CustomPermissions,
    pub state: MemberState,
    pub invited_by: UserId,
    pub invited_at: OffsetDateTime,
    pub accepted_at: Option<OffsetDateTime>,
    /// The space key, sealed to this member's `kx1` key. Present only while confirmed.
    pub sealed_space_key: Option<Vec<u8>>,
    /// The version of `sealed_space_key`.
    pub key_version: Option<u32>,
    pub confirmation: Option<Confirmation>,
    pub revoked_at: Option<OffsetDateTime>,
}

impl Member {
    pub fn is_confirmed(&self) -> bool {
        self.state == MemberState::Confirmed
    }

    /// A new invitation.
    pub fn invited(
        space: SpaceId,
        user: UserId,
        role: SpaceRole,
        custom: CustomPermissions,
        invited_by: UserId,
        now: OffsetDateTime,
    ) -> Member {
        Member {
            space,
            user,
            role,
            custom,
            state: MemberState::Invited,
            invited_by,
            invited_at: now,
            accepted_at: None,
            sealed_space_key: None,
            key_version: None,
            confirmation: None,
            revoked_at: None,
        }
    }
}

/// A named set of members. The name is encrypted under the space key.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Group {
    pub id: GroupId,
    pub space: SpaceId,
    pub name: Vec<u8>,
    pub members: BTreeSet<UserId>,
    pub created_at: OffsetDateTime,
}

/// A collection. Its name is encrypted under the space key; its key is its own.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Collection {
    pub id: CollectionId,
    pub space: SpaceId,
    pub parent: Option<CollectionId>,
    pub name: Vec<u8>,
    /// The version of the current collection key; items are wrapped under it.
    pub key_version: u32,
    /// Set while the key must be replaced because someone who held it lost access.
    pub stale_since: Option<OffsetDateTime>,
    pub created_at: OffsetDateTime,
}

/// Who a grant gives access to.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Grantee {
    Member(UserId),
    Group(GroupId),
}

impl fmt::Display for Grantee {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Grantee::Member(u) => write!(f, "user:{u}"),
            Grantee::Group(g) => write!(f, "group:{g}"),
        }
    }
}

impl fmt::Debug for Grantee {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, f)
    }
}

impl std::str::FromStr for Grantee {
    type Err = &'static str;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let (kind, id) = s
            .split_once(':')
            .ok_or("a grantee is user:<id> or group:<id>")?;
        let uuid = Uuid::parse_str(id).map_err(|_| "the grantee's id is not a UUID")?;
        match kind {
            "user" => Ok(Grantee::Member(UserId(uuid))),
            "group" => Ok(Grantee::Group(GroupId(uuid))),
            _ => Err("a grantee is user:<id> or group:<id>"),
        }
    }
}

/// A member's or group's permission on one collection.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CollectionGrant {
    pub collection: CollectionId,
    pub grantee: Grantee,
    pub permission: CollectionPermission,
}

/// A collection key sealed to one member.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct KeyCopy {
    pub collection: CollectionId,
    pub user: UserId,
    /// The collection key version that was sealed.
    pub key_version: u32,
    pub sealed: Vec<u8>,
}

/// Why a space rule refused something.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum SpaceError {
    #[error("you are not a confirmed member of this space")]
    NotAMember,
    #[error("{0}")]
    Forbidden(&'static str),
    #[error("{0}")]
    Invalid(&'static str),
    /// The target isn't in the state the action needs.
    #[error("{0}")]
    State(&'static str),
    #[error("the space's keys must be replaced before this can be done")]
    KeysPending,
    #[error("the collection's key is at version {current}")]
    StaleKeyVersion { current: u32 },
    #[error("the fingerprint is not the one of the member's key bundle")]
    FingerprintMismatch,
    #[error("a space needs at least one confirmed owner")]
    LastOwner,
}

/// Which collection keys must be sealed to whom after a change, and which copies are now held by
/// someone who may not hold them.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct KeyDelta {
    /// `(collection, member)` pairs that have access but no key copy yet.
    pub needed: BTreeSet<(CollectionId, UserId)>,
    /// `(collection, member)` copies held by someone who no longer has access.
    pub lost: BTreeSet<(CollectionId, UserId)>,
}

impl KeyDelta {
    /// The collections whose key a member who lost access has seen: they need a new key.
    pub fn stale_collections(&self) -> BTreeSet<CollectionId> {
        self.lost.iter().map(|(c, _)| *c).collect()
    }
}

/// What a key replacement must cover.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReplacementPlan {
    /// Whether the space key is replaced too. Then every confirmed member gets a new sealed copy
    /// and every name is re-encrypted under it.
    pub space_key: bool,
    /// The collections whose key is replaced.
    pub collections: BTreeSet<CollectionId>,
}

/// A space with everything the rules need: members, groups, collections and grants.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SpaceState {
    pub space: Space,
    pub members: Vec<Member>,
    pub groups: Vec<Group>,
    pub collections: Vec<Collection>,
    pub grants: Vec<CollectionGrant>,
}

/// Whether `actor` may manage `target` (invite them, confirm, revoke, change their role): an owner
/// manages anyone, an admin anyone but an owner, and a Custom member with `MANAGE_USERS` other
/// Custom members and members.
fn can_manage_member(actor: &Member, target: &Member) -> bool {
    match actor.role {
        SpaceRole::Owner => true,
        SpaceRole::Admin => target.role != SpaceRole::Owner,
        SpaceRole::Custom => {
            actor.custom.contains(CustomPermissions::MANAGE_USERS)
                && matches!(target.role, SpaceRole::Custom | SpaceRole::Member)
        }
        SpaceRole::Member => false,
    }
}

/// Whether `actor` may give someone `role` with `custom` permissions. An owner may give any role
/// (making an owner is a role change, never an invitation); an admin any but owner; a Custom
/// member with `MANAGE_USERS` Member, or Custom with permissions it holds itself.
fn can_assign(actor: &Member, role: SpaceRole, custom: CustomPermissions) -> bool {
    match actor.role {
        SpaceRole::Owner => true,
        SpaceRole::Admin => role != SpaceRole::Owner,
        SpaceRole::Custom => {
            actor.custom.contains(CustomPermissions::MANAGE_USERS)
                && match role {
                    SpaceRole::Member => true,
                    SpaceRole::Custom => custom.is_subset_of(actor.custom),
                    SpaceRole::Owner | SpaceRole::Admin => false,
                }
        }
        SpaceRole::Member => false,
    }
}

fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

/// A sealed key must be a `kx1` sealed box of a 32-byte key.
pub fn check_sealed_key(value: &[u8]) -> Result<(), SpaceError> {
    if value.len() == SEALED_KEY_LEN && value[0] == 1 {
        Ok(())
    } else {
        Err(SpaceError::Invalid(
            "a sealed key must be a kx1 sealed box of a 32-byte key",
        ))
    }
}

/// An encrypted name must be a sealed value of a sensible size.
pub fn check_sealed_name(value: &[u8]) -> Result<(), SpaceError> {
    if (MIN_SEALED_LEN..=MAX_NAME_LEN).contains(&value.len()) {
        Ok(())
    } else {
        Err(SpaceError::Invalid(
            "an encrypted name must be a sealed value of at most 4 KiB",
        ))
    }
}

/// A confirmation's statement and signature must be of a size the server will keep.
pub fn check_confirmation_parts(statement: &[u8], signature: &[u8]) -> Result<(), SpaceError> {
    if statement.is_empty() || statement.len() > MAX_STATEMENT_LEN {
        return Err(SpaceError::Invalid(
            "the confirmation statement must be 1 to 4096 bytes",
        ));
    }
    if signature.len() != CONFIRMATION_SIGNATURE_LEN {
        return Err(SpaceError::Invalid(
            "the confirmation signature must be a 3,373-byte sig1 signature",
        ));
    }
    Ok(())
}

impl SpaceState {
    pub fn member(&self, user: UserId) -> Option<&Member> {
        self.members.iter().find(|m| m.user == user)
    }

    pub fn collection(&self, id: CollectionId) -> Option<&Collection> {
        self.collections.iter().find(|c| c.id == id)
    }

    pub fn group(&self, id: GroupId) -> Option<&Group> {
        self.groups.iter().find(|g| g.id == id)
    }

    /// The actor as a confirmed member, or `NotAMember`. Every action by someone already in the
    /// space starts here, so an invited, accepted or revoked account can do nothing in it.
    pub fn confirmed_actor(&self, user: UserId) -> Result<&Member, SpaceError> {
        self.member(user)
            .filter(|m| m.is_confirmed())
            .ok_or(SpaceError::NotAMember)
    }

    pub fn confirmed_owners(&self) -> usize {
        self.members
            .iter()
            .filter(|m| m.is_confirmed() && m.role == SpaceRole::Owner)
            .count()
    }

    pub fn confirmed_members(&self) -> impl Iterator<Item = &Member> {
        self.members.iter().filter(|m| m.is_confirmed())
    }

    /// Whether the whole space is paused until its key is replaced.
    pub fn writes_paused(&self) -> bool {
        self.space.keys_pending_since.is_some()
    }

    /// Refuses with `KeysPending` while the space key is awaiting replacement.
    pub fn ensure_keys_open(&self) -> Result<(), SpaceError> {
        if self.writes_paused() {
            Err(SpaceError::KeysPending)
        } else {
            Ok(())
        }
    }

    /// Refuses with `KeysPending` while the space or this collection awaits a key replacement.
    pub fn ensure_collection_open(&self, collection: &Collection) -> Result<(), SpaceError> {
        self.ensure_keys_open()?;
        if collection.stale_since.is_some() {
            Err(SpaceError::KeysPending)
        } else {
            Ok(())
        }
    }

    // ---- who may invite, confirm, change roles, revoke, remove ----

    /// Whether `actor` may invite `target` as `role`. Nobody is invited as an owner: an owner is
    /// made by promoting a confirmed member, so the new owner can't be one nobody has checked.
    pub fn authorize_invite(
        &self,
        actor: UserId,
        target: UserId,
        role: SpaceRole,
        custom: CustomPermissions,
    ) -> Result<(), SpaceError> {
        let a = self.confirmed_actor(actor)?;
        if self.member(target).is_some() {
            return Err(SpaceError::State(
                "that person is already a member or has an invitation",
            ));
        }
        if role == SpaceRole::Owner {
            return Err(SpaceError::Forbidden(
                "an owner is made by promoting a confirmed member, not by an invitation",
            ));
        }
        if role != SpaceRole::Custom && !custom.is_empty() {
            return Err(SpaceError::Invalid(
                "only a Custom member has custom permissions",
            ));
        }
        if !can_assign(a, role, custom) {
            return Err(SpaceError::Forbidden("your role can't invite that role"));
        }
        Ok(())
    }

    /// The actor as a confirmed member who manages users: an owner, an admin, or a Custom member
    /// with `MANAGE_USERS`. `NotAMember` for anyone not confirmed, `Forbidden` for a confirmed
    /// member whose role doesn't manage users.
    pub fn authorize_manage_users(&self, actor: UserId) -> Result<&Member, SpaceError> {
        let a = self.confirmed_actor(actor)?;
        let manages = match a.role {
            SpaceRole::Owner | SpaceRole::Admin => true,
            SpaceRole::Custom => a.custom.contains(CustomPermissions::MANAGE_USERS),
            SpaceRole::Member => false,
        };
        if manages {
            Ok(a)
        } else {
            Err(SpaceError::Forbidden("your role can't manage members"))
        }
    }

    /// Whether `actor` may have the invitation of `target` sent again: a confirmed member who
    /// manages users and may manage `target`, while `target` is still only invited. Whoever
    /// accepted has seen the invitation already.
    pub fn authorize_resend(&self, actor: UserId, target: UserId) -> Result<&Member, SpaceError> {
        let a = self.authorize_manage_users(actor)?;
        let t = self
            .member(target)
            .ok_or(SpaceError::State("that person is not in this space"))?;
        if !can_manage_member(a, t) {
            return Err(SpaceError::Forbidden("your role can't manage this member"));
        }
        if t.state != MemberState::Invited {
            return Err(SpaceError::State(
                "only a member who hasn't accepted yet is sent the invitation again",
            ));
        }
        Ok(t)
    }

    /// Whether `actor` may confirm `target`, who must have accepted, or be confirmed already: a
    /// confirmed member may be confirmed again, which replaces their confirmation (the confirmer
    /// left or lost their role, nobody confirmed them, or their keys changed). Who may do it is
    /// judged as of now. `submitted` is the
    /// fingerprint the confirmer says they compared and `actual` the one of the member's bundle.
    /// Confirming waits while the space's keys await replacement, because a key sealed now would
    /// be sealed under one that is about to be replaced.
    pub fn authorize_confirm(
        &self,
        actor: UserId,
        target: UserId,
        submitted: &[u8],
        actual: &[u8],
    ) -> Result<&Member, SpaceError> {
        let a = self.confirmed_actor(actor)?;
        let t = self
            .member(target)
            .ok_or(SpaceError::State("that person is not in this space"))?;
        if actor == target {
            return Err(SpaceError::Forbidden("you can't confirm yourself"));
        }
        if !matches!(t.state, MemberState::Accepted | MemberState::Confirmed) {
            return Err(SpaceError::State(
                "only a member who accepted the invitation can be confirmed",
            ));
        }
        if !can_manage_member(a, t) {
            return Err(SpaceError::Forbidden("your role can't confirm this member"));
        }
        self.ensure_keys_open()?;
        if !ct_eq(submitted, actual) {
            return Err(SpaceError::FingerprintMismatch);
        }
        Ok(t)
    }

    /// Whether `actor` may give `target` the role `role` (with `custom`). Only an owner makes an
    /// owner, and the new owner must be confirmed; the last confirmed owner can't be demoted.
    pub fn authorize_role_change(
        &self,
        actor: UserId,
        target: UserId,
        role: SpaceRole,
        custom: CustomPermissions,
    ) -> Result<&Member, SpaceError> {
        let a = self.confirmed_actor(actor)?;
        let t = self
            .member(target)
            .ok_or(SpaceError::State("that person is not in this space"))?;
        if t.state == MemberState::Revoked {
            return Err(SpaceError::State(
                "restore a revoked member before changing their role",
            ));
        }
        if role != SpaceRole::Custom && !custom.is_empty() {
            return Err(SpaceError::Invalid(
                "only a Custom member has custom permissions",
            ));
        }
        if role == SpaceRole::Owner {
            if a.role != SpaceRole::Owner {
                return Err(SpaceError::Forbidden("only an owner makes an owner"));
            }
            if t.state != MemberState::Confirmed {
                return Err(SpaceError::State(
                    "the new owner must be a confirmed member: the server can't hand out the space key",
                ));
            }
        }
        if !can_manage_member(a, t) || !can_assign(a, role, custom) {
            return Err(SpaceError::Forbidden(
                "your role can't give this member that role",
            ));
        }
        if t.role == SpaceRole::Owner
            && role != SpaceRole::Owner
            && t.is_confirmed()
            && self.confirmed_owners() <= 1
        {
            return Err(SpaceError::LastOwner);
        }
        Ok(t)
    }

    /// Whether `actor` may revoke `target`: someone confirmed, who is not the actor.
    pub fn authorize_revoke(&self, actor: UserId, target: UserId) -> Result<&Member, SpaceError> {
        let a = self.confirmed_actor(actor)?;
        let t = self
            .member(target)
            .ok_or(SpaceError::State("that person is not in this space"))?;
        if actor == target {
            return Err(SpaceError::Forbidden(
                "you can't revoke yourself; leave the space instead",
            ));
        }
        if t.state != MemberState::Confirmed {
            return Err(SpaceError::State(
                "only a confirmed member is revoked; remove an invitation instead",
            ));
        }
        if !can_manage_member(a, t) {
            return Err(SpaceError::Forbidden("your role can't revoke this member"));
        }
        if t.role == SpaceRole::Owner && self.confirmed_owners() <= 1 {
            return Err(SpaceError::LastOwner);
        }
        Ok(t)
    }

    /// Whether `actor` may restore a revoked `target`, who then waits to be confirmed again.
    pub fn authorize_restore(&self, actor: UserId, target: UserId) -> Result<&Member, SpaceError> {
        let a = self.confirmed_actor(actor)?;
        let t = self
            .member(target)
            .ok_or(SpaceError::State("that person is not in this space"))?;
        if t.state != MemberState::Revoked {
            return Err(SpaceError::State("only a revoked member can be restored"));
        }
        if !can_manage_member(a, t) {
            return Err(SpaceError::Forbidden("your role can't restore this member"));
        }
        Ok(t)
    }

    /// Whether `actor` may remove `target`, or leave when they are the same person. Anyone in any
    /// state may leave, except the last confirmed owner.
    pub fn authorize_remove(&self, actor: UserId, target: UserId) -> Result<&Member, SpaceError> {
        let t = self
            .member(target)
            .ok_or(SpaceError::State("that person is not in this space"))?;
        if actor != target {
            let a = self.confirmed_actor(actor)?;
            if !can_manage_member(a, t) {
                return Err(SpaceError::Forbidden("your role can't remove this member"));
            }
        }
        if t.is_confirmed() && t.role == SpaceRole::Owner && self.confirmed_owners() <= 1 {
            return Err(SpaceError::LastOwner);
        }
        Ok(t)
    }

    // ---- collections, groups, grants ----

    /// Whether `actor` may create a collection: owners, admins and Custom members with
    /// `CREATE_COLLECTIONS`.
    pub fn authorize_create_collection(&self, actor: UserId) -> Result<(), SpaceError> {
        let a = self.confirmed_actor(actor)?;
        let ok = matches!(a.role, SpaceRole::Owner | SpaceRole::Admin)
            || (a.role == SpaceRole::Custom
                && a.custom.contains(CustomPermissions::CREATE_COLLECTIONS));
        if ok {
            Ok(())
        } else {
            Err(SpaceError::Forbidden("your role can't create collections"))
        }
    }

    /// Whether `actor` may change, delete or grant `collection`: owners and admins, and members
    /// holding the Manage permission on it ("a grant's manage lets its holder grant that
    /// collection only").
    pub fn authorize_manage_collection(
        &self,
        actor: UserId,
        collection: CollectionId,
    ) -> Result<&Collection, SpaceError> {
        let a = self.confirmed_actor(actor)?;
        let c = self
            .collection(collection)
            .ok_or(SpaceError::Invalid("there is no such collection"))?;
        let ok = matches!(a.role, SpaceRole::Owner | SpaceRole::Admin)
            || self.access(actor, collection).is_some_and(|x| x.manage);
        if ok {
            Ok(c)
        } else {
            Err(SpaceError::Forbidden(
                "you need the Manage permission on this collection",
            ))
        }
    }

    /// Whether `actor` may make, change or delete groups.
    pub fn authorize_manage_groups(&self, actor: UserId) -> Result<(), SpaceError> {
        let a = self.confirmed_actor(actor)?;
        let ok = matches!(a.role, SpaceRole::Owner | SpaceRole::Admin)
            || (a.role == SpaceRole::Custom && a.custom.contains(CustomPermissions::MANAGE_GROUPS));
        if ok {
            Ok(())
        } else {
            Err(SpaceError::Forbidden("your role can't manage groups"))
        }
    }

    /// The nesting of `id` under `parent` is allowed: the parent is in this space, the chain of
    /// parents never comes back to `id`, and it is at most [`MAX_COLLECTION_DEPTH`] deep.
    pub fn check_parent(
        &self,
        id: CollectionId,
        parent: Option<CollectionId>,
    ) -> Result<(), SpaceError> {
        let mut depth = 1usize;
        let mut cursor = parent;
        while let Some(p) = cursor {
            if p == id {
                return Err(SpaceError::Invalid(
                    "a collection can't be nested under itself",
                ));
            }
            let c = self.collection(p).ok_or(SpaceError::Invalid(
                "the parent collection is not in this space",
            ))?;
            depth += 1;
            if depth > MAX_COLLECTION_DEPTH {
                return Err(SpaceError::Invalid("collections nest at most 16 deep"));
            }
            cursor = c.parent;
        }
        Ok(())
    }

    /// The rights `user` has on `collection` through grants, directly or by a group. `None` when
    /// they have none. The member's state isn't looked at: callers check it where it matters.
    pub fn access(&self, user: UserId, collection: CollectionId) -> Option<Access> {
        let mut found: Option<Access> = None;
        for grant in self.grants.iter().filter(|g| g.collection == collection) {
            let applies = match grant.grantee {
                Grantee::Member(u) => u == user,
                Grantee::Group(id) => self.group(id).is_some_and(|g| g.members.contains(&user)),
            };
            if applies {
                let rights = grant.permission.access();
                found = Some(found.map_or(rights, |known| known.combine(rights)));
            }
        }
        found
    }

    /// The confirmed members who may hold `collection`'s key.
    pub fn recipients(&self, collection: CollectionId) -> BTreeSet<UserId> {
        self.confirmed_members()
            .filter(|m| self.access(m.user, collection).is_some())
            .map(|m| m.user)
            .collect()
    }

    /// The collections `user` has access to through grants, whatever their state.
    pub fn collections_of(&self, user: UserId) -> BTreeSet<CollectionId> {
        self.collections
            .iter()
            .filter(|c| self.access(user, c.id).is_some())
            .map(|c| c.id)
            .collect()
    }

    /// Compares who may hold each collection key in this state with who holds a copy now:
    /// `needed` are the copies to seal, `lost` the copies held by someone without access.
    pub fn key_delta(&self, holders: &[(CollectionId, UserId)]) -> KeyDelta {
        let held: BTreeSet<(CollectionId, UserId)> = holders.iter().copied().collect();
        let mut delta = KeyDelta::default();
        for collection in &self.collections {
            for user in self.recipients(collection.id) {
                if !held.contains(&(collection.id, user)) {
                    delta.needed.insert((collection.id, user));
                }
            }
        }
        for (collection, user) in &held {
            if self.collection(*collection).is_some()
                && !self.recipients(*collection).contains(user)
            {
                delta.lost.insert((*collection, *user));
            }
        }
        delta
    }

    // ---- items ----

    /// Whether `actor` may write an item into `collection` under key `key_version` (`None` for a
    /// delete, which seals nothing): a confirmed member with edit on the collection, in a space
    /// and collection that aren't awaiting a key replacement, under the collection's current key.
    pub fn authorize_item_write(
        &self,
        actor: UserId,
        collection: CollectionId,
        key_version: Option<u32>,
    ) -> Result<&Collection, SpaceError> {
        self.confirmed_actor(actor)?;
        let c = self
            .collection(collection)
            .ok_or(SpaceError::Invalid("there is no such collection"))?;
        self.ensure_collection_open(c)?;
        if !self.access(actor, collection).is_some_and(|a| a.edit) {
            return Err(SpaceError::Forbidden(
                "you need edit access to this collection",
            ));
        }
        if let Some(version) = key_version
            && version != c.key_version
        {
            return Err(SpaceError::StaleKeyVersion {
                current: c.key_version,
            });
        }
        Ok(c)
    }

    // ---- key replacement ----

    /// What a replacement must cover, or `None` when no key awaits one.
    pub fn replacement_plan(&self) -> Option<ReplacementPlan> {
        let collections: BTreeSet<CollectionId> = self
            .collections
            .iter()
            .filter(|c| c.stale_since.is_some())
            .map(|c| c.id)
            .collect();
        let space_key = self.writes_paused();
        if !space_key && collections.is_empty() {
            None
        } else {
            Some(ReplacementPlan {
                space_key,
                collections,
            })
        }
    }
}

/// Applies an item write in a space: [`ItemWrite::apply`] with its owner rule swapped for the
/// caller's. `apply` allows only the actor's own vault, so this runs the same checks (`If-Match`,
/// revision, immutability, sizes) on a copy owned by the actor and puts the space back as the
/// owner of the draft. Access is not checked here: [`SpaceState::authorize_item_write`] is the
/// authorization step, and a caller must run it first.
///
/// When `ItemWrite::apply` itself learns spaces, `put_item` should call this step's
/// authorization and pass the result in instead of this projection.
pub fn apply_space_write(
    write: ItemWrite,
    stored: Option<&Item>,
    actor: UserId,
    limits: ItemLimits,
    now: OffsetDateTime,
) -> Result<ItemDraft, ItemError> {
    let owner = write.owner;
    if !matches!(owner, Owner::Space(_)) {
        return Err(ItemError::Forbidden);
    }
    if stored.is_some_and(|s| s.owner != owner) {
        return Err(ItemError::Immutable);
    }
    let projected = ItemWrite {
        owner: Owner::User(actor),
        ..write
    };
    let projected_stored = stored.map(|s| Item {
        owner: Owner::User(actor),
        ..s.clone()
    });
    let mut draft = projected.apply(projected_stored.as_ref(), actor, limits, now)?;
    draft.owner = owner;
    Ok(draft)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::change::{ChangeId, Hlc};
    use crate::ids::{ItemId, ServerId};
    use crate::item::{ITEM_KEY_LEN, ItemFormat, ItemKind, Revision, Sealed};
    use time::macros::datetime;

    const NOW: OffsetDateTime = datetime!(2026-06-01 12:00:00 UTC);
    const NONE: CustomPermissions = CustomPermissions::NONE;

    fn member(space: SpaceId, user: UserId, role: SpaceRole, state: MemberState) -> Member {
        let mut m = Member::invited(space, user, role, NONE, UserId::random(), NOW);
        m.state = state;
        if state == MemberState::Confirmed {
            m.sealed_space_key = Some(vec![1; SEALED_KEY_LEN]);
            m.key_version = Some(1);
        }
        m
    }

    fn collection(space: SpaceId, parent: Option<CollectionId>) -> Collection {
        Collection {
            id: CollectionId::random(),
            space,
            parent,
            name: vec![7; 40],
            key_version: 1,
            stale_since: None,
            created_at: NOW,
        }
    }

    /// A space with one of every role, one who accepted, and a collection granted to `member`.
    struct Fixture {
        state: SpaceState,
        owner: UserId,
        admin: UserId,
        custom: UserId,
        member: UserId,
        accepted: UserId,
        finance: CollectionId,
    }

    impl Fixture {
        fn new() -> Fixture {
            let space = SpaceId::random();
            let owner = UserId::random();
            let admin = UserId::random();
            let custom = UserId::random();
            let plain = UserId::random();
            let accepted = UserId::random();
            let mut custom_member =
                member(space, custom, SpaceRole::Custom, MemberState::Confirmed);
            custom_member.custom = CustomPermissions::MANAGE_USERS;
            let finance = collection(space, None);
            let finance_id = finance.id;
            let state = SpaceState {
                space: Space {
                    id: space,
                    name: vec![9; 40],
                    key_version: 1,
                    keys_pending_since: None,
                    created_at: NOW,
                    updated_at: NOW,
                },
                members: vec![
                    member(space, owner, SpaceRole::Owner, MemberState::Confirmed),
                    member(space, admin, SpaceRole::Admin, MemberState::Confirmed),
                    custom_member,
                    member(space, plain, SpaceRole::Member, MemberState::Confirmed),
                    member(space, accepted, SpaceRole::Member, MemberState::Accepted),
                ],
                groups: Vec::new(),
                collections: vec![finance],
                grants: vec![CollectionGrant {
                    collection: finance_id,
                    grantee: Grantee::Member(plain),
                    permission: CollectionPermission::Edit,
                }],
            };
            Fixture {
                state,
                owner,
                admin,
                custom,
                member: plain,
                accepted,
                finance: finance_id,
            }
        }

        fn set_role(&mut self, user: UserId, role: SpaceRole) {
            self.state
                .members
                .iter_mut()
                .find(|m| m.user == user)
                .expect("a member")
                .role = role;
        }

        fn set_state(&mut self, user: UserId, state: MemberState) {
            self.state
                .members
                .iter_mut()
                .find(|m| m.user == user)
                .expect("a member")
                .state = state;
        }
    }

    #[test]
    fn enums_and_ids_round_trip_their_text() {
        for role in [
            SpaceRole::Owner,
            SpaceRole::Admin,
            SpaceRole::Custom,
            SpaceRole::Member,
        ] {
            assert_eq!(SpaceRole::parse(role.as_str()), Some(role));
        }
        for state in [
            MemberState::Invited,
            MemberState::Accepted,
            MemberState::Confirmed,
            MemberState::Revoked,
        ] {
            assert_eq!(MemberState::parse(state.as_str()), Some(state));
        }
        for permission in [
            CollectionPermission::View,
            CollectionPermission::ViewHidePasswords,
            CollectionPermission::Edit,
            CollectionPermission::EditHidePasswords,
            CollectionPermission::Manage,
        ] {
            assert_eq!(
                CollectionPermission::parse(permission.as_str()),
                Some(permission)
            );
        }
        assert_eq!(SpaceRole::parse("manager"), None);
        let grantee = Grantee::Group(GroupId::random());
        assert_eq!(grantee.to_string().parse::<Grantee>(), Ok(grantee));
        let grantee = Grantee::Member(UserId::random());
        assert_eq!(grantee.to_string().parse::<Grantee>(), Ok(grantee));
        assert!(
            "team:7f3c4b1e-0000-4000-8000-000000000000"
                .parse::<Grantee>()
                .is_err()
        );
    }

    #[test]
    fn custom_permissions_are_a_checked_bit_set() {
        assert_eq!(
            CustomPermissions::from_bits(0b111).map(CustomPermissions::bits),
            Some(7)
        );
        assert_eq!(CustomPermissions::from_bits(0b1000), None);
        let both = CustomPermissions::MANAGE_USERS.union(CustomPermissions::MANAGE_GROUPS);
        assert!(both.contains(CustomPermissions::MANAGE_USERS));
        assert!(!both.contains(CustomPermissions::CREATE_COLLECTIONS));
        assert!(CustomPermissions::MANAGE_USERS.is_subset_of(both));
        assert!(!both.is_subset_of(CustomPermissions::MANAGE_USERS));
        assert!(NONE.is_empty());
    }

    #[test]
    fn permissions_give_the_rights_bitwarden_names() {
        let view = CollectionPermission::View.access();
        assert!(!view.edit && !view.hide_passwords && !view.manage);
        let hidden = CollectionPermission::EditHidePasswords.access();
        assert!(hidden.edit && hidden.hide_passwords && !hidden.manage);
        let manage = CollectionPermission::Manage.access();
        assert!(manage.edit && manage.manage && !manage.hide_passwords);
        // Two grants together: the more permissive wins, so passwords stay hidden only when both
        // grants hide them.
        let both_hide = CollectionPermission::ViewHidePasswords
            .access()
            .combine(CollectionPermission::EditHidePasswords.access());
        assert!(both_hide.edit && both_hide.hide_passwords);
        let one_hides = CollectionPermission::ViewHidePasswords
            .access()
            .combine(CollectionPermission::View.access());
        assert!(!one_hides.hide_passwords);
    }

    #[test]
    fn owners_and_admins_invite_below_themselves_and_nobody_invites_an_owner() {
        let f = Fixture::new();
        let target = UserId::random();
        for role in [SpaceRole::Admin, SpaceRole::Member] {
            assert_eq!(
                f.state.authorize_invite(f.owner, target, role, NONE),
                Ok(())
            );
        }
        assert_eq!(
            f.state.authorize_invite(
                f.owner,
                target,
                SpaceRole::Custom,
                CustomPermissions::MANAGE_GROUPS
            ),
            Ok(())
        );
        assert_eq!(
            f.state
                .authorize_invite(f.admin, target, SpaceRole::Admin, NONE),
            Ok(())
        );
        for actor in [f.owner, f.admin] {
            assert!(matches!(
                f.state
                    .authorize_invite(actor, target, SpaceRole::Owner, NONE),
                Err(SpaceError::Forbidden(_))
            ));
        }
    }

    #[test]
    fn a_custom_member_with_manage_users_invites_only_members_and_lesser_custom_members() {
        let f = Fixture::new();
        let target = UserId::random();
        assert_eq!(
            f.state
                .authorize_invite(f.custom, target, SpaceRole::Member, NONE),
            Ok(())
        );
        assert_eq!(
            f.state.authorize_invite(
                f.custom,
                target,
                SpaceRole::Custom,
                CustomPermissions::MANAGE_USERS
            ),
            Ok(())
        );
        assert!(matches!(
            f.state.authorize_invite(
                f.custom,
                target,
                SpaceRole::Custom,
                CustomPermissions::MANAGE_GROUPS
            ),
            Err(SpaceError::Forbidden(_))
        ));
        assert!(matches!(
            f.state
                .authorize_invite(f.custom, target, SpaceRole::Admin, NONE),
            Err(SpaceError::Forbidden(_))
        ));
    }

    #[test]
    fn a_member_an_outsider_and_a_repeat_invitation_are_refused() {
        let f = Fixture::new();
        let target = UserId::random();
        assert!(matches!(
            f.state
                .authorize_invite(f.member, target, SpaceRole::Member, NONE),
            Err(SpaceError::Forbidden(_))
        ));
        assert_eq!(
            f.state
                .authorize_invite(UserId::random(), target, SpaceRole::Member, NONE),
            Err(SpaceError::NotAMember)
        );
        // Someone who only accepted holds no keys and has no say.
        assert_eq!(
            f.state
                .authorize_invite(f.accepted, target, SpaceRole::Member, NONE),
            Err(SpaceError::NotAMember)
        );
        assert!(matches!(
            f.state
                .authorize_invite(f.owner, f.accepted, SpaceRole::Member, NONE),
            Err(SpaceError::State(_))
        ));
        assert!(matches!(
            f.state.authorize_invite(
                f.owner,
                target,
                SpaceRole::Member,
                CustomPermissions::MANAGE_USERS
            ),
            Err(SpaceError::Invalid(_))
        ));
    }

    #[test]
    fn confirming_needs_the_fingerprint_the_confirmer_compared() {
        let f = Fixture::new();
        let fingerprint = [5u8; FINGERPRINT_LEN];
        let confirmed = f
            .state
            .authorize_confirm(f.owner, f.accepted, &fingerprint, &fingerprint)
            .map(|m| m.user);
        assert_eq!(confirmed, Ok(f.accepted));
        for submitted in [vec![6u8; FINGERPRINT_LEN], vec![5u8; 10], Vec::new()] {
            assert_eq!(
                f.state
                    .authorize_confirm(f.owner, f.accepted, &submitted, &fingerprint)
                    .err(),
                Some(SpaceError::FingerprintMismatch)
            );
        }
    }

    #[test]
    fn confirming_is_for_accepted_members_by_someone_who_manages_them() {
        let f = Fixture::new();
        let fp = [5u8; FINGERPRINT_LEN];
        // A member who is already confirmed may be confirmed again, by someone who manages them
        // as of now; a member who is only invited or revoked can't be, and a member can't confirm.
        assert!(
            f.state
                .authorize_confirm(f.owner, f.member, &fp, &fp)
                .is_ok()
        );
        assert!(matches!(
            f.state.authorize_confirm(f.member, f.admin, &fp, &fp).err(),
            Some(SpaceError::Forbidden(_))
        ));
        assert!(matches!(
            f.state.authorize_confirm(f.admin, f.owner, &fp, &fp).err(),
            Some(SpaceError::Forbidden(_))
        ));
        let mut revoked = Fixture::new();
        revoked.set_state(revoked.member, MemberState::Revoked);
        assert!(matches!(
            revoked
                .state
                .authorize_confirm(revoked.owner, revoked.member, &fp, &fp)
                .err(),
            Some(SpaceError::State(_))
        ));
        assert!(matches!(
            f.state
                .authorize_confirm(f.member, f.accepted, &fp, &fp)
                .err(),
            Some(SpaceError::Forbidden(_))
        ));
        assert!(matches!(
            f.state.authorize_confirm(f.owner, f.owner, &fp, &fp).err(),
            Some(SpaceError::Forbidden(_))
        ));
        // A Custom member with Manage users may confirm a member.
        assert!(
            f.state
                .authorize_confirm(f.custom, f.accepted, &fp, &fp)
                .is_ok()
        );
        // An admin can't confirm an owner who somehow accepted; only an owner manages owners.
        let mut f = Fixture::new();
        f.set_role(f.accepted, SpaceRole::Owner);
        assert!(matches!(
            f.state
                .authorize_confirm(f.admin, f.accepted, &fp, &fp)
                .err(),
            Some(SpaceError::Forbidden(_))
        ));
    }

    #[test]
    fn confirming_waits_while_the_space_keys_await_replacement() {
        let mut f = Fixture::new();
        f.state.space.keys_pending_since = Some(NOW);
        let fp = [5u8; FINGERPRINT_LEN];
        assert_eq!(
            f.state
                .authorize_confirm(f.owner, f.accepted, &fp, &fp)
                .err(),
            Some(SpaceError::KeysPending)
        );
    }

    #[test]
    fn only_an_owner_makes_an_owner_and_the_new_owner_must_be_confirmed() {
        let f = Fixture::new();
        assert_eq!(
            f.state
                .authorize_role_change(f.owner, f.member, SpaceRole::Owner, NONE)
                .map(|m| m.user),
            Ok(f.member)
        );
        for actor in [f.admin, f.custom, f.member] {
            assert!(
                f.state
                    .authorize_role_change(actor, f.member, SpaceRole::Owner, NONE)
                    .is_err()
            );
        }
        assert_eq!(
            f.state
                .authorize_role_change(f.admin, f.member, SpaceRole::Owner, NONE)
                .err(),
            Some(SpaceError::Forbidden("only an owner makes an owner"))
        );
        // Accepted but unconfirmed: the server can't hand out the space key.
        assert!(matches!(
            f.state
                .authorize_role_change(f.owner, f.accepted, SpaceRole::Owner, NONE)
                .err(),
            Some(SpaceError::State(_))
        ));
    }

    #[test]
    fn an_admin_changes_roles_below_owner_and_never_touches_an_owner() {
        let f = Fixture::new();
        assert!(
            f.state
                .authorize_role_change(f.admin, f.member, SpaceRole::Admin, NONE)
                .is_ok()
        );
        assert!(
            f.state
                .authorize_role_change(f.admin, f.custom, SpaceRole::Member, NONE)
                .is_ok()
        );
        assert!(matches!(
            f.state
                .authorize_role_change(f.admin, f.owner, SpaceRole::Member, NONE)
                .err(),
            Some(SpaceError::Forbidden(_))
        ));
        assert!(matches!(
            f.state
                .authorize_role_change(f.custom, f.member, SpaceRole::Admin, NONE)
                .err(),
            Some(SpaceError::Forbidden(_))
        ));
    }

    #[test]
    fn the_last_confirmed_owner_can_not_be_demoted_removed_or_revoked() {
        let mut f = Fixture::new();
        assert_eq!(
            f.state
                .authorize_role_change(f.owner, f.owner, SpaceRole::Admin, NONE)
                .err(),
            Some(SpaceError::LastOwner)
        );
        assert_eq!(
            f.state.authorize_remove(f.owner, f.owner).err(),
            Some(SpaceError::LastOwner)
        );
        // With a second owner, the first may step down, leave or be revoked.
        f.set_role(f.admin, SpaceRole::Owner);
        assert!(
            f.state
                .authorize_role_change(f.owner, f.owner, SpaceRole::Admin, NONE)
                .is_ok()
        );
        assert!(f.state.authorize_remove(f.owner, f.owner).is_ok());
        assert!(f.state.authorize_revoke(f.admin, f.owner).is_ok());
    }

    #[test]
    fn revoking_is_for_confirmed_members_below_the_actor_and_never_oneself() {
        let f = Fixture::new();
        assert!(f.state.authorize_revoke(f.admin, f.member).is_ok());
        assert!(f.state.authorize_revoke(f.custom, f.member).is_ok());
        assert!(matches!(
            f.state.authorize_revoke(f.admin, f.owner).err(),
            Some(SpaceError::Forbidden(_))
        ));
        assert!(matches!(
            f.state.authorize_revoke(f.owner, f.owner).err(),
            Some(SpaceError::Forbidden(_))
        ));
        assert!(matches!(
            f.state.authorize_revoke(f.owner, f.accepted).err(),
            Some(SpaceError::State(_))
        ));
        assert!(matches!(
            f.state.authorize_revoke(f.member, f.custom).err(),
            Some(SpaceError::Forbidden(_))
        ));
    }

    #[test]
    fn restoring_needs_a_revoked_member() {
        let mut f = Fixture::new();
        assert!(matches!(
            f.state.authorize_restore(f.owner, f.member).err(),
            Some(SpaceError::State(_))
        ));
        f.set_state(f.member, MemberState::Revoked);
        assert!(f.state.authorize_restore(f.owner, f.member).is_ok());
        assert!(matches!(
            f.state
                .authorize_role_change(f.owner, f.member, SpaceRole::Admin, NONE)
                .err(),
            Some(SpaceError::State(_))
        ));
    }

    #[test]
    fn anyone_may_leave_in_any_state_but_only_a_manager_removes_others() {
        let f = Fixture::new();
        assert!(f.state.authorize_remove(f.accepted, f.accepted).is_ok());
        assert!(f.state.authorize_remove(f.member, f.member).is_ok());
        assert!(f.state.authorize_remove(f.admin, f.member).is_ok());
        assert!(matches!(
            f.state.authorize_remove(f.member, f.custom).err(),
            Some(SpaceError::Forbidden(_))
        ));
        assert!(matches!(
            f.state.authorize_remove(f.admin, f.owner).err(),
            Some(SpaceError::Forbidden(_))
        ));
        assert!(matches!(
            f.state.authorize_remove(f.owner, UserId::random()).err(),
            Some(SpaceError::State(_))
        ));
    }

    #[test]
    fn access_comes_from_grants_directly_or_through_a_group() {
        let mut f = Fixture::new();
        assert_eq!(
            f.state.access(f.member, f.finance).map(|a| a.edit),
            Some(true)
        );
        assert_eq!(
            f.state.access(f.admin, f.finance),
            None,
            "no implicit access"
        );
        assert_eq!(
            f.state.access(f.owner, f.finance),
            None,
            "no implicit access"
        );

        let group = Group {
            id: GroupId::random(),
            space: f.state.space.id,
            name: vec![3; 40],
            members: BTreeSet::from([f.admin]),
            created_at: NOW,
        };
        f.state.grants.push(CollectionGrant {
            collection: f.finance,
            grantee: Grantee::Group(group.id),
            permission: CollectionPermission::Manage,
        });
        f.state.groups.push(group);
        assert_eq!(
            f.state.access(f.admin, f.finance).map(|a| a.manage),
            Some(true)
        );
        assert_eq!(f.state.access(f.custom, f.finance), None);
        assert_eq!(
            f.state.recipients(f.finance),
            BTreeSet::from([f.member, f.admin])
        );
        assert_eq!(f.state.collections_of(f.admin), BTreeSet::from([f.finance]));
    }

    #[test]
    fn only_confirmed_members_are_recipients_of_a_key() {
        let mut f = Fixture::new();
        f.state.grants.push(CollectionGrant {
            collection: f.finance,
            grantee: Grantee::Member(f.accepted),
            permission: CollectionPermission::View,
        });
        assert_eq!(f.state.recipients(f.finance), BTreeSet::from([f.member]));
        assert!(f.state.collections_of(f.accepted).contains(&f.finance));
    }

    #[test]
    fn the_key_delta_names_copies_to_seal_and_copies_to_distrust() {
        let mut f = Fixture::new();
        // Nobody holds a copy yet: the one grantee needs one.
        let delta = f.state.key_delta(&[]);
        assert_eq!(delta.needed, BTreeSet::from([(f.finance, f.member)]));
        assert!(delta.lost.is_empty());
        // Someone who holds a copy but has no grant has lost access.
        let delta = f
            .state
            .key_delta(&[(f.finance, f.member), (f.finance, f.admin)]);
        assert!(delta.needed.is_empty());
        assert_eq!(delta.lost, BTreeSet::from([(f.finance, f.admin)]));
        assert_eq!(delta.stale_collections(), BTreeSet::from([f.finance]));
        // A revoked member is no recipient, so their copy is lost.
        f.set_state(f.member, MemberState::Revoked);
        let delta = f.state.key_delta(&[(f.finance, f.member)]);
        assert_eq!(delta.lost, BTreeSet::from([(f.finance, f.member)]));
        // A copy of a collection that no longer exists is not a loss to report.
        let gone = CollectionId::random();
        assert!(f.state.key_delta(&[(gone, f.member)]).lost.is_empty());
    }

    #[test]
    fn an_item_write_needs_edit_on_the_collection_under_its_current_key() {
        let f = Fixture::new();
        assert!(
            f.state
                .authorize_item_write(f.member, f.finance, Some(1))
                .is_ok()
        );
        // A delete seals nothing, so it has no key version to check.
        assert!(
            f.state
                .authorize_item_write(f.member, f.finance, None)
                .is_ok()
        );
        assert_eq!(
            f.state
                .authorize_item_write(f.member, f.finance, Some(2))
                .err(),
            Some(SpaceError::StaleKeyVersion { current: 1 })
        );
        // No grant: owners and admins have no implicit access to items.
        for actor in [f.owner, f.admin, f.custom] {
            assert!(matches!(
                f.state
                    .authorize_item_write(actor, f.finance, Some(1))
                    .err(),
                Some(SpaceError::Forbidden(_))
            ));
        }
        assert_eq!(
            f.state
                .authorize_item_write(f.accepted, f.finance, Some(1))
                .err(),
            Some(SpaceError::NotAMember)
        );
        assert!(matches!(
            f.state
                .authorize_item_write(f.member, CollectionId::random(), Some(1))
                .err(),
            Some(SpaceError::Invalid(_))
        ));
    }

    #[test]
    fn a_view_grant_does_not_write() {
        let mut f = Fixture::new();
        f.state.grants[0].permission = CollectionPermission::ViewHidePasswords;
        assert!(matches!(
            f.state
                .authorize_item_write(f.member, f.finance, Some(1))
                .err(),
            Some(SpaceError::Forbidden(_))
        ));
    }

    #[test]
    fn writes_pause_for_the_space_or_for_one_collection() {
        let mut f = Fixture::new();
        f.state.collections[0].stale_since = Some(NOW);
        assert_eq!(
            f.state
                .authorize_item_write(f.member, f.finance, Some(1))
                .err(),
            Some(SpaceError::KeysPending)
        );
        assert_eq!(
            f.state.replacement_plan(),
            Some(ReplacementPlan {
                space_key: false,
                collections: BTreeSet::from([f.finance])
            })
        );
        f.state.collections[0].stale_since = None;
        assert_eq!(f.state.replacement_plan(), None);
        f.state.space.keys_pending_since = Some(NOW);
        assert_eq!(
            f.state
                .authorize_item_write(f.member, f.finance, None)
                .err(),
            Some(SpaceError::KeysPending)
        );
        assert_eq!(
            f.state.replacement_plan(),
            Some(ReplacementPlan {
                space_key: true,
                collections: BTreeSet::new()
            })
        );
    }

    #[test]
    fn collections_nest_without_cycles_or_foreign_parents() {
        let mut f = Fixture::new();
        let space = f.state.space.id;
        let child = collection(space, Some(f.finance));
        let child_id = child.id;
        f.state.collections.push(child);

        let new_id = CollectionId::random();
        assert_eq!(f.state.check_parent(new_id, None), Ok(()));
        assert_eq!(f.state.check_parent(new_id, Some(child_id)), Ok(()));
        // Moving the root under its own child would close a loop.
        assert!(f.state.check_parent(f.finance, Some(child_id)).is_err());
        assert!(f.state.check_parent(f.finance, Some(f.finance)).is_err());
        assert!(
            f.state
                .check_parent(new_id, Some(CollectionId::random()))
                .is_err()
        );

        // A chain deeper than the limit is refused.
        let mut parent = f.finance;
        for _ in 0..MAX_COLLECTION_DEPTH {
            let next = collection(space, Some(parent));
            parent = next.id;
            f.state.collections.push(next);
        }
        assert!(f.state.check_parent(new_id, Some(parent)).is_err());
    }

    #[test]
    fn groups_and_collections_are_managed_by_role_or_permission() {
        let f = Fixture::new();
        assert!(f.state.authorize_create_collection(f.owner).is_ok());
        assert!(f.state.authorize_create_collection(f.admin).is_ok());
        assert!(f.state.authorize_create_collection(f.custom).is_err());
        assert!(f.state.authorize_manage_groups(f.admin).is_ok());
        assert!(f.state.authorize_manage_groups(f.member).is_err());

        let mut f = Fixture::new();
        for m in &mut f.state.members {
            if m.user == f.custom {
                m.custom =
                    CustomPermissions::CREATE_COLLECTIONS.union(CustomPermissions::MANAGE_GROUPS);
            }
        }
        assert!(f.state.authorize_create_collection(f.custom).is_ok());
        assert!(f.state.authorize_manage_groups(f.custom).is_ok());
    }

    #[test]
    fn a_grant_needs_a_role_that_manages_or_the_manage_permission() {
        let mut f = Fixture::new();
        assert!(
            f.state
                .authorize_manage_collection(f.owner, f.finance)
                .is_ok()
        );
        assert!(
            f.state
                .authorize_manage_collection(f.admin, f.finance)
                .is_ok()
        );
        // Edit isn't Manage.
        assert!(matches!(
            f.state
                .authorize_manage_collection(f.member, f.finance)
                .err(),
            Some(SpaceError::Forbidden(_))
        ));
        f.state.grants[0].permission = CollectionPermission::Manage;
        assert!(
            f.state
                .authorize_manage_collection(f.member, f.finance)
                .is_ok()
        );
        // Manage on one collection is no power over another.
        let other = collection(f.state.space.id, None);
        let other_id = other.id;
        f.state.collections.push(other);
        assert!(matches!(
            f.state
                .authorize_manage_collection(f.member, other_id)
                .err(),
            Some(SpaceError::Forbidden(_))
        ));
    }

    #[test]
    fn sealed_values_are_checked_for_shape() {
        assert_eq!(check_sealed_key(&[1; SEALED_KEY_LEN]), Ok(()));
        assert!(check_sealed_key(&[1; SEALED_KEY_LEN - 1]).is_err());
        assert!(check_sealed_key(&[2; SEALED_KEY_LEN]).is_err());
        assert_eq!(check_sealed_name(&[0; 28]), Ok(()));
        assert!(check_sealed_name(&[0; 27]).is_err());
        assert!(check_sealed_name(&vec![0; MAX_NAME_LEN + 1]).is_err());
        let signature = vec![0; CONFIRMATION_SIGNATURE_LEN];
        assert_eq!(check_confirmation_parts(b"statement", &signature), Ok(()));
        assert!(check_confirmation_parts(b"", &signature).is_err());
        assert!(check_confirmation_parts(b"statement", &signature[1..]).is_err());
        assert!(check_confirmation_parts(&vec![0; MAX_STATEMENT_LEN + 1], &signature).is_err());
    }

    fn space_write(owner: Owner, expected: Option<u64>, revision: u64) -> ItemWrite {
        ItemWrite {
            id: ItemId::random(),
            owner,
            kind: ItemKind::try_from("login".to_owned()).expect("valid kind"),
            format: ItemFormat::Kem1,
            expected: expected.map(Revision),
            revision: Revision(revision),
            key_version: 1,
            sealed: Some(Sealed {
                ciphertext: vec![7; 64],
                item_key: vec![1; ITEM_KEY_LEN],
            }),
        }
    }

    fn stored_like(write: &ItemWrite, revision: u64) -> Item {
        Item {
            id: write.id,
            owner: write.owner,
            kind: write.kind.clone(),
            format: write.format,
            revision: Revision(revision),
            key_version: 1,
            ciphertext: Some(vec![0; 64]),
            item_key: Some(vec![0; ITEM_KEY_LEN]),
            deleted_at: None,
            updated_at: NOW,
            change: ChangeId {
                origin: ServerId::random(),
                seq: 1,
                hlc: Hlc::default(),
            },
        }
    }

    #[test]
    fn a_space_write_keeps_the_space_as_owner() {
        let actor = UserId::random();
        let owner = Owner::Space(SpaceId::random());
        let draft = apply_space_write(
            space_write(owner, None, 1),
            None,
            actor,
            ItemLimits::default(),
            NOW,
        )
        .expect("a new item applies");
        assert_eq!(draft.owner, owner);
        assert_eq!(draft.revision, Revision(1));

        let next = space_write(owner, Some(1), 2);
        let stored = stored_like(&next, 1);
        let draft = apply_space_write(next, Some(&stored), actor, ItemLimits::default(), NOW)
            .expect("the next revision applies");
        assert_eq!(draft.owner, owner);
        assert_eq!(draft.revision, Revision(2));
    }

    #[test]
    fn a_space_write_still_keeps_the_revision_and_owner_rules() {
        let actor = UserId::random();
        let owner = Owner::Space(SpaceId::random());
        // Not a space owner: this is the vault path's business.
        assert_eq!(
            apply_space_write(
                space_write(Owner::User(actor), None, 1),
                None,
                actor,
                ItemLimits::default(),
                NOW
            ),
            Err(ItemError::Forbidden)
        );
        // A skipped revision, a stale write and a move to another space.
        assert_eq!(
            apply_space_write(
                space_write(owner, None, 2),
                None,
                actor,
                ItemLimits::default(),
                NOW
            ),
            Err(ItemError::BadRevision { got: Revision(2) })
        );
        let stale = space_write(owner, Some(1), 2);
        let stored = stored_like(&stale, 3);
        assert!(matches!(
            apply_space_write(stale, Some(&stored), actor, ItemLimits::default(), NOW),
            Err(ItemError::Stale { .. })
        ));
        let stored = stored_like(&space_write(owner, None, 1), 1);
        let moved = ItemWrite {
            id: stored.id,
            ..space_write(Owner::Space(SpaceId::random()), Some(1), 2)
        };
        assert_eq!(
            apply_space_write(moved, Some(&stored), actor, ItemLimits::default(), NOW),
            Err(ItemError::Immutable)
        );
    }
}
