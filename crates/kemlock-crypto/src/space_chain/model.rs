//! The vocabulary of a space chain: ids, roles, permissions, key references, commitments and the
//! record with its 21 kinds of body (docs/crypto.md, "Space chain").

use std::fmt;

/// An account, space, collection or group id: a UUID's 16 bytes.
pub type Id = [u8; 16];
/// A 32-byte hash.
pub type Hash = [u8; 32];

/// A UUID as its hyphenated lower-case text.
pub fn uuid_text(id: &Id) -> String {
    let h =
        |a: usize, b: usize| -> String { id[a..b].iter().map(|x| format!("{x:02x}")).collect() };
    format!(
        "{}-{}-{}-{}-{}",
        h(0, 4),
        h(4, 6),
        h(6, 8),
        h(8, 10),
        h(10, 16)
    )
}

/// Parses a hyphenated lower-case UUID. The version and variant bits aren't looked at.
pub fn parse_uuid(text: &str) -> Option<Id> {
    let b = text.as_bytes();
    if b.len() != 36 {
        return None;
    }
    let mut out = [0u8; 16];
    let mut n = 0usize;
    let mut i = 0usize;
    while i < 36 {
        if matches!(i, 8 | 13 | 18 | 23) {
            if b[i] != b'-' {
                return None;
            }
            i += 1;
            continue;
        }
        let hi = hex_digit(b[i])?;
        let lo = hex_digit(*b.get(i + 1)?)?;
        *out.get_mut(n)? = (hi << 4) | lo;
        n += 1;
        i += 2;
    }
    (n == 16).then_some(out)
}

fn hex_digit(c: u8) -> Option<u8> {
    match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        _ => None,
    }
}

/// Why a record or a chain is refused, in the order the checks run ("Verification").
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Reason {
    /// A shape the format refuses whatever the state.
    Malformed,
    /// Beyond a size limit.
    TooLarge,
    WrongSpace,
    BadSequence,
    BadLink,
    BadEpoch,
    UnknownSigner,
    BadSignature,
    BadBundle,
    BadConfirmation,
    /// A record that makes no sense in the state it meets.
    Invalid,
    NotAllowed,
    Forked,
    RolledBack,
}

impl Reason {
    /// The name the spec and the vectors use.
    pub fn as_str(self) -> &'static str {
        match self {
            Reason::Malformed => "malformed",
            Reason::TooLarge => "too large",
            Reason::WrongSpace => "wrong space",
            Reason::BadSequence => "bad sequence",
            Reason::BadLink => "bad link",
            Reason::BadEpoch => "bad epoch",
            Reason::UnknownSigner => "unknown signer",
            Reason::BadSignature => "bad signature",
            Reason::BadBundle => "bad bundle",
            Reason::BadConfirmation => "bad confirmation",
            Reason::Invalid => "invalid",
            Reason::NotAllowed => "not allowed",
            Reason::Forked => "forked",
            Reason::RolledBack => "rolled back",
        }
    }

    pub fn parse(name: &str) -> Option<Reason> {
        [
            Reason::Malformed,
            Reason::TooLarge,
            Reason::WrongSpace,
            Reason::BadSequence,
            Reason::BadLink,
            Reason::BadEpoch,
            Reason::UnknownSigner,
            Reason::BadSignature,
            Reason::BadBundle,
            Reason::BadConfirmation,
            Reason::Invalid,
            Reason::NotAllowed,
            Reason::Forked,
            Reason::RolledBack,
        ]
        .into_iter()
        .find(|r| r.as_str() == name)
    }
}

impl fmt::Display for Reason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// A refusal: the `seq` of the record (or its position in the array when it couldn't be read) and
/// the reason.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ChainError {
    pub seq: Option<u64>,
    pub reason: Reason,
}

impl fmt::Display for ChainError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.seq {
            Some(seq) => write!(f, "record {seq}: {}", self.reason),
            None => write!(f, "{}", self.reason),
        }
    }
}

impl std::error::Error for ChainError {}

/// A role. The order is the rank: `Owner` is the highest.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Role {
    Member,
    Custom,
    Admin,
    Owner,
}

impl Role {
    pub fn as_str(self) -> &'static str {
        match self {
            Role::Owner => "owner",
            Role::Admin => "admin",
            Role::Custom => "custom",
            Role::Member => "member",
        }
    }

    pub fn parse(text: &str) -> Option<Role> {
        match text {
            "owner" => Some(Role::Owner),
            "admin" => Some(Role::Admin),
            "custom" => Some(Role::Custom),
            "member" => Some(Role::Member),
            _ => None,
        }
    }
}

/// A custom permission. The order is the byte order of the names.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum CustomPerm {
    CreateCollections,
    ManageGroups,
    ManageUsers,
}

impl CustomPerm {
    pub fn as_str(self) -> &'static str {
        match self {
            CustomPerm::CreateCollections => "create-collections",
            CustomPerm::ManageGroups => "manage-groups",
            CustomPerm::ManageUsers => "manage-users",
        }
    }

    pub fn parse(text: &str) -> Option<CustomPerm> {
        match text {
            "create-collections" => Some(CustomPerm::CreateCollections),
            "manage-groups" => Some(CustomPerm::ManageGroups),
            "manage-users" => Some(CustomPerm::ManageUsers),
            _ => None,
        }
    }
}

/// What a member may do in a collection.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Rights {
    pub edit: bool,
    pub hide_passwords: bool,
    pub manage: bool,
}

impl Rights {
    /// `edit` and `manage` if either gives them, `hide_passwords` only if both hide.
    pub fn combine(self, other: Rights) -> Rights {
        Rights {
            edit: self.edit || other.edit,
            hide_passwords: self.hide_passwords && other.hide_passwords,
            manage: self.manage || other.manage,
        }
    }

    /// Whether `to` gives a right `from` doesn't: `edit` or `manage`, or no more hiding of
    /// passwords, or any access where there was none.
    pub fn widens(from: Option<Rights>, to: Option<Rights>) -> bool {
        match (from, to) {
            (_, None) => false,
            (None, Some(_)) => true,
            (Some(a), Some(b)) => {
                (b.edit && !a.edit)
                    || (b.manage && !a.manage)
                    || (a.hide_passwords && !b.hide_passwords)
            }
        }
    }
}

/// A collection permission.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum CollectionPerm {
    View,
    ViewHidePasswords,
    Edit,
    EditHidePasswords,
    Manage,
}

impl CollectionPerm {
    pub fn as_str(self) -> &'static str {
        match self {
            CollectionPerm::View => "view",
            CollectionPerm::ViewHidePasswords => "view-hide-passwords",
            CollectionPerm::Edit => "edit",
            CollectionPerm::EditHidePasswords => "edit-hide-passwords",
            CollectionPerm::Manage => "manage",
        }
    }

    pub fn parse(text: &str) -> Option<CollectionPerm> {
        match text {
            "view" => Some(CollectionPerm::View),
            "view-hide-passwords" => Some(CollectionPerm::ViewHidePasswords),
            "edit" => Some(CollectionPerm::Edit),
            "edit-hide-passwords" => Some(CollectionPerm::EditHidePasswords),
            "manage" => Some(CollectionPerm::Manage),
            _ => None,
        }
    }

    pub fn rights(self) -> Rights {
        let (edit, hide_passwords, manage) = match self {
            CollectionPerm::View => (false, false, false),
            CollectionPerm::ViewHidePasswords => (false, true, false),
            CollectionPerm::Edit => (true, false, false),
            CollectionPerm::EditHidePasswords => (true, true, false),
            CollectionPerm::Manage => (true, false, true),
        };
        Rights {
            edit,
            hide_passwords,
            manage,
        }
    }
}

/// Who a grant is to. The order is the byte order of the text (`group:` before `user:`).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Grantee {
    Group(Id),
    User(Id),
}

impl Grantee {
    pub fn text(&self) -> String {
        match self {
            Grantee::Group(id) => format!("group:{}", uuid_text(id)),
            Grantee::User(id) => format!("user:{}", uuid_text(id)),
        }
    }

    pub fn parse(text: &str) -> Option<Grantee> {
        if let Some(rest) = text.strip_prefix("user:") {
            return parse_uuid(rest).map(Grantee::User);
        }
        text.strip_prefix("group:")
            .and_then(parse_uuid)
            .map(Grantee::Group)
    }
}

/// A key: the space key or one collection's key. The order is the byte order of the text
/// (`collection:` before `space`).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum KeyRef {
    Collection(Id),
    Space,
}

impl KeyRef {
    pub fn text(&self) -> String {
        match self {
            KeyRef::Collection(id) => format!("collection:{}", uuid_text(id)),
            KeyRef::Space => "space".to_owned(),
        }
    }

    pub fn parse(text: &str) -> Option<KeyRef> {
        if text == "space" {
            return Some(KeyRef::Space);
        }
        text.strip_prefix("collection:")
            .and_then(parse_uuid)
            .map(KeyRef::Collection)
    }

    /// The binary form inside digests: `u8(1)` or `u8(2) ‖ collection id`.
    pub fn bytes(&self) -> Vec<u8> {
        match self {
            KeyRef::Space => vec![1],
            KeyRef::Collection(id) => {
                let mut out = vec![2];
                out.extend_from_slice(id);
                out
            }
        }
    }
}

/// What a name belongs to. The order is the byte order of the text.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum NameTarget {
    Collection(Id),
    Group(Id),
    Space,
}

impl NameTarget {
    pub fn text(&self) -> String {
        match self {
            NameTarget::Collection(id) => format!("collection:{}", uuid_text(id)),
            NameTarget::Group(id) => format!("group:{}", uuid_text(id)),
            NameTarget::Space => "space".to_owned(),
        }
    }

    pub fn parse(text: &str) -> Option<NameTarget> {
        if text == "space" {
            return Some(NameTarget::Space);
        }
        if let Some(rest) = text.strip_prefix("collection:") {
            return parse_uuid(rest).map(NameTarget::Collection);
        }
        text.strip_prefix("group:")
            .and_then(parse_uuid)
            .map(NameTarget::Group)
    }
}

/// A commitment to the seals of one key version ("Seal commitments").
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Commitment {
    pub key: KeyRef,
    pub version: u32,
    pub count: u32,
    pub digest: Hash,
    /// Present exactly when the commitment makes the key version.
    pub check: Option<Hash>,
}

/// The master-password policy.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct MasterPasswordPolicy {
    pub enforce_on_login: bool,
    pub min_complexity: u8,
    pub min_length: u8,
    pub require_lower: bool,
    pub require_numbers: bool,
    pub require_special: bool,
    pub require_upper: bool,
}

/// What a session timeout does.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum TimeoutAction {
    #[default]
    None,
    Lock,
    LogOut,
}

impl TimeoutAction {
    pub fn as_str(self) -> &'static str {
        match self {
            TimeoutAction::None => "none",
            TimeoutAction::Lock => "lock",
            TimeoutAction::LogOut => "log-out",
        }
    }

    pub fn parse(text: &str) -> Option<TimeoutAction> {
        match text {
            "none" => Some(TimeoutAction::None),
            "lock" => Some(TimeoutAction::Lock),
            "log-out" => Some(TimeoutAction::LogOut),
            _ => None,
        }
    }
}

/// The session timeout policy.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct SessionTimeoutPolicy {
    pub action: TimeoutAction,
    pub minutes: u32,
}

/// The policy set of a space: the closed list of settings the `policies` record sets.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Policies {
    pub account_recovery: bool,
    pub always_show_email: bool,
    pub central_ownership: bool,
    pub disable_export: bool,
    pub disable_send: bool,
    pub duplicate_matching: bool,
    pub master_password: MasterPasswordPolicy,
    pub no_card_items: bool,
    pub no_pin_unlock: bool,
    pub require_sso: bool,
    pub session_timeout: SessionTimeoutPolicy,
    pub single_space: bool,
    pub two_step: bool,
}

/// The 21 kinds of record.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Kind {
    Create,
    Invite,
    Confirm,
    Rekey,
    Role,
    Remove,
    Grant,
    Ungrant,
    Collection,
    Move,
    CollectionDelete,
    Group,
    GroupMembers,
    GroupDelete,
    Rename,
    Seal,
    Keys,
    Policies,
    RecoveryKey,
    RecoveryKeyClear,
    Fence,
}

impl Kind {
    /// Every kind, in the spec's order.
    pub const ALL: [Kind; 21] = [
        Kind::Create,
        Kind::Invite,
        Kind::Confirm,
        Kind::Rekey,
        Kind::Role,
        Kind::Remove,
        Kind::Grant,
        Kind::Ungrant,
        Kind::Collection,
        Kind::Move,
        Kind::CollectionDelete,
        Kind::Group,
        Kind::GroupMembers,
        Kind::GroupDelete,
        Kind::Rename,
        Kind::Seal,
        Kind::Keys,
        Kind::Policies,
        Kind::RecoveryKey,
        Kind::RecoveryKeyClear,
        Kind::Fence,
    ];

    pub fn as_str(self) -> &'static str {
        match self {
            Kind::Create => "create",
            Kind::Invite => "invite",
            Kind::Confirm => "confirm",
            Kind::Rekey => "rekey",
            Kind::Role => "role",
            Kind::Remove => "remove",
            Kind::Grant => "grant",
            Kind::Ungrant => "ungrant",
            Kind::Collection => "collection",
            Kind::Move => "move",
            Kind::CollectionDelete => "collection-delete",
            Kind::Group => "group",
            Kind::GroupMembers => "group-members",
            Kind::GroupDelete => "group-delete",
            Kind::Rename => "rename",
            Kind::Seal => "seal",
            Kind::Keys => "keys",
            Kind::Policies => "policies",
            Kind::RecoveryKey => "recovery-key",
            Kind::RecoveryKeyClear => "recovery-key-clear",
            Kind::Fence => "fence",
        }
    }

    pub fn parse(text: &str) -> Option<Kind> {
        Kind::ALL.into_iter().find(|k| k.as_str() == text)
    }
}

/// What a record sets. Each variant lists exactly the members its kind has; arrays are held in
/// the order they are written, and a record whose arrays aren't strictly ascending is refused
/// when it is read.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Body {
    Create {
        bundle: Vec<u8>,
        bundle_signature: Vec<u8>,
        collection: Id,
        collection_name: Hash,
        member: Id,
        name_hash: Hash,
        seals: Vec<Commitment>,
    },
    Invite {
        custom: Vec<CustomPerm>,
        grants: Vec<(Id, CollectionPerm)>,
        member: Id,
        role: Role,
    },
    Confirm {
        bundle: Vec<u8>,
        bundle_signature: Vec<u8>,
        member: Id,
        statement: Vec<u8>,
        statement_signature: Vec<u8>,
    },
    Rekey {
        bundle: Vec<u8>,
        bundle_signature: Vec<u8>,
    },
    Role {
        custom: Vec<CustomPerm>,
        member: Id,
        role: Role,
    },
    Remove {
        member: Id,
        replace: Vec<KeyRef>,
    },
    Grant {
        collection: Id,
        grantee: Grantee,
        permission: CollectionPerm,
    },
    Ungrant {
        collection: Id,
        grantee: Grantee,
        replace: Vec<KeyRef>,
    },
    Collection {
        collection: Id,
        grants: Vec<(Grantee, CollectionPerm)>,
        name_hash: Hash,
        parent: Option<Id>,
        seals: Vec<Commitment>,
    },
    Move {
        collection: Id,
        parent: Option<Id>,
    },
    CollectionDelete {
        collection: Id,
    },
    Group {
        group: Id,
        name_hash: Hash,
    },
    GroupMembers {
        add: Vec<Id>,
        group: Id,
        remove: Vec<Id>,
        replace: Vec<KeyRef>,
    },
    GroupDelete {
        group: Id,
        replace: Vec<KeyRef>,
    },
    Rename {
        name_hash: Hash,
        target: NameTarget,
    },
    Seal {
        seals: Vec<Commitment>,
    },
    Keys {
        names: Option<Vec<u8>>,
        rotate: Vec<Commitment>,
    },
    Policies {
        policies: Policies,
    },
    RecoveryKey {
        key: Vec<u8>,
    },
    RecoveryKeyClear,
    Fence {
        home: Id,
        promotion: Hash,
    },
}

impl Body {
    pub fn kind(&self) -> Kind {
        match self {
            Body::Create { .. } => Kind::Create,
            Body::Invite { .. } => Kind::Invite,
            Body::Confirm { .. } => Kind::Confirm,
            Body::Rekey { .. } => Kind::Rekey,
            Body::Role { .. } => Kind::Role,
            Body::Remove { .. } => Kind::Remove,
            Body::Grant { .. } => Kind::Grant,
            Body::Ungrant { .. } => Kind::Ungrant,
            Body::Collection { .. } => Kind::Collection,
            Body::Move { .. } => Kind::Move,
            Body::CollectionDelete { .. } => Kind::CollectionDelete,
            Body::Group { .. } => Kind::Group,
            Body::GroupMembers { .. } => Kind::GroupMembers,
            Body::GroupDelete { .. } => Kind::GroupDelete,
            Body::Rename { .. } => Kind::Rename,
            Body::Seal { .. } => Kind::Seal,
            Body::Keys { .. } => Kind::Keys,
            Body::Policies { .. } => Kind::Policies,
            Body::RecoveryKey { .. } => Kind::RecoveryKey,
            Body::RecoveryKeyClear => Kind::RecoveryKeyClear,
            Body::Fence { .. } => Kind::Fence,
        }
    }
}

/// A record of the chain, without its signatures.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Record {
    pub space: Id,
    pub seq: u64,
    pub prev: Hash,
    pub epoch: u32,
    pub at: u64,
    pub by: Id,
    pub body: Body,
}

impl Record {
    pub fn kind(&self) -> Kind {
        self.body.kind()
    }
}

/// A signed record as it travels: its exact bytes and its signatures.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SignedRecord {
    /// The record's canonical bytes.
    pub entry: Vec<u8>,
    /// The signer's `sig1` signature over them, 3373 bytes.
    pub signature: Vec<u8>,
    /// A `rekey`'s second signature, by the key of the bundle the record installs.
    pub cosignature: Option<Vec<u8>>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn uuids_round_trip_and_are_strict() {
        let id = parse_uuid("00000000-0000-4000-8000-0000000000f2").expect("a uuid");
        assert_eq!(id[15], 0xf2);
        assert_eq!(uuid_text(&id), "00000000-0000-4000-8000-0000000000f2");
        for bad in [
            "",
            "00000000-0000-4000-8000-0000000000F2",
            "00000000-0000-4000-8000-0000000000f",
            "00000000-0000-4000-8000-0000000000f22",
            "00000000000040008000-0000000000f2",
            "0000000g-0000-4000-8000-0000000000f2",
            "{00000000-0000-4000-8000-0000000000f2}",
        ] {
            assert_eq!(parse_uuid(bad), None, "{bad:?}");
        }
    }

    #[test]
    fn orders_follow_the_byte_order_of_the_text() {
        let a = [1u8; 16];
        let b = [2u8; 16];
        let mut keys = [KeyRef::Space, KeyRef::Collection(b), KeyRef::Collection(a)];
        keys.sort();
        assert_eq!(keys.map(|k| k.text()).to_vec(), {
            let mut texts = keys.map(|k| k.text()).to_vec();
            texts.sort();
            texts
        });
        let mut grantees = [Grantee::User(a), Grantee::Group(b), Grantee::Group(a)];
        grantees.sort();
        let texts: Vec<String> = grantees.iter().map(Grantee::text).collect();
        let mut sorted = texts.clone();
        sorted.sort();
        assert_eq!(texts, sorted);
        let mut perms = [
            CustomPerm::ManageUsers,
            CustomPerm::CreateCollections,
            CustomPerm::ManageGroups,
        ];
        perms.sort();
        let names: Vec<&str> = perms.iter().map(|p| p.as_str()).collect();
        let mut sorted = names.clone();
        sorted.sort_unstable();
        assert_eq!(names, sorted);
    }

    #[test]
    fn names_round_trip() {
        for kind in Kind::ALL {
            assert_eq!(Kind::parse(kind.as_str()), Some(kind));
        }
        assert_eq!(Kind::ALL.len(), 21);
        for role in [Role::Owner, Role::Admin, Role::Custom, Role::Member] {
            assert_eq!(Role::parse(role.as_str()), Some(role));
        }
        for p in [
            CollectionPerm::View,
            CollectionPerm::ViewHidePasswords,
            CollectionPerm::Edit,
            CollectionPerm::EditHidePasswords,
            CollectionPerm::Manage,
        ] {
            assert_eq!(CollectionPerm::parse(p.as_str()), Some(p));
        }
        let id = [9u8; 16];
        assert_eq!(
            KeyRef::parse(&KeyRef::Collection(id).text()),
            Some(KeyRef::Collection(id))
        );
        assert_eq!(
            Grantee::parse(&Grantee::Group(id).text()),
            Some(Grantee::Group(id))
        );
        assert_eq!(
            NameTarget::parse(&NameTarget::Space.text()),
            Some(NameTarget::Space)
        );
        assert_eq!(Reason::parse("bad link"), Some(Reason::BadLink));
        assert_eq!(KeyRef::Space.bytes(), vec![1]);
        assert_eq!(KeyRef::Collection(id).bytes().len(), 17);
    }

    #[test]
    fn permissions_give_the_documented_rights() {
        let r = |p: CollectionPerm| {
            let x = p.rights();
            (x.edit, x.hide_passwords, x.manage)
        };
        assert_eq!(r(CollectionPerm::View), (false, false, false));
        assert_eq!(r(CollectionPerm::ViewHidePasswords), (false, true, false));
        assert_eq!(r(CollectionPerm::Edit), (true, false, false));
        assert_eq!(r(CollectionPerm::EditHidePasswords), (true, true, false));
        assert_eq!(r(CollectionPerm::Manage), (true, false, true));
    }

    #[test]
    fn widening_is_a_new_right_or_less_hiding() {
        let view = Some(CollectionPerm::View.rights());
        let hidden = Some(CollectionPerm::ViewHidePasswords.rights());
        let edit = Some(CollectionPerm::Edit.rights());
        assert!(Rights::widens(None, view));
        assert!(!Rights::widens(view, None));
        assert!(Rights::widens(view, edit));
        assert!(!Rights::widens(edit, view));
        assert!(Rights::widens(hidden, view));
        assert!(!Rights::widens(view, hidden));
        assert!(!Rights::widens(view, view));
        let combined = CollectionPerm::ViewHidePasswords
            .rights()
            .combine(CollectionPerm::Edit.rights());
        assert!(combined.edit && !combined.hide_passwords && !combined.manage);
    }
}
