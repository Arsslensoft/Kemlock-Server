//! A space's roles, policies and keys as home records.
//!
//! A space is a federated vault like any other, and what only its home may change (who is a
//! member and with which role, the groups and collections with their grants, the space key and the
//! collection keys sealed to each member, the policies) travels to the replicas as home records.
//! The home makes one record per entity whenever the entity changed, and a record that says the
//! entity is gone when it was removed; a replica applies the records of the current epoch under the
//! epoch fence, and keeps a stale-epoch one for the vault's admins.
//!
//! Every payload is deterministic CBOR with the entity's id as a byte string under key 1 and the
//! format version under key 0; a record that an entity is gone has only those and key 15.
//!
//! | Kind | Entity (key 1) | Other fields |
//! | --- | --- | --- |
//! | `space` | the space id | 2 name, 3 key version, 4 keys pending since, 5 created, 6 updated |
//! | `space-member` | the user id | 2 role, 3 custom permission bits, 4 state, 5 invited by, 6 invited at, 7 accepted at, 8 sealed space key, 9 its key version, 10 confirmation `{0 by, 1 at, 2 fingerprint, 3 member key version, 4 statement, 5 signature}`, 11 revoked at |
//! | `space-group` | the group id | 2 name, 3 member user ids, 4 created |
//! | `space-collection` | the collection id | 2 parent, 3 name, 4 key version, 5 stale since, 6 created, 7 grants `[[0 member / 1 group, id, permission]]` |
//! | `space-keys` | the user id | 2 key copies `[[collection id, key version, sealed key]]` |
//! | `space-policies` | the space id | 2 updated by, 3 updated at, 4 to 12 the switches, 13 master password rules, 14 timeout minutes, 16 timeout action |
//! | `space-held` | the space id | 2 the ids of the live items a key replacement left held (docs/crypto.md, I3), sorted |
//!
//! Only confirmed members are published (they are the ones whose accounts a replica holds, see
//! [`crate::members`]); a member who is revoked or removed is a "gone" record, which also takes
//! their grants, group seats and key copies out of the replica. Times are Unix seconds.
//!
//! `space-held` carries the set of held items as it is now: a replica replaces its own set with it,
//! so an item the home released leaves the set, and a replica never serves a held item as live. The
//! home makes the record only for a space that has held items (or had, to say the set is empty
//! now).

use crate::cbor::{Fields, Value};
use crate::error::{FedError, Result};
use crate::publish::{GONE_KEY, Publisher};
use crate::replicate::{FedStore, Replica};
use kemlock_app::ports::StoreError;
use kemlock_domain::policies::{MasterPasswordPolicy, SpacePolicies, TimeoutAction};
use kemlock_domain::spaces::{
    Collection, CollectionGrant, CollectionId, CollectionPermission, Confirmation,
    CustomPermissions, Grantee, Group, GroupId, KeyCopy, Member, MemberState, Space, SpaceRole,
    SpaceState,
};
use kemlock_domain::{ItemId, Owner, SpaceId, UserId};
use std::collections::BTreeSet;
use std::future::{Future, ready};
use time::OffsetDateTime;
use uuid::Uuid;

type R<T> = std::result::Result<T, StoreError>;

/// The payload format version.
pub const VERSION: u64 = 1;
pub const KIND_SPACE: &str = "space";
pub const KIND_MEMBER: &str = "space-member";
pub const KIND_GROUP: &str = "space-group";
pub const KIND_COLLECTION: &str = "space-collection";
pub const KIND_KEYS: &str = "space-keys";
pub const KIND_POLICIES: &str = "space-policies";
pub const KIND_HELD: &str = "space-held";

/// The most entries of one list in a payload.
const MAX_ENTRIES: usize = 4096;

/// Whether `kind` is one of the space kinds.
pub fn is_space_kind(kind: &str) -> bool {
    matches!(
        kind,
        KIND_SPACE
            | KIND_MEMBER
            | KIND_GROUP
            | KIND_COLLECTION
            | KIND_KEYS
            | KIND_POLICIES
            | KIND_HELD
    )
}

/// A space's policies with when and by whom they were last set.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PolicyState {
    pub policies: SpacePolicies,
    pub updated_by: Option<UserId>,
    pub updated_at: Option<OffsetDateTime>,
}

/// Everything about a space that is home-only, as the home's store reads it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SpaceSnapshot {
    /// The space with its confirmed members, groups, collections and grants.
    pub state: SpaceState,
    /// The collection keys sealed to each confirmed member.
    pub key_copies: Vec<(UserId, Vec<KeyCopy>)>,
    /// `None` for a space nobody has set policies for.
    pub policies: Option<PolicyState>,
    /// The live items a key replacement left held and nobody has released, in id order.
    pub held: Vec<ItemId>,
}

/// One entity of a space as a home record carries it, or the news that it is gone.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SpaceRecord {
    Space(Space),
    Member(Member),
    MemberGone(UserId),
    Group(Group),
    GroupGone(GroupId),
    Collection {
        collection: Collection,
        grants: Vec<CollectionGrant>,
    },
    CollectionGone(CollectionId),
    Keys {
        user: UserId,
        copies: Vec<KeyCopy>,
    },
    KeysGone(UserId),
    Policies(PolicyState),
    /// The space's whole set of held items.
    Held(Vec<ItemId>),
}

/// What federation needs from storage to publish and apply a space's home-only state. Every method
/// has a default body that does nothing, so a store without spaces needs only an empty `impl`.
pub trait SpaceMirror: Send + Sync {
    /// The space's home-only state for publishing, or `None` when there is no such space here.
    fn space_snapshot(
        &self,
        _space: SpaceId,
    ) -> impl Future<Output = R<Option<SpaceSnapshot>>> + Send {
        ready(Ok(None))
    }

    /// The space's chain records after `after` (all of them for `None`), with what each
    /// committed, in ascending `seq`, for publishing.
    fn chain_records_after(
        &self,
        _space: SpaceId,
        _after: Option<u64>,
    ) -> impl Future<Output = R<Vec<crate::chain::ChainWire>>> + Send {
        ready(Ok(Vec::new()))
    }

    /// Keeps one chain record a replica took from the home, when it is the next in the chain.
    fn apply_chain_record(
        &self,
        _space: SpaceId,
        _record: &crate::chain::ChainWire,
    ) -> impl Future<Output = R<()>> + Send {
        ready(Ok(()))
    }

    /// Applies one record a replica took from the home: an upsert, or a removal.
    fn apply_space_record(
        &self,
        _space: SpaceId,
        _record: &SpaceRecord,
    ) -> impl Future<Output = R<()>> + Send {
        ready(Ok(()))
    }
}

// ---- encoding ----

fn uuid_value(id: &Uuid) -> Value {
    Value::bytes(id.as_bytes())
}

fn secs(time: OffsetDateTime) -> Value {
    Value::Uint(u64::try_from(time.unix_timestamp()).unwrap_or(0))
}

fn push_time(entries: &mut Vec<(u64, Value)>, key: u64, time: Option<OffsetDateTime>) {
    if let Some(time) = time {
        entries.push((key, secs(time)));
    }
}

fn head(id: &Uuid) -> Vec<(u64, Value)> {
    vec![(0, Value::Uint(VERSION)), (1, uuid_value(id))]
}

/// The payload that says the entity `id` is gone.
pub fn gone_payload(id: &[u8]) -> Vec<u8> {
    Value::map(vec![
        (0, Value::Uint(VERSION)),
        (1, Value::bytes(id)),
        (GONE_KEY, Value::flag(true)),
    ])
    .encode()
}

pub fn encode_space(space: &Space) -> Vec<u8> {
    let mut e = head(&space.id.0);
    e.push((2, Value::bytes(&space.name)));
    e.push((3, Value::Uint(u64::from(space.key_version))));
    push_time(&mut e, 4, space.keys_pending_since);
    e.push((5, secs(space.created_at)));
    e.push((6, secs(space.updated_at)));
    Value::map(e).encode()
}

pub fn encode_member(member: &Member) -> Vec<u8> {
    let mut e = head(&member.user.0);
    e.push((2, Value::text(member.role.as_str())));
    e.push((3, Value::Uint(u64::from(member.custom.bits()))));
    e.push((4, Value::text(member.state.as_str())));
    e.push((5, uuid_value(&member.invited_by.0)));
    e.push((6, secs(member.invited_at)));
    push_time(&mut e, 7, member.accepted_at);
    if let Some(sealed) = &member.sealed_space_key {
        e.push((8, Value::bytes(sealed)));
    }
    if let Some(version) = member.key_version {
        e.push((9, Value::Uint(u64::from(version))));
    }
    if let Some(c) = &member.confirmation {
        e.push((
            10,
            Value::map(vec![
                (0, uuid_value(&c.by.0)),
                (1, secs(c.at)),
                (2, Value::bytes(&c.fingerprint)),
                (3, Value::Uint(u64::from(c.member_key_version))),
                (4, Value::bytes(&c.statement)),
                (5, Value::bytes(&c.signature)),
            ]),
        ));
    }
    push_time(&mut e, 11, member.revoked_at);
    Value::map(e).encode()
}

pub fn encode_group(group: &Group) -> Vec<u8> {
    let mut e = head(&group.id.0);
    e.push((2, Value::bytes(&group.name)));
    e.push((
        3,
        Value::Array(group.members.iter().map(|u| uuid_value(&u.0)).collect()),
    ));
    e.push((4, secs(group.created_at)));
    Value::map(e).encode()
}

fn grantee_parts(grantee: Grantee) -> (u64, Uuid) {
    match grantee {
        Grantee::Member(user) => (0, user.0),
        Grantee::Group(group) => (1, group.0),
    }
}

/// `grants` are those of `collection`; they are written in grantee order.
pub fn encode_collection(collection: &Collection, grants: &[CollectionGrant]) -> Vec<u8> {
    let mut sorted: Vec<&CollectionGrant> = grants
        .iter()
        .filter(|g| g.collection == collection.id)
        .collect();
    sorted.sort_by_key(|g| g.grantee);
    let mut e = head(&collection.id.0);
    if let Some(parent) = collection.parent {
        e.push((2, uuid_value(&parent.0)));
    }
    e.push((3, Value::bytes(&collection.name)));
    e.push((4, Value::Uint(u64::from(collection.key_version))));
    push_time(&mut e, 5, collection.stale_since);
    e.push((6, secs(collection.created_at)));
    e.push((
        7,
        Value::Array(
            sorted
                .into_iter()
                .map(|g| {
                    let (kind, id) = grantee_parts(g.grantee);
                    Value::Array(vec![
                        Value::Uint(kind),
                        uuid_value(&id),
                        Value::text(g.permission.as_str()),
                    ])
                })
                .collect(),
        ),
    ));
    Value::map(e).encode()
}

pub fn encode_keys(user: UserId, copies: &[KeyCopy]) -> Vec<u8> {
    let mut sorted: Vec<&KeyCopy> = copies.iter().collect();
    sorted.sort_by_key(|c| c.collection);
    let mut e = head(&user.0);
    e.push((
        2,
        Value::Array(
            sorted
                .into_iter()
                .map(|c| {
                    Value::Array(vec![
                        uuid_value(&c.collection.0),
                        Value::Uint(u64::from(c.key_version)),
                        Value::bytes(&c.sealed),
                    ])
                })
                .collect(),
        ),
    ));
    Value::map(e).encode()
}

/// The held items of `space`, in id order and each once.
pub fn encode_held(space: SpaceId, items: &[ItemId]) -> Vec<u8> {
    let sorted: BTreeSet<ItemId> = items.iter().copied().collect();
    let mut e = head(&space.0);
    e.push((
        2,
        Value::Array(sorted.into_iter().map(|i| uuid_value(&i.0)).collect()),
    ));
    Value::map(e).encode()
}

pub fn encode_policies(space: SpaceId, state: &PolicyState) -> Vec<u8> {
    let s = &state.policies;
    let mut e = head(&space.0);
    if let Some(by) = state.updated_by {
        e.push((2, uuid_value(&by.0)));
    }
    push_time(&mut e, 3, state.updated_at);
    e.push((4, Value::flag(s.require_sso)));
    e.push((5, Value::flag(s.two_step)));
    e.push((6, Value::flag(s.single_space)));
    e.push((7, Value::flag(s.disable_export)));
    e.push((8, Value::flag(s.disable_send)));
    e.push((9, Value::flag(s.always_show_email)));
    e.push((10, Value::flag(s.no_pin_unlock)));
    e.push((11, Value::flag(s.central_ownership)));
    e.push((12, Value::flag(s.no_card_items)));
    if let Some(mp) = &s.master_password {
        let mut m = vec![
            (2, Value::flag(mp.require_upper)),
            (3, Value::flag(mp.require_lower)),
            (4, Value::flag(mp.require_numbers)),
            (5, Value::flag(mp.require_special)),
            (6, Value::flag(mp.enforce_on_login)),
        ];
        if let Some(n) = mp.min_length {
            m.push((0, Value::Uint(u64::from(n))));
        }
        if let Some(n) = mp.min_complexity {
            m.push((1, Value::Uint(u64::from(n))));
        }
        e.push((13, Value::map(m)));
    }
    if let Some(minutes) = s.session_timeout_minutes {
        e.push((14, Value::Uint(u64::from(minutes))));
    }
    if let Some(action) = s.session_timeout_action {
        e.push((16, Value::text(action.as_str())));
    }
    Value::map(e).encode()
}

// ---- decoding ----

fn from_secs(n: u64) -> Result<OffsetDateTime> {
    i64::try_from(n)
        .ok()
        .and_then(|s| OffsetDateTime::from_unix_timestamp(s).ok())
        .ok_or(FedError::Malformed("a time is out of range"))
}

fn uuid_at(f: &Fields<'_>, key: u64) -> Result<Uuid> {
    Ok(Uuid::from_bytes(f.fixed::<16>(key)?))
}

fn time_at(f: &Fields<'_>, key: u64) -> Result<OffsetDateTime> {
    from_secs(f.uint(key)?)
}

fn opt_time_at(f: &Fields<'_>, key: u64) -> Result<Option<OffsetDateTime>> {
    f.get(key)
        .map(|v| v.as_uint().and_then(from_secs))
        .transpose()
}

fn opt_uuid_at(f: &Fields<'_>, key: u64) -> Result<Option<Uuid>> {
    f.get(key)
        .map(|v| {
            v.as_bytes()
                .and_then(|b| {
                    <[u8; 16]>::try_from(b)
                        .map_err(|_| FedError::Malformed("an id has the wrong length"))
                })
                .map(Uuid::from_bytes)
        })
        .transpose()
}

fn small(n: u64) -> Result<u32> {
    u32::try_from(n).map_err(|_| FedError::Malformed("a number is out of range"))
}

fn opt_u32_at(f: &Fields<'_>, key: u64) -> Result<Option<u32>> {
    f.get(key).map(|v| v.as_uint().and_then(small)).transpose()
}

fn list<'a>(f: &Fields<'a>, key: u64) -> Result<&'a [Value]> {
    let items = f.array(key)?;
    if items.len() > MAX_ENTRIES {
        return Err(FedError::Malformed("too many entries"));
    }
    Ok(items)
}

fn decode_member(space: SpaceId, f: &Fields<'_>) -> Result<Member> {
    f.only(&[0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11])?;
    let confirmation = match f.get(10) {
        None => None,
        Some(v) => {
            let c = v.as_fields()?;
            c.only(&[0, 1, 2, 3, 4, 5])?;
            Some(Confirmation {
                by: UserId(uuid_at(&c, 0)?),
                at: time_at(&c, 1)?,
                fingerprint: c.bytes(2)?.to_vec(),
                member_key_version: small(c.uint(3)?)?,
                statement: c.bytes(4)?.to_vec(),
                signature: c.bytes(5)?.to_vec(),
            })
        }
    };
    Ok(Member {
        space,
        user: UserId(uuid_at(f, 1)?),
        role: SpaceRole::parse(f.text(2)?).ok_or(FedError::Malformed("an unknown role"))?,
        custom: CustomPermissions::from_bits(
            u16::try_from(f.uint(3)?).map_err(|_| FedError::Malformed("unknown permissions"))?,
        )
        .ok_or(FedError::Malformed("unknown permissions"))?,
        state: MemberState::parse(f.text(4)?)
            .ok_or(FedError::Malformed("an unknown member state"))?,
        invited_by: UserId(uuid_at(f, 5)?),
        invited_at: time_at(f, 6)?,
        accepted_at: opt_time_at(f, 7)?,
        sealed_space_key: f
            .get(8)
            .map(|v| v.as_bytes().map(<[u8]>::to_vec))
            .transpose()?,
        key_version: opt_u32_at(f, 9)?,
        confirmation,
        revoked_at: opt_time_at(f, 11)?,
    })
}

fn decode_group(space: SpaceId, f: &Fields<'_>) -> Result<Group> {
    f.only(&[0, 1, 2, 3, 4])?;
    let mut members = BTreeSet::new();
    for v in list(f, 3)? {
        let b: [u8; 16] = v
            .as_bytes()?
            .try_into()
            .map_err(|_| FedError::Malformed("an id has the wrong length"))?;
        members.insert(UserId(Uuid::from_bytes(b)));
    }
    Ok(Group {
        id: GroupId(uuid_at(f, 1)?),
        space,
        name: f.bytes(2)?.to_vec(),
        members,
        created_at: time_at(f, 4)?,
    })
}

fn decode_collection(space: SpaceId, f: &Fields<'_>) -> Result<SpaceRecord> {
    f.only(&[0, 1, 2, 3, 4, 5, 6, 7])?;
    let id = CollectionId(uuid_at(f, 1)?);
    let mut grants = Vec::new();
    for v in list(f, 7)? {
        let [kind, grantee, permission] = v.as_array()? else {
            return Err(FedError::Malformed("a grant has three parts"));
        };
        let b: [u8; 16] = grantee
            .as_bytes()?
            .try_into()
            .map_err(|_| FedError::Malformed("an id has the wrong length"))?;
        let uuid = Uuid::from_bytes(b);
        let grantee = match kind.as_uint()? {
            0 => Grantee::Member(UserId(uuid)),
            1 => Grantee::Group(GroupId(uuid)),
            _ => return Err(FedError::Malformed("an unknown grantee type")),
        };
        grants.push(CollectionGrant {
            collection: id,
            grantee,
            permission: CollectionPermission::parse(permission.as_text()?)
                .ok_or(FedError::Malformed("an unknown permission"))?,
        });
    }
    Ok(SpaceRecord::Collection {
        collection: Collection {
            id,
            space,
            parent: opt_uuid_at(f, 2)?.map(CollectionId),
            name: f.bytes(3)?.to_vec(),
            key_version: small(f.uint(4)?)?,
            stale_since: opt_time_at(f, 5)?,
            created_at: time_at(f, 6)?,
        },
        grants,
    })
}

fn decode_keys(f: &Fields<'_>) -> Result<SpaceRecord> {
    f.only(&[0, 1, 2])?;
    let mut copies = Vec::new();
    for v in list(f, 2)? {
        let [collection, version, sealed] = v.as_array()? else {
            return Err(FedError::Malformed("a key copy has three parts"));
        };
        let b: [u8; 16] = collection
            .as_bytes()?
            .try_into()
            .map_err(|_| FedError::Malformed("an id has the wrong length"))?;
        copies.push(KeyCopy {
            collection: CollectionId(Uuid::from_bytes(b)),
            user: UserId(uuid_at(f, 1)?),
            key_version: small(version.as_uint()?)?,
            sealed: sealed.as_bytes()?.to_vec(),
        });
    }
    Ok(SpaceRecord::Keys {
        user: UserId(uuid_at(f, 1)?),
        copies,
    })
}

fn decode_held(space: SpaceId, f: &Fields<'_>) -> Result<SpaceRecord> {
    f.only(&[0, 1, 2])?;
    if SpaceId(uuid_at(f, 1)?) != space {
        return Err(FedError::Invalid("a space record for another space"));
    }
    let mut items = Vec::new();
    for v in list(f, 2)? {
        let b: [u8; 16] = v
            .as_bytes()?
            .try_into()
            .map_err(|_| FedError::Malformed("an id has the wrong length"))?;
        items.push(ItemId(Uuid::from_bytes(b)));
    }
    Ok(SpaceRecord::Held(items))
}

fn decode_policies(f: &Fields<'_>) -> Result<PolicyState> {
    f.only(&[0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 16])?;
    let master_password = match f.get(13) {
        None => None,
        Some(v) => {
            let m = v.as_fields()?;
            m.only(&[0, 1, 2, 3, 4, 5, 6])?;
            Some(MasterPasswordPolicy {
                min_length: opt_u32_at(&m, 0)?,
                min_complexity: opt_u32_at(&m, 1)?
                    .map(u8::try_from)
                    .transpose()
                    .map_err(|_| FedError::Malformed("a number is out of range"))?,
                require_upper: m.flag(2)?,
                require_lower: m.flag(3)?,
                require_numbers: m.flag(4)?,
                require_special: m.flag(5)?,
                enforce_on_login: m.flag(6)?,
            })
        }
    };
    let session_timeout_action = match f.get(16) {
        None => None,
        Some(v) => Some(
            TimeoutAction::parse(v.as_text()?)
                .ok_or(FedError::Malformed("an unknown timeout action"))?,
        ),
    };
    Ok(PolicyState {
        policies: SpacePolicies {
            require_sso: f.flag(4)?,
            two_step: f.flag(5)?,
            master_password,
            single_space: f.flag(6)?,
            disable_export: f.flag(7)?,
            disable_send: f.flag(8)?,
            always_show_email: f.flag(9)?,
            session_timeout_minutes: opt_u32_at(f, 14)?,
            session_timeout_action,
            no_pin_unlock: f.flag(10)?,
            central_ownership: f.flag(11)?,
            no_card_items: f.flag(12)?,
        },
        updated_by: opt_uuid_at(f, 2)?.map(UserId),
        updated_at: opt_time_at(f, 3)?,
    })
}

impl SpaceRecord {
    /// Reads the payload of a home record of `kind` for `space`. `None` for a kind that is not a
    /// space kind; an error for a payload that is not what [`SpaceRecord::payload`] writes.
    pub fn from_record(space: SpaceId, kind: &str, payload: &[u8]) -> Result<Option<SpaceRecord>> {
        if !is_space_kind(kind) {
            return Ok(None);
        }
        let value = Value::decode(payload)?;
        let f = value.as_fields()?;
        if f.uint(0)? != VERSION {
            return Err(FedError::Malformed("an unknown space record version"));
        }
        if f.get(GONE_KEY).is_some() {
            f.only(&[0, 1, GONE_KEY])?;
            let id = uuid_at(&f, 1)?;
            return match kind {
                KIND_MEMBER => Ok(Some(SpaceRecord::MemberGone(UserId(id)))),
                KIND_GROUP => Ok(Some(SpaceRecord::GroupGone(GroupId(id)))),
                KIND_COLLECTION => Ok(Some(SpaceRecord::CollectionGone(CollectionId(id)))),
                KIND_KEYS => Ok(Some(SpaceRecord::KeysGone(UserId(id)))),
                _ => Err(FedError::Malformed("this kind of record can't be gone")),
            };
        }
        let record = match kind {
            KIND_SPACE => {
                f.only(&[0, 1, 2, 3, 4, 5, 6])?;
                let id = SpaceId(uuid_at(&f, 1)?);
                if id != space {
                    return Err(FedError::Invalid("a space record for another space"));
                }
                SpaceRecord::Space(Space {
                    id,
                    name: f.bytes(2)?.to_vec(),
                    key_version: small(f.uint(3)?)?,
                    keys_pending_since: opt_time_at(&f, 4)?,
                    created_at: time_at(&f, 5)?,
                    updated_at: time_at(&f, 6)?,
                })
            }
            KIND_MEMBER => SpaceRecord::Member(decode_member(space, &f)?),
            KIND_GROUP => SpaceRecord::Group(decode_group(space, &f)?),
            KIND_COLLECTION => decode_collection(space, &f)?,
            KIND_KEYS => decode_keys(&f)?,
            KIND_HELD => decode_held(space, &f)?,
            _ => SpaceRecord::Policies(decode_policies(&f)?),
        };
        if record.payload(space) != payload {
            return Err(FedError::Invalid("a space record is not canonical"));
        }
        Ok(Some(record))
    }

    /// The payload that carries this record.
    pub fn payload(&self, space: SpaceId) -> Vec<u8> {
        match self {
            SpaceRecord::Space(s) => encode_space(s),
            SpaceRecord::Member(m) => encode_member(m),
            SpaceRecord::MemberGone(u) | SpaceRecord::KeysGone(u) => gone_payload(u.0.as_bytes()),
            SpaceRecord::Group(g) => encode_group(g),
            SpaceRecord::GroupGone(g) => gone_payload(g.0.as_bytes()),
            SpaceRecord::Collection { collection, grants } => encode_collection(collection, grants),
            SpaceRecord::CollectionGone(c) => gone_payload(c.0.as_bytes()),
            SpaceRecord::Keys { user, copies } => encode_keys(*user, copies),
            SpaceRecord::Policies(p) => encode_policies(space, p),
            SpaceRecord::Held(items) => encode_held(space, items),
        }
    }

    /// The kind of home record that carries it.
    pub fn kind(&self) -> &'static str {
        match self {
            SpaceRecord::Space(_) => KIND_SPACE,
            SpaceRecord::Member(_) | SpaceRecord::MemberGone(_) => KIND_MEMBER,
            SpaceRecord::Group(_) | SpaceRecord::GroupGone(_) => KIND_GROUP,
            SpaceRecord::Collection { .. } | SpaceRecord::CollectionGone(_) => KIND_COLLECTION,
            SpaceRecord::Keys { .. } | SpaceRecord::KeysGone(_) => KIND_KEYS,
            SpaceRecord::Policies(_) => KIND_POLICIES,
            SpaceRecord::Held(_) => KIND_HELD,
        }
    }
}

// ---- publishing and applying ----

impl<S: FedStore> Replica<S> {
    /// Makes the records of one kind: one for each entity in `current` that changed, and a "gone"
    /// record for each entity published before that isn't there any more.
    async fn publish_kind(
        &self,
        publisher: &mut Publisher,
        kind: &str,
        current: Vec<(Vec<u8>, Vec<u8>)>,
    ) -> Result<()> {
        let present: BTreeSet<Vec<u8>> = current.iter().map(|(id, _)| id.clone()).collect();
        for (_, payload) in current {
            self.publish(publisher, kind, payload).await?;
        }
        for id in publisher.live_keys(kind) {
            if !present.contains(&id) {
                self.publish(publisher, kind, gone_payload(&id)).await?;
            }
        }
        Ok(())
    }

    /// At the home of a space: makes a home record for every member, group, collection, key set
    /// and policy that changed since its last record, and for every one that went. Returns how
    /// many records it made. Does nothing for a personal vault or at a replica.
    pub async fn publish_space_state(&self, vault: Owner) -> Result<usize> {
        let Owner::Space(space) = vault else {
            return Ok(0);
        };
        let Some(mut publisher) = self.publisher(vault).await? else {
            return Ok(0);
        };
        let Some(snapshot) = self.store.space_snapshot(space).await? else {
            return Ok(0);
        };
        let state = &snapshot.state;
        let id_of = |id: &Uuid| id.as_bytes().to_vec();

        self.publish_kind(
            &mut publisher,
            KIND_SPACE,
            vec![(id_of(&state.space.id.0), encode_space(&state.space))],
        )
        .await?;
        let members = state
            .members
            .iter()
            .filter(|m| m.state == MemberState::Confirmed)
            .map(|m| (id_of(&m.user.0), encode_member(m)))
            .collect();
        self.publish_kind(&mut publisher, KIND_MEMBER, members)
            .await?;
        let groups = state
            .groups
            .iter()
            .map(|g| (id_of(&g.id.0), encode_group(g)))
            .collect();
        self.publish_kind(&mut publisher, KIND_GROUP, groups)
            .await?;
        let collections = state
            .collections
            .iter()
            .map(|c| (id_of(&c.id.0), encode_collection(c, &state.grants)))
            .collect();
        self.publish_kind(&mut publisher, KIND_COLLECTION, collections)
            .await?;
        let keys = snapshot
            .key_copies
            .iter()
            .map(|(user, copies)| (id_of(&user.0), encode_keys(*user, copies)))
            .collect();
        self.publish_kind(&mut publisher, KIND_KEYS, keys).await?;
        let policies = snapshot
            .policies
            .iter()
            .map(|p| (id_of(&space.0), encode_policies(space, p)))
            .collect();
        self.publish_kind(&mut publisher, KIND_POLICIES, policies)
            .await?;
        // Only for a space that has held items, or had: a set that went empty is still said, as
        // the empty set, because a replica replaces its own set and can't tell "none" from "no news".
        let said_before = !publisher.live_keys(KIND_HELD).is_empty();
        if !snapshot.held.is_empty() || said_before {
            self.publish(
                &mut publisher,
                KIND_HELD,
                encode_held(space, &snapshot.held),
            )
            .await?;
        }
        let chained = self.publish_chain(vault).await?;
        Ok(publisher.made + chained)
    }

    /// Applies a space home record this server stored as applied. A payload that doesn't parse is
    /// logged and left.
    pub(crate) async fn apply_space_home_record(&self, vault: Owner, kind: &str, payload: &[u8]) {
        let Owner::Space(space) = vault else {
            return;
        };
        match SpaceRecord::from_record(space, kind, payload) {
            Ok(Some(record)) => {
                if let Err(e) = self.store.apply_space_record(space, &record).await {
                    tracing::warn!(error = %e, %kind, "a space record could not be applied");
                }
            }
            Ok(None) => {}
            Err(e) => tracing::warn!(error = %e, %kind, "a space record is not valid"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::memory::MemoryStore;
    use crate::message::{Request, Response};
    use crate::ports::VaultRepo as _;
    use crate::replicate::Channel;
    use crate::suite::Suite;
    use crate::testing::{identity, space_snapshot};
    use kemlock_domain::ServerId;
    use std::sync::Arc;

    const NOW: u64 = 1_800_000_000;

    #[test]
    fn every_record_round_trips_through_its_payload() {
        let space = SpaceId::random();
        let snap = space_snapshot(space);
        let mut records = vec![SpaceRecord::Space(snap.state.space.clone())];
        records.extend(snap.state.members.iter().cloned().map(SpaceRecord::Member));
        records.extend(snap.state.groups.iter().cloned().map(SpaceRecord::Group));
        for c in &snap.state.collections {
            // A payload writes a collection's grants in grantee order, so a record read back
            // has them in that order.
            let mut grants: Vec<CollectionGrant> = snap
                .state
                .grants
                .iter()
                .filter(|g| g.collection == c.id)
                .copied()
                .collect();
            grants.sort_by_key(|g| g.grantee);
            records.push(SpaceRecord::Collection {
                collection: c.clone(),
                grants,
            });
        }
        for (user, copies) in &snap.key_copies {
            // The payload writes a user's copies in collection order.
            let mut copies = copies.clone();
            copies.sort_by_key(|c| c.collection);
            records.push(SpaceRecord::Keys {
                user: *user,
                copies,
            });
        }
        records.push(SpaceRecord::Policies(
            snap.policies.clone().expect("policies"),
        ));
        records.push(SpaceRecord::MemberGone(UserId::random()));
        records.push(SpaceRecord::GroupGone(GroupId::random()));
        records.push(SpaceRecord::CollectionGone(CollectionId::random()));
        records.push(SpaceRecord::KeysGone(UserId::random()));
        for record in records {
            let payload = record.payload(space);
            let back = SpaceRecord::from_record(space, record.kind(), &payload)
                .expect("a payload")
                .expect("a space kind");
            assert_eq!(back, record, "{}", record.kind());
        }
    }

    #[test]
    fn grants_are_written_in_grantee_order_whatever_order_they_come_in() {
        let space = SpaceId::random();
        let snap = space_snapshot(space);
        let c = &snap.state.collections[0];
        let mut reversed = snap.state.grants.clone();
        reversed.reverse();
        assert_eq!(
            encode_collection(c, &snap.state.grants),
            encode_collection(c, &reversed)
        );
    }

    #[test]
    fn nonsense_payloads_are_refused() {
        let space = SpaceId::random();
        let snap = space_snapshot(space);
        let good = encode_member(&snap.state.members[0]);
        assert!(SpaceRecord::from_record(space, KIND_MEMBER, &good).is_ok());
        let mut longer = good.clone();
        longer.push(0);
        assert!(SpaceRecord::from_record(space, KIND_MEMBER, &longer).is_err());
        // An unknown field, and an unknown role.
        let mut value = Value::decode(&good).expect("decode");
        if let Value::Map(entries) = &mut value {
            entries.push((99, Value::Uint(1)));
        }
        assert!(SpaceRecord::from_record(space, KIND_MEMBER, &value.encode()).is_err());
        let mut value = Value::decode(&good).expect("decode");
        if let Value::Map(entries) = &mut value {
            for (k, v) in entries.iter_mut() {
                if *k == 2 {
                    *v = Value::text("emperor");
                }
            }
        }
        assert!(SpaceRecord::from_record(space, KIND_MEMBER, &value.encode()).is_err());
        // The space and its policies can't be gone.
        let gone = gone_payload(space.0.as_bytes());
        assert!(SpaceRecord::from_record(space, KIND_SPACE, &gone).is_err());
        assert!(SpaceRecord::from_record(space, KIND_POLICIES, &gone).is_err());
        // A kind that isn't a space kind is not ours.
        assert_eq!(
            SpaceRecord::from_record(space, "member-account", &good),
            Ok(None)
        );
    }

    struct Direct<'a> {
        remote: &'a Replica<MemoryStore>,
        caller: ServerId,
    }

    impl Channel for Direct<'_> {
        async fn call(&mut self, request: &Request) -> Result<Response> {
            Ok(self.remote.serve(self.caller, request, NOW).await.response)
        }
    }

    #[tokio::test]
    async fn the_home_publishes_what_changed_and_a_replica_applies_it() {
        let ia = identity(1, NOW, &Suite::IMPLEMENTED);
        let ib = identity(2, NOW, &Suite::IMPLEMENTED);
        let a = Replica::new(MemoryStore::new(ia.server), Arc::new(ia.clone()));
        let b = Replica::new(MemoryStore::new(ib.server), Arc::new(ib.clone()));
        a.pin_peer(&ib.descriptor, NOW).await.expect("pin");
        b.pin_peer(&ia.descriptor, NOW).await.expect("pin");
        let space = SpaceId::random();
        let vault = Owner::Space(space);
        a.federate(vault, vec![ib.server]).await.expect("federate");
        b.accept_vault(vault, ia.server, vec![ib.server])
            .await
            .expect("accept");

        // Nothing to publish before the space exists.
        assert_eq!(a.publish_space_state(vault).await.expect("publish"), 0);
        let snap = space_snapshot(space);
        a.store.set_space_snapshot(snap.clone());
        // One record for the space, two members, a group, two collections, one key set and the
        // policies.
        assert_eq!(a.publish_space_state(vault).await.expect("publish"), 8);
        assert_eq!(
            a.publish_space_state(vault).await.expect("publish"),
            0,
            "nothing changed"
        );
        // A replica makes none.
        b.store.set_space_snapshot(snap.clone());
        assert_eq!(b.publish_space_state(vault).await.expect("publish"), 0);

        let mut channel = Direct {
            remote: &a,
            caller: ib.server,
        };
        let sync = b
            .pull_home_records(&mut channel, ia.server, vault)
            .await
            .expect("sync");
        assert_eq!(sync.applied, 8);
        let applied = b.store.applied_space_records();
        assert_eq!(applied.len(), 8);
        assert!(
            applied
                .iter()
                .any(|r| matches!(r, SpaceRecord::Member(m) if m.role == SpaceRole::Owner)),
            "the owner's role arrived"
        );
        assert!(
            applied
                .iter()
                .any(|r| matches!(r, SpaceRecord::Keys { copies, .. } if copies.len() == 2)),
            "the collection keys arrived"
        );
        assert!(
            applied
                .iter()
                .any(|r| matches!(r, SpaceRecord::Policies(p) if p.policies.require_sso)),
            "the policies arrived"
        );

        // A member goes and a policy changes: a "gone" record and a new policy record, nothing else.
        let mut changed = snap.clone();
        let gone = changed.state.members.remove(1);
        changed.state.groups[0].members.clear();
        if let Some(p) = &mut changed.policies {
            p.policies.require_sso = false;
        }
        a.store.set_space_snapshot(changed);
        assert_eq!(a.publish_space_state(vault).await.expect("publish"), 3);
        let sync = b
            .pull_home_records(&mut channel, ia.server, vault)
            .await
            .expect("sync");
        assert_eq!(sync.applied, 3);
        let applied = b.store.applied_space_records();
        assert!(
            applied
                .iter()
                .any(|r| matches!(r, SpaceRecord::MemberGone(u) if *u == gone.user)),
            "the removed member is gone at the replica"
        );
        assert!(
            applied
                .iter()
                .any(|r| matches!(r, SpaceRecord::Policies(p) if !p.policies.require_sso))
        );
    }

    #[test]
    fn the_held_set_is_written_sorted_once_and_read_back() {
        let space = SpaceId::random();
        let a = ItemId::random();
        let b = ItemId::random();
        let (low, high) = if a < b { (a, b) } else { (b, a) };
        let payload = encode_held(space, &[high, low, high]);
        assert_eq!(payload, encode_held(space, &[low, high]));
        assert_eq!(
            SpaceRecord::from_record(space, KIND_HELD, &payload),
            Ok(Some(SpaceRecord::Held(vec![low, high])))
        );
        assert_eq!(
            SpaceRecord::from_record(space, KIND_HELD, &encode_held(space, &[])),
            Ok(Some(SpaceRecord::Held(Vec::new())))
        );
        // Another space's set, and a set that can't be gone, are refused.
        assert!(SpaceRecord::from_record(SpaceId::random(), KIND_HELD, &payload).is_err());
        assert!(
            SpaceRecord::from_record(space, KIND_HELD, &gone_payload(space.0.as_bytes())).is_err()
        );
    }

    #[tokio::test]
    async fn the_home_says_which_items_are_held_and_when_the_set_empties() {
        let ia = identity(1, NOW, &Suite::IMPLEMENTED);
        let ib = identity(2, NOW, &Suite::IMPLEMENTED);
        let a = Replica::new(MemoryStore::new(ia.server), Arc::new(ia.clone()));
        let b = Replica::new(MemoryStore::new(ib.server), Arc::new(ib.clone()));
        a.pin_peer(&ib.descriptor, NOW).await.expect("pin");
        b.pin_peer(&ia.descriptor, NOW).await.expect("pin");
        let space = SpaceId::random();
        let vault = Owner::Space(space);
        a.federate(vault, vec![ib.server]).await.expect("federate");
        b.accept_vault(vault, ia.server, vec![ib.server])
            .await
            .expect("accept");
        let mut snap = space_snapshot(space);
        a.store.set_space_snapshot(snap.clone());
        // A space with nothing held makes no held record.
        assert_eq!(a.publish_space_state(vault).await.expect("publish"), 8);

        let held = [ItemId::random(), ItemId::random()];
        snap.held = held.to_vec();
        a.store.set_space_snapshot(snap.clone());
        assert_eq!(a.publish_space_state(vault).await.expect("publish"), 1);
        assert_eq!(
            a.publish_space_state(vault).await.expect("publish"),
            0,
            "nothing changed"
        );
        let mut channel = Direct {
            remote: &a,
            caller: ib.server,
        };
        b.pull_home_records(&mut channel, ia.server, vault)
            .await
            .expect("sync");
        let mut want = held.to_vec();
        want.sort();
        assert!(
            b.store
                .applied_space_records()
                .iter()
                .any(|r| matches!(r, SpaceRecord::Held(items) if *items == want)),
            "the replica was told which items are held"
        );

        // One item is released at the home, then the other: each change is a new record, and the
        // last says the set is empty, which a replica can't tell from silence.
        snap.held = vec![held[0]];
        a.store.set_space_snapshot(snap.clone());
        assert_eq!(a.publish_space_state(vault).await.expect("publish"), 1);
        snap.held = Vec::new();
        a.store.set_space_snapshot(snap);
        assert_eq!(a.publish_space_state(vault).await.expect("publish"), 1);
        b.pull_home_records(&mut channel, ia.server, vault)
            .await
            .expect("sync");
        assert!(
            matches!(
                b.store.applied_space_records().last(),
                Some(SpaceRecord::Held(items)) if items.is_empty()
            ),
            "the replica was told the set is empty"
        );
    }

    #[tokio::test]
    async fn a_stale_epoch_space_record_is_quarantined_and_applies_nothing() {
        let ia = identity(1, NOW, &Suite::IMPLEMENTED);
        let ib = identity(2, NOW, &Suite::IMPLEMENTED);
        let a = Replica::new(MemoryStore::new(ia.server), Arc::new(ia.clone()));
        let b = Replica::new(MemoryStore::new(ib.server), Arc::new(ib.clone()));
        a.pin_peer(&ib.descriptor, NOW).await.expect("pin");
        b.pin_peer(&ia.descriptor, NOW).await.expect("pin");
        let space = SpaceId::random();
        let vault = Owner::Space(space);
        a.federate(vault, vec![ib.server]).await.expect("federate");
        b.accept_vault(vault, ia.server, vec![ib.server])
            .await
            .expect("accept");
        // B is promoted; A, which doesn't know, publishes a role change under epoch 1.
        b.promote(vault, NOW).await.expect("promote");
        a.store.set_space_snapshot(space_snapshot(space));
        assert_eq!(a.publish_space_state(vault).await.expect("publish"), 8);
        let mut channel = Direct {
            remote: &a,
            caller: ib.server,
        };
        let sync = b
            .pull_home_records(&mut channel, ia.server, vault)
            .await
            .expect("sync");
        assert_eq!((sync.applied, sync.quarantined), (0, 8));
        assert!(b.store.applied_space_records().is_empty());
        assert_eq!(b.store.quarantined(vault).await.expect("held").len(), 8);
    }
}
