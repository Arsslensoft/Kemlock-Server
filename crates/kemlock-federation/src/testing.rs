//! Helpers for tests in this crate and in the crates built on it. Not part of the API.

use crate::change::ms_to_time;
use crate::descriptor::VALIDITY_SECS;
use crate::identity::{DescriptorParams, KemPair, LocalIdentity};
use crate::spaces::{PolicyState, SpaceSnapshot};
use crate::suite::Suite;
use kemlock_crypto::sig1;
use kemlock_domain::policies::{MasterPasswordPolicy, SpacePolicies, TimeoutAction};
use kemlock_domain::spaces::{
    Collection, CollectionGrant, CollectionId, CollectionPermission, Confirmation,
    CustomPermissions, Grantee, Group, GroupId, KeyCopy, Member, MemberState, Space, SpaceRole,
    SpaceState,
};
use kemlock_domain::{
    ItemDraft, ItemFormat, ItemId, ItemKind, Owner, Revision, ServerId, SpaceId, UserId,
};
use std::collections::HashMap;
use time::OffsetDateTime;

/// A live item draft made at `at_ms` (Unix milliseconds). `expected` is the revision the store
/// must still find; the ciphertext is filled with the revision so versions differ.
pub fn draft(
    id: ItemId,
    owner: Owner,
    expected: Option<u64>,
    revision: u64,
    at_ms: u64,
) -> ItemDraft {
    ItemDraft {
        id,
        owner,
        kind: ItemKind::try_from("login".to_owned()).expect("a kind"),
        format: ItemFormat::Kem1,
        expected: expected.map(Revision),
        revision: Revision(revision),
        key_version: 1,
        ciphertext: Some(vec![(revision % 251) as u8; 40]),
        item_key: Some(vec![9; 60]),
        deleted_at: None,
        updated_at: ms_to_time(at_ms).expect("a time"),
        signature: None,
    }
}

/// Like [`draft`] with a ciphertext of `fill` bytes, to tell two versions of one revision apart.
pub fn draft_with(
    id: ItemId,
    owner: Owner,
    expected: Option<u64>,
    revision: u64,
    at_ms: u64,
    fill: u8,
) -> ItemDraft {
    ItemDraft {
        ciphertext: Some(vec![fill; 40]),
        ..draft(id, owner, expected, revision, at_ms)
    }
}

/// A server identity with a signing key made from `seed` and a fresh KEM key, whose descriptor
/// is valid from `now`.
pub fn identity(seed: u8, now: u64, suites: &[Suite]) -> LocalIdentity {
    let signing = sig1::SigningKey::from_bytes(&[seed; 64]);
    let kem = KemPair::generate().expect("a KEM key");
    LocalIdentity::new(
        ServerId::random(),
        signing,
        vec![kem],
        DescriptorParams {
            suites: suites.to_vec(),
            addresses: vec![format!("https://s{seed}.example.org")],
            operator: format!("Operator {seed}"),
            not_before: now,
            not_after: now + VALIDITY_SECS,
        },
    )
    .expect("an identity")
}

/// The identity keys of `ids`, as a verifier that has paired with all of them would hold them.
pub fn directory(ids: &[&LocalIdentity]) -> HashMap<ServerId, sig1::PublicKey> {
    ids.iter().map(|i| (i.server, i.public.clone())).collect()
}

/// A time `n` seconds after a fixed start, for the space helpers.
fn space_time(n: i64) -> OffsetDateTime {
    OffsetDateTime::from_unix_timestamp(1_700_000_000 + n).expect("a time")
}

pub fn space_member(space: SpaceId, role: SpaceRole) -> Member {
    Member {
        space,
        user: UserId::random(),
        role,
        custom: if role == SpaceRole::Custom {
            CustomPermissions::MANAGE_USERS
        } else {
            CustomPermissions::NONE
        },
        state: MemberState::Confirmed,
        invited_by: UserId::random(),
        invited_at: space_time(1),
        accepted_at: Some(space_time(2)),
        sealed_space_key: Some(vec![5; 64]),
        key_version: Some(1),
        confirmation: Some(Confirmation {
            by: UserId::random(),
            at: space_time(3),
            fingerprint: vec![6; 64],
            member_key_version: 1,
            statement: vec![7; 20],
            signature: vec![8; 30],
        }),
        revoked_at: None,
    }
}

pub fn space_snapshot(space: SpaceId) -> SpaceSnapshot {
    let owner = space_member(space, SpaceRole::Owner);
    let plain = space_member(space, SpaceRole::Member);
    let group = Group {
        id: GroupId::random(),
        space,
        name: vec![1; 30],
        members: [plain.user].into_iter().collect(),
        created_at: space_time(4),
    };
    let parent = Collection {
        id: CollectionId::random(),
        space,
        parent: None,
        name: vec![2; 30],
        key_version: 1,
        stale_since: None,
        created_at: space_time(5),
    };
    let child = Collection {
        id: CollectionId::random(),
        space,
        parent: Some(parent.id),
        name: vec![3; 30],
        key_version: 2,
        stale_since: Some(space_time(6)),
        created_at: space_time(7),
    };
    let grants = vec![
        CollectionGrant {
            collection: parent.id,
            grantee: Grantee::Group(group.id),
            permission: CollectionPermission::Edit,
        },
        CollectionGrant {
            collection: parent.id,
            grantee: Grantee::Member(owner.user),
            permission: CollectionPermission::Manage,
        },
    ];
    let copies = vec![
        KeyCopy {
            collection: parent.id,
            user: owner.user,
            key_version: 1,
            sealed: vec![9; 80],
        },
        KeyCopy {
            collection: child.id,
            user: owner.user,
            key_version: 2,
            sealed: vec![10; 80],
        },
    ];
    SpaceSnapshot {
        key_copies: vec![(owner.user, copies)],
        held: Vec::new(),
        policies: Some(PolicyState {
            policies: SpacePolicies {
                require_sso: true,
                master_password: Some(MasterPasswordPolicy::fourteen_characters()),
                session_timeout_minutes: Some(30),
                session_timeout_action: Some(TimeoutAction::LogOut),
                ..SpacePolicies::default()
            },
            updated_by: Some(owner.user),
            updated_at: Some(space_time(8)),
        }),
        state: SpaceState {
            space: Space {
                id: space,
                name: vec![4; 40],
                key_version: 3,
                keys_pending_since: Some(space_time(9)),
                created_at: space_time(0),
                updated_at: space_time(10),
            },
            members: vec![owner, plain],
            groups: vec![group],
            collections: vec![parent, child],
            grants,
        },
    }
}
