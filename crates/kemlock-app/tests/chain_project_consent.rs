//! The projection of a chain onto the server's tables keeps a member the chain holds as confirmed
//! `invited` until they have accepted: the invitee's consent is the server's own step, and a policy
//! or a key binds no one before it.

mod chain_kit;

use chain_kit::{Chain, Person};
use kemlock_app::spaces::chain_project::{Batch, project};
use kemlock_app::spaces::{SpaceChanges, StoredSeal};
use kemlock_crypto::space_chain::{Body, CollectionPerm, Grantee, Role, State};
use kemlock_domain::spaces::{
    CustomPermissions, Member, MemberState, Space, SpaceRole, SpaceState,
};
use kemlock_domain::{SpaceId, UserId};
use time::OffsetDateTime;
use uuid::Uuid;

const SAM: [u8; 16] = [1; 16];
const ANA: [u8; 16] = [2; 16];
const COLLECTION: [u8; 16] = [7; 16];

/// What the projection of a chain makes of the space, in which Sam made it and a collection, invited
/// Ana, granted her the collection, confirmed her and sealed its key to her, when the stored row of
/// Ana is in state `ana`.
fn project_with(ana: MemberState) -> SpaceChanges {
    let space_id = SpaceId(Uuid::from_bytes([9; 16]));
    let sam = Person::new(SAM, 1);
    let ana_person = Person::new(ANA, 2);
    let mut chain = Chain::new(*space_id.0.as_bytes(), 0);
    let steps = [
        chain.create(&sam, COLLECTION),
        chain.invite(&sam, ANA, Role::Member),
        chain.record(
            &sam,
            Body::Grant {
                collection: COLLECTION,
                grantee: Grantee::User(ANA),
                permission: CollectionPerm::View,
            },
        ),
        chain.confirm(&sam, &ana_person),
        chain.seal_collection_key(&sam, COLLECTION, &ana_person),
    ];
    let mut state = State::empty();
    for step in &steps {
        state = state
            .apply(space_id.0.as_bytes(), &step.record)
            .expect("a valid record")
            .state;
    }
    // The boxes of the newest records: Ana's copy of the collection key.
    let seals: Vec<StoredSeal> = steps[4]
        .seals
        .iter()
        .map(|seal| StoredSeal {
            seq: seal.seq,
            key: seal.key,
            version: seal.version,
            member: UserId(Uuid::from_bytes(seal.member)),
            bundle_version: 1,
            sealed: seal.sealed.clone(),
        })
        .collect();

    let now = OffsetDateTime::UNIX_EPOCH;
    let sam_id = UserId(Uuid::from_bytes(SAM));
    let ana_id = UserId(Uuid::from_bytes(ANA));
    let mut owner = Member::invited(
        space_id,
        sam_id,
        SpaceRole::Owner,
        CustomPermissions::NONE,
        sam_id,
        now,
    );
    owner.state = MemberState::Confirmed;
    let mut invitee = Member::invited(
        space_id,
        ana_id,
        SpaceRole::Member,
        CustomPermissions::NONE,
        sam_id,
        now,
    );
    invitee.state = ana;
    if ana != MemberState::Invited {
        invitee.accepted_at = Some(now);
    }
    let existing = SpaceState {
        space: Space {
            id: space_id,
            name: vec![0; 28],
            key_version: 1,
            keys_pending_since: None,
            created_at: now,
            updated_at: now,
        },
        members: vec![owner, invitee],
        groups: Vec::new(),
        collections: Vec::new(),
        grants: Vec::new(),
    };
    let batch = Batch {
        seals: &seals,
        names: &[],
    };
    project(space_id, Some(&existing), &[], &state, batch, now)
}

#[test]
fn a_member_who_has_not_accepted_stays_invited_though_the_chain_confirms_them() {
    let changes = project_with(MemberState::Invited);
    let ana = UserId(Uuid::from_bytes(ANA));
    // Her row is left as it is, or written invited: never confirmed, never holding the key.
    for row in changes.members.iter().filter(|m| m.user == ana) {
        assert_eq!(row.state, MemberState::Invited, "{row:?}");
        assert!(row.sealed_space_key.is_none() && row.confirmation.is_none());
        assert!(row.accepted_at.is_none());
    }
}

#[test]
fn no_collection_key_is_stored_for_a_member_who_has_not_accepted() {
    let ana = UserId(Uuid::from_bytes(ANA));
    let changes = project_with(MemberState::Invited);
    assert!(
        changes.key_copies.iter().all(|copy| copy.user != ana),
        "{:?}",
        changes.key_copies
    );
}

#[test]
fn a_member_who_accepted_is_confirmed_and_gets_the_key_when_the_chain_confirms_them() {
    let ana = UserId(Uuid::from_bytes(ANA));
    let changes = project_with(MemberState::Accepted);
    let row = changes
        .members
        .iter()
        .find(|m| m.user == ana)
        .expect("ana's row changes");
    assert_eq!(row.state, MemberState::Confirmed);
    assert!(changes.key_copies.iter().any(|copy| copy.user == ana));
}
