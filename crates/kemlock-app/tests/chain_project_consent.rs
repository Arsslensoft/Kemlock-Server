//! The projection of a chain onto the server's tables keeps a member the chain holds as confirmed
//! `invited` until they have accepted: the invitee's consent is the server's own step, and a policy
//! or a key binds no one before it.

mod chain_kit;

use chain_kit::{Chain, Person};
use kemlock_app::spaces::chain_project::{Batch, project};
use kemlock_crypto::space_chain::{Role, State};
use kemlock_domain::spaces::{CustomPermissions, Member, MemberState, Space, SpaceRole, SpaceState};
use kemlock_domain::{SpaceId, UserId};
use time::OffsetDateTime;
use uuid::Uuid;

const SAM: [u8; 16] = [1; 16];
const ANA: [u8; 16] = [2; 16];

/// The space after `create`, `invite(ana)` and `confirm(ana)`, with `ana`'s stored row in `ana`.
fn project_with(ana: MemberState) -> Vec<Member> {
    let space_id = SpaceId(Uuid::from_bytes([9; 16]));
    let sam = Person::new(SAM, 1);
    let ana_person = Person::new(ANA, 2);
    let mut chain = Chain::new(*space_id.0.as_bytes(), 0);
    let steps = [
        chain.create(&sam, [7; 16]),
        chain.invite(&sam, ANA, Role::Member),
        chain.confirm(&sam, &ana_person),
    ];
    let mut state = State::empty();
    for step in &steps {
        state = state
            .apply(space_id.0.as_bytes(), &step.record)
            .expect("a valid record")
            .state;
    }

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
        seals: &[],
        names: &[],
    };
    project(space_id, Some(&existing), &[], &state, batch, now).members
}

#[test]
fn a_member_who_has_not_accepted_stays_invited_though_the_chain_confirms_them() {
    let rows = project_with(MemberState::Invited);
    let ana = UserId(Uuid::from_bytes(ANA));
    // Her row is left as it is, or written invited: never confirmed, never holding the key.
    for row in rows.iter().filter(|m| m.user == ana) {
        assert_eq!(row.state, MemberState::Invited, "{row:?}");
        assert!(row.sealed_space_key.is_none() && row.confirmation.is_none());
        assert!(row.accepted_at.is_none());
    }
}

#[test]
fn a_member_who_accepted_is_confirmed_when_the_chain_confirms_them() {
    let rows = project_with(MemberState::Accepted);
    let ana = rows
        .iter()
        .find(|m| m.user == UserId(Uuid::from_bytes(ANA)))
        .expect("ana's row changes");
    assert_eq!(ana.state, MemberState::Confirmed);
}
