//! Spaces: creating, inviting, accepting, confirming, changing roles and taking members out.

mod fakes;
mod space_fakes;

use fakes::actor;
use kemlock_app::spaces::{CreateSpaceInput, InviteInput, NewCollection, SpacesError};
use kemlock_domain::spaces::{
    CollectionGrant, CollectionId, CollectionPermission, CustomPermissions, Grantee, Member,
    MemberState, SEALED_KEY_LEN, SpaceError, SpaceRole,
};
use kemlock_domain::{ItemId, SpaceId, UserId};
use space_fakes::{SpaceWorld, key_for, name, sealed_key, signature};

async fn change(
    w: &SpaceWorld,
    space: SpaceId,
    by: UserId,
    target: UserId,
    role: SpaceRole,
) -> Result<Member, SpacesError> {
    w.change_role()
        .execute(&actor(by), space, target, role, CustomPermissions::NONE)
        .await
}

fn invite(email: &str, role: SpaceRole) -> InviteInput {
    InviteInput {
        email: email.to_owned(),
        role,
        custom: CustomPermissions::NONE,
        grants: Vec::new(),
    }
}

#[tokio::test]
async fn a_new_space_has_a_confirmed_owner_who_holds_both_keys() {
    let w = SpaceWorld::new();
    let sam = w.user("sam@example.org").await;
    let (space, everyone) = w.make_space(sam).await;

    let state = w.spaces.state(space);
    assert_eq!(state.members.len(), 1);
    let owner = &state.members[0];
    assert_eq!(owner.user, sam);
    assert_eq!(owner.role, SpaceRole::Owner);
    assert_eq!(owner.state, MemberState::Confirmed);
    assert_eq!(owner.key_version, Some(1));
    assert_eq!(
        owner.sealed_space_key.as_ref().map(Vec::len),
        Some(SEALED_KEY_LEN)
    );

    assert_eq!(state.collections.len(), 1);
    assert_eq!(state.collections[0].id, everyone);
    assert_eq!(state.collections[0].key_version, 1);
    // The maker holds the collection by an explicit Manage grant, and holds its key.
    assert_eq!(
        state.grants,
        vec![CollectionGrant {
            collection: everyone,
            grantee: Grantee::Member(sam),
            permission: CollectionPermission::Manage,
        }]
    );
    assert_eq!(w.spaces.holders_of(everyone).len(), 1);
    assert!(
        w.world
            .store
            .events()
            .iter()
            .any(|e| e.action == "space.create" && e.actor == Some(sam))
    );
}

#[tokio::test]
async fn a_space_id_is_taken_once_and_keys_must_look_sealed() {
    let w = SpaceWorld::new();
    let sam = w.user("sam@example.org").await;
    let (space, _) = w.make_space(sam).await;
    let again = w
        .create_space()
        .execute(
            &actor(sam),
            CreateSpaceInput {
                id: space,
                name: name(1),
                sealed_space_key: sealed_key(2),
                space_key_signature: signature(),
                collection: NewCollection {
                    id: CollectionId::random(),
                    name: name(3),
                    sealed_key: sealed_key(4),
                    key_signature: signature(),
                },
            },
        )
        .await;
    assert_eq!(again.err(), Some(SpacesError::Duplicate));

    let short = w
        .create_space()
        .execute(
            &actor(sam),
            CreateSpaceInput {
                id: SpaceId::random(),
                name: name(1),
                sealed_space_key: vec![1; 10],
                space_key_signature: signature(),
                collection: NewCollection {
                    id: CollectionId::random(),
                    name: name(3),
                    sealed_key: sealed_key(4),
                    key_signature: signature(),
                },
            },
        )
        .await;
    assert!(matches!(
        short.err(),
        Some(SpacesError::Rule(SpaceError::Invalid(_)))
    ));
}

#[tokio::test]
async fn an_invitation_grants_nothing() {
    let w = SpaceWorld::new();
    let sam = w.user("sam@example.org").await;
    let ana = w.user("ana@example.org").await;
    let (space, everyone) = w.make_space(sam).await;

    let member = w
        .invite()
        .execute(
            &actor(sam),
            space,
            InviteInput {
                grants: vec![(everyone, CollectionPermission::Edit)],
                ..invite("ana@example.org", SpaceRole::Member)
            },
        )
        .await
        .expect("an owner invites");
    assert_eq!(member.state, MemberState::Invited);
    assert_eq!(member.invited_by, sam);
    assert_eq!(member.sealed_space_key, None);
    // The grant exists, but no key is sealed to Ana.
    let state = w.spaces.state(space);
    assert!(
        state
            .grants
            .iter()
            .any(|g| g.grantee == Grantee::Member(ana))
    );
    assert!(!w.spaces.holders_of(everyone).contains(&ana));
    // And she isn't among the owners she could sync.
    assert_eq!(
        w.sync_owners().execute(ana).await.expect("owners"),
        vec![kemlock_domain::Owner::User(ana)]
    );
}

#[tokio::test]
async fn who_may_invite_is_a_matter_of_role() {
    let w = SpaceWorld::new();
    let sam = w.user("sam@example.org").await;
    let mina = w.user("mina@example.org").await;
    let _lee = w.user("lee@example.org").await;
    let (space, _) = w.make_space(sam).await;
    w.join(space, sam, sam, mina, SpaceRole::Member, Vec::new())
        .await;

    // A member can't invite; an owner can't invite an owner; nobody invites a stranger's address;
    // nobody is invited twice.
    let by_member = w
        .invite()
        .execute(
            &actor(mina),
            space,
            invite("lee@example.org", SpaceRole::Member),
        )
        .await;
    assert!(matches!(
        by_member.err(),
        Some(SpacesError::Rule(SpaceError::Forbidden(_)))
    ));
    let owner_role = w
        .invite()
        .execute(
            &actor(sam),
            space,
            invite("lee@example.org", SpaceRole::Owner),
        )
        .await;
    assert!(matches!(
        owner_role.err(),
        Some(SpacesError::Rule(SpaceError::Forbidden(_)))
    ));
    let unknown = w
        .invite()
        .execute(
            &actor(sam),
            space,
            invite("nobody@example.org", SpaceRole::Member),
        )
        .await;
    assert_eq!(unknown.err(), Some(SpacesError::NotFound));
    let again = w
        .invite()
        .execute(
            &actor(sam),
            space,
            invite("mina@example.org", SpaceRole::Member),
        )
        .await;
    assert!(matches!(
        again.err(),
        Some(SpacesError::Rule(SpaceError::State(_)))
    ));
    // An admin invites an admin.
    w.join(space, sam, sam, _lee, SpaceRole::Admin, Vec::new())
        .await;
}

#[tokio::test]
async fn an_invitation_may_carry_grants_the_inviter_manages() {
    let w = SpaceWorld::new();
    let sam = w.user("sam@example.org").await;
    let mina = w.user("mina@example.org").await;
    let _lee = w.user("lee@example.org").await;
    let _zed = w.user("zed@example.org").await;
    let (space, everyone) = w.make_space(sam).await;
    // Mina is an admin with no grant on Everyone, but owners and admins manage every collection.
    w.join(space, sam, sam, mina, SpaceRole::Admin, Vec::new())
        .await;
    let ok = w
        .invite()
        .execute(
            &actor(mina),
            space,
            InviteInput {
                grants: vec![(everyone, CollectionPermission::View)],
                ..invite("lee@example.org", SpaceRole::Member)
            },
        )
        .await;
    assert!(ok.is_ok());
    // A collection that doesn't exist, or one named twice, is refused.
    let missing = w
        .invite()
        .execute(
            &actor(sam),
            space,
            InviteInput {
                grants: vec![(CollectionId::random(), CollectionPermission::View)],
                ..invite("zed@example.org", SpaceRole::Member)
            },
        )
        .await;
    assert!(matches!(
        missing.err(),
        Some(SpacesError::Rule(SpaceError::Invalid(_)))
    ));
    let twice = w
        .invite()
        .execute(
            &actor(sam),
            space,
            InviteInput {
                grants: vec![
                    (everyone, CollectionPermission::View),
                    (everyone, CollectionPermission::Edit),
                ],
                ..invite("zed@example.org", SpaceRole::Member)
            },
        )
        .await;
    assert!(matches!(
        twice.err(),
        Some(SpacesError::Rule(SpaceError::Invalid(_)))
    ));
}

#[tokio::test]
async fn a_custom_member_who_manages_users_invites_only_below_themselves() {
    let w = SpaceWorld::new();
    let sam = w.user("sam@example.org").await;
    let cleo = w.user("cleo@example.org").await;
    let _lee = w.user("lee@example.org").await;
    let _zed = w.user("zed@example.org").await;
    let (space, everyone) = w.make_space(sam).await;
    // Sam makes Cleo a Custom member who manages users.
    w.invite()
        .execute(
            &actor(sam),
            space,
            InviteInput {
                custom: CustomPermissions::MANAGE_USERS,
                ..invite("cleo@example.org", SpaceRole::Custom)
            },
        )
        .await
        .expect("invited");
    w.accept()
        .execute(&actor(cleo), space)
        .await
        .expect("accepts");
    w.confirm()
        .execute(&actor(sam), space, cleo, w.confirm_input(cleo, Vec::new()))
        .await
        .expect("confirmed");

    let member = w
        .invite()
        .execute(
            &actor(cleo),
            space,
            invite("lee@example.org", SpaceRole::Member),
        )
        .await
        .expect("Cleo invites a member");
    assert_eq!(member.invited_by, cleo);
    // Not an admin, and not a grant of a collection she holds no Manage on.
    let admin = w
        .invite()
        .execute(
            &actor(cleo),
            space,
            invite("zed@example.org", SpaceRole::Admin),
        )
        .await;
    assert!(matches!(
        admin.err(),
        Some(SpacesError::Rule(SpaceError::Forbidden(_)))
    ));
    let granted = w
        .invite()
        .execute(
            &actor(cleo),
            space,
            InviteInput {
                grants: vec![(everyone, CollectionPermission::View)],
                ..invite("zed@example.org", SpaceRole::Member)
            },
        )
        .await;
    assert!(matches!(
        granted.err(),
        Some(SpacesError::Rule(SpaceError::Forbidden(_)))
    ));
    // She confirms the member she invited, because she manages members.
    w.accept()
        .execute(&actor(_lee), space)
        .await
        .expect("accepts");
    w.confirm()
        .execute(&actor(cleo), space, _lee, w.confirm_input(_lee, Vec::new()))
        .await
        .expect("a Custom member with Manage users confirms a member");
}

#[tokio::test]
async fn accepting_moves_an_invitation_forward_once() {
    let w = SpaceWorld::new();
    let sam = w.user("sam@example.org").await;
    let ana = w.user("ana@example.org").await;
    let (space, _) = w.make_space(sam).await;
    w.invite()
        .execute(
            &actor(sam),
            space,
            invite("ana@example.org", SpaceRole::Member),
        )
        .await
        .expect("invited");

    let accepted = w
        .accept()
        .execute(&actor(ana), space)
        .await
        .expect("accepts");
    assert_eq!(accepted.state, MemberState::Accepted);
    assert!(accepted.accepted_at.is_some());
    // Accepting twice changes nothing.
    let twice = w
        .accept()
        .execute(&actor(ana), space)
        .await
        .expect("idempotent");
    assert_eq!(twice, accepted);
    // Someone who wasn't invited has nothing to accept; a confirmed member has nothing left to.
    let stranger = w.user("lee@example.org").await;
    assert_eq!(
        w.accept().execute(&actor(stranger), space).await.err(),
        Some(SpacesError::NotFound)
    );
    assert!(matches!(
        w.accept().execute(&actor(sam), space).await.err(),
        Some(SpacesError::Rule(SpaceError::State(_)))
    ));
}

#[tokio::test]
async fn confirming_seals_the_keys_and_keeps_the_signed_statement() {
    let w = SpaceWorld::new();
    let sam = w.user("sam@example.org").await;
    let ana = w.user("ana@example.org").await;
    let (space, everyone) = w.make_space(sam).await;
    w.join(
        space,
        sam,
        sam,
        ana,
        SpaceRole::Member,
        vec![(everyone, CollectionPermission::Edit)],
    )
    .await;

    let member = w.spaces.member(space, ana).expect("Ana is a member");
    assert_eq!(member.state, MemberState::Confirmed);
    assert_eq!(member.key_version, Some(1));
    assert_eq!(
        member.sealed_space_key.as_ref().map(Vec::len),
        Some(SEALED_KEY_LEN)
    );
    let confirmation = member.confirmation.expect("a confirmation is stored");
    assert_eq!(confirmation.by, sam);
    assert_eq!(confirmation.fingerprint, w.fingerprint_of(ana));
    assert_eq!(
        confirmation.statement,
        b"I compared the fingerprint".to_vec()
    );
    assert_eq!(confirmation.signature, space_fakes::signature());
    assert_eq!(confirmation.member_key_version, 1);
    let copy = w
        .spaces
        .copy(everyone, ana)
        .expect("a collection key is sealed to Ana");
    assert_eq!(copy.key_version, 1);
    // Now Ana syncs the space.
    assert_eq!(
        w.sync_owners().execute(ana).await.expect("owners"),
        vec![
            kemlock_domain::Owner::User(ana),
            kemlock_domain::Owner::Space(space)
        ]
    );
}

#[tokio::test]
async fn a_fingerprint_that_is_not_the_members_seals_nothing() {
    let w = SpaceWorld::new();
    let sam = w.user("sam@example.org").await;
    let ana = w.user("ana@example.org").await;
    let theo = w.user("theo@example.org").await;
    let (space, _) = w.make_space(sam).await;
    w.invite()
        .execute(
            &actor(sam),
            space,
            invite("ana@example.org", SpaceRole::Member),
        )
        .await
        .expect("invited");
    w.accept()
        .execute(&actor(ana), space)
        .await
        .expect("accepts");

    // Sam compared Theo's fingerprint, not Ana's.
    let mut input = w.confirm_input(ana, Vec::new());
    input.fingerprint = w.fingerprint_of(theo);
    let refused = w.confirm().execute(&actor(sam), space, ana, input).await;
    assert_eq!(
        refused.err(),
        Some(SpacesError::Rule(SpaceError::FingerprintMismatch))
    );
    let member = w.spaces.member(space, ana).expect("still a member");
    assert_eq!(member.state, MemberState::Accepted);
    assert_eq!(member.sealed_space_key, None);
    assert_eq!(member.confirmation, None);

    // A fingerprint of the wrong length is no better.
    let mut short = w.confirm_input(ana, Vec::new());
    short.fingerprint.truncate(10);
    assert_eq!(
        w.confirm()
            .execute(&actor(sam), space, ana, short)
            .await
            .err(),
        Some(SpacesError::Rule(SpaceError::FingerprintMismatch))
    );
}

#[tokio::test]
async fn confirming_needs_exactly_the_keys_of_the_granted_collections() {
    let w = SpaceWorld::new();
    let sam = w.user("sam@example.org").await;
    let ana = w.user("ana@example.org").await;
    let (space, everyone) = w.make_space(sam).await;
    w.invite()
        .execute(
            &actor(sam),
            space,
            InviteInput {
                grants: vec![(everyone, CollectionPermission::View)],
                ..invite("ana@example.org", SpaceRole::Member)
            },
        )
        .await
        .expect("invited");
    w.accept()
        .execute(&actor(ana), space)
        .await
        .expect("accepts");

    // No key for the collection she is granted; a key for one she isn't; the same key twice.
    let missing = w.confirm_input(ana, Vec::new());
    let extra = w.confirm_input(
        ana,
        vec![
            key_for(everyone, ana, 5),
            key_for(CollectionId::random(), ana, 5),
        ],
    );
    let twice = w.confirm_input(
        ana,
        vec![key_for(everyone, ana, 5), key_for(everyone, ana, 6)],
    );
    let mut malformed = w.confirm_input(ana, vec![key_for(everyone, ana, 5)]);
    malformed.collection_keys[0].sealed.truncate(100);
    for input in [missing, extra, twice, malformed] {
        let refused = w.confirm().execute(&actor(sam), space, ana, input).await;
        assert!(
            matches!(
                refused.err(),
                Some(SpacesError::Rule(SpaceError::Invalid(_)))
            ),
            "refused"
        );
    }
    assert_eq!(
        w.spaces.member(space, ana).expect("a member").state,
        MemberState::Accepted
    );
}

#[tokio::test]
async fn only_someone_who_manages_the_member_confirms_and_never_oneself() {
    let w = SpaceWorld::new();
    let sam = w.user("sam@example.org").await;
    let mina = w.user("mina@example.org").await;
    let ana = w.user("ana@example.org").await;
    let (space, _) = w.make_space(sam).await;
    w.join(space, sam, sam, mina, SpaceRole::Member, Vec::new())
        .await;
    w.invite()
        .execute(
            &actor(sam),
            space,
            invite("ana@example.org", SpaceRole::Member),
        )
        .await
        .expect("invited");
    w.accept()
        .execute(&actor(ana), space)
        .await
        .expect("accepts");

    let by_member = w
        .confirm()
        .execute(&actor(mina), space, ana, w.confirm_input(ana, Vec::new()))
        .await;
    assert!(matches!(
        by_member.err(),
        Some(SpacesError::Rule(SpaceError::Forbidden(_)))
    ));
    let by_self = w
        .confirm()
        .execute(&actor(ana), space, ana, w.confirm_input(ana, Vec::new()))
        .await;
    assert_eq!(
        by_self.err(),
        Some(SpacesError::Rule(SpaceError::NotAMember))
    );
    // An unconfirmed account can't confirm anyone.
    let by_sam_for_sam = w
        .confirm()
        .execute(&actor(sam), space, sam, w.confirm_input(sam, Vec::new()))
        .await;
    assert!(by_sam_for_sam.is_err());
}

#[tokio::test]
async fn a_confirmed_member_is_confirmed_again_by_someone_who_manages_them_now() {
    let w = SpaceWorld::new();
    let sam = w.user("sam@example.org").await;
    let mina = w.user("mina@example.org").await;
    let ana = w.user("ana@example.org").await;
    let (space, everyone) = w.make_space(sam).await;
    w.join(
        space,
        sam,
        sam,
        ana,
        SpaceRole::Member,
        vec![(everyone, CollectionPermission::View)],
    )
    .await;
    w.join(space, sam, sam, mina, SpaceRole::Member, Vec::new())
        .await;
    let before = w.spaces.copy(everyone, ana).expect("a copy");

    // Ana is confirmed already; Sam confirms her again with keys sealed anew.
    w.confirm()
        .execute(
            &actor(sam),
            space,
            ana,
            w.confirm_input(ana, vec![key_for(everyone, ana, 0x77)]),
        )
        .await
        .expect("confirmed again");
    let member = w.spaces.member(space, ana).expect("still a member");
    assert_eq!(member.state, MemberState::Confirmed);
    assert_eq!(member.confirmation.expect("a confirmation").by, sam);
    let after = w.spaces.copy(everyone, ana).expect("a copy");
    assert_ne!(after.sealed, before.sealed, "the key is sealed anew");

    // A member can't confirm anyone, again or not; the signature is still checked.
    let by_member = w
        .confirm()
        .execute(
            &actor(mina),
            space,
            ana,
            w.confirm_input(ana, vec![key_for(everyone, ana, 5)]),
        )
        .await;
    assert!(matches!(
        by_member.err(),
        Some(SpacesError::Rule(SpaceError::Forbidden(_)))
    ));
    let mut forged = w.confirm_input(ana, vec![key_for(everyone, ana, 5)]);
    forged.signature = vec![0x66; kemlock_domain::spaces::CONFIRMATION_SIGNATURE_LEN];
    let refused = w.confirm().execute(&actor(sam), space, ana, forged).await;
    assert!(matches!(
        refused.err(),
        Some(SpacesError::Rule(SpaceError::Invalid(_)))
    ));
}

#[tokio::test]
async fn an_owner_is_made_from_a_confirmed_member_by_an_owner() {
    let w = SpaceWorld::new();
    let sam = w.user("sam@example.org").await;
    let mina = w.user("mina@example.org").await;
    let ana = w.user("ana@example.org").await;
    let (space, _) = w.make_space(sam).await;
    w.join(space, sam, sam, mina, SpaceRole::Admin, Vec::new())
        .await;
    w.invite()
        .execute(
            &actor(sam),
            space,
            invite("ana@example.org", SpaceRole::Member),
        )
        .await
        .expect("invited");
    w.accept()
        .execute(&actor(ana), space)
        .await
        .expect("accepts");

    // An admin can't make an owner; an owner can't make one of someone who isn't confirmed.
    assert!(matches!(
        change(&w, space, mina, mina, SpaceRole::Owner).await.err(),
        Some(SpacesError::Rule(SpaceError::Forbidden(_)))
    ));
    assert!(matches!(
        change(&w, space, sam, ana, SpaceRole::Owner).await.err(),
        Some(SpacesError::Rule(SpaceError::State(_)))
    ));
    let made = change(&w, space, sam, mina, SpaceRole::Owner)
        .await
        .expect("an owner makes a confirmed member an owner");
    assert_eq!(made.role, SpaceRole::Owner);
    // Now the first owner can step down, because another is left.
    let stepped = change(&w, space, sam, sam, SpaceRole::Admin)
        .await
        .expect("a second owner exists");
    assert_eq!(stepped.role, SpaceRole::Admin);
    // And the last owner can't.
    assert_eq!(
        change(&w, space, mina, mina, SpaceRole::Member).await.err(),
        Some(SpacesError::Rule(SpaceError::LastOwner))
    );
}

#[tokio::test]
async fn revoking_removes_keys_pauses_the_space_and_lists_what_was_exposed() {
    let w = SpaceWorld::new();
    let sam = w.user("sam@example.org").await;
    let lee = w.user("lee@example.org").await;
    let (space, everyone) = w.make_space(sam).await;
    w.join(
        space,
        sam,
        sam,
        lee,
        SpaceRole::Member,
        vec![(everyone, CollectionPermission::Edit)],
    )
    .await;
    // Two live items and one deleted in the collection Lee can open.
    let versions = [
        (ItemId::random(), false),
        (ItemId::random(), false),
        (ItemId::random(), true),
    ];
    for (id, deleted) in versions {
        w.put_space_item()
            .execute(&actor(lee), everyone, w.item_write(space, id, None, 1, 1))
            .await
            .expect("Lee writes");
        if deleted {
            let mut tombstone = w.item_write(space, id, Some(1), 2, 1);
            tombstone.sealed = None;
            w.put_space_item()
                .execute(&actor(lee), everyone, tombstone)
                .await
                .expect("Lee deletes");
        }
    }

    let outcome = w
        .offboard()
        .revoke(&actor(sam), space, lee)
        .await
        .expect("an owner revokes");
    assert!(outcome.keys_pending);
    assert_eq!(outcome.exposed.len(), 1);
    assert_eq!(outcome.exposed[0].collection, everyone);
    assert_eq!(outcome.exposed[0].live_items, 2);

    let lee_row = w.spaces.member(space, lee).expect("the row stays");
    assert_eq!(lee_row.state, MemberState::Revoked);
    assert_eq!(lee_row.sealed_space_key, None);
    assert_eq!(lee_row.confirmation, None);
    assert!(lee_row.revoked_at.is_some());
    assert!(!w.spaces.holders_of(everyone).contains(&lee));

    let state = w.spaces.state(space);
    assert!(state.space.keys_pending_since.is_some());
    assert!(state.collections[0].stale_since.is_some());
    // Writes are paused until a replacement lands; Lee's devices stop syncing the space.
    let paused = w
        .put_space_item()
        .execute(
            &actor(sam),
            everyone,
            w.item_write(space, ItemId::random(), None, 1, 1),
        )
        .await;
    assert_eq!(
        paused.err(),
        Some(SpacesError::Rule(SpaceError::KeysPending))
    );
    assert_eq!(
        w.sync_owners().execute(lee).await.expect("owners"),
        vec![kemlock_domain::Owner::User(lee)]
    );
    assert!(
        w.world
            .store
            .events()
            .iter()
            .any(|e| e.action == "space.member.revoke")
    );
}

#[tokio::test]
async fn a_revoked_member_can_be_restored_and_must_be_confirmed_again() {
    let w = SpaceWorld::new();
    let sam = w.user("sam@example.org").await;
    let lee = w.user("lee@example.org").await;
    let (space, everyone) = w.make_space(sam).await;
    w.join(
        space,
        sam,
        sam,
        lee,
        SpaceRole::Member,
        vec![(everyone, CollectionPermission::View)],
    )
    .await;
    w.offboard()
        .revoke(&actor(sam), space, lee)
        .await
        .expect("revoked");

    let restored = w
        .offboard()
        .restore(&actor(sam), space, lee)
        .await
        .expect("restored");
    assert_eq!(restored.state, MemberState::Accepted);
    assert_eq!(restored.revoked_at, None);
    assert_eq!(restored.sealed_space_key, None);
    // The space still waits for its key replacement, so confirming Lee again waits too.
    let confirm = w
        .confirm()
        .execute(
            &actor(sam),
            space,
            lee,
            w.confirm_input(lee, vec![key_for(everyone, lee, 5)]),
        )
        .await;
    assert_eq!(
        confirm.err(),
        Some(SpacesError::Rule(SpaceError::KeysPending))
    );
    // A member who isn't revoked can't be restored.
    assert!(matches!(
        w.offboard().restore(&actor(sam), space, sam).await.err(),
        Some(SpacesError::Rule(SpaceError::State(_)))
    ));
}

#[tokio::test]
async fn removing_a_member_clears_their_row_grants_and_keys() {
    let w = SpaceWorld::new();
    let sam = w.user("sam@example.org").await;
    let lee = w.user("lee@example.org").await;
    let (space, everyone) = w.make_space(sam).await;
    w.join(
        space,
        sam,
        sam,
        lee,
        SpaceRole::Member,
        vec![(everyone, CollectionPermission::Edit)],
    )
    .await;

    let outcome = w
        .offboard()
        .remove(&actor(sam), space, lee)
        .await
        .expect("removed");
    assert!(outcome.keys_pending);
    assert_eq!(outcome.exposed.len(), 1);
    assert_eq!(w.spaces.member(space, lee), None);
    let state = w.spaces.state(space);
    assert!(
        state
            .grants
            .iter()
            .all(|g| g.grantee != Grantee::Member(lee))
    );
    assert!(!w.spaces.holders_of(everyone).contains(&lee));
    assert!(state.space.keys_pending_since.is_some());
}

#[tokio::test]
async fn leaving_and_declining_need_no_replacement_unless_keys_were_held() {
    let w = SpaceWorld::new();
    let sam = w.user("sam@example.org").await;
    let ana = w.user("ana@example.org").await;
    let lee = w.user("lee@example.org").await;
    let (space, _) = w.make_space(sam).await;
    // Ana declines before she is confirmed: she held nothing.
    w.invite()
        .execute(
            &actor(sam),
            space,
            invite("ana@example.org", SpaceRole::Member),
        )
        .await
        .expect("invited");
    let declined = w
        .offboard()
        .remove(&actor(ana), space, ana)
        .await
        .expect("declines");
    assert!(!declined.keys_pending);
    assert_eq!(w.spaces.member(space, ana), None);
    assert!(w.spaces.state(space).space.keys_pending_since.is_none());

    // Lee, confirmed, leaves: the keys he held must be replaced.
    w.join(space, sam, sam, lee, SpaceRole::Member, Vec::new())
        .await;
    let left = w
        .offboard()
        .remove(&actor(lee), space, lee)
        .await
        .expect("leaves");
    assert!(left.keys_pending);
    assert!(w.spaces.state(space).space.keys_pending_since.is_some());

    // The only owner can't leave.
    assert_eq!(
        w.offboard().remove(&actor(sam), space, sam).await.err(),
        Some(SpacesError::Rule(SpaceError::LastOwner))
    );
}

#[tokio::test]
async fn a_member_can_not_revoke_remove_or_change_roles() {
    let w = SpaceWorld::new();
    let sam = w.user("sam@example.org").await;
    let mina = w.user("mina@example.org").await;
    let lee = w.user("lee@example.org").await;
    let (space, _) = w.make_space(sam).await;
    w.join(space, sam, sam, mina, SpaceRole::Member, Vec::new())
        .await;
    w.join(space, sam, sam, lee, SpaceRole::Member, Vec::new())
        .await;

    for result in [
        w.offboard()
            .revoke(&actor(mina), space, lee)
            .await
            .map(|_| ()),
        w.offboard()
            .remove(&actor(mina), space, lee)
            .await
            .map(|_| ()),
        w.change_role()
            .execute(
                &actor(mina),
                space,
                lee,
                SpaceRole::Admin,
                CustomPermissions::NONE,
            )
            .await
            .map(|_| ()),
    ] {
        assert!(matches!(
            result.err(),
            Some(SpacesError::Rule(SpaceError::Forbidden(_)))
        ));
    }
    // An outsider learns nothing: a space they aren't in looks like a missing one.
    let outsider = w.user("zed@example.org").await;
    assert_eq!(
        w.offboard()
            .revoke(&actor(outsider), space, lee)
            .await
            .err(),
        Some(SpacesError::Rule(SpaceError::NotAMember))
    );
    assert_eq!(
        w.offboard()
            .revoke(&actor(sam), SpaceId::random(), lee)
            .await
            .err(),
        Some(SpacesError::NotFound)
    );
}

#[tokio::test]
async fn lists_show_each_reader_what_their_role_allows() {
    let w = SpaceWorld::new();
    let sam = w.user("sam@example.org").await;
    let mina = w.user("mina@example.org").await;
    let ana = w.user("ana@example.org").await;
    let theo = w.user("theo@example.org").await;
    let (space, everyone) = w.make_space(sam).await;
    w.join(
        space,
        sam,
        sam,
        mina,
        SpaceRole::Member,
        vec![(everyone, CollectionPermission::View)],
    )
    .await;
    w.invite()
        .execute(
            &actor(sam),
            space,
            invite("ana@example.org", SpaceRole::Member),
        )
        .await
        .expect("invited");
    w.invite()
        .execute(
            &actor(sam),
            space,
            invite("theo@example.org", SpaceRole::Member),
        )
        .await
        .expect("invited");
    w.accept()
        .execute(&actor(theo), space)
        .await
        .expect("accepts");

    // The owner sees every member, whatever their state; a member sees the confirmed ones.
    let all = w
        .list_members()
        .execute(&actor(sam), space)
        .await
        .expect("the owner lists");
    assert_eq!(all.len(), 4);
    let states: Vec<MemberState> = all.iter().map(|m| m.member.state).collect();
    assert!(states.contains(&MemberState::Invited));
    assert!(states.contains(&MemberState::Accepted));
    let theo_view = all.iter().find(|m| m.member.user == theo).expect("Theo");
    assert_eq!(theo_view.email, "theo@example.org");
    assert_eq!(theo_view.public_bundle, fakes::bundle(theo));
    assert!(!theo_view.needs_reconfirmation);
    let visible = w
        .list_members()
        .execute(&actor(mina), space)
        .await
        .expect("a member lists");
    assert_eq!(visible.len(), 2);
    assert!(
        visible
            .iter()
            .all(|m| m.member.state == MemberState::Confirmed)
    );
    // Someone who isn't confirmed lists nothing.
    assert_eq!(
        w.list_members().execute(&actor(theo), space).await.err(),
        Some(SpacesError::Rule(SpaceError::NotAMember))
    );

    // The account's spaces: Ana (invited) sees it, with her own row.
    let summaries = w.list_spaces().execute(&actor(ana)).await.expect("lists");
    assert_eq!(summaries.len(), 1);
    assert_eq!(summaries[0].member.state, MemberState::Invited);
    assert_eq!(summaries[0].space.id, space);

    // A space as its member sees it: Mina holds Everyone and its key; Theo, who only accepted,
    // sees his own row and nothing else.
    let mina_view = w
        .get_space()
        .execute(&actor(mina), space)
        .await
        .expect("view");
    assert_eq!(mina_view.collections.len(), 1);
    assert_eq!(mina_view.collection_keys.len(), 1);
    assert!(mina_view.me.sealed_space_key.is_some());
    let theo_space = w
        .get_space()
        .execute(&actor(theo), space)
        .await
        .expect("view");
    assert!(theo_space.collections.is_empty() && theo_space.collection_keys.is_empty());
    assert_eq!(theo_space.me.sealed_space_key, None);
}

#[tokio::test]
async fn a_member_whose_key_changed_needs_confirming_again() {
    let w = SpaceWorld::new();
    let sam = w.user("sam@example.org").await;
    let mina = w.user("mina@example.org").await;
    let (space, _) = w.make_space(sam).await;
    w.join(space, sam, sam, mina, SpaceRole::Member, Vec::new())
        .await;

    let flags = |views: Vec<kemlock_app::spaces::MemberView>| {
        views
            .into_iter()
            .map(|v| (v.member.user, v.needs_reconfirmation))
            .collect::<Vec<_>>()
    };
    let before = flags(
        w.list_members()
            .execute(&actor(sam), space)
            .await
            .expect("lists"),
    );
    assert!(before.iter().all(|(_, needs)| !needs));

    // Mina's account moves to a new key version: her fingerprint is no longer the one confirmed.
    let mut account = w.world.store.user(mina).expect("Mina's account");
    account.key_version = 2;
    w.world.store.put_user(account);
    let after = flags(
        w.list_members()
            .execute(&actor(sam), space)
            .await
            .expect("lists"),
    );
    assert!(after.contains(&(mina, true)));
    assert!(after.contains(&(sam, false)));
}

#[tokio::test]
async fn a_confirmation_whose_signature_does_not_verify_confirms_nobody() {
    let w = SpaceWorld::new();
    let sam = w.user("sam@example.org").await;
    let ana = w.user("ana@example.org").await;
    let (space, everyone) = w.make_space(sam).await;
    w.invite()
        .execute(
            &actor(sam),
            space,
            InviteInput {
                email: "ana@example.org".to_owned(),
                role: SpaceRole::Member,
                custom: CustomPermissions::NONE,
                grants: vec![(everyone, CollectionPermission::View)],
            },
        )
        .await
        .expect("invited");
    w.accept()
        .execute(&actor(ana), space)
        .await
        .expect("accepts");

    // The right length, but not the confirmer's signature over the statement.
    let mut forged = w.confirm_input(ana, vec![key_for(everyone, ana, 5)]);
    forged.signature = vec![0x66; kemlock_domain::spaces::CONFIRMATION_SIGNATURE_LEN];
    let refused = w.confirm().execute(&actor(sam), space, ana, forged).await;
    assert!(matches!(
        refused.err(),
        Some(SpacesError::Rule(SpaceError::Invalid(_)))
    ));
    let member = w.spaces.member(space, ana).expect("still a member");
    assert_eq!(member.state, MemberState::Accepted);
    assert_eq!(member.confirmation, None);
    assert_eq!(w.spaces.copy(everyone, ana), None, "no key was handed out");

    // The signature the confirmer made does.
    w.confirm()
        .execute(
            &actor(sam),
            space,
            ana,
            w.confirm_input(ana, vec![key_for(everyone, ana, 5)]),
        )
        .await
        .expect("confirmed");
}
