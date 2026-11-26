//! Signed key boxes: every sealed space key and collection key a client sends for a space with no
//! chain carries the sealing member's signature, which the server checks and keeps beside the box
//! (docs/crypto.md, "Signed key boxes"). The check itself is `kemlock-crypto`'s and is covered with
//! real keys in the API tests; here the fake accepts `signature()` only.

mod fakes;
mod space_fakes;

use fakes::actor;
use kemlock_app::spaces::{
    CreateCollectionInput, CreateSpaceInput, InviteInput, NewCollection, SpacesError,
};
use kemlock_domain::spaces::{
    CONFIRMATION_SIGNATURE_LEN, CollectionId, CollectionPermission, CustomPermissions, Grantee,
    KeyBoxSignature, MemberState, SpaceError, SpaceRole,
};
use kemlock_domain::{SpaceId, UserId};
use space_fakes::{SpaceWorld, key_for, name, sealed_key, signature};

fn signed_by(who: UserId) -> Option<KeyBoxSignature> {
    Some(KeyBoxSignature {
        by: who,
        key_version: 1,
        signature: signature(),
    })
}

fn wrong() -> Vec<u8> {
    vec![0x66; CONFIRMATION_SIGNATURE_LEN]
}

fn invalid<T: std::fmt::Debug>(result: Result<T, SpacesError>) -> bool {
    matches!(result, Err(SpacesError::Rule(SpaceError::Invalid(_))))
}

fn new_space(space: SpaceId, collection: CollectionId) -> CreateSpaceInput {
    CreateSpaceInput {
        id: space,
        name: name(1),
        sealed_space_key: sealed_key(2),
        space_key_signature: signature(),
        collection: NewCollection {
            id: collection,
            name: name(3),
            sealed_key: sealed_key(4),
            key_signature: signature(),
        },
    }
}

#[tokio::test]
async fn a_new_space_keeps_who_sealed_both_of_its_keys() {
    let w = SpaceWorld::new();
    let sam = w.user("sam@example.org").await;
    let (space, everyone) = w.make_space(sam).await;

    let owner = w.spaces.member(space, sam).expect("the owner");
    assert_eq!(owner.sealed_by, signed_by(sam));
    let copy = w.spaces.copy(everyone, sam).expect("the owner's copy");
    assert_eq!(copy.sealed_by, signed_by(sam));
}

#[tokio::test]
async fn a_space_is_not_made_with_a_key_nobody_signed() {
    let w = SpaceWorld::new();
    let sam = w.user("sam@example.org").await;

    let mut bad_space_key = new_space(SpaceId::random(), CollectionId::random());
    bad_space_key.space_key_signature = wrong();
    assert!(invalid(
        w.create_space().execute(&actor(sam), bad_space_key).await
    ));

    let mut bad_collection_key = new_space(SpaceId::random(), CollectionId::random());
    bad_collection_key.collection.key_signature = wrong();
    assert!(invalid(
        w.create_space()
            .execute(&actor(sam), bad_collection_key)
            .await
    ));

    // A signature of the wrong length never reaches the verifier.
    let mut short = new_space(SpaceId::random(), CollectionId::random());
    short.space_key_signature = vec![1; 10];
    assert!(invalid(w.create_space().execute(&actor(sam), short).await));

    // Nothing was made: Sam has no space.
    let listed = w
        .list_spaces()
        .execute(&actor(sam))
        .await
        .expect("the list");
    assert!(listed.is_empty());
}

/// Sam invites Ana to `space` with Edit on `everyone`, and Ana accepts.
async fn invited_and_accepted(w: &SpaceWorld, space: SpaceId, everyone: CollectionId, sam: UserId, ana: UserId) {
    let email = w
        .world
        .store
        .user(ana)
        .expect("Ana exists")
        .email
        .as_str()
        .to_owned();
    w.invite()
        .execute(
            &actor(sam),
            space,
            InviteInput {
                email,
                role: SpaceRole::Member,
                custom: CustomPermissions::NONE,
                grants: vec![(everyone, CollectionPermission::Edit)],
            },
        )
        .await
        .expect("the invitation is made");
    w.accept()
        .execute(&actor(ana), space)
        .await
        .expect("the invitation is accepted");
}

#[tokio::test]
async fn a_confirmation_keeps_the_confirmers_signature_on_each_box_it_seals() {
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

    let member = w.spaces.member(space, ana).expect("Ana");
    assert_eq!(member.state, MemberState::Confirmed);
    assert_eq!(member.sealed_by, signed_by(sam));
    let copy = w.spaces.copy(everyone, ana).expect("Ana's copy");
    assert_eq!(copy.sealed_by, signed_by(sam));
}

#[tokio::test]
async fn a_confirmation_with_an_unsigned_box_confirms_nobody() {
    let w = SpaceWorld::new();
    let sam = w.user("sam@example.org").await;
    let ana = w.user("ana@example.org").await;
    let (space, everyone) = w.make_space(sam).await;
    invited_and_accepted(&w, space, everyone, sam, ana).await;

    let mut bad_space_key = w.confirm_input(ana, vec![key_for(everyone, ana, 5)]);
    bad_space_key.space_key_signature = wrong();
    assert!(invalid(
        w.confirm()
            .execute(&actor(sam), space, ana, bad_space_key)
            .await
    ));

    let mut bad_collection_key = key_for(everyone, ana, 5);
    bad_collection_key.signature = wrong();
    assert!(invalid(
        w.confirm()
            .execute(
                &actor(sam),
                space,
                ana,
                w.confirm_input(ana, vec![bad_collection_key])
            )
            .await
    ));

    let member = w.spaces.member(space, ana).expect("Ana");
    assert_eq!(member.state, MemberState::Accepted);
    assert!(member.sealed_space_key.is_none() && member.sealed_by.is_none());
    assert!(w.spaces.copy(everyone, ana).is_none());
}

#[tokio::test]
async fn a_collection_key_copy_is_signed_by_whoever_sealed_it() {
    let w = SpaceWorld::new();
    let sam = w.user("sam@example.org").await;
    let (space, _) = w.make_space(sam).await;

    let id = CollectionId::random();
    let mut unsigned = key_for(id, sam, 6);
    unsigned.signature = wrong();
    let input = |keys| CreateCollectionInput {
        id,
        parent: None,
        name: name(10),
        grants: vec![(Grantee::Member(sam), CollectionPermission::Manage)],
        keys,
    };
    assert!(invalid(
        w.create_collection()
            .execute(&actor(sam), space, input(vec![unsigned]))
            .await
    ));
    w.create_collection()
        .execute(&actor(sam), space, input(vec![key_for(id, sam, 6)]))
        .await
        .expect("the collection is made");
    let copy = w.spaces.copy(id, sam).expect("Sam's copy");
    assert_eq!(copy.sealed_by, signed_by(sam));
}

#[tokio::test]
async fn the_creator_of_a_collection_always_holds_manage_on_it() {
    let w = SpaceWorld::new();
    let sam = w.user("sam@example.org").await;
    let (space, _) = w.make_space(sam).await;

    // Listing themselves below Manage doesn't take it away: the grantees' clients accept the
    // creator's key boxes only from a member who may manage the collection.
    let id = CollectionId::random();
    w.create_collection()
        .execute(
            &actor(sam),
            space,
            CreateCollectionInput {
                id,
                parent: None,
                name: name(10),
                grants: vec![(Grantee::Member(sam), CollectionPermission::View)],
                keys: vec![key_for(id, sam, 6)],
            },
        )
        .await
        .expect("the collection is made");
    let grants: Vec<_> = w
        .spaces
        .state(space)
        .grants
        .into_iter()
        .filter(|g| g.collection == id)
        .collect();
    assert_eq!(grants.len(), 1);
    assert_eq!(grants[0].grantee, Grantee::Member(sam));
    assert_eq!(grants[0].permission, CollectionPermission::Manage);
}
