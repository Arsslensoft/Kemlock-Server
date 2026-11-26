//! The spec's 18 test cases and the rest of the verifier, on both backends.
//!
//! The scenarios of [`scenarios::cases`] carry most of them (a chain and a verdict); the tests here
//! add what a verdict can't say: the state a chain gives, key opening, first contact and the
//! limits. The item side of case 12 belongs to the server's item rules, tested in `kemlock-app`.

use std::collections::BTreeSet;

use super::{
    Limits,
    client::{
        AnchorPerson, FirstContact, ItemRefusal, KeyRefusal, anchor_person, check_item_revision,
        open_key_in,
    },
    model::{Body, CollectionPerm, Grantee, Id, KeyRef, Kind, Reason, Record, Role, SignedRecord},
    scenarios::{Case, Expect, cases, oversized, valid_chain, verdict},
    seals::{link, seal_hash},
    state::{CollectionInfo, Member, State, Status},
    testkit::{
        ADMIN, ANA, Account, Kit, LEE, NEWBIE, OWNER, finance, general, space_id, uid, world,
    },
    verify::verify_chain_in,
};
use crate::backend::{Backend, rustcrypto::RustCrypto};

type Gen = RustCrypto;

fn find<'a>(cases: &'a [Case], name: &str) -> &'a Case {
    cases
        .iter()
        .find(|c| c.name == name)
        .unwrap_or_else(|| panic!("no case named {name}"))
}

fn reason_of(case: &Case) -> (Option<u64>, Reason) {
    match case.expect {
        Expect::Refused { seq, reason } => (seq, reason),
        Expect::Accepted { .. } => panic!("{} is accepted", case.name),
    }
}

/// Every scenario gets the verdict it was built for, on every backend, from chains made on the
/// RustCrypto backend (which is what the generator uses).
#[test]
fn every_scenario_gets_its_verdict_on_every_backend() {
    let all = cases::<Gen>();
    assert!(all.len() >= 50, "{} cases", all.len());
    for_backends!(B => {
        for case in &all {
            assert_eq!(verdict::<B>(case), case.expect, "{} on {}", case.name, B::NAME);
        }
    });
}

#[test]
fn the_valid_chain_has_every_kind_once_or_more() {
    let all = cases::<Gen>();
    let valid = find(&all, "valid-every-kind");
    let kinds: BTreeSet<Kind> = valid
        .chain
        .iter()
        .map(|s| Record::parse(&s.entry).expect("a record").kind())
        .collect();
    assert_eq!(kinds, Kind::ALL.into_iter().collect::<BTreeSet<_>>());
    // Every record reads back to its own bytes, and the links chain.
    let mut prev = [0u8; 32];
    for (i, signed) in valid.chain.iter().enumerate() {
        let record = Record::parse(&signed.entry).expect("a record");
        assert_eq!(record.to_bytes(), signed.entry);
        assert_eq!(record.seq, u64::try_from(i).expect("small"));
        assert_eq!(record.prev, prev);
        prev = link(&signed.entry);
    }
    let verified = verify_chain_in::<Gen>(&space_id(), &valid.chain, None).expect("verifies");
    assert_eq!(verified.state.epoch, 2);
    assert!(verified.state.home.is_some());
    assert_eq!(verified.links.len(), valid.chain.len());
    assert_eq!(verified.state.members[&uid(LEE)].status, Status::Removed);
    // Applying one record at a time gives the state the whole-chain check gives.
    let mut state = State::empty();
    for signed in &valid.chain {
        state = state
            .apply_in::<Gen>(&space_id(), signed)
            .expect("applies")
            .state;
    }
    assert_eq!(state, verified.state);
}

// ---- 1 to 5 ------------------------------------------------------------------------------------

#[test]
fn case_1_self_widening_through_a_group() {
    let all = cases::<Gen>();
    for name in [
        "self-widening-through-a-group",
        "grant-to-a-group-they-joined",
    ] {
        assert_eq!(reason_of(find(&all, name)).1, Reason::NotAllowed, "{name}");
    }
}

#[test]
fn case_2_group_access_needs_may_grant() {
    let all = cases::<Gen>();
    assert_eq!(
        reason_of(find(&all, "group-access-needs-may-grant")).1,
        Reason::NotAllowed
    );
    // With manage on Finance the same record is accepted, and Ana awaits Finance's key.
    let with_manage = find(&all, "group-access-with-manage");
    assert!(matches!(with_manage.expect, Expect::Accepted { .. }));
    let state = verify_chain_in::<Gen>(&space_id(), &with_manage.chain, None)
        .expect("verifies")
        .state;
    assert!(
        state
            .awaiting(&KeyRef::Collection(finance()))
            .contains(&uid(ANA))
    );
}

#[test]
fn case_3_owners_change_owners() {
    let all = cases::<Gen>();
    for name in [
        "owners-ungrant",
        "owners-group-members",
        "owners-grant-to-group",
        "owners-demote",
    ] {
        assert_eq!(reason_of(find(&all, name)).1, Reason::NotAllowed, "{name}");
        let by_owner = find(&all, &format!("{name}-by-the-other-owner"));
        assert!(matches!(by_owner.expect, Expect::Accepted { .. }), "{name}");
    }
    for name in ["sole-owner-demoted", "sole-owner-removed"] {
        assert_eq!(reason_of(find(&all, name)).1, Reason::Invalid, "{name}");
    }
}

#[test]
fn case_4_removal_ends_access() {
    let all = cases::<Gen>();
    assert_eq!(
        reason_of(find(&all, "removal-without-replace")).1,
        Reason::Invalid
    );
    let removed = find(&all, "removal-marks-the-keys");
    let state = verify_chain_in::<Gen>(&space_id(), &removed.chain, None)
        .expect("verifies")
        .state;
    let lee = uid(LEE);
    assert_eq!(state.members[&lee].status, Status::Removed);
    assert!(state.grants.keys().all(|(_, g)| *g != Grantee::User(lee)));
    assert!(state.groups_of(&lee).is_empty());
    assert!(state.space.marked);
    assert!(state.collections[&finance()].marked);

    // Inviting Lee again gives them nothing.
    let w = world::<Gen>();
    let mut k = w.clone();
    let remove = k.remove_body(&lee);
    k.ok::<Gen>(&uid(OWNER), remove);
    k.invite::<Gen>(&uid(OWNER), &lee, Role::Member, &[], &[]);
    assert_eq!(k.state.members[&lee].status, Status::Invited);
    assert!(k.state.grants.keys().all(|(_, g)| *g != Grantee::User(lee)));
    assert!(k.state.groups_of(&lee).is_empty());
    assert!(
        k.state
            .entitled(&KeyRef::Collection(finance()))
            .is_disjoint(&BTreeSet::from([lee]))
    );
}

#[test]
fn case_5_a_marked_key_isnt_shared() {
    let all = cases::<Gen>();
    for name in [
        "marked-key-seal",
        "marked-key-confirm",
        "marked-key-grant",
        "keys-without-names",
        "keys-with-a-name-missing",
    ] {
        assert_eq!(reason_of(find(&all, name)).1, Reason::Invalid, "{name}");
    }
    let replaced = find(&all, "keys-clear-both-marks");
    let state = verify_chain_in::<Gen>(&space_id(), &replaced.chain, None)
        .expect("verifies")
        .state;
    assert!(!state.space.marked);
    assert!(!state.collections[&finance()].marked);
    assert_eq!(state.space.key_version, 2);
    assert_eq!(state.collections[&finance()].key_version, 2);
    // Every name takes the hash the record gave, at the new name version.
    assert_eq!(state.space.name_version, 2);
    assert!(state.collections.values().all(|c| c.name_version == 2));
    assert!(state.groups.values().all(|g| g.name_version == 2));
}

// ---- 6: keys come from the chain ---------------------------------------------------------------

#[test]
fn case_6_keys_come_from_the_chain() {
    let owner = uid(OWNER);
    let ana = uid(ANA);
    let mut k = world::<Gen>();
    // The space key at version 3.
    for _ in 0..2 {
        let rotate = k.rotate_body::<Gen>(&[KeyRef::Space]);
        k.ok::<Gen>(&owner, rotate);
    }
    let space = space_id();
    let ana_key = k.acc(&ana).kx.clone();
    let committed = k.state.commitments[&(
        KeyRef::Space,
        3,
        k.state.seals[&(KeyRef::Space, 3, ana)].seq,
    )]
        .clone();
    let list = |k: &Kit, version: u32| -> Vec<(Id, u32, [u8; 32])> {
        committed
            .recipients
            .iter()
            .map(|(m, v)| (*m, *v, seal_hash(&k.boxes[&(KeyRef::Space, version, *m)])))
            .collect()
    };
    let honest = k.boxes[&(KeyRef::Space, 3, ana)].clone();
    let honest_list = list(&k, 3);
    for_backends!(B => {
        // The honest box opens, with the server's list.
        let key = open_key_in::<B>(&k.state, &space, &ana, &ana_key, &KeyRef::Space, 3, &honest, Some(honest_list.as_slice()));
        assert!(key.is_ok(), "{}", B::NAME);
        // Without the list a commitment that covers many members can't be checked.
        assert_eq!(
            open_key_in::<B>(&k.state, &space, &ana, &ana_key, &KeyRef::Space, 3, &honest, None).err(),
            Some(KeyRefusal::HashList)
        );
        // A box at version 2 that opens: the client doesn't use it.
        let old = k.boxes[&(KeyRef::Space, 2, ana)].clone();
        let old_list = list(&k, 2);
        assert_eq!(
            open_key_in::<B>(&k.state, &space, &ana, &ana_key, &KeyRef::Space, 2, &old, Some(old_list.as_slice())).err(),
            Some(KeyRefusal::WrongVersion)
        );
        // A version-3 box whose hash isn't committed.
        let (fake, _) = {
            let mut scratch = k.clone();
            let c = scratch.make::<Gen>(KeyRef::Space, 3, &[ana]);
            (scratch.boxes[&(KeyRef::Space, 3, ana)].clone(), c)
        };
        assert_eq!(
            open_key_in::<B>(&k.state, &space, &ana, &ana_key, &KeyRef::Space, 3, &fake, Some(honest_list.as_slice())).err(),
            Some(KeyRefusal::HashList)
        );
        // A hash list with an extra recipient, or a recipient missing.
        let mut extra = honest_list.clone();
        extra.push((uid(0xEE), 1, [7; 32]));
        extra.sort();
        assert_eq!(
            open_key_in::<B>(&k.state, &space, &ana, &ana_key, &KeyRef::Space, 3, &honest, Some(extra.as_slice())).err(),
            Some(KeyRefusal::HashList)
        );
        let short: Vec<_> = honest_list.iter().filter(|(m, _, _)| *m != uid(ADMIN)).cloned().collect();
        assert_eq!(
            open_key_in::<B>(&k.state, &space, &ana, &ana_key, &KeyRef::Space, 3, &honest, Some(short.as_slice())).err(),
            Some(KeyRefusal::HashList)
        );
        // A box for another member doesn't open for this one.
        let other = k.boxes[&(KeyRef::Space, 3, owner)].clone();
        assert_eq!(
            open_key_in::<B>(&k.state, &space, &ana, &ana_key, &KeyRef::Space, 3, &other, Some(honest_list.as_slice())).err(),
            Some(KeyRefusal::HashList)
        );
        // A key that opens but whose check isn't the chain's.
        let mut tampered = k.state.clone();
        tampered.key_checks.insert((KeyRef::Space, 3), [1; 32]);
        assert_eq!(
            open_key_in::<B>(&tampered, &space, &ana, &ana_key, &KeyRef::Space, 3, &honest, Some(honest_list.as_slice())).err(),
            Some(KeyRefusal::BadCheck)
        );
        // A key the chain has no seal of for this member.
        assert_eq!(
            open_key_in::<B>(&k.state, &space, &uid(0xEE), &ana_key, &KeyRef::Space, 3, &honest, Some(honest_list.as_slice())).err(),
            Some(KeyRefusal::NotCommitted)
        );
    });
}

// ---- 7: items under an old key version ---------------------------------------------------------

#[test]
fn case_7_items_under_an_old_key_version_are_held() {
    let owner = uid(OWNER);
    let lee = uid(LEE);
    let finance = finance();
    let mut k = world::<Gen>();
    // Before anything: a revision under Finance's version 1 is accepted, the others aren't.
    assert_eq!(check_item_revision(&k.state, &finance, 1), Ok(()));
    assert_eq!(
        check_item_revision(&k.state, &finance, 2),
        Err(ItemRefusal::NewKeyVersion)
    );
    assert_eq!(
        check_item_revision(&k.state, &uid(0xEE), 1),
        Err(ItemRefusal::UnknownCollection)
    );

    // Lee leaves. Between the `remove` and the `keys` record a revision under version 1 is held
    // too, though it is the current version: the key is marked.
    let remove = k.remove_body(&lee);
    k.ok::<Gen>(&owner, remove);
    assert_eq!(
        check_item_revision(&k.state, &finance, 1),
        Err(ItemRefusal::KeyMarked)
    );

    // Finance's key moves to version 2, and so does the space key. A revision under version 1 is
    // held, not applied; one under version 2 is accepted.
    let keys = k.rotate_body::<Gen>(&[KeyRef::Space, KeyRef::Collection(finance)]);
    k.ok::<Gen>(&owner, keys);
    assert_eq!(k.state.collections[&finance].key_version, 2);
    assert_eq!(
        check_item_revision(&k.state, &finance, 1),
        Err(ItemRefusal::OldKeyVersion)
    );
    assert_eq!(check_item_revision(&k.state, &finance, 2), Ok(()));
    assert_eq!(
        check_item_revision(&k.state, &finance, 3),
        Err(ItemRefusal::NewKeyVersion)
    );
}

// ---- 8, 9, 10, 14, 15, 16, 17, 18: verdicts ----------------------------------------------------

#[test]
fn cases_8_to_18_have_their_verdicts() {
    let all = cases::<Gen>();
    let table: &[(&str, Reason)] = &[
        ("epoch-raised-by-a-role", Reason::BadEpoch),
        ("fence-epoch-plus-two", Reason::BadEpoch),
        ("fence-same-epoch", Reason::BadEpoch),
        ("lower-epoch", Reason::BadEpoch),
        ("fence-by-an-admin", Reason::NotAllowed),
        ("fence-after-a-divergence", Reason::Forked),
        ("old-home-after-the-fence", Reason::Forked),
        ("rolled-back", Reason::RolledBack),
        ("forked", Reason::Forked),
        ("rekey-then-the-old-key", Reason::BadSignature),
        ("rekey-without-a-cosignature", Reason::Malformed),
        ("rekey-cosigned-by-another-key", Reason::BadSignature),
        ("rekey-to-the-same-key-version", Reason::Invalid),
        ("link-without-its-label", Reason::BadLink),
        ("recovery-on-without-a-key", Reason::Invalid),
        ("recovery-on-by-an-admin", Reason::NotAllowed),
        ("timeout-lock-with-no-minutes", Reason::Invalid),
        ("admin-without-access-replaces-a-key", Reason::NotAllowed),
        ("viewer-replaces-an-unmarked-key", Reason::NotAllowed),
        ("custom-manages-a-wider-custom", Reason::NotAllowed),
        ("unrecorded-key-beats-authority", Reason::BadSignature),
        ("bad-link-beats-bad-signature", Reason::BadLink),
        ("signer-not-in-the-chain", Reason::UnknownSigner),
        ("record-for-another-space", Reason::WrongSpace),
        ("record-skips-a-seq", Reason::BadSequence),
        ("marked-key-seal", Reason::Invalid),
        ("marked-key-confirm", Reason::Invalid),
        ("marked-key-grant", Reason::Invalid),
        ("keys-without-names", Reason::Invalid),
        ("keys-with-a-name-missing", Reason::Invalid),
        ("sole-owner-demoted", Reason::Invalid),
        ("sole-owner-removed", Reason::Invalid),
        ("removal-without-replace", Reason::Invalid),
        ("self-widening-through-a-group", Reason::NotAllowed),
        ("group-access-needs-may-grant", Reason::NotAllowed),
    ];
    for (name, reason) in table.iter().copied() {
        assert_eq!(reason_of(find(&all, name)).1, reason, "{name}");
    }
    for name in [
        "rekey-then-the-new-key",
        "sso-on-by-an-admin",
        "viewer-replaces-a-marked-key",
        "fence-drops-the-old-homes-records",
        "matching-anchor",
    ] {
        assert!(
            matches!(find(&all, name).expect, Expect::Accepted { .. }),
            "{name}"
        );
    }
}

#[test]
fn case_9_a_fence_drops_the_devices_own_records() {
    let all = cases::<Gen>();
    let case = find(&all, "fence-drops-the-old-homes-records");
    let anchor = case.anchor.as_ref().expect("an anchor");
    let verified =
        verify_chain_in::<Gen>(&space_id(), &case.chain, Some(anchor)).expect("accepted");
    let d = verified.divergence.expect("a divergence");
    assert!(d <= anchor.seq);
    assert_eq!(anchor.epoch, 1);
    assert_eq!(verified.state.epoch, 2);
    // The records from the fence to the anchor are the ones the device drops.
    assert_eq!(anchor.seq - d + 1, 3);
}

// ---- 11: one spelling --------------------------------------------------------------------------

#[test]
fn case_11_one_spelling_at_the_wire() {
    // The codec tests refuse every spelling; here a record of the valid chain with one changed
    // byte of its text fails as a signature at its own seq, never as a different record.
    let all = cases::<Gen>();
    let valid = find(&all, "valid-every-kind");
    for at in [0usize, 5, valid.chain.len() / 2, valid.chain.len() - 1] {
        let mut chain = valid.chain.clone();
        let entry = &mut chain[at].entry;
        let i = entry.len() / 2;
        entry[i] ^= 1;
        assert!(
            verify_chain_in::<Gen>(&space_id(), &chain, None).is_err(),
            "{at}"
        );
    }
    // A signature of the wrong length is a bad signature, not a panic.
    let mut chain = valid.chain.clone();
    chain[3].signature.pop();
    let err = verify_chain_in::<Gen>(&space_id(), &chain, None).expect_err("refused");
    assert_eq!((err.seq, err.reason), (Some(3), Reason::BadSignature));
}

// ---- 12: limits --------------------------------------------------------------------------------

#[test]
fn case_12_limits_of_records_and_chains() {
    assert_eq!(
        Record::parse(&vec![b' '; Limits::RECORD_BYTES + 1]),
        Err(Reason::TooLarge)
    );
    let big = oversized(Limits::RECORD_BYTES + 1);
    let err = verify_chain_in::<Gen>(&space_id(), &[big], None).expect_err("refused");
    assert_eq!((err.seq, err.reason), (Some(0), Reason::TooLarge));
    // A chain of 65,537 records is too large before any is read; 65,536 are read (and here
    // malformed, being blank).
    let blank = SignedRecord {
        entry: vec![b' '],
        signature: Vec::new(),
        cosignature: None,
    };
    let long = vec![blank; 65_537];
    let err = verify_chain_in::<Gen>(&space_id(), &long, None).expect_err("refused");
    assert_eq!((err.seq, err.reason), (None, Reason::TooLarge));
    let err = verify_chain_in::<Gen>(&space_id(), &long[..65_536], None).expect_err("refused");
    assert_eq!((err.seq, err.reason), (Some(0), Reason::Malformed));
}

fn stuffed_collection(i: u32) -> (Id, CollectionInfo) {
    let mut id = [0xCC; 16];
    id[..4].copy_from_slice(&i.to_be_bytes());
    (
        id,
        CollectionInfo {
            parent: None,
            name_hash: [0; 32],
            name_version: 1,
            key_version: 1,
            marked: false,
        },
    )
}

#[test]
fn case_12_the_1001st_collection_is_invalid() {
    let owner = uid(OWNER);
    let mut k = world::<Gen>();
    let have = u32::try_from(k.state.collections.len()).expect("few");
    for i in 0..(998 - have + 1) {
        let (id, info) = stuffed_collection(i);
        k.state.collections.insert(id, info);
    }
    assert_eq!(k.state.collections.len(), 998 + 1);
    // The 1,000th is accepted.
    let body = k.collection_body::<Gen>(
        uid(0xD0),
        "one more",
        &[(Grantee::User(owner), CollectionPerm::Manage)],
        None,
    );
    k.ok::<Gen>(&owner, body);
    assert_eq!(k.state.collections.len(), 1000);
    // The 1,001st is not.
    let body = k.collection_body::<Gen>(
        uid(0xD1),
        "too many",
        &[(Grantee::User(owner), CollectionPerm::Manage)],
        None,
    );
    let (_, result) = k.attempt::<Gen>(&owner, body);
    assert_eq!(result.expect_err("refused").reason, Reason::Invalid);
}

#[test]
fn case_12_the_10001st_member_is_invalid() {
    let owner = uid(OWNER);
    let mut k = world::<Gen>();
    let in_space = k.state.members.len();
    let stuffed = |i: u32| -> (Id, Member) {
        let mut id = [0xBB; 16];
        id[..4].copy_from_slice(&i.to_be_bytes());
        (
            id,
            Member {
                role: Role::Member,
                custom: BTreeSet::new(),
                status: Status::Invited,
                invited_by: uid(OWNER),
                bundle: None,
                bundle_signature: Vec::new(),
                confirmation: None,
                rekey_seq: None,
            },
        )
    };
    // The world has 8 members and two accounts that aren't invited yet; fill to 9,999.
    for i in 0..u32::try_from(9_999 - in_space).expect("few") {
        let (id, member) = stuffed(i);
        k.state.members.insert(id, member);
    }
    k.add(Account::new::<Gen>(NEWBIE, 1));
    k.invite::<Gen>(&owner, &uid(NEWBIE), Role::Member, &[], &[]);
    assert_eq!(
        k.state
            .members
            .values()
            .filter(|m| m.status != Status::Removed)
            .count(),
        10_000
    );
    let (_, result) = k.attempt::<Gen>(
        &owner,
        Body::Invite {
            custom: vec![],
            grants: vec![],
            member: uid(0x0A),
            role: Role::Member,
        },
    );
    assert_eq!(result.expect_err("refused").reason, Reason::Invalid);
}

#[test]
fn collections_nest_at_most_16_deep() {
    let owner = uid(OWNER);
    let mut k = Kit::new(space_id());
    k.add(Account::new::<Gen>(OWNER, 1));
    k.create::<Gen>(&owner, general());
    let mut parent = general();
    for depth in 2..=16u8 {
        let id = uid(0x40 + depth);
        let body = k.collection_body::<Gen>(
            id,
            "nested",
            &[(Grantee::User(owner), CollectionPerm::Manage)],
            Some(parent),
        );
        k.ok::<Gen>(&owner, body);
        parent = id;
    }
    assert_eq!(k.state.depth(&parent), 16);
    let body = k.collection_body::<Gen>(
        uid(0x70),
        "too deep",
        &[(Grantee::User(owner), CollectionPerm::Manage)],
        Some(parent),
    );
    let (_, result) = k.attempt::<Gen>(&owner, body);
    assert_eq!(result.expect_err("refused").reason, Reason::Invalid);
}

// ---- 13: first contact -------------------------------------------------------------------------

#[test]
fn case_13_a_server_made_chain_shows_another_fingerprint() {
    let owner = uid(OWNER);
    let newbie = uid(NEWBIE);
    // The real chain: the owner invites Newbie.
    let mut real = world::<Gen>();
    real.invite::<Gen>(&owner, &newbie, Role::Member, &[], &[]);
    let seen = compare(anchor_person(&real.state, &newbie));
    assert_eq!(seen.person, owner);
    let on_the_owners_screen = real.acc(&owner).bundle.fingerprint();
    assert_eq!(seen.fingerprint, on_the_owners_screen);

    // A hostile server makes a whole space of its own, with the owner's id and its own key.
    let mut fake = Kit::new(space_id());
    fake.add(Account::new::<Gen>(OWNER, 3));
    fake.add(Account::new::<Gen>(NEWBIE, 1));
    fake.create::<Gen>(&owner, general());
    fake.invite::<Gen>(&owner, &newbie, Role::Member, &[], &[]);
    // It verifies, which is why the comparison exists...
    verify_chain_in::<Gen>(&space_id(), &fake.records, None).expect("a consistent chain");
    // ...and the digits differ from the real owner's.
    let shown = compare(anchor_person(&fake.state, &newbie));
    assert_eq!(shown.person, owner);
    assert_ne!(shown.fingerprint, on_the_owners_screen);

    // A confirmed member's new device compares with their confirmer; the creator with no one.
    let confirmed = compare(anchor_person(&real.state, &uid(ANA)));
    assert_eq!(confirmed.person, owner);
    assert_eq!(anchor_person(&real.state, &owner), FirstContact::SelfVouched);
}

#[test]
fn a_rekey_vouches_for_the_chain_on_a_members_own_device() {
    let owner = uid(OWNER);
    let mut k = world::<Gen>();
    assert!(matches!(
        anchor_person(&k.state, &uid(ANA)),
        FirstContact::Compare(_)
    ));
    k.rekey::<Gen>(&uid(ANA));
    assert_eq!(
        anchor_person(&k.state, &uid(ANA)),
        FirstContact::SelfVouched
    );
    // A removed member, and an account the chain doesn't have, are not "no comparison needed":
    // the human picks an Owner.
    let remove = k.remove_body(&uid(LEE));
    k.ok::<Gen>(&owner, remove);
    assert_eq!(anchor_person(&k.state, &uid(LEE)), FirstContact::PickOwner);
    assert_eq!(anchor_person(&k.state, &[0xee; 16]), FirstContact::PickOwner);
}

#[test]
fn an_inviter_who_left_means_picking_an_owner() {
    let owner = uid(OWNER);
    let newbie = uid(NEWBIE);
    let mut k = world::<Gen>();
    k.invite::<Gen>(&uid(ADMIN), &newbie, Role::Member, &[], &[]);
    assert!(matches!(
        anchor_person(&k.state, &newbie),
        FirstContact::Compare(_)
    ));
    // The admin is removed: the invitee can no longer compare with the one who invited them.
    let remove = k.remove_body(&uid(ADMIN));
    k.ok::<Gen>(&owner, remove);
    assert_eq!(anchor_person(&k.state, &newbie), FirstContact::PickOwner);
}

/// The person of a `Compare`, which the case needs.
fn compare(contact: FirstContact) -> AnchorPerson {
    match contact {
        FirstContact::Compare(person) => person,
        other => panic!("expected a comparison, got {other:?}"),
    }
}

// ---- the rest of the verifier ------------------------------------------------------------------

#[test]
fn a_cosignature_belongs_to_a_rekey_only() {
    let owner = uid(OWNER);
    let w = world::<Gen>();
    let rec = w.record(
        &owner,
        Body::Group {
            group: uid(0x31),
            name_hash: [5; 32],
        },
    );
    let mut signed = w.sign::<Gen>(&rec, w.acc(&owner), Some(w.acc(&owner)));
    assert!(signed.cosignature.is_some());
    let err = w
        .state
        .apply_in::<Gen>(&space_id(), &signed)
        .expect_err("refused");
    assert_eq!(err.reason, Reason::Malformed);
    signed.cosignature = None;
    w.state
        .apply_in::<Gen>(&space_id(), &signed)
        .expect("accepted");
}

#[test]
fn seals_are_committed_by_seq_and_recipients() {
    let w = world::<Gen>();
    let state = &w.state;
    // Every seal the state holds has a commitment at its seq that lists it.
    for ((key, version, member), seal) in &state.seals {
        let committed = &state.commitments[&(*key, *version, seal.seq)];
        assert!(
            committed
                .recipients
                .contains(&(*member, seal.bundle_version))
        );
        assert_eq!(
            usize::try_from(committed.count).ok(),
            Some(committed.recipients.len())
        );
        assert!(state.key_checks.contains_key(&(*key, *version)));
    }
    // Nobody is awaiting a key in the finished world.
    for key in state.keys() {
        assert!(state.awaiting(&key).is_empty(), "{key:?}");
    }
}

#[test]
fn the_same_chain_is_accepted_when_served_in_pieces() {
    let all = cases::<Gen>();
    let valid = find(&all, "valid-every-kind");
    // A device that kept the state at the anchor applies only the rest and ends in the same state.
    let cut = valid.chain.len() / 2;
    let head = verify_chain_in::<Gen>(&space_id(), &valid.chain[..cut], None).expect("a prefix");
    let mut state = head.state;
    for signed in &valid.chain[cut..] {
        state = state
            .apply_in::<Gen>(&space_id(), signed)
            .expect("applies")
            .state;
    }
    let whole = verify_chain_in::<Gen>(&space_id(), &valid.chain, None).expect("whole");
    assert_eq!(state, whole.state);
}

#[test]
fn the_state_is_what_the_server_would_derive() {
    let w = world::<Gen>();
    let valid = valid_chain::<Gen>(&w);
    let s = &valid.state;
    assert_eq!(
        s.members
            .values()
            .filter(|m| m.role == Role::Owner && m.status == Status::Confirmed)
            .count(),
        2
    );
    assert!(s.retired.contains(&uid(0x14)));
    assert!(s.retired.contains(&uid(0x22)));
    assert!(s.recovery_key.is_none() && s.recovery_key_seq.is_none());
    assert!(s.policies.require_sso && !s.policies.account_recovery);
    assert!(s.home.is_some());
}
