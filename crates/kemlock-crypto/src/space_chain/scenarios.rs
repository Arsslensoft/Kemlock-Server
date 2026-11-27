//! The scenarios of the spec's "Test cases" that a chain can show: each is a chain, perhaps an
//! anchor, and what a verifier must say. The unit tests, the test-vector generator and the vector
//! checks all use them.

#![cfg_attr(not(test), allow(dead_code))]

use super::{
    model::{
        Body, CollectionPerm, Grantee, Id, KeyRef, NameTarget, Policies, Reason, Record, Role,
        SignedRecord, TimeoutAction,
    },
    testkit::{
        ADMIN, ANA, Account, CREATOR, GROUPS, Kit, LEE, NEWBIE, OWNER, OWNER2, USERS, ZED, finance,
        general, name, space_id, team, uid, world,
    },
    verify::{Anchor, verify_chain_in},
};
use crate::{backend::Backend, kx1, sig1};

/// What a verifier must say about a case's chain.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Expect {
    /// The chain verifies, to this head and (against an anchor) this divergence.
    Accepted {
        head_seq: u64,
        divergence: Option<u64>,
    },
    /// The chain is refused, naming this `seq` and reason.
    Refused { seq: Option<u64>, reason: Reason },
}

/// A chain, the anchor a device holds (if any), and what verifying it must give.
#[derive(Clone)]
pub(crate) struct Case {
    pub name: String,
    pub description: String,
    pub chain: Vec<SignedRecord>,
    pub anchor: Option<Anchor>,
    pub expect: Expect,
}

fn last_seq(chain: &[SignedRecord]) -> u64 {
    u64::try_from(chain.len()).map_or(0, |n| n.saturating_sub(1))
}

/// Collects the cases.
struct Cases(Vec<Case>);

impl Cases {
    /// A chain whose last record is refused with `reason`.
    fn refused(
        &mut self,
        name: &str,
        description: &str,
        kit: &Kit,
        last: SignedRecord,
        reason: Reason,
    ) {
        // The refusal names the record's own `seq` (docs/crypto.md, "Verification"), which is
        // its place in the chain unless the record lies about it.
        let own_seq = Record::parse(&last.entry).ok().map(|r| r.seq);
        let chain = kit.chain_with(last);
        let seq = Some(own_seq.unwrap_or_else(|| last_seq(&chain)));
        self.0.push(Case {
            name: name.to_owned(),
            description: description.to_owned(),
            chain,
            anchor: None,
            expect: Expect::Refused { seq, reason },
        });
    }

    /// A case whose last record the kit's own checks refuse with `reason`.
    fn bad<B: Backend>(
        &mut self,
        name: &str,
        description: &str,
        kit: &Kit,
        by: &Id,
        body: Body,
        reason: Reason,
    ) {
        let (signed, result) = kit.attempt::<B>(by, body);
        let got = result.expect_err("a record that should be refused");
        assert_eq!(got.reason, reason, "{name}");
        self.refused(name, description, kit, signed, reason);
    }

    /// A chain that verifies.
    fn accepted(&mut self, name: &str, description: &str, kit: &Kit) {
        self.0.push(Case {
            name: name.to_owned(),
            description: description.to_owned(),
            chain: kit.records.clone(),
            anchor: None,
            expect: Expect::Accepted {
                head_seq: last_seq(&kit.records),
                divergence: None,
            },
        });
    }

    /// A chain served to a device with an anchor.
    fn anchored(
        &mut self,
        name: &str,
        description: &str,
        chain: &[SignedRecord],
        anchor: &Anchor,
        expect: Expect,
    ) {
        self.0.push(Case {
            name: name.to_owned(),
            description: description.to_owned(),
            chain: chain.to_vec(),
            anchor: Some(anchor.clone()),
            expect,
        });
    }
}

fn policies_with(change: impl FnOnce(&mut Policies)) -> Policies {
    let mut p = Policies::default();
    change(&mut p);
    p
}

fn fence_body(promotion: &[u8]) -> Body {
    Body::Fence {
        home: uid(0xF2),
        promotion: crate::hash::sha256(promotion),
    }
}

/// A valid recovery key (a `kx1` public key).
fn recovery_key<B: Backend>() -> Vec<u8> {
    kx1::public_key_in::<B>(&kx1::PrivateKey::from_bytes(&[0x77; 96]))
        .expect("a recovery key")
        .as_bytes()
        .to_vec()
}

/// The valid chain with every kind of record, built from the world.
pub(crate) fn valid_chain<B: Backend>(w: &Kit) -> Kit {
    let owner = uid(OWNER);
    let owner2 = uid(OWNER2);
    let admin = uid(ADMIN);
    let ana = uid(ANA);
    let lee = uid(LEE);
    let mut k = w.clone();
    let hr = uid(0x13);
    let hr_body = k.collection_body::<B>(
        hr,
        "HR",
        &[(Grantee::User(owner), CollectionPerm::Manage)],
        None,
    );
    k.ok::<B>(&owner, hr_body);
    let sub = uid(0x14);
    let sub_body = k.collection_body::<B>(
        sub,
        "HR payroll",
        &[(Grantee::User(owner), CollectionPerm::Manage)],
        Some(hr),
    );
    k.ok::<B>(&owner, sub_body);
    k.ok::<B>(
        &owner,
        Body::Move {
            collection: sub,
            parent: None,
        },
    );
    k.ok::<B>(
        &owner,
        Body::Rename {
            name_hash: name("Space, renamed"),
            target: NameTarget::Space,
        },
    );
    k.ok::<B>(
        &owner,
        Body::Rename {
            name_hash: name("Team, renamed"),
            target: NameTarget::Group(team()),
        },
    );
    k.ok::<B>(
        &owner,
        Body::Grant {
            collection: hr,
            grantee: Grantee::User(ana),
            permission: CollectionPerm::Edit,
        },
    );
    k.seal_up::<B>(&owner);
    let replace = k.replace_for(|s| {
        s.grants.remove(&(hr, Grantee::User(ana)));
    });
    k.ok::<B>(
        &owner,
        Body::Ungrant {
            collection: hr,
            grantee: Grantee::User(ana),
            replace,
        },
    );
    k.ok::<B>(&owner, Body::CollectionDelete { collection: sub });
    let other = uid(0x22);
    k.ok::<B>(
        &owner,
        Body::Group {
            group: other,
            name_hash: name("Other"),
        },
    );
    let replace = k.replace_for(|s| {
        s.groups.remove(&other);
    });
    k.ok::<B>(
        &owner,
        Body::GroupDelete {
            group: other,
            replace,
        },
    );
    k.rekey::<B>(&ana);
    k.seal_up::<B>(&owner);
    k.ok::<B>(
        &owner,
        Body::RecoveryKey {
            key: recovery_key::<B>(),
        },
    );
    k.ok::<B>(
        &admin,
        Body::Policies {
            policies: policies_with(|p| p.require_sso = true),
        },
    );
    let mut p = k.state.policies;
    p.account_recovery = true;
    k.ok::<B>(&owner, Body::Policies { policies: p });
    p.account_recovery = false;
    k.ok::<B>(&owner, Body::Policies { policies: p });
    k.ok::<B>(&owner, Body::RecoveryKeyClear);
    // Lee leaves, and the keys they held are replaced.
    let remove = k.remove_body(&lee);
    k.ok::<B>(&owner, remove);
    let rotate = k.rotate_body::<B>(&[KeyRef::Collection(finance()), KeyRef::Space]);
    k.ok::<B>(&owner2, rotate);
    // A new home: the fence.
    k.ok::<B>(&owner, fence_body(b"example promotion record"));
    k
}

/// The scenarios, each as a chain, an optional anchor and a verdict. The first is the valid chain
/// with every kind.
#[allow(clippy::too_many_lines)]
pub(crate) fn cases<B: Backend>() -> Vec<Case> {
    let owner = uid(OWNER);
    let owner2 = uid(OWNER2);
    let admin = uid(ADMIN);
    let groups = uid(GROUPS);
    let ana = uid(ANA);
    let lee = uid(LEE);
    let users = uid(USERS);
    let creator = uid(CREATOR);
    let newbie = uid(NEWBIE);
    let zed = uid(ZED);
    let fin = KeyRef::Collection(finance());
    let mut out = Cases(Vec::new());
    let w = world::<B>();

    out.accepted(
        "valid-every-kind",
        "A valid chain with every kind of record: create, invite, confirm, rekey, role, remove, \
         grant, ungrant, collection, move, collection-delete, group, group-members, group-delete, \
         rename, seal, keys, policies, recovery-key, recovery-key-clear and fence.",
        &valid_chain::<B>(&w),
    );

    // 1. Self-widening through a group.
    out.bad::<B>(
        "self-widening-through-a-group",
        "A Custom member with only manage-groups adds themselves to a group that is granted \
         Finance: not allowed.",
        &w,
        &groups,
        Body::GroupMembers {
            add: vec![groups],
            group: team(),
            remove: vec![],
            replace: vec![],
        },
        Reason::NotAllowed,
    );
    {
        let mut k = w.clone();
        let club = uid(0x23);
        k.ok::<B>(
            &groups,
            Body::Group {
                group: club,
                name_hash: name("Club"),
            },
        );
        k.ok::<B>(
            &groups,
            Body::GroupMembers {
                add: vec![groups],
                group: club,
                remove: vec![],
                replace: vec![],
            },
        );
        out.bad::<B>(
            "grant-to-a-group-they-joined",
            "Adding themselves to a group with no grants is accepted; a later grant of Finance to \
             that group, signed by them, is not allowed.",
            &k,
            &groups,
            Body::Grant {
                collection: finance(),
                grantee: Grantee::Group(club),
                permission: CollectionPerm::View,
            },
            Reason::NotAllowed,
        );
    }

    // 2. Group access needs MayGrant.
    let add_ana = Body::GroupMembers {
        add: vec![ana],
        group: team(),
        remove: vec![],
        replace: vec![],
    };
    out.bad::<B>(
        "group-access-needs-may-grant",
        "The same member adds Ana to the group that is granted Finance, which they can't grant: \
         not allowed.",
        &w,
        &groups,
        add_ana.clone(),
        Reason::NotAllowed,
    );
    {
        let mut k = w.clone();
        k.ok::<B>(
            &owner,
            Body::Grant {
                collection: finance(),
                grantee: Grantee::User(groups),
                permission: CollectionPerm::Manage,
            },
        );
        k.seal_up::<B>(&owner);
        k.ok::<B>(&groups, add_ana);
        assert!(k.state.awaiting(&fin).contains(&ana));
        out.accepted(
            "group-access-with-manage",
            "Once they hold manage on Finance, the same record is accepted, and Ana awaits \
             Finance's key.",
            &k,
        );
    }

    // 3. Owners change Owners.
    {
        let mut k = w.clone();
        let board = uid(0x24);
        k.ok::<B>(
            &owner,
            Body::Group {
                group: board,
                name_hash: name("Board"),
            },
        );
        k.ok::<B>(
            &owner,
            Body::GroupMembers {
                add: vec![owner2],
                group: board,
                remove: vec![],
                replace: vec![],
            },
        );
        let hr = uid(0x13);
        let hr_body = k.collection_body::<B>(
            hr,
            "HR",
            &[(Grantee::User(owner), CollectionPerm::Manage)],
            None,
        );
        k.ok::<B>(&owner, hr_body);
        let replace = k.replace_for(|s| {
            s.grants.remove(&(finance(), Grantee::User(owner2)));
        });
        let records: [(&str, &str, Body); 4] = [
            (
                "owners-ungrant",
                "an ungrant of an Owner's grant",
                Body::Ungrant {
                    collection: finance(),
                    grantee: Grantee::User(owner2),
                    replace,
                },
            ),
            (
                "owners-group-members",
                "a group-members removing an Owner",
                Body::GroupMembers {
                    add: vec![],
                    group: board,
                    remove: vec![owner2],
                    replace: vec![],
                },
            ),
            (
                "owners-grant-to-group",
                "a grant to a group that holds an Owner",
                Body::Grant {
                    collection: hr,
                    grantee: Grantee::Group(board),
                    permission: CollectionPerm::View,
                },
            ),
            (
                "owners-demote",
                "a role demoting an Owner",
                Body::Role {
                    custom: vec![],
                    member: owner2,
                    role: Role::Admin,
                },
            ),
        ];
        for (case, what, body) in records {
            out.bad::<B>(
                case,
                &format!("In a space with two confirmed Owners, an Admin's {what} is not allowed."),
                &k,
                &admin,
                body.clone(),
                Reason::NotAllowed,
            );
            let mut by_owner = k.clone();
            by_owner.ok::<B>(&owner, body);
            out.accepted(
                &format!("{case}-by-the-other-owner"),
                &format!("The same record, signed by the other Owner, is accepted: {what}."),
                &by_owner,
            );
        }
    }
    let mut solo = Kit::new(space_id());
    solo.add(Account::new::<B>(OWNER, 1));
    solo.add(Account::new::<B>(OWNER2, 1));
    solo.create::<B>(&owner, general());
    out.bad::<B>(
        "sole-owner-demoted",
        "In a space with one confirmed Owner, demoting them is invalid, whoever signs it.",
        &solo,
        &owner,
        Body::Role {
            custom: vec![],
            member: owner,
            role: Role::Admin,
        },
        Reason::Invalid,
    );
    let remove_owner = solo.remove_body(&owner);
    out.bad::<B>(
        "sole-owner-removed",
        "In a space with one confirmed Owner, removing them is invalid, whoever signs it.",
        &solo,
        &owner,
        remove_owner,
        Reason::Invalid,
    );

    // 4 and 5. Removal ends access, and a marked key isn't shared. Newbie is confirmed and waits
    // for the space key; Zed is invited.
    let mut r = w.clone();
    r.invite::<B>(&owner, &newbie, Role::Member, &[], &[]);
    r.confirm::<B>(&owner, &newbie);
    r.invite::<B>(&owner, &zed, Role::Member, &[], &[]);
    out.bad::<B>(
        "removal-without-replace",
        "Lee holds Finance's key through a group; their remove with an empty replace is invalid.",
        &r,
        &owner,
        Body::Remove {
            member: lee,
            replace: vec![],
        },
        Reason::Invalid,
    );
    let remove = r.remove_body(&lee);
    assert!(
        matches!(&remove, Body::Remove { replace, .. } if *replace == vec![fin, KeyRef::Space])
    );
    let mut after = r.clone();
    after.ok::<B>(&owner, remove);
    assert!(
        !after
            .state
            .grants
            .keys()
            .any(|(_, g)| *g == Grantee::User(lee))
    );
    assert!(after.state.groups_of(&lee).is_empty());
    out.accepted(
        "removal-marks-the-keys",
        "Lee's remove with replace [collection:finance, space] is accepted: Lee has no grant and \
         is in no group, and Finance's key and the space key are marked.",
        &after,
    );
    let mut sealing = after.clone();
    let share = sealing.share::<B>(KeyRef::Space, &[newbie]);
    out.bad::<B>(
        "marked-key-seal",
        "After Lee's removal, a seal of the space key is invalid.",
        &after,
        &owner,
        Body::Seal { seals: vec![share] },
        Reason::Invalid,
    );
    let confirm = after.confirm_body::<B>(&owner, &zed);
    out.bad::<B>(
        "marked-key-confirm",
        "After Lee's removal, a confirm is invalid.",
        &after,
        &owner,
        confirm,
        Reason::Invalid,
    );
    out.bad::<B>(
        "marked-key-grant",
        "After Lee's removal, a grant of Finance to a new member is invalid.",
        &after,
        &owner,
        Body::Grant {
            collection: finance(),
            grantee: Grantee::User(newbie),
            permission: CollectionPerm::View,
        },
        Reason::Invalid,
    );
    {
        let mut scratch = after.clone();
        let rotate = scratch.rotate_body::<B>(&[fin, KeyRef::Space]);
        let mut done = after.clone();
        done.ok::<B>(&owner, rotate.clone());
        assert!(!done.state.space.marked && !done.state.collections[&finance()].marked);
        out.accepted(
            "keys-clear-both-marks",
            "A keys record that replaces the space key and Finance's key with every name is \
             accepted, and clears both marks.",
            &done,
        );
        let Body::Keys { names, rotate } = rotate else {
            unreachable!("rotate_body makes a keys record");
        };
        out.bad::<B>(
            "keys-without-names",
            "A keys record that replaces the space key without names is invalid.",
            &after,
            &owner,
            Body::Keys {
                names: None,
                rotate: rotate.clone(),
            },
            Reason::Invalid,
        );
        let mut packed = names.expect("the space key comes with its names");
        packed.truncate(packed.len() - 49);
        out.bad::<B>(
            "keys-with-a-name-missing",
            "A keys record that replaces the space key with a collection or group missing from its \
             names is invalid.",
            &after,
            &owner,
            Body::Keys {
                names: Some(packed),
                rotate,
            },
            Reason::Invalid,
        );
    }

    // 16. Who replaces a key.
    {
        let mut scratch = after.clone();
        let rotate = scratch.rotate_body::<B>(&[fin]);
        out.bad::<B>(
            "admin-without-access-replaces-a-key",
            "An Admin without access to Finance replaces Finance's key: not allowed.",
            &after,
            &admin,
            rotate.clone(),
            Reason::NotAllowed,
        );
        let mut done = after.clone();
        done.ok::<B>(&users, rotate);
        out.accepted(
            "viewer-replaces-a-marked-key",
            "A member with view on Finance replaces its key while it is marked: accepted.",
            &done,
        );
        let mut scratch = w.clone();
        let rotate = scratch.rotate_body::<B>(&[fin]);
        out.bad::<B>(
            "viewer-replaces-an-unmarked-key",
            "A member with view on Finance replaces its key while it isn't marked: not allowed.",
            &w,
            &users,
            rotate,
            Reason::NotAllowed,
        );
    }

    // 8. Epochs.
    {
        let signed_at = |kit: &Kit, body: Body, epoch: u32| {
            let mut rec = kit.record(&owner, body);
            rec.epoch = epoch;
            kit.sign::<B>(&rec, kit.acc(&owner), None)
        };
        let epoch = w.state.epoch;
        let role = Body::Role {
            custom: vec![],
            member: ana,
            role: Role::Admin,
        };
        out.refused(
            "epoch-raised-by-a-role",
            "A role with the epoch plus one is a bad epoch.",
            &w,
            signed_at(&w, role, epoch + 1),
            Reason::BadEpoch,
        );
        out.refused(
            "fence-epoch-plus-two",
            "A fence with the epoch plus two is a bad epoch.",
            &w,
            signed_at(&w, fence_body(b"p"), epoch + 2),
            Reason::BadEpoch,
        );
        out.refused(
            "fence-same-epoch",
            "A fence with the same epoch is a bad epoch.",
            &w,
            signed_at(&w, fence_body(b"p"), epoch),
            Reason::BadEpoch,
        );
        out.bad::<B>(
            "fence-by-an-admin",
            "A fence with the epoch plus one signed by an Admin is not allowed.",
            &w,
            &admin,
            fence_body(b"p"),
            Reason::NotAllowed,
        );
        let mut k = w.clone();
        k.ok::<B>(&owner, fence_body(b"p"));
        let low = signed_at(
            &k,
            Body::Policies {
                policies: policies_with(|p| p.two_step = true),
            },
            1,
        );
        out.refused(
            "lower-epoch",
            "A record with a lower epoch is a bad epoch.",
            &k,
            low,
            Reason::BadEpoch,
        );
    }

    // 9 and 14. Fence and dropped records, rollback and fork, against anchors.
    {
        // The device's chain: the world and three records the old home took.
        let mut device = w.clone();
        for on in [true, false, true] {
            device.ok::<B>(
                &owner,
                Body::Policies {
                    policies: policies_with(|p| p.two_step = on),
                },
            );
        }
        let anchor = device.anchor();
        let fork_at = last_seq(&w.records) + 1;
        // The new home's chain: the world, a fence where the device has its first record, one more.
        let mut moved = w.clone();
        moved.ok::<B>(&owner, fence_body(b"promotion"));
        moved.ok::<B>(
            &owner2,
            Body::Policies {
                policies: policies_with(|p| p.disable_send = true),
            },
        );
        out.anchored(
            "fence-drops-the-old-homes-records",
            "A device anchored in the old home's epoch is served a chain whose record after the \
             shared part is a fence to epoch 2: accepted, and its own records from there to its \
             anchor are dropped.",
            &moved.records,
            &anchor,
            Expect::Accepted {
                head_seq: last_seq(&moved.records),
                divergence: Some(fork_at),
            },
        );
        let mut forked = w.clone();
        forked.ok::<B>(
            &owner,
            Body::Policies {
                policies: policies_with(|p| p.single_space = true),
            },
        );
        forked.ok::<B>(&owner, fence_body(b"promotion"));
        out.anchored(
            "fence-after-a-divergence",
            "The chain parts from the device's anchor at a record that isn't a fence, then a fence \
             follows: forked.",
            &forked.records,
            &anchor,
            Expect::Refused {
                seq: Some(fork_at),
                reason: Reason::Forked,
            },
        );
        out.anchored(
            "old-home-after-the-fence",
            "A device anchored at epoch 2 is served the old home's epoch-1 records past the \
             fence: forked.",
            &device.records,
            &moved.anchor(),
            Expect::Refused {
                seq: Some(fork_at),
                reason: Reason::Forked,
            },
        );
        let mut shorter = device.records.clone();
        shorter.truncate(shorter.len() - 2);
        out.anchored(
            "rolled-back",
            "The device accepted a later record; the server's chain ends earlier: rolled back.",
            &shorter,
            &anchor,
            Expect::Refused {
                seq: Some(last_seq(&shorter)),
                reason: Reason::RolledBack,
            },
        );
        let mut other = w.clone();
        other.ok::<B>(
            &owner,
            Body::Policies {
                policies: policies_with(|p| p.disable_export = true),
            },
        );
        out.anchored(
            "forked",
            "The server's record at a seq the device accepted differs from the anchor's: forked.",
            &other.records,
            &anchor,
            Expect::Refused {
                seq: Some(fork_at),
                reason: Reason::Forked,
            },
        );
        out.anchored(
            "matching-anchor",
            "A device anchored at a record of the chain it is served: accepted.",
            &device.records,
            &anchor,
            Expect::Accepted {
                head_seq: last_seq(&device.records),
                divergence: None,
            },
        );
        // The fence names a promotion the device doesn't hold, and its signer is an Owner the
        // device's own records removed: a server that served the chain up to that removal and
        // then a fence signed by the removed Owner can't undo it.
        let mut removing = w.clone();
        let removal = removing.remove_body(&owner2);
        removing.ok::<B>(&owner, removal);
        removing.ok::<B>(
            &owner,
            Body::Policies {
                policies: policies_with(|p| p.disable_send = true),
            },
        );
        let removing_anchor = removing.anchor();
        let mut undone = w.clone();
        undone.ok::<B>(&owner2, fence_body(b"promotion"));
        out.anchored(
            "fence-by-an-owner-the-device-removed",
            "The device accepted the removal of an Owner. It is served a chain that parts at that \
             record with a fence signed by the removed Owner, whose promotion it doesn't hold: \
             forked.",
            &undone.records,
            &removing_anchor,
            Expect::Refused {
                seq: Some(fork_at),
                reason: Reason::Forked,
            },
        );
        // An Owner who rekeyed since: the device accepted the rekey, and is served a fence that
        // the Owner's old key signed at the rekey's place. The kept bundle is the new one.
        let mut rekeyed = w.clone();
        rekeyed.rekey::<B>(&owner2);
        rekeyed.ok::<B>(
            &owner,
            Body::Policies {
                policies: policies_with(|p| p.disable_send = true),
            },
        );
        let rekeyed_anchor = rekeyed.anchor();
        let mut leaked = w.clone();
        leaked.ok::<B>(&owner2, fence_body(b"promotion"));
        out.anchored(
            "fence-by-an-owners-old-key",
            "The device accepted an Owner's rekey. It is served a chain that parts at the rekey \
             with a fence signed by that Owner's old key, whose promotion it doesn't hold: forked.",
            &leaked.records,
            &rekeyed_anchor,
            Expect::Refused {
                seq: Some(fork_at),
                reason: Reason::Forked,
            },
        );
        let mut unknown = anchor.clone();
        unknown.owners = None;
        out.anchored(
            "fence-nothing-vouches-for",
            "A device that keeps no Owners with its anchor and holds no promotion record is served \
             a fence: forked.",
            &moved.records,
            &unknown,
            Expect::Refused {
                seq: Some(fork_at),
                reason: Reason::Forked,
            },
        );
        let mut holding = unknown.clone();
        holding.promotions = vec![(uid(0xF2), crate::hash::sha256(b"promotion"))];
        out.anchored(
            "fence-whose-promotion-the-device-holds",
            "The same device holds and verified the promotion record the fence names: accepted, \
             and its own records from there to its anchor are dropped.",
            &moved.records,
            &holding,
            Expect::Accepted {
                head_seq: last_seq(&moved.records),
                divergence: Some(fork_at),
            },
        );
    }

    // 10. The only Owner replaces their keys.
    {
        let mut k = solo.clone();
        let old = k.acc(&owner).clone();
        k.rekey::<B>(&owner);
        let mut next = k.clone();
        let policy = Body::Policies {
            policies: policies_with(|p| p.two_step = true),
        };
        next.ok::<B>(&owner, policy.clone());
        out.accepted(
            "rekey-then-the-new-key",
            "A rekey with a valid cosignature is accepted, and the next record signed with the new \
             key is accepted.",
            &next,
        );
        let rec = k.record(&owner, policy);
        let by_old = k.sign::<B>(&rec, &old, None);
        out.refused(
            "rekey-then-the-old-key",
            "After a rekey, a record signed with the old key is a bad signature.",
            &k,
            by_old,
            Reason::BadSignature,
        );

        let fresh = Account::new::<B>(OWNER, 2);
        let rekey = Body::Rekey {
            bundle: fresh.bytes.clone(),
            bundle_signature: fresh.self_sig.clone(),
        };
        let rec = solo.record(&owner, rekey);
        out.refused(
            "rekey-without-a-cosignature",
            "A rekey without a cosignature is malformed.",
            &solo,
            solo.sign::<B>(&rec, &old, None),
            Reason::Malformed,
        );
        let stranger = Account::new::<B>(OWNER2, 1);
        out.refused(
            "rekey-cosigned-by-another-key",
            "A rekey with a cosignature by another key is a bad signature.",
            &solo,
            solo.sign::<B>(&rec, &old, Some(&stranger)),
            Reason::BadSignature,
        );
        let same = Account::new::<B>(OWNER, 1);
        let rec = solo.record(
            &owner,
            Body::Rekey {
                bundle: same.bytes.clone(),
                bundle_signature: same.self_sig.clone(),
            },
        );
        out.refused(
            "rekey-to-the-same-key-version",
            "A rekey to a bundle of the same key version is invalid.",
            &solo,
            solo.sign::<B>(&rec, &old, Some(&same)),
            Reason::Invalid,
        );
    }

    // 11. One spelling, at chain level: a link without its label.
    {
        let mut rec = w.record(&owner, Body::RecoveryKeyClear);
        rec.prev = crate::hash::sha256(&w.records[w.records.len() - 1].entry);
        out.refused(
            "link-without-its-label",
            "A record whose prev is the unlabelled SHA-256 of the record before is a bad link.",
            &w,
            w.sign::<B>(&rec, w.acc(&owner), None),
            Reason::BadLink,
        );
    }

    // 15. Policies.
    {
        let mut k = w.clone();
        let on = policies_with(|p| p.account_recovery = true);
        out.bad::<B>(
            "recovery-on-without-a-key",
            "An Owner's policies that turns accountRecovery on with no recovery key is invalid.",
            &k,
            &owner,
            Body::Policies { policies: on },
            Reason::Invalid,
        );
        k.ok::<B>(
            &owner,
            Body::RecoveryKey {
                key: recovery_key::<B>(),
            },
        );
        out.bad::<B>(
            "recovery-on-by-an-admin",
            "An Admin's policies that turns accountRecovery on is not allowed.",
            &k,
            &admin,
            Body::Policies { policies: on },
            Reason::NotAllowed,
        );
        let mut sso = k.clone();
        sso.ok::<B>(
            &admin,
            Body::Policies {
                policies: policies_with(|p| p.require_sso = true),
            },
        );
        out.accepted(
            "sso-on-by-an-admin",
            "An Admin's policies that turns requireSso on is accepted.",
            &sso,
        );
        out.bad::<B>(
            "timeout-lock-with-no-minutes",
            "sessionTimeout with minutes 0 and action lock is invalid.",
            &k,
            &owner,
            Body::Policies {
                policies: policies_with(|p| p.session_timeout.action = TimeoutAction::Lock),
            },
            Reason::Invalid,
        );
    }

    // 17. Custom managing Custom.
    out.bad::<B>(
        "custom-manages-a-wider-custom",
        "A Custom member with manage-users changes the role of a Custom member who has \
         create-collections, which the signer lacks: not allowed.",
        &w,
        &users,
        Body::Role {
            custom: vec![],
            member: creator,
            role: Role::Member,
        },
        Reason::NotAllowed,
    );

    // 18. Reason order, and the position checks.
    {
        let stranger = Account::new::<B>(NEWBIE, 1);
        let rec = w.record(
            &ana,
            Body::Policies {
                policies: policies_with(|p| p.two_step = true),
            },
        );
        out.refused(
            "unrecorded-key-beats-authority",
            "A record signed by a key the chain doesn't record for by, which also breaks the \
             authority table, is a bad signature.",
            &w,
            w.sign::<B>(&rec, &stranger, None),
            Reason::BadSignature,
        );
        let mut rec = w.record(&ana, Body::RecoveryKeyClear);
        rec.prev = [9; 32];
        out.refused(
            "bad-link-beats-bad-signature",
            "A record with a bad link and a bad signature is a bad link.",
            &w,
            w.sign::<B>(&rec, &stranger, None),
            Reason::BadLink,
        );
        out.bad::<B>(
            "signer-not-in-the-chain",
            "A record by an account the chain doesn't have is an unknown signer.",
            &w,
            &newbie,
            Body::RecoveryKeyClear,
            Reason::UnknownSigner,
        );
        let mut rec = w.record(&owner, Body::RecoveryKeyClear);
        rec.space = uid(0xA1);
        out.refused(
            "record-for-another-space",
            "A record whose space isn't the one being verified is a wrong space.",
            &w,
            w.sign::<B>(&rec, w.acc(&owner), None),
            Reason::WrongSpace,
        );
        let mut rec = w.record(&owner, Body::RecoveryKeyClear);
        rec.seq += 1;
        out.refused(
            "record-skips-a-seq",
            "A record whose seq isn't the next is a bad sequence.",
            &w,
            w.sign::<B>(&rec, w.acc(&owner), None),
            Reason::BadSequence,
        );
    }
    out.0
}

/// A synthetic record `bytes` long, for the size limits.
pub(crate) fn oversized(bytes: usize) -> SignedRecord {
    SignedRecord {
        entry: vec![b' '; bytes],
        signature: vec![0; sig1::SIGNATURE_LEN],
        cosignature: None,
    }
}

/// What verifying a case's chain gives, as an [`Expect`].
pub(crate) fn verdict<B: Backend>(case: &Case) -> Expect {
    match verify_chain_in::<B>(&space_id(), &case.chain, case.anchor.as_ref()) {
        Ok(v) => Expect::Accepted {
            head_seq: v.state.head.map_or(0, |h| h.seq),
            divergence: v.divergence,
        },
        Err(e) => Expect::Refused {
            seq: e.seq,
            reason: e.reason,
        },
    }
}
