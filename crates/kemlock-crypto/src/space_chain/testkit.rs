//! Builds space chains for the unit tests, the test vectors and their checks: accounts with fixed
//! keys, a [`Kit`] that makes, signs and applies records (and the commitments they carry, with
//! real sealed boxes), and the world the scenarios start from.

#![cfg_attr(not(test), allow(dead_code))]

use std::collections::{BTreeMap, BTreeSet};

use super::{
    model::{
        Body, ChainError, CollectionPerm, Commitment, CustomPerm, Grantee, Hash, Id, KeyRef,
        Record, Role, SignedRecord,
    },
    seals::{box_context, key_check_in, seal_digest_in, seal_hash},
    state::{Head, State},
    verify::{Anchor, Applied},
};
use crate::{
    backend::Backend,
    bundle::{self, Bundle},
    confirm::Statement,
    kx1, rand, sealed_box,
    sig1::{
        self,
        context::{BUNDLE, CONFIRM, SPACE_CHAIN},
    },
};

/// `00000000-0000-4000-8000-0000000000nn`, the ids of the spec's examples.
pub(crate) fn uid(n: u8) -> Id {
    let mut id = [0u8; 16];
    id[6] = 0x40;
    id[8] = 0x80;
    id[15] = n;
    id
}

/// A stand-in for a sealed name: its hash is what the chain commits.
pub(crate) fn name(label: &str) -> Hash {
    crate::hash::sha256(format!("sealed name: {label}").as_bytes())
}

/// An account with fixed keys.
#[derive(Clone)]
pub(crate) struct Account {
    pub n: u8,
    pub id: Id,
    pub sig: sig1::SigningKey,
    pub kx: kx1::PrivateKey,
    pub bundle: Bundle,
    pub bytes: Vec<u8>,
    pub self_sig: Vec<u8>,
}

impl Account {
    /// The account `n` at a key version: the keys come from `n` and the version.
    pub(crate) fn new<B: Backend>(n: u8, version: u32) -> Account {
        let seed = n
            .wrapping_mul(16)
            .wrapping_add(u8::try_from(version).unwrap_or(0));
        let sig = sig1::SigningKey::from_bytes(&[seed; 64]);
        let kx = kx1::PrivateKey::from_bytes(&[seed ^ 0x5a; 96]);
        let bundle = Bundle {
            account_id: uid(n),
            key_version: version,
            kx1_public: kx1::public_key_in::<B>(&kx).expect("kx1 public key"),
            sig1_public: sig1::public_key_in::<B>(&sig).expect("sig1 public key"),
        };
        let bytes = bundle.to_bytes();
        let self_sig = sig1::sign_in::<B>(&sig, BUNDLE, &bytes).expect("bundle signature");
        Account {
            n,
            id: uid(n),
            sig,
            kx,
            bundle,
            bytes,
            self_sig,
        }
    }
}

/// A chain under construction: its records, the state they give, the accounts that sign, and the
/// keys and boxes the commitments were made from.
#[derive(Clone)]
pub(crate) struct Kit {
    pub space: Id,
    pub records: Vec<SignedRecord>,
    pub state: State,
    pub accounts: BTreeMap<Id, Account>,
    pub secrets: BTreeMap<(KeyRef, u32), [u8; 32]>,
    pub boxes: BTreeMap<(KeyRef, u32, Id), Vec<u8>>,
}

impl Kit {
    pub(crate) fn new(space: Id) -> Kit {
        Kit {
            space,
            records: Vec::new(),
            state: State::empty(),
            accounts: BTreeMap::new(),
            secrets: BTreeMap::new(),
            boxes: BTreeMap::new(),
        }
    }

    pub(crate) fn add(&mut self, account: Account) {
        self.accounts.insert(account.id, account);
    }

    pub(crate) fn acc(&self, id: &Id) -> &Account {
        self.accounts.get(id).expect("a known account")
    }

    /// The next record of `by`, with its position from the state.
    pub(crate) fn record(&self, by: &Id, body: Body) -> Record {
        let fence = matches!(body, Body::Fence { .. });
        let (seq, prev, epoch) = match self.state.head {
            None => (0, [0u8; 32], 1),
            Some(Head { seq, link }) => (seq + 1, link, self.state.epoch + u32::from(fence)),
        };
        Record {
            space: self.space,
            seq,
            prev,
            epoch,
            at: 1_700_000_000 + 60 * seq,
            by: *by,
            body,
        }
    }

    /// Signs a record with its signer's key, and a `rekey`'s cosignature with `cosigner`'s.
    pub(crate) fn sign<B: Backend>(
        &self,
        rec: &Record,
        signer: &Account,
        cosigner: Option<&Account>,
    ) -> SignedRecord {
        let entry = rec.to_bytes();
        let signature = sig1::sign_in::<B>(&signer.sig, SPACE_CHAIN, &entry).expect("signature");
        let cosignature =
            cosigner.map(|c| sig1::sign_in::<B>(&c.sig, SPACE_CHAIN, &entry).expect("cosignature"));
        SignedRecord {
            entry,
            signature,
            cosignature,
        }
    }

    /// Signs `body` as `by` and checks it against the head, without keeping it.
    pub(crate) fn attempt<B: Backend>(
        &self,
        by: &Id,
        body: Body,
    ) -> (SignedRecord, Result<Applied, ChainError>) {
        let rec = self.record(by, body);
        let signed = self.sign::<B>(&rec, self.acc(by), None);
        let result = self.state.apply_in::<B>(&self.space, &signed);
        (signed, result)
    }

    /// Keeps a record that was checked and accepted.
    pub(crate) fn keep(&mut self, signed: SignedRecord, applied: &Applied) {
        self.state = applied.state.clone();
        self.records.push(signed);
    }

    /// Makes, signs, checks and (when accepted) keeps a record. A refused record is still
    /// returned, so a scenario can use it as the last record of a chain.
    pub(crate) fn push<B: Backend>(
        &mut self,
        by: &Id,
        body: Body,
    ) -> (SignedRecord, Result<Applied, ChainError>) {
        let (signed, result) = self.attempt::<B>(by, body);
        if let Ok(applied) = &result {
            self.keep(signed.clone(), applied);
        }
        (signed, result)
    }

    /// A record that must be accepted.
    pub(crate) fn ok<B: Backend>(&mut self, by: &Id, body: Body) -> Applied {
        let (_, result) = self.push::<B>(by, body);
        result.unwrap_or_else(|e| panic!("a record that should be accepted was refused: {e}"))
    }

    /// The chain with one more record, which is the one the chain's verifier refuses.
    pub(crate) fn chain_with(&self, last: SignedRecord) -> Vec<SignedRecord> {
        let mut chain = self.records.clone();
        chain.push(last);
        chain
    }

    // ---- commitments ----------------------------------------------------------------------

    fn commit_with<B: Backend>(
        &mut self,
        key: KeyRef,
        version: u32,
        recipients: &[Id],
        secret: &[u8; 32],
        makes: bool,
    ) -> Commitment {
        let mut ids: Vec<Id> = recipients.to_vec();
        ids.sort_unstable();
        ids.dedup();
        let mut entries: Vec<(Id, u32, Hash)> = Vec::new();
        for id in &ids {
            let account = self.acc(id).clone();
            let (context, aad) = box_context(&key, &self.space, version, id);
            let sealed =
                sealed_box::seal_in::<B>(&account.bundle.kx1_public, context, &aad, secret)
                    .expect("a sealed key");
            entries.push((*id, account.bundle.key_version, seal_hash(&sealed)));
            self.boxes.insert((key, version, *id), sealed);
        }
        Commitment {
            key,
            version,
            count: u32::try_from(ids.len()).expect("few recipients"),
            digest: seal_digest_in::<B>(&self.space, &key, version, &entries),
            check: makes.then(|| {
                key_check_in::<B>(&self.space, &key, version, secret).expect("a key check")
            }),
        }
    }

    /// A commitment that makes a key version: a fresh key sealed to `recipients`.
    pub(crate) fn make<B: Backend>(
        &mut self,
        key: KeyRef,
        version: u32,
        recipients: &[Id],
    ) -> Commitment {
        let secret: [u8; 32] = rand::try_bytes::<B, 32>().expect("random bytes");
        self.secrets.insert((key, version), secret);
        self.commit_with::<B>(key, version, recipients, &secret, true)
    }

    /// A commitment that shares the key's current version with `recipients`.
    pub(crate) fn share<B: Backend>(&mut self, key: KeyRef, recipients: &[Id]) -> Commitment {
        let version = self.state.key_version(&key).expect("the key exists");
        let secret = *self.secrets.get(&(key, version)).expect("a known key");
        self.commit_with::<B>(key, version, recipients, &secret, false)
    }

    // ---- the kinds, as a member's app would make them -------------------------------------

    pub(crate) fn create<B: Backend>(&mut self, owner: &Id, collection: Id) -> Applied {
        let account = self.acc(owner).clone();
        let first = self.make::<B>(KeyRef::Collection(collection), 1, &[*owner]);
        let space_key = self.make::<B>(KeyRef::Space, 1, &[*owner]);
        self.ok::<B>(
            owner,
            Body::Create {
                bundle: account.bytes,
                bundle_signature: account.self_sig,
                collection,
                collection_name: name("General"),
                member: *owner,
                name_hash: name("Space"),
                seals: vec![first, space_key],
            },
        )
    }

    pub(crate) fn invite<B: Backend>(
        &mut self,
        by: &Id,
        member: &Id,
        role: Role,
        custom: &[CustomPerm],
        grants: &[(Id, CollectionPerm)],
    ) -> Applied {
        let mut custom = custom.to_vec();
        custom.sort_unstable();
        let mut grants = grants.to_vec();
        grants.sort_by_key(|g| g.0);
        self.ok::<B>(
            by,
            Body::Invite {
                custom,
                grants,
                member: *member,
                role,
            },
        )
    }

    /// The body of a confirmation of `member`'s current bundle by `by`.
    pub(crate) fn confirm_body<B: Backend>(&self, by: &Id, member: &Id) -> Body {
        let account = self.acc(member).clone();
        let fingerprint = bundle::fingerprint_in::<B>(&account.bytes);
        let statement = Statement {
            space: self.space,
            member: *member,
            member_key_version: account.bundle.key_version,
            fingerprint: &fingerprint,
            confirmer: *by,
        }
        .to_bytes();
        let statement_signature =
            sig1::sign_in::<B>(&self.acc(by).sig, CONFIRM, &statement).expect("signature");
        Body::Confirm {
            bundle: account.bytes,
            bundle_signature: account.self_sig,
            member: *member,
            statement,
            statement_signature,
        }
    }

    pub(crate) fn confirm<B: Backend>(&mut self, by: &Id, member: &Id) -> Applied {
        let body = self.confirm_body::<B>(by, member);
        self.ok::<B>(by, body)
    }

    /// Shares every key `by` holds with the members awaiting it. `false` when there is nothing to
    /// share.
    pub(crate) fn seal_up<B: Backend>(&mut self, by: &Id) -> bool {
        if self.state.space.marked {
            return false;
        }
        let mut seals = Vec::new();
        for key in self.state.keys() {
            if self.state.key_marked(&key) || !self.state.holds(by, &key) {
                continue;
            }
            let awaiting: Vec<Id> = self.state.awaiting(&key).into_iter().collect();
            if awaiting.is_empty() {
                continue;
            }
            seals.push(self.share::<B>(key, &awaiting));
        }
        if seals.is_empty() {
            return false;
        }
        self.ok::<B>(by, Body::Seal { seals });
        true
    }

    /// Invites, confirms and seals to a new member, as their inviter's app does.
    #[allow(dead_code)] // kept for scenarios that grow a space; none does yet
    pub(crate) fn add_member<B: Backend>(
        &mut self,
        by: &Id,
        account: Account,
        role: Role,
        custom: &[CustomPerm],
        grants: &[(Id, CollectionPerm)],
    ) {
        let id = account.id;
        self.add(account);
        self.invite::<B>(by, &id, role, custom, grants);
        self.confirm::<B>(by, &id);
        self.seal_up::<B>(by);
    }

    /// A new collection by `by`, its key sealed to the confirmed members with access.
    pub(crate) fn collection_body<B: Backend>(
        &mut self,
        id: Id,
        label: &str,
        grants: &[(Grantee, CollectionPerm)],
        parent: Option<Id>,
    ) -> Body {
        let mut who: BTreeSet<Id> = BTreeSet::new();
        for (grantee, _) in grants {
            match grantee {
                Grantee::User(user) => {
                    who.insert(*user);
                }
                Grantee::Group(group) => {
                    if let Some(info) = self.state.groups.get(group) {
                        who.extend(info.members.iter().copied());
                    }
                }
            }
        }
        who.retain(|m| self.state.confirmed(m).is_some());
        let recipients: Vec<Id> = who.into_iter().collect();
        let seal = self.make::<B>(KeyRef::Collection(id), 1, &recipients);
        let mut grants = grants.to_vec();
        grants.sort_by_key(|g| g.0);
        Body::Collection {
            collection: id,
            grants,
            name_hash: name(label),
            parent,
            seals: vec![seal],
        }
    }

    /// The keys a change makes some member lose: what a `replace` list must hold. `change` edits a
    /// copy of the state as the record would.
    pub(crate) fn replace_for(&self, change: impl FnOnce(&mut State)) -> Vec<KeyRef> {
        let mut next = self.state.clone();
        change(&mut next);
        self.state.lost(&next).into_iter().collect()
    }

    pub(crate) fn remove_body(&self, member: &Id) -> Body {
        let replace = self.replace_for(|s| {
            s.grants
                .retain(|(_, grantee), _| *grantee != Grantee::User(*member));
            for group in s.groups.values_mut() {
                group.members.remove(member);
            }
            if let Some(m) = s.members.get_mut(member) {
                m.status = super::state::Status::Removed;
            }
        });
        Body::Remove {
            member: *member,
            replace,
        }
    }

    /// The packed names of a `keys` record that replaces the space key.
    pub(crate) fn packed_names(&self, round: u32) -> Vec<u8> {
        let mut entries: Vec<[u8; 49]> = Vec::new();
        let mut push = |kind: u8, id: &Id, label: String| {
            let mut e = [0u8; 49];
            e[0] = kind;
            e[1..17].copy_from_slice(id);
            e[17..].copy_from_slice(&name(&label));
            entries.push(e);
        };
        push(1, &self.space, format!("space v{round}"));
        for id in self.state.collections.keys() {
            push(2, id, format!("collection {id:?} v{round}"));
        }
        for id in self.state.groups.keys() {
            push(3, id, format!("group {id:?} v{round}"));
        }
        entries.sort_unstable();
        entries.concat()
    }

    /// A `keys` record for the given keys: new versions sealed to everyone entitled.
    pub(crate) fn rotate_body<B: Backend>(&mut self, keys: &[KeyRef]) -> Body {
        let mut keys = keys.to_vec();
        keys.sort_unstable();
        let mut rotate = Vec::new();
        for key in &keys {
            let version = self.state.key_version(key).expect("the key exists") + 1;
            let who: Vec<Id> = self.state.entitled(key).into_iter().collect();
            rotate.push(self.make::<B>(*key, version, &who));
        }
        let names = keys
            .contains(&KeyRef::Space)
            .then(|| self.packed_names(self.state.space.key_version + 1));
        Body::Keys { names, rotate }
    }

    /// A member replaces their own key pair: a `rekey` signed by the old key and the new.
    pub(crate) fn rekey<B: Backend>(&mut self, id: &Id) -> (SignedRecord, Account, Applied) {
        let old = self.acc(id).clone();
        let new = Account::new::<B>(old.n, old.bundle.key_version + 1);
        let rec = self.record(
            id,
            Body::Rekey {
                bundle: new.bytes.clone(),
                bundle_signature: new.self_sig.clone(),
            },
        );
        let signed = self.sign::<B>(&rec, &old, Some(&new));
        let applied = self
            .state
            .apply_in::<B>(&self.space, &signed)
            .expect("a rekey");
        self.keep(signed.clone(), &applied);
        self.accounts.insert(*id, new.clone());
        (signed, new, applied)
    }

    /// What a device anchored at the head holds.
    pub(crate) fn anchor(&self) -> Anchor {
        Anchor {
            seq: self.state.head.map_or(0, |h| h.seq),
            epoch: self.state.epoch,
            links: self
                .records
                .iter()
                .map(|r| super::seals::link(&r.entry))
                .collect(),
            owners: Some(self.state.owners()),
            promotions: Vec::new(),
        }
    }
}

// ---- the world the scenarios start from ----------------------------------------------------------

pub(crate) const OWNER: u8 = 1;
pub(crate) const OWNER2: u8 = 2;
pub(crate) const ADMIN: u8 = 3;
/// A Custom member with only `manage-groups`.
pub(crate) const GROUPS: u8 = 4;
pub(crate) const ANA: u8 = 5;
pub(crate) const LEE: u8 = 6;
/// A Custom member with only `manage-users`.
pub(crate) const USERS: u8 = 7;
/// A Custom member with only `create-collections`.
pub(crate) const CREATOR: u8 = 8;
pub(crate) const NEWBIE: u8 = 9;
pub(crate) const ZED: u8 = 10;

pub(crate) fn space_id() -> Id {
    uid(0xA0)
}
pub(crate) fn general() -> Id {
    uid(0x11)
}
pub(crate) fn finance() -> Id {
    uid(0x12)
}
pub(crate) fn team() -> Id {
    uid(0x21)
}

/// The space the scenarios branch from: two Owners, an Admin, three Custom members, Ana, and Lee,
/// who holds Finance's key only through the group `team`.
pub(crate) fn world<B: Backend>() -> Kit {
    let mut kit = Kit::new(space_id());
    for n in [
        OWNER, OWNER2, ADMIN, GROUPS, ANA, LEE, USERS, CREATOR, NEWBIE, ZED,
    ] {
        kit.add(Account::new::<B>(n, 1));
    }
    let owner = uid(OWNER);
    kit.create::<B>(&owner, general());
    let view = [(general(), CollectionPerm::View)];
    for (n, role, custom, grants) in [
        (OWNER2, Role::Admin, vec![], view.to_vec()),
        (ADMIN, Role::Admin, vec![], view.to_vec()),
        (
            GROUPS,
            Role::Custom,
            vec![CustomPerm::ManageGroups],
            view.to_vec(),
        ),
        (ANA, Role::Member, vec![], view.to_vec()),
        (LEE, Role::Member, vec![], vec![]),
        (
            USERS,
            Role::Custom,
            vec![CustomPerm::ManageUsers],
            view.to_vec(),
        ),
        (
            CREATOR,
            Role::Custom,
            vec![CustomPerm::CreateCollections],
            view.to_vec(),
        ),
    ] {
        let id = uid(n);
        kit.invite::<B>(&owner, &id, role, &custom, &grants);
        kit.confirm::<B>(&owner, &id);
        kit.seal_up::<B>(&owner);
    }
    kit.ok::<B>(
        &owner,
        Body::Role {
            custom: vec![],
            member: uid(OWNER2),
            role: Role::Owner,
        },
    );
    let finance_body = kit.collection_body::<B>(
        finance(),
        "Finance",
        &[
            (Grantee::User(owner), CollectionPerm::Manage),
            (Grantee::User(uid(OWNER2)), CollectionPerm::Manage),
        ],
        None,
    );
    kit.ok::<B>(&owner, finance_body);
    kit.ok::<B>(
        &owner,
        Body::Group {
            group: team(),
            name_hash: name("Team"),
        },
    );
    kit.ok::<B>(
        &owner,
        Body::GroupMembers {
            add: vec![uid(LEE)],
            group: team(),
            remove: vec![],
            replace: vec![],
        },
    );
    kit.ok::<B>(
        &owner,
        Body::Grant {
            collection: finance(),
            grantee: Grantee::Group(team()),
            permission: CollectionPerm::View,
        },
    );
    // The member who manages users reads Finance too, so a member who isn't an Admin can be asked
    // to replace its key.
    kit.ok::<B>(
        &owner,
        Body::Grant {
            collection: finance(),
            grantee: Grantee::User(uid(USERS)),
            permission: CollectionPerm::View,
        },
    );
    kit.seal_up::<B>(&owner);
    kit
}
