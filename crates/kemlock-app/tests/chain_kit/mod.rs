//! Builds signed space-chain records with kemlock-crypto's public API, for the tests of the use
//! cases and the routes. A test file includes it with `mod chain_kit;`.
#![allow(dead_code, unused_imports)]

use kemlock_crypto::bundle::Bundle;
use kemlock_crypto::confirm::Statement;
use kemlock_crypto::space_chain::b64;
use kemlock_crypto::space_chain::seals::box_context;
use kemlock_crypto::space_chain::{
    Body, CollectionPerm, Commitment, Grantee, Id, KeyRef, NameTarget, Record, Role, SignedRecord,
    key_check, link, seal_digest, seal_hash, sign_record,
};
use kemlock_crypto::{kx1, sealed_box, sig1};
use serde_json::{Value, json};
use std::collections::BTreeMap;

/// A person with fixed keys.
pub(crate) struct Person {
    pub id: Id,
    pub sig: sig1::SigningKey,
    pub kx: kx1::PrivateKey,
    pub bundle: Bundle,
}

impl Person {
    pub(crate) fn new(id: Id, seed: u8) -> Person {
        Person::at_version(id, seed, 1)
    }

    /// The same account with a new key pair made from `seed`, at `key_version`: the account after
    /// a root-key rotation, whose `rekey` replaces `self`'s bundle with this one.
    pub(crate) fn rotated(&self, seed: u8, key_version: u32) -> Person {
        Person::at_version(self.id, seed, key_version)
    }

    pub(crate) fn at_version(id: Id, seed: u8, key_version: u32) -> Person {
        let sig = sig1::SigningKey::from_bytes(&[seed; 64]);
        let kx = kx1::PrivateKey::from_bytes(&[seed ^ 0x5a; 96]);
        let bundle = Bundle {
            account_id: id,
            key_version,
            kx1_public: kx.public_key().expect("a kx1 public key"),
            sig1_public: sig.public_key().expect("a sig1 public key"),
        };
        Person {
            id,
            sig,
            kx,
            bundle,
        }
    }

    pub(crate) fn bytes(&self) -> Vec<u8> {
        self.bundle.to_bytes()
    }

    pub(crate) fn self_signature(&self) -> Vec<u8> {
        self.bundle.sign(&self.sig).expect("a bundle signature")
    }
}

/// A box a request carries.
#[derive(Clone, Debug)]
pub(crate) struct SealOut {
    pub seq: u64,
    pub key: KeyRef,
    pub member: Id,
    pub version: u32,
    pub sealed: Vec<u8>,
}

/// A sealed name a request carries.
#[derive(Clone, Debug)]
pub(crate) struct NameOut {
    pub seq: u64,
    pub target: NameTarget,
    pub sealed: Vec<u8>,
}

/// What one step of a chain produces.
#[derive(Clone)]
pub(crate) struct Step {
    pub record: SignedRecord,
    pub seals: Vec<SealOut>,
    pub names: Vec<NameOut>,
}

/// A stand-in for a sealed name: 40 bytes, so it passes the size check, and its hash is committed.
pub(crate) fn sealed_name(fill: u8) -> Vec<u8> {
    vec![fill; 40]
}

pub(crate) struct Chain {
    pub space: Id,
    /// The `at` of every record: the server's clock.
    pub at: u64,
    pub head: Option<(u64, [u8; 32])>,
    secrets: BTreeMap<(KeyRef, u32), [u8; 32]>,
}

impl Chain {
    pub(crate) fn new(space: Id, at: u64) -> Chain {
        Chain {
            space,
            at,
            head: None,
            secrets: BTreeMap::new(),
        }
    }

    /// A record of `by` at the head, signed, without moving the head.
    pub(crate) fn peek(&self, by: &Person, body: Body) -> SignedRecord {
        let (seq, prev) = self.head.map_or((0, [0u8; 32]), |(s, l)| (s + 1, l));
        let record = Record {
            space: self.space,
            seq,
            prev,
            epoch: 1,
            at: self.at,
            by: by.id,
            body,
        };
        let entry = record.to_bytes();
        let signature = sign_record(&by.sig, &entry).expect("a signature");
        SignedRecord {
            entry,
            signature,
            cosignature: None,
        }
    }

    fn push(&mut self, by: &Person, body: Body) -> (u64, SignedRecord) {
        let record = self.peek(by, body);
        let seq = self.head.map_or(0, |(s, _)| s + 1);
        self.head = Some((seq, link(&record.entry)));
        (seq, record)
    }

    fn commit(
        &mut self,
        key: KeyRef,
        version: u32,
        to: &[&Person],
        makes: bool,
        seq: u64,
    ) -> (Commitment, Vec<SealOut>) {
        let secret = *self
            .secrets
            .entry((key, version))
            .or_insert_with(|| [u8::try_from(version).unwrap_or(0) ^ 0xA7; 32]);
        let mut people: Vec<&Person> = to.to_vec();
        people.sort_by_key(|p| p.id);
        let mut entries = Vec::new();
        let mut seals = Vec::new();
        for person in people {
            let (context, aad) = box_context(&key, &self.space, version, &person.id);
            let sealed = sealed_box::seal(&person.bundle.kx1_public, context, &aad, &secret)
                .expect("a sealed key");
            entries.push((person.id, person.bundle.key_version, seal_hash(&sealed)));
            seals.push(SealOut {
                seq,
                key,
                member: person.id,
                version,
                sealed,
            });
        }
        let commitment = Commitment {
            key,
            version,
            count: u32::try_from(entries.len()).expect("few"),
            digest: seal_digest(&self.space, &key, version, &entries),
            check: makes.then(|| key_check(&self.space, &key, version, &secret).expect("a check")),
        };
        (commitment, seals)
    }

    /// The `create` record: `owner` makes the space and its first collection.
    pub(crate) fn create(&mut self, owner: &Person, collection: Id) -> Step {
        let seq = self.head.map_or(0, |(s, _)| s + 1);
        let (first, mut seals) =
            self.commit(KeyRef::Collection(collection), 1, &[owner], true, seq);
        let (space_key, more) = self.commit(KeyRef::Space, 1, &[owner], true, seq);
        seals.extend(more);
        let names = vec![
            NameOut {
                seq,
                target: NameTarget::Space,
                sealed: sealed_name(1),
            },
            NameOut {
                seq,
                target: NameTarget::Collection(collection),
                sealed: sealed_name(2),
            },
        ];
        let body = Body::Create {
            bundle: owner.bytes(),
            bundle_signature: owner.self_signature(),
            collection,
            collection_name: seal_hash(&sealed_name(2)),
            member: owner.id,
            name_hash: seal_hash(&sealed_name(1)),
            seals: vec![first, space_key],
        };
        let (_, record) = self.push(owner, body);
        Step {
            record,
            seals,
            names,
        }
    }

    pub(crate) fn invite(&mut self, by: &Person, member: Id, role: Role) -> Step {
        let (_, record) = self.push(
            by,
            Body::Invite {
                custom: Vec::new(),
                grants: Vec::new(),
                member,
                role,
            },
        );
        Step {
            record,
            seals: Vec::new(),
            names: Vec::new(),
        }
    }

    pub(crate) fn confirm(&mut self, by: &Person, member: &Person) -> Step {
        let fingerprint = member.bundle.fingerprint();
        let statement = Statement {
            space: self.space,
            member: member.id,
            member_key_version: member.bundle.key_version,
            fingerprint: &fingerprint,
            confirmer: by.id,
        };
        let body = Body::Confirm {
            bundle: member.bytes(),
            bundle_signature: member.self_signature(),
            member: member.id,
            statement: statement.to_bytes(),
            statement_signature: statement.sign(&by.sig).expect("a statement signature"),
        };
        let (_, record) = self.push(by, body);
        Step {
            record,
            seals: Vec::new(),
            names: Vec::new(),
        }
    }

    /// A `seal` of the space key to `to`, by someone who holds it.
    pub(crate) fn seal_space_key(&mut self, by: &Person, to: &Person) -> Step {
        let seq = self.head.map_or(0, |(s, _)| s + 1);
        let (commitment, seals) = self.commit(KeyRef::Space, 1, &[to], false, seq);
        let (_, record) = self.push(
            by,
            Body::Seal {
                seals: vec![commitment],
            },
        );
        Step {
            record,
            seals,
            names: Vec::new(),
        }
    }

    /// A `seal` of `collection`'s key (version 1) to `to`, by someone who holds it.
    pub(crate) fn seal_collection_key(&mut self, by: &Person, collection: Id, to: &Person) -> Step {
        let seq = self.head.map_or(0, |(s, _)| s + 1);
        let (commitment, seals) = self.commit(KeyRef::Collection(collection), 1, &[to], false, seq);
        let (_, record) = self.push(
            by,
            Body::Seal {
                seals: vec![commitment],
            },
        );
        Step {
            record,
            seals,
            names: Vec::new(),
        }
    }

    /// A `keys` record that replaces `collection`'s key with `version`, sealed to `to`, who are
    /// the members entitled to it.
    pub(crate) fn rotate_collection(
        &mut self,
        by: &Person,
        collection: Id,
        version: u32,
        to: &[&Person],
    ) -> Step {
        let seq = self.head.map_or(0, |(s, _)| s + 1);
        let (commitment, seals) =
            self.commit(KeyRef::Collection(collection), version, to, true, seq);
        let (_, record) = self.push(
            by,
            Body::Keys {
                names: None,
                rotate: vec![commitment],
            },
        );
        Step {
            record,
            seals,
            names: Vec::new(),
        }
    }

    /// A `collection` record: `by` adds `collection` at the top level, with manage for itself.
    pub(crate) fn collection(&mut self, by: &Person, collection: Id) -> Step {
        let seq = self.head.map_or(0, |(s, _)| s + 1);
        let (commitment, seals) = self.commit(KeyRef::Collection(collection), 1, &[by], true, seq);
        let sealed = sealed_name(3);
        let (_, record) = self.push(
            by,
            Body::Collection {
                collection,
                grants: vec![(Grantee::User(by.id), CollectionPerm::Manage)],
                name_hash: seal_hash(&sealed),
                parent: None,
                seals: vec![commitment],
            },
        );
        Step {
            record,
            seals,
            names: vec![NameOut {
                seq,
                target: NameTarget::Collection(collection),
                sealed,
            }],
        }
    }

    /// Any record of `by`, with no boxes or names.
    pub(crate) fn record(&mut self, by: &Person, body: Body) -> Step {
        let (_, record) = self.push(by, body);
        Step {
            record,
            seals: Vec::new(),
            names: Vec::new(),
        }
    }

    /// A `rekey` record: `old` (a member the chain records with its old bundle) replaces its bundle
    /// with `new`'s. The record is signed by the old key, as every record is, and cosigned by the
    /// new one over the same bytes, which is what makes the new key's holder agree to it. It
    /// carries no boxes: a member seals the keys it holds to its new bundle in later records.
    pub(crate) fn rekey(&mut self, old: &Person, new: &Person) -> Step {
        assert_eq!(old.id, new.id, "a rekey replaces a member's own bundle");
        let (_, mut record) = self.push(
            old,
            Body::Rekey {
                bundle: new.bytes(),
                bundle_signature: new.self_signature(),
            },
        );
        record.cosignature = Some(sign_record(&new.sig, &record.entry).expect("a cosignature"));
        Step {
            record,
            seals: Vec::new(),
            names: Vec::new(),
        }
    }

    pub(crate) fn remove(&mut self, by: &Person, member: Id, replace: Vec<KeyRef>) -> Step {
        let (_, record) = self.push(by, Body::Remove { member, replace });
        Step {
            record,
            seals: Vec::new(),
            names: Vec::new(),
        }
    }
}

/// The JSON of an append request for these steps.
pub(crate) fn request(steps: &[&Step]) -> Value {
    let mut records = Vec::new();
    let mut seals = Vec::new();
    let mut names = Vec::new();
    for step in steps {
        let mut r = json!({
            "entry": b64::encode(&step.record.entry),
            "signature": b64::encode(&step.record.signature),
        });
        if let Some(c) = &step.record.cosignature {
            r["cosignature"] = json!(b64::encode(c));
        }
        records.push(r);
        for s in &step.seals {
            seals.push(json!({
                "box": b64::encode(&s.sealed),
                "key": s.key.text(),
                "member": kemlock_crypto::space_chain::uuid_text(&s.member),
                "seq": s.seq,
                "version": s.version,
            }));
        }
        for n in &step.names {
            names.push(json!({
                "name": b64::encode(&n.sealed),
                "seq": n.seq,
                "target": n.target.text(),
            }));
        }
    }
    json!({"records": records, "seals": seals, "names": names})
}

/// The append that stores a chain in which `sam` made `space` and invited `ana`, and in which a
/// `confirm` record confirmed her only when `confirmed` says so. A fake's members table is left
/// as it is, which is the point: a test makes the table and the chain disagree.
pub(crate) fn invited_chain(
    space: kemlock_domain::SpaceId,
    sam: kemlock_domain::UserId,
    ana: kemlock_domain::UserId,
    confirmed: bool,
) -> kemlock_app::spaces::ChainAppend {
    use kemlock_app::spaces::{ChainAppend, SpaceChanges, StoredRecord};
    let sam = Person::new(*sam.0.as_bytes(), 1);
    let ana = Person::new(*ana.0.as_bytes(), 2);
    let mut chain = Chain::new(*space.0.as_bytes(), 0);
    let mut steps = vec![
        chain.create(&sam, [9; 16]),
        chain.invite(&sam, ana.id, Role::Member),
    ];
    if confirmed {
        steps.push(chain.confirm(&sam, &ana));
    }
    let records: Vec<StoredRecord> = steps
        .iter()
        .enumerate()
        .map(|(seq, step)| {
            let SignedRecord {
                entry,
                signature,
                cosignature,
            } = step.record.clone();
            StoredRecord {
                seq: u64::try_from(seq).expect("a few records"),
                link: link(&entry),
                epoch: 1,
                by: kemlock_domain::UserId(uuid::Uuid::from_bytes(sam.id)),
                at: 0,
                entry,
                signature,
                cosignature,
            }
        })
        .collect();
    ChainAppend {
        expected: None,
        records,
        seals: Vec::new(),
        names: Vec::new(),
        changes: SpaceChanges::new(space),
        creating: false,
        held: Vec::new(),
        writes: Vec::new(),
        answers: None,
        state: None,
    }
}

/// The append that stores these steps, all signed by `signer`, as a chain's first records. A fake's
/// members table is left as it is.
pub(crate) fn append_of(
    space: kemlock_domain::SpaceId,
    signer: &Person,
    steps: &[&Step],
) -> kemlock_app::spaces::ChainAppend {
    use kemlock_app::spaces::{ChainAppend, SpaceChanges, StoredRecord};
    let records: Vec<StoredRecord> = steps
        .iter()
        .enumerate()
        .map(|(seq, step)| {
            let SignedRecord {
                entry,
                signature,
                cosignature,
            } = step.record.clone();
            StoredRecord {
                seq: u64::try_from(seq).expect("a few records"),
                link: link(&entry),
                epoch: 1,
                by: kemlock_domain::UserId(uuid::Uuid::from_bytes(signer.id)),
                at: 0,
                entry,
                signature,
                cosignature,
            }
        })
        .collect();
    ChainAppend {
        expected: None,
        records,
        seals: Vec::new(),
        names: Vec::new(),
        changes: SpaceChanges::new(space),
        creating: false,
        held: Vec::new(),
        writes: Vec::new(),
        answers: None,
        state: None,
    }
}
