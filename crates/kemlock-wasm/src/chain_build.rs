//! Making the records of a space's chain in the unlocked session (`docs/crypto.md`, "Space
//! chain": "Kinds", "Commitments", "Using the state").
//!
//! A record is built from the **verified state** this unlock holds for the space, signed with the
//! unlocked account's `sig1` key, and applied to a copy of that state with the shared verifier
//! before it is returned, so what leaves the worker is a record the server's own checks accept (or
//! a refusal that names the verifier's reason). The worker signs nothing else under context
//! `"space-chain"`: the page can't hand it bytes to sign, only a change to make.
//!
//! What a builder returns is the body of `POST /kem/v1/spaces/{id}/chain`: the records, the boxes
//! their seal commitments cover (one per recipient the verifier derives, rule A11) and the sealed
//! names their name hashes cover. The builders never keep a key or change the held state: the page
//! appends the records, then verifies the chain again, and the keys come back through
//! `open_chain_key` like every other member's.
//!
//! - [`Session::create_chained_space`] makes the `create` record of a new space.
//! - [`Session::build_key_replacement`] replaces the keys a removal or an ungrant marked
//!   ("Removal and replacement"): a `keys` record, and the items of the replaced collections
//!   re-written under their new key versions, which the append route stores with it.
//! - [`Session::build_chain_records`] makes the records of one [`Change`]. A change that gives
//!   members keys (a `confirm`, a `grant`, new group members) is followed by a `seal` record that
//!   shares the keys this account holds with the members now awaiting them.

use std::collections::{BTreeMap, BTreeSet};

use kemlock_crypto::{
    bundle::Bundle,
    confirm::Statement,
    hash::{ct_eq, sha256},
    kem1,
    keys::{ITEM_WRAP_LABEL, SecretKey},
    owner::Owner,
    sealed_box,
    sig1::SigningKey,
    space_chain::{
        self as sc, Body, ChainError, CollectionPerm, Commitment, CustomPerm, Grantee, Hash, Id,
        KeyRef, NameTarget, Record, Role, SignedRecord, State, Status,
    },
};
use serde::{Deserialize, Serialize};

use crate::{
    b64,
    error::Error,
    ids,
    session::{SealedItemRef, Session},
    spaces::{NameKind, SpaceKeys, seal_name_under},
};

// ---- what the page asks for ---------------------------------------------------------------------

/// A grant of a collection to a member, in an `invite`.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct CollectionGrantIn {
    collection: String,
    permission: String,
}

/// A grant to a member or a group, in a new collection.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct GranteeGrantIn {
    grantee: String,
    permission: String,
}

/// A change to a space the unlocked account makes as a record.
#[derive(Deserialize)]
#[serde(
    tag = "action",
    rename_all = "kebab-case",
    rename_all_fields = "camelCase",
    deny_unknown_fields
)]
pub(crate) enum Change {
    /// `invite`: an account, a role and the collections it is granted.
    Invite {
        member: String,
        role: String,
        custom: Vec<String>,
        grants: Vec<CollectionGrantIn>,
    },
    /// `confirm`, after the person compared `fingerprint` with the member's own app; then a `seal`
    /// of the keys this account holds.
    Confirm {
        member: String,
        bundle: String,
        bundle_signature: String,
        fingerprint: String,
    },
    /// `role`.
    Role {
        member: String,
        role: String,
        custom: Vec<String>,
    },
    /// `remove`: the verifier's own `replace` list is worked out here.
    Remove { member: String },
    /// `grant`, then a `seal` for the members it newly entitles.
    Grant {
        collection: String,
        grantee: String,
        permission: String,
    },
    /// `ungrant`.
    Ungrant { collection: String, grantee: String },
    /// `collection`: a new collection with its key sealed to the confirmed members who reach it.
    /// With no `grants` it is granted `manage` to this account.
    Collection {
        collection: String,
        name: String,
        parent: Option<String>,
        #[serde(default)]
        grants: Vec<GranteeGrantIn>,
    },
    /// `collection-delete`.
    CollectionDelete { collection: String },
    /// `rename`: `target` is `space`, `collection:<uuid>` or `group:<uuid>`.
    Rename { target: String, name: String },
    /// `group`, and a `group-members` for `members` when there are any.
    Group {
        group: String,
        name: String,
        #[serde(default)]
        members: Vec<String>,
    },
    /// `group-members`, then a `seal` for the members it newly entitles.
    GroupMembers {
        group: String,
        add: Vec<String>,
        remove: Vec<String>,
    },
    /// `group-delete`.
    GroupDelete { group: String },
    /// A `seal` of every key this account holds that a member awaits; no record when none does.
    Seal,
}

// ---- what the page is given ------------------------------------------------------------------

/// A record, as the append route takes it (docs/crypto.md, "Wire form").
#[derive(Serialize)]
struct RecordOut {
    entry: String,
    signature: String,
}

/// A box a request carries for a commitment of record `seq`.
#[derive(Serialize)]
struct SealOut {
    #[serde(rename = "box")]
    sealed: String,
    key: String,
    member: String,
    seq: u64,
    version: u32,
}

/// A sealed name a request carries for a name hash of record `seq`.
#[derive(Serialize)]
struct NameOut {
    name: String,
    seq: u64,
    target: String,
}

/// An item as the append route takes it in a re-write: `PUT /kem/v1/items/{id}`'s body.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ItemOut {
    id: String,
    owner: String,
    kind: String,
    format: &'static str,
    revision: u64,
    key_version: u32,
    ciphertext: String,
    item_key: String,
    deleted: bool,
    collection_id: String,
}

/// An item a `keys` record re-writes under its collection's new key version.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct WriteOut {
    collection: String,
    /// The revision being replaced; the item is written as the next one.
    expected_revision: u64,
    item: ItemOut,
}

/// What `POST /kem/v1/spaces/{id}/chain` takes (docs/crypto.md, "Accepting records").
#[derive(Serialize)]
pub(crate) struct AppendOut {
    ok: bool,
    records: Vec<RecordOut>,
    seals: Vec<SealOut>,
    names: Vec<NameOut>,
    /// The live items of the replaced collections this account can't re-write (I3).
    #[serde(skip_serializing_if = "Vec::is_empty")]
    held: Vec<String>,
    /// The items of the replaced collections re-written under their new key versions.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    writes: Vec<WriteOut>,
}

/// An item as the server serves it, of a collection whose key is marked.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct ItemIn {
    id: String,
    collection: String,
    kind: String,
    revision: u64,
    key_version: u32,
    ciphertext: String,
    item_key: String,
}

/// A sealed name as the server serves it: `space`, `collection:<uuid>` or `group:<uuid>`.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct NameIn {
    target: String,
    sealed: String,
}

/// What a key replacement needs of the server's copy: the live items of the space, and, when the
/// space key is replaced, every sealed name (they are sealed again under the new key).
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Replacement {
    items: Vec<ItemIn>,
    #[serde(default)]
    names: Vec<NameIn>,
}

/// A change the verifier refused, with its reason and the `seq` it would have had.
#[derive(Serialize)]
pub(crate) struct RefusedOut {
    ok: bool,
    reason: &'static str,
    seq: Option<u64>,
}

/// Records ready to append, or the verifier's reason for refusing them.
#[derive(Serialize)]
#[serde(untagged)]
pub(crate) enum Built {
    Ready(AppendOut),
    Refused(RefusedOut),
}

// ---- the builder -------------------------------------------------------------------------------

/// Why a change wasn't built.
#[derive(Clone, Copy, Debug)]
enum Fail {
    /// Something the page sent is malformed, a key isn't held, or the session is locked.
    Error(Error),
    /// The verifier refused the record.
    Refused(ChainError),
}

const INVALID: Fail = Fail::Error(Error::Invalid);

impl From<Error> for Fail {
    fn from(error: Error) -> Fail {
        Fail::Error(error)
    }
}

impl From<kemlock_crypto::Error> for Fail {
    fn from(_: kemlock_crypto::Error) -> Fail {
        INVALID
    }
}

/// A chain of records under construction: the state each gives, and the boxes and names the next
/// one commits.
struct Build<'a> {
    space: Id,
    me: Id,
    at: u64,
    sig: &'a SigningKey,
    keys: &'a SpaceKeys,
    state: State,
    records: Vec<RecordOut>,
    seals: Vec<SealOut>,
    names: Vec<NameOut>,
    /// The boxes the next record's commitments cover.
    boxes: Vec<(KeyRef, u32, Id, Vec<u8>)>,
    /// The sealed names the next record's name hashes cover.
    sealed_names: Vec<(NameTarget, Vec<u8>)>,
    /// Items of replaced collections that this account holds and doesn't re-write.
    held: Vec<String>,
    /// Items re-written under a replaced collection's new key.
    writes: Vec<WriteOut>,
}

fn sorted<T: Ord>(mut list: Vec<T>) -> Vec<T> {
    list.sort();
    list
}

/// Whether a list sorted by `key` repeats an element.
fn repeats<T, K: PartialEq>(list: &[T], key: impl Fn(&T) -> K) -> bool {
    list.windows(2).any(|pair| match pair {
        [a, b] => key(a) == key(b),
        _ => false,
    })
}

fn parse_ids(texts: &[String]) -> Result<Vec<Id>, Fail> {
    let parsed: Result<Vec<Id>, Error> = texts.iter().map(|t| ids::parse_uuid(t)).collect();
    let parsed = sorted(parsed?);
    if repeats(&parsed, |id| *id) {
        return Err(INVALID);
    }
    Ok(parsed)
}

fn parse_custom(texts: &[String]) -> Result<Vec<CustomPerm>, Fail> {
    let mut custom = Vec::with_capacity(texts.len());
    for text in texts {
        custom.push(CustomPerm::parse(text).ok_or(INVALID)?);
    }
    let custom = sorted(custom);
    if repeats(&custom, |p| *p) {
        return Err(INVALID);
    }
    Ok(custom)
}

impl<'a> Build<'a> {
    fn new(
        space: Id,
        me: Id,
        at: u64,
        sig: &'a SigningKey,
        keys: &'a SpaceKeys,
        state: State,
    ) -> Build<'a> {
        Build {
            space,
            me,
            at,
            sig,
            keys,
            state,
            records: Vec::new(),
            seals: Vec::new(),
            names: Vec::new(),
            boxes: Vec::new(),
            sealed_names: Vec::new(),
            held: Vec::new(),
            writes: Vec::new(),
        }
    }

    fn out(self) -> AppendOut {
        AppendOut {
            ok: true,
            records: self.records,
            seals: self.seals,
            names: self.names,
            held: self.held,
            writes: self.writes,
        }
    }

    /// Makes, signs and checks the next record with `body`, and keeps the boxes and names that
    /// were made for it. The state moves on only when the verifier accepts it.
    fn push(&mut self, body: Body) -> Result<(), Fail> {
        let (seq, prev, epoch) = match self.state.head {
            None => (0u64, [0u8; 32], 1u32),
            Some(head) => (head.seq + 1, head.link, self.state.epoch),
        };
        let record = Record {
            space: self.space,
            seq,
            prev,
            epoch,
            at: self.at,
            by: self.me,
            body,
        };
        let entry = record.to_bytes();
        let signature = sc::sign_record(self.sig, &entry)?;
        let signed = SignedRecord {
            entry,
            signature,
            cosignature: None,
        };
        let applied = self
            .state
            .apply(&self.space, &signed)
            .map_err(Fail::Refused)?;
        self.state = applied.state;
        for (key, version, member, sealed) in self.boxes.drain(..) {
            self.seals.push(SealOut {
                sealed: b64::encode(&sealed),
                key: key.text(),
                member: sc::uuid_text(&member),
                seq,
                version,
            });
        }
        for (target, sealed) in self.sealed_names.drain(..) {
            self.names.push(NameOut {
                name: b64::encode(&sealed),
                seq,
                target: target.text(),
            });
        }
        self.records.push(RecordOut {
            entry: b64::encode(&signed.entry),
            signature: b64::encode(&signed.signature),
        });
        Ok(())
    }

    /// The key of the version, when this unlock holds it.
    fn secret(&self, key: &KeyRef, version: u32) -> Option<SecretKey> {
        let held = match key {
            KeyRef::Space => self.keys.spaces.get(&(self.space, version)),
            KeyRef::Collection(id) => self.keys.collections.get(&(self.space, *id, version)),
        };
        held.map(|secret| SecretKey::from_bytes(secret.as_bytes()))
    }

    /// The bundles the chain records for these members.
    fn bundles_of(&self, members: &BTreeSet<Id>) -> Result<Vec<(Id, Bundle)>, Fail> {
        let mut out = Vec::with_capacity(members.len());
        for id in members {
            let bundle = self
                .state
                .members
                .get(id)
                .and_then(|m| m.bundle.clone())
                .ok_or(INVALID)?;
            out.push((*id, bundle));
        }
        Ok(out)
    }

    /// A commitment to `secret` as `key` at `version`, sealed to each of `bundles` (their `kx1`
    /// keys, as the chain records them), with the boxes kept for the record that carries it.
    /// `makes` says it makes the key version, which adds the key check.
    fn commit(
        &mut self,
        key: KeyRef,
        version: u32,
        bundles: &[(Id, Bundle)],
        secret: &SecretKey,
        makes: bool,
    ) -> Result<Commitment, Fail> {
        let mut entries: Vec<(Id, u32, Hash)> = Vec::with_capacity(bundles.len());
        for (member, bundle) in bundles {
            let (context, aad) = sc::seals::box_context(&key, &self.space, version, member);
            let sealed = sealed_box::seal(&bundle.kx1_public, context, &aad, secret.as_bytes())?;
            entries.push((*member, bundle.key_version, sc::seal_hash(&sealed)));
            self.boxes.push((key, version, *member, sealed));
        }
        entries.sort_by_key(|entry| entry.0);
        let check = if makes {
            Some(sc::key_check(&self.space, &key, version, secret.as_bytes())?)
        } else {
            None
        };
        Ok(Commitment {
            key,
            version,
            count: u32::try_from(entries.len()).map_err(|_| INVALID)?,
            digest: sc::seal_digest(&self.space, &key, version, &entries),
            check,
        })
    }

    /// A name sealed under the space key at the chain's current version, and its hash; the sealed
    /// bytes are kept for the record that commits them.
    fn name(&mut self, kind: NameKind, id: &Id, target: NameTarget, name: &str) -> Result<Hash, Fail> {
        let version = self.state.space.key_version;
        let key = self.secret(&KeyRef::Space, version).ok_or(INVALID)?;
        let sealed = seal_name_under(&key, &self.space, version, kind, id, name)?;
        let hash = sha256(&sealed);
        self.sealed_names.push((target, sealed));
        Ok(hash)
    }

    /// A `seal` of every key this account holds that a member awaits ("Using the state",
    /// "Sealing"). Nothing is made when none is, or while the space key is marked.
    fn seal_held(&mut self) -> Result<(), Fail> {
        if self.state.space.marked {
            return Ok(());
        }
        let mut commitments = Vec::new();
        for key in sorted(self.state.keys()) {
            if self.state.key_marked(&key) || !self.state.holds(&self.me, &key) {
                continue;
            }
            let awaiting = self.state.awaiting(&key);
            if awaiting.is_empty() {
                continue;
            }
            let version = self.state.key_version(&key).ok_or(INVALID)?;
            // A key this browser hasn't opened is left to a member who has.
            let Some(secret) = self.secret(&key, version) else {
                continue;
            };
            let bundles = self.bundles_of(&awaiting)?;
            commitments.push(self.commit(key, version, &bundles, &secret, false)?);
        }
        if commitments.is_empty() {
            return Ok(());
        }
        self.push(Body::Seal {
            seals: commitments,
        })
    }

    /// The keys a change to a copy of the state makes some member lose.
    fn replace_for(&self, change: impl FnOnce(&mut State)) -> Vec<KeyRef> {
        let mut next = self.state.clone();
        change(&mut next);
        self.state.lost(&next).into_iter().collect()
    }

    /// Replaces the keys the chain marks ("Removal and replacement"): a `keys` record that gives
    /// each its next version, sealed to the members entitled to it, with every name sealed again
    /// when the space key is one of them; then the items of the replaced collections, each sealed
    /// again under a fresh item key and wrapped under the new collection key as the next revision.
    ///
    /// An item this account can't re-write (it holds no key of its version, has no edit on the
    /// collection, or the item doesn't open) is named as held, which is all the chain allows
    /// ("Using the state", "Items"): a removed member's write under a key they kept is never
    /// re-wrapped into the new key. A key nobody entitled can use is left marked, and one this
    /// account isn't entitled to is left to someone who is.
    fn replace_marked(&mut self, session: &Session, input: &Replacement) -> Result<(), Fail> {
        let marked: Vec<KeyRef> = sorted(
            self.state
                .keys()
                .into_iter()
                .filter(|key| self.state.key_marked(key))
                .collect(),
        );
        let mut fresh: BTreeMap<KeyRef, (u32, SecretKey)> = BTreeMap::new();
        let mut rotate = Vec::new();
        for key in marked {
            let entitled = self.state.entitled(&key);
            // A collection's key is replaced by a member entitled to it; the space key's rotation
            // is the record's own check (an Owner or an Admin), so it is tried and answered.
            let mine = entitled.contains(&self.me);
            if entitled.is_empty() || (key != KeyRef::Space && !mine) {
                continue;
            }
            let version = self
                .state
                .key_version(&key)
                .and_then(|v| v.checked_add(1))
                .ok_or(INVALID)?;
            let secret = SecretKey::generate();
            let bundles = self.bundles_of(&entitled)?;
            rotate.push(self.commit(key, version, &bundles, &secret, true)?);
            fresh.insert(key, (version, secret));
        }
        if rotate.is_empty() {
            return Ok(());
        }
        let names = match fresh.get(&KeyRef::Space) {
            Some((version, secret)) => Some(self.sealed_again(session, input, *version, secret)?),
            None => None,
        };
        self.push(Body::Keys { names, rotate })?;

        let owner = Owner::space(self.space);
        for item in &input.items {
            let collection = ids::parse_uuid(&item.collection)?;
            let Some((version, secret)) = fresh.get(&KeyRef::Collection(collection)) else {
                continue;
            };
            let id = ids::parse_uuid(&item.id)?;
            let may_edit = self
                .state
                .access(&self.me, &collection)
                .is_some_and(|rights| rights.edit);
            let again = if may_edit && item.key_version.checked_add(1) == Some(*version) {
                self.rewrite(session, item, &id, &collection, *version, secret, &owner)
            } else {
                None
            };
            match again {
                Some(write) => self.writes.push(write),
                None => self.held.push(sc::uuid_text(&id)),
            }
        }
        Ok(())
    }

    /// One item opened under the collection key it was sealed with, and sealed again as the next
    /// revision under a fresh item key, wrapped under the new key. `None` when it doesn't open.
    #[allow(clippy::too_many_arguments)]
    fn rewrite(
        &self,
        session: &Session,
        item: &ItemIn,
        id: &Id,
        collection: &Id,
        version: u32,
        secret: &SecretKey,
        owner: &Owner,
    ) -> Option<WriteOut> {
        let ciphertext = b64::decode(&item.ciphertext).ok()?;
        let wrapped = b64::decode(&item.item_key).ok()?;
        let plain = session
            .open_space_item(
                &self.space,
                collection,
                &SealedItemRef {
                    id,
                    owner,
                    kind: &item.kind,
                    revision: item.revision,
                    ciphertext: &ciphertext,
                    item_key: &wrapped,
                    key_version: Some(item.key_version),
                },
            )
            .ok()?;
        let revision = item.revision.checked_add(1)?;
        let item_key = SecretKey::generate();
        let sealed = kem1::seal_item(&item_key, id, revision, &item.kind, owner, &plain).ok()?;
        let wrap = secret.child(ITEM_WRAP_LABEL).ok()?;
        let wrapped = kem1::wrap_item_key(&wrap, &item_key, id, owner, version).ok()?;
        Some(WriteOut {
            collection: sc::uuid_text(collection),
            expected_revision: item.revision,
            item: ItemOut {
                id: sc::uuid_text(id),
                owner: format!("space:{}", sc::uuid_text(&self.space)),
                kind: item.kind.clone(),
                format: "kem1",
                revision,
                key_version: version,
                ciphertext: b64::encode(&sealed),
                item_key: b64::encode(&wrapped),
                deleted: false,
                collection_id: sc::uuid_text(collection),
            },
        })
    }

    /// Every name of the space sealed again under the new space key: opened as the chain committed
    /// it (the server's copy must be the committed one), sealed under `version`, kept for the
    /// record that commits it, and packed as a `keys` record's `names` ("Name commitments").
    fn sealed_again(
        &mut self,
        session: &Session,
        input: &Replacement,
        version: u32,
        secret: &SecretKey,
    ) -> Result<Vec<u8>, Fail> {
        let mut targets: Vec<(u8, Id, NameTarget, NameKind, u32)> = vec![(
            1,
            self.space,
            NameTarget::Space,
            NameKind::Space,
            self.state.space.name_version,
        )];
        for (id, info) in &self.state.collections {
            targets.push((
                2,
                *id,
                NameTarget::Collection(*id),
                NameKind::Collection,
                info.name_version,
            ));
        }
        for (id, info) in &self.state.groups {
            targets.push((3, *id, NameTarget::Group(*id), NameKind::Group, info.name_version));
        }
        let mut served: BTreeMap<NameTarget, Vec<u8>> = BTreeMap::new();
        for name in &input.names {
            let target = NameTarget::parse(&name.target).ok_or(INVALID)?;
            if served.insert(target, b64::decode(&name.sealed)?).is_some() {
                return Err(INVALID);
            }
        }
        let mut packed: Vec<[u8; 49]> = Vec::with_capacity(targets.len());
        for (kind_byte, id, target, kind, name_version) in targets {
            let old = served.get(&target).ok_or(INVALID)?;
            let name = session.open_name(&self.space, name_version, kind, &id, old)?;
            let sealed = seal_name_under(secret, &self.space, version, kind, &id, &name)?;
            let mut entry = [0u8; 49];
            entry[0] = kind_byte;
            entry[1..17].copy_from_slice(&id);
            entry[17..].copy_from_slice(&sha256(&sealed));
            packed.push(entry);
            self.sealed_names.push((target, sealed));
        }
        packed.sort_unstable();
        Ok(packed.concat())
    }

    fn apply_change(&mut self, change: &Change) -> Result<(), Fail> {
        match change {
            Change::Invite {
                member,
                role,
                custom,
                grants,
            } => {
                let role = Role::parse(role).ok_or(INVALID)?;
                let mut parsed = Vec::with_capacity(grants.len());
                for grant in grants {
                    parsed.push((
                        ids::parse_uuid(&grant.collection)?,
                        CollectionPerm::parse(&grant.permission).ok_or(INVALID)?,
                    ));
                }
                parsed.sort_by_key(|grant| grant.0);
                if repeats(&parsed, |grant| grant.0) {
                    return Err(INVALID);
                }
                self.push(Body::Invite {
                    custom: parse_custom(custom)?,
                    grants: parsed,
                    member: ids::parse_uuid(member)?,
                    role,
                })
            }
            Change::Confirm {
                member,
                bundle,
                bundle_signature,
                fingerprint,
            } => {
                let member = ids::parse_uuid(member)?;
                let bundle_bytes = b64::decode(bundle)?;
                let bundle_signature = b64::decode(bundle_signature)?;
                let parsed = Bundle::from_bytes(&bundle_bytes)?;
                if parsed.account_id != member {
                    return Err(INVALID);
                }
                parsed.verify_self_signature(&bundle_signature)?;
                // What the person compared is the fingerprint of exactly this bundle.
                let compared = b64::decode(fingerprint)?;
                let own = parsed.fingerprint();
                if !ct_eq(&compared, &own) {
                    return Err(INVALID);
                }
                let statement = Statement {
                    space: self.space,
                    member,
                    member_key_version: parsed.key_version,
                    fingerprint: &own,
                    confirmer: self.me,
                };
                let statement_signature = statement.sign(self.sig)?;
                self.push(Body::Confirm {
                    bundle: bundle_bytes,
                    bundle_signature,
                    member,
                    statement: statement.to_bytes(),
                    statement_signature,
                })?;
                self.seal_held()
            }
            Change::Role {
                member,
                role,
                custom,
            } => self.push(Body::Role {
                custom: parse_custom(custom)?,
                member: ids::parse_uuid(member)?,
                role: Role::parse(role).ok_or(INVALID)?,
            }),
            Change::Remove { member } => {
                let member = ids::parse_uuid(member)?;
                let replace = self.replace_for(|next| {
                    if let Some(m) = next.members.get_mut(&member) {
                        m.status = Status::Removed;
                    }
                    next.grants
                        .retain(|(_, grantee), _| *grantee != Grantee::User(member));
                    for group in next.groups.values_mut() {
                        group.members.remove(&member);
                    }
                });
                self.push(Body::Remove { member, replace })
            }
            Change::Grant {
                collection,
                grantee,
                permission,
            } => {
                self.push(Body::Grant {
                    collection: ids::parse_uuid(collection)?,
                    grantee: Grantee::parse(grantee).ok_or(INVALID)?,
                    permission: CollectionPerm::parse(permission).ok_or(INVALID)?,
                })?;
                self.seal_held()
            }
            Change::Ungrant {
                collection,
                grantee,
            } => {
                let collection = ids::parse_uuid(collection)?;
                let grantee = Grantee::parse(grantee).ok_or(INVALID)?;
                let replace = self.replace_for(|next| {
                    next.grants.remove(&(collection, grantee));
                });
                self.push(Body::Ungrant {
                    collection,
                    grantee,
                    replace,
                })
            }
            Change::Collection {
                collection,
                name,
                parent,
                grants,
            } => self.new_collection(collection, name, parent.as_deref(), grants),
            Change::CollectionDelete { collection } => self.push(Body::CollectionDelete {
                collection: ids::parse_uuid(collection)?,
            }),
            Change::Rename { target, name } => {
                let target = NameTarget::parse(target).ok_or(INVALID)?;
                let (kind, id) = match target {
                    NameTarget::Space => (NameKind::Space, self.space),
                    NameTarget::Collection(id) => (NameKind::Collection, id),
                    NameTarget::Group(id) => (NameKind::Group, id),
                };
                let name_hash = self.name(kind, &id, target, name)?;
                self.push(Body::Rename { name_hash, target })
            }
            Change::Group {
                group,
                name,
                members,
            } => {
                let group = ids::parse_uuid(group)?;
                let name_hash = self.name(NameKind::Group, &group, NameTarget::Group(group), name)?;
                self.push(Body::Group { group, name_hash })?;
                if members.is_empty() {
                    return Ok(());
                }
                self.push(Body::GroupMembers {
                    add: parse_ids(members)?,
                    group,
                    remove: Vec::new(),
                    replace: Vec::new(),
                })?;
                self.seal_held()
            }
            Change::GroupMembers { group, add, remove } => {
                let group = ids::parse_uuid(group)?;
                let (add, remove) = (parse_ids(add)?, parse_ids(remove)?);
                let replace = self.replace_for(|next| {
                    if let Some(info) = next.groups.get_mut(&group) {
                        info.members.extend(add.iter().copied());
                        for id in &remove {
                            info.members.remove(id);
                        }
                    }
                });
                self.push(Body::GroupMembers {
                    add,
                    group,
                    remove,
                    replace,
                })?;
                self.seal_held()
            }
            Change::GroupDelete { group } => {
                let group = ids::parse_uuid(group)?;
                let replace = self.replace_for(|next| {
                    next.groups.remove(&group);
                    next.grants
                        .retain(|(_, grantee), _| *grantee != Grantee::Group(group));
                });
                self.push(Body::GroupDelete { group, replace })
            }
            Change::Seal => self.seal_held(),
        }
    }

    /// A `collection` record: the new key sealed to the confirmed members who reach it through
    /// the grants, and its name under the space key.
    fn new_collection(
        &mut self,
        collection: &str,
        name: &str,
        parent: Option<&str>,
        grants: &[GranteeGrantIn],
    ) -> Result<(), Fail> {
        let collection = ids::parse_uuid(collection)?;
        let parent = parent.map(ids::parse_uuid).transpose()?;
        let mut parsed: Vec<(Grantee, CollectionPerm)> = Vec::with_capacity(grants.len() + 1);
        for grant in grants {
            parsed.push((
                Grantee::parse(&grant.grantee).ok_or(INVALID)?,
                CollectionPerm::parse(&grant.permission).ok_or(INVALID)?,
            ));
        }
        if parsed.is_empty() {
            parsed.push((Grantee::User(self.me), CollectionPerm::Manage));
        }
        parsed.sort_by_key(|grant| grant.0);
        if repeats(&parsed, |grant| grant.0) {
            return Err(INVALID);
        }
        // Whoever reaches the collection and is confirmed gets its key.
        let mut who: BTreeSet<Id> = BTreeSet::new();
        for (grantee, _) in &parsed {
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
        who.retain(|member| self.state.confirmed(member).is_some());
        let key = KeyRef::Collection(collection);
        let bundles = self.bundles_of(&who)?;
        let commitment = self.commit(key, 1, &bundles, &SecretKey::generate(), true)?;
        let name_hash = self.name(
            NameKind::Collection,
            &collection,
            NameTarget::Collection(collection),
            name,
        )?;
        self.push(Body::Collection {
            collection,
            grants: parsed,
            name_hash,
            parent,
            seals: vec![commitment],
        })
    }
}

fn finish(built: Result<Build<'_>, Fail>) -> Result<Built, Error> {
    match built {
        Ok(build) => Ok(Built::Ready(build.out())),
        Err(Fail::Refused(error)) => Ok(Built::Refused(RefusedOut {
            ok: false,
            reason: error.reason.as_str(),
            seq: error.seq,
        })),
        Err(Fail::Error(error)) => Err(error),
    }
}

impl Session {
    /// Makes a new space as a chain: its first record, `create`, signed with this account's
    /// `sig1` key, with the space key and the first collection's key (both version 1) sealed to
    /// this account's own bundle, the key checks, and both names under the space key. `at` is the
    /// time in Unix seconds, which the server checks is within 10 minutes of its own clock.
    ///
    /// The keys are not kept: the space opens through its chain once the record is appended, as
    /// for every member.
    pub(crate) fn create_chained_space(
        &self,
        space: &Id,
        collection: &Id,
        space_name: &str,
        collection_name: &str,
        at: u64,
    ) -> Result<Built, Error> {
        let unlocked = self.unlocked()?;
        let (kx_private, sig_private) = unlocked.private.as_ref().ok_or(Error::Locked)?;
        unlocked.spaces.require_unchained(space)?;
        let me = unlocked.account_id;
        let bundle = Bundle {
            account_id: me,
            key_version: unlocked.key_version,
            kx1_public: kx_private.public_key()?,
            sig1_public: sig_private.public_key()?,
        };
        let mut build = Build::new(*space, me, at, sig_private, &unlocked.spaces, State::empty());
        let result = (|| -> Result<(), Fail> {
            let space_key = SecretKey::generate();
            let collection_key = SecretKey::generate();
            let own = [(me, bundle.clone())];
            let collection_ref = KeyRef::Collection(*collection);
            let collection_commitment = build.commit(collection_ref, 1, &own, &collection_key, true)?;
            let space_commitment = build.commit(KeyRef::Space, 1, &own, &space_key, true)?;
            let space_sealed = seal_name_under(&space_key, space, 1, NameKind::Space, space, space_name)?;
            let collection_sealed = seal_name_under(
                &space_key,
                space,
                1,
                NameKind::Collection,
                collection,
                collection_name,
            )?;
            let body = Body::Create {
                bundle: bundle.to_bytes(),
                bundle_signature: bundle.sign(sig_private)?,
                collection: *collection,
                collection_name: sha256(&collection_sealed),
                member: me,
                name_hash: sha256(&space_sealed),
                // Sorted by key: a collection's before the space's.
                seals: vec![collection_commitment, space_commitment],
            };
            build
                .sealed_names
                .push((NameTarget::Collection(*collection), collection_sealed));
            build.sealed_names.push((NameTarget::Space, space_sealed));
            build.push(body)
        })();
        finish(result.map(|()| build))
    }

    /// Replaces the keys the verified chain marks, with the items of the replaced collections
    /// sealed again (see [`Build::replace_marked`]). `input` is the server's copy of the space's
    /// live items and, when the space key is replaced, its sealed names. Answers no records when
    /// there is nothing this account can replace.
    pub(crate) fn build_key_replacement(
        &self,
        space: &Id,
        at: u64,
        input: &Replacement,
    ) -> Result<Built, Error> {
        let unlocked = self.unlocked()?;
        let (_, sig_private) = unlocked.private.as_ref().ok_or(Error::Locked)?;
        if unlocked.spaces.refused.contains(space) {
            return Err(Error::Invalid);
        }
        let held = unlocked.spaces.chains.get(space).ok_or(Error::Invalid)?;
        if !held.trusted {
            return Err(Error::Invalid);
        }
        let mut build = Build::new(
            *space,
            unlocked.account_id,
            at,
            sig_private,
            &unlocked.spaces,
            held.state.clone(),
        );
        let result = build.replace_marked(self, input);
        finish(result.map(|()| build))
    }

    /// Makes the records of one change to a chained space, from the verified state this unlock
    /// holds for it, which must be trusted (first contact done). Answers the records with the
    /// boxes and names they commit, or the verifier's reason for refusing the change.
    pub(crate) fn build_chain_records(
        &self,
        space: &Id,
        at: u64,
        change: &Change,
    ) -> Result<Built, Error> {
        let unlocked = self.unlocked()?;
        let (_, sig_private) = unlocked.private.as_ref().ok_or(Error::Locked)?;
        if unlocked.spaces.refused.contains(space) {
            return Err(Error::Invalid);
        }
        let held = unlocked.spaces.chains.get(space).ok_or(Error::Invalid)?;
        if !held.trusted {
            return Err(Error::Invalid);
        }
        let mut build = Build::new(
            *space,
            unlocked.account_id,
            at,
            sig_private,
            &unlocked.spaces,
            held.state.clone(),
        );
        let result = build.apply_change(change);
        finish(result.map(|()| build))
    }
}
