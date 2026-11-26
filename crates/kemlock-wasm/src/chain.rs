//! The space chain in the unlocked session (`docs/crypto.md`, "Space chain").
//!
//! A space's keys, members, roles, grants and key versions come from its chain, which this module
//! verifies with the same verifier the server uses (`kemlock_crypto::space_chain`), and never from
//! the server's lists. What it keeps, per space, is the **verified state**: so what the page is
//! told about a space (and what the worker then does with keys) can't be anything but what the
//! chain gave.
//!
//! - [`Session::verify_space_chain`] verifies the records the server served against the anchor the
//!   page kept (and against the head this unlock already verified, so a server can't roll the
//!   chain back within a session), keeps the state, and returns a view of it for the page.
//! - First contact: a chain that verifies is only consistent. Until the person compared the
//!   fingerprint of the anchor person (or the chain is the account's own: it made it, or its key
//!   signed a `rekey`), the state is **not trusted**: no key of the space is opened or sealed.
//!   [`Session::accept_first_contact`] says the comparison matched.
//! - [`Session::open_chain_key`] opens a key at the chain's current version only, under
//!   `open_key`'s checks (the version, the commitment's digest, the box's `aad`, the key check).
//! - A space that has a chain, or whose served chain was refused, refuses the older, unchained
//!   operations (`open_space`, `seal_space_key_to` and the rest in `spaces.rs`): a page that
//!   skipped the chain can't open or seal a key the chain doesn't vouch for.

use std::collections::BTreeMap;

use kemlock_crypto::{
    bundle::{Bundle, fingerprint_groups},
    keys::SecretKey,
    space_chain::{
        self as sc, Anchor, Body, Hash, Id, KeyRef, Record, SignedRecord, State, Status,
        client::{FirstContact, SealListEntry, anchor_person, open_key},
        verify_chain,
    },
};
use serde::{Deserialize, Serialize};

use crate::{b64, error::Error, ids, session::Session};

/// A record as the server serves it.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct WireIn {
    pub(crate) entry: String,
    pub(crate) signature: String,
    #[serde(default)]
    pub(crate) cosignature: Option<String>,
}

/// What a device keeps for a space: the `seq` and `epoch` of the last record it accepted and the
/// link of every record from `seq` 0 to it (base64url).
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct AnchorIn {
    seq: u64,
    epoch: u32,
    links: Vec<String>,
}

impl AnchorIn {
    fn to_anchor(&self) -> Result<Anchor, Error> {
        let links = self
            .links
            .iter()
            .map(|link| -> Result<Hash, Error> {
                b64::decode(link)?
                    .try_into()
                    .map_err(|_: Vec<u8>| Error::Invalid)
            })
            .collect::<Result<Vec<Hash>, Error>>()?;
        Ok(Anchor {
            seq: self.seq,
            epoch: self.epoch,
            links,
        })
    }
}

/// An entry of the server's seal hash list for a record (`G5`).
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct SealListIn {
    bundle_version: u32,
    key: String,
    member: String,
    seal_hash: String,
    version: u32,
}

/// What a verified chain holds for one space in this unlock.
pub(crate) struct HeldChain {
    pub(crate) state: State,
    /// The link of every record, from `seq` 0: the anchor to store.
    links: Vec<Hash>,
    /// Whether first contact is done: the page's anchor was there, the chain is this account's own,
    /// or the person compared the fingerprint.
    pub(crate) trusted: bool,
    contact: ContactOut,
    divergence: Option<u64>,
}

// ---- what the page is told ---------------------------------------------------------------------

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct Refused {
    ok: bool,
    reason: &'static str,
    seq: Option<u64>,
}

impl Refused {
    fn new(reason: &'static str, seq: Option<u64>) -> Refused {
        Refused {
            ok: false,
            reason,
            seq,
        }
    }
}

#[derive(Serialize)]
#[serde(untagged)]
pub(crate) enum Verdict {
    View(Box<ChainView>),
    Refused(Refused),
}

#[derive(Serialize)]
struct HeadOut {
    seq: u64,
    /// The head's link, base64url.
    link: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct MemberOut {
    id: String,
    role: &'static str,
    custom: Vec<&'static str>,
    status: &'static str,
    invited_by: String,
    /// The chain's bundle of the member, base64url; absent until they are confirmed.
    #[serde(skip_serializing_if = "Option::is_none")]
    bundle: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    bundle_version: Option<u32>,
    /// The fingerprint of that bundle, as 12 groups of 5 digits.
    #[serde(skip_serializing_if = "Option::is_none")]
    fingerprint: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    confirmed_by: Option<String>,
    /// The `seq` of the record that confirmed them.
    #[serde(skip_serializing_if = "Option::is_none")]
    confirmed_seq: Option<u64>,
    /// The `seq` of their last `rekey`: nobody compared the new fingerprint.
    #[serde(skip_serializing_if = "Option::is_none")]
    rekey_seq: Option<u64>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct SpaceOut {
    key_version: u32,
    marked: bool,
    name_hash: String,
    name_version: u32,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct CollectionOut {
    id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    parent: Option<String>,
    key_version: u32,
    marked: bool,
    name_hash: String,
    name_version: u32,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct GroupOut {
    id: String,
    members: Vec<String>,
    name_hash: String,
    name_version: u32,
}

#[derive(Serialize)]
struct GrantOut {
    collection: String,
    grantee: String,
    permission: &'static str,
}

/// A key of the space, and what this account holds of it.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct KeyOut {
    /// `space` or `collection:<uuid>`.
    key: String,
    /// The key's current version in the chain.
    version: u32,
    marked: bool,
    /// The `seq` of the record that committed this account's seal of that version, when it did.
    #[serde(skip_serializing_if = "Option::is_none")]
    seal_seq: Option<u64>,
    /// Whether the commitment covers more than this account, so its seal hash list is needed.
    needs_list: bool,
}

#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct OwnerOut {
    id: String,
    fingerprint: String,
}

/// What the person does on first contact.
#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct ContactOut {
    /// `self` (nothing to compare), `compare` (compare `fingerprint` with `person`'s) or `pick`
    /// (pick one of `owners` and compare with them).
    kind: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    person: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    fingerprint: Option<String>,
    owners: Vec<OwnerOut>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct ChainView {
    ok: bool,
    /// Whether the space has a chain at all. A space with none is as it was before chains.
    chained: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    head: Option<HeadOut>,
    epoch: u32,
    /// The link of every record, base64url: what the page stores as its anchor.
    links: Vec<String>,
    /// Whether first contact is done, so keys may be opened.
    trusted: bool,
    /// What to compare, while `trusted` is false.
    #[serde(skip_serializing_if = "Option::is_none")]
    first_contact: Option<ContactOut>,
    /// The `seq` of the `fence` where the chain parted from the page's anchor, when it did.
    #[serde(skip_serializing_if = "Option::is_none")]
    divergence: Option<u64>,
    members: Vec<MemberOut>,
    space: SpaceOut,
    collections: Vec<CollectionOut>,
    groups: Vec<GroupOut>,
    grants: Vec<GrantOut>,
    keys: Vec<KeyOut>,
}

fn uuid(id: &Id) -> String {
    sc::uuid_text(id)
}

fn text_of(hash: &Hash) -> String {
    b64::encode(hash)
}

/// The view of a verified state for the page, from the point of view of account `me`.
fn view_of(held: &HeldChain, me: &Id) -> ChainView {
    let state = &held.state;
    let members = state
        .members
        .iter()
        .map(|(id, m)| MemberOut {
            id: uuid(id),
            role: m.role.as_str(),
            custom: m.custom.iter().map(|p| p.as_str()).collect(),
            status: match m.status {
                Status::Invited => "invited",
                Status::Confirmed => "confirmed",
                Status::Removed => "removed",
            },
            invited_by: uuid(&m.invited_by),
            bundle: m.bundle.as_ref().map(|b| b64::encode(&b.to_bytes())),
            bundle_version: m.bundle.as_ref().map(|b| b.key_version),
            fingerprint: m.bundle.as_ref().map(Bundle::fingerprint_text),
            confirmed_by: m.confirmation.as_ref().map(|c| uuid(&c.by)),
            confirmed_seq: m.confirmation.as_ref().map(|c| c.seq),
            rekey_seq: m.rekey_seq,
        })
        .collect();
    let keys = state
        .keys()
        .into_iter()
        .map(|key| {
            let version = state.key_version(&key).unwrap_or(0);
            let seal = state.seals.get(&(key, version, *me));
            let alone = seal
                .and_then(|s| state.commitments.get(&(key, version, s.seq)))
                .is_some_and(|c| c.recipients.len() == 1);
            KeyOut {
                key: key.text(),
                version,
                marked: state.key_marked(&key),
                seal_seq: seal.map(|s| s.seq),
                needs_list: seal.is_some() && !alone,
            }
        })
        .collect();
    ChainView {
        ok: true,
        chained: true,
        head: state.head.map(|h| HeadOut {
            seq: h.seq,
            link: text_of(&h.link),
        }),
        epoch: state.epoch,
        links: held.links.iter().map(text_of).collect(),
        trusted: held.trusted,
        first_contact: (!held.trusted).then(|| held.contact.clone()),
        divergence: held.divergence,
        members,
        space: SpaceOut {
            key_version: state.space.key_version,
            marked: state.space.marked,
            name_hash: text_of(&state.space.name_hash),
            name_version: state.space.name_version,
        },
        collections: state
            .collections
            .iter()
            .map(|(id, c)| CollectionOut {
                id: uuid(id),
                parent: c.parent.as_ref().map(uuid),
                key_version: c.key_version,
                marked: c.marked,
                name_hash: text_of(&c.name_hash),
                name_version: c.name_version,
            })
            .collect(),
        groups: state
            .groups
            .iter()
            .map(|(id, g)| GroupOut {
                id: uuid(id),
                members: g.members.iter().map(uuid).collect(),
                name_hash: text_of(&g.name_hash),
                name_version: g.name_version,
            })
            .collect(),
        grants: state
            .grants
            .iter()
            .map(|((collection, grantee), permission)| GrantOut {
                collection: uuid(collection),
                grantee: grantee.text(),
                permission: permission.as_str(),
            })
            .collect(),
        keys,
    }
}

/// The view of a space with no chain.
fn unchained() -> ChainView {
    ChainView {
        ok: true,
        chained: false,
        head: None,
        epoch: 0,
        links: Vec::new(),
        trusted: true,
        first_contact: None,
        divergence: None,
        members: Vec::new(),
        space: SpaceOut {
            key_version: 0,
            marked: false,
            name_hash: String::new(),
            name_version: 0,
        },
        collections: Vec::new(),
        groups: Vec::new(),
        grants: Vec::new(),
        keys: Vec::new(),
    }
}

// ---- first contact -----------------------------------------------------------------------------

/// The `seq` of the last record each account signed, and of the last `invite` of `me`.
fn signers(chain: &[SignedRecord], me: &Id) -> (BTreeMap<Id, u64>, Option<u64>) {
    let mut last = BTreeMap::new();
    let mut invited = None;
    for signed in chain {
        let Ok(record) = Record::parse(&signed.entry) else {
            continue;
        };
        last.insert(record.by, record.seq);
        if let Body::Invite { member, .. } = &record.body
            && member == me
        {
            invited = Some(record.seq);
        }
    }
    (last, invited)
}

/// What the person does: compare with the inviter or confirmer, nothing when the chain is this
/// account's own, or pick a confirmed Owner who signed a record since this account was admitted.
fn contact_of(
    state: &State,
    me: &Id,
    own_bundle: &[u8],
    last_signed: &BTreeMap<Id, u64>,
    invited_seq: Option<u64>,
) -> ContactOut {
    let own_listed = state
        .confirmed(me)
        .and_then(|m| m.bundle.as_ref())
        .is_some_and(|b| b.to_bytes() == own_bundle);
    let pick = || {
        let admitted = state.members.get(me).map_or(0, |m| match m.status {
            Status::Invited => invited_seq.unwrap_or(0),
            _ => m.confirmation.as_ref().map_or(0, |c| c.seq),
        });
        ContactOut {
            kind: "pick",
            person: None,
            fingerprint: None,
            owners: state
                .members
                .iter()
                .filter(|(id, m)| {
                    *id != me
                        && m.status == Status::Confirmed
                        && m.role == sc::Role::Owner
                        && last_signed.get(*id).is_some_and(|seq| *seq >= admitted)
                })
                .filter_map(|(id, m)| {
                    m.bundle.as_ref().map(|b| OwnerOut {
                        id: uuid(id),
                        fingerprint: b.fingerprint_text(),
                    })
                })
                .collect(),
        }
    };
    match anchor_person(state, me) {
        // The chain's own key for this account must be the one this browser holds, or the chain
        // vouches for nothing: a server can put its own bundle under any account id.
        FirstContact::SelfVouched if own_listed => ContactOut {
            kind: "self",
            person: None,
            fingerprint: None,
            owners: Vec::new(),
        },
        FirstContact::SelfVouched | FirstContact::PickOwner => pick(),
        FirstContact::Compare(person) => ContactOut {
            kind: "compare",
            person: Some(uuid(&person.person)),
            fingerprint: Some(fingerprint_groups(&person.fingerprint).join(" ")),
            owners: Vec::new(),
        },
    }
}

fn own_bundle_bytes(session: &Session) -> Result<Vec<u8>, Error> {
    let unlocked = session.unlocked()?;
    let (kx_private, sig_private) = unlocked.private.as_ref().ok_or(Error::Locked)?;
    Ok(Bundle {
        account_id: unlocked.account_id,
        key_version: unlocked.key_version,
        kx1_public: kx_private.public_key()?,
        sig1_public: sig_private.public_key()?,
    }
    .to_bytes())
}

// ---- the operations ----------------------------------------------------------------------------

impl Session {
    /// Verifies the chain the server served for `space` ("Verification"), against the page's
    /// `anchor` and the head this unlock already verified, and keeps the state when it verifies.
    ///
    /// A refusal is a [`Verdict::Refused`] with the spec's reason and the `seq`, not an error: the
    /// page shows the space as "can't be checked". Anything the page sent that isn't well formed
    /// is an error. An empty chain is a space with no chain, unless the anchor says there was one.
    pub(crate) fn verify_space_chain(
        &mut self,
        space: &Id,
        wire: &[WireIn],
        anchor: Option<&AnchorIn>,
    ) -> Result<Verdict, Error> {
        let verdict = self.verify_inner(space, wire, anchor)?;
        // A chain the server served and the verifier refused is still a chain: the space stays
        // closed to the unchained operations, so a page can't fall back on keys the server names.
        let unlocked = self.unlocked_mut()?;
        match &verdict {
            Verdict::Refused(_) => {
                unlocked.spaces.refused.insert(*space);
            }
            Verdict::View(_) => {
                unlocked.spaces.refused.remove(space);
            }
        }
        Ok(verdict)
    }

    fn verify_inner(
        &mut self,
        space: &Id,
        wire: &[WireIn],
        anchor: Option<&AnchorIn>,
    ) -> Result<Verdict, Error> {
        let own = own_bundle_bytes(self)?;
        let me = self.unlocked()?.account_id;
        let mut chain = Vec::with_capacity(wire.len());
        for (i, record) in wire.iter().enumerate() {
            match SignedRecord::from_wire(
                &record.entry,
                &record.signature,
                record.cosignature.as_deref(),
            ) {
                Ok(signed) => chain.push(signed),
                Err(reason) => {
                    return Ok(Verdict::Refused(Refused::new(
                        reason.as_str(),
                        u64::try_from(i).ok(),
                    )));
                }
            }
        }

        let given = anchor.map(AnchorIn::to_anchor).transpose()?;
        let unlocked = self.unlocked_mut()?;
        let before = unlocked.spaces.chains.get(space);
        // The head this unlock verified is an anchor too: a server can't roll a chain back or fork
        // it between two reads in one session.
        let held_anchor = before.and_then(|held| {
            held.state.head.map(|head| Anchor {
                seq: head.seq,
                epoch: held.state.epoch,
                links: held.links.clone(),
            })
        });
        let effective = match (given.as_ref(), held_anchor) {
            (Some(a), Some(h)) if h.seq > a.seq => Some(h),
            (Some(a), _) => Some(a.clone()),
            (None, h) => h,
        };
        let previously_trusted = before.is_some_and(|held| held.trusted);

        let verified = match verify_chain(space, &chain, effective.as_ref()) {
            Ok(verified) => verified,
            Err(error) => {
                return Ok(Verdict::Refused(Refused::new(
                    error.reason.as_str(),
                    error.seq,
                )));
            }
        };
        if verified.state.head.is_none() {
            return Ok(Verdict::View(Box::new(unchained())));
        }

        // The chain's bundle for this account, at the key version this account is at, is this
        // account's own key: another one means someone else's key is in the account's place.
        if let Some(listed) = verified.state.confirmed(&me).and_then(|m| m.bundle.as_ref())
            && listed.key_version == unlocked.key_version
            && listed.to_bytes() != own
        {
            return Ok(Verdict::Refused(Refused::new("own keys", None)));
        }

        let (last_signed, invited_seq) = signers(&chain, &me);
        let contact = contact_of(&verified.state, &me, &own, &last_signed, invited_seq);
        let trusted = given.is_some() || previously_trusted || contact.kind == "self";
        let held = HeldChain {
            state: verified.state,
            links: verified.links,
            trusted,
            contact,
            divergence: verified.divergence,
        };
        let view = view_of(&held, &me);
        unlocked.spaces.chains.insert(*space, held);
        Ok(Verdict::View(Box::new(view)))
    }

    /// The view of the chain this unlock holds for `space`, when it does.
    pub(crate) fn space_chain_view(&self, space: &Id) -> Result<Option<ChainView>, Error> {
        let unlocked = self.unlocked()?;
        Ok(unlocked
            .spaces
            .chains
            .get(space)
            .map(|held| view_of(held, &unlocked.account_id)))
    }

    /// The person compared the fingerprint of the anchor person and it matched: the chain is
    /// trusted from now on in this unlock, and keys of the space may be opened and sealed.
    pub(crate) fn accept_first_contact(&mut self, space: &Id) -> Result<(), Error> {
        let unlocked = self.unlocked_mut()?;
        let held = unlocked.spaces.chains.get_mut(space).ok_or(Error::Invalid)?;
        held.trusted = true;
        Ok(())
    }

    /// Opens the space key or a collection key of a chained space at the chain's current version,
    /// and keeps it. `served_version` and `sealed` are what the server served for this account;
    /// `list` is the server's seal hash list for the record that committed the seal, when the
    /// commitment covers more than this account.
    pub(crate) fn open_chain_key(
        &mut self,
        space: &Id,
        key: &KeyRef,
        served_version: u32,
        sealed: &[u8],
        list: Option<&[SealListEntry]>,
    ) -> Result<(), Error> {
        let unlocked = self.unlocked_mut()?;
        let held = unlocked.spaces.chains.get(space).ok_or(Error::Invalid)?;
        if !held.trusted {
            return Err(Error::Invalid);
        }
        let (kx_private, _) = unlocked.private.as_ref().ok_or(Error::Locked)?;
        let version = held.state.key_version(key).ok_or(Error::Invalid)?;
        let secret = open_key(
            &held.state,
            space,
            &unlocked.account_id,
            kx_private,
            key,
            served_version,
            sealed,
            list,
        )
        .map_err(|_| Error::Invalid)?;
        let opened = SecretKey::from_bytes(&secret);
        match key {
            KeyRef::Space => {
                unlocked.spaces.spaces.insert((*space, version), opened);
            }
            KeyRef::Collection(collection) => {
                unlocked
                    .spaces
                    .collections
                    .insert((*space, *collection, version), opened);
            }
        }
        Ok(())
    }
}

/// The server's seal hash list entries of one key version, as `open_key` takes them, in ascending
/// order of member.
pub(crate) fn seal_list(
    entries: &[SealListIn],
    key: &KeyRef,
    version: u32,
) -> Result<Vec<SealListEntry>, Error> {
    let mut out = Vec::new();
    for entry in entries {
        if entry.version != version || KeyRef::parse(&entry.key) != Some(*key) {
            continue;
        }
        let member = ids::parse_uuid(&entry.member)?;
        let hash: Hash = b64::decode(&entry.seal_hash)?
            .try_into()
            .map_err(|_: Vec<u8>| Error::Invalid)?;
        out.push((member, entry.bundle_version, hash));
    }
    out.sort_by_key(|(member, _, _)| *member);
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_anchor_reads_and_refuses_what_is_not_a_link() {
        let good = AnchorIn {
            seq: 1,
            epoch: 1,
            links: vec![b64::encode(&[7u8; 32]), b64::encode(&[8u8; 32])],
        };
        let anchor = good.to_anchor().expect("an anchor");
        assert_eq!(anchor.seq, 1);
        assert_eq!(anchor.links, vec![[7u8; 32], [8u8; 32]]);
        let short = AnchorIn {
            seq: 0,
            epoch: 1,
            links: vec![b64::encode(&[7u8; 31])],
        };
        assert_eq!(short.to_anchor().map(|_| ()), Err(Error::Invalid));
        let junk = AnchorIn {
            seq: 0,
            epoch: 1,
            links: vec!["not base64!".to_owned()],
        };
        assert_eq!(junk.to_anchor().map(|_| ()), Err(Error::Invalid));
    }

    #[test]
    fn a_seal_list_keeps_one_key_version_in_member_order() {
        let entry = |member: &str, key: &str, version: u32, byte: u8| SealListIn {
            bundle_version: 1,
            key: key.to_owned(),
            member: member.to_owned(),
            seal_hash: b64::encode(&[byte; 32]),
            version,
        };
        let b = "00000000-0000-4000-8000-00000000000b";
        let a = "00000000-0000-4000-8000-00000000000a";
        let entries = [
            entry(b, "space", 2, 2),
            entry(a, "space", 2, 1),
            entry(a, "space", 1, 9),
            entry(a, "collection:00000000-0000-4000-8000-0000000000c1", 2, 8),
        ];
        let list = seal_list(&entries, &KeyRef::Space, 2).expect("a list");
        assert_eq!(list.len(), 2);
        assert_eq!(list[0].0[15], 0x0a);
        assert_eq!(list[1].0[15], 0x0b);
        assert_eq!(list[0].2, [1u8; 32]);
        let bad = [entry("not-a-uuid", "space", 2, 1)];
        assert_eq!(seal_list(&bad, &KeyRef::Space, 2), Err(Error::Invalid));
    }

    #[test]
    fn a_refusal_names_its_reason_and_seq() {
        let json = serde_json::to_string(&Verdict::Refused(Refused::new("forked", Some(3))))
            .expect("json");
        assert_eq!(json, r#"{"ok":false,"reason":"forked","seq":3}"#);
    }

    #[test]
    fn a_space_with_no_chain_is_not_chained() {
        let json = serde_json::to_string(&Verdict::View(Box::new(unchained()))).expect("json");
        assert!(json.contains(r#""ok":true"#));
        assert!(json.contains(r#""chained":false"#));
        assert!(json.contains(r#""trusted":true"#));
    }
}
