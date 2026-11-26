//! A federated vault's home, its epoch, signed promotions, and the fence around home-only writes.
//!
//! The **home** is the one server that orders a vault's members, roles, keys and policies. Each
//! change of home raises the vault's **epoch** by one. A **promotion record**, signed by the new
//! home with its identity key, announces it; peers accept it only from a server already in the
//! vault's set, and put the new home first. Every home-only write carries the epoch it was made
//! under: a write from an older epoch (the old home, back after a split) is not applied but kept
//! for the vault's admins to redo or drop. Items are not home-only; they replicate from any
//! server holding the vault.

use crate::cbor::Value;
use crate::crypto;
use crate::error::{FedError, Result};
use crate::identity::KeyDirectory;
use crate::signed::Signed;
use crate::wire::{owner, server_id};
use kemlock_crypto::sig1;
use kemlock_domain::{Owner, ServerId};

/// The promotion and home-record format version.
pub const VERSION: u64 = 1;
/// The `sig1` context of a promotion record.
pub const PROMOTION_CONTEXT: &str = "federation-promotion";
/// The `sig1` context of a home record.
pub const HOME_RECORD_CONTEXT: &str = "federation-home-record";
/// The most replicas a vault may have.
pub const MAX_REPLICAS: usize = 32;
/// The largest home-record payload.
pub const MAX_PAYLOAD: usize = 256 * 1024;
/// The most earlier epochs whose home a vault remembers.
pub const MAX_HOME_HISTORY: usize = 256;

/// The admin's choice per vault. Local is the default and means the vault never leaves its server.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Policy {
    Local,
    Federated,
}

impl Policy {
    pub fn as_str(self) -> &'static str {
        match self {
            Policy::Local => "local",
            Policy::Federated => "federated",
        }
    }

    pub fn parse(s: &str) -> Option<Policy> {
        match s {
            "local" => Some(Policy::Local),
            "federated" => Some(Policy::Federated),
            _ => None,
        }
    }
}

/// How one vault is federated.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VaultFederation {
    pub owner: Owner,
    pub policy: Policy,
    /// The server that orders members, keys and policies.
    pub home: ServerId,
    /// Raised by one at each promotion. Starts at 1.
    pub epoch: u64,
    /// The replicas, in the order devices fail over to them.
    pub replicas: Vec<ServerId>,
    /// The signed promotion record that made the current epoch, if any.
    pub promotion: Option<Vec<u8>>,
    /// A promotion another server signed that would make it the home of a vault this server is
    /// the home of. It is held, not applied, until this server's own admin accepts it: otherwise
    /// any replica could take a vault over, and as its home erase this server's copy.
    pub held_demotion: Option<Vec<u8>>,
    /// The home of each earlier epoch, oldest first: every promotion adds the home it replaced.
    /// A server that learned of the vault at a later epoch has none for the epochs before.
    pub home_history: Vec<(u64, ServerId)>,
}

impl VaultFederation {
    /// A vault that never leaves its server.
    pub fn local(owner: Owner, home: ServerId) -> VaultFederation {
        VaultFederation {
            owner,
            policy: Policy::Local,
            home,
            epoch: 1,
            replicas: Vec::new(),
            promotion: None,
            held_demotion: None,
            home_history: Vec::new(),
        }
    }

    /// A federated vault at epoch 1.
    pub fn federated(owner: Owner, home: ServerId, replicas: Vec<ServerId>) -> VaultFederation {
        VaultFederation {
            owner,
            policy: Policy::Federated,
            home,
            epoch: 1,
            replicas,
            promotion: None,
            held_demotion: None,
            home_history: Vec::new(),
        }
    }

    /// Whether `server` is the home or a replica.
    pub fn holds(&self, server: ServerId) -> bool {
        self.home == server || self.replicas.contains(&server)
    }

    /// The server that was the home in `epoch`, when this server knows: the current home for the
    /// current epoch, the recorded one for an earlier epoch, and `None` for an epoch it never
    /// saw (or a later one).
    pub fn epoch_home(&self, epoch: u64) -> Option<ServerId> {
        if epoch == self.epoch {
            return Some(self.home);
        }
        self.home_history
            .iter()
            .find(|(e, _)| *e == epoch)
            .map(|(_, home)| *home)
    }

    /// The servers in failover order: the home first, then each replica.
    pub fn order(&self) -> Vec<ServerId> {
        let mut out = vec![self.home];
        out.extend(self.replicas.iter().copied());
        out
    }
}

fn ids_value(ids: &[ServerId]) -> Value {
    Value::Array(ids.iter().map(|i| Value::bytes(i.as_bytes())).collect())
}

fn ids_from(values: &[Value]) -> Result<Vec<ServerId>> {
    if values.len() > MAX_REPLICAS {
        return Err(FedError::Malformed("too many replicas"));
    }
    values
        .iter()
        .map(|v| -> Result<ServerId> {
            let b: [u8; 16] = v
                .as_bytes()?
                .try_into()
                .map_err(|_| FedError::Malformed("a server id has the wrong length"))?;
            Ok(server_id(b))
        })
        .collect()
}

/// A change of home, signed by the new home.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PromotionRecord {
    pub vault: Owner,
    /// The epoch this record starts.
    pub epoch: u64,
    pub new_home: ServerId,
    pub previous_home: ServerId,
    /// Unix seconds.
    pub issued_at: u64,
    /// The replicas after the promotion: the others in their order, the old home last.
    pub replicas: Vec<ServerId>,
}

impl PromotionRecord {
    /// The record that promotes `new_home` (a replica of `current`) at `issued_at`.
    pub fn build(
        current: &VaultFederation,
        new_home: ServerId,
        issued_at: u64,
    ) -> Result<PromotionRecord> {
        if current.policy != Policy::Federated {
            return Err(FedError::Refused(
                "only a federated vault has a home to move",
            ));
        }
        if !current.replicas.contains(&new_home) {
            return Err(FedError::Refused("only a replica can become the home"));
        }
        let mut replicas: Vec<ServerId> = current
            .replicas
            .iter()
            .copied()
            .filter(|r| *r != new_home)
            .collect();
        // The old home rejoins at the end of the replica order.
        replicas.push(current.home);
        Ok(PromotionRecord {
            vault: current.owner,
            epoch: current.epoch + 1,
            new_home,
            previous_home: current.home,
            issued_at,
            replicas,
        })
    }

    pub fn to_body(&self) -> Vec<u8> {
        Value::map(vec![
            (0, Value::Uint(VERSION)),
            (1, Value::bytes(&self.vault.to_bytes())),
            (2, Value::Uint(self.epoch)),
            (3, Value::bytes(self.new_home.as_bytes())),
            (4, Value::bytes(self.previous_home.as_bytes())),
            (5, Value::Uint(self.issued_at)),
            (6, ids_value(&self.replicas)),
        ])
        .encode()
    }

    pub fn from_body(body: &[u8]) -> Result<PromotionRecord> {
        let value = Value::decode(body)?;
        let f = value.as_fields()?;
        f.only(&[0, 1, 2, 3, 4, 5, 6])?;
        if f.uint(0)? != VERSION {
            return Err(FedError::Malformed("unknown promotion version"));
        }
        Ok(PromotionRecord {
            vault: owner(f.fixed::<17>(1)?)?,
            epoch: f.uint(2)?,
            new_home: server_id(f.fixed::<16>(3)?),
            previous_home: server_id(f.fixed::<16>(4)?),
            issued_at: f.uint(5)?,
            replicas: ids_from(f.array(6)?)?,
        })
    }

    /// Signs the record with the new home's identity key.
    pub fn sign(&self, key: &sig1::SigningKey) -> Result<Signed> {
        Signed::sign(key, PROMOTION_CONTEXT, self.to_body())
    }
}

/// The fields of a signed promotion, without checking the signature: for showing a held demotion,
/// whose signature was checked when it arrived and is checked again when it is accepted.
pub fn peek_promotion(envelope: &[u8]) -> Result<PromotionRecord> {
    PromotionRecord::from_body(&Signed::decode(envelope)?.body)
}

/// Parses a signed promotion and checks the new home's signature with the key `keys` holds.
pub fn open_promotion(envelope: &[u8], keys: &dyn KeyDirectory) -> Result<PromotionRecord> {
    let signed = Signed::decode(envelope)?;
    let record = PromotionRecord::from_body(&signed.body)?;
    let key = keys.identity_key(record.new_home).ok_or(FedError::Refused(
        "a promotion by a server we hold no key for",
    ))?;
    signed.verify(&key, PROMOTION_CONTEXT)?;
    if record.to_body() != signed.body {
        return Err(FedError::Invalid("the promotion body is not canonical"));
    }
    Ok(record)
}

/// The vault after a promotion, or why this server refuses it.
///
/// The record must be for this vault and the next epoch, name the home we know as the previous
/// home, come from a replica we know, and keep exactly the servers we know. Two replicas that
/// promote themselves at once both make records for the same next epoch; the first to arrive
/// wins and the other fails the previous-home check, which is why an admin does it.
pub fn apply_promotion(
    current: &VaultFederation,
    record: &PromotionRecord,
) -> Result<VaultFederation> {
    if record.vault != current.owner || current.policy != Policy::Federated {
        return Err(FedError::Refused(
            "the promotion is not for a federated vault we hold",
        ));
    }
    if record.epoch <= current.epoch {
        return Err(FedError::Refused(
            "the promotion is for an epoch we already passed",
        ));
    }
    if record.epoch != current.epoch + 1 {
        return Err(FedError::Refused("the promotion skips an epoch"));
    }
    if record.previous_home != current.home {
        return Err(FedError::Refused(
            "the promotion's previous home is not our home",
        ));
    }
    if !current.replicas.contains(&record.new_home) {
        return Err(FedError::Refused(
            "a promotion only from a server already in the set",
        ));
    }
    let mut ours: Vec<ServerId> = current.order();
    ours.sort();
    let mut theirs: Vec<ServerId> = record.replicas.clone();
    theirs.push(record.new_home);
    theirs.sort();
    if ours != theirs {
        return Err(FedError::Refused(
            "the promotion changes the set of servers",
        ));
    }
    let mut home_history = current.home_history.clone();
    home_history.push((current.epoch, current.home));
    if home_history.len() > MAX_HOME_HISTORY {
        home_history.remove(0);
    }
    Ok(VaultFederation {
        owner: current.owner,
        policy: Policy::Federated,
        home: record.new_home,
        epoch: record.epoch,
        replicas: record.replicas.clone(),
        promotion: None,
        held_demotion: None,
        home_history,
    })
}

/// What to do with a home-only write, by its epoch.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Fence {
    /// The epoch is the vault's current one.
    Accept,
    /// The epoch is older: the write came from a home that has since been replaced.
    Stale,
    /// The epoch is newer than ours: we have missed a promotion.
    Behind,
}

pub fn fence(current_epoch: u64, write_epoch: u64) -> Fence {
    match write_epoch.cmp(&current_epoch) {
        std::cmp::Ordering::Equal => Fence::Accept,
        std::cmp::Ordering::Less => Fence::Stale,
        std::cmp::Ordering::Greater => Fence::Behind,
    }
}

/// How many low bits of a home record's index count the records of one epoch.
pub const INDEX_SEQ_BITS: u32 = 32;
const INDEX_SEQ_MASK: u64 = (1 << INDEX_SEQ_BITS) - 1;
/// The highest epoch an index can carry.
const INDEX_MAX_EPOCH: u64 = (1 << 31) - 1;

/// The index of the `seq`th (from 1) home record made under `epoch`: the epoch in the high bits,
/// the count in the low ones. The old home, cut off, and the new home each count from 1 in their
/// own epoch, so two records made apart never have the same index.
pub fn home_index(epoch: u64, seq: u64) -> u64 {
    (epoch.min(INDEX_MAX_EPOCH) << INDEX_SEQ_BITS) | (seq & INDEX_SEQ_MASK)
}

/// The count within its epoch of a record's index.
pub fn index_seq(index: u64) -> u64 {
    index & INDEX_SEQ_MASK
}

/// The epoch an index was made under.
pub fn index_epoch(index: u64) -> u64 {
    index >> INDEX_SEQ_BITS
}

/// A home-only write (a member, a role, a policy, a space key) as it travels to the replicas. The
/// server only moves it: what `payload` holds is for the spaces code that wrote it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HomeRecord {
    pub vault: Owner,
    /// Orders the vault's home records: [`home_index`] of the epoch and the count within it,
    /// from 1. Records made apart in different epochs can't collide.
    pub index: u64,
    /// The epoch the write was made under.
    pub epoch: u64,
    pub kind: String,
    pub payload: Vec<u8>,
    /// The server that made the write.
    pub signer: ServerId,
}

impl HomeRecord {
    pub fn to_body(&self) -> Vec<u8> {
        Value::map(vec![
            (0, Value::Uint(VERSION)),
            (1, Value::bytes(&self.vault.to_bytes())),
            (2, Value::Uint(self.index)),
            (3, Value::Uint(self.epoch)),
            (4, Value::text(&self.kind)),
            (5, Value::bytes(&self.payload)),
            (6, Value::bytes(self.signer.as_bytes())),
        ])
        .encode()
    }

    pub fn from_body(body: &[u8]) -> Result<HomeRecord> {
        let value = Value::decode(body)?;
        let f = value.as_fields()?;
        f.only(&[0, 1, 2, 3, 4, 5, 6])?;
        if f.uint(0)? != VERSION {
            return Err(FedError::Malformed("unknown home record version"));
        }
        let kind = f.text(4)?;
        let payload = f.bytes(5)?;
        if kind.is_empty() || kind.len() > 64 || payload.len() > MAX_PAYLOAD {
            return Err(FedError::Malformed("a home record is out of bounds"));
        }
        let record = HomeRecord {
            vault: owner(f.fixed::<17>(1)?)?,
            index: f.uint(2)?,
            epoch: f.uint(3)?,
            kind: kind.to_owned(),
            payload: payload.to_vec(),
            signer: server_id(f.fixed::<16>(6)?),
        };
        if record.index == 0 || record.epoch == 0 {
            return Err(FedError::Malformed("index and epoch start at 1"));
        }
        Ok(record)
    }

    pub fn sign(&self, key: &sig1::SigningKey) -> Result<Signed> {
        Signed::sign(key, HOME_RECORD_CONTEXT, self.to_body())
    }
}

/// Parses a signed home record and checks its signer's signature.
pub fn open_home_record(envelope: &[u8], keys: &dyn KeyDirectory) -> Result<HomeRecord> {
    let signed = Signed::decode(envelope)?;
    let record = HomeRecord::from_body(&signed.body)?;
    let key = keys.identity_key(record.signer).ok_or(FedError::Refused(
        "a home record by a server we hold no key for",
    ))?;
    signed.verify(&key, HOME_RECORD_CONTEXT)?;
    if record.to_body() != signed.body {
        return Err(FedError::Invalid("the home record body is not canonical"));
    }
    Ok(record)
}

/// What the receiving server does with a verified home record.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Verdict {
    /// Current epoch, signed by the home: apply it.
    Apply,
    /// Older epoch: keep it for the admins to redo or drop; apply nothing.
    Quarantine,
    /// Newer epoch: we have missed a promotion and must fetch it first.
    Behind,
}

/// Decides a home record against what this server knows of the vault.
pub fn judge(current: &VaultFederation, record: &HomeRecord) -> Result<Verdict> {
    if record.vault != current.owner || current.policy != Policy::Federated {
        return Err(FedError::Refused(
            "a home record for a vault we do not federate",
        ));
    }
    if !current.holds(record.signer) {
        return Err(FedError::Refused(
            "a home record from a server outside the vault's set",
        ));
    }
    match fence(current.epoch, record.epoch) {
        Fence::Accept if record.signer == current.home => Ok(Verdict::Apply),
        Fence::Accept => Err(FedError::Refused(
            "a current-epoch home record not made by the home",
        )),
        Fence::Stale => Ok(Verdict::Quarantine),
        Fence::Behind => Ok(Verdict::Behind),
    }
}

/// The signing context labels, for the docs and vectors.
pub fn contexts() -> [&'static str; 2] {
    [PROMOTION_CONTEXT, HOME_RECORD_CONTEXT]
}

/// The public key of an identity, for tests and callers that hold a signing key.
pub fn public_of(key: &sig1::SigningKey) -> Result<sig1::PublicKey> {
    crypto::sign_public(key)
}

#[cfg(test)]
mod tests {
    use super::*;
    use kemlock_domain::UserId;
    use std::collections::HashMap;

    struct World {
        ids: Vec<ServerId>,
        keys: Vec<sig1::SigningKey>,
        directory: HashMap<ServerId, sig1::PublicKey>,
        vault: VaultFederation,
    }

    fn world() -> World {
        let ids: Vec<ServerId> = (0..3).map(|_| ServerId::random()).collect();
        let keys: Vec<sig1::SigningKey> = (0..3u8)
            .map(|i| sig1::SigningKey::from_bytes(&[i + 1; 64]))
            .collect();
        let directory = ids
            .iter()
            .zip(&keys)
            .map(|(id, k)| (*id, public_of(k).expect("public")))
            .collect();
        let vault =
            VaultFederation::federated(Owner::User(UserId::random()), ids[0], vec![ids[1], ids[2]]);
        World {
            ids,
            keys,
            directory,
            vault,
        }
    }

    #[test]
    fn the_order_is_home_then_replicas() {
        let w = world();
        assert_eq!(w.vault.order(), w.ids);
        assert!(w.vault.holds(w.ids[2]));
        assert!(!w.vault.holds(ServerId::random()));
        assert_eq!(Policy::parse("local"), Some(Policy::Local));
        assert_eq!(
            Policy::parse(Policy::Federated.as_str()),
            Some(Policy::Federated)
        );
        assert_eq!(Policy::parse("x"), None);
        let local = VaultFederation::local(w.vault.owner, w.ids[0]);
        assert_eq!(local.policy, Policy::Local);
    }

    #[test]
    fn a_promotion_raises_the_epoch_and_puts_the_old_home_last() {
        let w = world();
        let record = PromotionRecord::build(&w.vault, w.ids[2], 1_800_000_000).expect("build");
        assert_eq!(record.epoch, 2);
        assert_eq!(record.replicas, vec![w.ids[1], w.ids[0]]);
        let signed = record.sign(&w.keys[2]).expect("sign").encode();
        let opened = open_promotion(&signed, &w.directory).expect("open");
        assert_eq!(opened, record);
        let next = apply_promotion(&w.vault, &opened).expect("apply");
        assert_eq!(next.home, w.ids[2]);
        assert_eq!(next.epoch, 2);
        assert_eq!(next.order(), vec![w.ids[2], w.ids[1], w.ids[0]]);
        // The new home's record of who held each epoch.
        assert_eq!(next.epoch_home(1), Some(w.ids[0]));
        assert_eq!(next.epoch_home(2), Some(w.ids[2]));
        assert_eq!(next.epoch_home(3), None);
        assert_eq!(w.vault.epoch_home(1), Some(w.ids[0]));
        assert_eq!(w.vault.epoch_home(2), None);
    }

    #[test]
    fn a_promotion_signed_by_anyone_but_the_new_home_fails() {
        let w = world();
        let record = PromotionRecord::build(&w.vault, w.ids[2], 1).expect("build");
        let by_other = record.sign(&w.keys[1]).expect("sign").encode();
        assert!(open_promotion(&by_other, &w.directory).is_err());
        let stranger = sig1::SigningKey::from_bytes(&[9; 64]);
        let by_stranger = record.sign(&stranger).expect("sign").encode();
        assert!(open_promotion(&by_stranger, &w.directory).is_err());
        // A promotion by a server we hold no key for.
        let none: HashMap<ServerId, sig1::PublicKey> = HashMap::new();
        let ok = record.sign(&w.keys[2]).expect("sign").encode();
        assert!(open_promotion(&ok, &none).is_err());
    }

    #[test]
    fn promotions_the_vault_cannot_take_are_refused() {
        let w = world();
        // Not a replica, and the home itself.
        assert!(PromotionRecord::build(&w.vault, ServerId::random(), 1).is_err());
        assert!(PromotionRecord::build(&w.vault, w.ids[0], 1).is_err());

        let good = PromotionRecord::build(&w.vault, w.ids[1], 1).expect("build");
        let mut skip = good.clone();
        skip.epoch = 3;
        assert!(apply_promotion(&w.vault, &skip).is_err());
        let mut old = good.clone();
        old.epoch = 1;
        assert!(apply_promotion(&w.vault, &old).is_err());
        let mut wrong_previous = good.clone();
        wrong_previous.previous_home = w.ids[2];
        assert!(apply_promotion(&w.vault, &wrong_previous).is_err());
        let mut outsider = good.clone();
        outsider.new_home = ServerId::random();
        assert!(apply_promotion(&w.vault, &outsider).is_err());
        let mut extra = good.clone();
        extra.replicas.push(ServerId::random());
        assert!(apply_promotion(&w.vault, &extra).is_err());
        let mut other_vault = good.clone();
        other_vault.vault = Owner::User(UserId::random());
        assert!(apply_promotion(&w.vault, &other_vault).is_err());
        let local = VaultFederation::local(w.vault.owner, w.ids[0]);
        assert!(apply_promotion(&local, &good).is_err());
        assert!(PromotionRecord::build(&local, w.ids[1], 1).is_err());
        // The right one still applies.
        assert!(apply_promotion(&w.vault, &good).is_ok());
    }

    #[test]
    fn the_second_of_two_simultaneous_promotions_is_refused() {
        let w = world();
        let one = PromotionRecord::build(&w.vault, w.ids[1], 1).expect("build");
        let two = PromotionRecord::build(&w.vault, w.ids[2], 1).expect("build");
        let after_one = apply_promotion(&w.vault, &one).expect("first");
        assert!(apply_promotion(&after_one, &two).is_err());
    }

    #[test]
    fn the_old_home_applies_the_promotion_when_it_returns() {
        let w = world();
        let record = PromotionRecord::build(&w.vault, w.ids[1], 1).expect("build");
        // The old home still holds the vault at epoch 1 with itself as home.
        let at_old_home = apply_promotion(&w.vault, &record).expect("apply");
        assert_eq!(at_old_home.home, w.ids[1]);
        assert_eq!(at_old_home.replicas.last(), Some(&w.ids[0]));
    }

    #[test]
    fn fencing_by_epoch() {
        assert_eq!(fence(4, 4), Fence::Accept);
        assert_eq!(fence(4, 3), Fence::Stale);
        assert_eq!(fence(4, 5), Fence::Behind);
    }

    fn home_record(w: &World, signer: usize, epoch: u64, index: u64) -> HomeRecord {
        HomeRecord {
            vault: w.vault.owner,
            index,
            epoch,
            kind: "member-added".to_owned(),
            payload: vec![1, 2, 3],
            signer: w.ids[signer],
        }
    }

    #[test]
    fn home_records_sign_open_and_are_judged_by_epoch() {
        let w = world();
        let r = home_record(&w, 0, 1, 1);
        let opened = open_home_record(&r.sign(&w.keys[0]).expect("sign").encode(), &w.directory)
            .expect("open");
        assert_eq!(opened, r);
        assert_eq!(judge(&w.vault, &r), Ok(Verdict::Apply));

        // After a promotion to epoch 2, the old home's epoch-1 write is quarantined.
        let promo = PromotionRecord::build(&w.vault, w.ids[1], 1).expect("build");
        let after = apply_promotion(&w.vault, &promo).expect("apply");
        assert_eq!(judge(&after, &r), Ok(Verdict::Quarantine));
        // The new home's epoch-2 write applies; the old home's epoch-2 claim doesn't.
        assert_eq!(judge(&after, &home_record(&w, 1, 2, 2)), Ok(Verdict::Apply));
        assert!(judge(&after, &home_record(&w, 0, 2, 2)).is_err());
        // A server that missed the promotion sees a newer epoch.
        assert_eq!(
            judge(&w.vault, &home_record(&w, 1, 2, 2)),
            Ok(Verdict::Behind)
        );
        // A stranger's record is refused outright.
        let mut stranger = r.clone();
        stranger.signer = ServerId::random();
        assert!(judge(&w.vault, &stranger).is_err());
    }

    #[test]
    fn a_changed_home_record_fails_its_signature() {
        let w = world();
        let r = home_record(&w, 0, 1, 1);
        let signed = r.sign(&w.keys[0]).expect("sign");
        let mut changed = r.clone();
        changed.payload = vec![9];
        let forged = Signed {
            body: changed.to_body(),
            signature: signed.signature,
        };
        assert!(open_home_record(&forged.encode(), &w.directory).is_err());
    }

    #[test]
    fn malformed_records_are_refused() {
        let w = world();
        let mut zero = home_record(&w, 0, 1, 1);
        zero.index = 0;
        assert!(HomeRecord::from_body(&zero.to_body()).is_err());
        let mut big = home_record(&w, 0, 1, 1);
        big.payload = vec![0; MAX_PAYLOAD + 1];
        assert!(HomeRecord::from_body(&big.to_body()).is_err());
        let mut nameless = home_record(&w, 0, 1, 1);
        nameless.kind = String::new();
        assert!(HomeRecord::from_body(&nameless.to_body()).is_err());
        assert!(PromotionRecord::from_body(&[0xa0]).is_err());
        assert_eq!(contexts().len(), 2);
    }

    #[test]
    fn an_index_carries_its_epoch_so_records_made_apart_never_collide() {
        let old_home = home_index(1, 5);
        let new_home = home_index(2, 5);
        assert_ne!(old_home, new_home);
        assert!(
            old_home < new_home,
            "a later epoch sorts after an earlier one"
        );
        assert_eq!((index_epoch(old_home), index_seq(old_home)), (1, 5));
        assert_eq!((index_epoch(new_home), index_seq(new_home)), (2, 5));
        // The first record of the first epoch is not zero, which a record refuses.
        assert_ne!(home_index(1, 1), 0);
        // A count too large for its bits can't spill into the epoch.
        assert_eq!(index_epoch(home_index(1, u64::MAX)), 1);
    }
}
