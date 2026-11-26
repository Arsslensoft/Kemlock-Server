//! Change records: one accepted write of an item, as it travels between servers, signed by the
//! server that accepted it.
//!
//! A record carries the item exactly as stored (ciphertext and wrapped item key, which the
//! servers can't read), the change id (origin, sequence, HLC time), and the lineage: the change
//! keys of the versions this one replaced, nearest first. The origin signs all of it, so a peer
//! relaying the record can pass it on but can't alter it or invent one. See `docs/federation.md`.

use crate::cbor::Value;
use crate::error::{FedError, Result};
use crate::identity::KeyDirectory;
use crate::signed::Signed;
use crate::wire::{ChangeKey, item_id, owner, pack_keys, server_id, unpack_keys};
use kemlock_crypto::sig1;
use kemlock_domain::{
    ChangeId, Hlc, Item, ItemFormat, ItemId, ItemKind, Owner, Revision, ServerId,
};
use time::OffsetDateTime;

/// The record format version.
pub const VERSION: u64 = 1;
/// The `sig1` context of a record's signature.
pub const CONTEXT: &str = "federation-change";
/// The most ancestors a record names. Older ones are forgotten, which can only make a later
/// merge keep a sibling it could have dropped, never lose a version.
pub const MAX_LINEAGE: usize = 64;

/// One version of an item and the change that made it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ChangeRecord {
    pub change: ChangeId,
    pub item: ItemId,
    pub owner: Owner,
    pub kind: ItemKind,
    pub format: ItemFormat,
    pub revision: Revision,
    pub key_version: u32,
    /// Absent on a tombstone.
    pub ciphertext: Option<Vec<u8>>,
    /// Absent on a tombstone.
    pub item_key: Option<Vec<u8>>,
    pub deleted: bool,
    /// When the write was made, in Unix milliseconds. A tombstone's deletion time is the same.
    pub updated_at_ms: u64,
    /// The versions this one replaced, nearest first, at most [`MAX_LINEAGE`].
    pub lineage: Vec<ChangeKey>,
}

/// Milliseconds since the epoch; times before 1970 count as 0.
pub fn time_to_ms(time: OffsetDateTime) -> u64 {
    u64::try_from(time.unix_timestamp_nanos() / 1_000_000).unwrap_or(0)
}

/// The time at `ms` milliseconds since the epoch.
pub fn ms_to_time(ms: u64) -> Result<OffsetDateTime> {
    OffsetDateTime::from_unix_timestamp_nanos(i128::from(ms) * 1_000_000)
        .map_err(|_| FedError::Malformed("a time is out of range"))
}

fn format_from(name: &str) -> Result<ItemFormat> {
    match name {
        "kem1" => Ok(ItemFormat::Kem1),
        "bw" => Ok(ItemFormat::Bw),
        _ => Err(FedError::Malformed("unknown item format")),
    }
}

impl ChangeRecord {
    pub fn key(&self) -> ChangeKey {
        ChangeKey::of(&self.change)
    }

    /// The record of a stored item. `lineage` is the versions it replaced.
    pub fn from_item(item: &Item, lineage: Vec<ChangeKey>) -> ChangeRecord {
        ChangeRecord {
            change: item.change,
            item: item.id,
            owner: item.owner,
            kind: item.kind.clone(),
            format: item.format,
            revision: item.revision,
            key_version: item.key_version,
            ciphertext: item.ciphertext.clone(),
            item_key: item.item_key.clone(),
            deleted: item.is_tombstone(),
            updated_at_ms: time_to_ms(item.updated_at),
            lineage,
        }
    }

    /// The item this record stores. A tombstone's deletion time is its write time.
    pub fn to_item(&self) -> Result<Item> {
        let updated_at = ms_to_time(self.updated_at_ms)?;
        Ok(Item {
            id: self.item,
            owner: self.owner,
            kind: self.kind.clone(),
            format: self.format,
            revision: self.revision,
            key_version: self.key_version,
            ciphertext: self.ciphertext.clone(),
            item_key: self.item_key.clone(),
            deleted_at: self.deleted.then_some(updated_at),
            updated_at,
            change: self.change,
        })
    }

    /// The canonical CBOR body that is signed.
    pub fn to_body(&self) -> Vec<u8> {
        let mut entries = vec![
            (0, Value::Uint(VERSION)),
            (1, Value::bytes(self.change.origin.as_bytes())),
            (2, Value::Uint(self.change.seq)),
            (3, Value::Uint(self.change.hlc.0)),
            (4, Value::bytes(self.item.as_bytes())),
            (5, Value::bytes(&self.owner.to_bytes())),
            (6, Value::text(self.kind.as_str())),
            (7, Value::text(self.format.as_str())),
            (8, Value::Uint(self.revision.0)),
            (9, Value::Uint(u64::from(self.key_version))),
            (12, Value::flag(self.deleted)),
            (13, Value::Uint(self.updated_at_ms)),
            (14, Value::Bytes(pack_keys(&self.lineage))),
        ];
        if let Some(ciphertext) = &self.ciphertext {
            entries.push((10, Value::bytes(ciphertext)));
        }
        if let Some(item_key) = &self.item_key {
            entries.push((11, Value::bytes(item_key)));
        }
        Value::map(entries).encode()
    }

    /// Parses a body, refusing unknown fields and records that make no sense: a zero sequence or
    /// revision, a tombstone with ciphertext, a live item without it, a lineage that names the
    /// record itself.
    pub fn from_body(body: &[u8]) -> Result<ChangeRecord> {
        let value = Value::decode(body)?;
        let f = value.as_fields()?;
        f.only(&[0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14])?;
        if f.uint(0)? != VERSION {
            return Err(FedError::Malformed("unknown record version"));
        }
        let kind = ItemKind::try_from(f.text(6)?.to_owned())
            .map_err(|_| FedError::Malformed("the item kind is not valid"))?;
        let deleted = f.flag(12)?;
        let ciphertext = f
            .get(10)
            .map(|v| v.as_bytes().map(<[u8]>::to_vec))
            .transpose()?;
        let item_key = f
            .get(11)
            .map(|v| v.as_bytes().map(<[u8]>::to_vec))
            .transpose()?;
        if deleted == (ciphertext.is_some() || item_key.is_some()) {
            return Err(FedError::Malformed(
                "a tombstone holds no ciphertext and a live item does",
            ));
        }
        if !deleted && (ciphertext.is_none() || item_key.is_none()) {
            return Err(FedError::Malformed(
                "a live item needs ciphertext and a key",
            ));
        }
        let record = ChangeRecord {
            change: ChangeId {
                origin: server_id(f.fixed::<16>(1)?),
                seq: f.uint(2)?,
                hlc: Hlc(f.uint(3)?),
            },
            item: item_id(f.fixed::<16>(4)?),
            owner: owner(f.fixed::<17>(5)?)?,
            kind,
            format: format_from(f.text(7)?)?,
            revision: Revision(f.uint(8)?),
            key_version: u32::try_from(f.uint(9)?)
                .map_err(|_| FedError::Malformed("the key version is out of range"))?,
            ciphertext,
            item_key,
            deleted,
            updated_at_ms: f.uint(13)?,
            lineage: unpack_keys(f.bytes(14)?)?,
        };
        if record.change.seq == 0 || record.revision.0 == 0 {
            return Err(FedError::Malformed("sequence and revision start at 1"));
        }
        if record.lineage.len() > MAX_LINEAGE || record.lineage.contains(&record.key()) {
            return Err(FedError::Malformed("the lineage is not valid"));
        }
        Ok(record)
    }

    /// Signs the record with the origin's identity key.
    pub fn sign(&self, key: &sig1::SigningKey) -> Result<Signed> {
        Signed::sign(key, CONTEXT, self.to_body())
    }
}

/// Parses a signed record and checks the origin's signature with the key `keys` holds for the
/// origin. A record from an origin we hold no key for is refused: we can't tell it from a forgery.
pub fn open(envelope: &[u8], keys: &dyn KeyDirectory) -> Result<ChangeRecord> {
    let signed = Signed::decode(envelope)?;
    let record = ChangeRecord::from_body(&signed.body)?;
    let origin = record.change.origin;
    let key = keys.identity_key(origin).ok_or(FedError::Refused(
        "a change from an origin whose key we do not hold",
    ))?;
    signed.verify(&key, CONTEXT)?;
    // The body must be the canonical encoding of what it parsed to, or two encodings of one
    // record could carry one signature.
    if record.to_body() != signed.body {
        return Err(FedError::Invalid("the record body is not canonical"));
    }
    Ok(record)
}

/// How far ahead of this server's clock a record's HLC time may be, in milliseconds: the 300
/// seconds of clock skew every other check here allows.
pub const MAX_FUTURE_MS: u64 = 300_000;

/// Refuses a record whose HLC time is more than [`MAX_FUTURE_MS`] ahead of `now_ms` (Unix
/// milliseconds). Old records are normal (a peer that was away); a time far ahead would raise this
/// server's clock with it, and a clock at the top of its range can't tick again.
pub fn check_not_future(record: &ChangeRecord, now_ms: u64) -> Result<()> {
    if record.change.hlc.millis() > now_ms.saturating_add(MAX_FUTURE_MS) {
        return Err(FedError::Refused("a change from the future"));
    }
    Ok(())
}

/// The server that signs a record.
pub fn origin_of(record: &ChangeRecord) -> ServerId {
    record.change.origin
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto;
    use kemlock_domain::UserId;
    use std::collections::HashMap;

    pub(super) fn record(origin: ServerId, seq: u64, revision: u64) -> ChangeRecord {
        ChangeRecord {
            change: ChangeId {
                origin,
                seq,
                hlc: Hlc::from_parts(1_700_000_000_000, 3),
            },
            item: ItemId::random(),
            owner: Owner::User(UserId::random()),
            kind: ItemKind::try_from("login".to_owned()).expect("kind"),
            format: ItemFormat::Kem1,
            revision: Revision(revision),
            key_version: 1,
            ciphertext: Some(vec![7; 40]),
            item_key: Some(vec![8; 60]),
            deleted: false,
            updated_at_ms: 1_700_000_000_123,
            lineage: vec![ChangeKey {
                origin,
                seq: seq.saturating_sub(1).max(1),
            }],
        }
    }

    fn keys_for(origin: ServerId, key: &sig1::SigningKey) -> HashMap<ServerId, sig1::PublicKey> {
        let public = crypto::sign_public(key).expect("public");
        [(origin, public)].into_iter().collect()
    }

    #[test]
    fn a_record_round_trips_signed() {
        let origin = ServerId::random();
        let key = sig1::SigningKey::from_bytes(&[1; 64]);
        let mut r = record(origin, 5, 3);
        r.lineage = vec![ChangeKey { origin, seq: 4 }];
        let signed = r.sign(&key).expect("sign").encode();
        assert_eq!(open(&signed, &keys_for(origin, &key)), Ok(r));
    }

    #[test]
    fn an_origin_we_hold_no_key_for_is_refused() {
        let origin = ServerId::random();
        let key = sig1::SigningKey::from_bytes(&[1; 64]);
        let signed = record(origin, 5, 3).sign(&key).expect("sign").encode();
        let none: HashMap<ServerId, sig1::PublicKey> = HashMap::new();
        assert!(matches!(open(&signed, &none), Err(FedError::Refused(_))));
    }

    #[test]
    fn a_relayed_record_altered_or_forged_fails() {
        let origin = ServerId::random();
        let key = sig1::SigningKey::from_bytes(&[1; 64]);
        let keys = keys_for(origin, &key);
        let r = record(origin, 5, 3);
        // Altered ciphertext, re-wrapped in the original signature.
        let signed = r.sign(&key).expect("sign");
        let mut altered = r.clone();
        altered.ciphertext = Some(vec![9; 40]);
        let forged = Signed {
            body: altered.to_body(),
            signature: signed.signature.clone(),
        };
        assert!(open(&forged.encode(), &keys).is_err());
        // Invented by a relay with its own key.
        let relay = sig1::SigningKey::from_bytes(&[2; 64]);
        let invented = r.sign(&relay).expect("sign");
        assert!(open(&invented.encode(), &keys).is_err());
        // A changed lineage is a changed record.
        let mut lineage = r.clone();
        lineage.lineage.clear();
        let forged = Signed {
            body: lineage.to_body(),
            signature: signed.signature,
        };
        assert!(open(&forged.encode(), &keys).is_err());
    }

    #[test]
    fn items_survive_the_trip_through_a_record() {
        let origin = ServerId::random();
        let mut r = record(origin, 5, 3);
        let item = r.to_item().expect("item");
        assert_eq!(item.revision, Revision(3));
        assert!(!item.is_tombstone());
        assert_eq!(ChangeRecord::from_item(&item, r.lineage.clone()), r);
        // Tombstones.
        r.deleted = true;
        r.ciphertext = None;
        r.item_key = None;
        let tomb = r.to_item().expect("tombstone");
        assert!(tomb.is_tombstone());
        assert_eq!(tomb.deleted_at, Some(tomb.updated_at));
        assert_eq!(ChangeRecord::from_item(&tomb, r.lineage.clone()), r);
    }

    #[test]
    fn nonsense_records_are_refused() {
        let origin = ServerId::random();
        let good = record(origin, 5, 3);
        let mut cases = Vec::new();
        let mut c = good.clone();
        c.deleted = true; // a tombstone with ciphertext
        cases.push(c);
        let mut c = good.clone();
        c.ciphertext = None; // live without ciphertext
        cases.push(c);
        let mut c = good.clone();
        c.change.seq = 0;
        cases.push(c);
        let mut c = good.clone();
        c.revision = Revision(0);
        cases.push(c);
        let mut c = good.clone();
        c.lineage = vec![good.key()];
        cases.push(c);
        let mut c = good.clone();
        c.lineage = (1..=65).map(|seq| ChangeKey { origin, seq }).collect();
        cases.push(c);
        for bad in cases {
            assert!(ChangeRecord::from_body(&bad.to_body()).is_err(), "{bad:?}");
        }
        // An unknown field.
        let mut value = Value::decode(&good.to_body()).expect("decode");
        if let Value::Map(entries) = &mut value {
            entries.push((99, Value::Uint(1)));
        }
        assert!(ChangeRecord::from_body(&value.encode()).is_err());
    }

    #[test]
    fn a_record_from_the_future_is_refused_and_an_old_one_is_not() {
        let origin = ServerId::random();
        let mut r = record(origin, 5, 3);
        let now_ms = 1_700_000_000_000;
        r.change.hlc = Hlc::from_parts(now_ms + MAX_FUTURE_MS, 9);
        assert!(
            check_not_future(&r, now_ms).is_ok(),
            "the skew allowance is kept"
        );
        r.change.hlc = Hlc::from_parts(now_ms + MAX_FUTURE_MS + 1, 0);
        assert!(matches!(
            check_not_future(&r, now_ms),
            Err(FedError::Refused(_))
        ));
        r.change.hlc = Hlc(u64::MAX >> 1);
        assert!(check_not_future(&r, now_ms).is_err());
        r.change.hlc = Hlc::from_parts(1_000, 0);
        assert!(
            check_not_future(&r, now_ms).is_ok(),
            "old records are normal"
        );
    }

    #[test]
    fn times_convert_to_milliseconds_and_back() {
        let t = ms_to_time(1_700_000_000_123).expect("time");
        assert_eq!(time_to_ms(t), 1_700_000_000_123);
        assert_eq!(
            time_to_ms(OffsetDateTime::UNIX_EPOCH - time::Duration::seconds(5)),
            0
        );
    }
}
