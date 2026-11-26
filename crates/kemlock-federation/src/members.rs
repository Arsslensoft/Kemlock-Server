//! Member accounts as a federated vault carries them to its replicas.
//!
//! A replica holds a copy of each member of a federated vault so a device can sign in there with
//! its device key when the home is away. The copy is the account's public part: its public-key
//! bundle and signature, the root key wrapped by the password, the private keys sealed under the
//! user key, the KDF settings, and the device registrations (the thumbprint of each device's DPoP
//! key). It never holds the OPAQUE record, the security stamp, the role, the two-step methods or
//! any token, so no password secret is shared and a copy can't be used to sign in with a password.
//!
//! The home publishes one [home record](crate::home::HomeRecord) of kind [`KIND`] per account
//! whenever it changes; the replicas apply them under the epoch fence like every home-only write.
//! The payload is deterministic CBOR:
//!
//! | Key | Field |
//! | --- | --- |
//! | 0 | version `1` |
//! | 1 | user id, 16 bytes |
//! | 2 | email, text |
//! | 3 | name, text, absent when none |
//! | 4 | mode, `"kemlock-only"` or `"compatible"` |
//! | 5 | KDF: array `[memory KiB, iterations, parallelism, salt]` |
//! | 6 | wrapped root key |
//! | 7 | public bundle |
//! | 8 | bundle signature |
//! | 9 | sealed private keys |
//! | 10 | key version |
//! | 11 | created at, Unix seconds |
//! | 12 | updated at, Unix seconds |
//! | 13 | devices: array of maps `{0: id (16), 1: name, 2: kind, 3: DPoP thumbprint (absent when none), 4: created at}` |
//! | 14 | past bundles, absent when there are none: array of `[key version, public bundle, bundle signature]` in ascending key version, the bundles the account had before its current key version, so a replica can check a write signed under one (docs/crypto.md, "Signed item writes") |

use crate::cbor::Value;
use crate::error::{FedError, Result};
use kemlock_domain::{AccountMode, DeviceId, DeviceKind, KdfParams, UserId};
use uuid::Uuid;

/// The home-record kind that carries one member account.
pub const KIND: &str = "member-account";
/// The payload format version.
pub const VERSION: u64 = 1;
/// The most device registrations one account copy carries.
pub const MAX_DEVICES: usize = 64;
/// The most past bundles one account copy carries: one for each key replacement.
pub const MAX_PAST_BUNDLES: usize = 64;

/// A public-key bundle an account had before its current one.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PastBundle {
    pub key_version: u32,
    pub public_bundle: Vec<u8>,
    pub bundle_signature: Vec<u8>,
}

/// One device registration of a member.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MemberDevice {
    pub id: DeviceId,
    pub name: String,
    pub kind: DeviceKind,
    /// The RFC 7638 thumbprint of the device's DPoP key, which is what a replica checks a
    /// device-key sign-in against.
    pub dpop_jkt: Option<String>,
    /// Unix seconds.
    pub created_at: i64,
}

/// The public part of an account, as a replica keeps it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MemberAccount {
    pub id: UserId,
    pub email: String,
    pub name: Option<String>,
    pub mode: AccountMode,
    pub kdf: KdfParams,
    pub wrapped_root_key: Vec<u8>,
    pub public_bundle: Vec<u8>,
    pub bundle_signature: Vec<u8>,
    pub sealed_private_keys: Vec<u8>,
    pub key_version: u32,
    /// Unix seconds.
    pub created_at: i64,
    /// Unix seconds.
    pub updated_at: i64,
    /// Sorted by id, so one account always encodes to the same bytes.
    pub devices: Vec<MemberDevice>,
    /// The bundles before the current key version, in ascending key version.
    pub past_bundles: Vec<PastBundle>,
}

fn kind_name(kind: DeviceKind) -> &'static str {
    match kind {
        DeviceKind::KemlockAndroid => "kemlock-android",
        DeviceKind::KemlockIos => "kemlock-ios",
        DeviceKind::KemlockWeb => "kemlock-web",
        DeviceKind::KemlockBrowser => "kemlock-browser",
        DeviceKind::KemlockCli => "kemlock-cli",
        DeviceKind::Amethystora => "amethystora",
        DeviceKind::Bitwarden => "bitwarden",
        DeviceKind::Other => "other",
    }
}

fn kind_from(name: &str) -> DeviceKind {
    match name {
        "kemlock-android" => DeviceKind::KemlockAndroid,
        "kemlock-ios" => DeviceKind::KemlockIos,
        "kemlock-web" => DeviceKind::KemlockWeb,
        "kemlock-browser" => DeviceKind::KemlockBrowser,
        "kemlock-cli" => DeviceKind::KemlockCli,
        "amethystora" => DeviceKind::Amethystora,
        "bitwarden" => DeviceKind::Bitwarden,
        _ => DeviceKind::Other,
    }
}

fn mode_name(mode: AccountMode) -> &'static str {
    match mode {
        AccountMode::KemlockOnly => "kemlock-only",
        AccountMode::Compatible => "compatible",
    }
}

fn mode_from(name: &str) -> Result<AccountMode> {
    match name {
        "kemlock-only" => Ok(AccountMode::KemlockOnly),
        "compatible" => Ok(AccountMode::Compatible),
        _ => Err(FedError::Malformed("an unknown account mode")),
    }
}

fn secs(value: i64) -> Value {
    Value::Uint(u64::try_from(value).unwrap_or(0))
}

fn from_secs(value: u64) -> Result<i64> {
    i64::try_from(value).map_err(|_| FedError::Malformed("a time is out of range"))
}

fn uuid16(bytes: [u8; 16]) -> Uuid {
    Uuid::from_bytes(bytes)
}

impl MemberAccount {
    /// The payload of the home record that carries this account.
    pub fn to_payload(&self) -> Vec<u8> {
        let mut devices = self.devices.clone();
        devices.sort_by_key(|d| d.id);
        let mut past = self.past_bundles.clone();
        past.sort_by_key(|b| b.key_version);
        let mut entries = vec![
            (0, Value::Uint(VERSION)),
            (1, Value::bytes(self.id.as_bytes())),
            (2, Value::text(&self.email)),
        ];
        if let Some(name) = &self.name {
            entries.push((3, Value::text(name)));
        }
        entries.extend([
            (4, Value::text(mode_name(self.mode))),
            (
                5,
                Value::Array(vec![
                    Value::Uint(u64::from(self.kdf.memory_kib)),
                    Value::Uint(u64::from(self.kdf.iterations)),
                    Value::Uint(u64::from(self.kdf.parallelism)),
                    Value::bytes(&self.kdf.salt),
                ]),
            ),
            (6, Value::bytes(&self.wrapped_root_key)),
            (7, Value::bytes(&self.public_bundle)),
            (8, Value::bytes(&self.bundle_signature)),
            (9, Value::bytes(&self.sealed_private_keys)),
            (10, Value::Uint(u64::from(self.key_version))),
            (11, secs(self.created_at)),
            (12, secs(self.updated_at)),
            (
                13,
                Value::Array(
                    devices
                        .iter()
                        .map(|d| {
                            let mut e = vec![
                                (0, Value::bytes(d.id.as_bytes())),
                                (1, Value::text(&d.name)),
                                (2, Value::text(kind_name(d.kind))),
                                (4, secs(d.created_at)),
                            ];
                            if let Some(jkt) = &d.dpop_jkt {
                                e.push((3, Value::text(jkt)));
                            }
                            Value::map(e)
                        })
                        .collect(),
                ),
            ),
        ]);
        if !past.is_empty() {
            entries.push((
                14,
                Value::Array(
                    past.iter()
                        .map(|b| {
                            Value::Array(vec![
                                Value::Uint(u64::from(b.key_version)),
                                Value::bytes(&b.public_bundle),
                                Value::bytes(&b.bundle_signature),
                            ])
                        })
                        .collect(),
                ),
            ));
        }
        Value::map(entries).encode()
    }

    /// Reads a payload, refusing anything that isn't what [`to_payload`](Self::to_payload) writes.
    pub fn from_payload(payload: &[u8]) -> Result<MemberAccount> {
        let value = Value::decode(payload)?;
        let f = value.as_fields()?;
        f.only(&[0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14])?;
        if f.uint(0)? != VERSION {
            return Err(FedError::Malformed("an unknown member account version"));
        }
        let kdf = f.array(5)?;
        let [memory, iterations, parallelism, salt] = kdf else {
            return Err(FedError::Malformed("the KDF settings have four parts"));
        };
        let small = |v: &Value| -> Result<u32> {
            u32::try_from(v.as_uint()?).map_err(|_| FedError::Malformed("a KDF value is too large"))
        };
        let kdf = KdfParams {
            memory_kib: small(memory)?,
            iterations: small(iterations)?,
            parallelism: small(parallelism)?,
            salt: salt.as_bytes()?.to_vec(),
        };
        let device_values = f.array(13)?;
        if device_values.len() > MAX_DEVICES {
            return Err(FedError::Malformed("too many devices"));
        }
        let mut devices = Vec::with_capacity(device_values.len());
        for v in device_values {
            let d = v.as_fields()?;
            d.only(&[0, 1, 2, 3, 4])?;
            devices.push(MemberDevice {
                id: DeviceId(uuid16(d.fixed::<16>(0)?)),
                name: d.text(1)?.to_owned(),
                kind: kind_from(d.text(2)?),
                dpop_jkt: d
                    .get(3)
                    .map(|v| v.as_text().map(str::to_owned))
                    .transpose()?,
                created_at: from_secs(d.uint(4)?)?,
            });
        }
        let mut past_bundles = Vec::new();
        if let Some(list) = f.get(14) {
            let list = list.as_array()?;
            if list.len() > MAX_PAST_BUNDLES {
                return Err(FedError::Malformed("too many past bundles"));
            }
            for entry in list {
                let [version, bundle, signature] = entry.as_array()? else {
                    return Err(FedError::Malformed("a past bundle has three parts"));
                };
                past_bundles.push(PastBundle {
                    key_version: u32::try_from(version.as_uint()?)
                        .map_err(|_| FedError::Malformed("a key version is too large"))?,
                    public_bundle: bundle.as_bytes()?.to_vec(),
                    bundle_signature: signature.as_bytes()?.to_vec(),
                });
            }
        }
        let account = MemberAccount {
            id: UserId(uuid16(f.fixed::<16>(1)?)),
            email: f.text(2)?.to_owned(),
            name: f
                .get(3)
                .map(|v| v.as_text().map(str::to_owned))
                .transpose()?,
            mode: mode_from(f.text(4)?)?,
            kdf,
            wrapped_root_key: f.bytes(6)?.to_vec(),
            public_bundle: f.bytes(7)?.to_vec(),
            bundle_signature: f.bytes(8)?.to_vec(),
            sealed_private_keys: f.bytes(9)?.to_vec(),
            key_version: u32::try_from(f.uint(10)?)
                .map_err(|_| FedError::Malformed("a key version is too large"))?,
            created_at: from_secs(f.uint(11)?)?,
            updated_at: from_secs(f.uint(12)?)?,
            devices,
            past_bundles,
        };
        if account.to_payload() != payload {
            return Err(FedError::Invalid("the member account is not canonical"));
        }
        Ok(account)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn account() -> MemberAccount {
        MemberAccount {
            id: UserId::random(),
            email: "ada@example.org".to_owned(),
            name: Some("Ada".to_owned()),
            mode: AccountMode::KemlockOnly,
            kdf: KdfParams::new_account([3; 16]),
            wrapped_root_key: vec![1; 80],
            public_bundle: vec![2; 300],
            bundle_signature: vec![3; 100],
            sealed_private_keys: vec![4; 200],
            key_version: 1,
            created_at: 1_700_000_000,
            updated_at: 1_700_000_100,
            past_bundles: Vec::new(),
            devices: vec![
                MemberDevice {
                    id: DeviceId::random(),
                    name: "Pixel".to_owned(),
                    kind: DeviceKind::KemlockAndroid,
                    dpop_jkt: Some("thumbprint".to_owned()),
                    created_at: 1_700_000_050,
                },
                MemberDevice {
                    id: DeviceId::random(),
                    name: "Web".to_owned(),
                    kind: DeviceKind::Other,
                    dpop_jkt: None,
                    created_at: 1_700_000_060,
                },
            ],
        }
    }

    #[test]
    fn an_account_round_trips_with_devices_in_id_order() {
        let a = account();
        let back = MemberAccount::from_payload(&a.to_payload()).expect("a payload");
        let mut expected = a.clone();
        expected.devices.sort_by_key(|d| d.id);
        assert_eq!(back, expected);
        // The same account always writes the same bytes, whatever order its devices came in.
        let mut reversed = a.clone();
        reversed.devices.reverse();
        assert_eq!(reversed.to_payload(), a.to_payload());
    }

    #[test]
    fn a_browser_device_keeps_its_kind_in_the_payload() {
        let mut a = account();
        a.devices[0].kind = DeviceKind::KemlockBrowser;
        let back = MemberAccount::from_payload(&a.to_payload()).expect("a payload");
        assert!(
            back.devices
                .iter()
                .any(|d| d.kind == DeviceKind::KemlockBrowser)
        );
    }

    #[test]
    fn an_account_without_a_name_round_trips() {
        let mut a = account();
        a.name = None;
        a.devices.clear();
        let back = MemberAccount::from_payload(&a.to_payload()).expect("a payload");
        assert_eq!(back, a);
    }

    #[test]
    fn trailing_bytes_and_unknown_fields_are_refused() {
        let payload = account().to_payload();
        let mut longer = payload.clone();
        longer.push(0);
        assert!(MemberAccount::from_payload(&longer).is_err());
        let mut value = Value::decode(&payload).expect("decode");
        if let Value::Map(entries) = &mut value {
            entries.push((20, Value::Uint(1)));
        }
        assert!(MemberAccount::from_payload(&value.encode()).is_err());
    }

    #[test]
    fn past_bundles_travel_in_key_order_and_round_trip() {
        let mut a = account();
        a.key_version = 3;
        a.past_bundles = vec![
            PastBundle {
                key_version: 2,
                public_bundle: vec![6; 300],
                bundle_signature: vec![7; 100],
            },
            PastBundle {
                key_version: 1,
                public_bundle: vec![8; 300],
                bundle_signature: vec![9; 100],
            },
        ];
        let back = MemberAccount::from_payload(&a.to_payload()).expect("a payload");
        let mut expected = a.clone();
        expected.past_bundles.sort_by_key(|b| b.key_version);
        assert_eq!(back, expected);
        // The same account always writes the same bytes, whatever order the list came in.
        let mut reversed = a.clone();
        reversed.past_bundles.reverse();
        assert_eq!(reversed.to_payload(), a.to_payload());
    }

    #[test]
    fn too_many_past_bundles_or_a_malformed_one_are_refused() {
        let mut a = account();
        a.past_bundles = (1..=u32::try_from(MAX_PAST_BUNDLES).expect("small") + 1)
            .map(|key_version| PastBundle {
                key_version,
                public_bundle: vec![1; 10],
                bundle_signature: vec![2; 10],
            })
            .collect();
        assert!(MemberAccount::from_payload(&a.to_payload()).is_err());

        let payload = account().to_payload();
        let mut value = Value::decode(&payload).expect("decode");
        if let Value::Map(entries) = &mut value {
            entries.push((14, Value::Array(vec![Value::Array(vec![Value::Uint(1)])])));
        }
        assert!(MemberAccount::from_payload(&value.encode()).is_err());
    }

    #[test]
    fn a_payload_carries_no_opaque_record_or_role() {
        // The fields are listed in the module comment; nothing past key 13 exists.
        let payload = account().to_payload();
        let value = Value::decode(&payload).expect("decode");
        let f = value.as_fields().expect("a map");
        assert!(f.get(14).is_none());
    }
}
