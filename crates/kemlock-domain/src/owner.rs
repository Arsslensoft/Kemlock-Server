//! Who owns an item: a person's own vault or a space.

use crate::ids::{SpaceId, UserId};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::fmt;

/// The owner of an item. On the wire it is `user:<uuid>` or `space:<uuid>`; in binary formats it
/// is `u8(type) ‖ uuid`, 17 bytes (docs/crypto.md).
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Owner {
    User(UserId),
    Space(SpaceId),
}

impl Owner {
    pub const TYPE_USER: u8 = 0x01;
    pub const TYPE_SPACE: u8 = 0x02;

    /// The 17-byte binary encoding used inside AADs and signed inputs.
    pub fn to_bytes(&self) -> [u8; 17] {
        let mut out = [0u8; 17];
        let (tag, id) = match self {
            Owner::User(u) => (Self::TYPE_USER, u.as_bytes()),
            Owner::Space(s) => (Self::TYPE_SPACE, s.as_bytes()),
        };
        out[0] = tag;
        out[1..].copy_from_slice(id);
        out
    }

    /// Decodes the 17-byte form; `None` for an unknown type byte.
    pub fn from_bytes(bytes: &[u8; 17]) -> Option<Self> {
        let mut id = [0u8; 16];
        id.copy_from_slice(&bytes[1..]);
        let uuid = uuid::Uuid::from_bytes(id);
        match bytes[0] {
            Self::TYPE_USER => Some(Owner::User(UserId(uuid))),
            Self::TYPE_SPACE => Some(Owner::Space(SpaceId(uuid))),
            _ => None,
        }
    }
}

impl fmt::Display for Owner {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Owner::User(u) => write!(f, "user:{u}"),
            Owner::Space(s) => write!(f, "space:{s}"),
        }
    }
}

impl fmt::Debug for Owner {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, f)
    }
}

impl std::str::FromStr for Owner {
    type Err = &'static str;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let (kind, id) = s
            .split_once(':')
            .ok_or("owner must be user:<id> or space:<id>")?;
        let uuid = uuid::Uuid::parse_str(id).map_err(|_| "owner id is not a UUID")?;
        match kind {
            "user" => Ok(Owner::User(UserId(uuid))),
            "space" => Ok(Owner::Space(SpaceId(uuid))),
            _ => Err("owner must be user:<id> or space:<id>"),
        }
    }
}

impl Serialize for Owner {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.collect_str(self)
    }
}

impl<'de> Deserialize<'de> for Owner {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let s = String::deserialize(d)?;
        s.parse().map_err(serde::de::Error::custom)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trips_text_and_bytes() {
        let owner = Owner::Space(SpaceId::random());
        assert_eq!(owner.to_string().parse::<Owner>(), Ok(owner));
        assert_eq!(Owner::from_bytes(&owner.to_bytes()), Some(owner));
    }

    #[test]
    fn refuses_unknown_kinds() {
        assert!(
            "team:7f3c4b1e-0000-4000-8000-000000000000"
                .parse::<Owner>()
                .is_err()
        );
        let mut bytes = Owner::User(UserId::random()).to_bytes();
        bytes[0] = 9;
        assert_eq!(Owner::from_bytes(&bytes), None);
    }
}
