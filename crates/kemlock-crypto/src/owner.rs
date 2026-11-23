//! Who an item, a manifest or a dedup key belongs to: `u8(type) ‖ uuid`, 17 bytes.

use crate::Error;

/// The length of an owner's wire form.
pub const LEN: usize = 17;

/// Whether the owner is a person's own vault or a space.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum OwnerKind {
    /// A user's own vault (type `0x01`).
    User,
    /// A space (type `0x02`).
    Space,
}

/// An owner: a kind and a UUID in its 16 raw bytes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Owner {
    kind: OwnerKind,
    id: [u8; 16],
}

impl Owner {
    /// A user's own vault.
    pub fn user(id: [u8; 16]) -> Owner {
        Owner {
            kind: OwnerKind::User,
            id,
        }
    }

    /// A space.
    pub fn space(id: [u8; 16]) -> Owner {
        Owner {
            kind: OwnerKind::Space,
            id,
        }
    }

    pub fn kind(&self) -> OwnerKind {
        self.kind
    }

    pub fn id(&self) -> &[u8; 16] {
        &self.id
    }

    /// `u8(type) ‖ uuid`.
    pub fn to_bytes(&self) -> [u8; LEN] {
        let mut out = [0u8; LEN];
        out[0] = match self.kind {
            OwnerKind::User => 0x01,
            OwnerKind::Space => 0x02,
        };
        out[1..].copy_from_slice(&self.id);
        out
    }

    /// Parses the wire form, refusing any other type byte.
    pub fn from_bytes(bytes: &[u8; LEN]) -> Result<Owner, Error> {
        let kind = match bytes[0] {
            0x01 => OwnerKind::User,
            0x02 => OwnerKind::Space,
            _ => return Err(Error::invalid()),
        };
        let mut id = [0u8; 16];
        id.copy_from_slice(&bytes[1..]);
        Ok(Owner { kind, id })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wire_form_is_type_then_uuid() {
        let user = Owner::user([7; 16]);
        let bytes = user.to_bytes();
        assert_eq!(bytes[0], 1);
        assert_eq!(&bytes[1..], &[7; 16]);
        assert_eq!(Owner::space([7; 16]).to_bytes()[0], 2);
    }

    #[test]
    fn round_trips() {
        for owner in [Owner::user([1; 16]), Owner::space([2; 16])] {
            assert_eq!(Owner::from_bytes(&owner.to_bytes()), Ok(owner));
        }
    }

    #[test]
    fn unknown_type_is_refused() {
        let mut bytes = Owner::user([1; 16]).to_bytes();
        for bad in [0u8, 3, 255] {
            bytes[0] = bad;
            assert!(Owner::from_bytes(&bytes).is_err());
        }
    }
}
