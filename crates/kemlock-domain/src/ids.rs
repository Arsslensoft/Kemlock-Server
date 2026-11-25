//! Typed identifiers, so a user id can never be passed where an item id is meant.

use serde::{Deserialize, Serialize};
use std::fmt;
use uuid::Uuid;

macro_rules! id_type {
    ($(#[$doc:meta])* $name:ident) => {
        $(#[$doc])*
        #[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
        #[serde(transparent)]
        pub struct $name(pub Uuid);

        impl $name {
            /// A new random id (UUID v4).
            pub fn random() -> Self {
                Self(Uuid::new_v4())
            }

            /// The id's 16 raw bytes, as binary formats encode it.
            pub fn as_bytes(&self) -> &[u8; 16] {
                self.0.as_bytes()
            }
        }

        impl fmt::Debug for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(f, concat!(stringify!($name), "({})"), self.0)
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                self.0.fmt(f)
            }
        }

        impl std::str::FromStr for $name {
            type Err = uuid::Error;
            fn from_str(s: &str) -> Result<Self, Self::Err> {
                Uuid::parse_str(s).map(Self)
            }
        }
    };
}

id_type!(
    /// An account.
    UserId
);
id_type!(
    /// A device signed in to an account.
    DeviceId
);
id_type!(
    /// An item. Clients make item ids, so a failed batch can be resent unchanged.
    ItemId
);
id_type!(
    /// A space (shared vault).
    SpaceId
);
id_type!(
    /// A Kemlock Server installation. Every change carries the id of the server that accepted it,
    /// so federation needs no migration of items later.
    ServerId
);
id_type!(
    /// A custom field an admin defined for the server's items.
    CustomFieldId
);
