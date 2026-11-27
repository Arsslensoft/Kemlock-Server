//! Opening the vault without the master password (design, "Unlocking without the master
//! password"): device approvals, the trusted-device copy of the root key, and emergency access.
//!
//! Every key that moves through these flows is sealed on a device before it reaches the server,
//! so the types here hold opaque bytes and the rules around them: who may answer, how long a
//! request lives, which state follows which. Nothing here opens a sealed box.

/// Declares a UUID-backed id type with the derives and conversions the other ids have. Defined
/// before the modules that use it, so they see it without an import.
macro_rules! uuid_id {
    ($(#[$doc:meta])* $name:ident) => {
        $(#[$doc])*
        #[derive(
            Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, serde::Serialize, serde::Deserialize,
        )]
        #[serde(transparent)]
        pub struct $name(pub uuid::Uuid);

        impl $name {
            /// A new random id (UUID v4).
            pub fn random() -> Self {
                Self(uuid::Uuid::new_v4())
            }
        }

        impl std::fmt::Debug for $name {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                write!(f, concat!(stringify!($name), "({})"), self.0)
            }
        }

        impl std::fmt::Display for $name {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                std::fmt::Display::fmt(&self.0, f)
            }
        }

        impl std::str::FromStr for $name {
            type Err = uuid::Error;
            fn from_str(s: &str) -> Result<Self, Self::Err> {
                uuid::Uuid::parse_str(s).map(Self)
            }
        }
    };
}

mod approval;
mod emergency;
mod key_copy;
mod phrase;

pub use approval::{
    ApprovalError, ApprovalId, ApprovalState, AuthRequest, HARD_HOURLY_REQUEST_LIMIT,
    HOURLY_REQUEST_LIMIT, KX1_PUBLIC_KEY_LEN, REQUEST_TTL, SEALED_BOX_OVERHEAD,
    SOURCE_HOURLY_REQUEST_LIMIT, sealed_key_len_ok, truncate_ip,
};
pub use emergency::{
    EmergencyError, EmergencyGrant, EmergencyKind, EmergencyState, GrantId, MAX_GRANTS_PER_GRANTOR,
    MAX_WAIT_DAYS, MIN_WAIT_DAYS,
};
pub use key_copy::{DeviceKeyCopy, KeyProtection, MAX_WRAPPED_KEY_LEN};
pub use phrase::{PHRASE_LABEL, PHRASE_WORDS, WORD_COUNT, phrase_from_digest, phrase_input};
