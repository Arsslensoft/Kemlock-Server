//! Making the keys of an account that has none: a first single sign-on sign-in creates the account
//! with `key_version` 0 and no key material, and "its device makes its keys now"
//! (`routes/sso.rs`). The device generates them (docs/crypto.md) and sends what the server may
//! hold: the public bundle, its signature, the private keys sealed under the user key, and this
//! device's trusted-device copy of the root key. The server can open none of it.
//!
//! The account has no password (no OPAQUE record, no password wrap of the root key), so the
//! trusted-device copy is how the device opens the vault again; a passkey with PRF, or another
//! device's approval, opens it elsewhere. Keys are made once: a second enrolment, or one for an
//! account that already has keys, is refused as a duplicate.

use crate::authenticate::Actor;
use crate::devices::{KeyCopies, KeyCopyRepo};
use crate::error::AppError;
use crate::ports::{Clock, DeviceRepo, Event, EventLog, UserRepo};
use crate::register::{
    BUNDLE_LEN, BUNDLE_PREFIX, BUNDLE_SIGNATURE_LEN, FIRST_KEY_VERSION, SEALED_PRIVATE_KEYS_RANGE,
    check_bundle_signature,
};
use crate::sso::finish::NO_KEYS_YET;
use kemlock_domain::unlock::{KeyProtection, MAX_WRAPPED_KEY_LEN};

#[derive(Debug)]
pub struct EnrolKeys<U, D, C, E, V> {
    pub users: U,
    pub devices: D,
    pub copies: C,
    pub clock: E,
    pub events: V,
}

#[derive(Clone, Debug)]
pub struct EnrolKeysInput {
    pub public_bundle: Vec<u8>,
    pub bundle_signature: Vec<u8>,
    pub sealed_private_keys: Vec<u8>,
    /// The root key wrapped by a key only the signed-in device holds.
    pub device_copy: Vec<u8>,
    pub protection: KeyProtection,
}

impl<U, D, C, E, V> EnrolKeys<U, D, C, E, V>
where
    U: UserRepo,
    D: DeviceRepo + Clone,
    C: KeyCopyRepo + Clone,
    E: Clock + Clone,
    V: EventLog,
{
    /// Stores the keys, and returns the key version they are for.
    pub async fn execute(&self, actor: &Actor, input: EnrolKeysInput) -> Result<u32, AppError> {
        let mut user = self
            .users
            .by_id(actor.user)
            .await?
            .ok_or(AppError::Unauthorized)?;
        if user.key_version != NO_KEYS_YET
            || !user.public_bundle.is_empty()
            || !user.wrapped_root_key.is_empty()
        {
            return Err(AppError::Duplicate);
        }
        check(actor, &input)?;

        // What the copy's own store would refuse, refused now: once the keys are stored the copy
        // has nothing left to fail on but the database.
        if input.device_copy.is_empty() || input.device_copy.len() > MAX_WRAPPED_KEY_LEN {
            return Err(AppError::Invalid("the wrapped key must be 1 to 1024 bytes"));
        }
        self.devices
            .get(actor.device)
            .await?
            .filter(|d| d.user == actor.user)
            .ok_or(AppError::NotFound)?;

        // The keys go in only while the account has none, in one step in the store: of two
        // enrolments at once one wins and the other is a duplicate, and only the winner goes on
        // to write a copy of the root key, so a loser can't overwrite the winner's.
        let now = self.clock.now();
        user.public_bundle = input.public_bundle;
        user.bundle_signature = input.bundle_signature;
        user.sealed_private_keys = input.sealed_private_keys;
        user.key_version = FIRST_KEY_VERSION;
        user.updated_at = now;
        self.users.set_first_keys(&user).await?;

        KeyCopies {
            devices: self.devices.clone(),
            copies: self.copies.clone(),
            clock: self.clock.clone(),
        }
        .put(actor, input.device_copy, input.protection)
        .await?;

        let event = Event {
            actor: Some(actor.user),
            device: Some(actor.device),
            action: "account.keys_enrolled",
            target: None,
            at: now,
        };
        if let Err(e) = self.events.record(event).await {
            tracing::warn!(error = %e, "couldn't record an event");
        }
        Ok(FIRST_KEY_VERSION)
    }
}

/// The layout of what the device sends, and the bundle's own signature. The server can't open the
/// sealed parts, but a malformed bundle would be served to every other account that looks the
/// account up.
fn check(actor: &Actor, input: &EnrolKeysInput) -> Result<(), AppError> {
    let bundle = &input.public_bundle;
    let layout_ok = bundle.len() == BUNDLE_LEN
        && bundle.starts_with(BUNDLE_PREFIX)
        && bundle[17..33] == *actor.user.as_bytes()
        && bundle[33..37] == FIRST_KEY_VERSION.to_be_bytes();
    if !layout_ok {
        return Err(AppError::Invalid("the public bundle is malformed"));
    }
    if input.bundle_signature.len() != BUNDLE_SIGNATURE_LEN {
        return Err(AppError::Invalid("the bundle signature is malformed"));
    }
    check_bundle_signature(bundle, &input.bundle_signature)?;
    if !SEALED_PRIVATE_KEYS_RANGE.contains(&input.sealed_private_keys.len()) {
        return Err(AppError::Invalid("the sealed private keys are malformed"));
    }
    Ok(())
}
