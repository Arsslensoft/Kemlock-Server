//! Trusted devices: the root key wrapped by a key only the device holds, kept so the device can
//! open the vault after a sign-in without the password (design, "Unlocking without the master
//! password").
//!
//! The wrapping key lives in the Secure Enclave, the Android Keystore or a non-extractable
//! WebCrypto key and never reaches the server, so the copy is as good as ciphertext to anyone who
//! only has the database. A device reads and writes only its own copy, and signing it out deletes
//! the copy with its tokens.

use super::ports::KeyCopyRepo;
use crate::authenticate::Actor;
use crate::error::AppError;
use crate::ports::{Clock, DeviceRepo, Event, EventLog, TokenRepo};
use kemlock_domain::DeviceId;
use kemlock_domain::unlock::{DeviceKeyCopy, KeyProtection, MAX_WRAPPED_KEY_LEN};

/// A device's own copy of the root key.
#[derive(Debug)]
pub struct KeyCopies<D, C, E> {
    pub devices: D,
    pub copies: C,
    pub clock: E,
}

impl<D: DeviceRepo, C: KeyCopyRepo, E: Clock> KeyCopies<D, C, E> {
    /// Stores or replaces the signed-in device's copy.
    pub async fn put(
        &self,
        actor: &Actor,
        wrapped_key: Vec<u8>,
        protection: KeyProtection,
    ) -> Result<DeviceKeyCopy, AppError> {
        if wrapped_key.is_empty() || wrapped_key.len() > MAX_WRAPPED_KEY_LEN {
            return Err(AppError::Invalid("the wrapped key must be 1 to 1024 bytes"));
        }
        // The token names a device; the device may have been signed out since.
        let device = self
            .devices
            .get(actor.device)
            .await?
            .filter(|d| d.user == actor.user)
            .ok_or(AppError::NotFound)?;
        let now = self.clock.now();
        let created_at = self
            .copies
            .key_copy(device.id)
            .await?
            .map_or(now, |old| old.created_at);
        let copy = DeviceKeyCopy {
            device: device.id,
            wrapped_key,
            protection,
            created_at,
            updated_at: now,
        };
        self.copies.put_key_copy(&copy).await?;
        Ok(copy)
    }

    /// The signed-in device's copy; `NotFound` when it holds none.
    pub async fn get(&self, actor: &Actor) -> Result<DeviceKeyCopy, AppError> {
        self.copies
            .key_copy(actor.device)
            .await?
            .ok_or(AppError::NotFound)
    }

    /// Removes the signed-in device's copy: the device stops being trusted, its session goes on.
    pub async fn remove(&self, actor: &Actor) -> Result<(), AppError> {
        Ok(self.copies.remove_key_copy(actor.device).await?)
    }
}

/// Stops trusting a device of the account: its key copy goes and its session carries on.
#[derive(Debug)]
pub struct UntrustDevice<D, C, E, V> {
    pub devices: D,
    pub copies: C,
    pub clock: E,
    pub events: V,
}

impl<D: DeviceRepo, C: KeyCopyRepo, E: Clock, V: EventLog> UntrustDevice<D, C, E, V> {
    /// Any device of the account can stop trusting any other, or itself, as it can sign one out. A
    /// device of another account is `NotFound`. Taking a copy away only lowers trust, so no key
    /// is needed; making one still takes the device that holds the wrapping key.
    pub async fn execute(&self, actor: &Actor, target: DeviceId) -> Result<(), AppError> {
        self.devices
            .get(target)
            .await?
            .filter(|d| d.user == actor.user)
            .ok_or(AppError::NotFound)?;
        self.copies.remove_key_copy(target).await?;
        let event = Event {
            actor: Some(actor.user),
            device: Some(actor.device),
            action: "device.untrust",
            target: Some(target.to_string()),
            at: self.clock.now(),
        };
        if let Err(e) = self.events.record(event).await {
            tracing::warn!(error = %e, "couldn't record an event");
        }
        Ok(())
    }
}

/// Signs a device out: its tokens, its key copy and the device itself go.
#[derive(Debug)]
pub struct SignOutDevice<D, C, T, E, V> {
    pub devices: D,
    pub copies: C,
    pub tokens: T,
    pub clock: E,
    pub events: V,
}

impl<D: DeviceRepo, C: KeyCopyRepo, T: TokenRepo, E: Clock, V: EventLog>
    SignOutDevice<D, C, T, E, V>
{
    /// Any device of the account can sign any other out, or itself. A device of another account
    /// is `NotFound`.
    pub async fn execute(&self, actor: &Actor, target: DeviceId) -> Result<(), AppError> {
        self.devices
            .get(target)
            .await?
            .filter(|d| d.user == actor.user)
            .ok_or(AppError::NotFound)?;
        // Tokens first, so the device can't refresh while the rest is deleted.
        self.tokens.revoke_device(target).await?;
        self.copies.remove_key_copy(target).await?;
        self.devices.remove(target).await?;
        let event = Event {
            actor: Some(actor.user),
            device: Some(actor.device),
            action: "device.sign_out",
            target: Some(target.to_string()),
            at: self.clock.now(),
        };
        if let Err(e) = self.events.record(event).await {
            tracing::warn!(error = %e, "couldn't record an event");
        }
        Ok(())
    }

    /// Signs out every device of the account but the one asking, as a password change with "Sign
    /// out my other devices" does. Returns how many went. The asking device keeps its tokens and
    /// its key copy.
    pub async fn execute_others(&self, actor: &Actor) -> Result<usize, AppError> {
        let mut signed_out = 0;
        for device in self.devices.list(actor.user).await? {
            if device.id != actor.device {
                self.execute(actor, device.id).await?;
                signed_out += 1;
            }
        }
        Ok(signed_out)
    }
}
