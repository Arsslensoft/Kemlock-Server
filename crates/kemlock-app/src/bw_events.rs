//! What the Bitwarden API tells the live channels, and the push tokens of Bitwarden's phone apps.
//!
//! Every write the Bitwarden API makes ends in a [`BwEvent`], which a [`BwEvents`] sender turns
//! into what Vaultwarden 1.37.5 sends (`src/api/notifications.rs`): a message on the account's
//! `/notifications/hub` sockets, a push through Bitwarden's relay, and a nudge for the owner's
//! Kemlock devices. The API holds only this port, so it needs no live channel to run and its
//! tests read the events as plain values.
//!
//! [`BwDeviceRepo`] keeps what the API knows of each device (identifier, type, the phone's push
//! registration), and [`BwRelay`] is Bitwarden's push relay as the device routes use it.

use crate::notices::BoxFuture;
use crate::ports::StoreError;
use kemlock_domain::{DeviceId, SpaceId, UserId};
use std::future::Future;
use time::OffsetDateTime;
use uuid::Uuid;

/// What happened to a record.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Change {
    Created,
    Updated,
    Deleted,
}

/// The wider sync a client is asked for when one message can't say what changed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum UserSync {
    /// Everything (`SyncVault`).
    Vault,
    /// Several ciphers at once (`SyncCiphers`).
    Ciphers,
    /// The account's settings (`SyncSettings`).
    Settings,
    /// The account's organizations or their keys (`SyncOrgKeys`).
    OrgKeys,
}

/// The device that made a change. A Bitwarden client names itself in a change by its identifier
/// (`ContextId`), and ignores changes that name it. `identifier` is `None` for a session that
/// began before the server kept identifiers: the client then syncs its own change once more.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Acting {
    pub device: DeviceId,
    pub identifier: Option<Uuid>,
}

/// A cipher was created, changed or deleted.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CipherEvent {
    pub change: Change,
    pub id: Uuid,
    /// The account a personal cipher belongs to; `None` for an organization's.
    pub user: Option<UserId>,
    pub organization: Option<SpaceId>,
    /// The collections a share put the cipher in. Set, the message names no account and carries
    /// the time of the change instead of the cipher's revision date, as Vaultwarden's does, so
    /// clients sync the collection change.
    pub collections: Option<Vec<Uuid>>,
    pub revision: OffsetDateTime,
    /// The accounts whose sockets hear of it.
    pub recipients: Vec<UserId>,
    /// The device that made the change, which ignores its own echo.
    pub device: Option<Acting>,
}

/// A folder was created, renamed or deleted.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FolderEvent {
    pub change: Change,
    pub id: Uuid,
    pub user: UserId,
    pub revision: OffsetDateTime,
    pub device: Option<Acting>,
}

/// A Send was created, changed or deleted.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SendEvent {
    pub change: Change,
    pub id: Uuid,
    pub user: UserId,
    pub revision: OffsetDateTime,
    /// The device that made the change; a recipient reading the Send has none.
    pub device: Option<Acting>,
}

/// One thing the live channels should hear.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum BwEvent {
    Cipher(CipherEvent),
    Folder(FolderEvent),
    Send(SendEvent),
    /// The account should sync more than one record.
    Sync {
        sync: UserSync,
        user: UserId,
        at: OffsetDateTime,
        device: Option<Acting>,
    },
    /// The account's sessions ended. `device` is the one that asked and stays signed in.
    LogOut {
        user: UserId,
        device: Option<Acting>,
        at: OffsetDateTime,
    },
}

/// Turns events into live messages, pushes and nudges. Never waits and never fails: a change has
/// been committed already, and a missed message only means a client syncs a little later.
pub trait BwEvents: Send + Sync + 'static {
    fn publish(&self, event: BwEvent);
}

/// The sender of a server with no live channels: events go nowhere.
#[derive(Clone, Copy, Debug, Default)]
pub struct NoEvents;

impl BwEvents for NoEvents {
    fn publish(&self, _event: BwEvent) {}
}

/// What the relay knows a phone by.
#[derive(Clone, PartialEq, Eq)]
pub struct BwPushToken {
    /// The id the relay knows the phone by.
    pub push_uuid: Uuid,
    pub token: String,
}

impl std::fmt::Debug for BwPushToken {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // The token is a bearer credential for the phone's pushes.
        f.debug_struct("BwPushToken")
            .field("push_uuid", &self.push_uuid)
            .field("token", &"<redacted>")
            .finish()
    }
}

/// What the Bitwarden API keeps of a device beyond the device row: the identifier the app signs in
/// with (a Bitwarden client names itself in a change's `ContextId` by it, so it ignores its own
/// echo), its Bitwarden device type, and the phone's push registration with Bitwarden's relay.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BwDevice {
    pub device: DeviceId,
    pub user: UserId,
    pub identifier: Uuid,
    /// Bitwarden's device type number (0 Android, 1 iOS, 15 Android on Amazon).
    pub device_type: i32,
    pub push: Option<BwPushToken>,
    pub updated_at: OffsetDateTime,
}

/// The devices of the Bitwarden API, one row per device.
pub trait BwDeviceRepo: Send + Sync {
    /// Records the identifier and device type of a device that signed in. A device already known
    /// keeps its push registration. `NotFound` when the device row doesn't exist.
    fn note_bw_device(
        &self,
        device: DeviceId,
        user: UserId,
        identifier: Uuid,
        device_type: i32,
        at: OffsetDateTime,
    ) -> impl Future<Output = Result<(), StoreError>> + Send;

    fn bw_device(
        &self,
        device: DeviceId,
    ) -> impl Future<Output = Result<Option<BwDevice>, StoreError>> + Send;

    /// Every account's device that signs in with this identifier (the same app can be signed in
    /// to two accounts).
    fn bw_devices_by_identifier(
        &self,
        identifier: Uuid,
    ) -> impl Future<Output = Result<Vec<BwDevice>, StoreError>> + Send;

    /// Sets (`Some`) or clears (`None`) the device's push registration. `NotFound` when the device
    /// has not signed in to the Bitwarden API.
    fn set_bw_push(
        &self,
        device: DeviceId,
        push: Option<BwPushToken>,
    ) -> impl Future<Output = Result<(), StoreError>> + Send;

    /// Whether the account has a phone registered with the relay.
    fn bw_user_has_push(
        &self,
        user: UserId,
    ) -> impl Future<Output = Result<bool, StoreError>> + Send;
}

/// Bitwarden's push relay, as the device routes use it. The error text is for logs and for the
/// message Vaultwarden's `err!` gives.
pub trait BwRelay: Send + Sync + 'static {
    /// Whether pushes are on. A relay that can be switched off says so; the device routes then
    /// keep no push token, as when there is no relay.
    fn enabled(&self) -> bool {
        true
    }

    /// Registers the phone (`device.push` is set) with the relay.
    fn register<'a>(&'a self, device: &'a BwDevice) -> BoxFuture<'a, Result<(), String>>;

    /// Forgets the phone the relay knows by this id.
    fn unregister(&self, push_uuid: Uuid) -> BoxFuture<'_, Result<(), String>>;
}

/// Bitwarden's device types that have a push token: Android, iOS and Android on Amazon.
pub fn is_push_device(device_type: i32) -> bool {
    matches!(device_type, 0 | 1 | 15)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_phones_are_push_devices() {
        assert!(is_push_device(0));
        assert!(is_push_device(1));
        assert!(is_push_device(15));
        assert!(!is_push_device(9));
        assert!(!is_push_device(8));
    }

    #[test]
    fn a_push_token_stays_out_of_debug_output() {
        let device = BwDevice {
            device: DeviceId(Uuid::nil()),
            user: UserId(Uuid::nil()),
            identifier: Uuid::nil(),
            device_type: 0,
            push: Some(BwPushToken {
                push_uuid: Uuid::nil(),
                token: "fcm-secret-token".to_owned(),
            }),
            updated_at: OffsetDateTime::UNIX_EPOCH,
        };
        assert!(!format!("{device:?}").contains("fcm-secret-token"));
    }

    #[test]
    fn no_events_swallows_everything() {
        NoEvents.publish(BwEvent::LogOut {
            user: UserId(Uuid::nil()),
            device: None,
            at: OffsetDateTime::UNIX_EPOCH,
        });
    }
}
