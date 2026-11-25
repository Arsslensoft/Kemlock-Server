//! [`BwNotifier`]: what the Bitwarden API publishes ([`BwEvent`]), sent where Vaultwarden 1.37.5
//! sends it (`src/api/notifications.rs`, `push.rs`).
//!
//! - a message on the open `/notifications/hub` sockets of every account the change is for, with
//!   Vaultwarden's types and payloads;
//! - a push through Bitwarden's relay when the operator set one up and the account has a phone
//!   registered (a personal cipher's, a folder's, a Send's and the account-wide ones; never an
//!   organization cipher's, as in Vaultwarden);
//! - a nudge for the owner's Kemlock devices and the other replicas, through [`Notify`]. The
//!   Bitwarden sockets on this replica were told in detail already, so their next `SyncVault` is
//!   covered ([`BwHub::cover`]) and the apps don't sync twice for one change.
//!
//! [`BwNotifier::publish`] never waits: pushes are sent from a task of their own.

use super::hub::BwHub;
use super::message::{Message, UpdateType};
use super::relay::{BwPush, BwPushSwitch};
use crate::Notify;
use kemlock_app::bw_events::{
    Acting, BwDeviceRepo, BwEvent, BwEvents, Change, CipherEvent, FolderEvent, SendEvent, UserSync,
};
use kemlock_domain::{Owner, UserId};
use time::OffsetDateTime;

/// Bitwarden's push relay and where the phones registered with it are kept.
pub struct BwPushing<R> {
    pub relay: BwPushSwitch,
    pub devices: R,
}

impl<R> std::fmt::Debug for BwPushing<R> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BwPushing").finish_non_exhaustive()
    }
}

impl<R> Clone for BwPushing<R>
where
    R: Clone,
{
    fn clone(&self) -> Self {
        BwPushing {
            relay: self.relay.clone(),
            devices: self.devices.clone(),
        }
    }
}

/// Sends the Bitwarden API's events to every live channel. Cheap to clone.
pub struct BwNotifier<R> {
    hub: BwHub,
    notify: Notify,
    push: Option<BwPushing<R>>,
}

impl<R> std::fmt::Debug for BwNotifier<R> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BwNotifier")
            .field("push", &self.push.is_some())
            .finish_non_exhaustive()
    }
}

impl<R: BwDeviceRepo + Clone + 'static> BwNotifier<R> {
    /// `push` is `None` when Bitwarden's relay isn't set up (`PUSH_ENABLED`).
    pub fn new(hub: BwHub, notify: Notify, push: Option<BwPushing<R>>) -> BwNotifier<R> {
        BwNotifier { hub, notify, push }
    }

    /// Tells the accounts' sockets, and covers them when a nudge for the same change follows.
    fn tell(&self, users: &[UserId], message: &Message, nudged: bool) {
        for user in users {
            self.hub.send(*user, message.clone());
            if nudged {
                self.hub.cover(*user);
            }
        }
    }

    /// Pushes to the account's phones, from a task of its own. `with_identifier` says whether the
    /// acting device's identifier goes along (Vaultwarden's account-wide updates leave it out).
    fn push(&self, user: UserId, acting: Option<Acting>, push: BwPush, with_identifier: bool) {
        let Some(pushing) = self.push.clone().filter(|p| p.relay.get().is_some()) else {
            return;
        };
        tokio::spawn(async move {
            match pushing.devices.bw_user_has_push(user).await {
                Ok(true) => {}
                Ok(false) => return,
                Err(error) => {
                    tracing::debug!(%error, "couldn't look up the account's phones for a push");
                    return;
                }
            }
            let push_uuid = match acting {
                Some(acting) => match pushing.devices.bw_device(acting.device).await {
                    Ok(device) => device.and_then(|d| d.push).map(|p| p.push_uuid),
                    Err(_) => None,
                },
                None => None,
            };
            let identifier = acting
                .filter(|_| with_identifier)
                .and_then(|a| a.identifier);
            let push = push.from_device(push_uuid, identifier);
            let Some(relay) = pushing.relay.get() else {
                return;
            };
            if let Err(error) = relay.send(&push).await {
                tracing::debug!(%error, "Bitwarden's push relay didn't take a push");
            }
        });
    }

    fn cipher(&self, event: CipherEvent) {
        let kind = match event.change {
            Change::Created => UpdateType::SyncCipherCreate,
            Change::Updated => UpdateType::SyncCipherUpdate,
            Change::Deleted => UpdateType::SyncLoginDelete,
        };
        // With collections the message names no account, as Vaultwarden's does, or the clients
        // wouldn't sync the collection change.
        let user = match event.collections {
            Some(_) => None,
            None => event.user,
        };
        let identifier = event.device.and_then(|d| d.identifier);
        let message = Message::cipher_in(
            kind,
            event.id,
            user.map(|u| u.0),
            event.organization.map(|o| o.0),
            event.collections.clone(),
            event.revision,
            identifier,
        );
        self.tell(&event.recipients, &message, true);
        match (event.user, event.organization) {
            (Some(user), None) => {
                self.notify.nudge(Owner::User(user));
                if let [only] = event.recipients.as_slice() {
                    let push = BwPush::cipher(kind, event.id, only.0, event.revision, None);
                    self.push(*only, event.device, push, true);
                }
            }
            (_, Some(space)) => self.notify.nudge(Owner::Space(space)),
            (None, None) => {}
        }
    }

    fn folder(&self, event: FolderEvent) {
        let kind = match event.change {
            Change::Created => UpdateType::SyncFolderCreate,
            Change::Updated => UpdateType::SyncFolderUpdate,
            Change::Deleted => UpdateType::SyncFolderDelete,
        };
        let identifier = event.device.and_then(|d| d.identifier);
        let message = Message::folder(kind, event.id, event.user.0, event.revision, identifier);
        self.tell(&[event.user], &message, true);
        self.notify.nudge(Owner::User(event.user));
        let push = BwPush::folder(kind, event.id, event.user.0, event.revision, None);
        self.push(event.user, event.device, push, true);
    }

    fn send(&self, event: SendEvent) {
        let kind = match event.change {
            Change::Created => UpdateType::SyncSendCreate,
            Change::Updated => UpdateType::SyncSendUpdate,
            Change::Deleted => UpdateType::SyncSendDelete,
        };
        // Sends aren't items: Kemlock devices have nothing to sync for them.
        let message = Message::send(kind, event.id, event.user.0, event.revision);
        self.tell(&[event.user], &message, false);
        let push = BwPush::send(kind, event.id, event.user.0, event.revision);
        self.push(event.user, event.device, push, true);
    }

    fn sync(&self, sync: UserSync, user: UserId, at: OffsetDateTime, device: Option<Acting>) {
        let kind = match sync {
            UserSync::Vault => UpdateType::SyncVault,
            UserSync::Ciphers => UpdateType::SyncCiphers,
            UserSync::Settings => UpdateType::SyncSettings,
            UserSync::OrgKeys => UpdateType::SyncOrgKeys,
        };
        let message = Message::user_update(kind, user.0, at);
        // Settings are the account's and not an item, so no Kemlock device has anything to sync;
        // the rest change what the account's vault holds.
        let nudged = sync != UserSync::Settings;
        self.tell(&[user], &message, nudged);
        if nudged {
            self.notify.nudge(Owner::User(user));
        }
        self.push(user, device, BwPush::user_update(kind, user.0, at), false);
    }

    fn log_out(&self, user: UserId, device: Option<Acting>, at: OffsetDateTime) {
        let identifier = device.and_then(|d| d.identifier);
        self.tell(&[user], &Message::logout(user.0, identifier, at), false);
        self.push(user, device, BwPush::logout(user.0, identifier, at), true);
    }
}

impl<R: BwDeviceRepo + Clone + 'static> BwEvents for BwNotifier<R> {
    fn publish(&self, event: BwEvent) {
        match event {
            BwEvent::Cipher(event) => self.cipher(event),
            BwEvent::Folder(event) => self.folder(event),
            BwEvent::Send(event) => self.send(event),
            BwEvent::Sync {
                sync,
                user,
                at,
                device,
            } => self.sync(sync, user, at, device),
            BwEvent::LogOut { user, device, at } => self.log_out(user, device, at),
        }
    }
}

#[cfg(test)]
mod tests;
