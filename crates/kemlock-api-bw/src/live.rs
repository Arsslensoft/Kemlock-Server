//! What the API tells the live channels: Vaultwarden's `nt.send_*` calls, as [`BwEvent`]s
//! published through the port `kemlock-notify` implements (the hub, Bitwarden's push relay and a
//! nudge for the owner's Kemlock devices).
//!
//! Every write ends in one of these helpers once it has committed. They never fail and never
//! wait: a client that misses a message syncs at its next poll.

use crate::app::{App, Authed, BwStore};
use crate::orgs::model::Org;
use kemlock_app::bw_events::{
    Acting, BwEvent, BwEvents, BwRelay, Change, CipherEvent, FolderEvent, NoEvents, SendEvent,
    UserSync,
};
use kemlock_app::notices::Notices;
use kemlock_app::privacy::OwnErasure;
use kemlock_domain::UserId;
use kemlock_domain::spaces::CollectionId;
use std::sync::Arc;
use time::OffsetDateTime;
use uuid::Uuid;

/// The live channels the API publishes to. The default publishes nowhere and has no relay.
#[derive(Clone)]
pub struct BwLive {
    pub events: Arc<dyn BwEvents>,
    /// Bitwarden's push relay, for the device-token routes; `None` when `PUSH_ENABLED` is off.
    pub relay: Option<Arc<dyn BwRelay>>,
    /// The sender of the mail the API raises (a new device signed in). Without SMTP it only logs.
    pub notices: Notices,
    /// Vaultwarden's `REQUIRE_DEVICE_EMAIL`: a sign-in from a new device is refused when the mail
    /// about it can't be sent.
    pub require_device_email: bool,
    /// What deletes the account that asks (`DELETE /api/accounts`): the whole erasure of the
    /// privacy area. Without it the route refuses, so a half erasure is never done.
    pub erasure: Option<Arc<dyn OwnErasure>>,
}

impl Default for BwLive {
    fn default() -> Self {
        BwLive {
            events: Arc::new(NoEvents),
            relay: None,
            notices: Notices::logging(),
            require_device_email: false,
            erasure: None,
        }
    }
}

impl std::fmt::Debug for BwLive {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BwLive")
            // Whether pushes go out now: the switch is always there, the relay behind it may not be.
            .field(
                "relay",
                &self.relay.as_ref().is_some_and(|relay| relay.enabled()),
            )
            .field("notices", &self.notices)
            .field("require_device_email", &self.require_device_email)
            .field("erasure", &self.erasure.is_some())
            .finish_non_exhaustive()
    }
}

/// The device behind a request, as an event names it.
pub(crate) fn acting_of(authed: &Authed) -> Option<Acting> {
    Some(Acting {
        device: authed.device.id,
        identifier: authed.identifier,
    })
}

fn uuid_of(text: &str) -> Option<Uuid> {
    Uuid::parse_str(text).ok()
}

impl<S: BwStore> App<S> {
    /// A personal cipher was created, changed or deleted: its owner's clients hear of it.
    pub(crate) fn cipher_changed(
        &self,
        authed: &Authed,
        change: Change,
        id: &str,
        revision: OffsetDateTime,
    ) {
        let Some(id) = uuid_of(id) else {
            return;
        };
        let user = authed.user.id;
        self.events.publish(BwEvent::Cipher(CipherEvent {
            change,
            id,
            user: Some(user),
            organization: None,
            collections: None,
            revision,
            recipients: vec![user],
            device: acting_of(authed),
        }));
    }

    /// An organization's cipher was created, changed or deleted: the members who can see it hear
    /// of it. `shared` is a share, which names the collections and carries the time of the change,
    /// so clients sync the collection change.
    pub(crate) fn org_cipher_changed(
        &self,
        authed: &Authed,
        change: Change,
        org: &Org,
        id: &str,
        links: &[CollectionId],
        shared: bool,
    ) {
        let Some(id) = uuid_of(id) else {
            return;
        };
        let recipients: Vec<UserId> = org
            .members
            .keys()
            .copied()
            .filter(|user| org.cipher_restrictions(*user, links).is_some())
            .collect();
        self.events.publish(BwEvent::Cipher(CipherEvent {
            change,
            id,
            user: None,
            organization: Some(org.id),
            collections: shared.then(|| links.iter().map(|c| c.0).collect()),
            revision: self.now(),
            recipients,
            device: acting_of(authed),
        }));
    }

    /// The account should sync more than one record (or its settings).
    pub(crate) fn user_synced(&self, authed: &Authed, sync: UserSync) {
        self.events.publish(BwEvent::Sync {
            sync,
            user: authed.user.id,
            at: self.now(),
            device: acting_of(authed),
        });
    }

    /// Every confirmed member of the organization should sync everything: a change to its
    /// members, collections, groups or policies.
    pub(crate) fn members_synced(&self, org: &Org, sync: UserSync, by: Option<&Authed>) {
        let at = self.now();
        for (user, member) in &org.members {
            if member.confirmed() {
                self.events.publish(BwEvent::Sync {
                    sync,
                    user: *user,
                    at,
                    device: by.and_then(acting_of),
                });
            }
        }
    }

    /// The account's other sessions ended: their live connections close and their apps sign in
    /// again. The device that asked (`authed`) stays signed in.
    pub(crate) fn sessions_ended(&self, authed: &Authed) {
        self.events.publish(BwEvent::LogOut {
            user: authed.user.id,
            device: acting_of(authed),
            at: self.now(),
        });
    }

    /// A member joined or left an organization: their clients should fetch its keys again.
    pub(crate) fn org_keys_changed(&self, user: UserId) {
        self.events.publish(BwEvent::Sync {
            sync: UserSync::OrgKeys,
            user,
            at: self.now(),
            device: None,
        });
    }

    pub(crate) fn folder_changed(
        &self,
        authed: &Authed,
        change: Change,
        id: Uuid,
        revision: OffsetDateTime,
    ) {
        self.events.publish(BwEvent::Folder(FolderEvent {
            change,
            id,
            user: authed.user.id,
            revision,
            device: acting_of(authed),
        }));
    }

    /// A Send changed. `by` is the owner's device; a recipient's access has none.
    pub(crate) fn send_changed(
        &self,
        by: Option<&Authed>,
        user: UserId,
        change: Change,
        id: Uuid,
        revision: OffsetDateTime,
    ) {
        self.events.publish(BwEvent::Send(SendEvent {
            change,
            id,
            user,
            revision,
            device: by.and_then(acting_of),
        }));
    }
}
