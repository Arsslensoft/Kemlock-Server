use super::*;
use crate::audience::UserOnly;
use crate::bitwarden::hub::{HubConfig, Tap};
use crate::bitwarden::message::Field;
use crate::bitwarden::relay::{BitwardenPush, BitwardenPushConfig};
use crate::fanout::Fanout;
use crate::fanout::testing::Heard;
use crate::testing::{eventually, serve};
use axum::extract::State;
use axum::http::StatusCode;
use axum::routing::post;
use axum::{Json, Router};
use kemlock_app::bw_events::{BwDevice, BwPushToken};
use kemlock_app::ports::{StoreError, Zeroizing};
use kemlock_domain::{DeviceId, SpaceId};
use serde_json::{Value, json};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use time::macros::datetime;
use uuid::Uuid;

const AT: OffsetDateTime = datetime!(2026-11-25 10:00 UTC);

/// The devices of the Bitwarden API, in memory.
#[derive(Clone, Default)]
struct Devices(Arc<Mutex<HashMap<DeviceId, BwDevice>>>);

impl Devices {
    fn phone(&self, user: UserId, identifier: Uuid) -> (DeviceId, Uuid) {
        let device = DeviceId::random();
        let push_uuid = Uuid::new_v4();
        self.0.lock().expect("lock").insert(
            device,
            BwDevice {
                device,
                user,
                identifier,
                device_type: 0,
                push: Some(BwPushToken {
                    push_uuid,
                    token: "fcm-token".to_owned(),
                }),
                updated_at: AT,
            },
        );
        (device, push_uuid)
    }
}

impl BwDeviceRepo for Devices {
    async fn note_bw_device(
        &self,
        device: DeviceId,
        user: UserId,
        identifier: Uuid,
        device_type: i32,
        at: OffsetDateTime,
    ) -> Result<(), StoreError> {
        let mut map = self.0.lock().expect("lock");
        let push = map.get(&device).and_then(|d| d.push.clone());
        map.insert(
            device,
            BwDevice {
                device,
                user,
                identifier,
                device_type,
                push,
                updated_at: at,
            },
        );
        Ok(())
    }

    async fn bw_device(&self, device: DeviceId) -> Result<Option<BwDevice>, StoreError> {
        Ok(self.0.lock().expect("lock").get(&device).cloned())
    }

    async fn bw_devices_by_identifier(
        &self,
        identifier: Uuid,
    ) -> Result<Vec<BwDevice>, StoreError> {
        Ok(self
            .0
            .lock()
            .expect("lock")
            .values()
            .filter(|d| d.identifier == identifier)
            .cloned()
            .collect())
    }

    async fn set_bw_push(
        &self,
        device: DeviceId,
        push: Option<BwPushToken>,
    ) -> Result<(), StoreError> {
        match self.0.lock().expect("lock").get_mut(&device) {
            Some(known) => {
                known.push = push;
                Ok(())
            }
            None => Err(StoreError::NotFound),
        }
    }

    async fn bw_user_has_push(&self, user: UserId) -> Result<bool, StoreError> {
        Ok(self
            .0
            .lock()
            .expect("lock")
            .values()
            .any(|d| d.user == user && d.push.is_some()))
    }
}

/// Bitwarden's identity service and relay: the bodies of the sends it took.
#[derive(Default)]
struct Relay {
    sent: Mutex<Vec<Value>>,
}

async fn token() -> Json<Value> {
    Json(json!({"access_token": "t", "expires_in": 3600, "token_type": "Bearer"}))
}

async fn take(State(relay): State<Arc<Relay>>, Json(body): Json<Value>) -> StatusCode {
    relay.sent.lock().expect("lock").push(body);
    StatusCode::OK
}

struct Rig {
    notifier: BwNotifier<Devices>,
    hub: BwHub,
    tap: Tap,
    heard: Heard,
    devices: Devices,
    relay: Arc<Relay>,
}

async fn rig(push: bool) -> Rig {
    let hub = BwHub::new(Arc::new(UserOnly), HubConfig::default());
    let tap = hub.tap();
    let heard = Heard::default();
    let notify = Notify::new(Fanout::in_process(heard.sink()), None);
    let devices = Devices::default();
    let relay = Arc::new(Relay::default());
    let pushing = if push {
        let app = Router::new()
            .route("/connect/token", post(token))
            .route("/push/send", post(take))
            .with_state(relay.clone());
        let base = format!("http://{}", serve(app).await);
        let client = BitwardenPush::new(BitwardenPushConfig {
            installation_id: "inst".to_owned(),
            installation_key: Zeroizing::new("key".to_owned()),
            relay_uri: base.clone(),
            identity_uri: base,
        })
        .expect("a client");
        Some(BwPushing {
            relay: crate::bitwarden::BwPushSwitch::new(Some(Arc::new(client))),
            devices: devices.clone(),
        })
    } else {
        None
    };
    Rig {
        notifier: BwNotifier::new(hub.clone(), notify, pushing),
        hub,
        tap,
        heard,
        devices,
        relay,
    }
}

fn id(n: u128) -> Uuid {
    Uuid::from_u128(n)
}

fn payload<'a>(message: &'a Message, key: &str) -> &'a Field {
    message
        .payload
        .iter()
        .find(|(k, _)| *k == key)
        .map(|(_, v)| v)
        .unwrap_or_else(|| panic!("no {key}"))
}

fn acting(identifier: Option<Uuid>) -> Option<Acting> {
    Some(Acting {
        device: DeviceId::random(),
        identifier,
    })
}

fn cipher_event(user: UserId, device: Option<Acting>) -> CipherEvent {
    CipherEvent {
        change: Change::Updated,
        id: id(1),
        user: Some(user),
        organization: None,
        collections: None,
        revision: AT,
        recipients: vec![user],
        device,
    }
}

#[tokio::test]
async fn a_personal_cipher_reaches_its_owner_with_the_acting_devices_context() {
    let mut rig = rig(false).await;
    let ada = UserId::random();
    rig.notifier
        .publish(BwEvent::Cipher(cipher_event(ada, acting(Some(id(9))))));
    let heard = rig.tap.heard();
    assert_eq!(heard.len(), 1);
    assert_eq!(heard[0].0, ada);
    let message = &heard[0].1;
    assert_eq!(message.kind, UpdateType::SyncCipherUpdate);
    assert_eq!(message.context, Some(id(9)));
    assert_eq!(payload(message, "Id"), &Field::id(id(1)));
    assert_eq!(payload(message, "UserId"), &Field::id(ada.0));
    assert_eq!(payload(message, "OrganizationId"), &Field::Nil);
    assert_eq!(payload(message, "CollectionIds"), &Field::Nil);
    assert_eq!(payload(message, "RevisionDate"), &Field::Date(AT));
}

#[tokio::test]
async fn the_change_kind_picks_the_update_type() {
    let mut rig = rig(false).await;
    let ada = UserId::random();
    for (change, kind) in [
        (Change::Created, UpdateType::SyncCipherCreate),
        (Change::Updated, UpdateType::SyncCipherUpdate),
        (Change::Deleted, UpdateType::SyncLoginDelete),
    ] {
        let mut event = cipher_event(ada, None);
        event.change = change;
        rig.notifier.publish(BwEvent::Cipher(event));
        assert_eq!(rig.tap.heard()[0].1.kind, kind);
    }
}

#[tokio::test]
async fn kemlock_devices_are_nudged_and_the_bitwarden_sockets_are_not_told_twice() {
    let mut rig = rig(false).await;
    let ada = UserId::random();
    rig.notifier
        .publish(BwEvent::Cipher(cipher_event(ada, None)));
    assert_eq!(rig.heard.owners(), vec![Owner::User(ada)]);
    assert_eq!(rig.tap.heard().len(), 1, "only the detailed message");
    // The nudge's own SyncVault for the hub is the covered one.
    rig.hub.nudge(Owner::User(ada));
    assert!(rig.tap.heard().is_empty());
}

#[tokio::test]
async fn a_share_names_the_collections_and_no_account() {
    let mut rig = rig(false).await;
    let (ada, grace) = (UserId::random(), UserId::random());
    let space = SpaceId::random();
    let later = datetime!(2026-11-25 10:05 UTC);
    rig.notifier.publish(BwEvent::Cipher(CipherEvent {
        change: Change::Updated,
        id: id(1),
        user: None,
        organization: Some(space),
        collections: Some(vec![id(6)]),
        revision: later,
        recipients: vec![ada, grace],
        device: None,
    }));
    let heard = rig.tap.heard();
    let users: Vec<UserId> = heard.iter().map(|(u, _)| *u).collect();
    assert_eq!(users, vec![ada, grace]);
    let message = &heard[0].1;
    assert_eq!(payload(message, "UserId"), &Field::Nil);
    assert_eq!(payload(message, "OrganizationId"), &Field::id(space.0));
    assert_eq!(
        payload(message, "CollectionIds"),
        &Field::Texts(vec![id(6).to_string()])
    );
    assert_eq!(payload(message, "RevisionDate"), &Field::Date(later));
    assert_eq!(message.context, None);
    // Kemlock devices hear of the space's change.
    assert_eq!(rig.heard.owners(), vec![Owner::Space(space)]);
}

#[tokio::test]
async fn a_folder_has_its_own_types_and_payload() {
    let mut rig = rig(false).await;
    let ada = UserId::random();
    for (change, kind) in [
        (Change::Created, UpdateType::SyncFolderCreate),
        (Change::Updated, UpdateType::SyncFolderUpdate),
        (Change::Deleted, UpdateType::SyncFolderDelete),
    ] {
        rig.notifier.publish(BwEvent::Folder(FolderEvent {
            change,
            id: id(2),
            user: ada,
            revision: AT,
            device: acting(Some(id(8))),
        }));
        let heard = rig.tap.heard();
        assert_eq!(heard[0].1.kind, kind);
        assert_eq!(heard[0].1.context, Some(id(8)));
        assert_eq!(payload(&heard[0].1, "UserId"), &Field::id(ada.0));
    }
}

#[tokio::test]
async fn a_send_has_no_context_and_no_kemlock_nudge() {
    let mut rig = rig(false).await;
    let ada = UserId::random();
    rig.notifier.publish(BwEvent::Send(SendEvent {
        change: Change::Created,
        id: id(3),
        user: ada,
        revision: AT,
        device: acting(Some(id(8))),
    }));
    let heard = rig.tap.heard();
    assert_eq!(heard[0].1.kind, UpdateType::SyncSendCreate);
    assert_eq!(heard[0].1.context, None);
    assert!(rig.heard.owners().is_empty());
    // Nothing was covered: a later nudge is heard.
    rig.hub.nudge(Owner::User(ada));
    assert_eq!(rig.tap.heard().len(), 1);
}

#[tokio::test]
async fn settings_are_told_but_not_nudged_and_an_org_key_sync_is_both() {
    let mut rig = rig(false).await;
    let ada = UserId::random();
    rig.notifier.publish(BwEvent::Sync {
        sync: UserSync::Settings,
        user: ada,
        at: AT,
        device: None,
    });
    assert_eq!(rig.tap.heard()[0].1.kind, UpdateType::SyncSettings);
    assert!(rig.heard.owners().is_empty());
    rig.notifier.publish(BwEvent::Sync {
        sync: UserSync::OrgKeys,
        user: ada,
        at: AT,
        device: None,
    });
    assert_eq!(rig.tap.heard()[0].1.kind, UpdateType::SyncOrgKeys);
    assert_eq!(rig.heard.owners(), vec![Owner::User(ada)]);
}

#[tokio::test]
async fn a_logout_names_the_device_that_stays() {
    let mut rig = rig(false).await;
    let ada = UserId::random();
    rig.notifier.publish(BwEvent::LogOut {
        user: ada,
        device: acting(Some(id(8))),
        at: AT,
    });
    let heard = rig.tap.heard();
    assert_eq!(heard[0].1.kind, UpdateType::LogOut);
    assert_eq!(heard[0].1.context, Some(id(8)));
    assert!(rig.heard.owners().is_empty());
}

#[tokio::test]
async fn a_personal_change_is_pushed_to_phones_through_bitwardens_relay() {
    let rig = rig(true).await;
    let ada = UserId::random();
    let (acting_device, push_uuid) = rig.devices.phone(ada, id(8));
    rig.notifier.publish(BwEvent::Cipher(cipher_event(
        ada,
        Some(Acting {
            device: acting_device,
            identifier: Some(id(8)),
        }),
    )));
    eventually(|| !rig.relay.sent.lock().expect("lock").is_empty()).await;
    let sent = rig.relay.sent.lock().expect("lock")[0].clone();
    assert_eq!(sent["userId"], json!(ada.0));
    assert_eq!(sent["type"], 0);
    assert_eq!(sent["deviceId"], json!(push_uuid));
    assert_eq!(sent["identifier"], json!(id(8)));
    assert_eq!(sent["payload"]["id"], json!(id(1)));
}

#[tokio::test]
async fn an_account_without_a_phone_gets_no_push() {
    let rig = rig(true).await;
    let ada = UserId::random();
    rig.notifier
        .publish(BwEvent::Cipher(cipher_event(ada, None)));
    // A second event that does push, so the test knows the first one had its chance.
    let grace = UserId::random();
    rig.devices.phone(grace, id(7));
    rig.notifier
        .publish(BwEvent::Cipher(cipher_event(grace, None)));
    eventually(|| !rig.relay.sent.lock().expect("lock").is_empty()).await;
    let sent = rig.relay.sent.lock().expect("lock").clone();
    assert_eq!(sent.len(), 1);
    assert_eq!(sent[0]["userId"], json!(grace.0));
}

#[tokio::test]
async fn an_organization_cipher_is_never_pushed() {
    let rig = rig(true).await;
    let ada = UserId::random();
    rig.devices.phone(ada, id(8));
    let mut event = cipher_event(ada, None);
    event.user = None;
    event.organization = Some(SpaceId::random());
    rig.notifier.publish(BwEvent::Cipher(event));
    // A push that does go out, after the one that must not.
    rig.notifier.publish(BwEvent::Folder(FolderEvent {
        change: Change::Created,
        id: id(2),
        user: ada,
        revision: AT,
        device: None,
    }));
    eventually(|| !rig.relay.sent.lock().expect("lock").is_empty()).await;
    let sent = rig.relay.sent.lock().expect("lock").clone();
    assert_eq!(sent.len(), 1);
    assert_eq!(sent[0]["type"], 7, "only the folder");
}

#[tokio::test]
async fn an_account_wide_push_leaves_the_identifier_out() {
    let rig = rig(true).await;
    let ada = UserId::random();
    let (acting_device, push_uuid) = rig.devices.phone(ada, id(8));
    rig.notifier.publish(BwEvent::Sync {
        sync: UserSync::Ciphers,
        user: ada,
        at: AT,
        device: Some(Acting {
            device: acting_device,
            identifier: Some(id(8)),
        }),
    });
    eventually(|| !rig.relay.sent.lock().expect("lock").is_empty()).await;
    let sent = rig.relay.sent.lock().expect("lock")[0].clone();
    assert_eq!(sent["type"], 4);
    assert_eq!(sent["deviceId"], json!(push_uuid));
    assert!(sent["identifier"].is_null());
}

#[tokio::test]
async fn without_a_relay_nothing_is_pushed_and_nothing_fails() {
    let rig = rig(false).await;
    let ada = UserId::random();
    rig.devices.phone(ada, id(8));
    rig.notifier
        .publish(BwEvent::Cipher(cipher_event(ada, None)));
    assert!(rig.relay.sent.lock().expect("lock").is_empty());
}
