//! The Bitwarden API's devices: identifier, device type and push registration, on SQLite always and
//! on PostgreSQL and MySQL when `KEMLOCK_TEST_POSTGRES_URL` / `KEMLOCK_TEST_MYSQL_URL` are set.

mod common;

use common::{device, external, memory, unique_email, user};
use kemlock_app::bw_events::{BwDeviceRepo, BwPushToken};
use kemlock_app::ports::{DeviceRepo, StoreError, UserRepo};
use kemlock_domain::DeviceId;
use kemlock_store_sql::SqlStore;
use time::macros::datetime;
use uuid::Uuid;

const AT: time::OffsetDateTime = datetime!(2026-11-25 10:00 UTC);

async fn identifiers_types_and_phones(store: &SqlStore) {
    let ada = user(&unique_email("ada"));
    let grace = user(&unique_email("grace"));
    UserRepo::insert(store, &ada).await.expect("ada");
    UserRepo::insert(store, &grace).await.expect("grace");
    let phone = device(ada.id, "Pixel", datetime!(2026-11-01 00:00 UTC));
    let laptop = device(ada.id, "Laptop", datetime!(2026-11-01 00:00 UTC));
    let other = device(grace.id, "Pixel", datetime!(2026-11-01 00:00 UTC));
    for d in [&phone, &laptop, &other] {
        DeviceRepo::upsert(store, d).await.expect("device");
    }
    let app_id = Uuid::new_v4();

    // Nothing is known of a device before it signs in to the Bitwarden API.
    assert_eq!(store.bw_device(phone.id).await.expect("reads"), None);
    assert_eq!(
        store
            .set_bw_push(
                phone.id,
                Some(BwPushToken {
                    push_uuid: Uuid::new_v4(),
                    token: "early".to_owned(),
                })
            )
            .await,
        Err(StoreError::NotFound)
    );

    store
        .note_bw_device(phone.id, ada.id, app_id, 0, AT)
        .await
        .expect("noted");
    store
        .note_bw_device(laptop.id, ada.id, Uuid::new_v4(), 9, AT)
        .await
        .expect("noted");
    // The same app signed in to a second account is a second row with the same identifier.
    store
        .note_bw_device(other.id, grace.id, app_id, 0, AT)
        .await
        .expect("noted");
    let known = store
        .bw_device(phone.id)
        .await
        .expect("reads")
        .expect("known");
    assert_eq!((known.identifier, known.device_type), (app_id, 0));
    assert!(known.push.is_none());
    assert_eq!(
        store
            .bw_devices_by_identifier(app_id)
            .await
            .expect("by identifier")
            .len(),
        2
    );

    // No phone yet.
    assert!(!store.bw_user_has_push(ada.id).await.expect("checks"));
    let push = BwPushToken {
        push_uuid: Uuid::new_v4(),
        token: "fcm-token".to_owned(),
    };
    store
        .set_bw_push(phone.id, Some(push.clone()))
        .await
        .expect("registers");
    assert!(store.bw_user_has_push(ada.id).await.expect("checks"));
    assert!(!store.bw_user_has_push(grace.id).await.expect("checks"));
    // Setting the same values again is fine.
    store
        .set_bw_push(phone.id, Some(push.clone()))
        .await
        .expect("registers again");

    // Signing in again keeps the registration and moves the type and time.
    store
        .note_bw_device(phone.id, ada.id, app_id, 15, AT + time::Duration::hours(1))
        .await
        .expect("noted again");
    let known = store
        .bw_device(phone.id)
        .await
        .expect("reads")
        .expect("known");
    assert_eq!(known.device_type, 15);
    assert_eq!(known.push, Some(push));

    // Clearing the token leaves the device known.
    store.set_bw_push(phone.id, None).await.expect("clears");
    assert!(!store.bw_user_has_push(ada.id).await.expect("checks"));
    assert!(store.bw_device(phone.id).await.expect("reads").is_some());

    // A device that doesn't exist can't be noted.
    assert_eq!(
        store
            .note_bw_device(DeviceId::random(), ada.id, app_id, 0, AT)
            .await,
        Err(StoreError::NotFound)
    );

    // Signing a device out takes its row with it.
    DeviceRepo::remove(store, phone.id).await.expect("sign out");
    assert_eq!(store.bw_device(phone.id).await.expect("reads"), None);
}

#[tokio::test]
async fn bitwarden_devices_on_sqlite() {
    identifiers_types_and_phones(&memory().await).await;
}

#[tokio::test]
async fn bitwarden_devices_on_external_backends() {
    for var in ["KEMLOCK_TEST_POSTGRES_URL", "KEMLOCK_TEST_MYSQL_URL"] {
        if let Some(store) = external(var).await {
            identifiers_types_and_phones(&store).await;
        }
    }
}
