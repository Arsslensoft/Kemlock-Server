//! One device on both APIs, and the Bitwarden API's own last-use column.

mod common;

use axum::http::StatusCode;
use common::{HASH, Harness, claims};
use kemlock_app::api_use::ApiUseRepo;
use kemlock_app::devices::bitwarden_device_id;
use kemlock_app::ports::DeviceRepo;
use kemlock_domain::api_use::ApiKind;
use kemlock_domain::{Device, DeviceId, DeviceKind};
use time::Duration;

/// The identifier `Harness::password_fields` sends.
const IDENTIFIER: &str = "6a3c5f2e-9d1b-4c7e-8a40-0f9e7d6c5b4a";

#[tokio::test]
async fn a_sign_in_and_each_authenticated_request_record_a_bitwarden_use() {
    let h = Harness::new().await;
    h.account("ada@example.com", HASH).await;
    let body = h.login("ada@example.com", HASH).await;
    let token = body["access_token"].as_str().expect("a token").to_owned();
    let device = DeviceId(
        claims(&token, h.env.time().unix_timestamp())
            .device
            .parse()
            .expect("a device id"),
    );

    let signed_in = h.env.time();
    let usage = h.store.uses_of(&[device]).await.expect("reads");
    assert_eq!(usage.len(), 1);
    assert_eq!(usage[0].bitwarden, Some(signed_in));
    assert_eq!(usage[0].kemlock, None, "the Kemlock column is not touched");

    h.env.advance(Duration::minutes(5));
    let (status, _) = h
        .json("GET", "/api/accounts/revision-date", Some(&token), None)
        .await;
    assert_eq!(status, StatusCode::OK);
    let usage = h.store.uses_of(&[device]).await.expect("reads");
    assert_eq!(usage[0].bitwarden, Some(h.env.time()));
}

#[tokio::test]
async fn a_request_inside_the_granularity_leaves_the_use_where_it_was() {
    let h = Harness::new().await;
    h.account("ada@example.com", HASH).await;
    let body = h.login("ada@example.com", HASH).await;
    let token = body["access_token"].as_str().expect("a token").to_owned();
    let device = DeviceId(
        claims(&token, h.env.time().unix_timestamp())
            .device
            .parse()
            .expect("a device id"),
    );
    let signed_in = h.env.time();

    h.env.advance(Duration::seconds(20));
    let (status, _) = h
        .json("GET", "/api/accounts/revision-date", Some(&token), None)
        .await;
    assert_eq!(status, StatusCode::OK);
    let usage = h.store.uses_of(&[device]).await.expect("reads");
    assert_eq!(usage[0].bitwarden, Some(signed_in));
}

#[tokio::test]
async fn the_kemlock_apis_device_is_the_row_a_bitwarden_sign_in_finds() {
    let h = Harness::new().await;
    let user = h.account("ada@example.com", HASH).await;
    let now = h.env.time();

    // What the Kemlock API wrote when the phone signed in there with its Vaultwarden identifier:
    // the id the Bitwarden API makes from it, and a DPoP key.
    let id = bitwarden_device_id(kemlock_crypto::hash::sha256, user, IDENTIFIER);
    DeviceRepo::upsert(
        &h.store,
        &Device {
            id,
            user,
            name: "Kemlock on Pixel".to_owned(),
            kind: DeviceKind::KemlockAndroid,
            dpop_jkt: Some("kemlock-jkt".to_owned()),
            created_at: now,
            last_seen_at: now,
        },
    )
    .await
    .expect("the Kemlock API's device");
    h.store
        .record_use(id, ApiKind::Kemlock, now)
        .await
        .expect("a Kemlock use");

    h.env.advance(Duration::minutes(5));
    let body = h.login("ada@example.com", HASH).await;
    let token = body["access_token"].as_str().expect("a token");
    assert_eq!(
        claims(token, h.env.time().unix_timestamp()).device,
        id.to_string(),
        "the Bitwarden API signs in to the same device"
    );

    let devices = DeviceRepo::list(&h.store, user).await.expect("lists");
    assert_eq!(devices.len(), 1, "one phone is one device");
    assert_eq!(
        devices[0].dpop_jkt.as_deref(),
        Some("kemlock-jkt"),
        "the Kemlock API's key is kept"
    );
    let usage = h.store.uses_of(&[id]).await.expect("reads");
    assert_eq!(usage[0].kemlock, Some(now), "each API keeps its own column");
    assert_eq!(usage[0].bitwarden, Some(h.env.time()));
}
