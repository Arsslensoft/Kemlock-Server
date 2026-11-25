//! Push tokens of Bitwarden's phone apps: `PUT /api/devices/identifier/{id}/token` and the
//! `clear-token` routes, as Vaultwarden 1.37.5 has them (`src/api/core/accounts.rs`, `push.rs`).
//!
//! The server registers a phone with Bitwarden's push relay when the operator set one up
//! (`PUSH_ENABLED` with an installation id and key), and keeps the relay's id for it with the
//! device (`bw_devices`). Without a relay the routes answer 200 and keep nothing: there is nothing
//! a token could be used for.

use crate::app::{App, Authed, BwStore};
use crate::error::{BwError, BwResult};
use crate::routes::{EmptyResult, Peer, empty, parse};
use axum::Router;
use axum::body::Bytes;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::routing::put;
use kemlock_app::bw_events::{BwDevice, BwDeviceRepo, BwPushToken, is_push_device};
use kemlock_domain::DeviceKind;
use serde::Deserialize;
use uuid::Uuid;

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct PushToken {
    push_token: String,
}

/// The Bitwarden device type a session without a recorded one is taken to have: what its kind
/// says, which tells the phones (the only devices with a push token) apart.
fn type_of_kind(kind: DeviceKind) -> i32 {
    match kind {
        DeviceKind::KemlockAndroid => 0,
        DeviceKind::KemlockIos => 1,
        _ => 14,
    }
}

/// The signed-in device's row; made from the request when the session began before the server
/// kept one.
async fn device_of<S: BwStore>(
    app: &App<S>,
    authed: &Authed,
    identifier: &str,
) -> BwResult<BwDevice> {
    if let Some(known) = BwDeviceRepo::bw_device(&app.store, authed.device.id).await? {
        return Ok(known);
    }
    let identifier = authed
        .identifier
        .or_else(|| Uuid::parse_str(identifier.trim()).ok())
        .ok_or_else(|| {
            BwError::msg(format!(
                "Error: device {identifier} should be present before a token can be assigned"
            ))
        })?;
    let device_type = type_of_kind(authed.device.kind);
    BwDeviceRepo::note_bw_device(
        &app.store,
        authed.device.id,
        authed.user.id,
        identifier,
        device_type,
        app.now(),
    )
    .await?;
    Ok(BwDevice {
        device: authed.device.id,
        user: authed.user.id,
        identifier,
        device_type,
        push: None,
        updated_at: app.now(),
    })
}

/// `PUT` and `POST /api/devices/identifier/{id}/token`.
pub(crate) async fn put_token<S: BwStore>(
    app: &App<S>,
    authed: &Authed,
    identifier: &str,
    token: &str,
) -> BwResult<()> {
    let Some(relay) = app.relay.as_ref().filter(|relay| relay.enabled()) else {
        return Ok(());
    };
    let device = device_of(app, authed, identifier).await?;
    // Only phones have a push token; the apps of other kinds never send one.
    if !is_push_device(device.device_type) {
        return Ok(());
    }
    // The same token again is already registered.
    if device.push.as_ref().is_some_and(|p| p.token == token) {
        return Ok(());
    }
    let push_uuid = device
        .push
        .as_ref()
        .map_or_else(Uuid::new_v4, |p| p.push_uuid);
    let registered = BwDevice {
        push: Some(BwPushToken {
            push_uuid,
            token: token.to_owned(),
        }),
        ..device
    };
    relay.register(&registered).await.map_err(|error| {
        tracing::warn!(%error, "Bitwarden's push relay did not take a device");
        BwError::msg(format!(
            "An error occurred while proceeding registration of a device: {error}"
        ))
    })?;
    BwDeviceRepo::set_bw_push(&app.store, registered.device, registered.push).await?;
    Ok(())
}

/// `PUT` and `POST /api/devices/identifier/{id}/clear-token`: forgets the phones that sign in
/// with this identifier, at the relay and here. Vaultwarden has no sign-in for it either.
pub(crate) async fn clear_token<S: BwStore>(app: &App<S>, identifier: &str) -> BwResult<()> {
    let Some(relay) = app.relay.as_ref().filter(|relay| relay.enabled()) else {
        return Ok(());
    };
    let Ok(identifier) = Uuid::parse_str(identifier.trim()) else {
        return Ok(());
    };
    for device in BwDeviceRepo::bw_devices_by_identifier(&app.store, identifier).await? {
        let Some(push) = device.push else {
            continue;
        };
        BwDeviceRepo::set_bw_push(&app.store, device.device, None).await?;
        relay.unregister(push.push_uuid).await.map_err(|error| {
            tracing::warn!(%error, "Bitwarden's push relay did not forget a device");
            BwError::msg(format!(
                "An error occurred during device unregistration: {error}"
            ))
        })?;
    }
    Ok(())
}

async fn put_device_token<S: BwStore>(
    State(app): State<App<S>>,
    authed: Authed,
    Path(identifier): Path<String>,
    body: Bytes,
) -> EmptyResult {
    let data: PushToken = parse(&body)?;
    empty(put_token(&app, &authed, &identifier, &data.push_token).await)
}

async fn clear_device_token<S: BwStore>(
    State(app): State<App<S>>,
    Peer(ip): Peer,
    Path(identifier): Path<String>,
) -> EmptyResult {
    // No sign-in guards this route, so a client address gets Vaultwarden's unauthenticated limit
    // (`check_limit_unauthenticated`, which is not the login one): a burst of 50, then one request a
    // minute. Without it the identifiers of phones could be tried as fast as it answers.
    app.unauthenticated_limit
        .check(ip, app.now_secs())
        .map_err(|_| BwError::status(StatusCode::TOO_MANY_REQUESTS, "Too many requests"))?;
    empty(clear_token(&app, &identifier).await)
}

pub(crate) fn routes<S: BwStore>() -> Router<App<S>> {
    Router::new()
        .route(
            "/api/devices/identifier/{id}/token",
            put(put_device_token::<S>).post(put_device_token::<S>),
        )
        .route(
            "/api/devices/identifier/{id}/clear-token",
            put(clear_device_token::<S>).post(clear_device_token::<S>),
        )
}
