//! Bitwarden's push relay, as Vaultwarden uses it (1.37.5, `src/api/push.rs`).
//!
//! An operator who wants Bitwarden's phone apps woken registers an installation at
//! <https://bitwarden.com/host> and sets `PUSH_ENABLED`, `PUSH_INSTALLATION_ID` and
//! `PUSH_INSTALLATION_KEY` (and, for the EU cloud, `PUSH_RELAY_URI` and `PUSH_IDENTITY_URI`).
//! The server gets a bearer token from Bitwarden's identity service with the installation as a
//! client (`client_credentials`, scope `api.push`), registers each phone's push token at the
//! relay, and sends it updates. Bitwarden is then the operator's processor for these pushes, on
//! its own terms; Kemlock's relay (`crate::push`) is separate.

use super::message::UpdateType;
use crate::push::RelayError;
use kemlock_app::bw_events::{BwDevice, BwRelay};
use kemlock_app::notices::BoxFuture;
use kemlock_app::ports::Zeroizing;
use serde::Deserialize;
use serde_json::{Value, json};
use std::time::Duration;
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;
use tokio::sync::Mutex;
use tokio::time::Instant;
use uuid::Uuid;

/// Bitwarden's US relay, Vaultwarden's default.
pub const DEFAULT_RELAY_URI: &str = "https://push.bitwarden.com";
/// Bitwarden's US identity service, Vaultwarden's default.
pub const DEFAULT_IDENTITY_URI: &str = "https://identity.bitwarden.com";

#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum PushConfigError {
    #[error("PUSH_ENABLED is true, but {0} is not set")]
    Missing(&'static str),
    #[error("{0} is not an https URL")]
    NotHttps(&'static str),
}

/// `PUSH_*` settings. The key stays out of `Debug` output.
#[derive(Clone)]
pub struct BitwardenPushConfig {
    pub installation_id: String,
    pub installation_key: Zeroizing<String>,
    pub relay_uri: String,
    pub identity_uri: String,
}

impl std::fmt::Debug for BitwardenPushConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BitwardenPushConfig")
            .field("installation_id", &self.installation_id)
            .field("relay_uri", &self.relay_uri)
            .field("identity_uri", &self.identity_uri)
            .finish_non_exhaustive()
    }
}

impl BitwardenPushConfig {
    /// Reads the settings through `get`. `Ok(None)` unless `PUSH_ENABLED` is true.
    pub fn from_lookup(
        get: &dyn Fn(&str) -> Option<String>,
    ) -> Result<Option<BitwardenPushConfig>, PushConfigError> {
        let non_empty = |name: &str| {
            get(name)
                .map(|v| v.trim().to_owned())
                .filter(|v| !v.is_empty())
        };
        let enabled = non_empty("PUSH_ENABLED").is_some_and(|v| {
            matches!(v.to_ascii_lowercase().as_str(), "true" | "1" | "yes" | "on")
        });
        if !enabled {
            return Ok(None);
        }
        let installation_id = non_empty("PUSH_INSTALLATION_ID")
            .ok_or(PushConfigError::Missing("PUSH_INSTALLATION_ID"))?;
        let installation_key = non_empty("PUSH_INSTALLATION_KEY")
            .ok_or(PushConfigError::Missing("PUSH_INSTALLATION_KEY"))?;
        let relay_uri = non_empty("PUSH_RELAY_URI")
            .unwrap_or_else(|| DEFAULT_RELAY_URI.to_owned())
            .trim_end_matches('/')
            .to_owned();
        let identity_uri = non_empty("PUSH_IDENTITY_URI")
            .unwrap_or_else(|| DEFAULT_IDENTITY_URI.to_owned())
            .trim_end_matches('/')
            .to_owned();
        // The key goes to both services: they must be https.
        if !(relay_uri.starts_with("https://") || relay_uri.starts_with("http://127.0.0.1")) {
            return Err(PushConfigError::NotHttps("PUSH_RELAY_URI"));
        }
        if !(identity_uri.starts_with("https://") || identity_uri.starts_with("http://127.0.0.1")) {
            return Err(PushConfigError::NotHttps("PUSH_IDENTITY_URI"));
        }
        Ok(Some(BitwardenPushConfig {
            installation_id,
            installation_key: Zeroizing::new(installation_key),
            relay_uri,
            identity_uri,
        }))
    }
}

/// A phone to register with the relay.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BwPushDevice {
    /// The id the relay knows the device by; `None` the first time (one is made).
    pub push_uuid: Option<Uuid>,
    pub push_token: String,
    pub user: Uuid,
    /// Bitwarden's device type number.
    pub device_type: i32,
    /// The device's own identifier (the `deviceIdentifier` it signs in with).
    pub identifier: Uuid,
}

/// A push to send.
#[derive(Clone, Debug, PartialEq)]
pub struct BwPush {
    pub user: Uuid,
    /// The relay's id for the device to skip or target; `None` for every device of the account.
    pub device_push_uuid: Option<Uuid>,
    /// The device that made the change (the app ignores a push for its own change).
    pub identifier: Option<Uuid>,
    pub kind: UpdateType,
    pub payload: Value,
}

fn rfc3339(at: OffsetDateTime) -> String {
    at.format(&Rfc3339).unwrap_or_default()
}

impl BwPush {
    /// The account's data changed (`SyncVault`, `SyncSettings`, `SyncOrgKeys`, `SyncCiphers`).
    pub fn user_update(kind: UpdateType, user: Uuid, at: OffsetDateTime) -> BwPush {
        BwPush {
            user,
            device_push_uuid: None,
            identifier: None,
            kind,
            payload: json!({"userId": user, "date": rfc3339(at)}),
        }
    }

    /// The account's sessions ended.
    pub fn logout(user: Uuid, identifier: Option<Uuid>, at: OffsetDateTime) -> BwPush {
        BwPush {
            identifier,
            ..BwPush::user_update(UpdateType::LogOut, user, at)
        }
    }

    /// A personal cipher changed. Vaultwarden sends none for an organisation's.
    pub fn cipher(
        kind: UpdateType,
        id: Uuid,
        user: Uuid,
        revision: OffsetDateTime,
        identifier: Option<Uuid>,
    ) -> BwPush {
        BwPush {
            user,
            device_push_uuid: None,
            identifier,
            kind,
            payload: json!({
                "id": id,
                "userId": user,
                "organizationId": null,
                "collectionIds": null,
                "revisionDate": rfc3339(revision),
            }),
        }
    }

    /// A folder changed.
    pub fn folder(
        kind: UpdateType,
        id: Uuid,
        user: Uuid,
        revision: OffsetDateTime,
        identifier: Option<Uuid>,
    ) -> BwPush {
        BwPush {
            user,
            device_push_uuid: None,
            identifier,
            kind,
            payload: json!({"id": id, "userId": user, "revisionDate": rfc3339(revision)}),
        }
    }

    /// A Send changed (Vaultwarden's `push_send_update`).
    pub fn send(kind: UpdateType, id: Uuid, user: Uuid, revision: OffsetDateTime) -> BwPush {
        BwPush {
            user,
            device_push_uuid: None,
            identifier: None,
            kind,
            payload: json!({"id": id, "userId": user, "revisionDate": rfc3339(revision)}),
        }
    }

    /// The same push made by one phone: the relay doesn't send it back to the device with this
    /// relay id and identifier.
    #[must_use]
    pub fn from_device(
        mut self,
        device_push_uuid: Option<Uuid>,
        identifier: Option<Uuid>,
    ) -> BwPush {
        self.device_push_uuid = device_push_uuid;
        self.identifier = identifier;
        self
    }

    /// A login request was made (`AuthRequest`) or answered (`AuthRequestResponse`).
    pub fn auth_request(
        kind: UpdateType,
        id: Uuid,
        user: Uuid,
        device_push_uuid: Option<Uuid>,
        identifier: Option<Uuid>,
    ) -> BwPush {
        BwPush {
            user,
            device_push_uuid,
            identifier,
            kind,
            payload: json!({"userId": user, "id": id}),
        }
    }

    /// The body of `POST /push/send`.
    fn body(&self) -> Value {
        json!({
            "userId": self.user,
            "organizationId": null,
            "deviceId": self.device_push_uuid,
            "identifier": self.identifier,
            "type": self.kind.code(),
            "payload": self.payload,
            "clientType": null,
            "installationId": null,
        })
    }
}

#[derive(Debug, Deserialize)]
struct TokenResponse {
    access_token: String,
    expires_in: i64,
}

/// The relay's client. Cheap to share behind an `Arc`.
pub struct BitwardenPush {
    http: reqwest::Client,
    config: BitwardenPushConfig,
    /// The bearer token and when to fetch another: half of its lifetime, as Vaultwarden does.
    token: Mutex<Option<(String, Instant)>>,
}

impl std::fmt::Debug for BitwardenPush {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BitwardenPush")
            .field("config", &self.config)
            .finish_non_exhaustive()
    }
}

impl BitwardenPush {
    pub fn new(config: BitwardenPushConfig) -> Result<BitwardenPush, RelayError> {
        let http = reqwest::Client::builder()
            .timeout(Duration::from_secs(10))
            .user_agent(concat!("kemlock-server/", env!("CARGO_PKG_VERSION")))
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .map_err(|e| RelayError::Transport(e.to_string()))?;
        Ok(BitwardenPush {
            http,
            config,
            token: Mutex::new(None),
        })
    }

    /// A bearer token for the relay, from the identity service, cached for half its lifetime.
    async fn bearer(&self) -> Result<String, RelayError> {
        let mut cached = self.token.lock().await;
        if let Some((token, renew_at)) = cached.as_ref()
            && Instant::now() < *renew_at
        {
            return Ok(token.clone());
        }
        let response = self
            .http
            .post(format!("{}/connect/token", self.config.identity_uri))
            .form(&[
                ("grant_type", "client_credentials"),
                ("scope", "api.push"),
                (
                    "client_id",
                    format!("installation.{}", self.config.installation_id).as_str(),
                ),
                ("client_secret", self.config.installation_key.as_str()),
            ])
            .send()
            .await
            .map_err(|e| RelayError::Transport(e.to_string()))?;
        match response.status().as_u16() {
            200..=299 => {}
            401 | 403 => return Err(RelayError::Unauthorized),
            other => return Err(RelayError::Status(other)),
        }
        let issued: TokenResponse = response
            .json()
            .await
            .map_err(|e| RelayError::Transport(e.to_string()))?;
        let half = u64::try_from(issued.expires_in / 2).unwrap_or(0);
        *cached = Some((
            issued.access_token.clone(),
            Instant::now() + Duration::from_secs(half),
        ));
        Ok(issued.access_token)
    }

    async fn post(&self, path: &str, body: &Value) -> Result<(), RelayError> {
        let token = self.bearer().await?;
        let response = self
            .http
            .post(format!("{}{path}", self.config.relay_uri))
            .bearer_auth(token)
            .header(reqwest::header::ACCEPT, "application/json")
            .json(body)
            .send()
            .await
            .map_err(|e| RelayError::Transport(e.to_string()))?;
        match response.status().as_u16() {
            200..=299 => Ok(()),
            401 | 403 => {
                // The token may have been revoked: fetch a new one next time.
                *self.token.lock().await = None;
                Err(RelayError::Unauthorized)
            }
            other => Err(RelayError::Status(other)),
        }
    }

    /// Registers a phone: `POST /push/register`. Returns the id the relay knows it by (made here
    /// when the device had none), for the caller to store with the device.
    pub async fn register_device(&self, device: &BwPushDevice) -> Result<Uuid, RelayError> {
        let push_uuid = device.push_uuid.unwrap_or_else(Uuid::new_v4);
        self.post(
            "/push/register",
            &json!({
                "deviceId": push_uuid,
                "pushToken": device.push_token,
                "userId": device.user,
                "type": device.device_type,
                "identifier": device.identifier,
                "installationId": self.config.installation_id,
            }),
        )
        .await?;
        Ok(push_uuid)
    }

    /// Forgets a phone: `POST /push/delete`.
    pub async fn unregister_device(&self, push_uuid: Uuid) -> Result<(), RelayError> {
        self.post("/push/delete", &json!({"id": push_uuid})).await
    }

    /// Sends an update: `POST /push/send`.
    pub async fn send(&self, push: &BwPush) -> Result<(), RelayError> {
        self.post("/push/send", &push.body()).await
    }
}

/// The device routes register and forget phones through this.
impl BwRelay for BitwardenPush {
    fn register<'a>(&'a self, device: &'a BwDevice) -> BoxFuture<'a, Result<(), String>> {
        Box::pin(async move {
            let Some(push) = &device.push else {
                return Err("the device has no push token".to_owned());
            };
            self.register_device(&BwPushDevice {
                push_uuid: Some(push.push_uuid),
                push_token: push.token.clone(),
                user: device.user.0,
                device_type: device.device_type,
                identifier: device.identifier,
            })
            .await
            .map(|_| ())
            .map_err(|error| error.to_string())
        })
    }

    fn unregister(&self, push_uuid: Uuid) -> BoxFuture<'_, Result<(), String>> {
        Box::pin(async move {
            self.unregister_device(push_uuid)
                .await
                .map_err(|error| error.to_string())
        })
    }
}

#[cfg(test)]
mod tests;
