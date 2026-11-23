//! Kemlock's push relay, from the server's side.
//!
//! The relay is a separate hosted service (see `docs/push-relay.md` for its small HTTP contract).
//! An operator who opts in registers the server once and gets an installation id and key; from
//! then on, when a commit nudges an owner, the server sends the relay "sync now" for the push
//! tokens of that owner's devices. The relay sees only those tokens, the installation id and the
//! nudge: no email, account id or item.

mod admin;
mod dispatch;

pub use admin::PushRelayAdmin;
pub use dispatch::{DEFAULT_WINDOW, PushDispatcher};

use kemlock_app::ports::{SecretSeal, StoreError, Zeroizing};
use kemlock_app::push::{PURPOSE_PUSH_INSTALLATION_KEY, PushInstallation, PushKind, PushRepo};
use serde::{Deserialize, Serialize};
use std::time::Duration;

/// Where Kemlock runs the relay unless `KEMLOCK_PUSH_RELAY_URL` says otherwise.
pub const DEFAULT_RELAY_URL: &str = "https://push.kemlock.app";

/// The most tokens one send carries; more go in further sends.
pub const MAX_TOKENS_PER_SEND: usize = 500;

#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum RelayError {
    /// The URL is not one the server may send credentials to.
    #[error("the relay URL must be https (or loopback http)")]
    BadUrl,
    /// The relay couldn't be reached or answered nonsense.
    #[error("couldn't reach the push relay: {0}")]
    Transport(String),
    /// The installation id or key was refused: register again.
    #[error("the push relay refused this installation")]
    Unauthorized,
    /// Too many sends; try again after this many seconds.
    #[error("the push relay asks to slow down ({0} s)")]
    SlowDown(u64),
    /// Any other answer.
    #[error("the push relay answered {0}")]
    Status(u16),
}

/// The server's registration with the relay. The key stays out of `Debug` output.
#[derive(Clone)]
pub struct Installation {
    pub id: String,
    pub key: Zeroizing<String>,
}

impl std::fmt::Debug for Installation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Installation")
            .field("id", &self.id)
            .finish_non_exhaustive()
    }
}

/// A device to wake.
#[derive(Clone, PartialEq, Eq)]
pub struct PushTarget {
    pub kind: PushKind,
    pub token: String,
}

impl std::fmt::Debug for PushTarget {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PushTarget")
            .field("kind", &self.kind)
            .finish_non_exhaustive()
    }
}

/// What a send did.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct SendOutcome {
    /// How many tokens the relay took.
    pub accepted: usize,
    /// Tokens the push services no longer know: forget them.
    pub rejected: Vec<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct Registered {
    installation_id: String,
    installation_key: String,
}

#[derive(Debug, Serialize)]
struct TokenBody<'a> {
    kind: &'static str,
    token: &'a str,
}

#[derive(Debug, Serialize)]
struct SendBody<'a> {
    #[serde(rename = "type")]
    kind: &'static str,
    tokens: Vec<TokenBody<'a>>,
}

#[derive(Debug, Deserialize)]
struct SendResponse {
    accepted: usize,
    #[serde(default)]
    rejected: Vec<String>,
}

/// The relay's HTTP client. Cheap to clone.
#[derive(Clone, Debug)]
pub struct RelayClient {
    http: reqwest::Client,
    base: String,
}

fn allowed_url(url: &str) -> bool {
    url.starts_with("https://")
        || url.starts_with("http://127.0.0.1")
        || url.starts_with("http://localhost")
        || url.starts_with("http://[::1]")
}

impl RelayClient {
    /// A client for the relay at `base_url`. The installation key travels with every send, so
    /// the URL must be https; plain http is accepted only for the loopback address, for tests
    /// and for a relay behind a local proxy.
    pub fn new(base_url: &str) -> Result<Self, RelayError> {
        let base = base_url.trim().trim_end_matches('/').to_owned();
        if !allowed_url(&base) {
            return Err(RelayError::BadUrl);
        }
        let http = reqwest::Client::builder()
            .timeout(Duration::from_secs(10))
            .user_agent(concat!("kemlock-server/", env!("CARGO_PKG_VERSION")))
            // A redirect would carry the credentials somewhere the operator never chose.
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .map_err(|e| RelayError::Transport(e.to_string()))?;
        Ok(RelayClient { http, base })
    }

    fn url(&self, path: &str) -> String {
        format!("{}{path}", self.base)
    }

    fn failure(response: &reqwest::Response) -> RelayError {
        match response.status().as_u16() {
            401 | 403 => RelayError::Unauthorized,
            429 => {
                let seconds = response
                    .headers()
                    .get(reqwest::header::RETRY_AFTER)
                    .and_then(|v| v.to_str().ok())
                    .and_then(|v| v.trim().parse::<u64>().ok())
                    .unwrap_or(60);
                RelayError::SlowDown(seconds)
            }
            other => RelayError::Status(other),
        }
    }

    /// Registers this server with the relay: `POST /v1/installations`. Nothing is sent but the
    /// request itself, so the relay learns the server's address and the time, as any web service
    /// does.
    pub async fn register_installation(&self) -> Result<Installation, RelayError> {
        let response = self
            .http
            .post(self.url("/v1/installations"))
            .json(&serde_json::json!({}))
            .send()
            .await
            .map_err(|e| RelayError::Transport(e.to_string()))?;
        if !response.status().is_success() {
            return Err(Self::failure(&response));
        }
        let registered: Registered = response
            .json()
            .await
            .map_err(|e| RelayError::Transport(e.to_string()))?;
        Ok(Installation {
            id: registered.installation_id,
            key: Zeroizing::new(registered.installation_key),
        })
    }

    /// Sends "sync now" to these devices: `POST /v1/push`, in sends of at most
    /// [`MAX_TOKENS_PER_SEND`] tokens. Stops at the first failed send.
    pub async fn send_sync(
        &self,
        installation: &Installation,
        targets: &[PushTarget],
    ) -> Result<SendOutcome, RelayError> {
        let mut outcome = SendOutcome::default();
        for chunk in targets.chunks(MAX_TOKENS_PER_SEND) {
            let body = SendBody {
                kind: "sync",
                tokens: chunk
                    .iter()
                    .map(|t| TokenBody {
                        kind: t.kind.as_str(),
                        token: &t.token,
                    })
                    .collect(),
            };
            let response = self
                .http
                .post(self.url("/v1/push"))
                .basic_auth(&installation.id, Some(installation.key.as_str()))
                .json(&body)
                .send()
                .await
                .map_err(|e| RelayError::Transport(e.to_string()))?;
            if !response.status().is_success() {
                return Err(Self::failure(&response));
            }
            let sent: SendResponse = response
                .json()
                .await
                .map_err(|e| RelayError::Transport(e.to_string()))?;
            outcome.accepted += sent.accepted;
            outcome.rejected.extend(sent.rejected);
        }
        Ok(outcome)
    }

    /// Erases this installation at the relay: `DELETE /v1/installations/{id}`. Already gone
    /// counts as done.
    pub async fn delete_installation(&self, installation: &Installation) -> Result<(), RelayError> {
        let response = self
            .http
            .delete(self.url(&format!("/v1/installations/{}", installation.id)))
            .basic_auth(&installation.id, Some(installation.key.as_str()))
            .send()
            .await
            .map_err(|e| RelayError::Transport(e.to_string()))?;
        match response.status().as_u16() {
            200..=299 | 404 => Ok(()),
            _ => Err(Self::failure(&response)),
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum EnableError {
    #[error(transparent)]
    Relay(#[from] RelayError),
    #[error(transparent)]
    Store(#[from] StoreError),
}

/// Opts in to the relay: registers the server, seals the key under `server.key` and stores both.
/// Nothing is typed by the operator.
pub async fn enable_relay<R: PushRepo, S: SecretSeal>(
    repo: &R,
    seal: &S,
    client: &RelayClient,
) -> Result<String, EnableError> {
    let installation = client.register_installation().await?;
    let sealed_key = seal.seal(PURPOSE_PUSH_INSTALLATION_KEY, installation.key.as_bytes());
    repo.set_installation(&PushInstallation {
        id: installation.id.clone(),
        sealed_key,
    })
    .await?;
    Ok(installation.id)
}

/// Opts out: asks the relay to erase the installation, then forgets it here. The local copy goes
/// even when the relay can't be reached, so the operator is never stuck opted in.
pub async fn disable_relay<R: PushRepo, S: SecretSeal>(
    repo: &R,
    seal: &S,
    client: &RelayClient,
) -> Result<(), EnableError> {
    let outcome = match open_installation(repo, seal).await? {
        Some(installation) => client.delete_installation(&installation).await,
        None => Ok(()),
    };
    repo.clear_installation().await?;
    Ok(outcome?)
}

/// The stored installation with its key opened, or `None` when the server hasn't registered (or
/// the key can't be opened, which means `server.key` changed: register again).
pub(crate) async fn open_installation<R: PushRepo, S: SecretSeal>(
    repo: &R,
    seal: &S,
) -> Result<Option<Installation>, StoreError> {
    let Some(stored) = repo.installation().await? else {
        return Ok(None);
    };
    let Ok(bytes) = seal.open(PURPOSE_PUSH_INSTALLATION_KEY, &stored.sealed_key) else {
        tracing::warn!("the push installation key can't be opened; register with the relay again");
        return Ok(None);
    };
    let Ok(key) = std::str::from_utf8(&bytes) else {
        return Ok(None);
    };
    Ok(Some(Installation {
        id: stored.id,
        key: Zeroizing::new(key.to_owned()),
    }))
}

#[cfg(test)]
mod tests;
