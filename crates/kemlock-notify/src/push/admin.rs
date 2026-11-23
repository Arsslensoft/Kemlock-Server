//! [`PushRelayAdmin`]: Kemlock's push relay as the admin console turns it on and off.
//!
//! Turning it on is [`enable_relay`] (register with the relay, seal the key, store both) and
//! turning it off is [`disable_relay`] (ask the relay to erase the installation, forget it here
//! even when the relay can't be reached). The dispatcher reads the installation for every send,
//! so a change takes effect at once, with no restart.

use super::{EnableError, RelayClient, disable_relay, enable_relay};
use kemlock_app::admin::{AdminError, PushRelayControl, RelayStatus};
use kemlock_app::notices::BoxFuture;
use kemlock_app::ports::SecretSeal;
use kemlock_app::push::PushRepo;

/// The console's hold on the relay. Cheap to clone when its parts are.
#[derive(Clone)]
pub struct PushRelayAdmin<R, S> {
    repo: R,
    seal: S,
    client: RelayClient,
    url: String,
}

impl<R, S> std::fmt::Debug for PushRelayAdmin<R, S> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PushRelayAdmin")
            .field("url", &self.url)
            .finish_non_exhaustive()
    }
}

impl<R: PushRepo, S: SecretSeal> PushRelayAdmin<R, S> {
    /// `url` is the relay `client` talks to, shown in the console.
    pub fn new(repo: R, seal: S, client: RelayClient, url: impl Into<String>) -> Self {
        PushRelayAdmin {
            repo,
            seal,
            client,
            url: url.into(),
        }
    }

    async fn current(&self) -> Result<RelayStatus, AdminError> {
        let installation = self.repo.installation().await?;
        Ok(RelayStatus {
            enabled: installation.is_some(),
            installation_id: installation.map(|i| i.id),
            relay_url: self.url.clone(),
        })
    }
}

impl<R, S> PushRelayControl for PushRelayAdmin<R, S>
where
    R: PushRepo + 'static,
    S: SecretSeal + 'static,
{
    fn status(&self) -> BoxFuture<'_, Result<RelayStatus, AdminError>> {
        Box::pin(self.current())
    }

    fn enable(&self) -> BoxFuture<'_, Result<RelayStatus, AdminError>> {
        Box::pin(async move {
            if self.current().await?.enabled {
                return self.current().await;
            }
            match enable_relay(&self.repo, &self.seal, &self.client).await {
                Ok(id) => tracing::info!(installation = %id, "registered with the push relay"),
                Err(EnableError::Relay(error)) => {
                    tracing::warn!(%error, "couldn't register with the push relay");
                    return Err(AdminError::State(
                        "the push relay could not be reached, or refused the registration; try again later",
                    ));
                }
                Err(EnableError::Store(error)) => return Err(error.into()),
            }
            self.current().await
        })
    }

    fn disable(&self) -> BoxFuture<'_, Result<RelayStatus, AdminError>> {
        Box::pin(async move {
            if !self.current().await?.enabled {
                return self.current().await;
            }
            match disable_relay(&self.repo, &self.seal, &self.client).await {
                Ok(()) => {}
                // The installation is gone here, which is what the operator asked for; the relay
                // still holds a record it will age out.
                Err(EnableError::Relay(error)) => {
                    tracing::warn!(%error, "the push relay wasn't told it was turned off");
                }
                Err(EnableError::Store(error)) => return Err(error.into()),
            }
            self.current().await
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::{MemoryPush, TaggedSeal, serve};
    use axum::extract::{Path, State};
    use axum::http::StatusCode;
    use axum::routing::{delete, post};
    use axum::{Json, Router};
    use serde_json::json;
    use std::sync::{Arc, Mutex};

    /// A relay that registers installations and remembers which it was asked to erase.
    #[derive(Default)]
    struct Relay {
        registered: Mutex<usize>,
        erased: Mutex<Vec<String>>,
    }

    async fn register(State(relay): State<Arc<Relay>>) -> (StatusCode, Json<serde_json::Value>) {
        *relay.registered.lock().expect("lock") += 1;
        (
            StatusCode::CREATED,
            Json(json!({"installationId": "inst-1", "installationKey": "key-1"})),
        )
    }

    async fn erase(State(relay): State<Arc<Relay>>, Path(id): Path<String>) -> StatusCode {
        relay.erased.lock().expect("lock").push(id);
        StatusCode::NO_CONTENT
    }

    async fn admin() -> (
        Arc<Relay>,
        MemoryPush,
        PushRelayAdmin<MemoryPush, TaggedSeal>,
    ) {
        let relay = Arc::new(Relay::default());
        let app = Router::new()
            .route("/v1/installations", post(register))
            .route("/v1/installations/{id}", delete(erase))
            .with_state(relay.clone());
        let url = format!("http://{}", serve(app).await);
        let repo = MemoryPush::default();
        let admin = PushRelayAdmin::new(
            repo.clone(),
            TaggedSeal,
            RelayClient::new(&url).expect("client"),
            url,
        );
        (relay, repo, admin)
    }

    #[tokio::test]
    async fn a_server_that_has_not_registered_is_off() {
        let (_, _, admin) = admin().await;
        let status = admin.status().await.expect("reads");
        assert!(!status.enabled);
        assert_eq!(status.installation_id, None);
        assert!(status.relay_url.starts_with("http://127.0.0.1"));
    }

    #[tokio::test]
    async fn turning_it_on_registers_once_and_shows_the_id_but_not_the_key() {
        let (relay, repo, admin) = admin().await;
        let status = admin.enable().await.expect("enables");
        assert!(status.enabled);
        assert_eq!(status.installation_id.as_deref(), Some("inst-1"));
        assert!(!format!("{status:?}").contains("key-1"));
        assert!(repo.installation.lock().expect("lock").is_some());

        // Again: already on, no second registration.
        admin.enable().await.expect("stays on");
        assert_eq!(*relay.registered.lock().expect("lock"), 1);
        assert!(admin.status().await.expect("reads").enabled);
    }

    #[tokio::test]
    async fn turning_it_off_erases_at_the_relay_and_forgets_here() {
        let (relay, repo, admin) = admin().await;
        admin.enable().await.expect("enables");
        let status = admin.disable().await.expect("disables");
        assert!(!status.enabled);
        assert_eq!(
            *relay.erased.lock().expect("lock"),
            vec!["inst-1".to_owned()]
        );
        assert!(repo.installation.lock().expect("lock").is_none());

        // Off already: nothing more to erase.
        admin.disable().await.expect("stays off");
        assert_eq!(relay.erased.lock().expect("lock").len(), 1);
    }

    #[tokio::test]
    async fn a_relay_that_cannot_be_reached_keeps_it_off_and_says_why() {
        let address = {
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
                .await
                .expect("binds");
            listener.local_addr().expect("address")
        };
        let url = format!("http://{address}");
        let repo = MemoryPush::default();
        let admin = PushRelayAdmin::new(
            repo.clone(),
            TaggedSeal,
            RelayClient::new(&url).expect("client"),
            url,
        );
        assert!(matches!(
            admin.enable().await,
            Err(AdminError::State(why)) if why.contains("could not be reached")
        ));
        assert!(!admin.status().await.expect("reads").enabled);
    }

    #[tokio::test]
    async fn turning_it_off_works_when_the_relay_is_down() {
        let (_, repo, admin) = admin().await;
        admin.enable().await.expect("enables");
        // The relay of a console whose relay went away.
        let address = {
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
                .await
                .expect("binds");
            listener.local_addr().expect("address")
        };
        let url = format!("http://{address}");
        let down = PushRelayAdmin::new(
            repo.clone(),
            TaggedSeal,
            RelayClient::new(&url).expect("client"),
            url,
        );
        let status = down
            .disable()
            .await
            .expect("the operator is never stuck on");
        assert!(!status.enabled);
        assert!(repo.installation.lock().expect("lock").is_none());
    }
}
