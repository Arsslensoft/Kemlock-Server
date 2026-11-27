//! Wires federation: this server's identity on disk, the replication engine over the store, the
//! per-peer replication job, the pairing and admin routes, and what the Kemlock API reads of it.
//!
//! The `/fed/v1` routes (the signed descriptor, the peer session and the two public pairing
//! routes) and `/admin/v1/federation` are served from the state built here. The identity key and
//! KEM keys are sealed under `server.key` in the data folder. [`wire`] is generic over the
//! [`Connector`] that opens sessions to peers, so the gate test runs three servers in one process
//! over channels; [`production`] is the WebSocket client.

use crate::app::RunError;
use crate::config::Config;
use crate::jobs::holder_name;
use axum::Router;
use axum::extract::{ConnectInfo, FromRequestParts};
use axum::http::request::Parts;
use axum::http::{Request, StatusCode};
use kemlock_api_fed::{
    AdminActor, AdminGate, AdminState, FedEvent, FedState, FileRotator, GateRefusal, HomeGate,
    IdentityParams, admin_router, default_suites, load_or_create, pair_router, refresh_due,
};
use kemlock_api_kem::extract::Authed;
use kemlock_api_kem::{Api, JwsTokenSigner};
use kemlock_app::admin::StepUp;
use kemlock_app::federation_view::{
    BoxFut, CancelOutcome, FederationView, PeerHealthView, PeerStatus, ResumeOutcome, ServerEntry,
    ServerRole, SharedView, SiblingSet, VaultServers, WaitingChanges,
};
use kemlock_app::ports::{Event, EventLog, ServerInfo, StoreError, Zeroizing};
use kemlock_crypto::seal::ServerSeal;
use kemlock_domain::{ItemId, Owner, ServerId, UserId};
use kemlock_federation::blobs::{BlobFetcher, BlobFiles, StoreFiles};
use kemlock_federation::home::Policy;
use kemlock_federation::job::PeerBlobFetcher;
use kemlock_federation::net::Http;
use kemlock_federation::outbox::Withholding;
use kemlock_federation::ports::{PeerRepo, ReplicaStore, VaultRepo};
use kemlock_federation::{
    Connector, FedAdminRepo, Federation, HealthConfig, HttpLink, MemberStore, PairingLink,
    Pairings, PeerRunner, Replica, ServerProfile, WsConnector, unix_now,
};
use kemlock_store_sql::SqlStore;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;
use tokio::sync::mpsc::UnboundedReceiver;

/// The operator name in the descriptor until the admin console sets one.
const DEFAULT_OPERATOR: &str = "Kemlock Server";
/// How often the running server checks whether its descriptor is due for a refresh.
const REFRESH_CHECK: Duration = Duration::from_secs(60 * 60);
/// How recently an admin must have signed in (not merely refreshed) to count as fresh: a recent
/// sign-in stands in for a step-up check where one is not asked for outright.
const FRESH_SECS: i64 = 300;

/// What the server runs for federation in the background, behind one handle the application and
/// the gate test hold.
pub trait Replication: Send + Sync {
    /// Visits every peer that is due. Returns how many it visited.
    fn tick(&self) -> BoxFut<'_, usize>;
    /// A peer showed it has more: visit it soon.
    fn mark_dirty(&self, peer: ServerId);
    /// Starts the replication loop, the pump of events from the `/fed/v1` routes and the
    /// descriptor refresh. The tasks end when the handles are aborted.
    fn spawn(&self) -> Vec<tokio::task::JoinHandle<()>>;
}

struct Running<C> {
    runner: Arc<PeerRunner<SqlStore, C>>,
    replica: Arc<Replica<SqlStore>>,
    events: Mutex<Option<UnboundedReceiver<FedEvent>>>,
    folder: PathBuf,
    key: Zeroizing<[u8; 32]>,
    params: IdentityParams,
}

impl<C: Connector + 'static> Replication for Running<C> {
    fn tick(&self) -> BoxFut<'_, usize> {
        Box::pin(async move { self.runner.tick(unix_now()).await.len() })
    }

    fn mark_dirty(&self, peer: ServerId) {
        self.runner.mark_dirty(peer);
    }

    fn spawn(&self) -> Vec<tokio::task::JoinHandle<()>> {
        let mut handles = vec![
            tokio::spawn(self.runner.clone().run()),
            tokio::spawn(self.runner.clone().run_probes()),
        ];
        let events = self
            .events
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .take();
        if let Some(mut events) = events {
            let runner = self.runner.clone();
            handles.push(tokio::spawn(async move {
                while let Some(event) = events.recv().await {
                    if let FedEvent::Nudge { peer, .. } = event {
                        runner.mark_dirty(peer);
                    }
                }
            }));
        }
        let replica = self.replica.clone();
        let folder = self.folder.clone();
        let key = *self.key;
        let params = self.params.clone();
        handles.push(tokio::spawn(async move {
            let mut every = tokio::time::interval(REFRESH_CHECK);
            loop {
                every.tick().await;
                refresh(&replica, &folder, &key, &params);
            }
        }));
        handles
    }
}

/// Signs the descriptor afresh (and rotates the KEM key at 30 days) when it is due.
fn refresh(
    replica: &Replica<SqlStore>,
    folder: &std::path::Path,
    key: &[u8; 32],
    params: &IdentityParams,
) {
    let now = unix_now();
    let current = replica.identity();
    if !refresh_due(&current, now) {
        return;
    }
    match load_or_create(folder, &ServerSeal::new(key), current.server, params, now) {
        Ok(identity) => match replica.replace_identity(Arc::new(identity)) {
            Ok(()) => tracing::info!("the federation descriptor was signed afresh"),
            Err(e) => tracing::warn!(error = %e, "the refreshed federation identity was refused"),
        },
        Err(e) => tracing::warn!(error = %e, "couldn't refresh the federation descriptor"),
    }
}

/// Everything [`wire`] makes.
pub struct Federated {
    /// The routes: `/fed/v1` (descriptor, session, pairing) and `/admin/v1/federation`.
    pub router: Router,
    /// What the Kemlock API reads: layer it on the router as a request extension.
    pub view: SharedView,
    pub replica: Arc<Replica<SqlStore>>,
    pub replication: Arc<dyn Replication>,
    /// The fence at the Kemlock API: layer it on the merged router (see `kemlock_api_fed::home_gate`).
    pub home_gate: HomeGate<SqlStore>,
    fetcher: Arc<dyn BlobFetcher>,
}

impl std::fmt::Debug for Federated {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Federated").finish_non_exhaustive()
    }
}

impl Federated {
    /// Brings a file the bytes of which this server lacks from a peer, for the file routes.
    pub fn fetcher(&self) -> Arc<dyn BlobFetcher> {
        self.fetcher.clone()
    }
}

/// The WebSocket client and the HTTP pairing link: how a running server reaches its peers.
pub fn production(
    replica: &Arc<Replica<SqlStore>>,
) -> Result<(WsConnector<SqlStore>, Arc<dyn PairingLink>), RunError> {
    let connector = WsConnector::new(replica.clone())
        .map_err(|e| RunError::Config(format!("the federation client: {e}")))?;
    let http = Http::new().map_err(|e| RunError::Config(format!("the federation client: {e}")))?;
    Ok((connector, Arc::new(HttpLink(http))))
}

/// Loads or makes the federation identity and builds everything federation needs. `make` builds
/// the connector and the pairing link from the replica; `gate` decides who may use the admin
/// routes; `files` is this server's file storage, which the engine serves and fills.
pub fn wire<C, F>(
    config: &Config,
    server_key: &[u8; 32],
    store: &SqlStore,
    files: Arc<dyn BlobFiles>,
    gate: Arc<dyn AdminGate>,
    make: F,
) -> Result<Federated, RunError>
where
    C: Connector + 'static,
    F: FnOnce(&Arc<Replica<SqlStore>>) -> Result<(C, Arc<dyn PairingLink>), RunError>,
{
    let params = IdentityParams {
        address: config.domain.clone(),
        operator: DEFAULT_OPERATOR.to_owned(),
        suites: default_suites(),
    };
    let identity = load_or_create(
        &config.data_folder,
        &ServerSeal::new(server_key),
        ServerInfo::server_id(store),
        &params,
        unix_now(),
    )
    .map_err(|e| RunError::Config(format!("the federation identity: {e}")))?;
    let replica = Arc::new(Replica::new(store.clone(), Arc::new(identity)).with_blob_files(files));
    let (connector, link) = make(&replica)?;
    let runner = Arc::new(
        PeerRunner::new(replica.clone(), connector, holder_name())
            .with_health(HealthConfig::every(config.federation_probe_seconds)),
    );
    let pairings = Arc::new(Pairings::new(replica.clone(), link));
    let facade = Federation::new(replica.clone(), runner.clone(), pairings.clone())
        .with_rotator(Arc::new(FileRotator::new(
            config.data_folder.clone(),
            *server_key,
        )))
        .with_profile(ServerProfile {
            name: None,
            database: database_kind(&config.database_url),
            country: None,
        });
    let (events_tx, events_rx) = tokio::sync::mpsc::unbounded_channel();
    let state = FedState::new(replica.clone()).with_events(events_tx);

    let router = kemlock_api_fed::router(state)
        .merge(pair_router(pairings))
        .merge(admin_router(AdminState {
            federation: facade,
            gate,
        }));
    let view: SharedView = Arc::new(View {
        replica: replica.clone(),
        runner: runner.clone(),
    });
    let for_gate = runner.clone();
    let home_gate = HomeGate::new(
        replica.clone(),
        Arc::new(move |peer| for_gate.mark_dirty(peer)),
    );
    Ok(Federated {
        router,
        view,
        home_gate,
        replica: replica.clone(),
        replication: Arc::new(Running {
            runner: runner.clone(),
            replica,
            events: Mutex::new(Some(events_rx)),
            folder: config.data_folder.clone(),
            key: Zeroizing::new(*server_key),
            params,
        }),
        fetcher: Arc::new(PeerBlobFetcher::new(runner)),
    })
}

/// The kind of database `url` names (`postgres`, `sqlite`, `mysql`): what the console shows beside
/// this server. Nothing of the address, user or password.
fn database_kind(url: &str) -> Option<String> {
    let (scheme, _) = url.split_once(':')?;
    let kind = scheme.split('+').next().unwrap_or(scheme);
    Some(
        if kind == "postgresql" {
            "postgres"
        } else {
            kind
        }
        .to_owned(),
    )
}

/// This server's file storage as the engine reads and writes it.
pub fn files_of<B: kemlock_app::sends::SendBlobs + 'static>(blobs: B) -> Arc<dyn BlobFiles> {
    Arc::new(StoreFiles(blobs))
}

// ---- what the Kemlock API reads ----

/// What the view reads of the replication job, without naming the connector it was built with.
trait RunnerOps: Send + Sync {
    fn health(&self, peer: ServerId) -> PeerHealthView;
    fn reconcile_soon(&self, peer: ServerId, vault: Owner);
}

impl<C: Connector + 'static> RunnerOps for PeerRunner<SqlStore, C> {
    fn reconcile_soon(&self, peer: ServerId, vault: Owner) {
        PeerRunner::reconcile_soon(self, peer, vault);
    }

    fn health(&self, peer: ServerId) -> PeerHealthView {
        let now = unix_now();
        let Some(found) = self.health_of(peer) else {
            return PeerHealthView::unknown();
        };
        let status = found.status(now, self.health_config());
        PeerHealthView {
            status: status.into(),
            last_seen: found.last_seen,
            latency_ms: found.latency_ms,
            last_error: found.last_error.clone(),
            offline_since: found
                .down_since
                .filter(|_| status == kemlock_federation::HealthStatus::Offline),
        }
    }
}

struct View {
    replica: Arc<Replica<SqlStore>>,
    runner: Arc<dyn RunnerOps>,
}

impl FederationView for View {
    fn vault_servers(&self, vault: Owner) -> BoxFut<'_, Result<Option<VaultServers>, StoreError>> {
        Box::pin(async move {
            let store = self.replica.store();
            let me = self.replica.server_id();
            let Some(settings) = VaultRepo::get_vault(store, vault).await? else {
                return Ok(None);
            };
            if settings.policy != Policy::Federated || !settings.holds(me) {
                return Ok(None);
            }
            let identity = self.replica.identity();
            let mut servers = Vec::new();
            for server in settings.order() {
                let (address, identity_key) = if server == me {
                    (
                        identity
                            .descriptor
                            .descriptor
                            .addresses
                            .first()
                            .cloned()
                            .unwrap_or_default(),
                        identity.public.as_bytes().to_vec(),
                    )
                } else {
                    match PeerRepo::get_peer(store, server).await? {
                        Some(peer) => (
                            peer.addresses.first().cloned().unwrap_or_default(),
                            peer.identity_key,
                        ),
                        None => continue,
                    }
                };
                servers.push(ServerEntry {
                    server,
                    address,
                    identity_key,
                    role: if server == settings.home {
                        ServerRole::Home
                    } else {
                        ServerRole::Replica
                    },
                });
            }
            Ok(Some(VaultServers {
                vault,
                epoch: settings.epoch,
                servers,
                promotion: settings.promotion,
            }))
        })
    }

    fn siblings(&self, owner: Owner) -> BoxFut<'_, Result<Vec<SiblingSet>, StoreError>> {
        Box::pin(async move {
            let store = self.replica.store();
            let mut sets = Vec::new();
            for item in FedAdminRepo::items_with_siblings(store, owner).await? {
                let siblings = ReplicaStore::siblings(store, owner, item).await?;
                if !siblings.is_empty() {
                    sets.push(SiblingSet { item, siblings });
                }
            }
            Ok(sets)
        })
    }

    fn resolve_siblings(&self, owner: Owner, item: ItemId) -> BoxFut<'_, Result<u64, StoreError>> {
        Box::pin(
            async move { ReplicaStore::resolve_siblings(self.replica.store(), owner, item).await },
        )
    }

    fn is_replica_account(&self, user: UserId) -> BoxFut<'_, Result<bool, StoreError>> {
        Box::pin(async move { MemberStore::is_replica_account(self.replica.store(), user).await })
    }

    fn peer_health(&self, server: ServerId) -> BoxFut<'_, Result<PeerHealthView, StoreError>> {
        Box::pin(async move { Ok(self.runner.health(server)) })
    }

    fn withheld_from(&self, vault: Owner) -> BoxFut<'_, Result<Vec<ServerId>, StoreError>> {
        Box::pin(async move {
            let me = self.replica.server_id();
            let store = self.replica.store();
            let Some(settings) = VaultRepo::get_vault(store, vault).await? else {
                return Ok(Vec::new());
            };
            let mut out = Vec::new();
            for server in settings.order() {
                if server != me && Withholding::withheld(store, server, vault).await?.is_some() {
                    out.push(server);
                }
            }
            Ok(out)
        })
    }

    fn resume_waiting(
        &self,
        vault: Owner,
        peer: ServerId,
        by: UserId,
    ) -> BoxFut<'_, Result<ResumeOutcome, StoreError>> {
        Box::pin(async move {
            let me = self.replica.server_id();
            let store = self.replica.store();
            let federated = VaultRepo::get_vault(store, vault)
                .await?
                .is_some_and(|v| v.policy == Policy::Federated && v.holds(me) && v.holds(peer));
            if !federated || peer == me {
                return Ok(ResumeOutcome::Unknown);
            }
            let lifted = self
                .replica
                .resume_waiting(peer, vault)
                .await
                .map_err(|e| StoreError::Backend(e.to_string()))?;
            if !lifted {
                return Ok(ResumeOutcome::NothingHeld);
            }
            self.runner.reconcile_soon(peer, vault);
            store
                .record(Event {
                    actor: Some(by),
                    device: None,
                    action: "federation.waiting_resumed",
                    target: Some(format!("vault:{vault} peer:{peer}")),
                    at: time::OffsetDateTime::now_utc(),
                })
                .await?;
            Ok(ResumeOutcome::Resumed)
        })
    }

    fn limited_send_home(&self, owner: UserId) -> BoxFut<'_, Result<Option<String>, StoreError>> {
        Box::pin(async move {
            let store = self.replica.store();
            let me = self.replica.server_id();
            let Some(settings) = VaultRepo::get_vault(store, Owner::User(owner)).await? else {
                return Ok(None);
            };
            if settings.policy != Policy::Federated || !settings.holds(me) || settings.home == me {
                return Ok(None);
            }
            Ok(PeerRepo::get_peer(store, settings.home)
                .await?
                .and_then(|home| home.addresses.first().cloned()))
        })
    }

    fn waiting_changes(&self, vault: Owner) -> BoxFut<'_, Result<Vec<WaitingChanges>, StoreError>> {
        Box::pin(async move {
            let me = self.replica.server_id();
            let Some(settings) = VaultRepo::get_vault(self.replica.store(), vault).await? else {
                return Ok(Vec::new());
            };
            if settings.policy != Policy::Federated || !settings.holds(me) {
                return Ok(Vec::new());
            }
            let mut out = Vec::new();
            for server in settings.order() {
                if server == me {
                    continue;
                }
                let waiting = self
                    .replica
                    .waiting_for(server, vault)
                    .await
                    .map_err(|e| StoreError::Backend(e.to_string()))?;
                if waiting.changes > 0 {
                    out.push(WaitingChanges {
                        peer: server,
                        changes: waiting.changes,
                        at_least: waiting.at_least,
                        oldest_at: waiting.oldest_at,
                    });
                }
            }
            Ok(out)
        })
    }

    fn cancel_waiting(
        &self,
        vault: Owner,
        peer: ServerId,
        by: UserId,
    ) -> BoxFut<'_, Result<CancelOutcome, StoreError>> {
        Box::pin(async move {
            let me = self.replica.server_id();
            let store = self.replica.store();
            let federated = VaultRepo::get_vault(store, vault)
                .await?
                .is_some_and(|v| v.policy == Policy::Federated && v.holds(me) && v.holds(peer));
            if !federated || peer == me {
                return Ok(CancelOutcome::Unknown);
            }
            // Only changes queued for a server that is down may be dropped: for one that answers
            // they are on their way.
            if self.runner.health(peer).status != PeerStatus::Offline {
                return Ok(CancelOutcome::NotOffline);
            }
            let cancelled = self
                .replica
                .cancel_waiting(peer, vault, unix_now())
                .await
                .map_err(|e| StoreError::Backend(e.to_string()))?;
            let Some(cancelled) = cancelled else {
                return Ok(CancelOutcome::NothingWaiting);
            };
            // For the account's record, and the operator's: which vault, which server, how many.
            store
                .record(Event {
                    actor: Some(by),
                    device: None,
                    action: "federation.waiting_cancelled",
                    target: Some(format!(
                        "vault:{vault} peer:{peer} dropped:{}{}",
                        cancelled.dropped,
                        if cancelled.at_least { "+" } else { "" }
                    )),
                    at: time::OffsetDateTime::now_utc(),
                })
                .await?;
            Ok(CancelOutcome::Cancelled {
                dropped: cancelled.dropped,
            })
        })
    }
}

// ---- who may use the admin routes ----

/// The admin gate: a Kemlock API access token (with its DPoP proof) of an effective admin. An
/// admin is "fresh" when the sign-in the session began with was in the last five minutes: a refresh
/// renews the token, not that time.
#[derive(Debug)]
pub struct ApiGate<S, P> {
    api: Api<S, P, JwsTokenSigner>,
}

impl<S, P> ApiGate<S, P> {
    pub fn new(api: Api<S, P, JwsTokenSigner>) -> ApiGate<S, P> {
        ApiGate { api }
    }
}

/// A copy of the request's head the extractor can take by `&mut`: method, URI, headers and the
/// peer address.
fn copy_head(parts: &Parts) -> Result<Parts, GateRefusal> {
    let mut request = Request::builder()
        .method(parts.method.clone())
        .uri(parts.uri.clone())
        .version(parts.version)
        .body(())
        .map_err(|_| GateRefusal {
            status: StatusCode::BAD_REQUEST,
            detail: "the request can't be read",
        })?;
    *request.headers_mut() = parts.headers.clone();
    if let Some(info) = parts.extensions.get::<ConnectInfo<SocketAddr>>() {
        request.extensions_mut().insert(*info);
    }
    Ok(request.into_parts().0)
}

impl<S, P> AdminGate for ApiGate<S, P>
where
    S: kemlock_api_kem::Store,
    P: kemlock_api_kem::Crypto,
{
    fn authorize<'a>(&'a self, parts: &'a Parts) -> BoxFut<'a, Result<AdminActor, GateRefusal>> {
        Box::pin(async move {
            let mut head = copy_head(parts)?;
            let authed = Authed::from_request_parts(&mut head, &self.api)
                .await
                .map_err(|problem| GateRefusal {
                    status: problem.status,
                    detail: "sign in as an admin",
                })?;
            if !authed.actor.admin {
                return Err(GateRefusal {
                    status: StatusCode::FORBIDDEN,
                    detail: "only an admin may do this",
                });
            }
            let now = self.api.crypto.now().unix_timestamp();
            // A step-up token in the header counts: the same token the rest of /admin/v1 takes for
            // a write, made for this account and this device in the last few minutes.
            let step_up = parts
                .headers
                .get("step-up-token")
                .and_then(|v| v.to_str().ok())
                .is_some_and(|token| {
                    StepUp {
                        users: self.api.store.clone(),
                        two_factor: self.api.store.clone(),
                        auth: self.api.crypto.clone(),
                        seal: self.api.crypto.clone(),
                        totp: self.api.crypto.clone(),
                        env: self.api.crypto.clone(),
                    }
                    .check(&authed.actor, token)
                    .is_ok()
                });
            Ok(AdminActor {
                user: authed.actor.user,
                fresh: now - authed.auth_time <= FRESH_SECS,
                step_up,
            })
        })
    }

    fn audit<'a>(
        &'a self,
        actor: &'a AdminActor,
        action: &'static str,
        target: Option<String>,
    ) -> BoxFut<'a, ()> {
        Box::pin(async move {
            let event = Event {
                actor: Some(actor.user),
                device: None,
                action,
                target,
                at: self.api.crypto.now(),
            };
            // The audit log failing must not undo what the admin asked for, but it is said.
            if let Err(e) = self.api.store.record(event).await {
                tracing::warn!(error = %e, action, "a federation admin write could not be logged");
            }
        })
    }
}
