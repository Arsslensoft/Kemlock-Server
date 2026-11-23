//! `/notifications/hub`: Bitwarden's WebSocket for live sync, as Vaultwarden serves it.
//!
//! - `GET /notifications/hub?access_token=<jwt>` (or an `Authorization: Bearer` header): the
//!   account's own socket. A missing or bad token is a 401 before any upgrade.
//! - `POST /notifications/hub/negotiate`: SignalR's negotiation, which offers WebSockets only.
//! - `GET /notifications/anonymous-hub?token=<id>`: a device waiting for the answer to its
//!   login request; at most 25 sockets per address.
//!
//! A socket speaks SignalR: the client's handshake picks MessagePack or JSON, then the server
//! pushes updates and pings every 15 seconds, and a client silent for 30 seconds is dropped
//! (this clears half-open connections). Any other frame is echoed back, as Vaultwarden does.

use super::message::{HANDSHAKE_RESPONSE, MSGPACK_PING, Message, Protocol, UpdateType};
use crate::audience::Audience;
use axum::Json;
use axum::Router;
use axum::extract::ws::{Message as Frame, WebSocket, WebSocketUpgrade};
use axum::extract::{FromRequestParts, Query, Request, State, connect_info};
use axum::http::request::Parts;
use axum::http::{HeaderMap, StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use kemlock_app::notices::BoxFuture;
use kemlock_domain::{DeviceId, Owner, UserId};
use serde::Deserialize;
use std::collections::HashMap;
use std::convert::Infallible;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;
use time::OffsetDateTime;
use tokio::sync::broadcast::{self, error::RecvError};
use tokio::time::Instant;

/// Anonymous sockets one address may hold.
pub const MAX_ANONYMOUS_PER_IP: usize = 25;

/// How long [`BwHub::cover`] holds: the fan-out answers in milliseconds, so a cover that is not
/// used within this time was for a nudge that never came.
pub const COVER_FOR: Duration = Duration::from_secs(5);

/// Who an access token names.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct HubIdentity {
    pub user: UserId,
    pub device: Option<DeviceId>,
}

/// Checks a Bitwarden access token for the hub. The server implements it over `kemlock-api-bw`'s
/// token keys, so a token the API would refuse the hub refuses too (a changed security stamp, a
/// signed-out device).
pub trait HubAuth: Send + Sync + 'static {
    fn authenticate(&self, token: &str) -> BoxFuture<'_, Option<HubIdentity>>;
}

/// Timings and the address header of the hub.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HubConfig {
    /// How often the server pings an open socket.
    pub ping_every: Duration,
    /// How long a socket may say nothing before it is dropped.
    pub client_timeout: Duration,
    /// The header that carries the client's address behind a proxy (`IP_HEADER`), if any.
    pub ip_header: Option<String>,
}

impl Default for HubConfig {
    fn default() -> Self {
        HubConfig {
            ping_every: Duration::from_secs(15),
            client_timeout: Duration::from_secs(30),
            ip_header: None,
        }
    }
}

#[derive(Clone, Debug)]
enum Event {
    /// An update for one account's sockets.
    User(UserId, Arc<Message>),
    /// Every socket should sync (a lost connection between replicas, a missed burst).
    Everyone,
}

struct Inner {
    events: broadcast::Sender<Event>,
    anonymous: Mutex<HashMap<String, broadcast::Sender<Arc<Message>>>>,
    per_ip: Mutex<HashMap<IpAddr, usize>>,
    /// Accounts told of a change in detail a moment ago, whose next `SyncVault` is skipped.
    covered: Mutex<HashMap<UserId, Instant>>,
    open: AtomicUsize,
    audience: Arc<dyn Audience>,
    config: HubConfig,
}

/// The hub: accounts' sockets and what reaches them. Cheap to clone.
#[derive(Clone)]
pub struct BwHub {
    inner: Arc<Inner>,
}

impl std::fmt::Debug for BwHub {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BwHub")
            .field("open", &self.connections())
            .finish_non_exhaustive()
    }
}

fn locked<T>(mutex: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}

impl BwHub {
    /// A hub. `audience` maps a nudge for a space to the accounts that hear of it.
    pub fn new(audience: Arc<dyn Audience>, config: HubConfig) -> BwHub {
        let (events, _) = broadcast::channel(256);
        BwHub {
            inner: Arc::new(Inner {
                events,
                anonymous: Mutex::new(HashMap::new()),
                per_ip: Mutex::new(HashMap::new()),
                covered: Mutex::new(HashMap::new()),
                open: AtomicUsize::new(0),
                audience,
                config,
            }),
        }
    }

    /// How many account sockets are open.
    pub fn connections(&self) -> usize {
        self.inner.open.load(Ordering::SeqCst)
    }

    /// Sends an update to every open socket of the account.
    pub fn send(&self, user: UserId, message: Message) {
        // No receiver is not an error.
        let _ = self.inner.events.send(Event::User(user, Arc::new(message)));
    }

    /// A change reached `owner`'s vault: its accounts' Bitwarden apps sync (`SyncVault`, which
    /// the apps answer with a full sync). A space's nudge goes to its members, found in the
    /// background.
    pub fn nudge(&self, owner: Owner) {
        match owner {
            Owner::User(user) => self.sync_vault(user),
            Owner::Space(_) => {
                let hub = self.clone();
                tokio::spawn(async move {
                    for user in hub.inner.audience.users(owner).await {
                        hub.sync_vault(user);
                    }
                });
            }
        }
    }

    /// The account was just sent a message that says what changed, and the change will also reach
    /// [`BwHub::nudge`] (through the fan-out that tells the other replicas and the Kemlock
    /// devices). Its next `SyncVault` within [`COVER_FOR`] is skipped, so the app doesn't sync twice
    /// for one change. Other replicas' sockets, which heard nothing in detail, still get it.
    pub fn cover(&self, user: UserId) {
        let mut covered = locked(&self.inner.covered);
        covered.retain(|_, at| at.elapsed() < COVER_FOR);
        covered.insert(user, Instant::now());
    }

    /// Whether `user`'s next `SyncVault` is covered; using the cover up.
    fn take_cover(&self, user: UserId) -> bool {
        locked(&self.inner.covered)
            .remove(&user)
            .is_some_and(|at| at.elapsed() < COVER_FOR)
    }

    fn sync_vault(&self, user: UserId) {
        if self.take_cover(user) {
            return;
        }
        self.send(
            user,
            Message::user_update(UpdateType::SyncVault, user.0, OffsetDateTime::now_utc()),
        );
    }

    /// Reads what the hub sends to accounts, for tests of what sends to it.
    #[cfg(test)]
    pub(crate) fn tap(&self) -> Tap {
        Tap(self.inner.events.subscribe())
    }

    /// Every open socket syncs, for a server that may have missed nudges.
    pub fn nudge_everyone(&self) {
        let _ = self.inner.events.send(Event::Everyone);
    }

    /// Answers the device waiting on the anonymous hub with this `token` (a login request id).
    pub fn send_anonymous(&self, token: &str, message: Message) {
        let sender = locked(&self.inner.anonymous).get(token).cloned();
        if let Some(sender) = sender {
            let _ = sender.send(Arc::new(message));
        }
    }

    fn subscribe_anonymous(&self, token: &str) -> broadcast::Receiver<Arc<Message>> {
        locked(&self.inner.anonymous)
            .entry(token.to_owned())
            .or_insert_with(|| broadcast::channel(16).0)
            .subscribe()
    }

    /// Takes an anonymous slot for `ip`, or `None` at the limit.
    fn take_ip_slot(&self, ip: IpAddr) -> Option<IpSlot> {
        let mut per_ip = locked(&self.inner.per_ip);
        let count = per_ip.entry(ip).or_insert(0);
        if *count >= MAX_ANONYMOUS_PER_IP {
            return None;
        }
        *count += 1;
        Some(IpSlot {
            hub: self.clone(),
            ip,
        })
    }
}

/// What a test heard on the hub: the account and message of every update since it tapped, in order.
#[cfg(test)]
pub(crate) struct Tap(broadcast::Receiver<Event>);

#[cfg(test)]
impl Tap {
    pub(crate) fn heard(&mut self) -> Vec<(UserId, Arc<Message>)> {
        let mut out = Vec::new();
        while let Ok(event) = self.0.try_recv() {
            if let Event::User(user, message) = event {
                out.push((user, message));
            }
        }
        out
    }
}

/// An anonymous socket's place under its address's limit, given back on drop.
struct IpSlot {
    hub: BwHub,
    ip: IpAddr,
}

impl Drop for IpSlot {
    fn drop(&mut self) {
        let mut per_ip = locked(&self.hub.inner.per_ip);
        if let Some(count) = per_ip.get_mut(&self.ip) {
            *count = count.saturating_sub(1);
            if *count == 0 {
                per_ip.remove(&self.ip);
            }
        }
    }
}

/// Counts an account socket as open while it lives.
struct OpenSocket(BwHub);

impl OpenSocket {
    fn new(hub: &BwHub) -> OpenSocket {
        hub.inner.open.fetch_add(1, Ordering::SeqCst);
        OpenSocket(hub.clone())
    }
}

impl Drop for OpenSocket {
    fn drop(&mut self) {
        self.0.inner.open.fetch_sub(1, Ordering::SeqCst);
    }
}

/// Forgets an anonymous token's channel once nobody listens to it. Declare it before the
/// receiver so the receiver is dropped first.
struct AnonymousToken {
    hub: BwHub,
    token: String,
}

impl Drop for AnonymousToken {
    fn drop(&mut self) {
        let mut map = locked(&self.hub.inner.anonymous);
        if map
            .get(&self.token)
            .is_some_and(|sender| sender.receiver_count() == 0)
        {
            map.remove(&self.token);
        }
    }
}

// ---------------------------------------------------------------------------------------------
// The socket.

fn encode(protocol: Protocol, message: &Message) -> Frame {
    match protocol {
        Protocol::MessagePack => Frame::Binary(message.msgpack().into()),
        Protocol::Json => Frame::Text(message.json().into()),
    }
}

/// The WebSocket ping the server sends every interval, with Vaultwarden's payload.
fn ws_ping() -> Frame {
    Frame::Ping(MSGPACK_PING.to_vec().into())
}

/// What one client frame asks of the socket loop.
enum Next {
    Continue,
    Stop,
}

/// The state of one socket's SignalR session.
struct Session {
    protocol: Option<Protocol>,
}

impl Session {
    /// Handles a frame from the client: the handshake, a close, or anything else (echoed).
    async fn on_frame(&mut self, socket: &mut WebSocket, frame: Frame) -> Next {
        match frame {
            Frame::Close(_) => Next::Stop,
            // The library answers a ping with a pong; both only show the client is alive.
            Frame::Ping(_) | Frame::Pong(_) => Next::Continue,
            Frame::Text(text) => {
                if self.protocol.is_none()
                    && let Some(protocol) = Protocol::from_handshake(text.as_str())
                {
                    self.protocol = Some(protocol);
                    let reply = match protocol {
                        Protocol::MessagePack => Frame::Binary(HANDSHAKE_RESPONSE.to_vec().into()),
                        Protocol::Json => Frame::Text("{}\u{1e}".into()),
                    };
                    return send(socket, reply).await;
                }
                send(socket, Frame::Text(text)).await
            }
            other @ Frame::Binary(_) => send(socket, other).await,
        }
    }
}

async fn send(socket: &mut WebSocket, frame: Frame) -> Next {
    if socket.send(frame).await.is_err() {
        Next::Stop
    } else {
        Next::Continue
    }
}

/// Serves one account's socket until it closes or goes quiet.
async fn serve_user(mut socket: WebSocket, hub: BwHub, identity: HubIdentity) {
    let config = hub.inner.config.clone();
    // Subscribed before it counts as open, so an open socket has not missed an update.
    let mut events = hub.inner.events.subscribe();
    let _open = OpenSocket::new(&hub);
    let mut session = Session { protocol: None };
    let mut ping = tokio::time::interval_at(Instant::now() + config.ping_every, config.ping_every);
    let mut last_heard = Instant::now();
    loop {
        tokio::select! {
            _ = ping.tick() => {
                if last_heard.elapsed() > config.client_timeout {
                    break;
                }
                if socket.send(ws_ping()).await.is_err() {
                    break;
                }
            }
            event = events.recv() => {
                let message = match event {
                    Ok(Event::User(user, message)) if user == identity.user => Some(message),
                    Ok(Event::User(..)) => None,
                    // Missed some updates, or told to: one full sync answers them all.
                    Ok(Event::Everyone) | Err(RecvError::Lagged(_)) => Some(Arc::new(
                        Message::user_update(
                            UpdateType::SyncVault,
                            identity.user.0,
                            OffsetDateTime::now_utc(),
                        ),
                    )),
                    Err(RecvError::Closed) => break,
                };
                // Updates wait for the handshake: until then the format is unknown.
                if let (Some(message), Some(protocol)) = (message, session.protocol)
                    && matches!(send(&mut socket, encode(protocol, &message)).await, Next::Stop)
                {
                    break;
                }
            }
            incoming = socket.recv() => {
                last_heard = Instant::now();
                match incoming {
                    None | Some(Err(_)) => break,
                    Some(Ok(frame)) => {
                        if matches!(session.on_frame(&mut socket, frame).await, Next::Stop) {
                            break;
                        }
                    }
                }
            }
        }
    }
    let _ = socket.send(Frame::Close(None)).await;
}

/// Serves one anonymous socket: the answer to a login request, once.
async fn serve_anonymous(mut socket: WebSocket, hub: BwHub, token: String, slot: IpSlot) {
    let _slot = slot;
    let config = hub.inner.config.clone();
    // Declared before the receiver, so it is dropped after it.
    let _token = AnonymousToken {
        hub: hub.clone(),
        token: token.clone(),
    };
    let mut answers = hub.subscribe_anonymous(&token);
    let mut session = Session { protocol: None };
    let mut ping = tokio::time::interval_at(Instant::now() + config.ping_every, config.ping_every);
    let mut last_heard = Instant::now();
    loop {
        tokio::select! {
            _ = ping.tick() => {
                if last_heard.elapsed() > config.client_timeout {
                    break;
                }
                if socket.send(ws_ping()).await.is_err() {
                    break;
                }
            }
            answer = answers.recv() => {
                match answer {
                    Ok(message) => {
                        if let Some(protocol) = session.protocol
                            && matches!(send(&mut socket, encode(protocol, &message)).await, Next::Stop)
                        {
                            break;
                        }
                    }
                    Err(RecvError::Lagged(_)) => {}
                    Err(RecvError::Closed) => break,
                }
            }
            incoming = socket.recv() => {
                last_heard = Instant::now();
                match incoming {
                    None | Some(Err(_)) => break,
                    Some(Ok(frame)) => {
                        if matches!(session.on_frame(&mut socket, frame).await, Next::Stop) {
                            break;
                        }
                    }
                }
            }
        }
    }
    let _ = socket.send(Frame::Close(None)).await;
}

// ---------------------------------------------------------------------------------------------
// The routes.

#[derive(Clone)]
struct HubState {
    hub: BwHub,
    auth: Arc<dyn HubAuth>,
}

/// The connecting address: the configured proxy header, else the socket's peer.
struct ClientIp(IpAddr);

impl FromRequestParts<HubState> for ClientIp {
    type Rejection = Infallible;

    async fn from_request_parts(parts: &mut Parts, state: &HubState) -> Result<Self, Infallible> {
        let from_header = state
            .hub
            .inner
            .config
            .ip_header
            .as_deref()
            .and_then(|name| parts.headers.get(name))
            .and_then(|v| v.to_str().ok())
            // A list of hops: the first is the client.
            .and_then(|v| v.split(',').next())
            .and_then(|v| v.trim().parse::<IpAddr>().ok());
        let peer = parts
            .extensions
            .get::<connect_info::ConnectInfo<SocketAddr>>()
            .map(|c| c.0.ip());
        Ok(ClientIp(
            from_header
                .or(peer)
                .unwrap_or(IpAddr::V4(Ipv4Addr::UNSPECIFIED)),
        ))
    }
}

#[derive(Debug, Deserialize)]
struct HubQuery {
    access_token: Option<String>,
}

#[derive(Debug, Deserialize)]
struct AnonymousQuery {
    token: String,
}

fn bearer(headers: &HeaderMap) -> Option<String> {
    let value = headers.get(header::AUTHORIZATION)?.to_str().ok()?;
    // Vaultwarden takes what follows `Bearer `.
    value.strip_prefix("Bearer ").map(|t| t.trim().to_owned())
}

fn unauthorized(detail: &str) -> Response {
    (StatusCode::UNAUTHORIZED, detail.to_owned()).into_response()
}

async fn hub_socket(
    State(state): State<HubState>,
    Query(query): Query<HubQuery>,
    request: Request,
) -> Response {
    let token = query
        .access_token
        .filter(|t| !t.is_empty())
        .or_else(|| bearer(request.headers()));
    let Some(token) = token else {
        return unauthorized("Invalid claim");
    };
    let Some(identity) = state.auth.authenticate(&token).await else {
        return unauthorized("Invalid token");
    };
    let (mut parts, _body) = request.into_parts();
    let upgrade = match WebSocketUpgrade::from_request_parts(&mut parts, &()).await {
        Ok(upgrade) => upgrade,
        Err(rejection) => return rejection.into_response(),
    };
    let hub = state.hub.clone();
    upgrade.on_upgrade(move |socket| serve_user(socket, hub, identity))
}

async fn anonymous_socket(
    State(state): State<HubState>,
    Query(query): Query<AnonymousQuery>,
    ClientIp(ip): ClientIp,
    request: Request,
) -> Response {
    let Some(slot) = state.hub.take_ip_slot(ip) else {
        return (StatusCode::TOO_MANY_REQUESTS, "Too many connections").into_response();
    };
    let (mut parts, _body) = request.into_parts();
    let upgrade = match WebSocketUpgrade::from_request_parts(&mut parts, &()).await {
        Ok(upgrade) => upgrade,
        Err(rejection) => return rejection.into_response(),
    };
    let hub = state.hub.clone();
    upgrade.on_upgrade(move |socket| serve_anonymous(socket, hub, query.token, slot))
}

/// SignalR's negotiation. Only WebSockets are offered, in binary, as Vaultwarden does.
async fn negotiate() -> Json<serde_json::Value> {
    Json(serde_json::json!({
        "connectionId": uuid::Uuid::new_v4().simple().to_string(),
        "availableTransports": [
            {"transport": "WebSockets", "transferFormats": ["Binary"]}
        ],
    }))
}

/// The routes under `/notifications`. Serve the app with
/// `into_make_service_with_connect_info::<SocketAddr>()` so the per-address limit sees peers.
pub fn router(hub: BwHub, auth: Arc<dyn HubAuth>) -> Router {
    Router::new()
        .route("/notifications/hub", get(hub_socket))
        .route("/notifications/hub/negotiate", post(negotiate))
        .route("/notifications/anonymous-hub", get(anonymous_socket))
        .with_state(HubState { hub, auth })
}

#[cfg(test)]
mod tests;
