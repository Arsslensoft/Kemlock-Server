//! The fence at the Kemlock API: what only a federated space's home may change.
//!
//! Members, roles, policies, groups, collections, grants and key replacement are home-only writes
//! (`docs/federation.md`, "Home epochs, promotion and the fence"). [`home_gate`] is a middleware for
//! the merged router. For a write to `/kem/v1/spaces/{id}/{members, collections, groups, grants,
//! key-replacement, reseal, policies, chain}`, to the Bitwarden API's `/api/organizations/{id}/{users,
//! collections, groups, policies, keys, leave}` or to the admin console's
//! `/admin/v1/spaces/{id}/owner`, of a space this server federates:
//!
//! - at a server that is **not** the home (a replica, or an old home that was promoted over) the
//!   write is refused with `409` and the home's address, in the problem body and in the
//!   `X-Kemlock-Home` header, so the device can send it there;
//! - at the home the write goes through, and when it succeeded the home makes the home records for
//!   what changed (members, roles, groups, collections, key copies, policies) and tells its
//!   replicas, so they follow at once instead of at their next visit.
//!
//! Reads and writes of anything else pass untouched, and so does everything for a space that is
//! not federated here. A write whose space id can't be read is refused with `400`, and one the gate
//! can't check (the vault's settings can't be read) with `503`, never passed on.

use axum::extract::{Request, State};
use axum::http::{HeaderValue, Method, StatusCode, header};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use kemlock_domain::{Owner, ServerId, SpaceId};
use kemlock_federation::home::Policy;
use kemlock_federation::{FedStore, Replica};
use std::sync::Arc;

/// The header that names the home's address in a refusal.
pub const HOME_HEADER: &str = "x-kemlock-home";

/// The parts of `/kem/v1/spaces/{id}/…` only the home may write. `chain` is the space's signed
/// chain: appending to it changes members, roles and keys.
const HOME_ONLY: [&str; 8] = [
    "members",
    "collections",
    "groups",
    "grants",
    "key-replacement",
    "reseal",
    "policies",
    "chain",
];

/// The parts of `/api/organizations/{id}/…` (the Bitwarden API's name for a space) only the home
/// may write: members, collections, groups, policies, the organization's keys and leaving it.
const BITWARDEN_HOME_ONLY: [&str; 6] = ["users", "collections", "groups", "policies", "keys", "leave"];

/// What the gate needs: the engine, and what to call when the home changed something so the
/// replicas are visited soon (the server passes the replication job's `mark_dirty`).
pub struct HomeGate<S> {
    replica: Arc<Replica<S>>,
    changed: Arc<dyn Fn(ServerId) + Send + Sync>,
}

impl<S> Clone for HomeGate<S> {
    fn clone(&self) -> Self {
        HomeGate {
            replica: self.replica.clone(),
            changed: self.changed.clone(),
        }
    }
}

impl<S> std::fmt::Debug for HomeGate<S> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HomeGate").finish_non_exhaustive()
    }
}

impl<S: FedStore> HomeGate<S> {
    pub fn new(
        replica: Arc<Replica<S>>,
        changed: Arc<dyn Fn(ServerId) + Send + Sync>,
    ) -> HomeGate<S> {
        HomeGate { replica, changed }
    }
}

/// What a request that writes home-only state names.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HomeTarget {
    /// The space it writes.
    Space(SpaceId),
    /// A request for the home-only part of a space whose id this middleware can't read: it is
    /// refused rather than passed, because the handler might read the same text another way.
    Malformed,
}

/// A path parameter as the router hands it to a handler: percent-decoded. `None` for a `%` that
/// isn't followed by two hex digits, or for bytes that aren't UTF-8.
fn decode_segment(segment: &str) -> Option<String> {
    let bytes = segment.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut at = 0;
    while at < bytes.len() {
        if bytes[at] == b'%' {
            let pair = bytes.get(at + 1..at + 3)?;
            if !pair.iter().all(u8::is_ascii_hexdigit) {
                return None;
            }
            let text = std::str::from_utf8(pair).ok()?;
            out.push(u8::from_str_radix(text, 16).ok()?);
            at += 3;
        } else {
            out.push(bytes[at]);
            at += 1;
        }
    }
    String::from_utf8(out).ok()
}

/// What a request writes home-only state of, if it is such a write: `/kem/v1/spaces/{id}/…`, the
/// Bitwarden API's `/api/organizations/{id}/…` and the admin console's
/// `/admin/v1/spaces/{id}/owner`. The router matches the literal parts of a path as they came and
/// decodes its parameters, so the space's id is decoded here too: `%30` is `0` to the handler.
pub fn home_only_target(method: &Method, path: &str) -> Option<HomeTarget> {
    if matches!(*method, Method::GET | Method::HEAD | Method::OPTIONS) {
        return None;
    }
    let segments: Vec<&str> = path.split('/').collect();
    let id = match segments.as_slice() {
        ["", "kem", "v1", "spaces", id, section, ..] if HOME_ONLY.contains(section) => id,
        ["", "api", "organizations", id, section, ..] if BITWARDEN_HOME_ONLY.contains(section) => {
            id
        }
        ["", "admin", "v1", "spaces", id, "owner", ..] => id,
        _ => return None,
    };
    Some(
        decode_segment(id)
            .and_then(|id| uuid::Uuid::parse_str(&id).ok())
            .map_or(HomeTarget::Malformed, |id| HomeTarget::Space(SpaceId(id))),
    )
}

/// The `400` of a home-only write whose space id can't be read.
fn malformed() -> Response {
    problem_response(
        StatusCode::BAD_REQUEST,
        "urn:kemlock:problem:bad-request",
        "The space in the address isn't a valid id",
    )
}

/// The `503` of a home-only write when the vault's settings couldn't be read: the write is not
/// passed on, because the fence can't say whether this server may take it.
fn unavailable() -> Response {
    problem_response(
        StatusCode::SERVICE_UNAVAILABLE,
        "urn:kemlock:problem:unavailable",
        "This change can't be checked against the vault's home right now: try again shortly",
    )
}

fn problem_response(status: StatusCode, kind: &str, title: &str) -> Response {
    let body = serde_json::json!({
        "type": kind,
        "title": title,
        "status": status.as_u16(),
    });
    (
        status,
        [(header::CONTENT_TYPE, "application/problem+json")],
        body.to_string(),
    )
        .into_response()
}

/// The `409` of a home-only write at a server that isn't the home.
fn refusal(home: ServerId, address: Option<String>) -> Response {
    let body = serde_json::json!({
        "type": "urn:kemlock:problem:home-only",
        "title": "This change is made at the vault's home",
        "status": 409,
        "detail": "members, roles, policies and keys of a federated vault are changed at its home server",
        "home": {
            "server": home,
            "address": address,
        },
    });
    let mut response = (
        StatusCode::CONFLICT,
        [(header::CONTENT_TYPE, "application/problem+json")],
        body.to_string(),
    )
        .into_response();
    if let Some(value) = address.and_then(|a| HeaderValue::from_str(&a).ok()) {
        response.headers_mut().insert(HOME_HEADER, value);
    }
    response
}

/// The middleware. Layer it on the router that serves the Kemlock API with
/// `axum::middleware::from_fn_with_state(gate, home_gate::<S>)`.
pub async fn home_gate<S: FedStore + 'static>(
    State(gate): State<HomeGate<S>>,
    request: Request,
    next: Next,
) -> Response {
    let space = match home_only_target(request.method(), request.uri().path()) {
        None => return next.run(request).await,
        Some(HomeTarget::Malformed) => return malformed(),
        Some(HomeTarget::Space(space)) => space,
    };
    let vault = Owner::Space(space);
    let me = gate.replica.server_id();
    let store = gate.replica.store();
    let settings = match store.get_vault(vault).await {
        Ok(Some(s)) if s.policy == Policy::Federated && s.holds(me) => s,
        Ok(_) => return next.run(request).await,
        Err(e) => {
            tracing::warn!(error = %e, "the home check of a space write could not read the vault");
            return unavailable();
        }
    };
    if settings.home != me {
        let address = match store.get_peer(settings.home).await {
            Ok(peer) => peer.and_then(|p| p.addresses.first().cloned()),
            Err(_) => None,
        };
        return refusal(settings.home, address);
    }
    let response = next.run(request).await;
    if response.status().is_success() {
        if let Err(e) = gate.replica.publish_members(vault).await {
            tracing::warn!(error = %e, "the member accounts of a space could not be published");
        }
        if let Err(e) = gate.replica.publish_space_state(vault).await {
            tracing::warn!(error = %e, "a space's home records could not be published");
        }
        for peer in &settings.replicas {
            (gate.changed)(*peer);
        }
    }
    response
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::Router;
    use axum::body::{Body, to_bytes};
    use axum::middleware::from_fn_with_state;
    use axum::routing::post;
    use kemlock_federation::memory::MemoryStore;
    use kemlock_federation::ports::VaultRepo;
    use kemlock_federation::testing::{identity, space_snapshot};
    use kemlock_federation::{Suite, unix_now};
    use std::sync::Mutex;
    use tower::ServiceExt as _;

    #[test]
    fn only_writes_to_the_home_only_parts_of_a_space_are_targeted() {
        let id = uuid::Uuid::new_v4();
        let space = Some(HomeTarget::Space(SpaceId(id)));
        let target = |method: Method, path: String| home_only_target(&method, &path);
        for section in HOME_ONLY {
            assert_eq!(
                target(Method::POST, format!("/kem/v1/spaces/{id}/{section}")),
                space,
                "{section}"
            );
            assert_eq!(
                target(Method::GET, format!("/kem/v1/spaces/{id}/{section}")),
                None,
                "a read is made anywhere"
            );
        }
        assert_eq!(
            target(
                Method::PUT,
                format!("/kem/v1/spaces/{id}/members/{id}/role")
            ),
            space
        );
        assert_eq!(target(Method::POST, "/kem/v1/spaces".to_owned()), None);
        assert_eq!(
            target(Method::POST, format!("/kem/v1/spaces/{id}/items")),
            None
        );
        assert_eq!(target(Method::POST, format!("/kem/v1/items/{id}")), None);
    }

    #[test]
    fn the_bitwarden_organization_routes_and_the_admin_owner_route_are_fenced_too() {
        let id = uuid::Uuid::new_v4();
        let space = Some(HomeTarget::Space(SpaceId(id)));
        let target = |method: Method, path: String| home_only_target(&method, &path);
        for section in BITWARDEN_HOME_ONLY {
            assert_eq!(
                target(Method::POST, format!("/api/organizations/{id}/{section}")),
                space,
                "{section}"
            );
            assert_eq!(
                target(Method::GET, format!("/api/organizations/{id}/{section}")),
                None
            );
        }
        assert_eq!(
            target(
                Method::PUT,
                format!("/api/organizations/{id}/users/{id}/confirm")
            ),
            space
        );
        assert_eq!(
            target(Method::PUT, format!("/admin/v1/spaces/{id}/owner")),
            space
        );
        // Other organization and admin routes are not home-only writes.
        for path in [
            "/api/organizations".to_owned(),
            format!("/api/organizations/{id}/api-key"),
            format!("/api/organizations/{id}/export"),
            format!("/admin/v1/spaces/{id}"),
        ] {
            assert_eq!(target(Method::POST, path.clone()), None, "{path}");
        }
    }

    #[test]
    fn the_space_id_is_read_as_the_router_hands_it_to_the_handler() {
        let id = uuid::Uuid::new_v4();
        let space = Some(HomeTarget::Space(SpaceId(id)));
        // `%30` is `0` and `%61` is `a`: an encoded digit is still the same space.
        let text = id.to_string();
        let mut encoded = text.clone();
        let first = encoded.remove(0);
        encoded.insert_str(0, &format!("%{:02X}", u32::from(first)));
        assert_eq!(
            home_only_target(&Method::POST, &format!("/kem/v1/spaces/{encoded}/members")),
            space
        );
        assert_eq!(
            home_only_target(
                &Method::POST,
                &format!("/api/organizations/{encoded}/users/invite")
            ),
            space
        );
        // An id that can't be read is refused by the gate, not passed on.
        for bad in ["me", "%zz", "%FF", "%2", "not-a-space"] {
            assert_eq!(
                home_only_target(&Method::POST, &format!("/kem/v1/spaces/{bad}/members")),
                Some(HomeTarget::Malformed),
                "{bad}"
            );
        }
    }

    type Server = Arc<Replica<MemoryStore>>;

    fn server(seed: u8) -> Server {
        let id = identity(seed, unix_now(), &Suite::IMPLEMENTED);
        Arc::new(Replica::new(MemoryStore::new(id.server), Arc::new(id)))
    }

    fn app(replica: &Server, told: &Arc<Mutex<Vec<ServerId>>>) -> Router {
        let told = told.clone();
        let gate = HomeGate::new(
            replica.clone(),
            Arc::new(move |peer| told.lock().expect("lock").push(peer)),
        );
        Router::new()
            .route(
                "/kem/v1/spaces/{id}/members",
                post(|| async { "ok" }).get(|| async { "list" }),
            )
            .route(
                "/kem/v1/spaces/{id}/items",
                post(|| async { StatusCode::CREATED }),
            )
            .layer(from_fn_with_state(gate, home_gate::<MemoryStore>))
    }

    async fn send(
        app: &Router,
        method: &str,
        path: &str,
    ) -> (StatusCode, axum::http::HeaderMap, String) {
        let response = app
            .clone()
            .oneshot(
                axum::http::Request::builder()
                    .method(method)
                    .uri(path)
                    .body(Body::empty())
                    .expect("a request"),
            )
            .await
            .expect("a response");
        let status = response.status();
        let headers = response.headers().clone();
        let body = to_bytes(response.into_body(), 1 << 20)
            .await
            .expect("a body");
        (status, headers, String::from_utf8_lossy(&body).into_owned())
    }

    #[tokio::test]
    async fn a_replica_refuses_with_the_homes_address_and_the_home_publishes_after_a_write() {
        let home = server(1);
        let replica = server(2);
        let now = unix_now();
        home.pin_peer(&replica.identity().descriptor, now)
            .await
            .expect("pin");
        replica
            .pin_peer(&home.identity().descriptor, now)
            .await
            .expect("pin");
        let space = SpaceId::random();
        let vault = Owner::Space(space);
        home.federate(vault, vec![replica.server_id()])
            .await
            .expect("federate");
        replica
            .accept_vault(vault, home.server_id(), vec![replica.server_id()])
            .await
            .expect("accept");
        home.store().set_space_snapshot(space_snapshot(space));

        // At the replica: refused, and told where the home is.
        let told_replica = Arc::new(Mutex::new(Vec::new()));
        let at_replica = app(&replica, &told_replica);
        let (status, headers, body) = send(
            &at_replica,
            "POST",
            &format!("/kem/v1/spaces/{}/members", space.0),
        )
        .await;
        assert_eq!(status, StatusCode::CONFLICT, "{body}");
        let problem: serde_json::Value = serde_json::from_str(&body).expect("JSON");
        assert_eq!(problem["type"], "urn:kemlock:problem:home-only");
        assert_eq!(problem["home"]["server"], home.server_id().to_string());
        let address = home.identity().descriptor.descriptor.addresses[0].clone();
        assert_eq!(problem["home"]["address"], address);
        assert_eq!(
            headers.get(HOME_HEADER).and_then(|v| v.to_str().ok()),
            Some(address.as_str())
        );
        assert!(told_replica.lock().expect("lock").is_empty());
        // Reads, and writes of other things, pass at the replica.
        let (status, _, _) = send(
            &at_replica,
            "GET",
            &format!("/kem/v1/spaces/{}/members", space.0),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        let (status, _, _) = send(
            &at_replica,
            "POST",
            &format!("/kem/v1/spaces/{}/items", space.0),
        )
        .await;
        assert_eq!(status, StatusCode::CREATED);
        // A space that isn't federated here is nobody's business.
        let (status, _, _) = send(
            &at_replica,
            "POST",
            &format!("/kem/v1/spaces/{}/members", uuid::Uuid::new_v4()),
        )
        .await;
        assert_eq!(status, StatusCode::OK);

        // At the home: the write goes through, the home records are made and the replica is told.
        let told_home = Arc::new(Mutex::new(Vec::new()));
        let at_home = app(&home, &told_home);
        assert_eq!(
            home.store()
                .home_records(vault, 0, 100)
                .await
                .expect("records")
                .len(),
            0
        );
        let (status, _, _) = send(
            &at_home,
            "POST",
            &format!("/kem/v1/spaces/{}/members", space.0),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(
            home.store()
                .home_records(vault, 0, 100)
                .await
                .expect("records")
                .len(),
            8,
            "the space, two members, a group, two collections, a key set and the policies"
        );
        assert_eq!(*told_home.lock().expect("lock"), vec![replica.server_id()]);
    }

    #[tokio::test]
    async fn a_write_for_a_space_the_gate_cannot_read_is_refused_not_passed() {
        let home = server(4);
        let told = Arc::new(Mutex::new(Vec::new()));
        let app = app(&home, &told);
        for path in [
            "/kem/v1/spaces/%6De/members",
            "/kem/v1/spaces/%zz/members",
            "/kem/v1/spaces/not-a-space/members",
        ] {
            let (status, _, body) = send(&app, "POST", path).await;
            assert_eq!(status, StatusCode::BAD_REQUEST, "{path}: {body}");
        }
        // A read of the same address passes: only writes are fenced.
        let (status, _, _) = send(&app, "GET", "/kem/v1/spaces/not-a-space/members").await;
        assert_eq!(status, StatusCode::OK);
    }

    #[tokio::test]
    async fn a_failed_write_at_the_home_publishes_nothing() {
        let home = server(3);
        let space = SpaceId::random();
        let vault = Owner::Space(space);
        let other = ServerId::random();
        home.federate(vault, vec![other]).await.expect("federate");
        home.store().set_space_snapshot(space_snapshot(space));
        let told = Arc::new(Mutex::new(Vec::new()));
        let gate = HomeGate::new(home.clone(), {
            let told = told.clone();
            Arc::new(move |peer| told.lock().expect("lock").push(peer))
        });
        let app = Router::new()
            .route(
                "/kem/v1/spaces/{id}/members",
                post(|| async { StatusCode::FORBIDDEN }),
            )
            .layer(from_fn_with_state(gate, home_gate::<MemoryStore>));
        let (status, _, _) =
            send(&app, "POST", &format!("/kem/v1/spaces/{}/members", space.0)).await;
        assert_eq!(status, StatusCode::FORBIDDEN);
        assert_eq!(
            home.store()
                .home_records(vault, 0, 100)
                .await
                .expect("records")
                .len(),
            0
        );
        assert!(told.lock().expect("lock").is_empty());
    }
}
