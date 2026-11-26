//! The fence at the Kemlock API: what only a federated space's home may change.
//!
//! Members, roles, policies, groups, collections, grants and key replacement are home-only writes
//! (`docs/federation.md`, "Home epochs, promotion and the fence"). [`home_gate`] is a middleware for
//! the merged router. For a write to `/kem/v1/spaces/{id}/{members, collections, groups, grants,
//! key-replacement, reseal, policies}` of a space this server federates:
//!
//! - at a server that is **not** the home (a replica, or an old home that was promoted over) the
//!   write is refused with `409` and the home's address, in the problem body and in the
//!   `X-Kemlock-Home` header, so the device can send it there;
//! - at the home the write goes through, and when it succeeded the home makes the home records for
//!   what changed (members, roles, groups, collections, key copies, policies) and tells its
//!   replicas, so they follow at once instead of at their next visit.
//!
//! Reads and writes of anything else pass untouched, and so does everything for a space that is
//! not federated here.

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

/// The parts of `/kem/v1/spaces/{id}/…` only the home may write.
const HOME_ONLY: [&str; 7] = [
    "members",
    "collections",
    "groups",
    "grants",
    "key-replacement",
    "reseal",
    "policies",
];

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

/// The space a request writes home-only state of, if it is such a write.
pub fn home_only_target(method: &Method, path: &str) -> Option<SpaceId> {
    if matches!(*method, Method::GET | Method::HEAD | Method::OPTIONS) {
        return None;
    }
    let rest = path.strip_prefix("/kem/v1/spaces/")?;
    let mut parts = rest.split('/');
    let id = parts.next()?;
    let section = parts.next()?;
    if !HOME_ONLY.contains(&section) {
        return None;
    }
    uuid::Uuid::parse_str(id).ok().map(SpaceId)
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
    let Some(space) = home_only_target(request.method(), request.uri().path()) else {
        return next.run(request).await;
    };
    let vault = Owner::Space(space);
    let me = gate.replica.server_id();
    let store = gate.replica.store();
    let settings = match store.get_vault(vault).await {
        Ok(Some(s)) if s.policy == Policy::Federated && s.holds(me) => s,
        Ok(_) => return next.run(request).await,
        Err(e) => {
            tracing::warn!(error = %e, "the home check of a space write could not read the vault");
            return next.run(request).await;
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
        let target = |method: Method, path: String| home_only_target(&method, &path);
        for section in HOME_ONLY {
            assert_eq!(
                target(Method::POST, format!("/kem/v1/spaces/{id}/{section}")),
                Some(SpaceId(id)),
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
            Some(SpaceId(id))
        );
        assert_eq!(target(Method::POST, "/kem/v1/spaces".to_owned()), None);
        assert_eq!(
            target(Method::POST, format!("/kem/v1/spaces/{id}/items")),
            None
        );
        assert_eq!(
            target(Method::POST, "/kem/v1/spaces/me/members".to_owned()),
            None
        );
        assert_eq!(target(Method::POST, format!("/kem/v1/items/{id}")), None);
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
