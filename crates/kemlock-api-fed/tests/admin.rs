//! The admin routes of federation and the public pairing routes, over in-memory servers.

use axum::Router;
use axum::body::{Body, to_bytes};
use axum::http::request::Parts;
use axum::http::{Method, Request, StatusCode, header};
use kemlock_api_fed::{AdminActor, AdminGate, AdminState, GateRefusal, admin_router, pair_router};
use kemlock_app::federation_view::BoxFut;
use kemlock_domain::{ServerId, UserId};
use kemlock_federation::memory::MemoryStore;
use kemlock_federation::message::{Request as FedRequest, Response as FedResponse};
use kemlock_federation::ports::Peer;
use kemlock_federation::testing::identity;
use kemlock_federation::{
    Channel, Connector, FedError, Federation, PairingLink, Pairings, PeerRunner, Replica, Suite,
    unix_now,
};
use serde_json::{Value, json};
use std::sync::Arc;
use tower::ServiceExt as _;

/// A connector that never connects: these tests don't run the job.
struct NoConnector;

struct NoChannel;

impl Channel for NoChannel {
    async fn call(&mut self, _request: &FedRequest) -> Result<FedResponse, FedError> {
        Err(FedError::Remote("no session in these tests".to_owned()))
    }
}

impl Connector for NoConnector {
    type Chan = NoChannel;

    async fn connect(&self, _peer: &Peer) -> Result<NoChannel, FedError> {
        Err(FedError::Remote("no session in these tests".to_owned()))
    }

    async fn close(&self, _channel: NoChannel) -> Result<(), FedError> {
        Ok(())
    }
}

/// A pairing link with nobody at the other end.
struct Dead;

impl PairingLink for Dead {
    fn start(&self, _address: &str, _message: Vec<u8>) -> BoxFut<'_, Result<Vec<u8>, FedError>> {
        Box::pin(async { Err(FedError::Remote("nobody there".to_owned())) })
    }

    fn finish(
        &self,
        _address: &str,
        _initiator: ServerId,
        _message: Vec<u8>,
    ) -> BoxFut<'_, Result<(), FedError>> {
        Box::pin(async { Err(FedError::Remote("nobody there".to_owned())) })
    }
}

/// A pairing link that hands the messages straight to another server's hub.
struct Loop(Arc<Pairings<MemoryStore>>);

impl PairingLink for Loop {
    fn start(&self, _address: &str, message: Vec<u8>) -> BoxFut<'_, Result<Vec<u8>, FedError>> {
        Box::pin(async move { self.0.respond(&message, unix_now()) })
    }

    fn finish(
        &self,
        _address: &str,
        initiator: ServerId,
        message: Vec<u8>,
    ) -> BoxFut<'_, Result<(), FedError>> {
        Box::pin(async move { self.0.finish(initiator, &message, unix_now()) })
    }
}

/// Lets a request through when it carries `x-admin`; it is fresh when it also carries `x-fresh`, and
/// has a step-up token when it carries `x-step-up`.
struct Gate;

impl AdminGate for Gate {
    fn authorize<'a>(&'a self, parts: &'a Parts) -> BoxFut<'a, Result<AdminActor, GateRefusal>> {
        Box::pin(async move {
            if !parts.headers.contains_key("x-admin") {
                return Err(GateRefusal {
                    status: StatusCode::UNAUTHORIZED,
                    detail: "send x-admin",
                });
            }
            Ok(AdminActor {
                user: UserId::random(),
                fresh: parts.headers.contains_key("x-fresh"),
                step_up: parts.headers.contains_key("x-step-up"),
            })
        })
    }
}

struct Env {
    app: Router,
    replica: Arc<Replica<MemoryStore>>,
    pairings: Arc<Pairings<MemoryStore>>,
}

fn env(seed: u8, link: Arc<dyn PairingLink>) -> Env {
    let id = identity(seed, unix_now(), &Suite::IMPLEMENTED);
    let replica = Arc::new(Replica::new(MemoryStore::new(id.server), Arc::new(id)));
    let pairings = Arc::new(Pairings::new(replica.clone(), link));
    let runner = Arc::new(PeerRunner::new(
        replica.clone(),
        NoConnector,
        format!("test-{seed}"),
    ));
    let federation = Federation::new(replica.clone(), runner, pairings.clone());
    let app = admin_router(AdminState {
        federation,
        gate: Arc::new(Gate),
    })
    .merge(pair_router(pairings.clone()));
    Env {
        app,
        replica,
        pairings,
    }
}

async fn call(
    app: &Router,
    method: Method,
    uri: &str,
    body: Option<Value>,
    headers: &[(&str, &str)],
) -> (StatusCode, axum::http::HeaderMap, Vec<u8>) {
    let mut builder = Request::builder().method(method).uri(uri);
    for (name, value) in headers {
        builder = builder.header(*name, *value);
    }
    let body = body.map_or_else(Body::empty, |v| Body::from(v.to_string()));
    let response = app
        .clone()
        .oneshot(builder.body(body).expect("a request"))
        .await
        .expect("a response");
    let status = response.status();
    let headers = response.headers().clone();
    let bytes = to_bytes(response.into_body(), 1 << 20)
        .await
        .expect("a body");
    (status, headers, bytes.to_vec())
}

/// An admin with a step-up token, which every write needs.
async fn admin(
    app: &Router,
    method: Method,
    uri: &str,
    body: Option<Value>,
) -> (StatusCode, Value) {
    let (status, _, bytes) = call(
        app,
        method,
        uri,
        body,
        &[("x-admin", "1"), ("x-step-up", "1")],
    )
    .await;
    let value = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
    (status, value)
}

#[tokio::test]
async fn without_the_gate_nothing_is_served() {
    let e = env(1, Arc::new(Dead));
    let (status, headers, bytes) =
        call(&e.app, Method::GET, "/admin/v1/federation", None, &[]).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert_eq!(
        headers
            .get(header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok()),
        Some("application/problem+json")
    );
    let problem: Value = serde_json::from_slice(&bytes).expect("a problem");
    assert_eq!(problem["type"], "urn:kemlock:problem:unauthorized");
    for (method, uri) in [
        (Method::GET, "/admin/v1/federation/peers"),
        (Method::POST, "/admin/v1/federation/pairing/code"),
        (Method::GET, "/admin/v1/federation/vaults"),
        (Method::GET, "/admin/v1/federation/offers"),
    ] {
        let (status, _, _) = call(&e.app, method, uri, None, &[]).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED, "{uri}");
    }
}

#[tokio::test]
async fn the_overview_and_the_peer_list_answer() {
    let e = env(1, Arc::new(Dead));
    let (status, overview) = admin(&e.app, Method::GET, "/admin/v1/federation", None).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        overview["server"]["serverId"],
        e.replica.server_id().0.to_string()
    );
    assert_eq!(overview["server"]["operator"], "Operator 1");
    assert_eq!(overview["peers"], json!([]));
    assert_eq!(overview["vaults"], json!([]));
    let (status, peers) = admin(&e.app, Method::GET, "/admin/v1/federation/peers", None).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(peers, json!([]));
}

#[tokio::test]
async fn the_code_route_shows_a_displayable_code() {
    let e = env(1, Arc::new(Dead));
    let (status, body) = admin(
        &e.app,
        Method::POST,
        "/admin/v1/federation/pairing/code",
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let code = body["code"].as_str().expect("a code");
    assert_eq!(code.len(), 14);
    assert_eq!(code.matches('-').count(), 2);
    assert!(body["expiresAt"].as_u64().expect("a time") > unix_now());
    assert!(e.pairings.code_waiting(unix_now()));
}

#[tokio::test]
async fn a_new_code_needs_a_step_up_token_like_every_other_write() {
    let e = env(1, Arc::new(Dead));
    let uri = "/admin/v1/federation/pairing/code";
    for headers in [
        &[("x-admin", "1")][..],
        &[("x-admin", "1"), ("x-fresh", "1")][..],
    ] {
        let (status, _, bytes) = call(&e.app, Method::POST, uri, None, headers).await;
        assert_eq!(status, StatusCode::FORBIDDEN);
        let problem: Value = serde_json::from_slice(&bytes).expect("a problem");
        assert_eq!(problem["type"], "urn:kemlock:problem:step-up-required");
    }
    assert!(
        !e.pairings.code_waiting(unix_now()),
        "no code was made without the token"
    );
}

#[tokio::test]
async fn two_servers_pair_through_their_admin_routes() {
    let b = env(2, Arc::new(Dead));
    let a = env(1, Arc::new(Loop(b.pairings.clone())));
    let (_, code) = admin(
        &b.app,
        Method::POST,
        "/admin/v1/federation/pairing/code",
        None,
    )
    .await;
    let (status, awaiting) = admin(
        &a.app,
        Method::POST,
        "/admin/v1/federation/pairing",
        Some(json!({"address": "http://b.example.org", "code": code["code"]})),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{awaiting}");
    assert_eq!(awaiting["peerId"], b.replica.server_id().0.to_string());
    assert_eq!(awaiting["otherOrganisation"], true);
    assert_eq!(
        awaiting["identityKey"],
        hex::encode(b.replica.identity().public.as_bytes()),
        "the key the pairing would pin"
    );
    assert_eq!(awaiting["side"], "typed");
    assert_eq!(awaiting["fingerprint"].as_array().expect("words").len(), 6);

    // B sees A waiting with the same six words.
    let (_, theirs) = admin(&b.app, Method::GET, "/admin/v1/federation/pairings", None).await;
    assert_eq!(theirs.as_array().expect("a list").len(), 1);
    assert_eq!(theirs[0]["fingerprint"], awaiting["fingerprint"]);
    assert_eq!(theirs[0]["side"], "showed");

    // Another organisation needs the three acknowledgements.
    let a_path = format!(
        "/admin/v1/federation/pairings/{}/confirm",
        b.replica.server_id().0
    );
    let (status, _) = admin(
        &a.app,
        Method::POST,
        &a_path,
        Some(json!({"fingerprintMatches": true})),
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT);

    let ack = json!({"metadata": true, "deletion": true, "crossBorder": true, "by": "admin"});
    let (status, peer) = admin(
        &a.app,
        Method::POST,
        &a_path,
        Some(json!({"fingerprintMatches": true, "acknowledgement": ack})),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{peer}");
    assert_eq!(peer["id"], b.replica.server_id().0.to_string());
    assert_eq!(peer["fingerprint"], awaiting["fingerprint"]);

    let b_path = format!(
        "/admin/v1/federation/pairings/{}/confirm",
        a.replica.server_id().0
    );
    let (status, _) = admin(
        &b.app,
        Method::POST,
        &b_path,
        Some(json!({"fingerprintMatches": true, "acknowledgement": ack})),
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    let (_, peers) = admin(&a.app, Method::GET, "/admin/v1/federation/peers", None).await;
    assert_eq!(peers.as_array().expect("a list").len(), 1);
    assert_eq!(peers[0]["state"], "paired");
    assert_eq!(
        peers[0]["identityKey"],
        hex::encode(b.replica.identity().public.as_bytes()),
        "the pinned key"
    );
    assert_eq!(peers[0]["switches"], json!({"send": false, "pull": false}));
    let (_, left) = admin(&a.app, Method::GET, "/admin/v1/federation/pairings", None).await;
    assert_eq!(left, json!([]));
}

#[tokio::test]
async fn a_wrong_code_is_a_bare_400_and_uses_the_code_up() {
    let b = env(2, Arc::new(Dead));
    let a = env(1, Arc::new(Loop(b.pairings.clone())));
    let (_, code) = admin(
        &b.app,
        Method::POST,
        "/admin/v1/federation/pairing/code",
        None,
    )
    .await;
    let wrong = "0000-0000-0000";
    assert_ne!(code["code"], wrong);
    let (status, problem) = admin(
        &a.app,
        Method::POST,
        "/admin/v1/federation/pairing",
        Some(json!({"address": "http://b.example.org", "code": wrong})),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(problem["type"], "urn:kemlock:problem:pairing-failed");
    assert!(problem.get("detail").is_none());
    // The one attempt is gone: the right code no longer works.
    let (status, _) = admin(
        &a.app,
        Method::POST,
        "/admin/v1/federation/pairing",
        Some(json!({"address": "http://b.example.org", "code": code["code"]})),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    let (_, awaiting) = admin(&b.app, Method::GET, "/admin/v1/federation/pairings", None).await;
    assert_eq!(awaiting, json!([]));
}

#[tokio::test]
async fn the_public_pairing_routes_refuse_with_a_bare_400() {
    let e = env(1, Arc::new(Dead));
    for (uri, body) in [
        ("/fed/v1/pair/start", "garbage"),
        ("/fed/v1/pair/finish?initiator=not-a-uuid", "garbage"),
        (
            "/fed/v1/pair/finish?initiator=00000000-0000-0000-0000-000000000000",
            "garbage",
        ),
        ("/fed/v1/pair/finish", "garbage"),
    ] {
        let response = e
            .app
            .clone()
            .oneshot(
                Request::builder()
                    .method(Method::POST)
                    .uri(uri)
                    .body(Body::from(body))
                    .expect("a request"),
            )
            .await
            .expect("a response");
        assert_eq!(response.status(), StatusCode::BAD_REQUEST, "{uri}");
        let bytes = to_bytes(response.into_body(), 1 << 16)
            .await
            .expect("a body");
        let problem: Value = serde_json::from_slice(&bytes).expect("a problem");
        assert_eq!(problem["status"], 400);
        assert!(problem.get("detail").is_none(), "{uri}");
    }
}

#[tokio::test]
async fn the_public_pairing_routes_are_rate_limited() {
    let e = env(1, Arc::new(Dead));
    let mut last = StatusCode::OK;
    for _ in 0..25 {
        let response = e
            .app
            .clone()
            .oneshot(
                Request::builder()
                    .method(Method::POST)
                    .uri("/fed/v1/pair/start")
                    .body(Body::from("x"))
                    .expect("a request"),
            )
            .await
            .expect("a response");
        last = response.status();
    }
    assert_eq!(last, StatusCode::TOO_MANY_REQUESTS);
}

#[tokio::test]
async fn promotion_needs_a_step_up_token_not_just_a_recent_sign_in() {
    let e = env(1, Arc::new(Dead));
    let owner = format!("user:{}", uuid::Uuid::new_v4());
    let uri = format!("/admin/v1/federation/vaults/{owner}/promote");
    let (status, _, bytes) = call(&e.app, Method::POST, &uri, None, &[("x-admin", "1")]).await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    let problem: Value = serde_json::from_slice(&bytes).expect("a problem");
    assert_eq!(problem["type"], "urn:kemlock:problem:step-up-required");
    // A sign-in minutes old is not enough.
    let (status, _, _) = call(
        &e.app,
        Method::POST,
        &uri,
        None,
        &[("x-admin", "1"), ("x-fresh", "1")],
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    // With a step-up token it gets as far as the vault, which this server doesn't hold.
    let (status, _, _) = call(
        &e.app,
        Method::POST,
        &uri,
        None,
        &[("x-admin", "1"), ("x-step-up", "1")],
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn accepting_a_demotion_needs_a_step_up_token_and_a_held_promotion() {
    let e = env(1, Arc::new(Dead));
    let owner = format!("user:{}", uuid::Uuid::new_v4());
    let uri = format!("/admin/v1/federation/vaults/{owner}/demotion");
    let (status, _, bytes) = call(&e.app, Method::POST, &uri, None, &[("x-admin", "1")]).await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    let problem: Value = serde_json::from_slice(&bytes).expect("a problem");
    assert_eq!(problem["type"], "urn:kemlock:problem:step-up-required");
    // With a step-up token it gets as far as the vault, which this server doesn't hold.
    let (status, _, _) = call(
        &e.app,
        Method::POST,
        &uri,
        None,
        &[("x-admin", "1"), ("x-step-up", "1")],
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn a_policy_names_paired_replicas_and_a_good_owner() {
    let e = env(1, Arc::new(Dead));
    let owner = format!("user:{}", uuid::Uuid::new_v4());
    let uri = format!("/admin/v1/federation/vaults/{owner}");
    // A replica this server isn't paired with.
    let (status, _) = admin(
        &e.app,
        Method::PUT,
        &uri,
        Some(json!({"policy": "federated", "replicas": [uuid::Uuid::new_v4()]})),
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    // Federated with no replica.
    let (status, _) = admin(
        &e.app,
        Method::PUT,
        &uri,
        Some(json!({"policy": "federated", "replicas": []})),
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT);
    // Unknown policy, unknown field, bad owner.
    let (status, _) = admin(&e.app, Method::PUT, &uri, Some(json!({"policy": "both"}))).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    let (status, _) = admin(
        &e.app,
        Method::PUT,
        &uri,
        Some(json!({"policy": "local", "extra": 1})),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    let (status, _) = admin(
        &e.app,
        Method::PUT,
        "/admin/v1/federation/vaults/team:nope",
        Some(json!({"policy": "local"})),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    // Local is the default and is accepted.
    let (status, vault) = admin(&e.app, Method::PUT, &uri, Some(json!({"policy": "local"}))).await;
    assert_eq!(status, StatusCode::OK, "{vault}");
    assert_eq!(vault["policy"], "local");
    assert_eq!(vault["isHome"], true);
    let (_, vaults) = admin(&e.app, Method::GET, "/admin/v1/federation/vaults", None).await;
    assert_eq!(vaults.as_array().expect("a list").len(), 1);
}

#[tokio::test]
async fn log_switches_and_revoking_need_a_known_peer() {
    let e = env(1, Arc::new(Dead));
    let id = uuid::Uuid::new_v4();
    let (status, _) = admin(
        &e.app,
        Method::PUT,
        &format!("/admin/v1/federation/peers/{id}/logs"),
        Some(json!({"send": true, "pull": false})),
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    let (status, _) = admin(
        &e.app,
        Method::DELETE,
        &format!("/admin/v1/federation/peers/{id}"),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    let (status, _) = admin(
        &e.app,
        Method::DELETE,
        &format!("/admin/v1/federation/pairings/{id}"),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn every_federation_write_asks_for_a_step_up_token() {
    let e = env(1, Arc::new(Dead));
    let id = uuid::Uuid::new_v4();
    let owner = format!("user:{}", uuid::Uuid::new_v4());
    let base = "/admin/v1/federation";
    let ack = json!({"metadata": true, "deletion": true, "crossBorder": true, "by": "admin"});
    for (method, uri, body) in [
        (
            Method::POST,
            format!("{base}/pairing"),
            Some(json!({"address": "http://b.example.org", "code": "x"})),
        ),
        (
            Method::POST,
            format!("{base}/pairings/{id}/confirm"),
            Some(json!({"fingerprintMatches": true, "acknowledgement": ack})),
        ),
        (Method::DELETE, format!("{base}/pairings/{id}"), None),
        (
            Method::PUT,
            format!("{base}/peers/{id}/logs"),
            Some(json!({"send": true, "pull": false})),
        ),
        (Method::POST, format!("{base}/peers/{id}/revoke"), None),
        (Method::POST, format!("{base}/peers/{id}/unpair"), None),
        (Method::DELETE, format!("{base}/peers/{id}"), None),
        (
            Method::PUT,
            format!("{base}/vaults/{owner}"),
            Some(json!({"policy": "local"})),
        ),
        (Method::POST, format!("{base}/offers/{owner}/accept"), None),
        (Method::POST, format!("{base}/offers/{owner}/decline"), None),
    ] {
        // A fresh sign-in is not a step-up token.
        for headers in [
            &[("x-admin", "1")][..],
            &[("x-admin", "1"), ("x-fresh", "1")][..],
        ] {
            let (status, _, bytes) =
                call(&e.app, method.clone(), &uri, body.clone(), headers).await;
            assert_eq!(status, StatusCode::FORBIDDEN, "{method} {uri}");
            let problem: Value = serde_json::from_slice(&bytes).expect("a problem");
            assert_eq!(
                problem["type"], "urn:kemlock:problem:step-up-required",
                "{method} {uri}"
            );
        }
    }
}

#[tokio::test]
async fn held_promotions_are_listed_and_refusing_one_needs_a_step_up_token() {
    use kemlock_domain::Owner;
    use kemlock_federation::home::{PromotionRecord, VaultFederation};
    use kemlock_federation::ports::VaultRepo;

    let e = env(1, Arc::new(Dead));
    let me = e.replica.server_id();
    let vault = Owner::User(UserId::random());
    // Another server is the home; a third one (not this server) signed a promotion for itself,
    // which this replica holds for its admin.
    let home = ServerId::random();
    let other = ServerId::random();
    let settings = VaultFederation::federated(vault, home, vec![other, me]);
    let record = PromotionRecord::build(&settings, other, unix_now()).expect("a promotion");
    let signer = kemlock_federation::testing::identity(9, unix_now(), &Suite::IMPLEMENTED);
    let held = VaultFederation {
        held_demotion: vec![record.sign(&signer.signing).expect("sign").encode()],
        ..settings
    };
    e.replica.store().put_vault(&held).await.expect("put");

    let listing = "/admin/v1/federation/promotions";
    let (status, listed) = admin(&e.app, Method::GET, listing, None).await;
    assert_eq!(status, StatusCode::OK, "{listed}");
    assert_eq!(listed[0]["vault"], vault.to_string());
    assert_eq!(listed[0]["newHome"], other.0.to_string());
    assert_eq!(listed[0]["epoch"], 2);

    let uri = format!("/admin/v1/federation/vaults/{vault}/demotion");
    // A recent sign-in is not enough to refuse: a step-up token is.
    let (status, _, bytes) = call(
        &e.app,
        Method::DELETE,
        &uri,
        None,
        &[("x-admin", "1"), ("x-fresh", "1")],
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    let problem: Value = serde_json::from_slice(&bytes).expect("a problem");
    assert_eq!(problem["type"], "urn:kemlock:problem:step-up-required");

    let (status, _) = admin(&e.app, Method::DELETE, &uri, None).await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    let (_, listed) = admin(&e.app, Method::GET, listing, None).await;
    assert_eq!(listed, json!([]));
    // Nothing is left to refuse.
    let (status, _) = admin(&e.app, Method::DELETE, &uri, None).await;
    assert_eq!(status, StatusCode::CONFLICT);
}

#[tokio::test]
async fn an_address_change_that_came_with_a_rotation_waits_for_a_step_up_token() {
    use kemlock_federation::keyrecs::{KeyStore, PendingAddresses};
    use kemlock_federation::ports::PeerRepo;

    let e = env(1, Arc::new(Dead));
    let other = identity(2, unix_now(), &Suite::IMPLEMENTED);
    e.replica
        .pin_peer(&other.descriptor, unix_now())
        .await
        .expect("pin");
    e.replica
        .store()
        .put_pending_addresses(&PendingAddresses {
            peer: other.server,
            operator: "Operator 2".to_owned(),
            addresses: vec!["https://moved.example.org".to_owned()],
            suites: other.descriptor.descriptor.suites.clone(),
            received_at: unix_now(),
        })
        .await
        .expect("put");

    let (status, listed) = admin(
        &e.app,
        Method::GET,
        "/admin/v1/federation/address-changes",
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{listed}");
    assert_eq!(listed[0]["peer"], other.server.0.to_string());
    assert_eq!(listed[0]["addresses"], json!(["https://moved.example.org"]));

    let uri = format!(
        "/admin/v1/federation/peers/{}/address-change",
        other.server.0
    );
    let (status, _, _) = call(
        &e.app,
        Method::POST,
        &uri,
        None,
        &[("x-admin", "1"), ("x-fresh", "1")],
    )
    .await;
    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "a recent sign-in is not enough"
    );
    let (status, _) = admin(&e.app, Method::POST, &uri, None).await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    let moved = e
        .replica
        .store()
        .get_peer(other.server)
        .await
        .expect("get")
        .expect("peer");
    assert_eq!(
        moved.addresses,
        vec!["https://moved.example.org".to_owned()]
    );
    let (_, listed) = admin(
        &e.app,
        Method::GET,
        "/admin/v1/federation/address-changes",
        None,
    )
    .await;
    assert_eq!(listed, json!([]));
    // Nothing is left to approve or refuse.
    let (status, _) = admin(&e.app, Method::POST, &uri, None).await;
    assert_eq!(status, StatusCode::CONFLICT);
    let (status, _) = admin(&e.app, Method::DELETE, &uri, None).await;
    assert_eq!(status, StatusCode::CONFLICT);
}

#[tokio::test]
async fn a_contested_peer_shows_as_such_and_is_trusted_again_only_with_a_step_up_token() {
    use kemlock_federation::ports::{PeerRepo, PeerState};

    let e = env(1, Arc::new(Dead));
    let other = identity(2, unix_now(), &Suite::IMPLEMENTED);
    e.replica
        .pin_peer(&other.descriptor, unix_now())
        .await
        .expect("pin");
    e.replica
        .store()
        .set_peer_state(other.server, PeerState::Contested)
        .await
        .expect("contested");

    let (_, peers) = admin(&e.app, Method::GET, "/admin/v1/federation/peers", None).await;
    assert_eq!(peers[0]["state"], "contested");

    let uri = format!("/admin/v1/federation/peers/{}/contest", other.server.0);
    let (status, _, _) = call(
        &e.app,
        Method::DELETE,
        &uri,
        None,
        &[("x-admin", "1"), ("x-fresh", "1")],
    )
    .await;
    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "a recent sign-in is not enough"
    );
    let (status, _) = admin(&e.app, Method::DELETE, &uri, None).await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    let held = e
        .replica
        .store()
        .get_peer(other.server)
        .await
        .expect("get")
        .expect("peer");
    assert_eq!(held.state, PeerState::Paired);
    // Nothing is left to settle.
    let (status, _) = admin(&e.app, Method::DELETE, &uri, None).await;
    assert_eq!(status, StatusCode::CONFLICT);
}

/// A gate that lets every request in with a step-up token and remembers what was audited.
struct Recording {
    seen: std::sync::Mutex<Vec<(&'static str, Option<String>)>>,
}

impl AdminGate for Recording {
    fn authorize<'a>(&'a self, parts: &'a Parts) -> BoxFut<'a, Result<AdminActor, GateRefusal>> {
        Box::pin(async move {
            if !parts.headers.contains_key("x-admin") {
                return Err(GateRefusal {
                    status: StatusCode::UNAUTHORIZED,
                    detail: "send x-admin",
                });
            }
            Ok(AdminActor {
                user: UserId::random(),
                fresh: false,
                step_up: parts.headers.contains_key("x-step-up"),
            })
        })
    }

    fn audit<'a>(
        &'a self,
        _actor: &'a AdminActor,
        action: &'static str,
        target: Option<String>,
    ) -> BoxFut<'a, ()> {
        Box::pin(async move {
            self.seen
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .push((action, target));
        })
    }
}

#[tokio::test]
async fn a_federation_write_that_got_past_the_step_up_check_is_audited() {
    let id = identity(1, unix_now(), &Suite::IMPLEMENTED);
    let replica = Arc::new(Replica::new(MemoryStore::new(id.server), Arc::new(id)));
    let pairings = Arc::new(Pairings::new(replica.clone(), Arc::new(Dead)));
    let runner = Arc::new(PeerRunner::new(
        replica.clone(),
        NoConnector,
        "audit".to_owned(),
    ));
    let gate = Arc::new(Recording {
        seen: std::sync::Mutex::new(Vec::new()),
    });
    let app = admin_router(AdminState {
        federation: Federation::new(replica, runner, pairings),
        gate: gate.clone(),
    });
    let peer = uuid::Uuid::new_v4();
    let owner = format!("user:{}", uuid::Uuid::new_v4());
    let base = "/admin/v1/federation";

    // Turned away for lack of a step-up token: nothing happened, nothing is logged.
    let (status, _, _) = call(
        &app,
        Method::POST,
        &format!("{base}/peers/{peer}/revoke"),
        None,
        &[("x-admin", "1")],
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert!(
        gate.seen
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .is_empty()
    );

    // With one, the write is logged, naming the peer and never the vault.
    for (method, uri) in [
        (Method::POST, format!("{base}/peers/{peer}/revoke")),
        (Method::POST, format!("{base}/offers/{owner}/decline")),
    ] {
        let _ = call(
            &app,
            method,
            &uri,
            None,
            &[("x-admin", "1"), ("x-step-up", "1")],
        )
        .await;
    }
    let seen = gate
        .seen
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .clone();
    assert_eq!(
        seen,
        vec![
            ("federation.admin.peer_revoke", Some(format!("peer:{peer}"))),
            ("federation.admin.offer_decline", None),
        ]
    );
}

#[tokio::test]
async fn accepting_an_offer_for_an_account_copied_from_another_server_has_its_own_problem() {
    use kemlock_federation::extra::{AccountStanding, FedAdminRepo as _, StoredOffer};
    use kemlock_federation::message::OfferState;
    let e = env(1, Arc::new(Dead));
    let user = UserId::random();
    let owner = format!("user:{}", user.0);
    // This server holds the account as a copy of a third server's, and another server offers it.
    let offering = ServerId::random();
    e.replica
        .store()
        .set_account_standing(user, AccountStanding::Copy(ServerId::random()));
    e.replica
        .store()
        .put_offer(&StoredOffer {
            vault: kemlock_domain::Owner::User(user),
            home: offering,
            epoch: 1,
            replicas: vec![e.replica.server_id()],
            state: OfferState::Pending,
            received_at: unix_now(),
        })
        .await
        .expect("an offer");

    let (status, body) = admin(
        &e.app,
        Method::POST,
        &format!("/admin/v1/federation/offers/{owner}/accept"),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT, "{body}");
    assert_eq!(
        body["type"],
        "urn:kemlock:problem:account-copy-from-another-server"
    );
    assert!(
        body["detail"]
            .as_str()
            .is_some_and(|d| d.contains("re-homing"))
    );
}
