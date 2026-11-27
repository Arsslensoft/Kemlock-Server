//! The `/fed/v1` routes: the descriptor documents, and a peer session driven over channels.

use axum::body::{Body, to_bytes};
use axum::http::{Request, StatusCode, header};
use kemlock_api_fed::{
    DESCRIPTOR_MEDIA_TYPE, Duplex, FedEvent, FedState, SessionEnd, router, serve,
    serve_session_within,
};
use kemlock_domain::{ItemId, Owner, UserId};
use kemlock_federation::memory::MemoryStore;
use kemlock_federation::testing::{draft, identity};
use kemlock_federation::{FedError, Replica, SignedDescriptor, Suite, Transport, unix_now};
use std::sync::Arc;
use tokio::sync::mpsc;
use tower::ServiceExt as _;

type Server = Arc<Replica<MemoryStore>>;

fn server(seed: u8) -> Server {
    let id = identity(seed, unix_now(), &Suite::IMPLEMENTED);
    Arc::new(Replica::new(MemoryStore::new(id.server), Arc::new(id)))
}

async fn pin_each_other(a: &Server, b: &Server) {
    let now = unix_now();
    a.pin_peer(&b.identity().descriptor, now)
        .await
        .expect("A pins B");
    b.pin_peer(&a.identity().descriptor, now)
        .await
        .expect("B pins A");
}

struct ServerEnd {
    from_client: mpsc::Receiver<Vec<u8>>,
    to_client: mpsc::Sender<Vec<u8>>,
}

impl Duplex for ServerEnd {
    async fn recv(&mut self) -> Option<Vec<u8>> {
        self.from_client.recv().await
    }

    async fn send(&mut self, message: Vec<u8>) -> bool {
        self.to_client.send(message).await.is_ok()
    }
}

struct ClientEnd {
    to_server: mpsc::Sender<Vec<u8>>,
    from_server: mpsc::Receiver<Vec<u8>>,
}

impl Transport for ClientEnd {
    async fn exchange(&mut self, message: Vec<u8>) -> Result<Vec<u8>, FedError> {
        self.to_server
            .send(message)
            .await
            .map_err(|_| FedError::Frame("the server end is gone"))?;
        self.from_server
            .recv()
            .await
            .ok_or(FedError::Frame("the server sent nothing"))
    }
}

fn ends() -> (ServerEnd, ClientEnd) {
    let (to_server, from_client) = mpsc::channel(8);
    let (to_client, from_server) = mpsc::channel(8);
    (
        ServerEnd {
            from_client,
            to_client,
        },
        ClientEnd {
            to_server,
            from_server,
        },
    )
}

async fn get(app: axum::Router, uri: &str) -> (StatusCode, axum::http::HeaderMap, Vec<u8>) {
    let response = app
        .oneshot(
            Request::builder()
                .uri(uri)
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
    (status, headers, body.to_vec())
}

#[tokio::test]
async fn the_descriptor_is_served_at_both_paths_and_verifies() {
    let a = server(1);
    let app = router(FedState::new(a.clone()));
    for path in ["/fed/v1/descriptor", "/.well-known/kemlock-federation"] {
        let (status, headers, body) = get(app.clone(), path).await;
        assert_eq!(status, StatusCode::OK, "{path}");
        assert_eq!(
            headers
                .get(header::CONTENT_TYPE)
                .and_then(|v| v.to_str().ok()),
            Some(DESCRIPTOR_MEDIA_TYPE)
        );
        let parsed = SignedDescriptor::parse(&body).expect("a descriptor");
        parsed
            .verify(unix_now(), Some(&a.identity().public))
            .expect("signed by the identity key");
        assert_eq!(parsed.descriptor.server, a.server_id());
        assert_eq!(parsed, a.identity().descriptor);
    }
}

#[tokio::test]
async fn unknown_paths_and_a_plain_get_of_the_session_are_not_a_session() {
    let app = router(FedState::new(server(1)));
    let (status, _, _) = get(app.clone(), "/fed/v1/nothing").await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    // Without the WebSocket upgrade headers the session route refuses.
    let (status, _, _) = get(app, "/fed/v1/session").await;
    assert_ne!(status, StatusCode::OK);
}

#[tokio::test]
async fn a_paired_peer_opens_a_session_pulls_items_and_closes() {
    let a = server(2);
    let b = server(3);
    pin_each_other(&a, &b).await;
    let vault = Owner::User(UserId::random());
    a.federate(vault, vec![b.server_id()])
        .await
        .expect("federate");
    b.accept_vault(vault, a.server_id(), vec![b.server_id()])
        .await
        .expect("accept");
    a.store()
        .put(draft(ItemId::random(), vault, None, 1, 1_000))
        .expect("put");

    let (events_tx, mut events) = mpsc::unbounded_channel();
    let state = FedState::new(a.clone()).with_events(events_tx);
    let (mut server_end, client_end) = ends();
    let running = tokio::spawn(async move { serve(&state, &mut server_end).await });

    let mut channel = b
        .connect(
            a.server_id(),
            &a.identity().descriptor,
            client_end,
            unix_now(),
        )
        .await
        .expect("connect");
    let report = b
        .pull(&mut channel, a.server_id(), vault)
        .await
        .expect("pull");
    assert_eq!(report.counts.applied, 1);
    assert_eq!(b.store().len(), 1);

    // B has nothing A lacks, so a nudge from B asks A to pull nothing; one from A would.
    b.nudge(&mut channel, vault).await.expect("nudge");
    channel.close().await.expect("close");
    assert_eq!(running.await.expect("the session task"), SessionEnd::Closed);
    assert!(
        events.try_recv().is_err(),
        "no event for an uneventful session"
    );
}

#[tokio::test]
async fn a_nudge_that_shows_more_is_reported_to_the_replication_job() {
    let a = server(4);
    let b = server(5);
    pin_each_other(&a, &b).await;
    let vault = Owner::User(UserId::random());
    a.federate(vault, vec![b.server_id()])
        .await
        .expect("federate");
    b.accept_vault(vault, a.server_id(), vec![b.server_id()])
        .await
        .expect("accept");
    b.store()
        .put(draft(ItemId::random(), vault, None, 1, 1_000))
        .expect("put");

    let (events_tx, mut events) = mpsc::unbounded_channel();
    let state = FedState::new(a.clone()).with_events(events_tx);
    let (mut server_end, client_end) = ends();
    let running = tokio::spawn(async move { serve(&state, &mut server_end).await });
    let mut channel = b
        .connect(
            a.server_id(),
            &a.identity().descriptor,
            client_end,
            unix_now(),
        )
        .await
        .expect("connect");
    b.nudge(&mut channel, vault).await.expect("nudge");
    channel.close().await.expect("close");
    running.await.expect("the session task");
    assert_eq!(
        events.try_recv().expect("an event"),
        FedEvent::Nudge {
            peer: b.server_id(),
            vault
        }
    );
}

#[tokio::test]
async fn a_server_that_is_not_paired_is_refused_at_the_first_message() {
    let a = server(6);
    let stranger = server(7);
    // The stranger reads A's public descriptor and pins it; A never paired with the stranger.
    stranger
        .pin_peer(&a.identity().descriptor, unix_now())
        .await
        .expect("pin");

    let (events_tx, mut events) = mpsc::unbounded_channel();
    let state = FedState::new(a.clone()).with_events(events_tx);
    let (mut server_end, client_end) = ends();
    let running = tokio::spawn(async move { serve(&state, &mut server_end).await });
    let result = stranger
        .connect(
            a.server_id(),
            &a.identity().descriptor,
            client_end,
            unix_now(),
        )
        .await;
    assert!(result.is_err());
    assert_eq!(
        running.await.expect("the session task"),
        SessionEnd::Refused(FedError::UnknownPeer)
    );
    assert!(matches!(
        events.try_recv().expect("an event"),
        FedEvent::Refused { .. }
    ));
}

#[tokio::test]
async fn a_known_server_with_another_identity_key_is_reported_as_a_key_mismatch() {
    let a = server(8);
    let b = server(9);
    pin_each_other(&a, &b).await;
    // An impostor with B's server id and a different identity key, reaching A.
    let mut impostor = identity(10, unix_now(), &Suite::IMPLEMENTED);
    impostor.server = b.server_id();
    let impostor = kemlock_federation::LocalIdentity::new(
        b.server_id(),
        impostor.signing.clone(),
        impostor.kems.clone(),
        kemlock_federation::DescriptorParams {
            suites: Suite::IMPLEMENTED.to_vec(),
            addresses: vec![],
            operator: "impostor".to_owned(),
            not_before: unix_now(),
            not_after: unix_now() + 1_000,
        },
    )
    .expect("identity");
    let impostor_replica =
        Replica::new(MemoryStore::new(b.server_id()), Arc::new(impostor.clone()));
    impostor_replica
        .pin_peer(&a.identity().descriptor, unix_now())
        .await
        .expect("pin");

    let (events_tx, mut events) = mpsc::unbounded_channel();
    let state = FedState::new(a.clone()).with_events(events_tx);
    let (mut server_end, client_end) = ends();
    let running = tokio::spawn(async move { serve(&state, &mut server_end).await });
    let result = impostor_replica
        .connect(
            a.server_id(),
            &a.identity().descriptor,
            client_end,
            unix_now(),
        )
        .await;
    assert!(result.is_err());
    running.await.expect("the session task");
    match events.try_recv().expect("an event") {
        FedEvent::KeyMismatch { offered } => {
            assert_eq!(offered, impostor.public.as_bytes().to_vec());
        }
        other => panic!("expected a key mismatch, got {other:?}"),
    }
}

#[tokio::test]
async fn a_connection_that_never_sends_its_hello_is_let_go() {
    let state = FedState::new(server(1));
    let (mut server_end, client_end) = ends();
    // The client end stays open and says nothing.
    let ended = tokio::time::timeout(
        std::time::Duration::from_secs(5),
        serve_session_within(
            &state,
            &mut server_end,
            unix_now,
            std::time::Duration::from_millis(50),
        ),
    )
    .await
    .expect("the session gave up on its own");
    assert_eq!(ended, SessionEnd::Cut);
    drop(client_end);
}
