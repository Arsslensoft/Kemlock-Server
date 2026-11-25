use super::dispatch::{DirectSenders, PushDispatcher};
use super::*;
use crate::audience::UserOnly;
use crate::testing::{MemoryPush, TaggedSeal, eventually, serve};
use axum::extract::{Path, State};
use axum::http::{HeaderMap, StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::routing::{delete, post};
use axum::{Json, Router};
use kemlock_domain::{Owner, SpaceId, UserId};
use serde_json::{Value, json};
use std::sync::{Arc, Mutex};

/// The `Authorization` header for `inst-1:key-1`.
const GOOD_AUTH: &str = "aW5zdC0xOmtleS0x";

/// A relay that follows docs/push-relay.md: it keeps what it is sent, takes `inst-1:key-1` and
/// reports the token `dead-token` as gone.
#[derive(Default)]
struct FakeRelay {
    pushes: Mutex<Vec<Value>>,
    deleted: Mutex<Vec<String>>,
}

fn authorised(headers: &HeaderMap) -> bool {
    headers
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        == Some(format!("Basic {GOOD_AUTH}").as_str())
}

async fn register() -> Response {
    (
        StatusCode::CREATED,
        Json(json!({"installationId": "inst-1", "installationKey": "key-1"})),
    )
        .into_response()
}

async fn push(
    State(relay): State<Arc<FakeRelay>>,
    headers: HeaderMap,
    Json(body): Json<Value>,
) -> Response {
    if !authorised(&headers) {
        return StatusCode::UNAUTHORIZED.into_response();
    }
    relay.pushes.lock().expect("lock").push(body.clone());
    let tokens: Vec<String> = body["tokens"]
        .as_array()
        .map(|a| {
            a.iter()
                .filter_map(|t| t["token"].as_str().map(str::to_owned))
                .collect()
        })
        .unwrap_or_default();
    let rejected: Vec<&String> = tokens.iter().filter(|t| *t == "dead-token").collect();
    (
        StatusCode::ACCEPTED,
        Json(json!({"accepted": tokens.len() - rejected.len(), "rejected": rejected})),
    )
        .into_response()
}

async fn erase(
    State(relay): State<Arc<FakeRelay>>,
    Path(id): Path<String>,
    headers: HeaderMap,
) -> StatusCode {
    if !authorised(&headers) {
        return StatusCode::UNAUTHORIZED;
    }
    relay.deleted.lock().expect("lock").push(id);
    StatusCode::NO_CONTENT
}

async fn relay() -> (Arc<FakeRelay>, RelayClient) {
    let state = Arc::new(FakeRelay::default());
    let app = Router::new()
        .route("/v1/installations", post(register))
        .route("/v1/installations/{id}", delete(erase))
        .route("/v1/push", post(push))
        .with_state(state.clone());
    let address = serve(app).await;
    let client = RelayClient::new(&format!("http://{address}/")).expect("client");
    (state, client)
}

fn good() -> Installation {
    Installation {
        id: "inst-1".to_owned(),
        key: Zeroizing::new("key-1".to_owned()),
    }
}

fn target(token: &str) -> PushTarget {
    PushTarget {
        kind: PushKind::Apns,
        token: token.to_owned(),
    }
}

#[tokio::test]
async fn the_server_registers_and_gets_an_id_and_a_key() {
    let (_, client) = relay().await;
    let installation = client.register_installation().await.expect("registers");
    assert_eq!(installation.id, "inst-1");
    assert_eq!(installation.key.as_str(), "key-1");
    assert!(!format!("{installation:?}").contains("key-1"));
}

#[tokio::test]
async fn a_send_carries_tokens_and_the_nudge_and_nothing_else() {
    let (state, client) = relay().await;
    let outcome = client
        .send_sync(
            &good(),
            &[
                target("tok-a"),
                target("tok-b"),
            ],
        )
        .await
        .expect("sends");
    assert_eq!(outcome.accepted, 2);
    assert!(outcome.rejected.is_empty());
    let pushes = state.pushes.lock().expect("lock");
    assert_eq!(
        pushes.as_slice(),
        &[json!({
            "type": "sync",
            "tokens": [
                {"kind": "apns", "token": "tok-a"},
                {"kind": "apns", "token": "tok-b"}
            ]
        })]
    );
}

#[tokio::test]
async fn dead_tokens_come_back_as_rejected() {
    let (_, client) = relay().await;
    let outcome = client
        .send_sync(&good(), &[target("ok"), target("dead-token")])
        .await
        .expect("sends");
    assert_eq!(outcome.accepted, 1);
    assert_eq!(outcome.rejected, vec!["dead-token".to_owned()]);
}

#[tokio::test]
async fn a_wrong_key_is_unauthorized() {
    let (state, client) = relay().await;
    let wrong = Installation {
        id: "inst-1".to_owned(),
        key: Zeroizing::new("wrong".to_owned()),
    };
    assert_eq!(
        client.send_sync(&wrong, &[target("t")]).await,
        Err(RelayError::Unauthorized)
    );
    assert!(state.pushes.lock().expect("lock").is_empty());
}

#[tokio::test]
async fn many_tokens_go_in_several_sends() {
    let (state, client) = relay().await;
    let targets: Vec<PushTarget> = (0..MAX_TOKENS_PER_SEND * 2 + 5)
        .map(|i| target(&format!("t{i}")))
        .collect();
    let outcome = client.send_sync(&good(), &targets).await.expect("sends");
    assert_eq!(outcome.accepted, targets.len());
    assert_eq!(state.pushes.lock().expect("lock").len(), 3);
}

#[tokio::test]
async fn too_many_sends_say_how_long_to_wait() {
    async fn slow() -> Response {
        (StatusCode::TOO_MANY_REQUESTS, [(header::RETRY_AFTER, "7")]).into_response()
    }
    let address = serve(Router::new().route("/v1/push", post(slow))).await;
    let client = RelayClient::new(&format!("http://{address}")).expect("client");
    assert_eq!(
        client.send_sync(&good(), &[target("t")]).await,
        Err(RelayError::SlowDown(7))
    );
}

#[tokio::test]
async fn an_unreachable_relay_is_a_transport_error() {
    let address = {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("binds");
        listener.local_addr().expect("address")
    };
    let client = RelayClient::new(&format!("http://{address}")).expect("client");
    assert!(matches!(
        client.send_sync(&good(), &[target("t")]).await,
        Err(RelayError::Transport(_))
    ));
}

#[test]
fn the_key_only_travels_over_https_or_loopback() {
    assert!(RelayClient::new("https://push.example.com").is_ok());
    assert!(RelayClient::new("http://127.0.0.1:8080").is_ok());
    assert!(RelayClient::new("http://localhost:8080/").is_ok());
    assert_eq!(
        RelayClient::new("http://push.example.com").expect_err("plain http elsewhere is refused"),
        RelayError::BadUrl
    );
    assert_eq!(
        RelayClient::new("ftp://x").expect_err("only https is a relay"),
        RelayError::BadUrl
    );
}

#[tokio::test]
async fn opting_in_stores_the_id_and_a_sealed_key() {
    let (_, client) = relay().await;
    let repo = MemoryPush::default();
    let id = enable_relay(&repo, &TaggedSeal, &client)
        .await
        .expect("enables");
    assert_eq!(id, "inst-1");
    let stored = repo
        .installation()
        .await
        .expect("reads")
        .expect("an installation");
    assert_eq!(stored.id, "inst-1");
    assert!(
        !stored.sealed_key.windows(5).any(|w| w == b"key-1"),
        "the key is not stored as given"
    );
    let opened = open_installation(&repo, &TaggedSeal)
        .await
        .expect("reads")
        .expect("opens");
    assert_eq!(opened.key.as_str(), "key-1");
}

#[tokio::test]
async fn an_installation_sealed_for_another_purpose_does_not_open() {
    let repo = MemoryPush::default();
    repo.set_installation(&PushInstallation {
        id: "inst-1".to_owned(),
        sealed_key: TaggedSeal.seal("something-else", b"key-1"),
    })
    .await
    .expect("sets");
    assert!(
        open_installation(&repo, &TaggedSeal)
            .await
            .expect("reads")
            .is_none()
    );
}

#[tokio::test]
async fn opting_out_erases_at_the_relay_and_here() {
    let (state, client) = relay().await;
    let repo = MemoryPush::default();
    enable_relay(&repo, &TaggedSeal, &client)
        .await
        .expect("enables");
    disable_relay(&repo, &TaggedSeal, &client)
        .await
        .expect("disables");
    assert_eq!(
        *state.deleted.lock().expect("lock"),
        vec!["inst-1".to_owned()]
    );
    assert!(repo.installation().await.expect("reads").is_none());
}

#[tokio::test]
async fn opting_out_works_when_the_relay_is_down() {
    let repo = MemoryPush::default();
    repo.set_installation(&PushInstallation {
        id: "inst-1".to_owned(),
        sealed_key: TaggedSeal.seal(PURPOSE_PUSH_INSTALLATION_KEY, b"key-1"),
    })
    .await
    .expect("sets");
    let address = {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("binds");
        listener.local_addr().expect("address")
    };
    let client = RelayClient::new(&format!("http://{address}")).expect("client");
    let result = disable_relay(&repo, &TaggedSeal, &client).await;
    assert!(result.is_err(), "the failure is reported");
    assert!(
        repo.installation().await.expect("reads").is_none(),
        "but the operator is no longer opted in"
    );
}

const WINDOW: Duration = Duration::from_millis(40);

async fn opted_in() -> (Arc<FakeRelay>, MemoryPush, PushDispatcher) {
    let (state, client) = relay().await;
    let repo = MemoryPush::default();
    enable_relay(&repo, &TaggedSeal, &client)
        .await
        .expect("enables");
    let dispatcher = PushDispatcher::start(
        repo.clone(),
        UserOnly,
        TaggedSeal,
        client,
        DirectSenders::default(),
        WINDOW,
    );
    (state, repo, dispatcher)
}

#[tokio::test]
async fn a_burst_of_nudges_is_one_push_per_device() {
    let (state, repo, dispatcher) = opted_in().await;
    let ada = UserId::random();
    repo.add(ada, "phone");
    repo.add(ada, "tablet");
    repo.add(UserId::random(), "someone-else");
    for _ in 0..20 {
        dispatcher.nudge(Owner::User(ada));
    }
    eventually(|| !state.pushes.lock().expect("lock").is_empty()).await;
    tokio::time::sleep(WINDOW * 3).await;
    let pushes = state.pushes.lock().expect("lock");
    assert_eq!(pushes.len(), 1, "one send for the whole burst");
    let mut tokens: Vec<String> = pushes[0]["tokens"]
        .as_array()
        .expect("tokens")
        .iter()
        .map(|t| t["token"].as_str().expect("token").to_owned())
        .collect();
    tokens.sort();
    assert_eq!(tokens, ["phone", "tablet"], "only the owner's devices");
}

#[tokio::test]
async fn a_space_nobody_hears_of_pushes_nothing() {
    let (state, repo, dispatcher) = opted_in().await;
    repo.add(UserId::random(), "phone");
    dispatcher.nudge(Owner::Space(SpaceId::random()));
    tokio::time::sleep(WINDOW * 4).await;
    assert!(state.pushes.lock().expect("lock").is_empty());
}

#[tokio::test]
async fn without_an_installation_nothing_is_sent() {
    let (state, client) = relay().await;
    let repo = MemoryPush::default();
    let ada = UserId::random();
    repo.add(ada, "phone");
    let dispatcher = PushDispatcher::start(
        repo,
        UserOnly,
        TaggedSeal,
        client,
        DirectSenders::default(),
        WINDOW,
    );
    dispatcher.nudge(Owner::User(ada));
    tokio::time::sleep(WINDOW * 4).await;
    assert!(state.pushes.lock().expect("lock").is_empty());
}

#[tokio::test]
async fn a_token_the_relay_calls_dead_is_forgotten() {
    let (state, repo, dispatcher) = opted_in().await;
    let ada = UserId::random();
    repo.add(ada, "alive");
    repo.add(ada, "dead-token");
    dispatcher.nudge(Owner::User(ada));
    eventually(|| repo.tokens() == ["alive"]).await;
    assert_eq!(state.pushes.lock().expect("lock").len(), 1);
}

#[tokio::test]
async fn pushes_continue_after_the_relay_failed_once() {
    let (state, repo, dispatcher) = opted_in().await;
    let ada = UserId::random();
    repo.add(ada, "phone");
    // A bad key makes the first send fail...
    repo.set_installation(&PushInstallation {
        id: "inst-1".to_owned(),
        sealed_key: TaggedSeal.seal(PURPOSE_PUSH_INSTALLATION_KEY, b"wrong"),
    })
    .await
    .expect("sets");
    dispatcher.nudge(Owner::User(ada));
    tokio::time::sleep(WINDOW * 4).await;
    assert!(state.pushes.lock().expect("lock").is_empty());
    // ...and the worker is still alive for the next one.
    repo.set_installation(&PushInstallation {
        id: "inst-1".to_owned(),
        sealed_key: TaggedSeal.seal(PURPOSE_PUSH_INSTALLATION_KEY, b"key-1"),
    })
    .await
    .expect("sets");
    dispatcher.nudge(Owner::User(ada));
    eventually(|| state.pushes.lock().expect("lock").len() == 1).await;
}

// ---- routing: Apple direct, the relay as a fallback, UnifiedPush direct, Firebase ignored ----

/// What the fake Apple and the fake UnifiedPush distributor were asked.
#[derive(Default)]
struct Pushed {
    apple: Mutex<Vec<String>>,
    distributor: Mutex<Vec<String>>,
}

async fn apple(State(pushed): State<Arc<Pushed>>, Path(token): Path<String>) -> Response {
    pushed.apple.lock().expect("lock").push(token.clone());
    if token == "dead0410" {
        return (StatusCode::GONE, Json(json!({"reason": "Unregistered"}))).into_response();
    }
    StatusCode::OK.into_response()
}

async fn distributor(State(pushed): State<Arc<Pushed>>, uri: axum::http::Uri) -> Response {
    pushed
        .distributor
        .lock()
        .expect("lock")
        .push(uri.path().to_owned());
    if uri.path() == "/gone" {
        return StatusCode::GONE.into_response();
    }
    StatusCode::CREATED.into_response()
}

/// A server with a fake Apple and distributor, a fake relay, and the dispatcher over all three.
/// `with_apple` says whether the server holds an Apple key, `opted_in` whether the operator
/// turned the relay on.
async fn everything(
    with_apple: bool,
    opted_in: bool,
) -> (Arc<Pushed>, Arc<FakeRelay>, String, MemoryPush, PushDispatcher) {
    let pushed = Arc::new(Pushed::default());
    let apple_address = serve(
        Router::new()
            .route("/3/device/{token}", post(apple))
            .with_state(pushed.clone()),
    )
    .await;
    let distributor_address = serve(
        Router::new()
            .fallback(distributor)
            .with_state(pushed.clone()),
    )
    .await;
    let (relay_state, client) = relay().await;
    let repo = MemoryPush::default();
    if opted_in {
        enable_relay(&repo, &TaggedSeal, &client)
            .await
            .expect("enables");
    }
    let direct = DirectSenders {
        apns: with_apple.then(|| {
            ApnsSender::with_base(apns::test_config(), &format!("http://{apple_address}"))
                .expect("apple")
        }),
        unified_push: UnifiedPushSender::allowing_local(),
    };
    let dispatcher =
        PushDispatcher::start(repo.clone(), UserOnly, TaggedSeal, client, direct, WINDOW);
    (
        pushed,
        relay_state,
        format!("http://{distributor_address}"),
        repo,
        dispatcher,
    )
}

#[tokio::test]
async fn an_iphone_is_pushed_to_directly_when_the_server_has_an_apple_key() {
    let (pushed, relay, _, repo, dispatcher) = everything(true, true).await;
    let ada = UserId::random();
    repo.add(ada, "c0ffee01");
    dispatcher.nudge(Owner::User(ada));
    eventually(|| !pushed.apple.lock().expect("lock").is_empty()).await;
    tokio::time::sleep(WINDOW * 3).await;
    assert_eq!(*pushed.apple.lock().expect("lock"), ["c0ffee01"]);
    // The relay, though the operator turned it on, hears nothing: Apple is the better way.
    assert!(relay.pushes.lock().expect("lock").is_empty());
}

#[tokio::test]
async fn an_iphone_goes_through_the_relay_when_there_is_no_apple_key_and_the_relay_is_on() {
    let (pushed, relay, _, repo, dispatcher) = everything(false, true).await;
    let ada = UserId::random();
    repo.add(ada, "c0ffee01");
    dispatcher.nudge(Owner::User(ada));
    eventually(|| !relay.pushes.lock().expect("lock").is_empty()).await;
    assert!(pushed.apple.lock().expect("lock").is_empty());
}

#[tokio::test]
async fn an_iphone_is_skipped_with_no_apple_key_and_no_relay() {
    let (pushed, relay, _, repo, dispatcher) = everything(false, false).await;
    let ada = UserId::random();
    repo.add(ada, "c0ffee01");
    dispatcher.nudge(Owner::User(ada));
    tokio::time::sleep(WINDOW * 4).await;
    assert!(pushed.apple.lock().expect("lock").is_empty());
    assert!(relay.pushes.lock().expect("lock").is_empty());
    assert_eq!(repo.tokens(), ["c0ffee01"], "the token is kept for later");
}

#[tokio::test]
async fn a_unifiedpush_phone_is_pushed_to_directly_whatever_the_relay_says() {
    for (with_apple, opted_in) in [(false, false), (true, false), (false, true)] {
        let (pushed, relay, base, repo, dispatcher) = everything(with_apple, opted_in).await;
        let ada = UserId::random();
        repo.add_kind(ada, PushKind::UnifiedPush, &format!("{base}/up123"));
        dispatcher.nudge(Owner::User(ada));
        eventually(|| !pushed.distributor.lock().expect("lock").is_empty()).await;
        assert_eq!(*pushed.distributor.lock().expect("lock"), ["/up123"]);
        assert!(relay.pushes.lock().expect("lock").is_empty());
        assert!(pushed.apple.lock().expect("lock").is_empty());
    }
}

#[tokio::test]
async fn one_nudge_reaches_each_phone_by_its_own_way() {
    let (pushed, _, base, repo, dispatcher) = everything(true, false).await;
    let ada = UserId::random();
    repo.add(ada, "c0ffee01");
    repo.add_kind(ada, PushKind::UnifiedPush, &format!("{base}/up1"));
    repo.add_kind(ada, PushKind::UnifiedPush, &format!("{base}/up2"));
    for _ in 0..10 {
        dispatcher.nudge(Owner::User(ada));
    }
    eventually(|| pushed.distributor.lock().expect("lock").len() == 2).await;
    tokio::time::sleep(WINDOW * 3).await;
    let mut seen = pushed.distributor.lock().expect("lock").clone();
    seen.sort();
    assert_eq!(seen, ["/up1", "/up2"], "once each for the whole burst");
    assert_eq!(*pushed.apple.lock().expect("lock"), ["c0ffee01"]);
}

#[tokio::test]
async fn a_firebase_token_is_never_sent_to_and_never_crashes_anything() {
    let (pushed, relay, _, repo, dispatcher) = everything(true, true).await;
    let ada = UserId::random();
    repo.add_kind(ada, PushKind::Fcm, "old-firebase-token");
    dispatcher.nudge(Owner::User(ada));
    tokio::time::sleep(WINDOW * 4).await;
    assert!(pushed.apple.lock().expect("lock").is_empty());
    assert!(pushed.distributor.lock().expect("lock").is_empty());
    assert!(relay.pushes.lock().expect("lock").is_empty());
    assert_eq!(repo.tokens(), ["old-firebase-token"]);
}

#[tokio::test]
async fn tokens_that_apple_or_a_distributor_no_longer_know_are_forgotten() {
    let (_, _, base, repo, dispatcher) = everything(true, false).await;
    let ada = UserId::random();
    repo.add(ada, "dead0410");
    repo.add(ada, "c0ffee01");
    repo.add_kind(ada, PushKind::UnifiedPush, &format!("{base}/gone"));
    let fine = format!("{base}/fine");
    repo.add_kind(ada, PushKind::UnifiedPush, &fine);
    dispatcher.nudge(Owner::User(ada));
    let mut kept = vec!["c0ffee01".to_owned(), fine];
    kept.sort();
    eventually(|| repo.tokens() == kept).await;
}
