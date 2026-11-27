use super::super::message::{HANDSHAKE_RESPONSE, MSGPACK_PING, read_varint};
use super::*;
use crate::audience::UserOnly;
use crate::testing::{eventually, serve_with_peers};
use futures_util::{SinkExt, StreamExt};
use kemlock_domain::SpaceId;
use rmpv::Value;
use tokio_tungstenite::tungstenite::client::IntoClientRequest;
use tokio_tungstenite::tungstenite::{self, Message as Wire};
use tokio_tungstenite::{MaybeTlsStream, WebSocketStream, connect_async};
use uuid::Uuid;

type Client = WebSocketStream<MaybeTlsStream<tokio::net::TcpStream>>;

const MSGPACK_HANDSHAKE: &str = "{\"protocol\":\"messagepack\",\"version\":1}\u{1e}";
const JSON_HANDSHAKE: &str = "{\"protocol\":\"json\",\"version\":1}\u{1e}";

/// Tokens `ada`, `grace` and `bad`.
struct Tokens {
    ada: UserId,
    grace: UserId,
}

impl HubAuth for Tokens {
    fn authenticate(&self, token: &str) -> BoxFuture<'_, Option<HubIdentity>> {
        let user = match token {
            "ada" => Some(self.ada),
            "grace" => Some(self.grace),
            _ => None,
        };
        Box::pin(async move { user.map(|user| HubIdentity { user, device: None }) })
    }
}

/// Everyone in a space: ada and grace.
struct Both(UserId, UserId);

impl Audience for Both {
    fn users(&self, owner: Owner) -> BoxFuture<'_, Vec<UserId>> {
        Box::pin(async move {
            match owner {
                Owner::User(user) => vec![user],
                Owner::Space(_) => vec![self.0, self.1],
            }
        })
    }
}

struct Rig {
    hub: BwHub,
    address: SocketAddr,
    ada: UserId,
    grace: UserId,
}

async fn rig_with(config: HubConfig) -> Rig {
    let (ada, grace) = (UserId::random(), UserId::random());
    let hub = BwHub::new(Arc::new(Both(ada, grace)), config);
    let auth = Arc::new(Tokens { ada, grace });
    let address = serve_with_peers(router(hub.clone(), auth)).await;
    Rig {
        hub,
        address,
        ada,
        grace,
    }
}

async fn rig() -> Rig {
    rig_with(HubConfig::default()).await
}

impl Rig {
    fn url(&self, path: &str) -> String {
        format!("ws://{}{path}", self.address)
    }

    async fn connect(&self, path: &str) -> Client {
        connect_async(self.url(path))
            .await
            .expect("the socket opens")
            .0
    }

    /// Opens the account's socket and finishes the handshake.
    async fn open(&self, token: &str, handshake: &str) -> Client {
        let mut client = self
            .connect(&format!("/notifications/hub?access_token={token}"))
            .await;
        client
            .send(Wire::text(handshake))
            .await
            .expect("handshake sent");
        let reply = next(&mut client).await;
        match reply {
            Wire::Binary(bytes) => assert_eq!(bytes.as_ref(), HANDSHAKE_RESPONSE),
            Wire::Text(text) => assert_eq!(text.as_str(), "{}\u{1e}"),
            other => panic!("unexpected handshake reply {other:?}"),
        }
        client
    }
}

/// The next data frame, skipping pings, within five seconds.
async fn next(client: &mut Client) -> Wire {
    loop {
        let frame = tokio::time::timeout(Duration::from_secs(5), client.next())
            .await
            .expect("a frame in time")
            .expect("the stream is open")
            .expect("no error");
        if !matches!(frame, Wire::Ping(_) | Wire::Pong(_)) {
            return frame;
        }
    }
}

/// Decodes a MessagePack invocation frame into its `ReceiveMessage` argument.
fn argument(frame: &Wire) -> (String, Value) {
    let Wire::Binary(bytes) = frame else {
        panic!("not a binary frame: {frame:?}");
    };
    let (length, used) = read_varint(bytes).expect("a length");
    assert_eq!(length, bytes.len() - used);
    let value = rmpv::decode::read_value(&mut &bytes[used..]).expect("msgpack");
    let parts = value.as_array().expect("an invocation");
    let target = parts[3].as_str().expect("a target").to_owned();
    (target, parts[4].as_array().expect("arguments")[0].clone())
}

fn get<'a>(map: &'a Value, key: &str) -> &'a Value {
    map.as_map()
        .expect("a map")
        .iter()
        .find(|(k, _)| k.as_str() == Some(key))
        .map(|(_, v)| v)
        .unwrap_or_else(|| panic!("no {key}"))
}

fn sync_type(frame: &Wire) -> i64 {
    get(&argument(frame).1, "Type").as_i64().expect("a type")
}

#[tokio::test]
async fn a_missing_or_bad_token_is_a_401_before_any_upgrade() {
    let rig = rig().await;
    for path in [
        "/notifications/hub",
        "/notifications/hub?access_token=",
        "/notifications/hub?access_token=bad",
    ] {
        match connect_async(rig.url(path)).await {
            Err(tungstenite::Error::Http(response)) => {
                assert_eq!(response.status(), 401, "{path}");
            }
            other => panic!("{path}: {:?}", other.map(|_| ())),
        }
    }
    // A plain request without a token is a 401 too, not a complaint about the upgrade.
    let response = reqwest::get(format!("http://{}/notifications/hub", rig.address))
        .await
        .expect("answers");
    assert_eq!(response.status(), 401);
    assert_eq!(rig.hub.connections(), 0);
}

#[tokio::test]
async fn a_bearer_header_works_as_the_query_does() {
    let rig = rig().await;
    let mut request = rig
        .url("/notifications/hub")
        .into_client_request()
        .expect("a request");
    request
        .headers_mut()
        .insert("Authorization", "Bearer ada".parse().expect("a header"));
    let (_client, response) = connect_async(request).await.expect("opens");
    assert_eq!(response.status(), 101);
}

#[tokio::test]
async fn a_valid_token_without_an_upgrade_is_refused_but_not_as_a_401() {
    let rig = rig().await;
    let response = reqwest::get(format!(
        "http://{}/notifications/hub?access_token=ada",
        rig.address
    ))
    .await
    .expect("answers");
    assert_ne!(response.status(), 401);
    assert!(response.status().is_client_error());
}

#[tokio::test]
async fn negotiation_offers_websockets_only() {
    let rig = rig().await;
    let response = reqwest::Client::new()
        .post(format!(
            "http://{}/notifications/hub/negotiate?negotiateVersion=1",
            rig.address
        ))
        .send()
        .await
        .expect("answers");
    assert_eq!(response.status(), 200);
    let body: serde_json::Value = response.json().await.expect("json");
    assert!(body["connectionId"].as_str().is_some_and(|s| s.len() >= 16));
    assert_eq!(
        body["availableTransports"],
        serde_json::json!([{"transport": "WebSockets", "transferFormats": ["Binary"]}])
    );
}

#[tokio::test]
async fn the_handshake_is_answered_with_an_empty_object_in_binary() {
    let rig = rig().await;
    let mut client = rig.connect("/notifications/hub?access_token=ada").await;
    client
        .send(Wire::text(MSGPACK_HANDSHAKE))
        .await
        .expect("sent");
    let reply = next(&mut client).await;
    assert!(matches!(&reply, Wire::Binary(b) if b.as_ref() == [0x7b, 0x7d, 0x1e]));
}

#[tokio::test]
async fn a_sync_update_reaches_the_account_in_messagepack() {
    let rig = rig().await;
    let mut ada = rig.open("ada", MSGPACK_HANDSHAKE).await;
    eventually(|| rig.hub.connections() == 1).await;
    rig.hub.send(
        rig.ada,
        Message::user_update(UpdateType::SyncVault, rig.ada.0, OffsetDateTime::now_utc()),
    );
    let frame = next(&mut ada).await;
    let (target, arg) = argument(&frame);
    assert_eq!(target, "ReceiveMessage");
    assert_eq!(get(&arg, "Type").as_i64(), Some(5));
    assert_eq!(
        get(get(&arg, "Payload"), "UserId").as_str(),
        Some(rig.ada.to_string().as_str())
    );
}

#[tokio::test]
async fn an_update_reaches_only_its_accounts_sockets() {
    let rig = rig().await;
    let mut ada = rig.open("ada", MSGPACK_HANDSHAKE).await;
    let mut grace = rig.open("grace", MSGPACK_HANDSHAKE).await;
    eventually(|| rig.hub.connections() == 2).await;
    rig.hub.send(
        rig.grace,
        Message::user_update(
            UpdateType::SyncSettings,
            rig.grace.0,
            OffsetDateTime::now_utc(),
        ),
    );
    rig.hub.send(
        rig.ada,
        Message::user_update(
            UpdateType::SyncCiphers,
            rig.ada.0,
            OffsetDateTime::now_utc(),
        ),
    );
    // Each socket's first update is its own account's.
    assert_eq!(sync_type(&next(&mut grace).await), 10);
    assert_eq!(sync_type(&next(&mut ada).await), 4);
}

#[tokio::test]
async fn two_sockets_of_one_account_both_hear() {
    let rig = rig().await;
    let mut first = rig.open("ada", MSGPACK_HANDSHAKE).await;
    let mut second = rig.open("ada", MSGPACK_HANDSHAKE).await;
    eventually(|| rig.hub.connections() == 2).await;
    rig.hub.nudge(Owner::User(rig.ada));
    assert_eq!(sync_type(&next(&mut first).await), 5);
    assert_eq!(sync_type(&next(&mut second).await), 5);
}

#[tokio::test]
async fn a_space_nudge_reaches_its_members() {
    let rig = rig().await;
    let mut ada = rig.open("ada", MSGPACK_HANDSHAKE).await;
    let mut grace = rig.open("grace", MSGPACK_HANDSHAKE).await;
    eventually(|| rig.hub.connections() == 2).await;
    rig.hub.nudge(Owner::Space(SpaceId::random()));
    assert_eq!(sync_type(&next(&mut ada).await), 5);
    assert_eq!(sync_type(&next(&mut grace).await), 5);
}

#[tokio::test]
async fn nudging_everyone_syncs_every_socket() {
    let rig = rig().await;
    let mut ada = rig.open("ada", MSGPACK_HANDSHAKE).await;
    let mut grace = rig.open("grace", MSGPACK_HANDSHAKE).await;
    eventually(|| rig.hub.connections() == 2).await;
    rig.hub.nudge_everyone();
    assert_eq!(sync_type(&next(&mut ada).await), 5);
    assert_eq!(sync_type(&next(&mut grace).await), 5);
}

#[tokio::test]
async fn the_json_protocol_gets_text_frames() {
    let rig = rig().await;
    let mut ada = rig.open("ada", JSON_HANDSHAKE).await;
    eventually(|| rig.hub.connections() == 1).await;
    rig.hub.send(
        rig.ada,
        Message::cipher(
            UpdateType::SyncCipherUpdate,
            Uuid::from_u128(1),
            rig.ada.0,
            OffsetDateTime::now_utc(),
            Some(Uuid::from_u128(2)),
        ),
    );
    let Wire::Text(text) = next(&mut ada).await else {
        panic!("not a text frame");
    };
    let body = text.as_str().strip_suffix('\u{1e}').expect("a separator");
    let value: serde_json::Value = serde_json::from_str(body).expect("json");
    assert_eq!(value["target"], "ReceiveMessage");
    assert_eq!(value["arguments"][0]["Type"], 0);
    assert_eq!(
        value["arguments"][0]["ContextId"],
        Uuid::from_u128(2).to_string()
    );
}

#[tokio::test]
async fn updates_before_the_handshake_are_not_sent() {
    let rig = rig().await;
    let mut ada = rig.connect("/notifications/hub?access_token=ada").await;
    eventually(|| rig.hub.connections() == 1).await;
    // The format isn't known yet, so this one is dropped...
    rig.hub.nudge(Owner::User(rig.ada));
    tokio::time::sleep(Duration::from_millis(50)).await;
    ada.send(Wire::text(MSGPACK_HANDSHAKE)).await.expect("sent");
    let reply = next(&mut ada).await;
    assert!(matches!(&reply, Wire::Binary(b) if b.as_ref() == HANDSHAKE_RESPONSE));
    // ...and the next one arrives.
    rig.hub.nudge(Owner::User(rig.ada));
    assert_eq!(sync_type(&next(&mut ada).await), 5);
}

/// Waits for the server to close the socket: the next thing to arrive is a close, an error or the
/// end of the stream, not a data frame.
async fn closes(client: &mut Client) {
    let end = tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            match client.next().await {
                None | Some(Err(_)) | Some(Ok(Wire::Close(_))) => return,
                Some(Ok(Wire::Ping(_) | Wire::Pong(_))) => continue,
                Some(Ok(other)) => panic!("a data frame came back: {other:?}"),
            }
        }
    })
    .await;
    assert!(end.is_ok(), "the socket stayed open");
}

#[tokio::test]
async fn a_keep_alive_ping_is_taken_and_not_echoed() {
    let rig = rig().await;
    let mut ada = rig.open("ada", MSGPACK_HANDSHAKE).await;
    ada.send(Wire::binary(MSGPACK_PING.to_vec()))
        .await
        .expect("sent");
    // The socket stays up and the next thing it says is an update, not the ping.
    rig.hub.nudge(Owner::User(rig.ada));
    assert_eq!(sync_type(&next(&mut ada).await), 5);

    let mut json = rig.open("grace", JSON_HANDSHAKE).await;
    json.send(Wire::text("{\"type\":6}\u{1e}"))
        .await
        .expect("sent");
    rig.hub.nudge(Owner::User(rig.grace));
    assert!(matches!(next(&mut json).await, Wire::Text(_)));
}

#[tokio::test]
async fn any_other_frame_closes_the_socket() {
    let rig = rig().await;
    // Something that is not a ping, after the handshake.
    let mut ada = rig.open("ada", MSGPACK_HANDSHAKE).await;
    ada.send(Wire::binary(vec![0x04, 0x93, 0x01, 0x02, 0x03]))
        .await
        .expect("sent");
    closes(&mut ada).await;
    // A second handshake.
    let mut again = rig.open("ada", MSGPACK_HANDSHAKE).await;
    again
        .send(Wire::text(MSGPACK_HANDSHAKE))
        .await
        .expect("sent");
    closes(&mut again).await;
    // A first frame that is no handshake.
    let mut first = rig.connect("/notifications/hub?access_token=ada").await;
    first.send(Wire::text("hello")).await.expect("sent");
    closes(&mut first).await;
    eventually(|| rig.hub.connections() == 0).await;
}

#[tokio::test]
async fn an_anonymous_socket_echoes_nothing() {
    let rig = rig().await;
    let mut anon = rig
        .connect("/notifications/anonymous-hub?token=login-request")
        .await;
    anon.send(Wire::text(MSGPACK_HANDSHAKE))
        .await
        .expect("sent");
    let reply = next(&mut anon).await;
    assert!(matches!(&reply, Wire::Binary(b) if b.as_ref() == HANDSHAKE_RESPONSE));
    anon.send(Wire::binary(vec![0u8; 64])).await.expect("sent");
    closes(&mut anon).await;
}

#[tokio::test]
async fn a_message_past_a_few_kib_closes_the_socket_before_it_is_buffered() {
    let rig = rig().await;
    let mut ada = rig.open("ada", MSGPACK_HANDSHAKE).await;
    ada.send(Wire::binary(vec![7u8; 64 * 1024]))
        .await
        .expect("sent");
    closes(&mut ada).await;
    eventually(|| rig.hub.connections() == 0).await;

    let mut anon = rig.connect("/notifications/anonymous-hub?token=big").await;
    anon.send(Wire::text("x".repeat(MAX_CLIENT_MESSAGE + 1)))
        .await
        .expect("sent");
    closes(&mut anon).await;
}

/// A token that holds until the test says it doesn't.
struct Revocable {
    user: UserId,
    valid: Arc<std::sync::atomic::AtomicBool>,
}

impl HubAuth for Revocable {
    fn authenticate(&self, _token: &str) -> BoxFuture<'_, Option<HubIdentity>> {
        let good = self.valid.load(Ordering::SeqCst);
        let user = self.user;
        Box::pin(async move { good.then_some(HubIdentity { user, device: None }) })
    }
}

#[tokio::test]
async fn a_socket_closes_when_its_token_stops_holding() {
    let user = UserId::random();
    let valid = Arc::new(std::sync::atomic::AtomicBool::new(true));
    let hub = BwHub::new(
        Arc::new(UserOnly),
        HubConfig {
            ping_every: Duration::from_millis(30),
            recheck_every: Duration::from_millis(60),
            ..HubConfig::default()
        },
    );
    let auth = Arc::new(Revocable {
        user,
        valid: valid.clone(),
    });
    let address = serve_with_peers(router(hub.clone(), auth)).await;
    let rig = Rig {
        hub: hub.clone(),
        address,
        ada: user,
        grace: user,
    };
    let mut client = rig.open("any", MSGPACK_HANDSHAKE).await;
    eventually(|| hub.connections() == 1).await;
    // Still good: the socket stays open through several checks.
    tokio::time::sleep(Duration::from_millis(250)).await;
    assert_eq!(hub.connections(), 1);
    // The password changed, or the account was disabled: the next check closes it.
    valid.store(false, Ordering::SeqCst);
    eventually(|| hub.connections() == 0).await;
    closes(&mut client).await;
}

#[tokio::test]
async fn the_server_pings_with_vaultwardens_payload() {
    let rig = rig_with(HubConfig {
        ping_every: Duration::from_millis(40),
        client_timeout: Duration::from_secs(30),
        ip_header: None,
        ..HubConfig::default()
    })
    .await;
    let mut ada = rig.open("ada", MSGPACK_HANDSHAKE).await;
    let ping = tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            match ada.next().await.expect("open").expect("no error") {
                Wire::Ping(payload) => return payload,
                _ => continue,
            }
        }
    })
    .await
    .expect("a ping in time");
    assert_eq!(ping.as_ref(), MSGPACK_PING);
}

#[tokio::test]
async fn a_socket_that_goes_quiet_is_dropped() {
    let rig = rig_with(HubConfig {
        ping_every: Duration::from_millis(30),
        client_timeout: Duration::from_millis(100),
        ip_header: None,
        ..HubConfig::default()
    })
    .await;
    // The client never reads again, so it never answers a ping.
    let _silent = rig.open("ada", MSGPACK_HANDSHAKE).await;
    eventually(|| rig.hub.connections() == 1).await;
    eventually(|| rig.hub.connections() == 0).await;
}

#[tokio::test]
async fn closing_a_socket_frees_its_count() {
    let rig = rig().await;
    let mut ada = rig.open("ada", MSGPACK_HANDSHAKE).await;
    eventually(|| rig.hub.connections() == 1).await;
    ada.close(None).await.expect("closes");
    eventually(|| rig.hub.connections() == 0).await;
}

#[tokio::test]
async fn a_logout_message_reaches_the_account() {
    let rig = rig().await;
    let mut ada = rig.open("ada", MSGPACK_HANDSHAKE).await;
    eventually(|| rig.hub.connections() == 1).await;
    rig.hub.send(
        rig.ada,
        Message::logout(
            rig.ada.0,
            Some(Uuid::from_u128(9)),
            OffsetDateTime::now_utc(),
        ),
    );
    let (_, arg) = argument(&next(&mut ada).await);
    assert_eq!(get(&arg, "Type").as_i64(), Some(11));
    assert_eq!(
        get(&arg, "ContextId").as_str(),
        Some(Uuid::from_u128(9).to_string().as_str())
    );
}

// ---- the anonymous hub ----

#[tokio::test]
async fn the_anonymous_hub_needs_a_token() {
    let rig = rig().await;
    assert!(matches!(
        connect_async(rig.url("/notifications/anonymous-hub")).await,
        Err(tungstenite::Error::Http(r)) if r.status() == 400
    ));
}

async fn open_anonymous(rig: &Rig, token: &str) -> Client {
    let mut client = rig
        .connect(&format!("/notifications/anonymous-hub?token={token}"))
        .await;
    client
        .send(Wire::text(MSGPACK_HANDSHAKE))
        .await
        .expect("sent");
    let reply = next(&mut client).await;
    assert!(matches!(&reply, Wire::Binary(b) if b.as_ref() == HANDSHAKE_RESPONSE));
    client
}

#[tokio::test]
async fn an_anonymous_socket_hears_the_answer_to_its_request() {
    let rig = rig().await;
    let mut waiting = open_anonymous(&rig, "request-1").await;
    let mut other = open_anonymous(&rig, "request-2").await;
    // The socket is subscribed once its handshake was answered.
    rig.hub.send_anonymous(
        "request-1",
        Message::anonymous_response(Uuid::from_u128(5), rig.ada.0),
    );
    let (target, arg) = argument(&next(&mut waiting).await);
    assert_eq!(target, "AuthRequestResponseRecieved");
    assert_eq!(get(&arg, "Type").as_i64(), Some(16));
    assert_eq!(
        get(&arg, "UserId").as_str(),
        Some(rig.ada.to_string().as_str())
    );
    // The other token's socket heard nothing.
    let silence = tokio::time::timeout(Duration::from_millis(100), other.next()).await;
    assert!(silence.is_err());
}

#[tokio::test]
async fn sockets_sharing_a_token_all_hear_and_the_token_is_forgotten_after() {
    let rig = rig().await;
    let mut a = open_anonymous(&rig, "shared").await;
    let mut b = open_anonymous(&rig, "shared").await;
    rig.hub.send_anonymous(
        "shared",
        Message::anonymous_response(Uuid::from_u128(5), rig.ada.0),
    );
    assert_eq!(sync_type(&next(&mut a).await), 16);
    assert_eq!(sync_type(&next(&mut b).await), 16);
    a.close(None).await.expect("closes");
    b.close(None).await.expect("closes");
    eventually(|| locked(&rig.hub.inner.anonymous).is_empty()).await;
}

#[tokio::test]
async fn one_address_may_hold_25_anonymous_sockets() {
    let rig = rig().await;
    let mut held = Vec::new();
    for n in 0..MAX_ANONYMOUS_PER_IP {
        held.push(
            rig.connect(&format!("/notifications/anonymous-hub?token=t{n}"))
                .await,
        );
    }
    match connect_async(rig.url("/notifications/anonymous-hub?token=extra")).await {
        Err(tungstenite::Error::Http(response)) => assert_eq!(response.status(), 429),
        other => panic!("the 26th socket opened: {:?}", other.map(|_| ())),
    }
    // Closing one makes room.
    let mut first = held.remove(0);
    first.close(None).await.expect("closes");
    drop(first);
    let mut opened = false;
    for _ in 0..200 {
        if connect_async(rig.url("/notifications/anonymous-hub?token=again"))
            .await
            .is_ok()
        {
            opened = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    assert!(opened, "a slot never freed up");
}

#[tokio::test]
async fn the_proxy_header_names_the_client_for_the_limit() {
    let rig = rig_with(HubConfig {
        ip_header: Some("X-Real-IP".to_owned()),
        ..HubConfig::default()
    })
    .await;
    // Different clients behind one proxy don't share a limit.
    let mut held = Vec::new();
    for n in 0..MAX_ANONYMOUS_PER_IP {
        let mut request = rig
            .url(&format!("/notifications/anonymous-hub?token=t{n}"))
            .into_client_request()
            .expect("a request");
        request
            .headers_mut()
            .insert("X-Real-IP", "203.0.113.1".parse().expect("header"));
        held.push(connect_async(request).await.expect("opens").0);
    }
    let mut other = rig
        .url("/notifications/anonymous-hub?token=x")
        .into_client_request()
        .expect("a request");
    other
        .headers_mut()
        .insert("X-Real-IP", "203.0.113.2".parse().expect("header"));
    assert!(
        connect_async(other).await.is_ok(),
        "another client is not limited"
    );
    let mut same = rig
        .url("/notifications/anonymous-hub?token=y")
        .into_client_request()
        .expect("a request");
    same.headers_mut()
        .insert("X-Real-IP", "203.0.113.1".parse().expect("header"));
    assert!(matches!(
        connect_async(same).await,
        Err(tungstenite::Error::Http(r)) if r.status() == 429
    ));
}

#[tokio::test]
async fn a_hub_with_no_audience_still_serves_users() {
    // `UserOnly` is what a server without spaces uses.
    let user = UserId::random();
    let hub = BwHub::new(Arc::new(UserOnly), HubConfig::default());
    let auth = Arc::new(Tokens {
        ada: user,
        grace: UserId::random(),
    });
    let address = serve_with_peers(router(hub.clone(), auth)).await;
    let (mut client, _) =
        connect_async(format!("ws://{address}/notifications/hub?access_token=ada"))
            .await
            .expect("opens");
    client
        .send(Wire::text(MSGPACK_HANDSHAKE))
        .await
        .expect("sent");
    let _ = next(&mut client).await;
    eventually(|| hub.connections() == 1).await;
    hub.nudge(Owner::User(user));
    assert_eq!(sync_type(&next(&mut client).await), 5);
}

fn bare_hub() -> BwHub {
    BwHub::new(Arc::new(UserOnly), HubConfig::default())
}

#[tokio::test]
async fn a_covered_account_skips_one_sync_vault_and_hears_the_next() {
    let hub = bare_hub();
    let mut tap = hub.tap();
    let ada = UserId::random();
    hub.cover(ada);
    // The nudge that follows a detailed message is the covered one.
    hub.nudge(Owner::User(ada));
    assert!(tap.heard().is_empty());
    // The cover is used up: the next change is told.
    hub.nudge(Owner::User(ada));
    let heard = tap.heard();
    assert_eq!(heard.len(), 1);
    assert_eq!(heard[0].0, ada);
    assert_eq!(heard[0].1.kind, UpdateType::SyncVault);
}

#[tokio::test]
async fn a_cover_is_for_one_account_only() {
    let hub = bare_hub();
    let mut tap = hub.tap();
    let (ada, grace) = (UserId::random(), UserId::random());
    hub.cover(ada);
    hub.nudge(Owner::User(grace));
    let heard = tap.heard();
    assert_eq!(heard.len(), 1);
    assert_eq!(heard[0].0, grace);
}

#[tokio::test]
async fn sending_a_message_does_not_cover_by_itself() {
    let hub = bare_hub();
    let mut tap = hub.tap();
    let ada = UserId::random();
    hub.send(
        ada,
        Message::user_update(UpdateType::SyncSettings, ada.0, OffsetDateTime::now_utc()),
    );
    hub.nudge(Owner::User(ada));
    let kinds: Vec<UpdateType> = tap.heard().iter().map(|(_, m)| m.kind).collect();
    assert_eq!(kinds, [UpdateType::SyncSettings, UpdateType::SyncVault]);
}

#[tokio::test]
async fn the_address_the_server_settled_beats_a_header_the_client_wrote() {
    let (ada, grace) = (UserId::random(), UserId::random());
    let hub = BwHub::new(
        Arc::new(Both(ada, grace)),
        HubConfig {
            ip_header: Some("X-Real-IP".to_owned()),
            ..HubConfig::default()
        },
    );
    let auth = Arc::new(Tokens { ada, grace });
    // The server's request layer settles the address and puts it in the extensions.
    let settled = router(hub, auth).layer(axum::middleware::from_fn(
        |mut request: Request, next: axum::middleware::Next| async move {
            request
                .extensions_mut()
                .insert(ClientAddr("198.51.100.5".parse().expect("an address")));
            next.run(request).await
        },
    ));
    let address = serve_with_peers(settled).await;
    // A client that writes a new address in each request still counts as the one settled.
    let mut held = Vec::new();
    for n in 0..MAX_ANONYMOUS_PER_IP {
        let mut request = format!("ws://{address}/notifications/anonymous-hub?token=t{n}")
            .into_client_request()
            .expect("a request");
        request.headers_mut().insert(
            "X-Real-IP",
            format!("203.0.113.{}", n + 1).parse().expect("header"),
        );
        held.push(connect_async(request).await.expect("opens").0);
    }
    let mut spoofed = format!("ws://{address}/notifications/anonymous-hub?token=x")
        .into_client_request()
        .expect("a request");
    spoofed
        .headers_mut()
        .insert("X-Real-IP", "192.0.2.77".parse().expect("header"));
    assert!(matches!(
        connect_async(spoofed).await,
        Err(tungstenite::Error::Http(r)) if r.status() == 429
    ));
}

/// A store that fails now and then: a refusal it cannot make is `Unknown`, and the socket stays.
struct Flaky(UserId);

impl HubAuth for Flaky {
    fn authenticate(&self, _token: &str) -> BoxFuture<'_, Option<HubIdentity>> {
        let user = self.0;
        Box::pin(async move { Some(HubIdentity { user, device: None }) })
    }

    fn recheck(&self, _token: &str, _user: UserId) -> BoxFuture<'_, Recheck> {
        Box::pin(async { Recheck::Unknown })
    }
}

#[tokio::test]
async fn a_transient_failure_of_the_recheck_does_not_close_the_socket() {
    let user = UserId::random();
    let hub = BwHub::new(
        Arc::new(UserOnly),
        HubConfig {
            ping_every: Duration::from_millis(30),
            recheck_every: Duration::from_millis(30),
            ..HubConfig::default()
        },
    );
    let address = serve_with_peers(router(hub.clone(), Arc::new(Flaky(user)))).await;
    let rig = Rig {
        hub: hub.clone(),
        address,
        ada: user,
        grace: user,
    };
    let _client = rig.open("any", MSGPACK_HANDSHAKE).await;
    eventually(|| hub.connections() == 1).await;
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert_eq!(hub.connections(), 1, "several rechecks said Unknown");
}
