//! The notification wiring: mail from `SMTP_*`, the hub's path through the fan-out, the push relay
//! settings, and the routes the server serves for them.

use axum::body::Body;
use axum::http::{Request, StatusCode};
use kemlock_app::ports::Notifier;
use kemlock_crypto::opaque::OpaqueServer;
use kemlock_crypto::seal::ServerSeal;
use kemlock_domain::{ChangeId, Hlc, Owner, ServerId, UserId};
use kemlock_server::adapters::ServerCrypto;
use kemlock_server::notify;
use kemlock_server::{Config, RunError, build};
use kemlock_store_sql::SqlStore;
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::time::Duration;
use tower::ServiceExt;

struct TempDir(PathBuf);

impl TempDir {
    fn new(name: &str) -> TempDir {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_nanos());
        let path = std::env::temp_dir().join(format!(
            "kemlock-server-notify-{}-{name}-{nanos}",
            std::process::id()
        ));
        std::fs::create_dir_all(&path).expect("a temp dir");
        TempDir(path)
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn config(data: &Path) -> Config {
    let data = data.display().to_string();
    Config::from_sources(
        &|name| match name {
            "DATA_FOLDER" => Some(data.clone()),
            "DOMAIN" => Some("https://kemlock.test".to_owned()),
            _ => None,
        },
        None,
    )
    .expect("a valid configuration")
}

fn crypto() -> ServerCrypto {
    ServerCrypto::new(ServerSeal::new(&[5u8; 32]), OpaqueServer::generate())
}

fn env(pairs: &[(&str, &str)]) -> impl Fn(&str) -> Option<String> {
    let map: HashMap<String, String> = pairs
        .iter()
        .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
        .collect();
    move |name| map.get(name).cloned()
}

async fn memory_store() -> SqlStore {
    SqlStore::connect("sqlite::memory:").await.expect("a store")
}

fn change() -> ChangeId {
    ChangeId {
        origin: ServerId::random(),
        seq: 1,
        hlc: Hlc(1),
    }
}

#[tokio::test]
async fn without_smtp_mail_is_only_logged_by_a_sender_that_can_be_switched_later() {
    use kemlock_notify::mail::{Mail, Mailer};
    let dir = TempDir::new("no-smtp");
    let started = notify::start(&config(&dir.0), &env(&[]), &memory_store().await, &crypto())
        .await
        .expect("starts");
    // The sender is there from the start, so settings saved later can point it at a server; with
    // none set it logs and sends nothing.
    assert!(format!("{:?}", started.hub).contains("mail: true"));
    let mail = Mail {
        to: "ada@example.org".to_owned(),
        subject: "Hello".to_owned(),
        text: "Hello".to_owned(),
        html: "<p>Hello</p>".to_owned(),
    };
    assert_eq!(started.mailer.send(mail).await, Ok(()));
}

#[tokio::test]
async fn with_smtp_the_hub_carries_a_mailing_sender() {
    let dir = TempDir::new("smtp");
    let started = notify::start(
        &config(&dir.0),
        &env(&[
            ("SMTP_HOST", "mail.example.com"),
            ("SMTP_FROM", "vault@example.com"),
            ("SMTP_USERNAME", "vault"),
            ("SMTP_PASSWORD", "hunter2"),
        ]),
        &memory_store().await,
        &crypto(),
    )
    .await
    .expect("starts");
    assert!(format!("{:?}", started.hub).contains("mail: true"));
}

#[tokio::test]
async fn bad_smtp_settings_stop_the_start_and_name_the_setting() {
    let dir = TempDir::new("bad-smtp");
    let result = notify::start(
        &config(&dir.0),
        &env(&[("SMTP_HOST", "mail.example.com")]),
        &memory_store().await,
        &crypto(),
    )
    .await;
    match result {
        Err(RunError::Config(message)) => assert!(message.contains("SMTP_FROM"), "{message}"),
        other => panic!("expected a config error, got {:?}", other.map(|_| ())),
    }
}

#[tokio::test]
async fn a_relay_url_that_would_leak_the_key_stops_the_start() {
    let dir = TempDir::new("bad-relay");
    let result = notify::start(
        &config(&dir.0),
        &env(&[("KEMLOCK_PUSH_RELAY_URL", "http://push.example.com")]),
        &memory_store().await,
        &crypto(),
    )
    .await;
    match result {
        Err(RunError::Config(message)) => {
            assert!(message.contains("KEMLOCK_PUSH_RELAY_URL"), "{message}");
        }
        other => panic!("expected a config error, got {:?}", other.map(|_| ())),
    }
}

#[tokio::test]
async fn a_commit_reaches_the_sockets_through_the_fan_out() {
    let dir = TempDir::new("commit");
    let started = notify::start(&config(&dir.0), &env(&[]), &memory_store().await, &crypto())
        .await
        .expect("starts");
    let mut sockets = started.hub.subscribe();
    let owner = Owner::User(UserId::random());
    started.hub.sync_now(owner, change()).await;
    let heard = tokio::time::timeout(Duration::from_secs(5), sockets.recv())
        .await
        .expect("a nudge in time")
        .expect("open");
    assert_eq!(heard, owner);
    // Once: the fan-out is the only path.
    assert!(sockets.try_recv().is_err());
}

async fn status(router: &axum::Router, method: &str, path: &str) -> StatusCode {
    router
        .clone()
        .oneshot(
            Request::builder()
                .method(method)
                .uri(path)
                .body(Body::empty())
                .expect("a valid request"),
        )
        .await
        .expect("infallible")
        .status()
}

#[tokio::test]
async fn the_built_server_serves_the_hub_and_the_push_token_routes() {
    let dir = TempDir::new("routes");
    let built = build(&config(&dir.0)).await.expect("builds");
    // Both exist and ask for a token (a missing route would be a 404).
    assert_eq!(
        status(&built.router, "GET", "/notifications/hub").await,
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(
        status(&built.router, "POST", "/kem/v1/devices/push-token").await,
        StatusCode::UNAUTHORIZED
    );
    // SignalR's negotiation is open: the token comes with the socket.
    assert_eq!(
        status(&built.router, "POST", "/notifications/hub/negotiate").await,
        StatusCode::OK
    );
}

#[tokio::test]
async fn the_built_server_serves_the_custom_fields_and_untrust_routes() {
    let dir = TempDir::new("custom-fields");
    let built = build(&config(&dir.0)).await.expect("builds");
    // Each exists and asks for a token (a missing route would be a 404, a missing method a 405).
    for (method, path) in [
        ("GET", "/kem/v1/custom-fields"),
        ("GET", "/admin/v1/custom-fields"),
        ("POST", "/admin/v1/custom-fields"),
        ("PUT", "/admin/v1/custom-fields/allow-own"),
        (
            "PUT",
            "/admin/v1/custom-fields/7d0f3a52-6c1d-4f3b-9a58-2e3b5a0a9c11",
        ),
        (
            "DELETE",
            "/admin/v1/custom-fields/7d0f3a52-6c1d-4f3b-9a58-2e3b5a0a9c11",
        ),
        (
            "DELETE",
            "/kem/v1/devices/7d0f3a52-6c1d-4f3b-9a58-2e3b5a0a9c11/key-copy",
        ),
    ] {
        assert_eq!(
            status(&built.router, method, path).await,
            StatusCode::UNAUTHORIZED,
            "{method} {path}"
        );
    }
}

#[tokio::test]
async fn bitwardens_push_relay_is_off_unless_push_is_enabled() {
    let dir = TempDir::new("no-push");
    let started = notify::start(&config(&dir.0), &env(&[]), &memory_store().await, &crypto())
        .await
        .expect("starts");
    assert!(format!("{:?}", started.bw_live).contains("relay: false"));
}

#[tokio::test]
async fn push_enabled_with_an_installation_turns_bitwardens_relay_on() {
    let dir = TempDir::new("push");
    let started = notify::start(
        &config(&dir.0),
        &env(&[
            ("PUSH_ENABLED", "true"),
            ("PUSH_INSTALLATION_ID", "installation-1"),
            ("PUSH_INSTALLATION_KEY", "key-1"),
        ]),
        &memory_store().await,
        &crypto(),
    )
    .await
    .expect("starts");
    assert!(format!("{:?}", started.bw_live).contains("relay: true"));
}

#[tokio::test]
async fn push_enabled_without_its_installation_stops_the_start_and_names_the_setting() {
    let dir = TempDir::new("push-missing");
    let result = notify::start(
        &config(&dir.0),
        &env(&[("PUSH_ENABLED", "true")]),
        &memory_store().await,
        &crypto(),
    )
    .await;
    match result {
        Err(RunError::Config(message)) => {
            assert!(message.contains("PUSH_INSTALLATION_ID"), "{message}");
        }
        other => panic!("expected a config error, got {:?}", other.map(|_| ())),
    }
}

#[tokio::test]
async fn a_relay_that_would_leak_the_installation_key_stops_the_start() {
    let dir = TempDir::new("push-http");
    let result = notify::start(
        &config(&dir.0),
        &env(&[
            ("PUSH_ENABLED", "true"),
            ("PUSH_INSTALLATION_ID", "installation-1"),
            ("PUSH_INSTALLATION_KEY", "key-1"),
            ("PUSH_RELAY_URI", "http://push.example.com"),
        ]),
        &memory_store().await,
        &crypto(),
    )
    .await;
    match result {
        Err(RunError::Config(message)) => assert!(message.contains("PUSH_RELAY_URI"), "{message}"),
        other => panic!("expected a config error, got {:?}", other.map(|_| ())),
    }
}

#[tokio::test]
async fn the_built_server_serves_the_bitwarden_device_token_routes() {
    let dir = TempDir::new("device-token");
    let built = build(&config(&dir.0)).await.expect("builds");
    // The token route asks for a sign-in; clear-token has none, as in Vaultwarden, and with no
    // relay set up there is nothing to forget.
    assert_eq!(
        status(&built.router, "PUT", "/api/devices/identifier/abc/token").await,
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(
        status(
            &built.router,
            "PUT",
            "/api/devices/identifier/abc/clear-token"
        )
        .await,
        StatusCode::OK
    );
}

#[tokio::test]
async fn the_admin_consoles_mail_follows_smtp() {
    use kemlock_app::admin::Mailer;

    let dir = TempDir::new("admin-no-smtp");
    let without = notify::start(&config(&dir.0), &env(&[]), &memory_store().await, &crypto())
        .await
        .expect("starts");
    assert!(!without.admin_mail.configured());

    let dir = TempDir::new("admin-smtp");
    let with = notify::start(
        &config(&dir.0),
        &env(&[
            ("SMTP_HOST", "mail.example.com"),
            ("SMTP_FROM", "vault@example.com"),
            ("SMTP_USERNAME", "vault"),
            ("SMTP_PASSWORD", "hunter2"),
        ]),
        &memory_store().await,
        &crypto(),
    )
    .await
    .expect("starts");
    assert!(with.admin_mail.configured());
}

#[tokio::test]
async fn the_admin_console_can_see_and_turn_the_push_relay_of_the_server() {
    let dir = TempDir::new("admin-relay");
    let started = notify::start(
        &config(&dir.0),
        &env(&[("KEMLOCK_PUSH_RELAY_URL", "https://push.example.org")]),
        &memory_store().await,
        &crypto(),
    )
    .await
    .expect("starts");
    let status = started.push_relay.status().await.expect("reads");
    assert!(!status.enabled, "off until the server registers");
    assert_eq!(status.installation_id, None);
    assert_eq!(status.relay_url, "https://push.example.org");

    let dir = TempDir::new("admin-relay-default");
    let started = notify::start(&config(&dir.0), &env(&[]), &memory_store().await, &crypto())
        .await
        .expect("starts");
    assert_eq!(
        started.push_relay.status().await.expect("reads").relay_url,
        "https://push.kemlock.app"
    );
}

#[tokio::test]
async fn the_built_server_serves_the_push_relay_routes_to_admins_only() {
    let dir = TempDir::new("relay-routes");
    let built = build(&config(&dir.0)).await.expect("builds");
    for (method, path) in [
        ("GET", "/admin/v1/push-relay"),
        ("POST", "/admin/v1/push-relay/enable"),
        ("POST", "/admin/v1/push-relay/disable"),
    ] {
        assert_eq!(
            status(&built.router, method, path).await,
            StatusCode::UNAUTHORIZED,
            "{method} {path}"
        );
    }
}

/// A throwaway P-256 key in the form Apple's `.p8` files have; it signs nothing real.
const TEST_P8: &str = "-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgLCpHyhHVUWJyiE+w
5q1Ed49bwewRopqW+tx19E2IisihRANCAAS3O272KD8fVm1SZrcrHSKRua0ttLzN
mYa1o1kWjBqRy4lH9qL07NARM5LqJup5OCX1OiEs94cqi24FaRV+H9V7
-----END PRIVATE KEY-----
";

#[tokio::test]
async fn an_apple_key_makes_the_console_say_iphones_are_pushed_to_directly() {
    let dir = TempDir::new("apns-on");
    let key = dir.0.join("AuthKey_TEST.p8");
    std::fs::write(&key, TEST_P8).expect("writes the key");
    let key = key.display().to_string();
    let started = notify::start(
        &config(&dir.0),
        &env(&[
            ("KEMLOCK_APNS_KEY_FILE", key.as_str()),
            ("KEMLOCK_APNS_KEY_ID", "KEY1234567"),
            ("KEMLOCK_APNS_TEAM_ID", "TEAM123456"),
            ("KEMLOCK_APNS_SANDBOX", "true"),
        ]),
        &memory_store().await,
        &crypto(),
    )
    .await
    .expect("starts");
    let status = started.push_relay.status().await.expect("reads");
    assert!(status.apns_configured);
    assert!(status.apns_sandbox);
    assert!(!status.enabled, "the relay stays off");

    let dir = TempDir::new("apns-off");
    let started = notify::start(&config(&dir.0), &env(&[]), &memory_store().await, &crypto())
        .await
        .expect("starts");
    let status = started.push_relay.status().await.expect("reads");
    assert!(!status.apns_configured && !status.apns_sandbox);
}

#[tokio::test]
async fn bad_apple_settings_stop_the_start_and_name_the_setting() {
    let dir = TempDir::new("bad-apns");
    let key = dir.0.join("AuthKey_TEST.p8");
    std::fs::write(&key, TEST_P8).expect("writes the key");
    let key = key.display().to_string();
    for (pairs, setting) in [
        // Only some of the three.
        (
            vec![("KEMLOCK_APNS_KEY_ID", "KEY1234567")],
            "KEMLOCK_APNS_KEY_FILE",
        ),
        (
            vec![
                ("KEMLOCK_APNS_KEY_FILE", key.as_str()),
                ("KEMLOCK_APNS_KEY_ID", "KEY1234567"),
            ],
            "KEMLOCK_APNS_TEAM_ID",
        ),
        (
            vec![
                ("KEMLOCK_APNS_KEY_FILE", "/no/such/AuthKey.p8"),
                ("KEMLOCK_APNS_KEY_ID", "KEY1234567"),
                ("KEMLOCK_APNS_TEAM_ID", "TEAM123456"),
            ],
            "KEMLOCK_APNS_KEY_FILE",
        ),
        (
            vec![
                ("KEMLOCK_APNS_KEY_FILE", key.as_str()),
                ("KEMLOCK_APNS_KEY_ID", "KEY1234567"),
                ("KEMLOCK_APNS_TEAM_ID", "TEAM123456"),
                ("KEMLOCK_APNS_SANDBOX", "maybe"),
            ],
            "KEMLOCK_APNS_SANDBOX",
        ),
    ] {
        let result = notify::start(
            &config(&dir.0),
            &env(&pairs),
            &memory_store().await,
            &crypto(),
        )
        .await;
        match result {
            Err(RunError::Config(message)) => assert!(message.contains(setting), "{message}"),
            other => panic!("expected a config error, got {:?}", other.map(|_| ())),
        }
    }
}
