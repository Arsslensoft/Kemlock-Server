//! The server wired for real: its keys made on disk, a SQLite file migrated, the API and the
//! health routes answering in-process.

use axum::body::Body;
use axum::http::{Request, StatusCode};
use kemlock_server::{Config, build, keys};
use std::path::{Path, PathBuf};
use tower::ServiceExt;

struct TempDir(PathBuf);

impl TempDir {
    fn new(name: &str) -> TempDir {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_nanos());
        let path = std::env::temp_dir().join(format!(
            "kemlock-server-boot-{}-{name}-{nanos}",
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

async fn get(router: &axum::Router, path: &str) -> (StatusCode, serde_json::Value) {
    let response = router
        .clone()
        .oneshot(
            Request::builder()
                .uri(path)
                .body(Body::empty())
                .expect("a valid request"),
        )
        .await
        .expect("infallible");
    let status = response.status();
    let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("a body");
    (
        status,
        serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null),
    )
}

#[tokio::test]
async fn a_fresh_data_folder_gets_its_keys_and_a_working_server() {
    let dir = TempDir::new("fresh");
    let built = build(&config(&dir.0)).await.expect("the server builds");

    for file in [
        keys::SERVER_KEY_FILE,
        keys::OPAQUE_SETUP_FILE,
        keys::SIGNING_KEY_FILE,
    ] {
        assert!(dir.0.join(file).is_file(), "{file} was made");
    }
    assert_eq!(
        std::fs::read(dir.0.join(keys::SERVER_KEY_FILE))
            .expect("readable")
            .len(),
        32
    );

    let (status, _) = get(&built.router, "/alive").await;
    assert_eq!(status, StatusCode::OK);
    let (status, health) = get(&built.router, "/health").await;
    assert_eq!(status, StatusCode::OK, "{health}");
    assert_eq!(health["status"], "ok");

    let (status, config) = get(&built.router, "/kem/v1/config").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(config["server"], "kemlock-server");
    assert_eq!(config["domain"], "https://kemlock.test");
    assert_eq!(config["signupsAllowed"], false);

    // Starting setup opens it, with a code to log.
    let code = built
        .api
        .start_setup()
        .await
        .expect("setup starts")
        .expect("no admin exists, so there is a code");
    assert_eq!(code.as_display().len(), 14);
    let (_, config) = get(&built.router, "/kem/v1/config").await;
    assert_eq!(config["setup"], "needs-admin");

    built.store.close().await.expect("closes");
}

#[tokio::test]
async fn a_restart_keeps_the_keys_and_the_servers_identity() {
    let dir = TempDir::new("restart");
    let first = build(&config(&dir.0)).await.expect("the server builds");
    let key = std::fs::read(dir.0.join(keys::SERVER_KEY_FILE)).expect("readable");
    let signing = std::fs::read(dir.0.join(keys::SIGNING_KEY_FILE)).expect("readable");
    let (_, before) = get(&first.router, "/kem/v1/config").await;
    first.store.close().await.expect("closes");

    let second = build(&config(&dir.0))
        .await
        .expect("the server builds again");
    assert_eq!(
        std::fs::read(dir.0.join(keys::SERVER_KEY_FILE)).expect("readable"),
        key
    );
    assert_eq!(
        std::fs::read(dir.0.join(keys::SIGNING_KEY_FILE)).expect("readable"),
        signing
    );
    let (_, after) = get(&second.router, "/kem/v1/config").await;
    assert_eq!(before["serverId"], after["serverId"]);
    second.store.close().await.expect("closes");
}

#[tokio::test]
async fn a_replaced_server_key_is_refused_rather_than_silently_resetting_secrets() {
    let dir = TempDir::new("replaced");
    let first = build(&config(&dir.0)).await.expect("the server builds");
    first.store.close().await.expect("closes");

    std::fs::write(dir.0.join(keys::SERVER_KEY_FILE), [9u8; 32]).expect("replaced");
    let error = build(&config(&dir.0))
        .await
        .expect_err("the old secrets don't open");
    assert!(error.to_string().contains("server.key"), "{error}");
}

async fn get_text(router: &axum::Router, path: &str) -> (StatusCode, String) {
    let response = router
        .clone()
        .oneshot(
            Request::builder()
                .uri(path)
                .body(Body::empty())
                .expect("a valid request"),
        )
        .await
        .expect("infallible");
    let status = response.status();
    let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("a body");
    (status, String::from_utf8_lossy(&bytes).into_owned())
}

#[tokio::test]
async fn the_source_and_the_licence_are_offered_to_anyone() {
    let dir = TempDir::new("source");
    let built = build(&config(&dir.0)).await.expect("the server builds");

    let (status, config) = get(&built.router, "/kem/v1/config").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(config["license"], "AGPL-3.0-only");
    let source = config["sourceUrl"].as_str().expect("a source address");
    assert!(
        source.starts_with("https://github.com/Arsslensoft/Kemlock-Server/"),
        "{source}"
    );

    let (status, licence) = get_text(&built.router, "/LICENSE.txt").await;
    assert_eq!(status, StatusCode::OK);
    assert!(licence.contains("GNU AFFERO GENERAL PUBLIC LICENSE"));
    let (status, notice) = get_text(&built.router, "/NOTICE.txt").await;
    assert_eq!(status, StatusCode::OK);
    assert!(notice.contains("Kemlock Server"));
    // Written at release time, so a test build has none beside it.
    let (status, _) = get_text(&built.router, "/THIRD-PARTY-NOTICES.txt").await;
    assert!(
        status == StatusCode::OK || status == StatusCode::NOT_FOUND,
        "{status}"
    );

    built.store.close().await.expect("closes");
}

#[tokio::test]
async fn the_operators_source_address_replaces_the_projects() {
    let dir = TempDir::new("own-source");
    let data = dir.0.display().to_string();
    let config = Config::from_sources(
        &|name| match name {
            "DATA_FOLDER" => Some(data.clone()),
            "DOMAIN" => Some("https://kemlock.test".to_owned()),
            "KEMLOCK_SOURCE_URL" => Some("https://git.example.org/me/kemlock".to_owned()),
            _ => None,
        },
        None,
    )
    .expect("a valid configuration");
    let built = build(&config).await.expect("the server builds");
    let (_, served) = get(&built.router, "/kem/v1/config").await;
    assert_eq!(served["sourceUrl"], "https://git.example.org/me/kemlock");
    built.store.close().await.expect("closes");
}
