//! The attachment routes wired into the server: served next to the API, authenticated, with the
//! local folder made inside the data folder.

use axum::body::Body;
use axum::http::{Method, Request, StatusCode};
use kemlock_server::{Config, build};
use std::path::{Path, PathBuf};
use tower::ServiceExt;

struct TempDir(PathBuf);

impl TempDir {
    fn new(name: &str) -> TempDir {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_nanos());
        let path = std::env::temp_dir().join(format!(
            "kemlock-server-files-{}-{name}-{nanos}",
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

async fn send(router: &axum::Router, method: Method, path: &str) -> (StatusCode, String) {
    let response = router
        .clone()
        .oneshot(
            Request::builder()
                .method(method)
                .uri(path)
                .body(Body::empty())
                .expect("a valid request"),
        )
        .await
        .expect("infallible");
    let status = response.status();
    let content_type = response
        .headers()
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_owned();
    (status, content_type)
}

#[tokio::test]
async fn the_file_routes_are_served_and_need_a_token() {
    let dir = TempDir::new("routes");
    let built = build(&config(&dir.0)).await.expect("the server builds");
    assert!(
        dir.0.join("attachments").is_dir(),
        "the default folder is made in the data folder"
    );

    let item = "7f3c4b1e-0000-4000-8000-000000000000";
    let file = "7f3c4b1e-0000-4000-8000-000000000001";
    for (method, path) in [
        (Method::POST, format!("/kem/v1/items/{item}/files")),
        (Method::PUT, format!("/kem/v1/items/{item}/files/{file}")),
        (Method::GET, format!("/kem/v1/items/{item}/files/{file}")),
        (Method::DELETE, format!("/kem/v1/items/{item}/files/{file}")),
        (
            Method::POST,
            format!("/kem/v1/items/{item}/files/{file}/finish"),
        ),
    ] {
        let (status, content_type) = send(&built.router, method.clone(), &path).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED, "{method} {path}");
        assert!(
            content_type.starts_with("application/problem+json"),
            "{method} {path}: {content_type}"
        );
    }

    // The item route and unknown paths are as they were.
    let (status, _) = send(&built.router, Method::PUT, &format!("/kem/v1/items/{item}")).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    let (status, _) = send(&built.router, Method::GET, "/kem/v1/nope").await;
    assert_eq!(status, StatusCode::NOT_FOUND);

    built.store.close().await.expect("closes");
}
