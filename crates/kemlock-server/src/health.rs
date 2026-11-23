//! `/alive` and `/health` (design, "Self-hosting and homelab", Operations).
//!
//! `/alive` answers 200 while the process serves requests: liveness. `/health` also checks the
//! database and the data folder and answers 503 naming what failed: readiness. The 503 names the
//! check, never the error, which goes to the log.

use axum::Router;
use axum::extract::State;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use kemlock_store_sql::SqlStore;
use serde_json::json;
use std::future::Future;
use std::path::{Path, PathBuf};

/// Something whose reachability `/health` can check. `SqlStore` is one.
pub trait Ping: Clone + Send + Sync + 'static {
    /// `Err` carries a message for the log.
    fn ping(&self) -> impl Future<Output = Result<(), String>> + Send;
}

impl Ping for SqlStore {
    async fn ping(&self) -> Result<(), String> {
        SqlStore::ping(self).await.map_err(|e| e.to_string())
    }
}

/// What the health routes share.
#[derive(Clone, Debug)]
pub struct HealthState<S> {
    pub store: S,
    pub data_folder: PathBuf,
}

async fn alive() -> &'static str {
    "ok"
}

async fn check_data_folder(path: &Path) -> Result<(), String> {
    tokio::fs::write(path.join(".health"), b"ok")
        .await
        .map_err(|e| e.to_string())
}

async fn health<S: Ping>(State(state): State<HealthState<S>>) -> Response {
    let database = state.store.ping().await;
    let folder = check_data_folder(&state.data_folder).await;
    let mut failed = Vec::new();
    let mut checks = serde_json::Map::new();
    for (name, result) in [("database", &database), ("dataFolder", &folder)] {
        match result {
            Ok(()) => {
                checks.insert(name.to_owned(), json!("ok"));
            }
            Err(error) => {
                tracing::error!(check = name, %error, "a health check failed");
                checks.insert(name.to_owned(), json!("failed"));
                failed.push(name);
            }
        }
    }
    if failed.is_empty() {
        (
            StatusCode::OK,
            axum::Json(json!({"status": "ok", "checks": checks})),
        )
            .into_response()
    } else {
        (
            StatusCode::SERVICE_UNAVAILABLE,
            axum::Json(json!({"status": "unavailable", "failed": failed, "checks": checks})),
        )
            .into_response()
    }
}

/// `GET /alive` and `GET /health`.
pub fn router<S: Ping>(state: HealthState<S>) -> Router {
    Router::new()
        .route("/alive", get(alive))
        .route("/health", get(health::<S>))
        .with_state(state)
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use axum::http::Request;
    use tower::ServiceExt;

    #[derive(Clone)]
    struct Fake(Result<(), String>);

    impl Ping for Fake {
        async fn ping(&self) -> Result<(), String> {
            self.0.clone()
        }
    }

    async fn get_json(router: Router, path: &str) -> (StatusCode, serde_json::Value) {
        let response = router
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

    fn state(ping: Result<(), String>) -> HealthState<Fake> {
        HealthState {
            store: Fake(ping),
            data_folder: std::env::temp_dir(),
        }
    }

    #[tokio::test]
    async fn alive_is_200_whatever_the_database_does() {
        let router = router(state(Err("down".to_owned())));
        let response = router
            .oneshot(
                Request::builder()
                    .uri("/alive")
                    .body(Body::empty())
                    .expect("a valid request"),
            )
            .await
            .expect("infallible");
        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn health_is_200_when_everything_works() {
        let (status, json) = get_json(router(state(Ok(()))), "/health").await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(json["status"], "ok");
        assert_eq!(json["checks"]["database"], "ok");
    }

    #[tokio::test]
    async fn health_is_503_and_names_what_failed_but_not_why() {
        let secret = "postgres://user:hunter2@db/kemlock refused";
        let (status, json) = get_json(router(state(Err(secret.to_owned()))), "/health").await;
        assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(json["status"], "unavailable");
        assert_eq!(json["failed"], serde_json::json!(["database"]));
        assert!(!json.to_string().contains("hunter2"));
    }

    #[tokio::test]
    async fn a_missing_data_folder_fails_the_health_check() {
        let mut broken = state(Ok(()));
        broken.data_folder = std::env::temp_dir().join("kemlock-no-such-folder-for-health-test");
        let (status, json) = get_json(router(broken), "/health").await;
        assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(json["failed"], serde_json::json!(["dataFolder"]));
    }
}
