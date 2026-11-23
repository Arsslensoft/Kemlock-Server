//! Where the Corresponding Source is offered, and the licence texts served with it.
//!
//! The server is AGPL-3.0-only. Section 13 says that a user who interacts with a modified version
//! over a network must be offered the Corresponding Source of the version that is running. So
//! `/kem/v1/config` (public, no sign-in) carries the licence, the version, the commit and a
//! `sourceUrl`, and the web vault links to it from every screen, the sign-in screen included.
//!
//! The commit is not known to cargo. The Dockerfiles and the release workflow pass it as the build
//! environment variable `KEMLOCK_GIT_COMMIT`, which `option_env!` reads at compile time; a plain
//! `cargo build` leaves it out. The address defaults to the project's repository at that commit,
//! then at the release tag of the version when the commit is unknown. An operator who runs a
//! modified server sets `KEMLOCK_SOURCE_URL` (or `source_url` in the config file) to their own.
//!
//! Beside it, `/LICENSE.txt` and `/NOTICE.txt` are the repository's own files, built into the
//! binary, and `/THIRD-PARTY-NOTICES.txt` is the licence text of every dependency, written at
//! release time and shipped next to the binary in the archives and in `/usr/share/doc/kemlock-server`
//! in the images. It is read when asked for and is a 404 where there is none, as in a plain
//! `cargo build`. Their addresses are exact routes, which the web vault's catch-all, taking what
//! the others leave, never reaches.

use axum::Router;
use axum::body::Body;
use axum::extract::State;
use axum::http::{HeaderValue, StatusCode, header};
use axum::response::Response;
use axum::routing::get;
use std::path::PathBuf;
use std::sync::Arc;

/// The project's repository.
pub const REPOSITORY: &str = "https://github.com/Arsslensoft/Kemlock-Server";
/// The licence's SPDX identifier.
pub const LICENSE_ID: &str = "AGPL-3.0-only";
/// The file name of the dependencies' licence texts.
pub const THIRD_PARTY_FILE: &str = "THIRD-PARTY-NOTICES.txt";
/// Where the images keep it.
pub const DOC_FOLDER: &str = "/usr/share/doc/kemlock-server";

const LICENSE_TEXT: &str = include_str!("../../../LICENSE");
const NOTICE_TEXT: &str = include_str!("../../../NOTICE");

/// The git commit this binary was built from, as 7 to 64 hex digits, or `None` when the build did
/// not say or said something else.
pub fn build_commit() -> Option<String> {
    commit_of(option_env!("KEMLOCK_GIT_COMMIT"))
}

fn commit_of(raw: Option<&str>) -> Option<String> {
    let raw = raw?.trim();
    let hex = (7..=64).contains(&raw.len()) && raw.bytes().all(|b| b.is_ascii_hexdigit());
    hex.then(|| raw.to_ascii_lowercase())
}

/// The address of the Corresponding Source: the operator's own when they set one, otherwise the
/// repository at the build's commit, otherwise the repository itself. Not a release tag built from
/// the crate version: releases are versioned by their tag, not by Cargo.toml, so that link could
/// name a tag that doesn't exist.
pub fn source_url(configured: Option<&str>, commit: Option<&str>) -> String {
    if let Some(url) = configured {
        return url.to_owned();
    }
    match commit {
        Some(commit) => format!("{REPOSITORY}/tree/{commit}"),
        None => REPOSITORY.to_owned(),
    }
}

/// Where `THIRD-PARTY-NOTICES.txt` is looked for: next to the executable, then the images' doc
/// folder.
pub fn third_party_paths() -> Vec<PathBuf> {
    let mut paths = Vec::new();
    if let Some(folder) = std::env::current_exe()
        .ok()
        .and_then(|exe| exe.parent().map(std::path::Path::to_path_buf))
    {
        paths.push(folder.join(THIRD_PARTY_FILE));
    }
    paths.push(PathBuf::from(DOC_FOLDER).join(THIRD_PARTY_FILE));
    paths
}

fn plain(status: StatusCode, body: impl Into<Body>) -> Response {
    let mut response = Response::new(body.into());
    *response.status_mut() = status;
    let headers = response.headers_mut();
    headers.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("text/plain; charset=utf-8"),
    );
    headers.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-cache"));
    headers.insert(
        header::X_CONTENT_TYPE_OPTIONS,
        HeaderValue::from_static("nosniff"),
    );
    response
}

async fn license() -> Response {
    plain(StatusCode::OK, LICENSE_TEXT)
}

async fn notice() -> Response {
    plain(StatusCode::OK, NOTICE_TEXT)
}

async fn third_party(State(paths): State<Arc<Vec<PathBuf>>>) -> Response {
    for path in paths.iter() {
        if let Ok(bytes) = tokio::fs::read(path).await {
            return plain(StatusCode::OK, bytes);
        }
    }
    plain(
        StatusCode::NOT_FOUND,
        "the third-party notices are not installed with this server",
    )
}

/// `/LICENSE.txt`, `/NOTICE.txt` and `/THIRD-PARTY-NOTICES.txt`, the last read from the first of
/// `third_party_paths` that exists.
pub fn router(third_party_paths: Vec<PathBuf>) -> Router {
    Router::new()
        .route("/LICENSE.txt", get(license))
        .route("/NOTICE.txt", get(notice))
        .route("/THIRD-PARTY-NOTICES.txt", get(third_party))
        .with_state(Arc::new(third_party_paths))
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::Request;
    use tower::ServiceExt;

    async fn get_text(router: Router, path: &str) -> (StatusCode, HeaderValue, String) {
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
        let content_type = response.headers()[header::CONTENT_TYPE].clone();
        let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .expect("a body");
        (
            status,
            content_type,
            String::from_utf8(bytes.to_vec()).expect("text"),
        )
    }

    #[test]
    fn the_source_is_at_the_commit_when_it_is_known() {
        let commit = "0123456789abcdef0123456789abcdef01234567";
        assert_eq!(
            source_url(None, Some(commit)),
            format!("https://github.com/Arsslensoft/Kemlock-Server/tree/{commit}")
        );
    }

    #[test]
    fn the_source_is_the_repository_when_the_commit_is_not_known() {
        assert_eq!(
            source_url(None, None),
            "https://github.com/Arsslensoft/Kemlock-Server"
        );
    }

    #[test]
    fn the_operators_address_wins() {
        assert_eq!(
            source_url(Some("https://git.example.org/me/kemlock"), Some("0123456")),
            "https://git.example.org/me/kemlock"
        );
    }

    #[test]
    fn only_a_hex_commit_is_believed() {
        assert_eq!(commit_of(None), None);
        assert_eq!(commit_of(Some("")), None);
        assert_eq!(commit_of(Some("  ")), None);
        assert_eq!(commit_of(Some("main")), None);
        assert_eq!(commit_of(Some("abc12")), None, "too short to name a commit");
        assert_eq!(commit_of(Some("../../etc")), None);
        assert_eq!(
            commit_of(Some(" ABCDEF0123 \n")),
            Some("abcdef0123".to_owned())
        );
    }

    #[tokio::test]
    async fn the_licence_and_the_notice_are_served_as_plain_text() {
        let (status, content_type, body) = get_text(router(Vec::new()), "/LICENSE.txt").await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(content_type, "text/plain; charset=utf-8");
        assert!(body.contains("GNU AFFERO GENERAL PUBLIC LICENSE"));
        let (status, _, body) = get_text(router(Vec::new()), "/NOTICE.txt").await;
        assert_eq!(status, StatusCode::OK);
        assert!(!body.trim().is_empty());
    }

    #[tokio::test]
    async fn the_third_party_notices_are_a_404_where_there_are_none() {
        let missing = std::env::temp_dir().join("kemlock-no-such-notices-folder");
        let (status, _, _) = get_text(
            router(vec![missing.join(THIRD_PARTY_FILE)]),
            "/THIRD-PARTY-NOTICES.txt",
        )
        .await;
        assert_eq!(status, StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn the_third_party_notices_come_from_the_first_place_that_has_them() {
        let first = tempfile::tempdir().expect("a temp dir");
        let second = tempfile::tempdir().expect("a temp dir");
        std::fs::write(second.path().join(THIRD_PARTY_FILE), "from the second").expect("written");
        let paths = vec![
            first.path().join(THIRD_PARTY_FILE),
            second.path().join(THIRD_PARTY_FILE),
        ];
        let (status, content_type, body) =
            get_text(router(paths.clone()), "/THIRD-PARTY-NOTICES.txt").await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(content_type, "text/plain; charset=utf-8");
        assert_eq!(body, "from the second");

        std::fs::write(first.path().join(THIRD_PARTY_FILE), "from the first").expect("written");
        let (_, _, body) = get_text(router(paths), "/THIRD-PARTY-NOTICES.txt").await;
        assert_eq!(body, "from the first");
    }
}
