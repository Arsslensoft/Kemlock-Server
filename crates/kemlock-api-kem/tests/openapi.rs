//! One OpenAPI document for `/kem/v1`: every route the crate mounts is in it, whichever router
//! mounts it.

mod common;

use axum::http::StatusCode;
use common::App;
use std::collections::BTreeSet;
use std::path::Path;

/// The paths named by the `.route("...", ...)` calls in `source`, in the order they appear.
fn routed(source: &str) -> Vec<String> {
    let mut paths = Vec::new();
    let mut rest = source;
    while let Some(at) = rest.find(".route(") {
        rest = &rest[at + ".route(".len()..];
        if let Some(after) = rest.trim_start().strip_prefix('"')
            && let Some(end) = after.find('"')
        {
            paths.push(after[..end].to_owned());
        }
    }
    paths
}

/// Every `.route` of the crate's sources: the main router, and the routers that live beside
/// their handlers.
fn routed_paths() -> BTreeSet<String> {
    let src = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let mut files = vec![src.join("service.rs")];
    for entry in std::fs::read_dir(src.join("routes")).expect("the routes folder reads") {
        let path = entry.expect("an entry").path();
        if path.extension().is_some_and(|e| e == "rs") {
            files.push(path);
        }
    }
    files
        .iter()
        .flat_map(|file| {
            let source = std::fs::read_to_string(file).expect("a source file reads");
            routed(&source)
        })
        .filter(|path| path.starts_with("/kem/v1/"))
        .collect()
}

#[test]
fn the_scan_reads_route_calls() {
    let source = r#"
        Router::new()
            .route("/kem/v1/a", get(a))
            .route(
                "/kem/v1/b/{id}",
                post(b),
            )
            .route(path, get(c))
    "#;
    assert_eq!(routed(source), vec!["/kem/v1/a", "/kem/v1/b/{id}"]);
}

#[test]
fn the_scan_finds_the_whole_api() {
    let paths = routed_paths();
    // A scan that found little would make the check below pass for nothing.
    assert!(paths.len() > 50, "found only {} routes", paths.len());
    for known in [
        "/kem/v1/sync",
        "/kem/v1/items/{id}",
        "/kem/v1/spaces/{id}/members",
        "/kem/v1/items/{id}/files/{file}",
        "/kem/v1/auth/sso/start",
        "/kem/v1/devices/key-copy",
        "/kem/v1/emergency/grants/{id}",
    ] {
        assert!(paths.contains(known), "{known} isn't found");
    }
}

#[tokio::test]
async fn every_routed_path_is_in_the_one_document() {
    let app = App::new(false);
    let reply = app.client().get("/kem/v1/openapi.json").await;
    assert_eq!(reply.status, StatusCode::OK);
    let json = reply.json();
    let documented: BTreeSet<&str> = json["paths"]
        .as_object()
        .expect("the document has paths")
        .keys()
        .map(String::as_str)
        .collect();
    let missing: Vec<String> = routed_paths()
        .into_iter()
        .filter(|path| !documented.contains(path.as_str()))
        .collect();
    assert!(missing.is_empty(), "routed but not documented: {missing:?}");
    // And nothing is documented that isn't routed: a stale stub misleads clients.
    let routed = routed_paths();
    let stale: Vec<&&str> = documented
        .iter()
        .filter(|path| !routed.contains(**path))
        .collect();
    assert!(stale.is_empty(), "documented but not routed: {stale:?}");
}

#[tokio::test]
async fn the_document_has_the_parts_that_lived_apart() {
    let app = App::new(false);
    let json = app.client().get("/kem/v1/openapi.json").await.json();
    for (path, method) in [
        ("/kem/v1/items/{id}/files/{file}/finish", "post"),
        ("/kem/v1/auth/sso/callback", "get"),
        ("/kem/v1/spaces/{id}/key-replacement", "post"),
        ("/kem/v1/devices/sign-out", "post"),
        ("/kem/v1/emergency/grants/{id}/approve", "post"),
    ] {
        assert!(
            json["paths"][path][method].is_object(),
            "{method} {path} is documented"
        );
    }
    for schema in [
        "ItemDto",
        "FileDto",
        "SpaceViewDto",
        "KeyCopyResponse",
        "FinishResponse",
    ] {
        assert!(
            json["components"]["schemas"][schema].is_object(),
            "{schema} is in the components"
        );
    }
}

/// `test-vectors/openapi.json` is this document, for clients' contract tests to check against
/// without building the server (the Kemlock app copies it). `KEMLOCK_WRITE_OPENAPI=1` rewrites it;
/// then update its line in `test-vectors/SHA256SUMS` (kemlock-crypto's checksum test says so).
#[tokio::test]
async fn the_committed_openapi_file_is_the_served_document() {
    let app = App::new(false);
    let served = app.client().get("/kem/v1/openapi.json").await.json();
    let file = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../test-vectors/openapi.json");
    if std::env::var_os("KEMLOCK_WRITE_OPENAPI").is_some() {
        let text = serde_json::to_string_pretty(&served).expect("the document")
            + "
";
        std::fs::write(&file, text).expect("test-vectors/openapi.json is written");
    }
    let committed: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&file).expect("test-vectors/openapi.json"))
            .expect("JSON");
    assert!(
        committed == served,
        "test-vectors/openapi.json is not the served document: rerun with KEMLOCK_WRITE_OPENAPI=1"
    );
}

#[tokio::test]
async fn every_operation_has_the_common_answers() {
    let app = App::new(false);
    let json = app.client().get("/kem/v1/openapi.json").await.json();
    let problem = "#/components/schemas/ProblemDoc";
    let mut signed_in = 0;
    for (path, item) in json["paths"].as_object().expect("paths") {
        if path == "/kem/v1/openapi.json" {
            continue;
        }
        for (method, operation) in item.as_object().expect("a path item") {
            if !["get", "put", "post", "delete", "patch"].contains(&method.as_str()) {
                continue;
            }
            let answers = &operation["responses"];
            let secured = operation["security"]
                .as_array()
                .is_some_and(|s| !s.is_empty());
            assert!(answers["500"].is_object(), "{method} {path} has no 500");
            assert_eq!(
                answers["500"]["content"]["application/problem+json"]["schema"]["$ref"], problem,
                "{method} {path}: 500 isn't a problem"
            );
            if path != "/kem/v1/config" {
                assert!(answers["429"].is_object(), "{method} {path} has no 429");
            }
            if secured {
                signed_in += 1;
                assert!(answers["401"].is_object(), "{method} {path} has no 401");
            }
        }
    }
    assert!(
        signed_in > 20,
        "found only {signed_in} signed-in operations"
    );
}

#[tokio::test]
async fn the_document_says_what_the_code_takes_and_answers() {
    let app = App::new(false);
    let json = app.client().get("/kem/v1/openapi.json").await.json();
    let schemas = &json["components"]["schemas"];
    // GET /config: a repeated `vault`.
    let vault = json["paths"]["/kem/v1/config"]["get"]["parameters"]
        .as_array()
        .and_then(|p| p.iter().find(|p| p["name"] == "vault"))
        .expect("`vault` is documented");
    assert_eq!(vault["in"], "query");
    assert_eq!(vault["explode"], true);
    assert_eq!(vault["schema"]["type"], "array");
    // Item writes carry tags.
    for schema in [
        "ItemWriteDto",
        "ItemWriteAnswerDto",
        "TaggedBatchRequest",
        "TaggedBatchResponse",
    ] {
        assert!(schemas[schema].is_object(), "{schema} is in the components");
    }
    assert!(schemas["ItemWriteDto"].to_string().contains("tagVersion"));
    assert!(
        schemas["ItemWriteAnswerDto"]
            .to_string()
            .contains("tagsStored")
    );
    assert!(schemas["TaggedBatchResponse"]["properties"]["tags"].is_object());
    // Two groups, two schemas.
    assert!(schemas["DuplicateGroupDto"]["properties"]["items"].is_object());
    assert!(schemas["GroupDto"]["properties"]["members"].is_object());
    assert!(
        schemas["DuplicatesResponse"]["properties"]["groups"]["items"]["$ref"]
            .as_str()
            .is_some_and(|r| r.ends_with("/DuplicateGroupDto"))
    );
    // A Send opens without a body.
    for path in [
        "/kem/v1/send-access/{access_id}",
        "/kem/v1/send-access/{access_id}/file",
    ] {
        let body = &json["paths"][path]["post"]["requestBody"];
        assert!(body.is_object(), "{path} has a body");
        assert_ne!(body["required"], true, "{path}'s body is optional");
    }
    // Problems list their extension members.
    for member in [
        "itemId",
        "currentRevision",
        "retryAfter",
        "maxSize",
        "head",
        "seq",
    ] {
        assert!(
            schemas["ProblemDoc"]["properties"][member].is_object(),
            "ProblemDoc has {member}"
        );
    }
}
