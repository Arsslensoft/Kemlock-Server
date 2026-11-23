//! The web vault, embedded in the binary at build time and served with the design's headers
//! (design: Security, "Web vault hardening"; Performance targets, "Precompressed web vault,
//! immutable cache").
//!
//! Behind the `web` cargo feature, so the Rust workspace builds without `web/dist`: run
//! `npm run build` in `web/` first, then `cargo build -p kemlock-server --features web`. A release
//! build reads every file into the binary; a debug build reads `web/dist` from disk on each
//! request, which is the development override ([`is_dev_override`]).
//!
//! `npm run build` writes each text asset beside brotli, zstd and gzip copies (`app.js.br`, ...)
//! and a content hash in the name of everything under `assets/`. Those go out as stored, with the
//! smallest encoding the client accepts and `Cache-Control: public, max-age=31536000, immutable`.
//! `index.html` and the few unhashed files are revalidated with an ETag. A path that isn't a file
//! and has no extension is a route of the app, so it gets `index.html`.

use axum::Router;
use axum::body::Body;
use axum::http::{HeaderMap, HeaderName, HeaderValue, StatusCode, Uri, header};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use kemlock_api_kem::Problem;
use rust_embed::RustEmbed;
use std::borrow::Cow;
use std::fmt::Write as _;

/// `web/dist`, as `npm run build` left it.
#[derive(RustEmbed)]
#[folder = "../../web/dist"]
struct Dist;

/// The Content-Security-Policy of every web vault response: scripts only from this server, plus
/// `'wasm-unsafe-eval'` for the crypto worker's WebAssembly; no inline script, no `eval`; Trusted
/// Types required, with the one policy `kemlock`. The one outside call is the breach check's
/// k-anonymity request.
pub const CONTENT_SECURITY_POLICY: &str = "default-src 'none'; script-src 'self' \
     'wasm-unsafe-eval'; style-src 'self'; img-src 'self' data: blob:; font-src 'self'; \
     connect-src 'self' https://api.pwnedpasswords.com; worker-src 'self'; manifest-src 'self'; \
     frame-ancestors 'none'; base-uri 'none'; form-action 'self'; \
     require-trusted-types-for 'script'; trusted-types kemlock";

const IMMUTABLE: &str = "public, max-age=31536000, immutable";
const REVALIDATE: &str = "no-cache";

/// Whether files are read from `web/dist` on each request (a debug build) instead of from the
/// binary. The admin console and the build-hash check flag it.
pub fn is_dev_override() -> bool {
    cfg!(debug_assertions)
}

/// The routes that serve the web vault: `/` and everything else a GET asks for that the API and
/// the health routes didn't take. `/kem/...` addresses that don't exist stay JSON 404s.
pub fn router() -> Router {
    Router::new()
        .route("/", get(serve))
        .route("/{*path}", get(serve))
}

async fn serve(uri: Uri, headers: HeaderMap) -> Response {
    secure(respond(uri.path(), &headers))
}

/// The headers every web vault response carries, whatever its status.
fn secure(mut response: Response) -> Response {
    let headers = response.headers_mut();
    headers.insert(
        header::CONTENT_SECURITY_POLICY,
        HeaderValue::from_static(CONTENT_SECURITY_POLICY),
    );
    for (name, value) in [
        ("cross-origin-opener-policy", "same-origin"),
        ("cross-origin-embedder-policy", "require-corp"),
        ("cross-origin-resource-policy", "same-origin"),
    ] {
        headers.insert(
            HeaderName::from_static(name),
            HeaderValue::from_static(value),
        );
    }
    headers.insert(
        header::X_CONTENT_TYPE_OPTIONS,
        HeaderValue::from_static("nosniff"),
    );
    headers.insert(
        header::REFERRER_POLICY,
        HeaderValue::from_static("no-referrer"),
    );
    response
}

fn respond(path: &str, headers: &HeaderMap) -> Response {
    let trimmed = path.trim_start_matches('/');
    if trimmed == "kem" || trimmed.starts_with("kem/") {
        return Problem::not_found().into_response();
    }
    let name = if trimmed.is_empty() {
        "index.html"
    } else {
        trimmed
    };
    if let Some(response) = file(name, headers) {
        return response;
    }
    let last = name.rsplit('/').next().unwrap_or(name);
    if last.contains('.') || name.starts_with("assets/") {
        return text(StatusCode::NOT_FOUND, "not found");
    }
    file("index.html", headers).unwrap_or_else(|| {
        text(
            StatusCode::NOT_FOUND,
            "the web vault is not built into this server",
        )
    })
}

fn text(status: StatusCode, message: &'static str) -> Response {
    let mut response = Response::new(Body::from(message));
    *response.status_mut() = status;
    response.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("text/plain; charset=utf-8"),
    );
    response
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Encoding {
    Brotli,
    Zstd,
    Gzip,
}

impl Encoding {
    /// The `Content-Encoding` token.
    fn token(self) -> &'static str {
        match self {
            Encoding::Brotli => "br",
            Encoding::Zstd => "zstd",
            Encoding::Gzip => "gzip",
        }
    }

    /// The file extension `npm run build` gives the compressed copy.
    fn suffix(self) -> &'static str {
        match self {
            Encoding::Brotli => "br",
            Encoding::Zstd => "zst",
            Encoding::Gzip => "gz",
        }
    }
}

/// Whether an `Accept-Encoding` value offers `name` with a quality above zero.
fn offers(value: &str, name: &str) -> bool {
    value.split(',').any(|part| {
        let mut pieces = part.split(';');
        let token = pieces.next().unwrap_or("").trim();
        let refused = pieces.any(|piece| {
            piece
                .trim()
                .strip_prefix("q=")
                .and_then(|q| q.trim().parse::<f32>().ok())
                .is_some_and(|q| q <= 0.0)
        });
        token.eq_ignore_ascii_case(name) && !refused
    })
}

/// The encodings the client accepts, smallest first: brotli, zstd, gzip.
fn accepted(headers: &HeaderMap) -> Vec<Encoding> {
    let Some(value) = headers
        .get(header::ACCEPT_ENCODING)
        .and_then(|v| v.to_str().ok())
    else {
        return Vec::new();
    };
    [Encoding::Brotli, Encoding::Zstd, Encoding::Gzip]
        .into_iter()
        .filter(|encoding| offers(value, encoding.token()))
        .collect()
}

fn content_type(name: &str) -> &'static str {
    match name.rsplit('.').next().unwrap_or("") {
        "html" => "text/html; charset=utf-8",
        "js" | "mjs" => "text/javascript; charset=utf-8",
        "css" => "text/css; charset=utf-8",
        "json" => "application/json",
        "svg" => "image/svg+xml",
        "wasm" => "application/wasm",
        "woff2" => "font/woff2",
        "woff" => "font/woff",
        "png" => "image/png",
        "ico" => "image/x-icon",
        "txt" => "text/plain; charset=utf-8",
        _ => "application/octet-stream",
    }
}

fn hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        // Writing to a String can't fail.
        let _ = write!(out, "{byte:02x}");
    }
    out
}

/// Whether an `If-None-Match` value names `etag` (or is `*`).
fn matches(value: &str, etag: &str) -> bool {
    value.split(',').any(|candidate| {
        let candidate = candidate.trim();
        candidate == "*" || candidate.trim_start_matches("W/") == etag
    })
}

fn body_of(data: Cow<'static, [u8]>) -> Body {
    match data {
        Cow::Borrowed(bytes) => Body::from(bytes),
        Cow::Owned(bytes) => Body::from(bytes),
    }
}

/// One embedded file, in the best encoding the client takes; `None` when there is no such file.
fn file(name: &str, headers: &HeaderMap) -> Option<Response> {
    if name.contains("..") || name.contains('\\') {
        return None;
    }
    let original = Dist::get(name)?;
    let mut chosen = None;
    for encoding in accepted(headers) {
        if let Some(variant) = Dist::get(&format!("{name}.{}", encoding.suffix())) {
            chosen = Some((encoding, variant));
            break;
        }
    }
    let (encoding, embedded) = match chosen {
        Some((encoding, variant)) => (Some(encoding), variant),
        None => (None, original),
    };

    let etag = format!("\"{}\"", hex(&embedded.metadata.sha256_hash()));
    let unchanged = headers
        .get(header::IF_NONE_MATCH)
        .and_then(|v| v.to_str().ok())
        .is_some_and(|value| matches(value, &etag));
    let mut response = if unchanged {
        let mut response = Response::new(Body::empty());
        *response.status_mut() = StatusCode::NOT_MODIFIED;
        response
    } else {
        let mut response = Response::new(body_of(embedded.data));
        response.headers_mut().insert(
            header::CONTENT_TYPE,
            HeaderValue::from_static(content_type(name)),
        );
        response
    };
    let headers = response.headers_mut();
    if let Ok(value) = HeaderValue::from_str(&etag) {
        headers.insert(header::ETAG, value);
    }
    headers.insert(
        header::CACHE_CONTROL,
        HeaderValue::from_static(if name.starts_with("assets/") {
            IMMUTABLE
        } else {
            REVALIDATE
        }),
    );
    headers.insert(header::VARY, HeaderValue::from_static("Accept-Encoding"));
    if let Some(encoding) = encoding {
        headers.insert(
            header::CONTENT_ENCODING,
            HeaderValue::from_static(encoding.token()),
        );
    }
    Some(response)
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::Request;
    use tower::ServiceExt;

    fn headers(pairs: &[(&'static str, &'static str)]) -> HeaderMap {
        let mut map = HeaderMap::new();
        for (name, value) in pairs {
            map.insert(
                HeaderName::from_static(name),
                HeaderValue::from_static(value),
            );
        }
        map
    }

    #[test]
    fn the_policy_is_the_designs() {
        for part in [
            "default-src 'none'",
            "script-src 'self' 'wasm-unsafe-eval'",
            "style-src 'self'",
            "frame-ancestors 'none'",
            "base-uri 'none'",
            "require-trusted-types-for 'script'",
            "trusted-types kemlock",
        ] {
            assert!(CONTENT_SECURITY_POLICY.contains(part), "{part}");
        }
        assert!(!CONTENT_SECURITY_POLICY.contains("unsafe-inline"));
        assert!(!CONTENT_SECURITY_POLICY.contains("'unsafe-eval'"));
    }

    #[test]
    fn the_smallest_accepted_encoding_wins() {
        let all = headers(&[("accept-encoding", "gzip, deflate, br, zstd")]);
        assert_eq!(
            accepted(&all),
            vec![Encoding::Brotli, Encoding::Zstd, Encoding::Gzip]
        );
        let gzip = headers(&[("accept-encoding", "gzip;q=1.0, identity;q=0.5")]);
        assert_eq!(accepted(&gzip), vec![Encoding::Gzip]);
        assert!(accepted(&HeaderMap::new()).is_empty());
    }

    #[test]
    fn a_zero_quality_refuses_an_encoding() {
        assert!(!offers("br;q=0, gzip", "br"));
        assert!(offers("br;q=0, gzip", "gzip"));
        assert!(offers("BR", "br"));
        assert!(!offers("brotli", "br"));
    }

    #[test]
    fn if_none_match_names_the_etag() {
        assert!(matches("\"abc\"", "\"abc\""));
        assert!(matches("W/\"abc\", \"def\"", "\"abc\""));
        assert!(matches("*", "\"abc\""));
        assert!(!matches("\"abd\"", "\"abc\""));
    }

    #[test]
    fn types_follow_the_extension() {
        assert_eq!(
            content_type("assets/app-1a2b.js"),
            "text/javascript; charset=utf-8"
        );
        assert_eq!(
            content_type("assets/app-1a2b.css"),
            "text/css; charset=utf-8"
        );
        assert_eq!(content_type("assets/crypto.wasm"), "application/wasm");
        assert_eq!(content_type("index.html"), "text/html; charset=utf-8");
        assert_eq!(content_type("unknown.bin"), "application/octet-stream");
    }

    #[test]
    fn hashes_are_lower_case_hex() {
        assert_eq!(hex(&[0x00, 0xab, 0xff]), "00abff");
    }

    #[test]
    fn a_file_name_that_climbs_out_is_no_file() {
        assert!(file("../Cargo.toml", &HeaderMap::new()).is_none());
        assert!(file("assets\\app.js", &HeaderMap::new()).is_none());
    }

    #[tokio::test]
    async fn an_unknown_api_address_is_a_json_404_with_the_headers() {
        let response = router()
            .oneshot(
                Request::builder()
                    .uri("/kem/v1/nothing-here")
                    .body(Body::empty())
                    .expect("a valid request"),
            )
            .await
            .expect("infallible");
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
        assert_eq!(
            response.headers()[header::CONTENT_TYPE],
            "application/problem+json"
        );
        assert_eq!(
            response.headers()[header::CONTENT_SECURITY_POLICY],
            CONTENT_SECURITY_POLICY
        );
        assert_eq!(
            response.headers()["cross-origin-opener-policy"],
            "same-origin"
        );
    }
}
