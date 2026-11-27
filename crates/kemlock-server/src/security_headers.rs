//! Security headers on every response, not only the web vault's.
//!
//! The web vault's responses carry the full set (`web.rs`: a strict Content-Security-Policy and
//! the cross-origin policies). The API, the admin console's routes, the health routes and the
//! plain-text files carried none, so a browser that opens one of them directly sniffed its type, sent
//! a referrer and could frame it. This layer adds, to any response that doesn't set it already:
//!
//! - `X-Content-Type-Options: nosniff`;
//! - `Referrer-Policy: no-referrer`;
//! - `X-Frame-Options: DENY`;
//! - `Strict-Transport-Security: max-age=31536000` when `DOMAIN` is an `https://` address, so a
//!   browser that has seen the server once never asks for it over plain HTTP again. Without
//!   `includeSubDomains`: the server doesn't speak for the rest of the domain.
//!
//! Only headers that are safe for every route go here. The cross-origin policies stay with the web
//! vault, because the browser extension reads the API across origins.

use axum::extract::{Request, State};
use axum::http::{HeaderValue, header};
use axum::middleware::Next;
use axum::response::Response;

/// The `Strict-Transport-Security` value: a year.
pub const HSTS: &str = "max-age=31536000";

/// What the layer needs to know: whether to say HSTS.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SecurityHeaders {
    pub hsts: bool,
}

impl SecurityHeaders {
    /// HSTS only for a `DOMAIN` that starts with `https://`: said over plain HTTP it would be
    /// ignored, and said for a name that has no TLS it would lock people out.
    pub fn for_domain(domain: &str) -> SecurityHeaders {
        SecurityHeaders {
            hsts: domain
                .trim_start()
                .to_ascii_lowercase()
                .starts_with("https://"),
        }
    }
}

/// The middleware. Layer it outermost with `axum::middleware::from_fn_with_state`.
pub async fn add_security_headers(
    State(settings): State<SecurityHeaders>,
    request: Request,
    next: Next,
) -> Response {
    let mut response = next.run(request).await;
    let headers = response.headers_mut();
    let mut set_if_missing = |name: header::HeaderName, value: &'static str| {
        if !headers.contains_key(&name) {
            headers.insert(name, HeaderValue::from_static(value));
        }
    };
    set_if_missing(header::X_CONTENT_TYPE_OPTIONS, "nosniff");
    set_if_missing(header::REFERRER_POLICY, "no-referrer");
    set_if_missing(header::X_FRAME_OPTIONS, "DENY");
    if settings.hsts {
        set_if_missing(header::STRICT_TRANSPORT_SECURITY, HSTS);
    }
    response
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::Router;
    use axum::body::Body;
    use axum::http::{Request as HttpRequest, StatusCode};
    use axum::middleware::from_fn_with_state;
    use axum::routing::get;
    use tower::ServiceExt;

    fn app(settings: SecurityHeaders) -> Router {
        Router::new()
            .route("/plain", get(|| async { "ok" }))
            .route(
                "/own",
                get(|| async {
                    (
                        StatusCode::NOT_FOUND,
                        [(header::X_FRAME_OPTIONS, "SAMEORIGIN")],
                        "no",
                    )
                }),
            )
            .layer(from_fn_with_state(settings, add_security_headers))
    }

    async fn headers_of(app: Router, path: &str) -> axum::http::HeaderMap {
        app.oneshot(
            HttpRequest::builder()
                .uri(path)
                .body(Body::empty())
                .expect("a request"),
        )
        .await
        .expect("infallible")
        .headers()
        .clone()
    }

    #[test]
    fn hsts_is_for_https_domains_only() {
        assert!(SecurityHeaders::for_domain("https://vault.example.org").hsts);
        assert!(SecurityHeaders::for_domain(" HTTPS://vault.example.org").hsts);
        assert!(!SecurityHeaders::for_domain("http://vault.example.org").hsts);
        assert!(!SecurityHeaders::for_domain("http://localhost:8080").hsts);
    }

    #[tokio::test]
    async fn every_response_carries_the_headers_and_hsts_follows_the_domain() {
        let headers = headers_of(app(SecurityHeaders { hsts: true }), "/plain").await;
        assert_eq!(headers[header::X_CONTENT_TYPE_OPTIONS], "nosniff");
        assert_eq!(headers[header::REFERRER_POLICY], "no-referrer");
        assert_eq!(headers[header::X_FRAME_OPTIONS], "DENY");
        assert_eq!(headers[header::STRICT_TRANSPORT_SECURITY], HSTS);

        let headers = headers_of(app(SecurityHeaders { hsts: false }), "/plain").await;
        assert!(!headers.contains_key(header::STRICT_TRANSPORT_SECURITY));
        assert_eq!(headers[header::X_CONTENT_TYPE_OPTIONS], "nosniff");
    }

    #[tokio::test]
    async fn a_header_the_route_set_is_kept_and_an_error_response_gets_the_rest() {
        let headers = headers_of(app(SecurityHeaders { hsts: false }), "/own").await;
        assert_eq!(headers[header::X_FRAME_OPTIONS], "SAMEORIGIN");
        assert_eq!(headers[header::X_CONTENT_TYPE_OPTIONS], "nosniff");
        // Not found, too: an unrouted path is a response like any other.
        let headers = headers_of(app(SecurityHeaders { hsts: false }), "/nowhere").await;
        assert_eq!(headers[header::REFERRER_POLICY], "no-referrer");
    }
}
