//! `/kem/v1/webauthn`: a page of this server that a client which is not a page of it (the browser
//! extension) opens to run a passkey or security-key ceremony with PRF for the server's relying
//! party. WebAuthn binds an answer to the origin of the page that asks, so only a page on this
//! server's own origin can ask for this server's passkeys.
//!
//! The page is static and its script is a file of its own, so the policy below allows no inline
//! script. The request travels in the URL fragment, which no server sees, and the answer goes
//! only to an extension redirect address (or opener) whose id `KEMLOCK_BROWSER_EXTENSION_IDS`
//! names; the page reads that list from a `<meta>` tag.

use crate::state::{Api, Crypto, Store};
use axum::extract::State;
use axum::http::{HeaderName, HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};
use kemlock_app::ports::TokenSigner;

const PAGE: &str = include_str!("../../assets/webauthn.html");
const SCRIPT: &str = include_str!("../../assets/webauthn.js");

/// What the page's HTML carries where the allowlist goes.
const IDS_PLACEHOLDER: &str = "{{extension-ids}}";

/// The page's policy: its own script and nothing else, no connections, no framing, no forms, and
/// Trusted Types required so no string reaches a script sink.
pub(crate) const CONNECTOR_CSP: &str = "default-src 'none'; script-src 'self'; base-uri 'none'; \
     form-action 'none'; frame-ancestors 'none'; connect-src 'none'; \
     require-trusted-types-for 'script'";

/// The page with the allowlist in it. The ids are letters and digits only (the config refuses
/// anything else), and are escaped again here so no value can leave the attribute.
pub(crate) fn render(ids: &[String]) -> String {
    let list = ids
        .iter()
        .filter(|id| id.chars().all(|c| c.is_ascii_alphanumeric()))
        .cloned()
        .collect::<Vec<_>>()
        .join(",");
    PAGE.replace(IDS_PLACEHOLDER, &list)
}

fn respond(content_type: &'static str, cache: &'static str, body: String) -> Response {
    let mut response = (StatusCode::OK, body).into_response();
    let headers = response.headers_mut();
    headers.insert(header::CONTENT_TYPE, HeaderValue::from_static(content_type));
    headers.insert(header::CACHE_CONTROL, HeaderValue::from_static(cache));
    headers.insert(
        header::CONTENT_SECURITY_POLICY,
        HeaderValue::from_static(CONNECTOR_CSP),
    );
    headers.insert(
        header::X_CONTENT_TYPE_OPTIONS,
        HeaderValue::from_static("nosniff"),
    );
    headers.insert(
        header::REFERRER_POLICY,
        HeaderValue::from_static("no-referrer"),
    );
    headers.insert(header::X_FRAME_OPTIONS, HeaderValue::from_static("DENY"));
    // The page needs its opener (the extension that opened it), so no opener policy is set;
    // other pages can't read it, and it answers only the allowlist.
    headers.insert(
        HeaderName::from_static("cross-origin-resource-policy"),
        HeaderValue::from_static("same-origin"),
    );
    response
}

impl<S: Store, P: Crypto, K: TokenSigner + Clone + 'static> Api<S, P, K> {
    /// `GET /kem/v1/webauthn`: the connector page.
    pub(crate) async fn handle_webauthn_page(State(api): State<Self>) -> Response {
        respond(
            "text/html; charset=utf-8",
            "no-store",
            render(&api.config.browser_extension_ids),
        )
    }

    /// `GET /kem/v1/webauthn/connector.js`: the page's script.
    pub(crate) async fn handle_webauthn_script() -> Response {
        respond(
            "text/javascript; charset=utf-8",
            "no-cache",
            SCRIPT.to_owned(),
        )
    }
}
