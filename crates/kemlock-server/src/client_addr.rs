//! The client address of each request, settled once for the whole server.
//!
//! The layer works out who the client is the way the Kemlock API's rate limits do: the peer that
//! opened the connection, or, when that peer is a trusted proxy (`KEMLOCK_TRUSTED_PROXIES`) and
//! `IP_HEADER` names the client, the address in that header. It puts the answer in the request's
//! extensions as [`ClientAddr`] (the Bitwarden API's sign-in log reads it there) and runs the rest
//! of the request inside [`with_request_ip`], so every event the request writes carries the
//! address through `SqlStore`'s event log. The privacy port cuts the address to its /24 or /48 on
//! write (the whole one is kept only while the admin keeps full addresses, up to 30 days).

use crate::config::Config;
use axum::extract::{ConnectInfo, Request, State};
use axum::http::HeaderMap;
use axum::middleware::Next;
use axum::response::Response;
use kemlock_api_kem::ratelimit::{Proxy, client_ip, joined_header};
use kemlock_app::privacy::ClientAddr;
use kemlock_store_sql::with_request_ip;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;

/// What tells a proxy's client from the proxy.
#[derive(Clone, Debug, Default)]
pub struct ClientAddrSettings {
    pub trusted_proxies: Vec<Proxy>,
    pub ip_header: Option<String>,
}

impl ClientAddrSettings {
    pub fn from_config(config: &Config) -> Arc<Self> {
        Arc::new(ClientAddrSettings {
            trusted_proxies: config.trusted_proxies.clone(),
            ip_header: config.ip_header.clone(),
        })
    }

    /// The client's address, from the connection's peer and the request's headers; `None` when the
    /// server wasn't started to tell the peer (tests that call the router directly).
    pub fn settle(&self, peer: Option<IpAddr>, headers: &HeaderMap) -> Option<IpAddr> {
        let peer = peer?;
        // Every line of the header, not the first: a proxy may append its own line after the
        // client's, and the client's own line must not name the address.
        let header = self
            .ip_header
            .as_deref()
            .and_then(|name| joined_header(headers, name));
        Some(client_ip(peer, header.as_deref(), &self.trusted_proxies))
    }
}

/// The middleware: settles the address and serves the request inside its scope. Use it with
/// `axum::middleware::from_fn_with_state`, outermost, so every route is covered.
pub async fn settle_client_address(
    State(settings): State<Arc<ClientAddrSettings>>,
    mut request: Request,
    next: Next,
) -> Response {
    let peer = request
        .extensions()
        .get::<ConnectInfo<SocketAddr>>()
        .map(|c| c.0.ip());
    let ip = settings.settle(peer, request.headers());
    if let Some(ip) = ip {
        request.extensions_mut().insert(ClientAddr(ip));
    }
    with_request_ip(ip, next.run(request)).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::Router;
    use axum::body::Body;
    use axum::http::{Request as HttpRequest, StatusCode};
    use axum::middleware::from_fn_with_state;
    use axum::routing::get;
    use kemlock_app::ports::{Event, EventLog};
    use kemlock_app::privacy::PrivacyLog;
    use kemlock_domain::UserId;
    use kemlock_store_sql::{SqlStore, request_ip};
    use time::macros::datetime;
    use tower::ServiceExt;

    fn ip(text: &str) -> IpAddr {
        text.parse().expect("an address")
    }

    fn settings(proxies: &[&str], header: Option<&str>) -> ClientAddrSettings {
        ClientAddrSettings {
            trusted_proxies: proxies.iter().map(|p| Proxy::from(ip(p))).collect(),
            ip_header: header.map(str::to_owned),
        }
    }

    fn headers(name: &'static str, value: &str) -> HeaderMap {
        let mut map = HeaderMap::new();
        map.insert(name, value.parse().expect("a header value"));
        map
    }

    #[test]
    fn the_peer_is_the_client_unless_a_trusted_proxy_names_another() {
        let s = settings(&["10.0.0.1"], Some("x-forwarded-for"));
        let forwarded = headers("x-forwarded-for", "198.51.100.7");
        assert_eq!(
            s.settle(Some(ip("10.0.0.1")), &forwarded),
            Some(ip("198.51.100.7")),
            "behind a trusted proxy"
        );
        assert_eq!(
            s.settle(Some(ip("203.0.113.5")), &forwarded),
            Some(ip("203.0.113.5")),
            "a stranger's header is not believed"
        );
        assert_eq!(s.settle(None, &forwarded), None, "no peer, no address");
    }

    #[test]
    fn a_proxy_that_adds_its_own_header_line_is_read_last() {
        // HAProxy's `option forwardfor` adds a separate line after the client's own.
        let s = settings(&["10.0.0.1"], Some("x-forwarded-for"));
        let mut forwarded = HeaderMap::new();
        forwarded.append("x-forwarded-for", "1.2.3.4".parse().expect("a value"));
        forwarded.append("x-forwarded-for", "198.51.100.7".parse().expect("a value"));
        assert_eq!(
            s.settle(Some(ip("10.0.0.1")), &forwarded),
            Some(ip("198.51.100.7")),
            "the proxy's line, not the client's"
        );
    }

    /// A route that writes an event from inside a request, as a use case does.
    fn app(store: SqlStore, settings: ClientAddrSettings, actor: UserId) -> Router {
        Router::new()
            .route(
                "/",
                get(move |request: HttpRequest<Body>| {
                    let store = store.clone();
                    async move {
                        let settled = request.extensions().get::<ClientAddr>().map(|a| a.0);
                        assert_eq!(settled, request_ip(), "one address for both readers");
                        EventLog::record(
                            &store,
                            Event {
                                actor: Some(actor),
                                device: None,
                                action: "test.request",
                                target: None,
                                at: datetime!(2026-01-02 03:04:05 UTC),
                            },
                        )
                        .await
                        .expect("the event is written");
                        StatusCode::NO_CONTENT
                    }
                }),
            )
            .layer(from_fn_with_state(
                Arc::new(settings),
                settle_client_address,
            ))
    }

    async fn call(app: Router, peer: Option<&str>) {
        let mut request = HttpRequest::builder()
            .uri("/")
            .body(Body::empty())
            .expect("a request");
        if let Some(peer) = peer {
            request
                .extensions_mut()
                .insert(ConnectInfo(SocketAddr::new(ip(peer), 40_000)));
        }
        let response = app.oneshot(request).await.expect("the router answers");
        assert_eq!(response.status(), StatusCode::NO_CONTENT);
    }

    #[tokio::test]
    async fn an_event_written_by_a_request_carries_its_truncated_address() {
        let store = SqlStore::connect("sqlite::memory:").await.expect("a store");
        let actor = UserId::random();
        let plain = || app(store.clone(), settings(&[], None), actor);
        call(plain(), Some("203.0.113.77")).await;
        call(plain(), Some("2001:db8:1:2::7")).await;
        call(plain(), None).await;

        let events = PrivacyLog::events_of(&store, actor).await.expect("events");
        let mut addresses: Vec<Option<&str>> = events.iter().map(|e| e.ip.as_deref()).collect();
        addresses.sort_unstable();
        assert_eq!(
            addresses,
            vec![None, Some("2001:db8:1::/48"), Some("203.0.113.0/24")]
        );
    }
}
