//! The outbound side over the network: the WebSocket client that opens a peer session, and the
//! plain HTTPS calls of the descriptor and of pairing.
//!
//! TLS is the transport, not the security boundary: a session is sealed again inside it with keys
//! from the two servers' own identities (`docs/federation.md`), so a proxy that ends TLS, or a
//! certificate someone forged, sees only sealed frames. Addresses are base URLs
//! (`https://vault.example.org`); `http` and `ws` are accepted for a peer on a private network.

use crate::descriptor::SignedDescriptor;
use crate::error::{FedError, Result};
use crate::job::Connector;
use crate::ports::Peer;
use crate::replicate::{FedStore, Replica};
use crate::session::{SecureChannel, Transport, unix_now};
use futures_util::{SinkExt, StreamExt};
use std::sync::Arc;
use std::time::Duration;
use tokio::net::TcpStream;
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::tungstenite::protocol::WebSocketConfig;
use tokio_tungstenite::{Connector as TlsConnector, MaybeTlsStream, WebSocketStream};

/// How long a request, or the wait for one answer, may take.
pub const TIMEOUT: Duration = Duration::from_secs(30);
/// The largest descriptor or pairing message read over HTTP.
const MAX_HTTP_BODY: usize = 128 * 1024;
/// The largest WebSocket message read: a frame carries at most 4 MiB, plus its header, tag and
/// padding.
const MAX_WS_MESSAGE: usize = 5 * 1024 * 1024;

/// The path of the peer session, below an address.
pub const SESSION_PATH: &str = "/fed/v1/session";
/// The path of the descriptor.
pub const DESCRIPTOR_PATH: &str = "/fed/v1/descriptor";
/// The path key records are posted to.
pub const KEYS_PATH: &str = "/fed/v1/keys";

fn unreachable_peer(what: &'static str) -> FedError {
    FedError::Remote(what.to_owned())
}

/// `address` and `path` joined: `https://a.example.org/` and `/fed/v1/x` give
/// `https://a.example.org/fed/v1/x`. Only `http` and `https` addresses are accepted.
pub fn http_url(address: &str, path: &str) -> Result<String> {
    let url = url::Url::parse(address).map_err(|_| FedError::Invalid("an address is not a URL"))?;
    if !matches!(url.scheme(), "http" | "https") || url.host_str().is_none() {
        return Err(FedError::Invalid("an address must be an http or https URL"));
    }
    let base = url.as_str().trim_end_matches('/');
    Ok(format!("{base}{path}"))
}

/// The WebSocket URL of the peer session at `address`: `https` becomes `wss`, `http` becomes `ws`.
pub fn ws_url(address: &str) -> Result<String> {
    let http = http_url(address, SESSION_PATH)?;
    Ok(if let Some(rest) = http.strip_prefix("https://") {
        format!("wss://{rest}")
    } else {
        format!("ws://{}", http.trim_start_matches("http://"))
    })
}

/// The HTTP calls of federation: the descriptor and the pairing messages.
#[derive(Clone, Debug)]
pub struct Http {
    client: reqwest::Client,
}

impl Http {
    pub fn new() -> Result<Http> {
        let client = reqwest::Client::builder()
            .timeout(TIMEOUT)
            .connect_timeout(Duration::from_secs(10))
            .redirect(reqwest::redirect::Policy::none())
            .user_agent("kemlock-server")
            .build()
            .map_err(|_| FedError::Invalid("the HTTP client could not be built"))?;
        Ok(Http { client })
    }

    async fn read(response: reqwest::Response) -> Result<Vec<u8>> {
        if !response.status().is_success() {
            return Err(unreachable_peer("the peer answered with an error status"));
        }
        if response
            .content_length()
            .is_some_and(|n| n > MAX_HTTP_BODY as u64)
        {
            return Err(FedError::Malformed("an HTTP body is too large"));
        }
        let bytes = response
            .bytes()
            .await
            .map_err(|_| unreachable_peer("the peer's answer could not be read"))?;
        if bytes.len() > MAX_HTTP_BODY {
            return Err(FedError::Malformed("an HTTP body is too large"));
        }
        Ok(bytes.to_vec())
    }

    pub async fn get(&self, url: &str) -> Result<Vec<u8>> {
        let response = self
            .client
            .get(url)
            .send()
            .await
            .map_err(|_| unreachable_peer("the peer could not be reached"))?;
        Self::read(response).await
    }

    pub async fn post(&self, url: &str, body: Vec<u8>) -> Result<Vec<u8>> {
        let response = self
            .client
            .post(url)
            .header(
                "content-type",
                "application/vnd.kemlock.federation-pairing+cbor",
            )
            .body(body)
            .send()
            .await
            .map_err(|_| unreachable_peer("the peer could not be reached"))?;
        Self::read(response).await
    }

    /// The descriptor published at `address`, parsed but not yet checked.
    pub async fn descriptor(&self, address: &str) -> Result<SignedDescriptor> {
        let bytes = self.get(&http_url(address, DESCRIPTOR_PATH)?).await?;
        SignedDescriptor::parse(&bytes)
    }
}

type Socket = WebSocketStream<MaybeTlsStream<TcpStream>>;

/// A WebSocket as a [`Transport`]: one binary message out, the next binary message in.
pub struct WsTransport {
    socket: Socket,
}

impl std::fmt::Debug for WsTransport {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WsTransport").finish_non_exhaustive()
    }
}

fn tls() -> Result<TlsConnector> {
    let mut roots = rustls::RootCertStore::empty();
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    // The provider is named, not left to the process default, so a binary that links more than one
    // rustls provider still works.
    let config = rustls::ClientConfig::builder_with_provider(Arc::new(
        rustls::crypto::aws_lc_rs::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .map_err(|_| FedError::Invalid("TLS could not be set up"))?
    .with_root_certificates(roots)
    .with_no_client_auth();
    Ok(TlsConnector::Rustls(Arc::new(config)))
}

/// Opens the session WebSocket at `address`.
pub async fn connect_ws(address: &str) -> Result<WsTransport> {
    let url = ws_url(address)?;
    let connector = if url.starts_with("wss://") {
        Some(tls()?)
    } else {
        None
    };
    let config = WebSocketConfig::default()
        .max_message_size(Some(MAX_WS_MESSAGE))
        .max_frame_size(Some(MAX_WS_MESSAGE));
    let connecting =
        tokio_tungstenite::connect_async_tls_with_config(url, Some(config), true, connector);
    let (socket, _response) = tokio::time::timeout(TIMEOUT, connecting)
        .await
        .map_err(|_| unreachable_peer("the peer did not answer in time"))?
        .map_err(|_| unreachable_peer("the peer's session could not be opened"))?;
    Ok(WsTransport { socket })
}

impl Transport for WsTransport {
    async fn exchange(&mut self, message: Vec<u8>) -> Result<Vec<u8>> {
        self.socket
            .send(Message::Binary(message.into()))
            .await
            .map_err(|_| FedError::Frame("the session was closed"))?;
        let next = async {
            loop {
                match self.socket.next().await {
                    Some(Ok(Message::Binary(bytes))) => return Ok(bytes.to_vec()),
                    Some(Ok(Message::Ping(_) | Message::Pong(_))) => continue,
                    _ => return Err(FedError::Frame("the session was closed")),
                }
            }
        };
        tokio::time::timeout(TIMEOUT, next)
            .await
            .map_err(|_| FedError::Frame("the peer did not answer in time"))?
    }
}

/// Opens sessions over the network: reads the peer's descriptor from each of its addresses, checks
/// it against the pinned key, connects the WebSocket and runs the handshake.
pub struct WsConnector<S> {
    replica: Arc<Replica<S>>,
    http: Http,
}

impl<S> std::fmt::Debug for WsConnector<S> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WsConnector").finish_non_exhaustive()
    }
}

impl<S: FedStore> WsConnector<S> {
    pub fn new(replica: Arc<Replica<S>>) -> Result<WsConnector<S>> {
        Ok(WsConnector {
            replica,
            http: Http::new()?,
        })
    }
}

impl<S: FedStore> Connector for WsConnector<S> {
    type Chan = SecureChannel<WsTransport>;

    async fn connect(&self, peer: &Peer) -> Result<Self::Chan> {
        let pinned = peer.key()?;
        let mut last = FedError::Remote("the peer has no address".to_owned());
        for address in &peer.addresses {
            let now = unix_now();
            let descriptor = match self.http.descriptor(address).await {
                Ok(descriptor) => descriptor,
                Err(e) => {
                    last = e;
                    continue;
                }
            };
            // A key that isn't the pinned one is not "try the next address": it is the alert.
            descriptor.verify(now, Some(&pinned))?;
            let d = &descriptor.descriptor;
            if let Err(e) = self
                .replica
                .store()
                .update_peer_descriptor(peer.id, &d.operator, &d.addresses, &d.suites)
                .await
            {
                tracing::debug!(error = %e, "couldn't refresh what a peer's descriptor says");
            }
            let transport = match connect_ws(address).await {
                Ok(transport) => transport,
                Err(e) => {
                    last = e;
                    continue;
                }
            };
            return self
                .replica
                .connect(peer.id, &descriptor, transport, now)
                .await;
        }
        Err(last)
    }

    async fn close(&self, channel: Self::Chan) -> Result<()> {
        channel.close().await
    }

    async fn send_key_record(&self, peer: &Peer, record: Vec<u8>) -> Result<()> {
        let mut last = FedError::Remote("the peer has no address".to_owned());
        for address in &peer.addresses {
            let url = match http_url(address, KEYS_PATH) {
                Ok(url) => url,
                Err(e) => {
                    last = e;
                    continue;
                }
            };
            match self.http.post(&url, record.clone()).await {
                Ok(_) => return Ok(()),
                Err(e) => last = e,
            }
        }
        Err(last)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn addresses_become_urls() {
        assert_eq!(
            http_url("https://a.example.org/", DESCRIPTOR_PATH).expect("a url"),
            "https://a.example.org/fed/v1/descriptor"
        );
        assert_eq!(
            http_url("http://10.0.0.5:8080", "/x").expect("a url"),
            "http://10.0.0.5:8080/x"
        );
        assert!(http_url("ftp://a.example.org", "/x").is_err());
        assert!(http_url("not a url", "/x").is_err());
    }

    #[test]
    fn a_session_url_is_a_websocket_url() {
        assert_eq!(
            ws_url("https://a.example.org").expect("a url"),
            "wss://a.example.org/fed/v1/session"
        );
        assert_eq!(
            ws_url("http://10.0.0.5:8080/").expect("a url"),
            "ws://10.0.0.5:8080/fed/v1/session"
        );
    }
}
