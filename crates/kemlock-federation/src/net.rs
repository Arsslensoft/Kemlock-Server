//! The outbound side over the network: the WebSocket client that opens a peer session, and the
//! plain HTTPS calls of the descriptor and of pairing.
//!
//! TLS is the transport, not the security boundary: a session is sealed again inside it with keys
//! from the two servers' own identities (`docs/federation.md`), so a proxy that ends TLS, or a
//! certificate someone forged, sees only sealed frames. Addresses are base URLs
//! (`https://vault.example.org`); `http` is accepted, and a private network reached, only for an
//! address the admin chose ([`crate::addr`]): every other address is dialled over `https` to the
//! public addresses its name resolves to, and to no others.

use crate::addr::{self, Trust};
use crate::descriptor::SignedDescriptor;
use crate::error::{FedError, Result};
use crate::job::Connector;
use crate::ports::Peer;
use crate::replicate::{FedStore, Replica};
use crate::session::{SecureChannel, Transport, unix_now};
use futures_util::{SinkExt, StreamExt};
use kemlock_domain::ServerId;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::net::TcpStream;
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::tungstenite::protocol::WebSocketConfig;
use tokio_tungstenite::{Connector as TlsConnector, MaybeTlsStream, WebSocketStream};
use url::Host;

/// How long a request, or the wait for one answer, may take.
pub const TIMEOUT: Duration = Duration::from_secs(30);
/// How long opening a connection may take.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
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
/// `https://a.example.org/fed/v1/x`. The address is a plain `http` or `https` base URL with no
/// user name, query or fragment, and the path is joined as a path.
pub fn http_url(address: &str, path: &str) -> Result<String> {
    let base = addr::base_url(address, Trust::Admin)?;
    Ok(addr::join(&base, path).to_string())
}

/// The WebSocket URL of the peer session at `address`: `https` becomes `wss`, `http` becomes `ws`.
pub fn ws_url(address: &str) -> Result<String> {
    let base = addr::base_url(address, Trust::Admin)?;
    Ok(ws_of(&addr::join(&base, SESSION_PATH)))
}

fn ws_of(http: &url::Url) -> String {
    let mut url = http.clone();
    // `http` and `https` are special schemes, as `ws` and `wss` are, so the change is allowed.
    let _ = url.set_scheme(if http.scheme() == "https" { "wss" } else { "ws" });
    url.to_string()
}

/// The HTTP calls of federation: the descriptor and the pairing messages.
///
/// Each call resolves the name of the address itself, refuses what its [`Trust`] doesn't allow, and
/// connects to exactly the addresses it checked.
#[derive(Clone, Debug)]
pub struct Http {
    _private: (),
}

impl Http {
    pub fn new() -> Result<Http> {
        Ok(Http { _private: () })
    }

    /// A client that reaches `url` only at `addresses`.
    fn client(url: &url::Url, addresses: &[SocketAddr]) -> Result<reqwest::Client> {
        let mut builder = reqwest::Client::builder()
            .timeout(TIMEOUT)
            .connect_timeout(CONNECT_TIMEOUT)
            .redirect(reqwest::redirect::Policy::none())
            .user_agent("kemlock-server");
        if let Some(Host::Domain(name)) = url.host() {
            builder = builder.resolve_to_addrs(name, addresses);
        }
        builder
            .build()
            .map_err(|_| FedError::Invalid("the HTTP client could not be built"))
    }

    /// The body of a successful answer, at most [`MAX_HTTP_BODY`] bytes: read as it arrives, so a
    /// peer that sends more is cut off, not buffered.
    async fn read(mut response: reqwest::Response) -> Result<Vec<u8>> {
        if !response.status().is_success() {
            return Err(unreachable_peer("the peer answered with an error status"));
        }
        if response
            .content_length()
            .is_some_and(|n| n > MAX_HTTP_BODY as u64)
        {
            return Err(FedError::Malformed("an HTTP body is too large"));
        }
        let mut body = Vec::new();
        while let Some(chunk) = response
            .chunk()
            .await
            .map_err(|_| unreachable_peer("the peer's answer could not be read"))?
        {
            if body.len() + chunk.len() > MAX_HTTP_BODY {
                return Err(FedError::Malformed("an HTTP body is too large"));
            }
            body.extend_from_slice(&chunk);
        }
        Ok(body)
    }

    /// `GET` `path` below `address`.
    pub async fn get(&self, address: &str, path: &str, trust: Trust) -> Result<Vec<u8>> {
        let base = addr::base_url(address, trust)?;
        let url = addr::join(&base, path);
        let client = Self::client(&url, &addr::resolve(&url, trust).await?)?;
        let response = client
            .get(url)
            .send()
            .await
            .map_err(|_| unreachable_peer("the peer could not be reached"))?;
        Self::read(response).await
    }

    /// `POST` `body` to `path` below `address`.
    pub async fn post(
        &self,
        address: &str,
        path: &str,
        body: Vec<u8>,
        trust: Trust,
    ) -> Result<Vec<u8>> {
        let base = addr::base_url(address, trust)?;
        let url = addr::join(&base, path);
        let client = Self::client(&url, &addr::resolve(&url, trust).await?)?;
        let response = client
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
    pub async fn descriptor(&self, address: &str, trust: Trust) -> Result<SignedDescriptor> {
        let bytes = self.get(address, DESCRIPTOR_PATH, trust).await?;
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

/// A TCP connection to the first of `addresses` that answers.
async fn connect_tcp(addresses: &[SocketAddr]) -> Result<TcpStream> {
    for address in addresses {
        if let Ok(Ok(stream)) =
            tokio::time::timeout(CONNECT_TIMEOUT, TcpStream::connect(address)).await
        {
            let _ = stream.set_nodelay(true);
            return Ok(stream);
        }
    }
    Err(unreachable_peer("the peer's session could not be opened"))
}

/// Opens the session WebSocket at `address`, over a connection to the addresses its name resolved
/// to at this `trust` and to no others.
pub async fn connect_ws(address: &str, trust: Trust) -> Result<WsTransport> {
    let base = addr::base_url(address, trust)?;
    let url = ws_of(&addr::join(&base, SESSION_PATH));
    let addresses = addr::resolve(&base, trust).await?;
    let connector = if url.starts_with("wss://") {
        Some(tls()?)
    } else {
        None
    };
    let config = WebSocketConfig::default()
        .max_message_size(Some(MAX_WS_MESSAGE))
        .max_frame_size(Some(MAX_WS_MESSAGE));
    let opening = async {
        let stream = connect_tcp(&addresses).await?;
        tokio_tungstenite::client_async_tls_with_config(
            url.as_str(),
            stream,
            Some(config),
            connector,
        )
        .await
        .map_err(|_| unreachable_peer("the peer's session could not be opened"))
    };
    let (socket, _response) = tokio::time::timeout(TIMEOUT, opening)
        .await
        .map_err(|_| unreachable_peer("the peer did not answer in time"))??;
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

    /// How far `address` of `peer` is trusted: the admin's own when it is one the admin typed or
    /// confirmed, a descriptor's otherwise.
    async fn trust_of(&self, peer: ServerId, address: &str) -> Trust {
        match self.replica.store().trusted_addresses(peer).await {
            Ok(trusted) if trusted.iter().any(|t| addr::same_address(t, address)) => Trust::Admin,
            _ => Trust::Descriptor,
        }
    }
}

impl<S: FedStore> Connector for WsConnector<S> {
    type Chan = SecureChannel<WsTransport>;

    async fn connect(&self, peer: &Peer) -> Result<Self::Chan> {
        let pinned = peer.key()?;
        let mut last = FedError::Remote("the peer has no address".to_owned());
        for address in &peer.addresses {
            let now = unix_now();
            let trust = self.trust_of(peer.id, address).await;
            let descriptor = match self.http.descriptor(address, trust).await {
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
            let transport = match connect_ws(address, trust).await {
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

    /// The peer's signed descriptor over HTTP, checked against the pinned key: no session, so a
    /// probe costs one small request, and an answer from another server doesn't count.
    async fn probe(&self, peer: &Peer) -> Result<()> {
        let pinned = peer.key()?;
        let mut last = FedError::Remote("the peer has no address".to_owned());
        for address in &peer.addresses {
            let trust = self.trust_of(peer.id, address).await;
            match self.http.descriptor(address, trust).await {
                Ok(descriptor) => {
                    descriptor.verify(unix_now(), Some(&pinned))?;
                    return Ok(());
                }
                Err(e) => last = e,
            }
        }
        Err(last)
    }

    async fn send_key_record(&self, peer: &Peer, record: Vec<u8>) -> Result<()> {
        let mut last = FedError::Remote("the peer has no address".to_owned());
        for address in &peer.addresses {
            let trust = self.trust_of(peer.id, address).await;
            match self
                .http
                .post(address, KEYS_PATH, record.clone(), trust)
                .await
            {
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
        assert_eq!(
            http_url("https://a.example.org", "/fed/v1/pair/finish?initiator=abc").expect("a url"),
            "https://a.example.org/fed/v1/pair/finish?initiator=abc"
        );
        assert!(http_url("ftp://a.example.org", "/x").is_err());
        assert!(http_url("not a url", "/x").is_err());
    }

    #[test]
    fn an_address_that_would_swallow_the_path_is_refused() {
        // A base URL ending in a query or a fragment used to turn the path into part of it, so a
        // request for the descriptor went to whatever the peer wrote.
        for address in [
            "https://a.example.org/?x=",
            "https://a.example.org?x=",
            "https://a.example.org/#",
            "https://a.example.org#",
            "https://user:pass@a.example.org/",
        ] {
            assert!(http_url(address, DESCRIPTOR_PATH).is_err(), "{address}");
            assert!(ws_url(address).is_err(), "{address}");
        }
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

    #[tokio::test]
    async fn a_descriptors_address_on_a_private_network_is_never_dialled() {
        let http = Http::new().expect("a client");
        for address in [
            "http://a.example.org",
            "https://127.0.0.1:9",
            "https://169.254.169.254",
            "https://10.0.0.5",
            "https://[::1]:9",
        ] {
            assert!(
                matches!(
                    http.get(address, DESCRIPTOR_PATH, Trust::Descriptor).await,
                    Err(FedError::Refused(_))
                ),
                "{address}"
            );
            assert!(
                matches!(
                    http.post(address, KEYS_PATH, vec![1], Trust::Descriptor).await,
                    Err(FedError::Refused(_))
                ),
                "{address}"
            );
            assert!(
                matches!(
                    connect_ws(address, Trust::Descriptor).await,
                    Err(FedError::Refused(_))
                ),
                "{address}"
            );
        }
    }

    #[tokio::test]
    async fn an_answer_without_a_length_is_cut_off_at_the_cap_not_read_whole() {
        use std::io::{Read, Write};
        // A server that never says how long its answer is, and sends far more than a descriptor
        // can be.
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("a port");
        let port = listener.local_addr().expect("an address").port();
        let server = std::thread::spawn(move || {
            let Ok((mut stream, _)) = listener.accept() else {
                return;
            };
            let mut request = [0u8; 1024];
            let _ = stream.read(&mut request);
            let _ = stream.write_all(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n");
            let block = vec![b'x'; 64 * 1024];
            for _ in 0..8 {
                let sent = stream
                    .write_all(format!("{:x}\r\n", block.len()).as_bytes())
                    .and_then(|()| stream.write_all(&block))
                    .and_then(|()| stream.write_all(b"\r\n"));
                if sent.is_err() {
                    return;
                }
            }
            let _ = stream.write_all(b"0\r\n\r\n");
        });
        let http = Http::new().expect("a client");
        // The admin typed this one, so a loopback address is allowed.
        let answer = http
            .get(
                &format!("http://127.0.0.1:{port}"),
                DESCRIPTOR_PATH,
                Trust::Admin,
            )
            .await;
        assert!(
            matches!(answer, Err(FedError::Malformed(_))),
            "{answer:?}"
        );
        let _ = server.join();
    }

}
