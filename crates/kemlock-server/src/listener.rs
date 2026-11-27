//! The listener: what stands between a TCP connection and the router.
//!
//! `axum::serve` hands every connection to hyper and limits nothing, and hyper's own timeout for the
//! head of a request starts only after the connection has been sniffed for HTTP/1 or HTTP/2, so a
//! client that connects and sends nothing is never timed out. The accept loop here adds:
//!
//! - a bound on the time until the first request's head has arrived (10 seconds), enforced around
//!   the whole connection, so a client that sends nothing, or a byte at a time, is dropped;
//! - hyper's header-read timeout for the later requests of a kept-alive connection, set above what
//!   a reverse proxy keeps an idle connection for (125 seconds), so the proxy, not this server,
//!   ends an idle connection, and no request is sent down one that is about to close;
//! - a write-progress timeout: a write that moves no data for 60 seconds fails the connection, so a
//!   client that never reads its response doesn't hold the connection (and its buffers) for ever;
//! - a cap on the connections one client address holds (an IPv6 address by its /48), with the
//!   trusted proxies exempt, because behind a proxy every connection comes from the proxy;
//! - a cap on all connections (4096 by default, and at most three quarters of the open-file limit);
//! - for HTTP/2, which has no header-read timeout in hyper, pings that drop a dead peer, a bound on
//!   the streams and header size of one connection, and a graceful end after it has had no request
//!   in flight for the header-read timeout.
//!
//! A connection counts for as long as its socket lives, so a WebSocket, which leaves the HTTP
//! connection when it upgrades, still counts: the permit lives in the socket.

use crate::config::Config;
use axum::Router;
use hyper_util::rt::{TokioExecutor, TokioIo, TokioTimer};
use hyper_util::server::conn::auto::Builder as ConnectionBuilder;
use kemlock_api_kem::ratelimit::Proxy;
use std::collections::HashMap;
use std::future::Future;
use std::io::{self, IoSlice};
use std::net::{IpAddr, Ipv6Addr, SocketAddr};
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::task::{Context, Poll};
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tower::ServiceExt as _;

/// How long a new connection has to get the head of its first request to the server.
const FIRST_REQUEST_TIMEOUT: Duration = Duration::from_secs(10);

/// How long the head of a later request may take to arrive on a kept-alive connection, which is
/// also how long such a connection may sit idle. Above what common proxies keep an idle upstream
/// connection for (Caddy and nginx: 2 minutes and 1 minute), so they close it first.
const HEADER_READ_TIMEOUT: Duration = Duration::from_secs(125);

/// How long a write may make no progress before the connection is dropped.
const WRITE_TIMEOUT: Duration = Duration::from_secs(60);

/// How long a stop waits for requests in flight before it ends the connections still open.
const DRAIN_TIMEOUT: Duration = Duration::from_secs(30);

/// What the listener enforces before a request reaches the router.
#[derive(Debug, Clone)]
pub struct ServeLimits {
    /// How long a connection may take to deliver the head of its first request.
    pub first_request_timeout: Duration,
    /// How long the head of a later request may take, and how long a connection may be idle.
    pub header_read_timeout: Duration,
    /// How long a write may make no progress.
    pub write_timeout: Duration,
    /// How many connections are held at once in all; 0 for no limit.
    pub max_connections: usize,
    /// How many connections one address holds at once; 0 for no limit.
    pub max_connections_per_ip: usize,
    /// Addresses (or blocks of them) the per-address limit doesn't apply to: the trusted proxies.
    pub exempt: Vec<Proxy>,
}

/// The soft limit on open files this process runs under, read from `/proc/self/limits`. `None`
/// where there is no such file (not Linux) or the limit is "unlimited".
fn open_file_limit() -> Option<u64> {
    let limits = std::fs::read_to_string("/proc/self/limits").ok()?;
    parse_open_file_limit(&limits)
}

/// The soft "Max open files" value of the text of `/proc/self/limits`.
fn parse_open_file_limit(limits: &str) -> Option<u64> {
    let line = limits
        .lines()
        .find(|line| line.starts_with("Max open files"))?;
    line.split_whitespace().nth(3)?.parse().ok()
}

/// `max` connections lowered to what the open-file limit leaves room for: three quarters of it,
/// because a connection holds a descriptor and the database, the files and the outgoing requests
/// need some. 0 (no cap) stays 0, as the operator asked, and an unknown limit changes nothing.
fn within_file_limit(max: usize, limit: Option<u64>) -> usize {
    let Some(limit) = limit else { return max };
    if max == 0 {
        return 0;
    }
    let room = usize::try_from(limit.saturating_mul(3) / 4).unwrap_or(usize::MAX);
    max.min(room.max(1))
}

impl ServeLimits {
    pub fn from_config(config: &Config) -> Self {
        Self {
            first_request_timeout: FIRST_REQUEST_TIMEOUT,
            header_read_timeout: HEADER_READ_TIMEOUT,
            write_timeout: WRITE_TIMEOUT,
            max_connections: within_file_limit(config.max_connections, open_file_limit()),
            max_connections_per_ip: config.max_connections_per_ip,
            exempt: config.trusted_proxies.clone(),
        }
    }
}

/// The three timeouts a connection runs under.
#[derive(Debug, Clone, Copy)]
struct Timeouts {
    first_request: Duration,
    header_read: Duration,
    write: Duration,
}

/// Which connections are open, in all and per address.
#[derive(Debug)]
struct Tracker {
    state: Mutex<TrackerState>,
    /// Told when a connection ends, so a full accept loop looks again.
    freed: tokio::sync::Notify,
    max_total: usize,
    max_per_address: usize,
    exempt: Vec<Proxy>,
}

#[derive(Debug, Default)]
struct TrackerState {
    total: usize,
    per_address: HashMap<IpAddr, usize>,
}

/// What a client is counted under: its address, an IPv6 one by its /48 (one site holds a whole /48
/// or more, so counting single addresses, /64s or /56s would count it as many, and one /48 could
/// take every slot).
fn address_key(ip: IpAddr) -> IpAddr {
    match ip.to_canonical() {
        IpAddr::V6(v6) => {
            let mut segments = v6.segments();
            for segment in &mut segments[3..] {
                *segment = 0;
            }
            IpAddr::V6(Ipv6Addr::from(segments))
        }
        v4 => v4,
    }
}

impl Tracker {
    fn new(limits: &ServeLimits) -> Arc<Self> {
        Arc::new(Tracker {
            state: Mutex::new(TrackerState::default()),
            freed: tokio::sync::Notify::new(),
            max_total: limits.max_connections,
            max_per_address: limits.max_connections_per_ip,
            exempt: limits.exempt.clone(),
        })
    }

    fn lock(&self) -> MutexGuard<'_, TrackerState> {
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Whether the cap on all connections is reached.
    fn full(&self) -> bool {
        self.max_total > 0 && self.lock().total >= self.max_total
    }

    /// Counts a connection from `peer`, or `None` when that address holds as many as it may.
    fn admit(self: &Arc<Self>, peer: IpAddr) -> Option<Permit> {
        let exempt = self.exempt.iter().any(|proxy| proxy.contains(peer));
        let key = address_key(peer);
        let mut state = self.lock();
        if !exempt
            && self.max_per_address > 0
            && state.per_address.get(&key).copied().unwrap_or(0) >= self.max_per_address
        {
            return None;
        }
        state.total += 1;
        if !exempt {
            *state.per_address.entry(key).or_insert(0) += 1;
        }
        drop(state);
        Some(Permit {
            tracker: Arc::clone(self),
            address: (!exempt).then_some(key),
        })
    }
}

/// One counted connection; it ends when this is dropped.
#[derive(Debug)]
struct Permit {
    tracker: Arc<Tracker>,
    address: Option<IpAddr>,
}

impl Drop for Permit {
    fn drop(&mut self) {
        {
            let mut state = self.tracker.lock();
            state.total = state.total.saturating_sub(1);
            if let Some(key) = self.address {
                let gone = match state.per_address.get_mut(&key) {
                    Some(count) => {
                        *count = count.saturating_sub(1);
                        *count == 0
                    }
                    None => false,
                };
                if gone {
                    state.per_address.remove(&key);
                }
            }
        }
        self.tracker.freed.notify_one();
    }
}

/// A socket that fails a write that makes no progress for `write_timeout`, and holds the
/// connection's [`Permit`] for as long as it lives, which is until the socket closes: after a
/// WebSocket upgrade hyper hands this very value on.
struct GuardedIo<T> {
    inner: T,
    write_timeout: Duration,
    /// Started when a write can't proceed, cleared when one does.
    stalled: Option<Pin<Box<tokio::time::Sleep>>>,
    _permit: Option<Permit>,
}

impl<T> GuardedIo<T> {
    fn new(inner: T, write_timeout: Duration, permit: Option<Permit>) -> Self {
        GuardedIo {
            inner,
            write_timeout,
            stalled: None,
            _permit: permit,
        }
    }

    /// A write is pending: wait, until it has been pending for the write timeout.
    fn stall<R>(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<R>> {
        let timeout = self.write_timeout;
        let sleep = self
            .stalled
            .get_or_insert_with(|| Box::pin(tokio::time::sleep(timeout)));
        match sleep.as_mut().poll(cx) {
            Poll::Ready(()) => Poll::Ready(Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "the client took no data for the write timeout",
            ))),
            Poll::Pending => Poll::Pending,
        }
    }

    /// A write got somewhere (or failed): the clock starts again at the next stall.
    fn progressed<R>(&mut self, result: Poll<io::Result<R>>) -> Poll<io::Result<R>> {
        if result.is_ready() {
            self.stalled = None;
        }
        result
    }
}

impl<T: AsyncRead + Unpin> AsyncRead for GuardedIo<T> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_read(cx, buf)
    }
}

impl<T: AsyncWrite + Unpin> AsyncWrite for GuardedIo<T> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        match Pin::new(&mut this.inner).poll_write(cx, buf) {
            Poll::Pending => this.stall(cx),
            ready => this.progressed(ready),
        }
    }

    fn poll_write_vectored(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[IoSlice<'_>],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        match Pin::new(&mut this.inner).poll_write_vectored(cx, bufs) {
            Poll::Pending => this.stall(cx),
            ready => this.progressed(ready),
        }
    }

    fn is_write_vectored(&self) -> bool {
        self.inner.is_write_vectored()
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        match Pin::new(&mut this.inner).poll_flush(cx) {
            Poll::Pending => this.stall(cx),
            ready => this.progressed(ready),
        }
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        match Pin::new(&mut this.inner).poll_shutdown(cx) {
            Poll::Pending => this.stall(cx),
            ready => this.progressed(ready),
        }
    }
}

/// Serves `router` on `listener` until `shutdown` resolves, then lets the requests in flight
/// finish (for at most [`DRAIN_TIMEOUT`]) and returns. Like `axum::serve` it answers WebSocket
/// upgrades and gives the handlers each client's `ConnectInfo<SocketAddr>`; it adds the limits of
/// [`ServeLimits`]. A connection from an address that holds as many as it may is closed at once;
/// when the cap on all connections is reached the listener stops accepting, and further clients
/// wait in the operating system's queue until a connection ends.
pub async fn serve(
    listener: tokio::net::TcpListener,
    router: Router,
    limits: ServeLimits,
    shutdown: impl Future<Output = ()>,
) {
    let mut shutdown = std::pin::pin!(shutdown);
    let (stop, stopping) = tokio::sync::watch::channel(false);
    let tracker = Tracker::new(&limits);
    let timeouts = Timeouts {
        first_request: limits.first_request_timeout,
        header_read: limits.header_read_timeout,
        write: limits.write_timeout,
    };
    let mut connections = tokio::task::JoinSet::new();
    loop {
        tokio::select! {
            biased;
            () = &mut shutdown => break,
            // Reaps the finished connection tasks.
            Some(_) = connections.join_next(), if !connections.is_empty() => {}
            accepted = listener.accept(), if !tracker.full() => {
                match accepted {
                    Ok((stream, peer)) => match tracker.admit(peer.ip()) {
                        Some(permit) => {
                            connections.spawn(serve_connection(
                                stream,
                                peer,
                                permit,
                                router.clone(),
                                timeouts,
                                stopping.clone(),
                            ));
                        }
                        None => {
                            tracing::debug!(%peer, "closed a connection: its address holds too many");
                            drop(stream);
                        }
                    },
                    Err(e) if matches!(
                        e.kind(),
                        io::ErrorKind::ConnectionAborted
                            | io::ErrorKind::ConnectionReset
                            | io::ErrorKind::ConnectionRefused
                    ) => {}
                    Err(e) => {
                        // Out of file descriptors, most likely: wait for some to free up.
                        tracing::warn!(error = %e, "can't accept a connection");
                        tokio::time::sleep(Duration::from_secs(1)).await;
                    }
                }
            }
            // At the cap on all connections: look again when one ends.
            () = tracker.freed.notified(), if tracker.full() => {}
        }
    }
    // No new connections; the open ones finish their request and close.
    drop(listener);
    let _ = stop.send(true);
    let drained = async { while connections.join_next().await.is_some() {} };
    if tokio::time::timeout(DRAIN_TIMEOUT, drained).await.is_err() {
        tracing::warn!(
            open = connections.len(),
            "ending the connections still open after the stop"
        );
        connections.abort_all();
    }
}

/// How many requests a connection has in flight and when it last finished one, for telling an
/// idle HTTP/2 connection (which hyper's header-read timeout doesn't cover) from a busy one.
#[derive(Debug)]
struct Activity {
    in_flight: std::sync::atomic::AtomicUsize,
    last: Mutex<tokio::time::Instant>,
}

impl Activity {
    fn new() -> Self {
        Activity {
            in_flight: std::sync::atomic::AtomicUsize::new(0),
            last: Mutex::new(tokio::time::Instant::now()),
        }
    }

    fn begin(&self) {
        self.in_flight.fetch_add(1, Ordering::Relaxed);
    }

    /// Counts a request in flight until the returned guard is dropped. A request that never
    /// finishes (a client's RST_STREAM drops its future part way) still ends, so the count can't
    /// stay above zero and keep an HTTP/2 connection from ever being found idle.
    fn enter(self: &Arc<Self>) -> InFlight {
        self.begin();
        InFlight(Arc::clone(self))
    }

    fn end(&self) {
        self.in_flight.fetch_sub(1, Ordering::Relaxed);
        *self.last.lock().unwrap_or_else(PoisonError::into_inner) = tokio::time::Instant::now();
    }

    /// Whether no request is in flight and the last one ended at least `idle` ago.
    fn idle_for(&self, idle: Duration) -> bool {
        self.in_flight.load(Ordering::Relaxed) == 0
            && self
                .last
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .elapsed()
                >= idle
    }
}

/// One request in flight on a connection; it ends when this is dropped, however the request's
/// future ends.
#[derive(Debug)]
struct InFlight(Arc<Activity>);

impl Drop for InFlight {
    fn drop(&mut self) {
        self.0.end();
    }
}

/// How often a connection looks at whether it has been idle for too long.
const IDLE_CHECK_EVERY: Duration = Duration::from_secs(15);

/// How often an HTTP/2 connection is pinged, and how long the answer may take: a peer that has
/// gone away without closing is dropped after the two.
const H2_KEEP_ALIVE_INTERVAL: Duration = Duration::from_secs(30);
const H2_KEEP_ALIVE_TIMEOUT: Duration = Duration::from_secs(20);

/// How many requests one HTTP/2 connection may have open at once, and how large its request
/// headers may be.
const H2_MAX_CONCURRENT_STREAMS: u32 = 100;
const H2_MAX_HEADER_LIST_SIZE: u32 = 32 * 1024;

/// One client's connection: HTTP/1 (and HTTP/2 when the client opens with it) over `stream`, the
/// requests answered by `router`, ended gracefully once `stopping` turns true. The connection is
/// dropped when no request has begun within the first-request timeout, and, HTTP/2 included, ended
/// gracefully once it has had no request in flight for the header-read timeout.
async fn serve_connection(
    stream: tokio::net::TcpStream,
    peer: SocketAddr,
    permit: Permit,
    router: Router,
    timeouts: Timeouts,
    mut stopping: tokio::sync::watch::Receiver<bool>,
) {
    let started = Arc::new(AtomicBool::new(false));
    let activity = Arc::new(Activity::new());
    let service = hyper::service::service_fn({
        let started = Arc::clone(&started);
        let activity = Arc::clone(&activity);
        move |mut request: axum::http::Request<hyper::body::Incoming>| {
            started.store(true, Ordering::Relaxed);
            // What `into_make_service_with_connect_info` adds, for the handlers that name the peer.
            request
                .extensions_mut()
                .insert(axum::extract::ConnectInfo(peer));
            let router = router.clone();
            let activity = Arc::clone(&activity);
            async move {
                // Held for the whole request, and dropped with it if the client resets the
                // stream and hyper drops this future.
                let _in_flight = activity.enter();
                router.oneshot(request).await
            }
        }
    });
    let io = TokioIo::new(GuardedIo::new(stream, timeouts.write, Some(permit)));
    let mut builder = ConnectionBuilder::new(TokioExecutor::new());
    builder
        .http1()
        .timer(TokioTimer::new())
        .header_read_timeout(timeouts.header_read);
    // HTTP/2 has no header-read timeout in hyper: a dead peer is found by pings, a flood of streams
    // is bounded, and an idle connection is ended by the check below.
    builder
        .http2()
        .timer(TokioTimer::new())
        .keep_alive_interval(H2_KEEP_ALIVE_INTERVAL)
        .keep_alive_timeout(H2_KEEP_ALIVE_TIMEOUT)
        .max_concurrent_streams(H2_MAX_CONCURRENT_STREAMS)
        .max_header_list_size(H2_MAX_HEADER_LIST_SIZE);
    let connection = builder.serve_connection_with_upgrades(io, service);
    let mut connection = std::pin::pin!(connection);
    let first_request = tokio::time::sleep(timeouts.first_request);
    let mut first_request = std::pin::pin!(first_request);
    let mut waiting_for_first_request = true;
    let mut asked_to_stop = false;
    let mut idle_check = tokio::time::interval(IDLE_CHECK_EVERY);
    idle_check.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    loop {
        tokio::select! {
            result = connection.as_mut() => {
                if let Err(e) = result {
                    tracing::debug!(%peer, error = %e, "a connection ended with an error");
                }
                break;
            }
            // hyper's own timeout starts only once it has told HTTP/1 from HTTP/2, so a client that
            // sends nothing is caught here.
            () = &mut first_request, if waiting_for_first_request => {
                if started.load(Ordering::Relaxed) {
                    waiting_for_first_request = false;
                } else {
                    tracing::debug!(%peer, "closed a connection that sent no request in time");
                    break;
                }
            }
            // An HTTP/2 connection that has sat with no request for as long as an idle HTTP/1 one
            // may: ended gracefully, so a request on its way still gets its answer.
            _ = idle_check.tick(), if !asked_to_stop && !waiting_for_first_request => {
                if activity.idle_for(timeouts.header_read) {
                    asked_to_stop = true;
                    connection.as_mut().graceful_shutdown();
                }
            }
            // Resolves when the server is stopping (or gone); asks for one more answer at most.
            _ = stopping.changed(), if !asked_to_stop => {
                asked_to_stop = true;
                connection.as_mut().graceful_shutdown();
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    /// A router with one route that names the peer it was reached from.
    fn peer_router() -> Router {
        async fn peer(
            axum::extract::ConnectInfo(peer): axum::extract::ConnectInfo<SocketAddr>,
        ) -> String {
            peer.ip().to_string()
        }
        Router::new().route("/", axum::routing::get(peer))
    }

    /// Serves `peer_router` on a free local port; the sender stops it, the handle ends with it.
    async fn serve_for_test(
        limits: ServeLimits,
    ) -> (
        SocketAddr,
        tokio::sync::oneshot::Sender<()>,
        tokio::task::JoinHandle<()>,
    ) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind");
        let address = listener.local_addr().expect("address");
        let (stop, stopped) = tokio::sync::oneshot::channel::<()>();
        let task = tokio::spawn(async move {
            serve(listener, peer_router(), limits, async {
                let _ = stopped.await;
            })
            .await;
        });
        (address, stop, task)
    }

    const REQUEST: &[u8] = b"GET / HTTP/1.1\r\nHost: test\r\n\r\n";

    /// Reads until the answer's body (the peer's address) has arrived.
    async fn read_answer(stream: &mut tokio::net::TcpStream) -> String {
        let mut answer = Vec::new();
        let mut chunk = [0u8; 512];
        while !answer.ends_with(b"127.0.0.1") {
            let read = stream.read(&mut chunk).await.expect("read");
            assert_ne!(read, 0, "the connection closed before the answer");
            answer.extend_from_slice(&chunk[..read]);
        }
        String::from_utf8(answer).expect("utf-8")
    }

    /// Sends one request over `stream` and reads the answer.
    async fn ask(stream: &mut tokio::net::TcpStream) -> String {
        stream.write_all(REQUEST).await.expect("write");
        read_answer(stream).await
    }

    /// Whether the server closes `stream` within `within` (whatever it had sent first).
    async fn closed_within(stream: &mut tokio::net::TcpStream, within: Duration) -> bool {
        let mut rest = Vec::new();
        tokio::time::timeout(within, stream.read_to_end(&mut rest))
            .await
            .is_ok()
    }

    fn limits() -> ServeLimits {
        ServeLimits {
            first_request_timeout: Duration::from_secs(10),
            header_read_timeout: Duration::from_secs(10),
            write_timeout: Duration::from_secs(60),
            max_connections: 0,
            max_connections_per_ip: 0,
            exempt: Vec::new(),
        }
    }

    async fn connect(address: SocketAddr) -> tokio::net::TcpStream {
        tokio::net::TcpStream::connect(address)
            .await
            .expect("connect")
    }

    async fn finish(stop: tokio::sync::oneshot::Sender<()>, task: tokio::task::JoinHandle<()>) {
        let _ = stop.send(());
        tokio::time::timeout(Duration::from_secs(5), task)
            .await
            .expect("the server stopped")
            .expect("task");
    }

    #[tokio::test]
    async fn the_listener_answers_and_names_the_peer() {
        let (address, stop, task) = serve_for_test(limits()).await;
        let mut stream = connect(address).await;
        let answer = ask(&mut stream).await;
        assert!(answer.starts_with("HTTP/1.1 200"), "{answer}");
        drop(stream);
        finish(stop, task).await;
    }

    #[tokio::test]
    async fn a_client_that_sends_nothing_at_all_is_cut_off() {
        let (address, stop, task) = serve_for_test(ServeLimits {
            first_request_timeout: Duration::from_millis(300),
            ..limits()
        })
        .await;
        // Not one byte: hyper's own header timeout has not started for such a connection.
        let mut silent = connect(address).await;
        assert!(
            closed_within(&mut silent, Duration::from_secs(5)).await,
            "a silent connection held the server"
        );
        finish(stop, task).await;
    }

    #[tokio::test]
    async fn a_client_that_never_finishes_its_headers_is_cut_off() {
        let (address, stop, task) = serve_for_test(ServeLimits {
            first_request_timeout: Duration::from_millis(300),
            ..limits()
        })
        .await;
        let mut stream = connect(address).await;
        // The start of a request, then nothing.
        stream
            .write_all(b"GET / HTTP/1.1\r\nHost: test\r\nX-Slow: ")
            .await
            .expect("write");
        assert!(
            closed_within(&mut stream, Duration::from_secs(5)).await,
            "the half-sent request held the connection open"
        );
        finish(stop, task).await;
    }

    #[tokio::test]
    async fn a_connection_is_not_cut_off_early_once_it_has_made_a_request() {
        let (address, stop, task) = serve_for_test(ServeLimits {
            first_request_timeout: Duration::from_millis(300),
            ..limits()
        })
        .await;
        let mut stream = connect(address).await;
        ask(&mut stream).await;
        // Past the first-request limit and idle: kept alive, and it answers again.
        tokio::time::sleep(Duration::from_millis(700)).await;
        let answer = ask(&mut stream).await;
        assert!(answer.starts_with("HTTP/1.1 200"), "{answer}");
        finish(stop, task).await;
    }

    #[tokio::test]
    async fn an_idle_kept_alive_connection_ends_after_the_header_timeout() {
        let (address, stop, task) = serve_for_test(ServeLimits {
            header_read_timeout: Duration::from_millis(300),
            ..limits()
        })
        .await;
        let mut stream = connect(address).await;
        ask(&mut stream).await;
        assert!(
            closed_within(&mut stream, Duration::from_secs(5)).await,
            "an idle connection stayed open"
        );
        finish(stop, task).await;
    }

    #[tokio::test]
    async fn connections_past_the_total_limit_wait_for_one_to_end() {
        let (address, stop, task) = serve_for_test(ServeLimits {
            max_connections: 1,
            ..limits()
        })
        .await;
        let mut first = connect(address).await;
        ask(&mut first).await;
        // The second connects (the operating system queues it) but isn't served while the first
        // is open.
        let mut second = connect(address).await;
        let waiting = tokio::time::timeout(Duration::from_millis(400), ask(&mut second)).await;
        assert!(
            waiting.is_err(),
            "a second connection was served over the limit"
        );
        drop(first);
        // The request `ask` sent is still queued, and the answer follows once the slot is free.
        let answer = tokio::time::timeout(Duration::from_secs(5), read_answer(&mut second))
            .await
            .expect("the second connection was served once the first ended");
        assert!(answer.contains("200"), "{answer}");
        finish(stop, task).await;
    }

    #[tokio::test]
    async fn an_address_may_hold_only_so_many_connections() {
        let (address, stop, task) = serve_for_test(ServeLimits {
            max_connections_per_ip: 1,
            ..limits()
        })
        .await;
        let mut first = connect(address).await;
        ask(&mut first).await;
        // From the same address: closed at once, and the first is unaffected.
        let mut second = connect(address).await;
        let _ = second.write_all(REQUEST).await;
        assert!(
            closed_within(&mut second, Duration::from_secs(5)).await,
            "a second connection from one address was kept"
        );
        let answer = ask(&mut first).await;
        assert!(answer.starts_with("HTTP/1.1 200"), "{answer}");
        // Once the first ends, the address may connect again (the server notices the close a
        // moment later, so a try or two may still be refused).
        drop(first);
        let mut served = false;
        for _ in 0..50 {
            let mut stream = connect(address).await;
            let _ = stream.write_all(REQUEST).await;
            let mut chunk = [0u8; 64];
            if let Ok(Ok(read)) =
                tokio::time::timeout(Duration::from_millis(200), stream.read(&mut chunk)).await
                && read > 0
            {
                served = true;
                break;
            }
        }
        assert!(served, "the address was never let back in");
        finish(stop, task).await;
    }

    #[tokio::test]
    async fn a_trusted_proxy_is_exempt_from_the_address_limit() {
        let (address, stop, task) = serve_for_test(ServeLimits {
            max_connections_per_ip: 1,
            exempt: vec![Proxy::parse("127.0.0.1").expect("an address")],
            ..limits()
        })
        .await;
        let mut first = connect(address).await;
        let mut second = connect(address).await;
        assert!(ask(&mut first).await.starts_with("HTTP/1.1 200"));
        assert!(ask(&mut second).await.starts_with("HTTP/1.1 200"));
        finish(stop, task).await;
    }

    #[tokio::test]
    async fn a_stop_ends_idle_connections_and_returns() {
        let (address, stop, task) = serve_for_test(limits()).await;
        let mut idle = connect(address).await;
        ask(&mut idle).await;
        // The connection stays open, kept alive; the stop must not wait for the client.
        finish(stop, task).await;
    }

    #[test]
    fn addresses_are_counted_per_address_and_ipv6_per_48() {
        let mut limits = limits();
        limits.max_connections_per_ip = 2;
        limits.max_connections = 3;
        limits.exempt = vec![Proxy::parse("10.0.0.1").expect("an address")];
        let tracker = Tracker::new(&limits);
        let ip = |text: &str| text.parse::<IpAddr>().expect("an address");

        let a = tracker.admit(ip("192.0.2.1")).expect("one");
        let b = tracker.admit(ip("192.0.2.1")).expect("two");
        assert!(tracker.admit(ip("192.0.2.1")).is_none(), "a third");
        assert!(!tracker.full());
        // Another address is its own count; the proxy is exempt but still counts in total.
        let c = tracker.admit(ip("192.0.2.2")).expect("another address");
        assert!(tracker.full(), "three of three");
        drop(a);
        assert!(!tracker.full());
        let d = tracker.admit(ip("10.0.0.1")).expect("the proxy");
        let e = tracker.admit(ip("10.0.0.1")).expect("the proxy again");
        drop((b, c, d, e));
        assert_eq!(tracker.lock().total, 0);
        assert!(tracker.lock().per_address.is_empty());

        // One /48 is one client: a site holds 65,536 /64s, and a /48 holds 256 /56s.
        let x = tracker.admit(ip("2001:db8:1:2::1")).expect("one");
        let y = tracker.admit(ip("2001:db8:1:2:ffff::9")).expect("two");
        assert!(tracker.admit(ip("2001:db8:1:2::3")).is_none());
        assert!(
            tracker.admit(ip("2001:db8:1:3::1")).is_none(),
            "another /64 of the /48"
        );
        assert!(
            tracker.admit(ip("2001:db8:1:100::1")).is_none(),
            "another /56 of the /48"
        );
        let _next = tracker.admit(ip("2001:db8:2::1")).expect("the next /48");
        // An IPv4 address mapped into IPv6 is that IPv4 address.
        let _z = tracker.admit(ip("192.0.2.9")).expect("one");
        let _w = tracker.admit(ip("::ffff:192.0.2.9")).expect("two");
        assert!(tracker.admit(ip("192.0.2.9")).is_none());
        drop((x, y));
    }

    #[test]
    fn the_open_file_limit_is_read_from_proc_and_caps_the_total_of_connections() {
        let text = "Limit                     Soft Limit           Hard Limit           Units     \n\
                    Max cpu time              unlimited            unlimited            seconds   \n\
                    Max open files            1024                 524288               files     \n";
        assert_eq!(parse_open_file_limit(text), Some(1024));
        assert_eq!(
            parse_open_file_limit("Max open files unlimited unlimited files"),
            None
        );
        assert_eq!(parse_open_file_limit("nothing here"), None);
        // Three quarters of the limit at most; no cap and an unknown limit stay as they are.
        assert_eq!(within_file_limit(4096, Some(1024)), 768);
        assert_eq!(within_file_limit(4096, Some(65535)), 4096);
        assert_eq!(within_file_limit(0, Some(1024)), 0);
        assert_eq!(within_file_limit(4096, None), 4096);
        assert_eq!(within_file_limit(10, Some(0)), 1);
    }

    #[tokio::test]
    async fn a_connection_is_idle_only_with_nothing_in_flight_for_long_enough() {
        let idle = Duration::from_millis(60);
        let pause = Duration::from_millis(120);
        let activity = Activity::new();
        assert!(!activity.idle_for(idle));
        tokio::time::sleep(pause).await;
        assert!(activity.idle_for(idle));
        // A request in flight is never idle, however long it takes.
        activity.begin();
        tokio::time::sleep(pause).await;
        assert!(!activity.idle_for(idle));
        // Ending it starts the clock again.
        activity.end();
        assert!(!activity.idle_for(idle));
        tokio::time::sleep(pause).await;
        assert!(activity.idle_for(idle));
    }

    #[tokio::test]
    async fn a_request_dropped_part_way_is_no_longer_in_flight() {
        let idle = Duration::from_millis(40);
        let activity = Arc::new(Activity::new());
        let request = activity.enter();
        tokio::time::sleep(Duration::from_millis(80)).await;
        assert!(!activity.idle_for(idle), "in flight while it is held");
        // A reset stream drops the request's future without finishing it.
        drop(request);
        tokio::time::sleep(Duration::from_millis(80)).await;
        assert!(activity.idle_for(idle), "dropping it ends it");
    }

    #[tokio::test]
    async fn a_write_that_moves_nothing_fails_after_the_write_timeout() {
        // A 16-byte pipe nobody reads: the first bytes go, then writes stall.
        let (writer, _reader) = tokio::io::duplex(16);
        let mut io = GuardedIo::new(writer, Duration::from_millis(100), None);
        let big = vec![7u8; 4096];
        let outcome = tokio::time::timeout(Duration::from_secs(5), io.write_all(&big))
            .await
            .expect("the write timed out on its own, not the test's");
        let error = outcome.expect_err("a stalled write fails");
        assert_eq!(error.kind(), io::ErrorKind::TimedOut);
    }

    #[tokio::test]
    async fn a_write_that_keeps_moving_is_not_cut_off() {
        let (writer, mut reader) = tokio::io::duplex(16);
        let mut io = GuardedIo::new(writer, Duration::from_millis(300), None);
        let big = vec![7u8; 640];
        let drain = tokio::spawn(async move {
            let mut got = 0;
            let mut chunk = [0u8; 16];
            while got < 640 {
                tokio::time::sleep(Duration::from_millis(20)).await;
                let n = reader.read(&mut chunk).await.expect("read");
                if n == 0 {
                    break;
                }
                got += n;
            }
            got
        });
        // Longer than the timeout in all (40 reads of 20 ms), but never stalled for as long.
        io.write_all(&big).await.expect("slow but steady");
        assert_eq!(drain.await.expect("the reader"), 640);
    }
}
