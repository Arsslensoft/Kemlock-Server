//! UnifiedPush, sent by the server itself.
//!
//! An Android phone with a UnifiedPush distributor (ntfy, Gotify, NextPush and others) registers
//! the endpoint URL the distributor gave it. The server posts an empty body to that URL, which is
//! Web Push without a payload (RFC 8030): it needs no encryption, and the push says nothing but
//! "something happened". The app wakes and syncs.
//!
//! The endpoint is a URL a client chose, so the server never lets it reach its own network: the
//! name is resolved here, every address must be public (or, if the operator allows it, on a
//! private network), and the connection goes to exactly those addresses (a second lookup could
//! answer differently). Redirects are not followed.

use super::SendOutcome;
use kemlock_app::push::check_unifiedpush_endpoint;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::time::Duration;
use tokio::task::JoinSet;
use url::{Host, Url};

/// How many endpoints are pushed to at once.
const PARALLEL: usize = 16;

/// How long the distributor keeps the push for a phone that is off, in seconds.
const TTL_SECONDS: &str = "86400";

/// Whether `ip` is an address on the public internet. Private, loopback, link-local, shared
/// (carrier-grade NAT), documentation, multicast, unspecified and reserved ranges are not, and
/// neither is an IPv6 address that carries such an IPv4 one.
pub fn is_public_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => public_v4(v4),
        IpAddr::V6(v6) => public_v6(v6),
    }
}

fn public_v4(ip: Ipv4Addr) -> bool {
    let [a, b, c, _] = ip.octets();
    !(ip.is_unspecified()
        || ip.is_loopback()
        || ip.is_private()
        || ip.is_link_local()
        || ip.is_broadcast()
        || ip.is_multicast()
        || ip.is_documentation()
        // 0.0.0.0/8 ("this network").
        || a == 0
        // 100.64.0.0/10, shared address space (carrier-grade NAT).
        || (a == 100 && (64..=127).contains(&b))
        // 192.0.0.0/24, IETF protocol assignments.
        || (a == 192 && b == 0 && c == 0)
        // 192.88.99.0/24, the retired 6to4 relay anycast.
        || (a == 192 && b == 88 && c == 99)
        // 198.18.0.0/15, benchmarking.
        || (a == 198 && (b == 18 || b == 19))
        // 240.0.0.0/4, reserved.
        || a >= 240)
}

fn public_v6(ip: Ipv6Addr) -> bool {
    if let Some(v4) = ip.to_ipv4_mapped() {
        return public_v4(v4);
    }
    let s = ip.segments();
    // ::/96 (IPv4-compatible) and 64:ff9b::/96 (NAT64) carry an IPv4 address in the last 32 bits.
    let embedded = Ipv4Addr::new(
        (s[6] >> 8) as u8,
        (s[6] & 0xff) as u8,
        (s[7] >> 8) as u8,
        (s[7] & 0xff) as u8,
    );
    if s[..6] == [0; 6] || s[..6] == [0x64, 0xff9b, 0, 0, 0, 0] {
        return public_v4(embedded);
    }
    // 64:ff9b:1::/48 (local-use NAT64) carries one in the last 32 bits too.
    if s[..3] == [0x64, 0xff9b, 1] {
        return public_v4(embedded);
    }
    // 2002::/16 (6to4) carries one in bits 16 to 48.
    if s[0] == 0x2002 {
        return public_v4(Ipv4Addr::new(
            (s[1] >> 8) as u8,
            (s[1] & 0xff) as u8,
            (s[2] >> 8) as u8,
            (s[2] & 0xff) as u8,
        ));
    }
    !(ip.is_unspecified()
        || ip.is_loopback()
        || ip.is_multicast()
        // fc00::/7, unique local.
        || (s[0] & 0xfe00) == 0xfc00
        // fe80::/10 link-local and fec0::/10 site-local.
        || (s[0] & 0xffc0) == 0xfe80
        || (s[0] & 0xffc0) == 0xfec0
        // 2001:db8::/32, documentation.
        || (s[0] == 0x2001 && s[1] == 0x0db8)
        // ::ffff:0:0:0/96, IPv4-translated (deprecated).
        || s[..6] == [0, 0, 0, 0, 0xffff, 0]
        // 100::/64, discard-only.
        || s[..4] == [0x100, 0, 0, 0]
        // 2001:2::/48, benchmarking.
        || (s[0] == 0x2001 && s[1] == 2 && s[2] == 0)
        // 2001:10::/28, ORCHID (never routed).
        || (s[0] == 0x2001 && (s[1] & 0xfff0) == 0x10))
}

/// How one push to one endpoint went.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Delivery {
    Accepted,
    /// The endpoint is gone, or is one the server will never send to: forget it.
    Forget,
    /// It failed this time.
    Failed,
}

/// Whether `ip` is on a private network an operator may choose to reach: RFC 1918 IPv4, unique
/// local IPv6, or an IPv6 address that carries a private IPv4 one. Never loopback, link-local,
/// unspecified or multicast addresses, which are not public either.
pub fn is_lan_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => v4.is_private(),
        IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
            Some(v4) => v4.is_private(),
            // fc00::/7, unique local.
            None => (v6.segments()[0] & 0xfe00) == 0xfc00,
        },
    }
}

/// Sends "sync now" to UnifiedPush endpoints. Cheap to clone.
#[derive(Clone, Debug)]
pub struct UnifiedPushSender {
    /// Allows `http` and non-public addresses, for tests that talk to a server on this machine.
    allow_local: bool,
    /// Also reaches private (LAN) addresses: the operator's own ntfy or Gotify.
    allow_private: bool,
}

impl Default for UnifiedPushSender {
    fn default() -> Self {
        UnifiedPushSender::new()
    }
}

impl UnifiedPushSender {
    pub fn new() -> UnifiedPushSender {
        UnifiedPushSender {
            allow_local: false,
            allow_private: false,
        }
    }

    /// Reads `KEMLOCK_UNIFIEDPUSH_ALLOW_PRIVATE` (`true` or `false`, default `false`) through
    /// `get`: whether endpoints on a private network (a LAN ntfy) are pushed to. A bad value is
    /// an error that names the setting.
    pub fn from_lookup(get: &dyn Fn(&str) -> Option<String>) -> Result<UnifiedPushSender, String> {
        const NAME: &str = "KEMLOCK_UNIFIEDPUSH_ALLOW_PRIVATE";
        let allow_private = match get(NAME)
            .map(|v| v.trim().to_ascii_lowercase())
            .filter(|v| !v.is_empty())
            .as_deref()
        {
            None | Some("false" | "0" | "no" | "off") => false,
            Some("true" | "1" | "yes" | "on") => true,
            Some(other) => return Err(format!("{NAME} must be true or false, not {other:?}")),
        };
        Ok(UnifiedPushSender::new().allowing_private(allow_private))
    }

    /// A sender that also reaches private (LAN) addresses when `allow` is true.
    pub fn allowing_private(mut self, allow: bool) -> UnifiedPushSender {
        self.allow_private = allow;
        self
    }

    /// A sender that also reaches this machine over plain `http`.
    #[cfg(test)]
    pub(super) fn allowing_local() -> UnifiedPushSender {
        UnifiedPushSender {
            allow_local: true,
            allow_private: false,
        }
    }

    /// Whether the server may connect to `ip`.
    fn may_reach(&self, ip: IpAddr) -> bool {
        self.allow_local || is_public_ip(ip) || (self.allow_private && is_lan_ip(ip))
    }

    /// Sends "sync now" to these endpoints. One the server won't send to, or that is gone (404 or
    /// 410), comes back in `rejected`. A failure is logged and not retried.
    pub async fn send_sync(&self, endpoints: &[String]) -> SendOutcome {
        let mut outcome = SendOutcome::default();
        for chunk in endpoints.chunks(PARALLEL) {
            let mut sends = JoinSet::new();
            for endpoint in chunk {
                let (sender, endpoint) = (self.clone(), endpoint.clone());
                sends.spawn(async move {
                    let delivery = sender.send_one(&endpoint).await;
                    (endpoint, delivery)
                });
            }
            while let Some(done) = sends.join_next().await {
                let Ok((endpoint, delivery)) = done else {
                    continue;
                };
                match delivery {
                    Delivery::Accepted => outcome.accepted += 1,
                    Delivery::Forget => outcome.rejected.push(endpoint),
                    Delivery::Failed => {}
                }
            }
        }
        outcome
    }

    fn parse(&self, endpoint: &str) -> Option<Url> {
        if self.allow_local {
            Url::parse(endpoint).ok()
        } else {
            check_unifiedpush_endpoint(endpoint).ok()
        }
    }

    /// The addresses to connect to, all public: `Ok(None)` for an address in the URL itself
    /// (nothing to pin), `Err` for a refusal.
    async fn addresses(&self, url: &Url) -> Result<Option<Vec<SocketAddr>>, Delivery> {
        let port = url.port_or_known_default().unwrap_or(443);
        match url.host() {
            None => Err(Delivery::Forget),
            Some(Host::Ipv4(ip)) => self.literal(IpAddr::V4(ip)),
            Some(Host::Ipv6(ip)) => self.literal(IpAddr::V6(ip)),
            Some(Host::Domain(name)) => {
                let found = tokio::time::timeout(
                    Duration::from_secs(5),
                    tokio::net::lookup_host((name, port)),
                )
                .await;
                let found: Vec<SocketAddr> = match found {
                    Ok(Ok(found)) => found.collect(),
                    // The name may resolve next time.
                    _ => return Err(Delivery::Failed),
                };
                if found.is_empty() {
                    return Err(Delivery::Failed);
                }
                // One private answer is enough to refuse: the client could be handed it. The
                // endpoint is kept, though: the name can answer differently next time (split
                // horizon DNS, a blocker answering 0.0.0.0, a bad answer that passes).
                if found.iter().any(|a| !self.may_reach(a.ip())) {
                    tracing::warn!(
                        "didn't push to a UnifiedPush endpoint whose name resolves to a non-public \
                         address (KEMLOCK_UNIFIEDPUSH_ALLOW_PRIVATE allows a private network)"
                    );
                    return Err(Delivery::Failed);
                }
                Ok(Some(found))
            }
        }
    }

    fn literal(&self, ip: IpAddr) -> Result<Option<Vec<SocketAddr>>, Delivery> {
        if !self.may_reach(ip) {
            tracing::warn!("forgot a UnifiedPush endpoint on a non-public address");
            return Err(Delivery::Forget);
        }
        Ok(None)
    }

    async fn send_one(&self, endpoint: &str) -> Delivery {
        self.send_via(endpoint, |http| http).await
    }

    /// Sends to one endpoint; `tweak` changes the client's builder just before the proxy
    /// settings are cleared (a test adds a proxy to see it is not used).
    async fn send_via(
        &self,
        endpoint: &str,
        tweak: impl FnOnce(reqwest::ClientBuilder) -> reqwest::ClientBuilder,
    ) -> Delivery {
        let Some(url) = self.parse(endpoint) else {
            return Delivery::Forget;
        };
        let addresses = match self.addresses(&url).await {
            Ok(addresses) => addresses,
            Err(delivery) => return delivery,
        };
        let mut http = reqwest::Client::builder()
            .timeout(Duration::from_secs(10))
            .connect_timeout(Duration::from_secs(5))
            .user_agent(concat!("kemlock-server/", env!("CARGO_PKG_VERSION")))
            // A redirect could lead to an address the checks above never saw.
            .redirect(reqwest::redirect::Policy::none());
        if let (Some(addresses), Some(Host::Domain(name))) = (&addresses, url.host()) {
            // Connect to the addresses that were checked, not to a fresh lookup.
            http = http.resolve_to_addrs(name, addresses);
        }
        // A proxy from HTTPS_PROXY or ALL_PROXY would resolve the name itself and so connect to
        // an address the checks above never saw.
        let http = match tweak(http).no_proxy().build() {
            Ok(http) => http,
            Err(error) => {
                tracing::warn!(%error, "couldn't set up a UnifiedPush send");
                return Delivery::Failed;
            }
        };
        let response = http
            .post(url)
            .header("TTL", TTL_SECONDS)
            .header("Urgency", "normal")
            .body(Vec::new())
            .send()
            .await;
        match response.map(|r| r.status().as_u16()) {
            Ok(200..=299) => Delivery::Accepted,
            Ok(404 | 410) => Delivery::Forget,
            Ok(status) => {
                tracing::warn!(status, "a UnifiedPush endpoint didn't take a push");
                Delivery::Failed
            }
            Err(error) => {
                tracing::warn!(%error, "couldn't reach a UnifiedPush endpoint");
                Delivery::Failed
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::serve;
    use axum::Router;
    use axum::extract::State;
    use axum::http::{HeaderMap, Method, StatusCode, header};
    use axum::response::IntoResponse;
    use std::sync::{Arc, Mutex};

    fn ip(text: &str) -> IpAddr {
        text.parse().expect("an address")
    }

    #[test]
    fn private_and_special_addresses_are_not_public() {
        for text in [
            "127.0.0.1",
            "127.1.2.3",
            "10.0.0.5",
            "172.16.0.1",
            "172.31.255.255",
            "192.168.1.10",
            "169.254.169.254",
            "100.64.0.1",
            "100.127.255.255",
            "0.0.0.0",
            "0.1.2.3",
            "192.0.0.8",
            "192.0.2.1",
            "198.18.0.1",
            "198.51.100.7",
            "203.0.113.9",
            "224.0.0.1",
            "240.0.0.1",
            "255.255.255.255",
            "::1",
            "::",
            "fe80::1",
            "fec0::1",
            "fc00::1",
            "fd12:3456::1",
            "ff02::1",
            "2001:db8::1",
            "::ffff:127.0.0.1",
            "::ffff:10.0.0.1",
            "::ffff:192.168.0.1",
            "64:ff9b::7f00:1",
            "64:ff9b::a00:1",
            "2002:7f00:1::1",
            "2002:c0a8:101::1",
            "::7f00:1",
            "192.88.99.1",
            "64:ff9b:1::7f00:1",
            "64:ff9b:1:2:3:4:a00:1",
            "::ffff:0:8.8.8.8",
            "0:0:0:0:ffff:0:808:808",
            "100::1",
            "100::ffff",
            "2001:2::1",
            "2001:2:0:ffff::1",
            "2001:10::1",
            "2001:1f:ffff::1",
        ] {
            assert!(!is_public_ip(ip(text)), "{text}");
        }
    }

    #[test]
    fn public_addresses_are_public() {
        for text in [
            "8.8.8.8",
            "1.1.1.1",
            "93.184.216.34",
            "172.15.0.1",
            "172.32.0.1",
            "100.63.255.255",
            "100.128.0.1",
            "198.17.0.1",
            "198.20.0.1",
            "2606:4700:4700::1111",
            "2001:4860:4860::8888",
            "::ffff:8.8.8.8",
            "2002:808:808::1",
            "192.88.98.1",
            "192.88.100.1",
            "64:ff9b:1::808:808",
            "100:0:0:1::1",
            "2001:3::1",
            "2001:2:1::1",
            "2001:20::1",
        ] {
            assert!(is_public_ip(ip(text)), "{text}");
        }
    }

    /// What the fake distributor saw.
    #[derive(Default)]
    struct Seen {
        requests: Mutex<Vec<(Method, String, HeaderMap, usize)>>,
    }

    async fn distributor(
        State(seen): State<Arc<Seen>>,
        method: Method,
        uri: axum::http::Uri,
        headers: HeaderMap,
        body: axum::body::Bytes,
    ) -> axum::response::Response {
        let path = uri.path().to_owned();
        seen.requests
            .lock()
            .expect("lock")
            .push((method, path.clone(), headers, body.len()));
        match path.as_str() {
            "/gone" => StatusCode::GONE.into_response(),
            "/missing" => StatusCode::NOT_FOUND.into_response(),
            "/broken" => StatusCode::INTERNAL_SERVER_ERROR.into_response(),
            "/moved" => (
                StatusCode::FOUND,
                [(header::LOCATION, "http://127.0.0.1:9/elsewhere")],
            )
                .into_response(),
            _ => StatusCode::CREATED.into_response(),
        }
    }

    async fn fake() -> (Arc<Seen>, String) {
        let seen = Arc::new(Seen::default());
        let app = Router::new().fallback(distributor).with_state(seen.clone());
        let address = serve(app).await;
        (seen, format!("http://{address}"))
    }

    #[tokio::test]
    async fn a_push_is_an_empty_post_with_a_ttl_and_urgency() {
        let (seen, base) = fake().await;
        let sender = UnifiedPushSender::allowing_local();
        let outcome = sender.send_sync(&[format!("{base}/upAbc?up=1")]).await;
        assert_eq!(outcome.accepted, 1);
        assert!(outcome.rejected.is_empty());
        let requests = seen.requests.lock().expect("lock");
        let (method, path, headers, body_len) = &requests[0];
        assert_eq!(method, Method::POST);
        assert_eq!(path, "/upAbc");
        assert_eq!(headers["ttl"], "86400");
        assert_eq!(headers["urgency"], "normal");
        assert_eq!(*body_len, 0);
        assert!(!headers.contains_key(header::AUTHORIZATION));
    }

    #[tokio::test]
    async fn gone_endpoints_are_forgotten_and_other_failures_are_not() {
        let (seen, base) = fake().await;
        let sender = UnifiedPushSender::allowing_local();
        let outcome = sender
            .send_sync(&[
                format!("{base}/gone"),
                format!("{base}/missing"),
                format!("{base}/broken"),
                format!("{base}/fine"),
            ])
            .await;
        assert_eq!(outcome.accepted, 1);
        let mut rejected = outcome.rejected;
        rejected.sort();
        assert_eq!(
            rejected,
            [format!("{base}/gone"), format!("{base}/missing")]
        );
        assert_eq!(seen.requests.lock().expect("lock").len(), 4, "no retry");
    }

    #[tokio::test]
    async fn a_redirect_is_not_followed() {
        let (seen, base) = fake().await;
        let sender = UnifiedPushSender::allowing_local();
        let outcome = sender.send_sync(&[format!("{base}/moved")]).await;
        assert_eq!(
            outcome,
            SendOutcome::default(),
            "a failure, nothing forgotten"
        );
        assert_eq!(seen.requests.lock().expect("lock").len(), 1);
    }

    #[tokio::test]
    async fn the_real_sender_refuses_this_machine_and_the_local_network() {
        let (seen, base) = fake().await;
        let sender = UnifiedPushSender::new();
        let targets: Vec<String> = [
            // http, even to a public name.
            "http://ntfy.example.org/up".to_owned(),
            // A server on this machine: the fake itself, as an https URL.
            base.replace("http://", "https://"),
            "https://127.0.0.1/up".to_owned(),
            "https://[::1]/up".to_owned(),
            "https://10.1.2.3/up".to_owned(),
            "https://192.168.0.7:8443/up".to_owned(),
            "https://169.254.169.254/latest/meta-data".to_owned(),
            "https://[::ffff:127.0.0.1]/up".to_owned(),
            "https://[fd00::1]/up".to_owned(),
            "https://user:pw@8.8.8.8/up".to_owned(),
            "not a url".to_owned(),
        ]
        .into();
        let outcome = sender.send_sync(&targets).await;
        assert_eq!(outcome.accepted, 0);
        // Every one is forgotten: each is a literal address, or not an endpoint at all.
        let mut forgotten = outcome.rejected;
        forgotten.sort();
        let mut expected = targets.clone();
        expected.sort();
        assert_eq!(forgotten, expected);
        assert!(seen.requests.lock().expect("lock").is_empty());
    }

    #[tokio::test]
    async fn a_name_that_resolves_to_a_non_public_address_is_a_failure_not_a_forgetting() {
        let (seen, base) = fake().await;
        let port = base.rsplit(':').next().expect("a port");
        // `localhost` answers loopback: a split-horizon name or a DNS blocker could answer so
        // for a moment, and the endpoint must survive it.
        let endpoint = format!("https://localhost:{port}/up");
        for sender in [
            UnifiedPushSender::new(),
            // Private networks allowed: loopback still never is.
            UnifiedPushSender::new().allowing_private(true),
        ] {
            let outcome = sender.send_sync(&[endpoint.clone()]).await;
            assert_eq!(outcome, SendOutcome::default());
        }
        assert!(seen.requests.lock().expect("lock").is_empty());
    }

    #[test]
    fn private_networks_are_reached_only_when_allowed_and_never_loopback() {
        let strict = UnifiedPushSender::new();
        let lan = UnifiedPushSender::new().allowing_private(true);
        for text in [
            "10.0.0.5",
            "172.16.0.1",
            "192.168.1.10",
            "fd12:3456::1",
            "::ffff:192.168.0.1",
        ] {
            assert!(!strict.may_reach(ip(text)), "{text}");
            assert!(lan.may_reach(ip(text)), "{text}");
        }
        for text in [
            "127.0.0.1",
            "::1",
            "169.254.169.254",
            "fe80::1",
            "0.0.0.0",
            "::",
            "224.0.0.1",
            "ff02::1",
            "::ffff:127.0.0.1",
            "100.64.0.1",
            "192.0.2.1",
        ] {
            assert!(!strict.may_reach(ip(text)), "{text}");
            assert!(!lan.may_reach(ip(text)), "{text}");
        }
        for text in ["8.8.8.8", "2606:4700:4700::1111"] {
            assert!(strict.may_reach(ip(text)) && lan.may_reach(ip(text)), "{text}");
        }
    }

    #[test]
    fn the_private_network_setting_is_read_like_the_other_switches() {
        let read = |value: Option<&str>| {
            UnifiedPushSender::from_lookup(&|name| {
                (name == "KEMLOCK_UNIFIEDPUSH_ALLOW_PRIVATE")
                    .then(|| value.map(str::to_owned))
                    .flatten()
            })
        };
        assert!(!read(None).expect("ok").allow_private);
        assert!(!read(Some("")).expect("ok").allow_private);
        assert!(!read(Some("false")).expect("ok").allow_private);
        assert!(read(Some("true")).expect("ok").allow_private);
        assert!(read(Some(" ON ")).expect("ok").allow_private);
        let error = read(Some("maybe")).expect_err("refused");
        assert!(error.starts_with("KEMLOCK_UNIFIEDPUSH_ALLOW_PRIVATE"), "{error}");
    }

    #[tokio::test]
    async fn a_proxy_setting_is_never_used() {
        let (seen, base) = fake().await;
        let (proxied, proxy) = fake().await;
        let sender = UnifiedPushSender::allowing_local();
        let delivery = sender
            .send_via(&format!("{base}/up"), |http| {
                http.proxy(reqwest::Proxy::all(&proxy).expect("a proxy"))
            })
            .await;
        assert_eq!(delivery, Delivery::Accepted);
        assert_eq!(seen.requests.lock().expect("lock").len(), 1);
        assert!(
            proxied.requests.lock().expect("lock").is_empty(),
            "the proxy would have resolved the name itself"
        );
    }

    #[tokio::test]
    async fn a_name_that_does_not_resolve_is_a_failure_not_a_forgetting() {
        let sender = UnifiedPushSender::new();
        let outcome = sender
            .send_sync(&["https://no-such-host.invalid/up".to_owned()])
            .await;
        assert_eq!(outcome, SendOutcome::default());
    }

    #[tokio::test]
    async fn many_endpoints_are_sent_in_parallel_batches() {
        let (seen, base) = fake().await;
        let sender = UnifiedPushSender::allowing_local();
        let targets: Vec<String> = (0..PARALLEL * 2 + 3)
            .map(|i| format!("{base}/device{i}"))
            .collect();
        let outcome = sender.send_sync(&targets).await;
        assert_eq!(outcome.accepted, targets.len());
        assert_eq!(seen.requests.lock().expect("lock").len(), targets.len());
    }
}
