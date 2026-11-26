//! Request extractors: the capped body, the client address, a DPoP proof on a token endpoint,
//! and an authenticated actor. All reject with problem+json.

use crate::dpop::{DpopError, Pending};
use crate::problem::{Problem, rate_limited};
use crate::ratelimit::{client_ip, ip_key, joined_header};
use crate::state::{Api, Crypto, Store};
use axum::body::{Body as HttpBody, Bytes};
use axum::extract::{ConnectInfo, FromRequest, FromRequestParts, Request};
use axum::http::request::Parts;
use axum::http::{HeaderMap, HeaderName, StatusCode, header};
use kemlock_app::ports::TokenSigner;
use kemlock_app::{Actor, AppError};
use serde::de::DeserializeOwned;
use serde_json::json;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use uuid::Uuid;

/// JSON bodies are capped at 2 MiB (design, "Limits").
pub const MAX_BODY_BYTES: usize = 2 * 1024 * 1024;

/// The `DPoP-Nonce` header.
pub const DPOP_NONCE: HeaderName = HeaderName::from_static("dpop-nonce");

/// The raw request body, read up to [`MAX_BODY_BYTES`]. Must be a handler's last argument.
#[derive(Debug)]
pub struct Body(pub Bytes);

impl Body {
    /// Whether the request had no body at all.
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Parses the body as JSON, with problem+json errors.
    pub fn json<T: DeserializeOwned>(&self) -> Result<T, Problem> {
        serde_json::from_slice(&self.0)
            .map_err(|e| Problem::bad_request(format!("the body isn't the JSON expected: {e}")))
    }
}

impl<S: Send + Sync> FromRequest<S> for Body {
    type Rejection = Problem;

    async fn from_request(req: Request, _state: &S) -> Result<Self, Problem> {
        let body: HttpBody = req.into_body();
        axum::body::to_bytes(body, MAX_BODY_BYTES)
            .await
            .map(Body)
            .map_err(|_| Problem::payload_too_large())
    }
}

/// The address of the peer that opened the connection, never a forwarded one.
fn peer_address(parts: &Parts) -> IpAddr {
    parts
        .extensions
        .get::<ConnectInfo<SocketAddr>>()
        .map(|c| c.0.ip())
        .unwrap_or(IpAddr::V4(Ipv4Addr::UNSPECIFIED))
}

fn peer_and_header<S: Store, P: Crypto, K: TokenSigner + Clone + 'static>(
    parts: &Parts,
    api: &Api<S, P, K>,
) -> IpAddr {
    let peer = peer_address(parts);
    // Every line of the header, not the first: a proxy may append its own line after the client's.
    let header = api
        .config
        .ip_header
        .as_deref()
        .and_then(|name| joined_header(&parts.headers, name));
    client_ip(peer, header.as_deref(), &api.config.trusted_proxies)
}

/// Headers that say a proxy forwarded the request.
const FORWARDING_HEADERS: [&str; 5] = [
    "forwarded",
    "x-forwarded-for",
    "x-forwarded-proto",
    "x-forwarded-host",
    "x-real-ip",
];

/// Whether the connection a request came over is a secure context (HTTPS, or a browser on this
/// machine), decided from the connection and never from what the client says about itself:
///
/// - a peer that is a trusted proxy (`KEMLOCK_TRUSTED_PROXIES`) says which scheme the client used
///   in `X-Forwarded-Proto`, and `https` there makes the request secure;
/// - any other peer is secure only if it is on this machine (loopback) and the request carries no
///   forwarding header, because a proxy on this machine that was not named as one would make
///   every remote client look local;
/// - TLS terminated by this server will count too, when it exists.
///
/// The `Origin` header is the browser's claim about its page, which any client can write, so it
/// decides nothing; nor does the configured `DOMAIN`, which says what clients are meant to use,
/// not what this connection is.
pub fn is_secure_connection(
    peer: IpAddr,
    headers: &HeaderMap,
    trusted_proxies: &[IpAddr],
    ip_header: Option<&str>,
) -> bool {
    let peer = peer.to_canonical();
    if trusted_proxies.iter().any(|p| p.to_canonical() == peer) {
        // The nearest proxy appends last, so the last value is the one a trusted proxy wrote.
        return headers
            .get_all("x-forwarded-proto")
            .iter()
            .next_back()
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.rsplit(',').next())
            .is_some_and(|scheme| scheme.trim().eq_ignore_ascii_case("https"));
    }
    let forwarded = FORWARDING_HEADERS
        .iter()
        .copied()
        .chain(ip_header)
        .any(|name| headers.contains_key(name));
    peer.is_loopback() && !forwarded
}

/// Whether the request came over a secure connection; see [`is_secure_connection`].
#[derive(Clone, Copy, Debug)]
pub struct SecureConnection(pub bool);

impl<S: Store, P: Crypto, K: TokenSigner + Clone + 'static> FromRequestParts<Api<S, P, K>>
    for SecureConnection
{
    type Rejection = Problem;

    async fn from_request_parts(parts: &mut Parts, api: &Api<S, P, K>) -> Result<Self, Problem> {
        Ok(SecureConnection(is_secure_connection(
            peer_address(parts),
            &parts.headers,
            &api.config.trusted_proxies,
            api.config.ip_header.as_deref(),
        )))
    }
}

/// The client's address, behind a trusted proxy if there is one.
#[derive(Clone, Copy, Debug)]
pub struct ClientIp(pub IpAddr);

impl<S: Store, P: Crypto, K: TokenSigner + Clone + 'static> FromRequestParts<Api<S, P, K>>
    for ClientIp
{
    type Rejection = Problem;

    async fn from_request_parts(parts: &mut Parts, api: &Api<S, P, K>) -> Result<Self, Problem> {
        Ok(ClientIp(peer_and_header(parts, api)))
    }
}

fn dpop_problem<S: Store, P: Crypto, K: TokenSigner + Clone + 'static>(
    api: &Api<S, P, K>,
    error: DpopError,
) -> Problem {
    match error {
        DpopError::Invalid(reason) => Problem::new(
            StatusCode::UNAUTHORIZED,
            "invalid-dpop-proof",
            "The DPoP proof is invalid",
        )
        .detail(reason)
        .header(
            header::WWW_AUTHENTICATE,
            r#"DPoP error="invalid_dpop_proof", algs="ES256 EdDSA""#,
        ),
        DpopError::UseNonce => Problem::new(
            StatusCode::UNAUTHORIZED,
            "use-dpop-nonce",
            "The DPoP proof must carry the server's nonce",
        )
        .with("error", json!("use_dpop_nonce"))
        .header(header::WWW_AUTHENTICATE, r#"DPoP error="use_dpop_nonce""#)
        .header(DPOP_NONCE, &api.dpop.current_nonce(api.now())),
        DpopError::Overloaded => Problem::overloaded(),
    }
}

/// The proof header's text: there must be exactly one.
fn proof_header<'a, S: Store, P: Crypto, K: TokenSigner + Clone + 'static>(
    parts: &'a Parts,
    api: &Api<S, P, K>,
) -> Result<&'a str, Problem> {
    let mut values = parts.headers.get_all("dpop").iter();
    let (Some(value), None) = (values.next(), values.next()) else {
        return Err(dpop_problem(
            api,
            DpopError::Invalid("exactly one DPoP header is required"),
        ));
    };
    value
        .to_str()
        .map_err(|_| dpop_problem(api, DpopError::Invalid("the DPoP header isn't text")))
}

/// Checks the request's proof and remembers it. `source` names the client address of a request
/// nobody is authenticated for: its proofs may take only their share of the open set.
fn verify_proof<S: Store, P: Crypto, K: TokenSigner + Clone + 'static>(
    parts: &Parts,
    api: &Api<S, P, K>,
    access_token: Option<&str>,
    source: Option<&str>,
) -> Result<String, Problem> {
    let proof = proof_header(parts, api)?;
    api.dpop
        .verify_from(
            source.map(str::as_bytes),
            proof,
            parts.method.as_str(),
            parts.uri.path(),
            api.now(),
            access_token,
        )
        .map_err(|e| dpop_problem(api, e))
}

/// A request to a token endpoint: its DPoP proof checked, with the thumbprint of the proof's key.
///
/// Nobody is authenticated yet, so checking proofs is limited per client address first: a proof
/// costs a signature check and, when it passes, room in the replay set.
#[derive(Clone, Debug)]
pub struct Proof {
    pub jkt: String,
    pub ip: IpAddr,
}

impl<S: Store, P: Crypto, K: TokenSigner + Clone + 'static> FromRequestParts<Api<S, P, K>>
    for Proof
{
    type Rejection = Problem;

    async fn from_request_parts(parts: &mut Parts, api: &Api<S, P, K>) -> Result<Self, Problem> {
        let ip = peer_and_header(parts, api);
        api.limits
            .proof
            .check(&ip_key(ip), api.now())
            .map_err(rate_limited)?;
        let jkt = verify_proof(parts, api, None, Some(&ip_key(ip)))?;
        Ok(Proof { jkt, ip })
    }
}

/// A request to the refresh endpoint: its DPoP proof checked but not remembered yet, with the
/// thumbprint of the proof's key.
///
/// A refresh proof carries no access token, so remembering it on arrival would put it in the
/// open set anyone can fill, and a full set would stop every device refreshing. The handler
/// instead records it (in the set of proofs that belong to sessions) once the refresh token is
/// found and bound to this key. Limited per client address like [`Proof`].
#[derive(Clone, Debug)]
pub struct RefreshProof {
    pub jkt: String,
    pub ip: IpAddr,
    pub pending: Pending,
}

impl<S: Store, P: Crypto, K: TokenSigner + Clone + 'static> FromRequestParts<Api<S, P, K>>
    for RefreshProof
{
    type Rejection = Problem;

    async fn from_request_parts(parts: &mut Parts, api: &Api<S, P, K>) -> Result<Self, Problem> {
        let ip = peer_and_header(parts, api);
        api.limits
            .proof
            .check(&ip_key(ip), api.now())
            .map_err(rate_limited)?;
        let proof = proof_header(parts, api)?;
        let pending = api
            .dpop
            .verify_unrecorded(proof, parts.method.as_str(), parts.uri.path(), api.now())
            .map_err(|e| dpop_problem(api, e))?;
        Ok(RefreshProof {
            jkt: pending.jkt.clone(),
            ip,
            pending,
        })
    }
}

/// An authenticated request: `Authorization: DPoP <token>` and a proof made with the key the
/// token is bound to, for an account whose security stamp still matches.
#[derive(Clone, Debug)]
pub struct Authed {
    pub actor: Actor,
    pub jkt: String,
    pub ip: IpAddr,
    /// When the access token expires, in Unix seconds: a connection that outlives the request
    /// (a WebSocket) ends then.
    pub expires_at: i64,
    /// When the sign-in the session began with happened, in Unix seconds. A refresh keeps it, so
    /// it is the age of the last real sign-in, not of the token.
    pub auth_time: i64,
    /// The security stamp the access token carries, for the same connections to check.
    pub security_stamp: Uuid,
}

/// Marks a 401 as a refused token (RFC 9449, section 7.1); other problems pass unchanged.
fn invalid_token(problem: Problem) -> Problem {
    if problem.status == StatusCode::UNAUTHORIZED {
        problem.header(header::WWW_AUTHENTICATE, r#"DPoP error="invalid_token""#)
    } else {
        problem
    }
}

fn challenge(detail: &'static str) -> Problem {
    Problem::new(
        StatusCode::UNAUTHORIZED,
        "unauthorized",
        "Authentication is required",
    )
    .detail(detail)
    .header(header::WWW_AUTHENTICATE, r#"DPoP algs="ES256 EdDSA""#)
}

impl<S: Store, P: Crypto, K: TokenSigner + Clone + 'static> FromRequestParts<Api<S, P, K>>
    for Authed
{
    type Rejection = Problem;

    async fn from_request_parts(parts: &mut Parts, api: &Api<S, P, K>) -> Result<Self, Problem> {
        let token = parts
            .headers
            .get(header::AUTHORIZATION)
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.split_once(' '))
            .filter(|(scheme, _)| scheme.eq_ignore_ascii_case("dpop"))
            .map(|(_, token)| token.trim())
            .filter(|token| !token.is_empty())
            .ok_or_else(|| challenge("send Authorization: DPoP <access token>"))?;
        // The token itself first (signature and expiry, no state): a request with a made-up or
        // expired token must not get as far as taking room in the proof replay set.
        let Ok(claims) = api.signer.verify(token, api.crypto.now()) else {
            return Err(invalid_token(Problem::from(AppError::Unauthorized)));
        };
        // A token anyone who registered holds is enough to get a proof into the set of
        // authenticated ones, so each device may make only so many a minute.
        api.limits
            .device_proof
            .check(&format!("device:{}", claims.device.0), api.now())
            .map_err(rate_limited)?;
        let jkt = verify_proof(parts, api, Some(token), None)?;
        let actor = api
            .authenticate()
            .execute(token, &jkt)
            .await
            .map_err(|e| invalid_token(Problem::from(e)))?;
        // The device used the API; the device list shows it beside the Bitwarden API's use.
        api.note_use(actor.device).await;
        Ok(Authed {
            actor,
            jkt,
            ip: peer_and_header(parts, api),
            expires_at: claims.expires_at.unix_timestamp(),
            auth_time: claims.auth_time.unix_timestamp(),
            security_stamp: claims.security_stamp,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn headers(pairs: &[(&str, &str)]) -> HeaderMap {
        let mut map = HeaderMap::new();
        for (name, value) in pairs {
            map.append(
                HeaderName::from_bytes(name.as_bytes()).expect("a header name"),
                value.parse().expect("a header value"),
            );
        }
        map
    }

    fn ip(text: &str) -> IpAddr {
        text.parse().expect("an address")
    }

    #[test]
    fn a_peer_on_this_machine_is_secure_without_forwarding_headers() {
        for peer in ["127.0.0.1", "127.9.9.9", "::1", "::ffff:127.0.0.1"] {
            assert!(
                is_secure_connection(ip(peer), &headers(&[]), &[], None),
                "{peer}"
            );
        }
    }

    #[test]
    fn a_remote_peer_is_never_secure_whatever_it_claims() {
        let claims = headers(&[
            ("origin", "http://localhost:8080"),
            ("host", "localhost"),
            ("x-forwarded-proto", "https"),
        ]);
        for peer in ["203.0.113.5", "10.0.0.7", "2001:db8::1"] {
            assert!(
                !is_secure_connection(ip(peer), &claims, &[], None),
                "{peer}"
            );
        }
    }

    #[test]
    fn a_loopback_peer_behind_an_unlisted_proxy_is_not_local() {
        // nginx on the same host, not named in KEMLOCK_TRUSTED_PROXIES: its clients are remote.
        for name in FORWARDING_HEADERS {
            let forwarded = headers(&[(name, "198.51.100.9")]);
            assert!(
                !is_secure_connection(ip("127.0.0.1"), &forwarded, &[], None),
                "{name}"
            );
        }
        assert!(!is_secure_connection(
            ip("127.0.0.1"),
            &headers(&[("cf-connecting-ip", "198.51.100.9")]),
            &[],
            Some("cf-connecting-ip")
        ));
    }

    #[test]
    fn a_trusted_proxy_says_which_scheme_the_client_used() {
        let proxy = ip("10.0.0.1");
        let trusted = [proxy];
        let check =
            |pairs: &[(&str, &str)]| is_secure_connection(proxy, &headers(pairs), &trusted, None);
        assert!(check(&[("x-forwarded-proto", "https")]));
        assert!(check(&[("x-forwarded-proto", "HTTPS")]));
        assert!(!check(&[("x-forwarded-proto", "http")]));
        assert!(!check(&[]), "no header, no evidence");
        // The last value is the nearest proxy's; a client's own earlier value doesn't count.
        assert!(!check(&[("x-forwarded-proto", "https, http")]));
        assert!(check(&[("x-forwarded-proto", "http, https")]));
        assert!(!check(&[
            ("x-forwarded-proto", "https"),
            ("x-forwarded-proto", "http")
        ]));
        // A trusted proxy on this machine is judged by its header too, not by being local.
        assert!(!is_secure_connection(
            ip("127.0.0.1"),
            &headers(&[("x-forwarded-proto", "http")]),
            &[ip("127.0.0.1")],
            None
        ));
        // And an IPv4 proxy matches its mapped form.
        assert!(is_secure_connection(
            ip("::ffff:10.0.0.1"),
            &headers(&[("x-forwarded-proto", "https")]),
            &trusted,
            None
        ));
    }

    #[test]
    fn only_a_trusted_proxy_is_believed() {
        let trusted = [ip("10.0.0.1")];
        let https = headers(&[("x-forwarded-proto", "https")]);
        assert!(!is_secure_connection(
            ip("10.0.0.2"),
            &https,
            &trusted,
            None
        ));
    }
}
