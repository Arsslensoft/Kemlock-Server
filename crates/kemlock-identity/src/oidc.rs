//! The OpenID Connect relying party: discovery, the authorization code flow with PKCE and a
//! nonce, ID token validation and back-channel logout tokens, over the `openidconnect` crate.
//!
//! [`OidcClient`] implements `kemlock_app::sso::OidcProvider`. It discovers a provider the first
//! time it is asked, keeps the provider's metadata and keys for [`DEFAULT_CACHE_TTL`], and fetches
//! them again when a signature fails to verify, which is what a key rotation looks like.
//!
//! The `openidconnect` crate verifies each ID token: its signature against the provider's keys,
//! the issuer, the audience, the expiry and the nonce. Claims it doesn't model (`amr`, `groups`,
//! `sid`) are read from the payload of the same, already verified, token.

use crate::logout::{self, SignatureError};
use crate::token::{decode_object, identity_claims, split};
use kemlock_app::sso::model::{AuthorizationRequest, CodeExchange};
use kemlock_app::sso::{ClientConfig, IdentityClaims, LogoutClaims, OidcProvider, SsoError};
use openidconnect::core::{CoreAuthenticationFlow, CoreClient, CoreIdToken, CoreProviderMetadata};
use openidconnect::reqwest;
use openidconnect::{
    AuthorizationCode, ClaimsVerificationError, ClientId, ClientSecret, CsrfToken,
    EndpointMaybeSet, EndpointNotSet, EndpointSet, IssuerUrl, Nonce, PkceCodeChallenge,
    PkceCodeVerifier, RedirectUrl, Scope, TokenResponse,
};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use time::OffsetDateTime;

/// How long a provider's metadata and keys are reused before they are fetched again.
pub const DEFAULT_CACHE_TTL: Duration = Duration::from_secs(10 * 60);

/// The least time between two fetches of a provider's keys forced by a back-channel logout token
/// that doesn't verify. The route is open to anyone, so a forged token must not make the server
/// run discovery every time; a real key rotation is picked up by the first token after it, and by
/// the cache's own expiry otherwise.
pub const DEFAULT_REFRESH_FLOOR: Duration = Duration::from_secs(60);

/// How long a request to the provider may take.
const REQUEST_TIMEOUT: Duration = Duration::from_secs(15);

/// The client `from_provider_metadata` builds: an authorization endpoint, and token and userinfo
/// endpoints the metadata may or may not name.
type Client = CoreClient<
    EndpointSet,
    EndpointNotSet,
    EndpointNotSet,
    EndpointNotSet,
    EndpointMaybeSet,
    EndpointMaybeSet,
>;

struct Cached {
    fetched: Instant,
    metadata: Arc<CoreProviderMetadata>,
}

/// An OpenID Connect relying party. Cheap to share; clone the `Arc` it lives in.
pub struct OidcClient {
    http: reqwest::Client,
    cache: Mutex<HashMap<String, Cached>>,
    ttl: Duration,
    /// When each issuer's keys were last fetched again because a logout token didn't verify.
    forced: Mutex<HashMap<String, Instant>>,
    /// The least time between two such fetches for one issuer.
    refresh_floor: Duration,
}

impl std::fmt::Debug for OidcClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OidcClient").finish_non_exhaustive()
    }
}

/// An error and what caused it, joined: `Request failed: error sending request: connection refused`.
fn describe(error: &dyn std::error::Error) -> String {
    let mut text = error.to_string();
    let mut source = error.source();
    while let Some(cause) = source {
        text.push_str(": ");
        text.push_str(&cause.to_string());
        source = cause.source();
    }
    text
}

/// Verifies an ID token as the client sees it: signature against the keys it was built with,
/// issuer, audience, expiry and nonce.
fn verify_id_token(
    oidc: &Client,
    compact: &str,
    nonce: &Nonce,
) -> Result<(), ClaimsVerificationError> {
    let id_token: CoreIdToken = compact
        .parse()
        .map_err(|e: serde_json::Error| ClaimsVerificationError::Other(e.to_string()))?;
    id_token
        .claims(&oidc.id_token_verifier(), nonce)
        .map(|_| ())
}

impl OidcClient {
    /// A client that follows no redirects (a provider that redirects a back-channel request is
    /// trying to make the server fetch somewhere else) and gives up after 15 seconds.
    pub fn new() -> Result<Self, SsoError> {
        let http = reqwest::ClientBuilder::new()
            .redirect(reqwest::redirect::Policy::none())
            .timeout(REQUEST_TIMEOUT)
            .build()
            .map_err(|e| SsoError::Provider(format!("can't build the HTTP client: {e}")))?;
        Ok(OidcClient {
            http,
            cache: Mutex::new(HashMap::new()),
            ttl: DEFAULT_CACHE_TTL,
            forced: Mutex::new(HashMap::new()),
            refresh_floor: DEFAULT_REFRESH_FLOOR,
        })
    }

    /// Changes how long discovery results are reused.
    pub fn with_cache_ttl(mut self, ttl: Duration) -> Self {
        self.ttl = ttl;
        self
    }

    /// Changes the least time between two key fetches a back-channel logout token may force.
    pub fn with_refresh_floor(mut self, floor: Duration) -> Self {
        self.refresh_floor = floor;
        self
    }

    /// Whether a logout token that didn't verify may force the issuer's keys to be fetched again
    /// now: once in [`OidcClient::with_refresh_floor`], however many forged tokens arrive.
    fn may_force_refresh(&self, issuer: &str) -> bool {
        let Ok(mut forced) = self.forced.lock() else {
            return false;
        };
        if forced
            .get(issuer)
            .is_some_and(|at| at.elapsed() < self.refresh_floor)
        {
            return false;
        }
        forced.insert(issuer.to_owned(), Instant::now());
        true
    }

    fn cached(&self, issuer: &str) -> Option<Arc<CoreProviderMetadata>> {
        let cache = self.cache.lock().ok()?;
        let entry = cache.get(issuer)?;
        (entry.fetched.elapsed() < self.ttl).then(|| Arc::clone(&entry.metadata))
    }

    /// The provider's metadata and keys: from the cache, or discovered. `fresh` skips the cache.
    /// The flag returned says whether the metadata was fetched just now.
    async fn metadata(
        &self,
        issuer: &str,
        fresh: bool,
    ) -> Result<(Arc<CoreProviderMetadata>, bool), SsoError> {
        if !fresh && let Some(metadata) = self.cached(issuer) {
            return Ok((metadata, false));
        }
        let issuer_url = IssuerUrl::new(issuer.to_owned())
            .map_err(|e| SsoError::Provider(format!("the issuer URL is invalid: {e}")))?;
        let metadata = CoreProviderMetadata::discover_async(issuer_url, &self.http)
            .await
            .map_err(|e| SsoError::Provider(format!("discovery failed: {}", describe(&e))))?;
        let metadata = Arc::new(metadata);
        if let Ok(mut cache) = self.cache.lock() {
            cache.insert(
                issuer.to_owned(),
                Cached {
                    fetched: Instant::now(),
                    metadata: Arc::clone(&metadata),
                },
            );
        }
        Ok((metadata, true))
    }

    fn client(
        metadata: &CoreProviderMetadata,
        config: &ClientConfig,
        redirect_uri: &str,
    ) -> Result<Client, SsoError> {
        let redirect = RedirectUrl::new(redirect_uri.to_owned())
            .map_err(|e| SsoError::Provider(format!("the redirect URI is invalid: {e}")))?;
        Ok(CoreClient::from_provider_metadata(
            metadata.clone(),
            ClientId::new(config.client_id.clone()),
            config.client_secret.clone().map(ClientSecret::new),
        )
        .set_redirect_uri(redirect))
    }
}

impl OidcProvider for OidcClient {
    async fn authorization_url(
        &self,
        client: &ClientConfig,
        request: &AuthorizationRequest,
    ) -> Result<String, SsoError> {
        let (metadata, _) = self.metadata(&client.issuer, false).await?;
        let oidc = Self::client(&metadata, client, &request.redirect_uri)?;
        let challenge = PkceCodeChallenge::from_code_verifier_sha256(&PkceCodeVerifier::new(
            request.code_verifier.clone(),
        ));
        let (state, nonce) = (request.state.clone(), request.nonce.clone());
        let mut builder = oidc
            .authorize_url(
                CoreAuthenticationFlow::AuthorizationCode,
                move || CsrfToken::new(state),
                move || Nonce::new(nonce),
            )
            .set_pkce_challenge(challenge);
        // `openid` is always asked for; the others are the admin's.
        for scope in client.scopes.iter().filter(|s| s.as_str() != "openid") {
            builder = builder.add_scope(Scope::new(scope.clone()));
        }
        let (url, _state, _nonce) = builder.url();
        Ok(url.to_string())
    }

    async fn exchange(
        &self,
        client: &ClientConfig,
        request: &CodeExchange,
    ) -> Result<IdentityClaims, SsoError> {
        let (metadata, fetched_now) = self.metadata(&client.issuer, false).await?;
        let oidc = Self::client(&metadata, client, &request.redirect_uri)?;
        let response = oidc
            .exchange_code(AuthorizationCode::new(request.code.clone()))
            .map_err(|e| SsoError::Provider(format!("the provider has no token endpoint: {e}")))?
            .set_pkce_verifier(PkceCodeVerifier::new(request.code_verifier.clone()))
            .request_async(&self.http)
            .await
            .map_err(|e| {
                SsoError::Provider(format!("the token request failed: {}", describe(&e)))
            })?;
        // Keep the ID token as the compact string it came as, and nothing else of the response.
        let compact = response
            .id_token()
            .map(ToString::to_string)
            .ok_or_else(|| SsoError::Token("the provider sent no ID token".to_owned()))?;
        drop(response);

        // The provider's signing key may have rotated since its keys were cached: on a signature
        // failure, fetch them again once and verify the same token (the code is spent already).
        let nonce = Nonce::new(request.nonce.clone());
        match verify_id_token(&oidc, &compact, &nonce) {
            Ok(()) => {}
            Err(ClaimsVerificationError::SignatureVerification(_)) if !fetched_now => {
                let (metadata, _) = self.metadata(&client.issuer, true).await?;
                let oidc = Self::client(&metadata, client, &request.redirect_uri)?;
                verify_id_token(&oidc, &compact, &nonce)
                    .map_err(|e| SsoError::Token(describe(&e)))?;
            }
            Err(e) => return Err(SsoError::Token(describe(&e))),
        }

        // Verified: read the claims `openidconnect` doesn't model from the same token's payload.
        let (_, payload, _) = split(&compact)
            .ok_or_else(|| SsoError::Token("the ID token isn't a JWT".to_owned()))?;
        let payload = decode_object(payload)
            .ok_or_else(|| SsoError::Token("the ID token payload isn't JSON".to_owned()))?;
        identity_claims(&payload)
    }

    async fn validate_logout_token(
        &self,
        client: &ClientConfig,
        token: &str,
    ) -> Result<LogoutClaims, SsoError> {
        let (metadata, fetched_now) = self.metadata(&client.issuer, false).await?;
        let mut payload = logout::verify_signature(token, metadata.jwks());
        let mut issuer = metadata.issuer().to_string();
        if matches!(payload, Err(SignatureError::NoKey | SignatureError::Bad))
            && !fetched_now
            && self.may_force_refresh(&client.issuer)
        {
            let (metadata, _) = self.metadata(&client.issuer, true).await?;
            payload = logout::verify_signature(token, metadata.jwks());
            issuer = metadata.issuer().to_string();
        }
        let payload = payload.map_err(|e| SsoError::Token(format!("logout token: {e}")))?;
        logout::check_claims(
            &payload,
            &issuer,
            &client.client_id,
            OffsetDateTime::now_utc().unix_timestamp(),
        )
    }
}
