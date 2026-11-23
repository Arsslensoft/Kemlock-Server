//! The router: every `/kem/v1` route, and the headers every response carries.

use crate::extract::DPOP_NONCE;
use crate::problem::Problem;
use crate::routes::spaces::Env;
use crate::state::{Api, Crypto, Store};
use axum::Router;
use axum::extract::{Request, State};
use axum::http::HeaderValue;
use axum::middleware::{self, Next};
use axum::response::Response;
use axum::routing::{get, post};
use kemlock_app::bitwarden::BwAccountRepo;
use kemlock_app::devices::DevicesStore;
use kemlock_app::emergency::EmergencyRepo;
use kemlock_app::manifests::ManifestRepo;
use kemlock_app::ports::TokenSigner;
use kemlock_app::spaces::SpaceRepo;

/// Every response carries the current DPoP nonce (RFC 9449, section 8), so a client that sent
/// none learns it from the first answer and one whose nonce rotated learns the new one.
async fn nonce_header<S, P, K>(
    State(api): State<Api<S, P, K>>,
    request: Request,
    next: Next,
) -> Response
where
    S: Store,
    P: Crypto,
    K: TokenSigner + Clone + 'static,
{
    let mut response = next.run(request).await;
    if let Ok(value) = HeaderValue::from_str(&api.dpop.current_nonce(api.now())) {
        response.headers_mut().insert(DPOP_NONCE, value);
    }
    response
}

async fn not_found() -> Problem {
    Problem::not_found()
}

/// The `/kem/v1` router. Request bodies are capped at 2 MiB by the `Body` extractor; errors are
/// problem+json. The OpenAPI document is at `/kem/v1/openapi.json`. `/kem/v1/items:batch` is a
/// literal path: axum 0.8's matcher only treats `{name}` as a parameter, and a colon inside a
/// segment that doesn't start with one is plain text.
pub fn router<S, P, K, R>(api: Api<S, P, K>, spaces: R) -> Router
where
    S: Store + DevicesStore + EmergencyRepo + ManifestRepo + BwAccountRepo,
    P: Crypto,
    K: TokenSigner + Clone + 'static,
    R: SpaceRepo + Clone + 'static,
{
    let env = Env {
        api: api.clone(),
        spaces,
    };
    let manifests = crate::routes::manifests::router(env.clone());
    let items = crate::routes::items::router(env);
    type A<S, P, K> = Api<S, P, K>;
    Router::new()
        .route("/kem/v1/config", get(A::<S, P, K>::handle_config))
        .route("/kem/v1/openapi.json", get(A::<S, P, K>::handle_openapi))
        .route(
            "/kem/v1/setup/verify",
            post(A::<S, P, K>::handle_setup_verify),
        )
        .route(
            "/kem/v1/setup/finish",
            post(A::<S, P, K>::handle_setup_finish),
        )
        .route("/kem/v1/auth/prelogin", post(A::<S, P, K>::handle_prelogin))
        .route("/kem/v1/auth/methods", post(A::<S, P, K>::handle_methods))
        .route(
            "/kem/v1/accounts/register/start",
            post(A::<S, P, K>::handle_register_start),
        )
        .route(
            "/kem/v1/accounts/register/finish",
            post(A::<S, P, K>::handle_register_finish),
        )
        .route(
            "/kem/v1/auth/opaque/start",
            post(A::<S, P, K>::handle_opaque_start),
        )
        .route(
            "/kem/v1/auth/opaque/finish",
            post(A::<S, P, K>::handle_opaque_finish),
        )
        .route(
            "/kem/v1/auth/two-factor",
            post(A::<S, P, K>::handle_two_factor),
        )
        .route("/kem/v1/auth/token", post(A::<S, P, K>::handle_token))
        .route(
            "/kem/v1/account/two-factor/totp",
            post(A::<S, P, K>::handle_totp_enrol),
        )
        .route(
            "/kem/v1/account/two-factor/totp/confirm",
            post(A::<S, P, K>::handle_totp_confirm),
        )
        .route(
            "/kem/v1/account/two-factor/recovery-code",
            get(A::<S, P, K>::handle_recovery_code),
        )
        .merge(crate::routes::devices::router::<S, P, K>())
        .merge(crate::routes::emergency::router::<S, P, K>())
        .merge(crate::routes::contract::router::<S, P, K>())
        .merge(crate::routes::failover::router::<S, P, K>())
        .fallback(not_found)
        .layer(middleware::from_fn_with_state(
            api.clone(),
            nonce_header::<S, P, K>,
        ))
        .with_state(api)
        // The item routes answer with the nonce header themselves; the fallback stays the main
        // router's.
        .merge(items)
        .merge(manifests)
}
