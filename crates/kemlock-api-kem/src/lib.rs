//! The Kemlock API, `/kem/v1`: an axum router over the use cases of `kemlock-app`.
//!
//! A handler parses the request into a use-case input, calls the use case and maps its result or
//! error to JSON; errors leave as RFC 9457 `application/problem+json`. Every call except the
//! first-run, prelogin and registration routes is bound to a device key with DPoP (RFC 9449).
//! The router is generic over the ports, so tests run it in-process with
//! `tower::ServiceExt::oneshot` against in-memory fakes.

#![allow(clippy::result_large_err)]

pub mod dpop;
pub mod dto;
pub mod extract;
pub mod finish_gate;
pub mod jws;
pub mod live;
pub mod openapi;
pub mod problem;
pub mod ratelimit;
pub mod replay;
mod routes;
pub mod service;
mod signlog;
pub mod state;
pub mod testing;

pub use jws::JwsTokenSigner;
pub use live::LiveHub;
pub use problem::Problem;
pub use routes::account::{AccountServices, router as account_router};
pub use routes::api_key::{ApiKeyApiDoc, api_key_router};
pub use routes::attempts::{
    forget_second_step, forget_step_up, reserve_second_step, reserve_step_up,
};
pub use routes::custom_fields::{
    CustomFieldDto, CustomFieldsDto, KindsDto, router as custom_fields_router,
};
pub use routes::duplicates::{
    DedupRepo, openapi as duplicates_openapi, router as duplicates_router,
};
pub use routes::files::{
    DownloadLinkDto, FileDto, FilesApi, FilesDoc, StartFileRequest, StartFileResponse, files_router,
};
pub use routes::invite_link::{
    MaybeInviteLinks, openapi as invite_link_openapi, router as invite_link_router,
};
pub use routes::passkeys::{PasskeyRuntime, PasskeysApiDoc, passkeys_router};
pub use routes::policies::{
    MasterPasswordDto, PoliciesDoc, PoliciesDto, SpacePoliciesDto, policies_router, with_join_guard,
};
pub use routes::profile::{ProfileApiDoc, profile_router};
pub use routes::push::router as push_router;
pub use routes::recovery_kit::{RecoveryKitApiDoc, recovery_kit_router};
pub use routes::rotation::{RotationApiDoc, rotation_router};
pub use routes::sends::{
    AccessDto, AccessRequest, CreateSendRequest, SendDto, SendsApi, SendsDoc, UpdateSendRequest,
    sends_router,
};
pub use routes::space_chain::{openapi as space_chain_openapi, router as space_chain_router};
pub use routes::space_recovery::{
    openapi as space_recovery_openapi, router as space_recovery_router,
};
pub use routes::spaces::{openapi as spaces_openapi, router as spaces_router};
pub use routes::sso::{SsoApiDoc, SsoRuntime, sso_router};
pub use routes::two_step::{TwoStepApiDoc, TwoStepRuntime, two_step_router};
pub use service::router;
pub use state::{Api, ApiConfig, ApiSecrets, Crypto, Limits, Store};
