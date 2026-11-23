//! Who may call: an admin, and for a write an admin with a fresh step-up token.

use crate::error::{ApiError, step_up_required};
use crate::state::Env;
use axum::extract::FromRequestParts;
use axum::http::request::Parts;
use kemlock_api_kem::extract::Authed;
use kemlock_api_kem::{Crypto, Store};
use kemlock_app::admin::{AdminRepos, Mailer};
use kemlock_app::ports::TokenSigner;
use kemlock_app::spaces::SpaceRepo;
use kemlock_app::sso::{SsoRepos, TxtLookup};
use kemlock_app::{Actor, AppError};
use std::net::IpAddr;

/// The header a write carries its step-up token in.
pub const STEP_UP_HEADER: &str = "step-up-token";

/// An authenticated admin: the access token is good, bound to the caller's DPoP key, and the
/// account has the admin role **and** a confirmed two-step method (the Kemlock API's
/// `Actor::admin`). Anyone else gets 403.
#[derive(Clone, Copy, Debug)]
pub(crate) struct Caller {
    pub(crate) actor: Actor,
    /// The client's address, behind a trusted proxy if there is one.
    pub(crate) ip: IpAddr,
}

/// An admin whose request carries a step-up token made for this account and this device in the
/// last few minutes. Every write asks for one.
#[derive(Clone, Copy, Debug)]
pub(crate) struct Writer {
    pub(crate) actor: Actor,
    pub(crate) ip: IpAddr,
}

impl<S, P, K, R, Sp, So, D, M> FromRequestParts<Env<S, P, K, R, Sp, So, D, M>> for Caller
where
    S: Store,
    P: Crypto,
    K: TokenSigner + Clone + 'static,
    R: AdminRepos,
    Sp: SpaceRepo + Clone + 'static,
    So: SsoRepos,
    D: TxtLookup + Clone + 'static,
    M: Mailer + Clone + 'static,
{
    type Rejection = ApiError;

    async fn from_request_parts(
        parts: &mut Parts,
        env: &Env<S, P, K, R, Sp, So, D, M>,
    ) -> Result<Self, ApiError> {
        let authed = Authed::from_request_parts(parts, &env.api).await?;
        if !authed.actor.admin {
            return Err(AppError::Forbidden.into());
        }
        Ok(Caller {
            actor: authed.actor,
            ip: authed.ip,
        })
    }
}

impl<S, P, K, R, Sp, So, D, M> FromRequestParts<Env<S, P, K, R, Sp, So, D, M>> for Writer
where
    S: Store,
    P: Crypto,
    K: TokenSigner + Clone + 'static,
    R: AdminRepos,
    Sp: SpaceRepo + Clone + 'static,
    So: SsoRepos,
    D: TxtLookup + Clone + 'static,
    M: Mailer + Clone + 'static,
{
    type Rejection = ApiError;

    async fn from_request_parts(
        parts: &mut Parts,
        env: &Env<S, P, K, R, Sp, So, D, M>,
    ) -> Result<Self, ApiError> {
        let caller = Caller::from_request_parts(parts, env).await?;
        let token = parts
            .headers
            .get(STEP_UP_HEADER)
            .and_then(|v| v.to_str().ok())
            .ok_or_else(|| ApiError(step_up_required()))?;
        env.step_up().check(&caller.actor, token)?;
        Ok(Writer {
            actor: caller.actor,
            ip: caller.ip,
        })
    }
}
