//! Admin errors as RFC 9457 `application/problem+json`, the same shape `/kem/v1` answers with.

use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use kemlock_api_kem::Problem;
use kemlock_app::AppError;
use kemlock_app::admin::AdminError;
use kemlock_app::ports::StoreError;
use serde_json::json;

/// What a handler fails with: a problem, ready to become a response.
#[derive(Debug)]
pub struct ApiError(pub Problem);

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        self.0.into_response()
    }
}

impl From<Problem> for ApiError {
    fn from(p: Problem) -> Self {
        ApiError(p)
    }
}

impl From<AppError> for ApiError {
    fn from(e: AppError) -> Self {
        ApiError(Problem::from(e))
    }
}

impl From<StoreError> for ApiError {
    fn from(e: StoreError) -> Self {
        ApiError(Problem::from(AppError::from(e)))
    }
}

/// The 403 a request without a valid step-up token gets: the console reacts by asking the admin
/// for their password or a code, then sends the request again with the token.
pub fn step_up_required() -> Problem {
    Problem::new(
        StatusCode::FORBIDDEN,
        "step-up-required",
        "A fresh password or two-step check is required",
    )
    .detail(
        "make one at /admin/v1/step-up/password, /totp or /passkey and send the token in \
         the Step-Up-Token header",
    )
    .with("stepUp", json!(true))
}

impl From<AdminError> for ApiError {
    fn from(e: AdminError) -> Self {
        ApiError(match e {
            AdminError::NotFound => Problem::not_found(),
            AdminError::Invalid(why) => Problem::bad_request(why),
            AdminError::State(why) => Problem::new(
                StatusCode::CONFLICT,
                "wrong-state",
                "That isn't possible in the current state",
            )
            .detail(why),
            AdminError::ReadOnly(key) => Problem::new(
                StatusCode::CONFLICT,
                "setting-read-only",
                "The environment sets this setting, so the console can't change it",
            )
            .with("setting", json!(key)),
            AdminError::Forbidden(why) => {
                Problem::new(StatusCode::FORBIDDEN, "forbidden", "This isn't allowed").detail(why)
            }
            AdminError::StepUpRequired => step_up_required(),
            AdminError::StepUpFailed => Problem::new(
                StatusCode::FORBIDDEN,
                "step-up-failed",
                "The password or the code was wrong",
            ),
            AdminError::NotConfigured(why) => Problem::new(
                StatusCode::CONFLICT,
                "not-configured",
                "That needs something this server isn't set up with",
            )
            .detail(why),
            AdminError::App(e) => Problem::from(e),
        })
    }
}
