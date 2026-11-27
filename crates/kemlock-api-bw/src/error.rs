//! Errors as Vaultwarden answers them.
//!
//! An `err!` in Vaultwarden is a 400 whose body repeats the message under `message`,
//! `validationErrors[""]` and `errorModel.message`, with empty `error` and `error_description`.
//! A second-step challenge or an `invalid_grant` is a 400 whose body is the JSON itself.

use axum::Json;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use kemlock_app::ports::StoreError;
use serde_json::{Value, json};

#[derive(Debug, Clone, PartialEq)]
pub enum BwError {
    /// `err!(message)`: a 400 in Vaultwarden's error shape.
    Msg(String),
    /// `err_code!(message, status)`.
    Status(StatusCode, String),
    /// `err_json!(body, …)`: a 400 whose body is exactly this.
    Json(Value),
    /// A failed bearer token: Rocket's 401 with nothing to read.
    Unauthorized,
    /// A route or file that isn't there: 404.
    NotFound,
    /// The store or a file failed; the message is for logs, never for clients.
    Server(String),
}

pub type BwResult<T> = Result<T, BwError>;

impl BwError {
    pub fn msg(message: impl Into<String>) -> Self {
        BwError::Msg(message.into())
    }

    pub fn status(status: StatusCode, message: impl Into<String>) -> Self {
        BwError::Status(status, message.into())
    }
}

impl From<StoreError> for BwError {
    fn from(e: StoreError) -> Self {
        match e {
            // A collection or group id another space holds (docs/crypto.md, S4): the client's
            // to change, a 400 as Vaultwarden answers a refused request.
            StoreError::Duplicate => BwError::msg("That id is already in use"),
            // A space change that would leave members and no owner.
            StoreError::Backend(message) if message == kemlock_app::spaces::OWNER_REQUIRED => {
                BwError::msg(message)
            }
            other => BwError::Server(other.to_string()),
        }
    }
}

/// The body of an `err!`.
pub fn api_error(message: &str) -> Value {
    json!({
        "message": message,
        "validationErrors": { "": [message] },
        "errorModel": { "message": message, "object": "error" },
        "error": "",
        "error_description": "",
        "exceptionMessage": null,
        "exceptionStackTrace": null,
        "innerExceptionMessage": null,
        "object": "error",
    })
}

/// What `/api` answers for a route it doesn't have, with the JSON Vaultwarden's catcher sends.
pub fn not_found_body() -> Value {
    json!({
        "error": {
            "code": 404,
            "reason": "Not Found",
            "description": "The requested resource could not be found."
        }
    })
}

impl BwError {
    /// What a bulk route puts in the line of one member whose action failed: the message of a
    /// refusal, which is meant for the client, and for anything else a bare "Error" (the detail is
    /// logged), so a failure of the store or a file never reaches the client as a line of text.
    pub fn bulk_line_text(self) -> String {
        match self {
            BwError::Msg(text) | BwError::Status(_, text) => text,
            BwError::Unauthorized | BwError::NotFound => "Error".to_owned(),
            BwError::Json(_) => "Error".to_owned(),
            BwError::Server(detail) => {
                tracing::error!(%detail, "a bulk member action failed");
                "Error".to_owned()
            }
        }
    }
}

impl IntoResponse for BwError {
    fn into_response(self) -> Response {
        match self {
            BwError::Msg(m) => (StatusCode::BAD_REQUEST, Json(api_error(&m))).into_response(),
            BwError::Status(code, m) => (code, Json(api_error(&m))).into_response(),
            BwError::Json(body) => (StatusCode::BAD_REQUEST, Json(body)).into_response(),
            BwError::Unauthorized => StatusCode::UNAUTHORIZED.into_response(),
            BwError::NotFound => (StatusCode::NOT_FOUND, Json(not_found_body())).into_response(),
            BwError::Server(detail) => {
                tracing::error!(%detail, "the Bitwarden API failed");
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(api_error("Internal server error")),
                )
                    .into_response()
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_bulk_line_keeps_a_refusal_and_hides_a_failure() {
        assert_eq!(
            BwError::msg("User in invalid state").bulk_line_text(),
            "User in invalid state"
        );
        assert_eq!(
            BwError::status(StatusCode::TOO_MANY_REQUESTS, "Too many requests").bulk_line_text(),
            "Too many requests"
        );
        let leak = BwError::Server("database error: connection refused to db:5432".to_owned());
        assert_eq!(leak.bulk_line_text(), "Error");
        assert_eq!(BwError::Unauthorized.bulk_line_text(), "Error");
    }

    #[test]
    fn an_err_has_vaultwardens_shape() {
        let body = api_error("Invalid folder");
        assert_eq!(body["message"], "Invalid folder");
        assert_eq!(body["validationErrors"][""][0], "Invalid folder");
        assert_eq!(body["errorModel"]["message"], "Invalid folder");
        assert_eq!(body["errorModel"]["object"], "error");
        assert_eq!(body["error"], "");
        assert_eq!(body["error_description"], "");
        assert!(body["exceptionMessage"].is_null());
        assert_eq!(body["object"], "error");
        assert_eq!(body.as_object().map(|o| o.len()), Some(9));
    }

    #[test]
    fn a_refused_space_change_is_the_clients_400_not_a_server_failure() {
        for refused in [
            StoreError::Duplicate,
            StoreError::Backend(kemlock_app::spaces::OWNER_REQUIRED.to_owned()),
        ] {
            let error = BwError::from(refused);
            assert!(matches!(error, BwError::Msg(_)), "{error:?}");
            assert_eq!(error.into_response().status(), StatusCode::BAD_REQUEST);
        }
        assert!(matches!(
            BwError::from(StoreError::Backend("down".to_owned())),
            BwError::Server(_)
        ));
    }

    #[test]
    fn statuses_follow_the_kind() {
        assert_eq!(
            BwError::msg("x").into_response().status(),
            StatusCode::BAD_REQUEST
        );
        assert_eq!(
            BwError::status(StatusCode::UNPROCESSABLE_ENTITY, "x")
                .into_response()
                .status(),
            StatusCode::UNPROCESSABLE_ENTITY
        );
        assert_eq!(
            BwError::Json(json!({"error": "invalid_grant"}))
                .into_response()
                .status(),
            StatusCode::BAD_REQUEST
        );
        assert_eq!(
            BwError::Unauthorized.into_response().status(),
            StatusCode::UNAUTHORIZED
        );
        assert_eq!(
            BwError::NotFound.into_response().status(),
            StatusCode::NOT_FOUND
        );
        assert_eq!(
            BwError::Server("db".into()).into_response().status(),
            StatusCode::INTERNAL_SERVER_ERROR
        );
    }
}
