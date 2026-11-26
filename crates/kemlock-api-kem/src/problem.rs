//! Errors as RFC 9457 `application/problem+json`.

use axum::body::Body;
use axum::http::{HeaderName, HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};
use kemlock_app::AppError;
use kemlock_domain::{ItemError, SetupError};
use serde_json::{Map, Value, json};

/// The `type` of every problem is `urn:kemlock:problem:<slug>`.
pub const PROBLEM_TYPE_PREFIX: &str = "urn:kemlock:problem:";

/// A problem detail, ready to become a response.
#[derive(Debug, Clone, PartialEq)]
pub struct Problem {
    pub status: StatusCode,
    /// The last part of the problem's `type`.
    pub slug: &'static str,
    pub title: &'static str,
    pub detail: Option<String>,
    /// Extra members of the problem object (RFC 9457 allows them).
    pub extra: Map<String, Value>,
    pub headers: Vec<(HeaderName, HeaderValue)>,
}

impl Problem {
    pub fn new(status: StatusCode, slug: &'static str, title: &'static str) -> Self {
        Problem {
            status,
            slug,
            title,
            detail: None,
            extra: Map::new(),
            headers: Vec::new(),
        }
    }

    pub fn detail(mut self, detail: impl Into<String>) -> Self {
        self.detail = Some(detail.into());
        self
    }

    pub fn with(mut self, key: &str, value: Value) -> Self {
        self.extra.insert(key.to_owned(), value);
        self
    }

    /// Adds a response header; a value that isn't a valid header value is dropped.
    pub fn header(mut self, name: HeaderName, value: &str) -> Self {
        if let Ok(value) = HeaderValue::from_str(value) {
            self.headers.push((name, value));
        }
        self
    }

    pub fn bad_request(detail: impl Into<String>) -> Self {
        Problem::new(
            StatusCode::BAD_REQUEST,
            "invalid-request",
            "Invalid request",
        )
        .detail(detail)
    }

    pub fn not_found() -> Self {
        Problem::new(StatusCode::NOT_FOUND, "not-found", "Not found")
    }

    pub fn payload_too_large() -> Self {
        Problem::new(
            StatusCode::PAYLOAD_TOO_LARGE,
            "payload-too-large",
            "The request body is too large",
        )
        .detail("JSON bodies are limited to 2 MiB")
    }

    /// 503 with `Retry-After`: the server is holding all the state it will hold for now.
    pub fn overloaded() -> Self {
        Problem::new(
            StatusCode::SERVICE_UNAVAILABLE,
            "overloaded",
            "The server is busy: try again shortly",
        )
        .header(header::RETRY_AFTER, "30")
    }

    pub fn precondition_required(detail: impl Into<String>) -> Self {
        Problem::new(
            StatusCode::PRECONDITION_REQUIRED,
            "precondition-required",
            "A precondition header is required",
        )
        .detail(detail)
    }

    /// The problem as a JSON object.
    pub fn to_json(&self) -> Value {
        let mut body = Map::new();
        body.insert(
            "type".to_owned(),
            Value::String(format!("{PROBLEM_TYPE_PREFIX}{}", self.slug)),
        );
        body.insert("title".to_owned(), Value::String(self.title.to_owned()));
        body.insert("status".to_owned(), json!(self.status.as_u16()));
        if let Some(detail) = &self.detail {
            body.insert("detail".to_owned(), Value::String(detail.clone()));
        }
        for (k, v) in &self.extra {
            body.insert(k.clone(), v.clone());
        }
        Value::Object(body)
    }
}

impl IntoResponse for Problem {
    fn into_response(self) -> Response {
        let bytes = serde_json::to_vec(&self.to_json()).unwrap_or_default();
        let mut response = Response::new(Body::from(bytes));
        *response.status_mut() = self.status;
        response.headers_mut().insert(
            header::CONTENT_TYPE,
            HeaderValue::from_static("application/problem+json"),
        );
        for (name, value) in self.headers {
            response.headers_mut().append(name, value);
        }
        response
    }
}

impl From<AppError> for Problem {
    fn from(e: AppError) -> Self {
        match e {
            AppError::Invalid(detail) => Problem::bad_request(detail),
            AppError::Unauthorized => Problem::new(
                StatusCode::UNAUTHORIZED,
                "unauthorized",
                "The credentials are wrong or have expired",
            ),
            AppError::SessionEnded(reason) => Problem::new(
                StatusCode::UNAUTHORIZED,
                "session-ended",
                "The session has ended",
            )
            .with("reason", json!(reason)),
            AppError::Forbidden => {
                Problem::new(StatusCode::FORBIDDEN, "forbidden", "This isn't allowed")
            }
            AppError::AccountDisabled => Problem::new(
                StatusCode::FORBIDDEN,
                "account-disabled",
                "This account has been disabled",
            ),
            AppError::AccountBeingDeleted => Problem::new(
                StatusCode::FORBIDDEN,
                "account-being-deleted",
                "This account is being deleted",
            ),
            AppError::EmailNotConfirmed => Problem::new(
                StatusCode::FORBIDDEN,
                "email-not-confirmed",
                "This account's email address isn't confirmed",
            )
            .detail("Open the link mailed to the address, or ask for a new one."),
            AppError::SsoRequired { space } => Problem::new(
                StatusCode::FORBIDDEN,
                "sso-required",
                "A space this account belongs to requires single sign-on",
            )
            .with("spaceId", json!(space.to_string())),
            AppError::NotFound => Problem::not_found(),
            AppError::Conflict { item, current } => Problem::new(
                StatusCode::CONFLICT,
                "stale-revision",
                "The item changed since the revision the write expected",
            )
            .with("itemId", json!(item.to_string()))
            .with("currentRevision", json!(current.map(|r| r.0))),
            AppError::Duplicate => Problem::new(
                StatusCode::CONFLICT,
                "already-exists",
                "That already exists",
            ),
            AppError::FullSyncRequired => Problem::new(
                StatusCode::GONE,
                "full-sync-required",
                "The cursor is too old: start a full sync without one",
            ),
            AppError::SlowDown { retry_after_secs } => rate_limited(retry_after_secs),
            AppError::Setup(e) => setup_problem(&e),
            AppError::Item(e) => item_problem(&e),
            AppError::Store(message) => {
                tracing::error!(%message, "the store failed");
                Problem::new(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "internal",
                    "Something went wrong on the server",
                )
            }
        }
    }
}

/// A 429 with `Retry-After`.
pub fn rate_limited(retry_after_secs: u64) -> Problem {
    Problem::new(
        StatusCode::TOO_MANY_REQUESTS,
        "rate-limited",
        "Too many tries: slow down",
    )
    .with("retryAfter", json!(retry_after_secs))
    .header(header::RETRY_AFTER, &retry_after_secs.to_string())
}

fn setup_problem(e: &SetupError) -> Problem {
    match e {
        SetupError::AlreadyDone => Problem::new(
            StatusCode::CONFLICT,
            "setup-complete",
            "Setup is finished or not open",
        ),
        SetupError::InsecureContext => Problem::new(
            StatusCode::FORBIDDEN,
            "insecure-context",
            "Setup needs HTTPS, or a browser on this machine",
        ),
        SetupError::WrongCode => Problem::new(
            StatusCode::FORBIDDEN,
            "setup-code-wrong",
            "The setup code is wrong",
        ),
        SetupError::SlowDown => rate_limited(1),
        SetupError::TwoStepRequired => Problem::new(
            StatusCode::CONFLICT,
            "two-step-required",
            "An admin must confirm a two-step method before setup can finish",
        ),
    }
}

fn item_problem(e: &ItemError) -> Problem {
    match e {
        ItemError::BadKind | ItemError::Malformed => Problem::new(
            StatusCode::BAD_REQUEST,
            "invalid-item",
            "The item is malformed",
        )
        .detail(e.to_string()),
        ItemError::Stale { current, .. } => Problem::new(
            StatusCode::CONFLICT,
            "stale-revision",
            "The item changed since the revision the write expected",
        )
        .with("currentRevision", json!(current.map(|r| r.0))),
        ItemError::BadRevision { .. } | ItemError::Immutable => Problem::new(
            StatusCode::UNPROCESSABLE_ENTITY,
            "invalid-revision",
            "The write breaks the item's revision or ownership rules",
        )
        .detail(e.to_string()),
        ItemError::Taken => Problem::new(
            StatusCode::CONFLICT,
            "already-exists",
            "That already exists",
        ),
        ItemError::Forbidden => Problem::new(
            StatusCode::FORBIDDEN,
            "forbidden",
            "Only the owner's members may write this item",
        ),
        ItemError::TooLarge => Problem::new(
            StatusCode::PAYLOAD_TOO_LARGE,
            "item-too-large",
            "The item is larger than this server allows",
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use kemlock_domain::{ItemId, Revision};

    #[test]
    fn a_stale_write_names_the_item_and_the_current_revision() {
        let item = ItemId::random();
        let problem = Problem::from(AppError::Conflict {
            item,
            current: Some(Revision(7)),
        });
        assert_eq!(problem.status, StatusCode::CONFLICT);
        let body = problem.to_json();
        assert_eq!(body["type"], "urn:kemlock:problem:stale-revision");
        assert_eq!(body["status"], 409);
        assert_eq!(body["currentRevision"], 7);
        assert_eq!(body["itemId"], item.to_string());
    }

    #[test]
    fn a_new_item_conflict_has_a_null_current_revision() {
        let problem = Problem::from(AppError::Conflict {
            item: ItemId::random(),
            current: None,
        });
        assert!(problem.to_json()["currentRevision"].is_null());
    }

    #[test]
    fn the_response_is_problem_json_with_its_headers() {
        let response = rate_limited(30).into_response();
        assert_eq!(response.status(), StatusCode::TOO_MANY_REQUESTS);
        assert_eq!(
            response.headers()[header::CONTENT_TYPE],
            "application/problem+json"
        );
        assert_eq!(response.headers()[header::RETRY_AFTER], "30");
    }

    #[test]
    fn an_overloaded_server_answers_503_with_a_retry_hint() {
        let response = Problem::overloaded().into_response();
        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(response.headers()[header::RETRY_AFTER], "30");
        assert_eq!(
            Problem::overloaded().to_json()["type"],
            "urn:kemlock:problem:overloaded"
        );
    }

    #[test]
    fn store_failures_never_leak_their_message() {
        let problem = Problem::from(AppError::Store("password=hunter2".to_owned()));
        assert_eq!(problem.status, StatusCode::INTERNAL_SERVER_ERROR);
        assert!(!problem.to_json().to_string().contains("hunter2"));
    }

    #[test]
    fn statuses_follow_the_error() {
        let status = |e: AppError| Problem::from(e).status;
        assert_eq!(status(AppError::Unauthorized), StatusCode::UNAUTHORIZED);
        assert_eq!(status(AppError::FullSyncRequired), StatusCode::GONE);
        assert_eq!(status(AppError::Forbidden), StatusCode::FORBIDDEN);
        let deleting = Problem::from(AppError::AccountBeingDeleted);
        assert_eq!(deleting.status, StatusCode::FORBIDDEN);
        assert_eq!(
            deleting.to_json()["type"],
            "urn:kemlock:problem:account-being-deleted"
        );
        let disabled = Problem::from(AppError::AccountDisabled);
        assert_eq!(disabled.status, StatusCode::FORBIDDEN);
        assert_eq!(
            disabled.to_json()["type"],
            "urn:kemlock:problem:account-disabled"
        );
        let unconfirmed = Problem::from(AppError::EmailNotConfirmed);
        assert_eq!(unconfirmed.status, StatusCode::FORBIDDEN);
        assert_eq!(
            unconfirmed.to_json()["type"],
            "urn:kemlock:problem:email-not-confirmed"
        );
        let required = Problem::from(AppError::SsoRequired {
            space: kemlock_domain::SpaceId::random(),
        });
        assert_eq!(required.status, StatusCode::FORBIDDEN);
        assert_eq!(
            required.to_json()["type"],
            "urn:kemlock:problem:sso-required"
        );
        assert_eq!(
            status(AppError::Item(ItemError::TooLarge)),
            StatusCode::PAYLOAD_TOO_LARGE
        );
        assert_eq!(
            status(AppError::Setup(SetupError::WrongCode)),
            StatusCode::FORBIDDEN
        );
    }
}
