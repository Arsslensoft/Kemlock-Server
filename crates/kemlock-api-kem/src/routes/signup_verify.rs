//! Confirming the address of a new account (the "verify the email of a new account" setting):
//!
//! ```text
//! GET  /kem/v1/accounts/confirm-email?token=...   the link in the mail: a small page with a
//!                                                 Confirm button; it changes nothing
//! POST /kem/v1/accounts/confirm-email             the button: token=... as a form; confirms the
//!                                                 address and says so
//! POST /kem/v1/accounts/confirm-email/resend      {email}: mails a new link; 202 whatever the
//!                                                 address is, so it says nothing about who has
//!                                                 an account
//! ```
//!
//! None needs a session: the link is opened from the mail client, often in another browser, and
//! the account it is for can't sign in until it has been. Opening the link only shows the button,
//! because mail scanners and link previews fetch every link in a mail (GET and HEAD) and would
//! spend the token before its owner read the mail; only the POST spends it.

use super::guard;
use crate::dto::EmailRequest;
use crate::extract::{Body, ClientIp};
use crate::problem::Problem;
use crate::ratelimit::ip_key;
use crate::state::{Api, Crypto, Store};
use axum::extract::rejection::{FormRejection, QueryRejection};
use axum::extract::{Form, Query, State};
use axum::http::{HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};
use kemlock_app::ports::TokenSigner;
use kemlock_app::signup_verify::SignupVerify;
use kemlock_domain::Email;
use serde::Deserialize;

/// The policy of a page that only tells: nothing is loaded and nothing runs.
const PAGE_CSP: &str =
    "default-src 'none'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'";
/// The policy of the page with the button: its form may post back to this server and nowhere else.
const FORM_CSP: &str =
    "default-src 'none'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'";

#[derive(Debug, Deserialize)]
pub(crate) struct ConfirmQuery {
    token: String,
}

/// The form the button posts.
#[derive(Debug, Deserialize)]
pub(crate) struct ConfirmForm {
    token: String,
}

/// Whether `token` could be one of ours: base64url, so it can go in an attribute as it is.
fn token_shaped(token: &str) -> bool {
    !token.is_empty()
        && token.len() <= 64
        && token
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
}

fn page(status: StatusCode, title: &str, text: &str) -> Response {
    html(status, title, text, "", PAGE_CSP)
}

/// A page with `extra` (trusted markup) after the text, under the policy `csp`.
fn html(status: StatusCode, title: &str, text: &str, extra: &str, csp: &'static str) -> Response {
    let body = format!(
        "<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\">\
         <meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">\
         <meta name=\"color-scheme\" content=\"light dark\"><title>{title}</title></head>\
         <body><main><h1>{title}</h1><p>{text}</p>{extra}</main></body></html>"
    );
    let mut response = (status, body).into_response();
    let headers = response.headers_mut();
    headers.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("text/html; charset=utf-8"),
    );
    headers.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    headers.insert(
        header::CONTENT_SECURITY_POLICY,
        HeaderValue::from_static(csp),
    );
    headers.insert(
        header::X_CONTENT_TYPE_OPTIONS,
        HeaderValue::from_static("nosniff"),
    );
    // The token is in the address of this page: nothing it loads or links to may be told.
    headers.insert(
        header::REFERRER_POLICY,
        HeaderValue::from_static("no-referrer"),
    );
    headers.insert(header::X_FRAME_OPTIONS, HeaderValue::from_static("DENY"));
    response
}

/// The page for a link that is unknown, spent or out of time.
fn invalid_link() -> Response {
    page(
        StatusCode::BAD_REQUEST,
        "This link isn't valid",
        "It was opened already or has run out. Ask for a new one from the sign-in screen.",
    )
}

impl<S: Store, P: Crypto, K: TokenSigner + Clone + 'static> Api<S, P, K> {
    pub(crate) fn signup_verify(&self) -> SignupVerify<S, P> {
        SignupVerify {
            users: self.store.clone(),
            env: self.crypto.clone(),
            notices: self.hub.notices(),
        }
    }

    /// `GET /kem/v1/accounts/confirm-email`: the page the link in the mail opens. It shows a
    /// Confirm button and changes nothing, so a mail scanner or link preview that fetches the link
    /// can't spend it.
    pub(crate) async fn handle_confirm_signup_page(
        State(api): State<Self>,
        ClientIp(ip): ClientIp,
        query: Result<Query<ConfirmQuery>, QueryRejection>,
    ) -> Result<Response, Problem> {
        guard(
            &api.limits.sign_in,
            &format!("confirm-signup:{}", ip_key(ip)),
            api.now(),
        )?;
        let Ok(Query(query)) = query else {
            return Ok(invalid_link());
        };
        if !token_shaped(&query.token) {
            return Ok(invalid_link());
        }
        let form = format!(
            "<form method=\"post\" action=\"/kem/v1/accounts/confirm-email\">\
             <input type=\"hidden\" name=\"token\" value=\"{}\">\
             <button type=\"submit\">Confirm my address</button></form>",
            query.token
        );
        Ok(html(
            StatusCode::OK,
            "Confirm your address",
            "Press the button to confirm that this is your address and finish making your account.",
            &form,
            FORM_CSP,
        ))
    }

    /// `POST /kem/v1/accounts/confirm-email`: the button. Spends the link and confirms the
    /// address. Rate limited per IP: the token is 32 random bytes, but nothing else should be able
    /// to try them quickly.
    pub(crate) async fn handle_confirm_signup_email(
        State(api): State<Self>,
        ClientIp(ip): ClientIp,
        form: Result<Form<ConfirmForm>, FormRejection>,
    ) -> Result<Response, Problem> {
        guard(
            &api.limits.sign_in,
            &format!("confirm-signup:{}", ip_key(ip)),
            api.now(),
        )?;
        let Ok(Form(form)) = form else {
            return Ok(invalid_link());
        };
        Ok(match api.signup_verify().confirm(&form.token).await {
            Ok(_) => page(
                StatusCode::OK,
                "Your address is confirmed",
                "You can sign in to your account now.",
            ),
            Err(kemlock_app::AppError::Invalid(_)) => invalid_link(),
            Err(other) => return Err(other.into()),
        })
    }

    /// `POST /kem/v1/accounts/confirm-email/resend`: a new link for an account that is held. The
    /// answer is the same for every address; a link is mailed only when one is due.
    pub(crate) async fn handle_resend_signup_email(
        State(api): State<Self>,
        ClientIp(ip): ClientIp,
        body: Body,
    ) -> Result<StatusCode, Problem> {
        let now = api.now();
        guard(
            &api.limits.sign_in,
            &format!("resend-signup:{}", ip_key(ip)),
            now,
        )?;
        let request: EmailRequest = body.json()?;
        if request.email.len() > Email::MAX_LEN {
            return Err(Problem::bad_request("the email is too long"));
        }
        if let Ok(email) = Email::parse(&request.email) {
            // A failure is the server's to log; the answer must not differ.
            if let Err(error) = api.signup_verify().resend(&email).await {
                tracing::warn!(%error, "couldn't send a new link to confirm an address");
            }
        }
        Ok(StatusCode::ACCEPTED)
    }
}
