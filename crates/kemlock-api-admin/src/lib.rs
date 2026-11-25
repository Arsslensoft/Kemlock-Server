//! The admin console's API, `/admin/v1`: an axum router over the admin use cases of
//! `kemlock-app`.
//!
//! Who may call. Every route but the OpenAPI document needs an admin: an account with the admin
//! role and a confirmed two-step method, signed in on a device with a DPoP-bound access token
//! (the same tokens `/kem/v1` issues). Anyone else gets 403. Every write also needs a step-up
//! token, which the admin gets by running their password login again
//! (`/admin/v1/step-up/password/start` and `/finish`), with a code from their authenticator app
//! (`/admin/v1/step-up/totp`) or with a fresh passkey or security-key assertion
//! (`/admin/v1/step-up/passkey/options` and `/finish`), and sends in the `Step-Up-Token` header.
//! It lasts five minutes and is bound to the account and the device. A write without a fresh one
//! is refused with 403 and the problem type `step-up-required`.
//!
//! What it does. Overview counts; users (list, invite, resend, revoke, sign out, disable,
//! enable, reset two-step, delete); spaces (list, change owner to a confirmed member); the event
//! log (filters, pages, CSV, addresses cut to /24 or /48); typed settings (SMTP, sign-ups, file
//! limits, trash days, retention, rate limits) with secrets sealed and environment-set values
//! read-only; the SSO provider and its domains; the Vaultwarden move (a POST starts it in the
//! background and a GET shows its progress and result); the privacy requests queue; and Kemlock's
//! push relay (show where it stands, turn it on or off). Every write goes to the event log and is
//! mailed to the other admins.
//!
//! The router is generic over the ports, so tests run it in-process with
//! `tower::ServiceExt::oneshot` against in-memory fakes. Errors leave as RFC 9457
//! `application/problem+json`; the document is at `/admin/v1/openapi.json`.

#![allow(clippy::result_large_err)]

pub mod dto;
pub mod error;
mod extract;
mod migrate;
pub mod openapi;
mod routes;
mod state;

pub use error::ApiError;
pub use extract::STEP_UP_HEADER;
pub use openapi::openapi as admin_openapi;
pub use routes::admin_router;
pub use state::{AdminRuntime, SettingsSaved};
