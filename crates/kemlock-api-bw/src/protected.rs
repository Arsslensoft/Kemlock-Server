//! Protected actions, as Vaultwarden 1.37.5's `protected_actions.rs` and `PasswordOrOtpData` have
//! them.
//!
//! - `POST /api/accounts/request-otp` mails a one-time code to the account's address (through the
//!   mailer, so only on a server that can mail), at most one every 30 seconds.
//! - `POST /api/accounts/verify-otp` checks the code and uses it up (the web vault calls it before
//!   an export).
//! - [`validate`] is what every call that takes `masterPasswordHash` or `otp` runs: the password,
//!   or the code. The code expires with the emailed second-step codes and survives their number of
//!   wrong entries. The setup calls that hand out a `userVerificationToken` leave the code to be
//!   used again; the calls that act (the API key, deleting an organization, showing the recovery
//!   code) use it up.

use crate::account::check_valid_password;
use crate::app::{App, Authed, BwStore};
use crate::error::{BwError, BwResult};
use crate::routes::{EmptyResult, empty, parse};
use axum::Router;
use axum::body::Bytes;
use axum::extract::State;
use axum::routing::post;
use kemlock_app::two_step::ProtectedError;
use serde::Deserialize;

/// What Vaultwarden says to a request for a code on a server that can't mail.
const MAIL_DISABLED: &str = "Email is disabled for this server. Either enable email or login using your master password instead of login via device.";

/// What a code's refusal is to a Bitwarden client, in Vaultwarden's words.
pub(crate) fn failed(e: ProtectedError) -> BwError {
    match e {
        ProtectedError::Disabled => BwError::msg(MAIL_DISABLED),
        ProtectedError::Wait(seconds) => BwError::msg(format!(
            "Please wait {seconds} seconds before requesting another code."
        )),
        ProtectedError::NotFound => BwError::msg(
            "Protected action token not found, try sending the code again or restart the process",
        ),
        ProtectedError::Expired => BwError::msg("Token has expired"),
        ProtectedError::Invalid => BwError::msg("Token is invalid"),
        ProtectedError::App(e) => crate::two_step::failed(e),
    }
}

/// `PasswordOrOtpData::validate`: exactly one of the master password hash and a one-time code.
/// `delete_if_valid` says whether a right code is used up.
pub(crate) async fn validate<S: BwStore>(
    app: &App<S>,
    authed: &Authed,
    master_password_hash: Option<&str>,
    otp: Option<&str>,
    delete_if_valid: bool,
) -> BwResult<()> {
    match (master_password_hash, otp) {
        (Some(hash), None) => {
            if check_valid_password(&authed.account, hash) {
                Ok(())
            } else {
                Err(BwError::msg("Invalid password"))
            }
        }
        (None, Some(otp)) => crate::two_step::steps(app)
            .protected_validate(authed.user.id, otp, delete_if_valid)
            .await
            .map_err(failed),
        _ => Err(BwError::msg("No validation provided")),
    }
}

/// `POST /api/accounts/request-otp`.
async fn request_otp<S: BwStore>(State(app): State<App<S>>, authed: Authed) -> EmptyResult {
    empty(
        crate::two_step::steps(&app)
            .protected_request(&authed.user)
            .await
            .map_err(failed),
    )
}

#[derive(Deserialize)]
struct VerifyData {
    #[serde(rename = "OTP", alias = "otp")]
    otp: String,
}

/// `POST /api/accounts/verify-otp`: checks the code once and uses it up.
async fn verify_otp<S: BwStore>(
    State(app): State<App<S>>,
    authed: Authed,
    body: Bytes,
) -> EmptyResult {
    let data: VerifyData = parse(&body)?;
    empty(
        crate::two_step::steps(&app)
            .protected_validate(authed.user.id, &data.otp, true)
            .await
            .map_err(failed),
    )
}

/// The routes of this module, merged into the Bitwarden router.
pub(crate) fn routes<S: BwStore>() -> Router<App<S>> {
    Router::new()
        .route("/api/accounts/request-otp", post(request_otp::<S>))
        .route("/api/accounts/verify-otp", post(verify_otp::<S>))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn refusals_are_vaultwardens_messages() {
        assert_eq!(
            failed(ProtectedError::Wait(18)),
            BwError::msg("Please wait 18 seconds before requesting another code.")
        );
        assert_eq!(
            failed(ProtectedError::Expired),
            BwError::msg("Token has expired")
        );
        assert_eq!(
            failed(ProtectedError::Invalid),
            BwError::msg("Token is invalid")
        );
        assert_eq!(
            failed(ProtectedError::NotFound),
            BwError::msg(
                "Protected action token not found, try sending the code again or restart the process"
            )
        );
        assert!(matches!(
            failed(ProtectedError::Disabled),
            BwError::Msg(m) if m.starts_with("Email is disabled for this server.")
        ));
    }
}
