//! The provider's redirect back to the server. The callback doesn't sign anyone in: it checks the
//! sealed `state` is ours and fresh, then ends the browser's trip at the app's redirect with a
//! one-time code. Taking the code is useless without the phone's PKCE verifier and DPoP key, which
//! `finish` checks, so another app that claimed the `kemlock` scheme gets nothing.

use crate::ports::{Clock, SecretSeal};
use crate::sso::config::SsoConfig;
use crate::sso::error::SsoError;
use crate::sso::state::{PURPOSE_CODE, PURPOSE_STATE, SsoCode, SsoState, open_value, seal_value};
use kemlock_domain::DeviceKind;

#[derive(Debug)]
pub struct SsoCallback<S, E> {
    pub seal: S,
    pub env: E,
    pub config: SsoConfig,
}

/// The query parameters the provider sent back.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CallbackInput {
    /// The sealed state `start` sent to the provider.
    pub state: String,
    pub code: Option<String>,
    /// The OAuth error code, when the person declined or the provider refused.
    pub error: Option<String>,
}

/// The OAuth error codes (RFC 6749 section 4.1.2.1, OpenID Connect Core section 3.1.2.6) passed
/// on to the app; anything else becomes `server_error`.
const PASSED_ERRORS: [&str; 8] = [
    "access_denied",
    "login_required",
    "interaction_required",
    "consent_required",
    "account_selection_required",
    "invalid_request",
    "temporarily_unavailable",
    "server_error",
];

impl<S: SecretSeal, E: Clock> SsoCallback<S, E> {
    /// The address to redirect the browser to: the app's redirect with `code` and `state`, or
    /// with `error` and `state` when the provider reported a failure. `BadState` when the
    /// sealed state isn't ours or has expired, in which case there is nowhere safe to redirect.
    pub fn execute(&self, input: CallbackInput) -> Result<String, SsoError> {
        let state: SsoState =
            open_value(&self.seal, PURPOSE_STATE, &input.state).ok_or(SsoError::BadState)?;
        let now = self.env.now();
        if now.unix_timestamp() >= state.expires_at {
            return Err(SsoError::BadState);
        }
        // The redirect was checked at `start`, and sealing keeps it from being swapped; check
        // again anyway, since it is where a code is sent.
        let kind = if state.browser {
            DeviceKind::KemlockBrowser
        } else {
            DeviceKind::Other
        };
        if !self.config.redirect_allowed_for(&state.redirect, kind) {
            return Err(SsoError::BadState);
        }

        let query = if let Some(error) = input.error {
            let code = if PASSED_ERRORS.contains(&error.as_str()) {
                error.as_str()
            } else {
                "server_error"
            };
            format!("error={code}&state={}", state.app_state)
        } else {
            let provider_code = input
                .code
                .filter(|c| !c.is_empty() && c.len() <= 2048)
                .ok_or(SsoError::Invalid("the provider sent no code"))?;
            let code = SsoCode {
                expires_at: (now + self.config.code_ttl).unix_timestamp(),
                provider_code,
                provider_verifier: state.provider_verifier,
                nonce: state.nonce,
                app_challenge: state.app_challenge,
                jkt: state.jkt,
                browser: state.browser,
            };
            format!(
                "code={}&state={}",
                seal_value(&self.seal, PURPOSE_CODE, &code),
                state.app_state
            )
        };
        let separator = if state.redirect.contains('?') {
            '&'
        } else {
            '?'
        };
        Ok(format!("{}{separator}{query}", state.redirect))
    }
}
