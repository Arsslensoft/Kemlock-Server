//! `sso_start`: the first step of an SSO sign-in. A device asks for the provider's address; the
//! server answers with an authorization URL whose `state` carries, sealed, everything the callback
//! needs, bound to the device's DPoP key and to the PKCE challenge the device made.
//!
//! The server holds no sign-in state: the sealed `state` goes to the provider and comes back on
//! the callback (design, `sso/start` and `sso/finish`, "SSO through the system browser sheet").

use crate::b64url;
use crate::platform::Platform;
use crate::ports::SecretSeal;
use crate::sso::config::{SsoConfig, valid_app_state, valid_challenge};
use crate::sso::error::SsoError;
use crate::sso::model::AuthorizationRequest;
use crate::sso::ports::{OidcProvider, SsoSettingsRepo};
use crate::sso::state::{PURPOSE_STATE, SsoState, seal_value};

#[derive(Debug)]
pub struct SsoStart<R, O, S, E> {
    pub repos: R,
    pub provider: O,
    pub seal: S,
    pub env: E,
    pub config: SsoConfig,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StartInput {
    /// The phone's PKCE challenge: the unpadded base64url of the SHA-256 of a verifier it keeps.
    pub challenge: String,
    /// The phone's own `state`, handed back on the redirect so it can tell its own sign-in.
    pub app_state: String,
    /// Where the browser trip ends: `kemlock://sso`, or a path on this server.
    pub redirect: String,
    /// The thumbprint of the DPoP key that signed the request. `finish` must be signed by it.
    pub jkt: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Started {
    /// Where to open the system browser.
    pub authorization_url: String,
    /// The provider's name, for the sign-in sheet.
    pub provider_name: String,
}

impl<R: SsoSettingsRepo, O: OidcProvider, S: SecretSeal, E: Platform> SsoStart<R, O, S, E> {
    pub async fn execute(&self, input: StartInput) -> Result<Started, SsoError> {
        if !valid_challenge(&input.challenge) {
            return Err(SsoError::Invalid("challenge must be a base64url SHA-256"));
        }
        if !valid_app_state(&input.app_state) {
            return Err(SsoError::Invalid(
                "state must be 16 to 256 URL-safe characters",
            ));
        }
        if !self.config.redirect_allowed(&input.redirect) {
            return Err(SsoError::Invalid("the redirect isn't allowed"));
        }
        let settings = self
            .repos
            .sso_settings()
            .await?
            .filter(|s| s.enabled)
            .ok_or(SsoError::NotConfigured)?;
        let client = settings.client_config(&self.seal)?;

        let nonce = b64url::encode(&self.env.bytes::<24>());
        let code_verifier = b64url::encode(&self.env.bytes::<32>());
        let expires_at = (self.env.now() + self.config.state_ttl).unix_timestamp();
        let state = seal_value(
            &self.seal,
            PURPOSE_STATE,
            &SsoState {
                expires_at,
                nonce: nonce.clone(),
                provider_verifier: code_verifier.clone(),
                app_challenge: input.challenge,
                app_state: input.app_state,
                redirect: input.redirect,
                jkt: input.jkt,
            },
        );
        let authorization_url = self
            .provider
            .authorization_url(
                &client,
                &AuthorizationRequest {
                    state,
                    nonce,
                    code_verifier,
                    redirect_uri: self.config.callback_url(),
                },
            )
            .await?;
        Ok(Started {
            authorization_url,
            provider_name: settings.display_name,
        })
    }
}
