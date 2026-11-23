//! The two values the SSO flow hands out sealed instead of keeping state: the `state` sent to the
//! provider (everything the callback needs) and the one-time code sent to the app (everything
//! `finish` needs). Each is JSON sealed under `server.key` with its own purpose, so a value for
//! one never opens as the other, and carries its own expiry.

use crate::b64url;
use crate::ports::SecretSeal;
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};

/// `SecretSeal` purpose of the state sent to the provider.
pub const PURPOSE_STATE: &str = "sso-state";
/// `SecretSeal` purpose of the one-time code sent to the app.
pub const PURPOSE_CODE: &str = "sso-code";

/// The longest sealed value read back, so a hostile `state` costs nothing.
const MAX_SEALED_TEXT: usize = 4096;

/// What the callback needs, from `start`: the provider-side PKCE verifier and nonce, and what
/// binds the sign-in to the phone that began it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct SsoState {
    pub(crate) expires_at: i64,
    pub(crate) nonce: String,
    /// The server's PKCE verifier for the provider.
    pub(crate) provider_verifier: String,
    /// The phone's PKCE challenge: the S256 of a verifier only the phone holds.
    pub(crate) app_challenge: String,
    /// The phone's own `state`, handed back on the redirect.
    pub(crate) app_state: String,
    /// Where the browser trip ends.
    pub(crate) redirect: String,
    /// The thumbprint of the DPoP key that signed `start`.
    pub(crate) jkt: String,
    /// `start` said the device is the Kemlock browser extension: its redirect may be an
    /// extension's, and `finish` must see that kind of device.
    #[serde(default)]
    pub(crate) browser: bool,
}

/// What `finish` needs, from the callback.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct SsoCode {
    pub(crate) expires_at: i64,
    /// The provider's authorization code. Single use at the provider, which makes this code
    /// single use too.
    pub(crate) provider_code: String,
    pub(crate) provider_verifier: String,
    pub(crate) nonce: String,
    pub(crate) app_challenge: String,
    pub(crate) jkt: String,
    /// Carried from `SsoState::browser`.
    #[serde(default)]
    pub(crate) browser: bool,
}

/// Seals `value` and encodes it as unpadded base64url, for a URL.
pub(crate) fn seal_value<T: Serialize, S: SecretSeal>(
    seal: &S,
    purpose: &str,
    value: &T,
) -> String {
    // These structs only hold strings and integers; serialising them can't fail.
    let json = serde_json::to_vec(value).unwrap_or_default();
    b64url::encode(&seal.seal(purpose, &json))
}

/// The reverse of [`seal_value`]; `None` for anything that isn't a value this server sealed for
/// `purpose`.
pub(crate) fn open_value<T: DeserializeOwned, S: SecretSeal>(
    seal: &S,
    purpose: &str,
    text: &str,
) -> Option<T> {
    if text.len() > MAX_SEALED_TEXT {
        return None;
    }
    let sealed = b64url::decode(text)?;
    let json = seal.open(purpose, &sealed).ok()?;
    serde_json::from_slice(&json).ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ports::CryptoError;

    struct Seal;

    impl SecretSeal for Seal {
        fn seal(&self, purpose: &str, value: &[u8]) -> Vec<u8> {
            let mut out = purpose.as_bytes().to_vec();
            out.push(0);
            out.extend_from_slice(value);
            out
        }

        fn open(
            &self,
            purpose: &str,
            sealed: &[u8],
        ) -> Result<crate::ports::Zeroizing<Vec<u8>>, CryptoError> {
            let mut prefix = purpose.as_bytes().to_vec();
            prefix.push(0);
            sealed
                .strip_prefix(prefix.as_slice())
                .map(|rest| crate::ports::Zeroizing::new(rest.to_vec()))
                .ok_or(CryptoError::Invalid)
        }
    }

    fn state() -> SsoState {
        SsoState {
            expires_at: 1_800_000_000,
            nonce: "n".into(),
            provider_verifier: "v".into(),
            app_challenge: "c".into(),
            app_state: "s".into(),
            redirect: "kemlock://sso".into(),
            jkt: "j".into(),
            browser: false,
        }
    }

    #[test]
    fn a_value_round_trips_for_its_purpose_only() {
        let text = seal_value(&Seal, PURPOSE_STATE, &state());
        assert_eq!(
            open_value::<SsoState, _>(&Seal, PURPOSE_STATE, &text),
            Some(state())
        );
        assert_eq!(open_value::<SsoState, _>(&Seal, PURPOSE_CODE, &text), None);
    }

    #[test]
    fn garbage_and_oversized_text_are_refused() {
        assert_eq!(
            open_value::<SsoState, _>(&Seal, PURPOSE_STATE, "not base64!"),
            None
        );
        assert_eq!(open_value::<SsoState, _>(&Seal, PURPOSE_STATE, ""), None);
        let big = "A".repeat(MAX_SEALED_TEXT + 4);
        assert_eq!(open_value::<SsoState, _>(&Seal, PURPOSE_STATE, &big), None);
    }

    #[test]
    fn a_state_isnt_a_code() {
        let text = seal_value(&Seal, PURPOSE_STATE, &state());
        // Same purpose by mistake: the fields differ, so it still doesn't parse as a code.
        assert_eq!(open_value::<SsoCode, _>(&Seal, PURPOSE_STATE, &text), None);
    }
}
