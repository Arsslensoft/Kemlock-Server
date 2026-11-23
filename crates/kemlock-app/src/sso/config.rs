//! Settings the SSO use cases read, and the rules for the values clients hand them.

use crate::b64url;
use time::Duration;

/// The redirect the Kemlock apps use: the system browser sheet ends at `kemlock://sso`.
pub const APP_REDIRECT: &str = "kemlock://sso";

/// The path of the server's callback, which the provider redirects the browser to.
pub const CALLBACK_PATH: &str = "/kem/v1/auth/sso/callback";

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SsoConfig {
    /// `DOMAIN`: the address clients use, without a trailing slash.
    pub domain: String,
    /// How long a sign-in may take at the provider, from `start` to the callback.
    pub state_ttl: Duration,
    /// How long the one-time code lives, from the callback to `finish`.
    pub code_ttl: Duration,
}

impl SsoConfig {
    pub fn new(domain: &str) -> Self {
        SsoConfig {
            domain: domain.trim_end_matches('/').to_owned(),
            state_ttl: Duration::minutes(10),
            code_ttl: Duration::minutes(2),
        }
    }

    /// The address the provider sends the browser back to.
    pub fn callback_url(&self) -> String {
        format!("{}{CALLBACK_PATH}", self.domain)
    }

    /// Whether the server may end the browser's trip at `redirect`: the Kemlock apps' own
    /// `kemlock://sso`, or a path on this server's own address (the web vault). Nothing else, so
    /// a code can't be sent to a site the attacker chose.
    pub fn redirect_allowed(&self, redirect: &str) -> bool {
        if redirect.len() > 512
            || redirect
                .chars()
                .any(|c| c.is_whitespace() || c.is_control() || c == '#' || c == '\\')
        {
            return false;
        }
        if redirect == APP_REDIRECT {
            return true;
        }
        redirect
            .strip_prefix(self.domain.as_str())
            .is_some_and(|rest| rest.starts_with('/') && !rest.starts_with("//"))
    }
}

/// An RFC 3986 "unreserved" character, which needs no percent-encoding in a URL.
fn unreserved(c: char) -> bool {
    c.is_ascii_alphanumeric() || matches!(c, '-' | '.' | '_' | '~')
}

/// The phone's PKCE challenge: the unpadded base64url of a SHA-256, so 32 bytes.
pub fn valid_challenge(challenge: &str) -> bool {
    b64url::decode(challenge).is_some_and(|bytes| bytes.len() == 32)
}

/// A PKCE verifier (RFC 7636, section 4.1): 43 to 128 unreserved characters.
pub fn valid_verifier(verifier: &str) -> bool {
    (43..=128).contains(&verifier.len()) && verifier.chars().all(unreserved)
}

/// The phone's own `state`: 16 to 256 unreserved characters, so it goes into a URL unchanged.
pub fn valid_app_state(state: &str) -> bool {
    (16..=256).contains(&state.len()) && state.chars().all(unreserved)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config() -> SsoConfig {
        SsoConfig::new("https://vault.example.org/")
    }

    #[test]
    fn the_callback_is_under_the_domain() {
        assert_eq!(
            config().callback_url(),
            "https://vault.example.org/kem/v1/auth/sso/callback"
        );
    }

    #[test]
    fn the_app_scheme_and_own_paths_are_allowed() {
        let c = config();
        assert!(c.redirect_allowed("kemlock://sso"));
        assert!(c.redirect_allowed("https://vault.example.org/sso-done"));
        assert!(c.redirect_allowed("https://vault.example.org/a/b?x=1"));
    }

    #[test]
    fn other_places_are_refused() {
        let c = config();
        for bad in [
            "",
            "https://evil.example/",
            "https://vault.example.org.evil.example/x",
            "https://vault.example.org",
            "https://vault.example.org//evil.example",
            "https://vault.example.org/x#frag",
            "https://vault.example.org/x y",
            "https://vault.example.org\\@evil.example",
            "kemlock://sso/extra",
            "kemlock://other",
            "javascript:alert(1)",
        ] {
            assert!(!c.redirect_allowed(bad), "{bad:?}");
        }
    }

    #[test]
    fn challenges_are_32_byte_base64url() {
        assert!(valid_challenge(&b64url::encode(&[1u8; 32])));
        assert!(!valid_challenge(&b64url::encode(&[1u8; 31])));
        assert!(!valid_challenge("not base64!"));
        assert!(!valid_challenge(""));
    }

    #[test]
    fn verifiers_and_states_are_checked_for_length_and_alphabet() {
        assert!(valid_verifier(&"a".repeat(43)));
        assert!(valid_verifier(&"a".repeat(128)));
        assert!(!valid_verifier(&"a".repeat(42)));
        assert!(!valid_verifier(&"a".repeat(129)));
        assert!(!valid_verifier(&format!("{}+", "a".repeat(43))));
        assert!(valid_app_state(&"S".repeat(16)));
        assert!(!valid_app_state(&"S".repeat(15)));
        assert!(!valid_app_state(&format!("{}&", "S".repeat(20))));
    }
}
