//! Settings the SSO use cases read, and the rules for the values clients hand them.

use crate::b64url;
use kemlock_domain::DeviceKind;
use time::Duration;

/// The redirect the Kemlock apps use: the system browser sheet ends at `kemlock://sso`.
pub const APP_REDIRECT: &str = "kemlock://sso";

/// The paths of an extension's redirect address that the server will end a browser trip at: the
/// address `identity.getRedirectURL()` gives, and the one it gives for `"sso"`.
const BROWSER_REDIRECT_PATHS: [&str; 2] = ["/", "/sso"];

/// What follows the extension's id in the address Chrome and Edge give it.
const CHROMIUM_REDIRECT_HOST: &str = ".chromiumapp.org";

/// What follows the extension's hash in the address Firefox gives it.
const FIREFOX_REDIRECT_HOST: &str = ".extensions.allizom.org";

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
    /// `KEMLOCK_BROWSER_EXTENSION_IDS`: the ids of the Kemlock browser extensions whose redirect
    /// addresses a `KemlockBrowser` device may use, lower case. Empty: none may.
    pub browser_extension_ids: Vec<String>,
}

impl SsoConfig {
    pub fn new(domain: &str) -> Self {
        SsoConfig {
            domain: domain.trim_end_matches('/').to_owned(),
            state_ttl: Duration::minutes(10),
            code_ttl: Duration::minutes(2),
            browser_extension_ids: Vec::new(),
        }
    }

    /// The same, allowing the redirect addresses of these browser extensions to `KemlockBrowser`
    /// devices.
    pub fn with_browser_extensions(mut self, ids: &[String]) -> Self {
        self.browser_extension_ids = ids.iter().map(|id| id.trim().to_ascii_lowercase()).collect();
        self
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

impl SsoConfig {
    /// [`redirect_allowed`](Self::redirect_allowed) for the device that asks: a `KemlockBrowser`
    /// device may also end the trip at the redirect address of an extension on the allowlist,
    /// `https://<id>.chromiumapp.org/` or Firefox's `https://<hash>.extensions.allizom.org/`,
    /// with the path `/` or `/sso`. The id must be one the admin configured: any other
    /// extension, and any other kind of device, gets nothing, so a code can't reach an extension
    /// the admin didn't name.
    pub fn redirect_allowed_for(&self, redirect: &str, kind: DeviceKind) -> bool {
        self.redirect_allowed(redirect)
            || (kind == DeviceKind::KemlockBrowser && self.extension_redirect_allowed(redirect))
    }

    fn extension_redirect_allowed(&self, redirect: &str) -> bool {
        if redirect.len() > 512
            || redirect
                .chars()
                .any(|c| c.is_whitespace() || c.is_control() || c == '#' || c == '\\')
        {
            return false;
        }
        let Some(rest) = redirect.strip_prefix("https://") else {
            return false;
        };
        let Some((host, path)) = rest.split_once('/') else {
            return false;
        };
        let path = format!("/{path}");
        if !BROWSER_REDIRECT_PATHS.contains(&path.as_str()) {
            return false;
        }
        let id = host
            .strip_suffix(CHROMIUM_REDIRECT_HOST)
            .or_else(|| host.strip_suffix(FIREFOX_REDIRECT_HOST));
        id.is_some_and(|id| {
            !id.is_empty() && self.browser_extension_ids.iter().any(|allowed| allowed == id)
        })
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

    const CHROME_ID: &str = "abcdefghijklmnopabcdefghijklmnop";
    const FIREFOX_HASH: &str = "0123456789abcdef0123456789abcdef01234567";

    fn with_extensions() -> SsoConfig {
        config().with_browser_extensions(&[CHROME_ID.to_owned(), FIREFOX_HASH.to_owned()])
    }

    #[test]
    fn a_browser_device_may_use_the_redirect_of_an_extension_on_the_list() {
        let c = with_extensions();
        for ok in [
            format!("https://{CHROME_ID}.chromiumapp.org/"),
            format!("https://{CHROME_ID}.chromiumapp.org/sso"),
            format!("https://{FIREFOX_HASH}.extensions.allizom.org/"),
            format!("https://{FIREFOX_HASH}.extensions.allizom.org/sso"),
        ] {
            assert!(c.redirect_allowed_for(&ok, DeviceKind::KemlockBrowser), "{ok}");
        }
        // What every device may do, a browser device may too.
        assert!(c.redirect_allowed_for("kemlock://sso", DeviceKind::KemlockBrowser));
        assert!(c.redirect_allowed_for(
            "https://vault.example.org/sso-done",
            DeviceKind::KemlockBrowser
        ));
    }

    #[test]
    fn no_extension_is_allowed_until_the_admin_names_it() {
        let nobody = config();
        let other =
            config().with_browser_extensions(&["ponmlkjihgfedcbaponmlkjihgfedcba".to_owned()]);
        let address = format!("https://{CHROME_ID}.chromiumapp.org/");
        assert!(!nobody.redirect_allowed_for(&address, DeviceKind::KemlockBrowser));
        assert!(!other.redirect_allowed_for(&address, DeviceKind::KemlockBrowser));
        // An id is matched whole: a longer or shorter one is another extension.
        let c = with_extensions();
        for id in [CHROME_ID[1..].to_owned(), format!("{CHROME_ID}a")] {
            let address = format!("https://{id}.chromiumapp.org/");
            assert!(
                !c.redirect_allowed_for(&address, DeviceKind::KemlockBrowser),
                "{id}"
            );
        }
        // A blank entry in the list matches no address.
        let blank = config().with_browser_extensions(&[String::new()]);
        assert!(!blank.redirect_allowed_for("https://.chromiumapp.org/", DeviceKind::KemlockBrowser));
    }

    #[test]
    fn only_a_browser_device_may_use_an_extensions_redirect() {
        let c = with_extensions();
        let address = format!("https://{CHROME_ID}.chromiumapp.org/");
        for kind in [
            DeviceKind::KemlockAndroid,
            DeviceKind::KemlockIos,
            DeviceKind::KemlockWeb,
            DeviceKind::KemlockCli,
            DeviceKind::Amethystora,
            DeviceKind::Bitwarden,
            DeviceKind::Other,
        ] {
            assert!(!c.redirect_allowed_for(&address, kind), "{kind:?}");
        }
        assert!(!c.redirect_allowed(&address));
    }

    #[test]
    fn an_extensions_redirect_is_matched_exactly() {
        let c = with_extensions();
        let host = format!("{CHROME_ID}.chromiumapp.org");
        let firefox = format!("{FIREFOX_HASH}.extensions.allizom.org");
        for bad in [
            // The scheme.
            format!("http://{host}/"),
            format!("chrome-extension://{CHROME_ID}/"),
            format!("//{host}/"),
            // The host: another label, another suffix, a look-alike, a user, a port.
            format!("https://evil.{host}/"),
            format!("https://{host}.evil.example/"),
            format!("https://{CHROME_ID}.example.org/"),
            format!("https://{CHROME_ID}-x.chromiumapp.org/"),
            format!("https://{CHROME_ID}chromiumapp.org/"),
            format!("https://evil.example@{host}/"),
            format!("https://{host}@evil.example/"),
            format!("https://{host}:8443/"),
            format!("https://{}.chromiumapp.org/", CHROME_ID.to_uppercase()),
            format!("https://{CHROME_ID}.extensions.allizom.org.evil.example/"),
            // The path, query and fragment.
            format!("https://{host}"),
            format!("https://{host}/other"),
            format!("https://{host}//evil.example"),
            format!("https://{host}/sso/"),
            format!("https://{host}/sso/extra"),
            format!("https://{host}/?next=https://evil.example"),
            format!("https://{host}/#frag"),
            format!("https://{host}/ "),
            format!("https://{host}\\@evil.example/"),
            format!("https://{firefox}/other"),
            format!("https://{firefox}.evil.example/"),
        ] {
            assert!(
                !c.redirect_allowed_for(&bad, DeviceKind::KemlockBrowser),
                "{bad:?}"
            );
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
