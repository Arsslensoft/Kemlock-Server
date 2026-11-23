//! First-run setup rules (design, "Identity and SSO", First run).

/// Why setup can't go on.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum SetupError {
    #[error("setup is finished: an admin exists")]
    AlreadyDone,
    #[error("setup needs HTTPS, or a browser on this machine (localhost)")]
    InsecureContext,
    #[error("the setup code is wrong")]
    WrongCode,
    #[error("too many wrong setup codes; wait and try again")]
    SlowDown,
    #[error("an admin must set up two-step login before setup can finish")]
    TwoStepRequired,
}

/// Whether `origin` (scheme, host and optional port, as a browser's `Origin` header gives it) is a
/// secure context where WebCrypto and passkeys work: `https://` anywhere, or `http://` on
/// `localhost`, `*.localhost`, `127.0.0.0/8` or `[::1]`.
pub fn is_secure_context(origin: &str) -> bool {
    let origin = origin.trim().to_ascii_lowercase();
    if origin.starts_with("https://") {
        return origin.len() > "https://".len();
    }
    let Some(rest) = origin.strip_prefix("http://") else {
        return false;
    };
    let authority = rest.split('/').next().unwrap_or_default();
    let host = if let Some(v6) = authority.strip_prefix('[') {
        v6.split(']').next().unwrap_or_default()
    } else {
        authority.rsplit_once(':').map_or(authority, |(h, port)| {
            if port.bytes().all(|b| b.is_ascii_digit()) {
                h
            } else {
                authority
            }
        })
    };
    host == "localhost"
        || host.ends_with(".localhost")
        || host == "::1"
        || host.strip_prefix("127.").is_some_and(|r| {
            let parts: Vec<_> = r.split('.').collect();
            parts.len() == 3 && parts.iter().all(|p| p.parse::<u8>().is_ok())
        })
}

#[cfg(test)]
mod tests {
    use super::is_secure_context;

    #[test]
    fn https_and_loopback_are_secure() {
        for ok in [
            "https://vault.example.com",
            "https://vault.example.com:8443",
            "http://localhost:8080",
            "http://app.localhost",
            "http://127.0.0.1:8080",
            "http://127.1.2.3",
            "http://[::1]:8080",
        ] {
            assert!(is_secure_context(ok), "{ok}");
        }
    }

    #[test]
    fn plain_http_elsewhere_is_not() {
        for bad in [
            "http://192.168.1.10:8080",
            "http://vault.example.com",
            "http://localhost.evil.com",
            "http://127.0.0.1.evil.com",
            "ftp://localhost",
            "https://",
            "",
        ] {
            assert!(!is_secure_context(bad), "{bad}");
        }
    }
}
