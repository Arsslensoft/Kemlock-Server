//! `/.well-known/security.txt` (RFC 9116), also at `/security.txt`, which the RFC still allows.
//!
//! RFC 9116 requires `Contact` and `Expires` and recommends an `Expires` under a year away
//! (<https://www.rfc-editor.org/rfc/rfc9116>). The file has two contacts: the operator's, from the
//! admin settings `security_contact` (an email address, or a `mailto:`, `tel:` or `https:` address)
//! and `security_encryption` (where their PGP key is), and Kemlock's own address for flaws in the
//! software. An operator who set nothing still gets a valid file, with Kemlock's contact only.
//!
//! `Expires` is never stale: it is written fresh on each request as midnight UTC 180 days from now,
//! so a server that is kept running always says it can be trusted for another half year, and one
//! that is switched off stops answering anyway.

use axum::Router;
use axum::extract::State;
use axum::http::{HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use kemlock_app::admin::settings::Settings;
use kemlock_app::admin::{EnvSettings, SettingsRepo};
use kemlock_app::ports::SecretSeal;
use std::sync::Arc;
use time::format_description::well_known::Rfc3339;
use time::{Duration, OffsetDateTime, Time};

/// Where Kemlock takes reports of flaws in the software: a private GitHub security advisory.
pub const KEMLOCK_CONTACT: &str =
    "https://github.com/Arsslensoft/Kemlock-Server/security/advisories/new";
/// The disclosure policy (`SECURITY.md` in the repository).
pub const POLICY: &str = "https://github.com/Arsslensoft/Kemlock-Server/blob/main/SECURITY.md";
/// How far ahead `Expires` is. RFC 9116 recommends less than a year.
pub const EXPIRES_IN_DAYS: i64 = 180;

/// A contact as a URI, or `None` for something that isn't one: an address with no scheme is an
/// email address, and anything with blanks or control characters is refused, so nothing in a
/// setting can add a line to the file.
fn contact_uri(raw: &str) -> Option<String> {
    let raw = raw.trim();
    if raw.is_empty() || raw.chars().any(|c| c.is_whitespace() || c.is_control()) {
        return None;
    }
    if ["https://", "mailto:", "tel:"]
        .iter()
        .any(|scheme| raw.starts_with(scheme))
    {
        return Some(raw.to_owned());
    }
    kemlock_domain::Email::parse(raw)
        .ok()
        .map(|email| format!("mailto:{}", email.as_str()))
}

/// Where a PGP key can be had, as a URI, or `None`.
fn encryption_uri(raw: &str) -> Option<String> {
    let raw = raw.trim();
    if raw.is_empty() || raw.chars().any(|c| c.is_whitespace() || c.is_control()) {
        return None;
    }
    ["https://", "openpgp4fpr:", "dns:"]
        .iter()
        .any(|scheme| raw.starts_with(scheme))
        .then(|| raw.to_owned())
}

/// The text of the file. `canonical` is the address it is served from.
pub fn render(
    operator_contact: Option<&str>,
    operator_encryption: Option<&str>,
    canonical: &str,
    now: OffsetDateTime,
) -> String {
    let expires = (now + Duration::days(EXPIRES_IN_DAYS))
        .replace_time(Time::MIDNIGHT)
        .format(&Rfc3339)
        .unwrap_or_else(|_| "1970-01-01T00:00:00Z".to_owned());
    let mut text = String::new();
    if let Some(contact) = operator_contact.and_then(contact_uri) {
        text.push_str("# Problems with this server or how it is run:\n");
        text.push_str(&format!("Contact: {contact}\n"));
    }
    text.push_str("# Flaws in the Kemlock Server software itself:\n");
    text.push_str(&format!("Contact: {KEMLOCK_CONTACT}\n"));
    text.push_str(&format!("Expires: {expires}\n"));
    if let Some(key) = operator_encryption.and_then(encryption_uri) {
        text.push_str(&format!("Encryption: {key}\n"));
    }
    text.push_str("Preferred-Languages: en\n");
    text.push_str(&format!("Canonical: {canonical}\n"));
    text.push_str(&format!("Policy: {POLICY}\n"));
    text
}

struct Shared<R, S, E> {
    settings: Settings<R, S, E>,
    canonical: String,
}

async fn serve<R, S, E>(State(shared): State<Arc<Shared<R, S, E>>>) -> Response
where
    R: SettingsRepo + 'static,
    S: SecretSeal + 'static,
    E: EnvSettings + 'static,
{
    // A settings table that can't be read is no reason to withhold the file: Kemlock's contact
    // alone is still a valid one.
    let contact = read(&shared.settings, "security_contact").await;
    let encryption = read(&shared.settings, "security_encryption").await;
    let body = render(
        contact.as_deref(),
        encryption.as_deref(),
        &shared.canonical,
        OffsetDateTime::now_utc(),
    );
    let mut response = (StatusCode::OK, body).into_response();
    let headers = response.headers_mut();
    headers.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("text/plain; charset=utf-8"),
    );
    headers.insert(
        header::CACHE_CONTROL,
        HeaderValue::from_static("public, max-age=3600"),
    );
    response
}

async fn read<R, S, E>(settings: &Settings<R, S, E>, key: &str) -> Option<String>
where
    R: SettingsRepo,
    S: SecretSeal,
    E: EnvSettings,
{
    match settings.get(key).await {
        Ok(value) => value,
        Err(error) => {
            tracing::warn!(%error, key, "couldn't read a security.txt setting");
            None
        }
    }
}

/// `GET /.well-known/security.txt` and `GET /security.txt`. `domain` is the configured `DOMAIN`.
pub fn router<R, S, E>(settings: Settings<R, S, E>, domain: &str) -> Router
where
    R: SettingsRepo + 'static,
    S: SecretSeal + 'static,
    E: EnvSettings + 'static,
{
    let shared = Arc::new(Shared {
        settings,
        canonical: format!("{}/.well-known/security.txt", domain.trim_end_matches('/')),
    });
    Router::new()
        .route("/.well-known/security.txt", get(serve::<R, S, E>))
        .route("/security.txt", get(serve::<R, S, E>))
        .with_state(shared)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::adapters::ServerCrypto;
    use axum::body::Body;
    use axum::http::Request;
    use kemlock_app::admin::FnEnv;
    use kemlock_app::ports::StoreError;
    use kemlock_crypto::opaque::OpaqueServer;
    use kemlock_crypto::seal::ServerSeal;
    use std::collections::BTreeMap;
    use time::macros::datetime;
    use tower::ServiceExt;

    const NOW: OffsetDateTime = datetime!(2026-11-22 10:30 UTC);
    const CANONICAL: &str = "https://vault.example.org/.well-known/security.txt";

    #[test]
    fn the_file_has_both_contacts_and_an_expiry_under_a_year() {
        const { assert!(EXPIRES_IN_DAYS < 365) };
        let text = render(
            Some("Ops@Example.org"),
            Some("https://example.org/pgp.asc"),
            CANONICAL,
            NOW,
        );
        let lines: Vec<&str> = text.lines().filter(|l| !l.starts_with('#')).collect();
        assert_eq!(lines[0], "Contact: mailto:ops@example.org");
        assert_eq!(lines[1], format!("Contact: {KEMLOCK_CONTACT}"));
        assert_eq!(lines[2], "Expires: 2027-05-21T00:00:00Z");
        assert!(lines.contains(&"Encryption: https://example.org/pgp.asc"));
        assert!(lines.contains(&format!("Canonical: {CANONICAL}").as_str()));
        assert!(lines.contains(&format!("Policy: {POLICY}").as_str()));
    }

    #[test]
    fn without_an_operator_contact_only_kemlocks_is_listed() {
        for operator in [
            None,
            Some(""),
            Some("not an address"),
            Some("a b@example.org"),
        ] {
            let text = render(operator, None, CANONICAL, NOW);
            assert_eq!(text.matches("Contact:").count(), 1, "{operator:?}");
            assert!(text.contains("Expires:"));
            assert!(!text.contains("Encryption:"));
        }
    }

    #[test]
    fn a_setting_cannot_add_a_line() {
        let text = render(
            Some("https://example.org/x\nExpires: 2099-01-01T00:00:00Z"),
            Some("https://example.org/k\nPolicy: https://evil.example"),
            CANONICAL,
            NOW,
        );
        assert_eq!(text.matches("Expires:").count(), 1);
        assert_eq!(text.matches("Policy:").count(), 1);
        assert!(!text.contains("evil.example"));
    }

    #[test]
    fn contacts_are_uris() {
        assert_eq!(
            contact_uri("mailto:a@example.org").as_deref(),
            Some("mailto:a@example.org")
        );
        assert_eq!(
            contact_uri("https://example.org/report").as_deref(),
            Some("https://example.org/report")
        );
        assert_eq!(
            contact_uri("tel:+1-201-555-0123").as_deref(),
            Some("tel:+1-201-555-0123")
        );
        assert_eq!(contact_uri("javascript:alert(1)"), None);
        assert_eq!(encryption_uri("http://example.org/key"), None);
        assert_eq!(
            encryption_uri("openpgp4fpr:0123456789abcdef").as_deref(),
            Some("openpgp4fpr:0123456789abcdef")
        );
    }

    /// Saved settings in memory.
    struct Saved(BTreeMap<String, String>);

    impl SettingsRepo for Saved {
        async fn settings_with_prefix(
            &self,
            prefix: &str,
        ) -> Result<Vec<(String, String)>, StoreError> {
            Ok(self
                .0
                .iter()
                .filter(|(key, _)| key.starts_with(prefix))
                .map(|(key, value)| (key.clone(), value.clone()))
                .collect())
        }

        async fn put_setting(&self, _key: &str, _value: &str) -> Result<(), StoreError> {
            Ok(())
        }

        async fn delete_setting(&self, _key: &str) -> Result<(), StoreError> {
            Ok(())
        }
    }

    fn app(saved: &[(&str, &str)], env: &'static [(&str, &str)]) -> Router {
        let saved = Saved(
            saved
                .iter()
                .map(|(k, v)| (format!("setting.{k}"), (*v).to_owned()))
                .collect(),
        );
        let seal = ServerCrypto::new(ServerSeal::new(&[5u8; 32]), OpaqueServer::generate());
        let env = FnEnv(move |name: &str| {
            env.iter()
                .find(|(k, _)| *k == name)
                .map(|(_, v)| (*v).to_owned())
        });
        router(
            Settings {
                repo: saved,
                seal,
                env,
            },
            "https://vault.example.org/",
        )
    }

    async fn fetch(router: Router, path: &str) -> (StatusCode, Option<String>, String) {
        let response = router
            .oneshot(
                Request::builder()
                    .uri(path)
                    .body(Body::empty())
                    .expect("a valid request"),
            )
            .await
            .expect("infallible");
        let status = response.status();
        let content_type = response
            .headers()
            .get(header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok())
            .map(str::to_owned);
        let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .expect("a body");
        (
            status,
            content_type,
            String::from_utf8(bytes.to_vec()).expect("text"),
        )
    }

    #[tokio::test]
    async fn the_server_serves_the_file_from_its_settings_at_both_addresses() {
        for path in ["/.well-known/security.txt", "/security.txt"] {
            let router = app(
                &[
                    ("security_contact", "ops@example.org"),
                    ("security_encryption", "https://example.org/pgp.asc"),
                ],
                &[],
            );
            let (status, content_type, body) = fetch(router, path).await;
            assert_eq!(status, StatusCode::OK, "{path}");
            assert_eq!(content_type.as_deref(), Some("text/plain; charset=utf-8"));
            assert!(body.contains("Contact: mailto:ops@example.org\n"), "{body}");
            assert!(
                body.contains(&format!("Contact: {KEMLOCK_CONTACT}\n")),
                "{body}"
            );
            assert!(body.contains("\nExpires: 20"), "{body}");
            assert!(body.contains("Encryption: https://example.org/pgp.asc\n"));
            assert!(body.contains(&format!("Canonical: {CANONICAL}\n")));
        }
    }

    #[tokio::test]
    async fn an_environment_value_wins_over_a_saved_one() {
        let router = app(
            &[("security_contact", "saved@example.org")],
            &[("KEMLOCK_SECURITY_CONTACT", "env@example.org")],
        );
        let (_, _, body) = fetch(router, "/.well-known/security.txt").await;
        assert!(body.contains("mailto:env@example.org"), "{body}");
        assert!(!body.contains("saved@example.org"), "{body}");
    }

    #[tokio::test]
    async fn a_server_with_no_settings_still_serves_a_valid_file() {
        let (status, _, body) = fetch(app(&[], &[]), "/.well-known/security.txt").await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body.matches("Contact:").count(), 1);
        assert!(body.contains("Expires:"));
    }
}
