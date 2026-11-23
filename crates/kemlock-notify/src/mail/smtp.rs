//! SMTP with lettre, set up from the same variables Vaultwarden reads (`SMTP_HOST`, `SMTP_FROM`,
//! `SMTP_FROM_NAME`, `SMTP_PORT`, `SMTP_SECURITY`, `SMTP_USERNAME`, `SMTP_PASSWORD`,
//! `SMTP_TIMEOUT`, `SMTP_ACCEPT_INVALID_CERTS`, `SMTP_ACCEPT_INVALID_HOSTNAMES`).

use super::{Mail, MailError, Mailer};
use kemlock_app::notices::BoxFuture;
use lettre::message::{Mailbox, MultiPart};
use lettre::transport::smtp::authentication::Credentials;
use lettre::transport::smtp::client::{Tls, TlsParameters};
use lettre::{Address, AsyncSmtpTransport, AsyncTransport, Message, Tokio1Executor};
use std::time::Duration;

/// How the connection to the SMTP server is secured.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SmtpSecurity {
    /// Plain text, then `STARTTLS`, which is required (port 587).
    StartTls,
    /// TLS from the first byte (port 465).
    ForceTls,
    /// No encryption (port 25): for a relay on the same host or network.
    Off,
}

impl SmtpSecurity {
    fn default_port(self) -> u16 {
        match self {
            SmtpSecurity::StartTls => 587,
            SmtpSecurity::ForceTls => 465,
            SmtpSecurity::Off => 25,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum SmtpConfigError {
    #[error("{0} is not set")]
    Missing(&'static str),
    #[error("{0} is not valid: {1}")]
    Invalid(&'static str, String),
}

/// SMTP settings. The password stays out of `Debug` output.
#[derive(Clone, PartialEq, Eq)]
pub struct SmtpConfig {
    pub host: String,
    pub port: u16,
    pub security: SmtpSecurity,
    pub username: Option<String>,
    pub password: Option<String>,
    pub from: String,
    pub from_name: String,
    pub timeout: Duration,
    pub accept_invalid_certs: bool,
    pub accept_invalid_hostnames: bool,
}

impl std::fmt::Debug for SmtpConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SmtpConfig")
            .field("host", &self.host)
            .field("port", &self.port)
            .field("security", &self.security)
            .field("username", &self.username)
            .field("password", &self.password.as_ref().map(|_| "<redacted>"))
            .field("from", &self.from)
            .finish_non_exhaustive()
    }
}

fn flag(value: &str) -> Option<bool> {
    match value.trim().to_ascii_lowercase().as_str() {
        "true" | "1" | "yes" | "on" => Some(true),
        "false" | "0" | "no" | "off" | "" => Some(false),
        _ => None,
    }
}

impl SmtpConfig {
    /// Reads the settings through `get` (the environment, in the server). `Ok(None)` when
    /// `SMTP_HOST` is not set: the server then only logs its mail.
    pub fn from_lookup(
        get: &dyn Fn(&str) -> Option<String>,
    ) -> Result<Option<SmtpConfig>, SmtpConfigError> {
        let non_empty = |name: &str| {
            get(name)
                .map(|v| v.trim().to_owned())
                .filter(|v| !v.is_empty())
        };
        let Some(host) = non_empty("SMTP_HOST") else {
            return Ok(None);
        };
        let from = non_empty("SMTP_FROM").ok_or(SmtpConfigError::Missing("SMTP_FROM"))?;
        from.parse::<Address>()
            .map_err(|e| SmtpConfigError::Invalid("SMTP_FROM", e.to_string()))?;
        let security = match non_empty("SMTP_SECURITY")
            .map(|v| v.to_ascii_lowercase())
            .as_deref()
        {
            None | Some("starttls") => SmtpSecurity::StartTls,
            Some("force_tls") => SmtpSecurity::ForceTls,
            Some("off") => SmtpSecurity::Off,
            Some(other) => {
                return Err(SmtpConfigError::Invalid(
                    "SMTP_SECURITY",
                    format!("{other:?} is none of starttls, force_tls, off"),
                ));
            }
        };
        let port = match non_empty("SMTP_PORT") {
            None => security.default_port(),
            Some(text) => text
                .parse::<u16>()
                .map_err(|e| SmtpConfigError::Invalid("SMTP_PORT", e.to_string()))?,
        };
        let timeout = match non_empty("SMTP_TIMEOUT") {
            None => Duration::from_secs(15),
            Some(text) => Duration::from_secs(
                text.parse::<u64>()
                    .map_err(|e| SmtpConfigError::Invalid("SMTP_TIMEOUT", e.to_string()))?,
            ),
        };
        let parse_flag = |name: &'static str| match non_empty(name) {
            None => Ok(false),
            Some(text) => flag(&text)
                .ok_or_else(|| SmtpConfigError::Invalid(name, "expected true or false".to_owned())),
        };
        let username = non_empty("SMTP_USERNAME");
        // A password is kept as typed: spaces inside one are legitimate.
        let password = get("SMTP_PASSWORD").filter(|v| !v.is_empty());
        if username.is_some() != password.is_some() {
            return Err(SmtpConfigError::Invalid(
                "SMTP_USERNAME",
                "SMTP_USERNAME and SMTP_PASSWORD go together".to_owned(),
            ));
        }
        Ok(Some(SmtpConfig {
            host,
            port,
            security,
            username,
            password,
            from,
            from_name: non_empty("SMTP_FROM_NAME").unwrap_or_else(|| "Kemlock".to_owned()),
            timeout,
            accept_invalid_certs: parse_flag("SMTP_ACCEPT_INVALID_CERTS")?,
            accept_invalid_hostnames: parse_flag("SMTP_ACCEPT_INVALID_HOSTNAMES")?,
        }))
    }
}

/// Sends mail over SMTP. Each send opens its own connection: a server mails a handful of notices
/// an hour, so a pool would only hold sockets open.
pub struct SmtpMailer {
    transport: AsyncSmtpTransport<Tokio1Executor>,
    from: Mailbox,
}

impl std::fmt::Debug for SmtpMailer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SmtpMailer")
            .field("from", &self.from)
            .finish_non_exhaustive()
    }
}

impl SmtpMailer {
    pub fn new(config: &SmtpConfig) -> Result<SmtpMailer, MailError> {
        let address: Address = config
            .from
            .parse()
            .map_err(|e: lettre::address::AddressError| MailError::Address(e.to_string()))?;
        let from = Mailbox::new(Some(config.from_name.clone()), address);

        let tls = match config.security {
            SmtpSecurity::Off => Tls::None,
            secured => {
                let parameters = TlsParameters::builder(config.host.clone())
                    .dangerous_accept_invalid_certs(config.accept_invalid_certs)
                    .dangerous_accept_invalid_hostnames(config.accept_invalid_hostnames)
                    .build()
                    .map_err(|e| MailError::Transport(e.to_string()))?;
                if secured == SmtpSecurity::ForceTls {
                    Tls::Wrapper(parameters)
                } else {
                    Tls::Required(parameters)
                }
            }
        };
        let mut builder =
            AsyncSmtpTransport::<Tokio1Executor>::builder_dangerous(config.host.clone())
                .port(config.port)
                .timeout(Some(config.timeout))
                .tls(tls);
        if let (Some(user), Some(password)) = (&config.username, &config.password) {
            builder = builder.credentials(Credentials::new(user.clone(), password.clone()));
        }
        Ok(SmtpMailer {
            transport: builder.build(),
            from,
        })
    }

    fn message(&self, mail: &Mail) -> Result<Message, MailError> {
        let to: Address = mail
            .to
            .parse()
            .map_err(|e: lettre::address::AddressError| MailError::Address(e.to_string()))?;
        Message::builder()
            .from(self.from.clone())
            .to(Mailbox::new(None, to))
            .subject(mail.subject.clone())
            .multipart(MultiPart::alternative_plain_html(
                mail.text.clone(),
                mail.html.clone(),
            ))
            .map_err(|e| MailError::Build(e.to_string()))
    }
}

impl Mailer for SmtpMailer {
    fn send(&self, mail: Mail) -> BoxFuture<'_, Result<(), MailError>> {
        Box::pin(async move {
            let message = self.message(&mail)?;
            self.transport
                .send(message)
                .await
                .map(|_| ())
                .map_err(|e| MailError::Transport(e.to_string()))
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use std::sync::{Arc, Mutex};
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
    use tokio::net::TcpListener;

    fn lookup(pairs: &[(&str, &str)]) -> impl Fn(&str) -> Option<String> {
        let map: HashMap<String, String> = pairs
            .iter()
            .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
            .collect();
        move |name| map.get(name).cloned()
    }

    #[test]
    fn no_host_means_no_smtp() {
        assert_eq!(SmtpConfig::from_lookup(&lookup(&[])), Ok(None));
        assert_eq!(
            SmtpConfig::from_lookup(&lookup(&[("SMTP_HOST", "  ")])),
            Ok(None)
        );
    }

    #[test]
    fn defaults_follow_vaultwarden() {
        let config = SmtpConfig::from_lookup(&lookup(&[
            ("SMTP_HOST", "mail.example.com"),
            ("SMTP_FROM", "vault@example.com"),
        ]))
        .expect("valid")
        .expect("on");
        assert_eq!(config.port, 587);
        assert_eq!(config.security, SmtpSecurity::StartTls);
        assert_eq!(config.from_name, "Kemlock");
        assert_eq!(config.timeout, Duration::from_secs(15));
        assert!(!config.accept_invalid_certs);
        assert_eq!(config.username, None);
    }

    #[test]
    fn the_security_sets_the_default_port() {
        let port = |security: &str| {
            SmtpConfig::from_lookup(&lookup(&[
                ("SMTP_HOST", "h"),
                ("SMTP_FROM", "a@example.com"),
                ("SMTP_SECURITY", security),
            ]))
            .expect("valid")
            .expect("on")
            .port
        };
        assert_eq!(port("force_tls"), 465);
        assert_eq!(port("FORCE_TLS"), 465);
        assert_eq!(port("off"), 25);
        assert_eq!(port("starttls"), 587);
    }

    #[test]
    fn bad_settings_name_the_variable() {
        let base = [("SMTP_HOST", "h"), ("SMTP_FROM", "a@example.com")];
        let with = |extra: (&'static str, &'static str)| {
            let mut pairs = base.to_vec();
            pairs.push(extra);
            SmtpConfig::from_lookup(&lookup(&pairs))
        };
        assert!(matches!(
            with(("SMTP_PORT", "http")),
            Err(SmtpConfigError::Invalid("SMTP_PORT", _))
        ));
        assert!(matches!(
            with(("SMTP_SECURITY", "ssl")),
            Err(SmtpConfigError::Invalid("SMTP_SECURITY", _))
        ));
        assert!(matches!(
            with(("SMTP_TIMEOUT", "-1")),
            Err(SmtpConfigError::Invalid("SMTP_TIMEOUT", _))
        ));
        assert!(matches!(
            with(("SMTP_ACCEPT_INVALID_CERTS", "maybe")),
            Err(SmtpConfigError::Invalid("SMTP_ACCEPT_INVALID_CERTS", _))
        ));
        assert!(matches!(
            with(("SMTP_USERNAME", "ada")),
            Err(SmtpConfigError::Invalid("SMTP_USERNAME", _))
        ));
        assert_eq!(
            SmtpConfig::from_lookup(&lookup(&[("SMTP_HOST", "h")])),
            Err(SmtpConfigError::Missing("SMTP_FROM"))
        );
        assert!(matches!(
            SmtpConfig::from_lookup(&lookup(&[
                ("SMTP_HOST", "h"),
                ("SMTP_FROM", "not an address")
            ])),
            Err(SmtpConfigError::Invalid("SMTP_FROM", _))
        ));
    }

    #[test]
    fn the_password_stays_out_of_debug_output() {
        let config = SmtpConfig::from_lookup(&lookup(&[
            ("SMTP_HOST", "h"),
            ("SMTP_FROM", "a@example.com"),
            ("SMTP_USERNAME", "ada"),
            ("SMTP_PASSWORD", "hunter2 with spaces"),
        ]))
        .expect("valid")
        .expect("on");
        assert_eq!(config.password.as_deref(), Some("hunter2 with spaces"));
        assert!(!format!("{config:?}").contains("hunter2"));
    }

    /// A one-connection SMTP server that accepts one message and keeps its envelope and data.
    async fn fake_smtp() -> (u16, Arc<Mutex<Vec<String>>>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("binds");
        let port = listener.local_addr().expect("addr").port();
        let log = Arc::new(Mutex::new(Vec::new()));
        let kept = log.clone();
        tokio::spawn(async move {
            let Ok((stream, _)) = listener.accept().await else {
                return;
            };
            let (read, mut write) = stream.into_split();
            let mut lines = BufReader::new(read).lines();
            let _ = write.write_all(b"220 fake ESMTP\r\n").await;
            let mut in_data = false;
            while let Ok(Some(line)) = lines.next_line().await {
                if in_data {
                    if line == "." {
                        in_data = false;
                        let _ = write.write_all(b"250 queued\r\n").await;
                    } else {
                        kept.lock().expect("lock").push(format!("DATA {line}"));
                    }
                    continue;
                }
                let upper = line.to_ascii_uppercase();
                kept.lock().expect("lock").push(line.clone());
                let reply: &[u8] = if upper.starts_with("EHLO") {
                    b"250-fake\r\n250 8BITMIME\r\n"
                } else if upper.starts_with("DATA") {
                    in_data = true;
                    b"354 go ahead\r\n"
                } else if upper.starts_with("QUIT") {
                    let _ = write.write_all(b"221 bye\r\n").await;
                    break;
                } else {
                    b"250 ok\r\n"
                };
                let _ = write.write_all(reply).await;
            }
        });
        (port, log)
    }

    #[tokio::test]
    async fn a_mail_goes_out_over_smtp() {
        let (port, log) = fake_smtp().await;
        let config = SmtpConfig {
            host: "127.0.0.1".to_owned(),
            port,
            security: SmtpSecurity::Off,
            username: None,
            password: None,
            from: "vault@example.com".to_owned(),
            from_name: "Kemlock".to_owned(),
            timeout: Duration::from_secs(10),
            accept_invalid_certs: false,
            accept_invalid_hostnames: false,
        };
        let mailer = SmtpMailer::new(&config).expect("builds");
        mailer
            .send(Mail {
                to: "ada@example.com".to_owned(),
                subject: "Your Kemlock sign-in code".to_owned(),
                text: "Your sign-in code is 123456".to_owned(),
                html: "<p>Your sign-in code is 123456</p>".to_owned(),
            })
            .await
            .expect("sends");
        let seen = log.lock().expect("lock").join("\n");
        assert!(seen.contains("MAIL FROM:<vault@example.com>"), "{seen}");
        assert!(seen.contains("RCPT TO:<ada@example.com>"), "{seen}");
        assert!(
            seen.contains("DATA Subject: Your Kemlock sign-in code"),
            "{seen}"
        );
        assert!(seen.contains("multipart/alternative"), "{seen}");
        assert!(seen.contains("text/plain"), "{seen}");
        assert!(seen.contains("text/html"), "{seen}");
    }

    #[tokio::test]
    async fn an_unreachable_server_is_a_transport_error() {
        // Bind and drop to find a port nobody listens on.
        let port = {
            let l = TcpListener::bind("127.0.0.1:0").await.expect("binds");
            l.local_addr().expect("addr").port()
        };
        let config = SmtpConfig {
            host: "127.0.0.1".to_owned(),
            port,
            security: SmtpSecurity::Off,
            username: None,
            password: None,
            from: "vault@example.com".to_owned(),
            from_name: "Kemlock".to_owned(),
            timeout: Duration::from_secs(2),
            accept_invalid_certs: false,
            accept_invalid_hostnames: false,
        };
        let mailer = SmtpMailer::new(&config).expect("builds");
        let result = mailer
            .send(Mail {
                to: "ada@example.com".to_owned(),
                subject: "s".to_owned(),
                text: "t".to_owned(),
                html: "h".to_owned(),
            })
            .await;
        assert!(matches!(result, Err(MailError::Transport(_))), "{result:?}");
    }

    #[tokio::test]
    async fn a_bad_recipient_is_an_address_error() {
        let config = SmtpConfig {
            host: "127.0.0.1".to_owned(),
            port: 9,
            security: SmtpSecurity::Off,
            username: None,
            password: None,
            from: "vault@example.com".to_owned(),
            from_name: "Kemlock".to_owned(),
            timeout: Duration::from_secs(1),
            accept_invalid_certs: false,
            accept_invalid_hostnames: false,
        };
        let mailer = SmtpMailer::new(&config).expect("builds");
        let result = mailer
            .send(Mail {
                to: "not an address".to_owned(),
                subject: "s".to_owned(),
                text: "t".to_owned(),
                html: "h".to_owned(),
            })
            .await;
        assert!(matches!(result, Err(MailError::Address(_))), "{result:?}");
    }
}
