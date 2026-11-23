//! Mail: a [`Mailer`] port, SMTP and log-only senders, the templates, and the [`MailOutbox`] that
//! turns the server's notices into mails.

mod admin;
mod outbox;
mod smtp;
mod template;

pub use admin::AdminMail;
pub use outbox::MailOutbox;
pub use smtp::{SmtpConfig, SmtpConfigError, SmtpMailer, SmtpSecurity};
pub use template::{Branding, Rendered, render};

use kemlock_app::notices::BoxFuture;

/// One mail, as text and HTML for the same message.
#[derive(Clone, PartialEq, Eq)]
pub struct Mail {
    pub to: String,
    pub subject: String,
    pub text: String,
    pub html: String,
}

impl std::fmt::Debug for Mail {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // The body can hold a sign-in code, so only its subject shows.
        f.debug_struct("Mail")
            .field("subject", &self.subject)
            .finish_non_exhaustive()
    }
}

#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum MailError {
    /// An address that isn't one.
    #[error("bad address: {0}")]
    Address(String),
    /// The message couldn't be built.
    #[error("couldn't build the mail: {0}")]
    Build(String),
    /// The server refused or couldn't be reached.
    #[error("couldn't send the mail: {0}")]
    Transport(String),
}

/// Sends mail. Object safe, so the server holds one behind an `Arc`.
pub trait Mailer: Send + Sync + 'static {
    /// Whether mail really goes out: false for a sender that only logs. The admin console asks,
    /// so a server whose SMTP is set up after the start shows as configured.
    fn is_set_up(&self) -> bool {
        true
    }

    fn send(&self, mail: Mail) -> BoxFuture<'_, Result<(), MailError>>;
}

/// A mailer that only logs, for a server with no SMTP settings. It logs the subject, never the
/// body (a body can hold a code) or the recipient.
#[derive(Clone, Copy, Debug, Default)]
pub struct LogMailer;

impl Mailer for LogMailer {
    fn is_set_up(&self) -> bool {
        false
    }

    fn send(&self, mail: Mail) -> BoxFuture<'_, Result<(), MailError>> {
        Box::pin(async move {
            tracing::info!(subject = %mail.subject, "mail not sent (SMTP_HOST is not set)");
            Ok(())
        })
    }
}

#[cfg(test)]
pub(crate) mod fake {
    use super::*;
    use std::sync::{Arc, Mutex};

    /// Keeps what it is asked to send, or fails every time.
    #[derive(Clone, Default)]
    pub(crate) struct Recorder {
        pub(crate) sent: Arc<Mutex<Vec<Mail>>>,
        pub(crate) fail: bool,
    }

    impl Mailer for Recorder {
        fn send(&self, mail: Mail) -> BoxFuture<'_, Result<(), MailError>> {
            Box::pin(async move {
                if self.fail {
                    return Err(MailError::Transport("down".to_owned()));
                }
                self.sent.lock().expect("lock").push(mail);
                Ok(())
            })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn the_log_mailer_succeeds_and_hides_the_body() {
        let mail = Mail {
            to: "ada@example.com".to_owned(),
            subject: "Your sign-in code".to_owned(),
            text: "123456".to_owned(),
            html: "<p>123456</p>".to_owned(),
        };
        assert!(!format!("{mail:?}").contains("123456"));
        assert_eq!(LogMailer.send(mail).await, Ok(()));
    }
}
