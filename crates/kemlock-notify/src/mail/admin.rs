//! [`AdminMail`]: the admin console's mail (its alerts and invitations to the server) over the same
//! [`Mailer`] every other notice goes through, so one set of `SMTP_*` settings serves them all.
//!
//! The console writes its own subject and text. The HTML part is that text, escaped, so a client
//! that shows HTML shows the same words.

use super::template::escape;
use super::{Mail, Mailer};
use kemlock_app::admin as port;
use std::sync::Arc;

/// Sends the admin console's mail through SMTP, or reports that none is set up. Cheap to clone.
#[derive(Clone, Default)]
pub struct AdminMail {
    mailer: Option<Arc<dyn Mailer>>,
}

impl std::fmt::Debug for AdminMail {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AdminMail")
            .field("configured", &self.sender().is_some())
            .finish()
    }
}

impl AdminMail {
    /// `mailer` is `None`, or a sender that only logs, when no SMTP is set up: the console then says
    /// no mail is set up instead of pretending to send. The sender is asked every time, so one that
    /// switches to SMTP later (settings saved in the console) turns the console's mail on.
    pub fn new(mailer: Option<Arc<dyn Mailer>>) -> AdminMail {
        AdminMail { mailer }
    }

    /// The sender, if it really sends.
    fn sender(&self) -> Option<&Arc<dyn Mailer>> {
        self.mailer.as_ref().filter(|m| m.is_set_up())
    }
}

/// The text as an HTML body: each paragraph escaped, line breaks kept.
fn html_of(text: &str) -> String {
    let mut out = String::from(
        "<!doctype html><html><body style=\"font-family:sans-serif;line-height:1.5;color:#222\">",
    );
    for paragraph in text.split("\n\n") {
        out.push_str("<p>");
        out.push_str(&escape(paragraph.trim_end()).replace('\n', "<br>"));
        out.push_str("</p>");
    }
    out.push_str("</body></html>");
    out
}

impl port::Mailer for AdminMail {
    fn configured(&self) -> bool {
        self.sender().is_some()
    }

    async fn send(&self, notice: port::Notice) -> Result<(), port::MailError> {
        let Some(mailer) = self.sender() else {
            return Err(port::MailError::NotConfigured);
        };
        let mail = Mail {
            to: notice.to.as_str().to_owned(),
            html: html_of(&notice.body),
            subject: notice.subject,
            text: notice.body,
        };
        mailer
            .send(mail)
            .await
            .map_err(|error| port::MailError::Failed(error.to_string()))
    }
}

#[cfg(test)]
mod tests {
    use super::super::fake::Recorder;
    use super::*;
    use kemlock_app::admin::Mailer as _;
    use kemlock_domain::Email;

    fn notice(body: &str) -> port::Notice {
        port::Notice {
            to: Email::parse("admin@example.com").expect("email"),
            subject: "Alert: many failed sign-ins".to_owned(),
            body: body.to_owned(),
        }
    }

    #[tokio::test]
    async fn the_console_sends_through_the_servers_mailer() {
        let recorder = Recorder::default();
        let mail = AdminMail::new(Some(Arc::new(recorder.clone())));
        assert!(mail.configured());
        mail.send(notice("Line one\nline two\n\nSecond <paragraph>"))
            .await
            .expect("sends");
        let sent = recorder.sent.lock().expect("lock");
        assert_eq!(sent.len(), 1);
        assert_eq!(sent[0].to, "admin@example.com");
        assert_eq!(sent[0].subject, "Alert: many failed sign-ins");
        assert_eq!(sent[0].text, "Line one\nline two\n\nSecond <paragraph>");
        assert!(sent[0].html.contains("Line one<br>line two"));
        assert!(sent[0].html.contains("Second &lt;paragraph&gt;"));
    }

    #[tokio::test]
    async fn without_smtp_it_says_no_mail_is_set_up() {
        let mail = AdminMail::default();
        assert!(!mail.configured());
        assert_eq!(
            mail.send(notice("hello")).await,
            Err(port::MailError::NotConfigured)
        );
    }

    #[tokio::test]
    async fn a_mailer_that_fails_is_reported_to_the_console() {
        let down = Recorder {
            fail: true,
            ..Recorder::default()
        };
        let mail = AdminMail::new(Some(Arc::new(down)));
        match mail.send(notice("hello")).await {
            Err(port::MailError::Failed(why)) => assert!(why.contains("down"), "{why}"),
            other => panic!("expected a failure, got {other:?}"),
        }
    }
}
