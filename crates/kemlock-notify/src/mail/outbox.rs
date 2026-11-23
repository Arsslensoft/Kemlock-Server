//! [`MailOutbox`]: the server's notices, written out and handed to a [`Mailer`].

use super::template::{Branding, render};
use super::{Mail, Mailer};
use kemlock_app::notices::{BoxFuture, Notice, Notices, Outbox};
use std::sync::Arc;

/// Renders each notice with the templates and sends it. A failure is logged and dropped: a notice
/// is best effort, and nothing waits on it.
pub struct MailOutbox {
    mailer: Arc<dyn Mailer>,
    brand: Branding,
}

impl std::fmt::Debug for MailOutbox {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MailOutbox")
            .field("brand", &self.brand)
            .finish_non_exhaustive()
    }
}

impl MailOutbox {
    pub fn new(mailer: Arc<dyn Mailer>, brand: Branding) -> Self {
        MailOutbox { mailer, brand }
    }

    /// The sender the API holds: every notice goes through this outbox.
    pub fn into_notices(self) -> Notices {
        Notices::with_outbox(Arc::new(self))
    }
}

impl Outbox for MailOutbox {
    fn deliver(&self, notice: Notice) -> BoxFuture<'_, ()> {
        Box::pin(async move {
            let kind = notice.kind();
            if let Err(error) = self.deliver_checked(notice).await {
                tracing::warn!(notice = kind, %error, "a notice mail was not sent");
            }
        })
    }

    fn deliver_checked(&self, notice: Notice) -> BoxFuture<'_, Result<(), String>> {
        Box::pin(async move {
            let rendered = render(&notice, &self.brand);
            let mail = Mail {
                to: rendered.to,
                subject: rendered.subject,
                text: rendered.text,
                html: rendered.html,
            };
            self.mailer
                .send(mail)
                .await
                .map_err(|error| error.to_string())
        })
    }
}

#[cfg(test)]
mod tests {
    use super::super::fake::Recorder;
    use super::*;
    use kemlock_app::notices::TwoStepCodeNotice;
    use kemlock_domain::Email;

    fn code_notice() -> Notice {
        Notice::TwoStepCode(TwoStepCodeNotice {
            to: Email::parse("ada@example.com").expect("email"),
            code: "246810".to_owned(),
        })
    }

    #[tokio::test]
    async fn a_notice_becomes_a_mail_to_its_recipient() {
        let recorder = Recorder::default();
        let outbox = MailOutbox::new(
            Arc::new(recorder.clone()),
            Branding::new("https://vault.example.com"),
        );
        outbox.deliver(code_notice()).await;
        let sent = recorder.sent.lock().expect("lock");
        assert_eq!(sent.len(), 1);
        assert_eq!(sent[0].to, "ada@example.com");
        assert!(sent[0].text.contains("246810"));
    }

    #[tokio::test]
    async fn a_failing_mailer_is_swallowed() {
        let recorder = Recorder {
            fail: true,
            ..Recorder::default()
        };
        let outbox = MailOutbox::new(Arc::new(recorder), Branding::new("https://x.example"));
        // Must return normally.
        outbox.deliver(code_notice()).await;
    }

    #[tokio::test]
    async fn a_checked_delivery_says_whether_the_mail_went_out() {
        let recorder = Recorder::default();
        let outbox = MailOutbox::new(
            Arc::new(recorder.clone()),
            Branding::new("https://x.example"),
        );
        assert_eq!(outbox.deliver_checked(code_notice()).await, Ok(()));
        assert_eq!(recorder.sent.lock().expect("lock").len(), 1);

        let down = Recorder {
            fail: true,
            ..Recorder::default()
        };
        let outbox = MailOutbox::new(Arc::new(down), Branding::new("https://x.example"));
        let error = outbox
            .deliver_checked(code_notice())
            .await
            .expect_err("the mail fails");
        assert!(error.contains("down"), "{error}");
    }

    #[tokio::test]
    async fn the_api_sender_reaches_the_mailer() {
        use kemlock_app::devices::{DeviceNotices, NewDeviceNotice};
        let recorder = Recorder::default();
        let notices = MailOutbox::new(
            Arc::new(recorder.clone()),
            Branding::new("https://x.example"),
        )
        .into_notices();
        notices
            .new_device(NewDeviceNotice {
                to: Email::parse("ada@example.com").expect("email"),
                device_name: "Pixel".to_owned(),
                device_kind: kemlock_domain::DeviceKind::KemlockAndroid,
                ip: "203.0.113.0".to_owned(),
                at: time::macros::datetime!(2026-11-23 10:00 UTC),
            })
            .await;
        assert_eq!(recorder.sent.lock().expect("lock").len(), 1);
    }
}
