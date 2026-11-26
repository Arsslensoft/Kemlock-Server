//! Email notices, and the one sender the API holds for all of them.
//!
//! The use cases know the narrow ports ([`DeviceNotices`], [`EmergencyNotices`]); the API holds a
//! [`Notices`], which implements both and hands every notice to an [`Outbox`] (the SMTP sender
//! in `kemlock-notify`), or only logs it when no mail is configured. Every send is best effort.

use crate::devices::{DeviceNotices, NewDeviceNotice};
use crate::emergency::{EmergencyNotice, EmergencyNotices};
use kemlock_domain::{Email, SpaceId};
use std::fmt;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use time::OffsetDateTime;

/// An invitation to join a space. Names are plain text the inviter's client chose to share; both
/// may be absent, since the server can't read a space's sealed name.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct InvitationNotice {
    pub to: Email,
    pub space: Option<String>,
    pub inviter: Option<String>,
    /// The space, for the link the mail opens: it carries no secret, only the space's id, and the
    /// invitee signs in to accept.
    pub space_id: Option<SpaceId>,
}

/// The code of an email two-step login. Never logged.
#[derive(Clone, PartialEq, Eq)]
pub struct TwoStepCodeNotice {
    pub to: Email,
    pub code: String,
}

impl fmt::Debug for TwoStepCodeNotice {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TwoStepCodeNotice")
            .field("to", &self.to)
            .field("code", &"<redacted>")
            .finish()
    }
}

/// Every two-step method of an account was switched off with its recovery code. The mail tells the
/// owner, so a recovery they didn't make doesn't go unnoticed. It carries no code and no secret.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TwoStepRecoveredNotice {
    pub to: Email,
    pub at: OffsetDateTime,
}

/// A second step of the account was turned on or off from a signed-in device. The mail tells the
/// owner, so a change they didn't make doesn't go unnoticed. It names the method, nothing more.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TwoStepChangedNotice {
    pub to: Email,
    pub at: OffsetDateTime,
    /// `email`, `yubikey`, `duo` or `security-key`.
    pub method: &'static str,
    /// Turned on (true) or off (false).
    pub on: bool,
}

/// The one-time code of a protected action (exporting the vault, deleting the account, showing the
/// recovery code) when the person asked for a code instead of giving the master password. Never
/// logged.
#[derive(Clone, PartialEq, Eq)]
pub struct ProtectedActionNotice {
    pub to: Email,
    pub code: String,
}

impl fmt::Debug for ProtectedActionNotice {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ProtectedActionNotice")
            .field("to", &self.to)
            .field("code", &"<redacted>")
            .finish()
    }
}

/// The link that makes an address the account's sign-in address. The token in it is the proof that
/// the person owns the address, so it is never logged.
#[derive(Clone, PartialEq, Eq)]
pub struct EmailChangeNotice {
    /// The new address: the mail goes there.
    pub to: Email,
    /// The secret of the link, base64url.
    pub token: String,
}

impl fmt::Debug for EmailChangeNotice {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("EmailChangeNotice")
            .field("to", &self.to)
            .field("token", &"<redacted>")
            .finish()
    }
}

/// The mail that proves an address before an account is made for it (the Bitwarden API's
/// registration with `SIGNUPS_VERIFY` on). The token in it is the proof that the person owns the
/// address, so it is never logged.
#[derive(Clone, PartialEq, Eq)]
pub struct RegisterVerifyNotice {
    /// The address being registered: the mail goes there.
    pub to: Email,
    /// The signed token the registration finishes with.
    pub token: String,
}

impl fmt::Debug for RegisterVerifyNotice {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RegisterVerifyNotice")
            .field("to", &self.to)
            .field("token", &"<redacted>")
            .finish()
    }
}

/// The invitation of the Bitwarden API to an organization: a link that carries a signed token, which
/// accepts the invitation on its own (the person need not sign in, since an account made through
/// the Bitwarden API may have no other way in). The link is a secret, so it is never logged.
#[derive(Clone, PartialEq, Eq)]
pub struct BwOrgInviteNotice {
    pub to: Email,
    pub organization: String,
    pub inviter: Option<String>,
    /// `{domain}/#/accept-organization/?...&token=...`.
    pub link: String,
}

impl fmt::Debug for BwOrgInviteNotice {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("BwOrgInviteNotice")
            .field("to", &self.to)
            .field("organization", &self.organization)
            .field("link", &"<redacted>")
            .finish()
    }
}

/// The invitation of the Bitwarden API to be someone's emergency contact, with the link that
/// accepts it. The link is a secret, so it is never logged.
#[derive(Clone, PartialEq, Eq)]
pub struct BwEmergencyInviteNotice {
    pub to: Email,
    /// Who named the contact: the grantor's name or address.
    pub grantor: String,
    /// `{domain}/#/accept-emergency/?...&token=...`.
    pub link: String,
}

impl fmt::Debug for BwEmergencyInviteNotice {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("BwEmergencyInviteNotice")
            .field("to", &self.to)
            .field("grantor", &self.grantor)
            .field("link", &"<redacted>")
            .finish()
    }
}

/// A change of the sign-in address was asked for. The mail goes to the old address, so a change
/// the owner didn't ask for doesn't go unnoticed. It carries no link and no secret.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EmailChangeRequestedNotice {
    /// The address in force: the mail goes there.
    pub to: Email,
    /// The address asked for.
    pub new_address: Email,
    pub at: OffsetDateTime,
}

/// A change of the sign-in address was asked for, to an address that already has an account. The
/// mail goes to that address and says so: it carries no link and no token, so it opens nothing, and
/// whoever asked can't tell from the request that the address was taken.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EmailTakenNotice {
    /// The address asked for: the mail goes there.
    pub to: Email,
    pub at: OffsetDateTime,
}

/// The sign-in address of the account changed. The mail goes to the address it had, so a change the
/// owner didn't make doesn't go unnoticed. It carries no link and no secret.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EmailChangedNotice {
    /// The address the account had: the mail goes there.
    pub to: Email,
    /// The address the account signs in with now.
    pub new_address: Email,
    pub at: OffsetDateTime,
}

/// The master password of the account changed. The mail goes to the account's address, so a change
/// the owner didn't make doesn't go unnoticed. It carries no password and no secret.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PasswordChangedNotice {
    pub to: Email,
    pub at: OffsetDateTime,
    /// The account's other devices were signed out with the change.
    pub others_signed_out: bool,
}

/// Everything the server emails.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Notice {
    /// A new device asked to sign in: the account's owner can approve or deny it.
    ApprovalRequest(NewDeviceNotice),
    /// A device signed in that the account hadn't used before.
    NewDevice(NewDeviceNotice),
    Emergency(EmergencyNotice),
    Invitation(InvitationNotice),
    TwoStepCode(TwoStepCodeNotice),
    ProtectedAction(ProtectedActionNotice),
    /// The recovery code switched the account's two-step login off.
    TwoStepRecovered(TwoStepRecoveredNotice),
    /// A second step was turned on or off.
    TwoStepChanged(TwoStepChangedNotice),
    /// The link that confirms a new sign-in address, mailed to that address.
    EmailChange(EmailChangeNotice),
    /// A new sign-in address was asked for, mailed to the one in force.
    EmailChangeRequested(EmailChangeRequestedNotice),
    /// A new sign-in address was asked for that another account has, mailed to that address.
    EmailTaken(EmailTakenNotice),
    /// The sign-in address changed, mailed to the address it had.
    EmailChanged(EmailChangedNotice),
    /// The master password changed, mailed to the account's address.
    PasswordChanged(PasswordChangedNotice),
    /// The link that proves an address before its account is made, mailed to that address.
    RegisterVerify(RegisterVerifyNotice),
    /// An invitation to an organization of the Bitwarden API, with the link that accepts it.
    BwOrgInvite(BwOrgInviteNotice),
    /// An invitation to be an emergency contact through the Bitwarden API, with the link that
    /// accepts it.
    BwEmergencyInvite(BwEmergencyInviteNotice),
}

impl Notice {
    /// What the notice is, for logs. Never the recipient or a code.
    pub fn kind(&self) -> &'static str {
        match self {
            Notice::ApprovalRequest(_) => "approval-request",
            Notice::NewDevice(_) => "new-device",
            Notice::Emergency(_) => "emergency-access",
            Notice::Invitation(_) => "invitation",
            Notice::TwoStepCode(_) => "two-step-code",
            Notice::ProtectedAction(_) => "protected-action",
            Notice::TwoStepRecovered(_) => "two-step-recovered",
            Notice::TwoStepChanged(_) => "two-step-changed",
            Notice::EmailChange(_) => "email-change",
            Notice::EmailChangeRequested(_) => "email-change-requested",
            Notice::EmailTaken(_) => "email-taken",
            Notice::EmailChanged(_) => "email-changed",
            Notice::PasswordChanged(_) => "password-changed",
            Notice::RegisterVerify(_) => "register-verify",
            Notice::BwOrgInvite(_) => "bw-org-invite",
            Notice::BwEmergencyInvite(_) => "bw-emergency-invite",
        }
    }
}

/// A boxed future, so [`Outbox`] can be held as a trait object.
pub type BoxFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

/// Delivers notices. A failure is the outbox's to log; it never reaches the use case.
pub trait Outbox: Send + Sync {
    fn deliver(&self, notice: Notice) -> BoxFuture<'_, ()>;

    /// Delivers the notice and says whether it went out, for the few callers that refuse to go on
    /// without it (Vaultwarden's `REQUIRE_DEVICE_EMAIL`). The default can't tell, so it says yes.
    fn deliver_checked(&self, notice: Notice) -> BoxFuture<'_, Result<(), String>> {
        Box::pin(async move {
            self.deliver(notice).await;
            Ok(())
        })
    }
}

/// The notice sender the API holds. Cheap to clone. Without an outbox it only logs.
#[derive(Clone, Default)]
pub struct Notices {
    outbox: Option<Arc<dyn Outbox>>,
}

impl fmt::Debug for Notices {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Notices")
            .field("mail", &self.outbox.is_some())
            .finish()
    }
}

impl Notices {
    /// A sender that only writes log lines, for a server with no mail configured.
    pub fn logging() -> Self {
        Notices { outbox: None }
    }

    /// A sender that hands every notice to `outbox`.
    pub fn with_outbox(outbox: Arc<dyn Outbox>) -> Self {
        Notices {
            outbox: Some(outbox),
        }
    }

    /// Whether notices are really mailed: an outbox is set (SMTP is configured). Vaultwarden's
    /// `mail_enabled`.
    pub fn mails(&self) -> bool {
        self.outbox.is_some()
    }

    /// Sends a notice and says whether it went out. Without an outbox nothing is sent and nothing
    /// failed, so it says yes (check [`Notices::mails`] first to tell the cases apart).
    pub async fn send_checked(&self, notice: Notice) -> Result<(), String> {
        match &self.outbox {
            Some(outbox) => outbox.deliver_checked(notice).await,
            None => {
                self.send(notice).await;
                Ok(())
            }
        }
    }

    /// Sends a notice (or logs it, without an outbox).
    pub async fn send(&self, notice: Notice) {
        match &self.outbox {
            Some(outbox) => outbox.deliver(notice).await,
            None => {
                tracing::info!(
                    notice = notice.kind(),
                    "a notice was not emailed (no mail sender is configured)"
                );
            }
        }
    }
}

impl DeviceNotices for Notices {
    async fn new_device(&self, notice: NewDeviceNotice) {
        self.send(Notice::ApprovalRequest(notice)).await;
    }
}

impl EmergencyNotices for Notices {
    async fn notify(&self, notice: EmergencyNotice) {
        self.send(Notice::Emergency(notice)).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use kemlock_domain::DeviceKind;
    use std::sync::Mutex;
    use time::macros::datetime;

    #[derive(Default)]
    struct Collect(Mutex<Vec<Notice>>);

    impl Outbox for Collect {
        fn deliver(&self, notice: Notice) -> BoxFuture<'_, ()> {
            Box::pin(async move {
                self.0.lock().expect("lock").push(notice);
            })
        }
    }

    fn device_notice() -> NewDeviceNotice {
        NewDeviceNotice {
            to: Email::parse("ada@example.com").expect("email"),
            device_name: "Pixel".to_owned(),
            device_kind: DeviceKind::KemlockAndroid,
            ip: "203.0.113.0".to_owned(),
            at: datetime!(2026-11-23 10:00 UTC),
        }
    }

    #[tokio::test]
    async fn a_device_notice_reaches_the_outbox_as_an_approval_request() {
        let outbox = Arc::new(Collect::default());
        let notices = Notices::with_outbox(outbox.clone());
        notices.new_device(device_notice()).await;
        let seen = outbox.0.lock().expect("lock");
        assert_eq!(seen.as_slice(), &[Notice::ApprovalRequest(device_notice())]);
    }

    #[tokio::test]
    async fn without_an_outbox_a_notice_is_only_logged() {
        // Must not panic or block.
        Notices::logging().new_device(device_notice()).await;
        Notices::default().new_device(device_notice()).await;
    }

    /// An outbox whose mail never goes out.
    struct Failing;

    impl Outbox for Failing {
        fn deliver(&self, _notice: Notice) -> BoxFuture<'_, ()> {
            Box::pin(async {})
        }

        fn deliver_checked(&self, _notice: Notice) -> BoxFuture<'_, Result<(), String>> {
            Box::pin(async { Err("the server is down".to_owned()) })
        }
    }

    #[test]
    fn only_a_sender_with_an_outbox_mails() {
        assert!(!Notices::logging().mails());
        assert!(Notices::with_outbox(Arc::new(Collect::default())).mails());
    }

    #[tokio::test]
    async fn a_checked_send_reports_what_the_outbox_says() {
        let notice = Notice::NewDevice(device_notice());
        let failing = Notices::with_outbox(Arc::new(Failing));
        assert_eq!(
            failing.send_checked(notice.clone()).await,
            Err("the server is down".to_owned())
        );
        // An outbox that can't tell says yes, and still gets the notice.
        let outbox = Arc::new(Collect::default());
        let notices = Notices::with_outbox(outbox.clone());
        assert_eq!(notices.send_checked(notice.clone()).await, Ok(()));
        assert_eq!(
            outbox.0.lock().expect("lock").as_slice(),
            std::slice::from_ref(&notice)
        );
        // No mail configured is not a failure.
        assert_eq!(Notices::logging().send_checked(notice).await, Ok(()));
    }

    #[test]
    fn a_code_stays_out_of_debug_output() {
        let notice = TwoStepCodeNotice {
            to: Email::parse("ada@example.com").expect("email"),
            code: "123456".to_owned(),
        };
        assert!(!format!("{notice:?}").contains("123456"));
        assert!(!format!("{:?}", Notice::TwoStepCode(notice)).contains("123456"));
        let protected = ProtectedActionNotice {
            to: Email::parse("ada@example.com").expect("email"),
            code: "654321".to_owned(),
        };
        assert!(!format!("{protected:?}").contains("654321"));
        assert!(!format!("{:?}", Notice::ProtectedAction(protected)).contains("654321"));
        let change = EmailChangeNotice {
            to: Email::parse("ada@example.com").expect("email"),
            token: "s3cr3t-link-token".to_owned(),
        };
        assert!(!format!("{change:?}").contains("s3cr3t"));
        assert!(!format!("{:?}", Notice::EmailChange(change)).contains("s3cr3t"));
        let verify = RegisterVerifyNotice {
            to: Email::parse("ada@example.com").expect("email"),
            token: "v3rify-token".to_owned(),
        };
        assert!(!format!("{verify:?}").contains("v3rify"));
        assert!(!format!("{:?}", Notice::RegisterVerify(verify)).contains("v3rify"));
        let invite = BwOrgInviteNotice {
            to: Email::parse("ada@example.com").expect("email"),
            organization: "Family".to_owned(),
            inviter: None,
            link: "https://x/#/accept-organization/?token=l1nk-secret".to_owned(),
        };
        assert!(!format!("{invite:?}").contains("l1nk-secret"));
        assert!(!format!("{:?}", Notice::BwOrgInvite(invite)).contains("l1nk-secret"));
        let emergency = BwEmergencyInviteNotice {
            to: Email::parse("ada@example.com").expect("email"),
            grantor: "Sam".to_owned(),
            link: "https://x/#/accept-emergency/?token=l1nk-secret".to_owned(),
        };
        assert!(!format!("{:?}", Notice::BwEmergencyInvite(emergency)).contains("l1nk-secret"));
    }
}
