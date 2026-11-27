//! The words of every mail. Each notice becomes a subject, a plain-text body and an HTML body.
//!
//! A mail says enough for the account's owner to recognise their own activity and nothing that
//! could open the vault: no keys, no item names, no links that carry a secret. The links that
//! do are the one that confirms a new sign-in address and the one that verifies an address before
//! its account is made: each token proves the mailbox is the
//! person's, opens nothing by itself, and works once. Text from outside (a device name) is
//! escaped in the HTML and kept out of subjects.

use kemlock_app::devices::NewDeviceNotice;
use kemlock_app::emergency::{EmergencyEvent, EmergencyNotice};
use kemlock_app::notices::{
    BwEmergencyInviteNotice, BwOrgInviteNotice, EmailChangeNotice, EmailChangeRequestedNotice,
    EmailChangedNotice, EmailTakenNotice, EmergencyContactRekeyedNotice, InvitationNotice,
    KeysRotatedNotice, Notice, PasswordChangedNotice, ProtectedActionNotice, RegisterVerifyNotice,
    SignupVerifyNotice, TwoStepChangedNotice, TwoStepCodeNotice, TwoStepRecoveredNotice,
};
use kemlock_domain::DeviceKind;
use kemlock_domain::unlock::EmergencyKind;
use time::macros::format_description;
use time::{OffsetDateTime, UtcOffset};

/// What the mails call the server and where it is.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Branding {
    pub app_name: String,
    /// The server's public URL (`DOMAIN`), linked from the mails.
    pub domain: String,
}

impl Branding {
    pub fn new(domain: impl Into<String>) -> Self {
        Branding {
            app_name: "Kemlock".to_owned(),
            domain: domain.into(),
        }
    }
}

/// A notice, written out.
#[derive(Clone, PartialEq, Eq)]
pub struct Rendered {
    pub to: String,
    pub subject: String,
    pub text: String,
    pub html: String,
}

impl std::fmt::Debug for Rendered {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // The body can hold a sign-in code.
        f.debug_struct("Rendered")
            .field("subject", &self.subject)
            .finish_non_exhaustive()
    }
}

/// Escapes text for an HTML body.
pub(crate) fn escape(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for c in text.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#39;"),
            other => out.push(other),
        }
    }
    out
}

/// Drops control characters and cuts to 80 characters, for text that came from a client.
fn plain(text: &str) -> String {
    text.chars().filter(|c| !c.is_control()).take(80).collect()
}

fn when(at: OffsetDateTime) -> String {
    at.to_offset(UtcOffset::UTC)
        .format(format_description!(
            "[year]-[month]-[day] [hour]:[minute] UTC"
        ))
        .unwrap_or_default()
}

fn kind_label(kind: DeviceKind) -> &'static str {
    match kind {
        DeviceKind::KemlockAndroid => "Kemlock for Android",
        DeviceKind::KemlockIos => "Kemlock for iOS",
        DeviceKind::KemlockWeb => "Kemlock web vault",
        DeviceKind::KemlockBrowser => "Kemlock for browsers",
        DeviceKind::KemlockCli => "Kemlock command line",
        DeviceKind::Amethystora => "Amethystora Vault",
        DeviceKind::Bitwarden => "a Bitwarden app",
        DeviceKind::Other => "an app",
    }
}

/// The paragraphs of a mail: each is shown as a text paragraph and as an escaped HTML one.
struct Body {
    paragraphs: Vec<String>,
}

impl Body {
    fn new(paragraphs: &[&str]) -> Self {
        Body {
            paragraphs: paragraphs.iter().map(|p| (*p).to_owned()).collect(),
        }
    }

    fn text(&self, brand: &Branding) -> String {
        let mut out = self.paragraphs.join("\n\n");
        out.push_str("\n\n--\n");
        out.push_str(&brand.app_name);
        out.push(' ');
        out.push_str(&brand.domain);
        out.push('\n');
        out
    }

    fn html(&self, brand: &Branding) -> String {
        let mut out = String::from(
            "<!doctype html><html><body style=\"font-family:sans-serif;line-height:1.5;color:#222\">",
        );
        for paragraph in &self.paragraphs {
            out.push_str("<p>");
            out.push_str(&escape(paragraph).replace('\n', "<br>"));
            out.push_str("</p>");
        }
        out.push_str("<hr><p style=\"color:#666\">");
        out.push_str(&escape(&brand.app_name));
        out.push_str(" &middot; <a href=\"");
        out.push_str(&escape(&brand.domain));
        out.push_str("\">");
        out.push_str(&escape(&brand.domain));
        out.push_str("</a></p></body></html>");
        out
    }
}

fn finish(to: &str, subject: String, body: &Body, brand: &Branding) -> Rendered {
    Rendered {
        to: to.to_owned(),
        subject,
        text: body.text(brand),
        html: body.html(brand),
    }
}

fn device_facts(notice: &NewDeviceNotice) -> String {
    format!(
        "Device: {}\nApp: {}\nAddress: {}\nTime: {}",
        plain(&notice.device_name),
        kind_label(notice.device_kind),
        plain(&notice.ip),
        when(notice.at),
    )
}

fn approval_request(notice: &NewDeviceNotice, brand: &Branding) -> Rendered {
    let facts = device_facts(notice);
    let body = Body::new(&[
        "A device asked to sign in to your account and is waiting for approval.",
        &facts,
        "To let it in, open the app on a device you are already signed in on and approve the \
         request. If this wasn't you, deny it, and change your password.",
    ]);
    finish(
        notice.to.as_str(),
        format!("Approve a new device for your {} account", brand.app_name),
        &body,
        brand,
    )
}

fn new_device(notice: &NewDeviceNotice, brand: &Branding) -> Rendered {
    let facts = device_facts(notice);
    let body = Body::new(&[
        "Your account was signed in to from a device it hadn't used before.",
        &facts,
        "If this was you, there is nothing to do. If it wasn't, sign the device out in your \
         account's device list and change your password.",
    ]);
    finish(
        notice.to.as_str(),
        format!("New sign-in to your {} account", brand.app_name),
        &body,
        brand,
    )
}

fn access_label(kind: EmergencyKind) -> &'static str {
    match kind {
        EmergencyKind::View => "view access",
        EmergencyKind::Takeover => "takeover access",
    }
}

fn emergency(notice: &EmergencyNotice, brand: &Branding) -> Rendered {
    let access = access_label(notice.kind);
    let days = notice.wait_days;
    let (subject, lead) = match notice.event {
        EmergencyEvent::Invited => (
            "You were named an emergency contact",
            format!(
                "Someone named you as an emergency contact for their vault, with {access} after \
                 a waiting time of {days} days. Open {} to accept or decline.",
                brand.app_name
            ),
        ),
        EmergencyEvent::Accepted => (
            "An emergency contact accepted",
            "A person you named as an emergency contact accepted. They are not trusted until \
             you confirm their key fingerprint in the app."
                .to_owned(),
        ),
        EmergencyEvent::Confirmed => (
            "You are now an emergency contact",
            format!(
                "You were confirmed as an emergency contact, with {access}. You can ask for \
                 access from the app; the owner then has {days} days to refuse."
            ),
        ),
        EmergencyEvent::RecoveryInitiated => (
            "Emergency access was requested",
            format!(
                "Your emergency contact asked for {access} to your vault. It is granted in \
                 {days} days unless you refuse. If this isn't right, open the app and reject \
                 the request now."
            ),
        ),
        EmergencyEvent::Approved => (
            "Emergency access was granted",
            format!("The waiting time of {days} days is over and {access} is granted."),
        ),
        EmergencyEvent::Rejected => (
            "Emergency access was refused",
            "The owner refused your request for emergency access.".to_owned(),
        ),
    };
    let body = Body::new(&[&lead]);
    finish(
        notice.to.as_str(),
        format!("{} - {subject}", brand.app_name),
        &body,
        brand,
    )
}

fn invitation(notice: &InvitationNotice, brand: &Branding) -> Rendered {
    let who = notice
        .inviter
        .as_deref()
        .map(plain)
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "Someone".to_owned());
    let what = notice
        .space
        .as_deref()
        .map(plain)
        .filter(|s| !s.is_empty())
        .map_or_else(
            || "a shared space".to_owned(),
            |s| format!("the shared space \"{s}\""),
        );
    let lead = format!("{who} invited you to {what} on {}.", brand.app_name);
    // The link carries only the space's id: the invitee signs in to accept.
    let accept = match notice.space_id {
        Some(space) => format!(
            "Open {}/spaces/{space} and sign in to accept.",
            brand.domain.trim_end_matches('/')
        ),
        None => "Sign in to accept.".to_owned(),
    };
    let body = Body::new(&[
        &lead,
        &accept,
        "You get access to its items once an admin has checked your key fingerprint.",
    ]);
    finish(
        notice.to.as_str(),
        format!("You were invited to a space on {}", brand.app_name),
        &body,
        brand,
    )
}

fn two_step_code(notice: &TwoStepCodeNotice, brand: &Branding) -> Rendered {
    let lead = format!("Your sign-in code is {}", plain(&notice.code));
    let body = Body::new(&[
        &lead,
        "It works once and runs out in a few minutes. If you didn't try to sign in, ignore this \
         mail and consider changing your password.",
    ]);
    finish(
        notice.to.as_str(),
        format!("Your {} sign-in code", brand.app_name),
        &body,
        brand,
    )
}

fn two_step_recovered(notice: &TwoStepRecoveredNotice, brand: &Branding) -> Rendered {
    let lead = format!(
        "The recovery code of your account was used on {}, and every two-step method was \
         switched off.",
        when(notice.at)
    );
    let body = Body::new(&[
        &lead,
        "If this was you, set two-step login up again in your account settings. If it wasn't, \
         someone has your recovery code: sign in, change your password and turn two-step login \
         back on.",
    ]);
    finish(
        notice.to.as_str(),
        format!(
            "Two-step login was switched off on your {} account",
            brand.app_name
        ),
        &body,
        brand,
    )
}

fn two_step_changed(notice: &TwoStepChangedNotice, brand: &Branding) -> Rendered {
    let what = match notice.method {
        "email" => "emailed codes",
        "yubikey" => "a YubiKey",
        "duo" => "Duo",
        "totp" => "an authenticator app",
        _ => "a security key",
    };
    // A passkey signs in on its own, so it is a way into the account, not a second step.
    let passkey = notice.method == "passkey";
    let verb = if notice.on { "turned on" } else { "turned off" };
    let (lead, subject) = if passkey {
        let (done, to_from) = if notice.on {
            ("added", "to")
        } else {
            ("removed", "from")
        };
        (
            format!(
                "On {}, a passkey was {done} {to_from} your account. It can sign in without your \
                 password.",
                when(notice.at)
            ),
            format!("A passkey was {done} {to_from} your {} account", brand.app_name),
        )
    } else {
        (
            format!(
                "On {}, {what} was {verb} as a second step of your account.",
                when(notice.at)
            ),
            format!(
                "A second step was {verb} on your {} account",
                brand.app_name
            ),
        )
    };
    let body = Body::new(&[
        &lead,
        "If this was you, there is nothing to do. If it wasn't, someone is signed in to your account: sign in, change your password and check your devices.",
    ]);
    finish(notice.to.as_str(), subject, &body, brand)
}

fn protected_action(notice: &ProtectedActionNotice, brand: &Branding) -> Rendered {
    let lead = format!("Your verification code is {}", plain(&notice.code));
    let body = Body::new(&[
        &lead,
        "Enter it to confirm the action you asked for, such as showing your recovery code or \
         changing a two-step setting. It works for a few minutes. If you didn't ask for it, \
         ignore this mail and consider changing your password.",
    ]);
    finish(
        notice.to.as_str(),
        format!("Your {} verification code", brand.app_name),
        &body,
        brand,
    )
}

fn email_change(notice: &EmailChangeNotice, brand: &Branding) -> Rendered {
    // The token is base64url, so it needs no escaping in an address.
    let link = format!(
        "{}/confirm-email?token={}",
        brand.domain.trim_end_matches('/'),
        notice.token
    );
    let body = Body::new(&[
        "Open this link to make this address the one you sign in with:",
        &link,
        "It works once and runs out in 24 hours. Until you open it nothing changes, and after you do, every device signs in again with the new address. If you didn't ask for this, ignore this mail.",
    ]);
    finish(
        notice.to.as_str(),
        format!("Confirm your new {} sign-in address", brand.app_name),
        &body,
        brand,
    )
}

fn signup_verify(notice: &SignupVerifyNotice, brand: &Branding) -> Rendered {
    // The token is base64url, so it needs no escaping in an address.
    let link = format!(
        "{}/kem/v1/accounts/confirm-email?token={}",
        brand.domain.trim_end_matches('/'),
        notice.token
    );
    let body = Body::new(&[
        "Open this link to confirm that this is your address and finish making your account:",
        &link,
        "It works once and runs out in 24 hours. Until you open it the account can't be used. If you didn't make an account, ignore this mail.",
    ]);
    finish(
        notice.to.as_str(),
        format!("Confirm your {} account", brand.app_name),
        &body,
        brand,
    )
}

fn email_change_requested(notice: &EmailChangeRequestedNotice, brand: &Branding) -> Rendered {
    let lead = format!(
        "On {}, a change of the sign-in address of your account to {} was asked for.",
        when(notice.at),
        notice.new_address.as_str()
    );
    let body = Body::new(&[
        &lead,
        "Nothing changes until the link mailed to that address is opened. If this was you, there is nothing to do. If it wasn't, someone is signed in to your account: sign in, change your password and check your devices.",
    ]);
    finish(
        notice.to.as_str(),
        format!(
            "A new sign-in address was asked for on your {} account",
            brand.app_name
        ),
        &body,
        brand,
    )
}

fn email_taken(notice: &EmailTakenNotice, brand: &Branding) -> Rendered {
    let lead = format!(
        "On {}, someone asked to use this address as the sign-in address of another {} account.",
        when(notice.at),
        brand.app_name
    );
    let body = Body::new(&[
        &lead,
        "This address already has an account, so nothing was changed and there is no link to open. If it was you, sign in with this address as you always do. If it wasn't, ignore this mail: no one can use your account because of it.",
    ]);
    finish(
        notice.to.as_str(),
        format!("This address already has a {} account", brand.app_name),
        &body,
        brand,
    )
}

fn email_changed(notice: &EmailChangedNotice, brand: &Branding) -> Rendered {
    let lead = format!(
        "On {}, the sign-in address of your account was changed to {}.",
        when(notice.at),
        notice.new_address.as_str()
    );
    let body = Body::new(&[
        &lead,
        "Every device was signed out and signs in again with the new address. If this was you, there is nothing to do. If it wasn't, someone has your account: ask your server's admin for help right away.",
    ]);
    finish(
        notice.to.as_str(),
        format!(
            "The sign-in address of your {} account changed",
            brand.app_name
        ),
        &body,
        brand,
    )
}

fn password_changed(notice: &PasswordChangedNotice, brand: &Branding) -> Rendered {
    let lead = format!(
        "On {}, the master password of your account was changed.",
        when(notice.at)
    );
    let devices = if notice.others_signed_out {
        "Your other devices were signed out and ask for the new password."
    } else {
        "Your other devices stay signed in and ask for the new password the next time they open."
    };
    let body = Body::new(&[
        &lead,
        devices,
        "If this was you, there is nothing to do. If it wasn't, someone is signed in to your account: sign in, change your password and check your devices.",
    ]);
    finish(
        notice.to.as_str(),
        format!(
            "The master password of your {} account changed",
            brand.app_name
        ),
        &body,
        brand,
    )
}

fn keys_rotated(notice: &KeysRotatedNotice, brand: &Branding) -> Rendered {
    let lead = format!(
        "On {}, the keys of your account were rotated: a new root key now protects your vault, and every copy of the old one that this server held was deleted.",
        when(notice.at)
    );
    let body = Body::new(&[
        &lead,
        "Your other devices were signed out and ask you to sign in again. A Recovery Kit made before this stopped working; if you made a new one, it is the one to keep.",
        "If this was you, there is nothing to do. If it wasn't, someone is signed in to your account: sign in, change your password and check your devices.",
    ]);
    finish(
        notice.to.as_str(),
        format!("The keys of your {} account were rotated", brand.app_name),
        &body,
        brand,
    )
}

/// Tells a grantor that their emergency contact rotated their keys, so the contact has to be
/// confirmed again. It carries no key and no link.
fn emergency_contact_rekeyed(notice: &EmergencyContactRekeyedNotice, brand: &Branding) -> Rendered {
    let lead = format!(
        "On {}, your emergency contact {} replaced the keys of their account.",
        when(notice.at),
        plain(notice.contact.as_str())
    );
    let body = Body::new(&[
        &lead,
        "The copy of your vault key that you sealed for them opens no more, and it was deleted. They have no emergency access to your vault until you confirm them again: open Emergency access, check their new key fingerprint with them, and confirm.",
        "If you don't know why their keys changed, don't confirm them until you have asked them.",
    ]);
    finish(
        notice.to.as_str(),
        format!(
            "Your emergency contact replaced their keys on {}",
            brand.app_name
        ),
        &body,
        brand,
    )
}

/// The mail of a registration that has to prove its address first. The link is the Bitwarden web
/// vault's `finish-signup`; its token proves the mailbox is the person's, and works for 30 minutes.
fn register_verify(notice: &RegisterVerifyNotice, brand: &Branding) -> Rendered {
    let email: String =
        url::form_urlencoded::byte_serialize(notice.to.as_str().as_bytes()).collect();
    let link = format!(
        "{}/#/finish-signup/?token={}&email={}",
        brand.domain.trim_end_matches('/'),
        notice.token,
        email
    );
    let body = Body::new(&[
        "Open this link to verify this address and finish creating your account:",
        &link,
        "It runs out in 30 minutes. If you didn't ask for an account, ignore this mail.",
    ]);
    finish(
        notice.to.as_str(),
        format!("Verify your email for {}", brand.app_name),
        &body,
        brand,
    )
}

/// The invitation of the Bitwarden API to an organization. The link carries the signed token that
/// accepts it, so opening it is all the person has to do; it runs out in five days.
fn bw_org_invite(notice: &BwOrgInviteNotice, brand: &Branding) -> Rendered {
    let who = notice
        .inviter
        .as_deref()
        .map(plain)
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "Someone".to_owned());
    let lead = format!(
        "{who} invited you to join the organization \"{}\" on {}.",
        plain(&notice.organization),
        brand.app_name
    );
    let body = Body::new(&[
        &lead,
        "Open this link to accept the invitation:",
        &notice.link,
        "It runs out in five days. An administrator then confirms you before you can see anything in it. If you don't know who this is from, ignore this mail.",
    ]);
    finish(
        notice.to.as_str(),
        format!("You were invited to an organization on {}", brand.app_name),
        &body,
        brand,
    )
}

/// The invitation of the Bitwarden API to be an emergency contact.
fn bw_emergency_invite(notice: &BwEmergencyInviteNotice, brand: &Branding) -> Rendered {
    let lead = format!(
        "{} named you as an emergency contact on {}.",
        plain(&notice.grantor),
        brand.app_name
    );
    let body = Body::new(&[
        &lead,
        "Open this link to accept:",
        &notice.link,
        "It runs out in five days. Accepting gives you nothing yet: they confirm you, and you may later ask for access, which they can refuse during the wait they chose. If you don't know who this is from, ignore this mail.",
    ]);
    finish(
        notice.to.as_str(),
        format!("You were named an emergency contact on {}", brand.app_name),
        &body,
        brand,
    )
}

/// Writes a notice out as a mail.
pub fn render(notice: &Notice, brand: &Branding) -> Rendered {
    match notice {
        Notice::ApprovalRequest(n) => approval_request(n, brand),
        Notice::NewDevice(n) => new_device(n, brand),
        Notice::Emergency(n) => emergency(n, brand),
        Notice::Invitation(n) => invitation(n, brand),
        Notice::TwoStepCode(n) => two_step_code(n, brand),
        Notice::ProtectedAction(n) => protected_action(n, brand),
        Notice::TwoStepRecovered(n) => two_step_recovered(n, brand),
        Notice::TwoStepChanged(n) => two_step_changed(n, brand),
        Notice::EmailChange(n) => email_change(n, brand),
        Notice::EmailChangeRequested(n) => email_change_requested(n, brand),
        Notice::EmailTaken(n) => email_taken(n, brand),
        Notice::EmailChanged(n) => email_changed(n, brand),
        Notice::PasswordChanged(n) => password_changed(n, brand),
        Notice::KeysRotated(n) => keys_rotated(n, brand),
        Notice::EmergencyContactRekeyed(n) => emergency_contact_rekeyed(n, brand),
        Notice::SignupVerify(n) => signup_verify(n, brand),
        Notice::RegisterVerify(n) => register_verify(n, brand),
        Notice::BwOrgInvite(n) => bw_org_invite(n, brand),
        Notice::BwEmergencyInvite(n) => bw_emergency_invite(n, brand),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use kemlock_domain::Email;
    use kemlock_domain::unlock::GrantId;
    use time::macros::datetime;

    fn brand() -> Branding {
        Branding::new("https://vault.example.com")
    }

    fn email() -> Email {
        Email::parse("ada@example.com").expect("email")
    }

    fn device(name: &str) -> NewDeviceNotice {
        NewDeviceNotice {
            to: email(),
            device_name: name.to_owned(),
            device_kind: DeviceKind::KemlockIos,
            ip: "203.0.113.0".to_owned(),
            at: datetime!(2026-11-23 10:05 +01:00),
        }
    }

    #[test]
    fn a_browser_extension_is_named_as_such_in_the_device_facts() {
        let mut notice = device("Kemlock for browsers, Firefox");
        notice.device_kind = DeviceKind::KemlockBrowser;
        let facts = device_facts(&notice);
        assert!(facts.contains("App: Kemlock for browsers\n"), "{facts}");
        assert!(!facts.contains("web vault"));
    }

    fn emergency_notice(event: EmergencyEvent, kind: EmergencyKind) -> Notice {
        Notice::Emergency(EmergencyNotice {
            to: email(),
            grant: GrantId::random(),
            event,
            kind,
            wait_days: 7,
        })
    }

    #[test]
    fn an_approval_request_names_the_device_and_the_time_in_utc() {
        let r = render(&Notice::ApprovalRequest(device("Ada's phone")), &brand());
        assert_eq!(r.to, "ada@example.com");
        assert_eq!(r.subject, "Approve a new device for your Kemlock account");
        assert!(r.text.contains("Device: Ada's phone"));
        assert!(r.text.contains("Kemlock for iOS"));
        assert!(r.text.contains("203.0.113.0"));
        assert!(r.text.contains("2026-11-23 09:05 UTC"));
        assert!(r.text.contains("https://vault.example.com"));
        assert!(r.html.contains("Ada&#39;s phone"));
    }

    #[test]
    fn a_hostile_device_name_is_escaped_and_stays_out_of_the_subject() {
        let name = "<script>alert(1)</script>\r\nBcc: x@evil.test";
        for notice in [
            Notice::ApprovalRequest(device(name)),
            Notice::NewDevice(device(name)),
        ] {
            let r = render(&notice, &brand());
            assert!(!r.html.contains("<script>"), "{}", r.html);
            assert!(r.html.contains("&lt;script&gt;"));
            assert!(!r.subject.contains("script"));
            assert!(!r.subject.contains('\n'));
            // Control characters never reach the text body either.
            assert!(!r.text.contains('\r'));
        }
    }

    #[test]
    fn a_new_device_notice_is_not_an_approval_request() {
        let r = render(&Notice::NewDevice(device("Pixel")), &brand());
        assert_eq!(r.subject, "New sign-in to your Kemlock account");
        assert!(r.text.contains("hadn't used before"));
    }

    #[test]
    fn each_emergency_event_has_its_own_subject() {
        let events = [
            EmergencyEvent::Invited,
            EmergencyEvent::Accepted,
            EmergencyEvent::Confirmed,
            EmergencyEvent::RecoveryInitiated,
            EmergencyEvent::Approved,
            EmergencyEvent::Rejected,
        ];
        let mut subjects: Vec<String> = events
            .into_iter()
            .map(|event| {
                render(&emergency_notice(event, EmergencyKind::Takeover), &brand()).subject
            })
            .collect();
        assert!(subjects.iter().all(|s| s.starts_with("Kemlock - ")));
        subjects.sort();
        subjects.dedup();
        assert_eq!(subjects.len(), 6);
    }

    #[test]
    fn an_emergency_request_states_the_wait_and_the_kind_of_access() {
        let r = render(
            &emergency_notice(EmergencyEvent::RecoveryInitiated, EmergencyKind::View),
            &brand(),
        );
        assert!(r.text.contains("7 days"));
        assert!(r.text.contains("view access"));
    }

    #[test]
    fn an_invitation_works_without_names() {
        let bare = render(
            &Notice::Invitation(InvitationNotice {
                to: email(),
                space: None,
                inviter: None,
                space_id: None,
            }),
            &brand(),
        );
        assert!(
            bare.text
                .contains("Someone invited you to a shared space on Kemlock.")
        );
        let named = render(
            &Notice::Invitation(InvitationNotice {
                to: email(),
                space: Some("Family <3".to_owned()),
                inviter: Some("Grace".to_owned()),
                space_id: None,
            }),
            &brand(),
        );
        assert!(
            named
                .text
                .contains("Grace invited you to the shared space \"Family <3\"")
        );
        assert!(named.html.contains("Family &lt;3"));
    }

    #[test]
    fn an_invitation_carries_the_link_to_its_space() {
        let space = kemlock_domain::SpaceId::random();
        let r = render(
            &Notice::Invitation(InvitationNotice {
                to: email(),
                space: None,
                inviter: Some("Grace".to_owned()),
                space_id: Some(space),
            }),
            &Branding::new("https://vault.example.com/"),
        );
        let link = format!("https://vault.example.com/spaces/{space}");
        assert!(r.text.contains(&link), "{}", r.text);
        assert!(r.html.contains(&link));
        // The link is the id and nothing that opens the space without signing in.
        assert!(!r.text.contains("token"));
        let without = render(
            &Notice::Invitation(InvitationNotice {
                to: email(),
                space: None,
                inviter: None,
                space_id: None,
            }),
            &brand(),
        );
        assert!(without.text.contains("Sign in to accept."));
        assert!(!without.text.contains("/spaces/"));
    }

    #[test]
    fn a_code_mail_carries_the_code_in_the_body_only() {
        let r = render(
            &Notice::TwoStepCode(TwoStepCodeNotice {
                to: email(),
                code: "482913".to_owned(),
            }),
            &brand(),
        );
        assert!(r.text.contains("482913"));
        assert!(r.html.contains("482913"));
        assert!(!r.subject.contains("482913"));
        assert!(!format!("{r:?}").contains("482913"));
    }

    #[test]
    fn a_protected_action_mail_carries_the_code_in_the_body_only() {
        let r = render(
            &Notice::ProtectedAction(ProtectedActionNotice {
                to: email(),
                code: "730184".to_owned(),
            }),
            &brand(),
        );
        assert_eq!(r.to, "ada@example.com");
        assert!(r.text.contains("Your verification code is 730184"));
        assert!(r.html.contains("730184"));
        assert!(!r.subject.contains("730184"));
        assert!(!format!("{r:?}").contains("730184"));
    }

    #[test]
    fn a_recovery_mail_says_when_and_carries_no_code() {
        let r = render(
            &Notice::TwoStepRecovered(TwoStepRecoveredNotice {
                to: email(),
                at: datetime!(2026-11-26 10:05 +01:00),
            }),
            &brand(),
        );
        assert_eq!(r.to, "ada@example.com");
        assert_eq!(
            r.subject,
            "Two-step login was switched off on your Kemlock account"
        );
        assert!(r.text.contains("2026-11-26 09:05 UTC"), "{}", r.text);
        assert!(r.text.contains("recovery code"));
        assert!(r.html.contains("2026-11-26 09:05 UTC"));
    }

    #[test]
    fn a_changed_second_step_is_named_and_dated() {
        let r = render(
            &Notice::TwoStepChanged(TwoStepChangedNotice {
                to: email(),
                at: datetime!(2026-11-26 10:05 +01:00),
                method: "duo",
                on: false,
            }),
            &brand(),
        );
        assert_eq!(
            r.subject,
            "A second step was turned off on your Kemlock account"
        );
        assert!(r.text.contains("Duo was turned off"), "{}", r.text);
        assert!(r.text.contains("2026-11-26 09:05 UTC"));
    }


    #[test]
    fn a_turned_on_authenticator_app_and_a_new_passkey_are_named() {
        let render_for = |method, on| {
            render(
                &Notice::TwoStepChanged(TwoStepChangedNotice {
                    to: email(),
                    at: datetime!(2026-11-26 10:05 +01:00),
                    method,
                    on,
                }),
                &brand(),
            )
        };
        let totp = render_for("totp", true);
        assert_eq!(
            totp.subject,
            "A second step was turned on on your Kemlock account"
        );
        assert!(
            totp.text.contains("an authenticator app was turned on"),
            "{}",
            totp.text
        );
        let passkey = render_for("passkey", true);
        assert_eq!(
            passkey.subject,
            "A passkey was added to your Kemlock account"
        );
        assert!(
            passkey.text.contains("a passkey was added to your account"),
            "{}",
            passkey.text
        );
        assert!(
            render_for("passkey", false)
                .text
                .contains("a passkey was removed from your account")
        );
    }
    #[test]
    fn the_mail_to_a_new_address_carries_the_link_and_nothing_else_that_opens_anything() {
        let r = render(
            &Notice::EmailChange(EmailChangeNotice {
                to: Email::parse("new@example.com").expect("email"),
                token: "tok_en-123".to_owned(),
            }),
            &Branding::new("https://vault.example.com/"),
        );
        assert_eq!(r.to, "new@example.com");
        assert_eq!(r.subject, "Confirm your new Kemlock sign-in address");
        let link = "https://vault.example.com/confirm-email?token=tok_en-123";
        assert!(r.text.contains(link), "{}", r.text);
        assert!(r.html.contains(link), "{}", r.html);
        assert!(!r.subject.contains("tok_en"));
        assert!(!format!("{r:?}").contains("tok_en"));
    }

    #[test]
    fn the_mail_to_a_new_account_carries_the_link_and_the_token_nowhere_else() {
        let r = render(
            &Notice::SignupVerify(SignupVerifyNotice {
                to: email(),
                token: "tok_en-456".to_owned(),
            }),
            &Branding::new("https://vault.example.com/"),
        );
        assert_eq!(r.to, "ada@example.com");
        assert_eq!(r.subject, "Confirm your Kemlock account");
        let link = "https://vault.example.com/kem/v1/accounts/confirm-email?token=tok_en-456";
        assert!(r.text.contains(link), "{}", r.text);
        assert!(r.html.contains(link), "{}", r.html);
        assert!(!r.subject.contains("tok_en"));
        assert!(!format!("{r:?}").contains("tok_en"));
    }

    #[test]
    fn the_verification_mail_carries_the_link_with_the_address_encoded() {
        let r = render(
            &Notice::RegisterVerify(RegisterVerifyNotice {
                to: Email::parse("new.tag@example.com").expect("email"),
                token: "tok_en-123.sig".to_owned(),
            }),
            &Branding::new("https://vault.example.com/"),
        );
        assert_eq!(r.to, "new.tag@example.com");
        assert_eq!(r.subject, "Verify your email for Kemlock");
        let link = "https://vault.example.com/#/finish-signup/?token=tok_en-123.sig&email=new.tag%40example.com";
        assert!(r.text.contains(link), "{}", r.text);
        assert!(!r.subject.contains("tok_en"));
        assert!(!format!("{r:?}").contains("tok_en"));
    }

    #[test]
    fn the_bitwarden_invitations_carry_their_links() {
        let link = "https://vault.example.com/#/accept-organization/?organizationId=o&token=tok.en";
        let r = render(
            &Notice::BwOrgInvite(BwOrgInviteNotice {
                to: email(),
                organization: "Family".to_owned(),
                inviter: Some("sam@example.com".to_owned()),
                link: link.to_owned(),
            }),
            &brand(),
        );
        assert_eq!(r.to, "ada@example.com");
        assert!(r.text.contains(link), "{}", r.text);
        assert!(r.text.contains("sam@example.com invited you"), "{}", r.text);
        assert!(r.text.contains("\"Family\""));
        assert!(!r.subject.contains("tok.en"));
        assert!(!format!("{r:?}").contains("tok.en"));

        let link = "https://vault.example.com/#/accept-emergency/?id=g&token=tok.en";
        let r = render(
            &Notice::BwEmergencyInvite(BwEmergencyInviteNotice {
                to: email(),
                grantor: "Sam".to_owned(),
                link: link.to_owned(),
            }),
            &brand(),
        );
        assert!(r.text.contains(link), "{}", r.text);
        assert!(r.text.contains("Sam named you as an emergency contact"));
        assert!(!r.subject.contains("tok.en"));
    }

    #[test]
    fn the_mail_to_the_old_address_names_the_new_one_and_carries_no_link() {
        let r = render(
            &Notice::EmailChangeRequested(EmailChangeRequestedNotice {
                to: email(),
                new_address: Email::parse("new@example.com").expect("email"),
                at: datetime!(2026-11-26 10:05 +01:00),
            }),
            &brand(),
        );
        assert_eq!(r.to, "ada@example.com");
        assert_eq!(
            r.subject,
            "A new sign-in address was asked for on your Kemlock account"
        );
        assert!(r.text.contains("new@example.com"), "{}", r.text);
        assert!(r.text.contains("2026-11-26 09:05 UTC"));
        assert!(!r.text.contains("confirm-email"));
    }

    #[test]
    fn the_mail_to_an_address_that_has_an_account_says_so_and_carries_no_link() {
        let r = render(
            &Notice::EmailTaken(EmailTakenNotice {
                to: Email::parse("kim@example.com").expect("email"),
                at: datetime!(2026-11-26 10:05 +01:00),
            }),
            &brand(),
        );
        assert_eq!(r.to, "kim@example.com");
        assert_eq!(r.subject, "This address already has a Kemlock account");
        assert!(r.text.contains("already has an account"), "{}", r.text);
        assert!(r.text.contains("nothing was changed"), "{}", r.text);
        assert!(r.text.contains("2026-11-26 09:05 UTC"));
        assert!(!r.text.contains("confirm-email"));
        assert!(!r.html.contains("confirm-email"));
        assert!(!r.text.contains("token"));
    }

    #[test]
    fn the_mail_to_the_old_address_after_a_change_names_the_new_one_and_carries_no_link() {
        let r = render(
            &Notice::EmailChanged(EmailChangedNotice {
                to: email(),
                new_address: Email::parse("new@example.com").expect("email"),
                at: datetime!(2026-11-26 10:05 +01:00),
            }),
            &brand(),
        );
        assert_eq!(r.to, "ada@example.com");
        assert_eq!(
            r.subject,
            "The sign-in address of your Kemlock account changed"
        );
        assert!(r.text.contains("new@example.com"), "{}", r.text);
        assert!(r.text.contains("2026-11-26 09:05 UTC"));
        assert!(!r.text.contains("confirm-email"));
    }

    #[test]
    fn the_mail_about_rotated_keys_says_what_happened_and_holds_no_secret() {
        let rendered = render(
            &Notice::KeysRotated(KeysRotatedNotice {
                to: email(),
                at: datetime!(2026-12-02 10:05 +01:00),
            }),
            &brand(),
        );
        assert_eq!(rendered.to, "ada@example.com");
        assert_eq!(
            rendered.subject,
            "The keys of your Kemlock account were rotated"
        );
        assert!(
            rendered.text.contains("2026-12-02 09:05 UTC"),
            "{}",
            rendered.text
        );
        assert!(rendered.text.contains("other devices were signed out"));
        assert!(rendered.text.contains("If it wasn't"));
    }

    #[test]
    fn the_mail_to_a_grantor_whose_contact_rotated_says_to_confirm_the_contact_again() {
        let rendered = render(
            &Notice::EmergencyContactRekeyed(EmergencyContactRekeyedNotice {
                to: email(),
                contact: Email::parse("sam@example.org").expect("email"),
                at: datetime!(2026-12-02 10:05 +01:00),
            }),
            &brand(),
        );
        assert_eq!(rendered.to, "ada@example.com");
        assert_eq!(
            rendered.subject,
            "Your emergency contact replaced their keys on Kemlock"
        );
        assert!(rendered.text.contains("sam@example.org"), "{}", rendered.text);
        assert!(rendered.text.contains("2026-12-02 09:05 UTC"));
        assert!(rendered.text.contains("Emergency access"));
        assert!(rendered.text.contains("confirm them again"));
    }

    #[test]
    fn the_mail_about_a_new_password_says_what_happened_to_the_other_devices() {
        let render_with = |others_signed_out| {
            render(
                &Notice::PasswordChanged(PasswordChangedNotice {
                    to: email(),
                    at: datetime!(2026-11-26 10:05 +01:00),
                    others_signed_out,
                }),
                &brand(),
            )
        };
        let signed_out = render_with(true);
        assert_eq!(signed_out.to, "ada@example.com");
        assert_eq!(
            signed_out.subject,
            "The master password of your Kemlock account changed"
        );
        assert!(signed_out.text.contains("2026-11-26 09:05 UTC"));
        assert!(signed_out.text.contains("other devices were signed out"));
        let kept = render_with(false);
        assert!(kept.text.contains("stay signed in"), "{}", kept.text);
        assert!(!kept.text.contains("confirm-email"), "{}", kept.text);
    }

    #[test]
    fn escaping_covers_the_five_characters() {
        assert_eq!(
            escape(r#"<a href="x">&'"#),
            "&lt;a href=&quot;x&quot;&gt;&amp;&#39;"
        );
    }
}
