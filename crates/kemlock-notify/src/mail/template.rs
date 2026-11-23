//! The words of every mail. Each notice becomes a subject, a plain-text body and an HTML body.
//!
//! A mail says enough for the account's owner to recognise their own activity and nothing that
//! could open the vault: no keys, no item names, no links that carry a secret. Text from outside
//! (a device name) is escaped in the HTML and kept out of subjects.

use kemlock_app::devices::NewDeviceNotice;
use kemlock_app::emergency::{EmergencyEvent, EmergencyNotice};
use kemlock_app::notices::{
    InvitationNotice, Notice, ProtectedActionNotice, TwoStepCodeNotice, TwoStepRecoveredNotice,
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
    fn escaping_covers_the_five_characters() {
        assert_eq!(
            escape(r#"<a href="x">&'"#),
            "&lt;a href=&quot;x&quot;&gt;&amp;&#39;"
        );
    }
}
