//! Where the Bitwarden registration meets the server's sign-up verification (`SIGNUPS_VERIFY`):
//! whether an address has to be proven first, the mail that proves it, and the refusal of an
//! account that was made but is still held until it is proven.
//!
//! Everything the Bitwarden API asks of that feature is behind the functions of this file.

use crate::app::{App, BwStore};
use crate::error::{BwError, BwResult};
use kemlock_app::notices::{Notice, RegisterVerifyNotice};
use kemlock_app::ports::UserRepo;
use kemlock_domain::{Email, User};
use std::collections::HashMap;
use std::sync::{Mutex, PoisonError};

/// Whether registration has to prove the address with a mailed link first: the setting is on and
/// the server can mail the link.
///
/// `BwSettings::signups_verify()` reads the server's `Live::signups_verify()`, which is already
/// false when no mail server is set up.
pub(crate) fn verifies<S: BwStore>(app: &App<S>) -> bool {
    app.settings.signups_verify() && app.notices.mails()
}

/// Mails the token that proves `to`'s address. The token is a Bitwarden registration token
/// (`RegisterVerifyClaims`, verified), and `register/finish` takes it back; it is never returned
/// to the asker.
///
/// This is the Bitwarden clients' own flow (the address is proven before the account is made, and
/// the link is their `finish-signup` page), so it has its own mail rather than the Kemlock side's
/// `Notice::SignupVerify`, which holds an account that already exists.
pub(crate) async fn mail_token<S: BwStore>(app: &App<S>, to: &str, token: String) {
    // An address that can't be a mailbox gets no mail, and the same answer as one that did.
    if let Ok(to) = Email::parse(to) {
        app.notices
            .send(Notice::RegisterVerify(RegisterVerifyNotice { to, token }))
            .await;
    }
}

/// Holds a new account until its address is proven.
///
/// Nothing to do: the Bitwarden registration refuses an unproven address before the account is
/// made (`register` needs the verified token), so an account it makes is never held.
#[allow(clippy::unused_async)]
pub(crate) async fn hold<S: BwStore>(_app: &App<S>, _user: &User) -> BwResult<()> {
    Ok(())
}

/// Refuses a sign-in (password or API key) of an account the Kemlock side holds until its address
/// is confirmed (`SIGNUPS_VERIFY`, an account registered through the Kemlock API), while the
/// setting is on, as the Kemlock side does. Called after the credentials checked out, so it tells
/// a stranger nothing.
pub(crate) async fn refuse_if_held<S: BwStore>(app: &App<S>, user: &User) -> BwResult<()> {
    if app.settings.signups_verify() && UserRepo::email_unconfirmed(&app.store, user.id).await? {
        return Err(BwError::msg(
            "Your email address isn't confirmed yet. Open the link that was mailed to it.",
        ));
    }
    Ok(())
}

/// The most addresses whose last mail is remembered.
const MAX_RECIPIENTS: usize = 10_000;

/// When each address was last mailed a verification link, so one address can't be mailed again and
/// again by whoever asks (the Kemlock side lets a held account have a new link every
/// [`RESEND_AFTER`](kemlock_app::signup_verify::RESEND_AFTER), and this is the same rule for an
/// address that has no account yet). Kept in memory; a restart forgets it.
#[derive(Debug, Default)]
pub(crate) struct RecipientLimit {
    last: Mutex<HashMap<String, i64>>,
}

impl RecipientLimit {
    /// Whether `to` may be mailed at `now` (Unix seconds); if so, it counts as mailed.
    pub(crate) fn take(&self, to: &str, now: i64) -> bool {
        let gap = kemlock_app::signup_verify::RESEND_AFTER.whole_seconds();
        let key = to.trim().to_lowercase();
        let mut last = self.last.lock().unwrap_or_else(PoisonError::into_inner);
        if last.get(&key).is_some_and(|at| now - at < gap) {
            return false;
        }
        if last.len() >= MAX_RECIPIENTS {
            last.retain(|_, at| now - *at < gap);
        }
        // A map still full of recent ones leaves this one out rather than refusing it: the address
        // limit is what stops a flood, and an honest asker is not turned away for it.
        if last.len() < MAX_RECIPIENTS {
            last.insert(key, now);
        }
        true
    }
}
