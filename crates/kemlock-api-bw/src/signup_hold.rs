//! Where the Bitwarden registration meets the server's sign-up verification (`SIGNUPS_VERIFY`):
//! whether an address has to be proven first, the mail that proves it, and the refusal of an
//! account that was made but is still held until it is proven.
//!
//! Everything the Bitwarden API asks of that feature is behind the functions of this file, so the
//! branch that implements it on the Kemlock side (`SignupVerify`, `UserRepo::hold_unconfirmed`,
//! `Notice::SignupVerify`) can be pointed at it in one place. Each `MERGE:` comment says what the
//! function does today and what it should call.

use crate::app::{App, BwStore};
use crate::error::BwResult;
use kemlock_app::notices::{Notice, RegisterVerifyNotice};
use kemlock_domain::{Email, User};

/// Whether registration has to prove the address with a mailed link first: the setting is on and
/// the server can mail the link.
///
/// MERGE: today this reads `BwSettings::signups_verify()` (`Live::signups_verify`, added with this
/// change). Use the Kemlock side's `Live::signups_verify()`, which is already false when SMTP isn't
/// set, and drop the `Live` accessor and `Notice::RegisterVerify` this branch added.
pub(crate) fn verifies<S: BwStore>(app: &App<S>) -> bool {
    app.settings.signups_verify() && app.notices.mails()
}

/// Mails the token that proves `to`'s address. The token is a Bitwarden registration token
/// (`RegisterVerifyClaims`, verified), and `register/finish` takes it back; it is never returned
/// to the asker.
///
/// MERGE: today this sends this branch's `Notice::RegisterVerify`. The Kemlock side's
/// `SignupVerify::begin` mails `Notice::SignupVerify` and holds the account; route the Bitwarden
/// token through it if the two flows are to share one mail, or keep this one for the Bitwarden
/// clients' `finish-signup` link.
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
/// MERGE: a no-op today, because the Bitwarden registration refuses an unproven address before the
/// account is made (`register` needs the verified token). Call `UserRepo::hold_unconfirmed` here
/// for a registration that makes the account first and verifies after.
#[allow(clippy::unused_async)]
pub(crate) async fn hold<S: BwStore>(_app: &App<S>, _user: &User) -> BwResult<()> {
    Ok(())
}

/// Refuses a sign-in (password or API key) of an account that is held, as the Kemlock side does.
/// Called after the credentials checked out, so it tells a stranger nothing.
///
/// MERGE: always `Ok` today. Call `UserRepo::email_unconfirmed` and answer the account's held
/// state with the Bitwarden error the Kemlock side's message maps to.
#[allow(clippy::unused_async)]
pub(crate) async fn refuse_if_held<S: BwStore>(_app: &App<S>, _user: &User) -> BwResult<()> {
    Ok(())
}
