//! Proving the password again before a change that needs it: erasing the account, changing the
//! master password or the sign-in address.
//!
//! The body of such a request carries the last two messages of a fresh OPAQUE login
//! (`POST /kem/v1/auth/opaque/start` first, with the same device key), so a stolen access token
//! alone changes nothing. Each login state is good once, whether the password was right or not,
//! and a wrong password counts against the account like a wrong sign-in does.

use super::guard;
use crate::dto::decode;
use crate::extract::Authed;
use crate::problem::{Problem, rate_limited};
use crate::ratelimit::ip_key;
use crate::replay::Full;
use crate::state::{Api, Crypto, Store};
use kemlock_app::AppError;
use kemlock_app::ports::TokenSigner;
use kemlock_app::privacy::Reauthenticate;
use kemlock_app::sign_in::credential_id;
use kemlock_domain::User;

/// Checks that the person behind `authed` still knows the password of `user`, their account.
pub(crate) async fn reauthenticate<S, P, K>(
    api: &Api<S, P, K>,
    authed: &Authed,
    user: &User,
    login_state: &str,
    finalization: &str,
) -> Result<(), Problem>
where
    S: Store,
    P: Crypto,
    K: TokenSigner + Clone + 'static,
{
    guard(&api.limits.sign_in, &ip_key(authed.ip), api.now())?;

    // A wrong password counts against the account like a wrong sign-in does.
    let account = format!("acct:{}", credential_id(user.email.as_str()));
    api.limits
        .account
        .blocked(&account, api.now())
        .map_err(rate_limited)?;
    let login_state = decode("loginState", login_state)?;
    let finalization = decode("finalization", finalization)?;
    // A login state finishes once, whether the password was right or not. Only a genuine, fresh
    // state is remembered.
    api.sign_in().check_login_state(&login_state)?;
    match api.used_states.insert(&login_state, api.now()) {
        Ok(true) => {}
        Ok(false) => return Err(Problem::bad_request("the login state was already used")),
        Err(Full) => return Err(Problem::overloaded()),
    }
    let checked = Reauthenticate {
        users: api.store.clone(),
        auth: api.crypto.clone(),
        seal: api.crypto.clone(),
        clock: api.crypto.clone(),
    }
    .execute(user.id, &login_state, &finalization, &authed.jkt)
    .await;
    match &checked {
        Err(AppError::Unauthorized) => api.limits.account.fail(&account, api.now()),
        Ok(()) => api.limits.account.clear(&account),
        Err(_) => {}
    }
    Ok(checked?)
}
