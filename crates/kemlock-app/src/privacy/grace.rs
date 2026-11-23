//! The deleted-account grace period at sign-in. While an erasure is pending (`pending_erasures`),
//! the account has no session: every way in answers that the account is being deleted, once the
//! credentials have checked out (so nobody learns it of a stranger's account). Signing in does not
//! cancel the deletion: the design gives a deleted account a grace period and no way back through
//! the sign-in, so only an admin can cancel it (`AdminUsers::cancel_erasure`, `POST
//! /admin/v1/users/{id}/cancel-erasure`).

use crate::error::AppError;
use crate::ports::UserRepo;
use kemlock_domain::UserId;

/// Refuses with [`AppError::AccountBeingDeleted`] while the account's erasure is pending. Call it
/// beside the check for a disabled account, after the credentials were proved.
pub async fn ensure_not_pending<U: UserRepo>(users: &U, user: UserId) -> Result<(), AppError> {
    match users.erasure_pending(user).await? {
        Some(_) => Err(AppError::AccountBeingDeleted),
        None => Ok(()),
    }
}
