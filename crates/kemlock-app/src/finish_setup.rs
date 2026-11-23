//! Finish setup: makes the first account an admin and closes first-run setup for good, once it
//! has a confirmed two-step method (design, "Identity and SSO": two-step login is required for
//! admins).
//!
//! The account registered with the setup grant as a plain user. Only here, with a confirmed
//! two-step method in hand, does it become an admin, so no admin ever exists without a second
//! factor, whether setup was skipped, abandoned or interrupted by a restart.

use crate::error::AppError;
use crate::first_run::SetupState;
use crate::ports::{Clock, TwoFactorRepo, UserRepo};
use kemlock_domain::{Role, SetupError, UserId};
use std::sync::Arc;

#[derive(Debug)]
pub struct FinishSetup<U, F, C> {
    pub users: U,
    pub two_factor: F,
    pub setup: Arc<SetupState>,
    pub clock: C,
}

impl<U: UserRepo, F: TwoFactorRepo, C: Clock> FinishSetup<U, F, C> {
    /// `actor` is the signed-in account asking; it must be the account setup waits for.
    pub async fn execute(&self, actor: UserId) -> Result<(), AppError> {
        match self.setup.pending() {
            Some(pending) if pending == actor => {}
            Some(_) => return Err(AppError::Forbidden),
            None => return Err(SetupError::AlreadyDone.into()),
        }
        let mut user = self
            .users
            .by_id(actor)
            .await?
            .ok_or(AppError::Unauthorized)?;
        let confirmed = self.two_factor.list(actor).await?.iter().any(|t| t.enabled);
        if !confirmed {
            return Err(SetupError::TwoStepRequired.into());
        }
        // The promotion first, then the in-memory state: if the process dies in between, the
        // next start finds an admin and closes setup.
        if user.role != Role::Admin {
            user.role = Role::Admin;
            user.updated_at = self.clock.now();
            self.users.update(&user).await?;
        }
        self.setup.finish(actor)
    }
}
