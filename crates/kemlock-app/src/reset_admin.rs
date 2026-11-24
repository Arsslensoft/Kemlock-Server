//! `kemlock-cli reset-admin`: start over with a new first admin, or hand the role to an account
//! that exists.
//!
//! Every account with the admin role becomes a plain user, and the first-admin marker is
//! removed. With no one promoted, the server's next start finds no admin and no pending account
//! and opens setup with a new code (see [`crate::first_run`]). With `promote`, that existing
//! account becomes the admin instead and setup stays closed; it needs a confirmed two-step method,
//! as every admin does. Accounts, vaults, devices and sessions stay as they are; only roles
//! change. The reset is written to the event log as `admin.reset`, with no actor: it is made from
//! the server's own shell, not from a signed-in session.

use crate::admin::ports::{AdminEvent, AdminEventRepo, AdminUserRepo, SettingsRepo};
use crate::error::AppError;
use crate::first_admin::MARKER_KEY;
use crate::ports::{Clock, TwoFactorRepo, UserRepo};
use kemlock_domain::{Email, Role};

/// The event the reset leaves in the log.
pub const ACTION: &str = "admin.reset";

#[derive(Debug)]
pub struct ResetAdmin<U, A, E, S, T, C> {
    pub users: U,
    pub admins: A,
    pub events: E,
    pub settings: S,
    pub two_factor: T,
    pub clock: C,
}

impl<U, A, E, S, T, C> ResetAdmin<U, A, E, S, T, C>
where
    U: UserRepo,
    A: AdminUserRepo,
    E: AdminEventRepo,
    S: SettingsRepo,
    T: TwoFactorRepo,
    C: Clock,
{
    /// Returns the emails of the accounts that stopped being admins (the promoted account, if it
    /// was one, is not among them). Safe to run twice. A `promote` that can't be done (no such
    /// account, no confirmed two-step method) changes nothing.
    pub async fn execute(&self, promote: Option<&Email>) -> Result<Vec<String>, AppError> {
        let target = match promote {
            Some(email) => {
                let user = self
                    .users
                    .by_email(email)
                    .await?
                    .ok_or(AppError::NotFound)?;
                let confirmed = self
                    .two_factor
                    .list(user.id)
                    .await?
                    .iter()
                    .any(|t| t.enabled);
                if !confirmed {
                    return Err(AppError::Invalid(
                        "that account has no confirmed two-step method, which an admin needs",
                    ));
                }
                Some(user)
            }
            None => None,
        };
        let keep = target.as_ref().map(|u| u.id);
        let mut demoted = Vec::new();
        for admin in self.admins.admins().await? {
            if Some(admin.id) == keep {
                continue;
            }
            let Some(mut user) = self.users.by_id(admin.id).await? else {
                continue;
            };
            if user.role == Role::Admin {
                user.role = Role::User;
                user.updated_at = self.clock.now();
                self.users.update(&user).await?;
                demoted.push(admin.email.as_str().to_owned());
            }
        }
        if let Some(mut user) = target.clone()
            && user.role != Role::Admin
        {
            user.role = Role::Admin;
            user.updated_at = self.clock.now();
            self.users.update(&user).await?;
        }
        // After the role changes: if the process dies in between, the next run finds the marker
        // and finishes the job.
        self.settings.delete_setting(MARKER_KEY).await?;
        let promoted = target
            .as_ref()
            .map_or(String::new(), |u| format!(", {} promoted", u.email.as_str()));
        self.events
            .record_admin_event(AdminEvent {
                actor: None,
                device: None,
                action: ACTION.to_owned(),
                target: Some(format!("{} admin(s) demoted{promoted}", demoted.len())),
                ip: None,
                at: self.clock.now(),
            })
            .await?;
        Ok(demoted)
    }
}
