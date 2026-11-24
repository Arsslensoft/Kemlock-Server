//! `kemlock-cli reset-admin`: start over with a new first admin.
//!
//! Every account with the admin role becomes a plain user, and the first-admin marker is
//! removed, so the server's next start finds no admin and no pending account and opens setup with
//! a new code (see [`crate::first_run`]). Accounts, vaults, devices and sessions stay as they are;
//! only the role changes. The reset is written to the event log as `admin.reset`, with no actor:
//! it is made from the server's own shell, not from a signed-in session.

use crate::admin::ports::{AdminEvent, AdminEventRepo, AdminUserRepo, SettingsRepo};
use crate::error::AppError;
use crate::first_admin::MARKER_KEY;
use crate::ports::{Clock, UserRepo};
use kemlock_domain::Role;

/// The event the reset leaves in the log.
pub const ACTION: &str = "admin.reset";

#[derive(Debug)]
pub struct ResetAdmin<U, A, E, S, C> {
    pub users: U,
    pub admins: A,
    pub events: E,
    pub settings: S,
    pub clock: C,
}

impl<U, A, E, S, C> ResetAdmin<U, A, E, S, C>
where
    U: UserRepo,
    A: AdminUserRepo,
    E: AdminEventRepo,
    S: SettingsRepo,
    C: Clock,
{
    /// Returns the emails of the accounts that were admins. Safe to run twice: the second run
    /// finds no admin and returns an empty list, and still clears the marker.
    pub async fn execute(&self) -> Result<Vec<String>, AppError> {
        let mut demoted = Vec::new();
        for admin in self.admins.admins().await? {
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
        // After the demotions: if the process dies in between, the next run finds the marker
        // and the remaining admins and finishes the job.
        self.settings.delete_setting(MARKER_KEY).await?;
        self.events
            .record_admin_event(AdminEvent {
                actor: None,
                device: None,
                action: ACTION.to_owned(),
                target: Some(format!("{} admin(s) demoted", demoted.len())),
                ip: None,
                at: self.clock.now(),
            })
            .await?;
        Ok(demoted)
    }
}
