//! Admin actions are recorded in the event log, with the admin's name and truncated address, and
//! the other admins get a mail about each one (design, "Identity and SSO", Admins), so a stolen
//! admin session can't change the server unseen.

use super::ports::{AdminEvent, AdminEventRepo, AdminUserRepo, Mailer, Notice};
use crate::authenticate::Actor;
use crate::ports::Clock;
use kemlock_domain::unlock::truncate_ip;
use std::net::IpAddr;
use time::format_description::well_known::Rfc3339;

#[derive(Debug)]
pub struct Audit<V, U, M, C> {
    pub events: V,
    pub users: U,
    pub mail: M,
    pub clock: C,
}

impl<V: AdminEventRepo, U: AdminUserRepo, M: Mailer, C: Clock> Audit<V, U, M, C> {
    /// Records `action` on `target` as done by `actor`, then mails the other admins what
    /// `summary` says. Neither failing undoes the action, which has happened; both are logged.
    pub async fn record(
        &self,
        actor: &Actor,
        ip: Option<IpAddr>,
        action: &str,
        target: Option<String>,
        summary: &str,
    ) {
        let at = self.clock.now();
        let ip = ip.map(truncate_ip);
        let event = AdminEvent {
            actor: Some(actor.user),
            device: Some(actor.device),
            action: action.to_owned(),
            target: target.clone(),
            ip: ip.clone(),
            at,
        };
        if let Err(e) = self.events.record_admin_event(event).await {
            tracing::error!(action, error = %e, "couldn't record an admin action");
        }
        if !self.mail.configured() {
            return;
        }
        let admins = match self.users.admins().await {
            Ok(admins) => admins,
            Err(e) => {
                tracing::warn!(error = %e, "couldn't list the admins to tell");
                return;
            }
        };
        let who = admins
            .iter()
            .find(|a| a.id == actor.user)
            .map_or_else(|| "an admin".to_owned(), |a| a.email.as_str().to_owned());
        let when = at.format(&Rfc3339).unwrap_or_default();
        for admin in admins.into_iter().filter(|a| a.id != actor.user) {
            let body = format!(
                "{who} did this on your Kemlock Server:\n\n{summary}\n\n\
                 Action: {action}\nTarget: {}\nTime: {when}\nAddress: {}\n\n\
                 If you don't know about this, open the event log in the admin console.\n",
                target.as_deref().unwrap_or("-"),
                ip.as_deref().unwrap_or("unknown"),
            );
            let notice = Notice {
                to: admin.email,
                subject: format!("Kemlock Server admin action: {summary}"),
                body,
            };
            if let Err(e) = self.mail.send(notice).await {
                tracing::warn!(action, error = %e, "couldn't mail an admin about an action");
            }
        }
    }
}
