//! The Users screen: list, invite, resend, revoke an invitation, sign out, disable, enable, reset
//! two-step login and delete. Every write is recorded and mailed to the other admins by
//! [`Audit`].
//!
//! Disabling an account ends its sessions at once and sets a flag; sign-in paths ask
//! [`AdminUserRepo::is_disabled`] and refuse a disabled account. Deleting is refused for the
//! caller's own account, for the last admin, and for an account that is the only confirmed owner
//! of a space (the space needs a new owner first, which keeps its key with someone who can use
//! it).

use super::audit::Audit;
use super::error::AdminError;
use super::ports::{
    AdminEventRepo, AdminUserRepo, Invite, InviteRepo, Mailer, Notice, UserPage, UserQuery,
};
use crate::authenticate::Actor;
use crate::b64url;
use crate::notices::BoxFuture;
use crate::platform::{Platform, random_uuid};
use crate::ports::{DeviceRepo, TokenRepo, TwoFactorRepo, UserRepo};
use crate::privacy::{
    AccountEraser, EraseAccount, ErasureFiles, PrivacyLog, PrivacySettings, Requester, SendEraser,
};
use kemlock_domain::{Email, User, UserId};
use std::net::IpAddr;
use std::sync::Arc;
use time::Duration;
use uuid::Uuid;

/// How long an invitation can be accepted.
pub const INVITE_TTL: Duration = Duration::days(7);
/// The most accounts a page lists.
pub const MAX_USER_PAGE: u32 = 200;

/// A new or resent invitation, with the link that accepts it. The token inside the link is shown
/// here once: only its hash is kept.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct InviteIssued {
    pub invite: Invite,
    pub link: String,
    /// Whether the mail went out. False when no SMTP server is set up or it failed: the admin
    /// can pass the link on by hand.
    pub mailed: bool,
}

/// Erases an account for an admin: the whole erasure of the privacy area (items, files, Sends, the
/// sign-in log, federated peers), not a narrower one. Object safe, so the admin API holds one
/// without knowing the store. [`EraseAccount`] implements it, acting as `Requester::Admin`.
pub trait AccountErasure: Send + Sync {
    /// Erases `user` at once, on `admin`'s request.
    fn erase(&self, user: UserId, admin: UserId) -> BoxFuture<'_, Result<(), AdminError>>;
}

impl<U, E, S, F, P, L, C> AccountErasure for EraseAccount<U, E, S, F, P, L, C>
where
    U: UserRepo + Send + Sync,
    E: AccountEraser + Send + Sync,
    S: SendEraser + Send + Sync,
    F: ErasureFiles + Send + Sync,
    P: PrivacySettings + Send + Sync,
    L: PrivacyLog + Send + Sync,
    C: Platform + Send + Sync,
{
    fn erase(&self, user: UserId, admin: UserId) -> BoxFuture<'_, Result<(), AdminError>> {
        Box::pin(async move {
            // An admin's erasure is at once, whatever grace period the settings give a person's own
            // request, so only `Erased` comes back.
            self.execute(user, Requester::Admin(admin)).await?;
            Ok(())
        })
    }
}

pub struct AdminUsers<S, R, M, E> {
    /// The account, device, token and two-step ports.
    pub store: S,
    /// The admin repositories.
    pub repos: R,
    pub mail: M,
    pub env: E,
    /// `DOMAIN`, for the invitation link.
    pub domain: String,
    /// What deletes an account. Without one, deleting is refused rather than done by a narrower
    /// path that would leave Sends, files, the sign-in log and federated copies behind.
    pub erasure: Option<Arc<dyn AccountErasure>>,
}

impl<S, R, M, E> std::fmt::Debug for AdminUsers<S, R, M, E> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AdminUsers").finish_non_exhaustive()
    }
}

impl<S, R, M, E> AdminUsers<S, R, M, E>
where
    S: UserRepo + DeviceRepo + TokenRepo + TwoFactorRepo,
    R: AdminUserRepo + InviteRepo + AdminEventRepo + Clone,
    M: Mailer + Clone,
    E: Platform + Clone,
{
    fn audit(&self) -> Audit<R, R, M, E> {
        Audit {
            events: self.repos.clone(),
            users: self.repos.clone(),
            mail: self.mail.clone(),
            clock: self.env.clone(),
        }
    }

    pub async fn list(&self, mut query: UserQuery) -> Result<UserPage, AdminError> {
        query.limit = query.limit.clamp(1, MAX_USER_PAGE);
        query.search = query
            .search
            .map(|s| s.trim().to_owned())
            .filter(|s| !s.is_empty());
        if query.search.as_ref().is_some_and(|s| s.len() > 254) {
            return Err(AdminError::Invalid(
                "the search text is too long".to_owned(),
            ));
        }
        Ok(self.repos.list_users(&query).await?)
    }

    async fn target(&self, user: UserId) -> Result<User, AdminError> {
        self.store.by_id(user).await?.ok_or(AdminError::NotFound)
    }

    /// Ends every session of the account: its security stamp changes, so no access token or
    /// refresh token it holds works again, and its refresh tokens are revoked.
    async fn end_sessions(&self, mut user: User) -> Result<(), AdminError> {
        user.security_stamp = random_uuid(&self.env);
        user.updated_at = self.env.now();
        self.store.update(&user).await?;
        for device in DeviceRepo::list(&self.store, user.id).await? {
            TokenRepo::revoke_device(&self.store, device.id).await?;
        }
        Ok(())
    }

    pub async fn sign_out(
        &self,
        actor: &Actor,
        ip: Option<IpAddr>,
        user: UserId,
    ) -> Result<(), AdminError> {
        let target = self.target(user).await?;
        self.end_sessions(target).await?;
        self.audit()
            .record(
                actor,
                ip,
                "admin.user.sign_out",
                Some(user.to_string()),
                "signed an account out of every device",
            )
            .await;
        Ok(())
    }

    pub async fn disable(
        &self,
        actor: &Actor,
        ip: Option<IpAddr>,
        user: UserId,
    ) -> Result<(), AdminError> {
        if user == actor.user {
            return Err(AdminError::State("you can't disable your own account"));
        }
        let target = self.target(user).await?;
        let now = self.env.now();
        self.repos
            .set_disabled(user, Some((now, actor.user)))
            .await?;
        self.end_sessions(target).await?;
        self.audit()
            .record(
                actor,
                ip,
                "admin.user.disable",
                Some(user.to_string()),
                "disabled an account",
            )
            .await;
        Ok(())
    }

    pub async fn enable(
        &self,
        actor: &Actor,
        ip: Option<IpAddr>,
        user: UserId,
    ) -> Result<(), AdminError> {
        self.target(user).await?;
        self.repos.set_disabled(user, None).await?;
        self.audit()
            .record(
                actor,
                ip,
                "admin.user.enable",
                Some(user.to_string()),
                "enabled an account",
            )
            .await;
        Ok(())
    }

    /// Removes every two-step method of the account and signs it out, so its owner sets two-step
    /// login up again after the next sign-in. Not for the caller's own account: an admin without
    /// a two-step method is not an admin until they have one, so this would lock them out.
    pub async fn reset_two_step(
        &self,
        actor: &Actor,
        ip: Option<IpAddr>,
        user: UserId,
    ) -> Result<(), AdminError> {
        if user == actor.user {
            return Err(AdminError::State(
                "you can't reset your own two-step login: it is what makes you an admin",
            ));
        }
        let target = self.target(user).await?;
        for factor in TwoFactorRepo::list(&self.store, user).await? {
            TwoFactorRepo::remove(&self.store, user, factor.method).await?;
        }
        self.end_sessions(target).await?;
        self.audit()
            .record(
                actor,
                ip,
                "admin.user.reset_two_step",
                Some(user.to_string()),
                "reset an account's two-step login",
            )
            .await;
        Ok(())
    }

    /// Cancels the pending erasure of an account whose owner deleted it: the account stops
    /// being refused at sign-in. Its sessions stay ended (scheduling the erasure changed its
    /// security stamp), so its owner signs in again. The design gives a deleted account a grace
    /// period and no way back through the sign-in, so this is the only way to cancel one.
    pub async fn cancel_erasure(
        &self,
        actor: &Actor,
        ip: Option<IpAddr>,
        user: UserId,
    ) -> Result<(), AdminError> {
        self.target(user).await?;
        if !self.repos.cancel_pending_erasure(user).await? {
            return Err(AdminError::State("no erasure is pending for this account"));
        }
        self.audit()
            .record(
                actor,
                ip,
                "admin.user.cancel_erasure",
                Some(user.to_string()),
                "cancelled the pending deletion of an account",
            )
            .await;
        Ok(())
    }

    pub async fn delete(
        &self,
        actor: &Actor,
        ip: Option<IpAddr>,
        user: UserId,
    ) -> Result<(), AdminError> {
        if user == actor.user {
            return Err(AdminError::State("you can't delete your own account"));
        }
        let target = self.target(user).await?;
        if target.is_admin() && self.store.count_admins().await? <= 1 {
            return Err(AdminError::State("the last admin can't be deleted"));
        }
        if !self.repos.sole_owned_spaces(user).await?.is_empty() {
            return Err(AdminError::State(
                "the account is the only owner of a space: make someone else its owner first",
            ));
        }
        let Some(erasure) = &self.erasure else {
            return Err(AdminError::NotConfigured(
                "deleting accounts isn't set up on this server",
            ));
        };
        erasure.erase(user, actor.user).await?;
        self.audit()
            .record(
                actor,
                ip,
                "admin.user.delete",
                Some(user.to_string()),
                "deleted an account and its data",
            )
            .await;
        Ok(())
    }

    // ---- invitations ----

    pub async fn invites(&self) -> Result<Vec<Invite>, AdminError> {
        Ok(self.repos.invites().await?)
    }

    fn link(&self, token: &str) -> String {
        format!("{}/invite?token={token}", self.domain.trim_end_matches('/'))
    }

    fn new_token(&self) -> (String, [u8; 32]) {
        let token = b64url::encode(&self.env.bytes::<32>());
        let hash = self.env.sha256(token.as_bytes());
        (token, hash)
    }

    async fn send_invite(&self, invite: &Invite, link: &str) -> bool {
        if !self.mail.configured() {
            return false;
        }
        let notice = Notice {
            to: invite.email.clone(),
            subject: "You are invited to Kemlock Server".to_owned(),
            body: format!(
                "You have been invited to make an account on {}.\n\n\
                 Open this link to start (it works for 7 days):\n{link}\n",
                self.domain
            ),
        };
        match self.mail.send(notice).await {
            Ok(()) => true,
            Err(e) => {
                tracing::warn!(error = %e, "couldn't mail an invitation");
                false
            }
        }
    }

    pub async fn invite(
        &self,
        actor: &Actor,
        ip: Option<IpAddr>,
        email: &str,
    ) -> Result<InviteIssued, AdminError> {
        let email = Email::parse(email)
            .map_err(|_| AdminError::Invalid("that isn't an email address".to_owned()))?;
        if self.store.by_email(&email).await?.is_some() {
            return Err(AdminError::State("an account with that email exists"));
        }
        let now = self.env.now();
        for old in self.repos.invites().await? {
            if old.email != email {
                continue;
            }
            if old.is_pending(now) {
                return Err(AdminError::State(
                    "that address is already invited: resend the invitation instead",
                ));
            }
            // An expired invitation, or one already used, makes room for a new one.
            self.repos.remove_invite(old.id).await?;
        }
        let (token, token_hash) = self.new_token();
        let invite = Invite {
            id: random_uuid(&self.env),
            email,
            invited_by: actor.user,
            token_hash,
            created_at: now,
            expires_at: now + INVITE_TTL,
            last_sent_at: now,
            sent: 1,
            accepted_at: None,
        };
        self.repos.insert_invite(&invite).await?;
        let link = self.link(&token);
        let mailed = self.send_invite(&invite, &link).await;
        self.audit()
            .record(
                actor,
                ip,
                "admin.invite.create",
                Some(invite.id.to_string()),
                "invited an address to the server",
            )
            .await;
        Ok(InviteIssued {
            invite,
            link,
            mailed,
        })
    }

    /// Sends an invitation again with a new token (the old one can't be found from its hash) and
    /// a new week.
    pub async fn resend(
        &self,
        actor: &Actor,
        ip: Option<IpAddr>,
        id: Uuid,
    ) -> Result<InviteIssued, AdminError> {
        let mut invite = self.repos.invite(id).await?.ok_or(AdminError::NotFound)?;
        if invite.accepted_at.is_some() {
            return Err(AdminError::State("that invitation was already accepted"));
        }
        let now = self.env.now();
        let (token, token_hash) = self.new_token();
        invite.token_hash = token_hash;
        invite.expires_at = now + INVITE_TTL;
        invite.last_sent_at = now;
        invite.sent = invite.sent.saturating_add(1);
        self.repos.update_invite(&invite).await?;
        let link = self.link(&token);
        let mailed = self.send_invite(&invite, &link).await;
        self.audit()
            .record(
                actor,
                ip,
                "admin.invite.resend",
                Some(id.to_string()),
                "sent a server invitation again",
            )
            .await;
        Ok(InviteIssued {
            invite,
            link,
            mailed,
        })
    }

    pub async fn revoke_invite(
        &self,
        actor: &Actor,
        ip: Option<IpAddr>,
        id: Uuid,
    ) -> Result<(), AdminError> {
        self.repos.invite(id).await?.ok_or(AdminError::NotFound)?;
        self.repos.remove_invite(id).await?;
        self.audit()
            .record(
                actor,
                ip,
                "admin.invite.revoke",
                Some(id.to_string()),
                "revoked a server invitation",
            )
            .await;
        Ok(())
    }
}
