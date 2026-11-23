//! Registration by invitation: when sign-ups are closed, an address an admin invited may still
//! register, with the token from its invitation link.
//!
//! The token is checked against the invitation's stored hash, must be for the address that
//! registers, and must be neither used nor expired. It is consumed once the account exists, so
//! a registration that fails (a taken address, a rejected key) leaves the invitation usable.

use super::ports::InviteRepo;
use crate::error::AppError;
use crate::notices::BoxFuture;
use crate::platform::Platform;
use kemlock_domain::Email;
use uuid::Uuid;

/// The longest token looked at: ours are 43 characters.
const MAX_TOKEN_LEN: usize = 256;

/// A token that was accepted and has not been consumed yet.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct InviteTicket {
    pub invite: Uuid,
}

/// What registration asks of invitations. Object safe, so the API holds one behind an `Arc`
/// without knowing the store.
pub trait InviteGate: Send + Sync {
    /// Checks `token` for `email`. `Forbidden` for a token that is unknown, used, expired or for
    /// another address, with no word on which: a probe learns nothing.
    fn accept<'a>(
        &'a self,
        token: &'a str,
        email: &'a Email,
    ) -> BoxFuture<'a, Result<InviteTicket, AppError>>;

    /// Marks the invitation accepted. `Forbidden` when another registration got there first.
    fn consume<'a>(&'a self, ticket: &'a InviteTicket) -> BoxFuture<'a, Result<(), AppError>>;
}

/// The invitation gate over the invitation repository.
#[derive(Clone, Debug)]
pub struct AcceptInvite<R, E> {
    pub repo: R,
    pub env: E,
}

impl<R, E> InviteGate for AcceptInvite<R, E>
where
    R: InviteRepo,
    E: Platform,
{
    fn accept<'a>(
        &'a self,
        token: &'a str,
        email: &'a Email,
    ) -> BoxFuture<'a, Result<InviteTicket, AppError>> {
        Box::pin(async move {
            let token = token.trim();
            if token.is_empty() || token.len() > MAX_TOKEN_LEN {
                return Err(AppError::Forbidden);
            }
            let hash = self.env.sha256(token.as_bytes());
            let invite = self
                .repo
                .invite_by_token(hash)
                .await?
                .ok_or(AppError::Forbidden)?;
            if invite.email != *email || !invite.is_pending(self.env.now()) {
                return Err(AppError::Forbidden);
            }
            Ok(InviteTicket { invite: invite.id })
        })
    }

    fn consume<'a>(&'a self, ticket: &'a InviteTicket) -> BoxFuture<'a, Result<(), AppError>> {
        Box::pin(async move {
            let now = self.env.now();
            let mut invite = self
                .repo
                .invite(ticket.invite)
                .await?
                .ok_or(AppError::Forbidden)?;
            if !invite.is_pending(now) {
                return Err(AppError::Forbidden);
            }
            invite.accepted_at = Some(now);
            self.repo.update_invite(&invite).await?;
            Ok(())
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::admin::ports::Invite;
    use crate::platform::Hasher as _;
    use crate::ports::{Clock, Random, StoreError};
    use std::sync::{Arc, Mutex};
    use time::{Duration, OffsetDateTime};

    #[derive(Clone)]
    struct Env(OffsetDateTime);

    impl Clock for Env {
        fn now(&self) -> OffsetDateTime {
            self.0
        }
    }

    impl Random for Env {
        fn fill(&self, buf: &mut [u8]) {
            buf.fill(7);
        }
    }

    impl crate::platform::Hasher for Env {
        fn sha256(&self, data: &[u8]) -> [u8; 32] {
            // Not a real hash: enough to tell tokens apart.
            let mut out = [0u8; 32];
            for (i, b) in data.iter().enumerate() {
                out[i % 32] ^= b.wrapping_add(i as u8);
            }
            out
        }
        fn hmac_sha256(&self, _key: &[u8], data: &[u8]) -> [u8; 32] {
            self.sha256(data)
        }
    }

    #[derive(Clone, Default)]
    struct Repo(Arc<Mutex<Vec<Invite>>>);

    impl InviteRepo for Repo {
        async fn insert_invite(&self, invite: &Invite) -> Result<(), StoreError> {
            self.0.lock().expect("lock").push(invite.clone());
            Ok(())
        }
        async fn invites(&self) -> Result<Vec<Invite>, StoreError> {
            Ok(self.0.lock().expect("lock").clone())
        }
        async fn invite(&self, id: Uuid) -> Result<Option<Invite>, StoreError> {
            Ok(self
                .0
                .lock()
                .expect("lock")
                .iter()
                .find(|i| i.id == id)
                .cloned())
        }
        async fn update_invite(&self, invite: &Invite) -> Result<(), StoreError> {
            let mut all = self.0.lock().expect("lock");
            if let Some(slot) = all.iter_mut().find(|i| i.id == invite.id) {
                *slot = invite.clone();
            }
            Ok(())
        }
        async fn remove_invite(&self, id: Uuid) -> Result<(), StoreError> {
            self.0.lock().expect("lock").retain(|i| i.id != id);
            Ok(())
        }
        async fn invite_by_token(&self, hash: [u8; 32]) -> Result<Option<Invite>, StoreError> {
            Ok(self
                .0
                .lock()
                .expect("lock")
                .iter()
                .find(|i| i.token_hash == hash)
                .cloned())
        }
        async fn pending_invites(&self, now: OffsetDateTime) -> Result<u64, StoreError> {
            Ok(self
                .0
                .lock()
                .expect("lock")
                .iter()
                .filter(|i| i.is_pending(now))
                .count() as u64)
        }
    }

    const NOW: OffsetDateTime = time::macros::datetime!(2026-12-01 12:00 UTC);

    fn email(text: &str) -> Email {
        Email::parse(text).expect("a valid email")
    }

    async fn gate_with(
        token: &str,
        expires_in: Duration,
        accepted: bool,
    ) -> AcceptInvite<Repo, Env> {
        let env = Env(NOW);
        let repo = Repo::default();
        repo.insert_invite(&Invite {
            id: Uuid::from_u128(1),
            email: email("ada@example.org"),
            invited_by: kemlock_domain::UserId(Uuid::from_u128(9)),
            token_hash: env.sha256(token.as_bytes()),
            created_at: NOW - Duration::days(1),
            expires_at: NOW + expires_in,
            last_sent_at: NOW - Duration::days(1),
            sent: 1,
            accepted_at: accepted.then_some(NOW - Duration::hours(1)),
        })
        .await
        .expect("stored");
        AcceptInvite { repo, env }
    }

    #[tokio::test]
    async fn a_live_token_for_its_address_is_accepted_and_consumed_once() {
        let gate = gate_with("tok-1", Duration::days(3), false).await;
        let ticket = gate
            .accept(" tok-1 ", &email("Ada@Example.org"))
            .await
            .expect("accepted");
        assert_eq!(ticket.invite, Uuid::from_u128(1));
        gate.consume(&ticket).await.expect("consumed");
        let stored = gate.repo.invite(ticket.invite).await.expect("read");
        assert!(stored.expect("there").accepted_at.is_some());
        // A used token is refused, and so is a second consume.
        assert_eq!(
            gate.accept("tok-1", &email("ada@example.org")).await,
            Err(AppError::Forbidden)
        );
        assert_eq!(gate.consume(&ticket).await, Err(AppError::Forbidden));
    }

    #[tokio::test]
    async fn an_expired_token_is_refused() {
        let gate = gate_with("tok-1", Duration::seconds(-1), false).await;
        assert_eq!(
            gate.accept("tok-1", &email("ada@example.org")).await,
            Err(AppError::Forbidden)
        );
    }

    #[tokio::test]
    async fn an_accepted_invitation_is_refused() {
        let gate = gate_with("tok-1", Duration::days(3), true).await;
        assert_eq!(
            gate.accept("tok-1", &email("ada@example.org")).await,
            Err(AppError::Forbidden)
        );
    }

    #[tokio::test]
    async fn an_unknown_token_or_another_address_is_refused() {
        let gate = gate_with("tok-1", Duration::days(3), false).await;
        for (token, who) in [
            ("tok-2", "ada@example.org"),
            ("tok-1", "bob@example.org"),
            ("", "ada@example.org"),
        ] {
            assert_eq!(
                gate.accept(token, &email(who)).await,
                Err(AppError::Forbidden),
                "{token} for {who}"
            );
        }
        let long = "x".repeat(300);
        assert_eq!(
            gate.accept(&long, &email("ada@example.org")).await,
            Err(AppError::Forbidden)
        );
    }
}
