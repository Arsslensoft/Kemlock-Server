//! Signed item writes (docs/crypto.md, "Signed item writes"): the per-owner **signed-only** flag
//! and the rule it gives the write use cases.
//!
//! Once an owner asked (the account for its vault, an owner or admin for a space), this server
//! refuses an unsigned `kem1` write for it. A signed write does not set it: the Kemlock app does not
//! sign yet, and a vault one of its devices writes would be locked out by the first signed write of
//! another. The default will change once the app signs. The cryptographic check of a signature is done where the
//! writer's bundle is read (the API layer), because this crate has no crypto of its own; the
//! flag's rule is here so every route that writes items, and the key replacement that rewrites
//! them, applies the same one.

use crate::authenticate::Actor;
use crate::error::AppError;
use crate::ports::{Clock, Event, EventLog, ItemStore, StoreError};
use kemlock_domain::{ItemDraft, ItemFormat, Owner};

/// Whether the write `draft` came from must be refused for lacking a signature: it is a `kem1`
/// write with none, and the owner accepts signed writes only. A `bw` write is never signed and never
/// refused.
///
/// It is asked of the draft, after the use case has checked the caller's right to write the owner,
/// the revision and the sizes, so a caller who may not write the owner learns nothing about it.
pub async fn refuses_unsigned<I: ItemStore>(
    items: &I,
    draft: &ItemDraft,
) -> Result<bool, StoreError> {
    if draft.format != ItemFormat::Kem1 || draft.signature.is_some() {
        return Ok(false);
    }
    items.signed_writes_required(draft.owner).await
}

/// Turns the signed-only flag of an owner on or off (docs/crypto.md, "The signed-only flag"): the
/// account's own vault, or a space by a confirmed owner or admin of it. Both are logged. Turning it
/// off is the step that needs a fresh proof of the person, which the route asks before it gets here.
#[derive(Debug)]
pub struct SetSignedWrites<I, R, V, C> {
    pub items: I,
    pub spaces: R,
    pub events: V,
    pub clock: C,
}

impl<I: ItemStore, R: crate::spaces::SpaceRepo, V: EventLog, C: Clock> SetSignedWrites<I, R, V, C> {
    /// Whether `actor` may set or clear the flag of `owner`: `NotFound` for a space the actor isn't
    /// a confirmed member of, and `Forbidden` for another person's vault and for a member who is
    /// neither owner nor admin. The route asks it before it spends the password.
    pub async fn check(&self, actor: &Actor, owner: Owner) -> Result<(), AppError> {
        match owner {
            Owner::User(user) if user == actor.user => {}
            Owner::User(_) => return Err(AppError::Forbidden),
            Owner::Space(space) => {
                let state = self.spaces.load(space).await?.ok_or(AppError::NotFound)?;
                let member = state
                    .confirmed_actor(actor.user)
                    .map_err(|_| AppError::NotFound)?;
                if !matches!(
                    member.role,
                    kemlock_domain::spaces::SpaceRole::Owner
                        | kemlock_domain::spaces::SpaceRole::Admin
                ) {
                    return Err(AppError::Forbidden);
                }
            }
        }
        Ok(())
    }

    /// Sets (`required`) or clears the flag, when [`Self::check`] allows it.
    pub async fn execute(
        &self,
        actor: &Actor,
        owner: Owner,
        required: bool,
    ) -> Result<(), AppError> {
        self.check(actor, owner).await?;
        let now = self.clock.now();
        if required {
            self.items.require_signed_writes(owner, now).await?;
        } else {
            self.items.clear_signed_writes(owner).await?;
        }
        let event = Event {
            actor: Some(actor.user),
            device: Some(actor.device),
            action: if required {
                "signed_writes.require"
            } else {
                "signed_writes.clear"
            },
            target: Some(owner.to_string()),
            at: now,
        };
        if let Err(e) = self.events.record(event).await {
            tracing::warn!(error = %e, "couldn't record a signed-writes event");
        }
        Ok(())
    }
}

/// An account's bundle at a key version, for whoever may check a write it signed under that bundle
/// (docs/crypto.md, "Signed item writes", "Key versions"): the account itself, and a confirmed
/// member of a space the account is a confirmed member of. Anyone else, and a version the account
/// never had, is not found, so the answer says nothing about which accounts exist.
#[derive(Debug)]
pub struct GetBundleAt<U, R> {
    pub users: U,
    pub spaces: R,
}

impl<U: crate::ports::UserRepo, R: crate::spaces::SpaceRepo> GetBundleAt<U, R> {
    pub async fn execute(
        &self,
        actor: &Actor,
        account: kemlock_domain::UserId,
        key_version: u32,
    ) -> Result<crate::ports::StoredBundle, AppError> {
        if account != actor.user && !self.share_a_space(actor.user, account).await? {
            return Err(AppError::NotFound);
        }
        self.users
            .bundle_at(account, key_version)
            .await?
            .ok_or(AppError::NotFound)
    }

    async fn share_a_space(
        &self,
        a: kemlock_domain::UserId,
        b: kemlock_domain::UserId,
    ) -> Result<bool, StoreError> {
        use kemlock_domain::spaces::MemberState;
        let confirmed =
            |rows: Vec<kemlock_domain::spaces::Member>| -> std::collections::BTreeSet<_> {
                rows.into_iter()
                    .filter(|m| m.state == MemberState::Confirmed)
                    .map(|m| m.space)
                    .collect()
            };
        let mine = confirmed(self.spaces.memberships(a).await?);
        if mine.is_empty() {
            return Ok(false);
        }
        let theirs = confirmed(self.spaces.memberships(b).await?);
        Ok(mine.intersection(&theirs).next().is_some())
    }
}
