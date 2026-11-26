//! Signed item writes (docs/crypto.md, "Signed item writes"): the per-owner **signed-only** flag
//! and the rule it gives the write use cases.
//!
//! Once an owner has had a signed `kem1` write accepted (or its owner asked), this server refuses
//! an unsigned `kem1` write for it. The cryptographic check of a signature is done where the
//! writer's bundle is read (the API layer), because this crate has no crypto of its own; the
//! flag's rule is here so every route that writes items, and the key replacement that rewrites
//! them, applies the same one.

use crate::authenticate::Actor;
use crate::error::AppError;
use crate::ports::{Clock, ItemStore, StoreError};
use kemlock_domain::{ItemFormat, ItemWrite, Owner};

/// Whether `write` must be refused for lacking a signature: it is a `kem1` write with none, and
/// the owner accepts signed writes only. A `bw` write is never signed and never refused.
pub async fn refuses_unsigned<I: ItemStore>(
    items: &I,
    write: &ItemWrite,
) -> Result<bool, StoreError> {
    if write.format != ItemFormat::Kem1 || write.signature.is_some() {
        return Ok(false);
    }
    items.signed_writes_required(write.owner).await
}

/// Makes the account's own vault accept signed writes only, before any signed write has been
/// made. It never goes back.
#[derive(Debug)]
pub struct RequireSignedWrites<I, C> {
    pub items: I,
    pub clock: C,
}

impl<I: ItemStore, C: Clock> RequireSignedWrites<I, C> {
    /// `owner` must be the actor's own vault: the owner of a space is set by the first signed
    /// write of one of its members, not asked for.
    pub async fn execute(&self, actor: &Actor, owner: Owner) -> Result<(), AppError> {
        match owner {
            Owner::User(user) if user == actor.user => {
                self.items
                    .require_signed_writes(owner, self.clock.now())
                    .await?;
                Ok(())
            }
            _ => Err(AppError::Forbidden),
        }
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
        let confirmed = |rows: Vec<kemlock_domain::spaces::Member>| -> std::collections::BTreeSet<_> {
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
