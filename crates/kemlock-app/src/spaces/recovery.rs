//! Account recovery enrolment for a space (docs/crypto.md, "Policies and recovery"): a confirmed
//! member seals their root key to the recovery key the space's chain records, and the server keeps
//! the box for an Owner or Admin who may recover that member.
//!
//! The box is opaque here. The server checks only its shape (the version byte and the length of a
//! 64-byte root key's box), that the space's chain has `accountRecovery` on, and that the member
//! sealed under the chain's *current* recovery key, which the member names by the `seq` of the
//! record that set it (the box's aad carries the same `seq`). When the chain's recovery key
//! changes the stored boxes stay, and are served marked `stale`.
//!
//! Who may recover whom follows Bitwarden: an Owner may recover anyone, an Admin anyone but an
//! Owner.

use super::chain::SpaceChainRepo;
use super::ports::SpaceRepo;
use super::support::record;
use crate::authenticate::Actor;
use crate::ports::{Clock, EventLog, StoreError};
use kemlock_crypto::sealed_box;
use kemlock_crypto::space_chain::{Role, State, Status};
use kemlock_domain::spaces::MemberState;
use kemlock_domain::{SpaceId, UserId};
use std::future::Future;
use time::OffsetDateTime;

/// A root key's length.
const ROOT_KEY_LEN: usize = 64;

/// The length of the box a member enrols: a root key sealed under `"account-recovery"`.
pub const RECOVERY_BOX_LEN: usize = sealed_box::OVERHEAD + ROOT_KEY_LEN;

/// A member's enrolled box, as stored.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RecoveryBox {
    pub space: SpaceId,
    pub user: UserId,
    /// The `seq` of the `recovery-key` record the box is sealed under.
    pub key_seq: u64,
    pub sealed: Vec<u8>,
    pub enrolled_at: OffsetDateTime,
}

/// The storage of recovery boxes: one per space and member.
pub trait SpaceRecoveryRepo: Send + Sync {
    fn recovery_box(
        &self,
        space: SpaceId,
        user: UserId,
    ) -> impl Future<Output = Result<Option<RecoveryBox>, StoreError>> + Send;

    /// Stores the box, replacing the member's earlier one.
    fn put_recovery_box(
        &self,
        recovery: RecoveryBox,
    ) -> impl Future<Output = Result<(), StoreError>> + Send;

    /// [`put_recovery_box`](SpaceRecoveryRepo::put_recovery_box) for a box of the root key at
    /// `key_version`: a store that can read the account refuses (`StaleKeyVersion`) a box for a
    /// version that is no longer the account's. `None` checks nothing. The provided method
    /// ignores the version.
    fn put_recovery_box_at(
        &self,
        recovery: RecoveryBox,
        key_version: Option<u32>,
    ) -> impl Future<Output = Result<(), StoreError>> + Send {
        let _ = key_version;
        self.put_recovery_box(recovery)
    }

    /// Removes the member's box; false when there was none.
    fn delete_recovery_box(
        &self,
        space: SpaceId,
        user: UserId,
    ) -> impl Future<Output = Result<bool, StoreError>> + Send;
}

/// Why a recovery request was refused.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RecoveryError {
    /// No such space, the caller isn't an invited or confirmed member of it, or there is nothing
    /// to serve (the member isn't confirmed or hasn't enrolled).
    NotFound,
    /// The caller isn't allowed: not a confirmed member, not an Owner or Admin, or an Admin asking
    /// for an Owner.
    Forbidden,
    /// The space's chain has `accountRecovery` off (or no chain at all).
    NotEnabled,
    /// `key_seq` isn't the record that set the chain's current recovery key.
    Stale {
        current: Option<u64>,
    },
    /// The box isn't the shape of a sealed root key.
    Invalid(&'static str),
    /// The account replaced its keys after the box was made.
    StaleKeyVersion {
        current: u32,
    },
    Store(String),
}

impl From<StoreError> for RecoveryError {
    fn from(e: StoreError) -> Self {
        match e {
            StoreError::StaleKeyVersion { current } => RecoveryError::StaleKeyVersion { current },
            other => RecoveryError::Store(other.to_string()),
        }
    }
}

/// What an Owner or Admin gets for a member.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Recovered {
    pub sealed: Vec<u8>,
    pub key_seq: u64,
    /// The chain's recovery key is no longer the one the box was sealed under.
    pub stale: bool,
}

/// Whether a caller of this role may recover a member of that role.
pub fn may_recover(caller: Role, member: Role) -> bool {
    match caller {
        Role::Owner => true,
        Role::Admin => member != Role::Owner,
        Role::Custom | Role::Member => false,
    }
}

/// Whether a box is the shape of a sealed 64-byte root key.
pub fn well_formed(sealed: &[u8]) -> bool {
    sealed.len() == RECOVERY_BOX_LEN && sealed.first() == Some(&1)
}

fn confirmed_role(state: &State, user: UserId) -> Option<Role> {
    state
        .members
        .get(user.0.as_bytes())
        .filter(|m| m.status == Status::Confirmed)
        .map(|m| m.role)
}

/// `PUT`, `DELETE` and `GET` of `/kem/v1/spaces/{id}/members/{user}/recovery`.
#[derive(Debug)]
pub struct SpaceRecovery<R, V, C> {
    pub spaces: R,
    pub events: V,
    pub clock: C,
}

impl<R, V, C> SpaceRecovery<R, V, C>
where
    R: SpaceRepo + SpaceChainRepo + SpaceRecoveryRepo,
    V: EventLog,
    C: Clock,
{
    /// The caller's own row in the space, when they are invited, accepted or confirmed.
    async fn in_space(&self, actor: &Actor, space: SpaceId) -> Result<(), RecoveryError> {
        self.spaces
            .memberships(actor.user)
            .await?
            .into_iter()
            .find(|m| m.space == space && m.state != MemberState::Revoked)
            .map(|_| ())
            .ok_or(RecoveryError::NotFound)
    }

    /// Enrols the caller: stores `sealed`, sealed under the recovery key set by chain record
    /// `key_seq`, replacing any earlier box.
    pub async fn enrol(
        &self,
        actor: &Actor,
        space: SpaceId,
        key_seq: u64,
        sealed: Vec<u8>,
    ) -> Result<(), RecoveryError> {
        self.enrol_at(actor, space, key_seq, sealed, None).await
    }

    /// [`enrol`](SpaceRecovery::enrol) with a root key at `key_version`: refused
    /// (`StaleKeyVersion`) when the account has replaced its keys since. A client that doesn't
    /// say passes `None`.
    pub async fn enrol_at(
        &self,
        actor: &Actor,
        space: SpaceId,
        key_seq: u64,
        sealed: Vec<u8>,
        key_version: Option<u32>,
    ) -> Result<(), RecoveryError> {
        self.in_space(actor, space).await?;
        let Some((_, state)) = self.spaces.chain_state(space).await? else {
            return Err(RecoveryError::NotEnabled);
        };
        if confirmed_role(&state, actor.user).is_none() {
            return Err(RecoveryError::Forbidden);
        }
        if !state.policies.account_recovery {
            return Err(RecoveryError::NotEnabled);
        }
        if state.recovery_key_seq != Some(key_seq) {
            return Err(RecoveryError::Stale {
                current: state.recovery_key_seq,
            });
        }
        if !well_formed(&sealed) {
            return Err(RecoveryError::Invalid(
                "the box is a sealed 64-byte root key: u8(1) first, 1693 bytes",
            ));
        }
        let now = self.clock.now();
        self.spaces
            .put_recovery_box_at(
                RecoveryBox {
                    space,
                    user: actor.user,
                    key_seq,
                    sealed,
                    enrolled_at: now,
                },
                key_version,
            )
            .await?;
        record(
            &self.events,
            actor,
            "space.recovery.enrol",
            space.to_string(),
            now,
        )
        .await;
        Ok(())
    }

    /// Withdraws the caller's box. Nothing to withdraw is not an error.
    pub async fn withdraw(&self, actor: &Actor, space: SpaceId) -> Result<(), RecoveryError> {
        self.in_space(actor, space).await?;
        if self.spaces.delete_recovery_box(space, actor.user).await? {
            record(
                &self.events,
                actor,
                "space.recovery.withdraw",
                space.to_string(),
                self.clock.now(),
            )
            .await;
        }
        Ok(())
    }

    /// The box of `member`, for an Owner or Admin who may recover them.
    pub async fn fetch(
        &self,
        actor: &Actor,
        space: SpaceId,
        member: UserId,
    ) -> Result<Recovered, RecoveryError> {
        self.in_space(actor, space).await?;
        let Some((_, state)) = self.spaces.chain_state(space).await? else {
            return Err(RecoveryError::Forbidden);
        };
        let caller = confirmed_role(&state, actor.user).ok_or(RecoveryError::Forbidden)?;
        if !matches!(caller, Role::Owner | Role::Admin) {
            return Err(RecoveryError::Forbidden);
        }
        let target = confirmed_role(&state, member).ok_or(RecoveryError::NotFound)?;
        if !may_recover(caller, target) {
            return Err(RecoveryError::Forbidden);
        }
        let stored = self
            .spaces
            .recovery_box(space, member)
            .await?
            .ok_or(RecoveryError::NotFound)?;
        record(
            &self.events,
            actor,
            "space.recovery.read",
            format!("{space}/{member}"),
            self.clock.now(),
        )
        .await;
        Ok(Recovered {
            stale: state.recovery_key_seq != Some(stored.key_seq),
            key_seq: stored.key_seq,
            sealed: stored.sealed,
        })
    }
}
