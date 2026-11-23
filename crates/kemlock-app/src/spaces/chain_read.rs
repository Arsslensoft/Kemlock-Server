//! Reading a space's chain: the records, the seal hashes of one record, and the external changes
//! kept for the space's admins (docs/crypto.md, "Space chain": G1 to G5).

use super::chain::{ChainHead, PendingExternal, SpaceChainRepo, StoredRecord, StoredSeal};
use super::ports::SpaceRepo;
use super::support::record;
use crate::authenticate::Actor;
use crate::ports::{Clock, EventLog, StoreError, UserRepo};
use kemlock_domain::SpaceId;
use kemlock_domain::spaces::{MemberState, SpaceRole};
use uuid::Uuid;

/// Why a chain couldn't be read.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ChainReadError {
    /// No such space, or the caller isn't an invited or confirmed member of it (G3): a removed
    /// member gets this too, as for every other space route.
    NotFound,
    Forbidden,
    Store(String),
}

impl From<StoreError> for ChainReadError {
    fn from(e: StoreError) -> Self {
        ChainReadError::Store(e.to_string())
    }
}

/// The caller's row in the space, when they are invited, accepted or confirmed.
async fn member_row<R: SpaceRepo>(
    spaces: &R,
    actor: &Actor,
    space: SpaceId,
) -> Result<kemlock_domain::spaces::Member, ChainReadError> {
    spaces
        .memberships(actor.user)
        .await?
        .into_iter()
        .find(|m| m.space == space && m.state != MemberState::Revoked)
        .ok_or(ChainReadError::NotFound)
}

/// `GET /kem/v1/spaces/{id}/chain`: the whole chain, or from a `seq`.
#[derive(Debug)]
pub struct GetChain<R> {
    pub spaces: R,
}

impl<R: SpaceRepo + SpaceChainRepo> GetChain<R> {
    /// The records with `seq >= from`: an empty list past the head or for a space with no chain.
    pub async fn execute(
        &self,
        actor: &Actor,
        space: SpaceId,
        from: u64,
    ) -> Result<Vec<StoredRecord>, ChainReadError> {
        member_row(&self.spaces, actor, space).await?;
        Ok(self.spaces.chain_records(space, from).await?)
    }

    /// The head, for a caller who is a member.
    pub async fn head(
        &self,
        actor: &Actor,
        space: SpaceId,
    ) -> Result<Option<ChainHead>, ChainReadError> {
        member_row(&self.spaces, actor, space).await?;
        Ok(self.spaces.chain_head(space).await?)
    }
}

/// `GET /kem/v1/spaces/{id}/chain/{seq}/seals`: the sealed keys record `seq` committed.
#[derive(Debug)]
pub struct GetChainSeals<R> {
    pub spaces: R,
}

impl<R: SpaceRepo + SpaceChainRepo> GetChainSeals<R> {
    /// The boxes of one record, sorted by key then member. A `seq` past the head is not found.
    pub async fn execute(
        &self,
        actor: &Actor,
        space: SpaceId,
        seq: u64,
    ) -> Result<Vec<StoredSeal>, ChainReadError> {
        member_row(&self.spaces, actor, space).await?;
        let head = self
            .spaces
            .chain_head(space)
            .await?
            .ok_or(ChainReadError::NotFound)?;
        if seq > head.seq {
            return Err(ChainReadError::NotFound);
        }
        let mut seals = self.spaces.chain_seals(space, seq).await?;
        seals.sort_by_key(|s| (s.key, s.member, s.version));
        Ok(seals)
    }
}

/// The external changes kept for the space's Owners and Admins to sign as records (mode `queue`).
#[derive(Debug)]
pub struct PendingChanges<R, U, V, C> {
    pub spaces: R,
    pub users: U,
    pub events: V,
    pub clock: C,
}

impl<R: SpaceRepo + SpaceChainRepo, U: UserRepo, V: EventLog, C: Clock> PendingChanges<R, U, V, C> {
    async fn admin(&self, actor: &Actor, space: SpaceId) -> Result<(), ChainReadError> {
        let row = member_row(&self.spaces, actor, space).await?;
        if row.state == MemberState::Confirmed
            && matches!(row.role, SpaceRole::Owner | SpaceRole::Admin)
        {
            Ok(())
        } else {
            Err(ChainReadError::Forbidden)
        }
    }

    pub async fn list(
        &self,
        actor: &Actor,
        space: SpaceId,
    ) -> Result<Vec<PendingExternal>, ChainReadError> {
        self.admin(actor, space).await?;
        let mut list = self.spaces.pending_external(space).await?;
        for item in &mut list {
            if item.email.is_none()
                && let Some(user) = self.users.by_id(item.account).await?
            {
                item.email = Some(user.email.as_str().to_owned());
            }
        }
        Ok(list)
    }

    pub async fn dismiss(
        &self,
        actor: &Actor,
        space: SpaceId,
        id: Uuid,
    ) -> Result<bool, ChainReadError> {
        self.admin(actor, space).await?;
        let gone = self.spaces.dismiss_external(space, id).await?;
        if gone {
            record(
                &self.events,
                actor,
                "space.chain.pending.drop",
                format!("{space}/{id}"),
                self.clock.now(),
            )
            .await;
        }
        Ok(gone)
    }
}
