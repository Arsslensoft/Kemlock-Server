//! Read and set a space's policies, and read what binds one person.

use super::error::PoliciesError;
use super::ports::{PolicyRepo, StoredPolicies};
use crate::authenticate::Actor;
use crate::ports::{Clock, Event, EventLog, StoreError};
use crate::spaces::SpaceRepo;
use kemlock_domain::policies::{BoundBy, EffectivePolicies, SpacePolicies, is_exempt};
use kemlock_domain::{SpaceId, UserId};

/// What binds `user` across every space they are in.
pub(crate) async fn effective_of<R: SpaceRepo, P: PolicyRepo>(
    spaces: &R,
    policies: &P,
    user: UserId,
) -> Result<EffectivePolicies, StoreError> {
    let memberships = spaces.memberships(user).await?;
    if memberships.is_empty() {
        return Ok(EffectivePolicies::default());
    }
    let ids: Vec<SpaceId> = memberships.iter().map(|m| m.space).collect();
    let by_space = policies.policies_of_spaces(&ids).await?;
    let bound: Vec<BoundBy> = memberships
        .iter()
        .filter_map(|m| {
            by_space.get(&m.space).map(|p| BoundBy {
                role: m.role,
                state: m.state,
                policies: p.clone(),
            })
        })
        .collect();
    Ok(EffectivePolicies::of(&bound))
}

#[derive(Debug)]
pub struct GetPolicies<R, P> {
    pub spaces: R,
    pub policies: P,
}

impl<R: SpaceRepo, P: PolicyRepo> GetPolicies<R, P> {
    /// A space's policies, for any confirmed member: clients need them to enforce the ones only a
    /// client can. Someone outside the space gets `NotFound`.
    pub async fn execute(
        &self,
        actor: &Actor,
        space: SpaceId,
    ) -> Result<StoredPolicies, PoliciesError> {
        let state = self
            .spaces
            .load(space)
            .await?
            .ok_or(PoliciesError::NotFound)?;
        state.confirmed_actor(actor.user)?;
        Ok(self.policies.space_policies(space).await?)
    }
}

#[derive(Debug)]
pub struct SetPolicies<R, P, V, C> {
    pub spaces: R,
    pub policies: P,
    pub events: V,
    pub clock: C,
}

impl<R: SpaceRepo, P: PolicyRepo, V: EventLog, C: Clock> SetPolicies<R, P, V, C> {
    /// Replaces a space's policies. Only a confirmed owner or admin may. Turning a policy on does
    /// not remove members who break it; it applies from their next join (and, for the ones clients
    /// enforce, at once).
    pub async fn execute(
        &self,
        actor: &Actor,
        space: SpaceId,
        new: SpacePolicies,
    ) -> Result<StoredPolicies, PoliciesError> {
        let state = self
            .spaces
            .load(space)
            .await?
            .ok_or(PoliciesError::NotFound)?;
        let me = state.confirmed_actor(actor.user)?;
        if !is_exempt(me.role) {
            return Err(PoliciesError::Forbidden(
                "only an owner or an admin sets a space's policies",
            ));
        }
        new.validate()?;
        let now = self.clock.now();
        self.policies
            .put_space_policies(space, &new, actor.user, now)
            .await?;
        let event = Event {
            actor: Some(actor.user),
            device: Some(actor.device),
            action: "space.policies.update",
            target: Some(space.to_string()),
            at: now,
        };
        if let Err(e) = self.events.record(event).await {
            tracing::warn!(error = %e, "couldn't record a policy event");
        }
        Ok(StoredPolicies {
            policies: new,
            updated_at: Some(now),
            updated_by: Some(actor.user),
        })
    }
}

#[derive(Debug)]
pub struct MyPolicies<R, P> {
    pub spaces: R,
    pub policies: P,
}

impl<R: SpaceRepo, P: PolicyRepo> MyPolicies<R, P> {
    /// What binds the caller after every space they are in has had its say: the strictest master
    /// password rules and the shortest timeout, and which policies are on. Clients read it at
    /// sign-in and on sync.
    pub async fn execute(&self, actor: &Actor) -> Result<EffectivePolicies, PoliciesError> {
        Ok(effective_of(&self.spaces, &self.policies, actor.user).await?)
    }
}
