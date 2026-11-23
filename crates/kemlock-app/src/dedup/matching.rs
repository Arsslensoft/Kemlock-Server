//! Turning server matching on or off, and the key rotation that moves the dedup key version.

use super::access::{Need, authorize};
use super::error::DedupError;
use super::ports::TagStore;
use crate::authenticate::Actor;
use crate::ports::{Clock, Event, EventLog};
use crate::spaces::SpaceRepo;
use kemlock_domain::{MatchingSettings, Owner};

/// Turns server matching on or off for an owner. A person decides for their own vault; for a space
/// its owners and admins do, and every member then sees who changed it and when (`GetMatching`).
#[derive(Debug)]
pub struct SetMatching<T, R, V, C> {
    pub tags: T,
    pub spaces: R,
    pub events: V,
    pub clock: C,
}

impl<T: TagStore, R: SpaceRepo, V: EventLog, C: Clock> SetMatching<T, R, V, C> {
    /// Sets the switch and returns the settings as stored. Turning it off deletes every tag the
    /// owner uploaded (`DELETE /kem/v1/duplicates/tags` is this with `enabled` false).
    pub async fn execute(
        &self,
        actor: &Actor,
        owner: Owner,
        enabled: bool,
    ) -> Result<MatchingSettings, DedupError> {
        authorize(&self.spaces, actor.user, owner, Need::Settings).await?;
        let now = self.clock.now();
        let settings = self
            .tags
            .set_matching(owner, enabled, actor.user, now)
            .await?;
        let event = Event {
            actor: Some(actor.user),
            device: Some(actor.device),
            action: if enabled {
                "dedup.matching-on"
            } else {
                "dedup.matching-off"
            },
            target: Some(owner.to_string()),
            at: now,
        };
        if let Err(e) = self.events.record(event).await {
            tracing::warn!(error = %e, "couldn't record a duplicate-matching event");
        }
        Ok(settings)
    }
}

/// A new user key or space key: the owner's tags are deleted and the dedup key version moves up,
/// and the device doing the rotation uploads new tags under the new version.
#[derive(Debug)]
pub struct RotateDedupKey<T, C> {
    pub tags: T,
    pub clock: C,
}

impl<T: TagStore, C: Clock> RotateDedupKey<T, C> {
    /// Returns the new version.
    pub async fn execute(&self, owner: Owner) -> Result<u32, DedupError> {
        Ok(self.tags.bump_version(owner, self.clock.now()).await?)
    }
}
