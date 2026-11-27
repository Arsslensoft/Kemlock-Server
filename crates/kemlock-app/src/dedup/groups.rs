//! Reading the groups (`GET /kem/v1/duplicates`) and the settings of server matching.

use super::access::{Need, authorize, visible};
use super::error::DedupError;
use super::ports::{DismissalStore, TagStore};
use crate::authenticate::Actor;
use crate::spaces::SpaceRepo;
use kemlock_domain::dedup::without_dismissed;
use kemlock_domain::{DuplicateGroup, MatchingSettings, Owner};

/// What `GET /kem/v1/duplicates` answers.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DuplicateReport {
    /// Whether server matching is on for the owner. When it isn't there are no groups.
    pub enabled: bool,
    /// The dedup key version the groups were made under.
    pub version: u32,
    /// Groups of items with equal tags, without the ones answered "Not duplicates".
    pub groups: Vec<DuplicateGroup>,
    /// Live items still waiting for tags.
    pub waiting: u64,
}

/// Lists the owner's duplicate groups.
#[derive(Debug)]
pub struct ListDuplicates<T, D, R> {
    pub tags: T,
    pub dismissals: D,
    pub spaces: R,
}

impl<T: TagStore, D: DismissalStore, R: SpaceRepo> ListDuplicates<T, D, R> {
    /// The groups of `owner` that `actor` may see. In a space a member sees only the items of
    /// collections they hold a grant on, and a group left with fewer than two of them is hidden.
    pub async fn execute(
        &self,
        actor: &Actor,
        owner: Owner,
    ) -> Result<DuplicateReport, DedupError> {
        let state = authorize(&self.spaces, actor.user, owner, Need::Read).await?;
        let settings = self.tags.settings(owner).await?;
        if !settings.enabled {
            return Ok(DuplicateReport {
                enabled: false,
                version: settings.version,
                groups: Vec::new(),
                waiting: 0,
            });
        }
        let mut groups = self.tags.groups(owner, settings.version).await?;
        let dismissals = self.dismissals.list(owner).await?;
        groups = without_dismissed(groups, &dismissals);
        if let Some(state) = &state {
            let all: Vec<_> = groups
                .iter()
                .flat_map(|g| g.items.iter().copied())
                .collect();
            let seen = visible(&self.spaces, state, actor.user, &all).await?;
            groups = groups
                .into_iter()
                .filter_map(|mut group| {
                    group.items.retain(|item| seen.contains(item));
                    (group.items.len() >= 2).then_some(group)
                })
                .collect();
        }
        // In a space the count is of what this member sees, as the groups are.
        let waiting = match &state {
            Some(state) => {
                let waiting = self.tags.waiting_items(owner, settings.version).await?;
                let seen = visible(&self.spaces, state, actor.user, &waiting).await?;
                u64::try_from(seen.len()).unwrap_or(u64::MAX)
            }
            None => self.tags.waiting(owner, settings.version).await?,
        };
        Ok(DuplicateReport {
            enabled: true,
            version: settings.version,
            groups,
            waiting,
        })
    }
}

/// Reads whether server matching is on for an owner, who turned it on and when, so every member
/// of a space can be shown what the server can then learn.
#[derive(Debug)]
pub struct GetMatching<T, R> {
    pub tags: T,
    pub spaces: R,
}

impl<T: TagStore, R: SpaceRepo> GetMatching<T, R> {
    pub async fn execute(
        &self,
        actor: &Actor,
        owner: Owner,
    ) -> Result<MatchingSettings, DedupError> {
        authorize(&self.spaces, actor.user, owner, Need::Read).await?;
        Ok(self.tags.settings(owner).await?)
    }
}
