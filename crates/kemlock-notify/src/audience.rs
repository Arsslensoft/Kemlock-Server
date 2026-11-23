//! Who a nudge for an owner is for. A person's vault is theirs alone; a space's nudge is for its
//! confirmed members.

use kemlock_app::notices::BoxFuture;
use kemlock_app::spaces::SpaceRepo;
use kemlock_domain::spaces::MemberState;
use kemlock_domain::{Owner, UserId};

/// Maps an owner to the accounts whose devices should hear of a change to it.
pub trait Audience: Send + Sync + 'static {
    /// The accounts. A failure to look them up is the implementor's to log; it answers with none.
    fn users(&self, owner: Owner) -> BoxFuture<'_, Vec<UserId>>;
}

/// Audience for a server with no spaces: an account hears of its own vault, a space of nobody.
#[derive(Clone, Copy, Debug, Default)]
pub struct UserOnly;

impl Audience for UserOnly {
    fn users(&self, owner: Owner) -> BoxFuture<'_, Vec<UserId>> {
        Box::pin(async move {
            match owner {
                Owner::User(user) => vec![user],
                Owner::Space(_) => Vec::new(),
            }
        })
    }
}

/// An account hears of its own vault; a space's confirmed members hear of the space.
#[derive(Clone, Debug)]
pub struct SpaceMembers<R>(pub R);

impl<R: SpaceRepo + 'static> Audience for SpaceMembers<R> {
    fn users(&self, owner: Owner) -> BoxFuture<'_, Vec<UserId>> {
        Box::pin(async move {
            match owner {
                Owner::User(user) => vec![user],
                Owner::Space(space) => match self.0.load(space).await {
                    Ok(Some(state)) => state
                        .members
                        .iter()
                        .filter(|m| m.state == MemberState::Confirmed)
                        .map(|m| m.user)
                        .collect(),
                    Ok(None) => Vec::new(),
                    Err(error) => {
                        tracing::warn!(%error, "couldn't read a space's members for a nudge");
                        Vec::new()
                    }
                },
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use kemlock_domain::SpaceId;

    #[tokio::test]
    async fn a_person_hears_of_their_own_vault() {
        let user = UserId::random();
        assert_eq!(UserOnly.users(Owner::User(user)).await, vec![user]);
        assert!(
            UserOnly
                .users(Owner::Space(SpaceId::random()))
                .await
                .is_empty()
        );
    }
}
