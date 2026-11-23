//! Look an account up by email before inviting it. An admin's app needs the account's id and
//! public-key bundle to build the chain's `invite` record, and to show the fingerprint it will
//! compare at confirmation.

use super::error::SpacesError;
use super::ports::SpaceRepo;
use super::support::load_state;
use crate::authenticate::Actor;
use crate::ports::UserRepo;
use kemlock_domain::spaces::SpaceError;
use kemlock_domain::{Email, SpaceId, UserId};

#[derive(Debug)]
pub struct LookupAccount<R, U> {
    pub spaces: R,
    pub users: U,
}

/// An account an admin may invite: its id and its public-key bundle, which is public.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AccountLookup {
    pub account: UserId,
    pub public_bundle: Vec<u8>,
    pub bundle_signature: Vec<u8>,
    pub key_version: u32,
}

impl<R: SpaceRepo, U: UserRepo> LookupAccount<R, U> {
    /// The account with this email, for a confirmed Owner, Admin or Custom member with Manage
    /// users of the space (the space may have a chain: this only reads). `None` when there is no
    /// such account, or it has no keys yet. The caller's right is checked first, so only those
    /// who may invite learn whether an email has an account.
    pub async fn execute(
        &self,
        actor: &Actor,
        space: SpaceId,
        email: &str,
    ) -> Result<Option<AccountLookup>, SpacesError> {
        let state = load_state(&self.spaces, space).await?;
        state.authorize_manage_users(actor.user)?;
        let email = Email::parse(email)
            .map_err(|_| SpacesError::Rule(SpaceError::Invalid("not an email address")))?;
        Ok(self
            .users
            .by_email(&email)
            .await?
            .filter(|user| !user.public_bundle.is_empty())
            .map(|user| AccountLookup {
                account: user.id,
                public_bundle: user.public_bundle,
                bundle_signature: user.bundle_signature,
                key_version: user.key_version,
            }))
    }
}
