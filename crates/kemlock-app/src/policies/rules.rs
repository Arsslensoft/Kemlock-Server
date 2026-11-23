//! What a person's policies allow them to do with Sends: the bridge from the policies to the Send
//! use cases' [`SendPolicies`] port.

use super::ports::PolicyRepo;
use super::view::effective_of;
use crate::ports::StoreError;
use crate::sends::{SendPolicies, SendRules};
use crate::spaces::SpaceRepo;
use kemlock_domain::UserId;

/// [`SendPolicies`] over the spaces and their policies.
#[derive(Clone, Debug)]
pub struct MemberSendRules<R, P> {
    pub spaces: R,
    pub policies: P,
}

impl<R: SpaceRepo, P: PolicyRepo> SendPolicies for MemberSendRules<R, P> {
    async fn send_rules(&self, user: UserId) -> Result<SendRules, StoreError> {
        let effective = effective_of(&self.spaces, &self.policies, user).await?;
        Ok(SendRules {
            disabled: effective.disable_send,
            force_email: effective.always_show_email,
        })
    }
}
