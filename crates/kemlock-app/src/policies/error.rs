//! What a policy use case can fail with. The API layer maps each variant to a status.

use crate::ports::StoreError;
use kemlock_domain::policies::PolicyInvalid;
use kemlock_domain::spaces::SpaceError;

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum PoliciesError {
    /// The space isn't there, or the caller isn't a confirmed member of it: the same answer, so a
    /// person outside a space learns nothing about it.
    #[error("not found")]
    NotFound,
    /// The caller is a member but their role may not do this.
    #[error("{0}")]
    Forbidden(&'static str),
    #[error("{0}")]
    Invalid(&'static str),
    /// The space requires two-step login and the person has none.
    #[error("this space requires two-step login, and the account has none")]
    TwoStepRequired,
    /// The space allows one space per member, and the person is in another.
    #[error("this space allows its members in no other space")]
    SingleSpace,
    /// The person is in a space that allows them in no other.
    #[error("a space the account belongs to allows its members in no other space")]
    OtherSpaceSingle,
    /// The database failed; the message is for logs only.
    #[error("store failure: {0}")]
    Store(String),
}

impl From<StoreError> for PoliciesError {
    fn from(e: StoreError) -> Self {
        match e {
            StoreError::NotFound => PoliciesError::NotFound,
            other => PoliciesError::Store(other.to_string()),
        }
    }
}

impl From<PolicyInvalid> for PoliciesError {
    fn from(e: PolicyInvalid) -> Self {
        PoliciesError::Invalid(e.0)
    }
}

impl From<SpaceError> for PoliciesError {
    fn from(e: SpaceError) -> Self {
        match e {
            SpaceError::NotAMember => PoliciesError::NotFound,
            SpaceError::Forbidden(why) => PoliciesError::Forbidden(why),
            SpaceError::Invalid(why) | SpaceError::State(why) => PoliciesError::Invalid(why),
            SpaceError::KeysPending => {
                PoliciesError::Invalid("the space's keys must be replaced first")
            }
            SpaceError::StaleKeyVersion { .. }
            | SpaceError::FingerprintMismatch
            | SpaceError::LastOwner => PoliciesError::Invalid("the space refused this"),
        }
    }
}

impl From<crate::spaces::SpacesError> for PoliciesError {
    fn from(e: crate::spaces::SpacesError) -> Self {
        use crate::spaces::SpacesError;
        match e {
            SpacesError::Rule(rule) => rule.into(),
            SpacesError::NotFound => PoliciesError::NotFound,
            SpacesError::Store(message) => PoliciesError::Store(message),
            _ => PoliciesError::Store("unexpected spaces error".to_owned()),
        }
    }
}
