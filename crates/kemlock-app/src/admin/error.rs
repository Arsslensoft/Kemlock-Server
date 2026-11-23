//! What an admin use case can fail with. The admin API maps each variant to a status and a
//! problem type.

use crate::error::AppError;
use crate::ports::StoreError;
use crate::spaces::SpacesError;
use crate::sso::SsoError;
use kemlock_domain::spaces::SpaceError;

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum AdminError {
    #[error("not found")]
    NotFound,
    /// The request breaks a rule; the text says which.
    #[error("invalid request: {0}")]
    Invalid(String),
    /// The target isn't in the state the action needs, or the action would leave the server
    /// without something it needs (its last admin, a space's last owner).
    #[error("{0}")]
    State(&'static str),
    /// The setting is set by the environment, so the console may not change it.
    #[error("{0} is set by the environment")]
    ReadOnly(String),
    #[error("forbidden: {0}")]
    Forbidden(&'static str),
    /// The write needs a fresh step-up token (a password or two-step check made just now).
    #[error("a fresh password or two-step check is required")]
    StepUpRequired,
    /// The password or the code of a step-up check was wrong. Deliberately says nothing more.
    #[error("the step-up check failed")]
    StepUpFailed,
    /// The feature needs something the server isn't set up with (mail, a provider).
    #[error("{0}")]
    NotConfigured(&'static str),
    #[error(transparent)]
    App(AppError),
}

impl From<AppError> for AdminError {
    fn from(e: AppError) -> Self {
        match e {
            AppError::NotFound => AdminError::NotFound,
            AppError::Duplicate => AdminError::State("that already exists"),
            other => AdminError::App(other),
        }
    }
}

impl From<StoreError> for AdminError {
    fn from(e: StoreError) -> Self {
        AdminError::from(AppError::from(e))
    }
}

impl From<SpacesError> for AdminError {
    fn from(e: SpacesError) -> Self {
        match e {
            SpacesError::NotFound | SpacesError::Rule(SpaceError::NotAMember) => {
                AdminError::NotFound
            }
            SpacesError::Rule(
                SpaceError::Forbidden(why) | SpaceError::State(why) | SpaceError::Invalid(why),
            ) => AdminError::State(why),
            SpacesError::Rule(SpaceError::LastOwner) => {
                AdminError::State("a space needs at least one confirmed owner")
            }
            other => AdminError::from(AppError::from(other)),
        }
    }
}

impl From<SsoError> for AdminError {
    fn from(e: SsoError) -> Self {
        match e {
            SsoError::Invalid(why) => AdminError::Invalid(why.to_owned()),
            SsoError::App(e) => AdminError::from(e),
            SsoError::NotConfigured => AdminError::NotConfigured("single sign-on isn't set up"),
            SsoError::DomainProofMissing => AdminError::State("the DNS record isn't there yet"),
            SsoError::Provider(message) => {
                AdminError::App(AppError::Store(format!("DNS lookup failed: {message}")))
            }
            _ => AdminError::App(AppError::Unauthorized),
        }
    }
}
