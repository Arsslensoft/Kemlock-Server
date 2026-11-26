//! What the SSO use cases fail with. A route maps each variant to a status and a problem type;
//! other sign-in paths that only need to know "no" convert it into an `AppError`.

use crate::error::AppError;
use crate::ports::StoreError;
use kemlock_domain::SpaceId;

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum SsoError {
    /// SSO is off, or no provider has been set up.
    #[error("single sign-on is not set up")]
    NotConfigured,
    /// The request is well-formed but breaks a rule; the text says which.
    #[error("invalid request: {0}")]
    Invalid(&'static str),
    /// The sealed state or code is damaged, expired or isn't ours.
    #[error("the sign-in has expired or is invalid")]
    BadState,
    /// The identity provider couldn't be reached or answered something unusable. The text is for
    /// logs, never for clients.
    #[error("identity provider failure: {0}")]
    Provider(String),
    /// The ID token or logout token didn't validate. The text is for logs.
    #[error("token refused: {0}")]
    Token(String),
    /// The provider didn't say the email is verified, and the exception doesn't apply.
    #[error("the provider didn't verify the email address")]
    EmailNotVerified,
    /// The email's domain has no DNS proof where one is required.
    #[error("the email's domain hasn't been proven by DNS")]
    DomainNotVerified,
    /// An account with this email exists and linking by email is off.
    #[error("an account with this email exists; linking by email is off")]
    LinkingNotAllowed,
    /// The account with this email is a server administrator's, which is never linked by email:
    /// whoever the provider says owns the address would be given the console. It signs in with its
    /// password and second step.
    #[error("an administrator's account isn't linked by email")]
    AdminLinkingRefused,
    /// No account matches and the admin turned automatic sign-up off.
    #[error("no account matches and new accounts aren't created")]
    NoAccount,
    /// A space the account belongs to requires SSO, so this way in is closed to it.
    #[error("space {space} requires single sign-on")]
    SsoRequired { space: SpaceId },
    /// The proof binding the finish to the start didn't match: the verifier or the device key.
    #[error("unauthorized")]
    Unauthorized,
    /// The domain proof the admin asked to check isn't in DNS yet.
    #[error("the DNS record isn't there yet")]
    DomainProofMissing,
    #[error(transparent)]
    App(AppError),
}

impl From<AppError> for SsoError {
    fn from(e: AppError) -> Self {
        SsoError::App(e)
    }
}

impl From<StoreError> for SsoError {
    fn from(e: StoreError) -> Self {
        SsoError::App(AppError::from(e))
    }
}

impl From<SsoError> for AppError {
    fn from(e: SsoError) -> Self {
        match e {
            SsoError::NotConfigured => AppError::NotFound,
            SsoError::Invalid(why) => AppError::Invalid(why),
            SsoError::BadState => AppError::Invalid("the sign-in has expired or is invalid"),
            SsoError::Provider(_) | SsoError::Token(_) | SsoError::Unauthorized => {
                AppError::Unauthorized
            }
            SsoError::EmailNotVerified
            | SsoError::DomainNotVerified
            | SsoError::LinkingNotAllowed
            | SsoError::AdminLinkingRefused
            | SsoError::NoAccount => AppError::Forbidden,
            SsoError::SsoRequired { space } => AppError::SsoRequired { space },
            SsoError::DomainProofMissing => AppError::Invalid("the DNS record isn't there yet"),
            SsoError::App(e) => e,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn errors_map_to_the_app_errors_other_paths_know() {
        assert_eq!(AppError::from(SsoError::NotConfigured), AppError::NotFound);
        let space = SpaceId::random();
        assert_eq!(
            AppError::from(SsoError::SsoRequired { space }),
            AppError::SsoRequired { space }
        );
        assert_eq!(
            AppError::from(SsoError::Token("bad".into())),
            AppError::Unauthorized
        );
        assert_eq!(
            AppError::from(SsoError::App(AppError::Duplicate)),
            AppError::Duplicate
        );
        assert_eq!(
            SsoError::from(StoreError::Duplicate),
            SsoError::App(AppError::Duplicate)
        );
    }
}
