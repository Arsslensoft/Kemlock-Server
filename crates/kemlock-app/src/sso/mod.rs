//! Single sign-on through OpenID Connect: the use cases, the ports they call and the rules they
//! apply (design, "Identity and SSO").
//!
//! SSO decides who may sign in and never holds or hands out a vault key; a vault opens on the
//! device, from a trusted-device key, an approval from another device or the master password.
//!
//! The flow, as the Kemlock app plans it (decision 9 of `add-kemlock-server-sync`):
//!
//! 1. [`SsoStart`]: the phone sends a PKCE challenge, its own `state` and a DPoP proof; the server
//!    answers with the provider's authorization URL. The URL's `state` is the server's, sealed.
//! 2. The phone opens it in the system browser. The provider redirects to the server's callback.
//! 3. [`SsoCallback`]: the server checks its sealed `state` and redirects the browser to the app
//!    with a sealed one-time code.
//! 4. [`SsoFinish`]: the phone sends the code, its PKCE verifier and a DPoP proof. The server
//!    exchanges the provider's code, validates the ID token, finds or makes the account and issues
//!    the usual tokens, or asks for the second step.
//!
//! Beside the flow: [`SsoLogout`] ends a subject's sessions when the provider's session ends,
//! [`RequireSso`] is the check other sign-in paths call, [`DomainProofs`] proves email domains by
//! DNS, and [`rules`] maps the `groups` claim to spaces and roles.

pub mod callback;
pub mod claims;
pub mod config;
pub mod domains;
pub mod error;
pub mod finish;
pub mod logout;
pub mod methods;
pub mod model;
pub mod policy;
pub mod ports;
pub mod rules;
pub mod start;
pub mod state;

pub use callback::{CallbackInput, SsoCallback};
pub use config::SsoConfig;
pub use domains::DomainProofs;
pub use error::SsoError;
pub use finish::{FinishInput, SsoFinish, SsoSignedIn};
pub use logout::{LogoutOutcome, SsoLogout};
pub use methods::SignInMethods;
pub use model::{
    ClientConfig, GroupAssignment, GroupRule, IdentityClaims, LogoutClaims, SpaceRole, SsoIdentity,
    SsoSettings, VerifiedDomain,
};
pub use policy::{RequireSso, SignInMethod};
pub use ports::{
    GroupSync, MembershipFacts, NoSpaces, OidcProvider, SpaceMembership, SsoIdentityRepo, SsoRepos,
    SsoSettingsRepo, TxtLookup, VerifiedDomainRepo,
};
pub use start::{SsoStart, StartInput, Started};
