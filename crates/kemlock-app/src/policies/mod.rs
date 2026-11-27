//! Space policies: the rules an owner or admin sets for a space's members.
//!
//! The settings are `kemlock_domain::policies::SpacePolicies`; this module reads and writes them
//! ([`GetPolicies`], [`SetPolicies`]), works out what binds one person across their spaces
//! ([`MyPolicies`]), and holds the checks the server can enforce:
//!
//! - [`JoinGuard`] runs when someone is about to join a space: a space that requires two-step login
//!   refuses a member without one, and "one space per member" refuses a second space, in either
//!   direction;
//! - [`MemberSendRules`] tells the Send use cases what the person's policies allow;
//! - master password rules are *reported* by [`MyPolicies`] and [`GetPolicies`], since the server
//!   never sees a password; clients enforce them;
//! - "Require SSO" is enforced at sign-in by `crate::sso::policy`, which reads the facts this
//!   module's store provides ([`crate::sso::MembershipFacts`]).
//!
//! [`bitwarden`] maps a space's policies to Bitwarden's policy type numbers and JSON, and back, for
//! the Bitwarden API.

pub mod bitwarden;
pub mod error;
pub mod guard;
pub mod ports;
pub mod rules;
pub mod view;

pub use error::PoliciesError;
pub use guard::{JoinGuard, check_join, refusal_in_spaces};
pub use ports::{PolicyRepo, StoredPolicies};
pub use rules::MemberSendRules;
pub use view::{GetPolicies, MyPolicies, SetPolicies};
