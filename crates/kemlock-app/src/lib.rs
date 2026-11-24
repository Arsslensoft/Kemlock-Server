//! Kemlock Server's use cases, one module each, and the ports (traits) they call.
//!
//! Both APIs call these use cases, so a rule lives in one place. Adapters implement the ports:
//! `kemlock-store-sql` the repositories, `kemlock-crypto` (through `kemlock-server`'s wiring) the
//! password, token and sealing ports. Every port has an in-memory fake in `tests/`, so a use case
//! is tested without a database.
//!
//! A use case is a struct of ports with an `execute` method (some, like `sign_in`, have one per
//! step). Its fields are public and it has no constructor, so the server and tests build it with
//! a struct literal.

pub mod account_keys;
pub mod admin;
pub mod api_use;
pub mod authenticate;
pub mod b64url;
pub mod bitwarden;
pub mod bw_events;
pub mod config;
pub mod confirm_totp;
pub mod dedup;
pub mod devices;
pub mod emergency;
pub mod enrol_keys;
pub mod enrol_totp;
pub mod error;
pub mod event_reader;
pub mod federation_view;
pub mod files;
pub mod finish_setup;
pub mod first_admin;
pub mod first_run;
pub mod manifests;
pub mod notices;
pub mod passkeys;
pub mod placement;
pub mod platform;
pub mod policies;
pub mod ports;
pub mod prelogin;
pub mod privacy;
pub mod push;
pub mod put_batch;
pub mod put_item;
pub mod quota;
pub mod recovery_kit;
pub mod refresh;
pub mod register;
pub mod reset_admin;
pub mod sealed;
pub mod sends;
pub mod session;
pub mod setup_basics;
pub mod sign_in;
pub mod spaces;
pub mod sso;
pub mod sync_delta;
pub mod two_step;

pub use authenticate::{Actor, Authenticate};
pub use config::AuthConfig;
pub use confirm_totp::ConfirmTotp;
pub use enrol_totp::{EnrolTotp, TotpEnrolment};
pub use error::AppError;
pub use finish_setup::FinishSetup;
pub use first_admin::FirstAdminRepo;
pub use first_run::{FirstRun, SetupCode, SetupGrant, SetupPhase, SetupState};
pub use placement::{Placement, ReadPlacement};
pub use platform::{Hasher, Platform};
pub use prelogin::Prelogin;
pub use put_batch::PutBatch;
pub use put_item::PutItem;
pub use refresh::Refresh;
pub use register::{Register, RegisterInput, RegisterStartInput, Registered};
pub use session::{Continued, DeviceInfo, Sessions, TokenPair};
pub use setup_basics::{JoinPolicy, ServerBasics, save_basics, without_env_set};
pub use sign_in::{OpaqueFinishInput, OpaqueStartInput, OpaqueStarted, SignIn, SignedIn};
pub use sign_in::{SecondStep, SecondStepInput};
pub use sync_delta::{SyncDelta, SyncOutcome, SyncPage};
