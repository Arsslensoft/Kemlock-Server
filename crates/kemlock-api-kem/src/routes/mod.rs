//! The handlers, as associated functions of [`Api`](crate::Api) so each impl block states the
//! port bounds once. `router::router` wires them to paths.

pub(crate) mod account;
pub(crate) mod api_key;
pub(crate) mod attempts;
mod auth;
pub(crate) mod connector;
pub(crate) mod contract;
mod contract_crypto;
pub(crate) mod custom_fields;
pub(crate) mod devices;
pub(crate) mod duplicates;
pub(crate) mod emergency;
pub(crate) mod failover;
pub(crate) mod files;
pub(crate) mod items;
pub(crate) mod manifests;
pub(crate) mod new_device;
pub(crate) mod passkeys;
pub(crate) mod placement;
pub(crate) mod policies;
pub(crate) mod profile;
pub(crate) mod push;
pub(crate) mod reauth;
pub(crate) mod recovery_kit;
pub(crate) mod rotation;
pub(crate) mod sends;
mod server;
mod signup_verify;
pub(crate) mod space_chain;
pub(crate) mod space_recovery;
pub(crate) mod spaces;
pub(crate) mod sso;
pub(crate) mod two_step;
pub(crate) mod view;

use crate::problem::{Problem, rate_limited};
use crate::ratelimit::Limiter;

/// Counts one try against `limiter`; a 429 with `Retry-After` when it's over.
pub(crate) fn guard(limiter: &Limiter, key: &str, now: i64) -> Result<(), Problem> {
    limiter.check(key, now).map_err(rate_limited)
}
