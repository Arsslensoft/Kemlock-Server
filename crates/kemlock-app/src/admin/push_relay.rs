//! Kemlock's push relay, as the admin console turns it on and off and shows it.
//!
//! The relay is a hosted service that wakes the mobile apps (`docs/push-relay.md`). Turning it on
//! registers this server with the relay and keeps the installation (the key sealed under
//! `server.key`); turning it off asks the relay to erase the installation and forgets it here.
//! The server holds the means (`kemlock-notify`'s `enable_relay` and `disable_relay`); this is the
//! port the console's routes call.

use super::error::AdminError;
use crate::notices::BoxFuture;

/// Where the relay stands.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RelayStatus {
    /// Whether this server has registered with the relay, so pushes go out.
    pub enabled: bool,
    /// The relay's id for this server. Not a secret: the key it holds is never shown.
    pub installation_id: Option<String>,
    /// The relay the server talks to (`KEMLOCK_PUSH_RELAY_URL`, or Kemlock's).
    pub relay_url: String,
}

/// Turns the relay on and off and says where it stands. The errors are the console's: a relay that
/// can't be reached is `State`, a store failure `App`.
pub trait PushRelayControl: Send + Sync + 'static {
    fn status(&self) -> BoxFuture<'_, Result<RelayStatus, AdminError>>;

    /// Registers with the relay. A server that is registered already stays as it is.
    fn enable(&self) -> BoxFuture<'_, Result<RelayStatus, AdminError>>;

    /// Forgets the installation here, and at the relay when it can be reached. A server that is
    /// not registered stays as it is.
    fn disable(&self) -> BoxFuture<'_, Result<RelayStatus, AdminError>>;
}
