//! Bitwarden's live notifications, as Vaultwarden serves them (1.37.5, `src/api/notifications.rs`
//! and `push.rs`).
//!
//! - [`message`]: the SignalR messages Bitwarden apps expect on `/notifications/hub`, in
//!   MessagePack (what the apps speak) and JSON, with the framing of each.
//! - [`hub`]: the WebSocket routes and the hub that fans a change out to an account's sockets.
//! - [`relay`]: Bitwarden's own push relay, with `PUSH_INSTALLATION_ID` and `PUSH_INSTALLATION_KEY`
//!   as Vaultwarden uses it, so Bitwarden's phone apps wake when the vault changes.
//!
//! None of this is Kemlock's own protocol: Kemlock apps use `/kem/v1/live` and Kemlock's relay.

pub mod events;
pub mod hub;
pub mod message;
pub mod relay;

pub use events::{BwNotifier, BwPushing};
pub use hub::{BwHub, HubAuth, HubConfig, HubIdentity, router};
pub use message::{Field, Message, Protocol, UpdateType};
pub use relay::{BitwardenPush, BitwardenPushConfig, BwPush, BwPushDevice, BwPushSwitch};
