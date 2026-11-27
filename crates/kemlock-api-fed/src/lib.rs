//! The federation API of Kemlock Server, `/fed/v1`.
//!
//! One router, [`router`], serves the signed descriptor at `GET /fed/v1/descriptor` and at
//! `GET /.well-known/kemlock-federation`, and the peer session at `GET /fed/v1/session`, a
//! WebSocket that carries the handshake and then sealed frames (`docs/federation.md`). Only a
//! paired peer gets past the first message. [`serve_session`] runs a session over any [`Duplex`],
//! which is how the tests drive it without a network.
//!
//! [`pair_router`] serves the two public pairing routes (`/fed/v1/pair/start` and `/finish`), where
//! the code is the authentication. [`admin_router`] serves `/admin/v1/federation` (pairing with a
//! one-time code and a fingerprint, the peer list, the two log switches, revoking a peer, each
//! vault's policy and consent, promotion) behind an [`AdminGate`] the server provides. The replication
//! job that opens sessions to peers is in `kemlock-federation`.

pub mod admin;
pub mod homegate;
pub mod identity;
pub mod pair;
pub mod routes;
pub mod session;
pub mod state;

pub use admin::{
    AdminActor, AdminGate, AdminState, ApiError, GateRefusal, admin_openapi, admin_router,
};
pub use homegate::{HOME_HEADER, HomeGate, HomeTarget, home_gate, home_only_target};
pub use identity::{
    FileRotator, IdentityError, IdentityParams, REFRESH_AFTER_SECS, default_suites, load_or_create,
    refresh_due, rotate_identity,
};
pub use pair::{PAIRING_MEDIA_TYPE, pair_router};
pub use routes::{DESCRIPTOR_MEDIA_TYPE, router};
pub use session::{Duplex, SessionEnd, serve, serve_session};
pub use state::{FedEvent, FedState};
