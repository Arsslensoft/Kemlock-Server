//! Kemlock Server: configuration, wiring and the HTTP server.
//!
//! `config` reads the environment and a TOML file; `keys` makes `server.key` and the secrets
//! sealed under it; `adapters` implements the crypto and platform ports over `kemlock-crypto`;
//! `health` serves `/alive` and `/health`; `source` says where the source and the licence texts
//! are; `app` wires the store and the API together and serves until it is asked to stop.
//! `kemlock-cli` reuses `config` and the store.

pub mod adapters;
pub mod app;
pub mod backups;
pub mod bw_sends;
pub mod client_addr;
pub mod config;
pub mod federation;
pub mod files;
pub mod health;
pub mod healthcheck;
pub mod jobs;
pub mod keys;
pub mod listener;
pub mod live;
pub mod logging;
pub mod migration;
pub mod notify;
pub mod passkeys;
pub mod privacy;
pub mod restore;
pub mod security_txt;
pub mod sends;
pub mod source;
pub mod sso;
pub mod two_step;
#[cfg(feature = "web")]
pub mod web;

pub use app::{Built, RunError, build, run};
pub use config::{Config, ConfigError};
