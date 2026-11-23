//! The Bitwarden API: `/identity`, `/api` and the attachment download link, answering as
//! Vaultwarden 1.37.5 does, quirks included, so Bitwarden apps, the Kemlock app and Amethystora
//! Vault keep syncing with a server that is no longer Vaultwarden.
//!
//! The router is generic over one store, which implements the repository ports of `kemlock-app`
//! (users, devices, refresh tokens, two-step enrolments, items and [`BwAccountRepo`]), so tests
//! run it in-process with `tower::ServiceExt::oneshot`. Ciphers are `bw` items in the shared
//! items table, holding Vaultwarden's cipher JSON; folders are `bw-folder` items; every write
//! goes through the change log and moves the account's revision date.
//!
//! Organizations are spaces (module `orgs`): members, groups, collections and grants live in the space
//! tables, and what Bitwarden adds (the organization key pair, members' wrapped keys, policies, the
//! links between ciphers and collections) in side documents; organization ciphers are `bw` items
//! owned by the space, still encrypted under the organization key. Emergency access, Sends, events
//! and equivalent domains have their own modules.
//!
//! Not served: `/notifications/hub`. Account recovery (`orgs::recovery`) works without a mailer: the
//! server keeps and hands on what the clients encrypt. The public API serves the
//! Directory Connector's organization import, with the organization API key it signs in with.
//!
//! Every write tells the live channels through [`BwLive`] (module `live`), as Vaultwarden's
//! `nt.send_*` calls do.
//!
//! [`BwAccountRepo`]: kemlock_app::bitwarden::BwAccountRepo

// Vaultwarden's organization JSON is one large json! literal each, past the default 128.
#![recursion_limit = "256"]

mod account;
mod app;
mod attachments;
mod authenticator;
pub mod blob;
mod cipher;
mod dates;
mod device_push;
mod domains;
mod emergency;
pub mod env;
pub mod error;
mod events;
#[cfg(feature = "fuzzing")]
pub mod fuzzing;
mod identity;
pub mod imported;
mod ip_limit;
mod live;
mod orgs;
pub mod password;
mod pem;
mod protected;
mod public;
mod routes;
mod send_limit;
pub mod sends;
pub mod settings;
pub mod tokens;
mod two_step;
mod vault;
mod webauthn;

pub use app::{App, AppParts, Authed, BwStore};
pub use blob::{BlobError, BlobStore, BoxFuture, MemoryBlobStore};
pub use env::{Env, SystemEnv};
pub use error::{BwError, BwResult};
pub use live::BwLive;
pub use orgs::OrgMembership;
pub use routes::{CLAIMED_SERVER_VERSION, router};
pub use sends::{MemorySends, SendStore};
pub use settings::{BwSettings, ENV_VARS};
pub use tokens::{KeyError, TokenKeys};
pub use two_step::TwoStepParts;

use axum::Router;
use kemlock_app::admin::Live;
use kemlock_app::passkeys::WebAuthn;
use kemlock_crypto::seal::ServerSeal;
use std::path::Path;
use std::sync::Arc;

/// The Bitwarden router for a server: reads `KEMLOCK_BITWARDEN_COMPAT`, then (when it isn't off)
/// reads or makes `rsa_key.pem` in `data_folder`, keeps attachments in `blobs` (the server gives it
/// the one store every file uses) and seals nothing it can't open with `server_key`. With the switch
/// off the router has no routes, so every Bitwarden path is a 404. The error is the text of why the
/// key couldn't be used.
pub fn mount<S: BwStore>(
    store: S,
    server_key: &[u8; 32],
    domain: &str,
    data_folder: &Path,
    blobs: Arc<dyn BlobStore>,
    signups_allowed: bool,
) -> Result<Router, String> {
    mount_with_webauthn(
        store,
        server_key,
        domain,
        data_folder,
        blobs,
        signups_allowed,
        None,
    )
}

/// [`mount`] with a WebAuthn relying party, so accounts can have security keys as a second step
/// (provider 7) through `/api/two-factor/get-webauthn`, `get-webauthn-challenge` and `webauthn`,
/// and the token endpoint offers them. Without one those routes refuse.
pub fn mount_with_webauthn<S: BwStore>(
    store: S,
    server_key: &[u8; 32],
    domain: &str,
    data_folder: &Path,
    blobs: Arc<dyn BlobStore>,
    signups_allowed: bool,
    webauthn: Option<Arc<dyn WebAuthn>>,
) -> Result<Router, String> {
    mount_full(
        store,
        server_key,
        domain,
        data_folder,
        blobs,
        signups_allowed,
        webauthn,
        TwoStepParts::default(),
    )
}

/// [`mount_with_webauthn`] with the second steps beyond an authenticator app and a security key:
/// emailed codes (provider 1), Duo (2) and YubiKeys (3), with their settings and services. They
/// are served at `/api/two-factor/...` and at the token endpoint when `two_step` offers them.
#[allow(clippy::too_many_arguments)]
pub fn mount_full<S: BwStore>(
    store: S,
    server_key: &[u8; 32],
    domain: &str,
    data_folder: &Path,
    blobs: Arc<dyn BlobStore>,
    signups_allowed: bool,
    webauthn: Option<Arc<dyn WebAuthn>>,
    two_step: TwoStepParts,
) -> Result<Router, String> {
    let settings = BwSettings::new(domain, signups_allowed).compat_from_env();
    mount_settings(
        settings,
        store,
        server_key,
        data_folder,
        blobs,
        webauthn,
        two_step,
        BwLive::default(),
        None,
    )
}

/// [`mount_full`] with sign-ups and server invitations following `live`, the settings the
/// console changes while the server runs, instead of a value fixed at start; with the live
/// channels the API tells of every change (the hub, Bitwarden's push relay and a nudge for the
/// owner's Kemlock devices, see [`BwLive`]); and with where Sends are kept (`None` keeps them in
/// memory, so they are lost on a restart).
#[allow(clippy::too_many_arguments)]
pub fn mount_live<S: BwStore>(
    store: S,
    server_key: &[u8; 32],
    domain: &str,
    data_folder: &Path,
    blobs: Arc<dyn BlobStore>,
    live: Live,
    webauthn: Option<Arc<dyn WebAuthn>>,
    two_step: TwoStepParts,
    channels: BwLive,
    sends: Option<Arc<dyn SendStore>>,
    env: &dyn Fn(&str) -> Option<String>,
) -> Result<Router, String> {
    let settings = BwSettings::new(domain, live.signups_allowed())
        .env_from(env)
        .with_live(live);
    mount_settings(
        settings,
        store,
        server_key,
        data_folder,
        blobs,
        webauthn,
        two_step,
        channels,
        sends,
    )
}

#[allow(clippy::too_many_arguments)]
fn mount_settings<S: BwStore>(
    settings: BwSettings,
    store: S,
    server_key: &[u8; 32],
    data_folder: &Path,
    blobs: Arc<dyn BlobStore>,
    webauthn: Option<Arc<dyn WebAuthn>>,
    two_step: TwoStepParts,
    live: BwLive,
    sends: Option<Arc<dyn SendStore>>,
) -> Result<Router, String> {
    if !settings.compat {
        tracing::info!("the Bitwarden API is off (KEMLOCK_BITWARDEN_COMPAT)");
        return Ok(Router::new());
    }
    let keys = TokenKeys::load_or_create(data_folder).map_err(|e| e.to_string())?;
    let app = App::new(AppParts {
        store,
        env: Arc::new(SystemEnv),
        keys,
        seal: ServerSeal::new(server_key),
        blobs,
        two_step,
        settings,
        webauthn,
        sends,
        live,
    });
    Ok(router(app))
}
