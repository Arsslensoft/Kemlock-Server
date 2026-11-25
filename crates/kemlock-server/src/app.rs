//! The composition root: reads the keys, connects the store, wires the API over it, and serves.

use crate::adapters::ServerCrypto;
use crate::client_addr;
use crate::config::Config;
use crate::federation::{self, ApiGate, Replication};
use crate::files::{self, Files};
use crate::health::{self, HealthState};
use crate::jobs;
use crate::keys::{self, KeyError};
use crate::live::{self, Layered, SettingsWatch, SwitchMailer};
use crate::migration::VaultwardenMove;
use crate::notify;
use crate::passkeys;
use crate::sends::{self, SendJobs};
use crate::source;
use crate::sso;
use crate::two_step;
use axum::Router;
use axum::http::StatusCode;
use kemlock_api_bw::SendStore;
use kemlock_api_fed::AdminGate;
use kemlock_api_kem::{Api, ApiConfig, ApiSecrets, JwsTokenSigner};
use kemlock_app::AuthConfig;
use kemlock_app::admin::AcceptInvite;
use kemlock_app::passkeys::WebAuthn;
use kemlock_app::ports::Zeroizing;
use kemlock_crypto::hash;
use kemlock_crypto::seal::ServerSeal;
use kemlock_federation::{Connector, PairingLink, Replica};
use kemlock_store_sql::SqlStore;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tower_http::timeout::TimeoutLayer;
use tower_http::trace::TraceLayer;

/// How long a request may take before it is answered 408. WebSockets are upgraded long before.
const REQUEST_TIMEOUT: Duration = Duration::from_secs(30);

#[derive(Debug, thiserror::Error)]
pub enum RunError {
    #[error(transparent)]
    Keys(#[from] KeyError),
    #[error("can't use the data folder {path}: {source}")]
    DataFolder {
        path: String,
        #[source]
        source: std::io::Error,
    },
    #[error("can't open the database: {0}")]
    Store(String),
    #[error("{0}")]
    Config(String),
    #[error("can't listen on {address}: {source}")]
    Listen {
        address: String,
        #[source]
        source: std::io::Error,
    },
    #[error("the FIPS check failed: {0}")]
    Fips(String),
    #[error("the server stopped: {0}")]
    Serve(std::io::Error),
}

/// Everything wired, before it listens.
pub struct Built {
    pub api: Api<SqlStore, ServerCrypto, JwsTokenSigner>,
    pub store: SqlStore,
    /// The API, `/alive` and `/health`, with request tracing and timeouts.
    pub router: Router,
    /// What the attachment job needs; `run` starts it.
    pub files: Files,
    /// What the job that deletes due Sends needs; `run` starts it.
    pub send_jobs: SendJobs,
    /// The federation engine over the store.
    pub replica: Arc<Replica<SqlStore>>,
    /// The replication job and the other background work of federation; `run` starts it.
    pub replication: Arc<dyn Replication>,
    /// The saved settings, watched; `run` starts the polling and the applying.
    pub settings: Arc<SettingsWatch>,
    /// The mail sender the settings switch to another SMTP server.
    pub mailer: SwitchMailer,
    /// Makes the push relays follow the saved settings.
    pub push: crate::notify::PushFollower,
    /// What starts the move from Vaultwarden in the background; `run` recovers an orphaned one.
    pub migration: VaultwardenMove,
}

impl std::fmt::Debug for Built {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Built").finish_non_exhaustive()
    }
}

/// Secrets for the API, derived from `server.key` so one file backs them all.
fn derive_secrets(server_key: &[u8; 32]) -> ApiSecrets {
    ApiSecrets {
        prelogin: hash::hmac_sha256(server_key, b"kemlock/v1/prelogin-secret"),
        dpop_nonce: hash::hmac_sha256(server_key, b"kemlock/v1/dpop-nonce-key"),
    }
}

/// What a failed FIPS check of the crypto module costs: the server logs why and does not start.
/// A FIPS build that served requests from a library not in FIPS mode would be the silent fallback
/// the build exists to prevent.
#[cfg(any(feature = "fips", test))]
fn refuse_unless_fips<E: std::fmt::Display>(check: Result<(), E>) -> Result<(), RunError> {
    check.map_err(|e| {
        let why = format!(
            "the linked aws-lc-rs is not the AWS-LC FIPS module in FIPS mode, or its self-test \
             failed ({e})"
        );
        tracing::error!(error = %why, "refusing to start: the FIPS module check failed");
        RunError::Fips(why)
    })
}

/// Reads or makes the keys, connects the store (which migrates it) and wires the API, with the
/// network client federation reaches its peers with.
pub async fn build(config: &Config) -> Result<Built, RunError> {
    build_with(config, federation::production).await
}

/// [`build`] with the connector and the pairing link federation uses to reach its peers chosen by
/// the caller: the gate test runs three servers in one process over channels.
pub async fn build_with<C, F>(config: &Config, make: F) -> Result<Built, RunError>
where
    C: Connector + 'static,
    F: FnOnce(&Arc<Replica<SqlStore>>) -> Result<(C, Arc<dyn PairingLink>), RunError>,
{
    // A FIPS build serves nothing until the module says it is in FIPS mode.
    #[cfg(feature = "fips")]
    refuse_unless_fips(kemlock_crypto::fips::verify())?;
    std::fs::create_dir_all(&config.data_folder).map_err(|source| RunError::DataFolder {
        path: config.data_folder.display().to_string(),
        source,
    })?;
    // Wiped when `build` returns: the seal keeps its own copy, which it wipes on drop.
    let server_key = Zeroizing::new(keys::load_or_create_server_key(
        &config.data_folder,
        config.server_key.as_deref(),
    )?);
    let seal = ServerSeal::new(&server_key);
    let opaque = keys::load_opaque_server(&config.data_folder, &seal)?;
    let signing_key = keys::load_signing_key(&config.data_folder, &seal)?;

    // On PostgreSQL and MySQL a backup archive goes first when backups are set up; SQLite is
    // copied by the store itself.
    crate::backups::before_migration(config)
        .await
        .map_err(RunError::Config)?;
    let store = SqlStore::connect(&config.database_url)
        .await
        .map_err(|e| RunError::Store(e.to_string()))?;
    let crypto = ServerCrypto::new(seal, opaque);
    // SSO settings from `SSO_*` fill an empty table; a bad value turns SSO off and says why.
    match sso::seed_from_env(&store, &crypto, &|name| std::env::var(name).ok()).await {
        Ok(true) => tracing::info!("single sign-on is set up from the SSO_* settings"),
        Ok(false) => {}
        Err(e) => tracing::warn!(error = %e, "single sign-on isn't set up from the SSO_* settings"),
    }

    // Mail, live sync between replicas, the push relay and Bitwarden's hub (`SMTP_*`, `KEMLOCK_PUSH_*`).
    let notifications =
        notify::start(config, &|name| std::env::var(name).ok(), &store, &crypto).await?;
    // Emailed codes, YubiKeys and Duo: Vaultwarden's settings, from the environment and config.json.
    let two_step = two_step::wire(
        config,
        &|name| std::env::var(name).ok(),
        notifications.notices.clone(),
    )?;
    // AGPL-3.0 section 13: where the source of this exact build is offered, on `/kem/v1/config`.
    let commit = source::build_commit();
    let api_config = ApiConfig {
        domain: config.domain.clone(),
        version: env!("CARGO_PKG_VERSION").to_owned(),
        source_url: source::source_url(config.source_url.as_deref(), commit.as_deref()),
        commit,
        auth: AuthConfig {
            signups_allowed: config.signups_allowed,
            ..AuthConfig::default()
        },
        trusted_proxies: config.trusted_proxies.clone(),
        ip_header: config.ip_header.clone(),
        browser_extension_ids: config.browser_extension_ids.clone(),
    };
    let api = Api::new(
        store.clone(),
        crypto.clone(),
        JwsTokenSigner::new(signing_key),
        notifications.hub.clone(),
        api_config,
        derive_secrets(&server_key),
    )
    .map_err(|e| RunError::Config(format!("DOMAIN: {e}")))?;

    // What the console saves takes effect: the environment, then the config file, then the saved
    // settings, read now and again when they change (`run` starts the watching).
    let file_settings =
        live::read_file_settings(config.config_file.as_deref()).map_err(RunError::Config)?;
    let layered = Layered::from_config(config, file_settings);
    let settings = SettingsWatch::start(store.clone(), api.crypto.clone(), layered.clone())
        .await
        .map_err(RunError::Store)?;
    live::apply(
        &settings.current(),
        &api.live,
        &api.limits,
        &notifications.mailer,
    );
    notifications.push_follower.follow(&settings.current());
    settings.overlay_retention(&store);
    // An invited address registers with its token while sign-ups are closed.
    api.live.set_invites(Arc::new(AcceptInvite {
        repo: store.clone(),
        env: api.crypto.clone(),
    }));

    let (blobs, blob_settings) = files::open_blobs(&config.data_folder)?;
    // The move puts attachments and Send files in the file storage the Bitwarden API reads.
    let migration = VaultwardenMove::new(
        store.clone(),
        api.crypto.clone(),
        &server_key,
        config.data_folder.clone(),
        Arc::new(files::BitwardenBlobs::new(blobs.clone())),
    );

    let (sends_router, spaces_router, send_jobs) = sends::wire(&config.data_folder, &api, &store)?;
    let sso_runtime =
        sso::runtime(store.clone()).map_err(|e| RunError::Config(format!("SSO: {e}")))?;
    let relying_party = passkeys::relying_party(&config.domain)
        .map_err(|e| RunError::Config(format!("DOMAIN (WebAuthn): {e}")))?;
    let erasure_files =
        crate::privacy::server_files(&config.data_folder).map_err(RunError::Config)?;
    let admin_erasure = kemlock_app::privacy::EraseAccount {
        users: store.clone(),
        eraser: store.clone(),
        sends: erasure_files.send_eraser(&store),
        files: erasure_files.clone(),
        settings: store.clone(),
        log: store.clone(),
        env: api.crypto.clone(),
    };
    let account_routes = kemlock_api_kem::account_router(
        api.clone(),
        store.clone(),
        erasure_files.send_eraser(&store),
        erasure_files,
    );
    let gate: Arc<dyn AdminGate> = Arc::new(ApiGate::new(api.clone()));
    let federated = federation::wire(
        config,
        &server_key,
        &store,
        federation::files_of(blobs.clone()),
        gate,
        make,
    )?;
    let (files_router, files) =
        files::wire(&api, &store, blobs, &blob_settings, federated.fetcher())?;
    let router = Router::new()
        .merge(health::router(HealthState {
            store: store.clone(),
            data_folder: config.data_folder.clone(),
        }))
        // /LICENSE.txt, /NOTICE.txt and /THIRD-PARTY-NOTICES.txt, ahead of the web vault.
        .merge(source::router(source::third_party_paths()))
        .merge(kemlock_api_kem::router(api.clone(), store.clone()))
        .merge(kemlock_api_kem::push_router(api.clone(), store.clone()))
        .merge(notifications.bitwarden)
        .merge(
            kemlock_api_bw::mount_live(
                store.clone(),
                &server_key,
                &config.domain,
                &config.data_folder,
                files.bitwarden_blobs(),
                api.live.clone(),
                Some(relying_party.clone() as Arc<dyn WebAuthn>),
                two_step.bitwarden(),
                notifications.bw_live.clone(),
                // Bitwarden Sends live in the database, not in memory.
                Some(Arc::new(crate::bw_sends::SqlSends::new(store.clone())) as Arc<dyn SendStore>),
                // Read through the server's own lookup, as the settings are (see Config).
                &|name| config.bitwarden_env.get(name).cloned(),
            )
            .map_err(RunError::Config)?,
        );
    // The web vault takes the GET addresses the API and the health routes don't.
    #[cfg(feature = "web")]
    let router = router.merge(crate::web::router());
    let router = router
        .merge(kemlock_api_kem::duplicates_router(
            api.clone(),
            store.clone(),
            store.clone(),
        ))
        .merge(spaces_router)
        .merge(kemlock_api_kem::space_chain_router(
            api.clone(),
            store.clone(),
        ))
        .merge(kemlock_api_kem::space_recovery_router(
            api.clone(),
            store.clone(),
        ))
        .merge(kemlock_api_kem::sso_router(api.clone(), sso_runtime))
        .merge(kemlock_api_kem::passkeys_router(
            api.clone(),
            passkeys::runtime(store.clone(), relying_party.clone()),
        ))
        .merge(kemlock_api_kem::two_step_router(
            api.clone(),
            two_step.runtime(store.clone()),
        ))
        .merge(kemlock_api_kem::recovery_kit_router(
            api.clone(),
            store.clone(),
        ))
        .merge(account_routes)
        // /.well-known/security.txt, from the admin settings.
        .merge(crate::security_txt::router(
            kemlock_app::admin::Settings {
                repo: store.clone(),
                seal: crypto,
                env: kemlock_app::admin::FnEnv(|name: &str| std::env::var(name).ok()),
            },
            &config.domain,
        ))
        .merge(kemlock_api_admin::admin_router(
            api.clone(),
            kemlock_api_admin::AdminRuntime::new(
                store.clone(),
                store.clone(),
                store.clone(),
                std::sync::Arc::new(kemlock_identity::DnsTxtResolver::new()),
                notifications.admin_mail.clone(),
                layered,
            )
            .with_passkeys(passkeys::step_up(
                store.clone(),
                relying_party,
                api.crypto.clone(),
            ))
            .with_migration(Arc::new(migration.clone()))
            // "Delete user" takes the whole erasure: Sends, files, the sign-in log, federated peers.
            .with_account_erasure(Arc::new(admin_erasure))
            .on_settings_saved({
                let settings = settings.clone();
                move || settings.nudge()
            })
            .with_push_relay(notifications.push_relay.clone())
            .with_data_folder(config.data_folder.display().to_string()),
        ))
        .merge(federated.router)
        // Members, roles, policies and keys of a federated space are written at its home only.
        .layer(axum::middleware::from_fn_with_state(
            federated.home_gate.clone(),
            kemlock_api_fed::home_gate::<SqlStore>,
        ))
        // What the Kemlock API reads of federation: a vault's servers, siblings, copied accounts.
        .layer(axum::Extension(federated.view))
        .layer(TimeoutLayer::with_status_code(
            StatusCode::REQUEST_TIMEOUT,
            REQUEST_TIMEOUT,
        ))
        // After the timeout above: the file routes have a longer one of their own.
        .merge(files_router)
        .merge(sends_router)
        .layer(TraceLayer::new_for_http())
        // Outermost, so every route (both APIs, the admin console, federation) has its client
        // address settled and every event a request writes carries it.
        .layer(axum::middleware::from_fn_with_state(
            client_addr::ClientAddrSettings::from_config(config),
            client_addr::settle_client_address,
        ));
    Ok(Built {
        api,
        store,
        router,
        files,
        send_jobs,
        replica: federated.replica,
        replication: federated.replication,
        settings,
        mailer: notifications.mailer,
        push: notifications.push_follower,
        migration,
    })
}

/// Resolves when the process is asked to stop: Ctrl-C, or SIGTERM on Unix (what `docker stop`
/// sends).
async fn shutdown_signal() {
    let ctrl_c = async {
        if tokio::signal::ctrl_c().await.is_err() {
            // No signal handler: never resolve on this branch.
            std::future::pending::<()>().await;
        }
    };
    #[cfg(unix)]
    let terminate = async {
        match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
            Ok(mut signal) => {
                signal.recv().await;
            }
            Err(_) => std::future::pending::<()>().await,
        }
    };
    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();
    tokio::select! {
        () = ctrl_c => {}
        () = terminate => {}
    }
    tracing::info!("shutting down");
}

/// Binds the address, preferring dual-stack `::` and falling back to IPv4 on a host without IPv6.
async fn bind(config: &Config) -> Result<tokio::net::TcpListener, RunError> {
    let attempt = |address: &str| tokio::net::TcpListener::bind((address.to_owned(), config.port));
    match attempt(&config.address).await {
        Ok(listener) => Ok(listener),
        Err(e) if config.address == "::" => {
            tracing::warn!(error = %e, "can't listen on [::]; trying 0.0.0.0");
            attempt("0.0.0.0").await.map_err(|source| RunError::Listen {
                address: format!("0.0.0.0:{}", config.port),
                source,
            })
        }
        Err(source) => Err(RunError::Listen {
            address: format!("{}:{}", config.address, config.port),
            source,
        }),
    }
}

/// Runs the server until it is asked to stop.
pub async fn run(config: Config) -> Result<(), RunError> {
    if !config.ignored.is_empty() {
        tracing::warn!(
            settings = %config.ignored.join(", "),
            "ignoring Vaultwarden settings that Kemlock Server doesn't use"
        );
    }
    let Built {
        api,
        store,
        router,
        files,
        send_jobs,
        replication,
        settings,
        mailer,
        push,
        migration,
        ..
    } = build(&config).await?;
    send_jobs.spawn_purge();
    // A move that was running when the server last stopped can't finish: say so, so it can be
    // started again.
    match migration.recover().await {
        Ok(true) => tracing::warn!("a move from Vaultwarden was interrupted by the last stop"),
        Ok(false) => {}
        Err(e) => tracing::warn!(error = %e, "couldn't check for an interrupted Vaultwarden move"),
    }
    // Peers are visited, nudged and pulled from, and the descriptor refreshed, in the background.
    let replication_tasks = replication.spawn();
    // Settings saved in the console, here or on another replica, reach the running server.
    let settings_apply = settings.spawn_apply({
        let api = api.clone();
        move |snapshot| {
            live::apply(snapshot, &api.live, &api.limits, &mailer);
            push.follow(snapshot);
        }
    });
    let settings_poll = settings.spawn_poll();
    let listener = bind(&config).await?;
    let local = listener
        .local_addr()
        .map_or_else(|_| config.address.clone(), |a| a.to_string());
    tracing::info!(address = %local, domain = %config.domain, "kemlock-server {} listening", env!("CARGO_PKG_VERSION"));

    // With no admin yet, the setup code is the one thing an operator needs from this log, so it
    // is logged as a warning: it shows at any level but `error`.
    match api.start_setup().await {
        Ok(Some(code)) => tracing::warn!(
            "first run: no admin exists. Open {} and enter the setup code {} (it is valid until \
             this server restarts; a restart makes a new one)",
            config.domain,
            code.as_display()
        ),
        Ok(None) => {}
        Err(e) => tracing::error!(error = %e, "couldn't start setup"),
    }

    // The background jobs (old tombstones, emergency-access timer, expired device approvals,
    // orphaned files) each run on one replica at a time, under a lease.
    let background = jobs::spawn_all(&store, &api.crypto, files);
    // Retention, backups and accounts whose deletion grace period ended.
    let retention = crate::privacy::spawn_retention(
        store.clone(),
        api.crypto.clone(),
        crate::privacy::server_files(&config.data_folder).map_err(RunError::Config)?,
    );
    // A bad backup setting in the environment stops the start; the schedule itself follows the
    // saved settings from here on.
    crate::backups::settings(&config).map_err(RunError::Config)?;
    let layout = crate::backups::layout(&config).map_err(RunError::Config)?;
    let backups = crate::backups::spawn_backups(store.clone(), settings.clone(), layout);
    let served = axum::serve(
        listener,
        router.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .with_graceful_shutdown(shutdown_signal())
    .await;
    background.abort();
    retention.abort();
    settings_poll.abort();
    settings_apply.abort();
    backups.abort();
    for task in replication_tasks {
        task.abort();
    }
    // Let SQLite checkpoint its write-ahead log before the process ends.
    if let Err(e) = store.close().await {
        tracing::warn!(error = %e, "couldn't close the database cleanly");
    }
    served.map_err(RunError::Serve)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_failed_fips_check_stops_the_server_and_says_why() {
        assert!(refuse_unless_fips::<&str>(Ok(())).is_ok());
        let refused = refuse_unless_fips(Err("invalid")).expect_err("refused");
        assert!(matches!(&refused, RunError::Fips(why) if why.contains("FIPS module")));
        assert!(refused.to_string().starts_with("the FIPS check failed"));
    }

    #[cfg(feature = "fips")]
    #[test]
    fn a_fips_build_passes_its_own_check() {
        refuse_unless_fips(kemlock_crypto::fips::verify()).expect("the module is in FIPS mode");
    }
}
