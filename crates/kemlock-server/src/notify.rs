//! Wires `kemlock-notify` into the server: mail for the notices the API raises, the live hub
//! and its fan-out between replicas, Kemlock's push relay, Bitwarden's `/notifications/hub` and
//! the events the Bitwarden API publishes to it, with Bitwarden's own push relay (`PUSH_*`).
//!
//! Settings are Vaultwarden's where they exist: `SMTP_HOST`, `SMTP_FROM`, `SMTP_FROM_NAME`,
//! `SMTP_PORT`, `SMTP_SECURITY`, `SMTP_USERNAME`, `SMTP_PASSWORD`, `SMTP_TIMEOUT`,
//! `SMTP_ACCEPT_INVALID_CERTS` and `SMTP_ACCEPT_INVALID_HOSTNAMES`; `PUSH_ENABLED`,
//! `PUSH_INSTALLATION_ID`, `PUSH_INSTALLATION_KEY`, `PUSH_RELAY_URI`, `PUSH_IDENTITY_URI` and
//! `REQUIRE_DEVICE_EMAIL`.
//! Kemlock's own: `KEMLOCK_PUSH_RELAY`
//! (`true` registers this server with the relay at start when it hasn't yet) and
//! `KEMLOCK_PUSH_RELAY_URL` (another relay than Kemlock's).

use crate::adapters::ServerCrypto;
use crate::app::RunError;
use crate::config::Config;
use crate::live::SwitchMailer;
use axum::Router;
use kemlock_api_bw::BwLive;
use kemlock_api_bw::BwSettings;
use kemlock_api_bw::tokens::{LoginClaims, TokenKeys};
use kemlock_api_kem::LiveHub;
use kemlock_app::admin::PushRelayControl;
use kemlock_app::bw_events::BwRelay;
use kemlock_app::notices::{BoxFuture, Notices};
use kemlock_app::ports::{DeviceRepo, UserRepo};
use kemlock_domain::{DeviceId, Owner, UserId};
use kemlock_notify::Notify;
use kemlock_notify::audience::{Audience, SpaceMembers};
use kemlock_notify::bitwarden::{
    BitwardenPush, BitwardenPushConfig, BwHub, BwNotifier, BwPushing, HubAuth, HubConfig,
    HubIdentity,
};
use kemlock_notify::fanout::{Fanout, FanoutOptions, Sink};
use kemlock_notify::mail::{
    AdminMail, Branding, LogMailer, MailOutbox, Mailer, SmtpConfig, SmtpMailer,
};
use kemlock_notify::push::{
    DEFAULT_RELAY_URL, PushDispatcher, PushRelayAdmin, RelayClient, enable_relay,
};
use kemlock_store_sql::SqlStore;
use std::sync::Arc;
use time::OffsetDateTime;
use uuid::Uuid;

/// What the server needs from the wiring.
pub struct Notifications {
    /// The hub the API is built with: its sockets, its mail and its path to the fan-out.
    pub hub: LiveHub,
    /// `/notifications/hub` for Bitwarden's apps; empty when the Bitwarden API is off.
    pub bitwarden: Router,
    /// What the Bitwarden API tells of every change: the hub, Bitwarden's push relay (when
    /// `PUSH_ENABLED`) and the owner's Kemlock devices.
    pub bw_live: BwLive,
    /// The sender mail goes out through (SMTP, or a log line without `SMTP_HOST`): the emailed
    /// two-step codes use it too.
    pub notices: Notices,
    /// The switch under `notices`: the settings the console saves point it at another SMTP
    /// server while the server runs.
    pub mailer: SwitchMailer,
    /// The same SMTP server for the admin console's alerts and invitations to the server; says no
    /// mail is set up without `SMTP_HOST`.
    pub admin_mail: AdminMail,
    /// Turns Kemlock's push relay on and off for the admin console (`/admin/v1/push-relay`).
    pub push_relay: Arc<dyn PushRelayControl>,
}

impl std::fmt::Debug for Notifications {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Notifications")
            .field("hub", &self.hub)
            .finish_non_exhaustive()
    }
}

/// Checks a Bitwarden access token the way the Bitwarden API does: signed by `rsa_key.pem`, issued
/// for this server, not expired, naming a device of its account, with the account's current
/// security stamp.
struct BwHubAuth {
    keys: TokenKeys,
    issuer: String,
    store: SqlStore,
}

impl HubAuth for BwHubAuth {
    fn authenticate(&self, token: &str) -> BoxFuture<'_, Option<HubIdentity>> {
        let token = token.to_owned();
        Box::pin(async move {
            let now = OffsetDateTime::now_utc().unix_timestamp();
            let claims: LoginClaims = self.keys.decode(&token, &self.issuer, now).ok()?;
            let user = UserId(Uuid::parse_str(&claims.sub).ok()?);
            let device = DeviceId(Uuid::parse_str(&claims.device).ok()?);
            let stored = DeviceRepo::get(&self.store, device).await.ok()??;
            if stored.user != user {
                return None;
            }
            let account = UserRepo::by_id(&self.store, user).await.ok()??;
            (account.security_stamp.to_string() == claims.sstamp).then_some(HubIdentity {
                user,
                device: Some(device),
            })
        })
    }
}

fn enabled(value: Option<String>) -> bool {
    value.is_some_and(|v| {
        matches!(
            v.trim().to_ascii_lowercase().as_str(),
            "true" | "1" | "yes" | "on"
        )
    })
}

/// Builds the mail senders: SMTP when `SMTP_HOST` is set, else a sender that only logs for the
/// notices, while the admin console's says no mail is set up until an SMTP server is in use. The
/// notices sit behind a
/// [`SwitchMailer`], so the SMTP settings saved in the console can replace the server while it runs
/// (see `live`); the admin console's mail goes through the same switch.
fn mail(
    config: &Config,
    env: &dyn Fn(&str) -> Option<String>,
) -> Result<(Notices, SwitchMailer, AdminMail), RunError> {
    let smtp = SmtpConfig::from_lookup(env).map_err(|e| RunError::Config(e.to_string()))?;
    let mailer: Arc<dyn Mailer> = match smtp {
        None => Arc::new(LogMailer),
        Some(smtp) => {
            let mailer =
                SmtpMailer::new(&smtp).map_err(|e| RunError::Config(format!("SMTP: {e}")))?;
            tracing::info!(host = %smtp.host, port = smtp.port, "mail goes out over SMTP");
            Arc::new(mailer)
        }
    };
    let switch = SwitchMailer::new(mailer);
    let outbox = MailOutbox::new(
        Arc::new(switch.clone()),
        Branding::new(config.domain.clone()),
    );
    // The console asks the switch whether it sends, so SMTP settings saved later count.
    let admin_mail = AdminMail::new(Some(Arc::new(switch.clone())));
    Ok((outbox.into_notices(), switch, admin_mail))
}

/// Starts the notification machinery over `store`.
pub async fn start(
    config: &Config,
    env: &dyn Fn(&str) -> Option<String>,
    store: &SqlStore,
    crypto: &ServerCrypto,
) -> Result<Notifications, RunError> {
    let (notices, mailer, admin_mail) = mail(config, env)?;

    // The hub every replica's sockets hang off, and Bitwarden's, which hears the same nudges.
    let local = LiveHub::new().with_notices(notices.clone());
    let audience = Arc::new(SpaceMembers(store.clone()));
    let bw_hub = BwHub::new(
        audience.clone(),
        HubConfig {
            ip_header: config.ip_header.clone(),
            ..HubConfig::default()
        },
    );
    let sink = {
        let (hub, bw) = (local.clone(), bw_hub.clone());
        let (hub_all, bw_all) = (local.clone(), bw_hub.clone());
        Sink::new(
            move |owner| {
                match owner {
                    Owner::User(_) => hub.nudge(owner),
                    // `/kem/v1/live` sockets are an account's: a space's nudge goes to each of its
                    // confirmed members' sockets.
                    Owner::Space(_) => {
                        let (hub, audience) = (hub.clone(), audience.clone());
                        tokio::spawn(async move {
                            for user in audience.users(owner).await {
                                hub.nudge(Owner::User(user));
                            }
                        });
                    }
                }
                bw.nudge(owner);
            },
            move || {
                hub_all.nudge_all();
                bw_all.nudge_everyone();
            },
        )
    };
    let fanout = Fanout::connect(store, sink, FanoutOptions::default())
        .await
        .map_err(|e| RunError::Store(format!("can't set up live sync between replicas: {e}")))?;
    tracing::info!(transport = ?fanout.transport(), "live sync is set up");

    // Kemlock's push relay. It does nothing until the server has registered with it.
    let relay_url = env("KEMLOCK_PUSH_RELAY_URL")
        .filter(|v| !v.trim().is_empty())
        .unwrap_or_else(|| DEFAULT_RELAY_URL.to_owned());
    let client = RelayClient::new(&relay_url)
        .map_err(|e| RunError::Config(format!("KEMLOCK_PUSH_RELAY_URL: {e}")))?;
    if enabled(env("KEMLOCK_PUSH_RELAY")) {
        register_with_relay(store.clone(), crypto.clone(), client.clone());
    }
    let push_relay: Arc<dyn PushRelayControl> = Arc::new(PushRelayAdmin::new(
        store.clone(),
        crypto.clone(),
        client.clone(),
        relay_url.clone(),
    ));
    let push = PushDispatcher::start(
        store.clone(),
        SpaceMembers(store.clone()),
        crypto.clone(),
        client,
        kemlock_notify::push::DEFAULT_WINDOW,
    );
    let notify = Notify::new(fanout, Some(push));

    // A commit goes to `notify`, which nudges every replica's sockets (this one's included, by
    // calling back into `local`) and wakes the phones from here only.
    let hub = local.with_outbound({
        let notify = notify.clone();
        move |owner| notify.nudge(owner)
    });

    let bw_live = bitwarden_live(env, store, &bw_hub, notify, notices.clone())?;
    let bitwarden = bitwarden_hub(config, store, &bw_hub)?;
    Ok(Notifications {
        hub,
        bitwarden,
        bw_live,
        notices,
        mailer,
        admin_mail,
        push_relay,
    })
}

/// Registers with the relay in the background when the server hasn't, so start isn't held up by
/// a network call. A failure is logged; the next start tries again.
fn register_with_relay(store: SqlStore, crypto: ServerCrypto, client: RelayClient) {
    tokio::spawn(async move {
        match kemlock_app::push::PushRepo::installation(&store).await {
            Ok(Some(_)) => return,
            Ok(None) => {}
            Err(error) => {
                tracing::warn!(%error, "couldn't read the push installation");
                return;
            }
        }
        match enable_relay(&store, &crypto, &client).await {
            Ok(id) => tracing::info!(installation = %id, "registered with the push relay"),
            Err(error) => tracing::warn!(%error, "couldn't register with the push relay"),
        }
    });
}

/// What the Bitwarden API publishes to: Bitwarden's hub, the Kemlock devices and the other replicas
/// through `notify`, and Bitwarden's push relay when `PUSH_ENABLED` is true with
/// `PUSH_INSTALLATION_ID` and `PUSH_INSTALLATION_KEY` (`PUSH_RELAY_URI` and `PUSH_IDENTITY_URI` for
/// the EU cloud). A setting that is wrong stops the start rather than leave pushes silently off.
/// `REQUIRE_DEVICE_EMAIL` makes a sign-in from a new device fail when its mail can't be sent.
fn bitwarden_live(
    env: &dyn Fn(&str) -> Option<String>,
    store: &SqlStore,
    bw_hub: &BwHub,
    notify: Notify,
    notices: Notices,
) -> Result<BwLive, RunError> {
    let relay = BitwardenPushConfig::from_lookup(env)
        .map_err(|e| RunError::Config(e.to_string()))?
        .map(|config| BitwardenPush::new(config).map(Arc::new))
        .transpose()
        .map_err(|e| RunError::Config(format!("PUSH_*: {e}")))?;
    if relay.is_some() {
        tracing::info!("Bitwarden's push relay is on (PUSH_ENABLED)");
    }
    let pushing = relay.clone().map(|relay| BwPushing {
        relay,
        devices: store.clone(),
    });
    Ok(BwLive {
        events: Arc::new(BwNotifier::new(bw_hub.clone(), notify, pushing)),
        relay: relay.map(|relay| relay as Arc<dyn BwRelay>),
        notices,
        require_device_email: enabled(env("REQUIRE_DEVICE_EMAIL")),
        // Set by the app, which holds the files the erasure deletes.
        erasure: None,
    })
}

/// `/notifications/hub`, over the Bitwarden API's token keys. Empty when that API is off.
fn bitwarden_hub(config: &Config, store: &SqlStore, bw_hub: &BwHub) -> Result<Router, RunError> {
    let settings = BwSettings::new(&config.domain, config.signups_allowed).compat_from_env();
    if !settings.compat {
        return Ok(Router::new());
    }
    let keys = TokenKeys::load_or_create(&config.data_folder)
        .map_err(|e| RunError::Config(format!("the Bitwarden token key: {e}")))?;
    let auth = BwHubAuth {
        keys,
        issuer: format!("{}|login", settings.origin),
        store: store.clone(),
    };
    Ok(kemlock_notify::bitwarden::router(
        bw_hub.clone(),
        Arc::new(auth),
    ))
}
