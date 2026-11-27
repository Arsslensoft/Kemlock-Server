//! Wires `kemlock-notify` into the server: mail for the notices the API raises, the live hub
//! and its fan-out between replicas, push to the phones, Bitwarden's `/notifications/hub` and
//! the events the Bitwarden API publishes to it, with Bitwarden's own push relay (`PUSH_*`).
//!
//! Settings are Vaultwarden's where they exist: `SMTP_HOST`, `SMTP_FROM`, `SMTP_FROM_NAME`,
//! `SMTP_PORT`, `SMTP_SECURITY`, `SMTP_USERNAME`, `SMTP_PASSWORD`, `SMTP_TIMEOUT`,
//! `SMTP_ACCEPT_INVALID_CERTS` and `SMTP_ACCEPT_INVALID_HOSTNAMES`; `PUSH_ENABLED`,
//! `PUSH_INSTALLATION_ID`, `PUSH_INSTALLATION_KEY`, `PUSH_RELAY_URI`, `PUSH_IDENTITY_URI` and
//! `REQUIRE_DEVICE_EMAIL`.
//! Kemlock's own: the server pushes to iPhones itself with an Apple key,
//! `KEMLOCK_APNS_KEY_FILE`, `KEMLOCK_APNS_KEY_ID` and `KEMLOCK_APNS_TEAM_ID` (all three or none),
//! `KEMLOCK_APNS_TOPIC` (default `com.kemlock.app`) and `KEMLOCK_APNS_SANDBOX` (default false); to
//! Android phones through UnifiedPush with no setting. The hosted relay is an optional fallback for
//! iPhones, off unless turned on: `KEMLOCK_PUSH_RELAY` (`true` registers this server with the relay
//! at start when it hasn't yet) and `KEMLOCK_PUSH_RELAY_URL` (another relay than Kemlock's).

use crate::adapters::ServerCrypto;
use crate::app::RunError;
use crate::config::Config;
use crate::live::{PushValues, Snapshot, SwitchMailer};
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
    BitwardenPush, BitwardenPushConfig, BwHub, BwNotifier, BwPushSwitch, BwPushing, HubAuth,
    HubConfig, HubIdentity,
};
use kemlock_notify::fanout::{Fanout, FanoutOptions, Sink};
use kemlock_notify::mail::{
    AdminMail, Branding, LogMailer, MailOutbox, Mailer, SmtpConfig, SmtpMailer,
};
use kemlock_notify::push::{
    ApnsConfig, ApnsSender, BuiltInPush, DEFAULT_RELAY_URL, DirectSenders, PushDispatcher,
    PushRelayAdmin, RelayClient, UnifiedPushSender, enable_relay,
};
use kemlock_store_sql::SqlStore;
use std::sync::{Arc, Mutex, PoisonError};
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
    /// Shows push for the admin console and turns Kemlock's optional relay on and off
    /// (`/admin/v1/push-relay`).
    pub push_relay: Arc<dyn PushRelayControl>,
    /// Applies the saved push settings to the running relays.
    pub push_follower: PushFollower,
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
            // A password change moves the stamp, and a disabled account has no session.
            if account.security_stamp.to_string() != claims.sstamp {
                return None;
            }
            if UserRepo::account_disabled(&self.store, user).await.ok()? {
                return None;
            }
            Some(HubIdentity {
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

    // The server's own Apple push, when it has a key. A bad setting stops the start.
    let apns = ApnsConfig::from_lookup(env)
        .map_err(|e| RunError::Config(e.to_string()))?
        .map(ApnsSender::new)
        .transpose()
        .map_err(|e| RunError::Config(format!("KEMLOCK_APNS_*: {e}")))?;
    match &apns {
        Some(apns) => tracing::info!(
            sandbox = apns.sandbox(),
            "iPhones are pushed to through Apple"
        ),
        None => tracing::info!("no Apple push key (KEMLOCK_APNS_*): iPhones need the relay"),
    }
    let built_in = BuiltInPush::of(apns.as_ref());
    let direct = DirectSenders {
        apns,
        unified_push: UnifiedPushSender::from_lookup(env).map_err(RunError::Config)?,
    };

    // Kemlock's optional push relay. It does nothing until the server has registered with it.
    let relay_url = env("KEMLOCK_PUSH_RELAY_URL")
        .filter(|v| !v.trim().is_empty())
        .unwrap_or_else(|| DEFAULT_RELAY_URL.to_owned());
    let client = RelayClient::new(&relay_url)
        .map_err(|e| RunError::Config(format!("KEMLOCK_PUSH_RELAY_URL: {e}")))?;
    // Registering with the relay when `KEMLOCK_PUSH_RELAY` is on is the follower's job, so a
    // setting saved later counts as much as the environment.
    let push_relay: Arc<dyn PushRelayControl> = Arc::new(PushRelayAdmin::new(
        store.clone(),
        crypto.clone(),
        client.clone(),
        relay_url.clone(),
        built_in,
    ));
    let push = PushDispatcher::start(
        store.clone(),
        SpaceMembers(store.clone()),
        crypto.clone(),
        client.clone(),
        direct,
        kemlock_notify::push::DEFAULT_WINDOW,
    );
    let notify = Notify::new(fanout, Some(push));

    // A commit goes to `notify`, which nudges every replica's sockets (this one's included, by
    // calling back into `local`) and wakes the phones from here only.
    let hub = local.with_outbound({
        let notify = notify.clone();
        move |owner| notify.nudge(owner)
    });

    let (bw_live, bw_switch) = bitwarden_live(env, store, &bw_hub, notify, notices.clone())?;
    let push_follower = PushFollower::new(bw_switch, client, store.clone(), crypto.clone());
    let bitwarden = bitwarden_hub(config, store, &bw_hub)?;
    Ok(Notifications {
        hub,
        bitwarden,
        bw_live,
        notices,
        mailer,
        admin_mail,
        push_relay,
        push_follower,
    })
}

/// What the push relays last followed, so a snapshot that changed something else leaves them be.
#[derive(Default)]
struct Followed {
    bitwarden: Option<PushValues>,
    registered: bool,
}

/// Makes the push relays follow the saved settings while the server runs: Bitwarden's relay is
/// rebuilt when its settings change, Kemlock's client is pointed at the relay address now set, and
/// the server registers with Kemlock's relay the first time `KEMLOCK_PUSH_RELAY` turns on. A
/// setting that doesn't make a usable relay leaves the one in use as it is.
#[derive(Clone)]
pub struct PushFollower {
    switch: BwPushSwitch,
    client: RelayClient,
    store: SqlStore,
    crypto: ServerCrypto,
    followed: Arc<Mutex<Followed>>,
}

impl std::fmt::Debug for PushFollower {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PushFollower").finish_non_exhaustive()
    }
}

impl PushFollower {
    pub fn new(
        switch: BwPushSwitch,
        client: RelayClient,
        store: SqlStore,
        crypto: ServerCrypto,
    ) -> PushFollower {
        PushFollower {
            switch,
            client,
            store,
            crypto,
            followed: Arc::new(Mutex::new(Followed::default())),
        }
    }

    /// Applies `snapshot`. Call it from a Tokio runtime: registering is a background task.
    pub fn follow(&self, snapshot: &Snapshot) {
        let mut followed = self.followed.lock().unwrap_or_else(PoisonError::into_inner);
        if let Some(why) = &snapshot.push_error {
            tracing::warn!(%why, "the push settings are unusable; pushes go out as before");
        } else if followed.bitwarden.as_ref() != Some(&snapshot.push) {
            match snapshot.push.config().and_then(|config| {
                config
                    .map(|config| BitwardenPush::new(config).map(Arc::new))
                    .transpose()
                    .map_err(|e| e.to_string())
            }) {
                Ok(relay) => {
                    if relay.is_some() {
                        tracing::info!("Bitwarden's push relay is on");
                    } else {
                        tracing::info!("Bitwarden's push relay is off");
                    }
                    self.switch.set(relay);
                    followed.bitwarden = Some(snapshot.push.clone());
                }
                Err(why) => {
                    tracing::warn!(%why, "the Bitwarden push settings are unusable; pushes go out as before");
                }
            }
        }
        let url = if snapshot.kemlock_relay_url.trim().is_empty() {
            DEFAULT_RELAY_URL.to_owned()
        } else {
            snapshot.kemlock_relay_url.trim().to_owned()
        };
        let url = url.trim_end_matches('/').to_owned();
        let move_to = (url != self.client.base()).then_some(url);
        let register = snapshot.kemlock_relay && !followed.registered;
        followed.registered = snapshot.kemlock_relay;
        drop(followed);
        if move_to.is_none() && !register {
            return;
        }
        let (store, crypto, client) =
            (self.store.clone(), self.crypto.clone(), self.client.clone());
        tokio::spawn(async move {
            if let Some(url) = move_to {
                // The installation key goes to whatever relay the client talks to, and turning
                // the relay off erases the installation there: another address is taken only by
                // a server that isn't registered, so the key never reaches a relay that didn't
                // issue it. Turn the relay off first.
                match kemlock_app::push::PushRepo::installation(&store).await {
                    Ok(None) => {
                        if let Err(error) = client.set_base(&url) {
                            tracing::warn!(%error, "the Kemlock push relay address is unusable; the old one stays");
                            return;
                        }
                    }
                    Ok(Some(_)) => {
                        tracing::warn!(
                            "the server is registered with the push relay, so its address stays; turn the relay off before changing it"
                        );
                        return;
                    }
                    Err(error) => {
                        tracing::warn!(%error, "couldn't read the push installation; the relay address stays");
                        return;
                    }
                }
            }
            if register {
                register_with_relay(store, crypto, client);
            }
        });
    }
}

/// Registers with the relay in the background when the server hasn't, so start isn't held up by
/// a network call. A failure is logged; the next start tries again.
pub(crate) fn register_with_relay(store: SqlStore, crypto: ServerCrypto, client: RelayClient) {
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
) -> Result<(BwLive, BwPushSwitch), RunError> {
    let relay = BitwardenPushConfig::from_lookup(env)
        .map_err(|e| RunError::Config(e.to_string()))?
        .map(|config| BitwardenPush::new(config).map(Arc::new))
        .transpose()
        .map_err(|e| RunError::Config(format!("PUSH_*: {e}")))?;
    if relay.is_some() {
        tracing::info!("Bitwarden's push relay is on (PUSH_ENABLED)");
    }
    // The switch is what the later settings change: the notifier and the device routes both
    // hold it.
    let switch = BwPushSwitch::new(relay);
    let pushing = Some(BwPushing {
        relay: switch.clone(),
        devices: store.clone(),
    });
    let live = BwLive {
        events: Arc::new(BwNotifier::new(bw_hub.clone(), notify, pushing)),
        relay: Some(Arc::new(switch.clone()) as Arc<dyn BwRelay>),
        notices,
        require_device_email: enabled(env("REQUIRE_DEVICE_EMAIL")),
        // Set by the app, which holds the files the erasure deletes.
        erasure: None,
    };
    Ok((live, switch))
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::live::{Layered, SettingsWatch};
    use kemlock_app::admin::{Change, NoEnv, Settings};
    use kemlock_crypto::opaque::OpaqueServer;
    use kemlock_crypto::seal::ServerSeal;
    use std::collections::BTreeMap;

    fn crypto() -> ServerCrypto {
        ServerCrypto::new(ServerSeal::new(&[7u8; 32]), OpaqueServer::generate())
    }

    async fn save(store: &SqlStore, pairs: &[(&str, &str)]) {
        let settings = Settings {
            repo: store.clone(),
            seal: crypto(),
            env: NoEnv,
        };
        let changes = pairs
            .iter()
            .map(|(k, v)| ((*k).to_owned(), Change::Set((*v).to_owned())))
            .collect();
        settings.apply(&changes).await.expect("saved");
    }

    struct Rig {
        store: SqlStore,
        watch: Arc<SettingsWatch>,
        follower: PushFollower,
        switch: BwPushSwitch,
    }

    async fn rig() -> Rig {
        let store = SqlStore::connect("sqlite::memory:").await.expect("a store");
        let watch = SettingsWatch::start(
            store.clone(),
            crypto(),
            Layered::new(|_| None, BTreeMap::new()),
        )
        .await
        .expect("read");
        let switch = BwPushSwitch::new(None);
        let client = RelayClient::new("https://relay.example.org").expect("a client");
        let follower = PushFollower::new(switch.clone(), client, store.clone(), crypto());
        Rig {
            store,
            watch,
            follower,
            switch,
        }
    }

    impl Rig {
        async fn follow(&self) {
            self.watch.refresh().await.expect("read again");
            self.follower.follow(&self.watch.current());
        }
    }

    #[tokio::test]
    async fn bitwardens_relay_is_switched_on_swapped_and_left_alone_when_nothing_changed() {
        let rig = rig().await;
        rig.follow().await;
        assert!(rig.switch.get().is_none());

        save(
            &rig.store,
            &[
                ("push_enabled", "true"),
                ("push_installation_id", "inst-1"),
                ("push_installation_key", "key-1"),
            ],
        )
        .await;
        rig.follow().await;
        let first = rig.switch.get().expect("on");

        // A snapshot with the same push settings leaves the relay (and its token) in place.
        save(&rig.store, &[("trash_days", "45")]).await;
        rig.follow().await;
        assert!(Arc::ptr_eq(&first, &rig.switch.get().expect("on")));

        // New settings swap it.
        save(&rig.store, &[("push_installation_id", "inst-2")]).await;
        rig.follow().await;
        assert!(!Arc::ptr_eq(&first, &rig.switch.get().expect("on")));

        // Turning it off switches it off.
        save(&rig.store, &[("push_enabled", "false")]).await;
        rig.follow().await;
        assert!(rig.switch.get().is_none());
    }

    #[tokio::test]
    async fn an_unusable_push_setting_keeps_the_relay_in_use() {
        let rig = rig().await;
        save(
            &rig.store,
            &[
                ("push_enabled", "true"),
                ("push_installation_id", "inst-1"),
                ("push_installation_key", "key-1"),
            ],
        )
        .await;
        rig.follow().await;
        let before = rig.switch.get().expect("on");

        // A sealed value that doesn't open: the snapshot says so and the relay stays.
        kemlock_app::admin::SettingsRepo::put_setting(
            &rig.store,
            "setting.push_installation_key",
            "AAAA",
        )
        .await
        .expect("saved");
        rig.watch.refresh().await.expect("read again");
        assert!(rig.watch.current().push_error.is_some());
        rig.follower.follow(&rig.watch.current());
        assert!(Arc::ptr_eq(&before, &rig.switch.get().expect("still on")));
    }
}
