//! What the admin routes need beyond the Kemlock API's own state: the admin repositories, the
//! space and SSO stores, DNS, mail and the environment, wired once by the server.

use kemlock_api_kem::{Api, Crypto, Store};
use kemlock_app::admin::{
    AccountErasure, AdminError, AdminRepos, AdminSpaces, AdminUsers, Audit, Compliance,
    EnvSettings, EventLogView, Mailer, MigrationRecord, MigrationRunner, Overview, PasskeyStepper,
    PushRelayControl, Settings, SsoAdmin, StepUp,
};
use kemlock_app::ports::TokenSigner;
use kemlock_app::spaces::SpaceRepo;
use kemlock_app::sso::{SsoRepos, TxtLookup};
use std::sync::Arc;

/// The ports of the admin routes. `R` holds the admin repositories (`SqlStore` implements them
/// all), `Sp` the spaces, `So` the SSO settings and domains, `D` the DNS lookup for domain proofs
/// and `M` the mailer. A server wires `SqlStore` into the first three.
pub struct AdminRuntime<R, Sp, So, D, M> {
    pub repos: R,
    pub spaces: Sp,
    pub sso: So,
    pub dns: D,
    pub mail: M,
    /// The process environment as the settings screen reads it.
    pub env: Arc<dyn EnvSettings>,
    /// Called after settings are saved, so the server can re-read them at once instead of at its
    /// next poll.
    pub settings_saved: Option<SettingsSaved>,
    /// The passkey step-up, when the server has a WebAuthn relying party. Without it the passkey
    /// routes answer that they are not set up.
    pub passkeys: Option<Arc<dyn PasskeyStepper>>,
    /// What starts the move from Vaultwarden in the background. Without it the start route
    /// answers that the import isn't set up.
    pub migration: Option<Arc<dyn MigrationRunner>>,
    /// Kemlock's push relay, when the server has one to turn on and off (see
    /// [`AdminRuntime::with_push_relay`]).
    pub push_relay: Option<Arc<dyn PushRelayControl>>,
    /// What deletes an account for an admin: privacy's whole erasure (see
    /// [`AdminRuntime::with_account_erasure`]).
    pub erasure: Option<Arc<dyn AccountErasure>>,
    /// The data folder the server runs in, shown by `/admin/v1/server-address` (see
    /// [`AdminRuntime::with_data_folder`]).
    pub data_folder: Option<String>,
}

impl<R, Sp, So, D, M> AdminRuntime<R, Sp, So, D, M> {
    pub fn new(
        repos: R,
        spaces: Sp,
        sso: So,
        dns: D,
        mail: M,
        env: impl EnvSettings + 'static,
    ) -> Self {
        AdminRuntime {
            repos,
            spaces,
            sso,
            dns,
            mail,
            env: Arc::new(env),
            settings_saved: None,
            passkeys: None,
            migration: None,
            push_relay: None,
            erasure: None,
            data_folder: None,
        }
    }

    /// Tells the console which data folder the server uses, which only the environment sets.
    #[must_use]
    pub fn with_data_folder(mut self, folder: impl Into<String>) -> Self {
        self.data_folder = Some(folder.into());
        self
    }

    /// Sets what deletes an account for an admin: `kemlock_app::privacy::EraseAccount`, which takes
    /// the account's items, files, Sends, sign-in log and federated copies with it. Without one the
    /// delete route answers that deleting isn't set up, rather than leave those behind.
    #[must_use]
    pub fn with_account_erasure(mut self, erasure: Arc<dyn AccountErasure>) -> Self {
        self.erasure = Some(erasure);
        self
    }

    /// Lets the console turn Kemlock's push relay on and off and show where it stands
    /// (`/admin/v1/push-relay`). Without it those routes answer 409.
    #[must_use]
    pub fn with_push_relay(mut self, relay: Arc<dyn PushRelayControl>) -> Self {
        self.push_relay = Some(relay);
        self
    }
}

/// What the server runs after the console saves settings.
pub type SettingsSaved = Arc<dyn Fn() + Send + Sync>;

impl<R, Sp, So, D, M> AdminRuntime<R, Sp, So, D, M> {
    /// Lets an admin start the move from Vaultwarden (see `kemlock_app::admin::MigrationRunner`).
    #[must_use]
    pub fn with_migration(mut self, runner: Arc<dyn MigrationRunner>) -> Self {
        self.migration = Some(runner);
        self
    }

    /// Lets an admin step up with a passkey (see `kemlock_app::admin::PasskeyStepUp`).
    #[must_use]
    pub fn with_passkeys(mut self, stepper: Arc<dyn PasskeyStepper>) -> Self {
        self.passkeys = Some(stepper);
        self
    }

    /// Runs `hook` after each save of the settings (the server nudges its settings watcher).
    #[must_use]
    pub fn on_settings_saved(mut self, hook: impl Fn() + Send + Sync + 'static) -> Self {
        self.settings_saved = Some(Arc::new(hook));
        self
    }
}

impl<R, Sp, So, D, M> std::fmt::Debug for AdminRuntime<R, Sp, So, D, M> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AdminRuntime").finish_non_exhaustive()
    }
}

/// The router's state: the Kemlock API's and the admin runtime.
pub(crate) struct Env<S, P, K, R, Sp, So, D, M> {
    pub(crate) api: Api<S, P, K>,
    pub(crate) rt: Arc<AdminRuntime<R, Sp, So, D, M>>,
}

impl<S, P, K, R, Sp, So, D, M> Clone for Env<S, P, K, R, Sp, So, D, M> {
    fn clone(&self) -> Self {
        Env {
            api: self.api.clone(),
            rt: Arc::clone(&self.rt),
        }
    }
}

impl<S, P, K, R, Sp, So, D, M> Env<S, P, K, R, Sp, So, D, M>
where
    S: Store,
    P: Crypto,
    K: TokenSigner + Clone + 'static,
    R: AdminRepos,
    Sp: SpaceRepo + Clone + 'static,
    So: SsoRepos,
    D: TxtLookup + Clone + 'static,
    M: Mailer + Clone + 'static,
{
    pub(crate) fn step_up(&self) -> StepUp<S, S, P, P, P, P> {
        let api = &self.api;
        StepUp {
            users: api.store.clone(),
            two_factor: api.store.clone(),
            auth: api.crypto.clone(),
            seal: api.crypto.clone(),
            totp: api.crypto.clone(),
            env: api.crypto.clone(),
        }
    }

    /// What starts a move, or "not set up" when the server has no import wired in.
    pub(crate) fn migration_runner(&self) -> Result<Arc<dyn MigrationRunner>, AdminError> {
        self.rt.migration.clone().ok_or(AdminError::NotConfigured(
            "the Vaultwarden import isn't set up on this server",
        ))
    }

    /// The passkey step-up, or "not set up" when the server has no relying party.
    pub(crate) fn passkey_stepper(&self) -> Result<Arc<dyn PasskeyStepper>, AdminError> {
        self.rt.passkeys.clone().ok_or(AdminError::NotConfigured(
            "passkeys aren't set up on this server",
        ))
    }

    pub(crate) fn users(&self) -> AdminUsers<S, R, M, P> {
        AdminUsers {
            store: self.api.store.clone(),
            repos: self.rt.repos.clone(),
            mail: self.rt.mail.clone(),
            env: self.api.crypto.clone(),
            domain: self.api.config.domain.clone(),
            erasure: self.rt.erasure.clone(),
        }
    }

    pub(crate) fn spaces(&self) -> AdminSpaces<Sp, R, M, P> {
        AdminSpaces {
            spaces: self.rt.spaces.clone(),
            repos: self.rt.repos.clone(),
            mail: self.rt.mail.clone(),
            clock: self.api.crypto.clone(),
        }
    }

    pub(crate) fn settings(&self) -> Settings<R, P, Arc<dyn EnvSettings>> {
        Settings {
            repo: self.rt.repos.clone(),
            seal: self.api.crypto.clone(),
            env: Arc::clone(&self.rt.env),
        }
    }

    pub(crate) fn sso_admin(&self) -> SsoAdmin<So, D, R, M, P> {
        SsoAdmin {
            sso: self.rt.sso.clone(),
            dns: self.rt.dns.clone(),
            repos: self.rt.repos.clone(),
            mail: self.rt.mail.clone(),
            env: self.api.crypto.clone(),
            domain: self.api.config.domain.clone(),
        }
    }

    pub(crate) fn compliance(&self) -> Compliance<R, M, P> {
        Compliance {
            repos: self.rt.repos.clone(),
            mail: self.rt.mail.clone(),
            env: self.api.crypto.clone(),
        }
    }

    pub(crate) fn overview_case(&self) -> Overview<R, M, P> {
        Overview {
            repos: self.rt.repos.clone(),
            mail: self.rt.mail.clone(),
            clock: self.api.crypto.clone(),
        }
    }

    pub(crate) fn events(&self) -> EventLogView<R> {
        EventLogView {
            events: self.rt.repos.clone(),
        }
    }

    pub(crate) fn migration(&self) -> MigrationRecord<R, P> {
        MigrationRecord {
            repo: self.rt.repos.clone(),
            clock: self.api.crypto.clone(),
        }
    }

    /// Seconds since the Unix epoch, from the platform clock.
    pub(crate) fn now(&self) -> i64 {
        self.api.crypto.now().unix_timestamp()
    }
}

impl<S, P, K, R, Sp, So, D, M> Env<S, P, K, R, Sp, So, D, M>
where
    S: Store,
    P: Crypto,
    K: TokenSigner + Clone + 'static,
    R: AdminRepos,
    M: Mailer + Clone + 'static,
{
    /// The audit step for writes that no use case audits itself (settings, an export).
    pub(crate) fn audit(&self) -> Audit<R, R, M, P> {
        Audit {
            events: self.rt.repos.clone(),
            users: self.rt.repos.clone(),
            mail: self.rt.mail.clone(),
            clock: self.api.crypto.clone(),
        }
    }
}
