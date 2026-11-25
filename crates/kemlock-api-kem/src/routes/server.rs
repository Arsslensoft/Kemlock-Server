//! `/config`, `/openapi.json` and first-run setup.

use super::guard;
use super::view::MaybeView;
use crate::dto::{
    ConfigResponse, SetupFinishRequest, SetupVerifyRequest, SetupVerifyResponse, VaultServersDto,
};
use crate::extract::{Authed, Body, ClientIp, SecureConnection};
use crate::openapi::{ApiDoc, CommonAnswers};
use crate::problem::Problem;
use crate::ratelimit::ip_key;
use crate::state::{Api, Crypto, Store};
use axum::Json;
use axum::extract::{RawQuery, State};
use axum::http::StatusCode;
use kemlock_app::admin::{FnEnv, Settings, SettingsRepo};
use kemlock_app::ports::TokenSigner;
use kemlock_app::{AppError, SetupPhase, record_domain, save_basics, without_env_set};
use kemlock_domain::Owner;
use utoipa::{Modify, OpenApi};

/// The licence the server is under, as an SPDX identifier.
const LICENSE: &str = "AGPL-3.0-only";

/// The most vaults one `/config` call may ask about.
const MAX_VAULTS: usize = 32;

/// The `vault` parameters of a query string, each `user:<uuid>` or `space:<uuid>`, once each.
fn requested_vaults(query: Option<&str>) -> Result<Vec<Owner>, Problem> {
    let mut asked = 0usize;
    let mut owners: Vec<Owner> = Vec::new();
    for (key, value) in url::form_urlencoded::parse(query.unwrap_or_default().as_bytes()) {
        if key.as_ref() != "vault" {
            continue;
        }
        asked += 1;
        if asked > MAX_VAULTS {
            return Err(Problem::bad_request(
                "ask about at most 32 vaults at a time",
            ));
        }
        let owner: Owner = value
            .parse()
            .map_err(|e: &'static str| Problem::bad_request(format!("vault: {e}")))?;
        if !owners.contains(&owner) {
            owners.push(owner);
        }
    }
    Ok(owners)
}

impl<S: Store, P: Crypto, K: TokenSigner + Clone + 'static> Api<S, P, K> {
    /// `GET /kem/v1/config`: what a client reads before signing in. With `?vault=user:<uuid>` (or
    /// `space:<uuid>`, repeated up to 32 times) it also lists the servers of those vaults that
    /// are federated here, the home first.
    pub(crate) async fn handle_config(
        State(api): State<Self>,
        MaybeView(view): MaybeView,
        RawQuery(query): RawQuery,
    ) -> Result<Json<ConfigResponse>, Problem> {
        let asked = requested_vaults(query.as_deref())?;
        let mut vaults = Vec::new();
        if let Some(view) = view {
            for owner in asked {
                let known = view
                    .vault_servers(owner)
                    .await
                    .map_err(|e| Problem::from(AppError::from(e)))?;
                // A vault that isn't federated here is left out, not reported as missing.
                if let Some(servers) = known {
                    vaults.push(VaultServersDto::from_view(&servers));
                }
            }
        }
        let setup = match api.setup.phase() {
            SetupPhase::NeedsAdmin => "needs-admin",
            SetupPhase::Pending => "pending",
            SetupPhase::Done => "complete",
        };
        Ok(Json(ConfigResponse {
            server: "kemlock-server".to_owned(),
            api_versions: vec!["v1".to_owned()],
            version: api.config.version.clone(),
            commit: api.config.commit.clone(),
            license: LICENSE.to_owned(),
            source_url: api.config.source_url.clone(),
            server_id: api.store.server_id().0,
            domain: api.config.domain.clone(),
            setup: setup.to_owned(),
            signups_allowed: api.live.signups_allowed(),
            features: [
                "opaque",
                "dpop",
                "totp",
                "sync",
                "live",
                "manifest",
                "device-list",
                "bitwarden-enrol",
                "account-keys",
                "sends",
            ]
            .into_iter()
            .map(str::to_owned)
            .collect(),
            vaults,
        }))
    }

    /// `GET /kem/v1/openapi.json`: one document for every route: the API's own and the parts that
    /// live beside their routes: trusted devices, emergency access and the app contract, files,
    /// single sign-on, spaces, your data, push tokens, passkeys, Sends, policies, the Recovery Kit and the duplicate
    /// cleaner. `tests/openapi.rs` checks that every routed path is in it.
    pub(crate) async fn handle_openapi() -> Json<utoipa::openapi::OpenApi> {
        let mut document = ApiDoc::openapi()
            .merge_from(super::devices::document())
            .merge_from(super::files::FilesDoc::openapi())
            .merge_from(super::sso::SsoApiDoc::openapi())
            .merge_from(super::spaces::openapi())
            .merge_from(super::space_chain::openapi())
            .merge_from(super::space_recovery::openapi())
            .merge_from(super::account::document())
            .merge_from(super::push::document())
            .merge_from(super::passkeys::PasskeysApiDoc::openapi())
            .merge_from(super::sends::SendsDoc::openapi())
            .merge_from(super::policies::PoliciesDoc::openapi())
            .merge_from(super::duplicates::openapi())
            .merge_from(super::placement::document())
            .merge_from(super::two_step::TwoStepApiDoc::openapi())
            .merge_from(super::recovery_kit::RecoveryKitApiDoc::openapi());
        // The answers every route can give, over the whole merged document.
        CommonAnswers.modify(&mut document);
        Json(document)
    }

    /// `POST /kem/v1/setup/verify`: trades the setup code from the log for a grant.
    pub(crate) async fn handle_setup_verify(
        State(api): State<Self>,
        ClientIp(ip): ClientIp,
        SecureConnection(secure): SecureConnection,
        body: Body,
    ) -> Result<Json<SetupVerifyResponse>, Problem> {
        guard(&api.limits.setup, &ip_key(ip), api.now())?;
        let request: SetupVerifyRequest = body.json()?;
        // Setup goes no further than a secure context, which the connection decides (see
        // `is_secure_connection`), not the `Origin` header or `DOMAIN`.
        let grant = api
            .first_run()
            .verify(&request.code, secure, &ip_key(ip))
            .await?;
        Ok(Json(SetupVerifyResponse {
            grant: grant.token,
            expires_in: (grant.expires_at - api.crypto.now()).whole_seconds().max(0),
        }))
    }
}

impl<S: Store + SettingsRepo, P: Crypto, K: TokenSigner + Clone + 'static> Api<S, P, K> {
    /// `POST /kem/v1/setup/finish`: closes setup, for the admin who has a two-step method. The
    /// body is optional; with `basics` the server basics are saved as settings first, and only for
    /// the admin setup waits for, so a failed save leaves setup open to retry. They are checked
    /// before either, so a bad value changes nothing.
    pub(crate) async fn handle_setup_finish(
        State(api): State<Self>,
        authed: Authed,
        body: Body,
    ) -> Result<StatusCode, Problem> {
        let changes = if body.0.iter().all(u8::is_ascii_whitespace) {
            None
        } else {
            let request: SetupFinishRequest = body.json()?;
            request
                .basics
                .map(|basics| {
                    let basics = basics.into_basics()?;
                    Ok::<_, AppError>((basics.changes()?, basics.recorded_domain()?))
                })
                .transpose()?
        };
        let user = authed.actor.user;
        if let Some((changes, domain)) = changes {
            // Only the account setup waits for may write them; they are saved before setup
            // closes, so a store failure leaves setup open to retry (saving is idempotent).
            match api.setup.pending() {
                Some(pending) if pending == user => {}
                Some(_) => return Err(AppError::Forbidden.into()),
                None => return Err(AppError::Setup(kemlock_domain::SetupError::AlreadyDone).into()),
            }
            let env = FnEnv(|name: &str| std::env::var(name).ok());
            let changes = without_env_set(changes, &env);
            let settings = Settings {
                repo: api.store.clone(),
                seal: api.crypto.clone(),
                env,
            };
            save_basics(&settings, &changes).await?;
            if let Some(domain) = domain {
                record_domain(&api.store, &domain).await?;
            }
        }
        api.finish_setup().execute(user).await?;
        Ok(StatusCode::NO_CONTENT)
    }
}
