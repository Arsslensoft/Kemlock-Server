//! The handlers, as associated functions of the router's state so one impl block states the port
//! bounds, and the router that wires them to paths.

use crate::dto::*;
use crate::error::ApiError;
use crate::extract::{Caller, Writer};
use crate::migrate;
use crate::state::{AdminRuntime, Env};
use axum::body::Body as HttpBody;
use axum::extract::rejection::QueryRejection;
use axum::extract::{Path, Query, Request, State};
use axum::http::{HeaderName, HeaderValue, StatusCode, header};
use axum::middleware::{self, Next};
use axum::response::{IntoResponse, Response};
use axum::routing::{delete, get, post, put};
use axum::{Json, Router};
use kemlock_api_kem::dto::decode;
use kemlock_api_kem::extract::{Body, DPOP_NONCE};
use kemlock_api_kem::problem::rate_limited;
use kemlock_api_kem::ratelimit::ip_key;
use kemlock_api_kem::replay::Full;
use kemlock_api_kem::{
    Api, Crypto, CustomFieldDto, CustomFieldsDto, MaybeInviteLinks, Problem, Store,
    forget_second_step, reserve_second_step,
};
use kemlock_app::admin::events::{cursor_text, filter as event_filter, parse_cursor};
use kemlock_app::admin::{
    AdminError, AdminRepos, Change, FieldInput, Mailer, MigrationRequest, NewRequest,
    PushRelayControl, RequestKind, RequestStatus, RequestUpdate, SecretChange, SsoInput, UserQuery,
};
use kemlock_app::b64url;
use kemlock_app::ports::TokenSigner;
use kemlock_app::spaces::SpaceRepo;
use kemlock_app::sso::{SsoRepos, TxtLookup};
use kemlock_domain::{CustomFieldId, FieldType, SpaceId, UserId};
use serde::Deserialize;
use std::collections::BTreeMap;
use std::sync::Arc;
use time::OffsetDateTime;
use uuid::Uuid;

/// Kemlock's own relay, shown as the target when this server has none wired in
/// (`kemlock_notify::push::DEFAULT_RELAY_URL`).
const DEFAULT_PUSH_RELAY_URL: &str = "https://push.kemlock.app";

// ---------------------------------------------------------------------------------------------
// Small helpers

fn bad(why: impl Into<String>) -> ApiError {
    ApiError(Problem::bad_request(why))
}

fn uuid(text: &str) -> Result<Uuid, ApiError> {
    Uuid::parse_str(text).map_err(|_| bad("the id in the path isn't a UUID"))
}

fn query<T>(parsed: Result<Query<T>, QueryRejection>) -> Result<T, ApiError> {
    parsed
        .map(|Query(value)| value)
        .map_err(|_| bad("the query string isn't valid"))
}

fn time_of(secs: i64, name: &str) -> Result<OffsetDateTime, ApiError> {
    OffsetDateTime::from_unix_timestamp(secs).map_err(|_| bad(format!("{name} isn't a time")))
}

fn json_ok<T: serde::Serialize>(value: T) -> Result<Json<T>, ApiError> {
    Ok(Json(value))
}

#[derive(Debug, Deserialize)]
struct UsersQuery {
    search: Option<String>,
    limit: Option<u32>,
    offset: Option<u64>,
}

#[derive(Debug, Deserialize)]
struct PageQuery {
    limit: Option<u32>,
    offset: Option<u64>,
}

#[derive(Debug, Deserialize)]
struct EventsQuery {
    actor: Option<Uuid>,
    action: Option<String>,
    target: Option<String>,
    from: Option<i64>,
    to: Option<i64>,
    limit: Option<u32>,
    cursor: Option<String>,
}

#[derive(Debug, Deserialize)]
struct RequestsQuery {
    open: Option<bool>,
}

impl CustomFieldRequest {
    /// What the admin typed, or why it is refused.
    fn into_input(self) -> Result<FieldInput, ApiError> {
        let field_type = FieldType::parse(&self.field_type)
            .ok_or_else(|| bad("type is text, hidden or checkbox"))?;
        Ok(FieldInput {
            name: self.name,
            field_type,
            kinds: self.kinds.into_kinds()?,
        })
    }
}

impl EventsQuery {
    fn filter(&self) -> Result<kemlock_app::admin::EventFilter, ApiError> {
        let from = self.from.map(|s| time_of(s, "from")).transpose()?;
        let to = self.to.map(|s| time_of(s, "to")).transpose()?;
        Ok(event_filter(
            self.actor,
            self.action.as_deref(),
            self.target.as_deref(),
            from,
            to,
        )?)
    }
}

// ---------------------------------------------------------------------------------------------
// Handlers

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
    // ---- who am I, step-up ----

    /// `GET /admin/v1/me`: the caller is an admin (anyone else gets 403), and how long a step-up
    /// token lasts.
    async fn me(caller: Caller) -> Result<Json<MeResponse>, ApiError> {
        json_ok(MeResponse {
            user_id: caller.actor.user.0,
            device_id: caller.actor.device.0,
            step_up_ttl_seconds: kemlock_app::admin::step_up::TOKEN_TTL.whole_seconds(),
        })
    }

    /// `POST /admin/v1/step-up/password/start`: the first message of the admin's own OPAQUE login,
    /// run again.
    async fn step_up_password_start(
        State(env): State<Self>,
        caller: Caller,
        body: Body,
    ) -> Result<Json<StepUpStartResponse>, ApiError> {
        let request: StepUpStartRequest = body.json()?;
        let now = env.now();
        env.api
            .limits
            .sign_in
            .check(&ip_key(caller.ip), now)
            .map_err(rate_limited)?;
        let started = env
            .step_up()
            .password_start(&caller.actor, &decode("request", &request.request)?)
            .await?;
        json_ok(StepUpStartResponse {
            response: b64url::encode(&started.response),
            login_state: b64url::encode(&started.login_state),
        })
    }

    /// `POST /admin/v1/step-up/password/finish`: the last message; a step-up token when the
    /// password was right. A wrong password counts against the account, as at sign-in.
    async fn step_up_password_finish(
        State(env): State<Self>,
        caller: Caller,
        body: Body,
    ) -> Result<Json<StepUpResponse>, ApiError> {
        let request: StepUpFinishRequest = body.json()?;
        let now = env.now();
        let account = format!("stepup:{}", caller.actor.user);
        // Reserved before the password is looked at, so parallel guesses can't all pass the limit.
        env.api
            .limits
            .account
            .reserve(&account, now)
            .map_err(rate_limited)?;
        let login_state = decode("loginState", &request.login_state)?;
        let finalization = decode("finalization", &request.finalization)?;
        let step_up = env.step_up();
        // A state belongs to the admin who started it; another admin finishing it burns nothing.
        // A genuine, fresh state finishes once, right or wrong, and only then is it remembered.
        if step_up.login_state_user(&login_state)? != caller.actor.user {
            return Err(AdminError::StepUpFailed.into());
        }
        match env.api.used_states.insert(&login_state, now) {
            Ok(true) => {}
            Ok(false) => return Err(bad("the login state was already used")),
            Err(Full) => return Err(ApiError(Problem::overloaded())),
        }
        let finished = step_up
            .password_finish(&caller.actor, &login_state, &finalization)
            .await;
        if finished.is_ok() {
            env.api.limits.account.clear(&account);
        }
        let issued = finished?;
        json_ok(StepUpResponse {
            token: issued.token,
            expires_at: issued.expires_at,
        })
    }

    /// `POST /admin/v1/step-up/totp`: a step-up token for a code from the authenticator app. Wrong
    /// codes count against the account together with sign-in's (5 in 15 minutes).
    async fn step_up_totp(
        State(env): State<Self>,
        caller: Caller,
        body: Body,
    ) -> Result<Json<StepUpResponse>, ApiError> {
        let request: StepUpTotpRequest = body.json()?;
        let now = env.now();
        env.api
            .limits
            .sign_in
            .check(&ip_key(caller.ip), now)
            .map_err(rate_limited)?;
        // Reserved before the code is looked at, so parallel guesses can't all pass the limit,
        // and in the store, from the budget the account's sign-in second step spends too.
        reserve_second_step(&env.api, caller.actor.user, now).await?;
        let finished = env.step_up().totp(&caller.actor, &request.code).await;
        if finished.is_ok() {
            forget_second_step(&env.api, caller.actor.user).await;
        }
        let issued = finished?;
        json_ok(StepUpResponse {
            token: issued.token,
            expires_at: issued.expires_at,
        })
    }

    /// `POST /admin/v1/step-up/passkey/options`: the options for an assertion over the admin's own
    /// passkeys (user verification required) and security keys, and the sealed challenge.
    async fn step_up_passkey_options(
        State(env): State<Self>,
        caller: Caller,
    ) -> Result<Json<StepUpPasskeyOptionsResponse>, ApiError> {
        env.api
            .limits
            .sign_in
            .check(&ip_key(caller.ip), env.now())
            .map_err(rate_limited)?;
        let started = env.passkey_stepper()?.options(&caller.actor).await?;
        json_ok(StepUpPasskeyOptionsResponse {
            options: started.options,
            challenge: b64url::encode(&started.challenge),
        })
    }

    /// `POST /admin/v1/step-up/passkey/finish`: the authenticator's answer, for a step-up token.
    /// A challenge is good once, right answer or wrong. Wrong answers count against the account
    /// together with wrong codes (5 in 15 minutes).
    async fn step_up_passkey_finish(
        State(env): State<Self>,
        caller: Caller,
        body: Body,
    ) -> Result<Json<StepUpResponse>, ApiError> {
        let request: StepUpPasskeyRequest = body.json()?;
        let now = env.now();
        env.api
            .limits
            .sign_in
            .check(&ip_key(caller.ip), now)
            .map_err(rate_limited)?;
        // Reserved before the answer is looked at, so parallel guesses can't all pass the limit,
        // and in the store, from the budget the account's sign-in second step spends too.
        reserve_second_step(&env.api, caller.actor.user, now).await?;
        let stepper = env.passkey_stepper()?;
        let challenge = decode("challenge", &request.challenge)?;
        let response = serde_json::to_vec(&request.credential)
            .map_err(|_| bad("the credential can't be read"))?;
        // Only a genuine, fresh challenge for this admin and device is remembered as used, so
        // made-up ones take no room.
        stepper.check_challenge(&caller.actor, &challenge)?;
        match env.api.used_states.insert(&challenge, now) {
            Ok(true) => {}
            Ok(false) => return Err(bad("the passkey challenge was already used")),
            Err(Full) => return Err(ApiError(Problem::overloaded())),
        }
        let finished = stepper.finish(&caller.actor, &challenge, &response).await;
        if finished.is_ok() {
            forget_second_step(&env.api, caller.actor.user).await;
        }
        let issued = finished?;
        json_ok(StepUpResponse {
            token: issued.token,
            expires_at: issued.expires_at,
        })
    }

    // ---- overview ----

    /// `GET /admin/v1/overview`.
    async fn overview(
        State(env): State<Self>,
        _caller: Caller,
    ) -> Result<Json<OverviewDto>, ApiError> {
        json_ok(OverviewDto::from(env.overview_case().execute().await?))
    }

    // ---- users ----

    /// `GET /admin/v1/users?search&limit&offset`.
    async fn users_list(
        State(env): State<Self>,
        _caller: Caller,
        parsed: Result<Query<UsersQuery>, QueryRejection>,
    ) -> Result<Json<UsersPageDto>, ApiError> {
        let q = query(parsed)?;
        let page = env
            .users()
            .list(UserQuery {
                search: q.search,
                limit: q.limit.unwrap_or(50),
                offset: q.offset.unwrap_or(0),
            })
            .await?;
        json_ok(UsersPageDto {
            users: page.users.iter().map(AdminUserDto::from).collect(),
            total: page.total,
        })
    }

    /// `POST /admin/v1/users/{id}/sign-out`: ends every session of the account.
    async fn user_sign_out(
        State(env): State<Self>,
        writer: Writer,
        Path(id): Path<String>,
    ) -> Result<StatusCode, ApiError> {
        env.users()
            .sign_out(&writer.actor, Some(writer.ip), UserId(uuid(&id)?))
            .await?;
        Ok(StatusCode::NO_CONTENT)
    }

    /// `POST /admin/v1/users/{id}/disable`.
    async fn user_disable(
        State(env): State<Self>,
        writer: Writer,
        Path(id): Path<String>,
    ) -> Result<StatusCode, ApiError> {
        env.users()
            .disable(&writer.actor, Some(writer.ip), UserId(uuid(&id)?))
            .await?;
        Ok(StatusCode::NO_CONTENT)
    }

    /// `POST /admin/v1/users/{id}/enable`.
    async fn user_enable(
        State(env): State<Self>,
        writer: Writer,
        Path(id): Path<String>,
    ) -> Result<StatusCode, ApiError> {
        env.users()
            .enable(&writer.actor, Some(writer.ip), UserId(uuid(&id)?))
            .await?;
        Ok(StatusCode::NO_CONTENT)
    }

    /// `POST /admin/v1/users/{id}/cancel-erasure`: the account's owner deleted it and its grace
    /// period is running; this takes it off the schedule. Nothing else cancels it: signing in is
    /// refused while it is pending.
    async fn user_cancel_erasure(
        State(env): State<Self>,
        writer: Writer,
        Path(id): Path<String>,
    ) -> Result<StatusCode, ApiError> {
        env.users()
            .cancel_erasure(&writer.actor, Some(writer.ip), UserId(uuid(&id)?))
            .await?;
        Ok(StatusCode::NO_CONTENT)
    }

    /// `POST /admin/v1/users/{id}/reset-two-step`.
    async fn user_reset_two_step(
        State(env): State<Self>,
        writer: Writer,
        Path(id): Path<String>,
    ) -> Result<StatusCode, ApiError> {
        env.users()
            .reset_two_step(&writer.actor, Some(writer.ip), UserId(uuid(&id)?))
            .await?;
        Ok(StatusCode::NO_CONTENT)
    }

    /// `DELETE /admin/v1/users/{id}`.
    async fn user_delete(
        State(env): State<Self>,
        writer: Writer,
        Path(id): Path<String>,
    ) -> Result<StatusCode, ApiError> {
        env.users()
            .delete(&writer.actor, Some(writer.ip), UserId(uuid(&id)?))
            .await?;
        Ok(StatusCode::NO_CONTENT)
    }

    // ---- invitations ----

    /// `GET /admin/v1/invitations`.
    async fn invites_list(
        State(env): State<Self>,
        _caller: Caller,
    ) -> Result<Json<Vec<InviteDto>>, ApiError> {
        let now = env.now();
        let invites = env.users().invites().await?;
        json_ok(invites.iter().map(|i| InviteDto::new(i, now)).collect())
    }

    /// `POST /admin/v1/invitations`.
    async fn invite_create(
        State(env): State<Self>,
        writer: Writer,
        body: Body,
    ) -> Result<(StatusCode, Json<InviteIssuedDto>), ApiError> {
        let request: InviteRequest = body.json()?;
        let issued = env
            .users()
            .invite(&writer.actor, Some(writer.ip), &request.email)
            .await?;
        Ok((
            StatusCode::CREATED,
            Json(InviteIssuedDto::new(&issued, env.now())),
        ))
    }

    /// `POST /admin/v1/invitations/{id}/resend`.
    async fn invite_resend(
        State(env): State<Self>,
        writer: Writer,
        Path(id): Path<String>,
    ) -> Result<Json<InviteIssuedDto>, ApiError> {
        let issued = env
            .users()
            .resend(&writer.actor, Some(writer.ip), uuid(&id)?)
            .await?;
        json_ok(InviteIssuedDto::new(&issued, env.now()))
    }

    /// `DELETE /admin/v1/invitations/{id}`.
    async fn invite_revoke(
        State(env): State<Self>,
        writer: Writer,
        Path(id): Path<String>,
    ) -> Result<StatusCode, ApiError> {
        env.users()
            .revoke_invite(&writer.actor, Some(writer.ip), uuid(&id)?)
            .await?;
        Ok(StatusCode::NO_CONTENT)
    }

    // ---- spaces ----

    /// `GET /admin/v1/spaces?limit&offset`.
    async fn spaces_list(
        State(env): State<Self>,
        _caller: Caller,
        parsed: Result<Query<PageQuery>, QueryRejection>,
    ) -> Result<Json<SpacesPageDto>, ApiError> {
        let q = query(parsed)?;
        let page = env
            .spaces()
            .list(q.limit.unwrap_or(50), q.offset.unwrap_or(0))
            .await?;
        json_ok(SpacesPageDto {
            spaces: page.spaces.iter().map(AdminSpaceDto::from).collect(),
            total: page.total,
        })
    }

    /// `GET /admin/v1/spaces/{id}`.
    async fn space_get(
        State(env): State<Self>,
        _caller: Caller,
        Path(id): Path<String>,
    ) -> Result<Json<AdminSpaceDto>, ApiError> {
        let row = env.spaces().get(SpaceId(uuid(&id)?)).await?;
        json_ok(AdminSpaceDto::from(&row))
    }

    /// `PUT /admin/v1/spaces/{id}/owner`: the new owner must be a confirmed member.
    async fn space_change_owner(
        State(env): State<Self>,
        writer: Writer,
        Path(id): Path<String>,
        body: Body,
    ) -> Result<Json<AdminSpaceDto>, ApiError> {
        let request: ChangeOwnerRequest = body.json()?;
        let row = env
            .spaces()
            .change_owner(
                &writer.actor,
                Some(writer.ip),
                SpaceId(uuid(&id)?),
                UserId(request.new_owner),
                request.demote_previous,
            )
            .await?;
        json_ok(AdminSpaceDto::from(&row))
    }

    /// `GET /admin/v1/spaces/{id}/members/{user}/invite-link`: the link that accepts a member's
    /// invitation to a Bitwarden organization, for a server that can't mail it. Whoever opens it
    /// accepts for that account, so it needs a fresh step-up like a write, is recorded in the
    /// event log and is never cached.
    async fn space_invite_link(
        State(env): State<Self>,
        writer: Writer,
        links: MaybeInviteLinks,
        Path((id, user)): Path<(String, String)>,
    ) -> Result<([(header::HeaderName, &'static str); 1], Json<InviteLinkDto>), ApiError> {
        let links = links.0.ok_or(AdminError::NotConfigured(
            "the Bitwarden API isn't running on this server",
        ))?;
        let link = env
            .spaces()
            .invite_link(
                &*links,
                &writer.actor,
                Some(writer.ip),
                SpaceId(uuid(&id)?),
                UserId(uuid(&user)?),
            )
            .await?;
        Ok((
            [(header::CACHE_CONTROL, "no-store")],
            Json(InviteLinkDto {
                link: link.link,
                expires_at: link.expires_at,
            }),
        ))
    }

    // ---- custom fields ----

    /// `GET /admin/v1/custom-fields`: the fields and the switch, as clients read them.
    async fn custom_fields_list(
        State(env): State<Self>,
        _caller: Caller,
    ) -> Result<Json<CustomFieldsDto>, ApiError> {
        let definitions = env.custom_fields().list().await?;
        json_ok(CustomFieldsDto::from_definitions(&definitions))
    }

    /// `POST /admin/v1/custom-fields`: adds a field. A name another field has is a 409.
    async fn custom_field_create(
        State(env): State<Self>,
        writer: Writer,
        body: Body,
    ) -> Result<(StatusCode, Json<CustomFieldDto>), ApiError> {
        let request: CustomFieldRequest = body.json()?;
        let field = env
            .custom_fields()
            .create(&writer.actor, Some(writer.ip), request.into_input()?)
            .await?;
        Ok((
            StatusCode::CREATED,
            Json(CustomFieldDto::from_field(&field)),
        ))
    }

    /// `PUT /admin/v1/custom-fields/{id}`: changes a field's name, type and kinds.
    async fn custom_field_update(
        State(env): State<Self>,
        writer: Writer,
        Path(id): Path<String>,
        body: Body,
    ) -> Result<Json<CustomFieldDto>, ApiError> {
        let request: CustomFieldRequest = body.json()?;
        let field = env
            .custom_fields()
            .update(
                &writer.actor,
                Some(writer.ip),
                CustomFieldId(uuid(&id)?),
                request.into_input()?,
            )
            .await?;
        json_ok(CustomFieldDto::from_field(&field))
    }

    /// `DELETE /admin/v1/custom-fields/{id}`.
    async fn custom_field_delete(
        State(env): State<Self>,
        writer: Writer,
        Path(id): Path<String>,
    ) -> Result<StatusCode, ApiError> {
        env.custom_fields()
            .delete(&writer.actor, Some(writer.ip), CustomFieldId(uuid(&id)?))
            .await?;
        Ok(StatusCode::NO_CONTENT)
    }

    /// `PUT /admin/v1/custom-fields/allow-own`: whether people may add fields of their own.
    async fn custom_fields_allow_own(
        State(env): State<Self>,
        writer: Writer,
        body: Body,
    ) -> Result<Json<AllowOwnDto>, ApiError> {
        let request: AllowOwnRequest = body.json()?;
        let allow_own = env
            .custom_fields()
            .set_allow_own(&writer.actor, Some(writer.ip), request.allow)
            .await?;
        json_ok(AllowOwnDto { allow_own })
    }

    // ---- events ----

    /// `GET /admin/v1/events`: filters `actor`, `action` (a name, or a prefix ending in `*`),
    /// `target`, `from` and `to` (Unix seconds), pages by `limit` and `cursor`.
    async fn events_list(
        State(env): State<Self>,
        _caller: Caller,
        parsed: Result<Query<EventsQuery>, QueryRejection>,
    ) -> Result<Json<EventsPageDto>, ApiError> {
        let q = query(parsed)?;
        let filter = q.filter()?;
        let after = q.cursor.as_deref().map(parse_cursor).transpose()?;
        let page = env
            .events()
            .page(&filter, after.as_ref(), q.limit.unwrap_or(50))
            .await?;
        json_ok(EventsPageDto {
            events: page.events.iter().map(EventDto::from).collect(),
            next: page.next.as_ref().map(cursor_text),
        })
    }

    /// `GET /admin/v1/events.csv`: the same filters, as CSV (at most 100,000 rows; the
    /// `X-Export-Truncated` header says when it was cut short). An export is a write for the
    /// step-up check, and is recorded.
    async fn events_csv(
        State(env): State<Self>,
        writer: Writer,
        parsed: Result<Query<EventsQuery>, QueryRejection>,
    ) -> Result<Response, ApiError> {
        let q = query(parsed)?;
        let filter = q.filter()?;
        let (csv, truncated) = env.events().export_csv(&filter).await?;
        env.audit()
            .record(
                &writer.actor,
                Some(writer.ip),
                "admin.events.export",
                None,
                "exported the event log",
            )
            .await;
        let mut response = Response::new(HttpBody::from(csv));
        let headers = response.headers_mut();
        headers.insert(
            header::CONTENT_TYPE,
            HeaderValue::from_static("text/csv; charset=utf-8"),
        );
        headers.insert(
            header::CONTENT_DISPOSITION,
            HeaderValue::from_static("attachment; filename=\"kemlock-events.csv\""),
        );
        headers.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
        if truncated {
            headers.insert(
                HeaderName::from_static("x-export-truncated"),
                HeaderValue::from_static("true"),
            );
        }
        Ok(response)
    }

    // ---- settings ----

    /// `GET /admin/v1/settings`.
    async fn settings_get(
        State(env): State<Self>,
        _caller: Caller,
    ) -> Result<Json<SettingsResponse>, ApiError> {
        let views = env.settings().list().await?;
        json_ok(SettingsResponse {
            settings: views.iter().map(SettingDto::from).collect(),
        })
    }

    /// `PUT /admin/v1/settings`.
    async fn settings_put(
        State(env): State<Self>,
        writer: Writer,
        body: Body,
    ) -> Result<Json<SettingsResponse>, ApiError> {
        let request: SettingsRequest = body.json()?;
        if request.changes.is_empty() || request.changes.len() > 64 {
            return Err(bad("changes must hold 1 to 64 settings"));
        }
        let changes: BTreeMap<String, Change> = request
            .changes
            .into_iter()
            .map(|(key, value)| {
                (
                    key,
                    match value {
                        Some(v) => Change::Set(v),
                        None => Change::Reset,
                    },
                )
            })
            .collect();
        let settings = env.settings();
        settings.apply(&changes).await?;
        // This replica re-reads at once; the others at their next poll.
        if let Some(saved) = &env.rt.settings_saved {
            saved();
        }
        // The names only: a value may be a secret.
        let names: Vec<&str> = changes.keys().map(String::as_str).collect();
        env.audit()
            .record(
                &writer.actor,
                Some(writer.ip),
                "admin.settings.update",
                Some(names.join(",")),
                "changed the server settings",
            )
            .await;
        let views = settings.list().await?;
        json_ok(SettingsResponse {
            settings: views.iter().map(SettingDto::from).collect(),
        })
    }

    // ---- SSO ----

    /// `GET /admin/v1/sso`.
    async fn sso_get(State(env): State<Self>, _caller: Caller) -> Result<Json<SsoDto>, ApiError> {
        json_ok(SsoDto::from(&env.sso_admin().get().await?))
    }

    /// `PUT /admin/v1/sso`.
    async fn sso_put(
        State(env): State<Self>,
        writer: Writer,
        body: Body,
    ) -> Result<Json<SsoDto>, ApiError> {
        let request: SsoRequest = body.json()?;
        let group_rules = request
            .group_rules
            .iter()
            .map(GroupRuleDto::to_rule)
            .collect::<Result<Vec<_>, String>>()
            .map_err(bad)?;
        let client_secret = match (request.client_secret, request.clear_client_secret) {
            (Some(secret), _) => SecretChange::Set(secret),
            (None, true) => SecretChange::Clear,
            (None, false) => SecretChange::Keep,
        };
        let view = env
            .sso_admin()
            .put(
                &writer.actor,
                Some(writer.ip),
                SsoInput {
                    enabled: request.enabled,
                    display_name: request.display_name,
                    issuer: request.issuer,
                    client_id: request.client_id,
                    client_secret,
                    scopes: request.scopes,
                    allow_unknown_email_verification: request.allow_unknown_email_verification,
                    link_by_email: request.link_by_email,
                    create_accounts: request.create_accounts,
                    require_verified_domain: request.require_verified_domain,
                    group_rules,
                },
            )
            .await?;
        json_ok(SsoDto::from(&view))
    }

    /// `GET /admin/v1/sso/domains`.
    async fn sso_domains(
        State(env): State<Self>,
        _caller: Caller,
    ) -> Result<Json<Vec<DomainDto>>, ApiError> {
        let domains = env.sso_admin().domains().await?;
        json_ok(domains.iter().map(DomainDto::from).collect())
    }

    /// `POST /admin/v1/sso/domains`: claims a domain, or returns the claim that is there.
    async fn sso_domain_add(
        State(env): State<Self>,
        writer: Writer,
        body: Body,
    ) -> Result<(StatusCode, Json<DomainDto>), ApiError> {
        let request: DomainRequest = body.json()?;
        let claim = env
            .sso_admin()
            .add_domain(&writer.actor, Some(writer.ip), &request.domain)
            .await?;
        Ok((StatusCode::CREATED, Json(DomainDto::from(&claim))))
    }

    /// `POST /admin/v1/sso/domains/{domain}/verify`: looks for the DNS record; 409 until it is
    /// there.
    async fn sso_domain_verify(
        State(env): State<Self>,
        writer: Writer,
        Path(domain): Path<String>,
    ) -> Result<Json<DomainDto>, ApiError> {
        let claim = env
            .sso_admin()
            .check_domain(&writer.actor, Some(writer.ip), &domain)
            .await?;
        json_ok(DomainDto::from(&claim))
    }

    /// `DELETE /admin/v1/sso/domains/{domain}`.
    async fn sso_domain_remove(
        State(env): State<Self>,
        writer: Writer,
        Path(domain): Path<String>,
    ) -> Result<StatusCode, ApiError> {
        env.sso_admin()
            .remove_domain(&writer.actor, Some(writer.ip), &domain)
            .await?;
        Ok(StatusCode::NO_CONTENT)
    }

    // ---- migration ----

    /// `GET /admin/v1/migration`.
    async fn migration_status(
        State(env): State<Self>,
        _caller: Caller,
    ) -> Result<Json<MigrationDto>, ApiError> {
        json_ok(MigrationDto::from(&env.migration().status().await?))
    }

    /// `POST /admin/v1/migration/start`: starts the move from Vaultwarden in the background and
    /// answers 202 with the status (running). `GET /admin/v1/migration` shows its stage while it
    /// runs and its result when it ends. 409 when a move is already running.
    async fn migration_start(
        State(env): State<Self>,
        writer: Writer,
        body: Body,
    ) -> Result<(StatusCode, Json<MigrationDto>), ApiError> {
        let request: MigrationStartRequest = body.json()?;
        if !migrate::text_ok(&request.from)
            || request
                .files
                .as_deref()
                .is_some_and(|f| !migrate::text_ok(f))
        {
            return Err(bad(
                "from and files must be short text with no control characters",
            ));
        }
        let status = env
            .migration_runner()?
            .start(MigrationRequest {
                from: request.from.trim().to_owned(),
                files: request.files.map(|f| f.trim().to_owned()),
                by: writer.actor.user,
            })
            .await?;
        env.audit()
            .record(
                &writer.actor,
                Some(writer.ip),
                "admin.migration.start",
                status.source.clone(),
                "started moving a Vaultwarden server's data in",
            )
            .await;
        Ok((StatusCode::ACCEPTED, Json(MigrationDto::from(&status))))
    }

    // ---- address ----

    /// `GET /admin/v1/server-address`: the address in use next to the one recorded at setup.
    async fn server_address(
        State(env): State<Self>,
        _caller: Caller,
    ) -> Result<Json<ServerAddressDto>, ApiError> {
        let recorded = kemlock_app::admin::SettingsRepo::settings_with_prefix(
            &env.rt.repos,
            kemlock_app::RECORDED_DOMAIN_KEY,
        )
        .await?
        .into_iter()
        .find(|(key, _)| key == kemlock_app::RECORDED_DOMAIN_KEY)
        .map(|(_, value)| value);
        let domain = env.api.config.domain.clone();
        let differs = recorded.as_deref().is_some_and(|r| {
            !r.trim_end_matches('/')
                .eq_ignore_ascii_case(domain.trim_end_matches('/'))
        });
        json_ok(ServerAddressDto {
            domain,
            recorded_domain: recorded,
            differs,
            data_folder: env.rt.data_folder.clone(),
        })
    }

    // ---- push relay ----

    /// The relay the console controls, or 409 when this server has none.
    fn push_relay(&self) -> Result<&Arc<dyn PushRelayControl>, ApiError> {
        self.rt.push_relay.as_ref().ok_or_else(|| {
            AdminError::NotConfigured("this server has no push relay to turn on or off").into()
        })
    }

    /// `GET /admin/v1/push-relay`. A server with no relay wired in reports it as off, so a read
    /// answers; only turning it on or off is refused.
    async fn push_relay_get(
        State(env): State<Self>,
        _caller: Caller,
    ) -> Result<Json<PushRelayDto>, ApiError> {
        let Some(relay) = env.rt.push_relay.as_ref() else {
            return json_ok(PushRelayDto {
                enabled: false,
                installation_id: None,
                relay_url: DEFAULT_PUSH_RELAY_URL.to_owned(),
                apns_configured: false,
                apns_sandbox: false,
                unified_push: true,
            });
        };
        let status = relay.status().await?;
        json_ok(PushRelayDto::from(&status))
    }

    /// `POST /admin/v1/push-relay/enable`: registers this server with the relay.
    async fn push_relay_enable(
        State(env): State<Self>,
        writer: Writer,
    ) -> Result<Json<PushRelayDto>, ApiError> {
        let status = env.push_relay()?.enable().await?;
        env.audit()
            .record(
                &writer.actor,
                Some(writer.ip),
                "admin.push-relay.enable",
                status.installation_id.clone(),
                "turned the push relay on",
            )
            .await;
        json_ok(PushRelayDto::from(&status))
    }

    /// `POST /admin/v1/push-relay/disable`: erases the installation at the relay and here.
    async fn push_relay_disable(
        State(env): State<Self>,
        writer: Writer,
    ) -> Result<Json<PushRelayDto>, ApiError> {
        let status = env.push_relay()?.disable().await?;
        // Switched off here, it stays off after a restart: the saved switch is cleared, unless the
        // environment sets it (then it is the operator's to change).
        let mut forget = BTreeMap::new();
        forget.insert("kemlock_push_relay".to_owned(), Change::Reset);
        if env.settings().apply(&forget).await.is_ok()
            && let Some(saved) = &env.rt.settings_saved
        {
            saved();
        }
        env.audit()
            .record(
                &writer.actor,
                Some(writer.ip),
                "admin.push-relay.disable",
                None,
                "turned the push relay off",
            )
            .await;
        json_ok(PushRelayDto::from(&status))
    }

    // ---- compliance ----

    /// `GET /admin/v1/compliance/requests?open`.
    async fn compliance_list(
        State(env): State<Self>,
        _caller: Caller,
        parsed: Result<Query<RequestsQuery>, QueryRejection>,
    ) -> Result<Json<ComplianceListDto>, ApiError> {
        let q = query(parsed)?;
        let now = env.now();
        let requests = env.compliance().list(q.open.unwrap_or(true)).await?;
        json_ok(ComplianceListDto {
            requests: requests
                .iter()
                .map(|r| ComplianceRequestDto::new(r, now))
                .collect(),
        })
    }

    /// `POST /admin/v1/compliance/requests`: logs a request that arrived.
    async fn compliance_log(
        State(env): State<Self>,
        writer: Writer,
        body: Body,
    ) -> Result<(StatusCode, Json<ComplianceRequestDto>), ApiError> {
        let request: LogRequestRequest = body.json()?;
        let kind = RequestKind::parse(&request.kind)
            .ok_or_else(|| bad("kind must be access, erasure, correction, opt-out or other"))?;
        let logged = env
            .compliance()
            .log(
                &writer.actor,
                Some(writer.ip),
                NewRequest {
                    kind,
                    requester: request.requester,
                    user: request.user_id.map(UserId),
                    received_at: request
                        .received_at
                        .map(|s| time_of(s, "receivedAt"))
                        .transpose()?,
                    due_at: request.due_at.map(|s| time_of(s, "dueAt")).transpose()?,
                    note: request.note,
                },
            )
            .await?;
        Ok((
            StatusCode::CREATED,
            Json(ComplianceRequestDto::new(&logged, env.now())),
        ))
    }

    /// `PATCH /admin/v1/compliance/requests/{id}`: answer, close, reopen or extend.
    async fn compliance_update(
        State(env): State<Self>,
        writer: Writer,
        Path(id): Path<String>,
        body: Body,
    ) -> Result<Json<ComplianceRequestDto>, ApiError> {
        let request: UpdateRequestRequest = body.json()?;
        let status = request
            .status
            .as_deref()
            .map(|s| {
                RequestStatus::parse(s)
                    .ok_or_else(|| bad("status must be open, in-progress, done or rejected"))
            })
            .transpose()?;
        let updated = env
            .compliance()
            .update(
                &writer.actor,
                Some(writer.ip),
                uuid(&id)?,
                RequestUpdate {
                    status,
                    note: request.note,
                    extend: request.extend,
                },
            )
            .await?;
        json_ok(ComplianceRequestDto::new(&updated, env.now()))
    }
}

// ---------------------------------------------------------------------------------------------
// The router

/// The same `DPoP-Nonce` header every `/kem/v1` response carries.
#[allow(
    clippy::type_complexity,
    reason = "the state names every port the admin routes use"
)]
async fn nonce_header<S, P, K, R, Sp, So, D, M>(
    State(env): State<Env<S, P, K, R, Sp, So, D, M>>,
    request: Request,
    next: Next,
) -> Response
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
    let mut response = next.run(request).await;
    let now = env.api.crypto.now().unix_timestamp();
    if let Ok(value) = HeaderValue::from_str(&env.api.dpop.current_nonce(now)) {
        response.headers_mut().insert(DPOP_NONCE, value);
    }
    response
}

/// `GET /admin/v1/openapi.json`: the contract, public like `/kem/v1/openapi.json`.
async fn openapi_json() -> Response {
    Json(crate::openapi::openapi()).into_response()
}

/// The `/admin/v1` router. Merge it into the server's router beside `/kem/v1`:
///
/// ```ignore
/// router.merge(admin_router(api.clone(), AdminRuntime::new(store, store, store, dns, mail, env)))
/// ```
///
/// Every route but the OpenAPI document needs an admin's DPoP-bound access token; every write
/// also needs a step-up token (see `step_up`). It has no fallback, so merging keeps the main
/// router's.
pub fn admin_router<S, P, K, R, Sp, So, D, M>(
    api: Api<S, P, K>,
    runtime: AdminRuntime<R, Sp, So, D, M>,
) -> Router
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
    macro_rules! h {
        ($name:ident) => {
            Env::<S, P, K, R, Sp, So, D, M>::$name
        };
    }
    let env = Env {
        api,
        rt: Arc::new(runtime),
    };
    Router::new()
        .route("/admin/v1/openapi.json", get(openapi_json))
        .route("/admin/v1/me", get(h!(me)))
        .route(
            "/admin/v1/step-up/password/start",
            post(h!(step_up_password_start)),
        )
        .route(
            "/admin/v1/step-up/password/finish",
            post(h!(step_up_password_finish)),
        )
        .route("/admin/v1/step-up/totp", post(h!(step_up_totp)))
        .route(
            "/admin/v1/step-up/passkey/options",
            post(h!(step_up_passkey_options)),
        )
        .route(
            "/admin/v1/step-up/passkey/finish",
            post(h!(step_up_passkey_finish)),
        )
        .route("/admin/v1/overview", get(h!(overview)))
        .route("/admin/v1/users", get(h!(users_list)))
        .route("/admin/v1/users/{id}", delete(h!(user_delete)))
        .route("/admin/v1/users/{id}/sign-out", post(h!(user_sign_out)))
        .route("/admin/v1/users/{id}/disable", post(h!(user_disable)))
        .route("/admin/v1/users/{id}/enable", post(h!(user_enable)))
        .route(
            "/admin/v1/users/{id}/cancel-erasure",
            post(h!(user_cancel_erasure)),
        )
        .route(
            "/admin/v1/users/{id}/reset-two-step",
            post(h!(user_reset_two_step)),
        )
        .route(
            "/admin/v1/invitations",
            get(h!(invites_list)).post(h!(invite_create)),
        )
        .route("/admin/v1/invitations/{id}", delete(h!(invite_revoke)))
        .route("/admin/v1/invitations/{id}/resend", post(h!(invite_resend)))
        .route("/admin/v1/spaces", get(h!(spaces_list)))
        .route("/admin/v1/spaces/{id}", get(h!(space_get)))
        .route("/admin/v1/spaces/{id}/owner", put(h!(space_change_owner)))
        .route(
            "/admin/v1/spaces/{id}/members/{user}/invite-link",
            get(h!(space_invite_link)),
        )
        .route(
            "/admin/v1/custom-fields",
            get(h!(custom_fields_list)).post(h!(custom_field_create)),
        )
        .route(
            "/admin/v1/custom-fields/allow-own",
            put(h!(custom_fields_allow_own)),
        )
        .route(
            "/admin/v1/custom-fields/{id}",
            put(h!(custom_field_update)).delete(h!(custom_field_delete)),
        )
        .route("/admin/v1/events", get(h!(events_list)))
        .route("/admin/v1/events.csv", get(h!(events_csv)))
        .route(
            "/admin/v1/settings",
            get(h!(settings_get)).put(h!(settings_put)),
        )
        .route("/admin/v1/sso", get(h!(sso_get)).put(h!(sso_put)))
        .route(
            "/admin/v1/sso/domains",
            get(h!(sso_domains)).post(h!(sso_domain_add)),
        )
        .route(
            "/admin/v1/sso/domains/{domain}",
            delete(h!(sso_domain_remove)),
        )
        .route(
            "/admin/v1/sso/domains/{domain}/verify",
            post(h!(sso_domain_verify)),
        )
        .route("/admin/v1/migration", get(h!(migration_status)))
        .route("/admin/v1/migration/start", post(h!(migration_start)))
        .route("/admin/v1/server-address", get(h!(server_address)))
        .route("/admin/v1/push-relay", get(h!(push_relay_get)))
        .route("/admin/v1/push-relay/enable", post(h!(push_relay_enable)))
        .route("/admin/v1/push-relay/disable", post(h!(push_relay_disable)))
        .route(
            "/admin/v1/compliance/requests",
            get(h!(compliance_list)).post(h!(compliance_log)),
        )
        .route(
            "/admin/v1/compliance/requests/{id}",
            axum::routing::patch(h!(compliance_update)),
        )
        .layer(middleware::from_fn_with_state(
            env.clone(),
            nonce_header::<S, P, K, R, Sp, So, D, M>,
        ))
        .with_state(env)
}
