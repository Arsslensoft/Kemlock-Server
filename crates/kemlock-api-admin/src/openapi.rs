//! The OpenAPI 3.1 document of `/admin/v1`, served at `/admin/v1/openapi.json`.
//!
//! The documented routes are stubs below, one per route, because the real handlers are generic
//! over the server's ports. A test checks that the router answers every path and method named
//! here, so the two can't drift apart.

use crate::dto::*;
use kemlock_api_kem::openapi::ProblemDoc;
use utoipa::openapi::security::{ApiKey, ApiKeyValue, SecurityScheme};
use utoipa::{Modify, OpenApi};

/// Adds the DPoP-bound access token as a security scheme.
#[derive(Debug)]
struct SecurityAddon;

impl Modify for SecurityAddon {
    fn modify(&self, openapi: &mut utoipa::openapi::OpenApi) {
        let components = openapi.components.get_or_insert_with(Default::default);
        let mut scheme = ApiKeyValue::new("Authorization");
        scheme.description = Some(
            "`Authorization: DPoP <access token>` of an account with the admin role and a \
             confirmed two-step method, with a `DPoP` header carrying a proof signed by the key \
             the token is bound to (RFC 9449). Anyone else gets 403."
                .to_owned(),
        );
        components.add_security_scheme("dpop", SecurityScheme::ApiKey(ApiKey::Header(scheme)));
    }
}

macro_rules! doc {
    ($name:ident, $($attr:tt)*) => {
        #[utoipa::path($($attr)*)]
        #[allow(dead_code)]
        fn $name() {}
    };
}

doc!(
    doc_openapi,
    get,
    path = "/admin/v1/openapi.json",
    tag = "server",
    responses((status = 200, description = "This document"))
);

doc!(
    doc_me,
    get,
    path = "/admin/v1/me",
    tag = "session",
    security(("dpop" = [])),
    responses(
        (
            status = 200,
            description = "The caller is an admin",
            body = MeResponse
        ),
        (
            status = 403,
            description = "Not an admin, or an admin without a confirmed two-step method",
            body = ProblemDoc,
            content_type = "application/problem+json"
        ),
    )
);

doc!(
    doc_step_up_password_start,
    post,
    path = "/admin/v1/step-up/password/start",
    tag = "session",
    security(("dpop" = [])),
    request_body = StepUpStartRequest,
    responses(
        (
            status = 200,
            description = "OPAQUE's response to the admin's login request",
            body = StepUpStartResponse
        ),
        (
            status = 429,
            description = "Too many tries",
            body = ProblemDoc,
            content_type = "application/problem+json"
        ),
    )
);

doc!(
    doc_step_up_password_finish,
    post,
    path = "/admin/v1/step-up/password/finish",
    tag = "session",
    security(("dpop" = [])),
    request_body = StepUpFinishRequest,
    responses(
        (
            status = 200,
            description = "The password was right: a step-up token",
            body = StepUpResponse
        ),
        (
            status = 403,
            description = "The password was wrong",
            body = ProblemDoc,
            content_type = "application/problem+json"
        ),
        (
            status = 429,
            description = "Too many wrong passwords",
            body = ProblemDoc,
            content_type = "application/problem+json"
        ),
    )
);

doc!(
    doc_step_up_totp,
    post,
    path = "/admin/v1/step-up/totp",
    tag = "session",
    security(("dpop" = [])),
    request_body = StepUpTotpRequest,
    responses(
        (
            status = 200,
            description = "The code was right: a step-up token",
            body = StepUpResponse
        ),
        (
            status = 403,
            description = "The code was wrong",
            body = ProblemDoc,
            content_type = "application/problem+json"
        ),
        (
            status = 429,
            description = "Too many wrong codes",
            body = ProblemDoc,
            content_type = "application/problem+json"
        ),
    )
);

doc!(
    doc_step_up_passkey_options,
    post,
    path = "/admin/v1/step-up/passkey/options",
    tag = "session",
    security(("dpop" = [])),
    responses(
        (
            status = 200,
            description = "The options for an assertion over the admin's own passkeys, and the \
                           sealed challenge",
            body = StepUpPasskeyOptionsResponse
        ),
        (
            status = 409,
            description = "The account has no passkey, or the server has no relying party",
            body = ProblemDoc,
            content_type = "application/problem+json"
        ),
        (
            status = 429,
            description = "Too many tries",
            body = ProblemDoc,
            content_type = "application/problem+json"
        ),
    )
);

doc!(
    doc_step_up_passkey_finish,
    post,
    path = "/admin/v1/step-up/passkey/finish",
    tag = "session",
    security(("dpop" = [])),
    request_body = StepUpPasskeyRequest,
    responses(
        (
            status = 200,
            description = "The assertion was right and verified the user: a step-up token",
            body = StepUpResponse
        ),
        (
            status = 403,
            description = "The assertion was wrong, unverified, or for another passkey",
            body = ProblemDoc,
            content_type = "application/problem+json"
        ),
        (
            status = 429,
            description = "Too many wrong answers",
            body = ProblemDoc,
            content_type = "application/problem+json"
        ),
    )
);

doc!(
    doc_overview,
    get,
    path = "/admin/v1/overview",
    tag = "overview",
    security(("dpop" = [])),
    responses((status = 200, description = "Counts", body = OverviewDto))
);

doc!(doc_users_list, get, path = "/admin/v1/users", tag = "users", security(("dpop" = [])),
    params(
        ("search" = Option<String>, Query, description = "Part of an email or name"),
        ("limit" = Option<u32>, Query, description = "At most 200; default 50"),
        ("offset" = Option<u64>, Query, description = "Accounts to skip"),
    ),
    responses((status = 200, description = "A page of accounts, by email", body = UsersPageDto)));

doc!(
    doc_user_delete,
    delete,
    path = "/admin/v1/users/{id}",
    tag = "users",
    security(("dpop" = [])),
    params(
        ("id" = String, Path, description = "The account's UUID"),
        (
            "Step-Up-Token" = String,
            Header,
            description = "A fresh step-up token"
        ),
    ),
    responses(
        (
            status = 204,
            description = "The account and its data are gone"
        ),
        (
            status = 403,
            description = "No fresh step-up token",
            body = ProblemDoc,
            content_type = "application/problem+json"
        ),
        (
            status = 409,
            description = "Your own account, the last admin, or the only owner of a space",
            body = ProblemDoc,
            content_type = "application/problem+json"
        ),
    )
);

doc!(
    doc_user_sign_out,
    post,
    path = "/admin/v1/users/{id}/sign-out",
    tag = "users",
    security(("dpop" = [])),
    params(
        ("id" = String, Path, description = "The account's UUID"),
        (
            "Step-Up-Token" = String,
            Header,
            description = "A fresh step-up token"
        ),
    ),
    responses((
        status = 204,
        description = "Every session of the account ended"
    ))
);

doc!(
    doc_user_disable,
    post,
    path = "/admin/v1/users/{id}/disable",
    tag = "users",
    security(("dpop" = [])),
    params(
        ("id" = String, Path, description = "The account's UUID"),
        (
            "Step-Up-Token" = String,
            Header,
            description = "A fresh step-up token"
        ),
    ),
    responses(
        (
            status = 204,
            description = "The account is disabled and signed out"
        ),
        (
            status = 409,
            description = "Your own account",
            body = ProblemDoc,
            content_type = "application/problem+json"
        ),
    )
);

doc!(
    doc_user_enable,
    post,
    path = "/admin/v1/users/{id}/enable",
    tag = "users",
    security(("dpop" = [])),
    params(
        ("id" = String, Path, description = "The account's UUID"),
        (
            "Step-Up-Token" = String,
            Header,
            description = "A fresh step-up token"
        ),
    ),
    responses((status = 204, description = "The account can sign in again"))
);

doc!(
    doc_user_cancel_erasure,
    post,
    path = "/admin/v1/users/{id}/cancel-erasure",
    tag = "users",
    security(("dpop" = [])),
    params(
        ("id" = String, Path, description = "The account's UUID"),
        (
            "Step-Up-Token" = String,
            Header,
            description = "A fresh step-up token"
        ),
    ),
    responses(
        (
            status = 204,
            description = "The pending deletion is cancelled; the account's owner signs in again"
        ),
        (
            status = 409,
            description = "No erasure is pending for this account",
            body = ProblemDoc,
            content_type = "application/problem+json"
        ),
    )
);

doc!(
    doc_user_reset_two_step,
    post,
    path = "/admin/v1/users/{id}/reset-two-step",
    tag = "users",
    security(("dpop" = [])),
    params(
        ("id" = String, Path, description = "The account's UUID"),
        (
            "Step-Up-Token" = String,
            Header,
            description = "A fresh step-up token"
        ),
    ),
    responses(
        (
            status = 204,
            description = "Its two-step methods are removed and its sessions ended"
        ),
        (
            status = 409,
            description = "Your own account",
            body = ProblemDoc,
            content_type = "application/problem+json"
        ),
    )
);

doc!(doc_invites_list, get, path = "/admin/v1/invitations", tag = "users", security(("dpop" = [])),
    responses((status = 200, description = "Every invitation, newest first", body = Vec<InviteDto>)));

doc!(
    doc_invite_create,
    post,
    path = "/admin/v1/invitations",
    tag = "users",
    security(("dpop" = [])),
    params((
        "Step-Up-Token" = String,
        Header,
        description = "A fresh step-up token"
    )),
    request_body = InviteRequest,
    responses(
        (
            status = 201,
            description = "The invitation, with the link that accepts it",
            body = InviteIssuedDto
        ),
        (
            status = 409,
            description = "An account or a pending invitation exists for that email",
            body = ProblemDoc,
            content_type = "application/problem+json"
        ),
    )
);

doc!(
    doc_invite_resend,
    post,
    path = "/admin/v1/invitations/{id}/resend",
    tag = "users",
    security(("dpop" = [])),
    params(
        ("id" = String, Path, description = "The invitation's UUID"),
        (
            "Step-Up-Token" = String,
            Header,
            description = "A fresh step-up token"
        ),
    ),
    responses((
        status = 200,
        description = "Sent again with a new link and a new week",
        body = InviteIssuedDto
    ))
);

doc!(
    doc_invite_revoke,
    delete,
    path = "/admin/v1/invitations/{id}",
    tag = "users",
    security(("dpop" = [])),
    params(
        ("id" = String, Path, description = "The invitation's UUID"),
        (
            "Step-Up-Token" = String,
            Header,
            description = "A fresh step-up token"
        ),
    ),
    responses((status = 204, description = "The invitation is revoked"))
);

doc!(doc_spaces_list, get, path = "/admin/v1/spaces", tag = "spaces", security(("dpop" = [])),
    params(
        ("limit" = Option<u32>, Query, description = "At most 200; default 50"),
        ("offset" = Option<u64>, Query, description = "Spaces to skip"),
    ),
    responses((status = 200, description = "A page of spaces, oldest first", body = SpacesPageDto)));

doc!(
    doc_space_get,
    get,
    path = "/admin/v1/spaces/{id}",
    tag = "spaces",
    security(("dpop" = [])),
    params(("id" = String, Path, description = "The space's UUID")),
    responses((
        status = 200,
        description = "The space",
        body = AdminSpaceDto
    ))
);

doc!(
    doc_space_change_owner,
    put,
    path = "/admin/v1/spaces/{id}/owner",
    tag = "spaces",
    security(("dpop" = [])),
    params(
        ("id" = String, Path, description = "The space's UUID"),
        (
            "Step-Up-Token" = String,
            Header,
            description = "A fresh step-up token"
        ),
    ),
    request_body = ChangeOwnerRequest,
    responses(
        (
            status = 200,
            description = "The space after the change",
            body = AdminSpaceDto
        ),
        (
            status = 409,
            description = "The new owner isn't a confirmed member, or already owns it",
            body = ProblemDoc,
            content_type = "application/problem+json"
        ),
    )
);

doc!(doc_events_list, get, path = "/admin/v1/events", tag = "events", security(("dpop" = [])),
    params(
        ("actor" = Option<String>, Query, description = "An account's UUID"),
        ("action" = Option<String>, Query, description = "An action, or a prefix ending in `*`"),
        ("target" = Option<String>, Query, description = "Text the target contains"),
        ("from" = Option<i64>, Query, description = "Unix seconds"),
        ("to" = Option<i64>, Query, description = "Unix seconds"),
        ("limit" = Option<u32>, Query, description = "At most 200; default 50"),
        ("cursor" = Option<String>, Query, description = "`next` of the previous page"),
    ),
    responses((status = 200, description = "Events, newest first; addresses cut to /24 or /48", body = EventsPageDto)));

doc!(doc_events_csv, get, path = "/admin/v1/events.csv", tag = "events", security(("dpop" = [])),
    params(
        ("actor" = Option<String>, Query, description = "An account's UUID"),
        ("action" = Option<String>, Query, description = "An action, or a prefix ending in `*`"),
        ("target" = Option<String>, Query, description = "Text the target contains"),
        ("from" = Option<i64>, Query, description = "Unix seconds"),
        ("to" = Option<i64>, Query, description = "Unix seconds"),
        ("Step-Up-Token" = String, Header, description = "A fresh step-up token"),
    ),
    responses((status = 200, description = "At most 100,000 rows; `X-Export-Truncated: true` when cut short", content_type = "text/csv", body = String)));

doc!(
    doc_settings_get,
    get,
    path = "/admin/v1/settings",
    tag = "settings",
    security(("dpop" = [])),
    responses((
        status = 200,
        description = "Every setting with its source; secrets only say whether they are set",
        body = SettingsResponse
    ))
);

doc!(
    doc_settings_put,
    put,
    path = "/admin/v1/settings",
    tag = "settings",
    security(("dpop" = [])),
    params((
        "Step-Up-Token" = String,
        Header,
        description = "A fresh step-up token"
    )),
    request_body = SettingsRequest,
    responses(
        (
            status = 200,
            description = "Every setting after the change",
            body = SettingsResponse
        ),
        (
            status = 400,
            description = "A value is out of bounds, or a name isn't a setting",
            body = ProblemDoc,
            content_type = "application/problem+json"
        ),
        (
            status = 409,
            description = "The environment sets one of them",
            body = ProblemDoc,
            content_type = "application/problem+json"
        ),
    )
);

doc!(
    doc_sso_get,
    get,
    path = "/admin/v1/sso",
    tag = "sso",
    security(("dpop" = [])),
    responses((
        status = 200,
        description = "The provider connection; the secret only says whether it is set",
        body = SsoDto
    ))
);

doc!(
    doc_sso_put,
    put,
    path = "/admin/v1/sso",
    tag = "sso",
    security(("dpop" = [])),
    params((
        "Step-Up-Token" = String,
        Header,
        description = "A fresh step-up token"
    )),
    request_body = SsoRequest,
    responses(
        (
            status = 200,
            description = "The connection after the change",
            body = SsoDto
        ),
        (
            status = 400,
            description = "A value isn't valid",
            body = ProblemDoc,
            content_type = "application/problem+json"
        ),
    )
);

doc!(doc_sso_domains, get, path = "/admin/v1/sso/domains", tag = "sso", security(("dpop" = [])),
    responses((status = 200, description = "The claimed domains, proven or pending", body = Vec<DomainDto>)));

doc!(
    doc_sso_domain_add,
    post,
    path = "/admin/v1/sso/domains",
    tag = "sso",
    security(("dpop" = [])),
    params((
        "Step-Up-Token" = String,
        Header,
        description = "A fresh step-up token"
    )),
    request_body = DomainRequest,
    responses((
        status = 201,
        description = "The claim, with the TXT record to publish",
        body = DomainDto
    ))
);

doc!(
    doc_sso_domain_verify,
    post,
    path = "/admin/v1/sso/domains/{domain}/verify",
    tag = "sso",
    security(("dpop" = [])),
    params(
        ("domain" = String, Path, description = "The domain"),
        (
            "Step-Up-Token" = String,
            Header,
            description = "A fresh step-up token"
        ),
    ),
    responses(
        (
            status = 200,
            description = "The record is there: the domain is proven",
            body = DomainDto
        ),
        (
            status = 409,
            description = "The DNS record isn't there yet",
            body = ProblemDoc,
            content_type = "application/problem+json"
        ),
    )
);

doc!(
    doc_sso_domain_remove,
    delete,
    path = "/admin/v1/sso/domains/{domain}",
    tag = "sso",
    security(("dpop" = [])),
    params(
        ("domain" = String, Path, description = "The domain"),
        (
            "Step-Up-Token" = String,
            Header,
            description = "A fresh step-up token"
        ),
    ),
    responses((status = 204, description = "The claim is dropped"))
);

doc!(
    doc_migration_status,
    get,
    path = "/admin/v1/migration",
    tag = "migration",
    security(("dpop" = [])),
    responses((
        status = 200,
        description = "Where the move from Vaultwarden stands",
        body = MigrationDto
    ))
);

doc!(
    doc_migration_start,
    post,
    path = "/admin/v1/migration/start",
    tag = "migration",
    security(("dpop" = [])),
    params((
        "Step-Up-Token" = String,
        Header,
        description = "A fresh step-up token"
    )),
    request_body = MigrationStartRequest,
    responses(
        (
            status = 202,
            description = "The move was started in the background; poll GET /admin/v1/migration",
            body = MigrationDto
        ),
        (
            status = 400,
            description = "The source isn't a plausible Vaultwarden source",
            body = ProblemDoc,
            content_type = "application/problem+json"
        ),
        (
            status = 409,
            description = "A move is already running, or the import isn't set up",
            body = ProblemDoc,
            content_type = "application/problem+json"
        ),
    )
);

doc!(doc_compliance_list, get, path = "/admin/v1/compliance/requests", tag = "compliance",
    security(("dpop" = [])),
    params(("open" = Option<bool>, Query, description = "Only requests that still need an answer; default true")),
    responses((status = 200, description = "The queue, soonest due first", body = ComplianceListDto)));

doc!(
    doc_compliance_log,
    post,
    path = "/admin/v1/compliance/requests",
    tag = "compliance",
    security(("dpop" = [])),
    params((
        "Step-Up-Token" = String,
        Header,
        description = "A fresh step-up token"
    )),
    request_body = LogRequestRequest,
    responses((
        status = 201,
        description = "Logged, with its due date",
        body = ComplianceRequestDto
    ))
);

doc!(
    doc_compliance_update,
    patch,
    path = "/admin/v1/compliance/requests/{id}",
    tag = "compliance",
    security(("dpop" = [])),
    params(
        ("id" = String, Path, description = "The request's UUID"),
        (
            "Step-Up-Token" = String,
            Header,
            description = "A fresh step-up token"
        ),
    ),
    request_body = UpdateRequestRequest,
    responses(
        (
            status = 200,
            description = "The request after the change",
            body = ComplianceRequestDto
        ),
        (
            status = 409,
            description = "The deadline was already extended, or can't be",
            body = ProblemDoc,
            content_type = "application/problem+json"
        ),
    )
);

doc!(
    doc_server_address,
    get,
    path = "/admin/v1/server-address",
    tag = "settings",
    security(("dpop" = [])),
    responses((
        status = 200,
        description = "The address in use next to the one recorded at setup, and the data folder",
        body = ServerAddressDto
    ),)
);

doc!(
    doc_push_relay_get,
    get,
    path = "/admin/v1/push-relay",
    tag = "push-relay",
    security(("dpop" = [])),
    responses(
        (
            status = 200,
            description = "Where Kemlock's push relay stands",
            body = PushRelayDto
        ),
        (
            status = 409,
            description = "This server has no push relay to turn on or off",
            body = ProblemDoc,
            content_type = "application/problem+json"
        ),
    )
);

doc!(
    doc_push_relay_enable,
    post,
    path = "/admin/v1/push-relay/enable",
    tag = "push-relay",
    security(("dpop" = [])),
    params((
        "Step-Up-Token" = String,
        Header,
        description = "A fresh step-up token"
    )),
    responses(
        (
            status = 200,
            description = "Registered with the relay (or already was)",
            body = PushRelayDto
        ),
        (
            status = 409,
            description = "The relay could not be reached, or this server has none to turn on",
            body = ProblemDoc,
            content_type = "application/problem+json"
        ),
    )
);

doc!(
    doc_push_relay_disable,
    post,
    path = "/admin/v1/push-relay/disable",
    tag = "push-relay",
    security(("dpop" = [])),
    params((
        "Step-Up-Token" = String,
        Header,
        description = "A fresh step-up token"
    )),
    responses(
        (
            status = 200,
            description = "Forgotten here, and erased at the relay when it could be reached",
            body = PushRelayDto
        ),
        (
            status = 409,
            description = "This server has no push relay to turn off",
            body = ProblemDoc,
            content_type = "application/problem+json"
        ),
    )
);

/// The documented routes of `/admin/v1`.
#[derive(Debug, OpenApi)]
#[openapi(
    info(
        title = "Kemlock Server admin API",
        version = "1",
        description = "The admin console's API. Every route but this document needs an admin's DPoP-bound access token; every write also needs a step-up token made by a re-run password check, a TOTP code or a passkey. Errors are RFC 9457 problem details."
    ),
    paths(
        doc_openapi, doc_me, doc_step_up_password_start, doc_step_up_password_finish,
        doc_step_up_totp, doc_step_up_passkey_options, doc_step_up_passkey_finish, doc_overview,
        doc_users_list, doc_user_delete, doc_user_sign_out, doc_user_disable, doc_user_enable,
        doc_user_cancel_erasure, doc_user_reset_two_step, doc_invites_list,
        doc_invite_create, doc_invite_resend, doc_invite_revoke, doc_spaces_list, doc_space_get,
        doc_space_change_owner, doc_events_list, doc_events_csv, doc_settings_get,
        doc_settings_put, doc_sso_get, doc_sso_put, doc_sso_domains, doc_sso_domain_add,
        doc_sso_domain_verify, doc_sso_domain_remove, doc_migration_status, doc_migration_start,
        doc_server_address, doc_push_relay_get, doc_push_relay_enable, doc_push_relay_disable, doc_compliance_list,
        doc_compliance_log, doc_compliance_update
    ),
    components(schemas(
        ProblemDoc, MeResponse, StepUpStartRequest, StepUpStartResponse, StepUpFinishRequest,
        StepUpTotpRequest, StepUpResponse, StepUpPasskeyOptionsResponse, StepUpPasskeyRequest,
        OverviewDto, AdminUserDto, UsersPageDto, InviteRequest,
        InviteDto, InviteIssuedDto, SpaceOwnerDto, AdminSpaceDto, SpacesPageDto,
        ChangeOwnerRequest, EventDto, EventsPageDto, SettingDto, SettingsResponse,
        SettingsRequest, GroupRuleDto, SsoDto, SsoRequest, DomainDto, DomainRequest, MigrationDto,
        MigrationStartRequest, ServerAddressDto, PushRelayDto, ComplianceRequestDto, ComplianceListDto,
        LogRequestRequest, UpdateRequestRequest
    )),
    modifiers(&SecurityAddon)
)]
struct ApiDoc;

/// The OpenAPI document of `/admin/v1`.
pub fn openapi() -> utoipa::openapi::OpenApi {
    ApiDoc::openapi()
}
