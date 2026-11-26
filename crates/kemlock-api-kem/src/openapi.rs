//! The OpenAPI 3.1 document of `/kem/v1`, served at `/kem/v1/openapi.json`.
//!
//! The documented routes are stubs below, one per route, because the real handlers are generic
//! over the server's ports. This is the API's own part; `GET /kem/v1/openapi.json` merges in the
//! parts that live beside their routes (devices, emergency access, files, single sign-on, spaces,
//! your data, push tokens, passkeys, Sends, policies and the duplicate cleaner).
//! `tests/openapi.rs` checks that every routed path is in the merged document.

use crate::dto::{
    BundleAtDto, ClearSignedWritesRequest, ConfigResponse, EmailRequest, ItemDto, ItemWriteAnswerDto, ItemWriteDto, KdfDto,
    MethodsResponse, OpaqueFinishRequest, OpaqueStartRequest, OpaqueStartResponse,
    PreloginResponse, RecoveryCodeRequest, RecoveryCodeResponse, RefreshRequest,
    RegisterFinishRequest, RegisterFinishResponse, RegisterStartRequest, RegisterStartResponse,
    ServerBasicsDto, SetupFinishRequest, SetupVerifyRequest, SetupVerifyResponse, SignInResponse,
    SsoOffer, SyncBody, SyncResponse, TagOutcomeDto, TaggedBatchRequest, TaggedBatchResponse,
    TaggedBatchWriteDto, TokenResponse, TotpConfirmRequest, TotpEnrolResponse, TwoFactorRequest,
};
use serde::Serialize;
use utoipa::openapi::security::{ApiKey, ApiKeyValue, SecurityScheme};
use utoipa::{Modify, OpenApi, ToSchema};
use uuid::Uuid;

/// An RFC 9457 problem detail, served as `application/problem+json`. Besides the members below,
/// a problem carries the extension members of its kind: the optional ones listed here, each
/// present only on the problems it is named for.
#[derive(Debug, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct ProblemDoc {
    /// `urn:kemlock:problem:<slug>`.
    #[serde(rename = "type")]
    pub kind: String,
    pub title: String,
    pub status: u16,
    pub detail: Option<String>,
    /// `stale-revision` (409): the item whose write was stale; in a batch, the write that failed.
    pub item_id: Option<Uuid>,
    /// `stale-revision` (409): the item's current revision; `null` when the item doesn't exist.
    pub current_revision: Option<u64>,
    /// `session-ended` (401): why: `security-stamp-changed` or `refresh-token-reuse`.
    /// `space-chain-refused` (422): the refusal's reason.
    pub reason: Option<String>,
    /// `space-chain-refused` (422): the sequence number of the record refused, when there is one.
    pub seq: Option<u64>,
    /// `space-chain-conflict` (409): the chain's head, or `null` for a chain with no record.
    #[schema(value_type = Option<crate::routes::space_chain::HeadDto>)]
    pub head: Option<serde_json::Value>,
    /// `rate-limited` (429): the seconds to wait, as in the `Retry-After` header.
    pub retry_after: Option<u64>,
    /// `file-too-large` (413): the most bytes this server takes.
    pub max_size: Option<u64>,
    /// `stale-dedup-version` (409): the dedup key version the owner's tags are under.
    pub current_tag_version: Option<u32>,
    /// `stale-key-version` (409): the collection's current key version.
    pub current_key_version: Option<u32>,
    /// `stale-manifest` (409): the counter of the stored manifest.
    pub current_counter: Option<u64>,
    /// `sso-required` (403): the space that requires single sign-on.
    pub space_id: Option<Uuid>,
    /// `use-dpop-nonce` (401): `use_dpop_nonce` (RFC 9449). The back-channel logout's 400:
    /// `invalid_request`.
    pub error: Option<String>,
    /// The back-channel logout's 400: what was wrong, as in `detail`.
    #[serde(rename = "error_description")]
    pub error_description: Option<String>,
}

/// Adds the DPoP-bound access token as a security scheme.
#[derive(Debug)]
struct SecurityAddon;

impl Modify for SecurityAddon {
    fn modify(&self, openapi: &mut utoipa::openapi::OpenApi) {
        let components = openapi.components.get_or_insert_with(Default::default);
        let mut scheme = ApiKeyValue::new("Authorization");
        scheme.description = Some(
            "`Authorization: DPoP <access token>`, with a `DPoP` header carrying a proof signed by \
             the key the token is bound to (RFC 9449). Token endpoints take the `DPoP` header only."
                .to_owned(),
        );
        components.add_security_scheme("dpop", SecurityScheme::ApiKey(ApiKey::Header(scheme)));
    }
}

/// Adds the answers that most routes can give and the route stubs don't list one by one: 401 on
/// every route that takes a DPoP proof (a wrong or expired token, a bad proof, or the
/// `use-dpop-nonce` problem that carries the server's nonce), 429 where a limiter may refuse and
/// 500 for a store failure. An answer a route already lists is kept as it is. `GET /openapi.json`
/// is left alone, and `GET /config` has no limiter.
///
/// `GET /kem/v1/openapi.json` runs it over the merged document.
#[derive(Debug)]
pub struct CommonAnswers;

/// An answer that is a problem: `application/problem+json` with the `ProblemDoc` schema.
fn problem_answer(
    description: &str,
    headers: serde_json::Value,
) -> Option<utoipa::openapi::Response> {
    serde_json::from_value(serde_json::json!({
        "description": description,
        "headers": headers,
        "content": {
            "application/problem+json": {
                "schema": { "$ref": "#/components/schemas/ProblemDoc" }
            }
        }
    }))
    .ok()
}

impl Modify for CommonAnswers {
    fn modify(&self, openapi: &mut utoipa::openapi::OpenApi) {
        let header = |description: &str| serde_json::json!({ "description": description, "schema": { "type": "string" } });
        let unauthorized = problem_answer(
            "The access token or the DPoP proof is wrong or expired, or the session ended. A \
             `use-dpop-nonce` problem (`error` is `use_dpop_nonce`) carries the server's nonce in \
             `DPoP-Nonce`: sign the proof again with it",
            serde_json::json!({
                "WWW-Authenticate": header("`DPoP error=\"invalid_dpop_proof\"` or `DPoP error=\"use_dpop_nonce\"`"),
                "DPoP-Nonce": header("The nonce to put in the next proof, on a `use-dpop-nonce` problem"),
            }),
        );
        let too_many = problem_answer(
            "Too many tries: wait `retryAfter` seconds",
            serde_json::json!({ "Retry-After": header("The seconds to wait") }),
        );
        let internal = problem_answer("Something went wrong on the server", serde_json::json!({}));
        for (path, item) in &mut openapi.paths.paths {
            if path == "/kem/v1/openapi.json" {
                continue;
            }
            let operations = [
                &mut item.get,
                &mut item.put,
                &mut item.post,
                &mut item.delete,
                &mut item.options,
                &mut item.head,
                &mut item.patch,
                &mut item.trace,
            ];
            for operation in operations.into_iter().flatten() {
                let takes_proof = operation
                    .security
                    .as_ref()
                    .is_some_and(|requirements| !requirements.is_empty())
                    || operation.parameters.as_ref().is_some_and(|parameters| {
                        parameters.iter().any(|parameter| match parameter {
                            utoipa::openapi::RefOr::T(p) => p.name.eq_ignore_ascii_case("dpop"),
                            utoipa::openapi::RefOr::Ref(_) => false,
                        })
                    });
                let answers = &mut operation.responses.responses;
                let mut add = |status: &str, answer: &Option<utoipa::openapi::Response>| {
                    if let Some(answer) = answer {
                        answers
                            .entry(status.to_owned())
                            .or_insert_with(|| utoipa::openapi::RefOr::T(answer.clone()));
                    }
                };
                if takes_proof {
                    add("401", &unauthorized);
                }
                if path != "/kem/v1/config" {
                    add("429", &too_many);
                }
                add("500", &internal);
            }
        }
    }
}

#[utoipa::path(
    get, path = "/kem/v1/config", tag = "server",
    params(
        ("vault" = Option<Vec<String>>, Query, description = "A vault to list the servers of, `user:<uuid>` or `space:<uuid>`; repeat it for more, up to 32 (`?vault=a&vault=b`). Only a signed-in caller gets `vaults`; a vault that isn't federated here is left out", style = Form, explode),
    ),
    responses((status = 200, description = "What a client reads before signing in", body = ConfigResponse))
)]
#[allow(dead_code)]
fn doc_config() {}

#[utoipa::path(
    get, path = "/kem/v1/openapi.json", tag = "server",
    responses((status = 200, description = "This document"))
)]
#[allow(dead_code)]
fn doc_openapi() {}

#[utoipa::path(
    get, path = "/kem/v1/webauthn", tag = "auth",
    responses((status = 200, description = "A static HTML page a client that is not a page of this server (the browser extension) opens to ask for a passkey or security key, with the PRF extension, for this server's relying party. It takes the request in the URL fragment (`options`, `state`, `redirect` or `extension`, `prf`) and answers only an extension redirect address, or opener, named by `KEMLOCK_BROWSER_EXTENSION_IDS`", body = String, content_type = "text/html"))
)]
#[allow(dead_code)]
fn doc_webauthn_page() {}

#[utoipa::path(
    get, path = "/kem/v1/webauthn/connector.js", tag = "auth",
    responses((status = 200, description = "The connector page's script, which the page's policy allows as its only script", body = String, content_type = "text/javascript"))
)]
#[allow(dead_code)]
fn doc_webauthn_script() {}

#[utoipa::path(
    post, path = "/kem/v1/setup/verify", tag = "setup",
    request_body = SetupVerifyRequest,
    responses(
        (status = 200, description = "The code is right: a short-lived grant", body = SetupVerifyResponse),
        (status = 403, description = "Wrong code, or not a secure context", body = ProblemDoc, content_type = "application/problem+json"),
        (status = 409, description = "Setup is finished", body = ProblemDoc, content_type = "application/problem+json"),
        (status = 429, description = "Too many tries", body = ProblemDoc, content_type = "application/problem+json"),
    )
)]
#[allow(dead_code)]
fn doc_setup_verify() {}

#[utoipa::path(
    post, path = "/kem/v1/setup/finish", tag = "setup",
    security(("dpop" = [])),
    request_body = Option<SetupFinishRequest>,
    responses(
        (status = 204, description = "Setup is closed for good, and the server basics (when sent) are saved as settings"),
        (status = 400, description = "A server basic is not valid; setup stays open", body = ProblemDoc, content_type = "application/problem+json"),
        (status = 409, description = "The admin has no confirmed two-step method yet", body = ProblemDoc, content_type = "application/problem+json"),
    )
)]
#[allow(dead_code)]
fn doc_setup_finish() {}

#[utoipa::path(
    post, path = "/kem/v1/auth/prelogin", tag = "auth",
    request_body = EmailRequest,
    responses((status = 200, description = "The Argon2id settings and salt; a fake but stable answer for an unknown email", body = PreloginResponse))
)]
#[allow(dead_code)]
fn doc_prelogin() {}

#[utoipa::path(
    post, path = "/kem/v1/auth/methods", tag = "auth",
    request_body = EmailRequest,
    responses((status = 200, description = "The ways in", body = MethodsResponse))
)]
#[allow(dead_code)]
fn doc_methods() {}

#[utoipa::path(
    post, path = "/kem/v1/accounts/register/start", tag = "accounts",
    request_body = RegisterStartRequest,
    responses(
        (status = 200, description = "OPAQUE's registration response", body = RegisterStartResponse),
        (status = 403, description = "Signups are closed and there is no setup grant", body = ProblemDoc, content_type = "application/problem+json"),
        (status = 429, description = "Too many registrations", body = ProblemDoc, content_type = "application/problem+json"),
    )
)]
#[allow(dead_code)]
fn doc_register_start() {}

#[utoipa::path(
    post, path = "/kem/v1/accounts/register/finish", tag = "accounts",
    request_body = RegisterFinishRequest,
    responses(
        (status = 201, description = "The account exists. When the server verifies the address of a new account, `emailConfirmationRequired` is true: the account can't sign in until the link mailed to it is opened", body = RegisterFinishResponse),
        (status = 409, description = "The email is taken", body = ProblemDoc, content_type = "application/problem+json"),
    )
)]
#[allow(dead_code)]
fn doc_register_finish() {}

#[utoipa::path(
    get, path = "/kem/v1/accounts/confirm-email", tag = "accounts",
    params(("token" = String, Query, description = "The token in the link of the mail, base64url")),
    responses(
        (status = 200, description = "A small HTML page with a Confirm button that posts the token back. Nothing changes until it is pressed, so a mail scanner that opens the link spends nothing", body = String, content_type = "text/html"),
        (status = 400, description = "A small HTML page: the link isn't valid", body = String, content_type = "text/html"),
        (status = 429, description = "Too many tries", body = ProblemDoc, content_type = "application/problem+json"),
    )
)]
#[allow(dead_code)]
fn doc_confirm_email_page() {}

#[utoipa::path(
    post, path = "/kem/v1/accounts/confirm-email", tag = "accounts",
    request_body(content = String, content_type = "application/x-www-form-urlencoded", description = "`token=` and the token of the link"),
    responses(
        (status = 200, description = "A small HTML page: the address is confirmed and the account can sign in", body = String, content_type = "text/html"),
        (status = 400, description = "A small HTML page: the link is unknown, opened already or out of time", body = String, content_type = "text/html"),
        (status = 429, description = "Too many tries", body = ProblemDoc, content_type = "application/problem+json"),
    )
)]
#[allow(dead_code)]
fn doc_confirm_email() {}

#[utoipa::path(
    post, path = "/kem/v1/accounts/confirm-email/resend", tag = "accounts",
    request_body = EmailRequest,
    responses(
        (status = 202, description = "Asked for, whatever the address: a new link is mailed only to an address whose account is held back and has had none for five minutes"),
        (status = 429, description = "Too many tries", body = ProblemDoc, content_type = "application/problem+json"),
    )
)]
#[allow(dead_code)]
fn doc_resend_confirm_email() {}

#[utoipa::path(
    post, path = "/kem/v1/auth/opaque/start", tag = "auth",
    request_body = OpaqueStartRequest,
    responses(
        (status = 200, description = "OPAQUE's credential response and the sealed login state", body = OpaqueStartResponse),
        (status = 429, description = "Too many tries; wait Retry-After seconds", body = ProblemDoc, content_type = "application/problem+json"),
    )
)]
#[allow(dead_code)]
fn doc_opaque_start() {}

#[utoipa::path(
    post, path = "/kem/v1/auth/opaque/finish", tag = "auth",
    params(("DPoP" = String, Header, description = "A DPoP proof (RFC 9449) signed by the device key")),
    request_body = OpaqueFinishRequest,
    responses(
        (status = 200, description = "Signed in, or a second step is needed", body = SignInResponse),
        (status = 401, description = "Wrong credentials, or a DPoP error (use_dpop_nonce carries DPoP-Nonce)", body = ProblemDoc, content_type = "application/problem+json"),
    )
)]
#[allow(dead_code)]
fn doc_opaque_finish() {}

#[utoipa::path(
    post, path = "/kem/v1/auth/two-factor", tag = "auth",
    params(("DPoP" = String, Header, description = "A DPoP proof signed by the key that passed the password")),
    request_body = TwoFactorRequest,
    responses(
        (status = 200, description = "Signed in", body = TokenResponse),
        (status = 401, description = "Wrong code", body = ProblemDoc, content_type = "application/problem+json"),
    )
)]
#[allow(dead_code)]
fn doc_two_factor() {}

#[utoipa::path(
    post, path = "/kem/v1/auth/token", tag = "auth",
    params(("DPoP" = String, Header, description = "A DPoP proof signed by the device key")),
    request_body = RefreshRequest,
    responses(
        (status = 200, description = "A new access token and a new refresh token", body = TokenResponse),
        (status = 401, description = "The session ended (a refresh token used twice ends it)", body = ProblemDoc, content_type = "application/problem+json"),
    )
)]
#[allow(dead_code)]
fn doc_token() {}

#[utoipa::path(
    post, path = "/kem/v1/account/two-factor/totp", tag = "account",
    security(("dpop" = [])),
    responses((status = 200, description = "The secret to scan or type into an authenticator app", body = TotpEnrolResponse))
)]
#[allow(dead_code)]
fn doc_totp_enrol() {}

#[utoipa::path(
    post, path = "/kem/v1/account/two-factor/totp/confirm", tag = "account",
    security(("dpop" = [])),
    request_body = TotpConfirmRequest,
    responses(
        (status = 204, description = "The method is enabled. With another second step on, the request carries the recovery code as `proof`"),
        (status = 400, description = "Another second step is on and the proof is missing or wrong", body = ProblemDoc, content_type = "application/problem+json"),
        (status = 401, description = "Wrong code", body = ProblemDoc, content_type = "application/problem+json"),
    )
)]
#[allow(dead_code)]
fn doc_totp_confirm() {}

#[utoipa::path(
    post, path = "/kem/v1/account/two-factor/recovery-code", tag = "account",
    security(("dpop" = [])),
    request_body = RecoveryCodeRequest,
    responses(
        (status = 200, description = "The recovery code (null before the account's first second step, or once it was spent). While the account holds one, the request carries a fresh `proof` that is not the recovery code: a mailed code or a current code of the authenticator app", body = RecoveryCodeResponse),
        (status = 400, description = "The account holds a code and the proof is missing, wrong or has run out", body = ProblemDoc, content_type = "application/problem+json"),
        (status = 429, description = "Too many asks", body = ProblemDoc, content_type = "application/problem+json"),
    )
)]
#[allow(dead_code)]
fn doc_recovery_code() {}

#[utoipa::path(
    put, path = "/kem/v1/items/{id}", tag = "items",
    security(("dpop" = [])),
    params(
        ("id" = String, Path, description = "The item's id, a UUID made by the client"),
        ("If-Match" = Option<String>, Header, description = "The revision replaced; required unless If-None-Match is sent"),
        ("If-None-Match" = Option<String>, Header, description = "`*` for a new item"),
    ),
    request_body = ItemWriteDto,
    responses(
        (status = 200, description = "Replaced; `tagsStored` and `matches` when the write carried tags", body = ItemWriteAnswerDto),
        (status = 201, description = "Created; `tagsStored` and `matches` when the write carried tags", body = ItemWriteAnswerDto),
        (status = 403, description = "A space item the caller may not write: no edit on its collection", body = ProblemDoc, content_type = "application/problem+json"),
        (status = 404, description = "No such space, or the caller isn't in it", body = ProblemDoc, content_type = "application/problem+json"),
        (status = 409, description = "Stale write: the current revision is in `currentRevision`; or a space item sealed under a replaced collection key", body = ProblemDoc, content_type = "application/problem+json"),
        (status = 422, description = "`invalid-signature`: the write's signature is not the signed-in account's, or `signature-required`: the owner accepts signed writes only, or `key-version-stale`: the account replaced its keys after the device unlocked (`currentKeyVersion`)", body = ProblemDoc, content_type = "application/problem+json"),
        (status = 423, description = "The space waits for its keys to be replaced", body = ProblemDoc, content_type = "application/problem+json"),
        (status = 428, description = "No If-Match or If-None-Match", body = ProblemDoc, content_type = "application/problem+json"),
    )
)]
#[allow(dead_code)]
fn doc_put_item() {}

#[utoipa::path(
    post, path = "/kem/v1/items:batch", tag = "items",
    security(("dpop" = [])),
    request_body = TaggedBatchRequest,
    responses(
        (status = 200, description = "Every write was stored; `tags` says what became of the tags of the writes that carried some", body = TaggedBatchResponse),
        (status = 422, description = "`invalid-signature`: a write's signature is not the signed-in account's, or `signature-required`: an owner accepts signed writes only; nothing was stored", body = ProblemDoc, content_type = "application/problem+json"),
        (status = 403, description = "A space item the caller may not write; nothing was stored", body = ProblemDoc, content_type = "application/problem+json"),
        (status = 423, description = "A space waits for its keys to be replaced; nothing was stored", body = ProblemDoc, content_type = "application/problem+json"),
        (status = 409, description = "A write was stale; nothing was stored. `itemId` names it", body = ProblemDoc, content_type = "application/problem+json"),
    )
)]
#[allow(dead_code)]
fn doc_batch() {}

#[utoipa::path(
    get, path = "/kem/v1/accounts/{id}/bundles/{version}", tag = "items",
    security(("dpop" = [])),
    params(
        ("id" = String, Path, description = "The account's id, a UUID"),
        ("version" = u32, Path, description = "The key version of the bundle"),
    ),
    responses(
        (status = 200, description = "The bundle the account had at that key version (docs/crypto.md, \"Signed item writes\"): for the account itself and a confirmed member of a space it is a confirmed member of", body = BundleAtDto),
        (status = 404, description = "No such account or version, or the caller may not read it: the same answer", body = ProblemDoc, content_type = "application/problem+json"),
    )
)]
#[allow(dead_code)]
fn doc_bundle_at() {}

#[utoipa::path(
    put, path = "/kem/v1/owners/{owner}/signed-writes", tag = "items",
    security(("dpop" = [])),
    params(("owner" = String, Path, description = "The account's own vault `user:<uuid>`, or a space `space:<uuid>` the caller owns or administers")),
    responses(
        (status = 204, description = "The owner accepts signed writes only from now on (docs/crypto.md, \"The signed-only flag\"). Idempotent. Servers it replicates to learn it from the home server"),
        (status = 403, description = "Another account's vault, or a space the caller is neither owner nor admin of", body = ProblemDoc, content_type = "application/problem+json"),
        (status = 404, description = "A space the caller is not a member of", body = ProblemDoc, content_type = "application/problem+json"),
    )
)]
#[allow(dead_code)]
fn doc_signed_writes() {}

#[utoipa::path(
    delete, path = "/kem/v1/owners/{owner}/signed-writes", tag = "items",
    security(("dpop" = [])),
    params(("owner" = String, Path, description = "The account's own vault `user:<uuid>`, or a space `space:<uuid>` the caller owns or administers")),
    request_body = ClearSignedWritesRequest,
    responses(
        (status = 204, description = "Unsigned writes are accepted again (docs/crypto.md, \"The signed-only flag\"). Idempotent. Needs the password, and a fresh proof when a second step is on"),
        (status = 400, description = "The login state was used before, or isn't well formed; or a second step is on and the proof is missing, wrong or spent", body = ProblemDoc, content_type = "application/problem+json"),
        (status = 401, description = "Wrong password, or not signed in", body = ProblemDoc, content_type = "application/problem+json"),
        (status = 403, description = "Another account's vault, or a space the caller is neither owner nor admin of", body = ProblemDoc, content_type = "application/problem+json"),
        (status = 429, description = "Too many wrong passwords", body = ProblemDoc, content_type = "application/problem+json"),
    )
)]
#[allow(dead_code)]
fn doc_clear_signed_writes() {}

#[utoipa::path(
    get, path = "/kem/v1/sync", tag = "sync",
    security(("dpop" = [])),
    params(
        ("since" = Option<String>, Query, description = "The cursor of the last sync; omit for a first sync"),
        ("limit" = Option<u32>, Query, description = "The most items to return, up to 500"),
        ("Kemlock-Sync-Cursor" = Option<String>, Header, description = "The cursor, for one too long for the URL (it grows about 43 bytes per space). `since` wins when both are sent; `POST /kem/v1/sync` takes it in a JSON body instead"),
        ("If-None-Match" = Option<String>, Header, description = "The ETag of the last response, as an alternative to `since`"),
    ),
    responses(
        (status = 200, description = "Items changed since the cursor, with the next cursor: the vault's and those of every space the account is confirmed in", body = SyncResponse),
        (status = 304, description = "Nothing changed"),
        (status = 410, description = "The cursor is too old: sync again without one", body = ProblemDoc, content_type = "application/problem+json"),
    )
)]
#[allow(dead_code)]
fn doc_sync() {}

#[utoipa::path(
    post, path = "/kem/v1/sync", tag = "sync",
    security(("dpop" = [])),
    request_body(content = SyncBody, description = "The cursor and page size, for a cursor too long for a URL or a header. An empty body is a first sync"),
    params(
        ("Kemlock-Sync-Cursor" = Option<String>, Header, description = "The cursor, when the body has no `since`"),
        ("If-None-Match" = Option<String>, Header, description = "The ETag of the last response, as an alternative to `since`"),
    ),
    responses(
        (status = 200, description = "Exactly the answer of `GET /kem/v1/sync`", body = SyncResponse),
        (status = 304, description = "Nothing changed"),
        (status = 410, description = "The cursor is too old: sync again without one", body = ProblemDoc, content_type = "application/problem+json"),
    )
)]
#[allow(dead_code)]
fn doc_sync_post() {}

#[utoipa::path(
    get, path = "/kem/v1/live", tag = "sync",
    security(("dpop" = [])),
    responses((status = 101, description = "A WebSocket that sends {\"type\":\"sync\"} when the account's items change"))
)]
#[allow(dead_code)]
fn doc_live() {}

/// The OpenAPI document.
#[derive(Debug, OpenApi)]
#[openapi(
    info(
        title = "Kemlock Server API",
        version = "1",
        description = "The Kemlock API: OPAQUE sign-in, DPoP-bound tokens, items and sync, attachments, trusted devices, emergency access, single sign-on and spaces. Errors are RFC 9457 problem details."
    ),
    paths(
        doc_config, doc_openapi, doc_webauthn_page, doc_webauthn_script, doc_setup_verify, doc_setup_finish, doc_prelogin, doc_methods,
        doc_register_start, doc_register_finish, doc_confirm_email_page, doc_confirm_email, doc_resend_confirm_email, doc_opaque_start, doc_opaque_finish,
        doc_two_factor, doc_token, doc_totp_enrol, doc_totp_confirm, doc_recovery_code,
        doc_put_item, doc_batch, doc_signed_writes, doc_clear_signed_writes, doc_bundle_at, doc_sync, doc_sync_post, doc_live
    ),
    components(schemas(
        ProblemDoc, ConfigResponse, SetupVerifyRequest, SetupVerifyResponse, SetupFinishRequest,
        ServerBasicsDto, EmailRequest, KdfDto,
        PreloginResponse, MethodsResponse, SsoOffer, RegisterStartRequest, RegisterStartResponse,
        RegisterFinishRequest, RegisterFinishResponse, OpaqueStartRequest, OpaqueStartResponse,
        OpaqueFinishRequest, SignInResponse, TokenResponse, TwoFactorRequest, RefreshRequest,
        TotpEnrolResponse, TotpConfirmRequest, RecoveryCodeRequest, RecoveryCodeResponse, ItemDto,
        ItemWriteDto, ItemWriteAnswerDto, TaggedBatchWriteDto, TaggedBatchRequest, TagOutcomeDto,
        TaggedBatchResponse, SyncBody, SyncResponse, BundleAtDto, ClearSignedWritesRequest
    )),
    modifiers(&SecurityAddon)
)]
pub struct ApiDoc;
