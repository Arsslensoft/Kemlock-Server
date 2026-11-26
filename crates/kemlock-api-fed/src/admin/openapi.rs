//! The OpenAPI 3.1 document of the federation admin routes, served at
//! `/admin/v1/federation/openapi.json`.
//!
//! It documents the routes the web vault's federation screens use that the first version of the
//! admin API did not have, and the three whose answers grew (the overview, the peer list and
//! promotion). The documented routes are stubs below, one per route, because the real handlers
//! are generic over the server's ports. A test checks that the router answers every path and
//! method named here, so the two can't drift apart.

use super::console::{
    ComparisonDto, ConsistencyDto, DescriptorDto, KemDto, MismatchDto, PausedDto, PeerCheckDto,
    PeerSecurityDto, SelfDto, ShareableDto, SuiteChoice, SuiteRowDto, SuiteSettingDto, SuitesBody,
};
use super::{
    AckDto, AddressChangeDto, AwaitingDto, HeldDemotionDto, HeldPromotionDto, KeyChangeDto,
    OfferDto, OverviewDto, PeerDto, PromotionDto, PulledDto, ServerDto, StatusDto, SwitchesDto,
    VaultDto, VaultStatusDto,
};
use serde::Serialize;
use utoipa::openapi::security::{ApiKey, ApiKeyValue, SecurityScheme};
use utoipa::{Modify, OpenApi, ToSchema};

/// An RFC 9457 problem detail, served as `application/problem+json`.
#[derive(Debug, Serialize, ToSchema)]
pub(super) struct ProblemDoc {
    /// `urn:kemlock:problem:<slug>`.
    #[serde(rename = "type")]
    kind: String,
    title: String,
    status: u16,
    detail: Option<String>,
}

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
             the token is bound to (RFC 9449). Anyone else gets 403. A write also carries a \
             step-up token in `Step-Up-Token`."
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
    path = "/admin/v1/federation/openapi.json",
    tag = "federation",
    responses((status = 200, description = "This document"))
);

doc!(
    doc_overview,
    get,
    path = "/admin/v1/federation",
    tag = "federation",
    security(("dpop" = [])),
    responses(
        (
            status = 200,
            description = "This server, its peers (with their pinned key, lag and last change), \
                           the pairings that wait, the vaults federation knows of (with owner, \
                           members, size and waiting changes) and the offers",
            body = OverviewDto
        ),
        (
            status = 401,
            description = "Not signed in",
            body = ProblemDoc,
            content_type = "application/problem+json"
        ),
        (
            status = 403,
            description = "Not an admin",
            body = ProblemDoc,
            content_type = "application/problem+json"
        ),
    )
);

doc!(
    doc_peers,
    get,
    path = "/admin/v1/federation/peers",
    tag = "federation",
    security(("dpop" = [])),
    responses((status = 200, description = "Every peer, paired or revoked", body = Vec<PeerDto>))
);

doc!(
    doc_promote,
    post,
    path = "/admin/v1/federation/vaults/{owner}/promote",
    tag = "federation",
    security(("dpop" = [])),
    params(
        (
            "owner" = String,
            Path,
            description = "`user:<uuid>` or `space:<uuid>`"
        ),
        (
            "Step-Up-Token" = String,
            Header,
            description = "A step-up token; it counts as the fresh check promotion needs, as a \
                           recent sign-in does"
        ),
    ),
    responses(
        (
            status = 200,
            description = "This server is the vault's home now",
            body = PromotionDto
        ),
        (
            status = 403,
            description = "No fresh check",
            body = ProblemDoc,
            content_type = "application/problem+json"
        ),
    )
);

doc!(
    doc_accept_demotion,
    post,
    path = "/admin/v1/federation/vaults/{owner}/demotion",
    tag = "federation",
    security(("dpop" = [])),
    params(
        (
            "owner" = String,
            Path,
            description = "`user:<uuid>` or `space:<uuid>`"
        ),
        (
            "Step-Up-Token" = String,
            Header,
            description = "A step-up token; it counts as the fresh check, as a recent sign-in does"
        ),
    ),
    responses(
        (
            status = 200,
            description = "The server named in the held promotion is the vault's home now, and \
                           this server its last replica",
            body = VaultDto
        ),
        (
            status = 400,
            description = "No promotion waits for this vault, or it no longer fits the vault",
            body = ProblemDoc,
            content_type = "application/problem+json"
        ),
        (
            status = 403,
            description = "No fresh check",
            body = ProblemDoc,
            content_type = "application/problem+json"
        ),
    )
);

doc!(
    doc_held_promotions,
    get,
    path = "/admin/v1/federation/promotions",
    tag = "federation",
    security(("dpop" = [])),
    responses((
        status = 200,
        description = "The promotions held for this server's admin: another server signed one \
                       that would make it a vault's home, and this server is the home (always) \
                       or a replica (unless `federation_promotion` is `auto`)",
        body = Vec<HeldPromotionDto>
    ))
);

doc!(
    doc_refuse_demotion,
    delete,
    path = "/admin/v1/federation/vaults/{owner}/demotion",
    tag = "federation",
    security(("dpop" = [])),
    params(
        (
            "owner" = String,
            Path,
            description = "`user:<uuid>` or `space:<uuid>`"
        ),
        (
            "Step-Up-Token" = String,
            Header,
            description = "A step-up token"
        ),
    ),
    responses(
        (status = 204, description = "The held promotion is dropped and nothing changes"),
        (
            status = 409,
            description = "No promotion waits for this vault",
            body = ProblemDoc,
            content_type = "application/problem+json"
        ),
        (
            status = 403,
            description = "No step-up token",
            body = ProblemDoc,
            content_type = "application/problem+json"
        ),
    )
);

doc!(
    doc_address_changes,
    get,
    path = "/admin/v1/federation/address-changes",
    tag = "federation",
    security(("dpop" = [])),
    responses((
        status = 200,
        description = "The address changes that came with a peer's key rotation. This server \
                       still dials the addresses it knew until its admin accepts them",
        body = Vec<AddressChangeDto>
    ))
);

doc!(
    doc_approve_address_change,
    post,
    path = "/admin/v1/federation/peers/{id}/address-change",
    tag = "federation",
    security(("dpop" = [])),
    params(
        ("id" = String, Path, description = "The peer's server id"),
        (
            "Step-Up-Token" = String,
            Header,
            description = "A step-up token"
        ),
    ),
    responses(
        (status = 204, description = "This server dials the new addresses from now on"),
        (
            status = 409,
            description = "No address change waits for this peer",
            body = ProblemDoc,
            content_type = "application/problem+json"
        ),
    )
);

doc!(
    doc_refuse_address_change,
    delete,
    path = "/admin/v1/federation/peers/{id}/address-change",
    tag = "federation",
    security(("dpop" = [])),
    params(
        ("id" = String, Path, description = "The peer's server id"),
        (
            "Step-Up-Token" = String,
            Header,
            description = "A step-up token"
        ),
    ),
    responses(
        (status = 204, description = "The addresses this server knew stay"),
        (
            status = 409,
            description = "No address change waits for this peer",
            body = ProblemDoc,
            content_type = "application/problem+json"
        ),
    )
);

doc!(
    doc_clear_contest,
    delete,
    path = "/admin/v1/federation/peers/{id}/contest",
    tag = "federation",
    security(("dpop" = [])),
    params(
        ("id" = String, Path, description = "The peer's server id"),
        (
            "Step-Up-Token" = String,
            Header,
            description = "A step-up token"
        ),
    ),
    responses(
        (status = 204, description = "The contested peer is trusted again and syncs from the next visit"),
        (
            status = 409,
            description = "The peer is not contested",
            body = ProblemDoc,
            content_type = "application/problem+json"
        ),
    )
);

doc!(
    doc_shareable,
    get,
    path = "/admin/v1/federation/shareable",
    tag = "federation",
    security(("dpop" = [])),
    responses((
        status = 200,
        description = "The vaults homed here that no peer holds yet: an account's vault is named \
                       by its owner's email, a space by nothing (its name is ciphertext)",
        body = Vec<ShareableDto>
    ))
);

doc!(
    doc_check,
    post,
    path = "/admin/v1/federation/check",
    tag = "federation",
    security(("dpop" = [])),
    params((
        "Step-Up-Token" = String,
        Header,
        description = "A fresh step-up token"
    )),
    responses(
        (status = 200, description = "How the visit to each paired peer went", body = Vec<PeerCheckDto>),
        (status = 403, description = "No fresh step-up token", body = ProblemDoc, content_type = "application/problem+json"),
    )
);

doc!(
    doc_consistency,
    post,
    path = "/admin/v1/federation/consistency",
    tag = "federation",
    security(("dpop" = [])),
    params((
        "Step-Up-Token" = String,
        Header,
        description = "A fresh step-up token"
    )),
    responses(
        (
            status = 200,
            description = "The hash trees of every shared vault compared with each paired peer",
            body = Vec<ConsistencyDto>
        ),
        (status = 403, description = "No fresh step-up token", body = ProblemDoc, content_type = "application/problem+json"),
    )
);

doc!(
    doc_peer_security,
    get,
    path = "/admin/v1/federation/peers/{id}/security",
    tag = "federation",
    security(("dpop" = [])),
    params(("id" = String, Path, description = "The peer's server id")),
    responses(
        (
            status = 200,
            description = "The peer's keys, descriptor and suites",
            body = PeerSecurityDto
        ),
        (
            status = 404,
            description = "No such peer",
            body = ProblemDoc,
            content_type = "application/problem+json"
        ),
    )
);

doc!(
    doc_peer_descriptor,
    get,
    path = "/admin/v1/federation/peers/{id}/descriptor",
    tag = "federation",
    security(("dpop" = [])),
    params(("id" = String, Path, description = "The peer's server id")),
    responses(
        (
            status = 200,
            description = "The peer's signed descriptor as a file, \
                           `application/vnd.kemlock.federation-descriptor+cbor`"
        ),
        (
            status = 404,
            description = "No such peer, or no descriptor read yet",
            body = ProblemDoc,
            content_type = "application/problem+json"
        ),
    )
);

doc!(
    doc_self,
    get,
    path = "/admin/v1/federation/self",
    tag = "federation",
    security(("dpop" = [])),
    responses((
        status = 200,
        description = "This server's descriptor, identity fingerprint, KEM key age and suites",
        body = SelfDto
    ))
);

doc!(
    doc_self_kem_rotation,
    post,
    path = "/admin/v1/federation/self/kem-rotation",
    tag = "federation",
    security(("dpop" = [])),
    params((
        "Step-Up-Token" = String,
        Header,
        description = "A fresh step-up token"
    )),
    responses(
        (
            status = 200,
            description = "A new KEM key under the same identity key",
            body = SelfDto
        ),
        (
            status = 403,
            description = "No fresh step-up token",
            body = ProblemDoc,
            content_type = "application/problem+json"
        ),
    )
);

doc!(
    doc_self_identity_rotation,
    post,
    path = "/admin/v1/federation/self/identity-rotation",
    tag = "federation",
    security(("dpop" = [])),
    params((
        "Step-Up-Token" = String,
        Header,
        description = "A fresh step-up token"
    )),
    responses(
        (
            status = 200,
            description = "A new identity key, signed by the old one",
            body = KeyChangeDto
        ),
        (
            status = 403,
            description = "No fresh step-up token",
            body = ProblemDoc,
            content_type = "application/problem+json"
        ),
    )
);

doc!(
    doc_self_suites,
    put,
    path = "/admin/v1/federation/self/suites",
    tag = "federation",
    security(("dpop" = [])),
    params((
        "Step-Up-Token" = String,
        Header,
        description = "A fresh step-up token"
    )),
    request_body = SuitesBody,
    responses(
        (
            status = 200,
            description = "The descriptor is signed afresh with the suites turned on",
            body = SelfDto
        ),
        (
            status = 403,
            description = "No fresh step-up token",
            body = ProblemDoc,
            content_type = "application/problem+json"
        ),
        (
            status = 409,
            description = "No suite this build can run is left on",
            body = ProblemDoc,
            content_type = "application/problem+json"
        ),
    )
);

doc!(
    doc_mismatch,
    get,
    path = "/admin/v1/federation/mismatches/{peer}",
    tag = "federation",
    security(("dpop" = [])),
    params(("peer" = String, Path, description = "The peer's server id")),
    responses(
        (
            status = 200,
            description = "The key the peer offered against the pinned one, when, and from where",
            body = MismatchDto
        ),
        (
            status = 404,
            description = "No mismatch is on record for this peer",
            body = ProblemDoc,
            content_type = "application/problem+json"
        ),
    )
);

doc!(
    doc_keep_blocking,
    post,
    path = "/admin/v1/federation/mismatches/{peer}/keep-blocking",
    tag = "federation",
    security(("dpop" = [])),
    params(
        ("peer" = String, Path, description = "The peer's server id"),
        (
            "Step-Up-Token" = String,
            Header,
            description = "A fresh step-up token"
        ),
    ),
    responses(
        (
            status = 200,
            description = "The decision is on record; the key stays refused",
            body = MismatchDto
        ),
        (
            status = 403,
            description = "No fresh step-up token",
            body = ProblemDoc,
            content_type = "application/problem+json"
        ),
        (
            status = 404,
            description = "No mismatch is on record for this peer",
            body = ProblemDoc,
            content_type = "application/problem+json"
        ),
    )
);

#[derive(OpenApi)]
#[openapi(
    info(
        title = "Kemlock Server federation admin API",
        description = "The admin routes of federation the web vault's screens use beyond the \
                       first version: the vaults that may be federated, reaching peers and \
                       comparing hash trees now, a peer's keys and descriptor, this server's own \
                       keys and suites, and a peer that offered another identity key.",
        version = "1.0.0"
    ),
    paths(
        doc_openapi, doc_overview, doc_peers, doc_promote, doc_accept_demotion, doc_held_promotions,
        doc_refuse_demotion, doc_address_changes, doc_approve_address_change,
        doc_refuse_address_change, doc_clear_contest, doc_shareable, doc_check,
        doc_consistency, doc_peer_security, doc_peer_descriptor, doc_self, doc_self_kem_rotation,
        doc_self_identity_rotation, doc_self_suites, doc_mismatch, doc_keep_blocking
    ),
    components(schemas(
        ProblemDoc, OverviewDto, ServerDto, PeerDto, AwaitingDto, VaultDto, OfferDto, AckDto,
        SwitchesDto, StatusDto, VaultStatusDto, PulledDto, PromotionDto, KeyChangeDto,
        ShareableDto, PeerCheckDto, ConsistencyDto, ComparisonDto, PeerSecurityDto, DescriptorDto,
        KemDto, SuiteRowDto, SelfDto, SuiteSettingDto, SuitesBody, SuiteChoice, MismatchDto,
        PausedDto, HeldDemotionDto, HeldPromotionDto, AddressChangeDto
    )),
    modifiers(&SecurityAddon)
)]
struct ApiDoc;

/// The OpenAPI document of the federation admin routes.
pub fn openapi() -> utoipa::openapi::OpenApi {
    ApiDoc::openapi()
}
