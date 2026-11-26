//! `GET /kem/v1/custom-fields`: the fields an admin offers for the items, and whether people may
//! add their own.
//!
//! Names and types are not secret, so every signed-in client reads them in the clear; the values
//! live in the encrypted item bodies and never reach the server. Nothing is ever required.
//!
//! The route needs a store that keeps the definitions (`CustomFieldRepo`), which `SqlStore` does
//! and the shared [`Store`] bound doesn't say, so it has a router of its own, like push tokens:
//! [`router`] takes the [`Api`] and that store, authenticates with the same DPoP-bound tokens, and
//! is merged beside the main router. It has no fallback.

use crate::extract::{Authed, DPOP_NONCE};
use crate::openapi::ProblemDoc;
use crate::problem::Problem;
use crate::state::{Api, Crypto, Store};
use axum::extract::{FromRequestParts, Request, State};
use axum::http::HeaderValue;
use axum::http::request::Parts;
use axum::middleware::{self, Next};
use axum::response::Response;
use axum::routing::get;
use axum::{Json, Router};
use kemlock_app::admin::{CustomFieldRepo, CustomFieldsView, FieldDefinitions, SettingsRepo};
use kemlock_app::ports::TokenSigner;
use kemlock_domain::{CustomField, FieldKinds};
use serde::{Deserialize, Serialize};
use utoipa::{OpenApi, ToSchema};
use uuid::Uuid;

/// The word that stands for every item type.
const ALL_KINDS: &str = "all";

/// The item types a field applies to.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(untagged)]
pub enum KindsDto {
    /// The word `all`: every type that takes custom fields, now and later.
    All(String),
    /// These item kinds only, such as `login` or `card`.
    Only(Vec<String>),
}

impl KindsDto {
    pub fn from_kinds(kinds: &FieldKinds) -> KindsDto {
        match kinds {
            FieldKinds::All => KindsDto::All(ALL_KINDS.to_owned()),
            FieldKinds::Only(kinds) => KindsDto::Only(kinds.clone()),
        }
    }

    /// The kinds a request names, or why they are refused.
    pub fn into_kinds(self) -> Result<FieldKinds, Problem> {
        match self {
            KindsDto::All(word) if word == ALL_KINDS => Ok(FieldKinds::All),
            KindsDto::All(_) => Err(Problem::bad_request(
                "kinds is the word \"all\" or a list of item kinds",
            )),
            KindsDto::Only(ids) => {
                FieldKinds::from_ids(&ids).map_err(|e| Problem::bad_request(e.to_string()))
            }
        }
    }
}

/// One field an admin offers.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct CustomFieldDto {
    pub id: Uuid,
    pub name: String,
    /// `text`, `hidden` or `checkbox`.
    #[serde(rename = "type")]
    pub field_type: String,
    pub kinds: KindsDto,
}

impl CustomFieldDto {
    pub fn from_field(field: &CustomField) -> CustomFieldDto {
        CustomFieldDto {
            id: field.id.0,
            name: field.name.clone(),
            field_type: field.field_type.as_str().to_owned(),
            kinds: KindsDto::from_kinds(&field.kinds),
        }
    }
}

/// The fields an admin offers, oldest first, and whether people may add their own.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct CustomFieldsDto {
    pub fields: Vec<CustomFieldDto>,
    /// Whether people may add fields of their own to an item. Off only when an admin turned it
    /// off; fields already on items stay.
    pub allow_own: bool,
}

impl CustomFieldsDto {
    pub fn from_definitions(definitions: &FieldDefinitions) -> CustomFieldsDto {
        CustomFieldsDto {
            fields: definitions
                .fields
                .iter()
                .map(CustomFieldDto::from_field)
                .collect(),
            allow_own: definitions.allow_own,
        }
    }
}

/// The router's state: the API's and the definitions' store.
struct Env<S, P, K, R> {
    api: Api<S, P, K>,
    fields: R,
}

impl<S, P, K, R: Clone> Clone for Env<S, P, K, R> {
    fn clone(&self) -> Self {
        Env {
            api: self.api.clone(),
            fields: self.fields.clone(),
        }
    }
}

/// An authenticated request: `Authed`, extracted from this router's state.
struct Caller;

impl<S, P, K, R> FromRequestParts<Env<S, P, K, R>> for Caller
where
    S: Store,
    P: Crypto,
    K: TokenSigner + Clone + 'static,
    R: CustomFieldRepo + SettingsRepo + Clone + 'static,
{
    type Rejection = Problem;

    async fn from_request_parts(parts: &mut Parts, env: &Env<S, P, K, R>) -> Result<Self, Problem> {
        Authed::from_request_parts(parts, &env.api)
            .await
            .map(|_| Caller)
    }
}

async fn list<S, P, K, R>(
    State(env): State<Env<S, P, K, R>>,
    _caller: Caller,
) -> Result<Json<CustomFieldsDto>, Problem>
where
    S: Store,
    P: Crypto,
    K: TokenSigner + Clone + 'static,
    R: CustomFieldRepo + SettingsRepo + Clone + 'static,
{
    let definitions = CustomFieldsView { repo: env.fields }.read().await?;
    Ok(Json(CustomFieldsDto::from_definitions(&definitions)))
}

/// Every response carries the current DPoP nonce, as the main router's do.
async fn nonce_header<S, P, K, R>(
    State(env): State<Env<S, P, K, R>>,
    request: Request,
    next: Next,
) -> Response
where
    S: Store,
    P: Crypto,
    K: TokenSigner + Clone + 'static,
    R: CustomFieldRepo + SettingsRepo + Clone + 'static,
{
    let mut response = next.run(request).await;
    if let Ok(value) = HeaderValue::from_str(&env.api.dpop.current_nonce(env.api.now())) {
        response.headers_mut().insert(DPOP_NONCE, value);
    }
    response
}

/// The custom-fields route. Merge it beside [`crate::router`]; it has no fallback.
///
/// ```text
/// GET /kem/v1/custom-fields
///     200 { "fields": [{ "id", "name", "type": "text" | "hidden" | "checkbox",
///                        "kinds": ["login", ...] | "all" }], "allowOwn": true }
/// ```
pub fn router<S, P, K, R>(api: Api<S, P, K>, fields: R) -> Router
where
    S: Store,
    P: Crypto,
    K: TokenSigner + Clone + 'static,
    R: CustomFieldRepo + SettingsRepo + Clone + 'static,
{
    let env = Env { api, fields };
    Router::new()
        .route("/kem/v1/custom-fields", get(list::<S, P, K, R>))
        .layer(middleware::from_fn_with_state(
            env.clone(),
            nonce_header::<S, P, K, R>,
        ))
        .with_state(env)
}

// ---- OpenAPI ----

#[utoipa::path(
    get, path = "/kem/v1/custom-fields", tag = "custom-fields",
    security(("dpop" = [])),
    responses(
        (status = 200, description = "The fields the admin offers for items, oldest first, and whether people may add their own. Names and types are in the clear; the values live in the items and never reach the server. Nothing is required", body = CustomFieldsDto),
        (status = 401, description = "Not signed in", body = ProblemDoc, content_type = "application/problem+json"),
    )
)]
#[allow(dead_code)]
fn doc_custom_fields_list() {}

/// The custom-fields route's part of `/kem/v1/openapi.json`.
#[derive(Debug, OpenApi)]
#[openapi(
    paths(doc_custom_fields_list),
    components(schemas(CustomFieldsDto, CustomFieldDto, KindsDto))
)]
struct CustomFieldsDoc;

/// The documented routes of this module, for `/kem/v1/openapi.json`.
pub(crate) fn document() -> utoipa::openapi::OpenApi {
    CustomFieldsDoc::openapi()
}

#[cfg(test)]
mod tests {
    use super::*;
    use kemlock_domain::{CustomFieldId, FieldType};
    use serde_json::json;
    use time::macros::datetime;

    fn field(name: &str, field_type: FieldType, kinds: FieldKinds) -> CustomField {
        CustomField::create(
            CustomFieldId::random(),
            name,
            field_type,
            kinds,
            datetime!(2026-11-25 10:00:00 UTC),
        )
        .expect("a field")
    }

    #[test]
    fn a_field_is_an_id_a_name_a_type_and_its_kinds() {
        let everywhere = field("Employee ID", FieldType::Text, FieldKinds::All);
        let cards = field(
            "Security question",
            FieldType::Hidden,
            FieldKinds::from_ids(&["login", "card"]).expect("kinds"),
        );
        let body = serde_json::to_value(CustomFieldsDto::from_definitions(&FieldDefinitions {
            fields: vec![everywhere.clone(), cards.clone()],
            allow_own: false,
        }))
        .expect("serialises");
        assert_eq!(
            body,
            json!({
                "fields": [
                    {
                        "id": everywhere.id.to_string(),
                        "name": "Employee ID",
                        "type": "text",
                        "kinds": "all",
                    },
                    {
                        "id": cards.id.to_string(),
                        "name": "Security question",
                        "type": "hidden",
                        "kinds": ["login", "card"],
                    },
                ],
                "allowOwn": false,
            })
        );
    }

    #[test]
    fn kinds_read_as_the_word_all_or_a_list() {
        let all: KindsDto = serde_json::from_value(json!("all")).expect("all");
        assert_eq!(all.into_kinds().expect("kinds"), FieldKinds::All);
        let some: KindsDto = serde_json::from_value(json!(["card", "login"])).expect("list");
        assert_eq!(
            some.into_kinds().expect("kinds"),
            FieldKinds::Only(vec!["login".to_owned(), "card".to_owned()])
        );
        let other: KindsDto = serde_json::from_value(json!("everything")).expect("a word");
        assert!(other.into_kinds().is_err());
        let empty: KindsDto = serde_json::from_value(json!([])).expect("a list");
        assert!(empty.into_kinds().is_err());
        let passkey: KindsDto = serde_json::from_value(json!(["passkey"])).expect("a list");
        assert!(passkey.into_kinds().is_err());
        assert!(serde_json::from_value::<KindsDto>(json!(7)).is_err());
    }
}
