//! `GET /kem/v1/custom-fields` over HTTP against the fakes, with real DPoP.

mod common;

use axum::http::StatusCode;
use common::*;
use kemlock_api_kem::custom_fields_router;
use kemlock_api_kem::testing::DpopSigner;
use kemlock_app::admin::{CustomFieldRepo, SettingsRepo};
use kemlock_app::ports::StoreError;
use kemlock_domain::{CustomField, CustomFieldId, FieldKinds, FieldType};
use serde_json::json;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use time::macros::datetime;

/// Definitions and settings in memory.
#[derive(Clone, Default)]
struct MemFields {
    fields: Arc<Mutex<Vec<CustomField>>>,
    settings: Arc<Mutex<HashMap<String, String>>>,
}

impl CustomFieldRepo for MemFields {
    async fn custom_fields(&self) -> Result<Vec<CustomField>, StoreError> {
        Ok(self.fields.lock().expect("lock").clone())
    }

    async fn custom_field(&self, id: CustomFieldId) -> Result<Option<CustomField>, StoreError> {
        Ok(self
            .fields
            .lock()
            .expect("lock")
            .iter()
            .find(|f| f.id == id)
            .cloned())
    }

    async fn insert_custom_field(
        &self,
        field: &CustomField,
        _limit: usize,
    ) -> Result<bool, StoreError> {
        self.fields.lock().expect("lock").push(field.clone());
        Ok(true)
    }

    async fn update_custom_field(&self, _field: &CustomField) -> Result<(), StoreError> {
        Ok(())
    }

    async fn remove_custom_field(&self, _id: CustomFieldId) -> Result<bool, StoreError> {
        Ok(false)
    }
}

impl SettingsRepo for MemFields {
    async fn settings_with_prefix(
        &self,
        prefix: &str,
    ) -> Result<Vec<(String, String)>, StoreError> {
        Ok(self
            .settings
            .lock()
            .expect("lock")
            .iter()
            .filter(|(key, _)| key.starts_with(prefix))
            .map(|(key, value)| (key.clone(), value.clone()))
            .collect())
    }

    async fn put_setting(&self, key: &str, value: &str) -> Result<(), StoreError> {
        self.settings
            .lock()
            .expect("lock")
            .insert(key.to_owned(), value.to_owned());
        Ok(())
    }

    async fn delete_setting(&self, key: &str) -> Result<(), StoreError> {
        self.settings.lock().expect("lock").remove(key);
        Ok(())
    }
}

fn field(name: &str, field_type: FieldType, kinds: FieldKinds, hour: u8) -> CustomField {
    let at = datetime!(2026-11-25 00:00:00 UTC) + time::Duration::hours(i64::from(hour));
    CustomField::create(CustomFieldId::random(), name, field_type, kinds, at).expect("a field")
}

/// An app with the route merged beside the main router, and a signed-in device.
async fn scene() -> (Client, Session, MemFields) {
    let app = App::new(true);
    let fields = MemFields::default();
    let router = app
        .router
        .clone()
        .merge(custom_fields_router(app.api.clone(), fields.clone()));
    let client = Client::new(router, app.clock.clone(), DpopSigner::es256());
    let session = register_and_sign_in(&client, "ada@example.org").await;
    (client, session, fields)
}

#[tokio::test]
async fn a_signed_in_device_reads_the_fields_and_the_switch() {
    let (client, session, fields) = scene().await;
    let everywhere = field("Employee ID", FieldType::Text, FieldKinds::All, 1);
    let some = field(
        "Security question",
        FieldType::Hidden,
        FieldKinds::from_ids(&["login", "card"]).expect("kinds"),
        2,
    );
    fields
        .insert_custom_field(&everywhere, 100)
        .await
        .expect("insert");
    fields
        .insert_custom_field(&some, 100)
        .await
        .expect("insert");

    let reply = client
        .get_authed("/kem/v1/custom-fields", &session.access_token)
        .await;
    assert_eq!(reply.status, StatusCode::OK, "{:?}", reply.body);
    assert_eq!(
        reply.json(),
        json!({
            "fields": [
                {
                    "id": everywhere.id.to_string(),
                    "name": "Employee ID",
                    "type": "text",
                    "kinds": "all",
                },
                {
                    "id": some.id.to_string(),
                    "name": "Security question",
                    "type": "hidden",
                    "kinds": ["login", "card"],
                },
            ],
            "allowOwn": true,
        })
    );
}

#[tokio::test]
async fn the_switch_reads_back_off_when_an_admin_turned_it_off() {
    let (client, session, fields) = scene().await;
    let empty = client
        .get_authed("/kem/v1/custom-fields", &session.access_token)
        .await;
    assert_eq!(empty.json(), json!({"fields": [], "allowOwn": true}));

    fields
        .put_setting("custom_fields.allow_own", "false")
        .await
        .expect("put");
    let off = client
        .get_authed("/kem/v1/custom-fields", &session.access_token)
        .await;
    assert_eq!(off.json()["allowOwn"], false);
}

#[tokio::test]
async fn the_fields_need_a_signed_in_device() {
    let (client, _session, _fields) = scene().await;
    let reply = client
        .send("GET", "/kem/v1/custom-fields", Req::default())
        .await;
    assert_eq!(reply.status, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn the_document_names_the_route_and_its_shapes() {
    let app = App::new(false);
    let json = app.client().get("/kem/v1/openapi.json").await.json();
    assert!(json["paths"]["/kem/v1/custom-fields"]["get"].is_object());
    for schema in ["CustomFieldsDto", "CustomFieldDto", "KindsDto"] {
        assert!(
            json["components"]["schemas"][schema].is_object(),
            "{schema} is in the components"
        );
    }
}
