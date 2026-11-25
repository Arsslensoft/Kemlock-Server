//! The custom fields port: `CustomFieldRepo` on `custom_fields`.
//!
//! Each scenario runs on every backend that is available, as `recovery_kits.rs` does: in-memory
//! SQLite, SQLite in a file, and PostgreSQL and MySQL when `KEMLOCK_TEST_POSTGRES_URL` /
//! `KEMLOCK_TEST_MYSQL_URL` are set.

mod common;

use common::{external, file, memory};
use kemlock_app::admin::CustomFieldRepo;
use kemlock_app::ports::StoreError;
use kemlock_domain::{CustomField, CustomFieldId, FieldKinds, FieldType};
use kemlock_store_sql::SqlStore;
use time::OffsetDateTime;
use time::macros::datetime;

const T0: OffsetDateTime = datetime!(2026-11-25 10:00:00 UTC);
const T1: OffsetDateTime = datetime!(2026-11-25 11:00:00 UTC);
const T2: OffsetDateTime = datetime!(2026-11-25 12:00:00 UTC);

/// A name no other scenario of this run uses: PostgreSQL and MySQL may hold earlier runs' rows.
fn unique(prefix: &str) -> String {
    format!("{prefix} {}", CustomFieldId::random())
}

fn field(name: &str, field_type: FieldType, kinds: FieldKinds, at: OffsetDateTime) -> CustomField {
    CustomField::create(CustomFieldId::random(), name, field_type, kinds, at).expect("a field")
}

fn only(ids: &[&str]) -> FieldKinds {
    FieldKinds::from_ids(ids).expect("kinds")
}

async fn fields(store: &SqlStore) {
    let before = store.custom_fields().await.expect("list").len();
    let id_name = unique("Employee ID");
    let cost_name = unique("Cost center");
    let id = field(&id_name, FieldType::Text, FieldKinds::All, T0);
    let cost = field(&cost_name, FieldType::Hidden, only(&["card", "login"]), T1);

    assert_eq!(store.custom_field(id.id).await, Ok(None));
    store.insert_custom_field(&cost).await.expect("insert");
    store.insert_custom_field(&id).await.expect("insert");

    // What went in comes back as it went in: type, kinds and times.
    assert_eq!(store.custom_field(id.id).await, Ok(Some(id.clone())));
    assert_eq!(store.custom_field(cost.id).await, Ok(Some(cost.clone())));
    assert_eq!(
        store.custom_field(cost.id).await.expect("read").expect("there").kinds,
        FieldKinds::Only(vec!["login".to_owned(), "card".to_owned()])
    );

    // Oldest first, whatever the order they were stored in.
    let listed = store.custom_fields().await.expect("list");
    assert_eq!(listed.len(), before + 2);
    let position = |wanted: CustomFieldId| {
        listed
            .iter()
            .position(|f| f.id == wanted)
            .expect("listed")
    };
    assert!(position(id.id) < position(cost.id));

    // A name another field has is taken, whatever the case.
    let twin = field(&id_name.to_uppercase(), FieldType::Text, FieldKinds::All, T2);
    assert_eq!(
        store.insert_custom_field(&twin).await,
        Err(StoreError::Duplicate)
    );
    assert_eq!(store.custom_field(twin.id).await, Ok(None));

    // A change keeps the id and the creation time, and the new name is unique too.
    let revised = id
        .revised(
            &unique("Staff number"),
            FieldType::Checkbox,
            only(&["note"]),
            T2,
        )
        .expect("revised");
    store.update_custom_field(&revised).await.expect("update");
    let read = store
        .custom_field(id.id)
        .await
        .expect("read")
        .expect("still there");
    assert_eq!(read, revised);
    assert_eq!(read.created_at, T0);
    assert_eq!(read.updated_at, T2);
    let clash = cost
        .revised(&revised.name.to_lowercase(), FieldType::Text, FieldKinds::All, T2)
        .expect("revised");
    assert_eq!(
        store.update_custom_field(&clash).await,
        Err(StoreError::Duplicate)
    );
    assert_eq!(store.custom_field(cost.id).await, Ok(Some(cost.clone())));
    // Saving it as it is changes nothing and is not an error.
    store.update_custom_field(&revised).await.expect("same again");

    // A field that is gone can't be changed.
    let ghost = field(&unique("Ghost"), FieldType::Text, FieldKinds::All, T2);
    assert_eq!(
        store.update_custom_field(&ghost).await,
        Err(StoreError::NotFound)
    );

    // Deleting says whether there was one, and frees the name.
    assert_eq!(store.remove_custom_field(cost.id).await, Ok(true));
    assert_eq!(store.remove_custom_field(cost.id).await, Ok(false));
    assert_eq!(store.custom_field(cost.id).await, Ok(None));
    let again = field(&cost_name, FieldType::Text, FieldKinds::All, T2);
    store.insert_custom_field(&again).await.expect("name is free");
    assert_eq!(store.remove_custom_field(again.id).await, Ok(true));
    assert_eq!(store.remove_custom_field(id.id).await, Ok(true));
}

#[tokio::test]
async fn sqlite_in_memory() {
    fields(&memory().await).await;
}

#[tokio::test]
async fn sqlite_in_a_file() {
    let (store, _dir) = file().await;
    fields(&store).await;
}

#[tokio::test]
async fn postgres_when_configured() {
    if let Some(store) = external("KEMLOCK_TEST_POSTGRES_URL").await {
        fields(&store).await;
    }
}

#[tokio::test]
async fn mysql_when_configured() {
    if let Some(store) = external("KEMLOCK_TEST_MYSQL_URL").await {
        fields(&store).await;
    }
}
