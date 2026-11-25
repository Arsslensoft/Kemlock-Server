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

/// More than a scenario stores, so the cap is not in its way.
const LIMIT: usize = 1000;

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
    assert_eq!(store.insert_custom_field(&cost, LIMIT).await, Ok(true));
    assert_eq!(store.insert_custom_field(&id, LIMIT).await, Ok(true));

    // What went in comes back as it went in: type, kinds and times.
    assert_eq!(store.custom_field(id.id).await, Ok(Some(id.clone())));
    assert_eq!(store.custom_field(cost.id).await, Ok(Some(cost.clone())));
    assert_eq!(
        store
            .custom_field(cost.id)
            .await
            .expect("read")
            .expect("there")
            .kinds,
        FieldKinds::Only(vec!["login".to_owned(), "card".to_owned()])
    );

    // Oldest first, whatever the order they were stored in.
    let listed = store.custom_fields().await.expect("list");
    assert_eq!(listed.len(), before + 2);
    let position =
        |wanted: CustomFieldId| listed.iter().position(|f| f.id == wanted).expect("listed");
    assert!(position(id.id) < position(cost.id));

    // A name another field has is taken, whatever the case.
    let twin = field(
        &id_name.to_uppercase(),
        FieldType::Text,
        FieldKinds::All,
        T2,
    );
    assert_eq!(
        store.insert_custom_field(&twin, LIMIT).await,
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
        .revised(
            &revised.name.to_lowercase(),
            FieldType::Text,
            FieldKinds::All,
            T2,
        )
        .expect("revised");
    assert_eq!(
        store.update_custom_field(&clash).await,
        Err(StoreError::Duplicate)
    );
    assert_eq!(store.custom_field(cost.id).await, Ok(Some(cost.clone())));
    // Saving it as it is changes nothing and is not an error.
    store
        .update_custom_field(&revised)
        .await
        .expect("same again");

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
    assert_eq!(store.insert_custom_field(&again, LIMIT).await, Ok(true));
    assert_eq!(store.remove_custom_field(again.id).await, Ok(true));
    assert_eq!(store.remove_custom_field(id.id).await, Ok(true));
}

/// Names that differ by an accent or a letter's case are told apart exactly as far as lowercase
/// goes: `Café` and `Cafe` are two fields (a binary collation on MySQL), `Café` and `CAFÉ` one.
async fn accents(store: &SqlStore) {
    let plain = unique("Cafe");
    let accented = plain.replacen("Cafe", "Café", 1);
    let shouted = accented.to_uppercase();
    let a = field(&plain, FieldType::Text, FieldKinds::All, T0);
    let b = field(&accented, FieldType::Text, FieldKinds::All, T1);
    let c = field(&shouted, FieldType::Text, FieldKinds::All, T2);
    assert_eq!(store.insert_custom_field(&a, LIMIT).await, Ok(true));
    assert_eq!(
        store.insert_custom_field(&b, LIMIT).await,
        Ok(true),
        "an accent makes it another name"
    );
    assert_eq!(
        store.insert_custom_field(&c, LIMIT).await,
        Err(StoreError::Duplicate),
        "capitals do not"
    );
    assert_eq!(store.remove_custom_field(a.id).await, Ok(true));
    assert_eq!(store.remove_custom_field(b.id).await, Ok(true));
}

/// The cap is kept by the store: once it holds `limit` more fields than it did, a field is not
/// stored and the answer is `false`, including when inserts come at once.
async fn cap(store: &SqlStore) {
    let before = store.custom_fields().await.expect("list").len();
    let limit = before + 3;
    let made: Vec<CustomField> = (0..6)
        .map(|n| {
            field(
                &unique(&format!("Capped {n}")),
                FieldType::Text,
                FieldKinds::All,
                T0,
            )
        })
        .collect();
    // All six at once, each from its own task.
    let tasks: Vec<_> = made
        .iter()
        .cloned()
        .map(|field| {
            let store = store.clone();
            tokio::spawn(async move { store.insert_custom_field(&field, limit).await })
        })
        .collect();
    let mut stored = Vec::new();
    for task in tasks {
        stored.push(task.await.expect("the task ran").expect("answers"));
    }
    assert_eq!(
        stored.iter().filter(|stored| **stored).count(),
        3,
        "{stored:?}"
    );
    assert_eq!(store.custom_fields().await.expect("list").len(), limit);
    // Full: a field is turned away; after a delete there is room again.
    let extra = field(&unique("One more"), FieldType::Text, FieldKinds::All, T1);
    assert_eq!(store.insert_custom_field(&extra, limit).await, Ok(false));
    assert_eq!(store.custom_field(extra.id).await, Ok(None));
    let kept = made
        .iter()
        .zip(&stored)
        .find(|(_, stored)| **stored)
        .map(|(field, _)| field.id)
        .expect("one was stored");
    assert_eq!(store.remove_custom_field(kept).await, Ok(true));
    assert_eq!(store.insert_custom_field(&extra, limit).await, Ok(true));
    for field in made.iter().chain([&extra]) {
        let _ = store.remove_custom_field(field.id).await;
    }
}

#[tokio::test]
async fn sqlite_in_memory() {
    let store = memory().await;
    fields(&store).await;
    accents(&store).await;
    cap(&store).await;
}

#[tokio::test]
async fn sqlite_in_a_file() {
    let (store, _dir) = file().await;
    fields(&store).await;
    accents(&store).await;
    cap(&store).await;
}

#[tokio::test]
async fn postgres_when_configured() {
    if let Some(store) = external("KEMLOCK_TEST_POSTGRES_URL").await {
        fields(&store).await;
        accents(&store).await;
        cap(&store).await;
    }
}

#[tokio::test]
async fn mysql_when_configured() {
    if let Some(store) = external("KEMLOCK_TEST_MYSQL_URL").await {
        fields(&store).await;
        accents(&store).await;
        cap(&store).await;
    }
}
