//! The Custom fields screen: the fields an admin offers for the items, and whether people may add
//! their own.
//!
//! A definition is a name, a type and the item types it applies to. The names and types are not
//! secret, so the server keeps them in the clear and every signed-in client reads them
//! ([`CustomFieldsView`], behind `GET /kem/v1/custom-fields`). The values never reach the server:
//! they live in the encrypted item bodies. Nothing is ever required. Every change goes to the event
//! log through [`Audit`].

use super::audit::Audit;
use super::error::AdminError;
use super::ports::{AdminEventRepo, AdminUserRepo, CustomFieldRepo, Mailer, SettingsRepo};
use crate::authenticate::Actor;
use crate::error::AppError;
use crate::ports::{Clock, StoreError};
use kemlock_domain::custom_field::MAX_FIELDS;
use kemlock_domain::{CustomField, CustomFieldId, FieldKinds, FieldType};
use std::net::IpAddr;

/// The setting that says whether people may add fields of their own. Absent means they may.
pub const ALLOW_OWN_KEY: &str = "custom_fields.allow_own";

/// The fields an admin defined and whether people may add their own.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FieldDefinitions {
    /// Oldest first.
    pub fields: Vec<CustomField>,
    pub allow_own: bool,
}

/// What an admin types for a field.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FieldInput {
    pub name: String,
    pub field_type: FieldType,
    pub kinds: FieldKinds,
}

/// Reads the definitions. Clients and the console both read through this.
#[derive(Debug)]
pub struct CustomFieldsView<R> {
    pub repo: R,
}

impl<R: CustomFieldRepo + SettingsRepo> CustomFieldsView<R> {
    pub async fn read(&self) -> Result<FieldDefinitions, AppError> {
        Ok(FieldDefinitions {
            fields: self.repo.custom_fields().await?,
            allow_own: self.allow_own().await?,
        })
    }

    /// Whether people may add fields of their own: yes until an admin says no.
    pub async fn allow_own(&self) -> Result<bool, AppError> {
        let rows = self.repo.settings_with_prefix(ALLOW_OWN_KEY).await?;
        Ok(rows
            .into_iter()
            .find(|(key, _)| key == ALLOW_OWN_KEY)
            .is_none_or(|(_, value)| value != "false"))
    }
}

/// The console's changes to the definitions.
#[derive(Debug)]
pub struct CustomFields<R, M, C> {
    pub repos: R,
    pub mail: M,
    pub clock: C,
}

impl<R, M, C> CustomFields<R, M, C>
where
    R: CustomFieldRepo + SettingsRepo + AdminEventRepo + AdminUserRepo + Clone,
    M: Mailer + Clone,
    C: Clock + Clone,
{
    fn view(&self) -> CustomFieldsView<R> {
        CustomFieldsView {
            repo: self.repos.clone(),
        }
    }

    fn audit(&self) -> Audit<R, R, M, C> {
        Audit {
            events: self.repos.clone(),
            users: self.repos.clone(),
            mail: self.mail.clone(),
            clock: self.clock.clone(),
        }
    }

    pub async fn list(&self) -> Result<FieldDefinitions, AdminError> {
        Ok(self.view().read().await?)
    }

    pub async fn create(
        &self,
        actor: &Actor,
        ip: Option<IpAddr>,
        input: FieldInput,
    ) -> Result<CustomField, AdminError> {
        let field = CustomField::create(
            CustomFieldId::random(),
            &input.name,
            input.field_type,
            input.kinds,
            self.clock.now(),
        )
        .map_err(|e| AdminError::Invalid(e.to_string()))?;
        // The store counts and stores in one step, so the cap holds against two admins at once.
        let stored = self
            .repos
            .insert_custom_field(&field, MAX_FIELDS)
            .await
            .map_err(name_taken)?;
        if !stored {
            return Err(AdminError::State("a server holds at most 100 custom fields"));
        }
        self.audit()
            .record(
                actor,
                ip,
                "admin.custom_field.create",
                Some(field.id.to_string()),
                "added a custom field",
            )
            .await;
        Ok(field)
    }

    pub async fn update(
        &self,
        actor: &Actor,
        ip: Option<IpAddr>,
        id: CustomFieldId,
        input: FieldInput,
    ) -> Result<CustomField, AdminError> {
        let stored = self
            .repos
            .custom_field(id)
            .await?
            .ok_or(AdminError::NotFound)?;
        let field = stored
            .revised(&input.name, input.field_type, input.kinds, self.clock.now())
            .map_err(|e| AdminError::Invalid(e.to_string()))?;
        self.repos
            .update_custom_field(&field)
            .await
            .map_err(name_taken)?;
        self.audit()
            .record(
                actor,
                ip,
                "admin.custom_field.update",
                Some(id.to_string()),
                "changed a custom field",
            )
            .await;
        Ok(field)
    }

    /// Removes the definition. Items that carry a value for it keep the value; the server can't
    /// read them, and the apps show an orphaned value as a field of the person's own.
    pub async fn delete(
        &self,
        actor: &Actor,
        ip: Option<IpAddr>,
        id: CustomFieldId,
    ) -> Result<(), AdminError> {
        if !self.repos.remove_custom_field(id).await? {
            return Err(AdminError::NotFound);
        }
        self.audit()
            .record(
                actor,
                ip,
                "admin.custom_field.delete",
                Some(id.to_string()),
                "removed a custom field",
            )
            .await;
        Ok(())
    }

    /// Lets people add fields of their own, or stops them. Fields already on items stay.
    pub async fn set_allow_own(
        &self,
        actor: &Actor,
        ip: Option<IpAddr>,
        allow: bool,
    ) -> Result<bool, AdminError> {
        let value = if allow { "true" } else { "false" };
        self.repos.put_setting(ALLOW_OWN_KEY, value).await?;
        self.audit()
            .record(
                actor,
                ip,
                "admin.custom_field.allow_own",
                Some(value.to_owned()),
                if allow {
                    "let people add their own custom fields"
                } else {
                    "stopped people adding their own custom fields"
                },
            )
            .await;
        Ok(allow)
    }
}

/// A taken name is the admin's to fix, so it is a state error with words, not a store failure.
fn name_taken(e: StoreError) -> AdminError {
    match e {
        StoreError::Duplicate => AdminError::State("another custom field already has that name"),
        other => AdminError::from(other),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use std::sync::{Arc, Mutex};
    use time::macros::datetime;

    /// Definitions and settings in memory.
    #[derive(Clone, Default)]
    struct Mem {
        fields: Arc<Mutex<Vec<CustomField>>>,
        settings: Arc<Mutex<HashMap<String, String>>>,
    }

    impl CustomFieldRepo for Mem {
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
            limit: usize,
        ) -> Result<bool, StoreError> {
            let mut fields = self.fields.lock().expect("lock");
            if fields.iter().any(|f| f.name_key() == field.name_key()) {
                return Err(StoreError::Duplicate);
            }
            if fields.len() >= limit {
                return Ok(false);
            }
            fields.push(field.clone());
            Ok(true)
        }

        async fn update_custom_field(&self, field: &CustomField) -> Result<(), StoreError> {
            let mut fields = self.fields.lock().expect("lock");
            if fields
                .iter()
                .any(|f| f.id != field.id && f.name_key() == field.name_key())
            {
                return Err(StoreError::Duplicate);
            }
            let slot = fields
                .iter_mut()
                .find(|f| f.id == field.id)
                .ok_or(StoreError::NotFound)?;
            *slot = field.clone();
            Ok(())
        }

        async fn remove_custom_field(&self, id: CustomFieldId) -> Result<bool, StoreError> {
            let mut fields = self.fields.lock().expect("lock");
            let before = fields.len();
            fields.retain(|f| f.id != id);
            Ok(fields.len() != before)
        }
    }

    impl SettingsRepo for Mem {
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

    fn field(name: &str) -> CustomField {
        CustomField::create(
            CustomFieldId::random(),
            name,
            FieldType::Text,
            FieldKinds::All,
            datetime!(2026-11-25 10:00:00 UTC),
        )
        .expect("a field")
    }

    #[tokio::test]
    async fn people_may_add_their_own_fields_until_an_admin_says_no() {
        let view = CustomFieldsView {
            repo: Mem::default(),
        };
        assert!(view.allow_own().await.expect("read"));
        view.repo
            .put_setting(ALLOW_OWN_KEY, "false")
            .await
            .expect("put");
        assert!(!view.allow_own().await.expect("read"));
        view.repo
            .put_setting(ALLOW_OWN_KEY, "true")
            .await
            .expect("put");
        assert!(view.allow_own().await.expect("read"));
    }

    #[tokio::test]
    async fn a_setting_with_a_longer_key_is_not_this_one() {
        let view = CustomFieldsView {
            repo: Mem::default(),
        };
        view.repo
            .put_setting("custom_fields.allow_own_later", "false")
            .await
            .expect("put");
        assert!(view.allow_own().await.expect("read"));
    }

    #[tokio::test]
    async fn the_view_lists_the_definitions_with_the_switch() {
        let repo = Mem::default();
        repo.insert_custom_field(&field("Employee ID"), 100)
            .await
            .expect("insert");
        let view = CustomFieldsView { repo };
        let read = view.read().await.expect("read");
        assert_eq!(read.fields.len(), 1);
        assert_eq!(read.fields[0].name, "Employee ID");
        assert!(read.allow_own);
    }

    #[test]
    fn a_taken_name_says_so() {
        assert_eq!(
            name_taken(StoreError::Duplicate),
            AdminError::State("another custom field already has that name")
        );
        assert_eq!(name_taken(StoreError::NotFound), AdminError::NotFound);
    }
}
