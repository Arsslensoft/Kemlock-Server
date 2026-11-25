//! Custom fields an admin defines for the server's items.
//!
//! A definition is a name, a type and the item types it applies to. The names and types are not
//! secret, so the server keeps them in the clear and every signed-in client reads them. The
//! values never reach the server: they live in the encrypted item bodies, which this module knows
//! nothing about. No field is ever required.

use crate::ids::CustomFieldId;
use time::OffsetDateTime;

/// The longest a field's name may be, in characters.
pub const MAX_NAME_CHARS: usize = 64;

/// The most definitions a server holds.
pub const MAX_FIELDS: usize = 100;

/// The item kinds a custom field may apply to, in the order the apps list their types. A file and
/// a passkey have no custom fields.
pub const FIELD_KINDS: [&str; 10] = [
    "login",
    "note",
    "otp",
    "backup-codes",
    "card",
    "identity",
    "contact",
    "certificate",
    "ssh-key",
    "pgp-key",
];

/// How a field's value is held and shown.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum FieldType {
    /// Text, shown as typed.
    Text,
    /// Text that stays masked until the person shows it.
    Hidden,
    /// A tick box.
    Checkbox,
}

impl FieldType {
    /// The word the API and the database use.
    pub fn as_str(self) -> &'static str {
        match self {
            FieldType::Text => "text",
            FieldType::Hidden => "hidden",
            FieldType::Checkbox => "checkbox",
        }
    }

    /// The type a word names, or `None` for any other.
    pub fn parse(word: &str) -> Option<FieldType> {
        match word {
            "text" => Some(FieldType::Text),
            "hidden" => Some(FieldType::Hidden),
            "checkbox" => Some(FieldType::Checkbox),
            _ => None,
        }
    }
}

/// Which item types a field applies to.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum FieldKinds {
    /// Every type that takes custom fields, now and later.
    All,
    /// These types only: at least one, each from [`FIELD_KINDS`], in that order, none twice.
    Only(Vec<String>),
}

/// What the store keeps for [`FieldKinds::All`].
const ALL_STORED: &str = "*";

impl FieldKinds {
    /// The types a request names. An empty list, or an id that is not in [`FIELD_KINDS`], is an
    /// error; repeats collapse and the order is the apps'.
    pub fn from_ids<S: AsRef<str>>(ids: &[S]) -> Result<FieldKinds, CustomFieldError> {
        let asked: Vec<&str> = ids.iter().map(|id| id.as_ref()).collect();
        if asked.is_empty() {
            return Err(CustomFieldError::NoKinds);
        }
        if let Some(unknown) = asked.iter().find(|id| !FIELD_KINDS.contains(id)) {
            return Err(CustomFieldError::UnknownKind((*unknown).to_owned()));
        }
        let kept: Vec<String> = FIELD_KINDS
            .iter()
            .filter(|kind| asked.contains(kind))
            .map(|kind| (*kind).to_owned())
            .collect();
        Ok(FieldKinds::Only(kept))
    }

    /// Whether a field with these kinds shows on an item of `kind`.
    pub fn applies_to(&self, kind: &str) -> bool {
        match self {
            FieldKinds::All => FIELD_KINDS.contains(&kind),
            FieldKinds::Only(kinds) => kinds.iter().any(|k| k == kind),
        }
    }

    /// The text the store keeps: `*`, or the ids joined by commas.
    pub fn to_stored(&self) -> String {
        match self {
            FieldKinds::All => ALL_STORED.to_owned(),
            FieldKinds::Only(kinds) => kinds.join(","),
        }
    }

    /// Reads what [`FieldKinds::to_stored`] wrote; `None` when it is not that.
    pub fn from_stored(text: &str) -> Option<FieldKinds> {
        if text == ALL_STORED {
            return Some(FieldKinds::All);
        }
        let ids: Vec<&str> = text.split(',').collect();
        match FieldKinds::from_ids(&ids) {
            Ok(kinds) if kinds.to_stored() == text => Some(kinds),
            _ => None,
        }
    }
}

/// Why a definition is refused. The text is for the admin who typed it.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum CustomFieldError {
    #[error("the name can't be empty")]
    EmptyName,
    #[error("the name can be at most 64 characters")]
    NameTooLong,
    #[error("the name can't contain control characters")]
    BadName,
    #[error("pick at least one item type, or all of them")]
    NoKinds,
    #[error("{0} isn't an item type that takes custom fields")]
    UnknownKind(String),
}

/// A name as kept: whitespace trimmed and runs of it made one space.
pub fn clean_name(raw: &str) -> Result<String, CustomFieldError> {
    let name = raw.split_whitespace().collect::<Vec<_>>().join(" ");
    if name.is_empty() {
        return Err(CustomFieldError::EmptyName);
    }
    if name.chars().any(char::is_control) {
        return Err(CustomFieldError::BadName);
    }
    if name.chars().count() > MAX_NAME_CHARS {
        return Err(CustomFieldError::NameTooLong);
    }
    Ok(name)
}

/// One definition.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CustomField {
    pub id: CustomFieldId,
    /// Unique across the server, whatever the case.
    pub name: String,
    pub field_type: FieldType,
    pub kinds: FieldKinds,
    pub created_at: OffsetDateTime,
    pub updated_at: OffsetDateTime,
}

impl CustomField {
    /// A new definition. The name is cleaned; nothing is required of the person who fills it in.
    pub fn create(
        id: CustomFieldId,
        name: &str,
        field_type: FieldType,
        kinds: FieldKinds,
        now: OffsetDateTime,
    ) -> Result<CustomField, CustomFieldError> {
        Ok(CustomField {
            id,
            name: clean_name(name)?,
            field_type,
            kinds,
            created_at: now,
            updated_at: now,
        })
    }

    /// This definition with a new name, type and kinds. The id and the creation time stay.
    pub fn revised(
        &self,
        name: &str,
        field_type: FieldType,
        kinds: FieldKinds,
        now: OffsetDateTime,
    ) -> Result<CustomField, CustomFieldError> {
        Ok(CustomField {
            id: self.id,
            name: clean_name(name)?,
            field_type,
            kinds,
            created_at: self.created_at,
            updated_at: now,
        })
    }

    /// What the store compares to keep names unique: the name in lowercase.
    pub fn name_key(&self) -> String {
        self.name.to_lowercase()
    }

    /// Whether the field shows on an item of `kind`.
    pub fn applies_to(&self, kind: &str) -> bool {
        self.kinds.applies_to(kind)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use time::macros::datetime;

    const T0: OffsetDateTime = datetime!(2026-11-25 10:00:00 UTC);
    const T1: OffsetDateTime = datetime!(2026-11-25 11:00:00 UTC);

    #[test]
    fn types_have_one_word_each() {
        for (word, field_type) in [
            ("text", FieldType::Text),
            ("hidden", FieldType::Hidden),
            ("checkbox", FieldType::Checkbox),
        ] {
            assert_eq!(FieldType::parse(word), Some(field_type));
            assert_eq!(field_type.as_str(), word);
        }
        assert_eq!(FieldType::parse("Text"), None);
        assert_eq!(FieldType::parse("password"), None);
        assert_eq!(FieldType::parse(""), None);
    }

    #[test]
    fn a_name_is_cleaned_and_bounded() {
        assert_eq!(clean_name("  Cost \t center "), Ok("Cost center".to_owned()));
        assert_eq!(clean_name(""), Err(CustomFieldError::EmptyName));
        assert_eq!(clean_name(" \n "), Err(CustomFieldError::EmptyName));
        assert_eq!(clean_name("a\u{7}b"), Err(CustomFieldError::BadName));
        assert!(clean_name(&"x".repeat(64)).is_ok());
        assert_eq!(
            clean_name(&"x".repeat(65)),
            Err(CustomFieldError::NameTooLong)
        );
        // Characters, not bytes.
        assert!(clean_name(&"é".repeat(64)).is_ok());
    }

    #[test]
    fn kinds_come_from_the_known_ids_in_the_apps_order() {
        let kinds = FieldKinds::from_ids(&["card", "login", "card"]).expect("kinds");
        assert_eq!(
            kinds,
            FieldKinds::Only(vec!["login".to_owned(), "card".to_owned()])
        );
        assert_eq!(
            FieldKinds::from_ids::<&str>(&[]),
            Err(CustomFieldError::NoKinds)
        );
        assert_eq!(
            FieldKinds::from_ids(&["login", "passkey"]),
            Err(CustomFieldError::UnknownKind("passkey".to_owned()))
        );
        assert_eq!(
            FieldKinds::from_ids(&["file"]),
            Err(CustomFieldError::UnknownKind("file".to_owned()))
        );
    }

    #[test]
    fn kinds_round_trip_through_the_store() {
        let all = FieldKinds::All;
        assert_eq!(all.to_stored(), "*");
        assert_eq!(FieldKinds::from_stored("*"), Some(FieldKinds::All));
        let some = FieldKinds::from_ids(&["ssh-key", "login"]).expect("kinds");
        assert_eq!(some.to_stored(), "login,ssh-key");
        assert_eq!(FieldKinds::from_stored("login,ssh-key"), Some(some));
        for bad in ["", "login,", "card,login", "login,login", "passkey", "LOGIN"] {
            assert_eq!(FieldKinds::from_stored(bad), None, "{bad:?}");
        }
    }

    #[test]
    fn a_field_applies_to_the_kinds_it_names() {
        let everywhere = CustomField::create(
            CustomFieldId::random(),
            "ID",
            FieldType::Text,
            FieldKinds::All,
            T0,
        )
        .expect("field");
        assert!(everywhere.applies_to("login"));
        assert!(everywhere.applies_to("pgp-key"));
        assert!(!everywhere.applies_to("passkey"), "a passkey takes none");
        assert!(!everywhere.applies_to("file"), "a file takes none");

        let cards = CustomField::create(
            CustomFieldId::random(),
            "Cost center",
            FieldType::Text,
            FieldKinds::from_ids(&["card"]).expect("kinds"),
            T0,
        )
        .expect("field");
        assert!(cards.applies_to("card"));
        assert!(!cards.applies_to("login"));
    }

    #[test]
    fn a_revision_keeps_the_id_and_the_creation_time() {
        let field = CustomField::create(
            CustomFieldId::random(),
            "Employee ID",
            FieldType::Text,
            FieldKinds::All,
            T0,
        )
        .expect("field");
        let revised = field
            .revised(
                " Staff number ",
                FieldType::Hidden,
                FieldKinds::from_ids(&["login"]).expect("kinds"),
                T1,
            )
            .expect("revised");
        assert_eq!(revised.id, field.id);
        assert_eq!(revised.created_at, T0);
        assert_eq!(revised.updated_at, T1);
        assert_eq!(revised.name, "Staff number");
        assert_eq!(revised.field_type, FieldType::Hidden);
        assert!(
            field
                .revised("", FieldType::Text, FieldKinds::All, T1)
                .is_err()
        );
    }

    #[test]
    fn names_are_compared_without_case() {
        let make = |name: &str| {
            CustomField::create(
                CustomFieldId::random(),
                name,
                FieldType::Text,
                FieldKinds::All,
                T0,
            )
            .expect("field")
        };
        let (a, b) = (make("Employee ID"), make("employee id"));
        assert_eq!(a.name_key(), b.name_key());
    }
}
