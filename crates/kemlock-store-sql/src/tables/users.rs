//! `users`: accounts, as `kemlock_domain::User`.

use crate::convert::{corrupt, from_i64_u32, utc};
use kemlock_app::ports::StoreError;
use kemlock_domain::{AccountMode, Email, KdfParams, Role, User, UserId};
use sea_orm::ActiveValue::Set;
use sea_orm::entity::prelude::*;

#[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel)]
#[sea_orm(table_name = "users")]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false)]
    pub id: Uuid,
    /// Lower-cased; unique.
    pub email: String,
    pub name: Option<String>,
    /// `kemlock-only` or `compatible`.
    pub mode: String,
    /// `user` or `admin`.
    pub role: String,
    pub kdf_memory_kib: i64,
    pub kdf_iterations: i64,
    pub kdf_parallelism: i64,
    pub kdf_salt: Vec<u8>,
    pub opaque_record: Option<Vec<u8>>,
    pub wrapped_root_key: Vec<u8>,
    pub public_bundle: Vec<u8>,
    pub bundle_signature: Vec<u8>,
    pub sealed_private_keys: Vec<u8>,
    pub key_version: i64,
    pub security_stamp: Uuid,
    pub created_at: TimeDateTimeWithTimeZone,
    pub updated_at: TimeDateTimeWithTimeZone,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

impl ActiveModelBehavior for ActiveModel {}

pub(crate) const ROLE_ADMIN: &str = "admin";

fn mode_str(mode: AccountMode) -> &'static str {
    match mode {
        AccountMode::KemlockOnly => "kemlock-only",
        AccountMode::Compatible => "compatible",
    }
}

fn mode_from(s: &str) -> Result<AccountMode, StoreError> {
    match s {
        "kemlock-only" => Ok(AccountMode::KemlockOnly),
        "compatible" => Ok(AccountMode::Compatible),
        _ => Err(corrupt("account mode")),
    }
}

fn role_str(role: Role) -> &'static str {
    match role {
        Role::User => "user",
        Role::Admin => ROLE_ADMIN,
    }
}

fn role_from(s: &str) -> Result<Role, StoreError> {
    match s {
        "user" => Ok(Role::User),
        ROLE_ADMIN => Ok(Role::Admin),
        _ => Err(corrupt("role")),
    }
}

impl Model {
    pub(crate) fn into_domain(self) -> Result<User, StoreError> {
        Ok(User {
            id: UserId(self.id),
            email: Email::parse(&self.email).map_err(|_| corrupt("email"))?,
            name: self.name,
            mode: mode_from(&self.mode)?,
            role: role_from(&self.role)?,
            kdf: KdfParams {
                memory_kib: from_i64_u32(self.kdf_memory_kib, "kdf memory")?,
                iterations: from_i64_u32(self.kdf_iterations, "kdf iterations")?,
                parallelism: from_i64_u32(self.kdf_parallelism, "kdf parallelism")?,
                salt: self.kdf_salt,
            },
            opaque_record: self.opaque_record,
            wrapped_root_key: self.wrapped_root_key,
            public_bundle: self.public_bundle,
            bundle_signature: self.bundle_signature,
            sealed_private_keys: self.sealed_private_keys,
            key_version: from_i64_u32(self.key_version, "key version")?,
            security_stamp: self.security_stamp,
            created_at: self.created_at,
            updated_at: self.updated_at,
        })
    }
}

/// Every column set, the id included: fit for an insert. An update drops the id with
/// `ActiveModel { id: NotSet, ..active(user) }`.
pub(crate) fn active(user: &User) -> ActiveModel {
    ActiveModel {
        id: Set(user.id.0),
        email: Set(user.email.as_str().to_owned()),
        name: Set(user.name.clone()),
        mode: Set(mode_str(user.mode).to_owned()),
        role: Set(role_str(user.role).to_owned()),
        kdf_memory_kib: Set(i64::from(user.kdf.memory_kib)),
        kdf_iterations: Set(i64::from(user.kdf.iterations)),
        kdf_parallelism: Set(i64::from(user.kdf.parallelism)),
        kdf_salt: Set(user.kdf.salt.clone()),
        opaque_record: Set(user.opaque_record.clone()),
        wrapped_root_key: Set(user.wrapped_root_key.clone()),
        public_bundle: Set(user.public_bundle.clone()),
        bundle_signature: Set(user.bundle_signature.clone()),
        sealed_private_keys: Set(user.sealed_private_keys.clone()),
        key_version: Set(i64::from(user.key_version)),
        security_stamp: Set(user.security_stamp),
        created_at: Set(utc(user.created_at)),
        updated_at: Set(utc(user.updated_at)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use time::macros::datetime;

    fn sample() -> User {
        User {
            id: UserId::random(),
            email: Email::parse("Ada@Example.org").expect("valid"),
            name: Some("Ada".to_owned()),
            mode: AccountMode::Compatible,
            role: Role::Admin,
            kdf: KdfParams::new_account([7; 16]),
            opaque_record: Some(vec![1, 2, 3]),
            wrapped_root_key: vec![4; 60],
            public_bundle: vec![5; 80],
            bundle_signature: vec![6; 70],
            sealed_private_keys: vec![8; 90],
            key_version: 2,
            security_stamp: Uuid::new_v4(),
            created_at: datetime!(2026-01-02 03:04:05 UTC),
            updated_at: datetime!(2026-02-03 04:05:06 UTC),
        }
    }

    fn model_of(user: &User) -> Model {
        Model {
            id: user.id.0,
            email: user.email.as_str().to_owned(),
            name: user.name.clone(),
            mode: mode_str(user.mode).to_owned(),
            role: role_str(user.role).to_owned(),
            kdf_memory_kib: i64::from(user.kdf.memory_kib),
            kdf_iterations: i64::from(user.kdf.iterations),
            kdf_parallelism: i64::from(user.kdf.parallelism),
            kdf_salt: user.kdf.salt.clone(),
            opaque_record: user.opaque_record.clone(),
            wrapped_root_key: user.wrapped_root_key.clone(),
            public_bundle: user.public_bundle.clone(),
            bundle_signature: user.bundle_signature.clone(),
            sealed_private_keys: user.sealed_private_keys.clone(),
            key_version: i64::from(user.key_version),
            security_stamp: user.security_stamp,
            created_at: user.created_at,
            updated_at: user.updated_at,
        }
    }

    #[test]
    fn a_user_survives_the_trip_through_a_row() {
        let user = sample();
        assert_eq!(model_of(&user).into_domain(), Ok(user));
    }

    #[test]
    fn the_active_model_sets_every_column() {
        let user = sample();
        let a = active(&user);
        assert_eq!(a.id, Set(user.id.0));
        assert_eq!(a.email, Set("ada@example.org".to_owned()));
        assert_eq!(a.role, Set("admin".to_owned()));
        assert_eq!(
            a.kdf_memory_kib,
            Set(i64::from(KdfParams::DEFAULT_MEMORY_KIB))
        );
    }

    #[test]
    fn unknown_words_are_refused() {
        let mut model = model_of(&sample());
        model.role = "root".to_owned();
        assert!(model.into_domain().is_err());
        assert!(mode_from("both").is_err());
    }
}
