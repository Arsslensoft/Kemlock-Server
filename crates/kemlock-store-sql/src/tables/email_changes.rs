//! `email_changes`: an account's pending change of sign-in address, as `kemlock_domain::EmailChange`.

use crate::convert::{corrupt, from_i64_u32, utc};
use kemlock_app::ports::StoreError;
use kemlock_domain::{Email, EmailChange, KdfParams, UserId};
use sea_orm::ActiveValue::Set;
use sea_orm::entity::prelude::*;

#[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel)]
#[sea_orm(table_name = "email_changes")]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false)]
    pub user_id: Uuid,
    /// The address the account will have; lower-cased.
    pub email: String,
    /// The SHA-256 of the link's token, 32 bytes; unique.
    pub token_hash: Vec<u8>,
    pub opaque_record: Vec<u8>,
    pub kdf_memory_kib: i64,
    pub kdf_iterations: i64,
    pub kdf_parallelism: i64,
    pub kdf_salt: Vec<u8>,
    pub wrapped_root_key: Vec<u8>,
    /// The account's key version the wrap was made for.
    pub key_version: i64,
    pub requested_at: TimeDateTimeWithTimeZone,
    pub expires_at: TimeDateTimeWithTimeZone,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

impl ActiveModelBehavior for ActiveModel {}

impl Model {
    pub(crate) fn into_domain(self) -> Result<EmailChange, StoreError> {
        Ok(EmailChange {
            user: UserId(self.user_id),
            email: Email::parse(&self.email).map_err(|_| corrupt("pending email"))?,
            token_hash: self
                .token_hash
                .try_into()
                .map_err(|_| corrupt("email change token hash"))?,
            opaque_record: self.opaque_record,
            kdf: KdfParams {
                memory_kib: from_i64_u32(self.kdf_memory_kib, "kdf memory")?,
                iterations: from_i64_u32(self.kdf_iterations, "kdf iterations")?,
                parallelism: from_i64_u32(self.kdf_parallelism, "kdf parallelism")?,
                salt: self.kdf_salt,
            },
            wrapped_root_key: self.wrapped_root_key,
            key_version: from_i64_u32(self.key_version, "key version")?,
            requested_at: self.requested_at,
            expires_at: self.expires_at,
        })
    }
}

pub(crate) fn active(change: &EmailChange) -> ActiveModel {
    ActiveModel {
        user_id: Set(change.user.0),
        email: Set(change.email.as_str().to_owned()),
        token_hash: Set(change.token_hash.to_vec()),
        opaque_record: Set(change.opaque_record.clone()),
        kdf_memory_kib: Set(i64::from(change.kdf.memory_kib)),
        kdf_iterations: Set(i64::from(change.kdf.iterations)),
        kdf_parallelism: Set(i64::from(change.kdf.parallelism)),
        kdf_salt: Set(change.kdf.salt.clone()),
        wrapped_root_key: Set(change.wrapped_root_key.clone()),
        key_version: Set(i64::from(change.key_version)),
        requested_at: Set(utc(change.requested_at)),
        expires_at: Set(utc(change.expires_at)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use time::macros::datetime;

    fn sample() -> EmailChange {
        EmailChange {
            user: UserId::random(),
            email: Email::parse("New@Example.org").expect("an address"),
            token_hash: [3; 32],
            opaque_record: vec![1, 2, 3],
            kdf: KdfParams::new_account([7; 16]),
            wrapped_root_key: vec![9; 92],
            key_version: 2,
            requested_at: datetime!(2026-11-25 10:00:00 UTC),
            expires_at: datetime!(2026-11-26 10:00:00 UTC),
        }
    }

    fn model_of(change: &EmailChange) -> Model {
        Model {
            user_id: change.user.0,
            email: change.email.as_str().to_owned(),
            token_hash: change.token_hash.to_vec(),
            opaque_record: change.opaque_record.clone(),
            kdf_memory_kib: i64::from(change.kdf.memory_kib),
            kdf_iterations: i64::from(change.kdf.iterations),
            kdf_parallelism: i64::from(change.kdf.parallelism),
            kdf_salt: change.kdf.salt.clone(),
            wrapped_root_key: change.wrapped_root_key.clone(),
            key_version: i64::from(change.key_version),
            requested_at: change.requested_at,
            expires_at: change.expires_at,
        }
    }

    #[test]
    fn a_change_survives_the_trip_through_a_row() {
        let change = sample();
        assert_eq!(model_of(&change).into_domain(), Ok(change));
    }

    #[test]
    fn the_active_model_lower_cases_the_address_and_keeps_the_hash() {
        let a = active(&sample());
        assert_eq!(a.email, Set("new@example.org".to_owned()));
        assert_eq!(a.token_hash, Set(vec![3; 32]));
    }

    #[test]
    fn a_hash_of_another_length_is_a_corrupt_row() {
        let mut model = model_of(&sample());
        model.token_hash = vec![1; 16];
        assert!(model.into_domain().is_err());
    }
}
