//! `passkeys`: an account's WebAuthn credentials, with the PRF copy of the root key each holds.

use crate::convert::{corrupt, utc};
use kemlock_app::ports::StoreError;
use kemlock_domain::{Passkey, PasskeyId, PrfWrap, UserId};
use sea_orm::ActiveValue::Set;
use sea_orm::entity::prelude::*;

#[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel)]
#[sea_orm(table_name = "passkeys")]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false)]
    pub id: Uuid,
    pub user_id: Uuid,
    /// The WebAuthn credential id, up to 1,023 bytes, unique.
    pub credential_id: Vec<u8>,
    pub name: String,
    /// The WebAuthn library's credential, as JSON.
    pub credential: Vec<u8>,
    /// The root key wrapped under the PRF output, with the key version it was wrapped for.
    pub prf_wrapped_key: Option<Vec<u8>>,
    pub prf_key_version: Option<i64>,
    pub created_at: TimeDateTimeWithTimeZone,
    pub last_used_at: Option<TimeDateTimeWithTimeZone>,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

impl ActiveModelBehavior for ActiveModel {}

impl Model {
    pub(crate) fn into_domain(self) -> Result<Passkey, StoreError> {
        let prf_wrap = match (self.prf_wrapped_key, self.prf_key_version) {
            (Some(wrapped_key), Some(version)) => Some(PrfWrap {
                wrapped_key,
                key_version: u32::try_from(version).map_err(|_| corrupt("PRF key version"))?,
            }),
            (None, None) => None,
            _ => return Err(corrupt("PRF copy of the root key")),
        };
        Ok(Passkey {
            id: PasskeyId(self.id),
            user: UserId(self.user_id),
            credential_id: self.credential_id,
            name: self.name,
            credential: self.credential,
            prf_wrap,
            created_at: self.created_at,
            last_used_at: self.last_used_at,
        })
    }
}

pub(crate) fn active(passkey: &Passkey) -> ActiveModel {
    ActiveModel {
        id: Set(passkey.id.0),
        user_id: Set(passkey.user.0),
        credential_id: Set(passkey.credential_id.clone()),
        name: Set(passkey.name.clone()),
        credential: Set(passkey.credential.clone()),
        prf_wrapped_key: Set(passkey.prf_wrap.as_ref().map(|w| w.wrapped_key.clone())),
        prf_key_version: Set(passkey.prf_wrap.as_ref().map(|w| i64::from(w.key_version))),
        created_at: Set(utc(passkey.created_at)),
        last_used_at: Set(passkey.last_used_at.map(utc)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use time::macros::datetime;

    fn model() -> Model {
        Model {
            id: Uuid::new_v4(),
            user_id: Uuid::new_v4(),
            credential_id: vec![1, 2, 3],
            name: "Laptop".to_owned(),
            credential: b"{}".to_vec(),
            prf_wrapped_key: Some(vec![9; 92]),
            prf_key_version: Some(2),
            created_at: datetime!(2026-01-02 03:04:05 UTC),
            last_used_at: None,
        }
    }

    #[test]
    fn a_row_becomes_a_passkey_and_back() {
        let passkey = model().into_domain().expect("a valid row");
        assert_eq!(
            passkey.prf_wrap,
            Some(PrfWrap {
                wrapped_key: vec![9; 92],
                key_version: 2
            })
        );
        let active = active(&passkey);
        assert_eq!(active.prf_key_version, Set(Some(2)));
        assert_eq!(active.credential_id, Set(vec![1, 2, 3]));
    }

    #[test]
    fn a_passkey_without_prf_has_no_wrap() {
        let mut row = model();
        row.prf_wrapped_key = None;
        row.prf_key_version = None;
        assert_eq!(row.into_domain().expect("valid").prf_wrap, None);
    }

    #[test]
    fn half_a_wrap_or_a_negative_version_is_a_corrupt_row() {
        let mut half = model();
        half.prf_key_version = None;
        assert!(half.into_domain().is_err());
        let mut negative = model();
        negative.prf_key_version = Some(-1);
        assert!(negative.into_domain().is_err());
    }
}
