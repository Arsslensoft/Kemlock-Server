//! `refresh_tokens`: refresh tokens by the SHA-256 of their value.

use crate::convert::{corrupt, utc};
use kemlock_app::ports::{RefreshToken, StoreError, TokenApi};
use kemlock_domain::{DeviceId, UserId};
use sea_orm::ActiveValue::Set;
use sea_orm::entity::prelude::*;

#[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel)]
#[sea_orm(table_name = "refresh_tokens")]
pub struct Model {
    /// The token's SHA-256, 32 bytes.
    #[sea_orm(primary_key, auto_increment = false)]
    pub hash: Vec<u8>,
    pub family: Uuid,
    pub user_id: Uuid,
    pub device_id: Uuid,
    /// The account's security stamp when the token was issued.
    pub security_stamp: Uuid,
    pub created_at: TimeDateTimeWithTimeZone,
    pub expires_at: TimeDateTimeWithTimeZone,
    pub used_at: Option<TimeDateTimeWithTimeZone>,
    /// The API that issued it (`TokenApi::as_i16`); 0 for a token from before the column.
    pub api: i16,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

impl ActiveModelBehavior for ActiveModel {}

impl Model {
    pub(crate) fn into_domain(self) -> Result<RefreshToken, StoreError> {
        let hash: [u8; 32] = self
            .hash
            .try_into()
            .map_err(|_| corrupt("refresh token hash"))?;
        Ok(RefreshToken {
            hash,
            family: self.family,
            user: UserId(self.user_id),
            device: DeviceId(self.device_id),
            security_stamp: self.security_stamp,
            created_at: self.created_at,
            expires_at: self.expires_at,
            used_at: self.used_at,
            api: TokenApi::from_i16(self.api),
        })
    }
}

pub(crate) fn active(token: &RefreshToken) -> ActiveModel {
    ActiveModel {
        hash: Set(token.hash.to_vec()),
        family: Set(token.family),
        user_id: Set(token.user.0),
        device_id: Set(token.device.0),
        security_stamp: Set(token.security_stamp),
        created_at: Set(utc(token.created_at)),
        expires_at: Set(utc(token.expires_at)),
        used_at: Set(token.used_at.map(utc)),
        api: Set(token.api.as_i16()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use time::macros::datetime;

    #[test]
    fn a_token_survives_the_trip_through_a_row() {
        let token = RefreshToken {
            hash: [9; 32],
            family: Uuid::new_v4(),
            user: UserId::random(),
            device: DeviceId::random(),
            security_stamp: Uuid::new_v4(),
            created_at: datetime!(2026-01-02 03:04:05 UTC),
            expires_at: datetime!(2026-02-02 03:04:05 UTC),
            used_at: Some(datetime!(2026-01-03 03:04:05 UTC)),
            api: TokenApi::Bitwarden,
        };
        let model = Model {
            hash: token.hash.to_vec(),
            family: token.family,
            user_id: token.user.0,
            device_id: token.device.0,
            security_stamp: token.security_stamp,
            created_at: token.created_at,
            expires_at: token.expires_at,
            used_at: token.used_at,
            api: token.api.as_i16(),
        };
        assert_eq!(model.into_domain(), Ok(token.clone()));
        assert_eq!(active(&token).hash, Set(vec![9; 32]));
    }

    #[test]
    fn a_short_hash_is_corrupt() {
        let model = Model {
            hash: vec![1; 31],
            family: Uuid::new_v4(),
            user_id: Uuid::new_v4(),
            device_id: Uuid::new_v4(),
            security_stamp: Uuid::new_v4(),
            created_at: datetime!(2026-01-02 03:04:05 UTC),
            expires_at: datetime!(2026-02-02 03:04:05 UTC),
            used_at: None,
            api: 0,
        };
        assert!(model.into_domain().is_err());
    }
}
