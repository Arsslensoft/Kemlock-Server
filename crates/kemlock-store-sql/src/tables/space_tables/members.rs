//! `members`: one account's place in one space, with its role, state, the space key sealed to it
//! and the confirmer's signed statement.

use crate::convert::{corrupt, from_i64_u32, utc};
use kemlock_app::ports::StoreError;
use kemlock_domain::spaces::{
    Confirmation, CustomPermissions, KeyBoxSignature, Member, MemberState, SpaceRole,
};
use kemlock_domain::{SpaceId, UserId};
use sea_orm::ActiveValue::Set;
use sea_orm::entity::prelude::*;

#[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel)]
#[sea_orm(table_name = "members")]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false)]
    pub space_id: Uuid,
    #[sea_orm(primary_key, auto_increment = false)]
    pub user_id: Uuid,
    /// `owner`, `admin`, `custom` or `member`.
    pub role: String,
    pub custom_permissions: i64,
    /// `invited`, `accepted`, `confirmed` or `revoked`.
    pub state: String,
    pub invited_by: Uuid,
    pub invited_at: TimeDateTimeWithTimeZone,
    pub accepted_at: Option<TimeDateTimeWithTimeZone>,
    pub sealed_space_key: Option<Vec<u8>>,
    pub sealed_by: Option<Uuid>,
    pub sealed_by_key_version: Option<i64>,
    pub sealed_signature: Option<Vec<u8>>,
    pub key_version: Option<i64>,
    pub revoked_at: Option<TimeDateTimeWithTimeZone>,
    pub confirmed_by: Option<Uuid>,
    pub confirmed_at: Option<TimeDateTimeWithTimeZone>,
    pub confirmed_fingerprint: Option<Vec<u8>>,
    pub confirmed_key_version: Option<i64>,
    pub confirmation_statement: Option<Vec<u8>>,
    pub confirmation_signature: Option<Vec<u8>>,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

impl ActiveModelBehavior for ActiveModel {}

impl Model {
    pub(crate) fn into_domain(self) -> Result<Member, StoreError> {
        // A confirmation is all of its columns or none.
        let confirmation = match (
            self.confirmed_by,
            self.confirmed_at,
            self.confirmed_fingerprint,
            self.confirmed_key_version,
            self.confirmation_statement,
            self.confirmation_signature,
        ) {
            (
                Some(by),
                Some(at),
                Some(fingerprint),
                Some(version),
                Some(statement),
                Some(signature),
            ) => Some(Confirmation {
                by: UserId(by),
                at,
                fingerprint,
                member_key_version: from_i64_u32(version, "confirmed key version")?,
                statement,
                signature,
            }),
            (None, None, None, None, None, None) => None,
            _ => return Err(corrupt("member confirmation")),
        };
        let custom_bits =
            u16::try_from(self.custom_permissions).map_err(|_| corrupt("custom permissions"))?;
        Ok(Member {
            space: SpaceId(self.space_id),
            user: UserId(self.user_id),
            role: SpaceRole::parse(&self.role).ok_or_else(|| corrupt("space role"))?,
            custom: CustomPermissions::from_bits(custom_bits)
                .ok_or_else(|| corrupt("custom permissions"))?,
            state: MemberState::parse(&self.state).ok_or_else(|| corrupt("member state"))?,
            invited_by: UserId(self.invited_by),
            invited_at: self.invited_at,
            accepted_at: self.accepted_at,
            sealed_space_key: self.sealed_space_key,
            sealed_by: sealed_by_of(self.sealed_by, self.sealed_by_key_version, self.sealed_signature)?,
            key_version: self
                .key_version
                .map(|v| from_i64_u32(v, "member key version"))
                .transpose()?,
            confirmation,
            revoked_at: self.revoked_at,
        })
    }
}

pub(crate) fn active(member: &Member) -> ActiveModel {
    let confirmation = member.confirmation.as_ref();
    ActiveModel {
        space_id: Set(member.space.0),
        user_id: Set(member.user.0),
        role: Set(member.role.as_str().to_owned()),
        custom_permissions: Set(i64::from(member.custom.bits())),
        state: Set(member.state.as_str().to_owned()),
        invited_by: Set(member.invited_by.0),
        invited_at: Set(utc(member.invited_at)),
        accepted_at: Set(member.accepted_at.map(utc)),
        sealed_space_key: Set(member.sealed_space_key.clone()),
        sealed_by: Set(member.sealed_by.as_ref().map(|s| s.by.0)),
        sealed_by_key_version: Set(member.sealed_by.as_ref().map(|s| i64::from(s.key_version))),
        sealed_signature: Set(member.sealed_by.as_ref().map(|s| s.signature.clone())),
        key_version: Set(member.key_version.map(i64::from)),
        revoked_at: Set(member.revoked_at.map(utc)),
        confirmed_by: Set(confirmation.map(|c| c.by.0)),
        confirmed_at: Set(confirmation.map(|c| utc(c.at))),
        confirmed_fingerprint: Set(confirmation.map(|c| c.fingerprint.clone())),
        confirmed_key_version: Set(confirmation.map(|c| i64::from(c.member_key_version))),
        confirmation_statement: Set(confirmation.map(|c| c.statement.clone())),
        confirmation_signature: Set(confirmation.map(|c| c.signature.clone())),
    }
}

/// Who sealed a key copy: all three columns or none.
pub(crate) fn sealed_by_of(
    by: Option<Uuid>,
    key_version: Option<i64>,
    signature: Option<Vec<u8>>,
) -> Result<Option<KeyBoxSignature>, StoreError> {
    match (by, key_version, signature) {
        (Some(by), Some(version), Some(signature)) => Ok(Some(KeyBoxSignature {
            by: UserId(by),
            key_version: from_i64_u32(version, "sealer key version")?,
            signature,
        })),
        (None, None, None) => Ok(None),
        _ => Err(corrupt("key box signature")),
    }
}
