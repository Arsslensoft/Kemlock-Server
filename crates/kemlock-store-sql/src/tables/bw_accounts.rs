//! `bw_accounts`: the Bitwarden record of an account, as `kemlock_app::bitwarden::BwAccount`.

use crate::convert::{corrupt, from_i64_u32};
use kemlock_app::bitwarden::BwAccount;
use kemlock_app::ports::StoreError;
use kemlock_domain::UserId;
use sea_orm::ActiveValue::Set;
use sea_orm::entity::prelude::*;

#[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel)]
#[sea_orm(table_name = "bw_accounts")]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false)]
    pub user_id: Uuid,
    pub password_hash: Vec<u8>,
    pub salt: Vec<u8>,
    pub password_iterations: i64,
    pub kdf_type: i64,
    pub kdf_iterations: i64,
    pub kdf_memory: Option<i64>,
    pub kdf_parallelism: Option<i64>,
    pub akey: String,
    pub private_key: Option<String>,
    pub public_key: Option<String>,
    pub password_hint: Option<String>,
    pub api_key: Option<String>,
    pub avatar_color: Option<String>,
    pub revision_ms: i64,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

impl ActiveModelBehavior for ActiveModel {}

fn to_i32(value: i64, what: &str) -> Result<i32, StoreError> {
    i32::try_from(value).map_err(|_| corrupt(what))
}

fn opt_i32(value: Option<i64>, what: &str) -> Result<Option<i32>, StoreError> {
    value.map(|v| to_i32(v, what)).transpose()
}

impl Model {
    pub(crate) fn into_domain(self) -> Result<BwAccount, StoreError> {
        Ok(BwAccount {
            user: UserId(self.user_id),
            password_hash: self.password_hash,
            salt: self.salt,
            password_iterations: from_i64_u32(self.password_iterations, "password iterations")?,
            kdf_type: to_i32(self.kdf_type, "kdf type")?,
            kdf_iterations: to_i32(self.kdf_iterations, "kdf iterations")?,
            kdf_memory: opt_i32(self.kdf_memory, "kdf memory")?,
            kdf_parallelism: opt_i32(self.kdf_parallelism, "kdf parallelism")?,
            akey: self.akey,
            private_key: self.private_key,
            public_key: self.public_key,
            password_hint: self.password_hint,
            api_key: self.api_key,
            avatar_color: self.avatar_color,
            revision_ms: self.revision_ms,
        })
    }
}

/// Every column set, the user id and revision date included: fit for an insert. An update drops
/// those two with `ActiveModel { user_id: NotSet, revision_ms: NotSet, ..active(account) }`.
pub(crate) fn active(account: &BwAccount) -> ActiveModel {
    ActiveModel {
        user_id: Set(account.user.0),
        password_hash: Set(account.password_hash.clone()),
        salt: Set(account.salt.clone()),
        password_iterations: Set(i64::from(account.password_iterations)),
        kdf_type: Set(i64::from(account.kdf_type)),
        kdf_iterations: Set(i64::from(account.kdf_iterations)),
        kdf_memory: Set(account.kdf_memory.map(i64::from)),
        kdf_parallelism: Set(account.kdf_parallelism.map(i64::from)),
        akey: Set(account.akey.clone()),
        private_key: Set(account.private_key.clone()),
        public_key: Set(account.public_key.clone()),
        password_hint: Set(account.password_hint.clone()),
        api_key: Set(account.api_key.clone()),
        avatar_color: Set(account.avatar_color.clone()),
        revision_ms: Set(account.revision_ms),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn account() -> BwAccount {
        BwAccount {
            user: UserId::random(),
            password_hash: vec![1; 32],
            salt: vec![2; 64],
            password_iterations: 600_000,
            kdf_type: 1,
            kdf_iterations: 3,
            kdf_memory: Some(64),
            kdf_parallelism: Some(4),
            akey: "2.a|b|c".to_owned(),
            private_key: Some("2.d|e|f".to_owned()),
            public_key: Some("MIIB".to_owned()),
            password_hint: None,
            api_key: Some("k".repeat(30)),
            avatar_color: None,
            revision_ms: 1_794_000_000_000,
        }
    }

    fn model_of(a: &BwAccount) -> Model {
        Model {
            user_id: a.user.0,
            password_hash: a.password_hash.clone(),
            salt: a.salt.clone(),
            password_iterations: i64::from(a.password_iterations),
            kdf_type: i64::from(a.kdf_type),
            kdf_iterations: i64::from(a.kdf_iterations),
            kdf_memory: a.kdf_memory.map(i64::from),
            kdf_parallelism: a.kdf_parallelism.map(i64::from),
            akey: a.akey.clone(),
            private_key: a.private_key.clone(),
            public_key: a.public_key.clone(),
            password_hint: a.password_hint.clone(),
            api_key: a.api_key.clone(),
            avatar_color: a.avatar_color.clone(),
            revision_ms: a.revision_ms,
        }
    }

    #[test]
    fn an_account_survives_the_trip_through_a_row() {
        let a = account();
        assert_eq!(model_of(&a).into_domain(), Ok(a.clone()));
        assert_eq!(active(&a).kdf_memory, Set(Some(64)));
    }

    #[test]
    fn out_of_range_numbers_are_corrupt() {
        let mut m = model_of(&account());
        m.kdf_type = i64::from(i32::MAX) + 1;
        assert!(m.clone().into_domain().is_err());
        m.kdf_type = 1;
        m.password_iterations = -1;
        assert!(m.into_domain().is_err());
    }
}
