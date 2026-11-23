//! `key_records`: signed identity-key rotations and revocations, kept to pass on.

pub(crate) mod key_records {
    use sea_orm::entity::prelude::*;

    #[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel)]
    #[sea_orm(table_name = "key_records")]
    pub struct Model {
        #[sea_orm(primary_key, auto_increment = false)]
        pub server: Uuid,
        #[sea_orm(primary_key, auto_increment = false)]
        pub kind: String,
        /// Unix seconds.
        pub issued_at: i64,
        pub envelope: Vec<u8>,
    }

    #[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
    pub enum Relation {}

    impl ActiveModelBehavior for ActiveModel {}
}

/// `learned_keys`: the identity key of a server we aren't paired with, vouched for by a peer.
pub(crate) mod learned_keys {
    use sea_orm::entity::prelude::*;

    #[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel)]
    #[sea_orm(table_name = "learned_keys")]
    pub struct Model {
        #[sea_orm(primary_key, auto_increment = false)]
        pub server: Uuid,
        pub identity_key: Vec<u8>,
        pub via: Uuid,
        /// Unix seconds.
        pub learned_at: i64,
    }

    #[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
    pub enum Relation {}

    impl ActiveModelBehavior for ActiveModel {}
}
