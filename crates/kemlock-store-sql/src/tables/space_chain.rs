//! The space chain's tables: `space_chain_records`, `space_chain_seals`, `space_chain_names`,
//! `space_chain_pending` and `space_held_items`.

pub(crate) mod records {
    use sea_orm::entity::prelude::*;

    #[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel)]
    #[sea_orm(table_name = "space_chain_records")]
    pub struct Model {
        #[sea_orm(primary_key, auto_increment = false)]
        pub space_id: Uuid,
        #[sea_orm(primary_key, auto_increment = false)]
        pub seq: i64,
        pub link: Vec<u8>,
        pub epoch: i64,
        pub signer: Uuid,
        pub at: i64,
        pub entry: Vec<u8>,
        pub signature: Vec<u8>,
        pub cosignature: Option<Vec<u8>>,
    }

    #[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
    pub enum Relation {}

    impl ActiveModelBehavior for ActiveModel {}
}

pub(crate) mod seals {
    use sea_orm::entity::prelude::*;

    #[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel)]
    #[sea_orm(table_name = "space_chain_seals")]
    pub struct Model {
        #[sea_orm(primary_key, auto_increment = false)]
        pub space_id: Uuid,
        #[sea_orm(primary_key, auto_increment = false)]
        pub seq: i64,
        #[sea_orm(primary_key, auto_increment = false)]
        pub key_ref: String,
        #[sea_orm(primary_key, auto_increment = false)]
        pub version: i64,
        #[sea_orm(primary_key, auto_increment = false)]
        pub member: Uuid,
        pub bundle_version: i64,
        pub sealed: Vec<u8>,
    }

    #[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
    pub enum Relation {}

    impl ActiveModelBehavior for ActiveModel {}
}

pub(crate) mod names {
    use sea_orm::entity::prelude::*;

    #[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel)]
    #[sea_orm(table_name = "space_chain_names")]
    pub struct Model {
        #[sea_orm(primary_key, auto_increment = false)]
        pub space_id: Uuid,
        #[sea_orm(primary_key, auto_increment = false)]
        pub seq: i64,
        #[sea_orm(primary_key, auto_increment = false)]
        pub target: String,
        pub version: i64,
        pub name_hash: Vec<u8>,
        pub sealed: Vec<u8>,
    }

    #[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
    pub enum Relation {}

    impl ActiveModelBehavior for ActiveModel {}
}

pub(crate) mod pending {
    use sea_orm::entity::prelude::*;

    #[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel)]
    #[sea_orm(table_name = "space_pending_changes")]
    pub struct Model {
        #[sea_orm(primary_key, auto_increment = false)]
        pub id: Uuid,
        pub space_id: Uuid,
        pub source: String,
        /// Unix seconds.
        pub queued_at: i64,
        pub requested_by: Option<Uuid>,
        pub via: String,
        pub account: Uuid,
        pub kind: String,
        pub role: Option<String>,
        pub custom: i64,
        pub collection: Option<Uuid>,
        pub permission: Option<String>,
        pub grants: String,
        pub status: String,
        pub done_at: Option<i64>,
    }

    #[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
    pub enum Relation {}

    impl ActiveModelBehavior for ActiveModel {}
}

pub(crate) mod held {
    use sea_orm::entity::prelude::*;

    #[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel)]
    #[sea_orm(table_name = "space_held_items")]
    pub struct Model {
        #[sea_orm(primary_key, auto_increment = false)]
        pub item_id: Uuid,
        pub space_id: Uuid,
    }

    #[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
    pub enum Relation {}

    impl ActiveModelBehavior for ActiveModel {}
}
