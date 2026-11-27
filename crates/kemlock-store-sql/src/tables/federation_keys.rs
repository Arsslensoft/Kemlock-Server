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

/// `peer_key_history`: the identity keys a peer used before its current one.
pub(crate) mod peer_key_history {
    use sea_orm::entity::prelude::*;

    #[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel)]
    #[sea_orm(table_name = "peer_key_history")]
    pub struct Model {
        #[sea_orm(primary_key, auto_increment = false)]
        pub peer: Uuid,
        /// 0 for the oldest.
        #[sea_orm(primary_key, auto_increment = false)]
        pub position: i64,
        pub identity_key: Vec<u8>,
        /// Unix seconds this server replaced the key.
        pub replaced_at: i64,
    }

    #[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
    pub enum Relation {}

    impl ActiveModelBehavior for ActiveModel {}
}

/// `peer_pending_addresses`: the address change a peer's rotation brought, held for the admin.
pub(crate) mod peer_pending_addresses {
    use sea_orm::entity::prelude::*;

    #[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel)]
    #[sea_orm(table_name = "peer_pending_addresses")]
    pub struct Model {
        #[sea_orm(primary_key, auto_increment = false)]
        pub peer: Uuid,
        pub operator: String,
        /// One address a line.
        pub addresses: String,
        /// One suite a line.
        pub suites: String,
        /// Unix seconds.
        pub received_at: i64,
    }

    #[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
    pub enum Relation {}

    impl ActiveModelBehavior for ActiveModel {}
}

/// `peer_held_rotations`: an identity-key rotation a peer signed, held for the admin.
pub(crate) mod peer_held_rotations {
    use sea_orm::entity::prelude::*;

    #[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel)]
    #[sea_orm(table_name = "peer_held_rotations")]
    pub struct Model {
        #[sea_orm(primary_key, auto_increment = false)]
        pub server: Uuid,
        /// SHA-256 of the new identity key, in hex.
        #[sea_orm(primary_key, auto_increment = false)]
        pub fingerprint: String,
        /// Unix seconds.
        pub issued_at: i64,
        /// Unix seconds.
        pub received_at: i64,
        pub envelope: Vec<u8>,
    }

    #[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
    pub enum Relation {}

    impl ActiveModelBehavior for ActiveModel {}
}

/// `peer_trusted_addresses`: the addresses of a peer the admin chose, which may be `http` or on a
/// private network.
pub(crate) mod peer_trusted_addresses {
    use sea_orm::entity::prelude::*;

    #[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel)]
    #[sea_orm(table_name = "peer_trusted_addresses")]
    pub struct Model {
        #[sea_orm(primary_key, auto_increment = false)]
        pub peer: Uuid,
        #[sea_orm(primary_key, auto_increment = false)]
        pub address: String,
    }

    #[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
    pub enum Relation {}

    impl ActiveModelBehavior for ActiveModel {}
}
