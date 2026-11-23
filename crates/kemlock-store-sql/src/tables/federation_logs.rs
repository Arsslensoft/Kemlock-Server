//! `peer_events`: event log entries a peer sent for a federated vault.

/// `peer_events`, keyed by the peer, the vault and the event's id.
pub(crate) mod peer_events {
    use sea_orm::entity::prelude::*;

    #[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel)]
    #[sea_orm(table_name = "peer_events")]
    pub struct Model {
        #[sea_orm(primary_key, auto_increment = false)]
        pub peer: Uuid,
        #[sea_orm(primary_key, auto_increment = false)]
        pub owner_type: i16,
        #[sea_orm(primary_key, auto_increment = false)]
        pub owner_id: Uuid,
        #[sea_orm(primary_key, auto_increment = false)]
        pub id: Uuid,
        /// Unix milliseconds.
        pub at_ms: i64,
        pub actor: Option<Uuid>,
        pub device: Option<Uuid>,
        pub action: String,
        pub target: Option<String>,
    }

    #[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
    pub enum Relation {}

    impl ActiveModelBehavior for ActiveModel {}
}
