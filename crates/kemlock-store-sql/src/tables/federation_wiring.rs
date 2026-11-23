//! `peer_acknowledgements`, `vault_offers`, `replicated_accounts` and `federation_erasures`: the
//! rows behind consent, copied accounts and the erasures a home owes its replicas. Times are Unix
//! seconds in 64-bit columns, like the rest of federation's.

/// `peer_acknowledgements`: what an admin acknowledged when pairing with another operator.
pub(crate) mod peer_acknowledgements {
    use crate::convert::{from_i64, to_i64};
    use kemlock_app::ports::StoreError;
    use kemlock_federation::extra::Acknowledgement;
    use sea_orm::ActiveValue::Set;
    use sea_orm::entity::prelude::*;

    #[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel)]
    #[sea_orm(table_name = "peer_acknowledgements")]
    pub struct Model {
        #[sea_orm(primary_key, auto_increment = false)]
        pub peer: Uuid,
        pub metadata: bool,
        pub deletion: bool,
        pub cross_border: bool,
        pub acknowledged_by: String,
        pub acknowledged_at: i64,
    }

    #[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
    pub enum Relation {}

    impl ActiveModelBehavior for ActiveModel {}

    impl Model {
        pub(crate) fn into_domain(self) -> Result<Acknowledgement, StoreError> {
            Ok(Acknowledgement {
                metadata: self.metadata,
                deletion: self.deletion,
                cross_border: self.cross_border,
                by: self.acknowledged_by,
                at: from_i64(self.acknowledged_at, "acknowledged_at")?,
            })
        }
    }

    pub(crate) fn active(peer: Uuid, ack: &Acknowledgement) -> Result<ActiveModel, StoreError> {
        Ok(ActiveModel {
            peer: Set(peer),
            metadata: Set(ack.metadata),
            deletion: Set(ack.deletion),
            cross_border: Set(ack.cross_border),
            acknowledged_by: Set(ack.by.chars().take(128).collect()),
            acknowledged_at: Set(to_i64(ack.at, "acknowledged_at")?),
        })
    }
}

/// `vault_offers`: a vault a home offered this server.
pub(crate) mod vault_offers {
    use crate::convert::{corrupt, from_i64, to_i64};
    use crate::tables::items::{owner_from, owner_parts};
    use kemlock_app::ports::StoreError;
    use kemlock_domain::ServerId;
    use kemlock_federation::extra::StoredOffer;
    use kemlock_federation::message::OfferState;
    use sea_orm::ActiveValue::Set;
    use sea_orm::entity::prelude::*;

    #[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel)]
    #[sea_orm(table_name = "vault_offers")]
    pub struct Model {
        #[sea_orm(primary_key, auto_increment = false)]
        pub owner_type: i16,
        #[sea_orm(primary_key, auto_increment = false)]
        pub owner_id: Uuid,
        pub home: Uuid,
        pub epoch: i64,
        /// The replicas' 16-byte ids, in the home's order.
        pub replicas: Vec<u8>,
        /// `pending`, `accepted` or `declined`.
        pub state: String,
        pub received_at: i64,
    }

    #[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
    pub enum Relation {}

    impl ActiveModelBehavior for ActiveModel {}

    impl Model {
        pub(crate) fn into_domain(self) -> Result<StoredOffer, StoreError> {
            if !self.replicas.len().is_multiple_of(16) {
                return Err(corrupt("offer replica list"));
            }
            let replicas = self
                .replicas
                .as_chunks::<16>()
                .0
                .iter()
                .map(|c| {
                    let mut id = [0u8; 16];
                    id.copy_from_slice(c);
                    ServerId(Uuid::from_bytes(id))
                })
                .collect();
            Ok(StoredOffer {
                vault: owner_from(self.owner_type, self.owner_id)?,
                home: ServerId(self.home),
                epoch: from_i64(self.epoch, "offer epoch")?,
                replicas,
                state: OfferState::parse(&self.state).ok_or_else(|| corrupt("offer state"))?,
                received_at: from_i64(self.received_at, "received_at")?,
            })
        }
    }

    pub(crate) fn active(offer: &StoredOffer) -> Result<ActiveModel, StoreError> {
        let (owner_type, owner_id) = owner_parts(offer.vault);
        let mut replicas = Vec::with_capacity(offer.replicas.len() * 16);
        for r in &offer.replicas {
            replicas.extend_from_slice(r.as_bytes());
        }
        Ok(ActiveModel {
            owner_type: Set(owner_type),
            owner_id: Set(owner_id),
            home: Set(offer.home.0),
            epoch: Set(to_i64(offer.epoch, "offer epoch")?),
            replicas: Set(replicas),
            state: Set(offer.state.as_str().to_owned()),
            received_at: Set(to_i64(offer.received_at, "received_at")?),
        })
    }
}

/// `replicated_accounts`: accounts here that are copies of a home's.
pub(crate) mod replicated_accounts {
    use sea_orm::entity::prelude::*;

    #[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel)]
    #[sea_orm(table_name = "replicated_accounts")]
    pub struct Model {
        #[sea_orm(primary_key, auto_increment = false)]
        pub user_id: Uuid,
        pub home: Uuid,
        pub synced_at: i64,
    }

    #[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
    pub enum Relation {}

    impl ActiveModelBehavior for ActiveModel {}
}

/// `federation_erasures`: the erasures a home still has to tell a replica about.
pub(crate) mod federation_erasures {
    use sea_orm::entity::prelude::*;

    #[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel)]
    #[sea_orm(table_name = "federation_erasures")]
    pub struct Model {
        #[sea_orm(primary_key, auto_increment = false)]
        pub peer: Uuid,
        #[sea_orm(primary_key, auto_increment = false)]
        pub owner_type: i16,
        #[sea_orm(primary_key, auto_increment = false)]
        pub owner_id: Uuid,
        /// Unix seconds the home erased the vault.
        pub queued_at: i64,
    }

    #[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
    pub enum Relation {}

    impl ActiveModelBehavior for ActiveModel {}
}
