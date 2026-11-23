//! `peer_security` and `peer_mismatches`: what the console shows of a peer's descriptor and of a
//! key it offered that was not the pinned one. Times are Unix seconds in 64-bit columns.

use crate::convert::{from_i64, to_i64};
use kemlock_app::ports::StoreError;
use kemlock_domain::ServerId;
use kemlock_federation::insight::{MismatchRecord, PeerSecurityRecord};

/// `peer_security`: the last verified descriptor of a peer and its KEM key's first sighting.
pub(crate) mod peer_security {
    use sea_orm::entity::prelude::*;

    #[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel)]
    #[sea_orm(table_name = "peer_security")]
    pub struct Model {
        #[sea_orm(primary_key, auto_increment = false)]
        pub peer: Uuid,
        pub descriptor: Vec<u8>,
        pub fetched_at: i64,
        pub kem_key_id: Vec<u8>,
        pub kem_first_seen: i64,
        pub suite: Option<String>,
    }

    #[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
    pub enum Relation {}

    impl ActiveModelBehavior for ActiveModel {}
}

/// `peer_mismatches`: a peer that offered an identity key other than the pinned one.
pub(crate) mod peer_mismatches {
    use sea_orm::entity::prelude::*;

    #[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel)]
    #[sea_orm(table_name = "peer_mismatches")]
    pub struct Model {
        #[sea_orm(primary_key, auto_increment = false)]
        pub peer: Uuid,
        pub offered_key: Vec<u8>,
        pub first_at: i64,
        pub last_at: i64,
        pub attempts: i64,
        pub source: String,
        pub kept_blocking_at: Option<i64>,
        pub kept_blocking_by: Option<String>,
    }

    #[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
    pub enum Relation {}

    impl ActiveModelBehavior for ActiveModel {}
}

impl peer_security::Model {
    pub(crate) fn into_domain(self) -> Result<PeerSecurityRecord, StoreError> {
        Ok(PeerSecurityRecord {
            peer: ServerId(self.peer),
            descriptor: self.descriptor,
            fetched_at: from_i64(self.fetched_at, "descriptor fetch time")?,
            kem_key_id: self.kem_key_id,
            kem_first_seen: from_i64(self.kem_first_seen, "KEM first seen")?,
            suite: self.suite,
        })
    }
}

pub(crate) fn security_active(
    record: &PeerSecurityRecord,
) -> Result<peer_security::ActiveModel, StoreError> {
    use sea_orm::ActiveValue::Set;
    Ok(peer_security::ActiveModel {
        peer: Set(record.peer.0),
        descriptor: Set(record.descriptor.clone()),
        fetched_at: Set(to_i64(record.fetched_at, "descriptor fetch time")?),
        kem_key_id: Set(record.kem_key_id.clone()),
        kem_first_seen: Set(to_i64(record.kem_first_seen, "KEM first seen")?),
        suite: Set(record.suite.as_ref().map(|s| s.chars().take(64).collect())),
    })
}

impl peer_mismatches::Model {
    pub(crate) fn into_domain(self) -> Result<MismatchRecord, StoreError> {
        Ok(MismatchRecord {
            peer: ServerId(self.peer),
            offered_key: self.offered_key,
            first_at: from_i64(self.first_at, "mismatch first time")?,
            last_at: from_i64(self.last_at, "mismatch last time")?,
            attempts: from_i64(self.attempts, "mismatch attempts")?,
            source: self.source,
            kept_blocking_at: self
                .kept_blocking_at
                .map(|t| from_i64(t, "kept blocking time"))
                .transpose()?,
            kept_blocking_by: self.kept_blocking_by,
        })
    }
}

pub(crate) fn mismatch_active(
    record: &MismatchRecord,
) -> Result<peer_mismatches::ActiveModel, StoreError> {
    use sea_orm::ActiveValue::Set;
    Ok(peer_mismatches::ActiveModel {
        peer: Set(record.peer.0),
        offered_key: Set(record.offered_key.clone()),
        first_at: Set(to_i64(record.first_at, "mismatch first time")?),
        last_at: Set(to_i64(record.last_at, "mismatch last time")?),
        attempts: Set(to_i64(record.attempts, "mismatch attempts")?),
        source: Set(record.source.chars().take(256).collect()),
        kept_blocking_at: Set(record
            .kept_blocking_at
            .map(|t| to_i64(t, "kept blocking time"))
            .transpose()?),
        kept_blocking_by: Set(record
            .kept_blocking_by
            .as_ref()
            .map(|s| s.chars().take(128).collect())),
    })
}
