//! The federation tables: `peers`, `vault_federation`, `peer_log_switches`, `peer_cursors`,
//! `change_meta`, `home_records` and `item_siblings`.
//!
//! Times are Unix seconds (milliseconds for a sibling's write time) in 64-bit columns, because
//! federation compares and signs them as integers; lists (addresses, suites, replicas, lineages)
//! are packed into one column, as `kemlock-federation` packs them for the wire.

/// `peers`: the servers this one is paired with.
pub(crate) mod peers {
    use crate::convert::{corrupt, from_i64, to_i64};
    use kemlock_app::ports::StoreError;
    use kemlock_domain::ServerId;
    use kemlock_federation::ports::{Peer, PeerState};
    use sea_orm::ActiveValue::Set;
    use sea_orm::entity::prelude::*;

    #[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel)]
    #[sea_orm(table_name = "peers")]
    pub struct Model {
        #[sea_orm(primary_key, auto_increment = false)]
        pub id: Uuid,
        pub operator: String,
        pub identity_key: Vec<u8>,
        /// One address per line.
        pub addresses: String,
        /// One suite name per line.
        pub suites: String,
        pub state: String,
        pub paired_at: i64,
        pub last_seen: Option<i64>,
    }

    #[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
    pub enum Relation {}

    impl ActiveModelBehavior for ActiveModel {}

    fn lines(text: &str) -> Vec<String> {
        text.lines()
            .filter(|l| !l.is_empty())
            .map(str::to_owned)
            .collect()
    }

    impl Model {
        pub(crate) fn into_domain(self) -> Result<Peer, StoreError> {
            Ok(Peer {
                id: ServerId(self.id),
                operator: self.operator,
                identity_key: self.identity_key,
                addresses: lines(&self.addresses),
                suites: lines(&self.suites),
                state: PeerState::parse(&self.state).ok_or_else(|| corrupt("peer state"))?,
                paired_at: from_i64(self.paired_at, "paired_at")?,
                last_seen: self
                    .last_seen
                    .map(|t| from_i64(t, "last_seen"))
                    .transpose()?,
            })
        }
    }

    pub(crate) fn active(peer: &Peer) -> Result<ActiveModel, StoreError> {
        Ok(ActiveModel {
            id: Set(peer.id.0),
            operator: Set(peer.operator.clone()),
            identity_key: Set(peer.identity_key.clone()),
            addresses: Set(peer.addresses.join("\n")),
            suites: Set(peer.suites.join("\n")),
            state: Set(peer.state.as_str().to_owned()),
            paired_at: Set(to_i64(peer.paired_at, "paired_at")?),
            last_seen: Set(peer.last_seen.map(|t| to_i64(t, "last_seen")).transpose()?),
        })
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn a_peer_survives_the_trip_through_a_row() {
            let peer = Peer {
                id: ServerId::random(),
                operator: "Example".to_owned(),
                identity_key: vec![1; 40],
                addresses: vec![
                    "https://a.example".to_owned(),
                    "https://b.example".to_owned(),
                ],
                suites: vec!["kfed1-x".to_owned()],
                state: PeerState::Revoked,
                paired_at: 5,
                last_seen: Some(9),
            };
            let row = active(&peer).expect("fits");
            assert_eq!(
                row.addresses,
                Set("https://a.example\nhttps://b.example".to_owned())
            );
            assert_eq!(row.state, Set("revoked".to_owned()));
            assert_eq!(row.last_seen, Set(Some(9)));
            let model = Model {
                id: peer.id.0,
                operator: "Example".to_owned(),
                identity_key: vec![1; 40],
                addresses: "https://a.example\nhttps://b.example".to_owned(),
                suites: "kfed1-x".to_owned(),
                state: "revoked".to_owned(),
                paired_at: 5,
                last_seen: Some(9),
            };
            assert_eq!(model.into_domain(), Ok(peer));
        }
    }
}

/// `vault_federation`: how each federated vault is set up.
pub(crate) mod vault_federation {
    use crate::convert::{corrupt, from_i64, to_i64};
    use crate::tables::items::{owner_from, owner_parts};
    use kemlock_app::ports::StoreError;
    use kemlock_domain::ServerId;
    use kemlock_federation::home::{Policy, VaultFederation, pack_held, unpack_held};
    use sea_orm::ActiveValue::Set;
    use sea_orm::entity::prelude::*;

    #[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel)]
    #[sea_orm(table_name = "vault_federation")]
    pub struct Model {
        #[sea_orm(primary_key, auto_increment = false)]
        pub owner_type: i16,
        #[sea_orm(primary_key, auto_increment = false)]
        pub owner_id: Uuid,
        pub policy: String,
        pub home: Uuid,
        pub epoch: i64,
        /// The replicas' 16-byte ids, in failover order.
        pub replicas: Vec<u8>,
        /// The signed promotion record that made the current epoch.
        pub promotion: Option<Vec<u8>>,
        /// A promotion another server signed that waits for this server's admin.
        pub held_demotion: Option<Vec<u8>>,
        /// The home of each earlier epoch: 24 bytes each, `u64be(epoch) || server id`, oldest first.
        pub home_history: Option<Vec<u8>>,
    }

    #[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
    pub enum Relation {}

    impl ActiveModelBehavior for ActiveModel {}

    fn unpack_history(bytes: Option<&[u8]>) -> Result<Vec<(u64, ServerId)>, StoreError> {
        let Some(bytes) = bytes else {
            return Ok(Vec::new());
        };
        if !bytes.len().is_multiple_of(24) {
            return Err(corrupt("home history"));
        }
        Ok(bytes
            .as_chunks::<24>()
            .0
            .iter()
            .map(|c| {
                let mut epoch = [0u8; 8];
                epoch.copy_from_slice(&c[..8]);
                let mut id = [0u8; 16];
                id.copy_from_slice(&c[8..]);
                (u64::from_be_bytes(epoch), ServerId(Uuid::from_bytes(id)))
            })
            .collect())
    }

    fn pack_history(history: &[(u64, ServerId)]) -> Option<Vec<u8>> {
        if history.is_empty() {
            return None;
        }
        let mut out = Vec::with_capacity(history.len() * 24);
        for (epoch, home) in history {
            out.extend_from_slice(&epoch.to_be_bytes());
            out.extend_from_slice(home.as_bytes());
        }
        Some(out)
    }

    impl Model {
        pub(crate) fn into_domain(self) -> Result<VaultFederation, StoreError> {
            if !self.replicas.len().is_multiple_of(16) {
                return Err(corrupt("replica list"));
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
            Ok(VaultFederation {
                owner: owner_from(self.owner_type, self.owner_id)?,
                policy: Policy::parse(&self.policy).ok_or_else(|| corrupt("vault policy"))?,
                home: ServerId(self.home),
                epoch: from_i64(self.epoch, "epoch")?,
                replicas,
                promotion: self.promotion,
                held_demotion: unpack_held(self.held_demotion.as_deref())
                    .map_err(|_| corrupt("held promotions"))?,
                home_history: unpack_history(self.home_history.as_deref())?,
            })
        }
    }

    pub(crate) fn active(vault: &VaultFederation) -> Result<ActiveModel, StoreError> {
        let (owner_type, owner_id) = owner_parts(vault.owner);
        let mut replicas = Vec::with_capacity(vault.replicas.len() * 16);
        for r in &vault.replicas {
            replicas.extend_from_slice(r.as_bytes());
        }
        Ok(ActiveModel {
            owner_type: Set(owner_type),
            owner_id: Set(owner_id),
            policy: Set(vault.policy.as_str().to_owned()),
            home: Set(vault.home.0),
            epoch: Set(to_i64(vault.epoch, "epoch")?),
            replicas: Set(replicas),
            promotion: Set(vault.promotion.clone()),
            held_demotion: Set(pack_held(&vault.held_demotion)),
            home_history: Set(pack_history(&vault.home_history)),
        })
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use kemlock_domain::{Owner, UserId};

        #[test]
        fn a_vault_survives_the_trip_through_a_row() {
            let mut vault = VaultFederation::federated(
                Owner::User(UserId::random()),
                ServerId::random(),
                vec![ServerId::random(), ServerId::random()],
            );
            vault.epoch = 4;
            vault.promotion = Some(vec![1, 2, 3]);
            vault.held_demotion = vec![vec![4, 5], vec![6]];
            let row = active(&vault).expect("fits");
            let (owner_type, owner_id) = owner_parts(vault.owner);
            let mut replicas = Vec::new();
            for r in &vault.replicas {
                replicas.extend_from_slice(r.as_bytes());
            }
            assert_eq!(row.replicas, Set(replicas.clone()));
            assert_eq!(row.epoch, Set(4));
            let model = Model {
                owner_type,
                owner_id,
                policy: "federated".to_owned(),
                home: vault.home.0,
                epoch: 4,
                replicas,
                promotion: Some(vec![1, 2, 3]),
                held_demotion: pack_held(&vault.held_demotion),
                home_history: None,
            };
            assert_eq!(model.into_domain(), Ok(vault));
        }

        #[test]
        fn a_ragged_replica_list_is_corrupt() {
            let model = Model {
                owner_type: 1,
                owner_id: Uuid::nil(),
                policy: "federated".to_owned(),
                home: Uuid::nil(),
                epoch: 1,
                replicas: vec![0; 17],
                promotion: None,
                held_demotion: None,
                home_history: None,
            };
            assert!(model.into_domain().is_err());
        }
    }
}

/// `peer_log_switches`: the two event-log switches per peer, both off by default.
pub(crate) mod peer_log_switches {
    use sea_orm::entity::prelude::*;

    #[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel)]
    #[sea_orm(table_name = "peer_log_switches")]
    pub struct Model {
        #[sea_orm(primary_key, auto_increment = false)]
        pub peer: Uuid,
        /// "Send our logs".
        pub send: bool,
        /// "Pull their logs".
        pub pull: bool,
    }

    #[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
    pub enum Relation {}

    impl ActiveModelBehavior for ActiveModel {}
}

/// `peer_cursors`: what has been pulled from each peer, per vault.
pub(crate) mod peer_cursors {
    use sea_orm::entity::prelude::*;

    #[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel)]
    #[sea_orm(table_name = "peer_cursors")]
    pub struct Model {
        #[sea_orm(primary_key, auto_increment = false)]
        pub peer: Uuid,
        #[sea_orm(primary_key, auto_increment = false)]
        pub owner_type: i16,
        #[sea_orm(primary_key, auto_increment = false)]
        pub owner_id: Uuid,
        /// A version vector's cursor bytes.
        pub cursor_bytes: Vec<u8>,
    }

    #[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
    pub enum Relation {}

    impl ActiveModelBehavior for ActiveModel {}
}

/// `change_meta`: the lineage and the origin's signature of a change.
pub(crate) mod change_meta {
    use sea_orm::entity::prelude::*;

    #[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel)]
    #[sea_orm(table_name = "change_meta")]
    pub struct Model {
        #[sea_orm(primary_key, auto_increment = false)]
        pub origin: Uuid,
        #[sea_orm(primary_key, auto_increment = false)]
        pub seq: i64,
        /// Packed 24-byte change keys, nearest ancestor first.
        pub lineage: Vec<u8>,
        /// Absent for a change this server accepted and has not sent yet.
        pub signature: Option<Vec<u8>>,
    }

    #[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
    pub enum Relation {}

    impl ActiveModelBehavior for ActiveModel {}
}

/// `home_records`: home-only writes, applied or quarantined.
pub(crate) mod home_records {
    use crate::convert::{corrupt, from_i64, to_i64};
    use crate::tables::items::{owner_from, owner_parts};
    use kemlock_app::ports::StoreError;
    use kemlock_domain::ServerId;
    use kemlock_federation::home::HomeRecord;
    use kemlock_federation::ports::{HomeStatus, StoredHomeRecord};
    use sea_orm::ActiveValue::Set;
    use sea_orm::entity::prelude::*;

    #[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel)]
    #[sea_orm(table_name = "home_records")]
    pub struct Model {
        #[sea_orm(primary_key, auto_increment = false)]
        pub owner_type: i16,
        #[sea_orm(primary_key, auto_increment = false)]
        pub owner_id: Uuid,
        #[sea_orm(primary_key, auto_increment = false)]
        pub idx: i64,
        pub epoch: i64,
        pub kind: String,
        pub payload: Vec<u8>,
        pub signer: Uuid,
        /// The signed envelope, to pass on.
        pub envelope: Vec<u8>,
        pub status: String,
    }

    #[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
    pub enum Relation {}

    impl ActiveModelBehavior for ActiveModel {}

    impl Model {
        pub(crate) fn into_domain(self) -> Result<StoredHomeRecord, StoreError> {
            Ok(StoredHomeRecord {
                signed: self.envelope,
                record: HomeRecord {
                    vault: owner_from(self.owner_type, self.owner_id)?,
                    index: from_i64(self.idx, "home record index")?,
                    epoch: from_i64(self.epoch, "home record epoch")?,
                    kind: self.kind,
                    payload: self.payload,
                    signer: ServerId(self.signer),
                },
                status: HomeStatus::parse(&self.status).ok_or_else(|| corrupt("home status"))?,
            })
        }
    }

    pub(crate) fn active(stored: &StoredHomeRecord) -> Result<ActiveModel, StoreError> {
        let (owner_type, owner_id) = owner_parts(stored.record.vault);
        Ok(ActiveModel {
            owner_type: Set(owner_type),
            owner_id: Set(owner_id),
            idx: Set(to_i64(stored.record.index, "home record index")?),
            epoch: Set(to_i64(stored.record.epoch, "home record epoch")?),
            kind: Set(stored.record.kind.clone()),
            payload: Set(stored.record.payload.clone()),
            signer: Set(stored.record.signer.0),
            envelope: Set(stored.signed.clone()),
            status: Set(stored.status.as_str().to_owned()),
        })
    }
}

/// `item_siblings`: versions of an item held beside its head, after a conflict.
pub(crate) mod item_siblings {
    use crate::convert::{corrupt, from_i64, from_i64_u32, to_i64};
    use crate::tables::items::{owner_from, owner_parts};
    use kemlock_app::ports::StoreError;
    use kemlock_domain::{ChangeId, Hlc, Item, ItemFormat, ItemId, ItemKind, Revision, ServerId};
    use kemlock_federation::change::ms_to_time;
    use sea_orm::ActiveValue::Set;
    use sea_orm::entity::prelude::*;

    #[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel)]
    #[sea_orm(table_name = "item_siblings")]
    pub struct Model {
        #[sea_orm(primary_key, auto_increment = false)]
        pub origin: Uuid,
        #[sea_orm(primary_key, auto_increment = false)]
        pub seq: i64,
        pub item_id: Uuid,
        pub owner_type: i16,
        pub owner_id: Uuid,
        pub kind: String,
        pub format: String,
        pub revision: i64,
        pub key_version: i64,
        pub ciphertext: Option<Vec<u8>>,
        pub item_key: Option<Vec<u8>>,
        pub deleted: bool,
        /// Unix milliseconds.
        pub updated_at_ms: i64,
        pub hlc: i64,
        /// The writing account's signature, as `items.write_sig` holds it.
        pub write_sig: Option<Vec<u8>>,
    }

    #[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
    pub enum Relation {}

    impl ActiveModelBehavior for ActiveModel {}

    fn format_from(s: &str) -> Result<ItemFormat, StoreError> {
        match s {
            "kem1" => Ok(ItemFormat::Kem1),
            "bw" => Ok(ItemFormat::Bw),
            _ => Err(corrupt("item format")),
        }
    }

    impl Model {
        pub(crate) fn into_item(self) -> Result<Item, StoreError> {
            let updated_at = ms_to_time(from_i64(self.updated_at_ms, "updated_at")?)
                .map_err(|_| corrupt("updated_at"))?;
            Ok(Item {
                id: ItemId(self.item_id),
                owner: owner_from(self.owner_type, self.owner_id)?,
                kind: ItemKind::try_from(self.kind).map_err(|_| corrupt("item kind"))?,
                format: format_from(&self.format)?,
                revision: Revision(from_i64(self.revision, "revision")?),
                key_version: from_i64_u32(self.key_version, "key version")?,
                ciphertext: self.ciphertext,
                item_key: self.item_key,
                deleted_at: self.deleted.then_some(updated_at),
                updated_at,
                change: ChangeId {
                    origin: ServerId(self.origin),
                    seq: from_i64(self.seq, "sequence number")?,
                    hlc: Hlc(from_i64(self.hlc, "hlc")?),
                },
                signature: crate::tables::items::stored_signature(self.write_sig.as_deref())?,
            })
        }
    }

    pub(crate) fn active(item: &Item) -> Result<ActiveModel, StoreError> {
        let (owner_type, owner_id) = owner_parts(item.owner);
        Ok(ActiveModel {
            origin: Set(item.change.origin.0),
            seq: Set(to_i64(item.change.seq, "sequence number")?),
            item_id: Set(item.id.0),
            owner_type: Set(owner_type),
            owner_id: Set(owner_id),
            kind: Set(item.kind.as_str().to_owned()),
            format: Set(item.format.as_str().to_owned()),
            revision: Set(to_i64(item.revision.0, "revision")?),
            key_version: Set(i64::from(item.key_version)),
            ciphertext: Set(item.ciphertext.clone()),
            item_key: Set(item.item_key.clone()),
            deleted: Set(item.is_tombstone()),
            updated_at_ms: Set(to_i64(
                kemlock_federation::change::time_to_ms(item.updated_at),
                "updated_at",
            )?),
            hlc: Set(to_i64(item.change.hlc.0, "hlc")?),
            write_sig: Set(item.signature.as_ref().map(kemlock_domain::WriteSignature::to_stored)),
        })
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use kemlock_domain::{Owner, UserId};

        #[test]
        fn a_version_survives_the_trip_through_a_sibling_row() {
            let item = Item {
                id: ItemId::random(),
                owner: Owner::User(UserId::random()),
                kind: ItemKind::try_from("login".to_owned()).expect("kind"),
                format: ItemFormat::Kem1,
                revision: Revision(3),
                key_version: 1,
                ciphertext: Some(vec![1; 40]),
                item_key: Some(vec![2; 60]),
                deleted_at: None,
                updated_at: ms_to_time(1_700_000_000_123).expect("time"),
                change: ChangeId {
                    origin: ServerId::random(),
                    seq: 12,
                    hlc: Hlc::from_parts(1_700_000_000_123, 3),
                },
                signature: None,
            };
            let row = active(&item).expect("fits");
            assert_eq!(row.updated_at_ms, Set(1_700_000_000_123));
            assert_eq!(row.deleted, Set(false));
            let (owner_type, owner_id) = owner_parts(item.owner);
            let model = Model {
                origin: item.change.origin.0,
                seq: 12,
                item_id: item.id.0,
                owner_type,
                owner_id,
                kind: "login".to_owned(),
                format: "kem1".to_owned(),
                revision: 3,
                key_version: 1,
                ciphertext: Some(vec![1; 40]),
                item_key: Some(vec![2; 60]),
                deleted: false,
                updated_at_ms: 1_700_000_000_123,
                hlc: i64::try_from(item.change.hlc.0).expect("fits"),
                write_sig: None,
            };
            assert_eq!(model.into_item(), Ok(item));
        }
    }
}
