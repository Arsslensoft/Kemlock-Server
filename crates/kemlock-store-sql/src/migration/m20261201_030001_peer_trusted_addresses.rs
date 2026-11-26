//! `peer_trusted_addresses`: the addresses of a peer the admin chose (typed at pairing, listed by
//! its descriptor when the pairing was confirmed, or approved since). Only these may be dialled
//! over `http` or on a private network; any other address a descriptor lists must be `https` and
//! public (`kemlock_federation::addr`).
//!
//! The addresses every peer has now were all put there by pairing, so each is copied in: a server
//! that federates over a private network keeps working.

use sea_orm_migration::prelude::*;
use sea_orm_migration::schema as c;
use sea_orm_migration::sea_orm::{ConnectionTrait, Value};
use uuid::Uuid;

#[derive(DeriveMigrationName)]
pub(crate) struct Migration;

/// The longest address that can be kept (the column is a key).
const MAX_ADDRESS: usize = 512;

fn custom(error: impl std::fmt::Debug) -> DbErr {
    DbErr::Custom(format!("{error:?}"))
}

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .create_table(
                Table::create()
                    .table("peer_trusted_addresses")
                    .if_not_exists()
                    .col(c::uuid("peer"))
                    .col(c::string_len("address", 512))
                    .primary_key(Index::create().col("peer").col("address"))
                    .to_owned(),
            )
            .await?;

        let db = manager.get_connection();
        let peers = db
            .query_all(
                &Query::select()
                    .columns([Alias::new("id"), Alias::new("addresses")])
                    .from(Alias::new("peers"))
                    .to_owned(),
            )
            .await?;
        for row in peers {
            let peer: Uuid = row.try_get("", "id").map_err(custom)?;
            let addresses: String = row.try_get("", "addresses").map_err(custom)?;
            for address in addresses
                .lines()
                .map(str::trim)
                .filter(|a| !a.is_empty() && a.len() <= MAX_ADDRESS)
            {
                let present = db
                    .query_all(
                        &Query::select()
                            .column(Alias::new("peer"))
                            .from(Alias::new("peer_trusted_addresses"))
                            .and_where(Expr::col(Alias::new("peer")).eq(peer))
                            .and_where(Expr::col(Alias::new("address")).eq(address))
                            .to_owned(),
                    )
                    .await?;
                if !present.is_empty() {
                    continue;
                }
                let mut insert = Query::insert();
                insert
                    .into_table(Alias::new("peer_trusted_addresses"))
                    .columns([Alias::new("peer"), Alias::new("address")])
                    .values([
                        Expr::val(Value::Uuid(Some(peer))),
                        Expr::val(address.to_owned()),
                    ])
                    .map_err(custom)?;
                manager.exec_stmt(insert.to_owned()).await?;
            }
        }
        Ok(())
    }
}
