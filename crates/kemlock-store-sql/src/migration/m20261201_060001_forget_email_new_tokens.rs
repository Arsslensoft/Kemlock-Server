//! `bw_account_extras.email_new_token`: the move from Vaultwarden kept the token of a pending
//! change of email address as it was, which anyone with a copy of the database could use. The
//! move now keeps its SHA-256 (`sha256:<hex>`), and nothing here ever read the token back, so a
//! token an earlier move kept in the clear is dropped, which only abandons a change Vaultwarden
//! had asked for and no one finished.

use sea_orm_migration::prelude::*;

#[derive(DeriveMigrationName)]
pub(crate) struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .exec_stmt(
                Query::update()
                    .table(Alias::new("bw_account_extras"))
                    .value(Alias::new("email_new_token"), Option::<String>::None)
                    .and_where(Expr::col(Alias::new("email_new_token")).is_not_null())
                    .and_where(Expr::col(Alias::new("email_new_token")).not_like("sha256:%"))
                    .to_owned(),
            )
            .await
    }
}
