//! `Forgetting` on `SqlStore`: what a server deletes when a peer unpairs and asks it to.
//!
//! The vaults the peer is the home of go: a space with everything in it, and for a personal vault
//! its account copy with the account's items, devices and sessions (the same erasure an account
//! deletion runs). Account copies that came from the peer and are still here (the members of its
//! spaces) go too, and so do the offers it made. A vault this server is the home of, or an account
//! that lives here and is not a copy, is never touched.

use super::privacy::delete_space;
use crate::error::StoreResult;
use crate::store::SqlStore;
use crate::tables::federation_wiring::{replicated_accounts, vault_offers};
use kemlock_app::ports::{StoreError, UserRepo};
use kemlock_app::privacy::ErasedRows;
use kemlock_domain::{Owner, ServerId, UserId};
use kemlock_federation::extra::MemberStore;
use kemlock_federation::forget::{Forgetting, Forgotten};
use kemlock_federation::ports::{ReplicaStore, VaultRepo};
use sea_orm::{ColumnTrait, EntityTrait, QueryFilter, TransactionTrait};

impl SqlStore {
    /// Erases the account copy `user`, if it is a copy, and adds what went to `out`.
    async fn forget_account_copy(
        &self,
        user: UserId,
        out: &mut Forgotten,
    ) -> Result<(), StoreError> {
        if !MemberStore::is_replica_account(self, user).await? {
            return Ok(());
        }
        if let Some(account) = UserRepo::by_id(self, user).await? {
            // Not the account's own erasure: the owner check of that one would refuse a copy that
            // owns a space with local members, and the clean-up of an unpaired peer must finish.
            let rows = self.erase_account(&account, false).await?;
            out.items += rows.items;
            out.blobs.extend(rows.blobs);
            out.accounts += 1;
        }
        replicated_accounts::Entity::delete_many()
            .filter(replicated_accounts::Column::UserId.eq(user.0))
            .exec(self.writer())
            .await
            .store()?;
        Ok(())
    }
}

impl Forgetting for SqlStore {
    async fn forget_peer(&self, peer: ServerId) -> Result<Forgotten, StoreError> {
        let mut out = Forgotten::default();
        let me = ReplicaStore::server_id(self);
        if peer == me {
            return Ok(out);
        }
        // The peer's spaces go before its account copies: a copy that was the only owner of a
        // space is erased without the space's local members in the way.
        let vaults: Vec<_> = VaultRepo::list_vaults(self)
            .await?
            .into_iter()
            .filter(|vault| vault.home == peer)
            .collect();
        for vault in vaults
            .iter()
            .filter(|v| matches!(v.owner, Owner::Space(_)))
            .chain(vaults.iter().filter(|v| matches!(v.owner, Owner::User(_))))
        {
            match vault.owner {
                Owner::User(user) => self.forget_account_copy(user, &mut out).await?,
                Owner::Space(space) => {
                    let txn = self.writer().begin().await.store()?;
                    let mut rows = ErasedRows::default();
                    match delete_space(&txn, space.0, me, &mut rows).await {
                        Ok(()) => txn.commit().await.store()?,
                        Err(err) => {
                            if let Err(rollback) = txn.rollback().await {
                                tracing::warn!(%rollback, "rollback after a failed forgetting failed");
                            }
                            return Err(err);
                        }
                    }
                    out.items += rows.items;
                    out.blobs.extend(rows.blobs);
                }
            }
            out.vaults += 1;
        }
        // The members' accounts that came from the peer and are still here.
        let copies = replicated_accounts::Entity::find()
            .filter(replicated_accounts::Column::Home.eq(peer.0))
            .all(self.reader())
            .await
            .store()?;
        for copy in copies {
            self.forget_account_copy(UserId(copy.user_id), &mut out)
                .await?;
        }
        vault_offers::Entity::delete_many()
            .filter(vault_offers::Column::Home.eq(peer.0))
            .exec(self.writer())
            .await
            .store()?;
        Ok(out)
    }
}
