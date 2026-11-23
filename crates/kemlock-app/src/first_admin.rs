//! The first-admin marker: a record in the store, written in the same transaction as the account
//! that registers with a setup grant, that makes a second first admin impossible.
//!
//! The setup code and grants live in each process's memory, so two replicas of one server each
//! have a code of their own and each would accept a registration. The database is the one place
//! they share, so the decision is made there: the marker is unique, and the insert of the account
//! that carries it fails for whoever comes second. The marker also tells a restarted server which
//! account is waiting to finish setup.

use crate::ports::StoreError;
use kemlock_domain::{User, UserId};
use std::future::Future;

pub trait FirstAdminRepo: Send + Sync {
    /// Inserts `user` and the first-admin marker naming it, in one transaction. `Duplicate` when a
    /// marker already names an account that still exists, or when the id or the email is taken;
    /// then nothing is stored. A marker whose account is gone doesn't hold the place.
    fn insert_first_admin(
        &self,
        user: &User,
    ) -> impl Future<Output = Result<(), StoreError>> + Send;

    /// The account the marker names, if there is one and it still exists: the first admin, or the
    /// account that registered with the setup grant and has not finished setup.
    fn first_admin(&self) -> impl Future<Output = Result<Option<UserId>, StoreError>> + Send;
}
