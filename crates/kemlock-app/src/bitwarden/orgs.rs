//! The side store of the Bitwarden API: small JSON documents it keeps beside the domain rows.
//!
//! Spaces hold what Kemlock's own rules need (members, roles, groups, collections, grants). A
//! Bitwarden organization also has values no space has room for: the organization's RSA key pair,
//! each member's wrapped organization key (`akey`), policies, external ids, the links between a
//! cipher and its collections, an account's equivalent-domains list. The Bitwarden API keeps them
//! here, as opaque text it serialises itself, keyed by a scope (a space id, or an account id), a
//! kind and a key. The store never reads a document.

use crate::ports::StoreError;
use std::future::Future;
use uuid::Uuid;

/// Documents of the Bitwarden API. `SqlStore` implements it on `bw_docs`; the method names start
/// with `doc_` so a store that implements many ports needs no disambiguation.
pub trait BwOrgStore: Send + Sync {
    /// The document at `(scope, kind, key)`.
    fn doc_get(
        &self,
        scope: Uuid,
        kind: &str,
        key: &str,
    ) -> impl Future<Output = Result<Option<String>, StoreError>> + Send;

    /// Inserts the document, or replaces the one that is there.
    fn doc_put(
        &self,
        scope: Uuid,
        kind: &str,
        key: &str,
        body: &str,
    ) -> impl Future<Output = Result<(), StoreError>> + Send;

    /// Removes the document; whether there was one.
    fn doc_delete(
        &self,
        scope: Uuid,
        kind: &str,
        key: &str,
    ) -> impl Future<Output = Result<bool, StoreError>> + Send;

    /// Every document of one kind in a scope, as `(key, body)` ordered by key.
    fn doc_list(
        &self,
        scope: Uuid,
        kind: &str,
    ) -> impl Future<Output = Result<Vec<(String, String)>, StoreError>> + Send;

    /// The documents of one kind and key in any scope, as `(scope, body)` ordered by scope.
    fn doc_find(
        &self,
        kind: &str,
        key: &str,
    ) -> impl Future<Output = Result<Vec<(Uuid, String)>, StoreError>> + Send;

    /// Removes every document of a scope; how many went.
    fn doc_delete_scope(&self, scope: Uuid)
    -> impl Future<Output = Result<u64, StoreError>> + Send;
}
