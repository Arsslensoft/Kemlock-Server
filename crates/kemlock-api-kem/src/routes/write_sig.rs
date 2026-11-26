//! The signature of an item write, checked against the signed-in account's own bundle
//! (docs/crypto.md, "Signed item writes").
//!
//! The domain checks that a signature can be the actor's (the writer is the actor, the item is
//! `kem1`, the signature has its length); the use cases refuse an unsigned write to a signed-only
//! owner. Here the signature itself is verified, where the crypto and the bundle are: the bundle
//! the account registered, at the account's current key version.

use super::spaces::{Caller, Env};
use crate::dto::BundleAtDto;
use crate::problem::Problem;
use crate::state::{Crypto, Store};
use axum::Json;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use kemlock_app::ports::{TokenSigner, UserRepo};
use kemlock_app::signed_writes::GetBundleAt;
use kemlock_app::spaces::SpaceRepo;
use kemlock_app::{AppError, b64url};
use kemlock_crypto::{item_write, owner::Owner as CryptoOwner};
use kemlock_domain::spaces::CollectionId;
use kemlock_domain::{ItemError, ItemWrite, UserId};

fn invalid() -> Problem {
    Problem::from(AppError::Item(ItemError::BadSignature))
}

/// The statement `write` says it signed, rebuilt from the write and the collection it names (an
/// item of a space is written into one, an item of a vault into none). `None` when the write
/// carries no signature or can't have a statement.
pub(crate) fn statement_of(
    write: &ItemWrite,
    collection: Option<CollectionId>,
) -> Option<item_write::Statement<'_>> {
    let signature = write.signature.as_ref()?;
    let sealed = write
        .sealed
        .as_ref()
        .map(|s| (s.ciphertext.as_slice(), s.item_key.as_slice()));
    Some(item_write::Statement {
        owner: CryptoOwner::from_bytes(&write.owner.to_bytes()).ok()?,
        item_id: *write.id.as_bytes(),
        kind: write.kind.as_str(),
        revision: write.revision.0,
        deleted: write.sealed.is_none(),
        envelope: item_write::envelope_hash(write.key_version, sealed).ok()?,
        writer: *signature.writer.as_bytes(),
        writer_key_version: signature.key_version,
        collection: collection.map(|c| *c.0.as_bytes()),
    })
}

/// Verifies the signature of every write that carries one, as the account `actor` made them: the
/// writer is the actor, the key version is the one of the actor's registered bundle, and the
/// signature verifies over the statement rebuilt from the write under that bundle's `sig1` key.
/// A write without a signature is left to the use case, which knows whether the owner needs one.
pub(crate) async fn verify_writes<U: UserRepo>(
    users: &U,
    actor: UserId,
    writes: &[(&ItemWrite, Option<CollectionId>)],
) -> Result<(), Problem> {
    if writes.iter().all(|(w, _)| w.signature.is_none()) {
        return Ok(());
    }
    let account = users
        .by_id(actor)
        .await
        .map_err(|e| Problem::from(AppError::from(e)))?
        .ok_or_else(|| Problem::from(AppError::Unauthorized))?;
    for (write, collection) in writes {
        let Some(signature) = &write.signature else {
            continue;
        };
        if signature.writer == actor
            && signature.key_version != account.key_version
            && !account.public_bundle.is_empty()
        {
            // The account replaced its keys after this device unlocked: it must unlock again, and
            // the device can tell that from a signature that is simply wrong.
            return Err(Problem::new(
                StatusCode::UNPROCESSABLE_ENTITY,
                "key-version-stale",
                "The account's keys changed since this device unlocked",
            )
            .with("currentKeyVersion", serde_json::json!(account.key_version)));
        }
        if signature.writer != actor || account.public_bundle.is_empty() {
            return Err(invalid());
        }
        let statement = statement_of(write, *collection).ok_or_else(invalid)?;
        item_write::verify_with_bundle(&statement, &account.public_bundle, &signature.signature)
            .map_err(|_| invalid())?;
    }
    Ok(())
}

/// `GET /kem/v1/accounts/{id}/bundles/{version}`: the public-key bundle the account had at that key
/// version, for checking a write it signed before a key replacement. The account itself and a
/// confirmed member of a space it is a confirmed member of may read it; anyone else, an account
/// that doesn't exist and a version it never had are the same `404`.
pub(crate) async fn get_bundle_at<S, P, K, R>(
    State(env): State<Env<S, P, K, R>>,
    caller: Caller,
    Path((account, version)): Path<(String, u32)>,
) -> Result<Json<BundleAtDto>, Problem>
where
    S: Store,
    P: Crypto,
    K: TokenSigner + Clone + 'static,
    R: SpaceRepo + Clone + 'static,
{
    let account: UserId = account.parse().map_err(|_| Problem::not_found())?;
    let stored = GetBundleAt {
        users: env.api.store.clone(),
        spaces: env.spaces.clone(),
    }
    .execute(&caller.actor(), account, version)
    .await?;
    Ok(Json(BundleAtDto {
        key_version: stored.key_version,
        public_bundle: b64url::encode(&stored.public_bundle),
        bundle_signature: b64url::encode(&stored.bundle_signature),
    }))
}
