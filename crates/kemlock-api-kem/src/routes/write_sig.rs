//! The signature of an item write, checked against the signed-in account's own bundle
//! (docs/crypto.md, "Signed item writes").
//!
//! The domain checks that a signature can be the actor's (the writer is the actor, the item is
//! `kem1`, the signature has its length); the use cases refuse an unsigned write to a signed-only
//! owner. Here the signature itself is verified, where the crypto and the bundle are: the bundle
//! the account registered, at the account's current key version.

use crate::problem::Problem;
use kemlock_app::AppError;
use kemlock_app::ports::UserRepo;
use kemlock_crypto::{item_write, owner::Owner as CryptoOwner};
use kemlock_domain::{ItemError, ItemWrite, UserId};

fn invalid() -> Problem {
    Problem::from(AppError::Item(ItemError::BadSignature))
}

/// The statement `write` says it signed, rebuilt from the write. `None` when the write carries no
/// signature or can't have a statement.
pub(crate) fn statement_of(write: &ItemWrite) -> Option<item_write::Statement<'_>> {
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
    })
}

/// Verifies the signature of every write that carries one, as the account `actor` made them: the
/// writer is the actor, the key version is the one of the actor's registered bundle, and the
/// signature verifies over the statement rebuilt from the write under that bundle's `sig1` key.
/// A write without a signature is left to the use case, which knows whether the owner needs one.
pub(crate) async fn verify_writes<U: UserRepo>(
    users: &U,
    actor: UserId,
    writes: &[&ItemWrite],
) -> Result<(), Problem> {
    if writes.iter().all(|w| w.signature.is_none()) {
        return Ok(());
    }
    let account = users
        .by_id(actor)
        .await
        .map_err(|e| Problem::from(AppError::from(e)))?
        .ok_or_else(|| Problem::from(AppError::Unauthorized))?;
    for write in writes {
        let Some(signature) = &write.signature else {
            continue;
        };
        if signature.writer != actor
            || signature.key_version != account.key_version
            || account.public_bundle.is_empty()
        {
            return Err(invalid());
        }
        let statement = statement_of(write).ok_or_else(invalid)?;
        item_write::verify_with_bundle(&statement, &account.public_bundle, &signature.signature)
            .map_err(|_| invalid())?;
    }
    Ok(())
}
