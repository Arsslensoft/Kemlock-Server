//! Signed key boxes: who sealed a space key or collection key to a member, checked when the server
//! takes the box (docs/crypto.md, "Signed key boxes").
//!
//! A box is anonymous: anyone who knows a member's public key can seal anything to it. For a space
//! with no chain nothing else says who made a box, so the member who seals one signs it, and the
//! server refuses a box whose signature isn't the signed-in account's over exactly this box. It
//! keeps the signature beside the box for the recipient's client to verify against the sealer's
//! bundle, as it keeps a confirmation's.

use super::error::SpacesError;
use kemlock_domain::spaces::{CollectionId, KeyBoxSignature, check_key_box_signature};
use kemlock_domain::{SpaceId, UserId};
use std::future::Future;

/// Which key a box seals.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum KeyBoxKey {
    /// The space key.
    Space,
    /// The key of one collection.
    Collection(CollectionId),
}

/// What a key box signature is over, as the server knows it: the statement is built from exactly
/// these (docs/crypto.md, "Signed key boxes"), never from what the client says it signed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct KeyBoxFacts<'a> {
    pub space: SpaceId,
    pub key: KeyBoxKey,
    /// The version of the key the box holds: the one the server will store it under.
    pub key_version: u32,
    /// The member the box is sealed to.
    pub recipient: UserId,
    /// The sealed box.
    pub sealed_box: &'a [u8],
    /// The account that sealed it: the signed-in account.
    pub sealer: UserId,
}

/// What the server asks of `kemlock-crypto` and the account store about a key box. The server wires
/// it to the sealer's registered bundle.
pub trait KeyBoxVerifier: Send + Sync {
    /// Checks that `signature` is the `sig1` signature, under context `"key-box"`, of the key in the
    /// sealer's registered bundle over the statement these facts give, with the bundle's key
    /// version as the sealer's. Returns that key version, or an invalid-request error when the
    /// signature doesn't verify or the sealer has no keys.
    fn verify(
        &self,
        facts: &KeyBoxFacts<'_>,
        signature: &[u8],
    ) -> impl Future<Output = Result<u32, SpacesError>> + Send;
}

/// Verifies one box and returns what the server keeps beside it.
pub(crate) async fn check_box<K: KeyBoxVerifier>(
    boxes: &K,
    facts: KeyBoxFacts<'_>,
    signature: &[u8],
) -> Result<KeyBoxSignature, SpacesError> {
    check_key_box_signature(signature)?;
    let key_version = boxes.verify(&facts, signature).await?;
    Ok(KeyBoxSignature {
        by: facts.sealer,
        key_version,
        signature: signature.to_vec(),
    })
}
