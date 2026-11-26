//! The signed manifest of an owner's items: stored as the writer signed it, checked before it is
//! kept, and given back to any device of the owner.
//!
//! The server cannot make a manifest and cannot read what it protects. It checks what it can: the
//! bytes parse as docs/crypto.md's manifest for this owner, the `sig1` signature verifies under the
//! signer's published bundle, and the counter is above the stored one (a manifest only goes
//! forward, so a replayed older one cannot take the newest's place) and not more than
//! [`SignedManifest::MAX_STEP`] above it, so no writer can freeze the counter. A device checks the
//! rest.
//!
//! A manifest is kept per owner, each with its own counter. An account writes its own manifest; a
//! space's is written by a confirmed member with edit on one of its collections and read by any
//! confirmed member (see [`ManifestAccess`]). The signer is the signed-in account, whose published
//! bundle verifies the signature, so a signer is a member of the space when it signs.

use crate::authenticate::Actor;
use crate::error::AppError;
use crate::ports::{Clock, CryptoError, StoreError, UserRepo};
use crate::spaces::{SpaceRepo, SpacesError};
use kemlock_domain::manifest::SignedManifest;
use kemlock_domain::spaces::{SpaceError, SpaceState};
use kemlock_domain::{Owner, UserId};
use std::future::Future;

/// Where signed manifests are kept, one per owner.
pub trait ManifestRepo: Send + Sync {
    fn manifest(
        &self,
        owner: Owner,
    ) -> impl Future<Output = Result<Option<SignedManifest>, StoreError>> + Send;

    /// Stores the manifest when its counter is above the stored one (or none is stored),
    /// atomically, and says whether it did. Of two writers racing with the same counter, one wins.
    fn put_manifest(
        &self,
        manifest: &SignedManifest,
    ) -> impl Future<Output = Result<bool, StoreError>> + Send;
}

/// What a verified manifest says of itself.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ManifestHeader {
    pub owner: Owner,
    pub counter: u64,
}

/// Checks a manifest's wire form and signature. The server wires it to `kemlock_crypto::manifest`
/// and `sig1`; `kemlock-app` has no crypto of its own.
pub trait ManifestVerifier: Send + Sync {
    /// Parses `manifest` (docs/crypto.md, "Signed manifest") and checks `signature` is the `sig1`
    /// signature of it, under context `"manifest"`, by the signing key in `bundle`. `Invalid` for
    /// anything wrong, without saying which.
    fn verify(
        &self,
        bundle: &[u8],
        manifest: &[u8],
        signature: &[u8],
    ) -> Result<ManifestHeader, CryptoError>;
}

/// Why a manifest write failed.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ManifestError {
    /// The counter is not above the stored one, which is `current`.
    #[error("the stored manifest has counter {current}")]
    Stale { current: u64 },
    #[error(transparent)]
    App(#[from] AppError),
    /// A rule of the space refused the write.
    #[error(transparent)]
    Space(SpacesError),
}

impl From<StoreError> for ManifestError {
    fn from(e: StoreError) -> Self {
        ManifestError::App(e.into())
    }
}

/// The manifest as a device sends it.
#[derive(Clone, Debug)]
pub struct PutManifestInput {
    pub owner: Owner,
    pub bytes: Vec<u8>,
    pub signature: Vec<u8>,
}

/// Who may write and read the manifest of an owner.
pub trait ManifestAccess: Send + Sync {
    /// Whether `actor` may store a manifest for `owner`.
    fn may_write(
        &self,
        actor: &Actor,
        owner: Owner,
    ) -> impl Future<Output = Result<(), ManifestError>> + Send;

    /// Whether `actor` may read the manifest of `owner`.
    fn may_read(
        &self,
        actor: &Actor,
        owner: Owner,
    ) -> impl Future<Output = Result<(), AppError>> + Send;
}

fn own_vault(actor: &Actor, owner: Owner) -> Result<(), AppError> {
    match owner {
        Owner::User(user) if user == actor.user => Ok(()),
        Owner::User(_) => Err(AppError::Forbidden),
        Owner::Space(_) => Err(AppError::Invalid(
            "this server keeps no manifests of spaces",
        )),
    }
}

/// The account's own manifest only; a space's is refused.
#[derive(Clone, Copy, Debug, Default)]
pub struct OwnVault;

impl ManifestAccess for OwnVault {
    async fn may_write(&self, actor: &Actor, owner: Owner) -> Result<(), ManifestError> {
        Ok(own_vault(actor, owner)?)
    }

    async fn may_read(&self, actor: &Actor, owner: Owner) -> Result<(), AppError> {
        own_vault(actor, owner)
    }
}

/// The account's own manifest, and the manifest of a space for its members. A space the actor
/// isn't a confirmed member of reads as absent, so it tells a stranger nothing.
#[derive(Clone, Debug)]
pub struct SpaceMembers<R> {
    pub spaces: R,
}

impl<R: SpaceRepo> SpaceMembers<R> {
    /// Refuses `user` unless the space counts them as a confirmed member: the members table says
    /// so and, on a chained space, the chain does too (`SpaceRepo::chain_confirmed_members`). The
    /// table alone can say "confirmed" for a row no `confirm` record stands behind.
    async fn ensure_confirmed(&self, state: &SpaceState, user: UserId) -> Result<(), SpacesError> {
        state.confirmed_actor(user)?;
        let by_chain = self.spaces.chain_confirmed_members(state.space.id).await?;
        if by_chain.is_some_and(|confirmed| !confirmed.contains(&user)) {
            return Err(SpaceError::NotAMember.into());
        }
        Ok(())
    }
}

impl<R: SpaceRepo> ManifestAccess for SpaceMembers<R> {
    /// A confirmed member with edit on at least one collection of the space (a manifest lists
    /// the space's items, so it is written by someone who can write them), while the space's
    /// keys aren't waiting for a replacement.
    async fn may_write(&self, actor: &Actor, owner: Owner) -> Result<(), ManifestError> {
        let Owner::Space(space) = owner else {
            return Ok(own_vault(actor, owner)?);
        };
        let state = self
            .spaces
            .load(space)
            .await?
            .ok_or(ManifestError::Space(SpacesError::NotFound))?;
        self.ensure_confirmed(&state, actor.user)
            .await
            .map_err(ManifestError::Space)?;
        state
            .ensure_keys_open()
            .map_err(|e| ManifestError::Space(e.into()))?;
        let may_edit = state
            .collections
            .iter()
            .any(|c| state.access(actor.user, c.id).is_some_and(|a| a.edit));
        if !may_edit {
            return Err(ManifestError::Space(
                SpaceError::Forbidden("you need edit access to a collection of this space").into(),
            ));
        }
        Ok(())
    }

    /// Any confirmed member of the space.
    async fn may_read(&self, actor: &Actor, owner: Owner) -> Result<(), AppError> {
        let Owner::Space(space) = owner else {
            return own_vault(actor, owner);
        };
        let state = self.spaces.load(space).await?.ok_or(AppError::NotFound)?;
        Ok(self.ensure_confirmed(&state, actor.user).await?)
    }
}

#[derive(Debug)]
pub struct PutManifest<M, U, V, C, A> {
    pub manifests: M,
    pub users: U,
    pub verifier: V,
    pub clock: C,
    pub access: A,
}

impl<M: ManifestRepo, U: UserRepo, V: ManifestVerifier, C: Clock, A: ManifestAccess>
    PutManifest<M, U, V, C, A>
{
    /// Stores the manifest and returns it as stored. The signer is the signed-in account, whose
    /// published bundle must verify the signature. The counter must be above the
    /// one stored for this owner, whatever other owners' counters are.
    pub async fn execute(
        &self,
        actor: &Actor,
        input: PutManifestInput,
    ) -> Result<SignedManifest, ManifestError> {
        self.access.may_write(actor, input.owner).await?;
        if input.bytes.is_empty() || input.bytes.len() > SignedManifest::MAX_BYTES {
            return Err(AppError::Invalid("the manifest's size is out of range").into());
        }
        if input.signature.len() != SignedManifest::SIGNATURE_LEN {
            return Err(
                AppError::Invalid("the signature must be a 3373-byte sig1 signature").into(),
            );
        }
        let signer = self
            .users
            .by_id(actor.user)
            .await?
            .ok_or(AppError::Unauthorized)?;
        if signer.public_bundle.is_empty() {
            return Err(AppError::Invalid("the account has published no public keys yet").into());
        }
        let header = self
            .verifier
            .verify(&signer.public_bundle, &input.bytes, &input.signature)
            .map_err(|_| AppError::Invalid("the manifest or its signature is invalid"))?;
        if header.owner != input.owner {
            return Err(AppError::Invalid("the manifest is for another owner").into());
        }
        if header.counter > SignedManifest::MAX_COUNTER {
            return Err(AppError::Invalid("the counter is out of range").into());
        }
        // One write raises the counter by a bounded step, so a writer can't use up the counter for
        // every other writer of the owner.
        let stored = self
            .manifests
            .manifest(header.owner)
            .await?
            .map_or(0, |stored| stored.counter);
        if header.counter > stored.saturating_add(SignedManifest::MAX_STEP) {
            return Err(AppError::Invalid("the counter is too far above the stored one").into());
        }
        let manifest = SignedManifest {
            owner: header.owner,
            counter: header.counter,
            bytes: input.bytes,
            signature: input.signature,
            signer: actor.user,
            stored_at: self.clock.now(),
        };
        if self.manifests.put_manifest(&manifest).await? {
            return Ok(manifest);
        }
        let current = self
            .manifests
            .manifest(manifest.owner)
            .await?
            .map_or(manifest.counter, |stored| stored.counter);
        Err(ManifestError::Stale { current })
    }
}

#[derive(Debug)]
pub struct GetManifest<M, A> {
    pub manifests: M,
    pub access: A,
}

impl<M: ManifestRepo, A: ManifestAccess> GetManifest<M, A> {
    /// The latest manifest of `owner`; `NotFound` when none was ever stored.
    pub async fn execute(&self, actor: &Actor, owner: Owner) -> Result<SignedManifest, AppError> {
        self.access.may_read(actor, owner).await?;
        self.manifests
            .manifest(owner)
            .await?
            .ok_or(AppError::NotFound)
    }
}
