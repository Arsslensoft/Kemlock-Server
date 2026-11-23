//! Signed manifests of spaces: who may write and read one, and a counter per owner.

mod chain_kit;
mod fakes;
mod space_fakes;

use chain_kit::invited_chain;
use fakes::{FakeEnv, FakeStore, actor};
use kemlock_app::AppError;
use kemlock_app::manifests::{
    GetManifest, ManifestError, ManifestHeader, ManifestVerifier, PutManifest, PutManifestInput,
    SpaceMembers,
};
use kemlock_app::ports::CryptoError;
use kemlock_app::spaces::{SpaceChainRepo, SpacesError};
use kemlock_domain::manifest::SignedManifest;
use kemlock_domain::spaces::{CollectionPermission, SpaceError, SpaceRole};
use kemlock_domain::{Owner, SpaceId, UserId};
use space_fakes::{SpaceWorld, Spaces};

/// Reads a manifest as the owner's 17 bytes then the counter's 8; a signature of `0x5a` verifies.
#[derive(Clone, Copy)]
struct FakeVerifier;

impl ManifestVerifier for FakeVerifier {
    fn verify(
        &self,
        bundle: &[u8],
        manifest: &[u8],
        signature: &[u8],
    ) -> Result<ManifestHeader, CryptoError> {
        if bundle.is_empty() || manifest.len() != 25 || signature.iter().any(|b| *b != 0x5a) {
            return Err(CryptoError::Invalid);
        }
        let mut owner = [0u8; 17];
        owner.copy_from_slice(&manifest[..17]);
        let mut counter = [0u8; 8];
        counter.copy_from_slice(&manifest[17..]);
        Ok(ManifestHeader {
            owner: Owner::from_bytes(&owner).ok_or(CryptoError::Invalid)?,
            counter: u64::from_be_bytes(counter),
        })
    }
}

type Put = PutManifest<FakeStore, FakeStore, FakeVerifier, FakeEnv, SpaceMembers<Spaces>>;
type Get = GetManifest<FakeStore, SpaceMembers<Spaces>>;

fn put(w: &SpaceWorld) -> Put {
    PutManifest {
        manifests: w.world.store.clone(),
        users: w.world.store.clone(),
        verifier: FakeVerifier,
        clock: w.world.env.clone(),
        access: SpaceMembers {
            spaces: w.spaces.clone(),
        },
    }
}

fn get(w: &SpaceWorld) -> Get {
    GetManifest {
        manifests: w.world.store.clone(),
        access: SpaceMembers {
            spaces: w.spaces.clone(),
        },
    }
}

fn input(owner: Owner, counter: u64) -> PutManifestInput {
    let mut bytes = owner.to_bytes().to_vec();
    bytes.extend_from_slice(&counter.to_be_bytes());
    PutManifestInput {
        owner,
        bytes,
        signature: vec![0x5a; SignedManifest::SIGNATURE_LEN],
    }
}

/// Sam owns a space; Ana is a confirmed member with Edit, Lee with View only; Zed is outside.
struct Ctx {
    w: SpaceWorld,
    sam: UserId,
    ana: UserId,
    lee: UserId,
    zed: UserId,
    space: SpaceId,
}

impl Ctx {
    async fn new() -> Ctx {
        let w = SpaceWorld::new();
        let sam = w.user("sam@example.org").await;
        let ana = w.user("ana@example.org").await;
        let lee = w.user("lee@example.org").await;
        let zed = w.user("zed@example.org").await;
        let (space, collection) = w.make_space(sam).await;
        w.join(
            space,
            sam,
            sam,
            ana,
            SpaceRole::Member,
            vec![(collection, CollectionPermission::Edit)],
        )
        .await;
        w.join(
            space,
            sam,
            sam,
            lee,
            SpaceRole::Member,
            vec![(collection, CollectionPermission::View)],
        )
        .await;
        Ctx {
            w,
            sam,
            ana,
            lee,
            zed,
            space,
        }
    }
}

#[tokio::test]
async fn a_member_with_edit_stores_the_spaces_manifest_with_themselves_as_signer() {
    let c = Ctx::new().await;
    let owner = Owner::Space(c.space);
    let stored = put(&c.w)
        .execute(&actor(c.ana), input(owner, 2))
        .await
        .expect("Ana may write the space's manifest");
    assert_eq!(
        (stored.owner, stored.counter, stored.signer),
        (owner, 2, c.ana)
    );
    // Any confirmed member reads it, a viewer included.
    for reader in [c.sam, c.ana, c.lee] {
        let read = get(&c.w)
            .execute(&actor(reader), owner)
            .await
            .expect("a member reads");
        assert_eq!(read, stored);
    }
}

#[tokio::test]
async fn a_viewer_and_a_stranger_may_not_write_and_a_stranger_cannot_read() {
    let c = Ctx::new().await;
    let owner = Owner::Space(c.space);
    let viewer = put(&c.w).execute(&actor(c.lee), input(owner, 1)).await;
    assert!(matches!(
        viewer,
        Err(ManifestError::Space(SpacesError::Rule(
            SpaceError::Forbidden(_)
        )))
    ));
    let stranger = put(&c.w).execute(&actor(c.zed), input(owner, 1)).await;
    assert_eq!(
        stranger.map(|_| ()),
        Err(ManifestError::Space(SpacesError::Rule(
            SpaceError::NotAMember
        )))
    );
    let missing = put(&c.w)
        .execute(&actor(c.sam), input(Owner::Space(SpaceId::random()), 1))
        .await;
    assert_eq!(
        missing.map(|_| ()),
        Err(ManifestError::Space(SpacesError::NotFound))
    );
    // Nothing was stored, and a stranger can't read what is.
    put(&c.w)
        .execute(&actor(c.sam), input(owner, 1))
        .await
        .expect("Sam writes");
    assert_eq!(
        get(&c.w).execute(&actor(c.zed), owner).await,
        Err(AppError::NotFound)
    );
    assert_eq!(
        get(&c.w)
            .execute(&actor(c.zed), Owner::Space(SpaceId::random()))
            .await,
        Err(AppError::NotFound)
    );
}

#[tokio::test]
async fn each_space_keeps_its_own_counter() {
    let c = Ctx::new().await;
    let (second, _) = c.w.make_space(c.sam).await;
    let (first, second) = (Owner::Space(c.space), Owner::Space(second));
    let own = Owner::User(c.sam);
    put(&c.w)
        .execute(&actor(c.sam), input(first, 5))
        .await
        .expect("stores");
    // Another space and the account's own start from nothing.
    for owner in [second, own] {
        put(&c.w)
            .execute(&actor(c.sam), input(owner, 1))
            .await
            .expect("an owner's counter doesn't depend on another's");
    }
    let stale = put(&c.w).execute(&actor(c.ana), input(first, 5)).await;
    assert_eq!(stale.map(|_| ()), Err(ManifestError::Stale { current: 5 }));
    let newer = put(&c.w)
        .execute(&actor(c.ana), input(first, 6))
        .await
        .expect("a member may raise it");
    assert_eq!(newer.signer, c.ana);
    // A manifest signed for one space can't be stored as another's.
    let mut crossed = input(second, 9);
    crossed.owner = first;
    let refused = put(&c.w).execute(&actor(c.sam), crossed).await;
    assert!(matches!(
        refused,
        Err(ManifestError::App(AppError::Invalid(_)))
    ));
}

#[tokio::test]
async fn the_account_still_writes_only_its_own_vault_manifest() {
    let c = Ctx::new().await;
    put(&c.w)
        .execute(&actor(c.ana), input(Owner::User(c.ana), 1))
        .await
        .expect("her own");
    let other = put(&c.w)
        .execute(&actor(c.ana), input(Owner::User(c.sam), 1))
        .await;
    assert_eq!(
        other.map(|_| ()),
        Err(ManifestError::App(AppError::Forbidden))
    );
    assert_eq!(
        get(&c.w).execute(&actor(c.ana), Owner::User(c.sam)).await,
        Err(AppError::Forbidden)
    );
}

#[tokio::test]
async fn a_space_waiting_for_new_keys_takes_no_manifest_but_still_serves_the_last() {
    let c = Ctx::new().await;
    let owner = Owner::Space(c.space);
    let stored = put(&c.w)
        .execute(&actor(c.sam), input(owner, 1))
        .await
        .expect("stores");
    c.w.offboard()
        .revoke(&actor(c.sam), c.space, c.lee)
        .await
        .expect("Lee is revoked");
    let paused = put(&c.w).execute(&actor(c.sam), input(owner, 2)).await;
    assert_eq!(
        paused.map(|_| ()),
        Err(ManifestError::Space(SpacesError::Rule(
            SpaceError::KeysPending
        )))
    );
    assert_eq!(get(&c.w).execute(&actor(c.ana), owner).await, Ok(stored));
    // The revoked member is out: no read either.
    assert_eq!(
        get(&c.w).execute(&actor(c.lee), owner).await,
        Err(AppError::NotFound)
    );
}

#[tokio::test]
async fn a_row_confirmed_without_a_confirm_record_neither_writes_nor_reads_a_chained_space() {
    let c = Ctx::new().await;
    let owner = Owner::Space(c.space);
    // The table says Ana is confirmed with Edit, but her chain invited her and never confirmed her.
    c.w.spaces
        .chain_append(c.space, invited_chain(c.space, c.sam, c.ana, false))
        .await
        .expect("the chain is stored");
    let write = put(&c.w).execute(&actor(c.ana), input(owner, 1)).await;
    assert_eq!(
        write.map(|_| ()),
        Err(ManifestError::Space(SpacesError::Rule(
            SpaceError::NotAMember
        )))
    );
    // Sam, whom the chain made, still does; Ana then finds the manifest absent, as a stranger does.
    put(&c.w)
        .execute(&actor(c.sam), input(owner, 1))
        .await
        .expect("Sam writes");
    assert_eq!(
        get(&c.w).execute(&actor(c.ana), owner).await,
        Err(AppError::NotFound)
    );
    get(&c.w)
        .execute(&actor(c.sam), owner)
        .await
        .expect("Sam reads");
}

#[tokio::test]
async fn a_member_the_chain_confirms_writes_and_reads_a_chained_space() {
    let c = Ctx::new().await;
    let owner = Owner::Space(c.space);
    c.w.spaces
        .chain_append(c.space, invited_chain(c.space, c.sam, c.ana, true))
        .await
        .expect("the chain is stored");
    put(&c.w)
        .execute(&actor(c.ana), input(owner, 1))
        .await
        .expect("Ana writes");
    get(&c.w)
        .execute(&actor(c.ana), owner)
        .await
        .expect("Ana reads");
}
