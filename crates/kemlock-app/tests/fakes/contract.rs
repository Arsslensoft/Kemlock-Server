//! Fakes for the signed-manifest, per-API device use and Bitwarden account ports, kept beside
//! `FakeStore` so one store value serves every repository port.
//!
//! The state lives in `ContractState`, a field of `FakeStore`; the repository impls are on
//! `FakeStore` itself.

use super::FakeStore;
use kemlock_app::api_use::{ApiUseRepo, USE_GRANULARITY};
use kemlock_app::bitwarden::{BwAccount, BwAccountRepo};
use kemlock_app::manifests::ManifestRepo;
use kemlock_app::ports::StoreError;
use kemlock_domain::api_use::{ApiKind, DeviceApiUse};
use kemlock_domain::manifest::SignedManifest;
use kemlock_domain::{DeviceId, Owner, UserId};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use time::OffsetDateTime;

#[derive(Default)]
struct ContractInner {
    manifests: HashMap<Owner, SignedManifest>,
    uses: HashMap<DeviceId, DeviceApiUse>,
    bw: HashMap<UserId, BwAccount>,
}

/// The maps behind the three repositories.
#[derive(Clone, Default)]
pub(crate) struct ContractState(Arc<Mutex<ContractInner>>);

impl ContractState {
    fn lock(&self) -> std::sync::MutexGuard<'_, ContractInner> {
        self.0.lock().expect("the contract lock isn't poisoned")
    }
}

impl FakeStore {
    pub(crate) fn manifest_of(&self, owner: Owner) -> Option<SignedManifest> {
        self.contract.lock().manifests.get(&owner).cloned()
    }

    pub(crate) fn use_of(&self, device: DeviceId) -> Option<DeviceApiUse> {
        self.contract.lock().uses.get(&device).copied()
    }

    /// Gives an account a Bitwarden record, as the Bitwarden API's registration does.
    pub(crate) fn put_bw_account(&self, account: BwAccount) {
        self.contract.lock().bw.insert(account.user, account);
    }

    pub(crate) fn bw_account_of(&self, user: UserId) -> Option<BwAccount> {
        self.contract.lock().bw.get(&user).cloned()
    }
}

impl ManifestRepo for FakeStore {
    async fn manifest(&self, owner: Owner) -> Result<Option<SignedManifest>, StoreError> {
        Ok(self.contract.lock().manifests.get(&owner).cloned())
    }

    async fn put_manifest(&self, manifest: &SignedManifest) -> Result<bool, StoreError> {
        if !self.lock().users.contains_key(&manifest.signer) {
            return Err(StoreError::NotFound);
        }
        let mut g = self.contract.lock();
        if g.manifests
            .get(&manifest.owner)
            .is_some_and(|stored| stored.counter >= manifest.counter)
        {
            return Ok(false);
        }
        g.manifests.insert(manifest.owner, manifest.clone());
        Ok(true)
    }
}

impl ApiUseRepo for FakeStore {
    async fn record_use(
        &self,
        device: DeviceId,
        api: ApiKind,
        at: OffsetDateTime,
    ) -> Result<(), StoreError> {
        if !self.lock().devices.contains_key(&device) {
            return Err(StoreError::NotFound);
        }
        let mut g = self.contract.lock();
        let row = g
            .uses
            .entry(device)
            .or_insert_with(|| DeviceApiUse::none(device));
        let slot = match api {
            ApiKind::Kemlock => &mut row.kemlock,
            ApiKind::Bitwarden => &mut row.bitwarden,
        };
        if slot.is_none_or(|old| old < at - USE_GRANULARITY) {
            *slot = Some(at);
        }
        Ok(())
    }

    async fn uses_of(&self, devices: &[DeviceId]) -> Result<Vec<DeviceApiUse>, StoreError> {
        let g = self.contract.lock();
        Ok(devices
            .iter()
            .filter_map(|d| g.uses.get(d).copied())
            .collect())
    }
}

impl BwAccountRepo for FakeStore {
    async fn get(&self, user: UserId) -> Result<Option<BwAccount>, StoreError> {
        Ok(self.contract.lock().bw.get(&user).cloned())
    }

    async fn insert(&self, account: &BwAccount) -> Result<(), StoreError> {
        if !self.lock().users.contains_key(&account.user) {
            return Err(StoreError::NotFound);
        }
        let mut g = self.contract.lock();
        if g.bw.contains_key(&account.user) {
            return Err(StoreError::Duplicate);
        }
        g.bw.insert(account.user, account.clone());
        Ok(())
    }

    async fn update(&self, account: &BwAccount) -> Result<(), StoreError> {
        let mut g = self.contract.lock();
        match g.bw.get_mut(&account.user) {
            Some(stored) => {
                let revision_ms = stored.revision_ms;
                *stored = BwAccount {
                    revision_ms,
                    ..account.clone()
                };
                Ok(())
            }
            None => Err(StoreError::NotFound),
        }
    }

    async fn touch(&self, user: UserId, now_ms: i64) -> Result<i64, StoreError> {
        let mut g = self.contract.lock();
        let stored = g.bw.get_mut(&user).ok_or(StoreError::NotFound)?;
        stored.revision_ms = now_ms.max(stored.revision_ms + 1);
        Ok(stored.revision_ms)
    }
}
