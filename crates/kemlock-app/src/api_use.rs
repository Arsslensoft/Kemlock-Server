//! Which API each device last used, and the account's device list.
//!
//! The Kemlock API records a use on every authenticated request and the Bitwarden API does the
//! same on its own, both into `device_api_use`. The list reads them back beside the device row, so
//! the app can say which devices still sync through the Bitwarden API (a phone that moved to the
//! Kemlock API has a recent Kemlock use and an old Bitwarden one).

use crate::authenticate::Actor;
use crate::devices::KeyCopyRepo;
use crate::error::AppError;
use crate::ports::{Clock, DeviceRepo, StoreError};
use kemlock_domain::api_use::{ApiKind, DeviceApiUse};
use kemlock_domain::{Device, DeviceId, DeviceKind};
use std::future::Future;
use time::{Duration, OffsetDateTime};

/// A recorded use moves at most once in this long, so an authenticated request costs a cheap
/// conditional update, not a write.
pub const USE_GRANULARITY: Duration = Duration::seconds(60);

/// The last use of each API per device (`device_api_use`). It is a separate table, keyed by the
/// device, so neither API's use case needs to know the other's column.
pub trait ApiUseRepo: Send + Sync {
    /// Sets the device's last use of `api` to `at`, unless it is already within
    /// [`USE_GRANULARITY`] of it or later. The other API's column is left alone. `NotFound` when
    /// the device does not exist (it was signed out).
    fn record_use(
        &self,
        device: DeviceId,
        api: ApiKind,
        at: OffsetDateTime,
    ) -> impl Future<Output = Result<(), StoreError>> + Send;

    /// The use of each of these devices that has any; a device that used no API has no row.
    fn uses_of(
        &self,
        devices: &[DeviceId],
    ) -> impl Future<Output = Result<Vec<DeviceApiUse>, StoreError>> + Send;
}

/// Records that a device used an API now. It never fails: the request it rides on has succeeded
/// already, and a missed use only makes a device look idle a minute longer.
#[derive(Debug)]
pub struct RecordApiUse<R, C> {
    pub uses: R,
    pub clock: C,
}

impl<R: ApiUseRepo, C: Clock> RecordApiUse<R, C> {
    pub async fn execute(&self, device: DeviceId, api: ApiKind) {
        match self.uses.record_use(device, api, self.clock.now()).await {
            Ok(()) => {}
            // Signed out between the token check and now.
            Err(StoreError::NotFound) => {}
            Err(e) => tracing::warn!(error = %e, ?api, "could not record a device's API use"),
        }
    }
}

/// A device as the list shows it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DeviceEntry {
    pub id: DeviceId,
    pub name: String,
    pub kind: DeviceKind,
    pub created_at: OffsetDateTime,
    /// The latest sign-in, refresh or use of either API.
    pub last_seen_at: OffsetDateTime,
    /// The last authenticated request on the Kemlock API, if any.
    pub last_kemlock_use_at: Option<OffsetDateTime>,
    /// The last authenticated request on the Bitwarden API, if any.
    pub last_bitwarden_use_at: Option<OffsetDateTime>,
    /// Whether this is the device that asked.
    pub current: bool,
    /// Whether the device keeps a trusted-device copy of the root key on the server.
    pub trusted: bool,
}

/// Lists the signed-in account's devices.
#[derive(Debug)]
pub struct ListDevices<D, U, K> {
    pub devices: D,
    pub uses: U,
    pub copies: K,
}

impl<D: DeviceRepo, U: ApiUseRepo, K: KeyCopyRepo> ListDevices<D, U, K> {
    /// The account's devices, most recently seen first.
    pub async fn execute(&self, actor: &Actor) -> Result<Vec<DeviceEntry>, AppError> {
        let devices = self.devices.list(actor.user).await?;
        let ids: Vec<DeviceId> = devices.iter().map(|d| d.id).collect();
        let uses = self.uses.uses_of(&ids).await?;
        let mut entries = Vec::with_capacity(devices.len());
        for device in devices {
            let usage = uses
                .iter()
                .find(|u| u.device == device.id)
                .copied()
                .unwrap_or_else(|| DeviceApiUse::none(device.id));
            let trusted = self.copies.key_copy(device.id).await?.is_some();
            entries.push(entry(device, &usage, actor.device, trusted));
        }
        entries.sort_by(|a, b| {
            b.last_seen_at
                .cmp(&a.last_seen_at)
                .then_with(|| a.id.cmp(&b.id))
        });
        Ok(entries)
    }
}

/// A device the Bitwarden API made and the Kemlock API never saw has no DPoP key, and may have no
/// recorded use either: it signed in before uses were recorded, or came in with an import. Its
/// last sign-in or refresh is then its last Bitwarden use, so the move off Vaultwarden still sees
/// it as one that only talks to the Bitwarden API.
fn last_bitwarden_use(device: &Device, usage: &DeviceApiUse) -> Option<OffsetDateTime> {
    let only_bitwarden = usage.kemlock.is_none() && device.dpop_jkt.is_none();
    usage
        .bitwarden
        .or_else(|| only_bitwarden.then_some(device.last_seen_at))
}

fn entry(device: Device, usage: &DeviceApiUse, current: DeviceId, trusted: bool) -> DeviceEntry {
    DeviceEntry {
        id: device.id,
        last_seen_at: device
            .last_seen_at
            .max(usage.latest().unwrap_or(device.last_seen_at)),
        last_kemlock_use_at: usage.kemlock,
        last_bitwarden_use_at: last_bitwarden_use(&device, usage),
        current: device.id == current,
        trusted,
        name: device.name,
        kind: device.kind,
        created_at: device.created_at,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use kemlock_domain::UserId;
    use time::macros::datetime;

    fn device(seen: OffsetDateTime) -> Device {
        Device {
            id: DeviceId::random(),
            user: UserId::random(),
            name: "Pixel".to_owned(),
            kind: DeviceKind::KemlockAndroid,
            dpop_jkt: None,
            created_at: datetime!(2026-01-01 00:00:00 UTC),
            last_seen_at: seen,
        }
    }

    #[test]
    fn last_seen_is_the_latest_of_the_row_and_both_uses() {
        let d = device(datetime!(2026-03-01 00:00:00 UTC));
        let usage = DeviceApiUse {
            device: d.id,
            kemlock: Some(datetime!(2026-04-01 00:00:00 UTC)),
            bitwarden: Some(datetime!(2026-02-01 00:00:00 UTC)),
        };
        let e = entry(d.clone(), &usage, d.id, true);
        assert_eq!(e.last_seen_at, datetime!(2026-04-01 00:00:00 UTC));
        assert_eq!(e.last_kemlock_use_at, usage.kemlock);
        assert_eq!(e.last_bitwarden_use_at, usage.bitwarden);
        assert!(e.current && e.trusted);
    }

    #[test]
    fn a_device_with_no_use_keeps_its_own_last_seen() {
        let d = device(datetime!(2026-03-01 00:00:00 UTC));
        let e = entry(
            d.clone(),
            &DeviceApiUse::none(d.id),
            DeviceId::random(),
            false,
        );
        assert_eq!(e.last_seen_at, d.last_seen_at);
        assert_eq!(e.last_kemlock_use_at, None);
        assert!(!e.current && !e.trusted);
    }

    #[test]
    fn a_bitwarden_only_device_with_no_recorded_use_shows_its_last_seen_as_the_use() {
        let seen = datetime!(2026-03-01 00:00:00 UTC);
        let d = device(seen);
        let e = entry(
            d.clone(),
            &DeviceApiUse::none(d.id),
            DeviceId::random(),
            false,
        );
        assert_eq!(e.last_bitwarden_use_at, Some(seen));
        assert_eq!(e.last_kemlock_use_at, None);

        // A recorded use wins over the guess.
        let used = datetime!(2026-03-05 00:00:00 UTC);
        let usage = DeviceApiUse {
            device: d.id,
            kemlock: None,
            bitwarden: Some(used),
        };
        let e = entry(d.clone(), &usage, DeviceId::random(), false);
        assert_eq!(e.last_bitwarden_use_at, Some(used));
        assert_eq!(e.last_seen_at, used);
    }

    #[test]
    fn a_device_the_kemlock_api_knows_is_not_taken_for_a_bitwarden_one() {
        let mut d = device(datetime!(2026-03-01 00:00:00 UTC));
        d.dpop_jkt = Some("jkt".to_owned());
        let e = entry(
            d.clone(),
            &DeviceApiUse::none(d.id),
            DeviceId::random(),
            false,
        );
        assert_eq!(e.last_bitwarden_use_at, None);

        // Nor one with a recorded Kemlock use, even without a key on its row.
        let mut d = device(datetime!(2026-03-01 00:00:00 UTC));
        d.dpop_jkt = None;
        let usage = DeviceApiUse {
            device: d.id,
            kemlock: Some(datetime!(2026-03-02 00:00:00 UTC)),
            bitwarden: None,
        };
        let e = entry(d, &usage, DeviceId::random(), false);
        assert_eq!(e.last_bitwarden_use_at, None);
    }
}
