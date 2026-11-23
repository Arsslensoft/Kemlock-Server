//! The mail about a device that signs in for the first time ("a new device signed in to your
//! account"), sent after the sign-in completes by any route: the password, a second step, a
//! passkey or single sign-on. A device the account has used before is not announced.
//!
//! The Bitwarden API sends the same mail when its own sign-in meets a device it hasn't seen
//! (Vaultwarden's new-device notice); both share one device row, so a device that signed in on
//! one API is not new to the other.

use crate::state::{Api, Crypto, Store};
use kemlock_app::TokenPair;
use kemlock_app::devices::NewDeviceNotice;
use kemlock_app::notices::Notice;
use kemlock_app::ports::{DeviceRepo, TokenSigner, UserRepo};
use kemlock_domain::Device;
use kemlock_domain::unlock::truncate_ip;
use std::net::IpAddr;

/// Whether the device has signed in only once. A device is stored with the same time for its
/// creation and its last sight, and any later sign-in or refresh moves the second.
pub(crate) fn is_first_sign_in(device: &Device) -> bool {
    device.created_at == device.last_seen_at
}

/// Mails the account's owner when `tokens` are the first a device was given. Best effort and never
/// waited for: the sign-in has succeeded already, and mail can be slow.
pub(crate) async fn announce<S, P, K>(api: &Api<S, P, K>, tokens: &TokenPair, ip: IpAddr)
where
    S: Store,
    P: Crypto,
    K: TokenSigner + Clone + 'static,
{
    let notices = api.hub.notices();
    if !notices.mails() {
        return;
    }
    let Ok(Some(device)) = DeviceRepo::get(&api.store, tokens.device).await else {
        return;
    };
    if !is_first_sign_in(&device) {
        return;
    }
    let Ok(Some(user)) = UserRepo::by_id(&api.store, tokens.user).await else {
        return;
    };
    let notice = NewDeviceNotice {
        to: user.email,
        device_name: device.name,
        device_kind: device.kind,
        ip: truncate_ip(ip),
        at: device.last_seen_at,
    };
    tokio::spawn(async move {
        notices.send(Notice::NewDevice(notice)).await;
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use kemlock_domain::{DeviceId, DeviceKind, UserId};
    use time::macros::datetime;

    fn device(created: time::OffsetDateTime, seen: time::OffsetDateTime) -> Device {
        Device {
            id: DeviceId::random(),
            user: UserId::random(),
            name: "Pixel".to_owned(),
            kind: DeviceKind::KemlockAndroid,
            dpop_jkt: None,
            created_at: created,
            last_seen_at: seen,
        }
    }

    #[test]
    fn a_device_never_seen_again_is_on_its_first_sign_in() {
        let at = datetime!(2026-11-25 10:00 UTC);
        assert!(is_first_sign_in(&device(at, at)));
        assert!(!is_first_sign_in(&device(
            at,
            datetime!(2026-11-25 10:05 UTC)
        )));
    }
}
