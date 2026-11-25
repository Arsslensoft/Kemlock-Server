//! Helpers for this crate's tests: a server on an ephemeral port, an in-memory push repository
//! and a seal that is not one.

use axum::Router;
use kemlock_app::ports::{CryptoError, SecretSeal, StoreError, Zeroizing};
use kemlock_app::push::{PushInstallation, PushRegistration, PushRepo};
use kemlock_domain::{DeviceId, UserId};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::Duration;

/// Serves `router` on 127.0.0.1 and returns its address. The server lives as long as the test's
/// runtime.
pub(crate) async fn serve(router: Router) -> SocketAddr {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("binds");
    let address = listener.local_addr().expect("address");
    tokio::spawn(async move {
        let _ = axum::serve(listener, router).await;
    });
    address
}

/// Waits until `check` holds, up to five seconds.
pub(crate) async fn eventually(mut check: impl FnMut() -> bool) {
    for _ in 0..500 {
        if check() {
            return;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    panic!("the condition never held");
}

/// A "seal" that only tags the value with its purpose, so a test can see the purpose is bound and
/// the value is not stored as given.
#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct TaggedSeal;

impl SecretSeal for TaggedSeal {
    fn seal(&self, purpose: &str, value: &[u8]) -> Vec<u8> {
        let mut out: Vec<u8> = value.iter().map(|b| b ^ 0x5a).collect();
        out.extend_from_slice(b"|");
        out.extend_from_slice(purpose.as_bytes());
        out
    }

    fn open(&self, purpose: &str, sealed: &[u8]) -> Result<Zeroizing<Vec<u8>>, CryptoError> {
        let tag = [b"|".as_slice(), purpose.as_bytes()].concat();
        let body = sealed
            .strip_suffix(tag.as_slice())
            .ok_or(CryptoError::Invalid)?;
        Ok(Zeroizing::new(body.iter().map(|b| b ^ 0x5a).collect()))
    }
}

/// A push repository in memory.
#[derive(Clone, Default)]
pub(crate) struct MemoryPush {
    pub(crate) registrations: Arc<Mutex<HashMap<DeviceId, PushRegistration>>>,
    pub(crate) installation: Arc<Mutex<Option<PushInstallation>>>,
}

impl MemoryPush {
    /// An iPhone's token.
    pub(crate) fn add(&self, user: UserId, token: &str) -> DeviceId {
        self.add_kind(user, kemlock_app::push::PushKind::Apns, token)
    }

    pub(crate) fn add_kind(
        &self,
        user: UserId,
        kind: kemlock_app::push::PushKind,
        token: &str,
    ) -> DeviceId {
        let device = DeviceId::random();
        self.registrations.lock().expect("lock").insert(
            device,
            PushRegistration {
                device,
                user,
                kind,
                token: token.to_owned(),
                updated_at: time::macros::datetime!(2026-11-23 12:00 UTC),
            },
        );
        device
    }

    pub(crate) fn tokens(&self) -> Vec<String> {
        let mut tokens: Vec<String> = self
            .registrations
            .lock()
            .expect("lock")
            .values()
            .map(|r| r.token.clone())
            .collect();
        tokens.sort();
        tokens
    }
}

impl PushRepo for MemoryPush {
    async fn put_registration(&self, registration: &PushRegistration) -> Result<(), StoreError> {
        self.registrations
            .lock()
            .expect("lock")
            .insert(registration.device, registration.clone());
        Ok(())
    }

    async fn remove_registration(&self, device: DeviceId) -> Result<(), StoreError> {
        self.registrations.lock().expect("lock").remove(&device);
        Ok(())
    }

    async fn registrations_for(
        &self,
        users: &[UserId],
    ) -> Result<Vec<PushRegistration>, StoreError> {
        Ok(self
            .registrations
            .lock()
            .expect("lock")
            .values()
            .filter(|r| users.contains(&r.user))
            .cloned()
            .collect())
    }

    async fn installation(&self) -> Result<Option<PushInstallation>, StoreError> {
        Ok(self.installation.lock().expect("lock").clone())
    }

    async fn set_installation(&self, installation: &PushInstallation) -> Result<(), StoreError> {
        *self.installation.lock().expect("lock") = Some(installation.clone());
        Ok(())
    }

    async fn clear_installation(&self) -> Result<(), StoreError> {
        *self.installation.lock().expect("lock") = None;
        Ok(())
    }
}

/// Like [`serve`], with peer addresses available to handlers (`ConnectInfo`).
pub(crate) async fn serve_with_peers(router: Router) -> SocketAddr {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("binds");
    let address = listener.local_addr().expect("address");
    tokio::spawn(async move {
        let _ = axum::serve(
            listener,
            router.into_make_service_with_connect_info::<SocketAddr>(),
        )
        .await;
    });
    address
}
