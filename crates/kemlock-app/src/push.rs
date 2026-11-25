//! Push: the device tokens a mobile app registers, the installation the server may hold with
//! Kemlock's optional push relay, and the small log replicas read to nudge each other's sockets.
//!
//! A push carries nothing but "sync now". The server sends it itself: to Apple's push service
//! with the operator's own key, and to a UnifiedPush endpoint on the phone's distributor. Only an
//! operator who opts in to the hosted relay (a fallback for iPhones when the server has no Apple
//! key) sends a device's token through it, with the server's installation id and that nudge; the
//! relay never sees an email, an account id or an item.

use crate::authenticate::Actor;
use crate::error::AppError;
use crate::ports::{Clock, DeviceRepo, StoreError};
use kemlock_domain::{DeviceId, Owner, UserId};
use std::future::Future;
use time::OffsetDateTime;

/// The longest push token stored. APNs tokens are 64 hex digits and UnifiedPush endpoints are
/// URLs; the cap leaves room without letting a client fill the table.
pub const MAX_PUSH_TOKEN_LEN: usize = 512;

/// Which service a push token is for.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum PushKind {
    /// Firebase Cloud Messaging. Kemlock does not use it: no new token of this kind is accepted
    /// and none is sent to. The variant stays so rows an older server stored still read.
    Fcm,
    /// Apple Push Notification service (iOS).
    Apns,
    /// UnifiedPush (Android): the token is the endpoint URL the phone's distributor gave.
    UnifiedPush,
}

impl PushKind {
    pub fn as_str(self) -> &'static str {
        match self {
            PushKind::Fcm => "fcm",
            PushKind::Apns => "apns",
            PushKind::UnifiedPush => "unifiedpush",
        }
    }

    /// Reads a stored or sent kind. `fcm` parses (old rows still read) but is not
    /// [`registrable`](PushKind::registrable).
    pub fn parse(text: &str) -> Option<PushKind> {
        match text {
            "fcm" => Some(PushKind::Fcm),
            "apns" => Some(PushKind::Apns),
            "unifiedpush" => Some(PushKind::UnifiedPush),
            _ => None,
        }
    }

    /// Whether a device may register a token of this kind now.
    pub fn registrable(self) -> bool {
        !matches!(self, PushKind::Fcm)
    }
}

/// Checks the endpoint URL a UnifiedPush distributor gave: `https`, a host, no credentials, port
/// 443 (the default) or 8443 so the server can't be pointed at other services on a public host,
/// at most [`MAX_PUSH_TOKEN_LEN`] characters. Whether the host is a public address is checked when
/// sending, because a name can resolve differently later.
pub fn check_unifiedpush_endpoint(endpoint: &str) -> Result<url::Url, &'static str> {
    if endpoint.len() > MAX_PUSH_TOKEN_LEN {
        return Err("the UnifiedPush endpoint is too long");
    }
    let url = url::Url::parse(endpoint).map_err(|_| "the UnifiedPush endpoint is not a URL")?;
    if url.scheme() != "https" {
        return Err("the UnifiedPush endpoint must be an https URL");
    }
    if url.host_str().is_none_or(str::is_empty) {
        return Err("the UnifiedPush endpoint has no host");
    }
    if !url.username().is_empty() || url.password().is_some() {
        return Err("the UnifiedPush endpoint must not carry a user name or password");
    }
    // `https` with no port means 443, which the parser leaves out.
    if url.port().is_some_and(|port| port != 8443) {
        return Err("the UnifiedPush endpoint must use port 443 or 8443");
    }
    Ok(url)
}

/// A device's push token.
#[derive(Clone, PartialEq, Eq)]
pub struct PushRegistration {
    pub device: DeviceId,
    pub user: UserId,
    pub kind: PushKind,
    pub token: String,
    pub updated_at: OffsetDateTime,
}

impl std::fmt::Debug for PushRegistration {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // The token is a bearer credential for the device's pushes.
        f.debug_struct("PushRegistration")
            .field("device", &self.device)
            .field("user", &self.user)
            .field("kind", &self.kind)
            .field("token", &"<redacted>")
            .finish_non_exhaustive()
    }
}

/// What the server holds from registering with the optional relay: its installation id, and the
/// installation key sealed under `server.key` (purpose `push-installation-key`).
#[derive(Clone, PartialEq, Eq)]
pub struct PushInstallation {
    pub id: String,
    pub sealed_key: Vec<u8>,
}

impl std::fmt::Debug for PushInstallation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PushInstallation")
            .field("id", &self.id)
            .finish_non_exhaustive()
    }
}

/// The seal purpose of the installation key.
pub const PURPOSE_PUSH_INSTALLATION_KEY: &str = "push-installation-key";

pub trait PushRepo: Send + Sync {
    /// Stores or replaces the device's token. `NotFound` when the device doesn't exist.
    fn put_registration(
        &self,
        registration: &PushRegistration,
    ) -> impl Future<Output = Result<(), StoreError>> + Send;

    /// Forgets the device's token, if it has one.
    fn remove_registration(
        &self,
        device: DeviceId,
    ) -> impl Future<Output = Result<(), StoreError>> + Send;

    /// The tokens of these accounts' devices.
    fn registrations_for(
        &self,
        users: &[UserId],
    ) -> impl Future<Output = Result<Vec<PushRegistration>, StoreError>> + Send;

    /// The server's installation with the relay, once it has registered.
    fn installation(
        &self,
    ) -> impl Future<Output = Result<Option<PushInstallation>, StoreError>> + Send;

    fn set_installation(
        &self,
        installation: &PushInstallation,
    ) -> impl Future<Output = Result<(), StoreError>> + Send;

    /// Forgets the installation (the admin turned the relay off).
    fn clear_installation(&self) -> impl Future<Output = Result<(), StoreError>> + Send;
}

/// One entry of the nudge log: a change reached `owner`'s vault.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct NudgeEntry {
    pub id: i64,
    pub owner: Owner,
}

/// A small table every replica appends to and polls, for a database with no notification
/// channel (MySQL). It carries only the owner, never what changed.
pub trait NudgeLog: Send + Sync {
    /// Appends an entry and returns its id.
    fn append_nudge(&self, owner: Owner) -> impl Future<Output = Result<i64, StoreError>> + Send;

    /// Entries after `after`, oldest first, at most `limit`.
    fn nudges_since(
        &self,
        after: i64,
        limit: u32,
    ) -> impl Future<Output = Result<Vec<NudgeEntry>, StoreError>> + Send;

    /// The newest entry's id, 0 for an empty log: where a replica starts listening.
    fn latest_nudge(&self) -> impl Future<Output = Result<i64, StoreError>> + Send;

    /// Deletes entries older than `before`. Returns how many went.
    fn prune_nudges(
        &self,
        before: OffsetDateTime,
    ) -> impl Future<Output = Result<u64, StoreError>> + Send;
}

/// `POST /kem/v1/devices/push-token`: the signed-in device's push token.
#[derive(Debug)]
pub struct RegisterPushToken<D, R, C> {
    pub devices: D,
    pub push: R,
    pub clock: C,
}

impl<D: DeviceRepo, R: PushRepo, C: Clock> RegisterPushToken<D, R, C> {
    /// Stores the token for the device the access token names.
    pub async fn register(
        &self,
        actor: &Actor,
        kind: PushKind,
        token: &str,
    ) -> Result<(), AppError> {
        if !kind.registrable() {
            return Err(AppError::Invalid("the push kind is not accepted"));
        }
        let token = token.trim();
        if token.is_empty() || token.len() > MAX_PUSH_TOKEN_LEN {
            return Err(AppError::Invalid(
                "the push token must be 1 to 512 characters",
            ));
        }
        if token.chars().any(|c| c.is_control() || c.is_whitespace()) {
            return Err(AppError::Invalid(
                "the push token has a space or control character",
            ));
        }
        if kind == PushKind::UnifiedPush {
            check_unifiedpush_endpoint(token).map_err(AppError::Invalid)?;
        }
        // The token names a device; the device may have been signed out since.
        let device = self
            .devices
            .get(actor.device)
            .await?
            .filter(|d| d.user == actor.user)
            .ok_or(AppError::NotFound)?;
        self.push
            .put_registration(&PushRegistration {
                device: device.id,
                user: device.user,
                kind,
                token: token.to_owned(),
                updated_at: self.clock.now(),
            })
            .await?;
        Ok(())
    }

    /// Forgets the token (the app turned notifications off). Fine when there is none.
    pub async fn unregister(&self, actor: &Actor) -> Result<(), AppError> {
        self.push.remove_registration(actor.device).await?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use kemlock_domain::{Device, DeviceKind};
    use std::collections::HashMap;
    use std::sync::{Arc, Mutex};
    use time::macros::datetime;

    #[derive(Clone, Default)]
    struct Devices(Arc<Mutex<HashMap<DeviceId, Device>>>);

    impl DeviceRepo for Devices {
        async fn get(&self, id: DeviceId) -> Result<Option<Device>, StoreError> {
            Ok(self.0.lock().expect("lock").get(&id).cloned())
        }
        async fn upsert(&self, device: &Device) -> Result<(), StoreError> {
            self.0
                .lock()
                .expect("lock")
                .insert(device.id, device.clone());
            Ok(())
        }
        async fn list(&self, _user: UserId) -> Result<Vec<Device>, StoreError> {
            Ok(Vec::new())
        }
        async fn remove(&self, id: DeviceId) -> Result<(), StoreError> {
            self.0.lock().expect("lock").remove(&id);
            Ok(())
        }
    }

    #[derive(Clone, Default)]
    struct Pushes(Arc<Mutex<HashMap<DeviceId, PushRegistration>>>);

    impl PushRepo for Pushes {
        async fn put_registration(&self, r: &PushRegistration) -> Result<(), StoreError> {
            self.0.lock().expect("lock").insert(r.device, r.clone());
            Ok(())
        }
        async fn remove_registration(&self, device: DeviceId) -> Result<(), StoreError> {
            self.0.lock().expect("lock").remove(&device);
            Ok(())
        }
        async fn registrations_for(
            &self,
            users: &[UserId],
        ) -> Result<Vec<PushRegistration>, StoreError> {
            Ok(self
                .0
                .lock()
                .expect("lock")
                .values()
                .filter(|r| users.contains(&r.user))
                .cloned()
                .collect())
        }
        async fn installation(&self) -> Result<Option<PushInstallation>, StoreError> {
            Ok(None)
        }
        async fn set_installation(&self, _: &PushInstallation) -> Result<(), StoreError> {
            Ok(())
        }
        async fn clear_installation(&self) -> Result<(), StoreError> {
            Ok(())
        }
    }

    struct Now;
    impl Clock for Now {
        fn now(&self) -> OffsetDateTime {
            datetime!(2026-11-23 12:00 UTC)
        }
    }

    fn setup() -> (RegisterPushToken<Devices, Pushes, Now>, Actor, Pushes) {
        let devices = Devices::default();
        let push = Pushes::default();
        let user = UserId::random();
        let device = Device {
            id: DeviceId::random(),
            user,
            name: "Pixel".to_owned(),
            kind: DeviceKind::KemlockAndroid,
            dpop_jkt: None,
            created_at: datetime!(2026-11-01 00:00 UTC),
            last_seen_at: datetime!(2026-11-01 00:00 UTC),
        };
        devices
            .0
            .lock()
            .expect("lock")
            .insert(device.id, device.clone());
        let actor = Actor {
            user,
            device: device.id,
            admin: false,
        };
        (
            RegisterPushToken {
                devices,
                push: push.clone(),
                clock: Now,
            },
            actor,
            push,
        )
    }

    #[tokio::test]
    async fn a_device_registers_and_replaces_its_token() {
        let (case, actor, push) = setup();
        case.register(&actor, PushKind::Apns, "token-one")
            .await
            .expect("registers");
        case.register(&actor, PushKind::Apns, " token-two ")
            .await
            .expect("replaces");
        let all = push.registrations_for(&[actor.user]).await.expect("lists");
        assert_eq!(all.len(), 1);
        assert_eq!(all[0].token, "token-two");
        assert_eq!(all[0].updated_at, datetime!(2026-11-23 12:00 UTC));
    }

    #[tokio::test]
    async fn bad_tokens_are_refused() {
        let (case, actor, _) = setup();
        let long = "x".repeat(513);
        for bad in ["", "   ", "has space", "tab\there", long.as_str()] {
            assert!(
                matches!(
                    case.register(&actor, PushKind::Apns, bad).await,
                    Err(AppError::Invalid(_))
                ),
                "{bad:?}"
            );
        }
    }

    #[tokio::test]
    async fn a_unifiedpush_endpoint_registers_when_it_is_an_https_url() {
        let (case, actor, push) = setup();
        case.register(
            &actor,
            PushKind::UnifiedPush,
            "https://ntfy.example.org/upABC123?up=1",
        )
        .await
        .expect("registers");
        let all = push.registrations_for(&[actor.user]).await.expect("lists");
        assert_eq!(all[0].kind, PushKind::UnifiedPush);
        assert_eq!(all[0].token, "https://ntfy.example.org/upABC123?up=1");
    }

    #[test]
    fn only_ports_443_and_8443_are_accepted_for_an_endpoint() {
        for good in [
            "https://ntfy.example.org/up",
            "https://ntfy.example.org:443/up",
            "https://ntfy.example.org:8443/up",
        ] {
            assert!(check_unifiedpush_endpoint(good).is_ok(), "{good}");
        }
        for bad in ["https://ntfy.example.org:80/up", "https://ntfy.example.org:1/up"] {
            assert_eq!(
                check_unifiedpush_endpoint(bad).map(|_| ()),
                Err("the UnifiedPush endpoint must use port 443 or 8443"),
                "{bad}"
            );
        }
    }

    #[tokio::test]
    async fn bad_unifiedpush_endpoints_are_refused() {
        let (case, actor, push) = setup();
        let long = format!("https://example.org/{}", "x".repeat(500));
        for bad in [
            "http://ntfy.example.org/up",
            "ftp://ntfy.example.org/up",
            "not a url",
            "no-scheme.example.org/up",
            "https://",
            "https://user:pw@ntfy.example.org/up",
            "https://ntfy.example.org:22/up",
            "https://ntfy.example.org:8080/up",
            "https://ntfy.example.org:6379/up",
            "https://ntfy.example.org:444/up",
            long.as_str(),
        ] {
            assert!(
                matches!(
                    case.register(&actor, PushKind::UnifiedPush, bad).await,
                    Err(AppError::Invalid(_))
                ),
                "{bad:?}"
            );
        }
        assert!(
            push.registrations_for(&[actor.user])
                .await
                .expect("lists")
                .is_empty()
        );
    }

    #[tokio::test]
    async fn fcm_is_no_longer_accepted() {
        let (case, actor, push) = setup();
        assert_eq!(
            case.register(&actor, PushKind::Fcm, "token").await,
            Err(AppError::Invalid("the push kind is not accepted"))
        );
        assert!(
            push.registrations_for(&[actor.user])
                .await
                .expect("lists")
                .is_empty()
        );
        // Old rows still read: the kind parses, it just can't be registered.
        assert_eq!(PushKind::parse("fcm"), Some(PushKind::Fcm));
        assert!(!PushKind::Fcm.registrable());
        assert!(PushKind::Apns.registrable() && PushKind::UnifiedPush.registrable());
    }

    #[test]
    fn kinds_keep_their_wire_names() {
        for kind in [PushKind::Fcm, PushKind::Apns, PushKind::UnifiedPush] {
            assert_eq!(PushKind::parse(kind.as_str()), Some(kind));
        }
        assert_eq!(PushKind::UnifiedPush.as_str(), "unifiedpush");
    }

    #[tokio::test]
    async fn a_signed_out_device_cannot_register() {
        let (case, actor, _) = setup();
        case.devices.remove(actor.device).await.expect("removes");
        assert_eq!(
            case.register(&actor, PushKind::Apns, "t").await,
            Err(AppError::NotFound)
        );
    }

    #[tokio::test]
    async fn another_accounts_device_is_not_found() {
        let (case, mut actor, _) = setup();
        actor.user = UserId::random();
        assert_eq!(
            case.register(&actor, PushKind::Apns, "t").await,
            Err(AppError::NotFound)
        );
    }

    #[tokio::test]
    async fn unregistering_forgets_the_token() {
        let (case, actor, push) = setup();
        case.register(&actor, PushKind::Apns, "t")
            .await
            .expect("registers");
        case.unregister(&actor).await.expect("unregisters");
        assert!(
            push.registrations_for(&[actor.user])
                .await
                .expect("lists")
                .is_empty()
        );
        // Twice is fine.
        case.unregister(&actor).await.expect("unregisters again");
    }

    #[test]
    fn a_token_stays_out_of_debug_output() {
        let r = PushRegistration {
            device: DeviceId::random(),
            user: UserId::random(),
            kind: PushKind::Fcm,
            token: "secret-token".to_owned(),
            updated_at: datetime!(2026-11-23 12:00 UTC),
        };
        assert!(!format!("{r:?}").contains("secret-token"));
        assert_eq!(PushKind::parse("apns"), Some(PushKind::Apns));
        assert_eq!(PushKind::parse("sms"), None);
    }
}
