//! The two values the server hands to a client sealed instead of keeping state: the OPAQUE login
//! state and the two-step challenge. Each carries its own expiry, is sealed under `server.key`
//! with its own purpose, and is checked when it comes back.

use crate::ports::{CryptoError, SecretSeal, Zeroizing};
use kemlock_domain::{DeviceId, DeviceKind, UserId};
use uuid::Uuid;

/// `SecretSeal` purpose of the OPAQUE login state.
pub const PURPOSE_LOGIN: &str = "opaque-login";
/// `SecretSeal` purpose of the two-step challenge.
pub const PURPOSE_CHALLENGE: &str = "two-factor-challenge";
/// `SecretSeal` purpose of a stored TOTP secret.
pub const PURPOSE_TOTP: &str = "totp";

/// The `settings` key that says the stored per-account secrets were sealed again, bound
/// ([`bound_purpose`]), by the start-up pass. It is a record only: the pass runs at every start, so
/// secrets a restored backup brings back sealed the old way are sealed again before the server
/// serves.
pub const SECRETS_BOUND_KEY: &str = "secrets_bound";

/// Whether [`open_bound`] still falls back to the bare purpose. On until the server has sealed every
/// stored secret again, bound: a fallback that stays on for good lets someone who can write the
/// database keep a copy of a secret sealed the old way (their own, say) and paste it into any
/// account's row later.
static BARE_FALLBACK: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(true);

/// Turns the fallback to the bare purpose on or off (the server turns it off once its start-up
/// pass has sealed every stored secret again, bound).
pub fn allow_bare_secrets(allowed: bool) {
    BARE_FALLBACK.store(allowed, std::sync::atomic::Ordering::Relaxed);
}

/// Whether [`open_bound`] falls back to the bare purpose now.
pub fn bare_secrets_allowed() -> bool {
    BARE_FALLBACK.load(std::sync::atomic::Ordering::Relaxed)
}

/// The purpose a per-account secret is sealed under: the secret's own purpose and the account's
/// id, so a sealed value copied into another account's row (by someone who can write the database
/// but doesn't hold `server.key`) doesn't open there. The purpose is the key's HKDF input and the
/// seal's associated data, so the binding needs no change to the seal.
pub fn bound_purpose(purpose: &str, user: UserId) -> String {
    format!("{purpose}:{user}")
}

/// Seals a per-account secret under [`bound_purpose`].
pub fn seal_bound<S: SecretSeal + ?Sized>(
    seal: &S,
    purpose: &str,
    user: UserId,
    value: &[u8],
) -> Vec<u8> {
    seal.seal(&bound_purpose(purpose, user), value)
}

/// A per-account secret as [`open_bound`] read it.
pub struct OpenedBound {
    pub value: Zeroizing<Vec<u8>>,
    /// Whether it was sealed the old way, under the bare purpose: the caller seals it again with
    /// [`seal_bound`] where it can write the row back.
    pub legacy: bool,
}

impl std::fmt::Debug for OpenedBound {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // The value is a secret.
        f.debug_struct("OpenedBound")
            .field("legacy", &self.legacy)
            .finish_non_exhaustive()
    }
}

/// Opens a per-account secret: sealed for this account, or, for what was stored before secrets
/// were bound to accounts, under the bare purpose (`legacy` is then set) while
/// [`bare_secrets_allowed`].
pub fn open_bound<S: SecretSeal + ?Sized>(
    seal: &S,
    purpose: &str,
    user: UserId,
    sealed: &[u8],
) -> Result<OpenedBound, CryptoError> {
    match seal.open(&bound_purpose(purpose, user), sealed) {
        Ok(value) => Ok(OpenedBound {
            value,
            legacy: false,
        }),
        Err(_) if bare_secrets_allowed() => seal.open(purpose, sealed).map(|value| OpenedBound {
            value,
            legacy: true,
        }),
        Err(error) => Err(error),
    }
}

struct Writer(Vec<u8>);

impl Writer {
    fn new() -> Self {
        Writer(Vec::new())
    }
    fn u8(&mut self, v: u8) {
        self.0.push(v);
    }
    fn u64(&mut self, v: u64) {
        self.0.extend_from_slice(&v.to_be_bytes());
    }
    fn raw(&mut self, bytes: &[u8]) {
        self.0.extend_from_slice(bytes);
    }
    fn lp(&mut self, bytes: &[u8]) {
        // Values here are short (emails, names, one OPAQUE state), well inside u32.
        self.0
            .extend_from_slice(&(bytes.len() as u32).to_be_bytes());
        self.0.extend_from_slice(bytes);
    }
}

struct Reader<'a>(&'a [u8]);

impl<'a> Reader<'a> {
    fn take(&mut self, n: usize) -> Option<&'a [u8]> {
        if self.0.len() < n {
            return None;
        }
        let (head, tail) = self.0.split_at(n);
        self.0 = tail;
        Some(head)
    }
    fn u8(&mut self) -> Option<u8> {
        self.take(1).map(|b| b[0])
    }
    fn u64(&mut self) -> Option<u64> {
        let b = self.take(8)?;
        let mut a = [0u8; 8];
        a.copy_from_slice(b);
        Some(u64::from_be_bytes(a))
    }
    fn lp(&mut self) -> Option<&'a [u8]> {
        let b = self.take(4)?;
        let mut a = [0u8; 4];
        a.copy_from_slice(b);
        let n = u32::from_be_bytes(a) as usize;
        self.take(n)
    }
    fn uuid(&mut self) -> Option<Uuid> {
        let b = self.take(16)?;
        let mut a = [0u8; 16];
        a.copy_from_slice(b);
        Some(Uuid::from_bytes(a))
    }
    fn done(&self) -> bool {
        self.0.is_empty()
    }
}

/// The server's half of an OPAQUE login between `start` and `finish`.
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct LoginState {
    pub(crate) expires_at: i64,
    pub(crate) credential_id: String,
    /// The thumbprint of the DPoP key that asked for this login; only that key may finish it.
    pub(crate) jkt: String,
    /// The OPAQUE state: wiped when dropped, like the encoding made from it.
    pub(crate) opaque: Zeroizing<Vec<u8>>,
}

impl LoginState {
    pub(crate) fn encode(&self) -> Zeroizing<Vec<u8>> {
        let mut w = Writer::new();
        w.u8(1);
        w.u64(self.expires_at.max(0) as u64);
        w.lp(self.credential_id.as_bytes());
        w.lp(self.jkt.as_bytes());
        w.lp(&self.opaque);
        Zeroizing::new(w.0)
    }

    pub(crate) fn decode(bytes: &[u8]) -> Option<Self> {
        let mut r = Reader(bytes);
        if r.u8()? != 1 {
            return None;
        }
        let expires_at = i64::try_from(r.u64()?).ok()?;
        let credential_id = String::from_utf8(r.lp()?.to_vec()).ok()?;
        let jkt = String::from_utf8(r.lp()?.to_vec()).ok()?;
        let opaque = Zeroizing::new(r.lp()?.to_vec());
        r.done().then_some(LoginState {
            expires_at,
            credential_id,
            jkt,
            opaque,
        })
    }
}

/// What a two-step challenge remembers: who passed the password, on which device and key.
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct Challenge {
    pub(crate) expires_at: i64,
    pub(crate) user: UserId,
    pub(crate) device: DeviceId,
    pub(crate) device_name: String,
    pub(crate) device_kind: DeviceKind,
    pub(crate) jkt: String,
}

fn kind_code(kind: DeviceKind) -> u8 {
    match kind {
        DeviceKind::KemlockAndroid => 1,
        DeviceKind::KemlockIos => 2,
        DeviceKind::KemlockWeb => 3,
        DeviceKind::KemlockCli => 4,
        DeviceKind::Amethystora => 5,
        DeviceKind::Bitwarden => 6,
        DeviceKind::Other => 7,
        DeviceKind::KemlockBrowser => 8,
    }
}

fn kind_from_code(code: u8) -> Option<DeviceKind> {
    Some(match code {
        1 => DeviceKind::KemlockAndroid,
        2 => DeviceKind::KemlockIos,
        3 => DeviceKind::KemlockWeb,
        4 => DeviceKind::KemlockCli,
        5 => DeviceKind::Amethystora,
        6 => DeviceKind::Bitwarden,
        7 => DeviceKind::Other,
        8 => DeviceKind::KemlockBrowser,
        _ => return None,
    })
}

impl Challenge {
    pub(crate) fn encode(&self) -> Vec<u8> {
        let mut w = Writer::new();
        w.u8(1);
        w.u64(self.expires_at.max(0) as u64);
        w.raw(self.user.as_bytes());
        w.raw(self.device.as_bytes());
        w.lp(self.device_name.as_bytes());
        w.u8(kind_code(self.device_kind));
        w.lp(self.jkt.as_bytes());
        w.0
    }

    pub(crate) fn decode(bytes: &[u8]) -> Option<Self> {
        let mut r = Reader(bytes);
        if r.u8()? != 1 {
            return None;
        }
        let expires_at = i64::try_from(r.u64()?).ok()?;
        let user = UserId(r.uuid()?);
        let device = DeviceId(r.uuid()?);
        let device_name = String::from_utf8(r.lp()?.to_vec()).ok()?;
        let device_kind = kind_from_code(r.u8()?)?;
        let jkt = String::from_utf8(r.lp()?.to_vec()).ok()?;
        r.done().then_some(Challenge {
            expires_at,
            user,
            device,
            device_name,
            device_kind,
            jkt,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct TestSeal(kemlock_crypto::seal::ServerSeal);

    impl SecretSeal for TestSeal {
        fn seal(&self, purpose: &str, value: &[u8]) -> Vec<u8> {
            self.0.seal(purpose, value)
        }
        fn open(&self, purpose: &str, sealed: &[u8]) -> Result<Zeroizing<Vec<u8>>, CryptoError> {
            self.0
                .open(purpose, sealed)
                .map_err(|_| CryptoError::Invalid)
        }
    }

    fn seal() -> TestSeal {
        TestSeal(kemlock_crypto::seal::ServerSeal::new(&[9u8; 32]))
    }

    #[test]
    fn a_bound_secret_opens_for_its_account_only() {
        let (sam, kim) = (UserId::random(), UserId::random());
        let sealed = seal_bound(&seal(), PURPOSE_TOTP, sam, b"seed");
        let opened = open_bound(&seal(), PURPOSE_TOTP, sam, &sealed).expect("opens");
        assert_eq!(opened.value.as_slice(), b"seed");
        assert!(!opened.legacy);
        // Copied into another account's row, it doesn't open there, bare or bound.
        assert!(open_bound(&seal(), PURPOSE_TOTP, kim, &sealed).is_err());
    }

    #[test]
    fn a_secret_sealed_under_the_bare_purpose_still_opens_and_says_so() {
        let sam = UserId::random();
        let sealed = seal().seal(PURPOSE_TOTP, b"seed");
        let opened = open_bound(&seal(), PURPOSE_TOTP, sam, &sealed).expect("opens");
        assert_eq!(opened.value.as_slice(), b"seed");
        assert!(opened.legacy);
    }

    #[test]
    fn login_state_round_trips_and_refuses_trailing_bytes() {
        let s = LoginState {
            expires_at: 1_700_000_000,
            credential_id: "a@b.co".into(),
            jkt: "thumbprint".into(),
            opaque: Zeroizing::new(vec![1, 2, 3]),
        };
        let mut bytes = s.encode();
        assert_eq!(LoginState::decode(&bytes), Some(s));
        bytes.push(0);
        assert_eq!(LoginState::decode(&bytes), None);
    }

    #[test]
    fn a_browser_extensions_challenge_keeps_its_kind() {
        for kind in [DeviceKind::KemlockBrowser, DeviceKind::KemlockWeb] {
            let c = Challenge {
                expires_at: 5,
                user: UserId::random(),
                device: DeviceId::random(),
                device_name: "Kemlock for browsers, Chrome".into(),
                device_kind: kind,
                jkt: "abc".into(),
            };
            assert_eq!(Challenge::decode(&c.encode()), Some(c));
        }
    }

    #[test]
    fn challenge_round_trips_and_refuses_truncation() {
        let c = Challenge {
            expires_at: 5,
            user: UserId::random(),
            device: DeviceId::random(),
            device_name: "Pixel".into(),
            device_kind: DeviceKind::KemlockAndroid,
            jkt: "abc".into(),
        };
        let bytes = c.encode();
        assert_eq!(Challenge::decode(&bytes), Some(c));
        assert_eq!(Challenge::decode(&bytes[..bytes.len() - 1]), None);
    }
}
