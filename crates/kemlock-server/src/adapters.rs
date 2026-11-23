//! The ports `kemlock-app` leaves to the server, implemented over `kemlock-crypto` and the
//! system: the wall clock, randomness, SHA-256 and HMAC, sealing under `server.key`, TOTP and
//! OPAQUE. The access-token signer (`JwsTokenSigner`) and the live-sync notifier (`LiveHub`) live
//! in `kemlock-api-kem`, where the API's token format and WebSocket are.

use kemlock_app::Hasher;
use kemlock_app::ports::{Clock, CryptoError, PasswordAuth, Random, SecretSeal, Totp, Zeroizing};
use kemlock_crypto::opaque::OpaqueServer;
use kemlock_crypto::seal::ServerSeal;
use kemlock_crypto::{hash, rand, totp};
use std::sync::Arc;
use time::OffsetDateTime;

/// Every non-store port in one cheap-to-clone value.
#[derive(Clone)]
pub struct ServerCrypto {
    seal: Arc<ServerSeal>,
    opaque: Arc<OpaqueServer>,
}

impl std::fmt::Debug for ServerCrypto {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ServerCrypto").finish_non_exhaustive()
    }
}

impl ServerCrypto {
    pub fn new(seal: ServerSeal, opaque: OpaqueServer) -> Self {
        ServerCrypto {
            seal: Arc::new(seal),
            opaque: Arc::new(opaque),
        }
    }
}

impl Clock for ServerCrypto {
    fn now(&self) -> OffsetDateTime {
        OffsetDateTime::now_utc()
    }
}

impl Random for ServerCrypto {
    fn fill(&self, buf: &mut [u8]) {
        rand::fill(buf);
    }
}

impl Hasher for ServerCrypto {
    fn sha256(&self, data: &[u8]) -> [u8; 32] {
        hash::sha256(data)
    }

    fn hmac_sha256(&self, key: &[u8], data: &[u8]) -> [u8; 32] {
        hash::hmac_sha256(key, data)
    }
}

impl SecretSeal for ServerCrypto {
    fn seal(&self, purpose: &str, value: &[u8]) -> Vec<u8> {
        self.seal.seal(purpose, value)
    }

    fn open(&self, purpose: &str, sealed: &[u8]) -> Result<Zeroizing<Vec<u8>>, CryptoError> {
        self.seal
            .open(purpose, sealed)
            .map_err(|_| CryptoError::Invalid)
    }
}

impl Totp for ServerCrypto {
    fn verify_step(&self, secret: &[u8], code: &str, now: OffsetDateTime) -> Option<u64> {
        // A time before 1970 is a broken clock; no code is right then.
        let seconds = u64::try_from(now.unix_timestamp()).ok()?;
        totp::verify_step(secret, code, seconds)
    }
}

impl PasswordAuth for ServerCrypto {
    fn registration_response(
        &self,
        credential_id: &[u8],
        request: &[u8],
    ) -> Result<Vec<u8>, CryptoError> {
        self.opaque
            .registration_response(credential_id, request)
            .map_err(|_| CryptoError::Invalid)
    }

    fn registration_record(&self, upload: &[u8]) -> Result<Vec<u8>, CryptoError> {
        OpaqueServer::registration_record(upload).map_err(|_| CryptoError::Invalid)
    }

    fn login_start(
        &self,
        credential_id: &[u8],
        record: Option<&[u8]>,
        request: &[u8],
    ) -> Result<(Vec<u8>, Vec<u8>), CryptoError> {
        self.opaque
            .login_start(credential_id, record, request)
            .map_err(|_| CryptoError::Invalid)
    }

    fn login_finish(&self, state: &[u8], finalization: &[u8]) -> Result<Vec<u8>, CryptoError> {
        OpaqueServer::login_finish(state, finalization).map_err(|_| CryptoError::Invalid)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use kemlock_crypto::opaque::{
        client_login_finish, client_login_start, client_registration_finish,
        client_registration_start,
    };

    fn crypto() -> ServerCrypto {
        ServerCrypto::new(ServerSeal::new(&[5u8; 32]), OpaqueServer::generate())
    }

    #[test]
    fn the_clock_is_now_and_randomness_differs() {
        let c = crypto();
        assert!((OffsetDateTime::now_utc() - c.now()).whole_seconds().abs() < 5);
        assert_ne!(c.bytes::<16>(), c.bytes::<16>());
    }

    #[test]
    fn hashing_matches_known_values() {
        let c = crypto();
        // SHA-256("abc").
        assert_eq!(
            c.sha256(b"abc")[..4],
            [0xba, 0x78, 0x16, 0xbf],
            "the well-known prefix"
        );
        assert_ne!(c.hmac_sha256(b"k1", b"d"), c.hmac_sha256(b"k2", b"d"));
    }

    #[test]
    fn sealing_binds_the_purpose() {
        let c = crypto();
        let sealed = c.seal("totp", b"secret");
        assert_eq!(
            c.open("totp", &sealed).expect("opens").as_slice(),
            b"secret"
        );
        assert_eq!(c.open("opaque-login", &sealed), Err(CryptoError::Invalid));
    }

    #[test]
    fn totp_checks_the_code_at_the_given_time() {
        let c = crypto();
        let secret = [7u8; 20];
        let at = OffsetDateTime::from_unix_timestamp(1_800_000_000).expect("a valid time");
        let code = totp::code_at(&secret, 1_800_000_000);
        assert!(c.verify(&secret, &code, at));
        assert!(!c.verify(&secret, &code, at + time::Duration::minutes(10)));
        assert!(!c.verify(
            &secret,
            &code,
            OffsetDateTime::UNIX_EPOCH - time::Duration::days(1)
        ));
    }

    #[test]
    fn opaque_registers_and_logs_in_with_the_clients_functions() {
        let c = crypto();
        let password = [4u8; 32];
        let (state, request) = client_registration_start(&password).expect("start");
        let response = c
            .registration_response(b"a@b.co", &request)
            .expect("response");
        let (upload, _export) =
            client_registration_finish(state, &password, &response).expect("finish");
        let record = c.registration_record(&upload).expect("record");

        let (state, request) = client_login_start(&password).expect("login start");
        let (server_state, response) = c
            .login_start(b"a@b.co", Some(&record), &request)
            .expect("login response");
        let (finalization, client_key, _export) =
            client_login_finish(state, &password, &response).expect("login finish");
        let server_key = c
            .login_finish(&server_state, &finalization)
            .expect("finished");
        assert_eq!(server_key, client_key);
    }
}
