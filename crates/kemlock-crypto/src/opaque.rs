//! `opaque1`: password sign-in with OPAQUE-3DH (RFC 9807) through `opaque-ke` 4.
//!
//! The configuration is the one of RFC 9807 appendix C test vector 1, apart from the context:
//! ristretto255-SHA512 OPRF, ristretto255 key exchange, HKDF-SHA512, HMAC-SHA512, SHA-512, the
//! Identity key-stretching function, context `"kemlock/v1/opaque"`, no client or server identity,
//! and the account's e-mail (trimmed, lower-cased, UTF-8; see [`credential_id`]) as the credential
//! identifier. The password input is the 32-byte Argon2id master key, not the typed password.
//!
//! `opaque-ke` is generic over `digest` 0.10 and brings its own SHA-512 (`sha2` 0.10), so OPAQUE's
//! hashing doesn't go through the aws-lc or RustCrypto backends of the other formats.
//!
//! All sizes: registration request 32, response 64, upload and record 192; credential request 96,
//! response 320, finalization 64; session and export keys 64; server setup 128.

use core::fmt;

use opaque_ke::{
    CipherSuite, ClientLoginFinishParameters, ClientRegistrationFinishParameters,
    CredentialFinalization, CredentialRequest, CredentialResponse, Identifiers,
    RegistrationRequest, RegistrationResponse, RegistrationUpload, Ristretto255,
    ServerLoginParameters, ServerRegistration, ServerSetup, TripleDh, ksf::Identity,
};
use rand_core_06::{CryptoRng, RngCore};
use zeroize::Zeroizing;

use crate::{Error, rand, wire::fixed};

/// The protocol context: both sides must give the same one.
pub const CONTEXT: &[u8] = b"kemlock/v1/opaque";

/// The cipher suite of `opaque1`.
pub(crate) struct Suite;

impl CipherSuite for Suite {
    type OprfCs = Ristretto255;
    type KeyExchange = TripleDh<Ristretto255, sha2_opaque::Sha512>;
    type Ksf = Identity;
}

/// The random source `opaque-ke` draws from: this crate's, so the test-vector generator can seed
/// it. Like [`rand::fill`] it panics if the operating system's source fails.
#[derive(Clone, Copy, Debug)]
pub(crate) struct SystemRng;

impl RngCore for SystemRng {
    fn next_u32(&mut self) -> u32 {
        let mut bytes = [0u8; 4];
        self.fill_bytes(&mut bytes);
        u32::from_le_bytes(bytes)
    }

    fn next_u64(&mut self) -> u64 {
        let mut bytes = [0u8; 8];
        self.fill_bytes(&mut bytes);
        u64::from_le_bytes(bytes)
    }

    fn fill_bytes(&mut self, dest: &mut [u8]) {
        rand::fill(dest);
    }

    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand_core_06::Error> {
        rand::fill(dest);
        Ok(())
    }
}

impl CryptoRng for SystemRng {}

fn invalid<E>(_: E) -> Error {
    Error::invalid()
}

/// The credential identifier of an account: its e-mail, trimmed and lower-cased, as UTF-8.
pub fn credential_id(email: &str) -> Vec<u8> {
    email.trim().to_lowercase().into_bytes()
}

fn server_params(context: &[u8]) -> ServerLoginParameters<'_, 'static> {
    ServerLoginParameters {
        context: Some(context),
        identifiers: Identifiers::default(),
    }
}

/// The server's OPAQUE setup: the OPRF seed and the server's key pair. Keep it sealed with
/// [`crate::seal::ServerSeal`] under the purpose `"opaque-setup"`.
///
/// It is held as its 128 serialized bytes (wiped on drop) and parsed per call, because
/// `opaque-ke` doesn't wipe its own `ServerSetup`.
#[derive(Clone)]
pub struct OpaqueServer {
    setup: Zeroizing<Vec<u8>>,
}

impl fmt::Debug for OpaqueServer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("OpaqueServer").finish_non_exhaustive()
    }
}

impl OpaqueServer {
    /// A new setup with a fresh OPRF seed and key pair.
    pub fn generate() -> OpaqueServer {
        let setup = ServerSetup::<Suite>::new(&mut SystemRng);
        OpaqueServer {
            setup: Zeroizing::new(setup.serialize().to_vec()),
        }
    }

    /// The 128 bytes of the setup. Seal them before storing.
    pub fn to_bytes(&self) -> Vec<u8> {
        self.setup.to_vec()
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<OpaqueServer, Error> {
        ServerSetup::<Suite>::deserialize(bytes).map_err(invalid)?;
        Ok(OpaqueServer {
            setup: Zeroizing::new(bytes.to_vec()),
        })
    }

    fn setup(&self) -> Result<ServerSetup<Suite>, Error> {
        ServerSetup::<Suite>::deserialize(&self.setup).map_err(invalid)
    }

    /// Answers a client's registration request for `credential_id`: 64 bytes.
    pub fn registration_response(
        &self,
        credential_id: &[u8],
        request: &[u8],
    ) -> Result<Vec<u8>, Error> {
        let request = RegistrationRequest::<Suite>::deserialize(request).map_err(invalid)?;
        let started = ServerRegistration::<Suite>::start(&self.setup()?, request, credential_id)
            .map_err(invalid)?;
        Ok(started.message.serialize().to_vec())
    }

    /// Turns the client's registration upload into the record to store: 192 bytes.
    pub fn registration_record(upload: &[u8]) -> Result<Vec<u8>, Error> {
        let upload = RegistrationUpload::<Suite>::deserialize(upload).map_err(invalid)?;
        Ok(ServerRegistration::<Suite>::finish(upload)
            .serialize()
            .to_vec())
    }

    /// Starts a login. With `record` `None` (an unknown account) the response is a fake one of the
    /// same length, which the client can't open, so the answer doesn't say whether the account
    /// exists. Returns `(state, credential response)`; keep the state until the client finishes.
    pub fn login_start(
        &self,
        credential_id: &[u8],
        record: Option<&[u8]>,
        request: &[u8],
    ) -> Result<(Vec<u8>, Vec<u8>), Error> {
        self.login_start_with(&mut SystemRng, CONTEXT, credential_id, record, request)
    }

    pub(crate) fn login_start_with<R: RngCore + CryptoRng>(
        &self,
        rng: &mut R,
        context: &[u8],
        credential_id: &[u8],
        record: Option<&[u8]>,
        request: &[u8],
    ) -> Result<(Vec<u8>, Vec<u8>), Error> {
        let record = match record {
            Some(bytes) => Some(ServerRegistration::<Suite>::deserialize(bytes).map_err(invalid)?),
            None => None,
        };
        let request = CredentialRequest::<Suite>::deserialize(request).map_err(invalid)?;
        let started = opaque_ke::ServerLogin::<Suite>::start(
            rng,
            &self.setup()?,
            record,
            request,
            credential_id,
            server_params(context),
        )
        .map_err(invalid)?;
        Ok((
            started.state.serialize().to_vec(),
            started.message.serialize().to_vec(),
        ))
    }

    /// Finishes a login with the client's finalization; returns the 64-byte session key, or an
    /// error when the client didn't know the password.
    pub fn login_finish(state: &[u8], finalization: &[u8]) -> Result<Vec<u8>, Error> {
        OpaqueServer::login_finish_with(CONTEXT, state, finalization)
    }

    pub(crate) fn login_finish_with(
        context: &[u8],
        state: &[u8],
        finalization: &[u8],
    ) -> Result<Vec<u8>, Error> {
        let state = opaque_ke::ServerLogin::<Suite>::deserialize(state).map_err(invalid)?;
        let finalization =
            CredentialFinalization::<Suite>::deserialize(finalization).map_err(invalid)?;
        let finished = state
            .finish(finalization, server_params(context))
            .map_err(invalid)?;
        Ok(finished.session_key.to_vec())
    }
}

/// The client's state between registration start and finish. Wiped on drop.
pub struct ClientRegistration(opaque_ke::ClientRegistration<Suite>);

impl fmt::Debug for ClientRegistration {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ClientRegistration").finish_non_exhaustive()
    }
}

/// The client's state between login start and finish. Wiped on drop.
pub struct ClientLogin(opaque_ke::ClientLogin<Suite>);

impl fmt::Debug for ClientLogin {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ClientLogin").finish_non_exhaustive()
    }
}

/// Starts a registration with `password` (the 32-byte master key). Returns the state and the
/// 32-byte request for the server.
pub fn client_registration_start(password: &[u8]) -> Result<(ClientRegistration, Vec<u8>), Error> {
    client_registration_start_with(&mut SystemRng, password)
}

pub(crate) fn client_registration_start_with<R: RngCore + CryptoRng>(
    rng: &mut R,
    password: &[u8],
) -> Result<(ClientRegistration, Vec<u8>), Error> {
    let started = opaque_ke::ClientRegistration::<Suite>::start(rng, password).map_err(invalid)?;
    Ok((
        ClientRegistration(started.state),
        started.message.serialize().to_vec(),
    ))
}

/// Finishes a registration with the server's response. Returns the 192-byte upload for the server
/// and the 64-byte export key, which goes into the password wrap.
pub fn client_registration_finish(
    state: ClientRegistration,
    password: &[u8],
    response: &[u8],
) -> Result<(Vec<u8>, [u8; 64]), Error> {
    client_registration_finish_with(&mut SystemRng, state, password, response)
}

pub(crate) fn client_registration_finish_with<R: RngCore + CryptoRng>(
    rng: &mut R,
    state: ClientRegistration,
    password: &[u8],
    response: &[u8],
) -> Result<(Vec<u8>, [u8; 64]), Error> {
    let response = RegistrationResponse::<Suite>::deserialize(response).map_err(invalid)?;
    let finished = state
        .0
        .finish(
            rng,
            password,
            response,
            ClientRegistrationFinishParameters::<Suite>::default(),
        )
        .map_err(invalid)?;
    Ok((
        finished.message.serialize().to_vec(),
        fixed(&finished.export_key),
    ))
}

/// Starts a login with `password`. Returns the state and the 96-byte credential request.
pub fn client_login_start(password: &[u8]) -> Result<(ClientLogin, Vec<u8>), Error> {
    client_login_start_with(&mut SystemRng, password)
}

pub(crate) fn client_login_start_with<R: RngCore + CryptoRng>(
    rng: &mut R,
    password: &[u8],
) -> Result<(ClientLogin, Vec<u8>), Error> {
    let started = opaque_ke::ClientLogin::<Suite>::start(rng, password).map_err(invalid)?;
    Ok((
        ClientLogin(started.state),
        started.message.serialize().to_vec(),
    ))
}

/// What a finished client login gives: the finalization for the server, the session key and the
/// export key.
pub type LoginFinished = (Vec<u8>, Vec<u8>, [u8; 64]);

/// Finishes a login with the server's credential response. Fails when the password is wrong or
/// the response is fake. Returns the 64-byte finalization for the server, the 64-byte session key
/// and the 64-byte export key.
pub fn client_login_finish(
    state: ClientLogin,
    password: &[u8],
    response: &[u8],
) -> Result<LoginFinished, Error> {
    client_login_finish_with(&mut SystemRng, CONTEXT, state, password, response)
}

pub(crate) fn client_login_finish_with<R: RngCore + CryptoRng>(
    rng: &mut R,
    context: &[u8],
    state: ClientLogin,
    password: &[u8],
    response: &[u8],
) -> Result<LoginFinished, Error> {
    let response = CredentialResponse::<Suite>::deserialize(response).map_err(invalid)?;
    let finished = state
        .0
        .finish(
            rng,
            password,
            response,
            ClientLoginFinishParameters::<Suite>::new(Some(context), Identifiers::default(), None),
        )
        .map_err(invalid)?;
    Ok((
        finished.message.serialize().to_vec(),
        finished.session_key.to_vec(),
        fixed(&finished.export_key),
    ))
}

#[cfg(test)]
mod rfc9807;

#[cfg(test)]
mod tests {
    use super::*;

    const MASTER_KEY: [u8; 32] = [0x42; 32];
    const OTHER_KEY: [u8; 32] = [0x43; 32];

    /// Registers `password` for `credential_id` and returns the record and the export key.
    fn register(
        server: &OpaqueServer,
        credential_id: &[u8],
        password: &[u8],
    ) -> (Vec<u8>, [u8; 64]) {
        let (state, request) = client_registration_start(password).expect("start");
        assert_eq!(request.len(), 32);
        let response = server
            .registration_response(credential_id, &request)
            .expect("response");
        assert_eq!(response.len(), 64);
        let (upload, export_key) =
            client_registration_finish(state, password, &response).expect("finish");
        assert_eq!(upload.len(), 192);
        let record = OpaqueServer::registration_record(&upload).expect("record");
        assert_eq!(record, upload);
        (record, export_key)
    }

    #[test]
    fn registration_and_login_round_trip() {
        let server = OpaqueServer::generate();
        let id = credential_id("Alice@Example.com ");
        let (record, registration_export) = register(&server, &id, &MASTER_KEY);

        let (client, request) = client_login_start(&MASTER_KEY).expect("start");
        assert_eq!(request.len(), 96);
        let (state, response) = server
            .login_start(&id, Some(&record), &request)
            .expect("server start");
        assert_eq!(response.len(), 320);
        let (finalization, client_session, login_export) =
            client_login_finish(client, &MASTER_KEY, &response).expect("client finish");
        assert_eq!(finalization.len(), 64);
        let server_session =
            OpaqueServer::login_finish(&state, &finalization).expect("server finish");
        assert_eq!(server_session.len(), 64);
        assert_eq!(client_session, server_session);
        // The export key is the same at registration and at every login.
        assert_eq!(login_export, registration_export);
        assert_ne!(registration_export, [0u8; 64]);
    }

    #[test]
    fn two_logins_have_different_session_keys() {
        let server = OpaqueServer::generate();
        let id = credential_id("a@example.com");
        let (record, _) = register(&server, &id, &MASTER_KEY);
        let mut sessions = Vec::new();
        for _ in 0..2 {
            let (client, request) = client_login_start(&MASTER_KEY).expect("start");
            let (state, response) = server
                .login_start(&id, Some(&record), &request)
                .expect("server start");
            let (finalization, session, _) =
                client_login_finish(client, &MASTER_KEY, &response).expect("finish");
            assert_eq!(
                session,
                OpaqueServer::login_finish(&state, &finalization).expect("server finish")
            );
            sessions.push(session);
        }
        assert_ne!(sessions[0], sessions[1]);
    }

    #[test]
    fn a_wrong_password_fails_at_the_client() {
        let server = OpaqueServer::generate();
        let id = credential_id("a@example.com");
        let (record, _) = register(&server, &id, &MASTER_KEY);
        let (client, request) = client_login_start(&OTHER_KEY).expect("start");
        let (_, response) = server
            .login_start(&id, Some(&record), &request)
            .expect("server start");
        assert!(client_login_finish(client, &OTHER_KEY, &response).is_err());
    }

    #[test]
    fn a_forged_finalization_fails_at_the_server() {
        let server = OpaqueServer::generate();
        let id = credential_id("a@example.com");
        let (record, _) = register(&server, &id, &MASTER_KEY);
        let (client, request) = client_login_start(&MASTER_KEY).expect("start");
        let (state, response) = server
            .login_start(&id, Some(&record), &request)
            .expect("server start");
        let (mut finalization, _, _) =
            client_login_finish(client, &MASTER_KEY, &response).expect("finish");
        finalization[0] ^= 1;
        assert!(OpaqueServer::login_finish(&state, &finalization).is_err());
        assert!(OpaqueServer::login_finish(&state, &finalization[..63]).is_err());
    }

    #[test]
    fn an_unknown_account_gets_a_response_of_the_same_length_that_cannot_be_opened() {
        let server = OpaqueServer::generate();
        let id = credential_id("a@example.com");
        let (record, _) = register(&server, &id, &MASTER_KEY);

        let (client, request) = client_login_start(&MASTER_KEY).expect("start");
        let (real_state, real) = server
            .login_start(&id, Some(&record), &request)
            .expect("real");
        let (fake_state, fake) = server
            .login_start(&credential_id("nobody@example.com"), None, &request)
            .expect("fake");
        assert_eq!(fake.len(), real.len());
        assert_eq!(fake_state.len(), real_state.len());
        assert!(client_login_finish(client, &MASTER_KEY, &fake).is_err());
    }

    #[test]
    fn a_record_does_not_work_for_another_credential_id() {
        let server = OpaqueServer::generate();
        let (record, _) = register(&server, b"alice@example.com", &MASTER_KEY);
        let (client, request) = client_login_start(&MASTER_KEY).expect("start");
        let (_, response) = server
            .login_start(b"bob@example.com", Some(&record), &request)
            .expect("server start");
        assert!(client_login_finish(client, &MASTER_KEY, &response).is_err());
    }

    #[test]
    fn another_server_setup_cannot_open_the_record() {
        let server = OpaqueServer::generate();
        let id = credential_id("a@example.com");
        let (record, _) = register(&server, &id, &MASTER_KEY);
        let other = OpaqueServer::generate();
        let (client, request) = client_login_start(&MASTER_KEY).expect("start");
        let (_, response) = other
            .login_start(&id, Some(&record), &request)
            .expect("server start");
        assert!(client_login_finish(client, &MASTER_KEY, &response).is_err());
    }

    #[test]
    fn the_context_must_agree() {
        let server = OpaqueServer::generate();
        let id = credential_id("a@example.com");
        let (record, _) = register(&server, &id, &MASTER_KEY);
        let (client, request) = client_login_start(&MASTER_KEY).expect("start");
        let (_, response) = server
            .login_start_with(
                &mut SystemRng,
                b"kemlock/v1/other",
                &id,
                Some(&record),
                &request,
            )
            .expect("server start");
        // The client uses kemlock/v1/opaque, the server another: the key exchange doesn't verify.
        assert!(client_login_finish(client, &MASTER_KEY, &response).is_err());
        // The server checks the client MAC against the one it computed at login_start, so the
        // context is bound there; login_finish takes it only for opaque-ke's API.
    }

    #[test]
    fn the_setup_survives_serialisation() {
        let server = OpaqueServer::generate();
        let bytes = server.to_bytes();
        assert_eq!(bytes.len(), 128);
        let restored = OpaqueServer::from_bytes(&bytes).expect("restore");
        let id = credential_id("a@example.com");
        let (record, _) = register(&server, &id, &MASTER_KEY);
        // The restored setup answers a login for a record made under the original.
        let (client, request) = client_login_start(&MASTER_KEY).expect("start");
        let (state, response) = restored
            .login_start(&id, Some(&record), &request)
            .expect("server start");
        let (finalization, session, _) =
            client_login_finish(client, &MASTER_KEY, &response).expect("finish");
        assert_eq!(
            session,
            OpaqueServer::login_finish(&state, &finalization).expect("server finish")
        );
    }

    #[test]
    fn bad_setups_and_messages_are_errors() {
        assert!(OpaqueServer::from_bytes(&[]).is_err());
        assert!(OpaqueServer::from_bytes(&[0u8; 127]).is_err());
        let server = OpaqueServer::generate();
        assert!(server.registration_response(b"id", &[0u8; 31]).is_err());
        assert!(server.registration_response(b"id", &[0xFFu8; 32]).is_err());
        assert!(OpaqueServer::registration_record(&[0u8; 191]).is_err());
        assert!(server.login_start(b"id", None, &[0u8; 95]).is_err());
        assert!(OpaqueServer::login_finish(&[], &[0u8; 64]).is_err());
        let (state, _) = client_registration_start(&MASTER_KEY).expect("start");
        assert!(client_registration_finish(state, &MASTER_KEY, &[0u8; 63]).is_err());
        let (state, _) = client_login_start(&MASTER_KEY).expect("start");
        assert!(client_login_finish(state, &MASTER_KEY, &[0u8; 319]).is_err());
    }

    #[test]
    fn credential_ids_are_trimmed_and_lower_cased() {
        assert_eq!(credential_id("  Alice@Example.COM\n"), b"alice@example.com");
        assert_eq!(credential_id("a@b.c"), b"a@b.c");
        assert_eq!(credential_id("\u{c9}@x.y"), "\u{e9}@x.y".as_bytes());
    }

    #[test]
    fn debug_shows_no_contents() {
        assert!(!format!("{:?}", OpaqueServer::generate()).contains('['));
    }

    #[test]
    fn registrations_are_randomised() {
        let (_, request_a) = client_registration_start(&MASTER_KEY).expect("start");
        let (_, request_b) = client_registration_start(&MASTER_KEY).expect("start");
        assert_ne!(request_a, request_b);
    }

    #[test]
    fn a_seeded_random_source_makes_the_whole_exchange_reproducible() {
        let run = || {
            crate::with_seeded_random([9; 32], || {
                let server = OpaqueServer::generate();
                let id = credential_id("a@example.com");
                let (record, export_key) = register(&server, &id, &MASTER_KEY);
                (server.to_bytes(), record, export_key)
            })
        };
        assert_eq!(run(), run());
    }
}
