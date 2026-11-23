//! The WebAuthn relying party as the use cases see it: four ceremonies over plain bytes and JSON.
//!
//! `kemlock-identity` implements [`WebAuthn`] over `webauthn-rs-core`. The use cases never see a
//! library type: the state of a ceremony and a stored credential are opaque bytes the adapter
//! wrote and reads back, and options and responses are the JSON the browser's
//! `navigator.credentials` takes and makes.
//!
//! The methods are synchronous: a ceremony is arithmetic and parsing, with no I/O.

use serde_json::Value;

/// What a ceremony is for. The two kinds differ in what they ask of the person's device.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum CredentialKind {
    /// A passkey, which signs the person in on its own: a discoverable credential with user
    /// verification required, so one gesture is possession and knowledge or a body check.
    Passkey,
    /// A security key as a second step (Bitwarden's type 7): user verification discouraged and the
    /// `appid` extension asked for, as Vaultwarden does, so every key Bitwarden's clients take works.
    SecurityKey,
}

/// Why a ceremony failed.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum WebAuthnError {
    /// The response doesn't answer the challenge: a wrong challenge, origin or relying party, a
    /// bad signature, a counter that went backwards, a missing user verification. The text is for
    /// logs, never for clients.
    #[error("the WebAuthn response was refused: {0}")]
    Refused(String),
    /// A response, state or credential that doesn't parse.
    #[error("malformed WebAuthn data: {0}")]
    Malformed(&'static str),
    /// The relying party couldn't do its part: a configuration or serialisation failure.
    #[error("WebAuthn failure: {0}")]
    Failed(String),
}

/// Who a credential is being made for.
#[derive(Clone, Copy, Debug)]
pub struct RegistrationStart<'a> {
    pub kind: CredentialKind,
    /// The account's id, the 16 raw bytes. Authenticators keep it as the user handle.
    pub user_handle: &'a [u8],
    /// The account's email, shown in the authenticator's account list.
    pub user_name: &'a str,
    pub display_name: &'a str,
    /// The ids of the credentials the account has already, so a device is not enrolled twice.
    pub exclude: &'a [Vec<u8>],
}

/// A ceremony's first half: the options for the browser and the state to keep until it answers.
#[derive(Clone, Debug, PartialEq)]
pub struct Started {
    /// `PublicKeyCredentialCreationOptions` or `PublicKeyCredentialRequestOptions`, as JSON: the
    /// object `navigator.credentials.create`/`get` takes as `publicKey`.
    pub options: Value,
    /// What the second half needs. Keep it server side, once: a state used twice is a replay.
    pub state: Vec<u8>,
}

/// A credential a registration made.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NewCredential {
    /// The WebAuthn credential id, the raw bytes.
    pub credential_id: Vec<u8>,
    /// The credential to store: the public key, counter and flags, as the adapter writes them.
    pub credential: Vec<u8>,
}

/// A sign-in the authenticator signed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Assertion {
    pub credential_id: Vec<u8>,
    /// The stored credential after this sign-in: the counter moved on. Store it.
    pub credential: Vec<u8>,
    /// Whether the authenticator verified the person (a PIN, a fingerprint, a face).
    pub user_verified: bool,
}

/// Which credential a response names, before it is verified.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ResponseIds {
    pub credential_id: Vec<u8>,
    /// The user handle the authenticator returned, which a discoverable credential always sends.
    pub user_handle: Option<Vec<u8>>,
}

/// The relying party: this server, for one address.
pub trait WebAuthn: Send + Sync {
    /// Starts a registration: creation options and the state to keep.
    fn start_registration(&self, request: &RegistrationStart<'_>)
    -> Result<Started, WebAuthnError>;

    /// Finishes a registration with the browser's answer (`PublicKeyCredential.toJSON()`, or the
    /// Bitwarden clients' spelling of it) and the state `start_registration` made.
    fn finish_registration(
        &self,
        kind: CredentialKind,
        state: &[u8],
        response: &[u8],
    ) -> Result<NewCredential, WebAuthnError>;

    /// Starts a sign-in. `credentials` are the stored credentials the person may answer with: a
    /// security key's challenge lists them; a passkey's is discoverable and lists none.
    fn start_authentication(
        &self,
        kind: CredentialKind,
        credentials: &[&[u8]],
    ) -> Result<Started, WebAuthnError>;

    /// Which credential and user a sign-in answer names, so the caller can find the stored
    /// credential to verify it against.
    fn response_ids(&self, response: &[u8]) -> Result<ResponseIds, WebAuthnError>;

    /// Finishes a sign-in: checks the answer against the state and the stored credential it
    /// names, from `credentials`. A signature counter that didn't grow is refused.
    fn finish_authentication(
        &self,
        kind: CredentialKind,
        state: &[u8],
        response: &[u8],
        credentials: &[&[u8]],
    ) -> Result<Assertion, WebAuthnError>;
}

impl<T: WebAuthn + ?Sized> WebAuthn for std::sync::Arc<T> {
    fn start_registration(
        &self,
        request: &RegistrationStart<'_>,
    ) -> Result<Started, WebAuthnError> {
        (**self).start_registration(request)
    }

    fn finish_registration(
        &self,
        kind: CredentialKind,
        state: &[u8],
        response: &[u8],
    ) -> Result<NewCredential, WebAuthnError> {
        (**self).finish_registration(kind, state, response)
    }

    fn start_authentication(
        &self,
        kind: CredentialKind,
        credentials: &[&[u8]],
    ) -> Result<Started, WebAuthnError> {
        (**self).start_authentication(kind, credentials)
    }

    fn response_ids(&self, response: &[u8]) -> Result<ResponseIds, WebAuthnError> {
        (**self).response_ids(response)
    }

    fn finish_authentication(
        &self,
        kind: CredentialKind,
        state: &[u8],
        response: &[u8],
        credentials: &[&[u8]],
    ) -> Result<Assertion, WebAuthnError> {
        (**self).finish_authentication(kind, state, response, credentials)
    }
}
