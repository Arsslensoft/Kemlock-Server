//! Ports of passkeys and WebAuthn ceremonies.
//!
//! Method names are distinct from the other repositories' (`get`, `put`, `remove`), so one store
//! type can implement all of them and callers needn't spell out which trait they mean.

use crate::ports::StoreError;
use kemlock_domain::{Passkey, PasskeyId, PrfWrap, UserId};
use std::future::Future;
use time::OffsetDateTime;

/// The passkeys of every account (`passkeys`).
pub trait PasskeyRepo: Send + Sync {
    /// The account's passkeys, oldest first.
    fn passkeys_of(
        &self,
        user: UserId,
    ) -> impl Future<Output = Result<Vec<Passkey>, StoreError>> + Send;

    /// The passkey with this WebAuthn credential id, whichever account has it. A discoverable
    /// sign-in names the credential, not the account.
    fn passkey_by_credential(
        &self,
        credential_id: &[u8],
    ) -> impl Future<Output = Result<Option<Passkey>, StoreError>> + Send;

    /// Stores a new passkey; `Duplicate` when the credential id is taken, by any account, and
    /// `NotFound` when the account is gone.
    fn insert_passkey(
        &self,
        passkey: &Passkey,
    ) -> impl Future<Output = Result<(), StoreError>> + Send;

    /// Renames the account's passkey; `NotFound` when it has no such passkey.
    fn rename_passkey(
        &self,
        user: UserId,
        id: PasskeyId,
        name: &str,
    ) -> impl Future<Output = Result<(), StoreError>> + Send;

    /// Deletes the account's passkey; `NotFound` when it has no such passkey.
    fn delete_passkey(
        &self,
        user: UserId,
        id: PasskeyId,
    ) -> impl Future<Output = Result<(), StoreError>> + Send;

    /// After a sign-in: the credential with its new counter, and the time it was used.
    fn record_passkey_use(
        &self,
        id: PasskeyId,
        credential: &[u8],
        at: OffsetDateTime,
    ) -> impl Future<Output = Result<(), StoreError>> + Send;

    /// Sets, replaces or (with `None`) removes the PRF copy of the root key; `NotFound` when the
    /// account has no such passkey.
    fn set_passkey_wrap(
        &self,
        user: UserId,
        id: PasskeyId,
        wrap: Option<&PrfWrap>,
    ) -> impl Future<Output = Result<(), StoreError>> + Send;
}

/// What a stored ceremony state is for. An account has one of each at a time.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum ChallengeKind {
    /// Registering a passkey.
    PasskeyRegistration,
    /// Registering a security key for the second step.
    SecurityKeyRegistration,
    /// Signing in with a security key as the second step.
    SecurityKeyLogin,
    /// An address waiting for the first emailed code, before the method is on (`two_step`).
    EmailSetup,
    /// A Duo prompt waiting for its answer (`two_step`).
    DuoPrompt,
    /// A one-time code mailed for a protected action, waiting to be entered (`two_step`).
    ProtectedAction,
    /// An assertion by a security key or passkey, waiting to be answered as a fresh proof
    /// (`passkeys::AssertionProof`).
    Proof,
}

impl ChallengeKind {
    pub fn as_str(self) -> &'static str {
        match self {
            ChallengeKind::PasskeyRegistration => "passkey-registration",
            ChallengeKind::SecurityKeyRegistration => "security-key-registration",
            ChallengeKind::SecurityKeyLogin => "security-key-login",
            ChallengeKind::EmailSetup => "email-setup",
            ChallengeKind::DuoPrompt => "duo-prompt",
            ChallengeKind::ProtectedAction => "protected-action",
            ChallengeKind::Proof => "proof",
        }
    }
}

/// The states of ceremonies that have started and not yet been answered (`webauthn_challenges`).
///
/// A challenge is good once: [`ChallengeRepo::take_challenge`] removes it, so an answer, right or
/// wrong, uses it up, and a new challenge of the same kind replaces the older one, whose answer
/// then fails.
pub trait ChallengeRepo: Send + Sync {
    /// Stores the state for the account, replacing any of the same kind.
    fn put_challenge(
        &self,
        user: UserId,
        kind: ChallengeKind,
        state: &[u8],
        expires_at: OffsetDateTime,
    ) -> impl Future<Output = Result<(), StoreError>> + Send;

    /// Takes the account's state of this kind out of the store, atomically: of two calls racing
    /// for one state, one gets it. `None` when there is none or it expired before `now`.
    fn take_challenge(
        &self,
        user: UserId,
        kind: ChallengeKind,
        now: OffsetDateTime,
    ) -> impl Future<Output = Result<Option<Vec<u8>>, StoreError>> + Send;

    /// Deletes states that expired before `before`. Returns how many went.
    fn purge_challenges(
        &self,
        before: OffsetDateTime,
    ) -> impl Future<Output = Result<u64, StoreError>> + Send;
}

/// Both repositories: what the API's store type must be on top of the others.
pub trait PasskeyStore: PasskeyRepo + ChallengeRepo + Clone + 'static {}

impl<T: PasskeyRepo + ChallengeRepo + Clone + 'static> PasskeyStore for T {}
