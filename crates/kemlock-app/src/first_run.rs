//! First run: the setup code, and the grant it buys (design, "Identity and SSO", First run).
//!
//! Each start while no admin exists makes a new code and voids the old one. The code is 12
//! characters of Crockford's base32 (no `I`, `L`, `O` or `U`, so none can be misread) in groups
//! of four, and is logged once. A right code gives a short-lived grant that lets one account
//! register as the first admin. Wrong codes slow down after three tries, with doubling delays,
//! counted per client (the API passes the caller's address): one wrong code every quarter of an
//! hour from anywhere must not keep the real admin out, and 60 bits of code make guessing
//! impractical whatever the delays.
//!
//! The state lives in memory in a [`SetupState`] that the use cases of setup share. Whether an
//! admin exists, and whether an account registered as the first admin without finishing, is read
//! from the store at each start (the first-admin marker, see [`crate::FirstAdminRepo`]), so a
//! restart between the admin's registration and `finish_setup` resumes setup for that account
//! instead of leaving it half done.

use crate::b64url;
use crate::config::AuthConfig;
use crate::error::AppError;
use crate::first_admin::FirstAdminRepo;
use crate::platform::Platform;
use crate::ports::UserRepo;
use kemlock_domain::{SetupError, UserId};
use std::collections::HashMap;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use subtle::ConstantTimeEq;
use time::{Duration, OffsetDateTime};

/// Crockford's base32 alphabet: digits and letters without `I`, `L`, `O`, `U`.
const ALPHABET: &[u8; 32] = b"0123456789ABCDEFGHJKMNPQRSTVWXYZ";
/// Characters in a setup code, without separators.
pub const CODE_LEN: usize = 12;
/// Wrong tries allowed before delays start.
pub const FREE_TRIES: u32 = 3;
/// The longest delay between tries.
pub const MAX_DELAY_SECS: i64 = 900;
/// The most clients whose wrong tries are remembered at once. A flood of addresses can only make
/// the table forget them, which costs an attacker nothing it hadn't, and the real admin nothing.
const MAX_CLIENTS: usize = 4096;

/// A setup code as shown: `ABCD-EFGH-JKMN`.
#[derive(Clone, PartialEq, Eq)]
pub struct SetupCode(String);

impl SetupCode {
    /// The code with its dashes, for the log.
    pub fn as_display(&self) -> String {
        let c = &self.0;
        format!("{}-{}-{}", &c[0..4], &c[4..8], &c[8..12])
    }
}

impl std::fmt::Debug for SetupCode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("SetupCode(..)")
    }
}

/// What a right setup code buys: one registration as the first admin, within `expires_at`.
#[derive(Clone, PartialEq, Eq)]
pub struct SetupGrant {
    pub token: String,
    pub expires_at: OffsetDateTime,
}

impl std::fmt::Debug for SetupGrant {
    // The token is a credential: it stays out of logs.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SetupGrant")
            .field("expires_at", &self.expires_at)
            .finish_non_exhaustive()
    }
}

/// Where setup stands, as `/kem/v1/config` reports it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SetupPhase {
    /// No admin yet: the setup code is needed.
    NeedsAdmin,
    /// The first admin registered and must set up two-step login and finish.
    Pending,
    /// Setup is closed for good.
    Done,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Phase {
    Open,
    Claimed,
    Pending(UserId),
    Done,
}

#[derive(Debug)]
struct Grant {
    token: String,
    expires_at: OffsetDateTime,
}

/// One client's wrong tries.
#[derive(Debug, Default)]
struct Tries {
    failures: u32,
    blocked_until: Option<OffsetDateTime>,
}

#[derive(Debug)]
struct Inner {
    phase: Phase,
    code: Option<String>,
    /// Wrong tries by client. Never shared between clients.
    tries: HashMap<String, Tries>,
    grants: Vec<Grant>,
}

/// The setup state shared by `FirstRun`, `Register` and `FinishSetup`. Starts closed; `FirstRun`
/// opens it when no admin exists.
pub struct SetupState {
    inner: Mutex<Inner>,
}

impl std::fmt::Debug for SetupState {
    // Never prints the code or the grants.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SetupState").finish_non_exhaustive()
    }
}

impl Default for SetupState {
    fn default() -> Self {
        SetupState {
            inner: Mutex::new(Inner {
                phase: Phase::Done,
                code: None,
                tries: HashMap::new(),
                grants: Vec::new(),
            }),
        }
    }
}

/// Upper-cases a typed code, drops dashes and spaces, and reads `O` as 0 and `I`/`L` as 1, as
/// Crockford's base32 says a decoder should.
fn normalise(input: &str) -> String {
    input
        .chars()
        .filter(|c| !c.is_whitespace() && *c != '-')
        .map(|c| match c.to_ascii_uppercase() {
            'O' => '0',
            'I' | 'L' => '1',
            other => other,
        })
        .collect()
}

fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    bool::from(a.ct_eq(b))
}

impl SetupState {
    pub fn new() -> Arc<SetupState> {
        Arc::new(SetupState::default())
    }

    fn lock(&self) -> MutexGuard<'_, Inner> {
        self.inner.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// The account setup waits for, between its registration and `finish_setup`.
    pub fn pending(&self) -> Option<UserId> {
        match self.lock().phase {
            Phase::Pending(user) => Some(user),
            _ => None,
        }
    }

    pub fn phase(&self) -> SetupPhase {
        match self.lock().phase {
            Phase::Open | Phase::Claimed => SetupPhase::NeedsAdmin,
            Phase::Pending(_) => SetupPhase::Pending,
            Phase::Done => SetupPhase::Done,
        }
    }

    /// Opens setup with a new code, voiding the old code, tries and grants.
    fn open(&self, code: String) {
        let mut g = self.lock();
        g.phase = Phase::Open;
        g.code = Some(code);
        g.tries.clear();
        g.grants.clear();
    }

    /// Closes setup for good: an admin exists.
    pub(crate) fn close(&self) {
        let mut g = self.lock();
        g.phase = Phase::Done;
        g.code = None;
        g.grants.clear();
    }

    /// Setup was begun and not finished: `user` registered with a grant (here or in another
    /// process) and has to confirm a two-step method. No code is needed and none is valid.
    pub fn resume(&self, user: UserId) {
        let mut g = self.lock();
        g.phase = Phase::Pending(user);
        g.code = None;
        g.grants.clear();
    }

    /// Checks a typed code from `client` (an address, say). On success stores and returns a
    /// grant with `token`.
    fn check_code(
        &self,
        typed: &str,
        token: String,
        now: OffsetDateTime,
        ttl: Duration,
        client: &str,
    ) -> Result<SetupGrant, AppError> {
        let mut g = self.lock();
        if g.phase != Phase::Open {
            return Err(SetupError::AlreadyDone.into());
        }
        if let Some(until) = g.tries.get(client).and_then(|t| t.blocked_until)
            && now < until
        {
            let secs = (until - now).whole_seconds().max(1);
            return Err(AppError::SlowDown {
                retry_after_secs: u64::try_from(secs).unwrap_or(1),
            });
        }
        let typed = normalise(typed);
        let expected = g.code.clone().unwrap_or_default();
        // Both sides are the same public length when the code is right; the comparison itself
        // doesn't stop at the first differing byte.
        if expected.is_empty() || !ct_eq(typed.as_bytes(), expected.as_bytes()) {
            if !g.tries.contains_key(client) && g.tries.len() >= MAX_CLIENTS {
                g.tries.clear();
            }
            let tries = g.tries.entry(client.to_owned()).or_default();
            tries.failures = tries.failures.saturating_add(1);
            if tries.failures >= FREE_TRIES {
                let doublings = (tries.failures - FREE_TRIES).min(20);
                let delay = (2i64 << doublings).min(MAX_DELAY_SECS);
                tries.blocked_until = Some(now + Duration::seconds(delay));
            }
            return Err(SetupError::WrongCode.into());
        }
        g.tries.remove(client);
        g.grants.retain(|grant| grant.expires_at > now);
        let expires_at = now + ttl;
        g.grants.push(Grant {
            token: token.clone(),
            expires_at,
        });
        Ok(SetupGrant { token, expires_at })
    }

    /// Whether `grant` is a live grant of an open setup, without using it.
    pub fn has_grant(&self, grant: &str, now: OffsetDateTime) -> bool {
        let g = self.lock();
        g.phase == Phase::Open
            && g.grants
                .iter()
                .any(|x| x.expires_at > now && ct_eq(x.token.as_bytes(), grant.as_bytes()))
    }

    /// Uses a grant to claim the right to register the first admin. One claim at a time; a claim
    /// that fails is given back with [`SetupState::release`].
    pub fn claim(&self, grant: &str, now: OffsetDateTime) -> Result<(), AppError> {
        let mut g = self.lock();
        if g.phase != Phase::Open {
            return Err(SetupError::AlreadyDone.into());
        }
        let index = g
            .grants
            .iter()
            .position(|x| x.expires_at > now && ct_eq(x.token.as_bytes(), grant.as_bytes()))
            .ok_or(AppError::Forbidden)?;
        g.grants.remove(index);
        g.phase = Phase::Claimed;
        Ok(())
    }

    /// Gives back a claim whose registration failed.
    pub fn release(&self) {
        let mut g = self.lock();
        if g.phase == Phase::Claimed {
            g.phase = Phase::Open;
        }
    }

    /// The claimed registration succeeded: `user` is the first admin and must finish setup.
    pub fn registered(&self, user: UserId) {
        let mut g = self.lock();
        g.phase = Phase::Pending(user);
        g.code = None;
        g.grants.clear();
    }

    /// Closes setup for good, when `user` is the admin it waits for.
    pub fn finish(&self, user: UserId) -> Result<(), AppError> {
        let mut g = self.lock();
        match g.phase {
            Phase::Pending(admin) if admin == user => {
                g.phase = Phase::Done;
                Ok(())
            }
            Phase::Pending(_) => Err(AppError::Forbidden),
            _ => Err(SetupError::AlreadyDone.into()),
        }
    }
}

/// Makes the setup code at start and trades a right code for a grant.
#[derive(Debug)]
pub struct FirstRun<U, E> {
    pub users: U,
    pub env: E,
    pub setup: Arc<SetupState>,
    pub config: AuthConfig,
}

impl<U: UserRepo + FirstAdminRepo, E: Platform> FirstRun<U, E> {
    /// Called once at start. With no admin yet, opens setup with a fresh code (voiding any
    /// earlier one) and returns it for the log; with an admin, closes setup and returns `None`.
    ///
    /// With no admin but a first-admin marker, an account registered with a grant and never
    /// finished setup (the server restarted, or the admin skipped `/setup/finish`): setup resumes
    /// as pending for that account, which finishes it by signing in and confirming a two-step
    /// method. No code is made, because registering another admin is closed.
    pub async fn start(&self) -> Result<Option<SetupCode>, AppError> {
        if self.users.count_admins().await? > 0 {
            self.setup.close();
            return Ok(None);
        }
        if let Some(pending) = self.users.first_admin().await? {
            self.setup.resume(pending);
            tracing::warn!(
                user = %pending,
                "first run: setup was not finished. Sign in as the account that registered \
                 first, set up two-step login and finish setup; no new setup code is needed"
            );
            return Ok(None);
        }
        let mut code = String::with_capacity(CODE_LEN);
        for byte in self.env.bytes::<CODE_LEN>() {
            // 256 is a multiple of 32, so this is uniform.
            code.push(char::from(ALPHABET[usize::from(byte & 31)]));
        }
        self.setup.open(code.clone());
        Ok(Some(SetupCode(code)))
    }

    /// Checks a typed setup code. `secure_context` is whether the connection is HTTPS or on this
    /// machine; setup goes no further otherwise. `client` names who is asking (the API passes the
    /// caller's address key): wrong codes slow that client down and nobody else.
    pub async fn verify(
        &self,
        typed: &str,
        secure_context: bool,
        client: &str,
    ) -> Result<SetupGrant, AppError> {
        if !secure_context {
            return Err(SetupError::InsecureContext.into());
        }
        if self.users.count_admins().await? > 0 {
            self.setup.close();
            return Err(SetupError::AlreadyDone.into());
        }
        let token = b64url::encode(&self.env.bytes::<32>());
        self.setup
            .check_code(typed, token, self.env.now(), self.config.grant_ttl, client)
    }

    pub fn phase(&self) -> SetupPhase {
        self.setup.phase()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalise_reads_crockford_lookalikes() {
        assert_eq!(normalise("ab1o-il 2z"), "AB10112Z");
    }

    #[test]
    fn alphabet_has_32_distinct_symbols_without_lookalikes() {
        let mut seen = std::collections::BTreeSet::new();
        for &c in ALPHABET {
            assert!(seen.insert(c));
            assert!(!b"ILOU".contains(&c));
        }
        assert_eq!(seen.len(), 32);
    }

    #[test]
    fn display_groups_by_four() {
        assert_eq!(
            SetupCode("ABCDEFGHJKMN".into()).as_display(),
            "ABCD-EFGH-JKMN"
        );
    }
}
