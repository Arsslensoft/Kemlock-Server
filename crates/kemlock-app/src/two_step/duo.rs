//! Duo's Universal Prompt (Bitwarden's type 2), as Vaultwarden's `duo.rs` and `duo_oidc.rs` have
//! it.

use super::TwoStep;
use super::data::{DuoKeys, PURPOSE_DUO, PURPOSE_DUO_PROMPT, alphanumeric, open, same, sealed};
use super::ports::DuoPrompt;
use crate::error::AppError;
use crate::passkeys::{ChallengeKind, ChallengeRepo};
use crate::platform::Platform;
use crate::ports::{SecretSeal, TwoFactor, TwoFactorMethod, TwoFactorRepo};
use kemlock_domain::{User, UserId};
use serde::{Deserialize, Serialize};
use time::Duration;

/// How long a prompt waits for its answer, as Vaultwarden's `CTX_VALIDITY_SECS`.
const PROMPT_TTL: Duration = Duration::seconds(300);
/// The length of the OAuth state and the nonce.
const STATE_LENGTH: usize = 64;

/// Which Duo integration an account uses.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DuoStatus {
    /// The method is on, with the server's integration.
    Global(DuoKeys),
    /// The method is on, with the keys the account saved.
    User(DuoKeys),
    /// The method is off. `global_available` says whether the server has an integration the
    /// account could use.
    Disabled { global_available: bool },
}

impl DuoStatus {
    /// The keys a prompt is made with, when the method is on.
    pub fn keys(&self) -> Option<&DuoKeys> {
        match self {
            DuoStatus::Global(keys) | DuoStatus::User(keys) => Some(keys),
            DuoStatus::Disabled { .. } => None,
        }
    }
}

/// What a prompt keeps until its answer comes back.
#[derive(Serialize, Deserialize)]
struct PromptContext {
    state: String,
    nonce: String,
}

impl<F, S, E, C> TwoStep<F, S, E, C>
where
    F: TwoFactorRepo,
    S: SecretSeal,
    E: Platform,
    C: ChallengeRepo,
{
    fn global_duo(&self) -> Option<DuoKeys> {
        self.settings
            .duo_global
            .clone()
            .filter(DuoKeys::is_complete)
    }

    /// The keys a Duo row stands for: the ones it holds, or else the server's.
    fn duo_status_of(&self, row: &TwoFactor) -> DuoStatus {
        let own = self
            .seal
            .open(PURPOSE_DUO, &row.sealed_secret)
            .ok()
            .and_then(|plain| serde_json::from_slice::<DuoKeys>(&plain).ok())
            .filter(DuoKeys::is_complete);
        if let Some(keys) = own {
            return DuoStatus::User(keys);
        }
        match self.global_duo() {
            Some(keys) => DuoStatus::Global(keys),
            None => DuoStatus::Disabled {
                global_available: false,
            },
        }
    }

    pub(super) fn duo_usable(&self, row: &TwoFactor) -> bool {
        row.enabled && self.duo_status_of(row).keys().is_some()
    }

    /// Which integration the account uses, or that the method is off.
    pub async fn duo_status(&self, user: UserId) -> Result<DuoStatus, AppError> {
        let row = self
            .two_factor
            .list(user)
            .await?
            .into_iter()
            .find(|t| t.method == TwoFactorMethod::Duo);
        Ok(match row {
            Some(row) => self.duo_status_of(&row),
            None => DuoStatus::Disabled {
                global_available: self.global_duo().is_some(),
            },
        })
    }

    /// Turns the method on with the keys the account gives (checked with Duo first), or, with
    /// `None`, with the server's.
    pub async fn duo_set(
        &self,
        user: UserId,
        custom: Option<DuoKeys>,
    ) -> Result<DuoStatus, AppError> {
        let plain = self.duo_check(custom.as_ref()).await?;
        self.duo_store(user, &plain).await
    }

    /// The checks of [`TwoStep::duo_set`] alone, with Duo: what to store. A caller that wants a
    /// proof spent between the check and the change calls this, then the proof, then
    /// [`TwoStep::duo_store`].
    pub async fn duo_check(&self, custom: Option<&DuoKeys>) -> Result<Vec<u8>, AppError> {
        Ok(match custom {
            Some(keys) => {
                if !keys.is_complete() {
                    return Err(AppError::Invalid("the Duo host and keys are all required"));
                }
                if !duo_host_ok(&keys.host) {
                    return Err(AppError::Invalid(
                        "the Duo host must look like api-1234abcd.duosecurity.com",
                    ));
                }
                self.duo
                    .check_keys(keys)
                    .await
                    .map_err(|_| AppError::Invalid("Failed to validate Duo credentials"))?;
                serde_json::to_vec(keys).unwrap_or_default()
            }
            None => {
                if self.global_duo().is_none() {
                    return Err(AppError::Invalid("this server has no Duo keys to use"));
                }
                b"{}".to_vec()
            }
        })
    }

    /// Stores what [`TwoStep::duo_check`] accepted, and turns the method on.
    pub async fn duo_store(&self, user: UserId, plain: &[u8]) -> Result<DuoStatus, AppError> {
        self.two_factor
            .put(&TwoFactor {
                user,
                method: TwoFactorMethod::Duo,
                sealed_secret: self.seal.seal(PURPOSE_DUO, plain),
                enabled: true,
                created_at: self.env.now(),
            })
            .await?;
        self.duo_status(user).await
    }

    /// Takes the method off.
    pub async fn duo_remove(&self, user: UserId) -> Result<(), AppError> {
        self.two_factor.remove(user, TwoFactorMethod::Duo).await?;
        Ok(())
    }

    /// Starts a prompt: checks Duo is up and answers the address to send the person to. The state
    /// and nonce it makes are kept, five minutes, for the answer; a newer prompt replaces them.
    pub async fn duo_start(
        &self,
        user: &User,
        client: &str,
        device: &str,
    ) -> Result<String, AppError> {
        let status = self.duo_status(user.id).await?;
        let keys = status
            .keys()
            .ok_or(AppError::Invalid("Can't fetch Duo Keys"))?;
        let context = PromptContext {
            state: alphanumeric(&self.env, STATE_LENGTH),
            nonce: alphanumeric(&self.env, STATE_LENGTH),
        };
        self.challenges
            .put_challenge(
                user.id,
                ChallengeKind::DuoPrompt,
                &sealed(&self.seal, PURPOSE_DUO_PROMPT, &context),
                self.env.now() + PROMPT_TTL,
            )
            .await?;
        let prompt = DuoPrompt {
            keys,
            username: user.email.as_str(),
            client,
            device,
            state: &context.state,
            nonce: &context.nonce,
        };
        self.duo.auth_url(&prompt).await.map_err(|e| {
            tracing::warn!(error = %e, "Duo's prompt couldn't be started");
            AppError::Invalid("Duo couldn't be reached")
        })
    }

    /// Checks the answer of a prompt: `token` is what Duo's redirect brought back, `<code>|<state>`.
    /// A prompt is answered once, right or wrong.
    pub async fn duo_verify(
        &self,
        user: &User,
        client: &str,
        device: &str,
        token: &str,
    ) -> Result<(), AppError> {
        let mut parts = token.trim().split('|');
        let (Some(code), Some(state), None) = (parts.next(), parts.next(), parts.next()) else {
            return Err(AppError::Unauthorized);
        };
        let status = self.duo_status(user.id).await?;
        let keys = status.keys().ok_or(AppError::Unauthorized)?;
        let kept = self
            .challenges
            .take_challenge(user.id, ChallengeKind::DuoPrompt, self.env.now())
            .await?
            .ok_or(AppError::Unauthorized)?;
        let context = open::<PromptContext, _>(&self.seal, PURPOSE_DUO_PROMPT, &kept)
            .ok_or(AppError::Unauthorized)?;
        if !same(state, &context.state) {
            return Err(AppError::Unauthorized);
        }
        let prompt = DuoPrompt {
            keys,
            username: user.email.as_str(),
            client,
            device,
            state: &context.state,
            nonce: &context.nonce,
        };
        self.duo.verify(&prompt, code).await.map_err(|e| {
            tracing::debug!(error = %e, "Duo didn't accept the answer");
            AppError::Unauthorized
        })
    }
}

/// Whether `host` is a Duo API host, `api-<id>.duosecurity.com`, and so a place the server may
/// call with a person's keys (a Duo host that is any name would let a setup make the server
/// request an address of the person's choosing).
pub(crate) fn duo_host_ok(host: &str) -> bool {
    let Some(id) = host
        .strip_prefix("api-")
        .and_then(|rest| rest.strip_suffix(".duosecurity.com"))
    else {
        return false;
    };
    !id.is_empty()
        && id
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit())
}

#[cfg(test)]
mod host_tests {
    use super::duo_host_ok;

    #[test]
    fn only_duo_api_hosts_are_called() {
        assert!(duo_host_ok("api-1234abcd.duosecurity.com"));
        for bad in [
            "",
            "api-.duosecurity.com",
            "api-x.duosecurity.com.evil.example",
            "evil.example/api-x.duosecurity.com",
            "api-x@evil.example.duosecurity.com",
            "API-X.duosecurity.com",
            "api-a.b.duosecurity.com",
            "localhost",
            "127.0.0.1",
        ] {
            assert!(!duo_host_ok(bad), "{bad}");
        }
    }
}
