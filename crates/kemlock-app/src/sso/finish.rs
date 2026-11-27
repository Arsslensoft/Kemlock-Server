//! `sso_finish`: the last step of an SSO sign-in. The phone sends the one-time code from the
//! redirect, its PKCE verifier and a DPoP proof; the server checks they are those of `start`,
//! exchanges the provider's code, validates the ID token and finds or makes the account.
//!
//! SSO decides who may sign in and never holds or hands out a vault key: this use case issues the
//! same tokens as a password sign-in, bound to the device's DPoP key, and touches nothing that
//! opens a vault. A new account has no keys yet; its devices make them at first sign-in and the
//! server receives only the public halves (design, "Identity and SSO").

use crate::b64url;
use crate::error::AppError;
use crate::platform::{Platform, random_uuid};
use crate::ports::{
    DeviceRepo, EventLog, SecretSeal, StoreError, TokenRepo, TokenSigner, TwoFactorMethod,
    TwoFactorRepo, UserRepo,
};
use crate::privacy::ensure_not_pending;
use crate::register::MAX_NAME_LEN;
use crate::sealed::{Challenge, PURPOSE_CHALLENGE, SsoOrigin};
use crate::session::{DeviceInfo, Sessions};
use crate::sign_in::{SecondStep, SignedIn};
use crate::sso::claims::{EmailTrust, amr_shows_mfa, email_domain, email_trust};
use crate::sso::config::{SsoConfig, valid_verifier};
use crate::sso::error::SsoError;
use crate::sso::model::{CodeExchange, IdentityClaims, SsoIdentity, SsoSession, SsoSettings};
use crate::sso::ports::{
    GroupSync, OidcProvider, SsoIdentityRepo, SsoSettingsRepo, VerifiedDomainRepo,
};
use crate::sso::rules::map_groups;
use crate::sso::state::{PURPOSE_CODE, SsoCode, open_value};
use kemlock_domain::{AccountMode, DeviceKind, Email, KdfParams, Role, User, UserId};
use subtle::ConstantTimeEq;
use time::OffsetDateTime;

/// The key version of an account that has no keys yet. Its first device makes them.
pub const NO_KEYS_YET: u32 = 0;

#[derive(Debug)]
pub struct SsoFinish<U, F, R, O, G, S, D, T, K, E, V, W> {
    pub users: U,
    pub two_factor: F,
    /// The SSO repositories: settings, identities and domain claims.
    pub repos: R,
    pub provider: O,
    pub groups: G,
    pub seal: S,
    pub sessions: Sessions<D, T, K, E, V, W>,
    pub config: SsoConfig,
}

#[derive(Clone, Debug)]
pub struct FinishInput {
    /// The one-time code from the redirect, as sent: unpadded base64url.
    pub code: String,
    /// The phone's PKCE verifier. Its SHA-256 must be the challenge sent to `start`.
    pub verifier: String,
    pub device: DeviceInfo,
    /// The thumbprint of the DPoP key that signed this request; must be `start`'s.
    pub jkt: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SsoSignedIn {
    /// Tokens, or the second step the account still owes.
    pub outcome: SignedIn,
    pub user: UserId,
    /// This sign-in made the account.
    pub new_account: bool,
    /// Kemlock's own two-step check was skipped because the ID token's `amr` shows the provider
    /// did multi-factor authentication ("Via SSO").
    pub mfa_via_sso: bool,
}

fn constant_time_eq(a: &str, b: &str) -> bool {
    bool::from(a.as_bytes().ct_eq(b.as_bytes()))
}

fn same_issuer(a: &str, b: &str) -> bool {
    a.trim_end_matches('/') == b.trim_end_matches('/')
}

impl<U, F, R, O, G, S, D, T, K, E, V, W> SsoFinish<U, F, R, O, G, S, D, T, K, E, V, W>
where
    U: UserRepo,
    F: TwoFactorRepo,
    R: SsoSettingsRepo + SsoIdentityRepo + VerifiedDomainRepo,
    O: OidcProvider,
    G: GroupSync,
    S: SecretSeal,
    D: DeviceRepo,
    T: TokenRepo,
    K: TokenSigner,
    E: Platform,
    V: EventLog,
    W: crate::ports::TwoFactorRepo,
{
    pub async fn execute(&self, input: FinishInput) -> Result<SsoSignedIn, SsoError> {
        let now = self.sessions.env.now();

        // 1. The code is ours, fresh, and the caller is the device that started.
        let code: SsoCode =
            open_value(&self.seal, PURPOSE_CODE, &input.code).ok_or(SsoError::BadState)?;
        if now.unix_timestamp() >= code.expires_at {
            return Err(SsoError::BadState);
        }
        if !constant_time_eq(&code.jkt, &input.jkt) || !valid_verifier(&input.verifier) {
            return Err(SsoError::Unauthorized);
        }
        let challenge = b64url::encode(&self.sessions.env.sha256(input.verifier.as_bytes()));
        if !constant_time_eq(&challenge, &code.app_challenge) {
            return Err(SsoError::Unauthorized);
        }
        // A sign-in that began as the browser extension's ends as its device, with the kind it
        // began with: the redirect it was allowed is not for any other.
        if code.browser && input.device.kind != DeviceKind::KemlockBrowser {
            return Err(SsoError::Unauthorized);
        }

        // 2. The provider says who this is.
        let settings = self
            .repos
            .sso_settings()
            .await?
            .filter(|s| s.enabled)
            .ok_or(SsoError::NotConfigured)?;
        let client = settings.client_config(&self.seal)?;
        let claims = self
            .provider
            .exchange(
                &client,
                &CodeExchange {
                    code: code.provider_code,
                    code_verifier: code.provider_verifier,
                    redirect_uri: self.config.callback_url(),
                    nonce: code.nonce,
                },
            )
            .await?;
        if !same_issuer(&claims.issuer, &settings.issuer) {
            return Err(SsoError::Token(
                "the ID token's issuer isn't the configured one".to_owned(),
            ));
        }
        let email = self.trusted_email(&settings, &claims).await?;

        // 3. The account: linked, linkable by email, or new.
        let (user, new_account, amr_trusted) = self
            .resolve_account(&settings, &claims, &email, now)
            .await?;
        // The provider has said who this is, so the account may be told it is disabled. Before the
        // identity is touched or the group rules apply: a disabled account changes nothing here.
        if self.users.account_disabled(user.id).await? {
            return Err(AppError::AccountDisabled.into());
        }
        ensure_not_pending(&self.users, user.id).await?;
        // An account with a second step is signed in by email each time and has no stored link to
        // touch.
        match self
            .repos
            .touch_identity(&claims.issuer, &claims.subject, email.as_str(), now)
            .await
        {
            Ok(()) | Err(StoreError::NotFound) => {}
            Err(e) => return Err(e.into()),
        }
        if new_account {
            self.sessions
                .record("account.sso_created", user.id, None)
                .await;
        }

        // 4. Groups to spaces and roles, as the admin's rules say. A failure here never stops
        // the sign-in: the person is who the provider says.
        if !settings.group_rules.is_empty() {
            let assignments = map_groups(&settings.group_rules, &claims.groups);
            if let Err(e) = self.groups.apply_groups(user.id, &assignments).await {
                tracing::warn!(user = %user.id, error = %e, "couldn't apply the group rules");
            }
        }

        // 5. Kemlock's own second step, unless the provider did multi-factor authentication.
        let methods: Vec<TwoFactorMethod> = self
            .two_factor
            .list(user.id)
            .await?
            .into_iter()
            .filter(|t| t.enabled)
            .map(|t| t.method)
            .collect();
        // What the provider's `amr` says is how the provider's user signed in, not that they own this
        // account: it is taken in place of Kemlock's own second step only for a confirmed identity.
        // One made by linking to an account that has a second step never is, so the account's own
        // second step is asked at every sign-in with it, not only at the one that linked it (which
        // may have been abandoned at the challenge, leaving the link behind).
        let provider_did_mfa = amr_shows_mfa(&claims.amr) && amr_trusted;
        if !methods.is_empty() && !provider_did_mfa {
            // The device is registered only after the second step, as after a password.
            let device = input.device.resolve(user.id, &self.sessions.env);
            let challenge = Challenge {
                expires_at: (now + self.sessions.config.challenge_ttl).unix_timestamp(),
                user: user.id,
                device,
                device_name: input.device.name,
                device_kind: input.device.kind,
                jkt: input.jkt,
                via_sso: true,
                // The second step that finishes this sign-in records the session under this
                // identity, so a logout for it ends the device.
                sso: Some(SsoOrigin {
                    issuer: claims.issuer.clone(),
                    subject: claims.subject.clone(),
                    session_id: claims.session_id.clone(),
                }),
            };
            return Ok(SsoSignedIn {
                outcome: SignedIn::SecondStep(SecondStep {
                    challenge: self.seal.seal(PURPOSE_CHALLENGE, &challenge.encode()),
                    methods,
                }),
                user: user.id,
                new_account,
                mfa_via_sso: false,
            });
        }

        // 6. Tokens, bound to the device's DPoP key.
        let device = self
            .sessions
            .register_device(user.id, &input.device, &input.jkt)
            .await?;
        // The device this identity signed in, for a back-channel logout to end and no other.
        let started = SsoSession {
            device: device.id,
            user: user.id,
            issuer: claims.issuer.clone(),
            subject: claims.subject.clone(),
            session_id: claims.session_id.clone(),
            started_at: now,
        };
        // A session no logout could end is not one to hand out: a failed write fails the sign-in.
        self.repos.record_sso_session(&started).await?;
        let tokens = self
            .sessions
            .issue(&user, &device, &input.jkt, None)
            .await?;
        self.sessions
            .record("auth.sso_sign_in", user.id, Some(device.id))
            .await;
        Ok(SsoSignedIn {
            outcome: SignedIn::Tokens(tokens),
            user: user.id,
            new_account,
            mfa_via_sso: !methods.is_empty() && provider_did_mfa,
        })
    }

    /// The token's email, if the rules let this server trust it: `email_verified: true`, or no
    /// claim at all where the admin allows that and DNS proves the domain.
    async fn trusted_email(
        &self,
        settings: &SsoSettings,
        claims: &IdentityClaims,
    ) -> Result<Email, SsoError> {
        let trust = email_trust(settings, claims);
        let email = claims
            .email
            .as_deref()
            .and_then(|e| Email::parse(e).ok())
            .ok_or(SsoError::EmailNotVerified)?;
        match trust {
            EmailTrust::Verified => Ok(email),
            EmailTrust::NeedsDomainProof => {
                if self.domain_verified(email.as_str()).await? {
                    Ok(email)
                } else {
                    Err(SsoError::DomainNotVerified)
                }
            }
            EmailTrust::Refused => Err(SsoError::EmailNotVerified),
        }
    }

    async fn domain_verified(&self, email: &str) -> Result<bool, SsoError> {
        let Some(domain) = email_domain(email) else {
            return Ok(false);
        };
        Ok(self
            .repos
            .domain_claim(&domain)
            .await?
            .is_some_and(|claim| claim.is_verified()))
    }

    /// Two first sign-ins from one person's devices can race to make the account; the loser sees
    /// a duplicate and tries once more, when the winner's rows are there to find.
    async fn resolve_account(
        &self,
        settings: &SsoSettings,
        claims: &IdentityClaims,
        email: &Email,
        now: OffsetDateTime,
    ) -> Result<(User, bool, bool), SsoError> {
        match self.find_or_make(settings, claims, email, now).await {
            Err(SsoError::App(AppError::Duplicate)) => {
                self.find_or_make(settings, claims, email, now).await
            }
            other => other,
        }
    }

    async fn find_or_make(
        &self,
        settings: &SsoSettings,
        claims: &IdentityClaims,
        email: &Email,
        now: OffsetDateTime,
    ) -> Result<(User, bool, bool), SsoError> {
        // Linked already: issuer and subject name the account, whatever the email says now.
        if let Some(identity) = self
            .repos
            .find_identity(&claims.issuer, &claims.subject)
            .await?
        {
            let user = self
                .users
                .by_id(identity.user)
                .await?
                .ok_or(SsoError::Unauthorized)?;
            return Ok((user, false, identity.confirmed));
        }

        if settings.require_verified_domain && !self.domain_verified(email.as_str()).await? {
            return Err(SsoError::DomainNotVerified);
        }

        // Not linked: an account with this (verified) email may be linked, when the admin allows.
        if let Some(user) = self.users.by_email(email).await? {
            if !settings.link_by_email {
                return Err(SsoError::LinkingNotAllowed);
            }
            // A disabled account is refused before anything is linked to it.
            if self.users.account_disabled(user.id).await? {
                return Err(AppError::AccountDisabled.into());
            }
            ensure_not_pending(&self.users, user.id).await?;
            // An account whose address was never confirmed may have been made by someone who
            // doesn't own it.
            if self.sessions.config.signups_verify && self.users.email_unconfirmed(user.id).await? {
                return Err(AppError::EmailNotConfirmed.into());
            }
            // An account that has a second step is not linked here, and its second step is asked
            // at this sign-in and every one like it: nothing has shown this sign-in is the
            // account's owner, and a link stored before the second step passes would stay behind
            // if the challenge were abandoned (the holder of the provider identity could then
            // end the owner's sessions with a back-channel logout, and `amr` could never stand
            // in for the second step).
            let owes_second_step = self
                .two_factor
                .list(user.id)
                .await?
                .iter()
                .any(|t| t.enabled);
            if owes_second_step {
                return Ok((user, false, false));
            }
            let confirmed = self.link(&user, claims, email, now, true).await?;
            // The account's own events say that an identity was linked to it, by email.
            self.sessions
                .record("account.sso_linked", user.id, None)
                .await;
            return Ok((user, false, confirmed));
        }

        if !settings.create_accounts {
            return Err(SsoError::NoAccount);
        }
        let user = self.new_account(claims, email, now);
        self.users.insert(&user).await?;
        self.link(&user, claims, email, now, true).await?;
        Ok((user, true, true))
    }

    async fn link(
        &self,
        user: &User,
        claims: &IdentityClaims,
        email: &Email,
        now: OffsetDateTime,
        confirmed: bool,
    ) -> Result<bool, SsoError> {
        let identity = SsoIdentity {
            issuer: claims.issuer.clone(),
            subject: claims.subject.clone(),
            user: user.id,
            email: email.as_str().to_owned(),
            linked_at: now,
            last_login_at: now,
            confirmed,
        };
        match self.repos.insert_identity(&identity).await {
            Ok(()) => Ok(confirmed),
            // Another sign-in linked this subject a moment ago: fine if it was to this account.
            Err(StoreError::Duplicate) => match self
                .repos
                .find_identity(&claims.issuer, &claims.subject)
                .await?
            {
                Some(existing) if existing.user == user.id => Ok(existing.confirmed),
                _ => Err(SsoError::Unauthorized),
            },
            Err(e) => Err(e.into()),
        }
    }

    /// An account with no keys. Its devices make theirs at first sign-in; nothing here is a
    /// secret or opens a vault, and no password can sign in to it (no OPAQUE record).
    fn new_account(&self, claims: &IdentityClaims, email: &Email, now: OffsetDateTime) -> User {
        let env = &self.sessions.env;
        let name = claims
            .name
            .as_deref()
            .map(|n| n.trim().chars().take(MAX_NAME_LEN).collect::<String>())
            .filter(|n| !n.is_empty());
        User {
            id: UserId(random_uuid(env)),
            email: email.clone(),
            name,
            mode: AccountMode::KemlockOnly,
            role: Role::User,
            kdf: KdfParams::new_account(env.bytes::<{ KdfParams::SALT_LEN }>()),
            opaque_record: None,
            wrapped_root_key: Vec::new(),
            public_bundle: Vec::new(),
            bundle_signature: Vec::new(),
            sealed_private_keys: Vec::new(),
            key_version: NO_KEYS_YET,
            security_stamp: random_uuid(env),
            created_at: now,
            updated_at: now,
        }
    }
}
