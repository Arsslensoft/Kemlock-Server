//! Register: OPAQUE registration, start and finish, creating a Kemlock-only account with its
//! public bundle, bundle signature, sealed private keys and wrapped root key.
//!
//! Allowed while `SIGNUPS_ALLOWED`, or with a setup grant, which makes the account the first
//! admin to be: it stays a plain user until `finish_setup` sees a confirmed two-step method, and
//! only then becomes an admin. The client makes the account id and the salt (it needs them to
//! make the master key OPAQUE takes as its password); the KDF settings must be the defaults (64
//! MiB, 3 passes, 4 lanes) and the salt exactly 16 bytes, so that no account's prelogin answer
//! differs from the fake one an unknown email gets.
//! It checks the layout and length of every key blob (docs/crypto.md) but can't open any of them.
//! Verifying the bundle's `sig1` signature needs ML-DSA, which this slice leaves to clients.

use crate::config::AuthConfig;
use crate::error::AppError;
use crate::first_admin::FirstAdminRepo;
use crate::first_run::SetupState;
use crate::platform::{Platform, random_uuid};
use crate::ports::{PasswordAuth, UserRepo};
use kemlock_domain::{AccountMode, Email, KdfParams, Role, SetupError, User, UserId};
use std::sync::Arc;

/// `"kemlock/v1/bundle"`, the start of a public-key bundle.
pub const BUNDLE_PREFIX: &[u8] = b"kemlock/v1/bundle";
/// A bundle is its prefix, account id (16), key version (4), kx1 public key (1600) and sig1
/// public key (1984).
pub const BUNDLE_LEN: usize = 17 + 16 + 4 + 1600 + 1984;
/// A `sig1` signature: ML-DSA-65 (3309) and Ed25519 (64).
pub const BUNDLE_SIGNATURE_LEN: usize = 3309 + 64;
/// The root key (64 bytes) wrapped with AES-256-GCM: nonce, key, tag.
pub const WRAPPED_ROOT_KEY_LEN: usize = 12 + 64 + 16;
/// The shortest sealed value, and the longest sealed private-key blob accepted.
pub const SEALED_PRIVATE_KEYS_RANGE: std::ops::RangeInclusive<usize> = 28..=64 * 1024;
/// The first key version of a new account.
pub const FIRST_KEY_VERSION: u32 = 1;
/// The longest display name kept.
pub const MAX_NAME_LEN: usize = 100;

#[derive(Debug)]
pub struct Register<U, P, E> {
    pub users: U,
    pub auth: P,
    pub env: E,
    pub setup: Arc<SetupState>,
    pub config: AuthConfig,
}

#[derive(Clone, Debug)]
pub struct RegisterStartInput {
    pub email: String,
    /// OPAQUE's `RegistrationRequest`.
    pub request: Vec<u8>,
    pub setup_grant: Option<String>,
}

#[derive(Clone, Debug)]
pub struct RegisterInput {
    /// Chosen by the client: the bundle and the root-key wrap are bound to it.
    pub user: UserId,
    pub email: String,
    pub name: Option<String>,
    /// OPAQUE's `RegistrationUpload`.
    pub upload: Vec<u8>,
    pub kdf: KdfParams,
    pub public_bundle: Vec<u8>,
    pub bundle_signature: Vec<u8>,
    pub sealed_private_keys: Vec<u8>,
    pub wrapped_root_key: Vec<u8>,
    pub setup_grant: Option<String>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Registered {
    pub user: UserId,
    /// Whether the account registered as the first admin: it becomes one when it finishes setup.
    pub admin: bool,
}

impl<U: UserRepo + FirstAdminRepo, P: PasswordAuth, E: Platform> Register<U, P, E> {
    /// Registration, first message: the server's `RegistrationResponse`.
    pub async fn start(&self, input: RegisterStartInput) -> Result<Vec<u8>, AppError> {
        let email = Email::parse(&input.email).map_err(|_| AppError::Invalid("not an email"))?;
        let granted = input
            .setup_grant
            .as_deref()
            .is_some_and(|g| self.setup.has_grant(g, self.env.now()));
        if !granted && !self.config.signups_allowed {
            return Err(AppError::Forbidden);
        }
        Ok(self
            .auth
            .registration_response(email.as_str().as_bytes(), &input.request)?)
    }

    /// Registration, last message: stores the account.
    pub async fn finish(&self, input: RegisterInput) -> Result<Registered, AppError> {
        let email = Email::parse(&input.email).map_err(|_| AppError::Invalid("not an email"))?;
        check_keys(&input)?;
        let now = self.env.now();

        let admin = input.setup_grant.is_some();
        if admin {
            // The grant is this process's; an admin may exist already (made by another replica
            // or before this one started), and the database knows.
            if self.users.count_admins().await? > 0 {
                self.setup.close();
                return Err(SetupError::AlreadyDone.into());
            }
            let grant = input.setup_grant.as_deref().unwrap_or_default();
            self.setup.claim(grant, now)?;
        } else if !self.config.signups_allowed {
            return Err(AppError::Forbidden);
        }

        let result = self.create(input, email, admin).await;
        match &result {
            Ok(registered) if admin => self.setup.registered(registered.user),
            Ok(_) => {}
            Err(AppError::Duplicate) if admin => {
                // Either the email is taken, or another replica registered the first admin in
                // the meantime and the marker the database keeps refused this account.
                if let Some(other) = self.users.first_admin().await? {
                    self.setup.resume(other);
                    return Err(SetupError::AlreadyDone.into());
                }
                self.setup.release();
            }
            Err(_) if admin => self.setup.release(),
            Err(_) => {}
        }
        result
    }

    async fn create(
        &self,
        input: RegisterInput,
        email: Email,
        admin: bool,
    ) -> Result<Registered, AppError> {
        let record = self.auth.registration_record(&input.upload)?;
        let now = self.env.now();
        let name = input
            .name
            .map(|n| n.trim().chars().take(MAX_NAME_LEN).collect::<String>())
            .filter(|n| !n.is_empty());
        let user = User {
            id: input.user,
            email,
            name,
            mode: AccountMode::KemlockOnly,
            // The first admin is a plain user until setup finishes with a two-step method.
            role: Role::User,
            kdf: input.kdf,
            opaque_record: Some(record),
            wrapped_root_key: input.wrapped_root_key,
            public_bundle: input.public_bundle,
            bundle_signature: input.bundle_signature,
            sealed_private_keys: input.sealed_private_keys,
            key_version: FIRST_KEY_VERSION,
            security_stamp: random_uuid(&self.env),
            created_at: now,
            updated_at: now,
        };
        if admin {
            // The account and the first-admin marker go in together: a second first admin
            // (another replica has its own setup code) fails here, in the database.
            self.users.insert_first_admin(&user).await?;
        } else {
            self.users.insert(&user).await?;
        }
        Ok(Registered {
            user: user.id,
            admin,
        })
    }
}

pub(crate) fn check_keys(input: &RegisterInput) -> Result<(), AppError> {
    // Exactly the defaults and a 16-byte salt. Prelogin answers an unknown email with these, so a
    // registered account that differed would be told apart from an unknown one by its answer.
    if !input.kdf.is_account_default() {
        return Err(AppError::Invalid(
            "the KDF settings must be the defaults with a 16-byte salt",
        ));
    }
    let bundle = &input.public_bundle;
    let layout_ok = bundle.len() == BUNDLE_LEN
        && bundle.starts_with(BUNDLE_PREFIX)
        && bundle[17..33] == *input.user.as_bytes()
        && bundle[33..37] == FIRST_KEY_VERSION.to_be_bytes();
    if !layout_ok {
        return Err(AppError::Invalid("the public bundle is malformed"));
    }
    if input.bundle_signature.len() != BUNDLE_SIGNATURE_LEN {
        return Err(AppError::Invalid("the bundle signature is malformed"));
    }
    if input.wrapped_root_key.len() != WRAPPED_ROOT_KEY_LEN {
        return Err(AppError::Invalid("the wrapped root key is malformed"));
    }
    if !SEALED_PRIVATE_KEYS_RANGE.contains(&input.sealed_private_keys.len()) {
        return Err(AppError::Invalid("the sealed private keys are malformed"));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn input() -> RegisterInput {
        let user = UserId::random();
        let mut bundle = BUNDLE_PREFIX.to_vec();
        bundle.extend_from_slice(user.as_bytes());
        bundle.extend_from_slice(&FIRST_KEY_VERSION.to_be_bytes());
        bundle.resize(BUNDLE_LEN, 1);
        RegisterInput {
            user,
            email: "a@b.co".into(),
            name: None,
            upload: vec![],
            kdf: KdfParams::new_account([3; 16]),
            public_bundle: bundle,
            bundle_signature: vec![0; BUNDLE_SIGNATURE_LEN],
            sealed_private_keys: vec![0; 40],
            wrapped_root_key: vec![0; WRAPPED_ROOT_KEY_LEN],
            setup_grant: None,
        }
    }

    #[test]
    fn a_well_formed_input_passes() {
        assert_eq!(check_keys(&input()), Ok(()));
    }

    #[test]
    fn a_bundle_for_another_account_is_refused() {
        let mut i = input();
        i.public_bundle[20] ^= 1;
        assert!(check_keys(&i).is_err());
    }

    #[test]
    fn any_kdf_but_the_default_with_a_sixteen_byte_salt_is_refused() {
        let tweaks: [fn(&mut RegisterInput); 6] = [
            |i| i.kdf.memory_kib = 32 * 1024,
            |i| i.kdf.memory_kib = 128 * 1024,
            |i| i.kdf.iterations = 4,
            |i| i.kdf.parallelism = 2,
            |i| i.kdf.salt = vec![3; 32],
            |i| i.kdf.salt = vec![3; 100_000],
        ];
        for tweak in tweaks {
            let mut i = input();
            tweak(&mut i);
            assert!(check_keys(&i).is_err());
        }
    }

    #[test]
    fn short_blobs_and_weak_kdf_are_refused() {
        let mut i = input();
        i.wrapped_root_key.pop();
        assert!(check_keys(&i).is_err());
        let mut i = input();
        i.kdf.iterations = 1;
        assert!(check_keys(&i).is_err());
        let mut i = input();
        i.sealed_private_keys = vec![0; 3];
        assert!(check_keys(&i).is_err());
    }
}
