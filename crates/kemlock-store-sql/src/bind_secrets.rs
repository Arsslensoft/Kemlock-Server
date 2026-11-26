//! Sealing the stored per-account secrets to their accounts.
//!
//! Secrets of one account (its TOTP seed, the lists and settings of its other second steps, its
//! recovery code) are sealed under the secret's purpose and the account's id
//! ([`kemlock_app::sealed::bound_purpose`]), so a value copied into another account's row doesn't
//! open there. Rows written before that are sealed under the bare purpose. This pass seals each of
//! those again, bound, in one transaction, and the server then stops opening the bare form
//! ([`kemlock_app::sealed::allow_bare_secrets`]), which would otherwise let someone who can write
//! the database keep a copy of a secret sealed the old way and paste it into any row later.

use crate::error::StoreResult;
use crate::store::SqlStore;
use crate::tables::{bw_account_extras, two_factor, two_factor_recovery};
use kemlock_app::admin::SettingsRepo;
use kemlock_app::passkeys::PURPOSE_WEBAUTHN;
use kemlock_app::ports::{SecretSeal, StoreError, TwoFactorMethod};
use kemlock_app::sealed::{PURPOSE_TOTP, SECRETS_BOUND_KEY, bound_purpose, seal_bound};
use kemlock_app::two_step::{
    PURPOSE_DUO, PURPOSE_EMAIL, PURPOSE_LEGACY_RECOVERY, PURPOSE_RECOVERY, PURPOSE_YUBIKEY,
};
use kemlock_domain::UserId;
use sea_orm::sea_query::Expr;
use sea_orm::{ColumnTrait, EntityTrait, QueryFilter, TransactionTrait};

/// What a pass found.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct BindReport {
    /// Secrets that were sealed the old way and are sealed to their account now.
    pub sealed_again: u64,
    /// Secrets that open neither way (another `server.key`, or damage): left as they are.
    pub unreadable: u64,
}

fn purpose_of(method: TwoFactorMethod) -> &'static str {
    match method {
        TwoFactorMethod::Totp => PURPOSE_TOTP,
        TwoFactorMethod::WebAuthn => PURPOSE_WEBAUTHN,
        TwoFactorMethod::Email => PURPOSE_EMAIL,
        TwoFactorMethod::YubiKey => PURPOSE_YUBIKEY,
        TwoFactorMethod::Duo => PURPOSE_DUO,
    }
}

/// What to do with one sealed value.
enum Rebound {
    /// Sealed to the account already.
    Bound,
    /// Sealed the old way; this is the value sealed to the account.
    Again(Vec<u8>),
    /// Opens neither way.
    Unreadable,
}

fn rebind<S: SecretSeal>(seal: &S, purpose: &str, user: UserId, sealed: &[u8]) -> Rebound {
    if seal.open(&bound_purpose(purpose, user), sealed).is_ok() {
        return Rebound::Bound;
    }
    match seal.open(purpose, sealed) {
        Ok(plain) => Rebound::Again(seal_bound(seal, purpose, user, &plain)),
        Err(_) => Rebound::Unreadable,
    }
}

impl SqlStore {
    /// Seals every stored per-account secret that opens only the old way to its account, in one
    /// transaction, then records that it was done ([`SECRETS_BOUND_KEY`]). Cheap when there is
    /// nothing to do, so the server runs it at every start: a restore can bring old rows back.
    pub async fn bind_secrets<S: SecretSeal>(&self, seal: &S) -> Result<BindReport, StoreError> {
        let mut report = BindReport::default();
        let txn = self.writer().begin().await.store()?;

        for row in two_factor::Entity::find().all(&txn).await.store()? {
            let Some(method) = TwoFactorMethod::parse(&row.method) else {
                continue;
            };
            let user = UserId(row.user_id);
            match rebind(seal, purpose_of(method), user, &row.sealed_secret) {
                Rebound::Bound => {}
                Rebound::Unreadable => report.unreadable += 1,
                Rebound::Again(sealed) => {
                    // Named by the secret it held: a row changed since is left alone.
                    two_factor::Entity::update_many()
                        .col_expr(two_factor::Column::SealedSecret, Expr::value(sealed))
                        .filter(two_factor::Column::UserId.eq(row.user_id))
                        .filter(two_factor::Column::Method.eq(row.method.clone()))
                        .filter(two_factor::Column::SealedSecret.eq(row.sealed_secret.clone()))
                        .exec(&txn)
                        .await
                        .store()?;
                    report.sealed_again += 1;
                }
            }
        }

        for row in two_factor_recovery::Entity::find()
            .all(&txn)
            .await
            .store()?
        {
            let user = UserId(row.user_id);
            match rebind(seal, PURPOSE_RECOVERY, user, &row.sealed_code) {
                Rebound::Bound => {}
                Rebound::Unreadable => report.unreadable += 1,
                Rebound::Again(sealed) => {
                    two_factor_recovery::Entity::update_many()
                        .col_expr(two_factor_recovery::Column::SealedCode, Expr::value(sealed))
                        .filter(two_factor_recovery::Column::UserId.eq(row.user_id))
                        .filter(two_factor_recovery::Column::SealedCode.eq(row.sealed_code.clone()))
                        .exec(&txn)
                        .await
                        .store()?;
                    report.sealed_again += 1;
                }
            }
        }

        // The recovery code an account moved from Vaultwarden still has in its imported row.
        for row in bw_account_extras::Entity::find().all(&txn).await.store()? {
            let Some(held) = row.sealed_totp_recover.clone() else {
                continue;
            };
            let user = UserId(row.user_id);
            match rebind(seal, PURPOSE_LEGACY_RECOVERY, user, &held) {
                Rebound::Bound => {}
                Rebound::Unreadable => report.unreadable += 1,
                Rebound::Again(sealed) => {
                    bw_account_extras::Entity::update_many()
                        .col_expr(
                            bw_account_extras::Column::SealedTotpRecover,
                            Expr::value(sealed),
                        )
                        .filter(bw_account_extras::Column::UserId.eq(row.user_id))
                        .filter(bw_account_extras::Column::SealedTotpRecover.eq(held))
                        .exec(&txn)
                        .await
                        .store()?;
                    report.sealed_again += 1;
                }
            }
        }

        txn.commit().await.store()?;
        SettingsRepo::put_setting(self, SECRETS_BOUND_KEY, "1").await?;
        Ok(report)
    }
}
