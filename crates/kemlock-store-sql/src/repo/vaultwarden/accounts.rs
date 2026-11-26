//! Accounts, devices and two-step setups.

use super::rows::{self, row_time, row_uuid};
use super::scope::USER;
use super::{Ctx, Res, invalid};
use crate::convert::{unix_millis, utc};
use crate::error::StoreResult;
use crate::tables::{bw_account_extras, bw_accounts, devices, refresh_tokens, two_factor, users};
use kemlock_app::b64url;
use kemlock_app::bitwarden::BwAccount;
use kemlock_app::passkeys::{ImportedKey, PURPOSE_WEBAUTHN, encode_key_list};
use kemlock_app::ports::{RefreshToken, TwoFactorMethod};
use kemlock_app::two_step::{PURPOSE_DUO, PURPOSE_EMAIL, PURPOSE_YUBIKEY};
use kemlock_domain::{
    AccountMode, Device, DeviceId, DeviceKind, Email, KdfParams, Role, User, UserId,
};
use kemlock_vaultwarden::mapping::MappedAccount;
use kemlock_vaultwarden::snapshot::Table;
use kemlock_vaultwarden::two_step;
use sea_orm::ActiveValue::{NotSet, Set};
use sea_orm::{ColumnTrait, EntityTrait, QueryFilter};
use serde_json::Value;
use std::collections::BTreeSet;
use uuid::Uuid;

/// How long an imported refresh token lives from the import.
const REFRESH_DAYS: i64 = 90;

/// The `SecretSeal` purpose of the legacy TOTP columns of a Vaultwarden user.
const PURPOSE_ACCOUNT: &str = "vw-account";
/// The purpose `kemlock-app` and the Bitwarden API open a TOTP secret with.
const PURPOSE_TOTP: &str = "totp";

/// Vaultwarden's twofactor types: an authenticator app, email, Duo, a YubiKey, U2F and WebAuthn.
const TYPE_AUTHENTICATOR: i64 = 0;
const TYPE_EMAIL: i64 = 1;
const TYPE_DUO: i64 = 2;
const TYPE_YUBIKEY: i64 = 3;
const TYPE_U2F: i64 = 4;
const TYPE_WEBAUTHN: i64 = 7;

/// The UUID of a security stamp: Vaultwarden makes them UUIDs, and `users.security_stamp` is one.
/// A stamp that isn't gets a stable UUID made of its SHA-256.
pub(super) fn stamp_uuid(stamp: &str) -> Uuid {
    if let Ok(parsed) = Uuid::parse_str(stamp.trim()) {
        return parsed;
    }
    let digest = kemlock_crypto::hash::sha256(stamp.as_bytes());
    let mut bytes = [0u8; 16];
    bytes.copy_from_slice(&digest[..16]);
    Uuid::from_bytes(bytes)
}

fn to_i32(value: i64, what: &str) -> Res<i32> {
    i32::try_from(value).map_err(|_| invalid(format!("the {what} {value} is out of range")))
}

fn opt_i32(value: Option<i64>, what: &str) -> Res<Option<i32>> {
    value.map(|v| to_i32(v, what)).transpose()
}

pub(super) fn now_ms(ctx: &Ctx) -> i64 {
    i64::try_from(unix_millis(ctx.opts.now)).unwrap_or(0)
}

pub(super) async fn put_accounts(ctx: &mut Ctx, accounts: &[MappedAccount]) -> Res<()> {
    for account in accounts {
        // An account that exists and wasn't made by an import is not Vaultwarden's to rewrite.
        if !ctx.claim(USER, account.id.0).await? {
            continue;
        }
        put_account(ctx, account).await?;
        ctx.touched.insert(account.id.0);
    }
    Ok(())
}

async fn put_account(ctx: &Ctx, a: &MappedAccount) -> Res<()> {
    let txn = &ctx.txn;
    let id = a.id.0;
    let b = &a.bitwarden;
    let stamp = stamp_uuid(&b.security_stamp);
    let email = Email::parse(&a.email).map_err(|_| {
        invalid(format!(
            "the email of the user {id} is not one Kemlock accepts"
        ))
    })?;
    let name = Some(a.name.clone());

    if users::Entity::find_by_id(id)
        .one(txn)
        .await
        .store()?
        .is_some()
    {
        // The Kemlock side of the account (keys, OPAQUE record) is not Vaultwarden's to change.
        users::Entity::update_many()
            .set(users::ActiveModel {
                id: NotSet,
                email: Set(email.as_str().to_owned()),
                name: Set(name),
                mode: NotSet,
                role: NotSet,
                kdf_memory_kib: NotSet,
                kdf_iterations: NotSet,
                kdf_parallelism: NotSet,
                kdf_salt: NotSet,
                opaque_record: NotSet,
                wrapped_root_key: NotSet,
                public_bundle: NotSet,
                bundle_signature: NotSet,
                sealed_private_keys: NotSet,
                key_version: NotSet,
                security_stamp: Set(stamp),
                created_at: NotSet,
                updated_at: Set(utc(a.updated_at)),
            })
            .filter(users::Column::Id.eq(id))
            .exec(txn)
            .await
            .store()?;
    } else {
        // Like a Bitwarden registration: the Kemlock side is empty until its owner enrols OPAQUE.
        let user = User {
            id: a.id,
            email,
            name,
            mode: AccountMode::Compatible,
            role: Role::User,
            kdf: KdfParams::new_account(*Uuid::new_v4().as_bytes()),
            opaque_record: None,
            wrapped_root_key: Vec::new(),
            public_bundle: Vec::new(),
            bundle_signature: Vec::new(),
            sealed_private_keys: Vec::new(),
            key_version: 0,
            security_stamp: stamp,
            created_at: a.created_at,
            updated_at: a.updated_at,
        };
        users::Entity::insert(users::active(&user))
            .exec(txn)
            .await
            .store()?;
    }

    let account = BwAccount {
        user: a.id,
        password_hash: b.password_hash.clone(),
        salt: b.salt.clone(),
        password_iterations: u32::try_from(b.password_iterations).map_err(|_| {
            invalid(format!(
                "the password iterations of the user {id} are out of range"
            ))
        })?,
        kdf_type: to_i32(b.client_kdf_type, "KDF type")?,
        kdf_iterations: to_i32(b.client_kdf_iter, "KDF iterations")?,
        kdf_memory: opt_i32(b.client_kdf_memory, "KDF memory")?,
        kdf_parallelism: opt_i32(b.client_kdf_parallelism, "KDF parallelism")?,
        akey: b.akey.clone(),
        private_key: b.private_key.clone(),
        public_key: b.public_key.clone(),
        password_hint: b.password_hint.clone(),
        api_key: b.api_key.clone(),
        avatar_color: b.avatar_color.clone(),
        revision_ms: now_ms(ctx),
    };
    if bw_accounts::Entity::find_by_id(id)
        .one(txn)
        .await
        .store()?
        .is_some()
    {
        // The revision date only moves at the end of the pass.
        bw_accounts::Entity::update_many()
            .set(bw_accounts::ActiveModel {
                user_id: NotSet,
                revision_ms: NotSet,
                ..bw_accounts::active(&account)
            })
            .filter(bw_accounts::Column::UserId.eq(id))
            .exec(txn)
            .await
            .store()?;
    } else {
        bw_accounts::Entity::insert(bw_accounts::active(&account))
            .exec(txn)
            .await
            .store()?;
    }

    let seal = |text: &Option<String>| {
        text.as_ref()
            .map(|t| ctx.seal.seal(PURPOSE_ACCOUNT, t.as_bytes()))
    };
    bw_account_extras::Entity::delete_many()
        .filter(bw_account_extras::Column::UserId.eq(id))
        .exec(txn)
        .await
        .store()?;
    bw_account_extras::Entity::insert(bw_account_extras::ActiveModel {
        user_id: Set(id),
        enabled: Set(b.enabled),
        verified_at: Set(b.verified_at.map(utc)),
        last_verifying_at: Set(b.last_verifying_at.map(utc)),
        login_verify_count: Set(b.login_verify_count),
        email_new: Set(b.email_new.clone()),
        email_new_token: Set(b.email_new_token.clone()),
        stamp_exception: Set(b.stamp_exception.clone()),
        equivalent_domains: Set(b.equivalent_domains.clone()),
        excluded_globals: Set(b.excluded_globals.clone()),
        external_id: Set(b.external_id.clone()),
        key_id: Set(b.key_id.clone()),
        sealed_totp_secret: Set(seal(&b.totp_secret)),
        sealed_totp_recover: Set(seal(&b.totp_recover)),
        vw_security_stamp: Set(b.security_stamp.clone()),
    })
    .exec(txn)
    .await
    .store()?;
    Ok(())
}

/// A refresh token Vaultwarden kept in a device row: base64url (padded or not) of 32 or 64 bytes.
fn refresh_bytes(text: &str) -> Option<Vec<u8>> {
    let raw = b64url::decode(text.trim().trim_end_matches('='))?;
    matches!(raw.len(), 32 | 64).then_some(raw)
}

/// Devices become Bitwarden devices, so the access tokens they hold (signed with the carried
/// `rsa_key.pem`) still name a device; their refresh tokens are kept by hash.
pub(super) async fn put_devices(ctx: &Ctx, table: &Table) -> Res<()> {
    let txn = &ctx.txn;
    for row in table.rows() {
        let (Some(id), Some(user)) = (row_uuid(row.text("uuid")), row_uuid(row.text("user_uuid")))
        else {
            continue;
        };
        let Some(user_row) = users::Entity::find_by_id(user).one(txn).await.store()? else {
            continue;
        };
        let existing = devices::Entity::find_by_id(id).one(txn).await.store()?;
        // Vaultwarden keys a device by (id, user); here the id is the key, so a second user of
        // one device id is left out.
        if existing.as_ref().is_some_and(|d| d.user_id != user) {
            continue;
        }
        let created = row_time(row.text("created_at")).unwrap_or(ctx.opts.now);
        let seen = row_time(row.text("updated_at")).unwrap_or(created);
        let device = Device {
            id: DeviceId(id),
            user: UserId(user),
            name: Device::clean_name(row.text("name").unwrap_or_default()),
            kind: DeviceKind::Bitwarden,
            dpop_jkt: None,
            created_at: created,
            last_seen_at: seen,
        };
        if existing.is_some() {
            devices::Entity::update_many()
                .set(devices::ActiveModel {
                    id: NotSet,
                    ..devices::active(&device)
                })
                .filter(devices::Column::Id.eq(id))
                .exec(txn)
                .await
                .store()?;
        } else {
            devices::Entity::insert(devices::active(&device))
                .exec(txn)
                .await
                .store()?;
        }

        if let Some(raw) = row.text("refresh_token").and_then(refresh_bytes) {
            let hash = kemlock_crypto::hash::sha256(&raw);
            refresh_tokens::Entity::delete_many()
                .filter(refresh_tokens::Column::Hash.eq(hash.to_vec()))
                .exec(txn)
                .await
                .store()?;
            let token = RefreshToken {
                hash,
                family: id,
                user: UserId(user),
                device: DeviceId(id),
                security_stamp: user_row.security_stamp,
                created_at: created,
                expires_at: ctx.opts.now + time::Duration::days(REFRESH_DAYS),
                used_at: None,
            };
            refresh_tokens::Entity::insert(refresh_tokens::active(&token))
                .exec(txn)
                .await
                .store()?;
        }
    }
    Ok(())
}

/// RFC 4648 base32 as authenticator apps print it: any case, padding and spaces ignored.
fn base32_decode(text: &str) -> Option<Vec<u8>> {
    let mut buffer: u32 = 0;
    let mut bits: u32 = 0;
    let mut out = Vec::new();
    for c in text.chars() {
        if c == '=' || c == '-' || c.is_whitespace() {
            continue;
        }
        let c = c.to_ascii_uppercase();
        let value = match c {
            'A'..='Z' => u32::from(c) - u32::from('A'),
            '2'..='7' => u32::from(c) - u32::from('2') + 26,
            _ => return None,
        };
        buffer = (buffer << 5) | value;
        bits += 5;
        if bits >= 8 {
            bits -= 8;
            out.push(((buffer >> bits) & 0xFF) as u8);
            buffer &= (1 << bits) - 1;
        }
    }
    (!out.is_empty()).then_some(out)
}

pub(super) async fn put_twofactor(ctx: &Ctx, table: &Table) -> Res<()> {
    let users: BTreeSet<Uuid> = table
        .rows()
        .filter_map(|row| row_uuid(row.text("user_uuid")))
        .collect();
    rebuild_two_factor(ctx, &users).await
}

/// A setup read from the stored rows of one account, before it is written.
#[derive(Default)]
struct Setups {
    totp: Option<(Vec<u8>, bool, i64)>,
    email: Option<String>,
    duo: Option<String>,
    yubikey: Option<String>,
    webauthn: Option<String>,
    u2f: Option<String>,
}

impl Setups {
    /// What the account's stored `twofactor` rows hold.
    fn read(stored: &[(String, Value)], user: Uuid) -> Setups {
        let mut out = Setups::default();
        for (_, row) in stored {
            if row_uuid(rows::text(row, "user_uuid")) != Some(user) {
                continue;
            }
            let kind = row.get("atype").and_then(Value::as_i64).unwrap_or(-1);
            let enabled = row.get("enabled").and_then(Value::as_i64) != Some(0);
            let data = rows::text(row, "data").unwrap_or_default();
            match kind {
                TYPE_AUTHENTICATOR => {
                    if let Some(secret) = base32_decode(data) {
                        let last = row.get("last_used").and_then(Value::as_i64).unwrap_or(0);
                        out.totp = Some((secret, enabled, last));
                    }
                }
                // What can't be read is kept as it is, so the account has a second step that
                // fails to open rather than none: it is never let in without.
                TYPE_EMAIL if enabled => {
                    out.email = Some(two_step::email_data(data).unwrap_or_else(|| data.to_owned()));
                }
                TYPE_DUO if enabled => out.duo = Some(two_step::duo_data(data)),
                TYPE_YUBIKEY if enabled => {
                    out.yubikey =
                        Some(two_step::yubikey_data(data).unwrap_or_else(|| data.to_owned()));
                }
                TYPE_U2F if enabled => out.u2f = Some(data.to_owned()),
                TYPE_WEBAUTHN if enabled => out.webauthn = Some(data.to_owned()),
                _ => {}
            }
        }
        out
    }

    /// The account's security keys as the list `SecurityKeys` seals: its WebAuthn registrations
    /// and its legacy U2F ones. When it has setups of those kinds but none can be read, the raw
    /// data (which no one can open as a list), so the account stays closed.
    fn security_keys(&self) -> Option<Vec<u8>> {
        if self.webauthn.is_none() && self.u2f.is_none() {
            return None;
        }
        let keys: Vec<ImportedKey> =
            two_step::security_keys(self.webauthn.as_deref(), self.u2f.as_deref())
                .into_iter()
                .map(|k| ImportedKey {
                    slot: k.slot,
                    name: k.name,
                    credential_id: k.credential_id,
                    credential: k.credential,
                })
                .collect();
        Some(encode_key_list(&keys).unwrap_or_else(|| {
            let raw = format!(
                "{}{}",
                self.webauthn.as_deref().unwrap_or_default(),
                self.u2f.as_deref().unwrap_or_default()
            );
            raw.into_bytes()
        }))
    }
}

/// Rebuilds the `two_factor` rows of `users` from the stored Vaultwarden rows, one per method,
/// each sealed under `server.key` with the purpose its use case opens it with:
///
/// - an authenticator app (type 0) becomes a `totp` row holding the decoded secret;
/// - email (1), Duo (2) and a YubiKey (3) become `email`, `duo` and `yubikey` rows holding
///   Vaultwarden's own JSON, so the address, the account's Duo keys and the key ids stay;
/// - WebAuthn (7) and legacy U2F (4) registrations become one `webauthn` row, a list of security
///   keys whose credentials the WebAuthn relying party reads (a U2F key keeps the key handle as its
///   credential id, which the relying party's `appid` extension answers for).
///
/// The Duo integration an account without keys of its own uses, and Yubico's, are server settings
/// (`DUO_*`, `YUBICO_*`, or `config.json`), not part of any row.
pub(super) async fn rebuild_two_factor(ctx: &Ctx, users: &BTreeSet<Uuid>) -> Res<()> {
    if users.is_empty() {
        return Ok(());
    }
    let txn = &ctx.txn;
    let stored = rows::all_rows(ctx, "twofactor").await?;
    for user in users {
        if users::Entity::find_by_id(*user)
            .one(txn)
            .await
            .store()?
            .is_none()
        {
            continue;
        }
        let setups = Setups::read(&stored, *user);

        two_factor::Entity::delete_many()
            .filter(two_factor::Column::UserId.eq(*user))
            .exec(txn)
            .await
            .store()?;
        if let Some((secret, enabled, last)) = &setups.totp {
            insert(
                ctx,
                *user,
                TwoFactorMethod::Totp,
                PURPOSE_TOTP,
                secret,
                *enabled,
                (*last > 0).then_some(*last),
            )
            .await?;
        }
        let plain_rows = [
            (TwoFactorMethod::Email, PURPOSE_EMAIL, &setups.email),
            (TwoFactorMethod::Duo, PURPOSE_DUO, &setups.duo),
            (TwoFactorMethod::YubiKey, PURPOSE_YUBIKEY, &setups.yubikey),
        ];
        for (method, purpose, data) in plain_rows {
            if let Some(data) = data {
                insert(ctx, *user, method, purpose, data.as_bytes(), true, None).await?;
            }
        }
        if let Some(list) = setups.security_keys() {
            insert(
                ctx,
                *user,
                TwoFactorMethod::WebAuthn,
                PURPOSE_WEBAUTHN,
                &list,
                true,
                None,
            )
            .await?;
        }
    }
    Ok(())
}

/// Writes one sealed `two_factor` row.
async fn insert(
    ctx: &Ctx,
    user: Uuid,
    method: TwoFactorMethod,
    purpose: &str,
    plain: &[u8],
    enabled: bool,
    last_used_step: Option<i64>,
) -> Res<()> {
    two_factor::Entity::insert(two_factor::ActiveModel {
        user_id: Set(user),
        method: Set(two_factor::method_str(method).to_owned()),
        sealed_secret: Set(ctx.seal.seal(purpose, plain)),
        enabled: Set(enabled),
        last_used_step: Set(last_used_step),
        created_at: Set(ctx.opts.now),
    })
    .exec(&ctx.txn)
    .await
    .store()?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn base32_matches_rfc4648_vectors() {
        assert_eq!(base32_decode("MY"), Some(b"f".to_vec()));
        assert_eq!(base32_decode("MZXW6YTB"), Some(b"fooba".to_vec()));
        assert_eq!(
            base32_decode("mzxw 6ytb oi======"),
            Some(b"foobar".to_vec())
        );
        assert_eq!(base32_decode("not base32!"), None);
        assert_eq!(base32_decode(""), None);
    }

    #[test]
    fn stamps_become_uuids() {
        let id = "3785303e-d4f8-4724-be0a-6c3599471ffe";
        assert_eq!(stamp_uuid(id).to_string(), id);
        assert_eq!(stamp_uuid("stamp-alice"), stamp_uuid("stamp-alice"));
        assert_ne!(stamp_uuid("stamp-alice"), stamp_uuid("stamp-bob"));
    }

    #[test]
    fn refresh_tokens_are_32_or_64_bytes_of_base64url() {
        let thirty_two = b64url::encode(&[7u8; 32]);
        let sixty_four = b64url::encode(&[7u8; 64]);
        assert_eq!(refresh_bytes(&thirty_two), Some(vec![7u8; 32]));
        assert_eq!(refresh_bytes(&sixty_four), Some(vec![7u8; 64]));
        // Vaultwarden's own encoder pads.
        assert_eq!(
            refresh_bytes(&format!("{sixty_four}==")),
            Some(vec![7u8; 64])
        );
        assert_eq!(refresh_bytes(&b64url::encode(&[7u8; 20])), None);
        assert_eq!(refresh_bytes("not a token"), None);
    }
}
