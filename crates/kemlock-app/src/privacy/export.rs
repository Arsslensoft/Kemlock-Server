//! Export account: the server's record of one account as JSON, plus its encrypted vault as stored
//! (GDPR Art. 15, CCPA right to know). The web vault's "Download my data" and the admin console's
//! export for a request run this same use case.
//!
//! The document holds the profile, the devices, the sign-in log, the events whose actor is the
//! account, its place in spaces, its two-step methods (without secrets) and every item of its own
//! vault with its ciphertext and wrapped item key, exactly as the server keeps them. The server
//! can't read inside the vault, so nothing is decrypted or searched. The OPAQUE record and the
//! sealed two-step secrets are left out: they are verifiers the server uses, not data the person
//! gave it.

use super::Requester;
use super::ports::{AccountData, PrivacyLog};
use crate::b64url;
use crate::error::AppError;
use crate::ports::{Clock, Event, UserRepo};
use kemlock_domain::UserId;
use serde_json::{Value, json};
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;

/// The format name inside the document, for whoever reads it later.
pub const EXPORT_FORMAT: &str = "kemlock-account-export/1";

/// The export document and a file name to offer it under.
#[derive(Clone, Debug, PartialEq)]
pub struct AccountExport {
    pub document: Value,
    pub file_name: String,
}

impl AccountExport {
    /// The document as indented JSON text.
    pub fn to_json_string(&self) -> String {
        serde_json::to_string_pretty(&self.document).unwrap_or_default()
    }
}

pub(crate) fn iso(time: OffsetDateTime) -> String {
    time.format(&Rfc3339).unwrap_or_default()
}

fn iso_opt(time: Option<OffsetDateTime>) -> Value {
    time.map_or(Value::Null, |t| Value::String(iso(t)))
}

#[derive(Debug)]
pub struct ExportAccount<U, D, L, C> {
    pub users: U,
    pub data: D,
    pub log: L,
    pub clock: C,
}

impl<U: UserRepo, D: AccountData, L: PrivacyLog, C: Clock> ExportAccount<U, D, L, C> {
    /// Collects the record of `user`. `requested_by` is the account itself or the admin acting on
    /// its request; either way the export is written to the event log.
    pub async fn execute(
        &self,
        user: UserId,
        requested_by: Requester,
    ) -> Result<AccountExport, AppError> {
        let account = self.users.by_id(user).await?.ok_or(AppError::NotFound)?;
        let now = self.clock.now();

        let devices = self.data.devices(user).await?;
        let vault = self.data.vault(user).await?;
        let memberships = self.data.memberships(user).await?;
        let two_factor = self.data.two_factor(user).await?;
        let events = self.log.events_of(user).await?;
        let sign_ins = self.log.sign_ins_of(user).await?;

        let document = json!({
            "format": EXPORT_FORMAT,
            "exportedAt": iso(now),
            "account": {
                "id": account.id.to_string(),
                "email": account.email.as_str(),
                "name": account.name,
                "mode": serde_json::to_value(account.mode).unwrap_or(Value::Null),
                "role": serde_json::to_value(account.role).unwrap_or(Value::Null),
                "kdf": {
                    "memoryKib": account.kdf.memory_kib,
                    "iterations": account.kdf.iterations,
                    "parallelism": account.kdf.parallelism,
                    "salt": b64url::encode(&account.kdf.salt),
                },
                "keyVersion": account.key_version,
                "wrappedRootKey": b64url::encode(&account.wrapped_root_key),
                "publicBundle": b64url::encode(&account.public_bundle),
                "bundleSignature": b64url::encode(&account.bundle_signature),
                "sealedPrivateKeys": b64url::encode(&account.sealed_private_keys),
                "createdAt": iso(account.created_at),
                "updatedAt": iso(account.updated_at),
            },
            "devices": devices.iter().map(|d| json!({
                "id": d.id.to_string(),
                "name": d.name,
                "kind": serde_json::to_value(d.kind).unwrap_or(Value::Null),
                "createdAt": iso(d.created_at),
                "lastSeenAt": iso(d.last_seen_at),
            })).collect::<Vec<_>>(),
            "twoFactor": two_factor.iter().map(|t| json!({
                "method": t.method,
                "enabled": t.enabled,
                "createdAt": iso(t.created_at),
            })).collect::<Vec<_>>(),
            "signIns": sign_ins.iter().map(|s| json!({
                "at": iso(s.at),
                "method": s.method,
                "outcome": s.outcome.as_str(),
                "device": s.device.map(|d| d.to_string()),
                "ip": s.ip,
            })).collect::<Vec<_>>(),
            "events": events.iter().map(|e| json!({
                "at": iso(e.at),
                "action": e.action,
                "target": e.target,
                "device": e.device.map(|d| d.to_string()),
                "ip": e.ip,
            })).collect::<Vec<_>>(),
            "spaces": memberships.iter().map(|m| json!({
                "space": m.space.to_string(),
                "role": m.role.as_str(),
                "state": m.state.as_str(),
                "invitedAt": iso(m.invited_at),
                "acceptedAt": iso_opt(m.accepted_at),
                "revokedAt": iso_opt(m.revoked_at),
                "keyVersion": m.key_version,
                "sealedSpaceKey": m.sealed_space_key.as_deref().map(b64url::encode),
            })).collect::<Vec<_>>(),
            "vault": {
                "note": "Items are sealed on your devices; the server holds only this ciphertext and cannot read it.",
                "items": vault.iter().map(|i| json!({
                    "id": i.id.to_string(),
                    "kind": i.kind.as_str(),
                    "format": i.format.as_str(),
                    "revision": i.revision.0,
                    "keyVersion": i.key_version,
                    "ciphertext": i.ciphertext.as_deref().map(b64url::encode),
                    "itemKey": i.item_key.as_deref().map(b64url::encode),
                    "deletedAt": iso_opt(i.deleted_at),
                    "updatedAt": iso(i.updated_at),
                })).collect::<Vec<_>>(),
            },
        });

        let (actor, target) = match requested_by {
            Requester::Account => (user, None),
            Requester::Admin(admin) => (admin, Some(user.to_string())),
            // The retention job never exports; if it ever did, the log names the account.
            Requester::Retention => (user, None),
        };
        // The export has happened; a log that can't be written must not take it back.
        let event = Event {
            actor: Some(actor),
            device: None,
            action: "account.export",
            target,
            at: now,
        };
        if let Err(e) = self.log.record_event(event, None).await {
            tracing::warn!(error = %e, "couldn't record an account export");
        }

        Ok(AccountExport {
            document,
            file_name: format!(
                "kemlock-account-{}-{:04}{:02}{:02}.json",
                user,
                now.year(),
                u8::from(now.month()),
                now.day()
            ),
        })
    }
}
