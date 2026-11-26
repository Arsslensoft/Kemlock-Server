//! Signed item writes (`docs/crypto.md`, "Signed item writes") in the worker: signing a write with
//! the unlocked account's `sig1` key and checking the signature of one, so the page never holds a
//! signing key.
//!
//! - **Signing** takes the fields of a write (what the server is sent, minus the signature) and
//!   signs the statement rebuilt from them, under context `"item-write"`, as the unlocked account
//!   at its key version. It signs for the account's own vault or a space, never for another
//!   person's vault, and only a statement of this exact layout, so the key that signs the
//!   account's bundle can't be driven to sign arbitrary bytes.
//! - **Checking an account's own write** uses the public key of the account's own `sig1` private
//!   key, never a bundle the server served.
//! - **Checking another member's write** uses their bundle, which the page has already checked
//!   against what the space knows of its members (the space chain once that is verified).

use kemlock_crypto::{
    item_write::{self, Statement},
    owner::{Owner, OwnerKind},
};
use serde::{Deserialize, Serialize};

use crate::{b64, error::Error, ids, session::Session};

/// The fields of a write: what the statement is rebuilt from.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct WriteFields {
    owner: String,
    id: String,
    kind: String,
    revision: u64,
    deleted: bool,
    /// The key version the item carries (a collection's, for an item of a space).
    key_version: u32,
    #[serde(default)]
    ciphertext: Option<String>,
    #[serde(default)]
    item_key: Option<String>,
    /// To check only: the account that wrote, and the key version of the bundle that signed.
    #[serde(default)]
    writer: Option<String>,
    #[serde(default)]
    writer_key_version: Option<u32>,
}

/// What signing answers: the writer, its key version and the signature, as the server takes them.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct WriteSigned {
    pub(crate) writer: String,
    pub(crate) writer_key_version: u32,
    pub(crate) write_signature: String,
}

/// What a statement is made of besides the writer.
struct Parts {
    owner: Owner,
    id: [u8; 16],
    envelope: [u8; 32],
}

impl WriteFields {
    /// Parses a JSON object of fields; anything else is invalid.
    pub(crate) fn parse(json: &str) -> Result<WriteFields, Error> {
        serde_json::from_str(json).map_err(|_| Error::Invalid)
    }

    fn parts(&self) -> Result<Parts, Error> {
        let sealed = match (self.deleted, &self.ciphertext, &self.item_key) {
            (false, Some(ciphertext), Some(item_key)) => {
                Some((b64::decode(ciphertext)?, b64::decode(item_key)?))
            }
            (true, None, None) => None,
            _ => return Err(Error::Invalid),
        };
        let envelope = item_write::envelope_hash(
            self.key_version,
            sealed
                .as_ref()
                .map(|(ciphertext, item_key)| (ciphertext.as_slice(), item_key.as_slice())),
        )?;
        Ok(Parts {
            owner: ids::parse_owner(&self.owner)?,
            id: ids::parse_uuid(&self.id)?,
            envelope,
        })
    }

    fn statement<'a>(
        &'a self,
        parts: &Parts,
        writer: [u8; 16],
        writer_key_version: u32,
    ) -> Statement<'a> {
        Statement {
            owner: parts.owner,
            item_id: parts.id,
            kind: &self.kind,
            revision: self.revision,
            deleted: self.deleted,
            envelope: parts.envelope,
            writer,
            writer_key_version,
        }
    }

    /// The writer and key version a signature to check names.
    fn named_writer(&self) -> Result<([u8; 16], u32), Error> {
        let writer = self.writer.as_deref().ok_or(Error::Invalid)?;
        Ok((
            ids::parse_uuid(writer)?,
            self.writer_key_version.ok_or(Error::Invalid)?,
        ))
    }
}

impl Session {
    /// Signs the write `fields` as the unlocked account, at its key version. Fails unless the
    /// owner is this account's own vault or a space.
    pub(crate) fn sign_item_write(&self, fields: &WriteFields) -> Result<WriteSigned, Error> {
        let unlocked = self.unlocked()?;
        let parts = fields.parts()?;
        if parts.owner.kind() == OwnerKind::User && parts.owner != Owner::user(unlocked.account_id)
        {
            return Err(Error::Invalid);
        }
        let (_, sig_private) = unlocked.private.as_ref().ok_or(Error::Locked)?;
        let statement = fields.statement(&parts, unlocked.account_id, unlocked.key_version);
        let signature = statement.sign(sig_private)?;
        Ok(WriteSigned {
            writer: uuid_text(&unlocked.account_id),
            writer_key_version: unlocked.key_version,
            write_signature: b64::encode(&signature),
        })
    }

    /// Checks that `signature` is this account's own `sig1` signature of the write `fields`,
    /// which must name this account as the writer at its key version. The key is the one of the
    /// account's own private key, so the unlock has to have opened it.
    pub(crate) fn verify_own_item_write(
        &self,
        fields: &WriteFields,
        signature: &[u8],
    ) -> Result<(), Error> {
        let unlocked = self.unlocked()?;
        let (_, sig_private) = unlocked.private.as_ref().ok_or(Error::Locked)?;
        let (writer, version) = fields.named_writer()?;
        if writer != unlocked.account_id || version != unlocked.key_version {
            return Err(Error::Invalid);
        }
        let parts = fields.parts()?;
        let public = sig_private.public_key()?;
        fields
            .statement(&parts, writer, version)
            .verify(&public, signature)?;
        Ok(())
    }
}

/// Checks that `signature` is the signature of the write `fields` by the account whose bundle is
/// `signer_bundle`, at the bundle's key version. Public data only, so it needs no session.
pub(crate) fn verify_item_write(
    signer_bundle: &[u8],
    fields: &WriteFields,
    signature: &[u8],
) -> Result<(), Error> {
    let (writer, version) = fields.named_writer()?;
    let parts = fields.parts()?;
    item_write::verify_with_bundle(&fields.statement(&parts, writer, version), signer_bundle, signature)?;
    Ok(())
}

/// A UUID in its hyphenated lower-case form.
fn uuid_text(id: &[u8; 16]) -> String {
    let hex: String = id.iter().map(|b| format!("{b:02x}")).collect();
    format!(
        "{}-{}-{}-{}-{}",
        &hex[..8],
        &hex[8..12],
        &hex[12..16],
        &hex[16..20],
        &hex[20..]
    )
}
