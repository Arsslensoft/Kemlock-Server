//! Attachments, the v2 way: open a slot (`POST …/attachment/v2`), upload one `data` part to it,
//! download from a link on this server's own host, delete.
//!
//! The attachment's record lives in its cipher's document, so adding or removing one writes the
//! cipher (the change log moves, and so does the account's revision date) but leaves the cipher's
//! own `revisionDate` alone, as Vaultwarden does. The bytes go through the [`BlobStore`] under
//! `<cipher id>/<attachment id>`.
//!
//! An organization cipher takes attachments by the same rules and the same blob keys as a personal
//! one; what differs is who may (the cipher must be writable to the caller, readable to see one),
//! that every member's revision date moves, and that adding and removing one are events of the
//! organization.
//!
//! [`BlobStore`]: crate::blob::BlobStore

use crate::app::{App, Authed, BwStore};
use crate::cipher::{StoredAttachment, StoredCipher, attachment_json};
use crate::env::random_hex;
use crate::error::{BwError, BwResult};
use crate::events::{Acting, kind, log_event};
use crate::orgs::ciphers::{OrgLoaded, org_cipher, org_save_quietly, org_view};
use crate::tokens::FileDownloadClaims;
use crate::vault::{Loaded, save_quietly};
use kemlock_app::bw_events::Change;
use kemlock_app::quota::check;
use serde::Deserialize;
use serde_json::{Value, json};

/// Vaultwarden's largest file: 525 MB, which is also its upload limit.
pub(crate) const MAX_FILE_SIZE: i64 = 550_502_400;

/// How far the uploaded size may differ from the one declared: 1 MiB, as in Vaultwarden.
const LEEWAY: i64 = 1024 * 1024;

/// A size the client sends as a number or as text.
#[derive(Debug, Clone, Deserialize)]
#[serde(untagged)]
pub(crate) enum NumberOrString {
    Number(i64),
    Text(String),
}

impl NumberOrString {
    fn as_i64(&self) -> BwResult<i64> {
        match self {
            NumberOrString::Number(n) => Ok(*n),
            NumberOrString::Text(s) => s
                .trim()
                .parse()
                .map_err(|_| BwError::msg("Can't convert to number")),
        }
    }
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct AttachmentRequest {
    pub key: String,
    pub file_name: String,
    pub file_size: NumberOrString,
    pub admin_request: Option<bool>,
}

/// Attachment ids are 1 to 64 letters and digits; anything else can't be one of ours.
fn valid_attachment_id(id: &str) -> bool {
    (1..=64).contains(&id.len()) && id.bytes().all(|b| b.is_ascii_alphanumeric())
}

fn blob_key(cipher: &str, attachment: &str) -> String {
    format!("{cipher}/{attachment}")
}

/// How much of a cipher an attachment call needs.
#[derive(Clone, Copy)]
enum Access {
    /// `is_accessible_to_user`.
    Read,
    /// `is_write_accessible_to_user`.
    Write,
}

/// The cipher an attachment belongs to: an account's own, or an organization's. The two keep the
/// attachment's record in the cipher's document and its bytes under the same blob key, so the rules
/// are the same; they differ in who may touch the cipher and in how the change is written.
// One lives per request, on the stack: boxing either variant only moves the warning.
#[allow(clippy::large_enum_variant)]
enum Target {
    Personal(Loaded),
    Org(OrgLoaded),
}

impl Target {
    /// The cipher `id` as the caller may use it. `denied` is the message for an organization
    /// cipher the caller can't reach in the way `access` asks.
    async fn load<S: BwStore>(
        app: &App<S>,
        authed: &Authed,
        id: &str,
        access: Access,
        denied: &str,
    ) -> BwResult<Target> {
        let user = authed.user.id;
        if let Some(loaded) = org_cipher(app, user, id).await? {
            let allowed = match access {
                Access::Read => loaded.restrict.is_some(),
                Access::Write => loaded.restrict.is_some_and(|r| r.writable()),
            };
            if !allowed {
                return Err(BwError::msg(denied));
            }
            return Ok(Target::Org(loaded));
        }
        Ok(Target::Personal(app.load_cipher(user, id).await?))
    }

    fn cipher(&self) -> &StoredCipher {
        match self {
            Target::Personal(l) => &l.cipher,
            Target::Org(l) => &l.cipher,
        }
    }

    fn cipher_mut(&mut self) -> &mut StoredCipher {
        match self {
            Target::Personal(l) => &mut l.cipher,
            Target::Org(l) => &mut l.cipher,
        }
    }

    /// Writes the cipher with its attachments as they are now, and moves the revision date of
    /// whoever sees it; the cipher's own `revisionDate` stays.
    async fn save<S: BwStore>(&self, app: &App<S>, authed: &Authed) -> BwResult<()> {
        match self {
            Target::Personal(l) => save_quietly(app, authed.user.id, l).await,
            Target::Org(l) => org_save_quietly(app, l).await,
        }
    }

    /// Tells the live channels the cipher changed: its owner's clients, or an organization's
    /// members who can see it.
    fn changed<S: BwStore>(&self, app: &App<S>, authed: &Authed) {
        match self {
            Target::Personal(l) => {
                app.cipher_changed(authed, Change::Updated, &l.cipher.id, app.now());
            }
            Target::Org(l) => {
                app.org_cipher_changed(
                    authed,
                    Change::Updated,
                    &l.org,
                    &l.cipher.id,
                    &l.links,
                    false,
                );
            }
        }
    }

    /// The cipher as the caller sees it.
    async fn json<S: BwStore>(&self, app: &App<S>, authed: &Authed) -> BwResult<Value> {
        match self {
            Target::Personal(l) => app.cipher_to_json(&l.cipher),
            Target::Org(l) => org_view(app, authed, l).await,
        }
    }

    /// Logs an event about the cipher when it is an organization's.
    async fn log<S: BwStore>(&self, app: &App<S>, authed: &Authed, event_type: i32) {
        if let Target::Org(l) = self {
            log_event(
                app,
                event_type,
                &l.cipher.id,
                l.org.id.0,
                &Acting::of(authed),
            )
            .await;
        }
    }
}

impl Target {
    /// The storage quota that governs this cipher's attachments (Vaultwarden's
    /// `USER_ATTACHMENT_LIMIT` for a personal cipher, `ORG_ATTACHMENT_LIMIT` for an organization's),
    /// with what its owner stores already; `None` when no quota is set, so nothing is counted.
    async fn quota<S: BwStore>(
        &self,
        app: &App<S>,
        authed: &Authed,
    ) -> BwResult<Option<(u64, u64)>> {
        let live = app.settings.live.as_ref();
        let (limit, used) = match self {
            Target::Personal(_) => {
                let Some(limit) = live.and_then(|l| l.user_attachment_limit()) else {
                    return Ok(None);
                };
                (
                    limit,
                    crate::vault::attachment_bytes(app, authed.user.id).await?,
                )
            }
            Target::Org(l) => {
                let Some(limit) = live.and_then(|l| l.space_attachment_limit()) else {
                    return Ok(None);
                };
                (
                    limit,
                    crate::orgs::ciphers::attachment_bytes(app, l.org.id).await?,
                )
            }
        };
        Ok(Some((limit, used)))
    }
}

/// Refuses a file the owner's quota has no room for, in Vaultwarden's words. `used` is what the
/// owner stores, less the slot this file is for when it already counts.
fn check_quota(quota: Option<(u64, u64)>, size: i64, slot: i64) -> BwResult<()> {
    let Some((limit, used)) = quota else {
        return Ok(());
    };
    let used = used.saturating_sub(u64::try_from(slot).unwrap_or(0));
    let size = u64::try_from(size).unwrap_or(0);
    check(Some(limit), used, size).map_err(|refusal| BwError::msg(refusal.attachment_message()))
}

fn find_attachment<'a>(cipher: &'a StoredCipher, id: &str) -> BwResult<&'a StoredAttachment> {
    cipher
        .attachments
        .iter()
        .find(|a| a.id == id)
        .ok_or_else(|| BwError::msg("Attachment doesn't exist"))
}

/// `POST /api/ciphers/{id}/attachment/v2`: records the attachment and says where to send it.
pub(crate) async fn create_attachment<S: BwStore>(
    app: &App<S>,
    authed: &Authed,
    cipher_id: &str,
    request: AttachmentRequest,
) -> BwResult<Value> {
    // The quota's sum and the slot it admits are one step: no other announce reads between them.
    let _gate = app.quota_gate.lock().await;
    let mut target = Target::load(
        app,
        authed,
        cipher_id,
        Access::Write,
        "Cipher is not write accessible",
    )
    .await?;
    let size = request.file_size.as_i64()?;
    if size < 0 {
        return Err(BwError::msg("Attachment size can't be negative"));
    }
    if size > MAX_FILE_SIZE {
        return Err(BwError::msg("Max file size is 525 MB."));
    }
    check_quota(target.quota(app, authed).await?, size, 0)?;

    let id = random_hex::<10>(app.env.as_ref());
    target.cipher_mut().attachments.push(StoredAttachment {
        id: id.clone(),
        file_name: request.file_name,
        size,
        key: Some(request.key),
    });
    target.save(app, authed).await?;
    target
        .log(app, authed, kind::CIPHER_ATTACHMENT_CREATED)
        .await;

    let response_key = if request.admin_request == Some(true) {
        "cipherMiniResponse"
    } else {
        "cipherResponse"
    };
    let mut out = json!({
        "object": "attachment-fileUpload",
        "attachmentId": id,
        "url": format!("/ciphers/{}/attachment/{id}", target.cipher().id),
        "fileUploadType": 0,
    });
    out[response_key] = target.json(app, authed).await?;
    Ok(out)
}

/// `POST /api/ciphers/{id}/attachment/{attachmentId}`: the file. Its size must be within 1 MiB of
/// what was declared, and then it is the size the cipher shows.
pub(crate) async fn upload_attachment<S: BwStore>(
    app: &App<S>,
    authed: &Authed,
    cipher_id: &str,
    attachment_id: &str,
    data: Vec<u8>,
) -> BwResult<()> {
    if !valid_attachment_id(attachment_id) {
        return Err(BwError::NotFound);
    }
    let mut target = Target::load(
        app,
        authed,
        cipher_id,
        Access::Write,
        "Cipher is not write accessible",
    )
    .await
    .map_err(|e| match e {
        BwError::Msg(text) if text == "Cipher doesn't exist" => {
            BwError::msg("Attachment doesn't exist")
        }
        other => other,
    })?;
    let declared = find_attachment(target.cipher(), attachment_id)?.size;
    let size =
        i64::try_from(data.len()).map_err(|_| BwError::msg("Attachment data size overflow"))?;
    // A quota that was lowered since the slot was opened refuses the bytes. Vaultwarden's
    // `save_attachment` leaves the slot where it is (only a size mismatch deletes it), so it stays.
    check_quota(target.quota(app, authed).await?, size, declared)?;

    let (min, max) = (
        declared.saturating_sub(LEEWAY),
        declared.saturating_add(LEEWAY),
    );
    if !(min..=max).contains(&size) {
        // The slot was opened for a file this isn't: it goes, and the upload is refused.
        target
            .cipher_mut()
            .attachments
            .retain(|a| a.id != attachment_id);
        target.save(app, authed).await?;
        return Err(BwError::msg(format!(
            "Attachment size mismatch (expected within [{min}, {max}], got {size})"
        )));
    }

    app.blobs
        .put(&blob_key(&target.cipher().id, attachment_id), data)
        .await
        .map_err(|e| BwError::Server(e.to_string()))?;
    if size != declared {
        if let Some(attachment) = target
            .cipher_mut()
            .attachments
            .iter_mut()
            .find(|a| a.id == attachment_id)
        {
            attachment.size = size;
        }
        target.save(app, authed).await?;
    }
    // The file is there now: clients fetch the cipher again to see its attachment.
    target.changed(app, authed);
    Ok(())
}

/// `GET /api/ciphers/{id}/attachment/{attachmentId}`: the attachment and its download link.
pub(crate) async fn get_attachment<S: BwStore>(
    app: &App<S>,
    authed: &Authed,
    cipher_id: &str,
    attachment_id: &str,
) -> BwResult<Value> {
    let target = Target::load(
        app,
        authed,
        cipher_id,
        Access::Read,
        "Cipher is not accessible",
    )
    .await?;
    let attachment = find_attachment(target.cipher(), attachment_id)?;
    let url = app.download_url(&target.cipher().id, &attachment.id)?;
    Ok(attachment_json(attachment, &url))
}

/// `GET /attachments/{cipherId}/{attachmentId}?token=…`: the file, for whoever holds a link
/// less than a minute old. `None` for anything wrong with the link or the file.
pub(crate) async fn download<S: BwStore>(
    app: &App<S>,
    cipher_id: &str,
    attachment_id: &str,
    token: &str,
) -> Option<Vec<u8>> {
    let claims: FileDownloadClaims = app
        .keys
        .decode(token, &app.settings.issuer("file_download"), app.now_secs())
        .ok()?;
    if claims.sub != cipher_id
        || claims.file_id != attachment_id
        || !valid_attachment_id(attachment_id)
    {
        return None;
    }
    app.blobs
        .get(&blob_key(cipher_id, attachment_id))
        .await
        .ok()
        .flatten()
}

/// `DELETE /api/ciphers/{id}/attachment/{attachmentId}`: the cipher without it.
pub(crate) async fn delete_attachment<S: BwStore>(
    app: &App<S>,
    authed: &Authed,
    cipher_id: &str,
    attachment_id: &str,
) -> BwResult<Value> {
    let mut target = Target::load(
        app,
        authed,
        cipher_id,
        Access::Write,
        "Cipher cannot be deleted by user",
    )
    .await?;
    find_attachment(target.cipher(), attachment_id)?;
    target
        .cipher_mut()
        .attachments
        .retain(|a| a.id != attachment_id);
    target.save(app, authed).await?;
    target.changed(app, authed);
    if let Err(e) = app
        .blobs
        .delete(&blob_key(&target.cipher().id, attachment_id))
        .await
    {
        tracing::warn!(error = %e, "couldn't remove an attachment file");
    }
    target
        .log(app, authed, kind::CIPHER_ATTACHMENT_DELETED)
        .await;
    Ok(json!({ "cipher": target.json(app, authed).await? }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sizes_come_as_numbers_or_text() {
        let number: NumberOrString = serde_json::from_value(json!(17)).expect("a number");
        let text: NumberOrString = serde_json::from_value(json!("17")).expect("text");
        assert_eq!(number.as_i64(), Ok(17));
        assert_eq!(text.as_i64(), Ok(17));
        let bad: NumberOrString = serde_json::from_value(json!("seventeen")).expect("text");
        assert_eq!(bad.as_i64(), Err(BwError::msg("Can't convert to number")));
    }

    #[test]
    fn attachment_ids_are_letters_and_digits() {
        assert!(valid_attachment_id("a1b2c3d4e5f6a7b8c9d0"));
        for bad in [
            "",
            "a".repeat(65).as_str(),
            "../x",
            "a/b",
            "a.b",
            "a-b",
            "a b",
        ] {
            assert!(!valid_attachment_id(bad), "{bad:?}");
        }
    }

    #[test]
    fn files_are_named_by_cipher_and_attachment() {
        assert_eq!(blob_key("c", "a"), "c/a");
    }
}
