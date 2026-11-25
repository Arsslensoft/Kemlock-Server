//! File Sends travel with a federated vault, as ciphertext, so a Send link keeps working when the
//! vault fails over to a replica.
//!
//! A Send is stored as it was made: its name and notes, its key and its payload are sealed on the
//! owner's device, and a file Send's bytes are an encrypted file in blob storage. A replica lists a
//! peer's Sends of a personal vault (`Sends`), keeps a row for each (the same row, the same access
//! id, so the same link) and copies the file the way it copies an attachment: in chunks (`Blob`),
//! up to [`ON_DEMAND_THRESHOLD`], with a larger one fetched the first time someone opens it. The
//! server never opens a Send: it checks lengths and formats, and the blob store checks the file is
//! a `KMA1` file (for the format that says it is) as it does for an upload.
//!
//! A space has no Sends. A Send that the owner deleted at the home is deleted at a replica that
//! copied it, at that replica's next visit to the home; a Send made at the replica itself is never
//! touched by that.

use crate::blobs::{MAX_FETCH, ON_DEMAND_THRESHOLD};
use crate::cbor::{Fields, Value};
use crate::error::{FedError, Result};
use crate::message::{Request, Response};
use crate::replicate::{Channel, FedStore, Replica};
use kemlock_app::ports::StoreError;
use kemlock_domain::sends::{
    PASSWORD_HASH_LEN, PASSWORD_SALT_LEN, SendFile, SendFileFormat, SendId, SendKind, SendPassword,
    SendRecord,
};
use kemlock_domain::{BlobId, Owner, ServerId, UserId};
use std::collections::HashSet;
use std::future::{Future, ready};
use time::OffsetDateTime;

type R<T> = std::result::Result<T, StoreError>;

/// The most Sends one `Sends` response carries.
pub const MAX_SEND_ENTRIES: u32 = 50;
/// A response stops growing past this many bytes of Sends, so a frame stays far below its cap.
const PAGE_BYTES: usize = 1_500_000;
/// The longest sealed part (name and notes, payload) of a Send a replica takes.
pub const MAX_SEALED: usize = 1024 * 1024;
/// The longest sealed key of a Send a replica takes.
const MAX_SEALED_KEY: usize = 256;

fn millis(time: OffsetDateTime) -> u64 {
    u64::try_from(time.unix_timestamp_nanos() / 1_000_000).unwrap_or(0)
}

fn from_millis(ms: u64) -> Result<OffsetDateTime> {
    OffsetDateTime::from_unix_timestamp_nanos(i128::from(ms) * 1_000_000)
        .map_err(|_| FedError::Malformed("a time is out of range"))
}

/// A Send as it travels: deterministic CBOR, keys as in `docs/federation.md`.
pub fn send_to_value(send: &SendRecord) -> Value {
    let mut entries = vec![
        (0, Value::bytes(send.id.as_bytes())),
        (1, Value::Uint(u64::from(send.kind.code().unsigned_abs()))),
        (2, Value::Bytes(send.meta.clone())),
        (3, Value::Bytes(send.sealed_key.clone())),
        (4, Value::Bytes(send.payload.clone())),
        (8, Value::Uint(u64::from(send.access_count))),
        (9, Value::flag(send.hide_email)),
        (10, Value::flag(send.disabled)),
        (12, Value::Uint(millis(send.deletion_at))),
        (13, Value::Uint(millis(send.created_at))),
        (14, Value::Uint(millis(send.revised_at))),
    ];
    if let Some(file) = send.file {
        entries.push((
            5,
            Value::map(vec![
                (0, Value::bytes(file.blob.as_bytes())),
                (1, Value::Uint(file.size)),
                (2, Value::text(file.format.as_str())),
            ]),
        ));
    }
    if let Some(password) = &send.password {
        entries.push((
            6,
            Value::map(vec![
                (0, Value::Bytes(password.salt.clone())),
                (1, Value::Bytes(password.hash.clone())),
            ]),
        ));
    }
    if let Some(max) = send.max_access {
        entries.push((7, Value::Uint(u64::from(max))));
    }
    if let Some(expires) = send.expires_at {
        entries.push((11, Value::Uint(millis(expires))));
    }
    Value::map(entries)
}

/// Reads a Send, checking every length and the pairing of kind and file before anything is kept.
pub fn send_from_value(value: &Value, owner: UserId) -> Result<SendRecord> {
    let f: Fields<'_> = value.as_fields()?;
    f.only(&[0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14])?;
    let kind = i16::try_from(f.uint(1)?)
        .ok()
        .and_then(SendKind::from_code)
        .ok_or(FedError::Malformed("an unknown Send kind"))?;
    let meta = f.bytes(2)?;
    let sealed_key = f.bytes(3)?;
    let payload = f.bytes(4)?;
    if meta.len() > MAX_SEALED || payload.len() > MAX_SEALED || sealed_key.len() > MAX_SEALED_KEY {
        return Err(FedError::Malformed("a sealed part of a Send is too long"));
    }
    let file = match f.get(5) {
        None => None,
        Some(v) => {
            let ff = v.as_fields()?;
            ff.only(&[0, 1, 2])?;
            let size = ff.uint(1)?;
            if size == 0 {
                return Err(FedError::Malformed("a Send file is empty"));
            }
            Some(SendFile {
                blob: BlobId::from_bytes(ff.fixed::<16>(0)?),
                size,
                format: SendFileFormat::parse(ff.text(2)?)
                    .ok_or(FedError::Malformed("an unknown Send file format"))?,
                // Only ready files are listed.
                ready: true,
            })
        }
    };
    if (kind == SendKind::File) != file.is_some() {
        return Err(FedError::Malformed("a Send's kind and file don't agree"));
    }
    let password = match f.get(6) {
        None => None,
        Some(v) => {
            let pf = v.as_fields()?;
            pf.only(&[0, 1])?;
            let (salt, hash) = (pf.bytes(0)?, pf.bytes(1)?);
            if salt.len() != PASSWORD_SALT_LEN || hash.len() != PASSWORD_HASH_LEN {
                return Err(FedError::Malformed("a Send password has the wrong length"));
            }
            Some(SendPassword {
                salt: salt.to_vec(),
                hash: hash.to_vec(),
            })
        }
    };
    let small = |key: u64| -> Result<u32> {
        u32::try_from(f.uint(key)?).map_err(|_| FedError::Malformed("a count is out of range"))
    };
    Ok(SendRecord {
        id: SendId(uuid::Uuid::from_bytes(f.fixed::<16>(0)?)),
        owner,
        kind,
        meta: meta.to_vec(),
        sealed_key: sealed_key.to_vec(),
        payload: payload.to_vec(),
        file,
        password,
        max_access: f.get(7).map(|_| small(7)).transpose()?,
        access_count: small(8)?,
        hide_email: f.flag(9)?,
        disabled: f.flag(10)?,
        expires_at: f.get(11).map(|_| from_millis(f.uint(11)?)).transpose()?,
        deletion_at: from_millis(f.uint(12)?)?,
        created_at: from_millis(f.uint(13)?)?,
        revised_at: from_millis(f.uint(14)?)?,
    })
}

/// What keeping a replicated Send did.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SendApply {
    /// A row was added.
    Added,
    /// The row was newer at the peer, or had fewer views, and took that.
    Updated,
    /// Nothing changed (or the id belongs to another account, which is refused).
    Unchanged,
}

/// What federation needs from storage to move Sends. The defaults say there are none.
pub trait SendSync: Send + Sync {
    /// The Sends of `owner` with an id after `after`, in id order, at most `limit`: those that are
    /// text, and the file Sends whose bytes are here. Nothing for a space.
    fn sends_after(
        &self,
        _owner: Owner,
        _after: SendId,
        _limit: u32,
    ) -> impl Future<Output = R<Vec<SendRecord>>> + Send {
        ready(Ok(Vec::new()))
    }

    /// The Send whose file is stored as `blob`, if any.
    fn send_of_blob(&self, _blob: BlobId) -> impl Future<Output = R<Option<SendRecord>>> + Send {
        ready(Ok(None))
    }

    /// The Send with this id, if any.
    fn send_row(&self, _id: SendId) -> impl Future<Output = R<Option<SendRecord>>> + Send {
        ready(Ok(None))
    }

    /// Keeps a Send a peer holds: adds the row, marking it as copied from `from`, or takes the
    /// peer's newer revision and larger view count into the row held. Never changes the owner, the
    /// key or the file of a row.
    fn apply_replicated_send(
        &self,
        _from: ServerId,
        _send: &SendRecord,
    ) -> impl Future<Output = R<SendApply>> + Send {
        ready(Ok(SendApply::Unchanged))
    }

    /// The ids of the Sends of `owner` this server copied from `from`.
    fn replicated_send_ids(
        &self,
        _owner: Owner,
        _from: ServerId,
    ) -> impl Future<Output = R<Vec<SendId>>> + Send {
        ready(Ok(Vec::new()))
    }

    /// Deletes a Send that was copied from a peer, returning its file's blob if it had one. The
    /// file's bytes are the caller's to delete.
    fn drop_replicated_send(
        &self,
        _id: SendId,
    ) -> impl Future<Output = R<Option<BlobId>>> + Send {
        ready(Ok(None))
    }
}

/// What [`Replica::sync_sends`] did.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct SendReport {
    /// Rows added.
    pub rows: usize,
    /// Rows that took a newer revision.
    pub updated: usize,
    /// Files copied.
    pub fetched: usize,
    /// Files left for their first use, because they are over the threshold.
    pub deferred: usize,
    /// Sends left out: a file that couldn't be fetched, was too large or didn't check.
    pub skipped: usize,
    /// Copies deleted because the home no longer holds the Send.
    pub removed: usize,
}

impl<S: FedStore> Replica<S> {
    /// Serves a page of the Sends of `vault` to a peer.
    pub(crate) async fn serve_sends(
        &self,
        vault: Owner,
        after: [u8; 16],
        limit: u32,
    ) -> Result<Response> {
        let page = limit.clamp(1, MAX_SEND_ENTRIES) as usize;
        let rows = self
            .store
            .sends_after(
                vault,
                SendId(uuid::Uuid::from_bytes(after)),
                (page as u32).saturating_add(1),
            )
            .await?;
        let mut entries = Vec::new();
        let mut bytes = 0usize;
        let mut more = rows.len() > page;
        for row in rows.into_iter().take(page) {
            bytes += row.meta.len() + row.payload.len() + row.sealed_key.len() + 200;
            if !entries.is_empty() && bytes > PAGE_BYTES {
                more = true;
                break;
            }
            entries.push(row);
        }
        Ok(Response::Sends {
            vault,
            entries,
            more,
        })
    }

    /// Copies the Sends of the personal vault `vault` that `peer` holds: a row for each, and the
    /// file of a file Send when it is small enough and isn't here yet. When `peer` is the vault's
    /// home, the copies it no longer holds are deleted. Returns what it did; a Send whose file
    /// can't be had is left for the next visit and counted in `skipped`.
    pub async fn sync_sends<C: Channel>(
        &self,
        channel: &mut C,
        peer: ServerId,
        vault: Owner,
    ) -> Result<SendReport> {
        let settings = self.authorize(peer, vault).await?;
        let Owner::User(owner) = vault else {
            return Ok(SendReport::default());
        };
        let mut report = SendReport::default();
        let mut seen: HashSet<SendId> = HashSet::new();
        let mut complete = true;
        let mut after = [0u8; 16];
        loop {
            let response = channel
                .call(&Request::Sends {
                    vault,
                    after,
                    limit: MAX_SEND_ENTRIES,
                })
                .await?;
            let (entries, more) = match response {
                Response::Sends {
                    vault: v,
                    entries,
                    more,
                } if v == vault => (entries, more),
                Response::Error { detail, .. } => return Err(FedError::Remote(detail)),
                _ => return Err(FedError::Malformed("an unexpected response to a Send list")),
            };
            let Some(last) = entries.last() else { break };
            if *last.id.as_bytes() <= after {
                return Err(FedError::Malformed("the Sends are not in order"));
            }
            after = *last.id.as_bytes();
            for entry in &entries {
                seen.insert(entry.id);
                if entry.owner != owner {
                    return Err(FedError::Malformed("a Send names another owner"));
                }
                if !self.take_send(channel, peer, entry, &mut report).await? {
                    complete = false;
                }
            }
            if !more {
                break;
            }
        }
        if complete && settings.home == peer && settings.home != self.server_id() {
            for id in self.store.replicated_send_ids(vault, peer).await? {
                if seen.contains(&id) {
                    continue;
                }
                if let Some(blob) = self.store.drop_replicated_send(id).await? {
                    if let Some(files) = &self.files
                        && let Err(e) = files.delete(blob).await
                    {
                        tracing::info!(error = %e, "a deleted Send's file stayed in storage");
                    }
                }
                report.removed += 1;
            }
        }
        Ok(report)
    }

    /// Keeps one Send of a peer, with its file. `false` when the file couldn't be had.
    async fn take_send<C: Channel>(
        &self,
        channel: &mut C,
        peer: ServerId,
        entry: &SendRecord,
        report: &mut SendReport,
    ) -> Result<bool> {
        if let Some(file) = entry.file {
            if file.size > MAX_FETCH {
                report.skipped += 1;
                return Ok(false);
            }
            let have_row = self.store.send_row(entry.id).await?.is_some();
            let present = match &self.files {
                Some(files) => files
                    .has(file.blob)
                    .await
                    .map_err(|_| FedError::Store("blob storage failed".to_owned()))?,
                None => true,
            };
            if !present && !have_row && file.size <= ON_DEMAND_THRESHOLD {
                let owner = Owner::User(entry.owner);
                let raw = file.format == SendFileFormat::Opaque;
                if let Err(e) = self
                    .fetch_file(channel, owner, file.blob, file.size, raw)
                    .await
                {
                    tracing::info!(%peer, send = %entry.id, error = %e, "a Send's file didn't copy");
                    report.skipped += 1;
                    return Ok(false);
                }
                report.fetched += 1;
            } else if !present && file.size > ON_DEMAND_THRESHOLD {
                report.deferred += 1;
            }
        }
        match self.store.apply_replicated_send(peer, entry).await? {
            SendApply::Added => report.rows += 1,
            SendApply::Updated => report.updated += 1,
            SendApply::Unchanged => {}
        }
        Ok(true)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use time::macros::datetime;

    fn sample(file: Option<SendFile>) -> SendRecord {
        SendRecord {
            id: SendId::random(),
            owner: UserId::random(),
            kind: if file.is_some() {
                SendKind::File
            } else {
                SendKind::Text
            },
            meta: vec![1; 40],
            sealed_key: vec![2; 64],
            payload: vec![3; 90],
            file,
            password: Some(SendPassword {
                salt: vec![4; PASSWORD_SALT_LEN],
                hash: vec![5; PASSWORD_HASH_LEN],
            }),
            max_access: Some(5),
            access_count: 2,
            hide_email: true,
            disabled: false,
            expires_at: Some(datetime!(2026-12-01 10:00:00 UTC)),
            deletion_at: datetime!(2026-12-24 10:00:00 UTC),
            created_at: datetime!(2026-11-24 10:00:00 UTC),
            revised_at: datetime!(2026-11-25 10:00:00.123 UTC),
        }
    }

    fn file(format: SendFileFormat) -> SendFile {
        SendFile {
            blob: BlobId::random(),
            size: 4096,
            format,
            ready: true,
        }
    }

    #[test]
    fn a_send_round_trips_with_and_without_its_options() {
        for send in [
            sample(Some(file(SendFileFormat::Kma1))),
            sample(Some(file(SendFileFormat::Opaque))),
            sample(None),
        ] {
            let bytes = send_to_value(&send).encode();
            let back = send_from_value(&Value::decode(&bytes).expect("decode"), send.owner);
            assert_eq!(back, Ok(send));
        }
        let mut bare = sample(None);
        bare.password = None;
        bare.max_access = None;
        bare.expires_at = None;
        let value = send_to_value(&bare);
        assert_eq!(send_from_value(&value, bare.owner), Ok(bare));
    }

    #[test]
    fn a_send_that_disagrees_with_itself_is_refused() {
        let owner = UserId::random();
        // A file kind without a file, and a file on a note.
        let mut text = sample(None);
        text.owner = owner;
        let mut value = send_to_value(&text);
        if let Value::Map(entries) = &mut value {
            for (k, v) in entries.iter_mut() {
                if *k == 1 {
                    *v = Value::Uint(1);
                }
            }
        }
        assert!(send_from_value(&value, owner).is_err());
        let mut with_file = sample(Some(file(SendFileFormat::Kma1)));
        with_file.owner = owner;
        let mut value = send_to_value(&with_file);
        if let Value::Map(entries) = &mut value {
            for (k, v) in entries.iter_mut() {
                if *k == 1 {
                    *v = Value::Uint(0);
                }
            }
        }
        assert!(send_from_value(&value, owner).is_err());
    }

    #[test]
    fn lengths_and_unknown_fields_are_checked() {
        let owner = UserId::random();
        let send = sample(None);
        let with = |key: u64, new: Value| {
            let mut value = send_to_value(&send);
            if let Value::Map(entries) = &mut value {
                entries.retain(|(k, _)| *k != key);
                entries.push((key, new));
                entries.sort_by_key(|(k, _)| *k);
            }
            value
        };
        assert!(send_from_value(&with(2, Value::Bytes(vec![0; MAX_SEALED + 1])), owner).is_err());
        assert!(send_from_value(&with(3, Value::Bytes(vec![0; 1000])), owner).is_err());
        assert!(
            send_from_value(
                &with(
                    6,
                    Value::map(vec![
                        (0, Value::Bytes(vec![0; 5])),
                        (1, Value::Bytes(vec![0; PASSWORD_HASH_LEN])),
                    ])
                ),
                owner
            )
            .is_err()
        );
        assert!(send_from_value(&with(15, Value::Uint(1)), owner).is_err());
        assert!(send_from_value(&with(1, Value::Uint(7)), owner).is_err());
        let mut empty = sample(Some(file(SendFileFormat::Kma1)));
        empty.file = empty.file.map(|f| SendFile { size: 0, ..f });
        assert!(send_from_value(&send_to_value(&empty), empty.owner).is_err());
    }
}
