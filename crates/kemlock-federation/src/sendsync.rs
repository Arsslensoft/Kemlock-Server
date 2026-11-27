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

/// What a server lists among its descriptor's suites to say it answers `Sends` (request 17).
/// `negotiate` skips names it doesn't know, so an older peer keeps the name and ignores it; an
/// older peer would drop the session on a request type it doesn't know, so none is sent to a peer
/// that doesn't list it.
pub const SENDS_CAPABILITY: &str = "x-kemlock-sends1";
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
    /// text, and the file Sends whose bytes are here. Nothing for a space. A copy that came from
    /// `not_from` is left out: handing a server its own Sends back would bring a deleted one to life.
    fn sends_after(
        &self,
        _owner: Owner,
        _after: SendId,
        _limit: u32,
        _not_from: ServerId,
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
    fn drop_replicated_send(&self, _id: SendId) -> impl Future<Output = R<Option<BlobId>>> + Send {
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
        peer: ServerId,
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
                peer,
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
        self.authorize(peer, vault).await?;
        let Owner::User(owner) = vault else {
            return Ok(SendReport::default());
        };
        let mut report = SendReport::default();
        let mut seen: HashSet<SendId> = HashSet::new();
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
                // Whether its file could be had has no bearing on deleting what the peer dropped:
                // `seen` is the peer's whole list.
                self.take_send(channel, peer, entry, &mut report).await?;
            }
            if !more {
                break;
            }
        }
        // A copy is deleted when the server it came from no longer lists it, whichever server
        // that is: a Send deleted at the home, and a copy made from a replica's relay of it.
        {
            for id in self.store.replicated_send_ids(vault, peer).await? {
                if seen.contains(&id) {
                    continue;
                }
                let dropped = self.store.drop_replicated_send(id).await?;
                if let Some(blob) = dropped
                    && let Some(files) = &self.files
                    // Only a file no other row holds: a copy never deletes what it doesn't own.
                    && self.store.send_of_blob(blob).await?.is_none()
                    && self.store.attachment_of_blob(blob).await?.is_none()
                    && let Err(e) = files.delete(blob).await
                {
                    tracing::info!(error = %e, "a deleted Send's file stayed in storage");
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
            // A file Send needs file storage, and a server without it takes the notes only.
            if self.files.is_none() || file.size > MAX_FETCH {
                report.skipped += 1;
                return Ok(false);
            }
            // A copy owns its file alone. A blob another Send or an attachment already holds is
            // not taken: writing it would overwrite that file, and deleting the copy later
            // would delete it.
            let other_send = self.store.send_of_blob(file.blob).await?;
            let held_elsewhere = other_send.is_some_and(|other| other.id != entry.id)
                || self.store.attachment_of_blob(file.blob).await?.is_some();
            if held_elsewhere {
                tracing::info!(%peer, send = %entry.id, "a Send names a file another row holds");
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

    // ---- replication between two in-memory servers ----

    use crate::blobs::BlobFiles;
    use crate::memory::MemoryStore;
    use crate::suite::Suite;
    use crate::testing::identity;
    use kemlock_app::federation_view::BoxFut;
    use kemlock_app::files::BlobError;
    use std::collections::HashMap;
    use std::sync::{Arc, Mutex};

    const NOW: u64 = 1_800_000_000;

    /// File storage in memory, remembering which files were stored without the `KMA1` check.
    #[derive(Default)]
    struct Files {
        held: Mutex<HashMap<BlobId, Vec<u8>>>,
        raw: Mutex<HashSet<BlobId>>,
    }

    impl Files {
        fn put(&self, blob: BlobId, data: Vec<u8>) {
            self.held.lock().expect("lock").insert(blob, data);
        }

        fn get(&self, blob: BlobId) -> Option<Vec<u8>> {
            self.held.lock().expect("lock").get(&blob).cloned()
        }
    }

    impl BlobFiles for Files {
        fn read_chunk(
            &self,
            blob: BlobId,
            offset: u64,
            len: u32,
        ) -> BoxFut<'_, std::result::Result<(u64, Vec<u8>), BlobError>> {
            Box::pin(async move {
                let held = self.held.lock().expect("lock");
                let data = held.get(&blob).ok_or(BlobError::NotFound)?;
                let start = usize::try_from(offset)
                    .unwrap_or(usize::MAX)
                    .min(data.len());
                let end = start.saturating_add(len as usize).min(data.len());
                Ok((data.len() as u64, data[start..end].to_vec()))
            })
        }

        fn has(&self, blob: BlobId) -> BoxFut<'_, std::result::Result<bool, BlobError>> {
            Box::pin(async move { Ok(self.get(blob).is_some()) })
        }

        fn store(
            &self,
            blob: BlobId,
            data: Vec<u8>,
        ) -> BoxFut<'_, std::result::Result<(), BlobError>> {
            Box::pin(async move {
                self.put(blob, data);
                Ok(())
            })
        }

        fn store_raw(
            &self,
            blob: BlobId,
            data: Vec<u8>,
        ) -> BoxFut<'_, std::result::Result<(), BlobError>> {
            Box::pin(async move {
                self.raw.lock().expect("lock").insert(blob);
                self.put(blob, data);
                Ok(())
            })
        }

        fn delete(&self, blob: BlobId) -> BoxFut<'_, std::result::Result<(), BlobError>> {
            Box::pin(async move {
                self.held.lock().expect("lock").remove(&blob);
                Ok(())
            })
        }
    }

    struct Direct<'a> {
        remote: &'a Replica<MemoryStore>,
        caller: ServerId,
    }

    impl Channel for Direct<'_> {
        async fn call(&mut self, request: &Request) -> Result<Response> {
            Ok(self.remote.serve(self.caller, request, NOW).await.response)
        }
    }

    struct Pair {
        a: Replica<MemoryStore>,
        b: Replica<MemoryStore>,
        a_files: Arc<Files>,
        b_files: Arc<Files>,
        a_id: ServerId,
        b_id: ServerId,
        vault: Owner,
        user: UserId,
    }

    /// A is the home of a personal vault, B its replica.
    async fn pair() -> Pair {
        let ia = identity(1, NOW, &Suite::IMPLEMENTED);
        let ib = identity(2, NOW, &Suite::IMPLEMENTED);
        let (a_files, b_files) = (Arc::new(Files::default()), Arc::new(Files::default()));
        let a = Replica::new(MemoryStore::new(ia.server), Arc::new(ia.clone()))
            .with_blob_files(a_files.clone());
        let b = Replica::new(MemoryStore::new(ib.server), Arc::new(ib.clone()))
            .with_blob_files(b_files.clone());
        a.pin_peer(&ib.descriptor, NOW).await.expect("pin");
        b.pin_peer(&ia.descriptor, NOW).await.expect("pin");
        let user = UserId::random();
        let vault = Owner::User(user);
        a.federate(vault, vec![ib.server]).await.expect("federate");
        b.accept_vault(vault, ia.server, vec![ib.server])
            .await
            .expect("accept");
        Pair {
            a,
            b,
            a_files,
            b_files,
            a_id: ia.server,
            b_id: ib.server,
            vault,
            user,
        }
    }

    impl Pair {
        fn send(&self, file: Option<(u64, SendFileFormat)>) -> SendRecord {
            let mut send = sample(file.map(|(size, format)| SendFile {
                blob: BlobId::random(),
                size,
                format,
                ready: true,
            }));
            send.owner = self.user;
            send
        }

        /// A file Send at A whose bytes are there.
        fn file_send(&self, len: usize, format: SendFileFormat) -> SendRecord {
            let send = self.send(Some((len as u64, format)));
            let blob = send.file.map(|f| f.blob).expect("file");
            self.a_files
                .put(blob, (0..len).map(|i| (i % 251) as u8).collect());
            self.a.store.put_send(send.clone());
            send
        }

        async fn sync(&self) -> Result<SendReport> {
            let mut channel = Direct {
                remote: &self.a,
                caller: self.b_id,
            };
            self.b.sync_sends(&mut channel, self.a_id, self.vault).await
        }
    }

    #[tokio::test]
    async fn a_note_and_both_kinds_of_file_send_copy_to_the_replica() {
        let t = pair().await;
        let note = t.send(None);
        t.a.store.put_send(note.clone());
        let kma1 = t.file_send(5000, SendFileFormat::Kma1);
        let opaque = t.file_send(300, SendFileFormat::Opaque);

        let report = t.sync().await.expect("sync");
        assert_eq!((report.rows, report.fetched, report.skipped), (3, 2, 0));
        for sent in [&note, &kma1, &opaque] {
            assert_eq!(t.b.store.send(sent.id).as_ref(), Some(sent));
        }
        let kb = kma1.file.expect("file").blob;
        let ob = opaque.file.expect("file").blob;
        assert_eq!(t.b_files.get(kb), t.a_files.get(kb));
        assert_eq!(t.b_files.get(ob), t.a_files.get(ob));
        {
            let raw = t.b_files.raw.lock().expect("lock");
            assert!(
                raw.contains(&ob) && !raw.contains(&kb),
                "only the opaque file skips the KMA1 check"
            );
        }

        // A second visit has nothing to do.
        assert_eq!(t.sync().await, Ok(SendReport::default()));
    }

    #[tokio::test]
    async fn a_file_over_the_threshold_gets_its_row_and_waits_for_first_use() {
        let t = pair().await;
        let big = t.send(Some((ON_DEMAND_THRESHOLD + 1, SendFileFormat::Kma1)));
        t.a.store.put_send(big.clone());
        let report = t.sync().await.expect("sync");
        assert_eq!((report.rows, report.fetched, report.deferred), (1, 0, 1));
        assert!(t.b.store.send(big.id).is_some());
        assert_eq!(t.b_files.get(big.file.expect("file").blob), None);
    }

    #[tokio::test]
    async fn a_file_that_cannot_be_fetched_leaves_its_send_out_and_the_rest_go_on() {
        let t = pair().await;
        // The row is listed at A, but its bytes are gone there.
        let lost = t.send(Some((4000, SendFileFormat::Kma1)));
        t.a.store.put_send(lost.clone());
        let fine = t.send(None);
        t.a.store.put_send(fine.clone());
        let report = t.sync().await.expect("sync");
        assert_eq!((report.rows, report.skipped), (1, 1));
        assert!(t.b.store.send(lost.id).is_none());
        assert!(t.b.store.send(fine.id).is_some());

        // A file past the cap is never taken.
        let huge = t.send(Some((MAX_FETCH + 1, SendFileFormat::Kma1)));
        t.a.store.put_send(huge.clone());
        let report = t.sync().await.expect("sync");
        assert!(t.b.store.send(huge.id).is_none());
        assert_eq!(
            report.skipped, 2,
            "the lost one is tried again, the huge one is refused"
        );
    }

    #[tokio::test]
    async fn a_newer_revision_and_a_higher_view_count_reach_the_replica() {
        let t = pair().await;
        let send = t.send(None);
        t.a.store.put_send(send.clone());
        t.sync().await.expect("sync");

        // Views used at the replica don't go backwards when A has fewer.
        let mut at_b = t.b.store.send(send.id).expect("copied");
        at_b.access_count = 4;
        t.b.store.put_send(at_b);
        let mut edited = send.clone();
        edited.disabled = true;
        edited.max_access = Some(9);
        edited.revised_at = send.revised_at + time::Duration::hours(1);
        t.a.store.put_send(edited.clone());
        let report = t.sync().await.expect("sync");
        assert_eq!((report.rows, report.updated), (0, 1));
        let now = t.b.store.send(send.id).expect("held");
        assert!(now.disabled);
        assert_eq!(now.max_access, Some(9));
        assert_eq!(now.access_count, 4);

        // And A's higher count reaches B.
        let mut counted = edited;
        counted.access_count = 7;
        t.a.store.put_send(counted);
        t.sync().await.expect("sync");
        assert_eq!(t.b.store.send(send.id).expect("held").access_count, 7);
    }

    #[tokio::test]
    async fn another_peer_cannot_rewrite_a_copy_or_a_send_made_at_the_replica() {
        use crate::home::VaultFederation;
        use crate::ports::VaultRepo as _;
        let t = pair().await;
        let copied = t.send(None);
        t.a.store.put_send(copied.clone());
        t.sync().await.expect("sync");
        let local = t.send(None);
        t.b.store.put_send(local.clone());
        assert_eq!(t.b.store.send(copied.id), Some(copied.clone()));

        // A server in the set with a newer revision of each that clears the password and
        // disables it: its revision is refused for both (it isn't the server the copy came from,
        // nor the vault's home, and the other was never copied), but a larger view count is taken.
        let stranger = ServerId::random();
        for target in [&copied, &local] {
            let mut hostile = target.clone();
            hostile.revised_at += time::Duration::days(1);
            hostile.password = None;
            hostile.disabled = true;
            assert_eq!(
                t.b.store.apply_replicated_send(stranger, &hostile).await,
                Ok(SendApply::Unchanged)
            );
            hostile.access_count += 5;
            assert_eq!(
                t.b.store.apply_replicated_send(stranger, &hostile).await,
                Ok(SendApply::Updated)
            );
        }
        for target in [&copied, &local] {
            let held = t.b.store.send(target.id).expect("held");
            assert_eq!(held.access_count, target.access_count + 5);
            assert_eq!(
                SendRecord {
                    access_count: target.access_count,
                    ..held
                },
                *target
            );
        }

        // A promotion makes the stranger the home: from then on its revision is taken.
        t.b.store
            .put_vault(&VaultFederation::federated(t.vault, stranger, vec![t.a_id]))
            .await
            .expect("settings");
        let mut revised = copied.clone();
        revised.revised_at += time::Duration::days(2);
        revised.disabled = true;
        assert_eq!(
            t.b.store.apply_replicated_send(stranger, &revised).await,
            Ok(SendApply::Updated)
        );
        t.b.store
            .put_vault(&VaultFederation::federated(t.vault, t.a_id, vec![stranger]))
            .await
            .expect("settings");

        // The server the copy came from can still update it.
        let mut update = copied.clone();
        update.revised_at += time::Duration::days(3);
        update.disabled = false;
        assert_eq!(
            t.b.store.apply_replicated_send(t.a_id, &update).await,
            Ok(SendApply::Updated)
        );
        assert!(!t.b.store.send(copied.id).expect("held").disabled);
    }

    #[tokio::test]
    async fn a_send_the_home_dropped_goes_from_the_replica_but_one_made_there_stays() {
        let t = pair().await;
        let gone = t.file_send(600, SendFileFormat::Kma1);
        let kept = t.send(None);
        t.a.store.put_send(kept.clone());
        t.sync().await.expect("sync");
        let blob = gone.file.expect("file").blob;
        assert!(t.b_files.get(blob).is_some());

        // The owner made another Send at the replica itself.
        let local = t.send(None);
        t.b.store.put_send(local.clone());

        t.a.store.remove_send(gone.id);
        let report = t.sync().await.expect("sync");
        assert_eq!(report.removed, 1);
        assert!(t.b.store.send(gone.id).is_none());
        assert_eq!(t.b_files.get(blob), None, "the file went with it");
        assert!(t.b.store.send(kept.id).is_some());
        assert!(t.b.store.send(local.id).is_some());
    }

    #[tokio::test]
    async fn an_unfederated_vault_and_a_stranger_get_nothing() {
        let t = pair().await;
        let space = Owner::Space(kemlock_domain::SpaceId::random());
        let mut channel = Direct {
            remote: &t.a,
            caller: t.b_id,
        };
        // Not a vault either server federates: refused before anything is asked.
        assert!(t.b.sync_sends(&mut channel, t.a_id, space).await.is_err());

        // A server that is not paired may not list the Sends.
        let stranger = identity(9, NOW, &Suite::IMPLEMENTED);
        let asked =
            t.a.serve(
                stranger.server,
                &Request::Sends {
                    vault: t.vault,
                    after: [0; 16],
                    limit: 50,
                },
                NOW,
            )
            .await;
        assert!(matches!(asked.response, Response::Error { .. }));
    }

    #[tokio::test]
    async fn a_file_is_only_served_to_the_vault_of_its_owner() {
        let t = pair().await;
        let send = t.file_send(500, SendFileFormat::Kma1);
        let blob = send.file.expect("file").blob;
        let other = Owner::User(UserId::random());
        let ask = |vault| Request::Blob {
            vault,
            blob,
            offset: 0,
            len: 100,
        };
        let mine = t.a.serve(t.b_id, &ask(t.vault), NOW).await.response;
        assert!(
            matches!(mine, Response::BlobChunk { size: 500, .. }),
            "{mine:?}"
        );
        let wrong = t.a.serve(t.b_id, &ask(other), NOW).await.response;
        assert!(matches!(wrong, Response::Error { .. }));
    }

    #[tokio::test]
    async fn a_copy_is_not_handed_back_so_a_send_deleted_at_home_stays_deleted() {
        let t = pair().await;
        let gone = t.send(None);
        t.a.store.put_send(gone.clone());
        t.sync().await.expect("sync");
        assert!(t.b.store.send(gone.id).is_some());

        // The owner deletes it at the home. The home asks the replica for its Sends...
        t.a.store.remove_send(gone.id);
        let mut to_b = Direct {
            remote: &t.b,
            caller: t.a_id,
        };
        let listed = to_b
            .call(&Request::Sends {
                vault: t.vault,
                after: [0; 16],
                limit: 50,
            })
            .await
            .expect("answer");
        // ...and the copy is not among them, so the home can't take it back.
        assert!(
            matches!(&listed, Response::Sends { entries, .. } if entries.is_empty()),
            "{listed:?}"
        );
        // The replica drops it at its next visit.
        assert_eq!(t.sync().await.expect("sync").removed, 1);

        // A Send made at the replica is listed to the home.
        let local = t.send(None);
        t.b.store.put_send(local.clone());
        let listed = to_b
            .call(&Request::Sends {
                vault: t.vault,
                after: [0; 16],
                limit: 50,
            })
            .await
            .expect("answer");
        assert!(
            matches!(&listed, Response::Sends { entries, .. } if entries.len() == 1 && entries[0].id == local.id)
        );
    }

    #[tokio::test]
    async fn a_send_that_cannot_be_copied_does_not_hold_back_the_deletion_of_others() {
        let t = pair().await;
        let gone = t.send(None);
        t.a.store.put_send(gone.clone());
        t.sync().await.expect("sync");

        // A file the replica won't take stays in the home's list for good.
        let huge = t.send(Some((MAX_FETCH + 1, SendFileFormat::Kma1)));
        t.a.store.put_send(huge);
        t.a.store.remove_send(gone.id);
        let report = t.sync().await.expect("sync");
        assert_eq!((report.skipped, report.removed), (1, 1));
        assert!(t.b.store.send(gone.id).is_none());
    }

    #[tokio::test]
    async fn a_send_naming_a_file_another_row_holds_is_refused_and_that_file_is_left_alone() {
        let t = pair().await;
        // The replica holds a Send of its own, with a file.
        let own = t.send(Some((300, SendFileFormat::Kma1)));
        let blob = own.file.expect("file").blob;
        t.b.store.put_send(own.clone());
        t.b_files.put(blob, vec![7; 300]);

        // The home's Send names the same blob, as a hostile or broken home could.
        let mut stolen = t.send(Some((300, SendFileFormat::Kma1)));
        stolen.file = stolen.file.map(|f| SendFile { blob, ..f });
        t.a.store.put_send(stolen.clone());
        t.a_files.put(blob, vec![9; 300]);

        let report = t.sync().await.expect("sync");
        assert_eq!((report.rows, report.skipped), (0, 1));
        assert!(t.b.store.send(stolen.id).is_none());
        assert_eq!(t.b_files.get(blob), Some(vec![7; 300]), "not overwritten");
        assert!(t.b.store.send(own.id).is_some());
    }

    #[tokio::test]
    async fn deleting_a_copy_leaves_a_file_another_row_holds() {
        let t = pair().await;
        let copied = t.file_send(200, SendFileFormat::Kma1);
        t.sync().await.expect("sync");
        let blob = copied.file.expect("file").blob;
        // Another Send here comes to name the same blob (a row from before the check).
        let mut other = t.send(Some((200, SendFileFormat::Kma1)));
        other.file = other.file.map(|f| SendFile { blob, ..f });
        t.b.store.put_send(other.clone());

        t.a.store.remove_send(copied.id);
        let report = t.sync().await.expect("sync");
        assert_eq!(report.removed, 1);
        assert!(t.b_files.get(blob).is_some(), "the other row's file stays");
    }

    #[tokio::test]
    async fn a_server_without_file_storage_still_copies_notes() {
        let t = pair().await;
        // A replica of the same vault with no file storage configured.
        let ic = identity(3, NOW, &Suite::IMPLEMENTED);
        let ia = identity(1, NOW, &Suite::IMPLEMENTED);
        let c = Replica::new(MemoryStore::new(ic.server), Arc::new(ic.clone()));
        let home = Replica::new(MemoryStore::new(ia.server), Arc::new(ia.clone()))
            .with_blob_files(t.a_files.clone());
        c.pin_peer(&ia.descriptor, NOW).await.expect("pin");
        home.pin_peer(&ic.descriptor, NOW).await.expect("pin");
        home.federate(t.vault, vec![ic.server])
            .await
            .expect("federate");
        c.accept_vault(t.vault, ia.server, vec![ic.server])
            .await
            .expect("accept");

        let note = t.send(None);
        home.store.put_send(note.clone());
        let file = t.send(Some((300, SendFileFormat::Kma1)));
        t.a_files.put(file.file.expect("file").blob, vec![1; 300]);
        home.store.put_send(file.clone());

        let mut channel = Direct {
            remote: &home,
            caller: ic.server,
        };
        let report = c
            .sync_sends(&mut channel, ia.server, t.vault)
            .await
            .expect("sync");
        assert_eq!((report.rows, report.skipped), (1, 1));
        assert!(c.store.send(note.id).is_some());
        assert!(
            c.store.send(file.id).is_none(),
            "no row for a file it can't hold"
        );
    }
}
