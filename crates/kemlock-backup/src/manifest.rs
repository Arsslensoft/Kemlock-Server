//! The manifest: what an archive says it holds. Row counts of every table and the size and SHA-256
//! of every file, so a restore (and the drill, `kemlock-cli restore --check`) can tell whether what
//! came out of an archive is what went into it.

use crate::error::BackupError;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::io::Read;
use std::path::Path;

/// The manifest format this version writes and reads.
pub const MANIFEST_FORMAT: u32 = 1;

/// Where the manifest sits in an archive.
pub const MANIFEST_NAME: &str = "manifest.json";

/// A table of the snapshot.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TableEntry {
    pub name: String,
    pub rows: u64,
    pub columns: Vec<String>,
}

/// The longest table name an archive may carry.
pub const MAX_TABLE_NAME: usize = 64;

impl TableEntry {
    /// Whether `name` can be a table's name: lower-case letters, digits and underscores, at most
    /// [`MAX_TABLE_NAME`] long. The name becomes `db/<name>.jsonl`, so a name that could climb out
    /// of the folder (`..`, `a/b`, `/abs`) is never one.
    pub fn is_valid_name(name: &str) -> bool {
        !name.is_empty()
            && name.len() <= MAX_TABLE_NAME
            && name
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_')
    }
}

/// A file of the archive.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FileEntry {
    /// Its path in the archive: `db/<table>.jsonl`, `data/<name>`, `attachments/...` or
    /// `config/<name>`.
    pub path: String,
    pub size: u64,
    /// Lower-case hex.
    pub sha256: String,
}

/// Where the attachments are.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Attachments {
    /// In the archive, under `attachments/`.
    Included,
    /// In a bucket: backing it up is the bucket's job.
    External,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Manifest {
    pub format: u32,
    /// RFC 3339.
    pub created_at: String,
    /// The server's version that wrote it.
    pub kemlock_version: String,
    /// The database it was taken from: `sqlite`, `postgres` or `mysql`.
    pub database: String,
    /// The migrations the database had applied.
    pub migrations: Vec<String>,
    pub tables: Vec<TableEntry>,
    pub files: Vec<FileEntry>,
    pub attachments: Attachments,
}

impl Manifest {
    pub fn to_json(&self) -> Result<Vec<u8>, BackupError> {
        serde_json::to_vec_pretty(self).map_err(|e| BackupError::Manifest(e.to_string()))
    }

    pub fn from_json(bytes: &[u8]) -> Result<Manifest, BackupError> {
        let manifest: Manifest = serde_json::from_slice(bytes)
            .map_err(|e| BackupError::Manifest(format!("not valid: {e}")))?;
        if manifest.format != MANIFEST_FORMAT {
            return Err(BackupError::Manifest(format!(
                "format {} isn't one this version reads (it reads {MANIFEST_FORMAT})",
                manifest.format
            )));
        }
        manifest.check_names()?;
        Ok(manifest)
    }

    /// Refuses a manifest that names a table no database has: its name is joined into a path.
    pub fn check_names(&self) -> Result<(), BackupError> {
        for table in &self.tables {
            if !TableEntry::is_valid_name(&table.name) {
                return Err(BackupError::Manifest(format!(
                    "{:?} isn't a table name this server writes",
                    table.name
                )));
            }
        }
        Ok(())
    }

    /// Rows across every table.
    pub fn total_rows(&self) -> u64 {
        self.tables
            .iter()
            .fold(0u64, |total, table| total.saturating_add(table.rows))
    }
}

/// Where the manifest's authentication code sits in an archive, right after the manifest.
pub const MAC_NAME: &str = "manifest.mac";

/// The key an archive's manifest is authenticated with: 32 bytes the server derives from its
/// `server.key` (HMAC-SHA-256 of the label `kemlock/v1/backup-manifest-mac` under the key), so
/// only a server that holds `server.key` can make an archive its restore accepts. The manifest
/// lists the SHA-256 of every file, so authenticating it authenticates the archive.
#[derive(Clone, PartialEq, Eq)]
pub struct MacKey([u8; 32]);

impl MacKey {
    pub const fn new(bytes: [u8; 32]) -> Self {
        MacKey(bytes)
    }
}

impl std::fmt::Debug for MacKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MacKey").finish_non_exhaustive()
    }
}

/// HMAC-SHA-256 (RFC 2104) of what `data` reads, under `key` of at most 64 bytes, as lower-case
/// hex. The input is streamed, so a manifest of any size is no memory cost.
fn hmac_sha256_hex(key: &[u8], data: &mut impl Read) -> std::io::Result<String> {
    debug_assert!(key.len() <= 64, "a longer key would need hashing first");
    let mut inner_pad = [0x36u8; 64];
    let mut outer_pad = [0x5cu8; 64];
    for (i, byte) in key.iter().enumerate() {
        inner_pad[i] ^= byte;
        outer_pad[i] ^= byte;
    }
    let mut inner = Sha256::new();
    inner.update(inner_pad);
    let mut chunk = [0u8; 8192];
    loop {
        let read = data.read(&mut chunk)?;
        if read == 0 {
            break;
        }
        inner.update(&chunk[..read]);
    }
    let mut outer = Sha256::new();
    outer.update(outer_pad);
    outer.update(inner.finalize());
    Ok(hex::encode(outer.finalize()))
}

/// The authentication code of manifest bytes: lower-case hex.
pub fn manifest_mac(key: &MacKey, manifest: &[u8]) -> String {
    let mut bytes = manifest;
    // Reading a slice can't fail.
    hmac_sha256_hex(&key.0, &mut bytes).unwrap_or_default()
}

/// Whether two codes are equal, in time that depends only on their length.
fn same_code(a: &str, b: &str) -> bool {
    a.len() == b.len()
        && a.bytes()
            .zip(b.bytes())
            .fold(0u8, |difference, (x, y)| difference | (x ^ y))
            == 0
}

/// Checks the unpacked archive in `dir`: its `manifest.mac` is the code of its `manifest.json`
/// under `key`. Fails with [`BackupError::Unauthenticated`] when the code is missing or differs.
pub fn check_manifest_mac(dir: &Path, key: &MacKey) -> Result<(), BackupError> {
    let manifest_path = dir.join(MANIFEST_NAME);
    let mut manifest = std::fs::File::open(&manifest_path)
        .map_err(|e| BackupError::Manifest(format!("the archive has no {MANIFEST_NAME}: {e}")))?;
    let expected = hmac_sha256_hex(&key.0, &mut manifest)
        .map_err(|e| BackupError::io(format!("can't read {}", manifest_path.display()), e))?;

    let mut given = String::new();
    match std::fs::File::open(dir.join(MAC_NAME)) {
        Ok(file) => {
            // A code is 64 characters; never read more than a little over that.
            file.take(256)
                .read_to_string(&mut given)
                .map_err(|e| BackupError::Unauthenticated(format!("{MAC_NAME} isn't text: {e}")))?;
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            return Err(BackupError::Unauthenticated(format!(
                "the archive has no {MAC_NAME}: it was made before archives were authenticated, \
                 or not by a server holding this server.key"
            )));
        }
        Err(e) => {
            return Err(BackupError::io(
                format!("can't read {}", dir.join(MAC_NAME).display()),
                e,
            ));
        }
    }
    if same_code(given.trim(), &expected) {
        Ok(())
    } else {
        Err(BackupError::Unauthenticated(format!(
            "the archive's {MAC_NAME} is not the one this server.key makes for its manifest: the \
             archive was made by a server with another key, or was changed"
        )))
    }
}

/// A reader that hashes and counts what passes through it, so a file is read once for the archive
/// and for its manifest entry.
pub(crate) struct HashingReader<R> {
    inner: R,
    hasher: Sha256,
    len: u64,
}

impl<R> HashingReader<R> {
    pub(crate) fn new(inner: R) -> Self {
        HashingReader {
            inner,
            hasher: Sha256::new(),
            len: 0,
        }
    }

    pub(crate) fn len(&self) -> u64 {
        self.len
    }

    pub(crate) fn finish(self) -> String {
        hex::encode(self.hasher.finalize())
    }
}

impl<R: Read> Read for HashingReader<R> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let n = self.inner.read(buf)?;
        self.hasher.update(&buf[..n]);
        self.len += n as u64;
        Ok(n)
    }
}

/// The SHA-256 of a file's bytes, as lower-case hex, and its size.
pub fn hash_file(path: &Path) -> Result<(String, u64), BackupError> {
    let file = std::fs::File::open(path)
        .map_err(|e| BackupError::io(format!("can't read {}", path.display()), e))?;
    let mut reader = HashingReader::new(file);
    std::io::copy(&mut reader, &mut std::io::sink())
        .map_err(|e| BackupError::io(format!("can't read {}", path.display()), e))?;
    let len = reader.len();
    Ok((reader.finish(), len))
}

/// SHA-256 of bytes in memory, as lower-case hex.
pub fn hash_bytes(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> Manifest {
        Manifest {
            format: MANIFEST_FORMAT,
            created_at: "2026-11-23T03:00:00Z".to_owned(),
            kemlock_version: "0.1.0".to_owned(),
            database: "sqlite".to_owned(),
            migrations: vec!["m1".to_owned()],
            tables: vec![
                TableEntry {
                    name: "users".to_owned(),
                    rows: 2,
                    columns: vec!["id".to_owned()],
                },
                TableEntry {
                    name: "items".to_owned(),
                    rows: 5,
                    columns: vec!["id".to_owned(), "kind".to_owned()],
                },
            ],
            files: vec![FileEntry {
                path: "data/opaque-setup.sealed".to_owned(),
                size: 3,
                sha256: hash_bytes(b"abc"),
            }],
            attachments: Attachments::External,
        }
    }

    #[test]
    fn hmac_sha256_matches_rfc_4231() {
        let mut data: &[u8] = b"Hi There";
        assert_eq!(
            hmac_sha256_hex(&[0x0b; 20], &mut data).expect("hashes"),
            "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7"
        );
        let mut data: &[u8] = b"what do ya want for nothing?";
        assert_eq!(
            hmac_sha256_hex(b"Jefe", &mut data).expect("hashes"),
            "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"
        );
    }

    #[test]
    fn a_manifest_is_authentic_only_under_the_key_that_made_its_code() {
        let dir = tempfile::tempdir().expect("a temp dir");
        let manifest = sample().to_json().expect("json");
        let key = MacKey::new([7; 32]);
        std::fs::write(dir.path().join(MANIFEST_NAME), &manifest).expect("manifest");

        // No code at all.
        let err = check_manifest_mac(dir.path(), &key).expect_err("no code");
        assert!(matches!(&err, BackupError::Unauthenticated(m) if m.contains("no manifest.mac")), "{err}");

        // The right code, with the newline an editor might add.
        let code = manifest_mac(&key, &manifest);
        assert_eq!(code.len(), 64);
        std::fs::write(dir.path().join(MAC_NAME), format!("{code}\n")).expect("code");
        check_manifest_mac(dir.path(), &key).expect("authentic");

        // Another key.
        let err = check_manifest_mac(dir.path(), &MacKey::new([8; 32])).expect_err("another key");
        assert!(matches!(&err, BackupError::Unauthenticated(_)), "{err}");

        // A manifest changed after the code was made.
        let mut edited = sample();
        edited.files[0].sha256 = hash_bytes(b"planted");
        std::fs::write(dir.path().join(MANIFEST_NAME), edited.to_json().expect("json"))
            .expect("manifest");
        let err = check_manifest_mac(dir.path(), &key).expect_err("a changed manifest");
        assert!(matches!(&err, BackupError::Unauthenticated(_)), "{err}");

        // Garbage and a huge code file are wrong codes, not a crash or a big read.
        std::fs::write(dir.path().join(MANIFEST_NAME), &manifest).expect("manifest");
        std::fs::write(dir.path().join(MAC_NAME), vec![b'a'; 100_000]).expect("code");
        assert!(check_manifest_mac(dir.path(), &key).is_err());
        std::fs::write(dir.path().join(MAC_NAME), [0xff, 0xfe, 0x00]).expect("code");
        assert!(check_manifest_mac(dir.path(), &key).is_err());
    }

    #[test]
    fn a_manifest_round_trips_and_counts_its_rows() {
        let manifest = sample();
        let back = Manifest::from_json(&manifest.to_json().expect("writes")).expect("reads");
        assert_eq!(back, manifest);
        assert_eq!(back.total_rows(), 7);
    }

    #[test]
    fn counts_that_overflow_saturate_instead_of_panicking() {
        let mut manifest = sample();
        manifest.tables[0].rows = u64::MAX;
        assert_eq!(manifest.total_rows(), u64::MAX);
    }

    #[test]
    fn json_uses_camel_case_names() {
        let text = String::from_utf8(sample().to_json().expect("writes")).expect("utf-8");
        assert!(text.contains("\"createdAt\""), "{text}");
        assert!(text.contains("\"kemlockVersion\""), "{text}");
        assert!(text.contains("\"external\""), "{text}");
    }

    #[test]
    fn another_format_or_garbage_is_refused() {
        let mut other = sample();
        other.format = 99;
        let bytes = other.to_json().expect("writes");
        assert!(matches!(
            Manifest::from_json(&bytes),
            Err(BackupError::Manifest(_))
        ));
        assert!(matches!(
            Manifest::from_json(b"{}"),
            Err(BackupError::Manifest(_))
        ));
    }

    #[test]
    fn hashes_match_the_known_answer_and_the_streaming_reader() {
        assert_eq!(
            hash_bytes(b"abc"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
        let mut reader = HashingReader::new(&b"abc"[..]);
        let mut sink = Vec::new();
        reader.read_to_end(&mut sink).expect("reads");
        assert_eq!(reader.len(), 3);
        assert_eq!(reader.finish(), hash_bytes(b"abc"));
    }

    #[test]
    fn a_file_hashes_to_its_bytes() {
        let dir = tempfile::tempdir().expect("a temp dir");
        let path = dir.path().join("f");
        std::fs::write(&path, b"abc").expect("written");
        assert_eq!(hash_file(&path).expect("hashes"), (hash_bytes(b"abc"), 3));
    }
}
