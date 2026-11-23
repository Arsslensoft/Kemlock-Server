//! The archive: a tar, compressed with zstd, encrypted to an age recipient.
//!
//! ```text
//! manifest.json             row counts and file hashes (the last entry)
//! db/<table>.jsonl          the database as plain rows (kemlock-store-sql's snapshot)
//! data/<name>               the data folder's files: the sealed key files, the TOML file's
//!                           neighbours; never server.key and never the database file itself
//! attachments/...           the attachment folder, when files are on disk
//! config/<name>             the TOML configuration file, when there is one
//! ```
//!
//! The server holds only the public recipient, so it cannot read an archive it made. `server.key`
//! is never in one: a restore needs the operator to bring it, because it seals the OPAQUE server
//! secret and the other secrets the server must read.
//!
//! Everything here is blocking: call it from `spawn_blocking`.

use crate::error::BackupError;
use crate::manifest::{
    Attachments, FileEntry, HashingReader, MANIFEST_FORMAT, MANIFEST_NAME, Manifest, TableEntry,
    hash_bytes, hash_file,
};
use age::x25519::{Identity, Recipient};
use kemlock_store_sql::Snapshot;
use std::fs::File;
use std::io::{BufReader, BufWriter, Write};
use std::path::{Component, Path, PathBuf};
use std::str::FromStr;
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;

/// The data folder's file that never goes into an archive.
pub const SERVER_KEY_FILE: &str = "server.key";

/// What goes into an archive.
#[derive(Debug)]
pub struct ArchiveSpec<'a> {
    /// What the snapshot says it wrote.
    pub snapshot: &'a Snapshot,
    /// The folder the snapshot's `<table>.jsonl` files are in.
    pub rows: &'a Path,
    pub data_folder: &'a Path,
    /// Files of the data folder to leave out besides `server.key`: the SQLite database and its
    /// `-wal` and `-shm` files.
    pub skip: &'a [PathBuf],
    /// The attachments folder, when files are on disk; `None` when they are in a bucket.
    pub attachments: Option<&'a Path>,
    pub config_file: Option<&'a Path>,
    pub recipient: &'a Recipient,
    /// zstd's level: 3 by default, 1 on a small machine.
    pub zstd_level: i32,
    pub created_at: OffsetDateTime,
}

/// An age recipient (`age1...`), the public half of the operator's backup key.
pub fn parse_recipient(text: &str) -> Result<Recipient, BackupError> {
    if text.trim().is_empty() {
        return Err(BackupError::Key(
            "no age recipient is set: put your age public key (age1...) in KEMLOCK_BACKUP_RECIPIENT"
                .to_owned(),
        ));
    }
    Recipient::from_str(text.trim())
        .map_err(|e| BackupError::Key(format!("the backup recipient isn't an age public key: {e}")))
}

/// An age identity (`AGE-SECRET-KEY-1...`): the secret half of the backup key, from an identity
/// file as `age-keygen` writes it (comment lines are skipped) or the bare key.
pub fn parse_identity(text: &str) -> Result<Identity, BackupError> {
    let line = text
        .lines()
        .map(str::trim)
        .find(|l| !l.is_empty() && !l.starts_with('#'))
        .ok_or_else(|| BackupError::Key("the identity file holds no key".to_owned()))?;
    Identity::from_str(line).map_err(|e| BackupError::Key(format!("not an age identity: {e}")))
}

fn age_error(e: impl std::fmt::Display) -> BackupError {
    BackupError::Age(e.to_string())
}

/// A path as it is written in an archive: `/`-separated.
fn archive_path(prefix: &str, relative: &Path) -> String {
    let mut out = prefix.to_owned();
    for part in relative.components() {
        if let Component::Normal(p) = part {
            out.push('/');
            out.push_str(&p.to_string_lossy());
        }
    }
    out
}

/// The regular files under `folder`, in a stable order.
fn walk(folder: &Path) -> Result<Vec<PathBuf>, BackupError> {
    let mut out = Vec::new();
    let mut pending = vec![folder.to_path_buf()];
    while let Some(dir) = pending.pop() {
        let entries = std::fs::read_dir(&dir)
            .map_err(|e| BackupError::io(format!("can't read {}", dir.display()), e))?;
        for entry in entries {
            let entry =
                entry.map_err(|e| BackupError::io(format!("can't read {}", dir.display()), e))?;
            let path = entry.path();
            let kind = entry
                .file_type()
                .map_err(|e| BackupError::io(format!("can't read {}", path.display()), e))?;
            if kind.is_dir() {
                pending.push(path);
            } else if kind.is_file() {
                out.push(path);
            }
        }
    }
    out.sort();
    Ok(out)
}

/// The files directly in the data folder that go into an archive.
fn data_files(spec: &ArchiveSpec<'_>) -> Result<Vec<PathBuf>, BackupError> {
    let mut out = Vec::new();
    let entries = std::fs::read_dir(spec.data_folder)
        .map_err(|e| BackupError::io(format!("can't read {}", spec.data_folder.display()), e))?;
    for entry in entries {
        let entry = entry.map_err(|e| {
            BackupError::io(format!("can't read {}", spec.data_folder.display()), e)
        })?;
        let path = entry.path();
        let is_file = entry.file_type().is_ok_and(|t| t.is_file());
        let name = entry.file_name();
        let skipped = spec.skip.iter().any(|s| s == &path);
        let temporary = name.to_string_lossy().ends_with(".tmp");
        if is_file && name != SERVER_KEY_FILE && !skipped && !temporary {
            out.push(path);
        }
    }
    out.sort();
    Ok(out)
}

fn append_bytes<W: Write>(
    tar: &mut tar::Builder<W>,
    name: &str,
    bytes: &[u8],
) -> Result<FileEntry, BackupError> {
    let mut header = tar::Header::new_gnu();
    header.set_size(bytes.len() as u64);
    header.set_mode(0o600);
    header.set_mtime(0);
    tar.append_data(&mut header, name, bytes)
        .map_err(|e| BackupError::io(format!("can't add {name} to the archive"), e))?;
    Ok(FileEntry {
        path: name.to_owned(),
        size: bytes.len() as u64,
        sha256: hash_bytes(bytes),
    })
}

fn append_file<W: Write>(
    tar: &mut tar::Builder<W>,
    path: &Path,
    name: &str,
) -> Result<FileEntry, BackupError> {
    let file = File::open(path)
        .map_err(|e| BackupError::io(format!("can't read {}", path.display()), e))?;
    let size = file
        .metadata()
        .map_err(|e| BackupError::io(format!("can't read {}", path.display()), e))?
        .len();
    let mut header = tar::Header::new_gnu();
    header.set_size(size);
    header.set_mode(0o600);
    header.set_mtime(0);
    let mut reader = HashingReader::new(file);
    tar.append_data(&mut header, name, &mut reader)
        .map_err(|e| BackupError::io(format!("can't add {name} to the archive"), e))?;
    if reader.len() != size {
        return Err(BackupError::Verify(format!(
            "{} changed while it was being read",
            path.display()
        )));
    }
    Ok(FileEntry {
        path: name.to_owned(),
        size,
        sha256: reader.finish(),
    })
}

/// Writes the archive to `out` and returns its manifest.
pub fn write_archive(spec: &ArchiveSpec<'_>, out: &Path) -> Result<Manifest, BackupError> {
    let file = File::create(out)
        .map_err(|e| BackupError::io(format!("can't write {}", out.display()), e))?;
    let encryptor =
        age::Encryptor::with_recipients(std::iter::once(spec.recipient as &dyn age::Recipient))
            .map_err(age_error)?;
    let encrypted = encryptor
        .wrap_output(BufWriter::new(file))
        .map_err(|e| BackupError::io("can't start the encrypted archive", e))?;
    let compressed = zstd::stream::write::Encoder::new(encrypted, spec.zstd_level)
        .map_err(|e| BackupError::io("can't start compressing", e))?;
    let mut tar = tar::Builder::new(compressed);

    let mut files = Vec::new();
    let mut tables = Vec::new();
    for table in &spec.snapshot.tables {
        if !TableEntry::is_valid_name(&table.name) {
            return Err(BackupError::Manifest(format!(
                "{:?} isn't a table name this server writes",
                table.name
            )));
        }
        let path = spec.rows.join(format!("{}.jsonl", table.name));
        files.push(append_file(
            &mut tar,
            &path,
            &format!("db/{}.jsonl", table.name),
        )?);
        tables.push(TableEntry {
            name: table.name.clone(),
            rows: table.rows,
            columns: table.columns.clone(),
        });
    }
    for path in data_files(spec)? {
        let name = path
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_default();
        files.push(append_file(&mut tar, &path, &format!("data/{name}"))?);
    }
    if let Some(folder) = spec.attachments
        && folder.is_dir()
    {
        for path in walk(folder)? {
            let relative = path.strip_prefix(folder).unwrap_or(&path);
            files.push(append_file(
                &mut tar,
                &path,
                &archive_path("attachments", relative),
            )?);
        }
    }
    if let Some(config) = spec.config_file
        && config.is_file()
    {
        let name = config
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_default();
        files.push(append_file(&mut tar, config, &format!("config/{name}"))?);
    }

    let manifest = Manifest {
        format: MANIFEST_FORMAT,
        created_at: spec
            .created_at
            .format(&Rfc3339)
            .map_err(|e| BackupError::Manifest(e.to_string()))?,
        kemlock_version: env!("CARGO_PKG_VERSION").to_owned(),
        database: spec.snapshot.database.to_owned(),
        migrations: spec.snapshot.migrations.clone(),
        tables,
        files,
        attachments: if spec.attachments.is_some() {
            Attachments::Included
        } else {
            Attachments::External
        },
    };
    append_bytes(&mut tar, MANIFEST_NAME, &manifest.to_json()?)?;

    let compressed = tar
        .into_inner()
        .map_err(|e| BackupError::io("can't finish the archive", e))?;
    let encrypted = compressed
        .finish()
        .map_err(|e| BackupError::io("can't finish compressing", e))?;
    let buffered = encrypted
        .finish()
        .map_err(|e| BackupError::io("can't finish encrypting", e))?;
    let file = buffered
        .into_inner()
        .map_err(|e| BackupError::io("can't flush the archive", e.into_error()))?;
    file.sync_all()
        .map_err(|e| BackupError::io(format!("can't sync {}", out.display()), e))?;
    Ok(manifest)
}

/// A path from an archive that stays inside the folder it is unpacked into, or `None`.
fn safe_relative(path: &Path) -> Option<PathBuf> {
    let mut out = PathBuf::new();
    for part in path.components() {
        match part {
            Component::Normal(p) => out.push(p),
            _ => return None,
        }
    }
    (!out.as_os_str().is_empty()).then_some(out)
}

/// Decrypts, decompresses and unpacks `archive` into `dest`. Only plain files go out, and only to
/// paths inside `dest`; anything else in the archive stops the restore.
pub fn read_archive(archive: &Path, identity: &Identity, dest: &Path) -> Result<(), BackupError> {
    let file = File::open(archive)
        .map_err(|e| BackupError::io(format!("can't read {}", archive.display()), e))?;
    let decryptor = age::Decryptor::new(BufReader::new(file)).map_err(age_error)?;
    let decrypted = decryptor
        .decrypt(std::iter::once(identity as &dyn age::Identity))
        .map_err(age_error)?;
    let decompressed = zstd::stream::read::Decoder::new(decrypted)
        .map_err(|e| BackupError::io("can't start decompressing", e))?;
    let mut tar = tar::Archive::new(decompressed);
    let entries = tar
        .entries()
        .map_err(|e| BackupError::io("can't read the archive", e))?;
    for entry in entries {
        let mut entry = entry.map_err(|e| BackupError::io("can't read the archive", e))?;
        let path = entry
            .path()
            .map_err(|e| BackupError::io("can't read an entry's name", e))?
            .into_owned();
        if !entry.header().entry_type().is_file() {
            return Err(BackupError::Verify(format!(
                "{} is not a plain file",
                path.display()
            )));
        }
        let relative = safe_relative(&path).ok_or_else(|| {
            BackupError::Verify(format!("{} leaves the restore folder", path.display()))
        })?;
        let target = dest.join(&relative);
        if let Some(parent) = target.parent() {
            std::fs::create_dir_all(parent)
                .map_err(|e| BackupError::io(format!("can't make {}", parent.display()), e))?;
        }
        let mut out = File::create(&target)
            .map_err(|e| BackupError::io(format!("can't write {}", target.display()), e))?;
        std::io::copy(&mut entry, &mut out)
            .map_err(|e| BackupError::io(format!("can't write {}", target.display()), e))?;
        out.flush()
            .map_err(|e| BackupError::io(format!("can't write {}", target.display()), e))?;
    }
    Ok(())
}

/// Checks an unpacked archive against its manifest: every file is there with the size and SHA-256
/// the manifest says, and every table's file holds the rows it counts. Returns the manifest.
pub fn verify_unpacked(dir: &Path) -> Result<Manifest, BackupError> {
    let manifest_path = dir.join(MANIFEST_NAME);
    let bytes = std::fs::read(&manifest_path)
        .map_err(|e| BackupError::Manifest(format!("the archive has no {MANIFEST_NAME}: {e}")))?;
    let manifest = Manifest::from_json(&bytes)?;
    // Names go into paths below; a manifest built by hand skips `from_json`'s check, so repeat it.
    manifest.check_names()?;

    for entry in &manifest.files {
        let relative = safe_relative(Path::new(&entry.path)).ok_or_else(|| {
            BackupError::Verify(format!("{} isn't a path inside the archive", entry.path))
        })?;
        let path = dir.join(relative);
        if !path.is_file() {
            return Err(BackupError::Verify(format!("{} is missing", entry.path)));
        }
        let (sha256, size) = hash_file(&path)?;
        if size != entry.size {
            return Err(BackupError::Verify(format!(
                "{} is {size} bytes, the manifest says {}",
                entry.path, entry.size
            )));
        }
        if sha256 != entry.sha256 {
            return Err(BackupError::Verify(format!(
                "{}'s hash is not the manifest's",
                entry.path
            )));
        }
    }
    for table in &manifest.tables {
        let path = dir.join("db").join(format!("{}.jsonl", table.name));
        let text = std::fs::read_to_string(&path)
            .map_err(|e| BackupError::Verify(format!("db/{}.jsonl: {e}", table.name)))?;
        // The first line names the columns; every other line is a row.
        let rows = text
            .lines()
            .filter(|l| !l.is_empty())
            .count()
            .saturating_sub(1) as u64;
        if rows != table.rows {
            return Err(BackupError::Verify(format!(
                "{} holds {rows} rows, the manifest says {}",
                table.name, table.rows
            )));
        }
    }
    Ok(manifest)
}

#[cfg(test)]
mod tests {
    use super::*;
    use kemlock_store_sql::SnapshotTable;
    use time::macros::datetime;

    fn rows_file(dir: &Path, table: &str, rows: &[&str]) {
        std::fs::create_dir_all(dir).expect("a folder");
        let mut text = format!("{{\"table\":\"{table}\",\"columns\":[\"id\"]}}\n");
        for row in rows {
            text.push_str(row);
            text.push('\n');
        }
        std::fs::write(dir.join(format!("{table}.jsonl")), text).expect("written");
    }

    struct Fixture {
        _root: tempfile::TempDir,
        rows: PathBuf,
        data: PathBuf,
        attachments: PathBuf,
        config: PathBuf,
        snapshot: Snapshot,
    }

    fn fixture() -> Fixture {
        let root = tempfile::tempdir().expect("a temp dir");
        let rows = root.path().join("rows");
        rows_file(&rows, "users", &["[\"a\"]", "[\"b\"]"]);
        rows_file(&rows, "items", &[]);
        let data = root.path().join("data");
        std::fs::create_dir_all(&data).expect("a folder");
        std::fs::write(data.join("server.key"), b"SECRET-KEY").expect("key");
        std::fs::write(data.join("opaque-setup.sealed"), b"sealed-opaque").expect("sealed");
        std::fs::write(data.join("db.sqlite3"), b"the database").expect("db");
        std::fs::write(data.join("db.sqlite3-wal"), b"wal").expect("wal");
        std::fs::write(data.join("half.tmp"), b"tmp").expect("tmp");
        std::fs::create_dir_all(data.join("backups")).expect("a folder");
        std::fs::write(data.join("backups").join("old.age"), b"old").expect("old");
        let attachments = data.join("attachments");
        std::fs::create_dir_all(attachments.join("ab")).expect("a folder");
        std::fs::write(attachments.join("ab").join("abcdef"), b"blob bytes").expect("blob");
        let config = root.path().join("kemlock.toml");
        std::fs::write(&config, b"port = 8080\n").expect("config");
        let snapshot = Snapshot {
            database: "sqlite",
            migrations: vec!["m1".to_owned()],
            tables: vec![
                SnapshotTable {
                    name: "users".to_owned(),
                    columns: vec!["id".to_owned()],
                    rows: 2,
                },
                SnapshotTable {
                    name: "items".to_owned(),
                    columns: vec!["id".to_owned()],
                    rows: 0,
                },
            ],
        };
        Fixture {
            _root: root,
            rows,
            data,
            attachments,
            config,
            snapshot,
        }
    }

    fn spec<'a>(f: &'a Fixture, recipient: &'a Recipient, skip: &'a [PathBuf]) -> ArchiveSpec<'a> {
        ArchiveSpec {
            snapshot: &f.snapshot,
            rows: &f.rows,
            data_folder: &f.data,
            skip,
            attachments: Some(&f.attachments),
            config_file: Some(&f.config),
            recipient,
            zstd_level: 1,
            created_at: datetime!(2026-11-23 03:00 UTC),
        }
    }

    fn skip_list(f: &Fixture) -> Vec<PathBuf> {
        vec![f.data.join("db.sqlite3"), f.data.join("db.sqlite3-wal")]
    }

    #[test]
    fn an_archive_round_trips_through_age_and_checks_against_its_manifest() {
        let f = fixture();
        let identity = Identity::generate();
        let recipient = identity.to_public();
        let skip = skip_list(&f);
        let out = f._root.path().join("out.tar.zst.age");

        let manifest = write_archive(&spec(&f, &recipient, &skip), &out).expect("written");

        assert_eq!(manifest.tables.len(), 2);
        assert_eq!(manifest.total_rows(), 2);
        assert_eq!(manifest.attachments, Attachments::Included);
        let paths: Vec<&str> = manifest.files.iter().map(|e| e.path.as_str()).collect();
        assert!(paths.contains(&"db/users.jsonl"));
        assert!(paths.contains(&"data/opaque-setup.sealed"));
        assert!(paths.contains(&"attachments/ab/abcdef"));
        assert!(paths.contains(&"config/kemlock.toml"));
        // Never the key, the database itself, its WAL, a temporary file or earlier backups.
        for left_out in [
            "data/server.key",
            "data/db.sqlite3",
            "data/db.sqlite3-wal",
            "data/half.tmp",
            "data/old.age",
        ] {
            assert!(!paths.contains(&left_out), "{left_out}");
        }

        let unpacked = f._root.path().join("unpacked");
        read_archive(&out, &identity, &unpacked).expect("read");
        let back = verify_unpacked(&unpacked).expect("checks out");
        assert_eq!(back, manifest);
        assert_eq!(
            std::fs::read(unpacked.join("attachments/ab/abcdef")).expect("a file"),
            b"blob bytes"
        );
        assert!(!unpacked.join("data/server.key").exists());
    }

    #[test]
    fn the_archive_is_ciphertext_and_only_its_identity_opens_it() {
        let f = fixture();
        let identity = Identity::generate();
        let skip = skip_list(&f);
        let out = f._root.path().join("out.age");
        write_archive(&spec(&f, &identity.to_public(), &skip), &out).expect("written");

        let bytes = std::fs::read(&out).expect("the archive");
        assert!(bytes.starts_with(b"age-encryption.org/v1"));
        let text = String::from_utf8_lossy(&bytes);
        assert!(!text.contains("sealed-opaque"));
        assert!(!text.contains("opaque-setup"));

        let stranger = Identity::generate();
        let refused = read_archive(&out, &stranger, &f._root.path().join("nope"));
        assert!(matches!(refused, Err(BackupError::Age(_))), "{refused:?}");
    }

    #[test]
    fn a_changed_file_fails_the_check() {
        let f = fixture();
        let identity = Identity::generate();
        let skip = skip_list(&f);
        let out = f._root.path().join("out.age");
        write_archive(&spec(&f, &identity.to_public(), &skip), &out).expect("written");
        let unpacked = f._root.path().join("unpacked");
        read_archive(&out, &identity, &unpacked).expect("read");

        // Same size, other bytes: the hash catches it.
        std::fs::write(unpacked.join("data/opaque-setup.sealed"), b"SEALED-OPAQUE")
            .expect("edited");
        let err = verify_unpacked(&unpacked).expect_err("a different hash");
        assert!(
            matches!(&err, BackupError::Verify(m) if m.contains("hash")),
            "{err}"
        );

        // A missing file and a short file.
        std::fs::write(unpacked.join("data/opaque-setup.sealed"), b"sealed-opaque")
            .expect("restored");
        std::fs::write(unpacked.join("attachments/ab/abcdef"), b"short").expect("edited");
        let err = verify_unpacked(&unpacked).expect_err("a different size");
        assert!(
            matches!(&err, BackupError::Verify(m) if m.contains("bytes")),
            "{err}"
        );
        std::fs::remove_file(unpacked.join("attachments/ab/abcdef")).expect("removed");
        let err = verify_unpacked(&unpacked).expect_err("a missing file");
        assert!(
            matches!(&err, BackupError::Verify(m) if m.contains("missing")),
            "{err}"
        );
    }

    #[test]
    fn a_table_file_that_lost_a_row_fails_the_check() {
        let f = fixture();
        let identity = Identity::generate();
        let skip = skip_list(&f);
        let out = f._root.path().join("out.age");
        let manifest =
            write_archive(&spec(&f, &identity.to_public(), &skip), &out).expect("written");
        let unpacked = f._root.path().join("unpacked");
        read_archive(&out, &identity, &unpacked).expect("read");

        // Rewrite the file and its manifest entry so only the row count disagrees.
        let path = unpacked.join("db/users.jsonl");
        std::fs::write(
            &path,
            "{\"table\":\"users\",\"columns\":[\"id\"]}\n[\"a\"]\n",
        )
        .expect("edited");
        let mut edited = manifest.clone();
        let (sha256, size) = hash_file(&path).expect("hashes");
        let entry = edited
            .files
            .iter_mut()
            .find(|e| e.path == "db/users.jsonl")
            .expect("entry");
        entry.sha256 = sha256;
        entry.size = size;
        std::fs::write(
            unpacked.join(MANIFEST_NAME),
            edited.to_json().expect("json"),
        )
        .expect("manifest");

        let err = verify_unpacked(&unpacked).expect_err("a row is missing");
        assert!(
            matches!(&err, BackupError::Verify(m) if m.contains("rows")),
            "{err}"
        );
    }

    #[test]
    fn external_attachments_and_no_config_leave_those_entries_out() {
        let f = fixture();
        let identity = Identity::generate();
        let recipient = identity.to_public();
        let skip = skip_list(&f);
        let out = f._root.path().join("out.age");
        let spec = ArchiveSpec {
            attachments: None,
            config_file: None,
            ..spec(&f, &recipient, &skip)
        };
        let manifest = write_archive(&spec, &out).expect("written");
        assert_eq!(manifest.attachments, Attachments::External);
        assert!(
            manifest
                .files
                .iter()
                .all(|e| !e.path.starts_with("attachments/"))
        );
        assert!(
            manifest
                .files
                .iter()
                .all(|e| !e.path.starts_with("config/"))
        );
    }

    #[test]
    fn keys_parse_the_way_age_keygen_writes_them() {
        let identity = Identity::generate();
        let secret = {
            use age::secrecy::ExposeSecret;
            identity.to_string().expose_secret().to_owned()
        };
        let file = format!(
            "# created: now\n# public key: {}\n{secret}\n",
            identity.to_public()
        );
        let parsed = parse_identity(&file).expect("parses");
        assert_eq!(
            parsed.to_public().to_string(),
            identity.to_public().to_string()
        );
        assert!(parse_identity("# only a comment\n").is_err());
        assert!(parse_identity("AGE-SECRET-KEY-1nope").is_err());

        let recipient = identity.to_public().to_string();
        assert!(parse_recipient(&format!(" {recipient}\n")).is_ok());
        assert!(parse_recipient("age1nope").is_err());
        assert!(parse_recipient(&secret).is_err());
    }

    #[test]
    fn a_manifest_table_name_that_climbs_out_is_refused() {
        let f = fixture();
        let identity = Identity::generate();
        let skip = skip_list(&f);
        let out = f._root.path().join("out.age");
        let manifest =
            write_archive(&spec(&f, &identity.to_public(), &skip), &out).expect("written");
        let unpacked = f._root.path().join("unpacked");
        read_archive(&out, &identity, &unpacked).expect("read");
        // A file the traversal would reach: <unpacked>/db/../x.jsonl is <unpacked>/x.jsonl.
        std::fs::write(unpacked.join("x.jsonl"), "{}\n").expect("planted");

        for bad in ["../x", "/abs", "a/b", "..", "", "Users", "a.b"] {
            let mut edited = manifest.clone();
            edited.tables[0].name = bad.to_owned();
            std::fs::write(
                unpacked.join(MANIFEST_NAME),
                edited.to_json().expect("json"),
            )
            .expect("manifest");
            let err = verify_unpacked(&unpacked).expect_err(bad);
            assert!(
                matches!(&err, BackupError::Manifest(m) if m.contains("table name")),
                "{bad}: {err}"
            );
            assert!(Manifest::from_json(&edited.to_json().expect("json")).is_err());
        }
        assert!(!TableEntry::is_valid_name(&"a".repeat(65)));
        assert!(TableEntry::is_valid_name("item_revisions2"));
    }

    #[test]
    fn paths_that_leave_the_folder_are_refused() {
        assert_eq!(
            safe_relative(Path::new("data/x")),
            Some(PathBuf::from("data/x"))
        );
        assert_eq!(safe_relative(Path::new("../x")), None);
        assert_eq!(safe_relative(Path::new("/etc/passwd")), None);
        assert_eq!(safe_relative(Path::new("a/../../x")), None);
        assert_eq!(safe_relative(Path::new("")), None);
    }
}
