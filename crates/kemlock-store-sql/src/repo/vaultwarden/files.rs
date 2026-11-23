//! Files: attachments and Send files copied under the data folder, and `rsa_key.pem`.

use super::{Ctx, ImportError, Res, invalid};
use kemlock_vaultwarden::mapping::{FileCopy, MappedRsaKey};
use std::io::Write;
use std::path::{Path, PathBuf};

fn io(what: impl Into<String>) -> impl FnOnce(std::io::Error) -> ImportError {
    let what = what.into();
    move |source| ImportError::Io { what, source }
}

/// Where a file goes: `root` and the `/`-separated parts of its storage key, which may only be
/// letters, digits, `-` and `_`, so a key can't leave the folder.
fn destination(root: &Path, storage_key: &str) -> Res<PathBuf> {
    let mut path = root.to_path_buf();
    let mut parts = 0;
    for part in storage_key.split('/') {
        let ok = !part.is_empty()
            && part
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_');
        if !ok {
            return Err(invalid(format!(
                "{storage_key:?} is not a file name Kemlock keeps"
            )));
        }
        path.push(part);
        parts += 1;
    }
    if parts < 2 {
        return Err(invalid(format!(
            "{storage_key:?} is not a file name Kemlock keeps"
        )));
    }
    Ok(path)
}

/// The key the Bitwarden API's blob store names a file by: an attachment's storage key without
/// its `attachments/` (the API keeps `<cipher id>/<attachment id>`), a Send file's as it is.
fn blob_key(storage_key: &str) -> Res<String> {
    destination(Path::new(""), storage_key)?;
    Ok(storage_key
        .strip_prefix("attachments/")
        .unwrap_or(storage_key)
        .to_owned())
}

fn refused(what: &str, key: &str) -> impl FnOnce(String) -> ImportError {
    let text = format!("{what} {key}");
    move |reason| invalid(format!("{text}: {reason}"))
}

/// Copies a file unchanged to where the Bitwarden API reads it: into its blob store, by the key the
/// API names it with, so a rerun puts the same bytes again.
pub(super) async fn copy_file(ctx: &Ctx, file: &FileCopy) -> Res<()> {
    let key = blob_key(&file.storage_key)?;
    let bytes = tokio::fs::read(&file.from)
        .await
        .map_err(io(format!("can't read {}", file.from.display())))?;
    ctx.opts
        .files
        .put(&key, bytes)
        .await
        .map_err(refused("can't store", &key))
}

/// Removes a copied file from the blob store, if it is there.
pub(super) async fn remove_file(ctx: &Ctx, storage_key: &str) -> Res<()> {
    let key = blob_key(storage_key)?;
    ctx.opts
        .files
        .delete(&key)
        .await
        .map_err(refused("can't remove", &key))
}

/// Writes `bytes` to `path` through a file beside it. A file with those bytes already is left
/// alone. `private` keeps it readable by its owner only, on systems that have such a mode.
fn write_file(path: &Path, bytes: &[u8], private: bool) -> Res<()> {
    if std::fs::read(path).is_ok_and(|existing| existing == bytes) {
        return Ok(());
    }
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(io(format!("can't make {}", parent.display())))?;
    }
    let part = path.with_extension("pem.part");
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        if private {
            options.mode(0o600);
        }
    }
    #[cfg(not(unix))]
    let _ = private;
    let mut file = options
        .open(&part)
        .map_err(io(format!("can't write {}", part.display())))?;
    file.write_all(bytes)
        .and_then(|()| file.sync_all())
        .map_err(io(format!("can't write {}", part.display())))?;
    drop(file);
    std::fs::rename(&part, path).map_err(io(format!("can't move {} into place", path.display())))
}

/// Keeps `rsa_key.pem` (and `rsa_key.pub.pem` when there is one) in the data folder, where the
/// Bitwarden API reads its token key, so the tokens Bitwarden apps hold still verify. A server
/// that is already running keeps the key it loaded until it restarts.
pub(super) async fn put_rsa_key(ctx: &Ctx, key: &MappedRsaKey) -> Res<()> {
    let root = &ctx.opts.files_root;
    write_file(&root.join("rsa_key.pem"), &key.private_pem, true)?;
    if let Some(public) = &key.public_pem {
        write_file(&root.join("rsa_key.pub.pem"), public, false)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn storage_keys_stay_inside_the_folder() {
        let root = Path::new("data");
        assert_eq!(
            destination(root, "attachments/cipher-1/att0001").expect("a plain key"),
            root.join("attachments").join("cipher-1").join("att0001")
        );
        for bad in [
            "",
            "attachments",
            "attachments/../x",
            "/etc/passwd",
            "attachments//x",
            "attachments/a.b",
            "attachments/a b",
            "attachments\\x",
        ] {
            assert!(destination(root, bad).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn a_file_is_written_once_and_replaced_when_it_differs() {
        let dir = tempfile::tempdir().expect("a temp dir");
        let path = dir.path().join("rsa_key.pem");
        write_file(&path, b"one", true).expect("writes");
        assert_eq!(std::fs::read(&path).expect("reads"), b"one");
        write_file(&path, b"one", true).expect("writes again");
        write_file(&path, b"two", true).expect("replaces");
        assert_eq!(std::fs::read(&path).expect("reads"), b"two");
        assert!(!dir.path().join("rsa_key.pem.part").exists());
    }
}
