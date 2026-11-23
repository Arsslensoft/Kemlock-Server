//! `server.key` and the secrets sealed under it.
//!
//! `data/server.key` is 32 random bytes (docs/crypto.md, "Server-side secrets"), made at first
//! start with mode 0600 on Unix, or taken from `KEMLOCK_SERVER_KEY` (64 hex characters or 43
//! base64url characters) so it can live in a mounted secret instead. Two secrets the API needs
//! are kept sealed under it in files, because the store has no settings API yet: the OPAQUE
//! server setup (`opaque-setup.sealed`, purpose `"opaque-setup"`) and the access-token signing
//! key (`token-signing-key.sealed`, purpose `"token-signing-key"`). Losing `server.key` loses
//! them, which signs everyone out and needs every OPAQUE account to register again, so the key is
//! never part of a backup and setup tells the admin to keep it apart.

use kemlock_app::b64url;
use kemlock_app::ports::Zeroizing;
use kemlock_crypto::ed25519::SigningKey;
use kemlock_crypto::opaque::OpaqueServer;
use kemlock_crypto::seal::{ServerSeal, generate_server_key};
use std::io::{self, Write};
use std::path::Path;

/// The key file's name inside the data folder.
pub const SERVER_KEY_FILE: &str = "server.key";
/// The sealed OPAQUE setup's file name.
pub const OPAQUE_SETUP_FILE: &str = "opaque-setup.sealed";
/// The sealed token signing key's file name.
pub const SIGNING_KEY_FILE: &str = "token-signing-key.sealed";
/// `SecretSeal` purpose of the OPAQUE setup.
pub const PURPOSE_OPAQUE_SETUP: &str = "opaque-setup";
/// `SecretSeal` purpose of the token signing key.
pub const PURPOSE_SIGNING_KEY: &str = "token-signing-key";

#[derive(Debug, thiserror::Error)]
pub enum KeyError {
    #[error("{what}: {source}")]
    Io {
        what: String,
        #[source]
        source: io::Error,
    },
    #[error("{0}")]
    Invalid(String),
}

fn io_error(what: impl Into<String>) -> impl FnOnce(io::Error) -> KeyError {
    let what = what.into();
    move |source| KeyError::Io { what, source }
}

fn hex_decode(text: &str) -> Option<Vec<u8>> {
    if !text.len().is_multiple_of(2) {
        return None;
    }
    text.as_bytes()
        .chunks(2)
        .map(|pair| {
            let digit = |b: u8| (b as char).to_digit(16);
            Some((digit(pair[0])? * 16 + digit(pair[1])?) as u8)
        })
        .collect()
}

/// Reads a server key given as 64 hex characters or 43 base64url characters.
pub fn parse_server_key(text: &str) -> Result<[u8; 32], KeyError> {
    let text = text.trim();
    let bytes = if text.len() == 64 {
        hex_decode(text)
    } else {
        b64url::decode(text)
    };
    bytes
        .and_then(|b| <[u8; 32]>::try_from(b).ok())
        .ok_or_else(|| {
            KeyError::Invalid(
                "the server key must be 32 bytes, as 64 hex characters or 43 base64url characters"
                    .to_owned(),
            )
        })
}

/// Opens a new file for private data: it must not exist, and on Unix only its owner can read it.
fn create_private(path: &Path) -> io::Result<std::fs::File> {
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    options.open(path)
}

/// The server key: `from_env` when set, else `<data>/server.key`, made if it doesn't exist.
pub fn load_or_create_server_key(
    data: &Path,
    from_env: Option<&str>,
) -> Result<[u8; 32], KeyError> {
    if let Some(text) = from_env {
        return parse_server_key(text);
    }
    let path = data.join(SERVER_KEY_FILE);
    let read = |path: &Path| -> Result<[u8; 32], KeyError> {
        let bytes =
            std::fs::read(path).map_err(io_error(format!("can't read {}", path.display())))?;
        <[u8; 32]>::try_from(bytes)
            .map_err(|_| KeyError::Invalid(format!("{} must be exactly 32 bytes", path.display())))
    };
    match create_private(&path) {
        Ok(mut file) => {
            let key = generate_server_key();
            file.write_all(&key)
                .and_then(|()| file.sync_all())
                .map_err(io_error(format!("can't write {}", path.display())))?;
            Ok(key)
        }
        // Made by another process (or an earlier start): use it.
        Err(e) if e.kind() == io::ErrorKind::AlreadyExists => read(&path),
        Err(e) => Err(KeyError::Io {
            what: format!("can't create {}", path.display()),
            source: e,
        }),
    }
}

/// A secret kept in `path` sealed under `seal` with `purpose`. Made with `make` and written
/// (privately, atomically) when the file doesn't exist.
pub fn load_or_create_sealed(
    path: &Path,
    seal: &ServerSeal,
    purpose: &str,
    make: impl FnOnce() -> Vec<u8>,
) -> Result<Zeroizing<Vec<u8>>, KeyError> {
    match std::fs::read(path) {
        Ok(sealed) => {
            return seal.open(purpose, &sealed).map_err(|_| {
                KeyError::Invalid(format!(
                    "{} doesn't open with this server key: was server.key replaced?",
                    path.display()
                ))
            });
        }
        Err(e) if e.kind() == io::ErrorKind::NotFound => {}
        Err(e) => {
            return Err(KeyError::Io {
                what: format!("can't read {}", path.display()),
                source: e,
            });
        }
    }
    let secret = Zeroizing::new(make());
    let sealed = seal.seal(purpose, &secret);
    let temporary = path.with_extension(format!("tmp{}", std::process::id()));
    let write = || -> io::Result<()> {
        let mut file = create_private(&temporary)?;
        file.write_all(&sealed)?;
        file.sync_all()?;
        std::fs::rename(&temporary, path)
    };
    if let Err(e) = write() {
        let _ = std::fs::remove_file(&temporary);
        return Err(KeyError::Io {
            what: format!("can't write {}", path.display()),
            source: e,
        });
    }
    Ok(secret)
}

/// The OPAQUE server setup, made at first start.
pub fn load_opaque_server(data: &Path, seal: &ServerSeal) -> Result<OpaqueServer, KeyError> {
    let bytes = load_or_create_sealed(
        &data.join(OPAQUE_SETUP_FILE),
        seal,
        PURPOSE_OPAQUE_SETUP,
        || OpaqueServer::generate().to_bytes(),
    )?;
    OpaqueServer::from_bytes(&bytes)
        .map_err(|_| KeyError::Invalid("the sealed OPAQUE setup is malformed".to_owned()))
}

/// The access-token signing key, made at first start.
pub fn load_signing_key(data: &Path, seal: &ServerSeal) -> Result<SigningKey, KeyError> {
    let bytes = load_or_create_sealed(
        &data.join(SIGNING_KEY_FILE),
        seal,
        PURPOSE_SIGNING_KEY,
        || SigningKey::generate().seed().to_vec(),
    )?;
    let seed = Zeroizing::new(
        <[u8; 32]>::try_from(bytes.as_slice())
            .map_err(|_| KeyError::Invalid("the sealed signing key is malformed".to_owned()))?,
    );
    Ok(SigningKey::from_seed(&seed))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    /// A fresh, empty directory that is removed at the end of the test.
    struct TempDir(PathBuf);

    impl TempDir {
        fn new(name: &str) -> TempDir {
            let nanos = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_or(0, |d| d.as_nanos());
            let path = std::env::temp_dir().join(format!(
                "kemlock-server-test-{}-{name}-{nanos}",
                std::process::id()
            ));
            std::fs::create_dir_all(&path).expect("a temp dir");
            TempDir(path)
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn a_server_key_is_made_once_and_reused() {
        let dir = TempDir::new("key");
        let first = load_or_create_server_key(&dir.0, None).expect("made");
        let file = std::fs::read(dir.0.join(SERVER_KEY_FILE)).expect("the file exists");
        assert_eq!(file, first);
        let second = load_or_create_server_key(&dir.0, None).expect("read");
        assert_eq!(first, second);
        assert_ne!(first, [0u8; 32]);
    }

    #[cfg(unix)]
    #[test]
    fn the_key_file_is_private() {
        use std::os::unix::fs::PermissionsExt;
        let dir = TempDir::new("mode");
        load_or_create_server_key(&dir.0, None).expect("made");
        let mode = std::fs::metadata(dir.0.join(SERVER_KEY_FILE))
            .expect("metadata")
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o600);
    }

    #[test]
    fn a_key_from_the_environment_is_used_and_no_file_is_made() {
        let dir = TempDir::new("env");
        let hex = "0f".repeat(32);
        let key = load_or_create_server_key(&dir.0, Some(&hex)).expect("parsed");
        assert_eq!(key, [0x0f; 32]);
        assert!(!dir.0.join(SERVER_KEY_FILE).exists());

        let b64 = b64url::encode(&[7u8; 32]);
        assert_eq!(
            load_or_create_server_key(&dir.0, Some(&b64)).expect("parsed"),
            [7u8; 32]
        );
    }

    #[test]
    fn a_malformed_key_is_refused() {
        let dir = TempDir::new("bad");
        let not_hex = "zz".repeat(32);
        let too_short = "0f".repeat(31);
        for bad in ["", "abc", not_hex.as_str(), too_short.as_str()] {
            assert!(
                load_or_create_server_key(&dir.0, Some(bad)).is_err(),
                "{bad}"
            );
        }
        std::fs::write(dir.0.join(SERVER_KEY_FILE), [1u8; 5]).expect("written");
        assert!(load_or_create_server_key(&dir.0, None).is_err());
    }

    #[test]
    fn hex_and_base64url_keys_parse_the_same() {
        let bytes: Vec<u8> = (0..32).collect();
        let hex: String = bytes.iter().map(|b| format!("{b:02x}")).collect();
        assert_eq!(
            parse_server_key(&hex).expect("hex"),
            parse_server_key(&b64url::encode(&bytes)).expect("b64")
        );
        assert_eq!(
            parse_server_key(&format!(" {hex}\n")).expect("trimmed")[31],
            31
        );
    }

    #[test]
    fn a_sealed_secret_is_made_once_sealed_and_reopened() {
        let dir = TempDir::new("sealed");
        let seal = ServerSeal::new(&[9u8; 32]);
        let path = dir.0.join("secret.sealed");
        let first =
            load_or_create_sealed(&path, &seal, "test", || b"the secret".to_vec()).expect("made");
        assert_eq!(first.as_slice(), b"the secret");
        let on_disk = std::fs::read(&path).expect("the file exists");
        assert!(
            !on_disk.windows(10).any(|w| w == b"the secret"),
            "sealed, not plain"
        );
        let second = load_or_create_sealed(&path, &seal, "test", || unreachable!("exists"))
            .expect("reopened");
        assert_eq!(second.as_slice(), b"the secret");
        // No temporary file is left behind.
        let leftovers: Vec<_> = std::fs::read_dir(&dir.0)
            .expect("readable")
            .filter_map(Result::ok)
            .filter(|e| e.file_name().to_string_lossy().contains("tmp"))
            .collect();
        assert!(leftovers.is_empty());
    }

    #[test]
    fn a_sealed_secret_does_not_open_with_another_key_or_purpose() {
        let dir = TempDir::new("wrong");
        let seal = ServerSeal::new(&[9u8; 32]);
        let path = dir.0.join("secret.sealed");
        load_or_create_sealed(&path, &seal, "test", || b"x".to_vec()).expect("made");
        let other_key = ServerSeal::new(&[8u8; 32]);
        assert!(load_or_create_sealed(&path, &other_key, "test", Vec::new).is_err());
        assert!(load_or_create_sealed(&path, &seal, "other", Vec::new).is_err());
    }

    #[test]
    fn the_opaque_setup_and_signing_key_survive_a_restart() {
        let dir = TempDir::new("setup");
        let seal = ServerSeal::new(&[3u8; 32]);
        let first = load_opaque_server(&dir.0, &seal).expect("made");
        let again = load_opaque_server(&dir.0, &seal).expect("reloaded");
        assert_eq!(first.to_bytes(), again.to_bytes());

        let key = load_signing_key(&dir.0, &seal).expect("made");
        let key_again = load_signing_key(&dir.0, &seal).expect("reloaded");
        assert_eq!(key.public_key(), key_again.public_key());
    }
}
