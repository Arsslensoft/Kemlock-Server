//! This server's federation identity on disk, sealed with `server.key`.
//!
//! The file `federation-identity.sealed` in the data folder holds, sealed under the purpose
//! `"federation-identity"`:
//!
//! ```text
//! u8(1) ‖ sig1 private key (64) ‖ u8(n) ‖ n × (kx1 private key (96) ‖ u64be(created at))
//! ```
//!
//! newest KEM key first. The identity key changes only through a signed rotation or revocation
//! ([`rotate_identity`]; otherwise a new one means pairing again). The KEM
//! key is replaced every 30 days; the old one stays while a descriptor that names it can still be
//! valid, 37 days from its creation, so a peer that read the old descriptor can still open a
//! hello. Restoring a backup needs `server.key`, which is why the peers must be paired again
//! without it.

use kemlock_app::ports::Zeroizing;
use kemlock_crypto::seal::ServerSeal;
use kemlock_crypto::{kx1, sig1};
use kemlock_domain::ServerId;
use kemlock_federation::descriptor::{KEM_ROTATION_SECS, VALIDITY_SECS};
use kemlock_federation::keyrecs::IdentityRotator;
use kemlock_federation::{DescriptorParams, FedError, KemPair, LocalIdentity, Suite};
use std::path::{Path, PathBuf};

/// The purpose the identity file is sealed under.
pub const SEAL_PURPOSE: &str = "federation-identity";
/// The file's name in the data folder.
pub const FILE_NAME: &str = "federation-identity.sealed";
/// The file, beside the identity file, that holds the suites an admin chose, one name per line,
/// most preferred first. It is not secret. Without it the suites are the build's defaults.
pub const SUITES_FILE_NAME: &str = "federation-suites.txt";

/// Why the identity could not be loaded or made.
#[derive(Debug, thiserror::Error)]
pub enum IdentityError {
    #[error("can't read or write {path}: {source}")]
    Io {
        path: String,
        #[source]
        source: std::io::Error,
    },
    #[error("the federation identity file is damaged or sealed under another server.key")]
    Corrupt,
    #[error("a federation key could not be made: {0}")]
    Crypto(String),
}

/// What the descriptor says about this server.
#[derive(Clone, Debug)]
pub struct IdentityParams {
    /// Where peers reach this server, such as `https://vault.example.org`.
    pub address: String,
    /// Who runs it.
    pub operator: String,
    /// The suites to accept, most preferred first.
    pub suites: Vec<Suite>,
}

/// The descriptor is signed afresh once it is this old, so a peer that reads it always finds a
/// window with at least 30 of its 37 days left; the KEM key is replaced at 30 days, as
/// [`load_or_create`] does on the same call.
pub const REFRESH_AFTER_SECS: u64 = 7 * 24 * 60 * 60;

/// Whether the running server should reload its identity at `now`: the descriptor was signed
/// [`REFRESH_AFTER_SECS`] ago or more, or its KEM key is due for rotation.
pub fn refresh_due(identity: &LocalIdentity, now: u64) -> bool {
    let d = &identity.descriptor.descriptor;
    now >= d.not_before.saturating_add(REFRESH_AFTER_SECS)
        || kemlock_federation::descriptor::kem_rotation_due(d, now)
}

/// The suites to offer, the one this CPU runs fastest first.
pub fn default_suites() -> Vec<Suite> {
    if has_aes_instructions() {
        vec![Suite::Aes256Gcm, Suite::ChaCha20Poly1305]
    } else {
        vec![Suite::ChaCha20Poly1305, Suite::Aes256Gcm]
    }
}

#[allow(unreachable_code)]
fn has_aes_instructions() -> bool {
    #[cfg(target_arch = "x86_64")]
    {
        return std::arch::is_x86_feature_detected!("aes");
    }
    #[cfg(target_arch = "aarch64")]
    {
        return std::arch::is_aarch64_feature_detected!("aes");
    }
    false
}

struct Stored {
    signing: [u8; sig1::PRIVATE_KEY_LEN],
    /// Newest first.
    kems: Vec<([u8; kx1::PRIVATE_KEY_LEN], u64)>,
}

impl Stored {
    fn encode(&self) -> Vec<u8> {
        let mut out = vec![1u8];
        out.extend_from_slice(&self.signing);
        out.push(self.kems.len() as u8);
        for (private, created) in &self.kems {
            out.extend_from_slice(private);
            out.extend_from_slice(&created.to_be_bytes());
        }
        out
    }

    fn decode(bytes: &[u8]) -> Result<Stored, IdentityError> {
        let (&version, rest) = bytes.split_first().ok_or(IdentityError::Corrupt)?;
        if version != 1 || rest.len() < sig1::PRIVATE_KEY_LEN + 1 {
            return Err(IdentityError::Corrupt);
        }
        let (signing, rest) = rest.split_at(sig1::PRIVATE_KEY_LEN);
        let (&count, rest) = rest.split_first().ok_or(IdentityError::Corrupt)?;
        let entry = kx1::PRIVATE_KEY_LEN + 8;
        if count == 0 || rest.len() != usize::from(count) * entry {
            return Err(IdentityError::Corrupt);
        }
        let mut kems = Vec::new();
        for chunk in rest.chunks_exact(entry) {
            let mut private = [0u8; kx1::PRIVATE_KEY_LEN];
            private.copy_from_slice(&chunk[..kx1::PRIVATE_KEY_LEN]);
            let mut created = [0u8; 8];
            created.copy_from_slice(&chunk[kx1::PRIVATE_KEY_LEN..]);
            kems.push((private, u64::from_be_bytes(created)));
        }
        let mut key = [0u8; sig1::PRIVATE_KEY_LEN];
        key.copy_from_slice(signing);
        Ok(Stored { signing: key, kems })
    }
}

fn crypto(e: impl std::fmt::Display) -> IdentityError {
    IdentityError::Crypto(e.to_string())
}

fn write_private(path: &Path, bytes: &[u8]) -> Result<(), IdentityError> {
    let io = |source| IdentityError::Io {
        path: path.display().to_string(),
        source,
    };
    #[cfg(unix)]
    {
        use std::io::Write as _;
        use std::os::unix::fs::OpenOptionsExt as _;
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(path)
            .map_err(io)?;
        file.write_all(bytes).map_err(io)
    }
    #[cfg(not(unix))]
    {
        std::fs::write(path, bytes).map_err(io)
    }
}

/// Loads this server's federation identity from `folder`, making it on the first start, and
/// replaces the KEM key when it is 30 days old. The descriptor is signed afresh, valid from `now`
/// for 37 days.
pub fn load_or_create(
    folder: &Path,
    seal: &ServerSeal,
    server: ServerId,
    params: &IdentityParams,
    now: u64,
) -> Result<LocalIdentity, IdentityError> {
    let path = folder.join(FILE_NAME);
    let mut changed = false;
    let mut stored = match std::fs::read(&path) {
        Ok(sealed) => {
            let bytes = seal
                .open(SEAL_PURPOSE, &sealed)
                .map_err(|_| IdentityError::Corrupt)?;
            Stored::decode(&bytes)?
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            changed = true;
            let (private, _) = kemlock_federation::crypto::kem_generate().map_err(crypto)?;
            Stored {
                signing: *sig1::SigningKey::generate().as_bytes(),
                kems: vec![(*private.as_bytes(), now)],
            }
        }
        Err(source) => {
            return Err(IdentityError::Io {
                path: path.display().to_string(),
                source,
            });
        }
    };

    let newest = stored.kems.first().map_or(0, |(_, created)| *created);
    if now >= newest.saturating_add(KEM_ROTATION_SECS) {
        let (private, _) = kemlock_federation::crypto::kem_generate().map_err(crypto)?;
        stored.kems.insert(0, (*private.as_bytes(), now));
        changed = true;
    }
    // Keep the newest key and any older one a still-valid descriptor can name.
    let before = stored.kems.len();
    let mut index = 0;
    stored.kems.retain(|(_, created)| {
        index += 1;
        index == 1 || created.saturating_add(VALIDITY_SECS) >= now
    });
    changed |= stored.kems.len() != before;

    if changed {
        let sealed = seal
            .try_seal(SEAL_PURPOSE, &stored.encode())
            .map_err(crypto)?;
        write_private(&path, &sealed)?;
    }

    let kems = stored
        .kems
        .iter()
        .map(|(private, _)| KemPair::from_private(kx1::PrivateKey::from_bytes(private)))
        .collect::<Result<Vec<_>, _>>()
        .map_err(crypto)?;
    advertising_identity(
        server,
        sig1::SigningKey::from_bytes(&stored.signing),
        kems,
        DescriptorParams {
            suites: read_suites(folder).unwrap_or_else(|| params.suites.clone()),
            addresses: vec![params.address.clone()],
            operator: params.operator.clone(),
            not_before: now,
            not_after: now + VALIDITY_SECS,
        },
    )
    .map_err(crypto)
}

/// Makes a new identity for the server `current` is: a new signing key and a new KEM key, with the
/// same server id, addresses and operator, written over the sealed file in `folder`. The old key is
/// gone from disk afterwards; `current` still has it in memory, which is what signs the rotation
/// record that peers accept the new key through.
pub fn rotate_identity(
    folder: &Path,
    seal: &ServerSeal,
    current: &LocalIdentity,
    now: u64,
) -> Result<LocalIdentity, IdentityError> {
    let kem = KemPair::generate().map_err(crypto)?;
    let signing = sig1::SigningKey::generate();
    let stored = Stored {
        signing: *signing.as_bytes(),
        kems: vec![(*kem.private.as_bytes(), now)],
    };
    let sealed = seal
        .try_seal(SEAL_PURPOSE, &stored.encode())
        .map_err(crypto)?;
    write_private(&folder.join(FILE_NAME), &sealed)?;
    let d = &current.descriptor.descriptor;
    advertising_identity(
        current.server,
        signing,
        vec![kem],
        DescriptorParams {
            suites: current.suites(),
            addresses: d.addresses.clone(),
            operator: d.operator.clone(),
            not_before: now,
            not_after: now + VALIDITY_SECS,
        },
    )
    .map_err(crypto)
}

/// The suites an admin chose, if they chose any: the names of [`SUITES_FILE_NAME`] this build knows,
/// in order, provided one of them can run.
fn read_suites(folder: &Path) -> Option<Vec<Suite>> {
    let text = std::fs::read_to_string(folder.join(SUITES_FILE_NAME)).ok()?;
    let mut suites: Vec<Suite> = Vec::new();
    for suite in text.lines().filter_map(|l| Suite::from_name(l.trim())) {
        if !suites.contains(&suite) {
            suites.push(suite);
        }
    }
    suites.iter().any(|s| s.available()).then_some(suites)
}

fn write_suites(folder: &Path, suites: &[Suite]) -> Result<(), IdentityError> {
    let names: Vec<&str> = suites.iter().map(|s| s.name()).collect();
    let path = folder.join(SUITES_FILE_NAME);
    std::fs::write(&path, names.join("\n")).map_err(|source| IdentityError::Io {
        path: path.display().to_string(),
        source,
    })
}

fn load_stored(folder: &Path, seal: &ServerSeal) -> Result<Stored, IdentityError> {
    let path = folder.join(FILE_NAME);
    let sealed = std::fs::read(&path).map_err(|source| IdentityError::Io {
        path: path.display().to_string(),
        source,
    })?;
    let bytes = seal
        .open(SEAL_PURPOSE, &sealed)
        .map_err(|_| IdentityError::Corrupt)?;
    Stored::decode(&bytes)
}

fn same_identity(
    current: &LocalIdentity,
    signing: sig1::SigningKey,
    kems: Vec<KemPair>,
    suites: Vec<Suite>,
    now: u64,
) -> Result<LocalIdentity, IdentityError> {
    let d = &current.descriptor.descriptor;
    advertising_identity(
        current.server,
        signing,
        kems,
        DescriptorParams {
            suites,
            addresses: d.addresses.clone(),
            operator: d.operator.clone(),
            not_before: now,
            not_after: now + VALIDITY_SECS,
        },
    )
    .map_err(crypto)
}

/// Makes a new KEM key for the server `current` is and writes it over the sealed file in `folder`,
/// newest first, keeping the older ones a still-valid descriptor can name. The identity key stays.
/// The descriptor is signed afresh, valid from `now`.
pub fn rotate_kem(
    folder: &Path,
    seal: &ServerSeal,
    current: &LocalIdentity,
    now: u64,
) -> Result<LocalIdentity, IdentityError> {
    let mut stored = load_stored(folder, seal)?;
    let fresh = KemPair::generate().map_err(crypto)?;
    stored.kems.insert(0, (*fresh.private.as_bytes(), now));
    let mut index = 0;
    stored.kems.retain(|(_, created)| {
        index += 1;
        index == 1 || created.saturating_add(VALIDITY_SECS) >= now
    });
    let sealed = seal
        .try_seal(SEAL_PURPOSE, &stored.encode())
        .map_err(crypto)?;
    write_private(&folder.join(FILE_NAME), &sealed)?;
    let kems = stored
        .kems
        .iter()
        .map(|(private, _)| KemPair::from_private(kx1::PrivateKey::from_bytes(private)))
        .collect::<Result<Vec<_>, _>>()
        .map_err(crypto)?;
    same_identity(
        current,
        sig1::SigningKey::from_bytes(&stored.signing),
        kems,
        current.suites(),
        now,
    )
}

/// Signs the descriptor of `current` afresh with `suites` and keeps them in [`SUITES_FILE_NAME`],
/// so a restart or a refresh offers the same ones. The keys stay.
pub fn choose_suites(
    folder: &Path,
    current: &LocalIdentity,
    suites: &[Suite],
    now: u64,
) -> Result<LocalIdentity, IdentityError> {
    let identity = same_identity(
        current,
        current.signing.clone(),
        current.kems.clone(),
        suites.to_vec(),
        now,
    )?;
    write_suites(folder, suites)?;
    Ok(identity)
}

/// When the newest KEM key in the identity file was made, Unix seconds.
pub fn kem_made_at(folder: &Path, seal: &ServerSeal) -> Option<u64> {
    load_stored(folder, seal)
        .ok()
        .and_then(|stored| stored.kems.first().map(|(_, created)| *created))
}

/// [`IdentityRotator`] over the identity file in the data folder.
pub struct FileRotator {
    folder: PathBuf,
    key: Zeroizing<[u8; 32]>,
}

impl std::fmt::Debug for FileRotator {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FileRotator").finish_non_exhaustive()
    }
}

impl FileRotator {
    /// `key` is `server.key`, which seals the file.
    pub fn new(folder: PathBuf, key: [u8; 32]) -> FileRotator {
        FileRotator {
            folder,
            key: Zeroizing::new(key),
        }
    }
}

impl IdentityRotator for FileRotator {
    fn rotate(
        &self,
        current: &LocalIdentity,
        now: u64,
    ) -> kemlock_federation::Result<LocalIdentity> {
        rotate_identity(&self.folder, &ServerSeal::new(&self.key), current, now)
            .map_err(|_| FedError::Invalid("the identity key could not be rotated"))
    }

    fn rotate_kem(
        &self,
        current: &LocalIdentity,
        now: u64,
    ) -> kemlock_federation::Result<LocalIdentity> {
        rotate_kem(&self.folder, &ServerSeal::new(&self.key), current, now)
            .map_err(|_| FedError::Invalid("the KEM key could not be replaced"))
    }

    fn set_suites(
        &self,
        current: &LocalIdentity,
        suites: &[Suite],
        now: u64,
    ) -> kemlock_federation::Result<LocalIdentity> {
        choose_suites(&self.folder, current, suites, now)
            .map_err(|_| FedError::Invalid("the suites could not be changed"))
    }

    fn kem_made_at(&self) -> Option<u64> {
        kem_made_at(&self.folder, &ServerSeal::new(&self.key))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const NOW: u64 = 1_800_000_000;

    fn params() -> IdentityParams {
        IdentityParams {
            address: "https://vault.example.org".to_owned(),
            operator: "Example".to_owned(),
            suites: Suite::IMPLEMENTED.to_vec(),
        }
    }

    #[test]
    fn the_identity_is_made_once_and_loaded_after() {
        let dir = tempfile::tempdir().expect("a temp dir");
        let seal = ServerSeal::new(&[7; 32]);
        let server = ServerId::random();
        let first = load_or_create(dir.path(), &seal, server, &params(), NOW).expect("first");
        assert!(dir.path().join(FILE_NAME).exists());
        let second =
            load_or_create(dir.path(), &seal, server, &params(), NOW + 60).expect("second");
        assert_eq!(first.public, second.public);
        assert_eq!(first.kems[0].public, second.kems[0].public);
        second
            .descriptor
            .verify(NOW + 61, Some(&first.public))
            .expect("a valid descriptor");
        assert_eq!(
            second.descriptor.descriptor.addresses,
            vec!["https://vault.example.org"]
        );
    }

    #[test]
    fn the_file_is_sealed_and_another_key_cannot_open_it() {
        let dir = tempfile::tempdir().expect("a temp dir");
        let seal = ServerSeal::new(&[7; 32]);
        load_or_create(dir.path(), &seal, ServerId::random(), &params(), NOW).expect("made");
        let raw = std::fs::read(dir.path().join(FILE_NAME)).expect("file");
        assert!(
            raw.len() > 64 + 96,
            "sealed bytes, not the 64-byte key alone"
        );
        let other = ServerSeal::new(&[8; 32]);
        assert!(matches!(
            load_or_create(dir.path(), &other, ServerId::random(), &params(), NOW),
            Err(IdentityError::Corrupt)
        ));
    }

    #[test]
    fn the_kem_key_rotates_after_30_days_and_the_old_one_stays_for_the_overlap() {
        let dir = tempfile::tempdir().expect("a temp dir");
        let seal = ServerSeal::new(&[7; 32]);
        let server = ServerId::random();
        let first = load_or_create(dir.path(), &seal, server, &params(), NOW).expect("first");
        let later = NOW + KEM_ROTATION_SECS;
        let rotated = load_or_create(dir.path(), &seal, server, &params(), later).expect("rotated");
        assert_eq!(
            first.public, rotated.public,
            "the identity key does not change"
        );
        assert_ne!(first.kems[0].public, rotated.kems[0].public);
        assert_eq!(rotated.kems.len(), 2);
        assert_eq!(rotated.kems[1].public, first.kems[0].public);
        // Once no descriptor can name the old key any more it is dropped.
        let much_later = NOW + VALIDITY_SECS + 1;
        let again =
            load_or_create(dir.path(), &seal, server, &params(), much_later).expect("again");
        assert_eq!(again.kems.len(), 1);
    }

    #[test]
    fn a_damaged_file_is_refused() {
        let dir = tempfile::tempdir().expect("a temp dir");
        let seal = ServerSeal::new(&[7; 32]);
        std::fs::write(dir.path().join(FILE_NAME), b"not sealed").expect("write");
        assert!(matches!(
            load_or_create(dir.path(), &seal, ServerId::random(), &params(), NOW),
            Err(IdentityError::Corrupt)
        ));
        assert!(Stored::decode(&[]).is_err());
        assert!(Stored::decode(&[2; 100]).is_err());
    }

    #[test]
    fn a_descriptor_is_refreshed_after_a_week() {
        let dir = tempfile::tempdir().expect("a temp dir");
        let seal = ServerSeal::new(&[7; 32]);
        let identity =
            load_or_create(dir.path(), &seal, ServerId::random(), &params(), NOW).expect("made");
        assert!(!refresh_due(&identity, NOW + REFRESH_AFTER_SECS - 1));
        assert!(refresh_due(&identity, NOW + REFRESH_AFTER_SECS));
    }

    #[test]
    fn the_default_suites_always_offer_both() {
        let suites = default_suites();
        assert_eq!(suites.len(), 2);
        assert!(suites.contains(&Suite::Aes256Gcm) && suites.contains(&Suite::ChaCha20Poly1305));
    }

    #[test]
    fn a_rotation_writes_a_new_identity_that_loads_again_and_keeps_the_server() {
        let dir = tempfile::tempdir().expect("a temp dir");
        let seal = ServerSeal::new(&[7; 32]);
        let server = ServerId::random();
        let first = load_or_create(dir.path(), &seal, server, &params(), NOW).expect("first");
        let rotated = rotate_identity(dir.path(), &seal, &first, NOW + 10).expect("rotated");
        assert_eq!(rotated.server, server);
        assert_ne!(rotated.public, first.public);
        assert_eq!(
            rotated.descriptor.descriptor.addresses,
            first.descriptor.descriptor.addresses
        );
        rotated
            .descriptor
            .verify(NOW + 11, Some(&rotated.public))
            .expect("a valid descriptor");
        let loaded =
            load_or_create(dir.path(), &seal, server, &params(), NOW + 20).expect("loaded");
        assert_eq!(loaded.public, rotated.public, "the file holds the new key");
        // The rotator does the same through the trait.
        let rotator = FileRotator::new(dir.path().to_path_buf(), [7; 32]);
        let again = rotator.rotate(&loaded, NOW + 30).expect("rotated");
        assert_ne!(again.public, loaded.public);
        assert_eq!(again.server, server);
    }

    #[test]
    fn a_new_kem_key_keeps_the_identity_and_the_old_key_for_the_overlap() {
        let dir = tempfile::tempdir().expect("a temp dir");
        let seal = ServerSeal::new(&[7; 32]);
        let server = ServerId::random();
        let first = load_or_create(dir.path(), &seal, server, &params(), NOW).expect("first");
        assert_eq!(kem_made_at(dir.path(), &seal), Some(NOW));
        let rotator = FileRotator::new(dir.path().to_path_buf(), [7; 32]);
        let rotated = rotator
            .rotate_kem(&first, NOW + 100)
            .expect("a new KEM key");
        assert_eq!(rotated.public, first.public, "the identity key stays");
        assert_eq!(rotated.server, server);
        assert_ne!(rotated.kems[0].public, first.kems[0].public);
        assert_eq!(rotated.kems[1].public, first.kems[0].public);
        assert_eq!(
            rotated.descriptor.descriptor.kem_key,
            rotated.kems[0].public
        );
        rotated
            .descriptor
            .verify(NOW + 101, Some(&first.public))
            .expect("a valid descriptor");
        assert_eq!(rotator.kem_made_at(), Some(NOW + 100));
        // What the file holds is what a restart loads.
        let loaded =
            load_or_create(dir.path(), &seal, server, &params(), NOW + 200).expect("loaded");
        assert_eq!(loaded.kems[0].public, rotated.kems[0].public);
    }

    #[test]
    fn chosen_suites_are_signed_in_and_survive_a_reload() {
        let dir = tempfile::tempdir().expect("a temp dir");
        let seal = ServerSeal::new(&[7; 32]);
        let server = ServerId::random();
        let first = load_or_create(dir.path(), &seal, server, &params(), NOW).expect("first");
        assert_eq!(first.suites(), Suite::IMPLEMENTED.to_vec());
        let rotator = FileRotator::new(dir.path().to_path_buf(), [7; 32]);
        let chosen = [Suite::ChaCha20Poly1305];
        let changed = rotator
            .set_suites(&first, &chosen, NOW + 10)
            .expect("suites chosen");
        assert_eq!(changed.suites(), chosen.to_vec());
        assert_eq!(changed.public, first.public);
        changed
            .descriptor
            .verify(NOW + 11, Some(&first.public))
            .expect("a valid descriptor");
        let loaded =
            load_or_create(dir.path(), &seal, server, &params(), NOW + 20).expect("loaded");
        assert_eq!(
            loaded.suites(),
            chosen.to_vec(),
            "the choice outlives a restart"
        );
    }

    #[test]
    fn a_suites_file_with_nothing_this_build_can_run_is_ignored() {
        let dir = tempfile::tempdir().expect("a temp dir");
        let seal = ServerSeal::new(&[7; 32]);
        std::fs::write(
            dir.path().join(SUITES_FILE_NAME),
            format!("{}\nsomething-unknown", Suite::Fips.name()),
        )
        .expect("write");
        let identity =
            load_or_create(dir.path(), &seal, ServerId::random(), &params(), NOW).expect("made");
        assert_eq!(identity.suites(), Suite::IMPLEMENTED.to_vec());
    }
}

/// `LocalIdentity::new`, listing what this server answers beyond version 1 (`Sends`) after its
/// suites, so a peer that answers it too knows to ask.
fn advertising_identity(
    server: ServerId,
    signing: sig1::SigningKey,
    kems: Vec<KemPair>,
    params: DescriptorParams,
) -> Result<LocalIdentity, kemlock_federation::FedError> {
    LocalIdentity::new_advertising(
        server,
        signing,
        kems,
        params,
        &[kemlock_federation::sendsync::SENDS_CAPABILITY],
    )
}
