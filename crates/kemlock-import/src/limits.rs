//! The caps every parser applies, as `add-code-imports` sets them for the app: file size, entry
//! count, ZIP entries and inflated size, and key-derivation cost. They are checked before the work
//! they bound.

use crate::error::{ImportError, Result};

const MIB: usize = 1024 * 1024;

/// Limits on an import. [`Limits::default`] is what the web vault and the CLI use.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Limits {
    /// The largest text export (CSV, JSON, PGP) or KDBX file read: 32 MiB.
    pub max_input_bytes: usize,
    /// The largest ZIP read, which may hold attachments: 128 MiB.
    pub max_zip_bytes: usize,
    /// Entries (logins, notes, cards and the rest) in a batch; the rest are dropped and counted.
    pub max_entries: usize,
    /// Files listed in a ZIP's directory.
    pub max_zip_entries: usize,
    /// Inflated bytes of one ZIP entry (and of one gzip or deflate stream in a KDBX file).
    pub max_entry_bytes: usize,
    /// Inflated bytes of all ZIP entries read together.
    pub max_inflated_bytes: usize,
    /// Depth of folders, groups and collections read; deeper ones are flattened.
    pub max_folder_depth: usize,
    /// PBKDF2 rounds a Bitwarden export may ask for (the floor is Bitwarden's, 5,000).
    pub max_pbkdf2_iterations: u32,
    /// Argon2 passes.
    pub max_argon2_iterations: u32,
    /// Argon2 memory in KiB: 1 GiB.
    pub max_argon2_memory_kib: u32,
    /// Argon2 lanes.
    pub max_argon2_parallelism: u32,
    /// AES-KDF rounds in a KDBX file.
    pub max_aes_kdf_rounds: u64,
}

impl Default for Limits {
    fn default() -> Limits {
        Limits {
            max_input_bytes: 32 * MIB,
            max_zip_bytes: 128 * MIB,
            max_entries: 10_000,
            max_zip_entries: 10_000,
            max_entry_bytes: 64 * MIB,
            max_inflated_bytes: 256 * MIB,
            max_folder_depth: 8,
            max_pbkdf2_iterations: 2_000_000,
            max_argon2_iterations: 10,
            max_argon2_memory_kib: 1024 * 1024,
            max_argon2_parallelism: 16,
            max_aes_kdf_rounds: 100_000_000,
        }
    }
}

impl Limits {
    /// Small limits for fuzzing and tests, so a hostile input costs little.
    pub fn small() -> Limits {
        Limits {
            max_input_bytes: MIB,
            max_zip_bytes: 2 * MIB,
            max_entries: 200,
            max_zip_entries: 50,
            max_entry_bytes: 2 * MIB,
            max_inflated_bytes: 4 * MIB,
            max_folder_depth: 8,
            max_pbkdf2_iterations: 10_000,
            max_argon2_iterations: 3,
            max_argon2_memory_kib: 1024,
            max_argon2_parallelism: 2,
            max_aes_kdf_rounds: 20_000,
        }
    }

    /// Refuses `bytes` when it is over the text-export size limit.
    pub fn check_input(&self, bytes: &[u8]) -> Result<()> {
        if bytes.len() > self.max_input_bytes {
            return Err(ImportError::TooLarge {
                limit: self.max_input_bytes,
            });
        }
        Ok(())
    }

    /// Refuses `bytes` when it is over the ZIP size limit.
    pub fn check_zip_input(&self, bytes: &[u8]) -> Result<()> {
        if bytes.len() > self.max_zip_bytes {
            return Err(ImportError::TooLarge {
                limit: self.max_zip_bytes,
            });
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_are_the_documented_caps() {
        let l = Limits::default();
        assert_eq!(l.max_input_bytes, 32 * 1024 * 1024);
        assert_eq!(l.max_entries, 10_000);
        assert_eq!(l.max_folder_depth, 8);
    }

    #[test]
    fn checks_refuse_over_size_input() {
        let l = Limits::small();
        assert!(l.check_input(&vec![0; l.max_input_bytes]).is_ok());
        assert_eq!(
            l.check_input(&vec![0; l.max_input_bytes + 1]),
            Err(ImportError::TooLarge {
                limit: l.max_input_bytes
            })
        );
        assert!(l.check_zip_input(&vec![0; l.max_zip_bytes + 1]).is_err());
    }
}
