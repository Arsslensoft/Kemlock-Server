//! The cipher suites of a federation session and how two servers agree on one.
//!
//! Every suite is post-quantum and authenticated; there is nothing weaker to fall back to. A
//! suite is named by an ASCII string, which is what descriptors and hellos carry, so a name this
//! build has never heard of can be carried, hashed into the transcript and skipped.

use crate::crypto::Aead;
use crate::error::{FedError, Result};

/// A cipher suite.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Suite {
    /// ML-KEM-1024 + X25519, AES-256-GCM frames, ML-DSA-65 + Ed25519 signatures.
    Aes256Gcm,
    /// The same exchange and signatures, ChaCha20-Poly1305 frames, for servers without AES
    /// instructions.
    ChaCha20Poly1305,
    /// ML-KEM-1024 + ECDH P-384, AES-256-GCM, ML-DSA-65 + ECDSA P-384, for FIPS images. The id is
    /// defined so descriptors can list it; this build refuses it (see `docs/federation.md`).
    Fips,
}

impl Suite {
    /// Every suite this crate knows, in the default preference order.
    pub const ALL: [Suite; 3] = [Suite::Aes256Gcm, Suite::ChaCha20Poly1305, Suite::Fips];

    /// The suites this build can run.
    pub const IMPLEMENTED: [Suite; 2] = [Suite::Aes256Gcm, Suite::ChaCha20Poly1305];

    pub fn name(self) -> &'static str {
        match self {
            Suite::Aes256Gcm => "kfed1-mlkem1024x25519-aes256gcm",
            Suite::ChaCha20Poly1305 => "kfed1-mlkem1024x25519-chacha20poly1305",
            Suite::Fips => "kfed1-mlkem1024p384-aes256gcm",
        }
    }

    /// The suite with this name, `None` for a name this build doesn't know.
    pub fn from_name(name: &str) -> Option<Suite> {
        Suite::ALL.into_iter().find(|s| s.name() == name)
    }

    /// Whether this build implements the suite. The FIPS suite is defined but refused: its P-384
    /// hybrid exchange key and ECDSA P-384 signatures have no encoding or code here yet. The ML-KEM
    /// seed is no obstacle: kemlock-crypto expands it on RustCrypto's `ml-kem` for that one step on
    /// every backend (docs/crypto.md, "Crypto library"), and in a FIPS build ML-DSA runs on
    /// RustCrypto too, outside the FIPS module.
    pub fn available(self) -> bool {
        Suite::IMPLEMENTED.contains(&self)
    }

    /// The frame AEAD, for an available suite.
    pub fn aead(self) -> Result<Aead> {
        match self {
            Suite::Aes256Gcm => Ok(Aead::Aes256Gcm),
            Suite::ChaCha20Poly1305 => Ok(Aead::ChaCha20Poly1305),
            Suite::Fips => Err(FedError::SuiteUnavailable(self.name().to_owned())),
        }
    }
}

/// The names of `suites`, for a descriptor.
pub fn names(suites: &[Suite]) -> Vec<String> {
    suites.iter().map(|s| s.name().to_owned()).collect()
}

/// Picks the suite for a connection: the first in `theirs` (the connected server's list, most
/// preferred first) that is also in `ours` and that this build implements. Names this build
/// doesn't know are skipped, never approximated. With no match the error says whether a known
/// suite was refused only because it isn't implemented.
pub fn negotiate(theirs: &[String], ours: &[Suite]) -> Result<Suite> {
    let mut unavailable: Option<Suite> = None;
    for name in theirs {
        let Some(suite) = Suite::from_name(name) else {
            continue;
        };
        if !ours.contains(&suite) {
            continue;
        }
        if suite.available() {
            return Ok(suite);
        }
        unavailable.get_or_insert(suite);
    }
    match unavailable {
        Some(suite) => Err(FedError::SuiteUnavailable(suite.name().to_owned())),
        None => Err(FedError::NoCommonSuite),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn list(items: &[&str]) -> Vec<String> {
        items.iter().map(|s| (*s).to_owned()).collect()
    }

    #[test]
    fn names_round_trip() {
        for suite in Suite::ALL {
            assert_eq!(Suite::from_name(suite.name()), Some(suite));
        }
        assert_eq!(Suite::from_name("kfed1-nothing"), None);
        assert_eq!(Suite::from_name(""), None);
    }

    #[test]
    fn the_first_of_the_peers_list_that_we_support_wins() {
        let theirs = list(&[
            "kfed9-from-the-future",
            "kfed1-mlkem1024x25519-chacha20poly1305",
            "kfed1-mlkem1024x25519-aes256gcm",
        ]);
        let ours = [Suite::Aes256Gcm, Suite::ChaCha20Poly1305];
        assert_eq!(negotiate(&theirs, &ours), Ok(Suite::ChaCha20Poly1305));
        // Our own order doesn't matter, theirs does.
        let ours = [Suite::ChaCha20Poly1305, Suite::Aes256Gcm];
        assert_eq!(negotiate(&theirs, &ours), Ok(Suite::ChaCha20Poly1305));
    }

    #[test]
    fn a_suite_we_do_not_support_is_skipped() {
        let theirs = list(&[
            "kfed1-mlkem1024x25519-chacha20poly1305",
            "kfed1-mlkem1024x25519-aes256gcm",
        ]);
        assert_eq!(
            negotiate(&theirs, &[Suite::Aes256Gcm]),
            Ok(Suite::Aes256Gcm)
        );
    }

    #[test]
    fn no_match_is_an_error() {
        assert_eq!(
            negotiate(&list(&["kfed9-x"]), &Suite::IMPLEMENTED),
            Err(FedError::NoCommonSuite)
        );
        assert_eq!(
            negotiate(&[], &Suite::IMPLEMENTED),
            Err(FedError::NoCommonSuite)
        );
        assert_eq!(
            negotiate(
                &list(&["kfed1-mlkem1024x25519-aes256gcm"]),
                &[Suite::ChaCha20Poly1305]
            ),
            Err(FedError::NoCommonSuite)
        );
    }

    #[test]
    fn the_fips_suite_is_defined_but_refused() {
        let theirs = list(&["kfed1-mlkem1024p384-aes256gcm"]);
        assert_eq!(
            negotiate(&theirs, &Suite::ALL),
            Err(FedError::SuiteUnavailable(
                "kfed1-mlkem1024p384-aes256gcm".to_owned()
            ))
        );
        assert!(Suite::Fips.aead().is_err());
        // But it never blocks a suite that works.
        let theirs = list(&[
            "kfed1-mlkem1024p384-aes256gcm",
            "kfed1-mlkem1024x25519-aes256gcm",
        ]);
        assert_eq!(negotiate(&theirs, &Suite::ALL), Ok(Suite::Aes256Gcm));
    }
}
