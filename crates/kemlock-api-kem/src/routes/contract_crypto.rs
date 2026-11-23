//! The two crypto ports of the contract routes, over `kemlock-crypto` and aws-lc-rs.
//!
//! `kemlock-app` has no crypto of its own, so a manifest's signature and the Bitwarden password
//! check reach it through ports; these are their adapters.

use aws_lc_rs::pbkdf2;
use kemlock_app::bitwarden::enrol::BwPasswordCheck;
use kemlock_app::manifests::{ManifestHeader, ManifestVerifier};
use kemlock_app::ports::CryptoError;
use kemlock_crypto::bundle::Bundle;
use kemlock_crypto::manifest::Manifest;
use kemlock_domain::Owner;
use std::num::NonZeroU32;

/// Checks a manifest with `kemlock_crypto::manifest` and `sig1`: both the ML-DSA-65 and the
/// Ed25519 signature must verify under the signing key in the signer's bundle.
#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct Sig1Manifests;

impl ManifestVerifier for Sig1Manifests {
    fn verify(
        &self,
        bundle: &[u8],
        manifest: &[u8],
        signature: &[u8],
    ) -> Result<ManifestHeader, CryptoError> {
        let bundle = Bundle::from_bytes(bundle).map_err(|_| CryptoError::Invalid)?;
        let opened = Manifest::open_signed(&bundle.sig1_public, manifest, signature)
            .map_err(|_| CryptoError::Invalid)?;
        let owner = Owner::from_bytes(&opened.owner.to_bytes()).ok_or(CryptoError::Invalid)?;
        Ok(ManifestHeader {
            owner,
            counter: opened.counter,
        })
    }
}

/// The Bitwarden API's password check: PBKDF2-HMAC-SHA-256 over the text of the client's
/// `masterPasswordHash`, exactly as `kemlock-api-bw` makes it, compared in constant time.
#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct Pbkdf2Check;

impl BwPasswordCheck for Pbkdf2Check {
    fn matches(&self, secret: &[u8], salt: &[u8], stored: &[u8], iterations: u32) -> bool {
        let Some(rounds) = NonZeroU32::new(iterations) else {
            return false;
        };
        pbkdf2::verify(pbkdf2::PBKDF2_HMAC_SHA256, rounds, salt, secret, stored).is_ok()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use kemlock_crypto::kx1;
    use kemlock_crypto::manifest::Entry;
    use kemlock_crypto::owner::Owner as CryptoOwner;
    use kemlock_crypto::sig1;

    fn bundle_of(key: &sig1::SigningKey) -> Vec<u8> {
        Bundle {
            account_id: [9; 16],
            key_version: 1,
            kx1_public: kx1::PublicKey::from_bytes(&[7; kx1::PUBLIC_KEY_LEN])
                .expect("a key of the right length"),
            sig1_public: key.public_key().expect("the public key derives"),
        }
        .to_bytes()
    }

    fn signed(key: &sig1::SigningKey, counter: u64) -> (Vec<u8>, Vec<u8>) {
        let manifest = Manifest {
            owner: CryptoOwner::user([9; 16]),
            counter,
            entries: vec![Entry::live([1; 16], 2, b"cipher")],
        };
        (
            manifest.to_bytes().expect("encodes"),
            manifest.sign(key).expect("signs"),
        )
    }

    #[test]
    fn a_manifest_signed_by_the_bundles_key_verifies() {
        let key = sig1::SigningKey::generate();
        let (bytes, signature) = signed(&key, 5);
        let header = Sig1Manifests
            .verify(&bundle_of(&key), &bytes, &signature)
            .expect("verifies");
        assert_eq!(header.counter, 5);
        assert_eq!(
            header.owner.to_string(),
            "user:09090909-0909-0909-0909-090909090909"
        );
    }

    #[test]
    fn another_key_or_a_changed_byte_is_refused() {
        let key = sig1::SigningKey::generate();
        let other = sig1::SigningKey::generate();
        let (bytes, signature) = signed(&key, 5);
        assert!(
            Sig1Manifests
                .verify(&bundle_of(&other), &bytes, &signature)
                .is_err()
        );
        let mut changed = bytes.clone();
        let last = changed.len() - 1;
        changed[last] ^= 1;
        assert!(
            Sig1Manifests
                .verify(&bundle_of(&key), &changed, &signature)
                .is_err()
        );
        assert!(Sig1Manifests.verify(&[1; 10], &bytes, &signature).is_err());
    }

    #[test]
    fn the_password_check_is_pbkdf2_sha256() {
        let rounds = NonZeroU32::new(1_000).expect("non-zero");
        let mut stored = [0u8; 32];
        pbkdf2::derive(
            pbkdf2::PBKDF2_HMAC_SHA256,
            rounds,
            b"salty",
            b"the-hash",
            &mut stored,
        );
        assert!(Pbkdf2Check.matches(b"the-hash", b"salty", &stored, 1_000));
        assert!(!Pbkdf2Check.matches(b"other", b"salty", &stored, 1_000));
        assert!(!Pbkdf2Check.matches(b"the-hash", b"salty", &[], 1_000));
        assert!(!Pbkdf2Check.matches(b"the-hash", b"salty", &stored, 0));
    }
}
