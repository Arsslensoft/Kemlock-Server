//! The password wrap of the root key on Kemlock-only accounts.
//!
//! ```text
//! wrap key = HKDF(ikm = master key ‖ OPAQUE export key, salt = absent,
//!                 info = "kemlock/v1/password-wrap", L = 32)
//! aad      = "kemlock/v1/root-wrap" ‖ account id (16) ‖ u32be(key version)
//! wrapped  = AES-256-GCM(wrap key, nonce, root key, aad)
//! ```
//!
//! Neither the master key nor the export key alone opens the wrap.

use zeroize::Zeroizing;

use crate::{
    Error, aead,
    backend::{Active, Backend},
    keys::{ROOT_KEY_LEN, RootKey, SecretKey},
};

const WRAP_INFO: &[u8] = b"kemlock/v1/password-wrap";
const AAD_LABEL: &[u8] = b"kemlock/v1/root-wrap";

/// The length of a wrapped root key: nonce, 64 key bytes, tag.
pub const WRAPPED_LEN: usize = ROOT_KEY_LEN + aead::OVERHEAD;

/// The key the root key is wrapped under.
pub fn wrap_key(master_key: &[u8; 32], export_key: &[u8; 64]) -> Result<SecretKey, Error> {
    wrap_key_in::<Active>(master_key, export_key)
}

pub(crate) fn wrap_key_in<B: Backend>(
    master_key: &[u8; 32],
    export_key: &[u8; 64],
) -> Result<SecretKey, Error> {
    let mut ikm = Zeroizing::new([0u8; 96]);
    ikm[..32].copy_from_slice(master_key);
    ikm[32..].copy_from_slice(export_key);
    let mut out = Zeroizing::new([0u8; 32]);
    B::hkdf_sha256(&*ikm, None, WRAP_INFO, &mut *out)?;
    Ok(SecretKey::from_bytes(&out))
}

/// The additional data the wrap binds: the account and the key version.
pub fn aad(account_id: &[u8; 16], key_version: u32) -> Vec<u8> {
    let mut out = Vec::with_capacity(AAD_LABEL.len() + 20);
    out.extend_from_slice(AAD_LABEL);
    out.extend_from_slice(account_id);
    out.extend_from_slice(&key_version.to_be_bytes());
    out
}

/// Wraps the root key: `nonce(12) ‖ ciphertext(64) ‖ tag(16)`.
pub fn seal(
    master_key: &[u8; 32],
    export_key: &[u8; 64],
    root: &RootKey,
    account_id: &[u8; 16],
    key_version: u32,
) -> Result<Vec<u8>, Error> {
    seal_in::<Active>(master_key, export_key, root, account_id, key_version)
}

pub(crate) fn seal_in<B: Backend>(
    master_key: &[u8; 32],
    export_key: &[u8; 64],
    root: &RootKey,
    account_id: &[u8; 16],
    key_version: u32,
) -> Result<Vec<u8>, Error> {
    let key = wrap_key_in::<B>(master_key, export_key)?;
    aead::seal::<B>(
        key.as_bytes(),
        &aad(account_id, key_version),
        root.as_bytes(),
    )
}

/// Opens a wrapped root key. Fails for a wrong master key or export key, another account or key
/// version, and any altered byte.
pub fn open(
    master_key: &[u8; 32],
    export_key: &[u8; 64],
    wrapped: &[u8],
    account_id: &[u8; 16],
    key_version: u32,
) -> Result<RootKey, Error> {
    open_in::<Active>(master_key, export_key, wrapped, account_id, key_version)
}

pub(crate) fn open_in<B: Backend>(
    master_key: &[u8; 32],
    export_key: &[u8; 64],
    wrapped: &[u8],
    account_id: &[u8; 16],
    key_version: u32,
) -> Result<RootKey, Error> {
    if wrapped.len() != WRAPPED_LEN {
        return Err(Error::invalid());
    }
    let key = wrap_key_in::<B>(master_key, export_key)?;
    let plain = aead::open::<B>(key.as_bytes(), &aad(account_id, key_version), wrapped)?;
    let bytes: &[u8; ROOT_KEY_LEN] = plain.as_slice().try_into().map_err(|_| Error::invalid())?;
    Ok(RootKey::from_bytes(bytes))
}

#[cfg(test)]
mod tests {
    use super::*;

    const MASTER: [u8; 32] = [1; 32];
    const EXPORT: [u8; 64] = [2; 64];
    const ACCOUNT: [u8; 16] = [3; 16];

    #[test]
    fn round_trips() {
        for_backends!(B => {
            let root = RootKey::from_bytes(&[7u8; 64]);
            let wrapped = seal_in::<B>(&MASTER, &EXPORT, &root, &ACCOUNT, 1).expect("seal");
            assert_eq!(wrapped.len(), WRAPPED_LEN);
            let opened = open_in::<B>(&MASTER, &EXPORT, &wrapped, &ACCOUNT, 1).expect("open");
            assert_eq!(opened.as_bytes(), root.as_bytes(), "{}", B::NAME);
        });
    }

    #[test]
    fn neither_secret_alone_opens_it() {
        for_backends!(B => {
            let root = RootKey::from_bytes(&[7u8; 64]);
            let wrapped = seal_in::<B>(&MASTER, &EXPORT, &root, &ACCOUNT, 1).expect("seal");
            assert!(open_in::<B>(&[9; 32], &EXPORT, &wrapped, &ACCOUNT, 1).is_err());
            assert!(open_in::<B>(&MASTER, &[9; 64], &wrapped, &ACCOUNT, 1).is_err());
        });
    }

    #[test]
    fn account_and_key_version_are_bound() {
        for_backends!(B => {
            let root = RootKey::from_bytes(&[7u8; 64]);
            let wrapped = seal_in::<B>(&MASTER, &EXPORT, &root, &ACCOUNT, 1).expect("seal");
            assert!(open_in::<B>(&MASTER, &EXPORT, &wrapped, &[4; 16], 1).is_err());
            assert!(open_in::<B>(&MASTER, &EXPORT, &wrapped, &ACCOUNT, 2).is_err());
        });
    }

    #[test]
    fn tampering_and_wrong_lengths_fail() {
        for_backends!(B => {
            let root = RootKey::from_bytes(&[7u8; 64]);
            let wrapped = seal_in::<B>(&MASTER, &EXPORT, &root, &ACCOUNT, 1).expect("seal");
            for i in 0..wrapped.len() {
                let mut bad = wrapped.clone();
                bad[i] ^= 0x80;
                assert!(open_in::<B>(&MASTER, &EXPORT, &bad, &ACCOUNT, 1).is_err(), "byte {i}");
            }
            let mut long = wrapped.clone();
            long.push(0);
            assert!(open_in::<B>(&MASTER, &EXPORT, &long, &ACCOUNT, 1).is_err());
            assert!(open_in::<B>(&MASTER, &EXPORT, &wrapped[1..], &ACCOUNT, 1).is_err());
        });
    }

    #[test]
    fn aad_layout_matches_the_doc() {
        let aad = aad(&ACCOUNT, 0x0102_0304);
        assert_eq!(&aad[..20], b"kemlock/v1/root-wrap");
        assert_eq!(&aad[20..36], &ACCOUNT);
        assert_eq!(&aad[36..], &[1, 2, 3, 4]);
    }

    #[cfg(feature = "aws-lc")]
    #[test]
    fn a_wrap_made_on_one_backend_opens_on_the_other() {
        use crate::backend::{aws_lc::AwsLc, rustcrypto::RustCrypto};
        let root = RootKey::from_bytes(&[7u8; 64]);
        let a = seal_in::<AwsLc>(&MASTER, &EXPORT, &root, &ACCOUNT, 1).expect("seal");
        let b = seal_in::<RustCrypto>(&MASTER, &EXPORT, &root, &ACCOUNT, 1).expect("seal");
        assert_eq!(
            open_in::<RustCrypto>(&MASTER, &EXPORT, &a, &ACCOUNT, 1)
                .expect("open")
                .as_bytes(),
            root.as_bytes()
        );
        assert_eq!(
            open_in::<AwsLc>(&MASTER, &EXPORT, &b, &ACCOUNT, 1)
                .expect("open")
                .as_bytes(),
            root.as_bytes()
        );
    }
}
