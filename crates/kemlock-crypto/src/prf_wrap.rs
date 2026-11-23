//! The passkey PRF wrap of the root key.
//!
//! A passkey with the WebAuthn PRF extension wraps one more copy of the root key. The PRF is
//! evaluated with `first = SHA-256("kemlock/v1/prf-salt")`.
//!
//! ```text
//! wrap key = HKDF(ikm = PRF output (32), salt = absent,
//!                 info = "kemlock/v1/prf-wrap" ‖ lp(credential id), L = 32)
//! aad      = "kemlock/v1/root-wrap/prf" ‖ account id (16) ‖ u32be(key version) ‖ lp(credential id)
//! wrapped  = AES-256-GCM(wrap key, nonce, root key, aad)
//! ```
//!
//! The credential id is the raw WebAuthn credential id. This is the layout `docs/crypto.md` fixes
//! under "The passkey PRF wrap of the root key". The server stores the wrap as an opaque blob and
//! never opens it.

use zeroize::Zeroizing;

use crate::{
    Error, aead,
    backend::{Active, Backend},
    keys::{ROOT_KEY_LEN, RootKey, SecretKey},
    wire::lp,
};

const SALT_LABEL: &[u8] = b"kemlock/v1/prf-salt";
const WRAP_INFO: &[u8] = b"kemlock/v1/prf-wrap";
const AAD_LABEL: &[u8] = b"kemlock/v1/root-wrap/prf";

/// The length of a wrapped root key: nonce, 64 key bytes, tag.
pub const WRAPPED_LEN: usize = ROOT_KEY_LEN + aead::OVERHEAD;

/// The salt a client gives the PRF extension as `first`: `SHA-256("kemlock/v1/prf-salt")`.
pub fn prf_salt() -> [u8; 32] {
    prf_salt_in::<Active>()
}

pub(crate) fn prf_salt_in<B: Backend>() -> [u8; 32] {
    B::sha256(SALT_LABEL)
}

/// The key the root key is wrapped under, from the PRF output and the credential's id.
pub fn wrap_key(prf_output: &[u8; 32], credential_id: &[u8]) -> Result<SecretKey, Error> {
    wrap_key_in::<Active>(prf_output, credential_id)
}

pub(crate) fn wrap_key_in<B: Backend>(
    prf_output: &[u8; 32],
    credential_id: &[u8],
) -> Result<SecretKey, Error> {
    let mut info = Vec::with_capacity(WRAP_INFO.len() + 4 + credential_id.len());
    info.extend_from_slice(WRAP_INFO);
    lp(&mut info, credential_id)?;
    let mut out = Zeroizing::new([0u8; 32]);
    B::hkdf_sha256(prf_output, None, &info, &mut *out)?;
    Ok(SecretKey::from_bytes(&out))
}

/// The additional data the wrap binds: the account, the key version and the credential.
pub fn aad(
    account_id: &[u8; 16],
    key_version: u32,
    credential_id: &[u8],
) -> Result<Vec<u8>, Error> {
    let mut out = Vec::with_capacity(AAD_LABEL.len() + 20 + credential_id.len());
    out.extend_from_slice(AAD_LABEL);
    out.extend_from_slice(account_id);
    out.extend_from_slice(&key_version.to_be_bytes());
    lp(&mut out, credential_id)?;
    Ok(out)
}

/// Wraps the root key: `nonce(12) ‖ ciphertext(64) ‖ tag(16)`.
pub fn seal(
    prf_output: &[u8; 32],
    credential_id: &[u8],
    root: &RootKey,
    account_id: &[u8; 16],
    key_version: u32,
) -> Result<Vec<u8>, Error> {
    seal_in::<Active>(prf_output, credential_id, root, account_id, key_version)
}

pub(crate) fn seal_in<B: Backend>(
    prf_output: &[u8; 32],
    credential_id: &[u8],
    root: &RootKey,
    account_id: &[u8; 16],
    key_version: u32,
) -> Result<Vec<u8>, Error> {
    let key = wrap_key_in::<B>(prf_output, credential_id)?;
    aead::seal::<B>(
        key.as_bytes(),
        &aad(account_id, key_version, credential_id)?,
        root.as_bytes(),
    )
}

/// Opens a wrapped root key. Fails for another PRF output, credential, account or key version,
/// and for any altered byte.
pub fn open(
    prf_output: &[u8; 32],
    credential_id: &[u8],
    wrapped: &[u8],
    account_id: &[u8; 16],
    key_version: u32,
) -> Result<RootKey, Error> {
    open_in::<Active>(prf_output, credential_id, wrapped, account_id, key_version)
}

pub(crate) fn open_in<B: Backend>(
    prf_output: &[u8; 32],
    credential_id: &[u8],
    wrapped: &[u8],
    account_id: &[u8; 16],
    key_version: u32,
) -> Result<RootKey, Error> {
    if wrapped.len() != WRAPPED_LEN {
        return Err(Error::invalid());
    }
    let key = wrap_key_in::<B>(prf_output, credential_id)?;
    let plain = aead::open::<B>(
        key.as_bytes(),
        &aad(account_id, key_version, credential_id)?,
        wrapped,
    )?;
    let bytes: &[u8; ROOT_KEY_LEN] = plain.as_slice().try_into().map_err(|_| Error::invalid())?;
    Ok(RootKey::from_bytes(bytes))
}

#[cfg(test)]
mod tests {
    use super::*;

    const PRF: [u8; 32] = [1; 32];
    const CREDENTIAL: &[u8] = &[9, 8, 7, 6];
    const ACCOUNT: [u8; 16] = [3; 16];

    #[test]
    fn the_salt_is_the_hash_of_its_label() {
        for_backends!(B => {
            assert_eq!(prf_salt_in::<B>(), B::sha256(b"kemlock/v1/prf-salt"), "{}", B::NAME);
        });
    }

    #[test]
    fn round_trips_on_every_backend() {
        for_backends!(B => {
            let root = RootKey::from_bytes(&[7u8; 64]);
            let wrapped = seal_in::<B>(&PRF, CREDENTIAL, &root, &ACCOUNT, 1).expect("seal");
            assert_eq!(wrapped.len(), WRAPPED_LEN);
            let opened = open_in::<B>(&PRF, CREDENTIAL, &wrapped, &ACCOUNT, 1).expect("open");
            assert_eq!(opened.as_bytes(), root.as_bytes());
        });
    }

    #[test]
    fn the_key_and_aad_are_the_documented_bytes() {
        for_backends!(B => {
            let mut info = b"kemlock/v1/prf-wrap".to_vec();
            info.extend_from_slice(&[0, 0, 0, 4, 9, 8, 7, 6]);
            let mut expected = [0u8; 32];
            B::hkdf_sha256(&PRF, None, &info, &mut expected).expect("hkdf");
            let key = wrap_key_in::<B>(&PRF, CREDENTIAL).expect("key");
            assert_eq!(key.as_bytes(), &expected, "{}", B::NAME);
        });
        let mut expected = b"kemlock/v1/root-wrap/prf".to_vec();
        expected.extend_from_slice(&ACCOUNT);
        expected.extend_from_slice(&[0, 0, 0, 2]);
        expected.extend_from_slice(&[0, 0, 0, 4, 9, 8, 7, 6]);
        assert_eq!(aad(&ACCOUNT, 2, CREDENTIAL).expect("aad"), expected);
    }

    #[test]
    fn another_prf_credential_account_or_version_fails() {
        for_backends!(B => {
            let root = RootKey::from_bytes(&[7u8; 64]);
            let wrapped = seal_in::<B>(&PRF, CREDENTIAL, &root, &ACCOUNT, 1).expect("seal");
            assert!(open_in::<B>(&[2; 32], CREDENTIAL, &wrapped, &ACCOUNT, 1).is_err());
            assert!(open_in::<B>(&PRF, &[9, 8, 7], &wrapped, &ACCOUNT, 1).is_err());
            assert!(open_in::<B>(&PRF, CREDENTIAL, &wrapped, &[4; 16], 1).is_err());
            assert!(open_in::<B>(&PRF, CREDENTIAL, &wrapped, &ACCOUNT, 2).is_err());
            let mut altered = wrapped.clone();
            altered[20] ^= 1;
            assert!(open_in::<B>(&PRF, CREDENTIAL, &altered, &ACCOUNT, 1).is_err());
            assert!(open_in::<B>(&PRF, CREDENTIAL, &wrapped[1..], &ACCOUNT, 1).is_err());
        });
    }

    #[test]
    fn a_password_wrap_is_not_a_prf_wrap() {
        // Same plaintext shape, different key and aad: neither opens the other.
        for_backends!(B => {
            let root = RootKey::from_bytes(&[7u8; 64]);
            let wrapped =
                crate::password_wrap::seal_in::<B>(&[1; 32], &[2; 64], &root, &ACCOUNT, 1)
                    .expect("seal");
            assert!(open_in::<B>(&PRF, CREDENTIAL, &wrapped, &ACCOUNT, 1).is_err());
        });
    }
}
