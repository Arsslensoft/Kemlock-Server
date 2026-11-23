//! The account's sealed private keys: what a Kemlock-only account stores as `sealed_private_keys`.
//!
//! ```text
//! seal key  = the user key's child "kemlock/v1/private-keys"
//! plaintext = u8(1) ‖ kx1 private key (96) ‖ sig1 private key (64)   (161 bytes)
//! aad       = "kemlock/v1/private-keys" ‖ account id (16) ‖ u32be(key version)
//! sealed    = AES-256-GCM(seal key, nonce, plaintext, aad)   (nonce ‖ ciphertext ‖ tag)
//! ```
//!
//! This is the layout `docs/crypto.md` fixes under "The account's private keys", so the
//! web vault, the command-line client and the app agree. The blob is 189 bytes. The account id and
//! key version are bound, so a blob can't be moved to another account or passed off as an older
//! generation.

use zeroize::Zeroizing;

use crate::{
    Error, aead,
    backend::{Active, Backend},
    keys::{PRIVATE_KEYS_LABEL, SecretKey},
    kx1, sig1,
    wire::array_ref,
};

const AAD_LABEL: &[u8] = b"kemlock/v1/private-keys";
const PLAINTEXT_VERSION: u8 = 1;

/// What is sealed: a version byte, the `kx1` private key, then the `sig1` private key.
pub const PLAINTEXT_LEN: usize = 1 + kx1::PRIVATE_KEY_LEN + sig1::PRIVATE_KEY_LEN;
/// The length of the sealed blob: nonce, version byte, both private keys, tag.
pub const SEALED_LEN: usize = PLAINTEXT_LEN + aead::OVERHEAD;

/// The additional data the seal binds: the account and the key version.
pub fn aad(account_id: &[u8; 16], key_version: u32) -> Vec<u8> {
    let mut out = Vec::with_capacity(AAD_LABEL.len() + 20);
    out.extend_from_slice(AAD_LABEL);
    out.extend_from_slice(account_id);
    out.extend_from_slice(&key_version.to_be_bytes());
    out
}

/// Seals the account's two private keys under the user key's `"kemlock/v1/private-keys"` child.
pub fn seal(
    user_key: &SecretKey,
    kx1_private: &kx1::PrivateKey,
    sig1_private: &sig1::SigningKey,
    account_id: &[u8; 16],
    key_version: u32,
) -> Result<Vec<u8>, Error> {
    seal_in::<Active>(user_key, kx1_private, sig1_private, account_id, key_version)
}

pub(crate) fn seal_in<B: Backend>(
    user_key: &SecretKey,
    kx1_private: &kx1::PrivateKey,
    sig1_private: &sig1::SigningKey,
    account_id: &[u8; 16],
    key_version: u32,
) -> Result<Vec<u8>, Error> {
    let key = user_key.child_in::<B>(PRIVATE_KEYS_LABEL)?;
    let mut plain = Zeroizing::new(Vec::with_capacity(PLAINTEXT_LEN));
    plain.push(PLAINTEXT_VERSION);
    plain.extend_from_slice(kx1_private.as_bytes());
    plain.extend_from_slice(sig1_private.as_bytes());
    aead::seal::<B>(key.as_bytes(), &aad(account_id, key_version), &plain)
}

/// Opens the blob. Fails under another user key, account or key version, for a blob of any other
/// length and for any altered byte.
pub fn open(
    user_key: &SecretKey,
    sealed: &[u8],
    account_id: &[u8; 16],
    key_version: u32,
) -> Result<(kx1::PrivateKey, sig1::SigningKey), Error> {
    open_in::<Active>(user_key, sealed, account_id, key_version)
}

pub(crate) fn open_in<B: Backend>(
    user_key: &SecretKey,
    sealed: &[u8],
    account_id: &[u8; 16],
    key_version: u32,
) -> Result<(kx1::PrivateKey, sig1::SigningKey), Error> {
    if sealed.len() != SEALED_LEN {
        return Err(Error::invalid());
    }
    let key = user_key.child_in::<B>(PRIVATE_KEYS_LABEL)?;
    let plain = aead::open::<B>(key.as_bytes(), &aad(account_id, key_version), sealed)?;
    if plain.len() != PLAINTEXT_LEN || plain[0] != PLAINTEXT_VERSION {
        return Err(Error::invalid());
    }
    let (kx, sig) = plain[1..].split_at(kx1::PRIVATE_KEY_LEN);
    Ok((
        kx1::PrivateKey::from_bytes(array_ref(kx)?),
        sig1::SigningKey::from_bytes(array_ref(sig)?),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    const ACCOUNT: [u8; 16] = [3; 16];

    fn keys() -> (kx1::PrivateKey, sig1::SigningKey) {
        (
            kx1::PrivateKey::from_bytes(&[5; kx1::PRIVATE_KEY_LEN]),
            sig1::SigningKey::from_bytes(&[6; sig1::PRIVATE_KEY_LEN]),
        )
    }

    #[test]
    fn sizes_match_the_layout() {
        assert_eq!(PLAINTEXT_LEN, 161);
        assert_eq!(SEALED_LEN, 189);
    }

    #[test]
    fn round_trips() {
        for_backends!(B => {
            let user = SecretKey::from_bytes(&[9; 32]);
            let (kx, sig) = keys();
            let sealed = seal_in::<B>(&user, &kx, &sig, &ACCOUNT, 1).expect("seal");
            assert_eq!(sealed.len(), SEALED_LEN, "{}", B::NAME);
            let (kx2, sig2) = open_in::<B>(&user, &sealed, &ACCOUNT, 1).expect("open");
            assert_eq!(kx2.as_bytes(), kx.as_bytes());
            assert_eq!(sig2.as_bytes(), sig.as_bytes());
        });
    }

    #[test]
    fn user_key_account_and_version_are_bound() {
        for_backends!(B => {
            let user = SecretKey::from_bytes(&[9; 32]);
            let (kx, sig) = keys();
            let sealed = seal_in::<B>(&user, &kx, &sig, &ACCOUNT, 1).expect("seal");
            assert!(open_in::<B>(&SecretKey::from_bytes(&[8; 32]), &sealed, &ACCOUNT, 1).is_err());
            assert!(open_in::<B>(&user, &sealed, &[4; 16], 1).is_err());
            assert!(open_in::<B>(&user, &sealed, &ACCOUNT, 2).is_err());
        });
    }

    #[test]
    fn tampering_and_wrong_lengths_fail() {
        for_backends!(B => {
            let user = SecretKey::from_bytes(&[9; 32]);
            let (kx, sig) = keys();
            let sealed = seal_in::<B>(&user, &kx, &sig, &ACCOUNT, 1).expect("seal");
            for i in 0..sealed.len() {
                let mut bad = sealed.clone();
                bad[i] ^= 0x80;
                assert!(open_in::<B>(&user, &bad, &ACCOUNT, 1).is_err(), "byte {i}");
            }
            let mut long = sealed.clone();
            long.push(0);
            assert!(open_in::<B>(&user, &long, &ACCOUNT, 1).is_err());
            assert!(open_in::<B>(&user, &sealed[1..], &ACCOUNT, 1).is_err());
        });
    }

    #[test]
    fn aad_layout_matches_the_doc() {
        let aad = aad(&ACCOUNT, 0x0102_0304);
        assert_eq!(&aad[..23], b"kemlock/v1/private-keys");
        assert_eq!(&aad[23..39], &ACCOUNT);
        assert_eq!(&aad[39..], &[1, 2, 3, 4]);
    }
}
