//! The sealed box: a short secret (a key) sealed to a `kx1` public key under a context label.
//!
//! ```text
//! (ct, ss) = kx1.Encaps(pk)
//! key      = HKDF(ikm = ss, salt = absent, info = "kemlock/v1/seal" ‖ lp(context), L = 32)
//! box      = u8(1) ‖ ct (1600) ‖ AES-256-GCM(key, nonce, secret, aad = lp(context) ‖ lp(aad))
//! ```
//!
//! `aad` is the caller's extra binding (the recipient's account id, say); it isn't stored in the
//! box. Opening under another context or another `aad` fails.
//!
//! Sealing works on both backends; opening needs the RustCrypto one (see the crate docs).

use zeroize::Zeroizing;

use crate::{
    Error, aead,
    backend::{Active, Backend},
    kx1,
    wire::lp,
};

const VERSION: u8 = 1;
const INFO_LABEL: &[u8] = b"kemlock/v1/seal";

/// What a box adds to its secret: version byte, `kx1` ciphertext, nonce and tag.
pub const OVERHEAD: usize = 1 + kx1::CIPHERTEXT_LEN + aead::OVERHEAD;

/// Contexts in use (`docs/crypto.md`).
pub mod context {
    /// The root key to a new device's one-time key pair.
    pub const DEVICE_APPROVAL: &str = "device-approval";
    /// A space key to a member.
    pub const SPACE_KEY: &str = "space-key";
    /// A collection key to a member.
    pub const COLLECTION_KEY: &str = "collection-key";
    /// A root key to an emergency contact.
    pub const EMERGENCY_ACCESS: &str = "emergency-access";
    /// A member's root key to a space's recovery key.
    pub const ACCOUNT_RECOVERY: &str = "account-recovery";
}

/// The AEAD key and additional data for one box.
fn derive<B: Backend>(
    shared: &kx1::SharedSecret,
    context: &str,
    aad: &[u8],
) -> Result<(Zeroizing<[u8; 32]>, Vec<u8>), Error> {
    let mut info = Vec::with_capacity(INFO_LABEL.len() + 4 + context.len());
    info.extend_from_slice(INFO_LABEL);
    lp(&mut info, context.as_bytes())?;
    let mut key = Zeroizing::new([0u8; 32]);
    B::hkdf_sha256(shared.as_bytes(), None, &info, &mut *key)?;

    let mut full_aad = Vec::with_capacity(8 + context.len() + aad.len());
    lp(&mut full_aad, context.as_bytes())?;
    lp(&mut full_aad, aad)?;
    Ok((key, full_aad))
}

/// Seals `secret` to `public` under `context`, binding `aad`.
pub fn seal(
    public: &kx1::PublicKey,
    context: &str,
    aad: &[u8],
    secret: &[u8],
) -> Result<Vec<u8>, Error> {
    seal_in::<Active>(public, context, aad, secret)
}

pub(crate) fn seal_in<B: Backend>(
    public: &kx1::PublicKey,
    context: &str,
    aad: &[u8],
    secret: &[u8],
) -> Result<Vec<u8>, Error> {
    let (ciphertext, shared) = kx1::encapsulate_in::<B>(public)?;
    let (key, full_aad) = derive::<B>(&shared, context, aad)?;
    let sealed = aead::seal::<B>(&key, &full_aad, secret)?;
    let mut out = Vec::with_capacity(1 + ciphertext.len() + sealed.len());
    out.push(VERSION);
    out.extend_from_slice(&ciphertext);
    out.extend_from_slice(&sealed);
    Ok(out)
}

/// Opens a box with the recipient's private key. Fails under another context or `aad`, for another
/// recipient, and for any altered byte.
pub fn open(
    private: &kx1::PrivateKey,
    context: &str,
    aad: &[u8],
    sealed_box: &[u8],
) -> Result<Zeroizing<Vec<u8>>, Error> {
    open_in::<Active>(private, context, aad, sealed_box)
}

pub(crate) fn open_in<B: Backend>(
    private: &kx1::PrivateKey,
    context: &str,
    aad: &[u8],
    sealed_box: &[u8],
) -> Result<Zeroizing<Vec<u8>>, Error> {
    // Every length is checked before anything is decrypted.
    if sealed_box.len() < OVERHEAD || sealed_box[0] != VERSION {
        return Err(Error::invalid());
    }
    let (ciphertext, sealed) = sealed_box[1..].split_at(kx1::CIPHERTEXT_LEN);
    let shared = kx1::decapsulate_in::<B>(private, ciphertext)?;
    let (key, full_aad) = derive::<B>(&shared, context, aad)?;
    aead::open::<B>(&key, &full_aad, sealed)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn overhead_is_1629() {
        assert_eq!(OVERHEAD, 1 + 1600 + 12 + 16);
    }

    /// The same tests on every backend that is built, each in its own module.
    macro_rules! backend_suite {
        ($name:ident, $backend:ty) => {
            mod $name {
                use super::*;
                type B = $backend;

                fn keypair() -> (kx1::PrivateKey, kx1::PublicKey) {
                    let private = kx1::PrivateKey::from_bytes(&[5; 96]);
                    let public = kx1::public_key_in::<B>(&private).expect("public key");
                    (private, public)
                }

                #[test]
                fn round_trips() {
                    let (private, public) = keypair();
                    let boxed = seal_in::<B>(&public, context::SPACE_KEY, b"acct", &[7u8; 32])
                        .expect("seal");
                    assert_eq!(boxed.len(), OVERHEAD + 32);
                    assert_eq!(boxed[0], 1);
                    let opened =
                        open_in::<B>(&private, context::SPACE_KEY, b"acct", &boxed).expect("open");
                    assert_eq!(opened.as_slice(), &[7u8; 32]);
                }

                #[test]
                fn wrong_context_or_aad_fails() {
                    let (private, public) = keypair();
                    let boxed = seal_in::<B>(&public, context::SPACE_KEY, b"acct", b"secret")
                        .expect("seal");
                    assert!(
                        open_in::<B>(&private, context::COLLECTION_KEY, b"acct", &boxed).is_err()
                    );
                    assert!(open_in::<B>(&private, context::SPACE_KEY, b"other", &boxed).is_err());
                    assert!(open_in::<B>(&private, "", b"acct", &boxed).is_err());
                }

                #[test]
                fn context_and_aad_cannot_run_into_each_other() {
                    // lp() keeps ("ab", "c") and ("a", "bc") apart.
                    let (private, public) = keypair();
                    let boxed = seal_in::<B>(&public, "ab", b"c", b"secret").expect("seal");
                    assert!(open_in::<B>(&private, "a", b"bc", &boxed).is_err());
                    assert!(open_in::<B>(&private, "ab", b"c", &boxed).is_ok());
                }

                #[test]
                fn another_recipient_cannot_open_it() {
                    let (_, public) = keypair();
                    let boxed = seal_in::<B>(&public, context::DEVICE_APPROVAL, b"", b"secret")
                        .expect("seal");
                    let other = kx1::PrivateKey::from_bytes(&[6; 96]);
                    assert!(open_in::<B>(&other, context::DEVICE_APPROVAL, b"", &boxed).is_err());
                }

                #[test]
                fn every_tampered_region_fails() {
                    let (private, public) = keypair();
                    let boxed = seal_in::<B>(&public, context::DEVICE_APPROVAL, b"", b"secret")
                        .expect("seal");
                    // The version byte, both halves of the kx1 ciphertext, the nonce, the body, the
                    // tag.
                    for i in [
                        0usize,
                        1,
                        700,
                        1568,
                        1569,
                        1599,
                        1600,
                        1601,
                        1612,
                        1613,
                        boxed.len() - 1,
                    ] {
                        let mut bad = boxed.clone();
                        bad[i] ^= 1;
                        assert!(
                            open_in::<B>(&private, context::DEVICE_APPROVAL, b"", &bad).is_err(),
                            "byte {i}"
                        );
                    }
                }

                #[test]
                fn short_and_long_boxes_are_refused() {
                    let (private, public) = keypair();
                    let boxed = seal_in::<B>(&public, context::DEVICE_APPROVAL, b"", b"secret")
                        .expect("seal");
                    assert!(
                        open_in::<B>(
                            &private,
                            context::DEVICE_APPROVAL,
                            b"",
                            &boxed[..OVERHEAD - 1]
                        )
                        .is_err()
                    );
                    assert!(open_in::<B>(&private, context::DEVICE_APPROVAL, b"", &[]).is_err());
                    let mut long = boxed.clone();
                    long.push(0);
                    assert!(open_in::<B>(&private, context::DEVICE_APPROVAL, b"", &long).is_err());
                }

                #[test]
                fn an_empty_secret_round_trips() {
                    let (private, public) = keypair();
                    let boxed = seal_in::<B>(&public, "x", b"", b"").expect("seal");
                    assert_eq!(boxed.len(), OVERHEAD);
                    assert!(
                        open_in::<B>(&private, "x", b"", &boxed)
                            .expect("open")
                            .is_empty()
                    );
                }
            }
        };
    }

    backend_suite!(rustcrypto, crate::backend::rustcrypto::RustCrypto);
    #[cfg(feature = "aws-lc")]
    backend_suite!(aws_lc, crate::backend::aws_lc::AwsLc);

    #[cfg(feature = "aws-lc")]
    #[test]
    fn a_box_sealed_by_aws_lc_opens_with_rustcrypto_and_the_other_way_round() {
        use crate::backend::{aws_lc::AwsLc, rustcrypto::RustCrypto};
        let private = kx1::PrivateKey::from_bytes(&[5; 96]);
        let public = kx1::public_key_in::<RustCrypto>(&private).expect("public key");

        let boxed =
            seal_in::<AwsLc>(&public, context::SPACE_KEY, b"acct", b"from aws-lc").expect("seal");
        for opened in [
            open_in::<RustCrypto>(&private, context::SPACE_KEY, b"acct", &boxed).expect("open"),
            open_in::<AwsLc>(&private, context::SPACE_KEY, b"acct", &boxed).expect("open"),
        ] {
            assert_eq!(opened.as_slice(), b"from aws-lc");
        }

        let boxed = seal_in::<RustCrypto>(&public, context::SPACE_KEY, b"acct", b"from rustcrypto")
            .expect("seal");
        let opened = open_in::<AwsLc>(&private, context::SPACE_KEY, b"acct", &boxed).expect("open");
        assert_eq!(opened.as_slice(), b"from rustcrypto");
    }

    #[test]
    fn the_public_api_seals_and_opens_on_the_default_backend() {
        let (private, public) = kx1::generate().expect("generate");
        let boxed = seal(&public, context::SPACE_KEY, b"acct", b"secret").expect("seal");
        let opened = open(&private, context::SPACE_KEY, b"acct", &boxed).expect("open");
        assert_eq!(opened.as_slice(), b"secret");
    }
}
