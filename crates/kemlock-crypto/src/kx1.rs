//! `kx1`, the hybrid exchange key: ML-KEM-1024 + X25519.
//!
//! - Public key: `ML-KEM-1024 encapsulation key (1568) ‖ X25519 public key (32)`, 1600 bytes.
//! - Private key: `ML-KEM-1024 seed d ‖ z (64) ‖ X25519 private key (32)`, 96 bytes.
//! - Shared secret: `SHA3-256("kemlock/v1/kx1" ‖ ss_m ‖ ss_x ‖ ct_x ‖ pk_x)`, X-Wing's combiner over
//!   ML-KEM-1024. The ciphertext is `ct_m (1568) ‖ ct_x (32)`.
//!
//! Every operation works on both backends. aws-lc-rs can't expand an ML-KEM seed, so on the aws-lc
//! backend deriving a public key and decapsulating run that one step on RustCrypto's `ml-kem` (see
//! the crate docs); encapsulating to a public key stays on aws-lc.

use core::fmt;

use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use crate::{
    Error,
    backend::{Active, Backend, MLKEM_CIPHERTEXT_LEN, MLKEM_PUBLIC_LEN, MLKEM_SEED_LEN},
    rand,
    wire::{array, array_ref},
};

const LABEL: &[u8] = b"kemlock/v1/kx1";
const X25519_LEN: usize = 32;

/// The length of a public key.
pub const PUBLIC_KEY_LEN: usize = MLKEM_PUBLIC_LEN + X25519_LEN;
/// The length of a private key.
pub const PRIVATE_KEY_LEN: usize = MLKEM_SEED_LEN + X25519_LEN;
/// The length of a ciphertext.
pub const CIPHERTEXT_LEN: usize = MLKEM_CIPHERTEXT_LEN + X25519_LEN;
/// The length of the shared secret.
pub const SHARED_SECRET_LEN: usize = 32;

/// A ciphertext: `ct_m ‖ ct_x`.
pub type Ciphertext = [u8; CIPHERTEXT_LEN];

/// A `kx1` public key.
#[derive(Clone, PartialEq, Eq)]
pub struct PublicKey(Box<[u8; PUBLIC_KEY_LEN]>);

impl PublicKey {
    /// Takes the 1600 bytes of a public key. The ML-KEM half is validated when it is used.
    pub fn from_bytes(bytes: &[u8]) -> Result<PublicKey, Error> {
        Ok(PublicKey(Box::new(array(bytes)?)))
    }

    pub fn as_bytes(&self) -> &[u8; PUBLIC_KEY_LEN] {
        &self.0
    }

    /// Encapsulates to this key: a ciphertext for its holder and the shared secret.
    pub fn encapsulate(&self) -> Result<(Ciphertext, SharedSecret), Error> {
        encapsulate_in::<Active>(self)
    }
}

impl fmt::Debug for PublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("kx1::PublicKey").finish_non_exhaustive()
    }
}

/// A `kx1` private key. Wiped on drop; `Debug` shows no contents.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct PrivateKey([u8; PRIVATE_KEY_LEN]);

impl PrivateKey {
    pub fn from_bytes(bytes: &[u8; PRIVATE_KEY_LEN]) -> PrivateKey {
        PrivateKey(*bytes)
    }

    pub fn as_bytes(&self) -> &[u8; PRIVATE_KEY_LEN] {
        &self.0
    }

    /// The matching public key.
    pub fn public_key(&self) -> Result<PublicKey, Error> {
        public_key_in::<Active>(self)
    }

    /// Recovers the shared secret from a ciphertext. A ciphertext
    /// made for another key gives a different secret rather than an error (ML-KEM's implicit
    /// rejection), so opening what the secret protects is what fails.
    pub fn decapsulate(&self, ciphertext: &[u8]) -> Result<SharedSecret, Error> {
        decapsulate_in::<Active>(self, ciphertext)
    }
}

impl fmt::Debug for PrivateKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("kx1::PrivateKey").finish_non_exhaustive()
    }
}

/// The 32-byte shared secret. Wiped on drop.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct SharedSecret([u8; SHARED_SECRET_LEN]);

impl SharedSecret {
    pub fn as_bytes(&self) -> &[u8; SHARED_SECRET_LEN] {
        &self.0
    }
}

impl fmt::Debug for SharedSecret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("kx1::SharedSecret").finish_non_exhaustive()
    }
}

/// A fresh key pair.
pub fn generate() -> Result<(PrivateKey, PublicKey), Error> {
    generate_in::<Active>()
}

pub(crate) fn generate_in<B: Backend>() -> Result<(PrivateKey, PublicKey), Error> {
    let mut bytes = Zeroizing::new([0u8; PRIVATE_KEY_LEN]);
    rand::try_fill::<B>(&mut *bytes)?;
    let private = PrivateKey(*bytes);
    let public = public_key_in::<B>(&private)?;
    Ok((private, public))
}

pub(crate) fn public_key_in<B: Backend>(private: &PrivateKey) -> Result<PublicKey, Error> {
    let seed: &[u8; MLKEM_SEED_LEN] = array_ref(&private.0[..MLKEM_SEED_LEN])?;
    let x_secret: &[u8; X25519_LEN] = array_ref(&private.0[MLKEM_SEED_LEN..])?;
    let mlkem_public = B::mlkem1024_public(seed)?;
    if mlkem_public.len() != MLKEM_PUBLIC_LEN {
        return Err(Error::invalid());
    }
    let x_public = B::x25519_public(x_secret)?;
    let mut out = Box::new([0u8; PUBLIC_KEY_LEN]);
    out[..MLKEM_PUBLIC_LEN].copy_from_slice(&mlkem_public);
    out[MLKEM_PUBLIC_LEN..].copy_from_slice(&x_public);
    Ok(PublicKey(out))
}

/// `SHA3-256("kemlock/v1/kx1" ‖ ss_m ‖ ss_x ‖ ct_x ‖ pk_x)`.
fn combine<B: Backend>(
    ss_m: &[u8; 32],
    ss_x: &[u8; 32],
    ct_x: &[u8; 32],
    pk_x: &[u8; 32],
) -> SharedSecret {
    let mut input = Zeroizing::new(Vec::with_capacity(LABEL.len() + 128));
    input.extend_from_slice(LABEL);
    input.extend_from_slice(ss_m);
    input.extend_from_slice(ss_x);
    input.extend_from_slice(ct_x);
    input.extend_from_slice(pk_x);
    SharedSecret(B::sha3_256(&input))
}

pub(crate) fn encapsulate_in<B: Backend>(
    public: &PublicKey,
) -> Result<(Ciphertext, SharedSecret), Error> {
    let pk_m = &public.0[..MLKEM_PUBLIC_LEN];
    let pk_x: &[u8; X25519_LEN] = array_ref(&public.0[MLKEM_PUBLIC_LEN..])?;

    let (ct_m, ss_m) = B::mlkem1024_encaps(pk_m)?;
    let ss_m = Zeroizing::new(ss_m);
    if ct_m.len() != MLKEM_CIPHERTEXT_LEN {
        return Err(Error::invalid());
    }

    // An ephemeral X25519 key `e`: ct_x = X25519(e, 9), ss_x = X25519(e, pk_x), never all zero.
    let ephemeral = Zeroizing::new(rand::try_bytes::<B, X25519_LEN>()?);
    let ct_x = B::x25519_public(&ephemeral)?;
    let ss_x = Zeroizing::new(B::x25519(&ephemeral, pk_x)?);

    let secret = combine::<B>(&ss_m, &ss_x, &ct_x, pk_x);
    let mut ciphertext = [0u8; CIPHERTEXT_LEN];
    ciphertext[..MLKEM_CIPHERTEXT_LEN].copy_from_slice(&ct_m);
    ciphertext[MLKEM_CIPHERTEXT_LEN..].copy_from_slice(&ct_x);
    Ok((ciphertext, secret))
}

pub(crate) fn decapsulate_in<B: Backend>(
    private: &PrivateKey,
    ciphertext: &[u8],
) -> Result<SharedSecret, Error> {
    let ciphertext: &[u8; CIPHERTEXT_LEN] = array_ref(ciphertext)?;
    let ct_m = &ciphertext[..MLKEM_CIPHERTEXT_LEN];
    let ct_x: &[u8; X25519_LEN] = array_ref(&ciphertext[MLKEM_CIPHERTEXT_LEN..])?;
    let seed: &[u8; MLKEM_SEED_LEN] = array_ref(&private.0[..MLKEM_SEED_LEN])?;
    let x_secret: &[u8; X25519_LEN] = array_ref(&private.0[MLKEM_SEED_LEN..])?;

    // Neither half's failure is reported separately: any error here is the same error.
    let ss_m = Zeroizing::new(B::mlkem1024_decaps(seed, ct_m)?);
    let ss_x = Zeroizing::new(B::x25519(x_secret, ct_x)?);
    let pk_x = B::x25519_public(x_secret)?;
    Ok(combine::<B>(&ss_m, &ss_x, ct_x, &pk_x))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lengths_match_the_doc() {
        assert_eq!(PUBLIC_KEY_LEN, 1600);
        assert_eq!(PRIVATE_KEY_LEN, 96);
        assert_eq!(CIPHERTEXT_LEN, 1600);
    }

    #[test]
    fn public_key_parsing_checks_length() {
        assert!(PublicKey::from_bytes(&[0u8; 1599]).is_err());
        assert!(PublicKey::from_bytes(&[0u8; 1601]).is_err());
        assert!(PublicKey::from_bytes(&[0u8; 1600]).is_ok());
    }

    #[test]
    fn debug_shows_no_contents() {
        let key = PrivateKey::from_bytes(&[0xEE; 96]);
        assert!(!format!("{key:?}").contains("238"));
    }

    /// The same tests on every backend that is built, each in its own module.
    macro_rules! backend_suite {
        ($name:ident, $backend:ty) => {
            mod $name {
                use super::*;
                type B = $backend;

                fn keypair(byte: u8) -> (PrivateKey, PublicKey) {
                    let private = PrivateKey::from_bytes(&[byte; 96]);
                    let public = public_key_in::<B>(&private).expect("public key");
                    (private, public)
                }

                #[test]
                fn encapsulate_then_decapsulate_agree() {
                    let (private, public) = keypair(1);
                    let (ciphertext, sent) = encapsulate_in::<B>(&public).expect("encaps");
                    let received = decapsulate_in::<B>(&private, &ciphertext).expect("decaps");
                    assert_eq!(sent.as_bytes(), received.as_bytes());
                }

                #[test]
                fn generate_makes_a_working_pair() {
                    let (private, public) = generate_in::<B>().expect("generate");
                    assert_eq!(public_key_in::<B>(&private).expect("public"), public);
                    let (ciphertext, sent) = encapsulate_in::<B>(&public).expect("encaps");
                    let received = decapsulate_in::<B>(&private, &ciphertext).expect("decaps");
                    assert_eq!(sent.as_bytes(), received.as_bytes());
                }

                #[test]
                fn encapsulations_are_fresh() {
                    let (_, public) = keypair(2);
                    let (c1, s1) = encapsulate_in::<B>(&public).expect("encaps");
                    let (c2, s2) = encapsulate_in::<B>(&public).expect("encaps");
                    assert_ne!(c1, c2);
                    assert_ne!(s1.as_bytes(), s2.as_bytes());
                }

                #[test]
                fn another_key_gets_a_different_secret() {
                    let (_, public) = keypair(1);
                    let (other, _) = keypair(2);
                    let (ciphertext, sent) = encapsulate_in::<B>(&public).expect("encaps");
                    // Implicit rejection: ML-KEM gives a pseudo-random secret, and the X25519 half
                    // differs.
                    let received = decapsulate_in::<B>(&other, &ciphertext).expect("decaps");
                    assert_ne!(sent.as_bytes(), received.as_bytes());
                }

                #[test]
                fn swapping_either_half_changes_the_secret() {
                    let (private, public) = keypair(1);
                    let (_, other_public) = keypair(2);
                    let (other_ct, _) = encapsulate_in::<B>(&other_public).expect("encaps");
                    let (ciphertext, sent) = encapsulate_in::<B>(&public).expect("encaps");

                    // Only the ML-KEM half of the ciphertext from another key.
                    let mut mlkem_swapped = ciphertext;
                    mlkem_swapped[..1568].copy_from_slice(&other_ct[..1568]);
                    let a = decapsulate_in::<B>(&private, &mlkem_swapped).expect("decaps");
                    assert_ne!(a.as_bytes(), sent.as_bytes());

                    // Only the X25519 half.
                    let mut x_swapped = ciphertext;
                    x_swapped[1568..].copy_from_slice(&other_ct[1568..]);
                    let b = decapsulate_in::<B>(&private, &x_swapped).expect("decaps");
                    assert_ne!(b.as_bytes(), sent.as_bytes());
                    assert_ne!(a.as_bytes(), b.as_bytes());
                }

                #[test]
                fn tampered_ciphertext_changes_the_secret() {
                    let (private, public) = keypair(3);
                    let (ciphertext, sent) = encapsulate_in::<B>(&public).expect("encaps");
                    for i in [0usize, 100, 1567, 1568, 1599] {
                        let mut bad = ciphertext;
                        bad[i] ^= 1;
                        if let Ok(secret) = decapsulate_in::<B>(&private, &bad) {
                            assert_ne!(secret.as_bytes(), sent.as_bytes(), "byte {i}");
                        }
                    }
                }

                #[test]
                fn wrong_lengths_are_errors() {
                    let (private, public) = keypair(1);
                    let (ciphertext, _) = encapsulate_in::<B>(&public).expect("encaps");
                    assert!(decapsulate_in::<B>(&private, &ciphertext[..1599]).is_err());
                    let mut long = ciphertext.to_vec();
                    long.push(0);
                    assert!(decapsulate_in::<B>(&private, &long).is_err());
                }

                #[test]
                fn a_zero_x25519_public_key_is_refused() {
                    let (_, public) = keypair(1);
                    let mut bytes = *public.as_bytes();
                    bytes[1568..].fill(0);
                    let weak = PublicKey::from_bytes(&bytes).expect("length is right");
                    assert!(encapsulate_in::<B>(&weak).is_err());
                }

                #[test]
                fn the_secret_is_the_documented_hash() {
                    let (private, public) = keypair(4);
                    let (ciphertext, secret) = encapsulate_in::<B>(&public).expect("encaps");
                    let ss_m = B::mlkem1024_decaps(
                        array_ref(&private.as_bytes()[..64]).expect("seed"),
                        &ciphertext[..1568],
                    )
                    .expect("decaps");
                    let x_secret: &[u8; 32] = array_ref(&private.as_bytes()[64..]).expect("x25519");
                    let ss_x = B::x25519(x_secret, array_ref(&ciphertext[1568..]).expect("ct_x"))
                        .expect("x25519");
                    let mut input = b"kemlock/v1/kx1".to_vec();
                    input.extend_from_slice(&ss_m);
                    input.extend_from_slice(&ss_x);
                    input.extend_from_slice(&ciphertext[1568..]);
                    input.extend_from_slice(&public.as_bytes()[1568..]);
                    assert_eq!(&B::sha3_256(&input), secret.as_bytes());
                }
            }
        };
    }

    backend_suite!(rustcrypto, crate::backend::rustcrypto::RustCrypto);
    #[cfg(feature = "aws-lc")]
    backend_suite!(aws_lc, crate::backend::aws_lc::AwsLc);

    #[cfg(feature = "aws-lc")]
    mod cross {
        use super::*;
        use crate::backend::{aws_lc::AwsLc, rustcrypto::RustCrypto};

        fn seed_key() -> PrivateKey {
            PrivateKey::from_bytes(&[9; 96])
        }

        #[test]
        fn both_backends_expand_a_seed_to_the_same_public_key() {
            let private = seed_key();
            assert_eq!(
                public_key_in::<AwsLc>(&private).expect("aws-lc"),
                public_key_in::<RustCrypto>(&private).expect("rustcrypto")
            );
        }

        #[test]
        fn aws_lc_encapsulates_and_both_backends_open_it() {
            let private = seed_key();
            let public = public_key_in::<RustCrypto>(&private).expect("public key");
            let (ciphertext, sent) = encapsulate_in::<AwsLc>(&public).expect("encaps");
            for received in [
                decapsulate_in::<AwsLc>(&private, &ciphertext).expect("aws-lc decaps"),
                decapsulate_in::<RustCrypto>(&private, &ciphertext).expect("rustcrypto decaps"),
            ] {
                assert_eq!(sent.as_bytes(), received.as_bytes());
            }
        }

        #[test]
        fn rustcrypto_encapsulates_and_aws_lc_opens_it() {
            let private = seed_key();
            let public = public_key_in::<AwsLc>(&private).expect("public key");
            let (ciphertext, sent) = encapsulate_in::<RustCrypto>(&public).expect("encaps");
            let received = decapsulate_in::<AwsLc>(&private, &ciphertext).expect("decaps");
            assert_eq!(sent.as_bytes(), received.as_bytes());
        }

        #[test]
        fn a_key_generated_on_one_backend_works_on_the_other() {
            let (private, public) = generate_in::<AwsLc>().expect("generate");
            assert_eq!(
                public_key_in::<RustCrypto>(&private).expect("public"),
                public
            );
            let (ciphertext, sent) = encapsulate_in::<RustCrypto>(&public).expect("encaps");
            let received = decapsulate_in::<AwsLc>(&private, &ciphertext).expect("decaps");
            assert_eq!(sent.as_bytes(), received.as_bytes());
        }
    }

    #[test]
    fn the_public_api_round_trips_on_the_default_backend() {
        let (private, public) = generate().expect("generate");
        assert_eq!(private.public_key().expect("public"), public);
        let (ciphertext, sent) = public.encapsulate().expect("encaps");
        let received = private.decapsulate(&ciphertext).expect("decaps");
        assert_eq!(sent.as_bytes(), received.as_bytes());
    }
}
