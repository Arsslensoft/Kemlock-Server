//! Server-side secrets: values the server must read again, sealed under `server.key`.
//!
//! ```text
//! sealed = u8(1) ‖ AES-256-GCM(HKDF(server.key, info = "kemlock/v1/server-seal" ‖ lp(purpose)),
//!                              nonce, value, aad = lp(purpose))
//! ```
//!
//! Purposes include `"opaque-setup"`, `"totp"`, `"token-signing-key"` and `"smtp-password"`. A value
//! sealed for one purpose does not open for another.

use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use crate::{
    Error, aead,
    backend::{Active, Backend},
    rand,
    wire::lp,
};

const VERSION: u8 = 1;
const INFO_LABEL: &[u8] = b"kemlock/v1/server-seal";

/// Makes a fresh `server.key`: 32 random bytes.
pub fn generate_server_key() -> [u8; 32] {
    rand::bytes()
}

/// Seals and opens values under one `server.key`. The key is wiped on drop; `Debug` shows none.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct ServerSeal {
    server_key: [u8; 32],
}

impl core::fmt::Debug for ServerSeal {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("ServerSeal").finish_non_exhaustive()
    }
}

impl ServerSeal {
    pub fn new(server_key: &[u8; 32]) -> ServerSeal {
        ServerSeal {
            server_key: *server_key,
        }
    }

    /// Seals `value` for `purpose`.
    ///
    /// # Panics
    ///
    /// Only if the operating system's random source fails, which [`rand::fill`] also panics on;
    /// use [`ServerSeal::try_seal`] to get an error instead.
    pub fn seal(&self, purpose: &str, value: &[u8]) -> Vec<u8> {
        match self.try_seal(purpose, value) {
            Ok(sealed) => sealed,
            Err(_) => panic!("sealing failed: the random source or the cipher is unavailable"),
        }
    }

    /// Seals `value` for `purpose`, or fails when sealing can't be done.
    pub fn try_seal(&self, purpose: &str, value: &[u8]) -> Result<Vec<u8>, Error> {
        seal_in::<Active>(&self.server_key, purpose, value)
    }

    /// Opens a sealed value, which is wiped when the result is dropped (a TOTP secret, the
    /// OPAQUE login state and the signing key all come out of here). Fails for another purpose,
    /// another `server.key`, an unknown version and any altered byte.
    pub fn open(&self, purpose: &str, sealed: &[u8]) -> Result<Zeroizing<Vec<u8>>, Error> {
        open_in::<Active>(&self.server_key, purpose, sealed)
    }
}

/// The AEAD key and additional data of a purpose.
fn derive<B: Backend>(
    server_key: &[u8; 32],
    purpose: &str,
) -> Result<(Zeroizing<[u8; 32]>, Vec<u8>), Error> {
    let mut info = Vec::with_capacity(INFO_LABEL.len() + 4 + purpose.len());
    info.extend_from_slice(INFO_LABEL);
    lp(&mut info, purpose.as_bytes())?;
    let mut key = Zeroizing::new([0u8; 32]);
    B::hkdf_sha256(server_key, None, &info, &mut *key)?;
    let mut aad = Vec::with_capacity(4 + purpose.len());
    lp(&mut aad, purpose.as_bytes())?;
    Ok((key, aad))
}

pub(crate) fn seal_in<B: Backend>(
    server_key: &[u8; 32],
    purpose: &str,
    value: &[u8],
) -> Result<Vec<u8>, Error> {
    let (key, aad) = derive::<B>(server_key, purpose)?;
    let sealed = aead::seal::<B>(&key, &aad, value)?;
    let mut out = Vec::with_capacity(1 + sealed.len());
    out.push(VERSION);
    out.extend_from_slice(&sealed);
    Ok(out)
}

pub(crate) fn open_in<B: Backend>(
    server_key: &[u8; 32],
    purpose: &str,
    sealed: &[u8],
) -> Result<Zeroizing<Vec<u8>>, Error> {
    match sealed.split_first() {
        Some((&VERSION, rest)) if rest.len() >= aead::OVERHEAD => {
            let (key, aad) = derive::<B>(server_key, purpose)?;
            aead::open::<B>(&key, &aad, rest)
        }
        _ => Err(Error::invalid()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn server_keys_are_random() {
        assert_ne!(generate_server_key(), generate_server_key());
    }

    #[test]
    fn round_trips_through_the_public_api() {
        let seal = ServerSeal::new(&[1; 32]);
        let sealed = seal.seal("totp", b"JBSWY3DPEHPK3PXP");
        assert_eq!(sealed[0], 1);
        assert_eq!(sealed.len(), 1 + 12 + 16 + 16);
        assert_eq!(
            seal.open("totp", &sealed).expect("open").as_slice(),
            b"JBSWY3DPEHPK3PXP"
        );
    }

    #[test]
    fn an_opened_value_is_wiped_on_drop() {
        // The type is the guarantee: `open` hands back a `Zeroizing` buffer, so a caller that
        // holds a TOTP secret or a login state wipes it when it lets go, with nothing to remember.
        let seal = ServerSeal::new(&[1; 32]);
        let sealed = seal.seal("totp", b"secret");
        let opened: Zeroizing<Vec<u8>> = seal.open("totp", &sealed).expect("open");
        assert_eq!(opened.as_slice(), b"secret");
        let mut copy = opened.clone();
        copy.zeroize();
        assert!(copy.is_empty());
    }

    #[test]
    fn purposes_are_separate() {
        for_backends!(B => {
            let sealed = seal_in::<B>(&[1; 32], "totp", b"secret").expect("seal");
            assert!(open_in::<B>(&[1; 32], "totp", &sealed).is_ok());
            assert!(open_in::<B>(&[1; 32], "smtp-password", &sealed).is_err());
            assert!(open_in::<B>(&[1; 32], "", &sealed).is_err());
            assert!(open_in::<B>(&[2; 32], "totp", &sealed).is_err());
        });
    }

    #[test]
    fn tampering_versions_and_short_input_fail() {
        for_backends!(B => {
            let sealed = seal_in::<B>(&[1; 32], "totp", b"secret").expect("seal");
            for i in 0..sealed.len() {
                let mut bad = sealed.clone();
                bad[i] ^= 1;
                assert!(open_in::<B>(&[1; 32], "totp", &bad).is_err(), "byte {i}");
            }
            assert!(open_in::<B>(&[1; 32], "totp", &[]).is_err());
            assert!(open_in::<B>(&[1; 32], "totp", &sealed[..1 + 27]).is_err());
            assert!(open_in::<B>(&[1; 32], "totp", &sealed[1..]).is_err());
        });
    }

    #[test]
    fn nothing_is_the_same_twice() {
        let seal = ServerSeal::new(&[1; 32]);
        assert_ne!(seal.seal("totp", b"x"), seal.seal("totp", b"x"));
    }

    #[test]
    fn empty_values_work() {
        let seal = ServerSeal::new(&[1; 32]);
        let sealed = seal.seal("totp", b"");
        assert!(seal.open("totp", &sealed).expect("open").is_empty());
    }

    #[test]
    fn debug_shows_no_key() {
        assert!(!format!("{:?}", ServerSeal::new(&[0xEE; 32])).contains("238"));
    }

    #[cfg(feature = "aws-lc")]
    #[test]
    fn seals_open_across_backends() {
        use crate::backend::{aws_lc::AwsLc, rustcrypto::RustCrypto};
        let a = seal_in::<AwsLc>(&[1; 32], "totp", b"one").expect("seal");
        let b = seal_in::<RustCrypto>(&[1; 32], "totp", b"two").expect("seal");
        assert_eq!(
            open_in::<RustCrypto>(&[1; 32], "totp", &a)
                .expect("open")
                .as_slice(),
            b"one"
        );
        assert_eq!(
            open_in::<AwsLc>(&[1; 32], "totp", &b)
                .expect("open")
                .as_slice(),
            b"two"
        );
    }
}
