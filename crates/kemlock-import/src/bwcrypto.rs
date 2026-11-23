//! What a password-protected Bitwarden export needs: the KDF it records (PBKDF2-SHA256 or
//! Argon2id), the HKDF-Expand that stretches the result into an encryption and a MAC key, and
//! `EncString` type 2 (AES-256-CBC with an HMAC-SHA256 over IV and ciphertext).
//!
//! The export names its own KDF cost, so it is bounded before any work: PBKDF2 and Argon2 are held
//! to Bitwarden's own import bounds (5,000 rounds or more; 2 to 10 Argon2 passes, 16 MiB to 1 GiB,
//! 1 to 16 lanes) and to [`Limits`].

use std::fmt;

use aes::cipher::{BlockModeDecrypt, BlockModeEncrypt, KeyIvInit, block_padding::Pkcs7};
use argon2::{Algorithm, Argon2, Params, Version};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use hkdf::Hkdf;
use hmac::{Hmac, KeyInit as _, Mac as _};
use serde_json::Value;
use sha2::{Digest as _, Sha256};

use crate::error::{ImportError, Result};
use crate::limits::Limits;
use crate::util::jint;

/// The least PBKDF2 rounds an export may use (Bitwarden's import floor).
pub const MIN_PBKDF2_ITERATIONS: u32 = 5_000;
/// The least Argon2 passes.
pub const MIN_ARGON2_ITERATIONS: u32 = 2;
/// The least Argon2 memory, in MiB.
pub const MIN_ARGON2_MEMORY_MIB: u32 = 16;

/// The KDF an export records.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kdf {
    /// PBKDF2-HMAC-SHA256 with the salt as UTF-8.
    Pbkdf2 {
        /// Rounds.
        iterations: u32,
    },
    /// Argon2id with the SHA-256 of the salt as its salt.
    Argon2id {
        /// Passes.
        iterations: u32,
        /// Memory in MiB.
        memory_mib: u32,
        /// Lanes.
        parallelism: u32,
    },
}

/// Reads `kdfType`, `kdfIterations`, `kdfMemory` and `kdfParallelism` from a password-protected
/// export and checks them against the bounds. [`ImportError::KdfOutOfBounds`] for an unknown KDF
/// or a cost outside them.
pub fn kdf_from_export(export: &Value, limits: &Limits) -> Result<Kdf> {
    let within = |name: &str, least: u32, most: u32| -> Result<u32> {
        let value = jint(export, name).ok_or(ImportError::KdfOutOfBounds)?;
        u32::try_from(value)
            .ok()
            .filter(|v| (least..=most).contains(v))
            .ok_or(ImportError::KdfOutOfBounds)
    };
    match jint(export, "kdfType") {
        Some(0) => Ok(Kdf::Pbkdf2 {
            iterations: within(
                "kdfIterations",
                MIN_PBKDF2_ITERATIONS,
                limits.max_pbkdf2_iterations,
            )?,
        }),
        Some(1) => Ok(Kdf::Argon2id {
            iterations: within(
                "kdfIterations",
                MIN_ARGON2_ITERATIONS,
                limits.max_argon2_iterations,
            )?,
            memory_mib: within(
                "kdfMemory",
                MIN_ARGON2_MEMORY_MIB,
                limits.max_argon2_memory_kib / 1024,
            )?,
            parallelism: within("kdfParallelism", 1, limits.max_argon2_parallelism)?,
        }),
        _ => Err(ImportError::KdfOutOfBounds),
    }
}

/// The two keys an `EncString` uses.
#[derive(Clone, PartialEq, Eq)]
pub struct ExportKey {
    enc: [u8; 32],
    mac: [u8; 32],
}

impl fmt::Debug for ExportKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ExportKey(..)")
    }
}

impl ExportKey {
    /// Wraps two 32-byte keys.
    pub fn new(enc: [u8; 32], mac: [u8; 32]) -> ExportKey {
        ExportKey { enc, mac }
    }
}

fn pbkdf2_sha256(password: &[u8], salt: &[u8], rounds: u32) -> Result<[u8; 32]> {
    let base = Hmac::<Sha256>::new_from_slice(password).map_err(|_| ImportError::BadPassword)?;
    let mut first = base.clone();
    first.update(salt);
    first.update(&1u32.to_be_bytes());
    let mut u = first.finalize().into_bytes();
    let mut out = [0u8; 32];
    out.copy_from_slice(u.as_slice());
    for _ in 1..rounds {
        let mut mac = base.clone();
        mac.update(u.as_slice());
        u = mac.finalize().into_bytes();
        for (o, b) in out.iter_mut().zip(u.as_slice()) {
            *o ^= *b;
        }
    }
    Ok(out)
}

/// `deriveVaultExportKey`: the KDF, then HKDF-Expand (no extract) with `enc` and `mac` as info.
/// The caller has bounded `kdf` with [`kdf_from_export`].
pub fn derive_export_key(password: &str, salt: &str, kdf: Kdf) -> Result<ExportKey> {
    let master: [u8; 32] = match kdf {
        Kdf::Pbkdf2 { iterations } => {
            pbkdf2_sha256(password.as_bytes(), salt.as_bytes(), iterations)?
        }
        Kdf::Argon2id {
            iterations,
            memory_mib,
            parallelism,
        } => {
            let memory_kib = memory_mib
                .checked_mul(1024)
                .ok_or(ImportError::KdfOutOfBounds)?;
            let params = Params::new(memory_kib, iterations, parallelism, Some(32))
                .map_err(|_| ImportError::KdfOutOfBounds)?;
            let argon = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
            let salt_hash = Sha256::digest(salt.as_bytes());
            let mut out = [0u8; 32];
            argon
                .hash_password_into(password.as_bytes(), salt_hash.as_slice(), &mut out)
                .map_err(|_| ImportError::KdfOutOfBounds)?;
            out
        }
    };
    let hkdf = Hkdf::<Sha256>::from_prk(&master).map_err(|_| ImportError::BadPassword)?;
    let mut enc = [0u8; 32];
    let mut mac = [0u8; 32];
    hkdf.expand(b"enc", &mut enc)
        .map_err(|_| ImportError::BadPassword)?;
    hkdf.expand(b"mac", &mut mac)
        .map_err(|_| ImportError::BadPassword)?;
    Ok(ExportKey { enc, mac })
}

/// Opens an `EncString` of type 2 (`2.<iv>|<ciphertext>|<mac>`, each part base64). A damaged string
/// is [`ImportError::Malformed`]; a MAC that doesn't match, which is what a wrong password gives,
/// is [`ImportError::BadPassword`]. Any other type is [`ImportError::UnsupportedEncryption`].
pub fn decrypt_enc_string(enc: &str, key: &ExportKey) -> Result<Vec<u8>> {
    let damaged = || ImportError::malformed("an encrypted value is damaged");
    let (kind, rest) = enc.split_once('.').ok_or_else(damaged)?;
    if kind != "2" {
        return Err(ImportError::UnsupportedEncryption(
            "an encrypted value of a type other than 2".to_string(),
        ));
    }
    let mut parts = rest.split('|');
    let (Some(iv), Some(ct), Some(tag), None) =
        (parts.next(), parts.next(), parts.next(), parts.next())
    else {
        return Err(damaged());
    };
    let iv = STANDARD.decode(iv.as_bytes()).map_err(|_| damaged())?;
    let ct = STANDARD.decode(ct.as_bytes()).map_err(|_| damaged())?;
    let tag = STANDARD.decode(tag.as_bytes()).map_err(|_| damaged())?;
    if iv.len() != 16 {
        return Err(damaged());
    }
    let mut mac = Hmac::<Sha256>::new_from_slice(&key.mac).map_err(|_| ImportError::BadPassword)?;
    mac.update(&iv);
    mac.update(&ct);
    mac.verify_slice(&tag)
        .map_err(|_| ImportError::BadPassword)?;
    let cipher =
        cbc::Decryptor::<aes::Aes256>::new_from_slices(&key.enc, &iv).map_err(|_| damaged())?;
    cipher
        .decrypt_padded_vec::<Pkcs7>(&ct)
        .map_err(|_| ImportError::BadPassword)
}

/// Writes an `EncString` of type 2 (`2.<iv>|<ciphertext>|<mac>`, each part standard base64 with
/// padding): AES-256-CBC with PKCS#7 padding under `key`'s encryption key and the given IV, and an
/// HMAC-SHA256 over the IV and the ciphertext under its MAC key. The IV must be 16 random bytes,
/// fresh for every value; the caller supplies it so this stays pure.
pub fn encrypt_enc_string(plain: &[u8], key: &ExportKey, iv: &[u8; 16]) -> Result<String> {
    let broken = || ImportError::malformed("a value can't be encrypted");
    let cipher =
        cbc::Encryptor::<aes::Aes256>::new_from_slices(&key.enc, iv).map_err(|_| broken())?;
    let ct = cipher.encrypt_padded_vec::<Pkcs7>(plain);
    let mut mac = Hmac::<Sha256>::new_from_slice(&key.mac).map_err(|_| broken())?;
    mac.update(iv);
    mac.update(&ct);
    let tag = mac.finalize().into_bytes();
    Ok(format!(
        "2.{}|{}|{}",
        STANDARD.encode(iv),
        STANDARD.encode(&ct),
        STANDARD.encode(tag.as_slice())
    ))
}

/// [`decrypt_enc_string`], as UTF-8 text.
pub fn decrypt_enc_text(enc: &str, key: &ExportKey) -> Result<String> {
    let bytes = decrypt_enc_string(enc, key)?;
    String::from_utf8(bytes).map_err(|_| ImportError::malformed("encrypted text is not UTF-8"))
}

#[cfg(test)]
mod tests {
    use super::*;

    // Made with Node's crypto: PBKDF2-SHA256 (5,000 rounds) or Argon2id (2 passes, 16 MiB, 1 lane)
    // over password "correct horse" and salt "c2FsdHNhbHRzYWx0", HKDF-Expand with "enc" and "mac",
    // AES-256-CBC with the IV 00..0f, HMAC-SHA256 over IV and ciphertext. The plaintext is "hello".
    const SALT: &str = "c2FsdHNhbHRzYWx0";
    const PBKDF2_ENC: &str = "2.AAECAwQFBgcICQoLDA0ODw==|GF95MqGLkY//3Cgp2zEmkQ==|PBALJ9oFE2edEHve8mE64cLpVOaDTYyxdO3Zd+NL3+A=";
    const ARGON2_ENC: &str = "2.AAECAwQFBgcICQoLDA0ODw==|UcIu3Ue24N64ZttlBFXSCQ==|SIWonhuro/6MDXMNJ4iz8a4ViYB3mKFr7UJorQdVNbI=";

    fn hex(bytes: &[u8]) -> String {
        use std::fmt::Write as _;
        let mut out = String::new();
        for b in bytes {
            let _ = write!(out, "{b:02x}");
        }
        out
    }

    #[test]
    fn pbkdf2_matches_the_known_master_key() {
        let master = pbkdf2_sha256(b"correct horse", SALT.as_bytes(), 5000).expect("pbkdf2");
        assert_eq!(
            hex(&master),
            "9b20d2bcee3448a382feb57048d8866f14a6f160d13fcd7d9765585d079540c7"
        );
    }

    #[test]
    fn opens_a_pbkdf2_encstring() {
        let key = derive_export_key("correct horse", SALT, Kdf::Pbkdf2 { iterations: 5000 })
            .expect("key");
        assert_eq!(decrypt_enc_text(PBKDF2_ENC, &key).expect("open"), "hello");
    }

    #[test]
    fn opens_an_argon2id_encstring() {
        let key = derive_export_key(
            "correct horse",
            SALT,
            Kdf::Argon2id {
                iterations: 2,
                memory_mib: 16,
                parallelism: 1,
            },
        )
        .expect("key");
        assert_eq!(decrypt_enc_text(ARGON2_ENC, &key).expect("open"), "hello");
    }

    #[test]
    fn writes_the_encstrings_it_reads() {
        // The known vectors above: same key, same IV, same plaintext, same string.
        let iv: [u8; 16] = core::array::from_fn(|i| u8::try_from(i).expect("small"));
        let key = derive_export_key("correct horse", SALT, Kdf::Pbkdf2 { iterations: 5000 })
            .expect("key");
        assert_eq!(
            encrypt_enc_string(b"hello", &key, &iv).expect("encrypt"),
            PBKDF2_ENC
        );
        let key = derive_export_key(
            "correct horse",
            SALT,
            Kdf::Argon2id {
                iterations: 2,
                memory_mib: 16,
                parallelism: 1,
            },
        )
        .expect("key");
        assert_eq!(
            encrypt_enc_string(b"hello", &key, &iv).expect("encrypt"),
            ARGON2_ENC
        );
    }

    #[test]
    fn what_is_written_opens_for_any_length_and_fails_when_altered() {
        let key = ExportKey::new([3; 32], [4; 32]);
        for len in [0usize, 1, 15, 16, 17, 1000] {
            let plain: Vec<u8> = (0..len)
                .map(|i| u8::try_from(i % 251).expect("small"))
                .collect();
            let text = encrypt_enc_string(&plain, &key, &[9; 16]).expect("encrypt");
            assert!(text.starts_with("2."));
            assert_eq!(decrypt_enc_string(&text, &key).expect("opens"), plain);
        }
        let text = encrypt_enc_string(b"secret", &key, &[9; 16]).expect("encrypt");
        let (head, tag) = text.rsplit_once('|').expect("three parts");
        let swap = if tag.starts_with('A') { "B" } else { "A" };
        let forged = format!("{head}|{swap}{}", &tag[1..]);
        assert_eq!(
            decrypt_enc_string(&forged, &key),
            Err(ImportError::BadPassword)
        );
        let other = ExportKey::new([5; 32], [6; 32]);
        assert_eq!(
            decrypt_enc_string(&text, &other),
            Err(ImportError::BadPassword)
        );
    }

    #[test]
    fn a_wrong_password_fails_the_mac() {
        let key = derive_export_key("wrong", SALT, Kdf::Pbkdf2 { iterations: 5000 }).expect("key");
        assert_eq!(
            decrypt_enc_string(PBKDF2_ENC, &key),
            Err(ImportError::BadPassword)
        );
    }

    #[test]
    fn damaged_encstrings_are_told_from_wrong_passwords() {
        let key = derive_export_key("correct horse", SALT, Kdf::Pbkdf2 { iterations: 5000 })
            .expect("key");
        for bad in [
            "",
            "nonsense",
            "2.onlyone",
            "2.a|b",
            "2.!!!|!!!|!!!",
            "2.AAEC|AAEC|AAEC",
            "2.AAECAwQFBgcICQoLDA0ODw==|GF95MqGLkY//3Cgp2zEmkQ==|PBAL|extra",
        ] {
            assert!(
                matches!(
                    decrypt_enc_string(bad, &key),
                    Err(ImportError::Malformed(_))
                ),
                "{bad}"
            );
        }
        assert!(matches!(
            decrypt_enc_string("0.AAECAwQFBgcICQoLDA0ODw==|AAEC", &key),
            Err(ImportError::UnsupportedEncryption(_))
        ));
        // A flipped ciphertext bit is caught by the MAC.
        let flipped = PBKDF2_ENC.replace("GF95", "GF96");
        assert_eq!(
            decrypt_enc_string(&flipped, &key),
            Err(ImportError::BadPassword)
        );
    }

    #[test]
    fn kdf_settings_are_bounded() {
        let limits = Limits::default();
        let ok = |v: serde_json::Value| kdf_from_export(&v, &limits);
        assert_eq!(
            ok(serde_json::json!({"kdfType": 0, "kdfIterations": 600000})),
            Ok(Kdf::Pbkdf2 {
                iterations: 600_000
            })
        );
        assert_eq!(
            ok(
                serde_json::json!({"kdfType": 1, "kdfIterations": 3, "kdfMemory": 64, "kdfParallelism": 4})
            ),
            Ok(Kdf::Argon2id {
                iterations: 3,
                memory_mib: 64,
                parallelism: 4
            })
        );
        for bad in [
            serde_json::json!({}),
            serde_json::json!({"kdfType": 2, "kdfIterations": 600000}),
            serde_json::json!({"kdfType": 0, "kdfIterations": 4999}),
            serde_json::json!({"kdfType": 0, "kdfIterations": 2000001}),
            serde_json::json!({"kdfType": 0, "kdfIterations": -1}),
            serde_json::json!({"kdfType": 0}),
            serde_json::json!({"kdfType": 1, "kdfIterations": 1, "kdfMemory": 64, "kdfParallelism": 4}),
            serde_json::json!({"kdfType": 1, "kdfIterations": 3, "kdfMemory": 4096, "kdfParallelism": 4}),
            serde_json::json!({"kdfType": 1, "kdfIterations": 3, "kdfMemory": 8, "kdfParallelism": 4}),
            serde_json::json!({"kdfType": 1, "kdfIterations": 3, "kdfMemory": 64, "kdfParallelism": 0}),
            serde_json::json!({"kdfType": 1, "kdfIterations": 3, "kdfMemory": 64, "kdfParallelism": 99}),
        ] {
            assert_eq!(ok(bad.clone()), Err(ImportError::KdfOutOfBounds), "{bad}");
        }
        let small = Limits::small();
        assert_eq!(
            kdf_from_export(
                &serde_json::json!({"kdfType": 0, "kdfIterations": 600000}),
                &small
            ),
            Err(ImportError::KdfOutOfBounds)
        );
    }

    #[test]
    fn debug_never_shows_key_bytes() {
        let key = ExportKey::new([7; 32], [9; 32]);
        assert_eq!(format!("{key:?}"), "ExportKey(..)");
    }
}
