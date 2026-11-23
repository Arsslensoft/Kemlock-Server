//! Known-answer tests of every primitive on every compiled-in backend, and cross-checks between
//! the two backends when both are on.

use super::*;

fn unhex(s: &str) -> Vec<u8> {
    hex::decode(s).expect("hex")
}

#[test]
fn hashes_known_answers() {
    for_backends!(B => {
        assert_eq!(
            hex::encode(B::sha256(b"abc")),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
            "{}", B::NAME
        );
        assert_eq!(
            hex::encode(B::sha512(b"abc")),
            "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f",
            "{}", B::NAME
        );
        assert_eq!(
            hex::encode(B::sha3_256(b"")),
            "a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a",
            "{}", B::NAME
        );
    });
}

#[test]
fn hmac_known_answers() {
    for_backends!(B => {
        assert_eq!(
            hex::encode(B::hmac_sha256(b"Jefe", b"what do ya want for nothing?")),
            "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843",
            "{}", B::NAME
        );
        // RFC 2202 test case 2.
        assert_eq!(
            hex::encode(B::hmac_sha1(b"Jefe", b"what do ya want for nothing?")),
            "effcdf6ae5eb2fa2d27416d5f184df9c259a7c79",
            "{}", B::NAME
        );
    });
}

#[test]
fn hkdf_rfc5869_test_case_3_without_a_salt() {
    for_backends!(B => {
        let mut okm = [0u8; 42];
        B::hkdf_sha256(&[0x0b; 22], None, b"", &mut okm).expect("hkdf");
        assert_eq!(
            hex::encode(okm),
            "8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d9d201395faa4b61a96c8",
            "{}", B::NAME
        );
        // An empty salt and an absent one are the same thing.
        let mut again = [0u8; 42];
        B::hkdf_sha256(&[0x0b; 22], Some(&[]), b"", &mut again).expect("hkdf");
        assert_eq!(okm, again);
    });
}

#[test]
fn hkdf_sha512_is_deterministic_and_depends_on_every_input() {
    for_backends!(B => {
        let mut a = [0u8; 64];
        let mut b = [0u8; 64];
        B::hkdf_sha512(b"ikm", Some(b"salt"), b"info", &mut a).expect("hkdf");
        B::hkdf_sha512(b"ikm", Some(b"salt"), b"info", &mut b).expect("hkdf");
        assert_eq!(a, b);
        B::hkdf_sha512(b"ikm", Some(b"salt"), b"info2", &mut b).expect("hkdf");
        assert_ne!(a, b);
        B::hkdf_sha512(b"ikm", Some(b"salt2"), b"info", &mut b).expect("hkdf");
        assert_ne!(a, b);
        B::hkdf_sha512(b"ikm2", Some(b"salt"), b"info", &mut b).expect("hkdf");
        assert_ne!(a, b);
    });
}

#[test]
fn aes_gcm_nist_test_cases_13_and_14() {
    for_backends!(B => {
        let key = [0u8; 32];
        let nonce = [0u8; 12];
        // Test case 13: nothing to encrypt, just the tag.
        let sealed = B::aes256gcm_seal(&key, &nonce, b"", b"").expect("seal");
        assert_eq!(hex::encode(&sealed), "530f8afbc74536b9a963b4f1c4cb738b", "{}", B::NAME);
        assert!(B::aes256gcm_open(&key, &nonce, b"", &sealed).expect("open").is_empty());
        // Test case 14: 16 zero bytes.
        let sealed = B::aes256gcm_seal(&key, &nonce, b"", &[0u8; 16]).expect("seal");
        assert_eq!(
            hex::encode(&sealed),
            "cea7403d4d606b6e074ec5d3baf39d18d0d1c8a799996bf0265b98b5d48ab919",
            "{}", B::NAME
        );
        assert_eq!(B::aes256gcm_open(&key, &nonce, b"", &sealed).expect("open"), [0u8; 16]);
    });
}

#[test]
fn aes_gcm_binds_key_nonce_aad_and_every_byte() {
    for_backends!(B => {
        let key = [7u8; 32];
        let nonce = [8u8; 12];
        let sealed = B::aes256gcm_seal(&key, &nonce, b"aad", b"hello").expect("seal");
        assert_eq!(sealed.len(), 5 + 16);
        assert!(B::aes256gcm_open(&[6u8; 32], &nonce, b"aad", &sealed).is_err());
        assert!(B::aes256gcm_open(&key, &[9u8; 12], b"aad", &sealed).is_err());
        assert!(B::aes256gcm_open(&key, &nonce, b"aae", &sealed).is_err());
        for i in 0..sealed.len() {
            let mut bad = sealed.clone();
            bad[i] ^= 1;
            assert!(B::aes256gcm_open(&key, &nonce, b"aad", &bad).is_err(), "byte {i}");
        }
        assert!(B::aes256gcm_open(&key, &nonce, b"aad", &sealed[..15]).is_err());
    });
}

#[test]
fn x25519_rfc7748_section_6_1() {
    for_backends!(B => {
        let alice: [u8; 32] = unhex("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a").try_into().expect("32");
        let bob: [u8; 32] = unhex("5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb").try_into().expect("32");
        let alice_public = B::x25519_public(&alice).expect("public");
        let bob_public = B::x25519_public(&bob).expect("public");
        assert_eq!(hex::encode(alice_public), "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a", "{}", B::NAME);
        assert_eq!(hex::encode(bob_public), "de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f", "{}", B::NAME);
        let shared = "4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742";
        assert_eq!(hex::encode(B::x25519(&alice, &bob_public).expect("dh")), shared);
        assert_eq!(hex::encode(B::x25519(&bob, &alice_public).expect("dh")), shared);
    });
}

#[test]
fn x25519_refuses_an_all_zero_result() {
    for_backends!(B => {
        // The point u = 0 has order 1 and gives an all-zero shared secret.
        assert!(B::x25519(&[1u8; 32], &[0u8; 32]).is_err(), "{}", B::NAME);
    });
}

#[test]
fn ed25519_rfc8032_test_1() {
    for_backends!(B => {
        let seed: [u8; 32] = unhex("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60").try_into().expect("32");
        let public = B::ed25519_public(&seed).expect("public");
        assert_eq!(hex::encode(public), "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a", "{}", B::NAME);
        let sig = B::ed25519_sign(&seed, b"").expect("sign");
        B::ed25519_verify(&public, b"", &sig).expect("verify");
        assert!(B::ed25519_verify(&public, b"x", &sig).is_err());
    });
}

#[test]
fn mldsa65_signs_and_verifies() {
    for_backends!(B => {
        let seed = [5u8; MLDSA_SEED_LEN];
        let public = B::mldsa65_public(&seed).expect("public");
        assert_eq!(public.len(), MLDSA_PUBLIC_LEN, "{}", B::NAME);
        let sig = B::mldsa65_sign(&seed, b"message").expect("sign");
        assert_eq!(sig.len(), MLDSA_SIGNATURE_LEN);
        B::mldsa65_verify(&public, b"message", &sig).expect("verify");
        assert!(B::mldsa65_verify(&public, b"messagf", &sig).is_err());
        let other = B::mldsa65_public(&[6u8; MLDSA_SEED_LEN]).expect("public");
        assert!(B::mldsa65_verify(&other, b"message", &sig).is_err());
        assert!(B::mldsa65_verify(&public, b"message", &sig[..sig.len() - 1]).is_err());
        assert!(B::mldsa65_verify(&public[..public.len() - 1], b"message", &sig).is_err());
    });
}

#[test]
fn mlkem_encapsulation_to_a_bad_key_fails() {
    for_backends!(B => {
        assert!(B::mlkem1024_encaps(&[0u8; 1567]).is_err(), "{}", B::NAME);
        assert!(B::mlkem1024_encaps(&[]).is_err());
    });
}

mod rc {
    use super::*;
    use crate::backend::rustcrypto::RustCrypto;

    #[test]
    fn mlkem1024_round_trips_from_a_seed() {
        for_backends!(B => {
            let seed = [3u8; MLKEM_SEED_LEN];
            let public = B::mlkem1024_public(&seed).expect("public");
            assert_eq!(public.len(), MLKEM_PUBLIC_LEN, "{}", B::NAME);
            let (ciphertext, sent) = B::mlkem1024_encaps(&public).expect("encaps");
            assert_eq!(ciphertext.len(), MLKEM_CIPHERTEXT_LEN);
            assert_eq!(
                B::mlkem1024_decaps(&seed, &ciphertext).expect("decaps"),
                sent,
                "{}", B::NAME
            );
        });
    }

    #[test]
    fn mlkem1024_implicit_rejection_gives_another_secret_not_an_error() {
        for_backends!(B => {
            let seed = [3u8; MLKEM_SEED_LEN];
            let public = B::mlkem1024_public(&seed).expect("public");
            let (mut ciphertext, sent) = B::mlkem1024_encaps(&public).expect("encaps");
            ciphertext[10] ^= 1;
            let got = B::mlkem1024_decaps(&seed, &ciphertext).expect("decaps");
            assert_ne!(got, sent, "{}", B::NAME);
            assert!(B::mlkem1024_decaps(&seed, &ciphertext[1..]).is_err());
        });
    }

    #[test]
    fn the_same_seed_gives_the_same_key() {
        for_backends!(B => {
            let a = B::mlkem1024_public(&[1u8; MLKEM_SEED_LEN]).expect("public");
            let b = B::mlkem1024_public(&[1u8; MLKEM_SEED_LEN]).expect("public");
            let c = B::mlkem1024_public(&[2u8; MLKEM_SEED_LEN]).expect("public");
            assert_eq!(a, b, "{}", B::NAME);
            assert_ne!(a, c);
        });
    }

    #[test]
    fn a_seeded_random_source_makes_encapsulation_reproducible() {
        let public = RustCrypto::mlkem1024_public(&[3u8; MLKEM_SEED_LEN]).expect("public");
        let run = || {
            crate::with_seeded_random([1; 32], || {
                RustCrypto::mlkem1024_encaps(&public).expect("encaps")
            })
        };
        assert_eq!(run(), run());
    }
}

#[cfg(feature = "aws-lc")]
mod cross {
    use super::*;
    use crate::backend::{aws_lc::AwsLc, rustcrypto::RustCrypto};

    #[test]
    fn rustcrypto_encapsulates_to_an_aws_lc_key_and_aws_lc_opens_it() {
        use aws_lc_rs::kem::{Ciphertext, DecapsulationKey, ML_KEM_1024};
        let key = DecapsulationKey::generate(&ML_KEM_1024).expect("generate");
        let public = key
            .encapsulation_key()
            .expect("public")
            .key_bytes()
            .expect("bytes");
        let (ciphertext, sent) = RustCrypto::mlkem1024_encaps(public.as_ref()).expect("encaps");
        let got = key
            .decapsulate(Ciphertext::from(ciphertext.as_slice()))
            .expect("decaps");
        assert_eq!(got.as_ref(), &sent);
    }

    #[test]
    fn aws_lc_encapsulates_to_a_seed_key_and_both_backends_open_it() {
        let seed = [4u8; MLKEM_SEED_LEN];
        let public = RustCrypto::mlkem1024_public(&seed).expect("public");
        let (ciphertext, sent) = AwsLc::mlkem1024_encaps(&public).expect("encaps");
        assert_eq!(
            RustCrypto::mlkem1024_decaps(&seed, &ciphertext).expect("decaps"),
            sent
        );
        assert_eq!(
            AwsLc::mlkem1024_decaps(&seed, &ciphertext).expect("decaps"),
            sent
        );
    }

    #[test]
    fn aws_lc_expands_a_seed_to_the_same_key_as_rustcrypto() {
        // aws-lc-rs has no seed expansion; the aws-lc backend routes the step to RustCrypto and
        // must give exactly what the RustCrypto backend gives, not an error.
        let seed = [4u8; MLKEM_SEED_LEN];
        assert_eq!(
            AwsLc::mlkem1024_public(&seed).expect("aws-lc"),
            RustCrypto::mlkem1024_public(&seed).expect("rustcrypto")
        );
        let (ciphertext, _) =
            AwsLc::mlkem1024_encaps(&AwsLc::mlkem1024_public(&seed).expect("pk")).expect("encaps");
        assert_eq!(
            AwsLc::mlkem1024_decaps(&seed, &ciphertext).expect("aws-lc"),
            RustCrypto::mlkem1024_decaps(&seed, &ciphertext).expect("rustcrypto")
        );
        assert!(AwsLc::mlkem1024_decaps(&seed, &ciphertext[1..]).is_err());
    }

    #[test]
    fn mldsa_signatures_verify_across_backends_and_public_keys_agree() {
        let seed = [5u8; MLDSA_SEED_LEN];
        let aws_public = AwsLc::mldsa65_public(&seed).expect("public");
        assert_eq!(
            aws_public,
            RustCrypto::mldsa65_public(&seed).expect("public")
        );
        let by_aws = AwsLc::mldsa65_sign(&seed, b"m").expect("sign");
        let by_rc = RustCrypto::mldsa65_sign(&seed, b"m").expect("sign");
        RustCrypto::mldsa65_verify(&aws_public, b"m", &by_aws).expect("rustcrypto verifies aws-lc");
        AwsLc::mldsa65_verify(&aws_public, b"m", &by_rc).expect("aws-lc verifies rustcrypto");
    }

    #[test]
    fn x25519_and_hashes_agree() {
        let secret = [0x5au8; 32];
        let peer = RustCrypto::x25519_public(&[0x6bu8; 32]).expect("public");
        assert_eq!(
            AwsLc::x25519_public(&secret),
            RustCrypto::x25519_public(&secret)
        );
        assert_eq!(
            AwsLc::x25519(&secret, &peer),
            RustCrypto::x25519(&secret, &peer)
        );
        assert_eq!(AwsLc::sha3_256(b"x"), RustCrypto::sha3_256(b"x"));
        assert_eq!(AwsLc::sha512(b"x"), RustCrypto::sha512(b"x"));
    }

    #[test]
    fn aead_outputs_open_across_backends() {
        let key = [1u8; 32];
        let nonce = [2u8; 12];
        let a = AwsLc::aes256gcm_seal(&key, &nonce, b"aad", b"data").expect("seal");
        let b = RustCrypto::aes256gcm_seal(&key, &nonce, b"aad", b"data").expect("seal");
        assert_eq!(a, b, "same key, nonce and input give the same bytes");
        assert_eq!(
            RustCrypto::aes256gcm_open(&key, &nonce, b"aad", &a).expect("open"),
            b"data"
        );
        assert_eq!(
            AwsLc::aes256gcm_open(&key, &nonce, b"aad", &b).expect("open"),
            b"data"
        );
    }
}
