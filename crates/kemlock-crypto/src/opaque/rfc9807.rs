const OPRF_SEED: &str = "f433d0227b0b9dd54f7c4422b600e764e47fb503f1f9a0f0a47c6606b054a7fdc65347f1a08f277e22358bbabe26f823fca82c7848e9a75661f4ec5d5c1989ef";
const CREDENTIAL_IDENTIFIER: &str = "31323334";
const PASSWORD: &str = "436f7272656374486f72736542617474657279537461706c65";
const ENVELOPE_NONCE: &str = "ac13171b2f17bc2c74997f0fce1e1f35bec6b91fe2e12dbd323d23ba7a38dfec";
const MASKING_NONCE: &str = "38fe59af0df2c79f57b8780278f5ae47355fe1f817119041951c80f612fdfc6d";
const SERVER_PRIVATE_KEY: &str = "47451a85372f8b3537e249d7b54188091fb18edde78094b43e2ba42b5eb89f0d";
const SERVER_PUBLIC_KEY: &str = "b2fe7af9f48cc502d016729d2fe25cdd433f2c4bc904660b2a382c9b79df1a78";
const SERVER_NONCE: &str = "71cd9960ecef2fe0d0f7494986fa3d8b2bb01963537e60efb13981e138e3d4a1";
const CLIENT_NONCE: &str = "da7e07376d6d6f034cfa9bb537d11b8c6b4238c334333d1f0aebb380cae6a6cc";
const CLIENT_KEYSHARE_SEED: &str =
    "82850a697b42a505f5b68fcdafce8c31f0af2b581f063cf1091933541936304b";
const SERVER_KEYSHARE_SEED: &str =
    "05a4f54206eef1ba2f615bc0aa285cb22f26d1153b5b40a1e85ff80da12f982f";
const BLIND_REGISTRATION: &str = "76cfbfe758db884bebb33582331ba9f159720ca8784a2a070a265d9c2d6abe01";
const BLIND_LOGIN: &str = "6ecc102d2e7a7cf49617aad7bbe188556792d4acd60a1a8a8d2b65d4b0790308";
const REGISTRATION_REQUEST: &str =
    "5059ff249eb1551b7ce4991f3336205bde44a105a032e747d21bf382e75f7a71";
const REGISTRATION_RESPONSE: &str = "7408a268083e03abc7097fc05b587834539065e86fb0c7b6342fcf5e01e5b019b2fe7af9f48cc502d016729d2fe25cdd433f2c4bc904660b2a382c9b79df1a78";
const REGISTRATION_UPLOAD: &str = "76a845464c68a5d2f7e442436bb1424953b17d3e2e289ccbaccafb57ac5c36751ac5844383c7708077dea41cbefe2fa15724f449e535dd7dd562e66f5ecfb95864eadddec9db5874959905117dad40a4524111849799281fefe3c51fa82785c5ac13171b2f17bc2c74997f0fce1e1f35bec6b91fe2e12dbd323d23ba7a38dfec634b0f5b96109c198a8027da51854c35bee90d1e1c781806d07d49b76de6a28b8d9e9b6c93b9f8b64d16dddd9c5bfb5fea48ee8fd2f75012a8b308605cdd8ba5";
const KE1: &str = "c4dedb0ba6ed5d965d6f250fbe554cd45cba5dfcce3ce836e4aee778aa3cd44dda7e07376d6d6f034cfa9bb537d11b8c6b4238c334333d1f0aebb380cae6a6cc6e29bee50701498605b2c085d7b241ca15ba5c32027dd21ba420b94ce60da326";
const KE2: &str = "7e308140890bcde30cbcea28b01ea1ecfbd077cff62c4def8efa075aabcbb47138fe59af0df2c79f57b8780278f5ae47355fe1f817119041951c80f612fdfc6dd6ec60bcdb26dc455ddf3e718f1020490c192d70dfc7e403981179d8073d1146a4f9aa1ced4e4cd984c657eb3b54ced3848326f70331953d91b02535af44d9fedc80188ca46743c52786e0382f95ad85c08f6afcd1ccfbff95e2bdeb015b166c6b20b92f832cc6df01e0b86a7efd92c1c804ff865781fa93f2f20b446c8371b671cd9960ecef2fe0d0f7494986fa3d8b2bb01963537e60efb13981e138e3d4a1c4f62198a9d6fa9170c42c3c71f1971b29eb1d5d0bd733e40816c91f7912cc4a660c48dae03e57aaa38f3d0cffcfc21852ebc8b405d15bd6744945ba1a93438a162b6111699d98a16bb55b7bdddfe0fc5608b23da246e7bd73b47369169c5c90";
const KE3: &str = "4455df4f810ac31a6748835888564b536e6da5d9944dfea9e34defb9575fe5e2661ef61d2ae3929bcf57e53d464113d364365eb7d1a57b629707ca48da18e442";
const EXPORT_KEY: &str = "1ef15b4fa99e8a852412450ab78713aad30d21fa6966c9b8c9fb3262a970dc62950d4dd4ed62598229b1b72794fc0335199d9f7fcc6eaedde92cc04870e63f16";
const SESSION_KEY: &str = "42afde6f5aca0cfa5c163763fbad55e73a41db6b41bc87b8e7b62214a8eedc6731fa3cb857d657ab9b3764b89a84e91ebcb4785166fbb02cedfcbdfda215b96f";

// RFC 9807 appendix C.1.1, "OPAQUE-3DH Real Test Vector 1": ristretto255-SHA512, Identity KSF,
// HKDF-SHA512, HMAC-SHA512, the RFC's own context string `OPAQUE-POC` and no identities.
//
// The RFC lists the random inputs; a scripted random source hands them to `opaque-ke` in the order
// it draws them, and each draw's length is checked so a mismatch fails loudly.

use std::collections::VecDeque;

use rand_core_06::{CryptoRng, RngCore};

use super::*;

const CONTEXT: &[u8] = b"OPAQUE-POC";

struct ScriptedRng {
    chunks: VecDeque<Vec<u8>>,
}

impl ScriptedRng {
    fn new(chunks: Vec<Vec<u8>>) -> ScriptedRng {
        ScriptedRng {
            chunks: chunks.into(),
        }
    }
}

impl RngCore for ScriptedRng {
    fn next_u32(&mut self) -> u32 {
        panic!("opaque-ke drew a u32");
    }

    fn next_u64(&mut self) -> u64 {
        panic!("opaque-ke drew a u64");
    }

    fn fill_bytes(&mut self, dest: &mut [u8]) {
        let chunk = self
            .chunks
            .pop_front()
            .expect("opaque-ke drew more random bytes than the script holds");
        assert_eq!(chunk.len(), dest.len(), "a draw of an unexpected length");
        dest.copy_from_slice(&chunk);
    }

    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand_core_06::Error> {
        self.fill_bytes(dest);
        Ok(())
    }
}

impl CryptoRng for ScriptedRng {}

fn h(s: &str) -> Vec<u8> {
    hex::decode(s).expect("hex")
}

/// A 32-byte little-endian scalar as ristretto255's `Scalar::random` reads it: 64 bytes, reduced.
fn scalar_draw(s: &str) -> Vec<u8> {
    let mut bytes = h(s);
    bytes.extend_from_slice(&[0u8; 32]);
    bytes
}

#[test]
fn appendix_c_1_1_real_test_vector_1() {
    // The server setup: oprf_seed, server_private_key and (as the unused dummy key) the public key.
    let mut setup = h(OPRF_SEED);
    setup.extend_from_slice(&h(SERVER_PRIVATE_KEY));
    setup.extend_from_slice(&h(SERVER_PUBLIC_KEY));
    let server = OpaqueServer::from_bytes(&setup).expect("setup");
    let id = h(CREDENTIAL_IDENTIFIER);
    let password = h(PASSWORD);

    // Registration.
    let mut rng = ScriptedRng::new(vec![scalar_draw(BLIND_REGISTRATION)]);
    let (state, request) = client_registration_start_with(&mut rng, &password).expect("start");
    assert_eq!(hex::encode(&request), REGISTRATION_REQUEST);

    let response = server
        .registration_response(&id, &request)
        .expect("response");
    assert_eq!(hex::encode(&response), REGISTRATION_RESPONSE);

    let mut rng = ScriptedRng::new(vec![h(ENVELOPE_NONCE)]);
    let (upload, registration_export) =
        client_registration_finish_with(&mut rng, state, &password, &response).expect("finish");
    assert_eq!(hex::encode(&upload), REGISTRATION_UPLOAD);
    let record = OpaqueServer::registration_record(&upload).expect("record");

    // Login: KE1, KE2, KE3, then the keys.
    let mut rng = ScriptedRng::new(vec![
        scalar_draw(BLIND_LOGIN),
        h(CLIENT_KEYSHARE_SEED),
        h(CLIENT_NONCE),
    ]);
    let (client, ke1) = client_login_start_with(&mut rng, &password).expect("start");
    assert_eq!(hex::encode(&ke1), KE1);

    // opaque-ke makes a dummy record first (64 bytes), then the masking nonce, the server's
    // key-share seed and the server nonce.
    let mut rng = ScriptedRng::new(vec![
        vec![0u8; 64],
        h(MASKING_NONCE),
        h(SERVER_KEYSHARE_SEED),
        h(SERVER_NONCE),
    ]);
    let (state, ke2) = server
        .login_start_with(&mut rng, CONTEXT, &id, Some(&record), &ke1)
        .expect("server start");
    assert_eq!(hex::encode(&ke2), KE2);

    let mut rng = ScriptedRng::new(vec![]);
    let (ke3, client_session, login_export) =
        client_login_finish_with(&mut rng, CONTEXT, client, &password, &ke2)
            .expect("client finish");
    assert_eq!(hex::encode(&ke3), KE3);
    assert_eq!(hex::encode(client_session), SESSION_KEY);
    assert_eq!(hex::encode(login_export), EXPORT_KEY);
    assert_eq!(hex::encode(registration_export), EXPORT_KEY);

    let server_session =
        OpaqueServer::login_finish_with(CONTEXT, &state, &ke3).expect("server finish");
    assert_eq!(hex::encode(server_session), SESSION_KEY);

    // Under this crate's context the same inputs don't verify.
    let mut rng = ScriptedRng::new(vec![]);
    let (client_again, _) = client_login_start_with(
        &mut ScriptedRng::new(vec![
            scalar_draw(BLIND_LOGIN),
            h(CLIENT_KEYSHARE_SEED),
            h(CLIENT_NONCE),
        ]),
        &password,
    )
    .expect("start");
    assert!(
        client_login_finish_with(&mut rng, super::CONTEXT, client_again, &password, &ke2).is_err()
    );
}
