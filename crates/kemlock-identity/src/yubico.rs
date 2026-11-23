//! Yubico's OTP validation service, behind `kemlock_app::two_step::Yubico`.
//!
//! A YubiKey OTP is checked with Yubico's validation protocol 2.0, as Vaultwarden does through
//! `yubico_ng`: a signed `GET` to the validation server (`YUBICO_SERVER`, by default
//! `https://api.yubico.com/wsapi/2.0/verify`) with the client id (`YUBICO_CLIENT_ID`), the OTP and a
//! fresh nonce, and the HMAC-SHA1 of the query under the API key (`YUBICO_SECRET_KEY`, Base64 as
//! Yubico issues it). The answer is accepted only when it says `OK`, carries a signature that checks
//! under the same key, and repeats the OTP and the nonce.

use aws_lc_rs::hmac;
use kemlock_app::notices::BoxFuture;
use kemlock_app::two_step::{Yubico, YubicoError};
use kemlock_crypto::rand;
use std::collections::BTreeMap;
use std::time::Duration;

/// The validation server Vaultwarden uses unless `YUBICO_SERVER` says another.
pub const DEFAULT_SERVER: &str = "https://api.yubico.com/wsapi/2.0/verify";

/// The API key's length once decoded.
const KEY_LEN: usize = 20;

/// Yubico's validation service, as a client.
#[derive(Clone)]
pub struct YubicoClient {
    http: reqwest13::Client,
    client_id: String,
    key: Vec<u8>,
    server: String,
}

impl std::fmt::Debug for YubicoClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("YubicoClient")
            .field("server", &self.server)
            .finish_non_exhaustive()
    }
}

/// A server address that may carry the API key's signature: https, or plain http to this machine
/// (a validation server on the same host, and the tests).
fn allowed_server(url: &str) -> bool {
    url.starts_with("https://")
        || url.starts_with("http://127.0.0.1")
        || url.starts_with("http://localhost")
        || url.starts_with("http://[::1]")
}

impl YubicoClient {
    /// A client for the account `client_id` with the Base64 API key `secret_key`, asking `server`
    /// (the full address of its verify endpoint) or Yubico's. Says why when they can't be used.
    pub fn new(client_id: &str, secret_key: &str, server: Option<&str>) -> Result<Self, String> {
        let client_id = client_id.trim();
        if client_id.is_empty() {
            return Err("YUBICO_CLIENT_ID is empty".to_owned());
        }
        let key = base64_decode(secret_key.trim())
            .filter(|k| k.len() == KEY_LEN)
            .ok_or_else(|| "YUBICO_SECRET_KEY isn't a Base64 API key of 20 bytes".to_owned())?;
        let server = server
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .unwrap_or(DEFAULT_SERVER)
            .to_owned();
        if !allowed_server(&server) {
            return Err("YUBICO_SERVER must be an https address".to_owned());
        }
        let http = reqwest13::Client::builder()
            .timeout(Duration::from_secs(30))
            .user_agent(concat!("kemlock-server/", env!("CARGO_PKG_VERSION")))
            // A redirect would carry the signed request somewhere the operator never chose.
            .redirect(reqwest13::redirect::Policy::none())
            .build()
            .map_err(|e| e.to_string())?;
        Ok(YubicoClient {
            http,
            client_id: client_id.to_owned(),
            key,
            server,
        })
    }

    /// The query of a request for `otp` with `nonce`, signed.
    fn query(&self, otp: &str, nonce: &str) -> String {
        // The parameters are in alphabetical order, as the protocol demands.
        let query = url::form_urlencoded::Serializer::new(String::new())
            .append_pair("id", &self.client_id)
            .append_pair("nonce", nonce)
            .append_pair("otp", otp)
            .append_pair("sl", "100")
            .finish();
        let signature = base64_encode(&hmac_sha1(&self.key, query.as_bytes()));
        url::form_urlencoded::Serializer::new(query)
            .append_pair("h", &signature)
            .finish()
    }

    async fn check(&self, otp: &str) -> Result<(), YubicoError> {
        let otp = otp.trim();
        if !(32..=48).contains(&otp.len()) || !otp.bytes().all(|b| b.is_ascii_graphic()) {
            return Err(YubicoError::Rejected);
        }
        let nonce = nonce();
        let url = format!("{}?{}", self.server, self.query(otp, &nonce));
        let response = self
            .http
            .get(url)
            .send()
            .await
            .map_err(|e| YubicoError::Unavailable(e.to_string()))?;
        let status = response.status();
        if !status.is_success() {
            return Err(YubicoError::Unavailable(format!(
                "the validation server answered {status}"
            )));
        }
        let body = response
            .text()
            .await
            .map_err(|e| YubicoError::Unavailable(e.to_string()))?;
        accept(&self.key, &body, otp, &nonce)
    }
}

impl Yubico for YubicoClient {
    fn verify<'a>(&'a self, otp: &'a str) -> BoxFuture<'a, Result<(), YubicoError>> {
        Box::pin(self.check(otp))
    }
}

/// Whether the server's answer is a signed `OK` for this OTP and nonce.
fn accept(key: &[u8], body: &str, otp: &str, nonce: &str) -> Result<(), YubicoError> {
    let mut fields: BTreeMap<&str, &str> = BTreeMap::new();
    for line in body.lines() {
        if let Some((name, value)) = line.split_once('=') {
            fields.insert(name, value);
        }
    }
    // The status comes first: the errors that come with no signature are still errors.
    if fields.get("status") != Some(&"OK") {
        return Err(YubicoError::Rejected);
    }
    let signature = fields
        .get("h")
        .and_then(|h| base64_decode(h))
        .ok_or(YubicoError::Rejected)?;
    let signed: Vec<String> = fields
        .iter()
        .filter(|(name, _)| **name != "h")
        .map(|(name, value)| format!("{name}={value}"))
        .collect();
    let key = hmac::Key::new(hmac::HMAC_SHA1_FOR_LEGACY_USE_ONLY, key);
    hmac::verify(&key, signed.join("&").as_bytes(), &signature)
        .map_err(|_| YubicoError::Rejected)?;
    if fields.get("otp") != Some(&otp) || fields.get("nonce") != Some(&nonce) {
        return Err(YubicoError::Rejected);
    }
    Ok(())
}

/// HMAC-SHA1, which the validation protocol signs with.
fn hmac_sha1(key: &[u8], data: &[u8]) -> Vec<u8> {
    let key = hmac::Key::new(hmac::HMAC_SHA1_FOR_LEGACY_USE_ONLY, key);
    hmac::sign(&key, data).as_ref().to_vec()
}

/// A random nonce of 40 letters and digits.
fn nonce() -> String {
    const CHARSET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
    let mut out = String::with_capacity(40);
    while out.len() < 40 {
        let mut buf = [0u8; 40];
        rand::fill(&mut buf);
        for byte in buf {
            // 248 is the largest multiple of 62 a byte reaches: no modulo bias.
            if out.len() < 40 && byte < 248 {
                out.push(char::from(CHARSET[usize::from(byte) % CHARSET.len()]));
            }
        }
    }
    out
}

const STANDARD: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/// Standard Base64, padded.
fn base64_encode(data: &[u8]) -> String {
    let mut out = String::with_capacity(data.len().div_ceil(3) * 4);
    for chunk in data.chunks(3) {
        let b0 = u32::from(chunk[0]);
        let b1 = u32::from(chunk.get(1).copied().unwrap_or(0));
        let b2 = u32::from(chunk.get(2).copied().unwrap_or(0));
        let n = (b0 << 16) | (b1 << 8) | b2;
        for i in 0..4 {
            if i <= chunk.len() {
                out.push(char::from(STANDARD[((n >> (18 - 6 * i)) & 63) as usize]));
            } else {
                out.push('=');
            }
        }
    }
    out
}

/// Standard Base64, padded or not; `None` for anything else.
fn base64_decode(text: &str) -> Option<Vec<u8>> {
    let mut out = Vec::with_capacity(text.len() / 4 * 3 + 3);
    let mut buffer: u32 = 0;
    let mut bits: u32 = 0;
    for c in text.bytes() {
        let value = match c {
            b'A'..=b'Z' => c - b'A',
            b'a'..=b'z' => c - b'a' + 26,
            b'0'..=b'9' => c - b'0' + 52,
            b'+' => 62,
            b'/' => 63,
            b'=' => continue,
            _ => return None,
        };
        buffer = (buffer << 6) | u32::from(value);
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push(((buffer >> bits) & 0xFF) as u8);
            buffer &= (1 << bits) - 1;
        }
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }

    /// An API key as Yubico issues one: 20 bytes in Base64.
    fn key_text() -> String {
        base64_encode(&[0x42; 20])
    }

    #[test]
    fn hmac_sha1_matches_rfc_2202() {
        assert_eq!(
            hex(&hmac_sha1(b"Jefe", b"what do ya want for nothing?")),
            "effcdf6ae5eb2fa2d27416d5f184df9c259a7c79"
        );
    }

    #[test]
    fn base64_round_trips_and_reads_unpadded() {
        for data in [&b""[..], b"f", b"fo", b"foo", b"foob", b"fooba", b"foobar"] {
            assert_eq!(base64_decode(&base64_encode(data)), Some(data.to_vec()));
        }
        assert_eq!(base64_encode(b"fooba"), "Zm9vYmE=");
        assert_eq!(base64_decode("Zm9vYmE"), Some(b"fooba".to_vec()));
        assert_eq!(base64_decode("not base64!"), None);
    }

    #[test]
    fn a_request_is_signed_in_alphabetical_order() {
        let client = YubicoClient::new("12345", &key_text(), None).expect("a client");
        let query = client.query(
            "cccccccccccckhvfhkbjtkjlkhdfhjcehcbvlnbtjhgv",
            "NONCE123456789012",
        );
        let (signed, signature) = query.rsplit_once("&h=").expect("a signature");
        assert_eq!(
            signed,
            "id=12345&nonce=NONCE123456789012&otp=cccccccccccckhvfhkbjtkjlkhdfhjcehcbvlnbtjhgv&sl=100"
        );
        let signature = signature
            .replace("%3D", "=")
            .replace("%2B", "+")
            .replace("%2F", "/");
        assert_eq!(
            base64_decode(&signature),
            Some(hmac_sha1(&[0x42; 20], signed.as_bytes()))
        );
    }

    /// What a validation server answers, signed under `key`.
    fn answer(key: &[u8], status: &str, otp: &str, nonce: &str) -> String {
        let mut fields = BTreeMap::new();
        fields.insert("nonce", nonce.to_owned());
        fields.insert("otp", otp.to_owned());
        fields.insert("sl", "100".to_owned());
        fields.insert("status", status.to_owned());
        fields.insert("t", "2026-11-22T10:00:00Z0123".to_owned());
        let signed: Vec<String> = fields.iter().map(|(k, v)| format!("{k}={v}")).collect();
        let signature = base64_encode(&hmac_sha1(key, signed.join("&").as_bytes()));
        format!("h={signature}\r\n{}\r\n", signed.join("\r\n"))
    }

    #[test]
    fn an_answer_is_accepted_only_when_it_is_a_signed_ok_for_this_otp_and_nonce() {
        let key = [0x42u8; 20];
        let otp = "cccccccccccckhvfhkbjtkjlkhdfhjcehcbvlnbtjhgv";
        let good = answer(&key, "OK", otp, "N1");
        assert_eq!(accept(&key, &good, otp, "N1"), Ok(()));
        // Another nonce or OTP: a replayed answer.
        assert_eq!(accept(&key, &good, otp, "N2"), Err(YubicoError::Rejected));
        assert_eq!(
            accept(&key, &good, "other", "N1"),
            Err(YubicoError::Rejected)
        );
        // A status that isn't OK, even a signed one.
        let replayed = answer(&key, "REPLAYED_OTP", otp, "N1");
        assert_eq!(
            accept(&key, &replayed, otp, "N1"),
            Err(YubicoError::Rejected)
        );
        // Signed with another key, altered after signing, or not signed.
        assert_eq!(
            accept(&[0x43u8; 20], &good, otp, "N1"),
            Err(YubicoError::Rejected)
        );
        let altered = good.replace("sl=100", "sl=0");
        assert_eq!(
            accept(&key, &altered, otp, "N1"),
            Err(YubicoError::Rejected)
        );
        let unsigned: String = good.lines().skip(1).map(|l| format!("{l}\r\n")).collect();
        assert_eq!(
            accept(&key, &unsigned, otp, "N1"),
            Err(YubicoError::Rejected)
        );
        assert_eq!(accept(&key, "", otp, "N1"), Err(YubicoError::Rejected));
    }

    #[test]
    fn a_client_needs_an_id_a_key_of_twenty_bytes_and_a_safe_server() {
        assert!(YubicoClient::new("", &key_text(), None).is_err());
        assert!(YubicoClient::new("1", "not base64!", None).is_err());
        assert!(YubicoClient::new("1", &base64_encode(&[1; 19]), None).is_err());
        assert!(YubicoClient::new("1", &key_text(), Some("http://yubico.example")).is_err());
        assert!(YubicoClient::new("1", &key_text(), Some("https://yubi.example/verify")).is_ok());
        assert!(YubicoClient::new("1", &key_text(), Some("http://127.0.0.1:9/verify")).is_ok());
    }

    #[test]
    fn nonces_are_forty_letters_and_digits() {
        let a = nonce();
        assert_eq!(a.len(), 40);
        assert!(a.bytes().all(|b| b.is_ascii_alphanumeric()));
        assert_ne!(a, nonce());
    }
}
