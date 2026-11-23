//! The `data` column of a Vaultwarden two-step row: WebAuthn and U2F registrations (the input is
//! both, split at the first newline), and the email, YubiKey and Duo setups.

#![no_main]

use kemlock_vaultwarden::two_step::{duo_data, email_data, security_keys, yubikey_data};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let Ok(text) = std::str::from_utf8(data) else {
        return;
    };
    let (webauthn, u2f) = text.split_once('\n').unwrap_or((text, ""));
    let keys = security_keys(Some(webauthn), Some(u2f));
    assert!(keys.len() <= 5, "an account has at most five security keys");
    let _ = security_keys(Some(text), None);
    let _ = security_keys(None, Some(text));
    let _ = email_data(text);
    let _ = yubikey_data(text);
    let _ = duo_data(text);
});
