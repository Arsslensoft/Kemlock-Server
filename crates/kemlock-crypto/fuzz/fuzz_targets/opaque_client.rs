//! The client side of OPAQUE, which the web vault and the apps run: the server's registration
//! response and credential response, as bytes from a server that may be hostile. A made-up
//! credential response never opens a session.

#![no_main]

use kemlock_crypto::opaque;
use libfuzzer_sys::fuzz_target;

const PASSWORD: &[u8] = &[7; 32];

fuzz_target!(|data: &[u8]| {
    let Some((&op, rest)) = data.split_first() else {
        return;
    };
    if op % 2 == 0 {
        let (state, _request) = opaque::client_registration_start(PASSWORD).expect("starts");
        let _ = opaque::client_registration_finish(state, PASSWORD, rest);
    } else {
        let (state, _request) = opaque::client_login_start(PASSWORD).expect("starts");
        assert!(
            opaque::client_login_finish(state, PASSWORD, rest).is_err(),
            "a made-up credential response must not open a session"
        );
    }
});
