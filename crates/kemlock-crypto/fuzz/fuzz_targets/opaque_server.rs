//! The server side of OPAQUE: every message a client sends (registration requests and uploads,
//! credential requests and finalizations) and the setup the server loads. The first byte picks
//! the message, the rest is its bytes. None may panic, and a made-up finalization never opens a
//! session.

#![no_main]

use kemlock_crypto::opaque::{self, OpaqueServer};
use libfuzzer_sys::fuzz_target;
use std::sync::OnceLock;

const PASSWORD: &[u8] = &[7; 32];

/// A server and one registered account, made once.
struct Fixture {
    server: OpaqueServer,
    credential: Vec<u8>,
    record: Vec<u8>,
}

fn fixture() -> &'static Fixture {
    static FIXTURE: OnceLock<Fixture> = OnceLock::new();
    FIXTURE.get_or_init(|| {
        let server = OpaqueServer::generate();
        let credential = opaque::credential_id("fuzz@example.org");
        let (state, request) =
            opaque::client_registration_start(PASSWORD).expect("a client starts");
        let response = server
            .registration_response(&credential, &request)
            .expect("the server answers a real request");
        let (upload, _export) = opaque::client_registration_finish(state, PASSWORD, &response)
            .expect("the client finishes");
        let record = OpaqueServer::registration_record(&upload).expect("a real upload");
        Fixture {
            server,
            credential,
            record,
        }
    })
}

fuzz_target!(|data: &[u8]| {
    let Some((&op, rest)) = data.split_first() else {
        return;
    };
    let f = fixture();
    match op % 7 {
        0 => {
            if let Ok(server) = OpaqueServer::from_bytes(rest) {
                assert_eq!(server.to_bytes(), rest, "a setup is kept as it was read");
            }
        }
        1 => {
            let _ = f.server.registration_response(&f.credential, rest);
        }
        2 => {
            let _ = OpaqueServer::registration_record(rest);
        }
        3 => {
            // A request for the account that exists, and for one that doesn't: the answers have
            // the same length, so a client can't tell them apart.
            let real = f.server.login_start(&f.credential, Some(&f.record), rest);
            let fake = f.server.login_start(&f.credential, None, rest);
            if let (Ok(real), Ok(fake)) = (real, fake) {
                assert_eq!(real.1.len(), fake.1.len());
            }
        }
        4 => {
            // A stored record that isn't one, with a real request.
            let (_state, request) = opaque::client_login_start(PASSWORD).expect("a client starts");
            let _ = f.server.login_start(&f.credential, Some(rest), &request);
        }
        5 => {
            // A state that isn't one, and a finalization that isn't one.
            let cut = rest.len() / 2;
            let _ = OpaqueServer::login_finish(&rest[..cut], &rest[cut..]);
        }
        _ => {
            let (_state, request) = opaque::client_login_start(PASSWORD).expect("a client starts");
            let (state, _response) = f
                .server
                .login_start(&f.credential, Some(&f.record), &request)
                .expect("the server answers a real request");
            assert!(
                OpaqueServer::login_finish(&state, rest).is_err(),
                "a made-up finalization must not open a session"
            );
        }
    }
});
