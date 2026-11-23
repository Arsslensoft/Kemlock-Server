//! The hello and reply bodies and the signed envelope around them.

#![no_main]

use kemlock_federation::handshake::{Hello, Reply};
use kemlock_federation::signed::Signed;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(hello) = Hello::from_body(data) {
        assert_eq!(
            hello.to_body(),
            data,
            "a parsed hello re-encodes to its input"
        );
    }
    if let Ok(reply) = Reply::from_body(data) {
        assert_eq!(
            reply.to_body(),
            data,
            "a parsed reply re-encodes to its input"
        );
    }
    if let Ok(signed) = Signed::decode(data) {
        assert_eq!(signed.encode(), data);
    }
});
