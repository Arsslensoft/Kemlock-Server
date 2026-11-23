//! Replication requests and responses: what parses re-encodes to its input.

#![no_main]

use kemlock_federation::message::{Request, Response};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(request) = Request::decode(data) {
        assert_eq!(request.encode(), data, "a request re-encodes to its input");
    }
    if let Ok(response) = Response::decode(data) {
        assert_eq!(
            response.encode(),
            data,
            "a response re-encodes to its input"
        );
    }
});
