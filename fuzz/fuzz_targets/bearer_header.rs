#![no_main]

use libfuzzer_sys::fuzz_target;
use rust_panosmcp_auth::{TokenDigest, parse_bearer_header};

fuzz_target!(|data: &[u8]| {
    if let Ok(value) = std::str::from_utf8(data) {
        let _result = parse_bearer_header(value);
        let _digest = TokenDigest::parse(value.to_owned());
    }
});
