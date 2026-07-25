#![no_main]

use libfuzzer_sys::fuzz_target;
use rust_panosmcp_auth::{TokenDigest, parse_bearer_header};

fuzz_target!(|data: &[u8]| {
    if let Ok(value) = std::str::from_utf8(data) {
        let _result = parse_bearer_header(value);
        // Digest-string validation moved into the `Deserialize` impl upstream,
        // so that is now the entry point that parses untrusted digest text.
        let _digest = serde_json::from_str::<TokenDigest>(value);
    }
});
