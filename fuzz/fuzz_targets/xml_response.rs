#![no_main]

use libfuzzer_sys::fuzz_target;
use rust_panosmcp_core::xml::{XmlLimits, validate_panos_response};

fuzz_target!(|data: &[u8]| {
    let _result = validate_panos_response(
        data,
        XmlLimits {
            max_bytes: 64 * 1024,
            max_depth: 32,
        },
    );
});
