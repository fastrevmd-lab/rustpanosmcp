#![no_main]

use libfuzzer_sys::fuzz_target;
use rust_panosmcp_core::xml::validate_config_element;

fuzz_target!(|data: &[u8]| {
    if let Ok(value) = std::str::from_utf8(data) {
        let _result = validate_config_element(value);
    }
});
