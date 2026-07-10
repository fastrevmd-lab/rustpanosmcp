#![no_main]

use libfuzzer_sys::fuzz_target;
use rust_panosmcp_core::xml::{validate_read_xpath, validate_write_xpath};

fuzz_target!(|data: &[u8]| {
    if let Ok(value) = std::str::from_utf8(data) {
        let _read = validate_read_xpath(value);
        let roots = ["/config/shared/address".to_owned()];
        let _write = validate_write_xpath(value, &roots);
    }
});
