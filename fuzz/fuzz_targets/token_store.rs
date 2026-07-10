#![no_main]

use libfuzzer_sys::fuzz_target;
use rust_panosmcp_auth::TokenStoreFile;

fuzz_target!(|data: &[u8]| {
    let known_devices = ["fw".to_owned()];
    let _result = TokenStoreFile::parse(data, &known_devices);
});
