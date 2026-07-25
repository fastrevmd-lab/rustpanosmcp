#![no_main]

use libfuzzer_sys::fuzz_target;
use rust_panosmcp_auth::{TokenEntry, TokenStore};

fuzz_target!(|data: &[u8]| {
    // mecmcp-auth keeps its byte-to-store path private behind `TokenStoreFile`,
    // which only reads from a path. Drive the same two steps it performs:
    // deserialize the entries, then run store-level validation.
    if let Ok(entries) = serde_json::from_slice::<Vec<TokenEntry>>(data) {
        let _result = TokenStore::try_new(entries);
    }
});
