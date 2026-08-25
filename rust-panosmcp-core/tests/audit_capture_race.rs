//! Regression test for audit capture race condition (thread-local subscriber vs global callsite cache).
//!
//! IMPORTANT: This test file MUST contain only one test. Two such tests in one process is not
//! a valid reproduction, because whichever runs first registers the callsite under a capture
//! subscriber and immunises the second. The bug this tests is: `tracing` caches each callsite's
//! `Interest` per-process, while `tracing::subscriber::set_default` is thread-local. A thread
//! with no subscriber reaching a callsite can get `Interest::never` cached for it, after which
//! the capturing thread silently skips that callsite and returns EMPTY output.
//!
//! This test FAILS without the thread-local routing fix and PASSES with it.

mod common;

use mecmcp_audit::{AuditScope, testutil::CapturingWriter};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

fn emit(tool: &'static str) {
    let mut s = AuditScope::stdio(tool, "read", Vec::new());
    s.succeed();
}

#[test]
fn capture_survives_a_noisy_thread() {
    let stop = Arc::new(AtomicBool::new(false));
    let stop2 = Arc::clone(&stop);
    let noisy = std::thread::spawn(move || {
        while !stop2.load(Ordering::Relaxed) {
            emit("noise");
        }
    });

    // Install capture via the thread-local routing helper
    let cap = CapturingWriter::default();
    let _guard = common::install_audit_capture(cap.clone());

    // Emit events under capture while the noisy thread hammers the same callsite
    for _ in 0..50 {
        emit("under_capture");
        std::thread::yield_now();
    }

    // Stop the noisy thread
    stop.store(true, Ordering::Relaxed);
    noisy.join().expect("noisy thread panicked");

    // Assert the captured text contains our tool name
    let bytes = cap.0.lock().expect("lock audit capture").clone();
    let captured = String::from_utf8_lossy(&bytes);
    assert!(
        captured.contains("tool=under_capture"),
        "capture lost its own events: {:?}",
        captured
    );
}
