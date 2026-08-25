//! Shared test infrastructure for audit capture with thread-local routing.
//!
//! This module provides the `install_audit_capture` helper, which solves a race condition
//! in audit event capture. The problem: `tracing` caches callsite `Interest` per-process,
//! while `tracing::subscriber::set_default` is thread-local. A thread without a subscriber
//! can get `Interest::never` cached for a callsite, after which the capturing thread
//! silently skips that callsite and returns EMPTY output.
//!
//! The solution (ported from rustmistmcp): install a **global** subscriber once, with
//! a `MakeWriter` that routes to a **thread-local** `CapturingWriter`. Each test thread
//! activates capture by setting its thread-local, then clears it via an RAII guard.
//! Non-capturing threads route to `std::io::sink()`, so the global subscriber stays
//! always-enabled without cross-contaminating captures.

use mecmcp_audit::testutil::CapturingWriter;
use std::{cell::RefCell, io::Write, sync::OnceLock};

thread_local! {
    static ACTIVE_AUDIT_CAPTURE: RefCell<Option<CapturingWriter>> = const { RefCell::new(None) };
}

static AUDIT_SUBSCRIBER: OnceLock<()> = OnceLock::new();

struct ThreadLocalAuditWriter(Option<CapturingWriter>);

impl Write for ThreadLocalAuditWriter {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        match &mut self.0 {
            Some(capture) => capture.write(buf),
            None => std::io::sink().write(buf),
        }
    }

    fn flush(&mut self) -> std::io::Result<()> {
        match &mut self.0 {
            Some(capture) => capture.flush(),
            None => std::io::sink().flush(),
        }
    }
}

struct ThreadLocalAuditMakeWriter;

impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for ThreadLocalAuditMakeWriter {
    type Writer = ThreadLocalAuditWriter;

    fn make_writer(&'a self) -> Self::Writer {
        ThreadLocalAuditWriter(ACTIVE_AUDIT_CAPTURE.with(|capture| capture.borrow().clone()))
    }
}

/// RAII guard that clears the thread-local capture on drop.
pub struct AuditCaptureGuard;

impl Drop for AuditCaptureGuard {
    fn drop(&mut self) {
        ACTIVE_AUDIT_CAPTURE.with(|capture| {
            capture.borrow_mut().take();
        });
    }
}

/// Install audit capture with thread-local routing.
///
/// Returns an RAII guard that clears the thread-local on drop. The global subscriber
/// is installed exactly once per process (test binary) via `OnceLock`; subsequent
/// calls on the same or different threads just activate the thread-local capture.
///
/// # Panics
///
/// Panics if called when this thread already has an active capture (nested capture
/// on one thread is disallowed).
pub fn install_audit_capture(capture: CapturingWriter) -> AuditCaptureGuard {
    AUDIT_SUBSCRIBER.get_or_init(|| {
        let subscriber = tracing_subscriber::fmt()
            .with_writer(ThreadLocalAuditMakeWriter)
            .with_ansi(false)
            .with_target(true)
            .with_max_level(tracing::Level::INFO)
            .finish();
        tracing::subscriber::set_global_default(subscriber)
            .expect("test audit subscriber is installed once");
    });
    ACTIVE_AUDIT_CAPTURE.with(|active| {
        assert!(
            active.borrow().is_none(),
            "nested audit capture on one test thread"
        );
        *active.borrow_mut() = Some(capture);
    });
    AuditCaptureGuard
}
