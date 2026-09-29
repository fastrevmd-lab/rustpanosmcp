//! Advisory lock over the persisted mutation-state file.
//!
//! [`mecmcp_changeset::ChangesetCoordinator`]'s writer swaps the file in with
//! an atomic rename, which stops one writer's write from being observed
//! half-done. It does not stop two separate OS processes -- two service
//! instances, or a service alongside an offline recovery run -- from both
//! reading the file, both mutating their own in-memory copy, and each
//! clobbering the other's write with a last-writer-wins rename. This module
//! closes that gap with an OS advisory lock taken once, for the lifetime of
//! the service that opened the state file.

use crate::{PanosMcpError, Result};
use std::{
    ffi::OsString,
    fs::{File, OpenOptions},
    path::{Path, PathBuf},
};

/// Held for the lifetime of the [`PanosService`](crate::tools::PanosService)
/// that acquired it. Dropping it releases the OS advisory lock.
#[derive(Debug)]
pub(crate) struct StateFileLock {
    _file: File,
}

impl StateFileLock {
    /// Acquire an exclusive, non-blocking advisory lock on `state_path`'s
    /// sibling `.lock` file.
    ///
    /// Non-blocking and fails closed: a second process pointed at the same
    /// state file must be refused loudly and immediately, not queued
    /// silently behind the first where it would look hung.
    pub(crate) fn acquire(state_path: &Path) -> Result<Self> {
        let lock_path = lock_path_for(state_path);
        if let Some(parent) = lock_path.parent()
            && !parent.as_os_str().is_empty()
        {
            std::fs::create_dir_all(parent).map_err(|error| {
                PanosMcpError::Configuration(format!(
                    "could not create directory for state lock file {}: {error}",
                    lock_path.display()
                ))
            })?;
        }
        let file = OpenOptions::new()
            .create(true)
            .truncate(false)
            .write(true)
            .open(&lock_path)
            .map_err(|error| {
                PanosMcpError::Configuration(format!(
                    "could not open state lock file {}: {error}",
                    lock_path.display()
                ))
            })?;
        rustix::fs::flock(&file, rustix::fs::FlockOperation::NonBlockingLockExclusive).map_err(
            |error| {
                PanosMcpError::Configuration(format!(
                    "mutation state file {} is locked by another process ({error}); \
                     only one rust-panosmcp instance may use a given state file at a time",
                    state_path.display()
                ))
            },
        )?;
        Ok(Self { _file: file })
    }
}

fn lock_path_for(state_path: &Path) -> PathBuf {
    let mut name: OsString = state_path
        .file_name()
        .map(OsString::from)
        .unwrap_or_else(|| OsString::from("mutation-state"));
    name.push(".lock");
    state_path.with_file_name(name)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_second_process_pointed_at_the_same_state_file_is_refused() {
        let dir = tempfile::tempdir().expect("tempdir");
        let state_path = dir.path().join("mutation-state.json");

        let first = StateFileLock::acquire(&state_path).expect("first lock");
        let second = StateFileLock::acquire(&state_path);
        assert!(
            second.is_err(),
            "a second concurrent lock on the same state file must be refused"
        );
        drop(first);

        StateFileLock::acquire(&state_path).expect("lock is released after drop");
    }

    /// Two threads race to lock the same state file at the same instant.
    ///
    /// `flock` is per-open-file-description, so two file descriptors opened
    /// from the same process still conflict exactly as two separate
    /// processes would -- this is a faithful concurrency test, not a stand-in
    /// for one. Exactly one side must win; the loser must fail closed rather
    /// than silently proceed and race the winner's writes.
    #[test]
    fn concurrent_lock_attempts_on_one_state_file_never_both_succeed() {
        let dir = tempfile::tempdir().expect("tempdir");
        let state_path = dir.path().join("mutation-state.json");
        let barrier = std::sync::Arc::new(std::sync::Barrier::new(2));

        let attempt = |path: PathBuf, barrier: std::sync::Arc<std::sync::Barrier>| {
            std::thread::spawn(move || {
                barrier.wait();
                StateFileLock::acquire(&path)
            })
        };
        let a = attempt(state_path.clone(), barrier.clone());
        let b = attempt(state_path.clone(), barrier);

        let a_won = a.join().expect("thread a").is_ok();
        let b_won = b.join().expect("thread b").is_ok();
        assert_ne!(
            a_won, b_won,
            "exactly one concurrent lock attempt must succeed, got a={a_won} b={b_won}"
        );
    }
}
