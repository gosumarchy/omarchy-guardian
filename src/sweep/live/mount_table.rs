//! The walk's own mount table, `/proc/self/mountinfo`, read again only
//! when it has changed.
//!
//! The set-id walk asks what a mount on an entry is each time it holds
//! one (`pinned::MountKind`). The kernel writes the whole table for each
//! read, which an account can make megabytes long with its own FUSE
//! mounts, so the table is kept between questions and read again only
//! when a mount was made or removed since. The kernel flags that on the
//! open table: `poll` reports `POLLPRI` when the namespace's mounts
//! changed, however many times, since the file was opened or last polled
//! (`mounts_poll` in the kernel's `fs/proc_namespace.c`;
//! `proc_pid_mounts(5)`). std has no
//! wrapper for `poll`, so this module calls it through FFI, the crate's
//! second `unsafe` code after `capability::xattr`.
//!
//! A table kept without that flag would be wrong, not only old: mount ids
//! are reused, lowest first, as soon as a mount is freed, so an id read
//! from a held entry could name another mount in a table read before.
#![expect(
    unsafe_code,
    reason = "poll has no std wrapper; one call, argued below"
)]

use std::collections::HashMap;
use std::ffi::{c_int, c_short, c_ulong};
use std::fs;
use std::io::{self, Read as _};
use std::os::fd::AsRawFd as _;

use crate::sweep::live::pinned::{self, MountKind};

// `POLLPRI` and `POLLERR` have asm-generic's values on every Linux target,
// these four (the ones main.rs accepts) among them, and `nfds_t` is
// `unsigned long` on each in glibc and musl.
#[cfg(not(any(
    target_arch = "x86_64",
    target_arch = "aarch64",
    target_arch = "arm",
    target_arch = "riscv64"
)))]
compile_error!("CHANGED holds asm-generic poll flags; check them for this target");

/// `struct pollfd` (poll.h).
#[repr(C)]
struct PollFd {
    fd: c_int,
    events: c_short,
    revents: c_short,
}

// SAFETY: `poll` is the C library's (glibc and musl alike, which std links
// on Linux) with this signature: `int poll(struct pollfd *fds, nfds_t
// nfds, int timeout)`, where `nfds_t` is `unsigned long`.
unsafe extern "C" {
    fn poll(fds: *mut PollFd, nfds: c_ulong, timeout: c_int) -> c_int;
}

/// `POLLPRI` and `POLLERR` (asm-generic/poll.h): the kernel sets both on a
/// mount table that changed.
const CHANGED: c_short = 0x2 | 0x8;

/// The walk's own mount table, as last read.
#[derive(Debug, Default)]
pub(super) struct MountTable {
    /// The table as opened for the last read, polled for changes since.
    /// `None` before the first question, once it changed, and after a read
    /// that failed.
    open: Option<fs::File>,
    /// What each mount is, by id.
    kinds: HashMap<u64, MountKind>,
    /// How many times the table was read.
    #[cfg(test)]
    reads: usize,
}

impl MountTable {
    /// What mount `mount` is now (see `MountKind`). The ids are this
    /// process's, so the table is. Reads the table only where a mount was
    /// made or removed since it was last read, or where it was not read.
    pub(super) fn kind(&mut self, mount: u64) -> io::Result<MountKind> {
        self.open.take_if(|file| changed(file));
        if self.open.is_none() {
            // Opened before it is read, so a change made during the read or
            // since is flagged on the next poll. The kernel writes a mount
            // point and a FUSE source in any bytes, so it is read as bytes.
            let mut file = fs::File::open("/proc/self/mountinfo")?;
            let mut mountinfo = Vec::new();
            file.read_to_end(&mut mountinfo)?;
            self.kinds = kinds_by_id(&mountinfo);
            self.open = Some(file);
            #[cfg(test)]
            {
                self.reads += 1;
            }
        }
        Ok(kind_in(&self.kinds, mount))
    }

    /// How many times the table was read.
    #[cfg(test)]
    pub(super) fn reads(&self) -> usize {
        self.reads
    }
}

/// What mount `mount` is in a table read as `kinds_by_id`: gone where the
/// table does not hold it.
pub(super) fn kind_in(kinds: &HashMap<u64, MountKind>, mount: u64) -> MountKind {
    kinds.get(&mount).copied().unwrap_or(MountKind::Gone)
}

/// Whether the table open in `file` changed since it was opened or last
/// polled. A poll that fails says it did: reading the table again is
/// right either way, and only costs the read.
fn changed(file: &fs::File) -> bool {
    let mut polled = PollFd {
        fd: file.as_raw_fd(),
        events: CHANGED,
        revents: 0,
    };
    // SAFETY: `polled` is one valid `struct pollfd`, alive and not
    // otherwise borrowed through the call, and the count passed is 1; a
    // timeout of 0 returns at once.
    let ready = unsafe { poll(&raw mut polled, 1, 0) };
    ready < 0 || polled.revents & CHANGED != 0
}

/// What each mount of `mountinfo` is, by id.
pub(super) fn kinds_by_id(mountinfo: &[u8]) -> HashMap<u64, MountKind> {
    String::from_utf8_lossy(mountinfo)
        .lines()
        .filter_map(pinned::line)
        .map(|line| {
            let kind = if line.is_accounts() {
                MountKind::Accounts
            } else {
                MountKind::Roots
            };
            (line.id, kind)
        })
        .collect()
}
