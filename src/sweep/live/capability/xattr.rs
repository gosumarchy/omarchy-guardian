//! Reading a file's `security.capability` attribute. std has no wrapper
//! for `getxattr`, so this module calls it through FFI; with the `poll`
//! of `mount_table`, it is the crate's only `unsafe` code. The crate has
//! no Miri job, and Miri could not run this foreign call anyway, so the
//! argument below rests on review.
#![expect(
    unsafe_code,
    reason = "getxattr has no std wrapper; one call, argued below"
)]

use std::ffi::{CString, c_char, c_void};
use std::fs;
use std::io;
use std::os::fd::AsRawFd;

// The errno values below are asm-generic's, checked for these targets, the
// ones Arch and Arch Linux ARM build for. A target with errno values of its
// own (mips, sparc) would read every file without the attribute as failed.
#[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
compile_error!("NO_ATTRIBUTE holds asm-generic errno values; check them for this target");

// SAFETY: `getxattr` is the C library's (glibc and musl alike, which std
// links on Linux) with this signature: `ssize_t getxattr(const char *path,
// const char *name, void *value, size_t size)`.
unsafe extern "C" {
    fn getxattr(path: *const c_char, name: *const c_char, value: *mut c_void, size: usize)
    -> isize;
}

/// `ENODATA` and `EOPNOTSUPP` (asm-generic/errno.h): the file has no such
/// attribute, or its filesystem keeps none.
const NO_ATTRIBUTE: [i32; 2] = [61, 95];

/// The largest `vfs_cap_data` (revision 3, with its root id), in bytes;
/// a larger value fails the call (`ERANGE`), which the kernel never keeps.
const MAX_DATA: usize = 24;

/// The attribute of the file `held` (see `pinned::hold`), as its bytes;
/// `None` where it has none. Asked through `/proc/self/fd`, whose link
/// leads to the file held, not to whatever its path names now.
pub(super) fn security_capability(held: &fs::File) -> io::Result<Option<Vec<u8>>> {
    let path = CString::new(format!("/proc/self/fd/{}", held.as_raw_fd()))
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, error))?;
    let mut data = [0_u8; MAX_DATA];
    // SAFETY: `path` and the attribute's name are C strings that live
    // through the call, and `data` is valid for writes of `data.len()`
    // bytes, the size passed; the call writes at most that many.
    let read = unsafe {
        getxattr(
            path.as_ptr(),
            c"security.capability".as_ptr(),
            data.as_mut_ptr().cast::<c_void>(),
            data.len(),
        )
    };
    let Ok(read) = usize::try_from(read) else {
        let error = io::Error::last_os_error();
        if error
            .raw_os_error()
            .is_some_and(|code| NO_ATTRIBUTE.contains(&code))
        {
            return Ok(None);
        }
        return Err(error);
    };
    // The call says how many bytes it wrote, at most the size it was given.
    Ok(Some(data.get(..read).unwrap_or(&data).to_vec()))
}
