//! Who is running: the real and the effective user id, and whether a file's
//! owner is someone else.

use std::fs;

const STATUS: &str = "/proc/self/status";

/// The real uid of this process.
pub fn real_uid() -> Option<u32> {
    uid_in(&fs::read_to_string(STATUS).ok()?, REAL)
}

/// The effective user id, from `/proc/self/status` (`Uid: real effective saved fs`).
pub fn effective_uid() -> Result<u32, String> {
    let status = fs::read_to_string(STATUS).map_err(|error| format!("{STATUS}: {error}"))?;
    uid_in(&status, EFFECTIVE).ok_or_else(|| "cannot read the effective user id".to_string())
}

/// Where each id stands on the `Uid:` line.
const REAL: usize = 0;
const EFFECTIVE: usize = 1;

fn uid_in(status: &str, field: usize) -> Option<u32> {
    status
        .lines()
        .find_map(|line| line.strip_prefix("Uid:"))?
        .split_whitespace()
        .nth(field)?
        .parse()
        .ok()
}

/// Whether a file owned by `owner` belongs to someone other than root or
/// the user `uid`. In a user namespace that does not map root, root's
/// files show the overflow owner, which is then not foreign either.
pub fn is_foreign_owner(owner: u32, uid: Option<u32>) -> bool {
    owner != 0 && Some(owner) != uid && !(owner == overflow_uid() && root_unmapped())
}

/// The owner the kernel shows for users a user namespace does not map.
fn overflow_uid() -> u32 {
    fs::read_to_string("/proc/sys/kernel/overflowuid")
        .ok()
        .and_then(|text| text.trim().parse().ok())
        .unwrap_or(65_534)
}

/// Whether this process runs in a user namespace that does not map root
/// (a sandbox, as in the end-to-end tests), where root's directories show
/// the overflow owner. The real pacman hook never runs in one.
pub fn root_unmapped() -> bool {
    fs::read_to_string("/proc/self/uid_map").is_ok_and(|map| root_unmapped_in(&map))
}

fn root_unmapped_in(map: &str) -> bool {
    !map.lines().any(|line| {
        let mut fields = line.split_whitespace();
        let inside: Option<u64> = fields.next().and_then(|field| field.parse().ok());
        let count: Option<u64> = fields.nth(1).and_then(|field| field.parse().ok());
        matches!((inside, count), (Some(start), Some(count)) if start == 0 && count > 0)
    })
}

#[cfg(test)]
mod tests {
    use super::{
        EFFECTIVE, REAL, effective_uid, is_foreign_owner, real_uid, root_unmapped_in, uid_in,
    };

    #[test]
    fn reads_the_real_uid_from_proc_status() {
        let status = "Name:\tomarchy-guardian\nUid:\t1000\t1000\t1000\t1000\nGid:\t1000\n";
        assert_eq!(uid_in(status, REAL), Some(1000));
        assert_eq!(uid_in("Name:\tx\n", REAL), None);
    }

    #[test]
    fn the_real_and_the_effective_uid_are_told_apart() {
        let status = "Name:\tx\nUid:\t1000\t0\t0\t0\nGid:\t1000\t0\t0\t0\n";
        assert_eq!(uid_in(status, REAL), Some(1000));
        assert_eq!(uid_in(status, EFFECTIVE), Some(0));
        assert_eq!(uid_in("Uid:\t1000\n", EFFECTIVE), None);
        assert_eq!(uid_in("Uid:\tx\ty\n", EFFECTIVE), None);
        assert_eq!(uid_in("Name:\tx\n", EFFECTIVE), None);
        // Nothing here changes either id, so this process has one of each.
        assert!(real_uid().is_some());
        assert!(effective_uid().is_ok());
    }

    #[test]
    fn root_and_the_user_are_not_foreign_owners() {
        assert!(!is_foreign_owner(0, None));
        assert!(!is_foreign_owner(0, Some(1000)));
        assert!(!is_foreign_owner(1000, Some(1000)));
        assert!(is_foreign_owner(1000, Some(1001)));
        assert!(is_foreign_owner(1000, None));
    }

    #[test]
    fn root_is_unmapped_where_no_range_starts_at_zero() {
        assert!(!root_unmapped_in("         0          0 4294967295\n"));
        assert!(!root_unmapped_in("0 1000 1\n"));
        assert!(root_unmapped_in("1000 1000 1\n"));
        assert!(root_unmapped_in("0 1000 0\n"));
        assert!(root_unmapped_in(""));
    }
}
