//! A file's capabilities, as the kernel keeps them in its
//! `security.capability` attribute (`vfs_cap_data`, linux/capability.h).
//!
//! The walk asks about each regular file it holds where it was listed
//! (`pinned`), through that handle (`xattr`). Running `getcap -r`
//! over the system instead let any account fail the run (its own files can
//! carry capabilities of a user namespace, as many as getcap's output can
//! hold), named files by lossy names, and let a name with a line break
//! forge a line of the listing.

mod xattr;

use std::fmt;
use std::fs;
use std::io;

/// The capability names the kernel has, by number (linux/capability.h).
/// A newer one is named by its number, as getcap does.
const NAMES: [&str; 41] = [
    "cap_chown",
    "cap_dac_override",
    "cap_dac_read_search",
    "cap_fowner",
    "cap_fsetid",
    "cap_kill",
    "cap_setgid",
    "cap_setuid",
    "cap_setpcap",
    "cap_linux_immutable",
    "cap_net_bind_service",
    "cap_net_broadcast",
    "cap_net_admin",
    "cap_net_raw",
    "cap_ipc_lock",
    "cap_ipc_owner",
    "cap_sys_module",
    "cap_sys_rawio",
    "cap_sys_chroot",
    "cap_sys_ptrace",
    "cap_sys_pacct",
    "cap_sys_admin",
    "cap_sys_boot",
    "cap_sys_nice",
    "cap_sys_resource",
    "cap_sys_time",
    "cap_sys_tty_config",
    "cap_mknod",
    "cap_lease",
    "cap_audit_write",
    "cap_audit_control",
    "cap_setfcap",
    "cap_mac_override",
    "cap_mac_admin",
    "cap_syslog",
    "cap_wake_alarm",
    "cap_block_suspend",
    "cap_audit_read",
    "cap_perfmon",
    "cap_bpf",
    "cap_checkpoint_restore",
];

/// What a file's attribute gives: one bit per capability, by number.
#[derive(Debug)]
pub(super) struct Capabilities {
    pub(super) permitted: u64,
    pub(super) inheritable: u64,
    /// Whether the permitted ones are made effective when the file runs.
    pub(super) effective: bool,
    /// The root of the user namespace they are for, as a host user id: 0
    /// for the host's own. Others give nothing outside namespaces that
    /// user owns, where it has every capability anyway.
    pub(super) root_id: u32,
}

impl Capabilities {
    /// The name of each capability in either set, sorted by name (as
    /// `EXPECTED_CAPABILITIES` lists them).
    pub(super) fn names(&self) -> Vec<String> {
        let mut names: Vec<String> = (0..64)
            .filter(|bit| (self.permitted | self.inheritable) >> bit & 1 == 1)
            .map(name)
            .collect();
        names.sort();
        names
    }
}

/// The name of capability `number`.
fn name(number: usize) -> String {
    NAMES
        .get(number)
        .map_or_else(|| number.to_string(), |name| (*name).to_string())
}

/// Every capability `NAMES` has a name for, one bit each.
const KNOWN: u64 = (1 << NAMES.len()) - 1;

/// As clauses grouped by sets, in capability order (`cap_a,cap_b=ep
/// cap_c=i`), and the namespace's root last where it is not the host's
/// (`[rootid=1000]`). One that holds every capability `NAMES` has is `=ep`,
/// with any numbered past them folded in: the rules read `names`, which
/// lists those too.
impl fmt::Display for Capabilities {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Each combination of sets, with the capabilities in exactly those.
        let mut by_sets: Vec<(String, u64)> = Vec::new();
        for bit in 0..64 {
            let (p, i) = (
                self.permitted >> bit & 1 == 1,
                self.inheritable >> bit & 1 == 1,
            );
            if !(p || i) {
                continue;
            }
            let sets: String = [(self.effective, 'e'), (i, 'i'), (p, 'p')]
                .iter()
                .filter(|(set, _)| *set)
                .map(|(_, letter)| *letter)
                .collect();
            match by_sets.iter_mut().find(|(known, _)| *known == sets) {
                Some((_, bits)) => *bits |= 1 << bit,
                None => by_sets.push((sets, 1 << bit)),
            }
        }
        by_sets.sort();
        let mut clauses: Vec<String> = by_sets
            .into_iter()
            .map(|(sets, bits)| {
                if bits & KNOWN == KNOWN {
                    return format!("={sets}");
                }
                let names: Vec<String> = (0..64)
                    .filter(|bit| bits >> bit & 1 == 1)
                    .map(name)
                    .collect();
                format!("{}={sets}", names.join(","))
            })
            .collect();
        if self.root_id != 0 {
            clauses.push(format!("[rootid={}]", self.root_id));
        }
        f.write_str(&clauses.join(" "))
    }
}

/// The capabilities of the file `held` (see `pinned::hold`); `None` where
/// it has none.
pub(super) fn capabilities(held: &fs::File) -> io::Result<Option<Capabilities>> {
    let Some(data) = xattr::security_capability(held)? else {
        return Ok(None);
    };
    decode(&data).map_err(|why| io::Error::new(io::ErrorKind::InvalidData, why))
}

/// Reads `vfs_cap_data`: a little-endian word of revision and flags, then
/// for each 32 capabilities a permitted and an inheritable word, and in
/// revision 3 the root id. Revision 1 is left out: the kernel refuses to
/// write it and fails a read of one already on disk (`cap_inode_getsecurity`
/// takes only revisions 2 and 3), which the walk tells as not checked.
/// `None` where no capability is in any set.
pub(super) fn decode(data: &[u8]) -> Result<Option<Capabilities>, &'static str> {
    let word = |at: usize| {
        let bytes: [u8; 4] = data.get(at..at + 4)?.try_into().ok()?;
        Some(u32::from_le_bytes(bytes))
    };
    let magic = word(0).ok_or("no revision")?;
    let size = match magic & 0xff00_0000 {
        0x0200_0000 => 20,
        0x0300_0000 => 24,
        _ => return Err("an unknown revision"),
    };
    if data.len() != size {
        return Err("a size its revision does not have");
    }
    let low_and_high = |at: usize| Some(u64::from(word(at)?) | u64::from(word(at + 8)?) << 32);
    let capabilities = Capabilities {
        permitted: low_and_high(4).ok_or("short")?,
        inheritable: low_and_high(8).ok_or("short")?,
        effective: magic & 0x1 != 0,
        root_id: if size == 24 {
            word(20).ok_or("short")?
        } else {
            0
        },
    };
    let any = capabilities.permitted | capabilities.inheritable != 0;
    Ok(any.then_some(capabilities))
}
