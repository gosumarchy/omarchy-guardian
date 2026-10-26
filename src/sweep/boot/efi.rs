//! The EFI programs in `/boot` against the ones packages ship.
//!
//! A boot loader's tool copies the packaged program into `/boot`
//! (`limine-install`, `bootctl install`), and some change the copy in ways
//! that are known. Those changes are put back before the comparison, so a
//! program that differs from its package only by them counts as packaged:
//!
//! - a signature (`sbctl sign`, `sbsign`): the certificate table appended
//!   at the end, the header entry that points at it, the header checksum,
//!   and the up to seven zero bytes that align the table;
//! - the hash of `limine.conf` that `limine enroll-config` writes into
//!   Limine after a marker, in place of 128 `0` characters.
//!
//! What cannot be compared is listed with the reason, never passed as
//! packaged and never told as tampered: a unified kernel image (UKI) is
//! built on this machine from the kernel, the initramfs and the command
//! line, so only the kernel inside it is compared; `grub-install` builds
//! GRUB's program on this machine. A program no package ships is a finding
//! in the directories the boot loaders of an Arch system start from, and
//! listed with a note elsewhere (another system's boot loader, a firmware
//! tool). Nothing of `/boot` goes to the AI review: the items are hashed
//! binaries.

use std::fs::OpenOptions;
use std::io::{Read as _, Seek as _, SeekFrom};
use std::os::unix::fs::OpenOptionsExt as _;
use std::path::Path;

use super::Boot;
use crate::autorun::Category;
use crate::files::{O_NOFOLLOW, O_NONBLOCK};
use crate::paths::file_name;
use crate::rules::RuleId;
use crate::sha256::{Digest, Sha256};
use crate::sweep::collect::{self, Origin, Scope};
use crate::sweep::read::{self, Found};
use crate::sweep::tier::Tier;

/// Where packages ship the EFI programs that boot loader tools copy into
/// `/boot`: Limine, systemd-boot (and the UKI stub), fwupd, shim, rEFInd
/// and the UEFI shell.
const PACKAGED: &[&str] = &[
    "usr/share/limine/*",
    "usr/lib/systemd/boot/efi/*",
    "usr/lib/fwupd/efi/*",
    "usr/share/shim-signed/*",
    "usr/share/refind/*",
    "usr/share/refind/drivers_*/*",
    "usr/share/edk2-shell/*/*",
];

/// The directories under `/boot` that the boot loaders of an Arch system
/// start from, in lower case (FAT ignores case): the firmware's default
/// path, Limine's, systemd-boot's, and the one UKIs go in.
const STARTED: &[&str] = &[
    "boot/efi/boot/",
    "boot/efi/limine/",
    "boot/efi/systemd/",
    "boot/efi/linux/",
];

/// The marker `limine enroll-config` writes the configuration's hash
/// after, as 128 hexadecimal characters. Limine ships them as `0`s.
const ENROLL_MARKER: &[u8] = b"++CONFIG_B2SUM_SIGNATURE++";
const ENROLLED_LENGTH: usize = 128;

/// The most EFI programs compared (arbitrary: an ESP holds a handful).
const MAX_PROGRAMS: usize = 64;

/// sbsign and sbctl align the certificate table to 8 bytes, padding the
/// program with zeros before it.
const MAX_PADDING: usize = 7;

/// What is said of a UKI whose kernel no installed package ships.
const OTHER_KERNEL: &str = "a unified kernel image whose kernel no installed kernel package ships: an older kernel kept for a snapshot's boot entry, or one put there; its initramfs and command line are built on this machine and are not comparable";

/// What is said of GRUB's program.
const GRUB: &str = "not comparable: grub-install builds GRUB's EFI program on this machine, so no package has a copy";

/// What is said of a program no package ships outside `STARTED`.
const ELSEWHERE: &str = "an EFI program no installed package ships, outside the directories this system's boot loaders start from: another system's boot loader or a firmware tool, or one put there";

/// What an EFI program in `/boot` was found to be.
#[derive(Debug, PartialEq, Eq)]
enum Verdict {
    /// What a package ships, perhaps signed or with Limine's configuration
    /// hash enrolled since.
    Packaged,
    /// A UKI whose kernel an installed kernel package ships.
    PackagedKernel,
    /// Cannot be compared, for the reason given.
    NotComparable(&'static str),
    /// No installed package ships it.
    Unknown,
}

/// A packaged EFI program, still what its package shipped.
struct Reference {
    sha256: Digest,
    /// Its bytes as `normalized` gives them, where they were all read.
    normalized: Option<Vec<u8>>,
}

/// Compares the EFI programs among `files` (everything under `/boot`)
/// with the packaged ones; `kernels` are the digests of the packaged
/// kernel images, for what is inside a UKI.
pub(super) fn compare(scope: &Scope<'_>, files: &[String], kernels: &[Digest], boot: &mut Boot) {
    let as_root = scope.origin == Origin::Root;
    let programs: Vec<&String> = files
        .iter()
        .filter(|path| read::has_extension(file_name(path), "efi"))
        .collect();
    if programs.is_empty() {
        return;
    }
    if programs.len() > MAX_PROGRAMS {
        let sentence =
            format!("/boot: more than {MAX_PROGRAMS} EFI programs; the rest were not compared");
        if as_root {
            boot.unchecked.push(sentence);
        } else {
            boot.notes.push(sentence);
        }
    }
    let references = references(scope);
    let mut packaged_kernels = 0;
    for path in programs.into_iter().take(MAX_PROGRAMS) {
        let found = collect::look(scope, Category::Boot, path, None);
        let mut item = collect::item_of(scope, Category::Boot, path.clone(), None, &found);
        let verdict = match &found {
            Found::File { .. } if matches!(item.tier, Tier::Vendor | Tier::UserBuilt) => {
                Verdict::Packaged
            }
            Found::File {
                sha256, size, head, ..
            } => {
                let at = scope.root.join(path);
                verdict(&at, *sha256, (*size, head), &references, kernels)
            }
            // FAT, which an ESP is, has no links; one elsewhere in `/boot`
            // is the boot loader's to follow, and its target is a file of
            // its own here.
            Found::Link(_) | Found::Other => continue,
            Found::Unreadable(_) if as_root => {
                boot.unchecked
                    .push(format!("/{path}: could not be read; not compared"));
                continue;
            }
            Found::Unreadable(_) => {
                boot.notes.push(format!(
                    "/{path} cannot be read as this user; the root checks compare it with the packaged EFI programs"
                ));
                continue;
            }
        };
        match verdict {
            Verdict::Packaged => continue,
            Verdict::PackagedKernel => {
                packaged_kernels += 1;
                continue;
            }
            Verdict::NotComparable(reason) => item.notes.push(reason.into()),
            Verdict::Unknown if is_started(path) => item.alerts.push((
                RuleId::BootTampering,
                "not an EFI program any installed package ships, in a directory the boot loader starts from".into(),
            )),
            Verdict::Unknown => item.notes.push(ELSEWHERE.into()),
        }
        boot.items.push(item);
    }
    if packaged_kernels > 0 {
        boot.notes.push(format!(
            "{packaged_kernels} unified kernel image(s) in /boot: the kernel inside is what an installed kernel package ships; the initramfs and command line inside are built on this machine and are not compared"
        ));
    }
}

/// Whether `path` lies in a directory this system's boot loaders start
/// programs from.
fn is_started(path: &str) -> bool {
    let path = path.to_ascii_lowercase();
    STARTED.iter().any(|directory| path.starts_with(directory))
}

/// The packaged EFI programs that are still what their packages shipped.
fn references(scope: &Scope<'_>) -> Vec<Reference> {
    PACKAGED
        .iter()
        .flat_map(|pattern| read::matching(scope.root, pattern).files)
        .filter(|path| read::has_extension(file_name(path), "efi"))
        .filter_map(|path| {
            let found = collect::look(scope, Category::Boot, &path, None);
            let item = collect::item_of(scope, Category::Boot, path, None, &found);
            let Found::File {
                sha256, size, head, ..
            } = found
            else {
                return None;
            };
            matches!(item.tier, Tier::Vendor | Tier::UserBuilt).then(|| Reference {
                sha256,
                normalized: whole(size, &head).and_then(normalized),
            })
        })
        .collect()
}

/// `head` when it holds every byte of a file of `size` bytes.
fn whole(size: u64, head: &[u8]) -> Option<&[u8]> {
    (head.len() as u64 == size).then_some(head)
}

/// What the program at `path`, with digest `sha256` and `size` bytes of
/// which `head` holds the first, is, against the packaged `references`
/// and `kernels`.
fn verdict(
    path: &Path,
    sha256: Digest,
    (size, head): (u64, &[u8]),
    references: &[Reference],
    kernels: &[Digest],
) -> Verdict {
    if references
        .iter()
        .any(|reference| reference.sha256 == sha256)
    {
        return Verdict::Packaged;
    }
    if let Some(program) = whole(size, head).and_then(normalized) {
        let same = references.iter().any(|reference| {
            reference
                .normalized
                .as_deref()
                .is_some_and(|packaged| is_same_program(&program, packaged))
        });
        if same {
            return Verdict::Packaged;
        }
    }
    let kernel = header(head).and_then(|header| section(head, &header, b".linux"));
    if let Some((start, length)) = kernel {
        return match range_digest(path, start, length) {
            Some(kernel) if kernels.contains(&kernel) => Verdict::PackagedKernel,
            _ => Verdict::NotComparable(OTHER_KERNEL),
        };
    }
    let name = path
        .file_name()
        .map(|name| name.to_string_lossy().to_ascii_lowercase());
    if name.is_some_and(|name| name.starts_with("grub")) {
        return Verdict::NotComparable(GRUB);
    }
    Verdict::Unknown
}

/// Whether `program` is `packaged`, both `normalized`: the same bytes,
/// followed by no more than the zeros that align a certificate table.
/// Everything a loader reads (the headers, which equal the package's, and
/// the sections they point at, which lie within the package's length) is
/// then the package's.
fn is_same_program(program: &[u8], packaged: &[u8]) -> bool {
    program.len() >= packaged.len()
        && program.len() - packaged.len() <= MAX_PADDING
        && program[..packaged.len()] == *packaged
        && program[packaged.len()..].iter().all(|byte| *byte == 0)
}

/// Where the parts of a PE header that tools rewrite after install lie,
/// and the section table.
#[derive(Debug)]
struct Header {
    /// The offset of the checksum field.
    checksum: usize,
    /// The offset of the certificate table's entry, where there is one.
    certificates: Option<usize>,
    /// The offset of the section table, and how many sections it lists.
    sections: usize,
    count: usize,
}

fn u16_at(bytes: &[u8], at: usize) -> Option<u16> {
    let field = bytes.get(at..at.checked_add(2)?)?;
    Some(u16::from_le_bytes([field[0], field[1]]))
}

fn u32_at(bytes: &[u8], at: usize) -> Option<u32> {
    let field = bytes.get(at..at.checked_add(4)?)?;
    Some(u32::from_le_bytes([field[0], field[1], field[2], field[3]]))
}

/// The header of the PE program `bytes` starts with, if it is one, read
/// as Microsoft's PE format specification lays it out (the COFF header,
/// then the optional header with its data directories, then the section
/// table).
fn header(bytes: &[u8]) -> Option<Header> {
    if bytes.get(..2)? != b"MZ" {
        return None;
    }
    let pe = usize::try_from(u32_at(bytes, 0x3c)?).ok()?;
    if bytes.get(pe..pe.checked_add(4)?)? != b"PE\0\0" {
        return None;
    }
    // From here on every offset is below the length of `bytes` plus a few
    // hundred thousand, so none overflows.
    let count = usize::from(u16_at(bytes, pe + 6)?);
    let optional_size = usize::from(u16_at(bytes, pe + 20)?);
    let optional = pe + 24;
    // PE32 and PE32+ differ in where the data directories start.
    let (directories, directory_count) = match u16_at(bytes, optional)? {
        0x10b => (optional + 96, optional + 92),
        0x20b => (optional + 112, optional + 108),
        _ => return None,
    };
    // The certificate table is the fifth data directory.
    let certificates = (u32_at(bytes, directory_count)? > 4).then_some(directories + 4 * 8);
    Some(Header {
        checksum: optional + 64,
        certificates,
        sections: optional + optional_size,
        count,
    })
}

/// The bytes of the PE program `bytes` with what tools change after
/// install put back as packages ship it (see the module docs); `None` for
/// anything that is not a PE program.
fn normalized(bytes: &[u8]) -> Option<Vec<u8>> {
    let header = header(bytes)?;
    let mut program = bytes.to_vec();
    let mut end = program.len();
    if let Some(entry) = header.certificates {
        let offset = u32_at(bytes, entry)?;
        let size = u32_at(bytes, entry + 4)?;
        if size > 0 {
            end = end.min(usize::try_from(offset).ok()?);
        }
        program.get_mut(entry..entry + 8)?.fill(0);
    }
    program
        .get_mut(header.checksum..header.checksum + 4)?
        .fill(0);
    program.truncate(end);
    if let Some(at) = program
        .windows(ENROLL_MARKER.len())
        .position(|window| window == ENROLL_MARKER)
    {
        let start = at + ENROLL_MARKER.len();
        if let Some(hash) = program.get_mut(start..start + ENROLLED_LENGTH) {
            hash.fill(b'0');
        }
    }
    Some(program)
}

/// Where the section called `name` lies in the program: its offset in the
/// file and its length, without the padding to the file alignment where
/// the header says how long it really is.
fn section(bytes: &[u8], header: &Header, name: &[u8]) -> Option<(u64, u64)> {
    // The PE format allows at most 96 sections.
    (0..header.count.min(96)).find_map(|index| {
        let entry = header.sections + index * 40;
        let named = bytes.get(entry..entry + 8)?;
        if named.split(|byte| *byte == 0).next()? != name {
            return None;
        }
        let virtual_size = u64::from(u32_at(bytes, entry + 8)?);
        let raw_size = u64::from(u32_at(bytes, entry + 16)?);
        let start = u64::from(u32_at(bytes, entry + 20)?);
        let length = if virtual_size > 0 {
            virtual_size.min(raw_size)
        } else {
            raw_size
        };
        Some((start, length))
    })
}

/// The SHA-256 of `length` bytes from `start` of the file at `path`,
/// opened without following a link; `None` when they cannot all be read.
fn range_digest(path: &Path, start: u64, length: u64) -> Option<Digest> {
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(O_NOFOLLOW | O_NONBLOCK)
        .open(path)
        .ok()?;
    if !file.metadata().ok()?.is_file() {
        return None;
    }
    file.seek(SeekFrom::Start(start)).ok()?;
    let mut hasher = Sha256::new();
    let mut buffer = vec![0_u8; 64 * 1024];
    let mut taken = file.take(length);
    let mut read_so_far = 0;
    loop {
        let read = taken.read(&mut buffer).ok()?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
        read_so_far += read as u64;
    }
    (read_so_far == length).then(|| hasher.finalize())
}

#[cfg(test)]
mod tests;
