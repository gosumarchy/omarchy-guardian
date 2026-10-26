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
//! A unified kernel image (UKI) is built on this machine from systemd's
//! packaged stub, the kernel, the initramfs and the command line. Its stub
//! is compared with the packaged one (see `pe::is_built_from`) and its
//! kernel with the packaged kernels; its initramfs and command line cannot
//! be compared. One built from the packaged stub around another kernel is
//! a finding in the directories the boot loaders start from or where it
//! says it is the running release, as a kernel image is (see
//! `kernel_images`), and listed with a note elsewhere; one whose stub is
//! not the packaged one, or that no packaged stub is installed to compare
//! with, is told like any unknown program there.
//! `grub-install` builds GRUB's program on this machine: where the grub
//! package is installed, a `grub*.efi` is listed with a note.
//!
//! A program no package ships is a finding in the directories the boot
//! loaders of an Arch system start from, and listed with a note elsewhere
//! (another system's boot loader, a firmware tool). Nothing of `/boot`
//! goes to the AI review: the items are hashed binaries.

mod pe;

use std::borrow::Cow;
use std::fs::{self, OpenOptions};
use std::io::{self, Read as _};
use std::os::unix::fs::{MetadataExt as _, OpenOptionsExt as _};
use std::path::Path;

use super::Boot;
use crate::autorun::Category;
use crate::error::{Error, IoContext as _};
use crate::files::{O_NOFOLLOW, O_NONBLOCK};
use crate::paths::file_name;
use crate::rules::RuleId;
use crate::sha256::{Digest, Sha256};
use crate::sweep::collect::{self, Origin, Scope};
use crate::sweep::read::{self, Found};
use crate::sweep::tier::Tier;

/// Where packages ship the EFI programs that boot loader tools copy into
/// `/boot`: Limine, systemd-boot, fwupd, shim and rEFInd. A packaged
/// program counts wherever it sits.
const PACKAGED: &[&str] = &[
    "usr/share/limine/*",
    "usr/lib/systemd/boot/efi/*",
    "usr/lib/fwupd/efi/*",
    "usr/share/shim-signed/*",
    "usr/share/refind/*",
    "usr/share/refind/drivers_*/*",
];

/// Where packages ship the UEFI shell. It is a finding anywhere in `/boot`:
/// a trusted boot loader can start it from any path (systemd-boot's
/// `auto-efi-shell` entry), and it runs `startup.nsh` and whatever is
/// typed at the firmware's console, before the kernel and its defences.
const SHELLS: &str = "usr/share/edk2-shell/*/*";

/// Where systemd ships the stubs UKIs are built from.
const STUBS: &str = "usr/lib/systemd/boot/efi/*.efi.stub";

/// A file the grub package installs: where it is, `grub-install` can have
/// built a GRUB program into `/boot`.
const GRUB_MODULES: &str = "usr/lib/grub/x86_64-efi/kernel.img";

/// The directories under `/boot` that the boot loaders of an Arch system
/// start from, in lower case (FAT ignores case): the firmware's default
/// path, Limine's, systemd-boot's, and the one UKIs go in.
const STARTED: &[&str] = &[
    "boot/efi/boot/",
    "boot/efi/limine/",
    "boot/efi/systemd/",
    "boot/efi/linux/",
];

/// The most EFI programs compared (arbitrary: an ESP holds a handful).
const MAX_PROGRAMS: usize = 64;

/// The largest program read whole to be compared (arbitrary: UKIs with a
/// large initramfs stay well under it). A larger one is not compared, and
/// the sweep says so.
const MAX_PROGRAM_SIZE: u64 = 256 * 1024 * 1024;

/// What is said of a UKI built from the packaged stub around a kernel no
/// installed package ships.
const OTHER_KERNEL: &str = "a unified kernel image built from the packaged stub, whose kernel no installed kernel package ships: an older kernel kept for a snapshot's boot entry, or one put there; its initramfs and command line are built on this machine and are not comparable";

/// What is said of a UKI where systemd's stub is not installed.
const NO_STUB: &str = "a unified kernel image; no packaged stub is installed to compare its stub with, so neither it nor its kernel was compared";

/// What is said of GRUB's program.
const GRUB: &str = "not comparable: grub-install builds GRUB's EFI program on this machine, so no package has a copy";

/// What is said of a program no package ships outside `STARTED`.
const ELSEWHERE: &str = "an EFI program no installed package ships, outside the directories this system's boot loaders start from: another system's boot loader or a firmware tool, or one put there";

/// What an EFI program in `/boot` was found to be.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Verdict {
    /// What a package ships, perhaps signed or with Limine's configuration
    /// hash enrolled since.
    Packaged,
    /// A UKI built from the packaged stub around a packaged kernel.
    PackagedKernel,
    /// Cannot be compared, for the reason given.
    NotComparable(&'static str),
    /// A UKI built from the packaged stub around a kernel no package ships,
    /// that this system starts.
    StartedKernel,
    /// A packaged UEFI shell (see `SHELLS`).
    Shell,
    /// No installed package ships it.
    Unknown,
}

/// A packaged EFI program, still what its package shipped.
struct Reference {
    sha256: Digest,
    /// Its bytes as `pe::normalized` gives them, where they were all read.
    normalized: Option<Vec<u8>>,
}

/// What the programs in `/boot` are compared with.
struct Packaged<'a> {
    programs: Vec<Reference>,
    /// The packaged UEFI shells, which no program in `/boot` may be.
    shells: Vec<Reference>,
    /// The bytes of the packaged UKI stubs that are still what systemd
    /// shipped.
    stubs: Vec<Vec<u8>>,
    /// The digests of the packaged kernel images.
    kernels: &'a [Digest],
    /// Whether the grub package is installed.
    grub: bool,
    /// The release of the running kernel, where it is known.
    running: Option<String>,
}

/// Compares the EFI programs among `files` (everything under `/boot`)
/// with the packaged ones; `kernels` are the digests of the packaged
/// kernel images, for what is inside a UKI.
pub(super) fn compare(scope: &Scope<'_>, files: &[String], kernels: &[Digest], boot: &mut Boot) {
    let programs: Vec<&String> = files
        .iter()
        .filter(|path| read::has_extension(file_name(path), "efi"))
        .collect();
    if programs.is_empty() {
        return;
    }
    if programs.len() > MAX_PROGRAMS {
        not_checked(
            scope,
            boot,
            format!("/boot: more than {MAX_PROGRAMS} EFI programs; the rest were not compared"),
        );
    }
    let packaged = Packaged {
        programs: references(scope, PACKAGED),
        shells: references(scope, &[SHELLS]),
        stubs: stubs(scope),
        kernels,
        grub: scope
            .index
            .owner(GRUB_MODULES)
            .is_some_and(|owned| scope.index.package(owned) == "grub"),
        running: super::running_release(scope),
    };
    let mut packaged_kernels = 0;
    for path in programs.into_iter().take(MAX_PROGRAMS) {
        let found = collect::look(scope, Category::Boot, path, None);
        let mut item = collect::item_of(scope, Category::Boot, path.clone(), None, &found);
        let verdict = match &found {
            // Before what a package installed in `/boot` itself: a shell
            // there is a finding whoever put it there.
            Found::File { sha256, .. } if is_listed(&packaged.shells, *sha256) => Verdict::Shell,
            Found::File { .. } if matches!(item.tier, Tier::Vendor | Tier::UserBuilt) => {
                Verdict::Packaged
            }
            Found::File { sha256, .. } if is_listed(&packaged.programs, *sha256) => {
                Verdict::Packaged
            }
            Found::File { size, .. } if *size > MAX_PROGRAM_SIZE => {
                not_checked(
                    scope,
                    boot,
                    format!("/{path}: larger than {MAX_PROGRAM_SIZE} bytes; not compared"),
                );
                continue;
            }
            Found::File {
                sha256, size, head, ..
            } => match whole(&scope.root.join(path), *sha256, *size, head) {
                Ok(bytes) => verdict(path, &bytes, &packaged),
                Err(error) => {
                    unread(scope, boot, path, &error);
                    continue;
                }
            },
            Found::Link(target) => {
                link(scope, boot, path, target);
                continue;
            }
            Found::Other => continue,
            Found::Unreadable(_) => {
                unread(scope, boot, path, &open_error(&scope.root.join(path)));
                continue;
            }
        };
        match verdict {
            Verdict::Packaged => {}
            Verdict::PackagedKernel => packaged_kernels += 1,
            Verdict::NotComparable(_)
            | Verdict::StartedKernel
            | Verdict::Shell
            | Verdict::Unknown => {
                mark(&mut item, path, verdict);
                boot.items.push(item);
            }
        }
    }
    if packaged_kernels > 0 {
        boot.notes.push(format!(
            "{packaged_kernels} unified kernel image(s) in /boot: the stub and the kernel inside are what installed packages ship; the initramfs and command line inside are built on this machine and are not compared"
        ));
    }
}

/// Whether `sha256` is that of one of `references` as shipped.
fn is_listed(references: &[Reference], sha256: Digest) -> bool {
    references
        .iter()
        .any(|reference| reference.sha256 == sha256)
}

/// Puts on `item`, the program at `path`, what `verdict` says of it.
fn mark(item: &mut collect::Item, path: &str, verdict: Verdict) {
    let alert = match verdict {
        Verdict::Packaged | Verdict::PackagedKernel => return,
        Verdict::NotComparable(reason) => return item.notes.push(reason.into()),
        Verdict::Unknown if !is_started(path) => return item.notes.push(ELSEWHERE.into()),
        Verdict::StartedKernel => {
            "a unified kernel image this system starts, built around a kernel no installed kernel package ships"
        }
        Verdict::Shell => {
            "the UEFI shell, which a boot loader can start from any path and which runs startup.nsh and whatever is typed at the firmware's console"
        }
        Verdict::Unknown => {
            "not an EFI program any installed package ships, in a directory the boot loader starts from"
        }
    };
    item.alerts.push((RuleId::BootTampering, alert.into()));
}

/// Says what could not be checked: for root the sweep is incomplete, a
/// user's sweep says it in a note.
fn not_checked(scope: &Scope<'_>, boot: &mut Boot, sentence: String) {
    if scope.origin == Origin::Root {
        boot.unchecked.push(sentence);
    } else {
        boot.notes.push(sentence);
    }
}

/// Checks the link at `path`, named as an EFI program, with text `target`.
/// FAT, which an ESP is, has no links. One elsewhere in `/boot` that leads
/// to a `.efi` file in `/boot` needs no look: that file is compared as one
/// of its own. Any other target (out of `/boot`, nowhere, or a file not
/// named `.efi`, which is not compared) is not checked, and the sweep says
/// so.
fn link(scope: &Scope<'_>, boot: &mut Boot, path: &str, target: &str) {
    let lands = read::resolve_where(path, target, &|hop| read::plain_hop(scope.root, hop));
    let compared = lands.is_some_and(|lands| {
        lands.starts_with("boot/") && read::has_extension(file_name(&lands), "efi")
    });
    if !compared {
        not_checked(
            scope,
            boot,
            format!("/{path}: a link to a file that is not compared; not checked"),
        );
    }
}

/// Says that the program at `path` could not be read, for `error` (which
/// names the file): a user who may not read it leaves it to the root
/// checks, any other reason is said as it is.
fn unread(scope: &Scope<'_>, boot: &mut Boot, path: &str, error: &Error) {
    let denied = matches!(
        error,
        Error::Io { source, .. } if source.kind() == io::ErrorKind::PermissionDenied
    );
    if denied && scope.origin != Origin::Root {
        boot.notes.push(format!(
            "/{path} cannot be read as this user; the root checks compare it with the packaged EFI programs"
        ));
    } else {
        not_checked(scope, boot, format!("{error}; not compared"));
    }
}

/// Why the file at `path`, which `look` could not read, cannot be read:
/// opened again (without following a link or waiting on it) for an error
/// that says what kind of failure it is.
fn open_error(path: &Path) -> Error {
    match OpenOptions::new()
        .read(true)
        .custom_flags(O_NOFOLLOW | O_NONBLOCK)
        .open(path)
        .at(path)
    {
        Err(error) => error,
        Ok(_) => Error::Message(format!("{}: could not be read", path.display())),
    }
}

/// Whether `path` lies in a directory this system's boot loaders start
/// programs from.
fn is_started(path: &str) -> bool {
    let path = path.to_ascii_lowercase();
    STARTED.iter().any(|directory| path.starts_with(directory))
}

/// The packaged files `pattern` matches whose name ends in `extension`,
/// each with its digest and, where they could all be read, its bytes,
/// where it is still what its package shipped.
fn intact(scope: &Scope<'_>, pattern: &str, extension: &str) -> Vec<(Digest, Option<Vec<u8>>)> {
    read::matching(scope.root, pattern)
        .files
        .into_iter()
        .filter(|path| read::has_extension(file_name(path), extension))
        .filter_map(|path| {
            let found = collect::look(scope, Category::Boot, &path, None);
            let item = collect::item_of(scope, Category::Boot, path.clone(), None, &found);
            let Found::File {
                sha256, size, head, ..
            } = found
            else {
                return None;
            };
            if !matches!(item.tier, Tier::Vendor | Tier::UserBuilt) {
                return None;
            }
            // One that cannot be read whole is compared by its digest only,
            // so a program in `/boot` is the less likely to match it.
            let bytes = whole(&scope.root.join(&path), sha256, size, &head)
                .ok()
                .map(Cow::into_owned);
            Some((sha256, bytes))
        })
        .collect()
}

/// The packaged EFI programs `patterns` match that are still what their
/// packages shipped.
fn references(scope: &Scope<'_>, patterns: &[&str]) -> Vec<Reference> {
    patterns
        .iter()
        .flat_map(|pattern| intact(scope, pattern, "efi"))
        .map(|(sha256, bytes)| Reference {
            sha256,
            normalized: bytes.as_deref().and_then(pe::normalized),
        })
        .collect()
}

/// The packaged UKI stubs that are still what systemd shipped, whole.
fn stubs(scope: &Scope<'_>) -> Vec<Vec<u8>> {
    intact(scope, STUBS, "stub")
        .into_iter()
        .filter_map(|(_, bytes)| bytes)
        .collect()
}

/// Every byte of the file at `path`, which was looked at as `sha256`,
/// `size` bytes of which `head` holds the first: `head` itself when it
/// holds them all, otherwise read again and checked to be the same file
/// with the same content. `Err`, saying why, when that cannot be done.
fn whole<'a>(
    path: &Path,
    sha256: Digest,
    size: u64,
    head: &'a [u8],
) -> Result<Cow<'a, [u8]>, Error> {
    if head.len() as u64 == size {
        return Ok(Cow::Borrowed(head));
    }
    let refused = |reason: &str| Err(Error::Message(format!("{}: {reason}", path.display())));
    if size > MAX_PROGRAM_SIZE {
        return refused(&format!("larger than {MAX_PROGRAM_SIZE} bytes"));
    }
    // Checked before opening, so that a device or a pipe put in its place
    // is never opened.
    let before = fs::symlink_metadata(path).at(path)?;
    if !before.is_file() {
        return refused("not a regular file");
    }
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(O_NOFOLLOW | O_NONBLOCK)
        .open(path)
        .at(path)?;
    let opened = file.metadata().at(path)?;
    if !opened.is_file() || opened.ino() != before.ino() || opened.dev() != before.dev() {
        return refused("replaced while it was read");
    }
    let mut bytes = Vec::new();
    file.take(MAX_PROGRAM_SIZE + 1)
        .read_to_end(&mut bytes)
        .at(path)?;
    if Sha256::digest(&bytes) != sha256 {
        return refused("changed since it was hashed");
    }
    Ok(Cow::Owned(bytes))
}

/// What the program at `path` with content `bytes`, which is not a
/// packaged file as it is, was found to be against `packaged`.
fn verdict(path: &str, bytes: &[u8], packaged: &Packaged<'_>) -> Verdict {
    let Some(program) = pe::normalized(bytes) else {
        return Verdict::Unknown;
    };
    let is_one_of = |references: &[Reference]| {
        references.iter().any(|reference| {
            reference
                .normalized
                .as_deref()
                .is_some_and(|shipped| pe::is_same_program(&program, shipped))
        })
    };
    if is_one_of(&packaged.shells) {
        return Verdict::Shell;
    }
    if is_one_of(&packaged.programs) {
        return Verdict::Packaged;
    }
    if let Some(verdict) = unified(path, bytes, packaged) {
        return verdict;
    }
    if packaged.grub && file_name(path).to_ascii_lowercase().starts_with("grub") {
        return Verdict::NotComparable(GRUB);
    }
    Verdict::Unknown
}

/// What the program at `path` with content `bytes` is as a UKI, if it is
/// one (it holds a kernel).
fn unified(path: &str, bytes: &[u8], packaged: &Packaged<'_>) -> Option<Verdict> {
    let header = pe::header(bytes)?;
    let kernel = pe::section(bytes, &header, b".linux")?;
    if packaged.stubs.is_empty() {
        return Some(if is_started(path) {
            Verdict::Unknown
        } else {
            Verdict::NotComparable(NO_STUB)
        });
    }
    if !packaged
        .stubs
        .iter()
        .any(|stub| pe::is_built_from(bytes, stub))
    {
        return Some(Verdict::Unknown);
    }
    if packaged.kernels.contains(&Sha256::digest(kernel)) {
        return Some(Verdict::PackagedKernel);
    }
    // `.uname` is the release of the kernel inside, as `uname -r` gives it.
    let release = pe::section(bytes, &header, b".uname");
    let running = packaged
        .running
        .as_deref()
        .is_some_and(|running| release == Some(running.as_bytes()));
    Some(if running || is_started(path) {
        Verdict::StartedKernel
    } else {
        Verdict::NotComparable(OTHER_KERNEL)
    })
}

#[cfg(test)]
mod tests;
