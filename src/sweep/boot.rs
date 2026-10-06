//! What the machine was started with: the kernel's command line as it is
//! now, the kernel images in `/boot` against the ones the kernel packages
//! ship, and whether Secure Boot is on.
//!
//! The boot loader's configuration is reviewed as a file. A parameter
//! typed at the boot menu, or a kernel image swapped in `/boot`, is in no
//! file the sweep reviews, so both are compared here. `/boot` is usually
//! root's alone, so most of this is the root collector's to do. The EFI
//! programs (the boot loader itself) and what is inside the initramfs
//! image are not looked at.

use std::fs;

use super::collect::{self, Body, Item, Scope};
use super::read::{self, Found};
use super::tier::Tier;
use crate::autorun::Category;
use crate::paths::file_name;
use crate::rules::RuleId;
use crate::sha256::Sha256;

/// Kernel parameters that replace what starts first, open a root shell or
/// turn a defence off. One ending in `=` matches any value.
const WATCHED: &[&str] = &[
    "init=",
    "rdinit=",
    "systemd.unit=",
    "rd.systemd.unit=",
    "systemd.wants=",
    "systemd.mask=",
    "systemd.setenv=",
    "systemd.debug_shell",
    "systemd.debug-shell",
    "rd.systemd.debug_shell",
    "rd.break",
    "rd.shell",
    "emergency",
    "rescue",
    "single",
    "module.sig_enforce=0",
    "lockdown=none",
    "selinux=0",
    "apparmor=0",
    "enforcing=0",
    "security=none",
    "audit=0",
    "ima_appraise=off",
    "mitigations=off",
    "nokaslr",
];

/// Where a kernel command line is configured, relative to the root: what
/// the sweep reviews as files, and the other boot loaders' own.
const CONFIGURED: &[&str] = &[
    "boot/limine.conf",
    "boot/limine/limine.conf",
    "boot/EFI/limine/limine.conf",
    "etc/default/limine",
    "etc/kernel/cmdline",
    "etc/default/grub",
    "boot/grub/grub.cfg",
    "boot/loader/loader.conf",
];
/// Directories of boot entries, one file each.
const CONFIGURED_DIRECTORIES: &[&str] = &["boot/loader/entries", "etc/cmdline.d"];

/// The running kernel's command line, relative to the root.
const COMMAND_LINE: &str = "proc/cmdline";

/// The most kernel images compared.
const MAX_IMAGES: usize = 32;

/// What the boot checks found.
#[derive(Debug, Default)]
pub(super) struct Boot {
    pub(super) items: Vec<Item>,
    /// What is said of the system as a whole.
    pub(super) notes: Vec<String>,
    /// What could not be checked, as sentences: the sweep is incomplete.
    pub(super) unchecked: Vec<String>,
}

/// The watched parameters of the command line `running` that none of the
/// `configured` texts holds as a word.
fn unconfigured(running: &str, configured: &[String]) -> Vec<String> {
    let known = |parameter: &str| {
        configured.iter().any(|text| {
            text.split(|c: char| c.is_whitespace() || matches!(c, '"' | '\''))
                .any(|word| word == parameter)
        })
    };
    running
        .split_whitespace()
        .filter(|parameter| {
            WATCHED.iter().any(|watched| {
                if watched.ends_with('=') {
                    parameter.starts_with(watched)
                } else {
                    parameter == watched
                }
            })
        })
        .filter(|parameter| !known(parameter))
        .map(str::to_string)
        .collect()
}

/// The text of the file at `path`, as `scope` may read it: `Ok(None)` when
/// it is not there, `Err` when it is and cannot be read.
fn text(scope: &Scope<'_>, path: &str) -> Result<Option<String>, ()> {
    match fs::symlink_metadata(scope.root.join(path)) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        // A directory on the way that cannot be entered (`/boot`).
        Err(_) => return Err(()),
        Ok(_) => {}
    }
    match collect::look(scope, Category::Boot, path, None) {
        Found::File { head, .. } => Ok(Some(String::from_utf8_lossy(&head).into_owned())),
        Found::Link(_) | Found::Other => Ok(None),
        Found::Unreadable(_) => Err(()),
    }
}

fn command_line(scope: &Scope<'_>, boot: &mut Boot) {
    let Ok(running) = fs::read_to_string(scope.root.join(COMMAND_LINE)) else {
        return;
    };
    let mut configured = Vec::new();
    let mut unread = false;
    let paths = CONFIGURED.iter().map(|path| (*path).to_string()).chain(
        CONFIGURED_DIRECTORIES
            .iter()
            .flat_map(|directory| read::entries(scope.root, directory).files),
    );
    for path in paths {
        match text(scope, &path) {
            Ok(Some(text)) => configured.push(text),
            Ok(None) => {}
            Err(()) => unread = true,
        }
    }
    let odd = unconfigured(&running, &configured);
    if odd.is_empty() {
        return;
    }
    // Without the whole configuration there is nothing to say a parameter
    // is not in it; root's checks read it all.
    if unread {
        boot.notes.push(format!(
            "the kernel was started with {}; the boot configuration cannot be read as this user to see whether it says so (the root checks compare them)",
            odd.join(" ")
        ));
        return;
    }
    let running = running.trim().to_string();
    boot.items.push(Item {
        file: None,
        origin: scope.origin,
        category: Category::Boot,
        path: COMMAND_LINE.into(),
        tier: Tier::Unknown,
        sha256: Some(Sha256::digest(running.as_bytes())),
        body: Body::Text(running),
        runs: Vec::new(),
        run_by: None,
        notes: vec!["the command line the running kernel was started with".into()],
        alerts: vec![(
            RuleId::BootTampering,
            format!(
                "started with {}, which the boot configuration does not hold",
                odd.join(" ")
            ),
        )],
    });
}

/// The kernel images under `/boot`, as paths relative to the root: files
/// whose name starts with `vmlinuz`, up to three directories down (Limine's
/// entry tool keeps them in a directory for each machine and kernel); and
/// whether there were more than are compared. `Err` when `/boot` cannot be
/// listed.
fn images(scope: &Scope<'_>) -> Result<(Vec<String>, bool), ()> {
    match fs::read_dir(scope.root.join("boot")) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return Ok((Vec::new(), false));
        }
        Err(_) => return Err(()),
        Ok(_) => {}
    }
    let listing = read::entries(scope.root, "boot");
    if !listing.unreadable.is_empty() {
        return Err(());
    }
    let mut images: Vec<String> = listing
        .files
        .into_iter()
        .filter(|path| {
            path.matches('/').count() <= 4
                && path
                    .rsplit('/')
                    .next()
                    .is_some_and(|name| name.starts_with("vmlinuz"))
        })
        .collect();
    let more = images.len() > MAX_IMAGES;
    images.truncate(MAX_IMAGES);
    Ok((images, more))
}

/// The release a kernel image says it is (`6.12.1-arch1-1`), from the
/// header every Linux image for x86 starts with: the text its setup code
/// points at, up to the first blank. `None` for anything else.
fn image_release(head: &[u8]) -> Option<String> {
    if head.get(0x202..0x206)? != b"HdrS" {
        return None;
    }
    let pointer = u16::from_le_bytes([*head.get(0x20e)?, *head.get(0x20f)?]);
    let text = head.get(usize::from(pointer) + 0x200..)?;
    let end = text
        .iter()
        .take(128)
        .position(|byte| *byte == 0 || *byte == b' ')?;
    let release = std::str::from_utf8(&text[..end]).ok()?;
    (!release.is_empty()).then(|| release.to_string())
}

/// The names the installed kernel packages' images go by in `/boot`
/// (`vmlinuz-linux` for the package whose `pkgbase` is `linux`): what the
/// default boot entries start.
fn default_names(scope: &Scope<'_>) -> Vec<String> {
    read::matching(scope.root, "usr/lib/modules/*/pkgbase")
        .files
        .into_iter()
        .filter_map(|path| fs::read_to_string(scope.root.join(path)).ok())
        .map(|base| format!("vmlinuz-{}", base.trim()))
        .collect()
}

/// Whether the image at `path`, which is not what any installed kernel
/// package ships, is one the machine starts by default or runs now: it
/// goes by an installed kernel package's name, or says it is the release
/// that is running. Any other is most likely an older kernel kept for a
/// snapshot's boot entry (Limine with snapper keeps those after every
/// kernel update), which no installed package can vouch for any more.
fn is_started(scope: &Scope<'_>, path: &str, defaults: &[String]) -> bool {
    let name = file_name(path);
    if defaults.iter().any(|default| default == name) {
        return true;
    }
    let running = fs::read_to_string(scope.root.join("proc/sys/kernel/osrelease"))
        .map(|release| release.trim().to_string())
        .unwrap_or_default();
    match collect::look(scope, Category::Boot, path, None) {
        Found::File { head, .. } => {
            image_release(&head).is_some_and(|release| !running.is_empty() && release == running)
        }
        _ => false,
    }
}

fn kernel_images(scope: &Scope<'_>, boot: &mut Boot) {
    let as_root = scope.origin == collect::Origin::Root;
    let Ok((images, more)) = images(scope) else {
        if as_root {
            boot.unchecked
                .push("/boot: could not be listed; the kernel images were not compared".into());
        } else {
            boot.notes.push(
                "the kernel images in /boot cannot be read as this user; the root checks compare them with the packaged ones".into(),
            );
        }
        return;
    };
    if images.is_empty() {
        return;
    }
    if more {
        let sentence =
            format!("/boot: more than {MAX_IMAGES} kernel images; the rest were not compared");
        if as_root {
            boot.unchecked.push(sentence);
        } else {
            boot.notes.push(sentence);
        }
    }
    let defaults = default_names(scope);
    // What the kernel packages ship, where it is still what they shipped.
    let shipped: Vec<_> = read::matching(scope.root, "usr/lib/modules/*/vmlinuz")
        .files
        .into_iter()
        .filter_map(|path| {
            let item = collect::item(scope, Category::Boot, path, None);
            matches!(item.tier, Tier::Vendor | Tier::UserBuilt)
                .then_some(item.sha256)
                .flatten()
        })
        .collect();
    for path in images {
        let mut item = collect::item(scope, Category::Boot, path, None);
        match (&item.body, item.sha256) {
            (Body::Link(_), _) => {}
            (_, Some(digest)) if shipped.contains(&digest) => {}
            (_, Some(_)) if is_started(scope, &item.path, &defaults) => {
                item.alerts.push((
                    RuleId::BootTampering,
                    "not the kernel image any installed kernel package ships".into(),
                ));
                boot.items.push(item);
            }
            (_, Some(_)) => {
                item.notes.push(
                    "a kernel image no installed kernel package ships: an older kernel kept for a snapshot's boot entry, or one put there"
                        .into(),
                );
                boot.items.push(item);
            }
            (_, None) if as_root => boot
                .unchecked
                .push(format!("/{}: could not be read; not compared", item.path)),
            (_, None) => boot.notes.push(format!(
                "/{} cannot be read as this user; the root checks compare it with the packaged kernel",
                item.path
            )),
        }
    }
}

/// Whether Secure Boot is on, from the firmware's variable: four bytes of
/// attributes, then 1 for on.
fn secure_boot(scope: &Scope<'_>, boot: &mut Boot) {
    let variables = scope.root.join("sys/firmware/efi/efivars");
    let Ok(entries) = fs::read_dir(&variables) else {
        return;
    };
    let Some(variable) = entries.flatten().find(|entry| {
        entry
            .file_name()
            .to_string_lossy()
            .starts_with("SecureBoot-")
    }) else {
        return;
    };
    match fs::read(variable.path())
        .ok()
        .and_then(|bytes| bytes.get(4).copied())
    {
        Some(1) => boot.notes.push("Secure Boot is on".into()),
        Some(_) => boot.notes.push(
            "Secure Boot is off: the firmware starts any boot loader and kernel put on the disk"
                .into(),
        ),
        None => {}
    }
}

/// Runs the boot checks against `scope`.
pub(super) fn check(scope: &Scope<'_>) -> Boot {
    let mut boot = Boot::default();
    command_line(scope, &mut boot);
    kernel_images(scope, &mut boot);
    secure_boot(scope, &mut boot);
    boot
}

#[cfg(test)]
mod tests {
    use std::collections::HashSet;
    use std::fs;

    use super::{check, unconfigured};
    use crate::rules::RuleId;
    use crate::sha256::Sha256;
    use crate::sweep::collect::{Origin, Scope};
    use crate::sweep::index::PackageIndex;
    use crate::test_support::TempDir;

    #[test]
    fn only_watched_parameters_the_configuration_does_not_hold_are_told() {
        let configured = vec![
            "KERNEL_CMDLINE[default]=\"quiet splash mitigations=off root=/dev/mapper/root\"\n"
                .to_string(),
        ];
        assert!(
            unconfigured(
                "root=/dev/mapper/root quiet mitigations=off rw",
                &configured
            )
            .is_empty()
        );
        assert_eq!(
            unconfigured(
                "quiet init=/bin/sh rd.break module.sig_enforce=0 lockdown=none apparmor=0 selinux=0 systemd.unit=rescue.target module.sig_enforce=1",
                &configured
            ),
            [
                "init=/bin/sh",
                "rd.break",
                "module.sig_enforce=0",
                "lockdown=none",
                "apparmor=0",
                "selinux=0",
                "systemd.unit=rescue.target"
            ]
        );
        // The same parameter with another value is not the configured one.
        assert_eq!(
            unconfigured(
                "init=/tmp/x",
                &["cmdline: init=/usr/lib/systemd/systemd".to_string()]
            ),
            ["init=/tmp/x"]
        );
    }

    #[test]
    fn the_command_line_and_the_kernel_images_are_compared() {
        let dir = TempDir::new("sweep-boot");
        let root = dir.path();
        let write = |path: &str, text: &str| {
            fs::create_dir_all(root.join(path).parent().unwrap()).unwrap();
            fs::write(root.join(path), text).unwrap();
        };
        write("proc/cmdline", "root=/dev/x quiet init=/bin/sh\n");
        write("boot/limine.conf", "cmdline: root=/dev/x quiet\n");
        write("usr/lib/modules/6.1-arch/vmlinuz", "kernel");
        write("usr/lib/modules/6.1-arch/pkgbase", "linux\n");
        write("boot/vmlinuz-linux", "kernel");
        write("boot/abc/linux/vmlinuz-linux", "another kernel");
        // An older kernel kept for a snapshot's entry, and an image under
        // any name that says it is the kernel now running.
        write("boot/abc/old/vmlinuz-6.0-old", "an older kernel");
        let mut running = vec![0_u8; 0x300];
        running[0x202..0x206].copy_from_slice(b"HdrS");
        running[0x20e..0x210].copy_from_slice(&0x80_u16.to_le_bytes());
        running[0x280..0x28f].copy_from_slice(b"6.1-arch (x@y) ");
        assert_eq!(super::image_release(&running).as_deref(), Some("6.1-arch"));
        assert_eq!(super::image_release(b"another kernel"), None);
        fs::write(root.join("boot/abc/old/vmlinuz-snapshot"), &running).unwrap();
        write("proc/sys/kernel/osrelease", "6.1-arch\n");
        write("boot/initramfs-linux.img", "not compared");
        write(
            "sys/firmware/efi/efivars/SecureBoot-8be4df61",
            "\u{6}\0\0\0\0",
        );
        let mut index = PackageIndex::with_foreign(HashSet::new());
        index.add_for_test(
            "linux",
            &format!(
                "#mtree\n./usr/lib/modules/6.1-arch/vmlinuz type=file mode=644 sha256digest={}\n",
                Sha256::digest(b"kernel")
            ),
            &[],
        );
        let scope = Scope {
            root,
            home: None,
            index: &index,
            origin: Origin::System,
        };
        let boot = check(&scope);
        let found: Vec<(&str, RuleId)> = boot
            .items
            .iter()
            .filter(|item| !item.alerts.is_empty())
            .map(|item| (item.path.as_str(), item.alerts[0].0))
            .collect();
        assert_eq!(
            found,
            [
                ("proc/cmdline", RuleId::BootTampering),
                ("boot/abc/linux/vmlinuz-linux", RuleId::BootTampering),
                ("boot/abc/old/vmlinuz-snapshot", RuleId::BootTampering),
            ]
        );
        // The older kernel is listed, with a note and no alert.
        let old = boot
            .items
            .iter()
            .find(|item| item.path == "boot/abc/old/vmlinuz-6.0-old")
            .unwrap();
        assert!(old.alerts.is_empty() && old.notes[0].starts_with("a kernel image no installed"));
        for kept in [
            "boot/abc/old/vmlinuz-6.0-old",
            "boot/abc/old/vmlinuz-snapshot",
        ] {
            fs::remove_file(root.join(kept)).unwrap();
        }
        assert!(boot.items[0].alerts[0].1.contains("init=/bin/sh"));
        assert_eq!(boot.notes.len(), 1);
        assert!(boot.notes[0].starts_with("Secure Boot is off"));
        assert!(boot.unchecked.is_empty());

        // What the configuration holds is no finding, and a packaged image
        // that was changed vouches for nothing.
        write(
            "boot/limine.conf",
            "cmdline: root=/dev/x quiet init=/bin/sh\n",
        );
        write("usr/lib/modules/6.1-arch/vmlinuz", "patched");
        write("boot/vmlinuz-linux", "patched");
        write(
            "sys/firmware/efi/efivars/SecureBoot-8be4df61",
            "\u{6}\0\0\0\u{1}",
        );
        let boot = check(&scope);
        let paths: Vec<&str> = boot.items.iter().map(|item| item.path.as_str()).collect();
        assert_eq!(
            paths,
            ["boot/abc/linux/vmlinuz-linux", "boot/vmlinuz-linux"]
        );
        assert_eq!(boot.notes, ["Secure Boot is on"]);
    }

    #[test]
    fn more_kernel_images_than_are_compared_is_said() {
        let dir = TempDir::new("sweep-boot-many");
        let root = dir.path();
        let write = |path: &str, text: &str| {
            fs::create_dir_all(root.join(path).parent().unwrap()).unwrap();
            fs::write(root.join(path), text).unwrap();
        };
        let index = PackageIndex::with_foreign(HashSet::new());
        let scope = Scope {
            root,
            home: None,
            index: &index,
            origin: Origin::System,
        };
        for number in 0..=super::MAX_IMAGES {
            write(&format!("boot/many/vmlinuz-{number:02}"), "kernel");
        }
        // Said, and for root not checked.
        let boot = check(&scope);
        assert!(
            boot.notes
                .iter()
                .any(|note| note.starts_with("/boot: more than 32 kernel images")),
            "{:?}",
            boot.notes
        );
        assert!(boot.unchecked.is_empty());
        let as_root = check(&Scope {
            origin: Origin::Root,
            ..scope
        });
        assert_eq!(
            as_root.unchecked,
            ["/boot: more than 32 kernel images; the rest were not compared"]
        );
    }
}
