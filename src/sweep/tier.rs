//! How far an installed file can be trusted, from what pacman recorded.

use super::index::{PackageIndex, Recorded};
use crate::integrations::SESSION_ENV;
use crate::sha256::{Digest, Sha256};

/// From most to least trusted. The sweep hides the first two.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Tier {
    /// What a package from a configured repository installed, unchanged.
    Vendor,
    /// Does nothing: a link to `/dev/null` (a masked unit) or an empty file.
    Inert,
    /// Not installed as this file, but identical to a file a repository
    /// package ships (Omarchy copies its `etc-overrides` into `/etc`).
    Copied,
    /// What a package from no configured repository (AUR, `pacman -U`)
    /// installed, unchanged.
    UserBuilt,
    /// A package's configuration file (`backup=`) that was edited, as such
    /// files are meant to be.
    Edited,
    /// A package's file whose content, mode or link target is not what the
    /// package installed.
    Modified,
    /// Not vouched for by a package, but the user allowed it as it is
    /// (`sweep allow`).
    Allowed,
    /// No package installed it.
    Unknown,
}

impl Tier {
    pub const ALL: [Self; 8] = [
        Self::Vendor,
        Self::Inert,
        Self::Copied,
        Self::UserBuilt,
        Self::Edited,
        Self::Modified,
        Self::Allowed,
        Self::Unknown,
    ];

    /// A stable machine name.
    pub const fn name(self) -> &'static str {
        match self {
            Self::Vendor => "package",
            Self::Inert => "inert",
            Self::Copied => "copy",
            Self::UserBuilt => "user-built",
            Self::Edited => "edited",
            Self::Modified => "modified",
            Self::Allowed => "allowed",
            Self::Unknown => "unknown",
        }
    }

    pub fn from_name(name: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|tier| tier.name() == name)
    }
}

/// What is on disk at a path.
#[derive(Clone, Copy, Debug)]
pub enum Observed<'a> {
    File {
        sha256: &'a Digest,
        /// Permission bits including set-id bits.
        mode: u32,
        size: u64,
        /// Every byte of it, when it is small enough to have been kept:
        /// what a script's changed first line is told by (see
        /// `only_interpreter_line_changed`).
        content: Option<&'a [u8]>,
    },
    Link {
        target: &'a str,
        /// The tier of what the link points at, when it resolves to a file
        /// the sweep classified (an enabled unit's link to its unit).
        resolved: Option<Tier>,
        /// What it points at declares the link's name as an alias (a unit's
        /// `Alias=display-manager.service`).
        alias: bool,
    },
}

/// The mode bits a change of matters: set-id bits, and write access for
/// group and others. Execute bits change harmlessly, and so does a read
/// bit that was added (a package's own install step may relax them); a
/// read bit taken away is told by `is_closed`.
const SECURITY_BITS: u32 = 0o6022;

/// Read access for everyone.
const WORLD_READ: u32 = 0o004;

/// Whether the file at `path`, of mode `actual`, is one its package
/// installs readable by everyone and that no longer is. Nothing a package
/// does closes its own programs afterwards, and a closed one cannot be
/// compared with its package by anyone but root: that is how a changed
/// program would be kept from the comparison. A configuration file
/// (`backup=`) is left out: closing one that holds a password is the
/// administrator's good sense.
pub fn is_closed(path: &str, actual: u32, index: &PackageIndex) -> bool {
    index.owner(path).is_some_and(|owned| {
        !owned.backup
            && matches!(owned.recorded, Recorded::File { mode, .. }
                if mode & WORLD_READ != 0 && actual & WORLD_READ == 0)
    })
}

/// The tier of `path` (relative to `/`).
pub fn classify(path: &str, observed: Observed<'_>, index: &PackageIndex) -> Tier {
    // Guardian itself is installed with `pacman -U`, so it is foreign; the
    // files it ships, unchanged, are as trusted as the sweep that reads them.
    let packaged = |index: &PackageIndex, package: &str| {
        if index.is_foreign(package) && !(package == GUARDIAN && is_guardians_own(path, observed)) {
            Tier::UserBuilt
        } else {
            Tier::Vendor
        }
    };
    if let Some(owned) = index.owner(path) {
        let package = index.package(owned);
        let unchanged = match (&owned.recorded, observed) {
            (
                Recorded::File {
                    mode,
                    sha256: Some(recorded),
                },
                Observed::File {
                    sha256,
                    mode: actual,
                    ..
                },
            ) => {
                recorded == sha256
                    && *mode & SECURITY_BITS == actual & SECURITY_BITS
                    && !is_closed(path, actual, index)
            }
            (Recorded::Link(recorded), Observed::Link { target, .. }) => recorded == target,
            _ => false,
        };
        return match observed {
            _ if unchanged => packaged(index, package),
            Observed::File { sha256, .. } if owned.backup => {
                if index.copy_of(sha256, path).is_some() {
                    Tier::Copied
                } else {
                    Tier::Edited
                }
            }
            // Omarchy rewrites the first line of the packaged
            // `powerprofilesctl` on every install. Proven from the content,
            // not excused by the path: shown as edited, with a note, and
            // read no more than any other file its package installed (see
            // `collect::item_of`).
            Observed::File {
                mode,
                content: Some(content),
                ..
            } if only_interpreter_line_changed(&owned.recorded, mode, content, index) => {
                Tier::Edited
            }
            Observed::File { .. } | Observed::Link { .. } => Tier::Modified,
        };
    }
    let name = path.rsplit('/').next().unwrap_or(path);
    match observed {
        // A mask (an empty file, a link to /dev/null) disables what it
        // names; disabling a defence, or a pacman hook a package ships, is
        // worth seeing.
        Observed::File { size: 0, .. }
        | Observed::Link {
            target: "/dev/null",
            ..
        } if !masks_a_defence(path, name, index) => Tier::Inert,
        // A link no package made (`systemctl enable`) to a packaged unit of
        // the same name is as trusted as that unit. A link under another
        // name (a packaged script linked in as a profile script) is not, nor
        // is enabling a unit that opens a root shell.
        Observed::Link {
            target,
            resolved: Some(tier @ (Tier::Vendor | Tier::UserBuilt | Tier::Inert)),
            alias,
        } if (alias || same_unit(name, target))
            && enables_a_unit(path, target)
            && !ROOT_SHELL_UNITS.contains(&name) =>
        {
            tier
        }
        // What `protect` writes into the home, byte for byte: Guardian's
        // own, like the files its package ships.
        Observed::File {
            content: Some(content),
            mode,
            ..
        } if mode & 0o6000 == 0 && is_guardians_session_file(path, content) => Tier::Vendor,
        Observed::File { sha256, .. } if index.copy_of(sha256, path).is_some() => Tier::Copied,
        Observed::File { .. } | Observed::Link { .. } => Tier::Unknown,
    }
}

/// Where `protect` puts the file uwsm reads for the graphical session, in
/// a home's configuration, and every byte of it (`SESSION_ENV`, the
/// one constant `integrations` writes it from). It puts the
/// directory of Guardian's wrappers, root's own, first on `PATH` and does
/// nothing else, so a file with exactly this content is no more to review
/// than the package's files, whoever wrote it.
const SESSION_FILE: &str = "/.config/uwsm/env.d/90-omarchy-guardian";

/// What the note on such an item says.
const SESSION_NOTE: &str = "Guardian's own: written by `omarchy-guardian protect`, unchanged";

fn is_guardians_session_file(path: &str, content: &[u8]) -> bool {
    path.ends_with(SESSION_FILE) && content == SESSION_ENV.as_bytes()
}

/// The note for an item of tier `tier` at `path` that is the file
/// `protect` wrote (no package owns it, and it is trusted all the same).
pub fn session_note(path: &str, tier: Tier, index: &PackageIndex) -> Option<&'static str> {
    (tier == Tier::Vendor && path.ends_with(SESSION_FILE) && index.owner(path).is_none())
        .then_some(SESSION_NOTE)
}

/// The newest `python3.N` a package's script may have named.
const MAX_PYTHON_MINOR: u32 = 40;

/// What the note on such an item says (see `interpreter_note`).
const INTERPRETER_NOTE: &str =
    "its package's content, with only the first line (the interpreter) changed";

/// The note for an item of tier `tier` at `path` whose first line alone was
/// changed: an edited file that is not one of its package's configuration
/// files.
pub fn interpreter_note(path: &str, tier: Tier, index: &PackageIndex) -> Option<&'static str> {
    (tier == Tier::Edited && index.owner(path).is_some_and(|owned| !owned.backup))
        .then_some(INTERPRETER_NOTE)
}

/// Whether `note` is the one `interpreter_note` gives.
pub fn is_interpreter_note(note: &str) -> bool {
    note == INTERPRETER_NOTE
}

/// The program a `#!` line runs when it names one in the system's program
/// directory and nothing else: `python3` for `#!/bin/python3` and for
/// `#!/usr/bin/python3` (`/bin` is `/usr/bin`). `None` for a line with
/// arguments, with `env`, or with a program anywhere else.
fn system_interpreter(line: &[u8]) -> Option<&str> {
    let line = std::str::from_utf8(line).ok()?.strip_prefix("#!")?;
    let name = line
        .strip_prefix("/usr/bin/")
        .or_else(|| line.strip_prefix("/bin/"))?;
    let plain = !name.is_empty()
        && name != "env"
        && name
            .chars()
            .all(|character| character.is_ascii_alphanumeric() || "._+-".contains(character));
    plain.then_some(name)
}

/// The names one interpreter goes by: Python's are `python`, `python3` and
/// `python3.N`; any other has its own alone.
fn interpreter_names(name: &str) -> Vec<String> {
    let python = name == "python"
        || name.strip_prefix("python3").is_some_and(|rest| {
            rest.is_empty()
                || rest.strip_prefix('.').is_some_and(|minor| {
                    !minor.is_empty() && minor.chars().all(|digit| digit.is_ascii_digit())
                })
        });
    if !python {
        return vec![name.to_string()];
    }
    let mut names = vec!["python3".to_string(), "python".to_string()];
    names.extend((0..=MAX_PYTHON_MINOR).map(|minor| format!("python3.{minor}")));
    names
}

/// Whether `content`, which is not what `recorded` says the package
/// installed, is that file with nothing but its interpreter line written
/// another way. The first line must name a program in `/usr/bin` that a
/// repository package installed, and putting one of the lines the package
/// could have shipped for that same interpreter in its place must give
/// exactly the content the package recorded. Everything after the first
/// line is then the package's, byte for byte, and the first line runs the
/// interpreter the package meant, from the system's own directory. A line
/// that names another interpreter, passes arguments or points anywhere
/// else is not accepted, and neither is a changed mode.
fn only_interpreter_line_changed(
    recorded: &Recorded,
    mode: u32,
    content: &[u8],
    index: &PackageIndex,
) -> bool {
    let Recorded::File {
        mode: packaged_mode,
        sha256: Some(packaged),
    } = recorded
    else {
        return false;
    };
    if packaged_mode & SECURITY_BITS != mode & SECURITY_BITS {
        return false;
    }
    let Some(end) = content.iter().position(|byte| *byte == b'\n') else {
        return false;
    };
    let (line, rest) = content.split_at(end);
    let Some(name) = system_interpreter(line) else {
        return false;
    };
    let from_a_repository = index
        .owner(&format!("usr/bin/{name}"))
        .is_some_and(|owned| !index.is_foreign(index.package(owned)));
    if !from_a_repository {
        return false;
    }
    interpreter_names(name).iter().any(|name| {
        [
            format!("#!/usr/bin/env {name}"),
            format!("#!/usr/bin/{name}"),
            format!("#!/bin/{name}"),
        ]
        .iter()
        .filter(|shipped| shipped.as_bytes() != line)
        .any(|shipped| {
            let mut hasher = Sha256::new();
            hasher.update(shipped.as_bytes());
            hasher.update(rest);
            hasher.finalize() == *packaged
        })
    })
}

const GUARDIAN: &str = "omarchy-guardian";

/// What the omarchy-guardian package ships (`packaging/arch/PKGBUILD`).
const GUARDIANS_OWN: &[&str] = &[
    "usr/bin/omarchy-guardian",
    "usr/lib/omarchy-guardian/",
    // The hook pacman always loads; it reviews only once root turned it on.
    "usr/share/libalpm/hooks/omarchy-guardian.hook",
    "usr/share/omarchy-guardian/",
    "usr/share/doc/omarchy-guardian/",
    "usr/share/licenses/omarchy-guardian/",
    "usr/lib/systemd/user/omarchy-guardian-sweep.service",
    "usr/lib/systemd/user/omarchy-guardian-sweep.timer",
    "usr/lib/systemd/system/omarchy-guardian-sweep-collect.service",
    "usr/lib/systemd/system/omarchy-guardian-sweep-collect.timer",
    "usr/share/applications/omarchy-guardian.desktop",
    "usr/share/applications/omarchy-guardian-ask.desktop",
    "usr/share/icons/hicolor/scalable/apps/omarchy-guardian.svg",
    "usr/share/icons/hicolor/scalable/apps/omarchy-guardian-alert.svg",
    "usr/share/icons/hicolor/scalable/apps/omarchy-guardian-off.svg",
];

/// Whether `path` is one Guardian ships, and not set-id: a package that
/// merely takes Guardian's name gets no trust for anything else.
fn is_guardians_own(path: &str, observed: Observed<'_>) -> bool {
    let set_id = matches!(observed, Observed::File { mode, .. } if mode & 0o6000 != 0);
    !set_id
        && GUARDIANS_OWN.iter().any(|own| {
            if own.ends_with('/') {
                path.starts_with(own)
            } else {
                path == *own
            }
        })
}

/// Packaged units that give a root shell without a password when enabled.
const ROOT_SHELL_UNITS: &[&str] = &["debug-shell.service", "emergency.service", "rescue.service"];

/// Units whose mask turns off a defence: firewalls, access control and
/// auditing, malware and intrusion scanners, what blocks repeated logins,
/// the journal, the snapshots a rollback needs, and Guardian's own. A name
/// stands for itself and for the units that start with it and a dash
/// (`clamav-daemon`, `snapper-timeline.timer`). `systemd-resolved` and
/// `systemd-coredump` are left out: masking them is common and harmless.
const DEFENCES: &[&str] = &[
    "ufw",
    "firewalld",
    "nftables",
    "iptables",
    "ip6tables",
    "opensnitchd",
    "apparmor",
    "auditd",
    "audit-rules",
    "usbguard",
    "fail2ban",
    "sshguard",
    "crowdsec",
    "clamav",
    "aide",
    "aidecheck",
    "rkhunter",
    "snapper",
    "grub-btrfsd",
    "limine-snapper-sync",
    "btrfs-scrub",
    "systemd-journald",
    "omarchy-guardian",
];

fn masks_a_defence(path: &str, name: &str, index: &PackageIndex) -> bool {
    let unit = name.split('.').next().unwrap_or(name);
    let unit = unit.split('@').next().unwrap_or(unit);
    DEFENCES
        .iter()
        .any(|defence| unit == *defence || unit.starts_with(&format!("{defence}-")))
        || (path.starts_with("etc/pacman.d/hooks/")
            && index
                .owner(&format!("usr/share/libalpm/hooks/{name}"))
                .is_some())
}

/// Whether a link at `path` to `target` is one that enables what a
/// package ships to be enabled that way: a unit in a systemd directory or
/// a hook in pacman's, and nothing that is documentation or an example (a
/// packaged sample linked in under the same name is not something a
/// package means to run).
fn enables_a_unit(path: &str, target: &str) -> bool {
    // A unit directory, not any directory of systemd's: what sits among
    // its generators or sleep hooks is run as a program.
    let extension = std::path::Path::new(target)
        .extension()
        .and_then(|extension| extension.to_str())
        .unwrap_or_default();
    // A drop-in directory (`x.service.d/`) holds settings, not units.
    let drop_in = path.rsplit_once('/').is_some_and(|(directory, _)| {
        std::path::Path::new(directory)
            .extension()
            .is_some_and(|extension| extension == "d")
    });
    let unit = (path.contains("/systemd/system/") || path.contains("/systemd/user/"))
        && !drop_in
        && UNIT_EXTENSIONS.contains(&extension);
    let hook = path.starts_with("etc/pacman.d/hooks/")
        && std::path::Path::new(target)
            .extension()
            .is_some_and(|extension| extension == "hook");
    // A packaged launcher linked into autostart, or a packaged program
    // linked under its own name where the user's programs are.
    let launcher = path.contains("/autostart/")
        && std::path::Path::new(target)
            .extension()
            .is_some_and(|extension| extension == "desktop");
    let program = (path.contains("/.local/bin/") || path.contains("/.cargo/bin/"))
        && (target.starts_with("/usr/bin/") || target.starts_with("/usr/lib/"));
    // Named in full under a directory only root writes, so the text says
    // where the link leads: not through `..` or another link of the
    // user's.
    let plain = ["/usr/", "/etc/", "/opt/"]
        .iter()
        .any(|root| target.starts_with(root))
        && target.split('/').all(|part| part != ".." && part != ".");
    (unit || hook || launcher || program)
        && plain
        && !["/doc/", "/docs/", "/examples/", "/example/", "/samples/"]
            .iter()
            .any(|sample| target.contains(sample))
}

/// What systemd reads as a unit.
const UNIT_EXTENSIONS: &[&str] = &[
    "service",
    "socket",
    "timer",
    "target",
    "path",
    "mount",
    "automount",
    "swap",
    "slice",
    "device",
    "scope",
];

/// Whether link `name` enables the unit at `target`: the same name, or an
/// instance (`getty@tty1.service`) of a template (`getty@.service`).
fn same_unit(name: &str, target: &str) -> bool {
    let target_name = target.rsplit('/').next().unwrap_or(target);
    if name == target_name {
        return true;
    }
    match (name.split_once('@'), target_name.split_once('@')) {
        (Some((prefix, instance)), Some((template, suffix))) => {
            prefix == template
                && suffix.starts_with('.')
                && instance
                    .rsplit_once('.')
                    .is_some_and(|(_, extension)| suffix == format!(".{extension}"))
        }
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashSet;

    use super::{Observed, Tier, classify};
    use crate::sha256::Sha256;
    use crate::sweep::index::PackageIndex;

    fn index() -> PackageIndex {
        let abc = Sha256::digest(b"abc");
        let copy = Sha256::digest(b"override");
        let example = Sha256::digest(b"example");
        let mtree = format!(
            "#mtree\n/set type=file mode=644\n./usr/bin/demo mode=755 sha256digest={abc}\n./usr/bin/su mode=4755 sha256digest={abc}\n./usr/lib/x.so type=link link=x.so.1\n./etc/demo.conf sha256digest={abc}\n./usr/share/demo/demo.conf sha256digest={copy}\n./usr/share/doc/demo/examples/sudoers sha256digest={example}\n./usr/lib/systemd/system/debug-shell.service sha256digest={abc}\n./usr/lib/systemd/system/sshd.service sha256digest={abc}\n./usr/share/libalpm/hooks/demo.hook sha256digest={abc}\n"
        );
        let mut index = PackageIndex::with_foreign(HashSet::from(["aur-thing".to_string()]));
        index.add_for_test("demo", &mtree, &["etc/demo.conf"]);
        index.add_for_test(
            "aur-thing",
            &format!("#mtree\n./usr/bin/aur mode=755 type=file sha256digest={abc}\n"),
            &[],
        );
        index
    }

    #[test]
    fn the_session_file_protect_writes_is_guardians_own_while_it_is_exactly_that() {
        let index = index();
        let path = "home/u/.config/uwsm/env.d/90-omarchy-guardian";
        let tier = |path: &str, text: &str, mode| {
            classify(
                path,
                Observed::File {
                    sha256: &Sha256::digest(text.as_bytes()),
                    mode,
                    size: text.len() as u64,
                    content: Some(text.as_bytes()),
                },
                &index,
            )
        };
        assert_eq!(tier(path, super::SESSION_ENV, 0o644), Tier::Vendor);
        assert!(super::session_note(path, Tier::Vendor, &index).is_some());
        // One more line, another name, or set-id: a file like any other.
        let more = format!("{}export PATH=/tmp:$PATH\n", super::SESSION_ENV);
        assert_eq!(tier(path, &more, 0o644), Tier::Unknown);
        assert_eq!(tier(path, super::SESSION_ENV, 0o4755), Tier::Unknown);
        let other = "home/u/.config/uwsm/env.d/91-other";
        assert_eq!(tier(other, super::SESSION_ENV, 0o644), Tier::Unknown);
        assert!(super::session_note(other, Tier::Vendor, &index).is_none());
    }

    #[test]
    fn package_files_are_trusted_only_while_unchanged() {
        let index = index();
        let abc = Sha256::digest(b"abc");
        let other = Sha256::digest(b"other");
        let file = |sha256, mode| Observed::File {
            sha256,
            mode,
            size: 3,
            content: None,
        };
        assert_eq!(
            classify("usr/bin/demo", file(&abc, 0o100_755), &index),
            Tier::Vendor
        );
        assert_eq!(
            classify("usr/bin/demo", file(&other, 0o755), &index),
            Tier::Modified
        );
        // Execute bits may differ, and a read bit may be added; set-id
        // and write bits may not, and nobody's read access is taken away.
        assert_eq!(
            classify("usr/bin/demo", file(&abc, 0o744), &index),
            Tier::Vendor
        );
        assert_eq!(
            classify("usr/bin/demo", file(&abc, 0o711), &index),
            Tier::Modified
        );
        assert!(super::is_closed("usr/bin/demo", 0o750, &index));
        assert!(!super::is_closed("usr/bin/demo", 0o705, &index));
        assert!(!super::is_closed("usr/bin/nobody-owns", 0o700, &index));
        assert_eq!(
            classify("usr/bin/demo", file(&abc, 0o775), &index),
            Tier::Modified
        );
        // A set-id bit added or removed is a change.
        assert_eq!(
            classify("usr/bin/demo", file(&abc, 0o4755), &index),
            Tier::Modified
        );
        assert_eq!(
            classify("usr/bin/su", file(&abc, 0o4755), &index),
            Tier::Vendor
        );
        assert_eq!(
            classify("usr/bin/aur", file(&abc, 0o755), &index),
            Tier::UserBuilt
        );
        assert_eq!(
            classify("usr/bin/new", file(&other, 0o755), &index),
            Tier::Unknown
        );
        // The same content as a packaged file under another name is not a
        // copy of it.
        assert_eq!(
            classify("usr/bin/new", file(&abc, 0o755), &index),
            Tier::Unknown
        );
        // A file replaced by a link is a change.
        let link = Observed::Link {
            target: "/tmp/x",
            resolved: None,
            alias: false,
        };
        assert_eq!(classify("usr/bin/demo", link, &index), Tier::Modified);
        let same = Observed::Link {
            target: "x.so.1",
            resolved: None,
            alias: false,
        };
        assert_eq!(classify("usr/lib/x.so", same, &index), Tier::Vendor);
    }

    #[test]
    fn edited_configuration_and_packaged_copies_are_told_apart() {
        let index = index();
        let file = |sha256| Observed::File {
            sha256,
            mode: 0o644,
            size: 8,
            content: None,
        };
        let edited = Sha256::digest(b"edited");
        let copy = Sha256::digest(b"override");
        assert_eq!(
            classify("etc/demo.conf", file(&edited), &index),
            Tier::Edited
        );
        assert_eq!(classify("etc/demo.conf", file(&copy), &index), Tier::Copied);
        assert_eq!(
            classify("etc/other.conf", file(&copy), &index),
            Tier::Unknown
        );
        // Documentation and examples vouch for nothing.
        let example = Sha256::digest(b"example");
        assert_eq!(
            classify("etc/sudoers.d/sudoers", file(&example), &index),
            Tier::Unknown
        );
        // A changed file that is not configuration is still a modification.
        assert_eq!(
            classify(
                "usr/bin/demo",
                Observed::File {
                    sha256: &edited,
                    mode: 0o755,
                    size: 6,
                    content: None,
                },
                &index
            ),
            Tier::Modified
        );
    }

    #[test]
    fn a_link_is_trusted_only_where_units_are_read_and_its_text_says_where_it_leads() {
        let index = index();
        let link = |target, resolved| Observed::Link {
            target,
            resolved,
            alias: false,
        };
        let vendor = Some(Tier::Vendor);
        // Not every directory of systemd's holds units, and a target not
        // named in full under the system's own directories says nothing
        // of where the link leads.
        for (path, target) in [
            ("etc/systemd/system-generators/demo", "/usr/bin/demo"),
            (
                "usr/lib/systemd/system-sleep/demo.service",
                "/usr/lib/systemd/system/demo.service",
            ),
            (
                "etc/systemd/system/demo.service",
                "/usr/lib/systemd/system/../../share/demo/demo.service",
            ),
            (
                "home/u/.config/systemd/user/demo.service",
                "/home/u/d/demo.service",
            ),
            (
                "etc/systemd/system/demo.service.d/demo.service",
                "/usr/lib/systemd/system/demo.service",
            ),
            (
                "home/u/.config/systemd/user/demo.service",
                "../../../d/demo.service",
            ),
        ] {
            assert_eq!(
                classify(path, link(target, vendor), &index),
                Tier::Unknown,
                "{path} -> {target}"
            );
        }
    }

    #[test]
    fn links_inherit_trust_only_by_name_and_never_for_a_root_shell() {
        let index = index();
        let link = |target, resolved| Observed::Link {
            target,
            resolved,
            alias: false,
        };
        let vendor = Some(Tier::Vendor);
        let wants = "etc/systemd/system/multi-user.target.wants";
        assert_eq!(
            classify(
                &format!("{wants}/sshd.service"),
                link("/usr/lib/systemd/system/sshd.service", vendor),
                &index
            ),
            Tier::Vendor
        );
        assert_eq!(
            classify(
                &format!("{wants}/debug-shell.service"),
                link("/usr/lib/systemd/system/debug-shell.service", vendor),
                &index
            ),
            Tier::Unknown
        );
        assert_eq!(
            classify("etc/profile.d/x.sh", link("/usr/bin/demo", vendor), &index),
            Tier::Unknown
        );
        assert_eq!(
            classify(
                "etc/systemd/system/getty.target.wants/getty@tty1.service",
                link("/usr/lib/systemd/system/getty@.service", vendor),
                &index
            ),
            Tier::Vendor
        );
        // A link of the same name is only an enabled unit where systemd
        // reads units, and never to documentation or an example.
        assert_eq!(
            classify(
                "etc/sudoers.d/sudoers",
                link("/usr/share/doc/sudo/examples/sudoers", vendor),
                &index
            ),
            Tier::Unknown
        );
        assert_eq!(
            classify(
                "etc/profile.d/demo.sh",
                link("/usr/share/demo/demo.sh", vendor),
                &index
            ),
            Tier::Unknown
        );
        assert_eq!(
            classify(
                "etc/systemd/system/demo.service",
                link("/usr/share/doc/demo/examples/demo.service", vendor),
                &index
            ),
            Tier::Unknown
        );
        // A packaged hook linked into pacman's directory is enabled the
        // way hooks are.
        assert_eq!(
            classify(
                "etc/pacman.d/hooks/demo.hook",
                link("/usr/share/demo/demo.hook", vendor),
                &index
            ),
            Tier::Vendor
        );
        // Masking a defence or a packaged pacman hook is shown.
        assert_eq!(
            classify(
                "etc/systemd/system/ufw.service",
                link("/dev/null", None),
                &index
            ),
            Tier::Unknown
        );
        assert_eq!(
            classify(
                "etc/pacman.d/hooks/demo.hook",
                link("/dev/null", None),
                &index
            ),
            Tier::Unknown
        );
        assert_eq!(
            classify(
                "etc/systemd/system/NetworkManager-wait-online.service",
                link("/dev/null", None),
                &index
            ),
            Tier::Inert
        );
    }

    #[test]
    fn masks_and_enable_links_take_their_targets_trust() {
        let index = index();
        let link = |target, resolved| Observed::Link {
            target,
            resolved,
            alias: false,
        };
        let path = "etc/systemd/system/multi-user.target.wants/demo.service";
        assert_eq!(classify(path, link("/dev/null", None), &index), Tier::Inert);
        // Masking the resolver or the core dumps is common and no defence
        // lost; a unit that only starts like a defence is not one.
        for unit in [
            "systemd-resolved.service",
            "systemd-coredump.socket",
            "snapperd-x.service",
        ] {
            assert_eq!(
                classify(
                    &format!("etc/systemd/system/{unit}"),
                    link("/dev/null", None),
                    &index
                ),
                Tier::Inert,
                "{unit}"
            );
        }
        assert_eq!(
            classify(
                path,
                link("/usr/lib/systemd/system/demo.service", Some(Tier::Vendor)),
                &index
            ),
            Tier::Vendor
        );
        assert_eq!(
            classify(
                path,
                link("/home/u/.x.service", Some(Tier::Unknown)),
                &index
            ),
            Tier::Unknown
        );
        assert_eq!(classify(path, link("/gone", None), &index), Tier::Unknown);
        let empty = Sha256::digest(b"");
        assert_eq!(
            classify(
                "etc/profile.d/empty.sh",
                Observed::File {
                    sha256: &empty,
                    mode: 0o644,
                    size: 0,
                    content: None,
                },
                &index
            ),
            Tier::Inert
        );
        // An empty unit file masks like a link to /dev/null does: masking a
        // defence is shown, in a home directory too.
        for path in [
            "home/u/.config/systemd/user/omarchy-guardian-sweep.timer",
            "etc/systemd/system/ufw.service",
            "etc/systemd/system/omarchy-guardian-sweep-collect.timer",
            "etc/systemd/system/clamav-daemon.service",
            "etc/systemd/system/clamav-clamonacc.service",
            "etc/systemd/system/clamav-freshclam.service",
            "etc/systemd/system/opensnitchd.service",
            "etc/systemd/system/sshguard.service",
            "etc/systemd/system/crowdsec.service",
            "etc/systemd/system/audit-rules.service",
            "etc/systemd/system/aidecheck.timer",
            "etc/systemd/system/rkhunter.timer",
            "etc/systemd/system/snapper-timeline.timer",
            "etc/systemd/system/snapper-cleanup.timer",
            "etc/systemd/system/systemd-journald.service",
        ] {
            let observed = Observed::File {
                sha256: &empty,
                mode: 0o644,
                size: 0,
                content: None,
            };
            assert_eq!(classify(path, observed, &index), Tier::Unknown, "{path}");
            assert_eq!(
                classify(path, link("/dev/null", None), &index),
                Tier::Unknown,
                "{path}"
            );
        }
    }

    #[test]
    fn everything_the_package_installs_is_known_as_guardians_own() {
        use super::GUARDIANS_OWN;

        // Every destination the PKGBUILD's package() writes, up to the
        // first variable in it (`$unit`, `$wrapper`).
        let pkgbuild = include_str!("../../packaging/arch/PKGBUILD");
        let mut installed: Vec<String> = Vec::new();
        for line in pkgbuild.lines() {
            for (marker, prefix) in [("\"$pkgdir/", ""), ("\"$lib/", "usr/lib/omarchy-guardian/")] {
                if let Some((_, rest)) = line.split_once(marker) {
                    let path = rest.split(['"', '$']).next().unwrap_or_default();
                    installed.push(format!("{prefix}{path}"));
                }
            }
        }
        assert!(installed.len() > 15, "{installed:?}");
        assert!(installed.contains(&"usr/share/libalpm/hooks/omarchy-guardian.hook".to_string()));
        for path in &installed {
            // A destination cut at a variable is a prefix of what is known.
            let known = GUARDIANS_OWN.iter().any(|own| {
                path == own
                    || own.strip_suffix('/') == Some(path.as_str())
                    || (own.ends_with('/') && path.starts_with(own))
                    || (path.ends_with(['/', '-']) && own.starts_with(path.as_str()))
            });
            assert!(known, "{path} is installed by the package and not listed");
        }
    }

    #[test]
    fn guardians_own_files_are_trusted_though_installed_with_pacman_u() {
        let abc = Sha256::digest(b"abc");
        let mut index = PackageIndex::with_foreign(HashSet::from(["omarchy-guardian".to_string()]));
        index.add_for_test(
            "omarchy-guardian",
            &format!("#mtree\n/set type=file mode=644\n./usr/lib/systemd/user/omarchy-guardian-sweep.timer sha256digest={abc}\n./usr/bin/other sha256digest={abc}\n"),
            &[],
        );
        let file = Observed::File {
            sha256: &abc,
            mode: 0o644,
            size: 3,
            content: None,
        };
        assert_eq!(
            classify(
                "usr/lib/systemd/user/omarchy-guardian-sweep.timer",
                file,
                &index
            ),
            Tier::Vendor
        );
        // Only what Guardian ships, and never set-id.
        assert_eq!(classify("usr/bin/other", file, &index), Tier::UserBuilt);
        index.add_for_test(
            "omarchy-guardian",
            &format!(
                "#mtree\n./usr/lib/omarchy-guardian/helper type=file mode=4755 sha256digest={abc}\n"
            ),
            &[],
        );
        let setuid = Observed::File {
            sha256: &abc,
            mode: 0o4755,
            size: 3,
            content: None,
        };
        assert_eq!(
            classify("usr/lib/omarchy-guardian/helper", setuid, &index),
            Tier::UserBuilt
        );
    }

    /// What follows the interpreter line of the script the package `tool`
    /// ships as `#!/usr/bin/env python3`.
    const SCRIPT_BODY: &str = "\nimport sys\nprint(sys.argv)\n";

    /// The packages `tool` (the script, and a configuration file), `python`
    /// from a repository and a `python` from none.
    fn script_index() -> PackageIndex {
        let packaged = Sha256::digest(format!("#!/usr/bin/env python3{SCRIPT_BODY}").as_bytes());
        let other = Sha256::digest(b"python");
        let mut index = PackageIndex::with_foreign(HashSet::from(["aur-thing".to_string()]));
        index.add_for_test(
            "tool",
            &format!(
                "#mtree\n./usr/bin/tool type=file mode=755 sha256digest={packaged}\n./etc/tool.conf type=file mode=644 sha256digest={packaged}\n"
            ),
            &["etc/tool.conf"],
        );
        index.add_for_test(
            "python",
            &format!(
                "#mtree\n./usr/bin/python3 type=link link=python3.13\n./usr/bin/python3.13 type=file mode=755 sha256digest={other}\n./usr/bin/bash type=file mode=755 sha256digest={other}\n"
            ),
            &[],
        );
        index.add_for_test(
            "aur-thing",
            &format!("#mtree\n./usr/bin/python type=file mode=755 sha256digest={other}\n"),
            &[],
        );
        index
    }

    /// The tier of `text` at `path`, with its content kept or not.
    fn script_tier(index: &PackageIndex, path: &str, text: &str, mode: u32, kept: bool) -> Tier {
        let digest = Sha256::digest(text.as_bytes());
        classify(
            path,
            Observed::File {
                sha256: &digest,
                mode,
                size: text.len() as u64,
                content: kept.then_some(text.as_bytes()),
            },
            index,
        )
    }

    #[test]
    fn a_packaged_script_with_only_its_interpreter_line_rewritten_is_edited() {
        use super::{interpreter_note, is_interpreter_note};

        let index = script_index();
        let body = SCRIPT_BODY;
        let tier = |path: &str, text: &str| script_tier(&index, path, text, 0o755, true);
        let shipped = format!("#!/usr/bin/env python3{body}");
        assert_eq!(tier("usr/bin/tool", &shipped), Tier::Vendor);

        // What Omarchy makes of it, and the other ways to name the same
        // interpreter in the system's own directory.
        for line in [
            "#!/bin/python3",
            "#!/usr/bin/python3",
            "#!/usr/bin/python3.13",
        ] {
            let rewritten = format!("{line}{body}");
            let found = tier("usr/bin/tool", &rewritten);
            assert_eq!(found, Tier::Edited, "{line}");
            let note = interpreter_note("usr/bin/tool", found, &index).unwrap();
            assert!(is_interpreter_note(note));
        }
        // A configuration file that was edited gets no such note.
        assert_eq!(tier("etc/tool.conf", "changed"), Tier::Edited);
        assert_eq!(
            interpreter_note("etc/tool.conf", Tier::Edited, &index),
            None
        );
        assert_eq!(
            interpreter_note("usr/bin/tool", Tier::Modified, &index),
            None
        );
    }

    #[test]
    fn a_packaged_script_changed_in_any_other_way_is_modified() {
        let index = script_index();
        let body = SCRIPT_BODY;
        let tier = |path: &str, text: &str, mode: u32, kept: bool| {
            script_tier(&index, path, text, mode, kept)
        };
        for (line, rest, why) in [
            (
                "#!/bin/python3",
                "\nimport os\n",
                "the rest is not the package's",
            ),
            ("#!/bin/python3 -I", body, "an argument"),
            ("#!/usr/bin/env python3 ", body, "not the line, to the byte"),
            ("#!/bin/bash", body, "another interpreter"),
            (
                "#!/usr/local/bin/python3",
                body,
                "not the system's directory",
            ),
            ("#!/tmp/python3", body, "a temporary directory"),
            (
                "#!/bin/python",
                body,
                "an interpreter no repository package installed",
            ),
            (
                "#!/bin/python3.9",
                body,
                "an interpreter no package installed",
            ),
            (
                "#!/bin/../tmp/python3",
                body,
                "a path that leaves the directory",
            ),
            ("#!/usr/bin/env", body, "env alone"),
            ("", body, "no interpreter line"),
        ] {
            let changed = format!("{line}{rest}");
            assert_eq!(
                tier("usr/bin/tool", &changed, 0o755, true),
                Tier::Modified,
                "{why}"
            );
        }
        let rewritten = format!("#!/bin/python3{body}");
        // Set-id, or writable by others, on top of it; or too large for
        // the content to have been kept.
        assert_eq!(
            tier("usr/bin/tool", &rewritten, 0o4755, true),
            Tier::Modified
        );
        assert_eq!(
            tier("usr/bin/tool", &rewritten, 0o757, true),
            Tier::Modified
        );
        assert_eq!(
            tier("usr/bin/tool", &rewritten, 0o755, false),
            Tier::Modified
        );
        // One line and nothing after it.
        assert_eq!(
            tier("usr/bin/tool", "#!/bin/python3", 0o755, true),
            Tier::Modified
        );
    }
}
