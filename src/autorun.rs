//! Where files that run, or grant privileges, on their own live: one catalog
//! for the pacman gate (which reviews these files when a package ships them)
//! and the system sweep (which looks at what is already there).
//!
//! Pacman hooks and their scripts run on later transactions, sudoers and
//! polkit rules grant root, enabled systemd units, drop-ins, udev, sysctl and
//! modprobe rules, tmpfiles and sysusers entries run at boot or on events,
//! initcpio and kernel-install hooks run at every kernel update, and login
//! scripts, autostart entries, cron jobs and D-Bus services run on their own
//! schedule.

use std::path::Path;

/// What a location is for, for grouping and explaining what was found.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Category {
    Autostart,
    Boot,
    BootConfig,
    Cron,
    Dbus,
    Desktop,
    Environment,
    Git,
    Hyprland,
    Initramfs,
    Kernel,
    Linker,
    LocalBin,
    NetworkHook,
    OmarchyHook,
    PacmanHook,
    Pam,
    Polkit,
    Power,
    Shell,
    Ssh,
    Sudo,
    Systemd,
    SystemdGenerator,
    Udev,
    /// What runs now, found by the sweep's live checks.
    Process,
    Listener,
    Input,
    Camera,
    KernelModule,
    Setuid,
}

impl Category {
    pub const ALL: [Self; 31] = [
        Self::Autostart,
        Self::Boot,
        Self::BootConfig,
        Self::Cron,
        Self::Dbus,
        Self::Desktop,
        Self::Environment,
        Self::Git,
        Self::Hyprland,
        Self::Initramfs,
        Self::Kernel,
        Self::Linker,
        Self::LocalBin,
        Self::NetworkHook,
        Self::OmarchyHook,
        Self::PacmanHook,
        Self::Pam,
        Self::Polkit,
        Self::Power,
        Self::Shell,
        Self::Ssh,
        Self::Sudo,
        Self::Systemd,
        Self::SystemdGenerator,
        Self::Udev,
        Self::Process,
        Self::Listener,
        Self::Input,
        Self::Camera,
        Self::KernelModule,
        Self::Setuid,
    ];

    /// A stable machine name (`pam`, `systemd-generator`).
    pub const fn name(self) -> &'static str {
        match self {
            Self::Autostart => "autostart",
            Self::Boot => "boot",
            Self::BootConfig => "boot-config",
            Self::Cron => "cron",
            Self::Dbus => "dbus",
            Self::Desktop => "desktop",
            Self::Environment => "environment",
            Self::Git => "git",
            Self::Hyprland => "hyprland",
            Self::Initramfs => "initramfs",
            Self::Kernel => "kernel",
            Self::Linker => "linker",
            Self::LocalBin => "local-bin",
            Self::NetworkHook => "network-hook",
            Self::OmarchyHook => "omarchy-hook",
            Self::PacmanHook => "pacman-hook",
            Self::Pam => "pam",
            Self::Polkit => "polkit",
            Self::Power => "power",
            Self::Shell => "shell",
            Self::Ssh => "ssh",
            Self::Sudo => "sudo",
            Self::Systemd => "systemd",
            Self::SystemdGenerator => "systemd-generator",
            Self::Udev => "udev",
            Self::Process => "process",
            Self::Listener => "listener",
            Self::Input => "input",
            Self::Camera => "camera",
            Self::KernelModule => "kernel-module",
            Self::Setuid => "setuid",
        }
    }

    pub fn from_name(name: &str) -> Option<Self> {
        Self::ALL
            .into_iter()
            .find(|category| category.name() == name)
    }

    /// Found by the sweep's live checks, not in an auto-run location.
    pub const fn is_live(self) -> bool {
        matches!(
            self,
            Self::Process
                | Self::Listener
                | Self::Input
                | Self::Camera
                | Self::KernelModule
                | Self::Setuid
        )
    }

    /// A short name for headings.
    pub const fn label(self) -> &'static str {
        match self {
            Self::Autostart => "Autostart entries",
            Self::Boot => "Boot loader",
            Self::BootConfig => "Boot-time files (tmpfiles, sysusers)",
            Self::Cron => "Scheduled jobs (cron)",
            Self::Dbus => "D-Bus services and policy",
            Self::Desktop => "App launchers",
            Self::Environment => "Session environment",
            Self::Git => "Git configuration",
            Self::Hyprland => "Hyprland configuration",
            Self::Initramfs => "Initramfs and kernel install hooks",
            Self::Kernel => "Kernel modules and parameters",
            Self::Linker => "Dynamic linker",
            Self::LocalBin => "Programs in ~/.local/bin",
            Self::NetworkHook => "Network hooks",
            Self::OmarchyHook => "Omarchy hooks",
            Self::PacmanHook => "Pacman hooks",
            Self::Pam => "Login (PAM)",
            Self::Polkit => "Polkit rules",
            Self::Power => "Sleep and shutdown hooks",
            Self::Shell => "Shell start-up files",
            Self::Ssh => "SSH",
            Self::Sudo => "sudo",
            Self::Systemd => "systemd units",
            Self::SystemdGenerator => "systemd generators",
            Self::Udev => "udev rules",
            Self::Process => "Running programs",
            Self::Listener => "Programs listening on the network",
            Self::Input => "Programs reading the keyboard",
            Self::Camera => "Programs using a camera",
            Self::KernelModule => "Loaded kernel modules",
            Self::Setuid => "Programs with extra privileges",
        }
    }

    /// When what is found here runs, or what it grants.
    pub const fn when(self) -> &'static str {
        match self {
            Self::Autostart | Self::Hyprland => "runs when you log in",
            Self::Boot => "runs before the system starts",
            Self::BootConfig | Self::SystemdGenerator => "runs at every boot",
            Self::Cron => "runs on a schedule",
            Self::Dbus => "runs when a program asks for it over D-Bus",
            Self::Desktop => "runs when you open the app",
            Self::Environment | Self::Linker => "applies to every program started",
            Self::Git => "runs on git commands",
            Self::Initramfs => "runs at every kernel update and boot",
            Self::Kernel => "loads into the kernel",
            Self::LocalBin => "runs when you type its name",
            Self::NetworkHook => "runs when the network changes",
            Self::OmarchyHook => "runs on Omarchy events",
            Self::PacmanHook => "runs on pacman transactions, as root",
            Self::Pam | Self::Ssh => "runs when someone logs in",
            Self::Polkit | Self::Sudo => "grants administrator rights",
            Self::Power => "runs on sleep, resume and shutdown",
            Self::Shell => "runs in every shell",
            Self::Systemd => "runs as a service",
            Self::Udev => "runs when a device appears",
            Self::Process => "running now",
            Self::Listener => "accepts connections from the network",
            Self::Input => "can read every key you press",
            Self::Camera => "can see through the camera",
            Self::KernelModule => "runs inside the kernel",
            Self::Setuid => "runs with more rights than whoever starts it",
        }
    }
}

/// How a location matches paths.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind {
    /// Exactly this file.
    File,
    /// Every file under this directory.
    Directory,
    /// A unit directory: only links that enable a unit (`<target>.wants/`,
    /// `.requires/`, `.upholds/`) and drop-ins (`<unit>.d/<file>`), one
    /// level deep. Units themselves run only once enabled.
    Units,
    /// A systemd manager directory: `<manager>.conf.d/` drop-ins, which can
    /// set `DefaultEnvironment=LD_PRELOAD=...`.
    Manager,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Location {
    /// Relative to `/` (system) or to `$HOME` (user); a directory ends in `/`.
    pub path: &'static str,
    pub kind: Kind,
    pub category: Category,
}

const fn location(path: &'static str, kind: Kind, category: Category) -> Location {
    Location {
        path,
        kind,
        category,
    }
}

/// System locations a package can ship into: the pacman gate reviews these.
pub const SYSTEM: &[Location] = &[
    location("etc/sudoers", Kind::File, Category::Sudo),
    location("etc/sudo.conf", Kind::File, Category::Sudo),
    location("etc/ld.so.preload", Kind::File, Category::Linker),
    location("etc/ld.so.conf", Kind::File, Category::Linker),
    location("etc/nsswitch.conf", Kind::File, Category::Linker),
    location("etc/bash.bashrc", Kind::File, Category::Shell),
    location("etc/profile", Kind::File, Category::Shell),
    location("etc/environment", Kind::File, Category::Environment),
    location(
        "usr/share/libalpm/hooks/",
        Kind::Directory,
        Category::PacmanHook,
    ),
    location(
        "usr/share/libalpm/scripts/",
        Kind::Directory,
        Category::PacmanHook,
    ),
    location("etc/pacman.d/hooks/", Kind::Directory, Category::PacmanHook),
    location("etc/sudoers.d/", Kind::Directory, Category::Sudo),
    location("etc/polkit-1/rules.d/", Kind::Directory, Category::Polkit),
    location(
        "usr/share/polkit-1/rules.d/",
        Kind::Directory,
        Category::Polkit,
    ),
    location("etc/pam.d/", Kind::Directory, Category::Pam),
    location("usr/lib/pam.d/", Kind::Directory, Category::Pam),
    location("etc/security/", Kind::Directory, Category::Pam),
    location("etc/systemd/system/", Kind::Directory, Category::Systemd),
    location("etc/systemd/user/", Kind::Directory, Category::Systemd),
    location("etc/xdg/systemd/user/", Kind::Directory, Category::Systemd),
    location(
        "usr/lib/systemd/system-preset/",
        Kind::Directory,
        Category::Systemd,
    ),
    location(
        "usr/lib/systemd/user-preset/",
        Kind::Directory,
        Category::Systemd,
    ),
    location(
        "usr/lib/systemd/system-generators/",
        Kind::Directory,
        Category::SystemdGenerator,
    ),
    location(
        "usr/lib/systemd/user-generators/",
        Kind::Directory,
        Category::SystemdGenerator,
    ),
    location(
        "usr/lib/systemd/system-environment-generators/",
        Kind::Directory,
        Category::SystemdGenerator,
    ),
    location(
        "usr/lib/systemd/user-environment-generators/",
        Kind::Directory,
        Category::SystemdGenerator,
    ),
    location(
        "etc/systemd/system-environment-generators/",
        Kind::Directory,
        Category::SystemdGenerator,
    ),
    location(
        "etc/systemd/user-environment-generators/",
        Kind::Directory,
        Category::SystemdGenerator,
    ),
    location(
        "usr/lib/systemd/system-sleep/",
        Kind::Directory,
        Category::Power,
    ),
    location(
        "usr/lib/systemd/system-shutdown/",
        Kind::Directory,
        Category::Power,
    ),
    location(
        "etc/systemd/system-sleep/",
        Kind::Directory,
        Category::Power,
    ),
    location(
        "etc/systemd/system-shutdown/",
        Kind::Directory,
        Category::Power,
    ),
    location("usr/lib/tmpfiles.d/", Kind::Directory, Category::BootConfig),
    location("etc/tmpfiles.d/", Kind::Directory, Category::BootConfig),
    location("usr/lib/sysusers.d/", Kind::Directory, Category::BootConfig),
    location("etc/sysusers.d/", Kind::Directory, Category::BootConfig),
    location("usr/lib/sysctl.d/", Kind::Directory, Category::Kernel),
    location("etc/sysctl.d/", Kind::Directory, Category::Kernel),
    location("usr/lib/modules-load.d/", Kind::Directory, Category::Kernel),
    location("etc/modules-load.d/", Kind::Directory, Category::Kernel),
    location("usr/lib/binfmt.d/", Kind::Directory, Category::Kernel),
    location("etc/binfmt.d/", Kind::Directory, Category::Kernel),
    location("usr/lib/udev/rules.d/", Kind::Directory, Category::Udev),
    location("etc/udev/rules.d/", Kind::Directory, Category::Udev),
    location("usr/lib/modprobe.d/", Kind::Directory, Category::Kernel),
    location("etc/modprobe.d/", Kind::Directory, Category::Kernel),
    location(
        "usr/lib/environment.d/",
        Kind::Directory,
        Category::Environment,
    ),
    location("etc/environment.d/", Kind::Directory, Category::Environment),
    location(
        "usr/lib/initcpio/hooks/",
        Kind::Directory,
        Category::Initramfs,
    ),
    location(
        "usr/lib/initcpio/install/",
        Kind::Directory,
        Category::Initramfs,
    ),
    location("etc/initcpio/", Kind::Directory, Category::Initramfs),
    location(
        "etc/mkinitcpio.conf.d/",
        Kind::Directory,
        Category::Initramfs,
    ),
    location("etc/mkinitcpio.d/", Kind::Directory, Category::Initramfs),
    location(
        "usr/lib/kernel/install.d/",
        Kind::Directory,
        Category::Initramfs,
    ),
    location(
        "etc/kernel/install.d/",
        Kind::Directory,
        Category::Initramfs,
    ),
    location(
        "usr/lib/NetworkManager/dispatcher.d/",
        Kind::Directory,
        Category::NetworkHook,
    ),
    location(
        "etc/NetworkManager/dispatcher.d/",
        Kind::Directory,
        Category::NetworkHook,
    ),
    location("etc/ld.so.conf.d/", Kind::Directory, Category::Linker),
    location("etc/profile.d/", Kind::Directory, Category::Shell),
    location("etc/zsh/", Kind::Directory, Category::Shell),
    location(
        "usr/share/fish/vendor_conf.d/",
        Kind::Directory,
        Category::Shell,
    ),
    location("etc/ssh/sshd_config.d/", Kind::Directory, Category::Ssh),
    location("etc/ssh/ssh_config.d/", Kind::Directory, Category::Ssh),
    location("etc/xdg/autostart/", Kind::Directory, Category::Autostart),
    location(
        "etc/X11/xinit/xinitrc.d/",
        Kind::Directory,
        Category::Autostart,
    ),
    location("etc/cron.d/", Kind::Directory, Category::Cron),
    location("etc/cron.hourly/", Kind::Directory, Category::Cron),
    location("etc/cron.daily/", Kind::Directory, Category::Cron),
    location("etc/cron.weekly/", Kind::Directory, Category::Cron),
    location("etc/cron.monthly/", Kind::Directory, Category::Cron),
    location(
        "usr/share/dbus-1/system-services/",
        Kind::Directory,
        Category::Dbus,
    ),
    location(
        "usr/share/dbus-1/services/",
        Kind::Directory,
        Category::Dbus,
    ),
    location(
        "usr/share/dbus-1/system.d/",
        Kind::Directory,
        Category::Dbus,
    ),
    location("etc/dbus-1/system.d/", Kind::Directory, Category::Dbus),
    location("usr/lib/systemd/system/", Kind::Units, Category::Systemd),
    location("usr/lib/systemd/user/", Kind::Units, Category::Systemd),
    location("etc/systemd/", Kind::Manager, Category::Systemd),
    location("usr/lib/systemd/", Kind::Manager, Category::Systemd),
];

/// System locations no package should ship into, looked at by the sweep only.
pub const SYSTEM_SWEEP: &[Location] = &[
    // PAM modules: a `.so` every login loads.
    location("usr/lib/security/", Kind::Directory, Category::Pam),
    location("boot/limine.conf", Kind::File, Category::Boot),
    location("etc/default/limine", Kind::File, Category::Boot),
    location("var/spool/cron/", Kind::Directory, Category::Cron),
];

/// Locations in a home directory, relative to it.
pub const USER: &[Location] = &[
    location(".config/systemd/user/", Kind::Directory, Category::Systemd),
    location(
        ".config/environment.d/",
        Kind::Directory,
        Category::Environment,
    ),
    location(".config/autostart/", Kind::Directory, Category::Autostart),
    location(
        ".local/share/applications/",
        Kind::Directory,
        Category::Desktop,
    ),
    location(".bashrc", Kind::File, Category::Shell),
    location(".bash_profile", Kind::File, Category::Shell),
    location(".bash_login", Kind::File, Category::Shell),
    location(".bash_logout", Kind::File, Category::Shell),
    location(".profile", Kind::File, Category::Shell),
    location(".zshrc", Kind::File, Category::Shell),
    location(".zprofile", Kind::File, Category::Shell),
    location(".zshenv", Kind::File, Category::Shell),
    location(".zlogin", Kind::File, Category::Shell),
    location(".config/fish/config.fish", Kind::File, Category::Shell),
    location(".config/fish/conf.d/", Kind::Directory, Category::Shell),
    location(".xprofile", Kind::File, Category::Autostart),
    location(".xinitrc", Kind::File, Category::Autostart),
    location(".config/hypr/", Kind::Directory, Category::Hyprland),
    location(
        ".config/omarchy/hooks/",
        Kind::Directory,
        Category::OmarchyHook,
    ),
    location(".local/bin/", Kind::Directory, Category::LocalBin),
    location(".ssh/authorized_keys", Kind::File, Category::Ssh),
    location(".ssh/rc", Kind::File, Category::Ssh),
    location(".ssh/config", Kind::File, Category::Ssh),
    location(".gitconfig", Kind::File, Category::Git),
    location(".config/git/config", Kind::File, Category::Git),
];

const ENABLING: &[&str] = &[".wants", ".requires", ".upholds"];

impl Location {
    /// Whether `path` (relative, like `path`) falls under this location.
    pub fn contains(&self, path: &str) -> bool {
        match self.kind {
            Kind::File => path == self.path,
            Kind::Directory => path.starts_with(self.path),
            Kind::Units => path
                .strip_prefix(self.path)
                .and_then(|rest| rest.split_once('/'))
                .is_some_and(|(parent, unit)| {
                    !unit.contains('/')
                        && (ENABLING.iter().any(|suffix| parent.ends_with(suffix))
                            || Path::new(parent)
                                .extension()
                                .is_some_and(|extension| extension == "d"))
                }),
            Kind::Manager => path
                .strip_prefix(self.path)
                .and_then(|rest| rest.split_once('/'))
                .is_some_and(|(parent, file)| parent.ends_with(".conf.d") && !file.contains('/')),
        }
    }
}

/// The system location a canonical package path falls under, if any.
pub fn system_location(path: &str) -> Option<&'static Location> {
    if path
        .split('/')
        .any(|component| matches!(component, "" | "." | ".."))
    {
        return None;
    }
    SYSTEM.iter().find(|location| location.contains(path))
}

/// Whether the file at `path` (a canonical package path) runs or grants
/// privileges on its own.
pub fn is_auto_run(path: &str) -> bool {
    system_location(path).is_some()
}

/// The paths a hook or unit runs (`Exec =`, `ExecStart=` and friends),
/// without systemd's `-@:+!` prefixes, relative to `/`.
pub fn executed_paths(text: &str) -> Vec<String> {
    text.lines()
        .filter_map(|line| {
            let (key, value) = line.split_once('=')?;
            let key = key.trim();
            let runs = key == "Exec"
                || [
                    "ExecStart",
                    "ExecStartPre",
                    "ExecStartPost",
                    "ExecStop",
                    "ExecStopPost",
                    "ExecReload",
                    "ExecCondition",
                ]
                .contains(&key);
            if !runs {
                return None;
            }
            let program = value
                .trim()
                .trim_start_matches(['-', '@', ':', '+', '!'])
                .split_whitespace()
                .next()?;
            program
                .strip_prefix('/')
                .filter(|path| !path.is_empty())
                .map(str::to_string)
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use std::collections::HashSet;

    use super::{
        Category, Kind, SYSTEM, SYSTEM_SWEEP, USER, executed_paths, is_auto_run, system_location,
    };

    #[test]
    fn auto_run_locations() {
        for path in [
            "usr/share/libalpm/hooks/foo.hook",
            "usr/share/libalpm/scripts/foo",
            "etc/sudoers",
            "etc/sudoers.d/foo",
            "usr/share/polkit-1/rules.d/50-foo.rules",
            "etc/pam.d/foo",
            "usr/lib/systemd/system/multi-user.target.wants/foo.service",
            "usr/lib/systemd/user/default.target.wants/foo.service",
            "usr/lib/systemd/system/foo.service.d/override.conf",
            "etc/systemd/system.conf.d/env.conf",
            "usr/lib/systemd/system-generators/foo",
            "usr/lib/systemd/system-sleep/foo",
            "usr/lib/tmpfiles.d/foo.conf",
            "usr/lib/sysctl.d/50-foo.conf",
            "usr/lib/modules-load.d/foo.conf",
            "usr/lib/initcpio/hooks/foo",
            "usr/lib/kernel/install.d/50-foo.install",
            "etc/NetworkManager/dispatcher.d/foo",
            "usr/lib/udev/rules.d/99-foo.rules",
            "etc/profile.d/foo.sh",
            "etc/profile",
            "etc/bash.bashrc",
            "etc/xdg/autostart/foo.desktop",
            "etc/cron.daily/foo",
            "usr/share/dbus-1/system-services/org.foo.service",
            "usr/share/dbus-1/services/org.foo.service",
            "etc/ld.so.preload",
            "etc/ssh/sshd_config.d/foo.conf",
        ] {
            assert!(is_auto_run(path), "{path}");
        }
        for path in [
            "usr/bin/foo",
            "usr/lib/systemd/system/foo.service",
            "usr/share/doc/foo/README",
            "usr/share/applications/foo.desktop",
            "usr/lib/systemd/system/a.wants/b/c.service",
            "usr/lib/systemd/system/a.service.d/b/c.conf",
            "etc/sudoers.d/../../usr/bin/x",
            "etc/skel/.bashrc",
            "usr/share/bash-completion/completions/foo",
            // Sweep-only locations are not part of the gate's review.
            "usr/lib/security/pam_x.so",
            "boot/limine.conf",
        ] {
            assert!(!is_auto_run(path), "{path}");
        }
    }

    #[test]
    fn locations_are_relative_unique_and_categorised() {
        let mut seen = HashSet::new();
        for location in SYSTEM.iter().chain(SYSTEM_SWEEP).chain(USER) {
            assert!(!location.path.starts_with('/'), "{}", location.path);
            assert_eq!(
                location.path.ends_with('/'),
                location.kind != Kind::File,
                "{}",
                location.path
            );
            assert!(seen.insert(location.path), "{}", location.path);
            assert!(!location.category.label().is_empty());
            assert!(!location.category.when().is_empty());
        }
        for category in Category::ALL {
            assert_eq!(Category::from_name(category.name()), Some(category));
        }
        assert_eq!(
            system_location("etc/udev/rules.d/99-x.rules").map(|found| found.category),
            Some(Category::Udev)
        );
        assert_eq!(
            system_location("usr/lib/systemd/system-generators/x").map(|found| found.category),
            Some(Category::SystemdGenerator)
        );
    }

    #[test]
    fn executed_scripts_are_found_in_hooks_and_units() {
        let text = "[Action]\nExec = /usr/share/foo/run.sh --all\n[Service]\nExecStartPre=-/usr/lib/foo/pre\nExecStart=@/usr/bin/foo foo\nEnvironment=X=1\n";
        assert_eq!(
            executed_paths(text),
            ["usr/share/foo/run.sh", "usr/lib/foo/pre", "usr/bin/foo"]
        );
    }
}
