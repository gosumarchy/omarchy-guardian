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
    /// Looked at by the sweep only: no package ships into these.
    Account,
    Browser,
    Editor,
    Terminal,
    Toolchain,
    TrustStore,
}

impl Category {
    pub const ALL: [Self; 37] = [
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
        Self::Account,
        Self::Browser,
        Self::Editor,
        Self::Terminal,
        Self::Toolchain,
        Self::TrustStore,
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
            Self::Account => "account",
            Self::Browser => "browser",
            Self::Editor => "editor",
            Self::Terminal => "terminal",
            Self::Toolchain => "toolchain",
            Self::TrustStore => "trust",
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
            Self::LocalBin => "Programs ahead of the system's own on PATH",
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
            Self::Account => "Accounts and who may log in",
            Self::Browser => "Browser flags, policies and native hosts",
            Self::Editor => "Editor start-up files",
            Self::Terminal => "Terminal and prompt configuration",
            Self::Toolchain => "Developer tool configuration (npm, pip, cargo, mise)",
            Self::TrustStore => "Trust anchors and name resolution",
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
            Self::Account => "lets someone log in or administer",
            Self::Browser => "applies at every start of the browser",
            Self::Editor => "runs at every start of the editor",
            Self::Terminal => "runs in every terminal",
            Self::Toolchain => "decides what builds and installs run and fetch",
            Self::TrustStore => "decides which servers are believed",
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
    /// Exactly the files this path matches, `*` standing for any run of
    /// characters within one name (`usr/lib/python*/site-packages/*.pth`).
    Glob,
}

/// Whether `name` (one path component) matches `pattern`, in which each
/// `*` stands for any run of characters.
pub fn name_matches(pattern: &str, name: &str) -> bool {
    let mut parts = pattern.split('*');
    let Some(first) = parts.next() else {
        return name.is_empty();
    };
    let Some(mut rest) = name.strip_prefix(first) else {
        return false;
    };
    let mut parts = parts.peekable();
    if parts.peek().is_none() {
        return rest.is_empty();
    }
    while let Some(part) = parts.next() {
        if parts.peek().is_none() {
            return rest.ends_with(part);
        }
        match rest.find(part) {
            Some(at) => rest = &rest[at + part.len()..],
            None => return false,
        }
    }
    true
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
    // What systemd and udev also read, ahead of /usr/lib.
    location(
        "etc/systemd/system-generators/",
        Kind::Directory,
        Category::SystemdGenerator,
    ),
    location(
        "etc/systemd/user-generators/",
        Kind::Directory,
        Category::SystemdGenerator,
    ),
    location(
        "usr/local/lib/systemd/system-generators/",
        Kind::Directory,
        Category::SystemdGenerator,
    ),
    location(
        "usr/local/lib/systemd/system/",
        Kind::Units,
        Category::Systemd,
    ),
    location(
        "usr/local/lib/systemd/user/",
        Kind::Units,
        Category::Systemd,
    ),
    location(
        "usr/local/lib/udev/rules.d/",
        Kind::Directory,
        Category::Udev,
    ),
    location("etc/crontab", Kind::File, Category::Cron),
    location("etc/anacrontab", Kind::File, Category::Cron),
    location("var/spool/cron/", Kind::Directory, Category::Cron),
    // What an action may do without a password is set by its policy.
    location(
        "usr/share/polkit-1/actions/",
        Kind::Directory,
        Category::Polkit,
    ),
    location("etc/doas.conf", Kind::File, Category::Sudo),
    location("etc/gitconfig", Kind::File, Category::Git),
    location("etc/ssh/sshrc", Kind::File, Category::Ssh),
    location("etc/makepkg.conf.d/", Kind::Directory, Category::Shell),
    // Ahead of /usr/bin on every PATH: a program here stands in for the
    // system's own of that name.
    location("usr/local/bin/", Kind::Directory, Category::LocalBin),
    location("usr/local/sbin/", Kind::Directory, Category::LocalBin),
    // Where systemd also reads units and generators from.
    location(
        "etc/systemd/system.control/",
        Kind::Directory,
        Category::Systemd,
    ),
    location(
        "etc/systemd/system.attached/",
        Kind::Directory,
        Category::Systemd,
    ),
    // Scripts mkinitcpio runs after it built an image.
    location(
        "usr/lib/initcpio/post/",
        Kind::Directory,
        Category::Initramfs,
    ),
    // Python runs every `import` line of a `.pth` file, and these two
    // modules, at each start of the interpreter.
    location(
        "usr/lib/python*/site-packages/*.pth",
        Kind::Glob,
        Category::Linker,
    ),
    location(
        "usr/lib/python*/site-packages/sitecustomize.py",
        Kind::Glob,
        Category::Linker,
    ),
    location(
        "usr/lib/python*/site-packages/usercustomize.py",
        Kind::Glob,
        Category::Linker,
    ),
    location(
        "usr/lib/python*/sitecustomize.py",
        Kind::Glob,
        Category::Linker,
    ),
    // DKMS runs a module's build scripts as root at every kernel update.
    location("usr/src/*/dkms.conf", Kind::Glob, Category::Initramfs),
    // The main files beside the drop-in directories.
    location("etc/ssh/sshd_config", Kind::File, Category::Ssh),
    location("etc/ssh/ssh_config", Kind::File, Category::Ssh),
    location("etc/systemd/system.conf", Kind::File, Category::Systemd),
    location("etc/systemd/user.conf", Kind::File, Category::Systemd),
    location("etc/makepkg.conf", Kind::File, Category::Shell),
    location("etc/mkinitcpio.conf", Kind::File, Category::Initramfs),
    location("etc/bash.bash_logout", Kind::File, Category::Shell),
    location("etc/fish/", Kind::Directory, Category::Shell),
    // `HookDir`, `XferCommand` and the repositories packages come from.
    location("etc/pacman.conf", Kind::File, Category::PacmanHook),
    // Scripts logrotate runs as root (`postrotate`).
    location("etc/logrotate.conf", Kind::File, Category::Cron),
    location("etc/logrotate.d/", Kind::Directory, Category::Cron),
    // The login screen: its session and display commands, and the sessions
    // it offers.
    location("etc/sddm.conf", Kind::File, Category::Autostart),
    location("etc/sddm.conf.d/", Kind::Directory, Category::Autostart),
    location(
        "usr/lib/sddm/sddm.conf.d/",
        Kind::Directory,
        Category::Autostart,
    ),
    location(
        "usr/share/sddm/scripts/",
        Kind::Directory,
        Category::Autostart,
    ),
    location("etc/greetd/", Kind::Directory, Category::Autostart),
    location(
        "usr/share/wayland-sessions/",
        Kind::Directory,
        Category::Autostart,
    ),
    location("usr/share/xsessions/", Kind::Directory, Category::Autostart),
    location(
        "usr/local/lib/systemd/user-generators/",
        Kind::Directory,
        Category::SystemdGenerator,
    ),
    location(
        "usr/local/lib/systemd/system-environment-generators/",
        Kind::Directory,
        Category::SystemdGenerator,
    ),
    location(
        "usr/local/lib/systemd/user-environment-generators/",
        Kind::Directory,
        Category::SystemdGenerator,
    ),
];

/// System locations no package should ship into, looked at by the sweep only.
pub const SYSTEM_SWEEP: &[Location] = &[
    // PAM modules: a `.so` every login loads.
    location("usr/lib/security/", Kind::Directory, Category::Pam),
    location("boot/limine.conf", Kind::File, Category::Boot),
    location("etc/default/limine", Kind::File, Category::Boot),
    location("etc/kernel/cmdline", Kind::File, Category::Boot),
    // Libraries the dynamic linker prefers over the ones in `/usr/lib`.
    location("usr/lib/glibc-hwcaps/", Kind::Directory, Category::Linker),
    // Podman turns the quadlets here into units at every boot.
    location(
        "etc/containers/systemd/",
        Kind::Directory,
        Category::Systemd,
    ),
    // Jobs handed to `at`; only root can list them.
    location("var/spool/atd/", Kind::Directory, Category::Cron),
    // What mounts and unlocks at boot, with the options that run a helper.
    location("etc/fstab", Kind::File, Category::BootConfig),
    location("etc/crypttab", Kind::File, Category::BootConfig),
    // Certificate authorities added to the system's own, and names that
    // resolve without asking DNS.
    location(
        "etc/ca-certificates/trust-source/anchors/",
        Kind::Directory,
        Category::TrustStore,
    ),
    location(
        "usr/local/share/ca-certificates/",
        Kind::Directory,
        Category::TrustStore,
    ),
    location("etc/hosts", Kind::File, Category::TrustStore),
    // Browser policies (forced extensions, proxies) and the programs a
    // browser extension may start.
    location("etc/chromium/policies/", Kind::Directory, Category::Browser),
    location(
        "etc/opt/chrome/policies/",
        Kind::Directory,
        Category::Browser,
    ),
    location("etc/brave/policies/", Kind::Directory, Category::Browser),
    location("etc/firefox/policies/", Kind::Directory, Category::Browser),
    location(
        "usr/lib/firefox/distribution/policies.json",
        Kind::File,
        Category::Browser,
    ),
    location(
        "etc/chromium/native-messaging-hosts/",
        Kind::Directory,
        Category::Browser,
    ),
    location(
        "etc/opt/chrome/native-messaging-hosts/",
        Kind::Directory,
        Category::Browser,
    ),
    location(
        "usr/lib/mozilla/native-messaging-hosts/",
        Kind::Directory,
        Category::Browser,
    ),
    // What every Flatpak app may reach outside its sandbox.
    location(
        "var/lib/flatpak/overrides/",
        Kind::Directory,
        Category::Desktop,
    ),
    location("etc/npmrc", Kind::File, Category::Toolchain),
    location("etc/pip.conf", Kind::File, Category::Toolchain),
    location("etc/tmux.conf", Kind::File, Category::Terminal),
    location("etc/inputrc", Kind::File, Category::Shell),
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
    location(".zlogout", Kind::File, Category::Shell),
    // The user manager's own configuration (`DefaultEnvironment=`).
    location(".config/systemd/user.conf", Kind::File, Category::Systemd),
    location(
        ".config/systemd/user.conf.d/",
        Kind::Directory,
        Category::Systemd,
    ),
    // Where cargo installs programs; ahead of `/usr/bin` in many setups.
    location(".cargo/bin/", Kind::Directory, Category::LocalBin),
    location(".ssh/config.d/", Kind::Directory, Category::Ssh),
    // The other place systemd reads user units from.
    location(
        ".local/share/systemd/user/",
        Kind::Directory,
        Category::Systemd,
    ),
    // Services the session bus starts when their name is asked for.
    location(
        ".local/share/dbus-1/services/",
        Kind::Directory,
        Category::Dbus,
    ),
    // Functions fish loads by name: one called `ls` replaces the command.
    location(".config/fish/functions/", Kind::Directory, Category::Shell),
    // What uwsm sources before it starts the session.
    location(".config/uwsm/", Kind::Directory, Category::Shell),
    location(".makepkg.conf", Kind::File, Category::Shell),
    location(".config/pacman/makepkg.conf", Kind::File, Category::Shell),
    // The bar runs the commands of its custom modules.
    location(
        ".config/waybar/config.jsonc",
        Kind::File,
        Category::Autostart,
    ),
    location(".config/waybar/config", Kind::File, Category::Autostart),
    location(
        ".local/lib/python*/site-packages/*.pth",
        Kind::Glob,
        Category::Linker,
    ),
    location(
        ".local/lib/python*/site-packages/sitecustomize.py",
        Kind::Glob,
        Category::Linker,
    ),
    location(
        ".local/lib/python*/site-packages/usercustomize.py",
        Kind::Glob,
        Category::Linker,
    ),
    // Units `systemctl --user set-property` and its like write.
    location(
        ".config/systemd/user.control/",
        Kind::Directory,
        Category::Systemd,
    ),
    // Podman turns the quadlets here into user units.
    location(
        ".config/containers/systemd/",
        Kind::Directory,
        Category::Systemd,
    ),
    // Flags every start of the browser or an Electron app takes: an
    // extension to load, a debugging port, a proxy.
    location(".config/chromium-flags.conf", Kind::File, Category::Browser),
    location(".config/chrome-flags.conf", Kind::File, Category::Browser),
    location(".config/brave-flags.conf", Kind::File, Category::Browser),
    location(".config/code-flags.conf", Kind::File, Category::Browser),
    location(
        ".config/electron*-flags.conf",
        Kind::Glob,
        Category::Browser,
    ),
    // Programs a browser extension may start.
    location(
        ".config/chromium/NativeMessagingHosts/",
        Kind::Directory,
        Category::Browser,
    ),
    location(
        ".config/google-chrome/NativeMessagingHosts/",
        Kind::Directory,
        Category::Browser,
    ),
    location(
        ".config/BraveSoftware/Brave-Browser/NativeMessagingHosts/",
        Kind::Directory,
        Category::Browser,
    ),
    location(
        ".mozilla/native-messaging-hosts/",
        Kind::Directory,
        Category::Browser,
    ),
    // The shell or command a terminal, a prompt or tmux starts each time.
    location(
        ".config/alacritty/alacritty.toml",
        Kind::File,
        Category::Terminal,
    ),
    location(".alacritty.toml", Kind::File, Category::Terminal),
    location(".config/kitty/kitty.conf", Kind::File, Category::Terminal),
    location(".config/ghostty/config", Kind::File, Category::Terminal),
    location(".config/foot/foot.ini", Kind::File, Category::Terminal),
    location(".config/starship.toml", Kind::File, Category::Terminal),
    location(".tmux.conf", Kind::File, Category::Terminal),
    location(".config/tmux/tmux.conf", Kind::File, Category::Terminal),
    // Which launcher opens a link or a file; the launchers it names in the
    // home are followed from it.
    location(".config/mimeapps.list", Kind::File, Category::Desktop),
    location(
        ".local/share/applications/mimeapps.list",
        Kind::File,
        Category::Desktop,
    ),
    // What a Flatpak app may reach outside its sandbox.
    location(
        ".local/share/flatpak/overrides/",
        Kind::Directory,
        Category::Desktop,
    ),
    // Environment, hooks and tasks mise applies on entering a directory.
    location(".config/mise/config.toml", Kind::File, Category::Toolchain),
    location(".mise.toml", Kind::File, Category::Toolchain),
    // Where package managers fetch from and what they run on the way.
    location(".npmrc", Kind::File, Category::Toolchain),
    location(".config/pip/pip.conf", Kind::File, Category::Toolchain),
    location(".pydistutils.cfg", Kind::File, Category::Toolchain),
    location(".cargo/config.toml", Kind::File, Category::Toolchain),
    location(".cargo/config", Kind::File, Category::Toolchain),
    location(".gemrc", Kind::File, Category::Toolchain),
    location(".yarnrc", Kind::File, Category::Toolchain),
    location(".yarnrc.yml", Kind::File, Category::Toolchain),
    location(".bunfig.toml", Kind::File, Category::Toolchain),
    location(".config/go/env", Kind::File, Category::Toolchain),
    // What an editor runs at every start.
    location(".config/nvim/init.lua", Kind::File, Category::Editor),
    location(".config/nvim/init.vim", Kind::File, Category::Editor),
    location(".config/nvim/plugin/", Kind::Directory, Category::Editor),
    location(
        ".config/nvim/after/plugin/",
        Kind::Directory,
        Category::Editor,
    ),
    location(".config/nvim/lua/", Kind::Directory, Category::Editor),
    location(".vimrc", Kind::File, Category::Editor),
    location(".vim/plugin/", Kind::Directory, Category::Editor),
    location(
        ".config/Code/User/settings.json",
        Kind::File,
        Category::Editor,
    ),
    location(
        ".config/Code - OSS/User/settings.json",
        Kind::File,
        Category::Editor,
    ),
    location(
        ".config/VSCodium/User/settings.json",
        Kind::File,
        Category::Editor,
    ),
    location(
        ".config/Cursor/User/settings.json",
        Kind::File,
        Category::Editor,
    ),
    // More of what a shell or a login reads.
    location(".config/fish/fish_variables", Kind::File, Category::Shell),
    location(
        ".config/fish/completions/",
        Kind::Directory,
        Category::Shell,
    ),
    location(".inputrc", Kind::File, Category::Shell),
    location(".pam_environment", Kind::File, Category::Environment),
    location(".xsession", Kind::File, Category::Autostart),
    location(".xsessionrc", Kind::File, Category::Autostart),
    location(".ssh/authorized_keys2", Kind::File, Category::Ssh),
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
            Kind::Glob => {
                let (patterns, names): (Vec<&str>, Vec<&str>) =
                    (self.path.split('/').collect(), path.split('/').collect());
                patterns.len() == names.len()
                    && patterns
                        .iter()
                        .zip(&names)
                        .all(|(pattern, name)| name_matches(pattern, name))
            }
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

/// Whether the directory `link` may be a link to the directory `target`:
/// both are directories of auto-run files of the same kind, each exactly
/// as catalogued, so every file is reviewed where it really is, as what it
/// will be read as (systemd's `etc/xdg/systemd/user` for
/// `etc/systemd/user`). A link to a directory of another kind would have
/// its files read as something they were not reviewed as, and one to a
/// directory below a catalogued one may itself be a link elsewhere.
pub fn is_alias_of_reviewed_directory(link: &str, target: &str) -> bool {
    let (link, target) = (format!("{link}/"), format!("{target}/"));
    let directories = || {
        SYSTEM
            .iter()
            .filter(|location| location.kind == Kind::Directory)
    };
    directories().any(|aliased| {
        aliased.path == link
            && directories()
                .any(|reviewed| reviewed.path == target && reviewed.category == aliased.category)
    })
}

/// Whether `path` names a directory of auto-run files or one above it (an
/// `etc/cron.d`, a `<target>.wants`, a `usr/share/libalpm`): a link there
/// stands in for the directory, and what it leads to is read as its files.
pub fn is_auto_run_directory(path: &str) -> bool {
    let directory = format!("{path}/");
    // systemd reads `<target>.wants` and `<unit>.d` as directories
    // wherever it reads units.
    let unit_directory = path.rsplit_once('/').is_some_and(|(_, name)| {
        ENABLING.iter().any(|suffix| name.ends_with(suffix))
            || Path::new(name)
                .extension()
                .is_some_and(|extension| extension == "d")
    });
    SYSTEM.iter().any(|location| match location.kind {
        // A pattern names files, never a directory.
        Kind::File | Kind::Glob => false,
        Kind::Directory => {
            location.path.starts_with(&directory)
                || (unit_directory
                    && location.category == Category::Systemd
                    && path.starts_with(location.path))
        }
        Kind::Units | Kind::Manager => {
            location.path.starts_with(&directory) || location.contains(&format!("{directory}x"))
        }
    })
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
        Category, Kind, SYSTEM, SYSTEM_SWEEP, USER, executed_paths, is_auto_run,
        is_auto_run_directory, system_location,
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
            "etc/systemd/system-generators/foo",
            "usr/local/lib/systemd/system/multi-user.target.wants/foo.service",
            "usr/local/lib/udev/rules.d/99-foo.rules",
            "etc/crontab",
            "var/spool/cron/root",
            "usr/share/polkit-1/actions/org.foo.policy",
            "etc/doas.conf",
            "etc/gitconfig",
            "etc/ssh/sshrc",
            "etc/makepkg.conf.d/foo.conf",
            "usr/local/bin/sudo",
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
                !matches!(location.kind, Kind::File | Kind::Glob),
                "{}",
                location.path
            );
            assert_eq!(
                location.path.contains('*'),
                location.kind == Kind::Glob,
                "{}",
                location.path
            );
            assert!(seen.insert(location.path), "{}", location.path);
            assert!(!location.category.label().is_empty());
            assert!(!location.category.when().is_empty());
        }
        let pth = SYSTEM
            .iter()
            .find(|location| location.path.ends_with("*.pth"))
            .unwrap();
        assert!(pth.contains("usr/lib/python3.13/site-packages/evil.pth"));
        assert!(!pth.contains("usr/lib/python3.13/site-packages/pkg/evil.pth"));
        assert!(!pth.contains("usr/lib/python3.13/site-packages/evil.py"));
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
    fn a_directory_of_auto_run_files_is_told_from_a_file_in_one() {
        for directory in [
            "etc/cron.d",
            "etc/systemd/system-sleep",
            "usr/share/libalpm",
            "usr/share/libalpm/hooks",
            "usr/lib/systemd/system/multi-user.target.wants",
            "usr/lib/systemd/system/foo.service.d",
            "etc/systemd/system.conf.d",
            "usr/local/bin",
            "etc/systemd/system/multi-user.target.wants",
            "etc/systemd/system/foo.service.d",
            "etc/systemd/user/default.target.requires",
        ] {
            assert!(is_auto_run_directory(directory), "{directory}");
        }
        for other in [
            "etc/sudoers.d/out",
            "etc/cron.d/job",
            "usr/lib/systemd/system/foo.service",
            "usr/lib/systemd/system/multi-user.target.wants/foo.service",
            "usr/share/doc",
            "etc/systemd/system/display-manager.service",
            "etc/cron.d/jobs.d",
            "etc/sudoers",
            "lib",
        ] {
            assert!(!is_auto_run_directory(other), "{other}");
        }
        let alias = super::is_alias_of_reviewed_directory;
        assert!(alias("etc/xdg/systemd/user", "etc/systemd/user"));
        assert!(alias("etc/cron.daily", "etc/cron.weekly"));
        // Below a catalogued directory may be a link elsewhere.
        assert!(!alias("etc/xdg/systemd/user", "etc/systemd/user/sub"));
        assert!(!alias("etc/cron.d", "etc/cron.daily/sub"));
        // Another kind of file, a directory that is not all auto-run, a
        // directory above one, or somewhere else entirely.
        assert!(!alias("etc/sudoers.d", "usr/local/bin"));
        assert!(!alias("etc/cron.d", "usr/local/bin"));
        assert!(!alias("etc/xdg/systemd/user", "usr/lib/systemd/system"));
        assert!(!alias("etc/xdg/systemd", "etc/systemd/user"));
        assert!(!alias("etc/cron.d", "usr/share/x/sleep"));
        assert!(!alias("etc/cron.d", "etc"));
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
