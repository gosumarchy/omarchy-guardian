//! The pieces that connect Guardian to the system: the pacman hook, the yay
//! makepkg gate, the Bash theme interceptor, the session PATH wrappers, the
//! Omarchy menu entry and the bar widget.
//!
//! What depends on a PATH (which `yay` is found, whether the wrappers come
//! first) is read from the session's own: the one its service manager
//! hands to what it starts. Every caller sees the same one there, whatever
//! PATH its own shell made; the calling process's is only what is left
//! when there is no manager to ask.
//! Each has a state read from disk and a plan to turn it on or off. Plans
//! that need root or another program run as commands on the terminal (so
//! `sudo` can ask for a password); the rest are small, exact file edits.

mod luascan;
mod menufile;
mod shellscan;

use std::env;
use std::fs::{self, OpenOptions};
use std::io::Write as _;
use std::os::unix::fs::{MetadataExt as _, OpenOptionsExt};
use std::path::{Path, PathBuf};

use crate::config::model::RootConsent;
use crate::json::Json;
use crate::paths::{self, Accept};
use crate::sweep::own;
use shellscan::Loads;

pub const HOOK_SOURCE: &str = "/usr/share/omarchy-guardian/omarchy-guardian.hook";
pub const HOOK_TARGET: &str = "/etc/pacman.d/hooks/omarchy-guardian.hook";
pub const MAKEPKG_GATE: &str = "/usr/lib/omarchy-guardian/guardian-makepkg";
pub const INTERCEPTOR_INSTALLER: &str = "/usr/lib/omarchy-guardian/install-user-interceptor.sh";
const INTERCEPTOR_MARKER: &str = "# Omarchy Guardian theme command interception";
const INTERCEPTOR_SOURCE: &str = "/usr/lib/omarchy-guardian/omarchy-bash-interceptor.sh";
/// The line `install-user-interceptor.sh` writes. Only this exact line
/// counts as loading the interceptor.
const INTERCEPTOR_LINE: &str = "[[ -r /usr/lib/omarchy-guardian/omarchy-bash-interceptor.sh ]] && source /usr/lib/omarchy-guardian/omarchy-bash-interceptor.sh";
/// Root-owned commands with the names of Omarchy's theme and plugin
/// installers (and of its dispatcher), which go through Guardian. First on
/// the session's PATH, they catch every caller that finds those commands
/// by name: scripts, other shells, launchers, key bindings.
pub const WRAPPERS: &str = "/usr/lib/omarchy-guardian/bin";
const WRAPPED: [&str; 5] = [
    "omarchy",
    "omarchy-theme-install",
    "omarchy-theme-update",
    "omarchy-plugin-add",
    "omarchy-plugin-update",
];
/// The file Hyprland's configuration loads to put the wrappers first: a
/// root-owned file of the package, so the line in the user's file never
/// has to change.
pub const HYPR_PATH: &str = "/usr/lib/omarchy-guardian/hyprland-path.lua";
/// The lines `protect` adds at the end of `~/.config/hypr/hyprland.lua`:
/// after Omarchy's defaults, whose `envs.lua` puts Omarchy's own commands
/// first on PATH, and before Hyprland starts anything. Only the second,
/// exactly, counts as loading the file; a missing file is passed over.
const HYPR_MARKER: &str = "-- Omarchy Guardian: its theme and plugin commands first on PATH. Keep this after Omarchy's defaults.";
const HYPR_LINE: &str = "pcall(dofile, \"/usr/lib/omarchy-guardian/hyprland-path.lua\")";
/// The file uwsm sources for the graphical session, after Omarchy's own
/// (`10-omarchy`), and the line in it that counts.
const SESSION_ENV_NAME: &str = "90-omarchy-guardian";
const SESSION_ENV_LINE: &str = "export PATH=\"/usr/lib/omarchy-guardian/bin:$PATH\"";
pub(crate) const SESSION_ENV: &str = "# Omarchy Guardian: theme and plugin installs found on PATH go through Guardian.\n# Written by `omarchy-guardian protect`, removed by `omarchy-guardian protect --off`.\nexport PATH=\"/usr/lib/omarchy-guardian/bin:$PATH\"\n";
/// AUR helpers Guardian has no gate for.
const UNGATED_HELPERS: [&str; 3] = ["pikaur", "aura", "trizen"];
/// What is left of a file as it was before Guardian first edited it.
const BACKUP_SUFFIX: &str = ".guardian-bak";
const MENU_ID: &str = "\"setup.guardian\"";
/// The bar widget plugin the package ships, and its Omarchy plugin id.
pub const WIDGET_SOURCE: &str = "/usr/share/omarchy-guardian/bar-widget";
const WIDGET_ID: &str = "omarchy-guardian";
/// The Waybar module: an image module showing the Guardian knight (calm,
/// alert or dimmed), its name in a modules list, its definition (one line, so
/// it can be found and removed exactly), and the markers of its style block.
const WAYBAR_MODULE: &str = "\"image#omarchy-guardian\"";
const WAYBAR_DEFINITION: &str = "  \"image#omarchy-guardian\": {\"exec\": \"omarchy-guardian status --waybar\", \"size\": 18, \"interval\": 30, \"signal\": 9, \"tooltip\": true, \"on-click\": \"omarchy-launch-tui --app-id=TUI.float omarchy-guardian tui\", \"on-click-right\": \"omarchy-guardian status --open-report\"},";
const WAYBAR_STYLE_BEGIN: &str = "/* Omarchy Guardian: begin */";
const WAYBAR_STYLE_END: &str = "/* Omarchy Guardian: end */";
/// Waybar's CSS name for `image#omarchy-guardian`.
const WAYBAR_SELECTOR: &str = "#image.omarchy-guardian";
/// Omarchy menu items that install or update themes and plugins, overridden
/// so they run through Guardian. The menu keeps each item's other fields.
const THEME_OVERRIDES: [(&str, &str); 3] = [
    (
        "\"install.style.theme\"",
        "\"install.style.theme\": {\"action\":\"omarchy-launch-floating-terminal-with-presentation /usr/lib/omarchy-guardian/guardian-theme install\"},",
    ),
    (
        "\"update.themes\"",
        "\"update.themes\": {\"action\":\"omarchy-launch-floating-terminal-with-presentation /usr/lib/omarchy-guardian/guardian-theme update\"},",
    ),
    (
        "\"setup.plugin.add\"",
        "\"setup.plugin.add\": {\"action\":\"omarchy-launch-floating-terminal-with-presentation /usr/lib/omarchy-guardian/guardian-plugin add\"},",
    ),
];
/// What Guardian's own overrides run; a user's own override of these items
/// does not contain it.
const THEME_GATE: &str = "/usr/lib/omarchy-guardian/guardian-";
/// Installs OpenCode from the official repos, root-owned, where the pacman
/// gate looks for it.
const INSTALL_OPENCODE: [&str; 4] = ["/usr/bin/pacman", "-S", "--needed", "extra/opencode"];
/// The system sweep's timers, as the package installs them, and the links
/// `systemctl enable` makes for them.
const SWEEP_TIMER: &str = "omarchy-guardian-sweep.timer";
const SWEEP_ROOT_TIMER: &str = "omarchy-guardian-sweep-collect.timer";
pub const MENU_ENTRY: &str = "\"setup.guardian\": {\"icon\":\"󰒃\",\"label\":\"Guardian\",\"description\":\"Omarchy Guardian settings\",\"action\":\"omarchy-launch-tui --app-id=TUI.float omarchy-guardian tui\"},";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Integration {
    PacmanHook,
    AurGate,
    ThemeInterceptor,
    SessionPath,
    MenuEntry,
    BarWidget,
    WaybarModule,
    SystemSweep,
}

impl Integration {
    pub const ALL: [Self; 8] = [
        Self::PacmanHook,
        Self::AurGate,
        Self::ThemeInterceptor,
        Self::SessionPath,
        Self::MenuEntry,
        Self::BarWidget,
        Self::WaybarModule,
        Self::SystemSweep,
    ];

    pub const fn label(self) -> &'static str {
        match self {
            Self::PacmanHook => "Pacman hook",
            Self::AurGate => "AUR gate (yay)",
            Self::ThemeInterceptor => "Theme & plugin gate",
            Self::SessionPath => "Theme & plugin commands (PATH)",
            Self::MenuEntry => "Omarchy menu entry",
            Self::BarWidget => "Bar widget",
            Self::WaybarModule => "Waybar module",
            Self::SystemSweep => "System sweep",
        }
    }

    pub const fn help(self) -> &'static str {
        match self {
            Self::PacmanHook => {
                "Reviews install scriptlets before every pacman transaction. Needs a root-owned reviewer (claude-code or extra/opencode, matching the model) while pacman packages require AI; sudo to change."
            }
            Self::AurGate => "Makes yay build AUR packages through Guardian's makepkg gate.",
            Self::ThemeInterceptor => {
                "Routes theme and plugin installs and updates through Guardian, from Bash (new shells) and from the Omarchy menu."
            }
            Self::SessionPath => {
                "Puts Guardian's own `omarchy`, `omarchy-theme-install`, `omarchy-theme-update`, `omarchy-plugin-add` and `omarchy-plugin-update` first on the session's PATH, ahead of Omarchy's own (a line at the end of ~/.config/hypr/hyprland.lua and a file in ~/.config/uwsm/env.d), so scripts, other shells, launchers and key bindings go through Guardian too. Applies from the next login."
            }
            Self::MenuEntry => "Adds Setup › Guardian to the Omarchy menu, opening this window.",
            Self::BarWidget => {
                "A shield in the Omarchy bar showing whether Guardian protects this machine, what needs attention and the last block."
            }
            Self::SystemSweep => {
                "Checks daily what already runs on its own on this machine, and notifies about anything new that no package vouches for. Asks once whether the read-only root checks may run too."
            }
            Self::WaybarModule => {
                "The Guardian knight in Waybar: calm, red-eyed when something needs attention, dim when protection is off; its tooltip has the details, left-click opens this window, right-click the last report."
            }
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum State {
    On,
    Off,
    /// Present, but not the packaged setup (for example a hand-installed hook).
    Foreign(String),
    /// On, but not doing its whole job; turning it on again completes it.
    Partial(String),
    Unavailable(String),
}

/// One step of a plan.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Step {
    /// A program run on the terminal.
    Command(Vec<String>),
    /// A program run silently whose failure does not fail the plan.
    Optional(Vec<String>),
    RemoveInterceptor,
    AddMenuEntry,
    RemoveMenuEntry,
    AddThemeMenu,
    RemoveThemeMenu,
    InstallBarWidget,
    RemoveBarWidget,
    AddWaybarModule,
    RemoveWaybarModule,
    AddSessionPath,
    RemoveSessionPath,
    /// Asks whether the sweep's root checks may run, records the answer in
    /// the system configuration and, when allowed, enables their timer.
    AskSweepRoot,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Plan {
    pub summary: String,
    pub steps: Vec<Step>,
}

impl Plan {
    /// Lines describing exactly what will run or change.
    pub fn describe(&self, paths: &Paths) -> Vec<String> {
        self.steps
            .iter()
            .map(|step| match step {
                Step::Command(argv) => format!("run  {}", argv.join(" ")),
                Step::Optional(argv) => format!("run  {} (if available)", argv.join(" ")),
                Step::RemoveInterceptor => format!(
                    "edit {}: remove the Guardian interception lines",
                    paths.bashrc.display()
                ),
                Step::AddMenuEntry => {
                    format!("edit {}: add Setup › Guardian", paths.menu.display())
                }
                Step::RemoveMenuEntry => {
                    format!("edit {}: remove Setup › Guardian", paths.menu.display())
                }
                Step::AddThemeMenu => format!(
                    "edit {}: route the menu's theme install and update and plugin add through Guardian",
                    paths.menu.display()
                ),
                Step::RemoveThemeMenu => format!(
                    "edit {}: give the menu's theme and plugin items back to Omarchy",
                    paths.menu.display()
                ),
                Step::InstallBarWidget => format!(
                    "copy the Guardian bar widget into {}",
                    paths.widget_target.display()
                ),
                Step::RemoveBarWidget => format!("remove {}", paths.widget_target.display()),
                Step::AddWaybarModule => format!(
                    "edit {} and {}: add the Guardian module",
                    paths.waybar_config.display(),
                    paths.waybar_style.display()
                ),
                Step::RemoveWaybarModule => format!(
                    "edit {} and {}: remove the Guardian module",
                    paths.waybar_config.display(),
                    paths.waybar_style.display()
                ),
                Step::AddSessionPath => format!(
                    "write {}{}: put {} first on the session's PATH (from the next login)",
                    paths.session_env.display(),
                    if paths.hypr_config.is_file() {
                        format!(" and add a line to {}", paths.hypr_config.display())
                    } else {
                        String::new()
                    },
                    paths.wrappers.display()
                ),
                Step::RemoveSessionPath => format!(
                    "remove {}{}",
                    paths.session_env.display(),
                    if paths.hypr_config.is_file() {
                        format!(" and Guardian's line from {}", paths.hypr_config.display())
                    } else {
                        String::new()
                    }
                ),
                Step::AskSweepRoot => "ask whether the daily read-only root checks may run, then record the answer in the system configuration (sudo)".into(),
            })
            .collect()
    }

    /// Commands may ask for a password or print, so they run on the normal
    /// screen; optional steps (a menu refresh) run silently.
    pub fn needs_terminal(&self) -> bool {
        self.steps
            .iter()
            .any(|step| matches!(step, Step::Command(_) | Step::AskSweepRoot))
    }
}

/// Where each integration lives. Tests point these into a temporary
/// directory.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Paths {
    pub hook_source: PathBuf,
    pub hook_target: PathBuf,
    pub yay: PathBuf,
    pub yay_config: PathBuf,
    pub interceptor_installer: PathBuf,
    pub bashrc: PathBuf,
    pub omarchy: PathBuf,
    pub menu: PathBuf,
    pub widget_source: PathBuf,
    pub widget_target: PathBuf,
    pub shell_config: PathBuf,
    pub waybar_config: PathBuf,
    pub waybar_style: PathBuf,
    /// The pacman gate needs a root-owned OpenCode and none is installed
    /// (see `pacman::preflight`).
    pub opencode_missing: bool,
    /// The sweep's user timer as packaged, and its enable link.
    pub sweep_timer: PathBuf,
    pub sweep_timer_link: PathBuf,
    /// The sweep's root timer as packaged, and its enable link.
    pub sweep_root_timer: PathBuf,
    pub sweep_root_timer_link: PathBuf,
    /// What the system configuration says about the root checks, and the
    /// group allowed to read the daily results.
    pub sweep_consent: Option<RootConsent>,
    pub sweep_group: Option<String>,
    /// The files that stand in for, or change, one of the sweep's own
    /// units (see `sweep::own`), relative to the root.
    pub sweep_overrides: Vec<String>,
    /// The name of the user's login shell (`bash`, `zsh`), if known.
    pub login_shell: Option<String>,
    /// Guardian's makepkg shim, which yay is pointed at.
    pub makepkg_gate: PathBuf,
    /// Who must own the files Guardian installs: root. Tests, which cannot
    /// make root's files, name their own user.
    pub owner: u32,
    /// Where other AUR helpers are installed.
    pub system_bin: PathBuf,
    pub paru_config: PathBuf,
    /// The shell start-up files an alias or function could be in.
    pub shell_startup: Vec<PathBuf>,
    /// This process's PATH, and the session service manager's if it can
    /// be asked.
    pub path_dirs: Vec<PathBuf>,
    pub manager_path: Option<Vec<PathBuf>>,
    /// The wrapper commands as packaged, and the session file that puts
    /// them first on PATH.
    pub wrappers: PathBuf,
    pub session_env: PathBuf,
    /// The user's Hyprland Lua configuration, which gets Guardian's line,
    /// and the packaged file that line loads.
    pub hypr_config: PathBuf,
    pub hypr_path: PathBuf,
}

/// The directories of a PATH value.
fn path_list(path: &std::ffi::OsStr) -> Vec<PathBuf> {
    env::split_paths(path).collect()
}

/// The PATH the session's service manager gives what it starts, if there
/// is a manager to ask.
fn manager_path() -> Option<Vec<PathBuf>> {
    let shown = crate::tools::run(
        Path::new("/usr/bin/systemctl"),
        &["--user".into(), "show-environment".into()],
        None,
        &[],
        crate::tools::Limits {
            timeout_secs: 5,
            max_output: 256 * 1024,
        },
    )
    .ok()
    .filter(|shown| shown.status.success())?;
    String::from_utf8_lossy(&shown.stdout)
        .lines()
        .find_map(|line| line.strip_prefix("PATH="))
        .map(|path| path_list(std::ffi::OsStr::new(path)))
}

/// One half of the theme & plugin gate.
#[derive(Clone, Debug, PartialEq, Eq)]
enum Part {
    On,
    Off,
    /// Written, and not in effect: why.
    Broken(String),
}

/// The login shell's name: of the user's `/etc/passwd` entry, else of
/// `SHELL`.
fn login_shell() -> Option<String> {
    let uid = crate::user::real_uid();
    let shell = fs::read_to_string("/etc/passwd")
        .ok()
        .and_then(|passwd| uid.and_then(|uid| shell_of(&passwd, uid)))
        .or_else(|| env::var("SHELL").ok())?;
    shell
        .rsplit('/')
        .next()
        .filter(|name| !name.is_empty())
        .map(str::to_string)
}

/// The shell of `uid`'s entry in `passwd`, if it has one and names one.
fn shell_of(passwd: &str, uid: u32) -> Option<String> {
    let uid = uid.to_string();
    passwd
        .lines()
        .map(|line| line.split(':').collect::<Vec<_>>())
        .find(|fields| fields.get(2) == Some(&uid.as_str()))
        .and_then(|fields| fields.get(6).map(|shell| (*shell).to_string()))
        .filter(|shell| !shell.is_empty())
}

impl Paths {
    pub fn real(
        opencode_missing: bool,
        (sweep_consent, sweep_group): (Option<RootConsent>, Option<String>),
    ) -> Option<Self> {
        let home = env::var_os("HOME")
            .map(PathBuf::from)
            .filter(|path| path.is_absolute())?;
        // With an absolute HOME there is always one.
        let config = paths::config_home(Accept::Absolute, Accept::Absolute)?;
        Some(Self {
            hook_source: HOOK_SOURCE.into(),
            hook_target: HOOK_TARGET.into(),
            yay: "/usr/bin/yay".into(),
            yay_config: config.join("yay/config.json"),
            interceptor_installer: INTERCEPTOR_INSTALLER.into(),
            bashrc: home.join(".bashrc"),
            omarchy: "/usr/share/omarchy".into(),
            // Where the menu itself looks: under HOME, whatever
            // XDG_CONFIG_HOME says.
            menu: home.join(".config/omarchy/extensions/omarchy-menu.jsonc"),
            widget_source: WIDGET_SOURCE.into(),
            widget_target: config.join("omarchy/plugins").join(WIDGET_ID),
            shell_config: config.join("omarchy/shell.json"),
            // Waybar reads `config.jsonc` before `config`.
            waybar_config: ["waybar/config.jsonc", "waybar/config"]
                .iter()
                .map(|name| config.join(name))
                .find(|path| path.is_file())
                .unwrap_or_else(|| config.join("waybar/config.jsonc")),
            waybar_style: config.join("waybar/style.css"),
            opencode_missing,
            sweep_timer: Path::new("/usr/lib/systemd/user").join(SWEEP_TIMER),
            sweep_timer_link: config
                .join("systemd/user/timers.target.wants")
                .join(SWEEP_TIMER),
            sweep_root_timer: Path::new("/usr/lib/systemd/system").join(SWEEP_ROOT_TIMER),
            sweep_root_timer_link: Path::new("/etc/systemd/system/timers.target.wants")
                .join(SWEEP_ROOT_TIMER),
            sweep_consent,
            sweep_group,
            sweep_overrides: own::standing(
                Path::new("/"),
                home.to_str().map(|home| home.trim_matches('/')),
            ),
            login_shell: login_shell(),
            makepkg_gate: MAKEPKG_GATE.into(),
            owner: 0,
            system_bin: "/usr/bin".into(),
            paru_config: config.join("paru/paru.conf"),
            shell_startup: [
                ".bashrc",
                ".bash_profile",
                ".bash_login",
                ".profile",
                ".bash_aliases",
                ".zshrc",
                ".zshenv",
                ".zprofile",
            ]
            .iter()
            .map(|name| home.join(name))
            .chain([config.join("fish/config.fish")])
            .collect(),
            path_dirs: env::var_os("PATH")
                .map(|path| path_list(&path))
                .unwrap_or_default(),
            manager_path: manager_path(),
            wrappers: WRAPPERS.into(),
            session_env: config.join("uwsm/env.d").join(SESSION_ENV_NAME),
            hypr_config: config.join("hypr/hyprland.lua"),
            hypr_path: HYPR_PATH.into(),
        })
    }

    pub fn state(&self, integration: Integration) -> State {
        match integration {
            Integration::PacmanHook => self.hook_state(),
            Integration::AurGate => self.aur_state(),
            Integration::ThemeInterceptor => {
                if !self.interceptor_installer.exists() {
                    return State::Unavailable(
                        "the omarchy-guardian package is not installed".into(),
                    );
                }
                match self.theme_parts() {
                    (Part::Broken(why), _) | (_, Some(Part::Broken(why))) => State::Partial(why),
                    (Part::On, None | Some(Part::On)) => State::On,
                    (Part::On, Some(Part::Off)) => State::Partial(
                        "terminal only: themes and plugins from the Omarchy menu skip Guardian"
                            .into(),
                    ),
                    (Part::Off, Some(Part::On)) => State::Partial(
                        "menu only: `omarchy theme` and `omarchy plugin` in Bash skip Guardian"
                            .into(),
                    ),
                    (Part::Off, None | Some(Part::Off)) => State::Off,
                }
            }
            Integration::SessionPath => self.session_state(),
            Integration::MenuEntry => {
                if !self.omarchy.is_dir() {
                    return State::Unavailable("Omarchy is not installed".into());
                }
                let Ok(text) = fs::read_to_string(&self.menu) else {
                    return State::Off;
                };
                let written = text.lines().any(|line| names(line, MENU_ID));
                match menufile::items(&text) {
                    Ok(items)
                        if menufile::action(&items, MENU_ID.trim_matches('"'))
                            == menu_action(MENU_ENTRY).as_deref() =>
                    {
                        State::On
                    }
                    Ok(_) if written => State::Partial(
                        "in the menu file, but a later entry of the same name replaces it".into(),
                    ),
                    Err(why) if written => State::Partial(format!(
                        "in the menu file, but the Omarchy menu ignores that file: {why}"
                    )),
                    Ok(_) | Err(_) => State::Off,
                }
            }
            Integration::BarWidget => self.widget_state(),
            Integration::WaybarModule => self.waybar_state(),
            Integration::SystemSweep => self.sweep_state(),
        }
    }

    /// What the theme & plugin gate does not cover while it is on: its
    /// interceptor is a Bash file, so what is typed in another login shell
    /// goes straight to Omarchy. Nothing here can turn that on, so it is
    /// said beside the gate rather than counted as a fault.
    pub fn theme_caveat(&self) -> Option<String> {
        // With Guardian's commands first on PATH every shell finds them.
        if self.session_state() == State::On {
            return None;
        }
        let shell = self
            .login_shell
            .as_deref()
            .filter(|shell| !matches!(*shell, "bash" | "sh"))?;
        Some(format!(
            "Bash and the Omarchy menu only: `omarchy theme` and `omarchy plugin` typed in {shell} skip Guardian"
        ))
    }

    fn sweep_state(&self) -> State {
        if !self.sweep_timer.is_file() || !self.sweep_root_timer.is_file() {
            return State::Unavailable("the omarchy-guardian package is not installed".into());
        }
        let user = fs::symlink_metadata(&self.sweep_timer_link).is_ok();
        let root = fs::symlink_metadata(&self.sweep_root_timer_link).is_ok();
        // A unit file of the sweep's own name, or a drop-in for it, in a
        // directory systemd reads before the package's: the link is there
        // and the sweep may not run, or not look at this home. The same
        // files the sweep itself alerts on.
        if (user || root)
            && let Some(first) = self.sweep_overrides.first()
        {
            let more = match self.sweep_overrides.len() - 1 {
                0 => String::new(),
                more => format!(" and {more} more"),
            };
            return State::Partial(format!(
                "/{first}{more} overrides or masks the sweep's own unit, so it may not run as packaged"
            ));
        }
        match (user, self.sweep_consent, root) {
            (false, _, true) => State::Partial(
                "the daily root checks run, but the sweep itself is off".into(),
            ),
            (false, _, false) => State::Off,
            (true, Some(RootConsent::Allowed), true) => State::On,
            (true, Some(RootConsent::Allowed), false) if self.sweep_group.is_none() => {
                State::Partial(
                    "root checks only with `sweep --root`: no private group to share daily results with"
                        .into(),
                )
            }
            (true, Some(RootConsent::Allowed), false) => {
                State::Partial("root checks allowed, but their timer is off".into())
            }
            (true, Some(RootConsent::Declined), _) => State::Partial(
                "root checks declined: what only root can read is not checked".into(),
            ),
            (true, None, _) => State::Partial("root checks not set up yet".into()),
        }
    }

    /// Turns the sweep on (asking about the root checks when they were never
    /// answered, or were declined) or off (the answer is kept).
    fn sweep_steps(&self, on: bool) -> Vec<Step> {
        let user = fs::symlink_metadata(&self.sweep_timer_link).is_ok();
        let root = fs::symlink_metadata(&self.sweep_root_timer_link).is_ok();
        let mut steps = Vec::new();
        if on {
            // The root question first, so the first daily sweep (started
            // right away) already knows the answer.
            match self.sweep_consent {
                Some(RootConsent::Allowed) if !root && self.sweep_group.is_some() => {
                    steps.push(sudo(&[
                        "/usr/bin/systemctl",
                        "enable",
                        "--now",
                        SWEEP_ROOT_TIMER,
                    ]));
                }
                Some(RootConsent::Allowed) => {}
                None | Some(RootConsent::Declined) => steps.push(Step::AskSweepRoot),
            }
            if !user {
                steps.push(Step::Command(vec![
                    "systemctl".into(),
                    "--user".into(),
                    "enable".into(),
                    "--now".into(),
                    SWEEP_TIMER.into(),
                ]));
            }
        } else {
            if user {
                steps.push(Step::Command(vec![
                    "systemctl".into(),
                    "--user".into(),
                    "disable".into(),
                    "--now".into(),
                    SWEEP_TIMER.into(),
                ]));
            }
            if root {
                steps.push(sudo(&[
                    "/usr/bin/systemctl",
                    "disable",
                    "--now",
                    SWEEP_ROOT_TIMER,
                ]));
            }
        }
        steps
    }

    fn waybar_state(&self) -> State {
        let Ok(config) = fs::read_to_string(&self.waybar_config) else {
            return State::Unavailable("no Waybar configuration".into());
        };
        let key = format!("{WAYBAR_MODULE}:");
        let definitions: Vec<&str> = config
            .lines()
            .filter(|line| line.trim_start().starts_with(&key))
            .collect();
        let placed = config
            .lines()
            .any(|line| names(line, WAYBAR_MODULE) && !line.trim_start().starts_with(&key));
        let styled = fs::read_to_string(&self.waybar_style).is_ok_and(|style| {
            style.contains(WAYBAR_STYLE_BEGIN) && style.contains(WAYBAR_STYLE_END)
        });
        // Only Guardian's current line counts: an edited or older one (a
        // different command, size or click action) is replaced by turning
        // the module on.
        let current = definitions.as_slice() == [WAYBAR_DEFINITION];
        match (definitions.is_empty(), placed, styled) {
            (true, false, _) => State::Off,
            (false, true, true) if current => State::On,
            (false, _, _) if !current => State::Partial(
                "its config line is not Guardian's current one; turning it on replaces it".into(),
            ),
            _ => State::Partial("partly set up; turning it on completes it".into()),
        }
    }

    fn widget_state(&self) -> State {
        if !self.widget_source.is_dir() {
            return State::Unavailable("the omarchy-guardian package is not installed".into());
        }
        if !self.omarchy.join("bin/omarchy-plugin-enable").exists() {
            return State::Unavailable("this Omarchy has no shell plugins".into());
        }
        let installed = self.widget_target.join("manifest.json").is_file();
        let current = installed && self.widget_is_current();
        match (installed, self.widget_in_bar()) {
            (true, true) if current => State::On,
            (true, true) => State::Partial("an older copy; turning it on updates it".into()),
            (true, false) => State::Partial("installed but not in the bar".into()),
            (false, _) => State::Off,
        }
    }

    /// Whether every packaged widget file is installed unchanged.
    fn widget_is_current(&self) -> bool {
        widget_files(&self.widget_source).iter().all(|name| {
            fs::read(self.widget_source.join(name)).ok()
                == fs::read(self.widget_target.join(name)).ok()
        })
    }

    /// Whether the widget is placed in the bar (`bar.layout` of shell.json).
    fn widget_in_bar(&self) -> bool {
        let Some(config) = fs::read_to_string(&self.shell_config)
            .ok()
            .and_then(|text| Json::parse(&text).ok())
        else {
            return false;
        };
        let Some(layout) = config.get("bar").and_then(|bar| bar.get("layout")) else {
            return false;
        };
        ["left", "center", "right"].iter().any(|section| {
            layout
                .get(section)
                .and_then(Json::as_array)
                .is_some_and(|entries| {
                    entries
                        .iter()
                        .any(|entry| entry.get("id").and_then(Json::as_str) == Some(WIDGET_ID))
                })
        })
    }

    fn hook_state(&self) -> State {
        if !self.hook_source.exists() {
            return State::Unavailable("the omarchy-guardian package is not installed".into());
        }
        match fs::read_link(&self.hook_target) {
            Ok(target) if target == self.hook_source && self.opencode_missing => State::Partial(
                "on, but refuses packages that need AI: no root-owned OpenCode".into(),
            ),
            Ok(target) if target == self.hook_source => State::On,
            Ok(target) => State::Foreign(format!("links to {}", target.display())),
            Err(_) if fs::symlink_metadata(&self.hook_target).is_ok() => {
                State::Foreign("a hand-installed hook file".into())
            }
            Err(_) => State::Off,
        }
    }

    /// The yay gate: on when yay's saved configuration builds through
    /// Guardian's shim, the shim is root's, and nothing in front of yay
    /// (another yay on PATH, an alias or function passing `--makepkg`)
    /// takes the build elsewhere.
    fn aur_state(&self) -> State {
        if !self.yay.exists() {
            return State::Unavailable("yay is not installed".into());
        }
        let makepkg = fs::read_to_string(&self.yay_config)
            .ok()
            .and_then(|text| Json::parse(&text).ok())
            .and_then(|config| {
                config
                    .get("makepkgbin")
                    .and_then(Json::as_str)
                    .map(str::to_string)
            });
        match makepkg.as_deref() {
            Some(gate) if Path::new(gate) == self.makepkg_gate => {}
            None | Some("" | "makepkg" | "/usr/bin/makepkg") => return State::Off,
            Some(other) => {
                return State::Partial(format!(
                    "not on: yay builds with {other}, which is not Guardian's gate"
                ));
            }
        }
        if let Err(why) = self.installed_file(&self.makepkg_gate) {
            return State::Partial(format!("configured but not to be trusted: {why}"));
        }
        if let Some(first) = self.first_on_path("yay")
            && fs::canonicalize(&self.yay).ok().as_ref() != Some(&first)
        {
            return State::Partial(format!(
                "configured but bypassed: another yay comes first on PATH ({})",
                first.display()
            ));
        }
        if let Some(file) = self.makepkg_override("yay") {
            return State::Partial(format!(
                "configured but bypassed: an alias or function named yay in {} passes --makepkg",
                file.display()
            ));
        }
        State::On
    }

    /// AUR helpers on this machine that build without Guardian: one line
    /// each, for the bar's list of problems.
    pub fn helper_issues(&self) -> Vec<String> {
        let mut issues = Vec::new();
        if self.system_bin.join("paru").exists() {
            // paru.conf: `Makepkg = <command>` under `[bin]`.
            let routed = fs::read_to_string(&self.paru_config).is_ok_and(|text| {
                let mut section = "";
                text.lines().map(str::trim).any(|line| {
                    if line.starts_with('[') {
                        section = line;
                    }
                    section == "[bin]"
                        && line.split_once('=').is_some_and(|(key, value)| {
                            key.trim() == "Makepkg" && Path::new(value.trim()) == self.makepkg_gate
                        })
                })
            });
            if !routed {
                issues.push(format!(
                    "paru builds AUR packages without Guardian (set `Makepkg = {}` under `[bin]` in {})",
                    self.makepkg_gate.display(),
                    self.paru_config.display()
                ));
            } else if let Some(file) = self.makepkg_override("paru") {
                issues.push(format!(
                    "paru builds AUR packages without Guardian: an alias or function named paru in {} passes --makepkg",
                    file.display()
                ));
            }
        }
        for helper in UNGATED_HELPERS {
            if self.system_bin.join(helper).exists() {
                issues.push(format!("{helper} builds AUR packages without Guardian"));
            }
        }
        issues
    }

    /// The start-up file in which an alias or function called `helper`
    /// passes `--makepkg`.
    fn makepkg_override(&self, helper: &str) -> Option<&Path> {
        self.shell_startup
            .iter()
            .find(|file| {
                fs::read_to_string(file).is_ok_and(|text| {
                    shellscan::overrides_makepkg(
                        &text,
                        helper,
                        &self.makepkg_gate.to_string_lossy(),
                    )
                })
            })
            .map(PathBuf::as_path)
    }

    /// The PATH the session finds commands on: its service manager's, the
    /// same for every caller. Only without a manager to ask is it this
    /// process's own.
    fn session_path(&self) -> &[PathBuf] {
        self.manager_path.as_deref().unwrap_or(&self.path_dirs)
    }

    /// The integrations whose state hangs on a PATH, when the session's
    /// own could not be asked: what they read here is this caller's view,
    /// which another caller need not share, so it is not put on record
    /// (see `gatewatch`).
    pub fn unsettled(&self) -> Vec<Integration> {
        if self.manager_path.is_some() {
            Vec::new()
        } else {
            vec![Integration::AurGate, Integration::SessionPath]
        }
    }

    /// Whether there is anything on this machine for `integration` to
    /// guard or attach to: the AUR gate needs yay, the PATH wrappers and
    /// the menu entry need Omarchy. One that does not apply is not
    /// protection missing.
    pub fn applies(&self, integration: Integration) -> bool {
        match integration {
            Integration::AurGate => self.yay.exists(),
            Integration::SessionPath | Integration::MenuEntry => self.omarchy.is_dir(),
            _ => true,
        }
    }

    /// The first program called `name` on the session's PATH, resolved.
    fn first_on_path(&self, name: &str) -> Option<PathBuf> {
        self.session_path()
            .iter()
            .filter(|directory| directory.is_absolute())
            .map(|directory| directory.join(name))
            .find(|candidate| candidate.is_file())
            .and_then(|candidate| fs::canonicalize(candidate).ok())
    }

    /// Checks that `path` is a file Guardian's package installed: a
    /// regular file owned by root that only root can write, in such a
    /// directory. Anything else could be replaced by the user's programs.
    fn installed_file(&self, path: &Path) -> Result<(), String> {
        let metadata =
            fs::symlink_metadata(path).map_err(|_| format!("{} is missing", path.display()))?;
        if !metadata.file_type().is_file() {
            return Err(format!("{} is not a regular file", path.display()));
        }
        let directory = path.parent().and_then(|parent| fs::metadata(parent).ok());
        for metadata in std::iter::once(metadata).chain(directory) {
            if metadata.uid() != self.owner || metadata.mode() & 0o022 != 0 {
                return Err(format!("{} is not root's alone to write", path.display()));
            }
        }
        Ok(())
    }

    /// The wrappers on the session's PATH: on when Guardian's line is in
    /// the Hyprland configuration where it runs, the uwsm session file
    /// holds Guardian's line, the wrappers are root's, and the session's
    /// PATH finds them before any other command of those names.
    fn session_state(&self) -> State {
        if !self.wrappers.is_dir() {
            return State::Unavailable("the omarchy-guardian package is not installed".into());
        }
        if !self.omarchy.is_dir() {
            return State::Unavailable("Omarchy is not installed".into());
        }
        let env = fs::read_to_string(&self.session_env).is_ok_and(|text| {
            let code: Vec<&str> = text
                .lines()
                .map(str::trim)
                .filter(|line| !line.is_empty() && !line.starts_with('#'))
                .collect();
            code == [SESSION_ENV_LINE]
        });
        // Without a Hyprland Lua configuration nothing reorders what the
        // session file set, and there is no line to write.
        let hypr = fs::read_to_string(&self.hypr_config)
            .ok()
            .map(|text| luascan::loads(&text, HYPR_LINE, HYPR_PATH));
        match (env, &hypr) {
            (false, None | Some(Loads::Missing)) => return State::Off,
            (_, Some(Loads::Ineffective(why))) => {
                return State::Partial(format!(
                    "not effective: Guardian's line is in {}, but {why}",
                    self.hypr_config.display()
                ));
            }
            (false, Some(Loads::Effective)) => {
                return State::Partial(format!(
                    "half set up: {} is not Guardian's; turning it on completes it",
                    self.session_env.display()
                ));
            }
            (true, Some(Loads::Missing)) => {
                return State::Partial(format!(
                    "half set up: Guardian's line is not in {}, so Omarchy's own PATH line puts its commands first; turning it on completes it",
                    self.hypr_config.display()
                ));
            }
            (true, None | Some(Loads::Effective)) => {}
        }
        let installed = WRAPPED
            .iter()
            .map(|name| self.wrappers.join(name))
            .chain(hypr.is_some().then(|| self.hypr_path.clone()));
        for file in installed {
            if let Err(why) = self.installed_file(&file) {
                return State::Partial(format!("set up but not to be trusted: {why}"));
            }
        }
        if let Some(why) = self.path_problem(self.session_path()) {
            let whose = if self.manager_path.is_some() {
                "the session"
            } else {
                "this shell (the session's service manager did not answer)"
            };
            return State::Partial(format!(
                "set up, but not in effect for {whose}: {why}. It applies from the next login; if it stays after one, something else reorders PATH"
            ));
        }
        State::On
    }

    /// What to say beside the wrappers while they are on for the session
    /// and this caller's own shell finds something else first: its start-up
    /// files reorder PATH. Said to this caller only, never put on record.
    pub fn path_caveat(&self) -> Option<String> {
        self.manager_path.as_ref()?;
        if self.path_dirs.is_empty() || self.session_state() != State::On {
            return None;
        }
        let why = self.path_problem(&self.path_dirs)?;
        Some(format!(
            "on for the session, not for the shell this was asked from: {why}"
        ))
    }

    /// Why the wrappers are not what `directories` (a PATH) finds first.
    fn path_problem(&self, directories: &[PathBuf]) -> Option<String> {
        let Some(position) = directories
            .iter()
            .position(|directory| *directory == self.wrappers)
        else {
            return Some(format!("{} is not on PATH", self.wrappers.display()));
        };
        directories[..position]
            .iter()
            .flat_map(|directory| WRAPPED.iter().map(move |name| directory.join(name)))
            .find(|candidate| candidate.is_file())
            .map(|candidate| format!("{} comes before it on PATH", candidate.display()))
    }

    /// The Bash interceptor in `~/.bashrc`, and the Omarchy menu's theme
    /// and plugin items (`None` without Omarchy).
    fn theme_parts(&self) -> (Part, Option<Part>) {
        // Guardian's own line where it runs, not the marker above it or a
        // line that merely names the file.
        let bash = match fs::read_to_string(&self.bashrc)
            .map(|text| shellscan::interceptor(&text, INTERCEPTOR_LINE, INTERCEPTOR_SOURCE))
        {
            Ok(Loads::Effective) => Part::On,
            Ok(Loads::Ineffective(why)) => Part::Broken(format!(
                "not effective in Bash: the interceptor's line is in {}, but {why}",
                self.bashrc.display()
            )),
            Ok(Loads::Missing) | Err(_) => Part::Off,
        };
        let menu = self.omarchy.is_dir().then(|| self.menu_part());
        (bash, menu)
    }

    /// Whether the menu's theme and plugin items run Guardian: by the
    /// entry in effect for each, as the menu reads its file.
    fn menu_part(&self) -> Part {
        let Ok(text) = fs::read_to_string(&self.menu) else {
            return Part::Off;
        };
        let written = THEME_OVERRIDES
            .iter()
            .filter(|(id, _)| {
                text.lines()
                    .any(|line| names(line, id) && line.contains(THEME_GATE))
            })
            .count();
        let items = match menufile::items(&text) {
            Ok(items) => items,
            Err(_) if written == 0 => return Part::Off,
            Err(why) => {
                return Part::Broken(format!(
                    "not effective in the Omarchy menu, which ignores its user file: {why}"
                ));
            }
        };
        let replaced = THEME_OVERRIDES.iter().find(|(id, entry)| {
            menufile::action(&items, id.trim_matches('"')) != menu_action(entry).as_deref()
        });
        match replaced {
            None => Part::On,
            Some(_) if written == 0 => Part::Off,
            Some((id, _)) => Part::Broken(format!(
                "not effective in the Omarchy menu: the entry in effect for {id} is not Guardian's"
            )),
        }
    }

    /// The plan that flips `integration` from `state`; `None` when it
    /// cannot be changed from here.
    pub fn plan(&self, integration: Integration, state: &State) -> Option<Plan> {
        let text = |path: &Path| path.display().to_string();
        let on = match state {
            State::On => false,
            State::Off | State::Foreign(_) | State::Partial(_) => true,
            State::Unavailable(_) => return None,
        };

        let (summary, steps) = match (integration, on) {
            (Integration::PacmanHook, true) => ("Enable the pacman hook", self.hook_steps(state)),
            (Integration::PacmanHook, false) => (
                "Disable the pacman hook",
                vec![sudo(&["/usr/bin/rm", "-f", &text(&self.hook_target)])],
            ),
            (Integration::SessionPath, true) => (
                "Put Guardian's theme & plugin commands first on PATH",
                vec![Step::AddSessionPath],
            ),
            (Integration::SessionPath, false) => (
                "Take Guardian's theme & plugin commands off PATH",
                vec![Step::RemoveSessionPath],
            ),
            (Integration::AurGate, true) => ("Enable the AUR gate", self.aur_steps(on)),
            (Integration::AurGate, false) => ("Disable the AUR gate", self.aur_steps(on)),
            (Integration::ThemeInterceptor, _) => (
                if on {
                    "Enable the theme & plugin gate"
                } else {
                    "Disable the theme & plugin gate"
                },
                self.theme_steps(on),
            ),
            (Integration::BarWidget, _) => (
                if on {
                    "Add the Guardian bar widget"
                } else {
                    "Remove the Guardian bar widget"
                },
                self.widget_steps(on),
            ),
            (Integration::WaybarModule, _) => (
                if on {
                    "Add the Guardian Waybar module"
                } else {
                    "Remove the Guardian Waybar module"
                },
                vec![
                    if on {
                        Step::AddWaybarModule
                    } else {
                        Step::RemoveWaybarModule
                    },
                    // SIGUSR2 makes a running Waybar reload its config and style.
                    Step::Optional(vec![
                        "pkill".into(),
                        "-SIGUSR2".into(),
                        "-x".into(),
                        "waybar".into(),
                    ]),
                ],
            ),
            (Integration::SystemSweep, _) => (
                if on {
                    "Turn the system sweep on"
                } else {
                    "Turn the system sweep off"
                },
                self.sweep_steps(on),
            ),
            (Integration::MenuEntry, _) => (
                if on {
                    "Add the Omarchy menu entry"
                } else {
                    "Remove the Omarchy menu entry"
                },
                vec![
                    if on {
                        Step::AddMenuEntry
                    } else {
                        Step::RemoveMenuEntry
                    },
                    refresh(),
                ],
            ),
        };
        Some(Plan {
            summary: summary.to_string(),
            steps,
        })
    }

    /// Points yay's saved configuration at Guardian's shim, or back at
    /// makepkg.
    fn aur_steps(&self, on: bool) -> Vec<Step> {
        let makepkg = if on {
            self.makepkg_gate.display().to_string()
        } else {
            "makepkg".into()
        };
        vec![Step::Command(vec![
            self.yay.display().to_string(),
            "--makepkg".into(),
            makepkg,
            "--save".into(),
            "-P".into(),
            "--stats".into(),
        ])]
    }

    /// Turns the hook on. Without OpenCode it would refuse every package
    /// that needs the AI review, so OpenCode is installed first.
    fn hook_steps(&self, state: &State) -> Vec<Step> {
        let mut steps = Vec::new();
        if self.opencode_missing {
            steps.push(sudo(&INSTALL_OPENCODE));
        }
        if !matches!(state, State::Partial(_)) {
            steps.push(sudo(&[
                "/usr/bin/install",
                "-d",
                "-m",
                "0755",
                "/etc/pacman.d/hooks",
            ]));
            steps.push(sudo(&[
                "/usr/bin/ln",
                "-sfn",
                &self.hook_source.display().to_string(),
                &self.hook_target.display().to_string(),
            ]));
        }
        steps
    }

    /// Installs (or updates) the widget and puts it in the bar, or takes it
    /// out and removes it.
    fn widget_steps(&self, on: bool) -> Vec<Step> {
        let omarchy_bin = |name: &str| self.omarchy.join("bin").join(name).display().to_string();
        if on {
            let mut steps = vec![
                Step::InstallBarWidget,
                Step::Optional(vec![
                    "omarchy-shell".into(),
                    "shell".into(),
                    "rescanPlugins".into(),
                ]),
            ];
            if !self.widget_in_bar() {
                steps.push(Step::Command(vec![
                    omarchy_bin("omarchy-plugin-enable"),
                    WIDGET_ID.into(),
                ]));
            }
            steps
        } else {
            vec![
                Step::Optional(vec![
                    omarchy_bin("omarchy-plugin-disable"),
                    WIDGET_ID.into(),
                ]),
                Step::RemoveBarWidget,
            ]
        }
    }

    /// Brings both halves of the theme gate, Bash and the Omarchy menu, to
    /// `on`. A half that is written and not in effect is written anew, at
    /// the end of its file, where nothing after it undoes it.
    fn theme_steps(&self, on: bool) -> Vec<Step> {
        let (bash, menu) = self.theme_parts();
        let install = Step::Command(vec![self.interceptor_installer.display().to_string()]);
        let mut steps = Vec::new();
        match (on, bash) {
            (true, Part::Off) => steps.push(install),
            (true, Part::Broken(_)) => steps.extend([Step::RemoveInterceptor, install]),
            (false, Part::On | Part::Broken(_)) => steps.push(Step::RemoveInterceptor),
            (true, Part::On) | (false, Part::Off) => {}
        }
        match (on, menu) {
            (true, Some(Part::Off)) => steps.extend([Step::AddThemeMenu, refresh()]),
            (true, Some(Part::Broken(_))) => {
                steps.extend([Step::RemoveThemeMenu, Step::AddThemeMenu, refresh()]);
            }
            (false, Some(Part::On | Part::Broken(_))) => {
                steps.extend([Step::RemoveThemeMenu, refresh()]);
            }
            (true, Some(Part::On) | None) | (false, Some(Part::Off) | None) => {}
        }
        steps
    }

    /// Applies one file-editing step.
    pub fn edit(&self, step: &Step) -> Result<(), String> {
        match step {
            Step::RemoveInterceptor => {
                let text = fs::read_to_string(&self.bashrc).map_err(|error| error.to_string())?;
                // The file a symlinked ~/.bashrc names is replaced, so the
                // link stays one.
                edit_file(&self.bashrc, &without_interceptor(&text))
            }
            Step::AddMenuEntry => self.add_menu_lines(&[MENU_ENTRY]),
            Step::RemoveMenuEntry => self.remove_menu_lines(&|line| names(line, MENU_ID)),
            Step::AddThemeMenu => {
                let existing = fs::read_to_string(&self.menu).unwrap_or_default();
                let missing: Vec<&str> = THEME_OVERRIDES
                    .iter()
                    .filter(|(id, _)| {
                        !existing
                            .lines()
                            .any(|line| line.contains(id) && line.contains(THEME_GATE))
                    })
                    .map(|(_, entry)| *entry)
                    .collect();
                self.add_menu_lines(&missing)
            }
            // Only Guardian's overrides; a user's own override of these
            // items is left alone.
            Step::RemoveThemeMenu => self.remove_menu_lines(&|line| {
                line.contains(THEME_GATE) && THEME_OVERRIDES.iter().any(|(id, _)| line.contains(id))
            }),
            Step::InstallBarWidget => {
                fs::create_dir_all(&self.widget_target).map_err(|error| error.to_string())?;
                for name in widget_files(&self.widget_source) {
                    fs::copy(
                        self.widget_source.join(&name),
                        self.widget_target.join(&name),
                    )
                    .map_err(|error| format!("{name}: {error}"))?;
                }
                Ok(())
            }
            // Only a folder holding Guardian's own widget is removed.
            Step::RemoveBarWidget => {
                let manifest = self.widget_target.join("manifest.json");
                let ours = fs::read_to_string(&manifest)
                    .ok()
                    .and_then(|text| Json::parse(&text).ok())
                    .is_some_and(|json| json.get("id").and_then(Json::as_str) == Some(WIDGET_ID));
                if !ours {
                    return Ok(());
                }
                fs::remove_dir_all(&self.widget_target).map_err(|error| error.to_string())
            }
            Step::AddWaybarModule => {
                let config =
                    fs::read_to_string(&self.waybar_config).map_err(|error| error.to_string())?;
                edit_file(&self.waybar_config, &with_waybar_module(&config)?)?;
                let style = without_waybar_style(
                    &fs::read_to_string(&self.waybar_style).unwrap_or_default(),
                );
                let separator = if style.is_empty() || style.ends_with('\n') {
                    ""
                } else {
                    "\n"
                };
                edit_file(
                    &self.waybar_style,
                    &format!("{style}{separator}\n{}", waybar_style(&style)),
                )
            }
            Step::RemoveWaybarModule => {
                if let Ok(config) = fs::read_to_string(&self.waybar_config) {
                    edit_file(&self.waybar_config, &without_waybar_module(&config))?;
                }
                if let Ok(style) = fs::read_to_string(&self.waybar_style) {
                    edit_file(&self.waybar_style, &without_waybar_style(&style))?;
                }
                Ok(())
            }
            Step::AddSessionPath => {
                if let Some(directory) = self.session_env.parent() {
                    fs::create_dir_all(directory).map_err(|error| error.to_string())?;
                }
                replace_file(&self.session_env, SESSION_ENV)?;
                // A line where it runs is left where it is; one that does
                // not is written anew at the end of the file. A Hyprland
                // configuration is never made here: only one that is there
                // has Omarchy's PATH line to get behind.
                match fs::read_to_string(&self.hypr_config) {
                    Ok(text) if luascan::loads(&text, HYPR_LINE, HYPR_PATH) != Loads::Effective => {
                        edit_file(&self.hypr_config, &with_hypr_line(&text))
                    }
                    Ok(_) | Err(_) => Ok(()),
                }
            }
            // Only Guardian's own file: one of that name holding
            // something else is the user's.
            Step::RemoveSessionPath => {
                if fs::read_to_string(&self.session_env)
                    .is_ok_and(|text| text.contains(SESSION_ENV_LINE))
                {
                    fs::remove_file(&self.session_env).map_err(|error| error.to_string())?;
                }
                match fs::read_to_string(&self.hypr_config) {
                    Ok(text) if without_hypr_line(&text) != text => {
                        edit_file(&self.hypr_config, &without_hypr_line(&text))
                    }
                    Ok(_) | Err(_) => Ok(()),
                }
            }
            Step::Command(_) | Step::Optional(_) | Step::AskSweepRoot => Ok(()),
        }
    }

    fn add_menu_lines(&self, entries: &[&str]) -> Result<(), String> {
        if entries.is_empty() {
            return Ok(());
        }
        let text = if let Ok(text) = fs::read_to_string(&self.menu) {
            with_menu_entries(&text, entries)?
        } else {
            if let Some(directory) = self.menu.parent() {
                fs::create_dir_all(directory).map_err(|error| error.to_string())?;
            }
            with_menu_entries("{\n}\n", entries)?
        };
        edit_file(&self.menu, &text)
    }

    fn remove_menu_lines(&self, remove: &dyn Fn(&str) -> bool) -> Result<(), String> {
        let text = fs::read_to_string(&self.menu).map_err(|error| error.to_string())?;
        let kept: Vec<&str> = text.lines().filter(|line| !remove(line)).collect();
        edit_file(&self.menu, &(kept.join("\n") + "\n"))
    }
}

/// A command run with sudo on the terminal.
/// `config` with the Guardian module defined (one line after the opening
/// brace) and placed first in `modules-right`. Written in place, keeping every
/// other line (and any comments) as it was.
fn with_waybar_module(config: &str) -> Result<String, String> {
    let config = without_waybar_module(config);
    let mut lines: Vec<String> = config.lines().map(str::to_string).collect();
    let opening = lines
        .iter()
        .position(|line| line.trim() == "{")
        .ok_or("the Waybar config does not start with a single object")?;
    let modules = lines
        .iter()
        .position(|line| names(line, "\"modules-right\"") && line.contains('['))
        .ok_or("the Waybar config has no \"modules-right\" list")?;
    let line = &lines[modules];
    let at = line.find('[').map_or(line.len(), |index| index + 1);
    let rest = line[at..].trim_start();
    // No comma before the end of the list, wherever that is: on this
    // line, on a later one, or after a comment.
    let following = std::iter::once(rest)
        .chain(lines[modules + 1..].iter().map(String::as_str))
        .collect::<Vec<_>>()
        .join("\n");
    let comma = if list_ends(&following) { "" } else { ", " };
    lines[modules] = format!("{}{WAYBAR_MODULE}{comma}{rest}", &line[..at]);
    lines.insert(opening + 1, WAYBAR_DEFINITION.to_string());
    Ok(lines.join("\n") + "\n")
}

/// Whether `text`, what follows a list's `[`, closes the list before any
/// entry: blanks and comments aside.
fn list_ends(mut text: &str) -> bool {
    loop {
        text = text.trim_start();
        if let Some(comment) = text.strip_prefix("/*") {
            text = comment.split_once("*/").map_or("", |(_, after)| after);
        } else if let Some(comment) = text.strip_prefix("//") {
            text = comment.split_once('\n').map_or("", |(_, after)| after);
        } else {
            return text.starts_with(']');
        }
    }
}

/// Whether a line of a JSON-with-comments file holds `text` as more than
/// a comment: before any `//` on it.
fn names(line: &str, text: &str) -> bool {
    line.find(text)
        .is_some_and(|at| comment_start(line).is_none_or(|comment| at < comment))
}

/// The `action` of a menu entry line Guardian writes.
fn menu_action(entry: &str) -> Option<String> {
    let items = menufile::items(&format!("{{{entry}}}")).ok()?;
    let (id, _) = items.first()?;
    menufile::action(&items, id).map(str::to_string)
}

/// Replaces one of the user's own files (`~/.bashrc`, the menu file, the
/// Waybar config), keeping a copy of it as it was before Guardian's first
/// edit beside it, as `<name>.guardian-bak`. Later edits leave that copy
/// alone: it is the way back to the file as the user had it.
fn edit_file(path: &Path, text: &str) -> Result<(), String> {
    if let Ok(real) = fs::canonicalize(path)
        && let Ok(before) = fs::read(&real)
    {
        let mut name = real.clone().into_os_string();
        name.push(BACKUP_SUFFIX);
        // Made new: an existing copy, or anything else under that name, is
        // never written over or through.
        if let Ok(mut backup) = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(PathBuf::from(name))
        {
            backup
                .write_all(&before)
                .map_err(|error| format!("could not keep a copy of {}: {error}", path.display()))?;
        }
    }
    replace_file(path, text)
}

/// Replaces the file at `path` in one step, so a reader never sees it half
/// written and a failed write leaves the old one. A link is followed to
/// the file it names, which is what is replaced: the link stays a link.
/// Where a new file cannot be made beside it, it is written in place.
fn replace_file(path: &Path, text: &str) -> Result<(), String> {
    let in_place = |target: &Path| fs::write(target, text).map_err(|error| error.to_string());
    // A link that leads nowhere yet: writing through it makes its file.
    let Ok(real) = fs::canonicalize(path) else {
        return in_place(path);
    };
    let (Some(directory), Some(name)) = (real.parent(), real.file_name()) else {
        return Err(format!("{}: not a file path", path.display()));
    };
    let temporary = directory.join(format!(
        ".{}.{}.guardian-tmp",
        name.to_string_lossy(),
        std::process::id()
    ));
    drop(fs::remove_file(&temporary));
    let Ok(mut file) = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&temporary)
    else {
        return in_place(&real);
    };
    // The old file's mode, whatever the umask says.
    let mode = fs::metadata(&real).map(|metadata| metadata.permissions());
    let written = file
        .write_all(text.as_bytes())
        .and_then(|()| mode.and_then(|mode| file.set_permissions(mode)))
        .and_then(|()| file.sync_all());
    // The new text could not be written (a full disk): the old file is
    // left as it is.
    if let Err(error) = written {
        drop(fs::remove_file(&temporary));
        return Err(error.to_string());
    }
    // A file that cannot be moved over (a bind mount, say) is written as
    // before.
    if fs::rename(&temporary, &real).is_err() {
        drop(fs::remove_file(&temporary));
        return in_place(&real);
    }
    Ok(())
}

/// `config` without the Guardian module's definition line or list entries.
fn without_waybar_module(config: &str) -> String {
    let definition = format!("{WAYBAR_MODULE}:");
    let kept: Vec<String> = config
        .lines()
        .filter(|line| !line.trim_start().starts_with(&definition))
        .map(|line| {
            // A line that only mentions it in a comment is the user's.
            if !names(line, WAYBAR_MODULE) {
                return line.to_string();
            }
            line.replace(&format!("{WAYBAR_MODULE}, "), "")
                .replace(&format!("{WAYBAR_MODULE},"), "")
                .replace(&format!(", {WAYBAR_MODULE}"), "")
                .replace(WAYBAR_MODULE, "")
        })
        .collect();
    let mut text = kept.join("\n");
    if config.ends_with('\n') {
        text.push('\n');
    }
    text
}

/// The Guardian block for `style`: the knight takes the declarations of the
/// user's own rule for `#battery` (else `#network`), so it sits in the bar
/// like its neighbours.
fn waybar_style(style: &str) -> String {
    let base = ["#battery", "#network"]
        .iter()
        .find_map(|id| rule_declarations(style, id))
        .unwrap_or_else(|| "padding: 0 8px;".to_string());
    format!("{WAYBAR_STYLE_BEGIN}\n{WAYBAR_SELECTOR} {{ {base} }}\n{WAYBAR_STYLE_END}\n")
}

/// The declarations of the first rule whose selector list names `id`
/// exactly (not `#battery.warning`), on one line.
fn rule_declarations(style: &str, id: &str) -> Option<String> {
    let mut rest = style;
    while let Some(open) = rest.find('{') {
        let close = open + rest[open..].find('}')?;
        let selector = rest[..open].rsplit(['}', ';']).next().unwrap_or_default();
        if selector.split(',').map(str::trim).any(|name| name == id) {
            let body: Vec<&str> = rest[open + 1..close]
                .split(';')
                .map(str::trim)
                .filter(|declaration| !declaration.is_empty() && !declaration.starts_with("/*"))
                .collect();
            return Some(format!("{};", body.join("; ")));
        }
        rest = &rest[close + 1..];
    }
    None
}

/// `style` without the Guardian block (and the blank line before it).
fn without_waybar_style(style: &str) -> String {
    let (Some(begin), Some(end)) = (style.find(WAYBAR_STYLE_BEGIN), style.find(WAYBAR_STYLE_END))
    else {
        return style.to_string();
    };
    if end < begin {
        return style.to_string();
    }
    let after = end + WAYBAR_STYLE_END.len();
    let tail = style[after..].strip_prefix('\n').unwrap_or(&style[after..]);
    let head = style[..begin]
        .strip_suffix("\n\n")
        .map_or(&style[..begin], |head| head);
    let head = if head.ends_with('\n') || head.is_empty() {
        head.to_string()
    } else {
        format!("{head}\n")
    };
    format!("{head}{tail}")
}

/// The regular files of the packaged widget (it has no subfolders).
fn widget_files(source: &Path) -> Vec<String> {
    let mut names: Vec<String> = fs::read_dir(source)
        .map(|entries| {
            entries
                .filter_map(Result::ok)
                .filter(|entry| entry.file_type().is_ok_and(|kind| kind.is_file()))
                .filter_map(|entry| entry.file_name().into_string().ok())
                .collect()
        })
        .unwrap_or_default();
    names.sort();
    names
}

fn sudo(args: &[&str]) -> Step {
    let mut argv = vec!["/usr/bin/sudo".to_string()];
    argv.extend(args.iter().map(ToString::to_string));
    Step::Command(argv)
}

/// Makes the Omarchy menu re-read its files.
fn refresh() -> Step {
    Step::Optional(vec!["omarchy-menu".into(), "refresh".into()])
}

/// `~/.bashrc` without the lines `install-user-interceptor.sh` adds: the
/// marker, the source line after it, and the blank line before it.
fn without_interceptor(text: &str) -> String {
    let lines: Vec<&str> = text.lines().collect();
    let mut kept: Vec<&str> = Vec::with_capacity(lines.len());
    let mut index = 0;
    while index < lines.len() {
        if lines[index] == INTERCEPTOR_MARKER {
            if kept.last() == Some(&"") {
                kept.pop();
            }
            index += 1;
            if lines
                .get(index)
                .is_some_and(|line| line.contains(INTERCEPTOR_SOURCE))
            {
                index += 1;
            }
            continue;
        }
        // The line that loads it, wherever it stands.
        if lines[index].contains(INTERCEPTOR_SOURCE)
            && lines[index].contains("source ")
            && !lines[index].trim_start().starts_with('#')
        {
            index += 1;
            continue;
        }
        kept.push(lines[index]);
        index += 1;
    }
    let mut out = kept.join("\n");
    if text.ends_with('\n') {
        out.push('\n');
    }
    out
}

/// A Hyprland Lua configuration without the lines `protect` adds: the
/// marker, the line that loads Guardian's PATH file wherever it stands, and
/// the blank line before them.
fn without_hypr_line(text: &str) -> String {
    let mut kept: Vec<&str> = Vec::new();
    for line in text.lines() {
        let code = line.trim();
        let loads = code.contains(HYPR_PATH) && code.contains("dofile") && !code.starts_with("--");
        if code == HYPR_MARKER {
            if kept.last().is_some_and(|last| last.trim().is_empty()) {
                kept.pop();
            }
        } else if !loads {
            kept.push(line);
        }
    }
    let mut out = kept.join("\n");
    if text.ends_with('\n') && !out.is_empty() {
        out.push('\n');
    }
    out
}

/// The configuration with Guardian's lines at its end, once.
fn with_hypr_line(text: &str) -> String {
    let mut out = without_hypr_line(text);
    if !out.is_empty() && !out.ends_with('\n') {
        out.push('\n');
    }
    if !out.is_empty() {
        out.push('\n');
    }
    format!("{out}{HYPR_MARKER}\n{HYPR_LINE}\n")
}

/// Where a `//` comment starts in a JSONC line, outside of strings.
fn comment_start(line: &str) -> Option<usize> {
    let mut quoted = false;
    let mut escaped = false;
    let mut previous = None;
    for (index, character) in line.char_indices() {
        match character {
            _ if escaped => escaped = false,
            '\\' if quoted => escaped = true,
            '"' => quoted = !quoted,
            '/' if !quoted && previous == Some('/') => return Some(index - 1),
            _ => {}
        }
        previous = Some(character);
    }
    None
}

/// The menu file with `entries` added before its final `}`. A comma is
/// added after the previous entry when it has none.
fn with_menu_entries(text: &str, entries: &[&str]) -> Result<String, String> {
    let lines: Vec<&str> = text.lines().collect();
    let closing = lines
        .iter()
        .rposition(|line| !line.trim().is_empty())
        .filter(|index| lines[*index].trim() == "}")
        .ok_or("the menu file does not end with a lone `}`; add the entry by hand")?;

    let mut out: Vec<String> = lines.iter().map(ToString::to_string).collect();
    if let Some(previous) = (0..closing).rev().find(|index| {
        let line = lines[*index].trim();
        !line.is_empty() && !line.starts_with("//")
    }) {
        // The comma belongs after the value, before a comment that
        // follows it on the line.
        let line = out[previous].trim_end().to_string();
        let code_end = comment_start(&line).unwrap_or(line.len());
        let (code, comment) = line.split_at(code_end);
        let value = code.trim_end();
        if !value.ends_with(',') && !value.ends_with('{') {
            out[previous] = if comment.is_empty() {
                format!("{value},")
            } else {
                format!("{value}, {comment}")
            };
        }
    }
    for (offset, entry) in entries.iter().enumerate() {
        out.insert(closing + offset, format!("  {entry}"));
    }
    Ok(out.join("\n") + "\n")
}

#[cfg(test)]
mod tests;
