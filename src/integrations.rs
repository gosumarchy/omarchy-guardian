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
mod tests {
    use std::fs;
    use std::os::unix::fs::{PermissionsExt, symlink};

    use super::{
        HYPR_LINE, HYPR_MARKER, INTERCEPTOR_LINE, INTERCEPTOR_MARKER, Integration, MENU_ENTRY,
        Part, Paths, SESSION_ENV, State, Step, THEME_OVERRIDES, WRAPPED, with_menu_entries,
        without_interceptor,
    };
    use crate::test_support::TempDir;

    fn paths(dir: &TempDir) -> Paths {
        let root = dir.path();
        fs::create_dir_all(root.join("share")).unwrap();
        fs::create_dir_all(root.join("omarchy")).unwrap();
        fs::write(root.join("share/guardian.hook"), "[Trigger]\n").unwrap();
        fs::write(root.join("yay"), "").unwrap();
        fs::write(root.join("installer"), "").unwrap();
        Paths {
            hook_source: root.join("share/guardian.hook"),
            hook_target: root.join("hooks/guardian.hook"),
            yay: root.join("yay"),
            yay_config: root.join("yay.json"),
            interceptor_installer: root.join("installer"),
            bashrc: root.join("bashrc"),
            omarchy: root.join("omarchy"),
            menu: root.join("menu/omarchy-menu.jsonc"),
            widget_source: root.join("share/bar-widget"),
            widget_target: root.join("plugins/omarchy-guardian"),
            shell_config: root.join("shell.json"),
            waybar_config: root.join("waybar/config"),
            waybar_style: root.join("waybar/style.css"),
            opencode_missing: false,
            sweep_timer: root.join("units/omarchy-guardian-sweep.timer"),
            sweep_timer_link: root.join("user-wants/omarchy-guardian-sweep.timer"),
            sweep_root_timer: root.join("units/omarchy-guardian-sweep-collect.timer"),
            sweep_root_timer_link: root.join("system-wants/omarchy-guardian-sweep-collect.timer"),
            sweep_consent: None,
            sweep_group: Some("u".into()),
            sweep_overrides: Vec::new(),
            login_shell: Some("bash".into()),
            makepkg_gate: root.join("guardian-makepkg"),
            owner: std::os::unix::fs::MetadataExt::uid(&fs::metadata(root).unwrap()),
            system_bin: root.join("bin"),
            paru_config: root.join("paru.conf"),
            shell_startup: vec![root.join("bashrc"), root.join("zshrc")],
            path_dirs: Vec::new(),
            manager_path: None,
            wrappers: root.join("wrappers"),
            session_env: root.join("uwsm/env.d/90-omarchy-guardian"),
            hypr_config: root.join("hypr/hyprland.lua"),
            hypr_path: root.join("hyprland-path.lua"),
        }
    }

    #[test]
    fn the_system_sweep_needs_its_timer_and_an_answer_about_root() {
        use crate::config::model::RootConsent;
        let dir = TempDir::new("integrations-sweep");
        let mut paths = paths(&dir);
        assert!(matches!(
            paths.state(Integration::SystemSweep),
            State::Unavailable(_)
        ));
        fs::create_dir_all(dir.path().join("units")).unwrap();
        fs::write(&paths.sweep_timer, "").unwrap();
        fs::write(&paths.sweep_root_timer, "").unwrap();
        assert_eq!(paths.state(Integration::SystemSweep), State::Off);
        let plan = paths.plan(Integration::SystemSweep, &State::Off).unwrap();
        // The question comes before the daily sweep starts.
        assert_eq!(plan.steps[0], Step::AskSweepRoot);
        assert!(
            matches!(&plan.steps[1], Step::Command(argv) if argv.contains(&"--user".to_string()))
        );

        fs::create_dir_all(paths.sweep_timer_link.parent().unwrap()).unwrap();
        fs::write(&paths.sweep_timer_link, "").unwrap();
        assert!(matches!(
            paths.state(Integration::SystemSweep),
            State::Partial(_)
        ));
        // What stands in for one of the sweep's units (a unit file of its
        // name, a drop-in: `sweep::own` finds them) is named, whatever it
        // holds.
        paths.sweep_overrides = vec![
            "home/u/.config/systemd/user/omarchy-guardian-sweep.service.d/home.conf".into(),
            "home/u/.config/systemd/user.control/omarchy-guardian-sweep.timer".into(),
        ];
        let state = paths.state(Integration::SystemSweep);
        assert!(
            matches!(&state, State::Partial(detail) if detail.starts_with(
                "/home/u/.config/systemd/user/omarchy-guardian-sweep.service.d/home.conf and 1 more overrides or masks"
            )),
            "{state:?}"
        );
        paths.sweep_overrides.clear();

        paths.sweep_consent = Some(RootConsent::Declined);
        let state = paths.state(Integration::SystemSweep);
        assert!(matches!(&state, State::Partial(detail) if detail.contains("declined")));
        assert_eq!(
            paths.plan(Integration::SystemSweep, &state).unwrap().steps,
            [Step::AskSweepRoot]
        );

        paths.sweep_consent = Some(RootConsent::Allowed);
        let state = paths.state(Integration::SystemSweep);
        let steps = paths.plan(Integration::SystemSweep, &state).unwrap().steps;
        assert!(
            matches!(&steps[..], [Step::Command(argv)] if argv.iter().any(|arg| arg == "enable"))
        );
        fs::create_dir_all(paths.sweep_root_timer_link.parent().unwrap()).unwrap();
        fs::write(&paths.sweep_root_timer_link, "").unwrap();
        assert_eq!(paths.state(Integration::SystemSweep), State::On);
        // Off disables both timers and keeps the answer.
        let off = paths
            .plan(Integration::SystemSweep, &State::On)
            .unwrap()
            .steps;
        assert_eq!(off.len(), 2);
        assert!(!off.contains(&Step::AskSweepRoot));
    }

    #[test]
    fn hook_state_distinguishes_the_packaged_link() {
        let dir = TempDir::new("integrations-hook");
        let paths = paths(&dir);
        assert_eq!(paths.state(Integration::PacmanHook), State::Off);

        fs::create_dir_all(dir.path().join("hooks")).unwrap();
        symlink(&paths.hook_source, &paths.hook_target).unwrap();
        assert_eq!(paths.state(Integration::PacmanHook), State::On);
        // Off takes the link away and nothing else: the hook pacman always
        // loads from libalpm's own directory stays with the package, and
        // lets every transaction through once the link is gone.
        let plan = paths.plan(Integration::PacmanHook, &State::On).unwrap();
        let link = paths.hook_target.display().to_string();
        assert!(
            matches!(&plan.steps[..], [Step::Command(argv)]
                if argv[1..] == ["/usr/bin/rm".to_string(), "-f".to_string(), link.clone()]),
            "{plan:?}"
        );
        // The packaged hook file alone is not the hook turned on.
        fs::remove_file(&paths.hook_target).unwrap();
        assert!(paths.hook_source.exists());
        assert_eq!(paths.state(Integration::PacmanHook), State::Off);
        symlink(&paths.hook_source, &paths.hook_target).unwrap();

        fs::remove_file(&paths.hook_target).unwrap();
        fs::write(&paths.hook_target, "[Trigger]\n").unwrap();
        assert!(matches!(
            paths.state(Integration::PacmanHook),
            State::Foreign(_)
        ));

        fs::remove_file(&paths.hook_source).unwrap();
        assert!(matches!(
            paths.state(Integration::PacmanHook),
            State::Unavailable(_)
        ));
        assert_eq!(
            paths.plan(
                Integration::PacmanHook,
                &paths.state(Integration::PacmanHook)
            ),
            None
        );
    }

    #[test]
    fn aur_gate_state_reads_the_yay_config() {
        let dir = TempDir::new("integrations-yay");
        let paths = paths(&dir);
        assert_eq!(paths.state(Integration::AurGate), State::Off);
        let configure = |makepkg: &str| {
            fs::write(
                &paths.yay_config,
                format!("{{\"makepkgbin\": \"{makepkg}\"}}"),
            )
            .unwrap();
        };
        let gate = paths.makepkg_gate.display().to_string();
        fs::write(&paths.makepkg_gate, "").unwrap();
        configure(&gate);
        assert_eq!(paths.state(Integration::AurGate), State::On);
        let plan = paths.plan(Integration::AurGate, &State::On).unwrap();
        assert!(matches!(&plan.steps[..], [Step::Command(argv)] if argv[2] == "makepkg"));
        let plan = paths.plan(Integration::AurGate, &State::Off).unwrap();
        assert!(matches!(&plan.steps[..], [Step::Command(argv)] if argv[2] == gate));

        // makepkg itself is off; any other program is not Guardian's gate.
        configure("/usr/bin/makepkg");
        assert_eq!(paths.state(Integration::AurGate), State::Off);
        configure("/tmp/guardian-makepkg");
        let state = paths.state(Integration::AurGate);
        assert!(matches!(&state, State::Partial(why) if why.contains("not Guardian's gate")));
    }

    #[test]
    fn a_configured_aur_gate_that_is_bypassed_is_not_on() {
        let dir = TempDir::new("integrations-yay-bypass");
        let mut paths = paths(&dir);
        let gate = paths.makepkg_gate.display().to_string();
        fs::write(&paths.yay_config, format!("{{\"makepkgbin\": \"{gate}\"}}")).unwrap();
        let partial = |paths: &Paths, expected: &str| {
            let state = paths.state(Integration::AurGate);
            assert!(
                matches!(&state, State::Partial(why) if why.contains(expected)),
                "{state:?}"
            );
        };

        // The shim is not there, or is not one only its owner can write.
        partial(&paths, "is missing");
        fs::write(&paths.makepkg_gate, "").unwrap();
        fs::set_permissions(&paths.makepkg_gate, fs::Permissions::from_mode(0o666)).unwrap();
        partial(&paths, "not root's alone to write");
        fs::set_permissions(&paths.makepkg_gate, fs::Permissions::from_mode(0o755)).unwrap();
        assert_eq!(paths.state(Integration::AurGate), State::On);
        // Owned by somebody else than the installer.
        paths.owner += 1;
        partial(&paths, "not root's alone to write");
        paths.owner -= 1;

        // Another yay earlier on PATH.
        let front = dir.path().join("front");
        fs::create_dir_all(&front).unwrap();
        paths.path_dirs = vec![front.clone(), dir.path().to_path_buf()];
        assert_eq!(paths.state(Integration::AurGate), State::On);
        fs::write(front.join("yay"), "").unwrap();
        partial(&paths, "another yay comes first on PATH");
        fs::remove_file(front.join("yay")).unwrap();

        // An alias or function in front of it that names its own makepkg.
        fs::write(
            dir.path().join("zshrc"),
            "alias yay='yay --makepkg /usr/bin/makepkg'\n",
        )
        .unwrap();
        partial(&paths, "an alias or function named yay");
        fs::write(dir.path().join("zshrc"), "alias yay='yay --noconfirm'\n").unwrap();
        assert_eq!(paths.state(Integration::AurGate), State::On);
    }

    #[test]
    fn other_aur_helpers_without_the_gate_are_issues() {
        let dir = TempDir::new("integrations-helpers");
        let paths = paths(&dir);
        assert!(paths.helper_issues().is_empty());
        fs::create_dir_all(&paths.system_bin).unwrap();
        fs::write(paths.system_bin.join("paru"), "").unwrap();
        fs::write(paths.system_bin.join("pikaur"), "").unwrap();
        let issues = paths.helper_issues();
        assert_eq!(issues.len(), 2, "{issues:?}");
        assert!(issues[0].starts_with("paru builds AUR packages without Guardian"));
        assert_eq!(issues[1], "pikaur builds AUR packages without Guardian");

        // paru pointed at the gate by hand counts, in its own section only.
        let gate = paths.makepkg_gate.display();
        fs::write(&paths.paru_config, format!("[options]\nMakepkg = {gate}\n")).unwrap();
        assert_eq!(paths.helper_issues().len(), 2);
        fs::write(
            &paths.paru_config,
            format!("[options]\nBottomUp\n[bin]\nMakepkg = {gate}\n"),
        )
        .unwrap();
        assert_eq!(paths.helper_issues().len(), 1);
        fs::write(
            dir.path().join("bashrc"),
            "paru() {\n  command paru --makepkg makepkg \"$@\"\n}\n",
        )
        .unwrap();
        assert!(paths.helper_issues()[0].contains("an alias or function named paru"));
    }

    #[test]
    fn an_interceptor_line_that_cannot_take_effect_is_partial_and_repaired_at_the_end() {
        let dir = TempDir::new("integrations-bashrc-broken");
        let paths = paths(&dir);
        for bashrc in [
            ": source /usr/lib/omarchy-guardian/omarchy-bash-interceptor.sh\n".to_string(),
            format!("{INTERCEPTOR_LINE}\nunset -f omarchy\n"),
            format!("never() {{\n{INTERCEPTOR_LINE}\n}}\n"),
        ] {
            fs::write(&paths.bashrc, &bashrc).unwrap();
            let state = paths.state(Integration::ThemeInterceptor);
            assert!(
                matches!(&state, State::Partial(why) if why.starts_with("not effective in Bash")),
                "{state:?} for {bashrc}"
            );
            // Taken out, then written again by the installer, at the end.
            let steps = paths
                .plan(Integration::ThemeInterceptor, &state)
                .unwrap()
                .steps;
            assert_eq!(steps[0], Step::RemoveInterceptor);
            assert!(matches!(&steps[1], Step::Command(_)), "{steps:?}");
            // Off takes it out too.
            let off = paths
                .plan(Integration::ThemeInterceptor, &State::On)
                .unwrap()
                .steps;
            assert!(off.contains(&Step::RemoveInterceptor));
        }
    }

    #[test]
    fn a_menu_override_counts_only_when_it_is_the_entry_in_effect() {
        let dir = TempDir::new("integrations-menu-effective");
        let paths = paths(&dir);
        fs::write(&paths.bashrc, format!("{INTERCEPTOR_LINE}\n")).unwrap();
        paths.edit(&Step::AddThemeMenu).unwrap();
        paths.edit(&Step::AddMenuEntry).unwrap();
        assert_eq!(paths.state(Integration::ThemeInterceptor), State::On);
        assert_eq!(paths.state(Integration::MenuEntry), State::On);
        let written = fs::read_to_string(&paths.menu).unwrap();

        // A later entry of the same name wins when the menu reads the file.
        let later = written.replace(
            "\n}\n",
            "\n  \"update.themes\": {\"action\":\"omarchy-theme-update\"},\n  \"setup.guardian\": {\"action\":\"true\"},\n}\n",
        );
        fs::write(&paths.menu, &later).unwrap();
        let state = paths.state(Integration::ThemeInterceptor);
        assert!(
            matches!(&state, State::Partial(why) if why.contains("\"update.themes\" is not Guardian's")),
            "{state:?}"
        );
        assert!(matches!(
            paths.state(Integration::MenuEntry),
            State::Partial(_)
        ));
        // Turning it on writes Guardian's entries anew, after the other.
        for step in paths
            .plan(Integration::ThemeInterceptor, &state)
            .unwrap()
            .steps
        {
            paths.edit(&step).unwrap();
        }
        assert_eq!(paths.state(Integration::ThemeInterceptor), State::On);

        // A file the menu cannot parse is ignored by it, whatever it holds.
        fs::write(&paths.menu, written.replace("\n}\n", "\n  oops\n}\n")).unwrap();
        let state = paths.state(Integration::ThemeInterceptor);
        assert!(
            matches!(&state, State::Partial(why) if why.contains("ignores its user file")),
            "{state:?}"
        );
        assert!(matches!(
            paths.state(Integration::MenuEntry),
            State::Partial(_)
        ));
        // Guardian's path in an entry for something else proves nothing.
        fs::write(
            &paths.menu,
            "{\n  \"x\": {\"action\":\"/usr/lib/omarchy-guardian/guardian-theme install\"},\n}\n",
        )
        .unwrap();
        assert!(matches!(
            paths.state(Integration::ThemeInterceptor),
            State::Partial(why) if why.starts_with("terminal only")
        ));
        assert_eq!(THEME_OVERRIDES.len(), 3);
    }

    /// A home as `protect` finds it on Omarchy: the packaged wrappers and
    /// PATH file, and a Hyprland configuration that loads Omarchy's
    /// defaults. Returns the directory standing for Omarchy's own commands.
    fn omarchy_session(dir: &TempDir, paths: &Paths) -> std::path::PathBuf {
        fs::create_dir_all(&paths.wrappers).unwrap();
        for name in WRAPPED {
            fs::write(paths.wrappers.join(name), "").unwrap();
        }
        fs::write(&paths.hypr_path, "").unwrap();
        fs::create_dir_all(paths.hypr_config.parent().unwrap()).unwrap();
        fs::write(
            &paths.hypr_config,
            "require(\"default.hypr.omarchy\")\nrequire(\"hypr.autostart\")\n\n-- Add any other personal Hyprland configuration below.\n",
        )
        .unwrap();
        let stock = dir.path().join("stock");
        fs::create_dir_all(&stock).unwrap();
        fs::write(stock.join("omarchy-theme-install"), "").unwrap();
        stock
    }

    #[test]
    fn the_session_path_is_on_only_where_the_wrappers_are_found_first() {
        let dir = TempDir::new("integrations-session");
        let mut paths = paths(&dir);
        assert!(matches!(
            paths.state(Integration::SessionPath),
            State::Unavailable(_)
        ));
        let stock = omarchy_session(&dir, &paths);
        assert_eq!(paths.state(Integration::SessionPath), State::Off);

        let on = paths.plan(Integration::SessionPath, &State::Off).unwrap();
        assert_eq!(on.steps, [Step::AddSessionPath]);
        assert!(on.describe(&paths)[0].contains("add a line to"));
        paths.edit(&Step::AddSessionPath).unwrap();
        assert_eq!(fs::read_to_string(&paths.session_env).unwrap(), SESSION_ENV);
        // The line goes after everything Omarchy's defaults did, and the
        // file as it was is kept.
        let config = fs::read_to_string(&paths.hypr_config).unwrap();
        assert!(
            config.ends_with(&format!("below.\n\n{HYPR_MARKER}\n{HYPR_LINE}\n")),
            "{config}"
        );
        let backup = paths.hypr_config.with_extension("lua.guardian-bak");
        assert!(!fs::read_to_string(&backup).unwrap().contains("Guardian"));

        // Written, and as Omarchy's own PATH line leaves the session until
        // the next login: its commands first. That is not on.
        paths.manager_path = Some(vec![stock.clone(), paths.wrappers.clone()]);
        let state = paths.state(Integration::SessionPath);
        assert!(
            matches!(&state, State::Partial(why)
                if why.contains("not in effect for the session") && why.contains("comes before it on PATH")),
            "{state:?}"
        );
        paths.login_shell = Some("zsh".into());
        assert!(paths.theme_caveat().is_some());
        // After it: Guardian's first, then Omarchy's.
        paths.manager_path = Some(vec![
            paths.wrappers.clone(),
            stock.clone(),
            dir.path().join("tools"),
        ]);
        assert_eq!(paths.state(Integration::SessionPath), State::On);
        // In another shell the Bash interceptor is not needed for it.
        assert_eq!(paths.theme_caveat(), None);
        // Turning it on again changes nothing.
        paths.edit(&Step::AddSessionPath).unwrap();
        assert_eq!(fs::read_to_string(&paths.hypr_config).unwrap(), config);

        // Not on the session's PATH at all.
        paths.manager_path = Some(vec![stock.clone()]);
        let state = paths.state(Integration::SessionPath);
        assert!(
            matches!(&state, State::Partial(why) if why.contains("is not on PATH")),
            "{state:?}"
        );
        paths.manager_path = Some(vec![paths.wrappers.clone(), stock.clone()]);

        // A wrapper, or the PATH file, anyone can rewrite is no gate.
        for file in [paths.wrappers.join("omarchy"), paths.hypr_path.clone()] {
            fs::set_permissions(&file, fs::Permissions::from_mode(0o777)).unwrap();
            assert!(matches!(
                paths.state(Integration::SessionPath),
                State::Partial(why) if why.contains("not to be trusted")
            ));
            fs::set_permissions(&file, fs::Permissions::from_mode(0o644)).unwrap();
        }

        // A line added to the session file, or the line changed, is not
        // Guardian's file.
        fs::write(
            &paths.session_env,
            format!("{SESSION_ENV}export PATH=/tmp:$PATH\n"),
        )
        .unwrap();
        let state = paths.state(Integration::SessionPath);
        assert!(
            matches!(&state, State::Partial(why) if why.contains("half set up")),
            "{state:?}"
        );
        paths.edit(&Step::AddSessionPath).unwrap();
        assert_eq!(paths.state(Integration::SessionPath), State::On);

        // Off removes Guardian's file and its line, and only those.
        paths.edit(&Step::RemoveSessionPath).unwrap();
        assert!(!paths.session_env.exists());
        assert_eq!(
            fs::read_to_string(&paths.hypr_config).unwrap(),
            fs::read_to_string(&backup).unwrap()
        );
        assert_eq!(paths.state(Integration::SessionPath), State::Off);
        fs::write(&paths.session_env, "export X=1\n").unwrap();
        paths.edit(&Step::RemoveSessionPath).unwrap();
        assert!(paths.session_env.exists());
    }

    #[test]
    fn guardians_hyprland_line_counts_only_where_it_runs_last() {
        let dir = TempDir::new("integrations-hypr");
        let mut paths = paths(&dir);
        let stock = omarchy_session(&dir, &paths);
        paths.manager_path = Some(vec![paths.wrappers.clone(), stock]);
        paths.edit(&Step::AddSessionPath).unwrap();
        assert_eq!(paths.state(Integration::SessionPath), State::On);
        let written = fs::read_to_string(&paths.hypr_config).unwrap();

        // The session file alone: Omarchy's `envs.lua` puts its own
        // commands first again, which is the state that never went calm.
        fs::write(&paths.hypr_config, "require(\"default.hypr.omarchy\")\n").unwrap();
        let state = paths.state(Integration::SessionPath);
        assert!(
            matches!(&state, State::Partial(why) if why.contains("Omarchy's own PATH line")),
            "{state:?}"
        );
        // Turning it on is the way out of every partial state.
        let plan = paths.plan(Integration::SessionPath, &state).unwrap();
        assert_eq!(plan.steps, [Step::AddSessionPath]);

        // Commented out, in a block that does not run, or undone below.
        for broken in [
            format!("if false then\n{HYPR_LINE}\nend\n"),
            format!("--[[\n{HYPR_LINE}\n]]\n"),
            format!("{HYPR_LINE}\nhl.env(\"PATH\", \"/usr/share/omarchy/bin:/usr/bin\")\n"),
        ] {
            fs::write(&paths.hypr_config, &broken).unwrap();
            let state = paths.state(Integration::SessionPath);
            assert!(
                matches!(&state, State::Partial(why) if why.contains("not effective")),
                "{state:?} for {broken}"
            );
            // Written anew at the end, once.
            paths.edit(&Step::AddSessionPath).unwrap();
            let repaired = fs::read_to_string(&paths.hypr_config).unwrap();
            assert_eq!(repaired.matches(HYPR_LINE).count(), 1, "{repaired}");
            assert!(repaired.ends_with(&format!("{HYPR_MARKER}\n{HYPR_LINE}\n")));
        }
        // What a user adds below Guardian's line leaves it in effect.
        fs::write(
            &paths.hypr_config,
            format!("{written}o.window(\"qemu\", {{ workspace = \"5\" }})\n"),
        )
        .unwrap();
        assert_eq!(paths.state(Integration::SessionPath), State::On);

        // Without a Hyprland Lua configuration nothing reorders PATH: the
        // session file is the whole of it, and no configuration is made.
        fs::remove_file(&paths.hypr_config).unwrap();
        assert_eq!(paths.state(Integration::SessionPath), State::On);
        paths.edit(&Step::AddSessionPath).unwrap();
        assert!(!paths.hypr_config.exists());
        let plan = paths.plan(Integration::SessionPath, &State::Off).unwrap();
        assert!(!plan.describe(&paths)[0].contains("add a line"));
    }

    #[test]
    fn two_callers_with_different_paths_read_the_same_state() {
        let dir = TempDir::new("integrations-callers");
        let mut bar = paths(&dir);
        let stock = omarchy_session(&dir, &bar);
        let gate = bar.makepkg_gate.display().to_string();
        fs::write(&bar.yay_config, format!("{{\"makepkgbin\": \"{gate}\"}}")).unwrap();
        fs::write(&bar.makepkg_gate, "").unwrap();
        bar.edit(&Step::AddSessionPath).unwrap();
        // Another yay, and Omarchy's commands, in directories only the
        // second caller's shell has in front.
        let front = dir.path().join("front");
        fs::create_dir_all(&front).unwrap();
        fs::write(front.join("yay"), "").unwrap();
        bar.manager_path = Some(vec![bar.wrappers.clone(), stock.clone()]);
        bar.path_dirs = vec![bar.wrappers.clone(), stock.clone()];
        let mut remote = bar.clone();
        remote.path_dirs = vec![front, stock.clone()];

        // Both read the session's PATH, so both read the same.
        for integration in [Integration::SessionPath, Integration::AurGate] {
            assert_eq!(bar.state(integration), State::On);
            assert_eq!(remote.state(integration), State::On);
        }
        assert!(bar.unsettled().is_empty() && remote.unsettled().is_empty());
        // The second caller is told about its own shell, beside the gate.
        assert_eq!(bar.path_caveat(), None);
        assert!(
            remote
                .path_caveat()
                .is_some_and(|caveat| caveat.contains("is not on PATH"))
        );

        // With no session to ask, each reads its own PATH, and says that
        // what it read is not to be put on record.
        bar.manager_path = None;
        remote.manager_path = None;
        assert_eq!(bar.state(Integration::SessionPath), State::On);
        assert!(matches!(
            remote.state(Integration::SessionPath),
            State::Partial(why) if why.contains("this shell")
        ));
        assert!(matches!(
            remote.state(Integration::AurGate),
            State::Partial(why) if why.contains("another yay")
        ));
        assert_eq!(
            remote.unsettled(),
            [Integration::AurGate, Integration::SessionPath]
        );
        assert_eq!(remote.path_caveat(), None);
    }

    #[test]
    fn what_has_nothing_to_guard_on_this_machine_is_not_a_problem() {
        use crate::status::gate_issue;
        let dir = TempDir::new("integrations-applies");
        let paths = paths(&dir);
        fs::create_dir_all(&paths.wrappers).unwrap();
        // Plain Arch: no yay, no Omarchy.
        fs::remove_file(&paths.yay).unwrap();
        fs::remove_dir_all(&paths.omarchy).unwrap();
        for integration in [
            Integration::AurGate,
            Integration::SessionPath,
            Integration::MenuEntry,
        ] {
            let state = paths.state(integration);
            assert!(matches!(state, State::Unavailable(_)), "{state:?}");
            assert!(!paths.applies(integration));
            assert_eq!(gate_issue(&paths, integration, &state), None);
        }
        // A gate that does apply and cannot be there is protection missing.
        fs::remove_file(&paths.hook_source).unwrap();
        let state = paths.state(Integration::PacmanHook);
        assert!(
            gate_issue(&paths, Integration::PacmanHook, &state)
                .is_some_and(|issue| issue.contains("is unavailable"))
        );
        // With Omarchy there, wrappers the package did not bring are one too.
        fs::create_dir_all(&paths.omarchy).unwrap();
        fs::remove_dir_all(&paths.wrappers).unwrap();
        let state = paths.state(Integration::SessionPath);
        assert!(gate_issue(&paths, Integration::SessionPath, &state).is_some());
        assert!(
            gate_issue(&paths, Integration::SessionPath, &State::Off)
                .is_some_and(|issue| issue.contains("not fully on"))
        );
        assert_eq!(
            gate_issue(&paths, Integration::SessionPath, &State::On),
            None
        );
    }

    #[test]
    fn the_file_as_it_was_before_the_first_edit_is_kept_once() {
        let dir = TempDir::new("integrations-backup");
        let paths = paths(&dir);
        let original = format!("alias ll='ls -l'\n\n{INTERCEPTOR_MARKER}\n{INTERCEPTOR_LINE}\n");
        fs::write(&paths.bashrc, &original).unwrap();
        paths.edit(&Step::RemoveInterceptor).unwrap();
        let backup = dir.path().join("bashrc.guardian-bak");
        assert_eq!(fs::read_to_string(&backup).unwrap(), original);
        assert_eq!(
            fs::metadata(&backup).unwrap().permissions().mode() & 0o777,
            0o600
        );

        // A later edit leaves the first copy alone.
        fs::write(&paths.bashrc, format!("export X=1\n{INTERCEPTOR_LINE}\n")).unwrap();
        paths.edit(&Step::RemoveInterceptor).unwrap();
        assert_eq!(fs::read_to_string(&backup).unwrap(), original);
        assert_eq!(fs::read_to_string(&paths.bashrc).unwrap(), "export X=1\n");

        // A file Guardian makes itself has nothing to keep.
        paths.edit(&Step::AddMenuEntry).unwrap();
        let menu_backup = dir.path().join("menu/omarchy-menu.jsonc.guardian-bak");
        assert!(!menu_backup.exists());
        paths.edit(&Step::AddThemeMenu).unwrap();
        assert!(
            fs::read_to_string(&menu_backup)
                .unwrap()
                .contains("setup.guardian")
        );
    }

    #[test]
    fn interceptor_lines_are_removed_exactly() {
        let bashrc = format!(
            "alias ll='ls -l'\n\n{INTERCEPTOR_MARKER}\n[[ -r /usr/lib/omarchy-guardian/omarchy-bash-interceptor.sh ]] && source /usr/lib/omarchy-guardian/omarchy-bash-interceptor.sh\nexport X=1\n"
        );
        assert_eq!(
            without_interceptor(&bashrc),
            "alias ll='ls -l'\nexport X=1\n"
        );

        let dir = TempDir::new("integrations-bashrc");
        let paths = paths(&dir);
        fs::write(&paths.bashrc, &bashrc).unwrap();
        // Bash alone leaves the Omarchy menu's theme items ungated.
        assert!(matches!(
            paths.state(Integration::ThemeInterceptor),
            State::Partial(reason) if reason.starts_with("terminal only")
        ));
        paths.edit(&Step::RemoveInterceptor).unwrap();
        assert_eq!(paths.state(Integration::ThemeInterceptor), State::Off);
    }

    #[test]
    fn menu_entry_is_added_and_removed() {
        let template = "{\n  // Comments\n  // \"personal\": {\"icon\":\"\"},\n}\n";
        let added = with_menu_entries(template, &[MENU_ENTRY]).unwrap();
        assert!(added.ends_with(&format!("  {MENU_ENTRY}\n}}\n")));

        let without_comma = "{\n  \"a\": {\"label\":\"A\"}\n}\n";
        assert!(
            with_menu_entries(without_comma, &[MENU_ENTRY])
                .unwrap()
                .contains("\"a\": {\"label\":\"A\"},\n")
        );
        assert!(with_menu_entries("{ \"a\": 1 }", &[MENU_ENTRY]).is_err());

        let dir = TempDir::new("integrations-menu");
        let paths = paths(&dir);
        assert_eq!(paths.state(Integration::MenuEntry), State::Off);
        paths.edit(&Step::AddMenuEntry).unwrap();
        assert_eq!(paths.state(Integration::MenuEntry), State::On);
        paths.edit(&Step::RemoveMenuEntry).unwrap();
        assert_eq!(paths.state(Integration::MenuEntry), State::Off);
        assert_eq!(fs::read_to_string(&paths.menu).unwrap(), "{\n}\n");
    }

    #[test]
    fn a_hook_without_opencode_installs_it_first_and_counts_as_partial() {
        let dir = TempDir::new("integrations-opencode");
        let mut paths = paths(&dir);
        paths.opencode_missing = true;

        let plan = paths.plan(Integration::PacmanHook, &State::Off).unwrap();
        let commands: Vec<String> = plan
            .steps
            .iter()
            .filter_map(|step| match step {
                Step::Command(argv) => Some(argv.join(" ")),
                _ => None,
            })
            .collect();
        assert_eq!(
            commands[0],
            "/usr/bin/sudo /usr/bin/pacman -S --needed extra/opencode"
        );
        assert_eq!(commands.len(), 3);

        fs::create_dir_all(dir.path().join("hooks")).unwrap();
        symlink(&paths.hook_source, &paths.hook_target).unwrap();
        let state = paths.state(Integration::PacmanHook);
        assert!(matches!(&state, State::Partial(reason) if reason.contains("OpenCode")));
        // Already linked: only OpenCode is missing.
        let plan = paths.plan(Integration::PacmanHook, &state).unwrap();
        assert_eq!(plan.steps.len(), 1);

        paths.opencode_missing = false;
        assert_eq!(paths.state(Integration::PacmanHook), State::On);
    }

    #[test]
    fn the_theme_gate_covers_the_omarchy_menu_too() {
        let dir = TempDir::new("integrations-theme-menu");
        let paths = paths(&dir);
        let own = "{\n  \"install.style.theme\": {\"label\":\"Mine\"},\n}\n";
        fs::create_dir_all(paths.menu.parent().unwrap()).unwrap();
        fs::write(&paths.menu, own).unwrap();

        let plan = paths
            .plan(Integration::ThemeInterceptor, &State::Off)
            .unwrap();
        assert!(plan.steps.contains(&Step::AddThemeMenu), "{plan:?}");
        paths.edit(&Step::AddThemeMenu).unwrap();
        assert!(matches!(
            paths.state(Integration::ThemeInterceptor),
            State::Partial(reason) if reason.starts_with("menu only")
        ));
        let menu = fs::read_to_string(&paths.menu).unwrap();
        assert!(menu.contains("guardian-theme install"), "{menu}");
        assert!(menu.contains("guardian-theme update"), "{menu}");
        assert!(menu.contains("guardian-plugin add"), "{menu}");

        fs::write(
            &paths.bashrc,
            format!("{INTERCEPTOR_MARKER}\n{INTERCEPTOR_LINE}\n"),
        )
        .unwrap();
        assert_eq!(paths.state(Integration::ThemeInterceptor), State::On);

        // In another login shell the Bash interceptor is never read.
        let mut zsh = self::paths(&dir);
        zsh.login_shell = Some("zsh".into());
        assert_eq!(zsh.state(Integration::ThemeInterceptor), State::On);
        assert!(
            zsh.theme_caveat()
                .is_some_and(|caveat| caveat.contains("typed in zsh skip Guardian"))
        );
        assert_eq!(paths.theme_caveat(), None);
        let passwd = "root:x:0:0::/root:/usr/bin/bash\nu:x:1000:1000::/home/u:/usr/bin/zsh\nv:x:1001:1001::/home/v:\n";
        assert_eq!(
            super::shell_of(passwd, 1000).as_deref(),
            Some("/usr/bin/zsh")
        );
        assert_eq!(super::shell_of(passwd, 1001), None);
        assert_eq!(super::shell_of(passwd, 1002), None);

        // Turning it off removes only Guardian's overrides.
        let plan = paths
            .plan(Integration::ThemeInterceptor, &State::On)
            .unwrap();
        for step in &plan.steps {
            paths.edit(step).unwrap();
        }
        assert_eq!(paths.state(Integration::ThemeInterceptor), State::Off);
        assert_eq!(fs::read_to_string(&paths.menu).unwrap(), own);
    }

    const WAYBAR_CONFIG: &str = "{\n  \"layer\": \"top\",\n  \"modules-left\": [\"custom/omarchy\"],\n  \"modules-right\": [\"network\", \"battery\"],\n  // a comment\n  \"clock\": {}\n}\n";

    #[test]
    fn the_waybar_module_is_added_and_removed_exactly() {
        let added = super::with_waybar_module(WAYBAR_CONFIG).unwrap();
        assert!(
            added.contains(
                "\"modules-right\": [\"image#omarchy-guardian\", \"network\", \"battery\"]"
            )
        );
        assert_eq!(added.lines().nth(1).unwrap(), super::WAYBAR_DEFINITION);
        assert!(added.contains("// a comment"));
        // Adding twice keeps one copy.
        assert_eq!(super::with_waybar_module(&added).unwrap(), added);
        assert_eq!(super::without_waybar_module(&added), WAYBAR_CONFIG);

        let empty = "{\n  \"modules-right\": [],\n}\n";
        assert!(
            super::with_waybar_module(empty)
                .unwrap()
                .contains("[\"image#omarchy-guardian\"]")
        );
        assert!(super::with_waybar_module("{\n}\n").is_err());

        // An empty list over several lines, or with a comment in it,
        // gets no comma after the module.
        for empty in [
            "{\n  \"modules-right\": [\n  ]\n}\n",
            "{\n  \"modules-right\": [ /* none */ ]\n}\n",
            "{\n  \"modules-right\": [\n    // none\n  ]\n}\n",
        ] {
            let added = super::with_waybar_module(empty).unwrap();
            assert!(!added.contains("guardian\","), "{added}");
            assert!(!super::without_waybar_module(&added).contains("guardian"));
        }
        // One per line: taking it out leaves no comma of its own.
        let listed =
            "{\n  \"modules-right\": [\n    \"image#omarchy-guardian\",\n    \"clock\"\n  ]\n}\n";
        assert!(!super::without_waybar_module(listed).contains(','));
    }

    #[test]
    fn a_line_that_is_commented_out_turns_nothing_on() {
        let dir = TempDir::new("integrations-commented");
        let paths = paths(&dir);
        fs::create_dir_all(paths.menu.parent().unwrap()).unwrap();
        fs::write(&paths.menu, format!("{{\n  // {MENU_ENTRY}\n}}\n")).unwrap();
        assert_eq!(paths.state(Integration::MenuEntry), State::Off);
        // Named only in a comment after something else.
        assert!(!super::names(
            "  \"clock\", // \"image#omarchy-guardian\"",
            super::WAYBAR_MODULE
        ));
        assert!(super::names(
            "  \"image#omarchy-guardian\", // ours",
            super::WAYBAR_MODULE
        ));
        // Slashes inside a string before it start no comment.
        assert!(super::names(
            "  \"x\": \"https://a.test\", \"image#omarchy-guardian\"",
            super::WAYBAR_MODULE
        ));
        // A line that loads the interceptor with no marker above it is
        // taken out all the same.
        let loads = format!("x=1\n[[ -r y ]] && source {}\n", super::INTERCEPTOR_SOURCE);
        assert_eq!(without_interceptor(&loads), "x=1\n");
        // The marker alone, or the line after it commented out.
        for bashrc in [
            format!("{INTERCEPTOR_MARKER}\n"),
            format!(
                "{INTERCEPTOR_MARKER}\n# [[ -r x ]] && source {}\n",
                super::INTERCEPTOR_SOURCE
            ),
        ] {
            fs::write(&paths.bashrc, bashrc).unwrap();
            assert_eq!(paths.theme_parts().0, Part::Off);
        }
        fs::write(
            &paths.bashrc,
            format!("{INTERCEPTOR_MARKER}\n{INTERCEPTOR_LINE}\n"),
        )
        .unwrap();
        assert_eq!(paths.theme_parts().0, Part::On);
    }

    #[test]
    fn a_file_is_replaced_whole_and_a_link_to_it_stays_a_link() {
        let dir = TempDir::new("integrations-replace");
        let real = dir.path().join("real.conf");
        let link = dir.path().join("link.conf");
        fs::write(&real, "old\n").unwrap();
        symlink(&real, &link).unwrap();
        super::replace_file(&link, "new\n").unwrap();
        assert!(
            fs::symlink_metadata(&link)
                .unwrap()
                .file_type()
                .is_symlink()
        );
        assert_eq!(fs::read_to_string(&real).unwrap(), "new\n");
        // Nothing is left beside it.
        assert_eq!(fs::read_dir(dir.path()).unwrap().count(), 2);
        // Its mode stays what it was.
        fs::set_permissions(&real, fs::Permissions::from_mode(0o640)).unwrap();
        super::replace_file(&real, "newer\n").unwrap();
        assert_eq!(
            fs::metadata(&real).unwrap().permissions().mode() & 0o777,
            0o640
        );
        // A link that leads nowhere yet gets its file.
        let dangling = dir.path().join("dangling.conf");
        symlink(dir.path().join("made.conf"), &dangling).unwrap();
        super::replace_file(&dangling, "made\n").unwrap();
        assert_eq!(
            fs::read_to_string(dir.path().join("made.conf")).unwrap(),
            "made\n"
        );
    }

    #[test]
    fn the_waybar_integration_round_trips_config_and_style() {
        let dir = TempDir::new("integrations-waybar");
        let paths = paths(&dir);
        assert!(matches!(
            paths.state(Integration::WaybarModule),
            State::Unavailable(_)
        ));
        fs::create_dir_all(dir.path().join("waybar")).unwrap();
        fs::write(&paths.waybar_config, WAYBAR_CONFIG).unwrap();
        let style = "* { font-size: 12px; }\n\n#network,\n#battery {\n  padding: 0 9px;\n  border-radius: 11px;\n}\n\n#battery.warning { color: red; }\n";
        fs::write(&paths.waybar_style, style).unwrap();
        assert_eq!(paths.state(Integration::WaybarModule), State::Off);

        let on = paths.plan(Integration::WaybarModule, &State::Off).unwrap();
        for step in &on.steps {
            paths.edit(step).unwrap();
        }
        assert_eq!(paths.state(Integration::WaybarModule), State::On);
        assert!(
            fs::read_to_string(&paths.waybar_style)
                .unwrap()
                .contains("#image.omarchy-guardian { padding: 0 9px; border-radius: 11px; }")
        );

        let off = paths.plan(Integration::WaybarModule, &State::On).unwrap();
        for step in &off.steps {
            paths.edit(step).unwrap();
        }
        assert_eq!(paths.state(Integration::WaybarModule), State::Off);
        assert_eq!(
            fs::read_to_string(&paths.waybar_config).unwrap(),
            WAYBAR_CONFIG
        );
        assert_eq!(fs::read_to_string(&paths.waybar_style).unwrap(), style);
    }

    #[test]
    fn an_edited_waybar_line_is_repaired_by_turning_the_module_on() {
        let dir = TempDir::new("integrations-waybar-repair");
        let paths = paths(&dir);
        fs::create_dir_all(dir.path().join("waybar")).unwrap();
        fs::write(&paths.waybar_config, WAYBAR_CONFIG).unwrap();
        fs::write(&paths.waybar_style, "#battery { padding: 0 9px; }\n").unwrap();
        let on = paths.plan(Integration::WaybarModule, &State::Off).unwrap();
        for step in &on.steps {
            paths.edit(step).unwrap();
        }
        assert_eq!(paths.state(Integration::WaybarModule), State::On);

        // A line pointing at another binary, as a hand edit or an older
        // Guardian would leave it.
        let config = fs::read_to_string(&paths.waybar_config).unwrap();
        fs::write(
            &paths.waybar_config,
            config.replace(
                "\"omarchy-guardian status --waybar\"",
                "\"/tmp/other status --waybar\"",
            ),
        )
        .unwrap();
        let state = paths.state(Integration::WaybarModule);
        assert!(matches!(state, State::Partial(_)), "{state:?}");

        let repair = paths.plan(Integration::WaybarModule, &state).unwrap();
        for step in &repair.steps {
            paths.edit(step).unwrap();
        }
        assert_eq!(paths.state(Integration::WaybarModule), State::On);
        let repaired = fs::read_to_string(&paths.waybar_config).unwrap();
        assert!(!repaired.contains("/tmp/other"));
        assert_eq!(repaired.matches("\"image#omarchy-guardian\"").count(), 2);
    }

    #[test]
    fn a_comma_goes_before_a_comment_that_ends_the_line() {
        let text = "{\n  \"a\": \"x // not a comment\" // the last one\n}\n";
        let out = with_menu_entries(text, &["\"b\": 1"]).unwrap();
        assert_eq!(
            out,
            "{\n  \"a\": \"x // not a comment\", // the last one\n  \"b\": 1\n}\n"
        );
        // Already ended, or nothing before it: nothing is added.
        let out = with_menu_entries("{\n  \"a\": 1, // c\n}\n", &["\"b\": 1"]).unwrap();
        assert_eq!(out, "{\n  \"a\": 1, // c\n  \"b\": 1\n}\n");
    }
}
