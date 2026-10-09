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

mod edit;
mod luascan;
mod menufile;
mod plan;
mod shellscan;

use std::env;
use std::fs;
use std::os::unix::fs::MetadataExt as _;
use std::path::{Path, PathBuf};

use crate::config::model::RootConsent;
use crate::json::Json;
use crate::paths::{self, Accept};
use crate::sweep::own;
use shellscan::Loads;

pub(crate) use plan::{Plan, Step};

const HOOK_SOURCE: &str = "/usr/share/omarchy-guardian/omarchy-guardian.hook";
const HOOK_TARGET: &str = "/etc/pacman.d/hooks/omarchy-guardian.hook";
const MAKEPKG_GATE: &str = "/usr/lib/omarchy-guardian/guardian-makepkg";
const INTERCEPTOR_INSTALLER: &str = "/usr/lib/omarchy-guardian/install-user-interceptor.sh";
const INTERCEPTOR_SOURCE: &str = "/usr/lib/omarchy-guardian/omarchy-bash-interceptor.sh";
/// The line `install-user-interceptor.sh` writes. Only this exact line
/// counts as loading the interceptor.
const INTERCEPTOR_LINE: &str = "[[ -r /usr/lib/omarchy-guardian/omarchy-bash-interceptor.sh ]] && source /usr/lib/omarchy-guardian/omarchy-bash-interceptor.sh";
/// Root-owned commands with the names of Omarchy's theme and plugin
/// installers (and of its dispatcher), which go through Guardian. First on
/// the session's PATH, they catch every caller that finds those commands
/// by name: scripts, other shells, launchers, key bindings.
const WRAPPERS: &str = "/usr/lib/omarchy-guardian/bin";
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
const HYPR_PATH: &str = "/usr/lib/omarchy-guardian/hyprland-path.lua";
const HYPR_LINE: &str = "pcall(dofile, \"/usr/lib/omarchy-guardian/hyprland-path.lua\")";
/// The file uwsm sources for the graphical session, after Omarchy's own
/// (`10-omarchy`), and the line in it that counts.
const SESSION_ENV_NAME: &str = "90-omarchy-guardian";
const SESSION_ENV_LINE: &str = "export PATH=\"/usr/lib/omarchy-guardian/bin:$PATH\"";
pub(crate) const SESSION_ENV: &str = "# Omarchy Guardian: theme and plugin installs found on PATH go through Guardian.\n# Written by `omarchy-guardian protect`, removed by `omarchy-guardian protect --off`.\nexport PATH=\"/usr/lib/omarchy-guardian/bin:$PATH\"\n";
/// AUR helpers Guardian has no gate for.
const UNGATED_HELPERS: [&str; 3] = ["pikaur", "aura", "trizen"];
const MENU_ID: &str = "\"setup.guardian\"";
/// The bar widget plugin the package ships, and its Omarchy plugin id.
const WIDGET_SOURCE: &str = "/usr/share/omarchy-guardian/bar-widget";
const WIDGET_ID: &str = "omarchy-guardian";
/// The same widget as a plugin of its own, added with `omarchy plugin add`.
/// Where that one is installed it is Guardian's bar widget, and the
/// packaged copy is not put beside it.
const LISTED_WIDGET_ID: &str = "io.github.gosumarchy.guardian";
/// The Waybar module: an image module showing the Guardian knight (calm,
/// alert or dimmed), its name in a modules list, its definition (one line, so
/// it can be found and removed exactly), and the markers of its style block.
const WAYBAR_MODULE: &str = "\"image#omarchy-guardian\"";
const WAYBAR_DEFINITION: &str = "  \"image#omarchy-guardian\": {\"exec\": \"omarchy-guardian status --waybar\", \"size\": 18, \"interval\": 30, \"signal\": 9, \"tooltip\": true, \"on-click\": \"omarchy-launch-tui --app-id=TUI.float omarchy-guardian tui\", \"on-click-right\": \"omarchy-guardian status --open-report\"},";
const WAYBAR_STYLE_BEGIN: &str = "/* Omarchy Guardian: begin */";
const WAYBAR_STYLE_END: &str = "/* Omarchy Guardian: end */";
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
/// The system sweep's timers, as the package installs them, and the links
/// `systemctl enable` makes for them.
const SWEEP_TIMER: &str = "omarchy-guardian-sweep.timer";
const SWEEP_ROOT_TIMER: &str = "omarchy-guardian-sweep-collect.timer";
const MENU_ENTRY: &str = "\"setup.guardian\": {\"icon\":\"󰒃\",\"label\":\"Guardian\",\"description\":\"Omarchy Guardian settings\",\"action\":\"omarchy-launch-tui --app-id=TUI.float omarchy-guardian tui\"},";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Integration {
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
    pub(crate) const ALL: [Self; 8] = [
        Self::PacmanHook,
        Self::AurGate,
        Self::ThemeInterceptor,
        Self::SessionPath,
        Self::MenuEntry,
        Self::BarWidget,
        Self::WaybarModule,
        Self::SystemSweep,
    ];

    pub(crate) const fn label(self) -> &'static str {
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

    pub(crate) const fn help(self) -> &'static str {
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
pub(crate) enum State {
    On,
    Off,
    /// Present, but not the packaged setup (for example a hand-installed hook).
    Foreign(String),
    /// On, but not doing its whole job; turning it on again completes it.
    Partial(String),
    Unavailable(String),
}

/// Where each integration lives. Tests point these into a temporary
/// directory.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Paths {
    pub(crate) hook_source: PathBuf,
    pub(crate) hook_target: PathBuf,
    pub(crate) yay: PathBuf,
    pub(crate) yay_config: PathBuf,
    pub(crate) interceptor_installer: PathBuf,
    pub(crate) bashrc: PathBuf,
    pub(crate) omarchy: PathBuf,
    pub(crate) menu: PathBuf,
    pub(crate) widget_source: PathBuf,
    pub(crate) widget_target: PathBuf,
    pub(crate) shell_config: PathBuf,
    pub(crate) waybar_config: PathBuf,
    pub(crate) waybar_style: PathBuf,
    /// The pacman gate needs a root-owned OpenCode and none is installed
    /// (see `pacman::preflight`).
    pub(crate) opencode_missing: bool,
    /// The sweep's user timer as packaged, and its enable link.
    pub(crate) sweep_timer: PathBuf,
    pub(crate) sweep_timer_link: PathBuf,
    /// The sweep's root timer as packaged, and its enable link.
    pub(crate) sweep_root_timer: PathBuf,
    pub(crate) sweep_root_timer_link: PathBuf,
    /// What the system configuration says about the root checks, and the
    /// group allowed to read the daily results.
    pub(crate) sweep_consent: Option<RootConsent>,
    pub(crate) sweep_group: Option<String>,
    /// The files that stand in for, or change, one of the sweep's own
    /// units (see `sweep::own`), relative to the root.
    pub(crate) sweep_overrides: Vec<String>,
    /// The name of the user's login shell (`bash`, `zsh`), if known.
    pub(crate) login_shell: Option<String>,
    /// Guardian's makepkg shim, which yay is pointed at.
    pub(crate) makepkg_gate: PathBuf,
    /// Who must own the files Guardian installs: root. Tests, which cannot
    /// make root's files, name their own user.
    pub(crate) owner: u32,
    /// Where other AUR helpers are installed.
    pub(crate) system_bin: PathBuf,
    pub(crate) paru_config: PathBuf,
    /// The shell start-up files an alias or function could be in.
    pub(crate) shell_startup: Vec<PathBuf>,
    /// This process's PATH, and the session service manager's if it can
    /// be asked.
    pub(crate) path_dirs: Vec<PathBuf>,
    pub(crate) manager_path: Option<Vec<PathBuf>>,
    /// The wrapper commands as packaged, and the session file that puts
    /// them first on PATH.
    pub(crate) wrappers: PathBuf,
    pub(crate) session_env: PathBuf,
    /// The user's Hyprland Lua configuration, which gets Guardian's line,
    /// and the packaged file that line loads.
    pub(crate) hypr_config: PathBuf,
    pub(crate) hypr_path: PathBuf,
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
    pub(crate) fn real(
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

    pub(crate) fn state(&self, integration: Integration) -> State {
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
    pub(crate) fn theme_caveat(&self) -> Option<String> {
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
        if self.listed_widget_stands_in() {
            return if self.widget_in_bar(LISTED_WIDGET_ID) {
                State::On
            } else {
                State::Off
            };
        }
        let installed = self.widget_target.join("manifest.json").is_file();
        let current = installed && self.widget_is_current();
        match (installed, self.widget_in_bar(WIDGET_ID)) {
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

    /// Whether the widget added as a plugin of its own is the one to go
    /// by: it is installed, and the packaged copy is either not there or
    /// out of the bar while this one is in it (what is left after the
    /// packaged one was taken out for it). Otherwise the packaged copy is
    /// still Guardian's to update and to remove.
    fn listed_widget_stands_in(&self) -> bool {
        let Some(plugins) = self.widget_target.parent() else {
            return false;
        };
        let manifest = plugins.join(LISTED_WIDGET_ID).join("manifest.json");
        let listed = manifest.is_file()
            && fs::read_to_string(manifest)
                .ok()
                .and_then(|text| Json::parse(&text).ok())
                .is_some_and(|json| {
                    json.get("id").and_then(Json::as_str) == Some(LISTED_WIDGET_ID)
                });
        listed
            && (!self.widget_target.join("manifest.json").is_file()
                || !self.widget_in_bar(WIDGET_ID) && self.widget_in_bar(LISTED_WIDGET_ID))
    }

    /// Whether the widget `id` is placed in the bar (`bar.layout` of
    /// shell.json).
    fn widget_in_bar(&self, id: &str) -> bool {
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
                        .any(|entry| entry.get("id").and_then(Json::as_str) == Some(id))
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
    pub(crate) fn helper_issues(&self) -> Vec<String> {
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
    pub(crate) fn unsettled(&self) -> Vec<Integration> {
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
    pub(crate) fn applies(&self, integration: Integration) -> bool {
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
    pub(crate) fn path_caveat(&self) -> Option<String> {
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

#[cfg(test)]
mod tests;
