//! The pieces that connect Guardian to the system: the pacman hook, the yay
//! makepkg gate, the Bash theme interceptor, the Omarchy menu entry and the
//! bar widget.
//! Each has a state read from disk and a plan to turn it on or off. Plans
//! that need root or another program run as commands on the terminal (so
//! `sudo` can ask for a password); the rest are small, exact file edits.

use std::env;
use std::fs;
use std::path::{Path, PathBuf};

use crate::json::Json;

pub const HOOK_SOURCE: &str = "/usr/share/omarchy-guardian/omarchy-guardian.hook";
pub const HOOK_TARGET: &str = "/etc/pacman.d/hooks/omarchy-guardian.hook";
pub const MAKEPKG_GATE: &str = "/usr/lib/omarchy-guardian/guardian-makepkg";
pub const INTERCEPTOR_INSTALLER: &str = "/usr/lib/omarchy-guardian/install-user-interceptor.sh";
const INTERCEPTOR_MARKER: &str = "# Omarchy Guardian theme command interception";
const INTERCEPTOR_SOURCE: &str = "/usr/lib/omarchy-guardian/omarchy-bash-interceptor.sh";
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
pub const MENU_ENTRY: &str = "\"setup.guardian\": {\"icon\":\"󰒃\",\"label\":\"Guardian\",\"description\":\"Omarchy Guardian settings\",\"action\":\"omarchy-launch-tui --app-id=TUI.float omarchy-guardian tui\"},";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Integration {
    PacmanHook,
    AurGate,
    ThemeInterceptor,
    MenuEntry,
    BarWidget,
    WaybarModule,
}

impl Integration {
    pub const ALL: [Self; 6] = [
        Self::PacmanHook,
        Self::AurGate,
        Self::ThemeInterceptor,
        Self::MenuEntry,
        Self::BarWidget,
        Self::WaybarModule,
    ];

    pub const fn label(self) -> &'static str {
        match self {
            Self::PacmanHook => "Pacman hook",
            Self::AurGate => "AUR gate (yay)",
            Self::ThemeInterceptor => "Theme & plugin gate",
            Self::MenuEntry => "Omarchy menu entry",
            Self::BarWidget => "Bar widget",
            Self::WaybarModule => "Waybar module",
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
            Self::MenuEntry => "Adds Setup › Guardian to the Omarchy menu, opening this window.",
            Self::BarWidget => {
                "A shield in the Omarchy bar showing whether Guardian protects this machine, what needs attention and the last block."
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
            })
            .collect()
    }

    /// Commands may ask for a password or print, so they run on the normal
    /// screen; optional steps (a menu refresh) run silently.
    pub fn needs_terminal(&self) -> bool {
        self.steps
            .iter()
            .any(|step| matches!(step, Step::Command(_)))
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
}

impl Paths {
    pub fn real(opencode_missing: bool) -> Option<Self> {
        let home = env::var_os("HOME")
            .map(PathBuf::from)
            .filter(|path| path.is_absolute())?;
        let config = env::var_os("XDG_CONFIG_HOME")
            .map(PathBuf::from)
            .filter(|path| path.is_absolute())
            .unwrap_or_else(|| home.join(".config"));
        Some(Self {
            hook_source: HOOK_SOURCE.into(),
            hook_target: HOOK_TARGET.into(),
            yay: "/usr/bin/yay".into(),
            yay_config: config.join("yay/config.json"),
            interceptor_installer: INTERCEPTOR_INSTALLER.into(),
            bashrc: home.join(".bashrc"),
            omarchy: "/usr/share/omarchy".into(),
            menu: config.join("omarchy/extensions/omarchy-menu.jsonc"),
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
        })
    }

    pub fn state(&self, integration: Integration) -> State {
        match integration {
            Integration::PacmanHook => self.hook_state(),
            Integration::AurGate => {
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
                    Some(MAKEPKG_GATE) => State::On,
                    _ => State::Off,
                }
            }
            Integration::ThemeInterceptor => {
                if !self.interceptor_installer.exists() {
                    return State::Unavailable(
                        "the omarchy-guardian package is not installed".into(),
                    );
                }
                match self.theme_parts() {
                    (true, None | Some(true)) => State::On,
                    (true, Some(false)) => State::Partial(
                        "terminal only: themes and plugins from the Omarchy menu skip Guardian"
                            .into(),
                    ),
                    (false, Some(true)) => State::Partial(
                        "menu only: `omarchy theme` and `omarchy plugin` in Bash skip Guardian"
                            .into(),
                    ),
                    (false, None | Some(false)) => State::Off,
                }
            }
            Integration::MenuEntry => {
                if !self.omarchy.is_dir() {
                    return State::Unavailable("Omarchy is not installed".into());
                }
                let enabled =
                    fs::read_to_string(&self.menu).is_ok_and(|text| text.contains(MENU_ID));
                if enabled { State::On } else { State::Off }
            }
            Integration::BarWidget => self.widget_state(),
            Integration::WaybarModule => self.waybar_state(),
        }
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
            .any(|line| line.contains(WAYBAR_MODULE) && !line.trim_start().starts_with(&key));
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

    /// Whether the Bash interceptor is in `~/.bashrc`, and whether the
    /// Omarchy menu's theme items are overridden (`None` without Omarchy).
    fn theme_parts(&self) -> (bool, Option<bool>) {
        let bash = fs::read_to_string(&self.bashrc)
            .is_ok_and(|text| text.lines().any(|line| line == INTERCEPTOR_MARKER));
        let menu = self.omarchy.is_dir().then(|| {
            fs::read_to_string(&self.menu).is_ok_and(|text| {
                THEME_OVERRIDES.iter().all(|(id, _)| {
                    text.lines()
                        .any(|line| line.contains(id) && line.contains(THEME_GATE))
                })
            })
        });
        (bash, menu)
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
            (Integration::AurGate, _) => {
                let makepkg = if on { MAKEPKG_GATE } else { "makepkg" };
                (
                    if on {
                        "Enable the AUR gate"
                    } else {
                        "Disable the AUR gate"
                    },
                    vec![Step::Command(vec![
                        text(&self.yay),
                        "--makepkg".into(),
                        makepkg.into(),
                        "--save".into(),
                        "-P".into(),
                        "--stats".into(),
                    ])],
                )
            }
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
    /// `on`.
    fn theme_steps(&self, on: bool) -> Vec<Step> {
        let (bash, menu) = self.theme_parts();
        let mut steps = Vec::new();
        if on && !bash {
            steps.push(Step::Command(vec![
                self.interceptor_installer.display().to_string(),
            ]));
        }
        if !on && bash {
            steps.push(Step::RemoveInterceptor);
        }
        if menu == Some(!on) {
            steps.push(if on {
                Step::AddThemeMenu
            } else {
                Step::RemoveThemeMenu
            });
            steps.push(refresh());
        }
        steps
    }

    /// Applies one file-editing step.
    pub fn edit(&self, step: &Step) -> Result<(), String> {
        match step {
            Step::RemoveInterceptor => {
                let text = fs::read_to_string(&self.bashrc).map_err(|error| error.to_string())?;
                // Written in place, so a symlinked ~/.bashrc stays a symlink.
                fs::write(&self.bashrc, without_interceptor(&text))
                    .map_err(|error| error.to_string())
            }
            Step::AddMenuEntry => self.add_menu_lines(&[MENU_ENTRY]),
            Step::RemoveMenuEntry => self.remove_menu_lines(&|line| line.contains(MENU_ID)),
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
                fs::write(&self.waybar_config, with_waybar_module(&config)?)
                    .map_err(|error| error.to_string())?;
                let style = without_waybar_style(
                    &fs::read_to_string(&self.waybar_style).unwrap_or_default(),
                );
                let separator = if style.is_empty() || style.ends_with('\n') {
                    ""
                } else {
                    "\n"
                };
                fs::write(
                    &self.waybar_style,
                    format!("{style}{separator}\n{}", waybar_style(&style)),
                )
                .map_err(|error| error.to_string())
            }
            Step::RemoveWaybarModule => {
                if let Ok(config) = fs::read_to_string(&self.waybar_config) {
                    fs::write(&self.waybar_config, without_waybar_module(&config))
                        .map_err(|error| error.to_string())?;
                }
                if let Ok(style) = fs::read_to_string(&self.waybar_style) {
                    fs::write(&self.waybar_style, without_waybar_style(&style))
                        .map_err(|error| error.to_string())?;
                }
                Ok(())
            }
            Step::Command(_) | Step::Optional(_) => Ok(()),
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
        fs::write(&self.menu, text).map_err(|error| error.to_string())
    }

    fn remove_menu_lines(&self, remove: &dyn Fn(&str) -> bool) -> Result<(), String> {
        let text = fs::read_to_string(&self.menu).map_err(|error| error.to_string())?;
        let kept: Vec<&str> = text.lines().filter(|line| !remove(line)).collect();
        fs::write(&self.menu, kept.join("\n") + "\n").map_err(|error| error.to_string())
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
        .position(|line| line.contains("\"modules-right\"") && line.contains('['))
        .ok_or("the Waybar config has no \"modules-right\" list")?;
    let line = &lines[modules];
    let at = line.find('[').map_or(line.len(), |index| index + 1);
    let rest = line[at..].trim_start();
    let comma = if rest.starts_with(']') { "" } else { ", " };
    lines[modules] = format!("{}{WAYBAR_MODULE}{comma}{rest}", &line[..at]);
    lines.insert(opening + 1, WAYBAR_DEFINITION.to_string());
    Ok(lines.join("\n") + "\n")
}

/// `config` without the Guardian module's definition line or list entries.
fn without_waybar_module(config: &str) -> String {
    let definition = format!("{WAYBAR_MODULE}:");
    let kept: Vec<String> = config
        .lines()
        .filter(|line| !line.trim_start().starts_with(&definition))
        .map(|line| {
            line.replace(&format!("{WAYBAR_MODULE}, "), "")
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
        kept.push(lines[index]);
        index += 1;
    }
    let mut out = kept.join("\n");
    if text.ends_with('\n') {
        out.push('\n');
    }
    out
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
        let line = out[previous].trim_end().to_string();
        if !line.ends_with(',') && !line.ends_with('{') {
            out[previous] = format!("{line},");
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
    use std::os::unix::fs::symlink;

    use super::{
        INTERCEPTOR_MARKER, Integration, MENU_ENTRY, Paths, State, Step, with_menu_entries,
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
        }
    }

    #[test]
    fn hook_state_distinguishes_the_packaged_link() {
        let dir = TempDir::new("integrations-hook");
        let paths = paths(&dir);
        assert_eq!(paths.state(Integration::PacmanHook), State::Off);

        fs::create_dir_all(dir.path().join("hooks")).unwrap();
        symlink(&paths.hook_source, &paths.hook_target).unwrap();
        assert_eq!(paths.state(Integration::PacmanHook), State::On);
        let plan = paths.plan(Integration::PacmanHook, &State::On).unwrap();
        assert!(matches!(&plan.steps[..], [Step::Command(argv)] if argv[1] == "/usr/bin/rm"));

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
        fs::write(
            &paths.yay_config,
            r#"{"makepkgbin": "/usr/lib/omarchy-guardian/guardian-makepkg"}"#,
        )
        .unwrap();
        assert_eq!(paths.state(Integration::AurGate), State::On);
        let plan = paths.plan(Integration::AurGate, &State::On).unwrap();
        assert!(matches!(&plan.steps[..], [Step::Command(argv)] if argv[2] == "makepkg"));
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
            format!("{INTERCEPTOR_MARKER}\n[[ -r x ]] && source /usr/lib/omarchy-guardian/omarchy-bash-interceptor.sh\n"),
        )
        .unwrap();
        assert_eq!(paths.state(Integration::ThemeInterceptor), State::On);

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
}
