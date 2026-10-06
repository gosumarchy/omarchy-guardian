//! What turning an integration on or off would do: the steps, the plan
//! that holds them, and how each is described.

use std::path::Path;

use super::{Integration, Part, Paths, State, WIDGET_ID, refresh, sudo};

/// Installs OpenCode from the official repos, root-owned, where the pacman
/// gate looks for it.
const INSTALL_OPENCODE: [&str; 4] = ["/usr/bin/pacman", "-S", "--needed", "extra/opencode"];

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

impl Paths {
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
}
