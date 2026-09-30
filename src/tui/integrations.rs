//! The pieces that connect Guardian to the system: the pacman hook, the yay
//! makepkg gate, the Bash theme interceptor and the Omarchy menu entry.
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
pub const MENU_ENTRY: &str = "\"setup.guardian\": {\"icon\":\"󰒃\",\"label\":\"Guardian\",\"description\":\"Omarchy Guardian settings\",\"action\":\"omarchy-launch-tui --app-id=TUI.float omarchy-guardian tui\"},";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Integration {
    PacmanHook,
    AurGate,
    ThemeInterceptor,
    MenuEntry,
}

impl Integration {
    pub const ALL: [Self; 4] = [
        Self::PacmanHook,
        Self::AurGate,
        Self::ThemeInterceptor,
        Self::MenuEntry,
    ];

    pub const fn label(self) -> &'static str {
        match self {
            Self::PacmanHook => "Pacman hook",
            Self::AurGate => "AUR gate (yay)",
            Self::ThemeInterceptor => "Theme install gate",
            Self::MenuEntry => "Omarchy menu entry",
        }
    }

    pub const fn help(self) -> &'static str {
        match self {
            Self::PacmanHook => {
                "Reviews install scriptlets before every pacman transaction. Needs sudo to change."
            }
            Self::AurGate => "Makes yay build AUR packages through Guardian's makepkg gate.",
            Self::ThemeInterceptor => {
                "Routes `omarchy theme install/update` in Bash through Guardian. Takes effect in new shells."
            }
            Self::MenuEntry => "Adds Setup › Guardian to the Omarchy menu, opening this window.",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum State {
    On,
    Off,
    /// Present, but not the packaged setup (for example a hand-installed hook).
    Foreign(String),
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
}

impl Paths {
    pub fn real() -> Option<Self> {
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
                let enabled = fs::read_to_string(&self.bashrc)
                    .is_ok_and(|text| text.lines().any(|line| line == INTERCEPTOR_MARKER));
                if enabled { State::On } else { State::Off }
            }
            Integration::MenuEntry => {
                if !self.omarchy.is_dir() {
                    return State::Unavailable("Omarchy is not installed".into());
                }
                let enabled =
                    fs::read_to_string(&self.menu).is_ok_and(|text| text.contains(MENU_ID));
                if enabled { State::On } else { State::Off }
            }
        }
    }

    fn hook_state(&self) -> State {
        if !self.hook_source.exists() {
            return State::Unavailable("the omarchy-guardian package is not installed".into());
        }
        match fs::read_link(&self.hook_target) {
            Ok(target) if target == self.hook_source => State::On,
            Ok(target) => State::Foreign(format!("links to {}", target.display())),
            Err(_) if fs::symlink_metadata(&self.hook_target).is_ok() => {
                State::Foreign("a hand-installed hook file".into())
            }
            Err(_) => State::Off,
        }
    }

    /// The plan that flips `integration` from `state`; `None` when it
    /// cannot be changed from here.
    pub fn plan(&self, integration: Integration, state: &State) -> Option<Plan> {
        let text = |path: &Path| path.display().to_string();
        let on = match state {
            State::On => false,
            State::Off | State::Foreign(_) => true,
            State::Unavailable(_) => return None,
        };
        let sudo = |args: &[&str]| {
            let mut argv = vec!["/usr/bin/sudo".to_string()];
            argv.extend(args.iter().map(ToString::to_string));
            Step::Command(argv)
        };

        let (summary, steps) = match (integration, on) {
            (Integration::PacmanHook, true) => (
                "Enable the pacman hook",
                vec![
                    sudo(&[
                        "/usr/bin/install",
                        "-d",
                        "-m",
                        "0755",
                        "/etc/pacman.d/hooks",
                    ]),
                    sudo(&[
                        "/usr/bin/ln",
                        "-sfn",
                        &text(&self.hook_source),
                        &text(&self.hook_target),
                    ]),
                ],
            ),
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
            (Integration::ThemeInterceptor, true) => (
                "Enable the theme install gate",
                vec![Step::Command(vec![text(&self.interceptor_installer)])],
            ),
            (Integration::ThemeInterceptor, false) => (
                "Disable the theme install gate",
                vec![Step::RemoveInterceptor],
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
                    Step::Optional(vec!["omarchy-menu".into(), "refresh".into()]),
                ],
            ),
        };
        Some(Plan {
            summary: summary.to_string(),
            steps,
        })
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
            Step::AddMenuEntry => {
                let text = if let Ok(text) = fs::read_to_string(&self.menu) {
                    with_menu_entry(&text)?
                } else {
                    if let Some(directory) = self.menu.parent() {
                        fs::create_dir_all(directory).map_err(|error| error.to_string())?;
                    }
                    format!("{{\n  {MENU_ENTRY}\n}}\n")
                };
                fs::write(&self.menu, text).map_err(|error| error.to_string())
            }
            Step::RemoveMenuEntry => {
                let text = fs::read_to_string(&self.menu).map_err(|error| error.to_string())?;
                let kept: Vec<&str> = text
                    .lines()
                    .filter(|line| !line.contains(MENU_ID))
                    .collect();
                fs::write(&self.menu, kept.join("\n") + "\n").map_err(|error| error.to_string())
            }
            Step::Command(_) | Step::Optional(_) => Ok(()),
        }
    }
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

/// The menu file with the Guardian entry added before its final `}`. A
/// comma is added after the previous entry when it has none.
fn with_menu_entry(text: &str) -> Result<String, String> {
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
    out.insert(closing, format!("  {MENU_ENTRY}"));
    Ok(out.join("\n") + "\n")
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::os::unix::fs::symlink;

    use super::{
        INTERCEPTOR_MARKER, Integration, MENU_ENTRY, Paths, State, Step, with_menu_entry,
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
        assert_eq!(paths.state(Integration::ThemeInterceptor), State::On);
        paths.edit(&Step::RemoveInterceptor).unwrap();
        assert_eq!(paths.state(Integration::ThemeInterceptor), State::Off);
    }

    #[test]
    fn menu_entry_is_added_and_removed() {
        let template = "{\n  // Comments\n  // \"personal\": {\"icon\":\"\"},\n}\n";
        let added = with_menu_entry(template).unwrap();
        assert!(added.ends_with(&format!("  {MENU_ENTRY}\n}}\n")));

        let without_comma = "{\n  \"a\": {\"label\":\"A\"}\n}\n";
        assert!(
            with_menu_entry(without_comma)
                .unwrap()
                .contains("\"a\": {\"label\":\"A\"},\n")
        );
        assert!(with_menu_entry("{ \"a\": 1 }").is_err());

        let dir = TempDir::new("integrations-menu");
        let paths = paths(&dir);
        assert_eq!(paths.state(Integration::MenuEntry), State::Off);
        paths.edit(&Step::AddMenuEntry).unwrap();
        assert_eq!(paths.state(Integration::MenuEntry), State::On);
        paths.edit(&Step::RemoveMenuEntry).unwrap();
        assert_eq!(paths.state(Integration::MenuEntry), State::Off);
        assert_eq!(fs::read_to_string(&paths.menu).unwrap(), "{\n}\n");
    }
}
