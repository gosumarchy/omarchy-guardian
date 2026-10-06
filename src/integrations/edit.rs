//! The file edits a plan's steps make: writing and replacing files, and the
//! text changes to the waybar, menu and Hyprland configuration.

use std::fs::{self, OpenOptions};
use std::io::Write as _;
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};

use crate::json::Json;

use super::plan::Step;
use super::shellscan::Loads;
use super::{
    HYPR_LINE, HYPR_PATH, INTERCEPTOR_SOURCE, MENU_ENTRY, MENU_ID, Paths, SESSION_ENV,
    SESSION_ENV_LINE, THEME_GATE, THEME_OVERRIDES, WAYBAR_DEFINITION, WAYBAR_MODULE,
    WAYBAR_STYLE_BEGIN, WAYBAR_STYLE_END, WIDGET_ID, comment_start, luascan, names, widget_files,
};

pub(super) const INTERCEPTOR_MARKER: &str = "# Omarchy Guardian theme command interception";
/// The lines `protect` adds at the end of `~/.config/hypr/hyprland.lua`:
/// after Omarchy's defaults, whose `envs.lua` puts Omarchy's own commands
/// first on PATH, and before Hyprland starts anything. Only the second,
/// exactly, counts as loading the file; a missing file is passed over.
pub(super) const HYPR_MARKER: &str = "-- Omarchy Guardian: its theme and plugin commands first on PATH. Keep this after Omarchy's defaults.";
/// What is left of a file as it was before Guardian first edited it.
const BACKUP_SUFFIX: &str = ".guardian-bak";
/// Waybar's CSS name for `image#omarchy-guardian`.
const WAYBAR_SELECTOR: &str = "#image.omarchy-guardian";

impl Paths {
    /// Applies one file-editing step.
    pub(crate) fn edit(&self, step: &Step) -> Result<(), String> {
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
pub(super) fn with_waybar_module(config: &str) -> Result<String, String> {
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
pub(super) fn replace_file(path: &Path, text: &str) -> Result<(), String> {
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
pub(super) fn without_waybar_module(config: &str) -> String {
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

/// `~/.bashrc` without the lines `install-user-interceptor.sh` adds: the
/// marker, the source line after it, and the blank line before it.
pub(super) fn without_interceptor(text: &str) -> String {
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

/// The menu file with `entries` added before its final `}`. A comma is
/// added after the previous entry when it has none.
pub(super) fn with_menu_entries(text: &str, entries: &[&str]) -> Result<String, String> {
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
