//! The shell start-up and environment files that may give npm, pip or uv a
//! registry or index the sweep's own environment does not show: the sweep
//! may run from a timer or another session, while the tools ran from the
//! user's shell. The files are the autorun catalog's shell and environment
//! entries. A file is not parsed: any mention of a variable's name counts,
//! and so does a file that cannot be read, so a miss leaves packages out
//! rather than sending a private name.

use std::fs;
use std::io;
use std::path::Path;

use super::config::{ConfigFile, read_config};
use crate::autorun::{self, Category, Kind, Location};

/// The most files read. Arbitrary: well above the few dozen of a system
/// with every shell installed; past it, the rest count as unreadable.
const MAX_FILES: usize = 2_000;

/// How deep a catalogued directory is read. Arbitrary: `/etc/fish/conf.d`
/// is one below its location; a link back up is cut off here.
const MAX_DEPTH: usize = 4;

/// The parts of a catalogued path that mark files the shell reads only to
/// complete a command, define a function that runs when called, build a
/// package, edit a line, or log out: none sets the environment the tools
/// later run in. The completion files are many, and generated ones name
/// every variable a tool reads in their help text.
const NOT_START_UP: &[&str] = &["completion", "functions", "makepkg", "inputrc", "logout"];

/// pip's variables that set an index or a file that can, lowercased.
const PIP_VARIABLES: &[&str] = &[
    "pip_index_url",
    "pip_extra_index_url",
    "pip_find_links",
    "pip_requirement",
    "pip_constraint",
    "pip_config_file",
];

/// uv's the same way; `uv_index` covers every `UV_INDEX*` variable.
const UV_VARIABLES: &[&str] = &[
    "uv_index",
    "uv_default_index",
    "uv_extra_index_url",
    "uv_find_links",
    "uv_config_file",
];

/// npm's the same way; `npm_config_@` starts a scope's own registry. npm
/// reads `npm_config_*` in any case.
const NPM_VARIABLES: &[&str] = &[
    "npm_config_registry",
    "npm_config_userconfig",
    "npm_config_globalconfig",
    "npm_config_@",
];

/// The start-up files that name each tool's variables, and those that
/// could not be read, each as said to the user.
#[derive(Debug, Default)]
pub(super) struct Startup {
    pub(super) pip: Vec<String>,
    pub(super) uv: Vec<String>,
    pub(super) npm: Vec<String>,
    /// What is there and could not be read or listed, or is past
    /// `MAX_FILES`: it may name any of them.
    pub(super) unreadable: Vec<String>,
}

impl Startup {
    /// Reads the system's start-up files and, with a `home` (relative to
    /// the root), the user's.
    pub(super) fn read(root: &Path, home: Option<&str>) -> Self {
        let mut startup = Self::default();
        let mut files = Vec::new();
        let user = home.map(|home| (format!("{home}/"), autorun::USER));
        let catalog = [
            (String::new(), autorun::SYSTEM),
            (String::new(), autorun::SYSTEM_SWEEP),
        ]
        .into_iter()
        .chain(user);
        for (prefix, locations) in catalog {
            for location in locations.iter().filter(|location| is_start_up(location)) {
                let path = format!("{prefix}{}", location.path.trim_end_matches('/'));
                match location.kind {
                    Kind::File => files.push(path),
                    Kind::Directory => startup.list(root, &path, 0, &mut files),
                    // None of the shell's entries is one of these; one
                    // added later is not read, and that is said.
                    Kind::Units | Kind::Manager | Kind::Glob => {
                        startup.unreadable.push(format!("/{path}"));
                    }
                }
            }
        }
        if files.len() > MAX_FILES {
            files.truncate(MAX_FILES);
            startup.unreadable.push(format!(
                "the shell start-up and environment files past the first {MAX_FILES}"
            ));
        }
        for file in files {
            startup.scan(root, &file);
        }
        startup
    }

    /// Whether pip may be set to another index by a start-up file.
    pub(super) fn sets_pip(&self) -> bool {
        !self.pip.is_empty() || !self.unreadable.is_empty()
    }

    /// The same for uv.
    pub(super) fn sets_uv(&self) -> bool {
        !self.uv.is_empty() || !self.unreadable.is_empty()
    }

    /// The same for npm's registry or its configuration files.
    pub(super) fn sets_npm(&self) -> bool {
        !self.npm.is_empty() || !self.unreadable.is_empty()
    }

    /// Adds the files under `directory`, following links as the shell
    /// does.
    fn list(&mut self, root: &Path, directory: &str, depth: usize, files: &mut Vec<String>) {
        if files.len() > MAX_FILES {
            return;
        }
        let path = root.join(directory);
        match fs::metadata(&path) {
            Err(error) if error.kind() == io::ErrorKind::NotFound => return,
            Ok(metadata) if !metadata.is_dir() => {
                files.push(directory.to_string());
                return;
            }
            Ok(_) if depth < MAX_DEPTH => {}
            Ok(_) | Err(_) => {
                self.unreadable.push(format!("/{directory}"));
                return;
            }
        }
        let Ok(listing) = fs::read_dir(&path) else {
            self.unreadable.push(format!("/{directory}"));
            return;
        };
        let mut names = Vec::new();
        let mut whole = true;
        for entry in listing {
            match entry.map(|entry| entry.file_name().into_string()) {
                Ok(Ok(name)) => names.push(name),
                Ok(Err(_)) | Err(_) => whole = false,
            }
        }
        if !whole {
            self.unreadable.push(format!("/{directory}"));
        }
        names.sort();
        for name in names {
            self.list(root, &format!("{directory}/{name}"), depth + 1, files);
        }
    }

    /// Notes which tools' variables `file` names.
    fn scan(&mut self, root: &Path, file: &str) {
        let text = match read_config(root, file) {
            ConfigFile::Absent => return,
            ConfigFile::Unreadable => {
                self.unreadable.push(format!("/{file}"));
                return;
            }
            ConfigFile::Text(text) => text.to_ascii_lowercase(),
        };
        for (variables, files) in [
            (PIP_VARIABLES, &mut self.pip),
            (UV_VARIABLES, &mut self.uv),
            (NPM_VARIABLES, &mut self.npm),
        ] {
            if variables.iter().any(|variable| text.contains(variable)) {
                files.push(format!("/{file}"));
            }
        }
    }
}

/// Whether a catalogued location is one the shell or the session reads
/// before the tools run.
fn is_start_up(location: &Location) -> bool {
    matches!(location.category, Category::Shell | Category::Environment)
        && !NOT_START_UP.iter().any(|part| location.path.contains(part))
}
