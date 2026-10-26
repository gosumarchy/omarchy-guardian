//! The shell start-up, session and mise files that may give npm, pip or uv
//! a registry or index the sweep's own environment does not show: the
//! sweep may run from a timer or another session, while the tools ran
//! from the user's shell. The start-up files are the ones the `PATH` check
//! reads (`path::start_up_files`), with what they read in; mise's own
//! configuration is added, since mise sets its `[env]` in every shell it is
//! turned on for. A file is not parsed: any mention of a variable's name
//! counts, and so does a file that cannot be read, so a miss leaves
//! packages out rather than sending a private name.

use crate::sweep::collect::Scope;
use crate::sweep::path;

/// mise's configuration files that apply in every directory under the
/// home, relative to it, and the system's, relative to the root; `*`
/// stands for any run of characters (`config.local.toml`, a profile's
/// `config.<env>.toml`).
const MISE_HOME_FILES: &[&str] = &[
    ".config/mise/config.toml",
    ".config/mise/config.*.toml",
    ".config/mise/conf.d/*.toml",
    ".config/mise.toml",
    ".mise.toml",
    ".mise.*.toml",
    "mise.toml",
    "mise.*.toml",
];
const MISE_SYSTEM_FILES: &[&str] = &[
    "etc/mise/config.toml",
    "etc/mise/config.*.toml",
    "etc/mise/conf.d/*.toml",
];

/// The `[env]` directives with which mise loads variables from other
/// files (dotenv files, scripts), which are not read: a mise file that
/// names one counts as one that cannot be read.
const MISE_ENV_FILES: &[&str] = &["_.file", "_.source"];

/// The parts of a path that mark files the shell reads only to complete a
/// command, define a function that runs when called, build a package, edit
/// a line, or log out: none sets the environment the tools later run in.
/// Generated completions name every variable a tool reads in their help
/// text.
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
    /// What is there and could not be read or listed, or was not reached:
    /// it may name any of them.
    pub(super) unreadable: Vec<String>,
}

impl Startup {
    /// Reads the system's start-up and mise files and, with a home, the
    /// user's.
    pub(super) fn read(scope: &Scope<'_>) -> Self {
        let mise_home = scope.home.into_iter().flat_map(|home| {
            MISE_HOME_FILES
                .iter()
                .map(move |file| format!("{home}/{file}"))
        });
        let mise_system = MISE_SYSTEM_FILES.iter().map(|file| (*file).to_string());
        let mise: Vec<String> = mise_home.chain(mise_system).collect();

        let mut startup = Self::default();
        let shell = path::start_up_files(scope, &path::start_up_patterns(scope));
        startup.take(shell);
        let mise = path::start_up_files(scope, &mise);
        for (file, text) in &mise.files {
            let text = text.to_ascii_lowercase();
            if MISE_ENV_FILES
                .iter()
                .any(|directive| text.contains(directive))
            {
                startup.unreadable.push(format!("/{file}"));
            }
        }
        startup.take(mise);
        startup
    }

    /// Notes what `start_up` read and could not read, leaving out what is
    /// not a start-up file.
    fn take(&mut self, start_up: path::StartUp) {
        self.unreadable.extend(
            start_up
                .unreadable
                .into_iter()
                .filter(|path| is_start_up(path)),
        );
        for (file, text) in &start_up.files {
            if is_start_up(file) {
                self.scan(file, text);
            }
        }
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

    /// Notes which tools' variables `file` names.
    fn scan(&mut self, file: &str, text: &str) {
        let text = text.to_ascii_lowercase();
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

/// Whether a path read is one the shell or the session reads before the
/// tools run.
fn is_start_up(path: &str) -> bool {
    !NOT_START_UP.iter().any(|part| path.contains(part))
}
