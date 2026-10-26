//! What npm's, pip's, uv's and cargo's configuration say about where
//! packages come from, read locally only. These files hold registry tokens and index
//! passwords: only the keys named here are taken, and nothing of them is
//! shown or sent.
//!
//! A package from a registry other than the public one may have a private
//! name, which must not go to OSV: npm's `registry` (or a scope's own),
//! the `_resolved` an older npm wrote in `package.json`, pip's
//! `index-url`, `extra-index-url` and `find-links`, uv's index settings
//! (for what mise installs through uv), and cargo's source replacement
//! decide that.

use std::env;
use std::fmt;
use std::fs;
use std::io;
use std::path::{Component, Path};

use crate::files::read_small_file;
use crate::json::Json;
use crate::tomlish;

/// The largest configuration file read. Arbitrary: such a file holds a few
/// lines.
const MAX_CONFIG_BYTES: u64 = 1024 * 1024;

/// The global npm configuration file Arch's npm is built to read, besides
/// the one under the prefix.
const ARCH_NPMRC: &str = "etc/npmrc";

/// pip's global configuration files, read before the user's.
const GLOBAL_PIP: &[&str] = &["etc/xdg/pip/pip.conf", "etc/pip.conf"];

/// uv's global configuration files, read with the user's. uv reads the
/// first of the XDG ones; all are read here, which can only leave more out.
const GLOBAL_UV: &[&str] = &["etc/xdg/uv/uv.toml", "etc/uv/uv.toml"];

/// The keys of `uv.toml` that bring packages from somewhere other than the
/// Python Package Index, at the top or under `[pip]`; `index` is the
/// `[[index]]` table.
const UV_INDEX_KEYS: &[&str] = &["index", "index-url", "extra-index-url", "find-links"];

/// The keys of a requirement in uv's record of a tool that leave it on the
/// Python Package Index.
const UV_REQUIREMENT_KEYS: &[&str] = &["name", "specifier", "extras", "marker"];

/// The environment variables that do the same for uv.
const UV_INDEX_VARIABLES: &[&str] = &[
    "UV_INDEX",
    "UV_DEFAULT_INDEX",
    "UV_INDEX_URL",
    "UV_EXTRA_INDEX_URL",
    "UV_FIND_LINKS",
];

/// The npm settings the inventory reads, besides each scope's
/// `@scope:registry`.
const NPM_KEYS: &[&str] = &[
    "prefix",
    "globalconfig",
    "userconfig",
    "ignore-scripts",
    "registry",
];

/// The hosts of npm's public registry. Yarn's serves the same packages
/// under the same names.
const NPM_REGISTRIES: &[&str] = &["registry.npmjs.org", "registry.yarnpkg.com"];

/// The hosts of the Python Package Index.
const PYPI_HOSTS: &[&str] = &["pypi.org", "pypi.python.org", "files.pythonhosted.org"];

/// The pip settings that bring packages from somewhere other than the
/// Python Package Index, with those that name a requirements or
/// constraints file, which can set an index.
const PIP_INDEX_KEYS: &[&str] = &[
    "index-url",
    "extra-index-url",
    "find-links",
    "requirement",
    "constraint",
];

/// pip's long options that do the same, as pipx records them, with those
/// that name a requirements or constraints file, which can set an index.
const PIP_INDEX_OPTIONS: &[&str] = &[
    "index-url",
    "extra-index-url",
    "find-links",
    "requirement",
    "constraint",
];

/// Their short forms: `-i`, `-f`, `-r` and `-c`.
const PIP_INDEX_SHORT_OPTIONS: &[char] = &['i', 'f', 'r', 'c'];

/// Where the tools keep what they installed and their configuration,
/// relative to the root, with the settings the environment gives.
pub(super) struct Places {
    /// mise's data directory (`MISE_DATA_DIR`).
    pub(super) mise: Option<String>,
    /// cargo's home (`CARGO_HOME`).
    pub(super) cargo: Option<String>,
    /// pipx's home (`PIPX_HOME`).
    pub(super) pipx: Option<String>,
    /// The user's npm configuration (`npm_config_userconfig`).
    pub(super) npmrc: Option<String>,
    /// pip's configuration files other than the global ones: the user's,
    /// those under `XDG_CONFIG_DIRS`, and `PIP_CONFIG_FILE`.
    pub(super) pip: Vec<String>,
    /// uv's the same way: the user's, those under `XDG_CONFIG_DIRS`, and
    /// `UV_CONFIG_FILE`.
    pub(super) uv: Vec<String>,
    /// The home directory, which `~` in npm's `prefix` stands for.
    pub(super) home: Option<String>,
    /// npm settings the environment gives (`npm_config_*`, in any case),
    /// as a file would write them: they win over every file.
    pub(super) npm_env: Vec<(String, String)>,
    /// pip's index settings the environment gives (`PIP_INDEX_URL` and the
    /// like), as a file would write them.
    pub(super) pip_env: Vec<(String, String)>,
    /// The uv index variables the environment sets (`UV_INDEX_URL` and the
    /// like), by name.
    pub(super) uv_env: Vec<String>,
    /// npm's default global prefix where no `prefix` is set (`PREFIX`).
    pub(super) npm_global_prefix: Option<String>,
    /// The variables that name a configuration file, a tool's directory or
    /// an XDG directory by a path that is not absolute
    /// (`npm_config_userconfig`, `PIP_CONFIG_FILE`, `UV_CONFIG_FILE`,
    /// `CARGO_HOME`, `PIPX_HOME`, `MISE_DATA_DIR`, `XDG_CONFIG_HOME`,
    /// `XDG_CONFIG_DIRS`), with their value: it is not found here.
    pub(super) unfound: Vec<(&'static str, String)>,
}

impl fmt::Debug for Places {
    /// Names the environment's settings without their values, which may be
    /// addresses that hold a password.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let keys = |settings: &[(String, String)]| -> Vec<String> {
            settings.iter().map(|(key, _)| key.clone()).collect()
        };
        f.debug_struct("Places")
            .field("mise", &self.mise)
            .field("cargo", &self.cargo)
            .field("pipx", &self.pipx)
            .field("npmrc", &self.npmrc)
            .field("pip", &self.pip)
            .field("uv", &self.uv)
            .field("home", &self.home)
            .field("npm_env", &keys(&self.npm_env))
            .field("pip_env", &keys(&self.pip_env))
            .field("uv_env", &self.uv_env)
            .field("npm_global_prefix", &self.npm_global_prefix)
            .field("unfound", &self.unfound)
            .finish()
    }
}

impl Places {
    /// The tools' own defaults under `home` (relative to the root).
    pub(super) fn defaults(home: Option<&str>) -> Self {
        let under = |rest: &str| home.map(|home| format!("{home}/{rest}"));
        Self {
            mise: under(".local/share/mise"),
            cargo: under(".cargo"),
            pipx: under(".local/share/pipx"),
            npmrc: under(".npmrc"),
            pip: [under(".config/pip/pip.conf"), under(".pip/pip.conf")]
                .into_iter()
                .flatten()
                .collect(),
            uv: under(".config/uv/uv.toml").into_iter().collect(),
            home: home.map(str::to_string),
            npm_env: Vec::new(),
            pip_env: Vec::new(),
            uv_env: Vec::new(),
            npm_global_prefix: None,
            unfound: Vec::new(),
        }
    }

    /// The defaults, with what the environment changes. A variable that
    /// names a tool's directory, a configuration file or an XDG directory
    /// by a path that is not absolute without `..` is kept in `unfound`,
    /// and nothing is read in its place, and so is an empty entry of
    /// `XDG_CONFIG_DIRS`. An empty `CARGO_HOME` or `XDG_CONFIG_HOME` is
    /// unset, as cargo and pip take it; an empty `PIPX_HOME`
    /// or `MISE_DATA_DIR` is said as not absolute, since their manuals on
    /// this machine do not say how they take it.
    pub(super) fn from_env(home: Option<&str>) -> Self {
        let variables: Vec<(String, String)> = env::vars_os()
            .filter_map(|(name, value)| Some((name.into_string().ok()?, value.into_string().ok()?)))
            .collect();
        Self::from_variables(home, &variables)
    }

    fn from_variables(home: Option<&str>, variables: &[(String, String)]) -> Self {
        let mut places = Self::defaults(home);
        for (name, value) in variables {
            let (name, place) = match name.as_str() {
                "MISE_DATA_DIR" => ("MISE_DATA_DIR", &mut places.mise),
                "CARGO_HOME" if !value.is_empty() => ("CARGO_HOME", &mut places.cargo),
                "PIPX_HOME" => ("PIPX_HOME", &mut places.pipx),
                _ => continue,
            };
            // The tool would resolve a relative path against where it ran,
            // which is not known: nothing is read there, and that is said.
            *place = from_root(value);
            if place.is_none() {
                places.unfound.push((name, value.clone()));
            }
        }
        places.npm_env = npm_variables(variables);
        places.npm_global_prefix = variables
            .iter()
            .find(|(name, value)| name == "PREFIX" && !value.is_empty())
            .map(|(_, value)| value.clone());
        places.pip_env = pip_variables(variables);
        // npm takes the last of several spellings of one variable.
        if let Some((_, file)) = places
            .npm_env
            .iter()
            .rev()
            .find(|(key, _)| key == "userconfig")
        {
            places.npmrc = from_root(file);
            if places.npmrc.is_none() {
                places.unfound.push(("npm_config_userconfig", file.clone()));
            }
        }
        places.uv_env = variables
            .iter()
            .filter(|(name, value)| {
                UV_INDEX_VARIABLES.contains(&name.as_str()) && !value.is_empty()
            })
            .map(|(name, _)| name.clone())
            .collect();
        // pip and uv read their files under the XDG directories too; the
        // defaults stay, as pip also reads its older places.
        let variable = |wanted: &str| {
            variables
                .iter()
                .find(|(name, _)| name == wanted)
                .map(|(_, value)| value.as_str())
        };
        let mut config_dirs: Vec<(&'static str, &str)> = variable("XDG_CONFIG_HOME")
            .map(|home| ("XDG_CONFIG_HOME", home))
            .into_iter()
            .collect();
        config_dirs.extend(
            variable("XDG_CONFIG_DIRS")
                .filter(|dirs| !dirs.is_empty())
                .into_iter()
                .flat_map(|dirs| dirs.split(':'))
                .map(|directory| ("XDG_CONFIG_DIRS", directory)),
        );
        // A file already read (a default, or a global one) is read once.
        let add = |files: &mut Vec<String>, globals: &[&str], file: Option<String>| {
            if let Some(file) = file
                && !files.contains(&file)
                && !globals.contains(&file.as_str())
            {
                files.push(file);
            }
        };
        // An empty XDG_CONFIG_HOME is unset. A relative directory, or an
        // empty entry of XDG_CONFIG_DIRS, which pip and uv would resolve
        // against where they ran, is said.
        for (name, directory) in config_dirs {
            if name == "XDG_CONFIG_HOME" && directory.is_empty() {
                continue;
            }
            if from_root(directory).is_none() {
                places.unfound.push((name, directory.to_string()));
                continue;
            }
            let pip = from_root(&format!("{directory}/pip/pip.conf"));
            add(&mut places.pip, GLOBAL_PIP, pip);
            let uv = from_root(&format!("{directory}/uv/uv.toml"));
            add(&mut places.uv, GLOBAL_UV, uv);
        }
        for (name, files) in [
            ("PIP_CONFIG_FILE", &mut places.pip),
            ("UV_CONFIG_FILE", &mut places.uv),
        ] {
            if let Some(file) = variable(name) {
                match from_root(file) {
                    Some(path) => files.push(path),
                    None => places.unfound.push((name, file.to_string())),
                }
            }
        }
        places
    }
}

/// The npm settings among `variables`: npm reads `npm_config_<key>` in any
/// case, with `_` for `-` in the key.
fn npm_variables(variables: &[(String, String)]) -> Vec<(String, String)> {
    variables
        .iter()
        .filter_map(|(name, value)| {
            let lowered = name.to_ascii_lowercase();
            let key = lowered.strip_prefix("npm_config_")?.replace('_', "-");
            // npm skips a variable set to nothing. Only the keys read here
            // are kept: the others include registry tokens.
            let used = NPM_KEYS.contains(&key.as_str()) || key.ends_with(":registry");
            (used && !value.is_empty()).then(|| (key, value.clone()))
        })
        .collect()
}

/// pip's index settings among `variables`: pip reads `PIP_<KEY>`.
fn pip_variables(variables: &[(String, String)]) -> Vec<(String, String)> {
    variables
        .iter()
        .filter_map(|(name, value)| {
            let key = name
                .strip_prefix("PIP_")?
                .to_ascii_lowercase()
                .replace('_', "-");
            PIP_INDEX_KEYS
                .contains(&key.as_str())
                .then(|| (key, value.clone()))
        })
        .collect()
}

/// `path`, absolute and without `..`, relative to `/`.
pub(super) fn from_root(path: &str) -> Option<String> {
    let absolute = Path::new(path).is_absolute()
        && !Path::new(path)
            .components()
            .any(|component| component == Component::ParentDir);
    let relative = path.trim_matches('/');
    (absolute && !relative.is_empty()).then(|| relative.to_string())
}

/// What npm's configuration says that the inventory needs, for every node
/// installed: npm's files differ from one node to the next.
#[derive(Debug, Default)]
pub(super) struct NpmConfig {
    /// Where global packages go, relative to the root, where a node's
    /// configuration sets it.
    pub(super) prefixes: Vec<String>,
    /// Every node's npm is set not to run install scripts.
    pub(super) ignore_scripts: bool,
    /// Where each node's npm takes packages from.
    nodes: Vec<NpmRegistries>,
    /// The files that are there and could not be read (not a regular file,
    /// closed, or too large), or cannot be found, as said to the user: what
    /// they set is not known, so no package counts as public.
    pub(super) unreadable: Vec<String>,
    /// A shell start-up or environment file may set npm's registry or
    /// configuration files where npm runs, and no package counts as
    /// public.
    pub(super) set_at_start_up: bool,
}

/// Whether a node's npm counts for the install-scripts note: one that is
/// not installed runs none.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Scripts {
    Counted,
    Uncounted,
}

/// The registries one node's npm is set to use.
#[derive(Debug, Default)]
struct NpmRegistries {
    /// Whether the registry packages come from is a public one, where one
    /// is set. Only that is kept: an address may hold a password.
    registry: Option<bool>,
    /// The same for each scope that has its own (`@scope:registry`).
    scoped: Vec<(String, bool)>,
}

impl NpmConfig {
    /// Reads npm's configuration as the npm of each node in `nodes` (its
    /// install directory relative to the root, `usr` for the system's)
    /// reads it, in npm's order: its built-in file, the global file, the
    /// user's, then the environment, each winning over the one before.
    /// The global file is `globalconfig` where one is set, or else
    /// `etc/npmrc` under the prefix in effect: `prefix`, else `PREFIX`,
    /// else the node's own directory (`@npmcli/config` 10.12.0,
    /// lib/index.js, `loadGlobalPrefix` and `globalconfig`). npm's
    /// `DESTDIR`, which moves the default prefix, is not read.
    pub(super) fn read(root: &Path, places: &Places, nodes: &[String]) -> Self {
        let mut config = Self {
            ignore_scripts: true,
            ..Self::default()
        };
        for file in unfound(places, "npm_config_userconfig") {
            config.not_read(file);
        }
        let home = places.home.as_deref();
        let prefix_env = places.npm_global_prefix.as_deref().and_then(|value| {
            let path = from_root(value);
            if path.is_none() {
                config.not_read(format!("the prefix PREFIX names ({value})"));
            }
            path
        });
        let user = config.file(root, places.npmrc.as_deref());
        // The system's npm runs install scripts only where it is installed.
        let system_npm = fs::symlink_metadata(root.join("usr/bin/npm")).is_ok();
        for node in nodes {
            let builtin = config.file(root, Some(&format!("{node}/lib/node_modules/npm/npmrc")));
            let before: Vec<&(String, String)> =
                builtin.iter().chain(&user).chain(&places.npm_env).collect();
            let last = |key: &str| {
                before
                    .iter()
                    .rev()
                    .find(|(known, _)| known == key)
                    .map(|(_, value)| value.clone())
            };
            let prefix = match last("prefix") {
                Some(value) => config.path("prefix", &value, home),
                None => Some(prefix_env.clone().unwrap_or_else(|| node.clone())),
            };
            let global = match last("globalconfig") {
                Some(value) => config.path("globalconfig", &value, home),
                None => prefix.map(|prefix| format!("{prefix}/etc/npmrc")),
            };
            let system = node == "usr";
            // `/etc/npmrc` goes before the global file, so a public
            // registry there cannot override a private one in it.
            let mut globals = Vec::new();
            if system && global.as_deref() != Some(ARCH_NPMRC) {
                globals.extend(config.file(root, Some(ARCH_NPMRC)));
            }
            globals.extend(config.file(root, global.as_deref()));
            let ordered = builtin
                .iter()
                .chain(&globals)
                .chain(&user)
                .chain(&places.npm_env);
            let scripts = if system && !system_npm {
                Scripts::Uncounted
            } else {
                Scripts::Counted
            };
            config.apply(ordered, home, prefix_env.as_ref(), scripts);
            if system {
                // Where Arch's npm is built to read `/etc/npmrc` from could
                // not be cited (its PKGBUILD or built-in `npmrc`), so its
                // place among the files above is not known: on its own, it
                // too must take packages from the public registry, so a
                // private registry there is not overridden either.
                let arch = config.file(root, Some(ARCH_NPMRC));
                config.apply(arch.iter(), home, None, Scripts::Uncounted);
            }
        }
        config
    }

    /// Says something npm reads that could not be read, once.
    fn not_read(&mut self, what: String) {
        if !self.unreadable.contains(&what) {
            self.unreadable.push(what);
        }
    }

    /// The path an npm setting `key` gives, or `None` and said where npm
    /// would resolve it against what is not known here.
    fn path(&mut self, key: &str, value: &str, home: Option<&str>) -> Option<String> {
        let path = npm_prefix(value, home);
        if path.is_none() {
            self.not_read(format!("the path npm's {key} names ({value})"));
        }
        path
    }

    /// The settings of an npm configuration file, or none where there is
    /// none; one that cannot be read is said.
    fn file(&mut self, root: &Path, file: Option<&str>) -> Vec<(String, String)> {
        let Some(file) = file else {
            return Vec::new();
        };
        match read_config(root, file) {
            ConfigFile::Absent => Vec::new(),
            ConfigFile::Unreadable => {
                self.not_read(format!("/{file}"));
                Vec::new()
            }
            ConfigFile::Text(text) => npm_settings(&text).unwrap_or_else(|| {
                self.not_read(format!("/{file}"));
                Vec::new()
            }),
        }
    }

    /// Takes one node's settings, the last of each key winning. Its
    /// packages go under `default_prefix` where no `prefix` is set.
    fn apply<'a>(
        &mut self,
        settings: impl Iterator<Item = &'a (String, String)>,
        home: Option<&str>,
        default_prefix: Option<&String>,
        scripts: Scripts,
    ) {
        let mut registries = NpmRegistries::default();
        let mut prefix = None;
        let mut ignore_scripts = false;
        for (key, value) in settings {
            match key.as_str() {
                "prefix" => prefix = Some(value.clone()),
                "ignore-scripts" => ignore_scripts = value == "true",
                "registry" => registries.registry = Some(is_on(value, NPM_REGISTRIES)),
                _ => {
                    if let Some(scope) = key
                        .strip_suffix(":registry")
                        .filter(|scope| scope.starts_with('@'))
                    {
                        registries.scoped.retain(|(known, _)| known != scope);
                        registries
                            .scoped
                            .push((scope.to_string(), is_on(value, NPM_REGISTRIES)));
                    }
                }
            }
        }
        if scripts == Scripts::Counted {
            self.ignore_scripts &= ignore_scripts;
        }
        let prefix = match prefix {
            Some(value) => self.path("prefix", &value, home),
            None => default_prefix.cloned(),
        };
        if let Some(prefix) = prefix.filter(|prefix| !self.prefixes.contains(prefix)) {
            self.prefixes.push(prefix);
        }
        self.nodes.push(registries);
    }

    /// Whether the npm package `name`, installed from the address
    /// `resolved` where one is recorded, came from npm's public registry,
    /// whichever node's npm installed it.
    pub(super) fn is_public(&self, name: &str, resolved: Option<&str>) -> bool {
        // A file it could not read may set a private registry for any
        // scope, and npm follows a link to it.
        if !self.unreadable.is_empty() || self.set_at_start_up {
            return false;
        }
        if let Some(resolved) = resolved {
            return is_on(resolved, NPM_REGISTRIES);
        }
        let scope = name
            .split_once('/')
            .map(|(scope, _)| scope)
            .filter(|scope| scope.starts_with('@'));
        self.nodes.iter().all(|node| {
            scope
                .and_then(|scope| node.scoped.iter().find(|(known, _)| known == scope))
                .map(|(_, public)| *public)
                .or(node.registry)
                .unwrap_or(true)
        })
    }
}

/// What pip's or uv's configuration (files and environment) says of where
/// packages come from.
#[derive(Debug)]
pub(super) struct IndexConfig {
    /// It brings packages from somewhere other than the Python Package
    /// Index, or a file of it could not be read: then what the tool
    /// installed may be of a private index, and none of it is looked up.
    pub(super) other_index: bool,
    /// The files that are there and could not be read, or cannot be
    /// found, as said to the user.
    pub(super) unreadable: Vec<String>,
}

impl IndexConfig {
    pub(super) fn pip(root: &Path, places: &Places) -> Self {
        let files = GLOBAL_PIP
            .iter()
            .map(|file| (*file).to_string())
            .chain(places.pip.iter().cloned());
        let mut other_index = places
            .pip_env
            .iter()
            .any(|(_, value)| is_other_pip_index(value));
        let mut unreadable = unfound(places, "PIP_CONFIG_FILE");
        unreadable.extend(unfound_under(places, "pip.conf"));
        for file in files {
            match read_config(root, &file) {
                ConfigFile::Absent => {}
                ConfigFile::Unreadable => unreadable.push(format!("/{file}")),
                ConfigFile::Text(text) => other_index |= pip_file_other_index(&text),
            }
        }
        Self {
            other_index: other_index || !unreadable.is_empty(),
            unreadable,
        }
    }

    /// uv's configuration. Any index setting counts, the Python Package
    /// Index named as one included: telling them apart in `[[index]]`
    /// tables is not worth the risk of a miss. A file uv would reject
    /// counts as unreadable.
    pub(super) fn uv(root: &Path, places: &Places) -> Self {
        let files = GLOBAL_UV
            .iter()
            .map(|file| (*file).to_string())
            .chain(places.uv.iter().cloned());
        let mut other_index = !places.uv_env.is_empty();
        let mut unreadable = unfound(places, "UV_CONFIG_FILE");
        unreadable.extend(unfound_under(places, "uv.toml"));
        for file in files {
            let entries = match read_config(root, &file) {
                ConfigFile::Absent => continue,
                ConfigFile::Unreadable => Err(()),
                ConfigFile::Text(text) => tomlish::entries(&text).map_err(drop),
            };
            match entries {
                Ok(entries) => {
                    other_index |= entries.iter().any(|entry| {
                        is_uv_index(&entry.full_path())
                            || inline_keys(&entry.value).any(|key| UV_INDEX_KEYS.contains(&key))
                    });
                }
                Err(()) => unreadable.push(format!("/{file}")),
            }
        }
        Self {
            other_index: other_index || !unreadable.is_empty(),
            unreadable,
        }
    }

    /// cargo's configuration under its home (`config.toml`, and `config`,
    /// which cargo still reads), and the `.cargo` directories cargo reads
    /// from every ancestor of where it runs that are known to be one: the
    /// home's and the root's. Other ancestors of where `cargo install`
    /// ran are not known and not read. A crate from a source that replaces
    /// crates.io (`[source.crates-io] replace-with`) is recorded as from
    /// crates.io, so any `[source]` table counts, and so does `include`,
    /// whose files are not read. cargo reads neither from the environment
    /// (the cargo book, config reference: "Environment: not supported").
    pub(super) fn cargo(root: &Path, places: &Places) -> Self {
        let mut directories: Vec<String> = places.cargo.iter().cloned().collect();
        let others = places.home.iter().map(|home| format!("{home}/.cargo"));
        for directory in others.chain([".cargo".to_string()]) {
            if !directories.contains(&directory) {
                directories.push(directory);
            }
        }
        let files = directories.iter().flat_map(|directory| {
            [
                format!("{directory}/config.toml"),
                format!("{directory}/config"),
            ]
        });
        let mut other_index = false;
        let mut unreadable = Vec::new();
        for file in files {
            let entries = match read_config(root, &file) {
                ConfigFile::Absent => continue,
                ConfigFile::Unreadable => Err(()),
                ConfigFile::Text(text) => tomlish::entries(&text).map_err(drop),
            };
            match entries {
                Ok(entries) => {
                    other_index |= entries.iter().any(|entry| {
                        matches!(entry.full_path().first(), Some(&("source" | "include")))
                    });
                }
                Err(()) => unreadable.push(format!("/{file}")),
            }
        }
        Self {
            other_index: other_index || !unreadable.is_empty(),
            unreadable,
        }
    }
}

/// The configuration file the variable `name` names where it cannot be
/// found, as said to the user.
fn unfound(places: &Places, name: &str) -> Vec<String> {
    places
        .unfound
        .iter()
        .filter(|(variable, _)| *variable == name)
        .map(|(variable, value)| format!("the file {variable} names ({value})"))
        .collect()
}

/// The configuration file `file` under each XDG directory that cannot be
/// found, as said to the user.
fn unfound_under(places: &Places, file: &str) -> Vec<String> {
    places
        .unfound
        .iter()
        .filter(|(variable, _)| variable.starts_with("XDG_"))
        .map(|(variable, value)| {
            format!("the {file} under the directory {variable} names ({value})")
        })
        .collect()
}

/// Whether a `uv.toml` entry at `path` (table, then key) is an index
/// setting.
fn is_uv_index(path: &[&str]) -> bool {
    let (["pip", key, ..] | [key, ..]) = path else {
        return false;
    };
    UV_INDEX_KEYS.contains(key)
}

/// Whether uv's record of one tool (`uv-receipt.toml`) says it came from
/// somewhere other than the Python Package Index: an index among its
/// options, or a requirement (or constraint, or override) with anything
/// beyond a name, a version and extras (a git, url, path or index source).
/// Text it cannot read counts.
pub(super) fn uv_receipt_other_index(text: &str) -> bool {
    let Ok(entries) = tomlish::entries(text) else {
        return true;
    };
    entries.iter().any(|entry| {
        let path = entry.full_path();
        let mut keys = inline_keys(&entry.value);
        if path.iter().any(|part| UV_INDEX_KEYS.contains(part))
            || keys.any(|key| UV_INDEX_KEYS.contains(&key))
        {
            return true;
        }
        // Every list of requirements under `[tool]`; the entry points
        // name the programs installed, not where they came from.
        matches!(path.as_slice(), ["tool", list] if *list != "entrypoints")
            && entry.value.starts_with('[')
            && inline_keys(&entry.value).any(|key| !UV_REQUIREMENT_KEYS.contains(&key))
    })
}

/// The keys of the inline tables in a TOML value, unquoted. Splitting at
/// every delimiter finds every key; a delimiter inside a string can only
/// add a part that is not one. Those that cannot be a key are dropped (the
/// `<` of `">=1,<2"`); one that can is kept, which leaves more out, never
/// less.
fn inline_keys(value: &str) -> impl Iterator<Item = &str> {
    value
        .split([',', '{', '}', '[', ']'])
        .filter_map(|part| part.split_once('='))
        .map(|(key, _)| key.trim().trim_matches(['"', '\'']))
        .filter(|key| {
            !key.is_empty()
                && key
                    .chars()
                    .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.'))
        })
}

/// Whether the text of a pip configuration file sets an index other than
/// the Python Package Index. configparser joins to a value each line
/// indented deeper than its key, and keeps quotes and `#` in it: values
/// are taken raw here, not through `setting`, which reads npm's way.
pub(super) fn pip_file_other_index(text: &str) -> bool {
    // The setting being read: its key's indent, whether it is an index
    // key, and its value with the lines joined to it.
    let mut current: Option<(usize, bool, String)> = None;
    let mut other = false;
    for line in text.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with(['#', ';']) {
            continue;
        }
        let indent = line.len() - line.trim_start().len();
        if let Some((key_indent, _, value)) = &mut current
            && indent > *key_indent
        {
            value.push(' ');
            value.push_str(trimmed);
            continue;
        }
        other |= current
            .take()
            .is_some_and(|(_, index, value)| index && is_other_pip_index(&value));
        current = if trimmed.starts_with('[') {
            None
        } else {
            trimmed.split_once(['=', ':']).map(|(key, value)| {
                // pip takes an option's name with or without its `--`.
                let key = key.trim().to_ascii_lowercase().replace('_', "-");
                let key = key.strip_prefix("--").unwrap_or(&key);
                let index = PIP_INDEX_KEYS.contains(&key);
                (indent, index, value.trim().to_string())
            })
        };
    }
    other || current.is_some_and(|(_, index, value)| index && is_other_pip_index(&value))
}

/// Whether the value of a pip index setting names anything but the Python
/// Package Index. pip splits it on whitespace. An empty one counts: what
/// pip makes of it is not worth a guess.
fn is_other_pip_index(value: &str) -> bool {
    value.is_empty() || !value.split_whitespace().all(|url| is_on(url, PYPI_HOSTS))
}

/// Whether pipx's record of an environment (`pipx_metadata.json`) says
/// that a package in it was installed with another index. Text it cannot
/// read counts.
pub(super) fn pipx_metadata_other_index(text: &str) -> bool {
    let Ok(json) = Json::parse(text) else {
        return true;
    };
    let injected = json
        .get("injected_packages")
        .and_then(Json::as_object)
        .unwrap_or_default()
        .iter()
        .map(|(_, package)| package);
    json.get("main_package")
        .into_iter()
        .chain(injected)
        .filter_map(|package| package.get("pip_args")?.as_array())
        .any(|arguments| has_index_argument(arguments.iter().filter_map(Json::as_str)))
}

/// What reading one configuration file gave.
pub(super) enum ConfigFile {
    Absent,
    /// There, and a broken link, not a regular file, closed, or larger
    /// than `MAX_CONFIG_BYTES`.
    Unreadable,
    Text(String),
}

/// Reads a configuration file, following a link to it: dotfile managers
/// link these files, and the tool follows the link too. The target must
/// still be a regular file within the size limit.
///
/// A link's target resolves against the real `/`, not against `root`.
/// That is right because the sweep's root is `/`; the tests make their
/// links point inside their own root.
pub(super) fn read_config(root: &Path, file: &str) -> ConfigFile {
    let path = root.join(file);
    if let Err(error) = fs::symlink_metadata(&path) {
        return match error.kind() {
            io::ErrorKind::NotFound => ConfigFile::Absent,
            _ => ConfigFile::Unreadable,
        };
    }
    fs::canonicalize(&path)
        .ok()
        .and_then(|target| read_small_file(&target, MAX_CONFIG_BYTES))
        .map_or(ConfigFile::Unreadable, ConfigFile::Text)
}

/// Whether pip arguments, as pipx records them for an environment, bring
/// packages from somewhere other than the Python Package Index.
fn has_index_argument<'a>(arguments: impl IntoIterator<Item = &'a str>) -> bool {
    arguments.into_iter().any(|argument| {
        // Any mention of an index fails closed, whatever the spelling.
        if argument.contains("index") || argument.contains("find-link") {
            return true;
        }
        let name = argument.split_once('=').map_or(argument, |(name, _)| name);
        match name.strip_prefix("--") {
            // optparse takes any unambiguous start of a long option. One
            // that is ambiguous fails pip, so counting it costs nothing.
            Some(long) => {
                !long.is_empty()
                    && PIP_INDEX_OPTIONS
                        .iter()
                        .any(|option| option.starts_with(long))
            }
            // Short options cluster (`-Ui`) and take their value attached.
            None => argument
                .strip_prefix('-')
                .is_some_and(|short| short.contains(PIP_INDEX_SHORT_OPTIONS)),
        }
    })
}

/// The key and value of one line of an npm configuration file: `key =
/// value`, `;` and `#` starting a comment, which also ends an unquoted
/// value; a quoted value is taken whole.
fn setting(line: &str) -> Option<(&str, &str)> {
    let line = line.trim();
    if line.starts_with([';', '#', '[']) {
        return None;
    }
    let at = line.find('=')?;
    Some((unquoted(&line[..at]), unquoted(&line[at + 1..])))
}

/// A key or value of an npm configuration file as npm's `ini` reads it: a
/// quoted one taken whole, else up to a `;` or `#`.
fn unquoted(text: &str) -> &str {
    let text = text.trim();
    match text.chars().next() {
        Some(quote @ ('"' | '\'')) => text[1..].split(quote).next().unwrap_or_default(),
        _ => text.split([';', '#']).next().unwrap_or_default().trim(),
    }
}

/// The top-level settings of an npm configuration file that the inventory
/// reads (`NPM_KEYS` and each scope's registry), or `None` where npm would
/// read a key that is not known here: npm expands `${...}` in a key from
/// its own environment, decodes a double-quoted key as JSON (an escape in
/// it may spell any key), and reads a `key[]` as a list. A key under a
/// `[section]` is not one of npm's settings, so reading stops at the
/// first. Lines and sections are split as npm's `ini` package splits them
/// (`decode`): at any run of CR and LF, and a section is a line that starts
/// with `[` in its first column and ends with `]` and blanks, with no `]`
/// in between.
fn npm_settings(text: &str) -> Option<Vec<(String, String)>> {
    let mut settings = Vec::new();
    for line in text.split(['\r', '\n']) {
        let end = line.trim_end();
        let inner = end.strip_prefix('[').and_then(|end| end.strip_suffix(']'));
        if inner.is_some_and(|inner| !inner.contains(']')) {
            break;
        }
        let raw_key = line.split_once('=').map_or(line, |(key, _)| key).trim();
        if raw_key.starts_with('"') && raw_key.contains('\\') {
            return None;
        }
        let Some((key, value)) = setting(line) else {
            continue;
        };
        let list = key.strip_suffix("[]");
        let name = list.unwrap_or(key);
        let used = NPM_KEYS.contains(&name) || name.ends_with(":registry");
        if name.contains("${") || (used && list.is_some()) {
            return None;
        }
        // The other keys include registry tokens (`//host/:_authToken`).
        if used {
            settings.push((name.to_string(), value.to_string()));
        }
    }
    Some(settings)
}

/// A path npm's configuration gives (`prefix`, `globalconfig`), relative
/// to the root: an absolute path, or one under the home written as `~/` or
/// `${HOME}/`, the two forms npm expands to it. npm expands other `${...}`
/// from its own environment and resolves a relative path against its
/// working directory, neither of which is known here: those are `None`.
fn npm_prefix(value: &str, home: Option<&str>) -> Option<String> {
    let in_home = ["~/", "${HOME}/"]
        .iter()
        .find_map(|start| value.strip_prefix(start));
    let path = match (in_home, home) {
        (Some(rest), Some(home)) => format!("/{home}/{rest}"),
        (Some(_), None) => return None,
        (None, _) => value.to_string(),
    };
    if path.contains("${") {
        return None;
    }
    from_root(&path)
}

/// Whether `url` is an HTTPS address on one of `hosts`.
fn is_on(url: &str, hosts: &[&str]) -> bool {
    let Some(rest) = url.strip_prefix("https://") else {
        return false;
    };
    let authority = rest.split(['/', '?', '#']).next().unwrap_or_default();
    let host_and_port = authority.rsplit('@').next().unwrap_or_default();
    let host = host_and_port.split(':').next().unwrap_or_default();
    hosts.iter().any(|known| host.eq_ignore_ascii_case(known))
}

#[cfg(test)]
mod tests {
    use super::{
        IndexConfig, NpmConfig, Places, Scripts, from_root, has_index_argument, is_on, is_uv_index,
        npm_prefix, npm_settings, npm_variables, pip_file_other_index, pip_variables,
        pipx_metadata_other_index, setting, uv_receipt_other_index,
    };
    use crate::test_support::TempDir;

    #[test]
    fn npmrc_lines_are_read_as_npm_reads_them() {
        assert_eq!(
            setting(" ignore-scripts = \"true\" "),
            Some(("ignore-scripts", "true"))
        );
        assert_eq!(
            setting("ignore-scripts=true ; why"),
            Some(("ignore-scripts", "true"))
        );
        assert_eq!(setting("prefix = '/a;b'"), Some(("prefix", "/a;b")));
        assert_eq!(setting("; ignore-scripts=true"), None);
        assert_eq!(setting("# ignore-scripts=true"), None);
        assert_eq!(setting("[section]"), None);
    }

    #[test]
    fn prefixes_and_places_take_only_what_npm_would() {
        assert_eq!(
            npm_prefix("~/.npm-global", Some("home/u")).as_deref(),
            Some("home/u/.npm-global")
        );
        assert_eq!(
            npm_prefix("${HOME}/g", Some("home/u")).as_deref(),
            Some("home/u/g")
        );
        assert_eq!(npm_prefix("/opt/npm/", None).as_deref(), Some("opt/npm"));
        assert_eq!(npm_prefix("relative", Some("home/u")), None);
        assert_eq!(npm_prefix("$HOME/g", Some("home/u")), None);
        assert_eq!(npm_prefix("~/g", None), None);
        assert_eq!(npm_prefix("/opt/${USER}/g", Some("home/u")), None);
        assert_eq!(npm_prefix("/a/../etc", Some("home/u")), None);
        assert_eq!(from_root("/"), None);
        assert_eq!(
            Places::defaults(Some("home/u")).mise.as_deref(),
            Some("home/u/.local/share/mise")
        );
        assert_eq!(Places::defaults(None).cargo, None);
    }

    #[test]
    fn environment_settings_are_taken_in_npm_and_pip_spelling() {
        let variables = [
            ("NPM_CONFIG_IGNORE_SCRIPTS", "true"),
            ("npm_config_prefix", "/opt/g"),
            ("PIP_INDEX_URL", "https://pypi.example/simple"),
            ("PIP_TIMEOUT", "5"),
            ("HOME", "/home/u"),
        ]
        .map(|(name, value)| (name.to_string(), value.to_string()));
        let mut with_empty = variables.to_vec();
        with_empty.push(("npm_config_registry".to_string(), String::new()));
        // Settings not read here, tokens among them, are not kept.
        with_empty.push(("npm_config__auth".to_string(), "secret".to_string()));
        with_empty.push((
            "npm_config_//r.example/:_authToken".to_string(),
            "secret".to_string(),
        ));
        assert_eq!(
            npm_variables(&with_empty),
            [
                ("ignore-scripts".to_string(), "true".to_string()),
                ("prefix".to_string(), "/opt/g".to_string()),
            ]
        );
        assert_eq!(
            pip_variables(&variables),
            [(
                "index-url".to_string(),
                "https://pypi.example/simple".to_string()
            )]
        );
        let requirement = [("PIP_REQUIREMENT".to_string(), "/srv/r.txt".to_string())];
        assert_eq!(pip_variables(&requirement).len(), 1);
    }

    #[test]
    fn npm_files_are_read_only_to_their_first_section_and_fail_closed() {
        assert_eq!(setting("\"registry\" = x"), Some(("registry", "x")));
        assert_eq!(
            npm_settings("registry=a\n[corp]\nregistry=b\n"),
            Some(vec![("registry".to_string(), "a".to_string())])
        );
        assert_eq!(
            npm_settings("${SCOPE}:registry=https://npm.corp.example/\n"),
            None
        );
        let registry = Some(vec![("registry".to_string(), "x".to_string())]);
        // Tokens and other keys are not kept.
        assert_eq!(
            npm_settings("//r.example/:_authToken=s\nregistry=x\n"),
            registry
        );
        // An indented `[work]` is no section; a CR alone ends a line.
        assert_eq!(npm_settings("  [work]\nregistry=x\n"), registry);
        assert_eq!(
            npm_settings("a=b\rregistry=x\r[work]\rregistry=y"),
            registry
        );
        assert_eq!(npm_settings("[a]b]\nregistry=x\n"), registry);
        // A list or an escaped key npm would read differently.
        assert_eq!(npm_settings("registry[]=x\n"), None);
        assert_eq!(npm_settings("\"regi\\u0073try\"=x\n"), None);
        assert_eq!(npm_settings("ca[]=x\nregistry=x\n"), registry);
    }

    #[test]
    fn the_environment_is_kept_without_its_values_in_debug_output() {
        let variables = [
            ("PIP_INDEX_URL", "https://user:pw@pypi.corp.example/simple"),
            ("npm_config_registry", "https://user:pw@npm.corp.example/"),
            ("npm_config_userconfig", "/a/npmrc"),
            ("NPM_CONFIG_USERCONFIG", "/b/npmrc"),
            ("XDG_CONFIG_HOME", "/home/u/.config"),
            ("XDG_CONFIG_DIRS", "/etc/xdg"),
            ("CARGO_HOME", "cargo"),
        ]
        .map(|(name, value)| (name.to_string(), value.to_string()));

        let places = Places::from_variables(Some("home/u"), &variables);

        assert!(!format!("{places:?}").contains("pw@"));
        // npm takes the last spelling of a variable.
        assert_eq!(places.npmrc.as_deref(), Some("b/npmrc"));
        // XDG paths that repeat a default or global one are read once.
        assert_eq!(
            places.pip,
            ["home/u/.config/pip/pip.conf", "home/u/.pip/pip.conf"]
        );
        assert_eq!(places.uv, ["home/u/.config/uv/uv.toml"]);
        // A relative tool home is not replaced by the default.
        assert_eq!(places.cargo, None);
        assert_eq!(places.unfound, [("CARGO_HOME", "cargo".to_string())]);

        // Set to nothing, XDG_CONFIG_DIRS is unset.
        let empty = [("XDG_CONFIG_DIRS".to_string(), String::new())];
        assert_eq!(Places::from_variables(Some("home/u"), &empty).unfound, []);
    }

    #[test]
    fn an_empty_place_is_unset_and_a_relative_xdg_directory_is_said() {
        let variables = [
            ("CARGO_HOME", ""),
            ("XDG_CONFIG_HOME", ""),
            ("XDG_CONFIG_DIRS", "conf::/etc/corp"),
        ]
        .map(|(name, value)| (name.to_string(), value.to_string()));

        let places = Places::from_variables(Some("home/u"), &variables);

        assert_eq!(places.cargo.as_deref(), Some("home/u/.cargo"));
        assert_eq!(
            places.pip,
            [
                "home/u/.config/pip/pip.conf",
                "home/u/.pip/pip.conf",
                "etc/corp/pip/pip.conf"
            ]
        );
        assert_eq!(
            places.unfound,
            [
                ("XDG_CONFIG_DIRS", "conf".to_string()),
                ("XDG_CONFIG_DIRS", String::new())
            ]
        );
        let root = TempDir::new("xdg-relative");
        let pip = IndexConfig::pip(root.path(), &places);
        assert!(pip.other_index);
        assert_eq!(
            pip.unreadable,
            [
                "the pip.conf under the directory XDG_CONFIG_DIRS names (conf)",
                "the pip.conf under the directory XDG_CONFIG_DIRS names ()"
            ]
        );
    }

    #[test]
    fn only_the_public_registries_count_as_public() {
        assert!(is_on(
            "https://registry.npmjs.org/a/-/a-1.tgz",
            &["registry.npmjs.org"]
        ));
        assert!(is_on(
            "https://user:pw@Registry.NPMJS.org:443/a",
            &["registry.npmjs.org"]
        ));
        assert!(!is_on(
            "http://registry.npmjs.org/a",
            &["registry.npmjs.org"]
        ));
        assert!(!is_on(
            "https://registry.npmjs.org.evil.example/a",
            &["registry.npmjs.org"]
        ));
        assert!(!is_on(
            "git+ssh://git@github.com/x/y.git",
            &["registry.npmjs.org"]
        ));

        let with = |settings: &[(&str, &str)]| {
            let settings: Vec<(String, String)> = settings
                .iter()
                .map(|(key, value)| ((*key).to_string(), (*value).to_string()))
                .collect();
            let mut config = NpmConfig::default();
            config.apply(settings.iter(), None, None, Scripts::Counted);
            config
        };
        let config = with(&[]);
        assert!(config.is_public("a", None));
        assert!(!config.is_public("a", Some("file:../a")));
        let config = with(&[("@corp:registry", "https://npm.corp.example/")]);
        assert!(!config.is_public("@corp/a", None));
        assert!(config.is_public("@other/a", None));
        let config = with(&[("registry", "https://mirror.example/")]);
        assert!(!config.is_public("a", None));
        assert!(config.is_public("a", Some("https://registry.npmjs.org/a/-/a-1.tgz")));
        // Each node's npm decides for itself; one that is set elsewhere
        // is enough to leave a package out.
        let mut config = with(&[]);
        config.apply(
            [(
                "registry".to_string(),
                "https://mirror.example/".to_string(),
            )]
            .iter(),
            None,
            None,
            Scripts::Counted,
        );
        assert!(!config.is_public("a", None));

        assert!(has_index_argument(["--index-url", "https://x"]));
        assert!(has_index_argument(["--extra-index-url=https://x"]));
        assert!(has_index_argument(["-ihttps://x"]));
        assert!(!has_index_argument(["--no-cache-dir", "-U"]));
        assert!(has_index_argument(["--index-urlx"]));
        assert!(has_index_argument([
            "--trusted-host=x",
            "--find-links-somewhere"
        ]));
        for abbreviated in [
            "--extra-index=https://x",
            "--find",
            "-Ui",
            "-r",
            "--requirement=r.txt",
        ] {
            assert!(has_index_argument([abbreviated]), "{abbreviated}");
        }
        assert!(!has_index_argument(["-U", "--pre", "--"]));
    }

    #[test]
    fn pip_files_count_every_index_but_pypi() {
        for public in [
            "[global]\nindex-url = https://pypi.org/simple\ntimeout = 60\n",
            "[global]\nextra-index-url = https://pypi.org/simple https://pypi.python.org/simple\n",
            "[global]\n    # an indented comment\n",
            "[global]\n    timeout = 60\n    retries = 3\n",
            "[global]\nextra-index-url =\n    https://pypi.org/simple\n",
            "[global]\ntimeout =\n    index-url = https://pypi.corp.example\n",
        ] {
            assert!(!pip_file_other_index(public), "{public}");
        }
        for other in [
            "[global]\nextra-index-url = https://pypi.org/simple https://pypi.corp.example/simple\n",
            "[global]\nextra-index-url = https://pypi.org/simple\n    https://pypi.corp.example/simple\n",
            "[global]\nextra-index-url =\n    https://pypi.corp.example/simple\n",
            "[install]\nfind_links: /srv/wheels\n",
            "[global]\n  index-url =\n      https://pypi.corp.example/simple\n",
            "[global]\n--index-url = https://pypi.corp.example/simple\n",
            "[install]\nrequirement = /srv/requirements.txt\n",
            "[global]\nextra-index-url = https://pypi.org/simple#x https://pypi.corp.example/simple\n",
            "[global]\nindex-url = \"https://pypi.org/simple\" https://pypi.corp.example/simple\n",
        ] {
            assert!(pip_file_other_index(other), "{other}");
        }
    }

    #[test]
    fn a_pipx_record_says_an_index_or_counts_when_it_cannot_be_read() {
        let with = |arguments: &str| {
            format!(r#"{{"main_package":{{"pip_args":{arguments}}},"injected_packages":{{}}}}"#)
        };
        assert!(!pipx_metadata_other_index(&with("[]")));
        assert!(pipx_metadata_other_index(&with(
            r#"["-i","https://pypi.corp.example"]"#
        )));
        assert!(pipx_metadata_other_index("{not json"));
    }

    #[test]
    fn uv_index_settings_are_found_in_tables_and_inline() {
        assert!(is_uv_index(&["pip", "index-url"]));
        assert!(is_uv_index(&["index", "url"]));
        assert!(!is_uv_index(&["pip", "compile-bytecode"]));
        let places = Places::defaults(Some("home/u"));
        let root = TempDir::new("packages-uv-config");
        for (text, other) in [
            (
                "[pip]\nindex-url = \"https://pypi.corp.example/simple\"\n",
                true,
            ),
            (
                "pip = { extra-index-url = [\"https://pypi.corp.example/simple\"] }\n",
                true,
            ),
            ("[pip]\ncompile-bytecode = true\n", false),
        ] {
            let file = root.path().join("home/u/.config/uv/uv.toml");
            std::fs::create_dir_all(file.parent().unwrap()).unwrap();
            std::fs::write(&file, text).unwrap();
            assert_eq!(
                IndexConfig::uv(root.path(), &places).other_index,
                other,
                "{text}"
            );
        }
    }

    #[test]
    fn config_files_that_cannot_be_found_fail_closed() {
        let variables = [
            ("PIP_CONFIG_FILE", "pip.conf"),
            ("UV_CONFIG_FILE", "../uv.toml"),
            ("npm_config_userconfig", "npmrc"),
        ]
        .map(|(name, value)| (name.to_string(), value.to_string()));

        let places = Places::from_variables(Some("home/u"), &variables);
        let root = std::path::Path::new("/nonexistent");

        let npm = NpmConfig::read(root, &places, &["usr".to_string()]);
        assert_eq!(
            npm.unreadable,
            ["the file npm_config_userconfig names (npmrc)"]
        );
        assert!(!npm.is_public("x", Some("https://registry.npmjs.org/x/-/x-1.tgz")));
        let pip = IndexConfig::pip(root, &places);
        assert!(pip.other_index);
        assert_eq!(
            pip.unreadable,
            ["the file PIP_CONFIG_FILE names (pip.conf)"]
        );
        assert!(IndexConfig::uv(root, &places).other_index);
    }

    #[test]
    fn pip_and_uv_files_are_also_read_under_the_xdg_directories() {
        let variables = [
            ("XDG_CONFIG_HOME", "/home/u/conf"),
            ("XDG_CONFIG_DIRS", "/opt/xdg:relative"),
            ("PIP_CONFIG_FILE", "/srv/pip.conf"),
            ("UV_CONFIG_FILE", "/srv/uv.toml"),
            ("UV_INDEX_URL", "https://pypi.corp.example/simple"),
            ("UV_FIND_LINKS", ""),
        ]
        .map(|(name, value)| (name.to_string(), value.to_string()));

        let places = Places::from_variables(Some("home/u"), &variables);

        assert_eq!(
            places.pip,
            [
                "home/u/.config/pip/pip.conf",
                "home/u/.pip/pip.conf",
                "home/u/conf/pip/pip.conf",
                "opt/xdg/pip/pip.conf",
                "srv/pip.conf",
            ]
        );
        assert_eq!(
            places.uv,
            [
                "home/u/.config/uv/uv.toml",
                "home/u/conf/uv/uv.toml",
                "opt/xdg/uv/uv.toml",
                "srv/uv.toml",
            ]
        );
        assert_eq!(places.uv_env, ["UV_INDEX_URL"]);
    }

    #[test]
    fn a_uv_receipt_says_a_tool_from_elsewhere() {
        let public = "[tool]\nrequirements = [{ name = \"black\", specifier = \">=24,!=24.1\" }]\nentrypoints = [{ name = \"black\", install-path = \"/b\" }]\n";
        assert!(!uv_receipt_other_index(public));
        for elsewhere in [
            "[tool]\nrequirements = [{ name = \"inhouse\", git = \"https://git.example/x\" }]\n",
            "[tool]\nrequirements = [{ name = \"x\", index = \"https://pypi.corp.example\" }]\n",
            "[tool]\nrequirements = [{ name = \"x\" }]\n[tool.options]\nindex-url = \"https://a\"\n",
            "[tool]\nrequirements = [{ name = \"x\" }]\noptions = { index = [\"https://a\"] }\n",
            "[tool]\nrequirements = [{ name = \"x\" }]\nconstraints = [{ name = \"y\", url = \"https://a/y.whl\" }]\n",
            "[tool\n",
        ] {
            assert!(uv_receipt_other_index(elsewhere), "{elsewhere}");
        }
    }
}
