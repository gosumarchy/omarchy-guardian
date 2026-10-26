//! What npm's and pip's configuration say about where packages come from,
//! read locally only. These files hold registry tokens and index passwords:
//! only the keys named here are taken, and nothing of them is shown or
//! sent.
//!
//! A package from a registry other than the public one may have a private
//! name, which must not go to OSV: npm's `registry` (or a scope's own),
//! the address a hidden lockfile or `package.json` records, and pip's
//! `index-url`, `extra-index-url` and `find-links` decide that.

use std::env;
use std::fs;
use std::io;
use std::path::{Component, Path};

use crate::files::read_small_file;

/// The largest configuration file read. Arbitrary: such a file holds a few
/// lines.
const MAX_CONFIG_BYTES: u64 = 1024 * 1024;

/// npm's global configuration files: the one npm reads under its prefix
/// (`/usr`) and the one Arch's npm is built to read. The user's own file is
/// read after them, and the environment after that, as in npm.
const GLOBAL_NPMRC: &[&str] = &["usr/etc/npmrc", "etc/npmrc"];

/// pip's global configuration files, read before the user's.
const GLOBAL_PIP: &[&str] = &["etc/xdg/pip/pip.conf", "etc/pip.conf"];

/// The hosts of npm's public registry. Yarn's serves the same packages
/// under the same names.
const NPM_REGISTRIES: &[&str] = &["registry.npmjs.org", "registry.yarnpkg.com"];

/// The hosts of the Python Package Index.
const PYPI_HOSTS: &[&str] = &["pypi.org", "pypi.python.org", "files.pythonhosted.org"];

/// The pip settings that bring packages from somewhere other than the Python Package Index.
const PIP_INDEX_KEYS: &[&str] = &["index-url", "extra-index-url", "find-links"];

/// The pip arguments that do the same, as pipx records them.
const PIP_INDEX_ARGUMENTS: &[&str] = &[
    "--index-url",
    "--extra-index-url",
    "--find-links",
    "-i",
    "-f",
];

/// Where the tools keep what they installed and their configuration,
/// relative to the root, with the settings the environment gives.
#[derive(Debug)]
pub(super) struct Places {
    /// mise's data directory (`MISE_DATA_DIR`).
    pub(super) mise: Option<String>,
    /// cargo's home (`CARGO_HOME`).
    pub(super) cargo: Option<String>,
    /// pipx's home (`PIPX_HOME`).
    pub(super) pipx: Option<String>,
    /// The user's npm configuration (`npm_config_userconfig`).
    pub(super) npmrc: Option<String>,
    /// pip's configuration files of the user, and `PIP_CONFIG_FILE`.
    pub(super) pip: Vec<String>,
    /// The home directory, which `~` in npm's `prefix` stands for.
    pub(super) home: Option<String>,
    /// npm settings the environment gives (`npm_config_*`, in any case),
    /// as a file would write them: they win over every file.
    pub(super) npm_env: Vec<(String, String)>,
    /// pip's index settings the environment gives (`PIP_INDEX_URL` and the
    /// like), as a file would write them.
    pub(super) pip_env: Vec<(String, String)>,
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
            home: home.map(str::to_string),
            npm_env: Vec::new(),
            pip_env: Vec::new(),
        }
    }

    /// The defaults, with what the environment changes. A variable that
    /// names a place and is not an absolute path without `..` is ignored.
    pub(super) fn from_env(home: Option<&str>) -> Self {
        let mut places = Self::defaults(home);
        let variables: Vec<(String, String)> = env::vars_os()
            .filter_map(|(name, value)| Some((name.into_string().ok()?, value.into_string().ok()?)))
            .collect();
        for (name, value) in &variables {
            let place = match name.as_str() {
                "MISE_DATA_DIR" => &mut places.mise,
                "CARGO_HOME" => &mut places.cargo,
                "PIPX_HOME" => &mut places.pipx,
                _ => continue,
            };
            if let Some(path) = from_root(value) {
                *place = Some(path);
            }
        }
        places.npm_env = npm_variables(&variables);
        places.pip_env = pip_variables(&variables);
        if let Some((_, file)) = places.npm_env.iter().find(|(key, _)| key == "userconfig") {
            places.npmrc = from_root(file);
        }
        if let Some((_, file)) = variables.iter().find(|(name, _)| name == "PIP_CONFIG_FILE") {
            places.pip.extend(from_root(file));
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
            Some((key, value.clone()))
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

/// What npm's configuration says that the inventory needs.
#[derive(Debug, Default)]
pub(super) struct NpmConfig {
    /// Where global packages go, relative to the root.
    pub(super) prefix: Option<String>,
    pub(super) ignore_scripts: bool,
    /// The registry packages come from, where one is set.
    registry: Option<String>,
    /// The registry of each scope that has its own (`@scope:registry`).
    scoped: Vec<(String, String)>,
    /// The files that are there and could not be read (a link, closed, or
    /// too large), relative to the root: what they set is not known.
    pub(super) unreadable: Vec<String>,
}

impl NpmConfig {
    /// Reads the global files, then the user's, then the environment, each
    /// setting winning over the one before.
    pub(super) fn read(root: &Path, places: &Places) -> Self {
        let mut config = Self::default();
        let files = GLOBAL_NPMRC
            .iter()
            .map(|file| (*file).to_string())
            .chain(places.npmrc.clone());
        for file in files {
            let text = match read_config(root, &file) {
                ConfigFile::Absent => continue,
                ConfigFile::Unreadable => {
                    config.unreadable.push(file);
                    continue;
                }
                ConfigFile::Text(text) => text,
            };
            for (key, value) in text.lines().filter_map(|line| setting(line, &['='])) {
                config.set(key, value, places.home.as_deref());
            }
        }
        for (key, value) in &places.npm_env {
            config.set(key, value, places.home.as_deref());
        }
        config
    }

    fn set(&mut self, key: &str, value: &str, home: Option<&str>) {
        match key {
            "prefix" => self.prefix = npm_prefix(value, home),
            "ignore-scripts" => self.ignore_scripts = value == "true",
            "registry" => self.registry = Some(value.to_string()),
            _ => {
                if let Some(scope) = key
                    .strip_suffix(":registry")
                    .filter(|scope| scope.starts_with('@'))
                {
                    self.scoped.retain(|(known, _)| known != scope);
                    self.scoped.push((scope.to_string(), value.to_string()));
                }
            }
        }
    }

    /// Whether the npm package `name`, installed from the address
    /// `resolved` where one is recorded, came from npm's public registry.
    pub(super) fn is_public(&self, name: &str, resolved: Option<&str>) -> bool {
        if let Some(resolved) = resolved {
            return is_on(resolved, NPM_REGISTRIES);
        }
        let scope = name
            .split_once('/')
            .map(|(scope, _)| scope)
            .filter(|scope| scope.starts_with('@'));
        let registry = scope
            .and_then(|scope| self.scoped.iter().find(|(known, _)| known == scope))
            .map(|(_, registry)| registry)
            .or(self.registry.as_ref());
        registry.is_none_or(|registry| is_on(registry, NPM_REGISTRIES))
    }
}

/// What pip's configuration (files and environment) says of where
/// packages come from.
#[derive(Debug)]
pub(super) struct PipConfig {
    /// It brings packages from somewhere other than the Python Package
    /// Index, or a file of it could not be read: then what pip installed
    /// may be of a private index, and none of it is looked up.
    pub(super) other_index: bool,
    /// The files that are there and could not be read, relative to the
    /// root.
    pub(super) unreadable: Vec<String>,
}

impl PipConfig {
    pub(super) fn read(root: &Path, places: &Places) -> Self {
        let files = GLOBAL_PIP
            .iter()
            .map(|file| (*file).to_string())
            .chain(places.pip.iter().cloned());
        let mut settings: Vec<(String, String)> = Vec::new();
        let mut unreadable = Vec::new();
        for file in files {
            match read_config(root, &file) {
                ConfigFile::Absent => {}
                ConfigFile::Unreadable => unreadable.push(file),
                ConfigFile::Text(text) => settings.extend(text.lines().filter_map(|line| {
                    let (key, value) = setting(line, &['=', ':'])?;
                    Some((
                        key.to_ascii_lowercase().replace('_', "-"),
                        value.to_string(),
                    ))
                })),
            }
        }
        settings.extend(places.pip_env.iter().cloned());
        let other_index = !unreadable.is_empty()
            || settings.iter().any(|(key, value)| match key.as_str() {
                "index-url" => !is_on(value, PYPI_HOSTS),
                "extra-index-url" | "find-links" => !value.is_empty(),
                _ => false,
            });
        Self {
            other_index,
            unreadable,
        }
    }
}

/// What reading one configuration file gave.
enum ConfigFile {
    Absent,
    /// There, and a link, closed, or larger than `MAX_CONFIG_BYTES`.
    Unreadable,
    Text(String),
}

fn read_config(root: &Path, file: &str) -> ConfigFile {
    let path = root.join(file);
    match fs::symlink_metadata(&path) {
        Err(error) if error.kind() == io::ErrorKind::NotFound => ConfigFile::Absent,
        Err(_) => ConfigFile::Unreadable,
        Ok(_) => read_small_file(&path, MAX_CONFIG_BYTES)
            .map_or(ConfigFile::Unreadable, ConfigFile::Text),
    }
}

/// Whether pip arguments, as pipx records them for an environment, bring
/// packages from somewhere other than the Python Package Index.
pub(super) fn has_index_argument<'a>(arguments: impl IntoIterator<Item = &'a str>) -> bool {
    arguments.into_iter().any(|argument| {
        PIP_INDEX_ARGUMENTS.iter().any(|option| {
            argument == *option
                || argument
                    .strip_prefix(option)
                    .is_some_and(|rest| rest.starts_with('=') || !option.starts_with("--"))
        })
    })
}

/// The key and value of one line of an INI file: `key = value`, `;` and
/// `#` starting a comment, which also ends an unquoted value; a quoted
/// value is taken whole.
fn setting<'a>(line: &'a str, separators: &[char]) -> Option<(&'a str, &'a str)> {
    let line = line.trim();
    if line.starts_with([';', '#', '[']) {
        return None;
    }
    let at = line.find(separators)?;
    let (key, value) = (line[..at].trim(), line[at + 1..].trim());
    let value = match value.chars().next() {
        Some(quote @ ('"' | '\'')) => value[1..].split(quote).next().unwrap_or_default(),
        _ => value.split([';', '#']).next().unwrap_or_default().trim(),
    };
    Some((key, value))
}

/// npm's `prefix`, relative to the root: an absolute path, or one under the
/// home written as `~/`, `$HOME/` or `${HOME}/`.
fn npm_prefix(value: &str, home: Option<&str>) -> Option<String> {
    let in_home = ["~/", "$HOME/", "${HOME}/"]
        .iter()
        .find_map(|start| value.strip_prefix(start));
    match (in_home, home) {
        (Some(rest), Some(home)) => from_root(&format!("/{home}/{rest}")),
        (Some(_), None) => None,
        (None, _) => from_root(value),
    }
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
        NpmConfig, Places, from_root, has_index_argument, is_on, npm_prefix, npm_variables,
        pip_variables, setting,
    };

    #[test]
    fn ini_lines_are_read_as_npm_and_pip_read_them() {
        assert_eq!(
            setting(" ignore-scripts = \"true\" ", &['=']),
            Some(("ignore-scripts", "true"))
        );
        assert_eq!(
            setting("ignore-scripts=true ; why", &['=']),
            Some(("ignore-scripts", "true"))
        );
        assert_eq!(setting("prefix = '/a;b'", &['=']), Some(("prefix", "/a;b")));
        assert_eq!(setting("; ignore-scripts=true", &['=']), None);
        assert_eq!(setting("# ignore-scripts=true", &['=']), None);
        assert_eq!(setting("[global]", &['=', ':']), None);
        assert_eq!(
            setting("index-url: https://x.example/simple", &['=', ':']),
            Some(("index-url", "https://x.example/simple"))
        );
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
        assert_eq!(
            npm_variables(&variables),
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

        let mut config = NpmConfig::default();
        assert!(config.is_public("a", None));
        assert!(!config.is_public("a", Some("file:../a")));
        config.set("@corp:registry", "https://npm.corp.example/", None);
        assert!(!config.is_public("@corp/a", None));
        assert!(config.is_public("@other/a", None));
        config.set("registry", "https://mirror.example/", None);
        assert!(!config.is_public("a", None));
        assert!(config.is_public("a", Some("https://registry.npmjs.org/a/-/a-1.tgz")));

        assert!(has_index_argument(["--index-url", "https://x"]));
        assert!(has_index_argument(["--extra-index-url=https://x"]));
        assert!(has_index_argument(["-ihttps://x"]));
        assert!(!has_index_argument(["--no-cache-dir", "--index-urlx"]));
    }
}
