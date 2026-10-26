//! What npm's, pip's and uv's configuration say about where packages come
//! from, read locally only. These files hold registry tokens and index
//! passwords: only the keys named here are taken, and nothing of them is
//! shown or sent.
//!
//! A package from a registry other than the public one may have a private
//! name, which must not go to OSV: npm's `registry` (or a scope's own),
//! the address a hidden lockfile or `package.json` records, pip's
//! `index-url`, `extra-index-url` and `find-links`, and uv's index settings
//! (for what mise installs through uv) decide that.

use std::env;
use std::fs;
use std::io;
use std::path::{Component, Path};

use crate::files::read_small_file;
use crate::tomlish;

/// The largest configuration file read. Arbitrary: such a file holds a few
/// lines.
const MAX_CONFIG_BYTES: u64 = 1024 * 1024;

/// npm's global configuration files: the one npm reads under its prefix
/// (`/usr`) and the one Arch's npm is built to read. The user's own file is
/// read after them, and the environment after that, as in npm.
const GLOBAL_NPMRC: &[&str] = &["usr/etc/npmrc", "etc/npmrc"];

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
        }
    }

    /// The defaults, with what the environment changes. A variable that
    /// names a place and is not an absolute path without `..` is ignored.
    pub(super) fn from_env(home: Option<&str>) -> Self {
        let variables: Vec<(String, String)> = env::vars_os()
            .filter_map(|(name, value)| Some((name.into_string().ok()?, value.into_string().ok()?)))
            .collect();
        Self::from_variables(home, &variables)
    }

    fn from_variables(home: Option<&str>, variables: &[(String, String)]) -> Self {
        let mut places = Self::defaults(home);
        for (name, value) in variables {
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
        places.npm_env = npm_variables(variables);
        places.pip_env = pip_variables(variables);
        if let Some((_, file)) = places.npm_env.iter().find(|(key, _)| key == "userconfig") {
            places.npmrc = from_root(file);
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
        let mut config_dirs: Vec<&str> = variable("XDG_CONFIG_HOME").into_iter().collect();
        config_dirs.extend(
            variable("XDG_CONFIG_DIRS")
                .into_iter()
                .flat_map(|dirs| dirs.split(':')),
        );
        for directory in config_dirs {
            places
                .pip
                .extend(from_root(&format!("{directory}/pip/pip.conf")));
            places
                .uv
                .extend(from_root(&format!("{directory}/uv/uv.toml")));
        }
        places
            .pip
            .extend(variable("PIP_CONFIG_FILE").and_then(from_root));
        places
            .uv
            .extend(variable("UV_CONFIG_FILE").and_then(from_root));
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

/// What pip's or uv's configuration (files and environment) says of where
/// packages come from.
#[derive(Debug)]
pub(super) struct IndexConfig {
    /// It brings packages from somewhere other than the Python Package
    /// Index, or a file of it could not be read: then what the tool
    /// installed may be of a private index, and none of it is looked up.
    pub(super) other_index: bool,
    /// The files that are there and could not be read, relative to the
    /// root.
    pub(super) unreadable: Vec<String>,
}

impl IndexConfig {
    pub(super) fn pip(root: &Path, places: &Places) -> Self {
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
        // A value pip writes on the lines after its key reads here as an
        // empty one, so an empty value counts as another index too.
        let other_index = !unreadable.is_empty()
            || settings.iter().any(|(key, value)| {
                PIP_INDEX_KEYS.contains(&key.as_str()) && !is_on(value, PYPI_HOSTS)
            });
        Self {
            other_index,
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
        let mut unreadable = Vec::new();
        for file in files {
            let entries = match read_config(root, &file) {
                ConfigFile::Absent => continue,
                ConfigFile::Unreadable => Err(()),
                ConfigFile::Text(text) => tomlish::entries(&text).map_err(drop),
            };
            match entries {
                Ok(entries) => {
                    other_index |= entries.iter().any(|entry| is_uv_index(&entry.full_path()));
                }
                Err(()) => unreadable.push(file),
            }
        }
        Self {
            other_index: other_index || !unreadable.is_empty(),
            unreadable,
        }
    }
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
/// options, or a requirement with anything beyond a name, a version and
/// extras (a git, url, path or index source). Text it cannot read counts.
pub(super) fn uv_receipt_other_index(text: &str) -> bool {
    let Ok(entries) = tomlish::entries(text) else {
        return true;
    };
    entries.iter().any(|entry| {
        let path = entry.full_path();
        if path.iter().any(|part| UV_INDEX_KEYS.contains(part)) {
            return true;
        }
        // Splitting the inline tables at every delimiter finds every key; a
        // delimiter inside a string can only add a key that is not allowed.
        path == ["tool", "requirements"]
            && entry
                .value
                .split([',', '{', '}', '[', ']'])
                .filter_map(|part| part.split_once('='))
                .any(|(key, _)| {
                    !UV_REQUIREMENT_KEYS.contains(&key.trim().trim_matches(['"', '\'']))
                })
    })
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
        pip_variables, setting, uv_receipt_other_index,
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
        let public = "[tool]\nrequirements = [{ name = \"black\", specifier = \">=24\" }]\n";
        assert!(!uv_receipt_other_index(public));
        for elsewhere in [
            "[tool]\nrequirements = [{ name = \"inhouse\", git = \"https://git.example/x\" }]\n",
            "[tool]\nrequirements = [{ name = \"x\", index = \"https://pypi.corp.example\" }]\n",
            "[tool]\nrequirements = [{ name = \"x\" }]\n[tool.options]\nindex-url = \"https://a\"\n",
            "[tool\n",
        ] {
            assert!(uv_receipt_other_index(elsewhere), "{elsewhere}");
        }
    }
}
