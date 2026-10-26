//! Which language packages are installed outside pacman, read from the
//! files their tools leave behind: `package.json` in a global
//! `node_modules`, `*.dist-info/METADATA` in a Python environment, and
//! cargo's `.crates2.json`. No tool is run and no link is followed: a
//! linked package directory (what `npm link` makes) is said, not read.

use std::env;
use std::fs;
use std::io;
use std::path::{Component, Path};

use crate::deps::Ecosystem;
use crate::files::read_small_file;
use crate::json::Json;

/// The most packages taken in one sweep. Arbitrary: well above the global
/// installs of a heavy developer machine, and 40 requests to OSV.
const MAX_PACKAGES: usize = 20_000;

/// The most directory entries looked at in one sweep. Arbitrary: five
/// entries for each package `MAX_PACKAGES` allows.
const MAX_ENTRIES: usize = 100_000;

/// How many `node_modules` deep a global package's own dependencies are
/// read. npm installs them flat since version 3, so a chain past a few
/// levels is rare; 8 is arbitrary.
const MAX_NODE_DEPTH: usize = 8;

/// The largest `package.json` or `METADATA` read. `METADATA` carries the
/// package's whole description after its headers; 2 MiB is arbitrary and
/// far above what packages ship.
const MAX_MANIFEST_BYTES: u64 = 2 * 1024 * 1024;

/// The largest `.crates2.json` read: about 1 KiB per crate, so 8 MiB is
/// arbitrary room for thousands.
const MAX_CRATES_BYTES: u64 = 8 * 1024 * 1024;

/// The largest npm configuration file read. Arbitrary: such a file holds
/// a few lines.
const MAX_NPMRC_BYTES: u64 = 1024 * 1024;

/// The longest name or version taken as a registry's. npm allows 214
/// characters for a name; 256 is arbitrary room above that.
const MAX_NAME_BYTES: usize = 256;

/// How many names a sentence about left-out packages lists.
const NAMED: usize = 3;

/// The index cargo installs crates.io crates from, in its old (git) and
/// new (sparse) form, as `.crates2.json` names the source.
const CRATES_IO: &[&str] = &[
    "registry+https://github.com/rust-lang/crates.io-index",
    "sparse+https://index.crates.io/",
];

/// npm's global configuration files: the one npm reads under its prefix
/// (`/usr`) and the one Arch's npm is built to read. The user's own file is
/// read after them and wins, as in npm.
const GLOBAL_NPMRC: &[&str] = &["usr/etc/npmrc", "etc/npmrc"];

/// One package as OSV names it.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub(super) struct Package {
    pub(super) ecosystem: Ecosystem,
    pub(super) name: String,
    pub(super) version: String,
}

/// An installed package and where it was read.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct Installed {
    pub(super) package: Package,
    /// The manifest it was read from, relative to the root.
    pub(super) manifest: String,
}

/// What the inventory found.
#[derive(Debug, Default)]
pub(super) struct Inventory {
    pub(super) installed: Vec<Installed>,
    /// What could not be read, or lay past a limit, each as a sentence:
    /// those packages are not checked.
    pub(super) unchecked: Vec<String>,
    /// What is left out by design, each as a sentence: a linked package, a
    /// crate from git, a mise tool whose backend OSV has no ecosystem for.
    pub(super) notes: Vec<String>,
    /// npm is installed and its configuration lets packages run their
    /// install scripts.
    pub(super) npm_runs_scripts: bool,
}

/// Where the tools keep what they installed, relative to the root.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct Places {
    /// mise's data directory (`MISE_DATA_DIR`).
    pub(super) mise: Option<String>,
    /// cargo's home (`CARGO_HOME`).
    pub(super) cargo: Option<String>,
    /// pipx's home (`PIPX_HOME`).
    pub(super) pipx: Option<String>,
    /// The user's npm configuration (`NPM_CONFIG_USERCONFIG`).
    pub(super) npmrc: Option<String>,
    /// The home directory, which `~` in npm's `prefix` stands for.
    pub(super) home: Option<String>,
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
            home: home.map(str::to_string),
        }
    }

    /// The defaults, with each place the environment moves elsewhere. A
    /// variable that is not an absolute path without `..` is ignored.
    pub(super) fn from_env(home: Option<&str>) -> Self {
        let mut places = Self::defaults(home);
        let moved = [
            ("MISE_DATA_DIR", &mut places.mise),
            ("CARGO_HOME", &mut places.cargo),
            ("PIPX_HOME", &mut places.pipx),
            ("NPM_CONFIG_USERCONFIG", &mut places.npmrc),
        ];
        for (variable, place) in moved {
            if let Some(path) = env::var(variable).ok().as_deref().and_then(from_root) {
                *place = Some(path);
            }
        }
        places
    }
}

/// `path`, absolute and without `..`, relative to `/`.
fn from_root(path: &str) -> Option<String> {
    let absolute = Path::new(path).is_absolute()
        && !Path::new(path)
            .components()
            .any(|component| component == Component::ParentDir);
    let relative = path.trim_matches('/');
    (absolute && !relative.is_empty()).then(|| relative.to_string())
}

/// Reads what is installed under `root` in `places`.
pub(super) fn collect(root: &Path, places: &Places) -> Inventory {
    let npm = npm_config(root, places);
    let mut walk = Walk::new(root);

    let mut global = vec!["usr/lib/node_modules".to_string()];
    global.extend(
        npm.prefix
            .map(|prefix| format!("{prefix}/lib/node_modules")),
    );
    global.dedup();
    for directory in &global {
        walk.node_modules(directory);
    }
    if let Some(pipx) = &places.pipx {
        walk.pipx(&format!("{pipx}/venvs"));
    }
    if let Some(cargo) = &places.cargo {
        walk.crates(&format!("{cargo}/.crates2.json"));
    }
    let mise_node = places
        .mise
        .as_ref()
        .is_some_and(|mise| walk.mise(&format!("{mise}/installs")));

    let npm_installed = mise_node || fs::symlink_metadata(root.join("usr/bin/npm")).is_ok();
    walk.finish(npm_installed && !npm.ignore_scripts)
}

/// What npm's configuration files say that the inventory needs. These files
/// hold registry tokens: only these two keys are taken, and nothing of them
/// is shown or sent.
#[derive(Debug, Default, PartialEq, Eq)]
struct NpmConfig {
    /// Where global packages go, relative to the root.
    prefix: Option<String>,
    ignore_scripts: bool,
}

fn npm_config(root: &Path, places: &Places) -> NpmConfig {
    let mut config = NpmConfig::default();
    let files = GLOBAL_NPMRC
        .iter()
        .map(|file| (*file).to_string())
        .chain(places.npmrc.clone());
    for file in files {
        let Some(text) = read_small_file(&root.join(file), MAX_NPMRC_BYTES) else {
            continue;
        };
        for (key, value) in text.lines().filter_map(npmrc_setting) {
            match key {
                "prefix" => config.prefix = npm_prefix(value, places.home.as_deref()),
                "ignore-scripts" => config.ignore_scripts = value == "true",
                _ => {}
            }
        }
    }
    config
}

/// The key and value of one line of an npm configuration file, which is
/// INI: `key = value`, comments after `;` or `#`, values maybe quoted.
fn npmrc_setting(line: &str) -> Option<(&str, &str)> {
    let line = line.trim();
    if line.starts_with([';', '#']) {
        return None;
    }
    let (key, value) = line.split_once('=')?;
    Some((key.trim(), value.trim().trim_matches(['"', '\''])))
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

/// What a directory entry is, without following a link.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
enum Entry {
    Directory,
    Link,
    Other,
}

/// How mise installed a tool, by the name of its directory under
/// `installs/` (`node`, `npm-prettier`, `cargo-ripgrep`, `pipx-black`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Backend {
    /// Node itself: its `lib/node_modules` holds npm and whatever was
    /// installed globally with that node.
    Node,
    /// `npm install -g` into the tool's directory.
    Npm,
    /// `cargo install --root` into the tool's directory.
    Cargo,
    /// pipx with its home in the tool's directory.
    Pipx,
    /// Python itself: its `site-packages` holds what `pip install` put
    /// there.
    Python,
}

impl Backend {
    fn of(tool: &str) -> Option<Self> {
        match tool {
            "node" => Some(Self::Node),
            "python" => Some(Self::Python),
            _ if tool.starts_with("npm-") => Some(Self::Npm),
            _ if tool.starts_with("cargo-") => Some(Self::Cargo),
            _ if tool.starts_with("pipx-") => Some(Self::Pipx),
            _ => None,
        }
    }
}

/// A walk over the places packages are kept, within the limits.
struct Walk<'a> {
    root: &'a Path,
    inventory: Inventory,
    entries: usize,
    /// A limit was reached: nothing more is taken.
    full: bool,
    /// A `node_modules` lay deeper than `MAX_NODE_DEPTH`.
    too_deep: bool,
    /// Manifests (or the directories that should hold one) that could not
    /// be read or named no package.
    unreadable: Vec<String>,
    /// Package directories that are links.
    linked: Vec<String>,
    /// Crates from git, a path or another registry.
    elsewhere: Vec<String>,
    /// mise tools whose backend OSV has no ecosystem for.
    skipped: Vec<String>,
}

impl<'a> Walk<'a> {
    fn new(root: &'a Path) -> Self {
        Self {
            root,
            inventory: Inventory::default(),
            entries: 0,
            full: false,
            too_deep: false,
            unreadable: Vec::new(),
            linked: Vec::new(),
            elsewhere: Vec::new(),
            skipped: Vec::new(),
        }
    }

    /// The entries of directory `rel`, sorted; none when it does not
    /// exist. One that exists and cannot be listed is unreadable.
    fn list(&mut self, rel: &str) -> Vec<(String, Entry)> {
        let listing = match fs::read_dir(self.root.join(rel)) {
            Ok(listing) => listing,
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Vec::new(),
            Err(_) => {
                self.unreadable.push(rel.to_string());
                return Vec::new();
            }
        };
        let mut found = Vec::new();
        for entry in listing {
            if self.entries >= MAX_ENTRIES {
                self.full = true;
                break;
            }
            self.entries += 1;
            let Ok(entry) = entry else {
                self.unreadable.push(rel.to_string());
                continue;
            };
            let Some(name) = entry.file_name().to_str().map(str::to_string) else {
                self.unreadable
                    .push(format!("{rel}/{}", entry.file_name().to_string_lossy()));
                continue;
            };
            // `DirEntry::file_type` does not follow a link.
            let kind = match entry.file_type() {
                Ok(kind) if kind.is_symlink() => Entry::Link,
                Ok(kind) if kind.is_dir() => Entry::Directory,
                Ok(_) => Entry::Other,
                Err(_) => {
                    self.unreadable.push(format!("{rel}/{name}"));
                    continue;
                }
            };
            found.push((name, kind));
        }
        found.sort();
        found
    }

    /// Takes in one package, unless its name or version is no registry's.
    fn add(&mut self, ecosystem: Ecosystem, name: &str, version: &str, manifest: &str) {
        if !is_registry_word(name) || !is_registry_word(version) {
            self.unreadable.push(manifest.to_string());
            return;
        }
        if self.inventory.installed.len() >= MAX_PACKAGES {
            self.full = true;
            return;
        }
        let name = match ecosystem {
            Ecosystem::PyPi => canonical_python_name(name),
            Ecosystem::CratesIo | Ecosystem::Npm | Ecosystem::Go => name.to_string(),
        };
        self.inventory.installed.push(Installed {
            package: Package {
                ecosystem,
                name,
                version: version.to_string(),
            },
            manifest: manifest.to_string(),
        });
    }

    /// Every package in the `node_modules` directory `top`, and in their
    /// own `node_modules` below them.
    fn node_modules(&mut self, top: &str) {
        let mut pending = vec![(top.to_string(), 0)];
        while let Some((directory, depth)) = pending.pop() {
            for package in self.packages_in(&directory) {
                if self.full {
                    return;
                }
                let Some(nested) = self.npm_package(&package) else {
                    continue;
                };
                if depth + 1 < MAX_NODE_DEPTH {
                    pending.push((nested, depth + 1));
                } else {
                    self.too_deep = true;
                }
            }
        }
    }

    /// The package directories in the `node_modules` directory
    /// `directory`, scoped ones (`@scope/name`) included. Dot entries
    /// (`.bin`, npm's `.package-lock.json`) are npm's own.
    fn packages_in(&mut self, directory: &str) -> Vec<String> {
        let mut packages = Vec::new();
        for (name, kind) in self.list(directory) {
            let path = format!("{directory}/{name}");
            match kind {
                _ if name.starts_with('.') => {}
                Entry::Link => self.linked.push(path),
                Entry::Directory if name.starts_with('@') => {
                    for (scoped, kind) in self.list(&path) {
                        let scoped_path = format!("{path}/{scoped}");
                        match kind {
                            Entry::Link => self.linked.push(scoped_path),
                            Entry::Directory => packages.push(scoped_path),
                            Entry::Other => {}
                        }
                    }
                }
                Entry::Directory => packages.push(path),
                Entry::Other => {}
            }
        }
        packages
    }

    /// Reads the npm package in `directory`; returns its own
    /// `node_modules`, if it has one.
    fn npm_package(&mut self, directory: &str) -> Option<String> {
        let manifest = format!("{directory}/package.json");
        let json = read_small_file(&self.root.join(&manifest), MAX_MANIFEST_BYTES)
            .and_then(|text| Json::parse(&text).ok());
        let field = |key: &str| {
            json.as_ref()
                .and_then(|json| json.get(key))
                .and_then(Json::as_str)
                .map(str::to_string)
        };
        match (field("name"), field("version")) {
            (Some(name), Some(version)) => self.add(Ecosystem::Npm, &name, &version, &manifest),
            _ => self.unreadable.push(manifest),
        }
        let nested = format!("{directory}/node_modules");
        fs::symlink_metadata(self.root.join(&nested))
            .is_ok_and(|metadata| metadata.is_dir())
            .then_some(nested)
    }

    /// Every pipx environment under `venvs`.
    fn pipx(&mut self, venvs: &str) {
        for (venv, kind) in self.list(venvs) {
            let path = format!("{venvs}/{venv}");
            match kind {
                Entry::Directory if !self.pythons(&path) => self.unreadable.push(path),
                Entry::Link => self.linked.push(path),
                Entry::Directory | Entry::Other => {}
            }
        }
    }

    /// Every `lib/python*/site-packages` of `environment`; returns whether
    /// there was one.
    fn pythons(&mut self, environment: &str) -> bool {
        let lib = format!("{environment}/lib");
        let mut found = false;
        for (python, kind) in self.list(&lib) {
            if kind == Entry::Directory && python.starts_with("python") {
                let site = format!("{lib}/{python}/site-packages");
                found |= fs::symlink_metadata(self.root.join(&site)).is_ok();
                self.site_packages(&site);
            }
        }
        found
    }

    /// Every package pip recorded in `site`, a `*.dist-info` directory
    /// each. An `*.egg-info` is not read: pip has not written one for an
    /// install in years.
    fn site_packages(&mut self, site: &str) {
        for (name, kind) in self.list(site) {
            if self.full {
                return;
            }
            if kind != Entry::Directory || !name.ends_with(".dist-info") {
                continue;
            }
            let manifest = format!("{site}/{name}/METADATA");
            let headers = read_small_file(&self.root.join(&manifest), MAX_MANIFEST_BYTES)
                .and_then(|text| metadata(&text));
            match headers {
                Some((name, version)) => self.add(Ecosystem::PyPi, &name, &version, &manifest),
                None => self.unreadable.push(manifest),
            }
        }
    }

    /// Every crate cargo recorded in `file` (a `.crates2.json`), if there
    /// is one.
    fn crates(&mut self, file: &str) {
        let path = self.root.join(file);
        if fs::symlink_metadata(&path).is_err() {
            return;
        }
        let json =
            read_small_file(&path, MAX_CRATES_BYTES).and_then(|text| Json::parse(&text).ok());
        let Some(installs) = json
            .as_ref()
            .and_then(|json| json.get("installs"))
            .and_then(Json::as_object)
        else {
            self.unreadable.push(file.to_string());
            return;
        };
        for (key, _) in installs {
            if self.full {
                return;
            }
            match crate_key(key) {
                Some((name, version, source)) if CRATES_IO.contains(&source) => {
                    self.add(Ecosystem::CratesIo, name, version, file);
                }
                Some((name, _, _)) => self.elsewhere.push(name.to_string()),
                None => self.unreadable.push(file.to_string()),
            }
        }
    }

    /// What mise installed under `installs` through a backend OSV has an
    /// ecosystem for; returns whether a node of mise's is installed.
    fn mise(&mut self, installs: &str) -> bool {
        let mut node = false;
        for (tool, kind) in self.list(installs) {
            if kind != Entry::Directory {
                continue;
            }
            let Some(backend) = Backend::of(&tool) else {
                self.skipped.push(tool);
                continue;
            };
            let directory = format!("{installs}/{tool}");
            // mise links the short versions (`22`, `latest`) to a full
            // one, which is read under its own name.
            for (version, kind) in self.list(&directory) {
                if kind == Entry::Directory {
                    self.mise_tool(backend, &format!("{directory}/{version}"));
                    node |= backend == Backend::Node;
                }
            }
        }
        node
    }

    /// One version of one tool mise installed, in `directory`.
    fn mise_tool(&mut self, backend: Backend, directory: &str) {
        match backend {
            Backend::Node | Backend::Npm => {
                self.node_modules(&format!("{directory}/lib/node_modules"));
            }
            Backend::Cargo => {
                let file = format!("{directory}/.crates2.json");
                if fs::symlink_metadata(self.root.join(&file)).is_ok() {
                    self.crates(&file);
                } else {
                    self.unreadable.push(file);
                }
            }
            Backend::Pipx => {
                let venvs = format!("{directory}/venvs");
                let mut found = self.pythons(directory);
                for (venv, kind) in self.list(&venvs) {
                    if kind == Entry::Directory {
                        found |= self.pythons(&format!("{venvs}/{venv}"));
                    }
                }
                if !found {
                    self.unreadable.push(directory.to_string());
                }
            }
            Backend::Python => {
                if !self.pythons(directory) {
                    self.unreadable.push(directory.to_string());
                }
            }
        }
    }

    /// The inventory, with what was left out said.
    fn finish(mut self, npm_runs_scripts: bool) -> Inventory {
        let inventory = &mut self.inventory;
        inventory.npm_runs_scripts = npm_runs_scripts;
        if !self.unreadable.is_empty() {
            inventory.unchecked.push(format!(
                "{} language package manifest(s) or environment(s) could not be read or name no package and version, so those packages were not looked up in OSV: {}",
                self.unreadable.len(),
                named(&self.unreadable, "/")
            ));
        }
        if self.full {
            inventory.unchecked.push(format!(
                "more than {MAX_PACKAGES} language packages or {MAX_ENTRIES} entries where they are kept: the rest were not looked up in OSV"
            ));
        }
        if self.too_deep {
            inventory.unchecked.push(format!(
                "npm packages more than {MAX_NODE_DEPTH} node_modules deep were not looked up in OSV"
            ));
        }
        if !self.linked.is_empty() {
            inventory.notes.push(format!(
                "{} linked language package(s) were not followed or looked up in OSV (what `npm link` installs is a project of your own): {}",
                self.linked.len(),
                named(&self.linked, "/")
            ));
        }
        if !self.elsewhere.is_empty() {
            inventory.notes.push(format!(
                "{} crate(s) installed from git, a path or another registry than crates.io are not looked up in OSV: {}",
                self.elsewhere.len(),
                named(&self.elsewhere, "")
            ));
        }
        if !self.skipped.is_empty() {
            inventory.notes.push(format!(
                "{} mise tool(s) installed through a backend OSV has no ecosystem for are not looked up: {}",
                self.skipped.len(),
                named(&self.skipped, "")
            ));
        }
        self.inventory
    }
}

/// The first `NAMED` of `names`, each after `before`, and whether there are
/// more.
fn named(names: &[String], before: &str) -> String {
    let mut shown: Vec<String> = names
        .iter()
        .take(NAMED)
        .map(|name| crate::text::shown(&format!("{before}{name}")).into_owned())
        .collect();
    if names.len() > NAMED {
        shown.push("...".into());
    }
    shown.join(", ")
}

/// Whether `word` can be a registry's package name or version: not empty,
/// not too long, no blank or control character.
fn is_registry_word(word: &str) -> bool {
    !word.is_empty()
        && word.len() <= MAX_NAME_BYTES
        && !word
            .chars()
            .any(|character| character.is_whitespace() || character.is_control())
}

/// A Python package name as the index knows it: lowercase, each run of
/// `-`, `_` and `.` one `-`
/// (<https://packaging.python.org/en/latest/specifications/name-normalization/>).
fn canonical_python_name(name: &str) -> String {
    let mut canonical = String::with_capacity(name.len());
    for character in name.chars() {
        if matches!(character, '-' | '_' | '.') {
            if !canonical.ends_with('-') {
                canonical.push('-');
            }
        } else {
            canonical.push(character.to_ascii_lowercase());
        }
    }
    canonical
}

/// The `Name` and `Version` headers of a `METADATA` file, which come
/// before its first blank line.
fn metadata(text: &str) -> Option<(String, String)> {
    let mut name = None;
    let mut version = None;
    for line in text.lines().take_while(|line| !line.trim().is_empty()) {
        let Some((key, value)) = line.split_once(':') else {
            continue;
        };
        let value = Some(value.trim().to_string());
        if key.eq_ignore_ascii_case("name") {
            name = name.or(value);
        } else if key.eq_ignore_ascii_case("version") {
            version = version.or(value);
        }
    }
    Some((name?, version?))
}

/// The name, version and source of a `.crates2.json` key, which reads
/// `name version (source)`.
fn crate_key(key: &str) -> Option<(&str, &str, &str)> {
    let (name, rest) = key.split_once(' ')?;
    let (version, source) = rest.split_once(" (")?;
    Some((name, version, source.strip_suffix(')')?))
}

#[cfg(test)]
mod tests {
    use super::{
        Places, canonical_python_name, crate_key, from_root, metadata, npm_prefix, npmrc_setting,
    };

    #[test]
    fn names_and_keys_are_read_as_the_tools_write_them() {
        assert_eq!(canonical_python_name("Foo__Bar.baz"), "foo-bar-baz");
        assert_eq!(
            crate_key("ripgrep 14.1.0 (registry+https://github.com/rust-lang/crates.io-index)"),
            Some((
                "ripgrep",
                "14.1.0",
                "registry+https://github.com/rust-lang/crates.io-index"
            ))
        );
        assert_eq!(crate_key("odd"), None);
        assert_eq!(
            metadata("Metadata-Version: 2.1\nName: Black\nVersion: 24.1.0\n\nName: not a header\n"),
            Some(("Black".into(), "24.1.0".into()))
        );
        assert_eq!(metadata("Name: x\n\nVersion: 1\n"), None);
    }

    #[test]
    fn npm_settings_and_places_take_only_what_npm_would() {
        assert_eq!(
            npmrc_setting(" ignore-scripts = \"true\" "),
            Some(("ignore-scripts", "true"))
        );
        assert_eq!(npmrc_setting("; ignore-scripts=true"), None);
        assert_eq!(npmrc_setting("# ignore-scripts=true"), None);
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
}
