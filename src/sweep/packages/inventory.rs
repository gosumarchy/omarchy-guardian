//! Which language packages are installed outside pacman, read from the
//! files their tools leave behind: `package.json` in a global
//! `node_modules`, `*.dist-info/METADATA` in a Python environment, and
//! cargo's `.crates2.json`. No tool is run, and no link below a starting
//! place is followed: a linked package directory (what `npm link` makes),
//! environment, `lib`, `node_modules` or `site-packages` is said, not
//! read. A link among the parts of a starting place itself (npm's prefix,
//! `CARGO_HOME`, mise's and pipx's homes, a home kept on another disk) is
//! followed, as the tool that installed there follows it.
//!
//! A package that came from somewhere other than the public registry
//! (see `config`) is not taken: its name may be private, and it goes to no
//! one. It is said as not checked. Where the files keep no record of a
//! source (a global npm package installed from git, pip given
//! `--index-url` on its command line), the package is taken.

use std::fs;
use std::io;
use std::path::Path;

use super::config::{self, ConfigFile, IndexConfig, NpmConfig, Places};
use crate::deps::Ecosystem;
use crate::files::read_small_file;
use crate::json::Json;
use crate::text;

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

/// The largest `package.json`, `METADATA` or `pipx_metadata.json` read.
/// `METADATA` carries the package's whole description after its headers;
/// 2 MiB is arbitrary and far above what packages ship.
const MAX_MANIFEST_BYTES: u64 = 2 * 1024 * 1024;

/// The most nodes of mise's whose npm configuration is read. Arbitrary:
/// far more than anyone keeps installed.
const MAX_NODES: usize = 100;

/// The largest `.crates2.json` read: about 1 KiB
/// per package, so 8 MiB is arbitrary room for thousands.
const MAX_LIST_BYTES: u64 = 8 * 1024 * 1024;

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

/// One package as OSV names it.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(super) struct Package {
    pub(super) ecosystem: Ecosystem,
    pub(super) name: String,
    pub(super) version: String,
}

/// An installed package and where it was read.
#[derive(Debug)]
pub(super) struct Installed {
    pub(super) package: Package,
    /// The manifest it was read from, relative to the root.
    pub(super) manifest: String,
}

/// What the inventory found.
#[derive(Debug, Default)]
pub(super) struct Inventory {
    pub(super) installed: Vec<Installed>,
    /// What could not be read, lay past a limit or came from a registry
    /// that may be private, each as a sentence: those packages are not
    /// checked.
    pub(super) unchecked: Vec<String>,
    /// What is left out by design, each as a sentence: a link.
    pub(super) notes: Vec<String>,
    /// npm is installed and its configuration lets packages run their
    /// install scripts.
    pub(super) npm_runs_scripts: bool,
}

/// Reads what is installed under `root` in `places`.
pub(super) fn collect(root: &Path, places: &Places) -> Inventory {
    let mut nodes = vec!["usr".to_string()];
    nodes.extend(places.mise.as_ref().map_or_else(Vec::new, |mise| {
        mise_nodes(root, &format!("{mise}/installs/node"))
    }));
    let too_many_nodes = nodes.len() > MAX_NODES + 1;
    nodes.truncate(MAX_NODES + 1);
    let mut npm = NpmConfig::read(root, places, &nodes);
    if too_many_nodes {
        // A node whose configuration was not read may take packages from a
        // private registry: it counts as a file that could not be read.
        npm.unreadable.push(format!(
            "the npm configuration of the nodes mise installed past the first {MAX_NODES}"
        ));
    }
    let pip = IndexConfig::pip(root, places);
    let uv = IndexConfig::uv(root, places);
    let cargo = IndexConfig::cargo(root, places);
    let sources = Sources {
        pip: Source::configured(&pip),
        uv: Source::configured(&uv),
        cargo: Source::configured(&cargo),
    };
    let mut walk = Walk::new(root, &npm, sources);

    // A prefix set to a node's own directory is read with that node.
    walk.node_modules("usr/lib/node_modules");
    for prefix in npm.prefixes.iter().filter(|prefix| !nodes.contains(prefix)) {
        walk.node_modules(&format!("{prefix}/lib/node_modules"));
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
    let mut inventory = walk.finish(npm_installed && !npm.ignore_scripts);
    for (name, value) in &places.unfound {
        if ["CARGO_HOME", "PIPX_HOME", "MISE_DATA_DIR"].contains(name) {
            inventory.unchecked.push(format!(
                "{name} is not an absolute path ({}), so what is installed there was not read",
                text::shown(value)
            ));
        }
    }
    // Only the path is said: these files hold registry tokens.
    for file in &npm.unreadable {
        inventory.unchecked.push(format!(
            "{} could not be read (not a regular file, closed, too large, not found, or past a limit): it may name a private registry, so no npm package was looked up in OSV, and packages under an npm prefix it may set were not read",
            text::shown(file)
        ));
    }
    for file in &pip.unreadable {
        inventory.unchecked.push(format!(
            "{} could not be read (not a regular file, closed, too large, or not found): it may name a private index, so no Python package pip installed was looked up in OSV",
            text::shown(file)
        ));
    }
    for file in &cargo.unreadable {
        inventory.unchecked.push(format!(
            "{} could not be read (not a regular file, closed, too large, not TOML, or not found): it may replace crates.io with another source, so no crate was looked up in OSV",
            text::shown(file)
        ));
    }
    if cargo.other_index && cargo.unreadable.is_empty() {
        inventory.unchecked.push(
            "cargo's configuration replaces a source or includes other files (`[source]` or `include` in its config.toml), so installed crates may come from a mirror or a private registry and none was looked up in OSV".to_string(),
        );
    }
    for file in &uv.unreadable {
        inventory.unchecked.push(format!(
            "{} could not be read (not a regular file, closed, too large, not TOML, or not found): it may name a private index, so no Python package mise installed through uv was looked up in OSV",
            text::shown(file)
        ));
    }
    inventory
}

/// The directories of the nodes mise installed under `node`, relative to
/// the root. A link is one of mise's short versions, read under the full
/// one. One more than `MAX_NODES` is taken, to tell that there are more.
fn mise_nodes(root: &Path, node: &str) -> Vec<String> {
    let path = root.join(node);
    if !fs::symlink_metadata(&path).is_ok_and(|metadata| metadata.is_dir()) {
        return Vec::new();
    }
    let Ok(listing) = fs::read_dir(path) else {
        return Vec::new();
    };
    listing
        .flatten()
        .filter(|entry| entry.file_type().is_ok_and(|kind| kind.is_dir()))
        .filter_map(|entry| entry.file_name().into_string().ok())
        .take(MAX_NODES + 1)
        .map(|version| format!("{node}/{version}"))
        .collect()
}

/// What a directory entry is, without following a link.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
enum Entry {
    Directory,
    Link,
    Other,
}

/// Whether a package came from the public registry of its ecosystem.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Source {
    Public,
    /// Another registry or index, an address, git or a local path: its
    /// name may be private.
    Elsewhere,
}

impl Source {
    /// Where what pip or uv installs comes from, by its configuration.
    fn configured(config: &IndexConfig) -> Self {
        if config.other_index {
            Self::Elsewhere
        } else {
            Self::Public
        }
    }
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

/// Where what each tool installs comes from, by its configuration.
#[derive(Clone, Copy, Debug)]
struct Sources {
    pip: Source,
    uv: Source,
    cargo: Source,
}

/// A walk over the places packages are kept, within the limits.
struct Walk<'a> {
    root: &'a Path,
    npm: &'a NpmConfig,
    /// Where what pip installs comes from, by its configuration.
    pip: Source,
    /// The same for uv.
    uv: Source,
    /// Where what cargo records as from crates.io comes from, by cargo's
    /// configuration.
    cargo: Source,
    inventory: Inventory,
    entries: usize,
    /// A limit was reached: nothing more is read.
    full: bool,
    /// A `node_modules` lay deeper than `MAX_NODE_DEPTH`.
    too_deep: bool,
    /// Manifests, directories and environments that could not be read or
    /// named no package.
    unreadable: Vec<String>,
    /// Package directories, environments and directories on the way to
    /// them that are links.
    linked: Vec<String>,
    /// Packages from somewhere other than the public registry.
    elsewhere: Vec<String>,
}

impl<'a> Walk<'a> {
    fn new(root: &'a Path, npm: &'a NpmConfig, sources: Sources) -> Self {
        let Sources { pip, uv, cargo } = sources;
        Self {
            root,
            npm,
            pip,
            uv,
            cargo,
            inventory: Inventory::default(),
            entries: 0,
            full: false,
            too_deep: false,
            unreadable: Vec::new(),
            linked: Vec::new(),
            elsewhere: Vec::new(),
        }
    }

    /// What is at `rel`, without following a link; `None` when nothing is.
    /// A link is said, and so is a path that cannot be looked at.
    fn entry(&mut self, rel: &str) -> Option<Entry> {
        let metadata = match fs::symlink_metadata(self.root.join(rel)) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == io::ErrorKind::NotFound => return None,
            Err(_) => {
                self.unreadable.push(rel.to_string());
                return None;
            }
        };
        Some(if metadata.file_type().is_symlink() {
            self.linked.push(rel.to_string());
            Entry::Link
        } else if metadata.is_dir() {
            Entry::Directory
        } else {
            Entry::Other
        })
    }

    /// The entries of directory `rel`, sorted; none when it does not exist
    /// or is a link (which is said). One that cannot be listed is
    /// unreadable.
    fn list(&mut self, rel: &str) -> Vec<(String, Entry)> {
        // `read_dir` follows a link at the end of the path; the check
        // before it keeps it from doing so (a link swapped in between is
        // a race only a program already running as the user can run).
        if self.full || self.entry(rel) != Some(Entry::Directory) {
            return Vec::new();
        }
        let listing = match fs::read_dir(self.root.join(rel)) {
            Ok(listing) => listing,
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Vec::new(),
            Err(_) => {
                self.unreadable.push(rel.to_string());
                return Vec::new();
            }
        };
        let mut found = Vec::new();
        let mut broken = false;
        for entry in listing {
            if self.entries >= MAX_ENTRIES {
                self.full = true;
                break;
            }
            self.entries += 1;
            let Ok(entry) = entry else {
                broken = true;
                continue;
            };
            let Some(name) = entry.file_name().to_str().map(str::to_string) else {
                broken = true;
                continue;
            };
            // `DirEntry::file_type` does not follow a link.
            let kind = match entry.file_type() {
                Ok(kind) if kind.is_symlink() => Entry::Link,
                Ok(kind) if kind.is_dir() => Entry::Directory,
                Ok(_) => Entry::Other,
                Err(_) => {
                    broken = true;
                    continue;
                }
            };
            found.push((name, kind));
        }
        if broken {
            self.unreadable.push(rel.to_string());
        }
        found.sort();
        found
    }

    /// Takes in one package from `source`, unless its name or version is
    /// no registry's.
    fn add(&mut self, package: Package, manifest: &str, source: Source) {
        if !is_registry_word(&package.name) || !is_registry_word(&package.version) {
            self.unreadable.push(manifest.to_string());
            return;
        }
        if source == Source::Elsewhere {
            self.elsewhere.push(package.name);
            return;
        }
        if self.inventory.installed.len() >= MAX_PACKAGES {
            self.full = true;
            return;
        }
        let name = match package.ecosystem {
            Ecosystem::PyPi => canonical_python_name(&package.name),
            Ecosystem::CratesIo | Ecosystem::Npm | Ecosystem::Go => package.name,
        };
        self.inventory.installed.push(Installed {
            package: Package { name, ..package },
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
            (Some(name), Some(version)) => {
                // npm keeps no hidden lockfile for a global install, and npm
                // 7 and later write `_resolved` no more: where there is none,
                // the registry npm is set to use decides.
                let source = if self.npm.is_public(&name, field("_resolved").as_deref()) {
                    Source::Public
                } else {
                    Source::Elsewhere
                };
                let package = Package {
                    ecosystem: Ecosystem::Npm,
                    name,
                    version,
                };
                self.add(package, &manifest, source);
            }
            _ => self.unreadable.push(manifest),
        }
        let nested = format!("{directory}/node_modules");
        (self.entry(&nested) == Some(Entry::Directory)).then_some(nested)
    }

    /// Every pipx environment under `venvs`.
    fn pipx(&mut self, venvs: &str) {
        for (venv, kind) in self.list(venvs) {
            if self.full {
                return;
            }
            let path = format!("{venvs}/{venv}");
            match kind {
                Entry::Directory if !self.pipx_venv(&path) && !self.full => {
                    self.unreadable.push(path);
                }
                Entry::Link => self.linked.push(path),
                Entry::Directory | Entry::Other => {}
            }
        }
    }

    /// One pipx environment; returns whether it had a `site-packages`.
    fn pipx_venv(&mut self, venv: &str) -> bool {
        // pipx's record keeps the pip arguments each package was installed
        // with; pip also reads a `pip.conf` in the environment.
        let elsewhere = self.records_elsewhere(
            &format!("{venv}/pipx_metadata.json"),
            config::pipx_metadata_other_index,
        ) || self
            .records_elsewhere(&format!("{venv}/pip.conf"), config::pip_file_other_index);
        self.pythons(
            venv,
            if elsewhere {
                Source::Elsewhere
            } else {
                self.pip
            },
        )
    }

    /// One environment uv installed a tool in; returns whether it had a
    /// `site-packages`.
    fn uv_tool(&mut self, env: &str) -> bool {
        let elsewhere = self.records_elsewhere(
            &format!("{env}/uv-receipt.toml"),
            config::uv_receipt_other_index,
        );
        self.pythons(
            env,
            if elsewhere {
                Source::Elsewhere
            } else {
                self.uv
            },
        )
    }

    /// Whether the file `rel`, a record of where packages came from, says
    /// they came from somewhere else. It is read as a configuration file
    /// is, through a link too. One that is not there says nothing; one
    /// that is there and cannot be read counts, and is said.
    fn records_elsewhere(&mut self, rel: &str, elsewhere: fn(&str) -> bool) -> bool {
        match config::read_config(self.root, rel) {
            ConfigFile::Absent => false,
            ConfigFile::Unreadable => {
                self.unreadable.push(rel.to_string());
                true
            }
            ConfigFile::Text(text) => elsewhere(&text),
        }
    }

    /// Every `lib/python*/site-packages` of `environment`, whose packages
    /// came from `source`; returns whether there was one.
    fn pythons(&mut self, environment: &str, source: Source) -> bool {
        let lib = format!("{environment}/lib");
        let mut found = false;
        for (python, kind) in self.list(&lib) {
            if kind == Entry::Directory && python.starts_with("python") {
                let site = format!("{lib}/{python}/site-packages");
                if self.entry(&site) == Some(Entry::Directory) {
                    found = true;
                    self.site_packages(&site, source);
                }
            }
        }
        found
    }

    /// Every package pip recorded in `site`, a `*.dist-info` directory
    /// each. An `*.egg-info` is not read: pip has not written one for an
    /// install in years. One with a `direct_url.json` was installed from an
    /// address or a local directory, not from an index.
    fn site_packages(&mut self, site: &str, source: Source) {
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
            let Some((name, version)) = headers else {
                self.unreadable.push(manifest);
                continue;
            };
            let direct = fs::symlink_metadata(
                self.root
                    .join(manifest.replace("/METADATA", "/direct_url.json")),
            )
            .is_ok();
            let package = Package {
                ecosystem: Ecosystem::PyPi,
                name,
                version,
            };
            let source = if direct { Source::Elsewhere } else { source };
            self.add(package, &manifest, source);
        }
    }

    /// Every crate cargo recorded in `file` (a `.crates2.json`); returns
    /// whether anything is at that path (a link is said, not read).
    fn crates(&mut self, file: &str) -> bool {
        match self.entry(file) {
            None => return false,
            Some(Entry::Link) => return true,
            Some(Entry::Directory) => {
                self.unreadable.push(file.to_string());
                return true;
            }
            Some(Entry::Other) => {}
        }
        let json = read_small_file(&self.root.join(file), MAX_LIST_BYTES)
            .and_then(|text| Json::parse(&text).ok());
        let Some(installs) = json
            .as_ref()
            .and_then(|json| json.get("installs"))
            .and_then(Json::as_object)
        else {
            self.unreadable.push(file.to_string());
            return true;
        };
        let mut odd = false;
        for (key, _) in installs {
            if self.full {
                break;
            }
            let Some((name, version, source)) = crate_key(key) else {
                odd = true;
                continue;
            };
            let package = Package {
                ecosystem: Ecosystem::CratesIo,
                name: name.to_string(),
                version: version.to_string(),
            };
            let source = if CRATES_IO.contains(&source) {
                self.cargo
            } else {
                Source::Elsewhere
            };
            self.add(package, file, source);
        }
        if odd {
            self.unreadable.push(file.to_string());
        }
        true
    }

    /// What mise installed under `installs` through a backend OSV has an
    /// ecosystem for; returns whether a node of mise's is installed.
    fn mise(&mut self, installs: &str) -> bool {
        let mut node = false;
        for (tool, kind) in self.list(installs) {
            // The other backends leave no name and version of a
            // registry's behind (`go:` keeps only the program it built).
            let Some(backend) = Backend::of(&tool) else {
                continue;
            };
            let directory = format!("{installs}/{tool}");
            match kind {
                Entry::Directory => {}
                Entry::Link => {
                    self.linked.push(directory);
                    continue;
                }
                Entry::Other => continue,
            }
            // mise links the short versions (`22`, `latest`) to a full
            // one, which is read under its own name.
            for (version, kind) in self.list(&directory) {
                if self.full {
                    return node;
                }
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
        let found = match backend {
            // Newer mise installs `npm:` tools with aube, in pnpm's layout,
            // with no `lib`: such a tool is said as not read.
            Backend::Node | Backend::Npm => {
                let lib = format!("{directory}/lib");
                let there = self.entry(&lib) == Some(Entry::Directory);
                if there {
                    self.node_modules(&format!("{lib}/node_modules"));
                }
                there
            }
            Backend::Cargo => self.crates(&format!("{directory}/.crates2.json")),
            // mise points pipx's home (`venvs/<package>`) or uv's tool
            // directory (`<package>`) at the install directory.
            Backend::Pipx => {
                let mut found = false;
                for (name, kind) in self.list(directory) {
                    let path = format!("{directory}/{name}");
                    match (name.as_str(), kind) {
                        ("bin", _) | (_, Entry::Link | Entry::Other) => {}
                        ("venvs", Entry::Directory) => {
                            for (venv, kind) in self.list(&path) {
                                if kind == Entry::Directory {
                                    found |= self.pipx_venv(&format!("{path}/{venv}"));
                                }
                            }
                        }
                        (_, Entry::Directory) => found |= self.uv_tool(&path),
                    }
                }
                found
            }
            Backend::Python => {
                let elsewhere = self.records_elsewhere(
                    &format!("{directory}/pip.conf"),
                    config::pip_file_other_index,
                );
                self.pythons(
                    directory,
                    if elsewhere {
                        Source::Elsewhere
                    } else {
                        self.pip
                    },
                )
            }
        };
        if !found && !self.full {
            self.unreadable.push(directory.to_string());
        }
    }

    /// The inventory, with what was left out said.
    fn finish(mut self, npm_runs_scripts: bool) -> Inventory {
        let inventory = &mut self.inventory;
        inventory.npm_runs_scripts = npm_runs_scripts;
        if !self.unreadable.is_empty() {
            inventory.unchecked.push(format!(
                "{} language package manifest(s), director(ies) or environment(s) could not be read or name no package and version, so those packages were not looked up in OSV: {}",
                self.unreadable.len(),
                named(&self.unreadable, "/")
            ));
        }
        if !self.elsewhere.is_empty() {
            inventory.unchecked.push(format!(
                "{} language package(s) are, or may be, from a private registry or another index than the public one, an address, git or a local path, so they were not looked up in OSV (their names may be private) and are not checked: {}",
                self.elsewhere.len(),
                named(&self.elsewhere, "")
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
                "{} linked language package director(ies) or environment(s) were not followed or looked up in OSV (what `npm link` installs is a project of your own): {}",
                self.linked.len(),
                named(&self.linked, "/")
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
        .map(|name| text::shown(&format!("{before}{name}")).into_owned())
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
    use super::{canonical_python_name, crate_key, metadata};

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
}
