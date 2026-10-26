//! Neovim plugins that lazy.nvim installed (`$XDG_DATA_HOME/nvim/lazy/*`,
//! the way `LazyVim`, and so Omarchy, sets Neovim up): code Neovim runs at
//! every start, which lazy.nvim updates from GitHub without a review.
//!
//! Each plugin is one item, listed under its directory. Its content hash
//! covers every file of it outside `.git`, the address it was cloned from,
//! the commit it is at, its git hooks and the keys of its `.git/config`
//! that run commands: what of a checkout runs, or decides what runs. So
//! the sweep's record of what is new or changed, its notifications and
//! `sweep allow` see a change to any of them. The rest of `.git` (objects,
//! the index, logs) changes with every update and runs nothing.
//! What a checkout says is read as files and never by running git: the
//! origin from `.git/config`, the commit from `.git/HEAD` and the refs,
//! and the commit `lazy-lock.json` pins.
//!
//! Trust on first use. A `LazyVim` install holds some 3,500 Lua files: an AI
//! review of all of them on the first sweep would be one very large review,
//! and the local text rules find tens of matches in ordinary plugins (a
//! plugin manager starts shells and fetches from the network). So a sweep
//! that has no record of plugins takes them as they are, and after that the
//! Lua, Vimscript, shell and build files that are new or changed since the
//! record go through the local rules and the AI review like any other text
//! the sweep reviews (see `record`).
//!
//! What a checkout and the specs say is checked on every sweep: a plugin
//! that is no git checkout, whose origin is not where its spec says
//! lazy.nvim fetches it from, or that runs a program when lazy.nvim
//! installs or updates it (a shell build step, a git hook, a git key that
//! runs a command).

mod checkout;
mod record;

pub(super) use record::{Files, Record, plan, settle};

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::env;
use std::fmt::Write as _;
use std::fs;
use std::path::Path;

use super::collect::{self, Body, Item, Origin, Scope};
use super::lua::{self, Build, Spec};
use super::read::{self, Found};
use super::tier::Tier;
use crate::autorun::Category;
use crate::error::Error;
use crate::json::Json;
use crate::paths::file_name;
use crate::rules::RuleId;
use crate::scan::MAX_TEXT_FILE_SIZE;
use crate::sha256::{Digest, Sha256};
use crate::text::shown;
use checkout::{Checkout, Entry, Git, Remote, Shape};

/// The most spec files read, the user's and the ones plugins ship together.
/// Arbitrary: `LazyVim` ships about 150, counting every extra it offers.
const MAX_SPEC_FILES: usize = 2_000;

/// How many hex digits of a commit are shown, as git shows them.
const SHORT_COMMIT: usize = 12;

/// Where Neovim keeps its plugins and its configuration, relative to the
/// root.
#[derive(Debug, PartialEq, Eq)]
pub(super) struct Dirs {
    /// `$XDG_DATA_HOME/nvim/lazy`, where lazy.nvim installs plugins.
    lazy: String,
    /// `$XDG_CONFIG_HOME/nvim`.
    config: String,
    /// The home's `.config/nvim`, which the auto-run catalog lists.
    catalogued: String,
}

impl Dirs {
    /// Neovim's directories for the home `home` (relative to `/`), as the
    /// environment of this sweep sets them.
    pub(super) fn here(home: &str) -> Self {
        let variable = |name| env::var(name).ok();
        Self::new(
            home,
            variable("XDG_DATA_HOME").as_deref(),
            variable("XDG_CONFIG_HOME").as_deref(),
        )
    }

    /// `data_home` and `config_home` count only when they are absolute, as
    /// the XDG Base Directory spec says; otherwise the defaults under the
    /// home stand.
    fn new(home: &str, data_home: Option<&str>, config_home: Option<&str>) -> Self {
        let base = |value: Option<&str>, default: &str| {
            value
                .filter(|value| value.starts_with('/'))
                .and_then(|value| read::normalize(Path::new(value)))
                .filter(|value| !value.is_empty())
                .unwrap_or_else(|| format!("{home}/{default}"))
        };
        Self {
            lazy: format!("{}/nvim/lazy", base(data_home, ".local/share")),
            config: format!("{}/nvim", base(config_home, ".config")),
            catalogued: format!("{home}/.config/nvim"),
        }
    }
}

/// A plugin lazy.nvim installed, as the sweep found it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Plugin {
    /// Its directory name, which is how lazy.nvim and `lazy-lock.json`
    /// name it.
    name: String,
    /// The address its checkout was cloned from, without a user or a
    /// password.
    origin: Option<String>,
    /// The commit its checkout is at.
    commit: Option<String>,
    /// The commit `lazy-lock.json` pins for it.
    locked: Option<String>,
    /// Its code files (Lua, Vimscript, shell and build files) and the
    /// files that run unread (see `runs_unread`), relative to its
    /// directory, with their hashes: what the record keeps, and what is
    /// reviewed, or reported, once it changes.
    code: BTreeMap<String, Digest>,
    /// The paths among `code` that run unread: reported when they change,
    /// never read or sent.
    unread: BTreeSet<String>,
    /// The build steps its specs give.
    builds: Vec<Build>,
    /// What this sweep sends of it to the review (see `plan`).
    pub(crate) review: Review,
}

#[cfg(test)]
impl Plugin {
    /// A plugin named `name` of which only what this sweep sends of it
    /// (`review`) is known, for the tests of judging it.
    pub(crate) fn with_review(name: &str, review: Review) -> Self {
        Self {
            name: name.into(),
            origin: None,
            commit: None,
            locked: None,
            code: BTreeMap::new(),
            unread: BTreeSet::new(),
            builds: Vec::new(),
            review,
        }
    }
}

/// What this sweep sends of a plugin to the review.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum Review {
    /// Not compared with the record: the plugin is trusted, or `plan` did
    /// not run (`sweep allow` collects without it).
    Unplanned,
    /// Taken as it is, without a review: the first sweep that sees
    /// plugins, or one that lost the record.
    Baseline,
    /// Its code files are as recorded.
    Unchanged,
    /// It is new since the record: all its code files, as read now.
    New(Vec<Sent>),
    /// Its code files that are new or changed since the record, as read
    /// now.
    Changed(Vec<Sent>),
    /// More of it is new or changed than one plugin's review takes.
    TooLarge {
        /// How many code files are new or changed.
        files: usize,
    },
}

/// A code file of a plugin as it is sent to the review.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Sent {
    /// Relative to the plugin's directory.
    pub(crate) path: String,
    /// `None` where it could not be read again.
    pub(crate) sha256: Option<Digest>,
    pub(crate) body: Body,
}

/// What `collect` found.
#[derive(Debug, Default)]
pub(super) struct Collected {
    pub(super) items: Vec<Item>,
    /// What was not looked at, each as a sentence.
    pub(super) unchecked: Vec<String>,
    /// What is said of the plugins as a whole (`lazy-lock.json` could not
    /// be read).
    pub(super) notes: Vec<String>,
}

/// Collects the plugins under `dirs.lazy`, and Neovim's own start-up files
/// where `$XDG_CONFIG_HOME` puts them elsewhere than the catalogued
/// `~/.config/nvim`.
pub(super) fn collect(scope: &Scope<'_>, dirs: &Dirs) -> Collected {
    let mut collected = Collected::default();
    let checkouts = checkout::all(scope.root, &dirs.lazy, &mut collected.unchecked);
    let lock = locked(scope.root, &dirs.config, &mut collected.notes);
    let specs = Specs::read(scope.root, dirs, &checkouts, &mut collected.unchecked);
    collected.items = checkouts
        .into_iter()
        .map(|checkout| item(checkout, &specs, &lock))
        .collect();
    if dirs.config != dirs.catalogued {
        let config = config_items(scope, &dirs.config, &mut collected.unchecked);
        collected.items.extend(config);
    }
    collected
}

/// The plugin specs found, by plugin name: the user's and those plugins
/// ship alike.
///
/// Any of them may say where a plugin comes from. Only the user's would
/// keep a plugin's spec from vouching for another plugin's origin, but the
/// user's often lag behind a repository that moved (`LazyVim`'s starter
/// names `williamboman/mason.nvim` in a file that returns early, while
/// `LazyVim` itself names `mason-org/mason.nvim`); and a plugin that ships
/// a spec naming another plugin's origin is itself new or changed, and
/// reviewed, unless the first sweep took it as it was.
#[derive(Debug, Default)]
struct Specs(HashMap<String, Vec<Spec>>);

impl Specs {
    /// Reads the specs of the configuration's Lua files and those the
    /// plugins in `checkouts` ship: `lua/<module>/plugins/` and a top-level
    /// `lazy.lua`, where lazy.nvim looks for them. What of them could not
    /// be read is said in `unchecked`: an origin is then compared with
    /// fewer specs than there are.
    fn read(root: &Path, dirs: &Dirs, checkouts: &[Checkout], unchecked: &mut Vec<String>) -> Self {
        let lua = format!("{}/lua", dirs.config);
        let listing = read::entries(root, &lua);
        if listing.truncated {
            unchecked.push(format!(
                "/{lua}: more entries than were looked at, so the plugin specs in the rest were not checked"
            ));
        }
        unchecked.extend(listing.unreadable.iter().map(|directory| {
            format!("/{directory}: could not be listed, so the plugin specs in it were not checked")
        }));
        unchecked.extend(listing.unnamed.iter().map(|name| collect::not_utf8(name)));
        let init = format!("{}/init.lua", dirs.config);
        let init = fs::symlink_metadata(root.join(&init))
            .is_ok()
            .then_some(init);
        let shipped = checkouts.iter().flat_map(|checkout| {
            let files = match &checkout.shape {
                Shape::Tree { files, .. } => files.as_slice(),
                Shape::Link(_) => &[],
            };
            files
                .iter()
                .filter(|(path, _)| is_shipped_spec(path))
                .map(|(path, _)| format!("{}/{path}", checkout.path))
        });
        let mut paths: Vec<String> = init
            .into_iter()
            .chain(listing.files)
            .filter(|path| read::has_extension(path, "lua"))
            .chain(shipped)
            .collect();
        if paths.len() > MAX_SPEC_FILES {
            unchecked.push(format!(
                "Neovim plugin specs: more than {MAX_SPEC_FILES} files; the rest were not read"
            ));
            paths.truncate(MAX_SPEC_FILES);
        }
        let mut specs = Self::default();
        for path in &paths {
            let text = match spec_text(root, path) {
                Ok(text) => text,
                Err(reason) => {
                    unchecked.push(format!(
                        "/{path}: {reason}, so the plugin specs in it were not checked"
                    ));
                    continue;
                }
            };
            for spec in lua::plugin_specs(&text) {
                specs.0.entry(spec.name.clone()).or_default().push(spec);
            }
        }
        specs
    }

    /// Every spec that names `name`.
    fn of(&self, name: &str) -> &[Spec] {
        self.0.get(name).map_or(&[], Vec::as_slice)
    }

    /// Every build step any spec of `name` gives: lazy.nvim merges a
    /// plugin's specs.
    fn builds(&self, name: &str) -> Vec<Build> {
        let mut builds: Vec<Build> = Vec::new();
        for build in self.of(name).iter().flat_map(|spec| &spec.builds) {
            if !builds.contains(build) {
                builds.push(build.clone());
            }
        }
        builds
    }
}

/// Whether `path`, relative to a plugin, is where lazy.nvim reads specs a
/// plugin ships.
fn is_shipped_spec(path: &str) -> bool {
    let parts: Vec<&str> = path.split('/').collect();
    path == "lazy.lua"
        || (parts.len() >= 4
            && parts[0] == "lua"
            && parts[2] == "plugins"
            && read::has_extension(path, "lua"))
}

/// The text of the spec file at `path`, or why it was not read: it is not
/// a file within the text review limit.
fn spec_text(root: &Path, path: &str) -> Result<String, Error> {
    let why = match read::look(root, path) {
        Found::File { size, head, .. } if size <= MAX_TEXT_FILE_SIZE => {
            return Ok(String::from_utf8_lossy(&head).into_owned());
        }
        Found::File { .. } => "larger than the text review limit".into(),
        Found::Link(_) => "a link, which is not followed".into(),
        Found::Other => "not a file".into(),
        Found::Unreadable(reason) => format!("could not be read ({reason})"),
    };
    Err(Error::Message(why))
}

/// The commit `lazy-lock.json` in `config` pins for each plugin. One that
/// is there and cannot be read is said in `notes`: the commits are then
/// not compared, which leaves nothing unchecked (every file is hashed
/// anyway).
fn locked(root: &Path, config: &str, notes: &mut Vec<String>) -> HashMap<String, String> {
    let path = format!("{config}/lazy-lock.json");
    if fs::symlink_metadata(root.join(&path)).is_err() {
        return HashMap::new();
    }
    let pins = match read::look(root, &path) {
        Found::File { size, head, .. } if size <= MAX_TEXT_FILE_SIZE => {
            let text = String::from_utf8_lossy(&head);
            Json::parse(&text).ok().and_then(|json| pins(&json))
        }
        Found::File { .. } | Found::Link(_) | Found::Other | Found::Unreadable(_) => None,
    };
    pins.unwrap_or_else(|| {
        notes.push(format!(
            "/{path} is not the plain JSON file lazy.nvim writes: the commits it pins are not compared"
        ));
        HashMap::new()
    })
}

/// `{ "<plugin>": { "commit": "<hash>" } }` as plugin to commit.
fn pins(json: &Json) -> Option<HashMap<String, String>> {
    json.as_object()?
        .iter()
        .map(|(name, pin)| {
            let commit = pin.get("commit")?.as_str()?;
            Some((name.clone(), commit.to_string()))
        })
        .collect()
}

/// The item of `checkout`.
fn item(checkout: Checkout, specs: &Specs, lock: &HashMap<String, String>) -> Item {
    let builds = specs.builds(&checkout.name);
    let alerts = alerts(&checkout, specs, &builds);
    let (origin, commit, (code, unread)) = match &checkout.shape {
        Shape::Tree { git, files } => (
            git.as_ref().and_then(|git| match &git.remote {
                Remote::Url(url) => Some(url.clone()),
                Remote::Unnamed | Remote::Unread => None,
            }),
            git.as_ref().and_then(|git| git.commit.clone()),
            code_files(files),
        ),
        Shape::Link(_) => (None, None, (BTreeMap::new(), BTreeSet::new())),
    };
    let plugin = Plugin {
        locked: lock.get(&checkout.name).cloned(),
        name: checkout.name.clone(),
        origin,
        commit,
        code,
        unread,
        builds,
        review: Review::Unplanned,
    };
    let notes = notes(&checkout, &plugin, specs, lock.is_empty());
    let runs = plugin
        .builds
        .iter()
        .filter_map(|build| match build {
            Build::Shell(command) => Some(command.clone()),
            Build::Command(_) | Build::Lua(_) | Build::Computed(_) => None,
        })
        .collect();
    Item {
        origin: Origin::User,
        category: Category::Editor,
        sha256: Some(digest(&checkout)),
        path: checkout.path,
        tier: Tier::Unknown,
        body: Body::Plugin(Box::new(plugin)),
        runs,
        run_by: None,
        file: None,
        notes,
        alerts,
    }
}

/// What the local checks establish about `checkout`, whose specs give it
/// `builds`.
fn alerts(checkout: &Checkout, specs: &Specs, builds: &[Build]) -> Vec<(RuleId, String)> {
    let mut alerts = Vec::new();
    match &checkout.shape {
        Shape::Link(target) => alerts.push((
            RuleId::PluginSource,
            format!(
                "a link to {}, where lazy.nvim keeps a checkout of its own",
                shown(target)
            ),
        )),
        Shape::Tree { git: None, .. } => alerts.push((
            RuleId::PluginSource,
            "no git checkout, which is how lazy.nvim installs every plugin".into(),
        )),
        Shape::Tree { git: Some(git), .. } => git_alerts(&checkout.name, git, specs, &mut alerts),
    }
    for build in builds {
        if let Build::Shell(command) = build {
            alerts.push((
                RuleId::PluginBuild,
                format!(
                    "its spec's build step runs {} at install and update",
                    quoted(std::slice::from_ref(command))
                ),
            ));
        }
    }
    alerts
}

/// What the git directory of the plugin `name` says that is an alert.
fn git_alerts(name: &str, git: &Git, specs: &Specs, alerts: &mut Vec<(RuleId, String)>) {
    match &git.remote {
        Remote::Url(url) => {
            let mut expected: Vec<String> = specs.of(name).iter().map(fetched_from).collect();
            expected.dedup();
            let matched = expected
                .iter()
                .any(|expected| checkout::same_place(expected, url));
            if !expected.is_empty() && !matched {
                alerts.push((
                    RuleId::PluginSource,
                    format!(
                        "its origin is {}, and its spec has lazy.nvim fetch it from {}",
                        shown(url),
                        shown(&expected.join(" or "))
                    ),
                ));
            }
        }
        Remote::Unnamed => alerts.push((
            RuleId::PluginSource,
            "its checkout names no origin to fetch from".into(),
        )),
        // Said as not checked where it was read.
        Remote::Unread => {}
    }
    for (file, line, key) in &git.runs {
        alerts.push((
            RuleId::GitConfigCommand,
            format!(
                "line {line}: .git/{file} runs a command on the git commands lazy.nvim runs: {}",
                shown(key)
            ),
        ));
    }
    for (hook, _) in &git.hooks {
        alerts.push((
            RuleId::PluginBuild,
            format!(
                "git hook {} runs when lazy.nvim installs or updates it",
                shown(hook)
            ),
        ));
    }
}

/// Where lazy.nvim fetches the plugin of `spec` from: an address as given,
/// `owner/repo` from GitHub (lazy.nvim's default `git.url_format`).
fn fetched_from(spec: &Spec) -> String {
    if spec.source.contains("://") || spec.source.starts_with("git@") {
        spec.source.clone()
    } else {
        format!("https://github.com/{}.git", spec.source)
    }
}

/// `commands` as a report note or alert says them: each in backquotes,
/// joined by "or". Never for the facts the AI reads, where a backquote in
/// a command would end the quote and let the rest pass for Guardian's
/// words (see `fact`).
fn quoted(commands: &[String]) -> String {
    commands
        .iter()
        .map(|command| format!("`{}`", shown(command)))
        .collect::<Vec<_>>()
        .join(" or ")
}

/// What is said of `plugin`: where it comes from, how it stands to
/// `lazy-lock.json` (`unlocked` when there is none to compare with), and
/// the build steps that are no alert.
fn notes(checkout: &Checkout, plugin: &Plugin, specs: &Specs, unlocked: bool) -> Vec<String> {
    let mut notes = Vec::new();
    let short = |commit: &str| commit.chars().take(SHORT_COMMIT).collect::<String>();
    let mut from = String::from("a Neovim plugin lazy.nvim installed");
    if let Some(origin) = &plugin.origin {
        let _ = write!(from, " from {origin}");
    }
    if let Some(commit) = &plugin.commit {
        let _ = write!(from, " at commit {}", short(commit));
    }
    notes.push(from);
    match (&plugin.locked, &plugin.commit) {
        (Some(locked), Some(commit)) if locked != commit => notes.push(format!(
            "lazy-lock.json pins commit {}, not the one checked out",
            short(locked)
        )),
        (None, _) if !unlocked => notes.push("lazy-lock.json does not name it".into()),
        _ => {}
    }
    if specs.of(&plugin.name).is_empty() {
        notes.push("no spec found names it (a spec built by code is not read)".into());
    }
    for build in &plugin.builds {
        match build {
            Build::Command(command) => notes.push(format!(
                "its spec's build step runs the Neovim command {}",
                quoted(std::slice::from_ref(command))
            )),
            Build::Lua(strings) if strings.is_empty() => {
                notes.push("its spec's build step is Lua code".into());
            }
            Build::Lua(strings) => notes.push(format!(
                "its spec's build step is Lua code that may run {}",
                quoted(strings)
            )),
            Build::Computed(strings) => {
                let mut note = String::from(
                    "its spec has a field whose key is computed by code, which was not read: it may be a build step",
                );
                if !strings.is_empty() {
                    let _ = write!(note, " that runs {}", quoted(strings));
                }
                notes.push(note);
            }
            Build::Shell(_) => {}
        }
    }
    let build_lua = matches!(&checkout.shape, Shape::Tree { files, .. }
        if files.iter().any(|(path, _)| path == "build.lua"));
    if build_lua {
        notes.push("lazy.nvim runs its build.lua at install and update".into());
    }
    notes
}

/// The code files and the files that run unread among `files`, with their
/// hashes, and the paths of those that run unread.
fn code_files(files: &[(String, Entry)]) -> (BTreeMap<String, Digest>, BTreeSet<String>) {
    let mut code = BTreeMap::new();
    let mut unread = BTreeSet::new();
    for (path, entry) in files {
        let Entry::File { sha256, mode } = entry else {
            continue;
        };
        if runs_unread(path, *mode) {
            unread.insert(path.clone());
        } else if !is_code(path) {
            continue;
        }
        code.insert(path.clone(), *sha256);
    }
    (code, unread)
}

/// File name endings of scripts a plugin may run through another program:
/// Python (`pythonx/`, `python3/`, remote plugins), Node and Deno, Perl and
/// Ruby.
const SCRIPT_EXTENSIONS: &[&str] = &["py", "js", "mjs", "cjs", "ts", "pl", "rb"];

/// Whether the file at `path` of a plugin, with permission bits `mode`, is
/// code that may run and that the review does not read: a native library
/// (a Lua C module, a fuzzy matcher built at install), a file of a remote
/// plugin (`rplugin/`), a script in another language, or any executable
/// file (`bin/`). A change to one is reported, never sent.
fn runs_unread(path: &str, mode: u32) -> bool {
    !is_code(path)
        && (mode & 0o111 != 0
            || path.starts_with("rplugin/")
            || std::iter::once("so")
                .chain(SCRIPT_EXTENSIONS.iter().copied())
                .any(|extension| read::has_extension(path, extension)))
}

/// File name endings of the code files reviewed: Lua, Vimscript, shell and
/// luarocks' build spec.
const CODE_EXTENSIONS: &[&str] = &["lua", "vim", "sh", "bash", "zsh", "rockspec"];

/// Whether the file at `path` of a plugin is code the review reads: Lua,
/// Vimscript, shell, or a build file (a Makefile, a rockspec).
fn is_code(path: &str) -> bool {
    let name = file_name(path);
    matches!(name, "Makefile" | "makefile" | "GNUmakefile")
        || CODE_EXTENSIONS
            .iter()
            .any(|extension| read::has_extension(name, extension))
}

/// The content hash of `checkout` (see the module docs). Fields are
/// separated by NUL, which no path holds.
fn digest(checkout: &Checkout) -> Digest {
    let mut hasher = Sha256::new();
    let entry = |entry: &Entry| match entry {
        Entry::File { sha256, mode } => format!("file\0{sha256}\0{mode:o}"),
        Entry::Link(target) => format!("link\0{target}"),
    };
    match &checkout.shape {
        Shape::Link(target) => hasher.update(format!("link\0{target}").as_bytes()),
        Shape::Tree { git, files } => {
            if let Some(git) = git {
                if let Remote::Url(url) = &git.remote {
                    hasher.update(format!("origin\0{url}\0").as_bytes());
                }
                if let Some(commit) = &git.commit {
                    hasher.update(format!("commit\0{commit}\0").as_bytes());
                }
                for (file, line, key) in &git.runs {
                    hasher.update(format!("runs\0{file}\0{line}\0{key}\0").as_bytes());
                }
                for (name, hook) in &git.hooks {
                    hasher.update(format!("hook\0{name}\0{}\0", entry(hook)).as_bytes());
                }
            }
            for (path, file) in files {
                hasher.update(format!("{path}\0{}\0", entry(file)).as_bytes());
            }
        }
    }
    hasher.finalize()
}

/// Neovim's start-up files in `config` (relative to the root), as the
/// auto-run catalog lists them under `~/.config/nvim`.
fn config_items(scope: &Scope<'_>, config: &str, unchecked: &mut Vec<String>) -> Vec<Item> {
    let mut paths: Vec<String> = ["init.lua", "init.vim"]
        .iter()
        .map(|name| format!("{config}/{name}"))
        .filter(|path| fs::symlink_metadata(scope.root.join(path)).is_ok())
        .collect();
    for directory in ["plugin", "after/plugin", "lua"] {
        let base = format!("{config}/{directory}");
        let listing = read::entries(scope.root, &base);
        if listing.truncated {
            unchecked.push(format!("/{base}: more entries than were looked at"));
        }
        unchecked.extend(listing.unnamed.iter().map(|name| collect::not_utf8(name)));
        // A directory only root can list is one unreadable item.
        paths.extend(listing.unreadable);
        paths.extend(listing.files);
    }
    paths
        .into_iter()
        .map(|path| collect::item(scope, Category::Editor, path, None))
        .collect()
}

/// Why a plugin's files go to the review.
#[derive(Debug, Clone, Copy)]
pub(super) enum News {
    /// It is new since the record: all its code files go.
    New,
    /// It changed since the record: its new or changed code files go.
    Changed,
}

/// What Guardian established about `plugin`, listed as `label`, for the AI
/// review of its files, which go for `news`. Every string that comes from
/// the plugin is written as a Rust string literal (`{:?}`), which escapes
/// any quote in it, so a crafted one cannot pose as Guardian's words.
pub(super) fn fact(plugin: &Plugin, label: &str, news: News) -> String {
    let mut text = format!(
        "{:?} is a Neovim plugin lazy.nvim installed",
        shown(label).as_ref()
    );
    if let Some(origin) = &plugin.origin {
        let _ = write!(text, " from {:?}", shown(origin).as_ref());
    }
    if let Some(commit) = &plugin.commit {
        let _ = write!(text, " at commit {:?}", shown(commit).as_ref());
    }
    text.push_str("; Neovim runs it when the editor starts.");
    text.push_str(match news {
        News::New => {
            " It is new since the last sweep: all its Lua, Vimscript, shell and build files are sent."
        }
        News::Changed => {
            " Only its Lua, Vimscript, shell and build files that are new or changed since the last review are sent; the rest of it was there before."
        }
    });
    text.push_str(" Its other files (documentation, data, compiled libraries) are not sent.");
    for build in &plugin.builds {
        let _ = match build {
            Build::Shell(command) => write!(
                text,
                " Its spec's build step runs {:?} in a shell when lazy.nvim installs or updates it.",
                shown(command).as_ref()
            ),
            Build::Command(command) => write!(
                text,
                " Its spec's build step runs the Neovim command {:?}.",
                shown(command).as_ref()
            ),
            Build::Lua(strings) if strings.is_empty() => {
                write!(text, " Its spec's build step is Lua code.")
            }
            Build::Lua(strings) => write!(
                text,
                " Its spec's build step is Lua code that may run {} when lazy.nvim installs or updates it.",
                literals(strings)
            ),
            Build::Computed(strings) if strings.is_empty() => write!(
                text,
                " Its spec has a field whose key is computed by code: it may be a build step."
            ),
            Build::Computed(strings) => write!(
                text,
                " Its spec has a field whose key is computed by code: it may be a build step that runs {}.",
                literals(strings)
            ),
        };
    }
    text
}

/// `strings` as the facts the AI reads say them: each as a string literal,
/// joined by "or".
fn literals(strings: &[String]) -> String {
    strings
        .iter()
        .map(|string| format!("{:?}", shown(string).as_ref()))
        .collect::<Vec<_>>()
        .join(" or ")
}

#[cfg(test)]
mod tests;
