//! A plugin's directory as lazy.nvim left it: its files, and what its git
//! directory says, read as files. Git itself never runs: a checkout's
//! configuration can make git run commands.

use std::fs;
use std::io;
use std::path::Path;

use crate::git_state::{self, Reading, without_url_credentials};
use crate::scan::MAX_TEXT_FILE_SIZE;
use crate::sha256::Digest;
use crate::sweep::collect;
use crate::sweep::read::{self, Found};

/// The most plugins looked at. Arbitrary: `LazyVim` with all of its extras
/// installs about 200.
const MAX_PLUGINS: usize = 300;

/// How many directories deep a plugin is looked into. Arbitrary: the
/// deepest of a `LazyVim` install's plugins goes 7 deep.
const MAX_DEPTH: usize = 16;

/// The most entries one plugin may hold before the rest is reported, not
/// read: as for every other location the sweep walks.
const MAX_ENTRIES: usize = read::MAX_ENTRIES;

/// The largest `.git/config` or `.git/HEAD` read. Arbitrary: lazy.nvim
/// writes a few hundred bytes.
const MAX_GIT_FILE: u64 = 64 * 1024;

/// A directory, or what stands in for one, under lazy.nvim's.
#[derive(Debug)]
pub(super) struct Checkout {
    /// Its name, which names the plugin.
    pub(super) name: String,
    /// Relative to the root.
    pub(super) path: String,
    pub(super) shape: Shape,
}

#[derive(Debug)]
pub(super) enum Shape {
    /// A directory: what its git directory says (`None` without one) and
    /// every entry outside it, sorted by path relative to the directory.
    Tree {
        git: Option<Git>,
        files: Vec<(String, Entry)>,
    },
    /// A link where the directory belongs, with its target.
    Link(String),
}

/// An entry of a plugin's directory.
#[derive(Debug)]
pub(super) enum Entry {
    File {
        sha256: Digest,
        /// Permission bits including set-id bits.
        mode: u32,
    },
    Link(String),
}

/// What a plugin's `.git` directory says.
#[derive(Debug)]
pub(super) struct Git {
    pub(super) remote: Remote,
    /// The commit `HEAD` is at.
    pub(super) commit: Option<String>,
    /// What may make git run something that is not a hook: the keys of
    /// its configuration and its submodules' that run a command, every
    /// `core.hooksPath` among them, every entry of a git directory that is
    /// not plain data (see `PLAIN_DATA`), and every git directory or
    /// pointer below the checkout.
    pub(super) runs: Vec<Run>,
    /// The git hooks it holds (every file or link but `*.sample` in
    /// `.git/hooks`, in a `core.hooksPath` within the checkout, and in the
    /// `hooks` of each submodule), by path relative to the plugin, sorted.
    pub(super) hooks: Vec<(String, Entry)>,
}

/// Something in a checkout's git files that may make git run a program.
#[derive(Debug)]
pub(super) struct Run {
    /// Relative to the plugin.
    pub(super) file: String,
    /// The line of a configuration key; `None` for a file or directory.
    pub(super) line: Option<usize>,
    /// The key as `key = value` (URL credentials masked), or what the file
    /// or directory is.
    pub(super) what: String,
    /// The file's content, for the content hash; `None` for a key, whose
    /// text is `what`, for a directory, and for a `.git` below the top of
    /// the checkout, file or directory, whose content the walk of the tree
    /// hashes already.
    pub(super) entry: Option<Entry>,
}

/// Where a checkout fetches from (`remote.origin.url`).
#[derive(Debug)]
pub(super) enum Remote {
    /// The address, without a user or a password.
    Url(String),
    /// `.git/config` names no origin.
    Unnamed,
    /// `.git/config` could not be read, or can be read more than one way
    /// where it names the origin; said as not checked.
    Unread,
}

/// The entries of a git directory that are data git reads and never runs,
/// from gitrepository-layout(5) (permalink:
/// <https://github.com/git/git/blob/v2.47.0/Documentation/gitrepository-layout.txt>).
/// `config`, `config.worktree`, `hooks`, `modules` and `info` are read on
/// their own. Anything else (`commondir`, `gitdir`, `worktrees`,
/// `remotes`, `branches`, a name git may give meaning to later) is a
/// finding: it may point git at another repository, or change what runs.
const PLAIN_DATA: &[&str] = &[
    "objects",
    "refs",
    "HEAD",
    "index",
    "packed-refs",
    "logs",
    "description",
    "FETCH_HEAD",
    "ORIG_HEAD",
    "shallow",
];

/// The entries of `info/` that are plain data: patterns, and the list of
/// refs for dumb transports.
const PLAIN_INFO: &[&str] = &["exclude", "refs", "sparse-checkout"];

/// The most directories looked at under one plugin's `.git/modules`.
/// Arbitrary: submodules nest rarely, and a loop must end.
pub(super) const MAX_MODULE_DIRECTORIES: usize = 256;

/// Every plugin directory under `lazy` (relative to `root`), sorted by
/// name. What cannot be looked at is said in `unchecked`.
pub(super) fn all(root: &Path, lazy: &str, unchecked: &mut Vec<String>) -> Vec<Checkout> {
    let listing = match fs::read_dir(root.join(lazy)) {
        Ok(listing) => listing,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Vec::new(),
        Err(_) => {
            unchecked.push(format!("/{lazy}: could not be listed"));
            return Vec::new();
        }
    };
    let mut names = Vec::new();
    for entry in listing {
        let Ok(entry) = entry else {
            unchecked.push(format!("/{lazy}: could not be listed in full"));
            break;
        };
        let Some(name) = entry.file_name().to_str().map(str::to_string) else {
            let shown = format!("{lazy}/{}", entry.file_name().to_string_lossy());
            unchecked.push(collect::not_utf8(&shown));
            continue;
        };
        // lazy.nvim keeps nothing but plugins there; a plain file is no
        // plugin Neovim loads.
        match entry.file_type() {
            Ok(kind) if kind.is_dir() || kind.is_symlink() => names.push(name),
            Ok(_) => {}
            Err(error) => unchecked.push(format!("/{lazy}/{name}: could not be read ({error})")),
        }
    }
    names.sort();
    if names.len() > MAX_PLUGINS {
        unchecked.push(format!(
            "/{lazy}: more than {MAX_PLUGINS} plugins; the rest were not looked at"
        ));
        names.truncate(MAX_PLUGINS);
    }
    names
        .into_iter()
        .map(|name| checkout(root, lazy, name, unchecked))
        .collect()
}

fn checkout(root: &Path, lazy: &str, name: String, unchecked: &mut Vec<String>) -> Checkout {
    let path = format!("{lazy}/{name}");
    let shape = match read::look(root, &path) {
        Found::Link(target) => {
            unchecked.push(format!(
                "/{path}: a link; the plugin it leads to was not looked at"
            ));
            Shape::Link(target)
        }
        Found::File { .. } | Found::Other | Found::Unreadable(_) => {
            let mut inner = Vec::new();
            let files = walk(root, &path, &mut inner, unchecked);
            Shape::Tree {
                git: git(root, &path, inner, unchecked),
                files,
            }
        }
    };
    Checkout { name, path, shape }
}

/// Every entry under the directory `path` but its top-level `.git`, with no
/// link followed, sorted by path relative to `path`. A `.git` deeper down
/// (a directory, or a file pointing at one) is walked like the rest, and
/// its path is added to `inner`: git may take configuration and hooks from
/// it.
fn walk(
    root: &Path,
    path: &str,
    inner: &mut Vec<String>,
    unchecked: &mut Vec<String>,
) -> Vec<(String, Entry)> {
    let mut entries = Vec::new();
    let mut truncated = false;
    let mut pending = vec![(String::new(), 0_usize)];
    while let Some((directory, depth)) = pending.pop() {
        let full = if directory.is_empty() {
            path.to_string()
        } else {
            format!("{path}/{directory}")
        };
        let Ok(listing) = fs::read_dir(root.join(&full)) else {
            unchecked.push(format!("/{full}: could not be listed"));
            continue;
        };
        for entry in listing {
            let Ok(entry) = entry else {
                unchecked.push(format!("/{full}: could not be listed in full"));
                break;
            };
            let Some(name) = entry.file_name().to_str().map(str::to_string) else {
                let shown = format!("{full}/{}", entry.file_name().to_string_lossy());
                unchecked.push(collect::not_utf8(&shown));
                continue;
            };
            let relative = if directory.is_empty() {
                name
            } else {
                format!("{directory}/{name}")
            };
            if relative == ".git" {
                continue;
            }
            if relative.ends_with("/.git") {
                inner.push(relative.clone());
            }
            let is_directory = entry.file_type().is_ok_and(|kind| kind.is_dir());
            if is_directory && depth + 1 < MAX_DEPTH {
                pending.push((relative, depth + 1));
            } else if is_directory || entries.len() >= MAX_ENTRIES {
                truncated = true;
            } else {
                let found = read::look(root, &format!("{path}/{relative}"));
                match found {
                    Found::File { sha256, mode, .. } => {
                        entries.push((relative, Entry::File { sha256, mode }));
                    }
                    Found::Link(target) => entries.push((relative, Entry::Link(target))),
                    Found::Other => unchecked.push(format!(
                        "/{path}/{relative}: neither a file, a directory nor a link (a FIFO or a device), so it was not looked at"
                    )),
                    Found::Unreadable(reason) => {
                        unchecked.push(format!("/{path}/{relative}: could not be read ({reason})"));
                    }
                }
            }
        }
    }
    if truncated {
        unchecked.push(format!("/{path}: more entries than were looked at"));
    }
    entries.sort_by(|left, right| left.0.cmp(&right.0));
    entries
}

/// What the `.git` directory of the plugin at `path` says; `None` when it
/// has none (a `.git` file or link is no directory lazy.nvim made).
/// `inner` are the git directories and pointers found below the checkout
/// (see `walk`).
///
/// Besides the origin and the commit, that is what may make git run a
/// program when lazy.nvim fetches or checks out: hooks, the keys that run
/// commands in the configuration of the checkout and of each submodule
/// (`.git/modules`), and every entry of those git directories that is not
/// plain data (see `PLAIN_DATA`).
fn git(root: &Path, path: &str, inner: Vec<String>, unchecked: &mut Vec<String>) -> Option<Git> {
    let directory = format!("{path}/.git");
    if !fs::symlink_metadata(root.join(&directory)).is_ok_and(|metadata| metadata.is_dir()) {
        return None;
    }
    let config = text(root, &format!("{directory}/config"), MAX_GIT_FILE);
    let worktree = worktree_config(root, &directory, unchecked);
    let remote = match config
        .as_deref()
        .map(|config| origin(config, worktree.as_deref()))
    {
        Some(Remote::Unread) => {
            unchecked.push(format!(
                "/{directory}/config: the origin is not one url read one way (a continued line, more than one url), so where the plugin is fetched from was not checked"
            ));
            Remote::Unread
        }
        Some(remote) => remote,
        None => {
            unchecked.push(format!(
                "/{directory}/config: could not be read, so where the plugin is fetched from and what it has git run were not checked"
            ));
            Remote::Unread
        }
    };
    let mut gits = Gits {
        root,
        plugin: path,
        runs: Vec::new(),
        hooks: Vec::new(),
        visited: 0,
        unchecked,
    };
    let hooks_path = gits.git_directory(".git", config.as_deref(), worktree.as_deref());
    // A hooks directory within the checkout: git runs its hooks instead.
    if let Some(hooks_path) = hooks_path.filter(|value| git_state::is_in_tree(value)) {
        gits.hooks(hooks_path.trim_end_matches('/'));
    }
    gits.modules(".git/modules", 0);
    let Gits {
        mut runs,
        mut hooks,
        ..
    } = gits;
    runs.extend(inner.into_iter().map(|file| Run {
        file,
        line: None,
        what: "a git directory or pointer below the checkout; git may run its configuration and hooks".into(),
        entry: None,
    }));
    hooks.sort_by(|left, right| left.0.cmp(&right.0));
    Some(Git {
        remote,
        commit: commit(root, &directory),
        runs,
        hooks,
    })
}

/// What the git directories of one plugin say so far.
struct Gits<'a> {
    root: &'a Path,
    /// The plugin's directory, relative to the root; every other path here
    /// is relative to it.
    plugin: &'a str,
    runs: Vec<Run>,
    hooks: Vec<(String, Entry)>,
    /// How many directories under `.git/modules` were looked at.
    visited: usize,
    unchecked: &'a mut Vec<String>,
}

impl Gits<'_> {
    /// Takes in the git directory `git`, whose `config` is `config`
    /// (`None` when it could not be read, which is said already): its
    /// command keys, its hooks, and its entries that are not plain data.
    /// Returns the `core.hooksPath` git uses, if any.
    fn git_directory(
        &mut self,
        git: &str,
        config: Option<&str>,
        worktree: Option<&str>,
    ) -> Option<String> {
        self.layout(git);
        self.hooks(&format!("{git}/hooks"));
        self.settings(git, config, worktree)
    }

    /// Takes in every entry of the git directory `git` that is not plain
    /// data git reads (see `PLAIN_DATA`), or that is of a kind it should
    /// not be, as a run.
    fn layout(&mut self, git: &str) {
        let full = format!("{}/{git}", self.plugin);
        let Ok(listing) = fs::read_dir(self.root.join(&full)) else {
            self.unchecked.push(format!("/{full}: could not be listed"));
            return;
        };
        for entry in listing {
            let Ok(entry) = entry else {
                self.unchecked
                    .push(format!("/{full}: could not be listed in full"));
                break;
            };
            let name = entry.file_name().to_string_lossy().into_owned();
            let kind = entry.file_type().ok();
            let is_dir = kind.is_some_and(|kind| kind.is_dir());
            let is_file = kind.is_some_and(|kind| kind.is_file());
            let expected = match name.as_str() {
                "config" | "config.worktree" => is_file,
                "hooks" | "modules" => is_dir,
                "info" if is_dir => {
                    self.info(&format!("{git}/info"));
                    true
                }
                name => PLAIN_DATA.contains(&name),
            };
            if !expected {
                self.unknown(&format!("{git}/{name}"));
            }
        }
    }

    /// Takes in every entry of `info` but the plain data (`PLAIN_INFO`).
    fn info(&mut self, info: &str) {
        let full = format!("{}/{info}", self.plugin);
        let Ok(listing) = fs::read_dir(self.root.join(&full)) else {
            self.unchecked.push(format!("/{full}: could not be listed"));
            return;
        };
        for entry in listing {
            let Ok(entry) = entry else {
                self.unchecked
                    .push(format!("/{full}: could not be listed in full"));
                break;
            };
            let name = entry.file_name().to_string_lossy().into_owned();
            let is_file = entry.file_type().is_ok_and(|kind| kind.is_file());
            if !(is_file && PLAIN_INFO.contains(&name.as_str())) {
                self.unknown(&format!("{info}/{name}"));
            }
        }
    }

    /// Takes in `file`, an entry of a git directory that is not plain data,
    /// as a run, with its content where it is a file or a link.
    fn unknown(&mut self, file: &str) {
        let full = format!("{}/{file}", self.plugin);
        let (what, entry) = match read::look(self.root, &full) {
            Found::File { sha256, mode, .. } => ("a file", Some(Entry::File { sha256, mode })),
            Found::Link(target) => ("a link", Some(Entry::Link(target))),
            Found::Other => ("a directory or special file", None),
            Found::Unreadable(_) => ("an entry that could not be read", None),
        };
        self.runs.push(Run {
            file: file.to_string(),
            line: None,
            what: format!(
                "{what} git may take configuration, hooks or another repository from (not plain data in a git directory)"
            ),
            entry,
        });
    }

    /// Takes in the hooks in `directory` (see the free `hooks`).
    fn hooks(&mut self, directory: &str) {
        let found = hooks(self.root, self.plugin, directory, self.unchecked);
        self.hooks.extend(found);
    }

    /// Takes in what may make git run something in the configuration of
    /// the git directory `git`: its `config` and its `config.worktree`
    /// (`None` where there is none or it could not be read, which is said
    /// already). Returns the `core.hooksPath` git uses, if it reads one
    /// way.
    fn settings(
        &mut self,
        git: &str,
        config: Option<&str>,
        worktree: Option<&str>,
    ) -> Option<String> {
        let mut hooks_path = None;
        for (file, text) in [
            (format!("{git}/config"), config),
            (format!("{git}/config.worktree"), worktree),
        ] {
            let Some(text) = text else {
                continue;
            };
            // Every hooks path counts here, in the tree or not: a plugin's
            // files are reviewed only once they change.
            let keys = git_state::executing_keys(text).into_iter();
            let keys = keys.filter(|(_, key)| !key.starts_with("core.hookspath "));
            self.runs.extend(keys.map(|(line, what)| Run {
                file: file.clone(),
                line: Some(line),
                what,
                entry: None,
            }));
            for (line, value, reading) in git_state::values(text, "core", None, "hookspath") {
                self.runs.push(Run {
                    file: file.clone(),
                    line: Some(line),
                    what: format!("core.hookspath = {}", without_url_credentials(&value)),
                    entry: None,
                });
                hooks_path = match reading {
                    Reading::Sure => Some(value),
                    Reading::OneOfSeveral => None,
                };
            }
            self.other_remotes(&file, text);
        }
        hooks_path
    }

    /// Takes in, from the configuration `text` of `file`, what may make a
    /// bare `git fetch` (which lazy.nvim runs) fetch from elsewhere than
    /// origin, or move origin's refs: every key of a remote other than
    /// origin, and every `branch.*.remote` other than origin.
    fn other_remotes(&mut self, file: &str, text: &str) {
        let remotes = git_state::section_keys(text, "remote")
            .into_iter()
            .filter(|key| key.subsection.as_deref() != Some("origin"));
        let branches = git_state::section_keys(text, "branch")
            .into_iter()
            .filter(|key| key.key == "remote" && key.value != "origin");
        for found in remotes.chain(branches) {
            let section = if found.key == "remote" {
                "branch"
            } else {
                "remote"
            };
            let name = found.subsection.as_deref().unwrap_or_default();
            let what = format!(
                "{section}.{name}.{} = {} (a bare git fetch may use it)",
                found.key,
                without_url_credentials(&found.value)
            );
            let duplicate = self
                .runs
                .iter()
                .any(|run| run.file == file && run.line == Some(found.line));
            if !duplicate {
                self.runs.push(Run {
                    file: file.to_string(),
                    line: Some(found.line),
                    what,
                    entry: None,
                });
            }
        }
    }

    /// Takes in the submodule git directories under `modules`, `depth`
    /// directories below `.git/modules`: what they say, and what the
    /// submodules they hold in turn say. No link is followed, and at most
    /// `MAX_MODULE_DIRECTORIES` directories are looked at.
    fn modules(&mut self, modules: &str, depth: usize) {
        let full = format!("{}/{modules}", self.plugin);
        match fs::symlink_metadata(self.root.join(&full)) {
            Ok(metadata) if metadata.is_dir() => {}
            Ok(_) => {
                self.unchecked.push(format!(
                    "/{full}: not a directory, so it was not looked into"
                ));
                return;
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => return,
            Err(error) => {
                self.unchecked
                    .push(format!("/{full}: could not be read ({error})"));
                return;
            }
        }
        self.visited += 1;
        if self.visited > MAX_MODULE_DIRECTORIES {
            if self.visited == MAX_MODULE_DIRECTORIES + 1 {
                self.unchecked.push(format!(
                    "/{}/.git/modules: more than {MAX_MODULE_DIRECTORIES} directories; the rest were not looked at",
                    self.plugin
                ));
            }
            return;
        }
        let Ok(listing) = fs::read_dir(self.root.join(&full)) else {
            self.unchecked.push(format!("/{full}: could not be listed"));
            return;
        };
        for entry in listing {
            let Ok(entry) = entry else {
                self.unchecked
                    .push(format!("/{full}: could not be listed in full"));
                break;
            };
            let Some(name) = entry.file_name().to_str().map(str::to_string) else {
                let shown = format!("{full}/{}", entry.file_name().to_string_lossy());
                self.unchecked.push(collect::not_utf8(&shown));
                continue;
            };
            let git = format!("{modules}/{name}");
            match entry.file_type() {
                Ok(kind) if kind.is_dir() => {}
                Ok(kind) if kind.is_symlink() => {
                    self.unchecked.push(format!(
                        "/{}/{git}: a link, which was not followed",
                        self.plugin
                    ));
                    continue;
                }
                Ok(_) | Err(_) => {
                    self.unknown(&git);
                    continue;
                }
            }
            if depth + 1 >= MAX_DEPTH {
                self.unchecked.push(format!(
                    "/{}/{git}: deeper than submodules are looked into",
                    self.plugin
                ));
                continue;
            }
            self.module(&git, depth + 1);
        }
    }

    /// Takes in the directory `git` under `.git/modules`: a submodule's git
    /// directory where it holds a `config`, else a directory of a
    /// submodule name with a `/` in it, which holds more.
    fn module(&mut self, git: &str, depth: usize) {
        let config = format!("{}/{git}/config", self.plugin);
        if fs::symlink_metadata(self.root.join(&config)).is_err() {
            self.modules(git, depth);
            return;
        }
        let text = text(self.root, &config, MAX_GIT_FILE);
        if text.is_none() {
            self.unchecked.push(format!(
                "/{config}: could not be read, so the commands it may have git run were not checked"
            ));
        }
        let directory = format!("{}/{git}", self.plugin);
        let worktree = worktree_config(self.root, &directory, self.unchecked);
        // A submodule's hooks path is relative to its own working tree,
        // which is not looked for: the key is in `runs`, as a finding.
        self.git_directory(git, text.as_deref(), worktree.as_deref());
        self.modules(&format!("{git}/modules"), depth);
    }
}

/// The text of the file at `path`, if it is a plain file of at most
/// `limit` bytes.
fn text(root: &Path, path: &str, limit: u64) -> Option<String> {
    match read::look(root, path) {
        Found::File { size, head, .. } if size <= limit => {
            Some(String::from_utf8_lossy(&head).into_owned())
        }
        Found::File { .. } | Found::Link(_) | Found::Other | Found::Unreadable(_) => None,
    }
}

/// `config.worktree` of the git directory `directory` (relative to the
/// root), which git reads once `extensions.worktreeConfig` is set and
/// which is read whenever it is there; one that cannot be read is said in
/// `unchecked`.
fn worktree_config(root: &Path, directory: &str, unchecked: &mut Vec<String>) -> Option<String> {
    let path = format!("{directory}/config.worktree");
    fs::symlink_metadata(root.join(&path)).ok()?;
    let found = text(root, &path, MAX_GIT_FILE);
    if found.is_none() {
        unchecked.push(format!(
            "/{path}: could not be read, so the commands it may have git run were not checked"
        ));
    }
    found
}

/// Where a checkout whose configuration is `config` and `worktree` (its
/// `config.worktree`, read after it) fetches from: `remote.origin.url`.
/// Unread unless that names exactly one address, read one way: git keeps a
/// list of urls, an empty one clears the list (git 2.46 and later), and
/// which of several readings of a continued line git takes depends on
/// quoting rules this does not repeat.
pub(super) fn origin(config: &str, worktree: Option<&str>) -> Remote {
    let mut urls: Vec<String> = Vec::new();
    for text in std::iter::once(config).chain(worktree) {
        for (_, url, reading) in git_state::values(text, "remote", Some("origin"), "url") {
            if reading == Reading::OneOfSeveral {
                return Remote::Unread;
            }
            if url.is_empty() {
                urls.clear();
            } else {
                urls.push(url);
            }
        }
    }
    match urls.as_slice() {
        [] => Remote::Unnamed,
        [url] => Remote::Url(without_userinfo(url)),
        [_, _, ..] => Remote::Unread,
    }
}

/// The commit the git directory `directory` has checked out: `HEAD` itself
/// (lazy.nvim checks out a commit, not a branch), or the branch it names,
/// as a loose ref or in `packed-refs`.
fn commit(root: &Path, directory: &str) -> Option<String> {
    let head = text(root, &format!("{directory}/HEAD"), MAX_GIT_FILE)?;
    let head = head.trim();
    if is_hash(head) {
        return Some(head.to_ascii_lowercase());
    }
    let reference = head.strip_prefix("ref:")?.trim();
    let plain = reference.starts_with("refs/")
        && reference
            .split('/')
            .all(|part| !part.is_empty() && part != "." && part != "..");
    if !plain {
        return None;
    }
    if let Some(loose) = text(root, &format!("{directory}/{reference}"), MAX_GIT_FILE) {
        let loose = loose.trim();
        return is_hash(loose).then(|| loose.to_ascii_lowercase());
    }
    let packed = text(
        root,
        &format!("{directory}/packed-refs"),
        MAX_TEXT_FILE_SIZE,
    )?;
    packed.lines().find_map(|line| {
        let (hash, name) = line.split_once(' ')?;
        (name.trim() == reference && is_hash(hash)).then(|| hash.to_ascii_lowercase())
    })
}

/// Whether `text` is a git object name: SHA-1 or SHA-256 in hex.
fn is_hash(text: &str) -> bool {
    matches!(text.len(), 40 | 64) && text.chars().all(|c| c.is_ascii_hexdigit())
}

/// The hooks in `hooks`, a directory relative to the plugin at `plugin`:
/// every file or link but the `*.sample` files git puts there, which never
/// run, by path relative to the plugin.
fn hooks(
    root: &Path,
    plugin: &str,
    hooks: &str,
    unchecked: &mut Vec<String>,
) -> Vec<(String, Entry)> {
    let path = format!("{plugin}/{hooks}");
    if fs::symlink_metadata(root.join(&path)).is_ok_and(|metadata| !metadata.is_dir()) {
        unchecked.push(format!(
            "/{path}: not a directory (a link is not followed), so the hooks in it were not checked"
        ));
        return Vec::new();
    }
    let listing = match fs::read_dir(root.join(&path)) {
        Ok(listing) => listing,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Vec::new(),
        Err(_) => {
            unchecked.push(format!("/{path}: could not be listed"));
            return Vec::new();
        }
    };
    let mut found = Vec::new();
    for entry in listing {
        let Ok(entry) = entry else {
            unchecked.push(format!("/{path}: could not be listed in full"));
            break;
        };
        let name = entry.file_name().to_string_lossy().into_owned();
        if name.ends_with(".sample") {
            continue;
        }
        match read::look(root, &format!("{path}/{name}")) {
            Found::File { sha256, mode, .. } => {
                found.push((format!("{hooks}/{name}"), Entry::File { sha256, mode }));
            }
            Found::Link(target) => found.push((format!("{hooks}/{name}"), Entry::Link(target))),
            Found::Other => unchecked.push(format!(
                "/{path}/{name}: neither a file, a directory nor a link (a FIFO or a device), so it was not looked at"
            )),
            Found::Unreadable(reason) => {
                unchecked.push(format!("/{path}/{name}: could not be read ({reason})"));
            }
        }
    }
    found.sort_by(|left, right| left.0.cmp(&right.0));
    found
}

/// `url` without the user and password of an address
/// (`https://user:token@host/x` is `https://host/x`): a token there is
/// nobody's business but git's.
pub(super) fn without_userinfo(url: &str) -> String {
    let Some((scheme, rest)) = url.split_once("://") else {
        return url.to_string();
    };
    let (authority, path) = rest.split_at(rest.find('/').unwrap_or(rest.len()));
    let host = authority
        .rsplit_once('@')
        .map_or(authority, |(_, host)| host);
    format!("{scheme}://{host}{path}")
}

/// Whether the addresses `left` and `right` name the same repository: the
/// same host and path, whatever the scheme, user, case, trailing `/` or
/// `.git` (`git@github.com:a/b` is `https://github.com/a/b.git`).
pub(super) fn same_place(left: &str, right: &str) -> bool {
    place(left) == place(right)
}

/// `url` as `host/path`, lowercased (GitHub names are not case-sensitive).
fn place(url: &str) -> String {
    let url = without_userinfo(url.trim()).to_ascii_lowercase();
    let place = match url.split_once("://") {
        Some((_, rest)) => rest.to_string(),
        // An scp-like address: `user@host:path`.
        None => match url.split_once(':') {
            Some((host, path)) if !host.contains('/') => {
                let host = host.rsplit_once('@').map_or(host, |(_, host)| host);
                format!("{host}/{path}")
            }
            _ => url.clone(),
        },
    };
    let place = place.trim_end_matches('/');
    place
        .strip_suffix(".git")
        .unwrap_or(place)
        .trim_end_matches('/')
        .to_string()
}
