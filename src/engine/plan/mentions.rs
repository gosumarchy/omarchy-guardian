//! What the reviewed text names: the file names, stems, directories and
//! globs a file mentions, and matching a path against them.

use std::collections::{HashMap, HashSet};

use crate::paths::file_name;

/// The shortest file name looked for in the changed files.
const MIN_NAMED: usize = 5;

/// A file name without its extension, as code names a module (`import
/// helper` for `helper.py`).
fn stem(name: &str) -> Option<&str> {
    name.rsplit_once('.')
        .map(|(stem, _)| stem)
        .filter(|stem| !stem.is_empty())
}

/// The directory a path is in; empty at the top level.
pub(super) fn directory(path: &str) -> &str {
    path.rsplit_once('/').map_or("", |(directory, _)| directory)
}

/// A directory or a glob written in a text: `hooks.d/*`, `tests/*.dat`,
/// `for f in dir/`, or a bare `*.sh` beside the file that says it.
struct Glob<'a> {
    /// The directory as written, without `.` parts; empty for a bare glob.
    directory: String,
    /// What the file name must match; `*` for a directory named alone.
    pattern: &'a str,
    /// The directory of the file that wrote it.
    from: &'a str,
}

/// What texts say about other files: the words, path parts and globs in
/// them. A file is named by its name or module name as a word, by its
/// name as a part of something written as a path, or by a directory or
/// glob that covers it.
#[derive(Default)]
pub(super) struct Mentions<'a> {
    words: HashSet<&'a str>,
    parts: HashSet<&'a str>,
    /// By the last directory a glob names; under the empty key, the ones
    /// that name none.
    globs: HashMap<&'a str, Vec<Glob<'a>>>,
}

impl<'a> Mentions<'a> {
    /// Adds what `text`, a file in directory `from`, mentions.
    pub(super) fn add(&mut self, from: &'a str, text: &'a str) {
        for token in text.split(|character: char| {
            !(character.is_alphanumeric()
                || matches!(character, '.' | '_' | '-' | '+' | '/' | '*' | '?'))
        }) {
            if !token.contains(['/', '*', '?']) {
                self.word(token);
                continue;
            }
            let mut parts: Vec<&str> = token
                .split('/')
                .filter(|part| !part.is_empty() && *part != ".")
                .collect();
            let Some(&last) = parts.last() else {
                continue;
            };
            if last.contains(['*', '?']) {
                parts.pop();
                // A lone `*` is multiplication more often than a glob.
                if !parts.is_empty() || last.chars().any(char::is_alphanumeric) {
                    self.glob(&parts, last, from);
                }
            } else if token.ends_with('/') {
                self.glob(&parts, "*", from);
            }
            for part in parts {
                if !part.contains(['*', '?']) {
                    self.parts.insert(part);
                    self.word(part);
                }
            }
        }
    }

    /// As written, without what may only end a sentence (`see
    /// payload.c.`), and each part between dots (`pkg.helper`).
    fn word(&mut self, word: &'a str) {
        if word.is_empty() {
            return;
        }
        self.words.insert(word);
        self.words.insert(word.trim_end_matches(['.', '-', '+']));
        self.words
            .extend(word.split('.').filter(|part| !part.is_empty()));
    }

    fn glob(&mut self, directory: &[&'a str], pattern: &'a str, from: &'a str) {
        self.globs
            .entry(directory.last().copied().unwrap_or_default())
            .or_default()
            .push(Glob {
                directory: directory.join("/"),
                pattern,
                from,
            });
    }

    /// Whether the texts name the file at `path`. A short name without an
    /// extension (`run`, `x`) is a word in too many places: it counts only
    /// as a part of something written as a path (`build-aux/run`).
    pub(super) fn names(&self, path: &str) -> bool {
        let name = file_name(path);
        let stem = stem(name);
        if self.parts.contains(name)
            || (self.words.contains(name) && (stem.is_some() || name.len() >= MIN_NAMED))
            || stem.is_some_and(|stem| stem.len() >= MIN_NAMED && self.words.contains(stem))
        {
            return true;
        }
        let parent = directory(path);
        let beside = self
            .globs
            .get("")
            .into_iter()
            .flatten()
            .filter(|glob| glob.from == parent);
        // Written from anywhere: `tests/*.dat` is `$srcdir/tests/*.dat`.
        let under = self
            .globs
            .get(file_name(parent))
            .into_iter()
            .flatten()
            .filter(|glob| {
                !glob.directory.is_empty()
                    && parent
                        .strip_suffix(glob.directory.as_str())
                        .is_some_and(|above| above.is_empty() || above.ends_with('/'))
            });
        beside
            .chain(under)
            .any(|glob| glob_matches(glob.pattern, name))
    }
}

/// Whether `name` matches a shell pattern of literal characters, `*` and
/// `?`.
pub(crate) fn glob_matches(pattern: &str, name: &str) -> bool {
    let pattern: Vec<char> = pattern.chars().collect();
    let name: Vec<char> = name.chars().collect();
    let (mut at, mut seen) = (0, 0);
    // Where the last `*` was, and how much of the name it has taken.
    let mut star: Option<(usize, usize)> = None;
    while seen < name.len() {
        match pattern.get(at) {
            Some('*') => {
                star = Some((at, seen));
                at += 1;
            }
            Some(&character) if character == '?' || character == name[seen] => {
                at += 1;
                seen += 1;
            }
            _ => {
                let Some((star_at, taken)) = star else {
                    return false;
                };
                star = Some((star_at, taken + 1));
                at = star_at + 1;
                seen = taken + 1;
            }
        }
    }
    pattern[at..].iter().all(|character| *character == '*')
}

/// Which of `names` the texts hold as a word: a file name they mention.
pub(super) fn named_in<'a>(
    names: &HashSet<&'a str>,
    texts: &mut dyn Iterator<Item = &str>,
) -> HashSet<&'a str> {
    let mut found = HashSet::new();
    if names.is_empty() {
        return found;
    }
    for text in texts {
        for word in text.split(|character: char| {
            !(character.is_alphanumeric() || matches!(character, '.' | '_' | '-' | '+'))
        }) {
            // As written, without what may only end a sentence (`see
            // payload.c.`), and each part between dots (`pkg.helper`).
            for candidate in [word, word.trim_end_matches(['.', '-', '+'])]
                .into_iter()
                .chain(word.split('.'))
            {
                if let Some(name) = names.get(candidate) {
                    found.insert(*name);
                }
            }
        }
    }
    found
}
