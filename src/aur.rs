//! What the AUR gate knows beyond the recipe: how a makepkg call will use
//! the sources, whether those sources are pinned and verified, what the AUR
//! says about the package, and which upstream files run during the build.
//!
//! Parsing and selection are pure functions; the few steps that touch the
//! network or run makepkg live in `cli::makepkg_gate`.

pub mod lockfile;
pub mod recipe;
mod srcinfo;
mod trust;
mod upstream;

use std::ffi::OsString;

pub use self::srcinfo::{
    Source, base_section, check_listing, check_sources, git_source_url, is_vcs_source,
    parse_srcinfo, source_filename, source_host, source_protocol, written_mismatch,
};
pub use self::trust::{
    AurInfo, TRUST_UNKNOWN, aur_identity, declared_names, is_little_voted, lookalike_search_term,
    lookalikes, parse_rpc_info, parse_rpc_search, trust_signals,
};
pub use self::upstream::{
    Collected, NOT_REVIEWED_DATA, PARTIAL_REVIEW_BYTES, Roots, Upstream, is_target, recipe_runs,
    walk_upstream,
};

#[cfg(test)]
pub use self::trust::plain_name;
#[cfg(test)]
pub use self::upstream::{
    Archive, NOT_REVIEWED_BUDGET, NOT_REVIEWED_LOCKFILE, collect_upstream, unpack_patterns,
};
#[cfg(test)]
use self::upstream::{collect_with_cap, matches_pattern};

/// How one makepkg invocation uses the sources.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Invocation {
    /// Downloads the sources, and (but for generating checksums) runs
    /// PKGBUILD functions on them: `verify()` on every such call,
    /// `pkgver()` whenever it gets past extraction, and prepare, build,
    /// check and package.
    pub runs_functions: bool,
    /// Extracts the sources itself (no `--noextract`, not only verifying).
    pub extracts: bool,
    /// Goes on to use the sources: extracts them, or builds from a tree
    /// extracted earlier (`--noextract`). Only a call that downloads and
    /// stops (to verify, or to generate checksums) does not.
    pub uses_sources: bool,
}

/// Classifies makepkg's arguments. Only calls that print (the source list,
/// the package list, help or the version) touch nothing; generating
/// checksums downloads the sources, and `--verifysource`, `--source` and
/// `--nobuild --noprepare` also run `verify()` and `pkgver()` on what they
/// download.
pub fn classify(args: &[OsString]) -> Invocation {
    let mut info_only = false;
    let mut source_only = false;
    let mut noextract = false;
    // The value of an option that takes one is not an option itself.
    let mut is_value = false;
    for arg in args {
        if std::mem::take(&mut is_value) {
            continue;
        }
        let Some(arg) = arg.to_str() else { continue };
        match arg {
            "--config" | "--key" => is_value = true,
            "--packagelist" | "--printsrcinfo" | "--version" | "--help" => info_only = true,
            "--verifysource" | "--source" | "--allsource" | "--geninteg" => source_only = true,
            "--noextract" => noextract = true,
            _ => {
                if let Some(flags) = arg
                    .strip_prefix('-')
                    .filter(|flags| !flags.starts_with('-'))
                {
                    for (index, flag) in flags.char_indices() {
                        match flag {
                            'V' | 'h' => info_only = true,
                            'S' | 'g' => source_only = true,
                            'e' => noextract = true,
                            // `-p <file>`: the rest of the word is the
                            // file, or the next word is.
                            'p' => {
                                is_value = index + 1 == flags.len();
                                break;
                            }
                            _ => {}
                        }
                    }
                }
            }
        }
    }
    let runs_functions = !info_only;
    Invocation {
        runs_functions,
        extracts: runs_functions && !source_only && !noextract,
        uses_sources: runs_functions && !source_only,
    }
}

/// makepkg's own path variables: a recipe that sets them moves where the
/// sources are extracted or downloaded, past Guardian's review.
const PATH_VARIABLES: &[&str] = &[
    "BUILDDIR",
    "SRCDEST",
    "PKGDEST",
    "SRCPKGDEST",
    "LOGDEST",
    "startdir",
    "srcdir",
    "pkgdir",
    "BUILDFILE",
    "MAKEPKG_CONF",
];

/// Commands that assign to a variable they are given by name.
const ASSIGNING_COMMANDS: &[&str] = &[
    "printf",
    "read",
    "eval",
    "unset",
    "mapfile",
    "readarray",
    "let",
    "declare",
    "typeset",
    "local",
    "export",
    "readonly",
];

/// A line of shell without its comment, and its braces outside quotes: a
/// `#` starts a comment only at the start of a word (`$#` and `${#x}` are
/// not comments), and a brace in a string opens no block.
fn code_and_braces(line: &str) -> (&str, i64) {
    let mut quote = None;
    let mut braces = 0;
    let mut previous = ' ';
    for (index, character) in line.char_indices() {
        match (quote, character) {
            (None, '#') if previous.is_whitespace() => return (&line[..index], braces),
            (None, '\'' | '"') => quote = Some(character),
            (Some(open), _) if open == character => quote = None,
            (None, '{') if previous != '$' => braces += 1,
            (None, '}') => braces -= 1,
            _ => {}
        }
        previous = character;
    }
    (line, braces)
}

/// Top-level assignments (outside any function) to makepkg's path
/// variables, as `line: text`: `NAME=`, or the build or download directory
/// given by name to a command that assigns (`printf -v`, `read`, `eval`,
/// ...). This reads lines, not shell: it names the plain cases before
/// anything runs, and the listing run checks what the recipe really did.
pub fn path_variable_assignments(pkgbuild: &str) -> Vec<String> {
    let mut found = Vec::new();
    let mut depth = 0_i64;
    for (index, line) in pkgbuild.lines().enumerate() {
        let (code, braces) = code_and_braces(line);
        let moved = code.split([';', '&', '|']).any(|statement| {
            let mut words = statement.split_whitespace().peekable();
            let command = words.peek().copied().unwrap_or_default();
            if depth == 0
                && ASSIGNING_COMMANDS.contains(&command)
                && ["BUILDDIR", "SRCDEST"]
                    .iter()
                    .any(|name| names_bare(statement, name))
            {
                return true;
            }
            while let Some(word) = words.peek() {
                if matches!(
                    *word,
                    "export" | "declare" | "typeset" | "readonly" | "local"
                ) || word.starts_with('-')
                {
                    words.next();
                } else {
                    break;
                }
            }
            let word = words.next().unwrap_or_default();
            let name = word.split(['=', '+']).next().unwrap_or_default();
            depth == 0 && word.contains('=') && PATH_VARIABLES.contains(&name)
        });
        if moved {
            found.push(format!("line {}: {}", index + 1, line.trim()));
        }
        // `${x}` closes a brace it did not open here.
        depth = (depth + braces).max(0);
    }
    // The same read as commands, which sees a name through its quoting
    // (`declare BUILD''DIR=/x`) and a command over several lines.
    let names = recipe::Naming {
        set: PATH_VARIABLES,
        given: &["BUILDDIR", "SRCDEST"],
        assigners: ASSIGNING_COMMANDS,
    };
    let lines: Vec<&str> = pkgbuild.lines().collect();
    for line in recipe::top_level_naming(pkgbuild, &names).unwrap_or_default() {
        let text = lines
            .get(line.saturating_sub(1))
            .map_or("", |text| text.trim());
        let entry = format!("line {line}: {text}");
        if !found.contains(&entry) {
            found.push(entry);
        }
    }
    found
}

/// Whether `code` holds `name` as a whole word that is not being expanded
/// (`$NAME`, `${NAME...}`).
fn names_bare(code: &str, name: &str) -> bool {
    let word = |character: char| character.is_ascii_alphanumeric() || character == '_';
    code.match_indices(name).any(|(index, _)| {
        let before = code[..index].chars().next_back();
        let after = code[index + name.len()..].chars().next();
        !before.is_some_and(|character| word(character) || character == '$' || character == '{')
            && !after.is_some_and(word)
    })
}

/// The checksum arrays of a recipe, by makepkg's names.
pub const CHECKSUMS: &[&str] = &[
    "cksums",
    "md5sums",
    "sha1sums",
    "sha224sums",
    "sha256sums",
    "sha384sums",
    "sha512sums",
    "b2sums",
];

/// What a host is named as when its text is not a host name.
const UNPARSEABLE_HOST: &str = "an unparseable host";

/// The part of an address that says where it is fetched from.
struct Authority {
    /// The host as written, lowercased; not yet known to be a host name.
    host: String,
    /// Whether a user part (`user@`) stands before the host: what is
    /// written there can read as a host.
    user: bool,
}

impl Authority {
    /// Reads the authority of an address from just past its `://`. It ends
    /// at a `/`, a `?` or a `#`, so nothing after one is the host. Clients
    /// disagree in a few places, and an authority written that way names no
    /// host: one ends the host at a `\\` and another takes it for part of
    /// the user, the same goes for a `?` or a `#` with an `@` after it, and
    /// for a user part that is more than a name.
    fn of(rest: &str) -> Self {
        let whole = rest.split('/').next().unwrap_or_default();
        let authority = whole.split(['?', '#']).next().unwrap_or_default();
        if whole.contains('\\') || whole[authority.len()..].contains('@') {
            return Self {
                host: String::new(),
                user: true,
            };
        }
        let user = authority.rsplit_once('@');
        // A user part is a name: with a `:`, a `%` or a bracket in it, one
        // program reads the host out of it and another does not.
        let plain = |name: &str| {
            name.chars()
                .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-'))
        };
        if user.is_some_and(|(name, _)| !plain(name)) {
            return Self {
                host: String::new(),
                user: true,
            };
        }
        Self {
            host: user
                .map_or(authority, |(_, host)| host)
                .split(':')
                .next()
                .unwrap_or_default()
                .to_ascii_lowercase(),
            user: user.is_some(),
        }
    }

    /// The host as a validated name, for a person, a remembered answer or
    /// the AI to read.
    fn shown(self) -> String {
        let valid = !self.host.is_empty()
            && self.host.len() <= 253
            && self.host.chars().all(|character| {
                character.is_ascii_alphanumeric() || character == '.' || character == '-'
            });
        if valid {
            self.host
        } else {
            UNPARSEABLE_HOST.into()
        }
    }
}

/// What the AI is told about the recipe it reviews in the AUR gate.
pub const RECIPE_SCOPE: &str = "This is an AUR package recipe: the PKGBUILD, install script, \
patches and other files from the package's AUR repository. The upstream sources it downloads \
are fetched and reviewed separately in the next step, before prepare(), build(), check() and \
package() run. pkgver() and verify() also run on the downloaded sources: report a pkgver() or \
verify() that executes, sources, imports or builds any downloaded file (reading version \
metadata with git, hg or svn commands and checking signatures is routine). Prebuilt binaries or proprietary programs it installs cannot be reviewed by anyone: neither \
their absence nor their being opaque is grounds for inconclusive or a finding by itself. \
Guardian checks and reports itself whether sources are pinned to a commit and verified by a \
checksum; do not report that either. Judge what the recipe itself does: its functions, install \
script and patches, and whether it downloads, runs or installs anything beyond what the \
package needs. Routine packaging is not concerning by itself: installing files into $pkgdir, \
desktop entries, licenses, services and completions, and setuid on the package's own sandbox \
helper.";

/// What the AI is told about upstream files, alongside the facts.
pub const UPSTREAM_SCOPE: &str = "These files are from the upstream source that this AUR package \
downloads and builds (the recipe was reviewed separately). Report only malicious intent, not \
quality. That is: code that runs on this machine during the build (build scripts, makefiles, \
scripts the recipe runs, and the test suite when the recipe runs it) and does something \
harmful, such as downloading or running code the recipe does not declare, writing outside the \
build directory, touching home directories, credentials or keys, or installing persistence; \
or program code with a concealed malicious purpose, such as a backdoor, credential or data \
theft, hidden remote code execution, or an obfuscated payload. Do not report bugs, security \
vulnerabilities, insecure but ordinary practices, test code when the recipe does not run the \
tests, or features that do what the program is for.";

/// Whether a PKGBUILD defines `check()`, which runs the upstream test suite
/// during the build.
pub fn runs_tests(pkgbuild: &str) -> bool {
    defines_function(pkgbuild, "check")
}

/// Whether a PKGBUILD defines the function `name`.
pub fn defines_function(pkgbuild: &str, name: &str) -> bool {
    pkgbuild.lines().any(|line| {
        let line = line.trim_start();
        let line = line.strip_prefix("function ").unwrap_or(line).trim_start();
        line.strip_prefix(name).is_some_and(|rest| {
            rest.trim_start().starts_with("()")
                || rest.starts_with(' ') && rest.trim_start().starts_with('{')
        })
    })
}

#[cfg(test)]
mod tests;
