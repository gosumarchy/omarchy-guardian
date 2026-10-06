//! Reading pacman's command line: the targets the hook is handed, the
//! parent process's arguments, and the operation and operands they name.

use std::fs;
use std::io::BufRead;
use std::path::{Path, PathBuf};

use super::Operation;
use crate::error::{Error, IoContext};

/// The configuration pacman and `pacman-conf` read when none is named.
const DEFAULT_CONFIG: &str = "/etc/pacman.conf";
pub(super) fn read_targets(input: impl BufRead) -> Result<Vec<String>, Error> {
    let mut targets = Vec::new();
    for line in input.lines() {
        let line = line.at(Path::new("<stdin>"))?;
        let target = line.trim();
        if target.is_empty() {
            continue;
        }
        if !is_valid_package_name(target) {
            return Err(Error::Refused(format!(
                "invalid package target from pacman: {target:?}"
            )));
        }
        targets.push(target.to_string());
    }
    if targets.is_empty() {
        return Err(Error::Refused(
            "pacman hook received no package targets".into(),
        ));
    }
    Ok(targets)
}

/// Pacman package names: alphanumerics and `@._+-`, not starting with `-` or `.`.
pub fn is_valid_package_name(name: &str) -> bool {
    name.chars()
        .next()
        .is_some_and(|first| first.is_ascii_alphanumeric() || "@_+".contains(first))
        && name
            .chars()
            .all(|character| character.is_ascii_alphanumeric() || "@._+-".contains(character))
}

pub(super) fn pacman_argv(pid: u32) -> Result<Vec<String>, Error> {
    let comm_path = PathBuf::from(format!("/proc/{pid}/comm"));
    let comm = fs::read_to_string(&comm_path).at(&comm_path)?;
    if comm.trim_end() != "pacman" {
        return Err(Error::Refused(format!(
            "the hook's parent process is {:?}, not pacman",
            comm.trim_end()
        )));
    }

    let cmdline_path = PathBuf::from(format!("/proc/{pid}/cmdline"));
    let cmdline = fs::read(&cmdline_path).at(&cmdline_path)?;
    split_cmdline(&cmdline)
}

pub(super) fn split_cmdline(cmdline: &[u8]) -> Result<Vec<String>, Error> {
    let body = cmdline.strip_suffix(&[0]).unwrap_or(cmdline);
    body.split(|byte| *byte == 0)
        .map(|argument| {
            String::from_utf8(argument.to_vec())
                .map_err(|_| Error::Refused("pacman was given a non-UTF-8 argument".into()))
        })
        .collect()
}

/// Long options that point pacman at another system, database, cache or
/// configuration than the one Guardian reads: the review would be of the
/// wrong packages, or compare with the wrong installed files.
const REDIRECTING: &[&str] = &[
    "root", "dbpath", "config", "cachedir", "sysroot", "hookdir", "gpgdir",
];
/// Long options whose value is the next argument (or follows `=`).
const VALUED: &[&str] = &[
    "ignore",
    "ignoregroup",
    "overwrite",
    "assume-installed",
    "color",
    "print-format",
    "ask",
    "logfile",
    "arch",
];

/// A pacman command line: the operation and its operands (package names
/// for a sync, archives for an upgrade).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Transaction {
    pub operation: Operation,
    pub operands: Vec<String>,
}

/// Reads pacman's command line. Only sync (`-S`) and upgrade (`-U`)
/// transactions install scriptlets from archives Guardian can locate, and
/// only against the system Guardian itself reads. pacman takes a long
/// option by any unambiguous beginning, so a redirecting or valued one is
/// recognised by its beginning too; an argument that is no option is an
/// operand, whatever it is named.
pub fn parse_transaction(argv: &[String]) -> Result<Transaction, Error> {
    // A script named pacman shows as its interpreter, then itself; after
    // pacman itself, an argument of that name is an operand.
    let named = |index: usize| {
        argv.get(index)
            .is_some_and(|argument| argument.rsplit('/').next() == Some("pacman"))
    };
    let program = usize::from(!named(0) && named(1));
    let redirects = |option: &str| {
        Error::Refused(format!(
            "pacman was given {option}, which points it at another system, database, cache or configuration than the one Guardian reviews against"
        ))
    };
    let begins = |names: &[&str], name: &str| names.iter().any(|known| known.starts_with(name));

    let mut operation = None;
    let mut operands = Vec::new();
    let mut arguments = argv.iter().skip(program + 1);
    while let Some(argument) = arguments.next() {
        if argument == "--" {
            operands.extend(arguments.cloned());
            break;
        }
        if let Some(long) = argument.strip_prefix("--") {
            let (name, value) = long
                .split_once('=')
                .map_or((long, None), |(name, value)| (name, Some(value)));
            match name {
                "sync" => operation = operation.or(Some(Operation::Sync)),
                "upgrade" => operation = operation.or(Some(Operation::LocalUpgrade)),
                // `--print` is an option of its own, not `--print-format`.
                "print" => {}
                // yay names the configuration on every call; the one
                // Guardian reads itself is no redirection.
                _ if name.len() > 1 && "config".starts_with(name) => {
                    let value = value.or_else(|| arguments.next().map(String::as_str));
                    if value != Some(DEFAULT_CONFIG) {
                        return Err(redirects(argument));
                    }
                }
                _ if !name.is_empty() && begins(REDIRECTING, name) => {
                    return Err(redirects(argument));
                }
                _ if !name.is_empty() && begins(VALUED, name) && value.is_none() => {
                    arguments.next();
                }
                _ => {}
            }
        } else if let Some(flags) = argument.strip_prefix('-').filter(|flags| !flags.is_empty()) {
            // `-r` and `-b` are the only short options with a value.
            if flags.contains(['r', 'b']) {
                return Err(redirects(argument));
            }
            if flags.contains('S') {
                operation = operation.or(Some(Operation::Sync));
            } else if flags.contains('U') {
                operation = operation.or(Some(Operation::LocalUpgrade));
            }
        } else {
            operands.push(argument.clone());
        }
    }
    operation
        .map(|operation| Transaction {
            operation,
            operands,
        })
        .ok_or_else(|| {
            Error::Refused(
                "only pacman sync (-S) and upgrade (-U) transactions are supported".into(),
            )
        })
}
