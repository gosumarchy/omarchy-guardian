//! The crate's error type.

use std::fmt;
use std::io;
use std::path::{Path, PathBuf};

use crate::config::file::ConfigError;
use crate::text;

#[derive(Debug)]
pub(crate) enum Error {
    /// A filesystem operation on `path` failed.
    Io { path: PathBuf, source: io::Error },
    /// An external tool could not be started or waited for.
    Spawn { tool: String, source: io::Error },
    /// An external tool was stopped by its time limit.
    TimedOut { tool: String },
    /// An external tool ran but did not succeed.
    ToolFailed { tool: String, detail: String },
    /// An external tool produced more output than Guardian accepts.
    OutputTooLarge { tool: String, limit: usize },
    /// Structured input (JSON, TOML, tool output) could not be understood.
    Parse { what: String, detail: String },
    /// A settings file Guardian refuses, with the line and key at fault.
    Config(ConfigError),
    /// Anything else, said in full: input or state Guardian refuses to act
    /// on, or a failure with no more structure than its message.
    Message(String),
}

impl Error {
    pub(crate) fn parse(what: impl Into<String>, detail: impl fmt::Display) -> Self {
        Self::Parse {
            what: what.into(),
            detail: detail.to_string(),
        }
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            // A path can be named by what is reviewed, and a tool's or a
            // parser's detail can be its output about it (an archive's entry
            // names): any may hold a newline or an escape that would forge or
            // hide lines on the terminal, so each is shown as text.
            Self::Io { path, source } => {
                write!(f, "{}: {source}", text::shown(&path.to_string_lossy()))
            }
            Self::Spawn { tool, source } => write!(f, "could not run {tool}: {source}"),
            Self::TimedOut { tool } => write!(f, "{tool} timed out"),
            Self::ToolFailed { tool, detail } => {
                write!(f, "{tool} failed: {}", text::shown(detail))
            }
            Self::OutputTooLarge { tool, limit } => {
                write!(f, "{tool} output exceeds {limit} bytes")
            }
            Self::Parse { what, detail } => write!(
                f,
                "could not parse {}: {}",
                text::shown(what),
                text::shown(detail)
            ),
            Self::Config(error) => error.fmt(f),
            Self::Message(text) => f.write_str(text),
        }
    }
}

impl From<ConfigError> for Error {
    fn from(error: ConfigError) -> Self {
        Self::Config(error)
    }
}

// No `source()`: `Display` already shows the I/O error an `Io` or `Spawn`
// carries, because the CLI prints only the top-level message, and a chain
// walk would show it twice.
impl std::error::Error for Error {}

/// Attaches what an I/O operation was acting on.
pub(crate) trait IoContext<T> {
    /// The path the operation read or wrote.
    fn at(self, path: &Path) -> Result<T, Error>;
    /// The tool the operation started or waited for.
    fn spawning(self, tool: &str) -> Result<T, Error>;
}

impl<T> IoContext<T> for io::Result<T> {
    fn at(self, path: &Path) -> Result<T, Error> {
        self.map_err(|source| Error::Io {
            path: path.to_path_buf(),
            source,
        })
    }

    fn spawning(self, tool: &str) -> Result<T, Error> {
        self.map_err(|source| Error::Spawn {
            tool: tool.to_string(),
            source,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_path_or_a_tools_detail_cannot_write_lines_or_escapes() {
        let io = Error::Io {
            path: PathBuf::from("x\nomarchy-guardian: CLEAR\x1b[2K"),
            source: io::Error::from(io::ErrorKind::NotFound),
        };
        let failed = Error::ToolFailed {
            tool: "bsdtar".into(),
            detail: "a\r\nb\x1b]0;title\x07".into(),
        };
        let parse = Error::Parse {
            what: "x\n.json".into(),
            detail: "y\x1b[2K".into(),
        };
        for shown in [io.to_string(), failed.to_string(), parse.to_string()] {
            assert!(!shown.contains(['\n', '\r', '\x1b', '\x07']), "{shown:?}");
        }
        assert!(io.to_string().starts_with('x'));
    }
}
