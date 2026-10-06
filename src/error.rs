//! The crate's error type.

use std::fmt;
use std::io;
use std::path::{Path, PathBuf};

#[derive(Debug)]
pub(crate) enum Error {
    /// A filesystem operation on `path` failed.
    Io { path: PathBuf, source: io::Error },
    /// An external tool could not be started.
    Spawn { tool: String, source: io::Error },
    /// An external tool ran but did not succeed.
    ToolFailed { tool: String, detail: String },
    /// An external tool produced more output than Guardian accepts.
    OutputTooLarge { tool: String, limit: usize },
    /// Structured input (JSON, TOML, tool output) could not be understood.
    Parse { what: String, detail: String },
    /// Input or state that Guardian refuses to act on.
    Refused(String),
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
            Self::Io { path, source } => write!(f, "{}: {source}", path.display()),
            Self::Spawn { tool, source } => write!(f, "could not start {tool}: {source}"),
            Self::ToolFailed { tool, detail } => write!(f, "{tool} failed: {detail}"),
            Self::OutputTooLarge { tool, limit } => {
                write!(f, "{tool} output exceeds {limit} bytes")
            }
            Self::Parse { what, detail } => write!(f, "could not parse {what}: {detail}"),
            Self::Refused(reason) => f.write_str(reason),
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io { source, .. } | Self::Spawn { source, .. } => Some(source),
            Self::ToolFailed { .. }
            | Self::OutputTooLarge { .. }
            | Self::Parse { .. }
            | Self::Refused(_) => None,
        }
    }
}

/// Attaches the path an I/O operation was acting on.
pub(crate) trait IoContext<T> {
    fn at(self, path: &Path) -> Result<T, Error>;
}

impl<T> IoContext<T> for io::Result<T> {
    fn at(self, path: &Path) -> Result<T, Error> {
        self.map_err(|source| Error::Io {
            path: path.to_path_buf(),
            source,
        })
    }
}
