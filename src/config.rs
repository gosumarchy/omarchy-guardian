//! Settings: built-in profiles, the system and user config files, and how
//! they combine into a per-source-class policy.

pub(crate) mod file;
pub(crate) mod load;
pub(crate) mod model;
mod resolve;
pub(crate) mod show;
pub(crate) mod weaker;
pub(crate) mod write;

pub(crate) use load::Settings;
