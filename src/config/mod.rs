//! Settings: built-in profiles, the system and user config files, and how
//! they combine into a per-source-class policy.

pub mod file;
pub mod load;
pub mod model;
pub mod resolve;
pub mod show;
pub mod write;

pub use load::Settings;
