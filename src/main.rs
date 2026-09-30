//! Omarchy Guardian reviews downloaded source, AUR build directories, pacman
//! install scriptlets and Omarchy themes before they run.
//!
//! It combines local heuristics, an OSV dependency audit and a tool-less
//! OpenCode review, and gates commands on a clear result plus an unchanged
//! SHA-256 snapshot of what was reviewed.

#[cfg(not(target_os = "linux"))]
compile_error!("omarchy-guardian is a Linux (Arch Linux / Omarchy) application");

#[cfg(not(any(
    target_arch = "x86_64",
    target_arch = "aarch64",
    target_arch = "arm",
    target_arch = "riscv64"
)))]
compile_error!("scan.rs hard-codes O_NONBLOCK for the generic Linux ABI; check it for this target");

mod agent;
mod classify;
mod cli;
mod config;
mod deps;
mod engine;
mod error;
mod json;
mod osv;
mod pacman;
mod report;
mod review;
mod rules;
mod sandbox;
mod scan;
mod setup;
mod sha256;
#[cfg(test)]
mod test_support;
mod tomlish;
mod tools;
#[cfg(test)]
mod zero_deps;

use std::process::ExitCode;

fn main() -> ExitCode {
    cli::run(std::env::args_os().skip(1))
}
