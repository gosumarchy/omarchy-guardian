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
compile_error!("payload.rs hard-codes the open(2) flags of these targets; check them for this one");

#[macro_use]
mod output;

mod agent;
mod ask;
mod audit;
mod aur;
mod autorun;
mod classify;
mod cli;
mod config;
mod content;
mod deps;
mod engine;
mod error;
mod gatewatch;
mod git_state;
mod image;
mod json;
mod layout;
mod makepkg_gate;
mod mask;
mod notify;
mod osv;
mod pacman;
mod payload;
mod permit;
mod report;
mod review;
mod rules;
mod sandbox;
mod scan;
mod setup;
mod sha256;
mod sweep;
#[cfg(test)]
mod test_support;
mod text;
mod tomlish;
mod tools;
mod tui;
#[cfg(test)]
mod zero_deps;

use std::process::ExitCode;

fn main() -> ExitCode {
    cli::run(std::env::args_os().skip(1))
}
