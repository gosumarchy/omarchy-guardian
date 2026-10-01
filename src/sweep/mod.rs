//! The system sweep: what already runs on its own on this machine, and how
//! far each of it can be trusted (see `autorun` for the locations).
//!
//! `index` reads which package installed each file and what pacman recorded
//! for it; `tier` decides from that whether a file is what its package
//! shipped.

#![cfg_attr(
    not(test),
    expect(dead_code, reason = "the sweep command that uses these comes next")
)]

pub mod index;
pub mod tier;
