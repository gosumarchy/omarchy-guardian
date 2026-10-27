//! Language packages installed outside pacman: global npm packages (the
//! system's and each node mise installed), pipx's environments, crates
//! `cargo install` put in place, and what mise installed through its npm,
//! pipx and cargo backends (see `inventory`). Each installed name and
//! version is looked up in OSV, and only a known-malicious advisory (an ID
//! starting `MAL-`) is a finding: every other advisory is a vulnerability,
//! which is not this check's to report.
//!
//! What goes to OSV is the ecosystem, name and version of every installed
//! package from a public registry, as far as the files tell (see
//! `inventory`), at every sweep, and nothing else. Nothing is kept between
//! sweeps: a package is often found malicious only after it was installed,
//! and asking about all of them each time tells of it the next day. The
//! lookup costs no AI call.
//!
//! What cannot be read or asked about is said as not checked: a lookup that
//! failed is never a clear one. An item stands for one malicious package
//! where it is installed, named by its manifest, ecosystem and name; its
//! text names the version, so a new version is a changed item.
//!
//! Two decisions of the owner's (2026-10-26) govern this module:
//! - A package that may have a private name (from another registry or
//!   index, installed from git, an address or a local path, a crate not
//!   from crates.io, anything under a pip or uv extra index) is never sent
//!   to OSV, as far as the files the tools leave behind tell, and every
//!   sweep says it as not checked. Coverage gives way to that rule. The
//!   files cannot tell these, which are sent like any other package:
//!   - `npm i -g` of git or a tarball, under a name whose registry is the
//!     public one (npm records no source for a global install);
//!   - `pip install --index-url` given on the command line, directly or in
//!     a requirements file named there, into a Python mise installed or a
//!     pipx environment too old to have a record;
//!   - a setting exported in a way the start-up files do not show: by
//!     another program, by a file read in through a path with a variable
//!     other than the home and `OMARCHY_PATH` in it, by a file Hyprland
//!     reads with `source =`, or by a project's own `mise.toml`;
//!   - settings given on a tool's command line, such as `cargo install
//!     --config 'source.crates-io.replace-with=...'`.
//! - `sweep allow` on a package item runs the OSV lookup again: the item
//!   exists only as a result of a lookup, and nothing of OSV's answers is
//!   kept to find it from.

mod aube;
mod config;
mod inventory;
mod startup;

use std::collections::{BTreeMap, BTreeSet, HashMap};

use super::collect::{Body, Item, Origin, Scope};
use super::tier::Tier;
use crate::autorun::Category;
use crate::deps::{Dependency, Ecosystem};
use crate::error::Error;
use crate::osv::{self, Audit};
use crate::rules::RuleId;
use crate::sha256::Sha256;
use config::Places;
use inventory::{Installed, Inventory, Package};
use startup::Startup;

/// The ecosystems the inventory reads, each asked about on its own.
const ECOSYSTEMS: [Ecosystem; 3] = [Ecosystem::Npm, Ecosystem::PyPi, Ecosystem::CratesIo];

/// How the note starts that npm runs install scripts: a fact about the
/// machine, said once (see `sweep::FACTS`).
pub(super) const INSTALL_SCRIPTS: &str = "npm runs install scripts";

/// Asks OSV about one ecosystem's packages (in batches of its own):
/// `osv::query`, or a fake in tests.
type Lookup<'a> = &'a dyn Fn(&[Dependency]) -> Result<Audit, Error>;

/// The IDs of the known-malicious advisories OSV listed, for each package
/// that has one.
type Malicious = BTreeMap<Package, Vec<String>>;

/// What the check found.
#[derive(Debug)]
pub(super) struct Packages {
    /// One item for each malicious package where it is installed.
    pub(super) items: Vec<Item>,
    pub(super) notes: Vec<String>,
    /// What was not checked, each as a sentence (see
    /// `Collection::truncated`).
    pub(super) unchecked: Vec<String>,
}

/// Reads the language packages installed under `scope` and asks OSV about
/// every one of them. Waits on the network for as long as OSV takes; this
/// runs for `sweep allow` too (see the module docs).
pub(super) fn check(scope: &Scope<'_>) -> Packages {
    let places = Places::from_env(scope.home);
    let startup = Startup::read(scope);
    let inventory = inventory::collect(scope.root, &places, &startup);
    look_up(inventory, scope.home, &osv::query)
}

/// Asks `lookup` about the packages of `inventory`, and makes an item of
/// each malicious one.
fn look_up(inventory: Inventory, home: Option<&str>, lookup: Lookup<'_>) -> Packages {
    let mut packages = Packages {
        items: Vec::new(),
        notes: inventory.notes,
        unchecked: inventory.unchecked,
    };
    if inventory.npm_runs_scripts {
        packages.notes.push(format!(
            "{INSTALL_SCRIPTS} for every package it installs, as you and with your files in reach, which is how most malicious npm packages act: `npm config set ignore-scripts true` turns them off (a package that builds native code then needs `npm rebuild <name>`)"
        ));
    }

    let installed: BTreeSet<&Package> = inventory
        .installed
        .iter()
        .map(|installed| &installed.package)
        .collect();
    let mut malicious = Malicious::new();
    for ecosystem in ECOSYSTEMS {
        let of_ecosystem: Vec<&Package> = installed
            .iter()
            .copied()
            .filter(|package| package.ecosystem == ecosystem)
            .collect();
        if !of_ecosystem.is_empty() {
            ask(
                ecosystem,
                &of_ecosystem,
                lookup,
                &mut malicious,
                &mut packages.unchecked,
            );
        }
    }

    for installed in &inventory.installed {
        if let Some(ids) = malicious.get(&installed.package) {
            packages.items.push(item(installed, ids, home));
        }
    }
    packages
}

/// Asks `lookup` about `batch`, the packages of `ecosystem`, and puts what
/// it says in `malicious`. Within one ecosystem a name and version name one
/// package, which is how OSV's advisories are matched to them. A failed
/// lookup leaves every one of them not checked: `osv::query` gives no
/// answer for the batches before the one that failed.
fn ask(
    ecosystem: Ecosystem,
    batch: &[&Package],
    lookup: Lookup<'_>,
    malicious: &mut Malicious,
    unchecked: &mut Vec<String>,
) {
    let ecosystem = ecosystem.osv_name();
    let query: Vec<Dependency> = batch
        .iter()
        .map(|package| Dependency {
            ecosystem: package.ecosystem,
            name: package.name.clone(),
            version: package.version.clone(),
            lockfile: String::new(),
        })
        .collect();
    let audit = match lookup(&query) {
        Ok(audit) => audit,
        Err(error) => {
            unchecked.push(format!(
                "{} {ecosystem} package version(s) were not looked up in OSV ({error}), so whether they are known to be malicious is not checked",
                batch.len()
            ));
            return;
        }
    };
    // The advisories past OSV's first page for a package were not seen:
    // that package is not checked, whatever the first page held.
    for truncated in &audit.truncated {
        unchecked.push(format!(
            "OSV listed more advisories for {ecosystem} package {} {} than one answer holds: the rest were not checked",
            truncated.name, truncated.version
        ));
    }
    let mut by_package: HashMap<(&str, &str), Vec<String>> = HashMap::new();
    for advisory in audit
        .advisories
        .iter()
        .filter(|advisory| is_malicious_id(&advisory.id))
    {
        by_package
            .entry((advisory.package.as_str(), advisory.version.as_str()))
            .or_default()
            .push(advisory.id.clone());
    }
    for package in batch {
        if let Some(ids) = by_package.remove(&(package.name.as_str(), package.version.as_str())) {
            malicious.insert((*package).clone(), ids);
        }
    }
}

/// Whether `id` is a known-malicious advisory's: OSV gives those IDs that
/// start with `MAL-` (the malicious-packages database of the Open Source
/// Security Foundation).
fn is_malicious_id(id: &str) -> bool {
    id.strip_prefix("MAL-").is_some_and(|rest| !rest.is_empty())
}

/// The item of `installed`, which OSV lists as malicious in `ids`.
fn item(installed: &Installed, ids: &[String], home: Option<&str>) -> Item {
    let Package {
        ecosystem,
        name,
        version,
    } = &installed.package;
    let ecosystem = ecosystem.osv_name();
    let text = format!("{ecosystem} {name} {version}");
    let in_home = home.is_some_and(|home| installed.manifest.starts_with(&format!("{home}/")));
    Item {
        origin: if in_home {
            Origin::User
        } else {
            Origin::System
        },
        category: Category::Package,
        path: format!("{}#{ecosystem}:{name}", installed.manifest),
        tier: Tier::Unknown,
        sha256: Some(Sha256::digest(text.as_bytes())),
        body: Body::Text(text),
        runs: Vec::new(),
        run_by: None,
        file: None,
        notes: vec![format!(
            "{ecosystem} package {name} {version}, read from /{}",
            installed.manifest
        )],
        alerts: vec![(
            RuleId::MaliciousPackage,
            format!(
                "OSV lists {name} {version} as malicious: {}",
                ids.join(", ")
            ),
        )],
    }
}

#[cfg(test)]
mod tests;
