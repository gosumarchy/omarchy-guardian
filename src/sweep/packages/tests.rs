//! Tests of the language package check, against fixture trees and a fake
//! OSV.

use std::cell::RefCell;
use std::fs;
use std::os::unix::fs::symlink;
use std::path::Path;

use super::inventory::{self, Inventory, Package, Places};
use super::{INSTALL_SCRIPTS, Packages, look_up};
use crate::autorun::Category;
use crate::deps::{Dependency, Ecosystem};
use crate::error::Error;
use crate::osv::{Advisory, Audit};
use crate::rules::RuleId;
use crate::sweep::collect::{Body, Origin};
use crate::test_support::TempDir;

const HOME: &str = "home/u";

fn write(root: &Path, path: &str, text: &str) {
    fs::create_dir_all(root.join(path).parent().unwrap()).unwrap();
    fs::write(root.join(path), text).unwrap();
}

fn npm(root: &Path, directory: &str, name: &str, version: &str) {
    write(
        root,
        &format!("{directory}/package.json"),
        &format!(r#"{{"name":"{name}","version":"{version}","scripts":{{}}}}"#),
    );
}

fn python(root: &Path, site: &str, name: &str, version: &str) {
    write(
        root,
        &format!("{site}/{name}-{version}.dist-info/METADATA"),
        &format!("Metadata-Version: 2.1\nName: {name}\nVersion: {version}\n\nlong text\n"),
    );
}

fn crates(root: &Path, file: &str, keys: &[&str]) {
    let installs: Vec<String> = keys.iter().map(|key| format!(r#""{key}":{{}}"#)).collect();
    write(
        root,
        file,
        &format!(r#"{{"installs":{{{}}}}}"#, installs.join(",")),
    );
}

fn found(inventory: &Inventory) -> Vec<(Ecosystem, &str, &str)> {
    let mut found: Vec<_> = inventory
        .installed
        .iter()
        .map(|installed| {
            let package = &installed.package;
            (
                package.ecosystem,
                package.name.as_str(),
                package.version.as_str(),
            )
        })
        .collect();
    found.sort();
    found
}

fn package(ecosystem: Ecosystem, name: &str, version: &str) -> Package {
    Package {
        ecosystem,
        name: name.into(),
        version: version.into(),
    }
}

fn installed_at(manifest: &str, package: Package) -> inventory::Installed {
    inventory::Installed {
        package,
        manifest: manifest.into(),
    }
}

fn inventory_of(installed: Vec<inventory::Installed>) -> Inventory {
    Inventory {
        installed,
        ..Inventory::default()
    }
}

fn advisory(id: &str, name: &str, version: &str) -> Advisory {
    Advisory {
        id: id.into(),
        package: name.into(),
        version: version.into(),
        lockfile: String::new(),
        severity: None,
        summary: None,
    }
}

/// A fake OSV that answers with `advisories`, fails the calls whose
/// number (from 0) is in `failing`, and records every query.
struct FakeOsv {
    advisories: Vec<Advisory>,
    truncated: bool,
    failing: Vec<usize>,
    asked: RefCell<Vec<Vec<String>>>,
}

impl FakeOsv {
    fn new(advisories: Vec<Advisory>) -> Self {
        Self {
            advisories,
            truncated: false,
            failing: Vec::new(),
            asked: RefCell::new(Vec::new()),
        }
    }

    fn lookup(&self, query: &[Dependency]) -> Result<Audit, Error> {
        let call = self.asked.borrow().len();
        self.asked.borrow_mut().push(
            query
                .iter()
                .map(|dependency| {
                    format!(
                        "{} {} {}",
                        dependency.ecosystem.osv_name(),
                        dependency.name,
                        dependency.version
                    )
                })
                .collect(),
        );
        if self.failing.contains(&call) {
            return Err(Error::ToolFailed {
                tool: "curl".into(),
                detail: "could not resolve host".into(),
            });
        }
        Ok(Audit {
            advisories: self
                .advisories
                .iter()
                .filter(|advisory| {
                    query.iter().any(|dependency| {
                        dependency.name == advisory.package
                            && dependency.version == advisory.version
                    })
                })
                .cloned()
                .collect(),
            truncated: self.truncated,
        })
    }

    fn asked(&self) -> Vec<Vec<String>> {
        self.asked.borrow().clone()
    }
}

fn run(osv: &FakeOsv, inventory: Inventory) -> Packages {
    look_up(inventory, Some(HOME), &|query| osv.lookup(query))
}

#[test]
fn global_npm_packages_are_read_with_their_own_dependencies() {
    let root = TempDir::new("packages-npm");
    let root = root.path();
    let top = "usr/lib/node_modules";
    npm(root, &format!("{top}/a"), "a", "1.0.0");
    npm(root, &format!("{top}/a/node_modules/b"), "b", "2.0.0");
    npm(root, &format!("{top}/@scope/c"), "@scope/c", "3.0.0");
    write(root, &format!("{top}/.package-lock.json"), "{}");
    fs::create_dir_all(root.join(format!("{top}/.bin"))).unwrap();
    symlink("/home/u/project", root.join(format!("{top}/linked"))).unwrap();
    write(root, &format!("{top}/broken/package.json"), "{not json");
    npm(root, &format!("{top}/odd"), "odd name", "1.0.0");
    write(
        root,
        &format!("{top}/huge/package.json"),
        &" ".repeat(3 * 1024 * 1024),
    );
    fs::create_dir_all(root.join(format!("{top}/sneaky"))).unwrap();
    symlink(
        "/etc/passwd",
        root.join(format!("{top}/sneaky/package.json")),
    )
    .unwrap();

    let inventory = inventory::collect(root, &Places::defaults(Some(HOME)));

    assert_eq!(
        found(&inventory),
        [
            (Ecosystem::Npm, "@scope/c", "3.0.0"),
            (Ecosystem::Npm, "a", "1.0.0"),
            (Ecosystem::Npm, "b", "2.0.0"),
        ]
    );
    let unchecked = inventory.unchecked.join("\n");
    assert!(
        unchecked.starts_with("4 language package manifest(s)"),
        "{unchecked}"
    );
    assert!(unchecked.contains("/usr/lib/node_modules/broken/package.json"));
    assert!(
        inventory
            .notes
            .iter()
            .any(|note| note.starts_with("1 linked language package(s)")
                && note.contains("/usr/lib/node_modules/linked")),
        "{:?}",
        inventory.notes
    );
    // No npm program and no node of mise's: nothing runs install scripts.
    assert!(!inventory.npm_runs_scripts);
}

#[test]
fn nesting_past_the_limit_is_said() {
    let root = TempDir::new("packages-deep");
    let root = root.path();
    let mut directory = "usr/lib/node_modules".to_string();
    for depth in 0..10 {
        directory = format!("{directory}/p{depth}");
        npm(root, &directory, &format!("p{depth}"), "1.0.0");
        directory.push_str("/node_modules");
    }

    let inventory = inventory::collect(root, &Places::defaults(Some(HOME)));

    assert_eq!(inventory.installed.len(), 8);
    assert!(
        inventory
            .unchecked
            .iter()
            .any(|sentence| sentence.contains("more than 8 node_modules deep")),
        "{:?}",
        inventory.unchecked
    );
}

#[test]
fn pipx_cargo_mise_and_an_npm_prefix_are_read() {
    let root = TempDir::new("packages-tools");
    let root = root.path();
    python(
        root,
        "home/u/.local/share/pipx/venvs/black/lib/python3.12/site-packages",
        "Black_Formatter",
        "24.1.0",
    );
    fs::create_dir_all(root.join("home/u/.local/share/pipx/venvs/empty")).unwrap();
    crates(
        root,
        "home/u/.cargo/.crates2.json",
        &[
            "ripgrep 14.1.0 (registry+https://github.com/rust-lang/crates.io-index)",
            "fd-find 10.0.0 (sparse+https://index.crates.io/)",
            "mine 0.1.0 (git+https://example.com/mine#abc)",
        ],
    );
    let installs = "home/u/.local/share/mise/installs";
    npm(
        root,
        &format!("{installs}/node/22.1.0/lib/node_modules/npm"),
        "npm",
        "10.0.0",
    );
    symlink("22.1.0", root.join(format!("{installs}/node/22"))).unwrap();
    npm(
        root,
        &format!("{installs}/npm-prettier/3.0.0/lib/node_modules/prettier"),
        "prettier",
        "3.0.0",
    );
    crates(
        root,
        &format!("{installs}/cargo-just/1.0.0/.crates2.json"),
        &["just 1.0.0 (registry+https://github.com/rust-lang/crates.io-index)"],
    );
    python(
        root,
        &format!("{installs}/pipx-ruff/0.4.0/venvs/ruff/lib/python3.12/site-packages"),
        "ruff",
        "0.4.0",
    );
    fs::create_dir_all(root.join(format!("{installs}/go/1.22.0"))).unwrap();
    write(
        root,
        "home/u/.npmrc",
        "prefix=~/.npm-global\n//registry.npmjs.org/:_authToken=secret\n",
    );
    npm(root, "home/u/.npm-global/lib/node_modules/d", "d", "4.0.0");

    let inventory = inventory::collect(root, &Places::defaults(Some(HOME)));

    assert_eq!(
        found(&inventory),
        [
            (Ecosystem::CratesIo, "fd-find", "10.0.0"),
            (Ecosystem::CratesIo, "just", "1.0.0"),
            (Ecosystem::CratesIo, "ripgrep", "14.1.0"),
            (Ecosystem::Npm, "d", "4.0.0"),
            (Ecosystem::Npm, "npm", "10.0.0"),
            (Ecosystem::Npm, "prettier", "3.0.0"),
            (Ecosystem::PyPi, "black-formatter", "24.1.0"),
            (Ecosystem::PyPi, "ruff", "0.4.0"),
        ]
    );
    let notes = inventory.notes.join("\n");
    assert!(notes.contains("1 crate(s) installed from git"), "{notes}");
    assert!(
        notes.contains("1 mise tool(s)") && notes.contains("go"),
        "{notes}"
    );
    assert!(!notes.contains("secret"), "{notes}");
    let unchecked = inventory.unchecked.join("\n");
    assert!(
        unchecked.contains("/home/u/.local/share/pipx/venvs/empty"),
        "{unchecked}"
    );
    assert!(!unchecked.contains("secret"), "{unchecked}");
    // mise's node brings npm, and nothing turns install scripts off.
    assert!(inventory.npm_runs_scripts);
}

#[test]
fn the_user_npm_configuration_decides_about_install_scripts() {
    let root = TempDir::new("packages-npmrc");
    let root = root.path();
    write(root, "usr/bin/npm", "");
    let places = Places::defaults(Some(HOME));
    let runs = || inventory::collect(root, &places).npm_runs_scripts;
    assert!(runs());

    write(root, "home/u/.npmrc", "ignore-scripts = true\n");
    assert!(!runs());

    write(root, "etc/npmrc", "ignore-scripts=true\n");
    write(root, "home/u/.npmrc", "ignore-scripts=false\n");
    assert!(runs(), "the user's file wins over the global one");

    write(root, "home/u/.npmrc", "; ignore-scripts=false\n");
    assert!(!runs(), "a comment sets nothing");

    let moved = Places {
        npmrc: Some("home/u/elsewhere/npmrc".into()),
        ..Places::defaults(Some(HOME))
    };
    fs::remove_file(root.join("etc/npmrc")).unwrap();
    write(root, "home/u/elsewhere/npmrc", "ignore-scripts=true\n");
    assert!(!inventory::collect(root, &moved).npm_runs_scripts);
}

#[test]
fn only_malicious_advisories_are_findings() {
    let evil = package(Ecosystem::Npm, "evil", "1.0.0");
    let inventory = inventory_of(vec![
        installed_at("usr/lib/node_modules/evil/package.json", evil.clone()),
        installed_at(
            "home/u/.local/share/mise/installs/node/22.1.0/lib/node_modules/evil/package.json",
            evil,
        ),
        installed_at(
            "usr/lib/node_modules/old/package.json",
            package(Ecosystem::Npm, "old", "0.1.0"),
        ),
        installed_at(
            "home/u/.cargo/.crates2.json",
            package(Ecosystem::CratesIo, "evil", "1.0.0"),
        ),
    ]);
    let osv = FakeOsv::new(vec![
        advisory("MAL-2025-1234", "evil", "1.0.0"),
        advisory("GHSA-aaaa-bbbb-cccc", "old", "0.1.0"),
    ]);

    let packages = run(&osv, inventory);

    // One query per ecosystem, each with its own packages only, and a
    // package installed twice asked about once.
    assert_eq!(
        osv.asked(),
        [
            vec!["npm evil 1.0.0".to_string(), "npm old 0.1.0".to_string()],
            vec!["crates.io evil 1.0.0".to_string()],
        ]
    );
    let labels: Vec<&str> = packages
        .items
        .iter()
        .map(|item| item.path.as_str())
        .collect();
    assert_eq!(
        labels,
        [
            "usr/lib/node_modules/evil/package.json#npm:evil",
            "home/u/.local/share/mise/installs/node/22.1.0/lib/node_modules/evil/package.json#npm:evil",
            "home/u/.cargo/.crates2.json#crates.io:evil",
        ]
    );
    let item = &packages.items[0];
    assert_eq!(item.category, Category::Package);
    assert_eq!(item.origin, Origin::System);
    assert_eq!(packages.items[1].origin, Origin::User);
    assert_eq!(item.body, Body::Text("npm evil 1.0.0".into()));
    assert_eq!(item.alerts.len(), 1);
    assert_eq!(item.alerts[0].0, RuleId::MaliciousPackage);
    assert!(item.alerts[0].1.contains("MAL-2025-1234"));
    assert!(packages.unchecked.is_empty(), "{:?}", packages.unchecked);
}

#[test]
fn every_package_is_asked_about_in_batches_and_a_failed_one_is_not_checked() {
    let installed: Vec<_> = (0..1001)
        .map(|index| {
            installed_at(
                &format!("usr/lib/node_modules/p{index:04}/package.json"),
                package(Ecosystem::Npm, &format!("p{index:04}"), "1.0.0"),
            )
        })
        .collect();
    let mut osv = FakeOsv::new(vec![
        advisory("MAL-2025-1", "p0000", "1.0.0"),
        advisory("MAL-2025-2", "p0999", "1.0.0"),
    ]);
    osv.failing = vec![1];

    let packages = run(&osv, inventory_of(installed));

    let sizes: Vec<usize> = osv.asked().iter().map(Vec::len).collect();
    assert_eq!(sizes, [500, 500, 1]);
    // `p0999` sorts into the second batch, which failed: not listed, and
    // said as not checked; the other batches' answers stand.
    let labels: Vec<&str> = packages
        .items
        .iter()
        .map(|item| item.path.as_str())
        .collect();
    assert_eq!(
        labels,
        ["usr/lib/node_modules/p0000/package.json#npm:p0000"]
    );
    assert_eq!(packages.unchecked.len(), 1, "{:?}", packages.unchecked);
    assert!(packages.unchecked[0].starts_with("500 npm package version(s) were not looked up"));
    assert!(packages.unchecked[0].contains("could not resolve host"));
}

#[test]
fn a_truncated_answer_is_said() {
    let inventory = inventory_of(vec![installed_at(
        "usr/lib/node_modules/a/package.json",
        package(Ecosystem::Npm, "a", "1.0.0"),
    )]);
    let mut osv = FakeOsv::new(vec![advisory("MAL-2025-2", "a", "1.0.0")]);
    osv.truncated = true;

    let packages = run(&osv, inventory);

    assert_eq!(packages.items.len(), 1);
    assert_eq!(packages.unchecked.len(), 1);
    assert!(packages.unchecked[0].contains("more advisories"));
}

#[test]
fn install_scripts_are_noted_once_npm_runs_them() {
    let osv = FakeOsv::new(Vec::new());
    let inventory = Inventory {
        npm_runs_scripts: true,
        ..Inventory::default()
    };

    let packages = run(&osv, inventory);

    assert!(osv.asked().is_empty(), "nothing installed, nothing asked");
    assert_eq!(packages.notes.len(), 1);
    assert!(packages.notes[0].starts_with(INSTALL_SCRIPTS));
    assert!(packages.notes[0].contains("ignore-scripts true"));
}
