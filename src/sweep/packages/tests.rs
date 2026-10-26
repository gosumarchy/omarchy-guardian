//! Tests of the language package check, against fixture trees and a fake
//! OSV.

use std::cell::RefCell;
use std::fs;
use std::os::unix::fs::symlink;
use std::path::Path;

use super::config::Places;
use super::inventory::{self, Inventory, Package};
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
            truncated: if self.truncated {
                query.to_vec()
            } else {
                Vec::new()
            },
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
            .any(|note| note.starts_with("1 linked language package")
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
    // mise's Go leaves no package behind, and is not named every sweep.
    assert!(inventory.notes.is_empty(), "{:?}", inventory.notes);
    let unchecked = inventory.unchecked.join("\n");
    assert!(
        unchecked.contains("/home/u/.local/share/pipx/venvs/empty"),
        "{unchecked}"
    );
    assert!(
        unchecked.contains("1 language package(s) are, or may be, from a private registry")
            && unchecked.contains("mine"),
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

    // The environment wins over every file.
    let from_env = |value: &str| Places {
        npm_env: vec![("ignore-scripts".into(), value.into())],
        ..Places::defaults(Some(HOME))
    };
    assert!(inventory::collect(root, &from_env("false")).npm_runs_scripts);
    write(root, "home/u/.npmrc", "ignore-scripts=false\n");
    assert!(!inventory::collect(root, &from_env("true")).npm_runs_scripts);
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
fn a_failed_lookup_leaves_its_ecosystem_not_checked() {
    let mut installed: Vec<_> = (0..1001)
        .map(|index| {
            installed_at(
                &format!("usr/lib/node_modules/p{index:04}/package.json"),
                package(Ecosystem::Npm, &format!("p{index:04}"), "1.0.0"),
            )
        })
        .collect();
    installed.push(installed_at(
        "home/u/.cargo/.crates2.json",
        package(Ecosystem::CratesIo, "evil", "1.0.0"),
    ));
    let mut osv = FakeOsv::new(vec![
        advisory("MAL-2025-1", "p0000", "1.0.0"),
        advisory("MAL-2025-2", "evil", "1.0.0"),
    ]);
    osv.failing = vec![0];

    let packages = run(&osv, inventory_of(installed));

    // One lookup per ecosystem, which batches on its own.
    let sizes: Vec<usize> = osv.asked().iter().map(Vec::len).collect();
    assert_eq!(sizes, [1001, 1]);
    // The npm lookup failed: nothing of it is listed, every one of its
    // packages is said as not checked, and the crates' answer stands.
    let labels: Vec<&str> = packages
        .items
        .iter()
        .map(|item| item.path.as_str())
        .collect();
    assert_eq!(labels, ["home/u/.cargo/.crates2.json#crates.io:evil"]);
    assert_eq!(packages.unchecked.len(), 1, "{:?}", packages.unchecked);
    assert!(packages.unchecked[0].starts_with("1001 npm package version(s) were not looked up"));
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
    assert!(
        packages.unchecked[0].contains("more advisories for npm package a 1.0.0"),
        "{:?}",
        packages.unchecked
    );
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

#[test]
fn links_on_the_way_to_packages_are_said_and_not_followed() {
    let root = TempDir::new("packages-links");
    let root = root.path();
    let elsewhere = root.join("elsewhere");
    npm(root, "elsewhere/lib/node_modules/hidden", "hidden", "1.0.0");
    python(root, "elsewhere/site", "planted", "1.0.0");
    let installs = "home/u/.local/share/mise/installs";
    fs::create_dir_all(root.join(format!("{installs}/node/22.1.0/lib"))).unwrap();
    symlink(
        elsewhere.join("lib/node_modules"),
        root.join(format!("{installs}/node/22.1.0/lib/node_modules")),
    )
    .unwrap();
    let python_lib = "home/u/.local/share/pipx/venvs/tool/lib/python3.12";
    fs::create_dir_all(root.join(python_lib)).unwrap();
    symlink(
        elsewhere.join("site"),
        root.join(format!("{python_lib}/site-packages")),
    )
    .unwrap();
    let scope = "usr/lib/node_modules/@scope";
    fs::create_dir_all(root.join(scope)).unwrap();
    symlink(
        elsewhere.join("lib/node_modules/hidden"),
        root.join(format!("{scope}/x")),
    )
    .unwrap();

    let inventory = inventory::collect(root, &Places::defaults(Some(HOME)));

    assert_eq!(found(&inventory), []);
    let notes = inventory.notes.join("\n");
    assert!(notes.starts_with("3 linked language package"), "{notes}");
    assert!(notes.contains("/usr/lib/node_modules/@scope/x"), "{notes}");
}

#[test]
fn a_directory_that_cannot_be_listed_is_not_checked() {
    use std::os::unix::fs::PermissionsExt as _;
    let root = TempDir::new("packages-closed");
    let root = root.path();
    let closed = root.join("usr/lib/node_modules/closed");
    npm(
        root,
        "usr/lib/node_modules/closed/node_modules/x",
        "x",
        "1.0.0",
    );
    npm(root, "usr/lib/node_modules/closed", "closed", "1.0.0");
    let nested = closed.join("node_modules");
    fs::set_permissions(&nested, fs::Permissions::from_mode(0o000)).unwrap();
    // Root reads what it likes: there is nothing to test as root.
    let readable = fs::read_dir(&nested).is_ok();

    let inventory = inventory::collect(root, &Places::defaults(Some(HOME)));
    fs::set_permissions(&nested, fs::Permissions::from_mode(0o755)).unwrap();

    if readable {
        return;
    }
    assert_eq!(found(&inventory), [(Ecosystem::Npm, "closed", "1.0.0")]);
    let unchecked = inventory.unchecked.join("\n");
    assert!(
        unchecked.contains("/usr/lib/node_modules/closed/node_modules"),
        "{unchecked}"
    );
}

#[test]
fn more_packages_than_the_limit_are_said() {
    let root = TempDir::new("packages-limit");
    let root = root.path();
    let keys: Vec<String> = (0..20_001)
        .map(|index| {
            format!("c{index} 1.0.0 (registry+https://github.com/rust-lang/crates.io-index)")
        })
        .collect();
    let keys: Vec<&str> = keys.iter().map(String::as_str).collect();
    crates(root, "home/u/.cargo/.crates2.json", &keys);

    let inventory = inventory::collect(root, &Places::defaults(Some(HOME)));

    assert_eq!(inventory.installed.len(), 20_000);
    assert!(
        inventory
            .unchecked
            .iter()
            .any(|sentence| sentence.starts_with("more than 20000 language packages")),
        "{:?}",
        inventory.unchecked
    );
}

#[test]
fn mises_python_and_private_sources_are_told_apart() {
    let root = TempDir::new("packages-private");
    let root = root.path();
    let installs = "home/u/.local/share/mise/installs";
    let site = format!("{installs}/python/3.12.1/lib/python3.12/site-packages");
    python(root, &site, "requests", "2.31.0");
    python(root, &site, "inhouse", "1.0.0");
    write(
        root,
        &format!("{site}/inhouse-1.0.0.dist-info/direct_url.json"),
        r#"{"url":"file:///src/inhouse"}"#,
    );
    let top = "usr/lib/node_modules";
    npm(root, &format!("{top}/tool"), "tool", "1.0.0");
    write(
        root,
        &format!("{top}/old/package.json"),
        r#"{"name":"old","version":"1.0.0","_resolved":"git+ssh://git@example.com/old.git"}"#,
    );
    write(
        root,
        "home/u/.npmrc",
        "@corp:registry=https://npm.corp.example/\n",
    );
    npm(root, &format!("{top}/@corp/cli"), "@corp/cli", "2.0.0");
    let pipx = "home/u/.local/share/pipx/venvs/mirrored";
    python(
        root,
        &format!("{pipx}/lib/python3.12/site-packages"),
        "mirrored",
        "1.0.0",
    );
    write(
        root,
        &format!("{pipx}/pipx_metadata.json"),
        r#"{"main_package":{"pip_args":["--index-url","https://pypi.corp.example/simple"]}}"#,
    );

    let inventory = inventory::collect(root, &Places::defaults(Some(HOME)));

    assert_eq!(
        found(&inventory),
        [
            (Ecosystem::Npm, "tool", "1.0.0"),
            (Ecosystem::PyPi, "requests", "2.31.0"),
        ]
    );
    let unchecked = inventory.unchecked.join("\n");
    assert!(
        unchecked.starts_with("4 language package(s) are, or may be, from a private registry"),
        "{unchecked}"
    );

    // An index of pip's own other than PyPI keeps every Python package out.
    write(
        root,
        "home/u/.config/pip/pip.conf",
        "[global]\nindex-url = https://pypi.corp.example/simple\n",
    );
    let inventory = inventory::collect(root, &Places::defaults(Some(HOME)));
    assert!(
        found(&inventory)
            .iter()
            .all(|(ecosystem, ..)| *ecosystem == Ecosystem::Npm)
    );

    // So does one written on the line after its key, which reads as empty.
    for conf in [
        "[global]\nextra-index-url =\n    https://pypi.corp.example/simple\n",
        "[global]\nfind-links =\n    /srv/wheels\n",
    ] {
        write(root, "home/u/.config/pip/pip.conf", conf);
        let inventory = inventory::collect(root, &Places::defaults(Some(HOME)));
        assert!(
            found(&inventory)
                .iter()
                .all(|(ecosystem, ..)| *ecosystem == Ecosystem::Npm),
            "{conf}"
        );
    }
}

#[test]
fn a_linked_lib_is_not_followed() {
    let root = TempDir::new("packages-linked-lib");
    let root = root.path();
    python(
        root,
        "elsewhere/python3.12/site-packages",
        "planted",
        "1.0.0",
    );
    let venv = "home/u/.local/share/pipx/venvs/tool";
    fs::create_dir_all(root.join(venv)).unwrap();
    symlink(root.join("elsewhere"), root.join(format!("{venv}/lib"))).unwrap();

    let inventory = inventory::collect(root, &Places::defaults(Some(HOME)));

    assert_eq!(found(&inventory), []);
    assert!(
        inventory
            .notes
            .join("\n")
            .contains("/home/u/.local/share/pipx/venvs/tool/lib"),
        "{:?}",
        inventory.notes
    );
}

#[test]
fn a_linked_npmrc_is_followed_and_one_that_cannot_be_read_is_said_by_its_path_alone() {
    let root = TempDir::new("packages-npmrc-link");
    let root = root.path();
    write(
        root,
        "dotfiles/npmrc",
        "prefix=/opt/g\n//r.example/:_authToken=secret\n",
    );
    npm(root, "opt/g/lib/node_modules/hidden", "hidden", "1.0.0");
    npm(root, "usr/lib/node_modules/system", "system", "1.0.0");
    fs::create_dir_all(root.join("home/u")).unwrap();
    symlink(root.join("dotfiles/npmrc"), root.join("home/u/.npmrc")).unwrap();

    // A dotfile manager's link is followed, as npm follows it.
    let inventory = inventory::collect(root, &Places::defaults(Some(HOME)));
    assert_eq!(
        found(&inventory),
        [
            (Ecosystem::Npm, "hidden", "1.0.0"),
            (Ecosystem::Npm, "system", "1.0.0"),
        ]
    );

    // One that leads to no regular file may set a private registry, so no
    // npm package is taken at all.
    fs::remove_file(root.join("home/u/.npmrc")).unwrap();
    symlink(root.join("dotfiles"), root.join("home/u/.npmrc")).unwrap();
    let inventory = inventory::collect(root, &Places::defaults(Some(HOME)));
    assert_eq!(found(&inventory), []);
    let unchecked = inventory.unchecked.join("\n");
    assert!(
        unchecked.contains("/home/u/.npmrc could not be read")
            && unchecked.contains("no npm package was looked up"),
        "{unchecked}"
    );
    assert!(!unchecked.contains("secret") && !unchecked.contains("/opt/g"));

    fs::remove_file(root.join("home/u/.npmrc")).unwrap();
    write(
        root,
        "home/u/.npmrc",
        &format!("prefix=/opt/g\n{}", " ".repeat(2 * 1024 * 1024)),
    );
    let inventory = inventory::collect(root, &Places::defaults(Some(HOME)));
    assert_eq!(found(&inventory), []);
    assert!(
        inventory
            .unchecked
            .join("\n")
            .contains("/home/u/.npmrc could not be read")
    );
}

#[test]
fn mises_pipx_tools_are_read_in_uvs_layout_too() {
    let root = TempDir::new("packages-uv");
    let root = root.path();
    let install = "home/u/.local/share/mise/installs/pipx-black/24.1.0";
    python(
        root,
        &format!("{install}/black/lib/python3.12/site-packages"),
        "black",
        "24.1.0",
    );
    fs::create_dir_all(root.join(format!("{install}/bin"))).unwrap();

    let inventory = inventory::collect(root, &Places::defaults(Some(HOME)));

    assert_eq!(found(&inventory), [(Ecosystem::PyPi, "black", "24.1.0")]);
    assert!(inventory.unchecked.is_empty(), "{:?}", inventory.unchecked);
}

#[test]
fn uvs_index_settings_keep_what_mise_installed_through_uv_out() {
    let root = TempDir::new("packages-uv-index");
    let root = root.path();
    let installs = "home/u/.local/share/mise/installs";
    for name in ["black", "inhouse"] {
        python(
            root,
            &format!("{installs}/pipx-{name}/1.0.0/{name}/lib/python3.12/site-packages"),
            name,
            "1.0.0",
        );
    }
    write(
        root,
        &format!("{installs}/pipx-inhouse/1.0.0/inhouse/uv-receipt.toml"),
        "[tool]\nrequirements = [{ name = \"inhouse\", git = \"https://git.example/x\" }]\n",
    );

    let places = Places::defaults(Some(HOME));
    let inventory = inventory::collect(root, &places);
    assert_eq!(found(&inventory), [(Ecosystem::PyPi, "black", "1.0.0")]);
    assert!(
        inventory.unchecked[0]
            .starts_with("1 language package(s) are, or may be, from a private registry"),
        "{:?}",
        inventory.unchecked
    );

    let mut with_variable = Places::defaults(Some(HOME));
    with_variable.uv_env = vec!["UV_INDEX_URL".to_string()];
    assert_eq!(found(&inventory::collect(root, &with_variable)), []);

    write(
        root,
        "home/u/.config/uv/uv.toml",
        "[[index]]\nurl = \"https://pypi.corp.example/simple\"\n",
    );
    assert_eq!(found(&inventory::collect(root, &places)), []);

    write(root, "home/u/.config/uv/uv.toml", "[index\n");
    let inventory = inventory::collect(root, &places);
    assert_eq!(found(&inventory), []);
    assert!(
        inventory
            .unchecked
            .join("\n")
            .contains("/home/u/.config/uv/uv.toml could not be read"),
        "{:?}",
        inventory.unchecked
    );
}

#[test]
fn a_linked_crates_list_is_said_once_and_not_as_unreadable() {
    let root = TempDir::new("packages-crates-link");
    let root = root.path();
    write(root, "elsewhere/crates2.json", r#"{"installs":{}}"#);
    let mise_cargo = "home/u/.local/share/mise/installs/cargo-ripgrep/14.1.0";
    for cargo in ["home/u/.cargo", mise_cargo] {
        fs::create_dir_all(root.join(cargo)).unwrap();
        symlink(
            root.join("elsewhere/crates2.json"),
            root.join(format!("{cargo}/.crates2.json")),
        )
        .unwrap();
    }

    let inventory = inventory::collect(root, &Places::defaults(Some(HOME)));

    assert_eq!(found(&inventory), []);
    assert!(inventory.unchecked.is_empty(), "{:?}", inventory.unchecked);
    assert!(
        inventory.notes.join("\n").starts_with("2 linked"),
        "{:?}",
        inventory.notes
    );
}

#[test]
fn records_in_python_environments_that_name_another_index_leave_them_out() {
    let root = TempDir::new("packages-python-records");
    let root = root.path();
    let venvs = "home/u/.local/share/pipx/venvs";
    let python_dir = "home/u/.local/share/mise/installs/python/3.12.1";
    for (environment, name) in [
        (format!("{venvs}/plain"), "plain"),
        (format!("{venvs}/unreadable"), "unreadable"),
        (format!("{venvs}/siteconf"), "siteconf"),
        (python_dir.to_string(), "requests"),
    ] {
        python(
            root,
            &format!("{environment}/lib/python3.12/site-packages"),
            name,
            "1.0.0",
        );
    }
    write(
        root,
        &format!("{venvs}/unreadable/pipx_metadata.json"),
        "{not json",
    );
    write(
        root,
        &format!("{venvs}/siteconf/pip.conf"),
        "[global]\nindex-url = https://pypi.corp.example/simple\n",
    );

    let inventory = inventory::collect(root, &Places::defaults(Some(HOME)));
    assert_eq!(
        found(&inventory),
        [
            (Ecosystem::PyPi, "plain", "1.0.0"),
            (Ecosystem::PyPi, "requests", "1.0.0")
        ]
    );

    write(
        root,
        &format!("{python_dir}/pip.conf"),
        "[global]\nextra-index-url = https://pypi.corp.example/simple\n",
    );
    let inventory = inventory::collect(root, &Places::defaults(Some(HOME)));
    assert_eq!(found(&inventory), [(Ecosystem::PyPi, "plain", "1.0.0")]);

    // A linked record is followed, as pip follows it.
    symlink(
        root.join(format!("{venvs}/siteconf/pip.conf")),
        root.join(format!("{venvs}/plain/pip.conf")),
    )
    .unwrap();
    let inventory = inventory::collect(root, &Places::defaults(Some(HOME)));
    assert_eq!(found(&inventory), []);
    let unchecked = inventory.unchecked.join("\n");
    assert!(!unchecked.contains("could not be read"), "{unchecked}");

    // One that leads to no regular file is said by its path.
    fs::remove_file(root.join(format!("{venvs}/plain/pip.conf"))).unwrap();
    symlink(
        root.join(format!("{venvs}/siteconf")),
        root.join(format!("{venvs}/plain/pip.conf")),
    )
    .unwrap();
    let inventory = inventory::collect(root, &Places::defaults(Some(HOME)));
    assert_eq!(found(&inventory), []);
    assert!(
        inventory
            .unchecked
            .join("\n")
            .contains(&format!("/{venvs}/plain/pip.conf")),
        "{:?}",
        inventory.unchecked
    );
}

#[test]
fn a_mise_npm_tool_in_pnpms_layout_is_said_as_not_read() {
    let root = TempDir::new("packages-mise-aube");
    let root = root.path();
    let install = "home/u/.local/share/mise/installs/npm-x/1.0.0";
    npm(root, &format!("{install}/node_modules/x"), "x", "1.0.0");

    let inventory = inventory::collect(root, &Places::defaults(Some(HOME)));

    assert_eq!(found(&inventory), []);
    assert!(
        inventory
            .unchecked
            .join("\n")
            .contains(&format!("/{install}")),
        "{:?}",
        inventory.unchecked
    );
}

#[test]
fn npms_global_file_under_each_prefix_decides_too() {
    let root = TempDir::new("packages-npm-global");
    let root = root.path();
    let node = "home/u/.local/share/mise/installs/node/22.1.0";
    npm(root, "usr/lib/node_modules/system", "system", "1.0.0");
    npm(root, "opt/g/lib/node_modules/mine", "mine", "1.0.0");
    npm(
        root,
        &format!("{node}/lib/node_modules/npm"),
        "npm",
        "10.0.0",
    );
    let places = Places::defaults(Some(HOME));
    write(root, "home/u/.npmrc", "prefix=/opt/g\n");
    assert_eq!(found(&inventory::collect(root, &places)).len(), 3);

    // `npm config set -g registry ...` writes `{prefix}/etc/npmrc`; the
    // prefix comes from the user's file.
    write(root, "home/u/.npmrc", "prefix=/opt/g\n");
    write(
        root,
        "opt/g/etc/npmrc",
        "registry=https://npm.corp.example/\n",
    );
    let inventory = inventory::collect(root, &places);
    assert_eq!(found(&inventory), []);
    assert!(!inventory.unchecked.join("\n").contains("could not be read"));

    // Without a prefix, a node's own directory is its prefix.
    fs::remove_file(root.join("home/u/.npmrc")).unwrap();
    assert_eq!(found(&inventory::collect(root, &places)).len(), 2);
    write(
        root,
        &format!("{node}/etc/npmrc"),
        "registry=https://npm.corp.example/\n",
    );
    assert_eq!(found(&inventory::collect(root, &places)), []);

    // `globalconfig` names the global file in its place; one it names by
    // a path that is not absolute cannot be found, and leaves npm out.
    fs::remove_file(root.join(format!("{node}/etc/npmrc"))).unwrap();
    write(root, "home/u/.npmrc", "globalconfig=/srv/npmrc\n");
    write(
        root,
        "srv/npmrc",
        "@x:registry=https://npm.corp.example/\nregistry=https://npm.corp.example/\n",
    );
    assert_eq!(found(&inventory::collect(root, &places)), []);
    write(root, "home/u/.npmrc", "globalconfig=npmrc\n");
    let inventory = inventory::collect(root, &places);
    assert_eq!(found(&inventory), []);
    assert!(
        inventory
            .unchecked
            .join("\n")
            .contains("the path npm's globalconfig names (npmrc)"),
        "{:?}",
        inventory.unchecked
    );
}

#[test]
fn cargo_source_replacement_leaves_every_crate_out() {
    let root = TempDir::new("packages-cargo-config");
    let root = root.path();
    crates(
        root,
        "home/u/.cargo/.crates2.json",
        &["ripgrep 14.1.0 (registry+https://github.com/rust-lang/crates.io-index)"],
    );
    let places = Places::defaults(Some(HOME));
    write(root, "home/u/.cargo/config.toml", "[net]\nretry = 3\n");
    assert_eq!(
        found(&inventory::collect(root, &places)),
        [(Ecosystem::CratesIo, "ripgrep", "14.1.0")]
    );

    for (file, text) in [
        (
            "home/u/.cargo/config.toml",
            "[source.crates-io]\nreplace-with = \"mirror\"\n[source.mirror]\nregistry = \"sparse+https://mirror.example/\"\n",
        ),
        (
            "home/u/.cargo/config",
            "source = { crates-io = { replace-with = \"vendored\" } }\n",
        ),
        ("home/u/.cargo/config.toml", "include = [\"more.toml\"]\n"),
    ] {
        fs::remove_file(root.join("home/u/.cargo/config.toml")).ok();
        fs::remove_file(root.join("home/u/.cargo/config")).ok();
        write(root, file, text);
        let inventory = inventory::collect(root, &places);
        assert_eq!(found(&inventory), [], "{text}");
        assert!(
            inventory
                .unchecked
                .join("\n")
                .contains("cargo's configuration replaces a source"),
            "{:?}",
            inventory.unchecked
        );
    }

    write(root, "home/u/.cargo/config.toml", "[source\n");
    let inventory = inventory::collect(root, &places);
    assert_eq!(found(&inventory), []);
    assert!(
        inventory
            .unchecked
            .join("\n")
            .contains("/home/u/.cargo/config.toml could not be read"),
        "{:?}",
        inventory.unchecked
    );
}

#[test]
fn a_nodes_builtin_npmrc_and_prefix_variable_decide_too() {
    let root = TempDir::new("packages-npm-builtin");
    let root = root.path();
    let node = "home/u/.local/share/mise/installs/node/22.1.0";
    let builtin = format!("{node}/lib/node_modules/npm/npmrc");
    npm(
        root,
        &format!("{node}/lib/node_modules/npm"),
        "npm",
        "10.0.0",
    );
    npm(root, "opt/b/lib/node_modules/fromb", "fromb", "1.0.0");
    let places = Places::defaults(Some(HOME));

    write(root, &builtin, "prefix=/opt/b\n");
    assert_eq!(found(&inventory::collect(root, &places)).len(), 2);

    write(root, &builtin, "registry=https://npm.corp.example/\n");
    assert_eq!(found(&inventory::collect(root, &places)), []);

    write(root, &builtin, "globalconfig=/srv/npmrc\n");
    write(root, "srv/npmrc", "registry=https://npm.corp.example/\n");
    assert_eq!(found(&inventory::collect(root, &places)), []);
    fs::remove_file(root.join("srv/npmrc")).unwrap();
    assert_eq!(found(&inventory::collect(root, &places)).len(), 1);

    // PREFIX is npm's prefix where none is set: its packages are read, and
    // its global file too.
    fs::remove_file(root.join(&builtin)).unwrap();
    let with_prefix = Places {
        npm_global_prefix: Some("/opt/b".to_string()),
        ..Places::defaults(Some(HOME))
    };
    assert_eq!(found(&inventory::collect(root, &with_prefix)).len(), 2);
    write(
        root,
        "opt/b/etc/npmrc",
        "registry=https://npm.corp.example/\n",
    );
    assert_eq!(found(&inventory::collect(root, &with_prefix)), []);
}

#[test]
fn etc_npmrc_cannot_make_a_private_registry_public() {
    let root = TempDir::new("packages-etc-npmrc");
    let root = root.path();
    npm(root, "usr/lib/node_modules/system", "system", "1.0.0");
    let places = Places::defaults(Some(HOME));
    write(
        root,
        "usr/etc/npmrc",
        "registry=https://npm.corp.example/\n",
    );
    write(root, "etc/npmrc", "registry=https://registry.npmjs.org/\n");
    assert_eq!(found(&inventory::collect(root, &places)), []);

    write(
        root,
        "usr/etc/npmrc",
        "registry=https://registry.npmjs.org/\n",
    );
    write(root, "etc/npmrc", "registry=https://npm.corp.example/\n");
    assert_eq!(found(&inventory::collect(root, &places)), []);
}

#[test]
fn a_shared_unreadable_file_is_said_once_and_an_absent_npm_runs_no_scripts() {
    let root = TempDir::new("packages-npm-once");
    let root = root.path();
    let installs = "home/u/.local/share/mise/installs/node";
    for version in ["20.1.0", "22.1.0"] {
        write(
            root,
            &format!("{installs}/{version}/lib/node_modules/npm/npmrc"),
            "ignore-scripts=true\n",
        );
    }
    let places = Places::defaults(Some(HOME));
    // No npm of the system's: only the nodes' npm, which runs none.
    assert!(!inventory::collect(root, &places).npm_runs_scripts);

    fs::create_dir_all(root.join("srv/npmrc")).unwrap();
    write(root, "home/u/.npmrc", "globalconfig=/srv/npmrc\n");
    let inventory = inventory::collect(root, &places);
    let said = inventory
        .unchecked
        .iter()
        .filter(|sentence| sentence.contains("/srv/npmrc could not be read"))
        .count();
    assert_eq!(said, 1, "{:?}", inventory.unchecked);
}

#[test]
fn crates_from_another_sparse_registry_and_cargo_config_elsewhere_are_left_out() {
    let root = TempDir::new("packages-cargo-more");
    let root = root.path();
    crates(
        root,
        "home/u/.cargo/.crates2.json",
        &[
            "inhouse 1.0.0 (sparse+https://cargo.corp.example/)",
            "ripgrep 14.1.0 (registry+https://github.com/rust-lang/crates.io-index)",
        ],
    );
    let places = Places::defaults(Some(HOME));
    assert_eq!(
        found(&inventory::collect(root, &places)),
        [(Ecosystem::CratesIo, "ripgrep", "14.1.0")]
    );

    // The root's `.cargo`, and the home's when CARGO_HOME is elsewhere.
    let moved = Places {
        cargo: Some("opt/cargo".to_string()),
        ..Places::defaults(Some(HOME))
    };
    crates(
        root,
        "opt/cargo/.crates2.json",
        &["ripgrep 14.1.0 (registry+https://github.com/rust-lang/crates.io-index)"],
    );
    assert_eq!(found(&inventory::collect(root, &moved)).len(), 1);
    for file in ["home/u/.cargo/config.toml", ".cargo/config"] {
        write(
            root,
            file,
            "[source.crates-io]\nreplace-with = \"mirror\"\n",
        );
        assert_eq!(found(&inventory::collect(root, &moved)), [], "{file}");
        fs::remove_file(root.join(file)).unwrap();
    }
}
