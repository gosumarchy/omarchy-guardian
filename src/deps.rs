//! Dependency manifests and lockfiles found in a reviewed tree.
//!
//! Locked package versions are collected for the OSV audit. A manifest that
//! declares dependencies without a supported lockfile beside or above it makes
//! the review incomplete, since its dependencies cannot be audited.

use std::collections::HashSet;
use std::path::Path;

use crate::json::Json;
use crate::report::Gap;
use crate::tomlish::{self, Entry};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub(crate) enum Ecosystem {
    CratesIo,
    Npm,
    PyPi,
    Go,
}

impl Ecosystem {
    /// The ecosystem name in the OSV schema.
    pub(crate) const fn osv_name(self) -> &'static str {
        match self {
            Self::CratesIo => "crates.io",
            Self::Npm => "npm",
            Self::PyPi => "PyPI",
            Self::Go => "Go",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Dependency {
    pub(crate) ecosystem: Ecosystem,
    pub(crate) name: String,
    pub(crate) version: String,
    /// The lockfile it was found in, relative to the review root.
    pub(crate) lockfile: String,
}

#[derive(Debug, Default)]
pub(crate) struct Inventory {
    packages: Vec<Dependency>,
    seen: HashSet<(Ecosystem, String, String)>,
    manifests: Vec<(String, Ecosystem)>,
    lockfiles: Vec<(String, Ecosystem)>,
    /// The lockfiles that listed at least one package, local ones
    /// included.
    listed: HashSet<String>,
}

impl Inventory {
    pub(crate) fn packages(&self) -> &[Dependency] {
        &self.packages
    }

    pub(crate) fn lockfile_count(&self) -> usize {
        self.lockfiles.len()
    }

    fn add(&mut self, ecosystem: Ecosystem, name: &str, version: &str, lockfile: &str) {
        let name = name.trim();
        let version = version.trim();
        if name.is_empty() || version.is_empty() {
            return;
        }
        self.listed.insert(lockfile.to_string());
        if self
            .seen
            .insert((ecosystem, name.to_string(), version.to_string()))
        {
            self.packages.push(Dependency {
                ecosystem,
                name: name.to_string(),
                version: version.to_string(),
                lockfile: lockfile.to_string(),
            });
        }
    }

    fn lockfile(&mut self, rel: &str, ecosystem: Ecosystem) {
        self.lockfiles.push((rel.to_string(), ecosystem));
    }

    fn manifest(&mut self, rel: &str, ecosystem: Ecosystem) {
        self.manifests.push((rel.to_string(), ecosystem));
    }
}

/// Records whatever dependency information `contents` holds.
pub(crate) fn inspect(inventory: &mut Inventory, gaps: &mut Vec<Gap>, rel: &str, contents: &str) {
    let name = Path::new(rel)
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or_default()
        .to_ascii_lowercase();
    let mut gap = |message: String| gaps.push(Gap::Dependency(message));

    match name.as_str() {
        "cargo.lock" => parse_cargo_lock(inventory, &mut gap, rel, contents),
        "package-lock.json" | "npm-shrinkwrap.json" => {
            parse_npm_lock(inventory, &mut gap, rel, contents);
        }
        "poetry.lock" => parse_poetry_lock(inventory, &mut gap, rel, contents),
        "go.sum" => parse_go_sum(inventory, &mut gap, rel, contents),
        "pipfile.lock" | "yarn.lock" | "pnpm-lock.yaml" | "gemfile.lock" | "composer.lock" => {
            gap(format!(
                "{rel}: dependency lockfile format is not supported by Guardian's OSV audit"
            ));
        }
        "cargo.toml" => match tomlish::entries(contents) {
            Ok(entries) if cargo_manifest_has_dependencies(&entries) => {
                inventory.manifest(rel, Ecosystem::CratesIo);
            }
            Ok(_) => {}
            Err(error) => gap(format!(
                "{rel}: could not parse dependency manifest: {error}"
            )),
        },
        "pyproject.toml" => match tomlish::entries(contents) {
            Ok(entries) if pyproject_has_dependencies(&entries) => {
                inventory.manifest(rel, Ecosystem::PyPi);
            }
            Ok(_) => {}
            Err(error) => gap(format!(
                "{rel}: could not parse dependency manifest: {error}"
            )),
        },
        "package.json" => match Json::parse(contents) {
            Ok(value) if package_json_has_dependencies(&value) => {
                inventory.manifest(rel, Ecosystem::Npm);
            }
            Ok(_) => {}
            Err(error) => gap(format!(
                "{rel}: could not parse dependency manifest: {error}"
            )),
        },
        "go.mod" if go_mod_has_requirements(contents) => inventory.manifest(rel, Ecosystem::Go),
        _ if name.starts_with("requirements")
            && Path::new(&name)
                .extension()
                .is_some_and(|extension| extension == "txt") =>
        {
            parse_requirements(inventory, &mut gap, rel, contents);
        }
        _ => {}
    }
}

/// Requires every manifest to have a lockfile of its ecosystem in its own
/// directory or an ancestor (a Cargo workspace root, for example).
pub(crate) fn check_coverage(inventory: &Inventory, gaps: &mut Vec<Gap>) {
    for (manifest, ecosystem) in &inventory.manifests {
        let directory = Path::new(manifest).parent().unwrap_or(Path::new(""));
        let covering: Vec<&String> = inventory
            .lockfiles
            .iter()
            .filter(|(lockfile, locked)| {
                locked == ecosystem
                    && Path::new(lockfile)
                        .parent()
                        .is_some_and(|lock_directory| directory.starts_with(lock_directory))
            })
            .map(|(lockfile, _)| lockfile)
            .collect();
        // A lockfile that names nothing the audit can look up covers
        // nothing.
        let names_packages = |lockfile: &&String| inventory.listed.contains(*lockfile);
        if covering.is_empty() {
            gaps.push(Gap::Dependency(format!(
                "{manifest}: {} dependencies are declared but no supported matching lockfile was found",
                ecosystem.osv_name()
            )));
        } else if !covering.iter().any(names_packages) {
            gaps.push(Gap::Dependency(format!(
                "{manifest}: {} dependencies are declared but its lockfile lists none to audit",
                ecosystem.osv_name()
            )));
        }
    }
}

fn is_dependency_table(segment: &str) -> bool {
    matches!(
        segment,
        "dependencies"
            | "dev-dependencies"
            | "build-dependencies"
            | "dev_dependencies"
            | "build_dependencies"
    )
}

/// Any dependency table with at least one entry, including target-specific
/// and workspace tables, dotted keys and inline tables.
fn cargo_manifest_has_dependencies(entries: &[Entry]) -> bool {
    entries.iter().any(|entry| {
        let path = entry.full_path();
        path.iter().enumerate().any(|(index, segment)| {
            is_dependency_table(segment)
                && (index + 1 < path.len() || !tomlish::is_empty_container(&entry.value))
        })
    })
}

fn pyproject_has_dependencies(entries: &[Entry]) -> bool {
    entries.iter().any(|entry| {
        let non_empty = !tomlish::is_empty_container(&entry.value);
        match entry.full_path().as_slice() {
            ["project", "dependencies" | "optional-dependencies", ..]
            | ["tool", "poetry", "dependencies"]
            | ["tool", "poetry", "group", _, "dependencies"]
            | ["tool", "poetry", "dev-dependencies", ..] => non_empty,
            ["tool", "poetry", "dependencies", name, ..]
            | ["tool", "poetry", "group", _, "dependencies", name, ..] => *name != "python",
            _ => false,
        }
    })
}

fn package_json_has_dependencies(value: &Json) -> bool {
    [
        "dependencies",
        "devDependencies",
        "optionalDependencies",
        "peerDependencies",
    ]
    .iter()
    .any(|key| {
        value
            .get(key)
            .and_then(Json::as_object)
            .is_some_and(|members| !members.is_empty())
    })
}

fn go_mod_has_requirements(contents: &str) -> bool {
    contents
        .lines()
        .any(|line| line.trim_start().starts_with("require ") || line.trim() == "require (")
}

/// crates.io as a `Cargo.lock` names it, whole: its index repository, and
/// its sparse index. Any other registry is one OSV does not know.
const CRATES_IO_SOURCES: &[&str] = &[
    "registry+https://github.com/rust-lang/crates.io-index",
    "sparse+https://index.crates.io/",
];

fn parse_cargo_lock(
    inventory: &mut Inventory,
    gap: &mut dyn FnMut(String),
    rel: &str,
    contents: &str,
) {
    inventory.lockfile(rel, Ecosystem::CratesIo);
    let entries = match tomlish::entries(contents) {
        Ok(entries) => entries,
        Err(error) => {
            return gap(format!(
                "{rel}: could not parse Cargo.lock for dependency audit: {error}"
            ));
        }
    };

    for package in tomlish::array_table_items(&entries, "package") {
        inventory.listed.insert(rel.to_string());
        let (Some(name), Some(version)) = (
            tomlish::string_field(&package, "name"),
            tomlish::string_field(&package, "version"),
        ) else {
            gap(format!("{rel}: package entry without a name and version"));
            continue;
        };
        match tomlish::string_field(&package, "source") {
            Some(source) if CRATES_IO_SOURCES.contains(&source.as_str()) => {
                inventory.add(Ecosystem::CratesIo, &name, &version, rel);
            }
            Some(source) if source.starts_with("registry+") || source.starts_with("sparse+") => {
                gap(format!(
                    "{rel}: non-crates.io registry dependency {name} needs an external audit"
                ));
            }
            Some(source) if source.starts_with("git+") => gap(format!(
                "{rel}: Git-sourced dependency {name} cannot be matched to an OSV package version"
            )),
            Some(_) => gap(format!("{rel}: unsupported source for dependency {name}")),
            // Workspace members and path dependencies are part of the tree.
            None => {}
        }
    }
}

fn parse_npm_lock(
    inventory: &mut Inventory,
    gap: &mut dyn FnMut(String),
    rel: &str,
    contents: &str,
) {
    inventory.lockfile(rel, Ecosystem::Npm);
    let lockfile = match Json::parse(contents) {
        Ok(lockfile) => lockfile,
        Err(error) => {
            return gap(format!(
                "{rel}: could not parse npm lockfile for dependency audit: {error}"
            ));
        }
    };

    if let Some(packages) = lockfile.get("packages").and_then(Json::as_object) {
        for (package_path, package) in packages {
            if package_path.is_empty() {
                continue;
            }
            inventory.listed.insert(rel.to_string());
            if package.get("link").and_then(Json::as_bool) == Some(true) {
                continue;
            }
            if let Some(resolved) = package.get("resolved").and_then(Json::as_str)
                && !resolved.starts_with("https://registry.npmjs.org/")
                && !resolved.starts_with("https://registry.yarnpkg.com/")
            {
                gap(format!(
                    "{rel}: npm package source is not a recognized registry URL: {resolved}"
                ));
            }

            let name = package
                .get("name")
                .and_then(Json::as_str)
                .or_else(|| npm_name_from_path(package_path));
            let version = package.get("version").and_then(Json::as_str);
            match (name, version) {
                (Some(name), Some(version)) if !version.starts_with("file:") => {
                    inventory.add(Ecosystem::Npm, name, version, rel);
                }
                (Some(name), Some(_)) => gap(format!(
                    "{rel}: local npm dependency {name} has no OSV-resolvable registry version"
                )),
                (Some(_) | None, None) | (None, Some(_)) => {}
            }
        }
    } else if let Some(dependencies) = lockfile.get("dependencies").and_then(Json::as_object) {
        collect_legacy_npm(inventory, gap, rel, dependencies);
    } else {
        gap(format!("{rel}: unsupported npm lockfile structure"));
    }
}

fn npm_name_from_path(path: &str) -> Option<&str> {
    path.rsplit_once("node_modules/")
        .map(|(_, name)| name)
        .filter(|name| !name.is_empty())
}

/// Lockfile version 1 nests dependencies recursively.
fn collect_legacy_npm(
    inventory: &mut Inventory,
    gap: &mut dyn FnMut(String),
    rel: &str,
    dependencies: &[(String, Json)],
) {
    for (name, dependency) in dependencies {
        if let Some(version) = dependency.get("version").and_then(Json::as_str) {
            if version.starts_with("file:") || version.starts_with("git+") {
                gap(format!(
                    "{rel}: non-registry npm dependency {name} needs an external audit"
                ));
            } else {
                inventory.add(Ecosystem::Npm, name, version, rel);
            }
        }
        if let Some(nested) = dependency.get("dependencies").and_then(Json::as_object) {
            collect_legacy_npm(inventory, gap, rel, nested);
        }
    }
}

fn parse_poetry_lock(
    inventory: &mut Inventory,
    gap: &mut dyn FnMut(String),
    rel: &str,
    contents: &str,
) {
    inventory.lockfile(rel, Ecosystem::PyPi);
    let entries = match tomlish::entries(contents) {
        Ok(entries) => entries,
        Err(error) => {
            return gap(format!(
                "{rel}: could not parse Poetry lockfile for dependency audit: {error}"
            ));
        }
    };

    for package in tomlish::array_table_items(&entries, "package") {
        match (
            tomlish::string_field(&package, "name"),
            tomlish::string_field(&package, "version"),
        ) {
            (Some(name), Some(version)) => inventory.add(Ecosystem::PyPi, &name, &version, rel),
            (Some(_) | None, None) | (None, Some(_)) => {
                gap(format!("{rel}: package entry without a name and version"));
            }
        }
    }
}

fn parse_go_sum(inventory: &mut Inventory, gap: &mut dyn FnMut(String), rel: &str, contents: &str) {
    inventory.lockfile(rel, Ecosystem::Go);
    for line in contents.lines() {
        let mut fields = line.split_whitespace();
        let (Some(name), Some(version), Some(_checksum)) =
            (fields.next(), fields.next(), fields.next())
        else {
            if !line.trim().is_empty() {
                gap(format!("{rel}: malformed go.sum dependency entry"));
            }
            continue;
        };
        if !version.ends_with("/go.mod") {
            inventory.add(Ecosystem::Go, name, version, rel);
        }
    }
}

fn parse_requirements(
    inventory: &mut Inventory,
    gap: &mut dyn FnMut(String),
    rel: &str,
    contents: &str,
) {
    inventory.lockfile(rel, Ecosystem::PyPi);
    for line in contents.lines() {
        let requirement = line.split('#').next().unwrap_or_default().trim();
        if requirement.is_empty() {
            continue;
        }
        if requirement.starts_with('-') || requirement.contains(" @ ") {
            gap(format!(
                "{rel}: included or URL-based Python requirement cannot be resolved by the OSV audit"
            ));
            continue;
        }

        let requirement = requirement.split(';').next().unwrap_or_default().trim();
        let Some((name, version)) = requirement
            .split_once("===")
            .or_else(|| requirement.split_once("=="))
        else {
            gap(format!(
                "{rel}: Python requirement is not pinned to an exact version: {requirement}"
            ));
            continue;
        };

        let name = name.split('[').next().unwrap_or_default().trim();
        let version = version.split_whitespace().next().unwrap_or_default();
        if name.is_empty() || version.is_empty() || version.contains([',', '*']) {
            gap(format!(
                "{rel}: Python requirement is not pinned to one exact version: {requirement}"
            ));
            continue;
        }
        inventory.add(
            Ecosystem::PyPi,
            &name.to_ascii_lowercase().replace('_', "-"),
            version,
            rel,
        );
    }
}

#[cfg(test)]
mod tests {
    use super::{Ecosystem, Inventory, check_coverage, inspect};
    use crate::report::Gap;

    fn run(files: &[(&str, &str)]) -> (Inventory, Vec<Gap>) {
        let mut inventory = Inventory::default();
        let mut gaps = Vec::new();
        for (rel, contents) in files {
            inspect(&mut inventory, &mut gaps, rel, contents);
        }
        check_coverage(&inventory, &mut gaps);
        (inventory, gaps)
    }

    fn has(inventory: &Inventory, ecosystem: Ecosystem, name: &str, version: &str) -> bool {
        inventory.packages().iter().any(|package| {
            package.ecosystem == ecosystem && package.name == name && package.version == version
        })
    }

    #[test]
    fn parses_cargo_and_npm_lockfiles() {
        let (inventory, gaps) = run(&[
            (
                "Cargo.lock",
                "version = 4\n\n[[package]]\nname = \"serde\"\nversion = \"1.0.0\"\nsource = \"registry+https://github.com/rust-lang/crates.io-index\"\nchecksum = \"ab\"\ndependencies = [\n \"serde_derive\",\n]\n\n[[package]]\nname = \"my-app\"\nversion = \"0.1.0\"\n",
            ),
            (
                "package-lock.json",
                r#"{"lockfileVersion":3,"packages":{"":{"name":"app"},"node_modules/lodash":{"version":"4.17.21","resolved":"https://registry.npmjs.org/lodash/-/lodash-4.17.21.tgz"}}}"#,
            ),
        ]);

        assert!(gaps.is_empty(), "{gaps:?}");
        assert_eq!(inventory.packages().len(), 2);
        assert!(has(&inventory, Ecosystem::CratesIo, "serde", "1.0.0"));
        assert!(has(&inventory, Ecosystem::Npm, "lodash", "4.17.21"));
        assert_eq!(inventory.lockfile_count(), 2);
    }

    #[test]
    fn git_sources_and_unknown_registries_need_an_external_audit() {
        let (_, gaps) = run(&[(
            "Cargo.lock",
            "[[package]]\nname = \"a\"\nversion = \"1.0.0\"\nsource = \"git+https://example.test/a#abc\"\n",
        )]);
        assert_eq!(gaps.len(), 1);
        let lock = |source: &str| {
            format!("[[package]]\nname = \"a\"\nversion = \"1.0.0\"\nsource = \"{source}\"\n")
        };
        for source in [
            "registry+https://crates.io.evil.test/index",
            "registry+https://example.test/crates.io-index",
            "registry+https://github.com/rust-lang/crates.io-index.evil",
            "registry+https://github.com/evil/crates.io-index",
            "registry+http://github.com/rust-lang/crates.io-index",
            "sparse+https://index.crates.io.evil.test/",
            "sparse+https://example.test/index.crates.io/",
            "sparse+https://index.crates.io/mirror/",
        ] {
            let (inventory, gaps) = run(&[("Cargo.lock", &lock(source))]);
            assert!(inventory.packages().is_empty(), "{source}");
            assert_eq!(gaps.len(), 1, "{source}: {gaps:?}");
            assert!(
                gaps[0].to_string().contains("needs an external audit"),
                "{gaps:?}"
            );
        }
        for source in [
            "registry+https://github.com/rust-lang/crates.io-index",
            "sparse+https://index.crates.io/",
        ] {
            let (inventory, gaps) = run(&[("Cargo.lock", &lock(source))]);
            assert!(
                has(&inventory, Ecosystem::CratesIo, "a", "1.0.0"),
                "{source}"
            );
            assert!(gaps.is_empty(), "{source}: {gaps:?}");
        }
    }

    #[test]
    fn duplicates_are_recorded_once() {
        let (inventory, _) = run(&[
            (
                "a/go.sum",
                "example.test/m v1.0.0 h1:x=\nexample.test/m v1.0.0/go.mod h1:y=\n",
            ),
            ("b/go.sum", "example.test/m v1.0.0 h1:x=\n"),
        ]);
        assert_eq!(inventory.packages().len(), 1);
    }

    #[test]
    fn manifests_without_a_lockfile_are_incomplete() {
        for (rel, manifest) in [
            (
                "Cargo.toml",
                "[package]\nname = \"demo\"\n[dependencies]\nserde = \"1\"\n",
            ),
            (
                "Cargo.toml",
                "[target.'cfg(unix)'.dependencies.libc]\nversion = \"0.2\"\n",
            ),
            (
                "Cargo.toml",
                "dependencies.serde = \"1\"\n[package]\nname = \"demo\"\n",
            ),
            (
                "pyproject.toml",
                "[project]\nname = \"demo\"\ndependencies = [\n  \"requests>=2\",\n]\n",
            ),
            (
                "pyproject.toml",
                "[tool.poetry.dependencies]\npython = \"^3.11\"\nrequests = \"^2\"\n",
            ),
            ("package.json", r#"{"dependencies":{"left-pad":"1.0.0"}}"#),
            (
                "go.mod",
                "module x\n\nrequire (\n\texample.test/m v1.0.0\n)\n",
            ),
        ] {
            let (_, gaps) = run(&[(rel, manifest)]);
            assert!(
                matches!(gaps.as_slice(), [Gap::Dependency(message)] if message.contains("lockfile")),
                "{rel}: {manifest:?} gave {gaps:?}"
            );
        }
    }

    #[test]
    fn manifests_without_dependencies_need_no_lockfile() {
        for (rel, manifest) in [
            ("Cargo.toml", "[package]\nname = \"demo\"\n[dependencies]\n"),
            (
                "pyproject.toml",
                "[project]\nname = \"demo\"\ndependencies = []\n",
            ),
            (
                "pyproject.toml",
                "[tool.poetry.dependencies]\npython = \"^3.11\"\n",
            ),
            ("package.json", r#"{"name":"demo","dependencies":{}}"#),
            ("go.mod", "module x\n"),
        ] {
            let (_, gaps) = run(&[(rel, manifest)]);
            assert!(gaps.is_empty(), "{rel}: {manifest:?} gave {gaps:?}");
        }
    }

    #[test]
    fn a_workspace_lockfile_covers_member_manifests() {
        let lock = "version = 4\n\n[[package]]\nname = \"serde\"\nversion = \"1.0.0\"\nsource = \"registry+https://github.com/rust-lang/crates.io-index\"\n";
        let (_, gaps) = run(&[
            ("Cargo.lock", lock),
            ("crates/a/Cargo.toml", "[dependencies]\nserde = \"1\"\n"),
        ]);
        assert!(gaps.is_empty(), "{gaps:?}");

        // A lockfile that lists nothing covers nothing.
        let (_, gaps) = run(&[
            ("Cargo.lock", "version = 4\n"),
            ("crates/a/Cargo.toml", "[dependencies]\nserde = \"1\"\n"),
        ]);
        assert_eq!(gaps.len(), 1, "{gaps:?}");
        assert!(
            gaps[0].to_string().contains("lists none to audit"),
            "{gaps:?}"
        );

        // One that lists only the tree's own crates covers them.
        let (_, gaps) = run(&[
            (
                "Cargo.lock",
                "version = 4\n\n[[package]]\nname = \"b\"\nversion = \"0.1.0\"\n",
            ),
            (
                "crates/a/Cargo.toml",
                "[dependencies]\nb = { path = \"../b\" }\n",
            ),
        ]);
        assert!(gaps.is_empty(), "{gaps:?}");

        let (_, gaps) = run(&[
            ("other/Cargo.lock", "version = 4\n"),
            ("crates/a/Cargo.toml", "[dependencies]\nserde = \"1\"\n"),
        ]);
        assert_eq!(gaps.len(), 1);
    }

    #[test]
    fn parses_poetry_and_requirements() {
        let (inventory, gaps) = run(&[
            (
                "poetry.lock",
                "[[package]]\nname = \"requests\"\nversion = \"2.31.0\"\n\n[package.dependencies]\nidna = \">=2.5\"\n",
            ),
            (
                "requirements.txt",
                "# pinned\nDjango_Rest==3.14.0 ; python_version > '3'\nflask[async]===2.3.2\n",
            ),
        ]);

        assert!(gaps.is_empty(), "{gaps:?}");
        assert!(has(&inventory, Ecosystem::PyPi, "requests", "2.31.0"));
        assert!(has(&inventory, Ecosystem::PyPi, "django-rest", "3.14.0"));
        assert!(has(&inventory, Ecosystem::PyPi, "flask", "2.3.2"));
    }

    #[test]
    fn unpinned_or_url_requirements_are_gaps() {
        for requirement in [
            "requests>=2\n",
            "requests==2.*\n",
            "-r other.txt\n",
            "pkg @ https://x.test/p.whl\n",
        ] {
            let (_, gaps) = run(&[("requirements.txt", requirement)]);
            assert_eq!(gaps.len(), 1, "{requirement:?}");
        }
    }
}
