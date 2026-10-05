//! Dependency lockfiles and manifests in the upstream sources.
//!
//! A lockfile says where a build's dependencies come from, and it is data
//! that no one reads: the place to point one package at another server. It
//! can also be megabytes long, more than a review can take. So Guardian
//! reads it here for what matters (addresses outside the ecosystem's own
//! registry, version-control and unencrypted addresses, install scripts),
//! tells the AI what it found in its own words, and sends the file itself
//! only when it is small.

/// A lockfile up to this size is also sent to the AI whole.
pub const WHOLE_BYTES: usize = 64 * 1024;
/// The most of a larger lockfile that is read for the local scan.
pub const MAX_SCANNED_BYTES: u64 = 64 * 1024 * 1024;
/// The most foreign hosts named for one lockfile.
const MAX_HOSTS: usize = 8;

/// The package ecosystem a file belongs to, by its name.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Ecosystem {
    Npm,
    Cargo,
    Go,
    Python,
    Ruby,
    Php,
    Java,
}

impl Ecosystem {
    pub const fn label(self) -> &'static str {
        match self {
            Self::Npm => "npm",
            Self::Cargo => "cargo",
            Self::Go => "go modules",
            Self::Python => "pip",
            Self::Ruby => "bundler",
            Self::Php => "composer",
            Self::Java => "maven or gradle",
        }
    }

    /// The hosts the ecosystem's own tools fetch from by default.
    const fn registries(self) -> &'static [&'static str] {
        match self {
            Self::Npm => &["registry.npmjs.org", "registry.yarnpkg.com"],
            Self::Cargo => &["crates.io", "index.crates.io", "static.crates.io"],
            Self::Go => &["proxy.golang.org", "sum.golang.org"],
            Self::Python => &["pypi.org", "files.pythonhosted.org"],
            Self::Ruby => &["rubygems.org", "index.rubygems.org"],
            Self::Php => &["packagist.org", "repo.packagist.org"],
            Self::Java => &[
                "repo.maven.apache.org",
                "repo1.maven.org",
                "plugins.gradle.org",
            ],
        }
    }
}

/// The ecosystem whose lockfile `name` is: a file that pins or lists where
/// dependencies come from.
pub fn lockfile(name: &str) -> Option<Ecosystem> {
    let lower = name.to_ascii_lowercase();
    Some(match lower.as_str() {
        "package-lock.json"
        | "npm-shrinkwrap.json"
        | "yarn.lock"
        | "pnpm-lock.yaml"
        | "bun.lock" => Ecosystem::Npm,
        "cargo.lock" => Ecosystem::Cargo,
        "go.sum" | "go.mod" | "go.work" | "go.work.sum" => Ecosystem::Go,
        "poetry.lock" | "pipfile.lock" | "pipfile" | "uv.lock" | "pdm.lock" => Ecosystem::Python,
        "gemfile.lock" | "gemfile" => Ecosystem::Ruby,
        "composer.lock" => Ecosystem::Php,
        "gradle.lockfile" => Ecosystem::Java,
        _ if lower
            .strip_prefix("requirements")
            .is_some_and(|rest| rest.rsplit_once('.').is_some_and(|(_, end)| end == "txt")) =>
        {
            Ecosystem::Python
        }
        _ => return None,
    })
}

/// The ecosystem `name` is a manifest of: a build that has one usually
/// downloads the dependencies it names.
pub fn manifest(name: &str) -> Option<Ecosystem> {
    lockfile(name).or_else(|| {
        Some(match name.to_ascii_lowercase().as_str() {
            "package.json" => Ecosystem::Npm,
            "cargo.toml" => Ecosystem::Cargo,
            "composer.json" => Ecosystem::Php,
            "pom.xml" | "build.gradle" | "build.gradle.kts" => Ecosystem::Java,
            _ => return None,
        })
    })
}

/// What a local scan of one lockfile found.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Scan {
    /// Addresses in the file.
    pub addresses: usize,
    /// Addresses on a host that is not the ecosystem's registry.
    pub foreign: usize,
    /// Those hosts (validated names), sorted, up to `MAX_HOSTS`.
    pub hosts: Vec<String>,
    /// Addresses of a version-control repository.
    pub repositories: usize,
    /// Addresses fetched without encryption.
    pub unencrypted: usize,
    /// Entries marked as running a script when installed.
    pub install_scripts: usize,
    /// Lines that point a dependency somewhere else (`replace`, an extra
    /// index, a local path).
    pub redirects: usize,
}

impl Scan {
    /// Whether the scan found anything a reviewer should weigh.
    pub fn is_plain(&self) -> bool {
        self.foreign + self.repositories + self.unencrypted + self.install_scripts + self.redirects
            == 0
    }

    fn note_host(&mut self, host: String) {
        if !self.hosts.contains(&host) && self.hosts.len() < MAX_HOSTS {
            self.hosts.push(host);
        }
    }

    /// The scan in Guardian's own words: counts and validated host names,
    /// nothing of the file's own text.
    pub fn summary(&self, ecosystem: Ecosystem) -> String {
        if self.is_plain() {
            return format!(
                "{} lockfile, {} address(es), all on its registry",
                ecosystem.label(),
                self.addresses
            );
        }
        let mut parts = Vec::new();
        if self.foreign > 0 {
            parts.push(format!(
                "{} address(es) outside its registry (hosts: {}{})",
                self.foreign,
                self.hosts.join(", "),
                if self.hosts.len() == MAX_HOSTS {
                    ", possibly more"
                } else {
                    ""
                }
            ));
        }
        if self.repositories > 0 {
            parts.push(format!("{} version-control address(es)", self.repositories));
        }
        if self.unencrypted > 0 {
            parts.push(format!("{} unencrypted address(es)", self.unencrypted));
        }
        if self.install_scripts > 0 {
            parts.push(format!(
                "{} entr(ies) that run an install script",
                self.install_scripts
            ));
        }
        if self.redirects > 0 {
            parts.push(format!(
                "{} line(s) that point a dependency elsewhere",
                self.redirects
            ));
        }
        format!(
            "{} lockfile, {} address(es): {}",
            ecosystem.label(),
            self.addresses,
            parts.join("; ")
        )
    }
}

/// What a host is named as when its text is not a host name.
const UNPARSEABLE: &str = "an unparseable host";

/// Lines that send a dependency somewhere other than where its name says.
fn is_redirect(ecosystem: Ecosystem, line: &str) -> bool {
    let line = line.trim_start();
    match ecosystem {
        Ecosystem::Go => line.starts_with("replace ") || line.contains(" => "),
        Ecosystem::Python => [
            "--index-url",
            "--extra-index-url",
            "--find-links",
            "--trusted-host",
            "-i ",
            "-f ",
            "-e ",
        ]
        .iter()
        .any(|option| line.starts_with(option)),
        Ecosystem::Cargo => line.starts_with("path = ") || line.starts_with("replace-with"),
        Ecosystem::Npm => line.contains("\"file:") || line.contains("\"link:"),
        _ => false,
    }
}

/// How often `text` holds `key`, a colon and `true`, however they are
/// spaced: a lockfile written on one line counts like one written on many.
fn count_true(text: &str, key: &str) -> usize {
    text.match_indices(key)
        .filter(|(at, _)| {
            text[at + key.len()..]
                .trim_start()
                .strip_prefix(':')
                .is_some_and(|value| value.trim_start().starts_with("true"))
        })
        .count()
}

/// Scans a lockfile's text. It looks for addresses wherever they stand
/// rather than parsing each format: a format it knows less well is then
/// read too broadly, never too narrowly.
pub fn scan(ecosystem: Ecosystem, text: &str) -> Scan {
    let mut scan = Scan::default();
    let registries = ecosystem.registries();
    scan.install_scripts =
        count_true(text, "\"hasInstallScript\"") + count_true(text, "requiresBuild");
    for line in text.lines() {
        // JSON may write `/` as `\/`, and any character by its number: an
        // address written that way is one all the same.
        let unescaped = line.replace("\\/", "/");
        let line = unescaped.as_str();
        if line.contains("\\u00") {
            scan.addresses += 1;
            scan.foreign += 1;
            scan.note_host(UNPARSEABLE.to_string());
        }
        if is_redirect(ecosystem, line) {
            scan.redirects += 1;
        }
        // `github:owner/repo` and `git@host:path` name a repository too.
        if ["\"github:", "\"gitlab:", "\"bitbucket:"]
            .iter()
            .any(|form| line.contains(form))
            || (line.contains("git@") && !line.contains("://"))
        {
            scan.repositories += 1;
        }
        let mut rest = line;
        while let Some(at) = rest.find("://") {
            let scheme: String = rest[..at]
                .chars()
                .rev()
                .take_while(|c| c.is_ascii_alphanumeric() || "+.-".contains(*c))
                .collect::<Vec<char>>()
                .into_iter()
                .rev()
                .collect::<String>()
                .to_ascii_lowercase();
            rest = &rest[at + 3..];
            if scheme.is_empty() {
                continue;
            }
            // Where the client that fetches it ends the host: a `?` or a
            // `\` ends it like a `/`, so nothing after one is the host.
            let authority: &str = rest
                .split(|c: char| "/\"'#?\\".contains(c) || c.is_whitespace())
                .next()
                .unwrap_or_default();
            let user = authority.rsplit_once('@');
            let host = user
                .map_or(authority, |(_, host)| host)
                .split(':')
                .next()
                .unwrap_or_default()
                .to_ascii_lowercase();
            scan.addresses += 1;
            let transport = scheme.rsplit('+').next().unwrap_or_default();
            if scheme.starts_with("git") || scheme.contains("ssh") || scheme.contains("hg+") {
                // Cargo names its own registry as `registry+https://…`,
                // and its index is a repository on github.com.
                scan.repositories += 1;
            }
            if matches!(transport, "http" | "ftp" | "git") {
                scan.unencrypted += 1;
            }
            // An address with a user part is never the registry's own:
            // what stands before the `@` can read as its host.
            let registry = user.is_none() && registries.contains(&host.as_str())
                || (ecosystem == Ecosystem::Cargo
                    && scheme.starts_with("registry+")
                    && rest.starts_with("github.com/rust-lang/crates.io-index"))
                // Go names modules by host; they are fetched through the
                // module proxy and checked against the checksum database.
                || ecosystem == Ecosystem::Go;
            if registry {
                continue;
            }
            scan.foreign += 1;
            let valid = !host.is_empty()
                && host.len() <= 253
                && host
                    .chars()
                    .all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '-');
            scan.note_host(if valid { host } else { UNPARSEABLE.to_string() });
        }
    }
    scan.hosts.sort();
    scan
}

#[cfg(test)]
mod tests {
    use super::{Ecosystem, lockfile, manifest, scan};

    #[test]
    fn lockfiles_and_manifests_are_known_by_name() {
        for (name, ecosystem) in [
            ("package-lock.json", Ecosystem::Npm),
            ("yarn.lock", Ecosystem::Npm),
            ("pnpm-lock.yaml", Ecosystem::Npm),
            ("Cargo.lock", Ecosystem::Cargo),
            ("go.sum", Ecosystem::Go),
            ("go.mod", Ecosystem::Go),
            ("requirements-dev.txt", Ecosystem::Python),
            ("poetry.lock", Ecosystem::Python),
            ("Pipfile.lock", Ecosystem::Python),
        ] {
            assert_eq!(lockfile(name), Some(ecosystem), "{name}");
        }
        assert_eq!(lockfile("package.json"), None);
        assert_eq!(lockfile("notes.txt"), None);
        assert_eq!(manifest("package.json"), Some(Ecosystem::Npm));
        assert_eq!(manifest("Cargo.toml"), Some(Ecosystem::Cargo));
        assert_eq!(manifest("main.c"), None);
    }

    #[test]
    fn a_plain_lockfile_has_nothing_to_weigh() {
        let npm = r#"{"packages":{"node_modules/a":{"version":"1.0.0",
"resolved": "https://registry.npmjs.org/a/-/a-1.0.0.tgz","integrity":"sha512-x"}}}"#;
        let found = scan(Ecosystem::Npm, npm);
        assert!(found.is_plain(), "{found:?}");
        assert_eq!(found.addresses, 1);
        let cargo = "[[package]]\nname = \"a\"\nsource = \"registry+https://github.com/rust-lang/crates.io-index\"\n";
        assert!(scan(Ecosystem::Cargo, cargo).is_plain());
        let go = "github.com/a/b v1.0.0 h1:abc=\ngithub.com/a/b v1.0.0/go.mod h1:def=\n";
        assert!(scan(Ecosystem::Go, go).is_plain());
    }

    #[test]
    fn addresses_outside_the_registry_and_install_scripts_are_counted() {
        let npm = r#"
"resolved": "https://registry.npmjs.org/a/-/a-1.0.0.tgz",
"resolved": "https://evil.example/a-1.0.0.tgz",
"resolved": "git+ssh://git@github.com/x/y.git#abc",
"resolved": "http://registry.npmjs.org/b/-/b-1.tgz",
"hasInstallScript": true,
"dep": "github:someone/thing",
"local": "file:../elsewhere",
"#;
        let found = scan(Ecosystem::Npm, npm);
        assert_eq!(found.addresses, 4);
        assert_eq!(found.foreign, 2, "{found:?}");
        assert_eq!(found.hosts, ["evil.example", "github.com"]);
        assert_eq!(found.repositories, 2);
        assert_eq!(found.unencrypted, 1);
        assert_eq!(found.install_scripts, 1);
        assert_eq!(found.redirects, 1);
        let summary = found.summary(Ecosystem::Npm);
        assert!(
            summary
                .contains("2 address(es) outside its registry (hosts: evil.example, github.com)"),
            "{summary}"
        );

        let cargo = "source = \"git+https://example.org/x/y?rev=abc#abc\"\n";
        let found = scan(Ecosystem::Cargo, cargo);
        assert_eq!((found.foreign, found.repositories), (1, 1));

        let pip = "--extra-index-url https://pypi.evil.example/simple\nrequests==2.0\n\
-e git+https://example.org/x.git#egg=x\n";
        let found = scan(Ecosystem::Python, pip);
        assert_eq!((found.redirects, found.foreign), (2, 2), "{found:?}");

        let go = "replace github.com/a/b => ../local\n";
        assert_eq!(scan(Ecosystem::Go, go).redirects, 1);
        // A host is named only when it is one.
        let odd = scan(Ecosystem::Npm, "\"resolved\": \"https://ev il$(x)/a\"\n");
        assert_eq!(odd.hosts, ["ev"]);
        let odd = scan(Ecosystem::Npm, "\"resolved\": \"https://$(x)/a\"\n");
        assert_eq!(odd.hosts, ["an unparseable host"]);
    }

    #[test]
    fn a_foreign_host_does_not_read_as_the_registry() {
        // What stands after a `?`, a `\` or a user's `@` is not the host
        // the client fetches from.
        for (address, host) in [
            (
                "https://evil.example?@registry.npmjs.org/x.tgz",
                "evil.example",
            ),
            (
                "https://evil.example\\@registry.npmjs.org/x.tgz",
                "evil.example",
            ),
            (
                "https://evil.example#@registry.npmjs.org/x.tgz",
                "evil.example",
            ),
            (
                "https://registry.npmjs.org@evil.example/x.tgz",
                "evil.example",
            ),
            (
                "https://user:registry.npmjs.org@evil.example/x.tgz",
                "evil.example",
            ),
            (
                "https://evil.example@registry.npmjs.org/x.tgz",
                "registry.npmjs.org",
            ),
            ("https:\\/\\/evil.example\\/x.tgz", "evil.example"),
            (
                "https:\\u002f\\u002fevil.example/x.tgz",
                "an unparseable host",
            ),
            (
                "https://registry.npmjs.org.evil.example/x.tgz",
                "registry.npmjs.org.evil.example",
            ),
        ] {
            let found = scan(Ecosystem::Npm, &format!("\"resolved\": \"{address}\"\n"));
            assert_eq!(
                (found.foreign, found.addresses),
                (1, 1),
                "{address}: {found:?}"
            );
            assert_eq!(found.hosts, [host], "{address}");
            assert!(
                !found
                    .summary(Ecosystem::Npm)
                    .contains("all on its registry")
            );
        }
        let plain = scan(
            Ecosystem::Npm,
            "\"resolved\":\"https:\\/\\/registry.npmjs.org\\/a.tgz\"",
        );
        assert!(plain.is_plain(), "{plain:?}");
    }

    #[test]
    fn install_scripts_are_counted_however_the_file_is_spaced() {
        let minified = r#"{"a":{"hasInstallScript":true},"b":{"hasInstallScript" :  true},"c":{"hasInstallScript":false},"d":{"hasInstallScript":
true}}"#;
        assert_eq!(scan(Ecosystem::Npm, minified).install_scripts, 3);
        let pnpm = "  a:\n    requiresBuild: true\n  b:\n    requiresBuild:   true\n  c:\n    requiresBuild: false\n";
        assert_eq!(scan(Ecosystem::Npm, pnpm).install_scripts, 2);
    }
}
