//! Local checks of configuration files that run nothing themselves but
//! decide what does: where a browser loads extensions from, which registry
//! a package manager installs from, which address a well-known host name
//! resolves to. Each is a plain rule on the file's lines, so it also covers
//! the files that are never sent to the AI because they hold tokens.

use super::path;
use crate::autorun::Category;
use crate::rules::RuleId;

/// Hosts that updates, packages and the AI review come from: a line in
/// `/etc/hosts` for one of them, or for a name below it, sends that traffic
/// somewhere else.
const WATCHED_HOSTS: &[&str] = &[
    "archlinux.org",
    "omarchy.org",
    "github.com",
    "githubusercontent.com",
    "anthropic.com",
    "claude.ai",
    "claude.com",
    "opencode.ai",
    "openai.com",
    "osv.dev",
    "npmjs.org",
    "npmjs.com",
    "pypi.org",
    "pythonhosted.org",
    "crates.io",
    "rubygems.org",
    "golang.org",
    "jdx.dev",
];

/// The registries each package manager uses when nothing says otherwise.
const USUAL_REGISTRIES: &[&str] = &[
    "registry.npmjs.org",
    "registry.yarnpkg.com",
    "pypi.org",
    "files.pythonhosted.org",
    "rubygems.org",
    "proxy.golang.org",
    "index.crates.io",
    "static.crates.io",
    "crates.io",
    "github.com",
];

/// Browser switches that load code, open the browser to other programs or
/// send its traffic elsewhere.
const BROWSER_SWITCHES: &[&str] = &[
    "--remote-debugging-port",
    "--remote-debugging-address",
    "--remote-debugging-pipe",
    "--proxy-server",
    "--proxy-pac-url",
    "--host-resolver-rules",
    "--host-rules",
    "--disable-web-security",
    "--ignore-certificate-errors",
    "--no-sandbox",
    "--disable-extensions-except",
];

/// Browser policy keys that install extensions, set a proxy or add
/// certificate authorities.
const BROWSER_POLICIES: &[&str] = &[
    "ExtensionInstallForcelist",
    "ExtensionInstallSources",
    "ExtensionSettings",
    "ProxySettings",
    "ProxyServer",
    "ProxyPacUrl",
    "ProxyMode",
    "\"Proxy\"",
    "\"Certificates\"",
    "ImportEnterpriseRoots",
    "DnsOverHttpsTemplates",
    "ManagedConfigurationPerOrigin",
];

/// The most alerts kept for one file.
const MAX_ALERTS: usize = 20;

/// The host of a URL-like value (`https://user:pw@host:8080/x`), in lower
/// case; `None` when there is no host to tell.
fn host(value: &str) -> Option<String> {
    let value = value.trim().trim_matches(['"', '\'', ',']);
    let rest = value.split_once("://").map_or(value, |(_, rest)| rest);
    let authority = rest.split(['/', '?', '#']).next()?;
    let host = authority.rsplit('@').next()?.split(':').next()?;
    (!host.is_empty() && host.contains('.')).then(|| host.to_ascii_lowercase())
}

fn is_usual(host: &str) -> bool {
    USUAL_REGISTRIES
        .iter()
        .any(|usual| host == *usual || host.ends_with(&format!(".{usual}")))
}

/// The key and value of a `key = value`, `key: value` or `key value` line.
fn key_value(line: &str) -> Option<(&str, &str)> {
    // An `=` that is not part of an address comes first: npm scopes a key
    // with a colon (`@scope:registry=`).
    let equals = line
        .find('=')
        .filter(|at| line.find("://").is_none_or(|address| *at < address));
    let at = equals.or_else(|| line.find([':', ' ', '\t']))?;
    let key = line[..at].trim().trim_matches(['"', ':', '-', ' ']);
    let value = line[at + 1..].trim().trim_start_matches(['=', ':']).trim();
    (!key.is_empty() && !value.is_empty()).then_some((key, value))
}

fn browser_flags(line: &str) -> Option<String> {
    if let Some(extensions) = line.strip_prefix("--load-extension=") {
        // An extension a package installed is that package's to vouch for.
        let outside: Vec<&str> = extensions
            .split(',')
            .map(|path| path.trim_matches(['"', '\'']))
            .filter(|path| {
                !(path.starts_with("/usr/") || path.starts_with("/opt/")) || path.contains("..")
            })
            .collect();
        return (!outside.is_empty()).then(|| {
            format!(
                "loads an extension no package installed: {}",
                outside.join(", ")
            )
        });
    }
    BROWSER_SWITCHES
        .iter()
        .find(|switch| line.starts_with(*switch))
        .map(|switch| format!("starts the browser with {switch}"))
}

fn toolchain(name: &str, line: &str) -> Option<String> {
    // A gem source is a list entry, not a key.
    if name == ".gemrc" {
        let odd = line
            .split_whitespace()
            .filter(|word| word.contains("://"))
            .filter_map(host)
            .find(|host| !is_usual(host))?;
        return Some(format!("packages are fetched from {odd}"));
    }
    let (key, value) = key_value(line)?;
    let key = key.to_ascii_lowercase();
    let key = key.trim_start_matches("--");
    // Where packages are fetched from.
    let registry = match name {
        "npmrc" | ".npmrc" | ".yarnrc" | ".yarnrc.yml" | ".bunfig.toml" => {
            key == "registry" || key.ends_with(":registry") || key == "npmregistryserver"
        }
        "pip.conf" | ".pydistutils.cfg" => {
            matches!(
                key,
                "index-url" | "extra-index-url" | "index_url" | "find-links"
            )
        }
        "config.toml" | "config" => key == "registry" || key == "index",
        "env" => key == "goproxy",
        _ => false,
    };
    if registry {
        let odd: Vec<String> = value
            .split([',', '|', ' '])
            .filter(|entry| !matches!(entry.trim_matches(['"', '\'']), "direct" | "off" | ""))
            .filter_map(host)
            .filter(|host| !is_usual(host))
            .collect();
        if !odd.is_empty() {
            return Some(format!("packages are fetched from {}", odd.join(", ")));
        }
    }
    let said = |what: &str| Some(format!("{key}: {what}"));
    match (name, key) {
        ("npmrc" | ".npmrc", "script-shell") => {
            said("install scripts run through a shell of its choosing")
        }
        ("pip.conf" | ".pydistutils.cfg", "trusted-host") => {
            said("a host's certificate is not checked")
        }
        ("config.toml" | "config", "replace-with") => said("crates come from another source"),
        ("env", "goflags") if value.contains("-toolexec") || value.contains("-overlay") => {
            said("every Go build runs through a program of its choosing")
        }
        ("env", "goinsecure" | "gonosumdb" | "gonosumcheck" | "gosumdb")
            if !matches!(value.trim_matches(['"', '\'']), "sum.golang.org") =>
        {
            said("Go modules are fetched without the usual checks")
        }
        (_, "strict-ssl" | "ssl_verify" | "cafile" | "ca") if name.contains("rc") => {
            matches!(value.trim_matches(['"', '\'']), "false" | "0")
                .then(|| format!("{key}: certificates are not checked"))
        }
        _ => None,
    }
}

fn hosts(line: &str) -> Option<String> {
    let line = line.split('#').next().unwrap_or_default();
    let mut words = line.split_whitespace();
    let address = words.next()?;
    let redirected: Vec<&str> = words
        .filter(|name| {
            let name = name.to_ascii_lowercase();
            WATCHED_HOSTS
                .iter()
                .any(|watched| name == *watched || name.ends_with(&format!(".{watched}")))
        })
        .collect();
    (!redirected.is_empty())
        .then(|| format!("{} resolve(s) to {address} here", redirected.join(", ")))
}

fn flatpak(line: &str) -> Option<String> {
    let (key, value) = line.split_once('=')?;
    match key.trim() {
        "filesystems" => {
            let wide: Vec<&str> = value
                .split(';')
                .map(str::trim)
                .filter(|entry| {
                    let place = entry.split(':').next().unwrap_or_default();
                    !entry.starts_with('!')
                        && (matches!(place, "host" | "host-os" | "host-etc" | "home" | "/" | "~")
                            || place.starts_with("~/.ssh")
                            || place.starts_with("~/.config"))
                })
                .collect();
            (!wide.is_empty()).then(|| format!("the sandbox is opened to {}", wide.join(", ")))
        }
        "org.freedesktop.Flatpak" if matches!(value.trim(), "talk" | "own") => {
            Some("the app may start programs outside its sandbox (org.freedesktop.Flatpak)".into())
        }
        _ => None,
    }
}

fn editor(line: &str) -> Option<String> {
    let compact: String = line.chars().filter(|c| !c.is_whitespace()).collect();
    if compact.starts_with("\"security.workspace.trust.enabled\":false") {
        Some("every folder opened is trusted to run its tasks and extensions".into())
    } else if compact.starts_with("\"task.allowAutomaticTasks\":\"on\"") {
        Some("a folder's tasks run as soon as it is opened".into())
    } else {
        None
    }
}

/// What opens a web link or page: the kinds a browser registers for. An
/// app's own scheme (`x-scheme-handler/slack`) is that app's to handle; its
/// launcher is followed and reviewed like any other.
const WEB_KINDS: &[&str] = &[
    "x-scheme-handler/http",
    "x-scheme-handler/https",
    "x-scheme-handler/about",
    "x-scheme-handler/unknown",
    "text/html",
    "application/xhtml+xml",
];

/// What a `mimeapps.list` hands web links to: a launcher from the home
/// that no package ships a namesake of sees every link clicked in another
/// program.
fn handlers(line: &str, there: &dyn Fn(&str) -> bool) -> Option<String> {
    let (kind, launchers) = line.split_once('=')?;
    let kind = kind.trim();
    if !WEB_KINDS.contains(&kind) {
        return None;
    }
    let own: Vec<&str> = launchers
        .split(';')
        .map(str::trim)
        .filter(|launcher| {
            !launcher.is_empty()
                && !launcher.contains('/')
                && there(&format!("~/.local/share/applications/{launcher}"))
                && !there(&format!("/usr/share/applications/{launcher}"))
        })
        .collect();
    (!own.is_empty()).then(|| {
        format!(
            "{kind} opens with {}, a launcher in the home that no package ships",
            own.join(", ")
        )
    })
}

/// The alerts for the text of the file at `path`: what each rule saw, with
/// its line. `there` says whether a file exists (`~` is the home).
pub fn alerts(
    category: Category,
    path: &str,
    text: &str,
    there: &dyn Fn(&str) -> bool,
) -> Vec<(RuleId, String)> {
    let name = path.rsplit('/').next().unwrap_or(path);
    let mut found: Vec<(RuleId, String)> = Vec::new();
    if matches!(category, Category::Shell | Category::Environment) {
        found.extend(
            path::unsafe_entries(text)
                .into_iter()
                .map(|(line, what)| (RuleId::PathHijack, format!("line {line}: {what}"))),
        );
    }
    let policy = category == Category::Browser && path.contains("/policies");
    for (index, line) in text.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') || line.starts_with("//") {
            continue;
        }
        let seen = match category {
            Category::Browser if name.ends_with("-flags.conf") => browser_flags(line),
            Category::Browser if policy => BROWSER_POLICIES
                .iter()
                .find(|key| line.contains(*key))
                .map(|key| format!("the policy sets {}", key.trim_matches('"'))),
            Category::Toolchain => toolchain(name, line),
            Category::TrustStore if name == "hosts" => hosts(line),
            Category::Desktop if name == "mimeapps.list" => handlers(line, there),
            Category::Desktop if path.contains("/flatpak/overrides/") => flatpak(line),
            Category::Editor if name == "settings.json" => editor(line),
            Category::BootConfig if name == "crypttab" && line.contains("keyscript=") => {
                Some("a script is run to unlock a disk (keyscript=)".into())
            }
            _ => None,
        };
        if let Some(seen) = seen
            && found.len() < MAX_ALERTS
        {
            found.push((
                RuleId::RiskyConfiguration,
                format!("line {}: {seen}", index + 1),
            ));
        }
    }
    found
}

#[cfg(test)]
mod tests {
    use super::alerts;
    use crate::autorun::Category;
    use crate::rules::RuleId;

    fn seen(category: Category, path: &str, text: &str) -> Vec<String> {
        alerts(category, path, text, &|file| {
            file == "~/.local/share/applications/open.desktop"
                || file == "~/.local/share/applications/firefox.desktop"
                || file == "/usr/share/applications/firefox.desktop"
        })
        .into_iter()
        .map(|(rule, seen)| {
            assert!(matches!(
                rule,
                RuleId::RiskyConfiguration | RuleId::PathHijack
            ));
            seen
        })
        .collect()
    }

    #[test]
    fn browser_flags_and_policies_that_load_code_or_redirect_are_told() {
        let flags = "--ozone-platform=wayland\n--load-extension=/usr/share/omarchy/default/chromium/extensions/copy-url,/usr/share/x\n--load-extension=/usr/share/x,/home/u/.cache/ext\n# --remote-debugging-port=1\n--remote-debugging-port=9222\n--proxy-server=socks5://10.0.0.1:1080\n";
        let found = seen(
            Category::Browser,
            "home/u/.config/chromium-flags.conf",
            flags,
        );
        assert_eq!(found.len(), 3, "{found:?}");
        assert!(
            found[0].starts_with("line 3: loads an extension")
                && found[0].ends_with("/home/u/.cache/ext")
        );
        assert!(
            found[1].contains("--remote-debugging-port") && found[2].contains("--proxy-server")
        );
        let policy = "{\n  \"ExtensionInstallForcelist\": [\"abc;https://x.example/u.xml\"],\n  \"HomepageLocation\": \"https://x.example\"\n}\n";
        assert_eq!(
            seen(
                Category::Browser,
                "etc/chromium/policies/managed/x.json",
                policy
            ),
            ["line 2: the policy sets ExtensionInstallForcelist"]
        );
        // A native-messaging manifest is followed, not flagged here.
        assert!(
            seen(
                Category::Browser,
                "home/u/.mozilla/native-messaging-hosts/x.json",
                "{\"path\": \"/tmp/x\"}\n"
            )
            .is_empty()
        );
    }

    #[test]
    fn package_manager_settings_that_change_where_packages_come_from_are_told() {
        let npm = "registry=https://registry.npmjs.org/\n@corp:registry=https://npm.evil.example/\n//npm.evil.example/:_authToken=npm_SECRETSECRET\nscript-shell=/tmp/sh\nignore-scripts=false\nstrict-ssl=false\n";
        let found = seen(Category::Toolchain, "home/u/.npmrc", npm);
        assert_eq!(found.len(), 3, "{found:?}");
        assert!(found[0].contains("npm.evil.example") && found[1].contains("script-shell"));
        assert!(found[2].contains("strict-ssl"));
        // A token is never part of what is shown.
        assert!(!found.join(" ").contains("SECRET"));
        let pip = "[global]\nindex-url = https://user:hunter2hunter2@pypi.evil.example/simple\nextra-index-url = https://pypi.org/simple\ntrusted-host = pypi.evil.example\n";
        let found = seen(Category::Toolchain, "home/u/.config/pip/pip.conf", pip);
        assert_eq!(found.len(), 2, "{found:?}");
        assert!(
            found[0].ends_with("fetched from pypi.evil.example") && !found[0].contains("hunter2")
        );
        let cargo = "[build]\nrustc-wrapper = \"/usr/bin/sccache\"\n[source.crates-io]\nreplace-with = \"mirror\"\n[source.mirror]\nregistry = \"sparse+https://crates.evil.example/index/\"\n[registries.ok]\nindex = \"https://github.com/rust-lang/crates.io-index\"\n";
        let found = seen(Category::Toolchain, "home/u/.cargo/config.toml", cargo);
        assert_eq!(found.len(), 2, "{found:?}");
        let go = "GOPROXY=https://goproxy.evil.example,direct\nGOFLAGS=-toolexec=/tmp/x\nGOPATH=/home/u/go\nGONOSUMDB=*\n";
        assert_eq!(
            seen(Category::Toolchain, "home/u/.config/go/env", go).len(),
            3
        );
        let yarn = "npmRegistryServer: \"https://registry.yarnpkg.com\"\n";
        assert!(seen(Category::Toolchain, "home/u/.yarnrc.yml", yarn).is_empty());
    }

    #[test]
    fn hosts_overrides_handlers_and_paths_are_told() {
        let hosts = "127.0.0.1 localhost\n# 10.0.0.1 github.com\n10.0.0.9 pkgs.omarchy.org api.anthropic.com myhost\n::1 localhost\n10.0.0.2 notgithub.com.example\n";
        assert_eq!(
            seen(Category::TrustStore, "etc/hosts", hosts),
            ["line 3: pkgs.omarchy.org, api.anthropic.com resolve(s) to 10.0.0.9 here"]
        );
        let flatpak = "[Context]\nfilesystems=xdg-download;home;!host;/media/x:ro;\n[Session Bus Policy]\norg.freedesktop.Flatpak=talk\norg.gnome.x=talk\n";
        let found = seen(
            Category::Desktop,
            "home/u/.local/share/flatpak/overrides/global",
            flatpak,
        );
        assert_eq!(found.len(), 2, "{found:?}");
        assert!(found[0].ends_with("opened to home"));
        let mime = "[Default Applications]\nx-scheme-handler/https=open.desktop;\nx-scheme-handler/http=firefox.desktop\nimage/png=open.desktop\nx-scheme-handler/slack=open.desktop\n";
        assert_eq!(
            seen(Category::Desktop, "home/u/.config/mimeapps.list", mime),
            [
                "line 2: x-scheme-handler/https opens with open.desktop, a launcher in the home that no package ships"
            ]
        );
        let shell = "export PATH=\"/tmp/bin:$PATH\"\nexport PATH=\"$HOME/bin:$PATH\"\n";
        assert_eq!(seen(Category::Shell, "home/u/.bashrc", shell).len(), 1);
        let code = "{\n  \"editor.fontSize\": 12,\n  \"security.workspace.trust.enabled\": false,\n  \"task.allowAutomaticTasks\": \"on\"\n}\n";
        assert_eq!(
            seen(
                Category::Editor,
                "home/u/.config/Code/User/settings.json",
                code
            )
            .len(),
            2
        );
        assert_eq!(
            seen(
                Category::BootConfig,
                "etc/crypttab",
                "root UUID=x none luks,keyscript=/usr/local/bin/k\n"
            )
            .len(),
            1
        );
    }
}
