//! Tests of the checks of developer tools' settings.

use super::{CLEARTEXT, FROM_TEMPORARY, NOT_SETTINGS, NOT_TOML, alerts, editor, is_temporary};

/// What is seen in `text` at `path`, without the line numbers.
fn seen(path: &str, text: &str) -> Vec<String> {
    alerts(path, text)
        .into_iter()
        .map(|(_, seen)| seen)
        .collect()
}

/// Every line of `must` is told, by a sentence that starts with its
/// key, and none of `must_not` is.
fn told(path: &str, must: &[&str], must_not: &[&str]) {
    for line in must {
        let found = seen(path, &format!("{line}\n"));
        assert_eq!(found.len(), 1, "{path}: {line}: {found:?}");
    }
    let quiet = seen(path, &format!("{}\n", must_not.join("\n")));
    assert!(quiet.is_empty(), "{path}: {quiet:?}");
}

#[test]
fn temporary_and_cache_directories_are_told_from_others() {
    for path in [
        "/tmp/x",
        "\"/var/tmp/x\"",
        "--require /dev/shm/a.js",
        "~/.cache/x",
        "$HOME/.cache/a/b",
    ] {
        assert!(is_temporary(path), "{path}");
    }
    for path in [
        "/home/u/tmp/x",
        "~/tmp/x",
        "/usr/lib/tmpfiles.d/x",
        "~/.cachet/x",
    ] {
        assert!(!is_temporary(path), "{path}");
    }
}

#[test]
fn npm_and_yarn_settings_that_run_load_or_redirect_are_told() {
    told(
        "home/u/.npmrc",
        &[
            "node-options=--require /home/u/x.js",
            "NODE_OPTIONS=--import=/home/u/x.mjs",
            "git=/home/u/bin/git",
            "shell=/home/u/sh",
            "script-shell=/usr/bin/zsh",
            "onload-script=/home/u/x.js",
            "init-module=/home/u/.init.js",
            "https-proxy=http://10.0.0.1:3128",
            "proxy=http://proxy.corp.example:8080",
            "cafile=/home/u/ca.pem",
            "cafile=/tmp/ca.pem",
            "cafile=/etc/ssl/../../home/u/ca.pem",
            "ca=\"-----BEGIN CERTIFICATE-----\"",
            "strict-ssl=false",
            "prefix=/tmp/npm",
            "cache=/dev/shm/npm",
            "globalconfig=/home/u/other",
            "userconfig=/tmp/npmrc",
            "registry=http://registry.npmjs.org/",
            "@corp:registry=https://npm.corp.example/",
        ],
        &[
            "registry=https://registry.npmjs.org/",
            "//registry.npmjs.org/:_authToken=npm_SECRET.SECRET",
            "node-options=--max-old-space-size=4096",
            "prefix=/home/u/.npm-global",
            "prefix=~/.npm-global",
            "@corp:registry=https://npm.pkg.github.com",
            "cafile=/etc/ssl/certs/ca-certificates.crt",
            "cafile=/etc/ca-certificates/extracted/tls-ca-bundle.pem",
            "cafile=/usr/share/ca-certificates/trust-source/x.crt",
            "cache=/home/u/.cache/npm",
            "save-exact=true",
            "ca=null",
            "strict-ssl=true",
            "email=u@corp.example",
        ],
    );
    let graded = seen(
        "home/u/.npmrc",
        "node-options=--require /tmp/x.js\nregistry=http://npm.corp.example/\nproxy=http://u:hunter2@proxy.corp.example:8080\n",
    );
    assert!(graded[0].ends_with(FROM_TEMPORARY), "{graded:?}");
    assert!(graded[1].ends_with(CLEARTEXT), "{graded:?}");
    // A value is never shown, only the host of an address.
    assert!(graded[2].contains("(proxy.corp.example)") && !graded.join(" ").contains("hunter2"));
    told(
        "home/u/.yarnrc.yml",
        &[
            "yarnPath: .yarn/releases/evil.cjs",
            "plugins:",
            "httpProxy: \"http://10.0.0.1:3128\"",
            "httpsProxy: \"http://10.0.0.1:3128\"",
            "caFilePath: /home/u/ca.pem",
            "enableStrictSsl: false",
            "unsafeHttpWhitelist:",
            "npmRegistryServer: \"https://npm.corp.example\"",
        ],
        &[
            "npmRegistryServer: \"https://registry.yarnpkg.com\"",
            "enableStrictSsl: true",
            "nodeLinker: node-modules",
            "enableTelemetry: false",
            "npmAuthToken: \"abc.def.SECRET\"",
        ],
    );
    told(
        "home/u/.yarnrc",
        &[
            "yarn-path \"/home/u/yarn.js\"",
            "registry \"https://npm.corp.example\"",
            "strict-ssl false",
            "https-proxy \"http://10.0.0.1:3128\"",
            "cafile \"/home/u/ca.pem\"",
        ],
        &[
            "registry \"https://registry.yarnpkg.com\"",
            "lastUpdateCheck 1700000000",
        ],
    );
}

#[test]
fn bun_and_pip_settings_that_run_load_or_redirect_are_told() {
    told(
        "home/u/.bunfig.toml",
        &[
            "preload = [\"/home/u/x.ts\"]",
            "[install]\nregistry = \"https://npm.corp.example\"",
            "[install]\nregistry = { url = \"https://npm.corp.example\", token = \"abc.SECRET\" }",
            "[install.scopes]\n\"@corp\" = \"https://npm.corp.example\"",
            "[install]\ncafile = \"/home/u/ca.pem\"",
            "[run]\nshell = \"/home/u/sh\"",
        ],
        &[
            "telemetry = false",
            "[install]\nregistry = \"https://registry.npmjs.org\"",
            "[install]\nregistry = { url = \"https://registry.npmjs.org\", token = \"abc.SECRET\" }",
            "[run]\nshell = \"system\"\nbun = true",
            "[test]\ncoverage = true",
        ],
    );
    assert!(
        !seen(
            "home/u/.bunfig.toml",
            "[install]\nregistry = { url = \"https://npm.corp.example\", token = \"abc.SECRET\" }\n"
        )
        .join(" ")
        .contains("SECRET")
    );
    for path in [
        "home/u/.config/pip/pip.conf",
        "home/u/.pip/pip.conf",
        "home/u/.pydistutils.cfg",
    ] {
        told(
            path,
            &[
                "index-url = http://pypi.corp.example/simple",
                "extra-index-url = http://pypi.org/simple",
                "index-url = https://10.0.0.9/simple",
                "index-url = https://[fd00::9]:8443/simple",
                "extra-index-url = https://xn--pyp-qma.org/simple",
                "extra-index-url = https://github.com.evil.example/simple",
                "index-url = https://webhook.site/simple",
                "find-links = /tmp/wheels",
                "find-links = https://wheels.corp.example/",
                "trusted-host = pypi.corp.example",
                "proxy = http://10.0.0.1:3128",
                "cert = /home/u/ca.pem",
                "client-cert = /home/u/me.pem",
            ],
            &[
                "[global]",
                "index-url = https://pypi.org/simple",
                // A project's or a company's own index, over HTTPS.
                "extra-index-url = https://download.pytorch.org/whl/cpu",
                "index-url = https://files.pythonhosted.org/simple",
                "index-url = https://user:hunter2@pypi.corp.example/simple",
                "index-url = http://localhost:3141/root/pypi",
                "cert = /etc/ssl/certs/ca-certificates.crt",
                "timeout = 60",
                "no-index = true",
                "user-agent = x",
                "require-virtualenv = true",
            ],
        );
    }
    let wheels = seen("home/u/.pip/pip.conf", "find-links = /tmp/wheels\n");
    assert!(wheels[0].ends_with(FROM_TEMPORARY), "{wheels:?}");
}

#[test]
fn go_and_cargo_settings_that_run_load_or_redirect_are_told() {
    told(
        "home/u/.config/go/env",
        &[
            "GOPROXY=https://goproxy.corp.example,direct",
            "GOFLAGS=-toolexec=/home/u/x",
            "GOINSECURE=*.corp.example",
            "GONOSUMCHECK=1",
            "GOSUMDB=off",
            "GONOSUMDB=*",
            "GOPRIVATE=github.com",
            "GOPRIVATE=*.com",
            "CC=/home/u/cc",
            "CXX=evil++",
            "GOAUTH=/home/u/auth https://x",
            "GOBIN=/tmp/bin",
        ],
        &[
            "GOPROXY=https://proxy.golang.org,direct",
            "GOPATH=/home/u/go",
            "GOSUMDB=sum.golang.org",
            "GOPRIVATE=github.com/corp/*,*.corp.example",
            "GOPRIVATE=github.com/mycorp/*",
            "GONOSUMDB=git.corp.example",
            "CC=clang",
            "GOAUTH=netrc",
            "GOBIN=/home/u/go/bin",
            "GOFLAGS=-mod=mod",
            "GOTOOLCHAIN=local",
        ],
    );
    told(
        "home/u/.cargo/config.toml",
        &[
            "[http]\nproxy = \"http://10.0.0.1:3128\"",
            "[http]\ncainfo = \"/home/u/ca.pem\"",
            "[http]\ncheck-revoke = false",
            "[env]\nRUSTC_WRAPPER = \"/home/u/w\"",
            "[env]\nCC = \"/tmp/cc\"",
            "[env]\nCC = { value = \"bin/cc\", relative = true }",
            "[env]\nPATH = \"/home/u/bin\"",
            "[build]\nrustflags = [\"-C\", \"linker=/tmp/ld\"]",
            "[env]\nLD_PRELOAD = { value = \"/home/u/x.so\", force = true }",
            "[target.x86_64-unknown-linux-gnu]\nlinker = \"/home/u/ld\"",
            "[target.x86_64-unknown-linux-gnu]\nrunner = \"/tmp/run\"",
            "[target.x86_64-unknown-linux-gnu]\nrustflags = [\"-C\", \"linker=/home/u/ld\"]",
            "[build]\nrustflags = [\"-Clinker=/home/u/ld\"]",
            "[build]\nrustc = \"/home/u/rustc\"",
            "[build]\nrustdoc = \"/home/u/rustdoc\"",
            "[build]\nrustc-wrapper = \"/home/u/.cache/w\"",
            "[build]\nrustc-workspace-wrapper = \"./w\"",
            "[registries.corp]\nindex = \"sparse+https://crates.corp.example/index/\"",
            "[source.crates-io]\nreplace-with = \"mirror\"",
            "[source.mirror]\nregistry = \"http://crates.corp.example/index\"",
            "[registry]\nglobal-credential-providers = [\"/home/u/provider\"]",
            "[registries.corp]\ncredential-provider = [\"/home/u/provider\", \"--x\"]",
            "[alias]\nb = \"build --config /home/u/c.toml\"",
            "paths = [\"/home/u/crate\"]",
            "[patch.crates-io]\nserde = { path = \"/tmp/serde\" }",
        ],
        &[
            "[http]\ntimeout = 30\ncheck-revoke = true",
            "[net]\ngit-fetch-with-cli = true",
            "[env]\nCARGO_TERM_COLOR = \"always\"",
            // A system compiler by its name or path, as the direct
            // keys take it.
            "[env]\nCC = \"clang\"\nCXX = { value = \"/usr/bin/clang++\", force = true }",
            "[build]\nrustflags = [\"-C\", \"linker=clang\"]",
            "[target.x86_64-unknown-linux-gnu]\nrustflags = [\"-Clinker=/usr/bin/clang\", \"-C\", \"link-arg=-fuse-ld=mold\"]",
            "[build]\nrustc-wrapper = \"sccache\"",
            "[build]\nrustc-wrapper = \"/usr/bin/sccache\"\njobs = 8",
            "[target.x86_64-unknown-linux-gnu]\nlinker = \"clang\"\nrustflags = [\"-C\", \"link-arg=-fuse-ld=mold\"]",
            "[registries.ok]\nindex = \"https://github.com/rust-lang/crates.io-index\"",
            "[registry]\nglobal-credential-providers = [\"cargo:token\", \"cargo:libsecret\"]",
            "[alias]\nb = \"build --release\"",
            "[term]\ncolor = \"always\"",
        ],
    );
    // Mise shares the file name and is reviewed as text.
    assert!(
        seen(
            "home/u/.config/mise/config.toml",
            "[env]\nPATH = \"/tmp\"\n"
        )
        .is_empty()
    );
}

#[test]
fn gem_conda_wget_and_curl_settings_that_redirect_are_told() {
    told(
        "home/u/.gemrc",
        &[
            "- https://gems.corp.example/",
            "gem: --source https://gems.corp.example",
            "gem: --http-proxy http://10.0.0.1:3128",
            ":http_proxy: http://10.0.0.1:3128",
            ":ssl_verify_mode: 0",
            ":ssl_ca_cert: /home/u/ca.pem",
        ],
        &[
            "---",
            ":sources:",
            "- https://rubygems.org/",
            "gem: --no-document",
            ":ssl_verify_mode: 1",
        ],
    );
    told(
        "home/u/.condarc",
        &[
            "  - https://conda.corp.example/pkgs",
            "channel_alias: https://conda.corp.example",
            "ssl_verify: false",
            "ssl_verify: /home/u/ca.pem",
            "proxy_servers:",
            "  http: http://10.0.0.1:3128",
        ],
        &[
            "channels:",
            "  - conda-forge",
            "  - defaults",
            "ssl_verify: true",
            "auto_activate_base: false",
        ],
    );
    told(
        "home/u/.wgetrc",
        &[
            "check_certificate = off",
            "check-certificate=off",
            "http_proxy = http://10.0.0.1:3128/",
            "https_proxy = http://10.0.0.1:3128/",
            "ca_certificate = /home/u/ca.pem",
            "use_askpass = /home/u/ask",
            "output_document = /home/u/.bashrc",
        ],
        &[
            "check_certificate = on",
            "use_proxy = on",
            "tries = 3",
            "timestamping = on",
        ],
    );
    told(
        "home/u/.curlrc",
        &[
            "insecure",
            "-k",
            "--insecure",
            "proxy = http://10.0.0.1:3128",
            "-x socks5://10.0.0.1:1080",
            "--proxy=\"http://10.0.0.1:3128\"",
            "cacert = /home/u/ca.pem",
            "capath = /tmp/certs",
            "resolve = pypi.org:443:10.0.0.9",
            "output = /home/u/.bashrc",
            "-K /home/u/other",
            "trace-ascii = /tmp/t",
        ],
        &[
            "silent",
            "-s",
            "--location",
            "-L",
            "--silent",
            "cacert = /etc/ssl/certs/ca-certificates.crt",
            "user-agent = \"x\"",
            "connect-timeout = 10",
            "# insecure",
        ],
    );
}

#[test]
fn editor_settings_that_run_load_or_redirect_are_told() {
    let lines =
        |text: &str| -> Vec<usize> { editor(text).into_iter().map(|(line, _)| line).collect() };
    let settings = r#"{
  // "git.path": "/tmp/commented",
  "editor.fontSize": 12,
  "security.workspace.trust.enabled": false,
  "task.allowAutomaticTasks": "on",
  "terminal.integrated.env.linux": {
    "EDITOR_THEME": "dark",
    "LD_PRELOAD": "/home/u/x.so"
  },
  "terminal.integrated.profiles.linux": {
    "bash": { "path": "bash", "icon": "terminal-bash" },
    "odd": {
      "path": "/home/u/.local/sh",
      "args": ["-c", "curl x | sh"]
    }
  },
  "terminal.integrated.defaultProfile.linux": "odd",
  "terminal.integrated.automationProfile.linux": { "path": "/tmp/sh" },
  "terminal.integrated.shellArgs.linux": ["-c", "x"],
  "git.path": "/home/u/bin/git",
  "http.proxy": "http://u:hunter2@10.0.0.1:3128",
  "http.proxyStrictSSL": false,
  "python.defaultInterpreterPath": "/tmp/venv/bin/python",
  "clangd.path": "/home/u/.cache/clangd/clangd",
  "extensions.autoUpdate": true
}
"#;
    assert_eq!(
        lines(settings),
        [4, 5, 8, 13, 14, 18, 19, 20, 21, 22, 23, 24]
    );
    let found = editor(settings);
    assert!(!found.iter().any(|(_, seen)| seen.contains("hunter2")));
    assert!(found[5].1.ends_with(FROM_TEMPORARY), "{found:?}");
    let quiet = r#"{
  "terminal.integrated.env.linux": { "FOO": "bar", "EDITOR": "nvim", "CC": "clang" },
  "terminal.integrated.env.osx": {
    "VISUAL": "/home/u/bin/edit",
    "PAGER": "less",
    "LANG": "en_US.UTF-8",
    "TERM": "xterm-256color",
    "RUSTC_WRAPPER": "/usr/bin/sccache"
  },
  "terminal.integrated.defaultProfile.linux": "zsh",
  "python.defaultInterpreterPath": "/home/u/.cache/pypoetry/virtualenvs/app-x-py3.12/bin/python",
  "python.pythonPath": "~/.local/share/virtualenvs/app-x/bin/python",
  "mypy.interpreter.path": "/home/u/.cache/uv/environments-v2/x/bin/python",
  "terminal.integrated.profiles.linux": { "zsh": { "path": "/usr/bin/zsh", "args": ["-l"] } },
  "git.path": "/usr/bin/git",
  "http.proxyStrictSSL": true,
  "python.defaultInterpreterPath": "/home/u/.venv/bin/python",
  "rust-analyzer.server.path": "~/.cargo/bin/rust-analyzer",
  "security.workspace.trust.enabled": true,
  "files.exclude": { "**/.git": true }
}
"#;
    assert!(editor(quiet).is_empty(), "{:?}", editor(quiet));
    // The variables that change what the terminal's programs run or
    // load, and a compiler from the home.
    let loading = "{\n\"terminal.integrated.env.linux\": {\n\"PATH\": \"/home/u/bin:${env:PATH}\",\n\"GIT_CONFIG_GLOBAL\": \"/home/u/x\",\n\"https_proxy\": \"http://10.0.0.1:3128\",\n\"CC\": \"/home/u/bin/cc\",\n\"GIT_SSH_COMMAND\": \"ssh -i x\",\n\"MY_APP_MODE\": \"dev\"\n}\n}\n";
    assert_eq!(lines(loading), [3, 4, 5, 6, 7]);
    assert_eq!(
        lines(
            "{\n\"terminal.integrated.env.linux\": { \"A\": \"1\", \"NODE_OPTIONS\": \"--require /x.js\" }\n}\n"
        ),
        [2]
    );
}

#[test]
fn an_editors_settings_are_read_by_key_wherever_on_a_line_it_stands() {
    let lines =
        |text: &str| -> Vec<usize> { editor(text).into_iter().map(|(line, _)| line).collect() };
    // On one line, on the line of the brace, after another key.
    assert_eq!(lines(r#"{"git.path":"/tmp/x"}"#), [1]);
    // A comment ends at a lone carriage return, as it does for the
    // editor, and a `\u` escape is four hex digits and no sign.
    assert_eq!(lines("{ // x\r\"git.path\": \"/tmp/x\",\n\"a\": 1 }"), [2]);
    for separator in ['\u{2028}', '\u{2029}'] {
        let text = format!("{{ // x{separator}\"git.path\": \"/tmp/x\",\n\"a\": 1 }}");
        let found = editor(&text);
        assert_eq!(found.len(), 1, "{text:?}");
        assert!(found[0].1.starts_with("git.path"), "{found:?}");
    }
    assert_eq!(lines("{\"git.p\\u+061th\": \"/tmp/x\"}").len(), 1);
    assert!(
        editor("{\"git.p\\u+061th\": \"/tmp/x\"}")[0]
            .1
            .contains("cannot be read")
    );
    assert_eq!(
        lines(r#"{ "security.workspace.trust.enabled": false }"#),
        [1]
    );
    assert_eq!(
        lines("{ \"git.path\": \"/home/u/bin/git\",\n  \"editor.fontSize\": 12 }\n"),
        [1]
    );
    assert_eq!(
        lines(
            "{\n  \"editor.fontSize\": 12, \"http.proxyStrictSSL\": false,\n\n  \"task.allowAutomaticTasks\": \"on\" }"
        ),
        [2, 4]
    );
    // A value that goes over several lines, at the line of its key.
    assert_eq!(
        lines("{\n  \"terminal.integrated.shellArgs.linux\": [\n    \"-c\",\n    \"x\"\n  ]\n}\n"),
        [2]
    );
    assert_eq!(lines("{\n  \"git.path\":\n\n    \"/tmp/x\"\n}\n"), [2]);
    // A terminal table on one line with the rest, and its keys below.
    assert_eq!(
        lines("{\"a\": 1, \"terminal.integrated.env.linux\": {\"LD_PRELOAD\": \"/x.so\"}}"),
        [1]
    );
    assert_eq!(
        lines(
            "{\"terminal.integrated.profiles.linux\": {\"odd\": {\n\"path\": \"/tmp/sh\", \"args\": [\n\"-c\", \"x\"]}}}"
        ),
        [2, 2]
    );
    // A key in a table of another key's (a language's own settings).
    assert_eq!(
        lines("{\"[python]\": {\"python.defaultInterpreterPath\": \"/tmp/v/python\"}}"),
        [1]
    );
    // Comments and a comma after the last entry, as editors allow; a
    // key after a comment on its line; nothing inside a comment or a
    // string.
    let commented = "// \"git.path\": \"/tmp/a\"\n{\n  /* \"git.path\": \"/tmp/b\",\n     \"http.proxyStrictSSL\": false */\n  /* own */ \"git.path\": \"/tmp/c\", // \"git.path\": \"/tmp/d\"\n  \"x.note\": \"\\\"git.path\\\": \\\"/tmp/e\\\" // */ /*\",\n  \"x.list\": [1, 2,],\n}\n";
    assert_eq!(lines(commented), [5]);
    // Escapes are read before a key or a value is looked at.
    assert_eq!(lines(r#"{"git.p\u0061th": "\/tmp\/x"}"#), [1]);
    assert_eq!(
        lines(r#"{"terminal.integrated.shellArgs.linux": ["\u002dc", "x \ud83d\ude00"]}"#),
        [1]
    );
    // Nothing to read is nothing to say.
    for empty in ["", "\n", "// none\n", "/* none */", "{}", "\u{feff}{ }\n"] {
        assert_eq!(lines(empty), [0; 0], "{empty:?}");
    }
}

#[test]
fn an_editors_settings_that_cannot_be_read_to_the_end_are_said_to_be() {
    let unread = |text: &str| -> Option<usize> {
        let found = editor(text);
        assert!(found.len() <= 1 || found.iter().all(|(_, seen)| seen != NOT_SETTINGS));
        found
            .into_iter()
            .find(|(_, seen)| seen == NOT_SETTINGS)
            .map(|(line, _)| line)
    };
    for (text, line) in [
        // Cut short, in a table, a string or a comment.
        ("{\"git.path\": \"/tmp/x\"", 1),
        ("{\n\"git.path\": \"/tmp/x", 2),
        ("{\n\"a\": 1 /* \"git.path\": \"/tmp/x\"\n}\n", 3),
        // What an editor reads on past: a missing comma, a missing
        // value, a key without quotes, a string over two lines.
        ("{\n\"a\": 1\n\"git.path\": \"/tmp/x\"\n}\n", 3),
        ("{\n\"a\":\n}\n", 3),
        ("{\ngit.path: \"/tmp/x\"\n}\n", 2),
        ("{\"a\": \"x\ny\", \"git.path\": \"/tmp/x\"}", 1),
        ("{\"a\": \"\\x\"}", 1),
        ("{\"a\": 'x'}", 1),
        // No table of settings, or more after it.
        ("[]", 1),
        ("\"git.path\"", 1),
        ("{}\n{\"git.path\": \"/tmp/x\"}\n", 2),
        ("{}}", 1),
    ] {
        assert_eq!(unread(text), Some(line), "{text:?}");
    }
    // Deeper than any settings go.
    let deep = format!("{{\"a\": {}1{}}}", "[".repeat(100), "]".repeat(100));
    assert_eq!(unread(&deep), Some(1));
    let fine = format!("{{\"a\": {}1{}}}", "[".repeat(20), "]".repeat(20));
    assert_eq!(unread(&fine), None);
    // It is a finding of the file, at its line.
    let told = crate::sweep::config::alerts(
        crate::autorun::Category::Editor,
        "home/u/.config/Code/User/settings.json",
        "{\n  \"git.path\": \"/tmp/x\"\n",
        &|_| false,
    );
    assert_eq!(
        told,
        [(
            crate::rules::RuleId::RiskyConfiguration,
            format!("line 2: {NOT_SETTINGS}")
        )]
    );
}

#[test]
fn an_editors_settings_are_read_whatever_they_hold() {
    use crate::test_support::Rng;
    const PIECES: &[&str] = &[
        "{",
        "}",
        "[",
        "]",
        ":",
        ",",
        "\"",
        "\\",
        "\\u",
        "d83d",
        "//",
        "/*",
        "*/",
        "\n",
        " ",
        "\"git.path\"",
        "\"/tmp/x\"",
        "\"terminal.integrated.env.linux\"",
        "true",
        "1",
        "é",
    ];
    let settings = "{\n  // one\n  \"git.path\": \"/tmp/x\", /* two */\n  \"terminal.integrated.env.linux\": { \"LD_PRELOAD\": \"/x.so\" },\n  \"x\": [1, {\"path\": \"\\u00e9\"}],\n}\n";
    assert_eq!(editor(settings).len(), 2);
    let check = |text: &str| {
        let lines = text.lines().count().max(1);
        for (line, seen) in editor(text) {
            assert!((1..=lines).contains(&line), "{text:?}: {line}");
            assert!(!seen.is_empty());
        }
    };
    let mut rng = Rng::new(7);
    for _ in 0..10_000 {
        check(&rng.text(PIECES, 16));
        check(&rng.mutated(settings, PIECES));
    }
}

#[test]
fn toml_settings_are_read_by_key_however_they_are_written() {
    let cargo = "home/u/.cargo/config.toml";
    let lines = |path: &str, text: &str| -> Vec<usize> {
        alerts(path, text)
            .into_iter()
            .map(|(line, _)| line)
            .collect()
    };
    // A dotted key, a key in quotes, an inline table, and one in
    // another; a value over several lines, at the line of its key.
    for (text, line) in [
        ("build.rustc-wrapper = \"/tmp/w\"\n", 1),
        ("\"build\".\"rustc-wrapper\" = \"/tmp/w\"\n", 1),
        ("build = { rustc-wrapper = \"/tmp/w\" }\n", 1),
        ("build = { jobs = 8, rustc-wrapper = \"/tmp/w\" }\n", 1),
        (
            "http = { timeout = 30, proxy = \"http://10.0.0.1:3128\" }\n",
            1,
        ),
        ("env.LD_PRELOAD = \"/home/u/x.so\"\n", 1),
        // A variable as a table of its own, in each way to write one,
        // and a file that begins with a byte order mark.
        ("[env.LD_PRELOAD]\nvalue = \"/home/u/x.so\"\n", 2),
        ("env.LD_PRELOAD.value = \"/home/u/x.so\"\n", 1),
        ("[env]\nLD_PRELOAD.value = \"/home/u/x.so\"\n", 2),
        ("[env]\nCC = { \"value\" = \"/home/u/cc\" }\n", 2),
        ("\u{feff}build.rustc-wrapper = \"/tmp/w\"\n", 1),
        (
            "env = { A = \"x, y\", LD_PRELOAD = { value = \"/home/u/x.so\", force = true } }\n",
            1,
        ),
        (
            "target = { x86_64-unknown-linux-gnu = { linker = \"/home/u/ld\" } }\n",
            1,
        ),
        (
            "[target]\nx86_64-unknown-linux-gnu.runner = \"/tmp/run\"\n",
            2,
        ),
        (
            "registries.corp = { index = \"sparse+https://crates.corp.example/index/\" }\n",
            1,
        ),
        (
            "[build]\nrustflags = [\n  \"-C\",\n  \"linker=/tmp/ld\",\n]\n",
            2,
        ),
    ] {
        assert_eq!(lines(cargo, text), [line], "{text}");
    }
    assert_eq!(
        lines(
            cargo,
            "[build]\njobs = 8\nrustflags = [\n  \"-Clinker=/tmp/ld\",\n]\n"
        ),
        [3]
    );
    assert_eq!(
        lines(
            "home/u/.bunfig.toml",
            "install.registry = \"https://npm.corp.example\"\nrun = { shell = \"/home/u/sh\" }\n"
        ),
        [1, 2]
    );
    // The same written of what is fine says nothing.
    for text in [
        "build.rustc-wrapper = \"sccache\"\nbuild = { jobs = 8 }\n",
        "env = { CC = \"clang\", NOTE = \"LD_PRELOAD = /x.so, rustc = /tmp/x\" }\n",
        "registries.ok = { index = \"https://github.com/rust-lang/crates.io-index\" }\n",
        "[profile.release]\nlto = true\ndebug = { level = 1 }\n",
    ] {
        assert_eq!(lines(cargo, text), [0; 0], "{text}");
    }
    // A file that is no TOML is read line by line, and said to be.
    let broken = "[build]\nrustc-wrapper = \"/tmp/w\"\nnot toml at all\n";
    let found = alerts(cargo, broken);
    assert_eq!(found.len(), 2, "{found:?}");
    assert_eq!(found[0], (3, NOT_TOML.to_string()));
    assert_eq!(found[1].0, 2);
}
