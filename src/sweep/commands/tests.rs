//! Tests of what an auto-run file starts.

use std::fs;

use super::{commands, targets, targets_where};
use crate::autorun::Category;
use crate::test_support::TempDir;

#[test]
fn a_shell_script_is_told_by_its_first_line_or_its_name() {
    use super::is_shell_script;
    for first in [
        "#!/bin/sh",
        "#! /bin/bash -e",
        "#!/usr/bin/env bash",
        "#!/usr/bin/env -S bash -e",
        "#!/usr/bin/env -S -i bash",
        "#!/usr/bin/env -u VAR bash",
        "#!/usr/bin/env A=1 zsh",
        "#!/bin/busybox sh",
        "#!/bin/ash",
        "#!/bin/mksh",
        "\u{feff}#!/bin/sh",
    ] {
        assert!(is_shell_script("x", &format!("{first}\ntrue\n")), "{first}");
    }
    for first in [
        "#!/usr/bin/python3",
        "#!/usr/bin/env python3",
        "#!/usr/bin/fish",
        "#!/bin/busybox awk",
        "#!/usr/bin/env -u bash python3",
    ] {
        assert!(
            !is_shell_script("x.sh", &format!("{first}\ntrue\n")),
            "{first}"
        );
    }
    // Without such a line, the name says.
    assert!(is_shell_script("run.sh", "true\n"));
    assert!(!is_shell_script("run", "true\n"));
}

#[test]
fn commands_are_found_per_kind_of_file() {
    assert_eq!(
        commands(
            Category::Systemd,
            "x.service",
            "[Service]\nExecStartPre=-/usr/bin/true\nExecStart=/home/u/.cache/run.sh --now\nEnvironment=A=1\n"
        ),
        ["/usr/bin/true", "/home/u/.cache/run.sh --now"]
    );
    assert_eq!(
        commands(
            Category::Autostart,
            "x.desktop",
            "[Desktop Entry]\nExec=foo %u\nTryExec=foo\n"
        ),
        ["foo"]
    );
    assert_eq!(
        commands(
            Category::Udev,
            "99.rules",
            "ACTION==\"add\", RUN+=\"/usr/local/bin/x $kernel\"\n"
        ),
        ["/usr/local/bin/x $kernel"]
    );
    assert_eq!(
        commands(
            Category::Kernel,
            "x.conf",
            "install usb-storage /bin/sh -c 'curl x|sh'\noptions x y=1\n"
        ),
        ["/bin/sh -c 'curl x|sh'"]
    );
    assert_eq!(
        commands(
            Category::Pam,
            "x",
            "auth optional pam_exec.so quiet /usr/local/bin/log\n"
        ),
        ["/usr/lib/security/pam_exec.so", "/usr/local/bin/log"]
    );
    assert_eq!(
        commands(Category::Ssh, "config", "Host x\n  ProxyCommand nc %h %p\n"),
        ["nc %h %p"]
    );
    assert_eq!(
        commands(Category::Hyprland, "a.conf", "exec-once = waybar\n$x = 1\n"),
        ["waybar"]
    );
    // Crontabs: time fields, the system crontabs' user field, no
    // `Key=value` reading.
    assert_eq!(
        commands(
            Category::Cron,
            "var/spool/cron/u",
            "MAILTO=u\nExecStart=/etc/shadow\n*/5 * * * * /home/u/x.sh --now\n@reboot ~/y\n"
        ),
        ["/home/u/x.sh --now", "~/y"]
    );
    assert_eq!(
        commands(
            Category::Cron,
            "etc/cron.d/x",
            "0 3 * * mon root /usr/bin/z\n"
        ),
        ["/usr/bin/z"]
    );
    assert!(commands(Category::Cron, "etc/cron.daily/x", "#!/bin/sh\ncurl x\n").is_empty());
}

#[test]
fn patterns_variables_and_subshells_lead_to_their_files() {
    use super::glob_targets;
    let list = |directory: &str| {
        assert_eq!(directory, "home/u/.config/hypr/conf.d");
        vec![
            "a.conf".to_string(),
            "b.conf".to_string(),
            "notes.md".to_string(),
            ".hidden.conf".to_string(),
        ]
    };
    let (matched, more) = glob_targets("home/u", "~/.config/hypr/conf.d/*.conf", &list);
    assert_eq!(
        matched,
        [
            "home/u/.config/hypr/conf.d/a.conf",
            "home/u/.config/hypr/conf.d/b.conf"
        ]
    );
    assert!(!more);
    assert!(
        glob_targets("home/u", "~/x/*/y.conf", &|_| Vec::new())
            .0
            .is_empty()
    );
    // More files than a pattern is followed to: said, not dropped.
    let many = |_: &str| (0..=super::MAX_GLOB).map(|n| format!("{n}.conf")).collect();
    let (matched, more) = glob_targets("home/u", "~/d/*.conf", &many);
    assert_eq!(matched.len(), super::MAX_GLOB);
    assert!(more);
    assert_eq!(
        commands(
            Category::Hyprland,
            "home/u/.config/hypr/hyprland.conf",
            "source = ~/.config/hypr/conf.d/*.conf\n"
        ),
        ["~/.config/hypr/conf.d/*.conf"]
    );
    // A variable that names others is not written out: no growth.
    let mut grow = (0..32)
        .map(|index| format!("V{index}=/x{}", format!("$V{}", index + 1).repeat(20)))
        .collect::<Vec<_>>()
        .join("\n");
    grow.push('\n');
    grow.push_str("$V0/run\n");
    assert!(commands(Category::Shell, "home/u/.bashrc", &grow).len() <= 1);
    // A path in a variable, and a subshell's last program.
    assert_eq!(
        commands(
            Category::Shell,
            "home/u/.bashrc",
            "TOOLS=~/opt/tools\n$TOOLS/agent &\n(cd /tmp && ~/bin/y)\n",
        ),
        ["~/opt/tools/agent", "~/bin/y"]
    );
}

#[test]
fn terminals_and_prompts_name_what_they_run() {
    let terminal = |path: &str, text: &str| commands(Category::Terminal, path, text);
    assert_eq!(
        terminal(
            "home/u/.config/alacritty/alacritty.toml",
            "[terminal.shell]\nprogram = \"/tmp/sh\"\nargs = [\"-l\"]\n[font]\nsize = 9\n"
        ),
        ["/tmp/sh"]
    );
    assert_eq!(
        terminal(
            "home/u/.alacritty.toml",
            "shell = { program = \"/usr/bin/fish\", args = [\"-l\"] }\n"
        ),
        ["/usr/bin/fish"]
    );
    assert_eq!(
        terminal(
            "home/u/.config/kitty/kitty.conf",
            "font_size 11\nshell /tmp/sh --login\nshell_integration enabled\nstartup_session ~/.config/kitty/s.conf\nwatcher ~/w.py\nshell .\n"
        ),
        ["/tmp/sh --login", "~/.config/kitty/s.conf", "~/w.py"]
    );
    assert_eq!(
        terminal(
            "home/u/.config/ghostty/config",
            "font-size = 9\ncommand = /tmp/sh\ninitial-command = ~/bin/first\n"
        ),
        ["/tmp/sh", "~/bin/first"]
    );
    assert_eq!(
        terminal(
            "home/u/.config/foot/foot.ini",
            "[main]\nshell=/tmp/sh\nfont=x\n"
        ),
        ["/tmp/sh"]
    );
    assert_eq!(
        terminal(
            "home/u/.config/starship.toml",
            "[custom.x]\ncommand = \"~/bin/prompt\"\nwhen = \"test -d .git\"\nformat = \"$output\"\n[custom.y]\nwhen = true\n"
        ),
        ["~/bin/prompt", "test -d .git"]
    );
    assert_eq!(
        terminal(
            "home/u/.tmux.conf",
            "set -g default-command \"/tmp/sh\"\nrun-shell -b '~/bin/tmux-start'\nset -g mouse on\nsource-file ~/.tmux.local\n"
        ),
        ["/tmp/sh", "~/bin/tmux-start", "~/.tmux.local"]
    );
}

#[test]
fn tools_manifests_and_handlers_name_what_they_run() {
    let tool = |path: &str, text: &str| commands(Category::Toolchain, path, text);
    assert_eq!(
        tool(
            "home/u/.cargo/config.toml",
            "[build]\nrustc-wrapper = \"/tmp/wrap\"\njobs = 4\n[target.x86_64-unknown-linux-gnu]\nlinker = \"clang\"\nrunner = [\"~/bin/run\", \"--x\"]\n"
        ),
        ["/tmp/wrap", "clang", "~/bin/run --x"]
    );
    assert_eq!(
        tool(
            "home/u/.config/mise/config.toml",
            "[env]\n_.source = \"~/.secrets.sh\"\nNODE_ENV = \"x\"\n[hooks]\nenter = \"~/bin/on-enter\"\n[tasks.build]\nrun = \"make\"\n"
        ),
        ["~/.secrets.sh", "~/bin/on-enter", "make"]
    );
    assert_eq!(
        tool(
            "home/u/.npmrc",
            "registry=https://x.example/\nscript-shell=/tmp/sh\n"
        ),
        ["/tmp/sh"]
    );
}

#[test]
fn package_managers_manifests_and_handlers_name_what_they_run() {
    let tool = |path: &str, text: &str| commands(Category::Toolchain, path, text);
    assert_eq!(
        tool(
            "home/u/.npmrc",
            "node-options=--max-old-space-size=4096 --require /home/u/a.js --import=/home/u/b.mjs\ngit=/home/u/bin/git\nonload-script=~/c.js\nprefix=/home/u/.npm-global\n"
        ),
        ["/home/u/a.js", "/home/u/b.mjs", "/home/u/bin/git", "~/c.js"]
    );
    assert_eq!(
        tool(
            "home/u/.yarnrc.yml",
            "nodeLinker: node-modules\nyarnPath: .yarn/releases/yarn.cjs\n"
        ),
        ["~/.yarn/releases/yarn.cjs"]
    );
    assert_eq!(
        tool("home/u/.yarnrc", "yarn-path \"/home/u/yarn.js\"\n"),
        ["/home/u/yarn.js"]
    );
    assert_eq!(
        tool(
            "home/u/.config/go/env",
            "GOFLAGS=-mod=mod -toolexec=/tmp/x\nGOPATH=/home/u/go\nCC=/home/u/cc\n"
        ),
        ["/tmp/x", "/home/u/cc"]
    );
    assert_eq!(
        commands(
            Category::Browser,
            "home/u/.mozilla/native-messaging-hosts/x.json",
            "{\n  \"name\": \"x\",\n  \"path\": \"/home/u/.cache/host\",\n  \"type\": \"stdio\"\n}\n"
        ),
        ["/home/u/.cache/host"]
    );
    assert_eq!(
        commands(
            Category::Browser,
            "home/u/.config/chromium/NativeMessagingHosts/x.json",
            "{\"name\": \"x\", \"path\": \"/home/u/.cache/host\", \"type\": \"stdio\"}\n"
        ),
        ["/home/u/.cache/host"]
    );
    assert_eq!(
        commands(
            Category::Desktop,
            "home/u/.config/mimeapps.list",
            "[Default Applications]\nx-scheme-handler/https=open.desktop;firefox.desktop;\ntext/html=open.desktop\nimage/png=../x.desktop\n"
        ),
        [
            "~/.local/share/applications/open.desktop",
            "~/.local/share/applications/firefox.desktop"
        ]
    );
    // What hypridle and its like run.
    assert_eq!(
        commands(
            Category::Hyprland,
            "home/u/.config/hypr/hypridle.conf",
            "general {\n  lock_cmd = ~/bin/lock\n  before_sleep_cmd = loginctl lock-session\n}\nlistener {\n  timeout = 300\n  on-timeout = ~/bin/idle\n  on-resume = ~/bin/back\n}\n"
        ),
        [
            "~/bin/lock",
            "loginctl lock-session",
            "~/bin/idle",
            "~/bin/back"
        ]
    );
    // A `ZDOTDIR` moves zsh's start-up files: they are followed there.
    assert_eq!(
        commands(
            Category::Shell,
            "home/u/.zshenv",
            "export ZDOTDIR=\"$HOME/.config/zsh\"\n"
        ),
        [
            "$HOME/.config/zsh/.zshenv",
            "$HOME/.config/zsh/.zprofile",
            "$HOME/.config/zsh/.zshrc",
            "$HOME/.config/zsh/.zlogin",
            "$HOME/.config/zsh/.zlogout"
        ]
    );
}

#[test]
fn what_sudoers_reads_in_is_followed() {
    assert_eq!(
        commands(
            Category::Sudo,
            "etc/sudoers",
            "# a comment\nroot ALL=(ALL:ALL) ALL\n@includedir /etc/sudoers.d\n#includedir /usr/local/etc/sudoers.d/\n@include /etc/sudoers.local\n#include extra\n@include /etc/sudoers.%h\n#includedirx /no\n"
        ),
        [
            "/etc/sudoers.d/*",
            "/usr/local/etc/sudoers.d/*",
            "/etc/sudoers.local",
            "/etc/extra"
        ]
    );
    assert_eq!(
        commands(
            Category::Sudo,
            "etc/sudo.conf",
            "Plugin sudoers_policy sudoers.so\nPlugin evil /tmp/evil.so\nPath askpass /usr/local/bin/ask\nSet disable_coredump false\n"
        ),
        ["/tmp/evil.so", "/usr/local/bin/ask"]
    );
}

#[test]
fn a_units_continued_lines_and_specifiers_are_written_out() {
    assert_eq!(
        commands(
            Category::Systemd,
            "home/u/.config/systemd/user/x.service",
            "[Service]\nExecStart=/usr/bin/env \\\n    A=1 \\\n    %h/.cache/run.sh --now\nExecStartPre=%E/x/pre %i\nExecStop=%t/x/stop\n"
        ),
        [
            "/usr/bin/env A=1 ~/.cache/run.sh --now",
            "~/.config/x/pre",
            "%t/x/stop"
        ]
    );
    assert_eq!(
        commands(
            Category::Systemd,
            "etc/systemd/system/x.service",
            "[Service]\nExecStart=%E/x/run %h/y\nExecStop=%t/x/stop\nExecReload=%S/x/reload\n"
        ),
        ["/etc/x/run /root/y", "/run/x/stop", "/var/lib/x/reload"]
    );
    let dir = TempDir::new("sweep-specifiers");
    let root = dir.path();
    fs::create_dir_all(root.join("home/u/.cache")).unwrap();
    fs::write(root.join("home/u/.cache/run.sh"), "").unwrap();
    assert_eq!(
        targets(root, "home/u", "/usr/bin/env A=1 ~/.cache/run.sh --now"),
        ["home/u/.cache/run.sh"]
    );
}

#[test]
fn a_line_of_commands_splits_where_a_shell_would() {
    use super::inner_commands;
    // More commands than are looked up: the first, and that there
    // were more.
    let many = "x;".repeat(super::MAX_INNER_COMMANDS + 1);
    let (first, more) = super::split_commands(&many);
    assert_eq!(first.len(), super::MAX_INNER_COMMANDS);
    assert!(more);
    assert!(!super::split_commands(&"x;".repeat(super::MAX_INNER_COMMANDS)).1);
    let nested = format!("sh -c '{many}'");
    let lookup = super::Lookup {
        home: "home/u",
        search: &[],
        exists: &|_| false,
        capped: std::cell::Cell::new(false),
        shell_scripts: std::cell::RefCell::default(),
    };
    lookup.targets(&nested);
    assert!(lookup.capped.get());
    assert_eq!(
        inner_commands("/x.sh >/dev/null 2>&1; /y.sh &>/tmp/log && /z.sh"),
        ["/x.sh >/dev/null 2>&1", " /y.sh &>/tmp/log ", " /z.sh"]
    );
    assert_eq!(inner_commands("sh -c 'a; b' | c"), ["sh -c 'a; b' ", " c"]);
}

#[test]
fn what_a_start_up_file_or_a_command_line_names_is_found() {
    // A program a shell start-up file runs by its path.
    assert_eq!(
        commands(
            Category::Shell,
            "home/u/.bashrc",
            "export X=1\n~/bin/agent --daemon &\nexec /opt/x/run\neval \"$($HOME/bin/tool init)\"\nls -l\n[ -r ~/.x ] && . ~/.x\ncd /tmp && FOO=1 ~/bin/second\ntrue & A=\"b c\" nice ~/bin/third\nif ! ~/bin/fourth; then :; fi\nls >& /dev/null\nls &>/tmp/log\nX=$(find \"/etc/conf.d\" -name x)\nX=$(date) ~/bin/fifth\n( ~/bin/sixth ) &\n",
        ),
        [
            "~/bin/agent",
            "/opt/x/run",
            "$HOME/bin/tool",
            "~/.x",
            "~/bin/second",
            "~/bin/third",
            "~/bin/fourth",
            "~/bin/fifth",
            "~/bin/sixth",
        ]
    );
    // A `case` branch's pattern is matched, not run (the shape of a
    // packaged completion file): what its branches run still is.
    let completion = "case \"$prev\" in\n--bundle | -b)\n\tcase \"$cur\" in\n\t*:*) ;; # TODO somehow (see above)\n\t'')\n\t\tCOMPREPLY=($(compgen -W '/' -- \"$cur\"))\n\t\t;;\n\t/*)\n\t\t_filedir\n\t\t;;\n\t/opt/* | /srv/*)\n\t\t/opt/tool/run\n\t\t;;\n\t(/var/*)\n\t\t;;\n\tesac\n\treturn\n\t;;\n/etc/*) ~/bin/branch ;; /usr/*) ;;\nesac\ncase $1 in /*) ~/bin/inline ;; esac\n";
    assert_eq!(
        commands(Category::Shell, "usr/share/completions/x", completion),
        ["/opt/tool/run", "~/bin/branch", "~/bin/inline"]
    );
    // Only where a shell reads a pattern: a subshell that looks like
    // one, and a `case` that is a word of another command, hide nothing.
    assert_eq!(
        commands(
            Category::Shell,
            "home/u/.bashrc",
            "( ~/bin/first )\necho in case of doubt, look in\n( ~/bin/second )\ncase x in\nx) ( ~/bin/third ) ;;\nesac\n( ~/bin/fourth )\n",
        ),
        ["~/bin/first", "~/bin/second", "~/bin/third", "~/bin/fourth"]
    );
    // A packaged start-up file that only reads a directory names no
    // program (`find` in an assignment's substitution).
    let debuginfod = "prefix=\"/usr\"\nif [ -z \"${DEBUGINFOD_URLS:-}\" ]; then\n    DEBUGINFOD_URLS=$(find \"/etc/debuginfod\" -name \"*.urls\" -print0 2>/dev/null | xargs -0 cat 2>/dev/null | tr '\\n' ' ' || :)\n    [ -n \"$DEBUGINFOD_URLS\" ] && export DEBUGINFOD_URLS || unset DEBUGINFOD_URLS\nfi\n";
    assert!(
        commands(Category::Shell, "etc/profile.d/debuginfod.sh", debuginfod).is_empty(),
        "{:?}",
        commands(Category::Shell, "etc/profile.d/debuginfod.sh", debuginfod)
    );
    // A line of nothing but substitutions is read once, not once per
    // substitution.
    let many = "$(/x1 $(/x2 ".repeat(100);
    assert_eq!(commands(Category::Shell, "home/u/.bashrc", &many).len(), 2);
    let long = "$(/x ".repeat(400_000);
    let started = std::time::Instant::now();
    assert!(commands(Category::Shell, "home/u/.bashrc", &long).is_empty());
    assert!(started.elapsed().as_secs() < 10);
    let exists = |candidate: &str| {
        [
            "home/u/.cargo/bin/tool",
            "home/u/.config/app/run.sh",
            "home/u/.local/bin/first",
            "home/u/.local/bin/second",
            "usr/bin/sh",
        ]
        .contains(&candidate)
    };
    // A bare name where cargo installs, and the XDG directories.
    assert_eq!(
        targets_where("home/u", "tool --serve", &exists),
        ["home/u/.cargo/bin/tool"]
    );
    assert_eq!(
        targets_where("home/u", "$XDG_CONFIG_HOME/app/run.sh", &exists),
        ["home/u/.config/app/run.sh"]
    );
    // Every command of a `-c` line, not only its first.
    assert_eq!(
        targets_where("home/u", "sh -c 'first && second; third | first'", &exists),
        [
            "usr/bin/sh",
            "home/u/.local/bin/first",
            "home/u/.local/bin/second"
        ]
    );
    // A bare name is found first where the search list looks first.
    let lookup = super::Lookup {
        home: "home/u",
        search: &[
            "home/u/.local/share/mise/shims".to_string(),
            "usr/bin".to_string(),
        ],
        exists: &|candidate| {
            ["home/u/.local/share/mise/shims/sh", "usr/bin/sh"].contains(&candidate)
        },
        capped: std::cell::Cell::new(false),
        shell_scripts: std::cell::RefCell::default(),
    };
    assert_eq!(
        lookup.targets("sh -c true"),
        ["home/u/.local/share/mise/shims/sh", "usr/bin/sh"]
    );
    // A separator inside quotes separates nothing, and empty commands
    // do not use up the limit.
    assert_eq!(
        targets_where("home/u", "sh -c 'x=\";\" second'", &exists),
        ["usr/bin/sh", "home/u/.local/bin/second"]
    );
    let padded = format!("sh -c '{} second'", ";".repeat(100));
    assert_eq!(
        targets_where("home/u", &padded, &exists),
        ["usr/bin/sh", "home/u/.local/bin/second"]
    );
}

#[test]
fn targets_resolve_programs_and_the_scripts_interpreters_run() {
    let dir = TempDir::new("sweep-targets");
    let root = dir.path();
    for path in [
        "usr/bin/bash",
        "usr/bin/waybar",
        "home/u/.local/bin/sudo",
        "home/u/.cache/x.sh",
    ] {
        fs::create_dir_all(root.join(path).parent().unwrap()).unwrap();
        fs::write(root.join(path), "").unwrap();
    }
    assert_eq!(targets(root, "home/u", "waybar"), ["usr/bin/waybar"]);
    assert_eq!(
        targets(root, "home/u", "uwsm-app -- waybar --log"),
        ["usr/bin/waybar"]
    );
    assert_eq!(
        targets(root, "home/u", "/usr/bin/bash -l ~/.cache/x.sh"),
        ["usr/bin/bash", "home/u/.cache/x.sh"]
    );
    assert_eq!(targets(root, "home/u", "bash -c 'x'"), ["usr/bin/bash"]);
    // A name in ~/.local/bin is found before /usr/bin.
    assert_eq!(
        targets(root, "home/u", "sudo x"),
        ["home/u/.local/bin/sudo"]
    );
    assert_eq!(
        targets(root, "home/u", "A=1 %h/.cache/x.sh"),
        ["home/u/.cache/x.sh"]
    );
    assert!(targets(root, "home/u", "missing").is_empty());
}

#[test]
fn the_script_is_found_for_every_interpreter_and_past_its_options() {
    let there = [
        "usr/bin/bash",
        "usr/bin/tcsh",
        "usr/bin/python3",
        "usr/bin/pypy3",
        "usr/bin/java",
        "usr/bin/perl",
        "usr/bin/ncat",
        "home/u/x.sh",
        "home/u/x.py",
        "home/u/app.jar",
        "home/u/data",
        "run/x.sock",
    ];
    let exists = |path: &str| there.contains(&path);
    let lookup = super::Lookup {
        home: "home/u",
        search: &super::default_search("home/u"),
        exists: &exists,
        capped: std::cell::Cell::new(false),
        shell_scripts: std::cell::RefCell::default(),
    };
    // Interpreters the live checks knew and this one did not.
    assert_eq!(
        lookup.targets("pypy3 ~/x.py"),
        ["usr/bin/pypy3", "home/u/x.py"]
    );
    assert_eq!(
        lookup.targets("java -jar /home/u/app.jar"),
        ["usr/bin/java", "home/u/app.jar"]
    );
    assert_eq!(
        lookup.targets("tcsh -e /home/u/x.sh"),
        ["usr/bin/tcsh", "home/u/x.sh"]
    );
    // Only a Bourne shell's script is read as one.
    assert!(lookup.shell_scripts.borrow().is_empty());
    // `-e` is a plain flag of a shell, and code for another program.
    for command in [
        "/usr/bin/bash -e /home/u/x.sh",
        "bash -eu -o pipefail /home/u/x.sh",
        "bash +o posix -e /home/u/x.sh /home/u/data",
    ] {
        assert_eq!(
            lookup.targets(command),
            ["usr/bin/bash", "home/u/x.sh"],
            "{command}"
        );
    }
    assert_eq!(*lookup.shell_scripts.borrow(), ["home/u/x.sh"; 3]);
    assert_eq!(
        lookup.targets("perl -e 'print 1' /home/u/x.sh"),
        ["usr/bin/perl"]
    );
    // The script after the value of an option. An option that is a
    // plain flag for this program takes none: what follows the script
    // is the script's own, a file of data that is not looked at.
    assert_eq!(
        lookup.targets("python3 -W ignore /home/u/x.py"),
        ["usr/bin/python3", "home/u/x.py"]
    );
    assert_eq!(
        lookup.targets("python3 -I /home/u/x.py /home/u/data"),
        ["usr/bin/python3", "home/u/x.py"]
    );
    assert_eq!(
        lookup.targets("perl -I /home/u/lib /home/u/x.py /home/u/data"),
        ["usr/bin/perl", "home/u/x.py"]
    );
    // Code given another way than `-e`, and an option that only ends
    // like `-c`.
    let data = "home/u/data".to_string();
    assert!(
        !lookup
            .targets("php -r 'echo 1;' /home/u/data")
            .contains(&data)
    );
    assert!(
        lookup
            .targets("java -verbose:gc -cp /home/u/lib /home/u/x.py")
            .contains(&"home/u/x.py".to_string())
    );
    assert_eq!(
        lookup.targets("python3 /home/u/x.py /home/u/data"),
        ["usr/bin/python3", "home/u/x.py"]
    );
    // A netcat is given no script: the path is a socket's.
    assert_eq!(lookup.targets("ncat -U /run/x.sock"), ["usr/bin/ncat"]);
}

#[test]
fn configuration_commands_are_found_and_logrotate_is_no_crontab() {
    assert_eq!(
        commands(
            Category::Autostart,
            "etc/sddm.conf.d/x.conf",
            "[X11]\nSessionCommand=/usr/share/sddm/scripts/Xsession\nSessionDir=/usr/share/xsessions\n"
        ),
        ["/usr/share/sddm/scripts/Xsession"]
    );
    assert_eq!(
        commands(
            Category::PacmanHook,
            "etc/pacman.conf",
            "#XferCommand = /usr/bin/curl -L -C - -f -o %o %u\nXferCommand = /usr/local/bin/fetch %u\nHookDir = /etc/pacman.d/hooks/\n"
        ),
        ["/usr/local/bin/fetch"]
    );
    assert_eq!(
        commands(
            Category::Autostart,
            "etc/greetd/config.toml",
            "[default_session]\ncommand = \"tuigreet --cmd Hyprland\"\n"
        ),
        ["tuigreet --cmd Hyprland"]
    );
    assert!(
            commands(
                Category::Cron,
                "etc/logrotate.d/x",
                "/var/log/x {\n  compress delaycompress missingok notifempty copytruncate sharedscripts\n}\n"
            )
            .is_empty()
        );
}

#[test]
fn what_runs_is_found_past_wrappers_and_in_files_that_are_read_in() {
    let dir = TempDir::new("sweep-wrappers");
    let root = dir.path();
    for path in [
        "usr/bin/bash",
        "usr/bin/sudo",
        "usr/bin/waybar",
        "home/u/.cache/x.sh",
        "home/u/.local/bin/timeout",
    ] {
        fs::create_dir_all(root.join(path).parent().unwrap()).unwrap();
        fs::write(root.join(path), "").unwrap();
    }
    let payload = ["home/u/.cache/x.sh"];
    for command in [
        "uwsm app -- ~/.cache/x.sh",
        "sudo -u nobody ~/.cache/x.sh --flag",
        "systemd-run --user --unit x -p Restart=no ~/.cache/x.sh",
        "env -u DISPLAY A=1 ~/.cache/x.sh",
        "env -S \"~/.cache/x.sh --flag\"",
        "nice -n 5 ionice -c 3 ~/.cache/x.sh",
        "flock /tmp/lock ~/.cache/x.sh",
        "setsid nohup ~/.cache/x.sh",
    ] {
        assert_eq!(targets(root, "home/u", command), payload, "{command}");
    }
    // A wrapper that is not the system's own is what runs first.
    assert_eq!(
        targets(root, "home/u", "timeout 5 ~/.cache/x.sh"),
        ["home/u/.local/bin/timeout", "home/u/.cache/x.sh"]
    );
    // The program a shell is handed as its command line.
    for command in [
        "bash -c '~/.cache/x.sh --now'",
        "bash -lc 'nohup ~/.cache/x.sh'",
        "bash -c 'A=1 sudo ~/.cache/x.sh'",
        "bash -o pipefail -c '~/.cache/x.sh'",
    ] {
        assert_eq!(
            targets(root, "home/u", command),
            ["usr/bin/bash", "home/u/.cache/x.sh"],
            "{command}"
        );
    }
    assert_eq!(
        targets(root, "home/u", "uwsm app -s b -- ~/.cache/x.sh"),
        payload
    );
    // `-O` is a plain flag there: the script is what follows.
    fs::write(root.join("usr/bin/python3"), "").unwrap();
    assert_eq!(
        targets(root, "home/u", "python3 -O ~/.cache/x.sh"),
        ["usr/bin/python3", "home/u/.cache/x.sh"]
    );
    assert_eq!(
        targets(root, "home/u", "bash -c 'echo hi'"),
        ["usr/bin/bash"]
    );

    // Files a shell start-up file reads in.
    assert_eq!(
        commands(
            Category::Shell,
            "home/u/.bashrc",
            "source ~/.cache/x.sh\n[ -r /etc/x ] && . /etc/x\n# source /no\necho source of truth\nexport A=1\ntrue; . /etc/y\necho . done\n"
        ),
        ["~/.cache/x.sh", "/etc/x", "/etc/y"]
    );
    // What a unit reads into its environment.
    assert_eq!(
        commands(
            Category::Systemd,
            "etc/systemd/system/x.service",
            "[Service]\nEnvironmentFile=-/etc/x.env\nExecStart=/usr/bin/waybar\n"
        ),
        ["/etc/x.env", "/usr/bin/waybar"]
    );
    // Hyprland: binds, plugins and files it is told to read.
    assert_eq!(
        commands(
            Category::Hyprland,
            "home/u/.config/hypr/hyprland.conf",
            "exec-once = waybar\nbind = SUPER, Return, exec, ~/.cache/x.sh\nbindl = , XF86AudioMute, exec, wpctl set-mute\nbind = SUPER, Q, killactive\nbindd = SUPER, T, Open a terminal, exec, uwsm-app -- foot\nplugin = /tmp/evil.so\nsource = ~/.config/hypr/extra.txt\nsource = ~/.config/hypr/conf.d/*\n"
        ),
        [
            "waybar",
            "~/.cache/x.sh",
            "wpctl set-mute",
            "uwsm-app -- foot",
            "/tmp/evil.so",
            "~/.config/hypr/extra.txt",
            // A pattern is listed; the collector looks it up.
            "~/.config/hypr/conf.d/*"
        ]
    );
    // SSH: `=` or blanks, commands and libraries.
    for (line, runs) in [
        ("ProxyCommand=/tmp/x %h", Some("/tmp/x %h")),
        ("proxycommand   /tmp/x", Some("/tmp/x")),
        ("ProxyCommand none", None),
        (
            "Subsystem sftp /usr/lib/ssh/sftp-server",
            Some("/usr/lib/ssh/sftp-server"),
        ),
        ("Match user git exec \"/tmp/y %h\"", Some("/tmp/y %h")),
        ("Match host x", None),
        ("SecurityKeyProvider /tmp/sk.so", Some("/tmp/sk.so")),
        ("ProxyJump bastion", None),
        ("Subsystem sftp internal-sftp", None),
        ("SecurityKeyProvider internal", None),
        ("TrustedUserCAKeys /etc/ssh/ca.pub", Some("/etc/ssh/ca.pub")),
        (
            "AuthorizedKeysFile /etc/ssh/keys/%u .ssh/authorized_keys",
            None,
        ),
        ("AuthorizedKeysFile .ssh/authorized_keys", None),
        (
            "AuthorizedPrincipalsFile /etc/ssh/principals",
            Some("/etc/ssh/principals"),
        ),
        ("AuthorizedPrincipalsFile none", None),
        (
            "AuthorizedKeysCommand /usr/local/bin/keys %u",
            Some("/usr/local/bin/keys %u"),
        ),
        (
            "Include ~/.orbstack/ssh/config",
            Some("~/.orbstack/ssh/config"),
        ),
    ] {
        assert_eq!(
            super::ssh(line).map(|(_, value)| value).as_deref(),
            runs,
            "{line}"
        );
    }
}
