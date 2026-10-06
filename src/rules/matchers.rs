//! The matcher functions of the single-line rules: downloads piped to a
//! shell, encoded commands, privilege escalation, credentials, TLS, remote
//! shells, mining, protection and traces.

use crate::paths::file_name;

use super::shell::{
    PIPE_SHELLS, program_name, shell_words, short_flag, unquoted, unquoted_words, unversioned,
};
use super::{FETCHERS, contains_any, contains_pattern, encoded, exfil, fetch, shell};

pub(super) const CREDENTIAL_FILES: &[&str] = &[
    ".ssh/id_rsa",
    ".ssh/id_ed25519",
    ".ssh/id_ecdsa",
    ".ssh/id_dsa",
    ".gnupg/",
    ".password-store",
    ".netrc",
    ".git-credentials",
    ".local/share/opencode/auth.json",
    ".claude/.credentials.json",
    "logins.json",
    "key4.db",
    ".aws/credentials",
    ".config/gcloud/credentials.db",
    "/etc/shadow",
    "login data",
    "cookies.sqlite",
    // Credential stores of common tools and browsers, and wallet files.
    // `.gnupg/` (with the slash) is above; the bare directory name is left
    // out, since gpg's own tooling mentions it constantly.
    ".config/gh/hosts.yml",
    ".docker/config.json",
    ".kube/config",
    ".config/gcloud",
    ".cargo/credentials",
    ".local/share/keyrings",
    ".config/solana/id.json",
    ".electrum/wallets",
    ".ethereum/keystore",
    ".bitcoin/wallet",
    "/proc/self/environ",
    // Commands that read a secret out of a store or the clipboard.
    "secret-tool lookup",
    "pass show",
    "gpg --export-secret-keys",
    "security find-generic-password",
];

const ENCODED_PIPES: &[&str] = &[
    "base64 -d | sh",
    "base64 --decode | sh",
    "base64 -d | bash",
    "base64 --decode | bash",
];

const PRIVILEGE_ESCALATION: &[&str] = &[
    "sudo ",
    "doas ",
    "run0 ",
    "pkexec ",
    "setuid(",
    "chmod u+s",
    "chmod 4755",
    "chmod 6755",
    "chmod +s",
    "install -m4755",
    "install -m 4755",
    "install -dm4755",
    "setcap ",
    "cap_set_file",
    "/etc/sudoers",
    "usermod -ag",
    "chown root",
];

pub(super) fn is_download_piped_to_shell(line: &str) -> bool {
    is_fetch_piped_to_shell(line) || fetch::matches(line)
}

/// curl, wget or aria2c piped into a shell or run from a substitution.
fn is_fetch_piped_to_shell(line: &str) -> bool {
    // Bash's own network redirection: a reverse shell or a fetch without
    // any fetcher.
    if line.contains("/dev/tcp/") || line.contains("/dev/udp/") {
        return true;
    }
    if !FETCHERS.iter().any(|fetcher| line.contains(fetcher)) {
        return false;
    }
    pipes_into_shell(line, |segment| {
        FETCHERS
            .iter()
            .any(|fetcher| contains_pattern(segment, fetcher))
    }) || runs_fetched_text(line)
}

/// Whether the command on `line` goes on in `next`: a trailing backslash,
/// pipe or `&&`, or a pipe opening the next line.
pub(crate) fn continues(line: &str, next: &str) -> bool {
    let line = line.trim_end();
    line.ends_with('\\')
        || line.ends_with('|')
        || line.ends_with("&&")
        || next.trim_start().starts_with('|')
}

/// A shell reading a fetch through process substitution (`sh <(curl …)`,
/// `source <(curl …)`) or running a command substitution of one
/// (`bash -c "$(curl …)"`, `eval "$(curl …)"`).
fn runs_fetched_text(line: &str) -> bool {
    let substituted = FETCHERS.iter().any(|fetcher| {
        ["<(", "$(", "`"].iter().any(|open| {
            line.contains(&format!("{open}{fetcher}"))
                || line.contains(&format!("{open} {fetcher}"))
        })
    });
    substituted
        && (line.contains("<(")
            || ["sh -c", "bash -c", "zsh -c", "eval "]
                .iter()
                .any(|runner| contains_pattern(line, runner)))
}

/// Other interpreters that run what is piped into them. They double as
/// ordinary words in a regex alternation (`(curl|perl|wget)`), so a pipe
/// into one counts only when the pipe has whitespace beside it, as a real
/// pipeline does and an alternation does not.
const PIPE_INTERPRETERS: &[&str] = &["python", "perl", "ruby", "node", "php", "lua"];

/// Whether the program word of a pipeline segment reads and runs its input:
/// a shell or another interpreter, `source`/`.`, a `$SHELL` variable, or
/// `busybox sh`.
fn consumes_pipe<'a>(word: &str, mut rest: impl Iterator<Item = &'a str>, spaced: bool) -> bool {
    // In a JSON or QML string the command ends at `",` or `"]`.
    let cleaned = word
        .trim_end_matches([',', ']'])
        .trim_matches(['(', '{', ')', '}', ';', '&', '"', '\'', '`', ' ']);
    let program = program_name(cleaned);
    // `source /dev/stdin`, `. /dev/stdin`.
    if matches!(program, "source" | ".") {
        return rest.any(|argument| argument.contains("/dev/stdin"));
    }
    // A shell kept in a variable (`$SHELL`), expanded or not.
    if matches!(cleaned, "$shell" | "${shell}" | "$0") {
        return true;
    }
    if program == "busybox" {
        return rest
            .next()
            .is_some_and(|next| matches!(next, "sh" | "ash" | "bash"));
    }
    [program, unversioned(program)].iter().any(|name| {
        !name.is_empty()
            && (PIPE_SHELLS.contains(name) || (spaced && PIPE_INTERPRETERS.contains(name)))
    })
}

/// Whether a pipeline segment for which `source` holds is followed, later in
/// the pipeline, by a command reading it: `| sh`, `| sudo bash`, `|/bin/sh`,
/// `| timeout 5 python`, `| { bash; }`, `| xargs sh -c`.
pub(super) fn pipes_into_shell(line: &str, source: impl Fn(&str) -> bool) -> bool {
    // `a || b` runs b instead of a, not on its output.
    let line = line.replace("||", ";");
    let segments: Vec<&str> = line.split('|').collect();
    let Some(first) = segments.iter().position(|segment| source(segment)) else {
        return false;
    };
    (first + 1..segments.len()).any(|index| reads_pipe(&segments, index))
}

/// Whether the segment at `index`, which is not the first, runs what the
/// pipe before it carries.
fn reads_pipe(segments: &[&str], index: usize) -> bool {
    // A real pipe has whitespace on a side; a regex alternation
    // (`a|perl|b`) does not.
    let spaced = segments[index - 1].ends_with(char::is_whitespace)
        || segments[index].starts_with(char::is_whitespace);
    // A segment cut at a pipe may open a quote it does not close
    // (`sh -c "a | sh"`), so its words are cut at whitespace alone and
    // a quote before a word is taken off it. Wrappers that run the
    // command after them do not change what it is, so `| timeout 5 sh`
    // still reads the pipe into a shell.
    let mut words = segments[index]
        .split_whitespace()
        .map(|word| word.trim_start_matches(['(', '{', '"', '\'']));
    let Some(word) = shell::program_word(&mut words) else {
        return false;
    };
    // `xargs sh -c '…'`: xargs hands the input to the shell.
    if program_name(word) == "xargs" {
        let mut rest = words.skip_while(|argument| argument.starts_with('-'));
        return rest
            .next()
            .is_some_and(|program| consumes_pipe(program, rest, spaced));
    }
    consumes_pipe(word, words, spaced)
}

/// The last of `segments`, cut as `pipes_into_shell` cuts a line, that runs
/// what is piped into it.
pub(super) fn last_pipe_reader(segments: &[&str]) -> Option<usize> {
    (1..segments.len())
        .rev()
        .find(|index| reads_pipe(segments, *index))
}

pub(super) fn is_encoded_command_execution(line: &str) -> bool {
    contains_any(line, ENCODED_PIPES)
        || pipes_into_shell(line, |segment| {
            [
                "base64 -d",
                "base64 --decode",
                "xxd -r",
                "openssl base64 -d",
                "openssl enc -d",
            ]
            .iter()
            .any(|decoder| segment.contains(decoder))
        })
        || is_encoded_data_executed(line)
        || encoded::matches(line)
}

pub(super) fn is_encoded_data_executed(line: &str) -> bool {
    let decodes_data =
        line.contains("base64.b64decode(") || line.contains("[convert]::frombase64string");
    let executes_data = ["exec(", "eval(", "os.system(", "invoke-expression", "iex "]
        .iter()
        .any(|pattern| line.contains(pattern));
    decodes_data && executes_data
}

pub(super) fn is_privilege_escalation(line: &str) -> bool {
    match without_sandbox_helper_setuid(line) {
        Some(rest) => contains_any(&rest, PRIVILEGE_ESCALATION),
        None => contains_any(line, PRIVILEGE_ESCALATION),
    }
}

/// The setuid sandbox helpers of Chromium-based browsers and Electron apps.
/// They must be setuid root to sandbox their renderers, so every package of
/// Chrome, Brave, Edge, Opera, Vivaldi or an Electron app sets them up.
const SANDBOX_HELPERS: &[&str] = &[
    "chrome-sandbox",
    "chrome_sandbox",
    "msedge-sandbox",
    "opera_sandbox",
    "vivaldi-sandbox",
];

/// Whether `path` names one of those helpers.
pub(crate) fn is_sandbox_helper(path: &str) -> bool {
    SANDBOX_HELPERS.contains(&file_name(path))
}

/// The line with every `chmod 4755` / `chmod u+s` / `chown root` of a lone
/// sandbox helper removed, or `None` when it has none. Any other privilege
/// change on the line still matches.
fn without_sandbox_helper_setuid(line: &str) -> Option<String> {
    let words = shell_words(line);
    let mut kept: Vec<&str> = Vec::with_capacity(words.len());
    let mut exempted = false;
    let mut index = 0;
    while index < words.len() {
        let sets_up_helper = matches!(
            (
                words[index].as_str(),
                words.get(index + 1).map(String::as_str)
            ),
            ("chmod", Some("4755" | "u+s")) | ("chown", Some("root" | "root:root"))
        ) && words.get(index + 2).is_some_and(|target| {
            let target = unquoted(target.trim_end_matches(';'));
            SANDBOX_HELPERS.contains(&file_name(&target))
        }) && words.get(index + 3).is_none_or(|next| {
            matches!(next.as_str(), "||" | "&&" | ";" | "|" | "2>/dev/null")
                || words[index + 2].ends_with(';')
        });
        if sets_up_helper {
            exempted = true;
            index += 3;
        } else {
            kept.push(&words[index]);
            index += 1;
        }
    }
    exempted.then(|| kept.join(" "))
}

/// A credential file named in the plain list, or a credential store handed
/// to a command that takes it (see `exfil::takes_credential`).
pub(super) fn references_credential(line: &str) -> bool {
    contains_any(line, CREDENTIAL_FILES)
        || (exfil::mentions_credential(line) && exfil::takes_credential(line))
}

pub(super) fn looks_like_credential_exfiltration(line: &str) -> bool {
    if exfil::sends_secret(line) {
        return true;
    }
    let sends_data = [
        "curl ",
        "wget ",
        "fetch(",
        "requests.post(",
        "axios.post(",
        ".post(",
        ".put(",
        "http.post(",
        "http.request(",
        "upload(",
        "socket.send(",
        "websocket",
    ]
    .iter()
    .any(|pattern| line.contains(pattern));
    if !sends_data {
        return false;
    }

    let reads_secret_variable = [
        "process.env",
        "os.environ",
        "getenv(",
        "cookie",
        "authorization",
        "password",
        "secret",
        "api_key",
        "token",
    ]
    .iter()
    .any(|pattern| line.contains(pattern));
    let reads_sensitive_file = contains_any(line, CREDENTIAL_FILES)
        && [
            " -d @",
            "--data @",
            "--data-binary @",
            "-f @",
            "open(",
            "readfile(",
            "read_file(",
            "read_to_string(",
            "readtext(",
            "read_text(",
            "read_bytes(",
        ]
        .iter()
        .any(|pattern| line.contains(pattern));

    reads_secret_variable || reads_sensitive_file
}

/// Settings that switch off TLS certificate checking, by any of the common
/// tools. Each is distinctive enough to match as plain text.
const DISABLED_TLS_PATTERNS: &[&str] = &[
    "--no-check-certificate",
    "insecureskipverify: true",
    "insecureskipverify:true",
    "rejectunauthorized: false",
    "rejectunauthorized:false",
    "node_tls_reject_unauthorized=0",
    "verify=false",
    "cert_none",
    "ssl._create_unverified_context",
    "_create_unverified_https_context",
    "git_ssl_no_verify=",
    "pythonhttpsverify=0",
    "--proxy-insecure",
    "stricthostkeychecking=no",
    "strict-ssl=false",
    "strict-ssl false",
    "--trusted-host",
    "curl_sslverify_none",
];

/// Commands that only show what they are given.
const PRINTERS: &[&str] = &["echo", "printf"];

/// Whether a short-flag cluster of one of `programs` carries the flag
/// letter `flag`: `-k`, `-sk`, `-fsSLk`, before or after the command's
/// other arguments (`curl URL -k -o f`), but not `--key` nor a flag of
/// another command on the line. A program is matched without its path.
///
/// `unless` names options that give the flag another meaning in the same
/// command: one letter for a short flag, a whole word otherwise.
pub(super) fn program_short_flag(
    line: &str,
    programs: &[&str],
    flag: char,
    unless: &[&str],
) -> bool {
    // A quote inside a name is no part of it: `c""url`.
    let plain;
    let text = if line.contains(['"', '\'']) {
        plain = unquoted(line);
        plain.as_str()
    } else {
        line
    };
    if !programs.iter().any(|program| text.contains(program)) {
        return false;
    }
    // The parts follow one another in the line, so what divides each from
    // the next is read where it ends.
    let mut start = 0;
    for part in shell::split_top(line, &["&&", "||", ";", "|", "&", "\n"]) {
        let end = start + part.len();
        let after = line.get(end..).unwrap_or_default();
        let doubled = after.starts_with("&&") || after.starts_with("||");
        let piped = after.starts_with('|') && !doubled;
        if part_short_flag(part, piped, programs, flag, unless) {
            return true;
        }
        start = end + if doubled { 2 } else { 1 };
    }
    false
}

/// Whether `word` ends a command inside a part that was not cut there (a
/// part that opens a group it does not close is not cut inside it).
fn ends_command(word: &str) -> bool {
    matches!(word, ";" | "|" | "&&" | "||" | "&") || word.ends_with(';')
}

/// `program_short_flag` for one command; `piped` says a pipe carries its
/// output on.
fn part_short_flag(
    part: &str,
    piped: bool,
    programs: &[&str],
    flag: char,
    unless: &[&str],
) -> bool {
    if !(part.contains('-') && part.contains(flag)) {
        return false;
    }
    let words = unquoted_words(part);
    let mut rest = words.iter().map(String::as_str);
    let command = shell::program_word(&mut rest).map(program_name);
    // The words up to and with the command: wrappers, assignments, and
    // the program `shell::command` finds.
    let leading = words.len() - rest.len();
    // Shown, not run, unless what is shown goes on into a pipe or a file,
    // or another command follows in the same part.
    if command.is_some_and(|command| PRINTERS.contains(&command))
        && !piped
        && !part.contains('>')
        && !words.iter().any(|word| ends_command(word))
    {
        return false;
    }
    // Every option up to the end of the command is its own when the
    // program is the command. Named before it or further on (`CURL=curl
    // make -k`, `xargs curl -k`), only those before its first operand
    // are: another program may follow.
    let (mut own, mut running) = (false, false);
    // Whether the command so far has the flag, and an option that gives
    // the flag another meaning.
    let (mut has, mut other) = (false, false);
    for (index, word) in words.iter().enumerate() {
        let option = word.trim_end_matches([';', ')', '`']);
        if matches!(word.as_str(), ";" | "|" | "&&" | "||" | "&") {
            if has && !other {
                return true;
            }
            (own, running, has, other) = (false, false, false, false);
            continue;
        }
        if word.starts_with('-') {
            if running {
                has |= short_flag(option, flag);
                other |= unless.iter().any(|name| {
                    let mut letters = name.chars();
                    match (letters.next(), letters.next()) {
                        (Some(letter), None) => short_flag(option, letter),
                        _ => option == *name,
                    }
                });
            }
        } else if !own {
            let name = match command {
                Some(command) if index + 1 == leading => command,
                _ => program_name(word),
            };
            running = programs.contains(&name);
            own = running && index + 1 == leading;
        }
        if word.ends_with(';') {
            if has && !other {
                return true;
            }
            (own, running, has, other) = (false, false, false, false);
        }
    }
    has && !other
}

/// Whether a command named in `programs` is on the line with one of
/// `exact_flags` among its own arguments (or, with an empty `exact_flags`,
/// simply present as a command). Arguments stop at a command separator, so
/// a flag of a later command does not count.
fn command_has_flag(line: &str, programs: &[&str], exact_flags: &[&str]) -> bool {
    let words = unquoted_words(line);
    let mut index = 0;
    while index < words.len() {
        if programs.contains(&program_name(&words[index])) {
            if exact_flags.is_empty() {
                return true;
            }
            for argument in &words[index + 1..] {
                if matches!(argument.as_str(), ";" | "|" | "&&" | "||" | "&") {
                    break;
                }
                if exact_flags.contains(&argument.as_str()) {
                    return true;
                }
            }
        }
        index += 1;
    }
    false
}

pub(super) fn disables_tls_verification(line: &str) -> bool {
    if contains_any(line, DISABLED_TLS_PATTERNS) {
        return true;
    }
    // `--insecure` is curl's and others'; a bare `-k` is only curl's.
    if contains_pattern(line, "--insecure") {
        return true;
    }
    // git's own switch, written as a config key either way round.
    let git_off = [
        "http.sslverify false",
        "http.sslverify=false",
        "sslverify=false",
    ]
    .iter()
    .any(|pattern| line.contains(pattern));
    if git_off && line.contains("git") {
        return true;
    }
    program_short_flag(line, &["curl"], 'k', &[])
}

/// A shell wired to a network connection, so the commands come from
/// elsewhere. The plain `/dev/tcp/` form is already download-and-execute;
/// these are the shapes that hide the socket or build it in another
/// language.
pub(super) fn is_remote_shell(line: &str) -> bool {
    // netcat and ncat running a program on connect: the flag must be one
    // of the command's own, not any `-e` on the line (`echo -e`).
    let netcat = command_has_flag(line, &["nc", "ncat"], &["-e", "-c", "--exec", "--sh-exec"]);
    // socat giving a connection a shell.
    let socat = command_has_flag(line, &["socat"], &[])
        && (line.contains("exec:") || line.contains("system:"))
        && ["sh", "bash", "/bin/", "-i"]
            .iter()
            .any(|word| line.contains(word));
    // `/dev/tcp` built up through a variable: `d=/dev; sh -i >& $d/tcp/h/p`.
    let indirect_tcp = line.contains("/tcp/")
        && (line.contains(">&") || line.contains("0>&") || line.contains("<>"));
    // An interpreter opening a socket and wiring a shell to it: a socket
    // next to a terminal takeover, not a mere `import socket`.
    let python = line.contains("socket")
        && (line.contains("pty.spawn")
            || line.contains("os.dup2")
            || ((line.contains("/bin/sh") || line.contains("/bin/bash"))
                && ["subprocess", "os.system", "popen", "os.execv"]
                    .iter()
                    .any(|word| line.contains(word))));
    // The interpreter must be invoked with inline code, not merely named
    // inside a word (`wallpaperleft` holds `perl`).
    let perl = command_has_flag(line, &["perl"], &["-e"])
        && (line.contains("socket") || line.contains("sockaddr"))
        && (line.contains("exec") || line.contains("/bin/sh"));
    let php = command_has_flag(line, &["php"], &["-r"])
        && line.contains("fsockopen")
        && (line.contains("exec") || line.contains("proc_open"));
    let ruby = command_has_flag(line, &["ruby"], &["-e", "-rsocket"])
        && (line.contains("socket") || line.contains("-rsocket"))
        && (line.contains("exec") || line.contains("/bin/sh"));
    let awk = line.contains("/inet/tcp/") || line.contains("/inet/udp/");
    let piped = (line.contains("telnet") || line.contains("openssl s_client"))
        && pipes_into_shell(line, |segment| {
            segment.contains("telnet") || segment.contains("s_client")
        });
    netcat || socat || indirect_tcp || python || perl || php || ruby || awk || piped
}

/// Miners, mining pools and the stratum protocol.
const MINING_MARKERS: &[&str] = &[
    "stratum+tcp://",
    "stratum+ssl://",
    "stratum2+tcp://",
    "xmrig",
    "minerd",
    "cpuminer",
    "--donate-level",
    "pool.minexmr.",
    "supportxmr.com",
    "nanopool.org",
    "2miners.com",
    "pool.hashvault.pro",
    "minexmr.com",
    "randomx",
    "--coin monero",
    "--cinit-algo",
];

pub(super) fn is_crypto_mining(line: &str) -> bool {
    MINING_MARKERS.iter().any(|marker| line.contains(marker))
}

/// Security services whose removal leaves the system more exposed, Guardian
/// among them.
const PROTECTED_SERVICES: &[&str] = &[
    "firewalld",
    "ufw",
    "nftables",
    "iptables",
    "apparmor",
    "auditd",
    "clamav",
    "omarchy-guardian",
];

pub(super) fn disables_protection(line: &str) -> bool {
    // Turning a security service off or masking it.
    let systemctl = line.contains("systemctl")
        && (line.contains("mask") || line.contains("disable") || line.contains("stop"))
        && PROTECTED_SERVICES
            .iter()
            .any(|service| line.contains(service));
    let ufw_off = line.contains("ufw disable") || line.contains("ufw --force disable");
    let flush = line.contains("nft flush ruleset")
        // Lowercased, `-f` is also the fragment match of a rule. A rule
        // is appended, inserted, deleted, replaced or checked, and names
        // a target; a flush does none of that.
        || program_short_flag(
            line,
            &["iptables", "ip6tables"],
            'f',
            &[
                "a", "i", "d", "r", "c", "j", "g", "--append", "--insert", "--delete",
                "--replace", "--check", "--jump", "--goto",
            ],
        )
        || line.contains("iptables --flush")
        || line.contains("ip6tables --flush");
    let selinux = line.contains("setenforce 0") || line.contains("setenforce  0");
    let ptrace = line.replace(' ', "").contains("kernel.yama.ptrace_scope=0");
    // Taking Guardian itself out of the way.
    let removes_guardian = (line.contains("pacman -r") || line.contains("pacman --remove"))
        && line.contains("omarchy-guardian");
    let removes_hook = line.contains("/etc/pacman.d/hooks/omarchy-guardian")
        && (line.contains("rm ") || line.contains("unlink") || line.contains("mv "));
    let disarms_makepkg =
        line.contains("--makepkg") && line.contains("makepkg") && line.contains("--save");
    systemctl
        || ufw_off
        || flush
        || selinux
        || ptrace
        || removes_guardian
        || removes_hook
        || disarms_makepkg
}

/// Erasing the record of what ran.
pub(super) fn removes_traces(line: &str) -> bool {
    let history = line.contains("history -c")
        || line.replace(' ', "").contains("histfile=/dev/null")
        || line.contains("set +o history")
        || line.contains("unset histfile");
    let journal = line.contains("journalctl")
        && (line.contains("--vacuum") || line.contains("--rotate") || line.contains("--flush"));
    // Wiping the system logs themselves.
    let logs = ["/var/log/", "/var/log "]
        .iter()
        .any(|path| line.contains(path))
        && [
            "rm ",
            "rm -",
            "shred",
            "truncate",
            ": >",
            ":>",
            "> /var/log",
            ">/var/log",
        ]
        .iter()
        .any(|verb| line.contains(verb));
    history || journal || logs
}
