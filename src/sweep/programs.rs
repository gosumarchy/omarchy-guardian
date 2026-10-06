//! The programs the sweep tells by their name: shells, interpreters and
//! relays, and how the script an interpreter runs is found among its
//! arguments. Every check that asks "is this a shell?" asks it here, so no
//! two of them can answer differently.
//!
//! The sets are built from the lists below; a check that needs fewer
//! programs than all of a kind has a predicate of its own that says why.

/// Shells of the Bourne family. Only their scripts are looked through for
/// what they start (`commands::is_shell_script`): the others below are
/// written in a syntax of their own. They are matched by their exact name,
/// as a `#!` line and a `busybox` applet give it.
pub const SCRIPT_SHELLS: &[&str] = &["sh", "bash", "dash", "zsh", "ksh", "ash", "mksh"];

/// Shells with a syntax of their own that make no network connections
/// themselves.
const OTHER_SHELLS: &[&str] = &["fish", "tcsh", "csh", "elvish"];

/// Shells with a network client built in (`http get` in Nushell, any
/// Python library in xonsh): a connection among their open files is what
/// an ordinary command of theirs looks like while it runs.
const NETWORK_SHELLS: &[&str] = &["nu", "xonsh"];

/// Languages and runtimes that run the file they are given.
const LANGUAGES: &[&str] = &[
    "python", "python3", "pypy", "perl", "ruby", "node", "bun", "deno", "php", "lua", "luajit",
    "java", "awk", "gawk", "mawk", "tclsh", "wish", "expect", "R", "Rscript", "pwsh", "erl",
    "beam.smp", "julia", "dotnet", "mono", "guile", "gjs",
];

/// The netcats: they run or connect what their arguments say, and are
/// given no script.
const NETCATS: &[&str] = &[
    "nc",
    "ncat",
    "netcat",
    "nc.openbsd",
    "nc.traditional",
    "socat",
];

/// Programs that are whichever tool they are asked to be: a shell that
/// runs a script as much as a netcat.
const MULTI_CALL: &[&str] = &["busybox", "toybox"];

/// Programs that are no relay and take no script, and still do what their
/// arguments say (`openssl s_client`, `openssl s_server`).
const TOLD_BY_ARGUMENTS: &[&str] = &["openssl"];

/// The other tools that run or forward what they are told over the
/// network: servers that start a program per connection, and tunnels.
const SERVERS_AND_TUNNELS: &[&str] = &[
    "systemd-socket-activate",
    "telnetd",
    "in.telnetd",
    "dropbear",
    "tcpserver",
    "xinetd",
    "inetd",
    "websocat",
    "chisel",
    "gost",
    "frpc",
    "frps",
    "ngrok",
    "cloudflared",
    "bore",
    "rathole",
];

/// Whether file name `name` is `program`, or a version of it
/// (`python3.14`, `lua5.4`).
pub fn is_named(name: &str, program: &str) -> bool {
    name.strip_prefix(program)
        .is_some_and(|rest| rest.chars().all(|c| c.is_ascii_digit() || c == '.'))
}

fn is_any(name: &str, lists: &[&[&str]]) -> bool {
    lists
        .iter()
        .any(|list| list.iter().any(|program| is_named(name, program)))
}

/// Whether `name` (a program's file name) is one of `SCRIPT_SHELLS`.
pub fn is_script_shell(name: &str) -> bool {
    SCRIPT_SHELLS.contains(&name)
}

/// Whether `name` is a shell of any kind, or a version of one: what is
/// typed into it passes through its memory.
pub fn is_shell(name: &str) -> bool {
    is_any(name, &[SCRIPT_SHELLS, OTHER_SHELLS, NETWORK_SHELLS])
}

/// `is_shell` without `NETWORK_SHELLS`: the shells for which a connection
/// held on any descriptor is a finding. One with a client built in holds
/// connections in ordinary use, and is reported like any interpreter, when
/// the connection is its input or output.
pub fn is_shell_without_client(name: &str) -> bool {
    is_any(name, &[SCRIPT_SHELLS, OTHER_SHELLS])
}

/// The dynamic loader run as a program (`ld-linux-x86-64.so.2 ./program`):
/// it runs the program it is given, as an interpreter runs a script.
fn is_loader(name: &str) -> bool {
    name == "ld.so" || name.starts_with("ld-linux") || name.starts_with("ld-musl")
}

/// Whether a command line that starts the program called `name` may hand
/// it a script: a shell or a language. Narrower than `is_interpreter`: the
/// first path among a netcat's or `openssl`'s arguments is an address, a
/// socket or a key, and `busybox` is followed as the applet it is asked to
/// be.
pub fn runs_a_script(name: &str) -> bool {
    is_shell(name) || is_any(name, &[LANGUAGES])
}

/// Whether the program at `path` runs what it is given, so that who it is
/// says nothing about what it runs: a shell, a language, the loader, a
/// netcat, a multi-call program or `openssl`.
pub fn is_interpreter(path: &str) -> bool {
    let name = path.rsplit('/').next().unwrap_or(path);
    is_loader(name)
        || runs_a_script(name)
        || is_any(name, &[NETCATS, MULTI_CALL, TOLD_BY_ARGUMENTS])
}

/// Whether `name` is exactly a packaged tool that runs or forwards what it
/// is told over the network.
pub fn is_relay(name: &str) -> bool {
    [NETCATS, MULTI_CALL, SERVERS_AND_TUNNELS]
        .iter()
        .any(|list| list.contains(&name))
}

/// Whether `name` is exactly a netcat: of the relays that also count as
/// interpreters, the ones that are given no script (`ncat -e
/// /usr/bin/bash` names a program to run, not a file to read). Narrower
/// than `is_relay`: `busybox sh x.sh` does run a script.
pub fn is_netcat(name: &str) -> bool {
    NETCATS.contains(&name)
}

/// Options that take the next argument as their value in some interpreter
/// or in the loader (`python3 -W ignore x.py`, `ld-linux --library-path d
/// prog`). In another they are plain flags (`python3 -I x.py`), so what
/// follows one may be the script or may be a value before it.
const VALUE_OPTIONS: &[&str] = &[
    "--library-path",
    "--preload",
    "--audit",
    "--argv0",
    "--glibc-hwcaps-prepend",
    "--glibc-hwcaps-mask",
    "-W",
    "-X",
    "-r",
    "--require",
    "--import",
    "--loader",
    "-I",
    "-cp",
    "-classpath",
    "--class-path",
    "--module-path",
    // `bash -o pipefail script`.
    "-o",
    "-O",
];

/// The options of the program called `name` that take the next argument
/// as their value, for a command line, where the program is known: there
/// `python3 -O x.py data` has one script, and `data` is not it.
fn value_options_of(name: &str) -> &'static [&'static str] {
    let is = |programs: &[&str]| programs.iter().any(|program| is_named(name, program));
    if is_loader(name) {
        &[
            "--library-path",
            "--preload",
            "--audit",
            "--argv0",
            "--glibc-hwcaps-prepend",
            "--glibc-hwcaps-mask",
        ]
    } else if is_shell(name) && !is(NETWORK_SHELLS) {
        &["-o", "-O"]
    } else if is(&["python", "pypy"]) {
        &["-W", "-X"]
    } else if is(&["ruby"]) {
        &["-I", "-r"]
    } else if is(&["perl", "gjs", "nu"]) {
        &["-I"]
    } else if is(&["node", "bun", "deno"]) {
        &["-r", "--require", "--import", "--loader"]
    } else if is(&["java"]) {
        &["-cp", "-classpath", "--class-path", "--module-path"]
    } else {
        &[]
    }
}

/// Whether `option` gives the program called `name` its code on the
/// command line, so that no script follows (`perl -e code`, `php -r
/// code`). For a shell `-e` is a plain flag (`bash -e script`).
pub fn takes_code(name: &str, option: &str) -> bool {
    let is = |programs: &[&str]| programs.iter().any(|program| is_named(name, program));
    if is_shell(name) {
        false
    } else if is(&["php"]) {
        option == "-r"
    } else if is(&["node", "bun", "deno"]) {
        matches!(option, "-e" | "-p" | "--eval" | "--print")
    } else if is(&["perl"]) {
        matches!(option, "-e" | "-E")
    } else if is(&["awk", "gawk", "mawk"]) {
        matches!(option, "-e" | "--source")
    } else {
        option == "-e"
    }
}

/// What one argument of an interpreter is, on the way to its script.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Argument {
    /// An option: not the script.
    Option,
    /// The script, or the value of the option before it: the script may
    /// still follow.
    ScriptOrValue,
    /// The script, if anything is: nothing after it is one.
    Script,
}

/// Reads the arguments of an interpreter (or the loader) one by one, up
/// to its script.
#[derive(Debug)]
pub struct ScriptArguments {
    may_be_value: bool,
    value_options: &'static [&'static str],
}

/// For a process, whose program is told only by a file's name: any of
/// `VALUE_OPTIONS` may have taken a value.
impl Default for ScriptArguments {
    fn default() -> Self {
        Self {
            may_be_value: false,
            value_options: VALUE_OPTIONS,
        }
    }
}

impl ScriptArguments {
    /// For a command line that starts the program called `name`: only its
    /// own options take a value.
    pub fn of(name: &str) -> Self {
        Self {
            may_be_value: false,
            value_options: value_options_of(name),
        }
    }

    /// What `argument`, the next one, is.
    pub fn read(&mut self, argument: &str) -> Argument {
        if argument.starts_with('-') {
            self.may_be_value = self.value_options.contains(&argument);
            Argument::Option
        } else if std::mem::take(&mut self.may_be_value) {
            Argument::ScriptOrValue
        } else {
            Argument::Script
        }
    }
}

/// The arguments that may be the script (or, for the loader, the program)
/// of a process: the first that is no option, and, where that one follows
/// an option that may have taken it as its value, the next one too. Code
/// given on the command line (`python3 -c …`) comes out as one, and is
/// dropped where it names no file; `bash -e x.sh`, where `-e` is a plain
/// flag, keeps its script.
pub fn script_arguments(arguments: &[String]) -> Vec<&str> {
    let mut candidates = Vec::new();
    let mut reader = ScriptArguments::default();
    for argument in arguments.iter().skip(1).map(String::as_str) {
        match reader.read(argument) {
            Argument::Option => {}
            Argument::ScriptOrValue => candidates.push(argument),
            Argument::Script => {
                candidates.push(argument);
                break;
            }
        }
    }
    candidates
}

#[cfg(test)]
mod tests {
    use super::{
        Argument, LANGUAGES, MULTI_CALL, NETCATS, NETWORK_SHELLS, OTHER_SHELLS, SCRIPT_SHELLS,
        SERVERS_AND_TUNNELS, ScriptArguments, TOLD_BY_ARGUMENTS, is_interpreter, is_named,
        is_netcat, is_relay, is_script_shell, is_shell, is_shell_without_client, runs_a_script,
        script_arguments, takes_code,
    };

    const LISTS: &[&[&str]] = &[
        SCRIPT_SHELLS,
        OTHER_SHELLS,
        NETWORK_SHELLS,
        LANGUAGES,
        NETCATS,
        MULTI_CALL,
        TOLD_BY_ARGUMENTS,
        SERVERS_AND_TUNNELS,
    ];

    #[test]
    fn the_sets_are_built_from_one_table() {
        // A program is in one list only: the predicates combine them.
        let all: Vec<&str> = LISTS.iter().flat_map(|list| list.iter().copied()).collect();
        for name in &all {
            assert_eq!(
                all.iter().filter(|other| other == &name).count(),
                1,
                "{name}"
            );
        }
        // Every shell is one to each check that asks, but for the shells
        // with a client of their own where a held connection is asked
        // about; only the Bourne ones have their scripts looked through.
        for name in SCRIPT_SHELLS
            .iter()
            .chain(OTHER_SHELLS)
            .chain(NETWORK_SHELLS)
        {
            assert!(is_shell(name), "{name}");
            assert!(runs_a_script(name), "{name}");
            assert!(is_interpreter(&format!("usr/bin/{name}")), "{name}");
            assert_eq!(
                is_script_shell(name),
                SCRIPT_SHELLS.contains(name),
                "{name}"
            );
            assert_eq!(
                is_shell_without_client(name),
                !NETWORK_SHELLS.contains(name),
                "{name}"
            );
            assert!(!is_relay(name), "{name}");
        }
        // A language runs a script and is no shell.
        for name in LANGUAGES {
            assert!(runs_a_script(name) && is_interpreter(name), "{name}");
            assert!(!is_shell(name) && !is_shell_without_client(name), "{name}");
            assert!(!is_relay(name), "{name}");
        }
        // What does as its arguments say is an interpreter to the live
        // checks, and is handed no script by a command line; of the
        // relays among them only a netcat is never given one.
        for name in NETCATS.iter().chain(MULTI_CALL).chain(TOLD_BY_ARGUMENTS) {
            assert!(is_interpreter(name) && !runs_a_script(name), "{name}");
            assert!(!is_shell(name), "{name}");
            assert_eq!(is_relay(name), !TOLD_BY_ARGUMENTS.contains(name), "{name}");
            assert_eq!(is_netcat(name), NETCATS.contains(name), "{name}");
        }
        // A server or a tunnel is a relay and nothing else.
        for name in SERVERS_AND_TUNNELS {
            assert!(is_relay(name) && !is_netcat(name), "{name}");
            assert!(!is_interpreter(name) && !runs_a_script(name), "{name}");
        }
        for name in all {
            assert_eq!(
                runs_a_script(name),
                is_shell(name) || LANGUAGES.contains(&name),
                "{name}"
            );
        }
    }

    #[test]
    fn a_program_is_told_by_its_name_and_its_versions() {
        assert!(is_named("python3.14", "python"));
        assert!(is_named("lua5.4", "lua"));
        assert!(!is_named("pythonw", "python"));
        assert!(!is_named("xpython", "python"));
        for (name, shell, script) in [
            ("bash", true, true),
            ("bash5.3", true, false),
            ("mksh", true, true),
            ("fish", true, false),
            ("rbash", false, false),
            ("shx", false, false),
            ("python3", false, false),
        ] {
            assert_eq!(is_shell(name), shell, "{name}");
            assert_eq!(is_script_shell(name), script, "{name}");
        }
        // Programs each list of its own once lacked.
        for name in ["pypy3", "tcsh", "java", "gjs", "nu", "R", "ash"] {
            assert!(runs_a_script(name), "{name}");
            assert!(is_interpreter(&format!("usr/bin/{name}")), "{name}");
        }
        for name in ["ldd", "Rx", "nush", "sshd", "openssl", "socat"] {
            assert!(!runs_a_script(name), "{name}");
        }
        assert!(is_interpreter("usr/lib/ld-linux-x86-64.so.2"));
        assert!(is_interpreter("usr/bin/openssl"));
        assert!(!is_interpreter("usr/bin/ldd"));
        // A relay is told by its exact name.
        assert!(is_relay("socat") && is_relay("busybox") && is_relay("nc.openbsd"));
        assert!(!is_relay("socat2") && !is_relay("ssh"));
    }

    /// The names each check knew before the lists became one, written
    /// out: taking one off a list fails here.
    #[test]
    fn no_name_a_check_knew_is_lost() {
        let shells = [
            "sh", "bash", "dash", "zsh", "ksh", "ash", "mksh", "fish", "tcsh", "csh", "elvish",
            "nu", "xonsh",
        ];
        let languages = [
            "python", "python3", "pypy", "perl", "ruby", "node", "bun", "deno", "php", "lua",
            "luajit", "java", "awk", "gawk", "mawk", "tclsh", "wish", "expect", "R", "Rscript",
            "pwsh", "erl", "beam.smp", "julia", "dotnet", "mono", "guile", "gjs",
        ];
        let relays = [
            "nc",
            "ncat",
            "netcat",
            "socat",
            "busybox",
            "toybox",
            "systemd-socket-activate",
            "telnetd",
            "in.telnetd",
            "dropbear",
            "tcpserver",
            "xinetd",
            "inetd",
            "websocat",
            "chisel",
            "gost",
            "frpc",
            "frps",
            "ngrok",
            "cloudflared",
            "bore",
            "rathole",
        ];
        for name in shells {
            assert!(is_shell(name) && runs_a_script(name), "{name}");
            assert_eq!(
                is_shell_without_client(name),
                !["nu", "xonsh"].contains(&name),
                "{name}"
            );
        }
        for name in languages {
            assert!(runs_a_script(name) && !is_shell(name), "{name}");
        }
        for name in relays {
            assert!(is_relay(name), "{name}");
        }
        for name in shells.iter().chain(&languages).chain(&relays[..6]) {
            assert!(is_interpreter(name), "{name}");
        }
        assert!(is_interpreter("openssl") && is_interpreter("ld.so"));
    }

    #[test]
    fn only_a_programs_own_options_take_a_value_on_a_command_line() {
        let read = |name: &str, arguments: &[&str]| -> Vec<Argument> {
            let mut reader = ScriptArguments::of(name);
            arguments
                .iter()
                .map(|argument| reader.read(argument))
                .collect()
        };
        // For Python `-O` and `-I` are plain flags; `-W` takes a value.
        assert_eq!(
            read("python3", &["-O", "x.py"]),
            [Argument::Option, Argument::Script]
        );
        assert_eq!(read("python3.13", &["-I", "x.py"])[1], Argument::Script);
        assert_eq!(
            read("python3", &["-W", "ignore"])[1],
            Argument::ScriptOrValue
        );
        assert_eq!(read("perl", &["-I", "lib"])[1], Argument::ScriptOrValue);
        assert_eq!(read("perl", &["-W", "x.pl"])[1], Argument::Script);
        assert_eq!(
            read("bash", &["-o", "pipefail"])[1],
            Argument::ScriptOrValue
        );
        assert_eq!(read("java", &["-cp", "a:b"])[1], Argument::ScriptOrValue);
        assert_eq!(read("gawk", &["-O", "data"])[1], Argument::Script);
        // Code on the command line, by each program's own option.
        for (name, option, code) in [
            ("perl", "-e", true),
            ("perl5.42", "-E", true),
            ("php", "-r", true),
            ("php", "-e", false),
            ("node", "--eval", true),
            ("node", "-p", true),
            ("gawk", "--source", true),
            ("ruby", "-e", true),
            ("bash", "-e", false),
            ("tcsh", "-e", false),
            ("python3", "-W", false),
        ] {
            assert_eq!(takes_code(name, option), code, "{name} {option}");
        }
    }

    #[test]
    fn arguments_are_read_up_to_the_script() {
        let mut reader = ScriptArguments::default();
        let read: Vec<Argument> = ["-u", "-W", "ignore", "-X", "dev", "x.py", "more"]
            .iter()
            .map(|argument| reader.read(argument))
            .collect();
        assert_eq!(
            read,
            [
                Argument::Option,
                Argument::Option,
                Argument::ScriptOrValue,
                Argument::Option,
                Argument::ScriptOrValue,
                Argument::Script,
                Argument::Script,
            ]
        );
        let owned: Vec<String> = ["node", "-r", "./hook.js", "app.js", "argument"]
            .iter()
            .map(|argument| (*argument).to_string())
            .collect();
        assert_eq!(script_arguments(&owned), ["./hook.js", "app.js"]);
        assert!(script_arguments(&owned[..1]).is_empty());
    }
}
