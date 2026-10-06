//! Code that is decoded and then run: the ways a command is kept out of
//! sight of anyone reading the file, beyond the plain `base64 -d | sh`.
//!
//! Every shape here needs both halves on the line, a decoder and something
//! that runs its output. Decoding alone is ordinary (certificates, icons,
//! test data), and so is `eval`; the two meeting is what is flagged.

use super::matchers::last_pipe_reader;
use super::shell::{self, Command, program_name, short_flag, unquoted_words};
use super::{contains_pattern, pattern_starts, pipes_into_shell};

/// Programs that turn encoded text back into what it stands for when given
/// `-d` or `--decode`.
const DECODERS: &[&str] = &["base64", "base32", "basenc", "base58"];

/// Programs that unpack compressed data to standard output.
const DECOMPRESSORS: &[&str] = &[
    "gunzip", "zcat", "unxz", "xzcat", "unzstd", "zstdcat", "bunzip2", "bzcat",
];

/// Compressors that unpack when given `-d`.
const COMPRESSORS: &[&str] = &["gzip", "xz", "zstd", "bzip2", "lz4"];

/// The words of `text`, cut at what separates commands as well as at
/// whitespace, without quotes.
fn words(text: &str) -> Vec<String> {
    text.split(['|', ';', '&', '(', ')', '`'])
        .flat_map(|part| {
            let mut words = unquoted_words(part);
            // Marks where one command ends.
            words.push(String::new());
            words
        })
        .collect()
}

/// Whether `text` holds a command that decodes: `base64 -d`, `base32
/// --decode`, `basenc -d`, `xxd -r` in any option order, `openssl enc -d`,
/// `uudecode`.
pub(super) fn has_decoder(text: &str) -> bool {
    if !["base", "xxd", "openssl", "uudecode"]
        .iter()
        .any(|name| text.contains(name))
    {
        return false;
    }
    let words = words(text);
    words.iter().enumerate().any(|(index, word)| {
        let program = program_name(word);
        let own = || {
            words[index + 1..]
                .iter()
                .take_while(|word| !word.is_empty())
        };
        if program == "uudecode" {
            return true;
        }
        if program == "xxd" {
            return own().any(|word| short_flag(word, 'r'));
        }
        // `openssl x509 -dates` is not `-d`: its options are whole words.
        if program == "openssl" {
            return own().any(|word| word == "-d");
        }
        DECODERS.contains(&program) && own().any(|word| word == "--decode" || short_flag(word, 'd'))
    })
}

/// Whether `text` holds a command that unpacks to standard output.
fn has_decompressor(text: &str) -> bool {
    let words = words(text);
    words.iter().enumerate().any(|(index, word)| {
        let program = program_name(word);
        DECOMPRESSORS.contains(&program)
            || (COMPRESSORS.contains(&program)
                && words[index + 1..]
                    .iter()
                    .take_while(|word| !word.is_empty())
                    .any(|word| word == "--decompress" || short_flag(word, 'd')))
    })
}

/// How many `\x41` and `\101` escapes `text` holds. The escape character
/// itself (`\033`, `\x1b`), which opens every colour code, is not counted.
fn escapes(text: &str) -> usize {
    let bytes = text.as_bytes();
    let mut count = 0;
    let mut index = 0;
    while index + 3 < bytes.len() {
        if bytes[index] != b'\\' {
            index += 1;
            continue;
        }
        let hex = bytes[index + 1] == b'x'
            && bytes[index + 2].is_ascii_hexdigit()
            && bytes[index + 3].is_ascii_hexdigit();
        let octal = bytes[index + 1..=index + 3]
            .iter()
            .all(|byte| (b'0'..=b'7').contains(byte));
        let escape = matches!(&bytes[index + 1..=index + 3], b"x1b" | b"033");
        if (hex || octal) && !escape {
            count += 1;
            index += 4;
        } else {
            index += 1;
        }
    }
    count
}

/// The fewest escapes that make a printed literal a hidden command rather
/// than a message with a colour or a control character in it.
const MIN_ESCAPES: usize = 4;

/// `printf '\x63\x75…'` or `echo -e '\143\165…'`: a literal written as
/// character codes.
fn prints_escaped_literal(part: &str) -> bool {
    part.contains('\\')
        && escapes(part) >= MIN_ESCAPES
        && shell::pipes_from(part, &|command| {
            command.program == "printf" || (command.program == "echo" && command.has_short('e'))
        })
}

/// `echo '…'` or `printf '…'`, of a literal when `spelled_out`: nothing in
/// it is expanded.
fn prints(part: &str, spelled_out: bool) -> bool {
    !(spelled_out && (part.contains('$') || part.contains('`')))
        && shell::pipes_from(part, &|command| {
            matches!(command.program.as_str(), "echo" | "printf")
        })
}

/// Whether a filter for which `is_filter` holds is fed a literal (printed
/// just before it, or given as a here-document or here-string) and its
/// output is piped on into an interpreter. `spelled_out` asks for a
/// literal without any expansion.
fn filters_literal_into_shell(
    line: &str,
    is_filter: &dyn Fn(&Command) -> bool,
    spelled_out: bool,
) -> bool {
    let filters = |part: &str| shell::pipes_from(part, is_filter);
    // The line as `pipes_into_shell` cuts it: at single pipes, with `||`
    // read as `;`. Only what stands before the last reader is piped into
    // one.
    let groups = pipe_groups(line);
    let flat: Vec<String> = groups
        .iter()
        .map(|group| group.replace("||", ";"))
        .collect();
    let segments: Vec<&str> = flat.iter().map(String::as_str).collect();
    let Some(reader) = last_pipe_reader(&segments) else {
        return false;
    };
    // Whether a segment after the one looked at, and before the reader, is
    // a filter by itself: from the end, so each segment is read once.
    let mut later = false;
    let mut followed = 0;
    for index in (0..reader).rev() {
        let parts: Vec<&str> = groups[index].split('|').collect();
        // Where each part begins in the segment, which has one character
        // for each `||` before it.
        let mut start = 0;
        for (at, part) in parts.iter().enumerate() {
            let begins = start;
            start += part.len() + (at + 1) % 2;
            if !filters(part) {
                continue;
            }
            let before = match at.checked_sub(1) {
                Some(before) => Some(parts[before]),
                None => index
                    .checked_sub(1)
                    .and_then(|group| groups[group].rsplit('|').next()),
            };
            let fed = (part.contains("<<") && !(spelled_out && part.contains('$')))
                || before.is_some_and(|before| prints(before, spelled_out));
            if !fed {
                continue;
            }
            // Its output is piped on as it is, or a later filter's is.
            if at + 1 == parts.len() || later {
                return true;
            }
            // `tr … <<< x || y | sh`: what is piped on is the end of the
            // segment, read from the filter on.
            followed += 1;
            if followed > MAX_FOLLOWED || flat[index].get(begins..).is_some_and(&filters) {
                return true;
            }
        }
        later = later || filters(segments[index]);
    }
    false
}

/// The most filters of one line, each with a `||` after it, whose pipeline
/// is read on from there. A line with more is taken to run one: to read
/// each would cost a pass over the line apiece.
const MAX_FOLLOWED: usize = 64;

/// What the single pipes of `line` divide: a `||` is no pipe, and is left
/// in its part.
fn pipe_groups(line: &str) -> Vec<&str> {
    let bytes = line.as_bytes();
    let mut groups = Vec::new();
    let (mut start, mut index) = (0, 0);
    while index < bytes.len() {
        if bytes[index] != b'|' {
            index += 1;
        } else if bytes.get(index + 1) == Some(&b'|') {
            index += 2;
        } else {
            groups.push(&line[start..index]);
            index += 1;
            start = index;
        }
    }
    groups.push(&line[start..]);
    groups
}

/// The shell shapes: a decoder (or a literal written in escapes, or a
/// literal put through `rev`, `tr` or a decompressor) whose output is
/// piped into an interpreter or run as a substitution.
fn shell_shape(line: &str) -> bool {
    let decodes = |part: &str| has_decoder(shell::piped_statement(part));
    if line.contains('|')
        && (pipes_into_shell(line, decodes)
            || pipes_into_shell(line, prints_escaped_literal)
            || pipes_into_shell(line, |part| {
                shell::pipes_from(part, &|command| command.program == "rev")
            })
            || (contains_pattern(line, "tr ")
                && filters_literal_into_shell(line, &|command| command.program == "tr", true))
            || filters_literal_into_shell(
                line,
                &|command| {
                    DECOMPRESSORS.contains(&command.program.as_str())
                        || (COMPRESSORS.contains(&command.program.as_str())
                            && (command.has_short('d')
                                || command.arguments.iter().any(|word| word == "--decompress")))
                },
                false,
            ))
    {
        return true;
    }
    if shell::runs_substitution(line, &|body| {
        has_decoder(body)
            || prints_escaped_literal(body)
            || (body.contains("<<") && has_decompressor(body))
    }) {
        return true;
    }
    // `bash -c $'\x63\x75…'`: the command itself written as codes.
    line.contains("$'\\")
        && shell::statements(line).iter().any(|statement| {
            shell::command(statement).is_some_and(|command| {
                (command.program == "eval" || (command.is_shell() && command.has_short('c')))
                    && escapes(statement) >= MIN_ESCAPES
            })
        })
}

/// Calls that turn encoded data back into text or code, in Python,
/// JavaScript and Lua. Each is written as it is called, lowercased.
const DECODE_CALLS: &[&str] = &[
    // Python.
    "b64decode(",
    "b32decode(",
    "b16decode(",
    "a85decode(",
    "b85decode(",
    "bytes.fromhex(",
    "bytearray.fromhex(",
    "marshal.loads(",
    "zlib.decompress(",
    "lzma.decompress(",
    "bz2.decompress(",
    "gzip.decompress(",
    "binascii.unhexlify(",
    "binascii.a2b_base64(",
    "__import__('base64')",
    "__import__(\"base64\")",
    "__import__('zlib')",
    "__import__(\"zlib\")",
    "__import__('marshal')",
    "__import__(\"marshal\")",
    // JavaScript.
    "atob(",
    "string.fromcharcode(",
    "unescape(",
    // Lua.
    "string.char(",
    "base64.decode(",
    "base64.dec(",
    "from_base64(",
    "mime.unb64(",
    // PowerShell.
    "frombase64string(",
];

/// Codecs that hide text rather than name a character set.
const HIDING_CODECS: &[&str] = &[
    "rot13", "rot_13", "'hex'", "\"hex\"", "base64", "zlib", "bz2",
];

/// Whether `text` holds a call that decodes.
fn has_decode_call(text: &str) -> bool {
    DECODE_CALLS.iter().any(|call| text.contains(call))
        // `Buffer.from(x, 'base64')`: only with an encoding that hides.
        || (text.contains("buffer.from(")
            && ["base64", "'hex'", "\"hex\""].iter().any(|codec| text.contains(codec)))
        // `codecs.decode(x, 'rot13')`, `x.decode('rot13')`.
        || ((text.contains("codecs.decode(") || text.contains(".decode("))
            && HIDING_CODECS.iter().any(|codec| text.contains(codec)))
}

/// Calls that run the text or code they are given.
const RUN_CALLS: &[&str] = &[
    "exec(",
    "eval(",
    "load(",
    "loadstring(",
    "runinnewcontext(",
    "runinthiscontext(",
    "runincontext(",
    "iex(",
];

/// The furthest into a line a call's argument is read.
const MAX_ARGUMENT: usize = 4096;

/// The most of one line read as what its calls are given, a call at a time:
/// calls inside one another are each given the same text again. A line with
/// more is read once more, as a whole (see `Given::unread`).
const MAX_GIVEN: usize = 1 << 20;

/// What the run calls of a line are given.
pub(super) struct Given<'a> {
    /// What each call is given, with `function(` when what it is given
    /// opens the argument list (a declaration lists names there).
    pub(super) arguments: Vec<&'a str>,
    /// The line, when it has calls beyond the `MAX_GIVEN` read: what they
    /// are given is somewhere in it.
    pub(super) unread: Option<&'a str>,
}

impl Given<'_> {
    /// Whether `accepts` holds for what a call is given. Calls not read one
    /// by one count when it holds for the line: a line too long to read
    /// call by call is not taken to be without one.
    pub(super) fn any(&self, accepts: impl Fn(&str) -> bool) -> bool {
        self.arguments.iter().any(|argument| accepts(argument)) || self.unread.is_some_and(accepts)
    }
}

/// What each run call on the line is given.
pub(super) fn run_arguments(line: &str) -> Given<'_> {
    let mut given = Given {
        arguments: Vec::new(),
        unread: None,
    };
    let mut read = 0;
    for call in RUN_CALLS {
        // `vm.runInNewContext(` is a method: no word boundary before it.
        let method = call.starts_with("runin");
        let starts: Vec<usize> = if method {
            line.match_indices(call).map(|(start, _)| start).collect()
        } else {
            pattern_starts(line, call).collect()
        };
        for start in starts {
            if read > MAX_GIVEN {
                given.unread = Some(line);
                return given;
            }
            let mut end = (start + call.len() + MAX_ARGUMENT).min(line.len());
            while !line.is_char_boundary(end) {
                end -= 1;
            }
            let argument = shell::argument(&line[start + call.len()..end]);
            // An empty one was still looked at.
            read += argument.len() + 1;
            given.arguments.push(argument);
        }
    }
    given
}

/// A run call given a decode call, or a response just fetched: `exec(
/// base64.b64decode(…))`, `eval(atob(…))`, `new Function(atob(…))`,
/// `load(string.char(…))`, `eval(xhr.responseText)`.
fn call_shape(line: &str) -> bool {
    if !line.contains('(') {
        return false;
    }
    if run_arguments(line)
        .any(|argument| has_decode_call(argument) || argument.contains("responsetext"))
    {
        return true;
    }
    // `new Function(atob(…))`, `Function(Buffer.from(…, 'base64'))`: a
    // declaration (`function(a, b)`) opens with names instead.
    let mut read = 0;
    for start in pattern_starts(line, "function(") {
        let rest = &line[start + "function(".len()..];
        let opens = rest.trim_start();
        // Neither holds a parenthesis that closes, so what is given
        // reaches at least as far.
        if !(opens.starts_with("atob(") || opens.starts_with("buffer.from(")) {
            continue;
        }
        // Past `MAX_GIVEN` the rest of the line stands for what this call
        // and every later one is given.
        if read > MAX_GIVEN {
            return has_decode_call(rest);
        }
        let argument = shell::argument(rest);
        if has_decode_call(argument) {
            return true;
        }
        read += argument.len();
    }
    false
}

/// PowerShell given its command encoded: `powershell -enc …`.
fn encoded_powershell(line: &str) -> bool {
    (line.contains("powershell") || line.contains("pwsh"))
        && unquoted_words(line)
            .iter()
            .any(|word| matches!(word.as_str(), "-enc" | "-encodedcommand" | "-ec"))
}

/// Whether the line, lowercased, decodes something and runs it.
pub(super) fn matches(line: &str) -> bool {
    shell_shape(line) || call_shape(line) || encoded_powershell(line)
}

/// The file a decoder on `line` writes: `base64 -d > x`, `… | base64 -d |
/// tee x`, `openssl enc -d … -out x`.
pub(crate) fn decoded_file(line: &str) -> Option<String> {
    if !has_decoder(line) {
        return None;
    }
    shell::statements(line).into_iter().find_map(|statement| {
        let parts = shell::pipeline(statement);
        let at = parts.iter().position(|part| has_decoder(part))?;
        parts[at..]
            .iter()
            .find_map(|part| shell::written_file(part))
    })
}

/// A value assigned from a decode call, as the name it is assigned to:
/// `code = base64.b64decode(…)`, `local s = string.char(…)`, `const src =
/// atob(…)`.
pub(super) fn assigned_decode(line: &str) -> Option<&str> {
    let (name, value) = line.split_once('=')?;
    // `==`, `<=`, `!=` compare.
    if value.starts_with('=') || name.ends_with(['<', '>', '!', '=', '+', '-']) {
        return None;
    }
    let name = name.trim();
    let name = ["local ", "var ", "let ", "const "]
        .iter()
        .find_map(|keyword| name.strip_prefix(keyword))
        .unwrap_or(name)
        .trim();
    (shell::is_name(name) && has_decode_call(value)).then_some(name)
}

/// Whether a run call on `line` is given the variable `name`.
pub(super) fn runs_name(line: &str, name: &str) -> bool {
    let names = |text: &str| {
        pattern_starts(text, name).any(|start| {
            !text[start + name.len()..].starts_with(|c: char| c.is_ascii_alphanumeric() || c == '_')
        })
    };
    let given = run_arguments(line);
    given.arguments.iter().any(|argument| {
        // The code is the first thing a run call is given.
        names(argument.split(',').next().unwrap_or_default())
    }) || given.unread.is_some_and(names)
}

#[cfg(test)]
mod tests {
    use super::{assigned_decode, decoded_file, escapes, has_decoder, matches, runs_name};

    #[test]
    fn decoders_are_known_in_any_option_order() {
        for text in [
            "base64 -d",
            "base64 --decode x",
            "base64 -di",
            "base32 -d",
            "basenc --base64 -d",
            "xxd -r -p",
            "xxd -p -r",
            "xxd -rp x",
            "xxd -ps -r",
            "openssl enc -d -aes-256-cbc -in x",
            "openssl base64 -d",
            "/usr/bin/base64 -d",
            "uudecode x",
        ] {
            assert!(has_decoder(text), "{text}");
        }
        for text in [
            "base64 x",
            "base64 -w0 x",
            "xxd -p x",
            "xxd x",
            "openssl enc -aes-256-cbc -in x",
            "echo base64; ls -d",
            "base64 x | cut -d: -f1",
            "basename -d x",
        ] {
            assert!(!has_decoder(text), "{text}");
        }
    }

    #[test]
    fn decoded_text_run_by_a_shell_is_caught() {
        for line in [
            "eval \"$(echo ywjj | base64 -d)\"",
            "eval $(base64 --decode <<< ywjj)",
            "bash -c \"$(base64 -d <<< ywjj)\"",
            "sh -c \"`echo ywjj | base32 -d`\"",
            "source <(echo ywjj | base64 -d)",
            ". <(basenc --base64 -d payload)",
            "bash <<< \"$(xxd -r -p payload)\"",
            "echo 6964 | xxd -p -r | sh",
            "xxd -rp payload | bash",
            "openssl enc -d -aes-256-cbc -k x -in payload | sh",
            "openssl base64 -d -in payload | bash",
            "printf '\\x63\\x75\\x72\\x6c\\x20\\x78' | sh",
            "echo -e '\\143\\165\\162\\154\\040\\170' | bash",
            "echo -ne '\\x69\\x64\\x0a\\x69\\x64' | sudo sh",
            "eval \"$(printf '\\x69\\x64\\x0a\\x69\\x64')\"",
            "bash -c $'\\x69\\x64\\x0a\\x69\\x64'",
            "echo 'di' | rev | sh",
            "echo 'vq' | tr 'a-za-z' 'n-za-mn-za-m' | sh",
            "tr 'a-za-z' 'n-za-mn-za-m' <<< 'vq' | bash",
            "printf '%s' h4siaaaa | base64 -d | gunzip | sh",
            "gunzip <<< \"$blob\" | sh",
            "printf '\\x1f\\x8b\\x08' | zcat | bash",
            "echo x | xz -d | sh",
            "echo x | zstd -dc | sh",
        ] {
            assert!(matches(line), "{line}");
        }
        for line in [
            // Decoding without running, and running without decoding.
            "echo \"$cert\" | base64 -d > cert.pem",
            "key=$(echo \"$encoded\" | base64 -d)",
            "diff <(base64 -d a) <(base64 -d b)",
            "base64 -d icon.b64 | convert - icon.png",
            "xxd -r -p dump.hex > firmware.bin",
            "eval \"$(ssh-agent -s)\"",
            "eval \"$(dircolors -b)\"",
            "source <(kubectl completion bash)",
            "bash -c \"$(cat ./install.sh)\"",
            // Colour codes and a few control characters are messages.
            "printf '\\033[1m%s\\033[0m\\n' \"$title\" | tee log",
            "printf '\\x1b[31m%s\\x1b[0m\\n' error | sh -c 'cat >&2'",
            "echo -e '\\033[32mok\\033[0m' | bash helper.sh",
            // Filters on files and variables.
            "zcat /proc/config.gz | grep -i foo",
            "gunzip -c \"$file\" | sh",
            "echo \"$names\" | tr ' ' '\\n' | sh",
            "tr -d '\\r' < script.sh | sh",
            "git rev-parse head | sh",
            "echo abc | rev",
            "sort -r list | head",
        ] {
            assert!(!matches(line), "{line}");
        }
    }

    #[test]
    fn escapes_are_counted_without_the_escape_character() {
        assert_eq!(escapes("\\x63\\x75\\x72\\x6c"), 4);
        assert_eq!(escapes("\\143\\165 \\162\\154"), 4);
        assert_eq!(escapes("\\033[1m\\033[0m\\x1b[0m\\n\\t"), 0);
        assert_eq!(escapes("\\x6"), 0);
    }

    #[test]
    fn a_decode_call_given_to_a_run_call_is_caught() {
        for line in [
            "exec(base64.b64decode(payload))",
            "exec(__import__(\"base64\").b64decode(b'aw1wb3j0').decode())",
            "exec(b64decode(blob))",
            "exec(bytes.fromhex('696d706f7274'))",
            "eval(compile(zlib.decompress(blob), '<s>', 'exec'))",
            "exec(codecs.decode(src, 'rot13'))",
            "exec(codecs.decode(src, \"hex\"))",
            "exec(marshal.loads(blob))",
            "exec(binascii.unhexlify(blob))",
            "exec(src.decode('rot_13'))",
            "eval(atob('yq=='))",
            "new function(atob(src))()",
            "function(buffer.from(src, 'base64').tostring())()",
            "eval(buffer.from(src, 'base64').tostring())",
            "vm.runinnewcontext(buffer.from(src, 'hex').tostring())",
            "vm.runinthiscontext(atob(src))",
            "eval(string.fromcharcode(97,108,101,114,116))",
            "eval(unescape('%61%6c'))",
            "load(string.char(112,114,105,110,116))()",
            "loadstring(base64.decode(src))()",
            "eval(xhr.responsetext)",
            "iex([system.text.encoding]::utf8.getstring([convert]::frombase64string($b)))",
            "powershell -nop -w hidden -enc sqbfafga",
        ] {
            assert!(matches(line), "{line}");
        }
        for line in [
            // Decoding, and running, apart.
            "payload = base64.b64decode(encoded_data)",
            "data = zlib.decompress(blob)",
            "exec(compile(source, filename, 'exec'), namespace)",
            "eval(expression, globals_dict)",
            "result = eval(node.value)",
            "text = raw.decode('utf-8')",
            "exec(open(path).read().decode('utf-8'))",
            "const bytes = buffer.from(text, 'base64')",
            "const png = atob(datauri.split(',')[1])",
            "element.addeventlistener('click', function(event) { atob(x) })",
            "function(a, b) { return buffer.from(a, 'base64') }",
            "local chunk = load(source, name, 't', env)",
            "local s = string.char(27) .. '[0m'",
            "json.load(handle)",
            "module.load(base64.decode(icon))",
            "model.eval()",
            "pickle.load(f)",
            "const body = xhr.responsetext",
            "powershell -executionpolicy bypass -file setup.ps1",
        ] {
            assert!(!matches(line), "{line}");
        }
    }

    #[test]
    fn a_decoder_writing_a_file_names_it() {
        for (line, file) in [
            ("echo ywjj | base64 -d > /tmp/p.sh", "/tmp/p.sh"),
            ("base64 -d payload.b64 >p", "p"),
            ("xxd -r -p payload.hex | tee ./run.sh", "run.sh"),
            ("openssl enc -d -aes-256-cbc -in a -out b.sh", "b.sh"),
            (
                "true && base64 --decode <<< ywjj >> p.sh; chmod +x p.sh",
                "p.sh",
            ),
        ] {
            assert_eq!(decoded_file(line).as_deref(), Some(file), "{line}");
        }
        for line in [
            "base64 -d payload.b64",
            "base64 payload > p.b64",
            "echo ywjj | base64 -d > /dev/null",
            "echo ywjj | base64 -d 2>&1",
            "echo x > y; base64 -d z",
        ] {
            assert_eq!(decoded_file(line), None, "{line}");
        }
    }

    #[test]
    fn a_decoded_value_is_followed_to_the_call_that_runs_it() {
        for (line, name) in [
            ("code = base64.b64decode(blob)", "code"),
            ("    src = zlib.decompress(bytes.fromhex(blob))", "src"),
            ("local s = string.char(112, 114)", "s"),
            ("const src = atob(blob);", "src"),
            ("let js = buffer.from(blob, 'base64').tostring()", "js"),
        ] {
            assert_eq!(assigned_decode(line), Some(name), "{line}");
        }
        for line in [
            "if kind == base64.b64decode(x):",
            "data[key] = base64.b64decode(x)",
            "code = compile(source, name, 'exec')",
            "total += len(base64.b64decode(x))",
        ] {
            assert_eq!(assigned_decode(line), None, "{line}");
        }
        assert!(runs_name("exec(code)", "code"));
        assert!(runs_name("exec(compile(code, '<s>', 'exec'))", "code"));
        assert!(runs_name("load(s)()", "s"));
        assert!(!runs_name("exec(decode)", "code"));
        assert!(!runs_name("exec(other, code)", "code"));
        assert!(!runs_name("print(code)", "code"));
    }

    #[test]
    fn a_filter_before_an_or_is_read_to_what_is_piped_on() {
        for line in [
            "tr a b <<< x || tr c d <<< y | sh",
            "tr a b <<< x | cat || true | sh",
            "gunzip <<< x || gunzip <<< y | cat | bash",
            "echo x | tr a b || echo y | tr c d | sh",
        ] {
            assert!(matches(line), "{line}");
        }
        for line in [
            // What is piped on is the last command of its part.
            "tr a b <<< x || cat | sh",
            "tr a b <<< x || cat y | sh",
            "echo x | tr a b || true | sh",
            "tr a b <<< x ||| sh",
            // The shell is before the filter, or reads nothing.
            "sh | tr a b <<< x",
            "tr a b <<< x || sh",
            "tr a b <<< x |sh||x",
        ] {
            assert!(!matches(line), "{line}");
        }
    }

    #[test]
    fn a_long_line_of_filters_costs_one_pass() {
        use super::MAX_FOLLOWED;
        // Filters none of which is read by a shell, and then one that is.
        let filters = "tr a b<<<x|".repeat(12_000);
        assert!(!matches(&filters));
        assert!(matches(&(filters + "sh")));
        assert!(!matches(&"echo x|tr a b|".repeat(8_000)));
        // Each with a `||` after it: up to `MAX_FOLLOWED` are read on to
        // what is piped into the shell, and a line with more is taken to
        // run one.
        let followed = |count: usize| "tr a b<<<x||".repeat(count) + "cat|sh";
        assert!(!matches(&followed(MAX_FOLLOWED)));
        assert!(matches(&followed(MAX_FOLLOWED + 1)));
        assert!(matches(&followed(5_000)));
    }

    #[test]
    fn a_long_line_of_calls_costs_one_pass() {
        use super::MAX_ARGUMENT;
        // Calls that are never closed, each given the rest of the line.
        assert!(!matches(&"function(buffer.from(".repeat(8_000)));
        assert!(!matches(&"exec(".repeat(20_000)));
        assert!(!matches(&"eval(x(".repeat(15_000)));
        assert!(matches(&("exec(".repeat(20_000) + "atob(x)")));
        // Past `MAX_GIVEN` a decode call anywhere on the line counts: none
        // of these calls is given it.
        let closed = "exec(".repeat(300) + &")".repeat(300);
        assert!(!matches(&(closed.repeat(2) + " atob(x)")));
        assert!(matches(&(closed.repeat(6) + " atob(x)")));
        let named = "exec(".repeat(100) + &"x".repeat(MAX_ARGUMENT);
        assert!(!runs_name(&(named.repeat(2) + ", code"), "code"));
        assert!(runs_name(&(named.repeat(4) + ", code"), "code"));
    }
}
