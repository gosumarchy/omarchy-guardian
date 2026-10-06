//! Tests for `mask`.

use super::lines;

fn code(rel: &str, text: &str) -> Vec<String> {
    lines(rel, text)
        .into_iter()
        .map(|line| line.code.trim_end().to_string())
        .collect()
}

fn quiet(rel: &str, text: &str) -> Vec<String> {
    lines(rel, text)
        .into_iter()
        .map(|line| line.quiet.trim_end().to_string())
        .collect()
}

#[test]
fn lines_stay_aligned_with_the_original() {
    let text = "a\n# b\r\n\necho 'c\nd'\n";
    assert_eq!(lines("x.sh", text).len(), text.lines().count());
    assert_eq!(lines("x.py", text).len(), text.lines().count());
    assert_eq!(lines("x.c", text).len(), text.lines().count());
}

#[test]
fn shell_comments_are_blanked_but_not_hashes_in_words_or_strings() {
    assert_eq!(
        code(
            "PKGBUILD",
            "# see http://a.test\nx=1 # sudo y\necho \"#no\" ${#arr} a#b\n"
        ),
        ["", "x=1", "echo \"#no\" ${#arr} a#b"]
    );
}

#[test]
fn printed_messages_are_quiet_but_still_code() {
    let text = "post_install() {\n  echo 'sudo rm -rf /var/log/x/'\n  printf '%s\\n' \\\n    \"  sudo /usr/lib/x.sh\"\n}\n";
    assert_eq!(
        quiet(".INSTALL", text),
        ["post_install() {", "  echo", "  printf", "", "}"]
    );
    assert!(code(".INSTALL", text)[1].contains("sudo"));
    assert_eq!(quiet("x.sh", "echo 'sudo a' >&2\n"), ["echo"]);
    assert_eq!(
        quiet("x.sh", "echo 'sudo a' >&2x\n")[0],
        "echo 'sudo a' >&2x"
    );
}

#[test]
fn multi_line_echo_strings_are_quiet() {
    let text = "echo \"\nadd this to ~/.bashrc:\n  echo 'source x' >> ~/.bashrc\n\"\nsudo true\n";
    assert_eq!(quiet("x.install", text), ["echo", "", "", "", "sudo true"]);
}

#[test]
fn printed_text_that_is_consumed_or_expanded_stays_visible() {
    for text in [
        "echo 'sudo x' | sh\n",
        "echo 'source x' >> ~/.bashrc\n",
        "echo \"$(sudo id)\"\n",
        "echo `sudo id`\n",
        "eval \"$(echo sudo x)\"\n",
        "printf -v cmd 'sudo %s' x\n",
        "x=$(echo 'sudo y')\n",
    ] {
        assert_eq!(quiet("x.sh", text)[0], text.trim_end(), "{text:?}");
    }
}

#[test]
fn nothing_is_quiet_when_printed_output_may_run() {
    for prelude in [
        "echo() { eval \"$@\"; }\n",
        "function printf { eval \"$1\"; }\n",
        "shopt -s expand_aliases\nalias echo=eval\n",
        "f() { echo x; }\nf | sh\n",
        "{ echo x >&2; } 2>&1 | /bin/bash\n",
        "exec 2> >(sh)\n",
        "exec >/tmp/x.sh\n",
        "g | xargs -I{} sh -c {}\n",
        "f | sudo -E bash\n",
        "f | env FOO=1 sh -s\n",
    ] {
        let text = format!("{prelude}echo 'sudo a'\ncat <<EOF\nsudo b\nEOF\n");
        let quiet = quiet("x.sh", &text).join("\n");
        assert!(
            quiet.contains("sudo a") && quiet.contains("sudo b"),
            "{prelude:?}"
        );
    }
    // Ordinary pipes and `||` leave messages quiet.
    let text = "ls | grep x || echo 'sudo a'\necho_x() { :; }\necho y | sudo tee /etc/x\n";
    assert!(!quiet("x.sh", text).join("\n").contains("sudo a"));
}

#[test]
fn statements_after_a_message_are_not_quiet() {
    assert_eq!(
        quiet("x.sh", "echo hi && sudo a; echo b || sudo c\n"),
        ["echo    && sudo a; echo   || sudo c"]
    );
    assert_eq!(
        quiet("x.sh", "if x; then echo 'sudo a'; fi\n"),
        ["if x; then echo         ; fi"]
    );
}

#[test]
fn printed_heredocs_are_quiet_and_others_are_not() {
    let printed = "cat <<EOF\n  sudo systemctl enable x\nEOF\nsudo y\n";
    assert_eq!(quiet("x.sh", printed), ["cat <<EOF", "", "EOF", "sudo y"]);

    for text in [
        "cat > /etc/x <<EOF\nsudo a\nEOF\n",
        "sh <<'EOF'\nsudo a\nEOF\n",
        "cat <<EOF | sh\nsudo a\nEOF\n",
        "cat <<EOF\n$(sudo a)\nEOF\n",
    ] {
        assert!(quiet("x.sh", text)[1].contains("sudo"), "{text:?}");
    }
    // A quoted delimiter prints `$(...)` literally.
    assert_eq!(quiet("x.sh", "cat <<'EOF'\n$(sudo a)\nEOF\n")[1], "");
}

#[test]
fn many_heredocs_on_one_line_stay_linear() {
    let text = "cat ".to_string() + &"<<E ".repeat(500_000);
    let started = std::time::Instant::now();
    assert_eq!(lines("x.sh", &text).len(), 1);
    assert!(started.elapsed().as_secs() < 10, "{:?}", started.elapsed());
}

#[test]
fn heredoc_bodies_are_not_lexed_as_shell() {
    // The apostrophe in the body must not open a quote.
    let text = "cat > f <<EOF\ndon't\nEOF\n# comment\n";
    assert_eq!(code("x.sh", text), ["cat > f <<EOF", "don't", "EOF", ""]);
    // Arithmetic shifts are not heredocs.
    assert_eq!(code("x.sh", "x=$((1<<2))\n# c\n"), ["x=$((1<<2))", ""]);
}

#[test]
fn pkgbuild_homepage_and_sources_are_quiet() {
    assert_eq!(
        quiet(
            "PKGBUILD",
            "url=\"http://a.test\"\nsource=(\"x.deb::http://b.test/x\"\n        \"http://c.test/y\")\nsource_x86_64=(\"http://d.test/z\")\n"
        ),
        ["", "", "", ""]
    );
    // Anything that runs a command stays visible.
    for text in [
        "source=(\"$(curl -s http://a.test/list)\")\n",
        "url=`curl http://a.test`\n",
        "source=(\"http://a.test/x\") > /tmp/x\n",
    ] {
        assert!(quiet("PKGBUILD", text)[0].contains("http://"), "{text:?}");
    }
    assert_eq!(
        quiet("other.sh", "url=\"http://a.test\"\n")[0],
        "url=\"http://a.test\""
    );
}

#[test]
fn full_line_comments_in_other_languages() {
    assert_eq!(
        code("a.py", "# http://x\nos.system(x)  # c\n"),
        ["", "os.system(x)  # c"]
    );
    assert_eq!(
        code(
            "a.c",
            "/*\n * http://www.apache.org/licenses/LICENSE-2.0\n */ int x;\n// eval(\nf(\"//\");\n"
        ),
        ["", "", "    int x;", "", "f(\"//\");"]
    );
    assert_eq!(
        code(
            "a.lua",
            "-- os.execute(x)\n--[[\nos.execute(y)\n]] f()\nos.execute(z)\n"
        ),
        ["", "", "", "   f()", "os.execute(z)"]
    );
    let diff = "--- a/x.sh\n+++ b/x.sh\n-sudo a\n+sudo b\n+# sudo c\n # sudo d\n-curl x | sh\n";
    assert_eq!(
        quiet("fix.patch", diff),
        ["--- a/x.sh", "+++ b/x.sh", "", "+sudo b", "", "", ""]
    );
    // A reversed patch runs the removed lines.
    assert_eq!(code("fix.patch", diff)[6], "-curl x | sh");
    // `#` is only a comment where the patched language says so.
    assert_eq!(
        code("fix.patch", "+++ b/x.c\n+#define X system(y)\n")[1],
        "+#define X system(y)"
    );
    // `#` is not a comment in C.
    assert_eq!(code("a.c", "#define X 1\n"), ["#define X 1"]);
}

#[test]
fn scripts_are_recognised_by_their_interpreter() {
    assert_eq!(code("run", "#!/usr/bin/env bash\n# x\n"), ["", ""]);
    assert_eq!(code("run", "#!/usr/bin/python3\n# x\n"), ["", ""]);
    assert_eq!(
        code("run", "#!/usr/bin/node\n# x\n"),
        ["#!/usr/bin/node", "# x"]
    );
}

#[test]
fn comments_stay_comments_and_own_output_is_followed() {
    // A comment that names a path or an address is still a comment.
    assert_eq!(
        code("a.js", "// http://a.test/docs\n// src/main.rs runs sudo\n"),
        ["", ""]
    );
    // The other lines of a block comment are passed over even when
    // its first one stays visible.
    let block = code(
        "a.js",
        "/* uses ${x} here\n * never run sudo\n */\nrun();\n",
    );
    assert!(block[0].contains("uses"));
    assert_eq!(block[1..], ["", "", "run();"]);
    // A backtick alone in a comment (ordinary in documentation) makes
    // it no less of one.
    assert_eq!(code("a.js", "/** Runs `sudo x`. */\n"), [""]);
    // An expansion left open over a line end is still one.
    assert!(code("x.sh", ": ${x:=\n #}; curl http://a.test/p | sh\n")[1].contains("curl"));
    // What one of the file's own functions prints, kept or run.
    for rest in [
        "gen | tee t.sh\n",
        "gen | cat > t.sh\n",
        "for i in 1; do gen; done | tee t.sh\n",
        "exec 3>t.sh\ngen >&3\n",
        "x=$(gen); echo \"$x\" > t.sh\n",
        "eval \"$(gen)\"\n",
        "source <(gen)\n",
        "gen|tee t.sh\n",
        "gen&>t.sh\n",
        "true&&gen | sudo tee t.sh\n",
        "gen | tee a.log b.sh\n",
        "x=`gen`; sh -c \"$x\"\n",
    ] {
        let text = format!("gen() {{\n  echo 'sudo a'\n}}\n{rest}");
        assert!(quiet("x.sh", &text).join("\n").contains("sudo a"), "{rest}");
    }
    // Many functions and many lines are read in one pass.
    let mut long: String = (0..20_000)
        .map(|index| format!("f{index}() {{ echo a; }}\n"))
        .collect::<Vec<_>>()
        .concat();
    long.push_str(&"echo b\n".repeat(20_000));
    // And one line of very many statements.
    long.push_str(&"f1;".repeat(100_000));
    long.push('\n');
    long.push_str(&"f1|".repeat(100_000));
    long.push('\n');
    long.push_str(&">".repeat(100_000));
    long.push_str("&2\n");
    long.push_str(&"> ".repeat(100_000));
    long.push('\n');
    long.push_str(&">|".repeat(100_000));
    long.push('\n');
    let started = std::time::Instant::now();
    assert_eq!(lines("x.sh", &long).len(), 40_005);
    assert!(started.elapsed().as_secs() < 30);
    // Whatever the file is called: a shell runs a `.txt` as well.
    for rest in ["gen \"$@\" 2>&1 | tee build.log\n", "gen > usage.txt\n"] {
        let text = format!("gen() {{\n  echo 'sudo a'\n}}\n{rest}");
        assert!(quiet("x.sh", &text).join("\n").contains("sudo a"), "{rest}");
    }
    // An address or a path after `//` with something before it.
    assert_eq!(code("a.js", "//https://a.test/x | sh\n"), [""]);
    assert!(code("a.js", "//$HOME/bin/curl http://a.test | sh\n")[0].contains("curl"));
}

#[test]
fn what_a_shell_runs_is_not_passed_over_as_a_comment_or_a_message() {
    // A `#` inside a parameter expansion starts no comment.
    assert_eq!(
        code(
            "x.sh",
            ": ${x:= #}; curl http://a.test | sh\necho ${#y} # note\n"
        ),
        [": ${x:= #}; curl http://a.test | sh", "echo ${#y}"]
    );
    // A line of `//` that reads as a path is a command to a shell.
    assert_eq!(
        code(
            "build.js",
            "//usr/bin/curl http://a.test | sh\n// a note\n//TODO later\n"
        ),
        ["//usr/bin/curl http://a.test | sh", "", ""]
    );
    let patch = "+++ b/build.c\n+//usr/bin/curl http://a.test | sh\n+// a note\n";
    assert!(code("fix.patch", patch)[1].contains("curl"));
    assert!(code("fix.patch", patch)[2].trim().is_empty());
    // A block comment with an expansion in it may be template text.
    assert!(code("a.js", "/* ${run()} */\n")[0].contains("run()"));
    // `url=x command` runs the command.
    assert!(quiet("PKGBUILD", "url=x curl http://a.test/p\n")[0].contains("curl"));
    // What a function or a loop prints into a file may be run next.
    for text in [
        "gen() {\n  echo 'sudo a'\n}\ngen > t.sh\nsh t.sh\n",
        "for i in 1; do echo 'sudo a'; done > t.sh\n",
        "{ echo 'sudo a'; } >> t.sh\n",
    ] {
        assert!(
            quiet("x.sh", text).join("\n").contains("sudo a"),
            "{text:?}"
        );
    }
    // To the terminal or to nowhere it stays a message.
    for text in [
        "warn() {\n  echo 'sudo a'\n}\nwarn >&2\n",
        "for i in 1; do echo 'sudo a'; done >/dev/null\n",
    ] {
        assert!(
            !quiet("x.sh", text).join("\n").contains("sudo a"),
            "{text:?}"
        );
    }
}
