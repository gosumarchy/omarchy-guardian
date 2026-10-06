//! Tests for the recipe reader, with the table of what bash itself reads.

use super::lex::{Token, tokens};
use super::{Naming, Sources, sources, top_level_naming, written_variables};
use crate::test_support::{Rng, TempDir, tool_available};

fn written(recipe: &str) -> Vec<(String, Vec<String>)> {
    match sources(recipe) {
        Sources::Written(arrays) => arrays,
        other => panic!("{recipe:?}: {other:?}"),
    }
}

/// The words of each command, an array's elements after its name.
fn words(recipe: &str) -> Vec<Vec<String>> {
    let mut commands = vec![Vec::new()];
    for token in tokens(recipe).0 {
        match token {
            Token::Word(word) => {
                let elements = word.elements.unwrap_or_default();
                let last = commands.last_mut().unwrap();
                last.push(word.text);
                last.extend(elements.into_iter().map(|element| element.text));
            }
            Token::Operator(..) => commands.push(Vec::new()),
            Token::Redirect { target, .. } => {
                let last = commands.last_mut().unwrap();
                last.push(format!("> {}", target.text));
            }
        }
    }
    commands.retain(|command| !command.is_empty());
    commands
}

fn list(words: &[&str]) -> Vec<String> {
    words.iter().map(ToString::to_string).collect()
}

fn not_followed(recipe: &str) -> bool {
    matches!(sources(recipe), Sources::NotFollowed(ref why) if !why.is_empty())
}

#[test]
fn words_are_split_as_bash_splits_them() {
    assert_eq!(
        words("a=1; b=\"x ; y\" # c=3\nsource=(one\n  'two three' # note\n  four)\n"),
        [
            list(&["a=1"]),
            list(&["b=\"x ; y\""]),
            list(&["source=(", "one", "'two three'", "four"]),
        ]
    );
    // A substitution, a redirection and a here-document are no
    // command ends; `${#x}` and `$#` are no comments.
    assert_eq!(
        words("x=$(a; b | c) y=${#z} 2>&1\ncat <<EOF\nsource=(evil)\nEOF\nz=1\n"),
        [
            list(&["x=$(a; b | c)", "y=${#z}", "> 1"]),
            list(&["cat", "> "]),
            list(&["z=1"]),
        ]
    );
    assert_eq!(
        words("[[ a == b && c == d ]] && x=1\n(( a && b )); y=$'it\\'s'; z=2\n"),
        [
            list(&["[[", "a", "==", "b", "&&", "c", "==", "d", "]]"]),
            list(&["x=1"]),
            list(&["(( a && b ))"]),
            list(&["y=$'it\\'s'"]),
            list(&["z=2"]),
        ]
    );
    // Two arrays set by one command are two arrays.
    assert_eq!(
        words("depends=(a) source=(b c)\n"),
        [list(&["depends=(", "a", "source=(", "b", "c"])]
    );
}

#[test]
fn a_here_document_ends_at_its_marker_however_it_is_written() {
    for recipe in [
        "cat <<X>/dev/null\ntext\nX\nsource=(a)\n",
        "cat <<X;:\ntext\nX\nsource=(a)\n",
        "cat <<'X'|cat\n$(text)\nX\nsource=(a)\n",
        "cat <<-X\n\ttext\n\tX\nsource=(a)\n",
        "cat << \"X Y\"\ntext\nX Y\nsource=(a)\n",
        "cat <<\\X\n`text`\nX\nsource=(a)\n",
        "cat <<A <<B\none\nA\ntwo\nB\nsource=(a)\n",
    ] {
        assert_eq!(written(recipe)[0].1, ["a"], "{recipe}");
    }
    // One that never ends, or whose text bash expands, hides code.
    assert!(not_followed("source=(a)\ncat <<X\ntext\n"));
    assert!(not_followed("source=(a)\ncat <<X\n${source:=evil}\nX\n"));
    // Under a marker written without quotes, a line that ends in a
    // backslash goes on in the next, and the marker is looked for in
    // the two together.
    assert_eq!(
        words("cat <<X\ntext \\\nX\nx=1\nX\ncat <<X\nmore\nX\\\n\ny=2\n"),
        [list(&["cat", "> "]), list(&["cat", "> "]), list(&["y=2"])]
    );
    assert_eq!(
        words("cat <<-X\n\t\\\n\tX\ny=2\ncat <<-X\n\ta\\\n\tX\nx=1\nX\n"),
        [list(&["cat", "> "]), list(&["y=2"]), list(&["cat", "> "])]
    );
    // A backslash before the backslash, or a quoted marker: the line
    // ends where it ends.
    for recipe in [
        "cat <<X\ntext \\\\\nX\nsource=(a)\n",
        "cat <<'X'\ntext \\\nX\nx=1\nX\nsource=(a)\n",
        "cat <<\\X\nX\\\n\nx=1\nX\nsource=(a)\n",
    ] {
        assert_eq!(written(recipe)[0].1, ["a"], "{recipe}");
    }
    for body in ["X\\\n\nG\n", "te\\\nxt\nX\\\n\nG\nX\n"] {
        let recipe = format!("source=(good)\ncat <<X\n{body}").replace('G', GUARDED);
        assert!(not_followed(&recipe), "{recipe}: {:?}", sources(&recipe));
    }
}

#[test]
fn plain_arrays_are_written_with_their_plain_variables_put_in() {
    let recipe = "pkgname=demo\npkgver=1.2\n_commit=abc123 # pinned\nurl=\"https://example.org/$pkgname\"\n\
source=(\"$pkgname-$pkgver.tar.gz::$url/archive/v${pkgver}.tar.gz\"\n        'fix.patch'\n        \"git+$url.git#commit=$_commit\")\n\
sha256sums=('abc'\n            SKIP 'SKIP')\nbuild() {\n  local source=x\n  eval make\n  BUILDDIR=b make\n}\n";
    assert_eq!(
        written(recipe),
        [
            (
                "source".to_string(),
                list(&[
                    "demo-1.2.tar.gz::https://example.org/demo/archive/v1.2.tar.gz",
                    "fix.patch",
                    "git+https://example.org/demo.git#commit=abc123",
                ])
            ),
            ("sha256sums".to_string(), list(&["abc", "SKIP", "SKIP"])),
        ]
    );
    // A signed checkout's `?` matches no file: no directory is named
    // like an address, unless the recipe makes one while it loads.
    let signed = "url=https://example.org/x\nsource=(git+$url.git?signed#tag=v1)\n";
    assert_eq!(
        written(signed)[0].1,
        ["git+https://example.org/x.git?signed#tag=v1"]
    );
    assert!(not_followed(&format!(
        "mkdir -p git+https:/example.org\n{signed}"
    )));
    assert!(not_followed(&format!(
        "_x=$(mkdir -p git+https:)\n{signed}"
    )));
    assert!(not_followed("source=(x?signed::https://example.org/x)\n"));
    // The package base is the first package name.
    assert_eq!(
        written("pkgname=(one two)\nsource=($pkgbase.tar)\n")[0].1,
        ["one.tar"]
    );
    assert_eq!(
        written("export _x=1\nsource=(\"$_x.tar\")\n")[0].1,
        ["1.tar"]
    );
}

#[test]
fn sources_worked_out_from_written_values_are_derived() {
    for recipe in [
        "pkgver=1.2.3\nsource=(\"https://example.org/${pkgver%.*}/x.tar.gz\")\n",
        "source=(a)\nsource+=(b)\n",
        "source=(a)\nsource_x86_64=(\"x-$CARCH.tar\")\n",
        "case \"$CARCH\" in\n  x86_64) _a=amd64 ;;\n  aarch64|armv7h) _a=arm64 ;;\nesac\nsource=(\"x_$_a.deb\")\n",
        "[[ $CARCH == x86_64 ]] && source+=(a)\n",
        "[[ $CARCH == x86_64 || $CARCH == i686 ]] && source+=(a)\n",
        "if [ \"$CARCH\" = aarch64 ]; then\n  source=(b)\nelse\n  source=(c)\nfi\n",
        // Both ways set a written-out value.
        "if [[ $CARCH == x86_64 ]]; then _a=amd64; else _a=arm64; fi\nsource=(\"x-$_a.tar\")\n",
        "[[ $CARCH == x86_64 ]] && _a=amd64 || _a=arm64\nsource=(\"x-$_a.tar\")\n",
        "pkgver=1.2rc1\nif [[ $pkgver == *rc* ]]; then _d=testing; else _d=stable; fi\nsource=(\"$_d/x.tar\")\n",
        "_langs=(de fr)\nsource=()\nfor _l in \"${_langs[@]}\"; do\n  source+=(\"$_l.xpi\")\ndone\n",
        "source=({a,b}.tar)\n",
        // An element set by its number, always (pacman-contrib#119).
        "source=(a b)\nsha256sums=(x y)\nsha256sums[1]='SKIP'\n",
        "source=(a/b.tar c)\nnoextract=(\"${source[@]##*/}\")\n",
        "_names=(a b)\n_url=https://example.org\nsource=(\"${_names[@]/#/$_url/}\")\n",
        "create_links() { :; }\nsource=(a)\nsource+=(b)\n",
        "_n=$(nproc)\nif test \"$_n\" -ge 4; then _j=4; fi\nsource=(a)\nsource+=(b)\n",
    ] {
        assert_eq!(sources(recipe), Sources::Derived, "{recipe}");
    }
}

#[test]
fn sources_set_where_guardian_cannot_follow_are_named() {
    for recipe in [
        "[[ -w . ]] && source=(evil)\n",
        "[[ -w . ]] || source=(evil)\n",
        "source[$i]=evil\n",
        "[[ -w . ]] && source[0]=evil\n",
        "source[0]=$(curl x)\n",
        "source=evil\n",
        "declare -a source=(evil)\n",
        "typeset -a source=(evil)\n",
        "declare -n ref=source\n",
        "local -n ref=sha256sums\n",
        "readonly noextract=(x)\n",
        "eval 'source=(evil)'\n",
        "builtin eval 'source=(evil)'\n",
        "printf -v source %s evil\n",
        "v=source; printf -v \"$v\" %s evil\n",
        "read -r -a source <<<\"evil\"\n",
        "mapfile -t source < list\n",
        "readarray -t sha256sums < list\n",
        "if [ -e /.dockerenv ]; then source=(a); fi\n",
        "case $HOME in /home/*) source=(a) ;; esac\n",
        "while read -r _l; do source+=(a); done < list\n",
        "for x in $(ls); do source+=(a); done\n",
        "_f() { source=(evil); }\n_f\n",
        "_f() { eval \"$1\"; }\n_f x\n",
        "source=($(curl -s https://example.org/list))\n",
        "source=(`cat list`)\n",
        "_v=$(uname -r)\nsource=(\"x-$_v.tar\")\n",
        "source=(\"$HOME/x.tar\")\n",
        "[[ -n $DISPLAY ]] && _v=a\nsource=(\"x-$_v.tar\")\n",
        "source=(a)\n. ./more.sh\n",
        "source other\nsource=(a)\n",
        "trap 'source=(evil)' DEBUG\n",
        "source=(a)\nexit 0\n",
        "curl() { /usr/bin/curl evil; }\nsource=(a)\n",
        "prepare() { :; }\nprepare\n",
        ": \"${source:=evil}\"\n",
        "BUILDDIR=/x\n",
        "printf -v PKGDEST %s /x\n",
        "unset source\n",
        "source_x86_64[x]=evil\n",
        "source+=evil\n",
        "x=1 source=evil true\n",
        "DLAGENTS=(\"https::/usr/bin/evil $HOME\")\n",
        "_x=${!y}\nsource=($_x)\n",
        // Text that could hide code from a reader that pairs quotes
        // or braces otherwise than bash.
        "_x=$(cat <<E\n'\nE\n)\nsource=(evil) # '\n",
        "_f() { (true) }\nsource=(a)\n_g() { :; }\n}\n",
        "_f() {\n  :\nsource=(a)\n",
        "x=\"unclosed\nsource=(a)\n",
    ] {
        assert!(not_followed(recipe), "{recipe}: {:?}", sources(recipe));
    }
}

/// Each of these gave another answer in the listing than in the build
/// while reading as plain: the guard looks at something the listing's
/// jail changes.
#[test]
fn a_guard_bash_applies_is_one_guardian_sees() {
    let guard = "[[ -w PKGBUILD ]]";
    for body in [
        // A new line after `&&` ends no chain.
        "G &&\nsource=(evil)\n",
        "G ||\n\n  source=(evil)\n",
        // A group, a subshell or a compound command under a chain.
        "G && {\n  :\n  source=(evil)\n}\n",
        "G && { :; source+=(evil); }\n",
        "G || if true; then source=(evil); fi\n",
        "G && for _x in a; do source=(evil); done\n",
        "G && case a in a) source=(evil) ;; esac\n",
        "if G; then :; else source=(evil); fi\n",
        "if true; then G || source=(evil); fi\n",
        "G && _v=evil\nsource=(\"$_v\")\n",
        "G && { _v=evil; }\nsource=(\"good$_v\")\n",
        "! G || source=(evil)\n",
        "G; (( $? )) && source=(evil)\n",
        "G && x=(a) source=(evil)\n",
        "G && return\nsource+=(evil)\n",
        "_f() { G && return; source=(evil); }\n_f\n",
        "for _x in a b; do G && break; source=(evil); done\n",
    ] {
        let recipe = format!("source=(good)\n{}", body.replace('G', guard));
        assert!(not_followed(&recipe), "{recipe}: {:?}", sources(&recipe));
    }
}

#[test]
fn a_command_named_in_quotes_or_by_a_variable_is_not_followed() {
    for recipe in [
        "_f() { source=(evil); }\n\"_f\"\n",
        "_f() { source=(evil); }\n_f''\n",
        "_f() { source=(evil); }\n_g=_f\n$_g\n",
        "\\eval 'source=(evil)'\n",
        "'eval' 'source=(evil)'\n",
        "_e=eval\n$_e 'source=(evil)'\n",
        "\\. ./more.sh\n",
        "\"source\" ./more.sh\n",
        "command eval 'source=(evil)'\n",
        "builtin source ./more.sh\n",
        "command -p builtin eval x\n",
        "e\"\"val x\n",
        "${_x:-eval} x\n",
        // A function makepkg itself defines.
        "array_build source _x\n",
        "source_safe ./more.sh\n",
        "_f() { :; }\n_f() { source=(evil); }\n_f\n",
        "_f() { :; }\nunset -f _f\n_f\n",
    ] {
        assert!(not_followed(recipe), "{recipe}: {:?}", sources(recipe));
    }
}

#[test]
fn a_watched_name_given_to_a_command_in_any_quoting_is_seen() {
    for recipe in [
        "printf -v s''ource %s evil\n",
        "printf -vsource %s evil\n",
        "read sou\\rce\n",
        "read -r \"source\" < f\n",
        "read -rasource < f\n",
        "declare s\"ource\"=x\n",
        "declare 'source=x'\n",
        "local sou\\rce=x\n",
        "typeset \"$_n\"=x\n",
        "export \"source\"\n",
        "readonly 's'ource\n",
        "mapfile -t 'source' < f\n",
        "readarray \"source\" < f\n",
        "mapfile -C 'source=(evil);:' -c 1 _x < f\n",
        "getopts a source\n",
        "getopts a \"sou\"rce\n",
        "let source=1\n",
        "let 'BUILDDIR = 5'\n",
        "(( source = 1 ))\n",
        "(( BUILDDIR++ ))\n",
        "_e='source=1'\n(( _e ))\n",
        "_e='source[0]=1'\n_v=$(( _e ))\n",
        "_e='x[$(id)]'\n[[ $_e -eq 1 ]] && :\n",
        "[[ $(cat f) -eq 1 ]] && :\n",
        "_v=$(cat f)\n[[ $_v -ge 0 ]] && :\n",
        "_e='x[$(id)]'\n_a=(1 2)\n_v=${_a[$_e]}\n",
        ": ${source:=x}\n",
        ": \"${source=x}\"\n",
        "_v=${noextract:=x}\n",
        "echo ${_a:-${source:=x}}\n",
        "coproc source { :; }\n",
        "declare -n _r=source\n_r=(evil)\n",
        "declare -n _r\n",
        "declare -i _i\n_i='source=1'\n",
        "for source in evil; do :; done\n",
        "for sha256sums in a; do :; done\n",
        "select source in evil; do :; done\n",
        "while read source; do :; done < f\n",
        "while read -r _x source; do :; done < f\n",
        "wait -p source\n",
        "exec {source}>f\n",
        "unset 'source'\n",
        "unset sou\\rce\n",
        "_x=1 source=(evil) true\n",
    ] {
        assert!(not_followed(recipe), "{recipe}: {:?}", sources(recipe));
    }
}

#[test]
fn what_can_differ_between_two_runs_reaches_no_source() {
    for value in [
        "/home/*/.bash_history",
        "*.patch",
        "x?.tar",
        "[ab].tar",
        "~/x.tar",
        "~user/x",
        "$HOME/x",
        "$USER",
        "$PWD",
        "$RANDOM",
        "$SECONDS",
        "$EPOCHSECONDS",
        "$$",
        "$PPID",
        "$HOSTNAME",
        "$UID",
        "$EUID",
        "$BASHPID",
        "${BASH_VERSION}",
        "$SHLVL",
        "$TERM",
        "$DISPLAY",
        "$WAYLAND_DISPLAY",
        "$XDG_RUNTIME_DIR",
        "$PATH",
        "$1",
        "$@",
        "$?",
        "$(id -u)",
        "`id -u`",
        "$((RANDOM % 2))",
        "$(( $(id -u) + 1 ))",
        "${_unset:-x}",
        "${HOME:+x}",
        "${HOME##*/}",
        "${#HOME}",
        "<(echo x)",
        ">(cat)",
        "$\"text\"",
        "$[1+1]",
    ] {
        // In a source, in a variable a source reads, and in what a
        // condition or a loop depends on.
        for recipe in [
            format!("source=(good {value})\n"),
            format!("_x=({value})\nsource=(good ${{_x[0]:+evil}})\n"),
            format!("_x=({value})\nsource=(good)\n[[ -n $_x ]] && source+=(evil)\n"),
            format!("source=(good)\nfor _f in {value}; do source+=(evil); done\n"),
            format!("_x=({value})\nsource=(good)\ncase ${{_x[0]}} in ?*) source+=(evil) ;; esac\n"),
            format!("_x=({value})\n_y=a\n_y+=$_x\nsource=(\"$_y\")\n"),
        ] {
            assert!(not_followed(&recipe), "{recipe}: {:?}", sources(&recipe));
        }
    }
    // Looking at a file, or asking whether a command is there.
    for test in [
        "[[ -e /x ]]",
        "[[ -f x ]]",
        "[[ -d x ]]",
        "[[ -w . ]]",
        "[[ -r x ]]",
        "[[ -x x ]]",
        "[[ -s x ]]",
        "[[ -t 1 ]]",
        "[[ (-e x) ]]",
        "[[ a == a && -e x ]]",
        "[ -e x ]",
        "test -e x",
        "[ x = * ]",
        "type git",
        "command -v git",
        "hash git",
        "git --version",
        "cd /x",
        "{ true; }",
        "(true)",
        "ls | grep -q x",
        "[[ a < $HOME ]]",
    ] {
        for recipe in [
            format!("source=(good)\n{test} && source+=(evil)\n"),
            format!("source=(good)\nif {test}; then source+=(evil); fi\n"),
            format!("source=(good)\nwhile {test}; do source+=(evil); done\n"),
            format!("_v=good\n{test} || _v=evil\nsource=($_v)\n"),
        ] {
            assert!(not_followed(&recipe), "{recipe}: {:?}", sources(&recipe));
        }
    }
    // What one round of a loop sets, the next one reads.
    assert!(not_followed(
        "_c=a\nfor _i in 1 2 3; do source+=($_c); _c=$_b; _b=$_a; _a=$(id); done\n"
    ));
    // A variable set beside the shell, or for a function only, keeps
    // what the environment gave it.
    for recipe in [
        "(_v=good)\nsource=($_v)\n",
        "_v=good | true\nsource=($_v)\n",
        "_v=good &\nsource=($_v)\n",
        "_v=good true\nsource=($_v)\n",
        "_f() { local HOME=good; }\n_f\nsource=($HOME)\n",
    ] {
        assert!(not_followed(recipe), "{recipe}: {:?}", sources(recipe));
    }
}

#[test]
fn lines_of_package_that_makepkg_runs_are_read_as_top_level() {
    for recipe in [
        "source=(a)\npackage() {\n  depends=(foo) source=($([[ -w PKGBUILD ]] && echo evil || echo good))\n}\n",
        "source=(a)\npackage() { depends=(foo) source=(evil); }\n",
        "source=(a)\npackage_demo() {\n  pkgdesc=x source=(evil)\n}\n",
        "source=(a)\npackage() {\n  if true; then\n    depends+=(foo) && source=(evil)\n  fi\n}\n",
        "source=(a)\npackage() {\n  depends=(foo) BUILDDIR=/x\n}\n",
        "source=(a)\npackage() {\n  depends=(${source:=evil})\n}\n",
        "source=(a)\npackage() {\n  depends=(foo) && eval x\n}\n",
        "source=(a)\npackage() {\n  depends=(>(printf x))\n}\n",
        "source=(a)\npackage() {\n  options=(a) sha256sums=(evil)\n}\n",
        // Text that bash prints back as a line of its own.
        "source=(a)\npackage() {\n  cat <<E\n depends=(h) source=(evil)\nE\n}\n",
        "source=(a)\npackage() {\n  echo \"x\n depends=(s) source=(evil)\"\n}\n",
    ] {
        assert!(not_followed(recipe), "{recipe}: {:?}", sources(recipe));
    }
    // An attribute alone on its line sets nothing else.
    for recipe in [
        "source=(a)\npackage() {\n  depends=(foo\n    bar)\n  pkgdesc=\"x $pkgname\"\n  provides=(\"x=$pkgver\")\n  source=(evil)\n}\n",
        "source=(a)\npackage() {\n  depends=($(echo x))\n  install -Dm644 a b\n  cat <<E\n url=https://example.org\nE\n}\n",
        "source=(a)\nbuild() {\n  depends=(foo) source=(evil)\n}\n",
    ] {
        assert_eq!(written(recipe)[0].1, ["a"], "{recipe}");
    }
}

#[test]
fn quoting_that_bash_reads_as_one_word_hides_nothing() {
    // `$'\''` is one quote character; what follows is code.
    assert!(not_followed("x=$'\\''; eval evil #'\n"));
    // A comment inside a substitution opens no quote.
    assert!(not_followed("_x=$(echo a # it's\n)\neval evil # '\n"));
    // A `}` given to a command closes nothing.
    assert_eq!(
        written("_g() { echo }; }\nbuild() { _g; }\nsource=(a)\n")[0].1,
        ["a"]
    );
    // `${ ... }` holds blanks and `&` without ending a statement, so
    // the function's closing brace is the one bash takes.
    assert_eq!(
        sources("build() {\n  x=${CFLAGS/-g }\n  y=${v/a/&b}\n  eval z\n}\nsource=(a)\n"),
        Sources::Written(vec![("source".into(), vec!["a".into()])])
    );
    // A space bash does not split at splits nothing: this is one
    // word, and a command of that name.
    assert!(not_followed("eval\u{a0}'source=(evil)'\n"));
    assert!(not_followed(
        "x=1\u{2003}eval 'source=(evil)'\nsource=(\"$x\")\n"
    ));
    // `[[` is bash's own only where a command starts; `#` is no
    // comment in a pattern list or in arithmetic; a quote inside a
    // substitution inside quotes is a quote.
    for recipe in [
        "echo [[ ; source=(evil); : ]]\n",
        "echo @(a|#b) ; source=(evil)\n: )\n",
        ": $(( 1 #) )); source=(evil)\n: ) )\n",
        "_x=\"$(echo ')' ; echo \" )\"; source=(evil) #\"\n",
    ] {
        assert!(
            !matches!(sources(recipe), Sources::Written(ref arrays) if arrays.is_empty()),
            "{recipe}: {:?}",
            sources(recipe)
        );
    }
}

#[test]
fn a_quote_after_a_dollar_is_read_as_bash_reads_it() {
    // `$'...'` only after a `$` that stands alone: not after `\$`, and
    // not after `$$`, which is one parameter.
    for (recipe, expected) in [
        ("x=$'a\\'; y=1 # '\n", vec![list(&["x=$'a\\'; y=1 # '"])]),
        (
            "x=\\$'a\\'; y=1 # '\n",
            vec![list(&["x=\\$'a\\'"]), list(&["y=1"])],
        ),
        (
            "x=$$'a\\'; y=1 # '\n",
            vec![list(&["x=$$'a\\'"]), list(&["y=1"])],
        ),
        (
            "x=$$$'a\\'; y=1 # '\n",
            vec![list(&["x=$$$'a\\'; y=1 # '"])],
        ),
        (
            "x=\\\\$'a\\'; y=1 # '\n",
            vec![list(&["x=\\\\$'a\\'; y=1 # '"])],
        ),
        (
            "x=$?'a\\'; y=1 # '\n",
            vec![list(&["x=$?'a\\'"]), list(&["y=1"])],
        ),
        (
            "x=$(echo \\$'a\\'); y=1 # ')\n",
            vec![list(&["x=$(echo \\$'a\\')"]), list(&["y=1"])],
        ),
        (
            "x=${y#$'\\''}; y=1 # '\n",
            vec![list(&["x=${y#$'\\''}"]), list(&["y=1"])],
        ),
    ] {
        assert_eq!(words(recipe), expected, "{recipe}");
        assert!(tokens(recipe).1.is_empty(), "{recipe}");
    }
    // Where the `$` and the quote are a line apart, or inside
    // parentheses or braces after `$$`, Guardian does not say.
    for recipe in [
        "x=$\\\n'a\\'; y=1 # '\n",
        "x=$(echo $$'a\\'); y=1 # ')\n",
        "x=${y:-$$'a\\'}; y=1 # '}\n",
        "x=${y:-$$(echo })}\n",
    ] {
        assert!(!tokens(recipe).1.is_empty(), "{recipe}");
    }
}

#[test]
fn a_single_quote_in_quoted_braces_is_read_both_ways_or_not_at_all() {
    // Bash looks for the one that pairs with it, whatever stands between.
    for recipe in [
        "z=\"${x#'}\"'}\"; y=1 # '\n",
        "z=\"${x:-'}\"; y=1 # '}\"\n",
        "z=\"${x:-it's}\"\n",
        "z=\"${x%'a\\'}\"\n",
        "z=\"${x/'$y'/b}\"\n",
        "z=\"${x#${y%'}}\"\n",
        "z=\"${x#$'a\\'b'}\"\n",
    ] {
        assert!(!tokens(recipe).1.is_empty(), "{recipe}");
    }
    // A pair with plain text between reads the same either way.
    for (recipe, expected) in [
        ("z=\"${x//'.'/_}\"; y=1\n", "z=\"${x//'.'/_}\""),
        ("z=\"${x%'-bin'}\"; y=1\n", "z=\"${x%'-bin'}\""),
        ("z=\"${x:-'a b'}\"; y=1\n", "z=\"${x:-'a b'}\""),
        (
            "z=\"$(echo \"${x#'a'}\" 'b')\"; y=1\n",
            "z=\"$(echo \"${x#'a'}\" 'b')\"",
        ),
    ] {
        assert_eq!(
            words(recipe),
            [list(&[expected]), list(&["y=1"])],
            "{recipe}"
        );
        assert!(tokens(recipe).1.is_empty(), "{recipe}");
    }
    assert_eq!(
        sources("pkgver=1.2\nsource=(\"x-${pkgver//'.'/_}.tar\")\n"),
        Sources::Derived
    );
}

#[test]
fn an_expansion_cut_off_at_the_end_is_not_followed() {
    for recipe in ["x=${#", "x=\"${#", "x=$((", "x=${", "x=$(", "x=$((1 + "] {
        let recipe = format!("source=(a)\n{recipe}");
        assert!(not_followed(&recipe), "{recipe}: {:?}", sources(&recipe));
    }
    // A count and a lone `$` that are whole are read as they stand.
    assert_eq!(written("source=(a)\nx=${#}\ny=$")[0].1, ["a"]);
}

/// Pieces recipes are written with, for texts that reach far into the
/// lexer, the parser and the reader.
const PIECES: &[&str] = &[
    "source=(",
    "source+=(",
    "depends=(",
    "x=",
    "_y=",
    "a",
    "b.tar",
    "1",
    ")",
    "(",
    "\n",
    "\n",
    " ",
    " ",
    "\t",
    "'",
    "\"",
    "\\",
    "`",
    "$",
    "$x",
    "${",
    "${#",
    "${x",
    "$(",
    "$((",
    "$'",
    "}",
    "{",
    "[",
    "]",
    "[[",
    "]]",
    "((",
    "))",
    "#",
    "%",
    "/",
    ":-",
    ":=",
    "=",
    "+=",
    ";",
    ";;",
    "&",
    "&&",
    "||",
    "|",
    "<",
    ">",
    "<<",
    "<<-",
    "<<<",
    "X",
    "\nX\n",
    "!",
    "*",
    "?",
    "@",
    "~",
    "-",
    "if ",
    "then ",
    "else ",
    "fi",
    "for ",
    "in ",
    "do ",
    "done",
    "while ",
    "case ",
    "esac",
    "function ",
    "_f()",
    "_f",
    "package()",
    "build()",
    "local ",
    "declare -a ",
    "eval ",
    "read ",
    "printf -v ",
    "unset ",
    "é",
    "\u{a0}",
];

#[test]
fn no_text_makes_the_reader_panic() {
    let names = Naming {
        set: &["BUILDDIR", "x"],
        given: &["BUILDDIR", "x"],
        assigners: &["printf", "read", "declare"],
    };
    let mut rng = Rng::new(1);
    let (mut written, mut asked) = (0, 0);
    for _ in 0..2_000 {
        let text = rng.text(PIECES, 16);
        for recipe in [rng.mutated(&text, PIECES), text] {
            match sources(&recipe) {
                Sources::Written(_) | Sources::Derived => written += 1,
                Sources::NotFollowed(why) => {
                    assert!(!why.is_empty(), "{recipe:?}");
                    asked += 1;
                }
            }
            written_variables(&recipe);
            top_level_naming(&recipe, &names);
        }
    }
    // The pieces come together as shell Guardian follows, and as shell
    // it does not: the cases reach past the lexer.
    assert!(written > 100 && asked > 100, "{written} {asked}");
}

/// A command that sets a source if the directory can be written to,
/// and says that it ran.
const GUARDED: &str = "[[ -w . ]] && source=(evil) && echo RAN";

/// Recipe lines after `source=(good)`, with `G` for a command that is
/// seen to run, and whether bash 5.3 runs it.
const BASH_READS: &[(&str, bool)] = &[
    // Quotes.
    ("x='a\\'; G # '\n", true),
    ("x=\"a\\\"; G # \"\n", false),
    ("x='a\nG\n'\n", false),
    ("x=a#'b\nG # '\n", false),
    ("x=1 # '\nG # '\n", true),
    // `$'...'`, and a `$` that opens none.
    ("x=$'a\\'; G # '\n", false),
    ("x=$'a\\\\'; G # '\n", true),
    ("x=\\$'a\\'; G # '\n", true),
    ("x=$$'a\\'; G # '\n", true),
    ("x=$$$'a\\'; G # '\n", false),
    ("x=\\\\$'a\\'; G # '\n", false),
    ("x=$?'a\\'; G # '\n", true),
    ("x=\"$\"'a\\'; G # '\n", true),
    ("x=a$\\\n'b\\'; G # '\n", false),
    ("x=$(echo \\$'a\\'); G # ')\n", true),
    ("x=$(echo $$'a\\'); G # ')\n", true),
    ("x=$(echo $'a\\'); G # ')')\n", false),
    ("x=${y#$'\\''}; G # '\n", true),
    ("x=${y#$'\\''}; G # '}\n", true),
    ("x=${y:-$$'a\\'}; G # '}\n", true),
    // Quotes inside `${ ... }`, with and without quotes around it.
    ("z=\"${x#'}\"'}\"; G # '\n", true),
    ("z=\"${x%'}\"'}\"; G # '\n", true),
    ("z=\"${x/'}\"'/}\"; G # '\n", true),
    ("z=\"${x^'}\"'}\"; G # '\n", true),
    ("z=\"${x,,'}\"'}\"; G # '\n", true),
    ("z=\"${x:-'}\"; G # '}\"\n", false),
    ("z=\"${x:-'}'}\"; G\n", true),
    ("z=\"${x:-it's}\"; G\n", false),
    ("z=\"${x#'a'}\"; G\n", true),
    ("z=\"${x//'.'/_}\"; G\n", true),
    ("z=${x:-'}'}; G # '\n", true),
    ("z=${x:-a b}; G\n", true),
    ("z=\"${x:-\"}\"}\"; G # \"\n", true),
    // Substitutions.
    ("x=\"$(echo ')')\"; G\n", true),
    ("x=\"$(echo \"a b\")\"; G\n", true),
    ("x=$(echo a # '\n)\nG # '\n", true),
    ("x=`echo \\`; G # \\``\n", false),
    // Here-documents.
    (": <<X\nG\nX\n", false),
    (": <<X\ntext\nX\nG\n", true),
    (": <<X\ntext\n X\nG\nX\n", false),
    (": <<-X\n\ttext\n\tX\nG\n", true),
    (": <<-X\n text\n X\nG\n\tX\n", false),
    (": <<X\"Y\"\n$x\nXY\nG\n", true),
    (": <<A <<B\none\nA\nG\nB\n", false),
    (": <<A; : <<B\none\nA\ntwo\nB\nG\n", true),
    // Lines joined by a backslash inside one.
    (": <<true\ntr\\\nue\nG\ntrue\n", true),
    (": <<X\ntext\nX\\\n\nG\nX\n", true),
    (": <<X\n\\\nX\nG\n", true),
    (": <<X\ntext \\\nX\nG\nX\n", false),
    (": <<X\ntext\nX\\\\\n\nG\nX\n", false),
    (": <<'X'\ntext\nX\\\n\nG\nX\n", false),
    (": <<\\X\ntext\nX\\\n\nG\nX\n", false),
    (": <<X''\nte\\\nxt\nX\\\n\nG\nX\n", false),
    (": <<-X\n\t\\\n\tX\nG\n", true),
    (": <<-X\n\tte\\\n\tX\nG\nX\n", false),
    (": <<-X\n\ttext\n\t\\\nX\nG\n", true),
    // A marker over two lines is one written without quotes.
    (": <<X\\\nY\nG\nXY\nG\n", true),
    (": <<X\\\nY\nX\\\nY\nG\nXY\n", true),
    // A line joined between `<<` and its `-`, or after a `$`.
    (": <<\\\n-X\n\tX\nG\n-X\n", true),
    ("x=\"$\\\n(echo '\"')\"; G # '\n", true),
    ("x=${y:-$\\\n'a\\''}; G # '}\n", true),
    ("x=$(echo $\\\n'a\\''); G; : $( # '\n)\n", true),
    // A marker that is more than a word.
    (": <<$'X'\nX\nG\n$X\n", true),
    (": <<$\"X\"\n$X\n: '\nX\nG # '\n", true),
    (": <<\"X\\\\\"\nX\\\nG\nX\\\\\n", true),
    (": <<`a b`\n`a b`\nG`\n`a\n", true),
    // A `#` after an escaped character or a joined line, and one
    // straight after an array.
    ("x=$(echo \\ #); G; : $(\n)\n", true),
    ("x=$(echo \\;#); G; : $(\n)\n", true),
    ("x=$(echo \\(#); G; : $(\n)\n", true),
    ("x=$(echo a\\\n#); G; : $(\n)\n", true),
    ("x=(a)#b; G\n", true),
    // `<` and `<` joined, and an escaped `<` before `<<`.
    ("x=$(: <\\\n<X\n'\nX\n); G; : $( # '\n)\n", true),
    ("x=$(:\\<<<X\n'\nX\n); G; : $( # '\n)\n", true),
    // A `$` in a marker's double quotes, and a pattern list on one.
    (": <<\"${y+\" \"}\"\n${y+ }\nG\n${y+\nx=1}\n", true),
    ("shopt -s extglob\n: <<X+(a b)\nX+(a b)\nG\nX+\n", true),
    // A here-document named in a substitution that closes on its line.
    ("x=$(: <<X)\ny='\nX\nG # '\n", true),
    ("x=\"$(: <<-X)\"\ny='\nX\nG # '\n", true),
    // A `#` straight after a group inside a substitution.
    ("x=$( (:)# '\n); G # ')\n", true),
    // Bash drops a NUL as it reads the file.
    ("x=$\0$'a\\'; G # '\n", true),
    (": <<X\0\nX\nG\nX\0\n", true),
];

/// Whether bash runs the `G` in each of `BASH_READS`, as it loads them
/// the way makepkg loads a recipe. Where it does, Guardian must have
/// read the command: text that bash takes for code is never text to
/// Guardian.
#[test]
fn what_bash_runs_is_code_to_guardian() {
    if !tool_available("/usr/bin/bash") {
        return;
    }
    let dir = TempDir::new("recipe-bash");
    let mut wrong = Vec::new();
    for &(body, runs) in BASH_READS {
        let recipe = format!("source=(good)\n{}", body.replace('G', GUARDED));
        std::fs::write(dir.path().join("PKGBUILD"), &recipe).unwrap();
        let output = std::process::Command::new("/usr/bin/bash")
            .args(["-c", "source ./PKGBUILD"])
            .current_dir(dir.path())
            .env_clear()
            // Nothing here needs a program, and none is to be found.
            .env("PATH", dir.path())
            .stdin(std::process::Stdio::null())
            .output()
            .unwrap();
        let ran = String::from_utf8_lossy(&output.stdout).contains("RAN");
        if ran != runs {
            wrong.push(format!("bash runs it ({ran}) in {recipe:?}"));
        } else if ran && !not_followed(&recipe) {
            wrong.push(format!("{recipe:?}: {:?}", sources(&recipe)));
        }
    }
    assert!(wrong.is_empty(), "{wrong:#?}");
}

#[test]
fn what_a_recipe_does_elsewhere_is_no_reason_to_ask() {
    for recipe in [
        // A redirection whose file is on the next, joined line, and a
        // comment in one substitution after an escape in another.
        "source=(a)\nbuild() {\n  sed s/a/b/ x > \\\n    \"$pkgdir/y\"\n  cat < \\\n    x 2>> \\\n    log\n}\n",
        "x=$(a \\; b)\ny=$(ab; #c\n)\nsource=(a)\n",
        "pkgname=demo\nsource=(a)\nbuild() {\n  eval \"$(x)\"\n  printf -v v %s y\n  export BUILDDIR=b\n  read -r source < f\n}\n",
        "_helper() { local x=$1; echo \"$x\"; }\npackage() { _helper a; }\nsource=(a)\n",
        "shopt -s extglob\nsource=(a)\nprintf '%s\\n' hello\n",
        "# source=(evil)\nsource=(a) # eval\n",
        "pkgdesc=\"eval; source=(x) && exit\"\nsource=(a)\n",
        "package_demo() {\n  depends=(x)\n  source=(evil)\n}\nsource=(a)\n",
        "build() {\n  if true; then\n    make\n  fi\n  for x in a; do :; done\n}\nsource=(a)\n",
        "package(){\n  install -Dm755 x \"${pkgdir}/usr/bin/x\"\n}\nsource=(a)\n",
        "function _f {\n  :\n}\nsource=(a)\n",
        // Shell that only a function runs is read past, whatever it is.
        "source=(a)\nbuild() {\n  case $x in\n    a|b) make ;;\n    (c) : ;&\n    *) rm !(keep) ;;\n  esac\n  while read -r l; do :; done < <(ls)\n  for ((i=0; i<3; i++)); do :; done\n  [[ $x =~ ^(a|b)$ ]] && (cd x && make) |& tee log &>/dev/null\n  cat > f <<-EOF\n\t$x )\n\tEOF\n  x=$(( 1 << 2 ))\n  y=$(sed s/a/b/ <<< \"$x\")\n}\n",
        // Programs and what they are given depend on the run; they set
        // nothing in the shell that reads the recipe.
        "source=(a)\necho \"$HOME\" *.c > /dev/null\n[[ -e x ]] && msg hello\n",
    ] {
        assert_eq!(written(recipe)[0].1, ["a"], "{recipe}");
    }
}

#[test]
fn written_variables_are_the_plain_top_level_ones() {
    assert_eq!(
        written_variables(
            "pkgname=demo-bin\n_name=${pkgname%-bin}\n_bin=tool\npkgver=1\n[[ -n $X ]] && _c=1\nbuild() { _in=1; }\n"
        ),
        [
            ("pkgname".to_string(), "demo-bin".to_string()),
            ("pkgver".into(), "1".into()),
            ("_bin".into(), "tool".into()),
        ]
    );
}

#[test]
fn a_path_variable_is_found_however_its_name_is_quoted() {
    let names = Naming {
        set: &["BUILDDIR", "srcdir"],
        given: &["BUILDDIR"],
        assigners: &["printf", "read", "declare"],
    };
    let lines = |recipe: &str| top_level_naming(recipe, &names).unwrap();
    assert_eq!(lines("pkgname=x\ndeclare BUILD''DIR=/x\n"), [2]);
    assert_eq!(lines("export \"BUILDDIR\"=/x\n"), [1]);
    assert_eq!(lines("printf -v BUILD\\DIR %s /x\n"), [1]);
    assert_eq!(lines("command printf -v 'BUILDDIR' %s /x\n"), [1]);
    assert_eq!(lines("true &&\n  srcdir=/x\n"), [2]);
    assert_eq!(lines("for BUILDDIR in /x; do :; done\n"), [1]);
    assert_eq!(lines("$_c BUILDDIR\n"), [1]);
    assert!(lines("build() { BUILDDIR=/x; }\necho \"$BUILDDIR\" BUILDDIR\n").is_empty());
}

/// Run with `GUARDIAN_RECIPE_SAMPLES=<dir of package dirs> cargo test
/// measures_real_recipes -- --ignored --nocapture` to see how real
/// recipes are classified.
#[test]
#[ignore = "needs a directory of real PKGBUILDs"]
fn measures_real_recipes() {
    let Some(root) = std::env::var_os("GUARDIAN_RECIPE_SAMPLES") else {
        return;
    };
    let (mut total, mut plain, mut derived, mut asked, mut differs) = (0, 0, 0, 0, 0);
    for entry in std::fs::read_dir(root).unwrap().flatten() {
        let Ok(recipe) = std::fs::read_to_string(entry.path().join("PKGBUILD")) else {
            continue;
        };
        total += 1;
        match sources(&recipe) {
            Sources::Written(arrays) => {
                plain += 1;
                if let Ok(listing) = std::fs::read_to_string(entry.path().join(".SRCINFO"))
                    && let Some(what) = crate::aur::written_mismatch(&arrays, &listing)
                {
                    differs += 1;
                    outln!("DIFFERS {}: {what}", entry.path().display());
                }
            }
            Sources::Derived => derived += 1,
            Sources::NotFollowed(why) => {
                asked += 1;
                outln!("ASKED {}: {why:?}", entry.path().display());
            }
        }
    }
    outln!(
        "{total} recipes: {plain} written ({differs} differ from their .SRCINFO), {derived} derived, {asked} not followed"
    );
}
