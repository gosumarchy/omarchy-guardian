//! Reads a Hyprland Lua configuration line by line, to tell whether the
//! line that loads Guardian's PATH file can take effect.
//!
//! Like `shellscan` this is a line scanner, not an interpreter: it follows
//! comments, strings and blocks by their usual spelling and errs towards
//! "not effective". What another file loaded from here does is not seen;
//! whether the PATH really came out right is checked apart, on the PATH
//! itself.

use super::shellscan::Loads;

/// The text with comments and the insides of strings blanked, line breaks
/// kept, and for each line whether it starts inside a comment or string
/// that an earlier line opened.
fn bare(text: &str) -> (String, Vec<bool>) {
    let characters: Vec<char> = text.chars().collect();
    let mut out = String::with_capacity(text.len());
    let mut inside = vec![false];
    let mut index = 0;
    while index < characters.len() {
        let character = characters[index];
        let comment = character == '-' && characters.get(index + 1) == Some(&'-');
        let start = if comment { index + 2 } else { index };
        let end = if let Some(end) = long_bracket(&characters, start) {
            Some(end)
        } else if comment {
            Some(
                characters[index..]
                    .iter()
                    .position(|character| *character == '\n')
                    .map_or(characters.len(), |length| index + length),
            )
        } else if character == '"' || character == '\'' {
            let mut end = index + 1;
            while end < characters.len() && characters[end] != character && characters[end] != '\n'
            {
                end += if characters[end] == '\\' { 2 } else { 1 };
            }
            Some(end + 1)
        } else {
            None
        };
        if let Some(end) = end {
            // Blanked, noting the lines it spans.
            let end = end.min(characters.len());
            for character in &characters[index..end] {
                if *character == '\n' {
                    out.push('\n');
                    inside.push(true);
                } else {
                    out.push(' ');
                }
            }
            index = end;
        } else {
            out.push(character);
            if character == '\n' {
                inside.push(false);
            }
            index += 1;
        }
    }
    (out, inside)
}

/// Where the long bracket (`[[ … ]]`, `[==[ … ]==]`) opening at `start`
/// ends: past its closing bracket, or at the end of the text when it is
/// never closed. `None` when no long bracket opens there.
fn long_bracket(characters: &[char], start: usize) -> Option<usize> {
    if characters.get(start) != Some(&'[') {
        return None;
    }
    let level = characters[start + 1..]
        .iter()
        .take_while(|character| **character == '=')
        .count();
    if characters.get(start + 1 + level) != Some(&'[') {
        return None;
    }
    let mut index = start + 2 + level;
    while index < characters.len() {
        if characters[index] == ']'
            && characters[index + 1..]
                .iter()
                .take(level)
                .filter(|character| **character == '=')
                .count()
                == level
            && characters.get(index + 1 + level) == Some(&']')
        {
            return Some(index + 2 + level);
        }
        index += 1;
    }
    Some(characters.len())
}

/// The words of a line of bare code: names and keywords.
fn words(code: &str) -> impl Iterator<Item = &str> {
    code.split(|character: char| !(character.is_alphanumeric() || character == '_'))
        .filter(|word| !word.is_empty())
}

/// Whether `line`, the exact line Guardian writes, is in `text` (a
/// Hyprland Lua configuration) where it runs, with no later line setting
/// PATH again. `path` is the file the line loads.
pub(super) fn loads(text: &str, line: &str, path: &str) -> Loads {
    let (code, inside) = bare(text);
    let raw: Vec<&str> = text.lines().collect();
    let code: Vec<&str> = code.lines().collect();
    let Some(at) = raw.iter().rposition(|candidate| candidate.trim() == line) else {
        let named = raw
            .iter()
            .zip(&code)
            .zip(&inside)
            .any(|((raw, code), inside)| !inside && raw.contains(path) && !code.trim().is_empty());
        return if named {
            Loads::Ineffective("a line names it, but it is not the line Guardian writes".into())
        } else {
            Loads::Missing
        };
    };
    if inside.get(at) == Some(&true) {
        return Loads::Ineffective("it is inside a comment or a string".into());
    }
    let mut depth = 0_usize;
    for line in &code[..at.min(code.len())] {
        let mut previous = "";
        for word in words(line) {
            match word {
                "function" | "if" | "do" | "repeat" => depth += 1,
                "end" | "until" => depth = depth.saturating_sub(1),
                // At the top of the file, or as `do return end`, the only
                // way to write it before more code.
                "return" if depth == 0 || (depth == 1 && previous == "do") => {
                    return Loads::Ineffective("a `return` comes before it".into());
                }
                "exit" if previous == "os" => {
                    return Loads::Ineffective("an `os.exit` comes before it".into());
                }
                _ => {}
            }
            previous = word;
        }
    }
    if depth > 0 {
        return Loads::Ineffective("it is inside a function or block".into());
    }
    // Hyprland keeps the last value a variable is given.
    let again = raw.iter().zip(&code).skip(at + 1).any(|(raw, code)| {
        code.contains("env") && (raw.contains("\"PATH\"") || raw.contains("'PATH'"))
    });
    if again {
        return Loads::Ineffective("a later line sets PATH again".into());
    }
    Loads::Effective
}

#[cfg(test)]
mod tests {
    use super::{Loads, loads};

    const PATH: &str = "/usr/lib/omarchy-guardian/hyprland-path.lua";
    const LINE: &str = "pcall(dofile, \"/usr/lib/omarchy-guardian/hyprland-path.lua\")";

    fn why(text: &str) -> String {
        match loads(text, LINE, PATH) {
            Loads::Ineffective(why) => why,
            other => panic!("{other:?} for {text}"),
        }
    }

    #[test]
    fn guardians_line_at_the_top_level_of_the_configuration_counts() {
        let usual = format!(
            "-- Learn how\ndofile((os.getenv(\"OMARCHY_PATH\") or \"/usr/share/omarchy\") .. \"/default/hypr/bootstrap.lua\")\nrequire(\"default.hypr.omarchy\")\nrequire(\"hypr.monitors\")\nhl.on(\"hyprland.start\", function()\n  hl.exec_cmd(\"x\")\nend)\nif a then b() end\nfor i = 1, 2 do c() end\n--[[ a note\nover lines ]]\nlocal s = [[\nreturn\n]]\nhl.env(\"PATH\", \"/x\")\n\n-- Omarchy Guardian\n{LINE}\n\n-- o.window(\"qemu\", {{ workspace = \"5\" }})\no.window({{ class = \"^x$\" }}, {{ float = true }})\n"
        );
        assert_eq!(loads(&usual, LINE, PATH), Loads::Effective);
        assert_eq!(loads(&format!("  {LINE}  "), LINE, PATH), Loads::Effective);
        assert_eq!(
            loads("require(\"hypr.input\")\n", LINE, PATH),
            Loads::Missing
        );
        assert_eq!(loads(&format!("-- {LINE}\n"), LINE, PATH), Loads::Missing);
        assert_eq!(
            loads(&format!("--[[\n{PATH}\n]]\n"), LINE, PATH),
            Loads::Missing
        );
    }

    #[test]
    fn a_line_that_does_not_run_or_is_undone_is_not_effective() {
        assert!(why(&format!("--[[\n{LINE}\n]]\n")).contains("comment or a string"));
        assert!(why(&format!("local s = [==[\n{LINE}\n]==]\n")).contains("comment or a string"));
        assert!(why(&format!("if false then\n{LINE}\nend\n")).contains("function or block"));
        assert!(
            why(&format!("local function never()\n{LINE}\nend\n")).contains("function or block")
        );
        assert!(why(&format!("do return end\n{LINE}\n")).contains("`return`"));
        assert!(why(&format!("os.exit(0)\n{LINE}\n")).contains("os.exit"));
        assert!(why(&format!("{LINE}\nhl.env(\"PATH\", \"/usr/bin\")\n")).contains("PATH again"));
        assert!(why(&format!("{LINE}\nhl.env('PATH', p)\n")).contains("PATH again"));
        assert!(why(&format!("dofile(\"{PATH}\") x()\n")).contains("not the line Guardian writes"));
        assert!(why(&format!("if x then {LINE} end\n")).contains("not the line"));
        // A return inside a function that closed, and PATH named in a
        // later comment, change nothing.
        assert_eq!(
            loads(
                &format!("local function f()\n  return 1\nend\n{LINE}\n-- hl.env(\"PATH\", x)\n"),
                LINE,
                PATH
            ),
            Loads::Effective
        );
    }
}
