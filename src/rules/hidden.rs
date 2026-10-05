//! Characters a reader does not see, or sees in another order.
//!
//! None of them changes what a program does: `cu<zero width space>rl` is
//! simply a different name to a shell. What they change is what a person,
//! and the AI review, believes the text says. So they are findings in code
//! and configuration, and quiet where writing systems need them: inside
//! emoji, in Indic, Arabic and Hebrew text, and in translation files.

use std::path::Path;

use super::{RuleId, is_documentation};

/// One hidden character worth a finding.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Found {
    /// The line it is on, counted from 1.
    pub line: usize,
    pub rule: RuleId,
    /// The text around it; the report shows hidden characters as codes.
    pub excerpt: String,
}

/// The most findings of one rule reported for one file: a file full of
/// them says so once, not on every line.
const MAX_PER_RULE: usize = 3;

/// How much of a line is shown before and after the character.
const BEFORE: usize = 40;
const AFTER: usize = 100;

/// Controls that embed, override or isolate a run of text in the other
/// direction: the Trojan Source technique.
const fn is_reordering(character: char) -> bool {
    matches!(character, '\u{202a}'..='\u{202e}' | '\u{2066}'..='\u{2069}')
}

/// Marks that only say which direction a neighbour has. Right-to-left text
/// needs them, so they are quiet on a line that has such text.
const fn is_direction_mark(character: char) -> bool {
    matches!(character, '\u{61c}' | '\u{200e}' | '\u{200f}')
}

/// Unicode tag characters: invisible copies of ASCII, read by a model as
/// the text they spell.
const fn is_tag(character: char) -> bool {
    matches!(character, '\u{e0000}'..='\u{e007f}')
}

/// Characters without width, and selectors that only change how the
/// character before them is drawn.
const fn is_zero_width(character: char) -> bool {
    matches!(
        character,
        '\u{ad}'
            | '\u{34f}'
            | '\u{180e}'
            | '\u{200b}'..='\u{200d}'
            | '\u{2060}'..='\u{2064}'
            | '\u{2800}'
            | '\u{fe00}'..='\u{fe0f}'
            | '\u{feff}'
            | '\u{e0100}'..='\u{e01ef}'
    )
}

/// Hangul fillers: blank, yet letters, so a name can be made of one.
const fn is_filler(character: char) -> bool {
    matches!(character, '\u{115f}' | '\u{1160}' | '\u{3164}' | '\u{ffa0}')
}

const fn is_hangul(character: char) -> bool {
    matches!(
        character,
        '\u{1100}'..='\u{115e}'
            | '\u{1161}'..='\u{11ff}'
            | '\u{3131}'..='\u{3163}'
            | '\u{3165}'..='\u{318e}'
            | '\u{ac00}'..='\u{d7af}'
            | '\u{ffa1}'..='\u{ffdc}'
    )
}

/// Hebrew and Arabic letters, with their presentation forms.
const fn is_right_to_left(character: char) -> bool {
    matches!(
        character,
        '\u{590}'..='\u{6ff}'
            | '\u{750}'..='\u{77f}'
            | '\u{8a0}'..='\u{8ff}'
            | '\u{fb1d}'..='\u{fdff}'
            | '\u{fe70}'..='\u{fefc}'
    )
}

/// What a name, a command or a path is written with.
const fn is_token(character: char) -> bool {
    character.is_ascii_alphanumeric() || matches!(character, '_' | '-' | '.' | '/' | '$')
}

/// Files that hold text in many languages, where direction marks and
/// joiners are part of the writing: gettext catalogues, and anything under
/// a directory named for translations.
fn is_translation(rel: &str) -> bool {
    let path = Path::new(rel);
    let extension = path
        .extension()
        .and_then(|extension| extension.to_str())
        .unwrap_or_default()
        .to_ascii_lowercase();
    if matches!(
        extension.as_str(),
        "po" | "pot" | "xlf" | "xliff" | "arb" | "strings" | "resx"
    ) {
        return true;
    }
    path.parent().is_some_and(|parent| {
        parent.components().any(|component| {
            component.as_os_str().to_str().is_some_and(|name| {
                matches!(
                    name.to_ascii_lowercase().as_str(),
                    "locale"
                        | "locales"
                        | "i18n"
                        | "l10n"
                        | "lang"
                        | "langs"
                        | "languages"
                        | "translations"
                        | "translation"
                        | "po"
                        | "nls"
                )
            })
        })
    })
}

/// Markup, where a soft hyphen is ordinary typesetting.
fn is_markup(rel: &str) -> bool {
    Path::new(rel)
        .extension()
        .and_then(|extension| extension.to_str())
        .is_some_and(|extension| {
            matches!(
                extension.to_ascii_lowercase().as_str(),
                "html" | "htm" | "xhtml" | "xml" | "svg"
            )
        })
}

/// A translated entry of a desktop file: `Name[ar]=…`.
fn is_translated_entry(line: &str) -> bool {
    line.split_once('=').is_some_and(|(key, _)| {
        key.trim_end().ends_with(']')
            && key.contains('[')
            && key
                .chars()
                .all(|character| character.is_ascii_alphanumeric() || "[]@_-. ".contains(character))
    })
}

fn excerpt(characters: &[char], at: usize) -> String {
    let from = at.saturating_sub(BEFORE);
    let to = (at + AFTER).min(characters.len());
    characters[from..to]
        .iter()
        .collect::<String>()
        .trim()
        .to_string()
}

/// The hidden characters of `text` that are findings in the file `rel`.
/// Prose and translations are only checked for tag characters, which no
/// writing system uses.
pub fn findings(rel: &str, text: &str) -> Vec<Found> {
    let mut found: Vec<Found> = Vec::new();
    if text.is_ascii() {
        return found;
    }
    let only_tags = is_documentation(rel) || is_translation(rel);
    let markup = is_markup(rel);
    let mut add = |line: usize, rule: RuleId, characters: &[char], at: usize| {
        let reported = found.iter().filter(|known| known.rule == rule).count();
        let same_line = found
            .iter()
            .any(|known| known.rule == rule && known.line == line);
        if reported < MAX_PER_RULE && !same_line {
            found.push(Found {
                line,
                rule,
                excerpt: excerpt(characters, at),
            });
        }
    };
    for (index, line) in text.lines().enumerate() {
        if line.is_ascii() {
            continue;
        }
        let number = index + 1;
        let characters: Vec<char> = line.chars().collect();
        let translated = only_tags || is_translated_entry(line);
        let right_to_left = characters.iter().copied().any(is_right_to_left);
        // An emoji flag of a region is a black flag followed by tag
        // characters: the one place tags are ordinary.
        let mut in_flag = false;
        for (at, character) in characters.iter().copied().enumerate() {
            if is_tag(character) {
                if !in_flag {
                    add(number, RuleId::InvisibleText, &characters, at);
                }
                continue;
            }
            in_flag = character == '\u{1f3f4}';
            if translated {
                continue;
            }
            if is_reordering(character) || (is_direction_mark(character) && !right_to_left) {
                add(number, RuleId::ReorderedText, &characters, at);
                continue;
            }
            let visible = |range: &mut dyn Iterator<Item = &char>| {
                range
                    .copied()
                    .find(|other| !is_zero_width(*other) && !is_filler(*other))
            };
            let before = visible(&mut characters[..at].iter().rev());
            let after = visible(&mut characters[at + 1..].iter());
            if is_filler(character) {
                if !before.is_some_and(is_hangul) && !after.is_some_and(is_hangul) {
                    add(number, RuleId::HiddenCharacter, &characters, at);
                }
            } else if is_zero_width(character)
                && !(markup && character == '\u{ad}')
                && before.is_some_and(is_token)
                && after.is_some_and(is_token)
            {
                add(number, RuleId::HiddenCharacter, &characters, at);
            }
        }
    }
    found
}

/// Letters of Cyrillic and Greek that look like a Latin one.
const LOOKALIKES: &[char] = &[
    'а', 'е', 'о', 'р', 'с', 'у', 'х', 'і', 'ј', 'ѕ', 'ԁ', 'ӏ', 'һ', 'ԛ', 'ԝ', 'ο', 'α', 'ν', 'ρ',
    'τ', 'υ', 'ι', 'κ',
];

const fn is_cyrillic_or_greek(character: char) -> bool {
    matches!(character, '\u{370}'..='\u{3ff}' | '\u{400}'..='\u{52f}')
}

/// The letters a punycode label (`xn--` and then `encoded`) spells, by the
/// decoding of RFC 3492; `None` for one that is not punycode at all.
fn punycode(encoded: &str) -> Option<String> {
    const BASE: u32 = 36;
    const T_MIN: u32 = 1;
    const T_MAX: u32 = 26;
    // A DNS label is at most 63 bytes: more is no host name.
    const MAX_LABEL: usize = 63;
    if encoded.is_empty() || encoded.len() > MAX_LABEL {
        return None;
    }
    // The ASCII letters come first, as written, before the last hyphen.
    let (basic, digits) = encoded.rsplit_once('-').unwrap_or(("", encoded));
    let mut output: Vec<char> = basic.chars().collect();
    if !basic.is_ascii() || digits.is_empty() {
        return None;
    }
    let mut digits = digits.bytes().peekable();
    let (mut point, mut at, mut bias) = (128_u32, 0_u32, 72_u32);
    while digits.peek().is_some() {
        let before = at;
        let mut weight = 1_u32;
        let mut k = BASE;
        // One number, written in digits whose base changes with `bias`:
        // how far to step through the output and the code points.
        loop {
            let digit = match digits.next()? {
                letter @ b'a'..=b'z' => u32::from(letter - b'a'),
                letter @ b'A'..=b'Z' => u32::from(letter - b'A'),
                number @ b'0'..=b'9' => u32::from(number - b'0') + 26,
                _ => return None,
            };
            at = at.checked_add(digit.checked_mul(weight)?)?;
            let threshold = k.saturating_sub(bias).clamp(T_MIN, T_MAX);
            if digit < threshold {
                break;
            }
            weight = weight.checked_mul(BASE - threshold)?;
            k += BASE;
        }
        let length = u32::try_from(output.len()).ok()? + 1;
        bias = punycode_bias(at - before, length, before == 0);
        point = point.checked_add(at / length)?;
        at %= length;
        output.insert(usize::try_from(at).ok()?, char::from_u32(point)?);
        at += 1;
    }
    Some(output.into_iter().collect())
}

/// RFC 3492's bias adaptation: the next number's digits are sized by how
/// large the last one was.
fn punycode_bias(delta: u32, length: u32, first: bool) -> u32 {
    let mut delta = if first { delta / 700 } else { delta / 2 };
    delta += delta / length;
    let mut k = 0;
    while delta > (35 * 26) / 2 {
        delta /= 35;
        k += 36;
    }
    k + (36 * delta) / (delta + 38)
}

/// Whether one label of a host name mixes Latin letters with Cyrillic or
/// Greek ones, or is written only with look-alikes of Latin letters.
fn is_lookalike_label(label: &str) -> bool {
    let foreign = label.chars().any(is_cyrillic_or_greek);
    let latin = label
        .chars()
        .any(|character| character.is_ascii_alphabetic());
    foreign
        && (latin
            || label
                .chars()
                .filter(|character| character.is_alphabetic())
                .all(|character| LOOKALIKES.contains(&character)))
}

/// A host name made to read as another: a label that mixes Latin letters
/// with Cyrillic or Greek ones, or a label written only with look-alikes
/// of Latin letters. A punycode label (`xn--…`) is judged by the letters
/// it spells, and one that spells nothing is no name anyone registered in
/// good faith. A name written wholly in one other script is just a name,
/// in either spelling.
pub fn is_lookalike_host(host: &str) -> bool {
    host.split('.').any(|label| {
        let ascii_form = label
            .get(..4)
            .filter(|prefix| prefix.eq_ignore_ascii_case("xn--"))
            .map(|_| &label[4..]);
        match ascii_form {
            Some(encoded) => punycode(encoded).is_none_or(|spelled| {
                // Punycode of plain ASCII is not what any registry issues.
                spelled.is_ascii() || is_lookalike_label(&spelled)
            }),
            None => is_lookalike_label(label),
        }
    })
}

#[cfg(test)]
mod tests {
    use super::{RuleId, findings, is_lookalike_host, punycode};

    fn rules_in(rel: &str, text: &str) -> Vec<RuleId> {
        findings(rel, text)
            .into_iter()
            .map(|found| found.rule)
            .collect()
    }

    #[test]
    fn reordering_controls_in_code_are_found() {
        // The comment reads as closed before the check; it is not.
        let trojan = "if access != \"user\u{202e} \u{2066}// only admins\u{2069} \u{2066}\" {\n";
        assert_eq!(rules_in("src/auth.rs", trojan), [RuleId::ReorderedText]);
        assert_eq!(
            rules_in("install.sh", "x=1 # \u{2067}note\u{2069}\n"),
            [RuleId::ReorderedText]
        );
        // A lone mark with nothing right-to-left beside it.
        assert_eq!(
            rules_in("conf/app.toml", "name = \"gnp\u{200f}.exe\"\n"),
            [RuleId::ReorderedText]
        );
        for (rel, text) in [
            // Right-to-left text carries its marks.
            ("app.py", "title = \"שלום\u{200f}!\"\n"),
            ("x.desktop", "Name[ar]=\u{202b}متصفح الويب\u{202c}\n"),
            ("po/he.po", "msgstr \"\u{202b}קובץ %s\u{202c}\"\n"),
            ("locales/ar.json", "{\"open\": \"\u{2067}فتح\u{2069}\"}\n"),
            (
                "README.md",
                "The mark \u{200e} is used \u{202a}here\u{202c}.\n",
            ),
        ] {
            assert!(rules_in(rel, text).is_empty(), "{rel}: {text:?}");
        }
    }

    #[test]
    fn tag_characters_are_found_in_any_file() {
        let hidden: String = "ignore this"
            .chars()
            .filter_map(|character| char::from_u32(0xe0000 + u32::from(character)))
            .collect();
        for rel in ["README.md", "LICENSE", "install.sh", "po/de.po"] {
            assert_eq!(
                rules_in(rel, &format!("A plain line.{hidden}\n")),
                [RuleId::InvisibleText],
                "{rel}"
            );
        }
        // The flag of Scotland: a black flag, tags, and the cancel tag.
        let flag = "\u{1f3f4}\u{e0067}\u{e0062}\u{e0073}\u{e0063}\u{e0074}\u{e007f}";
        assert!(rules_in("README.md", &format!("Made in {flag}.\n")).is_empty());
        assert!(rules_in("flags.js", &format!("const sct = '{flag}';\n")).is_empty());
    }

    #[test]
    fn zero_width_characters_inside_a_name_are_found() {
        for (rel, text) in [
            ("install.sh", "cu\u{200b}rl https://x.test/i\n"),
            (
                "PKGBUILD",
                "source=(\"x::https://x.test/a\u{2060}b.tar.gz\")\n",
            ),
            ("main.js", "const is\u{200d}Admin = false;\n"),
            ("main.py", "pass\u{feff}word = read()\n"),
            ("a.conf", "exec = /usr/bin/to\u{ad}ol\n"),
            ("a.lua", "local a\u{fe0f}b = 1\n"),
            ("a.sh", "ru\u{34f}n=1\n"),
            // A filler is a letter, so it can be a whole name.
            ("a.js", "const { a, \u{3164} } = req.query;\n"),
            ("a.js", "let x\u{2800}y = 1;\n"),
        ] {
            assert_eq!(rules_in(rel, text), [RuleId::HiddenCharacter], "{text:?}");
        }
        for (rel, text) in [
            // A byte order mark opens the file, or a part joined into it.
            ("a.sh", "\u{feff}#!/bin/sh\necho hi\n"),
            ("a.css", "a{}\n\u{feff}b{}\n"),
            // Emoji joined into one, a keycap, a selector after a symbol.
            ("a.js", "const family = '👨\u{200d}👩\u{200d}👧';\n"),
            ("a.py", "ONE = '1\u{fe0f}\u{20e3}'\n"),
            ("a.sh", "echo \"\u{2764}\u{fe0f} done\"\n"),
            // Indic and Persian text needs its joiners.
            ("a.json", "{\"hi\": \"क\u{94d}\u{200d}ष\"}\n"),
            ("a.py", "word = 'می\u{200c}خواهم'\n"),
            // The character itself, named in code that handles it.
            ("a.js", "text.replace('\u{200b}', '')\n"),
            ("a.py", "ZWSP = \"\u{200b}\"\n"),
            // Hangul, and a spinner drawn in braille.
            ("a.json", "{\"ko\": \"ᄀ\u{1160}ᆨ\"}\n"),
            ("a.sh", "frames='⠋⠙\u{2800}⠹'\n"),
            ("index.html", "<p>extra\u{ad}ordinary</p>\n"),
            // Prose is read by people who see through none of this.
            ("README.md", "A long\u{200b}word and na\u{ad}me.\n"),
        ] {
            assert!(rules_in(rel, text).is_empty(), "{rel}: {text:?}");
        }
    }

    #[test]
    fn a_file_full_of_them_is_reported_a_few_times() {
        let text = "a\u{200b}b\n".repeat(500);
        assert_eq!(findings("a.sh", &text).len(), 3);
        let found = &findings("a.sh", "x = 1; cu\u{200b}rl\n")[0];
        assert_eq!(
            (found.line, found.excerpt.as_str()),
            (1, "x = 1; cu\u{200b}rl")
        );
    }

    #[test]
    fn host_names_made_to_read_as_another_are_lookalikes() {
        for host in [
            // Cyrillic `а` in a Latin name.
            "p\u{430}ypal.com",
            "xn--pypal-4ve.com",
            "cdn.xn--80ak6aa92e.com",
            // Every letter a look-alike: reads as `apple`.
            "\u{430}\u{440}\u{440}\u{4cf}\u{435}.com",
            "g\u{3bf}\u{3bf}gle.com",
            // Labels that are not punycode, or spell only ASCII.
            "xn--.com",
            "xn--example-.com",
            "xn--99999999999999.com",
        ] {
            assert!(is_lookalike_host(host), "{host}");
        }
        for host in [
            "example.com",
            "xn.example.com",
            // The same names as a resolver and most build files write them.
            "xn--d1acpjx3f.xn--p1ai",
            "xn--e1afmkfd.com",
            "xn--mnchen-3ya.de",
            "XN--MNCHEN-3YA.de",
            "xn--r8jz45g.jp",
            "xn--hxargifdar.gr",
            "яндекс.рф",
            "пример.com",
            "münchen.de",
            "例え.jp",
            "ελληνικά.gr",
        ] {
            assert!(!is_lookalike_host(host), "{host}");
        }
    }

    #[test]
    fn punycode_is_decoded_as_the_rfc_says() {
        // The sample strings of RFC 3492, section 7.1.
        for (encoded, spelled) in [
            (
                "egbpdaj6bu4bxfgehfvwxn",
                "\u{644}\u{64a}\u{647}\u{645}\u{627}\u{628}\u{62a}\u{643}\u{644}\u{645}\u{648}\u{634}\u{639}\u{631}\u{628}\u{64a}\u{61f}",
            ),
            (
                "ihqwcrb4cv8a8dqg056pqjye",
                "\u{4ed6}\u{4eec}\u{4e3a}\u{4ec0}\u{4e48}\u{4e0d}\u{8bf4}\u{4e2d}\u{6587}",
            ),
            (
                "b1abfaaepdrnnbgefbaDotcwatmq2g4l",
                "почемужеонинеговорятпорусски",
            ),
            (
                "PorqunopuedensimplementehablarenEspaol-fmd56a",
                "Porqu\u{e9}nopuedensimplementehablarenEspa\u{f1}ol",
            ),
            (
                "3B-ww4c5e180e575a65lsy2b",
                "3\u{5e74}B\u{7d44}\u{91d1}\u{516b}\u{5148}\u{751f}",
            ),
            (
                "MajiKoi5-783gue6qz075azm5e",
                "Maji\u{3067}Koi\u{3059}\u{308b}5\u{79d2}\u{524d}",
            ),
            (
                "d9juau41awczczp",
                "\u{305d}\u{306e}\u{30b9}\u{30d4}\u{30fc}\u{30c9}\u{3067}",
            ),
            // Names as registries hold them.
            ("mnchen-3ya", "münchen"),
            ("bcher-kva", "bücher"),
            ("pypal-4ve", "p\u{430}ypal"),
            ("80ak6aa92e", "\u{430}\u{440}\u{440}\u{4cf}\u{435}"),
            ("p1ai", "рф"),
        ] {
            assert_eq!(punycode(encoded).as_deref(), Some(spelled), "{encoded}");
        }
        // The RFC's one sample of plain ASCII ends in the delimiter.
        assert_eq!(punycode("-> $1.00 <--").as_deref(), None);
        for bad in [
            "",
            "abc-",
            "a_b",
            "é-kva",
            // A step past the last code point, and past a number's size.
            "99999999999999",
            &"a".repeat(64),
        ] {
            assert_eq!(punycode(bad), None, "{bad:?}");
        }
    }
}
