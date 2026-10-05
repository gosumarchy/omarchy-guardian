//! Making text from reviewed sources safe to show.
//!
//! File names, code excerpts, AI summaries and tool errors can carry
//! terminal control sequences (a clipboard write through OSC 52, a cursor
//! move that repaints a verdict as CLEAR), bidirectional overrides that make
//! `gnp.exe` read as `exe.png`, and invisible characters. Every such
//! character is shown as a visible code (`\u{1b}`) rather than deleted, so a
//! reader of a security report sees that a name held one.

use std::borrow::Cow;
use std::fmt::Write as _;

/// Characters that control a terminal, reorder text or are invisible.
/// `\t` and `\n` are included; callers decide whether to keep them.
pub const fn is_hidden(character: char) -> bool {
    matches!(
        character,
        '\u{0}'..='\u{1f}'
            | '\u{7f}'..='\u{9f}'
            | '\u{ad}'
            | '\u{34f}'
            | '\u{61c}'
            | '\u{115f}'
            | '\u{1160}'
            | '\u{180e}'
            | '\u{200b}'..='\u{200f}'
            | '\u{2028}'..='\u{202e}'
            | '\u{2060}'..='\u{2064}'
            | '\u{2066}'..='\u{206f}'
            | '\u{2800}'
            | '\u{3164}'
            | '\u{fe00}'..='\u{fe0f}'
            | '\u{feff}'
            | '\u{ffa0}'
            | '\u{fff9}'..='\u{fffb}'
            | '\u{e0000}'..='\u{e007f}'
            | '\u{e0100}'..='\u{e01ef}'
    )
}

fn push_code(out: &mut String, character: char) {
    match character {
        '\t' => out.push_str("\\t"),
        '\n' => out.push_str("\\n"),
        '\r' => out.push_str("\\r"),
        other => {
            let _ = write!(out, "\\u{{{:x}}}", u32::from(other));
        }
    }
}

fn replace(text: &str, keep: impl Fn(char) -> bool) -> Cow<'_, str> {
    if !text
        .chars()
        .any(|character| is_hidden(character) && !keep(character))
    {
        return Cow::Borrowed(text);
    }
    let mut out = String::with_capacity(text.len() + 16);
    for character in text.chars() {
        if is_hidden(character) && !keep(character) {
            push_code(&mut out, character);
        } else {
            out.push(character);
        }
    }
    Cow::Owned(out)
}

/// A single-line field: every hidden character, `\t` and `\n` included,
/// becomes a visible code.
pub fn shown(text: &str) -> Cow<'_, str> {
    replace(text, |_| false)
}

/// Multi-line text: like `shown`, keeping `\n` and `\t`.
pub fn shown_block(text: &str) -> Cow<'_, str> {
    replace(text, |character| matches!(character, '\n' | '\t'))
}

/// SGR parameters that only change weight or colour: nothing that hides
/// text, blinks or reaches beyond the line.
fn allowed_parameter(param: &str) -> bool {
    matches!(param.parse::<u8>(), Ok(0..=2 | 22 | 30..=37 | 39 | 90..=97)) && param.len() <= 2
}

/// Text for the terminal: `\n`, `\t` and Guardian's own colour sequences
/// (`ESC [ … m` with only the parameters it uses) pass; every other escape
/// sequence and hidden character becomes a visible code. The worst attacker
/// text can do is colour itself.
pub fn terminal_safe(text: &str) -> Cow<'_, str> {
    if !text
        .chars()
        .any(|character| is_hidden(character) && !matches!(character, '\n' | '\t'))
    {
        return Cow::Borrowed(text);
    }
    let mut out = String::with_capacity(text.len() + 16);
    let mut rest = text;
    while let Some(character) = rest.chars().next() {
        if character == '\u{1b}'
            && let Some(length) = allowed_sgr(rest)
        {
            out.push_str(&rest[..length]);
            rest = &rest[length..];
            continue;
        }
        if is_hidden(character) && !matches!(character, '\n' | '\t') {
            push_code(&mut out, character);
        } else {
            out.push(character);
        }
        rest = &rest[character.len_utf8()..];
    }
    Cow::Owned(out)
}

/// The length of an allowed SGR sequence at the start of `text`.
fn allowed_sgr(text: &str) -> Option<usize> {
    let body = text.strip_prefix("\u{1b}[")?;
    let end = body.find('m')?;
    let params = &body[..end];
    let allowed = params.split(';').all(allowed_parameter);
    (allowed && !params.is_empty()).then_some(2 + end + 1)
}

#[cfg(test)]
mod tests {
    use super::{is_hidden, shown, shown_block, terminal_safe};

    #[test]
    fn every_kind_of_hidden_character_is_caught() {
        for character in [
            '\u{1b}',
            '\u{7}',
            '\u{7f}',
            '\u{9b}',
            '\u{202e}',
            '\u{2066}',
            '\u{200b}',
            '\u{feff}',
            '\u{e0041}',
            '\u{fe0f}',
            '\u{2028}',
            '\u{206a}',
            '\u{206f}',
            '\u{34f}',
            '\u{fff9}',
            '\u{2800}',
            '\u{e0100}',
        ] {
            assert!(is_hidden(character), "{:x}", u32::from(character));
        }
        for character in [
            '✓',
            'é',
            '中',
            '\u{1f600}',
            'a',
            ' ',
            '\u{2801}',
            '\u{fffd}',
        ] {
            assert!(!is_hidden(character));
        }
    }

    #[test]
    fn fields_show_codes_and_blocks_keep_lines() {
        assert_eq!(shown("gnp\u{202e}.exe\nx"), "gnp\\u{202e}.exe\\nx");
        assert_eq!(shown_block("a\nb\u{1b}"), "a\nb\\u{1b}");
        assert!(matches!(shown("plain ✓"), std::borrow::Cow::Borrowed(_)));
    }

    #[test]
    fn the_terminal_keeps_only_guardians_colours() {
        assert_eq!(
            terminal_safe("\u{1b}[31;1mX\u{1b}[0m\n"),
            "\u{1b}[31;1mX\u{1b}[0m\n"
        );
        for hostile in [
            "\u{1b}[8m",
            "\u{1b}[1A",
            "\u{1b}]52;c;eA==\u{7}",
            "\u{1b}]0;t\u{1b}\\",
            "\u{9b}31m",
        ] {
            let safe = terminal_safe(hostile);
            assert!(
                !safe.contains('\u{1b}') && !safe.contains('\u{9b}'),
                "{safe:?}"
            );
        }
    }
}
