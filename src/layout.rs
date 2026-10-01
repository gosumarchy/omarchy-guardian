//! Terminal layout: colour, boxes, tables and labelled fields, fitted to the
//! terminal's width.
//!
//! Every text passed in is expected to be `shown` already: widths are
//! counted on what the terminal will draw, and colour is added only after
//! padding, so escape codes never count towards a column.

use std::env;
use std::fs::File;
use std::io::{self, IsTerminal};
use std::process::{Command, Stdio};

/// Narrower than this and a table no longer reads as one.
const MIN_WIDTH: usize = 60;
/// Wider than this and lines get hard to follow.
const MAX_WIDTH: usize = 120;
/// When stdout is not a terminal (a pipe, a saved report).
const DEFAULT_WIDTH: usize = 100;

#[derive(Clone, Copy)]
pub struct Painter {
    enabled: bool,
}

impl Painter {
    pub fn for_stdout() -> Self {
        Self {
            enabled: io::stdout().is_terminal()
                && env::var_os("NO_COLOR").is_none_or(|value| value.is_empty())
                && env::var("TERM").is_ok_and(|term| term != "dumb"),
        }
    }

    #[cfg(test)]
    pub const fn plain() -> Self {
        Self { enabled: false }
    }

    #[cfg(test)]
    pub const fn colored() -> Self {
        Self { enabled: true }
    }

    pub fn paint(self, text: &str, color: &str) -> String {
        if self.enabled && !color.is_empty() {
            format!("\x1b[{color}m{text}\x1b[0m")
        } else {
            text.to_string()
        }
    }
}

/// The width to lay output out in: the terminal's, kept between
/// `MIN_WIDTH` and `MAX_WIDTH`.
pub fn width() -> usize {
    let columns = env::var("COLUMNS")
        .ok()
        .and_then(|columns| columns.trim().parse::<usize>().ok())
        .filter(|columns| *columns > 0)
        .or_else(|| io::stdout().is_terminal().then(tty_columns).flatten());
    columns.map_or(DEFAULT_WIDTH, |columns| columns.clamp(MIN_WIDTH, MAX_WIDTH))
}

fn tty_columns() -> Option<usize> {
    let tty = File::open("/dev/tty").ok()?;
    let output = Command::new("/usr/bin/stty")
        .arg("size")
        .stdin(Stdio::from(tty))
        .stderr(Stdio::null())
        .output()
        .ok()?;
    let text = String::from_utf8_lossy(&output.stdout);
    text.split_whitespace().nth(1)?.parse().ok()
}

/// Columns a character takes: two for wide East Asian characters and
/// emoji, one for everything else.
const fn char_width(character: char) -> usize {
    match character {
        '\u{1100}'..='\u{115f}'
        | '\u{2e80}'..='\u{a4cf}'
        | '\u{ac00}'..='\u{d7a3}'
        | '\u{f900}'..='\u{faff}'
        | '\u{fe30}'..='\u{fe4f}'
        | '\u{ff00}'..='\u{ff60}'
        | '\u{ffe0}'..='\u{ffe6}'
        | '\u{1f300}'..='\u{1faff}'
        | '\u{20000}'..='\u{3fffd}' => 2,
        _ => 1,
    }
}

pub fn text_width(text: &str) -> usize {
    text.chars().map(char_width).sum()
}

/// Splits `text` into lines at most `width` wide: at spaces where it can,
/// and inside a word too long for a line (a path) where it must, after a
/// `/` when there is one.
pub fn wrap(text: &str, width: usize) -> Vec<String> {
    let width = width.max(1);
    if text_width(text) <= width {
        return vec![text.to_string()];
    }
    let mut lines = Vec::new();
    let mut line = String::new();
    let mut used = 0;
    for (spaces, word) in words(text) {
        // Spaces keep their run inside a line, and indent the first.
        let gap = if used > 0 || lines.is_empty() {
            spaces
        } else {
            0
        };
        let word_width = text_width(word);
        if used + gap + word_width <= width {
            line.push_str(&" ".repeat(gap));
            line.push_str(word);
            used += gap + word_width;
            continue;
        }
        if word_width <= width {
            // It starts the next line, without the spaces before it.
            if !line.is_empty() {
                lines.push(std::mem::take(&mut line));
            }
            line.push_str(word);
            used = word_width;
            continue;
        }
        // Too long for any line: after its spaces, it fills this one and
        // goes on in pieces.
        let first = word.chars().next().map_or(1, char_width);
        if used + gap + first <= width {
            line.push_str(&" ".repeat(gap));
            used += gap;
        } else if used > 0 {
            lines.push(std::mem::take(&mut line));
            used = 0;
        }
        let mut rest = word;
        while used + text_width(rest) > width {
            let cut = break_point(rest, width - used, used == 0);
            if cut == 0 {
                lines.push(std::mem::take(&mut line));
                used = 0;
                continue;
            }
            line.push_str(&rest[..cut]);
            lines.push(std::mem::take(&mut line));
            used = 0;
            rest = &rest[cut..];
        }
        line.push_str(rest);
        used += text_width(rest);
    }
    if !line.is_empty() || lines.is_empty() {
        lines.push(line);
    }
    lines
}

/// Each word of `text` and how many spaces come before it.
fn words(text: &str) -> Vec<(usize, &str)> {
    let mut words = Vec::new();
    let mut spaces = 0;
    for word in text.split(' ') {
        if word.is_empty() {
            spaces += 1;
        } else {
            words.push((spaces, word));
            spaces = 1;
        }
    }
    words
}

/// Where to cut `word` to fill `room` columns: after the last `/` that
/// fits, when that fills at least half the room, or else as far as fits.
/// Nothing fits is 0, unless `must` (a line of its own) takes one character.
fn break_point(word: &str, room: usize, must: bool) -> usize {
    let mut used = 0;
    let mut fit = 0;
    let mut slash = None;
    for (index, character) in word.char_indices() {
        let character_width = char_width(character);
        if used + character_width > room {
            break;
        }
        used += character_width;
        fit = index + character.len_utf8();
        if character == '/' && used * 2 >= room {
            slash = Some(fit);
        }
    }
    if fit == 0 && must {
        return word.chars().next().map_or(word.len(), char::len_utf8);
    }
    slash.unwrap_or(fit)
}

fn pad(text: &str, width: usize) -> String {
    let mut padded = text.to_string();
    padded.push_str(&" ".repeat(width.saturating_sub(text_width(text))));
    padded
}

/// One line of a cell, with its colour.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Span {
    pub text: String,
    pub color: &'static str,
    /// Never wrapped (a digest someone copies): it overflows instead.
    pub whole: bool,
}

impl Span {
    pub fn new(text: impl Into<String>, color: &'static str) -> Self {
        Self {
            text: text.into(),
            color,
            whole: false,
        }
    }

    pub fn whole(text: impl Into<String>, color: &'static str) -> Self {
        Self {
            whole: true,
            ..Self::new(text, color)
        }
    }

    pub fn plain(text: impl Into<String>) -> Self {
        Self::new(text, "")
    }
}

/// Lines of text, each wrapped to `width` and kept in its colour.
fn wrap_spans(spans: &[Span], width: usize) -> Vec<Span> {
    spans
        .iter()
        .flat_map(|span| {
            if span.whole {
                return vec![span.clone()];
            }
            wrap(&span.text, width)
                .into_iter()
                .map(|text| Span::new(text, span.color))
                .collect()
        })
        .collect()
}

/// A table drawn with box lines. Each cell holds lines; a line wider than
/// its column wraps.
pub struct Table {
    headers: Vec<&'static str>,
    rows: Vec<Vec<Vec<Span>>>,
}

impl Table {
    pub const fn new(headers: Vec<&'static str>) -> Self {
        Self {
            headers,
            rows: Vec::new(),
        }
    }

    pub fn row(&mut self, cells: Vec<Vec<Span>>) {
        self.rows.push(cells);
    }

    /// What each column needs for its widest line.
    fn natural(&self) -> Vec<usize> {
        let mut widths: Vec<usize> = self
            .headers
            .iter()
            .map(|header| text_width(header))
            .collect();
        for row in &self.rows {
            for (column, cell) in row.iter().enumerate() {
                if let Some(width) = widths.get_mut(column) {
                    for span in cell {
                        *width = (*width).max(text_width(&span.text));
                    }
                }
            }
        }
        widths
    }

    /// The table, `indent` spaces in, `width` wide.
    pub fn render(&self, width: usize, indent: usize, painter: Painter) -> String {
        Self::render_all(std::slice::from_ref(self), width, indent, painter).concat()
    }

    /// Tables with the same columns, drawn alike: each column as wide as
    /// the widest line any of them needs (narrowed from the widest column
    /// down until they fit), the last column taking what is left.
    pub fn render_all(
        tables: &[Self],
        width: usize,
        indent: usize,
        painter: Painter,
    ) -> Vec<String> {
        let columns = tables.first().map_or(0, |table| table.headers.len());
        let available = width.saturating_sub(indent + 3 * columns + 1);
        let mut widths = vec![0; columns];
        for table in tables {
            for (width, natural) in widths.iter_mut().zip(table.natural()) {
                *width = (*width).max(natural);
            }
        }
        // The last column (prose that wraps well) gives way first, then
        // the widest of the others.
        let floor = 8;
        let last_floor = 36.min(available / 2);
        while widths.iter().sum::<usize>() > available {
            let count = widths.len();
            let widest = match widths.last_mut() {
                Some(last) if *last > last_floor => Some(last),
                _ => widths
                    .iter_mut()
                    .take(count.saturating_sub(1))
                    .filter(|width| **width > floor)
                    .max_by_key(|width| **width),
            };
            let Some(widest) = widest else {
                break;
            };
            *widest -= 1;
        }
        let used: usize = widths.iter().sum();
        if let Some(last) = widths.last_mut() {
            *last += available.saturating_sub(used);
        }
        tables
            .iter()
            .map(|table| table.draw(&widths, indent, painter))
            .collect()
    }

    fn draw(&self, widths: &[usize], indent: usize, painter: Painter) -> String {
        let columns = self.headers.len();
        let margin = " ".repeat(indent);
        let rule = |left: &str, middle: &str, right: &str| {
            let parts: Vec<String> = widths.iter().map(|width| "─".repeat(width + 2)).collect();
            painter.paint(&format!("{margin}{left}{}{right}", parts.join(middle)), "2")
        };
        let bar = painter.paint("│", "2");
        let line = |cells: &[Span]| {
            let mut text = format!("{margin}{bar}");
            for (span, width) in cells.iter().zip(widths) {
                text.push(' ');
                text.push_str(&painter.paint(&pad(&span.text, *width), span.color));
                text.push(' ');
                text.push_str(&bar);
            }
            text
        };

        let mut out = vec![rule("┌", "┬", "┐")];
        let headers: Vec<Span> = self
            .headers
            .iter()
            .map(|header| Span::new(*header, "1"))
            .collect();
        out.push(line(&headers));
        out.push(rule("├", "┼", "┤"));
        let wrapped: Vec<Vec<Vec<Span>>> = self
            .rows
            .iter()
            .map(|row| {
                row.iter()
                    .zip(widths)
                    .map(|(cell, width)| wrap_spans(cell, *width))
                    .collect()
            })
            .collect();
        // Rows of more than one line are told apart by a rule between them.
        let separated = wrapped
            .iter()
            .any(|row| row.iter().any(|cell| cell.len() > 1));
        for (index, row) in wrapped.iter().enumerate() {
            if separated && index > 0 {
                out.push(rule("├", "┼", "┤"));
            }
            let height = row.iter().map(Vec::len).max().unwrap_or(1).max(1);
            for line_index in 0..height {
                let cells: Vec<Span> = (0..columns)
                    .map(|column| {
                        row.get(column)
                            .and_then(|cell| cell.get(line_index))
                            .cloned()
                            .unwrap_or_else(|| Span::plain(""))
                    })
                    .collect();
                out.push(line(&cells));
            }
        }
        out.push(rule("└", "┴", "┘"));
        out.join("\n")
    }
}

/// `text` cut to `width`, ending in `…` when cut.
fn shorten(text: &str, width: usize) -> String {
    if text_width(text) <= width {
        return text.to_string();
    }
    let mut out = String::new();
    let mut used = 0;
    for character in text.chars() {
        let character_width = char_width(character);
        if used + character_width + 1 > width {
            break;
        }
        out.push(character);
        used += character_width;
    }
    out.push('…');
    out
}

/// A rounded box around `lines`, with `title` in its top edge; the edges
/// take `color`.
pub fn boxed(title: &str, lines: &[Span], width: usize, color: &str, painter: Painter) -> String {
    let inner = width.saturating_sub(4);
    let title = shorten(title, width.saturating_sub(6));
    let title = title.as_str();
    let title_width = text_width(title);
    let top_rest = width.saturating_sub(title_width + 5);
    let mut out = vec![format!(
        "{}{}{}",
        painter.paint("╭─ ", color),
        painter.paint(title, "1"),
        painter.paint(&format!(" {}╮", "─".repeat(top_rest)), color)
    )];
    let edge = painter.paint("│", color);
    for span in wrap_spans(lines, inner) {
        out.push(format!(
            "{edge} {} {edge}",
            painter.paint(&pad(&span.text, inner), span.color)
        ));
    }
    out.push(painter.paint(&format!("╰{}╯", "─".repeat(width.saturating_sub(2))), color));
    out.join("\n")
}

/// Labelled fields, the labels in one column and each value wrapped
/// beside its label.
pub fn fields(rows: &[(&str, Vec<Span>)], width: usize, painter: Painter) -> String {
    let label_width = rows
        .iter()
        .map(|(label, _)| text_width(label))
        .max()
        .unwrap_or(0);
    let value_width = width.saturating_sub(label_width + 4).max(20);
    let mut out = Vec::new();
    for (label, spans) in rows {
        let label = painter.paint(&pad(label, label_width), "1");
        let blank = " ".repeat(label_width);
        for (index, span) in wrap_spans(spans, value_width).into_iter().enumerate() {
            let shown_label = if index == 0 { &label } else { &blank };
            out.push(format!(
                "  {shown_label}  {}",
                painter.paint(&span.text, span.color)
            ));
        }
    }
    out.join("\n")
}

/// A bar `width` wide, filled for `part` of `whole`.
pub fn bar(part: usize, whole: usize, width: usize) -> (String, String) {
    let filled = (part * width + whole / 2)
        .checked_div(whole)
        .unwrap_or(width);
    ("█".repeat(filled), "░".repeat(width - filled.min(width)))
}

#[cfg(test)]
mod tests {
    use super::{Painter, Span, Table, bar, boxed, fields, text_width, wrap};

    #[test]
    fn wraps_at_spaces_and_breaks_long_words() {
        assert_eq!(wrap("one two three", 7), ["one two", "three"]);
        assert_eq!(
            wrap("/a/very/long/path", 6),
            ["/a/", "very/", "long/", "path"]
        );
        assert_eq!(wrap("x  y", 9), ["x  y"]);
        // Runs of spaces and indentation survive wrapping.
        assert_eq!(wrap("  rm  -rf   / now", 10), ["  rm  -rf", "/ now"]);
        assert_eq!(
            wrap("x = 1;    /a/bb/ccc/dddd/eeeee", 16),
            ["x = 1;    /a/bb/", "ccc/dddd/eeeee"]
        );
        assert_eq!(wrap("    /a/bb/ccc/dddd", 12), ["    /a/bb/", "ccc/dddd"]);
        assert_eq!(wrap("  b a", 2), ["b", "a"]);
        assert_eq!(wrap("  😀é日éa", 3), ["😀é", "日é", "a"]);
        assert_eq!(
            wrap("→ /home/u/.config/systemd/user/v.service", 20),
            ["→ /home/u/.config/", "systemd/user/", "v.service"]
        );
        assert_eq!(wrap("", 5), [""]);
        assert_eq!(text_width("日本"), 4);
    }

    #[test]
    fn a_table_fits_its_width_and_wraps_cells() {
        let mut table = Table::new(vec!["Status", "Item"]);
        table.row(vec![
            vec![Span::plain("unknown")],
            vec![Span::plain(
                "~/.config/a-rather-long-name/that/does/not/fit",
            )],
        ]);
        let text = table.render(30, 2, Painter::plain());
        for line in text.lines() {
            assert!(text_width(line) <= 30, "{line:?}");
        }
        assert!(text.contains("│ unknown"));
        assert!(text.lines().count() > 5);
    }

    #[test]
    fn colour_comes_after_padding() {
        let mut table = Table::new(vec!["A"]);
        table.row(vec![vec![Span::new("x", "31")]]);
        let text = table.render(40, 0, Painter::colored());
        // The padding is inside the colour, so the column stays aligned.
        assert!(text.contains(&format!("\x1b[31mx{}\x1b[0m", " ".repeat(35))));
    }

    #[test]
    fn boxes_fields_and_bars_have_their_width() {
        let text = boxed("T", &[Span::plain("hello")], 20, "32", Painter::plain());
        for line in text.lines() {
            assert_eq!(text_width(line), 20, "{line:?}");
        }
        let text = fields(
            &[("Key", vec![Span::plain("a b c d e f g h")])],
            30,
            Painter::plain(),
        );
        assert!(text.starts_with("  Key  a b c"));
        let long = "x".repeat(50);
        for line in boxed(&long, &[Span::plain("y")], 20, "", Painter::plain()).lines() {
            assert_eq!(text_width(line), 20, "{line:?}");
        }
        let digest = "a".repeat(64);
        let text = fields(
            &[("Integrity", vec![Span::whole(digest.as_str(), "36")])],
            60,
            Painter::plain(),
        );
        assert!(text.contains(&digest));
        assert_eq!(bar(1, 2, 10), ("█".repeat(5), "░".repeat(5)));
        assert_eq!(bar(0, 0, 4).0, "█".repeat(4));
    }
}
