//! A grid of styled cells, rendered to one ANSI frame. Colours are the 16
//! palette colours, so the interface follows the terminal's (Omarchy's)
//! theme.

use std::fmt::Write as _;

/// Palette colours by role.
pub mod color {
    pub const RED: u8 = 1;
    pub const GREEN: u8 = 2;
    pub const YELLOW: u8 = 3;
    pub const ACCENT: u8 = 4;
    pub const CYAN: u8 = 6;
    pub const MUTED: u8 = 8;
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Style {
    pub fg: Option<u8>,
    pub bg: Option<u8>,
    pub bold: bool,
    pub dim: bool,
    pub reverse: bool,
}

impl Style {
    pub const PLAIN: Self = Self {
        fg: None,
        bg: None,
        bold: false,
        dim: false,
        reverse: false,
    };

    pub const fn fg(color: u8) -> Self {
        Self {
            fg: Some(color),
            ..Self::PLAIN
        }
    }

    #[cfg(test)]
    pub fn code(self) -> String {
        self.sgr()
    }

    pub const fn with_fg(self, color: u8) -> Self {
        Self {
            fg: Some(color),
            ..self
        }
    }

    pub const fn with_bg(self, color: u8) -> Self {
        Self {
            bg: Some(color),
            ..self
        }
    }

    pub const fn bold(self) -> Self {
        Self { bold: true, ..self }
    }

    pub const fn reverse(self) -> Self {
        Self {
            reverse: true,
            ..self
        }
    }

    fn sgr(self) -> String {
        let mut codes = vec!["0".to_string()];
        if self.bold {
            codes.push("1".into());
        }
        if self.dim {
            codes.push("2".into());
        }
        if self.reverse {
            codes.push("7".into());
        }
        for (color, normal, bright) in [(self.fg, 30, 90), (self.bg, 40, 100)] {
            if let Some(color) = color {
                codes.push(if color < 8 {
                    format!("{}", normal + u32::from(color))
                } else {
                    format!("{}", bright + u32::from(color - 8))
                });
            }
        }
        format!("\x1b[{}m", codes.join(";"))
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Cell {
    character: char,
    style: Style,
}

const BLANK: Cell = Cell {
    character: ' ',
    style: Style::PLAIN,
};

pub struct Canvas {
    pub width: usize,
    pub height: usize,
    cells: Vec<Cell>,
}

impl Canvas {
    pub fn new(width: usize, height: usize) -> Self {
        Self {
            width,
            height,
            cells: vec![BLANK; width * height],
        }
    }

    /// Writes `text` from `(x, y)`, clipped to the canvas and to `limit`
    /// columns. Returns the column after the last character written.
    pub fn text(&mut self, x: usize, y: usize, text: &str, style: Style, limit: usize) -> usize {
        let mut column = x;
        let end = (x + limit).min(self.width);
        if y >= self.height {
            return column;
        }
        for character in text.chars() {
            if column >= end {
                break;
            }
            let character = if character.is_control() {
                ' '
            } else {
                character
            };
            self.cells[y * self.width + column] = Cell { character, style };
            column += 1;
        }
        column
    }

    /// Like `text`, but ends with `…` when `text` does not fit.
    pub fn text_fit(&mut self, x: usize, y: usize, text: &str, style: Style, limit: usize) {
        if text.chars().count() <= limit {
            self.text(x, y, text, style, limit);
        } else if limit > 0 {
            let cut: String = text.chars().take(limit - 1).collect();
            let column = self.text(x, y, &cut, style, limit);
            self.text(column, y, "…", style, 1);
        }
    }

    pub fn fill(&mut self, x: usize, y: usize, width: usize, style: Style) {
        let end = (x + width).min(self.width);
        if y < self.height {
            for column in x..end {
                self.cells[y * self.width + column] = Cell {
                    character: ' ',
                    style,
                };
            }
        }
    }

    /// A rounded box with an optional title in its top edge.
    pub fn frame(&mut self, x: usize, y: usize, width: usize, height: usize, style: Style) {
        if width < 2 || height < 2 {
            return;
        }
        let right = x + width - 1;
        let bottom = y + height - 1;
        let horizontal: String = "─".repeat(width - 2);
        self.text(x, y, &format!("╭{horizontal}╮"), style, width);
        self.text(x, bottom, &format!("╰{horizontal}╯"), style, width);
        for row in y + 1..bottom {
            self.text(x, row, "│", style, 1);
            self.text(right, row, "│", style, 1);
            self.fill(x + 1, row, width - 2, Style::PLAIN);
        }
    }

    /// A horizontal divider joining a frame's sides.
    pub fn divider(&mut self, x: usize, y: usize, width: usize, style: Style) {
        if width >= 2 {
            let line = format!("├{}┤", "─".repeat(width - 2));
            self.text(x, y, &line, style, width);
        }
    }

    /// The rows as plain text, for tests.
    #[cfg(test)]
    pub fn rows(&self) -> Vec<String> {
        self.cells
            .chunks(self.width)
            .map(|row| {
                row.iter()
                    .map(|cell| cell.character)
                    .collect::<String>()
                    .trim_end()
                    .to_string()
            })
            .collect()
    }

    /// The whole screen as one ANSI frame. Characters a terminal may draw
    /// wider than one column (Nerd Font icons) are followed by an absolute
    /// column move, so one wide glyph never shifts the rest of its row.
    pub fn render(&self) -> String {
        let mut out = String::with_capacity(self.cells.len() * 2);
        for (row_index, row) in self.cells.chunks(self.width).enumerate() {
            let _ = write!(out, "\x1b[{};1H", row_index + 1);
            let mut current: Option<Style> = None;
            for (column, cell) in row.iter().enumerate() {
                if current != Some(cell.style) {
                    out.push_str(&cell.style.sgr());
                    current = Some(cell.style);
                }
                out.push(cell.character);
                if !is_narrow(cell.character) && column + 1 < self.width {
                    let _ = write!(out, "\x1b[{}G", column + 2);
                }
            }
        }
        out.push_str("\x1b[0m");
        out
    }
}

/// ASCII, Latin and the box-drawing, arrow and symbol ranges used here are
/// one column wide everywhere.
fn is_narrow(character: char) -> bool {
    let code = u32::from(character);
    code < 0x0300
        || (0x2190..=0x21FF).contains(&code)
        || (0x2500..=0x259F).contains(&code)
        || (0x2022..=0x2026).contains(&code)
        || matches!(code, 0x25CF | 0x25CB | 0x2713 | 0x2717)
}

#[cfg(test)]
mod tests {
    use super::{Canvas, Style};

    #[test]
    fn text_is_clipped_and_fitted() {
        let mut canvas = Canvas::new(10, 2);
        canvas.text(8, 0, "abc", Style::PLAIN, 10);
        canvas.text_fit(0, 1, "abcdefgh", Style::PLAIN, 5);
        assert_eq!(canvas.rows(), ["        ab", "abcd…"]);
    }

    #[test]
    fn frames_draw_rounded_borders() {
        let mut canvas = Canvas::new(6, 3);
        canvas.frame(0, 0, 6, 3, Style::PLAIN);
        assert_eq!(canvas.rows(), ["╭────╮", "│    │", "╰────╯"]);
    }

    #[test]
    fn styles_use_palette_codes_for_both_colours() {
        assert_eq!(Style::fg(12).with_bg(0).code(), "\x1b[0;94;40m");
        assert_eq!(Style::fg(1).bold().code(), "\x1b[0;1;31m");
    }

    #[test]
    fn wide_glyphs_are_followed_by_a_column_move() {
        let mut canvas = Canvas::new(4, 1);
        canvas.text(0, 0, "\u{f0483}ab", Style::PLAIN, 4);
        assert!(canvas.render().contains("\u{f0483}\x1b[2Ga"));
    }
}
