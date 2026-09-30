//! The Guardian: a small shield-knight drawn in half-block pixels, two
//! pixel rows per terminal row. Its colour and eyes follow the protection
//! state, and it blinks now and then.

use crate::tui::canvas::{Canvas, Style, color};

pub const WIDTH: usize = 16;
pub const HEIGHT: usize = PIXELS.len() / 2;

/// `#` is filled, `o` an eye, `.` empty.
const PIXELS: [&str; 12] = [
    ".......##.......",
    "......####......",
    "..############..",
    ".##############.",
    "################",
    "###oo######oo###",
    "###oo######oo###",
    "################",
    ".##############.",
    "..############..",
    "....########....",
    "......####......",
];

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Mood {
    /// Balanced protection, everything in place.
    Calm,
    /// Maximum protection.
    Vigilant,
    /// Private: nothing leaves the machine.
    Private,
    /// Something needs attention: a gate is off or a file is invalid.
    Worried,
}

impl Mood {
    const fn color(self) -> u8 {
        match self {
            Self::Calm => color::ACCENT,
            Self::Vigilant => color::GREEN,
            Self::Private => color::CYAN,
            Self::Worried => color::YELLOW,
        }
    }
}

/// Whether the pixel at `(column, row)` is lit. Eyes are open gaps; a
/// blink closes their upper row, a worried look their lower one.
fn lit(column: usize, row: usize, mood: Mood, blink: bool) -> bool {
    let Some(pixel) = PIXELS.get(row).and_then(|line| line.as_bytes().get(column)) else {
        return false;
    };
    match pixel {
        b'#' => true,
        b'o' => (blink && row == 5) || (mood == Mood::Worried && row == 6),
        _ => false,
    }
}

pub fn draw(canvas: &mut Canvas, x: usize, y: usize, mood: Mood, blink: bool) {
    let style = Style::fg(mood.color()).bold();
    for text_row in 0..HEIGHT {
        let line: String = (0..WIDTH)
            .map(|column| {
                match (
                    lit(column, text_row * 2, mood, blink),
                    lit(column, text_row * 2 + 1, mood, blink),
                ) {
                    (true, true) => '█',
                    (true, false) => '▀',
                    (false, true) => '▄',
                    (false, false) => ' ',
                }
            })
            .collect();
        // Blank cells are skipped so the mascot never paints over what is
        // around it.
        for (column, character) in line.chars().enumerate() {
            if character != ' ' {
                canvas.text(x + column, y + text_row, &character.to_string(), style, 1);
            }
        }
    }
}

/// A speech bubble whose tail points left at `(x, y + 1)`. `lines` are
/// already wrapped to fit `width - 4`.
pub fn bubble(canvas: &mut Canvas, x: usize, y: usize, width: usize, lines: &[String], tone: u8) {
    let height = lines.len() + 2;
    let border = Style::fg(color::MUTED);
    canvas.frame(x + 1, y, width.saturating_sub(1), height, border);
    canvas.text(x, y + 1, "╴", border, 1);
    canvas.text(x + 1, y + 1, "┤", border, 1);
    for (index, line) in lines.iter().enumerate() {
        canvas.text_fit(
            x + 3,
            y + 1 + index,
            line,
            Style::fg(tone),
            width.saturating_sub(5),
        );
    }
}

#[cfg(test)]
mod tests {
    use super::{HEIGHT, Mood, WIDTH, draw};
    use crate::tui::canvas::Canvas;

    fn art(mood: Mood, blink: bool) -> Vec<String> {
        let mut canvas = Canvas::new(WIDTH, HEIGHT);
        draw(&mut canvas, 0, 0, mood, blink);
        canvas.rows()
    }

    #[test]
    fn draws_a_shield_with_open_eyes() {
        assert_eq!(
            art(Mood::Calm, false),
            [
                "      ▄██▄",
                " ▄████████████▄",
                "███▀▀██████▀▀███",
                "███▄▄██████▄▄███",
                " ▀████████████▀",
                "    ▀▀████▀▀",
            ]
        );
    }

    #[test]
    fn blinking_and_worry_change_only_the_eyes() {
        let open = art(Mood::Calm, false);
        let blink = art(Mood::Calm, true);
        let worried = art(Mood::Worried, false);
        assert_ne!(open[2], blink[2]);
        assert_eq!(open[3], blink[3]);
        assert_eq!(open[2], worried[2]);
        assert_ne!(open[3], worried[3]);
        for row in [0, 1, 4, 5] {
            assert_eq!(open[row], blink[row]);
            assert_eq!(open[row], worried[row]);
        }
    }
}
