//! The Guardian: a small knight with a plumed helmet, a visor with glowing
//! eyes and a heater shield, drawn in half-block pixels. Each terminal
//! cell holds two pixels, the top one in the foreground colour of `▀` and
//! the bottom one in its background, so the art has proper colours.
//! Colours are palette entries, so the knight follows the terminal theme;
//! its eyes show the mood, and it blinks now and then.

use crate::tui::canvas::{Canvas, Style};

pub const WIDTH: usize = 18;
pub const HEIGHT: usize = PIXELS.len() / 2;

/// One character per pixel; see `palette` for the colours. `.` is empty
/// and `e` is an eye.
const PIXELS: [&str; 16] = [
    "...........rrr....",
    ".........rrrrR....",
    "........rrR..R....",
    "......bbbbbb......",
    "....bbwwbbbbbb....",
    "...bbwbbbbbbbbb...",
    "...bkkkkkkkkkkb...",
    "...bkeekkkkeekb...",
    "...dbbbbbbbbbbd...",
    "....dddddddddd....",
    ".sssss.bbbbbb.....",
    ".sfxfsbbbbbbbbb...",
    ".sxxxs.ssssssdb...",
    ".sfxfs.bbbbbb.....",
    "..sfs..bb..bb.....",
    "...s...dd..dd.....",
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
    /// The colour of the eyes behind the visor.
    const fn eyes(self) -> u8 {
        match self {
            Self::Calm => 15,
            Self::Vigilant => 10,
            Self::Private => 14,
            Self::Worried => 11,
        }
    }
}

/// The palette colour of one pixel, or `None` for an empty one.
fn palette(pixel: u8, mood: Mood, blink: bool) -> Option<u8> {
    Some(match pixel {
        b'b' => 12,
        b'd' => 4,
        b'w' => 15,
        b'k' => 0,
        b'r' => 9,
        b'R' | b'x' => 1,
        b's' => 3,
        b'f' => 7,
        b'e' if blink => 0,
        b'e' => mood.eyes(),
        _ => return None,
    })
}

fn pixel(column: usize, row: usize, mood: Mood, blink: bool) -> Option<u8> {
    let pixel = *PIXELS.get(row)?.as_bytes().get(column)?;
    palette(pixel, mood, blink)
}

/// Draws the knight with its top-left corner at `(x, y)`. Empty pixels are
/// left untouched, so it never paints over what is around it.
pub fn draw(canvas: &mut Canvas, x: usize, y: usize, mood: Mood, blink: bool) {
    for text_row in 0..HEIGHT {
        for column in 0..WIDTH {
            let top = pixel(column, text_row * 2, mood, blink);
            let bottom = pixel(column, text_row * 2 + 1, mood, blink);
            let (character, style) = match (top, bottom) {
                (None, None) => continue,
                (Some(top), None) => ("▀", Style::fg(top)),
                (None, Some(bottom)) => ("▄", Style::fg(bottom)),
                (Some(top), Some(bottom)) if top == bottom => ("█", Style::fg(top)),
                (Some(top), Some(bottom)) => ("▀", Style::fg(top).with_bg(bottom)),
            };
            canvas.text(x + column, y + text_row, character, style, 1);
        }
    }
}

/// A speech bubble whose tail points left at `(x, y + 1)`. `lines` are
/// already wrapped to fit `width - 4`.
pub fn bubble(canvas: &mut Canvas, x: usize, y: usize, width: usize, lines: &[String], tone: u8) {
    let height = lines.len() + 2;
    let border = Style::fg(crate::tui::canvas::color::MUTED);
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
    use super::{HEIGHT, Mood, PIXELS, WIDTH, draw, palette};
    use crate::tui::canvas::Canvas;

    fn art(mood: Mood, blink: bool) -> Vec<String> {
        let mut canvas = Canvas::new(WIDTH, HEIGHT);
        draw(&mut canvas, 0, 0, mood, blink);
        canvas.rows()
    }

    #[test]
    fn every_pixel_has_a_colour_and_rows_line_up() {
        for row in PIXELS {
            assert_eq!(row.len(), WIDTH, "{row}");
            for pixel in row.bytes() {
                assert!(
                    pixel == b'.' || palette(pixel, Mood::Calm, false).is_some(),
                    "{}",
                    pixel as char
                );
            }
        }
        assert_eq!(PIXELS.len() % 2, 0);
    }

    /// The shapes as drawn; the colours were checked by rendering a
    /// terminal capture back to pixels.
    #[test]
    fn draws_the_knight_in_half_blocks() {
        assert_eq!(
            art(Mood::Calm, false),
            [
                "         ▄▄██▀",
                "      ▄▄▀▀▀▄ ▀",
                "   ▄█▀▀▀██████▄",
                "   ██▀▀████▀▀██",
                "   ▀▀▀▀▀▀▀▀▀▀▀▀",
                " █▀▀▀█▄██████▄▄",
                " █▀█▀█ ▀▀▀▀▀▀▀▀",
                "  ▀▀▀  ▀▀  ▀▀",
            ]
        );
    }

    #[test]
    fn moods_and_blinks_only_change_the_visor_row() {
        let render = |mood, blink| {
            let mut canvas = Canvas::new(WIDTH, HEIGHT);
            draw(&mut canvas, 0, 0, mood, blink);
            canvas
                .render()
                .split("\x1b[")
                .map(str::to_string)
                .collect::<Vec<_>>()
        };
        let calm = art(Mood::Calm, false);
        for (mood, blink) in [(Mood::Worried, false), (Mood::Calm, true)] {
            let other = art(mood, blink);
            for row in (0..HEIGHT).filter(|row| *row != 3) {
                assert_eq!(calm[row], other[row], "{mood:?} {blink} row {row}");
            }
            assert_ne!(render(Mood::Calm, false), render(mood, blink));
        }
    }
}
