//! The controlling terminal: raw input, the alternate screen, and keys.
//!
//! The crate forbids `unsafe`, so the terminal mode is changed with
//! `stty` on `/dev/tty` rather than `tcsetattr`. Reads time out every
//! 200 ms (`min 0 time 2`), which lets the event loop notice a resize.

use std::fs::{File, OpenOptions};
use std::io::{self, Read, Write};
use std::process::{Command, Stdio};

const STTY: &str = "/usr/bin/stty";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Key {
    Up,
    Down,
    Left,
    Right,
    Home,
    End,
    PageUp,
    PageDown,
    Enter,
    Escape,
    Tab,
    BackTab,
    Backspace,
    Delete,
    /// Ctrl-C.
    Interrupt,
    Char(char),
}

/// Decodes the bytes of one read. Unknown escape sequences are dropped; a
/// lone ESC is the Escape key.
pub fn parse_keys(bytes: &[u8]) -> Vec<Key> {
    let text = String::from_utf8_lossy(bytes);
    let mut chars = text.chars().peekable();
    let mut keys = Vec::new();

    while let Some(character) = chars.next() {
        let key = match character {
            '\x1b' => match chars.peek() {
                Some('[' | 'O') => {
                    chars.next();
                    let mut sequence = String::new();
                    while let Some(&next) = chars.peek() {
                        chars.next();
                        sequence.push(next);
                        if next.is_ascii_alphabetic() || next == '~' {
                            break;
                        }
                    }
                    match sequence.as_str() {
                        "A" => Key::Up,
                        "B" => Key::Down,
                        "C" => Key::Right,
                        "D" => Key::Left,
                        "H" | "1~" | "7~" => Key::Home,
                        "F" | "4~" | "8~" => Key::End,
                        "5~" => Key::PageUp,
                        "6~" => Key::PageDown,
                        "3~" => Key::Delete,
                        "Z" => Key::BackTab,
                        _ => continue,
                    }
                }
                _ => Key::Escape,
            },
            '\r' | '\n' => Key::Enter,
            '\t' => Key::Tab,
            '\x7f' | '\x08' => Key::Backspace,
            '\x03' => Key::Interrupt,
            character if character.is_control() => continue,
            character => Key::Char(character),
        };
        keys.push(key);
    }
    keys
}

/// The terminal in raw mode on the alternate screen. Dropping it restores
/// the saved mode and the main screen.
pub struct Terminal {
    tty: File,
    saved: String,
    active: bool,
}

impl Terminal {
    pub fn open() -> io::Result<Self> {
        let tty = OpenOptions::new().read(true).write(true).open("/dev/tty")?;
        let saved = stty(&tty, &["-g"])?;
        let mut terminal = Self {
            tty,
            saved: saved.trim().to_string(),
            active: false,
        };
        terminal.resume()?;
        Ok(terminal)
    }

    /// Raw input, alternate screen, hidden cursor.
    pub fn resume(&mut self) -> io::Result<()> {
        stty(
            &self.tty,
            &[
                "-icanon", "-echo", "-isig", "-ixon", "-iexten", "min", "0", "time", "2",
            ],
        )?;
        self.tty.write_all(b"\x1b[?1049h\x1b[?25l\x1b[2J")?;
        self.tty.flush()?;
        self.active = true;
        Ok(())
    }

    /// Back to the main screen in the saved mode, for running a command
    /// that uses the terminal itself (sudo, an editor, the setup wizard).
    pub fn suspend(&mut self) -> io::Result<()> {
        if !self.active {
            return Ok(());
        }
        self.active = false;
        self.tty.write_all(b"\x1b[0m\x1b[?25h\x1b[?1049l")?;
        self.tty.flush()?;
        stty(&self.tty, &[&self.saved]).map(drop)
    }

    /// `(columns, rows)`, or 80×24 when the size cannot be read.
    pub fn size(&self) -> (usize, usize) {
        stty(&self.tty, &["size"])
            .ok()
            .and_then(|text| {
                let mut numbers = text.split_whitespace().map(str::parse::<usize>);
                let rows = numbers.next()?.ok()?;
                let columns = numbers.next()?.ok()?;
                Some((columns, rows))
            })
            .filter(|(columns, rows)| *columns > 0 && *rows > 0)
            .unwrap_or((80, 24))
    }

    /// The keys pressed since the last call; empty after a 200 ms timeout.
    pub fn keys(&mut self) -> io::Result<Vec<Key>> {
        let mut buffer = [0_u8; 64];
        let count = self.tty.read(&mut buffer)?;
        Ok(parse_keys(&buffer[..count]))
    }

    pub fn draw(&mut self, frame: &str) -> io::Result<()> {
        self.tty.write_all(frame.as_bytes())?;
        self.tty.flush()
    }

    /// Waits for Enter after an external command, so its output can be read
    /// before the screen switches back.
    pub fn pause(&mut self, message: &str) {
        let _ = writeln!(self.tty, "\n{message}");
        let _ = self.tty.flush();
        let mut line = String::new();
        let _ = io::BufRead::read_line(&mut io::BufReader::new(&self.tty), &mut line);
    }
}

impl Drop for Terminal {
    fn drop(&mut self) {
        // Nothing useful can be done if restoring fails while exiting.
        let _ = self.suspend();
    }
}

fn stty(tty: &File, args: &[&str]) -> io::Result<String> {
    let output = Command::new(STTY)
        .args(args)
        .stdin(Stdio::from(tty.try_clone()?))
        .stderr(Stdio::null())
        .output()?;
    if output.status.success() {
        Ok(String::from_utf8_lossy(&output.stdout).into_owned())
    } else {
        Err(io::Error::other(format!("stty {} failed", args.join(" "))))
    }
}

#[cfg(test)]
mod tests {
    use super::{Key, parse_keys};

    #[test]
    fn decodes_keys_and_escape_sequences() {
        assert_eq!(
            parse_keys(b"\x1b[A\x1b[B\x1b[C\x1b[D\x1bOH\x1b[4~\x1b[5~\x1b[6~\x1b[3~\x1b[Z"),
            [
                Key::Up,
                Key::Down,
                Key::Right,
                Key::Left,
                Key::Home,
                Key::End,
                Key::PageUp,
                Key::PageDown,
                Key::Delete,
                Key::BackTab
            ]
        );
        assert_eq!(
            parse_keys("q\r\t\x7f\x03\x1bé".as_bytes()),
            [
                Key::Char('q'),
                Key::Enter,
                Key::Tab,
                Key::Backspace,
                Key::Interrupt,
                Key::Escape,
                Key::Char('é')
            ]
        );
        assert_eq!(parse_keys(b"\x1b"), [Key::Escape]);
        // An unknown sequence is dropped without eating the next key.
        assert_eq!(parse_keys(b"\x1b[99xq"), [Key::Char('q')]);
    }
}
