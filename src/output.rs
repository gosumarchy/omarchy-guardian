//! Standard output that tolerates a reader going away and never passes a
//! terminal control sequence from reviewed text.
//!
//! `print!` panics once stdout is a closed pipe, as under
//! `omarchy-guardian scan x | head`. These macros drop the rest of the output
//! instead, so the run finishes normally: cleanup still happens and the exit
//! status still reports the review. Any other write error is reported once on
//! stderr and the output is dropped the same way.
//!
//! Everything goes through `text::terminal_safe`: a file name or AI summary
//! that holds an escape sequence is shown as codes, not run by the terminal.
//! Clippy's `disallowed-macros` keeps the standard print macros out of the
//! rest of the code.

use std::fmt;
use std::io::{self, ErrorKind, Write};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Mutex, PoisonError};

static WARNED: AtomicBool = AtomicBool::new(false);
static DIVERTED: AtomicBool = AtomicBool::new(false);

/// Everything written through these functions, kept so a blocked review's
/// report can be saved for the notification to open.
static CAPTURED: Mutex<String> = Mutex::new(String::new());

/// What is written while `held` runs: kept here, not shown.
static HELD: Mutex<Option<Held>> = Mutex::new(None);

/// What `held` kept from the terminal: each write with the stream it was
/// meant for, in order.
#[derive(Debug, Default)]
pub(crate) struct Held(pub(crate) Vec<(Stream, String)>);

impl Held {
    /// Everything held, both streams, in the order it was written.
    pub(crate) fn text(&self) -> String {
        self.0.iter().map(|(_, text)| text.as_str()).collect()
    }
}

/// The stream a write was meant for.
#[derive(Debug, Clone, Copy)]
pub(crate) enum Stream {
    Stdout,
    Stderr,
}

/// At most this much output is kept; a report is far smaller.
const MAX_CAPTURED: usize = 1024 * 1024;

fn capture(args: fmt::Arguments) {
    let mut captured = CAPTURED.lock().unwrap_or_else(PoisonError::into_inner);
    if captured.len() < MAX_CAPTURED {
        // Formatting into a String cannot fail.
        let _ = fmt::Write::write_fmt(&mut *captured, args);
    }
}

/// The output written so far.
pub(crate) fn captured() -> String {
    CAPTURED
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .clone()
}

/// Runs `print` with what it writes to stdout, and through `stderr_line`,
/// kept from the terminal, and returns that text. It is captured all the
/// same, so a report saved afterwards holds it. Must not be nested.
pub(crate) fn held(print: impl FnOnce()) -> Held {
    let previous = HELD
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .replace(Held::default());
    assert!(previous.is_none(), "output::held must not be nested");
    print();
    HELD.lock()
        .unwrap_or_else(PoisonError::into_inner)
        .take()
        .unwrap_or_default()
}

/// Shows on the terminal what `held` returned, each part on the stream it
/// was written to. It was captured when it was written, so it is not again.
pub(crate) fn release(held: &Held) {
    for (stream, text) in &held.0 {
        match stream {
            Stream::Stdout => write_stdout(text),
            // A failed write to stderr has nowhere to be reported.
            Stream::Stderr => drop(io::stderr().lock().write_all(text.as_bytes())),
        }
    }
}

/// Keeps `text` for `held` when it runs; returns whether it did.
fn hold(stream: Stream, text: &str) -> bool {
    let mut held = HELD.lock().unwrap_or_else(PoisonError::into_inner);
    let Some(held) = held.as_mut() else {
        return false;
    };
    held.0.push((stream, text.to_string()));
    true
}

/// Like `eprintln!`, and kept with the captured output.
pub(crate) fn stderr_line(args: fmt::Arguments) {
    let line = format!("{args}\n");
    let safe = crate::text::terminal_safe(&line);
    capture(format_args!("{safe}"));
    if hold(Stream::Stderr, &safe) {
        return;
    }
    // A failed write to stderr has nowhere to be reported.
    let _ = io::stderr().lock().write_all(safe.as_bytes());
}

/// Like `eprint!`, with terminal control sequences shown as codes.
pub(crate) fn stderr(args: fmt::Arguments) {
    let text = args.to_string();
    // A failed write to stderr has nowhere to be reported.
    let _ = io::stderr()
        .lock()
        .write_all(crate::text::terminal_safe(&text).as_bytes());
}

/// Like `eprintln!`, with terminal control sequences shown as codes.
macro_rules! errln {
    () => {
        $crate::output::stderr(format_args!("\n"))
    };
    ($($arg:tt)*) => {
        $crate::output::stderr(format_args!("{}\n", format_args!($($arg)*)))
    };
}

/// Like `print!`, but a closed stdout is not an error.
macro_rules! out {
    ($($arg:tt)*) => {
        $crate::output::stdout(format_args!($($arg)*))
    };
}

/// Like `println!`, but a closed stdout is not an error.
macro_rules! outln {
    () => {
        $crate::output::stdout(format_args!("\n"))
    };
    ($($arg:tt)*) => {
        $crate::output::stdout(format_args!("{}\n", format_args!($($arg)*)))
    };
}

/// From here on, what Guardian prints goes to standard error. For a gate
/// that stands in front of a command whose standard output a program reads
/// (yay takes the package names from `makepkg --packagelist`): one line of
/// Guardian's in it and the reader takes it for the command's.
pub(crate) fn leave_stdout_to_the_command() {
    DIVERTED.store(true, Ordering::Relaxed);
}

pub(crate) fn stdout(args: fmt::Arguments) {
    let text = args.to_string();
    let safe = crate::text::terminal_safe(&text);
    capture(format_args!("{safe}"));
    if hold(Stream::Stdout, &safe) {
        return;
    }
    write_stdout(&safe);
}

fn write_stdout(safe: &str) {
    if DIVERTED.load(Ordering::Relaxed) {
        // A failed write to stderr has nowhere to be reported.
        let _ = io::stderr().lock().write_all(safe.as_bytes());
        return;
    }
    if let Err(error) = write_ignoring_broken_pipe(&mut io::stdout().lock(), format_args!("{safe}"))
        && !WARNED.swap(true, Ordering::Relaxed)
    {
        stderr(format_args!(
            "omarchy-guardian: could not write to stdout: {error}\n"
        ));
    }
}

fn write_ignoring_broken_pipe(writer: &mut impl Write, args: fmt::Arguments) -> io::Result<()> {
    match writer.write_fmt(args) {
        Err(error) if error.kind() == ErrorKind::BrokenPipe => Ok(()),
        result => result,
    }
}

#[cfg(test)]
mod tests {
    use std::io::{self, ErrorKind, Write};

    use super::{held, write_ignoring_broken_pipe};

    struct Failing(ErrorKind);

    impl Write for Failing {
        fn write(&mut self, _: &[u8]) -> io::Result<usize> {
            Err(self.0.into())
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    #[test]
    fn a_closed_reader_is_ignored_but_other_errors_are_not() {
        assert!(
            write_ignoring_broken_pipe(&mut Failing(ErrorKind::BrokenPipe), format_args!("x"))
                .is_ok()
        );
        assert!(
            write_ignoring_broken_pipe(&mut Failing(ErrorKind::StorageFull), format_args!("x"))
                .is_err()
        );

        let mut buffer = Vec::new();
        write_ignoring_broken_pipe(&mut buffer, format_args!("{}-{}", 1, 2)).unwrap();
        assert_eq!(buffer, b"1-2");
    }

    /// `HELD` is global, so other tests printing meanwhile may land in it
    /// too; none checks what it prints, so only containment is asserted.
    #[test]
    fn held_output_is_returned_in_order_and_not_shown() {
        let kept = held(|| {
            outln!("to stdout");
            super::stderr_line(format_args!("to stderr"));
        });
        let text = kept.text();
        let stdout = text.find("to stdout\n").expect("stdout is held");
        let stderr = text.find("to stderr\n").expect("stderr is held");
        assert!(stdout < stderr, "held in the order written: {text}");
        assert!(super::captured().contains("to stdout\n"));
        assert!(super::HELD.lock().unwrap().is_none());
    }
}
