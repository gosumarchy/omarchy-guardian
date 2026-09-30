//! Standard output that tolerates a reader going away.
//!
//! `print!` panics once stdout is a closed pipe, as under
//! `omarchy-guardian scan x | head`. These macros drop the rest of the output
//! instead, so the run finishes normally: cleanup still happens and the exit
//! status still reports the review. Any other write error is reported once on
//! stderr and the output is dropped the same way.

use std::fmt;
use std::io::{self, ErrorKind, Write};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Mutex, PoisonError};

static WARNED: AtomicBool = AtomicBool::new(false);

/// Everything written through these functions, kept so a blocked review's
/// report can be saved for the notification to open.
static CAPTURED: Mutex<String> = Mutex::new(String::new());

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
pub fn captured() -> String {
    CAPTURED
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .clone()
}

/// Like `eprintln!`, and kept with the captured output.
pub fn stderr_line(args: fmt::Arguments) {
    eprintln!("{args}");
    capture(format_args!("{args}\n"));
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

pub fn stdout(args: fmt::Arguments) {
    capture(args);
    if let Err(error) = write_ignoring_broken_pipe(&mut io::stdout().lock(), args)
        && !WARNED.swap(true, Ordering::Relaxed)
    {
        eprintln!("omarchy-guardian: could not write to stdout: {error}");
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

    use super::write_ignoring_broken_pipe;

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
}
