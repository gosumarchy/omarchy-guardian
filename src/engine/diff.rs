//! Line diffs for upgrade reviews. The common prefix and suffix are trimmed,
//! the changed middle is aligned with a longest-common-subsequence table,
//! and the result is printed as unified hunks. Inputs too large to align
//! cheaply are refused, and the caller sends the file whole instead.

use std::fmt::Write as _;
use std::iter;

/// Either input above this size is sent whole instead of diffed.
const MAX_DIFF_INPUT: usize = 1024 * 1024;

/// The table has `old × new` cells for the trimmed middle; above this the
/// file is sent whole.
const MAX_TABLE_CELLS: usize = 4_000_000;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Op {
    Equal,
    Delete,
    Insert,
}

/// A unified diff from `old` to `new` with `context` unchanged lines around
/// each change, or `None` when the inputs are too large to diff. Identical
/// inputs give an empty string.
pub(super) fn unified(old: &str, new: &str, context: usize) -> Option<String> {
    if old.len() > MAX_DIFF_INPUT || new.len() > MAX_DIFF_INPUT {
        return None;
    }
    let old_lines: Vec<&str> = old.split_inclusive('\n').collect();
    let new_lines: Vec<&str> = new.split_inclusive('\n').collect();
    let ops = edit_script(&old_lines, &new_lines)?;
    Some(render(&ops, &old_lines, &new_lines, context))
}

fn edit_script(old: &[&str], new: &[&str]) -> Option<Vec<Op>> {
    let prefix = old
        .iter()
        .zip(new)
        .take_while(|(left, right)| left == right)
        .count();
    let suffix = old[prefix..]
        .iter()
        .rev()
        .zip(new[prefix..].iter().rev())
        .take_while(|(left, right)| left == right)
        .count();
    let old_middle = &old[prefix..old.len() - suffix];
    let new_middle = &new[prefix..new.len() - suffix];
    if old_middle.len().saturating_mul(new_middle.len()) > MAX_TABLE_CELLS {
        return None;
    }

    let mut ops = vec![Op::Equal; prefix];
    ops.extend(align(old_middle, new_middle));
    ops.extend(iter::repeat_n(Op::Equal, suffix));
    Some(ops)
}

/// A shortest edit script between two line lists via an LCS table.
fn align(old: &[&str], new: &[&str]) -> Vec<Op> {
    let width = new.len() + 1;
    // table[i * width + j]: LCS length of old[i..] and new[j..].
    let mut table = vec![0_u32; (old.len() + 1) * width];
    for i in (0..old.len()).rev() {
        for j in (0..new.len()).rev() {
            table[i * width + j] = if old[i] == new[j] {
                table[(i + 1) * width + j + 1] + 1
            } else {
                table[(i + 1) * width + j].max(table[i * width + j + 1])
            };
        }
    }

    let (mut i, mut j) = (0, 0);
    let mut ops = Vec::with_capacity(old.len() + new.len());
    while i < old.len() && j < new.len() {
        if old[i] == new[j] {
            ops.push(Op::Equal);
            i += 1;
            j += 1;
        } else if table[(i + 1) * width + j] >= table[i * width + j + 1] {
            ops.push(Op::Delete);
            i += 1;
        } else {
            ops.push(Op::Insert);
            j += 1;
        }
    }
    ops.extend(iter::repeat_n(Op::Delete, old.len() - i));
    ops.extend(iter::repeat_n(Op::Insert, new.len() - j));
    ops
}

fn render(ops: &[Op], old: &[&str], new: &[&str], context: usize) -> String {
    // (old line, new line) before each op, plus the end position.
    let mut positions = Vec::with_capacity(ops.len() + 1);
    let (mut old_at, mut new_at) = (0, 0);
    for op in ops {
        positions.push((old_at, new_at));
        match op {
            Op::Equal => {
                old_at += 1;
                new_at += 1;
            }
            Op::Delete => old_at += 1,
            Op::Insert => new_at += 1,
        }
    }
    positions.push((old_at, new_at));

    let changed: Vec<usize> = ops
        .iter()
        .enumerate()
        .filter(|(_, op)| **op != Op::Equal)
        .map(|(index, _)| index)
        .collect();

    let mut text = String::new();
    let mut next = 0;
    while next < changed.len() {
        let start = changed[next].saturating_sub(context);
        let mut end = changed[next] + 1;
        next += 1;
        // Changes separated by at most twice the context share a hunk.
        while next < changed.len() && changed[next] <= end + 2 * context {
            end = changed[next] + 1;
            next += 1;
        }
        let end = (end + context).min(ops.len());

        let (old_start, new_start) = positions[start];
        let (old_end, new_end) = positions[end];
        let _ = writeln!(
            text,
            "@@ -{} +{} @@",
            range(old_start, old_end - old_start),
            range(new_start, new_end - new_start)
        );
        for (index, (_old_line, new_line)) in ops[start..end]
            .iter()
            .zip(&positions[start..end])
            .enumerate()
        {
            let (old_line, new_line) = *new_line;
            let (marker, line) = match ops[start + index] {
                Op::Equal => (' ', new[new_line]),
                Op::Delete => ('-', old[old_line]),
                Op::Insert => ('+', new[new_line]),
            };
            text.push(marker);
            text.push_str(line);
            if !line.ends_with('\n') {
                text.push_str("\n\\ No newline at end of file\n");
            }
        }
    }
    text
}

/// `start,count` in unified-diff form: 1-based; an empty range names the
/// line before it.
fn range(start: usize, count: usize) -> String {
    match count {
        0 => format!("{start},0"),
        1 => format!("{}", start + 1),
        _ => format!("{},{count}", start + 1),
    }
}

#[cfg(test)]
#[expect(clippy::format_collect, reason = "test data generation")]
mod tests {
    use super::{MAX_DIFF_INPUT, unified};

    #[test]
    fn identical_inputs_give_an_empty_diff() {
        assert_eq!(unified("a\nb\n", "a\nb\n", 3).as_deref(), Some(""));
    }

    #[test]
    fn one_changed_line_with_context() {
        assert_eq!(
            unified("a\nb\nc\n", "a\nB\nc\n", 1).as_deref(),
            Some("@@ -1,3 +1,3 @@\n a\n-b\n+B\n c\n")
        );
    }

    #[test]
    fn distant_changes_make_separate_hunks() {
        let old: String = (1..=10).map(|line| format!("{line}\n")).collect();
        let new = old.replace("2\n", "two\n").replace("9\n", "nine\n");
        assert_eq!(
            unified(&old, &new, 1).as_deref(),
            Some("@@ -1,3 +1,3 @@\n 1\n-2\n+two\n 3\n@@ -8,3 +8,3 @@\n 8\n-9\n+nine\n 10\n")
        );
    }

    #[test]
    fn missing_final_newlines_are_marked() {
        assert_eq!(
            unified("a", "b", 3).as_deref(),
            Some(
                "@@ -1 +1 @@\n-a\n\\ No newline at end of file\n+b\n\\ No newline at end of file\n"
            )
        );
    }

    #[test]
    fn an_empty_old_file_is_all_insertions() {
        assert_eq!(
            unified("", "x\n", 3).as_deref(),
            Some("@@ -0,0 +1 @@\n+x\n")
        );
    }

    #[test]
    fn crlf_lines_are_kept_intact() {
        assert_eq!(
            unified("a\r\nb\r\n", "a\r\nc\r\n", 3).as_deref(),
            Some("@@ -1,2 +1,2 @@\n a\r\n-b\r\n+c\r\n")
        );
    }

    #[test]
    fn oversized_inputs_are_not_diffed() {
        let big = "a".repeat(MAX_DIFF_INPUT + 1);
        assert_eq!(unified(&big, "a", 3), None);

        let old: String = (0..3000).map(|line| format!("o{line}\n")).collect();
        let new: String = (0..3000).map(|line| format!("n{line}\n")).collect();
        assert_eq!(unified(&old, &new, 3), None);
    }
}
