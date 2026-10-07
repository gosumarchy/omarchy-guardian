//! The diff a person confirms before the system file is replaced: every
//! setting that goes or changes is shown, under whichever table it was.

use std::fs;

use super::super::{line_diff, run};
use super::{Fake, script};
use crate::test_support::TempDir;

fn changed(diff: &str) -> Vec<&str> {
    diff.lines()
        .filter(|line| line.starts_with('-') || line.starts_with('+'))
        .collect()
}

#[test]
fn a_setting_removed_under_one_table_is_shown_though_another_has_the_same_line() {
    let old = "[agent]\nmodel = \"a/b\"\n\n[class.official]\nmodel = \"a/b\"\nthinking = \"max\"\n\n[class.aur]\nthinking = \"max\"\n";
    let new = "[class.official]\nmodel = \"a/b\"\nthinking = \"high\"\n\n[class.aur]\nthinking = \"max\"\n";

    let diff = line_diff(old, new);

    assert_eq!(
        changed(&diff),
        [
            "- [agent] model = \"a/b\"",
            "- [class.official] thinking = \"max\"",
            "+ thinking = \"high\"",
        ],
        "{diff}"
    );
    // The addition stands under its table, the rest as it is.
    assert!(
        diff.contains("  [class.official]\n  model = \"a/b\"\n+ thinking = \"high\"\n"),
        "{diff}"
    );
    assert!(
        diff.contains("  [class.aur]\n  thinking = \"max\"\n"),
        "{diff}"
    );
}

#[test]
fn identical_texts_have_no_changed_line() {
    let text = "# header\nprofile = \"strict\"\n\n[agent]\nmodel = \"a/b\"\n";

    let diff = line_diff(text, text);

    assert!(changed(&diff).is_empty(), "{diff}");
    assert_eq!(line_diff("", ""), "");
}

#[test]
fn a_setting_moved_to_another_table_is_a_removal_and_an_addition() {
    let old = "[class.official]\nmodel = \"a/b\"\n\n[class.aur]\nconfirm = true\n";
    let new = "[class.official]\n\n[class.aur]\nconfirm = true\nmodel = \"a/b\"\n";

    let diff = line_diff(old, new);

    assert_eq!(
        changed(&diff),
        ["- [class.official] model = \"a/b\"", "+ model = \"a/b\""],
        "{diff}"
    );
    assert!(
        diff.contains("  confirm = true\n+ model = \"a/b\"\n"),
        "{diff}"
    );
}

#[test]
fn another_order_alone_changes_nothing() {
    let old = "profile = \"strict\"\n\n[class.aur]\nthinking = \"max\"\nconfirm = true\n\n[agent]\nmodel = \"a/b\"\n";
    let new = "profile = \"strict\"\n\n[agent]\nmodel = \"a/b\"\n\n[class.aur]\nconfirm = true\nthinking = \"max\"\n";

    let diff = line_diff(old, new);

    assert!(changed(&diff).is_empty(), "{diff}");
}

#[test]
fn a_new_table_and_a_setting_outside_any_table_are_shown() {
    let diff = line_diff(
        "# old\nprofile = \"strict\"\n",
        "# new\nprofile = \"standard\"\n\n[agent]\nmodel = \"a/b\"\n",
    );

    assert_eq!(
        changed(&diff),
        [
            "- # old",
            "- profile = \"strict\"",
            "+ # new",
            "+ profile = \"standard\"",
            "+ [agent]",
            "+ model = \"a/b\"",
        ],
        "{diff}"
    );
}

#[test]
fn setup_shows_every_setting_it_removes_or_lowers() {
    let existing = "profile = \"standard\"\n\
\n[agent]\nmodel = \"ollama/qwen3\"\n\
\n[class.official]\nthinking = \"max\"\nmodel = \"ollama/qwen3\"\n\
\n[class.third-party-repo]\nthinking = \"max\"\nmodel = \"ollama/qwen3\"\n\
\n[class.local-package]\nthinking = \"max\"\n";
    let directory = TempDir::new("setup-diff");
    let path = directory.path().join("config.toml");
    fs::write(&path, existing).unwrap();
    let environment = Fake {
        opencode: true,
        test_passes: true,
        system_path: Some(path),
        ..Fake::default()
    };
    // Every answer the default, then confirm the system write.
    let mut terminal = script(&["", "", "", "", "y"]);

    run(&mut terminal, &environment).unwrap();

    let removed: Vec<&str> = terminal
        .output
        .lines()
        .filter(|line| line.starts_with("- "))
        .collect();
    assert_eq!(
        removed,
        [
            "- [agent] model = \"ollama/qwen3\"",
            "- [class.official] model = \"ollama/qwen3\"",
            "- [class.third-party-repo] thinking = \"max\"",
            "- [class.local-package] thinking = \"max\"",
        ],
        "{}",
        terminal.output
    );
    // What stays is not among them: the official thinking level and the
    // third-party model are not setup's to change.
    assert!(
        terminal
            .output
            .contains("  [class.official]\n  thinking = \"max\"\n"),
        "{}",
        terminal.output
    );
}
