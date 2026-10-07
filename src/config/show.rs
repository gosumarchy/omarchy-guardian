//! Human-readable views of the effective settings.

use std::fmt::Write as _;
use std::path::Path;

use crate::config::Settings;
use crate::config::load::{FileStatus, UserBlock};
use crate::config::model::{Named, SourceClass};
use crate::config::resolve::KNOBS;
use crate::engine::store;

fn status_line(label: &str, path: &str, status: &FileStatus) -> String {
    let state = match status {
        FileStatus::Missing => "not present".to_string(),
        FileStatus::Loaded => "loaded".to_string(),
        FileStatus::Invalid(reason) => format!("INVALID: {reason}"),
    };
    format!("{label:<12} {path} ({state})\n")
}

fn header(settings: &Settings) -> String {
    let mut text = String::new();
    text.push_str(&status_line(
        "System file",
        &settings.system_path().display().to_string(),
        settings.system_status(),
    ));
    text.push_str(&status_line(
        "User file",
        &settings.user_path().map_or_else(
            || "(no HOME)".to_string(),
            |path| path.display().to_string(),
        ),
        settings.user_status(),
    ));
    if let Some(reason) = settings.privileged_block() {
        let _ = writeln!(text, "Pacman gate: BLOCKED — {reason}");
    }
    // The reason is beside the file above; `config check` prints this, so
    // it is not said here to run it.
    if let Some(cause) = settings.user_block_cause() {
        let _ = writeln!(
            text,
            "User-level reviews: BLOCKED — {}",
            match cause {
                UserBlock::SystemFile => "until the system file is fixed, as root",
                UserBlock::Unverified =>
                    "this is running in a user namespace that does not map root, where root's files look like nobody's: run it outside the sandbox",
                UserBlock::UserFile => "until the user file is fixed",
            }
        );
    }
    let memory = settings.store_settings();
    let _ = writeln!(
        text,
        "{:<12} cache {} day(s) · store up to {} MiB (user-level classes only)",
        "Memory", memory.cache_days, memory.max_store_mib
    );
    text
}

pub(crate) fn render_show(settings: &Settings, classes: &[SourceClass]) -> String {
    let mut text = header(settings);

    for class in classes {
        let resolved = settings.resolve(*class);
        let policy = &resolved.policy;
        let agent = settings.agent_settings(*class);
        let scope = if class.is_privileged() {
            "enforced by the pacman hook"
        } else {
            "user-level"
        };

        // A class no review runs for: what follows is what the files that
        // could be read give, not a policy in force.
        let blocked = if class.is_privileged() {
            settings.privileged_block()
        } else {
            settings.user_block()
        };
        let _ = writeln!(
            text,
            "\n[{}]  {scope} · profile {}{}",
            class.name(),
            settings.profile_for(*class).name(),
            if blocked.is_some() {
                " · NOT IN FORCE: blocked until the settings file is fixed"
            } else {
                ""
            }
        );
        for knob in KNOBS {
            let value = match knob {
                "ai" => policy.ai.name().to_string(),
                "on_findings" => policy.on_findings.name().to_string(),
                "on_ai_suspicious" => policy.on_ai_suspicious.name().to_string(),
                "thinking" => policy.thinking.name().to_string(),
                "model" => policy
                    .model
                    .clone()
                    .unwrap_or_else(|| "(agent default)".into()),
                "timeout_secs" => policy.timeout_secs().to_string(),
                "confirm" => policy.confirm.to_string(),
                "cache" => policy.cache.name().to_string(),
                "diff" => policy.diff.name().to_string(),
                other => format!("(unknown knob {other})"),
            };
            let _ = writeln!(
                text,
                "  {knob:<17} {value:<17} ({})",
                resolved.origin(knob).name()
            );
        }
        let _ = writeln!(
            text,
            "  {:<17} {} · timeout {}s · input {} KiB × up to {} chunk(s)",
            "agent",
            agent.label(),
            agent.timeout_secs,
            agent.max_input_bytes / 1024,
            agent.max_chunks
        );
        for ignored in &resolved.ignored {
            let _ = writeln!(text, "  ! {ignored}");
        }
    }
    text
}

/// The check report and whether both files are usable.
pub(crate) fn render_check(settings: &Settings) -> (String, bool) {
    let valid = !matches!(settings.system_status(), FileStatus::Invalid(_))
        && !matches!(settings.user_status(), FileStatus::Invalid(_))
        && settings.privileged_block().is_none();
    let mut text = header(settings);
    text.push_str(if valid {
        "Configuration is valid.\n"
    } else {
        "Configuration has errors; see above.\n"
    });
    (text, valid)
}

/// One line on the review memory: where it is, how many baselines it holds
/// and its size.
pub(crate) fn render_memory(root: Option<&Path>) -> String {
    let Some(root) = root else {
        return "\nReview memory: no state directory (set HOME or XDG_STATE_HOME)\n".into();
    };
    match store::summary(root) {
        None => format!("\nReview memory: {} (empty)\n", root.display()),
        Some((baselines, bytes)) => format!(
            "\nReview memory: {} · {baselines} approved baseline(s) · {} KiB\n",
            root.display(),
            bytes / 1024
        ),
    }
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::path::Path;

    use super::{render_check, render_memory, render_show};
    use crate::agent::SourceFile;
    use crate::config::Settings;
    use crate::config::load::Insecure;
    use crate::config::model::{AgentSettings, Named, SourceClass};
    use crate::engine::baseline::{self, Identity, Unit};
    use crate::engine::store::Store;
    use crate::test_support::TempDir;

    #[expect(
        clippy::unnecessary_wraps,
        reason = "must match the `Verify` callback signature `Settings::load_from` expects"
    )]
    fn secure(_: &Path) -> Result<(), Insecure> {
        Ok(())
    }

    #[test]
    fn show_lists_values_origins_and_ignored_user_values() {
        let dir = TempDir::new("show");
        let system = dir.path().join("system.toml");
        let user = dir.path().join("user.toml");
        fs::write(&system, "[class.official]\nthinking = \"medium\"\n").unwrap();
        fs::write(
            &user,
            "[class.official]\nai = \"off\"\n[class.aur]\nthinking = \"max\"\n",
        )
        .unwrap();
        let settings = Settings::load_from(&system, Some(&user), &secure);

        let text = render_show(&settings, &[SourceClass::Official, SourceClass::Aur]);

        assert!(text.contains("[official]  enforced by the pacman hook"));
        assert!(text.contains("thinking          medium            (system)"));
        assert!(text.contains("ai = off ignored (user file)"));
        assert!(text.contains("[aur]"));
        assert!(text.contains("thinking          max               (user)"));
        assert!(
            text.contains(
                "agent             default model · max (provider default) · timeout 300s · input 256 KiB"
            )
        );
        assert!(text.contains(&format!("  {:<17} {:<17} ({})", "cache", "on", "profile")));
        assert!(text.contains(&format!("  {:<17} {:<17} ({})", "diff", "off", "profile")));
        assert!(text.contains("× up to 8 chunk(s)"));
        assert!(text.contains(&format!(
            "{:<12} cache 30 day(s) · store up to 256 MiB",
            "Memory"
        )));
    }

    #[test]
    fn check_fails_on_an_invalid_file() {
        let dir = TempDir::new("check");
        let system = dir.path().join("system.toml");
        fs::write(&system, "profile = \"standard\"\n").unwrap();

        let (text, valid) = render_check(&Settings::load_from(&system, None, &secure));
        assert!(valid, "{text}");

        fs::write(&system, "profile = \"bogus\"\n").unwrap();
        let (text, valid) = render_check(&Settings::load_from(&system, None, &secure));
        assert!(!valid);
        assert!(text.contains("system.toml:1: profile: expected one of"));
    }

    #[test]
    fn a_broken_system_file_is_shown_as_blocking_every_class() {
        let dir = TempDir::new("show-system-broken");
        let system = dir.path().join("system.toml");
        fs::write(
            &system,
            "profile = \"strict\"\n[class.aur]\nai = \"sometimes\"\n",
        )
        .unwrap();
        let settings = Settings::load_from(&system, None, &secure);

        let (check, valid) = render_check(&settings);
        assert!(!valid);
        assert!(check.contains("(INVALID: "), "{check}");
        assert!(check.contains("system.toml:3:"), "{check}");
        assert!(check.contains("Pacman gate: BLOCKED — "), "{check}");
        assert!(
            check.contains(
                "User-level reviews: BLOCKED — until the system file is fixed, as root\n"
            ),
            "{check}"
        );
        // `config check` does not say to run `config check` for this; the
        // pacman gate's line is the gate's own text, as it was.
        assert_eq!(check.matches("config check").count(), 1, "{check}");
        assert!(check.contains("Configuration has errors"), "{check}");

        // Shown, and no class reads as reviewed at the defaults.
        let show = render_show(&settings, SourceClass::ALL);
        assert!(show.contains("User-level reviews: BLOCKED — "), "{show}");
        for class in SourceClass::ALL {
            let heading = show
                .lines()
                .find(|line| line.starts_with(&format!("[{}]", class.name())))
                .unwrap();
            assert!(heading.contains("NOT IN FORCE"), "{heading}");
        }

        // Not there, or valid: as before.
        let missing = Settings::load_from(&dir.path().join("none.toml"), None, &secure);
        fs::write(&system, "profile = \"strict\"\n").unwrap();
        for settings in [missing, Settings::load_from(&system, None, &secure)] {
            let (check, valid) = render_check(&settings);
            assert!(valid, "{check}");
            let show = render_show(&settings, SourceClass::ALL);
            assert!(!show.contains("BLOCKED"), "{show}");
            assert!(!show.contains("NOT IN FORCE"), "{show}");
        }

        // A broken user file blocks the user-level classes alone.
        let user = dir.path().join("user.toml");
        fs::write(&user, "profile = \"strict\n").unwrap();
        let settings = Settings::load_from(&system, Some(&user), &secure);
        let show = render_show(&settings, &[SourceClass::Official, SourceClass::Aur]);
        assert!(!show.contains("Pacman gate: BLOCKED"), "{show}");
        assert!(
            show.contains("User-level reviews: BLOCKED — until the user file is fixed\n"),
            "{show}"
        );

        // A namespace without root: said, and not as something to fix.
        let overflow = |path: &Path| Err(Insecure::owned_by(path, 65_534));
        let settings = Settings::load_in(&system, None, &overflow, &|_| true);
        let (check, valid) = render_check(&settings);
        assert!(!valid);
        assert!(check.contains("run it outside the sandbox"), "{check}");
        assert!(!check.contains("as root"), "{check}");
        assert!(show.contains("hook · profile strict\n"), "{show}");
        assert!(
            show.contains("[aur]  user-level · profile strict · NOT IN FORCE"),
            "{show}"
        );
    }

    #[test]
    fn memory_summary_counts_baselines() {
        let state = TempDir::new("show-memory");
        let root = state.path().join("store");
        assert!(render_memory(Some(&root)).contains("(empty)"));

        let store = Store::open(root.clone()).unwrap();
        let unit = Unit {
            prefix: String::new(),
            identity: Identity::parse("aur:demo").unwrap(),
        };
        let files = [SourceFile {
            path: "PKGBUILD".into(),
            content: "x\n".into(),
        }];
        baseline::record(
            &store,
            SourceClass::Aur,
            &[unit],
            &files,
            &baseline::Unread::new(),
            &AgentSettings::default(),
            1,
        )
        .unwrap();

        assert!(render_memory(Some(&root)).contains("1 approved baseline(s)"));
        assert!(render_memory(None).contains("no state directory"));
    }
}
