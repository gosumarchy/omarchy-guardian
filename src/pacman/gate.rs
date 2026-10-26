//! The pacman gate as the hook runs it.

use std::process::ExitCode;

use super::{HookArgs, review_transaction};
use crate::audit::{self, Gate};
use crate::config::Settings;
use crate::engine::store::Store;
use crate::notify;
use crate::permit::{self, Content};
use crate::report::FAILED;
use crate::report::{Decision, Hashes};
use crate::tools::OpenCode;

/// Who started the review.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum StartedBy {
    /// The hook script's root half, which takes a used permit away: it is
    /// told by the exit code (see `permit::PERMITTED_EXIT`), which the
    /// script turns into 0.
    RootHook,
    /// pacman itself, through the hook.
    Pacman,
}

/// The pacman gate: reviews the transaction pacman is about to run, prints
/// and records the verdict, and returns what pacman is to be told.
pub(crate) fn run(hook: &HookArgs, settings: &Settings, started_by: StartedBy) -> ExitCode {
    // A reviewer from PATH is for the end-to-end tests, whose pacman is a
    // script of the user's. In front of a real transaction (pacman runs as
    // root) it is refused, however it came to be asked for.
    if hook.opencode == OpenCode::UserPath
        && process_owner(hook.pacman_pid).is_none_or(|owner| owner == 0)
    {
        errln!(
            "Guardian blocked the pacman transaction: --opencode-from-path is for tests and is refused for a pacman run by root."
        );
        audit::refused(Gate::Pacman, "a reviewer from PATH was asked for", FAILED);
        return ExitCode::from(FAILED);
    }
    match review_transaction(hook, settings) {
        Ok(report) => {
            let decision = report.decide(&|class| settings.policy(class));
            let contents: Vec<Content> = super::reviewed_content(&report).into_iter().collect();
            let standing = permit::standing(
                &contents,
                &report,
                decision,
                settings,
                Store::default_root().as_deref(),
            );
            report.print(decision, Hashes::Hidden, standing.permitted());
            let exit = match (standing.permitted(), started_by) {
                (Some(_), StartedBy::RootHook) => permit::PERMITTED_EXIT,
                (Some(_), StartedBy::Pacman) => 0,
                (None, _) => decision.exit_status(),
            };
            audit::review(
                &audit::Reviewed {
                    gate: Gate::Pacman,
                    class: &super::reviewed_classes(&report),
                    subject: &super::reviewed_names(&report),
                    digest: &super::reviewed_digests(&report),
                    decision,
                    permit: standing.permitted(),
                    offered: standing.offered(),
                    // What pacman is told: a permitted transaction goes on.
                    exit: if standing.permitted().is_some() {
                        0
                    } else {
                        exit
                    },
                },
                &report,
            )
            .record();
            if let Some(permit) = standing.permitted() {
                errln!(
                    "Guardian: your permit {permit} overrules {}; the transaction goes on.",
                    report.decision_name(decision)
                );
            } else if let Decision::Blocked(blocked) = decision {
                standing.say();
                notify::blocked(
                    "a pacman transaction",
                    notify::reason(blocked),
                    notify::Ran::Nothing,
                );
            }
            ExitCode::from(exit)
        }
        Err(error) => {
            errln!("Guardian blocked the pacman transaction: {error}");
            audit::refused(Gate::Pacman, &error.to_string(), FAILED);
            notify::blocked(
                "a pacman transaction",
                &error.to_string(),
                notify::Ran::Nothing,
            );
            ExitCode::from(FAILED)
        }
    }
}

/// The user a process runs as, from the owner of its `/proc` entry.
fn process_owner(pid: u32) -> Option<u32> {
    std::fs::metadata(format!("/proc/{pid}"))
        .ok()
        .map(|metadata| std::os::unix::fs::MetadataExt::uid(&metadata))
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;
    use std::process::ExitCode;

    use super::{StartedBy, run};
    use crate::config::Settings;
    use crate::config::file::PartialConfig;
    use crate::pacman::HookArgs;
    use crate::report::FAILED;
    use crate::tools::OpenCode;

    #[test]
    fn a_reviewer_from_path_is_refused_for_a_pacman_run_by_root() {
        // Process 1 is root's, as a real pacman is; one that is not there
        // cannot be shown to be the user's.
        for pacman_pid in [1, u32::MAX] {
            let hook = HookArgs {
                pacman_pid,
                cwd: PathBuf::from("/"),
                opencode: OpenCode::UserPath,
            };
            assert_eq!(
                run(
                    &hook,
                    &Settings::from_parts(PartialConfig::default(), PartialConfig::default()),
                    StartedBy::Pacman,
                ),
                ExitCode::from(FAILED)
            );
        }
    }
}
