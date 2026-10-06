//! Every setting the TUI can edit: which file it lives in, how it is edited,
//! and its effective value once profiles and both files are combined.
//!
//! Classes the pacman hook enforces are edited in the system file, because
//! the user file may only tighten them; every user-level class is edited in
//! the user file.

use std::ops::RangeInclusive;
use std::path::Path;

use crate::config::Settings;
use crate::config::file::{
    CACHE_DAYS_RANGE, CHUNKS_RANGE, INPUT_KIB_RANGE, PartialConfig, STORE_MIB_RANGE, TIMEOUT_RANGE,
    is_model_name, parse,
};
use crate::config::model::{
    Action, AiRequirement, DEFAULT_MAX_CHUNKS, DEFAULT_MAX_INPUT_KIB, Named, Profile, SourceClass,
    Thinking, Toggle,
};
use crate::config::write::render;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Scope {
    User,
    System,
}

impl Scope {
    pub(super) const fn name(self) -> &'static str {
        match self {
            Self::User => "user",
            Self::System => "system",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Knob {
    Ai,
    OnFindings,
    OnAiSuspicious,
    Thinking,
    Model,
    Timeout,
    Confirm,
    Cache,
    Diff,
}

impl Knob {
    /// The knobs a class can set in the file it is edited in.
    pub(super) fn for_class(class: SourceClass) -> &'static [Self] {
        if class.is_privileged() {
            &[
                Self::Ai,
                Self::OnFindings,
                Self::OnAiSuspicious,
                Self::Thinking,
                Self::Model,
                Self::Timeout,
            ]
        } else {
            &[
                Self::Ai,
                Self::OnFindings,
                Self::OnAiSuspicious,
                Self::Thinking,
                Self::Model,
                Self::Timeout,
                Self::Confirm,
                Self::Cache,
                Self::Diff,
            ]
        }
    }

    const fn key(self) -> &'static str {
        match self {
            Self::Ai => "ai",
            Self::OnFindings => "on_findings",
            Self::OnAiSuspicious => "on_ai_suspicious",
            Self::Thinking => "thinking",
            Self::Model => "model",
            Self::Timeout => "timeout_secs",
            Self::Confirm => "confirm",
            Self::Cache => "cache",
            Self::Diff => "diff",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Setting {
    Profile,
    OfficialRepos,
    AgentModel,
    MaxInputKib,
    MaxChunks,
    CacheDays,
    MaxStoreMib,
    Class(SourceClass, Knob),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct Field {
    pub(super) scope: Scope,
    pub(super) setting: Setting,
}

/// How a value is entered. Every field can also be reset to inherit.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) enum Input {
    Choice(Vec<&'static str>),
    Number(RangeInclusive<u32>),
    Model,
    Repos,
}

fn names<T: Named>() -> Vec<&'static str> {
    T::ALL.iter().map(|value| value.name()).collect()
}

impl Field {
    pub(super) const fn new(scope: Scope, setting: Setting) -> Self {
        Self { scope, setting }
    }

    /// A class knob, in the file that class is edited in.
    pub(super) fn class(class: SourceClass, knob: Knob) -> Self {
        let scope = if class.is_privileged() {
            Scope::System
        } else {
            Scope::User
        };
        Self::new(scope, Setting::Class(class, knob))
    }

    pub(super) fn label(self) -> &'static str {
        match self.setting {
            Setting::Profile => match self.scope {
                Scope::User => "Your sources",
                Scope::System => "Pacman gate",
            },
            Setting::OfficialRepos => "Official repositories",
            Setting::AgentModel => "Model",
            Setting::MaxInputKib => "Input per AI call (KiB)",
            Setting::MaxChunks => "AI calls per review",
            Setting::CacheDays => "Cached verdicts (days)",
            Setting::MaxStoreMib => "Review memory cap (MiB)",
            Setting::Class(_, knob) => match knob {
                Knob::Ai => "AI review",
                Knob::OnFindings => "On local findings",
                Knob::OnAiSuspicious => "On AI suspicion",
                Knob::Thinking => "Thinking",
                Knob::Model => "Model",
                Knob::Timeout => "Timeout (s)",
                Knob::Confirm => "Ask before running",
                Knob::Cache => "Verdict cache",
                Knob::Diff => "Review upgrades as diffs",
            },
        }
    }

    pub(super) fn help(self) -> &'static str {
        match self.setting {
            Setting::Profile => match self.scope {
                Scope::User => {
                    "Profile for AUR builds, themes and sources you scan. Unset follows the pacman gate's profile."
                }
                Scope::System => {
                    "Profile for pacman transactions (official, third-party repos, local packages). Saved to /etc with sudo."
                }
            },
            Setting::OfficialRepos => {
                "Repos whose packages count as official (only when their SigLevel requires signatures)."
            }
            Setting::AgentModel => match self.scope {
                Scope::User => "OpenCode model for your sources, as provider/model.",
                Scope::System => "OpenCode model for the pacman gate, as provider/model.",
            },
            Setting::MaxInputKib => {
                "Source sent per AI call; bigger sources are split into chunks."
            }
            Setting::MaxChunks => {
                "AI calls one review may make. A source needing more is not reviewed (incomplete)."
            }
            Setting::CacheDays => {
                "How long an identical request is answered from cache. 0 turns the cache off."
            }
            Setting::MaxStoreMib => "Size cap of the review memory in your state directory.",
            Setting::Class(_, knob) => match knob {
                Knob::Ai => {
                    "required: no AI, no install. optional: warn when AI is unavailable. off: local checks only."
                }
                Knob::OnFindings => {
                    "What local-rule and dependency-advisory findings do: warn or block."
                }
                Knob::OnAiSuspicious => {
                    "What an AI 'suspicious' verdict or AI finding does: warn or block."
                }
                Knob::Thinking => "Reasoning effort requested from the model.",
                Knob::Model => {
                    "OpenCode model for this class, as provider/model. Unset uses the AI tab's model."
                }
                Knob::Timeout => "Seconds one AI call may take. Unset derives it from thinking.",
                Knob::Confirm => "With AI off: ask on the terminal before running anything.",
                Knob::Cache => "Answer an identical earlier request from the verdict cache.",
                Knob::Diff => {
                    "Send only what changed since the last approved review of this source."
                }
            },
        }
    }

    pub(super) fn input(self) -> Input {
        match self.setting {
            Setting::Profile => Input::Choice(names::<Profile>()),
            Setting::OfficialRepos => Input::Repos,
            Setting::AgentModel | Setting::Class(_, Knob::Model) => Input::Model,
            Setting::MaxInputKib => Input::Number(INPUT_KIB_RANGE),
            Setting::MaxChunks => Input::Number(CHUNKS_RANGE),
            Setting::CacheDays => Input::Number(CACHE_DAYS_RANGE),
            Setting::MaxStoreMib => Input::Number(STORE_MIB_RANGE),
            Setting::Class(_, knob) => match knob {
                Knob::Ai => Input::Choice(names::<AiRequirement>()),
                Knob::OnFindings | Knob::OnAiSuspicious => Input::Choice(names::<Action>()),
                Knob::Thinking => Input::Choice(names::<Thinking>()),
                Knob::Timeout => Input::Number(TIMEOUT_RANGE),
                Knob::Confirm => Input::Choice(vec!["true", "false"]),
                Knob::Cache | Knob::Diff => Input::Choice(names::<Toggle>()),
                Knob::Model => Input::Model,
            },
        }
    }

    /// The value set in `config`, or `None` when the field inherits.
    pub(super) fn get(self, config: &PartialConfig) -> Option<String> {
        let agent = &config.agent;
        match self.setting {
            Setting::Profile => config.profile.map(|value| value.name().to_string()),
            Setting::OfficialRepos => config.official_repos.as_ref().map(|repos| repos.join(", ")),
            Setting::AgentModel => agent.model.clone(),
            Setting::MaxInputKib => agent.max_input_kib.map(|value| value.to_string()),
            Setting::MaxChunks => agent.max_chunks.map(|value| value.to_string()),
            Setting::CacheDays => agent.cache_days.map(|value| value.to_string()),
            Setting::MaxStoreMib => agent.max_store_mib.map(|value| value.to_string()),
            Setting::Class(class, knob) => {
                let policy = config.class(class);
                match knob {
                    Knob::Ai => policy.ai.map(|value| value.name().to_string()),
                    Knob::OnFindings => policy.on_findings.map(|value| value.name().to_string()),
                    Knob::OnAiSuspicious => policy
                        .on_ai_suspicious
                        .map(|value| value.name().to_string()),
                    Knob::Thinking => policy.thinking.map(|value| value.name().to_string()),
                    Knob::Model => policy.model,
                    Knob::Timeout => policy.timeout_secs.map(|value| value.to_string()),
                    Knob::Confirm => policy.confirm.map(|value| value.to_string()),
                    Knob::Cache => policy.cache.map(|value| value.name().to_string()),
                    Knob::Diff => policy.diff.map(|value| value.name().to_string()),
                }
            }
        }
    }

    /// Sets (or with `None`, clears) the field in `config`. The whole file
    /// is then checked with the real parser, so a value the config file
    /// would reject is refused here with the parser's own message.
    pub(super) fn set(self, config: &mut PartialConfig, value: Option<&str>) -> Result<(), String> {
        let mut changed = config.clone();
        self.assign(&mut changed, value.map(str::trim))?;
        validate(&changed)?;
        *config = changed;
        Ok(())
    }

    fn assign(self, config: &mut PartialConfig, value: Option<&str>) -> Result<(), String> {
        fn named<T: Named>(value: Option<&str>) -> Result<Option<T>, String> {
            value
                .map(|text| {
                    T::parse(text)
                        .ok_or_else(|| format!("expected one of: {}", names::<T>().join(", ")))
                })
                .transpose()
        }
        fn number(value: Option<&str>, range: &RangeInclusive<u32>) -> Result<Option<u32>, String> {
            value
                .map(|text| {
                    text.parse::<u32>()
                        .ok()
                        .filter(|number| range.contains(number))
                        .ok_or_else(|| {
                            format!(
                                "expected a whole number from {} to {}",
                                range.start(),
                                range.end()
                            )
                        })
                })
                .transpose()
        }
        fn model(value: Option<&str>) -> Result<Option<String>, String> {
            value
                .map(|text| {
                    if is_model_name(text) && !text.contains(['"', '\\']) {
                        Ok(text.to_string())
                    } else {
                        Err("expected provider/model, for example anthropic/claude-sonnet-5".into())
                    }
                })
                .transpose()
        }

        let agent = &mut config.agent;
        match self.setting {
            Setting::Profile => config.profile = named(value)?,
            Setting::OfficialRepos => {
                config.official_repos = value
                    .map(|text| {
                        text.split([',', ' '])
                            .filter(|name| !name.is_empty())
                            .map(str::to_string)
                            .collect::<Vec<_>>()
                    })
                    .filter(|repos| !repos.is_empty());
            }
            Setting::AgentModel => agent.model = model(value)?,
            Setting::MaxInputKib => agent.max_input_kib = number(value, &INPUT_KIB_RANGE)?,
            Setting::MaxChunks => agent.max_chunks = number(value, &CHUNKS_RANGE)?,
            Setting::CacheDays => agent.cache_days = number(value, &CACHE_DAYS_RANGE)?,
            Setting::MaxStoreMib => agent.max_store_mib = number(value, &STORE_MIB_RANGE)?,
            Setting::Class(class, knob) => {
                let policy = config.class_mut(class);
                match knob {
                    Knob::Ai => policy.ai = named(value)?,
                    Knob::OnFindings => policy.on_findings = named(value)?,
                    Knob::OnAiSuspicious => policy.on_ai_suspicious = named(value)?,
                    Knob::Thinking => policy.thinking = named(value)?,
                    Knob::Model => policy.model = model(value)?,
                    Knob::Timeout => policy.timeout_secs = number(value, &TIMEOUT_RANGE)?,
                    Knob::Confirm => {
                        policy.confirm = value
                            .map(|text| match text {
                                "true" => Ok(true),
                                "false" => Ok(false),
                                _ => Err("expected true or false".to_string()),
                            })
                            .transpose()?;
                    }
                    Knob::Cache => policy.cache = named(value)?,
                    Knob::Diff => policy.diff = named(value)?,
                }
            }
        }
        Ok(())
    }

    /// The value in effect with both drafts applied, for display.
    pub(super) fn effective(
        self,
        settings: &Settings,
        user: &PartialConfig,
        system: &PartialConfig,
    ) -> String {
        let agent_value = |pick: &dyn Fn(&PartialConfig) -> Option<String>, default: String| {
            let chain: Vec<&PartialConfig> = match self.scope {
                Scope::User => vec![user, system],
                Scope::System => vec![system],
            };
            chain.into_iter().find_map(pick).unwrap_or(default)
        };
        match self.setting {
            Setting::Profile => match self.scope {
                Scope::User => settings.profile_for(SourceClass::Source).name().to_string(),
                Scope::System => settings.system_profile().name().to_string(),
            },
            Setting::OfficialRepos => settings.official_repos().join(", "),
            Setting::AgentModel => agent_value(
                &|config| config.agent.model.clone(),
                "OpenCode default".into(),
            ),
            Setting::MaxInputKib => agent_value(
                &|config| config.agent.max_input_kib.map(|value| value.to_string()),
                DEFAULT_MAX_INPUT_KIB.to_string(),
            ),
            Setting::MaxChunks => agent_value(
                &|config| config.agent.max_chunks.map(|value| value.to_string()),
                DEFAULT_MAX_CHUNKS.to_string(),
            ),
            Setting::CacheDays => settings.store_settings().cache_days.to_string(),
            Setting::MaxStoreMib => settings.store_settings().max_store_mib.to_string(),
            Setting::Class(class, knob) => {
                let policy = settings.policy(class);
                match knob {
                    Knob::Ai => policy.ai.name().to_string(),
                    Knob::OnFindings => policy.on_findings.name().to_string(),
                    Knob::OnAiSuspicious => policy.on_ai_suspicious.name().to_string(),
                    Knob::Thinking => policy.thinking.name().to_string(),
                    Knob::Model => settings
                        .agent_settings(class)
                        .model
                        .unwrap_or_else(|| "OpenCode default".into()),
                    Knob::Timeout => policy.timeout_secs().to_string(),
                    Knob::Confirm => policy.confirm.to_string(),
                    Knob::Cache => policy.cache.name().to_string(),
                    Knob::Diff => policy.diff.name().to_string(),
                }
            }
        }
    }

    /// Where the effective value of a class knob comes from.
    pub(super) fn origin(self, settings: &Settings) -> Option<&'static str> {
        match self.setting {
            Setting::Class(class, knob) => Some(settings.resolve(class).origin(knob.key()).name()),
            _ => None,
        }
    }
}

pub(super) const HEADER: &str =
    "# Written by `omarchy-guardian tui`. See `omarchy-guardian config show`.\n";

/// The file text for `config`, checked with the real parser.
pub(super) fn validate(config: &PartialConfig) -> Result<String, String> {
    let text = render(config, HEADER);
    parse(Path::new("config"), &text)
        .map(|_| text)
        .map_err(|error| error.to_string().trim_start_matches("config:").to_string())
}

#[cfg(test)]
mod tests {
    use super::{Field, Input, Knob, Scope, Setting, validate};
    use crate::config::Settings;
    use crate::config::file::PartialConfig;
    use crate::config::model::{AiRequirement, Named, SourceClass};

    #[test]
    fn privileged_classes_are_edited_in_the_system_file() {
        assert_eq!(
            Field::class(SourceClass::Official, Knob::Ai).scope,
            Scope::System
        );
        assert_eq!(Field::class(SourceClass::Aur, Knob::Ai).scope, Scope::User);
        for class in SourceClass::ALL.iter().copied() {
            let knobs = Knob::for_class(class);
            assert_eq!(
                knobs.contains(&Knob::Confirm),
                !class.is_privileged(),
                "{}",
                class.name()
            );
        }
    }

    #[test]
    fn set_get_and_clear_round_trip() {
        let mut config = PartialConfig::default();
        let field = Field::class(SourceClass::Aur, Knob::Ai);
        field.set(&mut config, Some("off")).unwrap();
        assert_eq!(field.get(&config).as_deref(), Some("off"));
        assert_eq!(config.class(SourceClass::Aur).ai, Some(AiRequirement::Off));
        field.set(&mut config, None).unwrap();
        assert_eq!(field.get(&config), None);

        let repos = Field::new(Scope::System, Setting::OfficialRepos);
        repos.set(&mut config, Some("core, extra omarchy")).unwrap();
        assert_eq!(repos.get(&config).as_deref(), Some("core, extra, omarchy"));
        assert!(
            validate(&config)
                .unwrap()
                .contains("official_repos = [\"core\", \"extra\", \"omarchy\"]")
        );
    }

    #[test]
    fn invalid_values_are_refused_and_leave_the_config_unchanged() {
        let mut config = PartialConfig::default();
        let cases = [
            (Field::class(SourceClass::Aur, Knob::Ai), "sometimes"),
            (Field::class(SourceClass::Aur, Knob::Timeout), "5"),
            (Field::class(SourceClass::Aur, Knob::Model), "no-slash"),
            (Field::class(SourceClass::Aur, Knob::Model), "a/b\"c"),
            (Field::new(Scope::User, Setting::MaxChunks), "0"),
            (
                Field::new(Scope::System, Setting::OfficialRepos),
                "bad/repo",
            ),
        ];
        for (field, value) in cases {
            assert!(field.set(&mut config, Some(value)).is_err(), "{value}");
        }
        assert_eq!(config, PartialConfig::default());
    }

    #[test]
    fn inputs_offer_the_valid_names() {
        assert_eq!(
            Field::class(SourceClass::Theme, Knob::Diff).input(),
            Input::Choice(vec!["on", "off"])
        );
        assert_eq!(
            Field::new(Scope::User, Setting::Profile).input(),
            Input::Choice(vec!["standard", "strict", "local-only"])
        );
    }

    #[test]
    fn effective_values_follow_profiles_and_files() {
        let mut user = PartialConfig::default();
        let system = PartialConfig::default();
        let profile = Field::new(Scope::User, Setting::Profile);
        profile.set(&mut user, Some("local-only")).unwrap();
        let settings = Settings::from_parts(system.clone(), user.clone());

        let ai = Field::class(SourceClass::Aur, Knob::Ai);
        assert_eq!(ai.effective(&settings, &user, &system), "off");
        assert_eq!(ai.origin(&settings), Some("profile"));
        assert_eq!(
            Field::class(SourceClass::Official, Knob::Ai).effective(&settings, &user, &system),
            "optional"
        );
        assert_eq!(
            Field::new(Scope::User, Setting::AgentModel).effective(&settings, &user, &system),
            "OpenCode default"
        );
    }
}
