//! The settings vocabulary (spec §3–§5): source classes, profiles, the
//! per-class knobs and the built-in profile tables.
//!
//! Knob enums declare their variants loosest first, so the derived `Ord` is
//! the strictness order the tighten-only rule relies on.

pub(crate) const DEFAULT_MAX_INPUT_KIB: u32 = 256;
pub(crate) const DEFAULT_MAX_CHUNKS: u32 = 8;
pub(super) const DEFAULT_CACHE_DAYS: u32 = 30;
pub(super) const DEFAULT_MAX_STORE_MIB: u32 = 256;

/// An enum spelled in the config file by a fixed lowercase name.
pub(crate) trait Named: Copy + 'static {
    const ALL: &'static [Self];

    fn name(self) -> &'static str;

    fn parse(text: &str) -> Option<Self> {
        Self::ALL.iter().copied().find(|value| value.name() == text)
    }
}

/// Whether the system sweep may run its read-only root collector (asked by
/// `protect`; system file only).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum RootConsent {
    Allowed,
    Declined,
}

impl Named for RootConsent {
    const ALL: &'static [Self] = &[Self::Allowed, Self::Declined];

    fn name(self) -> &'static str {
        match self {
            Self::Allowed => "allowed",
            Self::Declined => "declined",
        }
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub(crate) enum SourceClass {
    Official,
    ThirdPartyRepo,
    LocalPackage,
    Aur,
    Theme,
    Plugin,
    #[default]
    Source,
    /// What already runs on its own on this machine (`sweep`).
    System,
}

impl SourceClass {
    /// Enforced by the root pacman hook; user settings may only tighten these.
    pub(crate) const fn is_privileged(self) -> bool {
        match self {
            Self::Official | Self::ThirdPartyRepo | Self::LocalPackage => true,
            Self::Aur | Self::Theme | Self::Plugin | Self::Source | Self::System => false,
        }
    }
}

impl Named for SourceClass {
    const ALL: &'static [Self] = &[
        Self::Official,
        Self::ThirdPartyRepo,
        Self::LocalPackage,
        Self::Aur,
        Self::Theme,
        Self::Plugin,
        Self::Source,
        Self::System,
    ];

    fn name(self) -> &'static str {
        match self {
            Self::Official => "official",
            Self::ThirdPartyRepo => "third-party-repo",
            Self::LocalPackage => "local-package",
            Self::Aur => "aur",
            Self::Theme => "theme",
            Self::Plugin => "plugin",
            Self::Source => "source",
            Self::System => "system",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Profile {
    Standard,
    Strict,
    LocalOnly,
}

impl Profile {
    /// One line for the setup wizard and `config show`.
    pub(crate) const fn summary(self) -> &'static str {
        match self {
            Self::Standard => {
                "AI review for community sources; official updates never blocked by an unavailable AI"
            }
            Self::Strict => "AI review required everywhere; any finding blocks",
            Self::LocalOnly => {
                "no AI: source never leaves this machine; you confirm community installs"
            }
        }
    }
}

impl Named for Profile {
    const ALL: &'static [Self] = &[Self::Standard, Self::Strict, Self::LocalOnly];

    fn name(self) -> &'static str {
        match self {
            Self::Standard => "standard",
            Self::Strict => "strict",
            Self::LocalOnly => "local-only",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum AiRequirement {
    Off,
    Optional,
    Required,
}

impl Named for AiRequirement {
    const ALL: &'static [Self] = &[Self::Off, Self::Optional, Self::Required];

    fn name(self) -> &'static str {
        match self {
            Self::Off => "off",
            Self::Optional => "optional",
            Self::Required => "required",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum Action {
    Warn,
    Block,
}

impl Named for Action {
    const ALL: &'static [Self] = &[Self::Warn, Self::Block];

    fn name(self) -> &'static str {
        match self {
            Self::Warn => "warn",
            Self::Block => "block",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum Thinking {
    Default,
    Minimal,
    Low,
    Medium,
    High,
    Max,
}

impl Named for Thinking {
    const ALL: &'static [Self] = &[
        Self::Default,
        Self::Minimal,
        Self::Low,
        Self::Medium,
        Self::High,
        Self::Max,
    ];

    fn name(self) -> &'static str {
        match self {
            Self::Default => "default",
            Self::Minimal => "minimal",
            Self::Low => "low",
            Self::Medium => "medium",
            Self::High => "high",
            Self::Max => "max",
        }
    }
}

/// Whether a review-memory feature is used. `On` is the looser value: it lets
/// an earlier review stand in for part of this one.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum Toggle {
    On,
    Off,
}

impl Named for Toggle {
    const ALL: &'static [Self] = &[Self::On, Self::Off];

    fn name(self) -> &'static str {
        match self {
            Self::On => "on",
            Self::Off => "off",
        }
    }
}

/// Everything that decides how one source class is reviewed and judged.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Policy {
    pub(crate) ai: AiRequirement,
    /// Local-rule and OSV findings.
    pub(crate) on_findings: Action,
    /// An AI `suspicious` verdict or any AI finding.
    pub(crate) on_ai_suspicious: Action,
    pub(crate) thinking: Thinking,
    pub(super) model: Option<String>,
    /// `None` derives the timeout from `thinking`.
    pub(super) timeout_secs: Option<u32>,
    /// With `ai = off`: ask the user before running anything.
    pub(crate) confirm: bool,
    /// Reuse cached AI verdicts for identical requests. User-level only.
    pub(crate) cache: Toggle,
    /// Review upgrades of an approved source as diffs. User-level only.
    pub(crate) diff: Toggle,
}

impl Policy {
    pub(crate) fn timeout_secs(&self) -> u32 {
        self.timeout_secs.unwrap_or(match self.thinking {
            Thinking::High => 180,
            Thinking::Max => 300,
            Thinking::Default | Thinking::Minimal | Thinking::Low | Thinking::Medium => 120,
        })
    }
}

/// How one OpenCode review is run.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct AgentSettings {
    pub(crate) model: Option<String>,
    pub(crate) thinking: Thinking,
    /// The `--variant` value, or `None` for the provider default.
    pub(crate) variant: Option<String>,
    pub(crate) timeout_secs: u32,
    pub(crate) max_input_bytes: usize,
    /// AI calls one review may make; a source needing more is incomplete.
    pub(crate) max_chunks: usize,
}

impl Default for AgentSettings {
    fn default() -> Self {
        Self {
            model: None,
            thinking: Thinking::Default,
            variant: None,
            timeout_secs: 120,
            max_input_bytes: DEFAULT_MAX_INPUT_KIB as usize * 1024,
            max_chunks: DEFAULT_MAX_CHUNKS as usize,
        }
    }
}

impl AgentSettings {
    /// `model · thinking`, shown next to every AI verdict. A level without a
    /// variant is marked, because OpenCode never received it.
    pub(crate) fn label(&self) -> String {
        let model = self.model.as_deref().unwrap_or("default model");
        // The Claude Code CLI takes the level itself (`--effort`); OpenCode
        // only through a mapped provider variant.
        let applied =
            self.variant.is_some() || model.starts_with(crate::tools::Reviewer::CLAUDE_CODE_PREFIX);
        match (self.thinking, applied) {
            (Thinking::Default, _) => format!("{model} · default thinking"),
            (level, true) => format!("{model} · {}", level.name()),
            (level, false) => format!("{model} · {} (provider default)", level.name()),
        }
    }
}

/// Limits of the user-level review memory.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct StoreSettings {
    /// How long a cached verdict stays valid; 0 turns the cache off.
    pub(crate) cache_days: u32,
    pub(crate) max_store_mib: u32,
}

/// The built-in value of every knob for one profile and class (spec §5).
pub(crate) fn builtin(profile: Profile, class: SourceClass) -> Policy {
    use Action::{Block, Warn};
    use AiRequirement::{Off, Optional, Required};

    let official = class == SourceClass::Official;
    let (ai, on_findings, thinking) = match (profile, official) {
        (Profile::Standard, true) => (Optional, Warn, Thinking::Low),
        (Profile::Standard, false) => (Required, Block, Thinking::High),
        (Profile::Strict, true) => (Required, Block, Thinking::Medium),
        (Profile::Strict, false) => (Required, Block, Thinking::Max),
        (Profile::LocalOnly, true) => (Off, Warn, Thinking::Default),
        (Profile::LocalOnly, false) => (Off, Block, Thinking::Default),
    };

    let privileged = class.is_privileged();

    Policy {
        ai,
        on_findings,
        on_ai_suspicious: Block,
        thinking,
        model: None,
        timeout_secs: None,
        // The pacman hook has no reliable terminal, so only user-level
        // classes can ask.
        confirm: profile == Profile::LocalOnly && !privileged,
        // The review memory lives in the user's home; the root pacman gate
        // never uses it.
        cache: if privileged { Toggle::Off } else { Toggle::On },
        diff: if privileged || profile == Profile::Strict {
            Toggle::Off
        } else {
            Toggle::On
        },
    }
}

#[cfg(test)]
mod tests {
    use super::{
        Action, AgentSettings, AiRequirement, Named, Policy, Profile, SourceClass, Thinking,
        Toggle, builtin,
    };

    fn knobs(policy: &Policy) -> (AiRequirement, Action, Action, Thinking, bool) {
        (
            policy.ai,
            policy.on_findings,
            policy.on_ai_suspicious,
            policy.thinking,
            policy.confirm,
        )
    }

    #[test]
    fn builtin_profiles_match_the_spec() {
        use Action::{Block, Warn};
        use AiRequirement::{Off, Optional, Required};
        use Thinking::{Default, High, Low, Max, Medium};

        for class in SourceClass::ALL.iter().copied() {
            let official = class == SourceClass::Official;
            let user_level = !class.is_privileged();

            let standard = knobs(&builtin(Profile::Standard, class));
            let strict = knobs(&builtin(Profile::Strict, class));
            let local = knobs(&builtin(Profile::LocalOnly, class));

            if official {
                assert_eq!(standard, (Optional, Warn, Block, Low, false));
                assert_eq!(strict, (Required, Block, Block, Medium, false));
                assert_eq!(local, (Off, Warn, Block, Default, false));
            } else {
                assert_eq!(standard, (Required, Block, Block, High, false), "{class:?}");
                assert_eq!(strict, (Required, Block, Block, Max, false), "{class:?}");
                assert_eq!(local, (Off, Block, Block, Default, user_level), "{class:?}");
            }
        }
    }

    #[test]
    fn knob_order_is_strictness() {
        assert!(AiRequirement::Off < AiRequirement::Optional);
        assert!(AiRequirement::Optional < AiRequirement::Required);
        assert!(Action::Warn < Action::Block);
        assert!(Thinking::Default < Thinking::Minimal && Thinking::High < Thinking::Max);
    }

    #[test]
    fn names_round_trip() {
        for class in SourceClass::ALL.iter().copied() {
            assert_eq!(SourceClass::parse(class.name()), Some(class));
        }
        assert_eq!(
            SourceClass::parse("third-party-repo"),
            Some(SourceClass::ThirdPartyRepo)
        );
        assert_eq!(Profile::parse("local-only"), Some(Profile::LocalOnly));
        assert_eq!(Thinking::parse("max"), Some(Thinking::Max));
        assert_eq!(
            AiRequirement::parse("optional"),
            Some(AiRequirement::Optional)
        );
        assert_eq!(Action::parse("warn"), Some(Action::Warn));
        assert_eq!(Profile::parse("Standard"), None);
    }

    #[test]
    fn timeouts_follow_thinking_unless_set() {
        let mut policy = builtin(Profile::Standard, SourceClass::Aur);
        assert_eq!(policy.timeout_secs(), 180);
        policy.thinking = Thinking::Max;
        assert_eq!(policy.timeout_secs(), 300);
        policy.thinking = Thinking::Low;
        assert_eq!(policy.timeout_secs(), 120);
        policy.timeout_secs = Some(45);
        assert_eq!(policy.timeout_secs(), 45);
    }

    #[test]
    fn review_memory_is_user_level_only() {
        for class in SourceClass::ALL.iter().copied() {
            for profile in Profile::ALL.iter().copied() {
                let policy = builtin(profile, class);
                if class.is_privileged() {
                    assert_eq!(
                        (policy.cache, policy.diff),
                        (Toggle::Off, Toggle::Off),
                        "{class:?}"
                    );
                } else {
                    assert_eq!(policy.cache, Toggle::On, "{class:?}");
                    let diff = if profile == Profile::Strict {
                        Toggle::Off
                    } else {
                        Toggle::On
                    };
                    assert_eq!(policy.diff, diff, "{class:?} {profile:?}");
                }
            }
        }
        assert!(Toggle::On < Toggle::Off);
        assert_eq!(Toggle::parse("off"), Some(Toggle::Off));
        assert_eq!(AgentSettings::default().max_chunks, 8);
    }

    #[test]
    fn agent_label_names_model_and_thinking() {
        let mut settings = AgentSettings::default();
        assert_eq!(settings.label(), "default model · default thinking");
        settings.model = Some("anthropic/claude-sonnet-5".into());
        settings.thinking = Thinking::High;
        assert_eq!(
            settings.label(),
            "anthropic/claude-sonnet-5 · high (provider default)"
        );
        settings.variant = Some("high".into());
        assert_eq!(settings.label(), "anthropic/claude-sonnet-5 · high");
        settings.variant = None;
        settings.model = Some("claude-code/claude-sonnet-5-5".into());
        assert_eq!(settings.label(), "claude-code/claude-sonnet-5-5 · high");
    }
}
