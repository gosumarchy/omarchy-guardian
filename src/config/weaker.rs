//! Where a user-level class is reviewed more weakly than its protection
//! level's built-in profile: the AI review lowered, a finding policy
//! lowered, or the confirmation of the no-AI level taken away. Three such
//! lines in the user file make a gate do nothing while it still reads as
//! on, so each one is an issue until the root-owned system file accepts it.

use crate::config::Settings;
use crate::config::model::{AiRequirement, Named, SourceClass, builtin};
use crate::config::resolve::Origin;

/// The classes the user file can loosen.
pub const USER_CLASSES: [SourceClass; 5] = [
    SourceClass::Aur,
    SourceClass::Theme,
    SourceClass::Plugin,
    SourceClass::Source,
    SourceClass::System,
];

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Weakening {
    pub class: SourceClass,
    pub knob: &'static str,
    /// The value in effect, and the level's own.
    pub value: String,
    pub level: String,
    /// The level's name.
    pub profile: &'static str,
    /// Accepted: named in the system file's `[acknowledged]`, or set by
    /// the system file itself, which only root writes.
    pub acknowledged: bool,
}

impl Weakening {
    /// How the system file names it: `aur.ai=off`.
    pub fn key(&self) -> String {
        format!("{}.{}={}", self.class.name(), self.knob, self.value)
    }

    /// One line for the bar: what is weaker, and the two ways out.
    pub fn issue(&self) -> String {
        format!(
            "{}: {} = {} is weaker than the {} level ({}); set it back in `omarchy-guardian tui`, or keep it with `omarchy-guardian config acknowledge`",
            subject(self.class),
            self.knob,
            self.value,
            self.profile,
            self.level
        )
    }
}

/// What a class reviews, in the words the bar uses.
pub const fn subject(class: SourceClass) -> &'static str {
    match class {
        SourceClass::Official => "official packages",
        SourceClass::ThirdPartyRepo => "third-party packages",
        SourceClass::LocalPackage => "local packages",
        SourceClass::Aur => "AUR builds",
        SourceClass::Theme => "themes",
        SourceClass::Plugin => "plugins",
        SourceClass::Source => "scans",
        SourceClass::System => "the sweep",
    }
}

/// Every knob of every user-level class that is weaker than the class's
/// level. The review memory (`cache`, `diff`), the model and the thinking
/// level are choices, not weakenings.
pub fn weakenings(settings: &Settings) -> Vec<Weakening> {
    let accepted = settings.acknowledged_weaker();
    let mut found = Vec::new();
    for class in USER_CLASSES {
        let resolved = settings.resolve(class);
        let policy = &resolved.policy;
        let profile = settings.profile_for(class);
        let level = builtin(profile, class);
        let knobs = [
            (
                "ai",
                policy.ai < level.ai,
                policy.ai.name().to_string(),
                level.ai.name().to_string(),
            ),
            (
                "on_findings",
                policy.on_findings < level.on_findings,
                policy.on_findings.name().to_string(),
                level.on_findings.name().to_string(),
            ),
            (
                "on_ai_suspicious",
                policy.on_ai_suspicious < level.on_ai_suspicious,
                policy.on_ai_suspicious.name().to_string(),
                level.on_ai_suspicious.name().to_string(),
            ),
            // Only while nothing else reviews: with the AI on, the level's
            // question is never asked anyway.
            (
                "confirm",
                level.confirm && !policy.confirm && policy.ai == AiRequirement::Off,
                policy.confirm.to_string(),
                level.confirm.to_string(),
            ),
        ];
        for (knob, weaker, value, level) in knobs {
            if !weaker {
                continue;
            }
            let mut weakening = Weakening {
                class,
                knob,
                value,
                level,
                profile: profile.name(),
                acknowledged: resolved.origin(knob) == Origin::System,
            };
            weakening.acknowledged |= accepted.contains(&weakening.key());
            found.push(weakening);
        }
    }
    found
}

/// The `[acknowledged]` list that accepts exactly what the user file
/// weakens now: what was accepted and is no longer weak is dropped.
pub fn to_acknowledge(settings: &Settings) -> Vec<String> {
    weakenings(settings)
        .iter()
        .filter(|weakening| {
            settings.resolve(weakening.class).origin(weakening.knob) == Origin::User
        })
        .map(Weakening::key)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::{to_acknowledge, weakenings};
    use crate::config::Settings;
    use crate::config::file::PartialConfig;
    use crate::config::model::{Action, AiRequirement, Profile, SourceClass, Toggle};

    fn keys(settings: &Settings) -> Vec<(String, bool)> {
        weakenings(settings)
            .iter()
            .map(|weakening| (weakening.key(), weakening.acknowledged))
            .collect()
    }

    #[test]
    fn a_class_weaker_than_its_level_is_named_knob_by_knob() {
        let defaults = Settings::from_parts(PartialConfig::default(), PartialConfig::default());
        assert!(weakenings(&defaults).is_empty());

        // The three lines that make the AUR gate do nothing.
        let mut user = PartialConfig::default();
        let aur = user.class_mut(SourceClass::Aur);
        aur.ai = Some(AiRequirement::Off);
        aur.on_findings = Some(Action::Warn);
        aur.on_ai_suspicious = Some(Action::Warn);
        // Choices, not weakenings.
        aur.cache = Some(Toggle::Off);
        aur.diff = Some(Toggle::Off);
        user.class_mut(SourceClass::System).ai = Some(AiRequirement::Optional);
        let settings = Settings::from_parts(PartialConfig::default(), user.clone());
        assert_eq!(
            keys(&settings),
            [
                ("aur.ai=off".to_string(), false),
                ("aur.on_findings=warn".to_string(), false),
                ("aur.on_ai_suspicious=warn".to_string(), false),
                ("system.ai=optional".to_string(), false),
            ]
        );
        let issue = weakenings(&settings)[0].issue();
        assert!(
            issue.starts_with("AUR builds: ai = off is weaker than the standard level (required)")
        );
        assert!(issue.contains("config acknowledge"), "{issue}");

        // Accepted in the system file, value and all: a lower value later
        // is not covered.
        let system = PartialConfig {
            acknowledged_weaker: Some(vec!["aur.ai=off".into(), "system.ai=off".into()]),
            ..PartialConfig::default()
        };
        let settings = Settings::from_parts(system, user);
        assert_eq!(
            keys(&settings),
            [
                ("aur.ai=off".to_string(), true),
                ("aur.on_findings=warn".to_string(), false),
                ("aur.on_ai_suspicious=warn".to_string(), false),
                ("system.ai=optional".to_string(), false),
            ]
        );
        assert_eq!(to_acknowledge(&settings).len(), 4);
    }

    #[test]
    fn the_system_files_own_values_and_the_level_itself_are_accepted() {
        // Root wrote it: nothing a same-user program could have done.
        let mut system = PartialConfig::default();
        system.class_mut(SourceClass::Theme).ai = Some(AiRequirement::Off);
        let settings = Settings::from_parts(system, PartialConfig::default());
        assert_eq!(keys(&settings), [("theme.ai=off".to_string(), true)]);
        assert!(to_acknowledge(&settings).is_empty());

        // The no-AI level is a level; taking its question away is not.
        let private = PartialConfig {
            profile: Some(Profile::LocalOnly),
            ..PartialConfig::default()
        };
        let settings = Settings::from_parts(PartialConfig::default(), private.clone());
        assert!(weakenings(&settings).is_empty());
        let mut silent = private;
        silent.class_mut(SourceClass::Plugin).confirm = Some(false);
        let settings = Settings::from_parts(PartialConfig::default(), silent);
        assert_eq!(
            keys(&settings),
            [("plugin.confirm=false".to_string(), false)]
        );
    }
}
