//! Combining profile, system file and user file into one policy per class
//! (spec §6). For classes enforced by the root pacman hook the user layer
//! may only tighten; everything it cannot apply is recorded, never dropped
//! silently.

use crate::config::file::PartialPolicy;
use crate::config::model::{Named, Policy, Profile, SourceClass, builtin};

pub(super) const KNOBS: [&str; 9] = [
    "ai",
    "on_findings",
    "on_ai_suspicious",
    "thinking",
    "model",
    "timeout_secs",
    "confirm",
    "cache",
    "diff",
];

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Origin {
    Profile,
    System,
    User,
}

impl Origin {
    pub(crate) const fn name(self) -> &'static str {
        match self {
            Self::Profile => "profile",
            Self::System => "system",
            Self::User => "user",
        }
    }
}

pub(super) struct Layers<'a> {
    pub(super) system_profile: Profile,
    pub(super) system: &'a PartialPolicy,
    pub(super) user_profile: Option<Profile>,
    pub(super) user: &'a PartialPolicy,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Resolved {
    pub(super) policy: Policy,
    origins: Vec<(&'static str, Origin)>,
    /// User values that were not applied, with the reason.
    pub(super) ignored: Vec<String>,
}

impl Resolved {
    pub(crate) fn origin(&self, knob: &str) -> Origin {
        self.origins
            .iter()
            .find(|(name, _)| *name == knob)
            .map_or(Origin::Profile, |(_, origin)| *origin)
    }

    fn from_profile(profile: Profile, class: SourceClass) -> Self {
        Self {
            policy: builtin(profile, class),
            origins: KNOBS.iter().map(|knob| (*knob, Origin::Profile)).collect(),
            ignored: Vec::new(),
        }
    }

    fn mark(&mut self, knob: &'static str, origin: Origin) {
        if let Some(entry) = self.origins.iter_mut().find(|(name, _)| *name == knob) {
            entry.1 = origin;
        }
    }

    /// Unconditional override (system layer, or user layer for user-level classes).
    fn apply(&mut self, values: &PartialPolicy, origin: Origin) {
        if let Some(ai) = values.ai {
            self.policy.ai = ai;
            self.mark("ai", origin);
        }
        if let Some(action) = values.on_findings {
            self.policy.on_findings = action;
            self.mark("on_findings", origin);
        }
        if let Some(action) = values.on_ai_suspicious {
            self.policy.on_ai_suspicious = action;
            self.mark("on_ai_suspicious", origin);
        }
        if let Some(thinking) = values.thinking {
            self.policy.thinking = thinking;
            self.mark("thinking", origin);
        }
        if let Some(model) = &values.model {
            self.policy.model = Some(model.clone());
            self.mark("model", origin);
        }
        if let Some(timeout) = values.timeout_secs {
            self.policy.timeout_secs = Some(timeout);
            self.mark("timeout_secs", origin);
        }
        if let Some(confirm) = values.confirm {
            self.policy.confirm = confirm;
            self.mark("confirm", origin);
        }
        if let Some(cache) = values.cache {
            self.policy.cache = cache;
            self.mark("cache", origin);
        }
        if let Some(diff) = values.diff {
            self.policy.diff = diff;
            self.mark("diff", origin);
        }
    }

    /// Tighten-only override for privileged classes.
    fn tighten(&mut self, values: &PartialPolicy, source: &str) {
        tighten_knob(
            &mut self.policy.ai,
            values.ai,
            "ai",
            source,
            &mut self.origins,
            &mut self.ignored,
        );
        tighten_knob(
            &mut self.policy.on_findings,
            values.on_findings,
            "on_findings",
            source,
            &mut self.origins,
            &mut self.ignored,
        );
        tighten_knob(
            &mut self.policy.on_ai_suspicious,
            values.on_ai_suspicious,
            "on_ai_suspicious",
            source,
            &mut self.origins,
            &mut self.ignored,
        );

        // Thinking, model and timeout for pacman-enforced classes come only
        // from the system file; the user layer can never supply them, tighter
        // or not, because a level or model the provider rejects would make
        // the root gate's review unavailable.
        if let Some(thinking) = values.thinking
            && thinking != self.policy.thinking
        {
            self.ignored.push(format!(
                "thinking = {} ignored ({source}): only the system file sets it for pacman-enforced classes",
                thinking.name()
            ));
        }
        if let Some(model) = &values.model {
            self.ignored.push(format!(
                "model = {model} ignored ({source}): models for pacman-enforced classes come only from the system file"
            ));
        }
        if let Some(timeout) = values.timeout_secs {
            self.ignored.push(format!(
                "timeout_secs = {timeout} ignored ({source}): only the system file sets it for pacman-enforced classes"
            ));
        }

        // The review memory is never used for pacman-enforced classes.
        for (knob, value) in [("cache", values.cache), ("diff", values.diff)] {
            if let Some(value) = value {
                self.ignored.push(format!(
                    "{knob} = {} ignored ({source}): the review memory is never used for pacman-enforced classes",
                    value.name()
                ));
            }
        }
    }
}

fn tighten_knob<T: Named + Ord>(
    slot: &mut T,
    candidate: Option<T>,
    knob: &'static str,
    source: &str,
    origins: &mut [(&'static str, Origin)],
    ignored: &mut Vec<String>,
) {
    let Some(candidate) = candidate else {
        return;
    };

    if candidate < *slot {
        ignored.push(format!(
            "{knob} = {} ignored ({source}): looser than {} for a pacman-enforced class",
            candidate.name(),
            slot.name()
        ));
        return;
    }

    if candidate > *slot {
        *slot = candidate;
        if let Some(entry) = origins.iter_mut().find(|(name, _)| *name == knob) {
            entry.1 = Origin::User;
        }
    }
}

pub(super) fn resolve(class: SourceClass, layers: &Layers<'_>) -> Resolved {
    if class.is_privileged() {
        let mut resolved = Resolved::from_profile(layers.system_profile, class);
        resolved.apply(layers.system, Origin::System);

        if let Some(profile) = layers.user_profile {
            let stricter = builtin(profile, class);
            let profile_values = as_partial(&stricter);
            resolved.tighten(&profile_values, &format!("user profile {}", profile.name()));
            // No knob, so no file sets it: it follows the stricter of the
            // two profiles, like the knobs above.
            resolved.policy.ai_remarks = resolved.policy.ai_remarks.max(stricter.ai_remarks);
        }
        resolved.tighten(layers.user, "user file");

        resolved
    } else {
        let profile = layers.user_profile.unwrap_or(layers.system_profile);
        let mut resolved = Resolved::from_profile(profile, class);
        resolved.apply(layers.system, Origin::System);
        resolved.apply(layers.user, Origin::User);

        resolved
    }
}

/// A built-in policy's tightenable knobs as explicit values.
fn as_partial(policy: &Policy) -> PartialPolicy {
    PartialPolicy {
        ai: Some(policy.ai),
        on_findings: Some(policy.on_findings),
        on_ai_suspicious: Some(policy.on_ai_suspicious),
        thinking: Some(policy.thinking),
        model: None,
        timeout_secs: None,
        confirm: None,
        cache: None,
        diff: None,
    }
}

#[cfg(test)]
mod tests {
    use super::{Layers, Origin, resolve};
    use crate::config::file::PartialPolicy;
    use crate::config::model::{
        Action, AiRequirement, Named, Policy, Profile, SourceClass, Thinking, Toggle, builtin,
    };

    fn layers<'a>(
        system_profile: Profile,
        system: &'a PartialPolicy,
        user_profile: Option<Profile>,
        user: &'a PartialPolicy,
    ) -> Layers<'a> {
        Layers {
            system_profile,
            system,
            user_profile,
            user,
        }
    }

    #[test]
    fn review_memory_knobs_are_user_level_only() {
        let empty = PartialPolicy::default();
        let user = PartialPolicy {
            cache: Some(Toggle::Off),
            diff: Some(Toggle::Off),
            ..PartialPolicy::default()
        };

        let theme = resolve(
            SourceClass::Theme,
            &layers(Profile::Standard, &empty, None, &user),
        );
        assert_eq!(
            (theme.policy.cache, theme.policy.diff),
            (Toggle::Off, Toggle::Off)
        );
        assert_eq!(theme.origin("cache"), Origin::User);

        let loosen = PartialPolicy {
            cache: Some(Toggle::On),
            ..PartialPolicy::default()
        };
        let official = resolve(
            SourceClass::Official,
            &layers(Profile::Standard, &empty, None, &loosen),
        );
        assert_eq!(official.policy.cache, Toggle::Off);
        assert!(
            official
                .ignored
                .iter()
                .any(|line| line.starts_with("cache = on ignored (user file)")),
            "{:?}",
            official.ignored
        );
    }

    #[test]
    fn user_level_classes_take_user_values() {
        let system = PartialPolicy {
            thinking: Some(Thinking::Medium),
            ..PartialPolicy::default()
        };
        let user = PartialPolicy {
            ai: Some(AiRequirement::Off),
            model: Some("ollama/qwen3".into()),
            ..PartialPolicy::default()
        };

        let resolved = resolve(
            SourceClass::Theme,
            &layers(Profile::Standard, &system, Some(Profile::Strict), &user),
        );

        assert_eq!(resolved.policy.ai, AiRequirement::Off);
        assert_eq!(resolved.policy.thinking, Thinking::Medium);
        assert_eq!(resolved.policy.on_findings, Action::Block);
        assert_eq!(resolved.policy.model.as_deref(), Some("ollama/qwen3"));
        assert_eq!(resolved.origin("ai"), Origin::User);
        assert_eq!(resolved.origin("thinking"), Origin::System);
        assert_eq!(resolved.origin("on_findings"), Origin::Profile);
        assert!(resolved.ignored.is_empty());
    }

    #[test]
    fn user_cannot_loosen_privileged_classes() {
        let empty = PartialPolicy::default();
        let user = PartialPolicy {
            ai: Some(AiRequirement::Off),
            on_findings: Some(Action::Block),
            thinking: Some(Thinking::Minimal),
            model: Some("evil/model".into()),
            timeout_secs: Some(900),
            ..PartialPolicy::default()
        };

        let resolved = resolve(
            SourceClass::Official,
            &layers(Profile::Standard, &empty, None, &user),
        );

        assert_eq!(resolved.policy.ai, AiRequirement::Optional);
        assert_eq!(resolved.policy.on_findings, Action::Block);
        assert_eq!(resolved.policy.thinking, Thinking::Low);
        assert_eq!(resolved.policy.model, None);
        assert_eq!(resolved.policy.timeout_secs, None);
        assert_eq!(resolved.origin("on_findings"), Origin::User);
        assert_eq!(resolved.ignored.len(), 4, "{:?}", resolved.ignored);
        assert!(
            resolved
                .ignored
                .iter()
                .any(|line| line.starts_with("ai = off"))
        );
    }

    #[test]
    fn a_stricter_user_profile_tightens_privileged_classes() {
        let empty = PartialPolicy::default();
        let resolved = resolve(
            SourceClass::Official,
            &layers(Profile::Standard, &empty, Some(Profile::Strict), &empty),
        );
        let expected = Policy {
            thinking: Thinking::Low,
            ..builtin(Profile::Strict, SourceClass::Official)
        };
        assert_eq!(resolved.policy, expected);
        assert_eq!(resolved.origin("thinking"), Origin::Profile);
        assert!(
            resolved
                .ignored
                .iter()
                .any(|line| line.starts_with("thinking = medium ignored (user profile strict)"))
        );

        let looser = resolve(
            SourceClass::Official,
            &layers(Profile::Strict, &empty, Some(Profile::LocalOnly), &empty),
        );
        assert_eq!(
            looser.policy,
            builtin(Profile::Strict, SourceClass::Official)
        );
        assert!(!looser.ignored.is_empty());
    }

    #[test]
    fn low_ai_remarks_follow_the_profile_and_no_layer_of_values() {
        use crate::config::model::Remarks::{Findings, Shown};
        use Profile::{LocalOnly, Standard, Strict};

        // Every knob a file can set, at its loosest, in both files.
        let loosest = PartialPolicy {
            ai: Some(AiRequirement::Off),
            on_findings: Some(Action::Warn),
            on_ai_suspicious: Some(Action::Warn),
            thinking: Some(Thinking::Minimal),
            confirm: Some(false),
            cache: Some(Toggle::On),
            diff: Some(Toggle::On),
            ..PartialPolicy::default()
        };
        let empty = PartialPolicy::default();
        for values in [&empty, &loosest] {
            for class in SourceClass::ALL.iter().copied() {
                for (system, user, user_level, privileged) in [
                    (Standard, None, Shown, Shown),
                    (Strict, None, Findings, Findings),
                    (LocalOnly, None, Shown, Shown),
                    // A user-level class takes the user's profile; a
                    // pacman class the stricter of the two.
                    (Standard, Some(Strict), Findings, Findings),
                    (Strict, Some(Standard), Shown, Findings),
                    (Strict, Some(LocalOnly), Shown, Findings),
                    (LocalOnly, Some(Strict), Findings, Findings),
                ] {
                    let resolved = resolve(class, &layers(system, values, user, values));
                    assert_eq!(
                        resolved.policy.ai_remarks,
                        if class.is_privileged() {
                            privileged
                        } else {
                            user_level
                        },
                        "{class:?} system {system:?} user {user:?}"
                    );
                }
            }
        }
    }

    /// Spec §6: for privileged classes the result is never looser than the
    /// system layer, for every knob and every value pair.
    #[test]
    fn tighten_only_is_exhaustive() {
        let privileged = SourceClass::ALL
            .iter()
            .copied()
            .filter(|class| class.is_privileged());

        for class in privileged {
            for system_profile in Profile::ALL.iter().copied() {
                for &system_ai in AiRequirement::ALL {
                    for &user_ai in AiRequirement::ALL {
                        for &system_action in Action::ALL {
                            for &user_action in Action::ALL {
                                for &system_thinking in Thinking::ALL {
                                    for &user_thinking in Thinking::ALL {
                                        let system = PartialPolicy {
                                            ai: Some(system_ai),
                                            on_findings: Some(system_action),
                                            on_ai_suspicious: Some(system_action),
                                            thinking: Some(system_thinking),
                                            ..PartialPolicy::default()
                                        };
                                        let user = PartialPolicy {
                                            ai: Some(user_ai),
                                            on_findings: Some(user_action),
                                            on_ai_suspicious: Some(user_action),
                                            thinking: Some(user_thinking),
                                            ..PartialPolicy::default()
                                        };
                                        let policy = resolve(
                                            class,
                                            &layers(system_profile, &system, None, &user),
                                        )
                                        .policy;

                                        assert_eq!(policy.ai, system_ai.max(user_ai));
                                        assert_eq!(
                                            policy.on_findings,
                                            system_action.max(user_action)
                                        );
                                        assert_eq!(
                                            policy.on_ai_suspicious,
                                            system_action.max(user_action)
                                        );
                                        assert_eq!(policy.thinking, system_thinking);
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }
}
