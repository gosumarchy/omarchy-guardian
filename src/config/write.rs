//! Rendering a `PartialConfig` back to the config file format. Only explicit
//! values are written, so a rendered file means exactly what was set and
//! nothing else. `parse(render(config))` gives the config back; the settings
//! TUI relies on that to validate every edit with the real parser.

use std::fmt::Write as _;

use crate::config::file::{PartialConfig, PartialPolicy};
use crate::config::model::{Named, SourceClass};

/// The file text for `config`, after a comment `header` (each line of which
/// should start with `#`).
pub fn render(config: &PartialConfig, header: &str) -> String {
    let mut text = String::from(header);
    let line = |text: &mut String, key: &str, value: &str| {
        // Formatting into a String cannot fail.
        let _ = writeln!(text, "{key} = {value}");
    };

    if let Some(profile) = config.profile {
        line(&mut text, "profile", &quoted(profile.name()));
    }
    if let Some(repos) = &config.official_repos {
        let list: Vec<String> = repos.iter().map(|repo| quoted(repo)).collect();
        line(
            &mut text,
            "official_repos",
            &format!("[{}]", list.join(", ")),
        );
    }

    let agent = &config.agent;
    let numbers = [
        ("max_input_kib", agent.max_input_kib),
        ("max_chunks", agent.max_chunks),
        ("cache_days", agent.cache_days),
        ("max_store_mib", agent.max_store_mib),
    ];
    if agent.model.is_some() || numbers.iter().any(|(_, value)| value.is_some()) {
        text.push_str("\n[agent]\n");
        if let Some(model) = &agent.model {
            line(&mut text, "model", &quoted(model));
        }
        for (key, value) in numbers {
            if let Some(value) = value {
                line(&mut text, key, &value.to_string());
            }
        }
    }
    if !agent.variants.is_empty() {
        text.push_str("\n[agent.variants]\n");
        for (level, variant) in &agent.variants {
            line(&mut text, level.name(), &quoted(variant));
        }
    }

    for class in SourceClass::ALL.iter().copied() {
        let policy = config.class(class);
        let knobs = knobs(&policy);
        if knobs.is_empty() {
            continue;
        }
        let _ = writeln!(text, "\n[class.{}]", class.name());
        for (key, value) in knobs {
            line(&mut text, key, &value);
        }
    }
    text
}

/// The explicit knobs of one class, as `(key, rendered value)`.
fn knobs(policy: &PartialPolicy) -> Vec<(&'static str, String)> {
    [
        ("ai", policy.ai.map(|value| quoted(value.name()))),
        (
            "on_findings",
            policy.on_findings.map(|value| quoted(value.name())),
        ),
        (
            "on_ai_suspicious",
            policy.on_ai_suspicious.map(|value| quoted(value.name())),
        ),
        (
            "thinking",
            policy.thinking.map(|value| quoted(value.name())),
        ),
        ("model", policy.model.as_deref().map(quoted)),
        (
            "timeout_secs",
            policy.timeout_secs.map(|value| value.to_string()),
        ),
        ("confirm", policy.confirm.map(|value| value.to_string())),
        ("cache", policy.cache.map(|value| quoted(value.name()))),
        ("diff", policy.diff.map(|value| quoted(value.name()))),
    ]
    .into_iter()
    .filter_map(|(key, value)| value.map(|value| (key, value)))
    .collect()
}

/// A TOML basic string.
fn quoted(text: &str) -> String {
    let mut out = String::with_capacity(text.len() + 2);
    out.push('"');
    for character in text.chars() {
        match character {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\t' => out.push_str("\\t"),
            character if character.is_control() => {
                let _ = write!(out, "\\u{:04X}", u32::from(character));
            }
            character => out.push(character),
        }
    }
    out.push('"');
    out
}

#[cfg(test)]
mod tests {
    use std::path::Path;

    use super::{quoted, render};
    use crate::config::file::{AgentDefaults, PartialConfig, PartialPolicy, parse};
    use crate::config::model::{
        Action, AiRequirement, Named, Profile, SourceClass, Thinking, Toggle,
    };

    fn round_trip(config: &PartialConfig) -> PartialConfig {
        let text = render(config, "# test\n");
        parse(Path::new("rendered"), &text).unwrap_or_else(|error| panic!("{error}\n{text}"))
    }

    #[test]
    fn every_value_round_trips() {
        let config = PartialConfig {
            profile: Some(Profile::Strict),
            official_repos: Some(vec!["core".into(), "extra".into()]),
            agent: AgentDefaults {
                model: Some("anthropic/claude-sonnet-5".into()),
                max_input_kib: Some(512),
                max_chunks: Some(4),
                cache_days: Some(7),
                max_store_mib: Some(64),
                variants: vec![
                    (Thinking::Max, "xhigh".into()),
                    (Thinking::High, "high".into()),
                ],
            },
            classes: vec![
                (
                    SourceClass::Aur,
                    PartialPolicy {
                        ai: Some(AiRequirement::Required),
                        on_findings: Some(Action::Block),
                        on_ai_suspicious: Some(Action::Warn),
                        thinking: Some(Thinking::Max),
                        model: Some("ollama/qwen3".into()),
                        timeout_secs: Some(300),
                        confirm: Some(true),
                        cache: Some(Toggle::Off),
                        diff: Some(Toggle::On),
                    },
                ),
                (
                    SourceClass::Official,
                    PartialPolicy {
                        thinking: Some(Thinking::Low),
                        ..PartialPolicy::default()
                    },
                ),
            ],
        };

        let parsed = round_trip(&config);
        assert_eq!(parsed.profile, config.profile);
        assert_eq!(parsed.official_repos, config.official_repos);
        assert_eq!(parsed.agent, config.agent);
        for class in SourceClass::ALL.iter().copied() {
            assert_eq!(parsed.class(class), config.class(class), "{}", class.name());
        }
    }

    #[test]
    fn an_empty_config_renders_only_the_header() {
        assert_eq!(render(&PartialConfig::default(), "# h\n"), "# h\n");
        assert_eq!(
            round_trip(&PartialConfig::default()),
            PartialConfig::default()
        );
    }

    #[test]
    fn strings_are_escaped() {
        assert_eq!(quoted("a\"b\\c\nd"), "\"a\\\"b\\\\c\\nd\"");
    }
}
