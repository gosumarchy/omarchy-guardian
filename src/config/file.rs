//! Strict parsing of one config file (spec §6). Unknown keys, wrong types
//! and out-of-range values are errors naming the file, line and key, so a
//! typo never silently does nothing.

use std::fmt;
use std::ops::RangeInclusive;
use std::path::{Path, PathBuf};

use crate::config::model::{
    Action, AiRequirement, Named, Profile, RootConsent, SourceClass, Thinking, Toggle,
};
use crate::tomlish::{self, Entry, Value};

pub const TIMEOUT_RANGE: RangeInclusive<u32> = 10..=900;
pub const INPUT_KIB_RANGE: RangeInclusive<u32> = 16..=1024;
pub const CHUNKS_RANGE: RangeInclusive<u32> = 1..=64;
pub const CACHE_DAYS_RANGE: RangeInclusive<u32> = 0..=365;
pub const STORE_MIB_RANGE: RangeInclusive<u32> = 16..=4096;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ConfigError {
    pub file: PathBuf,
    pub line: usize,
    /// Dotted key path; empty for syntax errors.
    pub key: String,
    pub message: String,
}

impl fmt::Display for ConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}:{}: ", self.file.display(), self.line)?;
        if !self.key.is_empty() {
            write!(f, "{}: ", self.key)?;
        }
        f.write_str(&self.message)
    }
}

impl std::error::Error for ConfigError {}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct PartialPolicy {
    pub ai: Option<AiRequirement>,
    pub on_findings: Option<Action>,
    pub on_ai_suspicious: Option<Action>,
    pub thinking: Option<Thinking>,
    pub model: Option<String>,
    pub timeout_secs: Option<u32>,
    pub confirm: Option<bool>,
    pub cache: Option<Toggle>,
    pub diff: Option<Toggle>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct AgentDefaults {
    pub model: Option<String>,
    pub max_input_kib: Option<u32>,
    pub max_chunks: Option<u32>,
    pub cache_days: Option<u32>,
    pub max_store_mib: Option<u32>,
    /// Portable thinking level to provider variant name.
    pub variants: Vec<(Thinking, String)>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct SweepSettings {
    /// Whether the root collector may run.
    pub root: Option<RootConsent>,
    /// The group that may read what the scheduled root collector found.
    pub group: Option<String>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct PartialConfig {
    pub profile: Option<Profile>,
    pub official_repos: Option<Vec<String>>,
    /// Packages allowed to provide the reviewer binaries from outside the
    /// official repositories (system file only).
    pub trusted_reviewer_packages: Option<Vec<String>>,
    /// The system sweep's root collector (system file only).
    pub sweep: SweepSettings,
    /// Weaker-than-the-level settings of user-level classes the owner of
    /// this machine has accepted, as `class.knob=value` (system file only).
    pub acknowledged_weaker: Option<Vec<String>>,
    /// Whether a blocked install can be permitted under the strict level
    /// (`[permit] strict = "allowed"`; system file only).
    pub permit_strict: Option<bool>,
    /// Whether the scheduled sweep asks for a newer release of Guardian
    /// (`[update] check = "off"` in either file turns it off).
    pub update_check: Option<bool>,
    pub agent: AgentDefaults,
    pub classes: Vec<(SourceClass, PartialPolicy)>,
}

impl PartialConfig {
    /// The explicit values for one class (empty when the file has none).
    pub fn class(&self, class: SourceClass) -> PartialPolicy {
        self.classes
            .iter()
            .find(|(candidate, _)| *candidate == class)
            .map(|(_, policy)| policy.clone())
            .unwrap_or_default()
    }

    pub fn class_mut(&mut self, class: SourceClass) -> &mut PartialPolicy {
        if let Some(index) = self
            .classes
            .iter()
            .position(|(candidate, _)| *candidate == class)
        {
            return &mut self.classes[index].1;
        }
        self.classes.push((class, PartialPolicy::default()));
        let index = self.classes.len() - 1;
        &mut self.classes[index].1
    }
}

/// A model is spelled `provider/model`, both parts non-empty, of
/// characters model names are made of. It becomes an argument of the
/// reviewer's command, so it may not look like an option.
pub fn is_model_name(text: &str) -> bool {
    // Each part by itself too: one reviewer is given the part after the
    // provider as an argument of its own.
    text.split_once('/')
        .is_some_and(|(provider, model)| is_plain_argument(provider) && is_plain_argument(model))
        && is_plain_argument(text)
}

/// Whether `text` is safe as one argument of the reviewer's command: no
/// leading `-`, and only letters, digits and `._:/@-[]+=~`.
pub fn is_plain_argument(text: &str) -> bool {
    !text.is_empty()
        && !text.starts_with('-')
        && text
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || "._:/@-[]+=~".contains(c))
}

pub fn parse(file: &Path, text: &str) -> Result<PartialConfig, ConfigError> {
    let entries = tomlish::entries(text).map_err(|error| ConfigError {
        file: file.to_path_buf(),
        line: error.line(),
        key: String::new(),
        message: error.to_string(),
    })?;

    let mut config = PartialConfig::default();
    let mut seen: Vec<String> = Vec::new();

    for entry in &entries {
        let path = entry.full_path();
        let key = path.join(".");
        let field = Field {
            file,
            entry,
            key: &key,
        };

        if entry.array_table {
            return Err(field.error("array tables are not used in the config"));
        }
        if seen.contains(&key) {
            return Err(field.error("set more than once"));
        }
        seen.push(key.clone());

        let value = tomlish::typed_value(&entry.value).ok_or_else(|| {
            field.error("unsupported value (use a string, integer, boolean or list of strings)")
        })?;
        apply(&mut config, &path, &field, value)?;
    }
    Ok(config)
}

/// A Linux group name as `groupadd` accepts it.
pub fn is_group_name(name: &str) -> bool {
    let mut characters = name.chars();
    name.len() <= 32
        && characters
            .next()
            .is_some_and(|first| first.is_ascii_lowercase() || first == '_')
        && characters.all(|character| {
            character.is_ascii_lowercase() || character.is_ascii_digit() || "_-".contains(character)
        })
}

/// Whether `key` names one accepted weaker setting: `class.knob=value`, of
/// a user-level class, with a value that knob can have.
pub fn is_weaker_key(key: &str) -> bool {
    let Some((name, value)) = key.split_once('=') else {
        return false;
    };
    let Some((class, knob)) = name.split_once('.') else {
        return false;
    };
    let known_value = match knob {
        "ai" => AiRequirement::parse(value).is_some(),
        "on_findings" | "on_ai_suspicious" => Action::parse(value).is_some(),
        "confirm" => value == "false",
        _ => false,
    };
    SourceClass::parse(class).is_some_and(|class| !class.is_privileged()) && known_value
}

fn apply(
    config: &mut PartialConfig,
    path: &[&str],
    field: &Field<'_>,
    value: Value,
) -> Result<(), ConfigError> {
    match path {
        ["profile"] => config.profile = Some(field.named(value)?),
        ["official_repos"] => config.official_repos = Some(field.repo_list(value)?),
        ["trusted_reviewer_packages"] => {
            config.trusted_reviewer_packages = Some(field.package_list(value)?);
        }
        ["sweep", "root"] => config.sweep.root = Some(field.named(value)?),
        ["sweep", "group"] => {
            let group = field.text(value)?;
            if !is_group_name(&group) {
                return Err(field.error("expected a group name"));
            }
            config.sweep.group = Some(group);
        }
        ["acknowledged", "weaker"] => {
            config.acknowledged_weaker = Some(field.weaker_list(value)?);
        }
        ["permit", "strict"] => {
            config.permit_strict = Some(match field.text(value)?.as_str() {
                "allowed" => true,
                "off" => false,
                _ => return Err(field.error("expected \"allowed\" or \"off\"")),
            });
        }
        ["update", "check"] => {
            config.update_check = Some(match field.text(value)?.as_str() {
                "on" => true,
                "off" => false,
                _ => return Err(field.error("expected \"on\" or \"off\"")),
            });
        }
        ["agent", "model"] => config.agent.model = Some(field.model(value)?),
        ["agent", "max_input_kib"] => {
            config.agent.max_input_kib = Some(field.integer(&value, &INPUT_KIB_RANGE)?);
        }
        ["agent", "max_chunks"] => {
            config.agent.max_chunks = Some(field.integer(&value, &CHUNKS_RANGE)?);
        }
        ["agent", "cache_days"] => {
            config.agent.cache_days = Some(field.integer(&value, &CACHE_DAYS_RANGE)?);
        }
        ["agent", "max_store_mib"] => {
            config.agent.max_store_mib = Some(field.integer(&value, &STORE_MIB_RANGE)?);
        }
        ["agent", "variants", level] => {
            let level = Thinking::parse(level)
                .filter(|level| *level != Thinking::Default)
                .ok_or_else(|| field.error("variants map minimal, low, medium, high or max"))?;
            let variant = field.text(value)?;
            if !is_plain_argument(&variant) {
                return Err(field.error(
                    "a variant name is letters, digits and ._:/@-[]+=~ and does not start with -",
                ));
            }
            config.agent.variants.push((level, variant));
        }
        ["class", name, knob] => {
            let class = SourceClass::parse(name).ok_or_else(|| {
                field.error(&format!(
                    "unknown source class (known: {})",
                    names::<SourceClass>()
                ))
            })?;
            apply_knob(config.class_mut(class), class, knob, field, value)?;
        }
        _ => return Err(field.error("unknown key")),
    }
    Ok(())
}

fn apply_knob(
    policy: &mut PartialPolicy,
    class: SourceClass,
    knob: &str,
    field: &Field<'_>,
    value: Value,
) -> Result<(), ConfigError> {
    match knob {
        "ai" => policy.ai = Some(field.named(value)?),
        "on_findings" => policy.on_findings = Some(field.named(value)?),
        "on_ai_suspicious" => policy.on_ai_suspicious = Some(field.named(value)?),
        "thinking" => policy.thinking = Some(field.named(value)?),
        "model" => policy.model = Some(field.model(value)?),
        "timeout_secs" => policy.timeout_secs = Some(field.integer(&value, &TIMEOUT_RANGE)?),
        "cache" | "diff" if class.is_privileged() => {
            return Err(field.error(
                "cache and diff are not available for classes enforced by the pacman hook",
            ));
        }
        "cache" => policy.cache = Some(field.named(value)?),
        "diff" => policy.diff = Some(field.named(value)?),
        "confirm" if class.is_privileged() => {
            return Err(
                field.error("confirm is not available for classes enforced by the pacman hook")
            );
        }
        "confirm" => policy.confirm = Some(field.boolean(&value)?),
        _ => return Err(field.error("unknown key")),
    }
    Ok(())
}

fn names<T: Named>() -> String {
    T::ALL
        .iter()
        .map(|value| value.name())
        .collect::<Vec<_>>()
        .join(", ")
}

/// One entry being interpreted, for error construction.
struct Field<'a> {
    file: &'a Path,
    entry: &'a Entry,
    key: &'a str,
}

impl Field<'_> {
    fn error(&self, message: &str) -> ConfigError {
        ConfigError {
            file: self.file.to_path_buf(),
            line: self.entry.line,
            key: self.key.to_string(),
            message: message.to_string(),
        }
    }

    fn text(&self, value: Value) -> Result<String, ConfigError> {
        match value {
            Value::String(text) if !text.trim().is_empty() => Ok(text),
            Value::String(_) | Value::Integer(_) | Value::Bool(_) | Value::StringArray(_) => {
                Err(self.error("expected a non-empty string"))
            }
        }
    }

    fn named<T: Named>(&self, value: Value) -> Result<T, ConfigError> {
        let text = self.text(value)?;
        T::parse(&text).ok_or_else(|| self.error(&format!("expected one of: {}", names::<T>())))
    }

    fn model(&self, value: Value) -> Result<String, ConfigError> {
        let text = self.text(value)?;
        if is_model_name(&text) {
            Ok(text)
        } else {
            Err(self.error("expected provider/model"))
        }
    }

    fn integer(&self, value: &Value, range: &RangeInclusive<u32>) -> Result<u32, ConfigError> {
        let out_of_range = || {
            self.error(&format!(
                "expected an integer from {} to {}",
                range.start(),
                range.end()
            ))
        };
        match value {
            Value::Integer(number) => u32::try_from(*number)
                .ok()
                .filter(|number| range.contains(number))
                .ok_or_else(out_of_range),
            Value::String(_) | Value::Bool(_) | Value::StringArray(_) => Err(out_of_range()),
        }
    }

    fn boolean(&self, value: &Value) -> Result<bool, ConfigError> {
        match value {
            Value::Bool(flag) => Ok(*flag),
            Value::String(_) | Value::Integer(_) | Value::StringArray(_) => {
                Err(self.error("expected true or false"))
            }
        }
    }

    fn package_list(&self, value: Value) -> Result<Vec<String>, ConfigError> {
        match value {
            Value::StringArray(names)
                if names
                    .iter()
                    .all(|name| crate::pacman::is_valid_package_name(name)) =>
            {
                Ok(names)
            }
            Value::StringArray(_) | Value::String(_) | Value::Integer(_) | Value::Bool(_) => {
                Err(self.error("expected a list of pacman package names"))
            }
        }
    }

    fn weaker_list(&self, value: Value) -> Result<Vec<String>, ConfigError> {
        match value {
            Value::StringArray(keys) if keys.iter().all(|key| is_weaker_key(key)) => Ok(keys),
            Value::StringArray(_) | Value::String(_) | Value::Integer(_) | Value::Bool(_) => {
                Err(self.error(
                    "expected a list like [\"aur.ai=off\"]: a user-level class, one of ai, on_findings, on_ai_suspicious or confirm, and the accepted value",
                ))
            }
        }
    }

    fn repo_list(&self, value: Value) -> Result<Vec<String>, ConfigError> {
        let is_repo_name = |name: &str| {
            !name.is_empty()
                && name
                    .chars()
                    .all(|character| character.is_ascii_alphanumeric() || "._-".contains(character))
        };
        match value {
            Value::StringArray(names) if names.iter().all(|name| is_repo_name(name)) => Ok(names),
            Value::StringArray(_) | Value::String(_) | Value::Integer(_) | Value::Bool(_) => {
                Err(self.error("expected a list of pacman repository names"))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::path::Path;

    use super::{PartialPolicy, is_weaker_key, parse};

    #[test]
    fn the_check_for_a_newer_release_is_on_or_off() {
        let check = |text: &str| parse(Path::new("user"), text).map(|config| config.update_check);
        assert_eq!(check("").unwrap(), None);
        assert_eq!(check("[update]\ncheck = \"on\"\n").unwrap(), Some(true));
        assert_eq!(check("[update]\ncheck = \"off\"\n").unwrap(), Some(false));
        assert!(check("[update]\ncheck = \"never\"\n").is_err());
        assert!(check("[update]\ncheck = false\n").is_err());
        assert!(check("[update]\nurl = \"https://x.example\"\n").is_err());
    }

    #[test]
    fn permits_under_the_strict_level_are_allowed_or_off() {
        let strict =
            |text: &str| parse(Path::new("system"), text).map(|config| config.permit_strict);
        assert_eq!(
            strict("[permit]\nstrict = \"allowed\"\n").unwrap(),
            Some(true)
        );
        assert_eq!(strict("[permit]\nstrict = \"off\"\n").unwrap(), Some(false));
        assert_eq!(strict("profile = \"strict\"\n").unwrap(), None);
        assert!(strict("[permit]\nstrict = \"yes\"\n").is_err());
        assert!(strict("[permit]\nstrict = true\n").is_err());
        assert!(strict("[permit]\nstandard = \"off\"\n").is_err());
    }

    #[test]
    fn accepted_weaker_settings_name_a_user_level_class_a_knob_and_a_value() {
        let parsed = parse(
            Path::new("system"),
            "[acknowledged]\nweaker = [\"aur.ai=off\", \"theme.confirm=false\", \"system.on_findings=warn\"]\n",
        )
        .unwrap();
        assert_eq!(parsed.acknowledged_weaker.map(|keys| keys.len()), Some(3));
        for bad in [
            "aur.ai",
            "aur.ai=sometimes",
            "aur.thinking=low",
            "aur.confirm=true",
            // The pacman classes are never loosened by the user file.
            "official.ai=off",
            "nope.ai=off",
            "ai=off",
        ] {
            assert!(!is_weaker_key(bad), "{bad}");
            let text = format!("[acknowledged]\nweaker = [\"{bad}\"]\n");
            assert!(parse(Path::new("system"), &text).is_err(), "{bad}");
        }
        assert!(
            parse(
                Path::new("system"),
                "[acknowledged]\nweaker = \"aur.ai=off\"\n"
            )
            .is_err()
        );
    }

    use crate::config::model::{Action, AiRequirement, Profile, SourceClass, Thinking, Toggle};

    const EXAMPLE: &str = r#"
profile = "strict"
official_repos = ["core", "extra"]

[agent]
model = "anthropic/claude-sonnet-5"
max_input_kib = 512
max_chunks = 4
cache_days = 7
max_store_mib = 64

[agent.variants]
max = "xhigh"

[class.official]
model = "anthropic/claude-haiku-4-5"
thinking = "low"

[class.aur]
ai = "required"
on_findings = "block"
on_ai_suspicious = "warn"
thinking = "max"
timeout_secs = 300
confirm = true
cache = "off"
diff = "off"
"#;

    fn parse_str(text: &str) -> Result<super::PartialConfig, super::ConfigError> {
        parse(Path::new("/test/config.toml"), text)
    }

    #[test]
    fn parses_every_supported_key() {
        let config = parse_str(EXAMPLE).unwrap();

        assert_eq!(config.profile, Some(Profile::Strict));
        assert_eq!(
            config.official_repos,
            Some(vec!["core".into(), "extra".into()])
        );
        assert_eq!(
            config.agent.model.as_deref(),
            Some("anthropic/claude-sonnet-5")
        );
        assert_eq!(config.agent.max_input_kib, Some(512));
        assert_eq!(config.agent.max_chunks, Some(4));
        assert_eq!(config.agent.cache_days, Some(7));
        assert_eq!(config.agent.max_store_mib, Some(64));
        assert_eq!(
            config.agent.variants,
            [(Thinking::Max, "xhigh".to_string())]
        );
        assert_eq!(
            config.class(SourceClass::Official),
            PartialPolicy {
                model: Some("anthropic/claude-haiku-4-5".into()),
                thinking: Some(Thinking::Low),
                ..PartialPolicy::default()
            }
        );
        assert_eq!(
            config.class(SourceClass::Aur),
            PartialPolicy {
                ai: Some(AiRequirement::Required),
                on_findings: Some(Action::Block),
                on_ai_suspicious: Some(Action::Warn),
                thinking: Some(Thinking::Max),
                model: None,
                timeout_secs: Some(300),
                confirm: Some(true),
                cache: Some(Toggle::Off),
                diff: Some(Toggle::Off),
            }
        );
        assert_eq!(config.class(SourceClass::Theme), PartialPolicy::default());
    }

    #[test]
    fn names_that_become_arguments_cannot_look_like_options() {
        use super::{is_model_name, is_plain_argument};
        assert!(is_model_name("claude-code/claude-sonnet-5-5"));
        assert!(is_model_name("openrouter/anthropic/claude:beta@1"));
        assert!(is_model_name("claude-code/claude-sonnet-4-5[1m]"));
        for bad in [
            "claude-code/--x y",
            "claude-code/--x",
            "claude-code/-p",
            "-p/x",
            "a/b;c",
            "a/",
            "/b",
            "a/b\n",
        ] {
            assert!(!is_model_name(bad), "{bad:?}");
        }
        assert!(is_plain_argument("high"));
        assert!(!is_plain_argument("--dangerously"));
        assert!(parse(Path::new("c.toml"), "[agent.variants]\nhigh = \"--x\"\n").is_err());
    }

    #[test]
    fn errors_name_the_line_and_key() {
        let cases = [
            ("profile = \"paranoid\"\n", 1, "profile"),
            (
                "\n[class.aur]\non_finding = \"block\"\n",
                3,
                "class.aur.on_finding",
            ),
            ("[class.nope]\nai = \"off\"\n", 2, "class.nope.ai"),
            ("[agent]\nmax_input_kib = 4096\n", 2, "agent.max_input_kib"),
            (
                "[class.aur]\ntimeout_secs = 5\n",
                2,
                "class.aur.timeout_secs",
            ),
            ("[agent]\nmodel = \"no-slash\"\n", 2, "agent.model"),
            (
                "[agent.variants]\ndefault = \"x\"\n",
                2,
                "agent.variants.default",
            ),
            (
                "[class.official]\nconfirm = true\n",
                2,
                "class.official.confirm",
            ),
            (
                "official_repos = [\"core\", \"bad repo\"]\n",
                1,
                "official_repos",
            ),
            ("profile = 1\n", 1, "profile"),
            ("[[class]]\nai = \"off\"\n", 2, "class.ai"),
            (
                "[class.aur]\nai = \"off\"\n[class.aur]\nai = \"required\"\n",
                4,
                "class.aur.ai",
            ),
            ("mystery = true\n", 1, "mystery"),
            (
                "[class.official]\ncache = \"on\"\n",
                2,
                "class.official.cache",
            ),
            ("[class.aur]\ndiff = \"sometimes\"\n", 2, "class.aur.diff"),
            ("[agent]\nmax_chunks = 0\n", 2, "agent.max_chunks"),
            ("[agent]\ncache_days = 400\n", 2, "agent.cache_days"),
            ("[agent]\nmax_store_mib = 8\n", 2, "agent.max_store_mib"),
        ];

        for (text, line, key) in cases {
            let error = parse_str(text).unwrap_err();
            assert_eq!(
                (error.line, error.key.as_str()),
                (line, key),
                "{text:?}: {error}"
            );
        }
    }

    #[test]
    fn syntax_errors_carry_the_line() {
        let error = parse_str("profile = \"standard\"\n[agent\n").unwrap_err();
        assert_eq!(error.line, 2);
        assert!(error.to_string().starts_with("/test/config.toml:2: "));
    }

    #[test]
    fn an_empty_file_is_valid() {
        assert_eq!(
            parse_str("# nothing\n").unwrap(),
            super::PartialConfig::default()
        );
    }
}
