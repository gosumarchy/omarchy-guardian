//! Locating, validating and combining the two config files into `Settings`.

use std::env;
use std::fs;
use std::io;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};

use crate::config::file::{AgentDefaults, PartialConfig, parse};
use crate::config::model::{
    AgentSettings, DEFAULT_CACHE_DAYS, DEFAULT_MAX_CHUNKS, DEFAULT_MAX_INPUT_KIB,
    DEFAULT_MAX_STORE_MIB, Policy, Profile, SourceClass, StoreSettings,
};
use crate::config::resolve::{Layers, Resolved, resolve};

pub const SYSTEM_PATH: &str = "/etc/omarchy-guardian/config.toml";

pub const DEFAULT_OFFICIAL_REPOS: [&str; 7] = [
    "core",
    "extra",
    "multilib",
    "core-testing",
    "extra-testing",
    "multilib-testing",
    "omarchy",
];

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum FileStatus {
    Missing,
    Loaded,
    Invalid(String),
}

#[derive(Clone, Debug)]
pub struct Settings {
    system_path: PathBuf,
    user_path: Option<PathBuf>,
    system: PartialConfig,
    user: PartialConfig,
    system_status: FileStatus,
    user_status: FileStatus,
    profile_override: Option<Profile>,
    privileged_block: Option<String>,
    user_block: Option<String>,
    warnings: Vec<String>,
}

/// `$XDG_CONFIG_HOME/omarchy-guardian/config.toml`, else `~/.config/...`.
pub fn user_config_path() -> Option<PathBuf> {
    let base = env::var_os("XDG_CONFIG_HOME")
        .map(PathBuf::from)
        .filter(|path| path.is_absolute())
        .or_else(|| {
            env::var_os("HOME")
                .map(PathBuf::from)
                .filter(|path| path.is_absolute())
                .map(|home| home.join(".config"))
        })?;
    Some(base.join("omarchy-guardian").join("config.toml"))
}

/// The system file and its directory must be root-owned regular entries
/// that only root can write.
pub fn check_root_owned(path: &Path) -> Result<(), String> {
    let metadata = fs::symlink_metadata(path).map_err(|error| error.to_string())?;
    if !metadata.file_type().is_file() {
        return Err("not a regular file".into());
    }
    let checks = [(path, metadata)].into_iter().chain(
        path.parent()
            .and_then(|parent| fs::metadata(parent).ok().map(|meta| (parent, meta))),
    );
    for (entry, metadata) in checks {
        if metadata.uid() != 0 {
            return Err(format!(
                "{} is owned by uid {}, not root",
                entry.display(),
                metadata.uid()
            ));
        }
        if metadata.mode() & 0o022 != 0 {
            return Err(format!(
                "{} is writable by group or others",
                entry.display()
            ));
        }
    }
    Ok(())
}

enum Read {
    Missing,
    Parsed(PartialConfig),
    Failed(String),
}

/// A pluggable check for whether a config file is safely owned.
type Verify<'a> = dyn Fn(&Path) -> Result<(), String> + 'a;

fn read(path: &Path, secure: Option<&Verify<'_>>) -> Read {
    match fs::symlink_metadata(path) {
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Read::Missing,
        Err(error) => return Read::Failed(error.to_string()),
        Ok(_) => {}
    }
    if let Some(secure) = secure
        && let Err(reason) = secure(path)
    {
        return Read::Failed(format!("insecure: {reason}"));
    }
    match fs::read_to_string(path) {
        Ok(text) => match parse(path, &text) {
            Ok(config) => Read::Parsed(config),
            Err(error) => Read::Failed(error.to_string()),
        },
        Err(error) => Read::Failed(error.to_string()),
    }
}

impl Settings {
    pub fn load() -> Self {
        Self::load_from(
            Path::new(SYSTEM_PATH),
            user_config_path().as_deref(),
            &check_root_owned,
        )
    }

    /// The root-owned system file alone, for Guardian's root halves: the
    /// user's file is not read.
    pub fn system_only() -> Self {
        Self::load_from(Path::new(SYSTEM_PATH), None, &check_root_owned)
    }

    pub fn load_from(
        system_path: &Path,
        user_path: Option<&Path>,
        secure: &dyn Fn(&Path) -> Result<(), String>,
    ) -> Self {
        let mut settings = Self::from_parts(PartialConfig::default(), PartialConfig::default());
        settings.system_path = system_path.to_path_buf();
        settings.user_path = user_path.map(Path::to_path_buf);

        match read(system_path, Some(secure)) {
            Read::Missing => {}
            Read::Parsed(config) => {
                settings.system = config;
                settings.system_status = FileStatus::Loaded;
            }
            Read::Failed(reason) => {
                settings.privileged_block = Some(format!(
                    "{}: {reason}; fix it (see `omarchy-guardian config check`) before pacman transactions can be reviewed",
                    system_path.display()
                ));
                settings
                    .warnings
                    .push(format!("ignoring {}: {reason}", system_path.display()));
                settings.system_status = FileStatus::Invalid(reason);
            }
        }

        if let Some(user_path) = user_path {
            match read(user_path, None) {
                Read::Missing => {}
                Read::Parsed(config) => {
                    if config.sweep != crate::config::file::SweepSettings::default() {
                        settings.warnings.push(format!(
                            "[sweep] in {} is ignored: only the system file decides whether the root checks run",
                            user_path.display()
                        ));
                    }
                    if config.acknowledged_weaker.is_some() {
                        settings.warnings.push(format!(
                            "[acknowledged] in {} is ignored: only the system file can accept a weaker setting",
                            user_path.display()
                        ));
                    }
                    if config.permit_strict.is_some() {
                        settings.warnings.push(format!(
                            "[permit] in {} is ignored: only the system file says whether permits are given under the strict level",
                            user_path.display()
                        ));
                    }
                    settings.user = config;
                    settings.user_status = FileStatus::Loaded;
                }
                // Not carried on with the defaults: the file may hold a
                // stricter profile, and one typo would quietly undo it.
                Read::Failed(reason) => {
                    // A parse error names the file and line itself.
                    let file = user_path.display().to_string();
                    let named = if reason.starts_with(&file) {
                        reason.clone()
                    } else {
                        format!("{file}: {reason}")
                    };
                    let block = format!(
                        "{named}; fix it (see `omarchy-guardian config check`) before AUR builds, themes, plugins, scans and the sweep can be reviewed"
                    );
                    settings.warnings.push(block.clone());
                    settings.user_block = Some(block);
                    settings.user_status = FileStatus::Invalid(reason);
                }
            }
        }
        settings
    }

    pub fn from_parts(system: PartialConfig, user: PartialConfig) -> Self {
        Self {
            system_path: PathBuf::from(SYSTEM_PATH),
            user_path: None,
            system,
            user,
            system_status: FileStatus::Missing,
            user_status: FileStatus::Missing,
            profile_override: None,
            privileged_block: None,
            user_block: None,
            warnings: Vec::new(),
        }
    }

    /// A one-run profile for user-level classes (`--profile`).
    pub fn with_profile(mut self, profile: Profile) -> Self {
        self.profile_override = Some(profile);
        self
    }

    pub fn system_profile(&self) -> Profile {
        self.system.profile.unwrap_or(Profile::Standard)
    }

    fn user_profile(&self) -> Option<Profile> {
        self.profile_override.or(self.user.profile)
    }

    /// The profile whose built-ins a class starts from.
    pub fn profile_for(&self, class: SourceClass) -> Profile {
        if class.is_privileged() {
            self.system_profile()
        } else {
            self.user_profile().unwrap_or_else(|| self.system_profile())
        }
    }

    pub fn resolve(&self, class: SourceClass) -> Resolved {
        let system = self.system.class(class);
        let user = self.user.class(class);
        resolve(
            class,
            &Layers {
                system_profile: self.system_profile(),
                system: &system,
                user_profile: self.user_profile(),
                user: &user,
            },
        )
    }

    pub fn policy(&self, class: SourceClass) -> Policy {
        self.resolve(class).policy
    }

    /// Agent defaults that may influence a class: only the system file for
    /// pacman-enforced classes, the system then the user file otherwise.
    fn agent_layers(&self, class: SourceClass) -> Vec<&AgentDefaults> {
        if class.is_privileged() {
            vec![&self.system.agent]
        } else {
            vec![&self.system.agent, &self.user.agent]
        }
    }

    pub fn agent_settings(&self, class: SourceClass) -> AgentSettings {
        let policy = self.policy(class);
        let layers = self.agent_layers(class);

        let model = policy
            .model
            .clone()
            .or_else(|| layers.iter().rev().find_map(|layer| layer.model.clone()));
        // Variant names are provider-specific, so a level is only sent when
        // `[agent.variants]` maps it; otherwise the provider default applies.
        let variant = layers.iter().rev().find_map(|layer| {
            layer
                .variants
                .iter()
                .find(|(level, _)| *level == policy.thinking)
                .map(|(_, name)| name.clone())
        });
        let max_input_kib = layers
            .iter()
            .rev()
            .find_map(|layer| layer.max_input_kib)
            .unwrap_or(DEFAULT_MAX_INPUT_KIB);
        let max_chunks = layers
            .iter()
            .rev()
            .find_map(|layer| layer.max_chunks)
            .unwrap_or(DEFAULT_MAX_CHUNKS);

        AgentSettings {
            model,
            thinking: policy.thinking,
            variant,
            timeout_secs: policy.timeout_secs(),
            max_input_bytes: max_input_kib as usize * 1024,
            max_chunks: max_chunks as usize,
        }
    }

    /// Review-memory limits. The memory only serves user-level classes, so
    /// the user file's values come first.
    pub fn store_settings(&self) -> StoreSettings {
        let layers = [&self.user.agent, &self.system.agent];
        StoreSettings {
            cache_days: layers
                .iter()
                .find_map(|layer| layer.cache_days)
                .unwrap_or(DEFAULT_CACHE_DAYS),
            max_store_mib: layers
                .iter()
                .find_map(|layer| layer.max_store_mib)
                .unwrap_or(DEFAULT_MAX_STORE_MIB),
        }
    }

    /// Whether the system sweep may run its root collector, and the group
    /// that may read what the scheduled one found; only the root-owned
    /// system file says.
    pub fn sweep_root(&self) -> (Option<crate::config::model::RootConsent>, Option<String>) {
        (self.system.sweep.root, self.system.sweep.group.clone())
    }

    /// Reviewer packages trusted from outside the official repositories;
    /// only the root-owned system file can name them.
    pub fn trusted_reviewer_packages(&self) -> Vec<String> {
        self.system
            .trusted_reviewer_packages
            .clone()
            .unwrap_or_default()
    }

    pub fn official_repos(&self) -> Vec<String> {
        self.system.official_repos.clone().unwrap_or_else(|| {
            DEFAULT_OFFICIAL_REPOS
                .iter()
                .map(ToString::to_string)
                .collect()
        })
    }

    pub fn privileged_block(&self) -> Option<&str> {
        self.privileged_block.as_deref()
    }

    /// Why no user-level review can run: the user file is there and does
    /// not parse.
    pub fn user_block(&self) -> Option<&str> {
        self.user_block.as_deref()
    }

    /// The weaker settings accepted in the root-owned system file.
    pub fn acknowledged_weaker(&self) -> &[String] {
        self.system
            .acknowledged_weaker
            .as_deref()
            .unwrap_or_default()
    }

    /// Whether a blocked install can be permitted under the strict level:
    /// only when the root-owned system file says so.
    pub fn permits_under_strict(&self) -> bool {
        self.system.permit_strict == Some(true)
    }

    /// Whether Guardian asks, once a day, for a newer release of itself:
    /// unless either file turns it off.
    pub fn checks_for_updates(&self) -> bool {
        self.system.update_check != Some(false) && self.user.update_check != Some(false)
    }

    pub fn warnings(&self) -> &[String] {
        &self.warnings
    }

    pub fn system_status(&self) -> &FileStatus {
        &self.system_status
    }

    pub fn user_status(&self) -> &FileStatus {
        &self.user_status
    }

    /// The values set in the system file, as parsed.
    pub fn system_config(&self) -> &PartialConfig {
        &self.system
    }

    /// The values set in the user file, as parsed.
    pub fn user_config(&self) -> &PartialConfig {
        &self.user
    }

    pub fn system_path(&self) -> &Path {
        &self.system_path
    }

    pub fn user_path(&self) -> Option<&Path> {
        self.user_path.as_deref()
    }
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::path::Path;

    use super::{FileStatus, Settings};
    use crate::config::file::{AgentDefaults, PartialConfig, PartialPolicy};
    use crate::config::model::{
        AiRequirement, Profile, RootConsent, SourceClass, StoreSettings, Thinking,
    };
    use crate::test_support::TempDir;

    #[expect(
        clippy::unnecessary_wraps,
        reason = "must match the `Verify` callback signature `Settings::load_from` expects"
    )]
    fn secure(_: &Path) -> Result<(), String> {
        Ok(())
    }

    fn insecure(_: &Path) -> Result<(), String> {
        Err("owned by uid 1000".into())
    }

    #[test]
    fn missing_files_mean_the_standard_profile() {
        let dir = TempDir::new("settings-missing");
        let settings = Settings::load_from(
            &dir.path().join("system.toml"),
            Some(&dir.path().join("user.toml")),
            &secure,
        );

        assert_eq!(settings.system_status(), &FileStatus::Missing);
        assert_eq!(settings.privileged_block(), None);
        assert_eq!(
            settings.policy(SourceClass::Official).ai,
            AiRequirement::Optional
        );
        assert_eq!(
            settings.policy(SourceClass::Aur).ai,
            AiRequirement::Required
        );
    }

    #[test]
    fn insecure_or_invalid_system_file_blocks_privileged_classes() {
        let dir = TempDir::new("settings-insecure");
        let system = dir.path().join("system.toml");
        fs::write(&system, "profile = \"local-only\"\n").unwrap();

        let settings = Settings::load_from(&system, None, &insecure);
        assert!(
            settings
                .privileged_block()
                .unwrap()
                .contains("owned by uid 1000")
        );
        assert!(matches!(settings.system_status(), FileStatus::Invalid(_)));
        // User-level classes fall back to the built-in standard profile.
        assert_eq!(
            settings.policy(SourceClass::Theme).ai,
            AiRequirement::Required
        );

        fs::write(&system, "profile = \"bogus\"\n").unwrap();
        let settings = Settings::load_from(&system, None, &secure);
        assert!(
            settings
                .privileged_block()
                .unwrap()
                .contains("config check")
        );
    }

    #[test]
    fn only_the_system_file_decides_the_sweeps_root_checks() {
        let dir = TempDir::new("settings-sweep");
        let system = dir.path().join("system.toml");
        let user = dir.path().join("user.toml");
        fs::write(&system, "[sweep]\nroot = \"declined\"\n").unwrap();
        fs::write(&user, "[sweep]\nroot = \"allowed\"\ngroup = \"users\"\n").unwrap();
        let settings = Settings::load_from(&system, Some(&user), &secure);
        assert_eq!(settings.sweep_root(), (Some(RootConsent::Declined), None));
        assert!(
            settings
                .warnings()
                .iter()
                .any(|warning| warning.contains("[sweep]"))
        );
    }

    #[test]
    fn an_invalid_user_file_blocks_user_level_reviews() {
        let dir = TempDir::new("settings-user");
        let user = dir.path().join("user.toml");
        // A stricter level and one typo: not reviewed at the default.
        fs::write(
            &user,
            "profile = \"strict\"\n[class.aur]\nai = \"sometimes\"\n",
        )
        .unwrap();

        let settings = Settings::load_from(&dir.path().join("none.toml"), Some(&user), &secure);
        assert!(matches!(settings.user_status(), FileStatus::Invalid(_)));
        assert_eq!(settings.warnings().len(), 1);
        let block = settings.user_block().unwrap();
        // It names the file and the line.
        assert!(block.contains(&format!("{}:3:", user.display())), "{block}");
        assert!(block.contains("config check"), "{block}");
        assert_eq!(settings.privileged_block(), None);

        // A file that is not there, or parses, blocks nothing.
        let missing = Settings::load_from(
            &dir.path().join("none.toml"),
            Some(&dir.path().join("no-user.toml")),
            &secure,
        );
        assert_eq!(missing.user_block(), None);
        fs::write(&user, "profile = \"strict\"\n").unwrap();
        let valid = Settings::load_from(&dir.path().join("none.toml"), Some(&user), &secure);
        assert_eq!(valid.user_block(), None);
    }

    #[test]
    fn only_the_system_file_accepts_a_weaker_setting() {
        let dir = TempDir::new("settings-accepted");
        let system = dir.path().join("system.toml");
        let user = dir.path().join("user.toml");
        fs::write(&system, "[acknowledged]\nweaker = [\"aur.ai=off\"]\n").unwrap();
        fs::write(&user, "[acknowledged]\nweaker = [\"theme.ai=off\"]\n").unwrap();
        let settings = Settings::load_from(&system, Some(&user), &secure);
        assert_eq!(settings.acknowledged_weaker(), ["aur.ai=off"]);
        assert!(!settings.permits_under_strict());
        assert!(
            settings
                .warnings()
                .iter()
                .any(|warning| warning.contains("[acknowledged]"))
        );
    }

    #[test]
    fn an_invalid_user_file_leaves_the_defaults_for_what_shows_settings() {
        let dir = TempDir::new("settings-user-defaults");
        let user = dir.path().join("user.toml");
        fs::write(&user, "[class.aur]\nai = \"sometimes\"\n").unwrap();

        let settings = Settings::load_from(&dir.path().join("none.toml"), Some(&user), &secure);
        assert_eq!(
            settings.policy(SourceClass::Aur).ai,
            AiRequirement::Required
        );
    }

    #[test]
    fn either_file_turns_the_check_for_a_newer_release_off() {
        let with = |check: Option<bool>| PartialConfig {
            update_check: check,
            ..PartialConfig::default()
        };
        let checks =
            |system, user| Settings::from_parts(with(system), with(user)).checks_for_updates();
        assert!(checks(None, None));
        assert!(checks(Some(true), Some(true)));
        assert!(!checks(Some(false), None));
        assert!(!checks(None, Some(false)));
        // Neither file turns back on what the other turned off.
        assert!(!checks(Some(false), Some(true)));
        assert!(!checks(Some(true), Some(false)));
    }

    #[test]
    fn agent_settings_follow_layers_and_privilege() {
        let system = PartialConfig {
            agent: AgentDefaults {
                model: Some("anthropic/claude-sonnet-5".into()),
                max_input_kib: Some(512),
                variants: vec![(Thinking::Max, "xhigh".into())],
                ..AgentDefaults::default()
            },
            ..PartialConfig::default()
        };
        let user = PartialConfig {
            agent: AgentDefaults {
                model: Some("ollama/qwen3".into()),
                max_input_kib: None,
                variants: vec![(Thinking::High, "deep".into())],
                ..AgentDefaults::default()
            },
            classes: vec![(
                SourceClass::Aur,
                PartialPolicy {
                    thinking: Some(Thinking::Max),
                    ..PartialPolicy::default()
                },
            )],
            ..PartialConfig::default()
        };
        let settings = Settings::from_parts(system, user);

        let official = settings.agent_settings(SourceClass::Official);
        assert_eq!(official.model.as_deref(), Some("anthropic/claude-sonnet-5"));
        assert_eq!(official.variant, None);
        assert_eq!(
            official.label(),
            "anthropic/claude-sonnet-5 · low (provider default)"
        );
        assert_eq!(official.max_input_bytes, 512 * 1024);

        let aur = settings.agent_settings(SourceClass::Aur);
        assert_eq!(aur.model.as_deref(), Some("ollama/qwen3"));
        assert_eq!(aur.variant.as_deref(), Some("xhigh"));
        assert_eq!(aur.timeout_secs, 300);

        let theme = settings.agent_settings(SourceClass::Theme);
        assert_eq!(theme.variant.as_deref(), Some("deep"));

        let unmapped = Settings::from_parts(PartialConfig::default(), PartialConfig::default());
        assert_eq!(unmapped.agent_settings(SourceClass::Aur).variant, None);
    }

    #[test]
    fn store_settings_take_the_user_file_first() {
        let system = PartialConfig {
            agent: AgentDefaults {
                cache_days: Some(10),
                max_store_mib: Some(512),
                ..AgentDefaults::default()
            },
            ..PartialConfig::default()
        };
        let user = PartialConfig {
            agent: AgentDefaults {
                cache_days: Some(0),
                max_chunks: Some(3),
                ..AgentDefaults::default()
            },
            ..PartialConfig::default()
        };
        let settings = Settings::from_parts(system, user);

        assert_eq!(
            settings.store_settings(),
            StoreSettings {
                cache_days: 0,
                max_store_mib: 512
            }
        );
        assert_eq!(settings.agent_settings(SourceClass::Aur).max_chunks, 3);
        // Pacman classes take agent defaults from the system file only.
        assert_eq!(settings.agent_settings(SourceClass::Official).max_chunks, 8);

        let defaults = Settings::from_parts(PartialConfig::default(), PartialConfig::default());
        assert_eq!(
            defaults.store_settings(),
            StoreSettings {
                cache_days: 30,
                max_store_mib: 256
            }
        );
    }

    #[test]
    fn profile_override_applies_to_user_level_classes_only() {
        let settings = Settings::from_parts(PartialConfig::default(), PartialConfig::default())
            .with_profile(Profile::LocalOnly);
        assert_eq!(settings.policy(SourceClass::Source).ai, AiRequirement::Off);
        assert_eq!(
            settings.policy(SourceClass::Official).ai,
            AiRequirement::Optional
        );
        assert_eq!(
            settings.profile_for(SourceClass::Source),
            Profile::LocalOnly
        );
        assert_eq!(
            settings.profile_for(SourceClass::Official),
            Profile::Standard
        );
    }

    #[test]
    fn official_repos_default_and_override() {
        let settings = Settings::from_parts(PartialConfig::default(), PartialConfig::default());
        assert!(settings.official_repos().contains(&"omarchy".to_string()));

        let custom = PartialConfig {
            official_repos: Some(vec!["core".into()]),
            ..PartialConfig::default()
        };
        let user = PartialConfig {
            official_repos: Some(vec!["evil".into()]),
            ..PartialConfig::default()
        };
        assert_eq!(
            Settings::from_parts(custom, user).official_repos(),
            ["core"]
        );
    }
}
