//! Locating, validating and combining the two config files into `Settings`.

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
use crate::paths::{self, Accept};
use crate::user;

pub(crate) const SYSTEM_PATH: &str = "/etc/omarchy-guardian/config.toml";

const DEFAULT_OFFICIAL_REPOS: [&str; 7] = [
    "core",
    "extra",
    "multilib",
    "core-testing",
    "extra-testing",
    "multilib-testing",
    "omarchy",
];

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum FileStatus {
    Missing,
    Loaded,
    Invalid(String),
}

#[derive(Clone, Debug)]
pub(crate) struct Settings {
    system_path: PathBuf,
    user_path: Option<PathBuf>,
    system: PartialConfig,
    user: PartialConfig,
    system_status: FileStatus,
    user_status: FileStatus,
    profile_override: Option<Profile>,
    privileged_block: Option<String>,
    system_block: Option<String>,
    system_unverified: bool,
    user_block: Option<String>,
    warnings: Vec<String>,
}

/// `$XDG_CONFIG_HOME/omarchy-guardian/config.toml`, else `~/.config/...`.
pub(crate) fn user_config_path() -> Option<PathBuf> {
    let base = paths::config_home(Accept::Absolute, Accept::Absolute)?;
    Some(base.join("omarchy-guardian").join("config.toml"))
}

/// Why no user-level review runs, for what says so in its own words.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum UserBlock {
    /// The system file is there and is invalid or insecure.
    SystemFile,
    /// The system file looks like nobody's because this runs in a user
    /// namespace that does not map root: whose it is cannot be told.
    Unverified,
    /// The user file is there and does not parse.
    UserFile,
}

/// Why a system file is not root's alone.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Insecure {
    reason: String,
    /// The owner that was refused, where the owner is the reason.
    owner: Option<u32>,
}

impl Insecure {
    pub(crate) fn other(reason: String) -> Self {
        Self {
            reason,
            owner: None,
        }
    }

    /// `entry` (the file or its directory) belongs to `uid`.
    pub(crate) fn owned_by(entry: &Path, uid: u32) -> Self {
        Self {
            reason: format!("{} is owned by uid {uid}, not root", entry.display()),
            owner: Some(uid),
        }
    }

    /// `entry` (the file or its directory) can be written by more than root.
    pub(crate) fn writable(entry: &Path) -> Self {
        Self::other(format!(
            "{} is writable by group or others",
            entry.display()
        ))
    }

    /// The reason as it is said of the file at `path`, naming it once.
    pub(crate) fn said_of(&self, path: &Path) -> String {
        named(path, &self.reason_text())
    }

    fn reason_text(&self) -> String {
        format!("insecure: {}", self.reason)
    }

    /// Whether the refused owner is root as a user namespace that does not
    /// map root shows it: nothing in the file is then root's to fix.
    pub(crate) fn unverified(&self) -> bool {
        unverified_here(self.owner)
    }
}

/// `unverified` for the namespace this process runs in.
fn unverified_here(owner: Option<u32>) -> bool {
    unverified(user::root_unmapped(), owner, &|owner| {
        owner != 0 && !user::is_foreign_owner(owner, None)
    })
}

/// The system file and its directory must be root-owned regular entries
/// that only root can write.
pub(crate) fn check_root_owned(path: &Path) -> Result<(), Insecure> {
    let metadata =
        fs::symlink_metadata(path).map_err(|error| Insecure::other(error.to_string()))?;
    if !metadata.file_type().is_file() {
        return Err(Insecure::other("not a regular file".into()));
    }
    let checks = [(path, metadata)].into_iter().chain(
        path.parent()
            .and_then(|parent| fs::metadata(parent).ok().map(|meta| (parent, meta))),
    );
    for (entry, metadata) in checks {
        if metadata.uid() != 0 {
            return Err(Insecure::owned_by(entry, metadata.uid()));
        }
        if metadata.mode() & 0o022 != 0 {
            return Err(Insecure::writable(entry));
        }
    }
    Ok(())
}

enum Read {
    Missing,
    Parsed(PartialConfig),
    /// The reason, and the owner that was refused if that is the reason.
    Failed(String, Option<u32>),
}

/// A pluggable check for whether a config file is safely owned.
type Verify<'a> = dyn Fn(&Path) -> Result<(), Insecure> + 'a;

fn read(path: &Path, secure: Option<&Verify<'_>>) -> Read {
    match fs::symlink_metadata(path) {
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Read::Missing,
        Err(error) => return Read::Failed(error.to_string(), None),
        Ok(_) => {}
    }
    if let Some(secure) = secure
        && let Err(insecure) = secure(path)
    {
        return Read::Failed(insecure.reason_text(), insecure.owner);
    }
    match fs::read_to_string(path) {
        Ok(text) => match parse(path, &text) {
            Ok(config) => Read::Parsed(config),
            Err(error) => Read::Failed(error.to_string(), None),
        },
        Err(error) => Read::Failed(error.to_string(), None),
    }
}

/// `reason`, naming the file it is about once: in front, unless the reason
/// names it itself (a parse error with its line, the file's owner or mode).
fn named(path: &Path, reason: &str) -> String {
    let file = path.display().to_string();
    if reason.contains(&file) {
        reason.to_string()
    } else {
        format!("{file}: {reason}")
    }
}

/// Whether a refused owner is root seen from a user namespace that does
/// not map root (`unmapped`), where root's files show the overflow owner
/// (`nobody`). Such a file is still refused: the same owner is shown for
/// every user the namespace does not map.
fn unverified(unmapped: bool, owner: Option<u32>, nobody: &dyn Fn(u32) -> bool) -> bool {
    unmapped && owner.is_some_and(nobody)
}

/// What every command says of a system file that cannot be used, and what
/// stops the reviews for the user.
fn system_block_text(path: &Path, reason: &str, unverified: bool) -> String {
    let named = named(path, reason);
    if unverified {
        format!(
            "{named}; this is running in a user namespace that does not map root, where root's files look like nobody's: run it outside the sandbox for AUR builds, themes, plugins, scans and the sweep to be reviewed"
        )
    } else {
        format!(
            "{named}; fix it as root (`omarchy-guardian config check` shows the problem) before AUR builds, themes, plugins, scans and the sweep can be reviewed"
        )
    }
}

impl Settings {
    pub(crate) fn load() -> Self {
        Self::load_from(
            Path::new(SYSTEM_PATH),
            user_config_path().as_deref(),
            &check_root_owned,
        )
    }

    /// The root-owned system file alone, for Guardian's root halves: the
    /// user's file is not read.
    pub(crate) fn system_only() -> Self {
        Self::load_from(Path::new(SYSTEM_PATH), None, &check_root_owned)
    }

    pub(crate) fn load_from(
        system_path: &Path,
        user_path: Option<&Path>,
        secure: &Verify<'_>,
    ) -> Self {
        Self::load_in(system_path, user_path, secure, &unverified_here)
    }

    /// `load_from`, told by `unverified` whether a refused owner of the
    /// system file is root as a user namespace without root shows it.
    pub(crate) fn load_in(
        system_path: &Path,
        user_path: Option<&Path>,
        secure: &Verify<'_>,
        unverified: &dyn Fn(Option<u32>) -> bool,
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
            // Not carried on with the built-in defaults, for the pacman gate
            // or for anything else: the file may hold a stricter level or a
            // tightened class, and one typo would quietly undo it.
            Read::Failed(reason, owner) => {
                settings.privileged_block = Some(format!(
                    "{}: {reason}; fix it (see `omarchy-guardian config check`) before pacman transactions can be reviewed",
                    system_path.display()
                ));
                settings.system_unverified = unverified(owner);
                let block = system_block_text(system_path, &reason, settings.system_unverified);
                settings.warnings.push(block.clone());
                settings.system_block = Some(block);
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
                Read::Failed(reason, _) => {
                    let named = named(user_path, &reason);
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

    pub(crate) fn from_parts(system: PartialConfig, user: PartialConfig) -> Self {
        Self {
            system_path: PathBuf::from(SYSTEM_PATH),
            user_path: None,
            system,
            user,
            system_status: FileStatus::Missing,
            user_status: FileStatus::Missing,
            profile_override: None,
            privileged_block: None,
            system_block: None,
            system_unverified: false,
            user_block: None,
            warnings: Vec::new(),
        }
    }

    /// A one-run profile for user-level classes (`--profile`).
    pub(crate) fn with_profile(mut self, profile: Profile) -> Self {
        self.profile_override = Some(profile);
        self
    }

    pub(crate) fn system_profile(&self) -> Profile {
        self.system.profile.unwrap_or(Profile::Standard)
    }

    fn user_profile(&self) -> Option<Profile> {
        self.profile_override.or(self.user.profile)
    }

    /// The profile whose built-ins a class starts from.
    pub(crate) fn profile_for(&self, class: SourceClass) -> Profile {
        if class.is_privileged() {
            self.system_profile()
        } else {
            self.user_profile().unwrap_or_else(|| self.system_profile())
        }
    }

    pub(crate) fn resolve(&self, class: SourceClass) -> Resolved {
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

    pub(crate) fn policy(&self, class: SourceClass) -> Policy {
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

    pub(crate) fn agent_settings(&self, class: SourceClass) -> AgentSettings {
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
    pub(crate) fn store_settings(&self) -> StoreSettings {
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
    pub(crate) fn sweep_root(&self) -> (Option<crate::config::model::RootConsent>, Option<String>) {
        (self.system.sweep.root, self.system.sweep.group.clone())
    }

    /// Reviewer packages trusted from outside the official repositories;
    /// only the root-owned system file can name them.
    pub(crate) fn trusted_reviewer_packages(&self) -> Vec<String> {
        self.system
            .trusted_reviewer_packages
            .clone()
            .unwrap_or_default()
    }

    pub(crate) fn official_repos(&self) -> Vec<String> {
        self.system.official_repos.clone().unwrap_or_else(|| {
            DEFAULT_OFFICIAL_REPOS
                .iter()
                .map(ToString::to_string)
                .collect()
        })
    }

    pub(crate) fn privileged_block(&self) -> Option<&str> {
        self.privileged_block.as_deref()
    }

    /// Why no user-level review can run: the system file is there and is
    /// invalid or insecure, or the user file is there and does not parse.
    /// The system file's reason comes first: it is the one root has to fix.
    pub(crate) fn user_block(&self) -> Option<&str> {
        self.system_block.as_deref().or(self.user_block.as_deref())
    }

    /// Which file stops the reviews for the user, and whether it is the
    /// namespace this runs in that makes the system file unusable.
    pub(crate) fn user_block_cause(&self) -> Option<UserBlock> {
        if self.system_block.is_some() {
            Some(if self.system_unverified {
                UserBlock::Unverified
            } else {
                UserBlock::SystemFile
            })
        } else {
            self.user_block.as_ref().map(|_| UserBlock::UserFile)
        }
    }

    /// The weaker settings accepted in the root-owned system file.
    pub(crate) fn acknowledged_weaker(&self) -> &[String] {
        self.system
            .acknowledged_weaker
            .as_deref()
            .unwrap_or_default()
    }

    /// Whether a blocked install can be permitted under the strict level:
    /// only when the root-owned system file says so.
    pub(crate) fn permits_under_strict(&self) -> bool {
        self.system.permit_strict == Some(true)
    }

    /// Whether Guardian asks, once a day, for a newer release of itself:
    /// unless either file turns it off.
    pub(crate) fn checks_for_updates(&self) -> bool {
        self.system.update_check != Some(false) && self.user.update_check != Some(false)
    }

    pub(crate) fn warnings(&self) -> &[String] {
        &self.warnings
    }

    pub(crate) fn system_status(&self) -> &FileStatus {
        &self.system_status
    }

    pub(crate) fn user_status(&self) -> &FileStatus {
        &self.user_status
    }

    /// The values set in the system file, as parsed.
    pub(crate) fn system_config(&self) -> &PartialConfig {
        &self.system
    }

    /// The values set in the user file, as parsed.
    pub(crate) fn user_config(&self) -> &PartialConfig {
        &self.user
    }

    pub(crate) fn system_path(&self) -> &Path {
        &self.system_path
    }

    pub(crate) fn user_path(&self) -> Option<&Path> {
        self.user_path.as_deref()
    }
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::path::Path;

    use super::{
        FileStatus, Insecure, Settings, UserBlock, check_root_owned, system_block_text, unverified,
    };
    use crate::config::file::{AgentDefaults, PartialConfig, PartialPolicy};
    use crate::config::model::{
        AiRequirement, Profile, RootConsent, SourceClass, StoreSettings, Thinking,
    };
    use crate::test_support::TempDir;

    #[expect(
        clippy::unnecessary_wraps,
        reason = "must match the `Verify` callback signature `Settings::load_from` expects"
    )]
    fn secure(_: &Path) -> Result<(), Insecure> {
        Ok(())
    }

    /// What the real check says of a file that is a user's.
    fn insecure(path: &Path) -> Result<(), Insecure> {
        Err(Insecure::owned_by(path, 1000))
    }

    const FIX: &str = "; fix it as root (`omarchy-guardian config check` shows the problem) before AUR builds, themes, plugins, scans and the sweep can be reviewed";

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

        let file = system.display().to_string();
        let settings = Settings::load_from(&system, None, &insecure);
        // The pacman gate's own words, as they were.
        assert_eq!(
            settings.privileged_block(),
            Some(
                format!(
                    "{file}: insecure: {file} is owned by uid 1000, not root; fix it (see `omarchy-guardian config check`) before pacman transactions can be reviewed"
                )
                .as_str()
            )
        );
        assert!(matches!(settings.system_status(), FileStatus::Invalid(_)));
        // User-level classes are not reviewed at the built-in standard
        // profile instead: they are blocked too.
        let block = settings.user_block().unwrap();
        assert_eq!(settings.system_block.as_deref(), Some(block));
        assert_eq!(settings.user_block_cause(), Some(UserBlock::SystemFile));
        assert_eq!(settings.warnings(), [block.to_string()]);

        fs::write(&system, "profile = \"bogus\"\n").unwrap();
        let settings = Settings::load_from(&system, None, &secure);
        let privileged = settings.privileged_block().unwrap();
        assert!(privileged.contains("config check"), "{privileged}");
        assert!(
            privileged.ends_with("before pacman transactions can be reviewed"),
            "{privileged}"
        );
    }

    #[test]
    fn the_block_names_the_system_file_once_whatever_the_reason() {
        let dir = TempDir::new("settings-named");
        let system = dir.path().join("system.toml");
        let file = system.display().to_string();
        let folder = dir.path().display().to_string();
        fs::write(&system, "profile = \"strict\"\n").unwrap();
        let said = |secure: &dyn Fn(&Path) -> Result<(), Insecure>| {
            let settings = Settings::load_from(&system, None, secure);
            settings.user_block().unwrap().to_string()
        };

        // The file's owner and mode, as the real check words them.
        assert_eq!(
            said(&|path| Err(Insecure::owned_by(path, 1000))),
            format!("insecure: {file} is owned by uid 1000, not root{FIX}")
        );
        assert_eq!(
            said(&|path| Err(Insecure::writable(path))),
            format!("insecure: {file} is writable by group or others{FIX}")
        );
        // Its directory's: the file, then what is wrong with the directory.
        assert_eq!(
            said(&|path| Err(Insecure::owned_by(path.parent().unwrap(), 1000))),
            format!("{file}: insecure: {folder} is owned by uid 1000, not root{FIX}")
        );
        assert_eq!(
            said(&|path| Err(Insecure::writable(path.parent().unwrap()))),
            format!("{file}: insecure: {folder} is writable by group or others{FIX}")
        );
        assert_eq!(
            said(&|_| Err(Insecure::other("not a regular file".into()))),
            format!("{file}: insecure: not a regular file{FIX}")
        );

        // A parse error names the file with its line.
        fs::write(&system, "profile = \"bogus\"\n").unwrap();
        let block = said(&secure);
        assert!(
            block.starts_with(&format!("{file}:1: profile: ")),
            "{block}"
        );
        assert!(block.ends_with(FIX), "{block}");
        assert_eq!(block.matches(file.as_str()).count(), 1, "{block}");

        // It cannot be read: a directory in its place.
        fs::remove_file(&system).unwrap();
        fs::create_dir(&system).unwrap();
        let block = said(&secure);
        assert!(block.starts_with(&format!("{file}: ")), "{block}");
        assert!(block.ends_with(FIX), "{block}");
        assert_eq!(block.matches(file.as_str()).count(), 1, "{block}");
    }

    #[test]
    fn a_namespace_without_root_is_named_instead_of_a_fix_as_root() {
        let nobody = |owner: u32| owner == 65_534;
        assert!(unverified(true, Some(65_534), &nobody));
        // A user's file, another reason, or a namespace with root in it.
        assert!(!unverified(true, Some(1000), &nobody));
        assert!(!unverified(true, None, &nobody));
        assert!(!unverified(false, Some(65_534), &nobody));

        let path = Path::new("/etc/omarchy-guardian/config.toml");
        let reason = "insecure: /etc/omarchy-guardian/config.toml is owned by uid 65534, not root";
        assert_eq!(
            system_block_text(path, reason, true),
            "insecure: /etc/omarchy-guardian/config.toml is owned by uid 65534, not root; this is running in a user namespace that does not map root, where root's files look like nobody's: run it outside the sandbox for AUR builds, themes, plugins, scans and the sweep to be reviewed"
        );
        assert_eq!(
            system_block_text(path, reason, false),
            format!("{reason}{FIX}")
        );

        // Still refused, for both gates, and said to be the namespace's.
        let dir = TempDir::new("settings-namespace");
        let system = dir.path().join("system.toml");
        fs::write(&system, "profile = \"strict\"\n").unwrap();
        let overflow = |path: &Path| Err(Insecure::owned_by(path, 65_534));
        let settings = Settings::load_in(&system, None, &overflow, &|owner| {
            unverified(true, owner, &nobody)
        });
        assert_eq!(settings.user_block_cause(), Some(UserBlock::Unverified));
        assert!(matches!(settings.system_status(), FileStatus::Invalid(_)));
        assert!(
            settings
                .privileged_block()
                .unwrap()
                .ends_with("before pacman transactions can be reviewed")
        );
        let block = settings.user_block().unwrap();
        assert!(block.contains("run it outside the sandbox"), "{block}");
        assert!(!block.contains("as root"), "{block}");
        // The same owner where root is mapped is somebody else's file.
        let mapped = Settings::load_in(&system, None, &overflow, &|owner| {
            unverified(false, owner, &nobody)
        });
        assert_eq!(mapped.user_block_cause(), Some(UserBlock::SystemFile));
        assert!(mapped.user_block().unwrap().ends_with(FIX));
    }

    #[test]
    fn a_broken_system_file_blocks_user_level_reviews_whatever_the_user_file_says() {
        let dir = TempDir::new("settings-system-block");
        let system = dir.path().join("system.toml");
        let user = dir.path().join("user.toml");
        // A stricter level, a tightened class and one typo.
        fs::write(
            &system,
            "profile = \"strict\"\n[class.aur]\nai = \"sometimes\"\n",
        )
        .unwrap();
        fs::write(&user, "profile = \"standard\"\n").unwrap();

        let settings = Settings::load_from(&system, Some(&user), &secure);
        let block = settings.user_block().unwrap();
        assert!(
            block.contains(&format!("{}:3:", system.display())),
            "{block}"
        );
        assert_eq!(settings.system_block.as_deref(), Some(block));
        assert_eq!(settings.user_status(), &FileStatus::Loaded);
        assert_eq!(settings.user_block_cause(), Some(UserBlock::SystemFile));

        // Both broken: both are said, the system file's first.
        fs::write(&user, "profile = \"strict\n").unwrap();
        let both = Settings::load_from(&system, Some(&user), &secure);
        assert_eq!(both.warnings().len(), 2);
        assert!(both.user_block().unwrap().contains("as root"));
        assert!(both.warnings()[1].contains(&user.display().to_string()));

        // Not there: the built-in defaults, and nothing blocked by it.
        let missing = Settings::load_from(&dir.path().join("none.toml"), Some(&user), &secure);
        assert_eq!(missing.system_status(), &FileStatus::Missing);
        assert_eq!(missing.system_block.as_deref(), None);
        assert_eq!(missing.privileged_block(), None);
        assert!(missing.user_block().unwrap().contains("user.toml"));
        assert_eq!(missing.user_block_cause(), Some(UserBlock::UserFile));

        // Valid: in force, and nothing blocked.
        fs::write(&system, "profile = \"strict\"\n").unwrap();
        fs::write(&user, "").unwrap();
        let valid = Settings::load_from(&system, Some(&user), &secure);
        assert_eq!(valid.user_block(), None);
        assert_eq!(valid.system_block.as_deref(), None);
        assert_eq!(valid.user_block_cause(), None);
        assert_eq!(valid.privileged_block(), None);
        assert!(valid.warnings().is_empty());
        assert_eq!(valid.profile_for(SourceClass::Aur), Profile::Strict);
    }

    #[test]
    fn a_system_file_that_is_not_roots_alone_blocks_user_level_reviews() {
        use std::os::unix::fs::PermissionsExt;

        // The real ownership check. As a user the file is not root's; as
        // root it is, and writable by everyone: refused either way.
        let dir = TempDir::new("settings-system-owner");
        let system = dir.path().join("system.toml");
        fs::write(&system, "profile = \"strict\"\n").unwrap();
        fs::set_permissions(&system, fs::Permissions::from_mode(0o666)).unwrap();

        let settings = Settings::load_from(&system, None, &check_root_owned);
        let FileStatus::Invalid(reason) = settings.system_status() else {
            panic!("an insecure system file was loaded");
        };
        assert!(reason.starts_with("insecure: "), "{reason}");
        assert!(
            reason.contains("not root") || reason.contains("writable by group or others"),
            "{reason}"
        );
        let block = settings.user_block().unwrap();
        assert!(block.contains(reason.as_str()), "{block}");
        assert!(
            settings
                .privileged_block()
                .unwrap()
                .contains(reason.as_str())
        );
        // Its level is not in force, and nothing says it is.
        assert_eq!(settings.system_profile(), Profile::Standard);
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
