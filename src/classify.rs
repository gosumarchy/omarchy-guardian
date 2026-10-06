//! Which source class a pacman sync package belongs to (spec §8).

use std::ffi::OsString;
use std::path::Path;

use crate::config::model::SourceClass;
use crate::error::Error;
use crate::tools::{self, Limits};

/// `SigLevel` options under which a package can install without a valid
/// signature.
const UNSIGNED: &[&str] = &[
    "Never",
    "Optional",
    "PackageNever",
    "PackageOptional",
    "PackageTrustAll",
];

const LIMITS: Limits = Limits {
    timeout_secs: 30,
    max_output: 64 * 1024,
};

pub(crate) fn requires_signatures(siglevel: &str) -> bool {
    !siglevel
        .split(|character: char| character.is_whitespace() || character == '=')
        .any(|token| UNSIGNED.contains(&token))
}

pub(crate) fn repo_class(
    repo: &str,
    official_repos: &[String],
    signatures_required: bool,
) -> SourceClass {
    if signatures_required && official_repos.iter().any(|official| official == repo) {
        SourceClass::Official
    } else {
        SourceClass::ThirdPartyRepo
    }
}

/// A package offered by several repositories is only official if every
/// candidate is; no candidates at all is treated as third-party.
pub(crate) fn strictest(classes: impl IntoIterator<Item = SourceClass>) -> SourceClass {
    let mut classes = classes.into_iter().peekable();
    if classes.peek().is_none() {
        return SourceClass::ThirdPartyRepo;
    }
    if classes.all(|class| class == SourceClass::Official) {
        SourceClass::Official
    } else {
        SourceClass::ThirdPartyRepo
    }
}

/// The effective `SigLevel` of a repository, falling back to the global one
/// when the repository does not set its own.
pub(crate) fn siglevel(repo: &str) -> Result<String, Error> {
    let query = |args: Vec<OsString>| -> Result<String, Error> {
        let output = tools::run(
            Path::new(tools::PACMAN_CONF),
            &args,
            None,
            &[("LC_ALL", "C")],
            LIMITS,
        )?
        .into_success()?;
        Ok(String::from_utf8_lossy(&output).trim().to_string())
    };

    let own = query(vec![format!("--repo={repo}").into(), "SigLevel".into()])?;
    if own.is_empty() {
        query(vec!["SigLevel".into()])
    } else {
        Ok(own)
    }
}

#[cfg(test)]
mod tests {
    use super::{repo_class, requires_signatures, strictest};
    use crate::config::model::SourceClass;

    #[test]
    fn signature_requirements_are_read_from_siglevel() {
        assert!(requires_signatures("Required DatabaseOptional"));
        assert!(requires_signatures("Required\nDatabaseOptional\n"));
        assert!(requires_signatures("PackageRequired TrustedOnly"));
        assert!(!requires_signatures("Never"));
        assert!(!requires_signatures("Optional TrustAll"));
        assert!(!requires_signatures("PackageOptional"));
        assert!(!requires_signatures("Required PackageTrustAll"));
        assert!(!requires_signatures("PackageNever"));
    }

    #[test]
    fn only_listed_signed_repos_are_official() {
        let official = vec!["core".to_string(), "extra".to_string()];
        assert_eq!(repo_class("core", &official, true), SourceClass::Official);
        assert_eq!(
            repo_class("core", &official, false),
            SourceClass::ThirdPartyRepo
        );
        assert_eq!(
            repo_class("chaotic-aur", &official, true),
            SourceClass::ThirdPartyRepo
        );
    }

    #[test]
    fn any_third_party_candidate_makes_the_target_third_party() {
        assert_eq!(strictest([SourceClass::Official]), SourceClass::Official);
        assert_eq!(
            strictest([SourceClass::Official, SourceClass::ThirdPartyRepo]),
            SourceClass::ThirdPartyRepo
        );
        assert_eq!(strictest([]), SourceClass::ThirdPartyRepo);
    }
}
