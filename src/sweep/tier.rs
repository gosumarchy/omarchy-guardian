//! How far an installed file can be trusted, from what pacman recorded.

use super::index::{PackageIndex, Recorded};
use crate::sha256::Digest;

/// From most to least trusted. The sweep hides the first two.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Tier {
    /// What a package from a configured repository installed, unchanged.
    Vendor,
    /// Does nothing: a link to `/dev/null` (a masked unit) or an empty file.
    Inert,
    /// Not installed as this file, but identical to a file a repository
    /// package ships (Omarchy copies its `etc-overrides` into `/etc`).
    Copied,
    /// What a package from no configured repository (AUR, `pacman -U`)
    /// installed, unchanged.
    UserBuilt,
    /// A package's configuration file (`backup=`) that was edited, as such
    /// files are meant to be.
    Edited,
    /// A package's file whose content, mode or link target is not what the
    /// package installed.
    Modified,
    /// No package installed it.
    Unknown,
}

impl Tier {
    pub const ALL: [Self; 7] = [
        Self::Vendor,
        Self::Inert,
        Self::Copied,
        Self::UserBuilt,
        Self::Edited,
        Self::Modified,
        Self::Unknown,
    ];

    /// A stable machine name.
    pub const fn name(self) -> &'static str {
        match self {
            Self::Vendor => "package",
            Self::Inert => "inert",
            Self::Copied => "copy",
            Self::UserBuilt => "user-built",
            Self::Edited => "edited",
            Self::Modified => "modified",
            Self::Unknown => "unknown",
        }
    }

    pub fn from_name(name: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|tier| tier.name() == name)
    }
}

/// What is on disk at a path.
#[derive(Clone, Copy, Debug)]
pub enum Observed<'a> {
    File {
        sha256: &'a Digest,
        /// Permission bits including set-id bits.
        mode: u32,
        size: u64,
    },
    Link {
        target: &'a str,
        /// The tier of what the link points at, when it resolves to a file
        /// the sweep classified (an enabled unit's link to its unit).
        resolved: Option<Tier>,
    },
}

/// The tier of `path` (relative to `/`).
pub fn classify(path: &str, observed: Observed<'_>, index: &PackageIndex) -> Tier {
    let packaged = |index: &PackageIndex, package: &str| {
        if index.is_foreign(package) {
            Tier::UserBuilt
        } else {
            Tier::Vendor
        }
    };
    if let Some(owned) = index.owner(path) {
        let package = index.package(owned);
        let unchanged = match (&owned.recorded, observed) {
            (
                Recorded::File {
                    mode,
                    sha256: Some(recorded),
                },
                Observed::File {
                    sha256,
                    mode: actual,
                    ..
                },
            ) => recorded == sha256 && *mode == actual & 0o7777,
            (Recorded::Link(recorded), Observed::Link { target, .. }) => recorded == target,
            _ => false,
        };
        return match observed {
            _ if unchanged => packaged(index, package),
            Observed::File { sha256, .. } if owned.backup => {
                if index.copy_of(sha256).is_some() {
                    Tier::Copied
                } else {
                    Tier::Edited
                }
            }
            Observed::File { .. } | Observed::Link { .. } => Tier::Modified,
        };
    }
    match observed {
        Observed::File { size: 0, .. }
        | Observed::Link {
            target: "/dev/null",
            ..
        } => Tier::Inert,
        // A link no package made (`systemctl enable`) to a packaged file is
        // as trusted as that file.
        Observed::Link {
            resolved: Some(tier @ (Tier::Vendor | Tier::UserBuilt | Tier::Inert)),
            ..
        } => tier,
        Observed::File { sha256, .. } if index.copy_of(sha256).is_some() => Tier::Copied,
        Observed::File { .. } | Observed::Link { .. } => Tier::Unknown,
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashSet;

    use super::{Observed, Tier, classify};
    use crate::sha256::Sha256;
    use crate::sweep::index::PackageIndex;

    fn index() -> PackageIndex {
        let abc = Sha256::digest(b"abc");
        let copy = Sha256::digest(b"override");
        let mtree = format!(
            "#mtree\n/set type=file mode=644\n./usr/bin/demo mode=755 sha256digest={abc}\n./usr/bin/su mode=4755 sha256digest={abc}\n./usr/lib/x.so type=link link=x.so.1\n./etc/demo.conf sha256digest={abc}\n./usr/share/demo/override.conf sha256digest={copy}\n"
        );
        let mut index = PackageIndex::with_foreign(HashSet::from(["aur-thing".to_string()]));
        index.add_for_test("demo", &mtree, &["etc/demo.conf"]);
        index.add_for_test(
            "aur-thing",
            &format!("#mtree\n./usr/bin/aur mode=755 type=file sha256digest={abc}\n"),
            &[],
        );
        index
    }

    #[test]
    fn package_files_are_trusted_only_while_unchanged() {
        let index = index();
        let abc = Sha256::digest(b"abc");
        let other = Sha256::digest(b"other");
        let file = |sha256, mode| Observed::File {
            sha256,
            mode,
            size: 3,
        };
        assert_eq!(
            classify("usr/bin/demo", file(&abc, 0o100_755), &index),
            Tier::Vendor
        );
        assert_eq!(
            classify("usr/bin/demo", file(&other, 0o755), &index),
            Tier::Modified
        );
        // A set-id bit added or removed is a change.
        assert_eq!(
            classify("usr/bin/demo", file(&abc, 0o4755), &index),
            Tier::Modified
        );
        assert_eq!(
            classify("usr/bin/su", file(&abc, 0o4755), &index),
            Tier::Vendor
        );
        assert_eq!(
            classify("usr/bin/aur", file(&abc, 0o755), &index),
            Tier::UserBuilt
        );
        assert_eq!(
            classify("usr/bin/new", file(&other, 0o755), &index),
            Tier::Unknown
        );
        // The same content as a packaged file, somewhere else: a copy.
        assert_eq!(
            classify("usr/bin/new", file(&abc, 0o755), &index),
            Tier::Copied
        );
        // A file replaced by a link is a change.
        let link = Observed::Link {
            target: "/tmp/x",
            resolved: None,
        };
        assert_eq!(classify("usr/bin/demo", link, &index), Tier::Modified);
        let same = Observed::Link {
            target: "x.so.1",
            resolved: None,
        };
        assert_eq!(classify("usr/lib/x.so", same, &index), Tier::Vendor);
    }

    #[test]
    fn edited_configuration_and_packaged_copies_are_told_apart() {
        let index = index();
        let file = |sha256| Observed::File {
            sha256,
            mode: 0o644,
            size: 8,
        };
        let edited = Sha256::digest(b"edited");
        let copy = Sha256::digest(b"override");
        assert_eq!(
            classify("etc/demo.conf", file(&edited), &index),
            Tier::Edited
        );
        assert_eq!(classify("etc/demo.conf", file(&copy), &index), Tier::Copied);
        assert_eq!(
            classify("etc/other.conf", file(&copy), &index),
            Tier::Copied
        );
        // A changed file that is not configuration is still a modification.
        assert_eq!(
            classify(
                "usr/bin/demo",
                Observed::File {
                    sha256: &edited,
                    mode: 0o755,
                    size: 6
                },
                &index
            ),
            Tier::Modified
        );
    }

    #[test]
    fn masks_and_enable_links_take_their_targets_trust() {
        let index = index();
        let link = |target, resolved| Observed::Link { target, resolved };
        let path = "etc/systemd/system/multi-user.target.wants/demo.service";
        assert_eq!(classify(path, link("/dev/null", None), &index), Tier::Inert);
        assert_eq!(
            classify(
                path,
                link("/usr/lib/systemd/system/demo.service", Some(Tier::Vendor)),
                &index
            ),
            Tier::Vendor
        );
        assert_eq!(
            classify(
                path,
                link("/home/u/.x.service", Some(Tier::Unknown)),
                &index
            ),
            Tier::Unknown
        );
        assert_eq!(classify(path, link("/gone", None), &index), Tier::Unknown);
        let empty = Sha256::digest(b"");
        assert_eq!(
            classify(
                "etc/profile.d/empty.sh",
                Observed::File {
                    sha256: &empty,
                    mode: 0o644,
                    size: 0
                },
                &index
            ),
            Tier::Inert
        );
    }
}
