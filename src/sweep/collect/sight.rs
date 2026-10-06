//! What the collector may look at: as root, a path a user chose is seen
//! only as that user could see it, so nothing is told of a file they
//! cannot read.

use std::fs;
use std::os::fd::AsRawFd as _;
use std::os::unix::fs::MetadataExt;
use std::path::Path;

use super::{Body, COMPARED, Item, NOT_LOOKED_AT, Origin, Scope, item_of};
use crate::autorun::Category;
use crate::sweep::read::{self, Found, View};

/// Why root did not look at a path nobody chose.
const NOT_REACHED: &str = "gone, or behind a link that is not root's alone: not looked at";

/// Whether a user decides what `run_by` names: it is not a file that is
/// root's alone to write. What a live check reached (no `run_by`) comes
/// from a process, which any user can start with the arguments and
/// environment they like.
pub(super) fn user_steered(root: &Path, run_by: Option<&str>) -> bool {
    run_by.is_none_or(|by| {
        // A spool holds what users handed in (their crontabs), whoever
        // the files belong to.
        if by.starts_with("var/spool/") {
            return true;
        }
        // Root's own file in a directory somebody else may write can be
        // exchanged for theirs between two looks: it counts only where the
        // whole way to it is root's alone.
        let Some(read::Seen {
            what: read::Public::File(file),
            kept: true,
            ..
        }) = read::seen(root, by, View::Pinned)
        else {
            return true;
        };
        !file
            .metadata()
            .is_ok_and(|metadata| metadata.uid() == 0 && metadata.mode() & 0o022 == 0)
    })
}

/// How root looks at what `run_by` (or, without one, a process) names
/// (`None`: not root, who sees no more through a path than its user does
/// anyway). A path a user can choose (a line of their crontab, where a
/// link leads, an `LD_PRELOAD` value, a script argument) is looked at as
/// the user could look at it: otherwise its hash, its kind, where a link
/// leads and whether it exists at all would tell them about a file they
/// cannot read. And root never goes by the path alone: a user who owns a
/// directory on the way can swap it for a link elsewhere at any moment.
pub(super) fn view(scope: &Scope<'_>, run_by: Option<&str>) -> Option<View> {
    (scope.origin == Origin::Root).then(|| {
        if user_steered(scope.root, run_by) {
            View::Everyone
        } else {
            View::Trusted
        }
    })
}

/// Whether there is something at `path` that `run_by` may lead the
/// collector to.
/// A directory is not: a command that names one (`find /etc/x`) does not
/// run it.
pub(super) fn is_there(scope: &Scope<'_>, path: &str, run_by: Option<&str>) -> bool {
    match view(scope, run_by) {
        Some(view) => read::seen(scope.root, path, view)
            .is_some_and(|seen| !matches!(seen.what, read::Public::Directory(_))),
        // A link is there, as in the pinned view; where it leads is
        // looked at when it is followed.
        None => {
            fs::symlink_metadata(scope.root.join(path)).is_ok_and(|metadata| !metadata.is_dir())
        }
    }
}

/// Whether there is a regular file at `path` that `run_by` may lead the
/// collector to (a link to one counts, as for `Path::is_file`, unless root
/// looks).
pub(crate) fn is_file_there(scope: &Scope<'_>, path: &str, run_by: Option<&str>) -> bool {
    match view(scope, run_by) {
        Some(view) => matches!(
            read::seen(scope.root, path, view).map(|seen| seen.what),
            Some(read::Public::File(_))
        ),
        None => scope.root.join(path).is_file(),
    }
}

/// Whether anything at all (a directory too) is called `name` in
/// `directory`, which `run_by` (or, without one, a process) named. `None`
/// where root would have to look into a directory not everyone may enter:
/// whether a name is in there is not root's to tell whoever chose the
/// directory. Anyone who may enter a directory may ask that of it.
pub(crate) fn holds(
    scope: &Scope<'_>,
    directory: &str,
    name: &str,
    run_by: Option<&str>,
) -> Option<bool> {
    let Some(view) = view(scope, run_by) else {
        return Some(fs::symlink_metadata(scope.root.join(directory).join(name)).is_ok());
    };
    match read::seen(scope.root, directory, view)?.what {
        read::Public::Directory(handle) => Some(
            fs::symlink_metadata(format!("/proc/self/fd/{}/{name}", handle.as_raw_fd())).is_ok(),
        ),
        _ => None,
    }
}

/// Whether `path` is a regular file or a link that leads to one, as
/// `run_by` may lead the collector to it. (Root's look does not follow a
/// link by itself, so the chain is walked hop by hop.)
pub(super) fn names_a_file(scope: &Scope<'_>, path: &str, run_by: Option<&str>) -> bool {
    if is_file_there(scope, path, run_by) {
        return true;
    }
    let Some(Some(link)) = hop(scope, path) else {
        return false;
    };
    read::resolve_where(path, &link, &|next| hop(scope, next))
        .is_some_and(|resolved| matches!(look_past_link(scope, &resolved), Found::File { .. }))
}

/// How the collector sees the hops of a link chain. As root, a link leads
/// where its owner says, so every hop is seen as everyone sees it.
pub(super) fn hop(scope: &Scope<'_>, path: &str) -> read::Hop {
    if scope.origin == Origin::Root {
        read::public_hop(scope.root, path)
    } else {
        read::plain_hop(scope.root, path)
    }
}

/// `read::look` at where a link led.
pub(super) fn look_past_link(scope: &Scope<'_>, path: &str) -> Found {
    if scope.origin == Origin::Root {
        read::look_as(scope.root, path, View::Everyone)
            .unwrap_or_else(|| Found::Unreadable(NOT_LOOKED_AT.into()))
    } else {
        read::look(scope.root, path)
    }
}

/// `read::look` at an item. What a process names (a script argument, an
/// `LD_PRELOAD` value) or a file led to is seen as `view` has it; the
/// auto-run locations' own files, and the set-id and kernel-module checks'
/// (which find their files themselves, so nobody chose those), as root
/// sees them.
pub(crate) fn look(
    scope: &Scope<'_>,
    category: Category,
    path: &str,
    run_by: Option<&str>,
) -> Found {
    if scope.origin != Origin::Root {
        return read::look(scope.root, path);
    }
    let named = run_by.is_some()
        || matches!(
            category,
            Category::Process | Category::Listener | Category::Input | Category::Camera
        );
    let (view, unseen) = if named && user_steered(scope.root, run_by) {
        (View::Everyone, NOT_LOOKED_AT)
    } else if named {
        (View::Trusted, NOT_LOOKED_AT)
    } else {
        (View::Pinned, NOT_REACHED)
    };
    read::look_as(scope.root, path, view).unwrap_or_else(|| Found::Unreadable(unseen.into()))
}

/// The item of a packaged file that a process led the root collector to
/// and that not everyone may read (a running program's `exe`, a preloaded
/// library), for the one question the live checks ask of it: is it still
/// what its package installed?
///
/// A user decides which path this is, by running the program or naming the
/// library, so the rule for such paths applies: nothing of a file they
/// cannot read is told. Three things keep that rule here. The path must be
/// one the package index holds: the index is root's, pacman's database is
/// readable by everyone, and so is every package, so that a file is
/// installed at this path, and what it holds as installed, is already
/// public. The way to it must be root's alone, with no link followed
/// (`kept`, and the path the walk took is the path asked for), so the file
/// looked at is the one root's package manager put there and not one a
/// user moved or linked in. And what comes back is one bit: the file is as
/// its package installed it, or it is not. "It is" tells the user they
/// hold its content already (the package); "it is not" tells them a
/// packaged program was changed, which is what the sweep is for, and no
/// more than the size and time `pacman -Qkk` compares as any user. The
/// hash of a changed file is withheld: it could confirm a guess at content
/// only root may read. A package's configuration file (`backup=`), which
/// is meant to be edited and may hold secrets, never comes out as changed
/// here (see `tier::classify`), so nothing is told of those at all.
///
/// `None` where there is no such file to compare: the caller then treats
/// the path as not vouched for, unless that alone would tell (see
/// `packaged_out_of_sight`).
pub(crate) fn packaged_item(scope: &Scope<'_>, category: Category, path: &str) -> Option<Item> {
    scope.index.owner(path)?;
    let seen = read::seen(scope.root, path, View::Pinned)?;
    if !seen.kept || seen.path != path || !matches!(seen.what, read::Public::File(_)) {
        return None;
    }
    let found = read::look_pinned(seen);
    if !matches!(found, Found::File { .. }) {
        return None;
    }
    let mut item = item_of(scope, category, path.to_string(), None, &found);
    item.sha256 = None;
    item.body = Body::Binary(COMPARED);
    item.runs.clear();
    Some(item)
}

/// Whether `path`, which a process led the root collector to, is a
/// package's path inside a directory that is root's alone and that not
/// everyone may enter. Of such a path `packaged_item` answers with its one
/// bit or not at all: were "there is no regular file here" reported (as a
/// library no package vouches for), whoever named the path would learn
/// that a packaged file in a directory closed to them is missing or is
/// something else. Where everyone may enter the directory, that is theirs
/// to see anyway; where somebody else may write on the way, the file is
/// theirs and nothing of root's. A packaged file that is missing or odd is
/// for the look through the fixed directories to report, which no user
/// steers.
pub(crate) fn packaged_out_of_sight(scope: &Scope<'_>, path: &str) -> bool {
    use std::os::unix::fs::MetadataExt as _;
    if scope.index.owner(path).is_none() {
        return false;
    }
    let Some((directory, _)) = path.rsplit_once('/') else {
        return false;
    };
    let Some(read::Seen {
        path: walked,
        what: read::Public::Directory(handle),
        kept: true,
    }) = read::seen(scope.root, directory, View::Pinned)
    else {
        return false;
    };
    let owner = fs::metadata(scope.root).map(|top| top.uid()).ok();
    let roots_alone = handle
        .metadata()
        .is_ok_and(|metadata| Some(metadata.uid()) == owner && metadata.mode() & 0o022 == 0);
    walked == directory
        && roots_alone
        && read::seen(scope.root, directory, View::Everyone).is_none()
}
