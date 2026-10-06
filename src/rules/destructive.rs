//! Destructive system operations: formatting a filesystem, writing onto a
//! device, removing the root or home directory.

use super::shell::{program_name, unquoted, unquoted_words};
use super::{contains_any, shell};

const DESTRUCTIVE_COMMANDS: &[&str] = &[
    "shred /dev/",
    "dd if=/dev/zero of=/dev/",
    "dd if=/dev/urandom of=/dev/",
    "--no-preserve-root",
    "wipefs -a",
    "wipefs --all",
    "blkdiscard /dev/",
    "find / -delete",
    "cryptsetup luksformat",
    "cryptsetup erase",
    "cryptsetup lukserase",
    "sgdisk --zap-all",
    "sgdisk -z",
];

pub(super) fn is_destructive_operation(line: &str) -> bool {
    contains_any(line, DESTRUCTIVE_COMMANDS)
        || writes_a_device(line)
        || redirects_onto_device(line)
        || relabels_partition_table(line)
        || formats_filesystem(line)
        || removes_root_or_home(line)
}

/// Raw block devices, by the prefix their names share. A redirection onto
/// one overwrites the disk: `: > /dev/sda`, `cat x > /dev/nvme0n1`.
const BLOCK_DEVICES: &[&str] = &[
    "/dev/sd",
    "/dev/nvme",
    "/dev/vd",
    "/dev/hd",
    "/dev/mmcblk",
    "/dev/loop",
    "/dev/xvd",
];

/// A `>`/`>>` onto a whole block device.
fn redirects_onto_device(line: &str) -> bool {
    unquoted_words(line)
        .into_iter()
        .filter_map(|word| {
            word.strip_prefix(">>")
                .or_else(|| word.strip_prefix('>'))
                .map(ToString::to_string)
        })
        .chain(
            // `> /dev/sda` with a space: the device is the next word.
            line.split('>')
                .skip(1)
                .filter_map(|rest| rest.split_whitespace().next().map(unquoted)),
        )
        .any(|target| {
            BLOCK_DEVICES.iter().any(|device| {
                target
                    .strip_prefix(device)
                    .is_some_and(|rest| rest.chars().all(|c| c.is_ascii_alphanumeric()))
            })
        })
}

/// `parted … mklabel` / `mktable`, which replaces a disk's partition table.
fn relabels_partition_table(line: &str) -> bool {
    shell::statements(line).iter().any(|statement| {
        shell::command(statement).is_some_and(|command| {
            command.program == "parted"
                && command
                    .arguments
                    .iter()
                    .any(|word| matches!(word.as_str(), "mklabel" | "mktable"))
        })
    })
}

/// `dd` writing to a block device, in either argument order.
fn writes_a_device(line: &str) -> bool {
    let words = unquoted_words(line);
    words
        .iter()
        .any(|word| word == "dd" || word.ends_with("/dd"))
        && words.iter().any(|word| {
            word.strip_prefix("of=/dev/").is_some_and(|device| {
                !matches!(device, "null" | "stdout" | "stderr" | "zero")
                    && !device.starts_with("fd/")
                    && !device.starts_with("shm/")
            })
        })
}

/// Commands that only handle a file by name, so a `mkfs.*` argument is a
/// program being packaged or inspected rather than run.
const FILE_COMMANDS: &[&str] = &[
    "install",
    "cp",
    "mv",
    "ln",
    "chmod",
    "chown",
    "rm",
    "strip",
    "patchelf",
    "touch",
    "ls",
    "stat",
    "file",
    "test",
    "[",
    "sha256sum",
    "b2sum",
    "md5sum",
];

/// A `mkfs.*` program that is run. Packaging one (`install -Dm755
/// mkfs.erofs "$pkgdir/..."`, or its path alone on a continuation line) is
/// not; every other mention is, including inside another language's string.
pub(super) fn formats_filesystem(line: &str) -> bool {
    if !line.contains("mkfs.") {
        return false;
    }
    line.split([';', '|', '&'])
        .filter(|segment| segment.contains("mkfs."))
        .any(|segment| {
            // A path alone, as on a continuation line, runs nothing.
            if segment
                .split_whitespace()
                .filter(|word| *word != "\\")
                .count()
                <= 1
            {
                return false;
            }
            let words = unquoted_words(segment);
            let mut rest = words.iter().map(String::as_str);
            let handles_file = shell::program_word(&mut rest)
                .is_some_and(|program| FILE_COMMANDS.contains(&program_name(program)));
            // What stands before the program may run one itself:
            // `X="$(mkfs.ext4 /dev/sda)" ls`.
            let before = &words[..words.len() - rest.len()];
            // The word a wrapper's option takes may read as a file
            // command (`env -u install mkfs.ext4 …`): after an option,
            // the program found is not taken for one.
            let after_option = before
                .len()
                .checked_sub(2)
                .and_then(|index| before.get(index))
                .is_some_and(|word| word.starts_with('-') && !word.contains('=') && word != "--");
            !handles_file || after_option || before.iter().any(|word| word.contains("mkfs."))
        })
}

/// Recursive `rm` of `/`, `/*`, `~` or `$HOME` itself. Removing paths below
/// them (`rm -rf /tmp/build`, `rm -rf "$pkgdir"`) is ordinary build hygiene.
pub fn removes_root_or_home(line: &str) -> bool {
    let tokens: Vec<&str> = line.split_whitespace().collect();

    tokens.iter().enumerate().any(|(index, token)| {
        let command = token.trim_start_matches(['(', '`', '{']);
        if command != "rm" && !command.ends_with("/rm") {
            return false;
        }

        let mut arguments = Vec::new();
        for argument in &tokens[index + 1..] {
            if matches!(*argument, ";" | "&&" | "||" | "|" | "&") {
                break;
            }
            arguments.push(*argument);
            if argument.ends_with([';', '&', '|']) {
                break;
            }
        }
        let recursive = arguments.iter().any(|argument| {
            *argument == "--recursive"
                || argument
                    .strip_prefix('-')
                    .is_some_and(|flags| !flags.starts_with('-') && flags.contains('r'))
        });

        recursive
            && arguments
                .iter()
                .filter(|argument| !argument.starts_with('-'))
                .any(|argument| {
                    let target = argument
                        .trim_end_matches([';', ')', '`'])
                        .trim_matches(['"', '\'']);
                    is_root_or_home(target)
                })
    })
}

fn is_root_or_home(target: &str) -> bool {
    let base = target.trim_end_matches(['/', '*']);
    (target.starts_with('/') && base.is_empty()) || matches!(base, "~" | "$home" | "${home}")
}
