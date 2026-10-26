//! Reading the parts of a PE program (what UEFI firmware loads) that the
//! comparison with packaged programs needs, as Microsoft's PE format
//! specification lays them out: the COFF header, the optional header with
//! its data directories, then the section table.
//!
//! Every reader here takes bytes an attacker may have written and returns
//! `None` for anything malformed, never panics.

/// The marker `limine enroll-config` writes the configuration's hash
/// after, as 128 hexadecimal characters. Limine ships them as `0`s.
pub(super) const ENROLL_MARKER: &[u8] = b"++CONFIG_B2SUM_SIGNATURE++";
const ENROLLED_LENGTH: usize = 128;

/// sbsign and sbctl align the certificate table to 8 bytes, padding the
/// program with zeros before it.
const MAX_PADDING: usize = 7;

/// The certificate table is the fifth data directory; each directory is
/// an address and a size of four bytes each.
const CERTIFICATE_DIRECTORY: usize = 4;
const DIRECTORY_SIZE: usize = 8;

/// The size of a section table entry.
const SECTION_SIZE: usize = 40;

/// The most sections a program read here may have (arbitrary: the Windows
/// loader's limit, which the format itself does not set; stubs and UKIs
/// have about twenty). One with more is refused, so it is not comparable
/// rather than compared on part of its table.
const MAX_SECTIONS: usize = 96;

/// A section flag: its contents can be run.
const EXECUTABLE: u32 = 0x2000_0000;

/// The sections a unified kernel image adds to the stub, all data the
/// stub reads (the UAPI group's UKI specification). `.sbat` is in the stub
/// too, and `ukify` merges the kernel's SBAT entries into it.
const UKI_SECTIONS: &[&[u8]] = &[
    b".osrel",
    b".cmdline",
    b".linux",
    b".initrd",
    b".ucode",
    b".uname",
    b".splash",
    b".dtb",
    b".dtbauto",
    b".hwids",
    b".efifw",
    b".pcrsig",
    b".pcrpkey",
    b".profile",
    b".sbat",
];

/// Where the parts of a PE header that the comparison needs lie.
#[derive(Debug)]
pub(super) struct Header {
    /// Where the program starts, as an address once loaded.
    entry: u32,
    /// The offset of the checksum field.
    checksum: usize,
    /// The offset of the data directories, and how many there are that
    /// fit in the optional header.
    directories: usize,
    directory_count: usize,
    /// The offset of the section table, and how many sections it lists.
    sections: usize,
    pub(super) count: usize,
}

impl Header {
    /// The offset of the certificate table's directory, where there is one.
    fn certificates(&self) -> Option<usize> {
        (self.directory_count > CERTIFICATE_DIRECTORY)
            .then_some(self.directories + CERTIFICATE_DIRECTORY * DIRECTORY_SIZE)
    }
}

/// One entry of the section table.
#[derive(Debug, PartialEq, Eq)]
struct Section<'a> {
    /// Without the zeros that pad it to eight bytes.
    name: &'a [u8],
    virtual_size: u32,
    raw_size: u32,
    address: u32,
    flags: u32,
    /// Where its bytes lie in the file: without the padding to the file
    /// alignment where the header says how long it really is.
    start: usize,
    length: usize,
}

fn u16_at(bytes: &[u8], at: usize) -> Option<u16> {
    let field = bytes.get(at..at.checked_add(2)?)?;
    Some(u16::from_le_bytes([field[0], field[1]]))
}

fn u32_at(bytes: &[u8], at: usize) -> Option<u32> {
    let field = bytes.get(at..at.checked_add(4)?)?;
    Some(u32::from_le_bytes([field[0], field[1], field[2], field[3]]))
}

/// The header of the PE program `bytes` starts with, if it is one.
pub(super) fn header(bytes: &[u8]) -> Option<Header> {
    if bytes.get(..2)? != b"MZ" {
        return None;
    }
    let pe = usize::try_from(u32_at(bytes, 0x3c)?).ok()?;
    if bytes.get(pe..pe.checked_add(4)?)? != b"PE\0\0" {
        return None;
    }
    // `pe` is below `bytes.len()`, at most `isize::MAX`. Every offset below
    // adds at most 24 + 65,535 (the largest optional header) + 96 × 40 (the
    // largest section table) to it, which stays below `usize::MAX` on
    // every target, 32-bit ones included.
    let count = usize::from(u16_at(bytes, pe + 6)?);
    let optional_size = usize::from(u16_at(bytes, pe + 20)?);
    let optional = pe + 24;
    // PE32 and PE32+ differ in where the data directories start.
    let (directories, count_field) = match u16_at(bytes, optional)? {
        0x10b => (optional + 96, optional + 92),
        0x20b => (optional + 112, optional + 108),
        _ => return None,
    };
    let listed = usize::try_from(u32_at(bytes, count_field)?).ok()?;
    let room = (optional + optional_size).saturating_sub(directories) / DIRECTORY_SIZE;
    Some(Header {
        entry: u32_at(bytes, optional + 16)?,
        checksum: optional + 64,
        directories,
        directory_count: listed.min(room),
        sections: optional + optional_size,
        count,
    })
}

/// The sections of the program, or `None` where the table does not fit
/// or lists more than `MAX_SECTIONS`.
fn sections<'a>(bytes: &'a [u8], header: &Header) -> Option<Vec<Section<'a>>> {
    if header.count > MAX_SECTIONS {
        return None;
    }
    (0..header.count)
        .map(|index| {
            let entry = header.sections + index * SECTION_SIZE;
            let named = bytes.get(entry..entry + 8)?;
            let virtual_size = u32_at(bytes, entry + 8)?;
            let raw_size = u32_at(bytes, entry + 16)?;
            let length = if virtual_size > 0 {
                virtual_size.min(raw_size)
            } else {
                raw_size
            };
            Some(Section {
                name: named.split(|byte| *byte == 0).next()?,
                virtual_size,
                raw_size,
                address: u32_at(bytes, entry + 12)?,
                flags: u32_at(bytes, entry + 36)?,
                start: usize::try_from(u32_at(bytes, entry + 20)?).ok()?,
                length: usize::try_from(length).ok()?,
            })
        })
        .collect()
}

/// The bytes of the section called `name`, where it is there and its
/// bytes all lie in the file.
pub(super) fn section<'a>(bytes: &'a [u8], header: &Header, name: &[u8]) -> Option<&'a [u8]> {
    let found = sections(bytes, header)?
        .into_iter()
        .find(|section| section.name == name)?;
    bytes.get(found.start..found.start.checked_add(found.length)?)
}

/// The bytes of the PE program `bytes` with what tools change after
/// install put back as packages ship it (see `efi`'s module docs); `None`
/// for anything that is not a PE program.
pub(super) fn normalized(bytes: &[u8]) -> Option<Vec<u8>> {
    let header = header(bytes)?;
    let mut program = bytes.to_vec();
    let mut end = program.len();
    if let Some(entry) = header.certificates() {
        let offset = u32_at(bytes, entry)?;
        let size = u32_at(bytes, entry + 4)?;
        if size > 0 {
            end = end.min(usize::try_from(offset).ok()?);
        }
        program.get_mut(entry..entry + DIRECTORY_SIZE)?.fill(0);
    }
    program
        .get_mut(header.checksum..header.checksum + 4)?
        .fill(0);
    program.truncate(end);
    if let Some(at) = program
        .windows(ENROLL_MARKER.len())
        .position(|window| window == ENROLL_MARKER)
    {
        let start = at + ENROLL_MARKER.len();
        if let Some(hash) = program.get_mut(start..start + ENROLLED_LENGTH) {
            hash.fill(b'0');
        }
    }
    Some(program)
}

/// Whether `program` is `packaged`, both `normalized`: the same bytes,
/// followed by no more than the zeros that align a certificate table.
/// Everything a loader reads (the headers, which equal the package's, and
/// the sections they point at, which lie within the package's length) is
/// then the package's.
pub(super) fn is_same_program(program: &[u8], packaged: &[u8]) -> bool {
    program.len() >= packaged.len()
        && program.len() - packaged.len() <= MAX_PADDING
        && program[..packaged.len()] == *packaged
        && program[packaged.len()..].iter().all(|byte| *byte == 0)
}

/// Whether the unified kernel image `uki` was built from the packaged
/// `stub`: it starts where the stub does, its data directories are the
/// stub's (but the certificate table, which a signature changes), every
/// section of the stub is in it at the same address with the same flags
/// and bytes (`.sbat` may have grown), and every other section is one the
/// UKI format adds and cannot be run. What runs is then the stub's code;
/// the rest is data the stub reads, which the module docs say is compared
/// only for the kernel.
pub(super) fn is_built_from(uki: &[u8], stub: &[u8]) -> bool {
    built_from(uki, stub).unwrap_or(false)
}

fn built_from(uki: &[u8], stub: &[u8]) -> Option<bool> {
    let (uki_header, stub_header) = (header(uki)?, header(stub)?);
    let directories = |bytes: &'_ [u8], header: &Header| -> Option<Vec<u8>> {
        let mut all = bytes
            .get(header.directories..header.directories + header.directory_count * DIRECTORY_SIZE)?
            .to_vec();
        if let Some(entry) = header.certificates() {
            let at = entry - header.directories;
            all[at..at + DIRECTORY_SIZE].fill(0);
        }
        Some(all)
    };
    if uki_header.entry != stub_header.entry
        || directories(uki, &uki_header)? != directories(stub, &stub_header)?
    {
        return Some(false);
    }
    let (uki_sections, stub_sections) =
        (sections(uki, &uki_header)?, sections(stub, &stub_header)?);
    let bytes_of = |bytes: &'_ [u8], section: &Section<'_>| {
        bytes
            .get(section.start..section.start.checked_add(section.length)?)
            .map(<[u8]>::to_vec)
    };
    for packaged in &stub_sections {
        let Some(built) = uki_sections
            .iter()
            .find(|built| built.name == packaged.name)
        else {
            return Some(false);
        };
        let same = built.address == packaged.address
            && built.flags == packaged.flags
            && (packaged.name == b".sbat"
                || (built.virtual_size == packaged.virtual_size
                    && bytes_of(uki, built)? == bytes_of(stub, packaged)?));
        if !same {
            return Some(false);
        }
    }
    // A name the UKI lists twice would let a second `.text` pass as the
    // stub's; a section over another's addresses (an added one, or a grown
    // `.sbat`) would be loaded over the stub's code. A loader copies the
    // raw size where the virtual size is 0 (EDK2 does), and maps the
    // virtual size otherwise, so the larger of the two is what a section
    // can cover.
    let range = |section: &Section<'_>| {
        let extent = section.virtual_size.max(section.raw_size);
        u64::from(section.address)..u64::from(section.address) + u64::from(extent)
    };
    let apart = uki_sections.iter().enumerate().all(|(index, section)| {
        uki_sections[index + 1..].iter().all(|later| {
            let (one, other) = (range(section), range(later));
            later.name != section.name && (one.end <= other.start || other.end <= one.start)
        })
    });
    let added_only_data = uki_sections
        .iter()
        .filter(|built| {
            !stub_sections
                .iter()
                .any(|packaged| packaged.name == built.name)
        })
        .all(|added| UKI_SECTIONS.contains(&added.name) && added.flags & EXECUTABLE == 0);
    Some(apart && added_only_data)
}

#[cfg(test)]
mod tests;
