use std::collections::HashSet;
use std::fs;
use std::path::Path;

use super::{ELSEWHERE, ENROLL_MARKER, GRUB, OTHER_KERNEL, header, normalized, section};
use crate::rules::RuleId;
use crate::sha256::Sha256;
use crate::sweep::boot::check;
use crate::sweep::collect::{Origin, Scope};
use crate::sweep::index::PackageIndex;
use crate::test_support::TempDir;

/// Where the PE header starts in the programs `program` builds.
const PE: usize = 0x40;
/// The size of a PE32+ optional header with all 16 data directories.
const OPTIONAL_SIZE: usize = 112 + 16 * 8;
const CHECKSUM: usize = PE + 24 + 64;
const CERTIFICATES: usize = PE + 24 + 112 + 4 * 8;

/// `value` as the four little-endian bytes of a PE field.
fn le32(value: usize) -> [u8; 4] {
    u32::try_from(value)
        .expect("test programs are a few hundred bytes")
        .to_le_bytes()
}

fn le16(value: usize) -> [u8; 2] {
    u16::try_from(value)
        .expect("test programs have few sections and a fixed header")
        .to_le_bytes()
}

/// A PE32+ program with `sections`, each laid out after the headers and
/// padded to 16 bytes, as a linker pads to the file alignment.
fn program(sections: &[(&str, &[u8])]) -> Vec<u8> {
    let table = PE + 24 + OPTIONAL_SIZE;
    let mut bytes = vec![0_u8; table + 40 * sections.len()];
    bytes[..2].copy_from_slice(b"MZ");
    bytes[0x3c..0x40].copy_from_slice(&le32(PE));
    bytes[PE..PE + 4].copy_from_slice(b"PE\0\0");
    bytes[PE + 6..PE + 8].copy_from_slice(&le16(sections.len()));
    bytes[PE + 20..PE + 22].copy_from_slice(&le16(OPTIONAL_SIZE));
    bytes[PE + 24..PE + 26].copy_from_slice(&0x20b_u16.to_le_bytes());
    bytes[PE + 24 + 108..PE + 24 + 112].copy_from_slice(&16_u32.to_le_bytes());
    for (index, (name, data)) in sections.iter().enumerate() {
        let entry = table + 40 * index;
        let raw = data.len().div_ceil(16) * 16;
        let at = bytes.len();
        bytes[entry..entry + name.len()].copy_from_slice(name.as_bytes());
        bytes[entry + 8..entry + 12].copy_from_slice(&le32(data.len()));
        bytes[entry + 16..entry + 20].copy_from_slice(&le32(raw));
        bytes[entry + 20..entry + 24].copy_from_slice(&le32(at));
        bytes.extend_from_slice(data);
        bytes.resize(at + raw, 0);
    }
    bytes
}

/// `bytes` as `sbsign` leaves them: padded to 8 bytes, the certificate
/// table appended and pointed at, and the checksum set.
fn signed(bytes: &[u8]) -> Vec<u8> {
    let mut bytes = bytes.to_vec();
    bytes.resize(bytes.len().div_ceil(8) * 8, 0);
    let table = b"a certificate table";
    let at = bytes.len();
    bytes[CERTIFICATES..CERTIFICATES + 4].copy_from_slice(&le32(at));
    bytes[CERTIFICATES + 4..CERTIFICATES + 8].copy_from_slice(&le32(table.len()));
    bytes[CHECKSUM..CHECKSUM + 4].copy_from_slice(&0x1234_u32.to_le_bytes());
    bytes.extend_from_slice(table);
    bytes
}

/// `bytes` with a configuration hash enrolled, as `limine enroll-config`
/// writes it.
fn enrolled(bytes: &[u8]) -> Vec<u8> {
    let mut bytes = bytes.to_vec();
    let at = bytes
        .windows(ENROLL_MARKER.len())
        .position(|window| window == ENROLL_MARKER)
        .unwrap()
        + ENROLL_MARKER.len();
    bytes[at..at + 128].fill(b'a');
    bytes
}

fn limine() -> Vec<u8> {
    let mut text = b"limine code ".to_vec();
    text.extend_from_slice(ENROLL_MARKER);
    text.extend_from_slice(&[b'0'; 128]);
    program(&[(".text", &text)])
}

fn write(root: &Path, path: &str, bytes: &[u8]) {
    fs::create_dir_all(root.join(path).parent().unwrap()).unwrap();
    fs::write(root.join(path), bytes).unwrap();
}

fn mtree_line(path: &str, bytes: &[u8]) -> String {
    format!(
        "./{path} type=file mode=644 sha256digest={}\n",
        Sha256::digest(bytes)
    )
}

#[test]
fn a_pe_header_and_its_sections_are_read() {
    let uki = program(&[(".osrel", b"ID=arch"), (".linux", b"kernel")]);
    let read = header(&uki).unwrap();
    assert_eq!(read.count, 2);
    let (start, length) = section(&uki, &read, b".linux").unwrap();
    let start = usize::try_from(start).unwrap();
    let length = usize::try_from(length).unwrap();
    assert_eq!(&uki[start..start + length], b"kernel".as_slice());
    assert_eq!(section(&uki, &read, b".initrd"), None);
    // Not a PE program, or one cut short: nothing to read.
    assert!(header(b"MZ").is_none());
    assert!(header(b"#!/bin/sh\n").is_none());
    assert!(header(&uki[..PE + 30]).is_none());
    assert!(normalized(b"not a program").is_none());
}

#[test]
fn a_signature_and_an_enrolled_hash_are_put_back_before_comparing() {
    let packaged = normalized(&limine()).unwrap();
    for changed in [
        limine(),
        signed(&limine()),
        enrolled(&limine()),
        signed(&enrolled(&limine())),
    ] {
        let program = normalized(&changed).unwrap();
        assert!(super::is_same_program(&program, &packaged));
    }
    // A program whose length is not a multiple of 8 is padded before
    // the table.
    let mut odd = limine();
    odd.push(0x90);
    assert_eq!(
        signed(&odd).len() - odd.len(),
        7 + b"a certificate table".len()
    );
    assert!(super::is_same_program(
        &normalized(&signed(&odd)).unwrap(),
        &normalized(&odd).unwrap()
    ));
    // Code changed, signed or not, is another program.
    let mut patched = limine();
    patched[PE + 24 + OPTIONAL_SIZE + 40] ^= 1;
    for changed in [patched.clone(), signed(&patched)] {
        assert!(!super::is_same_program(
            &normalized(&changed).unwrap(),
            &packaged
        ));
    }
    // More than padding before the table, or a table that starts inside
    // the program, is no signature of the packaged one.
    let mut longer = limine();
    longer.extend_from_slice(&[0; 9]);
    assert!(!super::is_same_program(
        &normalized(&signed(&longer)).unwrap(),
        &packaged
    ));
    let mut cut = signed(&limine());
    cut[CERTIFICATES..CERTIFICATES + 4].copy_from_slice(&le32(limine().len() - 16));
    assert!(!super::is_same_program(
        &normalized(&cut).unwrap(),
        &packaged
    ));
}

/// What the packages in `efi_programs_are_compared_with_the_packaged_ones`
/// installed: Limine, systemd-boot as `systemd_boot`, and a kernel.
fn packages(systemd_boot: &[u8]) -> PackageIndex {
    let mut index = PackageIndex::with_foreign(HashSet::new());
    index.add_for_test(
        "limine",
        &mtree_line("usr/share/limine/BOOTX64.EFI", &limine()),
        &[],
    );
    index.add_for_test(
        "systemd",
        &mtree_line("usr/lib/systemd/boot/efi/systemd-bootx64.efi", systemd_boot),
        &[],
    );
    index.add_for_test(
        "linux",
        &mtree_line("usr/lib/modules/6.1-arch/vmlinuz", b"kernel"),
        &[],
    );
    index
}

#[test]
fn efi_programs_are_compared_with_the_packaged_ones() {
    let dir = TempDir::new("sweep-efi");
    let root = dir.path();
    let systemd_boot = program(&[(".text", b"systemd-boot"), (".osrel", b"ID=arch")]);
    let patched_boot = program(&[(".text", b"systemd-boot, patched")]);
    write(root, "usr/share/limine/BOOTX64.EFI", &limine());
    // A packaged program changed on disk vouches for nothing.
    write(
        root,
        "usr/lib/systemd/boot/efi/systemd-bootx64.efi",
        &patched_boot,
    );
    write(root, "usr/lib/modules/6.1-arch/vmlinuz", b"kernel");
    let index = packages(&systemd_boot);

    let esp = [
        ("boot/EFI/BOOT/BOOTX64.EFI", limine()),
        (
            "boot/EFI/limine/limine_x64.efi",
            signed(&enrolled(&limine())),
        ),
        (
            "boot/EFI/systemd/systemd-bootx64.efi",
            signed(&patched_boot),
        ),
        (
            "boot/EFI/Microsoft/Boot/bootmgfw.efi",
            program(&[(".text", b"windows")]),
        ),
        (
            "boot/EFI/Linux/arch-linux.efi",
            program(&[(".linux", b"kernel")]),
        ),
        (
            "boot/EFI/Linux/arch-old.efi",
            program(&[(".linux", b"older kernel")]),
        ),
        ("boot/EFI/arch/grubx64.efi", program(&[(".text", b"grub")])),
        ("boot/limine_x64.bak", b"not an EFI program".to_vec()),
    ];
    for (path, bytes) in &esp {
        write(root, path, bytes);
    }
    let scope = Scope {
        root,
        home: None,
        index: &index,
        origin: Origin::Root,
    };
    let boot = check(&scope);
    let found: Vec<(&str, Option<RuleId>, Option<&str>)> = boot
        .items
        .iter()
        .map(|item| {
            (
                item.path.as_str(),
                item.alerts.first().map(|(rule, _)| *rule),
                item.notes.last().map(String::as_str),
            )
        })
        .collect();
    assert_eq!(
        found,
        [
            ("boot/EFI/Linux/arch-old.efi", None, Some(OTHER_KERNEL)),
            (
                "boot/EFI/Microsoft/Boot/bootmgfw.efi",
                None,
                Some(ELSEWHERE)
            ),
            ("boot/EFI/arch/grubx64.efi", None, Some(GRUB)),
            (
                "boot/EFI/systemd/systemd-bootx64.efi",
                Some(RuleId::BootTampering),
                None
            ),
        ]
    );
    assert!(
        boot.notes
            .iter()
            .any(|note| note.starts_with("1 unified kernel image(s) in /boot: the kernel inside")),
        "{:?}",
        boot.notes
    );
    assert!(boot.unchecked.is_empty(), "{:?}", boot.unchecked);
}

#[test]
fn a_boot_directory_that_cannot_be_listed_is_said() {
    let dir = TempDir::new("sweep-efi-unlisted");
    let root = dir.path();
    // A file where the directory belongs cannot be listed either.
    write(root, "boot", b"");
    let index = PackageIndex::with_foreign(HashSet::new());
    let scope = Scope {
        root,
        home: None,
        index: &index,
        origin: Origin::System,
    };
    let boot = check(&scope);
    assert!(
        boot.notes
            .iter()
            .any(|note| note
                .starts_with("the kernel images and EFI programs in /boot cannot be read")),
        "{:?}",
        boot.notes
    );
    let as_root = check(&Scope {
        origin: Origin::Root,
        ..scope
    });
    assert_eq!(
        as_root.unchecked,
        ["/boot: could not be listed; the kernel images and EFI programs were not compared"]
    );
}
