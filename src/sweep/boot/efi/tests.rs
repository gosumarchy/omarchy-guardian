use std::collections::HashSet;
use std::fs;
use std::os::unix::fs::PermissionsExt as _;
use std::path::Path;

use super::pe::ENROLL_MARKER;
use super::{ELSEWHERE, GRUB, GRUB_MODULES, MAX_PROGRAMS, NO_STUB, OTHER_KERNEL};
use crate::rules::RuleId;
use crate::sha256::Sha256;
use crate::sweep::boot::check;
use crate::sweep::collect::{Origin, Scope};
use crate::sweep::index::PackageIndex;
use crate::test_support::TempDir;

/// Where the PE header starts in the programs `build` makes.
pub(super) const PE: usize = 0x40;
/// The optional header's magic for PE32 and PE32+.
pub(super) const PE32: u16 = 0x10b;
pub(super) const PE32_PLUS: u16 = 0x20b;
/// The checksum field and the certificate table's directory of a PE32+
/// program `build` makes.
pub(super) const CHECKSUM: usize = PE + 24 + 64;
pub(super) const CERTIFICATES: usize = PE + 24 + 112 + 4 * 8;
/// Section flags: code that can be run, and data.
pub(super) const CODE: u32 = 0x6000_0020;
pub(super) const DATA: u32 = 0x4000_0040;

/// One section of a program `build` makes.
pub(super) struct Part<'a> {
    pub(super) name: &'a str,
    pub(super) data: &'a [u8],
    pub(super) address: u32,
    pub(super) flags: u32,
}

/// `value` as the four little-endian bytes of a PE field.
pub(super) fn le32(value: usize) -> [u8; 4] {
    u32::try_from(value)
        .expect("test programs are a few hundred bytes")
        .to_le_bytes()
}

fn le16(value: usize) -> [u8; 2] {
    u16::try_from(value)
        .expect("test programs have few sections and a fixed header")
        .to_le_bytes()
}

/// A program of the optional header `magic` starting at `entry`, with all
/// 16 data directories (the base relocation one set) and `parts`, each laid
/// out after the headers and padded to 16 bytes, as a linker pads to the
/// file alignment.
pub(super) fn build(magic: u16, entry: u32, parts: &[Part<'_>]) -> Vec<u8> {
    let optional = PE + 24;
    let (directories, count_field) = if magic == PE32 {
        (optional + 96, optional + 92)
    } else {
        (optional + 112, optional + 108)
    };
    let optional_size = directories + 16 * 8 - optional;
    let table = optional + optional_size;
    let mut bytes = vec![0_u8; table + 40 * parts.len()];
    bytes[..2].copy_from_slice(b"MZ");
    bytes[0x3c..0x40].copy_from_slice(&le32(PE));
    bytes[PE..PE + 4].copy_from_slice(b"PE\0\0");
    bytes[PE + 6..PE + 8].copy_from_slice(&le16(parts.len()));
    bytes[PE + 20..PE + 22].copy_from_slice(&le16(optional_size));
    bytes[optional..optional + 2].copy_from_slice(&magic.to_le_bytes());
    bytes[optional + 16..optional + 20].copy_from_slice(&entry.to_le_bytes());
    bytes[count_field..count_field + 4].copy_from_slice(&16_u32.to_le_bytes());
    let relocations = directories + 5 * 8;
    bytes[relocations..relocations + 4].copy_from_slice(&0x9000_u32.to_le_bytes());
    for (index, part) in parts.iter().enumerate() {
        let entry = table + 40 * index;
        let raw = part.data.len().div_ceil(16) * 16;
        let at = bytes.len();
        bytes[entry..entry + part.name.len()].copy_from_slice(part.name.as_bytes());
        bytes[entry + 8..entry + 12].copy_from_slice(&le32(part.data.len()));
        bytes[entry + 12..entry + 16].copy_from_slice(&part.address.to_le_bytes());
        bytes[entry + 16..entry + 20].copy_from_slice(&le32(raw));
        bytes[entry + 20..entry + 24].copy_from_slice(&le32(at));
        bytes[entry + 36..entry + 40].copy_from_slice(&part.flags.to_le_bytes());
        bytes.extend_from_slice(part.data);
        bytes.resize(at + raw, 0);
    }
    bytes
}

/// A PE32+ program with `sections` of code, one page apart.
pub(super) fn program(sections: &[(&str, &[u8])]) -> Vec<u8> {
    let parts: Vec<Part<'_>> = sections
        .iter()
        .zip(1_u32..)
        .map(|((name, data), page)| Part {
            name,
            data,
            address: page * 0x1000,
            flags: CODE,
        })
        .collect();
    build(PE32_PLUS, 0x1000, &parts)
}

/// The sections of a UKI stub, as systemd ships one.
pub(super) fn stub_parts() -> Vec<Part<'static>> {
    vec![
        Part {
            name: ".text",
            data: b"stub code",
            address: 0x1000,
            flags: CODE,
        },
        Part {
            name: ".sbat",
            data: b"sbat,1\nsystemd,1\n",
            address: 0x2000,
            flags: DATA,
        },
        Part {
            name: ".sdmagic",
            data: b"#### LoaderInfo: systemd-stub ####",
            address: 0x3000,
            flags: DATA,
        },
    ]
}

pub(super) fn stub() -> Vec<u8> {
    build(PE32_PLUS, 0x1000, &stub_parts())
}

/// A UKI built from `stub` around `kernel`, as ukify builds one: the
/// stub's sections, `.sbat` with the kernel's entries merged in, and the
/// sections it adds after them.
pub(super) fn uki(kernel: &[u8]) -> Vec<u8> {
    let mut parts = stub_parts();
    parts[1].data = b"sbat,1\nsystemd,1\nlinux,1\n";
    parts.extend([
        Part {
            name: ".osrel",
            data: b"ID=arch\n",
            address: 0x10000,
            flags: DATA,
        },
        Part {
            name: ".linux",
            data: kernel,
            address: 0x20000,
            flags: DATA,
        },
    ]);
    build(PE32_PLUS, 0x1000, &parts)
}

/// `bytes` as `sbsign` leaves them: padded to 8 bytes, the certificate
/// table appended and pointed at, and the checksum set.
pub(super) fn signed(bytes: &[u8]) -> Vec<u8> {
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
pub(super) fn enrolled(bytes: &[u8]) -> Vec<u8> {
    let mut bytes = bytes.to_vec();
    let at = bytes
        .windows(ENROLL_MARKER.len())
        .position(|window| window == ENROLL_MARKER)
        .unwrap()
        + ENROLL_MARKER.len();
    bytes[at..at + 128].fill(b'a');
    bytes
}

pub(super) fn limine() -> Vec<u8> {
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

const STUB: &str = "usr/lib/systemd/boot/efi/linuxx64.efi.stub";

/// What the packages in `efi_programs_are_compared_with_the_packaged_ones`
/// installed: Limine, systemd-boot as `systemd_boot`, its UKI stub, and a
/// kernel.
fn packages(systemd_boot: &[u8]) -> PackageIndex {
    let mut index = PackageIndex::with_foreign(HashSet::new());
    index.add_for_test(
        "limine",
        &mtree_line("usr/share/limine/BOOTX64.EFI", &limine()),
        &[],
    );
    index.add_for_test(
        "systemd",
        &format!(
            "{}{}",
            mtree_line("usr/lib/systemd/boot/efi/systemd-bootx64.efi", systemd_boot),
            mtree_line(STUB, &stub())
        ),
        &[],
    );
    index.add_for_test(
        "linux",
        &mtree_line("usr/lib/modules/6.1-arch/vmlinuz", b"kernel"),
        &[],
    );
    index
}

/// The path, first alert and last note of each item `check` found.
fn found(scope: &Scope<'_>) -> Vec<(String, Option<RuleId>, Option<String>)> {
    check(scope)
        .items
        .into_iter()
        .map(|item| {
            (
                item.path,
                item.alerts.first().map(|(rule, _)| *rule),
                item.notes.last().cloned(),
            )
        })
        .collect()
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
    write(root, STUB, &stub());
    write(root, "usr/lib/modules/6.1-arch/vmlinuz", b"kernel");
    let mut index = packages(&systemd_boot);

    let mut patched_stub = uki(b"kernel");
    let code = patched_stub
        .windows(9)
        .position(|window| window == b"stub code")
        .unwrap();
    patched_stub[code] = b'S';
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
        ("boot/EFI/Linux/arch-linux.efi", signed(&uki(b"kernel"))),
        ("boot/EFI/Linux/arch-old.efi", uki(b"older kernel")),
        ("boot/EFI/Linux/arch-patched.efi", patched_stub),
        ("boot/EFI/BOOT/grubx64.efi", program(&[(".text", b"grub")])),
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
    let tampered = Some(RuleId::BootTampering);
    let item =
        |path: &str, alert, note: Option<&str>| (path.to_string(), alert, note.map(str::to_string));
    let expected = [
        item("boot/EFI/BOOT/grubx64.efi", tampered, None),
        item("boot/EFI/Linux/arch-old.efi", None, Some(OTHER_KERNEL)),
        item("boot/EFI/Linux/arch-patched.efi", tampered, None),
        item(
            "boot/EFI/Microsoft/Boot/bootmgfw.efi",
            None,
            Some(ELSEWHERE),
        ),
        item("boot/EFI/systemd/systemd-bootx64.efi", tampered, None),
    ];
    assert_eq!(found(&scope), expected);
    let boot = check(&scope);
    assert!(
        boot.notes.iter().any(|note| note
            .starts_with("1 unified kernel image(s) in /boot: the stub and the kernel inside")),
        "{:?}",
        boot.notes
    );
    assert!(boot.unchecked.is_empty(), "{:?}", boot.unchecked);

    // A grub*.efi is GRUB's own only where the grub package is installed.
    write(root, GRUB_MODULES, b"grub");
    index.add_for_test("grub", &mtree_line(GRUB_MODULES, b"grub"), &[]);
    let scope = Scope {
        root,
        home: None,
        index: &index,
        origin: Origin::Root,
    };
    assert_eq!(
        found(&scope)[0],
        item("boot/EFI/BOOT/grubx64.efi", None, Some(GRUB))
    );
}

#[test]
fn a_unified_kernel_image_without_a_packaged_stub_is_not_comparable() {
    let dir = TempDir::new("sweep-efi-no-stub");
    let root = dir.path();
    write(root, "boot/EFI/Linux/arch-linux.efi", &uki(b"kernel"));
    let index = PackageIndex::with_foreign(HashSet::new());
    let scope = Scope {
        root,
        home: None,
        index: &index,
        origin: Origin::Root,
    };
    assert_eq!(
        found(&scope),
        [(
            "boot/EFI/Linux/arch-linux.efi".to_string(),
            None,
            Some(NO_STUB.to_string())
        )]
    );
}

#[test]
fn more_programs_than_are_compared_and_unreadable_ones_are_said() {
    let dir = TempDir::new("sweep-efi-many");
    let root = dir.path();
    for number in 0..=MAX_PROGRAMS {
        write(
            root,
            &format!("boot/EFI/tools/tool{number:02}.efi"),
            &program(&[(".text", format!("tool {number}").as_bytes())]),
        );
    }
    let index = PackageIndex::with_foreign(HashSet::new());
    let scope = Scope {
        root,
        home: None,
        index: &index,
        origin: Origin::System,
    };
    let sentence =
        format!("/boot: more than {MAX_PROGRAMS} EFI programs; the rest were not compared");
    let boot = check(&scope);
    assert!(boot.notes.contains(&sentence), "{:?}", boot.notes);
    assert_eq!(boot.items.len(), MAX_PROGRAMS);
    let as_root = check(&Scope {
        origin: Origin::Root,
        ..scope
    });
    assert_eq!(as_root.unchecked, [sentence]);

    // A program the user cannot read is left to the root checks. Root
    // reads every file, so this holds only for a user.
    if crate::user::effective_uid().is_ok_and(|uid| uid == 0) {
        return;
    }
    let closed = root.join("boot/EFI/tools/tool00.efi");
    fs::set_permissions(&closed, fs::Permissions::from_mode(0o000)).unwrap();
    let boot = check(&scope);
    assert!(
        boot.notes.contains(&"/boot/EFI/tools/tool00.efi cannot be read as this user; the root checks compare it with the packaged EFI programs".to_string()),
        "{:?}",
        boot.notes
    );
    fs::set_permissions(&closed, fs::Permissions::from_mode(0o644)).unwrap();
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
