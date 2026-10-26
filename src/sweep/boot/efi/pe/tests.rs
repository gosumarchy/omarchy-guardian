use super::{MAX_SECTIONS, header, is_built_from, is_same_program, normalized, section};
use crate::sweep::boot::efi::tests::{
    CERTIFICATES, CODE, DATA, PE, PE32, PE32_PLUS, Part, build, enrolled, le32, limine, program,
    signed, stub, stub_parts, uki,
};

#[test]
fn a_pe_header_and_its_sections_are_read() {
    let built = uki(b"kernel");
    let read = header(&built).unwrap();
    assert_eq!(read.count, 5);
    assert_eq!(
        section(&built, &read, b".linux"),
        Some(b"kernel".as_slice())
    );
    assert_eq!(section(&built, &read, b".initrd"), None);
    // PE32 lays the optional header out differently.
    let old = build(PE32, 0x1000, &stub_parts());
    let read = header(&old).unwrap();
    assert_eq!(read.certificates(), Some(PE + 24 + 96 + 4 * 8));
    assert_eq!(
        section(&old, &read, b".text"),
        Some(b"stub code".as_slice())
    );
    // Not a PE program, or one cut short: nothing to read.
    assert!(header(b"MZ").is_none());
    assert!(header(b"#!/bin/sh\n").is_none());
    assert!(header(&built[..PE + 30]).is_none());
    assert!(normalized(b"not a program").is_none());
}

#[test]
fn a_directory_past_the_optional_header_is_not_read() {
    // An optional header that says it holds 16 directories but has room
    // for four holds no certificate table, whatever follows it.
    let mut short = stub();
    let room = 112 + 4 * 8;
    short[PE + 20..PE + 22].copy_from_slice(&u16::try_from(room).unwrap().to_le_bytes());
    assert_eq!(header(&short).unwrap().certificates(), None);
    assert!(header(&stub()).unwrap().certificates().is_some());
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
        assert!(is_same_program(&normalized(&changed).unwrap(), &packaged));
    }
    // A program whose length is not a multiple of 8 is padded before
    // the table.
    let mut odd = limine();
    odd.push(0x90);
    assert_eq!(
        signed(&odd).len() - odd.len(),
        7 + b"a certificate table".len()
    );
    assert!(is_same_program(
        &normalized(&signed(&odd)).unwrap(),
        &normalized(&odd).unwrap()
    ));
    // Code changed, signed or not, is another program.
    let mut patched = limine();
    let code = patched
        .windows(11)
        .position(|window| window == b"limine code")
        .unwrap();
    patched[code] ^= 1;
    for changed in [patched.clone(), signed(&patched)] {
        assert!(!is_same_program(&normalized(&changed).unwrap(), &packaged));
    }
    // More than padding before the table, or a table that starts inside
    // the program, is no signature of the packaged one.
    let mut longer = limine();
    longer.extend_from_slice(&[0; 9]);
    assert!(!is_same_program(
        &normalized(&signed(&longer)).unwrap(),
        &packaged
    ));
    let mut cut = signed(&limine());
    cut[CERTIFICATES..CERTIFICATES + 4].copy_from_slice(&le32(limine().len() - 16));
    assert!(!is_same_program(&normalized(&cut).unwrap(), &packaged));
}

/// A UKI built around `kernel` with `change` made to its parts.
fn changed_uki(change: impl FnOnce(&mut Vec<Part<'static>>)) -> Vec<u8> {
    let mut parts = stub_parts();
    parts.push(Part {
        name: ".linux",
        data: b"kernel",
        address: 0x20000,
        flags: DATA,
    });
    change(&mut parts);
    build(PE32_PLUS, 0x1000, &parts)
}

#[test]
fn a_unified_kernel_image_is_built_from_the_stub_only_where_its_code_is_the_stubs() {
    let stub = stub();
    assert!(is_built_from(&uki(b"kernel"), &stub));
    assert!(is_built_from(&signed(&uki(b"kernel")), &stub));
    assert!(is_built_from(&changed_uki(|_| {}), &stub));
    let not_built = [
        // The stub's code changed, or moved.
        changed_uki(|parts| parts[0].data = b"stub c0de"),
        changed_uki(|parts| parts[0].address = 0x4000),
        // A data section made executable.
        changed_uki(|parts| parts[2].flags = CODE),
        // A section of the stub left out.
        changed_uki(|parts| {
            parts.remove(2);
        }),
        // An added section that runs, that the format does not know, or
        // that lies over the stub's code.
        changed_uki(|parts| parts[3].flags = CODE),
        changed_uki(|parts| parts[3].name = ".payload"),
        changed_uki(|parts| parts[3].address = 0x1000),
        // A second section named as the stub's code.
        changed_uki(|parts| {
            parts.push(Part {
                name: ".text",
                data: b"more code",
                address: 0x30000,
                flags: CODE,
            });
        }),
        // A grown `.sbat` that reaches over the next section.
        changed_uki(|parts| parts[1].data = &[b's'; 0x1800]),
    ];
    for (index, built) in not_built.iter().enumerate() {
        assert!(!is_built_from(built, &stub), "case {index}");
    }
    // Another entry point, or other data directories.
    let mut entry = uki(b"kernel");
    entry[PE + 24 + 16] = 0x20;
    assert!(!is_built_from(&entry, &stub));
    let mut relocations = uki(b"kernel");
    relocations[PE + 24 + 112 + 5 * 8] = 0x10;
    assert!(!is_built_from(&relocations, &stub));
    assert!(!is_built_from(b"not a program", &stub));
}

/// `bytes`, a PE32+ program, with section `index` given a virtual size
/// of 0, so that a loader copies its raw size instead.
fn without_virtual_size(mut bytes: Vec<u8>, index: usize) -> Vec<u8> {
    let entry = PE + 24 + 112 + 16 * 8 + 40 * index;
    bytes[entry + 8..entry + 12].fill(0);
    bytes
}

#[test]
fn a_section_without_a_virtual_size_covers_its_raw_size() {
    let stub = stub();
    // An added splash, and a grown `.sbat`, each reaching over the next
    // section once its raw size is what is loaded.
    let splash = changed_uki(|parts| {
        parts.push(Part {
            name: ".splash",
            data: &[b'p'; 0x1000],
            address: 0x800,
            flags: DATA,
        });
    });
    let sbat = changed_uki(|parts| parts[1].data = &[b's'; 0x1800]);
    for (index, built) in [(4, splash), (1, sbat)] {
        assert!(!is_built_from(&without_virtual_size(built, index), &stub));
    }
    // Where it fits, a section without a virtual size is fine.
    let fits = changed_uki(|parts| {
        parts.push(Part {
            name: ".splash",
            data: b"picture",
            address: 0x30000,
            flags: DATA,
        });
    });
    assert!(is_built_from(&without_virtual_size(fits, 4), &stub));
}

#[test]
fn a_program_with_more_sections_than_are_read_is_refused() {
    let names: Vec<String> = (0..=MAX_SECTIONS).map(|n| format!(".s{n}")).collect();
    let sections: Vec<(&str, &[u8])> = names
        .iter()
        .map(|name| (name.as_str(), b"code".as_slice()))
        .collect();
    let many = program(&sections);
    let read = header(&many).unwrap();
    assert_eq!(section(&many, &read, b".s0"), None);
    let fewer = program(&sections[..MAX_SECTIONS]);
    let read = header(&fewer).unwrap();
    assert_eq!(section(&fewer, &read, b".s0"), Some(b"code".as_slice()));
}

/// The readers take bytes anyone may have written: none of them panics on
/// any prefix of a program or on any byte of it changed.
#[test]
fn the_readers_never_panic_on_a_damaged_program() {
    let stub = stub();
    let check = |bytes: &[u8]| {
        if let Some(read) = header(bytes) {
            std::hint::black_box(section(bytes, &read, b".linux"));
            std::hint::black_box(read.certificates());
        }
        std::hint::black_box(normalized(bytes));
        std::hint::black_box(is_built_from(bytes, &stub));
    };
    for program in [signed(&enrolled(&limine())), uki(b"kernel")] {
        for end in 0..=program.len() {
            check(&program[..end]);
        }
        for at in 0..program.len() {
            for value in [0x00, 0xff, program[at] ^ 0x80] {
                let mut damaged = program.clone();
                damaged[at] = value;
                check(&damaged);
            }
        }
    }
}
