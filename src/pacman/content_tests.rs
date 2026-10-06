//! Tests for how a reviewed transaction is named.

use super::{reviewed_classes, reviewed_content, reviewed_digests, reviewed_names};
use crate::config::model::SourceClass;
use crate::report::{Report, ReviewedArchive};

#[test]
fn a_transaction_is_named_by_every_archive_it_was_reviewed_from() {
    let mut report = Report::new("pacman transaction");
    // Nothing was read: nothing a permit could stand for.
    assert!(reviewed_content(&report).is_none());
    let archive = |name: &str, class, byte: &str| ReviewedArchive {
        name: name.to_string(),
        class,
        sha256: byte.repeat(64),
    };
    report.archives = vec![
        archive("demo-1-1-any", SourceClass::LocalPackage, "b"),
        archive("lib-2-1-x86_64", SourceClass::Official, "a"),
    ];
    assert_eq!(reviewed_classes(&report), "local-package+official");
    assert_eq!(reviewed_names(&report), "demo-1-1-any lib-2-1-x86_64");
    assert_eq!(
        reviewed_digests(&report),
        format!(
            "demo-1-1-any={} lib-2-1-x86_64={}",
            "b".repeat(64),
            "a".repeat(64)
        )
    );
    let key = reviewed_content(&report).unwrap().key();

    // The order of the targets and the archives' names say nothing.
    report.archives.reverse();
    report.archives[0].name = "renamed".into();
    assert_eq!(reviewed_content(&report).unwrap().key(), key);
    // Other bytes, or the same bytes as another kind of package, do.
    report.archives[0].sha256 = "c".repeat(64);
    assert_ne!(reviewed_content(&report).unwrap().key(), key);
    report.archives[0].sha256 = "a".repeat(64);
    assert_eq!(reviewed_content(&report).unwrap().key(), key);
    report.archives[0].class = SourceClass::ThirdPartyRepo;
    assert_ne!(reviewed_content(&report).unwrap().key(), key);
    // An archive more is another transaction.
    report.archives[0].class = SourceClass::Official;
    report
        .archives
        .push(archive("extra-1-1-any", SourceClass::Official, "d"));
    assert_ne!(reviewed_content(&report).unwrap().key(), key);
}
