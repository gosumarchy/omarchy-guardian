use std::collections::{BTreeSet, HashSet};
use std::fs;
use std::os::unix::fs::symlink;
use std::path::Path;

use super::{
    BROWSERS, Extension, MAX_EXTENSIONS, MAX_PROFILES, Source, check, host, read_text, text,
};
use crate::autorun::Category;
use crate::rules::RuleId;
use crate::sha256::Sha256;
use crate::sweep::collect::{Body, Collection, Item, Origin, Scope};
use crate::sweep::index::PackageIndex;
use crate::sweep::tier::Tier;
use crate::test_support::TempDir;

const HOME: &str = "home/u";
const CHROMIUM: &str = "home/u/.config/chromium";
const STORE_ID: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const ELSEWHERE_ID: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
const UNPACKED_ID: &str = "cccccccccccccccccccccccccccccccc";
const PACKAGED_ID: &str = "dddddddddddddddddddddddddddddddd";
const COMPONENT_ID: &str = "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee";

fn write(root: &Path, path: &str, text: &str) {
    fs::create_dir_all(root.join(path).parent().unwrap()).unwrap();
    fs::write(root.join(path), text).unwrap();
}

/// The items `check` found, and what it could not check.
fn found(scope: &Scope<'_>) -> (Vec<Item>, Vec<String>) {
    let found = check(scope);
    (found.items, found.unchecked)
}

fn by_id<'a>(items: &'a [Item], id: &str) -> Option<&'a Item> {
    items
        .iter()
        .find(|item| item.path.ends_with(&format!("#extension:{id}")))
}

/// A Chromium profile with one extension of each kind, and the packaged
/// directory Omarchy loads its own from.
fn chromium_profile(root: &Path) -> PackageIndex {
    let profile = format!("{CHROMIUM}/Default");
    write(
        root,
        &format!("{profile}/Extensions/{STORE_ID}/1.0_0/manifest.json"),
        r#"{"name":"__MSG_appName__","default_locale":"en","version":"1.0","update_url":"https://clients2.google.com/service/update2/crx"}"#,
    );
    write(
        root,
        &format!("{profile}/Extensions/{STORE_ID}/1.0_0/_locales/en/messages.json"),
        r#"{"AppName":{"message":"Store Extension"}}"#,
    );
    write(
        root,
        &format!("{profile}/Extensions/{ELSEWHERE_ID}/2.0_0/manifest.json"),
        r#"{"name":"Side","version":"2.0","update_url":"https://user:token@updates.example:8443/crx?id=1"}"#,
    );
    write(
        root,
        "home/u/dev/ext/manifest.json",
        r#"{"name":"Mine","version":"0.1"}"#,
    );
    write(
        root,
        "usr/share/omarchy/ext/manifest.json",
        r#"{"name":"Copy URL","version":"1"}"#,
    );
    write(root, "usr/share/omarchy/ext/background.js", "chrome.x()");
    let mut index = PackageIndex::with_foreign(HashSet::new());
    index.add_for_test(
        "omarchy-settings",
        &format!(
            "./usr/share/omarchy/ext/manifest.json type=file mode=644 sha256digest={}\n./usr/share/omarchy/ext/background.js type=file mode=644 sha256digest={}\n",
            Sha256::digest(br#"{"name":"Copy URL","version":"1"}"#),
            Sha256::digest(b"chrome.x()")
        ),
        &[],
    );
    let entry = |location: u32, path: &str, api: &str| {
        format!(
            r#"{{"location":{location},"path":"{path}","granted_permissions":{{"api":[{api}],"explicit_host":["https://a.example/*"],"scriptable_host":[]}}}}"#
        )
    };
    write(
        root,
        &format!("{profile}/Preferences"),
        &format!(
            r#"{{"extensions":{{"settings":{{"{STORE_ID}":{},"{ELSEWHERE_ID}":{},"{UNPACKED_ID}":{},"{PACKAGED_ID}":{},"{COMPONENT_ID}":{},"../x":{},"{STORE_ID}a":{}}}}},"browser":{{"history":"private"}}}}"#,
            entry(1, &format!("{STORE_ID}/1.0_0"), r#""storage""#),
            entry(1, &format!("{ELSEWHERE_ID}/2.0_0"), ""),
            entry(4, "/home/u/dev/ext", ""),
            entry(8, "/usr/share/omarchy/ext", r#""nativeMessaging""#),
            entry(5, "/usr/lib/chromium/resources/pdf", ""),
            entry(1, "x", ""),
            entry(1, "x", ""),
        ),
    );
    // What the protected file says of an extension stands.
    write(
        root,
        &format!("{profile}/Secure Preferences"),
        &format!(
            r#"{{"extensions":{{"settings":{{"{STORE_ID}":{}}}}}}}"#,
            entry(
                1,
                &format!("{STORE_ID}/1.0_0"),
                r#""storage",{"socket":["udp-bind"]}"#
            )
        ),
    );
    index
}

#[test]
fn chromium_extensions_are_judged_by_where_they_came_from() {
    let dir = TempDir::new("sweep-extensions");
    let root = dir.path();
    let index = chromium_profile(root);
    let scope = Scope {
        root,
        home: Some(HOME),
        index: &index,
        origin: Origin::System,
    };
    let (items, unchecked) = found(&scope);
    // `../x`, and a 33-letter id.
    assert_eq!(
        unchecked,
        [format!(
            "/{CHROMIUM}/Default: 2 extension(s) listed under an id the browser does not make; not checked"
        )]
    );
    assert_eq!(items.len(), 4, "{items:?}");
    assert!(by_id(&items, COMPONENT_ID).is_none());
    for item in &items {
        assert_eq!(item.category, Category::BrowserExtension);
        assert_eq!(item.origin, Origin::User);
        assert!(
            item.path
                .starts_with("home/u/.config/chromium/Default#extension:")
        );
    }

    let store = by_id(&items, STORE_ID).unwrap();
    assert!(store.alerts.is_empty());
    assert_eq!(store.notes[0], "Chromium extension Store Extension 1.0");
    let Body::Text(text) = &store.body else {
        unreachable!("an extension's body is text");
    };
    assert!(text.contains("permissions: socket, storage\n"), "{text}");
    assert!(text.contains("hosts: https://a.example/*\n"), "{text}");

    let elsewhere = by_id(&items, ELSEWHERE_ID).unwrap();
    assert_eq!(elsewhere.alerts[0].0, RuleId::RiskyConfiguration);
    // Only the host is shown: no credentials, port or query.
    assert_eq!(
        elsewhere.alerts[0].1,
        "installed from outside the Chrome Web Store (from updates.example)"
    );

    let unpacked = by_id(&items, UNPACKED_ID).unwrap();
    assert_eq!(unpacked.tier, Tier::Unknown);
    assert!(
        unpacked.alerts[0]
            .1
            .starts_with("loaded unpacked from /home/u/dev/ext")
    );

    // Every file of it is what its package installed: that package's.
    let packaged = by_id(&items, PACKAGED_ID).unwrap();
    assert_eq!(packaged.tier, Tier::Vendor);
    assert!(packaged.alerts.is_empty() && packaged.is_trusted());

    // Once a file of it changes, it is an unpacked extension like any.
    write(root, "usr/share/omarchy/ext/background.js", "steal()");
    let (items, _) = found(&scope);
    let changed = by_id(&items, PACKAGED_ID).unwrap();
    assert_eq!(changed.alerts[0].0, RuleId::RiskyConfiguration);
}

#[test]
fn what_is_remembered_is_what_was_granted_not_the_version() {
    let extension = |version: &str, hosts: &[&str]| Extension {
        browser: &BROWSERS[0],
        profile: format!("{CHROMIUM}/Default"),
        id: STORE_ID.into(),
        name: Some("Name".into()),
        version: Some(version.into()),
        source: Source::Store,
        permissions: BTreeSet::from(["storage".to_string()]),
        hosts: hosts.iter().map(|host| (*host).to_string()).collect(),
        notes: Vec::new(),
        unread: None,
    };
    let before = text(&extension("1.0", &["https://a/*"]));
    assert_eq!(before, text(&extension("1.1", &["https://a/*"])));
    assert_ne!(
        before,
        text(&extension("1.1", &["https://a/*", "<all_urls>"]))
    );
    let moved = Extension {
        source: Source::Elsewhere(Some("x".into())),
        ..extension("1.0", &["https://a/*"])
    };
    assert_ne!(before, text(&moved));
}

#[test]
fn firefox_extensions_are_judged_by_signature_and_source() {
    let dir = TempDir::new("sweep-extensions-firefox");
    let root = dir.path();
    write(
        root,
        "home/u/.mozilla/firefox/abc.default-release/extensions.json",
        r#"{"addons":[
            {"id":"store@example","type":"extension","location":"app-profile","signedState":2,"version":"1","sourceURI":"https://addons.mozilla.org/firefox/downloads/file/1/x.xpi","defaultLocale":{"name":"Store"},"userPermissions":{"permissions":["tabs"],"origins":["<all_urls>"]}},
            {"id":"{0000-1111}","type":"extension","location":"app-profile","signedState":2,"version":"1","sourceURI":"https://github.com/x/releases/x.xpi"},
            {"id":"unsigned@example","type":"extension","location":"app-profile","signedState":-1,"version":"1"},
            {"id":"temporary@example","type":"extension","location":"app-temporary","path":"/home/u/dev/addon","version":"1"},
            {"id":"builtin@mozilla.org","type":"extension","location":"app-builtin","version":"1"},
            {"id":"theme@example","type":"theme","location":"app-profile","version":"1"},
            {"id":"bad\nid","type":"extension","location":"app-profile","signedState":2}
        ]}"#,
    );
    let index = PackageIndex::with_foreign(HashSet::new());
    let scope = Scope {
        root,
        home: Some(HOME),
        index: &index,
        origin: Origin::System,
    };
    let (items, unchecked) = found(&scope);
    assert_eq!(
        unchecked,
        [
            "/home/u/.mozilla/firefox/abc.default-release: 1 extension(s) listed under an id the browser does not make; not checked"
        ]
    );
    let seen: Vec<(&str, Option<&str>)> = items
        .iter()
        .map(|item| {
            (
                item.path.rsplit("#extension:").next().unwrap(),
                item.alerts.first().map(|(_, seen)| seen.as_str()),
            )
        })
        .collect();
    assert_eq!(
        seen,
        [
            ("store@example", None),
            (
                "{0000-1111}",
                Some("installed from outside the addons.mozilla.org (from github.com)")
            ),
            ("unsigned@example", Some("not signed by Mozilla")),
            (
                "temporary@example",
                Some(
                    "loaded unpacked from /home/u/dev/addon (developer mode, --load-extension or a temporary add-on): nothing vets its code, which changes without an update"
                )
            ),
        ]
    );
    assert_eq!(items[0].notes[0], "Firefox extension Store 1");
}

#[test]
fn what_cannot_be_read_is_said_and_the_rest_still_checked() {
    let dir = TempDir::new("sweep-extensions-unread");
    let root = dir.path();
    let index = chromium_profile(root);
    write(
        root,
        &format!("{CHROMIUM}/Profile 1/Preferences"),
        "{not json",
    );
    // A link stands for no profile, and a preferences file that is a link
    // is not followed.
    symlink(
        root.join(CHROMIUM).join("Default"),
        root.join(CHROMIUM).join("Profile 2"),
    )
    .unwrap();
    fs::create_dir_all(root.join(CHROMIUM).join("Profile 3")).unwrap();
    symlink(
        root.join(CHROMIUM).join("Default/Preferences"),
        root.join(CHROMIUM).join("Profile 3/Preferences"),
    )
    .unwrap();
    let scope = Scope {
        root,
        home: Some(HOME),
        index: &index,
        origin: Origin::System,
    };
    let (items, unchecked) = found(&scope);
    assert_eq!(items.len(), 4);
    // The first is the ids of `chromium_profile` the browser does not make.
    assert_eq!(unchecked.len(), 3, "{unchecked:?}");
    assert!(unchecked[1].starts_with("could not parse "));
    assert!(unchecked[1].contains("Profile 1/Preferences: "));
    assert!(
        unchecked[1]
            .ends_with("the extensions of /home/u/.config/chromium/Profile 1 were not checked")
    );
    assert!(unchecked[2].contains("Profile 3/Preferences: not a file that can be read"));

    // A file past the limit is not read.
    let large = read_text(root, &format!("{CHROMIUM}/Default/Preferences"), 10);
    assert!(
        large
            .unwrap_err()
            .to_string()
            .contains("larger than 10 bytes")
    );
    assert_eq!(read_text(root, "home/u/none", 10).unwrap(), None);
    // Without a home there is nothing to look at.
    let homeless = check(&Scope {
        home: None,
        ..scope
    });
    assert!(homeless.items.is_empty() && homeless.unchecked.is_empty());
}

/// A Chromium extension id: `n` in hexadecimal, its digits shifted to
/// the letters `a` to `p`.
fn chromium_id(n: usize) -> String {
    format!("{n:032x}")
        .bytes()
        .map(|digit| {
            let value = char::from(digit).to_digit(16).unwrap();
            char::from(b'a' + u8::try_from(value).unwrap())
        })
        .collect()
}

#[test]
fn what_is_past_the_limits_is_said() {
    let dir = TempDir::new("sweep-extensions-limits");
    let root = dir.path();
    // Installed from the store, as Chromium marks it, with no update URL to
    // look at.
    let settings: Vec<String> = (0..=MAX_EXTENSIONS)
        .map(|n| {
            format!(
                r#""{}":{{"location":1,"from_webstore":true}}"#,
                chromium_id(n)
            )
        })
        .collect();
    write(
        root,
        &format!("{CHROMIUM}/Default/Preferences"),
        &format!(
            r#"{{"extensions":{{"settings":{{{}}}}}}}"#,
            settings.join(",")
        ),
    );
    for n in 1..=MAX_PROFILES {
        write(root, &format!("{CHROMIUM}/Profile {n}/Preferences"), "{}");
    }
    let index = PackageIndex::with_foreign(HashSet::new());
    let scope = Scope {
        root,
        home: Some(HOME),
        index: &index,
        origin: Origin::System,
    };
    let (items, unchecked) = found(&scope);
    assert_eq!(items.len(), MAX_EXTENSIONS);
    assert!(items.iter().all(|item| item.alerts.is_empty()), "{items:?}");
    assert_eq!(
        unchecked,
        [
            format!(
                "/{CHROMIUM}: more than {MAX_PROFILES} profiles; the extensions of the rest were not checked"
            ),
            format!(
                "/{CHROMIUM}/Default: more than {MAX_EXTENSIONS} extensions; the rest were not checked"
            ),
        ]
    );
}

#[test]
fn an_unread_manifest_is_said_and_only_the_store_mark_keeps_it_from_an_alert() {
    let dir = TempDir::new("sweep-extensions-manifest");
    let root = dir.path();
    let profile = format!("{CHROMIUM}/Default");
    // A manifest that is a directory cannot be read.
    for id in [STORE_ID, PACKAGED_ID] {
        fs::create_dir_all(
            root.join(&profile)
                .join(format!("Extensions/{id}/1/manifest.json")),
        )
        .unwrap();
    }
    write(
        root,
        &format!("{profile}/Extensions/{ELSEWHERE_ID}/1/manifest.json"),
        r#"{"name":"__MSG_name__","default_locale":"en","update_url":"https://clients2.google.com/service/update2/crx"}"#,
    );
    fs::create_dir_all(root.join(&profile).join(format!(
        "Extensions/{ELSEWHERE_ID}/1/_locales/en/messages.json"
    )))
    .unwrap();
    // The copy in the preferences names the store; the manifest the browser
    // loads names another host.
    write(
        root,
        &format!("{profile}/Extensions/{COMPONENT_ID}/1/manifest.json"),
        r#"{"update_url":"https://updates.example/crx"}"#,
    );
    let entry =
        |id: &str, extra: &str| format!(r#""{id}":{{"location":1,"path":"{id}/1"{extra}}}"#);
    // An unpacked one updates from nowhere: its unread manifest changes
    // nothing of what is said of it.
    fs::create_dir_all(root.join("home/u/dev/ext/manifest.json")).unwrap();
    let settings = [
        format!(r#""{UNPACKED_ID}":{{"location":4,"path":"/home/u/dev/ext"}}"#),
        entry(STORE_ID, r#","from_webstore":true"#),
        entry(PACKAGED_ID, ""),
        entry(ELSEWHERE_ID, ""),
        entry(
            COMPONENT_ID,
            r#","manifest":{"update_url":"https://clients2.google.com/service/update2/crx"}"#,
        ),
    ];
    write(
        root,
        &format!("{profile}/Preferences"),
        &format!(
            r#"{{"extensions":{{"settings":{{{}}}}}}}"#,
            settings.join(",")
        ),
    );
    let index = PackageIndex::with_foreign(HashSet::new());
    let scope = Scope {
        root,
        home: Some(HOME),
        index: &index,
        origin: Origin::System,
    };
    let (items, unchecked) = found(&scope);
    let not_checked = |id: &str| {
        unchecked.iter().any(|sentence| {
            sentence.contains(&format!("{id}/1/manifest.json: not a file that can be read; where /{profile}#extension:{id} updates from was not checked"))
        })
    };
    assert!(
        not_checked(STORE_ID) && not_checked(PACKAGED_ID),
        "{unchecked:?}"
    );
    assert_eq!(unchecked.len(), 2, "{unchecked:?}");
    assert!(
        by_id(&items, UNPACKED_ID).unwrap().alerts[0]
            .1
            .starts_with("loaded unpacked from /home/u/dev/ext")
    );

    // Marked as from the store: a note, no alert.
    let marked = by_id(&items, STORE_ID).unwrap();
    assert!(marked.alerts.is_empty(), "{:?}", marked.alerts);
    assert_eq!(marked.tier, Tier::Unknown);
    assert_eq!(
        marked.notes[1],
        "marked as from the Chrome Web Store, but its manifest could not be read: where it updates from was not checked"
    );
    // Without the mark, an unread manifest is no reason to trust it.
    let unmarked = by_id(&items, PACKAGED_ID).unwrap();
    assert_eq!(
        unmarked.alerts[0].1,
        "installed from outside the Chrome Web Store"
    );

    // The catalogue only names it: the store's update URL still counts.
    let unnamed = by_id(&items, ELSEWHERE_ID).unwrap();
    assert!(unnamed.alerts.is_empty(), "{:?}", unnamed.alerts);
    assert_eq!(
        unnamed.notes[0],
        "Chromium extension (no name found) (no version found)"
    );
    assert!(
        unnamed.notes[1].starts_with("its message catalogue could not be read ("),
        "{:?}",
        unnamed.notes
    );

    let copied = by_id(&items, COMPONENT_ID).unwrap();
    assert_eq!(
        copied.alerts[0].1,
        "installed from outside the Chrome Web Store (from updates.example)"
    );
}

#[test]
fn a_profile_whose_name_is_not_utf8_is_said() {
    use std::ffi::OsStr;
    use std::os::unix::ffi::OsStrExt as _;

    let dir = TempDir::new("sweep-extensions-names");
    let root = dir.path();
    let firefox = root.join("home/u/.mozilla/firefox");
    fs::create_dir_all(firefox.join(OsStr::from_bytes(b"bad\xff"))).unwrap();
    let index = PackageIndex::with_foreign(HashSet::new());
    let scope = Scope {
        root,
        home: Some(HOME),
        index: &index,
        origin: Origin::System,
    };
    let (items, unchecked) = found(&scope);
    assert!(items.is_empty());
    assert_eq!(
        unchecked,
        [
            "/home/u/.mozilla/firefox/bad\u{fffd}: a name that is not UTF-8; its extensions were not checked"
        ]
    );
}

#[test]
fn a_firefox_extension_without_a_signature_state_is_unsigned() {
    let dir = TempDir::new("sweep-extensions-signed");
    let root = dir.path();
    write(
        root,
        "home/u/.mozilla/firefox/abc.default/extensions.json",
        r#"{"addons":[
            {"id":"missing@example","type":"extension","location":"app-profile","sourceURI":"https://addons.mozilla.org/x.xpi"},
            {"id":"zero@example","type":"extension","location":"app-profile","signedState":0,"sourceURI":"https://addons.mozilla.org/x.xpi"},
            {"id":"signed@example","type":"extension","location":"app-profile","signedState":1,"sourceURI":"https://addons.mozilla.org/x.xpi"}
        ]}"#,
    );
    let index = PackageIndex::with_foreign(HashSet::new());
    let scope = Scope {
        root,
        home: Some(HOME),
        index: &index,
        origin: Origin::System,
    };
    let (items, _) = found(&scope);
    let alerts: Vec<Option<&str>> = items
        .iter()
        .map(|item| item.alerts.first().map(|(_, seen)| seen.as_str()))
        .collect();
    assert_eq!(
        alerts,
        [
            Some("not signed by Mozilla"),
            Some("not signed by Mozilla"),
            None
        ]
    );
}

#[test]
fn only_the_host_of_an_update_url_is_shown() {
    assert_eq!(
        host("https://u:p@Example.org:1/x?y#z").as_deref(),
        Some("example.org")
    );
    assert_eq!(host("not a url"), None);
    assert_eq!(host("https:///x"), None);
}

/// No extension goes to the AI: what decides it is the sweep's own rule.
#[test]
fn extensions_are_kept_from_the_review() {
    use crate::config::Settings;
    use crate::config::file::PartialConfig;
    use crate::config::model::{Profile, SourceClass};
    use crate::review::ReviewContext;
    use crate::test_support::mock_opencode_findings;
    use crate::tools::OpenCode;

    let dir = TempDir::new("sweep-extensions-judge");
    let index = chromium_profile(dir.path());
    let scope = Scope {
        root: dir.path(),
        home: Some(HOME),
        index: &index,
        origin: Origin::System,
    };
    let collection = Collection {
        items: check(&scope).items,
        ..Collection::default()
    };
    let bin = TempDir::new("sweep-extensions-judge-bin");
    let opencode = OpenCode::At(mock_opencode_findings(bin.path(), "clear", &[]));
    let settings = Settings::from_parts(PartialConfig::default(), PartialConfig::default())
        .with_profile(Profile::Standard);
    let context = ReviewContext {
        settings: &settings,
        class: SourceClass::System,
        opencode: &opencode,
        units: &[],
        state_root: None,
        context: &[],
    };
    let report = crate::sweep::judge::judge(&collection, Some(HOME), &context, &HashSet::new());
    assert!(report.agent_runs.is_empty() && report.agent_input.is_empty());
    let rules: Vec<RuleId> = report.findings.iter().map(|finding| finding.rule).collect();
    assert_eq!(
        rules,
        [RuleId::RiskyConfiguration, RuleId::RiskyConfiguration]
    );
}
