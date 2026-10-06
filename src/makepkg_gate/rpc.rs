//! What the AUR's RPC says about the package being built, as facts for the
//! reviews: its record, its trust signals and look-alike names.

use std::path::Path;

use super::print_warnings;
use crate::aur::{self, AurInfo};
use crate::error::Error;
use crate::json::Json;
use crate::osv;
use crate::pacman;
use crate::tools::{self, Limits};

const RPC_URL: &str = "https://aur.archlinux.org/rpc/v5/info";
const RPC_SEARCH_URL: &str = "https://aur.archlinux.org/rpc/v5/search";
const RPC_LIMITS: Limits = Limits {
    timeout_secs: 20,
    max_output: 1024 * 1024,
};
/// The AUR's facts about `base` (a confirmed AUR clone) for the reviews,
/// printing its summary and any trust warnings. Without a confirmed
/// identity, only that fact.
pub(super) fn aur_facts(base: Option<&str>, directory_name: &str, recipe: &str) -> Vec<String> {
    let mut facts = Vec::new();
    let Some(base) = base else {
        let fact = format!(
            "The build directory {directory_name:?} is not a clone of an AUR package (a local or private PKGBUILD); no AUR facts apply."
        );
        outln!("{fact}");
        facts.push(fact);
        return facts;
    };
    let mut names = vec![base.to_string()];
    names.extend(aur::declared_names(recipe));
    names.dedup();
    match aur_info(base, &names) {
        Ok(Some(info)) => {
            let now = crate::time::now();
            let (found, mut warnings) = aur::trust_signals(&info, now);
            if let Some(summary) = found.first() {
                outln!("{summary}");
            }
            facts.extend(found);
            warnings.extend(lookalikes(&info));
            print_warnings("AUR trust signals", &warnings);
            facts.extend(
                warnings
                    .iter()
                    .map(|warning| format!("Guardian's AUR check warns: {warning}.")),
            );
        }
        Ok(None) => {
            let fact = format!("{base} is not a package base in the AUR.");
            outln!("{fact}");
            facts.push(fact);
        }
        // The build goes on without them, and both the user and the AI
        // are told that they are missing, not that they are fine.
        Err(error) => {
            errln!("Guardian: AUR metadata unavailable ({error}).");
            print_warnings("AUR trust signals", &[aur::TRUST_UNKNOWN.to_string()]);
            facts.push(aur::TRUST_UNKNOWN.to_string());
        }
    }
    facts
}

/// Known packages a little-voted package's name could be taken for (see
/// `aur::lookalikes`). The official names come from pacman's own databases
/// on this machine; the AUR is asked once, and sent only the name. Without
/// either, that part is not checked.
fn lookalikes(info: &AurInfo) -> Vec<String> {
    if !aur::is_little_voted(info.votes) {
        return Vec::new();
    }
    let official: Vec<String> = tools::run(
        Path::new(tools::PACMAN),
        &["-Slq".into()],
        None,
        &[],
        RPC_LIMITS,
    )
    .and_then(tools::Captured::into_success)
    .map(|names| {
        String::from_utf8_lossy(&names)
            .lines()
            .map(str::to_string)
            .collect()
    })
    .unwrap_or_default();
    let searched = aur::lookalike_search_term(&info.name)
        .filter(|term| pacman::is_valid_package_name(term))
        .and_then(|term| {
            let mut args = osv::curl_args();
            args.push(format!("{RPC_SEARCH_URL}/{}?by=name", url_encoded(&term)).into());
            let body = tools::run(Path::new(tools::CURL), &args, None, &[], RPC_LIMITS)
                .and_then(tools::Captured::into_success)
                .ok()?;
            Json::parse(&String::from_utf8_lossy(&body)).ok()
        })
        .map(|reply| aur::parse_rpc_search(&reply))
        .unwrap_or_default();
    aur::lookalikes(&info.name, info.votes, &official, &searched)
}

/// A package name as part of an address.
fn url_encoded(name: &str) -> String {
    name.chars()
        .map(|character| match character {
            '+' => "%2B".to_string(),
            '@' => "%40".to_string(),
            other => other.to_string(),
        })
        .collect()
}

/// The AUR's record of the package base `base`, looked up by `names`.
fn aur_info(base: &str, names: &[String]) -> Result<Option<AurInfo>, Error> {
    let query: Vec<String> = names
        .iter()
        .filter(|name| pacman::is_valid_package_name(name))
        .take(20)
        .map(|name| format!("arg[]={}", url_encoded(name)))
        .collect();
    if query.is_empty() {
        return Ok(None);
    }
    let fetch = |over_ipv4: bool| {
        let mut args = osv::curl_args();
        if over_ipv4 {
            args.push("--ipv4".into());
        }
        args.push(format!("{RPC_URL}?{}", query.join("&")).into());
        tools::run(Path::new(tools::CURL), &args, None, &[], RPC_LIMITS)
            .and_then(tools::Captured::into_success)
    };
    // A second try over IPv4: the AUR has answered there while dropping
    // every IPv6 connection, and curl does not fall back by itself once the
    // connection was made.
    let body = fetch(false).or_else(|_| fetch(true))?;
    let reply = Json::parse(&String::from_utf8_lossy(&body))
        .map_err(|error| Error::parse("the AUR reply", error))?;
    Ok(aur::parse_rpc_info(&reply, base))
}
