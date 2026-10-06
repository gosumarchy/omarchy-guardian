//! Known-vulnerability lookup against the public OSV API.
//!
//! `/v1/querybatch` answers with advisory IDs only (plus a `next_page_token`
//! when a package has more than one page of them), so severities and
//! summaries come from a follow-up `/v1/vulns/{id}` fetch. That fetch is best
//! effort: an advisory blocks the gate whether or not its details arrived.

use std::collections::HashMap;
use std::ffi::OsString;
use std::path::Path;

use crate::deps::Dependency;
use crate::error::Error;
use crate::json::Json;
use crate::report::Severity;
use crate::tools::{self, Limits};

const QUERY_BATCH_URL: &str = "https://api.osv.dev/v1/querybatch";
const VULNERABILITY_URL: &str = "https://api.osv.dev/v1/vulns/";
const BATCH_SIZE: usize = 500;
const MAX_PACKAGES: usize = 20_000;
const MAX_DETAILED: usize = 50;
const LIMITS: Limits = Limits {
    timeout_secs: 60,
    max_output: 8 * 1024 * 1024,
};

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Advisory {
    pub(crate) id: String,
    pub(crate) package: String,
    pub(crate) version: String,
    pub(crate) lockfile: String,
    /// `None` when OSV did not provide a severity or details were unavailable.
    pub(crate) severity: Option<Severity>,
    pub(crate) summary: Option<String>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(crate) struct Audit {
    pub(crate) advisories: Vec<Advisory>,
    /// OSV had more advisories for some package than one response lists.
    pub(crate) truncated: bool,
}

pub(crate) fn audit(packages: &[Dependency]) -> Result<Audit, Error> {
    if packages.len() > MAX_PACKAGES {
        return Err(Error::Refused(format!(
            "dependency inventory exceeds the {MAX_PACKAGES}-package audit limit"
        )));
    }

    let mut audit = Audit::default();
    for batch in packages.chunks(BATCH_SIZE) {
        let response = post(QUERY_BATCH_URL, &batch_query(batch))?;
        collect_batch(&response, batch, &mut audit)?;
    }

    if let Ok(details) = fetch_details(&audit.advisories) {
        for advisory in &mut audit.advisories {
            if let Some((severity, summary)) = details.get(&advisory.id) {
                advisory.severity = *severity;
                advisory.summary.clone_from(summary);
            }
        }
    }
    Ok(audit)
}

fn batch_query(batch: &[Dependency]) -> Json {
    let queries = batch
        .iter()
        .map(|dependency| {
            Json::object([
                (
                    "package",
                    Json::object([
                        ("ecosystem", Json::from(dependency.ecosystem.osv_name())),
                        ("name", Json::from(dependency.name.as_str())),
                    ]),
                ),
                ("version", Json::from(dependency.version.as_str())),
            ])
        })
        .collect();
    Json::object([("queries", Json::Array(queries))])
}

fn collect_batch(response: &Json, batch: &[Dependency], audit: &mut Audit) -> Result<(), Error> {
    let results = response
        .get("results")
        .and_then(Json::as_array)
        .ok_or_else(|| Error::parse("the OSV response", "no results"))?;
    if results.len() != batch.len() {
        return Err(Error::parse(
            "the OSV response",
            "a different number of results than queried",
        ));
    }

    for (dependency, result) in batch.iter().zip(results) {
        audit.truncated |= result.get("next_page_token").is_some();
        let vulnerabilities = result
            .get("vulns")
            .and_then(Json::as_array)
            .unwrap_or_default();
        for vulnerability in vulnerabilities {
            let id = vulnerability
                .get("id")
                .and_then(Json::as_str)
                .filter(|id| is_valid_id(id))
                .ok_or_else(|| Error::parse("the OSV response", "invalid advisory id"))?;
            audit.advisories.push(Advisory {
                id: id.to_string(),
                package: dependency.name.clone(),
                version: dependency.version.clone(),
                lockfile: dependency.lockfile.clone(),
                severity: None,
                summary: None,
            });
        }
    }
    Ok(())
}

/// Advisory IDs are interpolated into URLs, so only their documented
/// character set is accepted.
fn is_valid_id(id: &str) -> bool {
    !id.is_empty()
        && id.len() <= 128
        && id
            .chars()
            .all(|character| character.is_ascii_alphanumeric() || "-_.:".contains(character))
}

type Details = HashMap<String, (Option<Severity>, Option<String>)>;

fn fetch_details(advisories: &[Advisory]) -> Result<Details, Error> {
    let mut ids: Vec<&str> = advisories
        .iter()
        .map(|advisory| advisory.id.as_str())
        .collect();
    ids.sort_unstable();
    ids.dedup();
    ids.truncate(MAX_DETAILED);
    if ids.is_empty() {
        return Ok(Details::new());
    }

    let mut args = curl_args();
    args.extend(
        ids.iter()
            .map(|id| OsString::from(format!("{VULNERABILITY_URL}{id}"))),
    );
    // Failed transfers write nothing, so whatever arrived is still usable.
    let captured = tools::run(Path::new(tools::CURL), &args, None, &[], LIMITS)?;
    let text = String::from_utf8_lossy(&captured.stdout);
    let records =
        Json::parse_stream(&text).map_err(|error| Error::parse("OSV advisories", error))?;

    Ok(records
        .iter()
        .filter_map(|record| {
            let id = record.get("id").and_then(Json::as_str)?;
            Some((
                id.to_string(),
                (advisory_severity(record), advisory_summary(record)),
            ))
        })
        .collect())
}

/// GitHub advisories carry a qualitative severity; other databases often
/// only have a CVSS vector, which is left unrated rather than guessed.
fn advisory_severity(record: &Json) -> Option<Severity> {
    let label = record
        .get("database_specific")
        .and_then(|specific| specific.get("severity"))
        .and_then(Json::as_str)?;
    match label.to_ascii_lowercase().as_str() {
        "critical" | "high" => Some(Severity::High),
        "moderate" | "medium" => Some(Severity::Medium),
        "low" => Some(Severity::Low),
        _ => None,
    }
}

fn advisory_summary(record: &Json) -> Option<String> {
    let text = record
        .get("summary")
        .and_then(Json::as_str)
        .or_else(|| record.get("details").and_then(Json::as_str))?;
    let line: String = text.lines().next()?.trim().chars().take(240).collect();
    (!line.is_empty()).then_some(line)
}

pub(crate) fn curl_args() -> Vec<OsString> {
    [
        "--disable",
        "--fail",
        "--silent",
        "--show-error",
        "--max-time",
        "50",
        "--proto",
        "=https",
        "--proto-redir",
        "=https",
    ]
    .into_iter()
    .map(OsString::from)
    .collect()
}

fn post(url: &str, body: &Json) -> Result<Json, Error> {
    let mut args = curl_args();
    args.extend(
        [
            "--header",
            "Content-Type: application/json",
            "--data-binary",
            "@-",
            url,
        ]
        .into_iter()
        .map(OsString::from),
    );
    let output = tools::run(
        Path::new(tools::CURL),
        &args,
        Some(body.to_string().as_bytes()),
        &[],
        LIMITS,
    )?
    .into_success()?;
    let text =
        String::from_utf8(output).map_err(|error| Error::parse("the OSV response", error))?;
    Json::parse(&text).map_err(|error| Error::parse("the OSV response", error))
}

#[cfg(test)]
mod tests {
    use super::{
        Audit, advisory_severity, advisory_summary, batch_query, collect_batch, is_valid_id,
    };
    use crate::deps::{Dependency, Ecosystem};
    use crate::json::Json;
    use crate::report::Severity;

    fn dependency(name: &str) -> Dependency {
        Dependency {
            ecosystem: Ecosystem::CratesIo,
            name: name.into(),
            version: "1.0.0".into(),
            lockfile: "Cargo.lock".into(),
        }
    }

    #[test]
    fn builds_the_documented_batch_query() {
        assert_eq!(
            batch_query(&[dependency("serde")]).to_string(),
            r#"{"queries":[{"package":{"ecosystem":"crates.io","name":"serde"},"version":"1.0.0"}]}"#
        );
    }

    #[test]
    fn collects_ids_and_notes_pagination() {
        let batch = [dependency("a"), dependency("b")];
        let response = Json::parse(
            r#"{"results":[{"vulns":[{"id":"RUSTSEC-2024-0001","modified":"x"}],"next_page_token":"t"},{}]}"#,
        )
        .unwrap();

        let mut audit = Audit::default();
        collect_batch(&response, &batch, &mut audit).unwrap();
        assert_eq!(audit.advisories.len(), 1);
        assert_eq!(audit.advisories[0].package, "a");
        assert!(audit.truncated);
    }

    #[test]
    fn rejects_mismatched_results_and_unsafe_ids() {
        let batch = [dependency("a")];
        let mut audit = Audit::default();
        assert!(
            collect_batch(
                &Json::parse(r#"{"results":[]}"#).unwrap(),
                &batch,
                &mut audit
            )
            .is_err()
        );
        assert!(
            collect_batch(
                &Json::parse(r#"{"results":[{"vulns":[{"id":"../../x?y"}]}]}"#).unwrap(),
                &batch,
                &mut audit
            )
            .is_err()
        );
        assert!(is_valid_id("GHSA-xxxx-yyyy-zzzz"));
        assert!(!is_valid_id("a/b"));
    }

    #[test]
    fn reads_severity_and_summary_from_details() {
        let record = Json::parse(
            r#"{"id":"GHSA-1","summary":"Bad thing\nmore","database_specific":{"severity":"MODERATE"}}"#,
        )
        .unwrap();
        assert_eq!(advisory_severity(&record), Some(Severity::Medium));
        assert_eq!(advisory_summary(&record).as_deref(), Some("Bad thing"));

        let unrated = Json::parse(r#"{"id":"RUSTSEC-1","details":"Only details"}"#).unwrap();
        assert_eq!(advisory_severity(&unrated), None);
        assert_eq!(advisory_summary(&unrated).as_deref(), Some("Only details"));
    }
}
