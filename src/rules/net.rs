//! Network destinations in a line: schemes, URL and host extraction, and
//! what is of concern about a host.

use std::net::IpAddr;
use std::path::Path;

use super::{hidden, hosts};

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub(crate) enum Scheme {
    Http,
    Https,
}

impl Scheme {
    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            Self::Http => "http",
            Self::Https => "https",
        }
    }
}

/// Literal HTTP(S) destinations in a line, reduced to scheme and host so
/// paths, queries and credentials in URLs are never echoed.
pub(crate) fn extract_network_destinations(line: &str) -> Vec<(Scheme, String)> {
    let mut result: Vec<(Scheme, String)> = destinations_with_path(line)
        .into_iter()
        .map(|(scheme, host, _)| (scheme, host))
        .collect();
    result.sort();
    result.dedup();
    result
}

/// How a host read from a URL is classified, kept apart so the path that
/// decides it is used but never stored (see `Report::network`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct HostConcern {
    /// A host made to read as another name (mixed scripts, a well-known
    /// host's name in front of another domain).
    pub(crate) lookalike: bool,
    /// A host commonly used to drop off or pick up stolen data.
    pub(crate) drop: bool,
}

/// Each literal HTTP(S) destination's host classified by the concerns its
/// name and path raise, with the path itself discarded.
pub(crate) fn host_concerns(line: &str) -> Vec<(String, HostConcern)> {
    destinations_with_path(line)
        .into_iter()
        .filter_map(|(_, host, path)| {
            let concern = HostConcern {
                lookalike: reads_as_another_host(&host),
                drop: hosts::is_drop_destination(&host, &path),
            };
            (concern.lookalike || concern.drop).then_some((host, concern))
        })
        .collect()
}

/// A host named to be taken for another: by its letters (see
/// `hidden::is_lookalike_host`), or by beginning with a well-known code
/// host's name while belonging to another domain.
fn reads_as_another_host(host: &str) -> bool {
    hidden::is_lookalike_host(host) || hosts::embeds_code_host(host)
}

/// Whether `code` names a host made to read as another that `quiet` does
/// not show: one in a recipe's `source=` or `url=`, which are declarations
/// and so no network requests of the recipe's own. Cleartext and bare
/// addresses there are makepkg's to fetch and check, but a source host
/// that passes for a forge is the typosquat itself.
pub(crate) fn declares_lookalike_host(code: &str, quiet: &str) -> bool {
    if code == quiet {
        return false;
    }
    let requested: Vec<String> = destinations_with_path(quiet)
        .into_iter()
        .map(|(_, host, _)| host)
        .collect();
    destinations_with_path(code)
        .into_iter()
        .any(|(_, host, _)| {
            !requested.contains(&host) && !is_local_host(&host) && reads_as_another_host(&host)
        })
}

/// The literal HTTP(S) destinations of a line as `(scheme, host, path)`.
/// The path (lowercased, query and fragment dropped) is for classification
/// only and is never recorded.
fn destinations_with_path(line: &str) -> Vec<(Scheme, String, String)> {
    let lower = line.to_ascii_lowercase();
    let mut result = Vec::new();
    let mut cursor = 0;
    // A DTD reference names a vocabulary; nothing requests it.
    let doctype = lower.contains("<!doctype");

    while cursor < lower.len() {
        // One search per candidate: finding each prefix separately rescans
        // the rest of the line for the absent one every time, which is
        // quadratic on a line of many `http://` URLs.
        let Some(offset) = lower[cursor..].find("http") else {
            break;
        };
        let candidate = &lower[cursor + offset..];
        let Some((prefix, scheme)) = [("https://", Scheme::Https), ("http://", Scheme::Http)]
            .into_iter()
            .find(|(prefix, _)| candidate.starts_with(prefix))
        else {
            cursor += offset + "http".len();
            continue;
        };

        let start = cursor + offset;
        let rest = &lower[start..];
        let end = rest
            .char_indices()
            .find_map(|(index, character)| {
                (character.is_whitespace()
                    || matches!(
                        character,
                        '"' | '\'' | '`' | '<' | '>' | ')' | ']' | '}' | ',' | ';'
                    ))
                .then_some(index)
            })
            .unwrap_or(rest.len());
        let url = rest[..end]
            .get(..512)
            .unwrap_or(&rest[..end])
            .trim_end_matches(['.', ':', '?', '!', '\\']);

        let after_scheme = &url[prefix.len().min(url.len())..];
        if let Some(host) = url_host(after_scheme)
            && !doctype
            && !Path::new(url)
                .extension()
                .is_some_and(|extension| extension == "dtd" || extension == "xsd")
            && !is_identifier_uri(&lower[..start])
        {
            // The path is what follows the authority, up to a query or
            // fragment: `/api/webhooks` of `host/api/webhooks?x=1`.
            let path = after_scheme
                .find('/')
                .map(|at| &after_scheme[at..])
                .unwrap_or_default()
                .split(['?', '#'])
                .next()
                .unwrap_or_default()
                .to_string();
            result.push((scheme, host, path));
        }
        cursor = start + end.max(prefix.len());
    }

    result
}

/// XML namespace and RDF URIs name a vocabulary; nothing requests them.
/// `before` is the lowercased text preceding the URL on its line.
fn is_identifier_uri(before: &str) -> bool {
    let Some(before) = before.strip_suffix(['"', '\'']) else {
        return false;
    };
    let Some(attribute) = before.trim_end().strip_suffix('=') else {
        return false;
    };
    let attribute = attribute
        .trim_end()
        .rsplit(|character: char| character.is_whitespace() || character == '<')
        .next()
        .unwrap_or_default();
    attribute == "xmlns"
        || attribute.starts_with("xmlns:")
        || matches!(
            attribute,
            "rdf:resource" | "rdf:about" | "xsi:schemalocation" | "xsi:nonamespaceschemalocation"
        )
}

fn url_host(after_scheme: &str) -> Option<String> {
    let authority = after_scheme
        .split(['/', '?', '#'])
        .next()
        .unwrap_or_default();
    let authority = authority.rsplit('@').next().unwrap_or_default();
    let host = if authority.starts_with('[') {
        authority
            .split_once(']')
            .map_or(authority, |(address, _)| address)
            .to_string()
            + "]"
    } else {
        authority.split(':').next().unwrap_or_default().to_string()
    };
    (!host.is_empty() && host != "]").then_some(host)
}

pub(crate) fn is_local_host(host: &str) -> bool {
    matches!(host, "localhost" | "127.0.0.1" | "::1" | "[::1]") || host.ends_with(".localhost")
}

pub(crate) fn is_ip_host(host: &str) -> bool {
    host.trim_start_matches('[')
        .trim_end_matches(']')
        .parse::<IpAddr>()
        .is_ok()
}
