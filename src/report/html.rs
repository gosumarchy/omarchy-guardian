//! The report as a self-contained HTML page, which a block notification
//! opens. Dark by default with the Guardian knight; a CSS-only switch gives a
//! light theme. Everything taken from the review (paths, code excerpts, the
//! AI's words) is escaped, and the Content-Security-Policy allows no script,
//! no network request and no external resource, so reviewed content cannot
//! run or load anything in the browser.

use std::fmt::Write as _;
use std::sync::{Mutex, PoisonError};

use super::{AgentOutcome, Blocked, Decision, Report, Severity, recommendation};
use crate::agent::Status;
use crate::notify::Ran;
use crate::scan::FileKind;

const KNIGHT: &str = include_str!("../../integrations/icons/omarchy-guardian-alert.svg");

/// Sections for every report this run printed, in order (the makepkg gate
/// prints the recipe's, then the upstream sources').
static SECTIONS: Mutex<Vec<String>> = Mutex::new(Vec::new());

/// Remembers `report` for the page.
pub fn collect(report: &Report, decision: Decision) {
    let section = section(report, decision);
    SECTIONS
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .push(section);
}

/// The whole page: `title` and `detail` say what was blocked, `when` is a
/// UTC time, `id` names the saved report for the ask link, and `fallback`
/// is the printed output, shown when no report was collected (a gate that
/// stopped before reviewing).
pub fn page(title: &str, detail: &str, ran: Ran, when: &str, id: &str, fallback: &str) -> String {
    let sections = SECTIONS
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .join("\n");
    let body = if sections.is_empty() {
        format!(
            "<section><h3>Output</h3><pre class=\"code\">{}</pre></section>",
            esc(&strip_ansi(fallback))
        )
    } else {
        sections
    };
    let what = title.strip_prefix("Guardian blocked ").unwrap_or(title);
    format!(
        r#"<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{title_text}</title>
<style>:root{{{palette}}}{STYLE}</style>
</head>
<body>
<main>
<header class="hero">
  <div class="knight">{KNIGHT}</div>
  <div>
    <h1>Guardian</h1>
    <div class="meta">BLOCKED · {when_text}</div>
  </div>
</header>
<hr>
<div class="row lead"><span>Blocked {what_text}</span><span class="word red">BLOCKED</span></div>
<p class="dim">{detail_text}. {ran_text}</p>
{body}
<hr>
<h3>Next</h3>
<div class="tiles">
  <a class="tile" href="omarchy-guardian://ask/{id_text}"><span class="glyph">✦</span><span>Ask your AI agent</span></a>
</div>
<p class="dim small">Opens Claude Code (or OpenCode) in a terminal with this report and no tools. It can explain the report; do not run commands it quotes from the report.</p>
<footer>OMARCHY GUARDIAN {version} · SAVED ON THIS MACHINE ONLY · A CLEAR REVIEW IS NOT A SAFETY GUARANTEE</footer>
</main>
</body>
</html>
"#,
        palette = palette(),
        title_text = esc(title),
        what_text = esc(what),
        detail_text = esc(detail),
        ran_text = ran_text(ran),
        when_text = esc(when),
        id_text = esc(id),
        version = env!("CARGO_PKG_VERSION"),
    )
}

/// What had run when the gate blocked, for the page's first lines.
const fn ran_text(ran: Ran) -> &'static str {
    match ran {
        Ran::Nothing => {
            "Nothing from this source ran: Guardian stopped it before any of its code could run."
        }
        Ran::RecipeToFetch => {
            "Nothing was built or installed. The recipe (PKGBUILD) had passed review, and makepkg ran it to download and unpack the sources; Guardian stopped the build before any of the upstream code ran."
        }
    }
}

/// The page's colours from the current Omarchy theme (the shell reads the
/// same file), so the report looks like the rest of the desktop; dark
/// defaults without one. Only `#rrggbb` values are used.
fn palette() -> String {
    let path = std::env::var_os("XDG_STATE_HOME")
        .map(std::path::PathBuf::from)
        .or_else(|| {
            std::env::var_os("HOME").map(|home| std::path::PathBuf::from(home).join(".local/state"))
        })
        .map(|base| base.join("omarchy/current/theme/colors.toml"));
    let theme = path
        .and_then(|path| std::fs::read_to_string(path).ok())
        .unwrap_or_default();
    palette_from(&theme)
}

fn palette_from(theme: &str) -> String {
    let color = |key: &str, fallback: &str| -> String {
        theme
            .lines()
            .find_map(|line| {
                let (name, value) = line.split_once('=')?;
                (name.trim() == key).then(|| value.trim().trim_matches('"').to_string())
            })
            .filter(|value| {
                value.len() == 7
                    && value.starts_with('#')
                    && value[1..].bytes().all(|byte| byte.is_ascii_hexdigit())
            })
            .unwrap_or_else(|| fallback.to_string())
    };
    format!(
        "--bg:{};--fg:{};--accent:{};--red:{};--amber:{};--green:{};--cyan:{};",
        color("background", "#111418"),
        color("foreground", "#e6e1d6"),
        color("accent", "#f08a3c"),
        color("color1", "#e0604f"),
        color("color3", "#e0af68"),
        color("color2", "#9ece6a"),
        color("color6", "#7dcfff"),
    )
}

/// The verdict as one right-aligned word, like the shell's status words.
fn verdict_word(report: &Report, decision: Decision) -> &'static str {
    match decision {
        Decision::Clear => "CLEAR",
        Decision::Warned => "WARNED",
        Decision::Limited => "LIMITED",
        Decision::Blocked(Blocked::Findings) if report.counts().high > 0 => "HIGH RISK",
        Decision::Blocked(Blocked::Findings) => "REVIEW REQUIRED",
        Decision::Blocked(Blocked::Incomplete) => "INCOMPLETE",
        Decision::Blocked(Blocked::AiUnavailable) => "AI UNAVAILABLE",
        Decision::Blocked(Blocked::NotConfirmed) => "NOT CONFIRMED",
    }
}

fn section(report: &Report, decision: Decision) -> String {
    let mut html = String::new();
    let (_, color) = report.headline(decision);
    let counts = report.counts();
    let _ = write!(
        html,
        r#"<section><hr><div class="row"><span class="subject">{subject}</span><span class="word {tone}">{word}</span></div><div class="meta">{high} HIGH · {medium} MEDIUM · {low} LOW · {files} TEXT FILES REVIEWED · {binary} BINARY HASHED</div>"#,
        subject = esc(&report.subject),
        tone = tone(color),
        word = verdict_word(report, decision),
        high = counts.high,
        medium = counts.medium,
        low = counts.low,
        files = report.text_files_reviewed,
        binary = report.snapshot.count(FileKind::Binary),
    );

    ai_reviews(&mut html, report);
    findings(&mut html, report);
    extras(&mut html, report);

    let _ = write!(
        html,
        "<h3>Recommendation</h3><p>{}</p></section>",
        esc(recommendation(decision)
            .strip_prefix("Recommendation: ")
            .unwrap_or(recommendation(decision)))
    );
    html
}

fn ai_reviews(html: &mut String, report: &Report) {
    if report.agent_runs.is_empty() && !report.agent_input_overflowed {
        return;
    }
    html.push_str("<h3>AI review</h3>");
    if report.agent_input_overflowed {
        html.push_str(r#"<div class="row"><span>Not run: the source exceeds the AI input limit</span><span class="word amber">SKIPPED</span></div>"#);
    }
    for run in &report.agent_runs {
        let mut meta = esc(&run.label);
        if let Some((index, count)) = run.chunk {
            let _ = write!(meta, " · chunk {index}/{count}");
        }
        if let Some(note) = &run.cached {
            let _ = write!(meta, " · {}", esc(note));
        }
        let _ = write!(meta, " · profile {}", esc(&report.profile));
        let (label, tone, text) = match &run.outcome {
            AgentOutcome::Reviewed(review) => (
                review.status.label(),
                match review.status {
                    Status::Clear => "green",
                    Status::Suspicious => "red",
                    Status::Inconclusive => "amber",
                },
                review.summary.clone(),
            ),
            AgentOutcome::Unavailable(error) => ("UNAVAILABLE", "amber", error.to_string()),
        };
        let _ = write!(
            html,
            r#"<div class="item"><div class="row"><span>{meta}</span><span class="word {tone}">{label}</span></div><p>{text}</p></div>"#,
            text = esc(&text),
        );
    }
}

fn findings(html: &mut String, report: &Report) {
    let ai: Vec<_> = report
        .agent_runs
        .iter()
        .filter_map(|run| match &run.outcome {
            AgentOutcome::Reviewed(review) => Some(review.findings.iter()),
            AgentOutcome::Unavailable(_) => None,
        })
        .flatten()
        .collect();
    if report.findings.is_empty() && ai.is_empty() {
        return;
    }
    html.push_str("<h3>Findings</h3>");
    for finding in &ai {
        let location = finding.line.map_or_else(
            || finding.file.clone(),
            |line| format!("{}:{line}", finding.file),
        );
        finding_card(
            html,
            finding.severity,
            "AI",
            &finding.title,
            &location,
            &finding.reason,
            None,
        );
    }
    for finding in &report.findings {
        finding_card(
            html,
            finding.rule.severity(),
            "Local rule",
            finding.rule.name(),
            &format!("{}:{}", finding.path, finding.line),
            finding.rule.description(),
            Some(&finding.excerpt).filter(|excerpt| !excerpt.is_empty()),
        );
    }
}

fn finding_card(
    html: &mut String,
    severity: Severity,
    source: &str,
    title: &str,
    location: &str,
    reason: &str,
    excerpt: Option<&String>,
) {
    let tone = match severity {
        Severity::High => "red",
        Severity::Medium => "amber",
        Severity::Low => "cyan",
    };
    let _ = write!(
        html,
        r#"<div class="item"><div class="row"><span class="strong">{title}</span><span class="word {tone}">{sev}</span></div><div class="meta">{source} · {location}</div><p>{reason}</p>"#,
        sev = severity.label(),
        source = esc(&source.to_uppercase()),
        location = esc(location),
        title = esc(title),
        reason = esc(reason),
    );
    if let Some(excerpt) = excerpt {
        let _ = write!(html, r#"<pre class="code">{}</pre>"#, esc(excerpt));
    }
    html.push_str("</div>");
}

fn extras(html: &mut String, report: &Report) {
    if !report.network.is_empty() {
        let mut endpoints = report.network.clone();
        endpoints.sort();
        endpoints.dedup();
        html.push_str(
            "<h3>Network destinations</h3><table><tr><th>Where</th><th>Destination</th></tr>",
        );
        for endpoint in endpoints.iter().take(50) {
            let _ = write!(
                html,
                "<tr><td><code>{}:{}</code></td><td><code>{}://{}</code></td></tr>",
                esc(&endpoint.path),
                endpoint.line,
                endpoint.scheme.as_str(),
                esc(&endpoint.host)
            );
        }
        html.push_str("</table>");
    }
    if let Some(audit) = report
        .audit
        .as_ref()
        .filter(|audit| !audit.advisories.is_empty())
    {
        html.push_str("<h3>Known dependency vulnerabilities</h3><ul>");
        for advisory in &audit.advisories {
            let _ = write!(
                html,
                "<li><code>{}@{}</code> — {} {}</li>",
                esc(&advisory.package),
                esc(&advisory.version),
                esc(&advisory.id),
                esc(advisory.summary.as_deref().unwrap_or_default())
            );
        }
        html.push_str("</ul>");
    }
    if !report.gaps.is_empty() {
        html.push_str(r#"<h3>Why the review is incomplete</h3><ul class="amber">"#);
        for gap in &report.gaps {
            let _ = write!(html, "<li>{}</li>", esc(&gap.to_string()));
        }
        html.push_str("</ul>");
    }
    if !report.context.is_empty() || !report.notes.is_empty() {
        html.push_str(
            "<details><summary>What Guardian told the reviewer, and review memory</summary><ul>",
        );
        for line in report.context.iter().chain(&report.notes) {
            let _ = write!(html, "<li>{}</li>", esc(line));
        }
        html.push_str("</ul></details>");
    }
    if !report.snapshot.files().is_empty() {
        let _ = write!(
            html,
            r#"<p class="integrity">SHA-256 manifest <code>{}</code> · {} file(s) hashed</p>"#,
            report.snapshot.manifest_digest(),
            report.snapshot.files().len()
        );
    }
}

const fn tone(color: &str) -> &'static str {
    match color.as_bytes() {
        [b'3', b'1', ..] => "red",
        [b'3', b'2', ..] => "green",
        [b'3', b'6', ..] => "cyan",
        _ => "amber",
    }
}

/// Escapes text for HTML content and attribute values. A hidden character
/// (a control, bidirectional override or invisible character) is shown as a
/// visible code, so a file name cannot reorder or hide what the page says.
pub fn esc(text: &str) -> String {
    let mut escaped = String::with_capacity(text.len());
    for character in text.chars() {
        match character {
            '&' => escaped.push_str("&amp;"),
            '<' => escaped.push_str("&lt;"),
            '>' => escaped.push_str("&gt;"),
            '"' => escaped.push_str("&quot;"),
            '\'' => escaped.push_str("&#39;"),
            '\n' | '\t' => escaped.push(character),
            hidden if crate::text::is_hidden(hidden) => {
                let _ = write!(
                    escaped,
                    "<span class=\"ctl\">\\u{{{:x}}}</span>",
                    u32::from(hidden)
                );
            }
            _ => escaped.push(character),
        }
    }
    escaped
}

/// Drops terminal escape sequences (ECMA-48 CSI, OSC and other string
/// controls, and two-character escapes) from captured output.
pub fn strip_ansi(text: &str) -> String {
    let mut plain = String::with_capacity(text.len());
    let mut characters = text.chars().peekable();
    while let Some(character) = characters.next() {
        match character {
            '\x1b' => match characters.next() {
                Some('[') => skip_csi(&mut characters),
                Some(']' | 'P' | 'X' | '^' | '_') => skip_string(&mut characters),
                _ => {}
            },
            '\u{9b}' => skip_csi(&mut characters),
            '\u{9d}' | '\u{90}' | '\u{98}' | '\u{9e}' | '\u{9f}' => skip_string(&mut characters),
            _ => plain.push(character),
        }
    }
    plain
}

/// Skips a CSI sequence's parameter and intermediate bytes and its final byte.
fn skip_csi(characters: &mut impl Iterator<Item = char>) {
    for code in characters {
        if ('\u{40}'..='\u{7e}').contains(&code) || !('\u{20}'..='\u{7e}').contains(&code) {
            break;
        }
    }
}

/// Skips a control string up to its terminator: BEL, ST (`ESC \\`) or C1 ST.
fn skip_string(characters: &mut std::iter::Peekable<impl Iterator<Item = char>>) {
    while let Some(code) = characters.next() {
        match code {
            '\u{7}' | '\u{9c}' => break,
            '\x1b' => {
                if characters.peek() == Some(&'\\') {
                    characters.next();
                }
                break;
            }
            _ => {}
        }
    }
}

/// `seconds` since the epoch as `YYYY-MM-DD HH:MM UTC`.
pub fn utc(seconds: u64) -> String {
    let days = seconds / 86_400;
    let rest = seconds % 86_400;
    // Days to a civil date (Howard Hinnant's algorithm), for dates after 1970.
    let z = days + 719_468;
    let era = z / 146_097;
    let day_of_era = z % 146_097;
    let year_of_era =
        (day_of_era - day_of_era / 1460 + day_of_era / 36_524 - day_of_era / 146_096) / 365;
    let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    let mp = (5 * day_of_year + 2) / 153;
    let day = day_of_year - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = year_of_era + era * 400 + u64::from(month <= 2);
    format!(
        "{year:04}-{month:02}-{day:02} {:02}:{:02} UTC",
        rest / 3600,
        rest % 3600 / 60
    )
}

const STYLE: &str = r#"
*{box-sizing:border-box}
html,body{margin:0;background:var(--bg);color:var(--fg)}
body{font:14px/1.6 "JetBrainsMono Nerd Font","JetBrains Mono",ui-monospace,monospace;padding:40px 20px 56px}
main{max-width:760px;margin:0 auto;padding:28px 32px;border:1px solid color-mix(in srgb,var(--fg) 22%,transparent);
  background:color-mix(in srgb,var(--bg) 92%,var(--fg))}
.hero{display:flex;gap:22px;align-items:center}
.knight svg{width:64px;height:64px;display:block}
h1{margin:0;font-size:22px;font-weight:700;letter-spacing:.02em}
hr{border:0;border-top:1px solid color-mix(in srgb,var(--fg) 16%,transparent);margin:22px 0}
h3{margin:24px 0 12px;font-size:12px;font-weight:700;letter-spacing:.14em;text-transform:uppercase;
  color:color-mix(in srgb,var(--fg) 55%,transparent)}
.meta{font-size:12px;letter-spacing:.12em;color:color-mix(in srgb,var(--fg) 45%,transparent);word-break:break-word}
.dim{color:color-mix(in srgb,var(--fg) 62%,transparent)}
.small{font-size:12px}
.row{display:flex;justify-content:space-between;align-items:baseline;gap:18px}
.row>span:first-child{min-width:0;word-break:break-word}
.lead{font-size:17px;font-weight:700}
.subject{font-weight:700}
.strong{font-weight:700}
.word{flex:none;font-weight:700;letter-spacing:.1em;font-size:13px}
.red{color:var(--red)}.amber{color:var(--amber)}.green{color:var(--green)}.cyan{color:var(--cyan)}.accent{color:var(--accent)}
.item{padding:14px 0;border-bottom:1px solid color-mix(in srgb,var(--fg) 8%,transparent)}
.item:last-child{border-bottom:0}
.item p{margin:8px 0 0}
p{margin:10px 0 0}
pre.code{margin:12px 0 0;padding:12px 14px;background:color-mix(in srgb,var(--fg) 6%,transparent);
  white-space:pre-wrap;word-break:break-all;font:inherit;font-size:13px}
code{font:inherit}
.ctl{color:var(--red);font-weight:700}
table{width:100%;border-collapse:collapse}
th,td{text-align:left;padding:6px 0;border-bottom:1px solid color-mix(in srgb,var(--fg) 8%,transparent)}
th{font-size:12px;letter-spacing:.12em;text-transform:uppercase;font-weight:700;color:color-mix(in srgb,var(--fg) 55%,transparent)}
ul{margin:0;padding-left:18px}
details{margin-top:22px}
summary{cursor:pointer;font-size:12px;letter-spacing:.12em;text-transform:uppercase;font-weight:700;
  color:color-mix(in srgb,var(--fg) 55%,transparent)}
details ul{margin-top:10px}
.integrity{font-size:12px;color:color-mix(in srgb,var(--fg) 45%,transparent);word-break:break-all}
.tiles{display:grid;grid-template-columns:repeat(auto-fit,minmax(180px,1fr));gap:12px}
.tile{display:flex;flex-direction:column;align-items:center;gap:10px;padding:22px 12px;text-decoration:none;
  color:var(--fg);font-weight:700;background:color-mix(in srgb,var(--fg) 6%,transparent)}
.tile:hover{background:color-mix(in srgb,var(--fg) 12%,transparent)}
.glyph{font-size:26px;color:var(--accent);line-height:1}
footer{margin-top:28px;font-size:11px;letter-spacing:.12em;color:color-mix(in srgb,var(--fg) 40%,transparent)}
@media (max-width:640px){main{padding:20px}.row{flex-direction:column;gap:4px}}
"#;

#[cfg(test)]
mod tests {
    use super::{esc, page, strip_ansi, utc};
    use crate::notify::Ran;

    #[test]
    fn hidden_characters_are_shown_and_every_escape_is_dropped() {
        assert_eq!(esc("a\u{202e}b"), "a<span class=\"ctl\">\\u{202e}</span>b");
        assert_eq!(
            strip_ansi("x\x1b]52;c;eA==\x07y\x1b]0;t\x1b\\z\x1b[1;31mw\u{9b}2Jv"),
            "xyzwv"
        );
    }

    #[test]
    fn reviewed_content_is_escaped() {
        assert_eq!(
            esc(r#"<script>alert("x")</script> & 'y'"#),
            "&lt;script&gt;alert(&quot;x&quot;)&lt;/script&gt; &amp; &#39;y&#39;"
        );
        let html = page(
            "t",
            "<img src=x onerror=alert(1)>",
            Ran::Nothing,
            "now",
            "1-2",
            "",
        );
        assert!(!html.contains("<img src=x"));
        assert!(html.contains("default-src 'none'"));
        assert!(html.contains("Nothing from this source ran"));
    }

    #[test]
    fn the_page_says_when_the_recipe_ran_to_fetch() {
        let html = page("t", "d", Ran::RecipeToFetch, "now", "1-2", "");
        assert!(html.contains("had passed review"));
        assert!(!html.contains("Nothing from this source ran"));
    }

    #[test]
    fn the_palette_comes_from_the_theme_and_only_takes_hex_colours() {
        let palette = super::palette_from(
            "accent = \"#a87692\"\nbackground = \"#14111a\"\ncolor1 = \"red;}body{x\"\n",
        );
        assert!(palette.contains("--accent:#a87692;"));
        assert!(palette.contains("--bg:#14111a;"));
        assert!(palette.contains("--red:#e0604f;"));
        assert!(!palette.contains("body"));
    }

    #[test]
    fn colour_codes_are_dropped_and_times_are_utc() {
        assert_eq!(strip_ansi("\x1b[31;1mHIGH\x1b[0m risk"), "HIGH risk");
        assert_eq!(utc(0), "1970-01-01 00:00 UTC");
        assert_eq!(utc(1_790_792_730), "2026-09-30 18:25 UTC");
    }
}
