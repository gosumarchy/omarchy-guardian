//! The report as a self-contained HTML page, which a block notification
//! opens. Dark by default with the Guardian knight; a CSS-only switch gives a
//! light theme. Everything taken from the review (paths, code excerpts, the
//! AI's words) is escaped, and the Content-Security-Policy allows no script,
//! no network request and no external resource, so reviewed content cannot
//! run or load anything in the browser.

use std::fmt::Write as _;
use std::sync::{Mutex, PoisonError};

use super::{AgentOutcome, Decision, Report, Severity, recommendation};
use crate::agent::Status;
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
pub fn page(title: &str, detail: &str, when: &str, id: &str, fallback: &str) -> String {
    let sections = SECTIONS
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .join("\n");
    let body = if sections.is_empty() {
        format!(
            "<section class=\"card\"><h2>Output</h2><pre class=\"code\">{}</pre></section>",
            esc(&strip_ansi(fallback))
        )
    } else {
        sections
    };
    format!(
        r#"<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{title_text}</title>
<style>{STYLE}</style>
</head>
<body>
<input type="checkbox" id="light" class="theme-switch">
<div class="page">
<header class="hero">
  <div class="knight">{KNIGHT}</div>
  <div class="hero-text">
    <div class="eyebrow">Omarchy Guardian · blocked</div>
    <h1>{title_text}</h1>
    <p class="detail">{detail_text}</p>
    <p class="meta">{when_text}</p>
  </div>
  <label for="light" class="toggle" title="Switch theme"><span class="to-light">☀ Light</span><span class="to-dark">☾ Dark</span></label>
</header>
<div class="banner">Nothing from this source ran: Guardian stopped it before any of its code could run.</div>
<div class="ask-row">
  <a class="ask" href="omarchy-guardian://ask/{id_text}">✦ Ask your AI agent about this report</a>
  <span class="ask-note">Opens Claude Code (or OpenCode) in a terminal with this report and no tools, so nothing in the report can make it run anything.</span>
</div>
{body}
<footer>Omarchy Guardian {version} · this report is saved on your machine and was not sent anywhere · a clear review is not a safety guarantee</footer>
</div>
</body>
</html>
"#,
        title_text = esc(title),
        detail_text = esc(detail),
        when_text = esc(when),
        id_text = esc(id),
        version = env!("CARGO_PKG_VERSION"),
    )
}

fn section(report: &Report, decision: Decision) -> String {
    let mut html = String::new();
    let (headline, color) = report.headline(decision);
    let counts = report.counts();
    let _ = write!(
        html,
        r#"<section class="card"><div class="verdict {tone}">{headline}</div><h2 class="subject">{subject}</h2><div class="chips">"#,
        tone = tone(color),
        headline = esc(&headline),
        subject = esc(&report.subject),
    );
    for (label, count, class) in [
        ("High", counts.high, "sev-high"),
        ("Medium", counts.medium, "sev-medium"),
        ("Low", counts.low, "sev-low"),
    ] {
        let class = if count > 0 { class } else { "muted" };
        let _ = write!(
            html,
            r#"<span class="chip {class}"><b>{count}</b> {label}</span>"#
        );
    }
    let _ = write!(
        html,
        r#"<span class="chip"><b>{}</b> text files reviewed</span><span class="chip"><b>{}</b> binary files hashed</span></div>"#,
        report.text_files_reviewed,
        report.snapshot.count(FileKind::Binary)
    );

    ai_reviews(&mut html, report);
    findings(&mut html, report);
    extras(&mut html, report);

    let _ = write!(
        html,
        r#"<div class="advice">{}</div></section>"#,
        esc(recommendation(decision))
    );
    html
}

fn ai_reviews(html: &mut String, report: &Report) {
    if report.agent_runs.is_empty() && !report.agent_input_overflowed {
        return;
    }
    html.push_str("<h3>AI review</h3>");
    if report.agent_input_overflowed {
        html.push_str(r#"<div class="ai tone-amber"><p>Not run: the source exceeds the AI input limit.</p></div>"#);
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
                    Status::Clear => "tone-green",
                    Status::Suspicious => "tone-red",
                    Status::Inconclusive => "tone-amber",
                },
                review.summary.clone(),
            ),
            AgentOutcome::Unavailable(error) => ("UNAVAILABLE", "tone-amber", error.to_string()),
        };
        let _ = write!(
            html,
            r#"<div class="ai {tone}"><div class="ai-head"><span class="pill">{label}</span><span class="meta">{meta}</span></div><p>{text}</p></div>"#,
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
    let class = match severity {
        Severity::High => "sev-high",
        Severity::Medium => "sev-medium",
        Severity::Low => "sev-low",
    };
    let _ = write!(
        html,
        r#"<article class="finding {class}"><div class="finding-head"><span class="sev">{sev}</span><span class="source">{source}</span><code class="loc">{location}</code></div><h4>{title}</h4><p>{reason}</p>"#,
        sev = severity.label(),
        location = esc(location),
        title = esc(title),
        reason = esc(reason),
    );
    if let Some(excerpt) = excerpt {
        let _ = write!(html, r#"<pre class="code">{}</pre>"#, esc(excerpt));
    }
    html.push_str("</article>");
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
        html.push_str(r#"<h3>Why the review is incomplete</h3><ul class="gaps">"#);
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
        [b'3', b'1', ..] => "tone-red",
        [b'3', b'2', ..] => "tone-green",
        [b'3', b'6', ..] => "tone-cyan",
        _ => "tone-amber",
    }
}

/// Escapes text for HTML content and attribute values.
pub fn esc(text: &str) -> String {
    let mut escaped = String::with_capacity(text.len());
    for character in text.chars() {
        match character {
            '&' => escaped.push_str("&amp;"),
            '<' => escaped.push_str("&lt;"),
            '>' => escaped.push_str("&gt;"),
            '"' => escaped.push_str("&quot;"),
            '\'' => escaped.push_str("&#39;"),
            _ => escaped.push(character),
        }
    }
    escaped
}

/// Drops terminal colour sequences from captured output.
pub fn strip_ansi(text: &str) -> String {
    let mut plain = String::with_capacity(text.len());
    let mut characters = text.chars();
    while let Some(character) = characters.next() {
        if character == '\x1b' {
            for code in characters.by_ref() {
                if code.is_ascii_alphabetic() {
                    break;
                }
            }
        } else {
            plain.push(character);
        }
    }
    plain
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
:root{color-scheme:dark}
*{box-sizing:border-box}
html,body{margin:0;background:#16161e}
.theme-switch{position:absolute;opacity:0;pointer-events:none}
.page{
  --bg:#16161e;--card:#1f2335;--card2:#24283b;--line:#2f3549;--text:#c0caf5;--muted:#7a85b0;
  --red:#f7768e;--amber:#e0af68;--green:#9ece6a;--cyan:#7dcfff;--blue:#7aa2f7;--code:#13131a;
  min-height:100vh;background:var(--bg);color:var(--text);
  font:15px/1.55 ui-sans-serif,system-ui,-apple-system,"Segoe UI",sans-serif;padding:32px 20px 48px}
.theme-switch:checked ~ .page{
  --bg:#f3f4f8;--card:#ffffff;--card2:#f6f7fb;--line:#dde0ea;--text:#2b2f3f;--muted:#6b7190;
  --red:#d20f39;--amber:#b35c00;--green:#2f7d32;--cyan:#0369a1;--blue:#3451b2;--code:#f1f2f6;color-scheme:light}
.page>*{max-width:920px;margin-left:auto;margin-right:auto}
.hero{display:flex;gap:24px;align-items:center;padding:24px 28px;background:linear-gradient(135deg,var(--card),var(--card2));
  border:1px solid var(--line);border-radius:18px;position:relative}
.knight svg{width:104px;height:104px;display:block;filter:drop-shadow(0 6px 18px rgba(247,118,142,.35))}
.hero-text{flex:1;min-width:0}
.eyebrow{text-transform:uppercase;letter-spacing:.14em;font-size:12px;color:var(--red);font-weight:700}
h1{margin:6px 0 4px;font-size:26px;line-height:1.25;word-break:break-word}
.detail{margin:0;font-size:16px}
.meta{margin:6px 0 0;color:var(--muted);font-size:13px}
.toggle{position:absolute;top:16px;right:18px;cursor:pointer;font-size:12px;color:var(--muted);border:1px solid var(--line);
  border-radius:999px;padding:4px 12px;user-select:none}
.toggle:hover{color:var(--text)}
.to-dark{display:none}
.theme-switch:checked ~ .page .to-dark{display:inline}
.theme-switch:checked ~ .page .to-light{display:none}
.banner{margin-top:16px;padding:12px 18px;border-radius:12px;background:color-mix(in srgb,var(--green) 14%,transparent);
  border:1px solid color-mix(in srgb,var(--green) 40%,transparent);color:var(--green);font-weight:600}
.card{margin-top:20px;padding:24px 28px;background:var(--card);border:1px solid var(--line);border-radius:18px}
.verdict{display:inline-block;font-weight:800;letter-spacing:.02em;padding:6px 14px;border-radius:10px;font-size:14px}
.tone-red.verdict{background:color-mix(in srgb,var(--red) 18%,transparent);color:var(--red)}
.tone-amber.verdict{background:color-mix(in srgb,var(--amber) 18%,transparent);color:var(--amber)}
.tone-green.verdict{background:color-mix(in srgb,var(--green) 18%,transparent);color:var(--green)}
.tone-cyan.verdict{background:color-mix(in srgb,var(--cyan) 18%,transparent);color:var(--cyan)}
.subject{margin:12px 0 14px;font-size:15px;font-weight:600;color:var(--muted);word-break:break-all}
.chips{display:flex;flex-wrap:wrap;gap:8px}
.chip{padding:5px 12px;border-radius:999px;background:var(--card2);border:1px solid var(--line);font-size:13px;color:var(--muted)}
.chip b{color:var(--text)}
.chip.sev-high{border-color:var(--red)}.chip.sev-high b{color:var(--red)}
.chip.sev-medium{border-color:var(--amber)}.chip.sev-medium b{color:var(--amber)}
.chip.sev-low{border-color:var(--cyan)}.chip.sev-low b{color:var(--cyan)}
h3{margin:26px 0 10px;font-size:13px;text-transform:uppercase;letter-spacing:.12em;color:var(--muted)}
.ai{padding:14px 18px;border-radius:12px;background:var(--card2);border-left:4px solid var(--line);margin-bottom:10px}
.ai.tone-red{border-left-color:var(--red)}.ai.tone-green{border-left-color:var(--green)}.ai.tone-amber{border-left-color:var(--amber)}
.ai-head{display:flex;flex-wrap:wrap;gap:10px;align-items:center}
.ai p{margin:8px 0 0}
.pill{font-weight:800;font-size:12px;letter-spacing:.06em;padding:2px 10px;border-radius:999px;background:var(--line)}
.ai.tone-red .pill{color:var(--red)}.ai.tone-green .pill{color:var(--green)}.ai.tone-amber .pill{color:var(--amber)}
.ai .meta{margin:0}
.finding{padding:16px 18px;border-radius:12px;background:var(--card2);border:1px solid var(--line);border-left:4px solid var(--line);margin-bottom:12px}
.finding.sev-high{border-left-color:var(--red)}.finding.sev-medium{border-left-color:var(--amber)}.finding.sev-low{border-left-color:var(--cyan)}
.finding-head{display:flex;flex-wrap:wrap;gap:10px;align-items:center;font-size:12px}
.sev{font-weight:800;letter-spacing:.08em}
.sev-high .sev{color:var(--red)}.sev-medium .sev{color:var(--amber)}.sev-low .sev{color:var(--cyan)}
.source{color:var(--muted);text-transform:uppercase;letter-spacing:.08em}
.loc{margin-left:auto;color:var(--blue)}
.finding h4{margin:8px 0 4px;font-size:16px}
.finding p{margin:0}
code,pre{font-family:ui-monospace,"JetBrainsMono Nerd Font","JetBrains Mono",monospace;font-size:13px}
pre.code{margin:10px 0 0;padding:12px 14px;background:var(--code);border:1px solid var(--line);border-radius:10px;
  white-space:pre-wrap;word-break:break-all;overflow:auto}
table{width:100%;border-collapse:collapse;font-size:13px}
th,td{text-align:left;padding:8px 10px;border-bottom:1px solid var(--line)}
th{color:var(--muted);font-weight:600}
ul{margin:0;padding-left:20px}
.gaps li{color:var(--amber)}
details{margin-top:22px;padding:12px 16px;border-radius:12px;background:var(--card2);border:1px solid var(--line)}
summary{cursor:pointer;color:var(--muted);font-weight:600}
details ul{margin-top:10px}
.integrity{margin:18px 0 0;color:var(--muted);font-size:12px;word-break:break-all}
.advice{margin-top:20px;padding:14px 18px;border-radius:12px;background:color-mix(in srgb,var(--blue) 12%,transparent);
  border:1px solid color-mix(in srgb,var(--blue) 35%,transparent);font-weight:600}
.ask-row{display:flex;flex-wrap:wrap;gap:12px;align-items:center;margin-top:16px}
.ask{display:inline-block;padding:10px 18px;border-radius:12px;font-weight:700;text-decoration:none;color:#16161e;
  background:linear-gradient(135deg,var(--blue),var(--cyan));box-shadow:0 6px 18px color-mix(in srgb,var(--blue) 35%,transparent)}
.ask:hover{filter:brightness(1.08)}
.ask-note{color:var(--muted);font-size:13px;flex:1;min-width:240px}
footer{margin-top:28px;text-align:center;color:var(--muted);font-size:12px}
@media (max-width:640px){.hero{flex-direction:column;text-align:center}.toggle{position:static}.loc{margin-left:0}}
"#;

#[cfg(test)]
mod tests {
    use super::{esc, page, strip_ansi, utc};

    #[test]
    fn reviewed_content_is_escaped() {
        assert_eq!(
            esc(r#"<script>alert("x")</script> & 'y'"#),
            "&lt;script&gt;alert(&quot;x&quot;)&lt;/script&gt; &amp; &#39;y&#39;"
        );
        let html = page("t", "<img src=x onerror=alert(1)>", "now", "1-2", "");
        assert!(!html.contains("<img src=x"));
        assert!(html.contains("default-src 'none'"));
    }

    #[test]
    fn colour_codes_are_dropped_and_times_are_utc() {
        assert_eq!(strip_ansi("\x1b[31;1mHIGH\x1b[0m risk"), "HIGH risk");
        assert_eq!(utc(0), "1970-01-01 00:00 UTC");
        assert_eq!(utc(1_790_792_730), "2026-09-30 18:25 UTC");
    }
}
