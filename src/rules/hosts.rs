//! Hosts that deliver or receive data for anyone, without an account that
//! ties them to a project.
//!
//! Software fetches from its own site, a forge or a package index. A paste
//! site, a chat webhook, a tunnel to someone's laptop or a link shortener
//! is where a stolen file is sent, or where a second stage is fetched from,
//! because nothing there names its owner. Ordinary tools use them too (a
//! log uploader, a notification hook), so this is a finding to look at, not
//! proof.

/// A host, and the start of the path that makes it one of these. Without a
/// path every address on the host counts. A host matches by itself and as
/// the parent of any subdomain.
const DROP_HOSTS: &[(&str, &str)] = &[
    // Chat webhooks and bot APIs: a message to a channel the author owns.
    // The path tells them from the service's site and its documented API.
    ("discord.com", "/api/webhooks"),
    ("discordapp.com", "/api/webhooks"),
    ("api.telegram.org", "/bot"),
    ("hooks.slack.com", "/services"),
    // Paste sites and anonymous file hosts.
    ("pastebin.com", ""),
    ("paste.ee", ""),
    ("hastebin.com", ""),
    ("ghostbin.com", ""),
    ("ghostbin.co", ""),
    ("rentry.co", ""),
    ("rentry.org", ""),
    ("dpaste.com", ""),
    ("dpaste.org", ""),
    ("termbin.com", ""),
    ("ix.io", ""),
    ("sprunge.us", ""),
    ("0x0.st", ""),
    ("transfer.sh", ""),
    ("file.io", ""),
    ("catbox.moe", ""),
    ("anonfiles.com", ""),
    ("gofile.io", ""),
    ("bashupload.com", ""),
    ("temp.sh", ""),
    ("oshi.at", ""),
    // Tunnels to a machine behind a home connection, and request catchers.
    ("ngrok.io", ""),
    ("ngrok.app", ""),
    ("ngrok-free.app", ""),
    ("trycloudflare.com", ""),
    ("serveo.net", ""),
    ("localhost.run", ""),
    ("loca.lt", ""),
    ("pipedream.net", ""),
    ("webhook.site", ""),
    ("requestbin.com", ""),
    ("requestbin.net", ""),
    ("interact.sh", ""),
    ("oast.fun", ""),
    ("oast.pro", ""),
    ("oast.live", ""),
    ("oast.site", ""),
    ("oast.online", ""),
    ("oast.me", ""),
    ("oastify.com", ""),
    ("burpcollaborator.net", ""),
    ("canarytokens.com", ""),
    ("canarytokens.org", ""),
    // Dynamic DNS: a name that follows a home connection around.
    ("duckdns.org", ""),
    ("ddns.net", ""),
    ("no-ip.org", ""),
    ("no-ip.biz", ""),
    ("dynu.net", ""),
    ("hopto.org", ""),
    ("zapto.org", ""),
    ("sytes.net", ""),
    // Tor hidden services.
    ("onion", ""),
    // Link shorteners: the address says nothing about where it leads.
    ("bit.ly", ""),
    ("tinyurl.com", ""),
    ("t.co", ""),
    ("is.gd", ""),
    ("cutt.ly", ""),
    ("rb.gy", ""),
    ("shorturl.at", ""),
];

/// Whether an address on `host` with `path` (both lowercased, the path
/// starting with `/` or empty) is one of the destinations above.
pub fn is_drop_destination(host: &str, path: &str) -> bool {
    let host = host.trim_end_matches('.');
    DROP_HOSTS.iter().any(|(known, prefix)| {
        let on_host = host
            .strip_suffix(known)
            .is_some_and(|parent| parent.is_empty() || parent.ends_with('.'));
        // A doubled slash still reaches the same handler.
        let path = path.trim_start_matches('/');
        on_host && path.starts_with(prefix.trim_start_matches('/'))
    })
}

#[cfg(test)]
mod tests {
    use super::is_drop_destination;

    #[test]
    fn hosts_that_take_data_from_anyone_are_named() {
        for (host, path) in [
            ("discord.com", "/api/webhooks/1/abc"),
            ("discordapp.com", "//api/webhooks/1/abc"),
            ("api.telegram.org", "/bot123:abc/senddocument"),
            ("hooks.slack.com", "/services/t/b/x"),
            ("pastebin.com", "/raw/abc"),
            ("0x0.st", ""),
            ("files.catbox.moe", "/x.sh"),
            ("litterbox.catbox.moe", "/resources/internals/api.php"),
            ("a1b2.ngrok-free.app", "/i"),
            ("x.trycloudflare.com", "/"),
            ("en1.m.pipedream.net", "/"),
            ("abc.oast.fun", "/"),
            ("home.duckdns.org", "/p"),
            ("abcdefghijklmnop.onion", "/"),
            ("bit.ly", "/3xyz"),
            ("t.co", "/abc"),
        ] {
            assert!(is_drop_destination(host, path), "{host}{path}");
        }
        for (host, path) in [
            // The service itself, its documented API, its downloads.
            ("discord.com", "/api/v10/channels/1/messages"),
            ("discord.com", "/download"),
            ("telegram.org", "/dl/desktop/linux"),
            ("api.telegram.org", "/file/x"),
            ("slack.com", "/downloads"),
            ("hooks.slack.com", ""),
            // Names that only end alike.
            ("mypastebin.com", ""),
            ("notbit.ly", ""),
            ("format.co", "/x"),
            ("microsoft.com", "/"),
            ("onion.example.com", "/"),
            ("ngrok.com", "/download"),
            ("github.com", "/x/y"),
            ("raw.githubusercontent.com", "/x/y/main/install.sh"),
            ("gist.githubusercontent.com", "/x/abc/raw/i.sh"),
        ] {
            assert!(!is_drop_destination(host, path), "{host}{path}");
        }
    }
}
