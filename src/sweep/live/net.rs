//! The live checks on sockets, from the kernel's tables under `/proc/net`
//! and the descriptors each process holds:
//!
//! - who listens for connections from the network (TCP), or waits for
//!   datagrams on a port of its choosing (UDP);
//! - a shell or interpreter whose input and output are a connection, the
//!   shape of a remote shell, which no listener check sees since the
//!   process called out;
//! - packaged tools that run or forward what they are told (netcat, socat,
//!   tunnels), listening or connected;
//! - raw packet sockets and interfaces that take in everybody's traffic.
//!
//! A socket is told from the pipes and local sockets every terminal, IDE
//! and language server puts on a program's input and output by finding its
//! inode in the kernel's table of network sockets: one that is not there
//! is not a network socket, and says nothing.

use std::collections::HashMap;
use std::fs;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::path::Path;

use super::{
    Found, Process, Running, is_interpreter, is_named, is_updated, packaged, plain,
    replaced_in_own_namespace, subject, told, trusted_program,
};
use crate::autorun::Category;
use crate::rules::RuleId;
use crate::sweep::collect::{Origin, Scope};
use crate::sweep::read::{self, View};

/// Shells: with a connection among their open files they are a remote
/// shell whatever their input is.
const SHELLS: &[&str] = &[
    "bash", "sh", "dash", "zsh", "fish", "tcsh", "csh", "ksh", "mksh", "ash",
];

/// Programs that are no interpreter of scripts but do what whoever is on
/// their input says.
const DRIVEN_BY_INPUT: &[&str] = &["gdb", "telnet"];

/// Packaged tools that run or forward what they are told over the network.
const RELAYS: &[&str] = &[
    "nc",
    "ncat",
    "netcat",
    "nc.openbsd",
    "nc.traditional",
    "socat",
    "systemd-socket-activate",
    "telnetd",
    "in.telnetd",
    "dropbear",
    "tcpserver",
    "xinetd",
    "inetd",
    "websocat",
    "chisel",
    "gost",
    "frpc",
    "frps",
    "ngrok",
    "cloudflared",
    "bore",
    "rathole",
    "busybox",
    "toybox",
];

/// Packaged desktop programs known to listen on the network by
/// themselves, with no unit that starts them.
const DESKTOP_LISTENERS: &[&str] = &[
    "chromium",
    "chrome",
    "firefox",
    "brave",
    "vivaldi-bin",
    "electron",
    "kdeconnectd",
    "spotify",
    "steam",
    "localsend",
    "syncthing",
    "dockerd",
    "docker-proxy",
    "rootlesskit",
    "slirp4netns",
    "pasta",
    "avahi-daemon",
    "cupsd",
    "sunshine",
];

/// UDP ports every desktop answers on: DHCP (and its pair for IPv6),
/// NTP, SSDP, mDNS and LLMNR.
const COMMON_UDP: &[u16] = &[67, 68, 123, 546, 547, 1900, 5353, 5355];

/// Programs that hold raw packet sockets to run the network.
const PACKET_USERS: &[&str] = &[
    "dhcpcd",
    "dhclient",
    "NetworkManager",
    "wpa_supplicant",
    "iwd",
    "systemd-networkd",
    "connmand",
    "hostapd",
    "pppd",
    "lldpd",
    "dnsmasq",
    "avahi-daemon",
    "tcpdump",
    "wireshark",
    "dumpcap",
    "tshark",
    "nmap",
    "arping",
];

/// Programs that capture traffic, which put an interface in promiscuous
/// mode while they run.
const CAPTURE_TOOLS: &[&str] = &["tcpdump", "wireshark", "dumpcap", "tshark"];

/// Kernel modules that listen by themselves (NFS, SMB, iSCSI and cluster
/// services): their sockets belong to no process.
const KERNEL_SERVERS: &[&str] = &[
    "nfsd",
    "lockd",
    "ksmbd",
    "iscsi_target_mod",
    "nvmet_tcp",
    "rds_tcp",
    "dlm",
    "ocfs2_nodemanager",
    "drbd",
    "smc",
];

/// Ports the kernel hands out by itself when nobody asks for one, unless
/// the system says otherwise.
const EPHEMERAL: (u16, u16) = (32768, 60999);

/// One socket of a `/proc/net/tcp{,6}` or `udp{,6}` table.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct Socket {
    /// Addresses as the table has them: hex, network order per 32-bit
    /// word.
    local: String,
    port: u16,
    remote: String,
    remote_port: u16,
    /// A TCP socket waiting for connections.
    listening: bool,
    inode: String,
}

impl Socket {
    /// Connected to somebody: it has a remote end.
    fn connected(&self) -> bool {
        !self.listening && self.remote_port != 0
    }
}

/// A socket from a line of a `/proc/net` table.
pub(super) fn socket(line: &str) -> Option<Socket> {
    let fields: Vec<&str> = line.split_whitespace().collect();
    let (local, port) = fields.get(1)?.split_once(':')?;
    let (remote, remote_port) = fields.get(2)?.split_once(':')?;
    Some(Socket {
        local: local.to_string(),
        port: u16::from_str_radix(port, 16).ok()?,
        remote: remote.to_string(),
        remote_port: u16::from_str_radix(remote_port, 16).ok()?,
        listening: fields.get(3) == Some(&"0A"),
        inode: (*fields.get(9)?).to_string(),
    })
}

/// Whether a `/proc/net` address (hex, network order per 32-bit word) is
/// loopback: `127.x.x.x`, `::1` or `::ffff:127.x.x.x`.
pub(super) fn is_loopback(address: &str) -> bool {
    match address.len() {
        8 => address.ends_with("7F"),
        32 => {
            address == "00000000000000000000000001000000"
                || (address.starts_with("0000000000000000FFFF0000") && address.ends_with("7F"))
        }
        _ => false,
    }
}

/// A `/proc/net` address as it is written (`203.0.113.5`, `2001:db8::1`).
pub(super) fn shown(address: &str) -> String {
    let words: Vec<[u8; 4]> = address
        .as_bytes()
        .chunks(8)
        .filter_map(|word| std::str::from_utf8(word).ok())
        .filter_map(|word| u32::from_str_radix(word, 16).ok())
        .map(u32::to_le_bytes)
        .collect();
    match words.as_slice() {
        [word] => Ipv4Addr::from(*word).to_string(),
        [a, b, c, d] => {
            let mut bytes = [0_u8; 16];
            for (index, word) in [a, b, c, d].into_iter().enumerate() {
                bytes[index * 4..index * 4 + 4].copy_from_slice(word);
            }
            let address = Ipv6Addr::from(bytes);
            address
                .to_ipv4_mapped()
                .map_or_else(|| address.to_string(), |mapped| mapped.to_string())
        }
        _ => address.to_string(),
    }
}

/// What a test checks of a parsed socket: its local address as written,
/// its port, whether it listens and its inode.
#[cfg(test)]
pub(super) fn shown_for_test(socket: &Socket) -> (String, u16, bool, String) {
    (
        shown(&socket.local),
        socket.port,
        socket.listening,
        socket.inode.clone(),
    )
}

/// The network sockets of one network namespace, by inode.
#[derive(Default)]
struct Tables {
    tcp: HashMap<String, Socket>,
    udp: HashMap<String, Socket>,
}

impl Tables {
    /// Reads the tables under `directory` (`/proc/net`, or a process's
    /// `/proc/<pid>/net` for the namespace it is in).
    fn read(directory: &Path) -> Self {
        let table = |names: [&str; 2]| -> HashMap<String, Socket> {
            names
                .iter()
                .filter_map(|name| fs::read_to_string(directory.join(name)).ok())
                .flat_map(|text| text.lines().skip(1).filter_map(socket).collect::<Vec<_>>())
                // Inode 0 is a socket the reader is not told the owner of.
                .filter(|socket| socket.inode != "0")
                .map(|socket| (socket.inode.clone(), socket))
                .collect()
        };
        Self {
            tcp: table(["tcp", "tcp6"]),
            udp: table(["udp", "udp6"]),
        }
    }
}

/// The inode of a descriptor that is a socket.
fn socket_inode(target: &str) -> Option<&str> {
    target.strip_prefix("socket:[")?.strip_suffix(']')
}

/// Every process that holds each socket. A socket is shared by every
/// process that inherited it: each one can use it, so each is looked at.
fn holders(processes: &[Process]) -> HashMap<&str, Vec<&Process>> {
    let mut holders: HashMap<&str, Vec<&Process>> = HashMap::new();
    for process in processes {
        for inode in process.fds.iter().filter_map(|(_, fd)| socket_inode(fd)) {
            // Once per process, however many copies of the socket it
            // holds.
            let sharing = holders.entry(inode).or_default();
            if sharing.last().is_none_or(|last| last.pid != process.pid) {
                sharing.push(process);
            }
        }
    }
    holders
}

/// Runs the socket checks.
pub(super) fn check(scope: &Scope<'_>, running: &Running, found: &mut Found) {
    let holders = holders(&running.processes);
    let own = Tables::read(&scope.root.join("proc/net"));
    listeners(scope, &own, &holders, found);
    // A process in a network namespace of its own (a container) is not in
    // the sweep's tables: its namespace's are read through it, once.
    let mut others: HashMap<&str, Tables> = HashMap::new();
    for process in &running.processes {
        let tables = match process.network.as_deref() {
            None => &own,
            Some(namespace) => others.entry(namespace).or_insert_with(|| {
                Tables::read(&scope.root.join("proc").join(&process.pid).join("net"))
            }),
        };
        connections(scope, process, tables, found);
    }
    packet_sockets(scope, &holders, found);
    promiscuous(scope, running, found);
}

/// Whether `process` runs a repository package's own program, unchanged:
/// the file at its path, or the copy an update replaced while it runs.
fn vouched(scope: &Scope<'_>, process: &Process, found: &mut Found) -> bool {
    let exe = process.path();
    if exe.starts_with("memfd:") {
        return false;
    }
    if process.deleted {
        return is_updated(scope, process) && !is_interpreter(exe);
    }
    trusted_program(scope, process, exe, found)
}

/// The ports the kernel hands out by itself.
fn ephemeral(scope: &Scope<'_>) -> (u16, u16) {
    fs::read_to_string(scope.root.join("proc/sys/net/ipv4/ip_local_port_range"))
        .ok()
        .and_then(|text| {
            let mut bounds = text.split_whitespace().map(str::parse::<u16>);
            Some((bounds.next()?.ok()?, bounds.next()?.ok()?))
        })
        .unwrap_or(EPHEMERAL)
}

/// TCP sockets listening on anything but the loopback interface, and UDP
/// sockets bound to a port somebody chose, by the program that holds them.
fn listeners(
    scope: &Scope<'_>,
    tables: &Tables,
    holders: &HashMap<&str, Vec<&Process>>,
    found: &mut Found,
) {
    let range = ephemeral(scope);
    let chosen = |port: u16| port < range.0 || port > range.1;
    let mut sockets: Vec<&Socket> = tables
        .tcp
        .values()
        .filter(|socket| socket.listening && !is_loopback(&socket.local))
        .collect();
    sockets.sort_by_key(|socket| socket.port);
    let mut unattributed = Vec::new();
    for socket in sockets {
        let Some(sharing) = holders.get(socket.inode.as_str()) else {
            unattributed.push(socket.port);
            continue;
        };
        // A port the kernel picked is not part of what the listener is:
        // it is another one at every start.
        let port = if chosen(socket.port) {
            format!("tcp-{}", socket.port)
        } else {
            "listens".to_string()
        };
        for process in sharing {
            listener(scope, process, ("TCP", socket.port, &port), found);
        }
    }
    no_process(scope, &unattributed, found);
    let mut datagrams: Vec<&Socket> = tables
        .udp
        .values()
        .filter(|socket| {
            !socket.connected()
                && !is_loopback(&socket.local)
                && chosen(socket.port)
                && !COMMON_UDP.contains(&socket.port)
        })
        .collect();
    datagrams.sort_by_key(|socket| socket.port);
    for socket in datagrams {
        for process in holders.get(socket.inode.as_str()).into_iter().flatten() {
            // Packaged servers answer on UDP as a matter of course: only
            // what nothing vouches for is worth showing.
            if !vouched(scope, process, found) {
                let port = format!("udp-{}", socket.port);
                listener(scope, process, ("UDP", socket.port, &port), found);
            }
        }
    }
}

/// Listening sockets that no process holds. As a user those are other
/// users'. Root sees every process: a socket none of them holds is the
/// kernel's own (an NFS or SMB server in the kernel), or one whose
/// process is hidden.
fn no_process(scope: &Scope<'_>, ports: &[u16], found: &mut Found) {
    if ports.is_empty() {
        return;
    }
    let count = ports.len();
    if scope.origin != Origin::Root {
        found.notes.push(format!(
            "{count} listening socket(s) belong to processes of other users; the root checks cover them"
        ));
        return;
    }
    let modules = fs::read_to_string(scope.root.join("proc/modules")).unwrap_or_default();
    let kernel_serves = modules
        .lines()
        .filter_map(|line| line.split_whitespace().next())
        .any(|module| KERNEL_SERVERS.contains(&module));
    if kernel_serves {
        found.notes.push(format!(
            "{count} listening socket(s) have no process that can be found: the kernel's own (a file server module is loaded), or one that is hidden"
        ));
        return;
    }
    for port in ports {
        found.add_missing(
            scope,
            Category::Listener,
            &format!("proc/net/tcp:{port}"),
            "a socket no process holds",
            format!("TCP port {port} listens from the network, and no process holds its socket"),
            RuleId::RootkitSign,
        );
    }
}

/// What to say about `process`, which holds a socket listening on a port:
/// the protocol, the port, and the port as part of an item's name.
fn listener(
    scope: &Scope<'_>,
    process: &Process,
    (protocol, port, port_name): (&str, u16, &str),
    found: &mut Found,
) {
    let exe = process.path();
    let pid = &process.pid;
    let started = process.started();
    let note =
        format!("process {pid} ({started}) listens on {protocol} port {port} from the network");
    let borrowed = replaced_in_own_namespace(process);
    // A program with no file on disk has its item from the program
    // checks; that it listens is said there.
    if exe.starts_with("memfd:") || (process.deleted && !borrowed && !is_updated(scope, process)) {
        found.add_missing(
            scope,
            Category::Process,
            exe,
            "no file on disk",
            note,
            RuleId::NetworkListener,
        );
        return;
    }
    if let Some(what) = relay(process) {
        found.add_as(
            scope,
            Category::Listener,
            &format!("{exe}:{port_name}"),
            exe,
            format!("{note}: {what}"),
            Some(RuleId::NetworkRelay),
        );
        return;
    }
    if vouched(scope, process, found) {
        if explained(scope, process) {
            // Listed with the trusted items: what it is, and where.
            found.add(scope, Category::Listener, exe, note, None);
        } else {
            found.add_as(
                scope,
                Category::Listener,
                &format!("{exe}:{port_name}"),
                exe,
                format!("{note}; no packaged service starts it, and it is not a desktop program known to listen"),
                Some(RuleId::NetworkListener),
            );
        }
        return;
    }
    let (path, _) = subject(scope, process, exe);
    // What an allowed item is allowed for: this script, or this code
    // handed to the interpreter, on this port.
    let mut name = format!("{path}:{port_name}");
    if path == exe
        && let Some(told) = told(process, exe)
    {
        name = format!("{name}:{told}");
    }
    // An interpreter's listener is always flagged: with no script on disk
    // (`python -c …`), or with a packaged "script" it was handed, it
    // would otherwise pass as trusted. So is one under a borrowed name,
    // whose item is the packaged file of that name.
    let alert = (is_interpreter(exe) || borrowed).then_some(RuleId::NetworkListener);
    found.add_as(scope, Category::Listener, &name, &path, note, alert);
}

/// Whether a packaged program that listens is one expected to: a desktop
/// program known for it, or the program of a packaged unit.
fn explained(scope: &Scope<'_>, process: &Process) -> bool {
    DESKTOP_LISTENERS
        .iter()
        .any(|known| is_named(process.name(), known))
        || started_by_packaged_unit(scope, process)
}

/// The service a control group path says a process belongs to.
#[derive(Debug, PartialEq, Eq)]
pub(super) enum Starter<'a> {
    /// A unit of the system manager (`/system.slice/sshd.service`).
    System(&'a str),
    /// A unit of a user's own manager
    /// (`/user.slice/user-1000.slice/user@1000.service/app.slice/mpd.service`).
    User(&'a str),
}

/// Units that run what users hand them (a crontab line, an `at` job): the
/// jobs run in the unit's own control group, as whoever queued them.
const JOB_RUNNERS: &[&str] = &[
    "cronie.service",
    "crond.service",
    "cron.service",
    "fcron.service",
    "atd.service",
];

/// Whether `name` is a user's manager as the system manager runs it
/// (`user@1000.service`).
fn is_user_manager(name: &str) -> bool {
    name.strip_prefix("user@")
        .and_then(|rest| rest.strip_suffix(".service"))
        .is_some_and(|uid| !uid.is_empty() && uid.chars().all(|digit| digit.is_ascii_digit()))
}

/// The service that `cgroup` (`/system.slice/sshd.service`) puts a process
/// in: the first name under the slices, which is the unit the manager made
/// the group for; what lies below it is the unit's own to arrange. A scope
/// (a login session, an app or terminal the desktop started, `run-*.scope`)
/// is no service, and nothing below one is: a user makes groups of any name
/// under a scope of theirs. Under `user@UID.service` the same holds once
/// more for that user's own manager; the manager's group itself (its
/// `init.scope`) starts nothing.
pub(super) fn starter(cgroup: &str) -> Option<Starter<'_>> {
    let mut names = cgroup
        .split('/')
        .filter(|name| !name.is_empty())
        .skip_while(|name| name.ends_with(".slice"));
    let unit = names.next()?;
    if !is_user_manager(unit) {
        return unit.ends_with(".service").then_some(Starter::System(unit));
    }
    let unit = names.find(|name| !name.ends_with(".slice"))?;
    unit.ends_with(".service").then_some(Starter::User(unit))
}

/// Whether a service a repository package ships started `process`: it is
/// in that unit's own control group (see `starter`), and the unit's file is
/// a package's.
///
/// The system's control groups are root's to make, so being in one is
/// enough there, except in the group of a unit that runs users' jobs. A
/// user arranges the groups under their own manager as they like (makes one
/// named after a packaged unit, moves a process into a real one): there the
/// unit must also name the program. What is left to somebody who is already
/// the user: starting the very program a packaged user unit names, with
/// arguments of their own, in a group of that unit's name. The program is
/// then an intact packaged one that is no interpreter, and it is listed
/// with what it listens on.
pub(super) fn started_by_packaged_unit(scope: &Scope<'_>, process: &Process) -> bool {
    let Some(starter) = starter(&process.cgroup) else {
        return false;
    };
    let (unit, directory, named) = match starter {
        Starter::System(unit) => (unit, "usr/lib/systemd/system", JOB_RUNNERS.contains(&unit)),
        Starter::User(unit) => (unit, "usr/lib/systemd/user", true),
    };
    // An instance (`getty@tty1.service`) is its template's.
    let template = unit
        .split_once('@')
        .map(|(name, _)| format!("{name}@.service"));
    [Some(unit.to_string()), template]
        .into_iter()
        .flatten()
        .map(|name| format!("{directory}/{name}"))
        .any(|path| packaged(scope, &path) && (!named || unit_runs(scope, &path, process.path())))
}

/// Whether the unit file at `unit` starts the program at `exe`.
fn unit_runs(scope: &Scope<'_>, unit: &str, exe: &str) -> bool {
    // The unit's name came from a process: root reads the file as anyone
    // may.
    let looked = if scope.origin == Origin::Root {
        read::look_as(scope.root, unit, View::Everyone)
    } else {
        Some(read::look(scope.root, unit))
    };
    let Some(read::Found::File { head, .. }) = looked else {
        return false;
    };
    String::from_utf8_lossy(&head).lines().any(|line| {
        line.trim()
            .strip_prefix("Exec")
            .and_then(|rest| rest.split_once('='))
            .and_then(|(_, command)| command.split_whitespace().next())
            .is_some_and(|program| {
                program.trim_start_matches(['@', '-', ':', '+', '!']) == format!("/{exe}")
            })
    })
}

/// What kind of relay `process` is, if it is one: a tool that runs or
/// forwards what it is told, an SSH client that only forwards, or an SSH
/// server started with settings of somebody's own.
fn relay(process: &Process) -> Option<&'static str> {
    let name = process.name();
    if RELAYS.contains(&name) {
        return Some("a tool that runs or forwards what it is told over the network");
    }
    // A process title may be one string (`sshd: /usr/bin/sshd -D
    // [listener]`).
    let words: Vec<&str> = process
        .arguments
        .iter()
        .flat_map(|argument| argument.split_whitespace())
        .collect();
    match name {
        "ssh" if !process.on_terminal() && forwards(&words) => {
            Some("an SSH client that forwards ports, started from no terminal")
        }
        "sshd" if own_settings(&words) => {
            Some("an SSH server started with settings or a port of somebody's own")
        }
        _ => None,
    }
}

/// Whether an `ssh` command line asks for a forwarded port or a tunnel
/// (`-R`, `-D`, `-w`, or the same as a `-o` setting).
pub(super) fn forwards(words: &[&str]) -> bool {
    // Options that take a value: what follows their letter is not flags.
    const VALUED: &str = "BbcEeFIiJLlmOoPpQSW";
    words.iter().skip(1).any(|word| {
        let setting = word.to_ascii_lowercase();
        if ["remoteforward", "dynamicforward", "tunnel="]
            .iter()
            .any(|key| setting.contains(key))
        {
            return true;
        }
        let Some(flags) = word.strip_prefix('-').filter(|rest| !rest.starts_with('-')) else {
            return false;
        };
        flags
            .chars()
            .take_while(|flag| !VALUED.contains(*flag))
            .any(|flag| matches!(flag, 'R' | 'D' | 'w'))
    })
}

/// Whether an `sshd` command line names a configuration outside
/// `/etc/ssh`, a setting or a port.
pub(super) fn own_settings(words: &[&str]) -> bool {
    words.iter().enumerate().skip(1).any(|(index, word)| {
        if let Some(file) = word.strip_prefix("-f") {
            let file = if file.is_empty() {
                words.get(index + 1).copied().unwrap_or_default()
            } else {
                file
            };
            return !file.starts_with("/etc/ssh/");
        }
        word.starts_with("-o") || word.starts_with("-p")
    })
}

/// The checks on the connections of one process: a shell or interpreter
/// whose input or output is a connection, a shell that holds one, and a
/// relay that is connected to another machine.
fn connections(scope: &Scope<'_>, process: &Process, tables: &Tables, found: &mut Found) {
    if is_updated(scope, process) && !is_interpreter(process.path()) {
        return;
    }
    let connection = |fd: &(u32, String)| {
        socket_inode(&fd.1)
            .and_then(|inode| tables.tcp.get(inode))
            .filter(|socket| socket.connected())
            .map(|socket| (fd.0, socket))
    };
    let mut held: Vec<(u32, &Socket)> = process.fds.iter().filter_map(connection).collect();
    if held.is_empty() {
        return;
    }
    // Another machine before this one; input and output before the rest.
    held.sort_by_key(|(fd, socket)| (is_loopback(&socket.remote), *fd));
    let name = process.name();
    let exe = process.path();
    let shell = SHELLS.iter().any(|shell| is_named(name, shell));
    let driven = is_interpreter(exe) || DRIVEN_BY_INPUT.contains(&name);
    let on_stdio = held.iter().find(|(fd, _)| *fd <= 2);
    if let Some((_, socket)) = on_stdio.filter(|_| driven) {
        // A service started per connection gets the connection as its
        // input and output; a shell started that way is still a shell on
        // the network.
        if !shell && started_by_packaged_unit(scope, process) {
            return;
        }
        remote_shell(scope, process, socket, "has its input or output on", found);
    } else if let Some((_, socket)) = held.first().filter(|_| shell) {
        remote_shell(scope, process, socket, "holds", found);
    } else if let Some((_, socket)) = held
        .first()
        .filter(|(_, socket)| !is_loopback(&socket.remote))
        && let Some(what) = relay(process)
    {
        let peer = shown(&socket.remote);
        found.add_as(
            scope,
            Category::Process,
            &format!("{exe}:to-{}", plain(&peer)),
            exe,
            format!(
                "process {} ({}) is connected to {peer} port {}: {what}",
                process.pid,
                process.started(),
                socket.remote_port
            ),
            Some(RuleId::NetworkRelay),
        );
    }
}

/// Reports `process`, a shell or interpreter with the connection `socket`.
/// One to this machine itself is what a developer's relay looks like, and
/// is reported a step lower than one to another machine.
fn remote_shell(
    scope: &Scope<'_>,
    process: &Process,
    socket: &Socket,
    how: &str,
    found: &mut Found,
) {
    let exe = process.path();
    let peer = shown(&socket.remote);
    let (rule, looks) = if is_loopback(&socket.remote) {
        (RuleId::NetworkRelay, "something on this machine drives it")
    } else {
        (RuleId::RemoteShell, "it looks like a remote shell")
    };
    let note = format!(
        "process {} ({}) {how} a connection to {peer} port {}: {looks}",
        process.pid,
        process.started(),
        socket.remote_port
    );
    // A program with no file on disk has its item already.
    if exe.starts_with("memfd:") || process.deleted {
        found.add_missing(scope, Category::Process, exe, "no file on disk", note, rule);
        return;
    }
    let (path, _) = subject(scope, process, exe);
    found.add_as(
        scope,
        Category::Process,
        &format!("{path}:to-{}", plain(&peer)),
        &path,
        note,
        Some(rule),
    );
}

/// Raw packet sockets (`/proc/net/packet`): what a sniffer, or a backdoor
/// that waits for a magic packet without opening a port, reads the
/// network through. The programs that run the network hold some too.
fn packet_sockets(scope: &Scope<'_>, holders: &HashMap<&str, Vec<&Process>>, found: &mut Found) {
    let Ok(text) = fs::read_to_string(scope.root.join("proc/net/packet")) else {
        return;
    };
    let mut unattributed = 0;
    for inode in text
        .lines()
        .skip(1)
        .filter_map(|line| line.split_whitespace().last())
    {
        let Some(sharing) = holders.get(inode) else {
            unattributed += 1;
            continue;
        };
        for process in sharing {
            if PACKET_USERS.contains(&process.name()) && vouched(scope, process, found) {
                continue;
            }
            let note = format!(
                "process {} ({}) holds a raw packet socket: it can read the traffic of this machine",
                process.pid,
                process.started()
            );
            let exe = process.path();
            if exe.starts_with("memfd:") || process.deleted {
                found.add_missing(
                    scope,
                    Category::Process,
                    exe,
                    "no file on disk",
                    note,
                    RuleId::KernelTap,
                );
                continue;
            }
            let (path, _) = subject(scope, process, exe);
            found.add_as(
                scope,
                Category::Process,
                &format!("{path}:packet-socket"),
                &path,
                note,
                Some(RuleId::KernelTap),
            );
        }
    }
    // As a user those are root's programs, which the root checks see.
    if unattributed > 0 && scope.origin == Origin::Root {
        found.add_missing(
            scope,
            Category::Process,
            "proc/net/packet",
            "a socket no process holds",
            format!("{unattributed} raw packet socket(s) are held by no process that can be found"),
            RuleId::KernelTap,
        );
    }
}

/// Interfaces in promiscuous mode, which take in traffic that is not for
/// this machine: noted, unless a bridge or a running capture tool
/// explains it.
fn promiscuous(scope: &Scope<'_>, running: &Running, found: &mut Found) {
    // Without every process in view, a capture tool may be running unseen.
    if scope.origin != Origin::Root && running.unreadable > 0 {
        return;
    }
    if running
        .processes
        .iter()
        .any(|process| CAPTURE_TOOLS.contains(&process.name()))
    {
        return;
    }
    let Ok(interfaces) = fs::read_dir(scope.root.join("sys/class/net")) else {
        return;
    };
    let mut names: Vec<String> = interfaces
        .filter_map(Result::ok)
        .filter(|entry| {
            let directory = entry.path();
            let flags = fs::read_to_string(directory.join("flags"))
                .ok()
                .and_then(|text| u32::from_str_radix(text.trim().trim_start_matches("0x"), 16).ok())
                .unwrap_or(0);
            // IFF_PROMISC; a bridge and its ports are promiscuous by
            // design.
            flags & 0x100 != 0
                && !directory.join("brport").exists()
                && !directory.join("bridge").exists()
        })
        .filter_map(|entry| entry.file_name().into_string().ok())
        .collect();
    names.sort();
    for name in names {
        found.notes.push(format!(
            "network interface {} is in promiscuous mode (it takes in traffic that is not for this machine), and no capture tool is running",
            name.escape_debug()
        ));
    }
}
