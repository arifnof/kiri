//! Servers: Docker engines on other machines, reached over SSH.
//!
//! The window keeps a list of them (~/.kiri/servers.json: bookmarks, never a
//! password). Connecting runs the system's `ssh`, which forwards the
//! server's Docker socket to one in ~/.kiri/run, and points the window's
//! requests at it (`client::set_target`). Containers, images, volumes and
//! networks then list and act on the server, through the same Docker Engine
//! API Kiri speaks. Disconnecting ends `ssh` and the window is back on Kiri.
//!
//! Signing in is ssh's own: a key or the ssh agent, as `ssh user@host` does
//! in a terminal; or a password, handed to ssh through `SSH_ASKPASS` (main.rs
//! answers it). A password is asked at Connect, or kept where the person
//! chose (secrets.rs: the system's store, or Kiri's encrypted file).
//!
//! A server behind another (a bastion) is reached through it: a jump host,
//! as ssh's ProxyCommand with `ssh -W`, signing in to each with its own key
//! or password. A new host key is accepted the first time and checked after
//! (`accept-new`), for the jump host and the server alike.

use std::io::{self, Read};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use super::secrets::{self, Store};
use crate::client;

/// The variables main.rs answers ssh's password prompts from.
pub const SECRET_ENV: &str = "KIRI_SSH_SECRET";
pub const JUMP_SECRET_ENV: &str = "KIRI_SSH_JUMP_SECRET";
pub const JUMP_HOST_ENV: &str = "KIRI_SSH_JUMP_HOST";
/// Where Docker listens on a Linux server, unless a bookmark says otherwise.
pub const DEFAULT_SOCKET: &str = "/var/run/docker.sock";
/// How long Connect waits for the server's Docker to answer.
const CONNECT_WAIT: Duration = Duration::from_secs(25);

/// The host a server is reached through.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct Jump {
    pub host: String,
    #[serde(default)]
    pub user: String,
    #[serde(default = "default_port")]
    pub port: u16,
    #[serde(default)]
    pub key: String,
    #[serde(default)]
    pub password: bool,
}

/// A bookmarked server.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct Server {
    pub id: String,
    pub name: String,
    /// An IP address or a host name.
    pub host: String,
    /// Empty: ssh's own choice (its config, else this Mac's user name).
    #[serde(default)]
    pub user: String,
    #[serde(default = "default_port")]
    pub port: u16,
    /// A private key file; empty for ssh's defaults and the agent.
    #[serde(default)]
    pub key: String,
    /// Docker's socket on the server.
    #[serde(default = "default_socket")]
    pub socket: String,
    /// Signs in with a password.
    #[serde(default)]
    pub password: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub jump: Option<Jump>,
    /// Where its passwords are kept ("keychain", "file"), or "": asked at each Connect.
    #[serde(default)]
    pub remember: String,
    /// Which are kept: the server's password, the jump host's.
    #[serde(default)]
    pub saved: bool,
    #[serde(default)]
    pub jump_saved: bool,
    /// When it was last connected to, in seconds since 1970.
    #[serde(default)]
    pub last: u64,
}

fn default_port() -> u16 {
    22
}

fn default_socket() -> String {
    DEFAULT_SOCKET.to_owned()
}

/// Passwords for one Connect: typed, or read from where they're kept.
#[derive(Default, Clone)]
pub struct Creds {
    pub password: Option<String>,
    pub jump: Option<String>,
    /// Keep what's typed here, once it works ("keychain", "file").
    pub remember: Option<String>,
}

/// A Connect that can't go on without something from the person.
#[derive(Debug)]
pub struct Failed {
    pub text: String,
    /// "server" or "jump": whose password to ask for.
    pub need: Option<&'static str>,
}

impl From<io::Error> for Failed {
    fn from(e: io::Error) -> Failed {
        Failed { text: e.to_string(), need: None }
    }
}

/// The connection in use.
struct Live {
    server: Server,
    child: Child,
    local: PathBuf,
    /// What ssh said on stderr: why it failed, when it does.
    said: Arc<Mutex<String>>,
    since: SystemTime,
}

static LIVE: Mutex<Option<Live>> = Mutex::new(None);
/// Whether a Connect is under way, and to which server.
static CONNECTING: Mutex<Option<String>> = Mutex::new(None);

fn live() -> std::sync::MutexGuard<'static, Option<Live>> {
    LIVE.lock().unwrap_or_else(|e| e.into_inner())
}

fn file() -> Option<PathBuf> {
    super::state_dir().map(|d| d.join("servers.json"))
}

/// The bookmarks, as saved.
pub fn load() -> Vec<Server> {
    file().and_then(|f| std::fs::read(f).ok()).and_then(|b| serde_json::from_slice(&b).ok()).unwrap_or_default()
}

fn save(list: &[Server]) -> io::Result<()> {
    let f = file().ok_or_else(|| io::Error::other("HOME is not set"))?;
    if let Some(dir) = f.parent() {
        std::fs::create_dir_all(dir)?;
    }
    let tmp = f.with_extension("json.tmp");
    std::fs::write(&tmp, serde_json::to_vec_pretty(list)?)?;
    #[cfg(unix)]
    std::fs::set_permissions(&tmp, std::os::unix::fs::PermissionsExt::from_mode(0o600))?;
    std::fs::rename(tmp, f)
}

/// The server in use, if the window is on one.
pub fn current() -> Option<Server> {
    live().as_ref().map(|l| l.server.clone())
}

/// The tunnel in use, for the Processes view: ssh's pid, the server, since when.
pub fn live_tunnel() -> Option<(u32, Server, SystemTime)> {
    live().as_ref().map(|l| (l.child.id(), l.server.clone(), l.since))
}

/// A host ssh takes as a destination: a name or an address, never an option.
fn valid_host(h: &str) -> bool {
    !h.is_empty() && h.len() <= 253 && !h.starts_with('-') && h.bytes().all(|b| b.is_ascii_alphanumeric() || b".-_:[]%".contains(&b))
}

fn valid_user(u: &str) -> bool {
    u.is_empty() || (u.len() <= 64 && !u.starts_with('-') && u.bytes().all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b)))
}

/// `~/…` as the home directory.
fn expand(p: &str) -> String {
    match (p.strip_prefix("~/"), std::env::var_os("HOME")) {
        (Some(rest), Some(home)) => Path::new(&home).join(rest).to_string_lossy().into_owned(),
        _ => p.to_owned(),
    }
}

fn bad(why: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, why.to_owned())
}

fn port_of(v: &Value) -> io::Result<u16> {
    let port = match v {
        Value::Number(n) => n.as_u64().unwrap_or(0),
        Value::String(s) if s.trim().is_empty() => 22,
        Value::String(s) => s.trim().parse().unwrap_or(0),
        _ => 22,
    };
    if (1..=65535).contains(&port) { Ok(port as u16) } else { Err(bad("The SSH port is a number from 1 to 65535")) }
}

/// A key file: there, and quotable in the jump host's command line.
fn key_of(raw: &str) -> io::Result<String> {
    let key = expand(raw.trim());
    if key.is_empty() {
        return Ok(key);
    }
    if key.contains(['\'', '\n', '\r']) {
        return Err(bad("A key file's path can't have a quote or a line break"));
    }
    if !Path::new(&key).is_file() {
        return Err(bad("The key file isn't there"));
    }
    Ok(key)
}

/// A bookmark from the page's form, checked; `id` empty for a new one.
/// What it keeps (remember, saved) is upsert's.
fn parse(v: &Value) -> io::Result<Server> {
    let text = |v: &Value, k: &str| v[k].as_str().unwrap_or("").trim().to_owned();
    let host = text(v, "host").trim_start_matches('[').trim_end_matches(']').to_owned();
    if !valid_host(&host) {
        return Err(bad("Enter the server's IP address or host name"));
    }
    let user = text(v, "user");
    if !valid_user(&user) {
        return Err(bad("A user name has only letters, digits, dots, dashes and underscores"));
    }
    let port = port_of(&v["port"])?;
    let password = v["password"].as_bool().unwrap_or(false);
    let key = if password { String::new() } else { key_of(&text(v, "key"))? };
    let socket = match text(v, "socket") {
        s if s.is_empty() => DEFAULT_SOCKET.to_owned(),
        s if s.starts_with('/') && !s.contains(char::is_whitespace) && !s.contains(':') => s,
        _ => return Err(bad("Docker's socket is a full path on the server, such as /var/run/docker.sock")),
    };
    let name = match text(v, "name") {
        n if n.is_empty() => host.clone(),
        n => n.chars().take(64).collect(),
    };
    let jump = match &v["jump"] {
        j if j.is_object() && !text(j, "host").is_empty() => {
            let jhost = text(j, "host").trim_start_matches('[').trim_end_matches(']').to_owned();
            if !valid_host(&jhost) {
                return Err(bad("Enter the jump host's IP address or host name"));
            }
            let juser = text(j, "user");
            if !valid_user(&juser) {
                return Err(bad("A user name has only letters, digits, dots, dashes and underscores"));
            }
            let jpassword = j["password"].as_bool().unwrap_or(false);
            Some(Jump { host: jhost, user: juser, port: port_of(&j["port"])?, key: if jpassword { String::new() } else { key_of(&text(j, "key"))? }, password: jpassword })
        }
        _ => None,
    };
    Ok(Server { id: text(v, "id"), name, host, user, port, key, socket, password, jump, ..Default::default() })
}

fn account(id: &str, jump: bool) -> String {
    if jump { format!("{id}:jump") } else { id.to_owned() }
}

/// Keeps or forgets one password as the form asked: `typed` replaces the
/// kept one; empty keeps it (moved, if the store changed).
fn keep(id: &str, jump: bool, wanted: bool, typed: &str, was: Option<Store>, now: Option<Store>, had: bool) -> io::Result<bool> {
    let acct = account(id, jump);
    let Some(store) = now.filter(|_| wanted) else {
        secrets::delete(&acct);
        return Ok(false);
    };
    if !typed.is_empty() {
        secrets::delete(&acct);
        secrets::save(store, &acct, typed)?;
        return Ok(true);
    }
    match was {
        Some(old) if had && old != store => match secrets::load(old, &acct) {
            Some(s) => {
                secrets::delete(&acct);
                secrets::save(store, &acct, &s)?;
                Ok(true)
            }
            None => Ok(false),
        },
        _ => Ok(had),
    }
}

/// Adds a bookmark, or changes the one with its id, keeping the passwords
/// the form says to keep (`secret`, `jumpSecret`, `remember`).
pub fn upsert(v: &Value) -> io::Result<Server> {
    let mut s = parse(v)?;
    let mut list = load();
    if current().is_some_and(|c| c.id == s.id) {
        return Err(io::Error::other("Disconnect from it first"));
    }
    let old = list.iter().find(|x| !s.id.is_empty() && x.id == s.id).cloned();
    if old.is_none() {
        s.id = new_id();
    }
    let remember = v["remember"].as_str().and_then(Store::parse);
    let was = old.as_ref().and_then(|o| Store::parse(&o.remember));
    let (had, jump_had) = old.as_ref().map_or((false, false), |o| (o.saved, o.jump_saved));
    let text = |k: &str| v[k].as_str().unwrap_or("").to_owned();
    s.saved = keep(&s.id, false, s.password, &text("secret"), was, remember, had)?;
    s.jump_saved = keep(&s.id, true, s.jump.as_ref().is_some_and(|j| j.password), &text("jumpSecret"), was, remember, jump_had)?;
    s.remember = remember.map(Store::name).unwrap_or_default().to_owned();
    s.last = old.as_ref().map_or(0, |o| o.last);
    match list.iter_mut().find(|x| x.id == s.id) {
        Some(x) => *x = s.clone(),
        None => list.push(s.clone()),
    }
    save(&list)?;
    Ok(s)
}

pub fn remove(id: &str) -> io::Result<()> {
    if current().is_some_and(|c| c.id == id) {
        disconnect();
    }
    secrets::delete(&account(id, false));
    secrets::delete(&account(id, true));
    let mut list = load();
    list.retain(|s| s.id != id);
    save(&list)
}

/// A kept password, for the form's eye button.
pub fn secret(id: &str, jump: bool) -> Option<String> {
    let s = load().into_iter().find(|s| s.id == id)?;
    secrets::load(Store::parse(&s.remember)?, &account(id, jump))
}

fn new_id() -> String {
    let t = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default();
    format!("{:x}{:x}", t.as_secs(), t.subsec_nanos() ^ std::process::id())
}

fn dest(user: &str, host: &str) -> String {
    if user.is_empty() { host.to_owned() } else { format!("{user}@{host}") }
}

/// The options both ssh's take: no prompt they can't show, a quick give-up,
/// and a host key checked after the first time.
fn common(password: bool) -> Vec<String> {
    let mut o = vec!["StrictHostKeyChecking=accept-new", "ConnectTimeout=12", "ServerAliveInterval=15", "ServerAliveCountMax=3", "ControlMaster=no", "ControlPath=none"];
    if password {
        o.extend(["NumberOfPasswordPrompts=1", "PreferredAuthentications=password,keyboard-interactive,publickey"]);
    } else {
        o.push("BatchMode=yes");
    }
    o.into_iter().flat_map(|x| ["-o".to_owned(), x.to_owned()]).collect()
}

/// The jump host's half: `ssh -W %h:%p` to it, as one command line for
/// ProxyCommand, which ssh runs through /bin/sh. Every value the person gave
/// is single-quoted (parse() refuses a quote in them), with `%` doubled so
/// ssh leaves it alone.
fn proxy_command(j: &Jump) -> String {
    let q = |s: &str| format!("'{}'", s.replace('%', "%%"));
    let mut p: Vec<String> = ["ssh", "-W", "%h:%p", "-T", "-x", "-a"].map(String::from).to_vec();
    p.extend(common(j.password));
    if !j.key.is_empty() {
        p.extend(["-o".into(), "IdentitiesOnly=yes".into(), "-i".into(), q(&j.key)]);
    }
    p.extend(["-p".into(), j.port.to_string(), "--".into(), q(&dest(&j.user, &j.host))]);
    p.join(" ")
}

/// What ssh runs with: the server's Docker socket forwarded to `local`,
/// nothing else, through its jump host if it has one.
fn ssh_args(s: &Server, local: &Path) -> Vec<String> {
    let mut a: Vec<String> = ["-N", "-T", "-x", "-a", "-o", "ExitOnForwardFailure=yes", "-o", "StreamLocalBindUnlink=yes"].map(String::from).to_vec();
    a.extend(common(s.password));
    if let Some(j) = &s.jump {
        a.extend(["-o".into(), format!("ProxyCommand={}", proxy_command(j))]);
    }
    if !s.key.is_empty() {
        a.extend(["-o".into(), "IdentitiesOnly=yes".into(), "-i".into(), s.key.clone()]);
    }
    a.extend(["-p".to_owned(), s.port.to_string()]);
    a.extend(["-L".to_owned(), format!("{}:{}", local.display(), s.socket)]);
    a.push("--".to_owned());
    a.push(dest(&s.user, &s.host));
    a
}

/// Where a server's socket comes out on this Mac (short: a unix socket's
/// path has a limit of about 100 bytes).
fn local_socket(name: &str) -> io::Result<PathBuf> {
    let dir = super::state_dir().ok_or_else(|| io::Error::other("HOME is not set"))?.join("run");
    std::fs::create_dir_all(&dir)?;
    let short: String = name.chars().filter(char::is_ascii_alphanumeric).take(14).collect();
    let sock = dir.join(format!("ssh-{short}.sock"));
    // ssh refuses a longer one as a "bad forwarding specification".
    if sock.as_os_str().len() > 100 {
        return Err(io::Error::other(format!("The path for the server's socket is too long for macOS: {}", sock.display())));
    }
    Ok(sock)
}

/// The passwords a Connect needs: typed, else kept; one that's neither is
/// asked for.
fn creds_for(s: &Server, typed: Creds) -> Result<Creds, Failed> {
    let store = Store::parse(&s.remember);
    let kept = |jump: bool| store.and_then(|st| secrets::load(st, &account(&s.id, jump)));
    let password = match typed.password.filter(|p| !p.is_empty()) {
        Some(p) => Some(p),
        None if s.password => Some(kept(false).ok_or(Failed { text: String::new(), need: Some("server") })?),
        None => None,
    };
    let jump = match typed.jump.filter(|p| !p.is_empty()) {
        Some(p) => Some(p),
        None if s.jump.as_ref().is_some_and(|j| j.password) => Some(kept(true).ok_or(Failed { text: String::new(), need: Some("jump") })?),
        None => None,
    };
    Ok(Creds { password, jump, remember: None })
}

/// Connects to the bookmark `id`, ending any other connection first, and
/// points the window at it once its Docker answers. A password typed for a
/// server set to keep its passwords is kept once it works.
pub fn connect(id: &str, typed: Creds) -> Result<Server, Failed> {
    let mut server = load().into_iter().find(|s| s.id == id).ok_or_else(|| io::Error::other("That server isn't in the list anymore"))?;
    {
        let mut c = CONNECTING.lock().unwrap_or_else(|e| e.into_inner());
        if c.is_some() {
            return Err(io::Error::other("Already connecting").into());
        }
        *c = Some(id.to_owned());
    }
    let result = (|| {
        let creds = creds_for(&server, typed.clone())?;
        disconnect();
        let local = local_socket(&server.id)?;
        let (child, said) = tunnel(&server, &creds, &local)?;
        crate::diag::info!("connected to a server", host = server.host);
        client::set_target(Some(local.clone()));
        server.last = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs();
        // Kept now that they're known to work, where the bookmark (or the prompt) says.
        if let Some(r) = typed.remember.as_deref().and_then(Store::parse) {
            server.remember = r.name().to_owned();
        }
        if let Some(store) = Store::parse(&server.remember) {
            if let Some(p) = typed.password.filter(|p| !p.is_empty() && server.password) {
                server.saved = secrets::save(store, &account(id, false), &p).is_ok() || server.saved;
            }
            if let Some(p) = typed.jump.filter(|p| !p.is_empty() && server.jump.as_ref().is_some_and(|j| j.password)) {
                server.jump_saved = secrets::save(store, &account(id, true), &p).is_ok() || server.jump_saved;
            }
        }
        let mut list = load();
        if let Some(x) = list.iter_mut().find(|x| x.id == server.id) {
            *x = server.clone();
            let _ = save(&list);
        }
        *live() = Some(Live { server: server.clone(), child, local, said, since: SystemTime::now() });
        Ok(server.clone())
    })();
    *CONNECTING.lock().unwrap_or_else(|e| e.into_inner()) = None;
    result
}

/// Test from the form: the bookmark as typed (passwords typed, else kept for
/// its id) is connected to on a socket of its own, asked for its Docker's
/// details, and let go. The window stays on the engine it's on.
pub fn test(v: &Value) -> Result<Value, Failed> {
    let mut s = parse(v)?;
    if let Some(old) = load().into_iter().find(|o| !s.id.is_empty() && o.id == s.id) {
        s.remember = old.remember;
    }
    let text = |k: &str| v[k].as_str().map(str::to_owned);
    let creds = creds_for(&s, Creds { password: text("secret"), jump: text("jumpSecret"), remember: None })?;
    let local = local_socket(&format!("test{}", std::process::id()))?;
    let (mut child, _) = tunnel(&s, &creds, &local)?;
    let info = client::get_at(&local, "/info");
    let _ = child.kill();
    let _ = child.wait();
    let _ = std::fs::remove_file(&local);
    let info = info?;
    Ok(json!({"os": info["OperatingSystem"], "version": info["ServerVersion"], "cpus": info["NCPU"], "memory": info["MemTotal"], "containers": info["Containers"], "running": info["ContainersRunning"]}))
}

/// Runs ssh for `s` and waits until the server's Docker answers on `local`.
fn tunnel(s: &Server, creds: &Creds, local: &Path) -> Result<(Child, Arc<Mutex<String>>), Failed> {
    let _ = std::fs::remove_file(local);
    let mut cmd = Command::new("ssh");
    cmd.args(ssh_args(s, local)).stdin(Stdio::null()).stdout(Stdio::null()).stderr(Stdio::piped());
    if creds.password.is_some() || creds.jump.is_some() {
        cmd.env("SSH_ASKPASS", askpass()?).env("SSH_ASKPASS_REQUIRE", "force").env("DISPLAY", ":0");
        if let Some(p) = &creds.password {
            cmd.env(SECRET_ENV, p);
        }
        if let (Some(p), Some(j)) = (&creds.jump, &s.jump) {
            cmd.env(JUMP_SECRET_ENV, p).env(JUMP_HOST_ENV, &j.host);
        }
    }
    let mut child = cmd.spawn().map_err(|e| if e.kind() == io::ErrorKind::NotFound { io::Error::other("ssh isn't installed on this computer") } else { e })?;
    let said = Arc::new(Mutex::new(String::new()));
    if let Some(mut err) = child.stderr.take() {
        let said = said.clone();
        std::thread::spawn(move || {
            let mut buf = [0u8; 1024];
            while let Ok(n) = err.read(&mut buf) {
                if n == 0 {
                    break;
                }
                let mut s = said.lock().unwrap_or_else(|e| e.into_inner());
                s.push_str(&String::from_utf8_lossy(&buf[..n]));
                if s.len() > 8192 {
                    let cut = s.len() - 4096;
                    let cut = (cut..s.len()).find(|&i| s.is_char_boundary(i)).unwrap_or(0);
                    s.drain(..cut);
                }
            }
        });
    }
    let began = Instant::now();
    let mut last = None;
    let told = || said.lock().unwrap_or_else(|e| e.into_inner()).clone();
    loop {
        if let Some(status) = child.try_wait()? {
            std::thread::sleep(Duration::from_millis(100));
            let _ = std::fs::remove_file(local);
            return Err(failed(&told(), Some(status.code().unwrap_or(-1)), s));
        }
        if local.exists() {
            match client::ping_at(local) {
                Ok(()) => return Ok((child, said)),
                Err(e) => last = Some(e),
            }
        }
        if began.elapsed() > CONNECT_WAIT {
            let _ = child.kill();
            let _ = child.wait();
            let _ = std::fs::remove_file(local);
            let t = told();
            return Err(if t.trim().is_empty() && last.is_some() {
                Failed { text: docker_unreached(s), need: None }
            } else if t.trim().is_empty() {
                Failed { text: "The server didn't answer in time".to_owned(), need: None }
            } else {
                failed(&t, None, s)
            });
        }
        std::thread::sleep(Duration::from_millis(150));
    }
}

/// The program ssh asks for the password: this one (main.rs answers it).
/// A test runs the built `kiri` instead, its own binary being the test harness.
fn askpass() -> io::Result<PathBuf> {
    #[cfg(test)]
    if let Some(p) = std::env::var_os("KIRI_TEST_ASKPASS") {
        return Ok(PathBuf::from(p));
    }
    std::env::current_exe()
}

fn docker_unreached(s: &Server) -> String {
    let who = if s.user.is_empty() { "your user".to_owned() } else { s.user.clone() };
    format!("Signed in, but Docker at {} didn't answer. Is Docker running there, and is {who} in the docker group?", s.socket)
}

/// A failed sign-in asks again for the password that didn't work.
fn failed(said: &str, code: Option<i32>, s: &Server) -> Failed {
    let text = why(said, code, s);
    let jump_side = s.jump.as_ref().is_some_and(|j| said.lines().any(|l| l.contains("Permission denied") && l.contains(&format!("@{}", j.host))));
    let need = if !said.contains("Permission denied") {
        None
    } else if jump_side {
        s.jump.as_ref().filter(|j| j.password).map(|_| "jump")
    } else if s.password {
        Some("server")
    } else {
        None
    };
    Failed { text, need }
}

/// "connect to host H port P: …" from ssh's line, for whichever host it was.
fn host_port(line: &str) -> Option<(String, String)> {
    let rest = line.split("connect to host ").nth(1)?;
    let mut w = rest.split_whitespace();
    let host = w.next()?.to_owned();
    let port = w.skip_while(|x| *x != "port").nth(1)?.trim_end_matches(':').to_owned();
    Some((host, port))
}

/// ssh's reason, in a sentence a person can act on, naming the jump host
/// when it was the one that failed.
fn why(said: &str, code: Option<i32>, s: &Server) -> String {
    let l = said.to_lowercase();
    let lines: Vec<&str> = said.lines().map(str::trim).filter(|x| !x.is_empty() && !x.starts_with("Warning: Permanently added")).collect();
    let last = lines.last().copied().unwrap_or("").to_owned();
    let jump = s.jump.as_ref();
    let on_jump = |line: &str| jump.is_some_and(|j| line.contains(&format!("@{}", j.host)) || line.contains(&format!("host {} ", j.host)) || line.contains(&format!("hostname {}", j.host)));
    if let Some(line) = lines.iter().find(|x| x.contains("Permission denied")) {
        if let Some(j) = jump.filter(|_| on_jump(line)) {
            return if j.password { format!("Signing in to the jump host {} failed: check its user name and password", j.host) } else { format!("Signing in to the jump host {} failed: it didn't accept this Mac's SSH key", j.host) };
        }
        return if s.password { "Signing in failed: check the user name and password".to_owned() } else { "Signing in failed: the server didn't accept this Mac's SSH key. Add the key to the server, or choose a password".to_owned() };
    }
    if l.contains("host key verification failed") || l.contains("remote host identification has changed") {
        let who = lines.iter().find(|x| x.contains("Host key for") || x.contains("host key for")).and_then(|x| x.split_whitespace().nth(3)).map(str::to_owned).unwrap_or_else(|| s.host.clone());
        return format!("The host key of {who} has changed since the last connection. If that's expected, remove {who} from ~/.ssh/known_hosts");
    }
    if let Some(line) = lines.iter().find(|x| x.to_lowercase().contains("could not resolve hostname")) {
        let h = line.split("hostname ").nth(1).and_then(|r| r.split(':').next()).unwrap_or(&s.host).to_owned();
        return format!("{h} can't be found: check the address");
    }
    if let Some((h, p)) = lines.iter().find_map(|x| host_port(x).filter(|_| x.to_lowercase().contains("refused"))) {
        return format!("{h} refused SSH on port {p}");
    }
    if let Some((h, p)) = lines.iter().find_map(|x| host_port(x).filter(|_| ["timed out", "no route", "unreachable"].iter().any(|w| x.to_lowercase().contains(w)))) {
        return format!("{h} didn't answer on port {p}");
    }
    // The jump host signed in but couldn't reach the server (ssh -W's channel).
    if let Some(j) = jump.filter(|_| l.contains("stdio forwarding failed") || (l.contains("channel 0: open failed") && l.contains("connect failed"))) {
        return format!("The jump host {} couldn't reach {} on port {}", j.host, s.host, s.port);
    }
    if l.contains("connection refused") {
        return format!("{} refused SSH on port {}", s.host, s.port);
    }
    if l.contains("timed out") || l.contains("no route to host") || l.contains("network is unreachable") {
        return format!("{} didn't answer on port {}", s.host, s.port);
    }
    if l.contains("open failed") || l.contains("administratively prohibited") || l.contains("forwarding failed") {
        return docker_unreached(s);
    }
    match (last.is_empty(), code) {
        (false, _) => last,
        (true, Some(c)) => format!("ssh stopped (exit {c})"),
        (true, None) => "ssh stopped".to_owned(),
    }
}

/// Ends the connection, if any, and points the window back at Kiri.
pub fn disconnect() {
    let gone = live().take();
    client::set_target(None);
    if let Some(mut l) = gone {
        let _ = l.child.kill();
        let _ = l.child.wait();
        let _ = std::fs::remove_file(&l.local);
        crate::diag::info!("disconnected from a server", host = l.server.host);
    }
}

/// Whether the connection in use still stands. When ssh has gone (the
/// server restarted, the network went), the window goes back to Kiri and
/// this says why.
pub fn check() -> Option<String> {
    let mut g = live();
    let l = g.as_mut()?;
    let code = match l.child.try_wait() {
        Ok(None) => return None,
        Ok(Some(st)) => st.code(),
        Err(_) => None,
    };
    let said = l.said.lock().unwrap_or_else(|e| e.into_inner()).clone();
    let why = why(&said, code, &l.server);
    let name = l.server.name.clone();
    drop(g);
    disconnect();
    Some(format!("Lost the connection to {name}: {why}"))
}

/// Where passwords can be kept on this computer.
fn stores() -> Value {
    let system = cfg!(target_os = "macos") || Command::new("secret-tool").arg("--version").stdout(Stdio::null()).stderr(Stdio::null()).status().is_ok();
    json!({"keychain": system, "file": true})
}

/// The page's view of it all: the bookmarks, which is in use, which is
/// connecting, where passwords can be kept; and an error, with whose
/// password to ask for when that's what it needs.
pub fn event(error: Option<(&str, &Failed)>) -> String {
    static STORES: std::sync::OnceLock<Value> = std::sync::OnceLock::new();
    let connecting = CONNECTING.lock().unwrap_or_else(|e| e.into_inner()).clone();
    let mut v = json!({"type": "servers", "servers": load(), "current": current().map(|s| s.id), "connecting": connecting, "stores": STORES.get_or_init(stores)});
    if let Some((id, e)) = error {
        v["error"] = json!({"id": id, "text": e.text, "need": e.need});
    }
    v.to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn server() -> Server {
        Server { id: "a1".into(), name: "web".into(), host: "10.0.0.5".into(), user: "deploy".into(), port: 2222, socket: DEFAULT_SOCKET.into(), ..Default::default() }
    }

    #[test]
    fn forwards_only_the_docker_socket_and_never_prompts() {
        let a = ssh_args(&server(), Path::new("/h/.kiri/run/ssh-a1.sock"));
        let at = |o: &str| a.iter().position(|x| x == o).unwrap();
        assert_eq!(a[at("-L") + 1], "/h/.kiri/run/ssh-a1.sock:/var/run/docker.sock");
        assert_eq!(a[at("-p") + 1], "2222");
        assert!(a.contains(&"BatchMode=yes".to_owned()));
        assert!(a.contains(&"-N".to_owned()));
        assert!(!a.iter().any(|x| x.starts_with("ProxyCommand")));
        // The destination comes last, after `--`, so it can never be read as an option.
        assert_eq!(&a[a.len() - 2..], ["--", "deploy@10.0.0.5"]);
    }

    #[test]
    fn a_password_lets_ssh_ask() {
        let a = ssh_args(&Server { password: true, user: String::new(), ..server() }, Path::new("/s"));
        assert!(!a.contains(&"BatchMode=yes".to_owned()));
        assert_eq!(a.last().unwrap(), "10.0.0.5");
    }

    #[test]
    fn goes_through_a_jump_host_with_its_own_sign_in() {
        let j = Jump { host: "bastion.example".into(), user: "ops".into(), port: 2200, key: "/k/my key%1".into(), password: false };
        let a = ssh_args(&Server { jump: Some(j), password: true, ..server() }, Path::new("/s"));
        let proxy = a.iter().find_map(|x| x.strip_prefix("ProxyCommand=")).unwrap();
        assert!(proxy.starts_with("ssh -W %h:%p "), "{proxy}");
        // The jump host signs in with its key, quietly; the server with its password.
        assert!(proxy.contains("BatchMode=yes") && !a.contains(&"BatchMode=yes".to_owned()));
        assert!(proxy.contains("-i '/k/my key%%1'"), "{proxy}");
        assert!(proxy.ends_with("-p 2200 -- 'ops@bastion.example'"), "{proxy}");
    }

    #[test]
    fn refuses_what_would_reach_ssh_as_an_option() {
        for host in ["-oProxyCommand=sh", "a b", "", "host;rm", "h'x"] {
            assert!(parse(&json!({"host": host})).is_err(), "{host}");
            assert!(parse(&json!({"host": "h", "jump": {"host": host}})).is_err() || host.is_empty(), "jump {host}");
        }
        assert!(parse(&json!({"host": "h", "user": "-l"})).is_err());
        assert!(parse(&json!({"host": "h", "port": "70000"})).is_err());
        assert!(parse(&json!({"host": "h", "socket": "tcp://x"})).is_err());
        assert!(parse(&json!({"host": "h", "jump": {"host": "j", "user": "a;b"}})).is_err());
    }

    #[test]
    fn fills_in_what_was_left_empty() {
        let s = parse(&json!({"host": " [fe80::1] ", "port": "", "jump": {"host": ""}})).unwrap();
        assert_eq!((s.name.as_str(), s.host.as_str(), s.port, s.socket.as_str(), s.jump.is_none()), ("fe80::1", "fe80::1", 22, DEFAULT_SOCKET, true));
        let s = parse(&json!({"host": "h", "jump": {"host": "j", "port": ""}})).unwrap();
        assert_eq!(s.jump.unwrap().port, 22);
    }

    /// Real servers, for a flight test (see docs/features.md):
    /// KIRI_TEST_SSH=user@host:port KIRI_TEST_SSH_KEY=… KIRI_TEST_SSH_PASSWORD=…
    /// [KIRI_TEST_JUMP=user@host:port KIRI_TEST_JUMP_KEY=… KIRI_TEST_JUMP_PASSWORD=…
    ///  KIRI_TEST_BEHIND=host:port, the server as the jump host reaches it]
    /// KIRI_TEST_ASKPASS=target/debug/kiri KIRI_TEST_DIR=<a short folder>
    /// cargo test -p kiri --bin kiri live_server -- --ignored --nocapture --test-threads 1
    #[test]
    #[ignore = "needs SSH servers with Docker"]
    fn live_server_flight() {
        let env = |k: &str| std::env::var(k).ok().filter(|v| !v.is_empty());
        let split = |t: &str| {
            let (user, rest) = t.split_once('@').unwrap();
            let (host, port) = rest.rsplit_once(':').unwrap();
            (user.to_owned(), host.to_owned(), port.to_owned())
        };
        let (user, host, port) = split(&env("KIRI_TEST_SSH").expect("KIRI_TEST_SSH"));
        let dir = env("KIRI_TEST_DIR").expect("KIRI_TEST_DIR");
        // SAFETY: this test runs alone (--ignored, by name, one thread).
        unsafe { std::env::set_var("KIRI_SOCKET", format!("{dir}/run/docker.sock")) };
        let key = env("KIRI_TEST_SSH_KEY").unwrap_or_default();
        let pw = env("KIRI_TEST_SSH_PASSWORD").expect("KIRI_TEST_SSH_PASSWORD");
        let timed = |what: &str, f: &mut dyn FnMut()| {
            let t = Instant::now();
            f();
            eprintln!("  {what}: ok ({} ms)", t.elapsed().as_millis());
        };

        // 1. A key; acting on the server; Kiri's own endpoints stay on Kiri.
        let s = upsert(&json!({"name": "flight", "host": host, "user": user, "port": port, "key": key})).unwrap();
        timed("connect with a key", &mut || drop(connect(&s.id, Creds::default()).unwrap()));
        let info = client::get_background("/info").unwrap();
        eprintln!("    server: {} · Docker {}", info["OperatingSystem"], info["ServerVersion"]);
        let image = "kiri-flight-ssh";
        let made = client::request("POST", "/containers/create?name=kiri-flight-probe", Some(&json!({"Image": image, "Entrypoint": ["sleep", "60"]}))).unwrap();
        assert!(made.ok(), "create: {}", made.error());
        let cid = made.json()["Id"].as_str().unwrap().to_owned();
        assert!(client::request("POST", &format!("/containers/{cid}/start"), None).unwrap().ok());
        // 2. The Processes view while on it: the tunnel, and the probe's sleep.
        let mine = super::super::activity::processes();
        assert!(mine["procs"].as_array().unwrap().iter().any(|p| p["kind"] == "tunnel" && p["name"] == "flight"), "{mine}");
        let procs = super::super::activity::container_procs();
        let probe = procs["containers"].as_array().unwrap().iter().find(|c| c["name"] == "kiri-flight-probe").expect("probe listed").clone();
        assert!(probe["procs"].as_array().unwrap().iter().any(|p| p["cmd"].as_str().is_some_and(|c| c.contains("sleep 60"))), "{probe}");
        eprintln!("  processes: tunnel listed; {} processes in {} containers on the server", procs["containers"].as_array().unwrap().iter().map(|c| c["procs"].as_array().unwrap().len()).sum::<usize>(), procs["containers"].as_array().unwrap().len());
        assert!(client::request("DELETE", &format!("/containers/{cid}?force=1"), None).unwrap().ok());
        disconnect();
        remove(&s.id).unwrap();

        // 3. A password kept in Kiri's file, then in the Keychain: Connect asks nothing.
        for store in ["file", "keychain"] {
            let p = upsert(&json!({"name": format!("pw-{store}"), "host": host, "user": user, "port": port, "password": true, "remember": store, "secret": pw})).unwrap();
            assert!(p.saved && p.remember == store, "{p:?}");
            assert_eq!(secret(&p.id, false).as_deref(), Some(pw.as_str()));
            timed(&format!("connect with a password kept in the {store}"), &mut || drop(connect(&p.id, Creds::default()).unwrap()));
            disconnect();
            remove(&p.id).unwrap();
            assert_eq!(secrets::load(Store::parse(store).unwrap(), &p.id), None, "forgotten with the bookmark");
        }
        // Not kept: Connect says which password it needs.
        let ask = upsert(&json!({"name": "ask", "host": host, "user": user, "port": port, "password": true})).unwrap();
        assert_eq!(connect(&ask.id, Creds::default()).unwrap_err().need, Some("server"));
        let wrong = connect(&ask.id, Creds { password: Some("nope".into()), ..Default::default() }).unwrap_err();
        assert_eq!(wrong.need, Some("server"));
        eprintln!("  wrong password: {} (asks again)", wrong.text);
        remove(&ask.id).unwrap();

        // 4. Test from the form: details, and the window stays where it was.
        let t = test(&json!({"host": host, "user": user, "port": port, "key": key})).unwrap();
        assert!(t["version"].is_string() && current().is_none(), "{t}");
        eprintln!("  test from the form: Docker {} · {} containers", t["version"], t["containers"]);

        // 5. Through a jump host, to a server only it can reach.
        if let (Some(jt), Some(behind)) = (env("KIRI_TEST_JUMP"), env("KIRI_TEST_BEHIND")) {
            let (juser, jhost, jport) = split(&jt);
            let (bhost, bport) = behind.rsplit_once(':').unwrap();
            let jpw = env("KIRI_TEST_JUMP_PASSWORD").unwrap();
            let jkey = env("KIRI_TEST_JUMP_KEY").unwrap();
            // The jump host by key, the server by a password kept in the file.
            let a = upsert(&json!({"name": "behind-a", "host": bhost, "user": user, "port": bport, "password": true, "remember": "file", "secret": pw,
                "jump": {"host": jhost, "user": juser, "port": jport, "key": jkey}})).unwrap();
            timed("jump host by key, server by kept password", &mut || drop(connect(&a.id, Creds::default()).unwrap()));
            let mine = super::super::activity::processes();
            assert!(mine["procs"].as_array().unwrap().iter().any(|p| p["kind"] == "jump"), "{mine}");
            assert!(client::get_background("/containers/json").is_ok());
            disconnect();
            // The jump host by password, typed; the server by key.
            let b = upsert(&json!({"name": "behind-b", "host": bhost, "user": user, "port": bport, "key": key,
                "jump": {"host": jhost, "user": juser, "port": jport, "password": true}})).unwrap();
            assert_eq!(connect(&b.id, Creds::default()).unwrap_err().need, Some("jump"));
            let bad = connect(&b.id, Creds { jump: Some("nope".into()), ..Default::default() }).unwrap_err();
            eprintln!("  wrong jump password: {} (need: {:?})", bad.text, bad.need);
            assert_eq!(bad.need, Some("jump"));
            assert!(bad.text.contains("jump host"), "{}", bad.text);
            timed("jump host by typed password, server by key", &mut || drop(connect(&b.id, Creds { jump: Some(jpw.clone()), ..Default::default() }).unwrap()));
            disconnect();
            // Both by password, both kept in the Keychain.
            let c = upsert(&json!({"name": "behind-c", "host": bhost, "user": user, "port": bport, "password": true, "remember": "keychain", "secret": pw,
                "jump": {"host": jhost, "user": juser, "port": jport, "password": true}, "jumpSecret": jpw})).unwrap();
            assert!(c.saved && c.jump_saved);
            timed("both by passwords kept in the Keychain", &mut || drop(connect(&c.id, Creds::default()).unwrap()));
            disconnect();
            // A server the jump host can't reach is named.
            let d = upsert(&json!({"name": "behind-d", "host": "nowhere.internal", "user": user, "port": bport, "key": key, "jump": {"host": jhost, "user": juser, "port": jport, "key": jkey}})).unwrap();
            let e = connect(&d.id, Creds::default()).unwrap_err();
            eprintln!("  unreachable behind the jump host: {}", e.text);
            for x in [a, b, c, d] {
                remove(&x.id).unwrap();
            }
        }
        assert!(load().is_empty());
    }

    #[test]
    fn explains_ssh_failures() {
        let s = server();
        assert!(why("deploy@10.0.0.5: Permission denied (publickey).", Some(255), &s).contains("SSH key"));
        assert!(why("ssh: connect to host 10.0.0.5 port 2222: Connection refused", Some(255), &s).contains("10.0.0.5 refused SSH on port 2222"));
        assert!(why("channel 2: open failed: administratively prohibited", None, &s).contains("docker group"));
        assert_eq!(why("something else\n", Some(1), &s), "something else");
    }

    #[test]
    fn names_the_jump_host_when_it_is_the_one_that_failed() {
        let s = Server { jump: Some(Jump { host: "bastion".into(), user: "ops".into(), port: 22, password: true, ..Default::default() }), ..server() };
        assert!(why("ops@bastion: Permission denied (password).", Some(255), &s).contains("jump host bastion"));
        assert!(why("ssh: connect to host bastion port 22: Connection refused\r\nConnection closed by UNKNOWN port 65535", Some(255), &s).contains("bastion refused SSH on port 22"));
        assert!(why("channel 0: open failed: connect failed: Name does not resolve\nstdio forwarding failed", Some(255), &s).contains("couldn't reach 10.0.0.5"));
        assert_eq!(failed("ops@bastion: Permission denied (password).", Some(255), &s).need, Some("jump"));
    }
}
