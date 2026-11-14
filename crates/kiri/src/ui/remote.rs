//! Servers: Docker engines on other machines, reached over SSH.
//!
//! The window keeps a list of them (~/.kiri/servers.json, bookmarks only: no
//! passwords). Connecting runs the system's `ssh`, which forwards the
//! server's Docker socket to one in ~/.kiri/run, and points the window's
//! requests at it (`client::set_target`). Containers, images, volumes and
//! networks then list and act on the server, through the same Docker Engine
//! API Kiri speaks. Disconnecting ends `ssh` and the window is back on Kiri.
//!
//! Signing in is ssh's own: a key or the ssh agent, as `ssh user@host` does
//! in a terminal; or a password typed at Connect, handed to ssh through
//! `SSH_ASKPASS` (main.rs answers it) and never written down. A new server's
//! host key is accepted the first time and checked after (`accept-new`).

use std::io::{self, Read};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use crate::client;

/// The variable main.rs answers ssh's password prompt from.
pub const SECRET_ENV: &str = "KIRI_SSH_SECRET";
/// Where Docker listens on a Linux server, unless a bookmark says otherwise.
pub const DEFAULT_SOCKET: &str = "/var/run/docker.sock";
/// How long Connect waits for the server's Docker to answer.
const CONNECT_WAIT: Duration = Duration::from_secs(25);

/// A bookmarked server.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
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
    /// Asks for a password at Connect.
    #[serde(default)]
    pub password: bool,
}

fn default_port() -> u16 {
    22
}

fn default_socket() -> String {
    DEFAULT_SOCKET.to_owned()
}

/// The connection in use.
struct Live {
    server: Server,
    child: Child,
    local: PathBuf,
    /// What ssh said on stderr: why it failed, when it does.
    said: Arc<Mutex<String>>,
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

/// A bookmark from the page's form, checked; `id` empty for a new one.
fn parse(v: &Value) -> io::Result<Server> {
    let text = |k: &str| v[k].as_str().unwrap_or("").trim().to_owned();
    let bad = |why: &str| io::Error::new(io::ErrorKind::InvalidInput, why.to_owned());
    let host = text("host");
    let host = host.trim_start_matches('[').trim_end_matches(']').to_owned();
    if !valid_host(&host) {
        return Err(bad("Enter the server's IP address or host name"));
    }
    let user = text("user");
    if !valid_user(&user) {
        return Err(bad("A user name has only letters, digits, dots, dashes and underscores"));
    }
    let port = match &v["port"] {
        Value::Number(n) => n.as_u64().unwrap_or(0),
        Value::String(s) if s.trim().is_empty() => 22,
        Value::String(s) => s.trim().parse().unwrap_or(0),
        _ => 22,
    };
    if !(1..=65535).contains(&port) {
        return Err(bad("The SSH port is a number from 1 to 65535"));
    }
    let key = expand(&text("key"));
    if !key.is_empty() && !Path::new(&key).is_file() {
        return Err(bad("The key file isn't there"));
    }
    let socket = match text("socket") {
        s if s.is_empty() => DEFAULT_SOCKET.to_owned(),
        s if s.starts_with('/') && !s.contains(char::is_whitespace) && !s.contains(':') => s,
        _ => return Err(bad("Docker's socket is a full path on the server, such as /var/run/docker.sock")),
    };
    let name = match text("name") {
        n if n.is_empty() => host.clone(),
        n => n.chars().take(64).collect(),
    };
    Ok(Server { id: text("id"), name, host, user, port: port as u16, key, socket, password: v["password"].as_bool().unwrap_or(false) })
}

/// Adds a bookmark, or changes the one with its id.
pub fn upsert(v: &Value) -> io::Result<Server> {
    let mut s = parse(v)?;
    let mut list = load();
    if current().is_some_and(|c| c.id == s.id) {
        return Err(io::Error::other("Disconnect from it first"));
    }
    match list.iter_mut().find(|x| !s.id.is_empty() && x.id == s.id) {
        Some(x) => *x = s.clone(),
        None => {
            s.id = new_id();
            list.push(s.clone());
        }
    }
    save(&list)?;
    Ok(s)
}

pub fn remove(id: &str) -> io::Result<()> {
    if current().is_some_and(|c| c.id == id) {
        disconnect();
    }
    let mut list = load();
    list.retain(|s| s.id != id);
    save(&list)
}

fn new_id() -> String {
    let t = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap_or_default();
    format!("{:x}{:x}", t.as_secs(), t.subsec_nanos() ^ std::process::id())
}

/// What ssh runs with: the server's Docker socket forwarded to `local`,
/// nothing else, and no prompt it can't show.
fn ssh_args(s: &Server, local: &Path, password: bool) -> Vec<String> {
    let mut a: Vec<String> = ["-N", "-T", "-x", "-a"].map(String::from).to_vec();
    let mut opt = |o: &str| a.extend(["-o".to_owned(), o.to_owned()]);
    opt("ExitOnForwardFailure=yes");
    opt("StreamLocalBindUnlink=yes");
    opt("StrictHostKeyChecking=accept-new");
    opt("ConnectTimeout=12");
    opt("ServerAliveInterval=15");
    opt("ServerAliveCountMax=3");
    opt("ControlMaster=no");
    opt("ControlPath=none");
    if password {
        opt("NumberOfPasswordPrompts=1");
        opt("PreferredAuthentications=password,keyboard-interactive,publickey");
    } else {
        opt("BatchMode=yes");
    }
    if !s.key.is_empty() {
        opt("IdentitiesOnly=yes");
        a.extend(["-i".to_owned(), s.key.clone()]);
    }
    a.extend(["-p".to_owned(), s.port.to_string()]);
    a.extend(["-L".to_owned(), format!("{}:{}", local.display(), s.socket)]);
    a.push("--".to_owned());
    a.push(if s.user.is_empty() { s.host.clone() } else { format!("{}@{}", s.user, s.host) });
    a
}

/// Where a server's socket comes out on this Mac (short: a unix socket's
/// path has a limit of about 100 bytes).
fn local_socket(id: &str) -> io::Result<PathBuf> {
    let dir = super::state_dir().ok_or_else(|| io::Error::other("HOME is not set"))?.join("run");
    std::fs::create_dir_all(&dir)?;
    let short: String = id.chars().filter(char::is_ascii_alphanumeric).take(12).collect();
    let sock = dir.join(format!("ssh-{short}.sock"));
    // ssh refuses a longer one as a "bad forwarding specification".
    if sock.as_os_str().len() > 100 {
        return Err(io::Error::other(format!("The path for the server's socket is too long for macOS: {}", sock.display())));
    }
    Ok(sock)
}

/// Connects to the bookmark `id`, ending any other connection first, and
/// points the window at it once its Docker answers.
pub fn connect(id: &str, password: Option<String>) -> io::Result<Server> {
    let server = load().into_iter().find(|s| s.id == id).ok_or_else(|| io::Error::other("That server isn't in the list anymore"))?;
    {
        let mut c = CONNECTING.lock().unwrap_or_else(|e| e.into_inner());
        if c.is_some() {
            return Err(io::Error::other("Already connecting"));
        }
        *c = Some(id.to_owned());
    }
    let result = open(&server, password.filter(|p| !p.is_empty()));
    *CONNECTING.lock().unwrap_or_else(|e| e.into_inner()) = None;
    result.map(|()| server)
}

fn open(server: &Server, password: Option<String>) -> io::Result<()> {
    disconnect();
    let local = local_socket(&server.id)?;
    let _ = std::fs::remove_file(&local);
    let mut cmd = Command::new("ssh");
    cmd.args(ssh_args(server, &local, password.is_some())).stdin(Stdio::null()).stdout(Stdio::null()).stderr(Stdio::piped());
    if let Some(p) = &password {
        cmd.env("SSH_ASKPASS", askpass()?).env("SSH_ASKPASS_REQUIRE", "force").env("DISPLAY", ":0").env(SECRET_ENV, p);
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
    loop {
        if let Some(status) = child.try_wait()? {
            std::thread::sleep(Duration::from_millis(100));
            let _ = std::fs::remove_file(&local);
            return Err(io::Error::other(why(&said.lock().unwrap_or_else(|e| e.into_inner()), Some(status.code().unwrap_or(-1)), server)));
        }
        if local.exists() {
            match client::ping_at(&local) {
                Ok(()) => break,
                Err(e) => last = Some(e),
            }
        }
        if began.elapsed() > CONNECT_WAIT {
            let _ = child.kill();
            let _ = child.wait();
            let _ = std::fs::remove_file(&local);
            let told = said.lock().unwrap_or_else(|e| e.into_inner()).clone();
            return Err(io::Error::other(if told.trim().is_empty() && last.is_some() { docker_unreached(server) } else if told.trim().is_empty() { "The server didn't answer in time".to_owned() } else { why(&told, None, server) }));
        }
        std::thread::sleep(Duration::from_millis(150));
    }
    crate::diag::info!("connected to a server", host = server.host);
    client::set_target(Some(local.clone()));
    *live() = Some(Live { server: server.clone(), child, local, said });
    Ok(())
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

/// ssh's reason, in a sentence a person can act on.
fn why(said: &str, code: Option<i32>, s: &Server) -> String {
    let l = said.to_lowercase();
    let last = said.lines().map(str::trim).filter(|x| !x.is_empty() && !x.starts_with("Warning: Permanently added")).last().unwrap_or("").to_owned();
    if l.contains("permission denied") {
        return if s.password { "Signing in failed: check the user name and password".to_owned() } else { "Signing in failed: the server didn't accept this Mac's SSH key. Add the key to the server, or choose a password".to_owned() };
    }
    if l.contains("host key verification failed") || l.contains("remote host identification has changed") {
        return format!("The server's host key has changed since the last connection. If that's expected, remove {} from ~/.ssh/known_hosts", s.host);
    }
    if l.contains("could not resolve hostname") {
        return format!("{} can't be found: check the address", s.host);
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

/// The page's view of it all: the bookmarks, which is in use, which is connecting.
pub fn event(error: Option<(&str, &str)>) -> String {
    let connecting = CONNECTING.lock().unwrap_or_else(|e| e.into_inner()).clone();
    let mut v = json!({"type": "servers", "servers": load(), "current": current().map(|s| s.id), "connecting": connecting});
    if let Some((id, e)) = error {
        v["error"] = json!({"id": id, "text": e});
    }
    v.to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn server() -> Server {
        Server { id: "a1".into(), name: "web".into(), host: "10.0.0.5".into(), user: "deploy".into(), port: 2222, key: String::new(), socket: DEFAULT_SOCKET.into(), password: false }
    }

    #[test]
    fn forwards_only_the_docker_socket_and_never_prompts() {
        let a = ssh_args(&server(), Path::new("/h/.kiri/run/ssh-a1.sock"), false);
        let at = |o: &str| a.iter().position(|x| x == o).unwrap();
        assert_eq!(a[at("-L") + 1], "/h/.kiri/run/ssh-a1.sock:/var/run/docker.sock");
        assert_eq!(a[at("-p") + 1], "2222");
        assert!(a.contains(&"BatchMode=yes".to_owned()));
        assert!(a.contains(&"-N".to_owned()));
        // The destination comes last, after `--`, so it can never be read as an option.
        assert_eq!(&a[a.len() - 2..], ["--", "deploy@10.0.0.5"]);
    }

    #[test]
    fn a_password_lets_ssh_ask() {
        let a = ssh_args(&Server { password: true, user: String::new(), ..server() }, Path::new("/s"), true);
        assert!(!a.contains(&"BatchMode=yes".to_owned()));
        assert_eq!(a.last().unwrap(), "10.0.0.5");
    }

    #[test]
    fn refuses_what_would_reach_ssh_as_an_option() {
        for host in ["-oProxyCommand=sh", "a b", "", "host;rm"] {
            assert!(parse(&json!({"host": host})).is_err(), "{host}");
        }
        assert!(parse(&json!({"host": "h", "user": "-l"})).is_err());
        assert!(parse(&json!({"host": "h", "port": "70000"})).is_err());
        assert!(parse(&json!({"host": "h", "socket": "tcp://x"})).is_err());
    }

    #[test]
    fn fills_in_what_was_left_empty() {
        let s = parse(&json!({"host": " [fe80::1] ", "port": ""})).unwrap();
        assert_eq!((s.name.as_str(), s.host.as_str(), s.port, s.socket.as_str()), ("fe80::1", "fe80::1", 22, DEFAULT_SOCKET));
    }

    /// A real server, for a flight test:
    /// `KIRI_TEST_SSH=user@host:port KIRI_TEST_SSH_KEY=… [KIRI_TEST_SSH_PASSWORD=… KIRI_TEST_ASKPASS=target/debug/kiri]
    /// KIRI_TEST_DIR=<a short folder> cargo test -p kiri --bin kiri live_server -- --ignored --nocapture`
    #[test]
    #[ignore = "needs an SSH server with Docker"]
    fn live_server_lists_and_acts_through_ssh() {
        let env = |k: &str| std::env::var(k).ok().filter(|v| !v.is_empty());
        let target = env("KIRI_TEST_SSH").expect("KIRI_TEST_SSH=user@host:port");
        let (user, rest) = target.split_once('@').unwrap();
        let (host, port) = rest.rsplit_once(':').unwrap();
        let dir = env("KIRI_TEST_DIR").expect("KIRI_TEST_DIR");
        // SAFETY: this test runs alone (--ignored, by name).
        unsafe { std::env::set_var("KIRI_SOCKET", format!("{dir}/run/docker.sock")) };
        let step = |what: &str, began: Instant| eprintln!("  {what}: {} ms", began.elapsed().as_millis());

        // Signing in with a key.
        let s = upsert(&json!({"name": "flight", "host": host, "user": user, "port": port, "key": env("KIRI_TEST_SSH_KEY").unwrap_or_default()})).unwrap();
        assert!(load().iter().any(|x| x.id == s.id), "saved");
        let t = Instant::now();
        connect(&s.id, None).unwrap();
        step("connect with a key", t);
        assert_eq!(current().map(|c| c.id), Some(s.id.clone()));
        assert!(client::target().is_some());
        let info = client::get_background("/info").unwrap();
        eprintln!("  server: {} · Docker {} · {} CPUs", info["OperatingSystem"], info["ServerVersion"], info["NCPU"]);
        let listed = client::get_background("/containers/json?all=1").unwrap();
        eprintln!("  containers on the server: {}", listed.as_array().unwrap().len());
        // Kiri's own endpoints still go to Kiri, never to the server.
        assert!(client::request("GET", "/kiri/nothing", None).map_or(true, |r| r.status != 200 || r.body.is_empty()));

        // Acting on it: a container made, started, stopped and removed there.
        let image = listed.as_array().unwrap().iter().find_map(|c| c["Image"].as_str().filter(|i| i.starts_with("kiri-flight-ssh")).map(str::to_owned)).unwrap_or_else(|| "kiri-flight-ssh".into());
        let made = client::request("POST", "/containers/create?name=kiri-flight-probe", Some(&json!({"Image": image, "Entrypoint": ["sleep", "60"]}))).unwrap();
        assert!(made.ok(), "create: {}", made.error());
        let id = made.json()["Id"].as_str().unwrap().to_owned();
        assert!(client::request("POST", &format!("/containers/{id}/start"), None).unwrap().ok());
        assert_eq!(client::get(&format!("/containers/{id}/json")).unwrap()["State"]["Running"], true);
        let (code, out) = client::exec(&id, &["sh", "-c", "echo flight-ok"]).unwrap();
        assert_eq!((code, out.trim()), (0, "flight-ok"));
        assert!(client::request("DELETE", &format!("/containers/{id}?force=1"), None).unwrap().ok());
        eprintln!("  create, start, exec, remove on the server: ok");
        // Builds: the server's own build history, through its default builder.
        if client::docker_cli().is_some() {
            let builds = crate::builds::list().unwrap();
            assert!(builds.iter().all(|b| b["builder"] == "default"), "{builds:?}");
            eprintln!("  builds on the server: {}", builds.len());
        }

        // Disconnect: back on Kiri, the tunnel's socket gone.
        let sock = live().as_ref().unwrap().local.clone();
        disconnect();
        assert!(current().is_none() && client::target().is_none() && !sock.exists());

        // A dropped connection is noticed and said.
        connect(&s.id, None).unwrap();
        let _ = live().as_mut().unwrap().child.kill();
        std::thread::sleep(Duration::from_millis(300));
        let lost = check().expect("noticed");
        eprintln!("  lost: {lost}");
        assert!(lost.starts_with("Lost the connection to flight") && current().is_none());

        // A key the server doesn't know: a sentence, not ssh's output.
        if let Some(other) = env("KIRI_TEST_SSH_WRONG_KEY") {
            let w = upsert(&json!({"name": "wrong", "host": host, "user": user, "port": port, "key": other})).unwrap();
            let e = connect(&w.id, None).unwrap_err().to_string();
            eprintln!("  wrong key: {e}");
            assert!(e.contains("SSH key"), "{e}");
            remove(&w.id).unwrap();
        }

        // Signing in with a password, through main.rs's askpass.
        if let Some(pw) = env("KIRI_TEST_SSH_PASSWORD") {
            let p = upsert(&json!({"name": "pw", "host": host, "user": user, "port": port, "password": true})).unwrap();
            let e = connect(&p.id, Some("not-it".into())).unwrap_err().to_string();
            eprintln!("  wrong password: {e}");
            assert!(e.contains("password"), "{e}");
            let t = Instant::now();
            connect(&p.id, Some(pw)).unwrap();
            step("connect with a password", t);
            assert!(client::get_background("/_ping").is_ok() || client::alive());
            disconnect();
            remove(&p.id).unwrap();
        }
        remove(&s.id).unwrap();
        assert!(load().is_empty());
    }

    #[test]
    fn explains_ssh_failures() {
        let s = server();
        assert!(why("deploy@10.0.0.5: Permission denied (publickey).", Some(255), &s).contains("SSH key"));
        assert!(why("ssh: connect to host 10.0.0.5 port 2222: Connection refused", Some(255), &s).contains("refused"));
        assert!(why("channel 2: open failed: administratively prohibited", None, &s).contains("docker group"));
        assert_eq!(why("something else\n", Some(1), &s), "something else");
    }
}
