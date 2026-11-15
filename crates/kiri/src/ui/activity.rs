//! The Processes view: what Kiri is doing right now (tasks), the processes
//! Kiri runs on this computer (the window, the engine, a server's SSH
//! tunnel, terminal shells), and the processes inside running containers.
//!
//! A task is begun where the work starts and ends when its guard drops, so
//! the list can't keep one that finished or failed. Each change is sent to
//! the page at once; the processes are read only while the view is open.

use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use serde_json::{Value, json};

use crate::client;

struct Task {
    id: u64,
    kind: String,
    target: String,
    started: u64,
    server: Option<String>,
}

static TASKS: Mutex<Vec<Task>> = Mutex::new(Vec::new());
static NEXT: AtomicU64 = AtomicU64::new(1);

fn now_ms() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_millis() as u64
}

/// A task under way; it ends when this drops.
pub struct Guard(u64);

impl Drop for Guard {
    fn drop(&mut self) {
        TASKS.lock().unwrap_or_else(|e| e.into_inner()).retain(|t| t.id != self.0);
        super::emit(event());
    }
}

/// Begins a task: `kind` is the action ("pull", "start", "connect", …),
/// `target` what it acts on, as the page names it.
pub fn begin(kind: &str, target: &str) -> Guard {
    let id = NEXT.fetch_add(1, Ordering::Relaxed);
    let server = super::remote::current().map(|s| s.name);
    TASKS.lock().unwrap_or_else(|e| e.into_inner()).push(Task { id, kind: kind.to_owned(), target: target.to_owned(), started: now_ms(), server });
    super::emit(event());
    Guard(id)
}

/// Every task under way, oldest first.
pub fn event() -> String {
    let tasks: Vec<Value> = TASKS
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .iter()
        .map(|t| json!({"id": t.id, "kind": t.kind, "target": t.target, "started": t.started, "server": t.server}))
        .collect();
    json!({"type": "tasks", "tasks": tasks, "now": now_ms()}).to_string()
}

/// `ps`'s elapsed time, [[dd-]hh:]mm:ss, in seconds.
fn elapsed(s: &str) -> u64 {
    let (days, rest) = s.split_once('-').map_or((0, s), |(d, r)| (d.parse().unwrap_or(0), r));
    let parts: Vec<u64> = rest.split(':').map(|p| p.parse().unwrap_or(0)).collect();
    let hms = match parts.as_slice() {
        [h, m, s] => h * 3600 + m * 60 + s,
        [m, s] => m * 60 + s,
        [s] => *s,
        _ => 0,
    };
    days * 86400 + hms
}

struct Ps {
    pid: u32,
    ppid: u32,
    cpu: f64,
    rss_kib: u64,
    secs: u64,
    args: String,
}

fn ps() -> Vec<Ps> {
    let Ok(out) = std::process::Command::new("ps").args(["-axo", "pid=,ppid=,pcpu=,rss=,etime=,args="]).output() else { return Vec::new() };
    String::from_utf8_lossy(&out.stdout)
        .lines()
        .filter_map(|l| {
            let mut w = l.split_whitespace();
            let (pid, ppid, cpu, rss, et) = (w.next()?.parse().ok()?, w.next()?.parse().ok()?, w.next()?.replace(',', ".").parse().ok()?, w.next()?.parse().ok()?, w.next()?);
            Some(Ps { pid, ppid, cpu, rss_kib: rss, secs: elapsed(et), args: w.collect::<Vec<_>>().join(" ") })
        })
        .collect()
}

fn base(args: &str) -> &str {
    args.split_whitespace().next().unwrap_or("").rsplit('/').next().unwrap_or("")
}

/// The processes Kiri runs here: this window and what it started, the
/// engine, a server's tunnel and its jump host link, terminal shells.
pub fn processes() -> Value {
    let all = ps();
    let me = std::process::id();
    let tunnel = super::remote::live_tunnel();
    let shells = super::term::pids();
    let mut out = Vec::new();
    let mut seen = std::collections::HashSet::new();
    let mut add = |p: &Ps, kind: &str, name: String| {
        if seen.insert(p.pid) {
            out.push(json!({"pid": p.pid, "kind": kind, "name": name, "cpu": p.cpu, "rss_kib": p.rss_kib, "secs": p.secs, "cmd": p.args}));
        }
    };
    for p in &all {
        let exe = base(&p.args);
        let sub = p.args.split_whitespace().nth(1).unwrap_or("");
        if p.pid == me {
            add(p, "window", "Kiri".to_owned());
        } else if exe.eq_ignore_ascii_case("kiri") && sub == "daemon" {
            add(p, "engine", "Kiri engine".to_owned());
        } else if let Some((_, s, _)) = tunnel.as_ref().filter(|t| t.0 == p.pid) {
            add(p, "tunnel", s.name.clone());
        } else if let Some((_, s, _)) = tunnel.as_ref().filter(|t| t.0 == p.ppid && (exe == "ssh" || exe == "sh")) {
            add(p, "jump", s.jump.as_ref().map(|j| j.host.clone()).unwrap_or_default());
        } else if let Some((id, _)) = shells.iter().find(|(_, pid)| *pid as u32 == p.pid) {
            add(p, "shell", id.clone());
        }
    }
    // Whatever else the window started and is still running (docker, buildx, a sign-in).
    for p in all.iter().filter(|p| p.ppid == me) {
        add(p, "child", base(&p.args).to_owned());
    }
    json!({"type": "kiriprocs", "procs": out})
}

/// Which column of `top`'s titles holds what the view shows.
fn column(titles: &[String], names: &[&str]) -> Option<usize> {
    titles.iter().position(|t| names.iter().any(|n| t.eq_ignore_ascii_case(n)))
}

/// One container's processes, as `top` gives them, in one shape whatever
/// `ps` the engine ran: Kiri's (`ps -ef`'s columns) or a server's own.
fn rows(top: &Value) -> Vec<Value> {
    let titles: Vec<String> = top["Titles"].as_array().into_iter().flatten().filter_map(|t| t.as_str().map(str::to_owned)).collect();
    let pick = |r: &Vec<Value>, names: &[&str]| column(&titles, names).and_then(|i| r.get(i)).and_then(Value::as_str).map(str::to_owned);
    top["Processes"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(|r| r.as_array())
        .map(|r| {
            json!({
                "pid": pick(r, &["PID"]),
                "user": pick(r, &["USER", "UID"]),
                "cpu": pick(r, &["%CPU", "C"]),
                "rss_kib": pick(r, &["RSS"]).and_then(|v| v.parse::<u64>().ok()),
                "time": pick(r, &["ELAPSED", "TIME"]),
                "cmd": pick(r, &["COMMAND", "CMD", "ARGS"]),
            })
        })
        .collect()
}

/// The processes in every running container of the engine in use, read
/// side by side. A server's `ps` is asked for CPU, memory and age; Kiri's
/// engine answers with its own columns.
pub fn container_procs() -> Value {
    let server = super::remote::current().map(|s| s.id);
    let list = match client::get_background("/containers/json") {
        Ok(v) => v,
        Err(e) => return json!({"type": "procs", "server": server, "error": e.to_string()}),
    };
    let running: Vec<&Value> = list.as_array().map(|a| a.iter().collect()).unwrap_or_default();
    let remote = server.is_some();
    let containers: Vec<Value> = std::thread::scope(|scope| {
        let handles: Vec<_> = running
            .iter()
            .map(|c| {
                scope.spawn(move || {
                    let id = c["Id"].as_str().unwrap_or("");
                    let name = c["Names"][0].as_str().unwrap_or("").trim_start_matches('/');
                    let top = if remote {
                        client::get_background(&format!("/containers/{id}/top?ps_args=-eo%20pid,user,pcpu,rss,etime,args")).or_else(|_| client::get_background(&format!("/containers/{id}/top")))
                    } else {
                        client::get_background(&format!("/containers/{id}/top"))
                    };
                    match top {
                        Ok(t) => json!({"id": id, "name": name, "image": c["Image"], "procs": rows(&t)}),
                        Err(e) => json!({"id": id, "name": name, "image": c["Image"], "procs": [], "error": e.to_string()}),
                    }
                })
            })
            .collect();
        handles.into_iter().filter_map(|h| h.join().ok()).collect()
    });
    json!({"type": "procs", "server": server, "containers": containers})
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_ps_elapsed_times() {
        assert_eq!([elapsed("05"), elapsed("01:05"), elapsed("02:01:05"), elapsed("3-02:01:05")], [5, 65, 7265, 266465]);
    }

    #[test]
    fn puts_kiris_and_a_servers_top_in_one_shape() {
        let kiri = json!({"Titles": ["UID", "PID", "PPID", "C", "STIME", "TTY", "TIME", "CMD"], "Processes": [["0", "1", "0", "2", "10:00", "?", "00:00:01", "nginx: master"]]});
        let r = &rows(&kiri)[0];
        assert_eq!((r["pid"].as_str(), r["user"].as_str(), r["cpu"].as_str(), r["cmd"].as_str(), r["rss_kib"].is_null()), (Some("1"), Some("0"), Some("2"), Some("nginx: master"), true));
        let docker = json!({"Titles": ["PID", "USER", "%CPU", "RSS", "ELAPSED", "COMMAND"], "Processes": [["42", "www", "1.5", "2048", "01:02", "php-fpm: pool www"]]});
        let r = &rows(&docker)[0];
        assert_eq!((r["pid"].as_str(), r["cpu"].as_str(), r["rss_kib"].as_u64(), r["time"].as_str()), (Some("42"), Some("1.5"), Some(2048), Some("01:02")));
    }

    #[test]
    fn a_task_lasts_as_long_as_its_guard() {
        let g = begin("pull", "alpine-test-task");
        assert!(event().contains("alpine-test-task"));
        drop(g);
        assert!(!event().contains("alpine-test-task"));
    }
}
