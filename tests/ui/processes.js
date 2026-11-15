// Processes: what Kiri is doing (each task the app says it's doing, with the
// page's own progress), the processes Kiri runs on this computer, and the
// processes in the running containers, read live while the view is open.
const R = [];
const t = (name, fn) => { try { fn(); R.push("PASS " + name); } catch (e) { R.push("FAIL " + name + ": " + e.message); } };
const eq = (a, b, m) => { if (JSON.stringify(a) !== JSON.stringify(b)) throw new Error(m + ": got " + JSON.stringify(a) + " want " + JSON.stringify(b)); };
const q = (s) => document.querySelector(s);
const now = Date.now();

t("nothing under way: it says so, and the sidebar counts nothing", () => {
  show("processes");
  eq(sent.some((m) => m.type === "tasks"), true, "asked for the tasks");
  eq(!!q("#content .pr-none"), true, "says so");
  eq(document.getElementById("n-processes").textContent, "", "no count");
});

t("each task reads as what it does, by name, with a pull's progress and Cancel", () => {
  ui.pulls.set("postgres:17", { name: "postgres:17", phase: "pulling", got: 50e6, total: 100e6 });
  kiri.on({ type: "tasks", now, tasks: [{ id: 1, kind: "pull", target: "postgres:17", started: now - 5000 }, { id: 2, kind: "restart", target: "a2", started: now - 1000 }, { id: 3, kind: "start", target: "", started: now }] });
  const titles = [...document.querySelectorAll(".pr-task b")].map((b) => b.textContent);
  eq(titles, ["Pulling postgres:17", "Restarting api", `Starting ${VM}`], "titles");
  eq(q(".pr-task .pr-bar span").style.width, "50%", "progress");
  q(".pr-task [data-pcancel]").click();
  eq(sent.at(-1).type, "cancelpull", "Cancel");
  eq(document.getElementById("n-processes").textContent, "3", "sidebar count");
  eq(document.getElementById("statusbar").textContent.includes("3 tasks"), true, "status bar");
});

t("Kiri's processes: the window, the engine and a server's tunnel, with Disconnect", () => {
  kiri.on({ type: "kiriprocs", procs: [
    { pid: 10, kind: "window", name: "Kiri", cpu: 1.5, rss_kib: 102400, secs: 90, cmd: "kiri ui" },
    { pid: 11, kind: "engine", name: "Kiri engine", cpu: 0.2, rss_kib: 15000, secs: 7200, cmd: "kiri daemon" },
    { pid: 12, kind: "tunnel", name: "prod", cpu: 0, rss_kib: 6000, secs: 60, cmd: "ssh -N … deploy@10.0.0.5" }] });
  const rows = [...document.querySelectorAll(".pr-table tbody tr")];
  eq(rows.map((r) => r.querySelector(".name > div > div").textContent), ["Kiri window", "Kiri engine", "SSH tunnel to prod"], "names");
  eq(rows[0].textContent.includes("100 MB"), true, "memory");
  rows[2].querySelector("[data-srvoff]").click();
  eq(sent.at(-1).type, "serverdisconnect", "Disconnect");
});

t("Container processes: grouped by container, searchable, asked for again while open", () => {
  q("#hright [data-prtab='procs']").click();
  eq(sent.at(-1).type, "procs", "asked");
  kiri.on({ type: "procs", server: null, containers: [
    { id: "a1", name: "web", image: "nginx:alpine", procs: [{ pid: "1", user: "root", cpu: "0", time: "00:00:02", cmd: "nginx: master process" }, { pid: "29", user: "nginx", cpu: "0", time: "00:00:00", cmd: "nginx: worker process" }] },
    { id: "a2", name: "api", image: "node:22", procs: [{ pid: "1", user: "node", cpu: "3", time: "00:01:00", cmd: "node server.js" }] }] });
  eq(document.querySelectorAll(".pr-group").length, 2, "groups");
  eq(document.querySelectorAll("table.procs tbody tr.row").length, 3, "rows");
  ui.filter = "worker"; render();
  eq([...document.querySelectorAll("table.procs td.pr-cmd")].map((d) => d.textContent), ["nginx: worker process"], "search");
  ui.filter = ""; render();
});

t("another engine's processes are not this one's", () => {
  kiri.on({ type: "procs", server: "elsewhere", containers: [] });
  eq(document.querySelectorAll(".pr-group").length, 2, "kept");
});
report(R);
