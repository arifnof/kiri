// Servers: Docker on other machines over SSH. Bookmarks list, the form saves,
// a password is asked at Connect only, and while connected the sidebar's card,
// the Docker heading and the port links are the server's.
const R = [];
const t = (name, fn) => { try { fn(); R.push("PASS " + name); } catch (e) { R.push("FAIL " + name + ": " + e.message); } };
const eq = (a, b, m) => { if (JSON.stringify(a) !== JSON.stringify(b)) throw new Error(m + ": got " + JSON.stringify(a) + " want " + JSON.stringify(b)); };
const q = (s) => document.querySelector(s);
const SRV = [
  { id: "s1", name: "prod", host: "10.0.0.5", user: "deploy", port: 22, key: "", socket: "/var/run/docker.sock", password: false },
  { id: "s2", name: "lab", host: "lab.local", user: "", port: 2222, key: "", socket: "/var/run/docker.sock", password: true },
];
const servers = (extra = {}) => kiri.on({ type: "servers", servers: SRV, current: null, connecting: null, ...extra });
servers();
show("servers");

t("the view lists Kiri and each bookmark with its address", () => {
  eq(sent.some((m) => m.type === "servers"), true, "asked for the list");
  const rows = [...document.querySelectorAll("#content tbody tr")].map((r) => r.querySelector("td.mono").textContent);
  eq(rows, ["—", "deploy@10.0.0.5", "lab.local:2222"], "rows");
  eq(document.getElementById("n-servers").textContent, "2", "count");
});

t("Add server opens the form, and Save sends what was typed", () => {
  q("[data-srvadd]").click();
  document.getElementById("srv-host").value = "192.168.1.9";
  document.getElementById("srv-user").value = "root";
  q("[data-srvsave]").click();
  const m = sent.at(-1);
  eq([m.type, m.value.host, m.value.user, m.value.port, m.value.password], ["serversave", "192.168.1.9", "root", "22", false], "sent");
  kiri.on({ type: "serversaved", id: "s3" }); servers();
  eq(q("#srv-form"), null, "form closed");
});

t("a save the app refuses keeps the form and says why", () => {
  q("[data-srvadd]").click();
  q("[data-srvsave]").click();
  servers({ error: { id: "new", text: "Enter the server's IP address or host name" } });
  eq(q("#srv-form .signin-err")?.textContent, "Enter the server's IP address or host name", "error");
  q("[data-srvcancel]").click();
});

t("a key server connects at once; a password one asks first", () => {
  q('[data-srvcon="s1"]').click();
  eq([sent.at(-1).type, sent.at(-1).id, sent.at(-1).value], ["serverconnect", "s1", null], "key");
  servers();
  q('[data-srvcon="s2"]').click();
  eq(sent.at(-1).type !== "serverconnect" || sent.at(-1).id !== "s2", true, "not yet");
  document.getElementById("srv-pass").value = "hunter2";
  q('[data-srvgo="s2"]').click();
  eq([sent.at(-1).type, sent.at(-1).id, sent.at(-1).value], ["serverconnect", "s2", "hunter2"], "password");
});

t("connected: each list reads as loading, not empty, until the server's lists come", () => {
  show("containers");
  servers({ current: "s1" });
  eq(q("#content .srv-wait")?.getAttribute("aria-busy"), "true", "busy");
  eq(q("#content .empty h3").textContent, "Reading containers from prod…", "words");
  eq(document.getElementById("n-containers").textContent, "", "no count yet");
  for (const v of ["images", "volumes", "networks", "builds"]) { show(v); eq(!!q("#content .srv-wait"), true, v); }
  show("containers");
  // Lists Kiri sent just before the switch are not the server's.
  kiri.on({ type: "lists", containers: [{ Id: "k1", Names: ["/local"], Image: "x", State: "running", Ports: [], Labels: {} }], images: [], volumes: [], networks: [] });
  eq(!!q("#content .srv-wait"), true, "stale lists ignored");
  eq(document.getElementById("statusbar").textContent.includes("Connected to prod"), true, "status bar");
});

t("a server whose lists can't be read says so, and Try again asks again", () => {
  kiri.on({ type: "listerror", server: "s1", error: "permission denied" });
  eq([q("#content .empty h3").textContent, q("#content .err").textContent], ["Couldn't read containers from prod", "permission denied"], "error");
  q("[data-srvretry]").click();
  eq([sent.at(-1).type, !!q("#content .srv-wait[aria-busy]")], ["refresh", true], "retry");
});

t("connected: the card, the Docker heading and port links are the server's", () => {
  kiri.on({ type: "vm", remote: true, awake: true, running: 3, cpus: 8, ceiling_mib: 16384, used_mib: 0, target_mib: 0, os: "Ubuntu 24.04", version: "27.3.1" });
  kiri.on({ type: "lists", server: "s1", containers: [{ Id: "r1", Names: ["/api"], Image: "nginx", State: "running", Status: "Up", Ports: [{ PublicPort: 8080, PrivatePort: 80, Type: "tcp" }], Labels: {} }], images: [], volumes: [], networks: [] });
  eq([document.getElementById("vm-name").textContent, document.getElementById("vm-toggle").textContent], ["prod", "Disconnect"], "card");
  eq(document.getElementById("vm-sub").textContent.startsWith("deploy@10.0.0.5"), true, "sub");
  eq(document.getElementById("docker-on").textContent, "· prod", "heading");
  show("containers");
  eq(q('#content [data-open^="http://"]')?.dataset.open, "http://10.0.0.5:8080", "port link");
  document.getElementById("vm-toggle").click();
  eq(sent.at(-1).type, "serverdisconnect", "card disconnects");
});

t("disconnected: back on Kiri, loading Kiri's lists; Kiri off ends the wait", () => {
  servers();
  eq([document.getElementById("vm-name").textContent, document.getElementById("docker-on").hidden], [tr(VM), true], "card");
  eq(q("#content .empty h3").textContent, "Reading containers from Kiri…", "loading Kiri");
  kiri.on({ type: "state", state: "stopped" });
  eq(!!q("#content .srv-wait"), false, "no wait once Kiri is off");
});
report(R);
