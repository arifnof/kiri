// Servers: Docker on other machines over SSH. Bookmarks as cards, the form as
// a dialog (a jump host, passwords kept where the person picks, Test), a
// password asked at Connect when it isn't kept (again when it didn't work),
// the engine switcher atop the sidebar, and while connected the sidebar's
// card, the lists and the port links are the server's.
const R = [];
const t = (name, fn) => { try { fn(); R.push("PASS " + name); } catch (e) { R.push("FAIL " + name + ": " + e.message); } };
const eq = (a, b, m) => { if (JSON.stringify(a) !== JSON.stringify(b)) throw new Error(m + ": got " + JSON.stringify(a) + " want " + JSON.stringify(b)); };
const q = (s) => document.querySelector(s);
const type = (id, v) => { const el = document.getElementById(id); el.value = v; return el; };
const SRV = [
  { id: "s1", name: "prod", host: "10.0.0.5", user: "deploy", port: 22, key: "", socket: "/var/run/docker.sock", password: false },
  { id: "s2", name: "lab", host: "lab.local", user: "", port: 2222, key: "", socket: "/var/run/docker.sock", password: true, remember: "keychain", saved: true },
  { id: "s3", name: "db", host: "10.0.8.21", user: "root", port: 22, key: "", socket: "/var/run/docker.sock", password: true,
    jump: { host: "bastion", user: "ops", port: 22, key: "", password: true } },
];
const servers = (extra = {}) => kiri.on({ type: "servers", servers: SRV, current: null, connecting: null, stores: { keychain: true, file: true }, ...extra });
servers();
show("servers");

t("each bookmark is a card with its address, how it signs in and its jump host", () => {
  eq(sent.some((m) => m.type === "servers"), true, "asked for the list");
  const cards = [...document.querySelectorAll("#content .srv-card[data-key]")];
  eq(cards.map((c) => c.querySelector(".srv-id .mono").textContent), ["deploy@10.0.0.5", "lab.local:2222", "root@10.0.8.21"], "addresses");
  eq(cards[1].textContent.includes("Password · Keychain"), true, "kept in the Keychain");
  eq(cards[2].querySelector(".srv-tag.jump").textContent, "via bastion", "jump host");
  eq(document.getElementById("n-servers").textContent, "3", "count");
});

t("Add server opens a dialog; Save sends what was typed, the jump host too", () => {
  q("[data-srvadd]").click();
  eq(!!q("#srvdlg .srv-dlg"), true, "dialog");
  type("sf-host", "192.168.1.9"); type("sf-user", "root");
  q("[data-sfauth='b']").click();
  type("sf-secret", "hunter2");
  q("[data-sfjump]").click();
  type("sj-host", "bastion.example"); type("sj-user", "ops");
  q("[data-sfremember]").click();
  q("[data-sfsave]").click();
  const m = sent.at(-1);
  eq([m.type, m.value.host, m.value.password, m.value.secret, m.value.remember, m.value.jump.host, m.value.jump.user], ["serversave", "192.168.1.9", true, "hunter2", "keychain", "bastion.example", "ops"], "sent");
  kiri.on({ type: "serversaved", id: "s4" });
  eq(q("#srvdlg"), null, "closed");
});

t("the eye shows the password typed, and asks for a kept one", () => {
  q("[data-srvedit='s2']").click();
  const input = document.getElementById("sf-secret"), eye = q("[data-eye='sf-secret']");
  eq([input.type, input.placeholder.includes("Kept")], ["password", true], "hidden, kept");
  eye.click();
  eq([sent.at(-1).type, sent.at(-1).id, input.type], ["serversecret", "s2", "text"], "asked");
  kiri.on({ type: "serversecret", id: "s2", which: "server", secret: "s3cret" });
  eq(input.value, "s3cret", "filled");
  q("[data-sfclose]").click();
});

t("Test connection says what it found, without saving", () => {
  q("[data-srvadd]").click();
  type("sf-host", "10.1.1.1");
  q("[data-sftest]").click();
  eq([sent.at(-1).type, sent.at(-1).value.host, !!q(".srv-test.busy")], ["servertest", "10.1.1.1", true], "testing");
  kiri.on({ type: "servertest", ok: true, info: { os: "Ubuntu 24.04", version: "27.3.1", cpus: 8, containers: 3 } });
  eq(q(".srv-test.ok").textContent.includes("Ubuntu 24.04 · Docker 27.3.1"), true, "found");
  kiri.on({ type: "servertest", ok: false, error: "10.1.1.1 refused SSH on port 22" });
  eq(q(".srv-test.bad").textContent, "10.1.1.1 refused SSH on port 22", "failed");
  q("[data-sfclose]").click();
});

t("a key server connects at once; a kept password too; one not kept is asked first", () => {
  q('[data-srvcon="s1"]').click();
  eq([sent.at(-1).type, sent.at(-1).id], ["serverconnect", "s1"], "key");
  servers();
  q('[data-srvcon="s2"]').click();
  eq([sent.at(-1).type, sent.at(-1).id, !!q("#srvask")], ["serverconnect", "s2", false], "kept");
  servers();
  q('[data-srvcon="s3"]').click();
  eq([...document.querySelectorAll("#srvask input[type=password]")].map((i) => i.id), ["sp-server", "sp-jump"], "asks both");
  type("sp-server", "a"); type("sp-jump", "b");
  q("[data-spgo]").click();
  eq([sent.at(-1).type, sent.at(-1).value.password, sent.at(-1).value.jump, sent.at(-1).value.remember], ["serverconnect", "a", "b", undefined], "sent both");
});

t("a password that didn't work is asked for again, saying why", () => {
  servers({ error: { id: "s3", text: "Signing in to the jump host bastion failed: check its user name and password", need: "jump" } });
  eq([!!q("#sp-jump"), q("#srvask .srv-err").textContent.includes("jump host bastion")], [true, true], "asked again");
  q("[data-spx]").click();
});

t("connected: each list reads as loading, not empty, until the server's lists come", () => {
  show("containers");
  servers({ current: "s1" });
  eq(q("#content .srv-wait")?.getAttribute("aria-busy"), "true", "busy");
  eq(q("#content .empty h3").textContent, "Reading containers from prod…", "words");
  eq(document.getElementById("n-containers").textContent, "", "no count yet");
  for (const v of ["images", "volumes", "networks", "builds"]) { show(v); eq(!!q("#content .srv-wait"), true, v); }
  show("containers");
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

t("connected: the switcher, the card and port links are the server's", () => {
  kiri.on({ type: "vm", remote: true, awake: true, running: 3, cpus: 8, ceiling_mib: 16384, used_mib: 0, target_mib: 0, os: "Ubuntu 24.04", version: "27.3.1" });
  kiri.on({ type: "lists", server: "s1", containers: [{ Id: "r1", Names: ["/api"], Image: "nginx", State: "running", Status: "Up", Ports: [{ PublicPort: 8080, PrivatePort: 80, Type: "tcp" }], Labels: {} }], images: [], volumes: [], networks: [] });
  eq([document.getElementById("engsw-name").textContent, document.getElementById("engsw-sub").textContent], ["prod", "deploy@10.0.0.5"], "switcher");
  eq([document.getElementById("vm-name").textContent, document.getElementById("vm-toggle").textContent], ["prod", "Disconnect"], "card");
  show("containers");
  eq(q('#content [data-open^="http://"]')?.dataset.open, "http://10.0.0.5:8080", "port link");
});

t("the layout switch shows the servers as a list, a row each, and is kept", () => {
  show("servers");
  q('#hright [data-srvlay="list"]').click();
  eq([sent.at(-1).type, sent.at(-1).name, sent.at(-1).value], ["setpref", "serversLayout", "list"], "kept");
  eq([...document.querySelectorAll("#content .srv-table tbody tr.srv-row:not(.here) .srv-id b")].map((b) => b.textContent), ["prod", "lab", "db"], "rows");
  eq(!!q('#content .srv-table [data-srvedit="s2"]'), true, "edit in the row");
  q('#hright [data-srvlay="cards"]').click();
  eq(!!q("#content .srv-grid"), true, "cards again");
  show("containers");
});

t("the switcher lists Kiri and every server, and picking one switches", () => {
  document.getElementById("engsw").click();
  const items = [...document.querySelectorAll(".menu.engmenu button")];
  eq(items.map((b) => b.dataset.eng), ["", "s1", "s2", "s3", "@manage"], "items");
  eq(!!items[1].querySelector(".engmi-tick svg"), true, "the one in use is ticked");
  items[0].click();
  eq(sent.at(-1).type, "serverdisconnect", "back to Kiri");
});

t("disconnected: back on Kiri, loading Kiri's lists; Kiri off ends the wait", () => {
  servers();
  eq([document.getElementById("vm-name").textContent, document.getElementById("engsw-name").textContent], [tr(VM), "Kiri"], "card");
  eq(q("#content .empty h3").textContent, "Reading containers from Kiri…", "loading Kiri");
  kiri.on({ type: "state", state: "stopped" });
  eq(!!q("#content .srv-wait"), false, "no wait once Kiri is off");
});
report(R);
