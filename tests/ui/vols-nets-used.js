// Volumes and Networks say which containers use each one (a chip per
// container, a click opens it), sort into In use and Unused, and Remove says
// why something in use can't go yet; bulk Delete leaves what's in use.
const R = [];
const t = (name, fn) => { try { fn(); R.push("PASS " + name); } catch (e) { R.push("FAIL " + name + ": " + e.message); } };
const eq = (a, b, m) => { if (JSON.stringify(a) !== JSON.stringify(b)) throw new Error(m + ": got " + JSON.stringify(a) + " want " + JSON.stringify(b)); };
const q = (s) => document.querySelector(s);
const C = (id, name, state, vols, nets) => ({ Id: id, Names: ["/" + name], Image: "x", State: state, Status: "", Ports: [], Labels: {},
  Mounts: vols.map((v) => ({ Type: "volume", Name: v, Destination: "/d" })), NetworkSettings: { Networks: Object.fromEntries(nets.map((n) => [n, {}])) }, HostConfig: { NetworkMode: nets[0] || "default" } });
kiri.on({ type: "lists", containers: [C("a1", "api", "running", ["pg", "up"], ["app"]), C("a2", "worker", "exited", ["up"], ["old"])], images: [],
  volumes: [{ Name: "pg", Driver: "local" }, { Name: "up", Driver: "local" }, { Name: "spare", Driver: "local" }],
  networks: [{ Id: "n1", Name: "bridge", Driver: "bridge" }, { Id: "n2", Name: "app", Driver: "bridge" }, { Id: "n3", Name: "old", Driver: "bridge" }, { Id: "n4", Name: "free", Driver: "bridge" }] });
const scrimText = () => { const s = q(".scrim"); const x = s?.textContent || ""; s?.remove(); return x; };

t("volumes: each one's containers, running first, and not in use", () => {
  show("volumes");
  const rows = [...document.querySelectorAll("#content tbody tr.row")];
  eq(rows.map((r) => [...r.querySelectorAll(".uchip")].map((c) => c.textContent)), [["api"], ["api", "worker"], []], "chips");
  eq(rows[1].querySelector(".uchip.running")?.textContent, "api", "state dot");
  eq(rows[2].textContent.includes("not in use"), true, "unused");
});
t("the tabs count In use and Unused; bulk Delete only picks the unused", () => {
  eq([LISTS.volumes.state(ui.volumes[0]), LISTS.volumes.state(ui.volumes[2])], ["inuse", "unused"], "state");
  eq(pickables("volumes").filter((v) => LISTS.volumes.bulk[0][3](v)).map((v) => v.Name), ["spare"], "deletable");
});
t("a chip opens its container", () => {
  q("#content .uchip").click();
  eq([ui.view, ui.detail?.id], ["containers", "a1"], "opened");
});
t("Remove on a volume in use says which containers, and sends nothing", () => {
  show("volumes");
  const n = sent.length;
  q('[data-rmvol="up"]').click();
  const x = scrimText();
  eq([x.includes("up is in use"), x.includes("api, worker"), sent.length], [true, true, n], "said why");
  q('[data-rmvol="spare"]').click();
  q(".scrim [data-go]").click();
  eq([sent.at(-1).type, sent.at(-1).name], ["rmvol", "spare"], "unused goes");
});
t("networks: a running container blocks Remove; a stopped one is named in the question", () => {
  show("networks");
  const rows = [...document.querySelectorAll("#content tbody tr.row")];
  eq(rows.map((r) => [...r.querySelectorAll(".uchip")].map((c) => c.textContent)), [[], ["api"], ["worker"], []], "chips");
  eq(!!rows[0].querySelector(".tagpill"), true, "built in");
  q('[data-rmnet="n2"]').click();
  eq(scrimText().includes("api is running on this network"), true, "blocked");
  q('[data-rmnet="n3"]').click();
  eq(q(".scrim").textContent.includes("worker is on this network"), true, "warned");
  q(".scrim [data-go]").click();
  eq([sent.at(-1).type, sent.at(-1).id], ["rmnet", "n3"], "removed");
});
report(R);
