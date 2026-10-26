/* AegisLab console (Phase R1). Talks only to this origin: /api/... (the unchanged control plane) and /api/lab/... (aegis/console.py).
   Every number on screen comes from those endpoints or from files they read; nothing here is a hard-coded result. */
"use strict";

const S = {
  status: null, tokens: {}, runs: [], labRun: null, result: null, selScenario: null, timers: [],
  ev: { run: "all", actor: "all", type: "all", decision: "all", live: true }, evData: [],
  bundles: [], selBundle: null, verify: {}, tamper: {}, mem: {}, exp: null, topoSel: "broker", journal: [],
};
const $ = (s, el = document) => el.querySelector(s);
const $$ = (s, el = document) => Array.from(el.querySelectorAll(s));
const esc = (v) => String(v ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
const short = (d, n = 16) => (d ? esc(String(d).replace(/^sha256:/, "").slice(0, n)) + "…" : "—");
const when = (t) => (t ? new Date(t * 1000).toLocaleString([], { day: "2-digit", month: "short", hour: "2-digit", minute: "2-digit", second: "2-digit" }) : "—");
const ROLE_NAMES = { observer: "Observer (no token)", operator: "Operator", reviewer: "Reviewer", blue_participant: "Blue participant", red_participant: "Red participant" };
const STATES = ["CREATED", "FROZEN", "RUNNING", "SEALED", "RELEASED"];
const STATE_HELP = { CREATED: "inputs staged", FROZEN: "config digests fixed", RUNNING: "brokered execution", SEALED: "results held", RELEASED: "reviewer released" };

/* ---------------------------------------------------------------- API */
class NetError extends Error {}
async function call(path, { method = "GET", body, role } = {}) {
  const headers = {};
  if (body !== undefined) headers["Content-Type"] = "application/json";
  if (role && role !== "observer") {
    if (!S.tokens[role]) return { status: 0, ok: false, body: { detail: "no demo identity for " + role + " (start the console with scripts/start_prototype.sh)" } };
    headers["X-Aegis-Token"] = S.tokens[role];
  }
  let r;
  try { r = await fetch(path, { method, headers, body: body === undefined ? undefined : JSON.stringify(body), cache: "no-store" }); }
  catch (e) { throw new NetError("The console server is not reachable. Is scripts/start_prototype.sh still running?"); }
  let b = null;
  const ct = r.headers.get("content-type") || "";
  if (ct.includes("json")) b = await r.json().catch(() => null); else b = { text: await r.text().catch(() => "") };
  return { status: r.status, ok: r.ok, body: b };
}
async function get(path, opts) {
  const r = await call(path, opts);
  if (!r.ok) { const e = new Error((r.body && r.body.detail) || "HTTP " + r.status); e.status = r.status; throw e; }
  return r.body;
}
function classify(status) {
  if (status === 0) return { kind: "error", text: "No response: the request did not reach the server" };
  if (status < 300) return { kind: "allowed", text: "Allowed by policy" };
  if (status === 401) return { kind: "denied", text: "Denied: unknown identity (HTTP 401)" };
  if (status === 403) return { kind: "denied", text: "Denied by policy (HTTP 403): a security decision, not a malfunction" };
  if (status === 404) return { kind: "invalid", text: "Not found (HTTP 404)" };
  if (status === 409) return { kind: "denied", text: "Refused by the lifecycle gate (HTTP 409)" };
  if (status === 400 || status === 422) return { kind: "invalid", text: "Malformed request rejected (HTTP " + status + ")" };
  if (status === 429) return { kind: "invalid", text: "Busy: too many concurrent requests (HTTP 429)" };
  if (status === 503) return { kind: "error", text: "Unavailable: a runtime dependency is missing (HTTP 503)" };
  return { kind: "error", text: "Backend failure (HTTP " + status + "): this is not a security result" };
}
function toast(msg, err) {
  const t = $("#toast"); t.textContent = msg; t.className = "toast show" + (err ? " err" : "");
  clearTimeout(t._h); t._h = setTimeout(() => (t.className = "toast"), 4200);
}
/* Two-step confirmation for final actions: the first click arms the button for 8 s, the second one acts. */
function armed(btn, label, why) {
  if (btn.dataset.armed === "1") { btn.dataset.armed = ""; btn.textContent = btn.dataset.label; const n = btn.parentElement.querySelector(".arm-note"); if (n) n.remove(); return true; }
  btn.dataset.armed = "1"; btn.dataset.label = btn.textContent; btn.textContent = label;
  const note = document.createElement("span"); note.className = "why arm-note"; note.textContent = why; btn.after(note);
  setTimeout(() => { if (btn.dataset.armed === "1") { btn.dataset.armed = ""; btn.textContent = btn.dataset.label; note.remove(); } }, 8000);
  return false;
}
function every(ms, fn) { const id = setInterval(fn, ms); S.timers.push(id); return id; }
function busy(btn, on) { if (!btn) return; btn.disabled = on; btn.classList.toggle("busy", on); btn.setAttribute("aria-busy", on ? "true" : "false"); }

/* ---------------------------------------------------------------- boot and status */
async function boot() {
  try { S.tokens = (await get("/api/demo/identities")).tokens || {}; } catch (e) { S.tokens = {}; }
  await refreshStatus();
  setInterval(refreshStatus, 15000);
  window.addEventListener("hashchange", route);
  $("#drawer-close").addEventListener("click", closeDrawer);
  $("#drawer").addEventListener("click", (e) => { if (e.target.id === "drawer") closeDrawer(); });
  document.addEventListener("keydown", (e) => { if (e.key === "Escape" && !$("#drawer").hidden) closeDrawer(); });
  route();
}
async function refreshStatus() {
  try {
    S.status = await get("/api/lab/status");
  } catch (e) {
    S.status = null;
    $("#strip").innerHTML = `<span class="pill bad">Control plane unreachable</span><span>${esc(e.message)}</span>`;
    $("#mode-pill").className = "pill bad"; $("#mode-pill").textContent = "Offline";
    return;
  }
  const st = S.status, pm = st.podman || {};
  const live = st.mode === "live";
  $("#mode-pill").className = "pill " + (live ? "acc" : "warn");
  $("#mode-pill").textContent = live ? "Live mode" : "Degraded: replay available";
  $("#strip").innerHTML = [
    `<span><b>Control plane</b> connected</span>`,
    live ? `<span><b>Containers</b> Podman ${esc(pm.podman)} rootless, ${esc(pm.oci_runtime)}</span>` : `<span class="pill warn">Live containers unavailable</span><span>${esc(st.mode_reason)}</span>`,
    `<span><b>Model</b> ${esc(st.model.label)}</span>`,
    `<span><b>Identities</b> ${st.demo_identities ? "local demo tokens, checked server-side" : "not issued (actions disabled)"}</span>`,
    `<span class="faint">State ${esc(st.state_dir)}</span>`,
  ].join("");
}

/* ---------------------------------------------------------------- router */
const PAGES = { overview, topology, lab, events, evidence, experiments, limits };
function route() {
  S.timers.forEach(clearInterval); S.timers = [];
  const h = (location.hash.replace(/^#\/?/, "") || "overview").split("?")[0];
  const page = PAGES[h] ? h : "overview";
  $$(".nav a").forEach((a) => a.classList.toggle("active", a.dataset.nav === page));
  $$(".nav a").forEach((a) => (a.dataset.nav === page ? a.setAttribute("aria-current", "page") : a.removeAttribute("aria-current")));
  window.scrollTo(0, 0);
  PAGES[page]().catch((e) => render(`<div class="note bad">This page could not load: ${esc(e.message)}</div>`));
}
function render(html) { $("#main").innerHTML = html; }
function query(k) { const q = location.hash.split("?")[1]; return q ? new URLSearchParams(q).get(k) : null; }

/* ---------------------------------------------------------------- shared fragments */
function lifecycle(rec) {
  if (!rec) return `<div class="empty">No run yet.</div>`;
  const failed = rec.state === "FAILED";
  const idx = STATES.indexOf(rec.state);
  const ts = { CREATED: rec.created_at, FROZEN: rec.frozen_at, RUNNING: rec.started_at, SEALED: rec.sealed_at, RELEASED: rec.released_at };
  return `<ol class="life life-wrap" aria-label="Run lifecycle">${STATES.map((s, i) => {
    const cls = failed ? (ts[s] ? "done" : i === idx + 1 ? "fail" : "") : i <= idx ? "done" + (i === idx ? " now" : "") : "";
    return `<li class="${cls}"><b>${s}</b><span>${ts[s] ? when(ts[s]) : STATE_HELP[s]}</span></li>`;
  }).join("")}</ol>${failed ? `<p class="dec failed small mt">Run FAILED: it failed closed and is not releasable.</p>` : ""}`;
}
function decisionOf(e) { return e.decision || (e.type === "policy.denied" ? "denied" : "info"); }
function verdictBox(v, title) {
  const map = { PASS: ["pass", "PASS", "The expected security outcome was observed."], FAIL: ["fail", "FAIL", "A security expectation did not hold. See the marked rows."],
    ERROR: ["error", "ERROR", "The backend failed. This is not a security result."] };
  const [cls, word, text] = map[v] || ["error", v, ""];
  return `<div class="verdict ${cls}" role="status"><b>${word}</b><div><div>${esc(title)}</div><div class="small muted">${text}</div></div></div>`;
}
function labelTag(kind) {
  const m = { live: ["live", "LIVE SYSTEM TEST"], rec: ["rec", "RECORDED EXECUTION"], pre: ["pre", "PRECOMPUTED REAL-MODEL EVIDENCE"], stub: ["stub", "STUB-MODEL TEST"] };
  return `<span class="tag ${m[kind][0]}">${m[kind][1]}</span>`;
}
function openDrawer(title, html) { $("#drawer-title").textContent = title; $("#drawer-body").innerHTML = html; $("#drawer").hidden = false; $("#drawer-close").focus(); }
function closeDrawer() { $("#drawer").hidden = true; }
async function loadRuns() { try { S.runs = await get("/api/runs"); } catch (e) { S.runs = []; } return S.runs; }
async function loadJournal() { try { S.journal = await get("/api/lab/journal"); } catch (e) { S.journal = []; } return S.journal; }

/* ================================================================ A. overview */
async function overview() {
  render(`<div class="empty">Loading the current state…</div>`);
  const [runs, tl, jr] = await Promise.all([loadRuns(), get("/api/lab/timeline?limit=400").catch(() => []), loadJournal()]);
  if (!S.status) await refreshStatus();
  const st = S.status || {};
  const pm = st.podman || {};
  const latest = runs[0];
  const integ = st.integrity_latest_terminal_run;
  const shipped = st.integrity_shipped_bundle || {};
  const done = (k) => jr.some((j) => j.kind === k && (j.verdict === "PASS" || j.verdict === "STARTED"));
  const recent = tl.filter((e) => ["denied", "failed", "alert"].includes(decisionOf(e))).slice(0, 7);
  render(`
  <section class="hero">
    <div>
      <h1>Try the walls of an AI red-team evaluation, then check the record yourself.</h1>
      <p class="lede">Attack payloads, defence rules and the model under test share one machine. AegisLab keeps them apart with rootless containers and a trusted broker, not with instructions to the model, and writes every decision into a hash-chained, signed log that a separate verifier can check.</p>
      <ol class="path" aria-label="Suggested walkthrough">
        <li class="${done("prepare") ? "done" : ""}"><div><a href="#/lab">Start a live evaluation run</a><div class="small muted">Red sandbox, defence runner and model worker start in fresh hardened containers.</div></div></li>
        <li class="${done("prohibited-access") ? "done" : ""}"><div><a href="#/lab?s=prohibited-access">Attempt prohibited access</a><div class="small muted">The red participant tries to read sealed results and release the run.</div></div></li>
        <li class="${done("cross-role-isolation") ? "done" : ""}"><div><a href="#/lab?s=cross-role-isolation">Cross a role boundary</a><div class="small muted">Blue reaches for red's payloads; the red sandbox's own forbidden requests are read back.</div></div></li>
        <li class="${done("authorized-release") ? "done" : ""}"><div><a href="#/lab?s=authorized-release">Release as the reviewer</a><div class="small muted">The one permitted path to the results, with a signed terminal checkpoint.</div></div></li>
        <li class="${jr.some((j) => j.kind.startsWith("tamper:") && j.verdict === "PASS") ? "done" : ""}"><div><a href="#/evidence">Verify, then tamper with a copy</a><div class="small muted">The independent verifier accepts the original and rejects the modified copy.</div></div></li>
      </ol>
    </div>
    <div class="box">
      <h2>System health</h2>
      <ul class="plain status-list">
        <li><span class="s-k">Control plane</span><span class="s-v">${st.control_plane ? `<span class="pill acc">Connected</span>` : `<span class="pill bad">Unreachable</span>`}</span></li>
        <li><span class="s-k">Container runtime</span><span class="s-v">${pm.available ? `Podman ${esc(pm.podman)}, rootless, ${esc(pm.oci_runtime)}` : `<span class="pill warn">Unavailable</span><br><span class="small muted">${esc(st.mode_reason || pm.reason)}</span>`}</span></li>
        <li><span class="s-k">Sandbox image</span><span class="s-v">${pm.image_present ? esc(pm.image) : `<span class="pill warn">Not built</span>`}</span></li>
        <li><span class="s-k">Kernel isolation</span><span class="s-v">${pm.available ? `SELinux ${pm.selinux ? "on" : "off"}, cgroups ${esc(pm.cgroups)}, cpuset ${pm.cpuset_delegated ? "pinned" : `<span class="dec warning">not delegated</span>`}` : "—"}</span></li>
        <li><span class="s-k">Model execution</span><span class="s-v">${esc(st.model ? st.model.label : "—")}<br><span class="small muted">${esc(st.model ? st.model.detail : "")}</span></span></li>
        <li><span class="s-k">Identities</span><span class="s-v">${st.demo_identities ? "Local demo tokens (loopback only)" : `<span class="pill warn">Not issued</span>`}</span></li>
        <li><span class="s-k">Code tree</span><span class="s-v hash">${st.code_revision ? short(st.code_revision.tree_sha256, 20) + " (" + st.code_revision.files + " files)" : "—"}</span></li>
      </ul>
    </div>
  </section>

  <section class="section grid g3">
    <div class="box">
      <div class="spread"><h3>Latest run</h3>${latest ? `<span class="mono small">${esc(latest.id)}</span>` : ""}</div>
      ${latest ? lifecycle(latest) + `<p class="small muted mt">${latest.evaluated ?? 0} of ${latest.attack_count ?? "?"} attacks evaluated${latest.state === "RUNNING" ? " so far" : ""}.</p>` : `<div class="empty">No run in this state directory yet. <a href="#/lab">Start one in the attack lab.</a></div>`}
    </div>
    <div class="box">
      <h3>Evidence integrity</h3>
      ${integ ? `<p><span class="pill ${integ.ok ? "ok" : "bad"}">${integ.ok ? "Verified" : "Verification failed"}</span></p>
        <p class="small">${esc(integ.run_id)} (${esc(integ.state)}): ${integ.entries} entries, ${integ.checkpoints_checked} signed checkpoints, terminal checkpoint ${integ.terminal_verified ? "verified" : "missing"}.</p>
        <p class="small muted">Checked against ${esc(integ.checked_against)}.</p>${integ.findings.map((f) => `<p class="small dec failed">${esc(f)}</p>`).join("")}`
        : `<p class="small muted">No released or failed run here yet; a run's log can only be verified strictly once it has a terminal checkpoint.</p>`}
      <p class="small" style="margin-top:10px">Shipped bundle DEMO-001 via the independent verifier: ${shipped.exit_code === 0 && shipped.ok ? `<span class="dec ok">exit 0, ok</span>` : shipped.exit_code == null ? "not checked" : `<span class="dec failed">exit ${esc(shipped.exit_code)}</span>`}. <a href="#/evidence">Open the verification centre</a></p>
    </div>
    <div class="box">
      <h3>What is live here</h3>
      <ul class="plain small">
        <li>${labelTag("live")} runs, refusals, sandbox probes and verification on this machine</li>
        <li>${labelTag("stub")} the model in live runs is a deterministic stub, not an LLM</li>
        <li>${labelTag("pre")} saved Qwen2.5-0.5B runs, recomputed from raw files on request</li>
        <li>${labelTag("rec")} a saved judge-demo transcript, shown only when containers are unavailable</li>
      </ul>
    </div>
  </section>

  <section class="section">
    <div class="spread"><h2>Recent security events</h2><a href="#/events">All events</a></div>
    ${recent.length ? `<div class="table-wrap"><table><thead><tr><th>Time</th><th>Run</th><th>Actor</th><th>Event</th><th>Decision</th><th>Summary</th></tr></thead><tbody>
      ${recent.map((e) => `<tr><td class="small">${when(e.ts)}</td><td class="mono">${esc(e.run_id)}</td><td>${esc(e.actor)}</td><td class="mono">${esc(e.type)}</td><td><span class="dec ${esc(decisionOf(e))}">${esc(decisionOf(e))}</span></td><td>${esc(e.summary)}</td></tr>`).join("")}
    </tbody></table></div>` : `<div class="empty">No denials or alerts recorded yet. They appear here as soon as a run or scenario produces one.</div>`}
  </section>

  <section class="section grid g2">
    <div class="box">
      <h3>Demonstrations in this session</h3>
      ${jr.length ? `<ul class="plain small">${jr.slice(0, 8).map((j) => `<li class="spread"><span>${esc(j.title)} ${j.run_id ? `<span class="mono faint">${esc(j.run_id)}</span>` : ""}</span><span class="dec ${j.verdict === "PASS" ? "ok" : j.verdict === "STARTED" ? "" : "failed"}">${esc(j.verdict)}</span></li>`).join("")}</ul><p class="tiny">Console journal: an unsigned convenience list. The signed record is each run's audit log.</p>`
        : `<div class="empty">Nothing run yet. Start with the attack lab.</div>`}
    </div>
    <div class="box">
      <h3>Known limitations</h3>
      <ul class="small" style="padding-left:18px;margin:6px 0">
        <li>The broker, its signing key, the host kernel and Podman are trusted, not defended.</li>
        <li>Containers share one kernel and one CPU; hardware side channels are untested.</li>
        <li>Role tokens are global per role and handed to this local browser in demo mode.</li>
        <li>Zero observed leaks in finite tests is evidence for this configuration, not proof.</li>
      </ul>
      <a href="#/limits">Threat model and limits</a>
    </div>
  </section>`);
}

/* ================================================================ B. topology */
const NODES = {
  red: { x: 40, y: 70, w: 180, h: 64, t: "Red-team sandbox", s: "attack payloads",
    role: "Runs the red team's attack agent against the model under test.",
    trust: "Untrusted. Assumed hostile: may plant links, FIFOs or oversized messages in its own mailbox.",
    allow: ["Write requests into its own mailbox (spool/out)", "Read the broker's replies (spool/in)", "Read its own attack pack, read-only"],
    deny: ["Any network connection (no interfaces besides loopback)", "Reaching the defence runner or model worker directly", "Reading the frozen defence config or sealed results", "Claiming another tenant's identity in a message"],
    controls: ["--network none, --read-only, --cap-drop ALL, no-new-privileges", "--userns keep-id (non-root), pids/memory/CPU limits", "Private SELinux label per container (:Z)"],
    flags: "red", test: ["sandbox-containment", "cross-role-isolation"] },
  blue: { x: 40, y: 250, w: 180, h: 64, t: "Defence runner (blue)", s: "frozen defence config",
    role: "Applies the blue team's frozen input and output rules to every attack and model answer.",
    trust: "A peer, not trusted: anything other than a clear allow or block verdict is treated as block.",
    allow: ["Read the frozen config, read-only", "Answer the broker's inspect_input / inspect_output requests"],
    deny: ["Network access", "Reaching red or the model directly", "Changing its config after freeze (digest attested at start)"],
    controls: ["Same hardening flags as red", "Config digest attested against the frozen manifest"], flags: "blue", test: ["cross-role-isolation"] },
  model: { x: 40, y: 420, w: 180, h: 64, t: "Model worker", s: "client model",
    role: "Answers prompts. Live runs use a deterministic stub; saved experiments used Qwen2.5-0.5B on CPU llama.cpp.",
    trust: "Untrusted output: the broker withholds any answer carrying another run's canary or a control-plane secret.",
    allow: ["Answer generate requests from the broker"],
    deny: ["Network access", "Keeping state between runs (fresh container per run)", "Seeing other tenants' data"],
    controls: ["Fresh container per run, destroyed at seal", "Stateless requests for a real-model backend (cache_prompt false)"], flags: "model", test: [] },
  broker: { x: 316, y: 214, w: 178, h: 110, t: "Trusted broker", s: "sole path between sandboxes", trusted: true,
    role: "Moves every message between the sandboxes, checks attack commitments, applies timing padding, seals artifacts and writes the audit log.",
    trust: "TRUSTED. It sees every payload and signs every checkpoint. A compromised broker can sign a false but consistent record; this is not defended.",
    allow: ["Read red's mailbox; reply after padding", "Call the defence runner and model worker", "Write the sealed store and the audit log"],
    deny: ["Following links or blocking on FIFOs in tenant mailboxes (O_NOFOLLOW, O_NONBLOCK)", "Answering red with another run's canary or a secret"],
    controls: ["Identity bound to the mailbox, never to a claimed field", "Commit-then-reveal for every attack", "Uniform refusal text and timing buckets"], test: ["cross-role-isolation", "sandbox-containment"] },
  net: { x: 316, y: 62, w: 178, h: 52, t: "Network and host", s: "outside every sandbox",
    role: "The internet, the host's services and this console's port.", trust: "Out of reach for tenant containers.",
    allow: [], deny: ["Any connection from a sandbox (TCP, DNS)"], controls: ["--network none"], test: ["sandbox-containment"] },
  people: { x: 590, y: 22, w: 200, h: 54, t: "People (browser)", s: "every role, by local token",
    role: "Humans using the control plane through this console.", trust: "Identified by local demo tokens; production would use SSO with run-scoped claims.",
    allow: ["Observer: the redacted monitoring stream", "Operator: create, freeze, start", "Reviewer: release, then read results"],
    deny: ["Participants reading sealed results before release", "Anyone but the reviewer releasing a run"], controls: ["Constant-time token comparison", "Role checks in every handler"], test: ["prohibited-access"] },
  api: { x: 590, y: 120, w: 200, h: 64, t: "Control-plane API", s: "roles and the result gate",
    role: "FastAPI service that enforces roles and the run lifecycle (CREATED, FROZEN, RUNNING, SEALED, RELEASED).",
    trust: "Trusted component on the same host as the broker.",
    allow: ["Release by the reviewer of a SEALED run that verifies", "Artifacts after release to reviewer and participants"],
    deny: ["Artifact reads before release (logged as policy.denied)", "Release by any other role (logged)", "Secret digests to non-privileged roles before release"],
    controls: ["Lifecycle lock: one state transition at a time", "Release re-verifies the chain and the commitments first"], test: ["prohibited-access", "authorized-release"] },
  sealed: { x: 590, y: 250, w: 200, h: 64, t: "Sealed result store", s: "payloads, outputs, verdicts",
    role: "Holds every raw artifact of the run until release.", trust: "Protected evaluation artifacts.",
    allow: ["Broker writes", "Reviewer and participants read after release"], deny: ["Any read before release", "Observers, ever"],
    controls: ["Result gate in the API", "Digest of the sealed artifacts bound into the audit log"], test: ["prohibited-access", "authorized-release"] },
  audit: { x: 590, y: 362, w: 200, h: 64, t: "Audit log, vault, anchor", s: "hash chain + Ed25519 checkpoints",
    role: "Append-only hash-chained log with signed, chained checkpoints copied to a reviewer vault, and a signed terminal anchor.",
    trust: "Integrity is checkable without trusting the files: a verifier needs only the pinned public key.",
    allow: ["Append by the control plane", "Export as a reviewer bundle"], deny: ["Undetected edit, deletion, reordering or truncation"],
    controls: ["Signing key mode 0600 (same Unix user: a stated limit)", "Terminal checkpoint closes the chain"], test: ["authorized-release"] },
  verifier: { x: 590, y: 462, w: 200, h: 50, t: "Independent verifier", s: "python -m aegis.verify_cli",
    role: "A separate program a reviewer runs on their own machine against an exported bundle.", trust: "Must run where the attacker has no control.",
    allow: ["Read a bundle and a pinned key"], deny: ["Accepting a log without a signed terminal checkpoint (fails closed)"],
    controls: ["--pubkey pins the key", "--expect-terminal-hash detects a full re-signed rewrite"], test: [] },
};
const EDGES = [
  { d: "M220 104 C 268 104, 268 240, 316 246", c: "allow", l: "mailbox only", lx: 240, ly: 168 },
  { d: "M220 282 L 316 276", c: "allow", l: "inspect", lx: 244, ly: 272 },
  { d: "M220 452 C 268 452, 268 316, 316 304", c: "allow", l: "generate", lx: 236, ly: 392 },
  { d: "M130 134 L 130 250", c: "deny", x: [130, 192] },
  { d: "M40 112 C 4 200, 4 380, 40 446", c: "deny", x: [13, 279] },
  { d: "M220 88 L 316 88", c: "deny", x: [268, 88] },
  { d: "M494 252 C 540 252, 548 282, 590 282", c: "allow", l: "seal", lx: 528, ly: 248 },
  { d: "M494 306 C 540 306, 548 394, 590 394", c: "audit", l: "log + sign", lx: 512, ly: 350 },
  { d: "M690 76 L 690 120", c: "allow" },
  { d: "M690 184 L 690 250", c: "allow", l: "release gate", lx: 698, ly: 222 },
  { d: "M690 426 L 690 462", c: "audit" },
  { d: "M590 64 C 540 120, 548 220, 590 270", c: "deny", x: [557, 165] },
];
async function topology() {
  if (!S.status) await refreshStatus();
  const svg = `<svg viewBox="0 0 820 548" role="group" aria-label="Isolation topology. Select a component for details.">
    <rect class="zone" x="20" y="40" width="222" height="472" rx="8"/><text class="zone-label" x="30" y="58">Tenant sandboxes: rootless Podman, one container each</text>
    <rect class="zone" x="300" y="196" width="210" height="146" rx="8"/><text class="zone-label" x="308" y="356">trusted on this host</text>
    <rect class="zone" x="574" y="104" width="232" height="438" rx="8"/><text class="zone-label" x="582" y="534">control plane and evidence</text>
    ${EDGES.map((e) => `<path class="edge ${e.c}" d="${e.d}"/>` + (e.x ? `<path class="edge-x" d="M${e.x[0] - 6} ${e.x[1] - 6} l12 12 M${e.x[0] + 6} ${e.x[1] - 6} l-12 12"/>` : "") + (e.l ? `<text class="edge-label" x="${e.lx}" y="${e.ly}">${esc(e.l)}</text>` : "")).join("")}
    ${Object.entries(NODES).map(([k, n]) => `<g class="node${n.trusted ? " trusted" : ""}${S.topoSel === k ? " sel" : ""}" data-node="${k}" tabindex="0" role="button" aria-pressed="${S.topoSel === k}" aria-label="${esc(n.t)}">
      <rect x="${n.x}" y="${n.y}" width="${n.w}" height="${n.h}" rx="6"/>
      <text x="${n.x + 12}" y="${n.y + (n.h > 60 ? 28 : 22)}">${esc(n.t)}</text>
      <text class="sub" x="${n.x + 12}" y="${n.y + (n.h > 60 ? 46 : 38)}">${esc(n.s)}</text></g>`).join("")}
  </svg>`;
  render(`
  <div class="page-head"><div><h1>Isolation topology</h1>
    <p>Red team, trusted broker, then the defence runner and the model. Solid lines are the only paths that exist; dashed red lines are paths the system refuses. Select a component to see its trust assumptions and what each one may and may not do.</p></div></div>
  <div class="topo">
    <div><div class="diagram">${svg}</div>
      <div class="legend"><span><i class="l-allow"></i>permitted path</span><span><i class="l-deny"></i>refused path</span><span><i class="l-audit"></i>audit and verification</span></div>
      <p class="small muted" style="margin-top:10px">All components run on one Linux host and share its kernel. The diagram shows process, container and network boundaries; it does not imply separate machines or hardware isolation.</p>
    </div>
    <div class="box detail" id="node-detail" aria-live="polite"></div>
  </div>`);
  const show = (k) => {
    S.topoSel = k;
    $$(".node").forEach((g) => { g.classList.toggle("sel", g.dataset.node === k); g.setAttribute("aria-pressed", g.dataset.node === k); });
    const n = NODES[k], st = S.status || {};
    const flags = n.flags && st.hardening_flags ? st.hardening_flags[n.flags] : null;
    $("#node-detail").innerHTML = `<h3>${esc(n.t)}</h3><p class="small">${esc(n.role)}</p>
      <h4>Trust assumption</h4><p class="small ${n.trusted ? "dec warning" : ""}">${esc(n.trust)}</p>
      ${n.allow.length ? `<h4>Permitted</h4><ul class="allow-list">${n.allow.map((x) => `<li>${esc(x)}</li>`).join("")}</ul>` : ""}
      ${n.deny.length ? `<h4>Denied</h4><ul class="deny-list">${n.deny.map((x) => `<li>${esc(x)}</li>`).join("")}</ul>` : ""}
      <h4>Security controls</h4><ul>${n.controls.map((x) => `<li>${esc(x)}</li>`).join("")}</ul>
      ${flags ? `<h4>Flags this host applies (runtime.hardening_flags)</h4><div class="cmd">podman run ${esc(flags.join(" "))}</div>${st.podman && st.podman.available && !st.podman.cpuset_delegated ? `<p class="small dec warning">cpuset pinning is not applied: the cpuset controller is not delegated to rootless users on this host.</p>` : ""}` : ""}
      ${n.test.length ? `<h4>Supporting evidence</h4><div class="row">${n.test.map((s) => `<a class="btn ghost" href="#/lab?s=${s}">Test: ${esc(SCN_TITLE[s] || s)}</a>`).join("")}</div>` : ""}`;
  };
  $$(".node").forEach((g) => {
    g.addEventListener("click", () => show(g.dataset.node));
    g.addEventListener("keydown", (e) => { if (e.key === "Enter" || e.key === " ") { e.preventDefault(); show(g.dataset.node); } });
  });
  show(S.topoSel);
}
const SCN_TITLE = { "prohibited-access": "prohibited access", "cross-role-isolation": "cross-role isolation", "authorized-release": "authorised release", "sandbox-containment": "sandbox containment" };

/* ================================================================ C. attack lab */
async function lab() {
  const [runs, scns] = await Promise.all([loadRuns(), get("/api/lab/scenarios")]);
  S.scenarios = scns;
  const labRuns = runs.filter((r) => /^LAB-\d{3}$/.test(r.id));
  if (!S.labRun || !labRuns.some((r) => r.id === S.labRun)) S.labRun = labRuns[0] ? labRuns[0].id : null;
  const qs = query("s"); if (qs) S.selScenario = qs;
  const live = S.status && S.status.mode === "live";
  render(`
  <div class="page-head"><div><h1>Attack lab</h1>
    <p>Run allowlisted security scenarios against a live evaluation. Each step is a real request to the control plane under a real role token; the verdict checks the security outcome (status, run state, audit entry, leaked values), not just whether HTTP succeeded.</p></div>
    ${labelTag(live ? "live" : "rec")}</div>
  ${live ? "" : `<div class="note">Live containers are unavailable on this machine: ${esc(S.status ? S.status.mode_reason : "status unknown")}. The scenarios below are disabled; a recorded real execution is shown instead. The evidence centre still works fully.</div>`}
  <div class="lab section">
    <div>
      <div class="box" id="run-box"></div>
      <div class="section" style="margin-top:16px" id="scn-list"></div>
      <div class="box section" id="probe-box" style="margin-top:16px"></div>
    </div>
    <div id="result" class="box" aria-live="polite" tabindex="-1"></div>
  </div>`);
  drawRunBox(labRuns);
  drawScenarios();
  drawProbe();
  drawResult();
  if (!live) drawReplay();
  every(1500, pollRun);
}
async function pollRun() {
  if (!S.labRun) return;
  const r = await call("/api/runs/" + S.labRun);
  if (!r.ok) return;
  const prev = (S.runs.find((x) => x.id === S.labRun) || {}).state;
  S.runs = S.runs.map((x) => (x.id === S.labRun ? r.body : x));
  if (prev !== r.body.state || r.body.state === "RUNNING") { drawRunBox(); drawScenarios(); }
  if (prev === "RUNNING" && r.body.state !== "RUNNING") toast(S.labRun + " is " + r.body.state);
}
function drawRunBox(labRuns) {
  labRuns = labRuns || S.runs.filter((r) => /^LAB-\d{3}$/.test(r.id));
  const rec = S.runs.find((r) => r.id === S.labRun);
  const live = S.status && S.status.mode === "live";
  const running = labRuns.some((r) => r.state === "RUNNING");
  $("#run-box").innerHTML = `
    <div class="spread"><h2>Evaluation run</h2>${labRuns.length ? `<label class="field">Run<select id="run-sel">${labRuns.map((r) => `<option value="${esc(r.id)}" ${r.id === S.labRun ? "selected" : ""}>${esc(r.id)}: ${esc(r.state)}</option>`).join("")}</select></label>` : ""}</div>
    ${rec ? lifecycle(rec) + `<p class="small muted">${rec.evaluated ?? 0} of ${rec.attack_count ?? "?"} attacks evaluated · timing bucket ${esc(rec.policy && rec.policy.timing_bucket_ms)} ms · ${rec.complete === false ? `<span class="dec warning">incomplete</span>` : rec.complete ? "complete" : "in progress"}</p>`
      : `<div class="empty">No lab run yet. Starting one creates, freezes and starts a run as the operator; the broker then drives a red sandbox through 10 synthetic attacks and 5 forbidden requests in real containers. It takes about 5 seconds.</div>`}
    <div class="row" style="margin-top:10px">
      <label class="field">Timing padding<select id="bucket"><option value="250">250 ms buckets (default policy)</option><option value="0">none (faster)</option></select></label>
      <button class="btn" id="start-run" type="button" ${!live || running || !S.tokens.operator ? "disabled" : ""}>Start a live run</button>
      <a href="#/events" class="small">Watch its events</a>
    </div>
    ${!S.tokens.operator ? `<p class="small dec warning">No operator identity in this browser: start the console with scripts/start_prototype.sh (demo identities on).</p>` : running ? `<p class="small muted">A run is executing; a new one can start once it seals.</p>` : ""}`;
  const sel = $("#run-sel");
  if (sel) sel.addEventListener("change", () => { S.labRun = sel.value; drawRunBox(); drawScenarios(); });
  $("#start-run").addEventListener("click", startRun);
}
async function startRun(ev) {
  const btn = ev.currentTarget; busy(btn, true);
  try {
    const r = await call("/api/lab/runs", { method: "POST", role: "operator", body: { timing_bucket_ms: Number($("#bucket").value) } });
    if (!r.ok) { toast(classify(r.status).text + ": " + ((r.body && r.body.detail) || ""), true); return; }
    S.labRun = r.body.run_id;
    await loadRuns();
    toast(r.body.run_id + " started: operator created, froze and started it");
    drawRunBox(); drawScenarios(); probeRuns();
  } catch (e) { toast(e.message, true); } finally { busy(btn, false); }
}
function drawScenarios() {
  const rec = S.runs.find((r) => r.id === S.labRun);
  const live = S.status && S.status.mode === "live";
  $("#scn-list").innerHTML = `<h2 style="margin-bottom:10px">Scenarios</h2>` + (S.scenarios || []).map((s) => {
    let why = "";
    if (!live) why = "Needs live containers.";
    else if (!S.tokens.operator) why = "Needs the operator identity.";
    else if (s.needs && !rec) why = "Start a live run first.";
    else if (s.needs && rec.state !== s.needs) why = rec.state === "RUNNING" ? "Waiting for " + rec.id + " to seal." : `Needs a ${s.needs} run; ${rec.id} is ${rec.state}. Start a new run.`;
    return `<article class="scn ${S.selScenario === s.id ? "sel" : ""}" id="scn-${s.id}">
      <div class="spread"><h3>${esc(s.title)}</h3>${s.needs ? `<span class="tiny">needs a ${esc(s.needs)} run</span>` : `<span class="tiny">no run needed</span>`}</div>
      <p class="small">${esc(s.summary)}</p>
      <div class="expect">Expected: ${esc(s.expected)}</div>
      <div class="row"><button class="btn ${S.selScenario === s.id ? "" : "ghost"}" type="button" data-run="${s.id}" ${why ? "disabled" : ""}>Run scenario</button>${why ? `<span class="why">${esc(why)}</span>` : ""}</div>
    </article>`;
  }).join("");
  $$("[data-run]").forEach((b) => b.addEventListener("click", runScenario));
  if (S.selScenario && query("s")) { const el = $("#scn-" + S.selScenario); if (el) el.scrollIntoView({ block: "nearest" }); }
}
async function runScenario(ev) {
  const btn = ev.currentTarget, sid = btn.dataset.run;
  if (sid === "authorized-release" && !armed(btn, "Confirm release of " + S.labRun, "Release is final: " + S.labRun + " becomes RELEASED and cannot return to SEALED. Start another run to repeat the other scenarios.")) return;
  S.selScenario = sid; busy(btn, true);
  $("#result").innerHTML = `<div class="empty">Running “${esc(SCN_TITLE[sid])}”…</div>`;
  try {
    const r = await call(`/api/lab/scenarios/${sid}/run`, { method: "POST", role: "operator", body: { run_id: S.labRun } });
    if (!r.ok) { S.result = { http: r.status, detail: (r.body && r.body.detail) || "", sid }; }
    else S.result = r.body;
  } catch (e) { S.result = { http: 0, detail: e.message, sid }; }
  finally { busy(btn, false); }
  await loadRuns(); drawRunBox(); drawScenarios(); drawResult(); probeRuns();
  if (window.innerWidth < 1100) $("#result").scrollIntoView({ block: "start" });
  $("#result").focus({ preventScroll: true });
}
function drawResult() {
  const R = S.result, el = $("#result");
  if (!R) { el.innerHTML = `<h2>Result</h2><div class="empty" style="margin-top:10px">Run a scenario to see each request, the policy decision, and the audit entry it produced.</div>`; return; }
  if (R.http !== undefined) {
    const c = classify(R.http);
    el.innerHTML = `<h2>Result</h2>${verdictBox(c.kind === "error" ? "ERROR" : "FAIL", "The scenario could not start")}<p class="small">${esc(c.text)}: ${esc(R.detail)}</p>`;
    return;
  }
  const stamp = (s) => {
    const d = s.decision === "denied" ? "denied" : s.decision === "allowed" ? "allowed" : s.decision === "error" ? "error" : "attempted";
    const word = { denied: "DENIED", allowed: "ALLOWED", error: "ERROR", attempted: "ATTEMPTED" }[d];
    return `<div class="stamp ${d}">${word}<small>${esc(typeof s.status === "number" ? "HTTP " + s.status : s.status)}</small></div>`;
  };
  el.innerHTML = `<div class="spread"><h2>${esc(R.title)}</h2>${labelTag("live")}</div>
    <p class="small muted">${R.run_id ? "Run " + esc(R.run_id) + " · " : ""}${when(R.started_at)} · ${(R.finished_at - R.started_at).toFixed(2)} s · launched by the operator; each step uses the role named on it</p>
    ${verdictBox(R.verdict, R.expected)}
    ${R.error ? `<div class="note bad">${esc(R.error)}</div>` : ""}
    <h3>Requests and decisions</h3>
    <ol class="ledger">${R.steps.map((s) => `<li>${stamp(s)}<div>
      <div><span class="who">${esc(s.actor)}</span> <span class="act">${esc(s.action)}</span></div>
      <div class="exp">${esc(s.explain)}</div>
      <div class="small" style="margin-top:4px">Expected ${esc(s.expected_status)}, observed ${esc(s.status)}${s.detail ? ": “" + esc(s.detail) + "”" : ""} <span class="${s.ok ? "ok-mark" : "bad-mark"}">${s.ok ? "as required" : "NOT as required"}</span></div>
      ${s.audit ? `<div class="ev">Audit entry <b>#${s.audit.seq}</b> <span class="mono">${esc(s.audit.type)}</span> by ${esc(s.audit.actor)}${s.audit.data.reason ? ": " + esc(s.audit.data.reason) : ""}<br><span class="hash">hash ${short(s.audit.hash, 24)} · prev ${short(s.audit.prev, 12)}</span><br>${s.audit.signed ? `<span class="dec ok">covered by a signed checkpoint</span>` : `<span class="dec warning">not yet covered by a signed checkpoint</span>`}</div>` : ""}
      ${s.audit_missing ? `<div class="ev dec failed">${esc(s.audit_missing)}</div>` : ""}
    </div></li>`).join("")}</ol>
    ${R.sandbox_denials ? `<h3 style="margin-top:14px">Denied inside the run: the red sandbox's own requests</h3><ul class="plain small">${R.sandbox_denials.map((d) => `<li><span class="mono">#${d.seq}</span> ${esc(d.summary)} ${d.signed ? `<span class="dec ok">signed</span>` : ""}</li>`).join("")}</ul>` : ""}
    <h3 style="margin-top:14px">Checks</h3>
    <ul class="checks">${R.checks.map((c) => `<li><span class="mark ${c.ok ? "ok" : "no"}" aria-label="${c.ok ? "holds" : "does not hold"}">${c.ok ? "✓" : "✗"}</span><div>${esc(c.label)}<span class="found">${esc(c.found)}</span></div></li>`).join("")}</ul>
    ${R.hardening_flags ? `<h3 style="margin-top:14px">Container flags used</h3><div class="cmd">podman run ${esc(R.hardening_flags.join(" "))}</div>` : ""}
    ${R.terminal_hash ? `<div class="note info" style="margin-top:12px">Terminal checkpoint hash, the value a reviewer writes down at release: <span class="hash">${esc(R.terminal_hash)}</span>. The bundle is now in the <a href="#/evidence">evidence centre</a>.</div>` : ""}
    <p class="small" style="margin-top:12px"><a href="#/events">See these entries in the event timeline</a></p>`;
}
const PROBE_OPS = {
  artifacts: { m: "GET", p: (r) => `/api/runs/${r}/artifacts`, t: "Read sealed attack artifacts" },
  evidence: { m: "GET", p: (r) => `/api/runs/${r}/evidence`, t: "Read the evidence report" },
  detail: { m: "GET", p: (r) => `/api/runs/${r}`, t: "Read run detail (secret digests?)" },
  verify: { m: "GET", p: (r) => `/api/runs/${r}/verify`, t: "Verify the audit log" },
  release: { m: "POST", p: (r) => `/api/runs/${r}/release`, t: "Release the run" },
};
function probeRuns() {
  const sel = $("#p-run"); if (!sel) return;
  const cur = sel.value;
  sel.innerHTML = S.runs.length ? S.runs.map((r) => `<option value="${esc(r.id)}" ${r.id === (cur || S.labRun) ? "selected" : ""}>${esc(r.id)} (${esc(r.state)})</option>`).join("") : `<option value="">no runs yet</option>`;
  $("#p-send").disabled = !S.runs.length;
}
function drawProbe() {
  const runs = S.runs;
  $("#probe-box").innerHTML = `<h2>Try a request yourself</h2>
    <p class="small muted">Pick an identity and an operation. The browser sends the request straight to the control plane with that identity's token; nothing is simulated.</p>
    <div class="row" style="margin-top:8px">
      <label class="field">Identity<select id="p-role">${Object.entries(ROLE_NAMES).map(([k, v]) => `<option value="${k}" ${k === "red_participant" ? "selected" : ""}>${esc(v)}</option>`).join("")}</select></label>
      <label class="field">Operation<select id="p-op">${Object.entries(PROBE_OPS).map(([k, v]) => `<option value="${k}">${esc(v.t)}</option>`).join("")}</select></label>
      <label class="field">Run<select id="p-run">${runs.length ? runs.map((r) => `<option value="${esc(r.id)}" ${r.id === S.labRun ? "selected" : ""}>${esc(r.id)} (${esc(r.state)})</option>`).join("") : `<option value="">no runs yet</option>`}</select></label>
      <button class="btn ghost" id="p-send" type="button" ${runs.length ? "" : "disabled"}>Send request</button>
    </div><div id="p-out" aria-live="polite"></div>`;
  $("#p-send").addEventListener("click", async (ev) => {
    const role = $("#p-role").value, op = PROBE_OPS[$("#p-op").value], run = $("#p-run").value;
    if (!run) return;
    const btn = ev.currentTarget;
    if (op.m === "POST" && role === "reviewer" && !armed(btn, "Confirm release of " + run, "This is a real release by the reviewer and it is final.")) return;
    busy(btn, true);
    try {
      const r = await call(op.p(run), { method: op.m, role });
      const c = classify(r.status);
      let body = JSON.stringify(r.body, null, 1) || "";
      if (body.length > 1400) body = body.slice(0, 1400) + "\n… (" + body.length + " characters; truncated in this view)";
      $("#p-out").innerHTML = `<div class="ev" style="margin-top:12px"><div class="row"><span class="stamp ${c.kind === "allowed" ? "allowed" : c.kind === "denied" ? "denied" : c.kind === "error" ? "error" : "attempted"}">${c.kind === "allowed" ? "ALLOWED" : c.kind === "denied" ? "DENIED" : c.kind === "error" ? "ERROR" : "REJECTED"}<small>HTTP ${r.status}</small></span>
        <div><div class="mono small">${esc(op.m + " " + op.p(run))}</div><div class="small">as ${esc(ROLE_NAMES[role])}: ${esc(c.text)}</div></div></div>
        <pre class="json">${esc(body)}</pre></div>`;
      loadRuns().then(() => { drawRunBox(); drawScenarios(); probeRuns(); });
    } catch (e) { $("#p-out").innerHTML = `<div class="note bad" style="margin-top:12px">${esc(e.message)}</div>`; }
    finally { busy(btn, false); }
  });
}
async function drawReplay() {
  try {
    const r = await get("/api/lab/replay");
    $("#result").innerHTML = `<div class="spread"><h2>Recorded execution</h2>${labelTag("rec")}</div>
      <p class="small muted">${esc(r.mode)} · recorded ${esc(r.recorded_utc)} · ${esc(r.checks)} checks · source ${esc(r.source)}. This is a recording of a real run on 23 Oct 2026, not a live result on this machine.</p>
      <div class="transcript">${r.lines.map((l) => `<span class="${esc(l.kind)}">${esc(l.text)}</span>`).join("\n")}</div>`;
  } catch (e) { $("#result").innerHTML = `<div class="note bad">No recording available: ${esc(e.message)}</div>`; }
}

/* ================================================================ D. events */
async function events() {
  await loadRuns();
  render(`
  <div class="page-head"><div><h1>Security events</h1>
    <p>The redacted monitoring stream of every run: who did what, and what the system decided. It carries no payloads, model outputs or defence rules, so any viewer may read it. Each entry's sequence number points into the run's hash-chained audit log.</p></div>
    <label class="row small"><input type="checkbox" id="ev-live" ${S.ev.live ? "checked" : ""}> Update every 2 s</label></div>
  <div class="row" id="ev-filters"></div>
  <p class="small muted" id="ev-meta" style="margin:10px 0"></p>
  <div id="ev-table"></div>`);
  $("#ev-live").addEventListener("change", (e) => { S.ev.live = e.target.checked; });
  await fetchEvents();
  every(2000, () => { if (S.ev.live) fetchEvents(); });
}
async function fetchEvents() {
  try {
    S.evData = await get("/api/lab/timeline?limit=1500" + (S.ev.run !== "all" ? "&run_id=" + encodeURIComponent(S.ev.run) : ""));
    drawEvents();
  } catch (e) { $("#ev-meta").innerHTML = `<span class="dec failed">Could not load events: ${esc(e.message)}</span>`; }
}
function drawEvents() {
  const data = S.evData;
  const uniq = (f) => Array.from(new Set(data.map(f))).sort();
  const opt = (id, label, vals, cur) => `<label class="field">${label}<select id="${id}"><option value="all">all</option>${vals.map((v) => `<option ${v === cur ? "selected" : ""}>${esc(v)}</option>`).join("")}</select></label>`;
  const f = $("#ev-filters");
  if (!f.dataset.ready || f.dataset.n !== String(data.length)) {
    f.innerHTML = opt("f-run", "Run", S.runs.map((r) => r.id), S.ev.run) + opt("f-actor", "Actor or role", uniq((e) => e.actor), S.ev.actor) +
      opt("f-type", "Event type", uniq((e) => e.type), S.ev.type) + opt("f-dec", "Decision", uniq(decisionOf), S.ev.decision);
    f.dataset.ready = "1"; f.dataset.n = String(data.length);
    $("#f-run").addEventListener("change", (e) => { S.ev.run = e.target.value; fetchEvents(); });
    $("#f-actor").addEventListener("change", (e) => { S.ev.actor = e.target.value; drawEvents(); });
    $("#f-type").addEventListener("change", (e) => { S.ev.type = e.target.value; drawEvents(); });
    $("#f-dec").addEventListener("change", (e) => { S.ev.decision = e.target.value; drawEvents(); });
  }
  const rows = data.filter((e) => (S.ev.actor === "all" || e.actor === S.ev.actor) && (S.ev.type === "all" || e.type === S.ev.type) && (S.ev.decision === "all" || decisionOf(e) === S.ev.decision));
  $("#ev-meta").textContent = `${rows.length} of ${data.length} events · updated ${new Date().toLocaleTimeString()}`;
  if (!data.length) { $("#ev-table").innerHTML = `<div class="empty">No events yet. <a href="#/lab">Start a live run</a> and its events appear here as the broker records them.</div>`; return; }
  $("#ev-table").innerHTML = `<div class="table-wrap"><table><thead><tr><th>Time</th><th>Run</th><th>Seq</th><th>Actor</th><th>Event</th><th>Decision</th><th>Summary</th><th>Signed</th></tr></thead><tbody>
    ${rows.slice(0, 600).map((e, i) => `<tr class="click" tabindex="0" data-i="${data.indexOf(e)}"><td class="small">${when(e.ts)}</td><td class="mono">${esc(e.run_id)}</td><td class="mono">${e.seq ?? "—"}</td><td>${esc(e.actor)}</td><td class="mono">${esc(e.type)}</td><td><span class="dec ${esc(decisionOf(e))}">${esc(decisionOf(e))}</span></td><td>${esc(e.summary)}</td><td>${e.post_terminal ? `<span class="faint">after close</span>` : e.signed ? `<span class="dec ok">yes</span>` : `<span class="faint">pending</span>`}</td></tr>`).join("")}
  </tbody></table></div>`;
  $$("#ev-table tr.click").forEach((tr) => {
    const open = () => {
      const e = data[Number(tr.dataset.i)];
      openDrawer(`${e.type} · ${e.run_id}`, `<p class="small">${esc(e.summary)}</p>
        <ul class="plain small status-list"><li><span class="s-k">Decision</span><span class="s-v">${esc(decisionOf(e))}</span></li>
        <li><span class="s-k">Actor</span><span class="s-v">${esc(e.actor)}</span></li>
        <li><span class="s-k">Audit sequence</span><span class="s-v">${e.seq ?? "none"}</span></li>
        <li><span class="s-k">Evidence</span><span class="s-v">${e.post_terminal ? "Recorded after the signed chain closed (post_terminal.jsonl, unsigned, informational)" : e.signed ? "Entry " + e.seq + " is covered by a signed checkpoint in the reviewer vault" : "Not yet covered by a signed checkpoint (the next periodic, seal or terminal checkpoint covers it)"}</span></li></ul>
        <h3 style="margin-top:14px">Monitoring record</h3><pre class="json">${esc(JSON.stringify(e, null, 2))}</pre>
        <p class="tiny">The monitoring stream holds digests and counts only. Payloads, model outputs and defence rules live in the sealed store.</p>`);
    };
    tr.addEventListener("click", open);
    tr.addEventListener("keydown", (ev) => { if (ev.key === "Enter") open(); });
  });
}

/* ================================================================ E. evidence */
async function evidence() {
  S.bundles = await get("/api/lab/bundles");
  if (!S.selBundle || !S.bundles.some((b) => b.id === S.selBundle)) S.selBundle = (S.bundles.find((b) => b.kind === "lab") || S.bundles[0] || {}).id;
  const modes = await get("/api/lab/tamper-modes");
  S.tamperModes = modes.disk_copy;
  render(`
  <div class="page-head"><div><h1>Evidence verification</h1>
    <p>Pick a bundle and run the independent verifier on it: the same program a reviewer runs on their own machine (<code>python -m aegis.verify_cli</code>), started here as a separate process. Then change a disposable copy and watch the verifier reject it while the original still passes.</p></div>${labelTag("live")}</div>
  <div class="split">
    <div class="box flat" style="padding:0"><div class="bundle-list" role="list">${S.bundles.map((b) => `<button type="button" role="listitem" data-b="${esc(b.id)}" class="${b.id === S.selBundle ? "sel" : ""}"><span>${esc(b.label)}<small>${esc(b.path)}</small></span><span class="pill ${b.expected === "pass" ? "acc" : "warn"}">${b.expected === "pass" ? "genuine" : b.kind === "shipped-legacy" ? "legacy" : "tampered"}</span></button>`).join("")}</div>
      <p class="tiny" style="padding:10px 6px">Lab bundles appear here after a reviewer releases a lab run.</p></div>
    <div id="bundle-detail"></div>
  </div>`);
  $$("[data-b]").forEach((b) => b.addEventListener("click", () => { S.selBundle = b.dataset.b; $$("[data-b]").forEach((x) => x.classList.toggle("sel", x === b)); drawBundle(); }));
  drawBundle();
}
const VCHECKS = [
  ["chain_ok", "Hash chain", "Each entry stores the previous entry's hash; editing, deleting or reordering breaks it."],
  ["checkpoint_ok", "Signed checkpoints", "Ed25519 signatures over the chain head, chained to each other through prev_cp."],
  ["terminal_verified", "Terminal checkpoint", "Signed once at RELEASED or FAILED; binds the final entry, so truncation is caught."],
  ["anchor_checked", "Retained anchor", "A separately kept copy of the terminal checkpoint must match and verify."],
  ["tail_uncovered", "Uncovered tail", "Entries after the last signed checkpoint. Must be 0."],
  ["key_source", "Public key", "Pinned: supplied by the reviewer. Bundle: read from the bundle itself, which an attacker could replace."],
];
function verifyView(v) {
  if (!v) return "";
  if (v.exit_code == null) return `<div class="note bad">${esc(v.error || "The verifier did not return a result.")}</div>`;
  const res = v.result || {};
  return `<div class="vchecks">${VCHECKS.map(([k, t, d]) => {
    let val = res[k], ok;
    if (k === "tail_uncovered") ok = val === 0;
    else if (k === "key_source") { ok = String(val || "").startsWith("pinned"); val = ok ? "pinned" : "from the bundle"; }
    else if (k === "anchor_checked") ok = val !== false;
    else ok = val === true;
    const neutral = k === "key_source" && !ok;
    return `<div class="vchk ${neutral ? "" : ok ? "ok" : "no"}"><div class="k"><b>${t}</b><span class="${neutral ? "dec warning" : ok ? "dec ok" : "dec failed"}">${esc(val === null || val === undefined ? "n/a" : String(val))}</span></div><p>${d}</p></div>`;
  }).join("")}</div>
  <p class="small" style="margin-top:10px">${res.entries} entries, ${res.checkpoints_checked} checkpoints, terminal state ${esc(res.terminal_state || "none")}. Exit code <b>${v.exit_code}</b>${v.seconds !== undefined ? " in " + v.seconds + " s" : ""}.</p>
  ${res.terminal_hash ? `<p class="hash">terminal hash ${esc(res.terminal_hash)}</p>` : ""}
  ${(res.findings || []).length ? `<h4 style="margin-top:8px">Findings</h4><ul class="small">${res.findings.map((f) => `<li class="dec failed">${esc(f.issue)}${f.seq ? " (entry " + f.seq + ")" : f.checkpoint_seq ? " (checkpoint at entry " + f.checkpoint_seq + ")" : ""}</li>`).join("")}</ul>` : ""}
  ${(v.stderr || []).map((l) => `<p class="small dec warning">${esc(l)}</p>`).join("")}
  <div class="cmd" style="margin-top:8px">$ ${esc(v.command)}</div>`;
}
function drawBundle() {
  const b = S.bundles.find((x) => x.id === S.selBundle);
  if (!b) { $("#bundle-detail").innerHTML = `<div class="empty">No bundles found in this tree.</div>`; return; }
  const v = S.verify[b.id], t = S.tamper[b.id];
  const canTamper = b.expected === "pass" && (S.tokens.reviewer || S.tokens.operator);
  $("#bundle-detail").innerHTML = `<div class="box">
    <div class="spread"><div><h2>${esc(b.label)}</h2><p class="small muted">${esc(b.note)}</p></div>
      <span class="pill ${b.expected === "pass" ? "acc" : "warn"}">expected: ${b.expected === "pass" ? "accept" : "reject"}</span></div>
    <p class="small">Run ${esc(b.run_id)}, expected state ${esc(b.expect_state)}, ${b.entries ?? "?"} audit entries. Files: <span class="mono">${b.files.map(esc).join(", ")}</span></p>
    <div class="row" style="margin-top:10px"><button class="btn" id="do-verify" type="button">Verify with the independent verifier</button>
      ${b.expected === "pass" ? `<a class="btn ghost" href="/api/lab/bundles/${encodeURIComponent(b.id)}/download" download>Download bundle (.zip)</a>` : ""}</div>
    <div id="v-out" aria-live="polite">${v ? `<h3 style="margin-top:16px">Result ${v.matches_expectation ? `<span class="pill ok">as expected</span>` : `<span class="pill bad">NOT as expected</span>`}</h3>
      <p class="small">${(v.result || {}).ok ? `<span class="dec ok">Accepted.</span> The log is complete and unmodified relative to the signed terminal checkpoint.` : `<span class="dec failed">Rejected.</span> The verifier could not establish an intact, complete log; the findings say why.`}</p>${verifyView(v)}` : ""}</div>
  </div>
  ${b.expected === "pass" ? `<div class="box section">
    <h2>Tamper with a disposable copy</h2>
    <p class="small muted">The server copies this bundle's files to a temporary directory, applies one change, runs the verifier on the copy and on the original, compares the original's SHA-256 digests before and after, and deletes the copy. The original is never written. Runs as the reviewer identity.</p>
    <div class="row" style="margin-top:8px"><label class="field">Change<select id="t-mode">${Object.entries(S.tamperModes).map(([k, d]) => `<option value="${k}">${esc(d)}</option>`).join("")}</select></label>
      <button class="btn ghost" id="do-tamper" type="button" ${canTamper ? "" : "disabled"}>Tamper and verify</button></div>
    <div id="t-out" aria-live="polite">${t ? tamperView(t) : ""}</div>
  </div>` : ""}
  ${b.kind === "lab" ? `<div class="box section"><h2>In-memory tamper suite for ${esc(b.run_id)}</h2>
    <p class="small muted">The control plane's own tamper test (POST /api/runs/{id}/tamper-test): twelve modifications applied to an in-memory copy of the stored log and vault, each verified strictly. The stored log is unchanged.</p>
    <button class="btn ghost" id="do-mem" type="button" ${S.tokens.reviewer ? "" : "disabled"}>Run all twelve</button><div id="m-out">${S.mem[b.id] ? memView(S.mem[b.id]) : ""}</div></div>` : ""}`;
  $("#do-verify").addEventListener("click", async (ev) => {
    busy(ev.currentTarget, true);
    try {
      const r = await call(`/api/lab/bundles/${encodeURIComponent(b.id)}/verify`, { method: "POST" });
      if (!r.ok) toast(classify(r.status).text + ": " + ((r.body && r.body.detail) || ""), true); else { S.verify[b.id] = r.body; drawBundle(); }
    } catch (e) { toast(e.message, true); } finally { busy(ev.currentTarget, false); }
  });
  const tb = $("#do-tamper");
  if (tb) tb.addEventListener("click", async (ev) => {
    busy(ev.currentTarget, true);
    try {
      const r = await call(`/api/lab/bundles/${encodeURIComponent(b.id)}/tamper`, { method: "POST", role: S.tokens.reviewer ? "reviewer" : "operator", body: { mode: $("#t-mode").value } });
      if (!r.ok) toast(classify(r.status).text + ": " + ((r.body && r.body.detail) || ""), true); else { S.tamper[b.id] = r.body; drawBundle(); }
    } catch (e) { toast(e.message, true); } finally { busy(ev.currentTarget, false); }
  });
  const mb = $("#do-mem");
  if (mb) mb.addEventListener("click", async (ev) => {
    busy(ev.currentTarget, true);
    try {
      const modes = Object.keys((await get("/api/lab/tamper-modes")).in_memory_run);
      const out = [];
      for (const m of modes) {
        const r = await call(`/api/runs/${encodeURIComponent(b.run_id)}/tamper-test`, { method: "POST", role: "reviewer", body: { mode: m } });
        out.push(r.ok ? r.body : { mode: m, error: classify(r.status).text });
      }
      S.mem[b.id] = out; drawBundle();
    } catch (e) { toast(e.message, true); } finally { busy(ev.currentTarget, false); }
  });
}
function tamperView(t) {
  return `<div style="margin-top:14px">${verdictBox(t.verdict, t.verdict === "PASS" ? "Tampered copy rejected, original accepted and byte-identical" : "Expectation not met")}
    <p class="small"><b>Change applied to the copy:</b> ${esc(t.change)}</p>
    <div class="grid g2" style="margin-top:10px">
      <div class="vchk ${t.tampered_copy.exit_code === 1 ? "ok" : "no"}"><div class="k"><b>Tampered copy</b><span class="${t.tampered_copy.exit_code === 1 ? "dec ok" : "dec failed"}">exit ${esc(t.tampered_copy.exit_code)}, ${(t.tampered_copy.result || {}).ok ? "accepted" : "rejected"}</span></div>
        <p>${Array.from(new Set(((t.tampered_copy.result || {}).findings || []).map((f) => f.issue))).slice(0, 3).map(esc).join("<br>") || "no findings"}</p></div>
      <div class="vchk ${t.original.exit_code === 0 ? "ok" : "no"}"><div class="k"><b>Original</b><span class="${t.original.exit_code === 0 ? "dec ok" : "dec failed"}">exit ${esc(t.original.exit_code)}, ${(t.original.result || {}).ok ? "accepted" : "rejected"}</span></div>
        <p>Byte-identical before and after: <b class="${t.original_unchanged ? "dec ok" : "dec failed"}">${t.original_unchanged ? "yes" : "NO"}</b>. Copy deleted: ${t.copy_deleted ? "yes" : "no"}.</p></div>
    </div>
    <details style="margin-top:8px"><summary class="small">Original file digests (SHA-256, first 16 hex)</summary><pre class="json">${esc(JSON.stringify(t.original_sha256, null, 1))}</pre></details></div>`;
}
function memView(rows) {
  const det = rows.filter((r) => r.detected).length;
  return `<p class="small" style="margin-top:10px"><b>${det} of ${rows.length}</b> modifications detected.</p><div class="table-wrap"><table><thead><tr><th>Modification</th><th>Detected</th><th>First finding</th></tr></thead><tbody>
    ${rows.map((r) => `<tr><td>${esc(r.description || r.mode)}</td><td>${r.error ? `<span class="dec failed">${esc(r.error)}</span>` : r.detected ? `<span class="dec ok">yes</span>` : `<span class="dec failed">NO</span>`}</td><td class="small">${esc((((r.verification || {}).findings || [])[0] || {}).issue || "")}</td></tr>`).join("")}</tbody></table></div>`;
}

/* ================================================================ F. experiments */
async function experiments() {
  render(`<div class="empty">Recomputing the saved results from their raw files…</div>`);
  const x = S.exp || (S.exp = await get("/api/lab/experiments"));
  const rm = x.real_model || {}, tm = x.timing || {}, sy = x.system_tests || {};
  const sec = (title, tags, body) => `<section class="section box"><div class="spread"><h2>${title}</h2><div class="row">${tags}</div></div>${body}</section>`;
  const recomp = (r) => r ? `<p class="small" style="margin-top:6px">${labelTag("live")} recomputed now: <b class="${r.passed === r.checks ? "dec ok" : "dec failed"}">${r.passed} of ${r.checks} checks agree</b> with the saved results.${r.what ? ` <span class="muted">${esc(r.what)}.</span>` : ""}</p>` : "";
  const bars = (tm.buckets || []).map((b) => {
    const pos = (a) => Math.max(0, Math.min(100, ((a - 0.4) / 0.5) * 100));
    return `<div class="bar-row"><span>${b.bucket_ms === 0 ? "no padding" : b.bucket_ms + " ms"}</span>
      <div class="bar-track" role="img" aria-label="held-out accuracy ${b.heldout_accuracy.join(", ")}"><span class="bar-chance" style="left:${pos(0.5)}%"></span>${b.heldout_accuracy.map((a) => `<span class="bar-dot ${a > 0.6 ? "hi" : ""}" style="left:${pos(a)}%" title="${a}"></span>`).join("")}</div>
      <span class="small">${b.heldout_accuracy.map((a) => a.toFixed(3)).join(" / ")}<br><span class="faint">p ${b.permutation_p.map((p) => p.toFixed(3)).join(" / ")}</span></span></div>`;
  }).join("");
  render(`
  <div class="page-head"><div><h1>Experiment results</h1>
    <p>Saved results from the project's experiments, with the label of how each was produced. Where the raw files are in the repository, the console recomputes the figures from them on request and says whether they agree.</p></div></div>
  <div class="box"><h3>Labels used</h3><ul class="plain small">
    <li>${labelTag("live")} executed now on this machine (this console's runs, refusals, sandbox probes, verifier runs, recomputations)</li>
    <li>${labelTag("rec")} a saved transcript of a real execution, replayed, not re-run</li>
    <li>${labelTag("pre")} saved runs against a real model (Qwen2.5-0.5B, CPU llama.cpp); no model runs in this console</li>
    <li>${labelTag("stub")} measured with the deterministic stub model, which is not an LLM</li></ul></div>
  ${rm.available === false ? `<div class="note bad section">${esc(rm.error)}</div>` : sec("Real-model isolation", labelTag("pre"), `
    <p class="small muted">${esc((rm.model || {}).model_class)} · ${esc((rm.model || {}).inference_server)} · ${esc((rm.model || {}).bind)} · temperature ${esc((rm.model || {}).temperature)} · model sha256 <span class="hash">${short((rm.model || {}).model_sha256, 16)}</span></p>
    ${recomp(rm.recompute)}
    <div class="grid g2" style="margin-top:12px">${(rm.experiments || []).map((e) => `<div class="box flat"><div class="spread"><h3>${esc(e.id)} · ${esc(e.title)}</h3><span class="pill ${e.classification === "pass" ? "ok" : "warn"}">${esc(e.classification)}</span></div>
      <ul class="claims">${e.claims.map((c) => `<li>${esc(c)}</li>`).join("")}</ul><p class="tiny" style="margin-top:6px">${esc(e.timestamp_utc)} · ${esc(e.dir)}</p></div>`).join("")}</div>
    <div class="note" style="margin-top:12px">Zero observed leaks are counts from finite experiments with one 0.5B model. They bound the leak rate for this configuration (see the one-sided 95% upper bound in E1); they do not prove isolation in general. The positive controls show the detectors do fire when context is deliberately shared. GPU memory and accelerator KV-cache isolation were not tested.</div>
    ${(rm.limitations || []).length ? `<h3 style="margin-top:14px">Stated limitations of these runs</h3><ul class="small">${rm.limitations.map((l) => `<li>${esc(l)}</li>`).join("")}</ul>` : ""}`)}
  ${tm.available === false ? `<div class="note bad section">${esc(tm.error)}</div>` : sec("Timing side channel and padding", labelTag("stub") + `<span class="tag pre">PRECOMPUTED</span>`, `
    <p class="small muted">Can red tell a refused request from an answered one by its latency? Held-out accuracy of a threshold classifier, three complete executions, 200 requests each per setting (0.5 is chance, dashed). Source: ${esc(tm.source)}.</p>
    <div class="bars">${bars}<div class="bar-axis"><span></span><span><span>0.40</span><span>0.50</span><span>0.65</span><span>0.90</span></span><span>accuracy · permutation p</span></div></div>
    ${recomp(tm.recompute)}
    <p class="small" style="margin-top:8px">With 250 ms buckets: accuracy ${esc(tm.claims.acc250)} (pooled ${esc(tm.claims.pool250)}); cost ${esc(tm.claims.cost250)} median added latency. Unrestricted CPU neighbour: broker mailbox round trip ${esc(tm.claims.unres_inc)}.</p>
    <div class="note">Padding weakened this classifier to chance level in these runs; n=200 cannot distinguish accuracy up to about 0.57 from chance, and stronger adversaries, cache and memory-bandwidth channels were not measured. The channel is weakened, not proven eliminated.</div>`)}
  ${sy.available === false ? `<div class="note bad section">${esc(sy.error)}</div>` : sec("Recorded system tests", labelTag("stub"), `
    <p class="small muted">Container-free access matrix and audit tamper sweep from the 22 Oct 2026 validation. Source: ${esc(sy.source)}.</p>
    <div class="table-wrap" style="margin-top:8px"><table><thead><tr><th>Claim</th><th>Value</th><th>File</th></tr></thead><tbody>${sy.rows.map((r) => `<tr><td>${esc(r.claim)}</td><td class="mono">${esc(r.value)}</td><td class="mono small">${esc(r.file)}</td></tr>`).join("")}</tbody></table></div>`)}
  ${sec("Known detector and measurement limits", "", `<ul class="plain small">${(x.detector_limits || []).map((d) => `<li class="spread"><span class="dec warning">${esc(d.item)}</span><span class="mono faint">${esc(d.test)}</span></li>`).join("")}</ul>`)}`);
}

/* ================================================================ G. threat model and limits */
async function limits() {
  render(`
  <div class="page-head"><div><h1>Threat model and limits</h1>
    <p>What this prototype was shown to stop, in the environment it was tested in, and what it does not claim. Full detail: <code>aegislab/THREAT_MODEL.md</code>, <code>PHASE2_SECURITY_REPORT.md</code>, <code>PHASE3_LLM_SECURITY_REPORT.md</code>.</p></div></div>
  <div class="grid g2">
    <div class="box lim-col"><h2><span class="pill ok">Tested</span> Protected in the demonstrated environment</h2><ul>
      <li><b>Cross-role authorisation.</b> 212-case role × operation × state matrix: 181/181 expected denials, 0 unauthorised successes; live in the attack lab.</li>
      <li><b>Unauthorised mailbox interaction.</b> Forbidden red requests denied by the broker; planted symlinks, FIFOs and replaced mailbox directories handled (Phase 2 fixes, live in sandbox containment).</li>
      <li><b>Evidence tampering.</b> Modification, deletion, reordering, truncation, re-hashing, forged signatures and key substitution detected by the verifier; live in evidence verification.</li>
      <li><b>Specific model-output leakage.</b> Another run's canary (token, digits, separated digits, 8-digit fragments) and control-plane secrets are withheld from red; tested with Qwen2.5-0.5B and positive controls.</li>
      <li><b>Sandbox reach.</b> No network, read-only root, no capabilities, no-new-privileges, seccomp, foreign paths absent.</li>
    </ul></div>
    <div class="box lim-col"><h2><span class="pill warn">Not proven</span> Not addressed or not fully addressed</h2><ul>
      <li><b>Compromised trusted broker.</b> It sees everything and can sign a false but consistent record.</li>
      <li><b>Compromised signing key.</b> Same Unix user as the broker. Only a terminal hash the reviewer wrote down at release detects a full re-signed rewrite.</li>
      <li><b>Global role tokens.</b> Tokens are per role, not per run, and this local console hands them to the browser in demo mode.</li>
      <li><b>Detector bypasses.</b> Base64, ciphers or spelled-out digits carry a canary past the detector (test P3B02d).</li>
      <li><b>Timing side channels.</b> One classifier is weakened by padding; other channels (cache, memory bandwidth) are not measured.</li>
      <li><b>GPU memory and accelerator KV cache.</b> Not tested; only CPU llama.cpp.</li>
      <li><b>Cross-host behaviour.</b> Single host only; containers share the kernel.</li>
      <li><b>Other models.</b> Results are for one 0.5B model; no universal guarantee.</li>
    </ul></div>
  </div>
  <section class="section box"><h2>Trusted, not defended</h2>
    <p class="small">The broker process and its signing key, the host kernel, Podman and crun, the verifier's execution environment, and the reviewer holding the release identity. AegisLab moves the security boundary from the model's instructions to the infrastructure around it; it does not remove the need to trust that infrastructure.</p>
    <h3 style="margin-top:12px">This console</h3>
    <ul class="small" style="padding-left:18px">
      <li>Binds to 127.0.0.1 and refuses requests whose Host header is not a loopback name (blocks DNS rebinding).</li>
      <li>Scenarios, bundles and tamper modes are fixed lists on the server; the browser cannot send a command, path, container option or network target.</li>
      <li>Tamper demonstrations work on deleted-after-use copies; originals are hashed before and after.</li>
      <li>Demo identities are for a local demonstration only. Never expose this console beyond loopback.</li>
    </ul>
  </section>`);
}

boot();
