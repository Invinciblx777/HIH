/* AegisLab web console. Live mode talks to the local control plane (/api).
   Static mode (no API reachable) renders a snapshot exported from a real local run. */
"use strict";

const S = { live: false, tokens: {}, role: "observer", runs: [], results: null, poll: null, tlFilter: "all" };
const $ = (sel, el = document) => el.querySelector(sel);
const esc = (v) => String(v ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
const short = (d, n = 12) => (d ? esc(String(d).replace(/^sha256:/, "").slice(0, n)) : "—");
const fmtTime = (t) => (t ? new Date(t * 1000).toLocaleString([], { hour: "2-digit", minute: "2-digit", second: "2-digit", day: "2-digit", month: "short" }) : "—");
const STATES = ["CREATED", "FROZEN", "RUNNING", "SEALED", "RELEASED"];
const STATE_HELP = {
  CREATED: "inputs staged", FROZEN: "config digests fixed", RUNNING: "brokered execution",
  SEALED: "results held", RELEASED: "reviewer released",
};
const ROLE_NAMES = { observer: "Observer", operator: "Operator", reviewer: "Reviewer", blue_participant: "Blue participant", red_participant: "Red participant" };

function store(k, v) { try { if (v === undefined) return localStorage.getItem(k); localStorage.setItem(k, v); } catch (e) { return null; } }

function toast(msg, err) {
  const t = $("#toast");
  t.textContent = msg; t.className = "toast show" + (err ? " err" : "");
  clearTimeout(t._h); t._h = setTimeout(() => (t.className = "toast"), 3600);
}

/* ---------------------------------------------------------------- data */
async function api(path, opts = {}) {
  if (!S.live) return snapshot(path, opts);
  const headers = { "Content-Type": "application/json" };
  const tok = S.tokens[S.role];
  if (tok) headers["X-Aegis-Token"] = tok;
  const r = await fetch("/api" + path, { ...opts, headers });
  const body = await r.json().catch(() => ({}));
  if (!r.ok) { const e = new Error(body.detail || r.statusText); e.status = r.status; throw e; }
  return body;
}

async function snapshot(path, opts) {
  if (opts.method === "POST") {
    const m = path.match(/^\/runs\/([^/]+)\/tamper-test$/);
    if (m) return getJSON(`snapshot/tamper_${m[1]}_${JSON.parse(opts.body).mode}.json`);
    const e = new Error("Static snapshot: actions run only against the local control plane"); e.status = 409; throw e;
  }
  let m;
  if (path === "/runs") return getJSON("snapshot/runs.json");
  if ((m = path.match(/^\/runs\/([^/]+)$/))) return getJSON(`snapshot/run_${m[1]}.json`);
  if ((m = path.match(/^\/runs\/([^/]+)\/events$/))) return getJSON(`snapshot/events_${m[1]}.json`);
  if ((m = path.match(/^\/runs\/([^/]+)\/verify$/))) return getJSON(`snapshot/verify_${m[1]}.json`);
  if ((m = path.match(/^\/runs\/([^/]+)\/evidence$/))) {
    try { return await getJSON(`snapshot/evidence_${m[1]}.json`); }
    catch (e) { const x = new Error("evidence report is available after release"); x.status = 403; throw x; }
  }
  if ((m = path.match(/^\/runs\/([^/]+)\/artifacts$/))) { const e = new Error("attack artifacts are sealed until an authorised reviewer releases them"); e.status = 403; throw e; }
  const e = new Error("not in snapshot"); e.status = 404; throw e;
}

async function getJSON(url) {
  const r = await fetch(url, { cache: "no-store" });
  if (!r.ok) { const e = new Error("not found"); e.status = r.status; throw e; }
  return r.json();
}

async function boot() {
  try {
    const h = await fetch("/api/health", { cache: "no-store" });
    S.live = h.ok && (await h.json()).ok === true;
  } catch (e) { S.live = false; }
  if (S.live) {
    try { S.tokens = (await api("/demo/identities")).tokens; } catch (e) { S.tokens = {}; }
    $("#mode-note").textContent = "· Live: connected to local control plane";
  } else {
    $("#mode-note").textContent = "· Static snapshot exported from a local prototype run (actions disabled)";
  }
  try { S.results = await getJSON("snapshot/results.json"); } catch (e) { S.results = null; }
  const saved = store("aegis-role");
  if (saved && ROLE_NAMES[saved]) S.role = saved;
  $("#role-select").value = S.role;
  $("#role-select").addEventListener("change", (ev) => {
    S.role = ev.target.value; store("aegis-role", S.role);
    toast("Viewing as " + ROLE_NAMES[S.role]);
    route();
  });
  window.addEventListener("hashchange", route);
  route();
}

/* ---------------------------------------------------------------- router */
function route() {
  clearInterval(S.poll);
  const h = location.hash.replace(/^#/, "") || "/";
  let m;
  document.querySelectorAll(".nav a").forEach((a) => a.classList.remove("active"));
  const nav = (k) => { const a = document.querySelector(`.nav a[data-nav="${k}"]`); if (a) a.classList.add("active"); };
  if (h === "/" || h === "") { nav("overview"); return overview(); }
  if (h === "/runs") { nav("runs"); return dashboard(); }
  if ((m = h.match(/^\/runs\/([A-Z0-9-]+)\/evidence$/))) { nav(m[1] === "DEMO-001" ? "evidence" : "runs"); return evidencePage(m[1]); }
  if ((m = h.match(/^\/runs\/([A-Z0-9-]+)$/))) { nav(m[1] === "DEMO-001" ? "run" : "runs"); return runPage(m[1]); }
  $("#app").innerHTML = `<div class="empty">Page not found. <a href="#/">Back to overview</a></div>`;
}

function render(html) { $("#app").innerHTML = html; window.scrollTo(0, 0); }

/* ---------------------------------------------------------------- overview */
function measuredStats() {
  const r = S.results;
  if (!r) return "";
  const e2 = r.E2_cross_tenant, e4 = r.E4_canary, e5 = r.E5_audit_tamper, e7 = r.E3_E7_latency_timing;
  return `
  <section class="mt2">
    <div class="spread"><div><h2>What the prototype measured</h2>
      <p class="muted small">From <code>evaluation/run_evaluation.py</code>: ${r.runs_per_condition} runs per condition on one host, stub model worker. Evidence for this configuration, not proof of confidentiality.</p></div>
      <span class="lbl measured">Measured result</span></div>
    <div class="grid g4 mt">
      <div class="stat"><div class="v">${e2.forbidden_broker_requests.denied}/${e2.forbidden_broker_requests.attempts}</div><div class="k">forbidden cross-tenant broker requests denied</div></div>
      <div class="stat"><div class="v">${e4.fresh_container_reset.runs_with_leak} of ${e4.fresh_container_reset.runs}</div><div class="k">fresh-worker runs leaked a canary (control without reset: ${e4.reuse_control_no_reset.runs_with_leak} of ${e4.reuse_control_no_reset.runs})</div></div>
      <div class="stat"><div class="v">${e5.modify.detected}/${e5.modify.trials}</div><div class="k">tampered logs detected per tamper type; truncation without a retained checkpoint: ${e5.truncate_unprotected.detected}/${e5.truncate_unprotected.trials}</div></div>
      <div class="stat"><div class="v">${e7.red_observed_no_padding.threshold_classifier_accuracy.toFixed(2)} → ${e7.red_observed_250ms_buckets.threshold_classifier_accuracy.toFixed(2)}</div><div class="k">timing-classifier accuracy without vs with 250 ms buckets (0.50 = chance)</div></div>
    </div>
  </section>`;
}

function overview() {
  render(`
  <section class="hero">
    <div class="hero-in">
      <div class="kicker">Hack in Hills ’26 · Track 04 · Bayora</div>
      <h1>AegisLab</h1>
      <p>Secure infrastructure for adversarial AI evaluation. Red team, defence and model run at the same time without seeing each other's secrets or carrying state between runs, and every finding comes with evidence a reviewer can verify.</p>
      <div class="row"><a class="btn orange" href="#/runs/DEMO-001">Open run DEMO-001</a><a class="btn ghost" href="#/runs">Evaluation dashboard</a></div>
    </div>
    <span class="photo-credit">Mountain image: Hack in Hills ’26 template</span>
  </section>

  <section class="problem mt2">
    <div>
      <h2>Why safety findings become unreliable</h2>
      <p class="muted">When attackers, defenders and the model share one environment, the environment itself can invalidate the result.</p>
      <ul class="pill-list">
        <li><span class="ic" style="background:var(--red)">1</span><div><b>Attack exposure.</b> Defenders see payloads before the test and tune for them.</div></li>
        <li><span class="ic" style="background:var(--blue)">2</span><div><b>Defence exposure.</b> Attack tooling reads or infers the defence rules.</div></li>
        <li><span class="ic" style="background:var(--slate)">3</span><div><b>Stale model state.</b> Cached context from one run answers the next.</div></li>
        <li><span class="ic" style="background:var(--orange)">4</span><div><b>Interference.</b> Shared CPU, memory and timing distort or leak results.</div></li>
      </ul>
    </div>
    <figure class="figure"><img src="img/01_shared_vs_isolated.svg" alt="Left: red team, blue team and client LLM share one sandbox with leakage paths. Right: AegisLab separates them behind a broker with audit and result gate."><figcaption>Shared sandbox versus AegisLab. <span class="lbl proposed">Diagram</span></figcaption></figure>
  </section>

  <section class="mt2">
    <div class="spread"><div><h2>Architecture and trust boundaries</h2>
    <p class="muted small">Tenant workloads have no network. Their only channel is a private mailbox read by the trusted broker. Trusted: host kernel, container runtime, broker, signing key, authorised reviewer.</p></div>
    <span class="lbl impl">Implemented prototype</span></div>
    <figure class="figure mt"><img src="img/02_architecture_trust_boundaries.svg" alt="Architecture: red sandbox, trusted broker, defence runner, model worker, audit service, result gate, reviewer and dashboard with permitted flows."></figure>
  </section>

  <section class="mt2">
    <h2>How a run works</h2>
    <ol class="steps mt">
      <li><b>Create and freeze</b>Defence config, attack pack and image digests are fixed in a signed manifest.</li>
      <li><b>Boundaries hold</b>Forbidden cross-tenant requests are denied and logged.</li>
      <li><b>Brokered evaluation</b>Each attack must match its prior commitment, then passes defence and model.</li>
      <li><b>Clean model state</b>A fresh worker per run; canary probes check for carry-over.</li>
      <li><b>Verifiable audit</b>Hash chain plus signed checkpoints held by the reviewer detect tampering.</li>
      <li><b>Controlled release</b>Payloads and verdicts open only after seal, verification and reviewer approval.</li>
    </ol>
  </section>
  ${measuredStats()}
  <section class="mt2 card">
    <h3>Labels used across AegisLab materials</h3>
    <div class="legend mt"><span class="lbl impl">Implemented prototype</span> working code in this repository
      <span class="lbl measured">Measured result</span> produced by a run on the local prototype
      <span class="lbl proposed">Proposed design</span> not built yet
      <span class="lbl target">Target</span> goal, not achieved
      <span class="lbl illus">Illustrative</span> concept or sample</div>
  </section>`);
}

/* ---------------------------------------------------------------- dashboard */
async function dashboard() {
  render(`<div class="empty">Loading runs…</div>`);
  try { S.runs = await api("/runs"); } catch (e) { return render(`<div class="notice red">Could not load runs: ${esc(e.message)}</div>`); }
  const tags = [...new Set(S.runs.flatMap((r) => r.tags || []))].sort();
  const count = (s) => S.runs.filter((r) => r.state === s).length;
  render(`
  <div class="spread"><div><h1>Evaluation dashboard</h1>
    <p class="muted">Every row is a real run executed on the local prototype. <code>EVAL-*</code> runs come from the evaluation harness; <code>DEMO-001</code> is the walkthrough run.</p></div>
    <span class="lbl impl">Implemented prototype</span></div>
  <div class="grid g4 mt">
    <div class="stat"><div class="v">${S.runs.length}</div><div class="k">runs</div></div>
    <div class="stat"><div class="v">${count("RELEASED")}</div><div class="k">released with evidence</div></div>
    <div class="stat"><div class="v">${count("SEALED") + count("RUNNING") + count("FROZEN") + count("CREATED")}</div><div class="k">in progress or sealed</div></div>
    <div class="stat"><div class="v">${count("FAILED")}</div><div class="k">failed closed (incl. instrumentation)</div></div>
  </div>
  ${S.role === "operator" && S.live ? `<div class="card mt"><div class="row"><b>New run</b><input id="new-id" placeholder="RUN-ID e.g. DEMO-002" style="padding:9px 12px;border:1px solid var(--line);border-radius:8px"><button class="btn" id="new-btn">Create run</button></div></div>` : ""}
  <div class="filters" role="search">
    <input id="f-q" type="search" placeholder="Search run ID" aria-label="Search run ID">
    <select id="f-state" aria-label="Filter by state"><option value="">All states</option>${STATES.concat("FAILED").map((s) => `<option>${s}</option>`).join("")}</select>
    <select id="f-tag" aria-label="Filter by tag"><option value="">All tags</option>${tags.map((t) => `<option>${esc(t)}</option>`).join("")}</select>
    <select id="f-ev" aria-label="Filter by evidence"><option value="">Any evidence</option><option value="yes">Evidence available</option><option value="no">Evidence sealed / none</option></select>
    <span class="muted small" id="f-count"></span>
  </div>
  <div class="tbl-wrap"><table>
    <thead><tr><th>Run</th><th>State</th><th>Policy state</th><th>Progress</th><th>Model reset</th><th>Evidence</th><th>Tags</th><th>Created</th></tr></thead>
    <tbody id="runs-body"></tbody></table></div>`);
  const draw = () => {
    const q = $("#f-q").value.trim().toUpperCase(), st = $("#f-state").value, tg = $("#f-tag").value, ev = $("#f-ev").value;
    const rows = S.runs.filter((r) => (!q || r.id.includes(q)) && (!st || r.state === st) && (!tg || (r.tags || []).includes(tg)) &&
      (!ev || (ev === "yes") === (r.state === "RELEASED")));
    $("#f-count").textContent = `${rows.length} of ${S.runs.length} runs`;
    $("#runs-body").innerHTML = rows.map((r) => `
      <tr class="click ${r.id === "DEMO-001" ? "hl" : ""}" data-id="${esc(r.id)}">
        <td><a class="runid" href="#/runs/${esc(r.id)}">${esc(r.id)}</a></td>
        <td><span class="state s-${esc(r.state)}">${esc(r.state)}</span></td>
        <td>${r.manifest_digest ? `Frozen <span class="mono muted">${short(r.manifest_digest, 8)}</span>` : "Editable"}</td>
        <td>${r.evaluated ?? 0}/${r.attack_count ?? "—"} attacks</td>
        <td>${r.policy?.reset_strategy === "reuse-control" ? `<span class="outc o-unsafe_output">control: no reset</span>` : "fresh container"}${r.model_cache_at_start != null ? ` · cache ${r.model_cache_at_start}` : ""}</td>
        <td>${r.state === "RELEASED" ? `<a href="#/runs/${esc(r.id)}/evidence">Available</a>` : r.state === "SEALED" ? "Sealed until release" : "—"}</td>
        <td class="small muted">${(r.tags || []).map(esc).join(", ")}</td>
        <td class="small muted">${fmtTime(r.created_at)}</td></tr>`).join("") || `<tr><td colspan="8" class="empty">No runs match these filters.</td></tr>`;
    document.querySelectorAll("#runs-body tr.click").forEach((tr) => tr.addEventListener("click", (e) => { if (e.target.tagName !== "A") location.hash = "#/runs/" + tr.dataset.id; }));
  };
  ["f-q", "f-state", "f-tag", "f-ev"].forEach((id) => $("#" + id).addEventListener("input", draw));
  draw();
  const nb = $("#new-btn");
  if (nb) nb.addEventListener("click", async () => {
    const id = $("#new-id").value.trim().toUpperCase();
    try { await api("/runs", { method: "POST", body: JSON.stringify({ run_id: id, tags: ["manual"] }) }); location.hash = "#/runs/" + id; }
    catch (e) { toast(e.message, true); }
  });
}

/* ---------------------------------------------------------------- run details */
function stepper(state) {
  const idx = STATES.indexOf(state);
  return `<div class="stepper" aria-label="Run lifecycle">${STATES.map((s, i) =>
    `<div class="st ${state === "FAILED" ? "" : i < idx ? "done" : i === idx ? (s === "RELEASED" ? "done" : "cur") : ""}">${s}<small>${STATE_HELP[s]}</small></div>`).join("")}</div>`;
}

function eventClass(e) {
  if (e.decision === "denied") return "denied";
  if (e.type === "audit.checkpoint") return "cp";
  if (e.decision === "ok") return "ok";
  return esc(e.decision || "");
}

function timelineHTML(events, t0) {
  const f = S.tlFilter;
  const keep = (e) => f === "all" || (f === "denied" && e.decision === "denied") || (f === "cp" && e.type === "audit.checkpoint") ||
    (f === "attack" && e.type === "attack.evaluated") || (f === "state" && /^run\.|model\.|defence\./.test(e.type));
  return events.filter(keep).map((e) => `<li class="${eventClass(e)}" data-type="${esc(e.type)}">
    <span class="t">+${(e.ts - t0).toFixed(2)}s</span><span class="dot"></span>
    <div><b>${esc(e.summary || e.type)}</b><div class="small muted">${esc(e.type)} · ${esc(e.actor)} · entry #${esc(e.seq)}${e.digest ? ` · <span class="mono">${esc(e.digest)}</span>` : ""}</div></div></li>`).join("")
    || `<li><span></span><span></span><div class="muted">No events for this filter.</div></li>`;
}

async function runPage(id) {
  let run, events;
  try { [run, events] = await Promise.all([api("/runs/" + id), api(`/runs/${id}/events`)]); }
  catch (e) { return render(`<div class="notice red">Run ${esc(id)}: ${esc(e.message)}</div>`); }
  const m = run.manifest || {};
  const t0 = events.length ? events[0].ts : 0;
  const denied = events.filter((e) => e.decision === "denied");
  const reset = events.find((e) => e.type === "model.reset" || e.type === "model.reset_skipped");
  const opened = events.find((e) => e.type === "model.session_opened");
  const role = S.role;
  const actions = [];
  if (role === "operator" && run.state === "CREATED") actions.push(`<button class="btn" data-act="freeze">Freeze configuration</button>`);
  if (role === "operator" && run.state === "FROZEN") actions.push(`<button class="btn orange" data-act="start">Start evaluation</button>`);
  if (role === "reviewer" && run.state === "SEALED") actions.push(`<button class="btn green" data-act="release">Verify and release to reviewer</button>`);
  if (role === "blue_participant") actions.push(`<button class="btn ghost" data-act="artifacts">Request attack artifacts</button>`);
  if (role === "red_participant") actions.push(`<button class="btn ghost" data-act="release">Attempt to release results</button>`);
  if (run.state === "RELEASED" || role === "reviewer") actions.push(`<a class="btn ghost" href="#/runs/${esc(id)}/evidence">Open evidence report</a>`);

  render(`
  <div class="spread"><div>
    <div class="row"><h1 class="mono" style="font-family:var(--mono);font-size:34px">${esc(id)}</h1><span class="state s-${esc(run.state)}">${esc(run.state)}</span></div>
    <p class="muted">Run details · tags: ${(run.tags || []).map(esc).join(", ") || "—"} · viewing as <b>${ROLE_NAMES[role]}</b></p></div>
    <span class="lbl impl">Implemented prototype</span></div>
  ${stepper(run.state)}
  <div class="row mt" id="actions">${actions.join("") || `<span class="muted small">Switch identity (top right) to Operator, Reviewer or a participant to try the gated actions.</span>`}</div>
  <div id="act-result" class="mt"></div>

  <div class="grid g3 mt">
    <div class="card"><h2>Frozen configuration</h2><p class="sub">${run.frozen_at ? "Fixed at " + fmtTime(run.frozen_at) + "; changes after this point are rejected." : "Not frozen yet: blue team can still edit."}</p>
      <dl class="kv">
        <dt>Manifest</dt><dd class="mono">${short(run.manifest_digest, 16)}</dd>
        <dt>Defence config</dt><dd class="mono">${short(m.defence_config_digest, 16)}</dd>
        <dt>Attack pack</dt><dd class="mono">${short(m.attack_pack_digest, 16)}</dd>
        <dt>Sandbox image</dt><dd class="mono">${short(m.sandbox_image_id, 16)}</dd>
        <dt>Timing bucket</dt><dd>${esc(run.policy?.timing_bucket_ms)} ms</dd>
      </dl></div>
    <div class="card"><h2>Model state</h2><p class="sub">Reset strategy: ${run.policy?.reset_strategy === "reuse-control" ? "<b style='color:var(--red)'>control experiment, worker reused</b>" : "fresh container per run"}</p>
      <dl class="kv">
        <dt>Cache at start</dt><dd><b>${run.model_cache_at_start ?? "—"}</b> entries</dd>
        <dt>Session opened</dt><dd>${opened ? "+" + (opened.ts - t0).toFixed(2) + "s" : "—"}</dd>
        <dt>Reset</dt><dd>${reset ? esc(reset.summary) : "pending"}</dd>
        <dt>Canary probe</dt><dd>${run.state === "RELEASED" ? `<a href="#/runs/${esc(id)}/evidence">see evidence</a>` : "result sealed"}</dd>
      </dl></div>
    <div class="card"><h2>Controlled release</h2><p class="sub">Artifacts open only after SEAL, audit + commitment verification and an authorised reviewer.</p>
      <dl class="kv">
        <dt>Attacks</dt><dd>${run.evaluated ?? 0}/${run.attack_count ?? "—"} evaluated</dd>
        <dt>Commitments</dt><dd class="mono">${short(run.commitments_root, 16)}</dd>
        <dt>Released</dt><dd>${run.released_at ? fmtTime(run.released_at) : "no"}</dd>
        <dt>Outcomes</dt><dd>${run.outcomes ? Object.entries(run.outcomes).map(([k, v]) => `<span class="outc o-${esc(k)}">${esc(k)} ${v}</span>`).join(" ") : "sealed"}</dd>
      </dl></div>
  </div>

  <div class="grid g2 mt" style="grid-template-columns:1fr 1.4fr">
    <div class="card"><h2>Access-control events</h2><p class="sub">${denied.length} requests denied at the boundary.</p>
      <ul class="timeline">${denied.map((e) => `<li class="denied"><span class="t">#${esc(e.seq)}</span><span class="dot"></span><div><b>${esc(e.summary)}</b><div class="small muted">${esc(e.actor)} · +${(e.ts - t0).toFixed(2)}s</div></div></li>`).join("") || `<li><span></span><span></span><div class="muted">None recorded.</div></li>`}</ul></div>
    <div class="card"><div class="spread"><div><h2>Timeline</h2><p class="sub">Redacted monitoring stream: no payloads, outputs or defence rules.</p></div></div>
      <div class="chips" id="tl-chips">${[["all", "All"], ["denied", "Denied"], ["attack", "Attacks"], ["state", "Lifecycle"], ["cp", "Checkpoints"]].map(([k, l]) => `<button class="chipbtn ${S.tlFilter === k ? "on" : ""}" data-f="${k}">${l}</button>`).join("")}</div>
      <ul class="timeline" id="tl">${timelineHTML(events, t0)}</ul></div>
  </div>`);

  $("#tl-chips").addEventListener("click", (e) => {
    const b = e.target.closest("[data-f]"); if (!b) return;
    S.tlFilter = b.dataset.f;
    document.querySelectorAll("#tl-chips .chipbtn").forEach((x) => x.classList.toggle("on", x === b));
    $("#tl").innerHTML = timelineHTML(events, t0);
  });
  $("#actions").addEventListener("click", async (e) => {
    const b = e.target.closest("[data-act]"); if (!b) return;
    const act = b.dataset.act; b.disabled = true;
    const out = $("#act-result");
    try {
      if (act === "freeze") { await api(`/runs/${id}/freeze`, { method: "POST" }); toast("Configuration frozen"); return runPage(id); }
      if (act === "start") { await api(`/runs/${id}/start`, { method: "POST" }); toast("Evaluation started"); return runPage(id); }
      if (act === "release") {
        const r = await api(`/runs/${id}/release`, { method: "POST" });
        toast("Released: audit verified, " + r.commitments.verified + " commitments verified");
        return runPage(id);
      }
      if (act === "artifacts") { const a = await api(`/runs/${id}/artifacts`); out.innerHTML = `<div class="notice blue">${a.length} artifacts released to blue participants.</div>`; }
    } catch (err) {
      out.innerHTML = `<div class="notice red"><b>${err.status === 403 ? "Denied (403)" : err.status === 409 ? "Rejected (409)" : "Error"}:</b> ${esc(err.message)}</div>`;
      toast(err.status === 403 ? "Access denied: " + err.message : err.message, true);
      if (S.live) setTimeout(async () => { try { const ev = await api(`/runs/${id}/events`); $("#tl").innerHTML = timelineHTML(ev, t0); const li = $("#tl li.denied:last-of-type"); } catch (x) {} }, 300);
    } finally { b.disabled = false; }
  });
  if (S.live && ["RUNNING", "FROZEN"].includes(run.state)) S.poll = setInterval(async () => {
    try { const r = await api("/runs/" + id); if (r.state !== run.state || r.evaluated !== run.evaluated) { clearInterval(S.poll); runPage(id); } } catch (x) {}
  }, 800);
}

/* ---------------------------------------------------------------- evidence */
function verdictHTML(v, title) {
  return `<div class="verdict ${v.ok ? "pass" : "fail"}"><span class="big">${v.ok ? "PASS" : "FAIL"}</span>
    <div>${esc(title)}<div class="small" style="font-weight:400">${v.entries} entries · ${v.checkpoints_checked} signed checkpoints · ${v.tail_uncovered} entries uncovered · checked against ${esc(v.checked_against || "reviewer-held checkpoints")}</div>
    ${(v.findings || []).map((f) => `<div class="small" style="font-weight:600">• ${esc(f.issue)}${f.seq ? " (entry #" + esc(f.seq) + ")" : f.checkpoint_seq ? " (checkpoint at #" + esc(f.checkpoint_seq) + ")" : ""}</div>`).join("")}</div></div>`;
}

async function evidencePage(id) {
  render(`<div class="empty">Loading evidence…</div>`);
  let rep;
  try { rep = await api(`/runs/${id}/evidence`); }
  catch (e) {
    let run = null; try { run = await api("/runs/" + id); } catch (x) {}
    return render(`<h1>Evidence report · <span class="mono" style="font-family:var(--mono)">${esc(id)}</span></h1>
      <div class="notice red mt"><b>Sealed (${esc(e.status || "")}).</b> ${esc(e.message)}. Current state: ${esc(run?.state || "unknown")}.
      An authorised reviewer can release a SEALED run after audit and commitment verification pass.</div>
      <p class="mt"><a class="btn ghost" href="#/runs/${esc(id)}">Back to run details</a></p>`);
  }
  const d = rep.digests, v = rep.audit_verification, c = rep.commitments, k = rep.canary, ms = rep.model_state;
  const counts = {}; rep.outcomes.forEach((o) => (counts[o.outcome] = (counts[o.outcome] || 0) + 1));
  const dl = S.live ? `/api/runs/${encodeURIComponent(id)}/evidence.md${S.tokens[S.role] ? "?token=" + encodeURIComponent(S.tokens[S.role]) : ""}` : `snapshot/evidence_${id}.md`;
  const modes = rep._tamper_modes || { modify: "Change the outcome field of one attack.evaluated entry", delete: "Delete one entry from the middle of the log", reorder: "Swap two adjacent entries", truncate: "Drop the final entries of the log (reviewer holds the seal checkpoint)", truncate_unprotected: "Drop the final entries when the reviewer kept only the freeze checkpoint", rehash: "Modify an entry and recompute every later hash (attacker without the signing key)" };
  render(`
  <div class="spread"><div><h1>Evidence report · <span style="font-family:var(--mono)">${esc(id)}</span></h1>
    <p class="muted">${esc(rep.label)}</p></div>
    <div class="row"><span class="lbl measured">Measured result</span><a class="btn ghost" href="${dl}" download>Download report (.md)</a></div></div>

  <div class="grid g2 mt" style="grid-template-columns:1.3fr 1fr">
    <div class="card"><h2>Audit verification</h2><p class="sub">Recomputes the hash chain and checks every Ed25519 checkpoint the reviewer retained independently.</p>
      <div id="verdict">${verdictHTML(v, "Audit log matches reviewer-held checkpoints")}</div>
      <div class="row mt"><button class="btn" id="reverify">Re-verify now</button><span class="muted small" id="reverify-note"></span></div></div>
    <div class="card"><h2>Tamper test</h2><p class="sub">Applies a modification to an in-memory copy of this log, then verifies it. The stored log is never changed.</p>
      <div class="row"><select id="tmode" style="padding:9px 12px;border:1px solid var(--line);border-radius:8px;max-width:100%">${Object.entries(modes).map(([m, dsc]) => `<option value="${m}">${esc(dsc)}</option>`).join("")}</select>
      <button class="btn orange" id="tamper">Run tamper test</button></div>
      <div id="tamper-out" class="mt"></div></div>
  </div>

  <div class="grid g4 mt">
    <div class="stat"><div class="v">${c.verified}/${c.committed}</div><div class="k">attack commitments verified against revealed payloads</div></div>
    <div class="stat"><div class="v">${rep.access_control.length}</div><div class="k">cross-boundary requests denied</div></div>
    <div class="stat"><div class="v">${k.leaks}</div><div class="k">canary leaks · ${k.prior_canaries_checked} earlier canaries probed</div></div>
    <div class="stat"><div class="v">${ms.cache_entries_at_start}</div><div class="k">model cache entries at start · ${esc(ms.reset?.action || ms.reset?.note || "")}</div></div>
  </div>

  <div class="grid g2 mt">
    <div class="card"><h2>Digests</h2><p class="sub">What was evaluated, fixed before execution.</p>
      <dl class="kv">${Object.entries(d).map(([kk, vv]) => `<dt>${esc(kk.replace(/_/g, " "))}</dt><dd class="mono">${esc(vv)}</dd>`).join("")}</dl></div>
    <div class="card"><h2>Outcomes</h2><p class="sub">${Object.entries(counts).map(([kk, vv]) => `<span class="outc o-${esc(kk)}">${esc(kk)} ${vv}</span>`).join(" ")}</p>
      <div class="tbl-wrap"><table><thead><tr><th>Attack</th><th>Category</th><th>Input</th><th>Output</th><th>Outcome</th></tr></thead><tbody>
      ${rep.outcomes.map((o) => `<tr><td class="mono">${esc(o.attack_id)}</td><td>${esc(o.category)}</td><td>${esc(o.verdict_in)}</td><td>${esc(o.verdict_out)}</td><td><span class="outc o-${esc(o.outcome)}">${esc(o.outcome)}</span></td></tr>`).join("")}
      </tbody></table></div><p class="small muted">Outcomes come from a deterministic stub model with synthetic prompts; they test the pipeline, not a real model's safety.</p></div>
  </div>

  <div class="grid g2 mt">
    <div class="card"><h2>Sandbox self-check</h2><p class="sub">Observed from inside the red sandbox during the run.</p>
      <div class="tbl-wrap"><table><thead><tr><th>Check</th><th>Result</th></tr></thead><tbody>
      ${rep.sandbox_selfcheck.map((s) => `<tr><td class="mono">${esc(s.check)}</td><td>${esc(s.result)}${s.errno ? ` <span class="muted small">errno ${esc(s.errno)}</span>` : ""}</td></tr>`).join("")}</tbody></table></div></div>
    <div class="card"><h2>Runtime settings applied</h2><p class="sub">Read back from <code>podman inspect</code>, not from the request.</p>
      <div class="tbl-wrap"><table><thead><tr><th>Workload</th><th>Network</th><th>Read-only</th><th>Memory</th><th>CPUs</th><th>PIDs</th></tr></thead><tbody>
      ${Object.entries(rep.runtime_applied).map(([w, a]) => `<tr><td><b>${esc(w)}</b></td><td>${esc(a.network_mode)}</td><td>${a.readonly_rootfs ? "yes" : "no"}</td><td>${Math.round((a.memory_bytes || 0) / 1048576)} MiB</td><td>${(a.nano_cpus || 0) / 1e9}</td><td>${esc(a.pids_limit)}</td></tr>`).join("")}</tbody></table></div>
      <p class="small muted">Environment: Podman ${esc(rep.environment?.podman)}, ${esc(rep.environment?.oci_runtime_version)}, rootless ${esc(rep.environment?.rootless)}, SELinux ${rep.environment?.selinux ? "enforcing" : "off"}, cpuset delegated ${esc(rep.environment?.cpuset_delegated)}.</p></div>
  </div>

  <div class="card mt"><h2>Limitations of this evidence</h2><ul class="limits">${rep.limitations.map((l) => `<li>${esc(l)}</li>`).join("")}</ul></div>`);

  $("#reverify").addEventListener("click", async () => {
    try { const nv = await api(`/runs/${id}/verify`); $("#verdict").innerHTML = verdictHTML(nv, "Audit log matches reviewer-held checkpoints"); $("#reverify-note").textContent = "Verified at " + new Date().toLocaleTimeString() + (S.live ? "" : " (snapshot result)"); }
    catch (e) { toast(e.message, true); }
  });
  $("#tamper").addEventListener("click", async () => {
    const mode = $("#tmode").value;
    try {
      const r = await api(`/runs/${id}/tamper-test`, { method: "POST", body: JSON.stringify({ mode }) });
      $("#tamper-out").innerHTML = `${r.detected ? `<div class="verdict fail"><span class="big">DETECTED</span><div>${esc(r.description)}${S.live ? "" : " (precomputed from the local run)"}${(r.verification.findings || []).map((f) => `<div class="small">• ${esc(f.issue)}${f.seq ? " (entry #" + esc(f.seq) + ")" : f.checkpoint_seq ? " (checkpoint #" + esc(f.checkpoint_seq) + ")" : ""}</div>`).join("")}</div></div>`
        : `<div class="verdict" style="background:var(--amber-soft);color:var(--amber)"><span class="big">NOT DETECTED</span><div>${esc(r.description)}<div class="small" style="font-weight:400">Known limitation: entries after the last checkpoint a reviewer kept can be truncated without detection. Reviewers must retain the seal checkpoint.</div></div></div>`}
        <p class="small muted">${esc(r.note || "Tampering applied to a copy; stored log unchanged.")}</p>`;
      if (S.live) toast(r.detected ? "Tampering detected" : "Not detected: documented limitation", !r.detected);
    } catch (e) { toast(e.message, true); }
  });
}

boot();
