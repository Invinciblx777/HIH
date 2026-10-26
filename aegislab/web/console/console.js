/* AegisLab console (Phase R1, redesigned in Phase R1-UI). Talks only to this origin: /api/... (the unchanged control plane)
   and /api/lab/... (aegis/console.py). Every number on screen comes from those endpoints or from files they read. The
   descriptive text of the scenario catalogue, the trust graph and the threat model restates the repository's code and
   documents (aegis/api.py, THREAT_MODEL.md) and names its source; it is never presented as a measurement.
   Icons: Lucide (https://lucide.dev, ISC licence), inlined below. */
"use strict";

const S = {
  status: null, session: null, runs: [], journal: [], page: null, q: {}, lastHash: null, booted: false,
  timers: [], cleanups: [], exp: null, expP: null,
  lab: { run: null, view: null, results: {}, scenarios: null, profiles: null, last: null, search: "", f: { sel: {}, match: "all" }, sig: "" },
  audit: { data: [], search: "", f: { sel: {}, match: "all" }, sort: "desc", live: true, limit: 300, sig: "",
    src: "monitor", run: null, log: null, off: 0, lf: { type: "", actor: "", decision: "" } },
  ev: { bundles: [], modes: null, verify: {}, tamper: {}, mem: {}, search: "", f: { sel: {}, match: "all" } },
  conn: { view: "topology", sel: {}, search: "", text: false, off: {}, run: null, events: [], pz: null, obs: [], showObs: true },
};
const $ = (s, el = document) => el.querySelector(s);
const $$ = (s, el = document) => Array.from(el.querySelectorAll(s));
const esc = (v) => String(v ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
const short = (d, n = 16) => (d ? esc(String(d).replace(/^sha256:/, "").slice(0, n)) + "…" : "—");
const when = (t) => (t ? new Date(t * 1000).toLocaleString([], { day: "2-digit", month: "short", hour: "2-digit", minute: "2-digit", second: "2-digit" }) : "—");
const clock = (t) => (t ? new Date(t * 1000).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit", second: "2-digit" }) : "—");
const cap = (s) => String(s).charAt(0) + String(s).slice(1).toLowerCase();
const fmt = (n) => Number(n).toLocaleString("en");
const ROLE_NAMES = { observer: "Observer (no token)", operator: "Operator", reviewer: "Reviewer", blue_participant: "Blue participant", red_participant: "Red participant", forged: "Forged token" };
const STATES = ["CREATED", "FROZEN", "RUNNING", "SEALED", "RELEASED"];
const STATE_HELP = { CREATED: "inputs staged", FROZEN: "config digests fixed", RUNNING: "brokered execution", SEALED: "results held", RELEASED: "reviewer released" };

/* ---------------------------------------------------------------- icons (Lucide, ISC) */
const ICONS = {
  search: '<circle cx="11" cy="11" r="8"/><path d="m21 21-4.34-4.34"/>',
  x: '<path d="M18 6 6 18"/><path d="m6 6 12 12"/>',
  chev: '<path d="m6 9 6 6 6-6"/>',
  sortDesc: '<path d="m3 16 4 4 4-4"/><path d="M7 20V4"/><path d="M11 4h10"/><path d="M11 8h7"/><path d="M11 12h4"/>',
  sortAsc: '<path d="m3 8 4-4 4 4"/><path d="M7 4v16"/><path d="M11 12h4"/><path d="M11 16h7"/><path d="M11 20h10"/>',
  plus: '<path d="M5 12h14"/><path d="M12 5v14"/>',
  minus: '<path d="M5 12h14"/>',
  reset: '<path d="M3 12a9 9 0 1 0 9-9 9.75 9.75 0 0 0-6.74 2.74L3 8"/><path d="M3 3v5h5"/>',
  info: '<circle cx="12" cy="12" r="10"/><path d="M12 16v-4"/><path d="M12 8h.01"/>',
  right: '<path d="M5 12h14"/><path d="m12 5 7 7-7 7"/>',
  left: '<path d="m12 19-7-7 7-7"/><path d="M19 12H5"/>',
  down: '<path d="M12 5v14"/><path d="m19 12-7 7-7-7"/>',
  up: '<path d="m5 12 7-7 7 7"/><path d="M12 19V5"/>',
  check: '<path d="M20 6 9 17l-5-5"/>',
  shield: '<path d="M20 13c0 5-3.5 7.5-7.66 8.95a1 1 0 0 1-.67-.01C7.5 20.5 4 18 4 13V6a1 1 0 0 1 1-1c2 0 4.5-1.2 6.24-2.72a1.17 1.17 0 0 1 1.52 0C14.51 3.81 17 5 19 5a1 1 0 0 1 1 1z"/><path d="m9 12 2 2 4-4"/>',
  ban: '<circle cx="12" cy="12" r="10"/><path d="m4.9 4.9 14.2 14.2"/>',
  circle: '<circle cx="12" cy="12" r="10"/>',
  alert: '<path d="m21.73 18-8-14a2 2 0 0 0-3.48 0l-8 14A2 2 0 0 0 4 21h16a2 2 0 0 0 1.73-3"/><path d="M12 9v4"/><path d="M12 17h.01"/>',
  net: '<rect x="16" y="16" width="6" height="6" rx="1"/><rect x="2" y="16" width="6" height="6" rx="1"/><rect x="9" y="2" width="6" height="6" rx="1"/><path d="M5 16v-3a1 1 0 0 1 1-1h12a1 1 0 0 1 1 1v3"/><path d="M12 12V8"/>',
  download: '<path d="M12 15V3"/><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/><path d="m7 10 5 5 5-5"/>',
  table: '<path d="M12 3v18"/><rect width="18" height="18" x="3" y="3" rx="2"/><path d="M3 9h18"/><path d="M3 15h18"/>',
  play: '<polygon points="6 3 20 12 6 21 6 3"/>',
};
const icon = (n, cls = "") => `<svg class="ico ${cls}" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true" focusable="false">${ICONS[n]}</svg>`;

/* ---------------------------------------------------------------- API */
class NetError extends Error {}
/* The browser holds no role token. Writes carry the operator session's CSRF token; the session cookie itself is HttpOnly
   and is sent by the browser to this origin only (SameSite=Strict). The server performs each role's request. */
async function call(path, { method = "GET", body, idem } = {}) {
  const headers = {};
  if (body !== undefined) headers["Content-Type"] = "application/json";
  if (idem) headers["X-Aegis-Idempotency-Key"] = idem;
  if (method !== "GET" && S.session && S.session.csrf) headers["X-Aegis-CSRF"] = S.session.csrf;
  let r;
  try { r = await fetch(path, { method, headers, body: body === undefined ? undefined : JSON.stringify(body), cache: "no-store", credentials: "same-origin" }); }
  catch (e) { throw new NetError("The console server is not reachable. Is scripts/start_prototype.sh still running?"); }
  let b = null;
  const ct = r.headers.get("content-type") || "";
  if (ct.includes("json")) b = await r.json().catch(() => null); else b = { text: await r.text().catch(() => "") };
  if (r.status === 403 && b && /operator session|CSRF/.test(b.detail || "")) { S.session = { authenticated: false }; paintSession(); }
  return { status: r.status, ok: r.ok, body: b };
}
const canAct = () => !!(S.session && S.session.authenticated);
const NO_SESSION = "Read-only: open the launch link printed by scripts/start_prototype.sh to act in the lab.";
async function loadSession() { try { S.session = await get("/api/lab/session"); } catch (e) { S.session = { authenticated: false }; } paintSession(); return S.session; }
function paintSession() {
  const el = $("#sess"); if (!el) return;
  const on = canAct();
  el.className = "sys " + (on ? "live" : "ro");
  el.title = on ? (S.session.limitation || "") : NO_SESSION;
  $(".txt", el).innerHTML = on ? `Operator session<span class="long"> · roles act server-side</span>` : `Read-only<span class="long"> · open the launch link</span>`;
  const end = $("#sess-end"); if (end) end.hidden = !on;
}
async function endSession(ev) {
  const btn = ev.currentTarget; busy(btn, true);
  try {
    const r = await call("/api/lab/session/end", { method: "POST" });
    await loadSession();
    toast(r.ok ? "Operator session ended. The console is read-only; a new launch link is needed to act again." : "The session had already ended.");
    await route();
  } catch (e) { toast(e.message, true); } finally { busy(btn, false); }
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
async function loadRuns() { try { S.runs = await get("/api/runs"); } catch (e) { S.runs = []; } return S.runs; }
async function loadJournal() { try { S.journal = await get("/api/lab/journal"); } catch (e) { S.journal = []; } return S.journal; }
function loadExp() {
  if (S.exp) return Promise.resolve(S.exp);
  if (!S.expP) S.expP = get("/api/lab/experiments").then((x) => (S.exp = x)).catch((e) => { S.expP = null; throw e; });
  return S.expP;
}
const isLive = () => !!(S.status && S.status.mode === "live");
const decisionOf = (e) => e.decision || (e.type === "policy.denied" ? "denied" : "info");
const lastJ = (pred) => S.journal.find(typeof pred === "function" ? pred : (j) => j.kind === pred);

/* ---------------------------------------------------------------- small UI */
function toast(msg, err) {
  const t = $("#toast"); t.textContent = msg; t.className = "toast show" + (err ? " err" : "");
  clearTimeout(t._h); t._h = setTimeout(() => (t.className = "toast"), 4200);
}
function busy(btn, on) { if (!btn) return; btn.disabled = on; btn.classList.toggle("busy", on); btn.setAttribute("aria-busy", on ? "true" : "false"); }
function every(ms, fn) { S.timers.push(setInterval(fn, ms)); }
function teardown() { S.timers.forEach(clearInterval); S.timers = []; S.cleanups.forEach((f) => f()); S.cleanups = []; }
function render(html) { $("#main").innerHTML = `<div class="page">${html}</div>`; afterRender($("#main")); }
function afterRender(root) { enter(root); drawRings(root); wrapTables(root); }
const loading = (t) => `<div class="loading" role="status"><i aria-hidden="true"><b></b><b></b><b></b></i>${esc(t)}</div>`;
const errorBox = (e) => `<div class="errorbox" role="alert"><b>Could not load.</b> ${esc(e && e.message ? e.message : e)}</div>`;
function confirmAction(title, html, ok) {
  const d = $("#confirm");
  $("#confirm-title").textContent = title; $("#confirm-body").innerHTML = html; $("#confirm-ok").textContent = ok;
  d.returnValue = "";
  /* resolve on the form's submit (which carries the button pressed), on Esc, or on close: some Chromium builds never
     dispatch "close" for a method=dialog form, which would leave a confirmed release waiting for ever */
  return new Promise((res) => {
    const f = $("form", d);
    let done = false;
    const finish = (v) => {
      if (done) return;
      done = true;
      f.removeEventListener("submit", onSubmit); d.removeEventListener("cancel", onCancel); d.removeEventListener("close", onClose);
      if (d.open) d.close(v ? "ok" : "cancel");
      res(v);
    };
    const onSubmit = (e) => { e.preventDefault(); finish(!!e.submitter && e.submitter.value === "ok"); };
    const onCancel = () => finish(false);
    const onClose = () => finish(d.returnValue === "ok");
    f.addEventListener("submit", onSubmit); d.addEventListener("cancel", onCancel); d.addEventListener("close", onClose);
    d.showModal();
  });
}
/* cards rise in with a short stagger, as in the reference; reduced motion skips it (CSS) */
function enter(root) {
  const cards = $$(".card.pre", root);
  cards.forEach((c, i) => c.style.setProperty("--d", Math.min(i, 12) * 35 + "ms"));
  requestAnimationFrame(() => requestAnimationFrame(() => cards.forEach((c) => { c.classList.remove("pre"); c.classList.add("in"); })));
}
function wrapTables(root) {
  $$(".table-wrap", root).forEach((w) => w.classList.toggle("scrolls", w.scrollWidth > w.clientWidth + 2));
}
function labelTag(kind) {
  const m = { live: "LIVE SYSTEM TEST", sandbox: "LIVE SANDBOX · STUB MODEL", rec: "REPLAY · RECORDED", pre: "PRECOMPUTED REAL-MODEL", stub: "STUB MODEL", na: "UNAVAILABLE" };
  return `<span class="label ${kind}">${m[kind]}</span>`;
}

/* ---------------------------------------------------------------- hand-drawn ring (own generator) */
function rng(seed) { let a = seed >>> 0; return () => { a = (a + 0x6D2B79F5) >>> 0; let t = a; t = Math.imul(t ^ (t >>> 15), t | 1); t ^= t + Math.imul(t ^ (t >>> 7), t | 61); return ((t ^ (t >>> 14)) >>> 0) / 4294967296; }; }
function loopPath(W, H, seed, k) {
  const R = rng(seed), cx = W / 2, cy = H / 2, rx = W / 2 - 3, ry = H / 2 - 3;
  const a0 = -2.3 + R() * 0.5, sweep = Math.PI * 2 * (1.07 + R() * 0.05), n = 26, tilt = (R() - 0.5) * 0.08;
  const pts = [];
  for (let i = 0; i <= n; i++) {
    const f = i / n, t = a0 + sweep * f, w = 1 + (R() - 0.5) * 0.04;
    const x = cx + rx * k * w * (1 - 0.04 * f) * Math.cos(t);
    pts.push([x, cy + ry * k * w * (1 + 0.07 * f) * Math.sin(t) + tilt * (x - cx)]);
  }
  let d = `M${pts[0][0].toFixed(1)} ${pts[0][1].toFixed(1)}`;
  for (let i = 0; i < pts.length - 1; i++) {
    const p0 = pts[i - 1] || pts[i], p1 = pts[i], p2 = pts[i + 1], p3 = pts[i + 2] || p2;
    d += ` C${(p1[0] + (p2[0] - p0[0]) / 6).toFixed(1)} ${(p1[1] + (p2[1] - p0[1]) / 6).toFixed(1)} ${(p2[0] - (p3[0] - p1[0]) / 6).toFixed(1)} ${(p2[1] - (p3[1] - p1[1]) / 6).toFixed(1)} ${p2[0].toFixed(1)} ${p2[1].toFixed(1)}`;
  }
  return d;
}
function ring(el, still) {
  $$(":scope > svg.ring", el).forEach((s) => s.remove());
  const w = el.offsetWidth, h = el.offsetHeight;
  if (!w) return;
  const px = Math.max(10, Math.min(17, w * 0.14)), py = Math.max(6, h * 0.3), W = w + px * 2, H = h + py * 2;
  const seed = Array.from(el.textContent).reduce((a, c) => a * 31 + c.charCodeAt(0), 7);
  el.insertAdjacentHTML("beforeend", `<svg class="ring${still ? " still" : ""}" aria-hidden="true" focusable="false" width="${W}" height="${H}" viewBox="0 0 ${W} ${H}" style="left:${-px}px;top:${-py}px"><path pathLength="1" d="${loopPath(W, H, seed, 1)}"/><path pathLength="1" d="${loopPath(W, H, seed + 11, 0.94)}"/></svg>`);
}
function drawRings(root, still) { $$("[data-ring]", root || document).forEach((el) => ring(el, still)); }

/* ---------------------------------------------------------------- search band and facet filters */
const B = { cfg: null, t: 0 };
function band(cfg) {
  B.cfg = cfg;
  $("#band").hidden = !cfg;
  const fp = $("#fpanel"); fp.hidden = true; fp.innerHTML = "";
  $("#f-toggle").setAttribute("aria-expanded", "false");
  if (!cfg) return;
  const q = $("#q"); q.placeholder = cfg.placeholder; q.value = cfg.value || "";
  $("#q-label").textContent = "Search: " + cfg.placeholder;
  $("#f-toggle").hidden = !cfg.filter;
  $("#s-toggle").hidden = !cfg.sort;
  paintBand();
}
function paintBand() {
  const c = B.cfg; if (!c) return;
  if (c.sort) { const s = $("#s-toggle"); s.innerHTML = `<span class="lbltxt">${esc(c.sort.label())}</span>${icon(c.sort.icon(), "md")}`; s.setAttribute("aria-label", "Sort: " + c.sort.label() + " (change)"); }
  if (c.filter) {
    const n = Object.values(c.filter.state.sel).reduce((a, s) => a + s.size, 0);
    const cnt = $("#f-count"); cnt.hidden = !n; cnt.textContent = n;
  }
}
function facetValues(rows, defs, state) {
  return defs.map((d) => {
    const m = new Map();
    rows.forEach((r) => [].concat(d.get(r)).forEach((v) => { if (v == null || v === "") return; m.set(String(v), (m.get(String(v)) || 0) + 1); }));
    (state.sel[d.key] || new Set()).forEach((v) => { if (!m.has(v)) m.set(v, 0); });
    const vals = Array.from(m, ([v, n]) => ({ v, n, color: d.color ? d.color(v) : null }));
    if (d.order) vals.sort((a, b) => d.order.indexOf(a.v) - d.order.indexOf(b.v)); else vals.sort((a, b) => b.n - a.n || a.v.localeCompare(b.v));
    return { key: d.key, title: d.title, values: vals };
  });
}
function facetFilter(rows, defs, state) {
  const act = defs.filter((d) => state.sel[d.key] && state.sel[d.key].size);
  if (!act.length) return rows;
  return rows.filter((r) => {
    const hits = act.map((d) => [].concat(d.get(r)).some((v) => state.sel[d.key].has(String(v))));
    return state.match === "any" ? hits.some(Boolean) : hits.every(Boolean);
  });
}
function textMatch(q, ...fields) {
  const words = String(q || "").toLowerCase().split(/\s+/).filter(Boolean);
  if (!words.length) return true;
  const hay = fields.flat().join(" ").toLowerCase();
  return words.every((w) => hay.includes(w));
}
function drawFacets() {
  const f = B.cfg && B.cfg.filter; if (!f) return;
  const st = f.state, groups = facetValues(f.rows(), f.defs, st);
  const n = Object.values(st.sel).reduce((a, s) => a + s.size, 0);
  $("#fpanel").innerHTML = `<div class="frow" role="radiogroup" aria-label="Match">
      <span>Match</span><label><input type="radio" name="fm" value="all" ${st.match !== "any" ? "checked" : ""}> All</label><label><input type="radio" name="fm" value="any" ${st.match === "any" ? "checked" : ""}> Any</label>
      <span class="spacer"></span><button class="btn" type="button" data-clear ${n ? "" : "disabled"}>Clear filters ${icon("x")}</button></div>
    <div class="facets">${groups.map((g) => `<div class="facet" role="group" aria-label="${esc(g.title)}"><h3>${esc(g.title)}<span>${g.values.length}</span></h3><div class="chips">${g.values.map((v) => {
      const on = !!(st.sel[g.key] && st.sel[g.key].has(v.v));
      return `<button type="button" class="chip${on ? " on" : ""}${v.n ? "" : " zero"}" aria-pressed="${on}" data-f="${esc(g.key)}" data-v="${esc(v.v)}" ${!v.n && !on ? "disabled" : ""} ${v.color ? `style="--fc:${v.color}"` : ""}>${v.color ? `<span class="sw" aria-hidden="true"></span>` : ""}${esc(v.v)}<span class="n">${v.n}</span></button>`;
    }).join("")}</div></div>`).join("")}</div>`;
}
function bindBand() {
  $("#q").addEventListener("input", (e) => { clearTimeout(B.t); B.t = setTimeout(() => B.cfg && B.cfg.onSearch && B.cfg.onSearch(e.target.value.trim()), 90); });
  $("#q").addEventListener("keydown", (e) => { if (e.key === "Escape" && e.target.value) { e.target.value = ""; B.cfg && B.cfg.onSearch && B.cfg.onSearch(""); e.stopPropagation(); } });
  $("#f-toggle").innerHTML = `<span class="lbltxt">Filters</span><span class="count" id="f-count" hidden></span>${icon("chev", "md chev")}`;
  $("#f-toggle").addEventListener("click", () => {
    const fp = $("#fpanel"), open = fp.hidden;
    fp.hidden = !open; $("#f-toggle").setAttribute("aria-expanded", String(open));
    if (open) drawFacets();
  });
  $("#s-toggle").addEventListener("click", () => { if (B.cfg && B.cfg.sort) { B.cfg.sort.onClick(); paintBand(); } });
  $("#fpanel").addEventListener("click", (e) => {
    const f = B.cfg && B.cfg.filter; if (!f) return;
    const chip = e.target.closest("[data-f]");
    if (chip) {
      const set = f.state.sel[chip.dataset.f] || (f.state.sel[chip.dataset.f] = new Set());
      set.has(chip.dataset.v) ? set.delete(chip.dataset.v) : set.add(chip.dataset.v);
    } else if (e.target.closest("[data-clear]")) { f.state.sel = {}; } else return;
    drawFacets(); paintBand(); f.onChange();
    const again = chip && $(`#fpanel [data-f="${CSS.escape(chip.dataset.f)}"][data-v="${CSS.escape(chip.dataset.v)}"]`);
    if (again) again.focus(); else if (!chip) $("#f-toggle").focus();
  });
  $("#fpanel").addEventListener("change", (e) => { const f = B.cfg && B.cfg.filter; if (f && e.target.name === "fm") { f.state.match = e.target.value; f.onChange(); drawFacets(); } });
}
function filterCfg(defs, state, rows, onChange) { return { defs, state, rows, onChange: () => { onChange(); paintBand(); } }; }

/* ---------------------------------------------------------------- detail sheet */
const SH = { open: false, key: null, opener: null };
function showSheet(c) {
  $("#sheet-title").textContent = c.title;
  $("#sheet-meta").innerHTML = c.meta || ""; $("#sheet-meta").hidden = !c.meta;
  const body = $("#sheet-body"), keep = SH.open && SH.key === S.q.open ? body.scrollTop : 0;
  body.innerHTML = c.body; body.scrollTop = keep;
  if (c.after) c.after(body);
  afterRender(body);
  SH.key = S.q.open;
  if (!SH.open) {
    SH.opener = document.activeElement && document.activeElement !== document.body ? document.activeElement : null;
    SH.open = true;
    $("#sheet").classList.add("open"); $("#sheet").setAttribute("aria-hidden", "false");
    $("#scrim").hidden = false; $("#app").inert = true;
    setTimeout(() => $("#sheet-close").focus(), 40);
  }
}
function hideSheet() {
  if (!SH.open) return;
  const key = SH.key;
  SH.open = false; SH.key = null;
  $("#sheet").classList.remove("open"); $("#sheet").setAttribute("aria-hidden", "true");
  $("#scrim").hidden = true; $("#app").inert = false;
  let back = SH.opener && document.contains(SH.opener) ? SH.opener : key ? $(`[data-key="${CSS.escape(key)}"]`) : null;
  if (back) back.focus({ preventScroll: true });
}
function openKey(key) { const { page, q } = parseHash(); history.pushState({ sheet: 1 }, "", href(page, { ...q, open: key })); route(); }
function closeKey() {
  const { page, q } = parseHash();
  if (history.state && history.state.sheet) history.back();
  else { history.replaceState(null, "", href(page, { ...q, open: null })); route(); }
}
async function refreshSheet() {
  const P = PAGES[S.page];
  if (!SH.open || !P.open || !S.q.open) return;
  try { const c = await P.open(S.q.open); if (c && SH.open) showSheet(c); } catch (e) { /* keep the current view */ }
}

/* ---------------------------------------------------------------- router */
const PAGES = {};
const ALIAS = { topology: "connections", events: "audit", limits: "threat-model" };
function parseHash() {
  const raw = location.hash.replace(/^#\/?/, "");
  const [p, qs] = raw.split("?");
  const page = ALIAS[p] || (PAGES[p] ? p : "overview");
  return { page, raw: p, q: Object.fromEntries(new URLSearchParams(qs || "")) };
}
function href(page, q = {}) {
  const s = new URLSearchParams(Object.entries(q).filter(([, v]) => v != null && v !== "")).toString();
  return "#/" + page + (s ? "?" + s : "");
}
function setQuery(patch) {
  const { page, q } = parseHash();
  history.replaceState(history.state, "", href(page, { ...q, ...patch }));
  S.lastHash = location.hash; S.q = parseHash().q;
}
let routing = Promise.resolve();
function route() { routing = routing.then(doRoute).catch((e) => console.error(e)); return routing; }
async function doRoute() {
  if (location.hash === S.lastHash) return;
  const { page, raw, q } = parseHash();
  let canon = !!ALIAS[raw];
  if (page === "lab" && q.s) { q.open = q.open || q.s; delete q.s; canon = true; }
  if (canon) history.replaceState(history.state, "", href(page, q));
  S.lastHash = location.hash; S.q = q;
  const P = PAGES[page];
  if (S.page !== page) {
    hideSheet(); teardown(); band(null);
    S.page = page; setNav(page);
    window.scrollTo(0, 0);
    try { await P.render(q); } catch (e) { render(errorBox(e)); }
    if (S.booted) $("#main").focus({ preventScroll: true });
    document.title = (page === "overview" ? "" : NAV_TITLES[page] + " · ") + "AegisLab Console";
  } else if (P.sync) {
    await P.sync(q);
  }
  if (q.open && P.open) {
    try { const c = await P.open(q.open); if (c) { showSheet(c); return; } }
    catch (e) { showSheet({ title: "Not available", body: errorBox(e) }); return; }
  }
  hideSheet();
}
const NAV_TITLES = { overview: "Overview", lab: "Lab", connections: "Connections", audit: "Audit", evidence: "Evidence", experiments: "Experiments", "threat-model": "Threat Model" };
function setNav(page) {
  $$("#subnav a").forEach((a) => {
    const on = a.dataset.nav === page, span = a.firstElementChild;
    if (on) { a.setAttribute("aria-current", "page"); span.classList.add("ringed"); span.dataset.ring = "1"; }
    else { a.removeAttribute("aria-current"); span.classList.remove("ringed"); delete span.dataset.ring; $$("svg.ring", span).forEach((s) => s.remove()); }
  });
  const act = $("#subnav a[aria-current] span");
  if (act) { ring(act); const nav = $("#subnav"); if (nav.scrollWidth > nav.clientWidth) nav.scrollTo({ left: act.parentElement.offsetLeft - nav.clientWidth / 2 + act.offsetWidth / 2, behavior: "smooth" }); }
}

/* ---------------------------------------------------------------- status */
async function refreshStatus() {
  const el = $("#sys"), txt = $(".txt", el);
  let cls, html, title;
  try {
    S.status = await get("/api/lab/status");
    const st = S.status, pm = st.podman || {}, live = st.mode === "live";
    cls = live ? "live" : "degraded";
    html = live ? `Live<span class="long"> · Podman ${esc(pm.podman)} rootless · ${esc((st.model || {}).label || "")}</span>` : `Degraded<span class="long"> · replay only</span>`;
    title = live ? "Control plane connected; scenarios start real rootless containers. The model in live runs is the deterministic stub." : "Live containers unavailable: " + (st.mode_reason || "");
  } catch (e) {
    S.status = null; cls = "offline"; html = `Offline<span class="long"> · control plane unreachable</span>`; title = e.message;
  }
  el.className = "sys " + cls; el.title = title;
  if (txt.innerHTML !== html) txt.innerHTML = html;
}

/* ---------------------------------------------------------------- shared fragments */
function lifecycle(rec) {
  if (!rec) return `<p class="muted">No run yet.</p>`;
  const failed = rec.state === "FAILED", idx = STATES.indexOf(rec.state);
  const ts = { CREATED: rec.created_at, FROZEN: rec.frozen_at, RUNNING: rec.started_at, SEALED: rec.sealed_at, RELEASED: rec.released_at };
  return `<ol class="life" aria-label="Run lifecycle, current state ${esc(rec.state)}">${STATES.map((s, i) => {
    const done = failed ? !!ts[s] : i <= idx, cur = !failed && i === idx;
    return `<li class="${done ? "" : "todo"}" ${cur ? 'aria-current="step"' : ""}><b${cur ? ' class="ringed" data-ring="1"' : ""}>${cap(s)}</b><span>${ts[s] ? clock(ts[s]) : STATE_HELP[s]}</span></li>`;
  }).join("")}${failed ? `<li class="fail" aria-current="step"><b class="ringed" data-ring="1">Failed</b><span>failed closed, not releasable</span></li>` : ""}</ol>`;
}
function verdictBox(v, title) {
  const map = { PASS: ["pass", "PASS", "The expected security outcome was observed."], FAIL: ["fail", "FAIL", "A security expectation did not hold. See the marked rows."],
    ERROR: ["error", "ERROR", "The backend failed. This is not a security result."] };
  const [cls, word, text] = map[v] || ["error", v, ""];
  return `<div class="verdict ${cls}" role="status"><b>${esc(word)}</b><div><div>${esc(title)}</div><div class="tiny">${text}</div></div></div>`;
}
const DEC_COLOR = { denied: "var(--s-deny)", ok: "var(--s-allow)", allowed: "var(--s-allow)", failed: "var(--s-fail)", alert: "var(--s-fail)", info: "var(--ink)" };
const decTag = (d) => `<span class="st ${esc(d)}">${esc(d)}</span>`;
function signedOf(e) { return e.post_terminal ? "after close" : e.signed ? "signed" : "pending"; }
function evTable(rows, opts = {}) {
  return `<div class="table-wrap"><table><thead><tr><th>Time</th><th>Run</th>${opts.seq ? "<th>Seq</th>" : ""}<th>Actor</th><th>Event</th><th>Decision</th><th>Summary</th>${opts.signed ? "<th>Signature</th>" : ""}</tr></thead><tbody>
    ${rows.map((e) => `<tr ${opts.click ? `class="click${S.q.open === evKey(e) ? " sel" : ""}" tabindex="0" data-key="${esc(evKey(e))}"` : ""}><td class="nw">${clock(e.ts)}</td><td class="nw">${esc(e.run_id)}</td>${opts.seq ? `<td>${e.seq ?? "—"}</td>` : ""}<td class="nw">${esc(e.actor)}</td><td class="nw">${esc(e.type)}</td><td>${decTag(decisionOf(e))}</td><td>${esc(e.summary)}</td>${opts.signed ? `<td class="nw">${e.post_terminal ? `<span class="muted">after close</span>` : e.signed ? `<span class="st ok">signed</span>` : `<span class="muted">pending</span>`}</td>` : ""}</tr>`).join("")}
  </tbody></table></div>`;
}
const evKey = (e) => `${e.run_id}~${e.seq ?? "x"}~${e.type}~${Math.round(e.ts * 1000)}`;
function secHead(title, aside) { return `<div class="sec-head"><h2>${title}</h2>${aside ? `<span class="aside">${aside}</span>` : ""}</div>`; }
function card({ key, hrefTo, cls, title, badge, meta, mark, body, tags, sel, auto }) {
  const tag = hrefTo ? "a" : auto ? "article" : "button";
  const attrs = hrefTo ? `href="${esc(hrefTo)}"` : auto ? "" : `type="button"`;
  return `<${tag} class="card pre ${cls}${sel ? " sel" : ""}${auto ? " auto" : ""}" ${attrs} ${key ? `data-key="${esc(key)}"` : ""}>
    <div class="top"><h3>${esc(title)}</h3>${badge ? `<span class="badge">${esc(badge)}</span>` : ""}</div>
    ${meta ? `<div class="meta">${esc(meta)}</div>` : ""}
    ${mark ? `<div class="mark">${mark}</div>` : ""}
    ${body ? `<div class="body">${body}</div>` : ""}
    ${tags && tags.length ? `<div class="tagline">${tags.map((t) => `<span class="tag">${esc(t)}</span>`).join("")}</div>` : ""}
  </${tag}>`;
}
function linkRows(rows) {
  return `<ul class="links">${rows.map((r) => `<li><${r.btn ? `button type="button" ${r.btn}` : `a href="${esc(r.href)}"`} style="--kc:${r.color || "var(--ink)"}"><span class="k">${icon(r.icon || "right", "md")}</span><span>${esc(r.title)}<small>${esc(r.sub || "")}</small></span></${r.btn ? "button" : "a"}></li>`).join("")}</ul>`;
}

/* ================================================================ 1. overview */
const WALK = [
  { k: "start", t: "Start a live evaluation run", h: "#/lab", step: 1, live: true, tags: ["Broker", "Mailbox"], b: "Red sandbox, defence runner and model worker start in fresh hardened containers; the broker drives the attacks." },
  { k: "prohibited-access", t: "Attempt prohibited access", h: "#/lab?open=prohibited-access", step: 2, live: true, tags: ["Result gate"], b: "The red participant tries to read sealed results and release the run." },
  { k: "cross-role-isolation", t: "Cross a role boundary", h: "#/lab?open=cross-role-isolation", step: 3, live: true, tags: ["Role boundary", "Mailbox"], b: "Blue reaches for red's payloads; the red sandbox's own forbidden requests are read back." },
  { k: "authorized-release", t: "Release as the reviewer", h: "#/lab?open=authorized-release", step: 4, live: true, tags: ["Release gate"], b: "The one permitted path to the results, closed with a signed terminal checkpoint." },
  { k: "tamper", t: "Verify, then tamper with a copy", h: "#/evidence", step: 5, live: false, tags: ["Audit log", "Verifier"], b: "The independent verifier accepts the original and rejects a modified copy." },
];
PAGES.overview = { render: overview };
async function overview() {
  render(loading("Loading the current state…"));
  const [runs, tl] = await Promise.all([loadRuns(), get("/api/lab/timeline?limit=400").catch(() => []), loadJournal()]);
  if (!S.status) await refreshStatus();
  const st = S.status || {}, pm = st.podman || {}, live = isLive();
  const latest = runs[0], integ = st.integrity_latest_terminal_run, shipped = st.integrity_shipped_bundle || {};
  const recent = tl.filter((e) => ["denied", "failed", "alert"].includes(decisionOf(e))).slice(0, 8);
  const walk = WALK.map((w) => {
    const j = w.k === "tamper" ? lastJ((x) => x.kind.startsWith("tamper:")) : w.k === "start" ? lastJ((x) => x.kind === "start" || x.kind === "prepare") : lastJ(w.k);
    let cls = "c-live", badge = "Live", mark = `${icon("circle")}<span class="st none">Not run in this session</span>`;
    if (j) {
      const ok = j.verdict === "PASS" || j.verdict === "STARTED";
      cls = ok ? "c-pass" : "c-fail"; badge = j.verdict === "STARTED" ? "Started" : cap(j.verdict);
      mark = `${icon(ok ? "shield" : "alert")}<span class="st ${ok ? "pass" : "fail"}">${esc(j.verdict)}</span><span class="muted">· ${esc(j.run_id || "")} · ${clock(j.ts)}</span>`;
    } else if (w.live && !live) { cls = "c-grey"; badge = "Needs containers"; mark = `${icon("ban")}<span class="st none">Unavailable on this machine</span>`; }
    return card({ hrefTo: w.h, cls, title: w.t, badge, meta: `Step ${w.step} · ${w.k === "tamper" ? "Evidence" : "Lab"}`, mark, body: esc(w.b), tags: w.tags });
  }).join("");
  render(`
  <section class="sec">
    <p class="statement">Attack payloads, defence rules and the model under test share one machine. AegisLab keeps them apart with rootless containers and a trusted broker, and records every decision in a signed log you can check yourself.</p>
    <p class="lede muted">The isolation problem: a red team must not read the blue team's defences, the blue team must not see red's payloads before release, and the model must not carry one session into the next. Instructions to the model do not enforce that; infrastructure does. This archive lets you test those walls live and verify the record independently.</p>
  </section>

  <section class="sec">
    ${secHead("Runtime status", `checked every 15 s · ${live ? `<span class="st pass">live</span>` : `<span class="st warn">degraded</span>`}`)}
    <div class="cols" style="--n:2">
      <div>
        <ul class="ledger">
          <li><span class="k">Control plane</span><span class="v">${st.control_plane ? `<span class="st pass">Connected</span>` : `<span class="st fail">Unreachable</span>`}</span></li>
          <li><span class="k">Container runtime</span><span class="v">${pm.available ? `Podman ${esc(pm.podman)}, rootless, ${esc(pm.oci_runtime)}` : `<span class="st warn">Unavailable</span> <span class="muted">${esc(st.mode_reason || pm.reason || "")}</span>`}</span></li>
          <li><span class="k">Sandbox image</span><span class="v">${pm.image_present ? esc(pm.image) : `<span class="st warn">Not built</span>`}</span></li>
          <li><span class="k">Kernel isolation</span><span class="v">${pm.available ? `SELinux ${pm.selinux ? "on" : "off"}, cgroups ${esc(pm.cgroups)}, cpuset ${pm.cpuset_delegated ? "pinned" : `<span class="st warn">not delegated</span>`}` : "—"}</span></li>
          <li><span class="k">Model execution</span><span class="v">${esc(st.model ? st.model.label : "—")}<br><span class="tiny">${esc(st.model ? st.model.detail : "")}</span></span></li>
          <li><span class="k">Identities</span><span class="v">${canAct() ? "Operator session (HttpOnly cookie, loopback); role tokens stay on the server" : `<span class="st warn">Read-only</span> <span class="muted">open the launch link printed by scripts/start_prototype.sh</span>`}</span></li>
          <li><span class="k">Code tree</span><span class="v hash">${st.code_revision ? short(st.code_revision.tree_sha256, 20) + " · " + st.code_revision.files + " files" : "—"}</span></li>
        </ul>
      </div>
      <div>
        <p class="lbl">Most recent run ${latest ? `· <span class="mono">${esc(latest.id)}</span>` : ""}</p>
        ${latest ? lifecycle(latest) + `<p class="small muted mt">${latest.evaluated ?? 0} of ${latest.attack_count ?? "?"} attacks evaluated${latest.state === "RUNNING" ? " so far" : ""}. <a href="#/connections?view=timeline&run=${encodeURIComponent(latest.id)}">See its timeline</a></p>` : `<p class="muted">No run in this state directory yet. <a href="#/lab?open=run">Start one in the lab.</a></p>`}
        <p class="lbl">Evidence integrity</p>
        ${integ ? `<p><span class="st ${integ.ok ? "pass" : "fail"}">${integ.ok ? "Verified" : "Verification failed"}</span> · ${esc(integ.run_id)} (${esc(integ.state)}): ${integ.entries} entries, ${integ.checkpoints_checked} signed checkpoints, terminal checkpoint ${integ.terminal_verified ? "verified" : "missing"}.</p>
          <p class="tiny">Checked against ${esc(integ.checked_against)}.</p>${(integ.findings || []).map((f) => `<p class="small st fail">${esc(f)}</p>`).join("")}`
          : `<p class="small muted">No released or failed run here yet; a log is verified strictly only once it has a terminal checkpoint.</p>`}
        <p class="small">Shipped bundle DEMO-001, independent verifier: ${shipped.exit_code === 0 && shipped.ok ? `<span class="st pass">exit 0, accepted</span>` : shipped.exit_code == null ? `<span class="muted">not checked</span>` : `<span class="st fail">exit ${esc(shipped.exit_code)}</span>`}. <a href="#/evidence">Evidence</a></p>
      </div>
    </div>
  </section>

  <section class="sec">
    ${secHead("Demonstrations", `${S.journal.length ? S.journal.length + " recorded in this console's journal" : "none run yet"}`)}
    <div class="cards five">${walk}</div>
    <p class="foot mt">The journal is an unsigned convenience list kept by this console. The signed record is each run's audit log.</p>
  </section>

  <section class="sec">
    ${secHead("Recent denials and alerts", `<a href="#/audit">Open the audit archive</a>`)}
    ${recent.length ? evTable(recent) : `<div class="empty">No denials or alerts recorded yet. They appear here as soon as a run or scenario produces one.</div>`}
  </section>

  <section class="sec">
    ${secHead("How to read this archive")}
    <div class="cols" style="--n:2">
      <div><p class="lbl">Labels</p><ul class="ledger">
        <li><span class="k">${labelTag("sandbox")}</span><span class="v">Executed now in real rootless containers on this machine; the model is the deterministic stub worker, not an LLM.</span></li>
        <li><span class="k">${labelTag("live")}</span><span class="v">Executed now on this machine without the model: refusals, verifier runs, recomputations.</span></li>
        <li><span class="k">${labelTag("pre")}</span><span class="v">Saved Qwen2.5-0.5B runs, recomputed from their raw files on request. No model runs here.</span></li>
        <li><span class="k">${labelTag("rec")}</span><span class="v">A saved judge-demo transcript, shown only when containers are unavailable.</span></li>
        <li><span class="k">${labelTag("na")}</span><span class="v">The required environment (rootless Podman, sandbox image) is missing; nothing is simulated instead.</span></li></ul></div>
      <div><p class="lbl">Known limitations</p><ul class="ledger">
        <li><span class="k">Trusted base</span><span class="v">The broker, its signing key, the host kernel and Podman are trusted, not defended.</span></li>
        <li><span class="k">One host</span><span class="v">Containers share one kernel and one CPU; hardware side channels are untested.</span></li>
        <li><span class="k">Identities</span><span class="v">One local operator session drives every demonstration role server-side; it is not multi-user authentication.</span></li>
        <li><span class="k">Finite tests</span><span class="v">Zero observed leaks is evidence for this configuration, not proof. <a href="#/threat-model">Threat model</a></span></li></ul></div>
    </div>
  </section>`);
}

/* ================================================================ 2. security lab */
const LAB_TYPE = { live: "Live scenario", pre: "Precomputed real-model", stub: "Precomputed stub model" };
const CATALOG = [
  { id: "run", kind: "live", title: "Authorised brokered communication", actor: ["Red sandbox", "Trusted broker", "Defence runner", "Model worker"], boundary: ["Mailbox", "Broker"],
    tested: "The permitted path. The operator creates, freezes and starts a run; the red sandbox submits synthetic attacks only through its own mailbox; the broker commits each attack, asks the defence runner and the model worker, pads the reply to a timing bucket and seals the results.",
    objective: "None: this is the authorised path the other scenarios try to bypass. The red sandbox also sends five forbidden requests of its own during the run.",
    expected: "The run reaches SEALED with every attack evaluated and marked complete; the red sandbox's forbidden requests are refused by the broker and logged.",
    evidence: ["Run record: GET /api/runs/{id}", "Monitoring stream: GET /api/runs/{id}/events (Audit page)", "Timeline: Connections, Timeline perspective"],
    limits: ["The model in live runs is the deterministic stub, not an LLM.", "cpuset pinning is not applied where the controller is not delegated to rootless users."] },
  { id: "sandbox-containment", kind: "live", actor: ["Red sandbox"], boundary: ["Container ↔ host", "Mailbox"],
    objective: "Reach the network or host files from inside the red container, write outside its mailbox, or trap the broker with a planted symlink, FIFO or renamed mailbox.",
    evidence: ["POST /api/lab/scenarios/sandbox-containment/run (fresh container, fixed probe)", "tests/test_phase2_*.py regression tests", "PHASE2_SECURITY_REPORT.md"],
    limits: ["Containers share the host kernel; no escape exploits were attempted.", "A tenant can still flood valid messages until the run deadline (THREAT_MODEL.md row 12)."] },
  { id: "prohibited-access", kind: "live", actor: ["Red participant", "Anonymous caller"], boundary: ["Result gate"],
    objective: "Read the sealed attack artifacts before release, or release the run without being the reviewer.",
    evidence: ["GET /api/runs/{id}/artifacts and POST /api/runs/{id}/release in aegis/api.py", "policy.denied entries in the run's audit log (Audit page)", "evidence/validation_2026-10-22/isolation_matrix.json"],
    limits: ["Role tokens are global per role, not per run. The console holds them server-side; one local operator session drives every role."] },
  { id: "cross-role-isolation", kind: "live", actor: ["Blue participant", "Red sandbox", "Forged token"], boundary: ["Role boundary", "Mailbox"],
    objective: "Read the other team's sealed payloads or the secret configuration digests, or act with a forged identity.",
    evidence: ["GET /api/runs/{id} digest redaction and GET /artifacts role check in aegis/api.py", "Broker denials of the red sandbox in the monitoring stream"],
    limits: ["Red legitimately sees refusals and could map the defence over many queries (black-box inference)."] },
  { id: "authorized-release", kind: "live", actor: ["Reviewer"], boundary: ["Release gate", "Audit log"],
    objective: "None: the permitted path. It shows the result gate opens for the reviewer only, after the chain and the attack commitments verify.",
    evidence: ["POST /api/runs/{id}/release (verifies, then signs the terminal checkpoint)", "Exported reviewer bundle (Evidence page)"],
    limits: ["Release is final for that run.", "The reviewer is a trusted human holding a local token."] },
  { id: "tamper", kind: "live", title: "Evidence tamper detection", actor: ["Anyone who can edit the run directory"], boundary: ["Audit log", "Verifier"],
    tested: "The server copies a bundle to a temporary directory, applies one modification, runs the independent verifier on the copy and on the original, and checks that the original is byte-identical afterwards.",
    objective: "Edit, delete, reorder, truncate or re-hash audit entries, forge the anchor signature or swap the public key without being detected.",
    expected: "Every modified copy rejected (exit 1); the untouched original still accepted (exit 0) and byte-identical.",
    evidence: ["Evidence page: POST /api/lab/bundles/{id}/tamper", "evidence/validation_2026-10-22/audit_tamper.json (recorded sweep)"],
    limits: ["A forger who holds the signing key and replaces every retained copy is not detected (THREAT_MODEL.md row 7)."] },
  { id: "E4", kind: "pre", title: "Prompt-injection containment", actor: ["Red attacker via the model"], boundary: ["Model output → red", "Model output → control plane"],
    tested: "72 injection attacks against Qwen2.5-0.5B through the full pipeline; red-visible output scanned for protected values; model-generated text replayed as gate messages.",
    objective: "Make the model emit protected values to red, or get model-generated text accepted as a control message that changes the run.",
    expected: "No protected value in red-visible output; model-generated gate messages denied with no state change." },
  { id: "E1", kind: "pre", title: "Session-leakage experiment", actor: ["Later session", "Red attacker"], boundary: ["Session ↔ session"],
    tested: "Canaries planted in independent sessions and probed from others, with negative and positive controls (shared history, sharing gateway), directly and through the full pipeline.",
    objective: "Recover a canary planted in another session or run.",
    expected: "No foreign canary in red-visible output; positive controls detect deliberate sharing." },
  { id: "E3", kind: "pre", title: "Prompt-cache observation", actor: ["Red attacker"], boundary: ["Inference server state"],
    tested: "A cached-token and latency oracle with the server prompt cache on (control) and off (AegisLab default), and with a fresh process per trial.",
    objective: "Learn whether another session sent a prompt by measuring cached tokens or latency.",
    expected: "With cache_prompt=false no cached tokens are observed; with caching on the oracle works (control)." },
  { id: "timing", kind: "stub", title: "Timing side channel and padding", actor: ["Red attacker"], boundary: ["Broker timing"],
    tested: "A held-out threshold classifier separating refused from answered requests by latency, three complete executions, 200 requests per setting, with and without bucket padding.",
    objective: "Tell a refused request from an answered one by its latency.",
    expected: "Without padding the classifier succeeds (control); with 250 ms buckets accuracy is near chance." },
];
const LAB_FACETS = [
  { key: "type", title: "Type", get: (c) => LAB_TYPE[c.kind], order: Object.values(LAB_TYPE) },
  { key: "boundary", title: "Boundary", get: (c) => c.boundary },
  { key: "actor", title: "Actor", get: (c) => c.actor },
  { key: "outcome", title: "Outcome", get: (c) => labOutcome(c).f },
];
const labRuns = () => S.runs.filter((r) => /^LAB-\d{3}$/.test(r.id));
const labRec = () => S.runs.find((r) => r.id === S.lab.run);
function scn(c) { return (S.lab.scenarios || []).find((s) => s.id === c.id) || {}; }
function expOf(id) { return S.exp && S.exp.real_model && (S.exp.real_model.experiments || []).find((e) => e.id === id); }
/* the outcome shown on a card: only from this session's results, the console journal, the run record or saved evidence */
function labOutcome(c) {
  const sess = (v, run, where) => {
    const ok = v === "PASS";
    return { cls: ok ? "pass" : v === "STARTED" ? "none" : "fail", f: ok ? "Pass this session" : v === "ERROR" ? "Error" : "Fail this session", text: `${v}${run ? " · " + run : ""}${where ? " · " + where : ""}`, ico: ok ? "shield" : "alert" };
  };
  if (c.id === "run") {
    const r = labRec();
    if (!r) return { cls: "none", f: "Not run yet", text: "No lab run yet", ico: "circle" };
    if (r.state === "RUNNING") return { cls: "none", f: "Running", text: `${r.id} running · ${r.evaluated ?? 0}/${r.attack_count ?? "?"}`, ico: "circle" };
    if (r.state === "FAILED") return { cls: "fail", f: "Fail this session", text: `${r.id} FAILED`, ico: "alert" };
    if (r.complete === false) return { cls: "warn", f: "Incomplete", text: `${r.id} incomplete`, ico: "alert" };
    if (r.state === "SEALED" || r.state === "RELEASED") return { cls: "pass", f: "Pass this session", text: `${r.id} ${r.state.toLowerCase()} · ${r.evaluated}/${r.attack_count} evaluated`, ico: "shield" };
    return { cls: "none", f: "Running", text: `${r.id} ${r.state.toLowerCase()}`, ico: "circle" };
  }
  if (c.kind === "live") {
    const R = S.lab.results[c.id];
    if (R && R.verdict) return sess(R.verdict, R.run_id, "this page");
    const j = c.id === "tamper" ? lastJ((x) => x.kind.startsWith("tamper:")) : lastJ(c.id);
    if (j) return sess(j.verdict, j.run_id, clock(j.ts));
    return { cls: "none", f: "Not run yet", text: "Not run in this session", ico: "circle" };
  }
  if (!S.exp) return { cls: "none", f: "Loading", text: "Loading saved evidence…", ico: "circle" };
  if (c.id === "timing") return S.exp.timing && S.exp.timing.available !== false ? { cls: "warn", f: "Inconclusive (precomputed)", text: "No leak detected with padding; absence not proven", ico: "alert" } : { cls: "fail", f: "Unavailable", text: "Saved files missing", ico: "alert" };
  const e = expOf(c.id);
  if (!e) return { cls: "fail", f: "Unavailable", text: "Saved run not found", ico: "alert" };
  return e.classification === "pass" ? { cls: "pass", f: "Pass (precomputed)", text: `Pass · ${e.id} · ${e.timestamp_utc.slice(0, 10)}`, ico: "shield" } : { cls: "warn", f: "Other (precomputed)", text: e.classification, ico: "alert" };
}
function labRows() { return CATALOG.filter((c) => textMatch(S.lab.search, c.title || scn(c).title || "", c.actor, c.boundary, c.objective, scn(c).summary || "", c.tested || "")); }
PAGES.lab = { render: lab, open: labOpen };
async function lab() {
  render(loading("Loading the scenario catalogue…"));
  const [, scns, profiles, recorded] = await Promise.all([loadRuns(), get("/api/lab/scenarios"), get("/api/lab/defence-profiles").catch(() => []),
    get("/api/lab/results?limit=50").catch(() => []), loadJournal()]);
  S.lab.scenarios = scns; S.lab.profiles = profiles;
  recorded.slice().reverse().forEach((r) => { if (r.scenario && r.scenario !== "tamper" && r.steps) S.lab.results[r.scenario] = r; });
  if (!S.status) await refreshStatus();
  const lr = labRuns();
  if (!S.lab.run || !lr.some((r) => r.id === S.lab.run)) S.lab.run = lr[0] ? lr[0].id : null;
  const live = isLive();
  band({ placeholder: "Scenarios, boundaries, actors", value: S.lab.search, onSearch: (v) => { S.lab.search = v; drawLabCards(); },
    filter: filterCfg(LAB_FACETS, S.lab.f, labRows, drawLabCards) });
  render(`
  <div class="intro"><p>Run the evaluation lifecycle yourself, then attack it. Live scenarios send real requests to the control plane as each role, with the role's token held on the server, and judge the security outcome (status, run state, audit entry, leaked values), not whether HTTP succeeded. Precomputed entries summarise saved experiments.</p>
    <div class="labels">${labelTag(live ? "sandbox" : "na")}${live ? "" : labelTag("rec")}${labelTag("pre")}</div></div>
  ${canAct() ? "" : `<div class="note">${esc(NO_SESSION)} Everything stays visible; nothing can be started.</div>`}
  ${live ? "" : `<div class="note">Live containers are unavailable on this machine: ${esc(S.status ? S.status.mode_reason : "status unknown")}. Live scenarios are disabled and a recorded real execution is shown below; evidence verification still works.</div>`}
  <section class="sec" id="run-box"></section>
  <section class="sec">${secHead("Scenarios", `<span id="lab-count"></span>`)}<div class="cards" id="lab-cards"></div></section>
  ${live ? "" : `<section class="sec" id="replay"></section>`}
  <section class="sec" id="probe-box"></section>`);
  drawRunBox(); drawLabCards(); drawProbe();
  if (!live) drawReplay();
  pollRun();
  $("#lab-cards").addEventListener("click", (e) => { const c = e.target.closest("[data-key]"); if (c) openKey(c.dataset.key); });
  loadExp().then(() => { if (S.page === "lab") { drawLabCards(); refreshSheet(); } }).catch(() => {});
  every(1500, pollRun);
}
function drawLabCards() {
  const el = $("#lab-cards"); if (!el) return;
  const rows = facetFilter(labRows(), LAB_FACETS, S.lab.f);
  $("#lab-count").textContent = `${rows.length} of ${CATALOG.length}`;
  el.innerHTML = rows.length ? rows.map((c) => {
    const o = labOutcome(c), s = scn(c);
    return card({ key: c.id, cls: "c-" + c.kind, title: c.title || s.title || c.id, badge: { live: "Live", pre: "Real model", stub: "Stub model" }[c.kind], meta: c.actor.join(" · "),
      mark: `${icon(o.ico)}<span class="st ${o.cls}">${esc(o.text)}</span>`, body: esc(c.objective), tags: c.boundary, sel: S.q.open === c.id });
  }).join("") : `<div class="empty" style="grid-column:1/-1"><strong>No scenario matches</strong>Clear the search or the filters.</div>`;
  S.lab.sig = labSig();
  enter(el);
}
const labSig = () => JSON.stringify([labRec(), Object.keys(S.lab.results), S.journal.length, !!S.exp]);
async function pollRun() {
  if (!S.lab.run) return;
  const r = await call("/api/lab/runs/" + encodeURIComponent(S.lab.run)).catch(() => null);
  if (!r || !r.ok) { S.lab.stale = true; return; }
  S.lab.stale = false;
  const prev = (labRec() || {}).state, prevEv = S.lab.view ? S.lab.view.events : -1;
  S.lab.view = r.body;
  S.runs = S.runs.map((x) => (x.id === S.lab.run ? r.body.run : x));
  if (prev !== r.body.run.state || r.body.events !== prevEv) {
    drawRunBox();
    if (labSig() !== S.lab.sig) drawLabCards();
    if (S.q.open === "run") refreshSheet();
  }
  if (prev === "RUNNING" && r.body.run.state !== "RUNNING") { toast(S.lab.run + " is " + r.body.run.state); loadJournal(); }
}
const STEP_HELP = {
  CREATED: "The operator created the run. Its inputs are staged: red's attack pack (with a fresh canary) and blue's working defence configuration, which blue may still change.",
  FROZEN: "The configuration is frozen: the manifest records the defence-config and attack-pack digests, the sandbox image digest and the hardening flags, and a signed checkpoint covers it.",
  RUNNING: "The broker is executing the run: red sandbox, defence runner and model worker each in a fresh rootless container with no network. Red can reach the others only through its mailbox.",
  SEALED: "Execution finished. Payloads, model outputs and verdicts sit in the sealed store; only a reviewer can release them. Try to get at them first with the scenarios below.",
  RELEASED: "The reviewer released the run after the audit chain and every attack commitment verified. The signed terminal checkpoint closes the log; the bundle is on the Evidence page.",
  FAILED: "The run failed closed and can never be released. The reason is in its audit log.",
};
function profileSel(id, cur) {
  return `<label class="field">Defence profile<select id="${id}" title="${esc((S.lab.profiles || []).map((p) => p.title + ": " + p.rules).join("; "))}">${(S.lab.profiles || []).map((p) => `<option value="${esc(p.id)}" ${p.id === (cur || "sample") ? "selected" : ""}>${esc(p.title.replace(/ \(.*\)$/, ""))} (${esc(p.rules.replace(/ patterns?/g, "").replace(", ", "/"))})</option>`).join("")}</select></label>`;
}
function drawRunBox() {
  const el = $("#run-box"); if (!el) return;
  const lr = labRuns(), rec = labRec(), live = isLive(), running = lr.some((r) => r.state === "RUNNING"), act = canAct();
  const v = S.lab.view && rec && S.lab.view.run.id === rec.id ? S.lab.view : null;
  const off = !live ? `disabled title="${esc("Unavailable: " + ((S.status || {}).mode_reason || "live containers missing"))}"` : !act ? `disabled title="${esc(NO_SESSION)}"` : "";
  const why = !live ? "UNAVAILABLE on this machine: " + ((S.status || {}).mode_reason || "live containers missing") + "." : !act ? NO_SESSION : "";
  const prof = (S.lab.profiles || []).find((p) => p.id === (v && v.defence_profile));
  let ctl = "";
  if (rec && rec.state === "CREATED") {
    ctl = `<p class="lbl">Step 2 · Configure the defence</p><p class="small muted">Submitted as the blue participant: the rules go to the control plane, never to red or to this page.</p>
      <div class="row">${profileSel("prof2", v && v.defence_profile)}<button class="btn lg" type="button" data-step="defence" ${off}>Submit as blue</button></div>
      <p class="lbl">Step 3 · Freeze</p><div class="row"><button class="btn solid lg" type="button" data-step="freeze" ${off}>${icon("shield")} Freeze configuration</button></div>`;
  } else if (rec && rec.state === "FROZEN") {
    ctl = `<p class="lbl">Step 4 · Start</p><p class="small muted">Launches three hardened rootless containers and the broker. About 5 s with no padding, about 10 s with 250 ms buckets.</p>
      <div class="row"><button class="btn solid lg" type="button" data-step="start" ${off || (running ? "disabled" : "")}>${icon("play")} Start the run</button></div>`;
  } else if (rec && rec.state === "RUNNING") {
    ctl = `<p class="lbl">Step 5 · Observe</p><div class="loading" role="status"><i aria-hidden="true"><b></b><b></b><b></b></i>${esc(rec.evaluated ?? 0)} of ${esc(rec.attack_count ?? "?")} attacks evaluated</div>
      ${v && v.last_event ? `<p class="small">Last event #${esc(v.last_event.seq ?? "–")} · ${esc(v.last_event.actor)} · ${esc(v.last_event.summary)}</p>` : ""}
      <p class="small"><a href="${href("connections", { view: "timeline", run: rec.id })}">Watch its timeline</a> · <a href="${href("audit", { run: rec.id })}">its audit events</a></p>`;
  } else if (rec && rec.state === "SEALED") {
    ctl = `<p class="lbl">Step 6 · Sealed: attack the result gate</p><p class="small muted">Open <b>Prohibited access</b> and <b>Cross-role isolation</b> below; each refusal is logged. Then release.</p>
      <p class="lbl">Step 7 · Release</p><div class="row"><button class="btn solid lg" type="button" data-step="release" ${off}>${icon("shield")} Release as the reviewer</button></div>`;
  } else if (rec && rec.state === "RELEASED") {
    ctl = `<p class="lbl">Step 8 · Verify</p><p class="small muted">The reviewer bundle was exported at release. Verify it with the independent verifier, then tamper with a disposable copy.</p>
      <div class="row"><a class="btn solid lg" href="${href("evidence", { open: rec.id })}">${icon("shield")} Verify ${esc(rec.id)}</a></div>`;
  } else if (rec && rec.state === "FAILED") {
    ctl = `<div class="note bad">${esc(STEP_HELP.FAILED)} <a href="${href("audit", { src: "log", run: rec.id })}">Open its audit log</a>.</div>`;
  }
  const facts = rec ? `<ul class="ledger mt">
      <li><span class="k">Run ID</span><span class="v mono">${esc(rec.id)}</span></li>
      <li><span class="k">Created</span><span class="v">${when(rec.created_at)}</span></li>
      <li><span class="k">State</span><span class="v"><b>${esc(rec.state)}</b> <span class="tiny">${esc(STEP_HELP[rec.state] || "")}</span></span></li>
      <li><span class="k">Mode</span><span class="v">${labelTag("sandbox")}</span></li>
      <li><span class="k">Defence</span><span class="v">${prof ? esc(prof.title) : v && v.defence_profile === undefined ? "—" : "sample (not changed)"}</span></li>
      <li><span class="k">Attacks</span><span class="v">${rec.evaluated ?? 0} of ${rec.attack_count ?? "?"} evaluated · timing bucket ${esc(rec.policy && rec.policy.timing_bucket_ms)} ms${rec.complete === false ? ` · <span class="st warn">incomplete</span>` : rec.complete ? " · complete" : ""}</span></li>
      ${v ? `<li><span class="k">Audit log</span><span class="v">${v.audit_entries} entries, signed up to #${v.signed_upto} · <a href="${href("audit", { src: "log", run: rec.id })}">open</a></span></li>` : ""}
      ${rec.state === "RELEASED" && rec.outcomes ? `<li><span class="k">Outcomes</span><span class="v">${Object.entries(rec.outcomes).map(([k, n]) => `${esc(k)} ${n}`).join(" · ")}</span></li>` : ""}
      ${v && v.next_actions.length ? `<li><span class="k">Next</span><span class="v">${v.next_actions.map((a) => esc(a.label)).join("<br>")}</span></li>` : ""}
    </ul>${S.lab.stale ? `<p class="tiny st warn">Status could not be refreshed; showing the last known state.</p>` : ""}` : "";
  const last = S.lab.last;
  el.innerHTML = `${secHead("Evaluation run", lr.length ? `<label class="field">Run <select id="run-sel">${lr.map((r) => `<option value="${esc(r.id)}" ${r.id === S.lab.run ? "selected" : ""}>${esc(r.id)}: ${esc(r.state)}</option>`).join("")}</select></label>` : "")}
    <div class="cols" style="--n:2"><div>
      ${rec ? lifecycle(rec) + facts : `<p class="muted">No lab run yet. Create one, choose a defence, freeze it and start it. The broker then drives a red sandbox through 10 synthetic attacks and 5 forbidden requests in real containers.</p>`}
    </div><div>
      ${ctl}
      <p class="lbl">${rec ? "New run" : "Step 1 · Create a run"}</p>
      <div class="row">
        <label class="field">Timing padding<select id="bucket"><option value="250">250 ms buckets (default policy)</option><option value="0">none (faster)</option></select></label>
        ${profileSel("prof1")}
        <button class="btn ${rec && rec.state !== "RELEASED" && rec.state !== "FAILED" ? "" : "solid"} lg" id="start-run" type="button" ${off || (running ? "disabled" : "")}>${icon("plus")} Create run</button>
      </div>
      <p class="why mt">${why || (running ? "A run is executing; a new one can be created once it seals." : "Each step calls the real control plane; the run ID appears only after the server confirms it.")}</p>
      ${last ? `<div class="ev mt" id="last-step"><b>Last step</b> · ${last.error ? `<span class="st fail">${esc(last.error)}</span>` : `${(last.steps || []).map((s) => `${esc(s.actor)} ${esc(s.action)} <span class="st ${s.status === 200 ? "pass" : "fail"}">HTTP ${esc(s.status)}</span>`).join("<br>")}`}<br><span class="tiny">${when(last.t)}</span></div>` : ""}
    </div></div>`;
  const sel = $("#run-sel");
  if (sel) sel.addEventListener("change", () => { S.lab.run = sel.value; S.lab.view = null; pollRun(); drawRunBox(); drawLabCards(); refreshSheet(); });
  $("#start-run").addEventListener("click", startRun);
  $$("[data-step]", el).forEach((b) => b.addEventListener("click", () => runStep(b.dataset.step, b)));
  drawRings(el);
}
async function labPost(btn, path, body, ok, idem) {
  busy(btn, true);
  try {
    const r = await call(path, { method: "POST", body, idem });
    if (!r.ok) {
      const msg = classify(r.status).text + ": " + ((r.body && r.body.detail) || "");
      S.lab.last = { t: Date.now() / 1000, error: msg }; toast(msg, true);
    } else {
      S.lab.run = r.body.run_id; S.lab.view = r.body.run;
      S.lab.last = { t: Date.now() / 1000, steps: r.body.steps || [r.body.step] };
      toast(r.body.replayed ? `${r.body.run_id}: this request was already processed; no second run was created` : ok(r.body));
    }
    await Promise.all([loadRuns(), loadJournal()]);
    if (S.page !== "lab") return r;
    drawRunBox(); drawLabCards(); probeRuns(); refreshSheet();
    return r;
  } catch (e) { toast(e.message, true); return null; } finally { if (document.contains(btn)) busy(btn, false); }
}
/* One key per click: a retried or duplicated create request returns the run it already created instead of a second one. */
const idemKey = () => Array.from(crypto.getRandomValues(new Uint8Array(16)), (x) => x.toString(16).padStart(2, "0")).join("");
async function startRun(ev) {
  const bucket = $("#bucket") ? Number($("#bucket").value) : 250, prof = $("#prof1") ? $("#prof1").value : "sample";
  await labPost(ev.currentTarget, "/api/lab/runs", { timing_bucket_ms: bucket, defence_profile: prof, stop_after: "created" },
    (b) => `${b.run_id} created by the operator; defence submitted by the blue participant`, idemKey());
}
async function runStep(step, btn) {
  const id = S.lab.run, base = "/api/lab/runs/" + encodeURIComponent(id);
  if (step === "defence") return labPost(btn, base + "/defence", { profile: $("#prof2").value }, () => `Blue participant submitted the ${$("#prof2") ? $("#prof2").value : ""} profile for ${id}`);
  if (step === "freeze") return labPost(btn, base + "/freeze", undefined, () => `${id} frozen: digests fixed and checkpoint signed`);
  if (step === "start") return labPost(btn, base + "/start", undefined, () => `${id} started: the broker is launching the containers`);
  if (step === "release") return runScenario("authorized-release", btn);
}
function scnBlocker(c) {
  const s = scn(c), rec = labRec();
  if (!isLive()) return "Needs live containers.";
  if (!canAct()) return NO_SESSION;
  if (s.needs && !rec) return "Start a live run first.";
  if (s.needs && rec.state !== s.needs) return rec.state === "RUNNING" ? "Waiting for " + rec.id + " to seal." : `Needs a ${s.needs} run; ${rec.id} is ${rec.state}. Start a new run.`;
  return "";
}
async function labOpen(key) {
  const c = CATALOG.find((x) => x.id === key);
  if (!c) return null;
  if (!S.lab.scenarios) S.lab.scenarios = await get("/api/lab/scenarios");
  const s = scn(c), o = labOutcome(c), R = S.lab.results[c.id];
  let actual = `<p><span class="st ${o.cls}">${esc(o.text)}</span></p>`, action = "", extra = "", evidence = c.evidence || [], limits = c.limits || [];
  if (c.kind === "live" && c.id !== "run" && c.id !== "tamper") {
    const why = scnBlocker(c);
    action = `<div class="row"><button class="btn solid lg" type="button" id="do-scn" ${why ? "disabled" : ""}>${icon("play")} Run scenario${s.needs ? " on " + esc(S.lab.run || "—") : ""}</button>${why ? `<span class="why">${esc(why)}</span>` : ""}</div>`;
    if (R) extra = resultView(R);
    if (!R) actual += `<p class="tiny">${lastJ(c.id) ? "From the console journal. Run it again to see each request and audit entry here." : "Run the scenario to see each request, the policy decision and the audit entry it produced."}</p>`;
  } else if (c.id === "run") {
    const rec = labRec();
    action = `<div class="row"><a class="btn solid lg" href="#/lab">${icon("play")} Go to the evaluation run</a><a href="#/connections?view=timeline${rec ? "&run=" + encodeURIComponent(rec.id) : ""}">Open its timeline</a></div>`;
    if (rec) actual += lifecycle(rec) + `<p class="tiny mt">${rec.evaluated ?? 0} of ${rec.attack_count ?? "?"} attacks evaluated · model backend errors ${esc(rec.model_backend_errors ?? 0)}</p>`;
  } else if (c.id === "tamper") {
    const sys = S.exp && S.exp.system_tests && (S.exp.system_tests.rows || []).filter((r) => r.file === "audit_tamper.json");
    action = `<a class="btn solid lg" href="#/evidence">Open evidence verification ${icon("right")}</a>`;
    if (sys && sys.length) actual += `<p class="lbl">Recorded sweep ${labelTag("stub")}</p><ul class="ledger">${sys.map((r) => `<li><span class="k">${esc(r.claim)}</span><span class="v">${esc(r.value)} <span class="tiny">${esc(r.file)}</span></span></li>`).join("")}</ul>`;
  } else if (c.id === "timing") {
    const tm = (S.exp || {}).timing;
    if (tm && tm.claims) actual += `<ul class="ledger"><li><span class="k">No padding</span><span class="v">accuracy ${esc(tm.claims.acc0)} (control: leak detected)</span></li><li><span class="k">250 ms buckets</span><span class="v">accuracy ${esc(tm.claims.acc250)}, pooled ${esc(tm.claims.pool250)}</span></li><li><span class="k">Cost</span><span class="v">${esc(tm.claims.cost250)} median added latency</span></li></ul>`;
    evidence = [tm ? tm.source : "evidence/closeout_2026-10-22/timing/", "Experiments page (recomputed from the raw files)"];
    limits = ["n=200 per execution cannot tell an accuracy up to about 0.57 from chance.", "Cache and memory-bandwidth channels were not measured.", "Stub latency is a constant sleep; a real model's variable latency was not measured."];
    action = `<a class="btn lg" href="#/experiments">Open experiments ${icon("right")}</a>`;
  } else {
    const ids = c.id === "E1" ? ["E1", "E2"] : [c.id];
    const exps = ids.map(expOf).filter(Boolean);
    if (exps.length) actual += exps.map((e) => `<p class="lbl">${esc(e.id)} · ${esc(e.title)}</p><ul class="dash" style="padding-left:18px;margin:0">${e.claims.map((x) => `<li>${esc(x)}</li>`).join("")}</ul>`).join("");
    else if (!S.exp) actual = `<p class="muted">Loading saved evidence…</p>`;
    evidence = exps.map((e) => e.dir).concat(["evaluation/check_claims.py recomputes these figures (Experiments page)"]);
    limits = ((S.exp || {}).real_model || {}).limitations || [];
    if (c.id === "E3") limits = limits.concat(["With cache_prompt=true a cached-token oracle reaches AUC 1.00: cross-session server state exists even when no content leaks."]);
    action = `<a class="btn lg" href="#/experiments">Open experiments ${icon("right")}</a>`;
  }
  return {
    title: c.title || s.title || c.id,
    meta: `${labelTag(c.kind)} · ${esc(c.actor.join(" · "))}`,
    body: `
      <p class="lbl">What is tested</p><p>${esc(c.tested || s.summary || "")}</p>
      <p class="lbl">Attacker objective</p><p>${esc(c.objective)}</p>
      <p class="lbl">Trust boundary</p><p class="row">${c.boundary.map((b) => `<span class="tag">${esc(b)}</span>`).join("")} <a href="#/connections" class="small">See it in Connections</a></p>
      <p class="lbl">Expected result</p><p>${esc(c.expected || s.expected || "")}</p>
      <p class="lbl">Actual result</p>${actual}
      ${action ? `<div class="mt">${action}</div>` : ""}
      ${extra}
      <hr>
      <p class="lbl">Evidence reference</p><ul class="dash" style="padding-left:18px;margin:0">${evidence.map((x) => `<li class="small">${esc(x)}</li>`).join("")}</ul>
      ${limits.length ? `<p class="lbl">Limitations</p><ul class="dash" style="padding-left:18px;margin:0">${limits.map((x) => `<li class="small">${esc(x)}</li>`).join("")}</ul>` : ""}`,
    after: (b) => {
      const run = $("#do-scn", b); if (run) run.addEventListener("click", () => runScenario(c.id, run));
    },
  };
}
async function runScenario(sid, btn) {
  if (sid === "authorized-release") {
    const ok = await confirmAction("Release " + S.lab.run + "?", `<p>The reviewer releases the sealed run. Release is final: <b>${esc(S.lab.run)}</b> becomes RELEASED and cannot return to SEALED. Start another run to repeat the other scenarios.</p>`, "Release " + S.lab.run);
    if (!ok) return;
  }
  busy(btn, true);
  try {
    const r = await call(`/api/lab/scenarios/${sid}/run`, { method: "POST", body: { run_id: S.lab.run } });
    S.lab.results[sid] = r.ok ? r.body : { http: r.status, detail: (r.body && r.body.detail) || "", sid, verdict: classify(r.status).kind === "error" ? "ERROR" : "FAIL", run_id: S.lab.run };
  } catch (e) { S.lab.results[sid] = { http: 0, detail: e.message, sid, verdict: "ERROR" }; }
  await Promise.all([loadRuns(), loadJournal()]);
  if (S.page !== "lab") return;
  drawRunBox(); drawLabCards(); probeRuns();
  await refreshSheet();
  const res = $("#scn-result"); if (res) { res.scrollIntoView({ block: "start", behavior: "smooth" }); res.focus({ preventScroll: true }); }
}
function resultView(R) {
  if (R.http !== undefined) {
    const c = classify(R.http);
    return `<div id="scn-result" tabindex="-1">${verdictBox(c.kind === "error" ? "ERROR" : "FAIL", "The scenario could not start")}<p class="small">${esc(c.text)}: ${esc(R.detail)}</p></div>`;
  }
  const stamp = (s) => {
    const d = s.decision === "denied" ? "denied" : s.decision === "allowed" ? "allowed" : s.decision === "error" ? "error" : "attempted";
    return `<span class="stamp ${d}">${{ denied: "DENIED", allowed: "ALLOWED", error: "ERROR", attempted: "ATTEMPTED" }[d]}<small>${esc(typeof s.status === "number" ? "HTTP " + s.status : s.status)}</small></span>`;
  };
  return `<div id="scn-result" tabindex="-1">
    <p class="lbl">Result of this run ${labelTag(R.scenario === "sandbox-containment" ? "sandbox" : "live")}</p>
    <p class="tiny">${R.run_id ? "Run " + esc(R.run_id) + " · " : ""}${when(R.started_at)} · ${(R.finished_at - R.started_at).toFixed(2)} s · ${R.result_id ? "recorded result #" + esc(R.result_id) + " · " : ""}started from the operator session; each step was sent server-side as the role named on it</p>
    ${verdictBox(R.verdict, R.expected)}
    ${R.error ? `<div class="note bad">${esc(R.error)}</div>` : ""}
    <p class="lbl">Requests and decisions</p>
    <ol class="steps">${R.steps.map((s) => `<li>${stamp(s)}<div>
      <div><span class="who">${esc(s.actor)}</span> <span class="act">${esc(s.action)}</span></div>
      <div class="exp">${esc(s.explain)}</div>
      <div class="tiny" style="margin-top:4px">Expected ${esc(s.expected_status)}, observed ${esc(s.status)}${s.detail ? ": “" + esc(s.detail) + "”" : ""} · <span class="st ${s.ok ? "pass" : "fail"}">${s.ok ? "as required" : "NOT as required"}</span></div>
      ${s.audit ? `<div class="ev">Audit entry <b>#${s.audit.seq}</b> ${esc(s.audit.type)} by ${esc(s.audit.actor)}${s.audit.data.reason ? ": " + esc(s.audit.data.reason) : ""}<br><span class="hash">hash ${short(s.audit.hash, 24)} · prev ${short(s.audit.prev, 12)}</span><br>${s.audit.signed ? `<span class="st pass">covered by a signed checkpoint</span>` : `<span class="st warn">not yet covered by a signed checkpoint</span>`}</div>` : ""}
      ${s.audit_missing ? `<div class="ev st fail">${esc(s.audit_missing)}</div>` : ""}
    </div></li>`).join("")}</ol>
    ${R.sandbox_denials ? `<p class="lbl">Denied inside the run: the red sandbox's own requests</p><ul class="checks">${R.sandbox_denials.map((d) => `<li><span class="st deny">${icon("ban")}</span><div>#${d.seq} ${esc(d.summary)} ${d.signed ? `<span class="st pass">signed</span>` : ""}</div></li>`).join("")}</ul>` : ""}
    <p class="lbl">Checks</p>
    <ul class="checks">${R.checks.map((c) => `<li><span class="${c.ok ? "ok" : "no"}" role="img" aria-label="${c.ok ? "holds" : "does not hold"}">${icon(c.ok ? "check" : "x")}</span><div>${esc(c.label)}<span class="found">${esc(c.found)}</span></div></li>`).join("")}</ul>
    ${R.hardening_flags ? `<p class="lbl">Container flags used</p><div class="cmd">podman run ${esc(R.hardening_flags.join(" "))}</div>` : ""}
    ${R.terminal_hash ? `<div class="note info">Terminal checkpoint hash, the value a reviewer writes down at release: <span class="hash">${esc(R.terminal_hash)}</span>. The bundle is now on the <a href="#/evidence">Evidence</a> page.</div>` : ""}
    <p class="small mt">${R.run_id ? `<a href="${href("audit", { src: "log", run: R.run_id })}">See these entries in the signed audit log</a> · ` : ""}<a href="${href("connections", { view: "topology", node: OBS_NODE[R.scenario] || "policy" })}">See the tested boundary on the graph</a></p></div>`;
}
const PROBE_OPS = {
  artifacts: "Read sealed attack artifacts",
  evidence: "Read the evidence report",
  detail: "Read run detail (secret digests?)",
  verify: "Verify the audit log",
  release: "Release the run",
};
function probeRuns() {
  const sel = $("#p-run"); if (!sel) return;
  const cur = sel.value, lr = labRuns();
  sel.innerHTML = lr.length ? lr.map((r) => `<option value="${esc(r.id)}" ${r.id === (cur || S.lab.run) ? "selected" : ""}>${esc(r.id)} (${esc(r.state)})</option>`).join("") : `<option value="">no lab runs yet</option>`;
  $("#p-send").disabled = !lr.length || !canAct();
}
function drawProbe() {
  const lr = labRuns();
  $("#probe-box").innerHTML = `${secHead("Try a request yourself", labelTag("live"))}
    <p class="small muted">Pick an identity and an operation. The console sends that exact request to the control plane server-side, with the identity's token (which never reaches this page), and shows the decision, the audit entry it produced and the shape of the response. Values the role received stay on the server.</p>
    <div class="row mt">
      <label class="field">Identity<select id="p-role">${Object.entries(ROLE_NAMES).map(([k, v]) => `<option value="${k}" ${k === "red_participant" ? "selected" : ""}>${esc(v)}</option>`).join("")}</select></label>
      <label class="field">Operation<select id="p-op">${Object.entries(PROBE_OPS).map(([k, v]) => `<option value="${k}">${esc(v)}</option>`).join("")}</select></label>
      <label class="field">Run<select id="p-run">${lr.length ? lr.map((r) => `<option value="${esc(r.id)}" ${r.id === S.lab.run ? "selected" : ""}>${esc(r.id)} (${esc(r.state)})</option>`).join("") : `<option value="">no lab runs yet</option>`}</select></label>
      <button class="btn lg" id="p-send" type="button" ${lr.length && canAct() ? "" : "disabled"}>Send request ${icon("right")}</button>
    </div>${canAct() ? "" : `<p class="why mt">${esc(NO_SESSION)}</p>`}<div id="p-out" aria-live="polite"></div>`;
  $("#p-send").addEventListener("click", async (ev) => {
    const role = $("#p-role").value, op = $("#p-op").value, run = $("#p-run").value;
    if (!run) return;
    const btn = ev.currentTarget;
    if (op === "release" && role === "reviewer" && !(await confirmAction("Release " + run + "?", "<p>This is a real release by the reviewer and it is final.</p>", "Release " + run))) return;
    busy(btn, true);
    try {
      const r = await call("/api/lab/probe", { method: "POST", body: { role, op, run_id: run } });
      if (!r.ok) { $("#p-out").innerHTML = `<div class="note bad">${esc(classify(r.status).text)}: ${esc((r.body && r.body.detail) || "")}</div>`; return; }
      const P = r.body, c = classify(P.status);
      const k = c.kind === "allowed" ? "allowed" : c.kind === "denied" ? "denied" : c.kind === "error" ? "error" : "attempted";
      $("#p-out").innerHTML = `<div class="ev mt"><div class="row"><span class="stamp ${k}">${{ allowed: "ALLOWED", denied: "DENIED", error: "ERROR", attempted: "REJECTED" }[k]}<small>HTTP ${P.status}</small></span>
        <div><div class="small">${esc(P.request)}</div><div class="tiny">as ${esc(ROLE_NAMES[role])}: ${esc(c.text)}${P.detail ? " · “" + esc(P.detail) + "”" : ""}</div></div></div>
        ${P.audit.length ? P.audit.map((a) => `<p class="small">Audit entry <b>#${a.seq}</b> ${esc(a.type)} by ${esc(a.actor)}${a.data.reason ? ": " + esc(a.data.reason) : ""} <span class="hash">${short(a.hash, 16)}</span> <a href="${href("audit", { src: "log", run: P.run_id })}">open</a></p>`).join("") : `<p class="tiny">${P.post_terminal && P.post_terminal.length ? P.post_terminal.map((a) => `Recorded after the signed chain closed: ${esc(a.type)} by ${esc(a.actor)}${a.data.reason ? ": " + esc(a.data.reason) : ""} <b>(unsigned, no audit sequence number)</b>`).join("<br>") + ". " : ""}${esc((P.recording || {}).explain || "No audit entry was written for this request.")}</p>`}
        ${P.summary ? `<p class="lbl">What the role received</p><pre class="json">${esc(JSON.stringify(P.summary, null, 1))}</pre>` : ""}
        ${P.response_shape ? `<details><summary>Response structure</summary><pre class="json">${esc(JSON.stringify(P.response_shape, null, 1))}</pre></details>` : ""}
        <p class="tiny">${P.status < 300 ? `Protected values in the raw response: ${P.protected_values_in_raw_response} (kept on the server).` : `Protected values in the refusal: ${P.protected_values_in_raw_response}.`} ${esc(P.note)}</p></div>`;
      loadRuns().then(() => { drawRunBox(); drawLabCards(); probeRuns(); });
    } catch (e) { $("#p-out").innerHTML = `<div class="note bad">${esc(e.message)}</div>`; }
    finally { busy(btn, false); }
  });
}
async function drawReplay() {
  const el = $("#replay"); if (!el) return;
  try {
    const r = await get("/api/lab/replay");
    el.innerHTML = `${secHead("Recorded execution", labelTag("rec"))}
      <p class="small muted">${esc(r.mode)} · recorded ${esc(r.recorded_utc)} · ${esc(r.checks)} checks · source ${esc(r.source)}. A recording of a real run on 23 Oct 2026, not a live result on this machine.</p>
      <div class="transcript">${r.lines.map((l) => `<span class="${esc(l.kind)}">${esc(l.text)}</span>`).join("\n")}</div>`;
  } catch (e) { el.innerHTML = `${secHead("Recorded execution")}<div class="note bad">No recording available: ${esc(e.message)}</div>`; }
}

/* ================================================================ 3. connections */
const TOPO = {
  w: 940, h: 610,
  zones: [
    { x: 16, y: 40, w: 238, h: 482, t: "Tenant sandboxes · rootless Podman" },
    { x: 306, y: 200, w: 238, h: 384, t: "Trusted on this host" },
    { x: 606, y: 118, w: 300, h: 474, t: "Control plane and evidence" },
  ],
  nodes: {
    red: { x: 40, y: 86, w: 190, h: 60, t: "Red-team workload", s: "attack agent, untrusted", mc: "var(--crimson)",
      role: "Runs the red team's attack agent against the model under test.",
      trust: "Untrusted. Assumed hostile: may plant links, FIFOs or oversized messages in its own mailbox.",
      allow: ["Write requests into its own mailbox (spool/out)", "Read the broker's replies (spool/in)", "Read its own attack pack, read-only"],
      deny: ["Any network connection (no interfaces besides loopback)", "Reaching the defence runner or model worker directly", "Reading the frozen defence config or sealed results", "Claiming another tenant's identity in a message"],
      controls: ["--network none, --read-only, --cap-drop ALL, no-new-privileges", "--userns keep-id (non-root), pids/memory/CPU limits", "Private SELinux label per container (:Z)"], flags: "red", test: ["sandbox-containment", "cross-role-isolation"] },
    blue: { x: 40, y: 262, w: 190, h: 60, t: "Blue-team workload", s: "defence runner, frozen config", mc: "var(--cobalt)",
      role: "Applies the blue team's frozen input and output rules to every attack and model answer.",
      trust: "A peer, not trusted: anything other than a clear allow or block verdict is treated as block.",
      allow: ["Read the frozen config, read-only", "Answer the broker's inspect_input / inspect_output requests"],
      deny: ["Network access", "Reaching red or the model directly", "Changing its config after freeze (digest attested at start)"],
      controls: ["Same hardening flags as red", "Config digest attested against the frozen manifest"], flags: "blue", test: ["cross-role-isolation"] },
    model: { x: 40, y: 438, w: 190, h: 60, t: "Client model", s: "model worker under test", mc: "var(--violet)",
      role: "Answers prompts. Live runs use a deterministic stub; saved experiments used Qwen2.5-0.5B on CPU llama.cpp.",
      trust: "Untrusted output: the broker withholds any answer carrying another run's canary or a control-plane secret.",
      allow: ["Answer generate requests from the broker"],
      deny: ["Network access", "Keeping state between runs (fresh container per run)", "Seeing other tenants' data"],
      controls: ["Fresh container per run, destroyed at seal", "Stateless requests for a real-model backend (cache_prompt false)"], flags: "model", test: ["E1", "E4"] },
    net: { x: 330, y: 52, w: 190, h: 54, t: "Network and host", s: "outside every sandbox", cls: "out",
      role: "The internet, the host's services and this console's port.", trust: "Out of reach for tenant containers.",
      allow: [], deny: ["Any connection from a sandbox (TCP, DNS); all three containers run with --network none"], controls: ["--network none"], test: ["sandbox-containment"] },
    broker: { x: 330, y: 232, w: 190, h: 78, t: "Trusted broker", s: "sole path between sandboxes", cls: "trusted",
      role: "Moves every message between the sandboxes, checks attack commitments, applies timing padding, seals artifacts and writes the audit log.",
      trust: "TRUSTED. It sees every payload and signs every checkpoint. A compromised broker can sign a false but consistent record; this is not defended.",
      allow: ["Read red's mailbox; reply after padding", "Call the defence runner and model worker", "Write the sealed store and the audit log"],
      deny: ["Following links or blocking on FIFOs in tenant mailboxes (O_NOFOLLOW, O_NONBLOCK)", "Answering red with another run's canary or a secret"],
      controls: ["Identity bound to the mailbox, never to a claimed field", "Commit-then-reveal for every attack", "Uniform refusal text and timing buckets"], test: ["run", "cross-role-isolation", "sandbox-containment"] },
    key: { x: 330, y: 392, w: 190, h: 54, t: "Signing key", s: "Ed25519, file mode 0600", cls: "trusted",
      role: "The broker's private key that signs every checkpoint and the terminal anchor.",
      trust: "TRUSTED. Same Unix user as the broker on this prototype; whoever holds it can forge a consistent history (THREAT_MODEL.md row 7).",
      allow: ["Read by the broker to sign"], deny: ["Readable by tenant containers (never mounted)"], controls: ["Mode 0600, atomic creation", "Key id recorded in every manifest and checkpoint"], test: ["tamper"] },
    host: { x: 330, y: 508, w: 190, h: 58, t: "Host kernel, Podman", s: "shared by every container", cls: "trusted",
      role: "The Linux kernel, rootless Podman and crun that enforce every container boundary.",
      trust: "TRUSTED. Containers share this kernel: one kernel or runtime bug defeats the boundary. Not separate hosts, not hardware isolation.",
      allow: ["Run the three tenant containers and the broker process"], deny: [], controls: ["Rootless, default seccomp, SELinux labels, cgroup v2 limits"], test: ["sandbox-containment"] },
    people: { x: 630, y: 36, w: 252, h: 54, t: "People (browser)", s: "every role, by local token", cls: "out",
      role: "Humans using the control plane through this console.", trust: "The console acts for each role with server-held local tokens after a loopback operator session; production would use SSO with run-scoped claims.",
      allow: ["Observer: the redacted monitoring stream", "Operator: create, freeze, start", "Reviewer: release, then read results"],
      deny: ["Participants reading sealed results before release", "Anyone but the reviewer releasing a run"], controls: ["Constant-time token comparison", "Role checks in every handler"], test: ["prohibited-access"] },
    policy: { x: 630, y: 150, w: 252, h: 62, t: "Policy enforcement", s: "control-plane API, result gate", cls: "trusted",
      role: "FastAPI service that enforces roles and the run lifecycle (CREATED, FROZEN, RUNNING, SEALED, RELEASED).",
      trust: "Trusted component on the same host as the broker.",
      allow: ["Release by the reviewer of a SEALED run that verifies", "Artifacts after release to reviewer and participants"],
      deny: ["Artifact reads before release (logged as policy.denied)", "Release by any other role (logged)", "Secret digests to non-privileged roles before release"],
      controls: ["Lifecycle lock: one state transition at a time", "Release re-verifies the chain and the commitments first"], test: ["prohibited-access", "authorized-release"] },
    sealed: { x: 630, y: 262, w: 252, h: 56, t: "Sealed result store", s: "payloads, outputs, verdicts",
      role: "Holds every raw artifact of the run until release.", trust: "Protected evaluation artifacts.",
      allow: ["Broker writes", "Reviewer and participants read after release"], deny: ["Any read before release", "Observers, ever"],
      controls: ["Result gate in the API", "Digest of the sealed artifacts bound into the audit log"], test: ["prohibited-access", "authorized-release"] },
    audit: { x: 630, y: 372, w: 252, h: 62, t: "Audit storage", s: "hash chain, vault, anchor",
      role: "Append-only hash-chained log with signed, chained checkpoints copied to a reviewer vault, and a signed terminal anchor.",
      trust: "Integrity is checkable without trusting the files: a verifier needs only the pinned public key. Vault and anchor are separate copies, not separate trust domains, on one filesystem.",
      allow: ["Append by the control plane", "Export as a reviewer bundle"], deny: ["Undetected edit, deletion, reordering or truncation"],
      controls: ["Terminal checkpoint closes the chain", "Later events go to post_terminal.jsonl, unsigned"], test: ["authorized-release", "tamper"] },
    verifier: { x: 630, y: 500, w: 252, h: 56, t: "Evidence verifier", s: "python -m aegis.verify_cli",
      role: "A separate program a reviewer runs on their own machine against an exported bundle.", trust: "Must run where the attacker has no control.",
      allow: ["Read a bundle and a pinned key"], deny: ["Accepting a log without a signed terminal checkpoint (fails closed)"],
      controls: ["--pubkey pins the key", "--expect-terminal-hash detects a full re-signed rewrite"], test: ["tamper"] },
  },
  edges: [
    { a: "red", b: "broker", k: "allow", l: "mailbox only", bo: -16, why: "The red sandbox's only channel: request files in its own mailbox, read by the broker." },
    { a: "broker", b: "blue", k: "allow", l: "inspect", ao: 8, why: "The broker asks the defence runner to inspect each attack and each answer." },
    { a: "broker", b: "model", k: "allow", l: "generate", ao: 24, why: "The broker forwards permitted prompts to the model worker." },
    { a: "red", b: "blue", k: "deny", why: "No direct path: separate containers, no network, no shared mount." },
    { a: "red", b: "model", k: "deny", d: "M40 116 C 2 116, 2 468, 40 468", m: [12, 292], why: "No direct path: red can reach the model only through the broker." },
    { a: "red", b: "net", k: "deny", l: "no network", ao: -16, why: "--network none: connections and DNS fail inside the container." },
    { a: "policy", b: "broker", k: "allow", l: "start run", bo: -26, why: "The operator's start request makes the control plane launch the broker for the run." },
    { a: "broker", b: "sealed", k: "allow", l: "seal", why: "Payloads, outputs and verdicts are written to the sealed store." },
    { a: "broker", b: "audit", k: "audit", l: "log + sign", bo: -6, ao: 26, why: "Every decision is appended to the hash chain and covered by signed checkpoints." },
    { a: "people", b: "policy", k: "allow", l: "role token", why: "Every request carries a role token checked in the handler." },
    { a: "policy", b: "sealed", k: "allow", l: "release gate", why: "Artifacts are served only after a reviewer releases a run that verifies." },
    { a: "people", b: "sealed", k: "deny", d: "M882 63 C 922 63, 922 290, 882 290", m: [912, 176], why: "No direct read: every read goes through the result gate; refusals are logged." },
    { a: "policy", b: "audit", k: "audit", d: "M630 200 C 590 250, 590 380, 630 398", m: [600, 300], why: "Denied requests are recorded as policy.denied entries." },
    { a: "audit", b: "verifier", k: "audit", l: "export bundle", why: "At release the reviewer bundle is exported for independent verification." },
    { a: "broker", b: "key", k: "trust", l: "signs with", why: "Checkpoints and the terminal anchor are signed with this key." },
    { a: "verifier", b: "key", k: "trust", l: "pinned public key", why: "The verifier must use a public key pinned out of band, not one found in the bundle." },
    { a: "model", b: "host", k: "trust", l: "shared kernel", ao: 14, why: "All three tenant containers depend on the host kernel and Podman for isolation." },
    { a: "broker", b: "host", k: "trust", d: "M346 310 C 316 380, 316 500, 330 536", m: [322, 470], why: "The broker runs as a host process." },
  ],
};
/* Observed overlay: which static topology paths a recorded scenario result exercised. The marks come from results this console
   recorded (/api/lab/results), each tied to a run and audit entries; the graph is still not a packet trace. */
const OBS_MAP = {
  "prohibited-access": [["people", "sealed", "Participant and anonymous reads of sealed results refused"], ["policy", "audit", "Each refusal written to the audit log"]],
  "cross-role-isolation": [["people", "sealed", "Blue read of red's payloads refused; forged token rejected"], ["red", "broker", "Forbidden mailbox requests of the red sandbox refused by the broker"]],
  "authorized-release": [["policy", "sealed", "Reviewer release opened the result gate after verification"], ["audit", "verifier", "Reviewer bundle exported and verified strictly"]],
  "sandbox-containment": [["red", "net", "Network, DNS and root-filesystem writes refused inside a hardened container"]],
  tamper: [["audit", "verifier", "Tampered copy rejected by the independent verifier; original accepted"]],
};
const OBS_NODE = { "prohibited-access": "sealed", "cross-role-isolation": "broker", "authorized-release": "policy", "sandbox-containment": "red", tamper: "verifier" };
const OBS_TITLE = { "prohibited-access": "Prohibited access", "cross-role-isolation": "Cross-role isolation", "authorized-release": "Authorised release", "sandbox-containment": "Sandbox containment", tamper: "Tamper detection" };
function obsLatest() {
  const out = {};
  (S.conn.obs || []).forEach((r) => { if (r.scenario && OBS_MAP[r.scenario] && !out[r.scenario]) out[r.scenario] = r; });
  return out;
}
function obsFor(a, b) {
  const L = obsLatest(), hits = [];
  Object.entries(OBS_MAP).forEach(([sid, edges]) => edges.forEach(([x, y, what]) => { if (x === a && y === b && L[sid]) hits.push({ sid, what, r: L[sid] }); }));
  return hits;
}
const HIER = {
  w: 1000, h: 640,
  heads: [[20, "Actor"], [330, "Operation"], [760, "Resource"]],
  nodes: {
    observer: { x: 20, y: 52, w: 210, h: 40, t: "Observer", s: "no token", col: 0 },
    operator: { x: 20, y: 140, w: 210, h: 40, t: "Operator", s: "runs the evaluation", col: 0 },
    reviewer: { x: 20, y: 250, w: 210, h: 40, t: "Reviewer", s: "the only role that releases", col: 0 },
    blue_p: { x: 20, y: 348, w: 210, h: 40, t: "Blue participant", s: "defence team", col: 0 },
    red_p: { x: 20, y: 440, w: 210, h: 40, t: "Red participant", s: "attack team", col: 0 },
    red_sb: { x: 20, y: 560, w: 210, h: 40, t: "Red sandbox", s: "container, via mailbox", col: 0 },
    o1: { x: 330, y: 40, w: 330, h: 36, t: "Read runs, monitoring stream, verify", col: 1, src: "GET /api/runs, /api/runs/{id}/events, /api/runs/{id}/verify: no role check (redacted stream)" },
    o2: { x: 330, y: 98, w: 330, h: 36, t: "Create, freeze, start a run", col: 1, src: "need(token, \"operator\") in POST /api/runs, /freeze, /start" },
    o3: { x: 330, y: 156, w: 330, h: 36, t: "Change defence config (before freeze)", col: 1, src: "need(token, \"blue_participant\", \"operator\") in POST /defence-config; the lifecycle gate refuses after freeze" },
    o8: { x: 330, y: 214, w: 330, h: 36, t: "In-memory tamper test", col: 1, src: "need(token, \"reviewer\", \"operator\") in POST /tamper-test; the stored log is unchanged" },
    o4: { x: 330, y: 272, w: 330, h: 36, t: "Read secret config digests", col: 1, src: "GET /api/runs/{id}: digests shown to operator and reviewer, to others only after RELEASED" },
    o5: { x: 330, y: 330, w: 330, h: 36, t: "Release a sealed run", col: 1, src: "POST /release: reviewer only; any other role is refused and logged as policy.denied" },
    o7: { x: 330, y: 388, w: 330, h: 36, t: "Read the evidence report", col: 1, src: "GET /evidence: reviewer, or anyone after RELEASED" },
    o6: { x: 330, y: 446, w: 330, h: 36, t: "Read sealed artifacts", col: 1, src: "GET /artifacts: reviewer and participants, only when RELEASED; otherwise refused and logged" },
    o9: { x: 330, y: 528, w: 330, h: 36, t: "Submit attacks through the mailbox", col: 1, src: "Broker: commit-then-reveal per attack, identity bound to the mailbox" },
    o10: { x: 330, y: 586, w: 330, h: 36, t: "Mailbox: verdicts, artifacts, release", col: 1, src: "Broker refuses read_artifact, get_verdicts, release_results from red and logs each refusal" },
    r7: { x: 760, y: 40, w: 220, h: 36, t: "Monitoring stream", col: 2, s: "" },
    r1: { x: 760, y: 112, w: 220, h: 36, t: "Run lifecycle", col: 2 },
    r2: { x: 760, y: 184, w: 220, h: 36, t: "Defence config", col: 2 },
    r6: { x: 760, y: 256, w: 220, h: 36, t: "Audit log", col: 2 },
    r3: { x: 760, y: 328, w: 220, h: 36, t: "Manifest digests", col: 2 },
    r5: { x: 760, y: 400, w: 220, h: 36, t: "Evidence report", col: 2 },
    r4: { x: 760, y: 472, w: 220, h: 36, t: "Sealed result store", col: 2 },
    r8: { x: 760, y: 560, w: 220, h: 36, t: "Broker mailbox", col: 2 },
  },
  edges: [
    { a: "observer", b: "o1", k: "allow", why: "Any caller, no token needed." },
    { a: "operator", b: "o2", k: "allow", why: "Operator only." },
    { a: "operator", b: "o3", k: "allow", why: "Before freeze." },
    { a: "operator", b: "o8", k: "allow", why: "Operator or reviewer." },
    { a: "operator", b: "o4", k: "allow", why: "Operator or reviewer, any state." },
    { a: "reviewer", b: "o8", k: "allow", why: "Reviewer or operator." },
    { a: "reviewer", b: "o4", k: "allow", why: "Operator or reviewer, any state." },
    { a: "reviewer", b: "o5", k: "allow", why: "Only the reviewer; release verifies first." },
    { a: "reviewer", b: "o7", k: "allow", why: "Reviewer at any time." },
    { a: "reviewer", b: "o6", k: "cond", why: "Only after RELEASED." },
    { a: "blue_p", b: "o3", k: "allow", why: "Before freeze; the gate refuses afterwards." },
    { a: "blue_p", b: "o4", k: "deny", why: "Digests omitted from the response before release (not logged)." },
    { a: "blue_p", b: "o6", k: "cond", why: "Only after RELEASED; earlier reads are refused and logged." },
    { a: "red_p", b: "o5", k: "deny", why: "Refused (HTTP 403) and logged as policy.denied." },
    { a: "red_p", b: "o6", k: "cond", why: "Only after RELEASED; earlier reads are refused and logged." },
    { a: "observer", b: "o6", k: "deny", why: "Never: refused and logged with reason \"no identity\"." },
    { a: "red_sb", b: "o9", k: "allow", why: "The sandbox's only channel." },
    { a: "red_sb", b: "o10", k: "deny", why: "Refused by the broker and logged (5 forbidden requests per run)." },
    { a: "o1", b: "r7", k: "acts" }, { a: "o1", b: "r6", k: "acts" }, { a: "o2", b: "r1", k: "acts" }, { a: "o3", b: "r2", k: "acts" },
    { a: "o8", b: "r6", k: "acts" }, { a: "o4", b: "r3", k: "acts" }, { a: "o5", b: "r1", k: "acts" }, { a: "o5", b: "r6", k: "acts" },
    { a: "o7", b: "r5", k: "acts" }, { a: "o6", b: "r4", k: "acts" }, { a: "o9", b: "r8", k: "acts" }, { a: "o10", b: "r4", k: "acts" },
  ],
};
const EDGE_KINDS = {
  topology: [["allow", "Authorised", "var(--e-allow)"], ["deny", "Prohibited", "var(--e-deny)"], ["audit", "Audited", "var(--e-audit)"], ["trust", "Trusted dependency", "var(--e-trust)"]],
  hierarchy: [["allow", "Allowed", "var(--e-allow)"], ["cond", "After release", "var(--e-audit)"], ["deny", "Refused or withheld", "var(--e-deny)"], ["acts", "Acts on", "var(--ink2)"]],
  timeline: [["denied", "Denied", "var(--s-deny)"], ["allowed", "Allowed", "var(--s-allow)"], ["checkpoint", "Signed checkpoints", "var(--ochre)"], ["info", "Other events", "var(--ink)"]],
};
const VIEWS = {
  topology: { t: "Topology", note: "The active trust-boundary architecture. Solid lines are the only paths that exist; dashed red lines are paths the system refuses. Select a component to see what it may and may not do." },
  hierarchy: { t: "Hierarchy", note: "Actors, the operations the control plane and broker allow them, and the resources those operations touch. Derived from the role checks in aegis/api.py at this commit." },
  timeline: { t: "Timeline", note: "Recorded security events of one run in audit order: one dot per monitoring event, a lane per actor, dashed lines at lifecycle transitions. Select an event to see its causal neighbours." },
};
PAGES.connections = { render: connections, sync: (q) => { if ((q.view || "topology") !== S.conn.view || (q.run && q.run !== S.conn.run)) return connections(q); } };
async function connections(q) {
  const C = S.conn;
  C.view = VIEWS[q.view] ? q.view : "topology";
  if (q.node) C.sel[C.view] = q.node;
  if (!C.off[C.view]) C.off[C.view] = {};
  if (!S.status) await refreshStatus();
  band({ placeholder: C.view === "timeline" ? "Find an event, actor or summary" : "Find a component, role or operation", value: C.search, onSearch: (v) => { C.search = v; markSearch(); } });
  if (C.view === "topology") C.obs = await get("/api/lab/results?limit=50").catch(() => []);
  if (C.view === "timeline") {
    await loadRuns();
    C.run = q.run && S.runs.some((r) => r.id === q.run) ? q.run : (S.runs[0] || {}).id || null;
    C.events = C.run ? (await get(`/api/lab/timeline?limit=1500&run_id=${encodeURIComponent(C.run)}`).catch(() => [])).slice().sort((a, b) => (a.seq ?? 0) - (b.seq ?? 0) || a.ts - b.ts) : [];
  }
  render(`
    <nav class="persp" aria-label="Perspective">${Object.entries(VIEWS).map(([k, v]) => `<a href="${href("connections", { view: k })}" ${k === C.view ? 'aria-current="page"' : ""}><span ${k === C.view ? 'class="ringed" data-ring="1"' : ""}>${v.t}</span></a>`).join("")}</nav>
    <p class="persp-note">${esc(VIEWS[C.view].note)}</p>
    <div class="kinds" id="kinds"></div>
    <div class="gwrap"><div class="gframe" id="gframe"></div><aside class="gside" id="gside" aria-live="polite" aria-label="Selection details"></aside></div>`);
  drawKinds(); drawGraph();
}
function graphData() {
  const C = S.conn;
  if (C.view === "topology") return TOPO;
  if (C.view === "hierarchy") return HIER;
  return null;
}
function drawKinds() {
  const C = S.conn, off = C.off[C.view], kinds = EDGE_KINDS[C.view];
  const count = (k) => C.view === "timeline" ? C.events.filter((e) => evClass(e) === k).length : graphData().edges.filter((e) => e.k === k).length;
  const total = C.view === "timeline" ? C.events.length : graphData().edges.length;
  const anyOff = kinds.some(([k]) => off[k]);
  $("#kinds").innerHTML = `<button type="button" class="chip kind${anyOff ? " off" : ""}" data-kind="all" aria-pressed="${!anyOff}" style="--fc:var(--ink)">All</button>
    ${kinds.map(([k, t, c]) => `<button type="button" class="chip kind${off[k] ? " off" : ""}" data-kind="${k}" aria-pressed="${!off[k]}" style="--fc:${c}">${t} ${count(k)}</button>`).join("")}
    ${C.view === "timeline" ? `<label class="field" style="flex-direction:row;align-items:center;gap:8px">Run <select id="tl-run">${S.runs.map((r) => `<option ${r.id === C.run ? "selected" : ""}>${esc(r.id)}</option>`).join("")}</select></label>` : ""}
    ${C.view === "topology" ? `<button type="button" class="chip kind obs${C.showObs ? "" : " off"}" id="obs-toggle" aria-pressed="${C.showObs}" style="--fc:var(--s-pass)">Observed ${Object.keys(obsLatest()).length}</button>` : ""}
    <span class="total">${C.view === "timeline" ? "Events" : "Paths"}: ${total}</span>`;
  $$("#kinds [data-kind]").forEach((b) => b.addEventListener("click", () => {
    const k = b.dataset.kind;
    if (k === "all") C.off[C.view] = {};
    else if (!anyOff) { C.off[C.view] = Object.fromEntries(kinds.map(([x]) => [x, x !== k])); }
    else { off[k] = !off[k]; if (kinds.every(([x]) => C.off[C.view][x])) C.off[C.view] = {}; }
    drawKinds(); applyKinds();
  }));
  const ot = $("#obs-toggle");
  if (ot) ot.addEventListener("click", () => { C.showObs = !C.showObs; drawKinds(); drawGraph(); });
  const tr = $("#tl-run");
  if (tr) tr.addEventListener("change", () => { setQuery({ run: tr.value, node: null }); C.sel.timeline = null; connections({ view: "timeline", run: tr.value }); });
}
function applyKinds() {
  const off = S.conn.off[S.conn.view];
  $$("#gframe [data-kind]").forEach((g) => g.classList.toggle("hide", !!off[g.dataset.kind]));
}
const anchorPt = (n, side, o = 0) => ({ r: [n.x + n.w, n.y + n.h / 2 + o], l: [n.x, n.y + n.h / 2 + o], t: [n.x + n.w / 2 + o, n.y], b: [n.x + n.w / 2 + o, n.y + n.h] }[side]);
function edgeGeom(e, N) {
  if (e.d) return { d: e.d, m: e.m };
  const A = N[e.a], Bn = N[e.b];
  let p, q, horiz = true;
  if (Bn.x >= A.x + A.w - 1) { p = anchorPt(A, "r", e.ao); q = anchorPt(Bn, "l", e.bo); }
  else if (Bn.x + Bn.w <= A.x + 1) { p = anchorPt(A, "l", e.ao); q = anchorPt(Bn, "r", e.bo); }
  else { horiz = false; const down = Bn.y > A.y; p = anchorPt(A, down ? "b" : "t", e.ao); q = anchorPt(Bn, down ? "t" : "b", e.bo); }
  const f = (n) => n.toFixed(1);
  if (horiz) { const mx = (p[0] + q[0]) / 2; return { d: `M${f(p[0])} ${f(p[1])} C${f(mx)} ${f(p[1])} ${f(mx)} ${f(q[1])} ${f(q[0])} ${f(q[1])}`, m: [mx, (p[1] + q[1]) / 2] }; }
  const my = (p[1] + q[1]) / 2;
  return { d: `M${f(p[0])} ${f(p[1])} C${f(p[0])} ${f(my)} ${f(q[0])} ${f(my)} ${f(q[0])} ${f(q[1])}`, m: [(p[0] + q[0]) / 2, my] };
}
function boxesSVG(G) {
  const N = G.nodes;
  const kindColor = { allow: "var(--e-allow)", deny: "var(--e-deny)", audit: "var(--e-audit)", trust: "var(--e-trust)", cond: "var(--e-audit)", acts: "var(--ink2)" };
  const markers = Object.entries(kindColor).map(([k, c]) => `<marker id="ar-${k}" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="7" markerHeight="7" orient="auto-start-reverse"><path d="M0 0 L10 5 L0 10 z" style="fill:${c}"/></marker>`).join("");
  const edges = G.edges.map((e, i) => {
    const g = edgeGeom(e, N), kcls = e.k === "cond" ? "audit" : e.k === "acts" ? "acts" : e.k;
    const x = e.k === "deny" ? `<path class="x" d="M${g.m[0] - 5} ${g.m[1] - 5} l10 10 M${g.m[0] + 5} ${g.m[1] - 5} l-10 10"/>` : "";
    const lab = e.l ? `<text x="${(g.m[0] + (e.lx || 0)).toFixed(1)}" y="${(g.m[1] + (e.ly || -6)).toFixed(1)}" text-anchor="middle">${esc(e.l)}</text>` : "";
    const ob = G === TOPO && S.conn.showObs ? obsFor(e.a, e.b) : [];
    const okAll = ob.every((o) => o.r.verdict === "PASS");
    const om = ob.length ? `<g class="obsmark ${okAll ? "pass" : "fail"}"><circle cx="${(g.m[0] + 14).toFixed(1)}" cy="${(g.m[1] + 12).toFixed(1)}" r="8"/><text x="${(g.m[0] + 14).toFixed(1)}" y="${(g.m[1] + 15.5).toFixed(1)}" text-anchor="middle">${okAll ? "✓" : "!"}</text><title>${esc(ob.map((o) => `Observed: ${OBS_TITLE[o.sid]} ${o.r.verdict} (${o.r.run_id || "no run"})`).join("; "))}</title></g>` : "";
    return `<g class="edge ${kcls}${ob.length ? " obs" : ""}" data-kind="${e.k}" data-e="${i}" data-a="${e.a}" data-b="${e.b}" ${kcls === "acts" ? 'style="--kc:var(--ink2)"' : ""}><path d="${g.d}" ${e.k === "deny" ? "" : `marker-end="url(#ar-${e.k})"`}/>${x}${lab}${om}</g>`;
  }).join("");
  const nodes = Object.entries(N).map(([k, n]) => {
    const two = !!n.s;
    return `<g class="node ${n.cls || ""}" data-k="${k}" data-cx="${n.x + n.w / 2}" data-cy="${n.y + n.h / 2}" tabindex="-1" role="button" aria-pressed="false" aria-label="${esc(n.t + (n.s ? ", " + n.s : ""))}" ${n.mc ? `style="--mc:${n.mc}"` : ""}>
      <rect class="box" x="${n.x}" y="${n.y}" width="${n.w}" height="${n.h}" rx="8"/>${n.cls === "trusted" ? `<rect class="inner" x="${n.x + 4}" y="${n.y + 4}" width="${n.w - 8}" height="${n.h - 8}" rx="5"/>` : ""}
      ${n.mc ? `<rect class="bar" x="${n.x + 1}" y="${n.y + 1}" width="6" height="${n.h - 2}" rx="2"/>` : ""}
      <text x="${n.x + (n.mc ? 18 : 14)}" y="${n.y + (two ? n.h / 2 - 3 : n.h / 2 + 4.5)}">${esc(n.t)}</text>
      ${two ? `<text class="sub" x="${n.x + (n.mc ? 18 : 14)}" y="${n.y + n.h / 2 + 13}">${esc(n.s)}</text>` : ""}</g>`;
  }).join("");
  const zones = (G.zones || []).map((z) => `<g class="zone"><rect x="${z.x}" y="${z.y}" width="${z.w}" height="${z.h}" rx="12"/><text x="${z.x + 12}" y="${z.y + 18}">${esc(z.t)}</text></g>`).join("");
  const heads = (G.heads || []).map(([x, t]) => `<text class="colhead" x="${x}" y="22">${esc(t)}</text>`).join("");
  return `<defs>${markers}</defs>${zones}${heads}<g class="edges">${edges}</g><g class="nodes">${nodes}</g>`;
}
const evClass = (e) => (e.type === "audit.checkpoint" || e.type === "audit.terminal" ? "checkpoint" : { denied: "denied", ok: "allowed", allowed: "allowed", failed: "denied", alert: "denied" }[decisionOf(e)] || "info");
const LANES = ["operator", "reviewer", "observer", "blue_participant", "red_participant", "control-plane", "broker", "red-sandbox", "defence-runner", "model-worker"];
function timelineSVG(evs) {
  const actors = Array.from(new Set(evs.map((e) => e.actor))).sort((a, b) => (LANES.indexOf(a) + 99 * (LANES.indexOf(a) < 0)) - (LANES.indexOf(b) + 99 * (LANES.indexOf(b) < 0)));
  const x0 = 170, step = Math.max(16, Math.min(30, 760 / Math.max(1, evs.length))), y0 = 76, lh = 42;
  const W = Math.max(940, x0 + evs.length * step + 40), H = y0 + actors.length * lh + 60;
  const X = (i) => x0 + i * step + step / 2, Y = (a) => y0 + actors.indexOf(a) * lh;
  const lanes = actors.map((a) => `<g class="lane"><line x1="${x0 - 10}" x2="${W - 20}" y1="${Y(a)}" y2="${Y(a)}"/><text x="${x0 - 18}" y="${Y(a) + 4}" text-anchor="end">${esc(a)}</text></g>`).join("");
  let lastX = -1e9, row = 0;
  const phases = evs.map((e, i) => {
    if (!/^run\.(created|frozen|sealed|released|failed)$/.test(e.type)) return "";
    row = X(i) - lastX < 72 ? 1 - row : 0; lastX = X(i);
    return `<g class="phase"><line x1="${X(i)}" x2="${X(i)}" y1="${40 - row * 16}" y2="${H - 40}"/><text x="${X(i) + 4}" y="${36 - row * 16}">${esc(e.type.slice(4))}</text></g>`;
  }).join("");
  const ticks = evs.map((e, i) => (i % Math.max(1, Math.round(5 * 22 / step)) === 0 ? `<text x="${X(i)}" y="${H - 18}" text-anchor="middle">#${e.seq ?? "–"}</text>` : "")).join("");
  const dots = evs.map((e, i) => `<g class="dot ${evClass(e)}" data-kind="${evClass(e)}" data-k="${i}" data-cx="${X(i)}" data-cy="${Y(e.actor)}" tabindex="-1" role="button" aria-pressed="false" aria-label="${esc(`#${e.seq ?? "–"} ${e.type} by ${e.actor}: ${e.summary}`)}"><circle cx="${X(i)}" cy="${Y(e.actor)}" r="6.5"/></g>`).join("");
  return { w: W, h: H, svg: `${lanes}${phases}<g class="axis"><line x1="${x0 - 10}" x2="${W - 20}" y1="${H - 36}" y2="${H - 36}"/>${ticks}<text x="${x0 - 18}" y="${H - 18}" text-anchor="end">audit seq</text></g>${dots}` };
}
function drawGraph() {
  const C = S.conn, frame = $("#gframe");
  if (S.conn.pz) S.conn.pz = null;
  let w, h, inner;
  if (C.view === "timeline") {
    if (!C.events.length) {
      frame.innerHTML = `<div class="empty" style="margin:40px;border:0"><div class="ring-plus">${icon("plus", "md")}</div><strong>No recorded events to show</strong>${S.runs.length ? "This run has no monitoring events yet." : `Start a run in the <a href="#/lab?open=run">lab</a> and its events appear here.`}</div>`;
      $("#gside").innerHTML = `<p class="muted">Nothing selected.</p>`;
      return;
    }
    ({ w, h, svg: inner } = timelineSVG(C.events));
  } else { const G = graphData(); w = G.w; h = G.h; inner = boxesSVG(G); }
  const foot = C.view === "topology" ? `All components run on one Linux host and share its kernel. Lines are the static architecture at this commit; ${C.showObs ? "a ✓ marks a path a recorded scenario of this console exercised (select a node for the run and audit entries), not a packet trace." : "observed marks are hidden."}`
    : C.view === "hierarchy" ? "Static description of the role checks in aegis/api.py and the broker's mailbox policy; the Lab runs them live."
    : `Run ${C.run}: ${C.events.length} monitoring events. Grey lane lines are actors; colour is the recorded decision.`;
  frame.innerHTML = `<div class="gtools">
      <label class="switch"><input type="checkbox" id="g-text" ${C.text ? "checked" : ""}> Text view</label>
      <span class="zoom" role="group" aria-label="Zoom"><button type="button" data-z="out" aria-label="Zoom out">${icon("minus")}</button><button type="button" data-z="in" aria-label="Zoom in">${icon("plus")}</button></span>
      <button class="roundbtn" type="button" data-z="reset" aria-label="Reset view" title="Reset view">${icon("reset")}</button></div>
    ${C.text ? `<div class="gtext" id="gtext">${graphText()}</div>` : `<svg class="g" id="gsvg" viewBox="0 -48 ${w} ${h + 48}" preserveAspectRatio="xMidYMid meet" role="group" aria-roledescription="graph" aria-label="${esc(VIEWS[C.view].t)} graph. Arrow keys move between items, Enter selects, plus and minus zoom. A text view is available." tabindex="-1"><g id="glayer">${inner}</g></svg>`}
    <div class="gfoot"><span>${esc(foot)} ${C.text ? "" : "Drag to pan; Ctrl + scroll or pinch to zoom."}</span></div>`;
  $("#g-text").addEventListener("change", (e) => { C.text = e.target.checked; drawGraph(); });
  frame.toggleAttribute("tabindex", false);
  if (C.text) { $$("[data-z]", frame).forEach((b) => (b.disabled = true)); bindTextView(); selectItem(curSel(), { quiet: true }); return; }
  const svg = $("#gsvg"), pz = (C.pz = panZoom(frame, svg, $("#glayer")));
  $$("[data-z]", frame).forEach((b) => b.addEventListener("click", () => pz[b.dataset.z]()));
  svg.addEventListener("click", (e) => { const g = e.target.closest("[data-k]"); if (g) selectItem(g.dataset.k); });
  svg.addEventListener("keydown", (e) => graphKeys(e, svg, pz));
  applyKinds(); markSearch();
  const k = curSel();
  selectItem(k, { quiet: true });
  if (frame.clientWidth < 640) { const g = $(`[data-k="${CSS.escape(String(k))}"]`, svg); if (g) pz.focusOn(+g.dataset.cx, +g.dataset.cy, C.view === "timeline" ? 1.6 : 1.9); }
}
function curSel() {
  const C = S.conn, s = C.sel[C.view];
  if (C.view === "timeline") { const i = s != null && C.events[+s] ? +s : C.events.findIndex((e) => evClass(e) === "denied"); return String(i < 0 ? 0 : i); }
  const N = graphData().nodes;
  return N[s] ? s : C.view === "topology" ? "broker" : "reviewer";
}
function selectItem(k, { quiet } = {}) {
  const C = S.conn; k = String(k);
  C.sel[C.view] = k;
  if (!quiet) setQuery({ node: k });
  const svg = $("#gsvg");
  if (svg) {
    $$("[data-k]", svg).forEach((g) => { const on = g.dataset.k === k; g.classList.toggle("sel", on); g.setAttribute("aria-pressed", String(on)); g.setAttribute("tabindex", on ? "0" : "-1"); });
    svg.classList.add("focus");
    if (C.view !== "timeline") {
      const near = new Set();
      $$(".edge", svg).forEach((e) => { const hot = e.dataset.a === k || e.dataset.b === k; e.classList.toggle("hot", hot); if (hot) { near.add(e.dataset.a); near.add(e.dataset.b); } });
      $$(".node", svg).forEach((g) => g.classList.toggle("near", near.has(g.dataset.k)));
    }
  }
  $$("#gtext tr[data-k]").forEach((tr) => tr.classList.toggle("sel", tr.dataset.k === k));
  $("#gside").innerHTML = C.view === "timeline" ? eventSide(+k) : C.view === "topology" ? topoSide(k) : hierSide(k);
  $$("#gside [data-go]").forEach((b) => b.addEventListener("click", () => { selectItem(b.dataset.go); const g = $(`#gsvg [data-k="${CSS.escape(b.dataset.go)}"]`); if (g) g.focus({ preventScroll: true }); }));
}
function edgeRows(G, k) {
  const names = EDGE_KINDS[S.conn.view].reduce((a, [x, t, c]) => ((a[x] = [t, c]), a), {});
  return G.edges.filter((e) => e.a === k || e.b === k).map((e) => {
    const out = e.a === k, other = G.nodes[out ? e.b : e.a], [kt, kc] = names[e.k];
    return { btn: `data-go="${out ? e.b : e.a}"`, icon: out ? "right" : "left", color: kc, title: other.t, sub: `${kt}${e.l ? " · " + e.l : ""}${e.why ? " — " + e.why : ""}` };
  });
}
function topoSide(k) {
  const n = TOPO.nodes[k], st = S.status || {};
  const flags = n.flags && st.hardening_flags ? st.hardening_flags[n.flags] : null;
  const list = (t, xs) => (xs && xs.length ? `<p class="lbl">${t}</p><ul class="dash">${xs.map((x) => `<li>${esc(x)}</li>`).join("")}</ul>` : "");
  return `<p class="lbl">${n.cls === "trusted" ? "Trusted component" : n.cls === "out" ? "Outside the sandboxes" : "Component"}</p><h3>${esc(n.t)}</h3><p class="sub">${esc(n.s)}</p><p>${esc(n.role)}</p>
    <p class="lbl">Trust assumption</p><p class="${n.cls === "trusted" ? "st warn" : ""}" style="font-weight:400">${esc(n.trust)}</p>
    ${list("Permitted", n.allow)}${list("Denied", n.deny)}${list("Security controls", n.controls)}
    ${flags ? `<p class="lbl">Flags this host applies</p><div class="cmd">podman run ${esc(flags.join(" "))}</div>${st.podman && st.podman.available && !st.podman.cpuset_delegated ? `<p class="tiny st warn" style="font-weight:400">cpuset pinning is not applied: the controller is not delegated to rootless users on this host.</p>` : ""}` : ""}
    <p class="lbl">Connections</p>${linkRows(edgeRows(TOPO, k))}
    ${obsSide(k)}
    ${n.test && n.test.length ? `<p class="lbl">Supporting evidence</p>${linkRows(n.test.map((t) => { const c = CATALOG.find((x) => x.id === t); return { href: "#/lab?open=" + t, title: c ? c.title || (S.lab.scenarios || []).find((s) => s.id === t)?.title || t : t, sub: c ? LAB_TYPE[c.kind] : "", icon: "right" }; }))}` : ""}`;
}
function obsSide(k) {
  const rows = [];
  TOPO.edges.filter((e) => e.a === k || e.b === k).forEach((e) => obsFor(e.a, e.b).forEach((o) => rows.push({ e, ...o })));
  if (!rows.length) return `<p class="lbl">Observed in this console</p><p class="small muted">No recorded scenario has exercised a path of this component yet.</p>`;
  return `<p class="lbl">Observed in this console ${labelTag(rows.some((o) => o.sid === "sandbox-containment") ? "sandbox" : "live")}</p><ul class="dash">${rows.map((o) => {
    const seqs = (o.r.steps || []).map((s) => s.audit && s.audit.seq).filter(Boolean);
    return `<li class="small"><span class="st ${o.r.verdict === "PASS" ? "pass" : "fail"}">${esc(o.r.verdict)}</span> ${esc(OBS_TITLE[o.sid])}: ${esc(o.what)}.<br><span class="tiny">${esc(TOPO.nodes[o.e.a].t)} → ${esc(TOPO.nodes[o.e.b].t)} · ${o.r.run_id ? esc(o.r.run_id) + " · " : ""}${when(o.r.finished_at)}${seqs.length ? " · audit #" + seqs.join(", #") : ""}</span>
      <br>${o.sid === "tamper" ? `<a href="${href("evidence", { open: o.r.bundle ? o.r.bundle.id : "" })}">Open the bundle</a>` : `<a href="${href("lab", { open: o.sid })}">Open the result</a>`}${o.r.run_id && o.sid !== "sandbox-containment" && o.sid !== "tamper" ? ` · <a href="${href("audit", { src: "log", run: o.r.run_id })}">audit log</a>` : ""}</li>`;
  }).join("")}</ul>`;
}
function hierSide(k) {
  const n = HIER.nodes[k];
  const col = ["Actor", "Operation", "Resource"][n.col];
  return `<p class="lbl">${col}</p><h3>${esc(n.t)}</h3>${n.s ? `<p class="sub">${esc(n.s)}</p>` : ""}
    ${n.src ? `<p class="lbl">Where it is enforced</p><p class="small">${esc(n.src)}</p>` : ""}
    <p class="lbl">Connections</p>${linkRows(edgeRows(HIER, k))}
    <p class="tiny mt">Static description at this commit. Live proof: the Lab's prohibited-access and cross-role scenarios, and the access matrix in evidence/validation_2026-10-22/isolation_matrix.json.</p>`;
}
function eventSide(i) {
  const evs = S.conn.events, e = evs[i];
  if (!e) return `<p class="muted">Nothing selected.</p>`;
  const nb = [];
  for (let j = Math.max(0, i - 3); j <= Math.min(evs.length - 1, i + 3); j++) if (j !== i) nb.push(j);
  return `<p class="lbl">Event #${e.seq ?? "–"} · ${esc(e.run_id)}</p><h3>${esc(e.type)}</h3><p class="sub">${esc(e.actor)} · ${when(e.ts)}</p><p>${esc(e.summary)}</p>
    <ul class="ledger"><li><span class="k">Decision</span><span class="v">${decTag(decisionOf(e))}</span></li>
      <li><span class="k">Signature</span><span class="v">${e.post_terminal ? "After the signed chain closed (post_terminal.jsonl, unsigned)" : e.signed ? `<span class="st pass">Covered by a signed checkpoint</span>` : "Not yet covered by a signed checkpoint"}</span></li></ul>
    <p class="lbl">Causal sequence</p>${linkRows(nb.map((j) => ({ btn: `data-go="${j}"`, icon: j < i ? "up" : "down", color: DEC_COLOR[decisionOf(evs[j])] || "var(--ink)", title: `#${evs[j].seq ?? "–"} ${evs[j].type}`, sub: `${evs[j].actor} · ${evs[j].summary}` })))}
    <p class="mt"><a href="${href("audit", { run: e.run_id, open: evKey(e) })}">Open in the audit archive</a></p>`;
}
function graphText() {
  const C = S.conn;
  if (C.view === "timeline") return `<h3>Events of ${esc(C.run)} in audit order</h3><div class="table-wrap"><table><thead><tr><th>Seq</th><th>Actor</th><th>Event</th><th>Decision</th><th>Summary</th></tr></thead><tbody>${C.events.map((e, i) => `<tr class="click" tabindex="0" data-k="${i}"><td>${e.seq ?? "—"}</td><td class="nw">${esc(e.actor)}</td><td class="nw">${esc(e.type)}</td><td>${decTag(decisionOf(e))}</td><td>${esc(e.summary)}</td></tr>`).join("")}</tbody></table></div>`;
  const G = graphData(), names = EDGE_KINDS[C.view].reduce((a, [x, t]) => ((a[x] = t), a), {});
  return `<h3>${C.view === "topology" ? "Components" : "Actors, operations and resources"}</h3><div class="table-wrap"><table><thead><tr><th>Name</th><th>${C.view === "topology" ? "Role" : "Kind"}</th></tr></thead><tbody>${Object.entries(G.nodes).map(([k, n]) => `<tr class="click" tabindex="0" data-k="${k}"><td class="nw">${esc(n.t)}</td><td>${esc(C.view === "topology" ? n.s : ["Actor", "Operation", "Resource"][n.col])}</td></tr>`).join("")}</tbody></table></div>
    <h3 class="mt">${C.view === "topology" ? "Paths" : "Relations"}</h3><div class="table-wrap"><table><thead><tr><th>From</th><th>To</th><th>Kind</th><th>Meaning</th></tr></thead><tbody>${G.edges.filter((e) => !C.off[C.view][e.k]).map((e) => `<tr><td class="nw">${esc(G.nodes[e.a].t)}</td><td class="nw">${esc(G.nodes[e.b].t)}</td><td class="nw">${esc(names[e.k])}</td><td>${esc((e.l ? e.l + ". " : "") + (e.why || ""))}</td></tr>`).join("")}</tbody></table></div>`;
}
function bindTextView() {
  $$("#gtext tr[data-k]").forEach((tr) => {
    tr.addEventListener("click", () => selectItem(tr.dataset.k));
    tr.addEventListener("keydown", (e) => { if (e.key === "Enter" || e.key === " ") { e.preventDefault(); selectItem(tr.dataset.k); } });
  });
  wrapTables($("#gtext"));
}
function markSearch() {
  const svg = $("#gsvg"), q = S.conn.search;
  if (!svg) return;
  svg.classList.toggle("searching", !!q);
  $$("[data-k]", svg).forEach((g) => g.classList.toggle("match", !!q && textMatch(q, g.getAttribute("aria-label"))));
  const first = q && $("[data-k].match", svg);
  if (first && S.conn.pz) S.conn.pz.focusOn(+first.dataset.cx, +first.dataset.cy, Math.max(S.conn.pz.st.k, 1.4));
}
function graphKeys(e, svg, pz) {
  if (e.key === "+" || e.key === "=") { e.preventDefault(); pz.in(); return; }
  if (e.key === "-" || e.key === "_") { e.preventDefault(); pz.out(); return; }
  if (e.key === "0") { e.preventDefault(); pz.reset(); return; }
  const g = e.target.closest("[data-k]");
  if (!g) return;
  if (e.key === "Enter" || e.key === " ") { e.preventDefault(); selectItem(g.dataset.k); return; }
  const dir = { ArrowRight: [1, 0], ArrowLeft: [-1, 0], ArrowDown: [0, 1], ArrowUp: [0, -1] }[e.key];
  if (!dir) return;
  e.preventDefault();
  const cx = +g.dataset.cx, cy = +g.dataset.cy;
  let best = null, bs = Infinity;
  $$("[data-k]", svg).forEach((o) => {
    if (o === g || o.classList.contains("hide")) return;
    const dx = +o.dataset.cx - cx, dy = +o.dataset.cy - cy, along = dx * dir[0] + dy * dir[1];
    if (along <= 2) return;
    const s = along + Math.abs(dx * dir[1] - dy * dir[0]) * 2.2;
    if (s < bs) { bs = s; best = o; }
  });
  if (best) { $$("[data-k]", svg).forEach((o) => o.setAttribute("tabindex", o === best ? "0" : "-1")); best.focus(); }
}
function panZoom(frame, svg, layer) {
  const st = { k: 1, x: 0, y: 0 }, vb = svg.viewBox.baseVal;
  const apply = () => layer.setAttribute("transform", `translate(${st.x.toFixed(2)} ${st.y.toFixed(2)}) scale(${st.k.toFixed(4)})`);
  const toSvg = (cx, cy) => { const m = svg.getScreenCTM(); return m ? new DOMPoint(cx, cy).matrixTransform(m.inverse()) : { x: (vb.x + vb.width / 2), y: (vb.y + vb.height / 2) }; };
  const zoomAt = (f, x, y) => { const k = Math.min(5, Math.max(0.5, st.k * f)), r = k / st.k; st.x = x - (x - st.x) * r; st.y = y - (y - st.y) * r; st.k = k; apply(); };
  const api = {
    st, moved: false,
    in: () => zoomAt(1.3, (vb.x + vb.width / 2), (vb.y + vb.height / 2)), out: () => zoomAt(1 / 1.3, (vb.x + vb.width / 2), (vb.y + vb.height / 2)),
    reset: () => { st.k = 1; st.x = 0; st.y = 0; apply(); },
    focusOn: (x, y, k) => { st.k = k; st.x = (vb.x + vb.width / 2) - x * k; st.y = (vb.y + vb.height / 2) - y * k; apply(); },
  };
  svg.addEventListener("wheel", (e) => { if (!e.ctrlKey && !e.metaKey) return; e.preventDefault(); const p = toSvg(e.clientX, e.clientY); zoomAt(Math.exp(-e.deltaY * 0.0025), p.x, p.y); }, { passive: false });
  const ptrs = new Map(); let start = null, pinch = null;
  svg.addEventListener("pointerdown", (e) => {
    ptrs.set(e.pointerId, { x: e.clientX, y: e.clientY }); api.moved = false; start = { x: e.clientX, y: e.clientY };
    if (ptrs.size === 2) { const [a, b] = [...ptrs.values()]; pinch = Math.hypot(a.x - b.x, a.y - b.y); }
  });
  svg.addEventListener("pointermove", (e) => {
    const prev = ptrs.get(e.pointerId); if (!prev) return;
    ptrs.set(e.pointerId, { x: e.clientX, y: e.clientY });
    const m = svg.getScreenCTM(); if (!m) return;
    if (ptrs.size === 1) {
      if (!api.moved && Math.hypot(e.clientX - start.x, e.clientY - start.y) < 5) return;
      if (!api.moved) { api.moved = true; svg.setPointerCapture(e.pointerId); svg.classList.add("dragging"); }
      st.x += (e.clientX - prev.x) / m.a; st.y += (e.clientY - prev.y) / m.d; apply();
    } else if (ptrs.size === 2 && pinch) {
      api.moved = true;
      const [a, b] = [...ptrs.values()], d = Math.hypot(a.x - b.x, a.y - b.y), p = toSvg((a.x + b.x) / 2, (a.y + b.y) / 2);
      zoomAt(d / pinch, p.x, p.y); pinch = d;
    }
  });
  const up = (e) => { ptrs.delete(e.pointerId); if (ptrs.size < 2) pinch = null; if (!ptrs.size) svg.classList.remove("dragging"); };
  svg.addEventListener("pointerup", up); svg.addEventListener("pointercancel", up);
  svg.addEventListener("click", (e) => { if (api.moved) { e.stopPropagation(); e.preventDefault(); api.moved = false; } }, true);
  return api;
}

/* ================================================================ 4. audit archive */
const AUD_FACETS = [
  { key: "run", title: "Run", get: (e) => e.run_id },
  { key: "actor", title: "Actor or role", get: (e) => e.actor },
  { key: "type", title: "Event type", get: (e) => e.type },
  { key: "decision", title: "Decision", get: decisionOf, color: (v) => DEC_COLOR[v] || null },
  { key: "signed", title: "Signature", get: signedOf, order: ["signed", "pending", "after close"] },
];
const audSearch = () => S.audit.data.filter((e) => textMatch(S.audit.search, e.summary, e.type, e.actor, e.run_id, String(e.seq ?? "")));
PAGES.audit = { render: audit, open: auditOpen, sync: (q) => {
  if ((q.src === "log" ? "log" : "monitor") !== S.audit.src || (q.src === "log" && q.run && q.run !== S.audit.run)) { hideSheet(); teardown(); return audit(q); }
  if (S.audit.src === "monitor" && q.run && !(S.audit.f.sel.run && S.audit.f.sel.run.has(q.run))) { S.audit.f.sel.run = new Set([q.run]); drawAudit(); }
} };
const AUD_SRC = { monitor: "Monitoring stream", log: "Signed audit log" };
async function audit(q) {
  const A = S.audit;
  A.src = q.src === "log" ? "log" : "monitor";
  const persp = `<nav class="persp" aria-label="Source">${Object.entries(AUD_SRC).map(([k, t]) => `<a href="${href("audit", { src: k === "log" ? "log" : null, run: q.run || null })}" ${k === A.src ? 'aria-current="page"' : ""}><span ${k === A.src ? 'class="ringed" data-ring="1"' : ""}>${t}</span></a>`).join("")}</nav>`;
  if (A.src === "log") return auditLog(q, persp);
  if (q.run) A.f.sel = { ...A.f.sel, run: new Set([q.run]) };
  band({ placeholder: "Summaries, event types, actors", value: A.search, onSearch: (v) => { A.search = v; A.limit = 300; drawAudit(); },
    filter: filterCfg(AUD_FACETS, A.f, audSearch, () => { A.limit = 300; drawAudit(); }),
    sort: { label: () => (A.sort === "desc" ? "Newest" : "Oldest"), icon: () => (A.sort === "desc" ? "sortDesc" : "sortAsc"), onClick: () => { A.sort = A.sort === "desc" ? "asc" : "desc"; drawAudit(); } } });
  render(`${persp}<div class="intro"><p>The redacted monitoring stream of every run: who did what, and what the system decided. It carries no payloads, model outputs or defence rules, so any viewer may read it. Each entry's sequence number points into the run's hash-chained audit log (the other perspective).</p>${labelTag("live")}</div>
    <div class="meta-row"><span id="a-meta" role="status" aria-live="polite">Loading…</span><label class="switch"><input type="checkbox" id="a-live" ${A.live ? "checked" : ""}> Update every 2 s</label></div>
    <div id="a-table">${loading("Loading events…")}</div>`);
  $("#a-live").addEventListener("change", (e) => { A.live = e.target.checked; });
  $("#a-table").addEventListener("click", (e) => { const tr = e.target.closest("tr[data-key]"); if (tr) openKey(tr.dataset.key); const more = e.target.closest("[data-more]"); if (more) { A.limit = Infinity; drawAudit(); } });
  $("#a-table").addEventListener("keydown", (e) => { const tr = e.target.closest("tr[data-key]"); if (tr && (e.key === "Enter" || e.key === " ")) { e.preventDefault(); openKey(tr.dataset.key); } });
  await fetchAudit(true);
  every(2000, () => { if (A.live && !document.hidden) fetchAudit(); });
}
/* signed audit log: metadata of every entry of one run, filtered and paged on the server */
const LOG_PAGE = 100;
async function auditLog(q, persp) {
  const A = S.audit;
  band(null);
  await loadRuns();
  const lr = labRuns();
  A.run = q.run && lr.some((r) => r.id === q.run) ? q.run : (lr[0] || {}).id || null;
  render(`${persp}<div class="intro"><p>The run's hash-chained audit log, entry by entry: sequence, actor, operation, decision, the entry's hash and whether a signed checkpoint covers it. Metadata only: payloads, model outputs, defence rules and the digests of team inputs never leave the server; attack outcomes appear once the run is released.</p>${labelTag("live")}</div>
    ${canAct() ? "" : `<div class="note">${esc(NO_SESSION)} The signed log is readable only in the operator session; the monitoring stream stays public.</div>`}
    <div class="row" id="l-filters"></div>
    <div class="meta-row"><span id="l-meta" role="status" aria-live="polite"></span><label class="switch"><input type="checkbox" id="l-live" ${A.live ? "checked" : ""}> Update every 2 s</label></div>
    <div id="l-table">${A.run ? loading("Reading the audit log…") : `<div class="empty"><strong>No lab run yet</strong><a href="#/lab">Create one in the lab</a>; its audit log appears here.</div>`}</div>`);
  if (!A.run || !canAct()) { if (A.run && !canAct()) $("#l-table").innerHTML = ""; return; }
  $("#l-live").addEventListener("change", (e) => { A.live = e.target.checked; });
  $("#l-table").addEventListener("click", (e) => {
    const tr = e.target.closest("tr[data-key]"); if (tr) openKey(tr.dataset.key);
    const pg = e.target.closest("[data-page]"); if (pg) { A.off = Math.max(0, A.off + Number(pg.dataset.page) * LOG_PAGE); fetchLog(); }
  });
  $("#l-table").addEventListener("keydown", (e) => { const tr = e.target.closest("tr[data-key]"); if (tr && (e.key === "Enter" || e.key === " ")) { e.preventDefault(); openKey(tr.dataset.key); } });
  A.off = 0; A.log = null;
  await fetchLog(true);
  every(2000, () => { if (A.live && !document.hidden && A.off === 0) fetchLog(); });
}
async function fetchLog(first) {
  const A = S.audit;
  const qs = new URLSearchParams({ offset: A.off, limit: LOG_PAGE, order: "desc" });
  Object.entries(A.lf).forEach(([k, v]) => v && qs.set(k, v));
  try {
    const d = await get(`/api/lab/runs/${encodeURIComponent(A.run)}/audit?${qs}`);
    const sig = [d.total, d.matched, d.signed_upto, A.off].join(":");
    const changed = !A.log || sig !== A.logSig;
    A.log = d; A.logSig = sig;
    if (first || changed) drawLog();
    else $("#l-meta").textContent = $("#l-meta").textContent.replace(/updated .*/, "updated " + new Date().toLocaleTimeString());
  } catch (e) { const m = $("#l-meta"); if (m) m.innerHTML = `<span class="st fail">Could not read the audit log: ${esc(e.message)}</span> <span class="muted">(showing the last data received)</span>`; }
}
function drawLog() {
  const A = S.audit, d = A.log, el = $("#l-table"); if (!el || !d) return;
  const sel = (key, label, vals) => `<label class="field">${label}<select data-lf="${key}"><option value="">all</option>${vals.map((v) => `<option ${A.lf[key] === v ? "selected" : ""}>${esc(v)}</option>`).join("")}</select></label>`;
  $("#l-filters").innerHTML = `<label class="field">Run<select id="l-run">${labRuns().map((r) => `<option ${r.id === A.run ? "selected" : ""}>${esc(r.id)}</option>`).join("")}</select></label>
    ${sel("type", "Event type", d.facets.type)}${sel("actor", "Actor", d.facets.actor)}${sel("decision", "Decision", ["denied", "allowed", "failed", "ok", "info"])}`;
  $("#l-run").addEventListener("change", (e) => { setQuery({ run: e.target.value, open: null }); A.run = e.target.value; A.off = 0; A.lf = { type: "", actor: "", decision: "" }; fetchLog(true); });
  $$("[data-lf]").forEach((x) => x.addEventListener("change", () => { A.lf[x.dataset.lf] = x.value; A.off = 0; fetchLog(true); }));
  $("#l-meta").textContent = `${d.run_id} · ${d.state} · ${fmt(d.matched)} of ${fmt(d.total)} entries · signed up to #${d.signed_upto} by ${d.checkpoints} checkpoints${d.terminal_anchor ? " · terminal anchor written" : ""} · updated ${new Date().toLocaleTimeString()}`;
  const ac = d.after_close, late = ac && ac.seen ? `<div class="note mt"><b>${fmt(ac.seen)} event${ac.seen === 1 ? "" : "s"} after the signed chain closed</b> (${fmt(ac.recorded)} kept in post_terminal.jsonl). ${esc(ac.note)}
    ${ac.entries.length ? `<ul class="small">${ac.entries.slice(0, 5).map((e) => `<li>${clock(e.ts)} · ${esc(e.actor)} · ${esc(e.type)}${e.data.op ? " · " + esc([e.data.op, e.data.reason].filter(Boolean).join(": ")) : ""} · <span class="muted">unsigned</span></li>`).join("")}</ul>` : ""}</div>` : "";
  if (!d.entries.length) { el.innerHTML = `<div class="empty"><strong>No entry matches</strong>Clear the filters.</div>${late}`; return; }
  el.innerHTML = `<div class="table-wrap"><table><thead><tr><th>Seq</th><th>Time</th><th>Actor</th><th>Event</th><th>Operation</th><th>Decision</th><th>Hash</th><th>Signature</th></tr></thead><tbody>
    ${d.entries.map((e) => { const k = `log~${d.run_id}~${e.seq}`; return `<tr class="click${S.q.open === k ? " sel" : ""}" tabindex="0" data-key="${esc(k)}"><td>${e.seq}</td><td class="nw">${clock(e.ts)}</td><td class="nw">${esc(e.actor)}</td><td class="nw">${esc(e.type)}</td><td>${esc([e.data.op, e.data.reason].filter(Boolean).join(": ") || e.data.attack_id || "")}</td><td>${decTag(e.decision)}</td><td class="hash nw">${short(e.hash, 12)}</td><td class="nw">${e.signed ? `<span class="st ok">signed</span>` : `<span class="muted">pending</span>`}</td></tr>`; }).join("")}
    </tbody></table></div>
    <div class="row mt"><button type="button" class="btn" data-page="-1" ${A.off ? "" : "disabled"}>${icon("left")} Newer</button><span class="small muted">${fmt(A.off + 1)}–${fmt(Math.min(A.off + LOG_PAGE, d.matched))} of ${fmt(d.matched)}</span><button type="button" class="btn" data-page="1" ${A.off + LOG_PAGE < d.matched ? "" : "disabled"}>Older ${icon("right")}</button></div>${late}`;
  wrapTables(el);
}
async function fetchAudit(first) {
  try {
    const d = await get("/api/lab/timeline?limit=1500");
    const sig = d.length + ":" + (d[0] ? d[0].ts : "");
    S.audit.data = d;
    if (first || sig !== S.audit.sig) { S.audit.sig = sig; drawAudit(); if (!$("#fpanel").hidden) drawFacets(); }
    else $("#a-meta").textContent = $("#a-meta").textContent.replace(/updated .*/, "updated " + new Date().toLocaleTimeString());
  } catch (e) { const m = $("#a-meta"); if (m) m.innerHTML = `<span class="st fail">Could not load events: ${esc(e.message)}</span>`; }
}
function drawAudit() {
  const A = S.audit, el = $("#a-table"); if (!el) return;
  let rows = facetFilter(audSearch(), AUD_FACETS, A.f);
  rows = rows.slice().sort((a, b) => (A.sort === "desc" ? b.ts - a.ts : a.ts - b.ts));
  $("#a-meta").textContent = `${fmt(rows.length)} of ${fmt(A.data.length)} events · updated ${new Date().toLocaleTimeString()}`;
  if (!A.data.length) { el.innerHTML = `<div class="empty"><strong>No events yet</strong><a href="#/lab?open=run">Start a live run</a> and its events appear here as the broker records them.</div>`; return; }
  if (!rows.length) { el.innerHTML = `<div class="empty"><strong>No event matches</strong>Clear the search or the filters.</div>`; return; }
  el.innerHTML = evTable(rows.slice(0, A.limit), { seq: true, signed: true, click: true }) + (rows.length > A.limit ? `<p class="mt"><button type="button" class="chip more" data-more>Show all ${fmt(rows.length)}</button></p>` : "");
  wrapTables(el);
}
async function auditOpen(key) {
  if (key.startsWith("log~")) return logOpen(key);
  if (!S.audit.data.length) await fetchAudit(true);
  const e = S.audit.data.find((x) => evKey(x) === key);
  if (!e) return { title: "Event not found", body: `<p class="muted">This event is no longer in the most recent 1,500 events.</p>` };
  $$("#a-table tr[data-key]").forEach((tr) => tr.classList.toggle("sel", tr.dataset.key === key));
  return {
    title: e.type, meta: `${esc(e.run_id)} · #${e.seq ?? "–"} · ${esc(e.actor)} · ${when(e.ts)}`,
    body: `<p>${esc(e.summary)}</p>
      <ul class="ledger"><li><span class="k">Decision</span><span class="v">${decTag(decisionOf(e))}</span></li>
      <li><span class="k">Actor</span><span class="v">${esc(e.actor)}</span></li>
      <li><span class="k">Audit sequence</span><span class="v">${e.seq ?? "none"}</span></li>
      <li><span class="k">Evidence</span><span class="v">${e.post_terminal ? "Recorded after the signed chain closed (post_terminal.jsonl, unsigned, informational)" : e.signed ? "Entry " + e.seq + " is covered by a signed checkpoint in the reviewer vault" : "Not yet covered by a signed checkpoint (the next periodic, seal or terminal checkpoint covers it)"}</span></li></ul>
      <p class="lbl">Monitoring record</p><pre class="json">${esc(JSON.stringify(e, null, 2))}</pre>
      <p class="tiny mt">The monitoring stream holds digests and counts only. Payloads, model outputs and defence rules stay in the sealed store.</p>
      <p class="mt"><a href="${href("connections", { view: "timeline", run: e.run_id })}">See it on the run's timeline</a></p>`,
  };
}

async function logOpen(key) {
  const [, rid, seq] = key.split("~");
  let e = ((S.audit.log || {}).entries || []).find((x) => String(x.seq) === seq && S.audit.log.run_id === rid);
  if (!e) {
    const d = await get(`/api/lab/runs/${encodeURIComponent(rid)}/audit?offset=${Math.max(0, Number(seq) - 1)}&limit=1`);
    e = d.entries.find((x) => String(x.seq) === seq);
  }
  if (!e) return { title: "Entry not found", body: `<p class="muted">Entry ${esc(seq)} of ${esc(rid)} was not found.</p>` };
  $$("#l-table tr[data-key]").forEach((tr) => tr.classList.toggle("sel", tr.dataset.key === key));
  return {
    title: e.type, meta: `${esc(rid)} · #${e.seq} · ${esc(e.actor)} · ${when(e.ts)}`,
    body: `<ul class="ledger"><li><span class="k">Decision</span><span class="v">${decTag(e.decision)}</span></li>
      <li><span class="k">Actor</span><span class="v">${esc(e.actor)}</span></li>
      <li><span class="k">Hash</span><span class="v hash">${esc(e.hash)}</span></li>
      <li><span class="k">Previous hash</span><span class="v hash">${esc(e.prev)}</span></li>
      <li><span class="k">Evidence</span><span class="v">${e.signed ? "Covered by a signed checkpoint in the reviewer vault; the exported bundle lets anyone check it with the independent verifier." : "Not yet covered by a signed checkpoint (the next periodic, seal, pre-release or terminal checkpoint covers it)."}</span></li></ul>
      <p class="lbl">Recorded metadata</p><pre class="json">${esc(JSON.stringify(e.data, null, 2))}</pre>
      <p class="tiny mt">Fields outside the metadata allowlist (payload and output digests, defence-config digests, rule text) are withheld by the server.</p>
      <p class="mt"><a href="${href("connections", { view: "timeline", run: rid })}">See the run's timeline</a>${S.runs.some((r) => r.id === rid && r.state === "RELEASED") ? ` · <a href="${href("evidence", { open: rid })}">Verify its bundle</a>` : ""}</p>`,
  };
}

/* ================================================================ 5. evidence verification */
const EV_KIND = { shipped: "Shipped", lab: "Lab run", "shipped-tampered": "Tampered copy", "shipped-legacy": "Legacy" };
const evSession = (b) => { const v = S.ev.verify[b.id]; return !v ? "Not verified yet" : (v.result || {}).ok ? "Accepted" : v.exit_code == null ? "Error" : "Rejected"; };
const EV_FACETS = [
  { key: "kind", title: "Bundle", get: (b) => EV_KIND[b.kind] || b.kind },
  { key: "expected", title: "Expected verdict", get: (b) => (b.expected === "pass" ? "accept" : "reject") },
  { key: "session", title: "This session", get: evSession, order: ["Not verified yet", "Accepted", "Rejected", "Error"] },
];
const evRows = () => S.ev.bundles.filter((b) => textMatch(S.ev.search, b.label, b.id, b.path, b.run_id, b.note));
PAGES.evidence = { render: evidence, open: evOpen };
async function evidence() {
  render(loading("Listing evidence bundles…"));
  const [bundles, modes] = await Promise.all([get("/api/lab/bundles"), get("/api/lab/tamper-modes"), loadJournal()]);
  S.ev.bundles = bundles; S.ev.modes = modes;
  band({ placeholder: "Bundles, runs, paths", value: S.ev.search, onSearch: (v) => { S.ev.search = v; drawBundles(); }, filter: filterCfg(EV_FACETS, S.ev.f, evRows, drawBundles) });
  render(`<div class="intro"><p>Run the independent verifier on a bundle: the same program a reviewer runs on their own machine (<code>python -m aegis.verify_cli</code>), started here as a separate process. Then change a disposable copy and watch the verifier reject it while the original still passes. Evidence files are never written.</p>${labelTag("live")}</div>
    <section class="sec">${secHead("Bundles", `<span id="ev-count"></span>`)}<div class="cards" id="ev-cards"></div>
    <p class="foot mt">Lab bundles appear here after a reviewer releases a lab run.</p></section>`);
  $("#ev-cards").addEventListener("click", (e) => { const c = e.target.closest("[data-key]"); if (c) openKey(c.dataset.key); });
  drawBundles();
}
function drawBundles() {
  const el = $("#ev-cards"); if (!el) return;
  const rows = facetFilter(evRows(), EV_FACETS, S.ev.f);
  $("#ev-count").textContent = `${rows.length} of ${S.ev.bundles.length}`;
  el.innerHTML = rows.length ? rows.map((b) => {
    const v = S.ev.verify[b.id], cls = b.expected === "pass" ? "c-pass" : b.kind === "shipped-legacy" ? "c-warn" : "c-deny";
    const mark = !v ? `${icon("circle")}<span class="st none">Not verified in this session</span>`
      : `${icon(v.matches_expectation ? "shield" : "alert")}<span class="st ${v.matches_expectation ? "pass" : "fail"}">${(v.result || {}).ok ? "Accepted" : "Rejected"} · exit ${esc(v.exit_code)} · ${v.matches_expectation ? "as expected" : "NOT as expected"}</span>`;
    return card({ key: b.id, cls, title: b.label, badge: b.expected === "pass" ? "Genuine" : b.kind === "shipped-legacy" ? "Legacy" : "Tampered", meta: b.path, mark, body: esc(b.note),
      tags: [b.run_id, `${b.entries ?? "?"} entries`, b.pinned ? "key pinned" : "key from bundle", "expect " + (b.expected === "pass" ? "accept" : "reject")], sel: S.q.open === b.id });
  }).join("") : `<div class="empty" style="grid-column:1/-1"><strong>No bundle matches</strong>Clear the search or the filters.</div>`;
  enter(el);
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
  if (v.exit_code == null) return `<div class="note bad">${esc(v.error || "The verifier did not return a result.")}</div>`;
  const res = v.result || {};
  return `<ul class="vchecks">${VCHECKS.map(([k, t, d]) => {
    let val = res[k], ok;
    if (k === "tail_uncovered") ok = val === 0;
    else if (k === "key_source") { ok = String(val || "").startsWith("pinned"); val = ok ? "pinned" : "from the bundle"; }
    else if (k === "anchor_checked") ok = val !== false;
    else ok = val === true;
    const cls = k === "key_source" && !ok ? "warn" : ok ? "pass" : "fail";
    return `<li><div class="k"><span>${t}</span><span class="st ${cls}">${esc(val === null || val === undefined ? "n/a" : String(val))}</span></div><p>${d}</p></li>`;
  }).join("")}</ul>
  <p class="small mt">${res.entries} entries, ${res.checkpoints_checked} checkpoints, terminal state ${esc(res.terminal_state || "none")}. Exit code <b>${v.exit_code}</b>${v.seconds !== undefined ? " in " + v.seconds + " s" : ""}.</p>
  ${res.terminal_hash ? `<p class="hash">terminal hash ${esc(res.terminal_hash)}</p>` : ""}
  ${(res.findings || []).length ? `<p class="lbl">Findings</p><ul class="dash" style="padding-left:18px;margin:0">${res.findings.map((f) => `<li class="small st fail" style="font-weight:400">${esc(f.issue)}${f.seq ? " (entry " + f.seq + ")" : f.checkpoint_seq ? " (checkpoint at entry " + f.checkpoint_seq + ")" : ""}</li>`).join("")}</ul>` : ""}
  ${(v.stderr || []).map((l) => `<p class="tiny st warn" style="font-weight:400">${esc(l)}</p>`).join("")}
  <div class="cmd mt">$ ${esc(v.command)}</div>`;
}
function tamperView(t) {
  const iss = Array.from(new Set(((t.tampered_copy.result || {}).findings || []).map((f) => f.issue))).slice(0, 3);
  return `${verdictBox(t.verdict, t.verdict === "PASS" ? "Tampered copy rejected, original accepted and byte-identical" : "Expectation not met")}
    <p class="small"><b>Change applied to the copy:</b> ${esc(t.change)}</p>
    <ul class="ledger mt"><li><span class="k">Tampered copy</span><span class="v"><span class="st ${t.tampered_copy.exit_code === 1 ? "pass" : "fail"}">exit ${esc(t.tampered_copy.exit_code)}, ${(t.tampered_copy.result || {}).ok ? "accepted" : "rejected"}</span><br><span class="tiny">${iss.map(esc).join("<br>") || "no findings"}</span></span></li>
      <li><span class="k">Original</span><span class="v"><span class="st ${t.original.exit_code === 0 ? "pass" : "fail"}">exit ${esc(t.original.exit_code)}, ${(t.original.result || {}).ok ? "accepted" : "rejected"}</span><br><span class="tiny">byte-identical before and after: <b>${t.original_unchanged ? "yes" : "NO"}</b> · copy deleted: ${t.copy_deleted ? "yes" : "no"}</span></span></li></ul>
    <details class="mt"><summary>Original file digests (SHA-256, first 16 hex)</summary><pre class="json">${esc(JSON.stringify(t.original_sha256, null, 1))}</pre></details>`;
}
function memView(m) {
  const rows = m.rows || [], det = rows.filter((r) => r.detected).length;
  return `${verdictBox(m.verdict, `${det} of ${rows.length} in-memory modifications detected; stored log unchanged: ${m.stored_log_unchanged ? "yes" : "NO"}`)}<div class="table-wrap"><table><thead><tr><th>Modification</th><th>Detected</th><th>First finding</th></tr></thead><tbody>
    ${rows.map((r) => `<tr><td>${esc(r.description || r.mode)}</td><td>${r.error ? `<span class="st fail">${esc(r.error)}</span>` : r.detected ? `<span class="st pass">yes</span>` : `<span class="st fail">NO</span>`}</td><td class="tiny">${esc((((r.verification || {}).findings || [])[0] || {}).issue || "")}</td></tr>`).join("")}</tbody></table></div>`;
}
async function evOpen(id) {
  if (!S.ev.bundles.length) S.ev.bundles = await get("/api/lab/bundles");
  if (!S.ev.modes) S.ev.modes = await get("/api/lab/tamper-modes");
  const b = S.ev.bundles.find((x) => x.id === id);
  if (!b) return null;
  $$("#ev-cards .card").forEach((c) => c.classList.toggle("sel", c.dataset.key === id));
  const v = S.ev.verify[id], t = S.ev.tamper[id], canTamper = b.expected === "pass" && canAct();
  return {
    title: b.label, meta: `${esc(EV_KIND[b.kind] || b.kind)} · expected: ${b.expected === "pass" ? "accept" : "reject"} · ${esc(b.path)}`,
    body: `<p>${esc(b.note)}</p>
      <ul class="ledger"><li><span class="k">Run</span><span class="v">${esc(b.run_id)}, expected state ${esc(b.expect_state)}</span></li><li><span class="k">Audit entries</span><span class="v">${b.entries ?? "?"}</span></li><li><span class="k">Public key</span><span class="v">${b.pinned ? "pinned (supplied by the reviewer)" : "read from the bundle"}</span></li><li><span class="k">Files</span><span class="v small">${b.files.map(esc).join(", ")}</span></li></ul>
      <div class="row mt"><button class="btn solid lg" id="do-verify" type="button">${icon("shield")} Verify with the independent verifier</button>
        ${b.expected === "pass" ? `<a class="btn lg" href="/api/lab/bundles/${encodeURIComponent(b.id)}/download" download>${icon("download")} Download .zip</a>` : ""}</div>
      <div id="v-out" aria-live="polite">${v ? `<p class="lbl">Verification ${v.matches_expectation ? `<span class="st pass">as expected</span>` : `<span class="st fail">NOT as expected</span>`}</p>
        <p class="small">${v.exit_code == null ? `<span class="st fail">No verdict.</span> The verifier gave no result, which never counts as a pass or as a rejection.` : (v.result || {}).ok ? `<span class="st pass">Accepted.</span> The log is complete and unmodified relative to the signed terminal checkpoint.` : `<span class="st fail">Rejected.</span> The verifier could not establish an intact, complete log; the findings say why.`}</p>${verifyView(v)}` : `<p class="tiny mt">Not verified in this session yet.</p>`}</div>
      ${b.expected === "pass" ? `<hr><p class="lbl">Tamper with a disposable copy</p>
        <p class="small muted">The server copies this bundle to a temporary directory, applies one change, runs the verifier on the copy and on the original, compares the original's SHA-256 digests before and after, and deletes the copy. Needs the operator session.</p>
        <div class="row mt"><label class="field">Change<select id="t-mode">${Object.entries(S.ev.modes.disk_copy).map(([k, d]) => `<option value="${k}" ${k === S.ev.tmode ? "selected" : ""}>${esc(d)}</option>`).join("")}</select></label>
          <button class="btn lg" id="do-tamper" type="button" ${canTamper ? "" : "disabled"}>Tamper and verify</button></div>
        <div id="t-out" aria-live="polite" class="mt">${t ? tamperView(t) : ""}</div>` : ""}
      ${b.kind === "lab" ? `<hr><p class="lbl">In-memory tamper suite for ${esc(b.run_id)}</p>
        <p class="small muted">The control plane's own tamper test (POST /api/runs/{id}/tamper-test), sent server-side as the reviewer: each modification applied to an in-memory copy of the stored log and vault, verified strictly. The stored log is hashed before and after.</p>
        <button class="btn lg mt" id="do-mem" type="button" ${canAct() ? "" : "disabled"}>Run all ${Object.keys(S.ev.modes.in_memory_run || {}).length}</button><div id="m-out">${S.ev.mem[id] ? memView(S.ev.mem[id]) : ""}</div>` : ""}
      ${b.expected === "pass" && !canAct() ? `<p class="tiny mt">${esc(NO_SESSION)}</p>` : ""}`,
    after: (body) => {
      $("#do-verify", body).addEventListener("click", async (ev) => {
        const btn = ev.currentTarget; busy(btn, true);
        try {
          const r = await call(`/api/lab/bundles/${encodeURIComponent(id)}/verify`, { method: "POST" });
          if (!r.ok) toast(classify(r.status).text + ": " + ((r.body && r.body.detail) || ""), true); else { S.ev.verify[id] = r.body; drawBundles(); await refreshSheet(); }
        } catch (e) { toast(e.message, true); } finally { if (document.contains(btn)) busy(btn, false); }
      });
      const tb = $("#do-tamper", body);
      if (tb) tb.addEventListener("click", async (ev) => {
        const btn = ev.currentTarget; busy(btn, true);
        try {
          const r = await call(`/api/lab/bundles/${encodeURIComponent(id)}/tamper`, { method: "POST", body: { mode: (S.ev.tmode = $("#t-mode").value) } });
          if (!r.ok) toast(classify(r.status).text + ": " + ((r.body && r.body.detail) || ""), true); else { S.ev.tamper[id] = r.body; loadJournal(); await refreshSheet(); }
        } catch (e) { toast(e.message, true); } finally { if (document.contains(btn)) busy(btn, false); }
      });
      const mb = $("#do-mem", body);
      if (mb) mb.addEventListener("click", async (ev) => {
        const btn = ev.currentTarget; busy(btn, true);
        try {
          const r = await call(`/api/lab/runs/${encodeURIComponent(b.run_id)}/tamper-suite`, { method: "POST" });
          if (!r.ok) toast(classify(r.status).text + ": " + ((r.body && r.body.detail) || ""), true);
          else { S.ev.mem[id] = r.body; await refreshSheet(); }
        } catch (e) { toast(e.message, true); } finally { if (document.contains(btn)) busy(btn, false); }
      });
    },
  };
}

/* ================================================================ 6. experiments */
PAGES.experiments = { render: experiments };
async function experiments() {
  render(loading("Recomputing the saved results from their raw files…"));
  const x = await loadExp();
  const rm = x.real_model || {}, tm = x.timing || {}, sy = x.system_tests || {};
  const recomp = (r) => (r ? `<p class="small">${labelTag("live")} recomputed now: <span class="st ${r.passed === r.checks ? "pass" : "fail"}">${r.passed} of ${r.checks} checks agree</span> with the saved results.${r.what ? ` <span class="muted">${esc(r.what)}.</span>` : ""}</p>` : "");
  const pos = (a) => Math.max(0, Math.min(100, ((a - 0.4) / 0.5) * 100));
  const strips = (tm.buckets || []).map((b) => `<div class="strip"><span>${b.bucket_ms === 0 ? "no padding" : b.bucket_ms + " ms buckets"}</span>
      <div class="track" role="img" aria-label="${esc(`${b.bucket_ms} ms: held-out accuracy ${b.heldout_accuracy.join(", ")}`)}"><span class="chance" style="left:${pos(0.5)}%"></span>${b.heldout_accuracy.map((a) => `<span class="pt ${a > 0.6 ? "hi" : ""}" style="left:${pos(a)}%" title="${a}"></span>`).join("")}</div>
      <span>${b.heldout_accuracy.map((a) => a.toFixed(3)).join(" / ")}<br><span class="tiny">p ${b.permutation_p.map((p) => p.toFixed(3)).join(" / ")} · ${esc(b.verdict)}</span></span></div>`).join("");
  render(`
  <div class="intro"><p>Saved results from the project's experiments, each with the label of how it was produced. Where the raw files are in the repository, the console recomputes the figures from them and says whether they agree. Nothing on this page is running now.</p></div>
  <section class="sec">${secHead("Labels used")}
    <ul class="ledger">
      <li><span class="k">${labelTag("pre")}</span><span class="v">Saved runs against a real model (Qwen2.5-0.5B, CPU llama.cpp). No model runs in this console.</span></li>
      <li><span class="k">${labelTag("rec")}</span><span class="v">A saved transcript of a real execution, replayed, not re-run.</span></li>
      <li><span class="k">${labelTag("live")}</span><span class="v">Executed now on this machine, including the recomputations below.</span></li>
      <li><span class="k">${labelTag("stub")}</span><span class="v">Measured with the deterministic stub model, which is not an LLM.</span></li></ul></section>
  ${rm.available === false ? `<div class="note bad">${esc(rm.error)}</div>` : `<section class="sec">${secHead("Real-model isolation", labelTag("pre"))}
    <ul class="ledger"><li><span class="k">Model</span><span class="v">${esc((rm.model || {}).model_class)}</span></li><li><span class="k">Server</span><span class="v">${esc((rm.model || {}).inference_server)} · ${esc((rm.model || {}).bind)} · temperature ${esc((rm.model || {}).temperature)}</span></li><li><span class="k">Model sha256</span><span class="v hash">${short((rm.model || {}).model_sha256, 24)}</span></li></ul>
    <div class="mt">${recomp(rm.recompute)}</div>
    <div class="cards three mt">${(rm.experiments || []).map((e) => `<article class="card auto pre c-pre"><div class="top"><h3>${esc(e.id)} · ${esc(e.title)}</h3><span class="badge" style="--bc:${e.classification === "pass" ? "var(--s-pass)" : "var(--s-warn)"}">${esc(e.classification)}</span></div>
      <div class="meta">${esc(e.timestamp_utc)}</div><ul class="claims">${e.claims.map((c) => `<li>${esc(c)}</li>`).join("")}</ul><div class="tiny" style="margin-top:auto;overflow-wrap:anywhere">${esc(e.dir)}</div></article>`).join("")}</div>
    <div class="note">Zero observed leaks are counts from finite experiments with one 0.5B model. They bound the leak rate for this configuration (see the one-sided 95% upper bound in E1); they do not prove isolation in general. The positive controls show the detectors fire when context is deliberately shared. GPU memory and accelerator KV-cache isolation were not tested.</div>
    ${(rm.limitations || []).length ? `<p class="lbl">Stated limitations of these runs</p><ul class="dash" style="padding-left:18px">${rm.limitations.map((l) => `<li class="small">${esc(l)}</li>`).join("")}</ul>` : ""}
    ${(rm.revalidation || []).length ? `<p class="lbl">Re-validation on later trees</p><ul class="dash" style="padding-left:18px">${rm.revalidation.map((l) => `<li class="small">${esc(l)}</li>`).join("")}</ul>` : ""}</section>`}
  ${tm.available === false ? `<div class="note bad">${esc(tm.error)}</div>` : `<section class="sec">${secHead("Timing side channel and padding", labelTag("stub") + " " + labelTag("pre").replace("PRECOMPUTED REAL-MODEL", "PRECOMPUTED"))}
    <p class="small muted">Can red tell a refused request from an answered one by its latency? Held-out accuracy of a threshold classifier, three complete executions, 200 requests each per setting; 0.5 is chance (dashed line). Source: ${esc(tm.source)}.</p>
    <div class="mt">${strips}<div class="strip-axis"><span></span><span class="ticks">${[0.4, 0.5, 0.6, 0.7, 0.8, 0.9].map((t) => `<span style="left:${pos(t)}%">${t.toFixed(1)}</span>`).join("")}</span><span>accuracy · permutation p</span></div></div>
    <div class="mt">${recomp(tm.recompute)}</div>
    <p class="small">With 250 ms buckets: accuracy ${esc(tm.claims.acc250)} (pooled ${esc(tm.claims.pool250)}); cost ${esc(tm.claims.cost250)} median added latency. Unrestricted CPU neighbour: broker mailbox round trip ${esc(tm.claims.unres_inc)}.</p>
    <div class="note">Padding weakened this classifier to chance level in these runs; n=200 cannot distinguish accuracy up to about 0.57 from chance, and stronger adversaries, cache and memory-bandwidth channels were not measured. The channel is weakened, not proven eliminated.</div></section>`}
  ${sy.available === false ? `<div class="note bad">${esc(sy.error)}</div>` : `<section class="sec">${secHead("Recorded system tests", labelTag("stub"))}
    <p class="small muted">Container-free access matrix and audit tamper sweep from the 22 Oct 2026 validation. Source: ${esc(sy.source)}.</p>
    <div class="table-wrap mt"><table><thead><tr><th>Claim</th><th>Value</th><th>File</th></tr></thead><tbody>${sy.rows.map((r) => `<tr><td>${esc(r.claim)}</td><td class="nw">${esc(r.value)}</td><td class="nw">${esc(r.file)}</td></tr>`).join("")}</tbody></table></div></section>`}
  <section class="sec">${secHead("Known detector and measurement limits")}
    <div class="table-wrap"><table><thead><tr><th>Limit</th><th>Where it is shown</th></tr></thead><tbody>${(x.detector_limits || []).map((d) => `<tr><td><span class="st warn" style="font-weight:400">${esc(d.item)}</span></td><td class="nw">${esc(d.test)}</td></tr>`).join("")}</tbody></table></div></section>`);
}

/* ================================================================ 7. threat model */
PAGES["threat-model"] = { render: threatModel };
async function threatModel() {
  const li = (k, v) => `<li><span class="k">${k}</span><span class="v">${v}</span></li>`;
  render(`
  <section class="sec"><p class="statement">What this prototype was shown to stop, in the environment it was tested in, and what it does not claim.</p>
    <p class="lede muted">Restated from <code>aegislab/THREAT_MODEL.md</code>, <code>PHASE2_SECURITY_REPORT.md</code> and <code>PHASE3_LLM_SECURITY_REPORT.md</code>. Figures are the recorded results named there, not live measurements.</p></section>
  <section class="sec">${secHead("Protected boundaries")}
    <div class="cols" style="--n:2">
      <div><p class="lbl"><span class="st pass">Tested</span> in the demonstrated environment</p><ul class="ledger">
        ${li("Cross-role authorisation", "212-case role × operation × state matrix: 181/181 expected denials, 0 unauthorised successes; live in the Lab.")}
        ${li("Unauthorised mailbox interaction", "Forbidden red requests denied by the broker; planted symlinks, FIFOs and replaced mailbox directories handled (Phase 2 fixes, live in sandbox containment).")}
        ${li("Evidence tampering", "Modification, deletion, reordering, truncation, re-hashing, forged signatures and key substitution detected by the verifier; live on the Evidence page.")}
        ${li("Model-output leakage", "Another run's canary (token, digits, separated digits, 8-digit fragments) and control-plane secrets withheld from red; tested with Qwen2.5-0.5B and positive controls.")}
        ${li("Sandbox reach", "No network, read-only root, no capabilities, no-new-privileges, seccomp, foreign paths absent.")}</ul></div>
      <div><p class="lbl"><span class="st warn">Not proven</span> or not addressed</p><ul class="ledger">
        ${li("Compromised broker", "It sees everything and can sign a false but consistent record.")}
        ${li("Compromised signing key", "Same Unix user as the broker. Only a terminal hash the reviewer wrote down at release detects a full re-signed rewrite.")}
        ${li("Global role tokens", "Tokens are per role, not per run. The console keeps them server-side, but one local operator session drives every role: not multi-user authentication.")}
        ${li("Detector bypasses", "Base64, ciphers or spelled-out digits carry a canary past the detector (test P3B02d).")}
        ${li("Timing side channels", "One classifier is weakened by padding; cache and memory-bandwidth channels are not measured.")}
        ${li("Kernel or runtime escape", "Containers share the host kernel; no escape exploits were attempted.")}</ul></div>
    </div></section>
  <section class="sec">${secHead("Trusted components", "trusted, not defended")}
    <ul class="ledger">
      ${li("Broker process", "Sees every payload and signs every checkpoint; a lie told before signing is not detectable.")}
      ${li("Signing key", "Ed25519, mode 0600, same Unix user as the broker on this prototype.")}
      ${li("Reviewer vault and anchor store", "Separate copies, not separate trust domains, unless relocated with AEGIS_VAULT / AEGIS_ANCHORS to storage the run writer cannot reach.")}
      ${li("Host kernel, Podman, crun", "Uncompromised. One kernel bug defeats the container boundary.")}
      ${li("Verifier", "Runs in an environment the attacker does not control, with a public key pinned out of band.")}
      ${li("Reviewer identity", "A trusted human holding a local demo token; a real deployment needs SSO with run-scoped claims.")}</ul>
    <p class="small mt"><a href="#/connections">See the trust boundaries as a graph</a></p></section>
  <section class="sec">${secHead("Attack assumptions")}
    <ul class="ledger">
      ${li("Red team", "Fully hostile inside its container: may plant links, FIFOs, huge or deeply nested messages, and probe the defence through refusals.")}
      ${li("Blue team", "A peer, not trusted: anything but a clear allow or block verdict counts as block.")}
      ${li("Model", "Untrusted output; may follow injected instructions or repeat what it saw.")}
      ${li("Participants and observers", "May call any API with their own token, or with none, at any lifecycle state.")}
      ${li("Finite tests", "Zero findings in n trials gives an upper bound, not a proof; sample sizes are in the result files.")}</ul></section>
  <section class="sec">${secHead("Tested attack classes")}
    <div class="table-wrap"><table><thead><tr><th>Attack class</th><th>Boundary</th><th>See it</th><th>Recorded evidence</th></tr></thead><tbody>
      <tr><td>Payload or config leakage across teams</td><td>Result gate, role boundary</td><td><a href="#/lab?open=prohibited-access">Lab</a></td><td class="nw">evidence/validation_2026-10-22/isolation_matrix.json</td></tr>
      <tr><td>Unauthorised mailbox operations, planted files</td><td>Mailbox, container</td><td><a href="#/lab?open=sandbox-containment">Lab</a></td><td class="nw">PHASE2_SECURITY_REPORT.md</td></tr>
      <tr><td>Audit modification, deletion, truncation</td><td>Audit log</td><td><a href="#/evidence">Evidence</a></td><td class="nw">evidence/validation_2026-10-22/audit_tamper.json</td></tr>
      <tr><td>Cross-session contamination</td><td>Session ↔ session</td><td><a href="#/lab?open=E1">Lab</a></td><td class="nw">evidence/phase3_2026-10-23/llm/</td></tr>
      <tr><td>Prompt injection against isolation</td><td>Model output</td><td><a href="#/lab?open=E4">Lab</a></td><td class="nw">evidence/phase3_2026-10-23/llm/</td></tr>
      <tr><td>Timing and resource contention</td><td>Broker timing</td><td><a href="#/experiments">Experiments</a></td><td class="nw">evidence/closeout_2026-10-22/timing/</td></tr>
      <tr><td>Model-server failure</td><td>Run integrity</td><td><a href="#/experiments">Experiments</a> (E5)</td><td class="nw">evidence/phase3_2026-10-23/llm/</td></tr>
    </tbody></table></div></section>
  <section class="sec">${secHead("Unverified environments")}
    <ul class="ledger">
      ${li("GPU and accelerators", "GPU memory, CUDA contexts and accelerator KV caches were not tested; only CPU llama.cpp.")}
      ${li("Other models", "Results are for one 0.5B model; there is no universal guarantee.")}
      ${li("Multiple hosts", "Single host only; separate machines, microVMs (gVisor, Kata, Firecracker) and confidential computing are not demonstrated.")}
      ${li("Production identity", "No SSO or run-scoped claims; demo tokens only.")}</ul></section>
  <section class="sec">${secHead("Deployment constraints", "this console")}
    <ul class="ledger">
      ${li("Loopback only", "Binds to 127.0.0.1 and refuses requests whose Host header is not a loopback name (blocks DNS rebinding).")}
      ${li("Fixed actions", "Scenarios, bundles and tamper modes are fixed lists on the server; the browser cannot send a command, path, container option or network target.")}
      ${li("Disposable copies", "Tamper demonstrations work on deleted-after-use copies; originals are hashed before and after.")}
      ${li("Operator session", "The launch link sets an HttpOnly, SameSite=Strict cookie; writes need a per-session CSRF token and a same-origin request. AEGIS_DEMO_MODE is refused. Never expose this console beyond loopback.")}</ul></section>`);
}

/* ---------------------------------------------------------------- boot */
async function boot() {
  $("#tm-link").innerHTML = icon("info", "lg");
  $(".search").insertAdjacentHTML("afterbegin", icon("search"));
  $("#sheet-close").innerHTML = icon("x", "md");
  bindBand();
  $("#sheet-close").addEventListener("click", closeKey);
  $("#scrim").addEventListener("click", closeKey);
  document.addEventListener("keydown", (e) => { if (e.key === "Escape" && SH.open && !$("#confirm").open) { e.preventDefault(); closeKey(); } });
  window.addEventListener("hashchange", route);
  window.addEventListener("popstate", route);
  let rt = 0;
  window.addEventListener("resize", () => { clearTimeout(rt); rt = setTimeout(() => { drawRings(document, true); wrapTables(document); }, 150); });
  $("#sess").innerHTML = `<span class="dot" aria-hidden="true"></span><span class="txt">Session…</span>`;
  $("#sess-end").addEventListener("click", endSession);
  await Promise.all([loadSession(), refreshStatus()]);
  setInterval(refreshStatus, 15000);
  await route();
  S.booted = true;
}
boot();
