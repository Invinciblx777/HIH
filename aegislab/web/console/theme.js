/* AegisLab console, presentation layer only. It never touches data or handlers of console.js:
   (1) scroll progress and header state, (2) scroll reveal (adds .rv / .in), (3) on the Overview page, a hero, a shape strip and
   an architecture node graph inserted above the existing sections. The graph is a conceptual diagram of the documented design
   (README, THREAT_MODEL.md), not live data. If anything here fails the page stays fully visible. */
(function () {
  "use strict";
  var root = document.documentElement;
  var reduce = window.matchMedia && matchMedia("(prefers-reduced-motion: reduce)").matches;

  var bar = document.createElement("div");
  bar.id = "scrollbar"; bar.setAttribute("aria-hidden", "true");
  document.body.appendChild(bar);
  var ticking = false;
  function onScroll() {
    if (ticking) return;
    ticking = true;
    requestAnimationFrame(function () {
      var y = window.scrollY || 0, max = Math.max(1, root.scrollHeight - innerHeight);
      root.style.setProperty("--p", Math.min(1, y / max).toFixed(4));
      root.classList.toggle("scrolled", y > 8);
      ticking = false;
    });
  }
  addEventListener("scroll", onScroll, { passive: true });
  addEventListener("resize", onScroll, { passive: true });
  onScroll();

  /* ------------------------------------------------------------ overview hero + architecture */
  var IC = {
    target: '<circle cx="12" cy="12" r="9"/><circle cx="12" cy="12" r="4"/><path d="M12 1v4M12 19v4M1 12h4M19 12h4"/>',
    shield: '<path d="M12 3 5 6v5c0 4.6 3 8.2 7 10 4-1.8 7-5.4 7-10V6z"/><path d="m9 12 2.2 2.2L15.5 10"/>',
    cpu: '<rect x="6" y="6" width="12" height="12" rx="2"/><path d="M9 2v3M15 2v3M9 19v3M15 19v3M2 9h3M2 15h3M19 9h3M19 15h3"/>',
    lock: '<rect x="5" y="11" width="14" height="10" rx="2"/><path d="M8 11V8a4 4 0 0 1 8 0v3"/>',
    link: '<path d="M10 14a4 4 0 0 0 5.7 0l3-3a4 4 0 0 0-5.7-5.7l-1 1"/><path d="M14 10a4 4 0 0 0-5.7 0l-3 3a4 4 0 0 0 5.7 5.7l1-1"/>',
    flag: '<path d="M5 21V4"/><path d="M5 4h12l-2 4 2 4H5"/>',
    file: '<path d="M14 3H7a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h10a2 2 0 0 0 2-2V8z"/><path d="M14 3v5h5M9 14l2 2 4-4"/>',
    arrow: '<path d="M5 12h14M13 6l6 6-6 6"/>',
    eye: '<path d="M2 12s3.6-7 10-7 10 7 10 7-3.6 7-10 7S2 12 2 12z"/><circle cx="12" cy="12" r="3"/>',
    plus: '<path d="M12 5v14M5 12h14"/>',
    x: '<path d="M6 6l12 12M18 6 6 18"/>',
    check: '<path d="m5 12 5 5 9-10"/>'
  };
  function svg(name, extra) {
    return '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true" focusable="false"' + (extra || "") + ">" + IC[name] + "</svg>";
  }

  // nodes in a 780 x 540 canvas; g = filter group
  var NODES = [
    { id: "red", g: "sandbox", x: 0, y: 36, ic: "target", t: "Red sandbox", s: "attack agent, no network" },
    { id: "blue", g: "sandbox", x: 0, y: 246, ic: "shield", t: "Blue defence runner", s: "frozen defence config" },
    { id: "model", g: "sandbox", x: 0, y: 456, ic: "cpu", t: "Model worker", s: "fresh container per run" },
    { id: "broker", g: "broker", x: 275, y: 200, w: 230, h: 150, big: true, t: "Trusted broker", s: "private mailbox per tenant. Identity comes from the mailbox, not a claimed field.", tools: ["lock", "eye", "link"] },
    { id: "gate", g: "broker", x: 550, y: 36, ic: "lock", t: "Result gate", s: "sealed until reviewer release" },
    { id: "audit", g: "audit", x: 550, y: 168, ic: "link", t: "Signed audit log", s: "hash chain, Ed25519 checkpoints" },
    { id: "term", g: "audit", x: 550, y: 300, ic: "flag", t: "Terminal checkpoint", s: "closes the chain on release" },
    { id: "bundle", g: "evidence", x: 550, y: 456, ic: "file", t: "Evidence bundle", s: "checked by the independent verifier" }
  ];
  var byId = {}; NODES.forEach(function (n) { n.w = n.w || 230; n.h = n.h || 58; byId[n.id] = n; });
  // k: a = allowed path, d = denied by policy
  var EDGES = [
    { f: "red", t: "broker", k: "a", g: "sandbox" },
    { f: "blue", t: "broker", k: "a", g: "sandbox" },
    { f: "model", t: "broker", k: "a", g: "sandbox" },
    { f: "broker", t: "gate", k: "a", g: "broker" },
    { f: "broker", t: "audit", k: "a", g: "audit" },
    { f: "audit", t: "term", k: "a", g: "audit", v: true },
    { f: "term", t: "bundle", k: "a", g: "evidence", v: true },
    { f: "red", t: "gate", k: "d", g: "broker", arc: true, label: "denied: red reads results" }
  ];
  var FILTERS = [["all", "All"], ["sandbox", "Sandboxes"], ["broker", "Broker"], ["audit", "Audit"], ["evidence", "Evidence"]];
  var ROLES = [
    ["O", "Operator", "creates, freezes, starts", "#1757ff"],
    ["R", "Reviewer", "releases and signs off", "#15803d"],
    ["B", "Blue participant", "submits defence config", "#3a3d41"],
    ["X", "Red participant", "submits attack pack", "#d92d4b"]
  ];

  function edgePath(e) {
    var a = byId[e.f], b = byId[e.t], x1, y1, x2, y2;
    if (e.v) {
      x1 = a.x + a.w / 2; y1 = a.y + a.h; x2 = b.x + b.w / 2; y2 = b.y;
      var m = (y1 + y2) / 2;
      return "M" + x1 + " " + y1 + " C" + x1 + " " + m + " " + x2 + " " + m + " " + x2 + " " + y2;
    }
    x1 = a.x + a.w; y1 = a.y + a.h / 2; x2 = b.x; y2 = b.y + b.h / 2;
    if (e.arc) return "M" + x1 + " " + y1 + " C" + (x1 + 110) + " -22 " + (x2 - 110) + " -22 " + x2 + " " + y2;
    var dx = (x2 - x1) * 0.55;
    return "M" + x1 + " " + y1 + " C" + (x1 + dx) + " " + y1 + " " + (x2 - dx) + " " + y2 + " " + x2 + " " + y2;
  }

  function nodeHTML(n, listMode) {
    var st = listMode ? "" : ' style="left:' + n.x + "px;top:" + n.y + "px" + (n.big ? ";width:" + n.w + "px;height:" + n.h + "px" : "") + '"';
    if (n.big) {
      return '<div class="node big" data-g="' + n.g + '"' + st + "><div><strong>" + n.t + "</strong><span>" + n.s + '</span></div><div class="tools">' + n.tools.map(function (i) { return "<i>" + svg(i) + "</i>"; }).join("") + "</div></div>";
    }
    return '<div class="node" data-g="' + n.g + '"' + st + '><div class="ic">' + svg(n.ic) + "</div><div><strong>" + n.t + "</strong><span>" + n.s + "</span></div></div>";
  }

  function landscape() {
    return '<svg class="land" viewBox="0 0 600 560" preserveAspectRatio="xMidYMid slice" aria-hidden="true" focusable="false">' +
      '<defs><linearGradient id="sky" x1="0" y1="0" x2="0" y2="1"><stop offset="0" stop-color="#4f8fd6"/><stop offset=".55" stop-color="#bcd4e6"/><stop offset="1" stop-color="#f3dfc4"/></linearGradient>' +
      '<linearGradient id="lake" x1="0" y1="0" x2="0" y2="1"><stop offset="0" stop-color="#a9c2cf"/><stop offset="1" stop-color="#e8d7bd"/></linearGradient>' +
      '<linearGradient id="m1" x1="0" y1="0" x2="0" y2="1"><stop offset="0" stop-color="#b8734a"/><stop offset="1" stop-color="#8e4b2e"/></linearGradient></defs>' +
      '<rect width="600" height="560" fill="url(#sky)"/>' +
      '<ellipse cx="420" cy="120" rx="150" ry="26" fill="#fff" opacity=".35"/><ellipse cx="150" cy="170" rx="110" ry="18" fill="#fff" opacity=".3"/>' +
      '<path d="M0 360 L90 300 L150 330 L230 250 L330 340 L420 290 L520 330 L600 300 V420 H0Z" fill="#7d93a8" opacity=".7"/>' +
      '<path d="M-10 420 L70 350 L130 390 L210 320 L300 400 L380 330 L470 400 L560 350 L610 390 V450 H-10Z" fill="url(#m1)"/>' +
      '<path d="M-10 450 H610 V560 H-10Z" fill="url(#lake)"/>' +
      '<path d="M40 470 H260 M300 492 H520 M90 516 H330" stroke="#fff" stroke-opacity=".5" stroke-width="2" stroke-linecap="round"/></svg>';
  }

  function heroHTML() {
    return '<section class="hero" data-injected="1">' +
      '<div class="hero-l"><h1>Red, blue and the model. <em>Kept apart.</em></h1>' +
      "<p>Attack payloads, defence rules and the model under test share one machine. Rootless containers and a trusted broker keep them apart, and every decision lands in a signed log you can check yourself.</p>" +
      '<div class="proof"><b>' + svg("check") + "</b><span>The fail-closed verifier caught 30 of 30 tamper cases in the recorded evaluation.</span></div>" +
      '<div class="hero-cta"><a class="pillbtn dark" href="#/evidence">Verify the evidence ' + svg("arrow") + '</a><a class="pillbtn ghost" href="#/lab">Open the lab</a></div></div>' +
      '<div class="hero-r">' + landscape() +
      '<span class="chipf c1"><i></i>Red sandbox, no network</span>' +
      '<span class="chipf c2 no"><i></i>Release denied to red</span>' +
      '<span class="chipf c3 ok" id="hero-ver"><i></i>Shipped bundle DEMO-001</span>' +
      '<p class="caption">Three tenants. One broker. One signed record.</p></div></section>' +
      '<div class="flow" aria-label="Isolate, then verify"><div class="f1">We</div><div class="f2">Isolate</div><div class="f3">' + svg("arrow") + '</div><div class="f4">Verify</div></div>';
  }

  function archHTML() {
    var edges = EDGES.map(function (e, i) {
      var p = edgePath(e);
      return '<path class="e' + (e.k === "d" ? " d" : "") + '" data-g="' + e.g + '" d="' + p + '"/>' +
        (e.k === "a" && !reduce ? '<circle class="pk" data-g="' + e.g + '" r="4"><animateMotion dur="' + (3.2 + (i % 3) * 0.7) + 's" begin="' + (i * 0.4) + 's" repeatCount="indefinite" path="' + p + '"/></circle>' : "");
    }).join("");
    var lab = EDGES.filter(function (e) { return e.label; }).map(function (e) { return '<span class="lab" style="left:392px;top:8px" data-g="' + e.g + '">' + e.label + "</span>"; }).join("");
    return '<section class="sec arch-sec" data-injected="1">' +
      '<div class="sec-head"><h2>Architecture</h2><span>Who may talk to whom, and where the evidence comes from</span></div>' +
      '<div class="arch"><div class="arch-bar" role="group" aria-label="Highlight part of the architecture">' +
      FILTERS.map(function (f, i) { return '<button class="pill" type="button" data-f="' + f[0] + '" aria-pressed="' + (i === 0) + '">' + f[1] + "</button>"; }).join("") +
      '<span class="legend"><span><i></i>allowed path</span><span><i class="d"></i>denied by policy</span></span></div>' +
      '<div class="arch-side">' +
      '<div class="acard dk"><span class="rb" aria-hidden="true">' + svg("x") + "</span><h3>Isolation walls</h3><small>5 enforced by the broker and the host</small></div>" +
      '<div class="acard bl"><span class="rb" aria-hidden="true">' + svg("plus") + '</span><div class="dots" aria-hidden="true"><i></i><i></i><i></i><i></i></div><h3>Signed record</h3><small>hash-chained, checkpointed, verifiable offline</small></div>' +
      '<div class="roles">' + ROLES.map(function (r) { return '<div class="role" data-g="sandbox"><b style="--c:' + r[3] + '">' + r[0] + "</b><div><strong>" + r[1] + "</strong><span>" + r[2] + "</span></div><em>" + svg("arrow", ' width="14" height="14"') + "</em></div>"; }).join("") + "</div></div>" +
      '<div class="arch-stage"><div class="arch-canvas"><svg width="780" height="540" viewBox="0 0 780 540" aria-hidden="true" focusable="false">' + edges + "</svg>" + lab + NODES.map(function (n) { return nodeHTML(n); }).join("") + "</div></div>" +
      '<div class="arch-list">' + NODES.map(function (n) { return nodeHTML(n, true); }).join("") + "</div></div></section>";
  }

  function fit(sec) {
    var stage = sec.querySelector(".arch-stage"), cv = sec.querySelector(".arch-canvas");
    if (!stage || !cv) return;
    var s = Math.min(1, stage.clientWidth / 780);
    if (!s) return;
    cv.style.transform = "scale(" + s + ")";
    stage.style.height = Math.round(560 * s) + "px";
  }

  function wireArch(sec) {
    var btns = sec.querySelectorAll(".arch-bar .pill");
    function apply(f) {
      btns.forEach(function (b) { b.setAttribute("aria-pressed", String(b.dataset.f === f)); });
      sec.querySelectorAll("[data-g]").forEach(function (el) { el.classList.toggle("dim", f !== "all" && el.dataset.g !== f); });
    }
    btns.forEach(function (b) { b.addEventListener("click", function () { apply(b.dataset.f); }); });
    fit(sec);
    var stage = sec.querySelector(".arch-stage");
    if (window.ResizeObserver) new ResizeObserver(function () { fit(sec); }).observe(stage);
    else addEventListener("resize", function () { fit(sec); });
  }

  var shipped = null;
  function paintShipped() {
    var el = document.getElementById("hero-ver");
    if (!el || !shipped) return;
    var ok = shipped.exit_code === 0 && shipped.ok;
    el.className = "chipf c3 " + (ok ? "ok" : "no");
    el.innerHTML = "<i></i>" + (ok ? "DEMO-001 verified: exit 0, accepted" : "DEMO-001: not accepted");
  }
  function loadShipped() {
    if (shipped || !window.fetch) return;
    fetch("/api/lab/status").then(function (r) { return r.json(); }).then(function (j) { shipped = j.integrity_shipped_bundle || null; paintShipped(); }).catch(function () {});
  }

  function inject() {
    var main = document.getElementById("main");
    if (!main) return;
    var h = location.hash.replace(/^#\/?/, "");
    var onOverview = h === "" || /^overview(\?|$)/.test(h);
    var page = main.querySelector(":scope > .page") || main;
    var first = page.querySelector(":scope > section.sec");
    if (!onOverview || !first || page.querySelector("[data-injected]") || !first.querySelector(".statement")) return;
    first.insertAdjacentHTML("beforebegin", heroHTML());
    var tmp = document.createElement("div");
    tmp.innerHTML = archHTML();
    var arch = tmp.firstChild;
    var secs = page.querySelectorAll(":scope > section.sec:not([data-injected])");
    (secs[1] || first).insertAdjacentElement("beforebegin", arch);  // after runtime status, before demonstrations
    wireArch(arch);
    loadShipped(); paintShipped();
  }

  /* ------------------------------------------------------------ scroll reveal */
  var io = null;
  var SEL = ".hero-l, .hero-r, .flow > div, .intro, .statement, .sec, .arch, .acard, .roles, .card, .gwrap, .table-wrap, .verdict, .strip, .note, .empty, .persp, .life, .cols > *";

  function scan() {
    var main = document.getElementById("main");
    if (!main) return;
    try { inject(); } catch (e) { /* the page stays usable without the injected blocks */ }
    if (!io) return;
    var nodes = main.querySelectorAll(SEL), batch = 0;
    for (var i = 0; i < nodes.length; i++) {
      var el = nodes[i];
      if (el.dataset.rv) continue;
      el.dataset.rv = "1";
      var r = el.getBoundingClientRect();
      var inView = r.top < innerHeight && r.bottom > 0;
      el.classList.add("rv");
      el.style.setProperty("--rd", Math.min(batch++ * 70, 420) + "ms");
      if (inView) { (function (t) { setTimeout(function () { t.classList.add("in"); }, 40); })(el); }
      else io.observe(el);
    }
  }

  var pending = 0;
  function schedule() { clearTimeout(pending); pending = setTimeout(scan, 30); }
  var mainEl = document.getElementById("main");
  if (mainEl) new MutationObserver(schedule).observe(mainEl, { childList: true, subtree: true });
  addEventListener("hashchange", schedule);

  if (!reduce && "IntersectionObserver" in window) {
    io = new IntersectionObserver(function (entries) {
      entries.forEach(function (e) {
        if (!e.isIntersecting) return;
        e.target.classList.add("in");
        io.unobserve(e.target);
      });
    }, { threshold: 0, rootMargin: "0px 0px -4% 0px" });
    root.classList.add("anim");
    // safety net: anything in or above the viewport is revealed within 250 ms, whatever the observer or frame timing did
    setInterval(function () {
      var list = document.querySelectorAll(".rv:not(.in)");
      for (var i = 0; i < list.length; i++) { var r = list[i].getBoundingClientRect(); if (r.top < innerHeight) list[i].classList.add("in"); }
    }, 250);
  }
  scan();
})();
