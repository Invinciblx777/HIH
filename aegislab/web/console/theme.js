/* AegisLab console, scroll motion only. Never touches data or handlers: it adds classes (.rv, .in) and two CSS variables.
   If anything here fails the page stays fully visible: reveal classes are only applied once the observer exists. */
(function () {
  "use strict";
  var root = document.documentElement;
  var reduce = window.matchMedia && matchMedia("(prefers-reduced-motion: reduce)").matches;

  // scroll progress bar, header state, cloud parallax (one rAF per frame)
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
      root.style.setProperty("--scroll", y);
      root.classList.toggle("scrolled", y > 8);
      ticking = false;
    });
  }
  addEventListener("scroll", onScroll, { passive: true });
  addEventListener("resize", onScroll, { passive: true });
  onScroll();

  if (reduce || !("IntersectionObserver" in window)) return;

  var SEL = ".intro, .statement, .sec, .card, .gwrap, .table-wrap, .verdict, .strip, .note, .empty, .persp, .life, .cols > *";
  var io = new IntersectionObserver(function (entries) {
    entries.forEach(function (e) {
      if (!e.isIntersecting) return;
      e.target.classList.add("in");
      io.unobserve(e.target);
    });
  }, { threshold: 0.08, rootMargin: "0px 0px -6% 0px" });

  function scan() {
    var main = document.getElementById("main");
    if (!main) return;
    var nodes = main.querySelectorAll(SEL), batch = 0;
    for (var i = 0; i < nodes.length; i++) {
      var el = nodes[i];
      if (el.dataset.rv) continue;
      // skip nested items already inside a revealing ancestor that is itself a target (keeps motion calm)
      el.dataset.rv = "1";
      var r = el.getBoundingClientRect();
      var inView = r.top < innerHeight && r.bottom > 0;
      el.classList.add("rv");
      el.style.setProperty("--rd", Math.min(batch++ * 70, 420) + "ms");
      if (inView) { var t = el; requestAnimationFrame(function () { requestAnimationFrame(function () { t.classList.add("in"); }); }); }
      else io.observe(el);
    }
  }

  var pending = 0;
  function schedule() { clearTimeout(pending); pending = setTimeout(scan, 30); }
  var main = document.getElementById("main");
  if (main) new MutationObserver(schedule).observe(main, { childList: true, subtree: true });
  root.classList.add("anim");
  scan();
  // safety net: nothing may stay hidden if an observer callback is missed
  setTimeout(function () {
    document.querySelectorAll(".rv:not(.in)").forEach(function (el) {
      var r = el.getBoundingClientRect();
      if (r.top < innerHeight) el.classList.add("in");
    });
  }, 1800);
})();
