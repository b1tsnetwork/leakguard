// LeakGuard – Komfortfunktionen und Live-Aktualisierung (CSP: nur same-origin Skripte)
"use strict";

// LeakGuard nutzt keinen Service Worker. Fremde Registrierungen dieser Adresse (z. B. von einer früher hier
// betriebenen Anwendung) blockieren sonst Anfragen und die Live-Verbindung – daher hier entfernen.
if ("serviceWorker" in navigator) {
  navigator.serviceWorker.getRegistrations().then((regs) => {
    if (!regs.length) return;
    Promise.all(regs.map((r) => r.unregister())).then(() => {
      if (window.caches) caches.keys().then((ks) => ks.forEach((k) => caches.delete(k)));
      if (navigator.serviceWorker.controller && !sessionStorage.getItem("lg-sw-reload")) {
        try { sessionStorage.setItem("lg-sw-reload", "1"); } catch (e) {}
        location.reload();
      }
    });
  }).catch(() => {});
}

document.addEventListener("click", async (ev) => {
  const sec = ev.target.closest("[data-secret]");
  if (sec) { sec.classList.toggle("revealed"); return; }
  const t = ev.target.closest("button, a, tr[data-href]");
  if (!t) return;

  if (t.matches("[data-confirm]") && !confirm(t.dataset.confirm)) {
    ev.preventDefault();
    return;
  }
  if (t.matches("[data-copy], [data-copy-secret]")) {
    const src = t.matches("[data-copy-secret]") ? t.parentElement.querySelector("[data-secret]") : t.parentElement.querySelector("code");
    const code = src.textContent;
    try {
      await navigator.clipboard.writeText(code);
    } catch {
      const ta = document.createElement("textarea");
      ta.value = code; document.body.appendChild(ta); ta.select(); document.execCommand("copy"); ta.remove();
    }
    t.textContent = "Kopiert ✓"; t.classList.add("copied");
    setTimeout(() => { t.textContent = "Kopieren"; t.classList.remove("copied"); }, 1800);
    return;
  }
  if (t.matches("[data-toggle-pw]")) {
    const inp = t.parentElement.querySelector("input");
    const show = inp.type === "password";
    inp.type = show ? "text" : "password";
    t.textContent = show ? "verbergen" : "anzeigen";
    return;
  }
  if (t.matches("[data-fill-identifier]")) {
    const f = document.getElementById("recheck-identifier");
    if (f) { f.value = t.dataset.fillIdentifier; f.closest("section").scrollIntoView({ behavior: "smooth" }); f.form.password.focus(); }
    return;
  }
  if (t.matches("[data-print]")) { window.print(); return; }
  if (t.matches("[data-fill]")) {
    const target = document.getElementById(t.dataset.fill);
    if (target) { target.value = t.dataset.value || ""; target.focus(); }
    return;
  }
  if (t.matches("tr[data-href]") && !ev.target.closest("a, button, select, input, form")) {
    location.href = t.dataset.href;
  }
});

// Doppelte Absendungen verhindern
document.addEventListener("submit", (ev) => {
  const b = ev.submitter;
  if (b && !b.name) setTimeout(() => { b.disabled = true; }, 0);
});

// Auswahlfelder mit data-autosubmit senden das Formular sofort
document.addEventListener("change", (ev) => {
  const el = ev.target;
  if (el.matches("[data-autosubmit]")) {
    if (el.dataset.confirm && !confirm(el.dataset.confirm)) { el.form.reset(); return; }
    el.form.requestSubmit();
  }
});

// ---------- Restzeiten (data-due = Unix-Sekunden) ----------
function fmtDue(sec) {
  let d = sec * 1000 - Date.now();
  const neg = d < 0;
  d = Math.abs(d);
  const m = Math.floor(d / 60000), h = Math.floor(m / 60), days = Math.floor(h / 24);
  let s;
  if (m < 60) s = m + " min";
  else if (h < 48) s = h + " h " + (m % 60) + " min";
  else s = days + " Tage " + (h % 24) + " h";
  return { text: neg ? "überfällig seit " + s : "in " + s, neg, soon: !neg && d < 6 * 3600 * 1000 };
}
function tickDue() {
  document.querySelectorAll("[data-due]").forEach((el) => {
    const v = parseInt(el.dataset.due, 10);
    if (!v || v < 0) return;
    const r = fmtDue(v);
    el.textContent = r.text;
    el.classList.toggle("due-over", r.neg);
    el.classList.toggle("due-soon", r.soon);
  });
  document.querySelectorAll("[data-clock]").forEach((el) => {
    el.textContent = new Date().toLocaleString("de-DE", { weekday: "short", day: "2-digit", month: "2-digit", hour: "2-digit", minute: "2-digit", second: "2-digit" });
  });
}
tickDue();
setInterval(tickDue, 1000);

// ---------- Live-Aktualisierung über Server-Sent Events ----------
// Seiten markieren aktualisierbare Bereiche mit data-live-region="<id>".
// Bei einem passenden Ereignis wird die Seite im Hintergrund neu geladen und nur diese Bereiche ersetzt –
// Bereiche, in denen gerade getippt wird, bleiben unangetastet.
(function () {
  if (!document.body.dataset.live || !window.EventSource) return;
  const badge = document.getElementById("livebadge");
  const scope = document.querySelector("[data-live-scope]");
  const incident = scope ? parseInt(scope.dataset.liveScope, 10) || 0 : -1; // -1 = keine Live-Seite
  let timer = null, busy = false, pending = false;

  function toast(text) {
    if (!text) return;
    const box = document.getElementById("toasts");
    const el = document.createElement("div");
    el.className = "toast";
    el.textContent = text;
    box.appendChild(el);
    setTimeout(() => el.classList.add("show"), 10);
    setTimeout(() => { el.classList.remove("show"); setTimeout(() => el.remove(), 400); }, 6000);
  }

  function busyIn(region) {
    const a = document.activeElement;
    if (a && region.contains(a) && a.matches("input, textarea, select")) return true;
    return [...region.querySelectorAll("textarea, input[type=text], input:not([type])")].some((f) => f.value && f.value !== f.defaultValue);
  }

  async function refresh() {
    if (busy) { pending = true; return; }
    busy = true;
    try {
      const res = await fetch(location.href, { headers: { "X-Live": "1" }, credentials: "same-origin" });
      if (res.redirected && res.url.includes("/login")) { location.reload(); return; }
      if (!res.ok) return;
      const doc = new DOMParser().parseFromString(await res.text(), "text/html");
      doc.querySelectorAll("[data-live-region]").forEach((fresh) => {
        const id = fresh.dataset.liveRegion;
        const cur = document.querySelector(`[data-live-region="${id}"]`);
        if (!cur || busyIn(cur)) return;
        const openDetails = [...cur.querySelectorAll("details[open][id]")].map((d) => d.id);
        cur.replaceWith(fresh);
        openDetails.forEach((did) => { const d = document.getElementById(did); if (d) d.open = true; });
        fresh.classList.add("flash-update");
        setTimeout(() => fresh.classList.remove("flash-update"), 1200);
      });
      tickDue();
      document.dispatchEvent(new Event("lg:refreshed"));
    } catch (e) { /* offline – nächster Versuch beim nächsten Ereignis */ }
    finally {
      busy = false;
      if (pending) { pending = false; schedule(); }
    }
  }
  function schedule() { clearTimeout(timer); timer = setTimeout(refresh, 400); }

  function onEvent(e) {
    if (incident < 0) return;
    if (incident === 0 || e.incident === incident) {
      schedule();
      if (e.text) toast(e.text);
    }
  }
  function setBadge(on) { if (badge) badge.classList.toggle("on", on); }

  // Browser erlauben über HTTP/1.1 nur 6 gleichzeitige Verbindungen je Server. Jede Live-Verbindung belegt
  // dauerhaft eine davon – mit mehreren Tabs hängen sonst alle weiteren Anfragen.
  // Lösung: Nur EIN Tab je Browser (der „Leader“, ermittelt per Web Locks) hält die Live-Verbindung und
  // verteilt die Ereignisse per BroadcastChannel an alle anderen Tabs.
  const bc = window.BroadcastChannel ? new BroadcastChannel("lg-live") : null;
  if (bc) {
    bc.onmessage = (m) => {
      if (m.data.type === "event") onEvent(m.data.e);
      if (m.data.type === "state") setBadge(m.data.on);
      if (m.data.type === "hello" && leaderES) bc.postMessage({ type: "state", on: leaderES.readyState === 1 });
    };
  }
  let leaderES = null;
  function lead() {
    // Wird nur im Leader-Tab ausgeführt; die Sperre bleibt gehalten, bis der Tab geschlossen wird.
    return new Promise(() => {
      leaderES = new EventSource("/live");
      leaderES.onopen = () => { setBadge(true); bc && bc.postMessage({ type: "state", on: true }); };
      leaderES.onerror = () => { setBadge(false); bc && bc.postMessage({ type: "state", on: false }); };
      leaderES.addEventListener("change", (m) => {
        let e;
        try { e = JSON.parse(m.data); } catch { return; }
        onEvent(e);
        bc && bc.postMessage({ type: "event", e });
      });
      window.addEventListener("pagehide", () => { leaderES && leaderES.close(); });
    });
  }
  if (navigator.locks && bc) {
    navigator.locks.request("lg-live-leader", lead);
    bc.postMessage({ type: "hello" });
  } else {
    // Ältere Browser: Live-Verbindung nur im sichtbaren Tab halten.
    let es = null;
    const open = () => {
      if (es) return;
      es = new EventSource("/live");
      es.onopen = () => setBadge(true);
      es.onerror = () => setBadge(false);
      es.addEventListener("change", (m) => { try { onEvent(JSON.parse(m.data)); } catch {} });
    };
    const close = () => { if (es) { es.close(); es = null; setBadge(false); } };
    document.addEventListener("visibilitychange", () => { if (document.hidden) close(); else { open(); schedule(); } });
    window.addEventListener("pagehide", close);
    if (!document.hidden) open();
  }
  // Fallback: alle 60 s aktualisieren, falls Ereignisse verloren gingen (z. B. Proxy-Puffer)
  if (incident >= 0) setInterval(() => { if (!document.hidden) schedule(); }, 60000);
})();

// ---------- Lagewand: alles ohne Scrollen sichtbar ----------
// Panels mit data-pager und das Kachelraster (data-tiles) werden so aufgeteilt, dass nur ganze Einträge sichtbar
// sind. Passt nicht alles hinein, blättert das Panel automatisch weiter (Punkte oben rechts, Klick = weiter,
// Mauszeiger über dem Panel = Pause).
(function () {
  const root = document.querySelector(".wallroot");
  if (!root) return;
  const html = document.documentElement;
  const INTERVAL = 12000;
  const small = window.matchMedia("(max-width: 900px), (max-height: 520px)");
  const state = new Map();

  try {
    if (localStorage.getItem("lg-wall-theme") === "light") { html.classList.remove("wall-dark"); html.classList.add("wall-light"); }
  } catch (e) { /* kein Speicher – dunkel bleibt Standard */ }

  function toggleFS() {
    if (document.fullscreenElement) document.exitFullscreen();
    else if (html.requestFullscreen) html.requestFullscreen().catch(() => {});
  }
  document.addEventListener("click", (e) => {
    if (e.target.closest("[data-theme-toggle]")) {
      const dark = html.classList.toggle("wall-dark");
      html.classList.toggle("wall-light", !dark);
      try { localStorage.setItem("lg-wall-theme", dark ? "dark" : "light"); } catch (err) { /* egal */ }
    }
    if (e.target.closest("[data-fullscreen]")) toggleFS();
  });
  document.addEventListener("keydown", (e) => {
    if (e.target.closest && e.target.closest("input, textarea, select")) return;
    if (e.key === "f" || e.key === "F") toggleFS();
  });

  // Mauszeiger nach 4 s Ruhe ausblenden (Großbildschirm)
  let idleT = null;
  const wake = () => { document.body.classList.remove("idle"); clearTimeout(idleT); idleT = setTimeout(() => document.body.classList.add("idle"), 4000); };
  document.addEventListener("mousemove", wake); wake();

  function listPages(el) {
    const items = [...el.children];
    items.forEach((i) => { i.hidden = false; });
    const H = el.clientHeight;
    if (small.matches || el.scrollHeight <= H + 1) return [items];
    const pages = [];
    let cur = [], top = null;
    for (const it of items) {
      const t = it.offsetTop, b = t + it.offsetHeight;
      if (top === null) top = t;
      if (b - top > H && cur.length) { pages.push(cur); cur = []; top = t; }
      cur.push(it);
    }
    if (cur.length) pages.push(cur);
    return pages;
  }

  function tilePages(el) {
    const tiles = [...el.children].filter((c) => c.classList.contains("wtile"));
    tiles.forEach((t) => { t.hidden = false; });
    el.style.gridTemplateColumns = el.style.gridTemplateRows = el.style.gridAutoRows = "";
    if (small.matches || !tiles.length) return [tiles];
    const fs = parseFloat(getComputedStyle(html).fontSize) || 16;
    const W = el.clientWidth, H = el.clientHeight, gap = 0.55 * fs;
    const maxC = Math.max(1, Math.floor((W + gap) / (21 * fs + gap)));
    const maxR = Math.max(1, Math.floor((H + gap) / (12.5 * fs + gap)));
    const n = tiles.length;
    let c = maxC, r = maxR;
    if (n <= maxC * maxR) {
      let best = -Infinity;
      for (let cc = 1; cc <= Math.min(maxC, n); cc++) {
        const rr = Math.ceil(n / cc);
        if (rr > maxR) continue;
        const w = (W - (cc - 1) * gap) / cc, h = (H - (rr - 1) * gap) / rr;
        const score = -Math.abs(Math.log(w / h / 1.7)) - 0.25 * (cc * rr - n);
        if (score > best) { best = score; c = cc; r = rr; }
      }
      // Einzelne Kacheln nicht ins Riesenhafte ziehen
      r = Math.max(r, Math.min(maxR, Math.ceil(H / (30 * fs))));
    }
    el.style.gridTemplateColumns = `repeat(${c}, minmax(0, 1fr))`;
    el.style.gridTemplateRows = `repeat(${r}, minmax(0, 1fr))`;
    el.style.gridAutoRows = "0";
    const per = c * r, pages = [];
    for (let i = 0; i < n; i += per) pages.push(tiles.slice(i, i + per));
    return pages;
  }

  function setup(el, pages) {
    const key = el.dataset.liveRegion || "";
    const old = state.get(key);
    if (old) clearInterval(old.timer);
    const panel = el.closest(".wpanel");
    const ind = panel ? panel.querySelector(".pg-ind") : null;
    // Feeds (neueste oben) springen bei neuen Inhalten auf Seite 1, damit Neues sofort sichtbar ist.
    const fresh = old && old.el !== el && el.hasAttribute("data-pager-top");
    const st = { el, pages, page: old && !fresh ? Math.min(old.page, pages.length - 1) : 0, timer: null, paused: false };
    state.set(key, st);
    const show = () => {
      const on = new Set(st.pages[st.page]);
      st.pages.forEach((p) => p.forEach((i) => { i.hidden = !on.has(i); }));
      if (!ind) return;
      if (st.pages.length < 2) { ind.textContent = ""; ind.className = "pg-ind"; ind.onclick = null; return; }
      const dots = st.pages.length <= 6 ? st.pages.map((_, i) => `<i class="${i === st.page ? "on" : ""}"></i>`).join("") : "";
      ind.innerHTML = dots +
        `<span>${st.page + 1}/${st.pages.length}</span><span class="pg-bar"><u></u></span>`;
      ind.style.setProperty("--pg-ms", INTERVAL + "ms");
      ind.className = "pg-ind";
      void ind.offsetWidth; // Fortschrittsbalken neu starten
      ind.className = "pg-ind pg-run" + (st.paused ? " pg-paused" : "");
      ind.title = "Weiterblättern";
      ind.onclick = () => { st.page = (st.page + 1) % st.pages.length; show(); restart(); };
    };
    const restart = () => {
      clearInterval(st.timer);
      if (st.pages.length > 1) st.timer = setInterval(() => { if (!st.paused) { st.page = (st.page + 1) % st.pages.length; show(); } }, INTERVAL);
    };
    if (panel) {
      panel.onmouseenter = () => { st.paused = true; ind && ind.classList.add("pg-paused"); };
      panel.onmouseleave = () => { st.paused = false; ind && ind.classList.remove("pg-paused"); };
    }
    show();
    restart();
  }

  function layoutAll() {
    root.querySelectorAll("[data-tiles]").forEach((el) => setup(el, tilePages(el)));
    root.querySelectorAll("[data-pager]").forEach((el) => setup(el, listPages(el)));
  }
  let rt = null;
  const later = () => { clearTimeout(rt); rt = setTimeout(layoutAll, 150); };
  layoutAll();
  window.addEventListener("load", layoutAll);
  window.addEventListener("resize", later);
  document.addEventListener("fullscreenchange", later);
  document.addEventListener("lg:refreshed", layoutAll);
  if (document.fonts && document.fonts.ready) document.fonts.ready.then(layoutAll);
})();
