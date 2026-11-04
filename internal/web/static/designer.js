// LeakGuard Workflow-Designer
// Ansichten: Phasen-Board · Ablaufgraph · Stabsmatrix · Einstellungen.
// Modus "design": gestalten (Admin) bzw. ansehen; Modus "run": Ablauf eines konkreten Vorfalls mit Zuständen.
"use strict";
(function () {
  const dataEl = document.getElementById("wf-data");
  const root = document.getElementById("wfd-app");
  if (!dataEl || !root) return;
  const D = JSON.parse(dataEl.textContent);
  const RUN = D.mode === "run";
  const RO = !!D.readonly || RUN;
  const L = D.labels;
  const PH = L.phases;
  const FIELDS = {};
  L.fields.forEach((f) => { FIELDS[f.key] = f; });
  const positions = D.positions || [];
  const POS = {};
  positions.forEach((p) => { POS[p.key] = p; });
  const RUNST = D.run || {};
  const STAFFRUN = D.staff_run || {};
  const csrfEl = document.querySelector('input[name="csrf"]');
  const CSRF = csrfEl ? csrfEl.value : "";
  const store = (k, v) => {
    try {
      if (v === undefined) return localStorage.getItem(k);
      localStorage.setItem(k, v);
    } catch (e) { /* kein Speicher */ }
    return null;
  };

  let def = normalize(D.def);
  const S = {
    view: store("wfd-view-" + D.mode) || (RUN ? "graph" : "board"), sel: null, sim: null, dirty: false, saving: false,
    issues: D.issues || [], undo: [], redo: [], q: "", hiPos: null, zoom: parseFloat(store("wfd-zoom-" + D.mode) || "1") || 1, msg: null, scroll: {},
  };
  if (!["board", "graph", "staff", "settings"].includes(S.view) || (RUN && ["staff", "settings"].includes(S.view))) S.view = RUN ? "graph" : "board";

  // ---------- Hilfen ----------
  function h(tag, attrs, ...kids) {
    const el = document.createElement(tag);
    let value, checked;
    for (const [k, v] of Object.entries(attrs || {})) {
      if (v == null || v === false) continue;
      if (k === "class") el.className = v;
      else if (k === "style") Object.assign(el.style, v);
      else if (k === "value") value = v;
      else if (k === "checked") checked = v;
      else if (k.startsWith("on")) el.addEventListener(k.slice(2), v);
      else if (k.startsWith("--")) el.style.setProperty(k, v);
      else el.setAttribute(k, v === true ? "" : v);
    }
    for (const c of kids.flat(3)) {
      if (c == null || c === false) continue;
      el.append(c.nodeType ? c : document.createTextNode(String(c)));
    }
    if (value !== undefined) el.value = value;
    if (checked !== undefined) el.checked = !!checked;
    return el;
  }
  // append mit Arrays und ohne false/null (DOM-append würde "false" als Text einfügen)
  function ap(el, ...kids) {
    for (const c of kids.flat(3)) {
      if (c == null || c === false || c === true) continue;
      el.append(c.nodeType ? c : document.createTextNode(String(c)));
    }
    return el;
  }
  const NS = "http://www.w3.org/2000/svg";
  function sv(tag, attrs, ...kids) {
    const el = document.createElementNS(NS, tag);
    for (const [k, v] of Object.entries(attrs || {})) {
      if (v == null || v === false) continue;
      if (k.startsWith("on")) el.addEventListener(k.slice(2), v);
      else if (k.startsWith("--")) el.style.setProperty(k, v);
      else el.setAttribute(k, v);
    }
    kids.flat(3).forEach((c) => c && el.append(c.nodeType ? c : document.createTextNode(String(c))));
    return el;
  }
  const phaseIdx = (k) => PH.findIndex((p) => p.key === k);
  const phaseLabel = (k) => (PH.find((p) => p.key === k) || { label: k }).label;
  const lab = (list, k) => ((L[list] || []).find((o) => o.key === k) || { label: k }).label;
  const stepById = (id) => def.steps.find((s) => s.id === id);
  const reqById = (id) => def.staff.find((r) => r.id === id);
  const posLabel = (k) => (POS[k] ? POS[k].label : k || "–");
  const posColor = (k) => (POS[k] && POS[k].color) || "#94a3b8";
  const fmtH = (n) => (n >= 48 && n % 24 === 0 ? n / 24 + " Tage" : n + " h");
  const uid = (p) => {
    let id;
    do id = p + Math.random().toString(36).slice(2, 8); while (stepById(id) || reqById(id));
    return id;
  };
  const KIND_ICON = { aufgabe: "▢", entscheidung: "◆", pruefung: "✓", meldung: "➚", kommunikation: "✉" };

  function normalize(d) {
    d = d || {};
    d.match = d.match || {};
    d.match.categories = d.match.categories || [];
    d.match.when = normWhen(d.match.when);
    d.match.priority = d.match.priority || 0;
    d.steps = (d.steps || []).map((s) => Object.assign({ kind: "aufgabe", priority: "mittel", due_from: "kenntnis", due_hours: 0, depends_on: [], y: 0,
      mandatory: false, manual: false, why: "", ref: "", details: "", position: "" }, s, { when: normWhen(s.when), depends_on: s.depends_on || [] }));
    d.staff = (d.staff || []).map((r) => Object.assign({ need: "soll", why: "", ref: "", auto_add: false, role: "" }, r, { when: normWhen(r.when) }));
    return d;
  }
  function normWhen(w) {
    w = w || {};
    return { mode: w.mode || "all", rules: (w.rules || []).map((r) => ({ field: r.field, op: r.op, values: r.values || [] })) };
  }

  // ---------- Bedingungen ----------
  const sevRank = (s) => (/^P[1-4]$/.test(s || "") ? +s[1] : 9);
  function ruleMatch(r, f) {
    const v = r.values || [], first = v[0];
    switch (r.field) {
      case "severity":
        if (r.op === "min") return sevRank(f.severity) <= sevRank(first);
        if (r.op === "max") return sevRank(f.severity) >= sevRank(first) && sevRank(f.severity) < 9;
        return v.includes(f.severity);
      case "category": case "tlp": case "org_type": {
        const val = f[r.field];
        return r.op === "not_in" ? !v.includes(val) : v.includes(val);
      }
      case "regulation": {
        const any = v.some((x) => (f.regulations || []).includes(x));
        return r.op === "not_in" ? !any : any;
      }
      case "affected_users": {
        const n = parseInt(first, 10);
        if (isNaN(n)) return false;
        return r.op === "lt" ? (f.affected_users || 0) < n : (f.affected_users || 0) >= n;
      }
      default:
        return r.op === "false" ? !f[r.field] : !!f[r.field];
    }
  }
  function whenMatch(w, f) {
    const rs = (w && w.rules) || [];
    if (!rs.length) return true;
    return w.mode === "any" ? rs.some((r) => ruleMatch(r, f)) : rs.every((r) => ruleMatch(r, f));
  }
  function setLabel(set, key) {
    if (set === "tlp") return "TLP:" + key;
    return lab(set, key);
  }
  function ruleText(r) {
    const f = FIELDS[r.field];
    if (!f) return "?";
    if (f.type === "bool") return r.op === "false" ? "nicht: " + f.label : f.label;
    const vals = (r.values || []).map((x) => (f.type === "set" ? setLabel(f.set, x) : x));
    return f.label + " " + (L.ops[r.op] || r.op) + " " + (vals.join(", ") || "…");
  }
  function whenText(w) {
    const rs = (w && w.rules) || [];
    if (!rs.length) return "immer";
    return rs.map(ruleText).join(w.mode === "any" ? " oder " : " und ");
  }
  function applies(obj, kind) {
    if (RUN) {
      if (kind === "staff") return !STAFFRUN[obj.id] || STAFFRUN[obj.id].applies;
      return !RUNST[obj.id] || RUNST[obj.id].applies;
    }
    if (!S.sim) return true;
    return whenMatch(obj.when, S.sim);
  }

  // ---------- Prüfung (Spiegel der Server-Prüfung) ----------
  function validate() {
    const out = [];
    const add = (level, ref, msg) => out.push({ level, ref, msg });
    if (!def.name) add("error", "def", "Name fehlt");
    if (!/^[a-z0-9][a-z0-9_-]{0,63}$/.test(def.key || "")) add("error", "def", "Schlüssel: nur Kleinbuchstaben, Ziffern, - und _");
    const ids = {};
    def.steps.forEach((s) => {
      const ref = "step:" + s.id;
      if (ids[s.id]) add("error", ref, "Schritt-ID doppelt: " + s.id);
      ids[s.id] = s;
      if (!s.title.trim()) add("error", ref, "Schritt ohne Titel");
      if (s.position && !POS[s.position]) add("error", ref, `„${s.title}“: Stabsposition existiert nicht`);
      if (!s.position) add("warn", ref, `„${s.title}“: keine Stabsposition – niemand ist zuständig`);
      if (!s.why.trim()) add("warn", ref, `„${s.title}“: Begründung (Warum?) fehlt`);
      s.when.rules.forEach((r) => { if (FIELDS[r.field] && FIELDS[r.field].type !== "bool" && !r.values.length) add("error", ref, `„${s.title}“: Bedingung ohne Wert`); });
    });
    def.steps.forEach((s) => s.depends_on.forEach((d) => {
      const ds = ids[d];
      if (!ds) add("error", "step:" + s.id, `„${s.title}“: Vorgänger existiert nicht`);
      else if (phaseIdx(ds.phase) > phaseIdx(s.phase)) add("error", "step:" + s.id, `„${s.title}“ wartet auf „${ds.title}“ aus einer späteren Phase`);
    }));
    const c = findCycle();
    if (c) add("error", "step:" + c, `Zirkuläre Abhängigkeit bei „${stepById(c).title}“`);
    const seenPos = {};
    def.staff.forEach((r) => {
      const ref = "staff:" + r.id;
      if (seenPos[r.position] && !r.when.rules.length) add("warn", ref, `Stabsposition „${posLabel(r.position)}“ mehrfach angefordert – die Anforderung ohne Bedingung gilt immer`);
      seenPos[r.position] = true;
      if (!POS[r.position]) add("error", ref, "Stabsposition existiert nicht: " + r.position);
      if (!r.why.trim()) add("warn", ref, `${posLabel(r.position)}: Begründung (Warum im Stab?) fehlt`);
      r.when.rules.forEach((x) => { if (FIELDS[x.field] && FIELDS[x.field].type !== "bool" && !x.values.length) add("error", ref, posLabel(r.position) + ": Bedingung ohne Wert"); });
    });
    return out;
  }
  function findCycle() {
    const state = {};
    const visit = (id) => {
      if (state[id] === 1) return id;
      if (state[id] === 2) return null;
      state[id] = 1;
      const s = stepById(id);
      if (s) for (const d of s.depends_on) { if (stepById(d)) { const c = visit(d); if (c) return c; } }
      state[id] = 2;
      return null;
    };
    for (const s of def.steps) { const c = visit(s.id); if (c) return c; }
    return null;
  }
  // Würde „step wartet auf dep“ einen Zyklus erzeugen? (dep hängt bereits – direkt oder indirekt – von step ab)
  function wouldCycle(stepId, depId) {
    const seen = new Set();
    const walk = (id) => {
      if (id === stepId) return true;
      if (seen.has(id)) return false;
      seen.add(id);
      const s = stepById(id);
      return !!s && s.depends_on.some(walk);
    };
    return walk(depId);
  }
  function ancestors(id, acc = new Set()) {
    const s = stepById(id);
    if (!s) return acc;
    s.depends_on.forEach((d) => { if (!acc.has(d)) { acc.add(d); ancestors(d, acc); } });
    return acc;
  }
  function descendants(id, acc = new Set()) {
    def.steps.forEach((s) => { if (s.depends_on.includes(id) && !acc.has(s.id)) { acc.add(s.id); descendants(s.id, acc); } });
    return acc;
  }

  // ---------- Änderungen ----------
  let editSnap = false;
  function snapshot() {
    S.undo.push(JSON.stringify(def));
    if (S.undo.length > 150) S.undo.shift();
    S.redo = [];
  }
  function mutate(fn) {
    if (RO) return;
    snapshot();
    fn();
    S.dirty = true;
    S.issues = validate();
    render();
  }
  // Tippen im Inspektor: nur ein Rückgängig-Schritt pro Feld, Inspektor nicht neu aufbauen (Fokus bleibt).
  function live(fn) {
    if (RO) return;
    if (!editSnap) { snapshot(); editSnap = true; }
    fn();
    S.dirty = true;
    S.issues = validate();
    render({ keepInspector: true });
  }
  function undo() {
    if (!S.undo.length) return;
    S.redo.push(JSON.stringify(def));
    def = JSON.parse(S.undo.pop());
    S.dirty = true;
    S.issues = validate();
    render();
  }
  function redo() {
    if (!S.redo.length) return;
    S.undo.push(JSON.stringify(def));
    def = JSON.parse(S.redo.pop());
    S.dirty = true;
    S.issues = validate();
    render();
  }
  function select(t, id) {
    S.sel = t ? { t, id } : null;
    editSnap = false;
    render();
  }
  const isSel = (t, id) => S.sel && S.sel.t === t && S.sel.id === id;

  function stepsIn(phase) {
    return def.steps.filter((s) => s.phase === phase).sort((a, b) => (a.y || 0) - (b.y || 0));
  }
  function relayout(phase) { stepsIn(phase).forEach((s, i) => { s.y = i * 96; }); }

  function addStep(phase, pos) {
    mutate(() => {
      const s = normalize({ steps: [{ id: uid("s_"), title: "Neuer Schritt", phase, position: pos || "", y: stepsIn(phase).length * 96 }] }).steps[0];
      def.steps.push(s);
      S.sel = { t: "step", id: s.id };
    });
    setTimeout(() => { const t = document.querySelector(".wfd-insp [name=title]"); if (t) { t.focus(); t.select(); } }, 30);
  }
  function addReq(position, phase) {
    const p = POS[position];
    if (!p) return;
    const existing = def.staff.find((r) => r.position === position && !r.when.rules.length);
    if (existing) {
      mutate(() => { existing.phase = phase; S.sel = { t: "staff", id: existing.id }; });
      return;
    }
    mutate(() => {
      const r = normalize({ staff: [{ id: uid("st_"), position, need: "soll", phase, why: p.why || "", ref: p.ref || "", role: p.role || "" }] }).staff[0];
      def.staff.push(r);
      S.sel = { t: "staff", id: r.id };
    });
  }
  function moveStep(id, phase, index) {
    mutate(() => {
      const s = stepById(id);
      const old = s.phase;
      s.phase = phase;
      const list = stepsIn(phase).filter((x) => x !== s);
      list.splice(Math.max(0, Math.min(index, list.length)), 0, s);
      list.forEach((x, i) => { x.y = i * 96; });
      if (old !== phase) relayout(old);
    });
  }
  function addDep(stepId, depId) {
    const s = stepById(stepId), d = stepById(depId);
    if (!s || !d || stepId === depId) return;
    if (s.depends_on.includes(depId)) return;
    if (phaseIdx(d.phase) > phaseIdx(s.phase)) return flash(`„${s.title}“ kann nicht auf einen Schritt aus einer späteren Phase warten.`, true);
    if (wouldCycle(stepId, depId)) return flash("Diese Verbindung würde eine Schleife erzeugen.", true);
    mutate(() => { s.depends_on.push(depId); S.sel = { t: "edge", id: depId + ">" + stepId }; });
  }
  function removeSel() {
    if (!S.sel || RO) return;
    const { t, id } = S.sel;
    if (t === "step") {
      const s = stepById(id);
      const dependents = def.steps.filter((x) => x.depends_on.includes(id));
      if (dependents.length && !confirm(`„${s.title}“ löschen? ${dependents.length} Schritt(e) warten darauf – die Verbindungen werden entfernt.`)) return;
      mutate(() => {
        def.steps = def.steps.filter((x) => x.id !== id);
        def.steps.forEach((x) => { x.depends_on = x.depends_on.filter((d) => d !== id); });
        relayout(s.phase);
        S.sel = null;
      });
    } else if (t === "staff") {
      mutate(() => { def.staff = def.staff.filter((r) => r.id !== id); S.sel = null; });
    } else if (t === "edge") {
      const [from, to] = id.split(">");
      mutate(() => { const s = stepById(to); if (s) s.depends_on = s.depends_on.filter((d) => d !== from); S.sel = null; });
    }
  }
  function duplicate() {
    if (!S.sel || S.sel.t !== "step" || RO) return;
    const s = stepById(S.sel.id);
    mutate(() => {
      const c = JSON.parse(JSON.stringify(s));
      c.id = uid("s_");
      c.title = s.title + " (Kopie)";
      c.y = (s.y || 0) + 1;
      def.steps.push(c);
      relayout(c.phase);
      S.sel = { t: "step", id: c.id };
    });
  }
  function autoLayout() {
    mutate(() => {
      PH.forEach((ph) => {
        const list = stepsIn(ph.key);
        const inPhase = new Set(list.map((s) => s.id));
        const depth = {};
        const d = (s) => {
          if (depth[s.id] != null) return depth[s.id];
          depth[s.id] = 0;
          const v = s.depends_on.filter((x) => inPhase.has(x)).map((x) => d(stepById(x)) + 1);
          depth[s.id] = v.length ? Math.max(...v) : 0;
          return depth[s.id];
        };
        list.forEach(d);
        list.sort((a, b) => depth[a.id] - depth[b.id] || (a.y || 0) - (b.y || 0)).forEach((s, i) => { s.y = i * 96; });
      });
    });
  }

  let flashT = null;
  function flash(text, err) {
    S.msg = { text, err };
    renderBar();
    clearTimeout(flashT);
    flashT = setTimeout(() => { S.msg = null; renderBar(); }, 5000);
  }

  // ---------- Speichern ----------
  async function save() {
    if (RO || S.saving) return false;
    S.saving = true;
    renderBar();
    let ok = false;
    try {
      const body = new URLSearchParams({ csrf: CSRF, def: JSON.stringify(def) });
      const res = await fetch(`/workflows/${D.workflow}/draft`, { method: "POST", body, credentials: "same-origin" });
      const j = await res.json();
      if (!j.ok) {
        flash(j.error || "Speichern fehlgeschlagen", true);
        if (j.issues) S.issues = j.issues;
      } else {
        ok = true;
        S.dirty = false;
        S.issues = j.issues || [];
        const sel = S.sel;
        def = normalize(j.def);
        S.sel = sel;
        D.status = "entwurf";
        document.querySelectorAll("[data-needs-draft]").forEach((e) => { e.hidden = false; });
        document.querySelectorAll("[data-status-label]").forEach((e) => { e.textContent = "Entwurf (nicht veröffentlicht)"; e.className = "tag warn"; });
        document.querySelectorAll("[data-wf-name]").forEach((e) => { e.textContent = def.name; });
        flash("Entwurf gespeichert · " + j.saved);
      }
    } catch (e) {
      flash("Netzwerkfehler – nicht gespeichert", true);
    }
    S.saving = false;
    render();
    return ok;
  }
  document.querySelectorAll("form[data-publish]").forEach((f) => {
    f.addEventListener("submit", async (e) => {
      e.preventDefault();
      const btn = e.submitter;
      const reenable = () => setTimeout(() => { if (btn) btn.disabled = false; }, 20);
      if (S.dirty && !(await save())) return reenable();
      if (S.issues.some((i) => i.level === "error")) { flash("Bitte zuerst die Fehler beheben (Prüfung).", true); showIssues(); return reenable(); }
      f.submit();
    });
  });
  window.addEventListener("beforeunload", (e) => { if (S.dirty) { e.preventDefault(); e.returnValue = ""; } });

  // ---------- Tastatur ----------
  document.addEventListener("keydown", (e) => {
    const typing = e.target.closest && e.target.closest("input, textarea, select, [contenteditable]");
    const mod = e.ctrlKey || e.metaKey;
    if (mod && e.key.toLowerCase() === "s") { e.preventDefault(); save(); return; }
    if (typing) return;
    if (mod && e.key.toLowerCase() === "z") { e.preventDefault(); e.shiftKey ? redo() : undo(); }
    else if (mod && e.key.toLowerCase() === "y") { e.preventDefault(); redo(); }
    else if (mod && e.key.toLowerCase() === "d") { e.preventDefault(); duplicate(); }
    else if (e.key === "Delete" || e.key === "Backspace") { if (S.sel) { e.preventDefault(); removeSel(); } }
    else if (e.key === "Escape") select(null);
  });

  // ---------- Rendering ----------
  let bar, simBar, pal, main, insp;
  function mount() {
    root.textContent = "";
    bar = h("div", { class: "wfd-bar" });
    simBar = h("div", { class: "wfd-sim", hidden: true });
    pal = h("aside", { class: "wfd-pal" });
    main = h("div", { class: "wfd-main" });
    insp = h("aside", { class: "wfd-insp" });
    ap(root, bar, simBar, h("div", { class: "wfd-body" + (RUN ? " run" : "") }, pal, main, insp));
    render();
  }
  function render(opt = {}) {
    renderBar();
    renderSim();
    renderPalette();
    const keep = main.querySelector(".wg, .wb, .wm");
    if (keep) S.scroll[S.view] = [keep.scrollLeft, keep.scrollTop];
    main.textContent = "";
    main.append(S.view === "graph" ? renderGraph() : S.view === "staff" ? renderMatrix() : S.view === "settings" ? renderSettings() : renderBoard());
    const nw = main.querySelector(".wg, .wb, .wm");
    if (nw && S.scroll[S.view]) { nw.scrollLeft = S.scroll[S.view][0]; nw.scrollTop = S.scroll[S.view][1]; }
    if (!opt.keepInspector) renderInspector();
  }

  function renderBar() {
    if (!bar) return;
    const errs = S.issues.filter((i) => i.level === "error").length;
    const warns = S.issues.length - errs;
    const views = [["board", "Phasen-Board", "Spalten = Phasen, Karten = Schritte"], ["graph", "Ablaufgraph", "Abhängigkeiten als Pfeile"]];
    if (!RUN) views.push(["staff", "Stabsmatrix", "Wer gehört ab wann in den Stab?"], ["settings", "Einstellungen", "Name, automatische Zuordnung"]);
    bar.textContent = "";
    ap(bar, 
      h("div", { class: "wfd-views", role: "tablist" }, views.map(([k, l, t]) => h("button", { type: "button", class: S.view === k ? "on" : "", title: t, role: "tab",
        onclick: () => { S.view = k; store("wfd-view-" + D.mode, k); render(); } }, l))),
      h("input", { type: "search", class: "wfd-search", placeholder: "Schritte suchen …", value: S.q, oninput: (e) => { S.q = e.target.value.toLowerCase(); render({ keepInspector: true }); } }),
      !RUN && h("button", { type: "button", class: "wbtn2" + (S.sim ? " on" : ""), title: "Szenario durchspielen: Welche Schritte und Stabsstellen gelten für einen Vorfall mit diesen Merkmalen?",
        onclick: () => { S.sim = S.sim ? null : { category: (def.match.categories[0] || (L.category[0] || {}).key), severity: "P2", regulations: [] }; render(); } }, "▶ Vorschau"),
      !RO && h("button", { type: "button", class: "wbtn2", title: "Schritte und Stabsanforderungen aus der Bibliothek oder anderen Workflows übernehmen", onclick: () => openPort() }, "⇩ Bausteine übernehmen"),
      !RO && h("span", { class: "wfd-grp" },
        h("button", { type: "button", class: "wbtn2", title: "Rückgängig (Strg+Z)", disabled: !S.undo.length, onclick: undo }, "↶"),
        h("button", { type: "button", class: "wbtn2", title: "Wiederholen (Strg+Y)", disabled: !S.redo.length, onclick: redo }, "↷")),
      h("button", { type: "button", class: "wfd-issues " + (errs ? "err" : warns ? "warn" : "ok"), title: "Prüfung anzeigen", onclick: showIssues },
        errs ? `✖ ${errs} Fehler` : "✓ Gültig", warns ? ` · ${warns} Hinweise` : ""),
      h("span", { class: "wfd-msg" + (S.msg && S.msg.err ? " err" : "") }, S.msg ? S.msg.text : S.dirty ? "Ungespeicherte Änderungen" : ""),
      !RO && h("button", { type: "button", class: "btn primary small", disabled: S.saving || !S.dirty, onclick: save, title: "Als Entwurf speichern (Strg+S)" },
        S.saving ? "Speichert …" : "Entwurf speichern"),
    );
  }
  function showIssues() { select(null); const el = insp.querySelector(".wi-issues"); if (el) el.scrollIntoView({ block: "start" }); }

  function renderSim() {
    simBar.hidden = !S.sim;
    simBar.textContent = "";
    if (!S.sim) return;
    const f = S.sim;
    const upd = (k, v) => { f[k] = v; render({ keepInspector: true }); renderInspectorIfIdle(); };
    const bools = ["personal_data", "crisis", "impact_a", "impact_c", "compromised", "classified", "confidential", "nis2"];
    ap(simBar, 
      h("b", null, "Vorschau-Szenario:"),
      h("label", null, "Kategorie ", h("select", { onchange: (e) => upd("category", e.target.value), value: f.category }, L.category.map((c) => h("option", { value: c.key }, c.label)))),
      h("label", null, "Schwere ", h("select", { onchange: (e) => upd("severity", e.target.value), value: f.severity }, L.severities.map((c) => h("option", { value: c.key }, c.label)))),
      bools.map((k) => h("label", { class: "wfd-chk" }, h("input", { type: "checkbox", checked: !!f[k], onchange: (e) => upd(k, e.target.checked) }), " " + FIELDS[k].label)),
      h("label", null, "Betroffene ", h("input", { type: "number", min: 0, value: f.affected_users || 0, style: { width: "6em" }, oninput: (e) => upd("affected_users", +e.target.value) })),
      h("span", { class: "wfd-simsum" }, simSummary()),
    );
  }
  function renderInspectorIfIdle() { if (!S.sel) renderInspector(); }
  function simSummary() {
    const st = def.steps.filter((s) => applies(s));
    const req = def.staff.filter((r) => applies(r, "staff"));
    return `→ ${st.length} von ${def.steps.length} Schritten, ${req.filter((r) => r.need === "pflicht").length} Pflicht- und ${req.filter((r) => r.need === "soll").length} Soll-Stabsstellen`;
  }
  const qMatch = (s) => S.q && (s.title.toLowerCase().includes(S.q) || (s.why || "").toLowerCase().includes(S.q));

  // ---------- Palette ----------
  function renderPalette() {
    pal.textContent = "";
    if (RUN) {
      ap(pal, h("h3", null, "Stab laut Workflow"), h("p", { class: "wfd-hint" }, "Soll-Ist-Abgleich der Stabsstellen, die der Workflow für diesen Vorfall vorsieht."));
      const list = def.staff.filter((r) => applies(r, "staff")).sort((a, b) => ["pflicht", "soll", "optional"].indexOf(a.need) - ["pflicht", "soll", "optional"].indexOf(b.need));
      list.forEach((r) => {
        const st = STAFFRUN[r.id] || {};
        const ok = (st.filled || []).length > 0;
        ap(pal, h("div", { class: "wp-run " + (ok ? "ok" : st.active ? "miss" : "later") + (isSel("staff", r.id) ? " sel" : ""), "--pc": posColor(r.position), onclick: () => select("staff", r.id) },
          h("span", { class: "wp-dot" }), h("div", null, h("b", null, posLabel(r.position)), h("small", null, lab("needs", r.need) + " ab " + phaseLabel(r.phase)),
            h("small", { class: "wp-fill" }, ok ? "✓ " + st.filled.join(", ") : st.active ? "✖ nicht besetzt" + (st.suggest && st.suggest.length ? " – vorgesehen: " + st.suggest.join(", ") : "") : "ab " + phaseLabel(r.phase)))));
      });
      if (!list.length) ap(pal, h("p", { class: "wfd-hint" }, "Keine Stabsanforderungen für diesen Vorfall."));
      return;
    }
    ap(pal, h("h3", null, "Stabspositionen"),
      h("p", { class: "wfd-hint" }, RO ? "Klick hebt die Schritte der Position hervor." :
        "Ziehen auf eine Karte = zuständig. Ziehen in den Kopf einer Phase = ab dort im Stab. Klick = Schritte hervorheben."));
    const groups = {};
    positions.forEach((p) => { (groups[p.group || "stab"] = groups[p.group || "stab"] || []).push(p); });
    L.groups.forEach((g) => {
      const list = groups[g.key];
      if (!list) return;
      ap(pal, h("div", { class: "wp-group" }, g.label));
      list.forEach((p) => {
        const n = def.steps.filter((s) => s.position === p.key).length;
        const req = def.staff.find((r) => r.position === p.key);
        ap(pal, h("div", { class: "wp" + (S.hiPos === p.key ? " on" : ""), draggable: RO ? null : "true", "--pc": p.color || "#94a3b8",
          title: (p.why || p.description || "") + (p.holders && p.holders.length ? "\nVorgesehene Besetzung: " + p.holders.join(", ") : ""),
          ondragstart: (e) => { e.dataTransfer.setData("text/wf-pos", p.key); e.dataTransfer.effectAllowed = "copy"; },
          onclick: () => { S.hiPos = S.hiPos === p.key ? null : p.key; render({ keepInspector: true }); } },
          h("span", { class: "wp-short" }, p.short || p.label.slice(0, 3)),
          h("span", { class: "wp-label" }, p.label),
          h("span", { class: "wp-meta" }, req ? h("i", { class: "need-" + req.need, title: lab("needs", req.need) + " ab " + phaseLabel(req.phase) }, req.need === "pflicht" ? "P" : req.need === "soll" ? "S" : "O") : null, n ? n : "")));
      });
    });
    ap(pal, h("a", { class: "wfd-hint", href: "/workflows/positions" }, "Stabspositionen verwalten →"));
  }

  // ---------- Phasen-Board ----------
  function renderBoard() {
    const board = h("div", { class: "wb" });
    PH.forEach((ph, i) => {
      const steps = stepsIn(ph.key);
      const appl = steps.filter((s) => applies(s));
      const mand = appl.filter((s) => s.mandatory);
      const reqs = def.staff.filter((r) => r.phase === ph.key);
      const cur = RUN && ph.key === D.phase;
      const list = h("div", { class: "wb-list", "data-phase": ph.key }, steps.map(card));
      if (!RO) dropList(list, ph.key);
      const staffZone = h("div", { class: "wb-staff", title: "Stabspositionen, die ab dieser Phase im Stab sein sollen" },
        reqs.map(staffChip), !RO && !reqs.length ? h("span", { class: "wb-staffhint" }, "Position hierher ziehen") : null);
      if (!RO) {
        staffZone.addEventListener("dragover", (e) => { if (e.dataTransfer.types.includes("text/wf-pos")) { e.preventDefault(); staffZone.classList.add("over"); } });
        staffZone.addEventListener("dragleave", () => staffZone.classList.remove("over"));
        staffZone.addEventListener("drop", (e) => { const k = e.dataTransfer.getData("text/wf-pos"); staffZone.classList.remove("over"); if (k) { e.preventDefault(); addReq(k, ph.key); } });
      }
      ap(board, h("section", { class: "wb-col" + (cur ? " cur" : "") + (RUN && phaseIdx(D.phase) > i ? " past" : "") },
        h("header", { class: "wb-head" },
          h("div", { class: "wb-ph" }, h("span", { class: "wb-num" }, i + 1), ph.label, cur ? h("span", { class: "wb-now" }, "aktuell") : null),
          h("div", { class: "wb-meta" }, `${appl.length} Schritt${appl.length === 1 ? "" : "e"}`,
            mand.length ? h("span", { class: "wb-gate", title: "Phasen-Gate: Diese Pflichtschritte müssen vor dem Wechsel in die nächste Phase erledigt (oder begründet verworfen) sein." }, mand.length + " Pflicht") : null)),
        staffZone, list,
        !RO ? h("button", { type: "button", class: "wb-add", onclick: () => addStep(ph.key) }, "+ Schritt") : null));
    });
    return board;
  }
  function staffChip(r) {
    const okA = applies(r, "staff");
    const st = RUN ? STAFFRUN[r.id] || {} : null;
    return h("button", { type: "button", class: `wb-chip need-${r.need}${isSel("staff", r.id) ? " sel" : ""}${okA ? "" : " na"}${st && st.active && !(st.filled || []).length ? " miss" : ""}`,
      "--pc": posColor(r.position), title: `${posLabel(r.position)} – ${lab("needs", r.need)}${r.when.rules.length ? "\nNur wenn: " + whenText(r.when) : ""}\n${r.why}`,
      onclick: (e) => { e.stopPropagation(); select("staff", r.id); } },
    (POS[r.position] && POS[r.position].short) || posLabel(r.position), r.when.rules.length ? " ⚑" : "", st && (st.filled || []).length ? " ✓" : "");
  }
  function card(s) {
    const p = POS[s.position];
    const okA = applies(s);
    const rs = RUN ? RUNST[s.id] || {} : null;
    const deps = s.depends_on.map(stepById).filter(Boolean);
    const cls = ["wc", isSel("step", s.id) ? "sel" : "", okA ? "" : "na", S.hiPos && s.position === S.hiPos ? "hi" : "", S.hiPos && s.position !== S.hiPos ? "dim" : "",
      qMatch(s) ? "match" : "", S.q && !qMatch(s) ? "dim" : "", rs ? "st-" + rs.state : ""].filter(Boolean).join(" ");
    const el = h("article", { class: cls, draggable: RO ? null : "true", "data-id": s.id, "--pc": p ? p.color || "#94a3b8" : "#cbd5e1", tabindex: 0,
      onclick: () => select("step", s.id), onkeydown: (e) => { if (e.key === "Enter") select("step", s.id); } },
    h("div", { class: "wc-top" },
      h("span", { class: "wc-kind k-" + s.kind, title: lab("kinds", s.kind) }, KIND_ICON[s.kind] || "▢"),
      h("span", { class: "wc-prio p-" + s.priority, title: "Priorität " + lab("priorities", s.priority) }),
      s.due_hours ? h("span", { class: "wc-due", title: "Frist " + fmtH(s.due_hours) + (s.due_from === "anlage" ? " ab Anlage der Aufgabe" : " ab Kenntnisnahme") }, "⏱ " + fmtH(s.due_hours)) : null,
      s.mandatory ? h("span", { class: "wc-badge mand", title: "Pflichtschritt – Phasen-Gate" }, "Pflicht") : null,
      s.manual ? h("span", { class: "wc-badge", title: "Wird nicht automatisch angelegt, sondern als Empfehlung angeboten" }, "manuell") : null),
    h("div", { class: "wc-title" }, s.title || "(ohne Titel)"),
    h("div", { class: "wc-foot" },
      p ? h("span", { class: "wc-pos", title: p.label }, p.short || p.label) : h("span", { class: "wc-pos none" }, "niemand zuständig"),
      s.when.rules.length ? h("span", { class: "wc-cond", title: "Nur wenn: " + whenText(s.when) }, "⚑ bedingt") : null,
      deps.length ? h("span", { class: "wc-deps", title: "Wartet auf: " + deps.map((d) => d.title).join("; ") }, "⟵ " + deps.length) : null,
      !s.why.trim() && !RUN ? h("span", { class: "wc-warn", title: "Begründung (Warum?) fehlt" }, "Warum?") : null),
    rs ? h("div", { class: "wc-state" }, rs.label + (rs.waiting && rs.waiting.length ? " – wartet auf: " + rs.waiting.join("; ") : "")) :
      (!okA ? h("div", { class: "wc-state" }, "entfällt in diesem Szenario") : null));
    if (!RO) {
      el.addEventListener("dragstart", (e) => { e.dataTransfer.setData("text/wf-step", s.id); e.dataTransfer.effectAllowed = "move"; el.classList.add("dragging"); });
      el.addEventListener("dragend", () => el.classList.remove("dragging"));
      el.addEventListener("dragover", (e) => { if (e.dataTransfer.types.includes("text/wf-pos")) { e.preventDefault(); e.stopPropagation(); el.classList.add("posover"); } });
      el.addEventListener("dragleave", () => el.classList.remove("posover"));
      el.addEventListener("drop", (e) => {
        const k = e.dataTransfer.getData("text/wf-pos");
        if (k) { e.preventDefault(); e.stopPropagation(); mutate(() => { s.position = k; S.sel = { t: "step", id: s.id }; }); }
      });
    }
    el.addEventListener("mouseenter", () => chainHighlight(s.id, true));
    el.addEventListener("mouseleave", () => chainHighlight(s.id, false));
    return el;
  }
  function chainHighlight(id, on) {
    const ids = on ? new Set([id, ...ancestors(id), ...descendants(id)]) : null;
    document.querySelectorAll(".wfd-main [data-id]").forEach((el) => {
      el.classList.toggle("chain", !!ids && ids.has(el.dataset.id) && el.dataset.id !== id);
    });
    document.querySelectorAll(".wfd-main [data-edge]").forEach((el) => {
      const [a, b] = el.dataset.edge.split(">");
      el.classList.toggle("chain", !!ids && ids.has(a) && ids.has(b));
    });
    const g = document.querySelector(".wfd-main .wg-svg");
    if (g) g.classList.toggle("chaining", !!on);
  }
  function dropList(list, phase) {
    let ind = null;
    const index = (e) => {
      const kids = [...list.querySelectorAll(".wc:not(.dragging)")];
      let i = kids.findIndex((k) => e.clientY < k.getBoundingClientRect().top + k.offsetHeight / 2);
      return i < 0 ? kids.length : i;
    };
    list.addEventListener("dragover", (e) => {
      if (!e.dataTransfer.types.includes("text/wf-step")) return;
      e.preventDefault();
      const i = index(e);
      if (!ind) ind = h("div", { class: "wb-ind" });
      const kids = [...list.querySelectorAll(".wc:not(.dragging)")];
      list.insertBefore(ind, kids[i] || null);
    });
    list.addEventListener("dragleave", (e) => { if (!list.contains(e.relatedTarget) && ind) { ind.remove(); ind = null; } });
    list.addEventListener("drop", (e) => {
      const id = e.dataTransfer.getData("text/wf-step");
      if (!id) return;
      e.preventDefault();
      const i = index(e);
      if (ind) { ind.remove(); ind = null; }
      moveStep(id, phase, i);
    });
  }

  // ---------- Ablaufgraph ----------
  const G = { LW: 264, NW: 228, NH: 74, TOP: 92, PAD: 18 };
  function nodeXY(s) { return { x: phaseIdx(s.phase) * G.LW + G.PAD, y: G.TOP + (s.y || 0) }; }
  function renderGraph() {
    const wrap = h("div", { class: "wg" });
    const maxY = Math.max(520, ...def.steps.map((s) => G.TOP + (s.y || 0) + G.NH + 60));
    const W = PH.length * G.LW, H = maxY;
    const z = S.zoom;
    const svgEl = sv("svg", { class: "wg-svg", width: W * z, height: H * z, viewBox: `0 0 ${W} ${H}`, role: "img", "aria-label": "Ablaufgraph" });
    ap(svgEl, sv("defs", null,
      sv("marker", { id: "wg-arrow", viewBox: "0 0 10 10", refX: 9, refY: 5, markerWidth: 7, markerHeight: 7, orient: "auto-start-reverse" }, sv("path", { d: "M0 0 L10 5 L0 10 z", class: "wg-arrowhead" })),
      sv("marker", { id: "wg-arrow-bad", viewBox: "0 0 10 10", refX: 9, refY: 5, markerWidth: 7, markerHeight: 7, orient: "auto-start-reverse" }, sv("path", { d: "M0 0 L10 5 L0 10 z", class: "wg-arrowhead bad" }))));
    // Phasenbahnen
    PH.forEach((ph, i) => {
      const steps = stepsIn(ph.key).filter((s) => applies(s));
      const mand = steps.filter((s) => s.mandatory).length;
      const cur = RUN && ph.key === D.phase;
      ap(svgEl, sv("rect", { x: i * G.LW, y: 0, width: G.LW, height: H, class: "wg-lane" + (i % 2 ? " alt" : "") + (cur ? " cur" : "") + (RUN && phaseIdx(D.phase) > i ? " past" : "") }));
      ap(svgEl, sv("text", { x: i * G.LW + 14, y: 26, class: "wg-lanetitle" }, `${i + 1}  ${ph.label}`));
      ap(svgEl, sv("text", { x: i * G.LW + 14, y: 44, class: "wg-lanemeta" }, `${steps.length} Schritte${mand ? " · " + mand + " Pflicht" : ""}${cur ? " · aktuell" : ""}`));
      // Stabsstellen, die ab dieser Phase gelten
      let cx = i * G.LW + 14;
      def.staff.filter((r) => r.phase === ph.key).forEach((r) => {
        const label = (POS[r.position] && POS[r.position].short) || posLabel(r.position).slice(0, 4);
        const w = 10 + label.length * 7;
        if (cx + w > (i + 1) * G.LW - 8) return;
        const st = RUN ? STAFFRUN[r.id] || {} : null;
        const g = sv("g", { class: `wg-chip need-${r.need}${isSel("staff", r.id) ? " sel" : ""}${applies(r, "staff") ? "" : " na"}${st && st.active && !(st.filled || []).length ? " miss" : ""}`,
          transform: `translate(${cx},54)`, onclick: (e) => { e.stopPropagation(); select("staff", r.id); } },
        sv("title", null, `${posLabel(r.position)} – ${lab("needs", r.need)}`), sv("rect", { width: w, height: 18, rx: 9, "--pc": posColor(r.position) }), sv("text", { x: w / 2, y: 13 }, label));
        ap(svgEl, g);
        cx += w + 4;
      });
    });
    // Kanten
    const edges = sv("g", { class: "wg-edges" });
    def.steps.forEach((s) => s.depends_on.forEach((dId) => {
      const d = stepById(dId);
      if (!d) return;
      const a = nodeXY(d), b = nodeXY(s);
      const bad = phaseIdx(d.phase) > phaseIdx(s.phase);
      let path;
      if (d.phase === s.phase) {
        const x = a.x + G.NW, y1 = a.y + G.NH / 2, y2 = b.y + G.NH / 2, k = 26 + Math.min(40, Math.abs(y2 - y1) / 6);
        path = `M${x} ${y1} C${x + k} ${y1}, ${x + k} ${y2}, ${x + 2} ${y2}`;
      } else {
        const x1 = a.x + G.NW, y1 = a.y + G.NH / 2, x2 = b.x, y2 = b.y + G.NH / 2, dx = Math.max(40, (x2 - x1) / 2);
        path = `M${x1} ${y1} C${x1 + dx} ${y1}, ${x2 - dx} ${y2}, ${x2 - 2} ${y2}`;
      }
      const key = d.id + ">" + s.id;
      const na = !applies(s) || !applies(d);
      const done = RUN && RUNST[d.id] && ["erledigt", "verworfen", "entfaellt"].includes(RUNST[d.id].state);
      const g = sv("g", { "data-edge": key, class: "wg-edge" + (isSel("edge", key) ? " sel" : "") + (bad ? " bad" : "") + (na ? " na" : "") + (done ? " done" : ""),
        onclick: (e) => { e.stopPropagation(); select("edge", key); } },
      sv("title", null, `„${s.title}“ wartet auf „${d.title}“`),
      sv("path", { d: path, class: "wg-hit" }), sv("path", { d: path, class: "wg-line", "marker-end": bad ? "url(#wg-arrow-bad)" : "url(#wg-arrow)" }));
      ap(edges, g);
    }));
    ap(svgEl, edges);
    // Knoten
    def.steps.forEach((s) => ap(svgEl, node(s, svgEl)));
    svgEl.addEventListener("click", () => { if (S.sel) select(null); });
    ap(wrap, svgEl);
    ap(wrap, h("div", { class: "wg-tools" },
      h("button", { type: "button", class: "wbtn2", title: "Verkleinern", onclick: () => zoom(-0.15) }, "−"),
      h("span", { class: "wg-zoom" }, Math.round(S.zoom * 100) + " %"),
      h("button", { type: "button", class: "wbtn2", title: "Vergrößern", onclick: () => zoom(0.15) }, "+"),
      h("button", { type: "button", class: "wbtn2", title: "An Fensterbreite anpassen", onclick: fit }, "Einpassen"),
      !RO && h("button", { type: "button", class: "wbtn2", title: "Schritte je Phase nach Abhängigkeiten ordnen", onclick: autoLayout }, "Automatisch anordnen"),
      !RO && h("span", { class: "wfd-hint" }, "Karte ziehen = verschieben (auch in andere Phase) · Punkt rechts auf einen anderen Schritt ziehen = „wartet auf“-Verbindung · Pfeil anklicken + Entf = löschen")));
    // Hintergrund ziehen = verschieben
    let pan = null;
    wrap.addEventListener("pointerdown", (e) => {
      if (e.target.closest(".wg-node, .wg-edge, .wg-chip, .wg-tools")) return;
      pan = { x: e.clientX, y: e.clientY, l: wrap.scrollLeft, t: wrap.scrollTop };
      wrap.classList.add("panning");
    });
    wrap.addEventListener("pointermove", (e) => { if (pan) { wrap.scrollLeft = pan.l - (e.clientX - pan.x); wrap.scrollTop = pan.t - (e.clientY - pan.y); } });
    const end = () => { pan = null; wrap.classList.remove("panning"); };
    wrap.addEventListener("pointerup", end);
    wrap.addEventListener("pointerleave", end);
    wrap.addEventListener("wheel", (e) => { if (e.ctrlKey) { e.preventDefault(); zoom(e.deltaY < 0 ? 0.1 : -0.1); } }, { passive: false });
    return wrap;
  }
  function zoom(d) {
    S.zoom = Math.max(0.4, Math.min(1.8, Math.round((S.zoom + d) * 100) / 100));
    store("wfd-zoom-" + D.mode, S.zoom);
    render({ keepInspector: true });
  }
  function fit() {
    const w = main.clientWidth - 24;
    S.zoom = Math.max(RUN ? 0.7 : 0.5, Math.min(1.4, w / (PH.length * G.LW)));
    store("wfd-zoom-" + D.mode, S.zoom);
    render({ keepInspector: true });
  }
  function toSvg(svgEl, e) {
    const pt = svgEl.createSVGPoint();
    pt.x = e.clientX;
    pt.y = e.clientY;
    return pt.matrixTransform(svgEl.getScreenCTM().inverse());
  }
  function node(s, svgEl) {
    const { x, y } = nodeXY(s);
    const p = POS[s.position];
    const okA = applies(s);
    const rs = RUN ? RUNST[s.id] || {} : null;
    const cls = ["wg-node", isSel("step", s.id) ? "sel" : "", okA ? "" : "na", S.hiPos && s.position === S.hiPos ? "hi" : "", S.hiPos && s.position !== S.hiPos ? "dim" : "",
      qMatch(s) ? "match" : "", S.q && !qMatch(s) ? "dim" : "", rs ? "st-" + rs.state : "", s.mandatory ? "mand" : ""].filter(Boolean).join(" ");
    const g = sv("g", { class: cls, transform: `translate(${x},${y})`, "data-id": s.id, "data-node": s.id, "--pc": p ? p.color || "#94a3b8" : "#cbd5e1" });
    ap(g, sv("rect", { class: "wg-box", width: G.NW, height: G.NH, rx: 9 }), sv("rect", { class: "wg-bar", width: 6, height: G.NH, rx: 3 }));
    const fo = sv("foreignObject", { x: 10, y: 4, width: G.NW - 16, height: G.NH - 8 });
    ap(fo, h("div", { class: "wg-html", xmlns: "http://www.w3.org/1999/xhtml" },
      h("div", { class: "wg-top" }, h("span", { class: "wc-kind k-" + s.kind }, KIND_ICON[s.kind] || "▢"),
        h("span", { class: "wg-pos" }, p ? p.short || p.label : "–"),
        s.due_hours ? h("span", { class: "wg-due" }, "⏱ " + fmtH(s.due_hours)) : null,
        s.mandatory ? h("span", { class: "wc-badge mand" }, "Pflicht") : null,
        s.when.rules.length ? h("span", { class: "wc-cond", title: "Nur wenn: " + whenText(s.when) }, "⚑") : null,
        rs ? h("span", { class: "wg-state" }, rs.label) : null),
      h("div", { class: "wg-title", title: s.title }, s.title)));
    ap(g, fo);
    ap(g, sv("title", null, s.title + (s.why ? "\n\nWarum: " + s.why : "") + (rs && rs.waiting ? "\nWartet auf: " + rs.waiting.join("; ") : "")));
    if (!RO) {
      const port = sv("circle", { class: "wg-port", cx: G.NW, cy: G.NH / 2, r: 7 });
      port.append(sv("title", null, "Ziehen auf einen anderen Schritt: dieser wartet dann auf „" + s.title + "“"));
      ap(g, port);
      port.addEventListener("pointerdown", (e) => {
        e.stopPropagation();
        e.preventDefault();
        const start = { x: x + G.NW, y: y + G.NH / 2 };
        const tmp = sv("path", { class: "wg-temp", d: "" });
        ap(svgEl, tmp);
        const move = (ev) => { const pt = toSvg(svgEl, ev); tmp.setAttribute("d", `M${start.x} ${start.y} L${pt.x} ${pt.y}`); };
        const up = (ev) => {
          document.removeEventListener("pointermove", move);
          document.removeEventListener("pointerup", up);
          tmp.remove();
          const t = document.elementFromPoint(ev.clientX, ev.clientY);
          const target = t && t.closest && t.closest("[data-node]");
          if (target && target.dataset.node !== s.id) addDep(target.dataset.node, s.id);
        };
        document.addEventListener("pointermove", move);
        document.addEventListener("pointerup", up);
      });
    }
    g.addEventListener("pointerdown", (e) => {
      if (e.button !== 0 || e.target.classList.contains("wg-port")) return;
      e.stopPropagation();
      if (RO) return;
      const p0 = toSvg(svgEl, e);
      let moved = false, nx = x, ny = y;
      g.setPointerCapture(e.pointerId);
      const move = (ev) => {
        const pt = toSvg(svgEl, ev);
        if (!moved && Math.hypot(pt.x - p0.x, pt.y - p0.y) < 4) return;
        moved = true;
        nx = x + pt.x - p0.x;
        ny = Math.max(G.TOP, y + pt.y - p0.y);
        g.setAttribute("transform", `translate(${nx},${ny})`);
        g.classList.add("dragging");
      };
      const up = () => {
        g.removeEventListener("pointermove", move);
        g.removeEventListener("pointerup", up);
        if (!moved) return;
        const lane = Math.max(0, Math.min(PH.length - 1, Math.floor((nx + G.NW / 2) / G.LW)));
        mutate(() => { s.phase = PH[lane].key; s.y = Math.round((ny - G.TOP) / 8) * 8; S.sel = { t: "step", id: s.id }; });
      };
      g.addEventListener("pointermove", move);
      g.addEventListener("pointerup", up);
    });
    g.addEventListener("click", (e) => { e.stopPropagation(); if (!g.classList.contains("dragging")) select("step", s.id); });
    g.addEventListener("mouseenter", () => chainHighlight(s.id, true));
    g.addEventListener("mouseleave", () => chainHighlight(s.id, false));
    return g;
  }

  // ---------- Stabsmatrix ----------
  function renderMatrix() {
    const used = new Set(def.staff.map((r) => r.position));
    const rows = [...positions].sort((a, b) => (used.has(b.key) - used.has(a.key)) || (a.sort || 0) - (b.sort || 0));
    const wrap = h("div", { class: "wm" });
    ap(wrap, h("p", { class: "wfd-hint wm-intro" },
      "Zeilen = Stabspositionen, Spalten = Phasen. Ein Balken zeigt, ab wann eine Position im Stab sein soll (", h("i", { class: "need-pflicht lg" }, "Pflicht"), " ",
      h("i", { class: "need-soll lg" }, "Soll"), " ", h("i", { class: "need-optional lg" }, "Optional"),
      "). Zahlen = Schritte, für die die Position in der Phase zuständig ist. ", RO ? "" : "Klick in eine leere Zelle legt eine Anforderung ab dieser Phase an; Klick auf einen Balken öffnet sie."));
    const t = h("table", { class: "wm-t" });
    ap(t, h("colgroup", null, h("col", { class: "c-pos" }), PH.map(() => h("col", { class: "c-ph" })), h("col", { class: "c-why" })));
    ap(t, h("thead", null, h("tr", null, h("th", null, "Position"), PH.map((p, i) => h("th", null, h("span", { class: "wb-num" }, i + 1), p.label)), h("th", null, "Begründung"))));
    const tb = h("tbody");
    rows.forEach((p) => {
      const reqs = def.staff.filter((r) => r.position === p.key);
      const tr = h("tr", { class: (S.hiPos === p.key ? "hi" : "") + (reqs.length ? "" : " unused") },
        h("th", { "--pc": p.color || "#94a3b8", onclick: () => { S.hiPos = S.hiPos === p.key ? null : p.key; render({ keepInspector: true }); } },
          h("span", { class: "wp-short" }, p.short || ""), " ", p.label,
          p.holders && p.holders.length ? h("small", { title: "Vorgesehene Besetzung" }, "👤 " + p.holders.join(", ")) : null));
      PH.forEach((ph, i) => {
        const active = reqs.filter((r) => phaseIdx(r.phase) <= i);
        const r = active.find((x) => applies(x, "staff")) || active[0];
        const n = def.steps.filter((s) => s.position === p.key && s.phase === ph.key && applies(s)).length;
        const start = r && phaseIdx(r.phase) === i;
        const td = h("td", { class: r ? `on need-${r.need}${start ? " start" : ""}${applies(r, "staff") ? "" : " na"}${isSel("staff", r.id) ? " sel" : ""}` : "", "--pc": p.color || "#94a3b8",
          title: r ? `${p.label}: ${lab("needs", r.need)} ab ${phaseLabel(r.phase)}${r.when.rules.length ? "\nNur wenn: " + whenText(r.when) : ""}` : RO ? "" : "Ab hier in den Stab aufnehmen",
          onclick: () => {
            if (r) select("staff", r.id);
            else if (!RO) {
              const later = reqs.find((x) => phaseIdx(x.phase) > i);
              if (later) mutate(() => { later.phase = ph.key; S.sel = { t: "staff", id: later.id }; });
              else addReq(p.key, ph.key);
            }
          } },
        start ? h("span", { class: "wm-need" }, lab("needs", r.need), r.when.rules.length ? " ⚑" : "", reqs.length > 1 ? " +" + (reqs.length - 1) : "") : null,
        n ? h("span", { class: "wm-n", title: n + " Schritt(e) in dieser Phase" }, n) : null);
        ap(tr, td);
      });
      const r0 = reqs[0];
      ap(tr, h("td", { class: "wm-why", title: r0 ? r0.why : "" }, r0 ? (r0.why || h("span", { class: "wc-warn" }, "Begründung fehlt")) : ""));
      ap(tb, tr);
    });
    ap(t, tb);
    ap(wrap, t);
    return wrap;
  }

  // ---------- Einstellungen ----------
  function renderSettings() {
    const d = def;
    const field = (label, input, hint) => h("label", { class: "wi-f" }, h("span", null, label), input, hint ? h("small", null, hint) : null);
    const inp = (k, attrs = {}) => h("input", Object.assign({ value: d[k] || "", disabled: RO, oninput: (e) => live(() => { d[k] = e.target.value; }), onblur: () => { editSnap = false; } }, attrs));
    const wrap = h("div", { class: "ws" },
      h("section", { class: "card" }, h("h2", null, "Allgemein"),
        field("Name", inp("name", { maxlength: 120 })),
        field("Schlüssel", inp("key", { maxlength: 64, pattern: "[a-z0-9_-]+" }), "Technischer Name für Export/Import (Kleinbuchstaben, Ziffern, - und _)."),
        field("Beschreibung", h("textarea", { rows: 3, disabled: RO, value: d.description || "", oninput: (e) => live(() => { d.description = e.target.value; }), onblur: () => { editSnap = false; } })),
        field("Farbe", h("input", { type: "color", value: d.color || "#1f5fbf", disabled: RO, oninput: (e) => live(() => { d.color = e.target.value; }) }))),
      h("section", { class: "card" }, h("h2", null, "Automatische Zuordnung"),
        h("p", { class: "wfd-hint" }, "Beim Anlegen eines Vorfalls wird der passendste aktive Workflow vorgeschlagen: Workflows mit passender Kategorie schlagen allgemeine; bei Gleichstand entscheidet die Rangfolge. Die Leitung kann jederzeit einen anderen wählen."),
        field("Für Kategorien", chipSelect(L.category, d.match.categories, (v) => mutate(() => { d.match.categories = v; })), "Leer = alle Kategorien."),
        field("Zusätzliche Bedingungen", condEditor(d.match.when, () => {})),
        field("Rangfolge", h("input", { type: "number", min: 0, max: 99, value: d.match.priority || 0, disabled: RO, oninput: (e) => live(() => { d.match.priority = parseInt(e.target.value, 10) || 0; }) }), "Höher = bevorzugt.")),
      h("section", { class: "card" }, h("h2", null, "Überblick"), stats()));
    return wrap;
  }
  function stats() {
    const byPhase = PH.map((p) => [p.label, def.steps.filter((s) => s.phase === p.key).length, def.steps.filter((s) => s.phase === p.key && s.mandatory).length]);
    return h("table", { class: "kvtable" }, h("tbody", null,
      h("tr", null, h("th", null, "Schritte"), h("td", null, def.steps.length + " (" + def.steps.filter((s) => s.mandatory).length + " Pflicht, " + def.steps.filter((s) => s.when.rules.length).length + " bedingt)")),
      h("tr", null, h("th", null, "Abhängigkeiten"), h("td", null, def.steps.reduce((a, s) => a + s.depends_on.length, 0))),
      h("tr", null, h("th", null, "Stabsanforderungen"), h("td", null, ["pflicht", "soll", "optional"].map((n) => def.staff.filter((r) => r.need === n).length + " " + lab("needs", n)).join(" · "))),
      byPhase.map(([l, n, m]) => h("tr", null, h("th", null, l), h("td", null, n + (m ? ` (${m} Pflicht)` : ""))))));
  }
  function chipSelect(options, selected, onChange) {
    return h("div", { class: "chips" }, options.map((o) => h("button", { type: "button", class: "chip" + (selected.includes(o.key) ? " on" : ""), disabled: RO, title: o.hint || "",
      onclick: () => onChange(selected.includes(o.key) ? selected.filter((x) => x !== o.key) : [...selected, o.key]) }, o.label)));
  }

  // ---------- Bedingungs-Baukasten ----------
  function condEditor(w, after) {
    const box = h("div", { class: "cond" });
    const redraw = () => { const n = condEditor(w, after); box.replaceWith(n); };
    const rules = w.rules;
    ap(box, h("div", { class: "cond-head" },
      rules.length > 1 ? h("select", { disabled: RO, value: w.mode, onchange: (e) => { mutate(() => { w.mode = e.target.value; }); } },
        h("option", { value: "all" }, "Alle Bedingungen müssen zutreffen (und)"), h("option", { value: "any" }, "Mindestens eine trifft zu (oder)")) : null,
      h("span", { class: "cond-text" }, rules.length ? "Gilt, wenn: " + whenText(w) : "Gilt immer (keine Bedingung).")));
    rules.forEach((r, i) => {
      const f = FIELDS[r.field] || L.fields[0];
      const row = h("div", { class: "cond-row" },
        h("select", { disabled: RO, value: r.field, onchange: (e) => mutate(() => { const nf = FIELDS[e.target.value]; r.field = nf.key; r.op = nf.ops[0]; r.values = defaultValues(nf); }) },
          L.fields.map((x) => h("option", { value: x.key }, x.label))),
        h("select", { disabled: RO, value: r.op, onchange: (e) => mutate(() => { r.op = e.target.value; }) }, f.ops.map((o) => h("option", { value: o }, L.ops[o] || o))),
        valueEditor(f, r),
        !RO ? h("button", { type: "button", class: "linkbtn", title: "Bedingung entfernen", onclick: () => mutate(() => { rules.splice(i, 1); }) }, "✕") : null);
      ap(box, row);
    });
    if (!RO) ap(box, h("button", { type: "button", class: "btn small", onclick: () => mutate(() => { const f = FIELDS.severity; rules.push({ field: f.key, op: "min", values: defaultValues(f) }); }) }, "+ Bedingung"));
    return box;
  }
  function defaultValues(f) {
    if (f.type === "sev") return ["P2"];
    if (f.type === "num") return ["1"];
    if (f.type === "bool") return [];
    return [];
  }
  function valueEditor(f, r) {
    if (f.type === "bool") return h("span", { class: "muted small" }, "");
    if (f.type === "sev") {
      return h("select", { disabled: RO, value: r.values[0] || "P2", onchange: (e) => mutate(() => { r.values = [e.target.value]; }) }, L.severities.map((s) => h("option", { value: s.key }, s.label)));
    }
    if (f.type === "num") {
      return h("input", { type: "number", min: 0, disabled: RO, value: r.values[0] || "", style: { width: "7em" }, oninput: (e) => live(() => { r.values = [e.target.value]; }), onblur: () => { editSnap = false; } });
    }
    const opts = f.set === "tlp" ? L.tlp : L[f.set] || [];
    return chipSelect(opts, r.values, (v) => mutate(() => { r.values = v; }));
  }

  // ---------- Übernehmen aus Bibliothek / anderen Workflows ----------
  let SOURCES = null;
  async function loadSources() {
    if (SOURCES) return SOURCES;
    const res = await fetch("/bibliothek.json", { credentials: "same-origin" });
    const j = await res.json();
    SOURCES = (j.sources || []).filter((x) => !(D.workflow && x.id === "wf:" + D.workflow)).map((x) => Object.assign(x, { def: normalize(x.def) }));
    return SOURCES;
  }
  function modal(title, wide) {
    const close = () => { ov.remove(); document.removeEventListener("keydown", esc, true); };
    const esc = (e) => { if (e.key === "Escape") { e.stopPropagation(); close(); } };
    document.addEventListener("keydown", esc, true);
    const body = h("div", { class: "pm-body" });
    const foot = h("div", { class: "pm-foot" });
    const box = h("div", { class: "pm" + (wide ? " wide" : ""), role: "dialog", "aria-modal": "true", "aria-label": title },
      h("div", { class: "pm-head" }, h("h2", null, title), h("button", { type: "button", class: "linkbtn", onclick: close, title: "Schließen (Esc)" }, "✕")), body, foot);
    const ov = h("div", { class: "pm-ov", onmousedown: (e) => { if (e.target === ov) close(); } }, box);
    document.body.append(ov);
    return { body, foot, close };
  }
  function sourceSelect(list, value, onChange) {
    const groups = {};
    list.forEach((x) => { (groups[x.group] = groups[x.group] || []).push(x); });
    return h("select", { class: "pm-src", value, onchange: (e) => onChange(e.target.value) },
      Object.entries(groups).map(([g, xs]) => h("optgroup", { label: g }, xs.map((x) => h("option", { value: x.id }, x.name)))));
  }
  const norm = (t) => (t || "").trim().toLowerCase();
  const findByTitle = (title) => def.steps.find((x) => norm(x.title) === norm(title));

  async function openPort(preselect) {
    const m = modal("Bausteine übernehmen", true);
    m.body.append(h("p", { class: "muted" }, "Lade Bibliothek …"));
    let list;
    try { list = await loadSources(); } catch (e) { m.body.textContent = "Bibliothek konnte nicht geladen werden."; return; }
    const st = { src: preselect || (list[0] && list[0].id), sel: new Set(), staff: new Set(), deps: true, mode: "skip", q: "" };
    const cur = () => list.find((x) => x.id === st.src);
    const preselectDefaults = () => {
      st.sel = new Set(); st.staff = new Set();
      const d = cur().def;
      d.steps.forEach((x) => { if (!findByTitle(x.title)) st.sel.add(x.id); });
      d.staff.forEach((r) => { if (!def.staff.some((t) => t.position === r.position)) st.staff.add(r.id); });
    };
    preselectDefaults();
    const draw = () => {
      const d = cur().def;
      const srcPos = (k) => POS[k];
      m.body.textContent = "";
      const withDeps = new Set(st.sel);
      if (st.deps) {
        const add = (id) => { const x = d.steps.find((y) => y.id === id); if (!x) return; x.depends_on.forEach((p) => { if (!withDeps.has(p)) { withDeps.add(p); add(p); } }); };
        [...st.sel].forEach(add);
      }
      const head = h("div", { class: "pm-bar" },
        h("label", null, "Quelle ", sourceSelect(list, st.src, (v) => { st.src = v; preselectDefaults(); draw(); })),
        h("input", { type: "search", placeholder: "Schritte filtern …", value: st.q, oninput: (e) => { st.q = e.target.value.toLowerCase(); draw(); setTimeout(() => { const i = m.body.querySelector(".pm-bar input[type=search]"); if (i) { i.focus(); i.setSelectionRange(i.value.length, i.value.length); } }, 0); } }),
        h("button", { type: "button", class: "btn small", onclick: () => { d.steps.forEach((x) => st.sel.add(x.id)); d.staff.forEach((r) => st.staff.add(r.id)); draw(); } }, "Alle"),
        h("button", { type: "button", class: "btn small", onclick: () => { st.sel.clear(); st.staff.clear(); draw(); } }, "Keine"),
        h("button", { type: "button", class: "btn small", onclick: () => { st.sel = new Set(d.steps.filter((x) => x.mandatory).map((x) => x.id)); draw(); } }, "Nur Pflichtschritte"),
        h("button", { type: "button", class: "btn small", onclick: () => { preselectDefaults(); draw(); } }, "Nur Neue"));
      m.body.append(head);
      if (cur().def.description) m.body.append(h("p", { class: "small muted" }, cur().def.description));
      const cols = h("div", { class: "pm-cols" });
      PH.forEach((ph) => {
        const steps = d.steps.filter((x) => x.phase === ph.key && (!st.q || norm(x.title).includes(st.q) || norm(x.why).includes(st.q)))
          .sort((a, b) => (a.y || 0) - (b.y || 0));
        if (!steps.length) return;
        cols.append(h("section", { class: "pm-ph" }, h("h3", null, ph.label),
          steps.map((x) => {
            const exists = findByTitle(x.title);
            const auto = !st.sel.has(x.id) && withDeps.has(x.id);
            const p = srcPos(x.position);
            return h("label", { class: "pm-step" + (st.sel.has(x.id) || auto ? " on" : "") + (exists ? " exists" : ""), "--pc": p ? p.color || "#94a3b8" : "#cbd5e1", title: x.why || "" },
              h("input", { type: "checkbox", checked: st.sel.has(x.id) || auto, disabled: auto, onchange: (e) => { e.target.checked ? st.sel.add(x.id) : st.sel.delete(x.id); draw(); } }),
              h("span", { class: "pm-t" }, h("span", { class: "wc-kind k-" + x.kind }, KIND_ICON[x.kind] || "▢"), " ", x.title,
                h("small", null, [p ? p.short || p.label : "niemand", x.due_hours ? "⏱ " + fmtH(x.due_hours) : "", x.mandatory ? "Pflicht" : "", x.when.rules.length ? "⚑ " + whenText(x.when) : "",
                  x.depends_on.length ? "wartet auf " + x.depends_on.length : ""].filter(Boolean).join(" · ")),
                exists ? h("span", { class: "pm-ex" }, "gleichnamig vorhanden") : null, auto ? h("span", { class: "pm-ex auto" }, "als Vorgänger") : null));
          })));
      });
      m.body.append(cols);
      if (d.staff.length) {
        m.body.append(h("h3", { class: "pm-sub" }, "Stabsanforderungen"),
          h("div", { class: "pm-staff" }, d.staff.map((r) => {
            const exists = def.staff.some((t) => t.position === r.position);
            return h("label", { class: "pm-step" + (st.staff.has(r.id) ? " on" : "") + (exists ? " exists" : ""), "--pc": posColor(r.position), title: r.why },
              h("input", { type: "checkbox", checked: st.staff.has(r.id), onchange: (e) => { e.target.checked ? st.staff.add(r.id) : st.staff.delete(r.id); draw(); } }),
              h("span", { class: "pm-t" }, posLabel(r.position), h("small", null, `${lab("needs", r.need)} ab ${phaseLabel(r.phase)}${r.when.rules.length ? " · ⚑ " + whenText(r.when) : ""}`),
                exists ? h("span", { class: "pm-ex" }, "Position bereits angefordert") : null));
          })));
      }
      m.foot.textContent = "";
      const nSteps = withDeps.size, nStaff = st.staff.size;
      m.foot.append(
        h("label", { class: "wfd-chk" }, h("input", { type: "checkbox", checked: st.deps, onchange: (e) => { st.deps = e.target.checked; draw(); } }), " Vorgänger automatisch mitnehmen"),
        h("label", null, "Bereits vorhandene: ", h("select", { value: st.mode, onchange: (e) => { st.mode = e.target.value; } },
          h("option", { value: "skip" }, "überspringen (nur verknüpfen)"), h("option", { value: "update" }, "Eigenschaften aktualisieren"), h("option", { value: "copy" }, "zusätzlich als Kopie anlegen"))),
        h("span", { class: "pm-sum" }, `${nSteps} Schritte, ${nStaff} Stabsanforderungen`),
        h("button", { type: "button", class: "btn primary", disabled: !nSteps && !nStaff, onclick: () => { const r = portIn(d, withDeps, st.staff, st.mode, cur().name); m.close(); flash(r); } }, "Übernehmen"));
    };
    draw();
  }

  const STEP_PROPS = ["kind", "position", "priority", "due_hours", "due_from", "mandatory", "manual", "why", "ref", "details", "when"];
  function portIn(src, stepIds, staffIds, mode, srcName) {
    let added = 0, updated = 0, skipped = 0, noPos = 0;
    mutate(() => {
      const map = {};
      const touched = [];
      src.steps.filter((x) => stepIds.has(x.id)).forEach((x) => {
        const exists = findByTitle(x.title);
        if (exists && mode !== "copy") {
          map[x.id] = exists.id;
          if (mode === "update") {
            STEP_PROPS.forEach((k) => { exists[k] = JSON.parse(JSON.stringify(x[k])); });
            if (exists.position && !POS[exists.position]) { exists.position = ""; noPos++; }
            touched.push([x, exists]);
            updated++;
          } else skipped++;
          return;
        }
        const c = JSON.parse(JSON.stringify(x));
        c.id = stepById(c.id) ? uid("s_") : c.id;
        if (exists) c.title = x.title + " (" + srcName + ")";
        c.depends_on = [];
        c.y = stepsIn(c.phase).length * 96;
        if (c.position && !POS[c.position]) { c.position = ""; noPos++; }
        def.steps.push(c);
        map[x.id] = c.id;
        touched.push([x, c]);
        added++;
      });
      // Abhängigkeiten nur zwischen übernommenen bzw. verknüpften Schritten, ohne Zyklen und Phasenfehler
      touched.forEach(([x, t]) => x.depends_on.forEach((d) => {
        const to = map[d];
        const dep = to && stepById(to);
        if (!dep || t.depends_on.includes(to) || to === t.id) return;
        if (phaseIdx(dep.phase) > phaseIdx(t.phase) || wouldCycle(t.id, to)) return;
        t.depends_on.push(to);
      }));
      src.staff.filter((r) => staffIds.has(r.id)).forEach((r) => {
        if (!POS[r.position]) { noPos++; return; }
        const exists = def.staff.find((t) => t.position === r.position && JSON.stringify(t.when) === JSON.stringify(r.when)) ||
          def.staff.find((t) => t.position === r.position);
        if (exists && mode === "update") {
          ["need", "phase", "when", "why", "ref", "auto_add", "role"].forEach((k) => { exists[k] = JSON.parse(JSON.stringify(r[k])); });
          updated++;
        } else if (exists && mode === "skip") skipped++;
        else { const c = JSON.parse(JSON.stringify(r)); c.id = reqById(c.id) ? uid("st_") : c.id; def.staff.push(c); added++; }
      });
      PH.forEach((ph) => relayout(ph.key));
      S.sel = null;
    });
    return `Übernommen aus „${srcName}“: ${added} neu, ${updated} aktualisiert, ${skipped} übersprungen${noPos ? `, ${noPos}× Stabsposition unbekannt (Zuständigkeit leer)` : ""}. Rückgängig mit Strg+Z.`;
  }

  const PROP_GROUPS = {
    step: [["why", "Begründung & Grundlage", ["why", "ref"], true], ["details", "Hinweise zur Durchführung", ["details"], true], ["when", "Bedingungen", ["when"], true],
      ["position", "Zuständigkeit", ["position"], true], ["prio", "Priorität & Frist", ["priority", "due_hours", "due_from"], true],
      ["flags", "Pflichtschritt / nur empfehlen", ["mandatory", "manual"], true], ["kind", "Art", ["kind"], false], ["title", "Titel", ["title"], false], ["phase", "Phase", ["phase"], false]],
    staff: [["why", "Begründung & Grundlage", ["why", "ref"], true], ["when", "Bedingungen", ["when"], true], ["need", "Bedarf & Phase", ["need", "phase"], true],
      ["auto", "Automatisch aufnehmen & Rolle", ["auto_add", "role"], false]],
  };
  async function openProps(type, id) {
    const target = type === "step" ? stepById(id) : reqById(id);
    if (!target) return;
    const m = modal(type === "step" ? `Eigenschaften übernehmen → „${target.title}“` : `Eigenschaften übernehmen → ${posLabel(target.position)}`, true);
    m.body.append(h("p", { class: "muted" }, "Lade Bibliothek …"));
    let list;
    try { list = await loadSources(); } catch (e) { m.body.textContent = "Bibliothek konnte nicht geladen werden."; return; }
    // alle Kandidaten aus allen Quellen; ähnlichste zuerst
    const words = norm(type === "step" ? target.title : posLabel(target.position)).split(/[^a-zäöüß0-9]+/).filter((w) => w.length > 3);
    const cands = [];
    list.forEach((src) => (type === "step" ? src.def.steps : src.def.staff).forEach((x) => {
      const text = norm(type === "step" ? x.title + " " + x.why : posLabel(x.position) + " " + x.why);
      let score = words.filter((w) => text.includes(w)).length;
      if (type === "step" && norm(x.title) === norm(target.title)) score += 10;
      if (type === "staff" && x.position === target.position) score += 10;
      if (type === "step" && x.position === target.position) score += 1;
      cands.push({ src, x, score });
    }));
    cands.sort((a, b) => b.score - a.score);
    // identische Bausteine (z. B. Vorlage und installierte Fassung) nur einmal zeigen
    const seenC = new Set();
    const dedup = [];
    cands.forEach((c) => {
      const k = JSON.stringify([c.x.title || "", c.x.position, c.x.why, c.x.ref, c.x.when, c.x.need || "", c.x.phase]);
      if (!seenC.has(k)) { seenC.add(k); dedup.push(c); }
    });
    cands.length = 0;
    dedup.forEach((c) => cands.push(c));
    const st = { q: "", pick: cands[0] || null, fields: new Set(PROP_GROUPS[type].filter((g) => g[3]).map((g) => g[0])) };
    const draw = () => {
      m.body.textContent = "";
      const shown = cands.filter((c) => !st.q || norm((type === "step" ? c.x.title : posLabel(c.x.position)) + " " + c.x.why + " " + c.src.name).includes(st.q)).slice(0, 80);
      const left = h("div", { class: "pp-list" },
        h("input", { type: "search", placeholder: "Suchen (Titel, Begründung, Quelle) …", value: st.q, oninput: (e) => { st.q = e.target.value.toLowerCase(); draw(); setTimeout(() => { const i = m.body.querySelector(".pp-list input"); if (i) { i.focus(); i.setSelectionRange(i.value.length, i.value.length); } }, 0); } }),
        shown.map((c) => h("button", { type: "button", class: "pp-item" + (st.pick === c ? " on" : ""), "--pc": posColor(c.x.position), onclick: () => { st.pick = c; draw(); } },
          h("b", null, type === "step" ? c.x.title : posLabel(c.x.position) + " – " + lab("needs", c.x.need)),
          h("small", null, c.src.name + " · " + phaseLabel(c.x.phase)))),
        !shown.length ? h("p", { class: "muted small" }, "Keine Treffer.") : null);
      const x = st.pick && st.pick.x;
      const right = h("div", { class: "pp-detail" }, x ? [
        h("h3", null, type === "step" ? x.title : posLabel(x.position)),
        h("p", { class: "small muted" }, "Quelle: " + st.pick.src.name),
        kv(type === "step" ? [["Warum", x.why || "–"], ["Grundlage", x.ref || "–"], ["Zuständig", posLabel(x.position)], ["Priorität / Frist", lab("priorities", x.priority) + (x.due_hours ? " · " + fmtH(x.due_hours) : "")],
          ["Bedingungen", whenText(x.when)], ["Pflicht", x.mandatory ? "ja" : "nein"], ["Hinweise", x.details || "–"]] :
          [["Warum", x.why || "–"], ["Grundlage", x.ref || "–"], ["Bedarf", lab("needs", x.need) + " ab " + phaseLabel(x.phase)], ["Bedingungen", whenText(x.when)]]),
        h("h4", null, "Übernehmen:"),
        h("div", { class: "pp-fields" }, PROP_GROUPS[type].map(([k, label]) => h("label", { class: "wfd-chk" },
          h("input", { type: "checkbox", checked: st.fields.has(k), onchange: (e) => { e.target.checked ? st.fields.add(k) : st.fields.delete(k); } }), " " + label)))] :
        h("p", { class: "muted" }, "Links einen Baustein wählen."));
      m.body.append(h("div", { class: "pp" }, left, right));
      m.foot.textContent = "";
      m.foot.append(h("span", { class: "pm-sum" }, "Vorhandene Werte des Ziels werden überschrieben – Rückgängig mit Strg+Z."),
        h("button", { type: "button", class: "btn primary", disabled: !x, onclick: () => {
          mutate(() => {
            PROP_GROUPS[type].forEach(([k, , props]) => {
              if (!st.fields.has(k)) return;
              props.forEach((p) => { target[p] = JSON.parse(JSON.stringify(x[p] === undefined ? "" : x[p])); });
            });
            if (type === "step") {
              if (target.position && !POS[target.position]) target.position = "";
              if (st.fields.has("phase")) {
                target.depends_on = target.depends_on.filter((d) => { const ds = stepById(d); return ds && phaseIdx(ds.phase) <= phaseIdx(target.phase); });
                relayout(target.phase);
              }
            }
            S.sel = { t: type, id };
          });
          m.close();
          flash("Eigenschaften aus „" + st.pick.src.name + "“ übernommen. Rückgängig mit Strg+Z.");
        } }, "Übernehmen"));
    };
    draw();
  }

  // ---------- Inspektor ----------
  function renderInspector() {
    insp.textContent = "";
    editSnap = false;
    const sel = S.sel;
    if (sel && sel.t === "step" && stepById(sel.id)) return inspStep(stepById(sel.id));
    if (sel && sel.t === "staff" && reqById(sel.id)) return inspStaff(reqById(sel.id));
    if (sel && sel.t === "edge") return inspEdge(sel.id);
    inspNone();
  }
  const fieldRow = (label, input, hint) => h("label", { class: "wi-f" }, h("span", null, label), input, hint ? h("small", null, hint) : null);
  function textIn(obj, k, attrs = {}) {
    return h(attrs.rows ? "textarea" : "input", Object.assign({ name: k, value: obj[k] || "", disabled: RO, oninput: (e) => live(() => { obj[k] = e.target.value; }), onblur: () => { editSnap = false; } }, attrs));
  }
  function selectIn(obj, k, options, after) {
    return h("select", { name: k, disabled: RO, value: obj[k] || "", onchange: (e) => mutate(() => { obj[k] = e.target.value; if (after) after(); }) },
      options.map((o) => h("option", { value: o.key }, o.label)));
  }
  function toggle(obj, k, label, hint) {
    return h("label", { class: "wi-toggle", title: hint || "" }, h("input", { type: "checkbox", disabled: RO, checked: !!obj[k], onchange: (e) => mutate(() => { obj[k] = e.target.checked; }) }),
      h("span", null, label), hint ? h("small", null, hint) : null);
  }
  function posOptions(withEmpty) {
    const o = withEmpty ? [{ key: "", label: "– niemand –" }] : [];
    return o.concat(positions.map((p) => ({ key: p.key, label: (p.short ? p.short + " · " : "") + p.label })));
  }

  function inspStep(s) {
    const rs = RUN ? RUNST[s.id] || {} : null;
    const p = POS[s.position];
    ap(insp, h("div", { class: "wi-head", "--pc": p ? p.color : "#cbd5e1" },
      h("span", { class: "wi-type" }, lab("kinds", s.kind) + " · " + phaseLabel(s.phase)),
      h("button", { type: "button", class: "linkbtn", onclick: () => select(null), title: "Schließen (Esc)" }, "✕")));
    if (RUN || RO) {
      ap(insp, h("h3", { class: "wi-title" }, s.title));
      if (rs) ap(insp, h("div", { class: "wi-state st-" + rs.state }, rs.label, rs.waiting && rs.waiting.length ? h("div", null, "Wartet auf: " + rs.waiting.join("; ")) : null,
        rs.task ? h("a", { href: `/incidents/${D.incident}?tab=aufgaben#task-${rs.task}` }, "→ Aufgabe #" + rs.task) : null));
      ap(insp, 
        h("div", { class: "wi-why" }, h("b", null, "Warum ist das notwendig?"), h("p", null, s.why || "– keine Begründung hinterlegt –"), s.ref ? h("small", null, "Grundlage: " + s.ref) : null),
        kv([["Zuständig", posLabel(s.position)], ["Priorität", lab("priorities", s.priority)], ["Frist", s.due_hours ? fmtH(s.due_hours) + (s.due_from === "anlage" ? " ab Anlage" : " ab Kenntnisnahme") : "–"],
          ["Pflichtschritt", s.mandatory ? "ja – Phasen-Gate" : "nein"], ["Anlage", s.manual ? "als Empfehlung" : "automatisch bei Erreichen der Phase"],
          ["Gilt", RUN && rs ? rs.cond : whenText(s.when)], ["Wartet auf", s.depends_on.map((d) => (stepById(d) || {}).title).filter(Boolean).join("; ") || "–"]]),
        s.details ? h("div", { class: "wi-why" }, h("b", null, "Hinweise"), h("p", null, s.details)) : null,
        p && p.why ? h("div", { class: "wi-why muted" }, h("b", null, "Warum " + p.label + "?"), h("p", null, p.why)) : null);
      return;
    }
    const deps = s.depends_on.map(stepById).filter(Boolean);
    const succ = def.steps.filter((x) => x.depends_on.includes(s.id));
    const desc = descendants(s.id);
    const candidates = def.steps.filter((x) => x.id !== s.id && !s.depends_on.includes(x.id) && !desc.has(x.id) && phaseIdx(x.phase) <= phaseIdx(s.phase))
      .sort((a, b) => phaseIdx(a.phase) - phaseIdx(b.phase) || (a.y || 0) - (b.y || 0));
    ap(insp, 
      fieldRow("Titel", textIn(s, "title", { maxlength: 300 })),
      h("div", { class: "wi-grid" },
        fieldRow("Art", selectIn(s, "kind", L.kinds)),
        fieldRow("Phase", selectIn(s, "phase", PH, () => relayout(s.phase)))),
      fieldRow("Zuständige Stabsposition", selectIn(s, "position", posOptions(true)), p && p.holders && p.holders.length ? "Vorgesehen: " + p.holders.join(", ") : null),
      h("div", { class: "wi-grid" },
        fieldRow("Priorität", selectIn(s, "priority", L.priorities)),
        fieldRow("Frist (Stunden)", h("input", { type: "number", min: 0, max: 8760, name: "due_hours", disabled: RO, value: s.due_hours || 0,
          oninput: (e) => live(() => { s.due_hours = parseInt(e.target.value, 10) || 0; }), onblur: () => { editSnap = false; } }))),
      fieldRow("Frist läuft ab", selectIn(s, "due_from", [{ key: "kenntnis", label: "Kenntnisnahme des Vorfalls" }, { key: "anlage", label: "Anlage der Aufgabe (Erreichen der Phase)" }])),
      h("div", { class: "wi-why-edit" },
        fieldRow("Warum ist der Schritt notwendig?", textIn(s, "why", { rows: 4, placeholder: "Begründung für die Beteiligten: Welches Risiko wird verhindert, welche Pflicht erfüllt?" }),
          "Wird bei der Aufgabe und in den Empfehlungen angezeigt."),
        fieldRow("Grundlage / Referenz", textIn(s, "ref", { placeholder: "z. B. BSI IT-Grundschutz DER.2.1, Art. 33 DSGVO" }))),
      fieldRow("Hinweise zur Durchführung", textIn(s, "details", { rows: 3 })),
      toggle(s, "mandatory", "Pflichtschritt (Phasen-Gate)", "Vor dem Wechsel in die nächste Phase erledigen – sonst nur mit Begründung"),
      toggle(s, "manual", "Nur empfehlen, nicht automatisch anlegen", "Erscheint als Empfehlung; die Aufgabe wird erst bei Übernahme angelegt"),
      h("div", { class: "wi-sec" }, h("b", null, "Gilt nur unter Bedingungen"), condEditor(s.when)),
      h("div", { class: "wi-sec" }, h("b", null, "Wartet auf (Vorgänger)"),
        h("div", { class: "chips" }, deps.map((d) => h("span", { class: "chip on" }, d.title.length > 40 ? d.title.slice(0, 40) + "…" : d.title,
          h("button", { type: "button", class: "linkbtn", title: "Verbindung entfernen", onclick: () => mutate(() => { s.depends_on = s.depends_on.filter((x) => x !== d.id); }) }, " ✕")))),
        candidates.length ? h("select", { onchange: (e) => { if (e.target.value) addDep(s.id, e.target.value); } },
          h("option", { value: "" }, "+ Vorgänger hinzufügen …"), candidates.map((c) => h("option", { value: c.id }, phaseLabel(c.phase) + ": " + c.title))) : null,
        succ.length ? h("small", null, "Danach folgen: " + succ.map((x) => x.title).join("; ")) : null),
      h("div", { class: "wi-actions" },
        h("button", { type: "button", class: "btn small", onclick: () => openProps("step", s.id), title: "Begründung, Bedingungen, Zuständigkeit usw. von einem Schritt aus der Bibliothek oder einem anderen Workflow übernehmen" }, "Eigenschaften übernehmen …"),
        h("button", { type: "button", class: "btn small", onclick: duplicate, title: "Strg+D" }, "Duplizieren"),
        h("button", { type: "button", class: "btn small danger", onclick: removeSel, title: "Entf" }, "Löschen")),
      h("small", { class: "muted" }, "ID: " + s.id));
  }
  function kv(rows) {
    return h("table", { class: "kvtable" }, h("tbody", null, rows.map(([k, v]) => h("tr", null, h("th", null, k), h("td", null, v)))));
  }
  function inspStaff(r) {
    const p = POS[r.position] || { label: r.position };
    const st = RUN ? STAFFRUN[r.id] || {} : null;
    ap(insp, h("div", { class: "wi-head", "--pc": p.color || "#cbd5e1" },
      h("span", { class: "wi-type" }, "Stabsanforderung"), h("button", { type: "button", class: "linkbtn", onclick: () => select(null) }, "✕")));
    if (RUN || RO) {
      ap(insp, h("h3", { class: "wi-title" }, p.label),
        st ? h("div", { class: "wi-state " + ((st.filled || []).length ? "st-erledigt" : st.active ? "st-gesperrt" : "st-spaeter") },
          (st.filled || []).length ? "Besetzt: " + st.filled.join(", ") : st.active ? "Nicht besetzt" : "Ab " + phaseLabel(r.phase),
          st.suggest && st.suggest.length && !(st.filled || []).length ? h("div", null, "Vorgesehen: " + st.suggest.join(", ")) : null,
          (st.filled || []).length ? null : h("a", { href: `/incidents/${D.incident}?tab=stab` }, "→ Stab")) : null,
        h("div", { class: "wi-why" }, h("b", null, "Warum gehört die Position in den Stab?"), h("p", null, r.why || p.why || "–"), r.ref || p.ref ? h("small", null, "Grundlage: " + (r.ref || p.ref)) : null),
        kv([["Bedarf", lab("needs", r.need)], ["Ab Phase", phaseLabel(r.phase)], ["Gilt", st ? st.cond : whenText(r.when)], ["Automatisch aufnehmen", r.auto_add ? "ja" : "nein"]]),
        p.duties && p.duties.length ? h("div", { class: "wi-why" }, h("b", null, "Aufgaben im Stab"), h("ul", null, p.duties.map((d) => h("li", null, d)))) : null);
      return;
    }
    ap(insp, 
      fieldRow("Stabsposition", selectIn(r, "position", posOptions(false))),
      h("div", { class: "wi-sec" }, h("b", null, "Bedarf"),
        h("div", { class: "seg" }, L.needs.map((n) => h("button", { type: "button", class: "need-" + n.key + (r.need === n.key ? " on" : ""), title: n.hint, onclick: () => mutate(() => { r.need = n.key; }) }, n.label))),
        h("small", null, (L.needs.find((n) => n.key === r.need) || {}).hint)),
      fieldRow("Ab Phase", selectIn(r, "phase", PH)),
      h("div", { class: "wi-why-edit" },
        fieldRow("Warum gehört die Position in den Stab?", textIn(r, "why", { rows: 4, placeholder: p.why || "" }), "Wird im Vorfall beim Soll-Ist-Abgleich und in den Empfehlungen angezeigt."),
        p.why && r.why !== p.why ? h("button", { type: "button", class: "linkbtn", onclick: () => mutate(() => { r.why = p.why; if (!r.ref) r.ref = p.ref || ""; }) }, "Standardbegründung der Position übernehmen") : null,
        fieldRow("Grundlage / Referenz", textIn(r, "ref"))),
      h("div", { class: "wi-sec" }, h("b", null, "Gilt nur unter Bedingungen"), condEditor(r.when)),
      toggle(r, "auto_add", "Vorgesehene Besetzung automatisch aufnehmen",
        p.holders && p.holders.length ? "Vorgesehen: " + p.holders.join(", ") + " (erste noch nicht beteiligte Person)" : "Für diese Position ist keine Besetzung hinterlegt – unter „Stabspositionen“ pflegen."),
      fieldRow("Rolle im Vorfall", selectIn(r, "role", [{ key: "", label: "Standard der Position (" + lab("roles", p.role || "mitglied") + ")" }].concat(L.roles.filter((x) => x.key !== "leitung")))),
      p.duties && p.duties.length ? h("div", { class: "wi-why muted" }, h("b", null, "Aufgaben der Position"), h("ul", null, p.duties.map((d) => h("li", null, d)))) : null,
      h("div", { class: "wi-actions" },
        h("button", { type: "button", class: "btn small", onclick: () => openProps("staff", r.id), title: "Begründung, Bedingungen und Bedarf von einer Stabsanforderung aus der Bibliothek oder einem anderen Workflow übernehmen" }, "Eigenschaften übernehmen …"),
        h("button", { type: "button", class: "btn small danger", onclick: removeSel }, "Anforderung entfernen")));
  }
  function inspEdge(id) {
    const [a, b] = id.split(">");
    const from = stepById(a), to = stepById(b);
    ap(insp, h("div", { class: "wi-head" }, h("span", { class: "wi-type" }, "Abhängigkeit"), h("button", { type: "button", class: "linkbtn", onclick: () => select(null) }, "✕")));
    if (!from || !to) return;
    ap(insp, h("p", null, h("b", null, to.title), " wartet auf ", h("b", null, from.title), "."),
      h("p", { class: "wfd-hint" }, "Im Vorfall bleibt die Aufgabe gesperrt, bis der Vorgänger erledigt, verworfen oder für den Vorfall nicht zutreffend ist."),
      !RO ? h("button", { type: "button", class: "btn small danger", onclick: removeSel }, "Verbindung entfernen") : null);
  }
  function inspNone() {
    ap(insp, h("h3", null, RUN ? "Ablauf dieses Vorfalls" : "Workflow gestalten"));
    if (RUN) {
      ap(insp, h("p", { class: "wfd-hint" }, "Klick auf einen Schritt zeigt, warum er notwendig ist, wer zuständig ist und worauf er wartet."),
        legend(), h("p", { class: "wfd-hint" }, "Schritte entstehen automatisch, sobald ihre Phase erreicht ist. Gesperrte Schritte warten auf ihre Vorgänger. Pflichtschritte (rot umrandet) müssen vor dem nächsten Phasenwechsel erledigt sein – Abweichungen nur mit Begründung."));
      return;
    }
    if (!RO) {
      ap(insp, h("ul", { class: "wfd-help" },
        h("li", null, h("b", null, "+ Schritt"), " in einer Phase anlegen, Karte anklicken zum Bearbeiten."),
        h("li", null, "Karten zwischen Phasen ", h("b", null, "ziehen"), "; Reihenfolge per Ziehen ändern."),
        h("li", null, "Stabsposition aus der Leiste links ", h("b", null, "auf eine Karte"), " ziehen = zuständig; ", h("b", null, "in den Phasenkopf"), " = ab dort im Stab."),
        h("li", null, "Im ", h("b", null, "Ablaufgraph"), " den Punkt rechts an einer Karte auf einen anderen Schritt ziehen = „wartet auf“."),
        h("li", null, h("b", null, "▶ Vorschau"), " zeigt, was in einem bestimmten Szenario gilt."),
        h("li", null, "Speichern erzeugt einen ", h("b", null, "Entwurf"), "; erst „Veröffentlichen“ macht ihn für neue Vorfälle wirksam.")));
    }
    const box = h("div", { class: "wi-issues" }, h("b", null, "Prüfung"));
    if (!S.issues.length) ap(box, h("p", { class: "ok" }, "✓ Keine Fehler oder Hinweise."));
    S.issues.forEach((i) => {
      const [t, id] = (i.ref || "").split(":");
      ap(box, h("button", { type: "button", class: "wi-issue " + i.level, onclick: () => { if (t === "step" || t === "staff") select(t, id); else if (t === "def" || t === "match") { S.view = "settings"; render(); } } },
        i.level === "error" ? "✖ " : "! ", i.msg));
    });
    ap(insp, box, legend());
  }
  function legend() {
    return h("div", { class: "wfd-legend" }, h("b", null, "Legende"),
      h("div", null, Object.entries(KIND_ICON).map(([k, i]) => h("span", null, h("span", { class: "wc-kind k-" + k }, i), " " + lab("kinds", k)))),
      RUN ? h("div", { class: "wfd-states" }, ["erledigt", "in_arbeit", "offen", "gesperrt", "bereit", "spaeter", "entfaellt", "verworfen"].map((k) => h("span", { class: "wc st-" + k }, h("span", { class: "dot" }), stateName(k)))) : null);
  }
  function stateName(k) {
    return { erledigt: "erledigt", in_arbeit: "in Arbeit", offen: "offen", gesperrt: "wartet", bereit: "bereit", spaeter: "später", entfaellt: "entfällt", verworfen: "verworfen", blockiert: "blockiert" }[k] || k;
  }

  S.issues = RO ? S.issues : validate();
  mount();
  const portParam = new URLSearchParams(location.search).get("port");
  if (portParam && !RO) openPort(portParam);
  if (S.view === "graph" && !store("wfd-zoom-" + D.mode)) fit();
})();
