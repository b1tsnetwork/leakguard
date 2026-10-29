// LeakGuard – kleine Komfortfunktionen (CSP: nur same-origin Skripte)
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
  if (t.matches("tr[data-href]") && !ev.target.closest("a")) {
    location.href = t.dataset.href;
  }
});

// Doppelte Absendungen verhindern
document.addEventListener("submit", (ev) => {
  const b = ev.submitter;
  if (b && !b.name) setTimeout(() => { b.disabled = true; }, 0);
});
