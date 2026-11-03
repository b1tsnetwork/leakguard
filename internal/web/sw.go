package web

import (
	"log/slog"
	"net/http"
)

// killSW ersetzt einen fremden Service Worker durch einen, der sich sofort selbst entfernt,
// alle Caches löscht und die offenen Fenster neu lädt. LeakGuard selbst nutzt keinen Service Worker.
//
// Hintergrund: Ein Service Worker bleibt im Browser aktiv, solange sein Skript nicht durch ein neues ersetzt
// wird. Liefert der Server für /sw.js nur 404, behält der Browser den alten Worker – der dann alle Anfragen
// abfängt (veraltete Seiten, hängende Anfragen, unterbrochene Live-Verbindung).
const killSW = `// LeakGuard: entfernt veraltete Service Worker dieser Adresse
self.addEventListener("install", () => self.skipWaiting());
self.addEventListener("activate", (event) => {
  event.waitUntil((async () => {
    try { const keys = await caches.keys(); await Promise.all(keys.map((k) => caches.delete(k))); } catch (e) {}
    await self.registration.unregister();
    const wins = await self.clients.matchAll({ type: "window" });
    wins.forEach((w) => { try { w.navigate(w.url); } catch (e) {} });
  })());
});
// Keine fetch-Behandlung: alle Anfragen gehen direkt an den Server.
`

func (s *Server) handleKillServiceWorker(w http.ResponseWriter, r *http.Request) {
	slog.Info("veralteter Service Worker wird entfernt", "path", r.URL.Path, "ip", s.clientIP(r))
	w.Header().Set("Content-Type", "text/javascript; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store, max-age=0")
	// "storage" entfernt registrierte Service Worker (und Browser-Speicher dieser Adresse) – Cookies bleiben erhalten,
	// die Anmeldung also auch. LeakGuard selbst speichert nur eine Kleinigkeit im sessionStorage.
	w.Header().Set("Clear-Site-Data", `"cache", "storage"`)
	_, _ = w.Write([]byte(killSW))
}
