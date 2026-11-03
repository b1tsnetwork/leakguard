package web

import (
	"encoding/json"
	"fmt"
	"net/http"
	"sync"
	"time"
)

// LiveEvent wird an verbundene Browser verteilt (Server-Sent Events).
// Er enthält bewusst nur Metadaten – die Seiten laden die Inhalte rechtegeprüft nach.
type LiveEvent struct {
	Incident int64  `json:"incident"` // 0 = global (z. B. Leak-Fall)
	Kind     string `json:"kind"`
	Actor    string `json:"actor"`
	Text     string `json:"text"`
	At       int64  `json:"at"`
}

type hub struct {
	mu   sync.Mutex
	subs map[chan LiveEvent]struct{}
}

func newHub() *hub { return &hub{subs: map[chan LiveEvent]struct{}{}} }

func (h *hub) subscribe() chan LiveEvent {
	ch := make(chan LiveEvent, 32)
	h.mu.Lock()
	h.subs[ch] = struct{}{}
	h.mu.Unlock()
	return ch
}

func (h *hub) unsubscribe(ch chan LiveEvent) {
	h.mu.Lock()
	delete(h.subs, ch)
	h.mu.Unlock()
	close(ch)
}

func (h *hub) publish(e LiveEvent) {
	e.At = time.Now().Unix()
	h.mu.Lock()
	defer h.mu.Unlock()
	for ch := range h.subs {
		select {
		case ch <- e:
		default: // langsamer Client – Ereignis verwerfen, Seite holt beim nächsten Ereignis alles nach
		}
	}
}

func (h *hub) count() int {
	h.mu.Lock()
	defer h.mu.Unlock()
	return len(h.subs)
}

// handleLive liefert den SSE-Strom. Ereignisse zu Vorfällen, die der Benutzer nicht sehen darf, werden gefiltert.
func (s *Server) handleLive(w http.ResponseWriter, r *http.Request) {
	se := sessionFrom(r)
	rc := http.NewResponseController(w)
	_ = rc.SetWriteDeadline(time.Time{}) // Server-WriteTimeout für diesen Strom aufheben
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Accel-Buffering", "no")
	w.WriteHeader(http.StatusOK)
	_, _ = fmt.Fprint(w, "retry: 5000\n: verbunden\n\n")
	_ = rc.Flush()

	ch := s.hub.subscribe()
	defer s.hub.unsubscribe(ch)
	ping := time.NewTicker(25 * time.Second)
	defer ping.Stop()
	v := s.viewer(r)
	for {
		select {
		case <-r.Context().Done():
			return
		case <-ping.C:
			if _, err := fmt.Fprint(w, ": ping\n\n"); err != nil {
				return
			}
			_ = rc.Flush()
		case e := <-ch:
			if e.Incident > 0 && !s.store.CanSee(r.Context(), v, e.Incident) {
				continue
			}
			if e.Actor == se.Username {
				e.Text = "" // eigene Änderungen nicht als Hinweis anzeigen
			}
			b, _ := json.Marshal(e)
			if _, err := fmt.Fprintf(w, "event: change\ndata: %s\n\n", b); err != nil {
				return
			}
			_ = rc.Flush()
		}
	}
}

// publish informiert alle Browser über eine Änderung.
func (s *Server) publish(r *http.Request, incident int64, kind, text string) {
	actor := ""
	if se := sessionFrom(r); se != nil {
		actor = se.Username
	}
	s.hub.publish(LiveEvent{Incident: incident, Kind: kind, Actor: actor, Text: text})
}
