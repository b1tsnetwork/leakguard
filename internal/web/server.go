// Package web stellt die Weboberfläche bereit.
package web

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"embed"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"html/template"
	"io/fs"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"leakguard/internal/config"
	"leakguard/internal/engine"
	"leakguard/internal/ldapx"
	"leakguard/internal/mailer"
	"leakguard/internal/model"
	"leakguard/internal/store"
)

//go:embed templates/*.html
var templateFS embed.FS

//go:embed static/*
var staticFS embed.FS

type ctxKey int

const sessionKey ctxKey = 1

const (
	cookieSession = "lg_session"
	cookiePre     = "lg_pre"
)

type Server struct {
	cfg     *config.Config
	store   *store.Store
	ldap    *ldapx.Client
	engine  *engine.Engine
	mailer  *mailer.Mailer
	pages   map[string]*template.Template
	limiter *limiter
	Version string
}

func New(cfg *config.Config, st *store.Store, l *ldapx.Client, e *engine.Engine, m *mailer.Mailer, version string) (*Server, error) {
	s := &Server{cfg: cfg, store: st, ldap: l, engine: e, mailer: m, limiter: newLimiter(), Version: version}
	if err := s.parseTemplates(); err != nil {
		return nil, err
	}
	return s, nil
}

func (s *Server) parseTemplates() error {
	funcs := template.FuncMap{
		"dt": func(t time.Time) string {
			if t.IsZero() {
				return "–"
			}
			return t.Local().Format("02.01.2006 15:04")
		},
		"date": func(t time.Time) string {
			if t.IsZero() {
				return "–"
			}
			return t.Local().Format("02.01.2006")
		},
		"ago": func(t time.Time) string {
			if t.IsZero() {
				return ""
			}
			d := time.Since(t)
			switch {
			case d < 48*time.Hour:
				return fmt.Sprintf("vor %d Std.", int(d.Hours()))
			default:
				return fmt.Sprintf("vor %d Tagen", int(d.Hours()/24))
			}
		},
		"statusLabel": statusLabel,
		"riskLabel":   func(r string) string { return strings.ToUpper(r[:1]) + r[1:] },
		"add":         func(a, b int) int { return a + b },
		"sub":         func(a, b int) int { return a - b },
		"join":        strings.Join,
		"deref":       func(b *bool) bool { return b != nil && *b },
		"statuses":    func() []string { return model.Statuses },
		"risks": func() []string {
			return []string{model.RiskCritical, model.RiskHigh, model.RiskMedium, model.RiskLow, model.RiskInfo}
		},
	}
	pages, err := fs.Glob(templateFS, "templates/*.html")
	if err != nil {
		return err
	}
	s.pages = map[string]*template.Template{}
	for _, p := range pages {
		name := strings.TrimSuffix(strings.TrimPrefix(p, "templates/"), ".html")
		if name == "layout" {
			continue
		}
		t, err := template.New("").Funcs(funcs).ParseFS(templateFS, "templates/layout.html", p)
		if err != nil {
			return fmt.Errorf("template %s: %w", p, err)
		}
		s.pages[name] = t
	}
	return nil
}

func statusLabel(st string) string {
	switch st {
	case model.StatusOpen:
		return "Offen"
	case model.StatusInProgress:
		return "In Bearbeitung"
	case model.StatusClosed:
		return "Abgeschlossen"
	}
	return st
}

func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	static, _ := fs.Sub(staticFS, "static")
	mux.Handle("GET /static/", http.StripPrefix("/static/", cacheStatic(http.FileServer(http.FS(static)))))
	mux.HandleFunc("GET /healthz", s.handleHealth)
	mux.HandleFunc("GET /login", s.handleLoginForm)
	mux.HandleFunc("POST /login", s.handleLogin)

	auth := func(h http.HandlerFunc) http.Handler { return s.requireAuth(h) }
	mux.Handle("POST /logout", auth(s.handleLogout))
	mux.Handle("GET /{$}", auth(s.handleList))
	mux.Handle("GET /export.csv", auth(s.handleExport))
	mux.Handle("GET /blocklist.txt", auth(s.handleBlocklist))
	mux.Handle("GET /cases/new", auth(s.handleNewForm))
	mux.Handle("POST /cases", auth(s.handleCreate))
	mux.Handle("GET /cases/{id}", auth(s.handleCase))
	mux.Handle("POST /cases/{id}/recheck", auth(s.handleRecheck))
	mux.Handle("POST /cases/{id}/mail/{kind}", auth(s.handleSendMail))
	mux.Handle("POST /cases/{id}/todo", auth(s.handleTodo))
	mux.Handle("POST /cases/{id}/status", auth(s.handleStatus))
	mux.Handle("POST /cases/{id}/note", auth(s.handleNote))
	mux.Handle("GET /settings", auth(s.handleSettings))
	mux.Handle("POST /settings", auth(s.handleSaveSettings))
	return s.securityHeaders(s.logRequests(mux))
}

func cacheStatic(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "public, max-age=3600")
		h.ServeHTTP(w, r)
	})
}

func (s *Server) securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("Content-Security-Policy", "default-src 'self'; img-src 'self' data:; style-src 'self'; script-src 'self'; frame-ancestors 'none'; form-action 'self'; base-uri 'none'")
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("X-Frame-Options", "DENY")
		h.Set("Referrer-Policy", "same-origin")
		h.Set("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
		if s.cfg.CookieSecure {
			h.Set("Strict-Transport-Security", "max-age=31536000")
		}
		if !strings.HasPrefix(r.URL.Path, "/static/") {
			h.Set("Cache-Control", "no-store")
		}
		next.ServeHTTP(w, r)
	})
}

type statusWriter struct {
	http.ResponseWriter
	code int
}

func (w *statusWriter) WriteHeader(c int) { w.code = c; w.ResponseWriter.WriteHeader(c) }

func (s *Server) logRequests(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		sw := &statusWriter{ResponseWriter: w, code: 200}
		next.ServeHTTP(sw, r)
		if strings.HasPrefix(r.URL.Path, "/static/") || r.URL.Path == "/healthz" {
			return
		}
		slog.Info("http", "method", r.Method, "path", r.URL.Path, "status", sw.code, "ip", s.clientIP(r), "dur", time.Since(start).Round(time.Millisecond))
	})
}

func (s *Server) clientIP(r *http.Request) string {
	if s.cfg.TrustProxy {
		if xf := r.Header.Get("X-Forwarded-For"); xf != "" {
			return strings.TrimSpace(strings.Split(xf, ",")[0])
		}
	}
	h, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return h
}

// ---------- Rendering ----------

type page struct {
	Title   string
	Nav     string
	Session *store.Session
	CSRF    string
	Msg     string
	Err     string
	Version string
	Data    any
}

var messages = map[string]string{
	"created":    "Fall angelegt und geprüft.",
	"rechecked":  "Prüfung erneut durchgeführt.",
	"usermail":   "E-Mail an den Benutzer wurde versendet.",
	"adminmail":  "Admin-Information wurde versendet.",
	"todo":       "Admin-ToDo aktualisiert.",
	"status":     "Status geändert.",
	"note":       "Notiz gespeichert.",
	"saved":      "Einstellungen gespeichert.",
	"loggedout":  "Sie wurden abgemeldet.",
	"closed":     "Fall abgeschlossen.",
	"reset":      "Vorlage auf Standard zurückgesetzt.",
	"mailerror":  "Mailversand fehlgeschlagen – Details im Verlauf.",
	"nopassword": "Gespeichertes Kennwort nicht lesbar – bitte Kennwort erneut eingeben.",
}

func (s *Server) render(w http.ResponseWriter, r *http.Request, name string, p page) {
	t, ok := s.pages[name]
	if !ok {
		http.Error(w, "template fehlt", 500)
		return
	}
	if se := sessionFrom(r); se != nil {
		p.Session, p.CSRF = se, se.CSRF
	}
	if p.Msg == "" {
		p.Msg = messages[r.URL.Query().Get("msg")]
	}
	p.Version = s.Version
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := t.ExecuteTemplate(w, "layout", p); err != nil {
		slog.Error("render", "page", name, "err", err)
	}
}

func (s *Server) fail(w http.ResponseWriter, r *http.Request, code int, msg string) {
	w.WriteHeader(code)
	s.render(w, r, "error", page{Title: "Fehler", Err: msg})
}

// ---------- Hilfen ----------

func randToken(n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return base64.RawURLEncoding.EncodeToString(b)
}

func hashToken(t string) string {
	h := sha256.Sum256([]byte(t))
	return hex.EncodeToString(h[:])
}

func sessionFrom(r *http.Request) *store.Session {
	se, _ := r.Context().Value(sessionKey).(*store.Session)
	return se
}

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/plain")
	_, _ = w.Write([]byte("ok\n"))
}

// ---------- Login-Rate-Limit ----------

type limiter struct {
	mu   sync.Mutex
	hits map[string][]time.Time
}

func newLimiter() *limiter { return &limiter{hits: map[string][]time.Time{}} }

const (
	limitWindow = 10 * time.Minute
	limitMax    = 5
)

func (l *limiter) blocked(key string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.prune(key)
	return len(l.hits[key]) >= limitMax
}

func (l *limiter) fail(key string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.hits[key] = append(l.hits[key], time.Now())
}

func (l *limiter) reset(key string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	delete(l.hits, key)
}

func (l *limiter) prune(key string) {
	cut := time.Now().Add(-limitWindow)
	var keep []time.Time
	for _, t := range l.hits[key] {
		if t.After(cut) {
			keep = append(keep, t)
		}
	}
	if len(keep) == 0 {
		delete(l.hits, key)
	} else {
		l.hits[key] = keep
	}
}

// Janitor räumt abgelaufene Sitzungen auf.
func (s *Server) Janitor(ctx context.Context) {
	t := time.NewTicker(30 * time.Minute)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			_ = s.store.PurgeSessions(ctx)
		}
	}
}
