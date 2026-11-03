package web

import (
	"context"
	"crypto/subtle"
	"errors"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"golang.org/x/crypto/bcrypt"

	"leakguard/internal/config"
	"leakguard/internal/ldapx"
	"leakguard/internal/model"
	"leakguard/internal/store"
)

func (s *Server) requireAuth(next http.HandlerFunc) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c, err := r.Cookie(cookieSession)
		if err != nil || c.Value == "" {
			http.Redirect(w, r, "/login", http.StatusSeeOther)
			return
		}
		se, err := s.store.GetSession(r.Context(), hashToken(c.Value))
		if err == nil && se.Role == "" { // Sitzung aus Version ohne Rollen -> neu anmelden
			_ = s.store.DeleteSession(r.Context(), se.TokenHash)
			err = store.ErrNotFound
		}
		if err != nil {
			s.clearCookie(w, cookieSession)
			http.Redirect(w, r, "/login", http.StatusSeeOther)
			return
		}
		if r.Method == http.MethodPost {
			tok := r.FormValue("csrf")
			if subtle.ConstantTimeCompare([]byte(tok), []byte(se.CSRF)) != 1 {
				http.Error(w, "CSRF-Token ungültig – bitte Seite neu laden", http.StatusForbidden)
				return
			}
		}
		next(w, r.WithContext(context.WithValue(r.Context(), sessionKey, se)))
	})
}

func (s *Server) setCookie(w http.ResponseWriter, name, val string, maxAge int) {
	http.SetCookie(w, &http.Cookie{Name: name, Value: val, Path: "/", MaxAge: maxAge, HttpOnly: true,
		Secure: s.cfg.CookieSecure, SameSite: http.SameSiteLaxMode})
}

func (s *Server) clearCookie(w http.ResponseWriter, name string) { s.setCookie(w, name, "", -1) }

type loginData struct {
	Username string
	PreCSRF  string
	LDAP     bool
	Dev      bool
}

func (s *Server) handleLoginForm(w http.ResponseWriter, r *http.Request) {
	pre := randToken(24)
	s.setCookie(w, cookiePre, pre, 900)
	s.render(w, r, "login", page{Title: "Anmeldung", Data: loginData{PreCSRF: pre, LDAP: s.ldap.Enabled(), Dev: s.cfg.DevAdmin.Enabled}})
}

func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	user := strings.TrimSpace(r.FormValue("username"))
	pass := r.FormValue("password")
	ip := s.clientIP(r)

	again := func(msg string) {
		pre := randToken(24)
		s.setCookie(w, cookiePre, pre, 900)
		w.WriteHeader(http.StatusUnauthorized)
		s.render(w, r, "login", page{Title: "Anmeldung", Err: msg,
			Data: loginData{Username: user, PreCSRF: pre, LDAP: s.ldap.Enabled(), Dev: s.cfg.DevAdmin.Enabled}})
	}

	pc, err := r.Cookie(cookiePre)
	if err != nil || subtle.ConstantTimeCompare([]byte(pc.Value), []byte(r.FormValue("csrf"))) != 1 {
		again("Sitzung abgelaufen – bitte erneut versuchen.")
		return
	}
	key := ip + "|" + strings.ToLower(user)
	if s.limiter.blocked(key) || s.limiter.blocked(ip) {
		slog.Warn("login rate limited", "user", user, "ip", ip)
		again("Zu viele Fehlversuche. Bitte in einigen Minuten erneut versuchen.")
		return
	}

	id, err := s.authenticate(user, pass)
	if err != nil {
		s.limiter.fail(key)
		s.limiter.fail(ip)
		slog.Warn("login failed", "user", user, "ip", ip, "err", err)
		s.store.Audit(r.Context(), model.AuditEntry{Actor: user, IP: ip, Action: "login_failed", Detail: err.Error()})
		switch {
		case errors.Is(err, ldapx.ErrNotAuthorized):
			again("Ihr Konto ist keiner Rolle zugeordnet (Gruppenmitgliedschaft fehlt).")
		case errors.Is(err, ldapx.ErrInvalidCredentials):
			again("Benutzername oder Kennwort falsch.")
		default:
			again("Anmeldung derzeit nicht möglich (Verzeichnisdienst nicht erreichbar).")
		}
		return
	}
	s.limiter.reset(key)

	token := randToken(32)
	se := store.Session{TokenHash: hashToken(token), Username: id.Username, Display: id.Display, Mail: id.Mail, Role: id.Role, CSRF: randToken(24),
		ExpiresAt: time.Now().Add(time.Duration(s.cfg.SessionHours) * time.Hour)}
	if err := s.store.CreateSession(r.Context(), se); err != nil {
		again("Interner Fehler beim Anlegen der Sitzung.")
		return
	}
	s.clearCookie(w, cookiePre)
	s.setCookie(w, cookieSession, token, s.cfg.SessionHours*3600)
	_ = s.store.UpsertUser(r.Context(), model.User{Username: id.Username, Display: id.Display, Mail: id.Mail, Role: id.Role})
	s.store.Audit(r.Context(), model.AuditEntry{Actor: id.Username, IP: ip, Action: "login", Detail: "Rolle " + roleLabel(id.Role)})
	slog.Info("login ok", "user", id.Username, "role", id.Role, "ip", ip)
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func (s *Server) authenticate(user, pass string) (ldapx.Identity, error) {
	if s.cfg.DevAdmin.Enabled && strings.EqualFold(user, s.cfg.DevAdmin.Username) {
		if pass != "" && bcrypt.CompareHashAndPassword([]byte(s.cfg.DevAdmin.PasswordHash), []byte(pass)) == nil {
			return ldapx.Identity{Username: s.cfg.DevAdmin.Username, Display: s.cfg.DevAdmin.Username + " (lokal)", Role: config.RoleAdmin}, nil
		}
		return ldapx.Identity{}, ldapx.ErrInvalidCredentials
	}
	if !s.ldap.Enabled() {
		return ldapx.Identity{}, ldapx.ErrInvalidCredentials
	}
	var roles []ldapx.RoleGroups
	for _, rg := range s.cfg.Roles.Ordered() {
		roles = append(roles, ldapx.RoleGroups{Role: rg.Role, Groups: rg.Groups})
	}
	return s.ldap.Authenticate(user, pass, roles)
}

func (s *Server) handleLogout(w http.ResponseWriter, r *http.Request) {
	if se := sessionFrom(r); se != nil {
		_ = s.store.DeleteSession(r.Context(), se.TokenHash)
		s.audit(r, "logout", "", 0, 0, "")
	}
	s.clearCookie(w, cookieSession)
	http.Redirect(w, r, "/login?msg=loggedout", http.StatusSeeOther)
}
