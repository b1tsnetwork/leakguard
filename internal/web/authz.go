package web

import (
	"context"
	"net/http"

	"leakguard/internal/config"
	"leakguard/internal/model"
	"leakguard/internal/store"
)

func (s *Server) viewer(r *http.Request) store.Viewer {
	se := sessionFrom(r)
	if se == nil {
		return store.Viewer{}
	}
	return store.Viewer{Username: se.Username, SeeAll: se.Role == config.RoleAdmin}
}

func hasRole(se *store.Session, min string) bool {
	return se != nil && config.RoleRank(se.Role) >= config.RoleRank(min)
}

// requireRole schützt Routen mit einer globalen Mindestrolle.
func (s *Server) requireRole(min string, next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !hasRole(sessionFrom(r), min) {
			s.fail(w, r, http.StatusForbidden, "Dafür fehlt Ihnen die Berechtigung (benötigt: "+roleLabel(min)+").")
			return
		}
		next(w, r)
	}
}

// incidentRole ermittelt die wirksame Rolle im Vorfall:
//   - Admin: immer Leitung
//   - vertraulicher Vorfall: nur die Stab-Mitgliedschaft zählt (need-to-know)
//   - sonst: Maximum aus globaler Rolle und Mitgliedschaft
func (s *Server) incidentRole(ctx context.Context, se *store.Session, in *model.Incident) string {
	if se == nil {
		return ""
	}
	if se.Role == config.RoleAdmin {
		return model.IRoleLead
	}
	member := s.store.MemberRole(ctx, in.ID, se.Username)
	if in.Confidential {
		return member
	}
	base := map[string]string{config.RoleLead: model.IRoleLead, config.RoleResponder: model.IRoleMember, config.RoleViewer: model.IRoleObserver}[se.Role]
	if model.IRoleRank(member) > model.IRoleRank(base) {
		return member
	}
	return base
}

func roleLabel(r string) string {
	switch r {
	case config.RoleAdmin:
		return "Administrator"
	case config.RoleLead:
		return "Leitung"
	case config.RoleResponder:
		return "Bearbeiter"
	case config.RoleViewer:
		return "Leser"
	}
	return r
}

// audit schreibt einen Eintrag ins technische Prüfprotokoll.
func (s *Server) audit(r *http.Request, action, object string, objectID, incidentID int64, detail string) {
	actor := ""
	if se := sessionFrom(r); se != nil {
		actor = se.Username
	}
	s.store.Audit(r.Context(), model.AuditEntry{Actor: actor, IP: s.clientIP(r), Action: action, Object: object,
		ObjectID: objectID, IncidentID: incidentID, Detail: detail})
}
