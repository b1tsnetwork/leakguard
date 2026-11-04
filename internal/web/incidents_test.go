package web

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"leakguard/internal/config"
	"leakguard/internal/engine"
	"leakguard/internal/ldapx"
	"leakguard/internal/mailer"
	"leakguard/internal/model"
	"leakguard/internal/store"
)

type testEnv struct {
	t   *testing.T
	srv *Server
	st  *store.Store
	h   http.Handler
}

func newEnv(t *testing.T) *testEnv {
	t.Helper()
	cfg := &config.Config{Secret: strings.Repeat("s", 32), BaseURL: "http://x", SessionHours: 1,
		Policy: config.Policy{MinLength: 12, MinCategories: 3, Complexity: true}, Mail: config.Mail{Signature: "IT"}}
	cfg.Defaults() // wie beim Laden der Konfiguration
	st, err := store.Open(filepath.Join(t.TempDir(), "t.db"))
	if err != nil {
		t.Fatal(err)
	}
	ld, _ := ldapx.New(cfg.LDAP)
	eng, err := engine.New(cfg, ld, st)
	if err != nil {
		t.Fatal(err)
	}
	srv, err := New(cfg, st, ld, eng, mailer.New(cfg.SMTP, cfg.Mail), "test")
	if err != nil {
		t.Fatal(err)
	}
	e := &testEnv{t: t, srv: srv, st: st, h: srv.Handler()}
	for _, u := range []struct{ name, role string }{{"lead", config.RoleLead}, {"resp", config.RoleResponder}, {"view", config.RoleViewer}, {"admin", config.RoleAdmin}, {"other", config.RoleResponder}} {
		_ = st.CreateSession(context.Background(), store.Session{TokenHash: hashToken(u.name), Username: u.name, Display: strings.ToUpper(u.name), Role: u.role, CSRF: "c", ExpiresAt: time.Now().Add(time.Hour)})
		_ = st.UpsertUser(context.Background(), model.User{Username: u.name, Display: strings.ToUpper(u.name), Role: u.role})
	}
	return e
}

func (e *testEnv) do(user, method, path string, form url.Values) (int, string, string) {
	var req *http.Request
	if method == http.MethodPost {
		if form == nil {
			form = url.Values{}
		}
		form.Set("csrf", "c")
		req = httptest.NewRequest(method, path, strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	} else {
		req = httptest.NewRequest(method, path, nil)
	}
	req.AddCookie(&http.Cookie{Name: cookieSession, Value: user})
	rr := httptest.NewRecorder()
	e.h.ServeHTTP(rr, req)
	return rr.Code, rr.Body.String(), rr.Header().Get("Location")
}

func (e *testEnv) mustOK(user, method, path string, form url.Values) string {
	e.t.Helper()
	code, body, loc := e.do(user, method, path, form)
	if code != 200 && code != 303 {
		e.t.Fatalf("%s %s als %s: %d\n%s", method, path, user, code, body)
	}
	return loc + body
}

var idRe = regexp.MustCompile(`/incidents/(\d+)`)

func TestIncidentWorkflow(t *testing.T) {
	e := newEnv(t)

	// Leser darf keinen Vorfall anlegen
	if code, _, _ := e.do("view", "POST", "/incidents", url.Values{"title": {"x"}}); code != 403 {
		t.Fatalf("leser anlegen: %d", code)
	}
	aw := time.Now().Add(-2 * time.Hour).Format("2006-01-02T15:04")
	loc := e.mustOK("resp", "POST", "/incidents", url.Values{"title": {"Ransomware FS01"}, "category": {"ransomware"}, "severity": {"P1"},
		"tlp": {"AMBER"}, "lead": {"lead"}, "awareness_at": {aw}, "playbook": {"1"}, "regulation": {"dsgvo", "nis2"}, "personal_data": {"1"}})
	m := idRe.FindStringSubmatch(loc)
	if m == nil {
		t.Fatalf("keine Weiterleitung: %s", loc)
	}
	path := "/incidents/" + m[1]
	id := m[1]

	// Workflow „Ransomware“: zum Start nur die Schritte der Phase „Gemeldet“ inkl. Sofortmaßnahme
	tasks, _ := e.st.Tasks(context.Background(), mustInt(id))
	if len(tasks) < 3 {
		t.Fatalf("Workflow-Aufgaben fehlen: %d", len(tasks))
	}
	obl, _ := e.st.Obligations(context.Background(), mustInt(id))
	if len(obl) != 5 {
		t.Fatalf("Meldepflichten: %d", len(obl))
	}
	for _, o := range obl {
		if o.Key == "nis2_early" && time.Until(o.DueAt) > 23*time.Hour {
			t.Fatalf("NIS2-Frühwarnung falsch berechnet: %v", o.DueAt)
		}
	}

	// Alle Reiter rendern
	for _, tab := range []string{"lage", "tagebuch", "aufgaben", "kommunikation", "systeme", "iocs", "meldepflichten", "stab", "nachbereitung", "protokoll"} {
		body := e.mustOK("lead", "GET", path+"?tab="+tab, nil)
		if !strings.Contains(body, "</html>") {
			t.Fatalf("Reiter %s unvollständig", tab)
		}
	}

	// Bearbeiter: Tagebuch, Aufgabe, Systeme, IOC, Lagemeldung
	e.mustOK("resp", "POST", path+"/journal", url.Values{"kind": {"decision"}, "text": {"Netz FS01 getrennt – Entscheidung Leitung"}})
	e.mustOK("resp", "POST", path+"/tasks", url.Values{"title": {"Backups prüfen"}, "assignee": {"other"}, "priority": {"hoch"}})
	e.mustOK("resp", "POST", path+"/assets", url.Values{"name": {"FS01"}, "kind": {"server"}, "status": {"kompromittiert"}})
	e.mustOK("resp", "POST", path+"/iocs", url.Values{"type": {"ip"}, "value": {"203.0.113.5\n198.51.100.7"}})
	e.mustOK("resp", "POST", path+"/sitrep", url.Values{"situation": {"FS01 verschlüsselt, isoliert."}, "decisions": {"Lösegeld: nein"}})

	// Leser darf nichts ändern
	if code, _, _ := e.do("view", "POST", path+"/journal", url.Values{"text": {"x"}}); code != 403 {
		t.Fatalf("leser tagebuch: %d", code)
	}
	// Bearbeiter darf keine Phase ändern
	if code, _, _ := e.do("resp", "POST", path+"/phase", url.Values{"phase": {"eindaemmung"}}); code != 403 {
		t.Fatalf("bearbeiter phase: %d", code)
	}
	e.mustOK("lead", "POST", path+"/phase", url.Values{"phase": {"eindaemmung"}, "comment": {"FS01 isoliert"}})

	// Externe Kommunikation: Bearbeiter -> zur Freigabe; Freigabe nur durch Leitung
	e.mustOK("resp", "POST", path+"/comms", url.Values{"direction": {"aus"}, "scope": {"extern"}, "subject": {"Info an Versicherung"}, "party_type": {"insurance"}})
	comms, _ := e.st.Comms(context.Background(), mustInt(id))
	if comms[0].Status != "zur_freigabe" {
		t.Fatalf("externe Kommunikation ohne Freigabe: %s", comms[0].Status)
	}
	cpath := path + "/comms/" + itoa(int(comms[0].ID))
	if code, _, _ := e.do("resp", "POST", cpath, url.Values{"status": {"versendet"}}); code != 403 {
		t.Fatalf("bearbeiter freigabe: %d", code)
	}
	e.mustOK("lead", "POST", cpath, url.Values{"status": {"freigegeben"}})
	c, _ := e.st.GetComm(context.Background(), comms[0].ID)
	if c.ApprovedBy != "lead" {
		t.Fatalf("Freigabe nicht dokumentiert: %+v", c)
	}
	// Eingehende Anfrage mit Antwortpflicht erscheint im Lagezentrum
	e.mustOK("resp", "POST", path+"/comms", url.Values{"direction": {"ein"}, "scope": {"extern"}, "subject": {"Rückfrage BSI"}, "needs_reply": {"1"},
		"reply_due": {time.Now().Add(3 * time.Hour).Format("2006-01-02T15:04")}})
	lage := e.mustOK("view", "GET", "/", nil)
	for _, want := range []string{"Ransomware FS01", "Rückfrage BSI", "Frühe Erstmeldung"} {
		if !strings.Contains(lage, want) {
			t.Errorf("Lagezentrum enthält nicht %q", want)
		}
	}
	// Meldepflicht "nicht erforderlich" verlangt Begründung
	o := obl[0]
	opath := path + "/obligations/" + itoa(int(o.ID))
	e.mustOK("lead", "POST", opath, url.Values{"status": {"nicht_erforderlich"}})
	if o2, _ := e.st.GetObligation(context.Background(), o.ID); o2.Status != "offen" {
		t.Fatal("ohne Begründung darf nicht geschlossen werden")
	}
	e.mustOK("lead", "POST", opath, url.Values{"status": {"erledigt"}, "reference": {"AZ-123"}})

	// Tagebuch ist unveränderlich
	if l, n, err := e.srv.store.AuditLog(context.Background(), store.AuditFilter{}); err != nil || n == 0 || len(l) == 0 {
		t.Fatal(err)
	}
	if err := e.st.Exec(context.Background(), `UPDATE journal SET text='x'`); err == nil {
		t.Fatal("journal darf nicht änderbar sein")
	}

	// Bericht
	rep := e.mustOK("view", "GET", path+"/report", nil)
	for _, want := range []string{"Vorfallbericht", "Netz FS01 getrennt", "AZ-123", "203.0.113.5"} {
		if !strings.Contains(rep, want) {
			t.Errorf("Bericht enthält nicht %q", want)
		}
	}
}

func TestConfidentialIncident(t *testing.T) {
	e := newEnv(t)
	loc := e.mustOK("lead", "POST", "/incidents", url.Values{"title": {"Insider-Verdacht"}, "category": {"insider"}, "confidential": {"1"},
		"lead": {"lead"}, "awareness_at": {time.Now().Format("2006-01-02T15:04")}})
	path := idRe.FindString(loc)
	if code, _, _ := e.do("resp", "GET", path, nil); code != 404 {
		t.Fatalf("vertraulicher Vorfall für Nicht-Mitglied sichtbar: %d", code)
	}
	if body := e.mustOK("resp", "GET", "/", nil); strings.Contains(body, "Insider-Verdacht") {
		t.Fatal("vertraulicher Vorfall im Lagezentrum sichtbar")
	}
	if code, _, _ := e.do("admin", "GET", path, nil); code != 200 {
		t.Fatalf("admin: %d", code)
	}
	e.mustOK("lead", "POST", path+"/members", url.Values{"username": {"resp"}, "function": {"forensics"}, "role": {"beobachter"}})
	if code, _, _ := e.do("resp", "GET", path, nil); code != 200 {
		t.Fatalf("Mitglied: %d", code)
	}
	if code, _, _ := e.do("resp", "POST", path+"/journal", url.Values{"text": {"x"}}); code != 403 {
		t.Fatalf("Beobachter darf nicht schreiben: %d", code)
	}
}

func TestLeakEscalation(t *testing.T) {
	e := newEnv(t)
	c := &model.Case{CaseNumber: "SOC-9", CreatedBy: "resp", Identifier: "pat@firma.de", Risk: model.RiskHigh, Compliant: true,
		Checks: model.Checks{User: &model.ADUser{SAM: "pat", UPN: "pat@firma.de", DisplayName: "Pat"}, Reasons: []string{"Kennwort erfüllt die Richtlinie"}}}
	if err := e.st.CreateCase(context.Background(), c); err != nil {
		t.Fatal(err)
	}
	if code, _, _ := e.do("view", "POST", "/cases/1/escalate", nil); code != 403 {
		t.Fatalf("leser eskalieren: %d", code)
	}
	loc := e.mustOK("resp", "POST", "/cases/1/escalate", url.Values{"playbook": {"1"}})
	if !strings.Contains(loc, "/incidents/") {
		t.Fatalf("keine Weiterleitung: %s", loc)
	}
	in, err := e.st.IncidentByLeakCase(context.Background(), 1)
	if err != nil || in.Category != "credential_leak" || in.Severity != "P2" {
		t.Fatalf("Vorfall falsch: %+v %v", in, err)
	}
	as, _ := e.st.Assets(context.Background(), in.ID)
	if len(as) != 1 || as[0].Name != "pat" {
		t.Fatalf("Konto nicht als System übernommen: %+v", as)
	}
	// zweite Eskalation führt zum bestehenden Vorfall
	_, _, loc2 := e.do("resp", "POST", "/cases/1/escalate", nil)
	if !strings.HasSuffix(loc2, "/incidents/"+itoa(int(in.ID))) {
		t.Fatalf("doppelte Eskalation: %s", loc2)
	}
	if body := e.mustOK("resp", "GET", "/cases/1", nil); !strings.Contains(body, in.Number) {
		t.Fatal("Leak-Fall verlinkt den Vorfall nicht")
	}
}

func TestLiveFiltersConfidential(t *testing.T) {
	e := newEnv(t)
	loc := e.mustOK("lead", "POST", "/incidents", url.Values{"title": {"Geheim"}, "confidential": {"1"}, "lead": {"lead"}, "awareness_at": {time.Now().Format("2006-01-02T15:04")}})
	id := mustInt(idRe.FindStringSubmatch(loc)[1])
	if e.st.CanSee(context.Background(), store.Viewer{Username: "resp"}, id) {
		t.Fatal("CanSee: vertraulich für Nicht-Mitglied")
	}
	if !e.st.CanSee(context.Background(), store.Viewer{Username: "lead"}, id) {
		t.Fatal("CanSee: Leitung")
	}
}

func mustInt(s string) int64 {
	var n int64
	for _, c := range s {
		n = n*10 + int64(c-'0')
	}
	return n
}

func TestRecommendations(t *testing.T) {
	e := newEnv(t)
	loc := e.mustOK("resp", "POST", "/incidents", url.Values{"title": {"Ransomware Rathaus"}, "category": {"ransomware"}, "severity": {"P1"},
		"lead": {"lead"}, "awareness_at": {time.Now().Add(-time.Hour).Format("2006-01-02T15:04")}, "impact_a": {"1"}})
	path := idRe.FindString(loc)
	body := e.mustOK("resp", "GET", path+"?tab=empfehlungen", nil)
	for _, want := range []string{"Stab / Krisenstab einberufen", "Behördenleitung informieren", "Notbetrieb nach Notfallhandbuch", "Grundlage:"} {
		if !strings.Contains(body, want) {
			t.Errorf("Empfehlungen enthalten nicht %q", want)
		}
	}
	// Bearbeiter darf keine Leitungsempfehlung umsetzen
	if code, _, _ := e.do("resp", "POST", path+"/recs", url.Values{"key": {"crisis"}, "op": {"apply"}}); code != 403 {
		t.Fatalf("crisis durch Bearbeiter: %d", code)
	}
	e.mustOK("lead", "POST", path+"/recs", url.Values{"key": {"crisis"}, "op": {"apply"}})
	in, _ := e.st.GetIncident(context.Background(), mustInt(idRe.FindStringSubmatch(loc)[1]))
	if !in.CrisisMode || in.NextBriefing.IsZero() {
		t.Fatal("Lage nicht aktiviert")
	}
	// Aufgabe aus Empfehlung
	e.mustOK("resp", "POST", path+"/recs", url.Values{"key": {"emergency_ops"}, "op": {"apply"}})
	tasks, _ := e.st.Tasks(context.Background(), in.ID)
	found := false
	for _, tk := range tasks {
		found = found || strings.Contains(tk.Title, "Notbetrieb")
	}
	if !found {
		t.Fatal("Aufgabe aus Empfehlung fehlt")
	}
	// Dieselbe Empfehlung lässt sich nicht doppelt übernehmen
	_, _, l2 := e.do("resp", "POST", path+"/recs", url.Values{"key": {"emergency_ops"}, "op": {"apply"}})
	if !strings.Contains(l2, "rec_gone") {
		t.Fatalf("Empfehlung doppelt übernehmbar: %s", l2)
	}
	tasks2, _ := e.st.Tasks(context.Background(), in.ID)
	if len(tasks2) != len(tasks) {
		t.Fatalf("Aufgabe doppelt angelegt: %d → %d", len(tasks), len(tasks2))
	}
	for _, tk := range tasks2 {
		if strings.Contains(tk.Title, "Notbetrieb") && tk.RecKey != "emergency_ops" {
			t.Fatalf("Aufgabe nicht mit Empfehlung verknüpft: %q", tk.RecKey)
		}
	}
	if b := e.mustOK("resp", "GET", path+"?tab=empfehlungen", nil); strings.Contains(b, `value="emergency_ops"`) {
		t.Fatal("übernommene Empfehlung wird weiter angeboten")
	}
	// Link-Empfehlung: Reiter, Anker und Vorbelegung korrekt (nicht als %23 maskiert)
	if b := e.mustOK("resp", "GET", path+"?tab=empfehlungen", nil); !strings.Contains(b, "tab=kommunikation") || !strings.Contains(b, "f_party_type=management") ||
		!strings.Contains(b, "#comm-form") || strings.Contains(b, "%23comm-form") {
		t.Fatal("Link „Information dokumentieren“ fehlerhaft")
	}
	// Verwerfen nur mit Begründung, danach dokumentiert
	e.mustOK("resp", "POST", path+"/recs", url.Values{"key": {"police"}, "op": {"dismiss"}})
	if e.st.DismissedRecs(context.Background(), in.ID)["police"] {
		t.Fatal("ohne Begründung verworfen")
	}
	e.mustOK("resp", "POST", path+"/recs", url.Values{"key": {"police"}, "op": {"dismiss"}, "reason": {"ZAC bereits telefonisch informiert"}})
	if !e.st.DismissedRecs(context.Background(), in.ID)["police"] {
		t.Fatal("nicht verworfen")
	}
	j, _ := e.st.Journal(context.Background(), in.ID, "decision", false)
	if len(j) == 0 || !strings.Contains(j[0].Text, "ZAC bereits telefonisch") {
		t.Fatal("Verwerfen nicht im Tagebuch dokumentiert")
	}
	// Lagezentrum zeigt Handlungsbedarf
	if lage := e.mustOK("view", "GET", "/", nil); !strings.Contains(lage, "Handlungsbedarf") || !strings.Contains(lage, "Behördenleitung informieren") {
		t.Fatal("Handlungsbedarf fehlt im Lagezentrum")
	}
}

func TestStaleServiceWorkerKillSwitch(t *testing.T) {
	e := newEnv(t)
	req := httptest.NewRequest("GET", "/sw.js", nil) // ohne Anmeldung
	rr := httptest.NewRecorder()
	e.h.ServeHTTP(rr, req)
	if rr.Code != 200 || !strings.Contains(rr.Body.String(), "registration.unregister") {
		t.Fatalf("/sw.js: %d %s", rr.Code, rr.Body.String())
	}
	if !strings.Contains(rr.Header().Get("Clear-Site-Data"), `"storage"`) || !strings.Contains(rr.Header().Get("Content-Type"), "javascript") {
		t.Fatalf("Header: %v", rr.Header())
	}
}

func TestCancelRestorePurge(t *testing.T) {
	e := newEnv(t)
	aw := time.Now().Format("2006-01-02T15:04")
	loc := e.mustOK("lead", "POST", "/incidents", url.Values{"title": {"TESTVORFALL Schulung"}, "category": {"malware"}, "lead": {"lead"},
		"awareness_at": {aw}, "regulation": {"dsgvo"}})
	path := idRe.FindString(loc)
	id := mustInt(idRe.FindStringSubmatch(loc)[1])
	e.mustOK("lead", "POST", path+"/journal", url.Values{"kind": {"note"}, "text": {"Test"}})
	ctx := context.Background()

	// Normale Vorfälle sind gegen Löschen geschützt
	if err := e.st.Exec(ctx, `DELETE FROM journal WHERE incident_id=?`, id); err == nil {
		t.Fatal("Tagebuch eines aktiven Vorfalls darf nicht löschbar sein")
	}
	if err := e.st.PurgeIncident(ctx, id); err == nil {
		t.Fatal("nicht stornierter Vorfall darf nicht gelöscht werden")
	}
	// Stornieren: Bearbeiter nicht, ohne Begründung nicht
	if code, _, _ := e.do("resp", "POST", path+"/cancel", url.Values{"reason": {"Test"}}); code != 403 {
		t.Fatalf("Bearbeiter storniert: %d", code)
	}
	e.mustOK("lead", "POST", path+"/cancel", nil)
	if in, _ := e.st.GetIncident(ctx, id); in.Cancelled {
		t.Fatal("ohne Begründung storniert")
	}
	e.mustOK("lead", "POST", path+"/cancel", url.Values{"reason": {"Testvorfall Schulung"}})
	in, _ := e.st.GetIncident(ctx, id)
	if !in.Cancelled || in.CancelledBy != "lead" {
		t.Fatal("nicht storniert")
	}
	if body := e.mustOK("lead", "GET", "/", nil); strings.Contains(body, "TESTVORFALL") {
		t.Fatal("stornierter Vorfall im Lagezentrum")
	}
	if body := e.mustOK("lead", "GET", "/incidents?state=alle", nil); strings.Contains(body, "TESTVORFALL") {
		t.Fatal("stornierter Vorfall in „Alle“")
	}
	if body := e.mustOK("lead", "GET", "/incidents?state=storniert", nil); !strings.Contains(body, "TESTVORFALL") {
		t.Fatal("stornierter Vorfall nicht unter „Stornierte“")
	}
	if obl, _ := e.st.OpenObligations(ctx, store.Viewer{SeeAll: true}); len(obl) != 0 {
		t.Fatal("Fristen eines stornierten Vorfalls noch offen")
	}
	// Wiederherstellen und erneut stornieren
	e.mustOK("lead", "POST", path+"/restore", nil)
	if in, _ := e.st.GetIncident(ctx, id); in.Cancelled {
		t.Fatal("Storno nicht aufgehoben")
	}
	e.mustOK("lead", "POST", path+"/cancel", url.Values{"reason": {"doch Test"}})

	// Endgültig löschen: nur Admin, nur mit korrekter Nummer
	if code, _, _ := e.do("lead", "POST", path+"/purge", url.Values{"confirm": {in.Number}}); code != 403 {
		t.Fatalf("Leitung löscht: %d", code)
	}
	e.mustOK("admin", "POST", path+"/purge", url.Values{"confirm": {"falsch"}})
	if _, err := e.st.GetIncident(ctx, id); err != nil {
		t.Fatal("ohne korrekte Bestätigung gelöscht")
	}
	e.mustOK("admin", "POST", path+"/purge", url.Values{"confirm": {in.Number}})
	if _, err := e.st.GetIncident(ctx, id); err == nil {
		t.Fatal("nicht gelöscht")
	}
	if j, _ := e.st.Journal(ctx, id, "", true); len(j) != 0 {
		t.Fatal("Tagebuch nicht gelöscht")
	}
	l, _, _ := e.st.AuditLog(ctx, store.AuditFilter{Query: "endgültig gelöscht"})
	if len(l) != 1 || !strings.Contains(l[0].Detail, in.Number) || !strings.Contains(l[0].Detail, "doch Test") {
		t.Fatalf("Löschvermerk im Audit-Log fehlt: %+v", l)
	}
}

func TestWalls(t *testing.T) {
	e := newEnv(t)
	loc := e.mustOK("lead", "POST", "/incidents", url.Values{"title": {"Wand-Test"}, "category": {"ransomware"}, "severity": {"P1"},
		"lead": {"lead"}, "playbook": {"1"}, "regulation": {"dsgvo"}, "awareness_at": {time.Now().Format("2006-01-02T15:04")}})
	path := idRe.FindString(loc)
	e.mustOK("lead", "POST", path+"/assets", url.Values{"name": {"FS01"}, "kind": {"server"}, "status": {"kompromittiert"}})
	e.mustOK("lead", "POST", path+"/sitrep", url.Values{"situation": {"Lage stabil"}})
	g := e.mustOK("resp", "GET", "/wall", nil)
	for _, want := range []string{"wallroot", "Gesamtlage", "Wand-Test", "data-tiles", path + "/wall"} {
		if !strings.Contains(g, want) {
			t.Fatalf("globale Lagewand ohne %q", want)
		}
	}
	if strings.Contains(g, `class="topbar"`) {
		t.Fatal("Lagewand soll ohne normale Navigation rendern")
	}
	w := e.mustOK("resp", "GET", path+"/wall", nil)
	for _, want := range []string{"wall-incident", "Wand-Test", "Lage stabil", "Kompromittiert", "Meldefristen", "Einsatztagebuch", "Nächste Schritte"} {
		if !strings.Contains(w, want) {
			t.Fatalf("Vorfall-Lagewand ohne %q", want)
		}
	}
	if code, _, _ := e.do("resp", "GET", "/?wall=1", nil); code != 303 {
		t.Fatalf("altes Lesezeichen /?wall=1 soll umleiten: %d", code)
	}
	// vertraulich: Wand ebenso geschützt wie die Akte
	loc = e.mustOK("lead", "POST", "/incidents", url.Values{"title": {"Geheim-Wand"}, "category": {"insider"}, "confidential": {"1"},
		"lead": {"lead"}, "awareness_at": {time.Now().Format("2006-01-02T15:04")}})
	cp := idRe.FindString(loc)
	if code, _, _ := e.do("resp", "GET", cp+"/wall", nil); code != 404 {
		t.Fatalf("vertrauliche Lagewand für Nicht-Mitglied sichtbar: %d", code)
	}
	if g := e.mustOK("resp", "GET", "/wall", nil); strings.Contains(g, "Geheim-Wand") {
		t.Fatal("vertraulicher Vorfall auf globaler Lagewand")
	}
}
