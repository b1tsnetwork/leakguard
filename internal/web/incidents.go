package web

import (
	"fmt"
	"html/template"
	"log/slog"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"leakguard/internal/advisor"
	"leakguard/internal/config"
	"leakguard/internal/mailer"
	"leakguard/internal/model"
	"leakguard/internal/store"
)

// ---------- Hilfen ----------

func parseDT(v string) time.Time {
	v = strings.TrimSpace(v)
	for _, layout := range []string{"2006-01-02T15:04", "2006-01-02T15:04:05", "2006-01-02", "02.01.2006 15:04", "02.01.2006"} {
		if t, err := time.ParseInLocation(layout, v, time.Local); err == nil {
			return t
		}
	}
	return time.Time{}
}

func clip(s string, n int) string {
	s = strings.TrimSpace(strings.ReplaceAll(s, "\r\n", "\n"))
	if len(s) > n {
		return s[:n]
	}
	return s
}

func formBool(r *http.Request, k string) bool {
	v := r.FormValue(k)
	return v == "1" || v == "on" || v == "true"
}

func oneOf(v string, list []model.Labeled, def string) string {
	for _, l := range list {
		if l.Key == v {
			return v
		}
	}
	return def
}

func optOneOf(v string, list []config.Option, def string) string {
	for _, l := range list {
		if l.Key == v {
			return v
		}
	}
	return def
}

func labelOf(list []model.Labeled, key string) string {
	for _, l := range list {
		if l.Key == key {
			return l.Label
		}
	}
	return key
}

func pathID(r *http.Request, name string) int64 {
	id, _ := strconv.ParseInt(r.PathValue(name), 10, 64)
	return id
}

// loadIncident lädt einen Vorfall inkl. wirksamer Rolle; unsichtbare Vorfälle liefern 404.
func (s *Server) loadIncident(w http.ResponseWriter, r *http.Request, min string) *model.Incident {
	in, err := s.store.GetIncident(r.Context(), pathID(r, "id"))
	if err != nil {
		s.fail(w, r, http.StatusNotFound, "Vorfall nicht gefunden.")
		return nil
	}
	in.MyRole = s.incidentRole(r.Context(), sessionFrom(r), in)
	if in.MyRole == "" {
		s.fail(w, r, http.StatusNotFound, "Vorfall nicht gefunden.")
		return nil
	}
	if model.IRoleRank(in.MyRole) < model.IRoleRank(min) {
		s.fail(w, r, http.StatusForbidden, "Für diese Aktion benötigen Sie im Vorfall die Rolle „"+labelOf(model.IncidentRoles, min)+"“.")
		return nil
	}
	return in
}

// jlog schreibt einen Eintrag ins Einsatztagebuch und benachrichtigt Live-Clients.
func (s *Server) jlog(r *http.Request, incidentID int64, kind, text string, auto bool) {
	se := sessionFrom(r)
	e := &model.JournalEntry{IncidentID: incidentID, Actor: se.Username, Kind: kind, Text: text, Auto: auto}
	if err := s.store.AddJournal(r.Context(), e); err != nil {
		slog.Error("journal", "err", err)
	}
	s.publish(r, incidentID, kind, se.Display+": "+firstLine(text))
}

func firstLine(s string) string {
	s, _, _ = strings.Cut(s, "\n")
	if len(s) > 140 {
		s = s[:140] + "…"
	}
	return s
}

func back(w http.ResponseWriter, r *http.Request, id int64, tab, msg string) {
	u := fmt.Sprintf("/incidents/%d", id)
	q := url.Values{}
	if tab != "" {
		q.Set("tab", tab)
	}
	if msg != "" {
		q.Set("msg", msg)
	}
	if len(q) > 0 {
		u += "?" + q.Encode()
	}
	http.Redirect(w, r, u, http.StatusSeeOther)
}

func (s *Server) names(r *http.Request) (map[string]string, []model.User) {
	users, _ := s.store.Users(r.Context())
	m := map[string]string{}
	for _, u := range users {
		m[strings.ToLower(u.Username)] = u.Display
	}
	return m, users
}

// ---------- Liste ----------

type incListData struct {
	Incidents []*model.Incident
	Filter    model.IncidentFilter
	Counts    map[int64]store.IncidentCounts
	Names     map[string]string
	CanCreate bool
}

func (s *Server) handleIncidents(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	f := model.IncidentFilter{Query: q.Get("q"), State: q.Get("state"), Severity: q.Get("sev"), Category: q.Get("cat")}
	list, err := s.store.ListIncidents(r.Context(), s.viewer(r), f)
	if err != nil {
		s.fail(w, r, 500, err.Error())
		return
	}
	counts := map[int64]store.IncidentCounts{}
	for _, in := range list {
		counts[in.ID] = s.store.Counts(r.Context(), in.ID)
	}
	names, _ := s.names(r)
	if f.State == "" {
		f.State = "aktiv"
	}
	s.render(w, r, "incidents", page{Title: "Vorfälle", Nav: "incidents", Data: incListData{Incidents: list, Filter: f, Counts: counts,
		Names: names, CanCreate: hasRole(sessionFrom(r), config.RoleResponder)}})
}

// ---------- Neuer Vorfall ----------

type incNewData struct {
	In       model.Incident
	Users    []model.User
	LeakCase int64
	Now      time.Time
}

func (s *Server) handleIncidentNew(w http.ResponseWriter, r *http.Request) {
	_, users := s.names(r)
	now := time.Now()
	s.render(w, r, "incident_new", page{Title: "Neuer Vorfall", Nav: "incidents", Data: incNewData{
		In: model.Incident{Severity: "P3", TLP: "AMBER", Category: r.URL.Query().Get("cat"), Lead: sessionFrom(r).Username,
			DetectedAt: now, AwarenessAt: now}, Users: users, Now: now}})
}

func (s *Server) incidentFromForm(r *http.Request, in *model.Incident) []string {
	ic := &s.cfg.Incident
	in.Title = clip(r.FormValue("title"), 200)
	in.Category = optOneOf(r.FormValue("category"), ic.Categories, "other")
	in.Severity = oneOf(r.FormValue("severity"), model.Severities, "P3")
	in.TLP = oneOf(r.FormValue("tlp"), model.TLPs, "AMBER")
	in.Classification = oneOf(r.FormValue("classification"), []model.Labeled{{Key: ""}, {Key: "VS-NfD"}}, "")
	in.Confidential = formBool(r, "confidential")
	in.Description = clip(r.FormValue("description"), 20000)
	in.Source = clip(r.FormValue("source"), 300)
	in.ReportedBy = clip(r.FormValue("reported_by"), 200)
	in.ImpactC, in.ImpactI, in.ImpactA = formBool(r, "impact_c"), formBool(r, "impact_i"), formBool(r, "impact_a")
	in.PersonalData = formBool(r, "personal_data")
	in.AffectedUsers, _ = strconv.Atoi(r.FormValue("affected_users"))
	in.OccurredAt = parseDT(r.FormValue("occurred_at"))
	in.DetectedAt = parseDT(r.FormValue("detected_at"))
	in.AwarenessAt = parseDT(r.FormValue("awareness_at"))
	var errs []string
	if in.Title == "" {
		errs = append(errs, "Titel fehlt")
	}
	if in.AwarenessAt.IsZero() {
		in.AwarenessAt = time.Now()
	}
	return errs
}

func (s *Server) handleIncidentCreate(w http.ResponseWriter, r *http.Request) {
	se := sessionFrom(r)
	in := &model.Incident{Phase: model.PhaseReported, CreatedBy: se.Username}
	errs := s.incidentFromForm(r, in)
	in.Lead = strings.TrimSpace(r.FormValue("lead"))
	if in.Lead == "" {
		in.Lead = se.Username
	}
	in.CrisisMode = formBool(r, "crisis_mode")
	if len(errs) > 0 {
		_, users := s.names(r)
		w.WriteHeader(http.StatusBadRequest)
		s.render(w, r, "incident_new", page{Title: "Neuer Vorfall", Nav: "incidents", Err: strings.Join(errs, " · "), Data: incNewData{In: *in, Users: users, Now: time.Now()}})
		return
	}
	if err := s.createIncident(r, in, formBool(r, "playbook"), r.Form["regulation"]); err != nil {
		s.fail(w, r, 500, err.Error())
		return
	}
	back(w, r, in.ID, "", "inc_created")
}

// createIncident legt Vorfall, Stab (Leitung + Ersteller), Playbook-Aufgaben und Meldepflichten an.
func (s *Server) createIncident(r *http.Request, in *model.Incident, playbook bool, regulations []string) error {
	ctx := r.Context()
	se := sessionFrom(r)
	if err := s.store.CreateIncident(ctx, s.cfg.Incident.NumberPrefix, in); err != nil {
		return err
	}
	s.audit(r, "incident_create", "incident", in.ID, in.ID, in.Number+" "+in.Title)
	names, _ := s.names(r)
	addMember := func(user, fn, role string) {
		d := names[strings.ToLower(user)]
		if d == "" {
			d = user
		}
		_ = s.store.UpsertMember(ctx, model.Member{IncidentID: in.ID, Username: user, Display: d, Function: fn, Role: role, AddedBy: se.Username})
	}
	addMember(in.Lead, "lead", model.IRoleLead)
	if !strings.EqualFold(in.Lead, se.Username) {
		addMember(se.Username, "s2", model.IRoleMember)
	}
	cat := s.cfg.Incident.Category(in.Category).Label
	s.jlog(r, in.ID, "status", fmt.Sprintf("Vorfall angelegt: %s · %s · %s · %s. Leitung: %s", in.Title, cat,
		labelOf(model.Severities, in.Severity), in.TLP, in.Lead), true)
	if playbook {
		n := 0
		for _, pt := range s.cfg.Incident.Playbook(in.Category) {
			t := &model.Task{IncidentID: in.ID, Title: pt.Title, Details: pt.Details, Function: pt.Function,
				Priority: oneOf(pt.Priority, model.Priorities, "mittel"), CreatedBy: se.Username}
			if pt.DueHours > 0 {
				t.DueAt = in.AwarenessAt.Add(time.Duration(pt.DueHours) * time.Hour)
			}
			if s.store.CreateTask(ctx, t) == nil {
				n++
			}
		}
		if n > 0 {
			s.jlog(r, in.ID, "task", fmt.Sprintf("%d Aufgaben aus dem Playbook „%s“ angelegt", n, cat), true)
		}
	}
	for _, key := range regulations {
		s.activateRegulation(r, in, key)
	}
	s.notifyNewIncident(in)
	return nil
}

func (s *Server) activateRegulation(r *http.Request, in *model.Incident, key string) {
	reg, ok := s.cfg.Incident.Regulation(key)
	if !ok {
		return
	}
	for _, d := range reg.Deadlines {
		_ = s.store.AddObligation(r.Context(), model.Obligation{IncidentID: in.ID, Regulation: reg.Key, Key: d.Key, Label: d.Label,
			Authority: reg.Authority, Hours: d.Hours, After: d.After})
	}
	s.audit(r, "obligation_activate", "incident", in.ID, in.ID, reg.Label)
	s.jlog(r, in.ID, "deadline", "Meldepflicht geprüft/aktiviert: "+reg.Label+" (Fristbeginn "+in.AwarenessAt.Local().Format("02.01.2006 15:04")+")", true)
}

func (s *Server) notifyNewIncident(in *model.Incident) {
	n := s.cfg.Incident.Notify
	if len(n.NewIncidentRecipients) == 0 || !s.mailer.Enabled() {
		return
	}
	min := n.NewIncidentMinSeverity
	if min == "" {
		min = "P2"
	}
	if in.Severity > min { // "P1" < "P2" < …
		return
	}
	msg := mailer.Message{To: n.NewIncidentRecipients,
		Subject: fmt.Sprintf("[%s] Neuer Sicherheitsvorfall %s – %s", in.Severity, in.Number, in.Title),
		Body: fmt.Sprintf("Neuer Sicherheitsvorfall %s\n\nTitel:     %s\nSchwere:   %s\nTLP:       %s\nLeitung:   %s\n\n%s/incidents/%d\n\nTLP beachten – Inhalte nicht weiterleiten.",
			in.Number, in.Title, labelOf(model.Severities, in.Severity), in.TLP, in.Lead, s.cfg.BaseURL, in.ID)}
	if in.Confidential {
		msg.Body = fmt.Sprintf("Neuer vertraulicher Sicherheitsvorfall %s (Schwere %s).\n\nDetails nur in der Kommandozentrale:\n%s/incidents/%d", in.Number, in.Severity, s.cfg.BaseURL, in.ID)
	}
	go func() {
		if err := s.mailer.Send(msg); err != nil {
			slog.Warn("benachrichtigung neuer vorfall", "err", err)
		}
	}()
}

// ---------- Vorfallakte ----------

type incView struct {
	In          *model.Incident
	Tab         string
	CanEdit     bool
	CanLead     bool
	Members     []model.Member
	Journal     []model.JournalEntry
	Tasks       []model.Task
	Comms       []model.Communication
	Assets      []model.Asset
	IOCs        []model.IOC
	Obligations []model.Obligation
	Sitreps     []model.Sitrep
	Counts      store.IncidentCounts
	Users       []model.User
	Names       map[string]string
	Inactive    []config.Regulation
	LeakCase    *model.Case
	Audit       []model.AuditEntry
	JKind       string
	ShowAuto    bool
	Now         time.Time
	Advice      advisor.Result
	TopRecs     []advisor.Rec
	RecCount    int
}

var incTabs = []model.Labeled{
	{Key: "lage", Label: "Lage"},
	{Key: "empfehlungen", Label: "Empfehlungen"},
	{Key: "tagebuch", Label: "Einsatztagebuch"},
	{Key: "aufgaben", Label: "Aufgaben"},
	{Key: "kommunikation", Label: "Kommunikation"},
	{Key: "systeme", Label: "Systeme"},
	{Key: "iocs", Label: "IOCs"},
	{Key: "meldepflichten", Label: "Meldepflichten"},
	{Key: "stab", Label: "Stab"},
	{Key: "nachbereitung", Label: "Nachbereitung"},
	{Key: "protokoll", Label: "Audit"},
}

func (s *Server) incidentView(r *http.Request, in *model.Incident) *incView {
	ctx := r.Context()
	v := &incView{In: in, CanEdit: model.IRoleRank(in.MyRole) >= 2, CanLead: in.MyRole == model.IRoleLead, Now: time.Now()}
	v.Tab = oneOf(r.URL.Query().Get("tab"), incTabs, "lage")
	v.JKind = r.URL.Query().Get("kind")
	v.ShowAuto = r.URL.Query().Get("auto") != "0"
	v.Members, _ = s.store.Members(ctx, in.ID)
	v.Journal, _ = s.store.Journal(ctx, in.ID, v.JKind, v.ShowAuto)
	v.Tasks, _ = s.store.Tasks(ctx, in.ID)
	v.Comms, _ = s.store.Comms(ctx, in.ID)
	v.Assets, _ = s.store.Assets(ctx, in.ID)
	v.IOCs, _ = s.store.IOCs(ctx, in.ID)
	v.Obligations, _ = s.store.Obligations(ctx, in.ID)
	v.Sitreps, _ = s.store.Sitreps(ctx, in.ID)
	v.Counts = s.store.Counts(ctx, in.ID)
	v.Names, v.Users = s.names(r)
	active := map[string]bool{}
	for _, o := range v.Obligations {
		active[o.Regulation] = true
	}
	for _, reg := range s.cfg.Incident.Regulations {
		if !active[reg.Key] {
			v.Inactive = append(v.Inactive, reg)
		}
	}
	if in.LeakCaseID > 0 {
		v.LeakCase, _ = s.store.GetCase(ctx, in.LeakCaseID)
	}
	v.Advice = s.advise(r, in)
	for _, rc := range v.Advice.Recs {
		if rc.Priority == advisor.PrioCritical || rc.Priority == advisor.PrioHigh {
			v.RecCount++
		}
	}
	v.TopRecs = v.Advice.Recs
	if len(v.TopRecs) > 5 {
		v.TopRecs = v.TopRecs[:5]
	}
	if v.Tab == "protokoll" && v.CanLead {
		v.Audit, _, _ = s.store.AuditLog(ctx, store.AuditFilter{IncidentID: in.ID, Limit: 500})
	}
	return v
}

func (s *Server) handleIncident(w http.ResponseWriter, r *http.Request) {
	in := s.loadIncident(w, r, model.IRoleObserver)
	if in == nil {
		return
	}
	v := s.incidentView(r, in)
	if v.Tab == "protokoll" && !v.CanLead {
		v.Tab = "lage"
	}
	s.render(w, r, "incident", page{Title: in.Number + " " + in.Title, Nav: "incidents", Data: v})
}

func (s *Server) handleIncidentReport(w http.ResponseWriter, r *http.Request) {
	in := s.loadIncident(w, r, model.IRoleObserver)
	if in == nil {
		return
	}
	v := s.incidentView(r, in)
	v.Journal, _ = s.store.Journal(r.Context(), in.ID, "", true)
	s.audit(r, "incident_report", "incident", in.ID, in.ID, "Bericht aufgerufen")
	s.render(w, r, "report", page{Title: "Bericht " + in.Number, Nav: "incidents", Data: v})
}

// ---------- Stammdaten, Phase, Lage ----------

func (s *Server) handleIncidentUpdate(w http.ResponseWriter, r *http.Request) {
	in := s.loadIncident(w, r, model.IRoleLead)
	if in == nil {
		return
	}
	old := *in
	if errs := s.incidentFromForm(r, in); len(errs) > 0 {
		back(w, r, in.ID, "lage", "invalid")
		return
	}
	if lead := strings.TrimSpace(r.FormValue("lead")); lead != "" {
		in.Lead = lead
	}
	var ch []string
	cmp := func(label, a, b string) {
		if a != b {
			ch = append(ch, fmt.Sprintf("%s: %s → %s", label, a, b))
		}
	}
	cmp("Titel", old.Title, in.Title)
	cmp("Kategorie", s.cfg.Incident.Category(old.Category).Label, s.cfg.Incident.Category(in.Category).Label)
	cmp("Schwere", old.Severity, in.Severity)
	cmp("TLP", old.TLP, in.TLP)
	cmp("VS-Einstufung", or(old.Classification, "keine"), or(in.Classification, "keine"))
	cmp("Vertraulich", yn(old.Confidential), yn(in.Confidential))
	cmp("Leitung", old.Lead, in.Lead)
	cmp("Personenbezogene Daten", yn(old.PersonalData), yn(in.PersonalData))
	cmp("Kenntnisnahme", fmtDT(old.AwarenessAt), fmtDT(in.AwarenessAt))
	if old.Description != in.Description {
		ch = append(ch, "Beschreibung geändert")
	}
	if err := s.store.UpdateIncident(r.Context(), in); err != nil {
		s.fail(w, r, 500, err.Error())
		return
	}
	if old.Lead != in.Lead {
		d := in.Lead
		if n, _ := s.names(r); n[strings.ToLower(d)] != "" {
			d = n[strings.ToLower(d)]
		}
		_ = s.store.UpsertMember(r.Context(), model.Member{IncidentID: in.ID, Username: in.Lead, Display: d, Function: "lead", Role: model.IRoleLead, AddedBy: sessionFrom(r).Username})
	}
	if len(ch) > 0 {
		s.audit(r, "incident_update", "incident", in.ID, in.ID, strings.Join(ch, "; "))
		s.jlog(r, in.ID, "status", "Stammdaten geändert: "+strings.Join(ch, "; "), true)
	}
	back(w, r, in.ID, "lage", "saved")
}

func (s *Server) handleIncidentPhase(w http.ResponseWriter, r *http.Request) {
	in := s.loadIncident(w, r, model.IRoleLead)
	if in == nil {
		return
	}
	phase := oneOf(r.FormValue("phase"), model.Phases, "")
	if phase == "" || phase == in.Phase {
		back(w, r, in.ID, "", "")
		return
	}
	if err := s.setPhase(r, in, phase, clip(r.FormValue("comment"), 2000)); err != nil {
		s.fail(w, r, 500, err.Error())
		return
	}
	back(w, r, in.ID, "", "phase")
}

// setPhase ändert die Phase, pflegt die Meilenstein-Zeitpunkte und dokumentiert den Wechsel.
func (s *Server) setPhase(r *http.Request, in *model.Incident, phase, comment string) error {
	now := time.Now()
	idx := func(p string) int {
		for i, x := range model.Phases {
			if x.Key == p {
				return i
			}
		}
		return 0
	}
	if idx(phase) >= idx(model.PhaseEradication) && in.ContainedAt.IsZero() {
		in.ContainedAt = now
	}
	if idx(phase) >= idx(model.PhasePostIncident) && in.ResolvedAt.IsZero() {
		in.ResolvedAt = now
	}
	if phase == model.PhaseClosed {
		in.ClosedAt, in.CrisisMode = now, false
	} else {
		in.ClosedAt = time.Time{}
	}
	old := in.Phase
	in.Phase = phase
	if err := s.store.UpdateIncident(r.Context(), in); err != nil {
		return err
	}
	txt := fmt.Sprintf("Phase: %s → %s", labelOf(model.Phases, old), labelOf(model.Phases, phase))
	if comment != "" {
		txt += "\nBegründung: " + comment
	}
	s.audit(r, "incident_phase", "incident", in.ID, in.ID, txt)
	s.jlog(r, in.ID, "status", txt, false)
	return nil
}

func (s *Server) handleIncidentCrisis(w http.ResponseWriter, r *http.Request) {
	in := s.loadIncident(w, r, model.IRoleLead)
	if in == nil {
		return
	}
	in.CrisisMode = formBool(r, "crisis_mode")
	in.NextBriefing = parseDT(r.FormValue("next_briefing"))
	if err := s.store.UpdateIncident(r.Context(), in); err != nil {
		s.fail(w, r, 500, err.Error())
		return
	}
	txt := "Lage/Krisenstab deaktiviert"
	if in.CrisisMode {
		txt = "Lage/Krisenstab AKTIV"
	}
	if !in.NextBriefing.IsZero() {
		txt += " · nächste Lagebesprechung " + fmtDT(in.NextBriefing)
	}
	s.audit(r, "incident_crisis", "incident", in.ID, in.ID, txt)
	s.jlog(r, in.ID, "status", txt, true)
	back(w, r, in.ID, "", "saved")
}

func (s *Server) handleIncidentPost(w http.ResponseWriter, r *http.Request) {
	in := s.loadIncident(w, r, model.IRoleLead)
	if in == nil {
		return
	}
	in.RootCause = clip(r.FormValue("root_cause"), 20000)
	in.Lessons = clip(r.FormValue("lessons"), 20000)
	in.Improvements = clip(r.FormValue("improvements"), 20000)
	if err := s.store.UpdateIncident(r.Context(), in); err != nil {
		s.fail(w, r, 500, err.Error())
		return
	}
	s.audit(r, "incident_postmortem", "incident", in.ID, in.ID, "Nachbereitung gespeichert")
	s.jlog(r, in.ID, "information", "Nachbereitung (Ursache / Lessons Learned / Maßnahmen) aktualisiert", true)
	back(w, r, in.ID, "nachbereitung", "saved")
}

// ---------- Einsatztagebuch ----------

func (s *Server) handleJournalAdd(w http.ResponseWriter, r *http.Request) {
	in := s.loadIncident(w, r, model.IRoleMember)
	if in == nil {
		return
	}
	text := clip(r.FormValue("text"), 20000)
	if text == "" {
		back(w, r, in.ID, "tagebuch", "")
		return
	}
	kind := r.FormValue("kind")
	ok := false
	for _, k := range model.ManualJournalKinds {
		ok = ok || k == kind
	}
	e := &model.JournalEntry{IncidentID: in.ID, Actor: sessionFrom(r).Username, Kind: kind, Text: text, OccurredAt: parseDT(r.FormValue("occurred_at"))}
	if ref, _ := strconv.ParseInt(r.FormValue("ref"), 10, 64); ref > 0 {
		e.Kind, e.RefID, ok = "correction", ref, true
	}
	if !ok {
		e.Kind = "note"
	}
	if err := s.store.AddJournal(r.Context(), e); err != nil {
		s.fail(w, r, 500, err.Error())
		return
	}
	s.audit(r, "journal_add", "journal", e.ID, in.ID, labelOf(model.JournalKinds, e.Kind)+": "+firstLine(text))
	s.publish(r, in.ID, e.Kind, sessionFrom(r).Display+": "+firstLine(text))
	tab := r.FormValue("return")
	if tab == "" {
		tab = "tagebuch"
	}
	back(w, r, in.ID, tab, "")
}

// ---------- Aufgaben ----------

func (s *Server) handleTaskCreate(w http.ResponseWriter, r *http.Request) {
	in := s.loadIncident(w, r, model.IRoleMember)
	if in == nil {
		return
	}
	t := &model.Task{IncidentID: in.ID, Title: clip(r.FormValue("title"), 300), Details: clip(r.FormValue("details"), 10000),
		Function: optOneOf(r.FormValue("function"), s.cfg.Incident.Functions, ""), Assignee: strings.TrimSpace(r.FormValue("assignee")),
		Priority: oneOf(r.FormValue("priority"), model.Priorities, "mittel"), DueAt: parseDT(r.FormValue("due_at")), CreatedBy: sessionFrom(r).Username}
	if t.Title == "" {
		back(w, r, in.ID, "aufgaben", "invalid")
		return
	}
	if err := s.store.CreateTask(r.Context(), t); err != nil {
		s.fail(w, r, 500, err.Error())
		return
	}
	txt := "Aufgabe #" + strconv.FormatInt(t.ID, 10) + ": " + t.Title
	if t.Assignee != "" {
		txt += " → " + t.Assignee
	}
	if !t.DueAt.IsZero() {
		txt += " (bis " + fmtDT(t.DueAt) + ")"
	}
	s.audit(r, "task_create", "task", t.ID, in.ID, txt)
	s.jlog(r, in.ID, "task", txt, true)
	s.notifyTask(r, in, t)
	back(w, r, in.ID, r.FormValue("return"), "")
}

func (s *Server) notifyTask(r *http.Request, in *model.Incident, t *model.Task) {
	if !s.cfg.Incident.Notify.TaskAssigned || t.Assignee == "" || !s.mailer.Enabled() || strings.EqualFold(t.Assignee, sessionFrom(r).Username) {
		return
	}
	u, err := s.store.User(r.Context(), t.Assignee)
	if err != nil || u.Mail == "" {
		return
	}
	body := fmt.Sprintf("Ihnen wurde im Vorfall %s eine Aufgabe zugewiesen:\n\n%s\nPriorität: %s\n", in.Number, t.Title, t.Priority)
	if !t.DueAt.IsZero() {
		body += "Fällig: " + fmtDT(t.DueAt) + "\n"
	}
	body += fmt.Sprintf("\n%s/incidents/%d?tab=aufgaben\n", s.cfg.BaseURL, in.ID)
	if in.Confidential {
		body = fmt.Sprintf("Ihnen wurde im vertraulichen Vorfall %s eine Aufgabe zugewiesen.\n\n%s/incidents/%d?tab=aufgaben\n", in.Number, s.cfg.BaseURL, in.ID)
	}
	go func() {
		_ = s.mailer.Send(mailer.Message{To: []string{u.Mail}, Subject: "[" + in.Number + "] Neue Aufgabe", Body: body})
	}()
}

func (s *Server) handleTaskUpdate(w http.ResponseWriter, r *http.Request) {
	in := s.loadIncident(w, r, model.IRoleMember)
	if in == nil {
		return
	}
	t, err := s.store.GetTask(r.Context(), pathID(r, "tid"))
	if err != nil || t.IncidentID != in.ID {
		s.fail(w, r, 404, "Aufgabe nicht gefunden")
		return
	}
	old := *t
	if v := r.FormValue("status"); v != "" {
		t.Status = oneOf(v, model.TaskStatuses, t.Status)
	}
	if _, ok := r.Form["assignee"]; ok {
		t.Assignee = strings.TrimSpace(r.FormValue("assignee"))
	}
	if v := r.FormValue("result"); v != "" {
		t.Result = clip(v, 10000)
	}
	if _, ok := r.Form["due_at"]; ok {
		t.DueAt = parseDT(r.FormValue("due_at"))
	}
	if !t.Open() && old.Open() {
		t.DoneAt, t.DoneBy = time.Now(), sessionFrom(r).Username
	} else if t.Open() {
		t.DoneAt, t.DoneBy = time.Time{}, ""
	}
	if err := s.store.UpdateTask(r.Context(), t); err != nil {
		s.fail(w, r, 500, err.Error())
		return
	}
	var ch []string
	if old.Status != t.Status {
		ch = append(ch, "Status "+labelOf(model.TaskStatuses, old.Status)+" → "+labelOf(model.TaskStatuses, t.Status))
	}
	if old.Assignee != t.Assignee {
		ch = append(ch, "zugewiesen an "+t.Assignee)
	}
	if old.Result != t.Result && t.Result != "" {
		ch = append(ch, "Rückmeldung: "+firstLine(t.Result))
	}
	if !old.DueAt.Equal(t.DueAt) {
		ch = append(ch, "Frist "+fmtDT(t.DueAt))
	}
	if len(ch) > 0 {
		txt := fmt.Sprintf("Aufgabe #%d „%s“: %s", t.ID, t.Title, strings.Join(ch, "; "))
		s.audit(r, "task_update", "task", t.ID, in.ID, txt)
		s.jlog(r, in.ID, "task", txt, true)
		if old.Assignee != t.Assignee {
			s.notifyTask(r, in, t)
		}
	}
	back(w, r, in.ID, r.FormValue("return"), "")
}

// ---------- Kommunikation ----------

func (s *Server) handleCommCreate(w http.ResponseWriter, r *http.Request) {
	in := s.loadIncident(w, r, model.IRoleMember)
	if in == nil {
		return
	}
	c := &model.Communication{IncidentID: in.ID, Direction: oneOf(r.FormValue("direction"), []model.Labeled{{Key: "ein"}, {Key: "aus"}}, "ein"),
		Scope:   oneOf(r.FormValue("scope"), []model.Labeled{{Key: "intern"}, {Key: "extern"}}, "intern"),
		Channel: oneOf(r.FormValue("channel"), model.CommChannels, "other"), PartyType: oneOf(r.FormValue("party_type"), model.CommParties, "other"),
		Party: clip(r.FormValue("party"), 300), Subject: clip(r.FormValue("subject"), 300), Content: clip(r.FormValue("content"), 50000),
		OccurredAt: parseDT(r.FormValue("occurred_at")), TLP: oneOf(r.FormValue("tlp"), model.TLPs, in.TLP),
		NeedsReply: formBool(r, "needs_reply"), ReplyDue: parseDT(r.FormValue("reply_due")), CreatedBy: sessionFrom(r).Username}
	if c.Subject == "" {
		back(w, r, in.ID, "kommunikation", "invalid")
		return
	}
	switch {
	case c.Direction == "ein" && c.NeedsReply:
		c.Status = "offen"
	case c.Direction == "ein":
		c.Status = "erledigt"
	case c.Scope == "extern" && r.FormValue("send_state") != "versendet":
		c.Status = "zur_freigabe" // externe Kommunikation: Vier-Augen-Freigabe durch Leitung
	case r.FormValue("send_state") == "entwurf":
		c.Status = "entwurf"
	default:
		c.Status = "versendet"
	}
	if c.Status == "versendet" && c.Scope == "extern" && !(in.MyRole == model.IRoleLead) {
		c.Status = "zur_freigabe"
	}
	if err := s.store.CreateComm(r.Context(), c); err != nil {
		s.fail(w, r, 500, err.Error())
		return
	}
	dir := map[string]string{"ein": "Eingang", "aus": "Ausgang"}[c.Direction]
	txt := fmt.Sprintf("%s %s (%s) %s %s: %s", dir, c.Scope, labelOf(model.CommChannels, c.Channel), map[string]string{"ein": "von", "aus": "an"}[c.Direction],
		strings.TrimSpace(c.Party+" / "+labelOf(model.CommParties, c.PartyType)), c.Subject)
	if c.Status == "zur_freigabe" {
		txt += " – wartet auf Freigabe"
	}
	if c.NeedsReply {
		txt += " – Antwort erforderlich"
		if !c.ReplyDue.IsZero() {
			txt += " bis " + fmtDT(c.ReplyDue)
		}
	}
	s.audit(r, "comm_create", "communication", c.ID, in.ID, txt)
	s.jlog(r, in.ID, "comm", txt, true)
	back(w, r, in.ID, "kommunikation", "")
}

func (s *Server) handleCommStatus(w http.ResponseWriter, r *http.Request) {
	in := s.loadIncident(w, r, model.IRoleMember)
	if in == nil {
		return
	}
	c, err := s.store.GetComm(r.Context(), pathID(r, "cid"))
	if err != nil || c.IncidentID != in.ID {
		s.fail(w, r, 404, "Eintrag nicht gefunden")
		return
	}
	st := oneOf(r.FormValue("status"), model.CommStatuses, "")
	if st == "" {
		back(w, r, in.ID, "kommunikation", "")
		return
	}
	// Externe Ausgänge dürfen nur nach Freigabe durch die Leitung versendet werden.
	if c.Scope == "extern" && c.Direction == "aus" && (st == "freigegeben" || st == "versendet") && c.ApprovedBy == "" {
		if in.MyRole != model.IRoleLead {
			s.fail(w, r, http.StatusForbidden, "Externe Kommunikation muss von der Leitung freigegeben werden.")
			return
		}
		c.ApprovedBy, c.ApprovedAt = sessionFrom(r).Username, time.Now()
	}
	old := c.Status
	c.Status = st
	if err := s.store.UpdateCommStatus(r.Context(), c); err != nil {
		s.fail(w, r, 500, err.Error())
		return
	}
	txt := fmt.Sprintf("Kommunikation „%s“: %s → %s", c.Subject, labelOf(model.CommStatuses, old), labelOf(model.CommStatuses, st))
	if c.ApprovedBy != "" && (st == "freigegeben" || st == "versendet") && old == "zur_freigabe" {
		txt += " (freigegeben durch " + c.ApprovedBy + ")"
	}
	if note := clip(r.FormValue("note"), 5000); note != "" {
		txt += "\n" + note
	}
	s.audit(r, "comm_status", "communication", c.ID, in.ID, txt)
	s.jlog(r, in.ID, "comm", txt, true)
	back(w, r, in.ID, r.FormValue("return"), "")
}

// ---------- Systeme ----------

func (s *Server) handleAssetCreate(w http.ResponseWriter, r *http.Request) {
	in := s.loadIncident(w, r, model.IRoleMember)
	if in == nil {
		return
	}
	a := &model.Asset{IncidentID: in.ID, Name: clip(r.FormValue("name"), 200), Kind: oneOf(r.FormValue("kind"), model.AssetKinds, "other"),
		Identifier: clip(r.FormValue("identifier"), 500), Owner: clip(r.FormValue("owner"), 200), Criticality: oneOf(r.FormValue("criticality"), model.Priorities, ""),
		Status: oneOf(r.FormValue("status"), model.AssetStatuses, "verdacht"), Notes: clip(r.FormValue("notes"), 10000), CreatedBy: sessionFrom(r).Username}
	if a.Name == "" {
		back(w, r, in.ID, "systeme", "invalid")
		return
	}
	if err := s.store.CreateAsset(r.Context(), a); err != nil {
		s.fail(w, r, 500, err.Error())
		return
	}
	txt := fmt.Sprintf("System erfasst: %s (%s) – %s", a.Name, labelOf(model.AssetKinds, a.Kind), labelOf(model.AssetStatuses, a.Status))
	s.audit(r, "asset_create", "asset", a.ID, in.ID, txt)
	s.jlog(r, in.ID, "system", txt, true)
	back(w, r, in.ID, "systeme", "")
}

func (s *Server) handleAssetUpdate(w http.ResponseWriter, r *http.Request) {
	in := s.loadIncident(w, r, model.IRoleMember)
	if in == nil {
		return
	}
	a, err := s.store.GetAsset(r.Context(), pathID(r, "aid"))
	if err != nil || a.IncidentID != in.ID {
		s.fail(w, r, 404, "System nicht gefunden")
		return
	}
	old := a.Status
	a.Status = oneOf(r.FormValue("status"), model.AssetStatuses, a.Status)
	note := clip(r.FormValue("note"), 5000)
	if note != "" {
		a.Notes = strings.TrimSpace(a.Notes + "\n" + time.Now().Format("02.01. 15:04") + " " + sessionFrom(r).Username + ": " + note)
	}
	a.UpdatedBy = sessionFrom(r).Username
	if err := s.store.UpdateAsset(r.Context(), a); err != nil {
		s.fail(w, r, 500, err.Error())
		return
	}
	txt := fmt.Sprintf("System %s: %s → %s", a.Name, labelOf(model.AssetStatuses, old), labelOf(model.AssetStatuses, a.Status))
	if note != "" {
		txt += "\n" + note
	}
	s.audit(r, "asset_update", "asset", a.ID, in.ID, txt)
	s.jlog(r, in.ID, "system", txt, true)
	back(w, r, in.ID, "systeme", "")
}

// ---------- IOCs ----------

func (s *Server) handleIOCCreate(w http.ResponseWriter, r *http.Request) {
	in := s.loadIncident(w, r, model.IRoleMember)
	if in == nil {
		return
	}
	typ := oneOf(r.FormValue("type"), model.IOCTypes, "other")
	desc := clip(r.FormValue("description"), 2000)
	n := 0
	// Mehrere Werte (eine Zeile pro IOC) auf einmal möglich
	for _, line := range strings.Split(r.FormValue("value"), "\n") {
		v := clip(line, 2000)
		if v == "" {
			continue
		}
		o := &model.IOC{IncidentID: in.ID, Type: typ, Value: v, Description: desc, TLP: oneOf(r.FormValue("tlp"), model.TLPs, in.TLP), CreatedBy: sessionFrom(r).Username}
		if s.store.CreateIOC(r.Context(), o) == nil {
			n++
			s.audit(r, "ioc_create", "ioc", o.ID, in.ID, labelOf(model.IOCTypes, typ)+": "+v)
		}
	}
	if n > 0 {
		s.jlog(r, in.ID, "observation", fmt.Sprintf("%d IOC(s) vom Typ %s erfasst", n, labelOf(model.IOCTypes, typ)), true)
	}
	back(w, r, in.ID, "iocs", "")
}

func (s *Server) handleIOCDelete(w http.ResponseWriter, r *http.Request) {
	in := s.loadIncident(w, r, model.IRoleMember)
	if in == nil {
		return
	}
	id := pathID(r, "oid")
	if err := s.store.DeleteIOC(r.Context(), in.ID, id); err != nil {
		s.fail(w, r, 500, err.Error())
		return
	}
	s.audit(r, "ioc_delete", "ioc", id, in.ID, "IOC entfernt")
	s.jlog(r, in.ID, "observation", fmt.Sprintf("IOC #%d entfernt", id), true)
	back(w, r, in.ID, "iocs", "")
}

func (s *Server) handleIOCExport(w http.ResponseWriter, r *http.Request) {
	in := s.loadIncident(w, r, model.IRoleObserver)
	if in == nil {
		return
	}
	list, _ := s.store.IOCs(r.Context(), in.ID)
	typ := r.URL.Query().Get("type")
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="%s-iocs.txt"`, in.Number))
	fmt.Fprintf(w, "# %s – %s – IOCs – TLP:%s – %s\n", in.Number, in.Title, in.TLP, time.Now().Format("2006-01-02 15:04"))
	for _, o := range list {
		if typ == "" || o.Type == typ {
			if typ == "" {
				fmt.Fprintf(w, "%s\t%s\t%s\n", o.Type, o.Value, o.Description)
			} else {
				fmt.Fprintln(w, o.Value)
			}
		}
	}
	s.audit(r, "ioc_export", "incident", in.ID, in.ID, "IOC-Export "+typ)
}

// ---------- Meldepflichten ----------

func (s *Server) handleObligationActivate(w http.ResponseWriter, r *http.Request) {
	in := s.loadIncident(w, r, model.IRoleLead)
	if in == nil {
		return
	}
	s.activateRegulation(r, in, r.FormValue("regulation"))
	back(w, r, in.ID, "meldepflichten", "")
}

func (s *Server) handleObligationUpdate(w http.ResponseWriter, r *http.Request) {
	in := s.loadIncident(w, r, model.IRoleLead)
	if in == nil {
		return
	}
	o, err := s.store.GetObligation(r.Context(), pathID(r, "oid"))
	if err != nil || o.IncidentID != in.ID {
		s.fail(w, r, 404, "Frist nicht gefunden")
		return
	}
	st := oneOf(r.FormValue("status"), []model.Labeled{{Key: "offen"}, {Key: "erledigt"}, {Key: "nicht_erforderlich"}}, o.Status)
	note := clip(r.FormValue("note"), 10000)
	if st == "nicht_erforderlich" && note == "" {
		back(w, r, in.ID, "meldepflichten", "needreason")
		return
	}
	o.Status, o.Reference, o.Note = st, clip(r.FormValue("reference"), 300), note
	if st == "offen" {
		o.DoneAt, o.DoneBy = time.Time{}, ""
	} else {
		o.DoneAt, o.DoneBy = time.Now(), sessionFrom(r).Username
		if at := parseDT(r.FormValue("done_at")); !at.IsZero() {
			o.DoneAt = at
		}
	}
	if err := s.store.UpdateObligation(r.Context(), o); err != nil {
		s.fail(w, r, 500, err.Error())
		return
	}
	txt := fmt.Sprintf("%s: %s", o.Label, map[string]string{"offen": "wieder offen", "erledigt": "erledigt", "nicht_erforderlich": "NICHT erforderlich"}[st])
	if st == "erledigt" {
		late := ""
		if o.DoneAt.After(o.DueAt) {
			late = " – nach Fristablauf!"
		}
		txt += fmt.Sprintf(" am %s%s", fmtDT(o.DoneAt), late)
	}
	if o.Reference != "" {
		txt += " · Az./Referenz: " + o.Reference
	}
	if o.Note != "" {
		txt += "\nBegründung/Notiz: " + o.Note
	}
	s.audit(r, "obligation_update", "obligation", o.ID, in.ID, txt)
	s.jlog(r, in.ID, "deadline", txt, false)
	back(w, r, in.ID, "meldepflichten", "")
}

// ---------- Stab ----------

func (s *Server) handleMemberAdd(w http.ResponseWriter, r *http.Request) {
	in := s.loadIncident(w, r, model.IRoleLead)
	if in == nil {
		return
	}
	user := strings.TrimSpace(r.FormValue("username"))
	if user == "" {
		back(w, r, in.ID, "stab", "invalid")
		return
	}
	names, _ := s.names(r)
	d := names[strings.ToLower(user)]
	if d == "" {
		d = user
	}
	m := model.Member{IncidentID: in.ID, Username: user, Display: d, Function: optOneOf(r.FormValue("function"), s.cfg.Incident.Functions, "member"),
		Role: oneOf(r.FormValue("role"), model.IncidentRoles, model.IRoleMember), AddedBy: sessionFrom(r).Username}
	if err := s.store.UpsertMember(r.Context(), m); err != nil {
		s.fail(w, r, 500, err.Error())
		return
	}
	txt := fmt.Sprintf("Stab: %s als %s (%s)", d, s.cfg.Incident.Function(m.Function).Label, labelOf(model.IncidentRoles, m.Role))
	s.audit(r, "member_upsert", "member", 0, in.ID, user+": "+txt)
	s.jlog(r, in.ID, "member", txt, true)
	back(w, r, in.ID, "stab", "")
}

func (s *Server) handleMemberRemove(w http.ResponseWriter, r *http.Request) {
	in := s.loadIncident(w, r, model.IRoleLead)
	if in == nil {
		return
	}
	user := r.FormValue("username")
	if strings.EqualFold(user, in.Lead) {
		back(w, r, in.ID, "stab", "leadremove")
		return
	}
	if err := s.store.RemoveMember(r.Context(), in.ID, user); err != nil {
		s.fail(w, r, 500, err.Error())
		return
	}
	s.audit(r, "member_remove", "member", 0, in.ID, user)
	s.jlog(r, in.ID, "member", "Stab: "+user+" entfernt", true)
	back(w, r, in.ID, "stab", "")
}

// ---------- Lagemeldung ----------

func (s *Server) handleSitrep(w http.ResponseWriter, r *http.Request) {
	in := s.loadIncident(w, r, model.IRoleMember)
	if in == nil {
		return
	}
	sr := &model.Sitrep{IncidentID: in.ID, By: sessionFrom(r).Username, Situation: clip(r.FormValue("situation"), 20000),
		Impact: clip(r.FormValue("impact"), 20000), Actions: clip(r.FormValue("actions"), 20000), Outlook: clip(r.FormValue("outlook"), 20000),
		Decisions: clip(r.FormValue("decisions"), 20000), Next: parseDT(r.FormValue("next")), Phase: in.Phase, Severity: in.Severity}
	if sr.Situation == "" {
		back(w, r, in.ID, "lage", "invalid")
		return
	}
	if err := s.store.AddSitrep(r.Context(), sr); err != nil {
		s.fail(w, r, 500, err.Error())
		return
	}
	if !sr.Next.IsZero() && in.MyRole == model.IRoleLead {
		in.NextBriefing = sr.Next
		_ = s.store.UpdateIncident(r.Context(), in)
	}
	s.audit(r, "sitrep_create", "sitrep", sr.ID, in.ID, fmt.Sprintf("Lagemeldung Nr. %d", sr.No))
	s.jlog(r, in.ID, "sitrep", fmt.Sprintf("Lagemeldung Nr. %d: %s", sr.No, firstLine(sr.Situation)), false)
	back(w, r, in.ID, "lage", "sitrep")
}

// ---------- Leak-Fall eskalieren ----------

func (s *Server) handleLeakEscalate(w http.ResponseWriter, r *http.Request) {
	c := s.loadCase(w, r)
	if c == nil {
		return
	}
	if ex, err := s.store.IncidentByLeakCase(r.Context(), c.ID); err == nil {
		http.Redirect(w, r, fmt.Sprintf("/incidents/%d", ex.ID), http.StatusSeeOther)
		return
	}
	se := sessionFrom(r)
	user := c.Username()
	sev := "P3"
	switch c.Risk {
	case model.RiskCritical:
		sev = "P1"
	case model.RiskHigh:
		sev = "P2"
	}
	in := &model.Incident{Title: "Kompromittierte Zugangsdaten: " + user, Category: "credential_leak", Severity: sev, Phase: model.PhaseTriage,
		TLP: "AMBER", Source: "SOC / Leak-Prüfung " + c.CaseNumber, ReportedBy: c.CreatedBy, Lead: se.Username, AwarenessAt: c.CreatedAt,
		DetectedAt: c.CreatedAt, LeakCaseID: c.ID, CreatedBy: se.Username, ImpactC: true,
		Description: "Eskaliert aus Leak-Fall " + c.CaseNumber + ".\n\n" + escalationSummary(c)}
	if c.Checks.User != nil && (len(c.Checks.User.Privileged) > 0 || c.Checks.User.AdminCount) {
		in.ImpactI = true
	}
	if err := s.createIncident(r, in, formBool(r, "playbook"), nil); err != nil {
		s.fail(w, r, 500, err.Error())
		return
	}
	if c.Checks.User != nil {
		u := c.Checks.User
		_ = s.store.CreateAsset(r.Context(), &model.Asset{IncidentID: in.ID, Name: u.SAM, Kind: "account", Identifier: u.UPN, Owner: u.DisplayName,
			Status: map[bool]string{true: "kompromittiert", false: "in_untersuchung"}[c.Checks.BindValid], CreatedBy: se.Username,
			Notes: "Aus Leak-Fall " + c.CaseNumber})
	}
	_ = s.store.AddEvent(r.Context(), c.ID, se.Username, "escalated", "Zu Sicherheitsvorfall "+in.Number+" eskaliert", "")
	s.publish(r, 0, "leak", "")
	http.Redirect(w, r, fmt.Sprintf("/incidents/%d?msg=inc_created", in.ID), http.StatusSeeOther)
}

func escalationSummary(c *model.Case) string {
	var b strings.Builder
	for _, r := range c.Checks.Reasons {
		b.WriteString("- " + r + "\n")
	}
	if u := c.Checks.User; u != nil {
		fmt.Fprintf(&b, "\nKonto: %s (%s), aktiv: %s, Kennwort gesetzt: %s", u.SAM, u.DisplayName, yn(u.Enabled), fmtDT(u.PwdLastSet))
	}
	return b.String()
}

// ---------- Audit (global) ----------

type auditData struct {
	Entries []model.AuditEntry
	Total   int
	Page    int
	Pages   int
	Filter  store.AuditFilter
	Query   template.URL
}

func (s *Server) handleAudit(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	f := store.AuditFilter{Actor: q.Get("actor"), Query: q.Get("q"), Limit: 200}
	f.IncidentID, _ = strconv.ParseInt(q.Get("incident"), 10, 64)
	pg, _ := strconv.Atoi(q.Get("page"))
	if pg < 1 {
		pg = 1
	}
	f.Offset = (pg - 1) * f.Limit
	list, total, err := s.store.AuditLog(r.Context(), f)
	if err != nil {
		s.fail(w, r, 500, err.Error())
		return
	}
	qs := url.Values{"actor": {f.Actor}, "q": {f.Query}}
	if f.IncidentID > 0 {
		qs.Set("incident", strconv.FormatInt(f.IncidentID, 10))
	}
	s.render(w, r, "audit", page{Title: "Audit-Log", Nav: "audit", Data: auditData{Entries: list, Total: total, Page: pg,
		Pages: (total + f.Limit - 1) / f.Limit, Filter: f, Query: template.URL(qs.Encode())}})
}

func or(a, b string) string {
	if a == "" {
		return b
	}
	return a
}

// ---------- Storno & endgültiges Löschen ----------

// handleIncidentCancel storniert einen Vorfall (Fehlanlage/Test). Er verschwindet aus allen Übersichten,
// bleibt aber vollständig erhalten und kann wiederhergestellt werden.
func (s *Server) handleIncidentCancel(w http.ResponseWriter, r *http.Request) {
	in := s.loadIncident(w, r, model.IRoleLead)
	if in == nil {
		return
	}
	reason := clip(r.FormValue("reason"), 2000)
	if len([]rune(reason)) < 3 {
		back(w, r, in.ID, "", "cancel_reason")
		return
	}
	se := sessionFrom(r)
	in.Cancelled, in.CancelReason, in.CancelledAt, in.CancelledBy, in.CrisisMode = true, reason, time.Now(), se.Username, false
	if err := s.store.UpdateIncident(r.Context(), in); err != nil {
		s.fail(w, r, 500, err.Error())
		return
	}
	// Offene Meldefristen beenden, damit keine Warnungen mehr entstehen.
	obl, _ := s.store.Obligations(r.Context(), in.ID)
	for i := range obl {
		if obl[i].Open() {
			obl[i].Status, obl[i].Note, obl[i].DoneAt, obl[i].DoneBy = "nicht_erforderlich", "Vorfall storniert: "+reason, time.Now(), se.Username
			_ = s.store.UpdateObligation(r.Context(), &obl[i])
		}
	}
	s.audit(r, "incident_cancel", "incident", in.ID, in.ID, in.Number+": "+reason)
	s.jlog(r, in.ID, "decision", "Vorfall STORNIERT (Fehlanlage/Test).\nBegründung: "+reason, false)
	s.publish(r, 0, "status", "")
	back(w, r, in.ID, "", "cancelled")
}

func (s *Server) handleIncidentRestore(w http.ResponseWriter, r *http.Request) {
	in := s.loadIncident(w, r, model.IRoleLead)
	if in == nil {
		return
	}
	if !in.Cancelled {
		back(w, r, in.ID, "", "")
		return
	}
	in.Cancelled, in.CancelReason, in.CancelledAt, in.CancelledBy = false, "", time.Time{}, ""
	if err := s.store.UpdateIncident(r.Context(), in); err != nil {
		s.fail(w, r, 500, err.Error())
		return
	}
	s.audit(r, "incident_restore", "incident", in.ID, in.ID, in.Number)
	s.jlog(r, in.ID, "decision", "Storno aufgehoben – Vorfall wieder aktiv. Beim Storno beendete Meldepflichten bitte prüfen und ggf. wieder öffnen.", false)
	s.publish(r, 0, "status", "")
	back(w, r, in.ID, "meldepflichten", "restored")
}

// handlePurge löscht einen stornierten Vorfall endgültig (nur Administratoren, Bestätigung per Vorfallnummer).
// Im globalen Audit-Log bleibt ein Eintrag mit Nummer, Titel, Storno-Begründung und Löschendem.
func (s *Server) handleIncidentPurge(w http.ResponseWriter, r *http.Request) {
	in := s.loadIncident(w, r, model.IRoleLead)
	if in == nil {
		return
	}
	if !hasRole(sessionFrom(r), config.RoleAdmin) {
		s.fail(w, r, http.StatusForbidden, "Endgültiges Löschen ist Administratoren vorbehalten.")
		return
	}
	if !in.Cancelled {
		back(w, r, in.ID, "", "purge_notcancelled")
		return
	}
	if strings.TrimSpace(r.FormValue("confirm")) != in.Number {
		back(w, r, in.ID, "", "purge_confirm")
		return
	}
	detail := fmt.Sprintf("%s „%s“ endgültig gelöscht (Kategorie %s, angelegt %s von %s; storniert %s von %s: %s)",
		in.Number, in.Title, in.Category, fmtDT(in.CreatedAt), in.CreatedBy, fmtDT(in.CancelledAt), in.CancelledBy, in.CancelReason)
	if err := s.store.PurgeIncident(r.Context(), in.ID); err != nil {
		s.fail(w, r, 500, "Löschen fehlgeschlagen: "+err.Error())
		return
	}
	s.audit(r, "incident_purge", "incident", in.ID, in.ID, detail)
	if in.LeakCaseID > 0 {
		_ = s.store.AddEvent(r.Context(), in.LeakCaseID, sessionFrom(r).Username, "note", "Verknüpfter Vorfall "+in.Number+" wurde gelöscht (Fehlanlage/Test).", "")
	}
	s.publish(r, 0, "status", "")
	http.Redirect(w, r, "/incidents?state=storniert&msg=purged", http.StatusSeeOther)
}
