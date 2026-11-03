package web

import (
	"net/http"
	"sort"
	"strconv"
	"time"

	"leakguard/internal/advisor"
	"leakguard/internal/config"
	"leakguard/internal/model"
	"leakguard/internal/store"
)

type lageCard struct {
	In      *model.Incident
	Counts  store.IncidentCounts
	Next    *model.Obligation
	Last    model.JournalEntry
	HasLast bool
	Sitrep  *model.Sitrep
	Top     *advisor.Rec
	Recs    int
}

type lageData struct {
	Cards      []lageCard
	BySeverity map[string]int
	Active     int
	Crisis     int
	OpenTasks  int
	Overdue    int
	Requests   []model.Communication
	Deadlines  []model.Obligation
	MyTasks    []model.Task
	Ticker     []model.JournalEntry
	LeakOpen   int
	LeakTodo   int
	Names      map[string]string
	Now        time.Time
	CanCreate  bool
	Connected  int
	Actions    []advisor.Rec
}

// handleLage – Lagezentrum: alle aktiven Vorfälle, Fristen, Anfragen, Aufgaben und Live-Ticker.
func (s *Server) handleLage(w http.ResponseWriter, r *http.Request) {
	if r.URL.Query().Get("wall") == "1" { // alte Lesezeichen
		http.Redirect(w, r, "/wall", http.StatusSeeOther)
		return
	}
	d, err := s.lageData(r)
	if err != nil {
		s.fail(w, r, 500, err.Error())
		return
	}
	if len(d.Actions) > 12 { // die Lagewand blättert durch alle, das Lagezentrum zeigt die wichtigsten
		d.Actions = d.Actions[:12]
	}
	s.render(w, r, "lage", page{Title: "Lagezentrum", Nav: "lage", Data: d})
}

// lageData sammelt die Gesamtlage für Lagezentrum und globale Lagewand.
func (s *Server) lageData(r *http.Request) (*lageData, error) {
	ctx := r.Context()
	se := sessionFrom(r)
	v := s.viewer(r)
	list, err := s.store.ListIncidents(ctx, v, model.IncidentFilter{State: "aktiv"})
	if err != nil {
		return nil, err
	}
	d := &lageData{BySeverity: map[string]int{}, Now: time.Now(),
		CanCreate: hasRole(se, config.RoleResponder), Connected: s.hub.count()}
	d.Deadlines, _ = s.store.OpenObligations(ctx, v)
	next := map[int64]*model.Obligation{}
	for i := range d.Deadlines {
		o := &d.Deadlines[i]
		if next[o.IncidentID] == nil {
			next[o.IncidentID] = o
		}
	}
	for _, in := range list {
		c := lageCard{In: in, Counts: s.store.Counts(ctx, in.ID), Next: next[in.ID]}
		c.Last, c.HasLast = s.store.LastJournal(ctx, in.ID)
		if srs, _ := s.store.Sitreps(ctx, in.ID); len(srs) > 0 {
			c.Sitrep = &srs[0]
		}
		adv := s.advise(r, in)
		for i := range adv.Recs {
			rc := adv.Recs[i]
			if rc.Priority != advisor.PrioCritical && rc.Priority != advisor.PrioHigh {
				continue
			}
			c.Recs++
			if c.Top == nil {
				c.Top = &adv.Recs[i]
			}
			d.Actions = append(d.Actions, rc)
		}
		d.Cards = append(d.Cards, c)
		d.BySeverity[in.Severity]++
		d.OpenTasks += c.Counts.OpenTasks
		d.Overdue += c.Counts.OverdueTasks
		if in.CrisisMode {
			d.Crisis++
		}
	}
	d.Active = len(list)
	// Lagen zuerst, dann nach Schwere, dann jüngste Aktivität
	sort.SliceStable(d.Cards, func(i, j int) bool {
		a, b := d.Cards[i].In, d.Cards[j].In
		if a.CrisisMode != b.CrisisMode {
			return a.CrisisMode
		}
		if a.Severity != b.Severity {
			return a.Severity < b.Severity
		}
		return a.UpdatedAt.After(b.UpdatedAt)
	})
	sort.SliceStable(d.Actions, func(i, j int) bool {
		pi, pj := d.Actions[i].Priority == advisor.PrioCritical, d.Actions[j].Priority == advisor.PrioCritical
		if pi != pj {
			return pi
		}
		return d.Actions[i].Incident.Severity < d.Actions[j].Incident.Severity
	})
	if len(d.Actions) > 30 {
		d.Actions = d.Actions[:30]
	}
	d.Requests, _ = s.store.PendingComms(ctx, v)
	d.MyTasks, _ = s.store.OpenTasks(ctx, v, se.Username)
	d.Ticker, _ = s.store.RecentJournal(ctx, v, 40)
	if st, err := s.store.Stats(ctx); err == nil {
		d.LeakOpen, d.LeakTodo = st.Open+st.InProgress, st.TodoOpen
	}
	d.Names, _ = s.names(r)
	return d, nil
}

// until formatiert eine Restzeit („in 3 h 10 min“ / „überfällig seit 2 h“).
func until(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	d := time.Until(t)
	neg := d < 0
	if neg {
		d = -d
	}
	var s string
	switch {
	case d < time.Hour:
		s = itoa(int(d.Minutes())) + " min"
	case d < 48*time.Hour:
		s = itoa(int(d.Hours())) + " h " + itoa(int(d.Minutes())%60) + " min"
	default:
		s = itoa(int(d.Hours()/24)) + " Tage " + itoa(int(d.Hours())%24) + " h"
	}
	if neg {
		return "überfällig seit " + s
	}
	return "in " + s
}

func itoa(i int) string { return strconv.Itoa(i) }
