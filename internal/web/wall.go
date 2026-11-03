package web

import (
	"net/http"
	"sort"

	"leakguard/internal/model"
)

// handleWall – globale Lagewand: Vollbild ohne Scrollen, alle aktiven Vorfälle plus Querschnittslisten.
func (s *Server) handleWall(w http.ResponseWriter, r *http.Request) {
	d, err := s.lageData(r)
	if err != nil {
		s.fail(w, r, 500, err.Error())
		return
	}
	s.render(w, r, "wall", page{Layout: "walllayout", Title: "Lagewand", Nav: "lage", Data: d})
}

type assetStat struct {
	Status string
	N      int
}

type incWall struct {
	*incView
	Sitrep    *model.Sitrep
	OpenTasks []model.Task
	DoneTasks int
	Comms     []model.Communication // offene Anfragen/Freigaben zuerst, dann jüngste
	OpenComms int
	Assets    []model.Asset // nach Dringlichkeit des Status sortiert
	AssetStat []assetStat
	OpenObl   []model.Obligation
	DoneObl   []model.Obligation
	Feed      []model.JournalEntry
}

// Reihenfolge der Systemstatus nach Handlungsbedarf.
var assetOrder = map[string]int{"kompromittiert": 0, "verdacht": 1, "in_untersuchung": 2, "isoliert": 3,
	"bereinigt": 4, "wiederhergestellt": 5, "nicht_betroffen": 6}

var taskOrder = map[string]int{"blockiert": 0, "in_arbeit": 1, "offen": 2}
var prioOrder = map[string]int{"hoch": 0, "mittel": 1, "niedrig": 2}

// handleIncidentWall – Lagewand eines einzelnen Vorfalls.
func (s *Server) handleIncidentWall(w http.ResponseWriter, r *http.Request) {
	in := s.loadIncident(w, r, model.IRoleObserver)
	if in == nil {
		return
	}
	v := s.incidentView(r, in)
	d := &incWall{incView: v}
	if len(v.Sitreps) > 0 {
		d.Sitrep = &v.Sitreps[0]
	}

	for _, t := range v.Tasks {
		if t.Open() {
			d.OpenTasks = append(d.OpenTasks, t)
		} else if t.Status == "erledigt" {
			d.DoneTasks++
		}
	}
	sort.SliceStable(d.OpenTasks, func(i, j int) bool {
		a, b := &d.OpenTasks[i], &d.OpenTasks[j]
		if a.Overdue() != b.Overdue() {
			return a.Overdue()
		}
		if taskOrder[a.Status] != taskOrder[b.Status] {
			return taskOrder[a.Status] < taskOrder[b.Status]
		}
		if prioOrder[a.Priority] != prioOrder[b.Priority] {
			return prioOrder[a.Priority] < prioOrder[b.Priority]
		}
		if a.DueAt.IsZero() != b.DueAt.IsZero() {
			return !a.DueAt.IsZero()
		}
		return a.DueAt.Before(b.DueAt)
	})

	var open, rest []model.Communication
	for _, c := range v.Comms {
		if c.OpenRequest() || c.PendingApproval() {
			open = append(open, c)
		} else {
			rest = append(rest, c)
		}
	}
	sort.SliceStable(open, func(i, j int) bool {
		if open[i].PendingApproval() != open[j].PendingApproval() {
			return open[i].PendingApproval()
		}
		return open[i].ReplyOverdue() && !open[j].ReplyOverdue()
	})
	sort.SliceStable(rest, func(i, j int) bool { return rest[i].OccurredAt.After(rest[j].OccurredAt) })
	if len(rest) > 15 {
		rest = rest[:15]
	}
	d.OpenComms = len(open)
	d.Comms = append(open, rest...)

	d.Assets = append(d.Assets, v.Assets...)
	sort.SliceStable(d.Assets, func(i, j int) bool { return assetOrder[d.Assets[i].Status] < assetOrder[d.Assets[j].Status] })
	cnt := map[string]int{}
	for _, a := range v.Assets {
		cnt[a.Status]++
	}
	for _, st := range model.AssetStatuses {
		if cnt[st.Key] > 0 {
			d.AssetStat = append(d.AssetStat, assetStat{st.Key, cnt[st.Key]})
		}
	}

	for _, o := range v.Obligations {
		if o.Open() {
			d.OpenObl = append(d.OpenObl, o)
		} else {
			d.DoneObl = append(d.DoneObl, o)
		}
	}

	sort.SliceStable(d.OpenObl, func(i, j int) bool { return d.OpenObl[i].DueAt.Before(d.OpenObl[j].DueAt) })

	d.Feed = v.Journal
	if len(d.Feed) > 60 {
		d.Feed = d.Feed[:60]
	}
	s.render(w, r, "incident_wall", page{Layout: "walllayout", Title: "Lagewand " + in.Number, Nav: "incidents", Data: d})
}
