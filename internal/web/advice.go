package web

import (
	"fmt"
	"net/http"
	"strings"
	"time"

	"leakguard/internal/advisor"
	"leakguard/internal/model"
)

// advise berechnet die Empfehlungen für einen Vorfall aus dem vollständigen Zustand.
func (s *Server) advise(r *http.Request, in *model.Incident) advisor.Result {
	ctx := r.Context()
	members, _ := s.store.Members(ctx, in.ID)
	tasks, _ := s.store.Tasks(ctx, in.ID)
	comms, _ := s.store.Comms(ctx, in.ID)
	assets, _ := s.store.Assets(ctx, in.ID)
	iocs, _ := s.store.IOCs(ctx, in.ID)
	obl, _ := s.store.Obligations(ctx, in.ID)
	sitreps, _ := s.store.Sitreps(ctx, in.ID)
	journal, _ := s.store.Journal(ctx, in.ID, "", true)
	return advisor.Advise(advisor.Input{In: in, Members: members, Tasks: tasks, Comms: comms, Assets: assets, IOCs: iocs,
		Obligations: obl, Sitreps: sitreps, Journal: journal, Dismissed: s.store.DismissedRecs(ctx, in.ID), Cfg: &s.cfg.Incident})
}

// handleRec übernimmt oder verwirft eine Empfehlung. Die Empfehlung wird serverseitig neu berechnet,
// damit nur tatsächlich gültige Aktionen ausgeführt werden.
func (s *Server) handleRec(w http.ResponseWriter, r *http.Request) {
	in := s.loadIncident(w, r, model.IRoleMember)
	if in == nil {
		return
	}
	ret := r.FormValue("return")
	key := r.FormValue("key")
	var rec *advisor.Rec
	res := s.advise(r, in)
	for i := range res.Recs {
		if res.Recs[i].Key == key {
			rec = &res.Recs[i]
			break
		}
	}
	if rec == nil {
		back(w, r, in.ID, ret, "rec_gone")
		return
	}
	se := sessionFrom(r)
	isLead := in.MyRole == model.IRoleLead

	if r.FormValue("op") == "dismiss" {
		reason := clip(r.FormValue("reason"), 2000)
		if rec.Sticky || len([]rune(reason)) < 3 {
			back(w, r, in.ID, ret, "rec_reason")
			return
		}
		if err := s.store.DismissRec(r.Context(), in.ID, rec.Key, se.Username, reason); err != nil {
			s.fail(w, r, 500, err.Error())
			return
		}
		s.audit(r, "rec_dismiss", "recommendation", 0, in.ID, rec.Key+": "+reason)
		s.jlog(r, in.ID, "decision", fmt.Sprintf("Empfehlung nicht umgesetzt: %s\nBegründung: %s", rec.Title, reason), false)
		back(w, r, in.ID, ret, "rec_dismissed")
		return
	}

	a := rec.Action
	if a.NeedsLead && !isLead {
		s.fail(w, r, http.StatusForbidden, "Diese Empfehlung kann nur die Leitung des Vorfalls umsetzen.")
		return
	}
	switch a.Kind {
	case "task":
		t := &model.Task{IncidentID: in.ID, Title: a.Title, Details: strings.TrimSpace(a.Details + "\n" + rec.Why + " (" + rec.Ref + ")"),
			Function: a.Function, Priority: oneOf(a.Priority, model.Priorities, "mittel"), CreatedBy: se.Username}
		if a.DueHours > 0 {
			t.DueAt = time.Now().Add(time.Duration(a.DueHours) * time.Hour)
		}
		if err := s.store.CreateTask(r.Context(), t); err != nil {
			s.fail(w, r, 500, err.Error())
			return
		}
		s.audit(r, "rec_apply", "task", t.ID, in.ID, rec.Key)
		s.jlog(r, in.ID, "task", fmt.Sprintf("Aufgabe #%d aus Empfehlung angelegt: %s", t.ID, t.Title), true)
	case "playbook":
		n := 0
		for _, pt := range s.cfg.Incident.Playbook(in.Category) {
			t := &model.Task{IncidentID: in.ID, Title: pt.Title, Details: pt.Details, Function: pt.Function,
				Priority: oneOf(pt.Priority, model.Priorities, "mittel"), CreatedBy: se.Username}
			if pt.DueHours > 0 {
				t.DueAt = time.Now().Add(time.Duration(pt.DueHours) * time.Hour)
			}
			if s.store.CreateTask(r.Context(), t) == nil {
				n++
			}
		}
		s.audit(r, "rec_apply", "incident", in.ID, in.ID, rec.Key)
		s.jlog(r, in.ID, "task", fmt.Sprintf("%d Aufgaben aus dem Playbook übernommen", n), true)
	case "regulation":
		s.activateRegulation(r, in, a.Regulation)
	case "phase":
		if err := s.setPhase(r, in, a.Phase, "Empfehlung: "+rec.Why); err != nil {
			s.fail(w, r, 500, err.Error())
			return
		}
	case "crisis":
		in.CrisisMode = true
		if in.NextBriefing.IsZero() {
			in.NextBriefing = time.Now().Add(2 * time.Hour).Truncate(15 * time.Minute)
		}
		if err := s.store.UpdateIncident(r.Context(), in); err != nil {
			s.fail(w, r, 500, err.Error())
			return
		}
		s.audit(r, "incident_crisis", "incident", in.ID, in.ID, "Lage aktiviert (Empfehlung)")
		s.jlog(r, in.ID, "decision", "Lage/Stab ausgerufen. Erste Lagebesprechung: "+fmtDT(in.NextBriefing), false)
	default:
		back(w, r, in.ID, a.Tab, "")
		return
	}
	back(w, r, in.ID, ret, "rec_applied")
}
