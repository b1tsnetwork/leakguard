package workflow

import (
	"strings"
	"time"

	"leakguard/internal/model"
)

// Zustände eines Schritts im laufenden Vorfall.
const (
	StDone     = "erledigt"  // Aufgabe erledigt
	StDropped  = "verworfen" // Aufgabe bewusst verworfen (mit Begründung)
	StOpen     = "offen"     // Aufgabe angelegt, bearbeitbar
	StActive   = "in_arbeit" // in Arbeit
	StBlocked  = "blockiert" // von Bearbeitenden als blockiert markiert
	StLocked   = "gesperrt"  // wartet auf Vorgänger
	StReady    = "bereit"    // Phase erreicht, aber (noch) nicht angelegt (manuell oder nachträglich)
	StLater    = "spaeter"   // Phase noch nicht erreicht
	StNotApply = "entfaellt" // Bedingung trifft nicht zu
)

var StateLabels = map[string]string{StDone: "Erledigt", StDropped: "Verworfen", StOpen: "Offen", StActive: "In Arbeit", StBlocked: "Blockiert",
	StLocked: "Wartet auf Vorgänger", StReady: "Bereit – noch nicht angelegt", StLater: "Spätere Phase", StNotApply: "Entfällt"}

// StepState ist der Zustand eines Schritts in einem Vorfall.
type StepState struct {
	Step       *Step
	Applicable bool
	Reached    bool // Phase erreicht
	State      string
	Task       *model.Task
	WaitingFor []*Step // offene Vorgänger
	Condition  string  // lesbare Bedingung
}

func (s *StepState) Finished() bool {
	return s.State == StDone || s.State == StDropped || s.State == StNotApply
}

// StaffState ist der Soll-Ist-Abgleich einer Stabsanforderung.
type StaffState struct {
	Req        *StaffReq
	Position   Position
	Applicable bool
	Active     bool // Phase erreicht
	Filled     []model.Member
	Suggest    []string // vordefinierte Besetzung, die noch nicht im Stab ist
	Condition  string
}

func (s *StaffState) Missing() bool { return s.Applicable && s.Active && len(s.Filled) == 0 }

// Gate fasst zusammen, was vor dem Verlassen einer Phase erledigt sein muss.
type Gate struct {
	Steps []*StepState  // offene Pflichtschritte
	Staff []*StaffState // unbesetzte Pflicht-Stabsstellen
}

func (g Gate) Open() bool { return len(g.Steps) > 0 || len(g.Staff) > 0 }

// Plan ist die Auswertung eines Workflows für einen Vorfall.
type Plan struct {
	Def    *Def
	Phase  string
	Steps  []*StepState
	ByID   map[string]*StepState
	ByTask map[int64]*StepState
	Staff  []*StaffState
}

// Compute wertet den Workflow für den aktuellen Zustand aus.
func Compute(d *Def, f Facts, phase string, tasks []model.Task, members []model.Member, positions map[string]Position, lab Labels) *Plan {
	p := &Plan{Def: d, Phase: phase, ByID: map[string]*StepState{}, ByTask: map[int64]*StepState{}}
	cur := PhaseIdx(phase)
	if phase == model.PhaseClosed {
		cur = len(model.Phases) // alles erreicht
	}
	taskOf := map[string]*model.Task{}
	for i := range tasks {
		if tasks[i].WFStep != "" {
			taskOf[tasks[i].WFStep] = &tasks[i]
		}
	}
	for i := range d.Steps {
		s := &d.Steps[i]
		st := &StepState{Step: s, Applicable: s.When.Match(f), Reached: PhaseIdx(s.Phase) <= cur, Task: taskOf[s.ID], Condition: s.When.Describe(lab)}
		p.Steps = append(p.Steps, st)
		p.ByID[s.ID] = st
		if st.Task != nil {
			p.ByTask[st.Task.ID] = st
		}
	}
	// Zustände – Vorgänger zuerst auswerten ist nicht nötig: „erfüllt“ hängt nur am eigenen Status.
	for _, st := range p.Steps {
		switch {
		case st.Task != nil:
			st.State = st.Task.Status
		case !st.Applicable:
			st.State = StNotApply
		case !st.Reached:
			st.State = StLater
		default:
			st.State = StReady
		}
	}
	for _, st := range p.Steps {
		if st.State == StDone || st.State == StDropped || st.State == StNotApply {
			continue
		}
		for _, dep := range st.Step.DependsOn {
			ds := p.ByID[dep]
			if ds == nil || ds.Finished() {
				continue
			}
			st.WaitingFor = append(st.WaitingFor, ds.Step)
		}
		if len(st.WaitingFor) > 0 && (st.State == StOpen || st.State == StReady) {
			st.State = StLocked
		}
	}
	for i := range d.Staff {
		r := &d.Staff[i]
		ss := &StaffState{Req: r, Position: positions[r.Position], Applicable: r.When.Match(f), Active: PhaseIdx(r.Phase) <= cur, Condition: r.When.Describe(lab)}
		if ss.Position.Key == "" {
			ss.Position = Position{Key: r.Position, Label: r.Position}
		}
		inStaff := map[string]bool{}
		for _, m := range members {
			inStaff[strings.ToLower(m.Username)] = true
			if m.Function == r.Position {
				ss.Filled = append(ss.Filled, m)
			}
		}
		for _, h := range ss.Position.Holders {
			if !inStaff[strings.ToLower(h)] {
				ss.Suggest = append(ss.Suggest, h)
			}
		}
		p.Staff = append(p.Staff, ss)
	}
	return p
}

// Locked meldet, ob die Aufgabe noch auf Vorgänger wartet.
func (p *Plan) Locked(taskID int64) (*StepState, bool) {
	st := p.ByTask[taskID]
	return st, st != nil && len(st.WaitingFor) > 0
}

// ToCreate liefert die Schritte, für die jetzt automatisch eine Aufgabe angelegt werden soll.
func (p *Plan) ToCreate() []*StepState {
	var out []*StepState
	for _, st := range p.Steps {
		if st.Task == nil && st.Applicable && st.Reached && !st.Step.Manual {
			out = append(out, st)
		}
	}
	return out
}

// Recommend liefert anwendbare, erreichte Schritte ohne Aufgabe (manuelle Schritte).
func (p *Plan) Recommend() []*StepState {
	var out []*StepState
	for _, st := range p.Steps {
		if st.Task == nil && st.Applicable && st.Reached && st.Step.Manual {
			out = append(out, st)
		}
	}
	return out
}

// GateFor ermittelt, was vor dem Wechsel in die Zielphase noch offen ist:
// Pflichtschritte aller Phasen vor dem Ziel und Pflicht-Stabsstellen, die bis dahin besetzt sein müssen.
func (p *Plan) GateFor(target string) Gate {
	var g Gate
	t := PhaseIdx(target)
	if target == model.PhaseClosed {
		t = len(model.Phases) - 1
	}
	for _, st := range p.Steps {
		if st.Step.Mandatory && st.Applicable && PhaseIdx(st.Step.Phase) < t && !st.Finished() {
			g.Steps = append(g.Steps, st)
		}
	}
	for _, ss := range p.Staff {
		if ss.Req.Need == "pflicht" && ss.Applicable && PhaseIdx(ss.Req.Phase) < t && len(ss.Filled) == 0 {
			g.Staff = append(g.Staff, ss)
		}
	}
	return g
}

// PhaseProgress zählt anwendbare Schritte je Phase.
type PhaseProgress struct {
	Phase      model.Labeled
	Total      int
	Done       int
	Mandatory  int
	MandDone   int
	Current    bool
	Reached    bool
	Steps      []*StepState
	StaffAdded []*StaffState // Stabsanforderungen, die in dieser Phase beginnen
}

func (p *Plan) Progress() []PhaseProgress {
	cur := PhaseIdx(p.Phase)
	var out []PhaseProgress
	for i, ph := range WorkPhases() {
		pp := PhaseProgress{Phase: ph, Current: i == cur, Reached: i <= cur || p.Phase == model.PhaseClosed}
		for _, st := range p.Steps {
			if st.Step.Phase != ph.Key {
				continue
			}
			pp.Steps = append(pp.Steps, st)
			if !st.Applicable {
				continue
			}
			pp.Total++
			if st.Finished() {
				pp.Done++
			}
			if st.Step.Mandatory {
				pp.Mandatory++
				if st.Finished() {
					pp.MandDone++
				}
			}
		}
		for _, ss := range p.Staff {
			if ss.Req.Phase == ph.Key {
				pp.StaffAdded = append(pp.StaffAdded, ss)
			}
		}
		out = append(out, pp)
	}
	return out
}

// DueAt berechnet die Frist einer neu anzulegenden Aufgabe.
func (s *Step) DueAt(awareness, now time.Time) time.Time {
	if s.DueHours <= 0 {
		return time.Time{}
	}
	base := awareness
	if s.DueFrom == "anlage" || base.IsZero() {
		base = now
	}
	due := base.Add(time.Duration(s.DueHours) * time.Hour)
	// Eine Frist ab Kenntnisnahme, die bei (später) Anlage schon verstrichen ist, bleibt bewusst sichtbar überfällig.
	return due
}

// Select wählt den passendsten veröffentlichten Workflow.
func Select(versions []*Version, f Facts) *Version {
	var best *Version
	bestScore := -1
	for _, v := range versions {
		if sc, ok := v.Def.MatchScore(f); ok && sc > bestScore {
			best, bestScore = v, sc
		}
	}
	return best
}
