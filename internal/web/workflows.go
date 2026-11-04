package web

import (
	"context"
	"encoding/json"
	"fmt"
	"html/template"
	"io"
	"log/slog"
	"net/http"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"gopkg.in/yaml.v3"

	"leakguard/internal/config"
	"leakguard/internal/model"
	"leakguard/internal/store"
	"leakguard/internal/workflow"
)

// wfState hält die Positionsbibliothek im Speicher; veröffentlichte Versionen sind unveränderlich und werden gecacht.
type wfState struct {
	mu        sync.RWMutex
	positions []workflow.Position
	byKey     map[string]workflow.Position
	versions  sync.Map // int64 → *workflow.Version
}

// loadWF spielt beim ersten Start den Startbestand ein und lädt die Positionen.
func (s *Server) loadWF(ctx context.Context) error {
	have, err := s.store.Positions(ctx)
	if err != nil {
		return err
	}
	known := map[string]bool{}
	for _, p := range have {
		known[p.Key] = true
	}
	// Neue Funktionen aus der Konfiguration ergänzen (bestehende werden nie überschrieben).
	for _, p := range workflow.DefaultPositions(s.cfg.Incident.Functions) {
		if !known[p.Key] {
			if err := s.store.SavePosition(ctx, p, "system"); err != nil {
				return err
			}
		}
	}
	if err := s.installLibrary(ctx); err != nil {
		return err
	}
	return s.reloadPositions(ctx)
}

// library liefert die eingebaute Bibliothek (abhängig von den konfigurierten Kategorien).
func (s *Server) library() []workflow.Template { return workflow.Library(s.cfg.Incident.Categories) }

// installLibrary stellt sicher, dass alle eingebauten Abläufe vorhanden sind. Neue Abläufe späterer Versionen
// werden automatisch ergänzt; bereits installierte (auch geänderte oder archivierte) werden nie überschrieben.
func (s *Server) installLibrary(ctx context.Context) error {
	inst, err := s.store.InstalledTemplates(ctx)
	if err != nil {
		return err
	}
	if len(inst) == 0 && s.store.HasWorkflows(ctx) {
		// Übernahme aus älteren Versionen: Startbestand ohne Herkunftsvermerk
		infos, _ := s.store.Workflows(ctx)
		for _, wi := range infos {
			if t := workflow.TemplateByKey(s.library(), wi.Key); t != nil {
				_ = s.store.MarkTemplate(ctx, t.Key, 1, wi.ID)
				inst[t.Key] = store.InstalledTemplate{Rev: 1, WorkflowID: wi.ID}
			}
		}
	}
	n := 0
	for _, t := range s.library() {
		if _, ok := inst[t.Key]; ok {
			continue
		}
		if _, err := s.store.InstallTemplate(ctx, t.Def, t.Rev, "system"); err != nil {
			return fmt.Errorf("workflow %s: %w", t.Key, err)
		}
		n++
	}
	if n > 0 {
		slog.Info("Workflow-Bibliothek installiert", "neu", n)
	}
	return nil
}

func (s *Server) reloadPositions(ctx context.Context) error {
	list, err := s.store.Positions(ctx)
	if err != nil {
		return err
	}
	m := map[string]workflow.Position{}
	for _, p := range list {
		m[p.Key] = p
	}
	s.wf.mu.Lock()
	s.wf.positions, s.wf.byKey = list, m
	s.wf.mu.Unlock()
	return nil
}

func (s *Server) positions() []workflow.Position {
	s.wf.mu.RLock()
	defer s.wf.mu.RUnlock()
	return append([]workflow.Position(nil), s.wf.positions...)
}

func (s *Server) position(key string) workflow.Position {
	s.wf.mu.RLock()
	defer s.wf.mu.RUnlock()
	if p, ok := s.wf.byKey[key]; ok {
		return p
	}
	if o := s.cfg.Incident.Function(key); o.Key != "" {
		return workflow.Position{Key: o.Key, Label: o.Label}
	}
	return workflow.Position{Key: key, Label: key}
}

func (s *Server) positionMap() map[string]workflow.Position {
	s.wf.mu.RLock()
	defer s.wf.mu.RUnlock()
	m := make(map[string]workflow.Position, len(s.wf.byKey))
	for k, v := range s.wf.byKey {
		m[k] = v
	}
	return m
}

func (s *Server) posKeys() map[string]bool {
	out := map[string]bool{}
	for k := range s.positionMap() {
		out[k] = true
	}
	return out
}

// posOptions liefert die Positionen als Auswahlliste (Ersatz für incident.functions).
func (s *Server) posOptions() []config.Option {
	var out []config.Option
	for _, p := range s.positions() {
		out = append(out, config.Option{Key: p.Key, Label: p.Label, Hint: p.Description})
	}
	return out
}

func (s *Server) wfLabels() workflow.Labels {
	org := map[string]string{"kommune": "Kommune", "land": "Landesbehörde", "bund": "Bundesbehörde", "sonstige": "Sonstige"}
	return func(set, key string) string {
		switch set {
		case "category":
			if l := s.cfg.Incident.Category(key).Label; l != "" {
				return l
			}
		case "regulation":
			if r, ok := s.cfg.Incident.Regulation(key); ok {
				return r.Label
			}
		case "org":
			if l := org[key]; l != "" {
				return l
			}
		case "tlp":
			return "TLP:" + key
		}
		return key
	}
}

// version lädt eine Workflow-Version (veröffentlichte aus dem Cache).
func (s *Server) version(ctx context.Context, id int64) *workflow.Version {
	if id == 0 {
		return nil
	}
	if v, ok := s.wf.versions.Load(id); ok {
		return v.(*workflow.Version)
	}
	v, err := s.store.WorkflowVersion(ctx, id)
	if err != nil {
		return nil
	}
	if v.Status != "entwurf" {
		s.wf.versions.Store(id, v)
	}
	return v
}

func (s *Server) facts(ctx context.Context, in *model.Incident) workflow.Facts {
	assets, _ := s.store.Assets(ctx, in.ID)
	obl, _ := s.store.Obligations(ctx, in.ID)
	return workflow.FactsFor(in, s.cfg.Incident.Org.Type, s.cfg.Incident.Org.NIS2, assets, obl)
}

// plan wertet den Workflow eines Vorfalls aus (nil = ohne Workflow).
func (s *Server) plan(ctx context.Context, in *model.Incident, tasks []model.Task, members []model.Member) (*workflow.Plan, *workflow.Version) {
	v := s.version(ctx, in.WFVersionID)
	if v == nil {
		return nil, nil
	}
	return workflow.Compute(&v.Def, s.facts(ctx, in), in.Phase, tasks, members, s.positionMap(), s.wfLabels()), v
}

func (s *Server) planFor(r *http.Request, in *model.Incident) (*workflow.Plan, *workflow.Version) {
	ctx := r.Context()
	tasks, _ := s.store.Tasks(ctx, in.ID)
	members, _ := s.store.Members(ctx, in.ID)
	return s.plan(ctx, in, tasks, members)
}

// selectWorkflow wählt den passendsten aktiven Workflow für einen neuen Vorfall.
func (s *Server) selectWorkflow(ctx context.Context, in *model.Incident) *workflow.Version {
	vs, err := s.store.ActiveVersions(ctx)
	if err != nil {
		return nil
	}
	f := workflow.FactsFor(in, s.cfg.Incident.Org.Type, s.cfg.Incident.Org.NIS2, nil, nil)
	return workflow.Select(vs, f)
}

// wfSync legt fällige Workflow-Aufgaben an und nimmt vorgesehene Besetzungen auf (falls im Workflow so festgelegt).
// Aufgerufen nach jeder Änderung, die Phase oder Bedingungen beeinflusst.
func (s *Server) wfSync(r *http.Request, in *model.Incident) {
	if in.Cancelled || in.WFVersionID == 0 {
		return
	}
	ctx := r.Context()
	tasks, _ := s.store.Tasks(ctx, in.ID)
	members, _ := s.store.Members(ctx, in.ID)
	p, v := s.plan(ctx, in, tasks, members)
	if p == nil {
		return
	}
	se := sessionFrom(r)
	unlinked := map[string]*model.Task{}
	for i := range tasks {
		if tasks[i].WFStep == "" {
			unlinked[strings.ToLower(strings.TrimSpace(tasks[i].Title))] = &tasks[i]
		}
	}
	var created []string
	now := time.Now()
	for _, st := range p.ToCreate() {
		step := st.Step
		if t := unlinked[strings.ToLower(step.Title)]; t != nil {
			// Bereits manuell (oder aus einem Playbook) angelegt: nur verknüpfen, nicht verdoppeln.
			t.WFStep = step.ID
			_ = s.store.UpdateTask(ctx, t)
			delete(unlinked, strings.ToLower(step.Title))
			continue
		}
		t := &model.Task{IncidentID: in.ID, Title: step.Title, Details: step.Details, Function: step.Position,
			Priority: oneOf(step.Priority, model.Priorities, "mittel"), DueAt: step.DueAt(in.AwarenessAt, now), CreatedBy: se.Username, WFStep: step.ID}
		if s.store.CreateTask(ctx, t) == nil {
			created = append(created, fmt.Sprintf("#%d %s", t.ID, t.Title))
		}
	}
	if len(created) > 0 {
		s.jlog(r, in.ID, "task", fmt.Sprintf("%d Aufgabe(n) aus Workflow „%s“ (v%d) angelegt:\n%s", len(created), v.Def.Name, v.Version,
			strings.Join(created, "\n")), true)
	}
	names, _ := s.names(r)
	for _, ss := range p.Staff {
		if !ss.Req.AutoAdd || !ss.Missing() || len(ss.Suggest) == 0 {
			continue
		}
		user := ss.Suggest[0]
		role := or(ss.Req.Role, or(ss.Position.Role, model.IRoleMember))
		d := names[strings.ToLower(user)]
		if d == "" {
			d = user
		}
		if err := s.store.UpsertMember(ctx, model.Member{IncidentID: in.ID, Username: user, Display: d, Function: ss.Req.Position,
			Role: oneOf(role, model.IncidentRoles, model.IRoleMember), AddedBy: se.Username}); err == nil {
			txt := fmt.Sprintf("Stab: %s als %s automatisch aufgenommen (Workflow „%s“). Begründung: %s", d, ss.Position.Label, v.Def.Name, or(ss.Req.Why, ss.Position.Why))
			s.audit(r, "member_upsert", "member", 0, in.ID, user+": "+txt)
			s.jlog(r, in.ID, "member", txt, true)
		}
	}
}

// phaseGate prüft beim Vorwärtswechsel, ob Pflichtschritte oder Pflicht-Stabsstellen offen sind.
func (s *Server) phaseGate(r *http.Request, in *model.Incident, target string) workflow.Gate {
	if workflow.PhaseIdx(target) <= workflow.PhaseIdx(in.Phase) {
		return workflow.Gate{}
	}
	p, _ := s.planFor(r, in)
	if p == nil {
		return workflow.Gate{}
	}
	return p.GateFor(target)
}

func gateText(g workflow.Gate, s *Server) string {
	var parts []string
	for _, st := range g.Steps {
		parts = append(parts, "„"+st.Step.Title+"“")
	}
	for _, ss := range g.Staff {
		parts = append(parts, "Stabsstelle "+s.position(ss.Req.Position).Label)
	}
	return strings.Join(parts, ", ")
}

// ---------- Ansicht in der Vorfallakte ----------

type wfView struct {
	Version  *workflow.Version
	Plan     *workflow.Plan
	Progress []workflow.PhaseProgress
	Upgrade  *workflow.Version // neuere Version desselben Workflows
	Choices  []*workflow.Version
	Suggest  *workflow.Version // passender Workflow (für Vorfälle ohne Workflow)
	Gate     workflow.Gate
	GateTo   string
	JSON     template.JS
}

func (v *incView) Step(taskID int64) *workflow.StepState {
	if v.WF == nil || v.WF.Plan == nil {
		return nil
	}
	return v.WF.Plan.ByTask[taskID]
}

func (s *Server) incidentWF(r *http.Request, v *incView) *wfView {
	ctx := r.Context()
	w := &wfView{}
	w.Plan, w.Version = s.plan(ctx, v.In, v.Tasks, v.Members)
	actives, _ := s.store.ActiveVersions(ctx)
	w.Choices = actives
	if w.Version == nil {
		w.Suggest = workflow.Select(actives, s.facts(ctx, v.In))
		return w
	}
	for _, a := range actives {
		if a.WorkflowID == w.Version.WorkflowID && a.Version > w.Version.Version {
			w.Upgrade = a
		}
	}
	w.Progress = w.Plan.Progress()
	if t := r.URL.Query().Get("gate"); t != "" && workflow.PhaseIdx(t) > workflow.PhaseIdx(v.In.Phase) {
		w.GateTo, w.Gate = t, w.Plan.GateFor(t)
	}
	if v.Tab == "workflow" {
		w.JSON = s.runJSON(w, v)
	}
	return w
}

// runJSON liefert die Daten für die grafische Ablaufansicht im Vorfall (nur lesend, mit Zuständen).
func (s *Server) runJSON(w *wfView, v *incView) template.JS {
	type stepRun struct {
		State   string   `json:"state"`
		Label   string   `json:"label"`
		Task    int64    `json:"task,omitempty"`
		Waiting []string `json:"waiting,omitempty"`
		Applies bool     `json:"applies"`
		Cond    string   `json:"cond"`
	}
	run := map[string]stepRun{}
	for _, st := range w.Plan.Steps {
		sr := stepRun{State: st.State, Label: workflow.StateLabels[st.State], Applies: st.Applicable, Cond: st.Condition}
		if st.Task != nil {
			sr.Task = st.Task.ID
		}
		for _, wf := range st.WaitingFor {
			sr.Waiting = append(sr.Waiting, wf.Title)
		}
		run[st.Step.ID] = sr
	}
	staff := map[string]any{}
	for _, ss := range w.Plan.Staff {
		var filled []string
		for _, m := range ss.Filled {
			filled = append(filled, m.Display)
		}
		staff[ss.Req.ID] = map[string]any{"applies": ss.Applicable, "active": ss.Active, "filled": filled, "suggest": ss.Suggest, "cond": ss.Condition}
	}
	data := s.designerPayload(&w.Version.Def, true)
	data["mode"] = "run"
	data["run"] = run
	data["staff_run"] = staff
	data["phase"] = v.In.Phase
	data["incident"] = v.In.ID
	raw, _ := json.Marshal(data)
	return template.JS(raw)
}

// ---------- Designer-Daten ----------

func (s *Server) designerPayload(d *workflow.Def, readOnly bool) map[string]any {
	type opt struct {
		Key   string `json:"key"`
		Label string `json:"label"`
		Hint  string `json:"hint,omitempty"`
	}
	conv := func(l []model.Labeled) []opt {
		var out []opt
		for _, x := range l {
			out = append(out, opt{x.Key, x.Label, x.Hint})
		}
		return out
	}
	var cats, regs []opt
	for _, c := range s.cfg.Incident.Categories {
		cats = append(cats, opt{c.Key, c.Label, c.Hint})
	}
	for _, r := range s.cfg.Incident.Regulations {
		regs = append(regs, opt{r.Key, r.Label, r.Authority})
	}
	return map[string]any{
		"def":       d,
		"positions": s.positions(),
		"readonly":  readOnly,
		"labels": map[string]any{
			"phases": conv(workflow.WorkPhases()), "kinds": conv(workflow.StepKinds), "needs": conv(workflow.Needs),
			"severities": conv(model.Severities), "priorities": conv(model.Priorities), "tlp": conv(model.TLPs),
			"category": cats, "regulation": regs, "org": []opt{{"kommune", "Kommune", ""}, {"land", "Landesbehörde", ""}, {"bund", "Bundesbehörde", ""}, {"sonstige", "Sonstige", ""}},
			"groups": conv(workflow.PositionGroups), "fields": workflow.Fields, "ops": workflow.OpLabels, "roles": conv(model.IncidentRoles),
		},
		"issues": d.Validate(s.posKeys()),
	}
}

// ---------- Übersicht ----------

type wfListData struct {
	Library   []workflow.Template
	Workflows []workflow.Info
	Positions []workflow.Position
	CanEdit   bool
}

// PhaseCount zählt die Schritte einer Phase (für die Mini-Übersicht).
func (d wfListData) PhaseCount(v *workflow.Version, phase string) int {
	n := 0
	for _, st := range v.Def.Steps {
		if st.Phase == phase {
			n++
		}
	}
	return n
}

func (s *Server) handleWorkflows(w http.ResponseWriter, r *http.Request) {
	list, err := s.store.Workflows(r.Context())
	if err != nil {
		s.fail(w, r, 500, err.Error())
		return
	}
	s.render(w, r, "workflows", page{Title: "Workflows", Nav: "workflows", Data: wfListData{Library: s.library(), Workflows: list, Positions: s.positions(), CanEdit: hasRole(sessionFrom(r), config.RoleAdmin)}})
}

var slugRe = regexp.MustCompile(`[^a-z0-9]+`)

func slug(s string) string {
	s = strings.ToLower(s)
	for a, b := range map[string]string{"ä": "ae", "ö": "oe", "ü": "ue", "ß": "ss"} {
		s = strings.ReplaceAll(s, a, b)
	}
	return strings.Trim(slugRe.ReplaceAllString(s, "_"), "_")
}

func (s *Server) handleWorkflowNew(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	name := clip(strings.TrimSpace(r.FormValue("name")), 120)
	src := workflow.Def{Color: "#1f5fbf"}
	from := r.FormValue("from")
	switch {
	case strings.HasPrefix(from, "tpl:"):
		if t := workflow.TemplateByKey(s.library(), strings.TrimPrefix(from, "tpl:")); t != nil {
			src = t.Def
		}
	default:
		if id, _ := strconv.ParseInt(from, 10, 64); id > 0 {
			if info, err := s.store.WorkflowInfo(ctx, id); err == nil && info.Current() != nil {
				src = info.Current().Def
			}
		}
	}
	if name == "" {
		name = "Neuer Workflow"
	}
	if cats := r.Form["category"]; len(cats) > 0 {
		src.Match.Categories = cats
	}
	s.createCopy(w, r, src, name, "workflow_create")
}

// createCopy legt aus einer Definition einen neuen Workflow (Entwurf) an und öffnet den Designer.
func (s *Server) createCopy(w http.ResponseWriter, r *http.Request, src workflow.Def, name, action string) {
	ctx := r.Context()
	d := src
	d.Steps = append([]workflow.Step(nil), src.Steps...)
	d.Staff = append([]workflow.StaffReq(nil), src.Staff...)
	d.Name = name
	base := slug(name)
	if base == "" {
		base = "workflow"
	}
	all, _ := s.store.Workflows(ctx)
	used := map[string]bool{}
	for _, wi := range all {
		used[wi.Key] = true
	}
	d.Key = base
	for i := 2; used[d.Key]; i++ {
		d.Key = fmt.Sprintf("%s_%d", base, i)
	}
	d.Normalize()
	id, err := s.store.CreateWorkflow(ctx, d, sessionFrom(r).Username)
	if err != nil {
		s.fail(w, r, 400, err.Error())
		return
	}
	txt := d.Name
	if src.Name != "" {
		txt += " (Kopie von „" + src.Name + "“)"
	}
	s.audit(r, action, "workflow", id, 0, txt)
	http.Redirect(w, r, fmt.Sprintf("/workflows/%d?msg=wf_copied", id), http.StatusSeeOther)
}

// handleWorkflowCopy kopiert einen Workflow (aktueller Stand inkl. Entwurf) als neuen Workflow.
func (s *Server) handleWorkflowCopy(w http.ResponseWriter, r *http.Request) {
	info, err := s.store.WorkflowInfo(r.Context(), pathID(r, "id"))
	if err != nil || info.Current() == nil {
		s.fail(w, r, 404, "Workflow nicht gefunden")
		return
	}
	src := info.Current().Def
	name := clip(strings.TrimSpace(r.FormValue("name")), 120)
	if name == "" {
		name = src.Name + " (Kopie)"
	}
	s.createCopy(w, r, src, name, "workflow_copy")
}

// ---------- Bibliothek ----------

type libEntry struct {
	T         workflow.Template
	Installed *workflow.Info // installierter Workflow (falls vorhanden)
	Outdated  bool           // Bibliothek enthält eine neuere Revision
	Steps     int
	Mandatory int
	Staff     int
}

type libGroup struct {
	Name    string
	Entries []libEntry
}

type libData struct {
	Groups  []libGroup
	CanEdit bool
	Count   int
	Small   int
	Size    string // "" | klein | gross
	Q       string
}

func (s *Server) handleLibrary(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	inst, _ := s.store.InstalledTemplates(ctx)
	infos, _ := s.store.Workflows(ctx)
	byID := map[int64]*workflow.Info{}
	for i := range infos {
		byID[infos[i].ID] = &infos[i]
	}
	groups := map[string][]libEntry{}
	lib := s.library()
	size := r.URL.Query().Get("size")
	q := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("q")))
	small := 0
	for _, t := range lib {
		if t.Small {
			small++
		}
		if (size == "klein" && !t.Small) || (size == "gross" && t.Small) {
			continue
		}
		if q != "" && !strings.Contains(strings.ToLower(t.Name+" "+t.Description), q) {
			continue
		}
		e := libEntry{T: t, Steps: len(t.Def.Steps), Staff: len(t.Def.Staff)}
		for _, st := range t.Def.Steps {
			if st.Mandatory {
				e.Mandatory++
			}
		}
		if it, ok := inst[t.Key]; ok {
			e.Installed = byID[it.WorkflowID]
			if c := e.Installed; c != nil && c.Current() != nil && c.Current().Def.Origin != "" && c.Current().Def.OriginRev < t.Rev {
				e.Outdated = true
			}
		}
		groups[t.Group] = append(groups[t.Group], e)
	}
	d := libData{CanEdit: hasRole(sessionFrom(r), config.RoleAdmin), Count: len(lib), Small: small, Size: size, Q: r.URL.Query().Get("q")}
	for _, g := range workflow.TemplateGroups {
		if len(groups[g]) > 0 {
			d.Groups = append(d.Groups, libGroup{Name: g, Entries: groups[g]})
		}
	}
	s.render(w, r, "library", page{Title: "Workflow-Bibliothek", Nav: "workflows", Data: d})
}

func (s *Server) handleTemplateView(w http.ResponseWriter, r *http.Request) {
	t := workflow.TemplateByKey(s.library(), r.PathValue("key"))
	if t == nil {
		s.fail(w, r, 404, "Vorlage nicht gefunden")
		return
	}
	payload := s.designerPayload(&t.Def, true)
	payload["mode"] = "design"
	payload["template"] = t.Key
	raw, _ := json.Marshal(payload)
	s.render(w, r, "designer", page{Title: "Vorlage: " + t.Name, Nav: "workflows",
		Data: designerData{Tmpl: t, JSON: template.JS(raw), CanEdit: hasRole(sessionFrom(r), config.RoleAdmin)}})
}

func (s *Server) handleTemplateCopy(w http.ResponseWriter, r *http.Request) {
	t := workflow.TemplateByKey(s.library(), r.PathValue("key"))
	if t == nil {
		s.fail(w, r, 404, "Vorlage nicht gefunden")
		return
	}
	name := clip(strings.TrimSpace(r.FormValue("name")), 120)
	if name == "" {
		name = t.Name + " (eigene Fassung)"
	}
	s.createCopy(w, r, t.Def, name, "workflow_copy")
}

// handleLibraryJSON liefert Bibliothek und Workflows als Quelle für „Übernehmen“ (Designer, Aufgaben).
func (s *Server) handleLibraryJSON(w http.ResponseWriter, r *http.Request) {
	type src struct {
		ID    string       `json:"id"`
		Name  string       `json:"name"`
		Group string       `json:"group"`
		Def   workflow.Def `json:"def"`
	}
	var out []src
	for _, t := range s.library() {
		out = append(out, src{ID: "tpl:" + t.Key, Name: t.Name, Group: "Bibliothek · " + t.Group, Def: t.Def})
	}
	infos, _ := s.store.Workflows(r.Context())
	for _, wi := range infos {
		if c := wi.Current(); c != nil && !wi.Archived {
			g := "Eigene Workflows"
			if c.Status == "entwurf" {
				g = "Eigene Workflows (Entwurf)"
			}
			out = append(out, src{ID: "wf:" + strconv.FormatInt(wi.ID, 10), Name: c.Def.Name, Group: g, Def: c.Def})
		}
	}
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, 200, map[string]any{"sources": out})
}

// ---------- Designer ----------

type designerData struct {
	Tmpl     *workflow.Template // Ansicht einer Bibliotheksvorlage
	Info     *workflow.Info
	Edit     *workflow.Version
	Versions []*workflow.Version
	JSON     template.JS
	CanEdit  bool
	ViewOnly *workflow.Version // ältere Version ansehen
}

func (s *Server) handleWorkflowDesigner(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	info, err := s.store.WorkflowInfo(ctx, pathID(r, "id"))
	if err != nil {
		s.fail(w, r, 404, "Workflow nicht gefunden")
		return
	}
	d := designerData{Info: info, CanEdit: hasRole(sessionFrom(r), config.RoleAdmin)}
	d.Versions, _ = s.store.WorkflowVersions(ctx, info.ID)
	d.Edit = info.Current()
	if vid, _ := strconv.ParseInt(r.URL.Query().Get("v"), 10, 64); vid > 0 {
		for _, v := range d.Versions {
			if v.ID == vid && v.Status != "entwurf" {
				d.ViewOnly, d.Edit = v, v
			}
		}
	}
	if d.Edit == nil {
		s.fail(w, r, 404, "Workflow ohne Version")
		return
	}
	readOnly := !d.CanEdit || d.ViewOnly != nil
	payload := s.designerPayload(&d.Edit.Def, readOnly)
	payload["mode"] = "design"
	payload["workflow"] = info.ID
	payload["status"] = d.Edit.Status
	payload["version"] = d.Edit.Version
	payload["incidents"] = info.Incidents
	payload["has_active"] = info.Active != nil
	raw, _ := json.Marshal(payload)
	d.JSON = template.JS(raw)
	s.render(w, r, "designer", page{Title: "Workflow: " + d.Edit.Def.Name, Nav: "workflows", Data: d})
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

// handleWorkflowDraft speichert den Entwurf (vom Designer per fetch gesendet).
func (s *Server) handleWorkflowDraft(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	id := pathID(r, "id")
	if _, err := s.store.WorkflowInfo(ctx, id); err != nil {
		writeJSON(w, 404, map[string]any{"ok": false, "error": "Workflow nicht gefunden"})
		return
	}
	var d workflow.Def
	if err := json.Unmarshal([]byte(r.FormValue("def")), &d); err != nil {
		writeJSON(w, 400, map[string]any{"ok": false, "error": "Ungültige Daten: " + err.Error()})
		return
	}
	d.Normalize()
	issues := d.Validate(s.posKeys())
	if err := s.store.SaveDraft(ctx, id, d, sessionFrom(r).Username); err != nil {
		writeJSON(w, 400, map[string]any{"ok": false, "error": err.Error(), "issues": issues})
		return
	}
	s.audit(r, "workflow_draft", "workflow", id, 0, fmt.Sprintf("%s: Entwurf gespeichert (%d Schritte, %d Stabsanforderungen)", d.Name, len(d.Steps), len(d.Staff)))
	writeJSON(w, 200, map[string]any{"ok": true, "issues": issues, "saved": time.Now().Format("15:04:05"), "def": d})
}

func (s *Server) handleWorkflowPublish(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	id := pathID(r, "id")
	info, err := s.store.WorkflowInfo(ctx, id)
	if err != nil || info.Draft == nil {
		s.fail(w, r, 404, "Kein Entwurf vorhanden")
		return
	}
	if issues := info.Draft.Def.Validate(s.posKeys()); workflow.HasErrors(issues) {
		http.Redirect(w, r, fmt.Sprintf("/workflows/%d?msg=wf_invalid", id), http.StatusSeeOther)
		return
	}
	v, err := s.store.Publish(ctx, id, clip(r.FormValue("note"), 2000), sessionFrom(r).Username)
	if err != nil {
		s.fail(w, r, 500, err.Error())
		return
	}
	s.audit(r, "workflow_publish", "workflow", id, 0, fmt.Sprintf("%s v%d veröffentlicht: %s", v.Def.Name, v.Version, v.Note))
	http.Redirect(w, r, fmt.Sprintf("/workflows/%d?msg=wf_published", id), http.StatusSeeOther)
}

func (s *Server) handleWorkflowDiscard(w http.ResponseWriter, r *http.Request) {
	id := pathID(r, "id")
	info, err := s.store.WorkflowInfo(r.Context(), id)
	if err != nil {
		s.fail(w, r, 404, "Workflow nicht gefunden")
		return
	}
	if info.Active == nil {
		s.fail(w, r, 400, "Der einzige Stand eines nie veröffentlichten Workflows kann nicht verworfen werden – stattdessen archivieren.")
		return
	}
	_ = s.store.DiscardDraft(r.Context(), id)
	s.audit(r, "workflow_discard", "workflow", id, 0, info.Active.Def.Name+": Entwurf verworfen")
	http.Redirect(w, r, fmt.Sprintf("/workflows/%d?msg=wf_discarded", id), http.StatusSeeOther)
}

func (s *Server) handleWorkflowArchive(w http.ResponseWriter, r *http.Request) {
	id := pathID(r, "id")
	arch := r.FormValue("archived") == "1"
	if err := s.store.ArchiveWorkflow(r.Context(), id, arch); err != nil {
		s.fail(w, r, 500, err.Error())
		return
	}
	s.audit(r, "workflow_archive", "workflow", id, 0, fmt.Sprintf("archiviert=%v", arch))
	http.Redirect(w, r, "/workflows?msg=saved", http.StatusSeeOther)
}

// handleWorkflowRestore übernimmt eine ältere Version als neuen Entwurf.
func (s *Server) handleWorkflowRestore(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	id := pathID(r, "id")
	vid, _ := strconv.ParseInt(r.FormValue("version"), 10, 64)
	v, err := s.store.WorkflowVersion(ctx, vid)
	if err != nil || v.WorkflowID != id {
		s.fail(w, r, 404, "Version nicht gefunden")
		return
	}
	if err := s.store.SaveDraft(ctx, id, v.Def, sessionFrom(r).Username); err != nil {
		s.fail(w, r, 400, err.Error())
		return
	}
	s.audit(r, "workflow_restore", "workflow", id, 0, fmt.Sprintf("%s: Version %d als Entwurf übernommen", v.Def.Name, v.Version))
	http.Redirect(w, r, fmt.Sprintf("/workflows/%d?msg=wf_restored", id), http.StatusSeeOther)
}

func (s *Server) handleWorkflowExport(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	info, err := s.store.WorkflowInfo(ctx, pathID(r, "id"))
	if err != nil || info.Current() == nil {
		s.fail(w, r, 404, "Workflow nicht gefunden")
		return
	}
	v := info.Current()
	if vid, _ := strconv.ParseInt(r.URL.Query().Get("v"), 10, 64); vid > 0 {
		if x, err := s.store.WorkflowVersion(ctx, vid); err == nil && x.WorkflowID == info.ID {
			v = x
		}
	}
	// Positionen, die der Workflow nutzt, mit exportieren – so ist die Datei in einer anderen Installation vollständig.
	used := map[string]bool{}
	for _, st := range v.Def.Steps {
		used[st.Position] = true
	}
	for _, rq := range v.Def.Staff {
		used[rq.Position] = true
	}
	var pos []workflow.Position
	for _, p := range s.positions() {
		if used[p.Key] {
			p.Holders = nil // Personen gehören nicht in eine Austauschdatei
			pos = append(pos, p)
		}
	}
	out, err := yaml.Marshal(exportFile{Format: "leakguard-workflow/1", Workflow: v.Def, Positions: pos})
	if err != nil {
		s.fail(w, r, 500, err.Error())
		return
	}
	w.Header().Set("Content-Type", "application/yaml; charset=utf-8")
	w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="workflow-%s-v%d.yaml"`, v.Def.Key, v.Version))
	_, _ = w.Write(out)
}

type exportFile struct {
	Format    string              `yaml:"format"`
	Workflow  workflow.Def        `yaml:"workflow"`
	Positions []workflow.Position `yaml:"positions,omitempty"`
}

// handleWorkflowImport liest eine YAML-Datei: neuer Workflow oder neuer Entwurf eines vorhandenen (gleicher Schlüssel).
func (s *Server) handleWorkflowImport(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	var raw []byte
	if f, _, err := r.FormFile("file"); err == nil {
		raw, _ = io.ReadAll(io.LimitReader(f, 2<<20))
		f.Close()
	}
	if len(raw) == 0 {
		raw = []byte(r.FormValue("yaml"))
	}
	var ef exportFile
	if err := yaml.Unmarshal(raw, &ef); err != nil || ef.Workflow.Key == "" {
		var d workflow.Def // auch reine Workflow-Definition akzeptieren
		if err2 := yaml.Unmarshal(raw, &d); err2 != nil || d.Key == "" {
			http.Redirect(w, r, "/workflows?msg=wf_import_invalid", http.StatusSeeOther)
			return
		}
		ef.Workflow = d
	}
	user := sessionFrom(r).Username
	have := s.posKeys()
	for _, p := range ef.Positions {
		if !have[p.Key] && keyOK(p.Key) {
			p.Holders = nil
			_ = s.store.SavePosition(ctx, p, user)
		}
	}
	_ = s.reloadPositions(ctx)
	d := ef.Workflow
	d.Normalize()
	all, _ := s.store.Workflows(ctx)
	var id int64
	for _, wi := range all {
		if wi.Key == d.Key {
			id = wi.ID
		}
	}
	var err error
	if id > 0 {
		err = s.store.SaveDraft(ctx, id, d, user)
	} else {
		id, err = s.store.CreateWorkflow(ctx, d, user)
	}
	if err != nil {
		s.fail(w, r, 400, err.Error())
		return
	}
	s.audit(r, "workflow_import", "workflow", id, 0, d.Name)
	http.Redirect(w, r, fmt.Sprintf("/workflows/%d?msg=wf_imported", id), http.StatusSeeOther)
}

var posKeyRe = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]{0,39}$`)

func keyOK(k string) bool { return posKeyRe.MatchString(k) }

// ---------- Stabspositionen ----------

type positionsData struct {
	Groups  []posGroup
	Users   []model.User
	CanEdit bool
	Usage   map[string]string
}

func (positionsData) GroupOpts() []model.Labeled { return workflow.PositionGroups }

type posGroup struct {
	Group     model.Labeled
	Positions []workflow.Position
}

func (s *Server) handlePositions(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	d := positionsData{CanEdit: hasRole(sessionFrom(r), config.RoleAdmin), Usage: map[string]string{}}
	_, d.Users = s.names(r)
	byGroup := map[string][]workflow.Position{}
	for _, p := range s.positions() {
		g := p.Group
		if g == "" {
			g = "stab"
		}
		byGroup[g] = append(byGroup[g], p)
		wfs, members := s.store.PositionInUse(ctx, p.Key)
		var parts []string
		if len(wfs) > 0 {
			parts = append(parts, fmt.Sprintf("%d Workflow(s)", len(wfs)))
		}
		if members > 0 {
			parts = append(parts, fmt.Sprintf("%d× in Stäben", members))
		}
		d.Usage[p.Key] = strings.Join(parts, " · ")
	}
	for _, g := range workflow.PositionGroups {
		d.Groups = append(d.Groups, posGroup{Group: g, Positions: byGroup[g.Key]})
	}
	s.render(w, r, "positions", page{Title: "Stabspositionen", Nav: "workflows", Data: d})
}

func lines(v string) []string {
	var out []string
	for _, l := range strings.FieldsFunc(v, func(r rune) bool { return r == '\n' || r == ',' || r == ';' }) {
		if l = strings.TrimSpace(l); l != "" {
			out = append(out, l)
		}
	}
	return out
}

// rows trennt nur an Zeilenumbrüchen (Aufgaben dürfen Kommas enthalten).
func rows(v string) []string {
	var out []string
	for _, l := range strings.Split(v, "\n") {
		if l = strings.TrimSpace(l); l != "" {
			out = append(out, l)
		}
	}
	return out
}

func (s *Server) handlePositionSave(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	key := strings.ToLower(strings.TrimSpace(r.FormValue("key")))
	if !keyOK(key) || strings.TrimSpace(r.FormValue("label")) == "" {
		http.Redirect(w, r, "/workflows/positions?msg=invalid", http.StatusSeeOther)
		return
	}
	sortN, _ := strconv.Atoi(r.FormValue("sort"))
	color := r.FormValue("color")
	if !regexp.MustCompile(`^#[0-9a-fA-F]{6}$`).MatchString(color) {
		color = "#64748b"
	}
	p := workflow.Position{Key: key, Label: clip(strings.TrimSpace(r.FormValue("label")), 120), Short: clip(strings.TrimSpace(r.FormValue("short")), 8),
		Color: color, Group: oneOf(r.FormValue("group"), workflow.PositionGroups, "stab"), Description: clip(r.FormValue("description"), 2000),
		Why: clip(r.FormValue("why"), 2000), Duties: rows(clip(r.FormValue("duties"), 4000)), Ref: clip(r.FormValue("ref"), 300),
		Role: oneOf(r.FormValue("role"), model.IncidentRoles, model.IRoleMember), Holders: lines(r.FormValue("holders")), Sort: sortN}
	if p.Role == model.IRoleLead && key != "lead" {
		p.Role = model.IRoleMember // Leitung wird je Vorfall vergeben
	}
	old, existed := s.positionMap()[key]
	if err := s.store.SavePosition(ctx, p, sessionFrom(r).Username); err != nil {
		s.fail(w, r, 500, err.Error())
		return
	}
	_ = s.reloadPositions(ctx)
	txt := "angelegt"
	if existed {
		txt = "geändert"
		if strings.Join(old.Holders, ",") != strings.Join(p.Holders, ",") {
			txt += "; Besetzung: " + or(strings.Join(p.Holders, ", "), "–")
		}
	}
	s.audit(r, "position_save", "position", 0, 0, p.Label+" ("+p.Key+") "+txt)
	http.Redirect(w, r, "/workflows/positions?msg=saved#pos-"+key, http.StatusSeeOther)
}

func (s *Server) handlePositionDelete(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	key := r.FormValue("key")
	if wfs, _ := s.store.PositionInUse(ctx, key); len(wfs) > 0 || key == "lead" {
		http.Redirect(w, r, "/workflows/positions?msg=pos_inuse#pos-"+key, http.StatusSeeOther)
		return
	}
	if err := s.store.DeletePosition(ctx, key); err != nil {
		s.fail(w, r, 500, err.Error())
		return
	}
	_ = s.reloadPositions(ctx)
	s.audit(r, "position_delete", "position", 0, 0, key)
	http.Redirect(w, r, "/workflows/positions?msg=saved", http.StatusSeeOther)
}

// ---------- Vorfall: Workflow zuordnen ----------

func (s *Server) handleIncidentWorkflow(w http.ResponseWriter, r *http.Request) {
	in := s.loadIncident(w, r, model.IRoleLead)
	if in == nil {
		return
	}
	ctx := r.Context()
	old := s.version(ctx, in.WFVersionID)
	vid, _ := strconv.ParseInt(r.FormValue("version"), 10, 64)
	var nv *workflow.Version
	if vid > 0 {
		nv = s.version(ctx, vid)
		if nv == nil || nv.Status == "entwurf" {
			s.fail(w, r, 400, "Workflow-Version nicht verfügbar")
			return
		}
	}
	in.WFVersionID = vid
	if err := s.store.UpdateIncident(ctx, in); err != nil {
		s.fail(w, r, 500, err.Error())
		return
	}
	desc := func(v *workflow.Version) string {
		if v == nil {
			return "ohne Workflow"
		}
		return fmt.Sprintf("„%s“ v%d", v.Def.Name, v.Version)
	}
	txt := "Workflow: " + desc(old) + " → " + desc(nv)
	if reason := clip(r.FormValue("reason"), 1000); reason != "" {
		txt += "\nBegründung: " + reason
	}
	s.audit(r, "incident_workflow", "incident", in.ID, in.ID, txt)
	s.jlog(r, in.ID, "decision", txt, false)
	s.wfSync(r, in)
	back(w, r, in.ID, "workflow", "saved")
}

// gateRedirect zeigt die offenen Pflichtpunkte; der Wechsel ist dann nur mit Begründung möglich.
func (s *Server) gateRedirect(w http.ResponseWriter, r *http.Request, in *model.Incident, target string) {
	http.Redirect(w, r, fmt.Sprintf("/incidents/%d?tab=workflow&gate=%s&msg=gate#gate", in.ID, target), http.StatusSeeOther)
}

func (s *Server) activeVersions(r *http.Request) []*workflow.Version {
	vs, _ := s.store.ActiveVersions(r.Context())
	sort.SliceStable(vs, func(i, j int) bool { return vs[i].Def.Name < vs[j].Def.Name })
	return vs
}
