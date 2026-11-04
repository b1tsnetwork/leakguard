// Package workflow beschreibt frei gestaltbare Abläufe für Sicherheitsvorfälle:
// Stabspositionen (wer gehört warum in den Stab), Schritte je Phase (was ist warum zu tun),
// Abhängigkeiten, Bedingungen und Phasen-Gates. Workflows werden versioniert gespeichert;
// laufende Vorfälle bleiben an die Version gebunden, mit der sie begonnen wurden.
package workflow

import (
	"fmt"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"leakguard/internal/model"
)

// ---------- Stabspositionen ----------

// Position ist eine Stelle im Stab, unabhängig vom einzelnen Workflow (Bibliothek).
type Position struct {
	Key         string   `json:"key" yaml:"key"`
	Label       string   `json:"label" yaml:"label"`
	Short       string   `json:"short,omitempty" yaml:"short,omitempty"` // Kürzel, z. B. S2, ISB
	Color       string   `json:"color,omitempty" yaml:"color,omitempty"`
	Group       string   `json:"group,omitempty" yaml:"group,omitempty"` // fuehrung | stab | fachberatung | beteiligung | extern
	Description string   `json:"description,omitempty" yaml:"description,omitempty"`
	Why         string   `json:"why,omitempty" yaml:"why,omitempty"` // Warum gehört die Position in den Stab?
	Duties      []string `json:"duties,omitempty" yaml:"duties,omitempty"`
	Ref         string   `json:"ref,omitempty" yaml:"ref,omitempty"`
	Role        string   `json:"role,omitempty" yaml:"role,omitempty"`       // Standardrolle im Vorfall: mitglied | beobachter
	Holders     []string `json:"holders,omitempty" yaml:"holders,omitempty"` // vordefinierte Besetzung: 1. = Hauptbesetzung, weitere = Vertretung
	Sort        int      `json:"sort,omitempty" yaml:"sort,omitempty"`
}

var PositionGroups = []model.Labeled{
	{Key: "fuehrung", Label: "Führung"}, {Key: "stab", Label: "Stabsfunktionen (S1–S6)"},
	{Key: "fachberatung", Label: "Fachberatung"}, {Key: "beteiligung", Label: "Beteiligung / Recht"}, {Key: "extern", Label: "Extern"},
}

// ---------- Bedingungen ----------

// Rule ist eine einzelne Bedingung über die Merkmale eines Vorfalls.
type Rule struct {
	Field  string   `json:"field" yaml:"field"`
	Op     string   `json:"op" yaml:"op"`
	Values []string `json:"values,omitempty" yaml:"values,omitempty,flow"`
}

// When verknüpft Regeln: "all" (und) oder "any" (oder). Keine Regeln = gilt immer.
type When struct {
	Mode  string `json:"mode,omitempty" yaml:"mode,omitempty"`
	Rules []Rule `json:"rules,omitempty" yaml:"rules,omitempty"`
}

func (w When) Empty() bool { return len(w.Rules) == 0 }

// Field beschreibt ein auswertbares Merkmal (für Designer und Validierung).
type Field struct {
	Key   string   `json:"key"`
	Label string   `json:"label"`
	Type  string   `json:"type"` // sev | set | bool | num
	Ops   []string `json:"ops"`
	Set   string   `json:"set,omitempty"` // Werteliste für Typ set: category | tlp | org | regulation
}

var Fields = []Field{
	{Key: "severity", Label: "Schweregrad", Type: "sev", Ops: []string{"min", "max", "in"}},
	{Key: "category", Label: "Kategorie", Type: "set", Ops: []string{"in", "not_in"}, Set: "category"},
	{Key: "personal_data", Label: "Personenbezogene Daten betroffen", Type: "bool", Ops: []string{"true", "false"}},
	{Key: "crisis", Label: "Lage / Stab ausgerufen", Type: "bool", Ops: []string{"true", "false"}},
	{Key: "impact_c", Label: "Vertraulichkeit verletzt", Type: "bool", Ops: []string{"true", "false"}},
	{Key: "impact_i", Label: "Integrität verletzt", Type: "bool", Ops: []string{"true", "false"}},
	{Key: "impact_a", Label: "Verfügbarkeit beeinträchtigt", Type: "bool", Ops: []string{"true", "false"}},
	{Key: "compromised", Label: "Kompromittierte Systeme erfasst", Type: "bool", Ops: []string{"true", "false"}},
	{Key: "classified", Label: "VS-Einstufung (VS-NfD)", Type: "bool", Ops: []string{"true", "false"}},
	{Key: "confidential", Label: "Vertraulicher Vorfall (need-to-know)", Type: "bool", Ops: []string{"true", "false"}},
	{Key: "nis2", Label: "Einrichtung ist NIS2-pflichtig", Type: "bool", Ops: []string{"true", "false"}},
	{Key: "affected_users", Label: "Anzahl Betroffene", Type: "num", Ops: []string{"gte", "lt"}},
	{Key: "tlp", Label: "TLP", Type: "set", Ops: []string{"in", "not_in"}, Set: "tlp"},
	{Key: "org_type", Label: "Art der Behörde", Type: "set", Ops: []string{"in", "not_in"}, Set: "org"},
	{Key: "regulation", Label: "Meldepflicht aktiviert", Type: "set", Ops: []string{"in", "not_in"}, Set: "regulation"},
}

var OpLabels = map[string]string{"min": "mindestens", "max": "höchstens", "in": "ist eine von", "not_in": "ist keine von",
	"true": "ja", "false": "nein", "gte": "mindestens", "lt": "weniger als"}

func FieldByKey(k string) (Field, bool) {
	for _, f := range Fields {
		if f.Key == k {
			return f, true
		}
	}
	return Field{}, false
}

// Facts sind die auswertbaren Merkmale eines konkreten Vorfalls.
type Facts struct {
	Severity, Category, TLP, OrgType                                         string
	PersonalData, Crisis, ImpactC, ImpactI, ImpactA, Compromised, Classified bool
	Confidential, NIS2                                                       bool
	AffectedUsers                                                            int
	Regulations                                                              map[string]bool
}

// FactsFor leitet die Merkmale aus dem Vorfall ab.
func FactsFor(in *model.Incident, orgType string, nis2 bool, assets []model.Asset, obl []model.Obligation) Facts {
	f := Facts{Severity: in.Severity, Category: in.Category, TLP: in.TLP, OrgType: orgType, PersonalData: in.PersonalData,
		Crisis: in.CrisisMode, ImpactC: in.ImpactC, ImpactI: in.ImpactI, ImpactA: in.ImpactA, Classified: in.Classification != "",
		Confidential: in.Confidential, NIS2: nis2, AffectedUsers: in.AffectedUsers, Regulations: map[string]bool{}}
	for _, a := range assets {
		if a.Status == "kompromittiert" {
			f.Compromised = true
		}
	}
	for _, o := range obl {
		f.Regulations[o.Regulation] = true
	}
	return f
}

// sevRank: P1 = 1 (am schwersten) … P4 = 4.
func sevRank(s string) int {
	if len(s) == 2 && s[0] == 'P' && s[1] >= '1' && s[1] <= '4' {
		return int(s[1] - '0')
	}
	return 9
}

func contains(list []string, v string) bool {
	for _, x := range list {
		if strings.EqualFold(x, v) {
			return true
		}
	}
	return false
}

func (f Facts) boolOf(field string) (bool, bool) {
	switch field {
	case "personal_data":
		return f.PersonalData, true
	case "crisis":
		return f.Crisis, true
	case "impact_c":
		return f.ImpactC, true
	case "impact_i":
		return f.ImpactI, true
	case "impact_a":
		return f.ImpactA, true
	case "compromised":
		return f.Compromised, true
	case "classified":
		return f.Classified, true
	case "confidential":
		return f.Confidential, true
	case "nis2":
		return f.NIS2, true
	}
	return false, false
}

// Match wertet eine einzelne Regel aus. Unbekannte Regeln gelten als nicht erfüllt.
func (r Rule) Match(f Facts) bool {
	first := ""
	if len(r.Values) > 0 {
		first = r.Values[0]
	}
	switch r.Field {
	case "severity":
		switch r.Op {
		case "min":
			return sevRank(f.Severity) <= sevRank(first)
		case "max":
			return sevRank(f.Severity) >= sevRank(first) && sevRank(f.Severity) < 9
		case "in":
			return contains(r.Values, f.Severity)
		}
	case "category", "tlp", "org_type":
		v := map[string]string{"category": f.Category, "tlp": f.TLP, "org_type": f.OrgType}[r.Field]
		switch r.Op {
		case "in":
			return contains(r.Values, v)
		case "not_in":
			return !contains(r.Values, v)
		}
	case "regulation":
		any := false
		for _, v := range r.Values {
			any = any || f.Regulations[v]
		}
		switch r.Op {
		case "in":
			return any
		case "not_in":
			return !any
		}
	case "affected_users":
		n, err := strconv.Atoi(strings.TrimSpace(first))
		if err != nil {
			return false
		}
		switch r.Op {
		case "gte":
			return f.AffectedUsers >= n
		case "lt":
			return f.AffectedUsers < n
		}
	default:
		if b, ok := f.boolOf(r.Field); ok {
			switch r.Op {
			case "true":
				return b
			case "false":
				return !b
			}
		}
	}
	return false
}

// Match wertet die Bedingungsgruppe aus.
func (w When) Match(f Facts) bool {
	if len(w.Rules) == 0 {
		return true
	}
	if w.Mode == "any" {
		for _, r := range w.Rules {
			if r.Match(f) {
				return true
			}
		}
		return false
	}
	for _, r := range w.Rules {
		if !r.Match(f) {
			return false
		}
	}
	return true
}

// Labels liefert Anzeigenamen für Wertelisten (Kategorien, Regelungen …).
type Labels func(set, key string) string

// Describe formuliert die Bedingung lesbar („Schweregrad mindestens P2 und personenbezogene Daten: ja“).
func (w When) Describe(lab Labels) string {
	if len(w.Rules) == 0 {
		return "immer"
	}
	var parts []string
	for _, r := range w.Rules {
		parts = append(parts, r.Describe(lab))
	}
	join := " und "
	if w.Mode == "any" {
		join = " oder "
	}
	return strings.Join(parts, join)
}

func (r Rule) Describe(lab Labels) string {
	f, ok := FieldByKey(r.Field)
	if !ok {
		return "unbekannte Bedingung " + r.Field
	}
	switch f.Type {
	case "bool":
		if r.Op == "false" {
			return "nicht " + lowerFirst(f.Label)
		}
		return f.Label
	case "set":
		var vals []string
		for _, v := range r.Values {
			if lab != nil {
				v = lab(f.Set, v)
			}
			vals = append(vals, v)
		}
		return fmt.Sprintf("%s %s „%s“", f.Label, OpLabels[r.Op], strings.Join(vals, "“, „"))
	default:
		return fmt.Sprintf("%s %s %s", f.Label, OpLabels[r.Op], strings.Join(r.Values, ", "))
	}
}

func lowerFirst(s string) string {
	if s == "" {
		return s
	}
	r := []rune(s)
	return strings.ToLower(string(r[0])) + string(r[1:])
}

// ---------- Workflow-Definition ----------

// Step ist ein Arbeitsschritt im Ablauf.
type Step struct {
	ID        string   `json:"id" yaml:"id"`
	Title     string   `json:"title" yaml:"title"`
	Kind      string   `json:"kind,omitempty" yaml:"kind,omitempty"` // aufgabe | entscheidung | meldung | pruefung | kommunikation
	Phase     string   `json:"phase" yaml:"phase"`
	Position  string   `json:"position,omitempty" yaml:"position,omitempty"`
	Priority  string   `json:"priority,omitempty" yaml:"priority,omitempty"`
	DueHours  int      `json:"due_hours,omitempty" yaml:"due_hours,omitempty"`
	DueFrom   string   `json:"due_from,omitempty" yaml:"due_from,omitempty"` // kenntnis (Standard) | anlage
	Mandatory bool     `json:"mandatory,omitempty" yaml:"mandatory,omitempty"`
	Manual    bool     `json:"manual,omitempty" yaml:"manual,omitempty"` // nicht automatisch anlegen, nur empfehlen
	DependsOn []string `json:"depends_on,omitempty" yaml:"depends_on,omitempty,flow"`
	When      When     `json:"when,omitempty" yaml:"when,omitempty"`
	Why       string   `json:"why,omitempty" yaml:"why,omitempty"`
	Ref       string   `json:"ref,omitempty" yaml:"ref,omitempty"`
	Details   string   `json:"details,omitempty" yaml:"details,omitempty"`
	Y         float64  `json:"y,omitempty" yaml:"y,omitempty"` // Position im Ablaufgraph (innerhalb der Phase)
}

// StaffReq legt fest, welche Stabsposition ab welcher Phase und unter welchen Bedingungen besetzt sein muss.
type StaffReq struct {
	ID       string `json:"id" yaml:"id"`
	Position string `json:"position" yaml:"position"`
	Need     string `json:"need" yaml:"need"`   // pflicht | soll | optional
	Phase    string `json:"phase" yaml:"phase"` // ab dieser Phase
	When     When   `json:"when,omitempty" yaml:"when,omitempty"`
	Why      string `json:"why,omitempty" yaml:"why,omitempty"`
	Ref      string `json:"ref,omitempty" yaml:"ref,omitempty"`
	AutoAdd  bool   `json:"auto_add,omitempty" yaml:"auto_add,omitempty"` // vordefinierte Besetzung automatisch aufnehmen
	Role     string `json:"role,omitempty" yaml:"role,omitempty"`
}

// Match bestimmt, wann ein Workflow automatisch vorgeschlagen wird.
type Match struct {
	Categories []string `json:"categories,omitempty" yaml:"categories,omitempty,flow"`
	When       When     `json:"when,omitempty" yaml:"when,omitempty"`
	Priority   int      `json:"priority,omitempty" yaml:"priority,omitempty"`
	// ManualOnly: wird nie automatisch gewählt, nur von Hand (z. B. Spezialabläufe wie AD-Kompromittierung).
	ManualOnly bool `json:"manual_only,omitempty" yaml:"manual_only,omitempty"`
}

// Def ist ein vollständiger Workflow.
type Def struct {
	Key         string     `json:"key" yaml:"key"`
	Name        string     `json:"name" yaml:"name"`
	Description string     `json:"description,omitempty" yaml:"description,omitempty"`
	Color       string     `json:"color,omitempty" yaml:"color,omitempty"`
	Match       Match      `json:"match" yaml:"match"`
	Staff       []StaffReq `json:"staff" yaml:"staff"`
	Steps       []Step     `json:"steps" yaml:"steps"`
	// Herkunft aus der eingebauten Bibliothek (leer = selbst erstellt).
	Origin    string `json:"origin,omitempty" yaml:"origin,omitempty"`
	OriginRev int    `json:"origin_rev,omitempty" yaml:"origin_rev,omitempty"`
}

var StepKinds = []model.Labeled{
	{Key: "aufgabe", Label: "Aufgabe", Hint: "Maßnahme, die jemand erledigt"},
	{Key: "entscheidung", Label: "Entscheidung", Hint: "Leitungsentscheidung – Ergebnis wird als Entscheidung ins Einsatztagebuch übernommen"},
	{Key: "pruefung", Label: "Prüfung", Hint: "Bewertung oder Kontrolle mit dokumentiertem Ergebnis"},
	{Key: "meldung", Label: "Meldung", Hint: "Meldung an eine externe Stelle (CERT, Datenschutz, Aufsicht …)"},
	{Key: "kommunikation", Label: "Kommunikation", Hint: "Information an Beschäftigte, Bürger, Presse, Gremien"},
}

var Needs = []model.Labeled{
	{Key: "pflicht", Label: "Pflicht", Hint: "Muss besetzt sein – sonst kein Phasenwechsel ohne Begründung"},
	{Key: "soll", Label: "Soll", Hint: "Wird empfohlen und als Handlungsbedarf angezeigt"},
	{Key: "optional", Label: "Optional", Hint: "Nur als Hinweis im Stab sichtbar"},
}

// WorkPhases sind die Phasen, denen Schritte zugeordnet werden können (ohne „Abgeschlossen“).
func WorkPhases() []model.Labeled { return model.Phases[:len(model.Phases)-1] }

func PhaseIdx(p string) int {
	for i, x := range model.Phases {
		if x.Key == p {
			return i
		}
	}
	return -1
}

// MatchScore liefert, ob der Workflow zum Vorfall passt, und wie spezifisch (höher = besser).
func (d *Def) MatchScore(f Facts) (int, bool) {
	if d.Match.ManualOnly {
		return 0, false
	}
	if len(d.Match.Categories) > 0 && !contains(d.Match.Categories, f.Category) {
		return 0, false
	}
	if !d.Match.When.Match(f) {
		return 0, false
	}
	score := d.Match.Priority * 100
	if len(d.Match.Categories) > 0 {
		score += 50
	}
	return score + len(d.Match.When.Rules), true
}

func (d *Def) Step(id string) *Step {
	for i := range d.Steps {
		if d.Steps[i].ID == id {
			return &d.Steps[i]
		}
	}
	return nil
}

// ---------- Validierung ----------

type Issue struct {
	Level string `json:"level"` // error | warn
	Ref   string `json:"ref"`   // step:<id> | staff:<id> | match | def
	Msg   string `json:"msg"`
}

var keyRe = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]{0,63}$`)

// Normalize setzt Standardwerte und bereinigt Eingaben (vor dem Speichern).
func (d *Def) Normalize() {
	d.Key = strings.ToLower(strings.TrimSpace(d.Key))
	d.Name = strings.TrimSpace(d.Name)
	for i := range d.Steps {
		s := &d.Steps[i]
		s.Title = strings.TrimSpace(s.Title)
		if s.Kind == "" {
			s.Kind = "aufgabe"
		}
		if s.Priority == "" {
			s.Priority = "mittel"
		}
		if s.DueFrom == "" {
			s.DueFrom = "kenntnis"
		}
		if s.When.Mode == "" {
			s.When.Mode = "all"
		}
		s.DependsOn = uniq(s.DependsOn)
	}
	for i := range d.Staff {
		r := &d.Staff[i]
		if r.Need == "" {
			r.Need = "soll"
		}
		if r.Phase == "" {
			r.Phase = model.PhaseReported
		}
		if r.When.Mode == "" {
			r.When.Mode = "all"
		}
	}
	if d.Match.When.Mode == "" {
		d.Match.When.Mode = "all"
	}
	if d.Steps == nil {
		d.Steps = []Step{}
	}
	if d.Staff == nil {
		d.Staff = []StaffReq{}
	}
}

func uniq(l []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, x := range l {
		if x != "" && !seen[x] {
			seen[x] = true
			out = append(out, x)
		}
	}
	return out
}

// Validate prüft den Workflow. Fehler verhindern das Veröffentlichen, Warnungen nicht.
func (d *Def) Validate(positions map[string]bool) []Issue {
	var out []Issue
	add := func(level, ref, f string, a ...any) { out = append(out, Issue{level, ref, fmt.Sprintf(f, a...)}) }
	if !keyRe.MatchString(d.Key) {
		add("error", "def", "Schlüssel muss aus Kleinbuchstaben, Ziffern, - oder _ bestehen")
	}
	if d.Name == "" {
		add("error", "def", "Name fehlt")
	}
	checkWhen := func(ref string, w When) {
		for _, r := range w.Rules {
			f, ok := FieldByKey(r.Field)
			if !ok {
				add("error", ref, "Bedingung: unbekanntes Merkmal %q", r.Field)
				continue
			}
			if !contains(f.Ops, r.Op) {
				add("error", ref, "Bedingung %s: Operator %q nicht zulässig", f.Label, r.Op)
			}
			if f.Type != "bool" && len(r.Values) == 0 {
				add("error", ref, "Bedingung %s: Wert fehlt", f.Label)
			}
		}
	}
	checkWhen("match", d.Match.When)
	ids := map[string]*Step{}
	for i := range d.Steps {
		s := &d.Steps[i]
		ref := "step:" + s.ID
		if s.ID == "" || !keyRe.MatchString(s.ID) {
			add("error", ref, "Schritt %q: ungültige ID", s.Title)
		}
		if ids[s.ID] != nil {
			add("error", ref, "Schritt-ID %q doppelt", s.ID)
		}
		ids[s.ID] = s
		if s.Title == "" {
			add("error", ref, "Schritt ohne Titel")
		}
		if i := PhaseIdx(s.Phase); i < 0 || i >= len(model.Phases)-1 {
			add("error", ref, "„%s“: Phase %q unbekannt", s.Title, s.Phase)
		}
		if s.Position != "" && positions != nil && !positions[s.Position] {
			add("error", ref, "„%s“: Stabsposition %q existiert nicht", s.Title, s.Position)
		}
		if s.Position == "" {
			add("warn", ref, "„%s“: keine Stabsposition zugeordnet – niemand ist zuständig", s.Title)
		}
		if strings.TrimSpace(s.Why) == "" {
			add("warn", ref, "„%s“: Begründung (Warum?) fehlt", s.Title)
		}
		if s.DueHours < 0 {
			add("error", ref, "„%s“: Frist darf nicht negativ sein", s.Title)
		}
		checkWhen(ref, s.When)
	}
	for _, s := range d.Steps {
		for _, dep := range s.DependsOn {
			ds := ids[dep]
			switch {
			case ds == nil:
				add("error", "step:"+s.ID, "„%s“: Vorgänger %q existiert nicht", s.Title, dep)
			case dep == s.ID:
				add("error", "step:"+s.ID, "„%s“ hängt von sich selbst ab", s.Title)
			case PhaseIdx(ds.Phase) > PhaseIdx(s.Phase):
				add("error", "step:"+s.ID, "„%s“ wartet auf „%s“ aus einer späteren Phase", s.Title, ds.Title)
			}
		}
	}
	if cyc := d.cycle(); cyc != "" {
		add("error", "step:"+cyc, "Zirkuläre Abhängigkeit bei „%s“", d.Step(cyc).Title)
	}
	staffSeen := map[string]bool{}
	for _, r := range d.Staff {
		ref := "staff:" + r.ID
		if r.ID == "" {
			add("error", ref, "Stabsanforderung ohne ID")
		}
		if positions != nil && !positions[r.Position] {
			add("error", ref, "Stabsposition %q existiert nicht", r.Position)
		}
		if !contains([]string{"pflicht", "soll", "optional"}, r.Need) {
			add("error", ref, "Bedarf %q unbekannt", r.Need)
		}
		if i := PhaseIdx(r.Phase); i < 0 || i >= len(model.Phases)-1 {
			add("error", ref, "Phase %q unbekannt", r.Phase)
		}
		if strings.TrimSpace(r.Why) == "" {
			add("warn", ref, "Stabsposition %q: Begründung (Warum im Stab?) fehlt", r.Position)
		}
		if staffSeen[r.Position] && r.When.Empty() {
			add("warn", ref, "Stabsposition %q mehrfach angefordert – die Anforderung ohne Bedingung gilt immer", r.Position)
		}
		staffSeen[r.Position] = true
		checkWhen(ref, r.When)
	}
	return out
}

// cycle liefert die ID eines Schritts in einem Zyklus (oder "").
func (d *Def) cycle() string {
	state := map[string]int{}
	var visit func(id string) string
	visit = func(id string) string {
		switch state[id] {
		case 1:
			return id
		case 2:
			return ""
		}
		state[id] = 1
		if s := d.Step(id); s != nil {
			for _, dep := range s.DependsOn {
				if d.Step(dep) == nil {
					continue
				}
				if c := visit(dep); c != "" {
					return c
				}
			}
		}
		state[id] = 2
		return ""
	}
	ids := make([]string, 0, len(d.Steps))
	for _, s := range d.Steps {
		ids = append(ids, s.ID)
	}
	sort.Strings(ids)
	for _, id := range ids {
		if c := visit(id); c != "" {
			return c
		}
	}
	return ""
}

func HasErrors(issues []Issue) bool {
	for _, i := range issues {
		if i.Level == "error" {
			return true
		}
	}
	return false
}

// ---------- Versionen ----------

type Version struct {
	ID          int64     `json:"id"`
	WorkflowID  int64     `json:"workflow_id"`
	Version     int       `json:"version"` // 0 = Entwurf
	Status      string    `json:"status"`  // entwurf | aktiv | abgeloest
	Def         Def       `json:"def"`
	Note        string    `json:"note"`
	CreatedAt   time.Time `json:"created_at"`
	CreatedBy   string    `json:"created_by"`
	PublishedAt time.Time `json:"published_at"`
	PublishedBy string    `json:"published_by"`
}

// Info fasst einen Workflow für Übersichten zusammen.
type Info struct {
	ID        int64
	Key       string
	Archived  bool
	Active    *Version
	Draft     *Version
	Versions  int
	Incidents int
}

func (i Info) Current() *Version {
	if i.Draft != nil {
		return i.Draft
	}
	return i.Active
}
