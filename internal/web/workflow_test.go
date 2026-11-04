package web

import (
	"context"
	"encoding/json"
	"net/url"
	"regexp"
	"strings"
	"testing"
	"time"

	"leakguard/internal/model"
	"leakguard/internal/workflow"
)

func taskByStep(t *testing.T, e *testEnv, incID int64, step string) *model.Task {
	t.Helper()
	tasks, _ := e.st.Tasks(context.Background(), incID)
	for i := range tasks {
		if tasks[i].WFStep == step {
			return &tasks[i]
		}
	}
	return nil
}

func TestWorkflowEngine(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	// Vordefinierte Besetzung für den ISB
	isb := e.srv.position("isb")
	isb.Holders = []string{"other"}
	if err := e.st.SavePosition(ctx, isb, "test"); err != nil {
		t.Fatal(err)
	}
	_ = e.srv.reloadPositions(ctx)

	loc := e.mustOK("lead", "POST", "/incidents", url.Values{"title": {"Verschlüsselung Bauamt"}, "category": {"ransomware"}, "severity": {"P2"},
		"lead": {"lead"}, "awareness_at": {time.Now().Add(-30 * time.Minute).Format("2006-01-02T15:04")}})
	path := idRe.FindString(loc)
	id := mustInt(idRe.FindStringSubmatch(loc)[1])
	in, _ := e.st.GetIncident(ctx, id)
	v := e.srv.version(ctx, in.WFVersionID)
	if v == nil || v.Def.Key != "ransomware" {
		t.Fatalf("Workflow nicht automatisch passend gewählt: %+v", v)
	}
	for _, step := range []string{"b_erfassen", "b_erst", "r_trennen"} {
		if taskByStep(t, e, id, step) == nil {
			t.Fatalf("Aufgabe %s fehlt", step)
		}
	}
	if taskByStep(t, e, id, "r_backup") != nil {
		t.Fatal("Schritt der Triage zu früh angelegt")
	}

	// Sperre: Erstbewertung wartet auf vollständige Erfassung
	erst := taskByStep(t, e, id, "b_erst")
	_, _, l := e.do("resp", "POST", path+"/tasks/"+itoa(int(erst.ID)), url.Values{"status": {"erledigt"}, "return": {"aufgaben"}})
	if !strings.Contains(l, "task_locked") {
		t.Fatalf("gesperrte Aufgabe ließ sich erledigen: %s", l)
	}
	erf := taskByStep(t, e, id, "b_erfassen")
	e.mustOK("resp", "POST", path+"/tasks/"+itoa(int(erf.ID)), url.Values{"status": {"erledigt"}})
	e.mustOK("resp", "POST", path+"/tasks/"+itoa(int(erst.ID)), url.Values{"status": {"erledigt"}})
	if taskByStep(t, e, id, "b_erst").Status != "erledigt" {
		t.Fatal("entsperrte Aufgabe nicht erledigt")
	}
	// Pflichtschritt nur mit Begründung verwerfen
	tr := taskByStep(t, e, id, "r_trennen")
	_, _, l = e.do("resp", "POST", path+"/tasks/"+itoa(int(tr.ID)), url.Values{"status": {"verworfen"}})
	if !strings.Contains(l, "task_reason") {
		t.Fatalf("Pflichtschritt ohne Begründung verworfen: %s", l)
	}

	// Phasen-Gate: „Systeme trennen“ ist Pflicht und offen
	_, _, l = e.do("lead", "POST", path+"/phase", url.Values{"phase": {"triage"}})
	if !strings.Contains(l, "gate=triage") {
		t.Fatalf("Gate griff nicht: %s", l)
	}
	if in, _ = e.st.GetIncident(ctx, id); in.Phase != model.PhaseReported {
		t.Fatal("Phase trotz Gate gewechselt")
	}
	body := e.mustOK("lead", "GET", path+"?tab=workflow&gate=triage", nil)
	if !strings.Contains(body, "Betroffene Systeme vom Netz trennen") || !strings.Contains(body, "Abweichung begründen") {
		t.Fatal("Gate-Hinweis fehlt")
	}
	e.mustOK("lead", "POST", path+"/phase", url.Values{"phase": {"triage"}, "override": {"Systeme bereits durch RZ getrennt, Nachweis folgt"}})
	if in, _ = e.st.GetIncident(ctx, id); in.Phase != model.PhaseTriage {
		t.Fatal("Phase mit Begründung nicht gewechselt")
	}
	j, _ := e.st.Journal(ctx, id, "decision", false)
	if len(j) == 0 || !strings.Contains(j[0].Text, "trotz offener Pflichtpunkte") {
		t.Fatal("Abweichung nicht dokumentiert")
	}
	if taskByStep(t, e, id, "r_backup") == nil || taskByStep(t, e, id, "b_melde") == nil {
		t.Fatal("Triage-Schritte nicht angelegt")
	}

	// Stab: ISB ist Pflicht ab Triage, vorgesehene Besetzung wird vorgeschlagen und per Empfehlung aufgenommen
	body = e.mustOK("lead", "GET", path+"?tab=stab", nil)
	if !strings.Contains(body, "Soll / Ist") || !strings.Contains(body, "other aufnehmen") {
		t.Fatal("Soll-Ist-Abgleich mit Vorschlag fehlt")
	}
	if !strings.Contains(e.mustOK("lead", "GET", path+"?tab=empfehlungen", nil), "In den Stab aufnehmen: Informationssicherheitsbeauftragte/r (ISB) (Pflicht)") {
		t.Fatal("Stab-Empfehlung aus Workflow fehlt")
	}
	if code, _, _ := e.do("resp", "POST", path+"/recs", url.Values{"key": {"staff:isb"}, "op": {"apply"}}); code != 403 {
		t.Fatalf("Bearbeiter darf Stab nicht besetzen: %d", code)
	}
	e.mustOK("lead", "POST", path+"/recs", url.Values{"key": {"staff:isb"}, "op": {"apply"}})
	members, _ := e.st.Members(ctx, id)
	ok := false
	for _, m := range members {
		ok = ok || (m.Username == "other" && m.Function == "isb")
	}
	if !ok {
		t.Fatal("vorgesehene Besetzung nicht aufgenommen")
	}

	// Ansichten
	if b := e.mustOK("view", "GET", path+"?tab=workflow", nil); !strings.Contains(b, `id="wf-data"`) || !strings.Contains(b, "Ransomware") {
		t.Fatal("Workflow-Reiter ohne Ablaufdaten")
	}
	if b := e.mustOK("view", "GET", path+"?tab=aufgaben", nil); !strings.Contains(b, "Warum?") || !strings.Contains(b, "Pflicht · Phasen-Gate") {
		t.Fatal("Begründungen bei Aufgaben fehlen")
	}
}

func TestWorkflowDesignerVersions(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	if code, _, _ := e.do("resp", "GET", "/workflows", nil); code != 403 {
		t.Fatalf("Bearbeiter sieht Workflows: %d", code)
	}
	list := e.mustOK("lead", "GET", "/workflows", nil)
	if !strings.Contains(list, "Standardablauf") || !strings.Contains(list, "Ransomware") {
		t.Fatal("Startbestand fehlt")
	}
	infos, _ := e.st.Workflows(ctx)
	var std workflow.Info
	for _, wi := range infos {
		if wi.Key == "standard" {
			std = wi
		}
	}
	page := e.mustOK("admin", "GET", "/workflows/"+itoa(int(std.ID)), nil)
	if !strings.Contains(page, `id="wf-data"`) || !strings.Contains(page, "designer.js") {
		t.Fatal("Designer-Seite unvollständig")
	}
	// Vorfall mit Version 1
	loc := e.mustOK("lead", "POST", "/incidents", url.Values{"title": {"Sonstiges"}, "category": {"other"}, "severity": {"P3"}, "lead": {"lead"},
		"awareness_at": {time.Now().Format("2006-01-02T15:04")}})
	id := mustInt(idRe.FindStringSubmatch(loc)[1])
	in, _ := e.st.GetIncident(ctx, id)
	if in.WFVersionID != std.Active.ID {
		t.Fatal("Standardablauf nicht zugeordnet")
	}

	// Entwurf: Schritt mit Zyklus ist ungültig
	d := std.Active.Def
	d.Steps = append(d.Steps, workflow.Step{ID: "x1", Title: "Extra A", Phase: "gemeldet", Position: "s2", Why: "w", DependsOn: []string{"x2"}},
		workflow.Step{ID: "x2", Title: "Extra B", Phase: "gemeldet", Position: "s2", Why: "w", DependsOn: []string{"x1"}})
	raw, _ := json.Marshal(d)
	if code, _, _ := e.do("lead", "POST", "/workflows/"+itoa(int(std.ID))+"/draft", url.Values{"def": {string(raw)}}); code != 403 {
		t.Fatalf("Leitung darf nicht gestalten: %d", code)
	}
	b := e.mustOK("admin", "POST", "/workflows/"+itoa(int(std.ID))+"/draft", url.Values{"def": {string(raw)}})
	if !strings.Contains(b, `"ok":true`) || !strings.Contains(b, "Zirkuläre Abhängigkeit") {
		t.Fatalf("Entwurf/Prüfung: %s", b)
	}
	_, _, l := e.do("admin", "POST", "/workflows/"+itoa(int(std.ID))+"/publish", url.Values{"note": {"x"}})
	if !strings.Contains(l, "wf_invalid") {
		t.Fatal("fehlerhafter Entwurf veröffentlicht")
	}
	// Korrigieren und veröffentlichen
	d.Steps[len(d.Steps)-1].DependsOn = nil
	raw, _ = json.Marshal(d)
	e.mustOK("admin", "POST", "/workflows/"+itoa(int(std.ID))+"/draft", url.Values{"def": {string(raw)}})
	e.mustOK("admin", "POST", "/workflows/"+itoa(int(std.ID))+"/publish", url.Values{"note": {"Extra-Schritte"}})
	info, _ := e.st.WorkflowInfo(ctx, std.ID)
	if info.Active == nil || info.Active.Version != 2 || info.Draft != nil {
		t.Fatalf("Version 2 nicht aktiv: %+v", info.Active)
	}
	// Laufender Vorfall bleibt auf v1, bis die Leitung aktualisiert
	in, _ = e.st.GetIncident(ctx, id)
	if in.WFVersionID != std.Active.ID {
		t.Fatal("laufender Vorfall wurde ungefragt umgestellt")
	}
	path := "/incidents/" + itoa(int(id))
	if !strings.Contains(e.mustOK("lead", "GET", path+"?tab=workflow", nil), "Neuere Version verfügbar") {
		t.Fatal("Hinweis auf neue Version fehlt")
	}
	e.mustOK("lead", "POST", path+"/workflow", url.Values{"version": {itoa(int(info.Active.ID))}})
	if taskByStep(t, e, id, "x1") == nil {
		t.Fatal("neuer Schritt nach Aktualisierung nicht angelegt")
	}
	// Veröffentlichte Versionen sind unveränderlich
	if _, err := e.st.WorkflowVersion(ctx, std.Active.ID); err != nil {
		t.Fatal(err)
	}
	if err := e.st.Exec(ctx, `UPDATE workflow_versions SET def='{}' WHERE id=?`, std.Active.ID); err == nil {
		t.Fatal("veröffentlichte Version ließ sich ändern")
	}
	// Export → Import als neuer Workflow
	y := e.mustOK("lead", "GET", "/workflows/"+itoa(int(std.ID))+"/export.yaml", nil)
	if !strings.Contains(y, "leakguard-workflow/1") || !strings.Contains(y, "Extra A") {
		t.Fatal("Export unvollständig")
	}
	y = strings.Replace(y, "key: standard", "key: standard_kopie", 1)
	_, _, l = e.do("admin", "POST", "/workflows/import", url.Values{"yaml": {y}})
	if !strings.Contains(l, "wf_imported") {
		t.Fatalf("Import: %s", l)
	}
	// Stabsposition mit Besetzung pflegen; Löschen nur ohne Verwendung
	e.mustOK("admin", "POST", "/workflows/positions", url.Values{"key": {"isb"}, "label": {"ISB"}, "holders": {"lead\nother"}, "color": {"#7c3aed"}, "group": {"fachberatung"},
		"duties": {"Meldepflichten (CERT, Aufsicht) prüfen\nAbschlussbericht"}})
	if p := e.srv.position("isb"); len(p.Holders) != 2 || p.Holders[0] != "lead" {
		t.Fatalf("Besetzung nicht gespeichert: %+v", p.Holders)
	}
	if p := e.srv.position("isb"); len(p.Duties) != 2 || !strings.Contains(p.Duties[0], "CERT, Aufsicht") {
		t.Fatalf("Aufgaben falsch getrennt: %q", p.Duties)
	}
	_, _, l = e.do("admin", "POST", "/workflows/positions/delete", url.Values{"key": {"isb"}})
	if !strings.Contains(l, "pos_inuse") {
		t.Fatal("verwendete Position gelöscht")
	}
	if b := e.mustOK("lead", "GET", "/workflows/positions", nil); !strings.Contains(b, "Warum im Stab?") {
		t.Fatal("Positionsseite ohne Begründungen")
	}
}

func TestWorkflowConditions(t *testing.T) {
	f := workflow.Facts{Severity: "P2", Category: "phishing", PersonalData: true, Regulations: map[string]bool{"dsgvo": true}}
	cases := []struct {
		w    workflow.When
		want bool
	}{
		{workflow.When{}, true},
		{workflow.When{Rules: []workflow.Rule{{Field: "severity", Op: "min", Values: []string{"P2"}}}}, true},
		{workflow.When{Rules: []workflow.Rule{{Field: "severity", Op: "min", Values: []string{"P1"}}}}, false},
		{workflow.When{Rules: []workflow.Rule{{Field: "severity", Op: "max", Values: []string{"P3"}}}}, false},
		{workflow.When{Rules: []workflow.Rule{{Field: "category", Op: "in", Values: []string{"phishing", "malware"}}, {Field: "personal_data", Op: "true"}}}, true},
		{workflow.When{Mode: "any", Rules: []workflow.Rule{{Field: "crisis", Op: "true"}, {Field: "regulation", Op: "in", Values: []string{"dsgvo"}}}}, true},
		{workflow.When{Rules: []workflow.Rule{{Field: "crisis", Op: "true"}, {Field: "regulation", Op: "in", Values: []string{"dsgvo"}}}}, false},
		{workflow.When{Rules: []workflow.Rule{{Field: "affected_users", Op: "gte", Values: []string{"1"}}}}, false},
	}
	for i, c := range cases {
		if got := c.w.Match(f); got != c.want {
			t.Errorf("Fall %d: %v, erwartet %v", i, got, c.want)
		}
	}
	// Startbestand ist gültig
	pos := map[string]bool{}
	for _, p := range workflow.DefaultPositions(newEnv(t).srv.cfg.Incident.Functions) {
		pos[p.Key] = true
	}
	for _, tp := range workflow.Library(newEnv(t).srv.cfg.Incident.Categories) {
		for _, is := range tp.Def.Validate(pos) {
			t.Errorf("%s: %s %s", tp.Key, is.Level, is.Msg)
		}
	}
}

func TestWorkflowLibrary(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	lib := e.srv.library()
	if len(lib) < 20 {
		t.Fatalf("Bibliothek zu klein: %d", len(lib))
	}
	inst, _ := e.st.InstalledTemplates(ctx)
	infos, _ := e.st.Workflows(ctx)
	if len(inst) != len(lib) || len(infos) != len(lib) {
		t.Fatalf("nicht alle Vorlagen installiert: %d/%d/%d", len(inst), len(infos), len(lib))
	}
	// Neustart: nichts doppelt
	if err := e.srv.installLibrary(ctx); err != nil {
		t.Fatal(err)
	}
	if again, _ := e.st.Workflows(ctx); len(again) != len(infos) {
		t.Fatalf("Vorlagen doppelt installiert: %d", len(again))
	}
	// Spezialabläufe werden nicht automatisch gewählt
	loc := e.mustOK("lead", "POST", "/incidents", url.Values{"title": {"Konto übernommen"}, "category": {"account_compromise"}, "severity": {"P1"},
		"lead": {"lead"}, "awareness_at": {time.Now().Format("2006-01-02T15:04")}})
	in, _ := e.st.GetIncident(ctx, mustInt(idRe.FindStringSubmatch(loc)[1]))
	if v := e.srv.version(ctx, in.WFVersionID); v == nil || v.Def.Origin != "account_compromise" {
		t.Fatalf("falscher Workflow: %+v", v)
	}
	// IT-Notfall-Kategorie bekommt den Notfall-Ablauf ohne Angriffs-Schritte
	loc = e.mustOK("lead", "POST", "/incidents", url.Values{"title": {"Stromausfall RZ"}, "category": {"infra_outage"}, "severity": {"P2"},
		"lead": {"lead"}, "awareness_at": {time.Now().Format("2006-01-02T15:04")}})
	in, _ = e.st.GetIncident(ctx, mustInt(idRe.FindStringSubmatch(loc)[1]))
	v := e.srv.version(ctx, in.WFVersionID)
	if v == nil || v.Def.Origin != "it_notfall" || v.Def.Step("b_strat") != nil {
		t.Fatalf("IT-Notfall-Ablauf falsch: %+v", v)
	}

	// Bibliotheksseite, Vorlagenansicht, Datenquelle
	if b := e.mustOK("lead", "GET", "/bibliothek", nil); !strings.Contains(b, "DDoS") || !strings.Contains(b, "Active Directory") || !strings.Contains(b, "manuell wählbar") {
		t.Fatal("Bibliotheksseite unvollständig")
	}
	if b := e.mustOK("lead", "GET", "/bibliothek/patch_notfall", nil); !strings.Contains(b, "Vorlage") || !strings.Contains(b, `id="wf-data"`) {
		t.Fatal("Vorlagenansicht fehlt")
	}
	if code, _, _ := e.do("resp", "GET", "/bibliothek", nil); code != 403 {
		t.Fatalf("Bearbeiter sieht Bibliotheksseite: %d", code)
	}
	j := e.mustOK("resp", "GET", "/bibliothek.json", nil)
	var src struct {
		Sources []struct {
			ID  string       `json:"id"`
			Def workflow.Def `json:"def"`
		} `json:"sources"`
	}
	if err := json.Unmarshal([]byte(j), &src); err != nil || len(src.Sources) < 2*len(lib)-1 {
		t.Fatalf("library.json: %v %d", err, len(src.Sources))
	}

	// Vorlage kopieren (nur Admin), Herkunft bleibt erhalten
	if code, _, _ := e.do("lead", "POST", "/bibliothek/ddos/copy", nil); code != 403 {
		t.Fatalf("Leitung darf nicht kopieren: %d", code)
	}
	_, _, l := e.do("admin", "POST", "/bibliothek/ddos/copy", url.Values{"name": {"DDoS Bürgerportal Stadt"}})
	if !strings.Contains(l, "wf_copied") {
		t.Fatalf("Kopie: %s", l)
	}
	id := mustInt(regexp.MustCompile(`/workflows/(\d+)`).FindStringSubmatch(l)[1])
	info, _ := e.st.WorkflowInfo(ctx, id)
	if info.Draft == nil || info.Active != nil || info.Draft.Def.Name != "DDoS Bürgerportal Stadt" || info.Draft.Def.Origin != "ddos" || len(info.Draft.Def.Steps) < 10 {
		t.Fatalf("Vorlagenkopie falsch: %+v", info.Draft)
	}
	// Workflow kopieren
	_, _, l = e.do("admin", "POST", "/workflows/"+itoa(int(id))+"/copy", nil)
	id2 := mustInt(regexp.MustCompile(`/workflows/(\d+)`).FindStringSubmatch(l)[1])
	info2, _ := e.st.WorkflowInfo(ctx, id2)
	if id2 == id || info2.Draft == nil || info2.Draft.Def.Name != "DDoS Bürgerportal Stadt (Kopie)" || len(info2.Draft.Def.Steps) != len(info.Draft.Def.Steps) {
		t.Fatal("Workflow-Kopie falsch")
	}
	// Neuer Workflow aus Bibliothek über das Formular
	_, _, l = e.do("admin", "POST", "/workflows/new", url.Values{"name": {"Serverraum Rathaus"}, "from": {"tpl:serverraum"}})
	id3 := mustInt(regexp.MustCompile(`/workflows/(\d+)`).FindStringSubmatch(l)[1])
	if i3, _ := e.st.WorkflowInfo(ctx, id3); i3.Draft == nil || i3.Draft.Def.Step("sr_gefahr") == nil {
		t.Fatal("Neuer Workflow aus Vorlage ohne Schritte")
	}
	// Aufgabenformular bietet Vorlagen an
	if b := e.mustOK("resp", "GET", "/incidents/"+itoa(int(in.ID))+"?tab=aufgaben", nil); !strings.Contains(b, "data-task-template") {
		t.Fatal("Vorlagenauswahl im Aufgabenformular fehlt")
	}
}

func TestSmallScenarios(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	small := 0
	for _, tp := range e.srv.library() {
		if tp.Small {
			small++
		}
	}
	if small < 30 {
		t.Fatalf("zu wenige kleine Abläufe: %d", small)
	}
	pick := func(cat, sev string) *workflow.Version {
		t.Helper()
		loc := e.mustOK("lead", "POST", "/incidents", url.Values{"title": {cat + " " + sev}, "category": {cat}, "severity": {sev},
			"lead": {"lead"}, "awareness_at": {time.Now().Format("2006-01-02T15:04")}})
		in, _ := e.st.GetIncident(ctx, mustInt(idRe.FindStringSubmatch(loc)[1]))
		return e.srv.version(ctx, in.WFVersionID)
	}
	for _, c := range []struct{ cat, sev, want string }{
		{"phishing", "P4", "k_phishing_gemeldet"}, {"phishing", "P3", "k_phishing_klick"}, {"phishing", "P2", "phishing"},
		{"malware", "P4", "k_virenfund"}, {"malware", "P3", "k_malware_client"}, {"malware", "P1", "malware"},
		{"data_breach", "P4", "k_fehlversand"}, {"data_breach", "P3", "data_breach"},
		{"credential_leak", "P3", "k_leak_einzeln"}, {"device_loss", "P4", "k_geraeteverlust"}, {"service_outage", "P4", "k_ausfall_einzeln"},
		{"infra_outage", "P3", "k_ausfall_einzeln"}, {"infra_outage", "P2", "it_notfall"}, {"fraud", "P4", "k_rechnung_versuch"}, {"fraud", "P2", "fraud"},
	} {
		if v := pick(c.cat, c.sev); v == nil || v.Def.Origin != c.want {
			got := "–"
			if v != nil {
				got = v.Def.Origin
			}
			t.Errorf("%s/%s: %s, erwartet %s", c.cat, c.sev, got, c.want)
		}
	}
	// Kleiner Ablauf: schlanker Stab und wenige Aufgaben
	v := pick("phishing", "P4")
	for _, r := range v.Def.Staff {
		if r.Need == "pflicht" && len(r.When.Rules) == 0 && r.Position != "lead" {
			t.Errorf("kleiner Ablauf fordert %s ohne Bedingung als Pflicht", r.Position)
		}
	}
	if len(v.Def.Staff) > 5 || len(v.Def.Steps) > 10 {
		t.Errorf("kleiner Ablauf zu groß: %d Stab, %d Schritte", len(v.Def.Staff), len(v.Def.Steps))
	}
	if b := e.mustOK("lead", "GET", "/bibliothek?size=klein", nil); !strings.Contains(b, "Fehlversand") || strings.Contains(b, "Active Directory") {
		t.Fatal("Filter „klein“ wirkt nicht")
	}
	if b := e.mustOK("lead", "GET", "/bibliothek?q=zertifikat", nil); !strings.Contains(b, "Abgelaufenes Zertifikat") || strings.Contains(b, "Fehlversand einer E-Mail") {
		t.Fatal("Suche wirkt nicht")
	}
}
