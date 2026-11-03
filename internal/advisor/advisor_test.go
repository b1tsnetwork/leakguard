package advisor

import (
	"strings"
	"testing"
	"time"

	"leakguard/internal/config"
	"leakguard/internal/model"
)

func cfg() *config.Incident {
	c := &config.Config{}
	c.Defaults()
	return &c.Incident
}

func keys(r Result) map[string]Rec {
	m := map[string]Rec{}
	for _, x := range r.Recs {
		m[x.Key] = x
	}
	return m
}

func base(cat, sev string) Input {
	now := time.Now()
	return Input{Cfg: cfg(), Now: now, In: &model.Incident{ID: 1, Category: cat, Severity: sev, Phase: model.PhaseTriage, Lead: "lead",
		AwarenessAt: now.Add(-2 * time.Hour), CreatedAt: now.Add(-2 * time.Hour), Description: "x"}}
}

func TestRansomwareP1(t *testing.T) {
	in := base("ransomware", "P1")
	in.In.PersonalData, in.In.ImpactA = true, true
	r := Advise(in)
	k := keys(r)
	for _, want := range []string{"crisis", "reg:dsgvo", "reg:cert", "reg:aufsicht", "staff:isb", "staff:dpo", "staff:s5", "staff:bcm",
		"inform_leadership", "inform_council", "inform_citizens", "ransom_decision", "emergency_ops", "evidence", "police", "playbook"} {
		if _, ok := k[want]; !ok {
			t.Errorf("Empfehlung %q fehlt", want)
		}
	}
	if r.Recs[0].Priority != PrioCritical {
		t.Errorf("Sortierung: erste Empfehlung %s", r.Recs[0].Priority)
	}
	if _, ok := k["reg:nis2"]; ok {
		t.Error("NIS2 ohne org.nis2 darf nicht empfohlen werden")
	}
	if !strings.Contains(k["reg:cert"].Title, "Landes-CERT") {
		t.Errorf("Behördenprofil nicht berücksichtigt: %s", k["reg:cert"].Title)
	}
}

func TestDismissAndSticky(t *testing.T) {
	in := base("ransomware", "P1")
	in.Obligations = []model.Obligation{{Key: "cert_first", Label: "Erstmeldung", Status: "offen", DueAt: in.Now.Add(-time.Hour), Regulation: "cert"}}
	in.Dismissed = map[string]bool{"crisis": true, "obl:cert_first": true}
	k := keys(Advise(in))
	if _, ok := k["crisis"]; ok {
		t.Error("verworfene Empfehlung erscheint erneut")
	}
	if r, ok := k["obl:cert_first"]; !ok || !r.Sticky || r.Priority != PrioCritical {
		t.Error("überfällige Frist muss kritisch und nicht verwerfbar sein")
	}
	if _, ok := k["reg:cert"]; ok {
		t.Error("aktive Meldepflicht darf nicht erneut empfohlen werden")
	}
}

func TestTechnical(t *testing.T) {
	in := base("account_compromise", "P2")
	in.In.Phase = model.PhaseContainment
	in.Assets = []model.Asset{{Name: "m.muster", Kind: "account", Status: "kompromittiert"}}
	in.IOCs = []model.IOC{{Type: "ip", Value: "1.2.3.4"}}
	k := keys(Advise(in))
	for _, want := range []string{"isolate:m.muster", "accounts:m.muster", "iocs_block"} {
		if _, ok := k[want]; !ok {
			t.Errorf("%s fehlt", want)
		}
	}
	// Erledigt per Aufgabe -> keine Empfehlung mehr
	in.Tasks = []model.Task{{Title: "IOCs sperren", Status: "erledigt"}, {Title: "Kennwort zurücksetzen", Status: "offen"}}
	k = keys(Advise(in))
	if _, ok := k["iocs_block"]; ok {
		t.Error("IOC-Empfehlung trotz Aufgabe")
	}
	if _, ok := k["accounts:m.muster"]; ok {
		t.Error("Konto-Empfehlung trotz Aufgabe")
	}
}

func TestPhaseCheck(t *testing.T) {
	in := base("malware", "P3")
	in.In.Phase = model.PhaseContainment
	in.Assets = []model.Asset{{Name: "PC1", Status: "isoliert"}}
	r := Advise(in)
	if !r.Phase.Ready || r.Phase.Next != model.PhaseEradication {
		t.Fatalf("Eindämmung -> Beseitigung sollte bereit sein: %+v", r.Phase)
	}
	if _, ok := keys(r)["phase:beseitigung"]; !ok {
		t.Error("Phasenempfehlung fehlt")
	}
	in.Assets[0].Status = "kompromittiert"
	if Advise(in).Phase.Ready {
		t.Error("mit kompromittiertem System nicht bereit")
	}
	// Nachbereitung -> Abschluss erst mit Lessons Learned und ohne offene Aufgaben
	in.In.Phase = model.PhasePostIncident
	in.Assets = nil
	in.Tasks = []model.Task{{Title: "x", Status: "offen"}}
	if Advise(in).Phase.Ready {
		t.Error("Abschluss trotz offener Aufgabe")
	}
	in.Tasks = nil
	in.In.RootCause, in.In.Lessons = "Phishing", "MFA"
	if !Advise(in).Phase.Ready {
		t.Error("Abschluss sollte möglich sein")
	}
}

func TestChecklistAndSitrep(t *testing.T) {
	in := base("malware", "P1")
	in.In.Phase = model.PhaseAnalysis
	in.In.AwarenessAt = in.Now.Add(-6 * time.Hour)
	k := keys(Advise(in))
	if _, ok := k["chk:analyse:0"]; !ok {
		t.Error("Checklistenschritt Analyse fehlt")
	}
	if _, ok := k["sitrep:0"]; !ok {
		t.Error("Lagebild-Empfehlung fehlt (P1, 6 h ohne Lagemeldung)")
	}
	in.Tasks = []model.Task{{Title: "Zeitlinie des Vorfalls erstellen (erste Kompromittierung bis heute)", Status: "offen"}}
	if _, ok := keys(Advise(in))["chk:analyse:0"]; ok {
		t.Error("Checklistenschritt trotz gleichnamiger Aufgabe")
	}
	in.Sitreps = []model.Sitrep{{No: 1, At: in.Now.Add(-time.Hour), Decisions: "Notbetrieb ja/nein"}}
	k = keys(Advise(in))
	if _, ok := k["decisions:1"]; !ok {
		t.Error("Entscheidungsbedarf aus Lagemeldung nicht erkannt")
	}
	in.Journal = []model.JournalEntry{{Kind: "decision", At: in.Now, Text: "Notbetrieb: ja"}}
	if _, ok := keys(Advise(in))["decisions:1"]; ok {
		t.Error("Entscheidung dokumentiert – Empfehlung muss entfallen")
	}
}

func TestInsiderPublicSector(t *testing.T) {
	in := base("insider", "P3")
	k := keys(Advise(in))
	for _, want := range []string{"staff:staff_council", "staff:legal", "insider_confidential"} {
		if _, ok := k[want]; !ok {
			t.Errorf("%s fehlt", want)
		}
	}
}
