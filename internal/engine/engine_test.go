package engine

import (
	"strings"
	"testing"
	"time"

	"leakguard/internal/config"
	"leakguard/internal/model"
)

func TestAssess(t *testing.T) {
	u := &model.ADUser{SAM: "mmuster", Enabled: true, PwdLastSet: time.Now().AddDate(0, -1, 0)}
	ch := model.Checks{User: u, Policy: model.PolicyResult{Compliant: true, Source: "Test"}}
	assess(&ch, Input{})
	if ch.Risk != model.RiskHigh || !ch.Actions.AdminTodo || !ch.Actions.UserMail || !ch.Actions.AdminMail {
		t.Fatalf("konform: %+v", ch)
	}

	ch = model.Checks{User: u, Policy: model.PolicyResult{Compliant: false}}
	assess(&ch, Input{})
	if ch.Risk != model.RiskLow || ch.Actions.AdminTodo || !ch.Actions.UserMail || ch.Actions.AdminMail {
		t.Fatalf("nicht konform: %+v", ch)
	}

	pu := *u
	pu.Privileged = []string{"Domain Admins"}
	ch = model.Checks{User: &pu, Policy: model.PolicyResult{Compliant: true}}
	assess(&ch, Input{})
	if ch.Risk != model.RiskCritical {
		t.Fatalf("privilegiert: %s", ch.Risk)
	}

	after := true
	ch = model.Checks{User: u, Policy: model.PolicyResult{Compliant: true}, PwdChangedAfterLeak: &after}
	assess(&ch, Input{})
	if ch.Risk != model.RiskMedium {
		t.Fatalf("nach Leak geändert: %s", ch.Risk)
	}
}

func TestDefaultTemplatesRender(t *testing.T) {
	c := &model.Case{ID: 7, CaseNumber: "SOC-1", PwMask: "S••••3", PwLen: 6, Risk: model.RiskHigh, Compliant: true,
		Checks: model.Checks{User: &model.ADUser{SAM: "o'brien", DisplayName: "Pat O'Brien", GivenName: "Pat", Mail: "pat@firma.de", UPN: "pat@firma.de", PasswordNeverExpires: true},
			Reasons: []string{"x"}, Actions: model.Actions{AdminTodo: true}}}
	e := &Engine{cfg: testCfg()}
	d := e.MailData(c, "Admin")
	for k, src := range DefaultTemplates {
		out, err := Render(src, d)
		if err != nil {
			t.Fatalf("%s: %v", k, err)
		}
		if strings.Contains(out, "<no value>") {
			t.Fatalf("%s enthält <no value>", k)
		}
	}
	ps := PowerShell(c)
	if !strings.Contains(ps, "'o''brien'") || !strings.Contains(ps, "-PasswordNeverExpires $false") {
		t.Fatalf("PowerShell-Quoting/Ablauf fehlerhaft:\n%s", ps)
	}
}

func testCfg() *config.Config {
	return &config.Config{BaseURL: "https://leakguard.firma.de", Secret: strings.Repeat("x", 32),
		Mail: config.Mail{Signature: "Gruß\nIT", OrgName: "IT"}}
}

func TestPasswordCrypto(t *testing.T) {
	e := &Engine{cfg: testCfg()}
	enc, err := e.EncryptPassword("Herbstlaub#2026")
	if err != nil || strings.Contains(enc, "Herbstlaub") {
		t.Fatal(enc, err)
	}
	if pw, err := e.DecryptPassword(enc); err != nil || pw != "Herbstlaub#2026" {
		t.Fatal(pw, err)
	}
	other := &Engine{cfg: &config.Config{Secret: strings.Repeat("y", 32)}}
	if _, err := other.DecryptPassword(enc); err == nil {
		t.Fatal("falscher Schlüssel darf nicht entschlüsseln")
	}
}
