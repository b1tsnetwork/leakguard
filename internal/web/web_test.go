package web

import (
	"context"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"leakguard/internal/config"
	"leakguard/internal/engine"
	"leakguard/internal/ldapx"
	"leakguard/internal/mailer"
	"leakguard/internal/model"
	"leakguard/internal/store"
)

// Rendert die Fallseite mit AD-Konto (inkl. PowerShell-Snippets) und prüft auf Template-Fehler.
func TestCasePageWithADUser(t *testing.T) {
	cfg := &config.Config{Secret: strings.Repeat("s", 32), BaseURL: "http://x", SessionHours: 1,
		Policy: config.Policy{MinLength: 12, MinCategories: 3, Complexity: true}, Mail: config.Mail{Signature: "IT"}}
	st, err := store.Open(filepath.Join(t.TempDir(), "t.db"))
	if err != nil {
		t.Fatal(err)
	}
	ld, _ := ldapx.New(cfg.LDAP)
	eng, err := engine.New(cfg, ld, st)
	if err != nil {
		t.Fatal(err)
	}
	srv, err := New(cfg, st, ld, eng, mailer.New(cfg.SMTP, cfg.Mail), "test")
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	c := &model.Case{CaseNumber: "SOC-1", CreatedBy: "admin", Identifier: "pat@firma.de", PwMask: "A••••z", PwLen: 14,
		Compliant: true, Risk: model.RiskCritical, Checks: model.Checks{
			User: &model.ADUser{DN: "CN=Pat,DC=firma,DC=local", SAM: "pat", UPN: "pat@firma.de", Mail: "pat@firma.de",
				DisplayName: "Pat Muster", GivenName: "Pat", Enabled: true, Privileged: []string{"Domain Admins"},
				PwdLastSet: time.Now().AddDate(0, -2, 0)},
			Policy:  model.PolicyResult{Compliant: true, Source: "Test", Findings: []model.Finding{{Rule: "Mindestlänge", OK: true, Detail: "14"}}},
			Risk:    model.RiskCritical,
			Reasons: []string{"Privilegiertes Konto"},
			Actions: model.Actions{AdminTodo: true, UserMail: true, AdminMail: true}}}
	c.PwEnc, _ = eng.EncryptPassword("Wagner-Laub2026")
	c.Checks.ADSSP = &model.ADSSPResult{Policy: "Standard", Compliant: false, Decisive: true, Native: true, ActiveSince: time.Now(),
		Satisfied: 2, Required: 3, Total: 4, Findings: []model.Finding{{Rule: "Tastaturfolgen", OK: false, Detail: "enthält qwer", Mandatory: true}}}
	c.Checks.Blocklist = model.BlockPattern{Words: []string{"wagner", "laub"}, Regex: "x"}
	if err := st.CreateCase(ctx, c); err != nil {
		t.Fatal(err)
	}
	se := store.Session{TokenHash: hashToken("tok"), Username: "admin", Display: "Admin", CSRF: "c", ExpiresAt: time.Now().Add(time.Hour)}
	if err := st.CreateSession(ctx, se); err != nil {
		t.Fatal(err)
	}
	h := srv.Handler()
	get := func(path string) (int, string) {
		req := httptest.NewRequest(http.MethodGet, path, nil)
		req.AddCookie(&http.Cookie{Name: cookieSession, Value: "tok"})
		rr := httptest.NewRecorder()
		h.ServeHTTP(rr, req)
		return rr.Code, rr.Body.String()
	}
	code, body := get("/cases/1")
	if code != 200 {
		t.Fatalf("status %d", code)
	}
	for _, want := range []string{"Kennwortänderung erzwingen", "Set-ADUser -Identity &#39;pat&#39; -ChangePasswordAtLogon $true",
		"Revoke-MgUserSignInSession", "Hallo Pat,", "privilegiert: Domain Admins", "</html>",
		`data-secret>Wagner-Laub2026</code>`, "Betroffenes Kennwort: Wagner-Laub2026", "Sperrliste (ADSelfService Plus)", "ADSelfService Plus: Standard", "schließt AD-Kennwort aus"} {
		if !strings.Contains(body, want) {
			t.Errorf("Fallseite enthält nicht %q", want)
		}
	}
	for _, p := range []string{"/", "/cases/new", "/settings", "/export.csv", "/?q=pat&status=offen"} {
		if code, b := get(p); code != 200 {
			t.Errorf("%s: status %d", p, code)
		} else if p == "/" && !strings.Contains(b, "SOC-1") {
			t.Errorf("Liste ohne Fall")
		}
	}
	if code, b := get("/blocklist.txt"); code != 200 || b != "laub\r\nwagner\r\n" {
		t.Errorf("blocklist.txt: %d %q", code, b)
	}
	if code, b := get("/blocklist.txt?format=regex"); code != 200 || !strings.HasPrefix(b, "^(?i)(?!") {
		t.Errorf("regex: %d %q", code, b)
	}
	if _, b := get("/export.csv"); strings.Contains(b, "Wagner-Laub2026") {
		t.Error("CSV darf das Kennwort nicht enthalten")
	}
	if code, _ := get("/cases/999"); code != 404 {
		t.Errorf("unbekannter Fall: %d", code)
	}
}
