package config

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLoadCreatesExampleAndResolvesPaths(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "config.yaml")

	if _, err := Load(p); !errors.Is(err, ErrCreated) {
		t.Fatalf("erwartet ErrCreated, bekommen %v", err)
	}
	raw, err := os.ReadFile(p)
	if err != nil || strings.Contains(string(raw), `secret: ""`) {
		t.Fatalf("secret nicht erzeugt: %v", err)
	}
	// Zweiter Start: Beispielwerte sind unvollständig (bind_password fehlt) -> verständlicher Fehler
	if _, err := Load(p); err == nil || !strings.Contains(err.Error(), "bind_password") {
		t.Fatalf("erwartet Validierungsfehler, bekommen %v", err)
	}

	t.Setenv("LEAKGUARD_LDAP_BIND_PASSWORD", "x")
	cfg, err := Load(p)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.DBPath != filepath.Join(dir, "leakguard.db") {
		t.Fatalf("db_path nicht relativ zur Konfiguration: %s", cfg.DBPath)
	}
}

func TestADSSPExampleParses(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "config.yaml")
	ex := strings.Replace(exampleConfig, "adssp:\n  enabled: false", "adssp:\n  enabled: true", 1)
	ex = strings.Replace(ex, `secret: ""`, `secret: "`+strings.Repeat("s", 40)+`"`, 1)
	if err := os.WriteFile(p, []byte(ex), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("LEAKGUARD_LDAP_BIND_PASSWORD", "x")
	cfg, err := Load(p)
	if err != nil {
		t.Fatal(err)
	}
	pol := cfg.ADSSP.Policies[0]
	if !cfg.ADSSP.Enabled || pol.MinLength != 12 || pol.Rules.KeyboardSequence.Value != 4 || !pol.Rules.Palindrome.Active() || pol.ActiveSinceTime().IsZero() {
		t.Fatalf("Beispiel falsch geparst: %+v", pol)
	}
}
