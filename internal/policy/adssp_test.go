package policy

import (
	"os"
	"path/filepath"
	"testing"

	"gopkg.in/yaml.v3"

	"leakguard/internal/config"
)

const testPolicy = `
name: Standard
min_length: 12
satisfy_at_least: 3
override_complexity_if_length_at_least: 20
rules:
  min_uppercase: 1
  min_lowercase: 1
  min_numeric: 1
  min_special: 1
  max_repeated_characters: 2
  max_username_sequence: 3
  keyboard_sequence: 4
  palindrome: true
  regex: "^(?!.*(?i:firma)).*$"
  max_unicode: 0
  must_not_start_with: "numeric"
`

func TestADSSP(t *testing.T) {
	var p config.ADSSPPolicy
	if err := yaml.Unmarshal([]byte(testPolicy), &p); err != nil {
		t.Fatal(err)
	}
	if !p.Rules.MaxUnicode.Active() || p.Rules.MaxUnicode.Value != 0 {
		t.Fatal("max_unicode: 0 muss aktiv sein")
	}
	ck, err := NewADSSPChecker(p)
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		pw   string
		want bool
		why  string
	}{
		{"Sommerwiese2026", true, "3 von 4 Komplexitätsregeln"},
		{"sommerwiese2026", false, "nur 2 von 4"},
		{"Qwertz-Haus77", false, "Tastaturfolge"},
		{"Haaaus-Garten1", false, "3 gleiche Zeichen"},
		{"Mmus-Garten1x", false, "Folge aus Benutzername"},
		{"Firma-Haus123!", false, "Regex mit Lookahead"},
		{"dies ist eine lange passphrase", true, "Komplexität durch Länge aufgehoben"},
		{"Gärten-Haus12", false, "max_unicode 0"},
		{"1Sommerwiese!", false, "beginnt mit Ziffer"},
		{"Abc1!xx!1cbA", false, "Palindrom (case-insensitiv) bzw. Folge"},
	}
	for _, c := range cases {
		r := ck.Check(c.pw, "mmuster", "Max Muster", -1)
		if r.Compliant != c.want {
			t.Errorf("%q (%s): compliant=%v, want %v\n%+v", c.pw, c.why, r.Compliant, c.want, r.Findings)
		}
	}
}

func TestADSSPDictionary(t *testing.T) {
	dir := t.TempDir()
	f := filepath.Join(dir, "dict.txt")
	_ = os.WriteFile(f, []byte("\ufeffpasswort\n# Kommentar\nsommer\n"), 0o600)
	p := config.ADSSPPolicy{Name: "D", Rules: config.ADSSPRules{Dictionary: config.Rule{Text: f}}}
	ck, err := NewADSSPChecker(p)
	if err != nil {
		t.Fatal(err)
	}
	if ck.Check("P@ssw0rt-2026", "", "", -1).Compliant {
		t.Error("Leetspeak-Variante von 'passwort' muss erkannt werden")
	}
	if !ck.Check("Gartenhaus-2026", "", "", -1).Compliant {
		t.Error("kein Wörterbuchwort -> konform")
	}
}

func TestSequence(t *testing.T) {
	for pw, want := range map[string]bool{"xx4321yy": true, "asdf": true, "Ztrewq": true, "Haus7Baum": false, "pökl": false} {
		if got := sequence(pw, 4) != ""; got != want {
			t.Errorf("%q: %v, want %v", pw, got, want)
		}
	}
}
