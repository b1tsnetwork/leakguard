package policy

import "testing"

func TestCheck(t *testing.T) {
	r := Rules{MinLength: 12, Complexity: true, MinCategories: 3, Blocklist: map[string]struct{}{"sommer2026!sommer": {}}}
	cases := []struct {
		pw, sam, disp string
		want          bool
	}{
		{"Sommer2026!", "mmuster", "Max Muster", false},       // zu kurz
		{"KaffeeTasse-42x", "mmuster", "Max Muster", true},    // ok
		{"kaffeetasse4242", "mmuster", "Max Muster", false},   // nur 2 Kategorien
		{"Muster-Kaffee-42", "mmuster", "Max Muster", false},  // Namensbestandteil "muster"
		{"Xmmuster!2026abc", "mmuster", "Max Muster", false},  // enthält Kontonamen (und Namen)
		{"Sommer2026!Sommer", "mmuster", "Max Muster", false}, // Sperrliste
		{"Ma-Kaffee-Tasse-1", "mmuster", "Ma Lu", true},       // Token < 3 Zeichen werden ignoriert
		{"ÄpfelBirnen2026x", "jdoe", "John Doe", true},        // Unicode-Großbuchstabe
	}
	for _, c := range cases {
		got := Check(c.pw, r, c.sam, c.disp)
		if got.Compliant != c.want {
			t.Errorf("%q: compliant=%v, want %v (%+v)", c.pw, got.Compliant, c.want, got.Findings)
		}
	}
}

func TestMask(t *testing.T) {
	if m := Mask("Geheim123!"); m != "G••••••••!" {
		t.Fatalf("mask = %q", m)
	}
	if m := Mask("abc"); m != "•••" {
		t.Fatalf("mask short = %q", m)
	}
}
