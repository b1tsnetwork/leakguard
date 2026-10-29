// Package policy prüft ein Kennwort gegen die (AD-)Kennwortrichtlinie.
package policy

import (
	"bufio"
	"fmt"
	"os"
	"strings"
	"unicode"
	"unicode/utf8"

	"leakguard/internal/model"
)

type Rules struct {
	MinLength     int
	Complexity    bool
	MinCategories int
	Blocklist     map[string]struct{}
	Source        string
}

// LoadBlocklist kombiniert Liste aus der Konfiguration und optionaler Datei (ein Eintrag pro Zeile).
func LoadBlocklist(list []string, file string) (map[string]struct{}, error) {
	m := map[string]struct{}{}
	for _, w := range list {
		if w = strings.TrimSpace(w); w != "" {
			m[strings.ToLower(w)] = struct{}{}
		}
	}
	if file == "" {
		return m, nil
	}
	f, err := os.Open(file)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		w := strings.TrimSpace(sc.Text())
		if w != "" && !strings.HasPrefix(w, "#") {
			m[strings.ToLower(w)] = struct{}{}
		}
	}
	return m, sc.Err()
}

// Check bildet die Windows-Komplexitätsregeln nach:
//   - Mindestlänge
//   - enthält nicht den sAMAccountName (ab 3 Zeichen)
//   - enthält keine Teile des Anzeigenamens (Token ab 3 Zeichen; Trenner , . - _ # Tab Leerzeichen)
//   - mindestens N von 5 Zeichenkategorien (Groß, Klein, Ziffer, Sonderzeichen, sonstige Unicode-Buchstaben)
func Check(pw string, r Rules, sam, displayName string) model.PolicyResult {
	res := model.PolicyResult{Source: r.Source, MinLength: r.MinLength}
	add := func(rule string, ok bool, detail string) {
		res.Findings = append(res.Findings, model.Finding{Rule: rule, OK: ok, Detail: detail})
	}
	n := utf8.RuneCountInString(pw)
	add("Mindestlänge", n >= r.MinLength, fmt.Sprintf("%d Zeichen, gefordert mindestens %d", n, r.MinLength))

	if r.Complexity {
		lpw := strings.ToLower(pw)
		if s := strings.ToLower(sam); utf8.RuneCountInString(s) >= 3 {
			contains := strings.Contains(lpw, s)
			add("Kein Benutzername", !contains, map[bool]string{true: "enthält den Kontonamen", false: "enthält den Kontonamen nicht"}[contains])
		}
		var hit []string
		for _, tok := range strings.FieldsFunc(strings.ToLower(displayName), func(r rune) bool {
			return strings.ContainsRune(",.-_# \t", r)
		}) {
			if utf8.RuneCountInString(tok) >= 3 && strings.Contains(lpw, tok) {
				hit = append(hit, tok)
			}
		}
		if displayName != "" {
			d := "enthält keine Namensbestandteile"
			if len(hit) > 0 {
				d = "enthält Namensbestandteil(e): " + strings.Join(hit, ", ")
			}
			add("Kein Namensbestandteil", len(hit) == 0, d)
		}
		cats, names := categories(pw)
		add("Komplexität", cats >= r.MinCategories, fmt.Sprintf("%d von 5 Kategorien (%s), gefordert %d", cats, strings.Join(names, ", "), r.MinCategories))
	}

	if len(r.Blocklist) > 0 {
		_, blocked := r.Blocklist[strings.ToLower(pw)]
		add("Sperrliste", !blocked, map[bool]string{true: "steht auf der Sperrliste", false: "nicht auf der Sperrliste"}[blocked])
	}

	res.Compliant = true
	for _, f := range res.Findings {
		if !f.OK {
			res.Compliant = false
		}
	}
	return res
}

func categories(pw string) (int, []string) {
	var up, lo, dg, sp, uni bool
	for _, r := range pw {
		switch {
		case unicode.IsUpper(r):
			up = true
		case unicode.IsLower(r):
			lo = true
		case unicode.IsDigit(r):
			dg = true
		case unicode.IsLetter(r): // Buchstaben ohne Groß/Klein (z. B. CJK)
			uni = true
		default:
			sp = true
		}
	}
	var names []string
	for _, c := range []struct {
		ok   bool
		name string
	}{{up, "Groß"}, {lo, "Klein"}, {dg, "Ziffer"}, {sp, "Sonderzeichen"}, {uni, "Unicode"}} {
		if c.ok {
			names = append(names, c.name)
		}
	}
	return len(names), names
}

// Mask liefert eine Wiedererkennungs-Maske, z. B. "S••••••••3".
func Mask(pw string) string {
	r := []rune(pw)
	switch {
	case len(r) == 0:
		return ""
	case len(r) <= 4:
		return strings.Repeat("•", len(r))
	default:
		return string(r[0]) + strings.Repeat("•", len(r)-2) + string(r[len(r)-1])
	}
}
