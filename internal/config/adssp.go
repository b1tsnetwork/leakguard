package config

import (
	"fmt"
	"path/filepath"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

// ADSSP bildet die Kennwortrichtlinien des ManageEngine ADSelfService Plus "Password Policy Enforcer" nach.
// ADSSP speichert diese Regeln in seiner eigenen Datenbank (nicht im AD), deshalb werden sie hier gepflegt.
type ADSSP struct {
	Enabled  bool          `yaml:"enabled"`
	Policies []ADSSPPolicy `yaml:"policies"`
}

type ADSSPPolicy struct {
	Name    string `yaml:"name"`
	ApplyTo struct {
		OUs    []string `yaml:"ous"`
		Groups []string `yaml:"groups"`
	} `yaml:"apply_to"`

	// Seit wann die Richtlinie aktiv ist (YYYY-MM-DD). Kennwörter, die davor gesetzt wurden, können sie verletzen.
	ActiveSince string `yaml:"active_since"`
	// "Enforce this policy in GINA/CP (Ctrl+Alt+Del) screen and ADUC password resets through Password Sync Agent"
	NativeEnforcement bool `yaml:"native_enforcement"`

	// Länge (immer Pflicht)
	MinLength int `yaml:"min_length"`
	MaxLength int `yaml:"max_length"`

	// "Password must satisfy at least <n> of the above complexity requirements" (0 = alle)
	SatisfyAtLeast int `yaml:"satisfy_at_least"`
	// "Override all complexity rules if password length is at least <n>" (0 = aus)
	OverrideComplexityIfLengthAtLeast int `yaml:"override_complexity_if_length_at_least"`

	Rules ADSSPRules `yaml:"rules"`

	activeSince time.Time
}

func (p ADSSPPolicy) ActiveSinceTime() time.Time { return p.activeSince }

// ADSSPRules – jede Regel ist einzeln aktivierbar. Kurzform: "min_uppercase: 1";
// Langform: "min_uppercase: {value: 1, mandatory: true}".
// min_*-Regeln zählen zu den Komplexitätsanforderungen ("satisfy at least <n>"), außer mandatory: true.
// Alle anderen Regeln sind Pflicht, außer complexity: true.
type ADSSPRules struct {
	// Zeichen – Mindestanzahl
	MinUppercase Rule `yaml:"min_uppercase"`
	MinLowercase Rule `yaml:"min_lowercase"`
	MinLetters   Rule `yaml:"min_letters"`
	MinNumeric   Rule `yaml:"min_numeric"`
	MinSpecial   Rule `yaml:"min_special"`
	MinUnicode   Rule `yaml:"min_unicode"`

	// Zeichen einschränken – Höchstanzahl
	MaxNumeric Rule `yaml:"max_numeric"`
	MaxSpecial Rule `yaml:"max_special"`
	MaxUnicode Rule `yaml:"max_unicode"`
	// Verbotene Zeichen, z. B. " <>&"
	DisallowedCharacters Rule `yaml:"disallowed_characters"`
	// Darf nicht beginnen/enden mit: Klassen kommagetrennt (numeric, special, unicode, uppercase, lowercase)
	MustNotStartWith Rule `yaml:"must_not_start_with"`
	MustNotEndWith   Rule `yaml:"must_not_end_with"`

	// Wiederholung
	MaxRepeatedCharacters Rule `yaml:"max_repeated_characters"` // höchstens n gleiche Zeichen hintereinander
	MaxUsernameSequence   Rule `yaml:"max_username_sequence"`   // keine Folge von n Zeichen aus dem Benutzernamen
	NoUsername            Rule `yaml:"no_username"`             // Benutzername darf nicht enthalten sein
	NoDisplayName         Rule `yaml:"no_display_name"`         // Namensbestandteile (≥ 3 Zeichen) nicht enthalten

	// Muster
	KeyboardSequence Rule `yaml:"keyboard_sequence"` // keine Tastatur-/Alphabet-/Zahlenfolge der Länge n (qwertz, qwerty, abc, 123)
	Dictionary       Rule `yaml:"dictionary"`        // text: Datei (ein Wort pro Zeile), value: Mindestwortlänge (Standard 4)
	Palindrome       Rule `yaml:"palindrome"`        // Kennwort darf kein Palindrom sein
	Regex            Rule `yaml:"regex"`             // text: Muster, das passen MUSS (Java/.NET-Syntax inkl. Lookahead)

	// Kompromittierte Kennwörter (Have I Been Pwned) – benötigt hibp.enabled
	Pwned Rule `yaml:"pwned"`
}

// Rule ist eine einzelne ADSSP-Regel.
type Rule struct {
	Value      int    `yaml:"value"`
	Text       string `yaml:"text"`
	On         bool   `yaml:"enabled"`
	Mandatory  bool   `yaml:"mandatory"`  // min_*-Regeln: Pflicht statt Komplexitätsanforderung
	Complexity bool   `yaml:"complexity"` // übrige Regeln: zählt zu satisfy_at_least statt Pflicht
}

func (r Rule) Active() bool { return r.Value > 0 || r.Text != "" || r.On }

// UnmarshalYAML erlaubt Kurzformen: Zahl, true/false oder Text.
func (r *Rule) UnmarshalYAML(n *yaml.Node) error {
	if n.Kind == yaml.ScalarNode {
		switch n.Tag {
		case "!!int":
			r.On = true // explizit gesetzt – auch 0 ist gültig (z. B. max_unicode: 0)
			return n.Decode(&r.Value)
		case "!!bool":
			return n.Decode(&r.On)
		case "!!null":
			return nil
		default:
			return n.Decode(&r.Text)
		}
	}
	type plain Rule
	var p plain
	if err := n.Decode(&p); err != nil {
		return err
	}
	*r = Rule(p)
	hasEnabled := false
	for i := 0; i+1 < len(n.Content); i += 2 {
		hasEnabled = hasEnabled || n.Content[i].Value == "enabled"
	}
	if !hasEnabled { // Langform ohne "enabled" gilt als aktiviert
		r.On = true
	}
	return nil
}

func (a *ADSSP) validate(base string) []string {
	if !a.Enabled {
		return nil
	}
	var errs []string
	if len(a.Policies) == 0 {
		errs = append(errs, "adssp.enabled, aber keine adssp.policies definiert")
	}
	for i := range a.Policies {
		p := &a.Policies[i]
		if p.Name == "" {
			p.Name = fmt.Sprintf("Richtlinie %d", i+1)
		}
		if p.ActiveSince != "" {
			t, err := time.ParseInLocation("2006-01-02", strings.TrimSpace(p.ActiveSince), time.Local)
			if err != nil {
				errs = append(errs, fmt.Sprintf("adssp %q: active_since muss YYYY-MM-DD sein", p.Name))
			}
			p.activeSince = t
		}
		if p.MaxLength > 0 && p.MaxLength < p.MinLength {
			errs = append(errs, fmt.Sprintf("adssp %q: max_length < min_length", p.Name))
		}
		if f := p.Rules.Dictionary.Text; f != "" && !filepath.IsAbs(f) && base != "" {
			p.Rules.Dictionary.Text = filepath.Join(base, f)
		}
	}
	return errs
}
