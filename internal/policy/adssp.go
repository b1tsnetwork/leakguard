package policy

import (
	"bufio"
	"fmt"
	"os"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/dlclark/regexp2"

	"leakguard/internal/blocklist"
	"leakguard/internal/config"
	"leakguard/internal/model"
)

// ADSSPChecker prüft Kennwörter gegen eine ManageEngine-ADSelfService-Plus-Richtlinie.
type ADSSPChecker struct {
	Policy config.ADSSPPolicy
	dict   []string
	regex  *regexp2.Regexp
}

func NewADSSPChecker(p config.ADSSPPolicy) (*ADSSPChecker, error) {
	c := &ADSSPChecker{Policy: p}
	if f := p.Rules.Dictionary.Text; f != "" {
		words, err := loadWords(f)
		if err != nil {
			return nil, fmt.Errorf("adssp %q: wörterbuch: %w", p.Name, err)
		}
		c.dict = words
	}
	if r := p.Rules.Regex.Text; r != "" {
		re, err := regexp2.Compile(r, regexp2.None)
		if err != nil {
			return nil, fmt.Errorf("adssp %q: regex: %w", p.Name, err)
		}
		re.MatchTimeout = time.Second
		c.regex = re
	}
	return c, nil
}

func loadWords(path string) ([]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var out []string
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		w := strings.ToLower(strings.TrimSpace(strings.TrimPrefix(sc.Text(), "\ufeff")))
		if w != "" && !strings.HasPrefix(w, "#") {
			out = append(out, w)
		}
	}
	return out, sc.Err()
}

type counts struct{ upper, lower, letters, numeric, special, unicode int }

// Zeichenklassen wie in ADSSP: Unicode = Buchstaben außerhalb von ASCII (z. B. ä, ß, é).
func classify(r rune) string {
	switch {
	case r > unicode.MaxASCII && unicode.IsLetter(r):
		return "unicode"
	case r >= 'A' && r <= 'Z':
		return "uppercase"
	case r >= 'a' && r <= 'z':
		return "lowercase"
	case r >= '0' && r <= '9':
		return "numeric"
	default:
		return "special"
	}
}

func count(pw string) counts {
	var c counts
	for _, r := range pw {
		switch classify(r) {
		case "uppercase":
			c.upper++
			c.letters++
		case "lowercase":
			c.lower++
			c.letters++
		case "numeric":
			c.numeric++
		case "unicode":
			c.unicode++
			c.letters++
			if unicode.IsUpper(r) {
				c.upper++
			} else if unicode.IsLower(r) {
				c.lower++
			}
		default:
			c.special++
		}
	}
	return c
}

var keyboardRows = []string{
	"^1234567890ß´", "qwertzuiopü+", "asdfghjklöä#", "<yxcvbnm,.-", // QWERTZ (DE)
	"`1234567890-=", "qwertyuiop[]", "asdfghjkl;'", "zxcvbnm,./", // QWERTY (US)
	"qaywsxedcrfvtgbzhnujmik,ol.pö-",                          // Spalten QWERTZ
	"abcdefghijklmnopqrstuvwxyz", "01234567890", "7894561230", // Alphabet, Ziffern, Ziffernblock
}

// sequence liefert die erste Tastatur-/Alphabet-/Zahlenfolge der Länge n (vorwärts oder rückwärts).
func sequence(pw string, n int) string {
	lp := []rune(strings.ToLower(pw))
	if n < 2 || len(lp) < n {
		return ""
	}
	for _, row := range keyboardRows {
		rr := []rune(row)
		rev := make([]rune, len(rr))
		for i, r := range rr {
			rev[len(rr)-1-i] = r
		}
		for _, line := range []string{string(rr), string(rev)} {
			for i := 0; i+n <= len(lp); i++ {
				if sub := string(lp[i : i+n]); strings.Contains(line, sub) {
					return sub
				}
			}
		}
	}
	return ""
}

func maxRun(pw string) (int, string) {
	best, cur := 0, 0
	var prev, bestR rune
	for i, r := range []rune(strings.ToLower(pw)) {
		if i > 0 && r == prev {
			cur++
		} else {
			cur = 1
		}
		if cur > best {
			best, bestR = cur, r
		}
		prev = r
	}
	return best, string(bestR)
}

func classesOf(spec string) []string {
	var out []string
	for _, c := range strings.Split(strings.ToLower(spec), ",") {
		if c = strings.TrimSpace(c); c != "" {
			out = append(out, c)
		}
	}
	return out
}

// Check prüft das Kennwort. hibpCount < 0 bedeutet "nicht geprüft".
func (c *ADSSPChecker) Check(pw, sam, displayName string, hibpCount int) model.ADSSPResult {
	p := c.Policy
	r := p.Rules
	res := model.ADSSPResult{Policy: p.Name, ActiveSince: p.ActiveSinceTime(), Native: p.NativeEnforcement}
	n := utf8.RuneCountInString(pw)
	cnt := count(pw)
	// Mindestanzahl-Regeln (min_*) sind Komplexitätsanforderungen, außer mandatory: true.
	// Alle anderen Regeln sind Pflicht, außer complexity: true.
	add := func(mandatory bool, name string, ok bool, detail string) {
		res.Findings = append(res.Findings, model.Finding{Rule: name, OK: ok, Detail: detail, Mandatory: mandatory})
	}

	if p.MinLength > 0 {
		add(true, "Mindestlänge", n >= p.MinLength, fmt.Sprintf("%d Zeichen, mindestens %d", n, p.MinLength))
	}
	if p.MaxLength > 0 {
		add(true, "Maximallänge", n <= p.MaxLength, fmt.Sprintf("%d Zeichen, höchstens %d", n, p.MaxLength))
	}

	minRule := func(rule config.Rule, name string, have int) {
		if rule.Value > 0 {
			add(rule.Mandatory, name, have >= rule.Value, fmt.Sprintf("%d vorhanden, mindestens %d", have, rule.Value))
		}
	}
	maxRule := func(rule config.Rule, name string, have int) {
		if rule.Active() {
			add(!rule.Complexity, name, have <= rule.Value, fmt.Sprintf("%d vorhanden, höchstens %d", have, rule.Value))
		}
	}
	minRule(r.MinUppercase, "Großbuchstaben", cnt.upper)
	minRule(r.MinLowercase, "Kleinbuchstaben", cnt.lower)
	minRule(r.MinLetters, "Buchstaben", cnt.letters)
	minRule(r.MinNumeric, "Ziffern", cnt.numeric)
	minRule(r.MinSpecial, "Sonderzeichen", cnt.special)
	minRule(r.MinUnicode, "Unicode-Zeichen", cnt.unicode)
	maxRule(r.MaxNumeric, "Max. Ziffern", cnt.numeric)
	maxRule(r.MaxSpecial, "Max. Sonderzeichen", cnt.special)
	maxRule(r.MaxUnicode, "Max. Unicode-Zeichen", cnt.unicode)

	if set := r.DisallowedCharacters.Text; set != "" {
		var hit []string
		for _, ch := range pw {
			if strings.ContainsRune(set, ch) {
				hit = append(hit, string(ch))
			}
		}
		add(!r.DisallowedCharacters.Complexity, "Verbotene Zeichen", len(hit) == 0, map[bool]string{true: "keine enthalten", false: "enthält " + strings.Join(hit, " ")}[len(hit) == 0])
	}
	edge := func(rule config.Rule, name string, ch rune) {
		if rule.Text == "" || n == 0 {
			return
		}
		cl := classify(ch)
		bad := false
		for _, want := range classesOf(rule.Text) {
			bad = bad || want == cl
		}
		add(!rule.Complexity, name, !bad, fmt.Sprintf("Zeichen %q ist %s (verboten: %s)", ch, cl, rule.Text))
	}
	if n > 0 {
		runes := []rune(pw)
		edge(r.MustNotStartWith, "Erstes Zeichen", runes[0])
		edge(r.MustNotEndWith, "Letztes Zeichen", runes[len(runes)-1])
	}

	if r.MaxRepeatedCharacters.Value > 0 {
		run, ch := maxRun(pw)
		add(!r.MaxRepeatedCharacters.Complexity, "Wiederholte Zeichen", run <= r.MaxRepeatedCharacters.Value,
			fmt.Sprintf("längste Wiederholung %d× %q, höchstens %d", run, ch, r.MaxRepeatedCharacters.Value))
	}
	lpw := strings.ToLower(pw)
	lsam := strings.ToLower(sam)
	if v := r.MaxUsernameSequence.Value; v > 0 && sam != "" {
		hit := ""
		us := []rune(lsam)
		for i := 0; i+v <= len(us) && hit == ""; i++ {
			if sub := string(us[i : i+v]); strings.Contains(lpw, sub) {
				hit = sub
			}
		}
		add(!r.MaxUsernameSequence.Complexity, "Folge aus Benutzername", hit == "",
			map[bool]string{true: fmt.Sprintf("keine Folge von %d Zeichen aus %q", v, sam), false: fmt.Sprintf("enthält %q aus dem Benutzernamen", hit)}[hit == ""])
	}
	if r.NoUsername.Active() && sam != "" {
		ok := !strings.Contains(lpw, lsam)
		add(!r.NoUsername.Complexity, "Benutzername", ok, map[bool]string{true: "nicht enthalten", false: "enthält den Benutzernamen"}[ok])
	}
	if r.NoDisplayName.Active() && displayName != "" {
		var hit []string
		for _, tok := range strings.FieldsFunc(strings.ToLower(displayName), func(r rune) bool { return strings.ContainsRune(",.-_# \t", r) }) {
			if utf8.RuneCountInString(tok) >= 3 && strings.Contains(lpw, tok) {
				hit = append(hit, tok)
			}
		}
		add(!r.NoDisplayName.Complexity, "Namensbestandteile", len(hit) == 0, map[bool]string{true: "nicht enthalten", false: "enthält " + strings.Join(hit, ", ")}[len(hit) == 0])
	}

	if v := r.KeyboardSequence.Value; v > 0 {
		seq := sequence(pw, v)
		add(!r.KeyboardSequence.Complexity, "Tastaturfolgen", seq == "", map[bool]string{true: fmt.Sprintf("keine Folge ab %d Zeichen", v), false: fmt.Sprintf("enthält Folge %q", seq)}[seq == ""])
	}
	if r.Dictionary.Active() && len(c.dict) > 0 {
		minLen := r.Dictionary.Value
		if minLen <= 0 {
			minLen = 4
		}
		norm := blocklist.Normalize(pw)
		hit := ""
		for _, w := range c.dict {
			if utf8.RuneCountInString(w) >= minLen && (strings.Contains(lpw, w) || strings.Contains(norm, w)) {
				hit = w
				break
			}
		}
		add(!r.Dictionary.Complexity, "Wörterbuch", hit == "", map[bool]string{true: fmt.Sprintf("kein Wörterbuchwort (%d Einträge)", len(c.dict)), false: fmt.Sprintf("enthält Wörterbuchwort %q", hit)}[hit == ""])
	}
	if r.Palindrome.Active() && n > 1 {
		rr := []rune(lpw)
		pal := true
		for i := 0; i < len(rr)/2; i++ {
			pal = pal && rr[i] == rr[len(rr)-1-i]
		}
		add(!r.Palindrome.Complexity, "Palindrom", !pal, map[bool]string{true: "ist ein Palindrom", false: "kein Palindrom"}[pal])
	}
	if c.regex != nil {
		ok, err := c.regex.MatchString(pw)
		d := "passt auf " + r.Regex.Text
		if !ok {
			d = "passt NICHT auf " + r.Regex.Text
		}
		if err != nil {
			d = "Regex-Fehler: " + err.Error()
		}
		add(!r.Regex.Complexity, "Regex", ok && err == nil, d)
	}
	if r.Pwned.Active() {
		switch {
		case hibpCount < 0:
			add(!r.Pwned.Complexity, "Kompromittiert (HIBP)", true, "nicht geprüft (hibp.enabled = false oder Fehler)")
		default:
			add(!r.Pwned.Complexity, "Kompromittiert (HIBP)", hibpCount == 0, fmt.Sprintf("%d Treffer", hibpCount))
		}
	}

	// Bewertung: Pflichtregeln müssen alle erfüllt sein, von den Komplexitätsregeln mindestens satisfy_at_least.
	mandatoryOK := true
	for _, f := range res.Findings {
		if f.Mandatory {
			mandatoryOK = mandatoryOK && f.OK
		} else {
			res.Total++
			if f.OK {
				res.Satisfied++
			}
		}
	}
	res.Required = res.Total
	if p.SatisfyAtLeast > 0 && p.SatisfyAtLeast < res.Total {
		res.Required = p.SatisfyAtLeast
	}
	if p.OverrideComplexityIfLengthAtLeast > 0 && n >= p.OverrideComplexityIfLengthAtLeast {
		res.Overridden = true
	}
	res.Compliant = mandatoryOK && (res.Overridden || res.Satisfied >= res.Required)
	return res
}
