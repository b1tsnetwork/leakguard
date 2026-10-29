// Package blocklist leitet aus einem geleakten Kennwort Sperrlisten-Einträge ab
// (Wörterbuch-Einträge und Regex) – z. B. für ManageEngine ADSelfService Plus.
package blocklist

import (
	"regexp"
	"sort"
	"strings"
	"unicode"
)

// Pattern ist das Ergebnis der Ableitung.
type Pattern struct {
	// Words: Wortstämme für die Wörterbuch-Sperrliste (klein, ohne Ziffern/Sonderzeichen, Leetspeak aufgelöst).
	Words []string `json:"words"`
	// Regex: leetspeak-tolerantes Muster der Stämme, z. B. "h[e3]rbstl[a4@]ub".
	Regex string `json:"regex"`
}

// MinWordLen – kürzere Stämme würden zu viele legitime Kennwörter blockieren.
const MinWordLen = 4

var leet = map[rune]rune{'0': 'o', '1': 'i', '3': 'e', '4': 'a', '5': 's', '7': 't', '8': 'b', '@': 'a', '$': 's', '!': 'i', '€': 'e', '|': 'l'}

// Rückrichtung für das Regex: welche Zeichen für einen Buchstaben stehen können.
var classes = map[rune]string{'a': "a4@", 'b': "b8", 'e': "e3€", 'i': "i1!l|", 'l': "l1|i", 'o': "o0", 's': "s5$", 't': "t7", 'g': "g9"}

// Derive erzeugt die Sperrlisten-Einträge.
//
// Vorgehen: Leetspeak auflösen (nur innerhalb von Buchstabenfolgen, damit "2026" Jahreszahl bleibt),
// an Nicht-Buchstaben trennen, Stämme ab 4 Zeichen übernehmen. Zusätzlich die Verkettung aller
// Stämme, wenn sie durch Trennzeichen zerlegt war ("Herbst-Laub" -> "herbstlaub").
func Derive(pw string) Pattern {
	runes := []rune(strings.ToLower(pw))
	norm := make([]rune, len(runes))
	for i, r := range runes {
		norm[i] = r
		if m, ok := leet[r]; ok && neighbourIsLetter(runes, i) {
			norm[i] = m
		}
	}
	tokens := strings.FieldsFunc(string(norm), func(r rune) bool { return !unicode.IsLetter(r) })
	set := map[string]struct{}{}
	var kept []string
	for _, t := range tokens {
		if len([]rune(t)) >= MinWordLen {
			if _, dup := set[t]; !dup {
				set[t] = struct{}{}
				kept = append(kept, t)
			}
		}
	}
	if len(tokens) > 1 {
		joined := strings.Join(tokens, "")
		if len([]rune(joined)) >= MinWordLen {
			if _, dup := set[joined]; !dup {
				set[joined] = struct{}{}
				kept = append(kept, joined)
			}
		}
	}
	p := Pattern{Words: kept}
	var alts []string
	for _, w := range kept {
		alts = append(alts, leetRegex(w))
	}
	if len(alts) == 1 {
		p.Regex = alts[0]
	} else if len(alts) > 1 {
		p.Regex = "(?:" + strings.Join(alts, "|") + ")"
	}
	return p
}

// Normalize liefert das Kennwort klein geschrieben mit aufgelöstem Leetspeak ("P@ssw0rd" -> "password").
func Normalize(pw string) string {
	runes := []rune(strings.ToLower(pw))
	out := make([]rune, len(runes))
	for i, r := range runes {
		out[i] = r
		if m, ok := leet[r]; ok && neighbourIsLetter(runes, i) {
			out[i] = m
		}
	}
	return string(out)
}

// neighbourIsLetter: Ein Leet-Zeichen zählt nur als Buchstabe, wenn es zwischen zwei Buchstaben
// steht ("H3rbst") oder ein Wort einleitet ("@pfel"). Ein "!" am Wortende bleibt Sonderzeichen.
func neighbourIsLetter(r []rune, i int) bool {
	next := i+1 < len(r) && unicode.IsLetter(r[i+1])
	if i == 0 {
		return next
	}
	return next && unicode.IsLetter(r[i-1])
}

func leetRegex(word string) string {
	var b strings.Builder
	for _, r := range word {
		if c, ok := classes[r]; ok {
			b.WriteString("[" + regexp.QuoteMeta(c) + "]")
		} else {
			b.WriteString(regexp.QuoteMeta(string(r)))
		}
	}
	return b.String()
}

// MergeWords vereinigt Wortlisten (sortiert, eindeutig).
func MergeWords(lists ...[]string) []string {
	set := map[string]struct{}{}
	for _, l := range lists {
		for _, w := range l {
			if w = strings.TrimSpace(strings.ToLower(w)); w != "" {
				set[w] = struct{}{}
			}
		}
	}
	out := make([]string, 0, len(set))
	for w := range set {
		out = append(out, w)
	}
	sort.Strings(out)
	return out
}

// DenyRegex baut ein Regex, das nur Kennwörter zulässt, die KEINEN der Stämme enthalten.
// Für Produkte, deren Regex-Regel ein "muss passen"-Muster erwartet (z. B. ADSelfService Plus).
func DenyRegex(words []string) string {
	if len(words) == 0 {
		return ""
	}
	alts := make([]string, len(words))
	for i, w := range words {
		alts[i] = leetRegex(w)
	}
	return "^(?i)(?!.*(?:" + strings.Join(alts, "|") + ")).*$"
}
