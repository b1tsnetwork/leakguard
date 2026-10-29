package blocklist

import (
	"reflect"
	"regexp"
	"testing"
)

func TestDerive(t *testing.T) {
	cases := map[string][]string{
		"Herbstlaub#2026": {"herbstlaub"},
		"H3rbst-L4ub!99":  {"herbst", "laub", "herbstlaub"},
		"P@ssw0rd2024":    {"password"},
		"Sommer2026!":     {"sommer"},
		"abc123!":         nil,
		"Ma$ch1ne_Kaffee": {"maschine", "kaffee", "maschinekaffee"},
	}
	for pw, want := range cases {
		got := Derive(pw).Words
		if len(got) == 0 && len(want) == 0 {
			continue
		}
		if !reflect.DeepEqual(got, want) {
			t.Errorf("%q: %v, want %v", pw, got, want)
		}
	}
}

func TestRegex(t *testing.T) {
	re := regexp.MustCompile("(?i)" + Derive("Herbstlaub#2026").Regex)
	for _, s := range []string{"herbstlaub", "H3rbstl4ub", "xxHERBSTL@UB99"} {
		if !re.MatchString(s) {
			t.Errorf("Regex sollte %q treffen", s)
		}
	}
	// DenyRegex nutzt Lookahead (Java/.NET) – Go-RE2 kann das nicht, daher nur Syntaxprüfung des Kerns.
	if DenyRegex([]string{"laub"}) != `^(?i)(?!.*(?:[l1\|i][a4@]u[b8])).*$` {
		t.Error(DenyRegex([]string{"laub"}))
	}
}
