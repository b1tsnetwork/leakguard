// Package engine führt die Prüfungen eines Falls durch und bewertet das Risiko.
package engine

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"leakguard/internal/blocklist"
	"leakguard/internal/config"
	"leakguard/internal/hibp"
	"leakguard/internal/ldapx"
	"leakguard/internal/model"
	"leakguard/internal/policy"
	"leakguard/internal/store"
)

type Engine struct {
	cfg       *config.Config
	ldap      *ldapx.Client
	hibp      *hibp.Client
	store     *store.Store
	blocklist map[string]struct{}
	adssp     []*policy.ADSSPChecker
}

func New(cfg *config.Config, l *ldapx.Client, st *store.Store) (*Engine, error) {
	bl, err := policy.LoadBlocklist(cfg.Policy.Blocklist, cfg.Policy.BlocklistFile)
	if err != nil {
		return nil, fmt.Errorf("sperrliste: %w", err)
	}
	e := &Engine{cfg: cfg, ldap: l, store: st, blocklist: bl}
	if cfg.ADSSP.Enabled {
		for _, p := range cfg.ADSSP.Policies {
			ck, err := policy.NewADSSPChecker(p)
			if err != nil {
				return nil, err
			}
			e.adssp = append(e.adssp, ck)
		}
	}
	if cfg.HIBP.Enabled {
		e.hibp = hibp.New(cfg.HIBP.URL, cfg.HIBP.Timeout())
	}
	return e, nil
}

func (e *Engine) BindTestAllowed() bool { return e.cfg.LDAP.AllowBindTest && e.ldap.Enabled() }

type Input struct {
	CaseNumber string
	Identifier string
	Password   string
	Source     string
	LeakDate   time.Time
	BindTest   bool
	Actor      string
}

// HMAC erzeugt einen nicht umkehrbaren Fingerabdruck des Kennworts zur Wiederholungserkennung.
func (e *Engine) HMAC(pw string) string {
	m := hmac.New(sha256.New, []byte(e.cfg.Secret))
	m.Write([]byte(pw))
	return hex.EncodeToString(m.Sum(nil))
}

// Run führt alle Prüfungen durch.
func (e *Engine) Run(ctx context.Context, in Input, excludeCaseID int64) model.Checks {
	ch := model.Checks{RunAt: time.Now(), RunBy: in.Actor}

	// 1) AD-Konto ermitteln
	if e.ldap.Enabled() {
		users, err := e.ldap.FindUsers(in.Identifier)
		switch {
		case err != nil:
			ch.LDAPError = err.Error()
			slog.Warn("ldap lookup", "err", err)
		case len(users) == 1:
			u := users[0]
			ch.User = &u
		case len(users) > 1:
			ch.Candidates = users
		}
	} else {
		ch.LDAPError = "LDAP nicht konfiguriert"
	}

	// 2) Kennwortrichtlinie
	rules := policy.Rules{MinLength: e.cfg.Policy.MinLength, Complexity: e.cfg.Policy.Complexity,
		MinCategories: e.cfg.Policy.MinCategories, Blocklist: e.blocklist, Source: "Konfiguration"}
	if e.cfg.Policy.ReadFromAD && e.ldap.Enabled() {
		dn := ""
		if ch.User != nil {
			dn = ch.User.DN
		}
		if p, err := e.ldap.EffectivePolicy(dn); err == nil {
			rules.MinLength, rules.Complexity, rules.Source = p.MinLength, p.Complexity, p.Source
		} else {
			ch.Warnings = append(ch.Warnings, "AD-Kennwortrichtlinie nicht lesbar, verwende Konfiguration: "+err.Error())
		}
	}
	sam, disp := "", ""
	if ch.User != nil {
		sam, disp = ch.User.SAM, ch.User.DisplayName
	} else if !strings.Contains(in.Identifier, "@") {
		sam = in.Identifier
	}
	ch.Policy = policy.Check(in.Password, rules, sam, disp)

	// 3) Pwned Passwords (k-Anonymität)
	if e.hibp != nil {
		ch.HIBPEnabled = true
		hctx, cancel := context.WithTimeout(ctx, e.cfg.HIBP.Timeout())
		n, err := e.hibp.Count(hctx, in.Password)
		cancel()
		if err != nil {
			ch.HIBPError = err.Error()
		} else {
			ch.HIBPCount = n
		}
	}

	// 4) Optional: Bind-Test mit dem geleakten Kennwort
	if in.BindTest && e.BindTestAllowed() && ch.User != nil {
		if ch.User.LockedOut {
			ch.Warnings = append(ch.Warnings, "Bind-Test übersprungen: Konto ist gesperrt")
		} else {
			ch.BindTested = true
			ok, txt, err := e.ldap.TestBind(ch.User.DN, in.Password)
			if err != nil {
				ch.BindResult = "Fehler: " + err.Error()
				ch.BindTested = false
				ch.Warnings = append(ch.Warnings, "Bind-Test fehlgeschlagen: "+err.Error())
			} else {
				ch.BindValid, ch.BindResult = ok, txt
			}
		}
	}

	// 5) Kennwort nach Leak geändert?
	if ch.User != nil && !in.LeakDate.IsZero() && !ch.User.PwdLastSet.IsZero() {
		after := ch.User.PwdLastSet.After(in.LeakDate)
		ch.PwdChangedAfterLeak = &after
	}

	// 6) Wiederholungen
	if e.store != nil {
		user := sam
		if user == "" {
			user = in.Identifier
		}
		if rec, err := e.store.FindRecurrences(ctx, excludeCaseID, user, e.HMAC(in.Password)); err == nil {
			ch.Recurrences = rec
		}
	}

	// 7) ManageEngine ADSelfService Plus
	if ck, note := e.adsspFor(ch.User); ck != nil {
		hc := -1
		if ch.HIBPEnabled && ch.HIBPError == "" {
			hc = ch.HIBPCount
		}
		r := ck.Check(in.Password, sam, disp, hc)
		r.Note = note
		ch.ADSSP = &r
	} else if note != "" {
		ch.Warnings = append(ch.Warnings, note)
	}

	bp := blocklist.Derive(in.Password)
	ch.Blocklist = model.BlockPattern{Words: bp.Words, Regex: bp.Regex}

	assess(&ch, in)
	return ch
}

var riskOrder = []string{model.RiskInfo, model.RiskLow, model.RiskMedium, model.RiskHigh, model.RiskCritical}

func raise(r string) string {
	for i, v := range riskOrder {
		if v == r && i < len(riskOrder)-1 {
			return riskOrder[i+1]
		}
	}
	return r
}

func assess(ch *model.Checks, in Input) {
	add := func(s string, a ...any) { ch.Reasons = append(ch.Reasons, fmt.Sprintf(s, a...)) }
	u := ch.User

	// ADSSP-Verstoß schließt das aktuelle AD-Kennwort nur aus, wenn die Richtlinie auch nativ (Strg+Alt+Entf/ADUC)
	// durchgesetzt wird und das Kennwort NACH der Aktivierung gesetzt wurde.
	a := ch.ADSSP
	adsspViolated := a != nil && !a.Compliant && ch.Policy.Compliant
	if adsspViolated && u != nil && a.Native && !a.ActiveSince.IsZero() && !u.PwdLastSet.IsZero() && u.PwdLastSet.After(a.ActiveSince) {
		a.Decisive = true
	}
	ch.PossibleADPassword = ch.Policy.Compliant && (a == nil || !a.Decisive)

	switch {
	case u == nil && len(ch.Candidates) > 1:
		ch.Risk = model.RiskInfo
		add("Mehrere AD-Konten gefunden (%d) – bitte eindeutiges Konto auswählen", len(ch.Candidates))
	case u == nil:
		ch.Risk = model.RiskInfo
		add("Kein AD-Konto zur Kennung gefunden")
		ch.Actions.UserMail = strings.Contains(in.Identifier, "@")
	case ch.Policy.Compliant && !(adsspViolated && a.Decisive):
		ch.Risk = model.RiskHigh
		add("Kennwort erfüllt die Kennwortrichtlinie (%s) – es kann das aktuelle oder ein früheres AD-Kennwort sein", ch.Policy.Source)
		ch.Actions = model.Actions{AdminTodo: true, UserMail: true, AdminMail: true}
		if ch.PwdChangedAfterLeak != nil && *ch.PwdChangedAfterLeak {
			ch.Risk = model.RiskMedium
			add("Kennwort wurde nach dem Leak-Datum geändert (%s)", u.PwdLastSet.Format("02.01.2006"))
		}
	case adsspViolated && a.Decisive:
		ch.Risk = model.RiskLow
		add("Kennwort erfüllt die AD-Richtlinie, verletzt aber die ADSelfService-Plus-Richtlinie %q, die seit %s auch nativ durchgesetzt wird – das aktuelle Kennwort (gesetzt %s) kann es nicht sein",
			a.Policy, a.ActiveSince.Format("02.01.2006"), u.PwdLastSet.Format("02.01.2006"))
		ch.Actions.UserMail = true
	default:
		ch.Risk = model.RiskLow
		add("Kennwort erfüllt die Kennwortrichtlinie NICHT – vermutlich Kennwort eines anderen Dienstes (Wiederverwendung prüfen)")
		ch.Actions.UserMail = true
	}
	if adsspViolated && !a.Decisive {
		why := "Kennwort wurde vor der Aktivierung gesetzt oder Aktivierungsdatum unbekannt"
		if !a.Native {
			why = "Richtlinie wird nicht nativ (Strg+Alt+Entf/ADUC) durchgesetzt"
		}
		add("Verletzt die ADSelfService-Plus-Richtlinie %q, ist aber trotzdem als AD-Kennwort möglich (%s)", a.Policy, why)
	} else if a != nil && a.Compliant && ch.Policy.Compliant {
		add("Erfüllt auch die ADSelfService-Plus-Richtlinie %q", a.Policy)
	}

	if u != nil {
		if !u.Enabled {
			add("AD-Konto ist deaktiviert")
		}
		if u.AccountExpired {
			add("AD-Konto ist abgelaufen")
		}
		if u.LockedOut {
			add("AD-Konto ist aktuell gesperrt (Lockout)")
		}
		if u.PasswordNeverExpires {
			add("Kennwort läuft nie ab (DONT_EXPIRE_PASSWORD gesetzt)")
		}
		if len(u.Privileged) > 0 || u.AdminCount {
			if ch.Risk == model.RiskHigh || ch.Risk == model.RiskMedium {
				ch.Risk = raise(ch.Risk)
			}
			g := strings.Join(u.Privileged, ", ")
			if g == "" {
				g = "adminCount=1"
			}
			add("Privilegiertes Konto (%s)", g)
		}
	}
	if ch.BindTested && ch.BindValid {
		ch.Risk = model.RiskCritical
		ch.Actions = model.Actions{AdminTodo: true, UserMail: true, AdminMail: true}
		add("Bind-Test: %s", ch.BindResult)
	}
	if ch.HIBPCount > 0 {
		add("Kennwort ist in öffentlichen Leak-Sammlungen %d× bekannt (Pwned Passwords)", ch.HIBPCount)
	}
	for _, r := range ch.Recurrences {
		if r.SamePW {
			add("Identisches Kennwort bereits in Fall %s gemeldet", r.CaseNumber)
		}
	}
	if n := countUser(ch.Recurrences); n > 0 {
		add("Für dieses Konto gibt es %d frühere Fälle", n)
	}
}

func countUser(r []model.Recurrence) int {
	n := 0
	for _, x := range r {
		if !x.SamePW {
			n++
		}
	}
	return n
}

// adsspFor wählt die erste passende ADSSP-Richtlinie (OU oder Gruppe; ohne apply_to = alle).
func (e *Engine) adsspFor(u *model.ADUser) (*policy.ADSSPChecker, string) {
	for _, ck := range e.adssp {
		at := ck.Policy.ApplyTo
		if len(at.OUs) == 0 && len(at.Groups) == 0 {
			return ck, "gilt für alle Konten"
		}
		if u == nil {
			continue
		}
		dn := strings.ToLower(u.DN)
		for _, ou := range at.OUs {
			if ou = strings.ToLower(strings.TrimSpace(ou)); ou != "" && strings.HasSuffix(dn, ","+ou) {
				return ck, "zugeordnet über OU " + ou
			}
		}
		if len(at.Groups) > 0 && e.ldap.Enabled() {
			ok, err := e.ldap.MemberOfAny(u.DN, at.Groups)
			if err != nil {
				return nil, "ADSSP-Gruppenzuordnung nicht prüfbar: " + err.Error()
			}
			if ok {
				return ck, "zugeordnet über Gruppenmitgliedschaft"
			}
		}
	}
	return nil, ""
}
