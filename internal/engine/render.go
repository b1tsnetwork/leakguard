package engine

import (
	"bytes"
	"fmt"
	"strings"
	"text/template"
	"time"

	"leakguard/internal/model"
)

// Template-Schlüssel (werden in der Tabelle settings überschrieben).
const (
	TplUserStrongSubject = "tpl.user_strong.subject"
	TplUserStrongBody    = "tpl.user_strong.body"
	TplUserWeakSubject   = "tpl.user_weak.subject"
	TplUserWeakBody      = "tpl.user_weak.body"
	TplAdminSubject      = "tpl.admin.subject"
	TplAdminBody         = "tpl.admin.body"
)

type TemplateDef struct {
	Key   string
	Label string
	Multi bool
}

var TemplateDefs = []TemplateDef{
	{TplUserStrongSubject, "Nutzer-Mail (Kennwort erfüllt Richtlinie) – Betreff", false},
	{TplUserStrongBody, "Nutzer-Mail (Kennwort erfüllt Richtlinie) – Text", true},
	{TplUserWeakSubject, "Nutzer-Mail (Kennwort erfüllt Richtlinie nicht) – Betreff", false},
	{TplUserWeakBody, "Nutzer-Mail (Kennwort erfüllt Richtlinie nicht) – Text", true},
	{TplAdminSubject, "Admin-Mail – Betreff", false},
	{TplAdminBody, "Admin-Mail – Text", true},
}

const commonUserAdvice = `Bitte prüfen Sie außerdem Ihre Zugänge AUSSERHALB unseres Firmennetzes:

  1. Wiederverwendung: Haben Sie dieses oder ein ähnliches Kennwort (z. B. mit anderer Zahl am Ende) auch bei anderen Diensten verwendet – etwa bei Online-Shops, Marktplätzen, sozialen Netzwerken, privaten E-Mail-Postfächern, Streaming-, Cloud-, Reise- oder Bezahldiensten? Ändern Sie es dort bitte umgehend und verwenden Sie für jeden Dienst ein eigenes Kennwort.

  2. Auffälligkeiten prüfen: Kontrollieren Sie bei diesen Diensten:
       - die letzten Anmeldungen und aktiven Sitzungen/Geräte,
       - Bestellungen, Zahlungen, gespeicherte Zahlungsmittel und Lieferadressen,
       - geänderte Kontaktdaten (E-Mail, Telefonnummer),
       - Weiterleitungs- und Filterregeln in privaten Postfächern.
     Melden Sie unbekannte Geräte ab und informieren Sie bei verdächtigen Vorgängen den jeweiligen Anbieter bzw. Ihre Bank.

  3. Zwei-Faktor-Anmeldung: Aktivieren Sie, wo möglich, eine zweite Anmeldestufe (Authenticator-App oder Passkey).

  4. Kennwort-Manager: Ein Kennwort-Manager hilft, für jeden Dienst ein eigenes, starkes Kennwort zu nutzen.

  5. Phishing: Rechnen Sie in nächster Zeit mit gezielten Betrugs-Mails, die sich auf genau diese Dienste beziehen. Klicken Sie keine Links in unerwarteten „Sicherheitswarnungen“, sondern rufen Sie die Seite selbst auf.

Wichtig: Wir fragen Sie niemals nach Ihrem Kennwort. Bitte antworten Sie auf diese Nachricht nicht mit Kennwörtern.`

var DefaultTemplates = map[string]string{
	TplUserStrongSubject: `Sicherheitshinweis: Ihr Kennwort wurde in einem Datenleck gefunden (Fall {{.CaseNumber}})`,
	TplUserStrongBody: `{{if .GivenName}}Hallo {{.GivenName}},{{else if .DisplayName}}Hallo {{.DisplayName}},{{else}}Guten Tag,{{end}}

unser Security Operations Center (SOC) hat uns informiert, dass Zugangsdaten zu Ihrem Benutzerkonto bzw. Ihrer E-Mail-Adresse ({{.Email}}) in einer Sammlung veröffentlichter Zugangsdaten aufgetaucht sind.

Betroffenes Kennwort: {{.Password}}

Dieses Kennwort erfüllt unsere Kennwortrichtlinien und könnte daher Ihr aktuelles oder ein früheres Firmenkennwort sein. {{if .AdminTodoDone}}Zu Ihrem Schutz haben wir Ihr Konto so eingestellt, dass Sie Ihr Kennwort bei der nächsten Anmeldung ändern müssen.{{else}}Zu Ihrem Schutz werden wir Ihr Konto kurzfristig so einstellen, dass Sie Ihr Kennwort bei der nächsten Anmeldung ändern müssen.{{end}} Bitte wählen Sie ein neues, bisher nirgends verwendetes Kennwort – am besten eine lange Passphrase.

` + commonUserAdvice + `

Haben Sie an Ihrem Firmenkonto Ungewöhnliches bemerkt (z. B. MFA-Anfragen, die Sie nicht ausgelöst haben, oder unbekannte Anmeldebenachrichtigungen)? Dann melden Sie sich bitte sofort bei uns – unter Angabe der Fallnummer {{.CaseNumber}}.

{{.Signature}}`,

	TplUserWeakSubject: `Sicherheitshinweis: Zugangsdaten zu Ihrer E-Mail-Adresse wurden veröffentlicht (Fall {{.CaseNumber}})`,
	TplUserWeakBody: `{{if .GivenName}}Hallo {{.GivenName}},{{else if .DisplayName}}Hallo {{.DisplayName}},{{else}}Guten Tag,{{end}}

unser Security Operations Center (SOC) hat uns informiert, dass Zugangsdaten zu Ihrer E-Mail-Adresse ({{.Email}}) in einer Sammlung veröffentlichter Zugangsdaten aufgetaucht sind.

Betroffenes Kennwort: {{.Password}}

Dieses Kennwort erfüllt unsere Kennwortrichtlinien nicht und ist daher sehr wahrscheinlich NICHT Ihr Firmenkennwort. Vermutlich stammt es von einem anderen Dienst, bei dem Sie sich mit Ihrer Firmen-E-Mail-Adresse registriert haben. Ihr Firmenkonto müssen Sie deshalb nicht ändern – sollten Sie dort jedoch ein ähnliches Kennwort verwenden, ändern Sie es bitte trotzdem.

` + commonUserAdvice + `

Tipp: Nutzen Sie Ihre Firmen-E-Mail-Adresse möglichst nur für dienstliche Zwecke.

Bei Fragen erreichen Sie uns unter Angabe der Fallnummer {{.CaseNumber}}.

{{.Signature}}`,

	TplAdminSubject: `[LeakGuard] Fall {{.CaseNumber}} – {{.Username}} – Risiko {{.Risk}}`,
	TplAdminBody: `Leak-Fall {{.CaseNumber}} wurde von {{.Actor}} bearbeitet.

Konto:          {{.Username}}{{if .DisplayName}} ({{.DisplayName}}){{end}}
E-Mail:         {{.Email}}
Quelle/Hinweis: {{if .Source}}{{.Source}}{{else}}–{{end}}
Leak-Datum:     {{if .LeakDate}}{{.LeakDate}}{{else}}unbekannt{{end}}
Kennwort:       {{.PasswordHint}} – Richtlinie {{if .PolicyCompliant}}ERFÜLLT{{else}}nicht erfüllt{{end}}
Risiko:         {{.Risk}}

Bewertung:
{{.ChecksSummary}}

Empfohlene Maßnahmen (PowerShell):
{{.PowerShell}}

Falldokumentation: {{.CaseURL}}
`,
}

type MailData struct {
	CaseNumber      string
	DisplayName     string
	GivenName       string
	Username        string
	Email           string
	PasswordHint    string
	Password        string // Klartext (Fallback: Maske, wenn nicht entschlüsselbar)
	PolicyCompliant bool
	Risk            string
	Source          string
	LeakDate        string
	Date            string
	Actor           string
	AdminTodoDone   bool
	ChecksSummary   string
	PowerShell      string
	CaseURL         string
	Signature       string
	OrgName         string
}

func (e *Engine) MailData(c *model.Case, actor string) MailData {
	d := MailData{
		CaseNumber:      c.CaseNumber,
		Username:        c.Username(),
		DisplayName:     c.DisplayName(),
		Email:           c.Recipient(),
		PasswordHint:    fmt.Sprintf("%s (%d Zeichen)", c.PwMask, c.PwLen),
		PolicyCompliant: c.Compliant,
		Risk:            c.Risk,
		Source:          c.Source,
		Date:            time.Now().Format("02.01.2006"),
		Actor:           actor,
		AdminTodoDone:   c.AdminTodoDone,
		ChecksSummary:   Summary(c),
		PowerShell:      PowerShell(c),
		CaseURL:         fmt.Sprintf("%s/cases/%d", e.cfg.BaseURL, c.ID),
		Signature:       e.cfg.Mail.Signature,
		OrgName:         e.cfg.Mail.OrgName,
	}
	d.Password = d.PasswordHint
	if pw, err := e.DecryptPassword(c.PwEnc); err == nil {
		d.Password = pw
	}
	if c.Checks.User != nil {
		d.GivenName = c.Checks.User.GivenName
	}
	if !c.LeakDate.IsZero() {
		d.LeakDate = c.LeakDate.Format("02.01.2006")
	}
	return d
}

// Render rendert eine Vorlage (text/template, keine HTML-Escapes).
func Render(src string, data any) (string, error) {
	t, err := template.New("t").Option("missingkey=error").Parse(src)
	if err != nil {
		return "", err
	}
	var b bytes.Buffer
	if err := t.Execute(&b, data); err != nil {
		return "", err
	}
	return b.String(), nil
}

func Validate(src string) error {
	_, err := Render(src, MailData{})
	return err
}

// Summary erzeugt eine Textzusammenfassung der Prüfergebnisse.
func Summary(c *model.Case) string {
	var b strings.Builder
	for _, r := range c.Checks.Reasons {
		b.WriteString("  - " + r + "\n")
	}
	for _, f := range c.Checks.Policy.Findings {
		mark := "OK  "
		if !f.OK {
			mark = "FAIL"
		}
		fmt.Fprintf(&b, "  [%s] %s: %s\n", mark, f.Rule, f.Detail)
	}
	if u := c.Checks.User; u != nil {
		fmt.Fprintf(&b, "  Konto aktiv: %s | gesperrt: %s | Kennwort zuletzt gesetzt: %s | letzte Anmeldung: %s\n",
			yn(u.Enabled), yn(u.LockedOut), fmtT(u.PwdLastSet), fmtT(u.LastLogon))
	}
	if c.Checks.LDAPError != "" {
		b.WriteString("  LDAP-Fehler: " + c.Checks.LDAPError + "\n")
	}
	return strings.TrimRight(b.String(), "\n")
}

func yn(b bool) string {
	if b {
		return "ja"
	}
	return "nein"
}

func fmtT(t time.Time) string {
	if t.IsZero() {
		return "–"
	}
	return t.Format("02.01.2006 15:04")
}

func psQuote(s string) string { return "'" + strings.ReplaceAll(s, "'", "''") + "'" }

// PSSnippet ist ein einzelner, kopierbarer PowerShell-Block.
type PSSnippet struct {
	Title string
	Hint  string
	Code  string
}

// PowerShellSnippets liefert die Admin-ToDos als einzelne Blöcke.
func PowerShellSnippets(c *model.Case) []PSSnippet {
	u := c.Checks.User
	if u == nil {
		return nil
	}
	id := psQuote(u.SAM)
	note := psQuote(fmt.Sprintf("LeakGuard Fall %s (%s)", c.CaseNumber, time.Now().Format("2006-01-02")))
	var out []PSSnippet

	check := fmt.Sprintf(`Import-Module ActiveDirectory
Get-ADUser -Identity %s -Properties Enabled,LockedOut,PasswordLastSet,PasswordNeverExpires,LastLogonDate,pwdLastSet |
  Select-Object SamAccountName,Enabled,LockedOut,PasswordLastSet,PasswordNeverExpires,LastLogonDate`, id)
	out = append(out, PSSnippet{"Status prüfen", "Aktuellen Kontostatus anzeigen.", check})

	force := "Import-Module ActiveDirectory\n"
	if u.PasswordNeverExpires {
		force += fmt.Sprintf("# \"Kennwort läuft nie ab\" ist gesetzt – muss vorher entfernt werden:\nSet-ADUser -Identity %s -PasswordNeverExpires $false\n", id)
	}
	force += fmt.Sprintf(`Set-ADUser -Identity %s -ChangePasswordAtLogon $true
# Vermerk im Feld "Notizen" (info)
$u = Get-ADUser -Identity %s -Properties info
Set-ADUser -Identity %s -Replace @{ info = ("$($u.info)`+"`r`n"+`" + %s + ": Kennwortänderung erzwungen").Trim() }`, id, id, id, note)
	out = append(out, PSSnippet{"Kennwortänderung erzwingen", "Nutzer muss das Kennwort bei der nächsten Anmeldung ändern. Bestehende Sitzungen/Tickets bleiben bis zum Ablauf gültig.", force})

	reset := fmt.Sprintf(`Import-Module ActiveDirectory
# Setzt ein zufälliges Kennwort – macht das geleakte Kennwort SOFORT ungültig
Add-Type -AssemblyName System.Web
$pw = [System.Web.Security.Membership]::GeneratePassword(24, 6)
Set-ADAccountPassword -Identity %s -Reset -NewPassword (ConvertTo-SecureString $pw -AsPlainText -Force)
Set-ADUser -Identity %s -ChangePasswordAtLogon $true
Remove-Variable pw`, id, id)
	if u.PasswordNeverExpires {
		reset = strings.Replace(reset, "Set-ADUser -Identity "+id+" -ChangePasswordAtLogon $true",
			"Set-ADUser -Identity "+id+" -PasswordNeverExpires $false\nSet-ADUser -Identity "+id+" -ChangePasswordAtLogon $true", 1)
	}
	out = append(out, PSSnippet{"Kennwort zurücksetzen (sofort ungültig)", "Empfohlen, wenn der Bind-Test positiv war oder das Konto privilegiert ist. Nutzer braucht danach Unterstützung (Servicedesk).", reset})

	disable := fmt.Sprintf(`Import-Module ActiveDirectory
Disable-ADAccount -Identity %s
Set-ADUser -Identity %s -Description ("Gesperrt: " + %s)`, id, id, note)
	out = append(out, PSSnippet{"Konto sperren (deaktivieren)", "Konto sofort deaktivieren, z. B. bei Verdacht auf aktive Kompromittierung.", disable})

	if u.UPN != "" {
		entra := fmt.Sprintf(`# Nur bei hybrider Identität (Entra ID / M365): Refresh-Tokens widerrufen
Connect-MgGraph -Scopes "User.RevokeSessions.All"
Revoke-MgUserSignInSession -UserId %s`, psQuote(u.UPN))
		out = append(out, PSSnippet{"Entra-ID-Sitzungen widerrufen (optional)", "Meldet den Nutzer in Cloud-Diensten ab (Microsoft Graph PowerShell).", entra})
	}
	return out
}

// PowerShell fasst alle Blöcke für die Admin-Mail zusammen.
func PowerShell(c *model.Case) string {
	sn := PowerShellSnippets(c)
	if len(sn) == 0 {
		return "  (kein AD-Konto ermittelt)"
	}
	var b strings.Builder
	for _, s := range sn {
		b.WriteString("# --- " + s.Title + " ---\n" + s.Code + "\n\n")
	}
	return strings.TrimRight(b.String(), "\n")
}
