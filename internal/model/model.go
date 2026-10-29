// Package model enthält die gemeinsam genutzten Datenstrukturen.
package model

import "time"

const (
	StatusOpen       = "offen"
	StatusInProgress = "in_bearbeitung"
	StatusClosed     = "abgeschlossen"

	RiskInfo     = "info"
	RiskLow      = "niedrig"
	RiskMedium   = "mittel"
	RiskHigh     = "hoch"
	RiskCritical = "kritisch"
)

var Statuses = []string{StatusOpen, StatusInProgress, StatusClosed}

// ADUser ist ein Schnappschuss des AD-Kontos zum Prüfzeitpunkt.
type ADUser struct {
	DN                   string    `json:"dn"`
	SAM                  string    `json:"sam"`
	UPN                  string    `json:"upn"`
	Mail                 string    `json:"mail"`
	DisplayName          string    `json:"display_name"`
	GivenName            string    `json:"given_name"`
	Surname              string    `json:"surname"`
	Department           string    `json:"department"`
	Title                string    `json:"title"`
	Enabled              bool      `json:"enabled"`
	LockedOut            bool      `json:"locked_out"`
	PasswordExpired      bool      `json:"password_expired"`
	PasswordNeverExpires bool      `json:"password_never_expires"`
	AccountExpired       bool      `json:"account_expired"`
	AdminCount           bool      `json:"admin_count"`
	PwdLastSet           time.Time `json:"pwd_last_set"`
	MustChangePassword   bool      `json:"must_change_password"`
	LastLogon            time.Time `json:"last_logon"`
	AccountExpires       time.Time `json:"account_expires"`
	WhenCreated          time.Time `json:"when_created"`
	MemberOf             []string  `json:"member_of"`
	Privileged           []string  `json:"privileged"`
}

func (u *ADUser) Name() string {
	if u == nil {
		return ""
	}
	if u.DisplayName != "" {
		return u.DisplayName
	}
	return u.SAM
}

type Finding struct {
	Rule      string `json:"rule"`
	OK        bool   `json:"ok"`
	Detail    string `json:"detail"`
	Mandatory bool   `json:"mandatory,omitempty"`
}

// ADSSPResult ist das Ergebnis der Prüfung gegen eine ManageEngine-ADSelfService-Plus-Richtlinie.
type ADSSPResult struct {
	Policy      string    `json:"policy"`
	Compliant   bool      `json:"compliant"`
	Findings    []Finding `json:"findings"`
	Satisfied   int       `json:"satisfied"`  // erfüllte Komplexitätsregeln
	Required    int       `json:"required"`   // geforderte Anzahl
	Total       int       `json:"total"`      // Anzahl Komplexitätsregeln
	Overridden  bool      `json:"overridden"` // Komplexität durch Länge aufgehoben
	ActiveSince time.Time `json:"active_since"`
	Native      bool      `json:"native"`
	Decisive    bool      `json:"decisive"` // Verstoß schließt aktuelles AD-Kennwort aus
	Note        string    `json:"note,omitempty"`
}

type PolicyResult struct {
	Compliant bool      `json:"compliant"`
	Source    string    `json:"source"`
	MinLength int       `json:"min_length"`
	Findings  []Finding `json:"findings"`
}

type Recurrence struct {
	CaseID     int64     `json:"case_id"`
	CaseNumber string    `json:"case_number"`
	CreatedAt  time.Time `json:"created_at"`
	SamePW     bool      `json:"same_pw"`
}

// BlockPattern sind die aus dem Kennwort abgeleiteten Sperrlisten-Einträge.
type BlockPattern struct {
	Words []string `json:"words"`
	Regex string   `json:"regex"`
}

type Actions struct {
	AdminTodo bool `json:"admin_todo"`
	UserMail  bool `json:"user_mail"`
	AdminMail bool `json:"admin_mail"`
}

// Checks ist das vollständige, dokumentierte Ergebnis eines Prüflaufs.
type Checks struct {
	RunAt               time.Time    `json:"run_at"`
	RunBy               string       `json:"run_by"`
	LDAPError           string       `json:"ldap_error,omitempty"`
	Candidates          []ADUser     `json:"candidates,omitempty"`
	User                *ADUser      `json:"user,omitempty"`
	Policy              PolicyResult `json:"policy"`
	HIBPEnabled         bool         `json:"hibp_enabled"`
	HIBPCount           int          `json:"hibp_count"`
	HIBPError           string       `json:"hibp_error,omitempty"`
	BindTested          bool         `json:"bind_tested"`
	BindValid           bool         `json:"bind_valid"`
	BindResult          string       `json:"bind_result,omitempty"`
	PwdChangedAfterLeak *bool        `json:"pwd_changed_after_leak,omitempty"`
	Recurrences         []Recurrence `json:"recurrences,omitempty"`
	Blocklist           BlockPattern `json:"blocklist"`
	ADSSP               *ADSSPResult `json:"adssp,omitempty"`
	// PossibleADPassword: Kennwort kann nach allen Regeln das aktuelle AD-Kennwort sein.
	PossibleADPassword bool     `json:"possible_ad_password"`
	Risk               string   `json:"risk"`
	Reasons            []string `json:"reasons"`
	Warnings           []string `json:"warnings,omitempty"`
	Actions            Actions  `json:"actions"`
}

type Case struct {
	ID         int64
	CaseNumber string
	CreatedAt  time.Time
	CreatedBy  string
	UpdatedAt  time.Time
	Identifier string
	Source     string
	LeakDate   time.Time // Zero = unbekannt
	PwMask     string
	PwLen      int
	PwHMAC     string
	PwEnc      string // AES-GCM-verschlüsseltes Kennwort
	Compliant  bool
	Risk       string
	Status     string
	Checks     Checks

	AdminTodoDone bool
	AdminTodoBy   string
	AdminTodoAt   time.Time
	UserMailBy    string
	UserMailAt    time.Time
	AdminMailBy   string
	AdminMailAt   time.Time
	ClosedBy      string
	ClosedAt      time.Time
}

func (c *Case) Username() string {
	if c.Checks.User != nil {
		return c.Checks.User.SAM
	}
	return c.Identifier
}

func (c *Case) DisplayName() string {
	if c.Checks.User != nil {
		return c.Checks.User.Name()
	}
	return ""
}

// Recipient liefert die vorgeschlagene Empfängeradresse für die Nutzer-Mail.
func (c *Case) Recipient() string {
	if c.Checks.User != nil && c.Checks.User.Mail != "" {
		return c.Checks.User.Mail
	}
	for _, r := range c.Identifier {
		if r == '@' {
			return c.Identifier
		}
	}
	return ""
}

type Event struct {
	ID      int64
	CaseID  int64
	At      time.Time
	Actor   string
	Kind    string
	Message string
	Detail  string
}

type CaseFilter struct {
	Query  string
	Status string
	Risk   string
	Limit  int
	Offset int
}
