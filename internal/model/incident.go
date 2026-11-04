package model

import "time"

// Phasen nach dem Incident-Response-Lebenszyklus (NIST SP 800-61 / BSI).
const (
	PhaseReported     = "gemeldet"
	PhaseTriage       = "triage"
	PhaseAnalysis     = "analyse"
	PhaseContainment  = "eindaemmung"
	PhaseEradication  = "beseitigung"
	PhaseRecovery     = "wiederherstellung"
	PhasePostIncident = "nachbereitung"
	PhaseClosed       = "abgeschlossen"
)

type Labeled struct{ Key, Label, Hint string }

var Phases = []Labeled{
	{PhaseReported, "Gemeldet", "Meldung eingegangen, noch nicht bewertet"},
	{PhaseTriage, "Triage", "Erstbewertung: echt? Schwere? Zuständigkeit?"},
	{PhaseAnalysis, "Analyse", "Umfang, Ursache, betroffene Systeme ermitteln"},
	{PhaseContainment, "Eindämmung", "Ausbreitung stoppen, Schaden begrenzen"},
	{PhaseEradication, "Beseitigung", "Ursache entfernen, Zugänge schließen"},
	{PhaseRecovery, "Wiederherstellung", "Systeme kontrolliert in Betrieb nehmen"},
	{PhasePostIncident, "Nachbereitung", "Lessons Learned, Maßnahmen, Abschlussbericht"},
	{PhaseClosed, "Abgeschlossen", ""},
}

// Schwere: P1 (kritisch) bis P4 (niedrig).
var Severities = []Labeled{
	{"P1", "P1 – Kritisch", "Kerngeschäft steht / großflächige Kompromittierung / Krisenstab"},
	{"P2", "P2 – Hoch", "Wesentliche Systeme oder viele Nutzer betroffen"},
	{"P3", "P3 – Mittel", "Begrenzte Auswirkungen, eingegrenzt"},
	{"P4", "P4 – Niedrig", "Einzelfall ohne nennenswerte Auswirkung"},
}

// Traffic Light Protocol 2.0 (FIRST).
var TLPs = []Labeled{
	{"CLEAR", "TLP:CLEAR", "Keine Einschränkung"},
	{"GREEN", "TLP:GREEN", "Community, nicht öffentlich"},
	{"AMBER", "TLP:AMBER", "Eigene Organisation und Kunden, need-to-know"},
	{"AMBER+STRICT", "TLP:AMBER+STRICT", "Nur eigene Organisation"},
	{"RED", "TLP:RED", "Nur anwesende Empfänger"},
}

// Rollen innerhalb eines Vorfalls.
const (
	IRoleNone     = ""
	IRoleObserver = "beobachter"
	IRoleMember   = "mitglied"
	IRoleLead     = "leitung"
)

var IncidentRoles = []Labeled{
	{IRoleLead, "Leitung", "Status, Stab, Fristen, Freigaben"},
	{IRoleMember, "Mitglied", "Dokumentieren, Aufgaben, Kommunikation"},
	{IRoleObserver, "Beobachter", "Nur lesen"},
}

func IRoleRank(r string) int {
	switch r {
	case IRoleLead:
		return 3
	case IRoleMember:
		return 2
	case IRoleObserver:
		return 1
	}
	return 0
}

type Incident struct {
	ID             int64
	Number         string
	Title          string
	Category       string
	Severity       string
	Phase          string
	TLP            string
	Classification string // "" | "VS-NfD"
	Confidential   bool
	Description    string
	Source         string // Meldeweg (SOC, Nutzer, Dienstleister …)
	ReportedBy     string
	Lead           string // Username Incident Commander

	// Schutzziele betroffen
	ImpactC, ImpactI, ImpactA bool
	PersonalData              bool
	AffectedUsers             int

	// Zeitpunkte
	OccurredAt  time.Time // Beginn (soweit bekannt)
	DetectedAt  time.Time // Entdeckung
	AwarenessAt time.Time // Kenntnisnahme – Fristbeginn für Meldepflichten
	ContainedAt time.Time
	ResolvedAt  time.Time
	ClosedAt    time.Time

	// Lage
	CrisisMode   bool // Krisenstab / Lage aktiv
	NextBriefing time.Time

	// Nachbereitung
	RootCause    string
	Lessons      string
	Improvements string

	LeakCaseID int64

	// Storno (Fehlanlage / Test)
	Cancelled    bool
	CancelReason string
	CancelledAt  time.Time
	CancelledBy  string
	WFVersionID  int64 // gebundene Workflow-Version (0 = ohne Workflow)

	CreatedAt time.Time
	CreatedBy string
	UpdatedAt time.Time

	// berechnet (nicht gespeichert)
	MyRole string
}

func (i *Incident) Active() bool { return i.Phase != PhaseClosed && !i.Cancelled }

type Member struct {
	IncidentID int64
	Username   string
	Display    string
	Function   string
	Role       string
	AddedAt    time.Time
	AddedBy    string
}

// JournalEntry – Einsatztagebuch (unveränderlich).
type JournalEntry struct {
	ID         int64
	IncidentID int64
	At         time.Time // Erfassungszeit
	OccurredAt time.Time // Ereigniszeit (falls abweichend)
	Actor      string
	Kind       string
	Text       string
	RefID      int64 // Korrektur zu Eintrag
	Auto       bool
	// Join
	IncidentNumber string
	IncidentTitle  string
}

var JournalKinds = []Labeled{
	{"information", "Lageinformation", ""},
	{"decision", "Entscheidung", "Wer hat was warum entschieden"},
	{"measure", "Maßnahme", "Durchgeführte Maßnahme"},
	{"observation", "Feststellung", "Befund, Beobachtung"},
	{"order", "Auftrag", ""},
	{"note", "Notiz", ""},
	{"correction", "Korrektur", "Berichtigt einen früheren Eintrag"},
	{"status", "Status", ""},
	{"task", "Aufgabe", ""},
	{"comm", "Kommunikation", ""},
	{"system", "System", ""},
	{"member", "Stab", ""},
	{"deadline", "Meldepflicht", ""},
	{"sitrep", "Lagemeldung", ""},
}

// ManualJournalKinds sind die Arten, die Benutzer selbst erfassen.
var ManualJournalKinds = []string{"information", "decision", "measure", "observation", "order", "note"}

type Task struct {
	ID         int64
	IncidentID int64
	Title      string
	Details    string
	Function   string
	Assignee   string
	Priority   string
	Status     string
	DueAt      time.Time
	Result     string
	CreatedAt  time.Time
	CreatedBy  string
	UpdatedAt  time.Time
	DoneAt     time.Time
	DoneBy     string
	WFStep     string // Schritt-ID aus dem Workflow (leer = manuell angelegt)
	RecKey     string // Empfehlung, aus der die Aufgabe übernommen wurde
	// Join
	IncidentNumber string
	IncidentTitle  string
}

func (t *Task) Open() bool { return t.Status != "erledigt" && t.Status != "verworfen" }
func (t *Task) Overdue() bool {
	return t.Open() && !t.DueAt.IsZero() && time.Now().After(t.DueAt)
}

var TaskStatuses = []Labeled{
	{"offen", "Offen", ""}, {"in_arbeit", "In Arbeit", ""}, {"blockiert", "Blockiert", ""},
	{"erledigt", "Erledigt", ""}, {"verworfen", "Verworfen", ""},
}
var Priorities = []Labeled{{"hoch", "Hoch", ""}, {"mittel", "Mittel", ""}, {"niedrig", "Niedrig", ""}}

// Communication – interne/externe Kommunikation, inkl. Anfragen mit Antwortpflicht und Freigabe.
type Communication struct {
	ID         int64
	IncidentID int64
	Direction  string // ein | aus
	Scope      string // intern | extern
	Channel    string
	PartyType  string
	Party      string
	Subject    string
	Content    string
	OccurredAt time.Time
	TLP        string
	NeedsReply bool
	ReplyDue   time.Time
	Status     string
	ApprovedBy string
	ApprovedAt time.Time
	CreatedAt  time.Time
	CreatedBy  string
	UpdatedAt  time.Time
	// Join
	IncidentNumber string
	IncidentTitle  string
}

func (c *Communication) OpenRequest() bool {
	return c.Direction == "ein" && c.NeedsReply && c.Status != "beantwortet" && c.Status != "erledigt"
}
func (c *Communication) PendingApproval() bool { return c.Status == "zur_freigabe" }
func (c *Communication) ReplyOverdue() bool {
	return c.OpenRequest() && !c.ReplyDue.IsZero() && time.Now().After(c.ReplyDue)
}

var CommChannels = []Labeled{{"email", "E-Mail", ""}, {"phone", "Telefon", ""}, {"meeting", "Besprechung", ""},
	{"chat", "Chat / Messenger", ""}, {"letter", "Brief / Fax", ""}, {"portal", "Meldeportal", ""}, {"press", "Pressemitteilung", ""}, {"other", "Sonstiges", ""}}
var CommParties = []Labeled{{"management", "Behördenleitung / Verwaltungsvorstand", ""}, {"staff", "Beschäftigte", ""},
	{"it", "IT / Fachbereich", ""}, {"staff_council", "Personalrat", ""}, {"dpo", "Datenschutz", ""},
	{"cert", "CERT (Landes-CERT / CERT-Bund / BSI)", ""}, {"authority", "Datenschutz-Aufsicht / andere Behörde", ""},
	{"supervisory", "Aufsicht / vorgesetzte Behörde", ""}, {"council", "Rat / Kreistag / politische Gremien", ""},
	{"police", "Polizei / ZAC", ""}, {"it_provider", "IT-Dienstleister / Rechenzentrum", ""}, {"provider", "Hersteller / externer Dienstleister", ""},
	{"insurance", "Versicherung / Kommunaler Schadenausgleich", ""}, {"citizens", "Bürgerinnen und Bürger", ""},
	{"customer", "Partnerbehörden / Unternehmen", ""}, {"press", "Presse / Öffentlichkeit", ""}, {"affected", "Betroffene Personen", ""},
	{"other", "Sonstige", ""}}
var CommStatuses = []Labeled{
	{"offen", "Offen", "Eingang, Antwort ausstehend"}, {"in_bearbeitung", "In Bearbeitung", ""}, {"beantwortet", "Beantwortet", ""},
	{"entwurf", "Entwurf", "Ausgang, noch nicht abgestimmt"}, {"zur_freigabe", "Zur Freigabe", "Externe Kommunikation – Freigabe durch Leitung"},
	{"freigegeben", "Freigegeben", ""}, {"versendet", "Versendet", ""}, {"erledigt", "Erledigt / dokumentiert", ""},
}

type Asset struct {
	ID          int64
	IncidentID  int64
	Name        string
	Kind        string
	Identifier  string // Hostname, IP, Konto, URL
	Owner       string
	Criticality string
	Status      string
	Notes       string
	CreatedAt   time.Time
	CreatedBy   string
	UpdatedAt   time.Time
	UpdatedBy   string
}

var AssetKinds = []Labeled{{"server", "Server", ""}, {"client", "Client / Arbeitsplatz", ""}, {"network", "Netzwerk / Firewall", ""},
	{"application", "Fachverfahren / Anwendung", ""}, {"account", "Benutzerkonto", ""}, {"cloud", "Cloud / SaaS", ""},
	{"mobile", "Mobilgerät", ""}, {"ot", "OT / Steuerung", ""}, {"data", "Datenbestand", ""}, {"other", "Sonstiges", ""}}
var AssetStatuses = []Labeled{
	{"verdacht", "Verdacht", ""}, {"in_untersuchung", "In Untersuchung", ""}, {"kompromittiert", "Kompromittiert", ""},
	{"isoliert", "Isoliert", ""}, {"bereinigt", "Bereinigt", ""}, {"wiederhergestellt", "Wiederhergestellt", ""},
	{"nicht_betroffen", "Nicht betroffen", ""},
}

type IOC struct {
	ID          int64
	IncidentID  int64
	Type        string
	Value       string
	Description string
	TLP         string
	CreatedAt   time.Time
	CreatedBy   string
}

var IOCTypes = []Labeled{{"ip", "IP-Adresse", ""}, {"domain", "Domain", ""}, {"url", "URL", ""}, {"hash", "Datei-Hash", ""},
	{"email", "E-Mail-Adresse", ""}, {"file", "Dateiname / Pfad", ""}, {"registry", "Registry", ""}, {"account", "Konto", ""}, {"other", "Sonstiges", ""}}

// Obligation – Melde-/Benachrichtigungsfrist eines Vorfalls.
type Obligation struct {
	ID         int64
	IncidentID int64
	Regulation string
	Key        string
	Label      string
	Authority  string
	Hours      int
	After      string
	DueAt      time.Time // berechnet
	Status     string    // offen | erledigt | nicht_erforderlich
	Reference  string
	Note       string
	DoneAt     time.Time
	DoneBy     string
	CreatedAt  time.Time
	// Join
	IncidentNumber string
	IncidentTitle  string
}

func (o *Obligation) Open() bool { return o.Status == "offen" }
func (o *Obligation) Overdue() bool {
	return o.Open() && !o.DueAt.IsZero() && time.Now().After(o.DueAt)
}

// Sitrep – nummerierte Lagemeldung.
type Sitrep struct {
	ID         int64
	IncidentID int64
	No         int
	At         time.Time
	By         string
	Situation  string
	Impact     string
	Actions    string
	Outlook    string
	Decisions  string
	Next       time.Time
	Phase      string
	Severity   string
}

// AuditEntry – technisches, unveränderliches Prüfprotokoll.
type AuditEntry struct {
	ID         int64
	At         time.Time
	Actor      string
	IP         string
	Action     string
	Object     string
	ObjectID   int64
	IncidentID int64
	Detail     string
}

type User struct {
	Username  string
	Display   string
	Mail      string
	Role      string
	LastLogin time.Time
}

type IncidentFilter struct {
	Query    string
	State    string // aktiv | abgeschlossen | alle
	Severity string
	Category string
	// State: aktiv | abgeschlossen | alle | storniert
}
