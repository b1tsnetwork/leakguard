package config

import (
	"fmt"
	"strings"
)

// Rollen (aufsteigend). Die höchste zutreffende Rolle gilt.
const (
	RoleViewer    = "leser"
	RoleResponder = "bearbeiter"
	RoleLead      = "leitung"
	RoleAdmin     = "admin"
)

var roleRank = map[string]int{RoleViewer: 1, RoleResponder: 2, RoleLead: 3, RoleAdmin: 4}

// RoleRank liefert die Rangfolge einer Rolle (0 = keine).
func RoleRank(r string) int { return roleRank[r] }

// Roles ordnet AD-Gruppen (DN) den globalen Rollen zu.
type Roles struct {
	Admin     []string `yaml:"admin"`
	Lead      []string `yaml:"leitung"`
	Responder []string `yaml:"bearbeiter"`
	Viewer    []string `yaml:"leser"`
}

// Ordered liefert die Rollen von hoch nach niedrig mit ihren Gruppen.
func (r Roles) Ordered() []struct {
	Role   string
	Groups []string
} {
	return []struct {
		Role   string
		Groups []string
	}{{RoleAdmin, r.Admin}, {RoleLead, r.Lead}, {RoleResponder, r.Responder}, {RoleViewer, r.Viewer}}
}

func (r Roles) Empty() bool {
	return len(r.Admin)+len(r.Lead)+len(r.Responder)+len(r.Viewer) == 0
}

// Incident – Einstellungen der Kommandozentrale.
type Incident struct {
	NumberPrefix string        `yaml:"number_prefix"`
	Categories   []Option      `yaml:"categories"`
	Functions    []Option      `yaml:"functions"`
	Regulations  []Regulation  `yaml:"regulations"`
	Playbooks    []Playbook    `yaml:"playbooks"`
	Checklists   []Checklist   `yaml:"checklists"`
	Notify       IncidentNotif `yaml:"notify"`
	Org          Org           `yaml:"org"`
}

type IncidentNotif struct {
	// Bei neuen Vorfällen ab dieser Schwere (P1..P4) eine Mail an diese Adressen senden.
	NewIncidentMinSeverity string   `yaml:"new_incident_min_severity"`
	NewIncidentRecipients  []string `yaml:"new_incident_recipients"`
	// Zugewiesene Personen per Mail über neue Aufgaben informieren (Mailadresse aus dem AD).
	TaskAssigned bool `yaml:"task_assigned"`
}

// Option ist ein Eintrag einer Auswahlliste (Schlüssel + Anzeigename).
type Option struct {
	Key   string `yaml:"key"`
	Label string `yaml:"label"`
	Hint  string `yaml:"hint"`
}

// Regulation beschreibt eine Melde- oder Benachrichtigungspflicht mit Fristen.
type Regulation struct {
	Key       string     `yaml:"key"`
	Label     string     `yaml:"label"`
	Authority string     `yaml:"authority"`
	Hint      string     `yaml:"hint"`
	Deadlines []Deadline `yaml:"deadlines"`
}

// Deadline: Frist in Stunden ab Kenntnisnahme – oder, mit "after", ab Erledigung einer anderen Frist.
type Deadline struct {
	Key   string `yaml:"key"`
	Label string `yaml:"label"`
	Hours int    `yaml:"hours"`
	After string `yaml:"after"`
}

// Playbook legt beim Anlegen eines Vorfalls einer Kategorie Standard-Aufgaben an.
type Playbook struct {
	Category string         `yaml:"category"`
	Tasks    []PlaybookTask `yaml:"tasks"`
}

type PlaybookTask struct {
	Title    string `yaml:"title"`
	Function string `yaml:"function"`
	Priority string `yaml:"priority"`
	DueHours int    `yaml:"due_hours"`
	Details  string `yaml:"details"`
}

// Org beschreibt die eigene Behörde – daraus werden Ansprechstellen in Meldepflichten und Empfehlungen abgeleitet.
type Org struct {
	Type                    string `yaml:"type"` // kommune | land | bund | sonstige
	Name                    string `yaml:"name"`
	CERT                    string `yaml:"cert"`
	DataProtectionAuthority string `yaml:"data_protection_authority"`
	Police                  string `yaml:"police"`
	Supervisory             string `yaml:"supervisory"`
	ITProvider              string `yaml:"it_provider"`
	Leadership              string `yaml:"leadership"`
	Council                 string `yaml:"council"`
	// Für NIS2/BSIG relevante Einrichtung (z. B. Bundesverwaltung, kommunale Versorger)?
	NIS2 bool `yaml:"nis2"`
}

func (o *Org) applyDefaults() {
	if o.Type == "" {
		o.Type = "kommune"
	}
	def := func(dst *string, kommune, land, bund string) {
		if *dst != "" {
			return
		}
		switch o.Type {
		case "bund":
			*dst = bund
		case "land":
			*dst = land
		default:
			*dst = kommune
		}
	}
	def(&o.CERT, "Landes-CERT / Kommunal-CERT", "Landes-CERT", "BSI – CERT-Bund / Nationales IT-Lagezentrum")
	def(&o.DataProtectionAuthority, "Landesbeauftragte/r für Datenschutz (LfD)", "Landesbeauftragte/r für Datenschutz (LfD)", "Bundesbeauftragte/r für den Datenschutz (BfDI)")
	def(&o.Police, "Zentrale Ansprechstelle Cybercrime (ZAC) des LKA", "Zentrale Ansprechstelle Cybercrime (ZAC) des LKA", "Zentrale Ansprechstelle Cybercrime (ZAC) / BKA")
	def(&o.Supervisory, "Kommunalaufsicht", "vorgesetzte Behörde / Fachministerium", "Fach- und Rechtsaufsicht (Ressort)")
	def(&o.ITProvider, "kommunaler IT-Dienstleister / Rechenzentrum", "Landes-IT-Dienstleister", "IT-Dienstleister des Bundes")
	def(&o.Leadership, "Verwaltungsvorstand / (Ober-)Bürgermeister/in bzw. Landrat/Landrätin", "Behördenleitung", "Behördenleitung")
	def(&o.Council, "Rat / Kreistag (Ältestenrat)", "zuständiger Landtagsausschuss (über das Ressort)", "zuständige Ausschüsse (über das Ressort)")
}

// Checklist – Schritte je Phase, die als Empfehlung erscheinen, solange keine gleichnamige Aufgabe existiert.
type Checklist struct {
	Phase string          `yaml:"phase"`
	Steps []ChecklistStep `yaml:"steps"`
}

type ChecklistStep struct {
	Title      string   `yaml:"title"`
	Why        string   `yaml:"why"`
	Ref        string   `yaml:"ref"`
	Function   string   `yaml:"function"`
	Priority   string   `yaml:"priority"`
	DueHours   int      `yaml:"due_hours"`
	Categories []string `yaml:"categories"` // leer = alle
	Severities []string `yaml:"severities"` // leer = alle, z. B. [P1, P2]
}

// Kategorien angelehnt an die ENISA/eCSIRT-Referenztaxonomie, ergänzt um verwaltungstypische Fälle.
var defaultCategories = []Option{
	{Key: "ransomware", Label: "Ransomware / Verschlüsselung"},
	{Key: "malware", Label: "Schadsoftware"},
	{Key: "phishing", Label: "Phishing / Social Engineering"},
	{Key: "credential_leak", Label: "Kompromittierte Zugangsdaten", Hint: "Einzelne geleakte Kennwörter zuerst über die Leak-Prüfung"},
	{Key: "account_compromise", Label: "Kompromittiertes Konto / unbefugter Zugriff"},
	{Key: "data_breach", Label: "Datenabfluss / Datenschutzverletzung"},
	{Key: "service_outage", Label: "Ausfall Fachverfahren / Bürgerdienste"},
	{Key: "dos", Label: "Verfügbarkeit / DDoS (z. B. Webportal, Online-Dienste)"},
	{Key: "vulnerability", Label: "Schwachstelle / Ausnutzung"},
	{Key: "fraud", Label: "Betrug (Rechnungs-/Zahlungsbetrug, CEO-Fraud)"},
	{Key: "insider", Label: "Insider / Fehlverhalten von Beschäftigten"},
	{Key: "device_loss", Label: "Verlust / Diebstahl von Geräten oder Datenträgern"},
	{Key: "supply_chain", Label: "IT-Dienstleister / Rechenzentrum / Lieferkette"},
	{Key: "other", Label: "Sonstiges"},
}

// Stabsfunktionen angelehnt an BSI-Standard 200-4 und FwDV 100 (Verwaltungsstab), ergänzt um Rollen der Verwaltung.
var defaultFunctions = []Option{
	{Key: "lead", Label: "Leitung Stab / Einsatzleitung"},
	{Key: "isb", Label: "Informationssicherheitsbeauftragte/r (ISB)"},
	{Key: "s1", Label: "S1 Personal & Innerer Dienst"},
	{Key: "s2", Label: "S2 Lage & Dokumentation"},
	{Key: "s3", Label: "S3 Einsatz / technische Maßnahmen"},
	{Key: "s4", Label: "S4 Versorgung & Beschaffung"},
	{Key: "s5", Label: "S5 Presse- und Öffentlichkeitsarbeit"},
	{Key: "s6", Label: "S6 IT & Kommunikationstechnik"},
	{Key: "bcm", Label: "Notfallbeauftragte/r (BCM)"},
	{Key: "dpo", Label: "Behördliche/r Datenschutzbeauftragte/r"},
	{Key: "legal", Label: "Justiziariat / Rechtsamt"},
	{Key: "staff_council", Label: "Personalrat (Beteiligung)"},
	{Key: "it_provider", Label: "IT-Dienstleister / Rechenzentrum"},
	{Key: "process_owner", Label: "Fachverfahrensverantwortliche/r"},
	{Key: "forensics", Label: "Forensik / Analyse"},
	{Key: "vs", Label: "Geheimschutzbeauftragte/r (VS)"},
	{Key: "external", Label: "Externer IR-Dienstleister"},
	{Key: "member", Label: "Mitarbeit"},
}

func defaultRegulations(o Org) []Regulation {
	regs := []Regulation{
		{
			Key: "dsgvo", Label: "DSGVO – Verletzung des Schutzes personenbezogener Daten", Authority: o.DataProtectionAuthority,
			Hint: "Art. 33 DSGVO: Meldung binnen 72 h nach Bekanntwerden (für Behörden ebenso). Art. 34: Benachrichtigung Betroffener bei hohem Risiko unverzüglich. Auch die Entscheidung GEGEN eine Meldung ist zu dokumentieren (Art. 33 Abs. 5). Für Polizei/Justiz ggf. Landes-DSG bzw. §§ 65 f. BDSG (JI-Richtlinie).",
			Deadlines: []Deadline{
				{Key: "dsgvo_33", Label: "Meldung an " + o.DataProtectionAuthority + " (Art. 33)", Hours: 72},
				{Key: "dsgvo_34", Label: "Benachrichtigung Betroffener prüfen (Art. 34)", Hours: 72},
			},
		},
		{
			Key: "cert", Label: "Meldung IT-Sicherheitsvorfall an " + o.CERT, Authority: o.CERT,
			Hint: "Meldepflichten bzw. -wege nach Landes-Informationssicherheitsgesetz, Landes-Leitlinie oder BSIG. Meist „unverzüglich“ – hier als 24 h vorbelegt. Erstmeldung auch mit unvollständigen Informationen.",
			Deadlines: []Deadline{
				{Key: "cert_first", Label: "Erstmeldung an " + o.CERT, Hours: 24},
				{Key: "cert_final", Label: "Abschlussmeldung an " + o.CERT, Hours: 720, After: "cert_first"},
			},
		},
		{
			Key: "aufsicht", Label: "Berichtspflicht im Dienstweg (" + o.Supervisory + ")", Authority: o.Supervisory,
			Hint:      "Unterrichtung der Aufsicht bzw. vorgesetzten Stelle über besondere Vorkommnisse (Erlasslage beachten).",
			Deadlines: []Deadline{{Key: "aufsicht_info", Label: "Unterrichtung " + o.Supervisory, Hours: 24}},
		},
		{
			Key: "nis2", Label: "NIS2 / BSIG – erheblicher Sicherheitsvorfall", Authority: "BSI (Meldeportal)",
			Hint: "Für Einrichtungen der Bundesverwaltung und NIS2-pflichtige Einrichtungen (z. B. kommunale Versorger): frühe Erstmeldung 24 h, Meldung 72 h, Abschlussmeldung spätestens einen Monat nach der Meldung.",
			Deadlines: []Deadline{
				{Key: "nis2_early", Label: "Frühe Erstmeldung (BSI)", Hours: 24},
				{Key: "nis2_report", Label: "Meldung (Vorfallmeldung, BSI)", Hours: 72},
				{Key: "nis2_final", Label: "Abschlussmeldung (BSI)", Hours: 720, After: "nis2_report"},
			},
		},
	}
	return regs
}

var defaultPlaybooks = []Playbook{
	{Category: "ransomware", Tasks: []PlaybookTask{
		{Title: "Betroffene Systeme vom Netz trennen (nicht ausschalten – RAM-Forensik)", Function: "s3", Priority: "hoch", DueHours: 1},
		{Title: "Backups prüfen und offline sichern (nicht mit betroffenen Systemen verbinden)", Function: "s6", Priority: "hoch", DueHours: 2},
		{Title: "IT-Dienstleister / Rechenzentrum einbinden und Netzübergänge prüfen", Function: "it_provider", Priority: "hoch", DueHours: 2},
		{Title: "Notbetrieb nach Notfallhandbuch aktivieren (Priorität Bürgerdienste / Fachverfahren laut BIA)", Function: "bcm", Priority: "hoch", DueHours: 4},
		{Title: "Ausbreitung ermitteln: Konten, Freigaben, laterale Bewegung", Function: "forensics", Priority: "hoch", DueHours: 4},
		{Title: "Privilegierte Kennwörter und Dienstkonten zurücksetzen (krbtgt zweimal)", Function: "s3", Priority: "hoch", DueHours: 8},
		{Title: "Grundsatzentscheidung zur Lösegeldforderung durch Behördenleitung dokumentieren", Function: "lead", Priority: "hoch", DueHours: 8,
			Details: "Empfehlung von BSI und Polizei: nicht zahlen. Kontaktaufnahme zu Tätern nur nach Abstimmung mit der Polizei."},
		{Title: "Meldepflichten prüfen (Datenschutz, CERT, Dienstweg)", Function: "isb", Priority: "hoch", DueHours: 12},
		{Title: "Strafanzeige bei der ZAC erstatten", Function: "legal", Priority: "mittel", DueHours: 24},
		{Title: "Information Bürgerinnen und Bürger / Presse abstimmen", Function: "s5", Priority: "mittel", DueHours: 6},
	}},
	{Category: "phishing", Tasks: []PlaybookTask{
		{Title: "Mail-Empfänger ermitteln und Mails aus Postfächern entfernen", Function: "s3", Priority: "hoch", DueHours: 2},
		{Title: "Links/Absender/Anhänge sperren (Proxy, Mail-Gateway)", Function: "s6", Priority: "hoch", DueHours: 2},
		{Title: "Klicks und Anmeldungen der Empfänger prüfen", Function: "forensics", Priority: "hoch", DueHours: 4},
		{Title: "Betroffene Konten sperren / Kennwort zurücksetzen / Sitzungen widerrufen", Function: "s3", Priority: "hoch", DueHours: 4},
		{Title: "Warnhinweis an alle Beschäftigten", Function: "s5", Priority: "mittel", DueHours: 4},
	}},
	{Category: "account_compromise", Tasks: []PlaybookTask{
		{Title: "Konto sperren, Kennwort zurücksetzen, Sitzungen/Token widerrufen", Function: "s3", Priority: "hoch", DueHours: 1},
		{Title: "MFA-Methoden und Weiterleitungs-/Posteingangsregeln prüfen", Function: "s3", Priority: "hoch", DueHours: 2},
		{Title: "Anmelde- und Audit-Logs der letzten 30 Tage auswerten (Personalrat/DSB beteiligen)", Function: "forensics", Priority: "hoch", DueHours: 8},
		{Title: "Zugriff auf personenbezogene Daten / Fachverfahren prüfen (Meldepflicht?)", Function: "dpo", Priority: "mittel", DueHours: 24},
	}},
	{Category: "data_breach", Tasks: []PlaybookTask{
		{Title: "Art und Umfang der betroffenen Daten feststellen (Kategorien, Anzahl Betroffene)", Function: "forensics", Priority: "hoch", DueHours: 12},
		{Title: "Risikobewertung für Betroffene durch behördliche/n DSB (Art. 33/34 DSGVO)", Function: "dpo", Priority: "hoch", DueHours: 24},
		{Title: "Abflussweg schließen", Function: "s3", Priority: "hoch", DueHours: 4},
		{Title: "Benachrichtigung Betroffener / Bürgerinformation vorbereiten", Function: "s5", Priority: "mittel", DueHours: 48},
	}},
	{Category: "malware", Tasks: []PlaybookTask{
		{Title: "System isolieren (EDR-Netzwerkisolation)", Function: "s3", Priority: "hoch", DueHours: 1},
		{Title: "Sample und IOCs sichern, Hashes erfassen", Function: "forensics", Priority: "hoch", DueHours: 4},
		{Title: "Nach IOCs im gesamten Netz suchen", Function: "forensics", Priority: "hoch", DueHours: 8},
		{Title: "System neu aufsetzen und wiederherstellen", Function: "s6", Priority: "mittel", DueHours: 48},
	}},
	{Category: "service_outage", Tasks: []PlaybookTask{
		{Title: "Ursache eingrenzen: Angriff oder technische Störung?", Function: "s6", Priority: "hoch", DueHours: 1},
		{Title: "Notbetrieb / Ersatzverfahren für betroffene Bürgerdienste aktivieren", Function: "bcm", Priority: "hoch", DueHours: 2},
		{Title: "Bürgerinformation (Website, Social Media, Telefonansage) veröffentlichen", Function: "s5", Priority: "hoch", DueHours: 2},
		{Title: "Fachverfahrensverantwortliche und IT-Dienstleister einbinden", Function: "process_owner", Priority: "hoch", DueHours: 2},
	}},
	{Category: "device_loss", Tasks: []PlaybookTask{
		{Title: "Gerät/Konto sperren, Fernlöschung auslösen (MDM)", Function: "s3", Priority: "hoch", DueHours: 1},
		{Title: "Verschlüsselungsstatus und gespeicherte Daten feststellen", Function: "s6", Priority: "hoch", DueHours: 4},
		{Title: "Datenschutzrechtliche Bewertung (Art. 33 DSGVO)", Function: "dpo", Priority: "hoch", DueHours: 24},
		{Title: "Diebstahlsanzeige bei der Polizei", Function: "legal", Priority: "mittel", DueHours: 24},
	}},
	{Category: "insider", Tasks: []PlaybookTask{
		{Title: "Vertraulichkeit sicherstellen (need-to-know), Personalrat und DSB nach PersVG/DSG beteiligen", Function: "staff_council", Priority: "hoch", DueHours: 8},
		{Title: "Rechtliche Bewertung (Dienst-/Disziplinarrecht, Strafrecht) durch Justiziariat", Function: "legal", Priority: "hoch", DueHours: 24},
		{Title: "Beweissicherung gerichtsfest dokumentieren (Chain of Custody)", Function: "forensics", Priority: "hoch", DueHours: 24},
	}},
	{Category: "fraud", Tasks: []PlaybookTask{
		{Title: "Zahlung stoppen / Rückruf bei Bank und Kasse veranlassen", Function: "s4", Priority: "hoch", DueHours: 1},
		{Title: "Strafanzeige erstatten", Function: "legal", Priority: "hoch", DueHours: 24},
		{Title: "Warnhinweis an Kasse/Buchhaltung und Beschäftigte", Function: "s5", Priority: "mittel", DueHours: 8},
	}},
}

// Phasen-Checklisten nach BSI IT-Grundschutz DER.2.1/DER.2.2, BSI-Standard 200-4 und NIST SP 800-61.
var defaultChecklists = []Checklist{
	{Phase: "gemeldet", Steps: []ChecklistStep{
		{Title: "Erstbewertung durchführen: echter Vorfall? betroffene Schutzziele? Schwere?", Function: "isb", Priority: "hoch", DueHours: 1,
			Why: "Frühzeitige Einstufung entscheidet über Eskalation, Stab und Meldefristen.", Ref: "BSI IT-Grundschutz DER.2.1"},
	}},
	{Phase: "triage", Steps: []ChecklistStep{
		{Title: "ISB informieren und Zuständigkeiten (Leitung, Ansprechpartner) festlegen", Function: "isb", Priority: "hoch", DueHours: 1,
			Why: "Der/die ISB koordiniert die Behandlung von Sicherheitsvorfällen.", Ref: "BSI IT-Grundschutz DER.2.1, ISMS.1"},
		{Title: "Meldewege und Meldepflichten prüfen (Datenschutz, CERT, Dienstweg)", Function: "isb", Priority: "hoch", DueHours: 4,
			Why: "Fristen laufen ab Kenntnisnahme – auch bei unklarer Lage ist eine Erstmeldung möglich.", Ref: "Art. 33 DSGVO, Landes-ISG / BSIG"},
	}},
	{Phase: "analyse", Steps: []ChecklistStep{
		{Title: "Zeitlinie des Vorfalls erstellen (erste Kompromittierung bis heute)", Function: "forensics", Priority: "hoch", DueHours: 12,
			Why: "Ohne Zeitlinie lassen sich Umfang, Datenabfluss und Wiederherstellungspunkt nicht bestimmen.", Ref: "BSI IT-Grundschutz DER.2.2"},
		{Title: "Beweismittel sichern (RAM, Datenträger, Logs) mit Chain of Custody", Function: "forensics", Priority: "hoch", DueHours: 4,
			Categories: []string{"ransomware", "malware", "account_compromise", "insider", "data_breach"},
			Why:        "Bereinigung vernichtet Spuren; gerichtsfeste Sicherung ist Voraussetzung für Strafverfolgung und Dienstrecht.", Ref: "BSI IT-Grundschutz DER.2.2.A3"},
		{Title: "Betroffene Fachverfahren und deren Schutzbedarf feststellen (BIA)", Function: "process_owner", Priority: "mittel", DueHours: 12,
			Severities: []string{"P1", "P2"}, Why: "Priorisierung von Eindämmung und Wiederanlauf nach Kritikalität der Verwaltungsleistungen.", Ref: "BSI-Standard 200-4"},
	}},
	{Phase: "eindaemmung", Steps: []ChecklistStep{
		{Title: "Eindämmungsstrategie durch Leitung entscheiden und dokumentieren", Function: "lead", Priority: "hoch", DueHours: 2,
			Why: "Abwägung Beweissicherung / Betriebsfortführung / Beobachtung des Angreifers ist eine Leitungsentscheidung.", Ref: "NIST SP 800-61, BSI DER.2.1"},
	}},
	{Phase: "beseitigung", Steps: []ChecklistStep{
		{Title: "Ursache beseitigen: Schwachstelle schließen, Schadsoftware/Persistenz entfernen", Function: "s3", Priority: "hoch", DueHours: 24,
			Why: "Ohne Ursachenbeseitigung droht Wiederinfektion nach dem Wiederanlauf.", Ref: "BSI IT-Grundschutz DER.2.1"},
		{Title: "Zugangsdaten aller betroffenen Konten und Dienstkonten erneuern", Function: "s3", Priority: "hoch", DueHours: 24,
			Categories: []string{"ransomware", "malware", "account_compromise", "phishing", "credential_leak"},
			Why:        "Abgegriffene Zugangsdaten bleiben sonst gültig.", Ref: "BSI IT-Grundschutz ORP.4"},
	}},
	{Phase: "wiederherstellung", Steps: []ChecklistStep{
		{Title: "Integrität der Backups vor Rücksicherung prüfen", Function: "s6", Priority: "hoch", DueHours: 8,
			Categories: []string{"ransomware", "malware"}, Why: "Backups können bereits kompromittiert sein.", Ref: "BSI IT-Grundschutz CON.3"},
		{Title: "Wiederanlauf nach Wiederanlaufplan (Reihenfolge nach Kritikalität der Fachverfahren)", Function: "bcm", Priority: "hoch", DueHours: 24,
			Severities: []string{"P1", "P2"}, Why: "Geordneter Wiederanlauf verhindert Folgefehler und priorisiert Bürgerdienste.", Ref: "BSI-Standard 200-4"},
		{Title: "Freigabe zur Wiederinbetriebnahme durch Fachverfahrensverantwortliche", Function: "process_owner", Priority: "mittel", DueHours: 24,
			Why: "Fachliche Abnahme dokumentiert die Funktionsfähigkeit und Datenrichtigkeit.", Ref: "BSI-Standard 200-4"},
		{Title: "Erhöhte Überwachung der wiederhergestellten Systeme (mind. 30 Tage)", Function: "s6", Priority: "mittel", DueHours: 24,
			Why: "Angreifer kehren häufig über verbliebene Zugänge zurück.", Ref: "NIST SP 800-61"},
	}},
	{Phase: "nachbereitung", Steps: []ChecklistStep{
		{Title: "Lessons-Learned-Besprechung mit allen Beteiligten durchführen", Function: "isb", Priority: "mittel", DueHours: 336,
			Why: "Erkenntnisse sichern, solange sie präsent sind (Empfehlung: binnen 14 Tagen).", Ref: "BSI IT-Grundschutz DER.2.1.A10"},
		{Title: "Abschlussbericht an die Behördenleitung", Function: "isb", Priority: "mittel", DueHours: 336,
			Why: "Die Leitung trägt die Gesamtverantwortung für die Informationssicherheit.", Ref: "BSI-Standard 200-1/200-2, ISMS.1"},
		{Title: "Sicherheitskonzept, Notfallhandbuch und Playbooks aktualisieren", Function: "isb", Priority: "mittel", DueHours: 720,
			Why: "Kontinuierliche Verbesserung des ISMS (PDCA).", Ref: "BSI-Standard 200-2, DER.2.1"},
	}},
}

func (in *Incident) applyDefaults() {
	in.Org.applyDefaults()
	if in.NumberPrefix == "" {
		in.NumberPrefix = "SI"
	}
	if len(in.Categories) == 0 {
		in.Categories = defaultCategories
	}
	if len(in.Functions) == 0 {
		in.Functions = defaultFunctions
	}
	if in.Regulations == nil {
		in.Regulations = defaultRegulations(in.Org)
	}
	if in.Playbooks == nil {
		in.Playbooks = defaultPlaybooks
	}
	if in.Checklists == nil {
		in.Checklists = defaultChecklists
	}
}

func (in *Incident) validate() []string {
	var errs []string
	seen := map[string]bool{}
	for _, r := range in.Regulations {
		if r.Key == "" || len(r.Deadlines) == 0 {
			errs = append(errs, fmt.Sprintf("incident.regulations: %q braucht key und deadlines", r.Label))
		}
		keys := map[string]bool{}
		for _, d := range r.Deadlines {
			if d.Key == "" || d.Hours <= 0 {
				errs = append(errs, fmt.Sprintf("incident.regulations %q: Frist braucht key und hours > 0", r.Key))
			}
			if seen[d.Key] {
				errs = append(errs, fmt.Sprintf("incident.regulations: Fristschlüssel %q doppelt", d.Key))
			}
			seen[d.Key], keys[d.Key] = true, true
		}
		for _, d := range r.Deadlines {
			if d.After != "" && !keys[d.After] {
				errs = append(errs, fmt.Sprintf("incident.regulations %q: after %q unbekannt (nur Fristen derselben Pflicht)", r.Key, d.After))
			}
		}
	}
	phases := map[string]bool{"gemeldet": true, "triage": true, "analyse": true, "eindaemmung": true, "beseitigung": true, "wiederherstellung": true, "nachbereitung": true}
	for _, c := range in.Checklists {
		if !phases[c.Phase] {
			errs = append(errs, fmt.Sprintf("incident.checklists: Phase %q unbekannt", c.Phase))
		}
	}
	switch in.Org.Type {
	case "kommune", "land", "bund", "sonstige":
	default:
		errs = append(errs, "incident.org.type muss kommune, land, bund oder sonstige sein")
	}
	for _, p := range in.Playbooks {
		if in.Category(p.Category).Key == "" {
			errs = append(errs, fmt.Sprintf("incident.playbooks: Kategorie %q unbekannt", p.Category))
		}
	}
	return errs
}

func find(list []Option, key string) Option {
	for _, o := range list {
		if o.Key == key {
			return o
		}
	}
	return Option{}
}

func (in *Incident) Category(key string) Option { return find(in.Categories, key) }
func (in *Incident) Function(key string) Option { return find(in.Functions, key) }

func (in *Incident) Regulation(key string) (Regulation, bool) {
	for _, r := range in.Regulations {
		if r.Key == key {
			return r, true
		}
	}
	return Regulation{}, false
}

func (in *Incident) Playbook(category string) []PlaybookTask {
	for _, p := range in.Playbooks {
		if strings.EqualFold(p.Category, category) {
			return p.Tasks
		}
	}
	return nil
}
