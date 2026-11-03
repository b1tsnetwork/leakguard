// Package advisor leitet aus dem Zustand eines Vorfalls nachvollziehbare Handlungsempfehlungen ab.
//
// Die Regeln sind bewusst deterministisch und erklärbar (Begründung + Quelle) – es werden keine
// Vorfalldaten an externe Dienste übermittelt. Grundlage: BSI IT-Grundschutz (DER.2.1, DER.2.2, ISMS.1),
// BSI-Standard 200-4 (Notfallmanagement/Stabsarbeit), NIST SP 800-61, DSGVO und Landes-/Bundesrecht.
package advisor

import (
	"fmt"
	"regexp"
	"sort"
	"strings"
	"time"

	"leakguard/internal/config"
	"leakguard/internal/model"
)

// Prioritäten (aufsteigend sortiert = wichtigste zuerst).
const (
	PrioCritical = "kritisch"
	PrioHigh     = "hoch"
	PrioMedium   = "mittel"
	PrioHint     = "hinweis"
)

var prioRank = map[string]int{PrioCritical: 0, PrioHigh: 1, PrioMedium: 2, PrioHint: 3}

// Action beschreibt, was „Übernehmen“ bewirkt.
type Action struct {
	Kind       string // task | playbook | regulation | phase | crisis | link
	Label      string // Beschriftung des Buttons
	Title      string // Aufgabe
	Details    string
	Function   string
	Priority   string
	DueHours   int
	Regulation string
	Phase      string
	Tab        string // für link
	NeedsLead  bool
}

// Rec ist eine einzelne Empfehlung.
type Rec struct {
	Key      string
	Priority string
	Title    string
	Why      string
	Ref      string
	Area     string // Reiter, auf den sich die Empfehlung bezieht
	Action   Action
	Sticky   bool // nicht verwerfbar (erledigt sich durch Handeln, z. B. Fristen)
	Incident *model.Incident
}

// Criterion ist ein Kriterium für den Phasenwechsel.
type Criterion struct {
	Label string
	OK    bool
}

// PhaseCheck bewertet die Reife für die nächste Phase.
type PhaseCheck struct {
	Current  string
	Next     string
	Criteria []Criterion
	Ready    bool
}

// Input ist der vollständige Zustand eines Vorfalls.
type Input struct {
	In          *model.Incident
	Members     []model.Member
	Tasks       []model.Task
	Comms       []model.Communication
	Assets      []model.Asset
	IOCs        []model.IOC
	Obligations []model.Obligation
	Sitreps     []model.Sitrep // neueste zuerst
	Journal     []model.JournalEntry
	Dismissed   map[string]bool
	Cfg         *config.Incident
	Now         time.Time
}

type Result struct {
	Recs  []Rec
	Phase PhaseCheck
}

// Counts für Badges.
func (r Result) Count(prio string) int {
	n := 0
	for _, x := range r.Recs {
		if x.Priority == prio {
			n++
		}
	}
	return n
}

type ctx struct {
	Input
	out []Rec
	org config.Org
}

func (c *ctx) add(r Rec) {
	if c.Dismissed[r.Key] && !r.Sticky {
		return
	}
	for _, x := range c.out {
		if x.Key == r.Key {
			return
		}
	}
	r.Incident = c.In
	c.out = append(c.out, r)
}

// Advise wertet alle Regeln aus.
func Advise(in Input) Result {
	if in.Now.IsZero() {
		in.Now = time.Now()
	}
	if in.Dismissed == nil {
		in.Dismissed = map[string]bool{}
	}
	c := &ctx{Input: in, org: in.Cfg.Org}
	if in.In.Cancelled {
		return Result{}
	}
	if in.In.Phase == model.PhaseClosed {
		c.closedRules()
	} else {
		c.deadlineRules()
		c.leadershipRules()
		c.staffRules()
		c.reportingRules()
		c.communicationRules()
		c.technicalRules()
		c.categoryRules()
		c.taskRules()
		c.phaseRules()
		c.checklistRules()
		c.playbookRule()
	}
	sort.SliceStable(c.out, func(i, j int) bool { return prioRank[c.out[i].Priority] < prioRank[c.out[j].Priority] })
	return Result{Recs: c.out, Phase: c.phaseCheck()}
}

// ---------- Hilfen ----------

func (c *ctx) sev(levels ...string) bool {
	for _, l := range levels {
		if c.In.Severity == l {
			return true
		}
	}
	return false
}

func (c *ctx) cat(cats ...string) bool {
	for _, x := range cats {
		if c.In.Category == x {
			return true
		}
	}
	return false
}

func (c *ctx) phaseIdx(p string) int {
	for i, x := range model.Phases {
		if x.Key == p {
			return i
		}
	}
	return 0
}

func (c *ctx) atLeast(p string) bool { return c.phaseIdx(c.In.Phase) >= c.phaseIdx(p) }
func (c *ctx) atMost(p string) bool  { return c.phaseIdx(c.In.Phase) <= c.phaseIdx(p) }

func (c *ctx) hasFunction(fn string) bool {
	for _, m := range c.Members {
		if m.Function == fn {
			return true
		}
	}
	return false
}

// hasTask prüft, ob eine Aufgabe (offen oder erledigt) zum Muster existiert.
func (c *ctx) hasTask(pattern string) bool {
	re := regexp.MustCompile("(?i)" + pattern)
	for _, t := range c.Tasks {
		if t.Status != "verworfen" && (re.MatchString(t.Title) || re.MatchString(t.Details)) {
			return true
		}
	}
	return false
}

func (c *ctx) hasTaskTitle(title string) bool {
	for _, t := range c.Tasks {
		if strings.EqualFold(strings.TrimSpace(t.Title), strings.TrimSpace(title)) {
			return true
		}
	}
	return false
}

func (c *ctx) hasComm(dir string, parties ...string) bool {
	for _, m := range c.Comms {
		if dir != "" && m.Direction != dir {
			continue
		}
		for _, p := range parties {
			if m.PartyType == p {
				return true
			}
		}
	}
	return false
}

func (c *ctx) hasJournal(kind, pattern string) bool {
	re := regexp.MustCompile("(?i)" + pattern)
	for _, j := range c.Journal {
		if (kind == "" || j.Kind == kind) && re.MatchString(j.Text) {
			return true
		}
	}
	return false
}

func (c *ctx) regActive(key string) bool {
	for _, o := range c.Obligations {
		if o.Regulation == key {
			return true
		}
	}
	return false
}

func (c *ctx) regExists(key string) bool {
	_, ok := c.Cfg.Regulation(key)
	return ok
}

func (c *ctx) since(t time.Time) time.Duration {
	if t.IsZero() {
		return 0
	}
	return c.Now.Sub(t)
}

func dur(d time.Duration) string {
	neg := d < 0
	if neg {
		d = -d
	}
	var s string
	switch {
	case d < time.Hour:
		s = fmt.Sprintf("%d min", int(d.Minutes()))
	case d < 48*time.Hour:
		s = fmt.Sprintf("%d h %d min", int(d.Hours()), int(d.Minutes())%60)
	default:
		s = fmt.Sprintf("%d Tagen", int(d.Hours()/24))
	}
	return s
}

func task(title, fn, prio string, due int, label string) Action {
	if label == "" {
		label = "Als Aufgabe anlegen"
	}
	return Action{Kind: "task", Label: label, Title: title, Function: fn, Priority: prio, DueHours: due}
}

func link(tab, label string) Action { return Action{Kind: "link", Tab: tab, Label: label} }

// ---------- Fristen ----------

func (c *ctx) deadlineRules() {
	for _, o := range c.Obligations {
		if !o.Open() {
			continue
		}
		left := o.DueAt.Sub(c.Now)
		switch {
		case left < 0:
			c.add(Rec{Key: "obl:" + o.Key, Priority: PrioCritical, Sticky: true, Area: "meldepflichten",
				Title: fmt.Sprintf("Frist überschritten: %s", o.Label),
				Why:   fmt.Sprintf("Die Frist ist seit %s abgelaufen. Meldung unverzüglich nachholen und die Gründe für die Verzögerung mitteilen bzw. dokumentieren – oder begründet als „nicht erforderlich“ abschließen.", dur(left)),
				Ref:   "Art. 33 Abs. 1 DSGVO („Gründe für die Verzögerung“), " + o.Authority, Action: link("meldepflichten", "Zur Meldepflicht")})
		case left < 12*time.Hour:
			c.add(Rec{Key: "obl:" + o.Key, Priority: PrioCritical, Sticky: true, Area: "meldepflichten",
				Title: fmt.Sprintf("%s fällig in %s", o.Label, dur(left)),
				Why:   "Eine Erstmeldung ist auch mit unvollständigen Informationen möglich und sollte nicht auf die Analyse warten. Ergänzungen können nachgereicht werden.",
				Ref:   o.Authority, Action: link("meldepflichten", "Zur Meldepflicht")})
		case left < 36*time.Hour:
			c.add(Rec{Key: "obl:" + o.Key, Priority: PrioHigh, Sticky: true, Area: "meldepflichten",
				Title: fmt.Sprintf("%s vorbereiten (fällig in %s)", o.Label, dur(left)),
				Why:   "Meldung rechtzeitig vorbereiten und durch die Leitung freigeben lassen.", Ref: o.Authority,
				Action: task("Meldung vorbereiten: "+o.Label, "isb", "hoch", int(left.Hours())-2, "")})
		}
	}
	if !c.In.NextBriefing.IsZero() && c.Now.After(c.In.NextBriefing) {
		c.add(Rec{Key: "briefing_overdue", Priority: PrioHigh, Sticky: true, Area: "lage",
			Title: fmt.Sprintf("Lagebesprechung seit %s überfällig", dur(c.Now.Sub(c.In.NextBriefing))),
			Why:   "Lagebesprechung durchführen, Ergebnis als neue Lagemeldung festhalten und den nächsten Termin setzen.",
			Ref:   "BSI-Standard 200-4 (Stabsarbeit, Lagevortrag)", Action: link("lage#sitrep-form", "Lagemeldung erstellen")})
	}
}

// ---------- Führung ----------

func (c *ctx) leadershipRules() {
	in := c.In
	if c.sev("P1") && !in.CrisisMode {
		c.add(Rec{Key: "crisis", Priority: PrioCritical, Area: "lage",
			Title: "Stab / Krisenstab einberufen und Lage ausrufen",
			Why:   "Bei kritischen Vorfällen (P1) ist die Bewältigung im Regelbetrieb nicht mehr möglich. Ein Stab mit festen Funktionen, Lagerhythmus und Einsatztagebuch schafft Führungsfähigkeit.",
			Ref:   "BSI-Standard 200-4 (Besondere Aufbauorganisation), FwDV 100", Action: Action{Kind: "crisis", Label: "Lage aktivieren", NeedsLead: true}})
	}
	if in.CrisisMode && in.NextBriefing.IsZero() {
		c.add(Rec{Key: "briefing_rhythm", Priority: PrioHigh, Area: "lage",
			Title: "Lagebesprechungsrhythmus festlegen",
			Why:   "Ein fester Rhythmus (z. B. alle 2–4 Stunden in der Akutphase) synchronisiert Stab, Leitung und Dienstleister.",
			Ref:   "BSI-Standard 200-4 (Stabsarbeit)", Action: link("lage", "Nächste Lagebesprechung setzen")})
	}
	interval := map[string]time.Duration{"P1": 4 * time.Hour, "P2": 12 * time.Hour, "P3": 48 * time.Hour}[in.Severity]
	if interval > 0 && c.atLeast(model.PhaseTriage) {
		last := in.AwarenessAt
		if len(c.Sitreps) > 0 {
			last = c.Sitreps[0].At
		}
		if c.since(last) > interval {
			what := "Noch keine Lagemeldung erstellt"
			if len(c.Sitreps) > 0 {
				what = fmt.Sprintf("Letzte Lagemeldung (Nr. %d) ist %s alt", c.Sitreps[0].No, dur(c.since(last)))
			}
			c.add(Rec{Key: fmt.Sprintf("sitrep:%d", len(c.Sitreps)), Priority: PrioHigh, Sticky: len(c.Sitreps) > 0, Area: "lage",
				Title: "Lagebild aktualisieren",
				Why:   what + ". Ein aktuelles, strukturiertes Lagebild (Lage – Auswirkungen – Maßnahmen – Prognose – Entscheidungsbedarf) ist Grundlage für Entscheidungen der Behördenleitung.",
				Ref:   "BSI-Standard 200-4 (Lagebild)", Action: link("lage#sitrep-form", "Lagemeldung erstellen")})
		}
	}
	if len(c.Sitreps) > 0 && strings.TrimSpace(c.Sitreps[0].Decisions) != "" {
		decided := false
		for _, j := range c.Journal {
			if j.Kind == "decision" && j.At.After(c.Sitreps[0].At) {
				decided = true
				break
			}
		}
		if !decided {
			c.add(Rec{Key: fmt.Sprintf("decisions:%d", c.Sitreps[0].No), Priority: PrioHigh, Area: "tagebuch",
				Title: "Offenen Entscheidungsbedarf herbeiführen und dokumentieren",
				Why:   fmt.Sprintf("Lagemeldung Nr. %d nennt Entscheidungsbedarf: „%s“. Entscheidungen der Leitung (wer, was, warum, Alternativen) gehören ins Einsatztagebuch.", c.Sitreps[0].No, firstLine(c.Sitreps[0].Decisions)),
				Ref:   "BSI-Standard 200-4 (Dokumentation), DER.2.1", Action: link("tagebuch", "Entscheidung eintragen")})
		}
	}
	if c.sev("P1", "P2") && c.atLeast(model.PhaseTriage) {
		var last time.Time
		for _, j := range c.Journal {
			if !j.Auto {
				last = j.At
				break
			}
		}
		limit := map[string]time.Duration{"P1": 3 * time.Hour, "P2": 8 * time.Hour}[in.Severity]
		if (last.IsZero() && c.since(in.CreatedAt) > limit) || (!last.IsZero() && c.since(last) > limit) {
			c.add(Rec{Key: "journal_silent", Priority: PrioMedium, Sticky: true, Area: "tagebuch",
				Title: "Einsatztagebuch fortschreiben",
				Why:   "Seit längerer Zeit keine manuellen Einträge (Feststellungen, Entscheidungen, Maßnahmen). Lückenlose Dokumentation ist Grundlage für Meldungen, Haftungsfragen, Rechnungsprüfung und Lessons Learned.",
				Ref:   "BSI IT-Grundschutz DER.2.1 (Dokumentation)", Action: link("tagebuch", "Eintrag erfassen")})
		}
	}
}

// ---------- Stab ----------

func (c *ctx) staffRules() {
	in := c.In
	type need struct {
		fn, prio, why, ref string
		when               bool
	}
	needs := []need{
		{"isb", PrioHigh, "Der/die Informationssicherheitsbeauftragte koordiniert die Behandlung von Sicherheitsvorfällen und berichtet an die Behördenleitung.", "BSI IT-Grundschutz ISMS.1, DER.2.1", c.sev("P1", "P2", "P3")},
		{"dpo", PrioHigh, "Personenbezogene Daten sind betroffen: Der/die behördliche Datenschutzbeauftragte bewertet das Risiko und berät zur Meldung nach Art. 33/34 DSGVO.", "Art. 38, 39 DSGVO", in.PersonalData || c.cat("data_breach")},
		{"s5", PrioHigh, "Bei kritischen Vorfällen besteht hoher Informationsbedarf bei Bürgerinnen und Bürgern, Presse und Politik – Kommunikation aus einer Hand.", "BSI-Standard 200-4 (Krisenkommunikation)", c.sev("P1") || (in.ImpactA && c.sev("P2"))},
		{"bcm", PrioHigh, "Die Verfügbarkeit ist beeinträchtigt: Notbetrieb und Wiederanlauf nach Notfallhandbuch koordiniert der/die Notfallbeauftragte.", "BSI-Standard 200-4", in.ImpactA && c.sev("P1", "P2")},
		{"staff_council", PrioHigh, "Bei Insider-Fällen und der Auswertung personenbezogener Protokoll- oder Leistungsdaten von Beschäftigten ist der Personalrat nach Personalvertretungsrecht zu beteiligen.", "BPersVG / LPersVG (Mitbestimmung bei technischen Überwachungseinrichtungen)", c.cat("insider")},
		{"legal", PrioMedium, "Rechtliche Bewertung (Strafanzeige, Dienst-/Disziplinarrecht, Vertragsrecht gegenüber Dienstleistern).", "Justiziariat / Rechtsamt", c.cat("insider", "fraud", "data_breach") || (c.sev("P1") && c.cat("ransomware"))},
		{"forensics", PrioMedium, "Gerichtsfeste Spurensicherung erfordert forensische Kompetenz (intern oder BSI-qualifizierter Dienstleister).", "BSI IT-Grundschutz DER.2.2", c.cat("ransomware", "malware", "account_compromise", "insider") && c.sev("P1", "P2")},
		{"it_provider", PrioMedium, "Der IT-Dienstleister/das Rechenzentrum betreibt Netzübergänge, Backups und Fachverfahren – frühe Einbindung beschleunigt Eindämmung und Wiederanlauf.", "BSI IT-Grundschutz OPS.2.3 (Outsourcing)", c.cat("ransomware", "malware", "supply_chain", "service_outage", "dos") && c.sev("P1", "P2")},
		{"vs", PrioHigh, "Der Vorfall ist als VS-NfD eingestuft bzw. betrifft Verschlusssachen – Geheimschutzbeauftragte/n einbinden.", "VSA (Verschlusssachenanweisung)", in.Classification != ""},
	}
	for _, n := range needs {
		if n.when && !c.hasFunction(n.fn) {
			c.add(Rec{Key: "staff:" + n.fn, Priority: n.prio, Area: "stab",
				Title: "In den Stab aufnehmen: " + c.Cfg.Function(n.fn).Label,
				Why:   n.why, Ref: n.ref, Action: Action{Kind: "link", Tab: "stab", Label: "Zum Stab", Function: n.fn}})
		}
	}
}

// ---------- Meldewege ----------

func (c *ctx) reportingRules() {
	in := c.In
	if (in.PersonalData || c.cat("data_breach", "device_loss")) && c.regExists("dsgvo") && !c.regActive("dsgvo") {
		prio := PrioCritical
		why := "Personenbezogene Daten sind betroffen. Die 72-Stunden-Frist nach Art. 33 DSGVO läuft ab Kenntnisnahme – auch für Behörden. Die Prüfung und ihr Ergebnis sind zu dokumentieren, auch wenn keine Meldung erfolgt."
		if !in.PersonalData {
			prio, why = PrioHigh, "Bei dieser Kategorie sind häufig personenbezogene Daten betroffen. Bitte prüfen und die Prüfung dokumentieren."
		}
		c.add(Rec{Key: "reg:dsgvo", Priority: prio, Area: "meldepflichten", Title: "Datenschutzrechtliche Meldepflicht prüfen (Art. 33/34 DSGVO)",
			Why: why, Ref: "Art. 33, 34 DSGVO; " + c.org.DataProtectionAuthority, Action: Action{Kind: "regulation", Regulation: "dsgvo", Label: "Meldepflicht aktivieren", NeedsLead: true}})
	}
	if c.sev("P1", "P2") && c.regExists("cert") && !c.regActive("cert") && !c.cat("device_loss") {
		c.add(Rec{Key: "reg:cert", Priority: PrioHigh, Area: "meldepflichten", Title: "IT-Sicherheitsvorfall an " + c.org.CERT + " melden",
			Why: "Erhebliche Vorfälle sind dem zuständigen CERT zu melden (Landes-ISG, Leitlinie Informationssicherheit, BSIG). Das CERT unterstützt mit Lageinformationen und warnt andere Verwaltungen.",
			Ref: "Landes-Informationssicherheitsgesetz / BSIG; " + c.org.CERT, Action: Action{Kind: "regulation", Regulation: "cert", Label: "Meldepflicht aktivieren", NeedsLead: true}})
	}
	if c.sev("P1", "P2") && c.regExists("aufsicht") && !c.regActive("aufsicht") {
		c.add(Rec{Key: "reg:aufsicht", Priority: PrioMedium, Area: "meldepflichten", Title: "Unterrichtung im Dienstweg: " + c.org.Supervisory,
			Why: "Besondere Vorkommnisse sind der Aufsicht bzw. vorgesetzten Stelle zu berichten (Erlasslage). Frühzeitige Information verhindert, dass die Aufsicht aus der Presse erfährt.",
			Ref: "Berichtspflichten nach Erlass / Kommunalverfassung", Action: Action{Kind: "regulation", Regulation: "aufsicht", Label: "Berichtspflicht aktivieren", NeedsLead: true}})
	}
	if c.org.NIS2 && c.sev("P1", "P2") && c.regExists("nis2") && !c.regActive("nis2") {
		c.add(Rec{Key: "reg:nis2", Priority: PrioCritical, Area: "meldepflichten", Title: "Meldung an das BSI nach NIS2/BSIG prüfen (24 h)",
			Why: "Die Einrichtung ist als NIS2-pflichtig konfiguriert. Erhebliche Sicherheitsvorfälle erfordern eine frühe Erstmeldung binnen 24 Stunden.",
			Ref: "§ 32 BSIG", Action: Action{Kind: "regulation", Regulation: "nis2", Label: "Meldepflicht aktivieren", NeedsLead: true}})
	}
	if c.cat("ransomware", "fraud", "data_breach", "account_compromise", "insider") && c.sev("P1", "P2") &&
		!c.hasComm("", "police") && !c.hasTask(`anzeige|ZAC|polizei`) {
		c.add(Rec{Key: "police", Priority: PrioMedium, Area: "kommunikation", Title: "Strafanzeige bei " + c.org.Police + " erstatten",
			Why: "Cyberangriffe auf Behörden sind Straftaten (u. a. §§ 202a, 303a/b StGB). Die ZAC berät vertraulich, unterstützt bei der Beweissicherung und koordiniert mit anderen Ermittlungen.",
			Ref: "ZAC der Landeskriminalämter / BKA", Action: task("Strafanzeige bei "+c.org.Police+" erstatten", "legal", "mittel", 24, "")})
	}
}

// ---------- Kommunikation ----------

func (c *ctx) communicationRules() {
	in := c.In
	if c.sev("P1", "P2") && !c.hasComm("aus", "management") {
		c.add(Rec{Key: "inform_leadership", Priority: PrioHigh, Area: "kommunikation", Title: "Behördenleitung informieren (" + c.org.Leadership + ")",
			Why: "Die Behördenleitung trägt die Gesamtverantwortung für die Informationssicherheit und muss über erhebliche Vorfälle, Auswirkungen auf Verwaltungsleistungen und Entscheidungsbedarf zeitnah unterrichtet werden.",
			Ref: "BSI-Standard 200-1/200-2 (Verantwortung der Leitung), ISMS.1", Action: link("kommunikation#comm-form", "Information dokumentieren")})
	}
	if c.sev("P1") && c.org.Type == "kommune" && !c.hasComm("aus", "council") {
		c.add(Rec{Key: "inform_council", Priority: PrioMedium, Area: "kommunikation", Title: "Information der politischen Gremien vorbereiten (" + c.org.Council + ")",
			Why: "Bei schwerwiegenden Vorfällen erwarten Rat bzw. Kreistag eine vertrauliche Unterrichtung, bevor Medien berichten. Inhalt mit Presse- und Rechtsamt abstimmen (TLP beachten).",
			Ref: "Kommunalverfassung (Unterrichtungspflicht), Krisenkommunikation", Action: task("Vertrauliche Unterrichtung "+c.org.Council+" vorbereiten", "s5", "mittel", 24, "")})
	}
	if in.ImpactA && c.sev("P1", "P2") && !c.hasComm("aus", "citizens", "press") {
		c.add(Rec{Key: "inform_citizens", Priority: PrioHigh, Area: "kommunikation", Title: "Bürgerinnen und Bürger über eingeschränkte Erreichbarkeit informieren",
			Why: "Verwaltungsleistungen sind beeinträchtigt. Proaktive Information (Website, Social Media, Telefonansage, Aushang) reduziert Anfragen und sichert Vertrauen. Keine technischen Details veröffentlichen.",
			Ref: "BSI-Standard 200-4 (Krisenkommunikation)", Action: task("Bürgerinformation zu eingeschränkten Diensten veröffentlichen", "s5", "hoch", 4, "")})
	}
	if (c.cat("phishing") || (c.cat("malware") && c.sev("P1", "P2"))) && !c.hasComm("aus", "staff") {
		c.add(Rec{Key: "warn_staff", Priority: PrioMedium, Area: "kommunikation", Title: "Warnhinweis an alle Beschäftigten",
			Why: "Weitere Beschäftigte haben vermutlich ähnliche Nachrichten erhalten. Ein kurzer Warnhinweis mit Erkennungsmerkmalen und Meldeweg verhindert weitere Klicks.",
			Ref: "BSI IT-Grundschutz ORP.3 (Sensibilisierung)", Action: task("Warnhinweis an alle Beschäftigten versenden", "s5", "mittel", 4, "")})
	}
	for _, m := range c.Comms {
		if m.ReplyOverdue() {
			c.add(Rec{Key: fmt.Sprintf("comm_overdue:%d", m.ID), Priority: PrioHigh, Sticky: true, Area: "kommunikation",
				Title: "Antwort überfällig: " + m.Subject,
				Why:   fmt.Sprintf("Anfrage von %s ist seit %s überfällig.", strings.TrimSpace(m.Party+" ("+partyLabel(m.PartyType)+")"), dur(c.Now.Sub(m.ReplyDue))),
				Ref:   "Kommunikationsplan", Action: link("kommunikation", "Zur Anfrage")})
		}
		if m.PendingApproval() && c.since(m.CreatedAt) > time.Hour {
			c.add(Rec{Key: fmt.Sprintf("comm_approval:%d", m.ID), Priority: PrioHigh, Sticky: true, Area: "kommunikation",
				Title: "Freigabe ausstehend: " + m.Subject,
				Why:   fmt.Sprintf("Externe Kommunikation wartet seit %s auf Freigabe durch die Leitung.", dur(c.since(m.CreatedAt))),
				Ref:   "Vier-Augen-Prinzip externe Kommunikation", Action: link("kommunikation", "Zur Freigabe")})
		}
	}
}

func partyLabel(k string) string {
	for _, p := range model.CommParties {
		if p.Key == k {
			return p.Label
		}
	}
	return k
}

// ---------- Technik ----------

func (c *ctx) technicalRules() {
	var compromised, accounts []string
	for _, a := range c.Assets {
		if a.Status == "kompromittiert" {
			compromised = append(compromised, a.Name)
			if a.Kind == "account" {
				accounts = append(accounts, a.Name)
			}
		}
	}
	if len(compromised) > 0 && c.atMost(model.PhaseContainment) {
		c.add(Rec{Key: "isolate:" + strings.Join(compromised, ","), Priority: PrioCritical, Area: "systeme",
			Title: fmt.Sprintf("Kompromittierte Systeme isolieren (%s)", strings.Join(compromised, ", ")),
			Why:   "Solange kompromittierte Systeme und Konten erreichbar sind, kann sich der Angriff ausbreiten oder Daten abfließen. Systeme vom Netz trennen, aber nicht ausschalten (flüchtige Spuren).",
			Ref:   "BSI IT-Grundschutz DER.2.1, NIST SP 800-61 (Containment)", Action: link("systeme", "Status aktualisieren")})
	}
	if len(accounts) > 0 && !c.hasTask(`kennwort|passwort|sitzung|token`) {
		c.add(Rec{Key: "accounts:" + strings.Join(accounts, ","), Priority: PrioHigh, Area: "aufgaben",
			Title: "Kompromittierte Konten absichern: " + strings.Join(accounts, ", "),
			Why:   "Kennwort zurücksetzen, aktive Sitzungen und Token widerrufen, MFA-Methoden und Weiterleitungsregeln prüfen – sonst bleibt der Zugriff des Angreifers bestehen.",
			Ref:   "BSI IT-Grundschutz ORP.4", Action: task("Konten absichern (Kennwort, Sitzungen, MFA, Regeln): "+strings.Join(accounts, ", "), "s3", "hoch", 2, "")})
	}
	if len(c.Assets) == 0 && c.atLeast(model.PhaseAnalysis) && !c.cat("fraud") {
		c.add(Rec{Key: "assets_none", Priority: PrioMedium, Area: "systeme", Title: "Betroffene und untersuchte Systeme erfassen",
			Why: "Ohne Systemübersicht sind Umfang, Fortschritt der Bereinigung und Wiederanlauf nicht steuerbar.",
			Ref: "BSI IT-Grundschutz DER.2.1", Action: link("systeme#asset-form", "System erfassen")})
	}
	if len(c.IOCs) > 0 && !c.hasTask(`IOC|sperr|block`) {
		c.add(Rec{Key: "iocs_block", Priority: PrioHigh, Area: "iocs", Title: "IOCs sperren und netzweit suchen",
			Why: fmt.Sprintf("%d Indikatoren erfasst. Sperren in Firewall, Proxy, Mail-Gateway und EDR sowie eine Suche in Logs aller Systeme decken weitere Betroffene auf. IOCs an das CERT weitergeben (TLP beachten).", len(c.IOCs)),
			Ref: "BSI IT-Grundschutz DER.2.1, DER.1", Action: task("IOCs in Firewall/Proxy/Mail-Gateway/EDR sperren und netzweit suchen", "s6", "hoch", 4, "")})
	}
	if c.cat("ransomware", "malware", "account_compromise", "insider", "data_breach") && c.atMost(model.PhaseContainment) &&
		!c.hasTask(`beweis|forens|sicher.*(ram|speicher|log)|image`) {
		c.add(Rec{Key: "evidence", Priority: PrioHigh, Area: "aufgaben", Title: "Beweismittel sichern, bevor bereinigt wird",
			Why: "Arbeitsspeicher, Datenträger-Images und Protokolle mit Zeitstempel und Übergabekette (Chain of Custody) sichern. Nach der Neuinstallation sind diese Spuren verloren.",
			Ref: "BSI IT-Grundschutz DER.2.2.A3 (Sicherung von Beweismitteln)", Action: task("Beweismittel sichern (RAM, Images, Logs) mit Chain of Custody", "forensics", "hoch", 4, "")})
	}
}

// ---------- Kategorie ----------

func (c *ctx) categoryRules() {
	in := c.In
	if c.cat("ransomware") && !c.hasJournal("decision", `lösegeld|zahl`) && !c.hasTask(`lösegeld`) {
		c.add(Rec{Key: "ransom_decision", Priority: PrioHigh, Area: "tagebuch", Title: "Grundsatzentscheidung zur Lösegeldforderung dokumentieren",
			Why: "BSI und Polizei raten von Zahlungen ab; für Behörden kommen haushalts- und strafrechtliche Bedenken hinzu. Die Entscheidung der Behördenleitung ist ausdrücklich zu dokumentieren.",
			Ref: "BSI-Empfehlungen Ransomware, Haushaltsrecht", Action: link("tagebuch", "Entscheidung eintragen")})
	}
	if in.ImpactA && c.sev("P1", "P2") && !c.hasTask(`notbetrieb|notfall|ersatzverfahren|papier`) {
		c.add(Rec{Key: "emergency_ops", Priority: PrioHigh, Area: "aufgaben", Title: "Notbetrieb nach Notfallhandbuch aktivieren",
			Why: "Kritische Verwaltungsleistungen (z. B. Meldewesen, Sozialleistungen, Kfz-Zulassung, Leitstellen) müssen auch ohne IT erbracht werden können – Ersatzverfahren und Papiernotbetrieb nach Priorität der Business Impact Analyse.",
			Ref: "BSI-Standard 200-4 (Notbetrieb)", Action: task("Notbetrieb nach Notfallhandbuch aktivieren (Priorität laut BIA)", "bcm", "hoch", 4, "")})
	}
	if c.cat("insider") && !in.Confidential {
		c.add(Rec{Key: "insider_confidential", Priority: PrioHigh, Area: "lage", Title: "Vorfall als vertraulich (need-to-know) kennzeichnen",
			Why: "Insider-Verdachtsfälle betreffen Persönlichkeitsrechte von Beschäftigten. Der Kreis der Beteiligten ist auf das Notwendige zu beschränken.",
			Ref: "Personalaktenrecht, DSGVO Art. 5 Abs. 1 lit. f", Action: link("lage#edit-incident", "Stammdaten bearbeiten")})
	}
	if c.cat("supply_chain") && !c.hasTask(`vertrag|dienstleister|auftragsverarbeit`) {
		c.add(Rec{Key: "supplier_contract", Priority: PrioMedium, Area: "aufgaben", Title: "Vertragliche Pflichten des Dienstleisters einfordern",
			Why: "Meldepflichten, Mitwirkungspflichten und Informationsrechte aus Vertrag und Auftragsverarbeitungsvertrag (Art. 28 DSGVO) nutzen.",
			Ref: "Art. 28 DSGVO, BSI IT-Grundschutz OPS.2.3", Action: task("Dienstleister: Bericht, Mitwirkung und Nachweise nach Vertrag/AVV anfordern", "legal", "mittel", 24, "")})
	}
	if c.cat("credential_leak", "account_compromise", "phishing") && !c.hasTask(`MFA|anmeld|konto prüfen|logs`) {
		c.add(Rec{Key: "account_review", Priority: PrioMedium, Area: "aufgaben", Title: "Anmeldeverlauf der betroffenen Konten prüfen",
			Why: "Anmeldungen aus ungewöhnlichen Netzen, neue MFA-Methoden und Posteingangsregeln sind typische Spuren einer Kontoübernahme.",
			Ref: "BSI IT-Grundschutz OPS.1.1.5 (Protokollierung)", Action: task("Anmeldeverlauf, MFA-Methoden und Postfachregeln der betroffenen Konten prüfen", "forensics", "mittel", 8, "")})
	}
}

// ---------- Aufgaben ----------

func (c *ctx) taskRules() {
	var overdue, unassigned []string
	for _, t := range c.Tasks {
		if t.Overdue() {
			overdue = append(overdue, fmt.Sprintf("#%d", t.ID))
		}
		if t.Open() && t.Priority == "hoch" && t.Assignee == "" {
			unassigned = append(unassigned, fmt.Sprintf("#%d", t.ID))
		}
	}
	if len(overdue) > 0 {
		c.add(Rec{Key: "tasks_overdue", Priority: PrioHigh, Sticky: true, Area: "aufgaben",
			Title: fmt.Sprintf("%d Aufgabe(n) überfällig (%s)", len(overdue), strings.Join(overdue, ", ")),
			Why:   "Überfällige Aufträge in der nächsten Lagebesprechung nachsteuern: Rückmeldung einholen, neu priorisieren oder Ressourcen zuweisen.",
			Ref:   "Stabsarbeit (Auftragscontrolling)", Action: link("aufgaben", "Zu den Aufgaben")})
	}
	if len(unassigned) > 0 {
		c.add(Rec{Key: "tasks_unassigned", Priority: PrioMedium, Sticky: true, Area: "aufgaben",
			Title: fmt.Sprintf("%d Aufgabe(n) mit hoher Priorität ohne Zuständigkeit (%s)", len(unassigned), strings.Join(unassigned, ", ")),
			Why:   "Aufträge ohne verantwortliche Person werden erfahrungsgemäß nicht erledigt.", Ref: "Stabsarbeit", Action: link("aufgaben", "Zuweisen")})
	}
}

// ---------- Phasen ----------

func (c *ctx) phaseRules() {
	pc := c.phaseCheck()
	if pc.Next == "" {
		return
	}
	in := c.In
	if in.Phase == model.PhaseReported && c.since(in.CreatedAt) > 30*time.Minute {
		c.add(Rec{Key: "phase:triage", Priority: PrioHigh, Area: "lage", Title: "Triage beginnen",
			Why: "Der Vorfall ist seit über 30 Minuten gemeldet, aber noch nicht bewertet.", Ref: "BSI IT-Grundschutz DER.2.1",
			Action: Action{Kind: "phase", Phase: model.PhaseTriage, Label: "Phase „Triage“ setzen", NeedsLead: true}})
		return
	}
	if pc.Ready {
		label := labelOf(model.Phases, pc.Next)
		var ok []string
		for _, cr := range pc.Criteria {
			ok = append(ok, cr.Label)
		}
		c.add(Rec{Key: "phase:" + pc.Next, Priority: PrioMedium, Area: "lage", Title: "Nächste Phase möglich: " + label,
			Why: "Alle Kriterien sind erfüllt: " + strings.Join(ok, "; ") + ".", Ref: "NIST SP 800-61 (Incident-Response-Lebenszyklus)",
			Action: Action{Kind: "phase", Phase: pc.Next, Label: "Phase „" + label + "“ setzen", NeedsLead: true}})
	}
}

func labelOf(list []model.Labeled, k string) string {
	for _, l := range list {
		if l.Key == k {
			return l.Label
		}
	}
	return k
}

// phaseCheck bewertet die Kriterien für den Übergang in die nächste Phase.
func (c *ctx) phaseCheck() PhaseCheck {
	in := c.In
	pc := PhaseCheck{Current: in.Phase}
	idx := c.phaseIdx(in.Phase)
	if idx+1 >= len(model.Phases) {
		return pc
	}
	pc.Next = model.Phases[idx+1].Key
	add := func(label string, ok bool) { pc.Criteria = append(pc.Criteria, Criterion{Label: label, OK: ok}) }
	count := func(states ...string) int {
		n := 0
		for _, a := range c.Assets {
			for _, s := range states {
				if a.Status == s {
					n++
				}
			}
		}
		return n
	}
	openTasks, openObl := 0, 0
	for _, t := range c.Tasks {
		if t.Open() {
			openTasks++
		}
	}
	for _, o := range c.Obligations {
		if o.Open() {
			openObl++
		}
	}
	switch in.Phase {
	case model.PhaseReported:
		add("Leitung benannt", in.Lead != "")
		add("Erstinformation erfasst", strings.TrimSpace(in.Description) != "")
	case model.PhaseTriage:
		add("Schwere und Kategorie bewertet", in.Severity != "" && in.Category != "")
		add("ISB im Stab", c.hasFunction("isb") || c.sev("P4"))
		add("Meldepflichten geprüft", len(c.Obligations) > 0 || c.Dismissed["reg:dsgvo"] || c.Dismissed["reg:cert"] || (!in.PersonalData && c.sev("P3", "P4")))
	case model.PhaseAnalysis:
		add("Betroffene Systeme erfasst", len(c.Assets) > 0)
		add("Umfang beschrieben (Lagemeldung vorhanden)", len(c.Sitreps) > 0)
	case model.PhaseContainment:
		add("Keine kompromittierten Systeme mehr am Netz", count("kompromittiert", "verdacht") == 0)
		add("Eindämmungsentscheidung dokumentiert", c.hasJournal("decision", ".") || c.sev("P3", "P4"))
	case model.PhaseEradication:
		add("Alle Systeme bereinigt, wiederhergestellt oder nicht betroffen", count("kompromittiert", "verdacht", "in_untersuchung", "isoliert") == 0)
		add("Ursache bekannt (Feststellung im Tagebuch oder Nachbereitung)", strings.TrimSpace(in.RootCause) != "" || c.hasJournal("observation", "ursache|einfallstor|schwachstelle"))
	case model.PhaseRecovery:
		add("Alle Systeme wiederhergestellt oder nicht betroffen", count("kompromittiert", "verdacht", "in_untersuchung", "isoliert", "bereinigt") == 0)
		add("Keine offenen Aufgaben mit hoher Priorität", !c.openHigh())
	case model.PhasePostIncident:
		add("Ursache dokumentiert", strings.TrimSpace(in.RootCause) != "")
		add("Lessons Learned dokumentiert", strings.TrimSpace(in.Lessons) != "")
		add("Alle Aufgaben erledigt", openTasks == 0)
		add("Alle Meldepflichten abgeschlossen", openObl == 0)
	}
	pc.Ready = len(pc.Criteria) > 0
	for _, cr := range pc.Criteria {
		pc.Ready = pc.Ready && cr.OK
	}
	return pc
}

func (c *ctx) openHigh() bool {
	for _, t := range c.Tasks {
		if t.Open() && t.Priority == "hoch" {
			return true
		}
	}
	return false
}

// ---------- Checklisten & Playbook ----------

func (c *ctx) checklistRules() {
	for _, cl := range c.Cfg.Checklists {
		if cl.Phase != c.In.Phase {
			continue
		}
		for i, st := range cl.Steps {
			if len(st.Categories) > 0 && !c.cat(st.Categories...) {
				continue
			}
			if len(st.Severities) > 0 && !c.sev(st.Severities...) {
				continue
			}
			if c.hasTaskTitle(st.Title) {
				continue
			}
			prio := PrioMedium
			if st.Priority == "hoch" {
				prio = PrioHigh
			}
			c.add(Rec{Key: fmt.Sprintf("chk:%s:%d", cl.Phase, i), Priority: prio, Area: "aufgaben",
				Title: st.Title, Why: st.Why, Ref: st.Ref, Action: task(st.Title, st.Function, orDefault(st.Priority, "mittel"), st.DueHours, "")})
		}
	}
}

func (c *ctx) playbookRule() {
	pb := c.Cfg.Playbook(c.In.Category)
	missing := 0
	for _, t := range pb {
		if !c.hasTaskTitle(t.Title) {
			missing++
		}
	}
	if missing > 0 && missing == len(pb) {
		c.add(Rec{Key: "playbook", Priority: PrioMedium, Area: "aufgaben",
			Title: fmt.Sprintf("Playbook „%s“ übernehmen (%d Standardaufgaben)", c.Cfg.Category(c.In.Category).Label, missing),
			Why:   "Für diese Vorfallart gibt es erprobte Standardmaßnahmen. Übernommene Aufgaben können einzeln angepasst oder verworfen werden.",
			Ref:   "Playbooks (Konfiguration)", Action: Action{Kind: "playbook", Label: "Aufgaben anlegen"}})
	}
}

// ---------- Abgeschlossen ----------

func (c *ctx) closedRules() {
	in := c.In
	if strings.TrimSpace(in.Lessons) == "" {
		c.add(Rec{Key: "closed_lessons", Priority: PrioMedium, Area: "nachbereitung", Title: "Lessons Learned nachtragen",
			Why: "Der Vorfall ist abgeschlossen, aber ohne dokumentierte Erkenntnisse. Ohne Nachbereitung fehlt die Grundlage zur Verbesserung des ISMS.",
			Ref: "BSI IT-Grundschutz DER.2.1.A10", Action: link("nachbereitung", "Nachbereitung öffnen")})
	}
	for _, t := range c.Tasks {
		if t.Open() {
			c.add(Rec{Key: "closed_tasks", Priority: PrioHint, Sticky: true, Area: "aufgaben", Title: "Abgeschlossener Vorfall hat offene Aufgaben",
				Why: "Offene Aufgaben erledigen oder begründet verwerfen.", Action: link("aufgaben", "Zu den Aufgaben")})
			break
		}
	}
}

func orDefault(v, d string) string {
	if v == "" {
		return d
	}
	return v
}

func firstLine(s string) string {
	s, _, _ = strings.Cut(strings.TrimSpace(s), "\n")
	if len(s) > 160 {
		s = s[:160] + "…"
	}
	return s
}
