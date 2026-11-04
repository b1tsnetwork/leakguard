package workflow

import (
	"leakguard/internal/config"
)

// ---------- Stabspositionen (Startbestand) ----------

type posInfo struct {
	short, color, group, desc, why, ref, role string
	duties                                    []string
}

// Erläuterungen angelehnt an BSI-Standard 200-4 (Stabsarbeit), FwDV 100 / Verwaltungsstab und IT-Grundschutz.
var posDefaults = map[string]posInfo{
	"lead": {"L", "#1f5fbf", "fuehrung", "Leitet die Bewältigung des Vorfalls, trifft Entscheidungen und verantwortet die Dokumentation gegenüber der Behördenleitung.",
		"Ohne eindeutige Leitung bleiben Entscheidungen liegen oder werden widersprüchlich getroffen. Die Leitung bündelt Lage, Entscheidungen und Kommunikation.",
		"BSI-Standard 200-4 (Stabsleitung)", "leitung",
		[]string{"Lagebesprechungen einberufen und leiten", "Entscheidungen treffen und begründen", "Stab zusammenstellen und Aufgaben verteilen", "Behördenleitung unterrichten"}},
	"isb": {"ISB", "#7c3aed", "fachberatung", "Koordiniert die Behandlung von Sicherheitsvorfällen, bewertet Sicherheitsauswirkungen und Meldepflichten.",
		"Der/die Informationssicherheitsbeauftragte ist nach IT-Grundschutz für die Vorfallbehandlung zuständig und berichtet direkt an die Behördenleitung.",
		"BSI IT-Grundschutz ISMS.1, DER.2.1", "mitglied",
		[]string{"Erstbewertung und Einstufung", "Meldepflichten (CERT, Aufsicht) prüfen", "Sicherheitsmaßnahmen fachlich bewerten", "Lessons Learned und Abschlussbericht"}},
	"s1": {"S1", "#0e7490", "stab", "Personal und innerer Dienst: Schichtplanung, Erreichbarkeit, Arbeitsfähigkeit des Stabs.",
		"Bei länger andauernden Lagen müssen Personal, Ablösung und Erreichbarkeit organisiert werden – sonst brennt der Stab aus.",
		"FwDV 100, BSI-Standard 200-4", "mitglied", []string{"Schicht- und Ablöseplanung", "Erreichbarkeitslisten", "Räume, Verpflegung, Arbeitsfähigkeit"}},
	"s2": {"S2", "#0891b2", "stab", "Lage und Dokumentation: führt Lagebild, Einsatztagebuch und Lagemeldungen.",
		"Ein aktuelles Lagebild ist Grundlage jeder Entscheidung; die lückenlose Dokumentation ist für Meldungen, Rechenschaft und Beweisführung zwingend.",
		"BSI-Standard 200-4 (Lagedarstellung, Dokumentation)", "mitglied", []string{"Einsatztagebuch führen", "Lagemeldungen erstellen", "Lagebesprechungen vorbereiten", "Fristen überwachen"}},
	"s3": {"S3", "#b45309", "stab", "Einsatz: plant und steuert technische Sofort-, Eindämmungs- und Bereinigungsmaßnahmen.",
		"Technische Maßnahmen müssen koordiniert erfolgen, damit Eindämmung, Beweissicherung und Betrieb sich nicht gegenseitig behindern.",
		"BSI IT-Grundschutz DER.2.1", "mitglied", []string{"Isolation und Sperrung", "Bereinigung und Härtung", "Koordination der Technikteams"}},
	"s4": {"S4", "#4d7c0f", "stab", "Versorgung und Beschaffung: Hardware, Dienstleister, Haushaltsmittel, Zahlungsverkehr.",
		"Ersatzhardware, externe Dienstleister und Notfallbeschaffungen brauchen eine haushaltsrechtlich saubere, schnelle Abwicklung.",
		"FwDV 100, Haushaltsrecht (Notfallbeschaffung)", "mitglied", []string{"Ersatzbeschaffung", "Beauftragung externer Dienstleister", "Zahlungsstopps / Kasse"}},
	"s5": {"S5", "#db2777", "stab", "Presse- und Öffentlichkeitsarbeit: Kommunikation mit Bürgerinnen und Bürgern, Presse, Beschäftigten und Politik.",
		"Bürgerdienste und Vertrauen hängen an verlässlicher Information aus einer Hand; widersprüchliche Aussagen schaden der Behörde und können Ermittlungen gefährden.",
		"BSI-Standard 200-4 (Krisenkommunikation)", "mitglied", []string{"Sprachregelungen abstimmen", "Bürgerinformation (Website, Telefonansage)", "Presseanfragen", "Information der Beschäftigten"}},
	"s6": {"S6", "#475569", "stab", "IT und Kommunikationstechnik: Infrastruktur, Backups, Ausweichkommunikation.",
		"Fällt die IT aus, muss der Stab trotzdem kommunizieren können; Backups und Infrastruktur sind Voraussetzung für den Wiederanlauf.",
		"BSI IT-Grundschutz CON.3, OPS.1.1", "mitglied", []string{"Backups sichern und prüfen", "Ausweichkommunikation (Telefon, Messenger, Papier)", "Wiederaufbau der Infrastruktur"}},
	"bcm": {"BCM", "#ea580c", "fachberatung", "Notfallbeauftragte/r: aktiviert Notbetrieb und Wiederanlauf nach Notfallhandbuch.",
		"Ist die Verfügbarkeit betroffen, entscheidet die geordnete Notfallvorsorge (BIA, Wiederanlaufpläne), welche Bürgerdienste zuerst wieder laufen.",
		"BSI-Standard 200-4", "mitglied", []string{"Notbetrieb aktivieren", "Wiederanlauf nach Kritikalität steuern", "Notfallhandbuch fortschreiben"}},
	"dpo": {"DSB", "#16a34a", "beteiligung", "Behördliche/r Datenschutzbeauftragte/r: bewertet Risiken für Betroffene und berät zu Meldungen nach Art. 33/34 DSGVO.",
		"Sind personenbezogene Daten betroffen, läuft die 72-Stunden-Frist. Der/die DSB ist frühzeitig einzubinden (Art. 38 Abs. 1 DSGVO) und bewertet das Risiko.",
		"Art. 33, 34, 38, 39 DSGVO", "beobachter", []string{"Risikobewertung für Betroffene", "Meldung an die Aufsichtsbehörde vorbereiten", "Benachrichtigung Betroffener prüfen"}},
	"legal": {"R", "#9333ea", "beteiligung", "Justiziariat / Rechtsamt: Strafanzeige, Dienst- und Disziplinarrecht, Verträge mit Dienstleistern.",
		"Strafanzeigen, Ansprüche gegen Dienstleister und dienstrechtliche Schritte brauchen eine rechtssichere Grundlage.",
		"Justiziariat / Rechtsamt", "beobachter", []string{"Strafanzeige", "Vertragsrechtliche Bewertung", "Dienst-/Disziplinarrecht"}},
	"staff_council": {"PR", "#be123c", "beteiligung", "Personalrat: Beteiligung nach Personalvertretungsrecht.",
		"Werden Protokoll-, Leistungs- oder Verhaltensdaten von Beschäftigten ausgewertet oder Insider-Fälle untersucht, hat der Personalrat Beteiligungsrechte.",
		"BPersVG / LPersVG (Mitbestimmung bei technischen Überwachungseinrichtungen)", "beobachter", []string{"Beteiligung bei Auswertungen von Beschäftigtendaten", "Begleitung von Insider-Fällen"}},
	"it_provider": {"IT-DL", "#64748b", "extern", "IT-Dienstleister / Rechenzentrum: betreibt Netze, Fachverfahren und Backups.",
		"Viele Behörden betreiben ihre IT über kommunale oder Landes-Rechenzentren – ohne sie gelingen weder Eindämmung an Netzübergängen noch Wiederanlauf.",
		"BSI IT-Grundschutz OPS.2.3 (Nutzung von Outsourcing)", "mitglied", []string{"Netzübergänge sperren", "Logs bereitstellen", "Fachverfahren wiederherstellen"}},
	"process_owner": {"FV", "#0d9488", "fachberatung", "Fachverfahrensverantwortliche/r: kennt Prozesse, Daten und Schutzbedarf der betroffenen Verwaltungsleistung.",
		"Nur die Fachseite kann bewerten, welche Leistung wie kritisch ist, welche Daten betroffen sind und ob ein Verfahren wieder freigegeben werden kann.",
		"BSI-Standard 200-4 (BIA)", "mitglied", []string{"Schutzbedarf / Kritikalität bewerten", "Ersatzverfahren organisieren", "Fachliche Freigabe zum Wiederanlauf"}},
	"forensics": {"F", "#c2410c", "fachberatung", "Forensik / Analyse: sichert Beweise gerichtsfest und rekonstruiert den Angriff.",
		"Bereinigung vernichtet Spuren. Ohne Beweissicherung lassen sich Umfang, Datenabfluss und Täterweg nicht klären – und Strafverfolgung scheitert.",
		"BSI IT-Grundschutz DER.2.2", "mitglied", []string{"Beweissicherung (Chain of Custody)", "Zeitlinie und Angriffsweg", "IOC-Suche im Netz"}},
	"vs": {"GSB", "#991b1b", "beteiligung", "Geheimschutzbeauftragte/r: Umgang mit Verschlusssachen.",
		"Betrifft der Vorfall Verschlusssachen, gelten die Regeln der Verschlusssachenanweisung für Meldung, Kommunikation und Dokumentation.",
		"VSA (Verschlusssachenanweisung)", "beobachter", []string{"VS-Bewertung", "Meldung nach VSA", "VS-gerechte Kommunikation"}},
	"external": {"EXT", "#6b7280", "extern", "Externer IR-Dienstleister (z. B. BSI-qualifiziert): Unterstützung bei Analyse und Bereinigung.",
		"Bei schweren Vorfällen übersteigen Analyse und Bereinigung oft die eigenen Kapazitäten; qualifizierte Dienstleister beschleunigen und sichern Beweise.",
		"BSI: qualifizierte APT-Response-Dienstleister", "mitglied", []string{"Forensische Analyse", "Bereinigung", "Beratung der Leitung"}},
	"member": {"M", "#94a3b8", "stab", "Mitarbeit ohne feste Stabsfunktion.", "", "", "mitglied", nil},
}

// DefaultPositions baut die Positionsbibliothek aus den konfigurierten Funktionen.
func DefaultPositions(funcs []config.Option) []Position {
	var out []Position
	for i, f := range funcs {
		p := Position{Key: f.Key, Label: f.Label, Description: f.Hint, Sort: (i + 1) * 10, Role: "mitglied", Group: "stab", Color: "#64748b"}
		if d, ok := posDefaults[f.Key]; ok {
			p.Short, p.Color, p.Group, p.Why, p.Ref, p.Role, p.Duties = d.short, d.color, d.group, d.why, d.ref, d.role, d.duties
			if p.Description == "" {
				p.Description = d.desc
			}
		}
		out = append(out, p)
	}
	return out
}

// ---------- Bausteine ----------

type opt func(*Step)

func st(id, phase, pos, prio string, due int, title, why, ref string, o ...opt) Step {
	s := Step{ID: id, Phase: phase, Position: pos, Priority: prio, DueHours: due, Title: title, Why: why, Ref: ref, Kind: "aufgabe", DueFrom: "kenntnis", When: When{Mode: "all"}}
	for _, f := range o {
		f(&s)
	}
	return s
}

func mand() opt               { return func(s *Step) { s.Mandatory = true } }
func manual() opt             { return func(s *Step) { s.Manual = true } }
func kind(k string) opt       { return func(s *Step) { s.Kind = k } }
func after(ids ...string) opt { return func(s *Step) { s.DependsOn = append(s.DependsOn, ids...) } }
func details(d string) opt    { return func(s *Step) { s.Details = d } }
func fromCreate() opt         { return func(s *Step) { s.DueFrom = "anlage" } }
func when(r ...Rule) opt      { return func(s *Step) { s.When = When{Mode: "all", Rules: r} } }
func whenAny(r ...Rule) opt   { return func(s *Step) { s.When = When{Mode: "any", Rules: r} } }
func sevMin(p string) Rule    { return Rule{Field: "severity", Op: "min", Values: []string{p}} }
func catIn(c ...string) Rule  { return Rule{Field: "category", Op: "in", Values: c} }
func is(field string) Rule    { return Rule{Field: field, Op: "true"} }
func regIn(r ...string) Rule  { return Rule{Field: "regulation", Op: "in", Values: r} }
func all(r ...Rule) When      { return When{Mode: "all", Rules: r} }
func anyOf(r ...Rule) When    { return When{Mode: "any", Rules: r} }
func always() When            { return When{Mode: "all"} }

func staff(pos, need, phase string, w When, why, ref string) StaffReq {
	return StaffReq{ID: "st_" + pos, Position: pos, Need: need, Phase: phase, When: w, Why: why, Ref: ref}
}

// ---------- Standardablauf ----------

func baseSteps() []Step {
	return []Step{
		// Gemeldet
		st("b_erfassen", "gemeldet", "s2", "hoch", 1, "Meldung vollständig erfassen: Wer, was, wann, wo, wie entdeckt?",
			"Bewertung, Meldungen und Beweisführung stützen sich auf die Erstinformation. Der Zeitpunkt der Kenntnisnahme startet alle Meldefristen.",
			"BSI IT-Grundschutz DER.2.1", mand()),
		st("b_erst", "gemeldet", "isb", "hoch", 2, "Erstbewertung: echter Vorfall? Welche Schutzziele? Welche Schwere?",
			"Die frühe Einstufung entscheidet über Eskalation, Zusammensetzung des Stabs und Meldefristen.",
			"BSI IT-Grundschutz DER.2.1", mand(), kind("pruefung"), after("b_erfassen")),
		// Triage
		st("b_zust", "triage", "lead", "hoch", 2, "Leitung und Zuständigkeiten festlegen, Stab nach Bedarf einberufen",
			"Klare Zuständigkeiten verhindern Doppelarbeit und Lücken. Der Umfang des Stabs richtet sich nach Schwere und betroffenen Bereichen.",
			"BSI-Standard 200-4 (Besondere Aufbauorganisation)", mand(), kind("entscheidung"), after("b_erst")),
		st("b_melde", "triage", "isb", "hoch", 6, "Meldepflichten prüfen: Datenschutz, CERT, Dienstweg, ggf. NIS2",
			"Fristen laufen ab Kenntnisnahme. Auch bei unklarer Lage ist eine Erstmeldung möglich – und die Entscheidung gegen eine Meldung ist zu dokumentieren.",
			"Art. 33 DSGVO, Landes-ISG / BSIG", mand(), kind("pruefung"), after("b_erst")),
		st("b_leitung", "triage", "lead", "hoch", 4, "Behördenleitung unterrichten",
			"Die Behördenleitung trägt die Gesamtverantwortung für die Informationssicherheit und muss über Ressourcen, Außenkommunikation und Grundsatzfragen entscheiden können.",
			"BSI-Standard 200-1, ISMS.1", kind("kommunikation"), when(sevMin("P2")), after("b_zust")),
		// Analyse
		st("b_umfang", "analyse", "s3", "hoch", 12, "Betroffene Systeme, Konten und Daten erfassen (Reiter „Systeme“)",
			"Ohne vollständige Übersicht der betroffenen Systeme bleiben Lücken bei Eindämmung, Meldung und Wiederanlauf.",
			"BSI IT-Grundschutz DER.2.1", mand()),
		st("b_zeit", "analyse", "forensics", "hoch", 12, "Zeitlinie des Vorfalls erstellen (erste Kompromittierung bis heute)",
			"Erst die Zeitlinie zeigt Umfang, möglichen Datenabfluss und den sauberen Wiederherstellungszeitpunkt.",
			"BSI IT-Grundschutz DER.2.2", when(sevMin("P3"))),
		st("b_bia", "analyse", "process_owner", "mittel", 12, "Betroffene Fachverfahren und deren Kritikalität feststellen (BIA)",
			"Eindämmung und Wiederanlauf werden nach der Kritikalität der Verwaltungsleistungen priorisiert, nicht nach technischer Bequemlichkeit.",
			"BSI-Standard 200-4 (Business Impact Analyse)", when(sevMin("P2"))),
		st("b_lage", "analyse", "s2", "mittel", 8, "Erste Lagemeldung erstellen",
			"Die Lagemeldung gibt allen Beteiligten denselben Kenntnisstand und ist Grundlage der Lagebesprechung.",
			"BSI-Standard 200-4 (Lagedarstellung)", whenAny(sevMin("P2"), is("crisis")), fromCreate()),
		// Eindämmung
		st("b_strat", "eindaemmung", "lead", "hoch", 2, "Eindämmungsstrategie entscheiden und dokumentieren",
			"Die Abwägung zwischen Beweissicherung, Betriebsfortführung und Beobachtung des Angreifers ist eine Leitungsentscheidung mit Folgen für Ermittlungen und Bürgerdienste.",
			"NIST SP 800-61, BSI DER.2.1", mand(), kind("entscheidung"), fromCreate(), when(sevMin("P3")), after("b_umfang")),
		st("b_beschaeftigte", "eindaemmung", "s5", "mittel", 4, "Beschäftigte über Einschränkungen und Verhaltensregeln informieren",
			"Beschäftigte, die wissen was los ist, melden Auffälligkeiten und umgehen gesperrte Wege nicht eigenmächtig.",
			"BSI-Standard 200-4 (Krisenkommunikation)", kind("kommunikation"), fromCreate(), when(is("impact_a")), after("b_strat")),
		// Beseitigung
		st("b_ursache", "beseitigung", "s3", "hoch", 24, "Ursache beseitigen: Schwachstelle schließen, Schadsoftware und Persistenz entfernen",
			"Ohne Beseitigung der Ursache droht die Wiederinfektion unmittelbar nach dem Wiederanlauf.",
			"BSI IT-Grundschutz DER.2.1", mand(), fromCreate(), after("b_strat")),
		st("b_zugang", "beseitigung", "s3", "hoch", 24, "Zugangsdaten aller betroffenen Konten und Dienstkonten erneuern",
			"Abgegriffene Zugangsdaten bleiben sonst gültig und öffnen dem Angreifer erneut die Tür.",
			"BSI IT-Grundschutz ORP.4", fromCreate(), when(catIn("ransomware", "malware", "account_compromise", "phishing", "credential_leak"))),
		// Wiederherstellung
		st("b_backup", "wiederherstellung", "s6", "hoch", 8, "Integrität der Backups vor Rücksicherung prüfen",
			"Backups können bereits kompromittiert oder manipuliert sein; eine Rücksicherung würde den Angreifer zurückholen.",
			"BSI IT-Grundschutz CON.3", kind("pruefung"), fromCreate(), when(catIn("ransomware", "malware"))),
		st("b_wiederanlauf", "wiederherstellung", "bcm", "hoch", 24, "Wiederanlauf nach Wiederanlaufplan (Reihenfolge nach Kritikalität)",
			"Ein geordneter Wiederanlauf verhindert Folgefehler und bringt die wichtigsten Bürgerdienste zuerst zurück.",
			"BSI-Standard 200-4", fromCreate(), when(sevMin("P2")), after("b_ursache")),
		st("b_freigabe", "wiederherstellung", "process_owner", "mittel", 24, "Fachliche Freigabe zur Wiederinbetriebnahme",
			"Die fachliche Abnahme dokumentiert Funktionsfähigkeit und Datenrichtigkeit – Voraussetzung, um wieder Bescheide und Leistungen zu erbringen.",
			"BSI-Standard 200-4", mand(), kind("entscheidung"), fromCreate(), after("b_wiederanlauf", "b_backup")),
		st("b_monitor", "wiederherstellung", "s6", "mittel", 24, "Erhöhte Überwachung der wiederhergestellten Systeme (mind. 30 Tage)",
			"Angreifer kehren häufig über verbliebene Zugänge zurück.", "NIST SP 800-61", fromCreate(), after("b_freigabe")),
		// Nachbereitung
		st("b_abschlussmeld", "nachbereitung", "isb", "mittel", 72, "Abschlussmeldungen an CERT, Datenschutzaufsicht und Dienstweg abgeben",
			"Mehrstufige Meldepflichten verlangen eine Abschlussmeldung mit Ursache und Maßnahmen.",
			"Landes-ISG / BSIG, Art. 33 Abs. 4 DSGVO", kind("meldung"), fromCreate(), when(regIn("cert", "nis2", "dsgvo", "aufsicht"))),
		st("b_ll", "nachbereitung", "isb", "mittel", 336, "Lessons-Learned-Besprechung mit allen Beteiligten",
			"Erkenntnisse gehen verloren, wenn sie nicht zeitnah gesichert werden (Empfehlung: binnen 14 Tagen).",
			"BSI IT-Grundschutz DER.2.1", mand(), fromCreate()),
		st("b_bericht", "nachbereitung", "isb", "mittel", 336, "Abschlussbericht an die Behördenleitung",
			"Die Leitung trägt die Gesamtverantwortung und entscheidet über Verbesserungsmaßnahmen und deren Finanzierung.",
			"BSI-Standard 200-1/200-2, ISMS.1", mand(), fromCreate(), after("b_ll")),
		st("b_update", "nachbereitung", "isb", "mittel", 720, "Sicherheitskonzept, Notfallhandbuch und Workflows aktualisieren",
			"Kontinuierliche Verbesserung (PDCA): Der nächste Vorfall soll besser bewältigt werden.",
			"BSI-Standard 200-2, DER.2.1", fromCreate(), after("b_ll")),
	}
}

func baseStaff() []StaffReq {
	return []StaffReq{
		staff("lead", "pflicht", "gemeldet", always(), "Jeder Vorfall braucht eine verantwortliche Leitung, die entscheidet und dokumentiert.", "BSI-Standard 200-4"),
		staff("vs", "pflicht", "gemeldet", all(is("classified")), "Der Vorfall betrifft Verschlusssachen – Meldung und Umgang richten sich nach der VSA.", "VSA"),
		staff("isb", "pflicht", "triage", all(sevMin("P3")), "Der/die ISB koordiniert die Vorfallbehandlung und bewertet Meldepflichten gegenüber CERT und Aufsicht.", "BSI IT-Grundschutz ISMS.1, DER.2.1"),
		staff("dpo", "pflicht", "triage", anyOf(is("personal_data"), catIn("data_breach", "device_loss")),
			"Personenbezogene Daten sind (möglicherweise) betroffen: Die 72-h-Frist läuft, der/die DSB bewertet das Risiko und ist frühzeitig einzubinden.", "Art. 33, 38 Abs. 1 DSGVO"),
		staff("s2", "soll", "triage", anyOf(sevMin("P2"), is("crisis")), "Bei größeren Lagen braucht es eine Stelle, die Lagebild, Tagebuch und Fristen führt.", "BSI-Standard 200-4"),
		staff("staff_council", "pflicht", "triage", all(catIn("insider")), "Insider-Fälle und Auswertungen von Beschäftigtendaten sind beteiligungspflichtig.", "BPersVG / LPersVG"),
		staff("it_provider", "soll", "triage", all(catIn("ransomware", "malware", "supply_chain", "service_outage", "dos"), sevMin("P2")),
			"Netzübergänge, Backups und Fachverfahren liegen oft beim Rechenzentrum – frühe Einbindung beschleunigt Eindämmung und Wiederanlauf.", "BSI IT-Grundschutz OPS.2.3"),
		staff("s3", "soll", "analyse", all(sevMin("P3")), "Technische Maßnahmen müssen koordiniert werden, damit Eindämmung und Beweissicherung sich nicht behindern.", "BSI IT-Grundschutz DER.2.1"),
		staff("forensics", "soll", "analyse", all(catIn("ransomware", "malware", "account_compromise", "insider", "data_breach"), sevMin("P2")),
			"Gerichtsfeste Spurensicherung und Rekonstruktion des Angriffswegs erfordern forensische Kompetenz.", "BSI IT-Grundschutz DER.2.2"),
		staff("s5", "soll", "analyse", anyOf(Rule{Field: "severity", Op: "in", Values: []string{"P1"}}, is("crisis")),
			"Bei schweren Vorfällen und Ausfällen von Bürgerdiensten besteht hoher Informationsbedarf – Kommunikation aus einer Hand.", "BSI-Standard 200-4 (Krisenkommunikation)"),
		staff("bcm", "pflicht", "analyse", all(is("impact_a"), sevMin("P2")), "Die Verfügbarkeit ist beeinträchtigt: Notbetrieb und Wiederanlauf steuert die Notfallvorsorge.", "BSI-Standard 200-4"),
		staff("process_owner", "soll", "analyse", all(sevMin("P2")), "Nur die Fachseite kann Kritikalität und Datenlage der betroffenen Verwaltungsleistung bewerten.", "BSI-Standard 200-4 (BIA)"),
		staff("legal", "soll", "analyse", all(catIn("insider", "fraud", "data_breach", "ransomware")), "Strafanzeige, Ansprüche gegen Dienstleister und dienstrechtliche Schritte brauchen rechtliche Bewertung.", "Justiziariat / Rechtsamt"),
		staff("s6", "soll", "eindaemmung", all(sevMin("P2")), "Ausweichkommunikation, Backups und Infrastruktur sind Voraussetzung für Eindämmung und Wiederanlauf.", "BSI IT-Grundschutz CON.3"),
		staff("s1", "optional", "eindaemmung", all(is("crisis")), "Länger andauernde Lagen brauchen Schicht- und Ablöseplanung.", "FwDV 100"),
		staff("s4", "optional", "eindaemmung", all(is("crisis")), "Ersatzbeschaffungen und Dienstleisterbeauftragungen müssen schnell und haushaltsrechtlich sauber laufen.", "FwDV 100"),
	}
}

// ---------- Szenarien ----------

type scenario struct {
	cat, desc string
	steps     []Step
	staff     []StaffReq
	// Bibliothek
	key, name, group string
	cats             []string // weitere Kategorien für die automatische Wahl
	manualOnly       bool
	rev              int
	skipBase         []string // Standardschritte, die für diesen Ablauf nicht passen (z. B. IT-Notfall ohne Angriff)
	color            string
	lean             bool     // kleiner Vorfall: schlanker Grundablauf und kleiner Stab statt Standardablauf
	sev              []string // automatische Wahl nur bei diesen Schweregraden (z. B. P3, P4)
}

func scenarios() []scenario {
	return []scenario{
		{cat: "ransomware", desc: "Verschlüsselung von Systemen mit Erpressung – häufig mit vorherigem Datenabfluss (Double Extortion).", steps: []Step{
			st("r_trennen", "gemeldet", "s3", "hoch", 1, "Betroffene Systeme vom Netz trennen – nicht ausschalten",
				"Stoppt Verschlüsselung und Ausbreitung. Der Arbeitsspeicher enthält Schlüsselmaterial und Spuren, die beim Herunterfahren verloren gehen.",
				"BSI: Maßnahmenkatalog Ransomware", mand()),
			st("r_backup", "triage", "s6", "hoch", 2, "Backups sofort offline sichern (nicht mit betroffenen Systemen verbinden)",
				"Täter zielen gezielt auf Sicherungen. Ohne saubere Backups ist ein Wiederanlauf ohne Lösegeld kaum möglich.",
				"BSI IT-Grundschutz CON.3", mand()),
			st("r_dl", "triage", "it_provider", "hoch", 2, "IT-Dienstleister / Rechenzentrum alarmieren, Netzübergänge prüfen",
				"Das Rechenzentrum kann Verbindungen zu anderen Behörden trennen und hält Logs, die die Ausbreitung zeigen.",
				"BSI IT-Grundschutz OPS.2.3", kind("kommunikation")),
			st("r_notbetrieb", "triage", "bcm", "hoch", 4, "Notbetrieb nach Notfallhandbuch aktivieren (Bürgerdienste nach BIA)",
				"Pflichtaufgaben der Verwaltung (z. B. Sozialleistungen, Meldewesen) müssen auch ohne IT weiterlaufen.",
				"BSI-Standard 200-4", when(sevMin("P2"))),
			st("r_ausbreitung", "analyse", "forensics", "hoch", 8, "Ausbreitung ermitteln: Konten, Freigaben, laterale Bewegung",
				"Nur wer alle betroffenen Systeme kennt, kann vollständig eindämmen – übersehene Systeme verschlüsseln nach dem Wiederanlauf erneut.",
				"BSI IT-Grundschutz DER.2.2", mand(), after("r_trennen")),
			st("r_exfil", "analyse", "forensics", "hoch", 24, "Datenabfluss prüfen (Leak-Seite der Tätergruppe, Firewall-/Proxy-Logs)",
				"Moderne Ransomware stiehlt vorher Daten. Ein Abfluss personenbezogener Daten löst Meldepflichten nach Art. 33/34 DSGVO aus.",
				"Art. 33 DSGVO, BSI-Lagebericht", kind("pruefung"), after("r_ausbreitung")),
			st("r_anzeige", "analyse", "legal", "mittel", 24, "Strafanzeige bei der Zentralen Ansprechstelle Cybercrime (ZAC) erstatten",
				"Die Polizei unterstützt bei der Täterkommunikation, kennt Tätergruppen und Entschlüsselungswerkzeuge.",
				"ZAC der Landeskriminalämter", kind("meldung")),
			st("r_loesegeld", "eindaemmung", "lead", "hoch", 8, "Grundsatzentscheidung zur Lösegeldforderung durch die Behördenleitung dokumentieren",
				"BSI und Polizei raten von Zahlungen ab: Sie finanzieren weitere Angriffe, garantieren keine Entschlüsselung und sind haushaltsrechtlich kaum vertretbar. Die Entscheidung muss nachvollziehbar dokumentiert sein.",
				"BSI-Empfehlung Ransomware", mand(), kind("entscheidung"), when(sevMin("P2")),
				details("Kontaktaufnahme zu Tätern nur nach Abstimmung mit der Polizei.")),
			st("r_presse", "eindaemmung", "s5", "mittel", 6, "Information der Bürgerinnen und Bürger / Presse abstimmen",
				"Bürgerdienste fallen sichtbar aus; eine abgestimmte, ehrliche Information verhindert Spekulationen.",
				"BSI-Standard 200-4 (Krisenkommunikation)", kind("kommunikation"), fromCreate(), when(sevMin("P2"))),
			st("r_krbtgt", "beseitigung", "s3", "hoch", 8, "Privilegierte Kennwörter und Dienstkonten zurücksetzen (krbtgt zweimal)",
				"Ransomware-Täter übernehmen fast immer die Domäne. Ohne Reset aller privilegierten Zugänge bleibt der Zugang bestehen.",
				"BSI IT-Grundschutz APP.2.2 (Active Directory)", mand(), fromCreate(), after("r_ausbreitung")),
			st("r_neuaufbau", "beseitigung", "s6", "hoch", 48, "Kompromittierte Systeme neu aufsetzen statt bereinigen",
				"Eine Bereinigung kann versteckte Persistenz übersehen; ein Neuaufbau aus vertrauenswürdigen Quellen ist sicherer.",
				"BSI IT-Grundschutz DER.2.3", fromCreate(), after("r_krbtgt")),
		}},
		{cat: "phishing", desc: "Phishing-Mails an Beschäftigte – Ziel sind Zugangsdaten oder Schadcode.", steps: []Step{
			st("p_empf", "gemeldet", "s3", "hoch", 2, "Empfänger ermitteln und Mails aus allen Postfächern entfernen",
				"Jede Mail, die noch im Postfach liegt, kann noch angeklickt werden.", "BSI IT-Grundschutz APP.5.3", mand()),
			st("p_sperren", "triage", "s6", "hoch", 2, "Links, Absender und Anhänge sperren (Proxy, Mail-Gateway)",
				"Sperrt den Weg auch für Beschäftigte, die die Mail weitergeleitet oder auf dem Smartphone geöffnet haben.", "BSI IT-Grundschutz NET.3.2"),
			st("p_warn", "triage", "s5", "mittel", 4, "Warnhinweis an alle Beschäftigten",
				"Gewarnte Beschäftigte melden weitere Mails und klicken nicht – die beste Sensorik der Behörde.", "BSI IT-Grundschutz ORP.3", kind("kommunikation")),
			st("p_klicks", "analyse", "forensics", "hoch", 4, "Klicks und Anmeldungen der Empfänger prüfen",
				"Entscheidet, ob aus dem Phishing ein kompromittiertes Konto geworden ist.", "BSI IT-Grundschutz DER.2.2", mand(), kind("pruefung"), after("p_empf")),
			st("p_konten", "eindaemmung", "s3", "hoch", 4, "Betroffene Konten sperren, Kennwort zurücksetzen, Sitzungen widerrufen",
				"Abgegriffene Zugangsdaten werden oft binnen Minuten genutzt.", "BSI IT-Grundschutz ORP.4", fromCreate(), after("p_klicks")),
		}},
		{cat: "account_compromise", desc: "Unbefugter Zugriff auf ein Benutzer- oder Dienstkonto.", steps: []Step{
			st("a_sperren", "gemeldet", "s3", "hoch", 1, "Konto sperren, Kennwort zurücksetzen, Sitzungen und Token widerrufen",
				"Ein Kennwortwechsel allein beendet bestehende Sitzungen und App-Token nicht.", "BSI IT-Grundschutz ORP.4", mand()),
			st("a_mfa", "triage", "s3", "hoch", 2, "MFA-Methoden, Weiterleitungen und Posteingangsregeln prüfen",
				"Angreifer sichern sich den Zugang über eigene MFA-Geräte und verstecken sich mit Weiterleitungsregeln.", "BSI IT-Grundschutz ORP.4", after("a_sperren")),
			st("a_logs", "analyse", "forensics", "hoch", 8, "Anmelde- und Audit-Logs der letzten 30 Tage auswerten",
				"Zeigt, worauf zugegriffen wurde. Die Auswertung von Beschäftigtendaten ist mit Personalrat und DSB abzustimmen.",
				"BSI IT-Grundschutz OPS.1.1.5, BPersVG", kind("pruefung"), after("a_sperren")),
			st("a_daten", "analyse", "dpo", "mittel", 24, "Zugriff auf personenbezogene Daten und Fachverfahren bewerten (Meldepflicht?)",
				"Ein Zugriff auf Bürger- oder Personaldaten kann eine meldepflichtige Datenschutzverletzung sein.", "Art. 33 DSGVO", kind("pruefung"), after("a_logs")),
		}, staff: []StaffReq{staff("staff_council", "soll", "analyse", always(),
			"Die Auswertung von Anmelde- und Protokolldaten betrifft Beschäftigtendaten – Personalrat beteiligen.", "BPersVG / LPersVG")}},
		{cat: "credential_leak", desc: "Geleakte Zugangsdaten (z. B. aus der Leak-Prüfung eskaliert).", steps: []Step{
			st("c_reset", "gemeldet", "s3", "hoch", 1, "Kennwort zurücksetzen und Sitzungen widerrufen",
				"Geleakte Zugangsdaten werden automatisiert ausprobiert (Credential Stuffing).", "BSI IT-Grundschutz ORP.4", mand()),
			st("c_logs", "analyse", "forensics", "hoch", 8, "Anmeldungen seit dem Leak-Zeitpunkt prüfen",
				"Entscheidet, ob das Konto bereits missbraucht wurde und ein Kontokompromittierungs-Ablauf nötig ist.", "BSI IT-Grundschutz DER.2.2",
				kind("pruefung"), after("c_reset")),
			st("c_info", "triage", "s3", "mittel", 24, "Betroffene Person über Prüfung privater und dienstlicher Online-Konten informieren",
				"Dasselbe Kennwort wird oft auch für Online-Shops oder Fachportale genutzt.", "BSI für Bürger: Passwörter", kind("kommunikation")),
		}},
		{cat: "data_breach", desc: "Abfluss, Veröffentlichung oder Fehlversand von Daten.", steps: []Step{
			st("d_weg", "gemeldet", "s3", "hoch", 4, "Abflussweg schließen", "Solange der Weg offen ist, fließen weitere Daten ab.", "BSI IT-Grundschutz DER.2.1", mand()),
			st("d_umfang", "analyse", "forensics", "hoch", 12, "Art und Umfang der Daten feststellen (Kategorien, Anzahl Betroffene)",
				"Grundlage jeder Risikobewertung und Meldung; Art. 33 Abs. 3 verlangt diese Angaben.", "Art. 33 Abs. 3 DSGVO", mand()),
			st("d_risiko", "analyse", "dpo", "hoch", 24, "Risikobewertung für die Betroffenen (Art. 33/34 DSGVO)",
				"Die Meldepflicht hängt vom Risiko für die Rechte und Freiheiten der Betroffenen ab.", "Art. 33, 34 DSGVO, EDSA-Leitlinien 9/2022",
				mand(), kind("pruefung"), after("d_umfang")),
			st("d_entscheid", "eindaemmung", "lead", "hoch", 48, "Entscheidung über Meldung (Art. 33) und Benachrichtigung (Art. 34) dokumentieren",
				"Auch die Entscheidung gegen eine Meldung ist mit Begründung zu dokumentieren.", "Art. 33 Abs. 5 DSGVO", mand(), kind("entscheidung"), after("d_risiko")),
			st("d_benachr", "eindaemmung", "s5", "mittel", 48, "Benachrichtigung der Betroffenen / Bürgerinformation vorbereiten",
				"Betroffene müssen sich schützen können (z. B. Kennwörter ändern, Kontoauszüge prüfen).", "Art. 34 DSGVO", kind("kommunikation"), fromCreate(), after("d_entscheid")),
		}},
		{cat: "malware", desc: "Schadsoftware auf einzelnen Systemen.", steps: []Step{
			st("m_iso", "gemeldet", "s3", "hoch", 1, "System isolieren (EDR-Netzwerkisolation)", "Verhindert Ausbreitung und Kommunikation mit dem Angreifer.", "BSI IT-Grundschutz DER.2.1", mand()),
			st("m_sample", "analyse", "forensics", "hoch", 4, "Sample und IOCs sichern, Hashes erfassen (Reiter „IOCs“)", "IOCs ermöglichen die Suche nach weiteren Infektionen.", "BSI IT-Grundschutz DER.2.2", after("m_iso")),
			st("m_hunt", "analyse", "forensics", "hoch", 8, "Nach IOCs im gesamten Netz suchen", "Ein Fund ist selten ein Einzelfall.", "BSI IT-Grundschutz DER.2.2", kind("pruefung"), after("m_sample")),
			st("m_neu", "beseitigung", "s6", "mittel", 48, "System neu aufsetzen und wiederherstellen", "Bereinigung kann Persistenz übersehen.", "BSI IT-Grundschutz DER.2.3", fromCreate(), after("m_hunt")),
		}},
		{cat: "service_outage", desc: "Ausfall von Fachverfahren oder Bürgerdiensten – Ursache zunächst unklar.", steps: []Step{
			st("o_ursache", "gemeldet", "s6", "hoch", 1, "Ursache eingrenzen: Angriff oder technische Störung?", "Entscheidet, ob Sicherheits- oder Störungsprozess führt.", "BSI IT-Grundschutz DER.2.1", mand(), kind("pruefung")),
			st("o_notbetrieb", "triage", "bcm", "hoch", 2, "Notbetrieb / Ersatzverfahren für betroffene Bürgerdienste aktivieren",
				"Gesetzliche Leistungen und Fristen gegenüber Bürgern laufen weiter.", "BSI-Standard 200-4"),
			st("o_buerger", "triage", "s5", "hoch", 2, "Bürgerinformation veröffentlichen (Website, Social Media, Telefonansage)",
				"Vermeidet unnötige Wege und Anrufe und zeigt Handlungsfähigkeit.", "BSI-Standard 200-4 (Krisenkommunikation)", kind("kommunikation")),
			st("o_fv", "triage", "process_owner", "hoch", 2, "Fachverfahrensverantwortliche und IT-Dienstleister einbinden", "Sie kennen Abhängigkeiten und Ersatzprozesse.", "BSI-Standard 200-4", kind("kommunikation")),
			st("o_angriff", "analyse", "forensics", "hoch", 8, "Angriff ausschließen oder bestätigen (Logs, EDR)", "Ein Ausfall kann Ablenkung oder Folge eines Angriffs sein.", "BSI IT-Grundschutz DER.2.2", kind("pruefung"), after("o_ursache")),
		}},
		{cat: "device_loss", desc: "Verlust oder Diebstahl von Notebooks, Smartphones oder Datenträgern.", steps: []Step{
			st("l_sperren", "gemeldet", "s3", "hoch", 1, "Gerät und Konto sperren, Fernlöschung auslösen (MDM)", "Verhindert Zugriff auf Daten und Netz.", "BSI IT-Grundschutz SYS.3.2.2", mand()),
			st("l_status", "triage", "s6", "hoch", 4, "Verschlüsselungsstatus und gespeicherte Daten feststellen", "Ein verschlüsseltes Gerät ist meist keine meldepflichtige Datenpanne.", "BSI IT-Grundschutz CON.1", kind("pruefung"), after("l_sperren")),
			st("l_dsgvo", "analyse", "dpo", "hoch", 24, "Datenschutzrechtliche Bewertung (Art. 33 DSGVO)", "Unverschlüsselte personenbezogene Daten lösen die 72-h-Frist aus.", "Art. 33 DSGVO", mand(), kind("pruefung"), after("l_status")),
			st("l_anzeige", "analyse", "legal", "mittel", 24, "Diebstahlsanzeige bei der Polizei", "Voraussetzung für Versicherung und Ermittlung.", "", kind("meldung")),
		}},
		{cat: "insider", desc: "Fehlverhalten oder Angriff durch Beschäftigte – besondere Vertraulichkeit.", steps: []Step{
			st("i_vertr", "triage", "lead", "hoch", 8, "Vertraulichkeit sicherstellen (need-to-know), Personalrat und DSB beteiligen",
				"Schützt Persönlichkeitsrechte der Beschäftigten und die Ermittlung; Beteiligungsrechte sind gesetzlich.", "BPersVG / LPersVG, Art. 88 DSGVO", mand(), kind("entscheidung")),
			st("i_recht", "analyse", "legal", "hoch", 24, "Rechtliche Bewertung (Dienst-/Disziplinarrecht, Strafrecht)", "Bestimmt zulässige Ermittlungsschritte und Folgen.", "Justiziariat", kind("pruefung"), after("i_vertr")),
			st("i_beweis", "analyse", "forensics", "hoch", 24, "Beweissicherung gerichtsfest dokumentieren (Chain of Custody)", "Disziplinar- und Strafverfahren scheitern an unsauberer Beweissicherung.", "BSI IT-Grundschutz DER.2.2", mand(), after("i_vertr")),
		}},
		{cat: "fraud", desc: "Rechnungs- und Zahlungsbetrug, CEO-Fraud.", steps: []Step{
			st("f_stop", "gemeldet", "s4", "hoch", 1, "Zahlung stoppen / Rückruf bei Bank und Kasse veranlassen", "Rückrufe gelingen meist nur innerhalb weniger Stunden.", "", mand()),
			st("f_anzeige", "triage", "legal", "hoch", 24, "Strafanzeige erstatten", "Ermöglicht Kontosperrungen über Ermittlungsbehörden.", "", kind("meldung")),
			st("f_warn", "triage", "s5", "mittel", 8, "Warnhinweis an Kasse, Buchhaltung und Beschäftigte", "Täter versuchen es meist mehrfach.", "", kind("kommunikation")),
			st("f_weg", "analyse", "forensics", "hoch", 24, "Einfallstor ermitteln (kompromittiertes Postfach? gefälschte Domain?)",
				"Ein kompromittiertes Postfach ist ein eigener Sicherheitsvorfall.", "BSI IT-Grundschutz DER.2.2", kind("pruefung"), after("f_stop")),
		}},
	}
}

// layout verteilt die Schritte innerhalb ihrer Phase untereinander (Ablaufgraph).
func layout(steps []Step) {
	n := map[string]int{}
	for i := range steps {
		steps[i].Y = float64(n[steps[i].Phase] * 96)
		n[steps[i].Phase]++
	}
}

// Template ist ein fest eingebauter, gepflegter Ablauf der Bibliothek.
type Template struct {
	Key         string
	Name        string
	Group       string
	Description string
	Rev         int
	Def         Def
	Available   bool // mindestens eine passende Kategorie ist konfiguriert (sonst nur manuell wählbar)
	Small       bool // kleiner Vorfall mit begrenztem Stab
}

// Gruppen der Bibliothek in Anzeigereihenfolge.
var TemplateGroups = []string{"Grundablauf", "Cyberangriff", "Konten & Zugangsdaten", "Datenschutz & Daten", "IT-Notfall & Ausfall", "Betrug & Missbrauch"}

var groupOf = map[string]string{"ransomware": "Cyberangriff", "malware": "Cyberangriff", "phishing": "Konten & Zugangsdaten",
	"account_compromise": "Konten & Zugangsdaten", "credential_leak": "Konten & Zugangsdaten", "data_breach": "Datenschutz & Daten",
	"device_loss": "Datenschutz & Daten", "service_outage": "IT-Notfall & Ausfall", "insider": "Betrug & Missbrauch", "fraud": "Betrug & Missbrauch"}

func standardDef() Def {
	d := Def{Key: "standard", Name: "Standardablauf IT-Sicherheitsvorfall", Color: "#1f5fbf",
		Description: "Grundablauf nach BSI-Standard 200-4, IT-Grundschutz DER.2.1 und NIST SP 800-61 – gilt für alle Vorfälle ohne eigenen Workflow.",
		Match:       Match{When: When{Mode: "all"}}, Staff: baseStaff(), Steps: baseSteps(), Origin: "standard", OriginRev: 1}
	layout(d.Steps)
	d.Normalize()
	return d
}

// Library liefert alle eingebauten Abläufe. Kategorien, die in der Konfiguration fehlen, werden aus der
// automatischen Zuordnung entfernt; bleibt keine übrig, ist der Ablauf nur manuell wählbar.
func Library(cats []config.Option) []Template {
	known := map[string]string{}
	for _, c := range cats {
		known[c.Key] = c.Label
	}
	std := standardDef()
	out := []Template{{Key: std.Key, Name: std.Name, Group: "Grundablauf", Description: std.Description, Rev: 1, Def: std, Available: true}}
	scs := append(scenarios(), moreScenarios()...)
	scs = append(scs, smallScenarios()...)
	for _, sc := range scs {
		key, name, group := sc.key, sc.name, sc.group
		if key == "" {
			key = sc.cat
		}
		if name == "" {
			name = known[sc.cat]
		}
		if name == "" {
			name = sc.cat
		}
		if group == "" {
			group = groupOf[sc.cat]
		}
		if sc.rev == 0 {
			sc.rev = 1
		}
		skip := map[string]bool{}
		for _, id := range sc.skipBase {
			skip[id] = true
		}
		steps := append([]Step(nil), sc.steps...)
		base, baseSt := baseSteps(), baseStaff()
		if sc.lean {
			base, baseSt = leanSteps(), leanStaff()
		}
		for _, b := range base {
			if skip[b.ID] {
				continue
			}
			var deps []string
			for _, d := range b.DependsOn {
				if !skip[d] {
					deps = append(deps, d)
				}
			}
			b.DependsOn = deps
			steps = append(steps, b)
		}
		layout(steps)
		staffReqs := baseSt
		for _, extra := range sc.staff {
			replaced := false
			for i := range staffReqs {
				if staffReqs[i].Position == extra.Position {
					staffReqs[i], replaced = extra, true
				}
			}
			if !replaced {
				staffReqs = append(staffReqs, extra)
			}
		}
		var mc []string
		for _, c := range append([]string{sc.cat}, sc.cats...) {
			if _, ok := known[c]; ok && !contains(mc, c) {
				mc = append(mc, c)
			}
		}
		color := sc.color
		if color == "" {
			color = "#b45309"
			if sc.lean {
				color = "#0d9488"
			}
		}
		prio := 1
		if sc.manualOnly {
			prio = 2
		}
		when := When{Mode: "all"}
		if len(sc.sev) > 0 {
			// spezifischer als der große Ablauf derselben Kategorie: gewinnt bei diesen Schweregraden
			when.Rules = []Rule{{Field: "severity", Op: "in", Values: sc.sev}}
		}
		d := Def{Key: key, Name: name, Description: sc.desc, Color: color, Staff: staffReqs, Steps: steps, Origin: key, OriginRev: sc.rev,
			Match: Match{Categories: mc, Priority: prio, When: when, ManualOnly: sc.manualOnly || len(mc) == 0}}
		d.Normalize()
		out = append(out, Template{Key: key, Name: name, Group: group, Description: sc.desc, Rev: sc.rev, Def: d, Available: len(mc) > 0, Small: sc.lean})
	}
	return out
}

// TemplateByKey sucht einen Ablauf der Bibliothek.
func TemplateByKey(lib []Template, key string) *Template {
	for i := range lib {
		if lib[i].Key == key {
			return &lib[i]
		}
	}
	return nil
}

// DefaultDefs liefert die Bibliothek als Workflow-Definitionen (Startbestand).
func DefaultDefs(cats []config.Option) []Def {
	var out []Def
	for _, t := range Library(cats) {
		out = append(out, t.Def)
	}
	return out
}
