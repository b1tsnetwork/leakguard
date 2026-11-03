# LeakGuard

Webbasiertes Go-Tool zur Abarbeitung von SOC-Meldungen über geleakte Kennwörter.
Fallnummer, Kennung (E-Mail/UPN/sAMAccountName) und Kennwort eingeben – LeakGuard prüft, bewertet,
schlägt Maßnahmen vor und dokumentiert jeden Schritt dauerhaft.

## Kommandozentrale für IT-Sicherheitsvorfälle

Neben der Leak-Prüfung bildet LeakGuard ein **Lagezentrum** mit Stabsarbeit ab – für mehrere Vorfälle parallel.

**Lagezentrum (`/`)** – Live-Übersicht aller aktiven Vorfälle (nach Lage/Schwere sortiert) mit Phase, offenen Aufgaben,
Anfragen, Systemen und nächster Meldefrist als Countdown; daneben Meldefristen, offene Anfragen/Freigaben, „Meine Aufgaben“
und ein Live-Ticker. **Lagewand** für den Großbildschirm im Lageraum (siehe unten).

### Lagewand

Vollbildansicht, die immer genau einen Bildschirm füllt – ohne Scrollen, ohne Navigation, standardmäßig dunkel.

* **Gesamtlage** `/wall` (Button „Lagewand“ im Lagezentrum): Kacheln aller aktiven Vorfälle (Lagen zuerst, dann nach Schwere),
  daneben Handlungsbedarf, Meldefristen sowie Anfragen & Freigaben, unten der Live-Ticker. Kennzahlen stehen in der Kopfzeile.
  Ein Klick auf eine Kachel öffnet die Lagewand des Vorfalls.
* **Vorfall** `/incidents/{id}/wall` (Button „Lagewand“ in der Vorfallakte): Phasenleiste, aktuelle Lagemeldung, nächste
  Schritte, Meldefristen, Aufgaben (überfällige zuerst), Systeme mit Statusübersicht, Kommunikation (offene Anfragen und
  Freigaben zuerst), Einsatztagebuch und die Stabsbesetzung.

Das Raster passt sich der Bildschirmgröße an (Schriftgröße skaliert mit). Passt ein Bereich nicht vollständig hinein, blättert
er automatisch alle 12 Sekunden weiter; Punkte bzw. „2/5“ zeigen die Seite, ein Klick darauf blättert sofort, Mauszeiger über dem
Bereich pausiert. Neue Tagebuch-/Ticker-Einträge springen auf Seite 1. Taste **F** = Vollbild, ◑ = hell/dunkel (wird pro Browser
gemerkt), der Mauszeiger verschwindet nach 4 Sekunden. Auf kleinen Bildschirmen (< 900 px) wird normal gescrollt.

**Vorfallakte** (je Vorfall, Nummer `SI-JJJJ-NNNN`):

| Reiter | Inhalt |
|---|---|
| Empfehlungen | Begründete Handlungsempfehlungen und Phasenreife (siehe unten) |
| Lage | Nächste Schritte, nummerierte **Lagemeldungen** (Lage – Auswirkungen – Maßnahmen – Prognose – Entscheidungsbedarf), Status, Steckbrief, nächste Lagebesprechung |
| Einsatztagebuch | Wer hat wann was festgestellt/entschieden/getan – **unveränderlich**, Korrekturen als eigener Eintrag, Ereigniszeit ≠ Erfassungszeit |
| Aufgaben | Aufträge mit Stabsfunktion, Zuständigen, Priorität, Frist, Status und Rückmeldung; Playbook-Aufgaben je Kategorie |
| Kommunikation | Interne/externe Ein- und Ausgänge (Kanal, Gegenüber, Wortlaut, TLP); **Anfragen mit Antwortfrist**; externe Ausgänge mit **Vier-Augen-Freigabe** durch die Leitung |
| Systeme | Betroffene/untersuchte Systeme und Konten mit Status (Verdacht → kompromittiert → isoliert → bereinigt → wiederhergestellt) |
| IOCs | Indikatoren (IP, Domain, Hash …), Mehrfacherfassung, Export je Typ für Sperrlisten |
| Meldepflichten | DSGVO Art. 33/34 (LfD/BfDI), CERT-Meldung, Dienstweg, NIS2/BSIG und eigene Pflichten mit Countdown; „nicht erforderlich“ nur mit Begründung |
| Stab | Beteiligte mit Stabsfunktion (BSI 200-4: S1–S6, Forensik, Datenschutz, Recht …) und Rolle im Vorfall |
| Nachbereitung | Ursache, Lessons Learned, Verbesserungsmaßnahmen, Kennzahlen (Zeit bis Eindämmung/Behebung) |
| Audit | Technisches Prüfprotokoll des Vorfalls inkl. IP (nur Leitung) |

Phasen nach dem Incident-Response-Lebenszyklus (NIST SP 800-61): Gemeldet → Triage → Analyse → Eindämmung → Beseitigung →
Wiederherstellung → Nachbereitung → Abgeschlossen. Einstufung nach Schwere (P1–P4) und **TLP 2.0**. Druckbarer
**Vorfallbericht** (Abschlussbericht) mit allen Abschnitten und chronologischem Tagebuch.

**Live:** Je Browser hält nur **ein** Tab die Verbindung (Web Locks) und verteilt Ereignisse per BroadcastChannel an die übrigen Tabs – so bleibt das Limit von 6 Verbindungen je Server (HTTP/1.1) frei, auch bei vielen offenen Tabs.
Fremde Service Worker, die eine früher unter derselben Adresse betriebene Anwendung registriert hat, entfernt LeakGuard automatisch (`/sw.js` liefert einen Selbstentfernungs-Worker mit `Clear-Site-Data`).
Alle Seiten aktualisieren sich per Server-Sent Events (`/live`) ohne Neuladen – Bereiche, in denen gerade getippt
wird, bleiben unangetastet. Ereignisse zu vertraulichen Vorfällen erhalten nur Berechtigte. Hinter einem Reverse-Proxy
Antwortpufferung für `/live` deaktivieren (Caddy erkennt `text/event-stream` automatisch; nginx: `proxy_buffering off`).

**Rechte:** Globale Rollen aus AD-Gruppen (`roles:` – admin, leitung, bearbeiter, leser) plus Rolle je Vorfall
(Leitung, Mitglied, Beobachter). **Vertrauliche Vorfälle** sehen nur eingetragene Stabsmitglieder und Admins (need-to-know).

| Aktion | benötigt |
|---|---|
| Vorfall / Leak-Fall anlegen | Rolle bearbeiter |
| Tagebuch, Aufgaben, Kommunikation, Systeme, IOCs, Lagemeldung | im Vorfall: Mitglied (bearbeiter in nicht vertraulichen Vorfällen automatisch) |
| Phase, Stammdaten, Stab, Meldepflichten, Freigabe externer Kommunikation | im Vorfall: Leitung (globale Rolle leitung automatisch) |
| Vorlagen, globales Audit-Log, alles Vertrauliche | admin |

### Handlungsempfehlungen & nächste Schritte

Für jeden Vorfall leitet LeakGuard aus dem aktuellen Stand **begründete Handlungsempfehlungen** ab: Reiter **Empfehlungen**,
Kasten **Nächste Schritte** auf der Lageseite und **Handlungsbedarf** im Lagezentrum. Jede Empfehlung nennt Priorität,
Begründung und Grundlage und lässt sich per Klick umsetzen (Aufgabe anlegen, Meldepflicht aktivieren, Lage ausrufen,
Phase wechseln) oder **mit Begründung verwerfen**. Das Verwerfen wird als Entscheidung im Einsatztagebuch dokumentiert.

Die Engine arbeitet regelbasiert und nachvollziehbar, **ohne KI-Dienst und ohne Datenübermittlung nach außen**.
Ausgerichtet ist sie auf den öffentlichen Dienst:

| Bereich | Beispiele |
|---|---|
| Fristen | überfällige oder bald fällige Meldungen (LfD/BfDI, CERT, Dienstweg, ggf. BSI), Lagebesprechung überfällig |
| Führung | Stab/Krisenstab bei P1, Lagerhythmus, veraltetes Lagebild, offener Entscheidungsbedarf aus der Lagemeldung, Einsatztagebuch fortschreiben |
| Stab | ISB, behördliche/r DSB, Pressestelle, Notfallbeauftragte/r, **Personalrat** (Insider, Auswertung von Beschäftigtendaten), Justiziariat, IT-Dienstleister, Geheimschutz bei VS-NfD |
| Meldewege | DSGVO Art. 33/34, Landes-CERT/CERT-Bund, Unterrichtung der Aufsicht, NIS2 (wenn `org.nis2`), Strafanzeige bei der ZAC |
| Kommunikation | Behördenleitung, Rat/Kreistag (Kommunen), Bürgerinformation bei Ausfall von Verwaltungsleistungen, Warnung der Beschäftigten, überfällige Anfragen, ausstehende Freigaben |
| Technik | kompromittierte Systeme isolieren, Konten absichern, IOCs sperren, Beweissicherung vor Bereinigung (DER.2.2) |
| Vorfallart | Lösegeld-Grundsatzentscheidung, Notbetrieb nach Notfallhandbuch/BIA, Vertraulichkeit bei Insider-Fällen, Pflichten des Dienstleisters (AVV) |
| Phasen | Phasenreife mit Kriterien („Bereit für Beseitigung?“), Phasen-Checklisten (konfigurierbar), Playbook übernehmen |

Das **Behördenprofil** (`incident.org`: Kommune/Land/Bund, CERT, Datenschutzaufsicht, Polizei, Aufsicht, IT-Dienstleister,
Leitung, Gremien) bestimmt die Ansprechstellen in Meldepflichten und Empfehlungen. Zusätzlich gibt es die
**VS-Einstufung „VS-NfD“** mit Kennzeichnung in Akte und Bericht. Höhere Einstufungen gehören nicht in dieses System.

**Leak-Fälle** bleiben eine eigene, schlanke Vorfallart mit allen Prüfungen. Über **„Zu Vorfall eskalieren“** entsteht daraus ein
Sicherheitsvorfall (Kategorie „Kompromittierte Zugangsdaten“) mit Stab, Playbook und dem Konto als betroffenem System.

**Audit-Log:** Jede Änderung, Anmeldung und fehlgeschlagene Anmeldung wird mit Benutzer und IP protokolliert
(append-only per Datenbank-Trigger, ebenso Einsatztagebuch und Lagemeldungen).

### Fehlanlagen und Testvorfälle entfernen

1. **Stornieren** (Vorfallleitung, Admins): In der Vorfallakte oben rechts neben „Bericht“ auf **„Stornieren …“**,
   Begründung eintragen (Pflicht, z. B. „Testvorfall“). Der Vorfall verschwindet aus Lagezentrum, Listen, Dashboard und
   Empfehlungen; offene Meldefristen werden als „nicht erforderlich“ geschlossen. Tagebuch und Audit-Log vermerken das Storno.
   Stornierte Vorfälle findest du unter *Vorfälle → Filter „Stornierte (Fehlanlage/Test)“*; dort ist **„Storno aufheben“** möglich.
2. **Endgültig löschen** (nur Admins, nur stornierte Vorfälle): Im roten Storno-Banner auf **„Endgültig löschen …“**, zur
   Bestätigung die Vorfallnummer eintippen. Gelöscht werden Vorfall, Tagebuch, Aufgaben, Kommunikation, Systeme, IOCs,
   Meldepflichten und Lagemeldungen. Im Audit-Log bleibt ein Löschvermerk (Nummer, Titel, Begründung, wer/wann).

## Funktionen

**Prüfungen pro Fall**
- AD-Konto per LDAPS ermitteln (sAMAccountName, UPN, `mail`, `proxyAddresses`) – aktiv, gesperrt, abgelaufen,
  „Kennwort läuft nie ab“, Kennwort zuletzt gesetzt, letzte Anmeldung, privilegierte Gruppen / `adminCount`
- Kennwortrichtlinie nach Windows-Regeln: Mindestlänge, 3 von 5 Zeichenkategorien, kein Kontoname,
  keine Bestandteile des Anzeigenamens – optional **live aus dem AD** (Domänenrichtlinie bzw. PSO des Nutzers)
- Abgleich Leak-Datum ↔ `pwdLastSet` („Kennwort wurde nach dem Leak geändert“)
- Optional: Pwned Passwords (k-Anonymität – nur 5 Hash-Zeichen verlassen das Netz)
- Optional: **Bind-Test**, ob das Kennwort aktuell gültig ist (wertet AD-Codes 773/532/533 … aus)
- Wiederholungserkennung: frühere Fälle zum selben Konto **und** identisches Kennwort in anderen Fällen

**Bewertung & Maßnahmen**

| Ergebnis | Risiko | Admin-ToDo (PowerShell) | Mail Benutzer | Mail Admins |
|---|---|---|---|---|
| Richtlinie erfüllt | hoch (mittel, wenn nach Leak geändert) | ✓ | ✓ | ✓ |
| Richtlinie nicht erfüllt | niedrig | – | ✓ | – |
| Privilegiertes Konto | eine Stufe höher | | | |
| Bind-Test erfolgreich | kritisch | ✓ | ✓ | ✓ |

PowerShell-Snippets zum Kopieren: Status prüfen, Kennwortänderung erzwingen (entfernt bei Bedarf
„Kennwort läuft nie ab“, schreibt Vermerk ins Feld *Notizen*), Kennwort zufällig zurücksetzen,
Konto deaktivieren, Entra-ID-Sitzungen widerrufen (bei hybriden Konten).

**Mails** werden nur per Klick versendet. Betreff, Empfänger und Text sind vorher in einer Vorschau
editierbar. Vorlagen (Go-Template-Syntax) sind unter *Vorlagen* in der Weboberfläche änderbar.
Die Nutzer-Mails enthalten Hinweise zur Prüfung von Online-Shops, sozialen Netzwerken, privaten
Postfächern usw. (Wiederverwendung, Anmeldeverlauf, Bestellungen, Weiterleitungsregeln, 2FA, Phishing).

**Dokumentation**: Jeder Fall mit Prüfergebnis-Schnappschuss, versendeten Mails im Wortlaut, ToDo-Status,
Notizen und Statuswechseln. Das Audit-Log ist per DB-Trigger append-only. Fallliste mit Suche/Filter,
Kennzahlen und CSV-Export (Excel-tauglich, Formel-Injection-geschützt).

**Kennwortspeicherung**: Das Kennwort wird vollständig gespeichert, verschlüsselt mit AES-256-GCM
(Schlüssel aus `secret` abgeleitet – die DB allein ist ohne Konfiguration wertlos). In der Fallansicht ist es
unscharf und wird bei Hover, Fokus oder Klick sichtbar. CSV-Export und Fallliste zeigen nur die Maske.
Zusätzlich ein HMAC-SHA256-Fingerabdruck zur Erkennung identischer Kennwörter.
**`secret` nie ändern** – sonst sind gespeicherte Kennwörter nicht mehr lesbar.

**Sperrliste für ManageEngine ADSelfService Plus**: Aus jedem Kennwort werden Wortstämme abgeleitet
(Leetspeak aufgelöst, Ziffern/Sonderzeichen entfernt, ≥ 4 Buchstaben; bei Trennzeichen auch die Verkettung),
z. B. `H3rbst-L4ub!2026` → `herbst`, `laub`, `herbstlaub`.
- `/blocklist.txt` – alle Fälle, ein Eintrag pro Zeile (UTF-8, CRLF) → Wörterbuch-Regel des Password Policy Enforcers
- `/blocklist.txt?format=regex` – ein Regex, das Kennwörter mit diesen Stämmen (inkl. Leetspeak) ausschließt,
  für die Regex-Regel („Kennwort muss passen“, Lookahead-Syntax wie in Java/.NET)
- Pro Fall werden Stämme und Regex in der Fallansicht zum Kopieren angezeigt.

## ManageEngine ADSelfService Plus (Password Policy Enforcer)

ADSSP speichert seine Kennwortregeln in der eigenen Datenbank, nicht im AD – sie werden daher im
Abschnitt `adssp:` der `config.yaml` nachgebildet (mehrere Richtlinien, Zuordnung per OU oder Gruppe).

| ADSSP-Einstellung | `config.yaml` |
|---|---|
| Minimum/Maximum length | `min_length`, `max_length` |
| Uppercase/lowercase/alphabets/numerals/special/Unicode (min.) | `min_uppercase`, `min_lowercase`, `min_letters`, `min_numeric`, `min_special`, `min_unicode` |
| Restrict special/numeric/Unicode characters (max.) | `max_special`, `max_numeric`, `max_unicode` (0 = verboten) |
| Unerlaubte Zeichen / Anfangs- und Endzeichen | `disallowed_characters`, `must_not_start_with`, `must_not_end_with` |
| Consecutive repetition of characters | `max_repeated_characters` |
| Consecutive characters from username | `max_username_sequence`, `no_username`, `no_display_name` |
| Keyboard sequences | `keyboard_sequence` (QWERTZ, QWERTY, Ziffernblock, abc/123 – auch rückwärts) |
| Dictionary words | `dictionary` (Datei, ein Wort pro Zeile, Leetspeak wird erkannt) |
| Palindromes | `palindrome` |
| Regex pattern | `regex` (Java/.NET-Syntax inkl. Lookahead) |
| Compromised passwords (HIBP) | `pwned` (benötigt `hibp.enabled`) |
| Satisfy at least n of the complexity requirements | `satisfy_at_least` |
| Override complexity if length ≥ n | `override_complexity_if_length_at_least` |
| Enforce in GINA/CP and ADUC via Password Sync Agent | `native_enforcement` |

`min_*`-Regeln sind Komplexitätsanforderungen (oder mit `mandatory: true` Pflicht), alle anderen Regeln sind
Pflicht (oder mit `complexity: true` Komplexitätsanforderung). Nicht prüfbar ist die Kennwort-Historie.

**Bewertung:** Ein Verstoß gegen die ADSSP-Richtlinie schließt das aktuelle AD-Kennwort nur aus, wenn
`native_enforcement: true` gesetzt ist **und** `pwdLastSet` nach `active_since` liegt. Sonst wird der Verstoß
angezeigt, das Kennwort gilt aber weiter als mögliches AD-Kennwort.

## Anmeldung

LDAPS-Bind gegen das AD; die Rolle ergibt sich aus der Gruppenmitgliedschaft (`roles:`, verschachtelte Gruppen optional).
Ohne passende Gruppe ist keine Anmeldung möglich. `ldap.admin_groups` aus älteren Versionen wird weiterhin als Admin-Rolle gelesen.
Sitzungen serverseitig in SQLite, CSRF-Token für alle Aktionen, Rate-Limit (5 Fehlversuche / 10 min),
strikte CSP. Für Entwicklung optional ein lokales Konto (`dev_admin`, bcrypt).

## Start mit Docker

Alle persistenten Daten liegen unter **`/data`**:

| Datei | Inhalt |
|---|---|
| `/data/config.yaml` | Konfiguration (wird beim ersten Start mit zufälligem `secret` angelegt) |
| `/data/leakguard.db` (+ `-wal`, `-shm`) | Fälle, Verlauf, Vorlagen, Sitzungen |
| `/data/firma-root-ca.pem` (optional) | Root-CA der DCs, in der Config als `ca_file: "firma-root-ca.pem"` |

Relative Pfade in der Konfiguration beziehen sich immer auf das Verzeichnis der `config.yaml`.

```bash
mkdir data && sudo chown 10001:10001 data   # Container läuft als UID 10001
docker compose up -d                         # 1. Start: legt data/config.yaml an und beendet sich
nano data/config.yaml                        # LDAP, SMTP, Gruppen … eintragen
docker compose up -d
docker compose exec leakguard leakguard -check   # LDAP-Bind + Richtlinie testen
```

Backup = Verzeichnis `data/` sichern. **`secret` niemals ändern**, sonst sind gespeicherte Kennwörter nicht mehr lesbar.

Hinter einem Reverse-Proxy mit HTTPS betreiben und `cookie_secure: true` setzen
(oder `tls.cert_file`/`tls.key_file` für direktes TLS).

Ohne Docker: `cp config.example.yaml config.yaml` (oder `leakguard init-config config.yaml`, erzeugt zusätzlich ein `secret`), danach `leakguard -config config.yaml`.
`config.example.yaml` im Root ist eine Kopie von `internal/config/config.example.yaml` (eingebettete Vorlage) – ein Test stellt sicher, dass beide gleich bleiben.
Lokales Dev-Konto: `leakguard hash-password` erzeugt den bcrypt-Hash für `dev_admin.password_hash`.

## GitHub Actions & Dependabot

- `.github/workflows/docker.yml`
  - **Test**: `go mod tidy -diff`, `go mod verify`, `gofmt`, `go vet`, `go test -race`
  - **Docker**: Multi-Arch-Image (`linux/amd64`, `linux/arm64`, nativ cross-kompiliert) nach `ghcr.io/<owner>/<repo>`,
    mit SBOM und Build-Provenance. Pull Requests werden nur gebaut, nicht gepusht.
  - Tags: `latest` (Default-Branch), Branchname, `sha-xxxxxxx`, bei Git-Tags `v1.2.3` → `1.2.3`, `1.2`, `1`
  - Release: `git tag v1.0.0 && git push --tags`
- `.github/dependabot.yml` – wöchentlich (Mo 06:00) Updates für Go-Module (gruppiert), Basis-Images im
  Dockerfile und die verwendeten Actions.

Das Paket ist nach dem ersten Push zunächst privat: unter *Packages → leakguard → Package settings*
Sichtbarkeit bzw. Zugriff einstellen.

### AD-Voraussetzungen

- Dienstkonto mit Leserechten (normaler Domänenbenutzer reicht). Für PSO-Auswertung zusätzlich
  Leserecht auf `CN=Password Settings Container,CN=System,…` – sonst wird die Domänenrichtlinie genutzt.
- LDAPS (636) mit vertrauenswürdigem DC-Zertifikat; interne Root-CA über `ldap.ca_file`.
- Anmeldegruppe, z. B. `GG-LeakGuard-Admins`.

SQLite über `modernc.org/sqlite` – reines Go, kein CGO. Das Binary ist statisch und lässt sich für jede Plattform
cross-kompilieren (`CGO_ENABLED=0 GOOS=windows go build ./cmd/leakguard`). Benötigt Go ≥ 1.26.

## Struktur

```
cmd/leakguard        main, hash-password, -check
internal/config      YAML + Umgebungsvariablen, Vorlage config.example.yaml
internal/ldapx       LDAPS: Login/Gruppe, Kontosuche, PSO/Domänenrichtlinie, Bind-Test
internal/policy      Richtlinienprüfung, Maskierung
internal/blocklist   Sperrlisten-Ableitung (Wortstämme, Regex)
internal/hibp        Pwned Passwords
internal/engine      Prüflauf, Risikobewertung, Mail-Vorlagen, PowerShell
internal/mailer      SMTP (STARTTLS/TLS, PLAIN/LOGIN)
internal/store       SQLite: Fälle, Audit-Log, Sitzungen, Vorlagen
internal/web         Handler, HTML-Templates, CSS/JS (eingebettet)
```
