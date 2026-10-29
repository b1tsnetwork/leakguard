# LeakGuard

Webbasiertes Go-Tool zur Abarbeitung von SOC-Meldungen über geleakte Kennwörter.
Fallnummer, Kennung (E-Mail/UPN/sAMAccountName) und Kennwort eingeben – LeakGuard prüft, bewertet,
schlägt Maßnahmen vor und dokumentiert jeden Schritt dauerhaft.

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

## Anmeldung

LDAPS-Bind gegen das AD, beschränkt auf `ldap.admin_groups` (verschachtelte Gruppen optional).
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

Ohne Docker: `leakguard init-config config.yaml` legt die Vorlage an, danach `leakguard -config config.yaml`.
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
