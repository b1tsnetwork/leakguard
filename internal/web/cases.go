package web

import (
	"encoding/csv"
	"errors"
	"fmt"
	"html/template"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"leakguard/internal/blocklist"
	"leakguard/internal/engine"
	"leakguard/internal/mailer"
	"leakguard/internal/model"
	"leakguard/internal/policy"
	"leakguard/internal/store"
)

const pageSize = 50

// ---------- Liste ----------

type listData struct {
	Cases  []*model.Case
	Total  int
	Page   int
	Pages  int
	Filter model.CaseFilter
	Stats  store.Stats
	Query  template.URL
}

func (s *Server) handleList(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	f := model.CaseFilter{Query: q.Get("q"), Status: q.Get("status"), Risk: q.Get("risk"), Limit: pageSize}
	pg, _ := strconv.Atoi(q.Get("page"))
	if pg < 1 {
		pg = 1
	}
	f.Offset = (pg - 1) * pageSize
	cases, total, err := s.store.ListCases(r.Context(), f)
	if err != nil {
		s.fail(w, r, 500, err.Error())
		return
	}
	st, _ := s.store.Stats(r.Context())
	qs := url.Values{"q": {f.Query}, "status": {f.Status}, "risk": {f.Risk}}
	s.render(w, r, "list", page{Title: "Fälle", Nav: "list", Data: listData{
		Cases: cases, Total: total, Page: pg, Pages: (total + pageSize - 1) / pageSize, Filter: f, Stats: st, Query: template.URL(qs.Encode())}})
}

// ---------- Neuer Fall ----------

type newData struct {
	CaseNumber, Identifier, Source, LeakDate string
	BindTestAllowed                          bool
	LDAPEnabled                              bool
}

func (s *Server) handleNewForm(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	s.render(w, r, "new", page{Title: "Neuer Fall", Nav: "new", Data: newData{
		CaseNumber: q.Get("case"), Identifier: q.Get("id"),
		BindTestAllowed: s.engine.BindTestAllowed(), LDAPEnabled: s.ldap.Enabled()}})
}

func parseDate(v string) (time.Time, error) {
	v = strings.TrimSpace(v)
	if v == "" {
		return time.Time{}, nil
	}
	for _, layout := range []string{"2006-01-02", "02.01.2006"} {
		if t, err := time.ParseInLocation(layout, v, time.Local); err == nil {
			return t, nil
		}
	}
	return time.Time{}, errors.New("ungültiges Datum")
}

func (s *Server) handleCreate(w http.ResponseWriter, r *http.Request) {
	se := sessionFrom(r)
	nd := newData{
		CaseNumber:      strings.TrimSpace(r.FormValue("case_number")),
		Identifier:      strings.TrimSpace(r.FormValue("identifier")),
		Source:          strings.TrimSpace(r.FormValue("source")),
		LeakDate:        r.FormValue("leak_date"),
		BindTestAllowed: s.engine.BindTestAllowed(), LDAPEnabled: s.ldap.Enabled(),
	}
	pw := r.FormValue("password")
	var errs []string
	if nd.CaseNumber == "" || len(nd.CaseNumber) > 100 {
		errs = append(errs, "Fallnummer fehlt")
	}
	if nd.Identifier == "" || len(nd.Identifier) > 256 {
		errs = append(errs, "E-Mail-Adresse / Benutzername fehlt")
	}
	if pw == "" || utf8.RuneCountInString(pw) > 512 {
		errs = append(errs, "Kennwort fehlt")
	}
	leak, err := parseDate(nd.LeakDate)
	if err != nil {
		errs = append(errs, "Leak-Datum ungültig")
	}
	if len(errs) > 0 {
		w.WriteHeader(http.StatusBadRequest)
		s.render(w, r, "new", page{Title: "Neuer Fall", Nav: "new", Err: strings.Join(errs, " · "), Data: nd})
		return
	}

	in := engine.Input{CaseNumber: nd.CaseNumber, Identifier: nd.Identifier, Password: pw, Source: nd.Source,
		LeakDate: leak, BindTest: r.FormValue("bind_test") == "1", Actor: se.Username}
	checks := s.engine.Run(r.Context(), in, 0)

	c := &model.Case{CaseNumber: nd.CaseNumber, CreatedBy: se.Username, Identifier: nd.Identifier, Source: nd.Source,
		LeakDate: leak, PwMask: policy.Mask(pw), PwLen: utf8.RuneCountInString(pw), PwHMAC: s.engine.HMAC(pw),
		Compliant: checks.PossibleADPassword, Risk: checks.Risk, Checks: checks}
	if c.PwEnc, err = s.engine.EncryptPassword(pw); err != nil {
		s.fail(w, r, 500, "Kennwort konnte nicht verschlüsselt werden: "+err.Error())
		return
	}
	if err := s.store.CreateCase(r.Context(), c); err != nil {
		s.fail(w, r, 500, "Fall konnte nicht gespeichert werden: "+err.Error())
		return
	}
	_ = s.store.AddEvent(r.Context(), c.ID, se.Username, "created",
		fmt.Sprintf("Fall angelegt, Prüfung durchgeführt – Risiko %s", c.Risk), engine.Summary(c))
	if checks.BindTested {
		_ = s.store.AddEvent(r.Context(), c.ID, se.Username, "bind_test", "Bind-Test mit geleaktem Kennwort durchgeführt: "+checks.BindResult, "")
	}
	http.Redirect(w, r, fmt.Sprintf("/cases/%d?msg=created", c.ID), http.StatusSeeOther)
}

// ---------- Falldetail ----------

type mailPreview struct {
	To, Subject, Body string
	Err               string
	Template          string
}

type caseData struct {
	Case            *model.Case
	Events          []model.Event
	Snippets        []engine.PSSnippet
	UserMail        mailPreview
	AdminMail       mailPreview
	MailEnabled     bool
	BindTestAllowed bool
	AllDone         bool
	Password        string
	PasswordErr     string
	DenyRegex       string
}

func (s *Server) loadCase(w http.ResponseWriter, r *http.Request) *model.Case {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		s.fail(w, r, 404, "Fall nicht gefunden")
		return nil
	}
	c, err := s.store.GetCase(r.Context(), id)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			s.fail(w, r, 404, "Fall nicht gefunden")
		} else {
			s.fail(w, r, 500, err.Error())
		}
		return nil
	}
	return c
}

func (s *Server) tpl(r *http.Request, key string) string {
	if v, ok, err := s.store.Setting(r.Context(), key); err == nil && ok {
		return v
	}
	return engine.DefaultTemplates[key]
}

func (s *Server) preview(r *http.Request, subjKey, bodyKey, to string, data engine.MailData) mailPreview {
	mp := mailPreview{To: to}
	var err error
	if mp.Subject, err = engine.Render(s.tpl(r, subjKey), data); err != nil {
		mp.Err = "Betreff-Vorlage fehlerhaft: " + err.Error()
	}
	if mp.Body, err = engine.Render(s.tpl(r, bodyKey), data); err != nil {
		mp.Err = "Text-Vorlage fehlerhaft: " + err.Error()
	}
	mp.Subject = strings.TrimSpace(strings.ReplaceAll(mp.Subject, "\n", " "))
	return mp
}

func (s *Server) handleCase(w http.ResponseWriter, r *http.Request) {
	c := s.loadCase(w, r)
	if c == nil {
		return
	}
	se := sessionFrom(r)
	evs, _ := s.store.Events(r.Context(), c.ID)
	md := s.engine.MailData(c, se.Display)

	userMail := s.preview(r, engine.TplUserWeakSubject, engine.TplUserWeakBody, c.Recipient(), md)
	userMail.Template = "Richtlinie nicht erfüllt"
	if c.Compliant || (c.Checks.BindTested && c.Checks.BindValid) {
		userMail = s.preview(r, engine.TplUserStrongSubject, engine.TplUserStrongBody, c.Recipient(), md)
		userMail.Template = "Richtlinie erfüllt"
	}
	adminMail := s.preview(r, engine.TplAdminSubject, engine.TplAdminBody, strings.Join(s.cfg.Mail.AdminRecipients, ", "), md)

	pw, pwErr := "", ""
	if c.PwEnc != "" {
		var err error
		if pw, err = s.engine.DecryptPassword(c.PwEnc); err != nil {
			pwErr = err.Error()
		}
	}

	a := c.Checks.Actions
	allDone := (!a.AdminTodo || c.AdminTodoDone) && (!a.UserMail || !c.UserMailAt.IsZero()) && (!a.AdminMail || !c.AdminMailAt.IsZero())

	s.render(w, r, "case", page{Title: "Fall " + c.CaseNumber, Nav: "list", Data: caseData{
		Case: c, Events: evs, Snippets: engine.PowerShellSnippets(c), UserMail: userMail, AdminMail: adminMail,
		MailEnabled: s.mailer.Enabled(), BindTestAllowed: s.engine.BindTestAllowed(), AllDone: allDone,
		Password: pw, PasswordErr: pwErr, DenyRegex: blocklist.DenyRegex(c.Checks.Blocklist.Words)}})
}

func (s *Server) touch(r *http.Request, c *model.Case) {
	if c.Status == model.StatusOpen {
		_ = s.store.SetStatus(r.Context(), c.ID, model.StatusInProgress, sessionFrom(r).Username)
	}
}

func redirectCase(w http.ResponseWriter, r *http.Request, id int64, msg, anchor string) {
	http.Redirect(w, r, fmt.Sprintf("/cases/%d?msg=%s%s", id, msg, anchor), http.StatusSeeOther)
}

// ---------- Aktionen ----------

func (s *Server) handleRecheck(w http.ResponseWriter, r *http.Request) {
	c := s.loadCase(w, r)
	if c == nil {
		return
	}
	se := sessionFrom(r)
	pw := r.FormValue("password")
	if pw == "" { // gespeichertes Kennwort verwenden
		var err error
		if pw, err = s.engine.DecryptPassword(c.PwEnc); err != nil {
			redirectCase(w, r, c.ID, "nopassword", "#recheck")
			return
		}
	}
	if id := strings.TrimSpace(r.FormValue("identifier")); id != "" {
		c.Identifier = id
	}
	in := engine.Input{CaseNumber: c.CaseNumber, Identifier: c.Identifier, Password: pw, Source: c.Source,
		LeakDate: c.LeakDate, BindTest: r.FormValue("bind_test") == "1", Actor: se.Username}
	samePW := s.engine.HMAC(pw) == c.PwHMAC
	c.Checks = s.engine.Run(r.Context(), in, c.ID)
	c.Compliant, c.Risk = c.Checks.PossibleADPassword, c.Checks.Risk
	c.PwMask, c.PwLen, c.PwHMAC = policy.Mask(pw), utf8.RuneCountInString(pw), s.engine.HMAC(pw)
	if enc, err := s.engine.EncryptPassword(pw); err == nil {
		c.PwEnc = enc
	}
	if err := s.store.UpdateChecks(r.Context(), c); err != nil {
		s.fail(w, r, 500, err.Error())
		return
	}
	msg := fmt.Sprintf("Erneute Prüfung (Kennung %s) – Risiko %s", c.Identifier, c.Risk)
	if !samePW {
		msg += " – Kennwort geändert (neues Kennwort gespeichert)"
	}
	_ = s.store.AddEvent(r.Context(), c.ID, se.Username, "recheck", msg, engine.Summary(c))
	if c.Checks.BindTested {
		_ = s.store.AddEvent(r.Context(), c.ID, se.Username, "bind_test", "Bind-Test mit geleaktem Kennwort durchgeführt: "+c.Checks.BindResult, "")
	}
	redirectCase(w, r, c.ID, "rechecked", "")
}

func (s *Server) handleSendMail(w http.ResponseWriter, r *http.Request) {
	c := s.loadCase(w, r)
	if c == nil {
		return
	}
	se := sessionFrom(r)
	kind := r.PathValue("kind")
	if kind != "user" && kind != "admin" {
		s.fail(w, r, 404, "unbekannte Mailart")
		return
	}
	to, err := mailer.ParseAddresses(r.FormValue("to"))
	subject := strings.TrimSpace(r.FormValue("subject"))
	body := r.FormValue("body")
	if err == nil && (len(to) == 0 || subject == "" || strings.TrimSpace(body) == "") {
		err = errors.New("Empfänger, Betreff und Text sind erforderlich")
	}
	label := map[string]string{"user": "E-Mail an Benutzer", "admin": "Admin-Information"}[kind]
	detail := fmt.Sprintf("An: %s\nBetreff: %s\n\n%s", strings.Join(to, ", "), subject, body)
	// Im Verlauf (unverschlüsselt in der DB) das Kennwort durch die Maske ersetzen.
	if pw, perr := s.engine.DecryptPassword(c.PwEnc); perr == nil && pw != "" {
		detail = strings.ReplaceAll(detail, pw, c.PwMask+" [Kennwort im Klartext versendet]")
	}
	if err == nil {
		msg := mailer.Message{To: to, Subject: subject, Body: body}
		if kind == "user" {
			msg.BCC = s.cfg.Mail.UserBCC
		}
		err = s.mailer.Send(msg)
	}
	if err != nil {
		_ = s.store.AddEvent(r.Context(), c.ID, se.Username, "mail_error", label+" fehlgeschlagen: "+err.Error(), detail)
		redirectCase(w, r, c.ID, "mailerror", "#verlauf")
		return
	}
	_ = s.store.MarkMailSent(r.Context(), c.ID, kind, se.Username)
	_ = s.store.AddEvent(r.Context(), c.ID, se.Username, "mail_"+kind, label+" versendet an "+strings.Join(to, ", "), detail)
	s.touch(r, c)
	redirectCase(w, r, c.ID, map[string]string{"user": "usermail", "admin": "adminmail"}[kind], "")
}

func (s *Server) handleTodo(w http.ResponseWriter, r *http.Request) {
	c := s.loadCase(w, r)
	if c == nil {
		return
	}
	se := sessionFrom(r)
	done := r.FormValue("done") == "1"
	if err := s.store.MarkAdminTodo(r.Context(), c.ID, done, se.Username); err != nil {
		s.fail(w, r, 500, err.Error())
		return
	}
	msg := "Admin-ToDo als erledigt markiert"
	if done {
		if a := strings.TrimSpace(r.FormValue("action")); a != "" {
			msg += ": " + a
		}
	} else {
		msg = "Admin-ToDo wieder geöffnet"
	}
	_ = s.store.AddEvent(r.Context(), c.ID, se.Username, "todo", msg, "")
	s.touch(r, c)
	redirectCase(w, r, c.ID, "todo", "")
}

func (s *Server) handleStatus(w http.ResponseWriter, r *http.Request) {
	c := s.loadCase(w, r)
	if c == nil {
		return
	}
	se := sessionFrom(r)
	st := r.FormValue("status")
	valid := false
	for _, v := range model.Statuses {
		valid = valid || v == st
	}
	if !valid {
		s.fail(w, r, 400, "ungültiger Status")
		return
	}
	if err := s.store.SetStatus(r.Context(), c.ID, st, se.Username); err != nil {
		s.fail(w, r, 500, err.Error())
		return
	}
	msg := fmt.Sprintf("Status: %s → %s", statusLabel(c.Status), statusLabel(st))
	if comment := strings.TrimSpace(r.FormValue("comment")); comment != "" {
		msg += " – " + comment
	}
	_ = s.store.AddEvent(r.Context(), c.ID, se.Username, "status", msg, "")
	m := "status"
	if st == model.StatusClosed {
		m = "closed"
	}
	redirectCase(w, r, c.ID, m, "")
}

func (s *Server) handleNote(w http.ResponseWriter, r *http.Request) {
	c := s.loadCase(w, r)
	if c == nil {
		return
	}
	note := strings.TrimSpace(r.FormValue("note"))
	if note == "" {
		redirectCase(w, r, c.ID, "", "#verlauf")
		return
	}
	if len(note) > 10000 {
		note = note[:10000]
	}
	_ = s.store.AddEvent(r.Context(), c.ID, sessionFrom(r).Username, "note", note, "")
	s.touch(r, c)
	redirectCase(w, r, c.ID, "note", "#verlauf")
}

// ---------- Export ----------

func (s *Server) handleExport(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	f := model.CaseFilter{Query: q.Get("q"), Status: q.Get("status"), Risk: q.Get("risk"), Limit: 1000000}
	cases, _, err := s.store.ListCases(r.Context(), f)
	if err != nil {
		s.fail(w, r, 500, err.Error())
		return
	}
	w.Header().Set("Content-Type", "text/csv; charset=utf-8")
	w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="leakguard-%s.csv"`, time.Now().Format("2006-01-02")))
	_, _ = w.Write([]byte("\xEF\xBB\xBF")) // BOM für Excel
	cw := csv.NewWriter(w)
	cw.Comma = ';'
	_ = cw.Write([]string{"ID", "Fallnummer", "Angelegt", "Angelegt von", "Kennung", "Konto", "Name", "E-Mail", "Konto aktiv",
		"Kennwort (maskiert)", "Richtlinie erfüllt", "Pwned-Treffer", "Risiko", "Status", "Admin-ToDo nötig", "Admin-ToDo erledigt",
		"Nutzer-Mail", "Admin-Mail", "Abgeschlossen", "Quelle"})
	for _, c := range cases {
		active := ""
		if c.Checks.User != nil {
			active = yn(c.Checks.User.Enabled)
		}
		_ = cw.Write(csvSafe([]string{strconv.FormatInt(c.ID, 10), c.CaseNumber, fmtDT(c.CreatedAt), c.CreatedBy, c.Identifier,
			c.Username(), c.DisplayName(), c.Recipient(), active, fmt.Sprintf("%s (%d)", c.PwMask, c.PwLen), yn(c.Compliant),
			strconv.Itoa(c.Checks.HIBPCount), c.Risk, statusLabel(c.Status), yn(c.Checks.Actions.AdminTodo), fmtDT(c.AdminTodoAt),
			fmtDT(c.UserMailAt), fmtDT(c.AdminMailAt), fmtDT(c.ClosedAt), c.Source}))
	}
	cw.Flush()
}

// csvSafe verhindert Formel-Injection in Tabellenkalkulationen.
func csvSafe(in []string) []string {
	for i, v := range in {
		if v != "" && strings.ContainsRune("=+-@\t\r", rune(v[0])) {
			in[i] = "'" + v
		}
	}
	return in
}

func yn(b bool) string {
	if b {
		return "ja"
	}
	return "nein"
}

func fmtDT(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return t.Local().Format("02.01.2006 15:04")
}

// ---------- Vorlagen ----------

type tplField struct {
	engine.TemplateDef
	Value    string
	Custom   bool
	ErrorMsg string
}

type settingsData struct {
	Fields      []tplField
	Recipients  string
	MailEnabled bool
	Policy      string
}

func (s *Server) settingsData(r *http.Request) settingsData {
	var fields []tplField
	for _, d := range engine.TemplateDefs {
		v, ok, _ := s.store.Setting(r.Context(), d.Key)
		if !ok {
			v = engine.DefaultTemplates[d.Key]
		}
		fields = append(fields, tplField{TemplateDef: d, Value: v, Custom: ok})
	}
	pol := fmt.Sprintf("Mindestlänge %d, Komplexität %s (≥ %d Kategorien)", s.cfg.Policy.MinLength, yn(s.cfg.Policy.Complexity), s.cfg.Policy.MinCategories)
	if s.cfg.Policy.ReadFromAD {
		pol += " – wird zur Laufzeit aus dem AD gelesen (Domänenrichtlinie / PSO)"
	}
	if s.cfg.ADSSP.Enabled {
		var names []string
		for _, p := range s.cfg.ADSSP.Policies {
			n := p.Name
			if p.NativeEnforcement {
				n += " (nativ)"
			}
			names = append(names, n)
		}
		pol += " · ADSelfService Plus: " + strings.Join(names, ", ")
	}
	return settingsData{Fields: fields, Recipients: strings.Join(s.cfg.Mail.AdminRecipients, ", "), MailEnabled: s.mailer.Enabled(), Policy: pol}
}

func (s *Server) handleSettings(w http.ResponseWriter, r *http.Request) {
	s.render(w, r, "settings", page{Title: "Vorlagen", Nav: "settings", Data: s.settingsData(r)})
}

func (s *Server) handleSaveSettings(w http.ResponseWriter, r *http.Request) {
	se := sessionFrom(r)
	if reset := r.FormValue("reset"); reset != "" {
		if _, ok := engine.DefaultTemplates[reset]; ok {
			_ = s.store.DeleteSetting(r.Context(), reset)
		}
		http.Redirect(w, r, "/settings?msg=reset", http.StatusSeeOther)
		return
	}
	d := s.settingsData(r)
	hasErr := false
	for i, f := range d.Fields {
		v := strings.ReplaceAll(r.FormValue(f.Key), "\r\n", "\n")
		d.Fields[i].Value = v
		if err := engine.Validate(v); err != nil {
			d.Fields[i].ErrorMsg = err.Error()
			hasErr = true
		}
	}
	if hasErr {
		w.WriteHeader(http.StatusBadRequest)
		s.render(w, r, "settings", page{Title: "Vorlagen", Nav: "settings", Err: "Mindestens eine Vorlage ist fehlerhaft – nichts gespeichert.", Data: d})
		return
	}
	for _, f := range d.Fields {
		if f.Value == engine.DefaultTemplates[f.Key] {
			_ = s.store.DeleteSetting(r.Context(), f.Key)
			continue
		}
		if err := s.store.SetSetting(r.Context(), f.Key, f.Value, se.Username); err != nil {
			s.fail(w, r, 500, err.Error())
			return
		}
	}
	http.Redirect(w, r, "/settings?msg=saved", http.StatusSeeOther)
}

// ---------- Sperrliste (z. B. ManageEngine ADSelfService Plus) ----------

func (s *Server) blocklistWords(r *http.Request) ([]string, error) {
	cases, _, err := s.store.ListCases(r.Context(), model.CaseFilter{Limit: 1000000})
	if err != nil {
		return nil, err
	}
	var lists [][]string
	for _, c := range cases {
		lists = append(lists, c.Checks.Blocklist.Words)
	}
	return blocklist.MergeWords(lists...), nil
}

// handleBlocklist liefert die Wörterbuch-Datei (UTF-8, ein Eintrag pro Zeile) oder das Regex.
func (s *Server) handleBlocklist(w http.ResponseWriter, r *http.Request) {
	words, err := s.blocklistWords(r)
	if err != nil {
		s.fail(w, r, 500, err.Error())
		return
	}
	name, body := "leakguard-sperrliste", strings.Join(words, "\r\n")
	if r.URL.Query().Get("format") == "regex" {
		name, body = "leakguard-sperrliste-regex", blocklist.DenyRegex(words)
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="%s-%s.txt"`, name, time.Now().Format("2006-01-02")))
	_, _ = w.Write([]byte(body + "\r\n"))
}
