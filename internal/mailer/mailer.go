// Package mailer versendet Text-Mails per SMTP (STARTTLS, implizites TLS oder unverschlüsselt intern).
package mailer

import (
	"bytes"
	"crypto/rand"
	"crypto/tls"
	"encoding/hex"
	"errors"
	"fmt"
	"mime"
	"mime/quotedprintable"
	"net"
	"net/mail"
	"net/smtp"
	"strconv"
	"strings"
	"time"

	"leakguard/internal/config"
)

type Mailer struct {
	smtp config.SMTP
	mail config.Mail
}

func New(s config.SMTP, m config.Mail) *Mailer { return &Mailer{smtp: s, mail: m} }

func (m *Mailer) Enabled() bool { return m.smtp.Host != "" && m.mail.From != "" }

type Message struct {
	To      []string
	CC      []string
	BCC     []string
	Subject string
	Body    string
}

// ParseAddresses validiert eine komma-/semikolongetrennte Adressliste.
func ParseAddresses(s string) ([]string, error) {
	var out []string
	for _, p := range strings.FieldsFunc(s, func(r rune) bool { return r == ',' || r == ';' || r == '\n' }) {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		a, err := mail.ParseAddress(p)
		if err != nil {
			return nil, fmt.Errorf("ungültige adresse %q", p)
		}
		out = append(out, a.Address)
	}
	return out, nil
}

func (m *Mailer) Send(msg Message) error {
	if !m.Enabled() {
		return errors.New("smtp ist nicht konfiguriert (smtp.host / mail.from)")
	}
	if len(msg.To) == 0 {
		return errors.New("kein empfänger angegeben")
	}
	from, err := mail.ParseAddress(m.mail.From)
	if err != nil {
		return fmt.Errorf("mail.from: %w", err)
	}
	raw, err := m.build(from, msg)
	if err != nil {
		return err
	}

	addr := net.JoinHostPort(m.smtp.Host, strconv.Itoa(m.smtp.Port))
	tc := &tls.Config{ServerName: m.smtp.Host, MinVersion: tls.VersionTLS12, InsecureSkipVerify: m.smtp.InsecureSkipVerify} //nolint:gosec
	dialer := &net.Dialer{Timeout: 15 * time.Second}

	var conn net.Conn
	if strings.EqualFold(m.smtp.Security, "tls") {
		conn, err = tls.DialWithDialer(dialer, "tcp", addr, tc)
	} else {
		conn, err = dialer.Dial("tcp", addr)
	}
	if err != nil {
		return fmt.Errorf("smtp verbinden: %w", err)
	}
	_ = conn.SetDeadline(time.Now().Add(60 * time.Second))
	c, err := smtp.NewClient(conn, m.smtp.Host)
	if err != nil {
		conn.Close()
		return fmt.Errorf("smtp: %w", err)
	}
	defer c.Close()
	if m.smtp.HeloName != "" {
		if err := c.Hello(m.smtp.HeloName); err != nil {
			return err
		}
	}
	if strings.EqualFold(m.smtp.Security, "starttls") {
		if ok, _ := c.Extension("STARTTLS"); !ok {
			return errors.New("smtp-server bietet kein STARTTLS an")
		}
		if err := c.StartTLS(tc); err != nil {
			return fmt.Errorf("starttls: %w", err)
		}
	}
	if m.smtp.Username != "" {
		if err := c.Auth(m.auth(c)); err != nil {
			return fmt.Errorf("smtp-auth: %w", err)
		}
	}
	if err := c.Mail(from.Address); err != nil {
		return err
	}
	for _, r := range append(append(append([]string{}, msg.To...), msg.CC...), msg.BCC...) {
		if err := c.Rcpt(r); err != nil {
			return fmt.Errorf("empfänger %s: %w", r, err)
		}
	}
	w, err := c.Data()
	if err != nil {
		return err
	}
	if _, err := w.Write(raw); err != nil {
		return err
	}
	if err := w.Close(); err != nil {
		return err
	}
	return c.Quit()
}

func (m *Mailer) auth(c *smtp.Client) smtp.Auth {
	_, mechs := c.Extension("AUTH")
	if strings.Contains(strings.ToUpper(mechs), "PLAIN") {
		return &plainAuth{user: m.smtp.Username, pass: m.smtp.Password}
	}
	return &loginAuth{user: m.smtp.Username, pass: m.smtp.Password}
}

func (m *Mailer) build(from *mail.Address, msg Message) ([]byte, error) {
	var b bytes.Buffer
	enc := func(s string) string { return mime.QEncoding.Encode("utf-8", s) }
	hdr := func(k, v string) { fmt.Fprintf(&b, "%s: %s\r\n", k, v) }
	fromHdr := from.Address
	if from.Name != "" {
		fromHdr = enc(from.Name) + " <" + from.Address + ">"
	}
	id := make([]byte, 12)
	_, _ = rand.Read(id)
	domain := "leakguard.local"
	if i := strings.LastIndex(from.Address, "@"); i >= 0 {
		domain = from.Address[i+1:]
	}
	hdr("From", fromHdr)
	hdr("To", strings.Join(msg.To, ", "))
	if len(msg.CC) > 0 {
		hdr("Cc", strings.Join(msg.CC, ", "))
	}
	if m.mail.ReplyTo != "" {
		hdr("Reply-To", m.mail.ReplyTo)
	}
	hdr("Subject", enc(msg.Subject))
	hdr("Date", time.Now().Format(time.RFC1123Z))
	hdr("Message-ID", "<"+hex.EncodeToString(id)+"@"+domain+">")
	hdr("MIME-Version", "1.0")
	hdr("Content-Type", "text/plain; charset=utf-8")
	hdr("Content-Transfer-Encoding", "quoted-printable")
	hdr("Auto-Submitted", "auto-generated")
	hdr("X-Auto-Response-Suppress", "All")
	b.WriteString("\r\n")
	qp := quotedprintable.NewWriter(&b)
	body := strings.ReplaceAll(strings.ReplaceAll(msg.Body, "\r\n", "\n"), "\n", "\r\n")
	if _, err := qp.Write([]byte(body)); err != nil {
		return nil, err
	}
	if err := qp.Close(); err != nil {
		return nil, err
	}
	return b.Bytes(), nil
}

// plainAuth wie smtp.PlainAuth, aber ohne die localhost-Einschränkung (TLS wird vorher erzwungen,
// außer security=none für interne Relays).
type plainAuth struct{ user, pass string }

func (a *plainAuth) Start(_ *smtp.ServerInfo) (string, []byte, error) {
	return "PLAIN", []byte("\x00" + a.user + "\x00" + a.pass), nil
}
func (a *plainAuth) Next(_ []byte, more bool) ([]byte, error) {
	if more {
		return nil, errors.New("unerwartete server-challenge")
	}
	return nil, nil
}

type loginAuth struct{ user, pass string }

func (a *loginAuth) Start(_ *smtp.ServerInfo) (string, []byte, error) { return "LOGIN", nil, nil }
func (a *loginAuth) Next(from []byte, more bool) ([]byte, error) {
	if !more {
		return nil, nil
	}
	switch strings.ToLower(strings.TrimSpace(string(from))) {
	case "username:":
		return []byte(a.user), nil
	case "password:":
		return []byte(a.pass), nil
	}
	return nil, fmt.Errorf("unbekannte login-challenge %q", from)
}
