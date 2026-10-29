// Package ldapx kapselt den Zugriff auf das Active Directory über LDAPS.
package ldapx

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/go-ldap/ldap/v3"

	"leakguard/internal/config"
	"leakguard/internal/model"
)

const (
	uacDisabled          = 0x0002
	uacDontExpirePasswd  = 0x10000
	uacComputedLockout   = 0x0010
	uacComputedPwExpired = 0x800000
	oidInChain           = "1.2.840.113556.1.4.1941"
)

var (
	ErrInvalidCredentials = errors.New("benutzername oder kennwort falsch")
	ErrNotAuthorized      = errors.New("benutzer ist nicht in einer berechtigten gruppe")
	ErrNotConfigured      = errors.New("ldap ist nicht konfiguriert")
)

type Client struct {
	cfg config.LDAP
	tls *tls.Config
}

func New(cfg config.LDAP) (*Client, error) {
	c := &Client{cfg: cfg}
	if cfg.URL == "" {
		return c, nil
	}
	u, err := url.Parse(cfg.URL)
	if err != nil {
		return nil, fmt.Errorf("ldap.url: %w", err)
	}
	host := u.Hostname()
	tc := &tls.Config{ServerName: host, MinVersion: tls.VersionTLS12, InsecureSkipVerify: cfg.InsecureSkipVerify} //nolint:gosec // bewusst konfigurierbar
	if cfg.CAFile != "" {
		pem, err := os.ReadFile(cfg.CAFile)
		if err != nil {
			return nil, fmt.Errorf("ldap.ca_file: %w", err)
		}
		pool, _ := x509.SystemCertPool()
		if pool == nil {
			pool = x509.NewCertPool()
		}
		if !pool.AppendCertsFromPEM(pem) {
			return nil, errors.New("ldap.ca_file enthält kein gültiges PEM-Zertifikat")
		}
		tc.RootCAs = pool
	}
	c.tls = tc
	return c, nil
}

func (c *Client) Enabled() bool { return c.cfg.URL != "" }

func (c *Client) dial() (*ldap.Conn, error) {
	if !c.Enabled() {
		return nil, ErrNotConfigured
	}
	conn, err := ldap.DialURL(c.cfg.URL,
		ldap.DialWithTLSConfig(c.tls),
		ldap.DialWithDialer(&net.Dialer{Timeout: c.cfg.Timeout()}))
	if err != nil {
		return nil, fmt.Errorf("verbindung zu %s: %w", c.cfg.URL, err)
	}
	conn.SetTimeout(c.cfg.Timeout())
	if c.cfg.StartTLS && strings.HasPrefix(strings.ToLower(c.cfg.URL), "ldap://") {
		if err := conn.StartTLS(c.tls); err != nil {
			conn.Close()
			return nil, fmt.Errorf("starttls: %w", err)
		}
	}
	return conn, nil
}

func (c *Client) serviceConn() (*ldap.Conn, error) {
	conn, err := c.dial()
	if err != nil {
		return nil, err
	}
	if err := conn.Bind(c.cfg.BindDN, c.cfg.BindPassword); err != nil {
		conn.Close()
		return nil, fmt.Errorf("service-bind fehlgeschlagen: %w", err)
	}
	return conn, nil
}

// Ping prüft Verbindung und Service-Bind (für Health-Check).
func (c *Client) Ping() error {
	conn, err := c.serviceConn()
	if err != nil {
		return err
	}
	conn.Close()
	return nil
}

func normalizeLogin(u string) string {
	u = strings.TrimSpace(u)
	if i := strings.LastIndex(u, `\`); i >= 0 { // DOMAIN\user
		u = u[i+1:]
	}
	return u
}

// Authenticate prüft Anmeldedaten und Gruppenmitgliedschaft und liefert den Anzeigenamen.
func (c *Client) Authenticate(username, password string) (string, string, error) {
	username = normalizeLogin(username)
	if username == "" || password == "" { // leeres Kennwort = unauthenticated bind -> immer ablehnen
		return "", "", ErrInvalidCredentials
	}
	conn, err := c.serviceConn()
	if err != nil {
		return "", "", err
	}
	defer conn.Close()

	filter := strings.ReplaceAll(c.cfg.LoginFilter, "{u}", ldap.EscapeFilter(username))
	sr, err := conn.Search(ldap.NewSearchRequest(c.cfg.BaseDN, ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 2, 0, false,
		filter, []string{"dn", "sAMAccountName", "displayName", "userAccountControl"}, nil))
	if err != nil {
		return "", "", fmt.Errorf("benutzersuche: %w", err)
	}
	if len(sr.Entries) != 1 {
		return "", "", ErrInvalidCredentials
	}
	e := sr.Entries[0]
	if uac, _ := strconv.Atoi(e.GetAttributeValue("userAccountControl")); uac&uacDisabled != 0 {
		return "", "", ErrInvalidCredentials
	}
	ok, err := c.inAnyGroup(conn, e.DN, c.cfg.AdminGroups)
	if err != nil {
		return "", "", err
	}

	// Kennwort mit eigener Verbindung prüfen (Gruppenprüfung erst danach offenlegen).
	uconn, err := c.dial()
	if err != nil {
		return "", "", err
	}
	defer uconn.Close()
	if err := uconn.Bind(e.DN, password); err != nil {
		if ldap.IsErrorWithCode(err, ldap.LDAPResultInvalidCredentials) {
			return "", "", ErrInvalidCredentials
		}
		return "", "", fmt.Errorf("bind: %w", err)
	}
	if !ok {
		return "", "", ErrNotAuthorized
	}
	sam := e.GetAttributeValue("sAMAccountName")
	disp := e.GetAttributeValue("displayName")
	if disp == "" {
		disp = sam
	}
	return sam, disp, nil
}

// MemberOfAny prüft, ob das Konto (ggf. verschachtelt) Mitglied einer der Gruppen ist.
func (c *Client) MemberOfAny(userDN string, groups []string) (bool, error) {
	conn, err := c.serviceConn()
	if err != nil {
		return false, err
	}
	defer conn.Close()
	return c.inAnyGroup(conn, userDN, groups)
}

func (c *Client) inAnyGroup(conn *ldap.Conn, userDN string, groups []string) (bool, error) {
	if len(groups) == 0 {
		return true, nil
	}
	var parts []string
	for _, g := range groups {
		g = strings.TrimSpace(g)
		if g == "" {
			continue
		}
		if c.cfg.NestedGroups {
			parts = append(parts, "(memberOf:"+oidInChain+":="+ldap.EscapeFilter(g)+")")
		} else {
			parts = append(parts, "(memberOf="+ldap.EscapeFilter(g)+")")
		}
	}
	filter := "(|" + strings.Join(parts, "") + ")"
	sr, err := conn.Search(ldap.NewSearchRequest(userDN, ldap.ScopeBaseObject, ldap.NeverDerefAliases, 1, 0, false,
		filter, []string{"dn"}, nil))
	if err != nil {
		if ldap.IsErrorWithCode(err, ldap.LDAPResultNoSuchObject) {
			return false, nil
		}
		return false, fmt.Errorf("gruppenprüfung: %w", err)
	}
	return len(sr.Entries) == 1, nil
}

var userAttrs = []string{"distinguishedName", "sAMAccountName", "userPrincipalName", "mail", "displayName", "givenName", "sn",
	"department", "title", "userAccountControl", "pwdLastSet", "lastLogonTimestamp", "accountExpires", "whenCreated",
	"memberOf", "adminCount", "lockoutTime"}

// FindUsers sucht Konten zu E-Mail, UPN oder sAMAccountName.
func (c *Client) FindUsers(identifier string) ([]model.ADUser, error) {
	q := normalizeLogin(identifier)
	if q == "" {
		return nil, errors.New("leere benutzerkennung")
	}
	conn, err := c.serviceConn()
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	filter := strings.ReplaceAll(c.cfg.UserFilter, "{q}", ldap.EscapeFilter(q))
	sr, err := conn.Search(ldap.NewSearchRequest(c.cfg.BaseDN, ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 10, 0, false,
		filter, userAttrs, nil))
	if err != nil && !ldap.IsErrorWithCode(err, ldap.LDAPResultSizeLimitExceeded) {
		return nil, fmt.Errorf("ldap-suche: %w", err)
	}
	var out []model.ADUser
	for _, e := range sr.Entries {
		u := c.parseUser(e)
		c.enrichComputed(conn, &u)
		out = append(out, u)
	}
	return out, nil
}

func (c *Client) parseUser(e *ldap.Entry) model.ADUser {
	uac, _ := strconv.ParseInt(e.GetAttributeValue("userAccountControl"), 10, 64)
	pls := e.GetAttributeValue("pwdLastSet")
	u := model.ADUser{
		DN:                   e.DN,
		SAM:                  e.GetAttributeValue("sAMAccountName"),
		UPN:                  e.GetAttributeValue("userPrincipalName"),
		Mail:                 e.GetAttributeValue("mail"),
		DisplayName:          e.GetAttributeValue("displayName"),
		GivenName:            e.GetAttributeValue("givenName"),
		Surname:              e.GetAttributeValue("sn"),
		Department:           e.GetAttributeValue("department"),
		Title:                e.GetAttributeValue("title"),
		Enabled:              uac&uacDisabled == 0,
		PasswordNeverExpires: uac&uacDontExpirePasswd != 0,
		AdminCount:           e.GetAttributeValue("adminCount") == "1",
		PwdLastSet:           FileTime(pls),
		MustChangePassword:   pls == "0",
		LastLogon:            FileTime(e.GetAttributeValue("lastLogonTimestamp")),
		AccountExpires:       FileTime(e.GetAttributeValue("accountExpires")),
		WhenCreated:          GeneralizedTime(e.GetAttributeValue("whenCreated")),
		MemberOf:             e.GetAttributeValues("memberOf"),
	}
	if lt := e.GetAttributeValue("lockoutTime"); lt != "" && lt != "0" {
		u.LockedOut = true // wird ggf. durch msDS-User-Account-Control-Computed präzisiert
	}
	if !u.AccountExpires.IsZero() && u.AccountExpires.Before(time.Now()) {
		u.AccountExpired = true
	}
	for _, g := range u.MemberOf {
		cn := groupCN(g)
		for _, p := range c.cfg.PrivilegedGroups {
			if strings.EqualFold(p, cn) || strings.EqualFold(p, g) {
				u.Privileged = append(u.Privileged, cn)
				break
			}
		}
	}
	return u
}

// enrichComputed liest konstruierte Attribute (nur per Base-Search verfügbar).
func (c *Client) enrichComputed(conn *ldap.Conn, u *model.ADUser) {
	sr, err := conn.Search(ldap.NewSearchRequest(u.DN, ldap.ScopeBaseObject, ldap.NeverDerefAliases, 1, 0, false,
		"(objectClass=*)", []string{"msDS-User-Account-Control-Computed"}, nil))
	if err != nil || len(sr.Entries) != 1 {
		return
	}
	v := sr.Entries[0].GetAttributeValue("msDS-User-Account-Control-Computed")
	if v == "" {
		return
	}
	cv, _ := strconv.ParseInt(v, 10, 64)
	u.LockedOut = cv&uacComputedLockout != 0
	u.PasswordExpired = cv&uacComputedPwExpired != 0
}

// EffectivePolicy liest die für den Nutzer gültige Kennwortrichtlinie (PSO oder Domäne).
type EffectivePolicy struct {
	MinLength  int
	Complexity bool
	Source     string
}

func (c *Client) EffectivePolicy(userDN string) (*EffectivePolicy, error) {
	conn, err := c.serviceConn()
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	// 1) Fine-Grained Password Policy (PSO) – benötigt Leserecht auf den Password Settings Container.
	if userDN != "" {
		sr, err := conn.Search(ldap.NewSearchRequest(userDN, ldap.ScopeBaseObject, ldap.NeverDerefAliases, 1, 0, false,
			"(objectClass=*)", []string{"msDS-ResultantPSO"}, nil))
		if err == nil && len(sr.Entries) == 1 {
			if pso := sr.Entries[0].GetAttributeValue("msDS-ResultantPSO"); pso != "" {
				ps, err := conn.Search(ldap.NewSearchRequest(pso, ldap.ScopeBaseObject, ldap.NeverDerefAliases, 1, 0, false,
					"(objectClass=*)", []string{"msDS-MinimumPasswordLength", "msDS-PasswordComplexityEnabled"}, nil))
				if err == nil && len(ps.Entries) == 1 && ps.Entries[0].GetAttributeValue("msDS-MinimumPasswordLength") != "" {
					e := ps.Entries[0]
					ml, _ := strconv.Atoi(e.GetAttributeValue("msDS-MinimumPasswordLength"))
					return &EffectivePolicy{MinLength: ml,
						Complexity: strings.EqualFold(e.GetAttributeValue("msDS-PasswordComplexityEnabled"), "TRUE"),
						Source:     "AD-PSO " + groupCN(pso)}, nil
				}
			}
		}
	}
	// 2) Domänenrichtlinie
	if c.cfg.DomainDN == "" {
		return nil, errors.New("domain_dn unbekannt")
	}
	sr, err := conn.Search(ldap.NewSearchRequest(c.cfg.DomainDN, ldap.ScopeBaseObject, ldap.NeverDerefAliases, 1, 0, false,
		"(objectClass=*)", []string{"minPwdLength", "pwdProperties"}, nil))
	if err != nil {
		return nil, fmt.Errorf("domänenrichtlinie lesen: %w", err)
	}
	if len(sr.Entries) != 1 || sr.Entries[0].GetAttributeValue("minPwdLength") == "" {
		return nil, errors.New("domänenrichtlinie nicht lesbar")
	}
	e := sr.Entries[0]
	ml, _ := strconv.Atoi(e.GetAttributeValue("minPwdLength"))
	pp, _ := strconv.Atoi(e.GetAttributeValue("pwdProperties"))
	return &EffectivePolicy{MinLength: ml, Complexity: pp&1 == 1, Source: "AD-Domänenrichtlinie"}, nil
}

// TestBind versucht eine Anmeldung mit dem geleakten Kennwort.
// ACHTUNG: Ein Fehlversuch erhöht badPwdCount des Kontos.
func (c *Client) TestBind(userDN, password string) (bool, string, error) {
	if password == "" {
		return false, "leeres kennwort", nil
	}
	conn, err := c.dial()
	if err != nil {
		return false, "", err
	}
	defer conn.Close()
	err = conn.Bind(userDN, password)
	if err == nil {
		return true, "Anmeldung erfolgreich – Kennwort ist AKTUELL GÜLTIG", nil
	}
	if ldap.IsErrorWithCode(err, ldap.LDAPResultInvalidCredentials) {
		return adSubcode(err.Error())
	}
	return false, "", err
}

// adSubcode wertet den AD-Diagnosecode (data xxx) aus.
func adSubcode(msg string) (bool, string, error) {
	codes := map[string]struct {
		valid bool
		text  string
	}{
		"52e": {false, "Kennwort ist nicht (mehr) gültig"},
		"525": {false, "Benutzer nicht gefunden"},
		"530": {true, "Kennwort korrekt – Anmeldung zu dieser Zeit nicht erlaubt"},
		"531": {true, "Kennwort korrekt – Anmeldung an dieser Arbeitsstation nicht erlaubt"},
		"532": {true, "Kennwort korrekt, aber abgelaufen"},
		"533": {true, "Kennwort korrekt, Konto deaktiviert"},
		"701": {true, "Kennwort korrekt, Konto abgelaufen"},
		"773": {true, "Kennwort korrekt – Benutzer muss Kennwort ändern"},
		"775": {false, "Konto gesperrt – Ergebnis nicht bestimmbar"},
	}
	lm := strings.ToLower(msg)
	for code, r := range codes {
		if strings.Contains(lm, "data "+code) {
			return r.valid, r.text + " (AD-Code " + code + ")", nil
		}
	}
	return false, "Anmeldung abgelehnt", nil
}

func groupCN(dn string) string {
	first := strings.SplitN(dn, ",", 2)[0]
	if strings.HasPrefix(strings.ToUpper(first), "CN=") {
		return first[3:]
	}
	return dn
}

// FileTime konvertiert Windows FILETIME (100ns seit 1601) nach time.Time.
func FileTime(v string) time.Time {
	n, err := strconv.ParseInt(v, 10, 64)
	if err != nil || n <= 0 || n == 9223372036854775807 {
		return time.Time{}
	}
	const epochDiff = 116444736000000000
	if n < epochDiff {
		return time.Time{}
	}
	return time.Unix(0, (n-epochDiff)*100)
}

func GeneralizedTime(v string) time.Time {
	t, err := time.Parse("20060102150405.0Z0700", v)
	if err != nil {
		t, err = time.Parse("20060102150405Z", v)
		if err != nil {
			return time.Time{}
		}
	}
	return t
}
