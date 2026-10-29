// Package config lädt und validiert die LeakGuard-Konfiguration.
package config

import (
	"crypto/rand"
	_ "embed"
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

type Config struct {
	Listen       string `yaml:"listen"`
	BaseURL      string `yaml:"base_url"`
	DBPath       string `yaml:"db_path"`
	Secret       string `yaml:"secret"`
	CookieSecure bool   `yaml:"cookie_secure"`
	SessionHours int    `yaml:"session_hours"`
	TrustProxy   bool   `yaml:"trust_proxy"`
	TLS          TLS    `yaml:"tls"`

	LDAP     LDAP     `yaml:"ldap"`
	SMTP     SMTP     `yaml:"smtp"`
	Mail     Mail     `yaml:"mail"`
	Policy   Policy   `yaml:"policy"`
	HIBP     HIBP     `yaml:"hibp"`
	DevAdmin DevAdmin `yaml:"dev_admin"`
}

type TLS struct {
	CertFile string `yaml:"cert_file"`
	KeyFile  string `yaml:"key_file"`
}

type LDAP struct {
	URL                string   `yaml:"url"`
	StartTLS           bool     `yaml:"start_tls"`
	CAFile             string   `yaml:"ca_file"`
	InsecureSkipVerify bool     `yaml:"insecure_skip_verify"`
	TimeoutSeconds     int      `yaml:"timeout_seconds"`
	BindDN             string   `yaml:"bind_dn"`
	BindPassword       string   `yaml:"bind_password"`
	BaseDN             string   `yaml:"base_dn"`
	DomainDN           string   `yaml:"domain_dn"`
	UserFilter         string   `yaml:"user_filter"`
	LoginFilter        string   `yaml:"login_filter"`
	AdminGroups        []string `yaml:"admin_groups"`
	NestedGroups       bool     `yaml:"nested_groups"`
	PrivilegedGroups   []string `yaml:"privileged_groups"`
	// Erlaubt im Fallformular den optionalen Bind-Test mit dem geleakten Kennwort.
	AllowBindTest bool `yaml:"allow_bind_test"`
}

type SMTP struct {
	Host               string `yaml:"host"`
	Port               int    `yaml:"port"`
	Security           string `yaml:"security"` // starttls | tls | none
	Username           string `yaml:"username"`
	Password           string `yaml:"password"`
	InsecureSkipVerify bool   `yaml:"insecure_skip_verify"`
	HeloName           string `yaml:"helo_name"`
}

type Mail struct {
	From            string   `yaml:"from"`
	ReplyTo         string   `yaml:"reply_to"`
	AdminRecipients []string `yaml:"admin_recipients"`
	UserBCC         []string `yaml:"user_bcc"`
	OrgName         string   `yaml:"org_name"`
	Signature       string   `yaml:"signature"`
}

type Policy struct {
	// Liest Mindestlänge/Komplexität aus dem AD (Domänenrichtlinie bzw. PSO des Nutzers)
	// und überschreibt damit die statischen Werte, sofern lesbar.
	ReadFromAD    bool     `yaml:"read_from_ad"`
	MinLength     int      `yaml:"min_length"`
	Complexity    bool     `yaml:"complexity"`
	MinCategories int      `yaml:"min_categories"`
	Blocklist     []string `yaml:"blocklist"`
	BlocklistFile string   `yaml:"blocklist_file"`
}

type HIBP struct {
	Enabled        bool   `yaml:"enabled"`
	URL            string `yaml:"url"`
	TimeoutSeconds int    `yaml:"timeout_seconds"`
}

type DevAdmin struct {
	Enabled      bool   `yaml:"enabled"`
	Username     string `yaml:"username"`
	PasswordHash string `yaml:"password_hash"` // bcrypt, erzeugen mit: leakguard hash-password
}

func (l LDAP) Timeout() time.Duration {
	if l.TimeoutSeconds <= 0 {
		return 10 * time.Second
	}
	return time.Duration(l.TimeoutSeconds) * time.Second
}

func (h HIBP) Timeout() time.Duration {
	if h.TimeoutSeconds <= 0 {
		return 8 * time.Second
	}
	return time.Duration(h.TimeoutSeconds) * time.Second
}

//go:embed config.example.yaml
var exampleConfig string

// ErrCreated signalisiert, dass eine neue Beispielkonfiguration angelegt wurde.
var ErrCreated = errors.New("konfiguration wurde angelegt")

// WriteExample legt eine Beispielkonfiguration mit frisch erzeugtem secret an (überschreibt nichts).
func WriteExample(path string) error {
	if dir := filepath.Dir(path); dir != "" {
		if err := os.MkdirAll(dir, 0o750); err != nil {
			return err
		}
	}
	b := make([]byte, 48)
	if _, err := rand.Read(b); err != nil {
		return err
	}
	content := strings.Replace(exampleConfig, `secret: ""`, `secret: "`+base64.RawStdEncoding.EncodeToString(b)+`"`, 1)
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	defer f.Close()
	_, err = f.WriteString(content)
	return err
}

// Load liest die YAML-Datei, setzt Defaults und übernimmt Geheimnisse aus Umgebungsvariablen.
// Fehlt die Datei, wird eine Beispielkonfiguration angelegt und ErrCreated geliefert.
// Relative Pfade in der Konfiguration (db_path, ca_file, …) beziehen sich auf das Verzeichnis der Konfigurationsdatei.
func Load(path string) (*Config, error) {
	raw, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		if werr := WriteExample(path); werr != nil {
			return nil, fmt.Errorf("konfiguration fehlt und konnte nicht angelegt werden: %w", werr)
		}
		return nil, fmt.Errorf("%w: %s – bitte anpassen und neu starten", ErrCreated, path)
	}
	if err != nil {
		return nil, fmt.Errorf("konfiguration lesen: %w", err)
	}
	cfg := &Config{}
	if err := yaml.Unmarshal(raw, cfg); err != nil {
		return nil, fmt.Errorf("konfiguration parsen: %w", err)
	}
	cfg.applyEnv()
	cfg.applyDefaults()
	cfg.resolvePaths(filepath.Dir(path))
	if err := cfg.validate(); err != nil {
		return nil, err
	}
	return cfg, nil
}

func (c *Config) resolvePaths(base string) {
	abs := func(p *string) {
		if *p != "" && !filepath.IsAbs(*p) {
			*p = filepath.Join(base, *p)
		}
	}
	abs(&c.DBPath)
	abs(&c.LDAP.CAFile)
	abs(&c.Policy.BlocklistFile)
	abs(&c.TLS.CertFile)
	abs(&c.TLS.KeyFile)
}

func (c *Config) applyEnv() {
	set := func(dst *string, key string) {
		if v, ok := os.LookupEnv(key); ok && v != "" {
			*dst = v
		}
	}
	set(&c.Secret, "LEAKGUARD_SECRET")
	set(&c.LDAP.BindPassword, "LEAKGUARD_LDAP_BIND_PASSWORD")
	set(&c.SMTP.Password, "LEAKGUARD_SMTP_PASSWORD")
	set(&c.DevAdmin.PasswordHash, "LEAKGUARD_DEV_ADMIN_HASH")
}

func (c *Config) applyDefaults() {
	if c.Listen == "" {
		c.Listen = ":8080"
	}
	if c.DBPath == "" {
		c.DBPath = "leakguard.db"
	}
	if c.SessionHours <= 0 {
		c.SessionHours = 8
	}
	c.BaseURL = strings.TrimRight(c.BaseURL, "/")
	if c.LDAP.UserFilter == "" {
		c.LDAP.UserFilter = "(&(objectCategory=person)(objectClass=user)(|(sAMAccountName={q})(userPrincipalName={q})(mail={q})(proxyAddresses=smtp:{q})))"
	}
	if c.LDAP.LoginFilter == "" {
		c.LDAP.LoginFilter = "(&(objectCategory=person)(objectClass=user)(|(sAMAccountName={u})(userPrincipalName={u})))"
	}
	if c.LDAP.DomainDN == "" {
		c.LDAP.DomainDN = domainFromBase(c.LDAP.BaseDN)
	}
	if len(c.LDAP.PrivilegedGroups) == 0 {
		c.LDAP.PrivilegedGroups = []string{"Domain Admins", "Domänen-Admins", "Enterprise Admins", "Organisations-Admins", "Schema Admins", "Schema-Admins", "Administrators", "Administratoren", "Account Operators", "Konten-Operatoren", "Backup Operators", "Sicherungs-Operatoren", "Server Operators", "Server-Operatoren"}
	}
	if c.SMTP.Port == 0 {
		switch strings.ToLower(c.SMTP.Security) {
		case "tls":
			c.SMTP.Port = 465
		case "none":
			c.SMTP.Port = 25
		default:
			c.SMTP.Port = 587
		}
	}
	if c.SMTP.Security == "" {
		c.SMTP.Security = "starttls"
	}
	if c.Policy.MinLength <= 0 {
		c.Policy.MinLength = 12
	}
	if c.Policy.MinCategories <= 0 {
		c.Policy.MinCategories = 3
	}
	if c.HIBP.URL == "" {
		c.HIBP.URL = "https://api.pwnedpasswords.com/range/"
	}
	if c.Mail.OrgName == "" {
		c.Mail.OrgName = "IT-Abteilung"
	}
	if c.Mail.Signature == "" {
		c.Mail.Signature = "Mit freundlichen Grüßen\nIhre " + c.Mail.OrgName
	}
}

func (c *Config) validate() error {
	var errs []string
	if len(c.Secret) < 32 {
		errs = append(errs, "secret muss mindestens 32 Zeichen lang sein (oder LEAKGUARD_SECRET setzen)")
	}
	if c.LDAP.URL == "" && !c.DevAdmin.Enabled {
		errs = append(errs, "ldap.url fehlt (oder dev_admin aktivieren)")
	}
	if c.LDAP.URL != "" {
		if c.LDAP.BaseDN == "" {
			errs = append(errs, "ldap.base_dn fehlt")
		}
		if strings.HasPrefix(strings.ToLower(c.LDAP.URL), "ldap://") && !c.LDAP.StartTLS {
			errs = append(errs, "ldap.url nutzt ldap:// ohne start_tls – bitte ldaps:// verwenden")
		}
		if c.LDAP.BindDN != "" && c.LDAP.BindPassword == "" {
			errs = append(errs, "ldap.bind_password fehlt (oder LEAKGUARD_LDAP_BIND_PASSWORD setzen)")
		}
		if len(c.LDAP.AdminGroups) == 0 {
			errs = append(errs, "ldap.admin_groups ist leer – ohne Gruppe dürfte sich jeder AD-Nutzer anmelden")
		}
	}
	if c.DevAdmin.Enabled && (c.DevAdmin.Username == "" || c.DevAdmin.PasswordHash == "") {
		errs = append(errs, "dev_admin benötigt username und password_hash")
	}
	if len(errs) > 0 {
		return errors.New("ungültige konfiguration:\n  - " + strings.Join(errs, "\n  - "))
	}
	return nil
}

func domainFromBase(base string) string {
	var dcs []string
	for _, p := range strings.Split(base, ",") {
		p = strings.TrimSpace(p)
		if strings.HasPrefix(strings.ToUpper(p), "DC=") {
			dcs = append(dcs, p)
		}
	}
	return strings.Join(dcs, ",")
}
