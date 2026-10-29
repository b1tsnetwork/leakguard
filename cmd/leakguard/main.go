// LeakGuard – Abarbeitung von SOC-Meldungen zu geleakten Kennwörtern.
package main

import (
	"bufio"
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"golang.org/x/crypto/bcrypt"
	"golang.org/x/term"

	"leakguard/internal/config"
	"leakguard/internal/engine"
	"leakguard/internal/ldapx"
	"leakguard/internal/mailer"
	"leakguard/internal/store"
	"leakguard/internal/web"
)

var version = "dev"

func main() {
	if len(os.Args) > 1 {
		switch os.Args[1] {
		case "hash-password":
			hashPassword()
			return
		case "version":
			fmt.Println(version)
			return
		case "init-config":
			p := envOr("LEAKGUARD_CONFIG", "config.yaml")
			if len(os.Args) > 2 {
				p = os.Args[2]
			}
			if err := config.WriteExample(p); err != nil {
				fatal(err)
			}
			fmt.Println("Konfiguration angelegt:", p)
			return
		}
	}
	cfgPath := flag.String("config", envOr("LEAKGUARD_CONFIG", "config.yaml"), "Pfad zur Konfigurationsdatei")
	check := flag.Bool("check", false, "Konfiguration, LDAP und SMTP prüfen und beenden")
	flag.Parse()

	slog.SetDefault(slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo})))

	cfg, err := config.Load(*cfgPath)
	if err != nil {
		fatal(err)
	}
	ldc, err := ldapx.New(cfg.LDAP)
	if err != nil {
		fatal(err)
	}
	if *check {
		runCheck(cfg, ldc)
		return
	}
	st, err := store.Open(cfg.DBPath)
	if err != nil {
		fatal(err)
	}
	defer st.Close()

	eng, err := engine.New(cfg, ldc, st)
	if err != nil {
		fatal(err)
	}
	srv, err := web.New(cfg, st, ldc, eng, mailer.New(cfg.SMTP, cfg.Mail), version)
	if err != nil {
		fatal(err)
	}
	if cfg.DevAdmin.Enabled {
		slog.Warn("lokales Entwicklerkonto ist AKTIV – nicht für Produktion", "user", cfg.DevAdmin.Username)
	}
	if !cfg.CookieSecure {
		slog.Warn("cookie_secure ist aus – nur hinter HTTPS-Reverse-Proxy mit cookie_secure: true betreiben")
	}
	if cfg.LDAP.InsecureSkipVerify {
		slog.Warn("ldap.insecure_skip_verify ist aktiv – Zertifikat des DC wird NICHT geprüft")
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	go srv.Janitor(ctx)

	hs := &http.Server{
		Addr:              cfg.Listen,
		Handler:           srv.Handler(),
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      90 * time.Second,
		IdleTimeout:       120 * time.Second,
		MaxHeaderBytes:    1 << 16,
	}
	go func() {
		slog.Info("LeakGuard gestartet", "listen", cfg.Listen, "version", version, "ldap", cfg.LDAP.URL != "", "tls", cfg.TLS.CertFile != "")
		var err error
		if cfg.TLS.CertFile != "" {
			err = hs.ListenAndServeTLS(cfg.TLS.CertFile, cfg.TLS.KeyFile)
		} else {
			err = hs.ListenAndServe()
		}
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			fatal(err)
		}
	}()
	<-ctx.Done()
	slog.Info("beende …")
	sctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	_ = hs.Shutdown(sctx)
}

func runCheck(cfg *config.Config, l *ldapx.Client) {
	fmt.Println("Konfiguration: OK")
	if l.Enabled() {
		if err := l.Ping(); err != nil {
			fmt.Println("LDAP:          FEHLER –", err)
		} else {
			fmt.Println("LDAP:          OK (Service-Bind erfolgreich)")
			if p, err := l.EffectivePolicy(""); err == nil {
				fmt.Printf("Richtlinie:    %s – Mindestlänge %d, Komplexität %v\n", p.Source, p.MinLength, p.Complexity)
			} else {
				fmt.Println("Richtlinie:    nicht lesbar –", err)
			}
		}
	} else {
		fmt.Println("LDAP:          nicht konfiguriert")
	}
	m := mailer.New(cfg.SMTP, cfg.Mail)
	if m.Enabled() {
		fmt.Printf("SMTP:          %s:%d (%s) – Versand wird nicht getestet\n", cfg.SMTP.Host, cfg.SMTP.Port, cfg.SMTP.Security)
	} else {
		fmt.Println("SMTP:          nicht konfiguriert")
	}
}

func hashPassword() {
	var pw []byte
	var err error
	if term.IsTerminal(int(os.Stdin.Fd())) {
		fmt.Fprint(os.Stderr, "Kennwort: ")
		pw, err = term.ReadPassword(int(os.Stdin.Fd()))
		fmt.Fprintln(os.Stderr)
	} else {
		var line string
		line, err = bufio.NewReader(os.Stdin).ReadString('\n')
		if errors.Is(err, nil) || line != "" {
			err = nil
		}
		pw = []byte(strings.TrimRight(line, "\r\n"))
	}
	if err != nil || len(pw) == 0 {
		fatal(errors.New("kein kennwort eingegeben"))
	}
	h, err := bcrypt.GenerateFromPassword(pw, 12)
	if err != nil {
		fatal(err)
	}
	fmt.Println(string(h))
}

func envOr(k, d string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return d
}

func fatal(err error) {
	fmt.Fprintln(os.Stderr, "FEHLER:", err)
	os.Exit(1)
}
