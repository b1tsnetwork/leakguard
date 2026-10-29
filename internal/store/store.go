// Package store persistiert Fälle, Ereignisse (Audit-Log), Sitzungen und Einstellungen in SQLite.
package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"leakguard/internal/model"

	_ "modernc.org/sqlite" // reines Go, kein CGO
)

var ErrNotFound = errors.New("nicht gefunden")

type Store struct{ db *sql.DB }

const schema = `
CREATE TABLE IF NOT EXISTS cases (
	id              INTEGER PRIMARY KEY AUTOINCREMENT,
	case_number     TEXT NOT NULL,
	created_at      INTEGER NOT NULL,
	created_by      TEXT NOT NULL,
	updated_at      INTEGER NOT NULL,
	identifier      TEXT NOT NULL,
	username        TEXT NOT NULL DEFAULT '',
	display_name    TEXT NOT NULL DEFAULT '',
	email           TEXT NOT NULL DEFAULT '',
	source          TEXT NOT NULL DEFAULT '',
	leak_date       INTEGER NOT NULL DEFAULT 0,
	pw_mask         TEXT NOT NULL DEFAULT '',
	pw_len          INTEGER NOT NULL DEFAULT 0,
	pw_hmac         TEXT NOT NULL DEFAULT '',
	pw_enc          TEXT NOT NULL DEFAULT '',
	compliant       INTEGER NOT NULL DEFAULT 0,
	risk            TEXT NOT NULL DEFAULT '',
	status          TEXT NOT NULL DEFAULT 'offen',
	checks_json     TEXT NOT NULL DEFAULT '{}',
	admin_todo_done INTEGER NOT NULL DEFAULT 0,
	admin_todo_by   TEXT NOT NULL DEFAULT '',
	admin_todo_at   INTEGER NOT NULL DEFAULT 0,
	user_mail_by    TEXT NOT NULL DEFAULT '',
	user_mail_at    INTEGER NOT NULL DEFAULT 0,
	admin_mail_by   TEXT NOT NULL DEFAULT '',
	admin_mail_at   INTEGER NOT NULL DEFAULT 0,
	closed_by       TEXT NOT NULL DEFAULT '',
	closed_at       INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_cases_number ON cases(case_number);
CREATE INDEX IF NOT EXISTS idx_cases_username ON cases(username);
CREATE INDEX IF NOT EXISTS idx_cases_pwhmac ON cases(pw_hmac);
CREATE INDEX IF NOT EXISTS idx_cases_status ON cases(status);

CREATE TABLE IF NOT EXISTS events (
	id       INTEGER PRIMARY KEY AUTOINCREMENT,
	case_id  INTEGER NOT NULL REFERENCES cases(id),
	at       INTEGER NOT NULL,
	actor    TEXT NOT NULL,
	kind     TEXT NOT NULL,
	message  TEXT NOT NULL,
	detail   TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS idx_events_case ON events(case_id);

CREATE TABLE IF NOT EXISTS sessions (
	token_hash TEXT PRIMARY KEY,
	username   TEXT NOT NULL,
	display    TEXT NOT NULL,
	csrf       TEXT NOT NULL,
	created_at INTEGER NOT NULL,
	expires_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS settings (
	key        TEXT PRIMARY KEY,
	value      TEXT NOT NULL,
	updated_at INTEGER NOT NULL,
	updated_by TEXT NOT NULL
);

-- Audit-Log ist append-only: Ereignisse dürfen weder geändert noch gelöscht werden.
CREATE TRIGGER IF NOT EXISTS events_no_update BEFORE UPDATE ON events
BEGIN SELECT RAISE(ABORT, 'audit log is append-only'); END;
CREATE TRIGGER IF NOT EXISTS events_no_delete BEFORE DELETE ON events
BEGIN SELECT RAISE(ABORT, 'audit log is append-only'); END;
`

func Open(path string) (*Store, error) {
	if dir := filepath.Dir(path); dir != "" {
		if err := os.MkdirAll(dir, 0o750); err != nil {
			return nil, err
		}
	}
	dsn := "file:" + path + "?_pragma=journal_mode(WAL)&_pragma=busy_timeout(5000)&_pragma=foreign_keys(1)"
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1)
	if _, err := db.Exec(schema); err != nil {
		return nil, fmt.Errorf("schema anlegen: %w", err)
	}
	s := &Store{db: db}
	if err := s.migrate(); err != nil {
		return nil, fmt.Errorf("migration: %w", err)
	}
	return s, nil
}

// migrate ergänzt Spalten in bestehenden Datenbanken.
func (s *Store) migrate() error {
	cols := map[string]bool{}
	rows, err := s.db.Query(`PRAGMA table_info(cases)`)
	if err != nil {
		return err
	}
	for rows.Next() {
		var cid, notnull, pk int
		var name, typ string
		var def sql.NullString
		if err := rows.Scan(&cid, &name, &typ, &notnull, &def, &pk); err != nil {
			rows.Close()
			return err
		}
		cols[name] = true
	}
	rows.Close()
	if !cols["pw_enc"] {
		if _, err := s.db.Exec(`ALTER TABLE cases ADD COLUMN pw_enc TEXT NOT NULL DEFAULT ''`); err != nil {
			return err
		}
	}
	return nil
}

func (s *Store) Close() error { return s.db.Close() }

func ts(t time.Time) int64 {
	if t.IsZero() {
		return 0
	}
	return t.Unix()
}

func fromTS(v int64) time.Time {
	if v == 0 {
		return time.Time{}
	}
	return time.Unix(v, 0)
}

func b2i(b bool) int {
	if b {
		return 1
	}
	return 0
}

// ---------- Fälle ----------

func (s *Store) CreateCase(ctx context.Context, c *model.Case) error {
	cj, err := json.Marshal(c.Checks)
	if err != nil {
		return err
	}
	now := time.Now()
	c.CreatedAt, c.UpdatedAt = now, now
	if c.Status == "" {
		c.Status = model.StatusOpen
	}
	res, err := s.db.ExecContext(ctx, `INSERT INTO cases
		(case_number, created_at, created_by, updated_at, identifier, username, display_name, email, source, leak_date,
		 pw_mask, pw_len, pw_hmac, pw_enc, compliant, risk, status, checks_json)
		VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
		c.CaseNumber, ts(now), c.CreatedBy, ts(now), c.Identifier, c.Username(), c.DisplayName(), c.Recipient(),
		c.Source, ts(c.LeakDate), c.PwMask, c.PwLen, c.PwHMAC, c.PwEnc, b2i(c.Compliant), c.Risk, c.Status, string(cj))
	if err != nil {
		return err
	}
	c.ID, err = res.LastInsertId()
	return err
}

// UpdateChecks speichert einen erneuten Prüflauf.
func (s *Store) UpdateChecks(ctx context.Context, c *model.Case) error {
	cj, err := json.Marshal(c.Checks)
	if err != nil {
		return err
	}
	_, err = s.db.ExecContext(ctx, `UPDATE cases SET updated_at=?, identifier=?, username=?, display_name=?, email=?,
		pw_mask=?, pw_len=?, pw_hmac=?, pw_enc=?, compliant=?, risk=?, checks_json=? WHERE id=?`,
		ts(time.Now()), c.Identifier, c.Username(), c.DisplayName(), c.Recipient(),
		c.PwMask, c.PwLen, c.PwHMAC, c.PwEnc, b2i(c.Compliant), c.Risk, string(cj), c.ID)
	return err
}

func (s *Store) SetStatus(ctx context.Context, id int64, status, actor string) error {
	closedAt, closedBy := int64(0), ""
	if status == model.StatusClosed {
		closedAt, closedBy = ts(time.Now()), actor
	}
	_, err := s.db.ExecContext(ctx, `UPDATE cases SET status=?, updated_at=?, closed_at=?, closed_by=? WHERE id=?`,
		status, ts(time.Now()), closedAt, closedBy, id)
	return err
}

func (s *Store) MarkAdminTodo(ctx context.Context, id int64, done bool, actor string) error {
	at, by := int64(0), ""
	if done {
		at, by = ts(time.Now()), actor
	}
	_, err := s.db.ExecContext(ctx, `UPDATE cases SET admin_todo_done=?, admin_todo_at=?, admin_todo_by=?, updated_at=? WHERE id=?`,
		b2i(done), at, by, ts(time.Now()), id)
	return err
}

func (s *Store) MarkMailSent(ctx context.Context, id int64, kind, actor string) error {
	col := "user_mail"
	if kind == "admin" {
		col = "admin_mail"
	}
	now := ts(time.Now())
	_, err := s.db.ExecContext(ctx, fmt.Sprintf(`UPDATE cases SET %s_at=?, %s_by=?, updated_at=? WHERE id=?`, col, col),
		now, actor, now, id)
	return err
}

const caseCols = `id, case_number, created_at, created_by, updated_at, identifier, source, leak_date, pw_mask, pw_len, pw_hmac, pw_enc,
	compliant, risk, status, checks_json, admin_todo_done, admin_todo_by, admin_todo_at, user_mail_by, user_mail_at,
	admin_mail_by, admin_mail_at, closed_by, closed_at`

type scanner interface{ Scan(...any) error }

func scanCase(r scanner) (*model.Case, error) {
	var c model.Case
	var created, updated, leak, todoAt, umAt, amAt, closedAt int64
	var compliant, todo int
	var cj string
	if err := r.Scan(&c.ID, &c.CaseNumber, &created, &c.CreatedBy, &updated, &c.Identifier, &c.Source, &leak,
		&c.PwMask, &c.PwLen, &c.PwHMAC, &c.PwEnc, &compliant, &c.Risk, &c.Status, &cj, &todo, &c.AdminTodoBy, &todoAt,
		&c.UserMailBy, &umAt, &c.AdminMailBy, &amAt, &c.ClosedBy, &closedAt); err != nil {
		return nil, err
	}
	c.CreatedAt, c.UpdatedAt, c.LeakDate = fromTS(created), fromTS(updated), fromTS(leak)
	c.AdminTodoAt, c.UserMailAt, c.AdminMailAt, c.ClosedAt = fromTS(todoAt), fromTS(umAt), fromTS(amAt), fromTS(closedAt)
	c.Compliant, c.AdminTodoDone = compliant == 1, todo == 1
	_ = json.Unmarshal([]byte(cj), &c.Checks)
	return &c, nil
}

func (s *Store) GetCase(ctx context.Context, id int64) (*model.Case, error) {
	row := s.db.QueryRowContext(ctx, `SELECT `+caseCols+` FROM cases WHERE id=?`, id)
	c, err := scanCase(row)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	return c, err
}

func (s *Store) ListCases(ctx context.Context, f model.CaseFilter) ([]*model.Case, int, error) {
	var where []string
	var args []any
	if q := strings.TrimSpace(f.Query); q != "" {
		like := "%" + strings.NewReplacer(`\`, `\\`, `%`, `\%`, `_`, `\_`).Replace(strings.ToLower(q)) + "%"
		where = append(where, `(lower(case_number) LIKE ? ESCAPE '\' OR lower(identifier) LIKE ? ESCAPE '\' OR lower(username) LIKE ? ESCAPE '\' OR lower(display_name) LIKE ? ESCAPE '\' OR lower(email) LIKE ? ESCAPE '\')`)
		args = append(args, like, like, like, like, like)
	}
	if f.Status != "" {
		where = append(where, "status = ?")
		args = append(args, f.Status)
	}
	if f.Risk != "" {
		where = append(where, "risk = ?")
		args = append(args, f.Risk)
	}
	w := ""
	if len(where) > 0 {
		w = " WHERE " + strings.Join(where, " AND ")
	}
	var total int
	if err := s.db.QueryRowContext(ctx, `SELECT count(*) FROM cases`+w, args...).Scan(&total); err != nil {
		return nil, 0, err
	}
	limit := f.Limit
	if limit <= 0 {
		limit = 50
	}
	q := `SELECT ` + caseCols + ` FROM cases` + w + ` ORDER BY created_at DESC, id DESC LIMIT ? OFFSET ?`
	rows, err := s.db.QueryContext(ctx, q, append(args, limit, f.Offset)...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()
	var out []*model.Case
	for rows.Next() {
		c, err := scanCase(rows)
		if err != nil {
			return nil, 0, err
		}
		out = append(out, c)
	}
	return out, total, rows.Err()
}

// FindRecurrences sucht frühere Fälle zum selben Konto oder mit identischem Kennwort (HMAC).
func (s *Store) FindRecurrences(ctx context.Context, excludeID int64, username, pwHMAC string) ([]model.Recurrence, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT id, case_number, created_at, pw_hmac FROM cases
		WHERE id <> ? AND ((username <> '' AND lower(username) = lower(?)) OR (pw_hmac <> '' AND pw_hmac = ?))
		ORDER BY created_at DESC LIMIT 20`, excludeID, username, pwHMAC)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []model.Recurrence
	for rows.Next() {
		var r model.Recurrence
		var at int64
		var h string
		if err := rows.Scan(&r.CaseID, &r.CaseNumber, &at, &h); err != nil {
			return nil, err
		}
		r.CreatedAt = fromTS(at)
		r.SamePW = h != "" && h == pwHMAC
		out = append(out, r)
	}
	return out, rows.Err()
}

type Stats struct {
	Open, InProgress, Closed, TodoOpen, Last30 int
}

func (s *Store) Stats(ctx context.Context) (Stats, error) {
	var st Stats
	err := s.db.QueryRowContext(ctx, `SELECT
		coalesce(sum(status='offen'),0), coalesce(sum(status='in_bearbeitung'),0), coalesce(sum(status='abgeschlossen'),0),
		coalesce(sum(status<>'abgeschlossen' AND admin_todo_done=0 AND json_extract(checks_json,'$.actions.admin_todo')=1),0),
		coalesce(sum(created_at >= ?),0) FROM cases`, time.Now().AddDate(0, 0, -30).Unix()).
		Scan(&st.Open, &st.InProgress, &st.Closed, &st.TodoOpen, &st.Last30)
	return st, err
}

// ---------- Ereignisse ----------

func (s *Store) AddEvent(ctx context.Context, caseID int64, actor, kind, msg, detail string) error {
	_, err := s.db.ExecContext(ctx, `INSERT INTO events (case_id, at, actor, kind, message, detail) VALUES (?,?,?,?,?,?)`,
		caseID, ts(time.Now()), actor, kind, msg, detail)
	return err
}

func (s *Store) Events(ctx context.Context, caseID int64) ([]model.Event, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT id, case_id, at, actor, kind, message, detail FROM events WHERE case_id=? ORDER BY at ASC, id ASC`, caseID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []model.Event
	for rows.Next() {
		var e model.Event
		var at int64
		if err := rows.Scan(&e.ID, &e.CaseID, &at, &e.Actor, &e.Kind, &e.Message, &e.Detail); err != nil {
			return nil, err
		}
		e.At = fromTS(at)
		out = append(out, e)
	}
	return out, rows.Err()
}

// ---------- Sitzungen ----------

type Session struct {
	TokenHash string
	Username  string
	Display   string
	CSRF      string
	ExpiresAt time.Time
}

func (s *Store) CreateSession(ctx context.Context, se Session) error {
	_, err := s.db.ExecContext(ctx, `INSERT INTO sessions (token_hash, username, display, csrf, created_at, expires_at) VALUES (?,?,?,?,?,?)`,
		se.TokenHash, se.Username, se.Display, se.CSRF, ts(time.Now()), ts(se.ExpiresAt))
	return err
}

func (s *Store) GetSession(ctx context.Context, tokenHash string) (*Session, error) {
	var se Session
	var exp int64
	err := s.db.QueryRowContext(ctx, `SELECT token_hash, username, display, csrf, expires_at FROM sessions WHERE token_hash=?`, tokenHash).
		Scan(&se.TokenHash, &se.Username, &se.Display, &se.CSRF, &exp)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	se.ExpiresAt = fromTS(exp)
	if time.Now().After(se.ExpiresAt) {
		_ = s.DeleteSession(ctx, tokenHash)
		return nil, ErrNotFound
	}
	return &se, nil
}

func (s *Store) DeleteSession(ctx context.Context, tokenHash string) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM sessions WHERE token_hash=?`, tokenHash)
	return err
}

func (s *Store) PurgeSessions(ctx context.Context) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM sessions WHERE expires_at < ?`, ts(time.Now()))
	return err
}

// ---------- Einstellungen ----------

func (s *Store) Setting(ctx context.Context, key string) (string, bool, error) {
	var v string
	err := s.db.QueryRowContext(ctx, `SELECT value FROM settings WHERE key=?`, key).Scan(&v)
	if errors.Is(err, sql.ErrNoRows) {
		return "", false, nil
	}
	return v, err == nil, err
}

func (s *Store) SetSetting(ctx context.Context, key, value, actor string) error {
	_, err := s.db.ExecContext(ctx, `INSERT INTO settings (key, value, updated_at, updated_by) VALUES (?,?,?,?)
		ON CONFLICT(key) DO UPDATE SET value=excluded.value, updated_at=excluded.updated_at, updated_by=excluded.updated_by`,
		key, value, ts(time.Now()), actor)
	return err
}

func (s *Store) DeleteSetting(ctx context.Context, key string) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM settings WHERE key=?`, key)
	return err
}
