package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"leakguard/internal/model"
)

const incidentSchema = `
CREATE TABLE IF NOT EXISTS users (
	username   TEXT PRIMARY KEY COLLATE NOCASE,
	display    TEXT NOT NULL DEFAULT '',
	mail       TEXT NOT NULL DEFAULT '',
	role       TEXT NOT NULL DEFAULT '',
	last_login INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS incidents (
	id            INTEGER PRIMARY KEY AUTOINCREMENT,
	number        TEXT NOT NULL UNIQUE,
	title         TEXT NOT NULL,
	category      TEXT NOT NULL DEFAULT '',
	severity      TEXT NOT NULL DEFAULT 'P3',
	phase         TEXT NOT NULL DEFAULT 'gemeldet',
	tlp           TEXT NOT NULL DEFAULT 'AMBER',
	classification TEXT NOT NULL DEFAULT '',
	confidential  INTEGER NOT NULL DEFAULT 0,
	description   TEXT NOT NULL DEFAULT '',
	source        TEXT NOT NULL DEFAULT '',
	reported_by   TEXT NOT NULL DEFAULT '',
	lead          TEXT NOT NULL DEFAULT '',
	impact_c      INTEGER NOT NULL DEFAULT 0,
	impact_i      INTEGER NOT NULL DEFAULT 0,
	impact_a      INTEGER NOT NULL DEFAULT 0,
	personal_data INTEGER NOT NULL DEFAULT 0,
	affected_users INTEGER NOT NULL DEFAULT 0,
	occurred_at   INTEGER NOT NULL DEFAULT 0,
	detected_at   INTEGER NOT NULL DEFAULT 0,
	awareness_at  INTEGER NOT NULL DEFAULT 0,
	contained_at  INTEGER NOT NULL DEFAULT 0,
	resolved_at   INTEGER NOT NULL DEFAULT 0,
	closed_at     INTEGER NOT NULL DEFAULT 0,
	crisis_mode   INTEGER NOT NULL DEFAULT 0,
	next_briefing INTEGER NOT NULL DEFAULT 0,
	root_cause    TEXT NOT NULL DEFAULT '',
	lessons       TEXT NOT NULL DEFAULT '',
	improvements  TEXT NOT NULL DEFAULT '',
	leak_case_id  INTEGER NOT NULL DEFAULT 0,
	created_at    INTEGER NOT NULL,
	created_by    TEXT NOT NULL,
	updated_at    INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_incidents_phase ON incidents(phase);

CREATE TABLE IF NOT EXISTS incident_members (
	incident_id INTEGER NOT NULL REFERENCES incidents(id),
	username    TEXT NOT NULL COLLATE NOCASE,
	display     TEXT NOT NULL DEFAULT '',
	function    TEXT NOT NULL DEFAULT '',
	role        TEXT NOT NULL DEFAULT 'mitglied',
	added_at    INTEGER NOT NULL,
	added_by    TEXT NOT NULL,
	PRIMARY KEY (incident_id, username)
);

CREATE TABLE IF NOT EXISTS journal (
	id          INTEGER PRIMARY KEY AUTOINCREMENT,
	incident_id INTEGER NOT NULL REFERENCES incidents(id),
	at          INTEGER NOT NULL,
	occurred_at INTEGER NOT NULL DEFAULT 0,
	actor       TEXT NOT NULL,
	kind        TEXT NOT NULL,
	text        TEXT NOT NULL,
	ref_id      INTEGER NOT NULL DEFAULT 0,
	auto        INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_journal_incident ON journal(incident_id, at);
CREATE TRIGGER IF NOT EXISTS journal_no_update BEFORE UPDATE ON journal BEGIN SELECT RAISE(ABORT, 'journal is append-only'); END;
CREATE TRIGGER IF NOT EXISTS journal_no_delete BEFORE DELETE ON journal BEGIN SELECT RAISE(ABORT, 'journal is append-only'); END;

CREATE TABLE IF NOT EXISTS tasks (
	id          INTEGER PRIMARY KEY AUTOINCREMENT,
	incident_id INTEGER NOT NULL REFERENCES incidents(id),
	title       TEXT NOT NULL,
	details     TEXT NOT NULL DEFAULT '',
	function    TEXT NOT NULL DEFAULT '',
	assignee    TEXT NOT NULL DEFAULT '',
	priority    TEXT NOT NULL DEFAULT 'mittel',
	status      TEXT NOT NULL DEFAULT 'offen',
	due_at      INTEGER NOT NULL DEFAULT 0,
	result      TEXT NOT NULL DEFAULT '',
	created_at  INTEGER NOT NULL,
	created_by  TEXT NOT NULL,
	updated_at  INTEGER NOT NULL,
	done_at     INTEGER NOT NULL DEFAULT 0,
	done_by     TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS idx_tasks_incident ON tasks(incident_id);

CREATE TABLE IF NOT EXISTS communications (
	id          INTEGER PRIMARY KEY AUTOINCREMENT,
	incident_id INTEGER NOT NULL REFERENCES incidents(id),
	direction   TEXT NOT NULL,
	scope       TEXT NOT NULL,
	channel     TEXT NOT NULL DEFAULT '',
	party_type  TEXT NOT NULL DEFAULT '',
	party       TEXT NOT NULL DEFAULT '',
	subject     TEXT NOT NULL,
	content     TEXT NOT NULL DEFAULT '',
	occurred_at INTEGER NOT NULL DEFAULT 0,
	tlp         TEXT NOT NULL DEFAULT '',
	needs_reply INTEGER NOT NULL DEFAULT 0,
	reply_due   INTEGER NOT NULL DEFAULT 0,
	status      TEXT NOT NULL,
	approved_by TEXT NOT NULL DEFAULT '',
	approved_at INTEGER NOT NULL DEFAULT 0,
	created_at  INTEGER NOT NULL,
	created_by  TEXT NOT NULL,
	updated_at  INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_comms_incident ON communications(incident_id);

CREATE TABLE IF NOT EXISTS assets (
	id          INTEGER PRIMARY KEY AUTOINCREMENT,
	incident_id INTEGER NOT NULL REFERENCES incidents(id),
	name        TEXT NOT NULL,
	kind        TEXT NOT NULL DEFAULT '',
	identifier  TEXT NOT NULL DEFAULT '',
	owner       TEXT NOT NULL DEFAULT '',
	criticality TEXT NOT NULL DEFAULT '',
	status      TEXT NOT NULL DEFAULT 'verdacht',
	notes       TEXT NOT NULL DEFAULT '',
	created_at  INTEGER NOT NULL,
	created_by  TEXT NOT NULL,
	updated_at  INTEGER NOT NULL,
	updated_by  TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS idx_assets_incident ON assets(incident_id);

CREATE TABLE IF NOT EXISTS iocs (
	id          INTEGER PRIMARY KEY AUTOINCREMENT,
	incident_id INTEGER NOT NULL REFERENCES incidents(id),
	type        TEXT NOT NULL,
	value       TEXT NOT NULL,
	description TEXT NOT NULL DEFAULT '',
	tlp         TEXT NOT NULL DEFAULT '',
	created_at  INTEGER NOT NULL,
	created_by  TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_iocs_incident ON iocs(incident_id);

CREATE TABLE IF NOT EXISTS obligations (
	id          INTEGER PRIMARY KEY AUTOINCREMENT,
	incident_id INTEGER NOT NULL REFERENCES incidents(id),
	regulation  TEXT NOT NULL,
	key         TEXT NOT NULL,
	label       TEXT NOT NULL,
	authority   TEXT NOT NULL DEFAULT '',
	hours       INTEGER NOT NULL,
	after       TEXT NOT NULL DEFAULT '',
	status      TEXT NOT NULL DEFAULT 'offen',
	reference   TEXT NOT NULL DEFAULT '',
	note        TEXT NOT NULL DEFAULT '',
	done_at     INTEGER NOT NULL DEFAULT 0,
	done_by     TEXT NOT NULL DEFAULT '',
	created_at  INTEGER NOT NULL,
	UNIQUE (incident_id, key)
);

CREATE TABLE IF NOT EXISTS sitreps (
	id          INTEGER PRIMARY KEY AUTOINCREMENT,
	incident_id INTEGER NOT NULL REFERENCES incidents(id),
	no          INTEGER NOT NULL,
	at          INTEGER NOT NULL,
	by          TEXT NOT NULL,
	situation   TEXT NOT NULL DEFAULT '',
	impact      TEXT NOT NULL DEFAULT '',
	actions     TEXT NOT NULL DEFAULT '',
	outlook     TEXT NOT NULL DEFAULT '',
	decisions   TEXT NOT NULL DEFAULT '',
	next_at     INTEGER NOT NULL DEFAULT 0,
	phase       TEXT NOT NULL DEFAULT '',
	severity    TEXT NOT NULL DEFAULT ''
);
CREATE TRIGGER IF NOT EXISTS sitreps_no_update BEFORE UPDATE ON sitreps BEGIN SELECT RAISE(ABORT, 'sitreps are append-only'); END;
CREATE TRIGGER IF NOT EXISTS sitreps_no_delete BEFORE DELETE ON sitreps BEGIN SELECT RAISE(ABORT, 'sitreps are append-only'); END;

CREATE TABLE IF NOT EXISTS rec_dismissals (
	incident_id INTEGER NOT NULL REFERENCES incidents(id),
	key         TEXT NOT NULL,
	at          INTEGER NOT NULL,
	by          TEXT NOT NULL,
	reason      TEXT NOT NULL DEFAULT '',
	PRIMARY KEY (incident_id, key)
);

CREATE TABLE IF NOT EXISTS audit (
	id          INTEGER PRIMARY KEY AUTOINCREMENT,
	at          INTEGER NOT NULL,
	actor       TEXT NOT NULL,
	ip          TEXT NOT NULL DEFAULT '',
	action      TEXT NOT NULL,
	object      TEXT NOT NULL DEFAULT '',
	object_id   INTEGER NOT NULL DEFAULT 0,
	incident_id INTEGER NOT NULL DEFAULT 0,
	detail      TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS idx_audit_incident ON audit(incident_id);
CREATE TRIGGER IF NOT EXISTS audit_no_update BEFORE UPDATE ON audit BEGIN SELECT RAISE(ABORT, 'audit log is append-only'); END;
CREATE TRIGGER IF NOT EXISTS audit_no_delete BEFORE DELETE ON audit BEGIN SELECT RAISE(ABORT, 'audit log is append-only'); END;
`

// Viewer beschreibt, wer abfragt – für die Sichtbarkeit vertraulicher Vorfälle.
type Viewer struct {
	Username string
	SeeAll   bool // Admin
}

// vis liefert eine SQL-Bedingung für sichtbare Vorfälle (Alias a = incidents).
func vis(alias string, v Viewer) (string, []any) {
	return fmt.Sprintf(`(%[1]s.confidential = 0 OR ? OR EXISTS (SELECT 1 FROM incident_members m WHERE m.incident_id = %[1]s.id AND m.username = ? COLLATE NOCASE))`, alias),
		[]any{v.SeeAll, v.Username}
}

func b(i int) bool { return i == 1 }

// ---------- Benutzer ----------

func (s *Store) UpsertUser(ctx context.Context, u model.User) error {
	_, err := s.db.ExecContext(ctx, `INSERT INTO users (username, display, mail, role, last_login) VALUES (?,?,?,?,?)
		ON CONFLICT(username) DO UPDATE SET display=excluded.display, mail=excluded.mail, role=excluded.role, last_login=excluded.last_login`,
		u.Username, u.Display, u.Mail, u.Role, ts(time.Now()))
	return err
}

func (s *Store) Users(ctx context.Context) ([]model.User, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT username, display, mail, role, last_login FROM users ORDER BY display COLLATE NOCASE`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []model.User
	for rows.Next() {
		var u model.User
		var ll int64
		if err := rows.Scan(&u.Username, &u.Display, &u.Mail, &u.Role, &ll); err != nil {
			return nil, err
		}
		u.LastLogin = fromTS(ll)
		out = append(out, u)
	}
	return out, rows.Err()
}

func (s *Store) User(ctx context.Context, username string) (model.User, error) {
	var u model.User
	var ll int64
	err := s.db.QueryRowContext(ctx, `SELECT username, display, mail, role, last_login FROM users WHERE username = ?`, username).
		Scan(&u.Username, &u.Display, &u.Mail, &u.Role, &ll)
	if errors.Is(err, sql.ErrNoRows) {
		return u, ErrNotFound
	}
	u.LastLogin = fromTS(ll)
	return u, err
}

// ---------- Vorfälle ----------

const incCols = `i.id, i.number, i.title, i.category, i.severity, i.phase, i.tlp, i.classification, i.confidential, i.description, i.source, i.reported_by, i.lead,
	i.impact_c, i.impact_i, i.impact_a, i.personal_data, i.affected_users, i.occurred_at, i.detected_at, i.awareness_at, i.contained_at,
	i.resolved_at, i.closed_at, i.crisis_mode, i.next_briefing, i.root_cause, i.lessons, i.improvements, i.leak_case_id,
	i.created_at, i.created_by, i.updated_at, i.cancelled, i.cancel_reason, i.cancelled_at, i.cancelled_by, i.wf_version_id`

func scanIncident(r scanner) (*model.Incident, error) {
	var i model.Incident
	var conf, ic, ii, ia, pd, crisis, canc int
	var occ, det, aw, cont, res, clo, nb, cr, up, cat int64
	if err := r.Scan(&i.ID, &i.Number, &i.Title, &i.Category, &i.Severity, &i.Phase, &i.TLP, &i.Classification, &conf, &i.Description, &i.Source,
		&i.ReportedBy, &i.Lead, &ic, &ii, &ia, &pd, &i.AffectedUsers, &occ, &det, &aw, &cont, &res, &clo, &crisis, &nb,
		&i.RootCause, &i.Lessons, &i.Improvements, &i.LeakCaseID, &cr, &i.CreatedBy, &up, &canc, &i.CancelReason, &cat, &i.CancelledBy, &i.WFVersionID); err != nil {
		return nil, err
	}
	i.Confidential, i.ImpactC, i.ImpactI, i.ImpactA, i.PersonalData, i.CrisisMode = b(conf), b(ic), b(ii), b(ia), b(pd), b(crisis)
	i.OccurredAt, i.DetectedAt, i.AwarenessAt, i.ContainedAt, i.ResolvedAt, i.ClosedAt = fromTS(occ), fromTS(det), fromTS(aw), fromTS(cont), fromTS(res), fromTS(clo)
	i.NextBriefing, i.CreatedAt, i.UpdatedAt = fromTS(nb), fromTS(cr), fromTS(up)
	i.Cancelled, i.CancelledAt = b(canc), fromTS(cat)
	return &i, nil
}

// CreateIncident legt den Vorfall an und vergibt die laufende Nummer (PREFIX-JJJJ-NNNN).
func (s *Store) CreateIncident(ctx context.Context, prefix string, in *model.Incident) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback() //nolint:errcheck
	year := time.Now().Year()
	pat := fmt.Sprintf("%s-%d-%%", prefix, year)
	var n int
	if err := tx.QueryRowContext(ctx, `SELECT count(*) FROM incidents WHERE number LIKE ?`, pat).Scan(&n); err != nil {
		return err
	}
	in.Number = fmt.Sprintf("%s-%d-%04d", prefix, year, n+1)
	now := time.Now()
	in.CreatedAt, in.UpdatedAt = now, now
	res, err := tx.ExecContext(ctx, `INSERT INTO incidents (number, title, category, severity, phase, tlp, classification, confidential, description, source,
		reported_by, lead, impact_c, impact_i, impact_a, personal_data, affected_users, occurred_at, detected_at, awareness_at, crisis_mode,
		leak_case_id, created_at, created_by, updated_at, wf_version_id) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
		in.Number, in.Title, in.Category, in.Severity, in.Phase, in.TLP, in.Classification, b2i(in.Confidential), in.Description, in.Source,
		in.ReportedBy, in.Lead, b2i(in.ImpactC), b2i(in.ImpactI), b2i(in.ImpactA), b2i(in.PersonalData), in.AffectedUsers,
		ts(in.OccurredAt), ts(in.DetectedAt), ts(in.AwarenessAt), b2i(in.CrisisMode), in.LeakCaseID, ts(now), in.CreatedBy, ts(now), in.WFVersionID)
	if err != nil {
		return err
	}
	if in.ID, err = res.LastInsertId(); err != nil {
		return err
	}
	return tx.Commit()
}

// UpdateIncident speichert alle veränderlichen Felder.
func (s *Store) UpdateIncident(ctx context.Context, in *model.Incident) error {
	in.UpdatedAt = time.Now()
	_, err := s.db.ExecContext(ctx, `UPDATE incidents SET title=?, category=?, severity=?, phase=?, tlp=?, classification=?, confidential=?, description=?,
		source=?, reported_by=?, lead=?, impact_c=?, impact_i=?, impact_a=?, personal_data=?, affected_users=?, occurred_at=?, detected_at=?,
		awareness_at=?, contained_at=?, resolved_at=?, closed_at=?, crisis_mode=?, next_briefing=?, root_cause=?, lessons=?, improvements=?,
		leak_case_id=?, updated_at=?, cancelled=?, cancel_reason=?, cancelled_at=?, cancelled_by=?, wf_version_id=? WHERE id=?`,
		in.Title, in.Category, in.Severity, in.Phase, in.TLP, in.Classification, b2i(in.Confidential), in.Description, in.Source, in.ReportedBy, in.Lead,
		b2i(in.ImpactC), b2i(in.ImpactI), b2i(in.ImpactA), b2i(in.PersonalData), in.AffectedUsers, ts(in.OccurredAt), ts(in.DetectedAt),
		ts(in.AwarenessAt), ts(in.ContainedAt), ts(in.ResolvedAt), ts(in.ClosedAt), b2i(in.CrisisMode), ts(in.NextBriefing),
		in.RootCause, in.Lessons, in.Improvements, in.LeakCaseID, ts(in.UpdatedAt), b2i(in.Cancelled), in.CancelReason,
		ts(in.CancelledAt), in.CancelledBy, in.WFVersionID, in.ID)
	return err
}

func (s *Store) Touch(ctx context.Context, incidentID int64) {
	_, _ = s.db.ExecContext(ctx, `UPDATE incidents SET updated_at=? WHERE id=?`, ts(time.Now()), incidentID)
}

func (s *Store) GetIncident(ctx context.Context, id int64) (*model.Incident, error) {
	in, err := scanIncident(s.db.QueryRowContext(ctx, `SELECT `+incCols+` FROM incidents i WHERE i.id=?`, id))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	return in, err
}

func (s *Store) IncidentByLeakCase(ctx context.Context, caseID int64) (*model.Incident, error) {
	in, err := scanIncident(s.db.QueryRowContext(ctx, `SELECT `+incCols+` FROM incidents i WHERE i.leak_case_id=? ORDER BY i.id LIMIT 1`, caseID))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	return in, err
}

func (s *Store) ListIncidents(ctx context.Context, v Viewer, f model.IncidentFilter) ([]*model.Incident, error) {
	w, args := vis("i", v)
	where := []string{w}
	switch f.State {
	case "", "aktiv":
		where = append(where, "i.phase <> 'abgeschlossen'", "i.cancelled = 0")
	case "abgeschlossen":
		where = append(where, "i.phase = 'abgeschlossen'", "i.cancelled = 0")
	case "storniert":
		where = append(where, "i.cancelled = 1")
	default:
		where = append(where, "i.cancelled = 0")
	}
	if f.Severity != "" {
		where, args = append(where, "i.severity = ?"), append(args, f.Severity)
	}
	if f.Category != "" {
		where, args = append(where, "i.category = ?"), append(args, f.Category)
	}
	if q := strings.TrimSpace(f.Query); q != "" {
		like := "%" + strings.NewReplacer(`\`, `\\`, `%`, `\%`, `_`, `\_`).Replace(strings.ToLower(q)) + "%"
		where = append(where, `(lower(i.number) LIKE ? ESCAPE '\' OR lower(i.title) LIKE ? ESCAPE '\' OR lower(i.description) LIKE ? ESCAPE '\')`)
		args = append(args, like, like, like)
	}
	rows, err := s.db.QueryContext(ctx, `SELECT `+incCols+` FROM incidents i WHERE `+strings.Join(where, " AND ")+
		` ORDER BY CASE WHEN i.phase='abgeschlossen' THEN 1 ELSE 0 END, i.severity, i.created_at DESC LIMIT 500`, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*model.Incident
	for rows.Next() {
		in, err := scanIncident(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, in)
	}
	return out, rows.Err()
}

// CanSee prüft die Sichtbarkeit eines Vorfalls.
func (s *Store) CanSee(ctx context.Context, v Viewer, incidentID int64) bool {
	w, args := vis("i", v)
	var n int
	_ = s.db.QueryRowContext(ctx, `SELECT count(*) FROM incidents i WHERE i.id = ? AND `+w, append([]any{incidentID}, args...)...).Scan(&n)
	return n == 1
}

// ---------- Stab ----------

func (s *Store) Members(ctx context.Context, incidentID int64) ([]model.Member, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT incident_id, username, display, function, role, added_at, added_by FROM incident_members
		WHERE incident_id=? ORDER BY CASE role WHEN 'leitung' THEN 0 WHEN 'mitglied' THEN 1 ELSE 2 END, display COLLATE NOCASE`, incidentID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []model.Member
	for rows.Next() {
		var m model.Member
		var at int64
		if err := rows.Scan(&m.IncidentID, &m.Username, &m.Display, &m.Function, &m.Role, &at, &m.AddedBy); err != nil {
			return nil, err
		}
		m.AddedAt = fromTS(at)
		out = append(out, m)
	}
	return out, rows.Err()
}

func (s *Store) MemberRole(ctx context.Context, incidentID int64, username string) string {
	var r string
	_ = s.db.QueryRowContext(ctx, `SELECT role FROM incident_members WHERE incident_id=? AND username=?`, incidentID, username).Scan(&r)
	return r
}

func (s *Store) UpsertMember(ctx context.Context, m model.Member) error {
	_, err := s.db.ExecContext(ctx, `INSERT INTO incident_members (incident_id, username, display, function, role, added_at, added_by)
		VALUES (?,?,?,?,?,?,?) ON CONFLICT(incident_id, username) DO UPDATE SET display=excluded.display, function=excluded.function, role=excluded.role`,
		m.IncidentID, m.Username, m.Display, m.Function, m.Role, ts(time.Now()), m.AddedBy)
	return err
}

func (s *Store) RemoveMember(ctx context.Context, incidentID int64, username string) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM incident_members WHERE incident_id=? AND username=?`, incidentID, username)
	return err
}

// ---------- Einsatztagebuch ----------

func (s *Store) AddJournal(ctx context.Context, e *model.JournalEntry) error {
	if e.At.IsZero() {
		e.At = time.Now()
	}
	res, err := s.db.ExecContext(ctx, `INSERT INTO journal (incident_id, at, occurred_at, actor, kind, text, ref_id, auto) VALUES (?,?,?,?,?,?,?,?)`,
		e.IncidentID, ts(e.At), ts(e.OccurredAt), e.Actor, e.Kind, e.Text, e.RefID, b2i(e.Auto))
	if err != nil {
		return err
	}
	e.ID, _ = res.LastInsertId()
	s.Touch(ctx, e.IncidentID)
	return nil
}

const jCols = `j.id, j.incident_id, j.at, j.occurred_at, j.actor, j.kind, j.text, j.ref_id, j.auto, i.number, i.title`

func scanJournal(rows *sql.Rows) ([]model.JournalEntry, error) {
	defer rows.Close()
	var out []model.JournalEntry
	for rows.Next() {
		var e model.JournalEntry
		var at, occ int64
		var auto int
		if err := rows.Scan(&e.ID, &e.IncidentID, &at, &occ, &e.Actor, &e.Kind, &e.Text, &e.RefID, &auto, &e.IncidentNumber, &e.IncidentTitle); err != nil {
			return nil, err
		}
		e.At, e.OccurredAt, e.Auto = fromTS(at), fromTS(occ), auto == 1
		out = append(out, e)
	}
	return out, rows.Err()
}

func (s *Store) Journal(ctx context.Context, incidentID int64, kind string, includeAuto bool) ([]model.JournalEntry, error) {
	q := `SELECT ` + jCols + ` FROM journal j JOIN incidents i ON i.id=j.incident_id WHERE j.incident_id=?`
	args := []any{incidentID}
	if kind != "" {
		q, args = q+` AND j.kind=?`, append(args, kind)
	}
	if !includeAuto {
		q += ` AND j.auto=0`
	}
	rows, err := s.db.QueryContext(ctx, q+` ORDER BY j.at DESC, j.id DESC`, args...)
	if err != nil {
		return nil, err
	}
	return scanJournal(rows)
}

// RecentJournal – Live-Ticker über alle sichtbaren, aktiven Vorfälle.
func (s *Store) RecentJournal(ctx context.Context, v Viewer, limit int) ([]model.JournalEntry, error) {
	w, args := vis("i", v)
	rows, err := s.db.QueryContext(ctx, `SELECT `+jCols+` FROM journal j JOIN incidents i ON i.id=j.incident_id WHERE `+w+
		` AND i.phase <> 'abgeschlossen' AND i.cancelled = 0 ORDER BY j.at DESC, j.id DESC LIMIT ?`, append(args, limit)...)
	if err != nil {
		return nil, err
	}
	return scanJournal(rows)
}

func (s *Store) LastJournal(ctx context.Context, incidentID int64) (model.JournalEntry, bool) {
	rows, err := s.db.QueryContext(ctx, `SELECT `+jCols+` FROM journal j JOIN incidents i ON i.id=j.incident_id WHERE j.incident_id=? ORDER BY j.at DESC, j.id DESC LIMIT 1`, incidentID)
	if err != nil {
		return model.JournalEntry{}, false
	}
	l, err := scanJournal(rows)
	if err != nil || len(l) == 0 {
		return model.JournalEntry{}, false
	}
	return l[0], true
}

// ---------- Aufgaben ----------

const tCols = `t.id, t.incident_id, t.title, t.details, t.function, t.assignee, t.priority, t.status, t.due_at, t.result,
	t.created_at, t.created_by, t.updated_at, t.done_at, t.done_by, t.wf_step, t.rec_key, i.number, i.title`

func scanTasks(rows *sql.Rows) ([]model.Task, error) {
	defer rows.Close()
	var out []model.Task
	for rows.Next() {
		var t model.Task
		var due, cr, up, done int64
		if err := rows.Scan(&t.ID, &t.IncidentID, &t.Title, &t.Details, &t.Function, &t.Assignee, &t.Priority, &t.Status, &due, &t.Result,
			&cr, &t.CreatedBy, &up, &done, &t.DoneBy, &t.WFStep, &t.RecKey, &t.IncidentNumber, &t.IncidentTitle); err != nil {
			return nil, err
		}
		t.DueAt, t.CreatedAt, t.UpdatedAt, t.DoneAt = fromTS(due), fromTS(cr), fromTS(up), fromTS(done)
		out = append(out, t)
	}
	return out, rows.Err()
}

const taskOrder = ` ORDER BY CASE WHEN t.status IN ('erledigt','verworfen') THEN 1 ELSE 0 END,
	CASE t.priority WHEN 'hoch' THEN 0 WHEN 'mittel' THEN 1 ELSE 2 END, CASE WHEN t.due_at=0 THEN 1 ELSE 0 END, t.due_at, t.id`

func (s *Store) Tasks(ctx context.Context, incidentID int64) ([]model.Task, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT `+tCols+` FROM tasks t JOIN incidents i ON i.id=t.incident_id WHERE t.incident_id=?`+taskOrder, incidentID)
	if err != nil {
		return nil, err
	}
	return scanTasks(rows)
}

// OpenTasks – offene Aufgaben aller sichtbaren aktiven Vorfälle (optional nur für einen Bearbeiter).
func (s *Store) OpenTasks(ctx context.Context, v Viewer, assignee string) ([]model.Task, error) {
	w, args := vis("i", v)
	q := `SELECT ` + tCols + ` FROM tasks t JOIN incidents i ON i.id=t.incident_id WHERE ` + w +
		` AND i.phase <> 'abgeschlossen' AND i.cancelled = 0 AND t.status NOT IN ('erledigt','verworfen')`
	if assignee != "" {
		q, args = q+` AND t.assignee = ? COLLATE NOCASE`, append(args, assignee)
	}
	rows, err := s.db.QueryContext(ctx, q+taskOrder, args...)
	if err != nil {
		return nil, err
	}
	return scanTasks(rows)
}

func (s *Store) GetTask(ctx context.Context, id int64) (*model.Task, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT `+tCols+` FROM tasks t JOIN incidents i ON i.id=t.incident_id WHERE t.id=?`, id)
	if err != nil {
		return nil, err
	}
	l, err := scanTasks(rows)
	if err != nil {
		return nil, err
	}
	if len(l) == 0 {
		return nil, ErrNotFound
	}
	return &l[0], nil
}

func (s *Store) CreateTask(ctx context.Context, t *model.Task) error {
	now := time.Now()
	if t.Status == "" {
		t.Status = "offen"
	}
	res, err := s.db.ExecContext(ctx, `INSERT INTO tasks (incident_id, title, details, function, assignee, priority, status, due_at, created_at, created_by, updated_at, wf_step, rec_key)
		VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)`, t.IncidentID, t.Title, t.Details, t.Function, t.Assignee, t.Priority, t.Status, ts(t.DueAt), ts(now), t.CreatedBy, ts(now), t.WFStep, t.RecKey)
	if err != nil {
		return err
	}
	t.ID, _ = res.LastInsertId()
	s.Touch(ctx, t.IncidentID)
	return nil
}

func (s *Store) UpdateTask(ctx context.Context, t *model.Task) error {
	_, err := s.db.ExecContext(ctx, `UPDATE tasks SET title=?, details=?, function=?, assignee=?, priority=?, status=?, due_at=?, result=?,
		updated_at=?, done_at=?, done_by=?, wf_step=? WHERE id=?`, t.Title, t.Details, t.Function, t.Assignee, t.Priority, t.Status, ts(t.DueAt), t.Result,
		ts(time.Now()), ts(t.DoneAt), t.DoneBy, t.WFStep, t.ID)
	s.Touch(ctx, t.IncidentID)
	return err
}

// ---------- Kommunikation ----------

const cCols = `c.id, c.incident_id, c.direction, c.scope, c.channel, c.party_type, c.party, c.subject, c.content, c.occurred_at, c.tlp,
	c.needs_reply, c.reply_due, c.status, c.approved_by, c.approved_at, c.created_at, c.created_by, c.updated_at, i.number, i.title`

func scanComms(rows *sql.Rows) ([]model.Communication, error) {
	defer rows.Close()
	var out []model.Communication
	for rows.Next() {
		var c model.Communication
		var occ, due, appr, cr, up int64
		var nr int
		if err := rows.Scan(&c.ID, &c.IncidentID, &c.Direction, &c.Scope, &c.Channel, &c.PartyType, &c.Party, &c.Subject, &c.Content, &occ,
			&c.TLP, &nr, &due, &c.Status, &c.ApprovedBy, &appr, &cr, &c.CreatedBy, &up, &c.IncidentNumber, &c.IncidentTitle); err != nil {
			return nil, err
		}
		c.OccurredAt, c.ReplyDue, c.ApprovedAt, c.CreatedAt, c.UpdatedAt, c.NeedsReply = fromTS(occ), fromTS(due), fromTS(appr), fromTS(cr), fromTS(up), nr == 1
		out = append(out, c)
	}
	return out, rows.Err()
}

func (s *Store) Comms(ctx context.Context, incidentID int64) ([]model.Communication, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT `+cCols+` FROM communications c JOIN incidents i ON i.id=c.incident_id WHERE c.incident_id=?
		ORDER BY c.occurred_at DESC, c.id DESC`, incidentID)
	if err != nil {
		return nil, err
	}
	return scanComms(rows)
}

// PendingComms – offene Anfragen und Freigaben aller sichtbaren aktiven Vorfälle.
func (s *Store) PendingComms(ctx context.Context, v Viewer) ([]model.Communication, error) {
	w, args := vis("i", v)
	rows, err := s.db.QueryContext(ctx, `SELECT `+cCols+` FROM communications c JOIN incidents i ON i.id=c.incident_id WHERE `+w+
		` AND i.phase <> 'abgeschlossen' AND i.cancelled = 0 AND ((c.direction='ein' AND c.needs_reply=1 AND c.status NOT IN ('beantwortet','erledigt')) OR c.status='zur_freigabe')
		ORDER BY CASE WHEN c.reply_due=0 THEN 1 ELSE 0 END, c.reply_due, c.occurred_at`, args...)
	if err != nil {
		return nil, err
	}
	return scanComms(rows)
}

func (s *Store) GetComm(ctx context.Context, id int64) (*model.Communication, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT `+cCols+` FROM communications c JOIN incidents i ON i.id=c.incident_id WHERE c.id=?`, id)
	if err != nil {
		return nil, err
	}
	l, err := scanComms(rows)
	if err != nil {
		return nil, err
	}
	if len(l) == 0 {
		return nil, ErrNotFound
	}
	return &l[0], nil
}

func (s *Store) CreateComm(ctx context.Context, c *model.Communication) error {
	now := time.Now()
	if c.OccurredAt.IsZero() {
		c.OccurredAt = now
	}
	res, err := s.db.ExecContext(ctx, `INSERT INTO communications (incident_id, direction, scope, channel, party_type, party, subject, content,
		occurred_at, tlp, needs_reply, reply_due, status, created_at, created_by, updated_at) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
		c.IncidentID, c.Direction, c.Scope, c.Channel, c.PartyType, c.Party, c.Subject, c.Content, ts(c.OccurredAt), c.TLP,
		b2i(c.NeedsReply), ts(c.ReplyDue), c.Status, ts(now), c.CreatedBy, ts(now))
	if err != nil {
		return err
	}
	c.ID, _ = res.LastInsertId()
	s.Touch(ctx, c.IncidentID)
	return nil
}

func (s *Store) UpdateCommStatus(ctx context.Context, c *model.Communication) error {
	_, err := s.db.ExecContext(ctx, `UPDATE communications SET status=?, approved_by=?, approved_at=?, updated_at=? WHERE id=?`,
		c.Status, c.ApprovedBy, ts(c.ApprovedAt), ts(time.Now()), c.ID)
	s.Touch(ctx, c.IncidentID)
	return err
}

// ---------- Systeme ----------

func (s *Store) Assets(ctx context.Context, incidentID int64) ([]model.Asset, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT id, incident_id, name, kind, identifier, owner, criticality, status, notes, created_at, created_by,
		updated_at, updated_by FROM assets WHERE incident_id=? ORDER BY CASE status WHEN 'kompromittiert' THEN 0 WHEN 'in_untersuchung' THEN 1
		WHEN 'verdacht' THEN 2 WHEN 'isoliert' THEN 3 ELSE 4 END, name COLLATE NOCASE`, incidentID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []model.Asset
	for rows.Next() {
		var a model.Asset
		var cr, up int64
		if err := rows.Scan(&a.ID, &a.IncidentID, &a.Name, &a.Kind, &a.Identifier, &a.Owner, &a.Criticality, &a.Status, &a.Notes,
			&cr, &a.CreatedBy, &up, &a.UpdatedBy); err != nil {
			return nil, err
		}
		a.CreatedAt, a.UpdatedAt = fromTS(cr), fromTS(up)
		out = append(out, a)
	}
	return out, rows.Err()
}

func (s *Store) GetAsset(ctx context.Context, id int64) (*model.Asset, error) {
	var a model.Asset
	var cr, up int64
	err := s.db.QueryRowContext(ctx, `SELECT id, incident_id, name, kind, identifier, owner, criticality, status, notes, created_at, created_by,
		updated_at, updated_by FROM assets WHERE id=?`, id).Scan(&a.ID, &a.IncidentID, &a.Name, &a.Kind, &a.Identifier, &a.Owner, &a.Criticality,
		&a.Status, &a.Notes, &cr, &a.CreatedBy, &up, &a.UpdatedBy)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	a.CreatedAt, a.UpdatedAt = fromTS(cr), fromTS(up)
	return &a, err
}

func (s *Store) CreateAsset(ctx context.Context, a *model.Asset) error {
	now := ts(time.Now())
	res, err := s.db.ExecContext(ctx, `INSERT INTO assets (incident_id, name, kind, identifier, owner, criticality, status, notes, created_at, created_by, updated_at, updated_by)
		VALUES (?,?,?,?,?,?,?,?,?,?,?,?)`, a.IncidentID, a.Name, a.Kind, a.Identifier, a.Owner, a.Criticality, a.Status, a.Notes, now, a.CreatedBy, now, a.CreatedBy)
	if err != nil {
		return err
	}
	a.ID, _ = res.LastInsertId()
	s.Touch(ctx, a.IncidentID)
	return nil
}

func (s *Store) UpdateAsset(ctx context.Context, a *model.Asset) error {
	_, err := s.db.ExecContext(ctx, `UPDATE assets SET status=?, notes=?, updated_at=?, updated_by=? WHERE id=?`,
		a.Status, a.Notes, ts(time.Now()), a.UpdatedBy, a.ID)
	s.Touch(ctx, a.IncidentID)
	return err
}

// ---------- IOCs ----------

func (s *Store) IOCs(ctx context.Context, incidentID int64) ([]model.IOC, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT id, incident_id, type, value, description, tlp, created_at, created_by FROM iocs WHERE incident_id=? ORDER BY type, value`, incidentID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []model.IOC
	for rows.Next() {
		var o model.IOC
		var cr int64
		if err := rows.Scan(&o.ID, &o.IncidentID, &o.Type, &o.Value, &o.Description, &o.TLP, &cr, &o.CreatedBy); err != nil {
			return nil, err
		}
		o.CreatedAt = fromTS(cr)
		out = append(out, o)
	}
	return out, rows.Err()
}

func (s *Store) CreateIOC(ctx context.Context, o *model.IOC) error {
	res, err := s.db.ExecContext(ctx, `INSERT INTO iocs (incident_id, type, value, description, tlp, created_at, created_by) VALUES (?,?,?,?,?,?,?)`,
		o.IncidentID, o.Type, o.Value, o.Description, o.TLP, ts(time.Now()), o.CreatedBy)
	if err != nil {
		return err
	}
	o.ID, _ = res.LastInsertId()
	s.Touch(ctx, o.IncidentID)
	return nil
}

func (s *Store) DeleteIOC(ctx context.Context, incidentID, id int64) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM iocs WHERE id=? AND incident_id=?`, id, incidentID)
	return err
}

// ---------- Meldepflichten ----------

func (s *Store) AddObligation(ctx context.Context, o model.Obligation) error {
	_, err := s.db.ExecContext(ctx, `INSERT OR IGNORE INTO obligations (incident_id, regulation, key, label, authority, hours, after, status, created_at)
		VALUES (?,?,?,?,?,?,?,'offen',?)`, o.IncidentID, o.Regulation, o.Key, o.Label, o.Authority, o.Hours, o.After, ts(time.Now()))
	return err
}

const oCols = `o.id, o.incident_id, o.regulation, o.key, o.label, o.authority, o.hours, o.after, o.status, o.reference, o.note,
	o.done_at, o.done_by, o.created_at, i.number, i.title, i.awareness_at, i.created_at`

func scanObligations(rows *sql.Rows) ([]model.Obligation, error) {
	defer rows.Close()
	var out []model.Obligation
	awareness := map[int64]time.Time{}
	for rows.Next() {
		var o model.Obligation
		var done, cr, aw, icr int64
		if err := rows.Scan(&o.ID, &o.IncidentID, &o.Regulation, &o.Key, &o.Label, &o.Authority, &o.Hours, &o.After, &o.Status, &o.Reference,
			&o.Note, &done, &o.DoneBy, &cr, &o.IncidentNumber, &o.IncidentTitle, &aw, &icr); err != nil {
			return nil, err
		}
		o.DoneAt, o.CreatedAt = fromTS(done), fromTS(cr)
		start := fromTS(aw)
		if start.IsZero() {
			start = fromTS(icr)
		}
		awareness[o.IncidentID] = start
		out = append(out, o)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	ComputeDue(out, awareness)
	return out, nil
}

// ComputeDue berechnet Fälligkeiten: Stunden ab Kenntnisnahme bzw. ab Erledigung (sonst Fälligkeit) der Vorgängerfrist.
func ComputeDue(list []model.Obligation, awareness map[int64]time.Time) {
	byKey := map[string]*model.Obligation{}
	for i := range list {
		byKey[fmt.Sprintf("%d/%s", list[i].IncidentID, list[i].Key)] = &list[i]
	}
	var due func(o *model.Obligation, depth int) time.Time
	due = func(o *model.Obligation, depth int) time.Time {
		base := awareness[o.IncidentID]
		if o.After != "" && depth < 5 {
			if p, ok := byKey[fmt.Sprintf("%d/%s", o.IncidentID, o.After)]; ok {
				if !p.DoneAt.IsZero() {
					base = p.DoneAt
				} else {
					base = due(p, depth+1)
				}
			}
		}
		return base.Add(time.Duration(o.Hours) * time.Hour)
	}
	for i := range list {
		list[i].DueAt = due(&list[i], 0)
	}
}

func (s *Store) Obligations(ctx context.Context, incidentID int64) ([]model.Obligation, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT `+oCols+` FROM obligations o JOIN incidents i ON i.id=o.incident_id WHERE o.incident_id=? ORDER BY o.id`, incidentID)
	if err != nil {
		return nil, err
	}
	list, err := scanObligations(rows)
	sortByDue(list)
	return list, err
}

// OpenObligations – offene Fristen aller sichtbaren aktiven Vorfälle, nach Fälligkeit sortiert.
func (s *Store) OpenObligations(ctx context.Context, v Viewer) ([]model.Obligation, error) {
	w, args := vis("i", v)
	rows, err := s.db.QueryContext(ctx, `SELECT `+oCols+` FROM obligations o JOIN incidents i ON i.id=o.incident_id
		WHERE `+w+` AND i.phase <> 'abgeschlossen' AND i.cancelled = 0 AND o.incident_id IN (SELECT incident_id FROM obligations WHERE status='offen') ORDER BY o.id`, args...)
	if err != nil {
		return nil, err
	}
	all, err := scanObligations(rows)
	if err != nil {
		return nil, err
	}
	var out []model.Obligation
	for _, o := range all {
		if o.Open() {
			out = append(out, o)
		}
	}
	sortByDue(out)
	return out, nil
}

func sortByDue(l []model.Obligation) {
	sort.SliceStable(l, func(i, j int) bool { return l[i].DueAt.Before(l[j].DueAt) })
}

func (s *Store) GetObligation(ctx context.Context, id int64) (*model.Obligation, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT `+oCols+` FROM obligations o JOIN incidents i ON i.id=o.incident_id WHERE o.id=?`, id)
	if err != nil {
		return nil, err
	}
	l, err := scanObligations(rows)
	if err != nil {
		return nil, err
	}
	if len(l) == 0 {
		return nil, ErrNotFound
	}
	return &l[0], nil
}

func (s *Store) UpdateObligation(ctx context.Context, o *model.Obligation) error {
	_, err := s.db.ExecContext(ctx, `UPDATE obligations SET status=?, reference=?, note=?, done_at=?, done_by=? WHERE id=?`,
		o.Status, o.Reference, o.Note, ts(o.DoneAt), o.DoneBy, o.ID)
	s.Touch(ctx, o.IncidentID)
	return err
}

// ---------- Lagemeldungen ----------

func (s *Store) AddSitrep(ctx context.Context, r *model.Sitrep) error {
	var n int
	_ = s.db.QueryRowContext(ctx, `SELECT coalesce(max(no),0) FROM sitreps WHERE incident_id=?`, r.IncidentID).Scan(&n)
	r.No, r.At = n+1, time.Now()
	res, err := s.db.ExecContext(ctx, `INSERT INTO sitreps (incident_id, no, at, by, situation, impact, actions, outlook, decisions, next_at, phase, severity)
		VALUES (?,?,?,?,?,?,?,?,?,?,?,?)`, r.IncidentID, r.No, ts(r.At), r.By, r.Situation, r.Impact, r.Actions, r.Outlook, r.Decisions, ts(r.Next), r.Phase, r.Severity)
	if err != nil {
		return err
	}
	r.ID, _ = res.LastInsertId()
	s.Touch(ctx, r.IncidentID)
	return nil
}

func (s *Store) Sitreps(ctx context.Context, incidentID int64) ([]model.Sitrep, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT id, incident_id, no, at, by, situation, impact, actions, outlook, decisions, next_at, phase, severity
		FROM sitreps WHERE incident_id=? ORDER BY no DESC`, incidentID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []model.Sitrep
	for rows.Next() {
		var r model.Sitrep
		var at, next int64
		if err := rows.Scan(&r.ID, &r.IncidentID, &r.No, &at, &r.By, &r.Situation, &r.Impact, &r.Actions, &r.Outlook, &r.Decisions, &next, &r.Phase, &r.Severity); err != nil {
			return nil, err
		}
		r.At, r.Next = fromTS(at), fromTS(next)
		out = append(out, r)
	}
	return out, rows.Err()
}

// ---------- Audit ----------

func (s *Store) Audit(ctx context.Context, a model.AuditEntry) {
	_, _ = s.db.ExecContext(ctx, `INSERT INTO audit (at, actor, ip, action, object, object_id, incident_id, detail) VALUES (?,?,?,?,?,?,?,?)`,
		ts(time.Now()), a.Actor, a.IP, a.Action, a.Object, a.ObjectID, a.IncidentID, a.Detail)
}

type AuditFilter struct {
	IncidentID int64
	Actor      string
	Query      string
	Limit      int
	Offset     int
}

func (s *Store) AuditLog(ctx context.Context, f AuditFilter) ([]model.AuditEntry, int, error) {
	where, args := []string{"1=1"}, []any{}
	if f.IncidentID > 0 {
		where, args = append(where, "incident_id=?"), append(args, f.IncidentID)
	}
	if f.Actor != "" {
		where, args = append(where, "actor=? COLLATE NOCASE"), append(args, f.Actor)
	}
	if q := strings.TrimSpace(f.Query); q != "" {
		like := "%" + strings.ToLower(q) + "%"
		where, args = append(where, "(lower(action) LIKE ? OR lower(detail) LIKE ? OR lower(object) LIKE ?)"), append(args, like, like, like)
	}
	w := strings.Join(where, " AND ")
	var total int
	if err := s.db.QueryRowContext(ctx, `SELECT count(*) FROM audit WHERE `+w, args...).Scan(&total); err != nil {
		return nil, 0, err
	}
	if f.Limit <= 0 {
		f.Limit = 100
	}
	rows, err := s.db.QueryContext(ctx, `SELECT id, at, actor, ip, action, object, object_id, incident_id, detail FROM audit WHERE `+w+
		` ORDER BY id DESC LIMIT ? OFFSET ?`, append(args, f.Limit, f.Offset)...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()
	var out []model.AuditEntry
	for rows.Next() {
		var a model.AuditEntry
		var at int64
		if err := rows.Scan(&a.ID, &at, &a.Actor, &a.IP, &a.Action, &a.Object, &a.ObjectID, &a.IncidentID, &a.Detail); err != nil {
			return nil, 0, err
		}
		a.At = fromTS(at)
		out = append(out, a)
	}
	return out, total, rows.Err()
}

// ---------- Kennzahlen ----------

type IncidentCounts struct {
	OpenTasks, OverdueTasks, OpenRequests, PendingApprovals, Assets, Compromised, IOCs, OpenObligations int
}

func (s *Store) Counts(ctx context.Context, incidentID int64) IncidentCounts {
	var c IncidentCounts
	now := ts(time.Now())
	_ = s.db.QueryRowContext(ctx, `SELECT
		(SELECT count(*) FROM tasks WHERE incident_id=?1 AND status NOT IN ('erledigt','verworfen')),
		(SELECT count(*) FROM tasks WHERE incident_id=?1 AND status NOT IN ('erledigt','verworfen') AND due_at>0 AND due_at<?2),
		(SELECT count(*) FROM communications WHERE incident_id=?1 AND direction='ein' AND needs_reply=1 AND status NOT IN ('beantwortet','erledigt')),
		(SELECT count(*) FROM communications WHERE incident_id=?1 AND status='zur_freigabe'),
		(SELECT count(*) FROM assets WHERE incident_id=?1 AND status<>'nicht_betroffen'),
		(SELECT count(*) FROM assets WHERE incident_id=?1 AND status='kompromittiert'),
		(SELECT count(*) FROM iocs WHERE incident_id=?1),
		(SELECT count(*) FROM obligations WHERE incident_id=?1 AND status='offen')`, incidentID, now).
		Scan(&c.OpenTasks, &c.OverdueTasks, &c.OpenRequests, &c.PendingApprovals, &c.Assets, &c.Compromised, &c.IOCs, &c.OpenObligations)
	return c
}

// ---------- Empfehlungen ----------

// DismissRec merkt sich eine verworfene Empfehlung (die Begründung steht zusätzlich im Einsatztagebuch).
func (s *Store) DismissRec(ctx context.Context, incidentID int64, key, by, reason string) error {
	_, err := s.db.ExecContext(ctx, `INSERT OR REPLACE INTO rec_dismissals (incident_id, key, at, by, reason) VALUES (?,?,?,?,?)`,
		incidentID, key, ts(time.Now()), by, reason)
	return err
}

func (s *Store) DismissedRecs(ctx context.Context, incidentID int64) map[string]bool {
	out := map[string]bool{}
	rows, err := s.db.QueryContext(ctx, `SELECT key FROM rec_dismissals WHERE incident_id=?`, incidentID)
	if err != nil {
		return out
	}
	defer rows.Close()
	for rows.Next() {
		var k string
		if rows.Scan(&k) == nil {
			out[k] = true
		}
	}
	return out
}

// ---------- Storno & endgültiges Löschen ----------

// PurgeIncident löscht einen stornierten Vorfall mit allen Daten. Die Löschsperren für Einsatztagebuch und
// Lagemeldungen greifen nur nicht für Vorfälle, die hier ausdrücklich zur Löschung markiert werden.
func (s *Store) PurgeIncident(ctx context.Context, id int64) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback() //nolint:errcheck
	res, err := tx.ExecContext(ctx, `UPDATE incidents SET purging=1 WHERE id=? AND cancelled=1`, id)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n != 1 {
		return errors.New("nur stornierte Vorfälle können gelöscht werden")
	}
	for _, t := range []string{"journal", "sitreps", "tasks", "communications", "assets", "iocs", "obligations", "incident_members", "rec_dismissals"} {
		if _, err := tx.ExecContext(ctx, `DELETE FROM `+t+` WHERE incident_id=?`, id); err != nil {
			return fmt.Errorf("%s: %w", t, err)
		}
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM incidents WHERE id=?`, id); err != nil {
		return err
	}
	return tx.Commit()
}
