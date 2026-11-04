package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"time"

	"leakguard/internal/workflow"
)

const workflowSchema = `
CREATE TABLE IF NOT EXISTS positions (
	key        TEXT PRIMARY KEY,
	sort       INTEGER NOT NULL DEFAULT 0,
	data       TEXT NOT NULL,
	updated_at INTEGER NOT NULL,
	updated_by TEXT NOT NULL DEFAULT ''
);
CREATE TABLE IF NOT EXISTS workflows (
	id         INTEGER PRIMARY KEY AUTOINCREMENT,
	key        TEXT NOT NULL UNIQUE,
	archived   INTEGER NOT NULL DEFAULT 0,
	created_at INTEGER NOT NULL,
	created_by TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS workflow_versions (
	id           INTEGER PRIMARY KEY AUTOINCREMENT,
	workflow_id  INTEGER NOT NULL REFERENCES workflows(id),
	version      INTEGER NOT NULL DEFAULT 0,
	status       TEXT NOT NULL,
	def          TEXT NOT NULL,
	note         TEXT NOT NULL DEFAULT '',
	created_at   INTEGER NOT NULL,
	created_by   TEXT NOT NULL,
	published_at INTEGER NOT NULL DEFAULT 0,
	published_by TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS idx_wfv_wf ON workflow_versions(workflow_id);
-- Welche Abläufe der eingebauten Bibliothek bereits installiert wurden (gelöschte/archivierte kommen nicht wieder).
CREATE TABLE IF NOT EXISTS workflow_templates (
	key          TEXT PRIMARY KEY,
	rev          INTEGER NOT NULL,
	workflow_id  INTEGER NOT NULL DEFAULT 0,
	installed_at INTEGER NOT NULL
);
-- Veröffentlichte Versionen sind unveränderlich: laufende Vorfälle verlassen sich darauf.
CREATE TRIGGER IF NOT EXISTS wfv_immutable BEFORE UPDATE OF def ON workflow_versions
	WHEN OLD.status <> 'entwurf' BEGIN SELECT RAISE(ABORT, 'published workflow versions are immutable'); END;
`

// ---------- Stabspositionen ----------

func (s *Store) Positions(ctx context.Context) ([]workflow.Position, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT data FROM positions ORDER BY sort, key`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []workflow.Position
	for rows.Next() {
		var raw string
		if err := rows.Scan(&raw); err != nil {
			return nil, err
		}
		var p workflow.Position
		if err := json.Unmarshal([]byte(raw), &p); err == nil {
			out = append(out, p)
		}
	}
	return out, rows.Err()
}

func (s *Store) SavePosition(ctx context.Context, p workflow.Position, user string) error {
	raw, err := json.Marshal(p)
	if err != nil {
		return err
	}
	_, err = s.db.ExecContext(ctx, `INSERT INTO positions (key, sort, data, updated_at, updated_by) VALUES (?,?,?,?,?)
		ON CONFLICT(key) DO UPDATE SET sort=excluded.sort, data=excluded.data, updated_at=excluded.updated_at, updated_by=excluded.updated_by`,
		p.Key, p.Sort, string(raw), ts(time.Now()), user)
	return err
}

func (s *Store) DeletePosition(ctx context.Context, key string) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM positions WHERE key=?`, key)
	return err
}

// PositionInUse zählt Verwendungen einer Position in Workflow-Entwürfen und aktiven Versionen sowie in Stäben.
func (s *Store) PositionInUse(ctx context.Context, key string) (workflows []string, members int) {
	infos, _ := s.Workflows(ctx)
	for _, wi := range infos {
		for _, v := range []*workflow.Version{wi.Active, wi.Draft} {
			if v == nil {
				continue
			}
			used := false
			for _, st := range v.Def.Steps {
				used = used || st.Position == key
			}
			for _, r := range v.Def.Staff {
				used = used || r.Position == key
			}
			if used {
				workflows = append(workflows, v.Def.Name)
				break
			}
		}
	}
	_ = s.db.QueryRowContext(ctx, `SELECT count(*) FROM incident_members WHERE function=?`, key).Scan(&members)
	return workflows, members
}

// ---------- Workflows ----------

const wfvCols = `id, workflow_id, version, status, def, note, created_at, created_by, published_at, published_by`

func scanVersion(r scanner) (*workflow.Version, error) {
	var v workflow.Version
	var raw string
	var cr, pub int64
	if err := r.Scan(&v.ID, &v.WorkflowID, &v.Version, &v.Status, &raw, &v.Note, &cr, &v.CreatedBy, &pub, &v.PublishedBy); err != nil {
		return nil, err
	}
	if err := json.Unmarshal([]byte(raw), &v.Def); err != nil {
		return nil, fmt.Errorf("workflow version %d: %w", v.ID, err)
	}
	v.CreatedAt, v.PublishedAt = fromTS(cr), fromTS(pub)
	return &v, nil
}

func (s *Store) WorkflowVersion(ctx context.Context, id int64) (*workflow.Version, error) {
	v, err := scanVersion(s.db.QueryRowContext(ctx, `SELECT `+wfvCols+` FROM workflow_versions WHERE id=?`, id))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	return v, err
}

func (s *Store) WorkflowVersions(ctx context.Context, workflowID int64) ([]*workflow.Version, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT `+wfvCols+` FROM workflow_versions WHERE workflow_id=? ORDER BY version=0 DESC, version DESC`, workflowID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*workflow.Version
	for rows.Next() {
		v, err := scanVersion(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, v)
	}
	return out, rows.Err()
}

// Workflows liefert alle Workflows mit aktiver Version und Entwurf.
func (s *Store) Workflows(ctx context.Context) ([]workflow.Info, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT id, key, archived FROM workflows`)
	if err != nil {
		return nil, err
	}
	var out []workflow.Info
	for rows.Next() {
		var wi workflow.Info
		var arch int
		if err := rows.Scan(&wi.ID, &wi.Key, &arch); err != nil {
			rows.Close()
			return nil, err
		}
		wi.Archived = arch == 1
		out = append(out, wi)
	}
	rows.Close()
	for i := range out {
		vs, err := s.WorkflowVersions(ctx, out[i].ID)
		if err != nil {
			return nil, err
		}
		for _, v := range vs {
			switch v.Status {
			case "entwurf":
				out[i].Draft = v
			case "aktiv":
				out[i].Active = v
			}
			if v.Version > 0 {
				out[i].Versions++
			}
		}
		_ = s.db.QueryRowContext(ctx, `SELECT count(*) FROM incidents i JOIN workflow_versions v ON v.id=i.wf_version_id
			WHERE v.workflow_id=? AND i.phase<>'abgeschlossen' AND i.cancelled=0`, out[i].ID).Scan(&out[i].Incidents)
	}
	sort.SliceStable(out, func(i, j int) bool {
		a, b := out[i].Current(), out[j].Current()
		if out[i].Archived != out[j].Archived {
			return !out[i].Archived
		}
		if a == nil || b == nil {
			return a != nil
		}
		if (a.Def.Key == "standard") != (b.Def.Key == "standard") {
			return a.Def.Key == "standard"
		}
		return a.Def.Name < b.Def.Name
	})
	return out, nil
}

func (s *Store) WorkflowInfo(ctx context.Context, id int64) (*workflow.Info, error) {
	all, err := s.Workflows(ctx)
	if err != nil {
		return nil, err
	}
	for i := range all {
		if all[i].ID == id {
			return &all[i], nil
		}
	}
	return nil, ErrNotFound
}

// ActiveVersions liefert die veröffentlichten, nicht archivierten Versionen (für Auswahl und Automatik).
func (s *Store) ActiveVersions(ctx context.Context) ([]*workflow.Version, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT `+prefixed("v", wfvCols)+` FROM workflow_versions v JOIN workflows w ON w.id=v.workflow_id
		WHERE v.status='aktiv' AND w.archived=0`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*workflow.Version
	for rows.Next() {
		v, err := scanVersion(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, v)
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].Def.Name < out[j].Def.Name })
	return out, rows.Err()
}

func prefixed(p, cols string) string {
	out := ""
	for i, c := range splitCols(cols) {
		if i > 0 {
			out += ", "
		}
		out += p + "." + c
	}
	return out
}

func splitCols(cols string) []string {
	var out []string
	cur := ""
	for _, r := range cols {
		switch r {
		case ',':
			out = append(out, cur)
			cur = ""
		case ' ', '\n', '\t':
		default:
			cur += string(r)
		}
	}
	return append(out, cur)
}

// CreateWorkflow legt einen Workflow mit einem Entwurf an.
func (s *Store) CreateWorkflow(ctx context.Context, d workflow.Def, user string) (int64, error) {
	raw, err := json.Marshal(d)
	if err != nil {
		return 0, err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, err
	}
	defer tx.Rollback() //nolint:errcheck
	now := ts(time.Now())
	res, err := tx.ExecContext(ctx, `INSERT INTO workflows (key, created_at, created_by) VALUES (?,?,?)`, d.Key, now, user)
	if err != nil {
		return 0, fmt.Errorf("Schlüssel %q bereits vergeben", d.Key)
	}
	id, _ := res.LastInsertId()
	if _, err := tx.ExecContext(ctx, `INSERT INTO workflow_versions (workflow_id, version, status, def, created_at, created_by) VALUES (?,0,'entwurf',?,?,?)`,
		id, string(raw), now, user); err != nil {
		return 0, err
	}
	return id, tx.Commit()
}

// SaveDraft speichert (oder erzeugt) den Entwurf eines Workflows.
func (s *Store) SaveDraft(ctx context.Context, workflowID int64, d workflow.Def, user string) error {
	raw, err := json.Marshal(d)
	if err != nil {
		return err
	}
	var exists int
	_ = s.db.QueryRowContext(ctx, `SELECT count(*) FROM workflows WHERE key=? AND id<>?`, d.Key, workflowID).Scan(&exists)
	if exists > 0 {
		return fmt.Errorf("Schlüssel %q wird bereits von einem anderen Workflow verwendet", d.Key)
	}
	now := ts(time.Now())
	res, err := s.db.ExecContext(ctx, `UPDATE workflow_versions SET def=?, created_at=?, created_by=? WHERE workflow_id=? AND status='entwurf'`,
		string(raw), now, user, workflowID)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		if _, err := s.db.ExecContext(ctx, `INSERT INTO workflow_versions (workflow_id, version, status, def, created_at, created_by) VALUES (?,0,'entwurf',?,?,?)`,
			workflowID, string(raw), now, user); err != nil {
			return err
		}
	}
	_, err = s.db.ExecContext(ctx, `UPDATE workflows SET key=? WHERE id=?`, d.Key, workflowID)
	return err
}

// Publish macht den Entwurf zur neuen aktiven Version; die bisherige wird abgelöst (bleibt für laufende Vorfälle erhalten).
func (s *Store) Publish(ctx context.Context, workflowID int64, note, user string) (*workflow.Version, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback() //nolint:errcheck
	var draftID int64
	if err := tx.QueryRowContext(ctx, `SELECT id FROM workflow_versions WHERE workflow_id=? AND status='entwurf'`, workflowID).Scan(&draftID); err != nil {
		return nil, ErrNotFound
	}
	var max int
	_ = tx.QueryRowContext(ctx, `SELECT coalesce(max(version),0) FROM workflow_versions WHERE workflow_id=?`, workflowID).Scan(&max)
	if _, err := tx.ExecContext(ctx, `UPDATE workflow_versions SET status='abgeloest' WHERE workflow_id=? AND status='aktiv'`, workflowID); err != nil {
		return nil, err
	}
	if _, err := tx.ExecContext(ctx, `UPDATE workflow_versions SET status='aktiv', version=?, note=?, published_at=?, published_by=? WHERE id=?`,
		max+1, note, ts(time.Now()), user, draftID); err != nil {
		return nil, err
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return s.WorkflowVersion(ctx, draftID)
}

func (s *Store) DiscardDraft(ctx context.Context, workflowID int64) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM workflow_versions WHERE workflow_id=? AND status='entwurf'`, workflowID)
	return err
}

func (s *Store) ArchiveWorkflow(ctx context.Context, workflowID int64, archived bool) error {
	_, err := s.db.ExecContext(ctx, `UPDATE workflows SET archived=? WHERE id=?`, b2i(archived), workflowID)
	return err
}

// HasWorkflows meldet, ob überhaupt Workflows angelegt sind (sonst Startbestand einspielen).
func (s *Store) HasWorkflows(ctx context.Context) bool {
	var n int
	_ = s.db.QueryRowContext(ctx, `SELECT count(*) FROM workflows`).Scan(&n)
	return n > 0
}

// SeedWorkflow legt einen Workflow direkt als veröffentlichte Version 1 an.
func (s *Store) SeedWorkflow(ctx context.Context, d workflow.Def, user string) error {
	id, err := s.CreateWorkflow(ctx, d, user)
	if err != nil {
		return err
	}
	_, err = s.Publish(ctx, id, "Startbestand", user)
	return err
}

// IncidentsOnVersion zählt aktive Vorfälle je Workflow-Version.
func (s *Store) IncidentsOnVersion(ctx context.Context, versionID int64) int {
	var n int
	_ = s.db.QueryRowContext(ctx, `SELECT count(*) FROM incidents WHERE wf_version_id=? AND phase<>'abgeschlossen' AND cancelled=0`, versionID).Scan(&n)
	return n
}

// ---------- Bibliothek ----------

type InstalledTemplate struct {
	Rev        int
	WorkflowID int64
}

func (s *Store) InstalledTemplates(ctx context.Context) (map[string]InstalledTemplate, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT key, rev, workflow_id FROM workflow_templates`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]InstalledTemplate{}
	for rows.Next() {
		var k string
		var it InstalledTemplate
		if err := rows.Scan(&k, &it.Rev, &it.WorkflowID); err != nil {
			return nil, err
		}
		out[k] = it
	}
	return out, rows.Err()
}

func (s *Store) MarkTemplate(ctx context.Context, key string, rev int, workflowID int64) error {
	_, err := s.db.ExecContext(ctx, `INSERT INTO workflow_templates (key, rev, workflow_id, installed_at) VALUES (?,?,?,?)
		ON CONFLICT(key) DO UPDATE SET rev=excluded.rev, workflow_id=excluded.workflow_id`, key, rev, workflowID, ts(time.Now()))
	return err
}

// InstallTemplate legt einen Bibliotheksablauf als veröffentlichten Workflow an (eindeutiger Schlüssel).
func (s *Store) InstallTemplate(ctx context.Context, d workflow.Def, rev int, user string) (int64, error) {
	base := d.Key
	for i := 2; ; i++ {
		var n int
		_ = s.db.QueryRowContext(ctx, `SELECT count(*) FROM workflows WHERE key=?`, d.Key).Scan(&n)
		if n == 0 {
			break
		}
		d.Key = fmt.Sprintf("%s_%d", base, i)
	}
	id, err := s.CreateWorkflow(ctx, d, user)
	if err != nil {
		return 0, err
	}
	if _, err := s.Publish(ctx, id, "Aus der eingebauten Bibliothek installiert", user); err != nil {
		return 0, err
	}
	return id, s.MarkTemplate(ctx, base, rev, id)
}
