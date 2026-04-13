package store

import (
	"database/sql"
	"time"

	_ "modernc.org/sqlite"
)

// Event mirrors api.SyncEvent but lives in the store package to avoid circular imports.
type Event struct {
	ID        int64
	Time      time.Time
	Operation string
	Engine    string
	Path      string
	Status    string
	Message   string
}

// EventStore persists sync events in SQLite.
type EventStore struct {
	db       *sql.DB
	maxRows  int
}

// NewEventStore opens (or creates) a SQLite database at dbPath.
func NewEventStore(dbPath string, maxRows int) (*EventStore, error) {
	db, err := sql.Open("sqlite", dbPath+"?_pragma=journal_mode(WAL)&_pragma=busy_timeout(5000)")
	if err != nil {
		return nil, err
	}
	if _, err := db.Exec(`CREATE TABLE IF NOT EXISTS events (
		id        INTEGER PRIMARY KEY AUTOINCREMENT,
		time      TEXT    NOT NULL,
		operation TEXT    NOT NULL,
		engine    TEXT    NOT NULL,
		path      TEXT    NOT NULL,
		status    TEXT    NOT NULL,
		message   TEXT    NOT NULL
	)`); err != nil {
		db.Close()
		return nil, err
	}
	s := &EventStore{db: db, maxRows: maxRows}
	s.prune()
	return s, nil
}

// Insert records a new event and prunes old rows beyond maxRows.
func (s *EventStore) Insert(ev Event) (int64, error) {
	res, err := s.db.Exec(
		`INSERT INTO events (time, operation, engine, path, status, message) VALUES (?,?,?,?,?,?)`,
		ev.Time.UTC().Format(time.RFC3339Nano),
		ev.Operation, ev.Engine, ev.Path, ev.Status, ev.Message,
	)
	if err != nil {
		return 0, err
	}
	id, _ := res.LastInsertId()
	s.prune()
	return id, nil
}

// Recent returns the last n events, newest first.
func (s *EventStore) Recent(n int) ([]Event, error) {
	rows, err := s.db.Query(
		`SELECT id, time, operation, engine, path, status, message FROM events ORDER BY id DESC LIMIT ?`, n,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Event
	for rows.Next() {
		var ev Event
		var ts string
		if err := rows.Scan(&ev.ID, &ts, &ev.Operation, &ev.Engine, &ev.Path, &ev.Status, &ev.Message); err != nil {
			return nil, err
		}
		ev.Time, _ = time.Parse(time.RFC3339Nano, ts)
		out = append(out, ev)
	}
	return out, rows.Err()
}

// Count returns the total number of stored events.
func (s *EventStore) Count() (int, error) {
	var c int
	err := s.db.QueryRow(`SELECT COUNT(*) FROM events`).Scan(&c)
	return c, err
}

// Close closes the underlying database.
func (s *EventStore) Close() error {
	return s.db.Close()
}

// DistinctPaths returns all unique secret paths with their most recent event.
func (s *EventStore) DistinctPaths() ([]Event, error) {
	rows, err := s.db.Query(`
		SELECT e.id, e.time, e.operation, e.engine, e.path, e.status, e.message
		FROM events e
		INNER JOIN (SELECT path, MAX(id) as max_id FROM events GROUP BY path) g ON e.id = g.max_id
		ORDER BY e.time DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Event
	for rows.Next() {
		var ev Event
		var ts string
		if err := rows.Scan(&ev.ID, &ts, &ev.Operation, &ev.Engine, &ev.Path, &ev.Status, &ev.Message); err != nil {
			return nil, err
		}
		ev.Time, _ = time.Parse(time.RFC3339Nano, ts)
		out = append(out, ev)
	}
	return out, rows.Err()
}

// EventsByPath returns all events for a given secret path, newest first.
func (s *EventStore) EventsByPath(path string) ([]Event, error) {
	rows, err := s.db.Query(
		`SELECT id, time, operation, engine, path, status, message FROM events WHERE path = ? ORDER BY id DESC LIMIT 50`, path,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Event
	for rows.Next() {
		var ev Event
		var ts string
		if err := rows.Scan(&ev.ID, &ts, &ev.Operation, &ev.Engine, &ev.Path, &ev.Status, &ev.Message); err != nil {
			return nil, err
		}
		ev.Time, _ = time.Parse(time.RFC3339Nano, ts)
		out = append(out, ev)
	}
	return out, rows.Err()
}

func (s *EventStore) prune() {
	s.db.Exec(`DELETE FROM events WHERE id NOT IN (SELECT id FROM events ORDER BY id DESC LIMIT ?)`, s.maxRows)
}
