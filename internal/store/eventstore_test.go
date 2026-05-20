package store

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestEventStore_InsertAndRecent(t *testing.T) {
	dir := t.TempDir()
	db, err := NewEventStore(filepath.Join(dir, "test.db"), 100)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer db.Close()

	// Insert 3 events
	for i, name := range []string{"alpha", "beta", "gamma"} {
		_, err := db.Insert(Event{
			Time:      time.Now().Add(time.Duration(i) * time.Second),
			Operation: "update",
			Engine:    "kv",
			Path:      name,
			Status:    "ok",
			Message:   "done " + name,
		})
		if err != nil {
			t.Fatalf("insert %s: %v", name, err)
		}
	}

	// Recent(2) should return newest first
	events, err := db.Recent(2)
	if err != nil {
		t.Fatalf("recent: %v", err)
	}
	if len(events) != 2 {
		t.Fatalf("expected 2 events, got %d", len(events))
	}
	if events[0].Path != "gamma" {
		t.Errorf("expected gamma first, got %s", events[0].Path)
	}
	if events[1].Path != "beta" {
		t.Errorf("expected beta second, got %s", events[1].Path)
	}

	count, err := db.Count()
	if err != nil {
		t.Fatalf("count: %v", err)
	}
	if count != 3 {
		t.Errorf("expected 3 total, got %d", count)
	}
}

func TestEventStore_Prunes(t *testing.T) {
	dir := t.TempDir()
	db, err := NewEventStore(filepath.Join(dir, "test.db"), 5)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer db.Close()

	for i := 0; i < 10; i++ {
		db.Insert(Event{
			Time:      time.Now(),
			Operation: "create",
			Engine:    "kv",
			Path:      "secret",
			Status:    "ok",
			Message:   "msg",
		})
	}

	count, err := db.Count()
	if err != nil {
		t.Fatalf("count: %v", err)
	}
	if count != 5 {
		t.Errorf("expected 5 after pruning, got %d", count)
	}
}

func TestEventStore_PersistsAcrossReopen(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "test.db")

	// Open, insert, close
	db, err := NewEventStore(dbPath, 100)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	db.Insert(Event{
		Time:      time.Now(),
		Operation: "update",
		Engine:    "kv",
		Path:      "persistent-secret",
		Status:    "ok",
		Message:   "should survive restart",
	})
	db.Close()

	// Reopen
	db2, err := NewEventStore(dbPath, 100)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	defer db2.Close()

	events, err := db2.Recent(10)
	if err != nil {
		t.Fatalf("recent: %v", err)
	}
	if len(events) != 1 {
		t.Fatalf("expected 1 event after reopen, got %d", len(events))
	}
	if events[0].Path != "persistent-secret" {
		t.Errorf("expected persistent-secret, got %s", events[0].Path)
	}
}

func TestEventStore_TimeParsesCorrectly(t *testing.T) {
	dir := t.TempDir()
	db, err := NewEventStore(filepath.Join(dir, "test.db"), 100)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer db.Close()

	now := time.Now().UTC().Truncate(time.Microsecond)
	db.Insert(Event{
		Time:      now,
		Operation: "create",
		Engine:    "kv",
		Path:      "timesecret",
		Status:    "ok",
		Message:   "time check",
	})

	events, _ := db.Recent(1)
	diff := events[0].Time.Sub(now)
	if diff < -time.Second || diff > time.Second {
		t.Errorf("time mismatch: stored=%v retrieved=%v diff=%v", now, events[0].Time, diff)
	}
}

func TestEventStore_InvalidPath(t *testing.T) {
	_, err := NewEventStore(filepath.Join(os.DevNull, "nonexistent", "path", "test.db"), 100)
	if err == nil {
		t.Fatal("expected error for invalid path")
	}
}
