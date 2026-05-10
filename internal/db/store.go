// Package db owns the SQLite store and the three repositories built on top
// of it (rules, audit, settings). The schema is embedded and applied
// idempotently on every Open.
package db

import (
	"context"
	"database/sql"
	_ "embed"
	"fmt"
	"path/filepath"
	"time"

	_ "modernc.org/sqlite"
)

//go:embed schema.sql
var schemaSQL string

// Store wraps the SQLite handle and exposes typed repositories.
type Store struct {
	DB *sql.DB

	Rules    *RulesRepo
	Audit    *AuditRepo
	Settings *SettingsRepo
}

// Open opens (or creates) the SQLite database at path, applies the schema,
// and returns a ready-to-use Store. Caller is responsible for Close().
func Open(path string) (*Store, error) {
	if path == "" {
		return nil, fmt.Errorf("db.Open: empty path")
	}
	// Use file:URI form so we can pin pragmas without a custom driver.
	dsn := fmt.Sprintf("file:%s?_pragma=journal_mode(WAL)&_pragma=foreign_keys(1)&_pragma=busy_timeout(5000)",
		filepath.ToSlash(path))

	conn, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("db.Open: %w", err)
	}
	conn.SetMaxOpenConns(1) // SQLite + WAL: writers serialize anyway; keep it simple.
	conn.SetConnMaxLifetime(0)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := conn.PingContext(ctx); err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("db.Open ping: %w", err)
	}
	if _, err := conn.ExecContext(ctx, schemaSQL); err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("db.Open schema: %w", err)
	}

	s := &Store{DB: conn}
	s.Rules = &RulesRepo{db: conn}
	s.Audit = &AuditRepo{db: conn}
	s.Settings = &SettingsRepo{db: conn}
	return s, nil
}

// Close releases the underlying handle.
func (s *Store) Close() error {
	if s == nil || s.DB == nil {
		return nil
	}
	return s.DB.Close()
}
