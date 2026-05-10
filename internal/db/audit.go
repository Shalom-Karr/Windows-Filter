package db

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"time"
)

// AuditEntry is a single row from audit_log.
type AuditEntry struct {
	ID      int64
	TS      time.Time
	Actor   string
	Action  string
	Payload string // JSON string
}

// AuditRepo is the typed accessor for audit_log.
type AuditRepo struct {
	db *sql.DB
}

// Log appends a row. payload is marshalled to JSON; pass nil for none.
func (a *AuditRepo) Log(actor, action string, payload any) error {
	if action == "" {
		return fmt.Errorf("audit.Log: empty action")
	}
	var payloadStr sql.NullString
	if payload != nil {
		b, err := json.Marshal(payload)
		if err != nil {
			return fmt.Errorf("audit.Log marshal: %w", err)
		}
		payloadStr = sql.NullString{String: string(b), Valid: true}
	}
	var actorStr sql.NullString
	if actor != "" {
		actorStr = sql.NullString{String: actor, Valid: true}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if _, err := a.db.ExecContext(ctx,
		`INSERT INTO audit_log (actor, action, payload_json) VALUES (?, ?, ?)`,
		actorStr, action, payloadStr); err != nil {
		return fmt.Errorf("audit.Log: %w", err)
	}
	return nil
}

// List returns up to limit most-recent entries (newest first).
func (a *AuditRepo) List(limit int) ([]AuditEntry, error) {
	if limit <= 0 {
		limit = 100
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	rows, err := a.db.QueryContext(ctx,
		`SELECT id, ts, actor, action, payload_json
		 FROM audit_log ORDER BY id DESC LIMIT ?`, limit)
	if err != nil {
		return nil, fmt.Errorf("audit.List: %w", err)
	}
	defer rows.Close()

	var out []AuditEntry
	for rows.Next() {
		var (
			e       AuditEntry
			actor   sql.NullString
			payload sql.NullString
		)
		if err := rows.Scan(&e.ID, &e.TS, &actor, &e.Action, &payload); err != nil {
			return nil, fmt.Errorf("audit.List scan: %w", err)
		}
		e.Actor = actor.String
		e.Payload = payload.String
		out = append(out, e)
	}
	return out, rows.Err()
}
