package db

import (
	"context"
	"crypto/rand"
	"database/sql"
	"errors"
	"fmt"
	"time"
)

// SettingsRepo accesses the single-row settings table.
type SettingsRepo struct {
	db *sql.DB
}

// GetPasswordHash returns the stored bcrypt hash, or (nil, nil) if not yet set.
func (s *SettingsRepo) GetPasswordHash() ([]byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	var hash []byte
	err := s.db.QueryRowContext(ctx,
		`SELECT password_hash FROM settings WHERE id = 1`).Scan(&hash)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("settings.GetPasswordHash: %w", err)
	}
	return hash, nil
}

// SetPasswordHash overwrites the stored bcrypt hash.
func (s *SettingsRepo) SetPasswordHash(hash []byte) error {
	if len(hash) == 0 {
		return fmt.Errorf("settings.SetPasswordHash: empty hash")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if _, err := s.db.ExecContext(ctx,
		`UPDATE settings SET password_hash = ? WHERE id = 1`, hash); err != nil {
		return fmt.Errorf("settings.SetPasswordHash: %w", err)
	}
	return nil
}

// GetSigningKey returns the cookie-session signing key.
func (s *SettingsRepo) GetSigningKey() ([]byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	var key []byte
	if err := s.db.QueryRowContext(ctx,
		`SELECT session_signing_key FROM settings WHERE id = 1`).Scan(&key); err != nil {
		return nil, fmt.Errorf("settings.GetSigningKey: %w", err)
	}
	return key, nil
}

// EnsureSigningKey returns the existing signing key, or generates and stores a
// fresh 32-byte random key if the column is empty/missing (defensive — the
// schema seeds randomblob(32) on first open).
func (s *SettingsRepo) EnsureSigningKey() ([]byte, error) {
	key, err := s.GetSigningKey()
	if err == nil && len(key) >= 16 {
		return key, nil
	}
	fresh := make([]byte, 32)
	if _, err := rand.Read(fresh); err != nil {
		return nil, fmt.Errorf("settings.EnsureSigningKey rand: %w", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if _, err := s.db.ExecContext(ctx,
		`UPDATE settings SET session_signing_key = ? WHERE id = 1`, fresh); err != nil {
		return nil, fmt.Errorf("settings.EnsureSigningKey persist: %w", err)
	}
	return fresh, nil
}
