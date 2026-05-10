package db

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"
)

// Rule is one allowlisted domain plus the IPs we last resolved for it.
type Rule struct {
	ID             int64
	Domain         string
	IPs            []string
	LastResolvedAt *time.Time
	Enabled        bool
	CreatedAt      time.Time
}

// RulesRepo is the typed accessor for the rules table.
type RulesRepo struct {
	db *sql.DB
}

// ErrNotFound is returned when a row lookup misses.
var ErrNotFound = errors.New("not found")

func splitIPs(csv string) []string {
	csv = strings.TrimSpace(csv)
	if csv == "" {
		return []string{}
	}
	parts := strings.Split(csv, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}

func joinIPs(ips []string) string {
	cleaned := make([]string, 0, len(ips))
	for _, ip := range ips {
		ip = strings.TrimSpace(ip)
		if ip != "" {
			cleaned = append(cleaned, ip)
		}
	}
	return strings.Join(cleaned, ",")
}

func scanRule(row interface {
	Scan(...any) error
}) (Rule, error) {
	var (
		r          Rule
		ipsCSV     string
		lastResolv sql.NullTime
		enabledI   int64
		created    time.Time
	)
	if err := row.Scan(&r.ID, &r.Domain, &ipsCSV, &lastResolv, &enabledI, &created); err != nil {
		return Rule{}, err
	}
	r.IPs = splitIPs(ipsCSV)
	if lastResolv.Valid {
		t := lastResolv.Time
		r.LastResolvedAt = &t
	}
	r.Enabled = enabledI != 0
	r.CreatedAt = created
	return r, nil
}

// List returns every rule, newest first.
func (r *RulesRepo) List() ([]Rule, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	rows, err := r.db.QueryContext(ctx,
		`SELECT id, domain, ips_csv, last_resolved_at, enabled, created_at
		 FROM rules ORDER BY id DESC`)
	if err != nil {
		return nil, fmt.Errorf("rules.List: %w", err)
	}
	defer rows.Close()
	var out []Rule
	for rows.Next() {
		rule, err := scanRule(rows)
		if err != nil {
			return nil, fmt.Errorf("rules.List scan: %w", err)
		}
		out = append(out, rule)
	}
	return out, rows.Err()
}

// AllEnabled returns every rule where enabled = 1.
func (r *RulesRepo) AllEnabled() ([]Rule, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	rows, err := r.db.QueryContext(ctx,
		`SELECT id, domain, ips_csv, last_resolved_at, enabled, created_at
		 FROM rules WHERE enabled = 1 ORDER BY id ASC`)
	if err != nil {
		return nil, fmt.Errorf("rules.AllEnabled: %w", err)
	}
	defer rows.Close()
	var out []Rule
	for rows.Next() {
		rule, err := scanRule(rows)
		if err != nil {
			return nil, fmt.Errorf("rules.AllEnabled scan: %w", err)
		}
		out = append(out, rule)
	}
	return out, rows.Err()
}

// Get fetches one rule by id.
func (r *RulesRepo) Get(id int64) (Rule, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	row := r.db.QueryRowContext(ctx,
		`SELECT id, domain, ips_csv, last_resolved_at, enabled, created_at
		 FROM rules WHERE id = ?`, id)
	rule, err := scanRule(row)
	if errors.Is(err, sql.ErrNoRows) {
		return Rule{}, ErrNotFound
	}
	if err != nil {
		return Rule{}, fmt.Errorf("rules.Get: %w", err)
	}
	return rule, nil
}

// Add inserts a new rule with enabled=true and an empty IP list.
func (r *RulesRepo) Add(domain string) (Rule, error) {
	domain = strings.TrimSpace(strings.ToLower(domain))
	if domain == "" {
		return Rule{}, fmt.Errorf("rules.Add: empty domain")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	res, err := r.db.ExecContext(ctx,
		`INSERT INTO rules (domain, ips_csv, enabled) VALUES (?, '', 1)`, domain)
	if err != nil {
		return Rule{}, fmt.Errorf("rules.Add: %w", err)
	}
	id, err := res.LastInsertId()
	if err != nil {
		return Rule{}, fmt.Errorf("rules.Add insert id: %w", err)
	}
	return r.Get(id)
}

// Delete removes a rule by id.
func (r *RulesRepo) Delete(id int64) error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	res, err := r.db.ExecContext(ctx, `DELETE FROM rules WHERE id = ?`, id)
	if err != nil {
		return fmt.Errorf("rules.Delete: %w", err)
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return ErrNotFound
	}
	return nil
}

// UpdateIPs writes a new IP list (CSV) and stamps last_resolved_at = now.
func (r *RulesRepo) UpdateIPs(id int64, ips []string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	res, err := r.db.ExecContext(ctx,
		`UPDATE rules SET ips_csv = ?, last_resolved_at = CURRENT_TIMESTAMP WHERE id = ?`,
		joinIPs(ips), id)
	if err != nil {
		return fmt.Errorf("rules.UpdateIPs: %w", err)
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return ErrNotFound
	}
	return nil
}
