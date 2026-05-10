package httpapi

import (
	"encoding/json"
	"net"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/Shalom-Karr/skfilter/internal/db"

	"github.com/go-chi/chi/v5"
)

// hostnameRe — RFC-1035-ish hostname validation. Used by both
// POST /api/rules and GET /api/check to reject anything weird.
var hostnameRe = regexp.MustCompile(`^(?i)([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}$`)

// isValidAllowlistEntry accepts three forms:
//   - hostname  (github.com)
//   - IP        (140.82.121.4, 2001:db8::1)
//   - CIDR      (140.82.112.0/20, 2001:db8::/32)
//
// Empty / malformed inputs return false. Domain matching is case-insensitive.
func isValidAllowlistEntry(s string) bool {
	if hostnameRe.MatchString(s) {
		return true
	}
	if strings.Contains(s, "/") {
		_, _, err := net.ParseCIDR(s)
		return err == nil
	}
	return net.ParseIP(s) != nil
}

// ruleJSON is the wire shape for a Rule row.
type ruleJSON struct {
	ID             int64    `json:"id"`
	Domain         string   `json:"domain"`
	IPs            []string `json:"ips"`
	LastResolvedAt *string  `json:"last_resolved_at"`
	Enabled        bool     `json:"enabled"`
}

func toRuleJSON(r db.Rule) ruleJSON {
	out := ruleJSON{
		ID:      r.ID,
		Domain:  r.Domain,
		IPs:     r.IPs,
		Enabled: r.Enabled,
	}
	if out.IPs == nil {
		out.IPs = []string{}
	}
	if r.LastResolvedAt != nil {
		s := r.LastResolvedAt.UTC().Format(time.RFC3339)
		out.LastResolvedAt = &s
	}
	return out
}

func (s *server) handleListRules(w http.ResponseWriter, r *http.Request) {
	rules, err := s.deps.Store.Rules.List()
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "db error"})
		return
	}
	out := make([]ruleJSON, 0, len(rules))
	for _, ru := range rules {
		out = append(out, toRuleJSON(ru))
	}
	writeJSON(w, http.StatusOK, out)
}

type addRuleReq struct {
	Domain string `json:"domain"`
}

func (s *server) handleAddRule(w http.ResponseWriter, r *http.Request) {
	var req addRuleReq
	if err := json.NewDecoder(http.MaxBytesReader(nil, r.Body, 4096)).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON"})
		return
	}
	domain := strings.ToLower(strings.TrimSpace(req.Domain))
	domain = strings.TrimSuffix(domain, ".")
	if !isValidAllowlistEntry(domain) {
		writeJSON(w, http.StatusBadRequest, map[string]string{
			"error": "invalid entry — expected a hostname (github.com), an IP (1.2.3.4), or a CIDR range (140.82.112.0/20)",
		})
		return
	}

	rule, err := s.deps.Store.Rules.Add(domain)
	if err != nil {
		// Treat unique-constraint-style errors as 409.
		msg := strings.ToLower(err.Error())
		if strings.Contains(msg, "unique") || strings.Contains(msg, "duplicate") || strings.Contains(msg, "already") {
			writeJSON(w, http.StatusConflict, map[string]string{"error": "domain already on allowlist"})
			return
		}
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "could not add rule: " + err.Error()})
		return
	}

	// Resolve + apply firewall rule. Best-effort: if it fails, the row
	// already exists, the resolver tick will retry, and we surface the error.
	if s.deps.Resolver != nil {
		if err := s.deps.Resolver.ResolveAndApply(rule.ID); err != nil {
			// Re-read the row so the client sees whatever state landed.
			if updated, gerr := s.deps.Store.Rules.Get(rule.ID); gerr == nil {
				rule = updated
			}
			writeJSON(w, http.StatusAccepted, map[string]any{
				"rule":    toRuleJSON(rule),
				"warning": "added but resolve failed: " + err.Error(),
			})
			return
		}
		if updated, gerr := s.deps.Store.Rules.Get(rule.ID); gerr == nil {
			rule = updated
		}
	}

	writeJSON(w, http.StatusCreated, toRuleJSON(rule))
}

func (s *server) handleDeleteRule(w http.ResponseWriter, r *http.Request) {
	idStr := chi.URLParam(r, "id")
	id, err := strconv.ParseInt(idStr, 10, 64)
	if err != nil || id <= 0 {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid id"})
		return
	}
	if err := s.deps.Store.Rules.Delete(id); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "delete failed: " + err.Error()})
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *server) handleRefreshRule(w http.ResponseWriter, r *http.Request) {
	idStr := chi.URLParam(r, "id")
	id, err := strconv.ParseInt(idStr, 10, 64)
	if err != nil || id <= 0 {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid id"})
		return
	}
	if s.deps.Resolver == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "resolver not available"})
		return
	}
	if err := s.deps.Resolver.ResolveAndApply(id); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "refresh failed: " + err.Error()})
		return
	}
	rule, err := s.deps.Store.Rules.Get(id)
	if err != nil {
		writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
		return
	}
	writeJSON(w, http.StatusOK, toRuleJSON(rule))
}
