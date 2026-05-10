package httpapi

import (
	"net/http"
	"strings"
)

type checkResp struct {
	Allowed bool   `json:"allowed"`
	RuleID  *int64 `json:"rule_id"`
}

// handleCheck answers the browser extension's "is this domain allowed?" query.
//
// Loopback-only and rate-limited via middleware. Read-only.
func (s *server) handleCheck(w http.ResponseWriter, r *http.Request) {
	domain := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("domain")))
	domain = strings.TrimSuffix(domain, ".")
	if !hostnameRe.MatchString(domain) {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid domain"})
		return
	}

	rules, err := s.deps.Store.Rules.List()
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "db error"})
		return
	}

	for _, ru := range rules {
		if !ru.Enabled {
			continue
		}
		if strings.EqualFold(ru.Domain, domain) {
			id := ru.ID
			writeJSON(w, http.StatusOK, checkResp{Allowed: true, RuleID: &id})
			return
		}
	}
	writeJSON(w, http.StatusOK, checkResp{Allowed: false, RuleID: nil})
}
