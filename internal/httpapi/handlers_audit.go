package httpapi

import (
	"encoding/json"
	"net/http"
	"strconv"
	"time"

	"github.com/Shalom-Karr/skfilter/internal/db"
)

type auditJSON struct {
	ID      int64  `json:"id"`
	TS      string `json:"ts"`
	Actor   string `json:"actor"`
	Action  string `json:"action"`
	Payload any    `json:"payload"`
}

func toAuditJSON(e db.AuditEntry) auditJSON {
	out := auditJSON{
		ID:     e.ID,
		Actor:  e.Actor,
		Action: e.Action,
	}
	if !e.TS.IsZero() {
		out.TS = e.TS.UTC().Format(time.RFC3339)
	}
	// Best-effort: try to decode the payload if it's a JSON-encoded string.
	switch p := any(e.Payload).(type) {
	case nil:
		out.Payload = nil
	case string:
		if p == "" {
			out.Payload = nil
		} else {
			var decoded any
			if json.Unmarshal([]byte(p), &decoded) == nil {
				out.Payload = decoded
			} else {
				out.Payload = p
			}
		}
	case []byte:
		if len(p) == 0 {
			out.Payload = nil
		} else {
			var decoded any
			if json.Unmarshal(p, &decoded) == nil {
				out.Payload = decoded
			} else {
				out.Payload = string(p)
			}
		}
	default:
		out.Payload = p
	}
	return out
}

func (s *server) handleListAudit(w http.ResponseWriter, r *http.Request) {
	limit := 200
	if q := r.URL.Query().Get("limit"); q != "" {
		if n, err := strconv.Atoi(q); err == nil && n > 0 && n <= 5000 {
			limit = n
		}
	}
	entries, err := s.deps.Store.Audit.List(limit)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "db error"})
		return
	}
	out := make([]auditJSON, 0, len(entries))
	for _, e := range entries {
		out = append(out, toAuditJSON(e))
	}
	writeJSON(w, http.StatusOK, out)
}
