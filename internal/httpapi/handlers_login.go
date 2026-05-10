package httpapi

import (
	"encoding/json"
	"net/http"
	"strings"

	"github.com/Shalom-Karr/skfilter/internal/auth"
)

type passwordReq struct {
	Password string `json:"password"`
}

// readPasswordBody decodes either JSON {"password": "..."} or
// application/x-www-form-urlencoded password=... bodies.
func readPasswordBody(r *http.Request) (string, error) {
	ct := r.Header.Get("Content-Type")
	if strings.HasPrefix(ct, "application/json") {
		var pr passwordReq
		if err := json.NewDecoder(http.MaxBytesReader(nil, r.Body, 4096)).Decode(&pr); err != nil {
			return "", err
		}
		return pr.Password, nil
	}
	if err := r.ParseForm(); err != nil {
		return "", err
	}
	return r.FormValue("password"), nil
}

func (s *server) handleLogin(w http.ResponseWriter, r *http.Request) {
	pw, err := readPasswordBody(r)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid request"})
		return
	}
	if pw == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "password required"})
		return
	}

	hash, err := s.deps.Store.Settings.GetPasswordHash()
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "db error"})
		return
	}
	if len(hash) == 0 {
		// First-run not yet completed — direct the caller to /setup.
		writeJSON(w, http.StatusConflict, map[string]string{"error": "setup required"})
		return
	}
	if !auth.VerifyPassword(hash, pw) {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "invalid password"})
		return
	}
	if err := s.deps.Sessions.SetAuthenticated(w, r); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "session error"})
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func (s *server) handleLogout(w http.ResponseWriter, r *http.Request) {
	_ = s.deps.Sessions.Logout(w, r)
	// HTML form posts come from the topbar — redirect back to /login. JSON
	// callers get a tiny ack.
	if wantsJSON(r) {
		writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
		return
	}
	http.Redirect(w, r, "/login", http.StatusFound)
}

func (s *server) handleSetup(w http.ResponseWriter, r *http.Request) {
	hash, err := s.deps.Store.Settings.GetPasswordHash()
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "db error"})
		return
	}
	if len(hash) > 0 {
		// Setup already done. Refuse — must use /login.
		writeJSON(w, http.StatusConflict, map[string]string{"error": "setup already completed"})
		return
	}

	pw, err := readPasswordBody(r)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid request"})
		return
	}
	if len(pw) < 8 {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "password must be at least 8 characters"})
		return
	}

	newHash, err := auth.HashPassword(pw)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "hash error"})
		return
	}
	if err := s.deps.Store.Settings.SetPasswordHash(newHash); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "db error"})
		return
	}
	if err := s.deps.Sessions.SetAuthenticated(w, r); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "session error"})
		return
	}
	writeJSON(w, http.StatusCreated, map[string]string{"status": "ok"})
}
