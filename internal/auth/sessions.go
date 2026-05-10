package auth

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"net/http"

	"github.com/gorilla/sessions"
)

const (
	sessionName    = "skfilter"
	authKey        = "auth"
	sessionIDKey   = "sid"
	maxAgeSeconds  = 60 * 60 * 12 // 12h
	cookiePathRoot = "/"
)

// Sessions wraps a gorilla/sessions cookie store with skfilter-specific helpers.
type Sessions struct {
	store *sessions.CookieStore
}

// NewSessions builds a CookieStore signed with signingKey. The cookie is
// HttpOnly + Secure (the dashboard is HTTPS-only) + SameSite=Lax.
func NewSessions(signingKey []byte) *Sessions {
	if len(signingKey) == 0 {
		panic("auth.NewSessions: empty signing key")
	}
	store := sessions.NewCookieStore(signingKey)
	store.Options = &sessions.Options{
		Path:     cookiePathRoot,
		MaxAge:   maxAgeSeconds,
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
	}
	return &Sessions{store: store}
}

// IsAuthenticated returns true if the request carries a valid signed session
// with the auth flag set.
func (s *Sessions) IsAuthenticated(r *http.Request) bool {
	sess, err := s.store.Get(r, sessionName)
	if err != nil || sess == nil {
		return false
	}
	v, ok := sess.Values[authKey].(bool)
	return ok && v
}

// SetAuthenticated marks the current session as authenticated, allocating a
// fresh session id used as the audit "actor".
func (s *Sessions) SetAuthenticated(w http.ResponseWriter, r *http.Request) error {
	sess, _ := s.store.Get(r, sessionName)
	sess.Values[authKey] = true
	if _, ok := sess.Values[sessionIDKey].(string); !ok {
		id, err := newSessionID()
		if err != nil {
			return fmt.Errorf("auth.SetAuthenticated: %w", err)
		}
		sess.Values[sessionIDKey] = id
	}
	if err := sess.Save(r, w); err != nil {
		return fmt.Errorf("auth.SetAuthenticated save: %w", err)
	}
	return nil
}

// Logout clears the session cookie.
func (s *Sessions) Logout(w http.ResponseWriter, r *http.Request) error {
	sess, _ := s.store.Get(r, sessionName)
	sess.Options.MaxAge = -1
	for k := range sess.Values {
		delete(sess.Values, k)
	}
	if err := sess.Save(r, w); err != nil {
		return fmt.Errorf("auth.Logout: %w", err)
	}
	return nil
}

// SessionID returns the per-session id (suitable for an audit "actor"), or
// an empty string when the request is unauthenticated / has no cookie.
func (s *Sessions) SessionID(r *http.Request) string {
	sess, err := s.store.Get(r, sessionName)
	if err != nil || sess == nil {
		return ""
	}
	if id, ok := sess.Values[sessionIDKey].(string); ok {
		return id
	}
	return ""
}

func newSessionID() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}
