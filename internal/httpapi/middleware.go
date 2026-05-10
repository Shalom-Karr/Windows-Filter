package httpapi

import (
	"encoding/json"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"golang.org/x/time/rate"
)

// jsonContentType sets a JSON content-type on responses that haven't already
// declared one. Handlers that render HTML should set their own header before
// writing.
func jsonContentType(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Don't pre-set — handler may want to write 204 with no body. Let the
		// handler call writeJSON which sets the header.
		next.ServeHTTP(w, r)
	})
}

// loopbackOnly rejects requests whose remote address isn't a loopback. The
// listener already binds 127.0.0.1, but this is defense-in-depth in case the
// bind ever changes.
func loopbackOnly(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		host, _, err := net.SplitHostPort(r.RemoteAddr)
		if err != nil {
			host = r.RemoteAddr
		}
		if !isLoopback(host) {
			http.Error(w, `{"error":"forbidden"}`, http.StatusForbidden)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func isLoopback(host string) bool {
	if host == "127.0.0.1" || host == "::1" || host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// authRequired blocks unauthenticated requests. JSON requests get 401, HTML
// requests are redirected to /login.
func (s *server) authRequired(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !s.deps.Sessions.IsAuthenticated(r) {
			if wantsJSON(r) {
				writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
				return
			}
			http.Redirect(w, r, "/login?next="+r.URL.Path, http.StatusFound)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func wantsJSON(r *http.Request) bool {
	if strings.HasPrefix(r.URL.Path, "/api/") {
		return true
	}
	accept := r.Header.Get("Accept")
	if strings.Contains(accept, "application/json") && !strings.Contains(accept, "text/html") {
		return true
	}
	if strings.Contains(r.Header.Get("Content-Type"), "application/json") {
		return true
	}
	return false
}

// statusRecorder captures the response status for the audit logger.
type statusRecorder struct {
	http.ResponseWriter
	status int
	wrote  bool
}

func (sr *statusRecorder) WriteHeader(code int) {
	if !sr.wrote {
		sr.status = code
		sr.wrote = true
	}
	sr.ResponseWriter.WriteHeader(code)
}

func (sr *statusRecorder) Write(b []byte) (int, error) {
	if !sr.wrote {
		sr.status = 200
		sr.wrote = true
	}
	return sr.ResponseWriter.Write(b)
}

// auditLogger writes an audit_log entry for state-changing requests.
// Skipped for GETs and for non-2xx responses.
func (s *server) auditLogger(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet || r.Method == http.MethodOptions || r.Method == http.MethodHead {
			next.ServeHTTP(w, r)
			return
		}
		sr := &statusRecorder{ResponseWriter: w, status: 200}
		next.ServeHTTP(sr, r)
		if sr.status < 200 || sr.status >= 300 {
			// Still log auth failures on /login and /setup.
			if !(r.URL.Path == "/login" || r.URL.Path == "/setup") {
				return
			}
		}
		actor := s.deps.Sessions.SessionID(r)
		if actor == "" {
			actor = "anonymous"
		}
		action := auditActionFor(r.Method, r.URL.Path, sr.status)
		payload := map[string]any{
			"method": r.Method,
			"path":   r.URL.Path,
			"status": sr.status,
			"remote": r.RemoteAddr,
		}
		_ = s.deps.Store.Audit.Log(actor, action, payload)
	})
}

func auditActionFor(method, path string, status int) string {
	switch {
	case path == "/login" && status >= 200 && status < 300:
		return "login_success"
	case path == "/login":
		return "login_failed"
	case path == "/logout":
		return "logout"
	case path == "/setup":
		return "setup_password"
	case method == http.MethodPost && path == "/api/rules":
		return "rule_added"
	case method == http.MethodDelete && strings.HasPrefix(path, "/api/rules/"):
		return "rule_removed"
	case method == http.MethodPost && strings.HasSuffix(path, "/refresh"):
		return "rule_refreshed"
	default:
		return method + " " + path
	}
}

// ipRateLimiter holds a per-IP token bucket; used on /api/check.
type ipRateLimiter struct {
	mu       sync.Mutex
	limits   map[string]*ipLimitEntry
	rps      rate.Limit
	burst    int
	lastSwep time.Time
}

type ipLimitEntry struct {
	limiter *rate.Limiter
	seen    time.Time
}

func newIPRateLimiter(rps rate.Limit, burst int) *ipRateLimiter {
	return &ipRateLimiter{
		limits: make(map[string]*ipLimitEntry),
		rps:    rps,
		burst:  burst,
	}
}

func (r *ipRateLimiter) get(host string) *rate.Limiter {
	r.mu.Lock()
	defer r.mu.Unlock()

	// Reap entries unseen for >5 minutes, every minute.
	now := time.Now()
	if now.Sub(r.lastSwep) > time.Minute {
		for k, v := range r.limits {
			if now.Sub(v.seen) > 5*time.Minute {
				delete(r.limits, k)
			}
		}
		r.lastSwep = now
	}

	e, ok := r.limits[host]
	if !ok {
		e = &ipLimitEntry{limiter: rate.NewLimiter(r.rps, r.burst)}
		r.limits[host] = e
	}
	e.seen = now
	return e.limiter
}

func (r *ipRateLimiter) middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		host, _, err := net.SplitHostPort(req.RemoteAddr)
		if err != nil {
			host = req.RemoteAddr
		}
		if !r.get(host).Allow() {
			w.Header().Set("Retry-After", "1")
			writeJSON(w, http.StatusTooManyRequests, map[string]string{"error": "rate limited"})
			return
		}
		next.ServeHTTP(w, req)
	})
}

// writeJSON encodes v and writes it with the given status code. It also sets
// Content-Type and Cache-Control: no-store for safety.
func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(status)
	if v == nil {
		return
	}
	enc := json.NewEncoder(w)
	enc.SetEscapeHTML(false)
	_ = enc.Encode(v)
}
