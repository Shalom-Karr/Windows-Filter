package httpapi

import (
	"html/template"
	"net/http"
	"sync"

	"github.com/Shalom-Karr/skfilter/internal/webui"
)

// Static SPA shells. The dashboard ("/") and audit page ("/audit") are
// authenticated and pulled directly from the embedded FS. The login and
// setup pages are templates so we can populate flash data.

var (
	loginTplOnce sync.Once
	loginTpl     *template.Template
	loginTplErr  error
)

func loadLoginTpl() (*template.Template, error) {
	loginTplOnce.Do(func() {
		raw, err := webui.ReadFile("login.html")
		if err != nil {
			loginTplErr = err
			return
		}
		loginTpl, loginTplErr = template.New("login").Parse(string(raw))
	})
	return loginTpl, loginTplErr
}

type loginData struct {
	Error string
	Next  string
}

func (s *server) handleLoginPage(w http.ResponseWriter, r *http.Request) {
	// If already authenticated, send to /.
	if s.deps.Sessions.IsAuthenticated(r) {
		http.Redirect(w, r, "/", http.StatusFound)
		return
	}
	// If first-run setup hasn't happened, redirect to /setup.
	hash, err := s.deps.Store.Settings.GetPasswordHash()
	if err == nil && len(hash) == 0 {
		http.Redirect(w, r, "/setup", http.StatusFound)
		return
	}

	tpl, err := loadLoginTpl()
	if err != nil {
		http.Error(w, "template error", http.StatusInternalServerError)
		return
	}
	data := loginData{Next: r.URL.Query().Get("next")}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	_ = tpl.Execute(w, data)
}

func (s *server) handleSetupPage(w http.ResponseWriter, r *http.Request) {
	// Setup is a one-time flow. If a password is already set, send to /login.
	hash, err := s.deps.Store.Settings.GetPasswordHash()
	if err == nil && len(hash) > 0 {
		http.Redirect(w, r, "/login", http.StatusFound)
		return
	}
	body, err := webui.ReadFile("setup.html")
	if err != nil {
		http.Error(w, "template error", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	_, _ = w.Write(body)
}

func (s *server) handleDashboard(w http.ResponseWriter, r *http.Request) {
	body, err := webui.ReadFile("index.html")
	if err != nil {
		http.Error(w, "template error", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	_, _ = w.Write(body)
}

func (s *server) handleAuditPage(w http.ResponseWriter, r *http.Request) {
	body, err := webui.ReadFile("audit.html")
	if err != nil {
		http.Error(w, "template error", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	_, _ = w.Write(body)
}
