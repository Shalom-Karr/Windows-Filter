package httpapi

import (
	"encoding/json"
	"html/template"
	"net/http"
	"net/url"
	"sync"

	"github.com/Shalom-Karr/skfilter/internal/webui"
)

var (
	blockedTplOnce sync.Once
	blockedTpl     *template.Template
	blockedTplErr  error
)

func loadBlockedTpl() (*template.Template, error) {
	blockedTplOnce.Do(func() {
		raw, err := webui.ReadFile("blocked.html")
		if err != nil {
			blockedTplErr = err
			return
		}
		blockedTpl, blockedTplErr = template.New("blocked").Parse(string(raw))
	})
	return blockedTpl, blockedTplErr
}

type blockedData struct {
	URL           string
	Domain        string
	URLJSON       template.JS
	DomainJSON    template.JS
	Authenticated bool
}

// handleBlocked renders the "this site isn't on your allowlist" landing page.
//
// Public — anyone (including the browser extension's redirect target) can hit
// it. The "Add to allowlist" action still requires auth; the page either
// exposes a one-click button (logged in) or an inline password prompt.
func (s *server) handleBlocked(w http.ResponseWriter, r *http.Request) {
	raw := r.URL.Query().Get("url")
	if raw == "" {
		http.Error(w, "missing url parameter", http.StatusBadRequest)
		return
	}
	u, err := url.Parse(raw)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		http.Error(w, "invalid url", http.StatusBadRequest)
		return
	}
	domain := u.Hostname()
	if !hostnameRe.MatchString(domain) {
		http.Error(w, "invalid domain in url", http.StatusBadRequest)
		return
	}

	tpl, err := loadBlockedTpl()
	if err != nil {
		http.Error(w, "template error", http.StatusInternalServerError)
		return
	}

	urlJSON, _ := json.Marshal(raw)
	domainJSON, _ := json.Marshal(domain)

	data := blockedData{
		URL:           raw,
		Domain:        domain,
		URLJSON:       template.JS(urlJSON),
		DomainJSON:    template.JS(domainJSON),
		Authenticated: s.deps.Sessions.IsAuthenticated(r),
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	if err := tpl.Execute(w, data); err != nil {
		// Headers already written — best we can do is log via the deps.
		return
	}
}
