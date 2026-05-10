// Package httpapi exposes the skfilter dashboard + REST API as a single
// http.Handler. The caller (cmd/skfilter) builds the TLS listener and
// serves this handler.
package httpapi

import (
	"net/http"

	"github.com/Shalom-Karr/skfilter/internal/auth"
	"github.com/Shalom-Karr/skfilter/internal/db"
	"github.com/Shalom-Karr/skfilter/internal/firewall"
	"github.com/Shalom-Karr/skfilter/internal/resolver"
	"github.com/Shalom-Karr/skfilter/internal/webui"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
)

// Deps holds the cross-package dependencies the API needs.
type Deps struct {
	Store    *db.Store
	Sessions *auth.Sessions
	Firewall firewall.Firewall
	Resolver *resolver.Resolver
}

// Mount returns the dashboard + API as a single http.Handler.
//
// The caller binds this to 127.0.0.1:8765 over TLS.
func Mount(d Deps) http.Handler {
	srv := &server{deps: d}
	srv.checkLimiter = newIPRateLimiter(10, 10) // 10 req/s burst 10

	r := chi.NewRouter()
	r.Use(middleware.RealIP)
	r.Use(middleware.Recoverer)

	// Static assets — never gated.
	r.Handle("/static/*", http.StripPrefix("/static/", http.FileServer(http.FS(webui.FS()))))

	// Public HTML pages.
	r.Get("/login", srv.handleLoginPage)
	r.Get("/setup", srv.handleSetupPage)
	r.Get("/blocked", srv.handleBlocked)

	// Public POST endpoints (gated internally by setup-state).
	// AuditLogger wraps these so we record every login attempt.
	r.Group(func(r chi.Router) {
		r.Use(jsonContentType)
		r.Use(srv.auditLogger)
		r.Post("/login", srv.handleLogin)
		r.Post("/setup", srv.handleSetup)
	})

	// /api/check — un-authenticated, loopback-only, rate-limited.
	r.Group(func(r chi.Router) {
		r.Use(jsonContentType)
		r.Use(loopbackOnly)
		r.Use(srv.checkLimiter.middleware)
		r.Get("/api/check", srv.handleCheck)
	})

	// Authenticated HTML pages.
	r.Group(func(r chi.Router) {
		r.Use(srv.authRequired)
		r.Get("/", srv.handleDashboard)
		r.Get("/audit", srv.handleAuditPage)
		r.Post("/logout", srv.handleLogout)
	})

	// Authenticated JSON API.
	r.Group(func(r chi.Router) {
		r.Use(jsonContentType)
		r.Use(srv.authRequired)
		r.Use(srv.auditLogger)
		r.Get("/api/rules", srv.handleListRules)
		r.Post("/api/rules", srv.handleAddRule)
		r.Delete("/api/rules/{id}", srv.handleDeleteRule)
		r.Post("/api/rules/{id}/refresh", srv.handleRefreshRule)
		r.Get("/api/audit", srv.handleListAudit)
	})

	return r
}

// server holds the runtime state shared across handlers.
type server struct {
	deps         Deps
	checkLimiter *ipRateLimiter
}
