// Package cmd contains the entry-point glue: service handler, install/uninstall,
// and -dev foreground runner. The actual business logic lives under internal/.
package cmd

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"sync"
	"time"

	"github.com/Shalom-Karr/skfilter/internal/auth"
	"github.com/Shalom-Karr/skfilter/internal/config"
	"github.com/Shalom-Karr/skfilter/internal/db"
	"github.com/Shalom-Karr/skfilter/internal/firewall"
	"github.com/Shalom-Karr/skfilter/internal/httpapi"
	"github.com/Shalom-Karr/skfilter/internal/resolver"

	"golang.org/x/sys/windows/svc"
)

const (
	serviceName = "skfilter"
	// Plain HTTP on loopback only. No cert warnings, no TLS handshake noise,
	// connection never leaves the machine. Cookies are HttpOnly + SameSite=Lax
	// and the session is HMAC-signed; loopback HTTP is the right trade-off
	// for a local dashboard.
	listenAddr = "127.0.0.1:8764"
)

// RunService is the entry point in service mode (called when SCM starts the
// EXE with no flags). It blocks until the SCM signals stop or shutdown.
func RunService() error {
	return svc.Run(serviceName, &skfilterService{})
}

type skfilterService struct{}

// Execute satisfies svc.Handler. The SCM calls this on a worker goroutine.
func (s *skfilterService) Execute(_ []string, r <-chan svc.ChangeRequest, status chan<- svc.Status) (bool, uint32) {
	const accepted = svc.AcceptStop | svc.AcceptShutdown
	status <- svc.Status{State: svc.StartPending}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	loopErr := make(chan error, 1)
	go func() { loopErr <- runMainLoop(ctx, runMode{enforceDefaultDeny: true}) }()

	status <- svc.Status{State: svc.Running, Accepts: accepted}

	for {
		select {
		case c := <-r:
			switch c.Cmd {
			case svc.Interrogate:
				status <- c.CurrentStatus
			case svc.Stop, svc.Shutdown:
				status <- svc.Status{State: svc.StopPending}
				cancel()
				// wait for clean shutdown (best-effort)
				select {
				case err := <-loopErr:
					if err != nil {
						slog.Error("service loop exited with error", "err", err)
						status <- svc.Status{State: svc.Stopped}
						return false, 1
					}
				case <-time.After(8 * time.Second):
					slog.Warn("service loop did not exit within 8s")
				}
				status <- svc.Status{State: svc.Stopped}
				return false, 0
			}
		case err := <-loopErr:
			// Loop exited on its own (probably a fatal startup error). Crash so
			// SCM's failure-action policy restarts us.
			if err != nil {
				slog.Error("service loop exited unexpectedly", "err", err)
				status <- svc.Status{State: svc.Stopped}
				return false, 1
			}
			status <- svc.Status{State: svc.Stopped}
			return false, 0
		}
	}
}

// runMode flags differences between -dev (foreground, no admin) and the
// installed Windows service (LocalSystem, expected to enforce policy).
type runMode struct {
	// enforceDefaultDeny — when true the reconciler re-applies the
	// blockoutbound default policy on every tick if it drifts. False in
	// dev mode so dashboard testing works without elevation.
	enforceDefaultDeny bool
}

// runMainLoop is the shared body of the service. It builds every runtime
// dependency, starts background workers (resolver + reconciler), serves HTTPS
// at 127.0.0.1:8765, and blocks until ctx is canceled.
func runMainLoop(ctx context.Context, mode runMode) error {
	if err := config.EnsureDirs(); err != nil {
		return fmt.Errorf("ensure dirs: %w", err)
	}

	store, err := db.Open(config.DBPath())
	if err != nil {
		return fmt.Errorf("open db: %w", err)
	}
	defer store.Close()

	signingKey, err := store.Settings.EnsureSigningKey()
	if err != nil {
		return fmt.Errorf("signing key: %w", err)
	}
	sess := auth.NewSessions(signingKey)

	fw := firewall.NewNetshFirewall()
	rsv := resolver.NewResolver(store.Rules, store.Audit, fw)

	// Background workers — both honor ctx.Done().
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		firewall.NewReconciler(store, fw, firewall.ReconcilerOptions{
			EnforceDefaultDeny: mode.enforceDefaultDeny,
		}).Run(ctx)
	}()
	go func() {
		defer wg.Done()
		rsv.Run(ctx)
	}()

	handler := httpapi.Mount(httpapi.Deps{
		Store:    store,
		Sessions: sess,
		Firewall: fw,
		Resolver: rsv,
	})

	server := &http.Server{
		Addr:              listenAddr,
		Handler:           handler,
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       120 * time.Second,
	}

	serverErr := make(chan error, 1)
	go func() {
		slog.Info("dashboard listening", "addr", "http://"+listenAddr)
		err := server.ListenAndServe()
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			serverErr <- err
		}
		close(serverErr)
	}()

	select {
	case <-ctx.Done():
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := server.Shutdown(shutdownCtx); err != nil {
			slog.Warn("http shutdown", "err", err)
		}
	case err, ok := <-serverErr:
		if ok && err != nil {
			return fmt.Errorf("http server: %w", err)
		}
	}

	wg.Wait()
	return nil
}

