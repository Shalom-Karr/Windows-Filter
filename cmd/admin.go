// Admin detection + idempotent install/start. The browser-policy work that
// expands EnsureInstalledAndRunning further is being added separately.
package cmd

import (
	"fmt"
	"os"
	"time"

	"github.com/Shalom-Karr/skfilter/internal/policies"

	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/mgr"
)

// IsAdmin returns true if the current process can manage Windows services
// (the proxy we use for "is admin"). Implementation: open the SCM with
// SC_MANAGER_ALL_ACCESS — that requires admin.
func IsAdmin() bool {
	m, err := mgr.Connect()
	if err != nil {
		return false
	}
	_ = m.Disconnect()
	return true
}

// EnsureInstalledAndRunning is the entry point for "skfilter.exe run as admin
// with no flags." Idempotent: install if not installed, start if stopped, no-op
// if already running.
func EnsureInstalledAndRunning() error {
	m, err := mgr.Connect()
	if err != nil {
		return fmt.Errorf("connect SCM (run as Administrator?): %w", err)
	}
	defer m.Disconnect()

	s, err := m.OpenService(serviceName)
	if err != nil {
		// Not installed → first-time install.
		fmt.Println("Installing skfilter for the first time...")
		if err := Install(); err != nil {
			return err
		}
		fmt.Println()
		fmt.Println("skfilter is now running and will auto-start on every boot.")
		fmt.Println("Open http://localhost:8764 to set your dashboard password.")
		return nil
	}
	defer s.Close()

	status, err := s.Query()
	if err != nil {
		return fmt.Errorf("query service: %w", err)
	}
	switch status.State {
	case svc.Running:
		fmt.Println("skfilter is already running.")
	case svc.StartPending:
		fmt.Println("skfilter is starting up...")
	case svc.Stopped, svc.StopPending:
		fmt.Println("Starting skfilter...")
		if err := s.Start(); err != nil {
			return fmt.Errorf("start service: %w", err)
		}
		deadline := time.Now().Add(10 * time.Second)
		for time.Now().Before(deadline) {
			time.Sleep(500 * time.Millisecond)
			st, qerr := s.Query()
			if qerr == nil && st.State == svc.Running {
				break
			}
		}
	default:
		fmt.Fprintf(os.Stdout, "skfilter service is in state %d.\n", status.State)
	}

	// Re-apply browser policies so we self-heal if a user yanked the keys
	// since the last install/restart. Non-fatal — the reconciler also
	// re-asserts these on every tick once the service is up.
	if err := policies.WriteBrowserPolicies(); err != nil {
		fmt.Fprintln(os.Stderr, "warning: write browser policies:", err)
	}

	fmt.Println("Dashboard: http://localhost:8764")
	return nil
}
