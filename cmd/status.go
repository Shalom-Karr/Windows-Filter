// Live status monitor. Spawns into its own console window after -install,
// or can be launched on demand via `skfilter.exe -status`.
//
// Read-only by design — the window has NO way to stop the service. Closing
// it just closes the display; the service keeps running. To actually stop
// skfilter, the user has to go through `-uninstall` (which prompts for the
// dashboard password).
package cmd

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/mgr"
)

const statusRefresh = 3 * time.Second

// RunStatus draws a live, auto-refreshing dashboard to the console.
func RunStatus() error {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	drawStatus()
	t := time.NewTicker(statusRefresh)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			fmt.Println()
			fmt.Println("Status window closed. The skfilter service is still running.")
			fmt.Println("Reopen with:  skfilter.exe -status")
			return nil
		case <-t.C:
			drawStatus()
		}
	}
}

func drawStatus() {
	// ANSI clear + home
	fmt.Print("\x1b[2J\x1b[H")
	fmt.Println("================================================================")
	fmt.Println("  skfilter — live status   (close this window any time)")
	fmt.Printf("  %s\n", time.Now().Format("Mon 2006-01-02  15:04:05"))
	fmt.Println("================================================================")
	fmt.Println()

	// Service status
	svcState := queryServiceState()
	fmt.Printf("  Service:    %s\n", svcState)

	// Dashboard reachability
	dashboard := "unreachable"
	client := &http.Client{Timeout: 2 * time.Second}
	if resp, err := client.Get("http://localhost:8764/api/check?domain=health.skfilter.local"); err == nil {
		_ = resp.Body.Close()
		dashboard = "http://localhost:8764"
	}
	fmt.Printf("  Dashboard:  %s\n", dashboard)

	// Default firewall policy
	policy := queryDefaultPolicy()
	fmt.Printf("  Policy:     %s\n", policy)

	// Allowlist rule count (counts unique skfilter_<id> rules in netsh)
	count := countAllowlistRules()
	fmt.Printf("  Allowlist:  %d rule(s)\n", count)

	fmt.Println()
	fmt.Println("----------------------------------------------------------------")
	fmt.Println("  Manage allowlist:  http://localhost:8764")
	fmt.Println("  Uninstall:         skfilter.exe -uninstall  (requires password)")
	fmt.Println("----------------------------------------------------------------")
	fmt.Println()
	fmt.Printf("  Refresh every %v.  Ctrl-C closes this window only.\n", statusRefresh)
	fmt.Println("  Closing this window does NOT stop the filter.")
}

func queryServiceState() string {
	m, err := mgr.Connect()
	if err != nil {
		return "(can't query — not admin)"
	}
	defer m.Disconnect()
	s, err := m.OpenService(serviceName)
	if err != nil {
		return "NOT INSTALLED"
	}
	defer s.Close()
	status, err := s.Query()
	if err != nil {
		return "(query failed)"
	}
	switch status.State {
	case svc.Running:
		return "RUNNING ✓"
	case svc.StartPending:
		return "starting…"
	case svc.StopPending:
		return "stopping…"
	case svc.Stopped:
		return "STOPPED"
	case svc.Paused:
		return "paused"
	default:
		return fmt.Sprintf("state %d", status.State)
	}
}

func queryDefaultPolicy() string {
	cmd := exec.Command("netsh", "advfirewall", "show", "allprofiles")
	out, err := cmd.Output()
	if err != nil {
		return "(unknown)"
	}
	for _, line := range strings.Split(string(out), "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "Firewall Policy") {
			parts := strings.Fields(strings.TrimPrefix(line, "Firewall Policy"))
			return strings.Join(parts, " ")
		}
	}
	return "(not found)"
}

func countAllowlistRules() int {
	cmd := exec.Command("netsh", "advfirewall", "firewall", "show", "rule", "name=all")
	out, err := cmd.Output()
	if err != nil {
		return 0
	}
	// Each user-added rule writes two netsh rules (_v4 + _v6). Count the
	// numerically-named ones only (skfilter_<id>_v4) and divide.
	seen := map[string]bool{}
	for _, line := range strings.Split(string(out), "\n") {
		line = strings.TrimSpace(line)
		if !strings.HasPrefix(line, "Rule Name:") {
			continue
		}
		name := strings.TrimSpace(strings.TrimPrefix(line, "Rule Name:"))
		if !strings.HasPrefix(name, "skfilter_") {
			continue
		}
		// Skip system-reserved rules
		if name == "skfilter_self_loopback" || name == "skfilter_self_program" ||
			strings.HasPrefix(name, "skfilter_preserve_") {
			continue
		}
		// Strip the _v4 / _v6 suffix so we count the logical rule once.
		base := strings.TrimSuffix(strings.TrimSuffix(name, "_v4"), "_v6")
		seen[base] = true
	}
	return len(seen)
}
