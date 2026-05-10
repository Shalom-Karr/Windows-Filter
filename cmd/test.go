// -test mode: a self-disarming dev run.
//
// Flow:
//
//   1. Add the loopback + self-program rules (harmless allow rules — these
//      don't activate filtering on their own).
//   2. Start the dashboard. NO firewall enforcement yet.
//   3. Wait for the user to set a password on /setup (poll the DB).
//   4. Apply default-deny outbound (the reconciler also picks up the
//      password-set state and starts enforcing rule sync).
//   5. Start the 5-minute auto-revert timer from THIS moment.
//   6. On timer expiry / Ctrl-C: revert firewall, delete helper rules, exit.
//
// The pre-password gate means the box never sits in a "default-deny with
// no UI to manage rules" state — the user always has a working dashboard
// path before traffic is actually blocked.
package cmd

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/Shalom-Karr/skfilter/internal/config"
	"github.com/Shalom-Karr/skfilter/internal/db"
)

const testDuration = 5 * time.Minute

// RunTest is invoked by `skfilter.exe -test`. Requires admin.
func RunTest() error {
	slog.SetDefault(slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelInfo})))

	if !IsAdmin() {
		return fmt.Errorf("-test requires Administrator (it sets the default firewall policy)")
	}

	// Loopback allow so the dashboard is reachable even once default-deny
	// is on later. Harmless in default-allow mode (it's just an allow rule
	// that's redundant with the default).
	_ = runNetsh("advfirewall", "firewall", "delete", "rule", "name="+loopbackRule)
	if err := runNetsh(
		"advfirewall", "firewall", "add", "rule",
		"name="+loopbackRule, "dir=out", "action=allow", "protocol=any",
		"remoteip=127.0.0.1", "enable=yes", "profile=any",
	); err != nil {
		fmt.Fprintln(os.Stderr, "warning: add loopback rule:", err)
	}

	// Allow skfilter.exe itself outbound (DNS resolver, etc.). Same logic —
	// harmless until default-deny is on.
	exePath, _ := os.Executable()
	_ = runNetsh("advfirewall", "firewall", "delete", "rule", "name="+selfProgramRule)
	if err := runNetsh(
		"advfirewall", "firewall", "add", "rule",
		"name="+selfProgramRule, "dir=out", "action=allow",
		"program="+exePath, "enable=yes", "profile=any",
	); err != nil {
		fmt.Fprintln(os.Stderr, "warning: add self-program rule:", err)
	}

	// Single restore-on-exit handler. Always runs, no matter how we leave.
	policyApplied := false
	cleanup := func() {
		fmt.Println()
		if policyApplied {
			fmt.Println("Reverting default firewall policy...")
			if err := runNetsh("advfirewall", "set", "allprofiles", "firewallpolicy", "blockinbound,allowoutbound"); err != nil {
				fmt.Fprintln(os.Stderr, "warning: restore default policy:", err)
				fmt.Fprintln(os.Stderr, "   manual recovery:")
				fmt.Fprintln(os.Stderr, "     netsh advfirewall set allprofiles firewallpolicy blockinbound,allowoutbound")
			} else {
				fmt.Println("Restored.")
			}
		}
		_ = runNetsh("advfirewall", "firewall", "delete", "rule", "name="+loopbackRule)
		_ = runNetsh("advfirewall", "firewall", "delete", "rule", "name="+selfProgramRule)
		disableFirewallLogging()
	}
	defer cleanup()

	// Signal-aware context that lives for the whole session.
	parent, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	// Open a Store handle for the password-polling + log-tailer.
	store, err := db.Open(config.DBPath())
	if err != nil {
		return fmt.Errorf("open db: %w", err)
	}
	defer store.Close()

	// Spawn the dashboard. EnforceDefaultDeny=true so the reconciler is
	// ARMED — but its ShouldEnforce gate (wired in cmd/service.go) checks
	// IsPasswordSet() per tick, so it stays in stand-down until the user
	// completes /setup.
	ctx, cancel := context.WithCancel(parent)
	defer cancel()
	runDone := make(chan error, 1)
	go func() {
		runDone <- runMainLoop(ctx, runMode{enforceDefaultDeny: true})
	}()

	fmt.Println()
	fmt.Println("Dashboard:  http://localhost:8764")
	fmt.Println()
	fmt.Println("→ Open it and set a password on /setup.")
	fmt.Println("  The firewall stays UNTOUCHED until you save a password.")
	fmt.Println("  Once you do, default-deny activates and the 5-minute timer starts.")
	fmt.Println()

	// Block until the user completes /setup. Returns false on Ctrl-C.
	if !waitForPasswordSet(parent, store) {
		return nil
	}

	// Password set — apply default-deny + start the timer.
	fmt.Println()
	fmt.Println("Password set — applying default-deny outbound.")
	if err := runNetsh("advfirewall", "set", "allprofiles", "firewallpolicy", "blockinbound,blockoutbound"); err != nil {
		return fmt.Errorf("apply default-deny: %w", err)
	}
	policyApplied = true

	enableFirewallLogging()
	go tailFirewallLog(ctx, store)

	fmt.Printf("Auto-revert at: %s\n", time.Now().Add(testDuration).Format(time.Kitchen))
	fmt.Println("Press Ctrl-C to revert sooner.")
	fmt.Println()

	select {
	case <-parent.Done():
	case <-time.After(testDuration):
	case err := <-runDone:
		if err != nil {
			fmt.Fprintln(os.Stderr, "service loop exited:", err)
		}
	}
	return nil
}

// waitForPasswordSet polls the settings row every 500ms until the password
// has been saved. Returns false if ctx was canceled (Ctrl-C) before the
// password was set.
func waitForPasswordSet(ctx context.Context, store *db.Store) bool {
	t := time.NewTicker(500 * time.Millisecond)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return false
		case <-t.C:
			ok, err := store.Settings.IsPasswordSet()
			if err == nil && ok {
				return true
			}
		}
	}
}
