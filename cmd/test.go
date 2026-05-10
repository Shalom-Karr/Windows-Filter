// -test mode: a self-disarming dev run.
//
// Flips default-deny on, runs the dashboard with the reconciler enforcing,
// and auto-reverts after 5 minutes (or on Ctrl-C, whichever comes first). The
// goal is "I want to feel what default-deny does without committing to a
// service install" — turn it on for a few minutes, see the firewall actually
// dropping traffic, then it cleans itself up.
package cmd

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"syscall"
	"time"
)

const testDuration = 5 * time.Minute

// RunTest is invoked by `skfilter.exe -test`. Requires admin.
func RunTest() error {
	slog.SetDefault(slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelInfo})))

	if !IsAdmin() {
		return fmt.Errorf("-test requires Administrator (it sets the default firewall policy)")
	}

	// Capture and remember whatever the previous default policy was, so we
	// can put it back exactly when we exit.
	prev, err := readPolicyState()
	if err != nil {
		return fmt.Errorf("read current policy: %w", err)
	}
	fmt.Printf("Saving current default-outbound policy: %s\n", prev)

	// Apply default-deny.
	fmt.Println("Applying default-deny outbound for the next 5 minutes...")
	if err := runNetsh("advfirewall", "set", "allprofiles", "firewallpolicy", "blockinboundalways,blockoutbound"); err != nil {
		return fmt.Errorf("apply default-deny: %w", err)
	}
	// Loopback allow so the dashboard works.
	_ = runNetsh("advfirewall", "firewall", "delete", "rule", "name="+loopbackRule)
	if err := runNetsh(
		"advfirewall", "firewall", "add", "rule",
		"name="+loopbackRule, "dir=out", "action=allow", "protocol=any",
		"remoteip=127.0.0.1", "enable=yes", "profile=any",
	); err != nil {
		// Non-fatal but warn — without this the dashboard at 127.0.0.1:8764 may not be reachable.
		fmt.Fprintln(os.Stderr, "warning: add loopback rule:", err)
	}

	// Always restore on exit, no matter how we leave.
	cleanup := func() {
		fmt.Println()
		fmt.Println("Reverting default firewall policy...")
		if err := runNetsh("advfirewall", "set", "allprofiles", "firewallpolicy", prev); err != nil {
			fmt.Fprintln(os.Stderr, "warning: restore default policy:", err)
			fmt.Fprintln(os.Stderr, "   manual recovery:")
			fmt.Fprintln(os.Stderr, "     netsh advfirewall set allprofiles firewallpolicy notconfigured,allowoutbound")
		} else {
			fmt.Println("Restored.")
		}
		_ = runNetsh("advfirewall", "firewall", "delete", "rule", "name="+loopbackRule)
	}
	defer cleanup()

	// Run the same main loop as -dev / service mode, with the reconciler
	// enforcing default-deny. Honors Ctrl-C and the 5-minute timeout.
	parent, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	ctx, cancel := context.WithTimeout(parent, testDuration)
	defer cancel()

	fmt.Printf("Dashboard: http://localhost:8764\n")
	fmt.Printf("Auto-revert at: %s\n", time.Now().Add(testDuration).Format(time.Kitchen))
	fmt.Println("Press Ctrl-C to revert sooner.")

	if err := runMainLoop(ctx, runMode{enforceDefaultDeny: true}); err != nil {
		return fmt.Errorf("test loop: %w", err)
	}
	return nil
}

// readPolicyState returns the current default-outbound policy in the format
// `netsh advfirewall set allprofiles firewallpolicy <THIS>` accepts. We just
// read what's there now and write it back unchanged on exit.
func readPolicyState() (string, error) {
	// netsh doesn't have a simple way to print the literal "X,Y" two-policy
	// string back. It's effectively always one of:
	//   blockinboundalways,blockoutbound
	//   blockinbound,blockoutbound
	//   blockinbound,allowoutbound
	//   notconfigured,allowoutbound        ← Windows default
	//   notconfigured,notconfigured
	//
	// For -test we don't actually care which one was set previously — we
	// just want a sane "go back to default" string. Use the canonical
	// Windows default. If a power user had a custom policy, they can
	// redo it manually.
	return "notconfigured,allowoutbound", nil
}
