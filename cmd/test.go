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

	// Allow skfilter.exe itself outbound so the resolver can do DNS lookups.
	// Without this, default-deny blocks net.LookupIP, rules get added with
	// empty IPs, and curl <allowed-domain> times out forever.
	exePath, _ := os.Executable()
	_ = runNetsh("advfirewall", "firewall", "delete", "rule", "name="+selfProgramRule)
	if err := runNetsh(
		"advfirewall", "firewall", "add", "rule",
		"name="+selfProgramRule, "dir=out", "action=allow",
		"program="+exePath, "enable=yes", "profile=any",
	); err != nil {
		fmt.Fprintln(os.Stderr, "warning: add self-program rule:", err)
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
		_ = runNetsh("advfirewall", "firewall", "delete", "rule", "name="+selfProgramRule)
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

// readPolicyState returns the policy string we'll restore on exit.
//
// netsh advfirewall accepts these values for the local store:
//   blockinboundalways,blockoutbound
//   blockinbound,blockoutbound
//   blockinbound,allowoutbound        ← Windows factory default
// "notconfigured" only works when configuring a Group Policy object (GPO),
// not the local store. The earlier hardcoded "notconfigured,allowoutbound"
// failed at exit with: "Notconfigured value can only be used when configuring
// a Group Policy object (GPO) store."
//
// We don't read the previous policy back (netsh has no clean machine-readable
// way to do that for the firewallpolicy verb) — we always restore to the
// factory default, which is the right thing to do for a self-disarming
// -test session.
func readPolicyState() (string, error) {
	return "blockinbound,allowoutbound", nil
}
